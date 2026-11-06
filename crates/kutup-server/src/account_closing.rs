//! An account's end (docs/plans/server-personal-data.md, A5): closing, its
//! grace period, keeping it, the legal hold that stops it, and the deletion
//! itself.
//!
//! - An account asked to be deleted (by its owner, after a reauth, or by an
//!   admin) is `closing` until `closes_at` (`account_closing_days` after the
//!   ask). Its sign-ins end; a sign-in that passes every step is offered to
//!   keep it instead of a session.
//! - Then [`run_due`] deletes it: everything it holds, bytes included, its
//!   row, its data key with it; a destruction event names it only by keyed
//!   hashes (`crate::destruction_events`). A deleted account leaves no row.
//! - While a legal hold is set, nothing deletes the account or anything of
//!   it: the closing job waits, an admin's delete or reset is refused, and
//!   the retention jobs pass its rows by.

use uuid::Uuid;

use crate::destruction_events::{self, Actor};
use crate::error::{AppError, AppResult};
use crate::AppState;

/// Who asked for the account to close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosingBy {
    User,
    Admin,
    /// A restore found the account destroyed after its dump.
    Restore,
}

impl ClosingBy {
    fn as_str(self) -> &'static str {
        match self {
            ClosingBy::User => "user",
            ClosingBy::Admin => "admin",
            ClosingBy::Restore => "restore",
        }
    }

    fn actor(name: &str) -> Actor {
        match name {
            "user" => Actor::User,
            "admin" => Actor::Admin,
            _ => Actor::Job,
        }
    }
}

/// The refusal while a legal hold is set.
pub fn on_hold() -> AppError {
    AppError::conflict("the account is under a legal hold")
        .with_details(serde_json::json!({ "code": "legalHold" }))
}

/// Refuses with [`on_hold`] while the account is under a legal hold.
pub async fn check_no_hold<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
) -> AppResult<()> {
    let held: Option<bool> =
        sqlx::query_scalar("SELECT legal_hold_reference IS NOT NULL FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(executor)
            .await?;
    if held == Some(true) {
        return Err(on_hold());
    }
    Ok(())
}

/// Moves an active (or suspended) account to `closing`, due in `days`; its
/// sign-ins and grants end. When it is due, or None when it was not open.
pub async fn close(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    by: ClosingBy,
    days: i64,
) -> AppResult<Option<time::OffsetDateTime>> {
    let closes_at: Option<time::OffsetDateTime> = sqlx::query_scalar(
        "UPDATE users SET state = 'closing', suspended_reason = NULL, closing_by = $2,
                closes_at = now() + make_interval(days => $3::int),
                purpose_ended_at = now(), state_changed_at = now()
          WHERE id = $1 AND state <> 'closing'
          RETURNING closes_at",
    )
    .bind(user_id)
    .bind(by.as_str())
    .bind(days as i32)
    .fetch_optional(&mut **tx)
    .await?;
    if closes_at.is_some() {
        crate::grants::end_all(tx, user_id).await?;
        crate::sessions::revoke_all_for_user_in(tx, user_id, None).await?;
    }
    Ok(closes_at)
}

/// Keeps a closing account: active again, its purpose not ended. Whether it
/// was closing and still could be: once its date has passed the closing job
/// may be deleting it, so it is kept no more (a held account waits for its
/// hold, and can be).
pub async fn keep(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<bool> {
    let kept = sqlx::query(
        "UPDATE users SET state = 'active', closing_by = NULL, closes_at = NULL,
                purpose_ended_at = NULL, state_changed_at = now()
          WHERE id = $1 AND state = 'closing'
            AND (closes_at > now() OR legal_hold_reference IS NOT NULL)",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(kept > 0)
}

/// Deletes the account now: everything it holds, bytes included, then its
/// row (its data key goes with it), recording the destruction. Refused under
/// a legal hold.
pub async fn destroy(
    state: &AppState,
    target: Uuid,
    actor: Actor,
    reference: &str,
) -> AppResult<()> {
    check_no_hold(&state.pool, target).await?;
    // Everything the account holds goes with it, bytes included (a bare row
    // delete would cascade the rows and leave every object in the bucket),
    // while what it added to other people's folders stays theirs.
    crate::handlers::chat_backup::purge_for_account(state, target).await?;
    crate::handlers::admin::purge_chat_media(state, target).await?;
    crate::handlers::admin::purge_owned_drive(state, target).await?;
    crate::handlers::admin::purge_mail(state, target).await?;
    crate::handlers::admin::hand_over_contributions(&state.pool, target).await?;

    // Its names stay held, receiving nothing, until the hold ends: nobody
    // takes a deleted person's name, nor their mail, before then
    // (docs/plans/username-renames.md).
    let (hold_days, _) = crate::site_settings::name_holds(&state.pool, &state.config).await?;
    let mut tx = state.pool.begin().await?;
    // A hold set while the purges ran stops the rest.
    let held: Option<bool> = sqlx::query_scalar(
        "SELECT legal_hold_reference IS NOT NULL FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(target)
    .fetch_optional(&mut *tx)
    .await?;
    match held {
        None => return Err(AppError::not_found("not found")),
        Some(true) => return Err(on_hold()),
        Some(false) => {}
    }
    sqlx::query(
        "UPDATE account_names SET state = 'held', receive_until = now(),
                free_at = now() + make_interval(days => $2::int)
          WHERE user_id = $1",
    )
    .bind(target)
    .bind(hold_days as i32)
    .execute(&mut *tx)
    .await?;
    // Its account id is never given to anyone again (docs/plans/account-ids.md).
    crate::account_ids::retire(&mut tx, target).await?;
    // The shared mailboxes it signed for need a new signer: its signing
    // shares go with it, but it may still hold the seed.
    crate::mail::group_keys::signer_leaving(&mut tx, target).await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(target)
        .execute(&mut *tx)
        .await?;
    destruction_events::record_account(
        &mut tx,
        &state.config.opaque_setup_keys,
        target,
        actor,
        reference,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Accounts the closing job deletes per run.
const DUE_BATCH: i64 = 20;

/// Deletes the closing accounts whose grace period is over, held ones
/// excepted. How many.
pub async fn run_due(state: &AppState) -> AppResult<u64> {
    let due: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, closing_by FROM users
          WHERE state = 'closing' AND closes_at <= now() AND legal_hold_reference IS NULL
          ORDER BY closes_at LIMIT $1",
    )
    .bind(DUE_BATCH)
    .fetch_all(&state.pool)
    .await?;
    let mut deleted = 0;
    for (account, by) in due {
        match destroy(state, account, ClosingBy::actor(&by), "account-closing").await {
            Ok(()) => deleted += 1,
            Err(error) => tracing::warn!(%account, "closing an account: {}", error.message),
        }
    }
    Ok(deleted)
}

/// How often the closing job looks for accounts due.
const CLOSING_TICK: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Runs [`run_due`] every few minutes.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CLOSING_TICK);
        loop {
            tick.tick().await;
            // A full batch: more may be due, so go on at once.
            loop {
                match run_due(&state).await {
                    Ok(deleted) if deleted >= DUE_BATCH as u64 => continue,
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!("account closing: {}", error.message);
                        break;
                    }
                }
            }
        }
    });
}
