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

/// The accounts that may sign in, as SQL over `users`: active ones, and
/// closing ones (to keep them) unless they were suspended when they closed.
pub const SIGNS_IN: &str =
    "(state = 'active' OR (state = 'closing' AND suspended_before_close IS NULL))";

/// The refusal while the account is being deleted (its date has passed).
pub fn deleting() -> AppError {
    AppError::conflict("the account is being deleted")
        .with_details(serde_json::json!({ "code": "accountDeleting" }))
}

/// Moves an active (or suspended) account to `closing`, due in `days`; its
/// sign-ins and grants end. A suspended account keeps its suspension's
/// reason for when it is kept. When it is due, or None when it was closing
/// already.
pub async fn close(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    by: ClosingBy,
    days: i64,
) -> AppResult<Option<time::OffsetDateTime>> {
    let closes_at: Option<time::OffsetDateTime> = sqlx::query_scalar(
        "UPDATE users SET state = 'closing',
                suspended_before_close = CASE WHEN state = 'suspended' THEN suspended_reason END,
                suspended_reason = NULL, closing_by = $2,
                closes_at = now() + make_interval(days => $3::int),
                purpose_ended_at = now(), state_changed_at = now(),
                deletion_attempts = 0, deletion_next_try_at = NULL
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
        // The shared mailboxes it signs for need a new signer: it may still
        // hold the seed (docs/plans/mail-groups.md).
        crate::mail::group_keys::signer_leaving(tx, user_id).await?;
    }
    Ok(closes_at)
}

/// Keeps a closing account: as it was before it closed (active, or suspended
/// with its reason), its purpose not ended. Whether it was closing and still
/// could be: once its date has passed the closing job may be deleting it, so
/// it is kept no more (a held account waits for its hold, and can be), and
/// never while a deletion is under way.
pub async fn keep(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<bool> {
    let kept = sqlx::query(
        "UPDATE users SET
                state = CASE WHEN suspended_before_close IS NULL THEN 'active' ELSE 'suspended' END,
                suspended_reason = suspended_before_close, suspended_before_close = NULL,
                closing_by = NULL, closes_at = NULL, purpose_ended_at = NULL,
                state_changed_at = now(), deletion_attempts = 0, deletion_next_try_at = NULL
          WHERE id = $1 AND state = 'closing' AND deleting_at IS NULL
            AND (closes_at > now() OR kutup_account_held(id))",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(kept > 0)
}

/// How long a deletion under way holds its claim: one that crashed is taken
/// up again after this.
const DELETION_CLAIM_MINUTES: i32 = 60;

/// Takes the account for deletion (`deleting_at`), so nothing comes between
/// its purges and its row's deletion: a hold or a keep is refused meanwhile,
/// and another server doesn't purge it too. `due_only`: only a closing
/// account past its date (the closing job).
async fn claim(state: &AppState, target: Uuid, due_only: bool) -> AppResult<()> {
    let claimed = sqlx::query(
        "UPDATE users SET deleting_at = now()
          WHERE id = $1 AND NOT kutup_account_held(id)
            AND (deleting_at IS NULL OR deleting_at < now() - make_interval(mins => $3))
            AND (NOT $2 OR (state = 'closing' AND closes_at <= now()))",
    )
    .bind(target)
    .bind(due_only)
    .bind(DELETION_CLAIM_MINUTES)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if claimed == 1 {
        return Ok(());
    }
    let row: Option<(bool, bool)> = sqlx::query_as(
        "SELECT kutup_account_held(id), deleting_at IS NOT NULL FROM users WHERE id = $1",
    )
    .bind(target)
    .fetch_optional(&state.pool)
    .await?;
    Err(match row {
        None => AppError::not_found("not found"),
        Some((true, _)) => on_hold(),
        Some((_, true)) => deleting(),
        Some(_) => AppError::conflict("the account is not due"),
    })
}

/// Deletes the account now: everything it holds, bytes included, then its
/// row (its data key goes with it), recording the destruction. Refused under
/// a legal hold, and while another deletion of it is under way. `due_only`
/// for the closing job.
pub async fn destroy(
    state: &AppState,
    target: Uuid,
    actor: Actor,
    reference: &str,
    due_only: bool,
) -> AppResult<()> {
    claim(state, target, due_only).await?;
    let purged = purge(state, target).await;
    if let Err(error) = purged {
        // Taken up again later: the purges are each safe to run again.
        sqlx::query("UPDATE users SET deleting_at = NULL WHERE id = $1")
            .bind(target)
            .execute(&state.pool)
            .await?;
        return Err(error);
    }

    // Its names stay held, receiving nothing, until the hold ends: nobody
    // takes a deleted person's name, nor their mail, before then
    // (docs/plans/username-renames.md).
    let (hold_days, _) = crate::site_settings::name_holds(&state.pool, &state.config).await?;
    let mut tx = state.pool.begin().await?;
    // Still claimed (a hold can't be set meanwhile; a lapsed claim taken by
    // another server is that server's to finish).
    let claimed: Option<bool> =
        sqlx::query_scalar("SELECT deleting_at IS NOT NULL FROM users WHERE id = $1 FOR UPDATE")
            .bind(target)
            .fetch_optional(&mut *tx)
            .await?;
    match claimed {
        None => return Err(AppError::not_found("not found")),
        Some(false) => return Err(deleting()),
        Some(true) => {}
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

/// Everything the account holds goes with it, bytes included (a bare row
/// delete would cascade the rows and leave every object in the bucket),
/// while what it added to other people's folders stays theirs.
async fn purge(state: &AppState, target: Uuid) -> AppResult<()> {
    crate::handlers::chat_backup::purge_for_account(state, target).await?;
    crate::handlers::admin::purge_chat_media(state, target).await?;
    crate::handlers::admin::purge_owned_drive(state, target).await?;
    crate::handlers::admin::purge_mail(state, target).await?;
    crate::handlers::admin::hand_over_contributions(&state.pool, target).await
}

/// Accounts the closing job deletes per run.
const DUE_BATCH: i64 = 20;
/// Failed deletions of one account after which the job logs it as an error
/// for the operator (it keeps trying, further apart).
const DELETION_ALERT_ATTEMPTS: i32 = 5;

/// Deletes the closing accounts whose grace period is over, held ones and
/// ones backing off after a failure excepted. How many.
pub async fn run_due(state: &AppState) -> AppResult<u64> {
    let due: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, closing_by FROM users
          WHERE state = 'closing' AND closes_at <= now() AND NOT kutup_account_held(id)
            AND (deletion_next_try_at IS NULL OR deletion_next_try_at <= now())
          ORDER BY closes_at LIMIT $1",
    )
    .bind(DUE_BATCH)
    .fetch_all(&state.pool)
    .await?;
    let mut deleted = 0;
    for (account, by) in due {
        match destroy(
            state,
            account,
            ClosingBy::actor(&by),
            "account-closing",
            true,
        )
        .await
        {
            Ok(()) => deleted += 1,
            Err(error) => {
                // Further apart each time (a minute, doubling, at most a day),
                // so one account that fails holds none of the rest back.
                let attempts: Option<i32> = sqlx::query_scalar(
                    "UPDATE users SET deletion_attempts = deletion_attempts + 1,
                            deletion_next_try_at = now() + LEAST(
                                make_interval(mins => 1) * power(2, LEAST(deletion_attempts, 11)),
                                make_interval(days => 1))
                      WHERE id = $1 RETURNING deletion_attempts",
                )
                .bind(account)
                .fetch_optional(&state.pool)
                .await?;
                if attempts.is_some_and(|n| n >= DELETION_ALERT_ATTEMPTS) {
                    tracing::error!(
                        %account,
                        attempts,
                        "a closing account could not be deleted: {}",
                        error.message
                    );
                } else {
                    tracing::warn!(%account, "closing an account: {}", error.message);
                }
            }
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

/// The jobs that delete an account's data, each of which passes held
/// accounts by (`kutup_account_held`): (file, function). A new deletion job
/// joins this list.
#[cfg(test)]
const DELETION_JOBS: &[(&str, &str, &str)] = &[
    (
        "jobs.rs",
        include_str!("jobs.rs"),
        "fn sweep_chat_mailboxes_before",
    ),
    (
        "jobs.rs",
        include_str!("jobs.rs"),
        "fn version_retention_tick",
    ),
    (
        "jobs.rs",
        include_str!("jobs.rs"),
        "fn sweep_expired_chat_backup_staging",
    ),
    (
        "jobs.rs",
        include_str!("jobs.rs"),
        "fn sweep_chat_delivery_media_before",
    ),
    ("jobs.rs", include_str!("jobs.rs"), "fn trash_sweep_once"),
    (
        "mail/retention.rs",
        include_str!("mail/retention.rs"),
        "fn once",
    ),
    ("mail/expiry.rs", include_str!("mail/expiry.rs"), "fn once"),
    (
        "security_events.rs",
        include_str!("security_events.rs"),
        "fn prune",
    ),
    ("sessions.rs", include_str!("sessions.rs"), "fn prune_ended"),
    ("audit_log.rs", include_str!("audit_log.rs"), "fn prune"),
    (
        "account_closing.rs",
        include_str!("account_closing.rs"),
        "fn run_due",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A function's text: from its signature to the next item at the file's
    /// top level.
    fn body<'a>(source: &'a str, name: &str) -> &'a str {
        let start = source
            .find(&format!("{name}("))
            .unwrap_or_else(|| panic!("{name} is gone: update DELETION_JOBS"));
        let rest = &source[start..];
        let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 3);
        &rest[..end]
    }

    async fn account(pool: &sqlx::PgPool) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '')",
        )
        .bind(user_id)
        .bind(format!("closing{}", &user_id.simple().to_string()[..12]))
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn state_of(pool: &sqlx::PgPool, user_id: Uuid) -> (String, Option<String>) {
        sqlx::query_as("SELECT state, suspended_reason FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// A suspended account that is closed and kept is suspended again, with
    /// its reason, and can't sign in meanwhile; a deletion under way can be
    /// neither kept nor held, nor taken by a second server.
    #[tokio::test]
    async fn live_closing_keeps_a_suspension_and_a_claim_shuts_out_keeps_and_holds() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let suspended = account(&pool).await;
        sqlx::query(
            "UPDATE users SET state = 'suspended', suspended_reason = 'operator_order' WHERE id = $1",
        )
        .bind(suspended)
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(close(&mut tx, suspended, ClosingBy::Admin, 14)
            .await
            .unwrap()
            .is_some());
        tx.commit().await.unwrap();
        let signs_in: bool =
            sqlx::query_scalar(&format!("SELECT {SIGNS_IN} FROM users WHERE id = $1"))
                .bind(suspended)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !signs_in,
            "a suspended account closed can't sign in to keep itself"
        );
        let mut tx = pool.begin().await.unwrap();
        assert!(keep(&mut tx, suspended).await.unwrap());
        tx.commit().await.unwrap();
        assert_eq!(
            state_of(&pool, suspended).await,
            ("suspended".into(), Some("operator_order".into()))
        );

        // Claimed for deletion: no keep, no hold, no second claim.
        let deleting = account(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        close(&mut tx, deleting, ClosingBy::User, 14).await.unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE users SET deleting_at = now() WHERE id = $1")
            .bind(deleting)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(!keep(&mut tx, deleting).await.unwrap());
        tx.rollback().await.unwrap();
        let claimed_again = sqlx::query(
            "UPDATE users SET deleting_at = now()
              WHERE id = $1 AND (deleting_at IS NULL OR deleting_at < now() - interval '1 hour')",
        )
        .bind(deleting)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(claimed_again, 0);

        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(vec![suspended, deleting])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn every_deletion_job_passes_held_accounts_by() {
        for (file, source, name) in DELETION_JOBS {
            let text = body(source, name);
            assert!(
                text.contains("kutup_account_held") || text.contains("legal_hold_reference"),
                "{file} {name} deletes without checking the legal hold"
            );
        }
    }
}
