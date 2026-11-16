//! The destruction log (docs/plans/server-personal-data.md, A7): what was
//! destroyed, when, how and by whom, naming nobody. Append-only for the app
//! role, as the security log is (`crate::db`).
//!
//! An account is a row's subject only as keyed hashes of its id, one under
//! each entry of the server key list when the row was written
//! (`kutup_crypto::server_data::destruction_subject`). A restored database
//! holds accounts deleted after its dump was taken; at start, before anything
//! is served, [`replay`] finds them by those hashes, destroys their data keys
//! and closes them at once (A2, measure 2). Bulk deletions (retention) are
//! one row with a count and no subject.
//!
//! The log is `account_keys.destruction_events`, beside the account data
//! keys: the database dump leaves it out and the key dump holds it, so a
//! restore, which takes the newest key dump, replays a log as new as its keys.

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use crate::account_closing::ClosingBy;
use crate::error::{AppError, AppResult};
use crate::opaque_setup::OpaqueSetupKeys;

/// What a bulk deletion destroyed (an account's own rows are
/// [`record_account`]'s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    /// Security-log rows past their retention.
    SecurityEvents,
    /// Admin-log rows past their retention.
    AdminAudit,
    /// Ended sessions past their grace period.
    Sessions,
    /// This log's own rows past their retention.
    DestructionEvents,
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Category::SecurityEvents => "security_events",
            Category::AdminAudit => "admin_audit",
            Category::Sessions => "sessions",
            Category::DestructionEvents => "destruction_events",
        }
    }
}

/// Who asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    User,
    Admin,
    Job,
}

impl Actor {
    fn as_str(self) -> &'static str {
        match self {
            Actor::User => "user",
            Actor::Admin => "admin",
            Actor::Job => "job",
        }
    }
}

/// The account's subjects, one under each entry of the server key list.
fn subjects(keys: &OpaqueSetupKeys, account: Uuid) -> AppResult<(Vec<i32>, Vec<Vec<u8>>)> {
    let mut ids = Vec::new();
    let mut subjects = Vec::new();
    for id in keys.ids() {
        let entry = keys.get(id).expect("an id the list holds");
        let subject = kutup_crypto::server_data::destruction_subject(entry, account.as_bytes())
            .map_err(|_| AppError::internal("derive a destruction subject"))?;
        ids.push(i32::from(id));
        subjects.push(subject.to_vec());
    }
    if ids.is_empty() {
        return Err(AppError::internal(
            "the server key list (OPAQUE_SETUP_KEYS) is empty",
        ));
    }
    Ok((ids, subjects))
}

/// Records that `account` was destroyed, in the caller's transaction.
pub async fn record_account(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    account: Uuid,
    actor: Actor,
    reference: &str,
) -> AppResult<()> {
    let (ids, subjects) = subjects(keys, account)?;
    sqlx::query(
        "INSERT INTO account_keys.destruction_events
             (category, subject_key_ids, subjects, method, actor, reference)
         VALUES ('account', $1, $2, 'crypto_shred', $3, $4)",
    )
    .bind(&ids)
    .bind(&subjects)
    .bind(actor.as_str())
    .bind(reference)
    .execute(conn)
    .await?;
    Ok(())
}

/// Records a bulk deletion of `count` rows (retention), naming no account.
pub async fn record_bulk<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    category: Category,
    count: u64,
    reference: &str,
) -> AppResult<()> {
    if count == 0 {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO account_keys.destruction_events (category, method, actor, reference, count)
         VALUES ($1, 'delete', 'job', $2, $3)",
    )
    .bind(category.as_str())
    .bind(reference)
    .bind(i32::try_from(count).unwrap_or(i32::MAX))
    .execute(executor)
    .await?;
    Ok(())
}

/// At start: every kept destruction event names its account under at least
/// one entry of the server key list, else a restore could no longer match it
/// and bring a deleted account back. An entry stays in the list while
/// events made under it are kept, unless they were made under a newer
/// entry too.
pub async fn check_entries(pool: &PgPool, keys: &OpaqueSetupKeys) -> Result<(), String> {
    let ids: Vec<i32> = keys.ids().map(i32::from).collect();
    let orphaned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_keys.destruction_events
          WHERE subject_key_ids IS NOT NULL AND NOT (subject_key_ids && $1::integer[])",
    )
    .bind(&ids)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("read the destruction log: {e}"))?;
    if orphaned == 0 {
        Ok(())
    } else {
        Err(format!(
            "the server key list (OPAQUE_SETUP_KEYS) lacks every entry {orphaned} kept \
             destruction events were made under: a restore could not match those deleted \
             accounts. Put the entries back (docs/self-hosting.md, \"OPAQUE_SETUP_KEYS, the server key list\")"
        ))
    }
}

/// Accounts read per page by [`replay`].
const REPLAY_PAGE: i64 = 5000;

/// Before the server serves anything: every account this database holds that
/// the log says was destroyed (a restore from a dump taken before) loses its
/// data key and closes at once, for the closing job to finish. How many.
pub async fn replay(pool: &PgPool, keys: &OpaqueSetupKeys) -> AppResult<u64> {
    let destroyed: HashSet<Vec<u8>> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT DISTINCT unnest(subjects) FROM account_keys.destruction_events
          WHERE category = 'account' AND subjects IS NOT NULL",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();
    if destroyed.is_empty() {
        return Ok(0);
    }
    let mut found = Vec::new();
    let mut after = Uuid::nil();
    loop {
        let page: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE id > $1 ORDER BY id LIMIT $2")
                .bind(after)
                .bind(REPLAY_PAGE)
                .fetch_all(pool)
                .await?;
        let Some(last) = page.last() else { break };
        after = *last;
        for account in page {
            let (_, subjects) = subjects(keys, account)?;
            if subjects.iter().any(|subject| destroyed.contains(subject)) {
                found.push(account);
            }
        }
    }
    for account in &found {
        let mut tx = pool.begin().await?;
        // A legal hold in the restored database wins: nothing of that account
        // is destroyed. The operator decides, told loudly.
        let held: bool = sqlx::query_scalar(
            "SELECT legal_hold_reference IS NOT NULL FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;
        if held {
            tracing::error!(
                %account,
                "a restored account the destruction log destroyed is under a legal hold: kept, \
                 for the operator to decide"
            );
            continue;
        }
        sqlx::query("DELETE FROM account_keys.account_data_keys WHERE user_id = $1")
            .bind(account)
            .execute(&mut *tx)
            .await?;
        crate::account_closing::close(&mut tx, *account, ClosingBy::Restore, 0).await?;
        // One closing already deletes now too, whoever asked.
        sqlx::query(
            "UPDATE users SET closes_at = LEAST(closes_at, now()), closing_by = 'restore'
              WHERE id = $1 AND state = 'closing'",
        )
        .bind(account)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    Ok(found.len() as u64)
}

/// Deletes rows older than `days`, recording how many. As the owner (A8).
pub async fn prune(pool: &PgPool, days: i64) -> AppResult<u64> {
    let deleted = sqlx::query(
        "DELETE FROM account_keys.destruction_events WHERE at < now() - make_interval(days => $1::int)",
    )
    .bind(days as i32)
    .execute(pool)
    .await?
    .rows_affected();
    record_bulk(pool, Category::DestructionEvents, deleted, "retention").await?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    async fn user(pool: &PgPool) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '')",
        )
        .bind(user_id)
        .bind(format!("replay{}", &user_id.simple().to_string()[..12]))
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    /// A restore holds an account the log destroyed after the dump: at
    /// start its key goes and it closes at once; another account keeps its
    /// key and its state.
    #[tokio::test]
    async fn live_a_restored_destroyed_account_loses_its_key_and_closes() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let mut entry = [0u8; 32];
        kutup_crypto::primitives::random(&mut entry);
        let keys = OpaqueSetupKeys::parse(&format!(
            "7:{}",
            base64::engine::general_purpose::STANDARD.encode(entry)
        ))
        .unwrap();
        let (destroyed, other) = (user(&pool).await, user(&pool).await);
        for account in [destroyed, other] {
            crate::account_data::key(&pool, &keys, account)
                .await
                .unwrap();
        }
        // The log, after the dump: `destroyed` was deleted.
        let mut conn = pool.acquire().await.unwrap();
        record_account(&mut conn, &keys, destroyed, Actor::Admin, "user.delete")
            .await
            .unwrap();
        drop(conn);

        assert!(replay(&pool, &keys).await.unwrap() >= 1);
        let state = |account: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_as::<_, (String, Option<String>, bool, bool)>(
                    "SELECT state, closing_by, COALESCE(closes_at <= now(), false),
                            EXISTS (SELECT 1 FROM account_keys.account_data_keys k
                                     WHERE k.user_id = u.id)
                       FROM users u WHERE id = $1",
                )
                .bind(account)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let (s, by, due, has_key) = state(destroyed).await;
        assert_eq!(
            (s.as_str(), by.as_deref(), has_key),
            ("closing", Some("restore"), false)
        );
        assert!(due);
        let (s, _, _, has_key) = state(other).await;
        assert_eq!((s.as_str(), has_key), ("active", true));

        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(vec![destroyed, other])
            .execute(&pool)
            .await
            .unwrap();
        // Its event goes too (as the owner): left, it names entry 7, which
        // the server's own list lacks, and the server would refuse to start.
        sqlx::query("DELETE FROM account_keys.destruction_events WHERE subject_key_ids = '{7}'")
            .execute(&pool)
            .await
            .unwrap();
    }
}
