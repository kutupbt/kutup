//! The account's one storage pool: Drive, Photos, Office, Maps and Chat
//! (and later Mail) all charge `users.storage_used_bytes` against
//! `users.storage_quota_bytes`, as Proton does with one storage figure per
//! account.
//!
//! Every write that adds stored bytes locks the user's row here, in the
//! same transaction as the row it inserts and the charge it makes, so
//! concurrent writers to one account queue and the pool is never
//! overcommitted. What is promised but not stored yet counts too: open tus
//! uploads (their whole declared length), open Chat-media uploads (what is
//! still to come) and Chat media another server is handing over.
//!
//! [`charge`] is the one place the counters change (an account's, or a mail
//! group's for its shared mailbox), in the transaction that stores or
//! deletes the bytes; [`charge_within_quota`] adds the room check for writes
//! that grow the pool. What fills the pool by app is summed from the tables
//! themselves (`GET /api/user/storage`).

use sqlx::{PgExecutor, Postgres, Transaction};
use uuid::Uuid;

/// An account's storage when nobody set another: 10 GiB, the
/// `users.storage_quota_bytes` column default (migration 001).
pub const DEFAULT_QUOTA_BYTES: i64 = 10 * 1024 * 1024 * 1024;

/// The `site_settings` key an administrator sets the quota new accounts get
/// with. Existing accounts keep theirs.
pub const DEFAULT_QUOTA_SETTING: &str = "default_storage_quota_bytes";

/// The quota a new account gets: the administrator's setting, else 10 GiB.
pub async fn default_quota<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<i64> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key = $1")
            .bind(DEFAULT_QUOTA_SETTING)
            .fetch_optional(executor)
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_QUOTA_BYTES),
    )
}

/// The reservation a check leaves out because it belongs to the very write
/// being checked (a tus upload being finalised, a federated hand-over being
/// committed), so it is not counted twice.
#[derive(Debug, Default, Clone, Copy)]
pub struct Leave<'a> {
    pub upload: Option<Uuid>,
    pub chat_upload: Option<Uuid>,
    /// A pending federated hand-over, by its `(origin, sequence)` key.
    pub inbound: Option<(&'a str, i64)>,
}

/// The account's pool, read under its row lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pool {
    pub quota: i64,
    pub used: i64,
    /// Bytes promised to writes still in flight.
    pub reserved: i64,
}

impl Pool {
    /// How many more bytes fit (negative when over quota).
    pub fn headroom(&self) -> i64 {
        self.quota
            .saturating_sub(self.used)
            .saturating_sub(self.reserved)
    }

    /// Whether `add` more bytes fit, with `allowance` beyond the quota
    /// (a write that only frees space later, see the Chat backup).
    pub fn fits(&self, add: i64, allowance: i64) -> bool {
        self.used
            .checked_add(self.reserved)
            .and_then(|total| total.checked_add(add))
            .is_some_and(|total| total <= self.quota.saturating_add(allowance))
    }
}

/// Locks `user_id`'s row until the transaction ends and reads their pool.
pub async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    leave: Leave<'_>,
) -> sqlx::Result<Pool> {
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let reserved = reserved(&mut **tx, user_id, leave).await?;
    Ok(Pool {
        quota,
        used,
        reserved,
    })
}

/// Whose pool a charge goes to: an account's, or a mail group's (its shared
/// mailbox has a pool of its own; docs/plans/mail-groups.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payer {
    Account(Uuid),
    MailGroup(Uuid),
}

/// Charges `delta` bytes to `payer`'s pool (`delta` < 0 frees them), never
/// below zero: the one place stored bytes are counted. The write that stores
/// or deletes them calls it in the same transaction; a write that adds bytes
/// checks the room first (`lock` and `Pool::fits`).
pub async fn charge<'e, E: PgExecutor<'e>>(
    executor: E,
    payer: Payer,
    delta: i64,
) -> sqlx::Result<()> {
    // The counter before, so a release past zero (an accounting slip the
    // reconciler will correct) is seen rather than hidden by the clamp.
    let (sql, id) = match payer {
        Payer::Account(id) => (
            "WITH before AS (SELECT storage_used_bytes AS used FROM users WHERE id = $1 FOR UPDATE)
             UPDATE users SET storage_used_bytes = GREATEST(before.used + $2, 0)
             FROM before WHERE users.id = $1 RETURNING before.used",
            id,
        ),
        Payer::MailGroup(id) => (
            "WITH before AS (SELECT storage_used_bytes AS used FROM mail_groups WHERE id = $1 FOR UPDATE)
             UPDATE mail_groups SET storage_used_bytes = GREATEST(before.used + $2, 0)
             FROM before WHERE mail_groups.id = $1 RETURNING before.used",
            id,
        ),
    };
    let before: Option<i64> = sqlx::query_scalar(sql)
        .bind(id)
        .bind(delta)
        .fetch_optional(executor)
        .await?;
    if let Some(used) = before.filter(|used| used.saturating_add(delta) < 0) {
        tracing::warn!(?payer, delta, used, "storage charge clamped at zero");
    }
    Ok(())
}

/// [`charge`] for a write that adds bytes within the account's quota:
/// locks its row, refuses (`413`) when `delta` more bytes don't fit, and
/// charges them. A negative `delta` always goes through.
pub async fn charge_within_quota(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    delta: i64,
) -> crate::error::AppResult<()> {
    let pool = lock(tx, user_id, Leave::default()).await?;
    if delta > 0 && !pool.fits(delta, 0) {
        return Err(crate::error::AppError::new(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        ));
    }
    charge(&mut **tx, Payer::Account(user_id), delta).await?;
    Ok(())
}

/// Bytes promised to `user_id`'s writes still in flight, less `leave`.
pub async fn reserved<'e, E: PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
    leave: Leave<'_>,
) -> sqlx::Result<i64> {
    let (origin, sequence) = match leave.inbound {
        Some((origin, sequence)) => (Some(origin), Some(sequence)),
        None => (None, None),
    };
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT SUM(total_bytes) FROM uploads
                           WHERE user_id = $1 AND id IS DISTINCT FROM $2), 0)::bigint
              + COALESCE((SELECT SUM(total_bytes - received_bytes) FROM chat_media_uploads
                           WHERE user_id = $1 AND id IS DISTINCT FROM $3), 0)::bigint
              + COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_media_federation_inbound_pending
                           WHERE recipient_user_id = $1
                             AND NOT (origin IS NOT DISTINCT FROM $4 AND sequence IS NOT DISTINCT FROM $5)), 0)::bigint",
    )
    .bind(user_id)
    .bind(leave.upload)
    .bind(leave.chat_upload)
    .bind(origin)
    .bind(sequence)
    .fetch_one(executor)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every write goes through [`charge`]: no other code (nor any
    /// migration) assigns the counters, except the two recounts that set
    /// them from what is stored (the reconciler in jobs.rs, an
    /// administrator's in admin.rs) and two test fixtures. The text is
    /// lowercased and its whitespace collapsed, so no line break, column
    /// list or `ON CONFLICT` form slips past.
    #[test]
    fn only_this_module_charges() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let column = ["storage", "used", "bytes"].join("_");
        let mut found = Vec::new();
        for base in ["src", "migrations"] {
            let mut stack = vec![root.join(base)];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    if !path
                        .extension()
                        .is_some_and(|ext| ext == "rs" || ext == "sql")
                    {
                        continue;
                    }
                    let text = std::fs::read_to_string(&path)
                        .unwrap()
                        .to_lowercase()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    let name = path
                        .strip_prefix(root.join("src"))
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned();
                    for (at, _) in text.match_indices(&column) {
                        // An assignment: `=` after the column, not `==`.
                        let rest = text[at + column.len()..].trim_start();
                        let Some(value) = rest.strip_prefix('=') else {
                            continue;
                        };
                        if value.starts_with('=') {
                            continue;
                        }
                        let value: String = value.trim_start().chars().take(16).collect();
                        found.push((name.clone(), value));
                    }
                }
            }
        }
        found.sort();
        let allowed = [
            // An administrator's recount from what the account stores.
            ("handlers/admin.rs", "( select coalesc"),
            // The reconciler's recounts: an account's and a mail group's.
            ("jobs.rs", "$2 where id = $1"),
            ("jobs.rs", "$2 where id = $1"),
            // Test fixtures: a drifted and a right counter, one each for an
            // account and for mail groups.
            ("jobs.rs", "$1 where id=$2\")"),
            ("jobs.rs", &format!("{column}+123")[..16]),
            ("jobs.rs", "$2 where id = $1"),
            ("jobs.rs", "500 where id = $"),
            // `charge`: an account's and a mail group's.
            ("storage_pool.rs", "greatest(before."),
            ("storage_pool.rs", "greatest(before."),
        ];
        let mut allowed: Vec<(String, String)> = allowed
            .iter()
            .map(|(file, value)| ((*file).to_owned(), (*value).to_owned()))
            .collect();
        allowed.sort();
        assert_eq!(found, allowed);
    }

    #[test]
    fn headroom_and_fits_count_what_is_reserved() {
        let pool = Pool {
            quota: 100,
            used: 60,
            reserved: 30,
        };
        assert_eq!(pool.headroom(), 10);
        assert!(pool.fits(10, 0));
        assert!(!pool.fits(11, 0));
        // An allowance beyond the quota (a backup tombstone) is not headroom.
        assert!(pool.fits(11, 1));
        let over = Pool {
            quota: 100,
            used: 101,
            reserved: 0,
        };
        assert!(over.headroom() < 0);
        assert!(!over.fits(0, 0));
        assert!(over.fits(0, 1));
    }

    #[test]
    fn fits_never_overflows() {
        let pool = Pool {
            quota: i64::MAX,
            used: i64::MAX,
            reserved: 1,
        };
        assert!(!pool.fits(1, 0));
    }
}
