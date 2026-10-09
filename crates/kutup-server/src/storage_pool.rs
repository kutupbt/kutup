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
