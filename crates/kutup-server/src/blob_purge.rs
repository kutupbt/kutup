//! Deleted blobs leave the object store only after a wait
//! (docs/plans/restore-drill-and-alerting.md, gap 5).
//!
//! Every delete the server makes is queued in `storage_pending_deletions`
//! (`StorageService::with_deferred_deletes`); this job removes the ones
//! queued at least `server.storage.deleted_blob_retention_seconds` ago. A database
//! dump taken before a delete is restored with its blobs still there, as long
//! as the dump is younger than that wait: set it to the backup interval plus
//! a margin.

use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;

use crate::site_settings::{
    STORAGE_DELETED_BLOB_RETENTION_SECONDS, STORAGE_DELETED_BLOB_SWEEP_SECONDS,
};
use crate::storage::{PendingKind, StorageService};

/// The job's name in `job_heartbeats` and `/api/health/ready`.
pub const JOB: &str = "storage.deleted_blob_purge";

/// Rows taken (and locked) per batch.
const BATCH: i64 = 100;

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PurgeResult {
    pub deleted: u64,
    pub failed: u64,
}

/// Runs [`purge_due`] every `server.storage.deleted_blob_sweep_seconds`, with the
/// interval and the wait read again as it goes, so a change applies without
/// a restart.
/// `storage` must be the immediate store ([`StorageService::immediate`]).
pub fn spawn(pool: PgPool, storage: StorageService) {
    tokio::spawn(async move {
        let mut last_run: Option<std::time::Instant> = None;
        loop {
            let every = STORAGE_DELETED_BLOB_SWEEP_SECONDS
                .load(&pool)
                .await
                .unwrap_or(STORAGE_DELETED_BLOB_SWEEP_SECONDS.default);
            let every = Duration::from_secs(every.max(1) as u64);
            crate::job_health::register(JOB, every);
            if last_run.is_none_or(|at| at.elapsed() >= every) {
                last_run = Some(std::time::Instant::now());
                pass(&pool, &storage).await;
            }
            // The interval is read again every few seconds, so a shorter
            // one applies at once, not after the longer wait.
            tokio::time::sleep(every.min(RECHECK)).await;
        }
    });
}

/// How often [`spawn`]'s loop rereads its interval.
const RECHECK: Duration = Duration::from_secs(5);

/// One pass, with the wait as it is set now.
async fn pass(pool: &PgPool, storage: &StorageService) {
    match STORAGE_DELETED_BLOB_RETENTION_SECONDS.load(pool).await {
        Ok(retention) => match purge_due(pool, storage, retention).await {
            Ok(result) => {
                if result.deleted > 0 || result.failed > 0 {
                    tracing::info!(
                        deleted = result.deleted,
                        failed = result.failed,
                        "storage: purged deleted blobs past their wait"
                    );
                }
                if result.failed == 0 {
                    crate::job_health::beat(pool, JOB).await;
                }
            }
            Err(error) => tracing::warn!(%error, "storage: deleted blob purge failed"),
        },
        Err(error) => tracing::warn!(%error, "storage: deleted blob wait not read"),
    }
}

/// Removes from the store every queued delete older than `retention_seconds`,
/// a batch at a time. Each batch's rows stay locked while their objects are
/// deleted, so a write to one of those keys (which first calls its delete
/// off) waits for the purge and lands after it. A delete the store refuses
/// stays queued and is tried again on the next pass.
pub async fn purge_due(
    pool: &PgPool,
    storage: &StorageService,
    retention_seconds: i64,
) -> anyhow::Result<PurgeResult> {
    let mut result = PurgeResult::default();
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(retention_seconds.max(0));
    // Rows that failed in this pass: left for the next one.
    let mut failed: Vec<i64> = Vec::new();
    loop {
        let mut tx = pool.begin().await?;
        let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT id, kind, key, version_id FROM storage_pending_deletions
             WHERE queued_at <= $1 AND NOT (id = ANY($2))
             ORDER BY queued_at, id
             LIMIT $3
             FOR UPDATE SKIP LOCKED",
        )
        .bind(cutoff)
        .bind(&failed)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            tx.commit().await?;
            return Ok(result);
        }
        let mut done: Vec<i64> = Vec::with_capacity(rows.len());
        for (id, kind, key, version_id) in rows {
            let outcome = match PendingKind::parse(&kind) {
                Some(PendingKind::Object) => storage.delete(&key).await,
                Some(PendingKind::Stored) => storage.delete_stored(&key, &version_id).await,
                Some(PendingKind::Version) => {
                    storage.delete_object_version(&key, &version_id).await
                }
                Some(PendingKind::Prefix) => storage.delete_prefix(&key).await,
                None => Err(anyhow::anyhow!("unknown kind {kind}")),
            };
            match outcome {
                Ok(()) => done.push(id),
                Err(error) => {
                    tracing::warn!(%key, %kind, error = %format!("{error:#}"), "storage: queued delete failed");
                    sqlx::query(
                        "UPDATE storage_pending_deletions
                         SET attempts = attempts + 1, last_error = $2 WHERE id = $1",
                    )
                    .bind(id)
                    .bind(format!("{error:#}"))
                    .execute(&mut *tx)
                    .await?;
                    failed.push(id);
                    result.failed += 1;
                }
            }
        }
        sqlx::query("DELETE FROM storage_pending_deletions WHERE id = ANY($1)")
            .bind(&done)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        result.deleted += done.len() as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::primitives::ByteStream;

    /// A live database and object store (the `KUTUP_LIVE_*` settings the
    /// other live job tests use), or `None` to skip.
    async fn live() -> Option<(PgPool, StorageService)> {
        let (Ok(database_url), Ok(s3_endpoint)) = (
            std::env::var("KUTUP_LIVE_DATABASE_URL"),
            std::env::var("KUTUP_LIVE_S3_ENDPOINT"),
        ) else {
            eprintln!("live database/S3 settings unset — skipping live blob purge test");
            return None;
        };
        let storage = StorageService::new(
            &s3_endpoint,
            &std::env::var("KUTUP_LIVE_S3_ACCESS_KEY").unwrap(),
            &std::env::var("KUTUP_LIVE_S3_SECRET_KEY").unwrap(),
            &std::env::var("KUTUP_LIVE_S3_BUCKET").unwrap(),
            "us-east-1",
            crate::storage::S3Timeouts::default(),
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .unwrap();
        Some((pool, storage))
    }

    async fn put(storage: &StorageService, key: &str, bytes: &[u8]) {
        storage
            .upload(key, ByteStream::from(bytes.to_vec()), bytes.len() as i64)
            .await
            .unwrap();
    }

    async fn read(storage: &StorageService, key: &str) -> Option<Vec<u8>> {
        let (body, _) = storage.get_object(key).await.ok()?;
        Some(body.collect().await.unwrap().into_bytes().to_vec())
    }

    /// Pretends the rows of `prefix` were queued `seconds` ago.
    async fn age(pool: &PgPool, prefix: &str, seconds: i64) {
        sqlx::query(
            "UPDATE storage_pending_deletions
             SET queued_at = now() - make_interval(secs => $2)
             WHERE key LIKE $1 || '%'",
        )
        .bind(prefix)
        .bind(seconds as f64)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn waiting(pool: &PgPool, prefix: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM storage_pending_deletions WHERE key LIKE $1 || '%'",
        )
        .bind(prefix)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// A delete waits for its retention: the blob is still readable (a
    /// restored dump could name it), then goes once the wait is over.
    #[tokio::test]
    async fn live_deleted_blobs_wait_for_their_retention() {
        let Some((pool, plain)) = live().await else {
            return;
        };
        let deferred = plain.clone().with_deferred_deletes(pool.clone());
        let root = format!("blob-purge-test/{}/", uuid::Uuid::new_v4());
        let one = format!("{root}one");
        let two = format!("{root}two");
        let under = format!("{root}dir/");
        put(&plain, &one, b"one").await;
        put(&plain, &two, b"two").await;
        put(&plain, &format!("{under}a"), b"a").await;

        deferred.delete(&one).await.unwrap();
        deferred
            .delete_objects_batch(std::slice::from_ref(&two))
            .await
            .unwrap();
        deferred.delete_prefix(&under).await.unwrap();
        // Queued twice: one row, the first time kept.
        deferred.delete(&one).await.unwrap();
        assert_eq!(waiting(&pool, &root).await, 3);
        // Nothing is gone yet.
        assert_eq!(read(&plain, &one).await.as_deref(), Some(&b"one"[..]));
        assert_eq!(read(&plain, &two).await.as_deref(), Some(&b"two"[..]));
        assert!(read(&plain, &format!("{under}a")).await.is_some());

        // Within the wait: nothing of these goes.
        purge_due(&pool, &plain, 3600).await.unwrap();
        assert_eq!(waiting(&pool, &root).await, 3);
        assert!(read(&plain, &one).await.is_some());

        // Past it: all go, and the queue is empty.
        age(&pool, &root, 7200).await;
        purge_due(&pool, &plain, 3600).await.unwrap();
        assert_eq!(waiting(&pool, &root).await, 0);
        assert!(read(&plain, &one).await.is_none());
        assert!(read(&plain, &two).await.is_none());
        assert!(read(&plain, &format!("{under}a")).await.is_none());
        pool.close().await;
    }

    /// A key written again after its delete was queued keeps the new
    /// object: the write calls the delete off.
    #[tokio::test]
    async fn live_a_new_write_calls_a_queued_delete_off() {
        let Some((pool, plain)) = live().await else {
            return;
        };
        let deferred = plain.clone().with_deferred_deletes(pool.clone());
        let root = format!("blob-purge-test/{}/", uuid::Uuid::new_v4());
        let key = format!("{root}reused");
        put(&deferred, &key, b"old").await;
        deferred.delete(&key).await.unwrap();
        assert_eq!(waiting(&pool, &root).await, 1);
        put(&deferred, &key, b"new").await;
        assert_eq!(waiting(&pool, &root).await, 0);
        age(&pool, &root, 7200).await;
        purge_due(&pool, &plain, 3600).await.unwrap();
        assert_eq!(read(&plain, &key).await.as_deref(), Some(&b"new"[..]));
        plain.delete(&key).await.unwrap();
        pool.close().await;
    }

    /// Wait zero: a queued delete goes on the next pass.
    #[tokio::test]
    async fn live_zero_wait_purges_on_the_next_pass() {
        let Some((pool, plain)) = live().await else {
            return;
        };
        let deferred = plain.clone().with_deferred_deletes(pool.clone());
        let root = format!("blob-purge-test/{}/", uuid::Uuid::new_v4());
        let key = format!("{root}soon");
        put(&plain, &key, b"soon").await;
        deferred.delete(&key).await.unwrap();
        let result = purge_due(&pool, &plain, 0).await.unwrap();
        assert!(result.deleted >= 1);
        assert_eq!(waiting(&pool, &root).await, 0);
        assert!(read(&plain, &key).await.is_none());
        pool.close().await;
    }
}
