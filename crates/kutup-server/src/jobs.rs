//! Background maintenance jobs — mirrors `backend/services/{version_cleanup,quota_reconcile,
//! uploads_sweeper,orphan_sweep}.go`.
//!
//! Three run as background tokio tasks for the server's lifetime (version cleanup, quota
//! reconcile, uploads sweeper — each runs once on boot, then on a fixed interval). The
//! orphan sweep is operator-driven (the `orphan-sweep` subcommand), dry-run by default.

use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chat_hub::ChatHub;
use crate::storage::StorageService;

// --- intervals / retention policy (mirror the Go defaults) ---
const VERSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);
const VERSION_KEEP_DAYS: i32 = 30;
const VERSION_KEEP_N: i32 = 50;
const QUOTA_RECONCILE_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const UPLOADS_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
const UPLOADS_STALE_AFTER_SECS: i64 = 24 * 3600;
const TRASH_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
const CHAT_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy)]
pub struct ChatMaintenancePolicy {
    pub mailbox_retention_days: i64,
    pub send_retention_days: i64,
    pub device_expiry_days: i64,
}

/// Spawns the lifetime background jobs (version cleanup, quota reconcile, uploads sweeper,
/// trash retention). Each runs once immediately, then on its interval.
/// `trash_retention_days == 0` disables the trash sweeper.
pub fn spawn_all(
    pool: PgPool,
    storage: StorageService,
    trash_retention_days: i64,
    chat: ChatMaintenancePolicy,
    chat_hub: ChatHub,
) {
    let (p1, s1) = (pool.clone(), storage.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(VERSION_CLEANUP_INTERVAL);
        loop {
            tick.tick().await;
            version_cleanup_tick(&p1, &s1).await;
        }
    });
    let p2 = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(QUOTA_RECONCILE_INTERVAL);
        loop {
            tick.tick().await;
            quota_reconcile_tick(&p2).await;
        }
    });
    if trash_retention_days > 0 {
        let (p3, s3) = (pool.clone(), storage.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TRASH_SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                trash_sweep_once(&p3, &s3, trash_retention_days).await;
            }
        });
    }
    if chat.mailbox_retention_days > 0
        || chat.send_retention_days > 0
        || chat.device_expiry_days > 0
    {
        let chat_pool = pool.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CHAT_SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                chat_maintenance_once(&chat_pool, chat, Some(&chat_hub)).await;
            }
        });
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(UPLOADS_SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            uploads_sweep_once(&pool, &storage).await;
        }
    });
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChatSweepResult {
    pub mailbox_rows: u64,
    pub send_rows: u64,
    pub devices: u64,
}

/// Bound offline-ciphertext and idempotency storage and retire abandoned chat
/// devices. Device deletion cascades its prekeys and mailbox. Its account's
/// signed manifest intentionally becomes fail-closed until an active device
/// explicitly authorizes and publishes the removal.
pub async fn chat_maintenance_once(
    pool: &PgPool,
    policy: ChatMaintenancePolicy,
    chat_hub: Option<&ChatHub>,
) -> ChatSweepResult {
    let mut result = ChatSweepResult::default();
    if policy.mailbox_retention_days > 0 {
        match sqlx::query(
            "DELETE FROM chat_mailbox
             WHERE server_ts < now() - ($1 * interval '1 day')",
        )
        .bind(policy.mailbox_retention_days)
        .execute(pool)
        .await
        {
            Ok(done) => result.mailbox_rows = done.rows_affected(),
            Err(error) => tracing::warn!("chat maintenance: mailbox retention failed: {error}"),
        }
    }
    if policy.send_retention_days > 0 {
        match sqlx::query(
            "DELETE FROM chat_sends
             WHERE created_at < now() - ($1 * interval '1 day')",
        )
        .bind(policy.send_retention_days)
        .execute(pool)
        .await
        {
            Ok(done) => result.send_rows = done.rows_affected(),
            Err(error) => tracing::warn!("chat maintenance: send retention failed: {error}"),
        }
    }
    if policy.device_expiry_days > 0 {
        match sqlx::query_as::<_, (Uuid, i32)>(
            "DELETE FROM chat_devices
             WHERE COALESCE(last_seen_at, created_at) < now() - ($1 * interval '1 day')
             RETURNING user_id, device_id",
        )
        .bind(policy.device_expiry_days)
        .fetch_all(pool)
        .await
        {
            Ok(expired) => {
                result.devices = expired.len() as u64;
                if let Some(hub) = chat_hub {
                    for (user_id, device_id) in expired {
                        hub.close_device(user_id, device_id);
                    }
                }
            }
            Err(error) => tracing::warn!("chat maintenance: device expiry failed: {error}"),
        }
    }
    if result != ChatSweepResult::default() {
        tracing::info!(
            mailbox_rows = result.mailbox_rows,
            send_rows = result.send_rows,
            devices = result.devices,
            "chat maintenance complete"
        );
    }
    result
}

/// Prunes file_versions rows that are BOTH older than KEEP_DAYS AND beyond KEEP_N per file
/// (keep_forever exempt), deleting their S3 noncurrent objects and releasing the author's
/// quota — mirrors `VersionCleanup.tick`. Returns the number pruned.
pub async fn version_cleanup_tick(pool: &PgPool, storage: &StorageService) -> usize {
    let doomed: Vec<(Uuid, String, String, Uuid, i64)> = match sqlx::query_as(
        r#"WITH ranked AS (
             SELECT id, file_id, storage_path, s3_version_id, author_user_id, size_bytes,
                    created_at, keep_forever,
                    ROW_NUMBER() OVER (PARTITION BY file_id ORDER BY created_at DESC) AS rn
             FROM file_versions
           )
           SELECT id, storage_path, s3_version_id, author_user_id, size_bytes
           FROM ranked
           WHERE keep_forever = false
             AND rn > $1
             AND created_at < now() - make_interval(days => $2)"#,
    )
    .bind(VERSION_KEEP_N)
    .bind(VERSION_KEEP_DAYS)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("version cleanup: query failed: {e}");
            return 0;
        }
    };

    let mut pruned = 0;
    for (id, path, vid, author, size) in &doomed {
        if let Err(e) = storage.delete_object_version(path, vid).await {
            tracing::warn!("version cleanup: delete {path}@{vid} failed: {e}");
            continue;
        }
        if sqlx::query("DELETE FROM file_versions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .is_err()
        {
            continue;
        }
        // Quota release; best-effort (reconcile heals any miss).
        let _ = sqlx::query(
            "UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2",
        )
        .bind(size)
        .bind(author)
        .execute(pool)
        .await;
        pruned += 1;
    }
    if pruned > 0 {
        tracing::info!("version cleanup: pruned {pruned} versions");
    }
    pruned
}

/// Rewrites `users.storage_used_bytes` from the authoritative row sums (files + file_assets +
/// file_versions) for any drifted user — mirrors `QuotaReconcile.Tick`. Returns the number of
/// users corrected.
pub async fn quota_reconcile_tick(pool: &PgPool) -> usize {
    let rows: Vec<(Uuid, i64)> = match sqlx::query_as(
        r#"WITH child_bytes AS (
             SELECT uploader_user_id AS user_id, encrypted_size_bytes AS bytes FROM files
             UNION ALL
             SELECT uploader_user_id,            size_bytes              FROM file_assets
             UNION ALL
             SELECT author_user_id,              size_bytes              FROM file_versions
           ),
           expected AS (
             SELECT u.id AS user_id, COALESCE(SUM(c.bytes), 0) AS bytes
             FROM users u
             LEFT JOIN child_bytes c ON c.user_id = u.id
             GROUP BY u.id
           )
           UPDATE users
           SET storage_used_bytes = expected.bytes
           FROM expected
           WHERE users.id = expected.user_id
             AND users.storage_used_bytes <> expected.bytes
           RETURNING users.id, users.storage_used_bytes"#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("quota reconcile: query failed: {e}");
            return 0;
        }
    };
    for (uid, used) in &rows {
        tracing::info!("quota reconcile: user={uid} storage_used_bytes={used} (drift corrected)");
    }
    if !rows.is_empty() {
        tracing::info!("quota reconcile: corrected {} users", rows.len());
    }
    rows.len()
}

/// Reaps abandoned tus uploads (rows whose `updated_at` is older than 24 h): aborts the S3
/// multipart, then drops the row (freeing soft-reserved quota) — mirrors
/// `UploadsSweeper.once`. Returns the number reaped.
pub async fn uploads_sweep_once(pool: &PgPool, storage: &StorageService) -> usize {
    let stale: Vec<(Uuid, String, String)> = match sqlx::query_as(
        "SELECT id, storage_path, s3_upload_id FROM uploads \
         WHERE updated_at < NOW() - $1 * interval '1 second'",
    )
    .bind(UPLOADS_STALE_AFTER_SECS)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("uploads-sweeper: list: {e}");
            return 0;
        }
    };
    let mut reaped = 0;
    for (id, path, s3_upload_id) in &stale {
        // Abort first; a failure leaves the row for the next sweep.
        if let Err(e) = storage.abort_multipart(path, s3_upload_id).await {
            tracing::warn!("uploads-sweeper: abort {id}: {e}");
            continue;
        }
        if sqlx::query("DELETE FROM uploads WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .is_err()
        {
            continue;
        }
        tracing::info!("uploads-sweeper: reaped upload={id} path={path}");
        reaped += 1;
    }
    reaped
}

// --- trash purge (shared by the trash endpoints + the retention sweeper) ---

/// Permanently purges one trashed file: releases the quota its blob + asset/version
/// children hold, deletes the row (FK-cascading the children), then GCs S3 — the same
/// sequence the old hard `DELETE /files/{id}` ran. A missing row is a no-op (another
/// purge path won the race).
pub async fn purge_file_root(
    pool: &PgPool,
    storage: &StorageService,
    file_id: Uuid,
) -> anyhow::Result<()> {
    let row: Option<(String, i64, Uuid)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes, uploader_user_id FROM files WHERE id = $1",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    let Some((storage_path, file_size, uploader_id)) = row else {
        return Ok(());
    };

    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"WITH per_uploader AS (
              SELECT uploader_user_id, COALESCE(SUM(size_bytes), 0) AS total
              FROM file_assets WHERE file_id = $1 GROUP BY uploader_user_id)
           UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - per_uploader.total)
           FROM per_uploader WHERE users.id = per_uploader.uploader_user_id"#,
    )
    .bind(file_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"WITH per_author AS (
              SELECT author_user_id, COALESCE(SUM(size_bytes), 0) AS total
              FROM file_versions WHERE file_id = $1 GROUP BY author_user_id)
           UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - per_author.total)
           FROM per_author WHERE users.id = per_author.author_user_id"#,
    )
    .bind(file_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM files WHERE id = $1")
        .bind(file_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2",
    )
    .bind(file_size)
    .bind(uploader_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // Best-effort S3 GC (post-commit): the legacy main blob + the whole files/{id}/ prefix.
    let _ = storage.delete(&storage_path).await;
    let _ = storage.delete_prefix(&format!("files/{file_id}/")).await;
    Ok(())
}

/// Permanently purges one trashed folder root: every file in its cascade-trashed
/// subtree (including files that had their own trash entry inside it — with the folder
/// gone they could never be restored), then the collection rows. Folders trashed
/// *independently* inside the subtree keep their own trash entry (their FK reparents
/// to NULL) and purge on their own schedule.
pub async fn purge_collection_root(
    pool: &PgPool,
    storage: &StorageService,
    root_id: Uuid,
) -> anyhow::Result<()> {
    let colls: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM collections WHERE trash_root_id = $1")
            .bind(root_id)
            .fetch_all(pool)
            .await?;
    if colls.is_empty() {
        return Ok(());
    }
    let files: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM files WHERE collection_id = ANY($1)")
        .bind(&colls)
        .fetch_all(pool)
        .await?;
    for fid in files {
        purge_file_root(pool, storage, fid).await?;
    }
    sqlx::query("DELETE FROM collections WHERE id = ANY($1)")
        .bind(&colls)
        .execute(pool)
        .await?;
    Ok(())
}

/// Purges every trash root older than `retention_days` — the 30-day-retention sweeper.
/// Returns the number of roots purged.
pub async fn trash_sweep_once(
    pool: &PgPool,
    storage: &StorageService,
    retention_days: i64,
) -> usize {
    let mut purged = 0;

    let coll_roots: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM collections WHERE trash_root_id = id \
         AND deleted_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(retention_days)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("trash sweep: list collection roots: {e}");
        Vec::new()
    });
    for root in coll_roots {
        match purge_collection_root(pool, storage, root).await {
            Ok(()) => purged += 1,
            Err(e) => tracing::warn!("trash sweep: purge collection {root}: {e:#}"),
        }
    }

    let file_roots: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM files WHERE trash_root_id = id \
         AND deleted_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(retention_days)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("trash sweep: list file roots: {e}");
        Vec::new()
    });
    for root in file_roots {
        match purge_file_root(pool, storage, root).await {
            Ok(()) => purged += 1,
            Err(e) => tracing::warn!("trash sweep: purge file {root}: {e:#}"),
        }
    }

    if purged > 0 {
        tracing::info!("trash sweep: purged {purged} expired trash roots");
    }
    purged
}

// --- orphan sweep (operator-driven subcommand) ---

/// Summary of one orphan-sweep pass — mirrors `services.SweepResult`.
#[derive(Debug, Default)]
pub struct SweepResult {
    pub pages_scanned: u64,
    pub keys_scanned: u64,
    pub orphans_found: u64,
    pub bytes_reclaimed: i64,
    pub skipped_age: u64,
    pub skipped_shape: u64,
    pub deleted: u64,
}

/// Extracts the file UUID from a `files/<uuid>/…` key, requiring the canonical lower-hex
/// 8-4-4-4-12 shape (matches Postgres `id::text`) — mirrors `fileIDFromKey`.
fn file_id_from_key(key: &str) -> Option<String> {
    let rest = key.strip_prefix("files/")?;
    let seg = rest.split('/').next()?;
    if rest.len() == seg.len() {
        return None; // no trailing '/', i.e. not `files/<uuid>/…`
    }
    let is_canonical = seg.len() == 36
        && seg.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        });
    is_canonical.then(|| seg.to_string())
}

/// Walks the bucket under `prefix`, deleting (or, in dry-run, just reporting) blobs whose
/// `file_id` has no `files` row and that are older than `age_floor` — mirrors `OrphanSweep.Run`.
pub async fn run_orphan_sweep(
    pool: &PgPool,
    storage: &StorageService,
    prefix: &str,
    age_floor: Duration,
    page_sleep: Duration,
    delete: bool,
) -> anyhow::Result<SweepResult> {
    let mut res = SweepResult::default();
    let cutoff = OffsetDateTime::now_utc() - age_floor;
    let mut token: Option<String> = None;

    loop {
        let (objs, next) = storage.list_objects_page(prefix, token.clone()).await?;
        res.pages_scanned += 1;
        res.keys_scanned += objs.len() as u64;

        // Age + shape filter → candidates.
        let mut cands: Vec<(String, String, i64)> = Vec::with_capacity(objs.len());
        for o in &objs {
            if o.last_modified > cutoff {
                res.skipped_age += 1;
                continue;
            }
            match file_id_from_key(&o.key) {
                Some(fid) => cands.push((o.key.clone(), fid, o.size)),
                None => res.skipped_shape += 1,
            }
        }

        if !cands.is_empty() {
            // Which of the candidate file ids are still alive?
            let mut fids: Vec<Uuid> = cands
                .iter()
                .filter_map(|(_, f, _)| Uuid::parse_str(f).ok())
                .collect();
            fids.sort();
            fids.dedup();
            let alive: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM files WHERE id = ANY($1)")
                .bind(&fids)
                .fetch_all(pool)
                .await?;
            let alive_set: std::collections::HashSet<String> =
                alive.iter().map(|u| u.to_string()).collect();

            let mut orphan_keys: Vec<String> = Vec::new();
            for (key, fid, size) in &cands {
                if alive_set.contains(fid) {
                    continue;
                }
                res.orphans_found += 1;
                res.bytes_reclaimed += size;
                orphan_keys.push(key.clone());
                let action = if delete { "delete" } else { "dry-run" };
                tracing::info!("orphan-sweep: orphan key={key} size={size} action={action}");
            }

            if delete && !orphan_keys.is_empty() {
                match storage.delete_objects_batch(&orphan_keys).await {
                    Ok(()) => res.deleted += orphan_keys.len() as u64,
                    Err(e) => tracing::warn!("orphan-sweep: delete batch failed: {e}"),
                }
            }
        }

        if !page_sleep.is_zero() {
            tokio::time::sleep(page_sleep).await;
        }
        match next {
            Some(t) => token = Some(t),
            None => break,
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::file_id_from_key;

    #[test]
    fn key_shape() {
        let uuid = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";
        assert_eq!(
            file_id_from_key(&format!("files/{uuid}/snapshot")).as_deref(),
            Some(uuid)
        );
        assert_eq!(
            file_id_from_key(&format!("files/{uuid}/assets/x")).as_deref(),
            Some(uuid)
        );
        // No trailing slash, foreign prefix, uppercase hex, short → skipped.
        assert_eq!(file_id_from_key(&format!("files/{uuid}")), None);
        assert_eq!(file_id_from_key("fed/abc/def"), None);
        assert_eq!(
            file_id_from_key("files/0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9/x"),
            None
        );
        assert_eq!(file_id_from_key("files/not-a-uuid/x"), None);
    }
}
