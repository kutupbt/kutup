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
    pub media_delivery_retention_days: i64,
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
    let chat_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHAT_SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            chat_maintenance_once(&chat_pool, chat, Some(&chat_hub)).await;
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(UPLOADS_SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            uploads_sweep_once(&pool, &storage, chat.media_delivery_retention_days).await;
        }
    });
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChatSweepResult {
    pub mailbox_rows: u64,
    pub mls_mailbox_rows: u64,
    pub send_rows: u64,
    pub federation_send_rows: u64,
    pub federation_transaction_rows: u64,
    pub devices: u64,
    pub ws_tickets: u64,
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
    let mailbox_retention_days = crate::site_settings::chat_delivery_retention_days(
        pool,
        crate::site_settings::CHAT_MAILBOX_RETENTION_DAYS,
        policy.mailbox_retention_days,
    )
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(%error, "chat maintenance: retention setting unavailable; mailbox cleanup skipped");
        0
    });
    match sqlx::query("DELETE FROM chat_ws_tickets WHERE expires_at <= now()")
        .execute(pool)
        .await
    {
        Ok(done) => result.ws_tickets = done.rows_affected(),
        Err(error) => tracing::warn!("chat maintenance: WS ticket cleanup failed: {error}"),
    }
    if mailbox_retention_days > 0 {
        let cutoff = OffsetDateTime::now_utc()
            - Duration::from_secs((mailbox_retention_days as u64).saturating_mul(86_400));
        match sweep_chat_mailboxes_before(pool, cutoff).await {
            Ok((direct, mls)) => {
                result.mailbox_rows = direct;
                result.mls_mailbox_rows = mls;
            }
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
        match sqlx::query(
            "DELETE FROM chat_federation_outbox
             WHERE state = 'delivered'
               AND updated_at < now() - ($1 * interval '1 day')",
        )
        .bind(policy.send_retention_days)
        .execute(pool)
        .await
        {
            Ok(done) => result.federation_send_rows = done.rows_affected(),
            Err(error) => {
                tracing::warn!("chat maintenance: federation send retention failed: {error}")
            }
        }
        match sqlx::query(
            "DELETE FROM chat_federation_inbound_transactions
             WHERE created_at < now() - ($1 * interval '1 day')",
        )
        .bind(policy.send_retention_days)
        .execute(pool)
        .await
        {
            Ok(done) => result.federation_transaction_rows = done.rows_affected(),
            Err(error) => {
                tracing::warn!("chat maintenance: federation transaction retention failed: {error}")
            }
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
            mls_mailbox_rows = result.mls_mailbox_rows,
            send_rows = result.send_rows,
            federation_send_rows = result.federation_send_rows,
            federation_transaction_rows = result.federation_transaction_rows,
            devices = result.devices,
            ws_tickets = result.ws_tickets,
            "chat maintenance complete"
        );
    }
    result
}

/// Delete Direct and MLS delivery ciphertext strictly older than an explicit
/// cutoff. Keeping cutoff calculation outside the repository operation makes
/// exact-boundary tests deterministic without exposing a production endpoint.
pub async fn sweep_chat_mailboxes_before(
    pool: &PgPool,
    cutoff: OffsetDateTime,
) -> anyhow::Result<(u64, u64)> {
    let mut transaction = pool.begin().await?;
    let direct = sqlx::query("DELETE FROM chat_mailbox WHERE server_ts < $1")
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    let mls = sqlx::query("DELETE FROM chat_mls_mailbox WHERE server_ts < $1")
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    transaction.commit().await?;
    Ok((direct, mls))
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

/// Rewrites the independent Drive/general and Chat usage counters from their
/// authoritative logical references for any drifted user.
pub async fn quota_reconcile_tick(pool: &PgPool) -> usize {
    let rows: Vec<(Uuid, i64, i64)> = match sqlx::query_as(
        r#"WITH drive_child_bytes AS (
             SELECT uploader_user_id AS user_id, encrypted_size_bytes AS bytes FROM files
             UNION ALL
             SELECT uploader_user_id,            size_bytes              FROM file_assets
             UNION ALL
             SELECT author_user_id,              size_bytes              FROM file_versions
           ),
           chat_child_bytes AS (
             SELECT user_id, logical_bytes AS bytes FROM chat_media_references
             UNION ALL
             SELECT user_id, ciphertext_bytes FROM chat_backup_segments
             UNION ALL
             SELECT user_id, ciphertext_bytes FROM chat_backup_bases
             UNION ALL
             SELECT user_id, ciphertext_bytes FROM chat_backup_media_objects
           ),
           expected AS (
             SELECT u.id AS user_id,
                    COALESCE((SELECT SUM(d.bytes) FROM drive_child_bytes d WHERE d.user_id=u.id),0) AS drive_bytes,
                    COALESCE((SELECT SUM(c.bytes) FROM chat_child_bytes c WHERE c.user_id=u.id),0) AS chat_bytes
             FROM users u
           )
           UPDATE users
           SET storage_used_bytes = expected.drive_bytes,
               chat_storage_used_bytes = expected.chat_bytes
           FROM expected
           WHERE users.id = expected.user_id
             AND (users.storage_used_bytes <> expected.drive_bytes
                  OR users.chat_storage_used_bytes <> expected.chat_bytes)
           RETURNING users.id, users.storage_used_bytes, users.chat_storage_used_bytes"#,
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
    for (uid, drive_used, chat_used) in &rows {
        tracing::info!(
            "quota reconcile: user={uid} drive_bytes={drive_used} chat_bytes={chat_used} (drift corrected)"
        );
    }
    if !rows.is_empty() {
        tracing::info!("quota reconcile: corrected {} users", rows.len());
    }
    rows.len()
}

/// Reaps abandoned tus uploads (rows whose `updated_at` is older than 24 h): aborts the S3
/// multipart, then drops the row (freeing soft-reserved quota) — mirrors
/// `UploadsSweeper.once`. Returns the number reaped.
pub async fn uploads_sweep_once(
    pool: &PgPool,
    storage: &StorageService,
    media_delivery_retention_days: i64,
) -> usize {
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
    let stale_media: Vec<(Uuid, String, String)> = match sqlx::query_as(
        "SELECT id, storage_path, s3_upload_id FROM chat_media_uploads \
         WHERE updated_at < NOW() - $1 * interval '1 second'",
    )
    .bind(UPLOADS_STALE_AFTER_SECS)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(error = %error, "Chat-media upload sweeper list failed");
            return reaped;
        }
    };
    for (id, path, s3_upload_id) in stale_media {
        if storage.abort_multipart(&path, &s3_upload_id).await.is_err() {
            continue;
        }
        if sqlx::query("DELETE FROM chat_media_uploads WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await
            .is_ok()
        {
            // Do not emit user, attachment, token, or storage-path identifiers.
            tracing::info!("reaped one abandoned Chat-media upload");
            reaped += 1;
        }
    }
    if let Err(error) = sweep_chat_media_orphans(pool, storage).await {
        tracing::warn!(error = %error, "Chat-media orphan sweep failed");
    }
    if let Err(error) = sweep_chat_backup_orphans(pool, storage).await {
        tracing::warn!(error = %error, "Chat backup orphan sweep failed");
    }
    let media_delivery_retention_days = crate::site_settings::chat_delivery_retention_days(
        pool,
        crate::site_settings::CHAT_MEDIA_DELIVERY_RETENTION_DAYS,
        media_delivery_retention_days,
    )
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(%error, "upload maintenance: retention setting unavailable; delivery-media cleanup skipped");
        0
    });
    if media_delivery_retention_days > 0 {
        let cutoff = OffsetDateTime::now_utc()
            - Duration::from_secs((media_delivery_retention_days as u64).saturating_mul(86_400));
        if let Err(error) = sweep_chat_delivery_media_before(pool, storage, cutoff).await {
            tracing::warn!(error = %error, "Chat-media delivery retention sweep failed");
        }
    }
    if let Err(error) = sweep_expired_chat_backup_staging(pool, storage).await {
        tracing::warn!(error = %error, "Chat backup staging sweep failed");
    }
    reaped
}

async fn sweep_expired_chat_backup_staging(
    pool: &PgPool,
    storage: &StorageService,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let expired: Vec<(Uuid, Uuid, i64, i64, String)> = sqlx::query_as(
        "SELECT user_id,object_id,generation,ciphertext_bytes,storage_path
         FROM chat_backup_bases
         WHERE state='staged' AND expires_at<=NOW()
         ORDER BY expires_at LIMIT 64 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for (user_id, object_id, generation, bytes, _) in &expired {
        sqlx::query("DELETE FROM chat_backup_bases WHERE user_id=$1 AND object_id=$2")
            .bind(user_id)
            .bind(object_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "DELETE FROM chat_backup_media_reconciliations
             WHERE user_id=$1 AND target_generation=$2",
        )
        .bind(user_id)
        .bind(generation)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE users SET chat_storage_used_bytes=GREATEST(0,chat_storage_used_bytes-$1)
             WHERE id=$2",
        )
        .bind(bytes)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    for (_, _, _, _, path) in &expired {
        if let Err(error) = storage.delete(path).await {
            tracing::warn!(error = %error, "expired backup base requires orphan sweep");
        }
    }
    if !expired.is_empty() {
        tracing::info!(objects = expired.len(), "expired staged Chat backup bases");
    }
    Ok(())
}

/// Expire ordinary delivery references after the administrator-selected window while leaving the
/// independent continuous-history media namespace untouched.
pub async fn sweep_chat_delivery_media_before(
    pool: &PgPool,
    storage: &StorageService,
    cutoff: OffsetDateTime,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let expired: Vec<(Uuid, Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT id,user_id,attachment_id,logical_bytes
         FROM chat_media_references
         WHERE created_at < $1
         ORDER BY created_at
         LIMIT 512 FOR UPDATE SKIP LOCKED",
    )
    .bind(cutoff)
    .fetch_all(&mut *transaction)
    .await?;
    if expired.is_empty() {
        transaction.rollback().await?;
        return Ok(());
    }
    for (reference_id, user_id, _, bytes) in &expired {
        sqlx::query("DELETE FROM chat_media_references WHERE id=$1")
            .bind(reference_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE users
             SET chat_storage_used_bytes=GREATEST(chat_storage_used_bytes-$1,0)
             WHERE id=$2",
        )
        .bind(bytes)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    }
    let attachment_ids: Vec<Uuid> = expired
        .iter()
        .map(|(_, _, attachment_id, _)| *attachment_id)
        .collect();
    let orphan_paths: Vec<String> = sqlx::query_scalar(
        "DELETE FROM chat_media_objects o
         WHERE o.attachment_id = ANY($1)
           AND NOT EXISTS (
             SELECT 1 FROM chat_media_references r WHERE r.attachment_id=o.attachment_id
           )
         RETURNING o.storage_path",
    )
    .bind(&attachment_ids)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    for path in orphan_paths {
        if let Err(error) = storage.delete(&path).await {
            tracing::warn!(error = %error, "expired Chat-media object requires orphan sweep");
        }
    }
    tracing::info!(
        references = expired.len(),
        "expired Chat-media delivery references"
    );
    Ok(())
}

/// Remove completed Chat-media objects whose database transaction never
/// committed. Object identifiers and paths are deliberately absent from logs.
async fn sweep_chat_media_orphans(pool: &PgPool, storage: &StorageService) -> anyhow::Result<()> {
    let cutoff = OffsetDateTime::now_utc() - Duration::from_secs(UPLOADS_STALE_AFTER_SECS as u64);
    let mut token = None;
    let mut removed = 0_u64;
    loop {
        let (objects, next) = storage
            .list_objects_page("chat-media/", token.take())
            .await?;
        let candidates: Vec<String> = objects
            .into_iter()
            .filter(|object| object.last_modified <= cutoff)
            .map(|object| object.key)
            .collect();
        if !candidates.is_empty() {
            let alive: Vec<String> = sqlx::query_scalar(
                "SELECT storage_path FROM chat_media_objects WHERE storage_path=ANY($1)",
            )
            .bind(&candidates)
            .fetch_all(pool)
            .await?;
            let alive: std::collections::HashSet<_> = alive.into_iter().collect();
            let orphaned: Vec<String> = candidates
                .into_iter()
                .filter(|path| !alive.contains(path))
                .collect();
            storage.delete_objects_batch(&orphaned).await?;
            removed = removed.saturating_add(orphaned.len() as u64);
        }
        match next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    if removed > 0 {
        tracing::info!(removed, "removed orphaned Chat-media objects");
    }
    Ok(())
}

/// Reconcile object storage after interrupted staging, CAS replacement or
/// account-lifecycle cleanup. Only database-referenced opaque objects survive.
async fn sweep_chat_backup_orphans(pool: &PgPool, storage: &StorageService) -> anyhow::Result<()> {
    let cutoff = OffsetDateTime::now_utc() - Duration::from_secs(UPLOADS_STALE_AFTER_SECS as u64);
    let mut token = None;
    let mut removed = 0_u64;
    loop {
        let (objects, next) = storage
            .list_objects_page("chat-backup/", token.take())
            .await?;
        let candidates: Vec<String> = objects
            .into_iter()
            .filter(|object| object.last_modified <= cutoff)
            .map(|object| object.key)
            .collect();
        if !candidates.is_empty() {
            let alive: Vec<String> = sqlx::query_scalar(
                "SELECT storage_path FROM chat_backup_bases WHERE storage_path=ANY($1)
                 UNION ALL
                 SELECT storage_path FROM chat_backup_media_objects WHERE storage_path=ANY($1)",
            )
            .bind(&candidates)
            .fetch_all(pool)
            .await?;
            let alive: std::collections::HashSet<_> = alive.into_iter().collect();
            let orphaned: Vec<String> = candidates
                .into_iter()
                .filter(|path| !alive.contains(path))
                .collect();
            storage.delete_objects_batch(&orphaned).await?;
            removed = removed.saturating_add(orphaned.len() as u64);
        }
        match next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    if removed > 0 {
        tracing::info!(removed, "removed orphaned Chat backup objects");
    }
    Ok(())
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
    use super::{
        file_id_from_key, quota_reconcile_tick, sweep_chat_delivery_media_before,
        sweep_chat_mailboxes_before,
    };
    use crate::storage::StorageService;
    use aws_sdk_s3::primitives::ByteStream;
    use sha2::Digest;

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

    #[tokio::test]
    async fn live_fixed_cutoff_mailbox_retention() {
        let Ok(database_url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset — skipping live retention test");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let (user_id, device_id): (uuid::Uuid, i32) = sqlx::query_as(
            "SELECT user_id,device_id FROM chat_devices ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("live Chat device fixture");
        sqlx::query(
            "INSERT INTO chat_mls_devices
             (user_id,device_id,manifest_version,suite,credential_public_key,
              anonymous_delivery_public_key,name)
             VALUES ($1,$2,1,3,$3,$4,'retention fixture')
             ON CONFLICT (user_id,device_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(vec![0x31u8; 32])
        .bind(vec![0x32u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        let direct_id: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM chat_mailbox WHERE recipient_user_id=$1 LIMIT 1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("live Direct mailbox fixture");
        let mls_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO chat_mls_mailbox
             (id,recipient_user_id,recipient_device_id,delivery_kind,send_id,opaque_envelope)
             VALUES ($1,$2,$3,'anonymous',$4,$5)",
        )
        .bind(mls_id)
        .bind(user_id)
        .bind(device_id)
        .bind(uuid::Uuid::new_v4())
        .bind(vec![0x41u8])
        .execute(&pool)
        .await
        .unwrap();
        let cutoff = time::OffsetDateTime::now_utc();
        sqlx::query("UPDATE chat_mailbox SET server_ts=$1 WHERE id=$2")
            .bind(cutoff)
            .bind(direct_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE chat_mls_mailbox SET server_ts=$1 WHERE id=$2")
            .bind(cutoff)
            .bind(mls_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            sweep_chat_mailboxes_before(&pool, cutoff).await.unwrap(),
            (0, 0)
        );
        sqlx::query("UPDATE chat_mailbox SET server_ts=$1 WHERE id=$2")
            .bind(cutoff - time::Duration::SECOND)
            .bind(direct_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE chat_mls_mailbox SET server_ts=$1 WHERE id=$2")
            .bind(cutoff - time::Duration::SECOND)
            .bind(mls_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            sweep_chat_mailboxes_before(&pool, cutoff).await.unwrap(),
            (1, 1)
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn live_fixed_cutoff_delivery_media_retention() {
        let (Ok(database_url), Ok(s3_endpoint)) = (
            std::env::var("KUTUP_LIVE_DATABASE_URL"),
            std::env::var("KUTUP_LIVE_S3_ENDPOINT"),
        ) else {
            eprintln!("live database/S3 settings unset — skipping live media-retention test");
            return;
        };
        let storage = StorageService::new(
            &s3_endpoint,
            &std::env::var("KUTUP_LIVE_S3_ACCESS_KEY").unwrap(),
            &std::env::var("KUTUP_LIVE_S3_SECRET_KEY").unwrap(),
            &std::env::var("KUTUP_LIVE_S3_BUCKET").unwrap(),
            "us-east-1",
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let user_id: uuid::Uuid =
            sqlx::query_scalar("SELECT user_id FROM chat_devices ORDER BY created_at DESC LIMIT 1")
                .fetch_one(&pool)
                .await
                .expect("live Chat user fixture");
        let original_used: i64 =
            sqlx::query_scalar("SELECT chat_storage_used_bytes FROM users WHERE id=$1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let cutoff = time::OffsetDateTime::now_utc();
        let expired_attachment = uuid::Uuid::new_v4();
        let boundary_attachment = uuid::Uuid::new_v4();
        let backup_incarnation = uuid::Uuid::new_v4();
        let protected_media_id = vec![0x71u8; 32];
        let expired_bytes = b"expired".to_vec();
        let boundary_bytes = b"boundary".to_vec();
        let protected_bytes = b"protected".to_vec();
        let expired_path = format!("chat-media/retention/{expired_attachment}");
        let boundary_path = format!("chat-media/retention/{boundary_attachment}");
        let protected_path = format!("chat-backup/retention/{backup_incarnation}");

        for (path, bytes) in [
            (&expired_path, &expired_bytes),
            (&boundary_path, &boundary_bytes),
            (&protected_path, &protected_bytes),
        ] {
            storage
                .upload(
                    path,
                    ByteStream::from(bytes.clone()),
                    i64::try_from(bytes.len()).unwrap(),
                )
                .await
                .unwrap();
        }
        for (attachment_id, path, bytes) in [
            (expired_attachment, &expired_path, &expired_bytes),
            (boundary_attachment, &boundary_path, &boundary_bytes),
        ] {
            sqlx::query(
                "INSERT INTO chat_media_objects
                 (attachment_id,origin_user_id,origin_domain,suite,ciphertext_bytes,
                  ciphertext_sha256,retrieval_token_hash,storage_path,created_at)
                 VALUES ($1,$2,'retention.test',1,$3,$4,$5,$6,$7)",
            )
            .bind(attachment_id)
            .bind(user_id)
            .bind(i64::try_from(bytes.len()).unwrap())
            .bind(hex::encode(sha2::Sha256::digest(bytes)))
            .bind(vec![0x51u8; 32])
            .bind(path)
            .bind(cutoff)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO chat_media_references
                 (user_id,attachment_id,logical_bytes,created_at) VALUES ($1,$2,$3,$4)",
            )
            .bind(user_id)
            .bind(attachment_id)
            .bind(i64::try_from(bytes.len()).unwrap())
            .bind(cutoff)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO chat_backups
             (user_id,backup_incarnation_id,suite,protection_domain,root_envelope,
              signer_authorization,signer_authorization_digest)
             VALUES ($1,$2,1,1,'retention-envelope','{}',repeat('0',64))",
        )
        .bind(user_id)
        .bind(backup_incarnation)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_backup_media_objects
             (user_id,media_id,ciphertext_bytes,ciphertext_sha256,storage_path,created_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(user_id)
        .bind(&protected_media_id)
        .bind(i64::try_from(protected_bytes.len()).unwrap())
        .bind(hex::encode(sha2::Sha256::digest(&protected_bytes)))
        .bind(&protected_path)
        .bind(cutoff - time::Duration::DAY)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_backup_media_references (user_id,media_id,reference_id,created_at)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind(&protected_media_id)
        .bind(uuid::Uuid::new_v4())
        .bind(cutoff - time::Duration::DAY)
        .execute(&pool)
        .await
        .unwrap();
        let fixture_bytes =
            i64::try_from(expired_bytes.len() + boundary_bytes.len() + protected_bytes.len())
                .unwrap();
        sqlx::query(
            "UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+$1 WHERE id=$2",
        )
        .bind(fixture_bytes)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

        // The boundary is strict: delivery references created exactly at the cutoff survive.
        sweep_chat_delivery_media_before(&pool, &storage, cutoff)
            .await
            .unwrap();
        let at_boundary: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM chat_media_references WHERE user_id=$1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(at_boundary, 2);

        sqlx::query("UPDATE chat_media_references SET created_at=$1 WHERE attachment_id=$2")
            .bind(cutoff - time::Duration::SECOND)
            .bind(expired_attachment)
            .execute(&pool)
            .await
            .unwrap();
        sweep_chat_delivery_media_before(&pool, &storage, cutoff)
            .await
            .unwrap();
        let used_after_expiry: i64 =
            sqlx::query_scalar("SELECT chat_storage_used_bytes FROM users WHERE id=$1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            used_after_expiry,
            original_used + i64::try_from(boundary_bytes.len() + protected_bytes.len()).unwrap()
        );
        assert!(storage.get_object(&expired_path).await.is_err());
        assert_eq!(
            storage.get_object(&boundary_path).await.unwrap().1,
            i64::try_from(boundary_bytes.len()).unwrap()
        );
        assert_eq!(
            storage.get_object(&protected_path).await.unwrap().1,
            i64::try_from(protected_bytes.len()).unwrap()
        );
        let protected_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chat_backup_media_objects WHERE user_id=$1 AND media_id=$2",
        )
        .bind(user_id)
        .bind(&protected_media_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(protected_rows, 1);

        // Reconciliation derives the exact total from both delivery and protected ledgers.
        sqlx::query(
            "UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+123 WHERE id=$1",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(quota_reconcile_tick(&pool).await >= 1);
        let reconciled: i64 =
            sqlx::query_scalar("SELECT chat_storage_used_bytes FROM users WHERE id=$1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reconciled, used_after_expiry);

        // Remove the boundary delivery fixture, then explicitly tear down protected history.
        sqlx::query("UPDATE chat_media_references SET created_at=$1 WHERE attachment_id=$2")
            .bind(cutoff - time::Duration::SECOND)
            .bind(boundary_attachment)
            .execute(&pool)
            .await
            .unwrap();
        sweep_chat_delivery_media_before(&pool, &storage, cutoff)
            .await
            .unwrap();
        sqlx::query("DELETE FROM chat_backups WHERE user_id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        storage.delete(&protected_path).await.unwrap();
        sqlx::query("UPDATE users SET chat_storage_used_bytes=$1 WHERE id=$2")
            .bind(original_used)
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(storage.get_object(&boundary_path).await.is_err());
        assert!(storage.get_object(&protected_path).await.is_err());
        pool.close().await;
    }
}
