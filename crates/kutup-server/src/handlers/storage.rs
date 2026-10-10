//! `GET /api/user/storage`: what the caller's one storage pool holds, by app
//! and by kind of stored bytes (docs/api.md). Sizes are the bytes the server
//! stores and charges, all ciphertext; what the files are (images, documents,
//! …) only the browser can tell, from the names it decrypts.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// The caller's storage pool and what fills it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsageResponse {
    pub quota_bytes: i64,
    /// The account counter every write charges and every limit checks.
    pub used_bytes: i64,
    /// Promised to uploads and hand-overs still in flight; counts against
    /// the quota until they finish or are abandoned.
    pub reserved_bytes: i64,
    pub drive: DriveUsage,
    pub chat: ChatUsage,
    pub contacts: ContactsUsage,
    pub mail: MailUsage,
}

/// The address book: each contact's summary and sealed card.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactsUsage {
    pub bytes: i64,
    pub count: i64,
}

/// Mail: every stored message, encrypted, attachments included.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailUsage {
    pub bytes: i64,
    pub count: i64,
}

/// Drive, which Photos, Office and Maps store their files in.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DriveUsage {
    /// Files the caller uploaded that are not in the trash, wherever they are.
    pub files_bytes: i64,
    pub files_count: i64,
    /// Files in the trash, until it is emptied or they expire.
    pub trash_bytes: i64,
    pub trash_count: i64,
    /// Earlier versions of files the caller saved.
    pub versions_bytes: i64,
    /// Thumbnails and previews.
    pub thumbnails_bytes: i64,
    /// Images and other parts that documents and whiteboards embed.
    pub assets_bytes: i64,
}

/// Chat. Every copy the account keeps counts, so an attachment sent and
/// kept in the history backup is charged once for each.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatUsage {
    /// Attachments the caller sent or received, while they are kept for delivery.
    pub media_bytes: i64,
    /// The encrypted message history backup.
    pub history_bytes: i64,
    /// Attachments kept in the history backup.
    pub history_media_bytes: i64,
}

#[utoipa::path(
    get,
    path = "/api/user/storage",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's storage, by app", body = StorageUsageResponse))
)]
pub async fn usage(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<StorageUsageResponse>> {
    let user_id = trusted_uuid(&user.user_id)?;
    type Row = (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64);
    let row: Row = sqlx::query_as(
        r#"SELECT u.storage_quota_bytes, u.storage_used_bytes,
             COALESCE(f.live_bytes, 0)::bigint, COALESCE(f.live_count, 0)::bigint,
             COALESCE(f.trash_bytes, 0)::bigint, COALESCE(f.trash_count, 0)::bigint,
             COALESCE((SELECT SUM(size_bytes) FROM file_versions WHERE author_user_id = u.id), 0)::bigint,
             COALESCE((SELECT SUM(size_bytes) FROM file_thumbnails WHERE uploader_user_id = u.id), 0)::bigint,
             COALESCE((SELECT SUM(size_bytes) FROM file_assets WHERE uploader_user_id = u.id), 0)::bigint,
             COALESCE((SELECT SUM(logical_bytes) FROM chat_media_references WHERE user_id = u.id), 0)::bigint,
             (COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_backup_segments WHERE user_id = u.id), 0)
              + COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_backup_bases WHERE user_id = u.id), 0))::bigint,
             COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_backup_media_objects WHERE user_id = u.id), 0)::bigint
           FROM users u
           LEFT JOIN LATERAL (
             SELECT SUM(CASE WHEN original_pruned THEN 0 ELSE encrypted_size_bytes END)
                      FILTER (WHERE deleted_at IS NULL) AS live_bytes,
                    COUNT(*) FILTER (WHERE deleted_at IS NULL) AS live_count,
                    SUM(CASE WHEN original_pruned THEN 0 ELSE encrypted_size_bytes END)
                      FILTER (WHERE deleted_at IS NOT NULL) AS trash_bytes,
                    COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) AS trash_count
             FROM files WHERE uploader_user_id = u.id
           ) f ON true
           WHERE u.id = $1"#,
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let reserved = crate::storage_pool::reserved(&state.pool, user_id, Default::default()).await?;
    let (contacts_bytes, contacts_count): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(octet_length(summary) + octet_length(card)), 0)::bigint, COUNT(*)
           FROM contacts WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let (mail_bytes, mail_count): (i64, i64) = sqlx::query_as(
        "SELECT (COALESCE((SELECT SUM(size_bytes) FROM mail_messages WHERE user_id = $1), 0)
               + COALESCE((SELECT SUM(size_bytes) FROM mail_draft_attachments WHERE user_id = $1), 0))::bigint,
                (SELECT COUNT(*) FROM mail_messages WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let (quota, used, files, files_count, trash, trash_count, versions, thumbnails, assets) = (
        row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8,
    );
    Ok(Json(StorageUsageResponse {
        quota_bytes: quota,
        used_bytes: used,
        reserved_bytes: reserved,
        drive: DriveUsage {
            files_bytes: files,
            files_count,
            trash_bytes: trash,
            trash_count,
            versions_bytes: versions,
            thumbnails_bytes: thumbnails,
            assets_bytes: assets,
        },
        chat: ChatUsage {
            media_bytes: row.9,
            history_bytes: row.10,
            history_media_bytes: row.11,
        },
        contacts: ContactsUsage {
            bytes: contacts_bytes,
            count: contacts_count,
        },
        mail: MailUsage {
            bytes: mail_bytes,
            count: mail_count,
        },
    }))
}

/// The caller's deletable earlier versions (every version they saved but each
/// file's newest), by whole days of age and whether they are kept forever.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VersionAge {
    pub age_days: i32,
    pub keep_forever: bool,
    pub bytes: i64,
    pub count: i64,
}

/// `GET /api/user/storage/versions` — what "Delete versions older than…"
/// would free, so the browser can show it for any age before asking.
#[utoipa::path(
    get,
    path = "/api/user/storage/versions",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Deletable versions by age", body = [VersionAge]))
)]
pub async fn version_ages(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<VersionAge>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(i32, bool, i64, i64)> = sqlx::query_as(&format!(
        "SELECT FLOOR(EXTRACT(EPOCH FROM now() - v.created_at) / 86400)::int AS age,
                v.keep_forever, SUM(v.size_bytes)::bigint, COUNT(*)::bigint
           FROM file_versions v
          WHERE v.author_user_id = $1 AND v.id <> ({newest})
          GROUP BY 1, 2
          ORDER BY 1, 2",
        newest = crate::handlers::file_versions::NEWEST_VERSION
    ))
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(age_days, keep_forever, bytes, count)| VersionAge {
                age_days,
                keep_forever,
                bytes,
                count,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PruneVersionsRequest {
    /// Versions at least this many whole days old go, matching
    /// `VersionAge::age_days`; 0 is every earlier version.
    pub older_than_days: i32,
    /// Also versions marked "keep forever".
    #[serde(default)]
    pub include_kept_forever: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PruneVersionsResponse {
    pub deleted_count: i64,
    pub freed_bytes: i64,
    /// More are left: call again to continue.
    pub more: bool,
}

/// At most this many versions go per request, so one call stays short.
const PRUNE_BATCH: i64 = 500;

/// `POST /api/user/storage/versions/prune` — deletes for good the earlier
/// versions the caller saved more than `olderThanDays` ago, never a file's
/// newest, and kept-forever ones only when asked. In batches: repeat while
/// `more`.
#[utoipa::path(
    post,
    path = "/api/user/storage/versions/prune",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = PruneVersionsRequest,
    responses((status = 200, description = "What was deleted", body = PruneVersionsResponse))
)]
pub async fn prune_versions(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<PruneVersionsRequest>,
) -> AppResult<Json<PruneVersionsResponse>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if !(0..=36_500).contains(&req.older_than_days) {
        return Err(AppError::bad_request(
            "olderThanDays must be between 0 and 36500",
        ));
    }
    let rows: Vec<(uuid::Uuid, String, String, i64)> = sqlx::query_as(&format!(
        "SELECT v.id, v.storage_path, v.s3_version_id, v.size_bytes
           FROM file_versions v
          WHERE v.author_user_id = $1
            AND v.created_at <= now() - make_interval(days => $2)
            AND ($3 OR NOT v.keep_forever)
            AND v.id <> ({newest})
          ORDER BY v.created_at
          LIMIT $4",
        newest = crate::handlers::file_versions::NEWEST_VERSION
    ))
    .bind(user_id)
    .bind(req.older_than_days)
    .bind(req.include_kept_forever)
    .bind(PRUNE_BATCH + 1)
    .fetch_all(&state.pool)
    .await?;
    let more = rows.len() as i64 > PRUNE_BATCH;
    let (mut deleted_count, mut freed_bytes) = (0, 0);
    for (id, path, s3_version, size) in rows.into_iter().take(PRUNE_BATCH as usize) {
        match crate::jobs::remove_version(&state.pool, &state.storage, id, &path, &s3_version).await
        {
            Ok(true) => {
                deleted_count += 1;
                freed_bytes += size;
            }
            Ok(false) => {}
            Err(_) => return Err(AppError::internal("could not delete versions")),
        }
    }
    Ok(Json(PruneVersionsResponse {
        deleted_count,
        freed_bytes,
        more,
    }))
}
