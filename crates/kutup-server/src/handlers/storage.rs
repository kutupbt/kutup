//! `GET /api/user/storage`: what the caller's one storage pool holds, by app
//! and by kind of stored bytes (docs/api.md). Sizes are the bytes the server
//! stores and charges, all ciphertext; what the files are (images, documents,
//! …) only the browser can tell, from the names it decrypts.

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::AppResult;
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
    }))
}
