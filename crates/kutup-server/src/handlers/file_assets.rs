//! File asset-blob handlers — mirrors `backend/handlers/file_assets.go`.
//!
//! Per-file encrypted binary blobs (whiteboard image binaries; Excalidraw's
//! content-addressed fileId ⇒ our assetId), stored at `files/{fileId}/assets/{assetId}`.
//! Upload is a quota transaction with idempotent INSERT (ON CONFLICT DO NOTHING) and a
//! compensating rollback if the S3 PUT fails, so an orphan-blob-with-no-row is impossible.

use std::io::Write;

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tempfile::NamedTempFile;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_file, octet_stream_response, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

/// Rejects empty/over-long/slashed/traversing asset ids — mirrors `validAssetID`.
fn valid_asset_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains("..")
}

fn asset_storage_path(file_id: Uuid, asset_id: &str) -> String {
    format!("files/{file_id}/assets/{asset_id}")
}

/// `PUT /api/files/{fileId}/assets/{assetId}` — mirrors `Upload`.
#[utoipa::path(
    put,
    path = "/api/files/{fileId}/assets/{assetId}",
    tag = "assets",
    operation_id = "uploadFileAsset",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("assetId" = String, Path, description = "Content-addressed asset id")
    ),
    request_body(
        content = Vec<u8>,
        content_type = "multipart/form-data",
        description = "The encrypted asset blob as the `file` part"
    ),
    responses((status = 204, description = "Asset stored (idempotent re-PUT is a no-op)"))
)]
pub async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, asset_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;

    if !valid_asset_id(&asset_id) {
        return Err(AppError::bad_request("invalid assetId"));
    }
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }

    // Read the file part to a temp file (to know its size before the quota gate + PUT).
    let mut tmp: Option<(NamedTempFile, i64)> = None;
    loop {
        let field = multipart
            .next_field()
            .await
            .map_err(|_| AppError::bad_request("missing file"))?;
        let Some(mut field) = field else { break };
        if field.name() == Some("file") {
            let mut file = NamedTempFile::new().map_err(|_| AppError::internal("temp file"))?;
            let mut size: i64 = 0;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| AppError::bad_request("missing file"))?
            {
                file.write_all(&chunk)
                    .map_err(|_| AppError::internal("temp write"))?;
                size += chunk.len() as i64;
            }
            tmp = Some((file, size));
        }
    }
    let Some((tmp_file, size)) = tmp else {
        return Err(AppError::bad_request("missing file"));
    };

    // Pre-flight under FOR UPDATE: lock user, idempotent INSERT, quota gate, counter bump.
    let mut tx = state.pool.begin().await?;
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;

    // ON CONFLICT DO NOTHING ⇒ a re-PUT of an existing content-addressed asset returns no
    // row, so we skip the quota charge (storage already paid for).
    let inserted: Option<i64> = sqlx::query_scalar(
        r#"INSERT INTO file_assets (file_id, asset_id, size_bytes, uploader_user_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (file_id, asset_id) DO NOTHING
           RETURNING size_bytes"#,
    )
    .bind(fid)
    .bind(&asset_id)
    .bind(size)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_some() {
        if used + size > quota {
            return Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "storage quota exceeded",
            ));
        }
        sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2")
            .bind(size)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }

    // S3 PUT after the DB increment but before commit (lock still held). A PUT failure
    // rolls back the whole pre-flight, keeping DB + S3 convergent.
    let path = asset_storage_path(fid, &asset_id);
    let body = ByteStream::from_path(tmp_file.path())
        .await
        .map_err(|_| AppError::internal("read upload"))?;
    if state.storage.upload(&path, body, size).await.is_err() {
        return Err(AppError::internal("storage error"));
    }

    if tx.commit().await.is_err() {
        let _ = state.storage.delete(&path).await;
        return Err(AppError::internal("commit"));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/files/{fileId}/assets/{assetId}` — mirrors `Download`.
#[utoipa::path(
    get,
    path = "/api/files/{fileId}/assets/{assetId}",
    tag = "assets",
    operation_id = "downloadFileAsset",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("assetId" = String, Path, description = "Content-addressed asset id")
    ),
    responses((status = 200, description = "The encrypted asset blob (application/octet-stream)"))
)]
pub async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, asset_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;

    if !valid_asset_id(&asset_id) {
        return Err(AppError::bad_request("invalid assetId"));
    }
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }

    let (body, size) = state
        .storage
        .get_object(&asset_storage_path(fid, &asset_id))
        .await
        .map_err(|_| AppError::not_found("not found"))?;
    Ok(octet_stream_response(body, size, &[]))
}

#[cfg(test)]
mod tests {
    use super::valid_asset_id;

    #[test]
    fn asset_id_validation() {
        assert!(valid_asset_id("abc123"));
        assert!(valid_asset_id(&"a".repeat(128)));
        assert!(!valid_asset_id(""));
        assert!(!valid_asset_id(&"a".repeat(129)));
        assert!(!valid_asset_id("a/b"));
        assert!(!valid_asset_id("a\\b"));
        assert!(!valid_asset_id("../etc"));
    }
}
