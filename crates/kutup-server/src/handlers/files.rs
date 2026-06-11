//! File handlers — mirrors `backend/handlers/files.go`.
//!
//! List/upload/download/rename/delete plus the collab first-seeder claim. Uploads stream
//! the multipart file to a temp file (to learn its size, like Go's parsed form) then to S3
//! under a quota transaction; deletes release quota for the file + its asset/version
//! children atomically, then wipe the S3 prefix.

use std::collections::HashMap;
use std::io::Write;

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_collection, octet_stream_response, trusted_uuid};
use crate::middleware::AuthUser;
use crate::models::{FileRow, MessageResponse, UploadResult};
use crate::AppState;

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateFileMetadataRequest {
    encrypted_metadata: String,
    metadata_nonce: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClaimSeedResponse {
    committed: bool,
}

/// `GET /api/collections/{id}/files` — mirrors `ListFiles`.
#[utoipa::path(
    get,
    path = "/api/collections/{id}/files",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "Files in the collection", body = Vec<FileRow>))
)]
pub async fn list_files(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = Uuid::parse_str(&id).map_err(|_| AppError::forbidden("forbidden"))?;

    if !can_access_collection(&state.pool, user_id, coll_id).await {
        return Err(AppError::forbidden("forbidden"));
    }

    type Row = (
        Uuid,
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        i64,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT id, collection_id, uploader_user_id,
                  encrypted_metadata, metadata_nonce,
                  encrypted_file_key, file_key_nonce,
                  encrypted_size_bytes, created_at, updated_at
           FROM files WHERE collection_id = $1 AND deleted_at IS NULL
           ORDER BY created_at DESC"#,
    )
    .bind(coll_id)
    .fetch_all(&state.pool)
    .await?;

    let out: Vec<FileRow> = rows
        .into_iter()
        .map(
            |(id, cid, uid, em, mn, efk, fkn, size, created, updated)| FileRow {
                id: id.to_string(),
                collection_id: cid.to_string(),
                uploader_user_id: uid.to_string(),
                encrypted_metadata: em,
                metadata_nonce: mn,
                encrypted_file_key: efk,
                file_key_nonce: fkn,
                encrypted_size_bytes: size,
                created_at: created,
                updated_at: updated,
            },
        )
        .collect();
    Ok(Json(out).into_response())
}

/// `POST /api/files/upload` — mirrors `Upload`.
#[utoipa::path(
    post,
    path = "/api/files/upload",
    tag = "files",
    operation_id = "uploadFile",
    security(("BearerAuth" = [])),
    request_body(
        content = Vec<u8>,
        content_type = "multipart/form-data",
        description = "Fields: collectionId, encryptedMetadata, metadataNonce, encryptedFileKey, fileKeyNonce + the encrypted `file` part"
    ),
    responses((status = 201, description = "File stored", body = UploadResult))
)]
pub async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;

    // Collect text fields into a map and stream the file part to a temp file (so we know
    // its size before the S3 PUT, like Go's parsed multipart form). Handles any field order.
    let mut fields: HashMap<String, String> = HashMap::new();
    let mut tmp: Option<(NamedTempFile, i64)> = None;
    loop {
        let field = multipart
            .next_field()
            .await
            .map_err(|_| AppError::bad_request("invalid multipart form"))?;
        let Some(mut field) = field else { break };
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let mut file = NamedTempFile::new().map_err(|_| AppError::internal("temp file"))?;
            let mut size: i64 = 0;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| AppError::bad_request("invalid multipart form"))?
            {
                file.write_all(&chunk)
                    .map_err(|_| AppError::internal("temp write"))?;
                size += chunk.len() as i64;
            }
            tmp = Some((file, size));
        } else {
            let val = field.text().await.unwrap_or_default();
            fields.insert(name, val);
        }
    }

    let coll_id_str = fields.get("collectionId").cloned().unwrap_or_default();
    let enc_metadata = fields.get("encryptedMetadata").cloned().unwrap_or_default();
    let metadata_nonce = fields.get("metadataNonce").cloned().unwrap_or_default();
    let enc_file_key = fields.get("encryptedFileKey").cloned().unwrap_or_default();
    let file_key_nonce = fields.get("fileKeyNonce").cloned().unwrap_or_default();

    if coll_id_str.is_empty() || enc_metadata.is_empty() || enc_file_key.is_empty() {
        return Err(AppError::bad_request("missing required fields"));
    }
    let Some((tmp_file, file_size)) = tmp else {
        return Err(AppError::bad_request("no file provided"));
    };
    let coll_id = Uuid::parse_str(&coll_id_str).map_err(|_| AppError::forbidden("forbidden"))?;

    // Write access: owner, or share recipient with can_upload.
    let owner_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2")
            .bind(coll_id)
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let is_owner = owner_count > 0;
    let mut share_quota: Option<i64> = None;
    if !is_owner {
        let row: Option<(bool, Option<i64>)> = sqlx::query_as(
            "SELECT can_upload, upload_quota_bytes FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = $2",
        )
        .bind(coll_id)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;
        match row {
            Some((true, quota)) => share_quota = quota,
            _ => return Err(AppError::forbidden("forbidden")),
        }
    }

    let file_id = Uuid::new_v4();
    let storage_path = format!("{}/{}/{}", user_id, coll_id, file_id);

    // Atomic quota check + reserve under FOR UPDATE.
    let mut tx = state.pool.begin().await?;
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if used + file_size > quota {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        ));
    }
    if !is_owner {
        if let Some(limit) = share_quota {
            let used_share: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(encrypted_size_bytes), 0) FROM files WHERE collection_id = $1 AND uploader_user_id = $2",
            )
            .bind(coll_id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
            if used_share + file_size > limit {
                return Err(AppError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "share upload quota exceeded",
                ));
            }
        }
    }

    // Stream the temp file to S3 (still holding the row lock, like Go).
    let body = ByteStream::from_path(tmp_file.path())
        .await
        .map_err(|_| AppError::internal("read upload"))?;
    state
        .storage
        .upload(&storage_path, body, file_size)
        .await
        .map_err(|e| {
            tracing::error!("s3 upload failed: {e:#}");
            AppError::internal("storage error")
        })?;

    let insert = sqlx::query(
        r#"INSERT INTO files (id, collection_id, uploader_user_id,
                              encrypted_metadata, metadata_nonce,
                              encrypted_file_key, file_key_nonce,
                              storage_path, encrypted_size_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
    )
    .bind(file_id)
    .bind(coll_id)
    .bind(user_id)
    .bind(&enc_metadata)
    .bind(&metadata_nonce)
    .bind(&enc_file_key)
    .bind(&file_key_nonce)
    .bind(&storage_path)
    .bind(file_size)
    .execute(&mut *tx)
    .await;
    if insert.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return Err(AppError::internal("insert file"));
    }

    if sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2")
        .bind(file_size)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = state.storage.delete(&storage_path).await;
        return Err(AppError::internal("update quota"));
    }

    if tx.commit().await.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return Err(AppError::internal("commit"));
    }

    Ok((
        StatusCode::CREATED,
        Json(UploadResult {
            id: file_id.to_string(),
        }),
    )
        .into_response())
}

/// `GET /api/files/{id}/download` — mirrors `Download`.
#[utoipa::path(
    get,
    path = "/api/files/{id}/download",
    tag = "files",
    operation_id = "downloadFile",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    responses((status = 200, description = "The encrypted blob (application/octet-stream)"))
)]
pub async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let row: Option<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT collection_id, storage_path, uploader_user_id FROM files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((coll_id, storage_path, _uploader)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if !can_access_collection(&state.pool, user_id, coll_id).await {
        return Err(AppError::forbidden("forbidden"));
    }

    let (body, size) = state
        .storage
        .get_object(&storage_path)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    Ok(octet_stream_response(body, size, &[]))
}

/// `PUT /api/files/{id}` — mirrors `UpdateMetadata` (rename).
#[utoipa::path(
    put,
    path = "/api/files/{id}",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = UpdateFileMetadataRequest,
    responses((status = 200, description = "Metadata updated", body = MessageResponse))
)]
pub async fn update_metadata(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateFileMetadataRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    if req.encrypted_metadata.is_empty() || req.metadata_nonce.is_empty() {
        return Err(AppError::bad_request(
            "encryptedMetadata and metadataNonce required",
        ));
    }

    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT collection_id, uploader_user_id FROM files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((coll_id, uploader_id)) = row else {
        return Err(AppError::not_found("not found"));
    };
    require_owner_or_uploader_with_delete(&state, user_id, coll_id, uploader_id).await?;

    sqlx::query("UPDATE files SET encrypted_metadata = $1, metadata_nonce = $2 WHERE id = $3")
        .bind(&req.encrypted_metadata)
        .bind(&req.metadata_nonce)
        .bind(file_id)
        .execute(&state.pool)
        .await?;
    Ok(Json(MessageResponse {
        message: "updated".to_string(),
    })
    .into_response())
}

/// `DELETE /api/files/{id}` — soft-deletes into the trash (30-day retention). Quota stays
/// reserved while the file is in trash (the blob still occupies storage); the permanent
/// path (`DELETE /api/trash/{id}` or the retention sweeper) releases it.
#[utoipa::path(
    delete,
    path = "/api/files/{id}",
    tag = "files",
    operation_id = "deleteFile",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    responses((status = 204, description = "File moved to trash"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT collection_id, uploader_user_id FROM files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((coll_id, uploader_id)) = row else {
        return Err(AppError::not_found("not found"));
    };
    require_owner_or_uploader_with_delete(&state, user_id, coll_id, uploader_id).await?;

    sqlx::query(
        "UPDATE files SET deleted_at = NOW(), trash_root_id = id WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(file_id)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/files/{fileId}/claim-seed` — mirrors `ClaimSeed`.
#[utoipa::path(
    post,
    path = "/api/files/{fileId}/claim-seed",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "File id")),
    responses((status = 200, description = "Whether this caller won the first-seeder race", body = ClaimSeedResponse))
)]
pub async fn claim_seed(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;

    let coll_id: Option<Uuid> =
        sqlx::query_scalar("SELECT collection_id FROM files WHERE id = $1 AND deleted_at IS NULL")
            .bind(fid)
            .fetch_optional(&state.pool)
            .await?;
    let Some(coll_id) = coll_id else {
        return Err(AppError::not_found("not found"));
    };
    if !can_access_collection(&state.pool, user_id, coll_id).await {
        return Err(AppError::forbidden("forbidden"));
    }

    // Atomic false → true; RETURNING reports whether this caller won the race.
    let claimed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE files SET seed_committed = true WHERE id = $1 AND seed_committed = false RETURNING id",
    )
    .bind(fid)
    .fetch_optional(&state.pool)
    .await?;
    Ok(Json(ClaimSeedResponse {
        committed: claimed.is_some(),
    })
    .into_response())
}

/// Permission gate shared by rename + delete: collection owner, or the file's uploader
/// holding a `can_delete` share. Mirrors the inline checks in `UpdateMetadata`/`Delete`.
async fn require_owner_or_uploader_with_delete(
    state: &AppState,
    user_id: Uuid,
    coll_id: Uuid,
    uploader_id: Uuid,
) -> AppResult<()> {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_user_id FROM collections WHERE id = $1")
            .bind(coll_id)
            .fetch_optional(&state.pool)
            .await?;
    if owner == Some(user_id) {
        return Ok(());
    }
    if uploader_id != user_id {
        return Err(AppError::forbidden("forbidden"));
    }
    let can_delete: Option<bool> = sqlx::query_scalar(
        "SELECT can_delete FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = $2",
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    if can_delete == Some(true) {
        Ok(())
    } else {
        Err(AppError::forbidden("forbidden"))
    }
}
