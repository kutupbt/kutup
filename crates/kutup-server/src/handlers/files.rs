//! File handlers — mirrors `backend/handlers/files.go`.
//!
//! List/upload/download/rename/delete plus the collab first-seeder claim. Uploads stream
//! the multipart file to a temp file (to learn its size, like Go's parsed form) then to S3
//! under a quota transaction; deletes release quota for the file + its asset/version
//! children atomically, then wipe the S3 prefix.

use std::collections::HashMap;
use std::io::{Read, Write};

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1, FILE_BLOB_HEADER_BYTES};
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
    metadata_envelope: String,
    metadata_revision: i64,
}

pub(crate) fn canonical_uuid(value: &str) -> AppResult<Uuid> {
    let parsed = Uuid::parse_str(value).map_err(|_| AppError::bad_request("invalid file id"))?;
    if parsed.to_string() != value {
        return Err(AppError::bad_request("invalid file id"));
    }
    Ok(parsed)
}

pub(crate) fn validate_envelope(value: &str, expected: DriveEnvelopeContextV1) -> AppResult<()> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?;
    if STANDARD.encode(&bytes) != value || drive_envelope::validate(&bytes, expected).is_err() {
        return Err(AppError::bad_request("invalid Drive envelope"));
    }
    Ok(())
}

pub(crate) fn validate_file_blob_prefix(
    bytes: &[u8],
    expected: DriveFileBlobContextV1,
) -> AppResult<()> {
    if bytes.len() < FILE_BLOB_HEADER_BYTES
        || drive_object::validate_file_blob_header(&bytes[..FILE_BLOB_HEADER_BYTES], expected)
            .is_err()
    {
        return Err(AppError::bad_request("invalid Drive file blob"));
    }
    Ok(())
}

pub(crate) fn validate_file_blob_file(
    file: &NamedTempFile,
    expected: DriveFileBlobContextV1,
) -> AppResult<()> {
    let mut prefix = [0u8; FILE_BLOB_HEADER_BYTES];
    std::fs::File::open(file.path())
        .and_then(|mut source| source.read_exact(&mut prefix))
        .map_err(|_| AppError::bad_request("invalid Drive file blob"))?;
    validate_file_blob_prefix(&prefix, expected)
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
        i32,
        i64,
        i64,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT id, collection_id, uploader_user_id,
                  metadata_envelope, file_key_envelope, key_epoch, metadata_revision,
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
            |(id, cid, uid, metadata, file_key, epoch, revision, size, created, updated)| FileRow {
                id: id.to_string(),
                collection_id: cid.to_string(),
                uploader_user_id: uid.to_string(),
                metadata_envelope: metadata,
                file_key_envelope: file_key,
                key_epoch: epoch,
                metadata_revision: revision,
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
        description = "Fields: fileId, collectionId, metadataEnvelope, fileKeyEnvelope + the encrypted `file` part"
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
    let file_id_str = fields.get("fileId").cloned().unwrap_or_default();
    let metadata_envelope = fields.get("metadataEnvelope").cloned().unwrap_or_default();
    let file_key_envelope = fields.get("fileKeyEnvelope").cloned().unwrap_or_default();

    if coll_id_str.is_empty()
        || file_id_str.is_empty()
        || metadata_envelope.is_empty()
        || file_key_envelope.is_empty()
    {
        return Err(AppError::bad_request("missing required fields"));
    }
    let Some((tmp_file, file_size)) = tmp else {
        return Err(AppError::bad_request("no file provided"));
    };
    let coll_id = Uuid::parse_str(&coll_id_str).map_err(|_| AppError::forbidden("forbidden"))?;
    let file_id = canonical_uuid(&file_id_str)?;

    // Write access: owner, or share recipient with can_upload.
    let collection: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT owner_user_id, key_epoch FROM collections WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(coll_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((owner_user_id, key_epoch)) = collection else {
        return Err(AppError::forbidden("forbidden"));
    };
    let is_owner = owner_user_id == user_id;
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

    let epoch = u32::try_from(key_epoch).map_err(|_| AppError::conflict("invalid epoch"))?;
    validate_envelope(
        &file_key_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileKey,
            epoch,
            1,
            &file_id_str,
            &coll_id_str,
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    validate_envelope(
        &metadata_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileMetadata,
            epoch,
            1,
            &file_id_str,
            &coll_id_str,
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    let blob_context = DriveFileBlobContextV1::new(&file_id_str, &coll_id_str, epoch)
        .map_err(|_| AppError::bad_request("invalid Drive file blob"))?;
    validate_file_blob_file(&tmp_file, blob_context)?;
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
                "SELECT COALESCE(SUM(encrypted_size_bytes), 0)::bigint FROM files WHERE collection_id = $1 AND uploader_user_id = $2",
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
                              metadata_envelope, file_key_envelope,
                              key_epoch, metadata_revision,
                              storage_path, encrypted_size_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8)"#,
    )
    .bind(file_id)
    .bind(coll_id)
    .bind(user_id)
    .bind(&metadata_envelope)
    .bind(&file_key_envelope)
    .bind(key_epoch)
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

    if req.metadata_envelope.is_empty() || req.metadata_revision <= 1 {
        return Err(AppError::bad_request(
            "metadataEnvelope and a revision greater than 1 are required",
        ));
    }

    let mut tx = state.pool.begin().await?;
    let row: Option<(Uuid, Uuid, i32, i64)> = sqlx::query_as(
        r#"SELECT collection_id, uploader_user_id, key_epoch, metadata_revision
           FROM files WHERE id = $1 AND deleted_at IS NULL FOR UPDATE"#,
    )
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((coll_id, uploader_id, key_epoch, current_revision)) = row else {
        return Err(AppError::not_found("not found"));
    };
    require_owner_or_uploader_with_delete(&state, user_id, coll_id, uploader_id).await?;

    let expected_revision = current_revision
        .checked_add(1)
        .ok_or_else(|| AppError::conflict("metadata revision exhausted"))?;
    if req.metadata_revision != expected_revision {
        return Err(AppError::conflict(
            "metadata revision must advance exactly once",
        ));
    }
    let epoch = u32::try_from(key_epoch).map_err(|_| AppError::conflict("invalid epoch"))?;
    let revision = u64::try_from(req.metadata_revision)
        .map_err(|_| AppError::bad_request("invalid metadata revision"))?;
    validate_envelope(
        &req.metadata_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileMetadata,
            epoch,
            revision,
            &file_id.to_string(),
            &coll_id.to_string(),
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;

    sqlx::query(
        "UPDATE files SET metadata_envelope = $1, metadata_revision = $2, updated_at = NOW() WHERE id = $3",
    )
        .bind(&req.metadata_envelope)
        .bind(req.metadata_revision)
        .bind(file_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
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
