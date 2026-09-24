//! File thumbnails (docs/plans/drive-thumbnails.md): a client-made preview
//! of a file, sealed under the file key. The server stores the envelope at
//! `files/{fileId}/thumbnails/{variant}`, checks its public header (purpose,
//! file, variant, epoch) without any key, and charges its size to the
//! uploader. An upload replaces the previous one of that variant.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use kutup_crypto::thumbnail::{self, ThumbnailVariant};

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_file, octet_stream_response, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

pub(crate) fn thumbnail_storage_path(file_id: Uuid, variant: ThumbnailVariant) -> String {
    format!("files/{file_id}/thumbnails/{}", variant.as_str())
}

fn parse_variant(value: &str) -> AppResult<ThumbnailVariant> {
    ThumbnailVariant::try_from(value).map_err(|_| AppError::not_found("not found"))
}

#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    /// The version the picture was drawn from, or `original` for the upload.
    source: Option<String>,
}

/// `PUT /api/files/{fileId}/thumbnails/{variant}?source={versionId|original}`
#[utoipa::path(
    put,
    path = "/api/files/{fileId}/thumbnails/{variant}",
    tag = "thumbnails",
    operation_id = "uploadFileThumbnail",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("variant" = String, Path, description = "`sm` or `lg`"),
        ("source" = Option<String>, Query, description = "Version id the picture was drawn from, or `original`")
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The thumbnail envelope"),
    responses(
        (status = 204, description = "Stored, replacing any previous thumbnail of this variant"),
        (status = 413, description = "Envelope too large, or storage quota exceeded")
    )
)]
pub async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, variant)): Path<(String, String)>,
    Query(query): Query<UploadQuery>,
    body: Bytes,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let variant = parse_variant(&variant)?;
    if body.len() > kutup_crypto::drive_envelope::max_thumbnail_envelope_bytes(variant) {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "thumbnail too large",
        ));
    }
    // The same right as saving a version: whoever may change the content
    // may change its picture.
    if !crate::drive_writes::can_write_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }
    let (collection_id, key_epoch): (Uuid, i32) = sqlx::query_as(
        "SELECT collection_id, key_epoch FROM files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(fid)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))?;
    let epoch =
        u32::try_from(key_epoch).map_err(|_| AppError::bad_request("invalid file epoch"))?;
    thumbnail::validate(&body, variant, &fid.to_string(), epoch)
        .map_err(|_| AppError::bad_request("invalid thumbnail envelope"))?;

    let source_version = match query.source.as_deref() {
        None | Some("original") => None,
        Some(value) => {
            let vid =
                Uuid::parse_str(value).map_err(|_| AppError::bad_request("invalid source"))?;
            let belongs: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM file_versions WHERE id = $1 AND file_id = $2)",
            )
            .bind(vid)
            .bind(fid)
            .fetch_one(&state.pool)
            .await?;
            if !belongs {
                return Err(AppError::bad_request("invalid source"));
            }
            Some(vid)
        }
    };
    let size = body.len() as i64;

    let mut tx = state.pool.begin().await?;
    // One writer per slot, including the first (when there is no row to lock
    // yet): two concurrent uploads would otherwise both be charged.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("file-thumbnail:{fid}:{}", variant.as_str()))
        .execute(&mut *tx)
        .await?;
    let previous: Option<(i64, Uuid, String)> = sqlx::query_as(
        "SELECT size_bytes, uploader_user_id, s3_version_id FROM file_thumbnails
         WHERE file_id = $1 AND variant = $2 FOR UPDATE",
    )
    .bind(fid)
    .bind(variant.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    // Replacing your own thumbnail frees its bytes first; someone else's
    // goes back to them.
    let own_previous = previous
        .as_ref()
        .filter(|(_, uploader, _)| *uploader == user_id)
        .map_or(0, |(bytes, _, _)| *bytes);
    crate::drive_writes::check_room(&mut tx, user_id, collection_id, size - own_previous, None)
        .await?
        .into_result()?;
    sqlx::query("UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1 + $2) WHERE id = $3")
        .bind(own_previous)
        .bind(size)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if let Some((bytes, uploader, _)) = previous
        .as_ref()
        .filter(|(_, uploader, _)| *uploader != user_id)
    {
        sqlx::query("UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2")
            .bind(bytes)
            .bind(uploader)
            .execute(&mut *tx)
            .await?;
    }

    // Stored before commit, with the row lock held: a failed PUT rolls the
    // whole change back.
    let path = thumbnail_storage_path(fid, variant);
    let version_id = state
        .storage
        .put_object_versioned(
            &path,
            aws_sdk_s3::primitives::ByteStream::from(body.to_vec()),
            size,
        )
        .await
        .map_err(|_| AppError::internal("storage error"))?;
    sqlx::query(
        r#"INSERT INTO file_thumbnails (file_id, variant, size_bytes, s3_version_id, source_version, uploader_user_id, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())
           ON CONFLICT (file_id, variant) DO UPDATE SET
             size_bytes = EXCLUDED.size_bytes,
             s3_version_id = EXCLUDED.s3_version_id,
             source_version = EXCLUDED.source_version,
             uploader_user_id = EXCLUDED.uploader_user_id,
             updated_at = NOW()"#,
    )
    .bind(fid)
    .bind(variant.as_str())
    .bind(size)
    .bind(&version_id)
    .bind(source_version)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    if tx.commit().await.is_err() {
        if !version_id.is_empty() {
            let _ = state
                .storage
                .delete_object_version(&path, &version_id)
                .await;
        }
        return Err(AppError::internal("commit"));
    }
    // The superseded object, exactly (the bucket is versioned: overwriting
    // alone would keep it until the lifecycle expired it).
    if let Some((_, _, old)) = previous.filter(|(_, _, old)| !old.is_empty() && *old != version_id)
    {
        let _ = state.storage.delete_object_version(&path, &old).await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/files/{fileId}/thumbnails/{variant}` — the envelope.
#[utoipa::path(
    get,
    path = "/api/files/{fileId}/thumbnails/{variant}",
    tag = "thumbnails",
    operation_id = "downloadFileThumbnail",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("variant" = String, Path, description = "`sm` or `lg`")
    ),
    responses(
        (status = 200, description = "The thumbnail envelope (application/octet-stream)"),
        (status = 404, description = "No thumbnail of this variant")
    )
)]
pub async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, variant)): Path<(String, String)>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let variant = parse_variant(&variant)?;
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM file_thumbnails WHERE file_id = $1 AND variant = $2)",
    )
    .bind(fid)
    .bind(variant.as_str())
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(AppError::not_found("not found"));
    }
    let (body, size) = state
        .storage
        .get_object(&thumbnail_storage_path(fid, variant))
        .await
        .map_err(|_| AppError::not_found("not found"))?;
    // Clients address a thumbnail with ?v={updatedAt}, so a URL never
    // changes meaning; the browser cache only ever holds ciphertext.
    Ok(octet_stream_response(
        body,
        size,
        &[(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable".to_string(),
        )],
    ))
}

/// `DELETE /api/files/{fileId}/thumbnails` — both variants, e.g. when the
/// content becomes something without a preview.
#[utoipa::path(
    delete,
    path = "/api/files/{fileId}/thumbnails",
    tag = "thumbnails",
    operation_id = "deleteFileThumbnails",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "File id")),
    responses((status = 204, description = "Removed (also when there were none)"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    if !crate::drive_writes::can_write_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }
    let mut tx = state.pool.begin().await?;
    let removed: Vec<(String, i64, Uuid, String)> = sqlx::query_as(
        "DELETE FROM file_thumbnails WHERE file_id = $1
         RETURNING variant, size_bytes, uploader_user_id, s3_version_id",
    )
    .bind(fid)
    .fetch_all(&mut *tx)
    .await?;
    for (_, bytes, uploader, _) in &removed {
        sqlx::query("UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2")
            .bind(bytes)
            .bind(uploader)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    for (variant, _, _, version_id) in removed {
        let Ok(variant) = ThumbnailVariant::try_from(variant.as_str()) else {
            continue;
        };
        let path = thumbnail_storage_path(fid, variant);
        let _ = if version_id.is_empty() {
            state.storage.delete(&path).await
        } else {
            state
                .storage
                .delete_object_version(&path, &version_id)
                .await
        };
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}
