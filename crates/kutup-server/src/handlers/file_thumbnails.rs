//! File thumbnails (docs/plans/drive-thumbnails.md): a client-made preview
//! of a file, sealed under the file key. The server stores each upload under
//! a key of its own, `files/{fileId}/thumbnails/{variant}/{objectId}` (the
//! row names the current one), checks its public header (purpose, file,
//! variant, the content revision it shows, key generation) without any key,
//! and charges its size to the uploader. An upload replaces the previous one
//! of that variant: the row moves to the new object at its commit, and the
//! old object is deleted after it, so no key is ever written twice.

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

/// Where one thumbnail upload is stored; `object_id` is the row's.
pub(crate) fn thumbnail_storage_path(
    file_id: Uuid,
    variant: ThumbnailVariant,
    object_id: Uuid,
) -> String {
    format!(
        "files/{file_id}/thumbnails/{}/{object_id}",
        variant.as_str()
    )
}

/// The current thumbnail object of a variant, as its row names it.
pub(crate) async fn current_object(
    pool: &sqlx::PgPool,
    file_id: Uuid,
    variant: ThumbnailVariant,
) -> sqlx::Result<Option<String>> {
    let object: Option<Uuid> = sqlx::query_scalar(
        "SELECT object_id FROM drive_file_thumbnails WHERE file_id = $1 AND variant = $2",
    )
    .bind(file_id)
    .bind(variant.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(object.map(|object| thumbnail_storage_path(file_id, variant, object)))
}

fn parse_variant(value: &str) -> AppResult<ThumbnailVariant> {
    ThumbnailVariant::try_from(value).map_err(|_| AppError::not_found("not found"))
}

#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    /// The version the picture was drawn from, or `original` for the upload.
    source: Option<String>,
    /// The content revision the envelope is bound to: the one the file's
    /// metadata commits to (docs/plans/drive-block-format.md §2). Readers
    /// open it only while that is still the file's content.
    revision: Option<String>,
}

/// `PUT /api/files/{fileId}/thumbnails/{variant}?source={versionId|original}&revision={revisionId}`
#[utoipa::path(
    put,
    path = "/api/files/{fileId}/thumbnails/{variant}",
    tag = "thumbnails",
    operation_id = "uploadFileThumbnail",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("variant" = String, Path, description = "`sm` or `lg`"),
        ("source" = Option<String>, Query, description = "Version id the picture was drawn from, or `original`"),
        ("revision" = String, Query, description = "The content revision the envelope is bound to (the metadata's `content.revisionId`)")
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
    if !crate::drive_writes::can_write_file(&state.pool, user_id, fid).await? {
        return Err(AppError::forbidden("forbidden"));
    }
    let (collection_id, key_generation): (Uuid, i32) = sqlx::query_as(
        "SELECT collection_id, key_generation FROM drive_files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(fid)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))?;
    let generation = u32::try_from(key_generation)
        .map_err(|_| AppError::bad_request("invalid file key generation"))?;
    let revision = query
        .revision
        .as_deref()
        .ok_or_else(|| AppError::bad_request("revision is required"))?;
    thumbnail::validate(&body, variant, &fid.to_string(), revision, generation)
        .map_err(|_| AppError::bad_request("invalid thumbnail envelope"))?;
    // The envelope binds whatever revision the caller named; it must also be
    // one of this file's: its original content or one of its versions.
    let revision_id =
        Uuid::parse_str(revision).map_err(|_| AppError::bad_request("invalid revision"))?;
    let known_revision: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM drive_files WHERE id = $1 AND content_revision_id = $2)
             OR EXISTS (SELECT 1 FROM drive_file_versions WHERE id = $2 AND file_id = $1)",
    )
    .bind(fid)
    .bind(revision_id)
    .fetch_one(&state.pool)
    .await?;
    if !known_revision {
        return Err(AppError::bad_request("invalid revision"));
    }

    let source_version = match query.source.as_deref() {
        None | Some("original") => None,
        Some(value) => {
            let vid =
                Uuid::parse_str(value).map_err(|_| AppError::bad_request("invalid source"))?;
            let belongs: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM drive_file_versions WHERE id = $1 AND file_id = $2)",
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
    // Sealed under the file key read above; a re-key since would put new
    // content under a key the folder has left.
    crate::drive_writes::lock_file_key(&mut tx, fid, key_generation).await?;
    // One writer per slot, including the first (when there is no row to lock
    // yet): two concurrent uploads would otherwise both be charged.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("file-thumbnail:{fid}:{}", variant.as_str()))
        .execute(&mut *tx)
        .await?;
    let previous: Option<(i64, Uuid, Uuid)> = sqlx::query_as(
        "SELECT size_bytes, uploader_account_id, object_id FROM drive_file_thumbnails
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
    crate::storage_pool::charge(
        &mut *tx,
        crate::storage_pool::Payer::Account(user_id),
        size - own_previous,
    )
    .await?;
    if let Some((bytes, uploader, _)) = previous
        .as_ref()
        .filter(|(_, uploader, _)| *uploader != user_id)
    {
        crate::storage_pool::charge(
            &mut *tx,
            crate::storage_pool::Payer::Account(*uploader),
            -bytes,
        )
        .await?;
    }

    // Stored before commit, with the row lock held, under a key of its own:
    // a failed PUT rolls the whole change back, and the current object is
    // never touched until the row has moved off it.
    let object_id = Uuid::new_v4();
    let path = thumbnail_storage_path(fid, variant, object_id);
    state
        .storage
        .upload(
            &path,
            aws_sdk_s3::primitives::ByteStream::from(body.to_vec()),
            size,
        )
        .await
        .map_err(|_| AppError::internal("storage error"))?;
    sqlx::query(
        r#"INSERT INTO drive_file_thumbnails (file_id, variant, size_bytes, object_id, source_version, uploader_account_id, key_generation, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
           ON CONFLICT (file_id, variant) DO UPDATE SET
             size_bytes = EXCLUDED.size_bytes,
             key_generation = EXCLUDED.key_generation,
             object_id = EXCLUDED.object_id,
             source_version = EXCLUDED.source_version,
             uploader_account_id = EXCLUDED.uploader_account_id,
             updated_at = NOW()"#,
    )
    .bind(fid)
    .bind(variant.as_str())
    .bind(size)
    .bind(object_id)
    .bind(source_version)
    .bind(user_id)
    .bind(key_generation)
    .execute(&mut *tx)
    .await?;
    if tx.commit().await.is_err() {
        let _ = state.storage.delete(&path).await;
        return Err(AppError::internal("commit"));
    }
    // The superseded object, now that no row names it (queued, as every
    // delete is; a failure leaves it to the orphan sweep).
    if let Some((_, _, old)) = previous {
        let _ = state
            .storage
            .delete(&thumbnail_storage_path(fid, variant, old))
            .await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// A file in its owner's trash (on its own, not inside a trashed folder):
/// its owner, who may restore it, may still see its picture (Photos' trash).
async fn owns_trashed_file(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    file_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM drive_files f JOIN drive_collections c ON c.id = f.collection_id
                        WHERE f.id = $1 AND f.trash_root_id = f.id AND c.owner_account_id = $2
                          AND c.deleted_at IS NULL)",
    )
    .bind(file_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
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
    if !can_access_file(&state.pool, user_id, fid).await?
        && !owns_trashed_file(&state.pool, user_id, fid).await?
    {
        return Err(AppError::forbidden("forbidden"));
    }
    serve(&state, fid, variant).await
}

/// A thumbnail's sealed bytes, for whoever may see the file (checked by the caller).
pub(crate) async fn serve_thumbnail(
    state: &AppState,
    fid: Uuid,
    variant: &str,
) -> AppResult<Response> {
    serve(state, fid, parse_variant(variant)?).await
}

async fn serve(state: &AppState, fid: Uuid, variant: ThumbnailVariant) -> AppResult<Response> {
    let Some(path) = current_object(&state.pool, fid, variant).await? else {
        return Err(AppError::not_found("not found"));
    };
    let (body, size) = state
        .storage
        .get_object(&path)
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
    if !crate::drive_writes::can_write_file(&state.pool, user_id, fid).await? {
        return Err(AppError::forbidden("forbidden"));
    }
    let mut tx = state.pool.begin().await?;
    let removed: Vec<(String, i64, Uuid, Uuid)> = sqlx::query_as(
        "DELETE FROM drive_file_thumbnails WHERE file_id = $1
         RETURNING variant, size_bytes, uploader_account_id, object_id",
    )
    .bind(fid)
    .fetch_all(&mut *tx)
    .await?;
    for (_, bytes, uploader, _) in &removed {
        crate::storage_pool::charge(
            &mut *tx,
            crate::storage_pool::Payer::Account(*uploader),
            -bytes,
        )
        .await?;
    }
    tx.commit().await?;
    for (variant, _, _, object_id) in removed {
        let Ok(variant) = ThumbnailVariant::try_from(variant.as_str()) else {
            continue;
        };
        let _ = state
            .storage
            .delete(&thumbnail_storage_path(fid, variant, object_id))
            .await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}
