//! Public-share handlers — mirrors `backend/handlers/shares.go`.
//!
//! A public share is a tokenised link to a collection or file. The link key never reaches
//! the server (it lives only in the URL `#fragment`); we store the collection key already
//! wrapped with that link key, so the stored ciphertext is useless without the fragment.
//! Read endpoints are anonymous — the token is the capability.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::drive_envelope::{DriveEnvelopeContextV1, DriveEnvelopePurpose};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::files::{canonical_uuid, validate_envelope};
use crate::handlers::{octet_stream_response, random_token};
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateShareRequest {
    /// "collection" (a folder) or "file" (one file).
    share_type: String,
    target_id: String,
    collection_key_envelope: String,
    expires_in_hours: Option<i64>,
    /// The link's id, chosen by the client (it is bound into the owner's copy).
    id: String,
    /// The link key sealed for the owner under their master key (purpose 9),
    /// so the owner can list and copy the link and keep it working across a
    /// rotation (docs/plans/drive-share-revocation.md).
    owner_link_key_envelope: String,
}

/// `POST /api/share` — mirrors `CreatePublicShare`. The link key is never sent here.
#[utoipa::path(
    post,
    path = "/api/share",
    tag = "shares",
    security(("BearerAuth" = [])),
    request_body = crate::models::CreateShareRequest,
    responses((status = 201, description = "Share created", body = crate::models::CreateShareResult))
)]
pub async fn create_public_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateShareRequest>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;

    let target_uuid = canonical_uuid(&req.target_id)?;
    // The key version the wrap is bound to: the folder's epoch, or the file
    // key's generation.
    let key_epoch: i32 = match req.share_type.as_str() {
        "collection" => {
            let key_epoch: Option<i32> = sqlx::query_scalar(
                "SELECT key_epoch FROM collections \
                 WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL",
            )
            .bind(target_uuid)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
            let Some(key_epoch) = key_epoch else {
                return Err(AppError::forbidden("forbidden"));
            };
            let epoch = u32::try_from(key_epoch)
                .map_err(|_| AppError::conflict("invalid collection epoch"))?;
            validate_envelope(
                &req.collection_key_envelope,
                DriveEnvelopeContextV1::new(
                    DriveEnvelopePurpose::PublicLinkCollectionKey,
                    epoch,
                    1,
                    &req.target_id,
                    &user_id.to_string(),
                )
                .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
            )?;
            key_epoch
        }
        // A link to one file (docs/plans/drive-file-sharing.md, slice 3):
        // its current key, sealed under the link key.
        "file" => {
            let generation: Option<i32> = sqlx::query_scalar(
                "SELECT f.key_generation FROM files f JOIN collections c ON c.id = f.collection_id
                 WHERE f.id = $1 AND c.owner_user_id = $2
                   AND f.deleted_at IS NULL AND c.deleted_at IS NULL",
            )
            .bind(target_uuid)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
            let Some(generation) = generation else {
                return Err(AppError::forbidden("forbidden"));
            };
            validate_envelope(
                &req.collection_key_envelope,
                DriveEnvelopeContextV1::public_link_file_key(
                    &req.target_id,
                    &user_id.to_string(),
                    u32::try_from(generation)
                        .map_err(|_| AppError::conflict("invalid key generation"))?,
                )
                .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
            )?;
            generation
        }
        _ => return Err(AppError::bad_request("unsupported public share type")),
    };
    let link_id = canonical_uuid(&req.id)?;
    validate_envelope(
        &req.owner_link_key_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::PublicLinkKey,
            1,
            1,
            &req.id,
            &user_id.to_string(),
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;

    let token = random_token(32);
    // An hour to ten years; anything else is a mistake (and a large value
    // would overflow the date arithmetic).
    let expires_at: Option<OffsetDateTime> = match req.expires_in_hours {
        None => None,
        Some(h) if (1..=MAX_LINK_HOURS).contains(&h) => {
            Some(OffsetDateTime::now_utc() + time::Duration::hours(h))
        }
        Some(_) => return Err(AppError::bad_request("expiresInHours out of range")),
    };

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO public_shares (id, share_type, target_id, token,
                                      collection_key_envelope, collection_key_epoch,
                                      owner_user_id, expires_at, owner_link_key_envelope)
           VALUES ($9,$1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id"#,
    )
    .bind(&req.share_type)
    .bind(target_uuid)
    .bind(&token)
    .bind(&req.collection_key_envelope)
    .bind(key_epoch)
    .bind(user_id)
    .bind(expires_at)
    .bind(&req.owner_link_key_envelope)
    .bind(link_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "token": token}))).into_response())
}

/// The longest a public link may live: ten years, in hours.
const MAX_LINK_HOURS: i64 = 10 * 366 * 24;

/// Whether a shared folder is live (not trashed, not gone).
async fn collection_live(state: &AppState, collection_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM collections WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(collection_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false)
}

/// Whether a linked file is live (it and its folder not trashed, not gone).
async fn file_live(state: &AppState, file_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM files f JOIN collections c ON c.id = f.collection_id
                        WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL)",
    )
    .bind(file_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false)
}

/// Whether a link's target is live, whichever kind it is.
async fn target_live(state: &AppState, share_type: &str, target_id: Uuid) -> bool {
    match share_type {
        "collection" => collection_live(state, target_id).await,
        "file" => file_live(state, target_id).await,
        _ => false,
    }
}

/// Authenticated public context plus the opaque key envelope. The fragment key
/// is deliberately absent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicShareResponse {
    id: Uuid,
    share_type: String,
    target_id: Uuid,
    collection_key_envelope: String,
    collection_key_epoch: i32,
    owner_user_id: Uuid,
    /// The owner's account authority, which signs the folder's key history.
    owner_authority_public_key: String,
    #[serde(with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
    /// A link to one file: the file (its key wrap is `collectionKeyEnvelope`,
    /// at generation `collectionKeyEpoch`).
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<PublicFileRow>,
}

/// `GET /api/share/{token}` — mirrors `GetPublicShare`. Anonymous.
#[utoipa::path(
    get,
    path = "/api/share/{token}",
    tag = "shares",
    params(("token" = String, Path, description = "Share token (the capability)")),
    responses((status = 200, description = "Share metadata + wrapped key", body = crate::models::PublicShareResponse))
)]
pub async fn get_public_share(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    type ShareRow = (
        Uuid,
        String,
        Uuid,
        String,
        i32,
        Uuid,
        Option<OffsetDateTime>,
        String,
    );
    let row: Option<ShareRow> = sqlx::query_as(
        r#"SELECT p.id, p.share_type, p.target_id,
                  p.collection_key_envelope, p.collection_key_epoch, p.owner_user_id, p.expires_at,
                  u.account_authority_public_key
           FROM public_shares p JOIN users u ON u.id = p.owner_user_id WHERE p.token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((id, share_type, target_id, envelope, epoch, owner_user_id, expires_at, authority)) =
        row
    else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }
    // Dark while its folder (or file) is in the trash, like the downloads.
    if !target_live(&state, &share_type, target_id).await {
        return Err(AppError::not_found("not found"));
    }
    let file = if share_type == "file" {
        public_files(&state, "f.id = $1", target_id).await?.pop()
    } else {
        None
    };
    Ok(Json(PublicShareResponse {
        id,
        share_type,
        target_id,
        collection_key_envelope: envelope,
        collection_key_epoch: epoch,
        owner_user_id,
        owner_authority_public_key: authority,
        expires_at,
        file,
    })
    .into_response())
}

/// `GET /api/share/{token}/epochs` — the shared folder's key history, so a
/// link holder can open files sealed before the folder's last rotation.
/// Anonymous.
#[utoipa::path(
    get,
    path = "/api/share/{token}/epochs",
    tag = "shares",
    params(("token" = String, Path, description = "Share token (the capability)")),
    responses((status = 200, description = "Key history, oldest first", body = Vec<crate::handlers::folder_access::EpochLink>))
)]
pub async fn public_share_epochs(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let meta: Option<(Uuid, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT target_id, expires_at FROM public_shares WHERE token = $1 AND share_type = 'collection'",
    )
            .bind(&token)
            .fetch_optional(&state.pool)
            .await?;
    let Some((target_id, expires_at)) = meta else {
        return Err(AppError::not_found("not found"));
    };
    if expires_at.is_some_and(|exp| OffsetDateTime::now_utc() > exp) {
        return Err(AppError::new(StatusCode::GONE, "link expired"));
    }
    if !collection_live(&state, target_id).await {
        return Err(AppError::not_found("not found"));
    }
    Ok(
        Json(crate::handlers::folder_access::epoch_chain(&state.pool, target_id).await?)
            .into_response(),
    )
}

/// One file in a public-collection share. Field order mirrors the Go struct; `created_at`
/// is the Postgres timestamp rendered as the same text Go's `time.Time` JSON produces.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct PublicFileRow {
    id: Uuid,
    collection_id: Uuid,
    metadata_envelope: String,
    file_key_envelope: String,
    key_epoch: i32,
    key_generation: i32,
    metadata_revision: i64,
    encrypted_size_bytes: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    original_key_generation: i32,
    content_key_generation: i32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    key_history: Vec<crate::models::FileKeyHistoryEntry>,
}

/// `GET /api/share/{token}/files` — mirrors `ListPublicShareFiles`. Anonymous.
#[utoipa::path(
    get,
    path = "/api/share/{token}/files",
    tag = "shares",
    params(("token" = String, Path, description = "Share token (the capability)")),
    responses((status = 200, description = "Files in the shared collection", body = Vec<PublicFileRow>))
)]
pub async fn list_public_share_files(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let meta: Option<(Uuid, String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT target_id, share_type, expires_at FROM public_shares WHERE token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((target_id, share_type, expires_at)) = meta else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }
    if share_type != "collection" {
        return Err(AppError::bad_request("not a collection share"));
    }
    // A trashed collection's share links go dark until it is restored.
    if !collection_live(&state, target_id).await {
        return Err(AppError::not_found("not found"));
    }

    let files = public_files(&state, "f.collection_id = $1", target_id).await?;
    Ok(Json(files).into_response())
}

/// The files matching `filter` (on `f`, `$1` = `id`), as a public link shows them.
async fn public_files(state: &AppState, filter: &str, id: Uuid) -> AppResult<Vec<PublicFileRow>> {
    type PubFileTuple = (
        Uuid,
        Uuid,
        String,
        String,
        i32,
        i32,
        i64,
        i64,
        OffsetDateTime,
        i32,
        i32,
        sqlx::types::Json<Vec<crate::models::FileKeyHistoryEntry>>,
    );
    let rows: Vec<PubFileTuple> = sqlx::query_as(&format!(
        r#"SELECT f.id, f.collection_id, f.metadata_envelope, f.file_key_envelope,
                  f.key_epoch, f.key_generation, f.metadata_revision, f.encrypted_size_bytes,
                  f.created_at, f.original_key_generation, {}, {}
           FROM files f WHERE {} AND f.deleted_at IS NULL
           ORDER BY f.created_at DESC"#,
        crate::models::CONTENT_KEY_GENERATION_SQL,
        crate::models::FILE_KEY_HISTORY_SQL,
        filter
    ))
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                collection_id,
                metadata,
                file_key,
                epoch,
                generation,
                revision,
                size,
                created_at,
                original_key_generation,
                content_key_generation,
                key_history,
            )| {
                PublicFileRow {
                    id,
                    collection_id,
                    metadata_envelope: metadata,
                    file_key_envelope: file_key,
                    key_epoch: epoch,
                    key_generation: generation,
                    metadata_revision: revision,
                    encrypted_size_bytes: size,
                    created_at,
                    original_key_generation,
                    content_key_generation,
                    key_history: key_history.0,
                }
            },
        )
        .collect())
}

/// The file `file_id`, when the link `token` reaches it (its folder's file,
/// or the one file it links to) and is live and unexpired.
async fn link_reaches(state: &AppState, token: &str, file_id: &str) -> AppResult<Uuid> {
    let meta: Option<(Uuid, String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT target_id, share_type, expires_at FROM public_shares WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((target_id, share_type, expires_at)) = meta else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }

    let fid = Uuid::parse_str(file_id).map_err(|_| AppError::not_found("not found"))?;
    let coll_id: Option<Uuid> =
        sqlx::query_scalar("SELECT collection_id FROM files WHERE id = $1 AND deleted_at IS NULL")
            .bind(fid)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let Some(coll_id) = coll_id else {
        return Err(AppError::not_found("not found"));
    };

    // A folder link reaches its folder's files; a file link its one file.
    let reaches = match share_type.as_str() {
        "collection" => coll_id == target_id,
        "file" => fid == target_id,
        _ => false,
    };
    if !reaches {
        return Err(AppError::forbidden("forbidden"));
    }
    if !target_live(state, &share_type, target_id).await {
        return Err(AppError::not_found("not found"));
    }

    Ok(fid)
}

/// `GET /api/share/{token}/state/{fileId}` — a note's or place list's latest
/// saved state (a Yjs version, sealed under the file key of the generation in
/// `X-Kutup-Key-Generation`), for the page to turn back into the file: their
/// edits are not whole-file versions, so the download alone would be the
/// upload. `404` when it has none. Anonymous.
#[utoipa::path(
    get,
    path = "/api/share/{token}/state/{fileId}",
    tag = "shares",
    params(
        ("token" = String, Path, description = "Share token (the capability)"),
        ("fileId" = String, Path, description = "File id")
    ),
    responses((status = 200, description = "The sealed state (application/octet-stream)"), (status = 404, description = "No saved state"))
)]
pub async fn public_share_state(
    State(state): State<AppState>,
    Path((token, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let fid = link_reaches(&state, &token, &file_id).await?;
    let latest: Option<(String, String, i64, i32)> = sqlx::query_as(
        "SELECT storage_path, s3_version_id, size_bytes, key_generation FROM file_versions
         WHERE file_id = $1 AND kind = 'yjs' AND size_bytes > 0
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(fid)
    .fetch_optional(&state.pool)
    .await?;
    let Some((path, s3_version_id, _, key_generation)) = latest else {
        return Err(AppError::not_found("no saved state"));
    };
    let (body, size) = if s3_version_id.is_empty() {
        state.storage.get_object(&path).await
    } else {
        state
            .storage
            .get_object_version(&path, &s3_version_id)
            .await
    }
    .map_err(|_| AppError::internal("storage"))?;
    Ok(octet_stream_response(
        body,
        size,
        &[(
            axum::http::HeaderName::from_static("x-kutup-key-generation"),
            key_generation.to_string(),
        )],
    ))
}

/// `GET /api/share/{token}/download/{fileId}` — streams the encrypted blob. Anonymous:
/// the token is the capability, and the content is E2EE (the link key that unwraps it
/// lives only in the URL fragment, never reaching the server).
///
/// This used to return a presigned S3 URL, but the storage endpoint is deliberately
/// unreachable from outside the deployment (`http://seaweedfs-s3:8333` in the bundled
/// compose), so no external client could follow it. Streaming through the backend
/// matches every other download path.
#[utoipa::path(
    get,
    path = "/api/share/{token}/download/{fileId}",
    tag = "shares",
    params(
        ("token" = String, Path, description = "Share token (the capability)"),
        ("fileId" = String, Path, description = "File id")
    ),
    responses((status = 200, description = "The encrypted blob (application/octet-stream)"))
)]
pub async fn download_public_share_file(
    State(state): State<AppState>,
    Path((token, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let fid = link_reaches(&state, &token, &file_id).await?;
    // A public link shows the file as it is now, edits included.
    let content = crate::file_content::current_content(&state.pool, fid)
        .await?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let (body, size) = content
        .open(&state.storage)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    Ok(octet_stream_response(body, size, &[]))
}
