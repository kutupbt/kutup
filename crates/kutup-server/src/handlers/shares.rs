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
    /// V1 accepts only "collection".
    share_type: String,
    target_id: String,
    collection_key_envelope: String,
    expires_in_hours: Option<i64>,
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

    if req.share_type != "collection" {
        return Err(AppError::bad_request("unsupported public share type"));
    }
    let target_uuid = canonical_uuid(&req.target_id)?;
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
    let epoch =
        u32::try_from(key_epoch).map_err(|_| AppError::conflict("invalid collection epoch"))?;
    let envelope_context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::PublicLinkCollectionKey,
        epoch,
        1,
        &req.target_id,
        &user_id.to_string(),
    )
    .map_err(|_| AppError::bad_request("invalid Drive envelope"))?;
    validate_envelope(&req.collection_key_envelope, envelope_context)?;

    let token = random_token(32);
    let expires_at: Option<OffsetDateTime> = req
        .expires_in_hours
        .map(|h| OffsetDateTime::now_utc() + time::Duration::hours(h));

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO public_shares (share_type, target_id, token,
                                      collection_key_envelope, collection_key_epoch,
                                      owner_user_id, expires_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           RETURNING id"#,
    )
    .bind(&req.share_type)
    .bind(target_uuid)
    .bind(&token)
    .bind(&req.collection_key_envelope)
    .bind(key_epoch)
    .bind(user_id)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "token": token}))).into_response())
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
    #[serde(with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
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
    );
    let row: Option<ShareRow> = sqlx::query_as(
        r#"SELECT id, share_type, target_id,
                  collection_key_envelope, collection_key_epoch, owner_user_id, expires_at
           FROM public_shares WHERE token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((id, share_type, target_id, envelope, epoch, owner_user_id, expires_at)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }
    Ok(Json(PublicShareResponse {
        id,
        share_type,
        target_id,
        collection_key_envelope: envelope,
        collection_key_epoch: epoch,
        owner_user_id,
        expires_at,
    })
    .into_response())
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
    metadata_revision: i64,
    encrypted_size_bytes: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
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
    let live: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM collections WHERE id = $1 AND deleted_at IS NULL")
            .bind(target_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    if live.unwrap_or(0) == 0 {
        return Err(AppError::not_found("not found"));
    }

    type PubFileTuple = (Uuid, Uuid, String, String, i32, i64, i64, OffsetDateTime);
    let rows: Vec<PubFileTuple> = sqlx::query_as(
        r#"SELECT id, collection_id, metadata_envelope, file_key_envelope,
                  key_epoch, metadata_revision, encrypted_size_bytes, created_at
           FROM files WHERE collection_id = $1 AND deleted_at IS NULL
           ORDER BY created_at DESC"#,
    )
    .bind(target_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let files: Vec<PublicFileRow> = rows
        .into_iter()
        .map(
            |(id, collection_id, metadata, file_key, epoch, revision, size, created_at)| {
                PublicFileRow {
                    id,
                    collection_id,
                    metadata_envelope: metadata,
                    file_key_envelope: file_key,
                    key_epoch: epoch,
                    metadata_revision: revision,
                    encrypted_size_bytes: size,
                    created_at,
                }
            },
        )
        .collect();
    Ok(Json(files).into_response())
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

    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let file: Option<(String, Uuid)> = sqlx::query_as(
        "SELECT storage_path, collection_id FROM files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(fid)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((storage_path, coll_id)) = file else {
        return Err(AppError::not_found("not found"));
    };

    if share_type == "collection" && coll_id != target_id {
        return Err(AppError::forbidden("forbidden"));
    }
    if share_type == "file" && fid != target_id {
        return Err(AppError::forbidden("forbidden"));
    }

    let (body, size) = state
        .storage
        .get_object(&storage_path)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    Ok(octet_stream_response(body, size, &[]))
}
