//! Name and content hashes beside the writes that carry them
//! (docs/plans/drive-unique-names.md): a file's content hash once its upload
//! has read it all, and which names are free in a folder.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::drive_names::{self, Place};
use crate::error::{AppError, AppResult};
use crate::handlers::drive_move::writable_folder;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentHashRequest {
    /// HMAC-SHA256 under the folder's hash key of the plaintext's SHA-256.
    pub content_hash: String,
}

/// `PUT /api/files/{id}/content-hash` — what a file's content is recognised
/// by in its folder, recorded once the upload has read it all. Whoever can
/// write the folder (or edit the file shared by itself).
#[utoipa::path(
    put,
    path = "/api/files/{id}/content-hash",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = ContentHashRequest,
    responses((status = 204, description = "Recorded"), (status = 404, description = "No such file"))
)]
pub async fn set_content_hash(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ContentHashRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let hash = drive_names::parse_content_hash(Some(&req.content_hash))?
        .ok_or_else(|| AppError::bad_request("invalid content hash"))?;
    let mut tx = state.pool.begin().await?;
    let folder: Option<Uuid> = sqlx::query_scalar(
        "SELECT collection_id FROM files WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(folder) = folder else {
        return Err(AppError::not_found("not found"));
    };
    if !crate::drive_writes::is_file_share_editor(&state.pool, user_id, file_id).await? {
        writable_folder(&mut tx, user_id, folder).await?;
    }
    sqlx::query("UPDATE files SET content_hash = $2 WHERE id = $1")
        .bind(file_id)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Most hashes one `available-hashes` request asks about, as Proton's
/// `checkAvailableHashes` batches (`HASH_CHECK_AMOUNT`).
pub const MAX_ASKED: usize = 10;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailableHashesRequest {
    /// Up to ten name hashes under the folder's hash key.
    pub hashes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AvailableHashes {
    /// The asked hashes no live file or folder there holds, in the order asked.
    pub available: Vec<String>,
}

/// `POST /api/collections/{id}/available-hashes` — which of these names are
/// free in the folder (Proton Drive's `checkAvailableHashes`): "Keep both"
/// and a restore into a taken name pick `name (n)` against the server, not a
/// listing that may be stale. Whoever can write the folder, ten at a time,
/// rate-limited per account; it tells no more than listing the folder does.
#[utoipa::path(
    post,
    path = "/api/collections/{id}/available-hashes",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Folder id")),
    request_body = AvailableHashesRequest,
    responses((status = 200, description = "The free ones", body = AvailableHashes))
)]
pub async fn available_hashes(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<AvailableHashesRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let folder = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    writable_folder(&mut tx, user_id, folder).await?;
    let available = free_of(&mut tx, Place::Folder(folder), user_id, &req).await?;
    tx.commit().await?;
    Ok(Json(AvailableHashes { available }).into_response())
}

/// `POST /api/drive/top-level-available-hashes` — the same among the
/// account's top-level folders.
#[utoipa::path(
    post,
    path = "/api/drive/top-level-available-hashes",
    tag = "collections",
    security(("BearerAuth" = [])),
    request_body = AvailableHashesRequest,
    responses((status = 200, description = "The free ones", body = AvailableHashes))
)]
pub async fn top_level_available_hashes(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AvailableHashesRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    let available = free_of(&mut tx, Place::TopLevel(user_id), user_id, &req).await?;
    tx.commit().await?;
    Ok(Json(AvailableHashes { available }).into_response())
}

async fn free_of(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    place: Place,
    user_id: Uuid,
    req: &AvailableHashesRequest,
) -> AppResult<Vec<String>> {
    if req.hashes.is_empty() || req.hashes.len() > MAX_ASKED {
        return Err(AppError::bad_request("ask about one to ten hashes"));
    }
    if !crate::ratelimit::AVAILABLE_HASHES.allow(&user_id.to_string()) {
        return Err(AppError::too_many_requests("too many name checks")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    let mut available = Vec::new();
    for hash in &req.hashes {
        let hash = drive_names::require_name_hash(Some(hash))?;
        if drive_names::ensure_name_free(tx, place, &hash, None)
            .await
            .is_ok()
        {
            available.push(hash);
        }
    }
    Ok(available)
}
