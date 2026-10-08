//! Filling in name and content hashes (docs/plans/drive-unique-names.md):
//! a file's content hash once its upload has read it all, and the name
//! hashes of what was made before names were kept unique.

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
    if !crate::drive_writes::is_file_share_editor(&state.pool, user_id, file_id).await {
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

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamedItem {
    pub id: String,
    pub name_hash: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FillNameHashesRequest {
    #[serde(default)]
    pub files: Vec<NamedItem>,
    #[serde(default)]
    pub folders: Vec<NamedItem>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NameClash {
    /// The item whose hash was not stored.
    pub id: String,
    /// `file` or `folder`: what already holds the name.
    pub holder_kind: String,
    pub holder_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FillNameHashesResult {
    /// Items whose name another already holds: rename one, then send again.
    pub clashes: Vec<NameClash>,
}

/// The most items one request fills in.
const MAX_ITEMS: usize = 1000;

/// `POST /api/collections/{id}/name-hashes` — the name hashes of a folder's
/// files and subfolders made before names were kept unique. Only items
/// without one are filled in; one whose name another already holds is
/// left out and reported. Whoever can write the folder.
#[utoipa::path(
    post,
    path = "/api/collections/{id}/name-hashes",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Folder id")),
    request_body = FillNameHashesRequest,
    responses((status = 200, description = "Filled in, with the clashes", body = FillNameHashesResult))
)]
pub async fn fill_name_hashes(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<FillNameHashesRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let folder = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    writable_folder(&mut tx, user_id, folder).await?;
    let place = Place::Folder(folder);
    let clashes = fill(&mut tx, place, &req, Some(folder)).await?;
    tx.commit().await?;
    Ok(Json(FillNameHashesResult { clashes }).into_response())
}

/// `POST /api/drive/top-level-name-hashes` — the same for the account's
/// top-level folders (no files live there).
#[utoipa::path(
    post,
    path = "/api/drive/top-level-name-hashes",
    tag = "collections",
    security(("BearerAuth" = [])),
    request_body = FillNameHashesRequest,
    responses((status = 200, description = "Filled in, with the clashes", body = FillNameHashesResult))
)]
pub async fn fill_top_level_name_hashes(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<FillNameHashesRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    if !req.files.is_empty() {
        return Err(AppError::bad_request("no files live at the top level"));
    }
    let mut tx = state.pool.begin().await?;
    let clashes = fill(&mut tx, Place::TopLevel(user_id), &req, None).await?;
    tx.commit().await?;
    Ok(Json(FillNameHashesResult { clashes }).into_response())
}

async fn fill(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    place: Place,
    req: &FillNameHashesRequest,
    folder: Option<Uuid>,
) -> AppResult<Vec<NameClash>> {
    if req.files.len() + req.folders.len() > MAX_ITEMS {
        return Err(AppError::bad_request("too many items"));
    }
    drive_names::lock_place(tx, place).await?;
    let mut clashes = Vec::new();
    for (items, is_file) in [(&req.files, true), (&req.folders, false)] {
        for item in items {
            let id =
                Uuid::parse_str(&item.id).map_err(|_| AppError::bad_request("invalid item id"))?;
            let hash = drive_names::parse_name_hash(Some(&item.name_hash))?
                .ok_or_else(|| AppError::bad_request("invalid name hash"))?;
            // Only an item of this place, still without a hash.
            let pending: bool = if is_file {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM files
                                    WHERE id = $1 AND collection_id = $2 AND deleted_at IS NULL AND name_hash IS NULL)",
                )
                .bind(id)
                .bind(folder)
                .fetch_one(&mut **tx)
                .await?
            } else {
                let (parent, owner) = match place {
                    Place::Folder(folder) => (Some(folder), None),
                    Place::TopLevel(owner) => (None, Some(owner)),
                };
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM collections
                                    WHERE id = $1 AND kind = 'folder' AND deleted_at IS NULL AND name_hash IS NULL
                                      AND parent_collection_id IS NOT DISTINCT FROM $2
                                      AND ($3::uuid IS NULL OR owner_user_id = $3))",
                )
                .bind(id)
                .bind(parent)
                .bind(owner)
                .fetch_one(&mut **tx)
                .await?
            };
            if !pending {
                continue;
            }
            if let Err(error) = drive_names::ensure_name_free(tx, place, &hash, Some(id)).await {
                let holder = error
                    .details
                    .as_ref()
                    .and_then(|details| details.get("holder"))
                    .cloned()
                    .unwrap_or_default();
                clashes.push(NameClash {
                    id: id.to_string(),
                    holder_kind: holder["kind"].as_str().unwrap_or_default().to_owned(),
                    holder_id: holder["id"].as_str().unwrap_or_default().to_owned(),
                });
                continue;
            }
            let table = if is_file { "files" } else { "collections" };
            sqlx::query(&format!("UPDATE {table} SET name_hash = $2 WHERE id = $1"))
                .bind(id)
                .bind(&hash)
                .execute(&mut **tx)
                .await
                .map_err(drive_names::map_unique_violation)?;
        }
    }
    Ok(clashes)
}
