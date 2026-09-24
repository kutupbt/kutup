//! Moving files and folders (docs/plans/drive-move.md).
//!
//! Everything sealed under a file's key is bound to the file alone; only the
//! file-key wrap names its folder. Moving a file therefore replaces that one
//! envelope, sealed by the client for the destination, and nothing else. A
//! folder's key is sealed to its owner, not to its parent, so moving a folder
//! changes nothing encrypted at all.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::files::validate_envelope;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoveFileRequest {
    /// The folder the client saw the file in (compare-and-swap).
    pub from_collection_id: String,
    pub to_collection_id: String,
    /// The destination's current epoch, which the envelope is sealed at.
    pub to_key_epoch: i32,
    /// The file's current key sealed under the destination's key.
    pub file_key_envelope: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MoveFileResult {
    pub collection_id: String,
    pub key_epoch: i32,
}

/// Whether `user_id` may add to or remove from `collection_id`, and its
/// owner: the owner, or a member who can edit. Holds the folder until the
/// transaction ends, so a rotation or removal waits.
async fn writable_folder(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    collection_id: Uuid,
) -> AppResult<(Uuid, i32)> {
    let folder: Option<(Uuid, i32, bool)> = sqlx::query_as(
        r#"SELECT c.owner_user_id, c.key_epoch,
                  c.owner_user_id = $2
                  OR EXISTS(SELECT 1 FROM collection_shares cs
                            WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2
                              AND cs.can_upload)
           FROM collections c WHERE c.id = $1 AND c.deleted_at IS NULL FOR SHARE"#,
    )
    .bind(collection_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    match folder {
        Some((owner, epoch, true)) => Ok((owner, epoch)),
        Some(_) => Err(AppError::forbidden("forbidden")),
        None => Err(AppError::not_found("not found")),
    }
}

/// `POST /api/files/{id}/move` — move a file to another folder of the same
/// owner. Needs edit rights on both. The client re-seals only the file's
/// key for the destination; a file its source folder has rotated past is
/// re-keyed first, so no one removed from the source can follow it.
#[utoipa::path(
    post,
    path = "/api/files/{id}/move",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = MoveFileRequest,
    responses(
        (status = 200, description = "Moved", body = MoveFileResult),
        (status = 400, description = "Invalid envelope, or the same folder, or another owner's folder"),
        (status = 409, description = "The file moved or needs a re-key, or the destination's key changed")
    )
)]
pub async fn move_file(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<MoveFileRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let from = Uuid::parse_str(&req.from_collection_id)
        .map_err(|_| AppError::bad_request("invalid request"))?;
    let to = crate::handlers::files::canonical_uuid(&req.to_collection_id)?;
    if from == to {
        return Err(AppError::bad_request("the file is already in that folder"));
    }

    let mut tx = state.pool.begin().await?;
    let file: Option<(Uuid, i32, i32)> = sqlx::query_as(
        "SELECT collection_id, key_epoch, key_generation
         FROM files WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((current, wrapped_at, generation)) = file else {
        return Err(AppError::not_found("not found"));
    };
    // Access before anything about the file's state is revealed.
    let (source_owner, source_epoch) = writable_folder(&mut tx, user_id, current).await?;
    let (target_owner, target_epoch) = writable_folder(&mut tx, user_id, to).await?;
    if current != from {
        return Err(AppError::conflict("the file moved"));
    }
    // Quota and ownership stay with one owner; across owners it is a copy.
    if source_owner != target_owner {
        return Err(AppError::bad_request(
            "a file moves only between folders of the same owner",
        ));
    }
    if wrapped_at != source_epoch {
        return Err(AppError::conflict("file needs a re-key"));
    }
    if target_epoch != req.to_key_epoch {
        return Err(AppError::conflict("folder key changed"));
    }
    validate_envelope(
        &req.file_key_envelope,
        DriveEnvelopeContextV1::file_key(
            &file_id.to_string(),
            &to.to_string(),
            target_epoch as u32,
            generation as u32,
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    sqlx::query(
        "UPDATE files SET collection_id = $2, key_epoch = $3, file_key_envelope = $4 WHERE id = $1",
    )
    .bind(file_id)
    .bind(to)
    .bind(target_epoch)
    .bind(&req.file_key_envelope)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // Who may open it changed: live sessions reconnect and are checked again.
    state.hub.close_room(&file_id.to_string());
    Ok(Json(MoveFileResult {
        collection_id: to.to_string(),
        key_epoch: target_epoch,
    })
    .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoveCollectionRequest {
    /// The new parent folder, or none for the top level.
    pub parent_collection_id: Option<String>,
}

/// `POST /api/collections/{id}/move` — put a folder under another of the
/// owner's folders, or at the top level. Owner only. A folder never goes
/// into itself or anything under it.
#[utoipa::path(
    post,
    path = "/api/collections/{id}/move",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    request_body = MoveCollectionRequest,
    responses(
        (status = 204, description = "Moved"),
        (status = 400, description = "Into itself, or under a folder that is not the owner's")
    )
)]
pub async fn move_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<MoveCollectionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let folder = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let parent = req
        .parent_collection_id
        .as_deref()
        .map(crate::handlers::files::canonical_uuid)
        .transpose()?;

    let mut tx = state.pool.begin().await?;
    // One tree change per owner at a time: two moves checked side by side
    // could otherwise each pass and together close a loop.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("kutup:folder-tree:{user_id}"))
        .execute(&mut *tx)
        .await?;
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM collections
                       WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL)",
    )
    .bind(folder)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if !owned {
        return Err(AppError::not_found("not found"));
    }
    if let Some(parent) = parent {
        // The destination and every folder above it: none may be the folder.
        let (parent_owned, loops): (bool, bool) = sqlx::query_as(
            r#"WITH RECURSIVE above AS (
                 SELECT id, parent_collection_id FROM collections
                 WHERE id = $1 AND owner_user_id = $3 AND deleted_at IS NULL
                 UNION ALL
                 SELECT c.id, c.parent_collection_id FROM collections c
                 JOIN above a ON c.id = a.parent_collection_id
               )
               SELECT EXISTS(SELECT 1 FROM above WHERE id = $1),
                      EXISTS(SELECT 1 FROM above WHERE id = $2)"#,
        )
        .bind(parent)
        .bind(folder)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        if !parent_owned {
            return Err(AppError::bad_request("invalid parent collection"));
        }
        if loops {
            return Err(AppError::bad_request(
                "a folder cannot move into itself or a folder inside it",
            ));
        }
    }
    sqlx::query("UPDATE collections SET parent_collection_id = $2 WHERE id = $1")
        .bind(folder)
        .bind(parent)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
