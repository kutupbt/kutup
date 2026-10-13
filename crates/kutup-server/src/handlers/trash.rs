//! Trash endpoints — list, restore, permanent delete, empty.
//!
//! Trash is **owner-scoped**: an item lives in the trash of the user who owns the
//! collection it belongs to (matching Google Drive's shared-folder semantics — a share
//! recipient's delete lands in the owner's trash). Every entry is a *trash root*
//! (`trash_root_id = its own id`); a deleted folder is one entry that carries its whole
//! subtree. Trashed items keep counting against quota until they are purged here or by
//! the retention sweeper (`jobs::trash_sweep_once`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::jobs;
use crate::middleware::AuthUser;
use crate::models::{MessageResponse, TrashFileRow, TrashFolderRow, TrashResponse};
use crate::AppState;

/// `GET /api/trash` — the caller's trash roots (owned folders + files), newest first.
#[utoipa::path(
    get,
    path = "/api/trash",
    tag = "trash",
    operation_id = "listTrash",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's trash roots, newest first", body = TrashResponse))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;

    type FolderTuple = (
        Uuid,
        Uuid,
        String,
        String,
        i32,
        i64,
        String,
        String,
        Option<String>,
        Option<Uuid>,
        i64,
        OffsetDateTime,
    );
    let folders: Vec<FolderTuple> = sqlx::query_as(
        r#"SELECT c.id, c.owner_user_id, c.name_envelope, c.owner_key_envelope,
                  c.key_epoch, c.name_revision, c.epoch_statement, c.epoch_statement_hash, c.color,
                  (SELECT p.id FROM collections p
                    WHERE p.id = c.parent_collection_id AND p.deleted_at IS NULL),
                  (SELECT COUNT(*) FROM files f WHERE f.trash_root_id = c.id),
                  c.deleted_at
           FROM collections c
           WHERE c.owner_user_id = $1 AND c.trash_root_id = c.id
           ORDER BY c.deleted_at DESC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    #[derive(sqlx::FromRow)]
    struct TrashedFile {
        id: Uuid,
        collection_id: Uuid,
        metadata_envelope: String,
        file_key_envelope: String,
        key_epoch: i32,
        key_generation: i32,
        metadata_revision: i64,
        owner_user_id: Uuid,
        owner_key_envelope: String,
        collection_key_epoch: i32,
        epoch_statement: String,
        epoch_statement_hash: String,
        deleted_at: OffsetDateTime,
        thumb_sm: Option<OffsetDateTime>,
        thumb_lg: Option<OffsetDateTime>,
        thumb_sm_generation: Option<i32>,
        thumb_lg_generation: Option<i32>,
    }
    let files: Vec<TrashedFile> = sqlx::query_as(
        r#"SELECT f.id, f.collection_id, f.metadata_envelope, f.file_key_envelope,
                  f.key_epoch, f.key_generation, f.metadata_revision,
                  c.owner_user_id, c.owner_key_envelope, c.key_epoch AS collection_key_epoch,
                  c.epoch_statement, c.epoch_statement_hash, f.deleted_at,
                  sm.updated_at AS thumb_sm, lg.updated_at AS thumb_lg,
                  sm.key_generation AS thumb_sm_generation,
                  lg.key_generation AS thumb_lg_generation
           FROM files f JOIN collections c ON c.id = f.collection_id
           LEFT JOIN file_thumbnails sm ON sm.file_id = f.id AND sm.variant = 'sm'
           LEFT JOIN file_thumbnails lg ON lg.file_id = f.id AND lg.variant = 'lg'
           WHERE c.owner_user_id = $1 AND f.trash_root_id = f.id
           ORDER BY f.deleted_at DESC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(TrashResponse {
        folders: folders
            .into_iter()
            .map(
                |(
                    id,
                    owner,
                    name,
                    owner_key,
                    epoch,
                    revision,
                    statement,
                    statement_hash,
                    color,
                    lands,
                    items,
                    deleted_at,
                )| TrashFolderRow {
                    id: id.to_string(),
                    owner_user_id: owner.to_string(),
                    name_envelope: name,
                    owner_key_envelope: owner_key,
                    key_epoch: epoch,
                    name_revision: revision,
                    epoch_statement: statement,
                    epoch_statement_hash: statement_hash,
                    color,
                    parent_collection_id: lands.map(|id| id.to_string()),
                    items,
                    deleted_at,
                },
            )
            .collect(),
        files: files
            .into_iter()
            .map(|f| TrashFileRow {
                id: f.id.to_string(),
                collection_id: f.collection_id.to_string(),
                metadata_envelope: f.metadata_envelope,
                file_key_envelope: f.file_key_envelope,
                key_epoch: f.key_epoch,
                key_generation: f.key_generation,
                metadata_revision: f.metadata_revision,
                collection_owner_user_id: f.owner_user_id.to_string(),
                collection_owner_key_envelope: f.owner_key_envelope,
                collection_key_epoch: f.collection_key_epoch,
                collection_epoch_statement: f.epoch_statement,
                collection_epoch_statement_hash: f.epoch_statement_hash,
                deleted_at: f.deleted_at,
                // Photos' trash shows the pictures (docs/plans/photos.md).
                thumbnails: crate::models::FileThumbnails {
                    sm: f.thumb_sm,
                    lg: f.thumb_lg,
                    sm_key_generation: f.thumb_sm_generation,
                    lg_key_generation: f.thumb_lg_generation,
                },
            })
            .collect(),
    })
    .into_response())
}

/// A restore that takes a name (docs/plans/drive-unique-names.md): the
/// name's hash where the item lands, and its new name when it changes
/// (a file's metadata, a folder's name, each at its next revision).
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    pub name_hash: Option<String>,
    pub metadata_envelope: Option<String>,
    pub metadata_revision: Option<i64>,
    pub name_envelope: Option<String>,
    pub name_revision: Option<i64>,
}

/// `POST /api/trash/{id}/restore` — puts a trash root back where it was. A file whose
/// folder is still in the trash is a 409 (restore the folder instead); a folder whose
/// original parent is gone or trashed comes back at the top level. Its name must be
/// free where it lands: a taken one is `409 name_taken`, and a folder landing at the
/// top level is `409 nameNeeded` (its hash belonged to the folder it left); the
/// client then restores with a name of its own and its hash, in the same request.
#[utoipa::path(
    post,
    path = "/api/trash/{id}/restore",
    tag = "trash",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Trash-root id (file or folder)")),
    request_body(content = Option<RestoreRequest>, description = "A name to come back under"),
    responses((status = 200, description = "Restored", body = MessageResponse))
)]
pub async fn restore(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<RestoreRequest>>,
) -> AppResult<Response> {
    let req = body.map(|Json(req)| req).unwrap_or_default();
    let given_hash = req
        .name_hash
        .as_deref()
        .map(|hash| crate::drive_names::require_name_hash(Some(hash)))
        .transpose()?;
    let user_id = trusted_uuid(&user.user_id)?;
    let root_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let mut tx = state.pool.begin().await?;

    // File root?
    let file_coll: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT f.collection_id FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.trash_root_id = f.id AND c.owner_user_id = $2"#,
    )
    .bind(root_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(coll_id) = file_coll {
        let parent_live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM collections WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(coll_id)
        .fetch_one(&mut *tx)
        .await?;
        if parent_live == 0 {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "restore the parent folder first",
            ));
        }
        // Its name must be free in its folder: its own, or one the client
        // gives it now (with the new name sealed at the next revision).
        let place = crate::drive_names::Place::Folder(coll_id);
        crate::drive_names::lock_place(&mut tx, place).await?;
        let (stored_hash, key_generation, revision): (String, i32, i64) = sqlx::query_as(
            "SELECT name_hash, key_generation, metadata_revision FROM files WHERE id = $1",
        )
        .bind(root_id)
        .fetch_one(&mut *tx)
        .await?;
        if let Some(envelope) = &req.metadata_envelope {
            let next = revision
                .checked_add(1)
                .filter(|next| req.metadata_revision == Some(*next))
                .ok_or_else(|| AppError::conflict("metadata revision must advance exactly once"))?;
            if given_hash.is_none() {
                return Err(AppError::bad_request("a new name comes with its nameHash"));
            }
            crate::handlers::files::validate_envelope(
                envelope,
                kutup_crypto::drive_envelope::DriveEnvelopeContextV1::file_metadata(
                    &root_id.to_string(),
                    u32::try_from(key_generation)
                        .map_err(|_| AppError::conflict("invalid key generation"))?,
                    u64::try_from(next).map_err(|_| AppError::bad_request("invalid revision"))?,
                )
                .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
            )?;
            sqlx::query(
                "UPDATE files SET metadata_envelope = $2, metadata_revision = $3 WHERE id = $1",
            )
            .bind(root_id)
            .bind(envelope)
            .bind(next)
            .execute(&mut *tx)
            .await?;
        }
        // A new hash is a new name: it comes with that name, sealed.
        if req.metadata_envelope.is_none() && given_hash.as_ref().is_some_and(|h| *h != stored_hash)
        {
            return Err(AppError::bad_request(
                "a new name hash comes with its metadataEnvelope",
            ));
        }
        let name_hash = given_hash.clone().unwrap_or(stored_hash);
        crate::drive_names::ensure_name_free(&mut tx, place, &name_hash, Some(root_id)).await?;
        sqlx::query(
            "UPDATE files SET deleted_at = NULL, trash_root_id = NULL, name_hash = $2 WHERE id = $1",
        )
        .bind(root_id)
        .bind(&name_hash)
        .execute(&mut *tx)
        .await
        .map_err(crate::drive_names::map_unique_violation)?;
        tx.commit().await?;
        return Ok(Json(MessageResponse {
            message: "restored".to_string(),
        })
        .into_response());
    }

    // Folder root?
    let parent: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT parent_collection_id FROM collections WHERE id = $1 AND trash_root_id = $1 AND owner_user_id = $2",
    )
    .bind(root_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(parent) = parent else {
        return Err(AppError::not_found("not found"));
    };

    // Original parent gone or still trashed → come back at the top level.
    let mut lands = parent;
    if let Some(parent_id) = parent {
        let parent_live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM collections WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(parent_id)
        .fetch_one(&mut *tx)
        .await?;
        if parent_live == 0 {
            sqlx::query("UPDATE collections SET parent_collection_id = NULL WHERE id = $1")
                .bind(root_id)
                .execute(&mut *tx)
                .await?;
            lands = None;
        }
    }
    // Its name must be free where it lands. Its own hash holds only where
    // it was (under that place's hash key); landing elsewhere, the client
    // names it there.
    let place = crate::drive_names::Place::of(lands, user_id);
    crate::drive_names::lock_place(&mut tx, place).await?;
    let (stored_hash, epoch, revision): (String, i32, i64) =
        sqlx::query_as("SELECT name_hash, key_epoch, name_revision FROM collections WHERE id = $1")
            .bind(root_id)
            .fetch_one(&mut *tx)
            .await?;
    if let Some(envelope) = &req.name_envelope {
        let next = revision
            .checked_add(1)
            .filter(|next| req.name_revision == Some(*next))
            .ok_or_else(|| AppError::conflict("name revision must advance exactly once"))?;
        if given_hash.is_none() {
            return Err(AppError::bad_request("a new name comes with its nameHash"));
        }
        crate::handlers::collections::validate_drive_envelope(
            envelope,
            kutup_crypto::drive_envelope::DriveEnvelopeContextV1::new(
                kutup_crypto::drive_envelope::DriveEnvelopePurpose::CollectionName,
                u32::try_from(epoch).map_err(|_| AppError::conflict("invalid collection epoch"))?,
                u64::try_from(next).map_err(|_| AppError::bad_request("invalid revision"))?,
                &root_id.to_string(),
                &user_id.to_string(),
            )
            .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
        )?;
        sqlx::query("UPDATE collections SET name_envelope = $2, name_revision = $3 WHERE id = $1")
            .bind(root_id)
            .bind(envelope)
            .bind(next)
            .execute(&mut *tx)
            .await?;
    }
    let name_hash = match given_hash {
        Some(hash) => hash,
        None if lands == parent => stored_hash,
        None => {
            return Err(
                AppError::conflict("the folder comes back at the top level: name it there")
                    .with_details(serde_json::json!({ "code": "nameNeeded" })),
            )
        }
    };
    crate::drive_names::ensure_name_free(&mut tx, place, &name_hash, Some(root_id)).await?;
    sqlx::query("UPDATE collections SET name_hash = $2 WHERE id = $1")
        .bind(root_id)
        .bind(&name_hash)
        .execute(&mut *tx)
        .await
        .map_err(crate::drive_names::map_unique_violation)?;

    sqlx::query(
        "UPDATE collections SET deleted_at = NULL, trash_root_id = NULL WHERE trash_root_id = $1",
    )
    .bind(root_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE files SET deleted_at = NULL, trash_root_id = NULL WHERE trash_root_id = $1",
    )
    .bind(root_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(MessageResponse {
        message: "restored".to_string(),
    })
    .into_response())
}

/// `DELETE /api/trash/{id}` — permanently purges one trash root (DB rows + S3 blobs +
/// quota release). Irreversible.
#[utoipa::path(
    delete,
    path = "/api/trash/{id}",
    tag = "trash",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Trash-root id (file or folder)")),
    responses((status = 204, description = "Permanently purged"))
)]
pub async fn destroy(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let root_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let is_file_root: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.trash_root_id = f.id AND c.owner_user_id = $2"#,
    )
    .bind(root_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    if is_file_root > 0 {
        jobs::purge_file_root(
            &state.pool,
            &state.storage,
            root_id,
            jobs::PurgeGuard::TrashedFile,
        )
        .await
        .map_err(|e| {
            tracing::error!("trash purge file {root_id}: {e:#}");
            AppError::internal("internal error")
        })?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let is_coll_root: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM collections WHERE id = $1 AND trash_root_id = $1 AND owner_user_id = $2",
    )
    .bind(root_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    if is_coll_root == 0 {
        return Err(AppError::not_found("not found"));
    }
    jobs::purge_collection_root(&state.pool, &state.storage, root_id)
        .await
        .map_err(|e| {
            tracing::error!("trash purge collection {root_id}: {e:#}");
            AppError::internal("internal error")
        })?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/trash` — empties the caller's whole trash. Irreversible.
#[utoipa::path(
    delete,
    path = "/api/trash",
    tag = "trash",
    operation_id = "emptyTrash",
    security(("BearerAuth" = [])),
    responses((status = 204, description = "Trash emptied"))
)]
pub async fn empty(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;

    let coll_roots: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM collections WHERE owner_user_id = $1 AND trash_root_id = id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    for root in coll_roots {
        if let Err(e) = jobs::purge_collection_root(&state.pool, &state.storage, root).await {
            tracing::error!("empty trash: purge collection {root}: {e:#}");
        }
    }

    let file_roots: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT f.id FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE c.owner_user_id = $1 AND f.trash_root_id = f.id"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    for root in file_roots {
        if let Err(e) = jobs::purge_file_root(
            &state.pool,
            &state.storage,
            root,
            jobs::PurgeGuard::TrashedFile,
        )
        .await
        {
            tracing::error!("empty trash: purge file {root}: {e:#}");
        }
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}
