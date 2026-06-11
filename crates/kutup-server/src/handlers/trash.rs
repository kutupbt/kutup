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
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        OffsetDateTime,
    );
    let folders: Vec<FolderTuple> = sqlx::query_as(
        r#"SELECT c.id, c.encrypted_name, c.name_nonce, c.encrypted_key, c.encrypted_key_nonce,
                  c.color,
                  (SELECT COUNT(*) FROM files f WHERE f.trash_root_id = c.id),
                  c.deleted_at
           FROM collections c
           WHERE c.owner_user_id = $1 AND c.trash_root_id = c.id
           ORDER BY c.deleted_at DESC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    type FileTuple = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        String,
        String,
        OffsetDateTime,
    );
    let files: Vec<FileTuple> = sqlx::query_as(
        r#"SELECT f.id, f.collection_id, f.encrypted_metadata, f.metadata_nonce,
                  f.encrypted_file_key, f.file_key_nonce,
                  c.encrypted_key, c.encrypted_key_nonce, f.deleted_at
           FROM files f JOIN collections c ON c.id = f.collection_id
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
                |(id, en, nn, ek, ekn, color, items, deleted_at)| TrashFolderRow {
                    id: id.to_string(),
                    encrypted_name: en,
                    name_nonce: nn,
                    encrypted_key: ek,
                    encrypted_key_nonce: ekn,
                    color,
                    items,
                    deleted_at,
                },
            )
            .collect(),
        files: files
            .into_iter()
            .map(
                |(id, cid, em, mn, efk, fkn, cek, cekn, deleted_at)| TrashFileRow {
                    id: id.to_string(),
                    collection_id: cid.to_string(),
                    encrypted_metadata: em,
                    metadata_nonce: mn,
                    encrypted_file_key: efk,
                    file_key_nonce: fkn,
                    collection_encrypted_key: cek,
                    collection_encrypted_key_nonce: cekn,
                    deleted_at,
                },
            )
            .collect(),
    })
    .into_response())
}

/// `POST /api/trash/{id}/restore` — puts a trash root back where it was. A file whose
/// folder is still in the trash is a 409 (restore the folder instead); a folder whose
/// original parent is gone or trashed comes back at the top level.
#[utoipa::path(
    post,
    path = "/api/trash/{id}/restore",
    tag = "trash",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Trash-root id (file or folder)")),
    responses((status = 200, description = "Restored", body = MessageResponse))
)]
pub async fn restore(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
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
        sqlx::query("UPDATE files SET deleted_at = NULL, trash_root_id = NULL WHERE id = $1")
            .bind(root_id)
            .execute(&mut *tx)
            .await?;
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
        }
    }

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
        jobs::purge_file_root(&state.pool, &state.storage, root_id)
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
        if let Err(e) = jobs::purge_file_root(&state.pool, &state.storage, root).await {
            tracing::error!("empty trash: purge file {root}: {e:#}");
        }
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}
