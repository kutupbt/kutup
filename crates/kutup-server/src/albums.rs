//! Albums (docs/plans/photos.md): collections of kind `album` that hold
//! references to photos, never files. Each item is a file id and the file's
//! key sealed under the album key (Drive envelope purpose 12), so a photo in
//! five albums is one file, counted once. This slice: an album's owner only.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::collections::{create_owned_collection, validate_drive_envelope};
use crate::handlers::files::file_rows;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::models::{CreateCollectionRequest, FileRow};
use crate::AppState;

/// At most this many photos go in with one request.
const MAX_ADD: usize = 500;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlbumRow {
    pub id: String,
    pub owner_user_id: String,
    pub name_envelope: String,
    pub owner_key_envelope: String,
    pub key_epoch: i32,
    pub name_revision: i64,
    pub epoch_statement: String,
    pub epoch_statement_hash: String,
    pub item_count: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When a photo was last added (or the album made).
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// `GET /api/albums` — your albums.
#[utoipa::path(
    get,
    path = "/api/albums",
    tag = "photos",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Your albums", body = [AlbumRow]))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<AlbumRow>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        owner_user_id: Uuid,
        name_envelope: String,
        owner_key_envelope: String,
        key_epoch: i32,
        name_revision: i64,
        epoch_statement: String,
        epoch_statement_hash: String,
        item_count: i64,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    }
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT c.id, c.owner_user_id, c.name_envelope, c.owner_key_envelope, c.key_epoch,
                  c.name_revision, c.epoch_statement, c.epoch_statement_hash,
                  (SELECT COUNT(*) FROM album_items i JOIN files f ON f.id = i.file_id
                    WHERE i.album_id = c.id AND f.deleted_at IS NULL) AS item_count,
                  c.created_at,
                  GREATEST(c.updated_at, COALESCE((SELECT MAX(i.added_at) FROM album_items i
                                                   WHERE i.album_id = c.id), c.updated_at)) AS updated_at
           FROM collections c
           WHERE c.owner_user_id = $1 AND c.kind = 'album' AND c.deleted_at IS NULL
           ORDER BY c.created_at ASC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| AlbumRow {
                id: r.id.to_string(),
                owner_user_id: r.owner_user_id.to_string(),
                name_envelope: r.name_envelope,
                owner_key_envelope: r.owner_key_envelope,
                key_epoch: r.key_epoch,
                name_revision: r.name_revision,
                epoch_statement: r.epoch_statement,
                epoch_statement_hash: r.epoch_statement_hash,
                item_count: r.item_count,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect(),
    ))
}

/// `POST /api/albums` — a new album: the body is a new collection's, without
/// a parent (albums are not inside folders).
#[utoipa::path(
    post,
    path = "/api/albums",
    tag = "photos",
    security(("BearerAuth" = [])),
    request_body = CreateCollectionRequest,
    responses((status = 201, description = "Album created"))
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateCollectionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    create_owned_collection(&state, user_id, request, "album").await
}

/// The album, if `user_id` owns it: its key epoch.
async fn owned_album(state: &AppState, user_id: Uuid, album_id: &str) -> AppResult<(Uuid, i32)> {
    let id = Uuid::parse_str(album_id).map_err(|_| AppError::not_found("album not found"))?;
    let epoch: Option<i32> = sqlx::query_scalar(
        "SELECT key_epoch FROM collections
         WHERE id = $1 AND owner_user_id = $2 AND kind = 'album' AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let epoch = epoch.ok_or_else(|| AppError::not_found("album not found"))?;
    Ok((id, epoch))
}

/// `DELETE /api/albums/{id}` — the album goes; its photos stay where they are.
#[utoipa::path(
    delete,
    path = "/api/albums/{id}",
    tag = "photos",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Album id")),
    responses((status = 204, description = "Deleted"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(album): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (id, _) = owned_album(&state, user_id, &album).await?;
    sqlx::query("DELETE FROM collections WHERE id = $1 AND kind = 'album'")
        .bind(id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlbumItem {
    /// The file as a folder listing gives it (its own key sealed under its
    /// folder's; album viewers use `fileKeyEnvelope` instead).
    pub file: FileRow,
    /// The file key of `keyGeneration`, sealed under the album key of `albumEpoch`.
    pub file_key_envelope: String,
    pub key_generation: i32,
    pub album_epoch: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
}

/// `GET /api/albums/{id}/items` — the album's photos (those in the trash are left out).
#[utoipa::path(
    get,
    path = "/api/albums/{id}/items",
    tag = "photos",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Album id")),
    responses((status = 200, description = "The album's photos", body = [AlbumItem]))
)]
pub async fn items(
    State(state): State<AppState>,
    user: AuthUser,
    Path(album): Path<String>,
) -> AppResult<Json<Vec<AlbumItem>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (id, _) = owned_album(&state, user_id, &album).await?;
    let files = file_rows(
        &state.pool,
        "f.id IN (SELECT file_id FROM album_items WHERE album_id = $1)",
        id,
        user_id,
    )
    .await?;
    #[derive(sqlx::FromRow)]
    struct Item {
        file_id: Uuid,
        file_key_envelope: String,
        key_generation: i32,
        album_epoch: i32,
        added_by: Option<Uuid>,
        added_at: OffsetDateTime,
    }
    let rows: Vec<Item> = sqlx::query_as(
        "SELECT file_id, file_key_envelope, key_generation, album_epoch, added_by, added_at
         FROM album_items WHERE album_id = $1",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let mut by_file: std::collections::HashMap<String, Item> = rows
        .into_iter()
        .map(|r| (r.file_id.to_string(), r))
        .collect();
    Ok(Json(
        files
            .into_iter()
            .filter_map(|file| {
                let item = by_file.remove(&file.id)?;
                Some(AlbumItem {
                    file,
                    file_key_envelope: item.file_key_envelope,
                    key_generation: item.key_generation,
                    album_epoch: item.album_epoch,
                    added_by: item.added_by.map(|u| u.to_string()),
                    added_at: item.added_at,
                })
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlbumItemInput {
    pub file_id: String,
    /// The file key of `keyGeneration` (its current one), sealed under the album key.
    pub file_key_envelope: String,
    pub key_generation: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddAlbumItems {
    pub items: Vec<AlbumItemInput>,
}

/// `POST /api/albums/{id}/items` — put photos in the album (or re-seal ones
/// already in it). Each must be one of your own files, not in the trash,
/// with its key sealed at its current generation and the album's current
/// epoch.
#[utoipa::path(
    post,
    path = "/api/albums/{id}/items",
    tag = "photos",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Album id")),
    request_body = AddAlbumItems,
    responses(
        (status = 204, description = "Added"),
        (status = 400, description = "Not your file, or a key not sealed as the album and file are now"),
        (status = 409, description = "A file's key or the album's changed: seal again")
    )
)]
pub async fn add_items(
    State(state): State<AppState>,
    user: AuthUser,
    Path(album): Path<String>,
    Json(request): Json<AddAlbumItems>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    if request.items.is_empty() || request.items.len() > MAX_ADD {
        return Err(AppError::bad_request(
            "add between 1 and 500 photos at a time",
        ));
    }
    let (album_id, epoch) = owned_album(&state, user_id, &album).await?;
    let album_string = album_id.to_string();
    let mut tx = state.pool.begin().await?;
    for item in &request.items {
        let file_id =
            Uuid::parse_str(&item.file_id).map_err(|_| AppError::bad_request("invalid file id"))?;
        let generation: Option<i32> = sqlx::query_scalar(
            "SELECT f.key_generation FROM files f JOIN collections c ON c.id = f.collection_id
             WHERE f.id = $1 AND c.owner_user_id = $2 AND f.deleted_at IS NULL AND c.deleted_at IS NULL
             FOR SHARE OF f",
        )
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let generation = generation
            .ok_or_else(|| AppError::bad_request("only your own photos go in your albums"))?;
        if generation != item.key_generation {
            return Err(AppError::conflict("the photo's key changed: seal it again"));
        }
        let generation_u32 = u32::try_from(generation)
            .map_err(|_| AppError::bad_request("invalid key generation"))?;
        let epoch_u32 = u32::try_from(epoch).map_err(|_| AppError::internal("album epoch"))?;
        validate_drive_envelope(
            &item.file_key_envelope,
            DriveEnvelopeContextV1::album_file_key(
                &file_id.to_string(),
                &album_string,
                epoch_u32,
                generation_u32,
            )
            .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
        )?;
        sqlx::query(
            "INSERT INTO album_items (album_id, file_id, file_key_envelope, key_generation, album_epoch, added_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (album_id, file_id) DO UPDATE SET
                 file_key_envelope = EXCLUDED.file_key_envelope,
                 key_generation = EXCLUDED.key_generation,
                 album_epoch = EXCLUDED.album_epoch",
        )
        .bind(album_id)
        .bind(file_id)
        .bind(&item.file_key_envelope)
        .bind(generation)
        .bind(epoch)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE collections SET updated_at = now() WHERE id = $1")
        .bind(album_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveAlbumItems {
    pub file_ids: Vec<String>,
}

/// `POST /api/albums/{id}/items/remove` — take photos out of the album (the
/// photos stay where they are).
#[utoipa::path(
    post,
    path = "/api/albums/{id}/items/remove",
    tag = "photos",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Album id")),
    request_body = RemoveAlbumItems,
    responses((status = 204, description = "Removed"))
)]
pub async fn remove_items(
    State(state): State<AppState>,
    user: AuthUser,
    Path(album): Path<String>,
    Json(request): Json<RemoveAlbumItems>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (album_id, _) = owned_album(&state, user_id, &album).await?;
    let ids: Vec<Uuid> = request
        .file_ids
        .iter()
        .map(|id| Uuid::parse_str(id))
        .collect::<Result<_, _>>()
        .map_err(|_| AppError::bad_request("invalid file id"))?;
    sqlx::query("DELETE FROM album_items WHERE album_id = $1 AND file_id = ANY($2)")
        .bind(album_id)
        .bind(&ids)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
