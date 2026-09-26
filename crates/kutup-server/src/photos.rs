//! The Photos app's library (docs/plans/photos.md): which Drive folders it
//! shows, and where its uploads go. Photos are Drive files; the server keeps
//! only folder ids here, never anything about the photos.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_collection, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

/// More folders than anyone arranges photos in; keeps listing bounded.
const MAX_LIBRARY_FOLDERS: usize = 200;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhotosPreferences {
    /// One of your own folders; null until the app makes "Photos" in My files.
    pub upload_folder_id: Option<Uuid>,
    /// Other folders shown in the library, each with its subfolders: your
    /// own, or shared with you. Ones you can no longer open are left out.
    pub library_folder_ids: Vec<Uuid>,
}

/// `GET /api/photos/preferences` — your library's folders.
#[utoipa::path(
    get,
    path = "/api/photos/preferences",
    tag = "photos",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Your photo library's folders", body = PhotosPreferences))
)]
pub async fn get_preferences(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<PhotosPreferences>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(preferences_of(&state, user_id).await?))
}

async fn preferences_of(state: &AppState, user_id: Uuid) -> AppResult<PhotosPreferences> {
    let upload: Option<Uuid> = sqlx::query_scalar(
        "SELECT p.upload_folder_id FROM photos_preferences p
         JOIN collections c ON c.id = p.upload_folder_id
         WHERE p.user_id = $1 AND c.owner_user_id = $1 AND c.deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .flatten();
    let listed: Vec<Uuid> = sqlx::query_scalar(
        "SELECT f.collection_id FROM photos_library_folders f
         JOIN collections c ON c.id = f.collection_id
         WHERE f.user_id = $1 AND c.deleted_at IS NULL
         ORDER BY f.added_at, f.collection_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut library_folder_ids = Vec::with_capacity(listed.len());
    for id in listed {
        // A folder unshared since it was added drops out.
        if Some(id) != upload && can_access_collection(&state.pool, user_id, id).await {
            library_folder_ids.push(id);
        }
    }
    Ok(PhotosPreferences {
        upload_folder_id: upload,
        library_folder_ids,
    })
}

/// `PUT /api/photos/preferences` — choose the upload folder (one of your own)
/// and the other folders the library shows.
#[utoipa::path(
    put,
    path = "/api/photos/preferences",
    tag = "photos",
    security(("BearerAuth" = [])),
    request_body = PhotosPreferences,
    responses(
        (status = 200, description = "Saved", body = PhotosPreferences),
        (status = 400, description = "A folder that is not yours to upload to, or one you cannot open")
    )
)]
pub async fn put_preferences(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PhotosPreferences>,
) -> AppResult<Json<PhotosPreferences>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if request.library_folder_ids.len() > MAX_LIBRARY_FOLDERS {
        return Err(AppError::bad_request("too many folders in the library"));
    }
    if let Some(folder) = request.upload_folder_id {
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM collections
                           WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL)",
        )
        .bind(folder)
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
        if !owned {
            return Err(AppError::bad_request(
                "photos are uploaded into one of your own folders",
            ));
        }
    }
    let mut folders: Vec<Uuid> = Vec::with_capacity(request.library_folder_ids.len());
    for &id in &request.library_folder_ids {
        if folders.contains(&id) || Some(id) == request.upload_folder_id {
            continue;
        }
        if !can_access_collection(&state.pool, user_id, id).await {
            return Err(AppError::bad_request("a library folder you cannot open"));
        }
        folders.push(id);
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO photos_preferences (user_id, upload_folder_id) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET
             upload_folder_id = EXCLUDED.upload_folder_id, updated_at = now()",
    )
    .bind(user_id)
    .bind(request.upload_folder_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM photos_library_folders WHERE user_id = $1 AND NOT (collection_id = ANY($2))",
    )
    .bind(user_id)
    .bind(&folders)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO photos_library_folders (user_id, collection_id)
         SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(&folders)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(preferences_of(&state, user_id).await?))
}
