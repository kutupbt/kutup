//! Mail folders and labels (docs/plans/mail-filters.md, F1), as Proton's:
//! folders nest three deep and hold mail in one place; labels are tags a
//! message keeps wherever it goes. Names arrive sealed by the browser
//! (kutup-crypto `mail_names`), bound to the account and the id the browser
//! chose, so the server keeps ids, colours, order and the tree, never names.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// Folders nest at most this deep: a top folder and two levels inside it
/// (Proton's `MAX_FOLDER_NESTING_LEVEL = 2` below the top).
pub const MAX_DEPTH: i32 = 3;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailFolder {
    pub id: String,
    pub parent_id: Option<String>,
    /// Sealed in the browser; base64.
    pub name: String,
    pub color: String,
    pub position: i32,
    pub expanded: bool,
    pub notify: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailLabel {
    pub id: String,
    /// Sealed in the browser; base64.
    pub name: String,
    pub color: String,
    pub position: i32,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailPlaces {
    pub folders: Vec<MailFolder>,
    pub labels: Vec<MailLabel>,
}

fn check_sealed(name: &str) -> AppResult<()> {
    let bytes = STANDARD
        .decode(name)
        .map_err(|_| AppError::bad_request("name is not base64"))?;
    kutup_crypto::mail_names::inspect_name(&bytes)
        .map_err(|_| AppError::bad_request("name is not a sealed mail name"))
}

fn check_color(color: &str) -> AppResult<()> {
    let ok = color.len() == 7
        && color.starts_with('#')
        && color[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(AppError::bad_request("color is #rrggbb, lowercase"))
    }
}

fn parse_id(id: &str) -> AppResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| AppError::bad_request("not an id"))
}

/// id, parent, sealed name, colour, position, expanded, notify.
type FolderRow = (Uuid, Option<Uuid>, String, String, i32, bool, bool);

/// `GET /api/mail/places` — the account's folders and labels.
#[utoipa::path(
    get,
    path = "/api/mail/places",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Folders and labels", body = MailPlaces))
)]
pub async fn places(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<MailPlaces>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let folders: Vec<FolderRow> = sqlx::query_as(
        "SELECT id, parent_id, name_sealed, color, position, expanded, notify
           FROM mail_folders WHERE user_id = $1 ORDER BY position, created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let labels: Vec<(Uuid, String, String, i32)> = sqlx::query_as(
        "SELECT id, name_sealed, color, position FROM mail_labels
          WHERE user_id = $1 ORDER BY position, created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(MailPlaces {
        folders: folders
            .into_iter()
            .map(
                |(id, parent, name, color, position, expanded, notify)| MailFolder {
                    id: id.to_string(),
                    parent_id: parent.map(|p| p.to_string()),
                    name,
                    color,
                    position,
                    expanded,
                    notify,
                },
            )
            .collect(),
        labels: labels
            .into_iter()
            .map(|(id, name, color, position)| MailLabel {
                id: id.to_string(),
                name,
                color,
                position,
            })
            .collect(),
    }))
}

/// How deep `folder` sits (a top folder is 1), and the depth of the deepest
/// folder under it, counted from it (1 when it has none).
async fn depth_of(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    folder: Uuid,
) -> AppResult<(i32, i32)> {
    let depth: Option<i32> = sqlx::query_scalar(
        "WITH RECURSIVE up(id, parent_id, depth) AS (
             SELECT id, parent_id, 1 FROM mail_folders WHERE user_id = $1 AND id = $2
           UNION ALL
             SELECT f.id, f.parent_id, up.depth + 1 FROM mail_folders f JOIN up ON f.id = up.parent_id
              WHERE up.depth < 10)
         SELECT MAX(depth) FROM up",
    )
    .bind(user_id)
    .bind(folder)
    .fetch_one(&mut **tx)
    .await?;
    let below: Option<i32> = sqlx::query_scalar(
        "WITH RECURSIVE down(id, depth) AS (
             SELECT id, 1 FROM mail_folders WHERE user_id = $1 AND id = $2
           UNION ALL
             SELECT f.id, down.depth + 1 FROM mail_folders f JOIN down ON f.parent_id = down.id
              WHERE down.depth < 10)
         SELECT MAX(depth) FROM down",
    )
    .bind(user_id)
    .bind(folder)
    .fetch_one(&mut **tx)
    .await?;
    match (depth, below) {
        (Some(depth), Some(below)) => Ok((depth, below)),
        _ => Err(AppError::not_found("no such folder")),
    }
}

/// The folder and every folder under it.
async fn subtree(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    folder: Uuid,
) -> AppResult<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        "WITH RECURSIVE down(id) AS (
             SELECT id FROM mail_folders WHERE user_id = $1 AND id = $2
           UNION
             SELECT f.id FROM mail_folders f JOIN down ON f.parent_id = down.id)
         SELECT id FROM down",
    )
    .bind(user_id)
    .bind(folder)
    .fetch_all(&mut **tx)
    .await?)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMailFolder {
    /// A new UUID, chosen by the browser: the sealed name is bound to it.
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub color: String,
}

/// `POST /api/mail/folders` — a new folder, at the top or inside another.
#[utoipa::path(
    post,
    path = "/api/mail/folders",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = CreateMailFolder,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "Bad name, colour or parent, too deep"),
        (status = 409, description = "The id is taken, or the account has its most folders"),
    )
)]
pub async fn create_folder(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateMailFolder>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = parse_id(&request.id)?;
    let parent = request.parent_id.as_deref().map(parse_id).transpose()?;
    check_sealed(&request.name)?;
    check_color(&request.color)?;
    let mut tx = state.pool.begin().await?;
    // One writer per account at a time, so the count and the tree hold.
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mail_folders WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= state.config.mail_folders_per_account {
        return Err(AppError::conflict("this account has its most folders"));
    }
    if let Some(parent) = parent {
        let (depth, _) = depth_of(&mut tx, user_id, parent)
            .await
            .map_err(|_| AppError::bad_request("no such parent folder"))?;
        if depth >= MAX_DEPTH {
            return Err(AppError::bad_request("folders nest three deep at most"));
        }
    }
    let position: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position) + 1, 0) FROM mail_folders
          WHERE user_id = $1 AND parent_id IS NOT DISTINCT FROM $2",
    )
    .bind(user_id)
    .bind(parent)
    .fetch_one(&mut *tx)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO mail_folders (id, user_id, parent_id, name_sealed, color, position)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(user_id)
    .bind(parent)
    .bind(&request.name)
    .bind(&request.color)
    .bind(position)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::conflict("that id is taken"));
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

/// A field that can be set, cleared (`null`) or left out.
fn double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailFolder {
    pub name: Option<String>,
    pub color: Option<String>,
    /// Another folder to move into, or `null` for the top.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub parent_id: Option<Option<String>>,
    pub position: Option<i32>,
    pub expanded: Option<bool>,
    pub notify: Option<bool>,
}

/// `PATCH /api/mail/folders/{id}` — rename (a new sealed name), recolour,
/// move into another folder or to the top, reorder, fold, notify.
#[utoipa::path(
    patch,
    path = "/api/mail/folders/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Folder id")),
    request_body = UpdateMailFolder,
    responses(
        (status = 204, description = "Saved"),
        (status = 400, description = "Bad name or colour, a cycle, too deep"),
        (status = 404, description = "No such folder"),
    )
)]
pub async fn update_folder(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateMailFolder>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such folder"))?;
    if let Some(name) = &request.name {
        check_sealed(name)?;
    }
    if let Some(color) = &request.color {
        check_color(color)?;
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let (_, below) = depth_of(&mut tx, user_id, id).await?;
    let parent = match &request.parent_id {
        None => None,
        Some(None) => Some(None),
        Some(Some(parent)) => {
            let parent = parse_id(parent)?;
            if subtree(&mut tx, user_id, id).await?.contains(&parent) {
                return Err(AppError::bad_request("a folder cannot go inside itself"));
            }
            let (depth, _) = depth_of(&mut tx, user_id, parent)
                .await
                .map_err(|_| AppError::bad_request("no such parent folder"))?;
            if depth + below > MAX_DEPTH {
                return Err(AppError::bad_request("folders nest three deep at most"));
            }
            Some(Some(parent))
        }
    };
    sqlx::query(
        "UPDATE mail_folders SET
             name_sealed = COALESCE($3, name_sealed),
             color = COALESCE($4, color),
             parent_id = CASE WHEN $5 THEN $6 ELSE parent_id END,
             position = COALESCE($7, position),
             expanded = COALESCE($8, expanded),
             notify = COALESCE($9, notify)
          WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .bind(request.name.as_deref())
    .bind(request.color.as_deref())
    .bind(parent.is_some())
    .bind(parent.flatten())
    .bind(request.position)
    .bind(request.expanded)
    .bind(request.notify)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeletedMailFolder {
    /// Folders removed: this one and those inside it.
    pub folders: u64,
    /// Messages moved to Archive.
    pub moved: u64,
}

/// `DELETE /api/mail/folders/{id}` — removes the folder and the folders in
/// it. Their mail is never deleted: it moves to Archive (Proton: "emails
/// stored in the folder will not be deleted and can be found in All Mail").
#[utoipa::path(
    delete,
    path = "/api/mail/folders/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Folder id")),
    responses(
        (status = 200, description = "Removed", body = DeletedMailFolder),
        (status = 404, description = "No such folder"),
    )
)]
pub async fn delete_folder(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<DeletedMailFolder>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such folder"))?;
    let mut tx = state.pool.begin().await?;
    let folders = subtree(&mut tx, user_id, id).await?;
    if folders.is_empty() {
        return Err(AppError::not_found("no such folder"));
    }
    let moved = sqlx::query(
        "UPDATE mail_messages SET folder = 'archive', custom_folder = NULL
          WHERE user_id = $1 AND custom_folder = ANY($2)",
    )
    .bind(user_id)
    .bind(&folders)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // Filters that filed mail there keep their other actions; one left
    // with none is switched off (docs/plans/mail-filters.md).
    let targets: Vec<String> = folders.iter().map(|f| format!("custom:{f}")).collect();
    sqlx::query(
        "UPDATE mail_filters SET actions = actions - 'folder',
             enabled = enabled AND (actions - 'folder') <> '{}'::jsonb
          WHERE user_id = $1 AND actions->>'folder' = ANY($2)",
    )
    .bind(user_id)
    .bind(&targets)
    .execute(&mut *tx)
    .await?;
    let removed = sqlx::query("DELETE FROM mail_folders WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(Json(DeletedMailFolder {
        folders: if removed == 0 {
            0
        } else {
            folders.len() as u64
        },
        moved,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMailLabel {
    /// A new UUID, chosen by the browser: the sealed name is bound to it.
    pub id: String,
    pub name: String,
    pub color: String,
}

/// `POST /api/mail/labels` — a new label.
#[utoipa::path(
    post,
    path = "/api/mail/labels",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = CreateMailLabel,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "Bad name or colour"),
        (status = 409, description = "The id is taken, or the account has its most labels"),
    )
)]
pub async fn create_label(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateMailLabel>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = parse_id(&request.id)?;
    check_sealed(&request.name)?;
    check_color(&request.color)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mail_labels WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= state.config.mail_labels_per_account {
        return Err(AppError::conflict("this account has its most labels"));
    }
    let inserted = sqlx::query(
        "INSERT INTO mail_labels (id, user_id, name_sealed, color, position)
         SELECT $1, $2, $3, $4, COALESCE(MAX(position) + 1, 0) FROM mail_labels WHERE user_id = $2
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.color)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::conflict("that id is taken"));
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailLabel {
    pub name: Option<String>,
    pub color: Option<String>,
    pub position: Option<i32>,
}

/// `PATCH /api/mail/labels/{id}` — rename, recolour, reorder.
#[utoipa::path(
    patch,
    path = "/api/mail/labels/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Label id")),
    request_body = UpdateMailLabel,
    responses((status = 204, description = "Saved"), (status = 404, description = "No such label"))
)]
pub async fn update_label(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateMailLabel>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such label"))?;
    if let Some(name) = &request.name {
        check_sealed(name)?;
    }
    if let Some(color) = &request.color {
        check_color(color)?;
    }
    let updated = sqlx::query(
        "UPDATE mail_labels SET name_sealed = COALESCE($3, name_sealed),
             color = COALESCE($4, color), position = COALESCE($5, position)
          WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .bind(request.name.as_deref())
    .bind(request.color.as_deref())
    .bind(request.position)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::not_found("no such label"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/mail/labels/{id}` — removes the label from every message;
/// the mail stays where it is.
#[utoipa::path(
    delete,
    path = "/api/mail/labels/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Label id")),
    responses((status = 204, description = "Removed"), (status = 404, description = "No such label"))
)]
pub async fn delete_label(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such label"))?;
    let mut tx = state.pool.begin().await?;
    let removed = sqlx::query("DELETE FROM mail_labels WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::not_found("no such label"));
    }
    // Filters that added it keep their other actions; one left with none is switched off.
    sqlx::query(
        "UPDATE mail_filters SET actions = CASE
                 WHEN jsonb_array_length(actions->'labels') = 1 THEN actions - 'labels'
                 ELSE jsonb_set(actions, '{labels}', (actions->'labels') - $2) END
          WHERE user_id = $1 AND actions->'labels' ? $2",
    )
    .bind(user_id)
    .bind(id.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE mail_filters SET enabled = false WHERE user_id = $1 AND actions = '{}'::jsonb",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_and_names_are_checked() {
        assert!(check_color("#1a2b3c").is_ok());
        for bad in ["#1A2B3C", "1a2b3c", "#12345", "#zzzzzz", "#1a2b3c0"] {
            assert!(check_color(bad).is_err(), "{bad}");
        }
        assert!(check_sealed("not base64!").is_err());
        assert!(check_sealed(&STANDARD.encode(b"KUTMN1\0\0short")).is_err());
        let key = kutup_crypto::mail_names::derive_names_key(&[1; 32]).unwrap();
        let sealed = kutup_crypto::mail_names::seal_name(
            &key,
            "alice@kutup.dev",
            kutup_crypto::mail_names::MailNameKind::Folder,
            &[2; 16],
            "Faturalar",
        )
        .unwrap();
        assert!(check_sealed(&STANDARD.encode(sealed)).is_ok());
    }
}
