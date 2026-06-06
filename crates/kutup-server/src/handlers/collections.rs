//! Collection handlers — mirrors `backend/handlers/collections.go`.
//!
//! CRUD over collections plus local (same-server) sharing. The federated-share and
//! remote-pubkey endpoints (`/collections/{id}/share-federated`, `/collections/fed-pubkey`)
//! land with the federation slice (slice 6), alongside the SSRF guard + outbound client.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::models::{
    CollectionRow, CreateCollectionRequest, CreateCollectionResult, MessageResponse,
    ShareCollectionRequest, UpdateCollectionRequest, UpdateColorRequest,
};
use crate::AppState;

/// Parses a collection-id path param; an invalid UUID is a 404 (Go's scan-fails → 404).
fn coll_id_or_404(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| AppError::not_found("not found"))
}

/// `GET /api/collections` — mirrors `ListCollections`. Owned collections, then those
/// shared with the user (with the recipient-specific key + permissions + computed usage).
pub async fn list_collections(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;

    type OwnRow = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        Option<Uuid>,
        Option<String>,
    );
    let own: Vec<OwnRow> = sqlx::query_as(
        r#"SELECT id, owner_user_id, encrypted_name, name_nonce,
                  encrypted_key, encrypted_key_nonce, parent_collection_id, color
           FROM collections WHERE owner_user_id = $1
           ORDER BY created_at ASC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    let mut out: Vec<CollectionRow> = own
        .into_iter()
        .map(
            |(id, owner, en, nn, ek, ekn, parent, color)| CollectionRow {
                id: id.to_string(),
                owner_user_id: owner.to_string(),
                encrypted_name: en,
                name_nonce: nn,
                encrypted_key: ek,
                encrypted_key_nonce: ekn,
                parent_collection_id: parent.map(|p| p.to_string()),
                color,
                can_upload: None,
                can_delete: None,
                upload_quota_bytes: None,
                upload_used_bytes: None,
                is_shared: false,
            },
        )
        .collect();

    type SharedRow = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        Option<Uuid>,
        Option<String>,
        String,
        bool,
        bool,
        Option<i64>,
    );
    let shared: Vec<SharedRow> = sqlx::query_as(
        r#"SELECT c.id, c.owner_user_id, c.encrypted_name, c.name_nonce,
                  c.encrypted_key, c.encrypted_key_nonce, c.parent_collection_id, c.color,
                  cs.encrypted_collection_key, cs.can_upload, cs.can_delete, cs.upload_quota_bytes
           FROM collections c
           JOIN collection_shares cs ON cs.collection_id = c.id
           WHERE cs.recipient_user_id = $1
           ORDER BY c.created_at ASC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    for (id, owner, en, nn, _ek, ekn, parent, color, shared_key, can_upload, can_delete, quota) in
        shared
    {
        // Compute this user's usage in the shared collection when an upload quota applies.
        let upload_used_bytes = if can_upload && quota.is_some() {
            let used: Option<i64> = sqlx::query_scalar(
                "SELECT COALESCE(SUM(encrypted_size_bytes), 0) FROM files WHERE collection_id = $1 AND uploader_user_id = $2",
            )
            .bind(id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
            Some(used.unwrap_or(0))
        } else {
            None
        };

        out.push(CollectionRow {
            id: id.to_string(),
            owner_user_id: owner.to_string(),
            encrypted_name: en,
            name_nonce: nn,
            encrypted_key: shared_key, // recipient-specific key overrides the owner's
            encrypted_key_nonce: ekn,
            parent_collection_id: parent.map(|p| p.to_string()),
            color,
            can_upload: Some(can_upload),
            can_delete: Some(can_delete),
            upload_quota_bytes: quota,
            upload_used_bytes,
            is_shared: true,
        });
    }

    Ok(Json(out).into_response())
}

/// `POST /api/collections` — mirrors `CreateCollection`.
pub async fn create_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateCollectionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let parent = req
        .parent_collection_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| AppError::bad_request("invalid request"))?;

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO collections (owner_user_id, encrypted_name, name_nonce,
                                    encrypted_key, encrypted_key_nonce, parent_collection_id)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING id"#,
    )
    .bind(user_id)
    .bind(&req.encrypted_name)
    .bind(&req.name_nonce)
    .bind(&req.encrypted_key)
    .bind(&req.encrypted_key_nonce)
    .bind(parent)
    .fetch_one(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateCollectionResult { id: id.to_string() }),
    )
        .into_response())
}

/// `GET /api/collections/{id}` — mirrors `GetCollection`.
pub async fn get_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = coll_id_or_404(&id)?;

    type Row = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        Option<Uuid>,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT id, owner_user_id, encrypted_name, name_nonce,
                  encrypted_key, encrypted_key_nonce, parent_collection_id, color
           FROM collections WHERE id = $1 AND owner_user_id = $2"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((cid, owner, en, nn, ek, ekn, parent, color)) = row else {
        return Err(AppError::not_found("not found"));
    };
    Ok(Json(CollectionRow {
        id: cid.to_string(),
        owner_user_id: owner.to_string(),
        encrypted_name: en,
        name_nonce: nn,
        encrypted_key: ek,
        encrypted_key_nonce: ekn,
        parent_collection_id: parent.map(|p| p.to_string()),
        color,
        can_upload: None,
        can_delete: None,
        upload_quota_bytes: None,
        upload_used_bytes: None,
        is_shared: false,
    })
    .into_response())
}

/// `PUT /api/collections/{id}` — mirrors `UpdateCollection` (rename).
pub async fn update_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateCollectionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = coll_id_or_404(&id)?;

    let res = sqlx::query(
        r#"UPDATE collections SET encrypted_name = $1, name_nonce = $2, updated_at = NOW()
           WHERE id = $3 AND owner_user_id = $4"#,
    )
    .bind(&req.encrypted_name)
    .bind(&req.name_nonce)
    .bind(coll_id)
    .bind(user_id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => Ok(Json(MessageResponse {
            message: "updated".to_string(),
        })
        .into_response()),
        _ => Err(AppError::not_found("not found")),
    }
}

/// `PATCH /api/collections/{id}/color` — mirrors `UpdateCollectionColor`.
pub async fn update_collection_color(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateColorRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = coll_id_or_404(&id)?;

    let res = sqlx::query(
        "UPDATE collections SET color = $1, updated_at = NOW() WHERE id = $2 AND owner_user_id = $3",
    )
    .bind(req.color)
    .bind(coll_id)
    .bind(user_id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => Ok(StatusCode::NO_CONTENT.into_response()),
        _ => Err(AppError::not_found("not found")),
    }
}

/// `DELETE /api/collections/{id}` — mirrors `DeleteCollection`.
pub async fn delete_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = coll_id_or_404(&id)?;

    let res = sqlx::query("DELETE FROM collections WHERE id = $1 AND owner_user_id = $2")
        .bind(coll_id)
        .bind(user_id)
        .execute(&state.pool)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => Ok(StatusCode::NO_CONTENT.into_response()),
        _ => Err(AppError::not_found("not found")),
    }
}

/// `POST /api/collections/{id}/share` — mirrors `ShareCollection` (local share/upsert).
pub async fn share_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ShareCollectionRequest>,
) -> AppResult<Response> {
    let sharer_id = trusted_uuid(&user.user_id)?;
    // Invalid collection id ⇒ ownership check fails ⇒ 403 (matches Go).
    let coll_id = Uuid::parse_str(&id).map_err(|_| AppError::forbidden("forbidden"))?;
    let recipient_id = Uuid::parse_str(&req.recipient_user_id)
        .map_err(|_| AppError::bad_request("invalid request"))?;

    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_user_id FROM collections WHERE id = $1")
            .bind(coll_id)
            .fetch_optional(&state.pool)
            .await?;
    if owner != Some(sharer_id) {
        return Err(AppError::forbidden("forbidden"));
    }

    sqlx::query(
        r#"INSERT INTO collection_shares (collection_id, sharer_user_id, recipient_user_id,
                                          encrypted_collection_key, can_upload, can_delete, upload_quota_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (collection_id, recipient_user_id)
           DO UPDATE SET encrypted_collection_key = $4, can_upload = $5, can_delete = $6, upload_quota_bytes = $7"#,
    )
    .bind(coll_id)
    .bind(sharer_id)
    .bind(recipient_id)
    .bind(&req.encrypted_collection_key)
    .bind(req.can_upload)
    .bind(req.can_delete)
    .bind(req.upload_quota_bytes)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: "shared".to_string(),
        }),
    )
        .into_response())
}
