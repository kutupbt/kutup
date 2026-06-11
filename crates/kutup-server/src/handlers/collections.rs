//! Collection handlers — mirrors `backend/handlers/collections.go`.
//!
//! CRUD over collections plus local (same-server) sharing, the federated-share invite, and
//! the remote-pubkey lookup (`/collections/{id}/share-federated`, `/collections/fed-pubkey`)
//! — the last two go through the SSRF guard + the shared federation HTTP client.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{trusted_uuid, FED_CLIENT};
use crate::middleware::AuthUser;
use crate::models::{
    CollectionRow, CreateCollectionRequest, CreateCollectionResult, MessageResponse,
    ShareCollectionRequest, UpdateCollectionRequest, UpdateColorRequest,
};
use crate::{ssrf, AppState};

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
           FROM collections WHERE owner_user_id = $1 AND deleted_at IS NULL
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
           WHERE cs.recipient_user_id = $1 AND c.deleted_at IS NULL
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
           FROM collections WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    if let Some((cid, owner, en, nn, ek, ekn, parent, color)) = row {
        return Ok(Json(CollectionRow {
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
        .into_response());
    }

    // Not the owner — fall back to a collection shared *with* this user, returning the
    // recipient-specific sealed key (so the file editor can open a shared note/doc). The
    // owner-only Go GetCollection 404'd here, which left shared-file open broken; serving the
    // share view matches ListCollections + the frontend's FileEditorPage.
    type SharedRow = (
        Uuid,
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
    let shared: Option<SharedRow> = sqlx::query_as(
        r#"SELECT c.owner_user_id, c.encrypted_name, c.name_nonce, c.encrypted_key_nonce,
                  c.parent_collection_id, c.color,
                  cs.encrypted_collection_key, cs.can_upload, cs.can_delete, cs.upload_quota_bytes
           FROM collections c
           JOIN collection_shares cs ON cs.collection_id = c.id
           WHERE c.id = $1 AND cs.recipient_user_id = $2 AND c.deleted_at IS NULL"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((owner, en, nn, ekn, parent, color, shared_key, can_upload, can_delete, quota)) =
        shared
    else {
        return Err(AppError::not_found("not found"));
    };
    Ok(Json(CollectionRow {
        id: coll_id.to_string(),
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
        upload_used_bytes: None,
        is_shared: true,
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
           WHERE id = $3 AND owner_user_id = $4 AND deleted_at IS NULL"#,
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
        "UPDATE collections SET color = $1, updated_at = NOW() WHERE id = $2 AND owner_user_id = $3 AND deleted_at IS NULL",
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

/// `DELETE /api/collections/{id}` — soft-deletes the folder *and its whole subtree*
/// (sub-folders + files) into the trash. The folder is the single trash entry
/// (`trash_root_id = its id`); restore/purge operate on the entry and everything
/// tagged with it. Items already in the trash keep their own entry + deletion time.
pub async fn delete_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = coll_id_or_404(&id)?;

    let mut tx = state.pool.begin().await?;
    // Walk the live subtree from the root (only the owner's root qualifies).
    let subtree: Vec<Uuid> = sqlx::query_scalar(
        r#"WITH RECURSIVE subtree AS (
             SELECT id FROM collections
             WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
             UNION ALL
             SELECT c.id FROM collections c
             JOIN subtree s ON c.parent_collection_id = s.id
             WHERE c.deleted_at IS NULL
           )
           SELECT id FROM subtree"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    if subtree.is_empty() {
        return Err(AppError::not_found("not found"));
    }

    sqlx::query(
        "UPDATE collections SET deleted_at = NOW(), trash_root_id = $2 WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&subtree)
    .bind(coll_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE files SET deleted_at = NOW(), trash_root_id = $2 WHERE collection_id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&subtree)
    .bind(coll_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT.into_response())
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

    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_user_id FROM collections WHERE id = $1 AND deleted_at IS NULL",
    )
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

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ShareFederatedRequest {
    recipient_username: String,
    recipient_server: String,
    encrypted_collection_key: String,
    can_upload: bool,
    can_delete: bool,
    upload_quota_bytes: Option<i64>,
}

/// `POST /api/collections/{id}/share-federated` — mirrors `ShareFederated`. Creates an
/// outgoing federated share + a random access token, returning an invite URL the recipient
/// pastes into their server.
pub async fn share_federated(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ShareFederatedRequest>,
) -> AppResult<Response> {
    let sharer_id = trusted_uuid(&user.user_id)?;
    if req.recipient_username.is_empty() || req.recipient_server.is_empty() {
        return Err(AppError::bad_request("invalid request"));
    }
    let coll_id = Uuid::parse_str(&id).map_err(|_| AppError::forbidden("forbidden"))?;

    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_user_id FROM collections WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(coll_id)
    .fetch_optional(&state.pool)
    .await?;
    if owner != Some(sharer_id) {
        return Err(AppError::forbidden("forbidden"));
    }

    // 32-byte random access token, hex-encoded (matches Go's hex.EncodeToString).
    let mut token_bytes = [0u8; 32];
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token_bytes);
    }
    let access_token = hex::encode(token_bytes);

    sqlx::query(
        r#"INSERT INTO federated_outgoing_shares (collection_id, sharer_user_id,
               recipient_username, recipient_server, encrypted_collection_key,
               access_token, can_upload, can_delete, upload_quota_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
    )
    .bind(coll_id)
    .bind(sharer_id)
    .bind(&req.recipient_username)
    .bind(&req.recipient_server)
    .bind(&req.encrypted_collection_key)
    .bind(&access_token)
    .bind(req.can_upload)
    .bind(req.can_delete)
    .bind(req.upload_quota_bytes)
    .execute(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let invite_url = format!("{}/invite/{}", state.config.server_url, access_token);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "inviteToken": access_token, "inviteUrl": invite_url })),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct FedPubkeyQuery {
    username: Option<String>,
    server: Option<String>,
}

/// `GET /api/collections/fed-pubkey?username=…&server=…` — mirrors `FetchRemotePubkey`.
/// SSRF-validates `server`, then proxies the remote `/api/fed/users` lookup.
pub async fn fetch_remote_pubkey(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(q): Query<FedPubkeyQuery>,
) -> AppResult<Response> {
    let username = q.username.unwrap_or_default();
    let server = q.server.unwrap_or_default();
    if username.is_empty() || server.is_empty() {
        return Err(AppError::bad_request("username and server required"));
    }

    let allow_http = state.config.app_env != "production";
    if let Err(e) = ssrf::validate_federation_url(&server, allow_http).await {
        return Err(AppError::bad_request(format!("invalid server URL: {e}")));
    }

    let url = format!("{server}/api/fed/users?username={username}");
    let resp = FED_CLIENT.get(&url).send().await;
    let pubkey = match resp {
        Ok(r) if r.status().as_u16() == 200 => {
            #[derive(serde::Deserialize)]
            struct Data {
                #[serde(rename = "publicKey", default)]
                public_key: String,
            }
            match r.json::<Data>().await {
                Ok(d) if !d.public_key.is_empty() => d.public_key,
                _ => {
                    return Err(AppError::new(
                        StatusCode::BAD_GATEWAY,
                        "invalid response from remote server",
                    ))
                }
            }
        }
        _ => {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "failed to fetch pubkey from remote server",
            ))
        }
    };
    Ok(Json(json!({ "publicKey": pubkey })).into_response())
}
