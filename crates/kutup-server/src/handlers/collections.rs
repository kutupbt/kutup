//! Collection handlers — mirrors `backend/handlers/collections.go`.
//!
//! CRUD over collections plus local (same-server) sharing. Federated Drive
//! sharing lives in the unified `drive_federation` feature adapter.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::named_share::NamedShareEnvelopeV1;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::models::{
    CollectionRow, CreateCollectionRequest, CreateCollectionResult, MessageResponse,
    ShareCollectionRequest, UpdateCollectionRequest, UpdateColorRequest,
};
use crate::AppState;

#[derive(sqlx::FromRow)]
struct SharedCollectionDbRow {
    id: Uuid,
    owner_user_id: Uuid,
    name_envelope: String,
    key_epoch: i32,
    name_revision: i64,
    epoch_statement: String,
    epoch_statement_hash: String,
    parent_collection_id: Option<Uuid>,
    color: Option<String>,
    named_share_envelope: String,
    can_upload: bool,
    can_delete: bool,
    upload_quota_bytes: Option<i64>,
    owner_username: Option<String>,
    owner_incarnation_id: String,
    owner_signing_public_key: String,
    owner_authority_public_key: String,
}

/// Parses a collection-id path param; an invalid UUID is a 404 (Go's scan-fails → 404).
fn coll_id_or_404(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| AppError::not_found("not found"))
}

fn canonical_uuid(value: &str) -> AppResult<Uuid> {
    let parsed = Uuid::parse_str(value).map_err(|_| AppError::bad_request("invalid request"))?;
    if parsed.to_string() != value {
        return Err(AppError::bad_request("invalid request"));
    }
    Ok(parsed)
}

fn validate_drive_envelope(envelope: &str, expected: DriveEnvelopeContextV1) -> AppResult<()> {
    let bytes = STANDARD
        .decode(envelope)
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?;
    if STANDARD.encode(&bytes) != envelope || drive_envelope::validate(&bytes, expected).is_err() {
        return Err(AppError::bad_request("invalid Drive envelope"));
    }
    Ok(())
}

fn decode_public_key(value: &str) -> AppResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AppError::conflict("account identity is unavailable"))?;
    if bytes.len() != 32 || STANDARD.encode(&bytes) != value {
        return Err(AppError::conflict("account identity is unavailable"));
    }
    Ok(bytes)
}

/// `GET /api/collections` — mirrors `ListCollections`. Owned collections, then those
/// shared with the user (with the recipient-specific key + permissions + computed usage).
#[utoipa::path(
    get,
    path = "/api/collections",
    tag = "collections",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Owned + shared collections", body = Vec<CollectionRow>))
)]
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
        i32,
        i64,
        String,
        String,
        Option<Uuid>,
        Option<String>,
    );
    let own: Vec<OwnRow> = sqlx::query_as(
        r#"SELECT id, owner_user_id, name_envelope, owner_key_envelope,
                  key_epoch, name_revision, epoch_statement, epoch_statement_hash,
                  parent_collection_id, color
           FROM collections WHERE owner_user_id = $1 AND deleted_at IS NULL
           ORDER BY created_at ASC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    let mut out: Vec<CollectionRow> = own
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
                parent,
                color,
            )| CollectionRow {
                id: id.to_string(),
                owner_user_id: owner.to_string(),
                name_envelope: name,
                owner_key_envelope: Some(owner_key),
                named_share_envelope: None,
                key_epoch: epoch,
                name_revision: revision,
                epoch_statement: statement,
                epoch_statement_hash: statement_hash,
                owner_account: None,
                owner_incarnation_id: None,
                owner_drive_signing_public_key: None,
                owner_authority_public_key: None,
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

    let shared: Vec<SharedCollectionDbRow> = sqlx::query_as(
        r#"SELECT c.id, c.owner_user_id, c.name_envelope, c.key_epoch,
                  c.name_revision, c.epoch_statement, c.epoch_statement_hash,
                  c.parent_collection_id, c.color, cs.named_share_envelope,
                  cs.can_upload, cs.can_delete, cs.upload_quota_bytes,
                  owner.username AS owner_username,
                  owner.account_incarnation_id AS owner_incarnation_id,
                  owner.drive_signing_public_key AS owner_signing_public_key,
                  owner.account_authority_public_key AS owner_authority_public_key
           FROM collections c
           JOIN collection_shares cs ON cs.collection_id = c.id
           JOIN users owner ON owner.id = c.owner_user_id
           WHERE cs.recipient_user_id = $1 AND c.deleted_at IS NULL
           ORDER BY c.created_at ASC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    for row in shared {
        // Compute this user's usage in the shared collection when an upload quota applies.
        let upload_used_bytes = if row.can_upload && row.upload_quota_bytes.is_some() {
            let used: Option<i64> = sqlx::query_scalar(
                "SELECT COALESCE(SUM(encrypted_size_bytes), 0)::bigint FROM files WHERE collection_id = $1 AND uploader_user_id = $2",
            )
            .bind(row.id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
            Some(used.unwrap_or(0))
        } else {
            None
        };

        let domain = state
            .federation
            .as_ref()
            .map(|federation| federation.server_name())
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| AppError::conflict("named shares require a canonical server domain"))?;
        let owner_username = row
            .owner_username
            .as_deref()
            .filter(|username| !username.is_empty())
            .ok_or_else(|| AppError::conflict("share owner identity is unavailable"))?;
        out.push(CollectionRow {
            id: row.id.to_string(),
            owner_user_id: row.owner_user_id.to_string(),
            name_envelope: row.name_envelope,
            owner_key_envelope: None,
            named_share_envelope: Some(row.named_share_envelope),
            key_epoch: row.key_epoch,
            name_revision: row.name_revision,
            epoch_statement: row.epoch_statement,
            epoch_statement_hash: row.epoch_statement_hash,
            owner_account: Some(format!("{owner_username}@{domain}")),
            owner_incarnation_id: Some(row.owner_incarnation_id),
            owner_drive_signing_public_key: Some(row.owner_signing_public_key),
            owner_authority_public_key: Some(row.owner_authority_public_key),
            parent_collection_id: row.parent_collection_id.map(|p| p.to_string()),
            color: row.color,
            can_upload: Some(row.can_upload),
            can_delete: Some(row.can_delete),
            upload_quota_bytes: row.upload_quota_bytes,
            upload_used_bytes,
            is_shared: true,
        });
    }

    Ok(Json(out).into_response())
}

/// `POST /api/collections` — mirrors `CreateCollection`.
#[utoipa::path(
    post,
    path = "/api/collections",
    tag = "collections",
    security(("BearerAuth" = [])),
    request_body = CreateCollectionRequest,
    responses((status = 201, description = "Collection created", body = CreateCollectionResult))
)]
pub async fn create_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateCollectionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = canonical_uuid(&req.id)?;
    let parent = req
        .parent_collection_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| AppError::bad_request("invalid request"))?;

    let authority_public_key: String =
        sqlx::query_scalar("SELECT account_authority_public_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let authority_public_key = decode_public_key(&authority_public_key)?;
    let id_string = id.to_string();
    let owner_string = user_id.to_string();
    validate_drive_envelope(
        &req.owner_key_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::CollectionKey,
            1,
            1,
            &id_string,
            &owner_string,
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    validate_drive_envelope(
        &req.name_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::CollectionName,
            1,
            1,
            &id_string,
            &owner_string,
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    let epoch_statement = CollectionEpochStatementV1::decode_b64(&req.epoch_statement)
        .map_err(|_| AppError::bad_request("invalid collection epoch statement"))?;
    epoch_statement
        .verify_authority(&authority_public_key)
        .and_then(|_| epoch_statement.verify_binding(&id_string, &owner_string, 1, None))
        .map_err(|_| AppError::bad_request("invalid collection epoch statement"))?;
    let statement_hash = epoch_statement.statement_hash();

    let mut tx = state.pool.begin().await?;
    if let Some(parent_id) = parent {
        let parent_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM collections WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL)",
        )
        .bind(parent_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        if !parent_owned {
            return Err(AppError::bad_request("invalid parent collection"));
        }
    }
    sqlx::query(
        r#"INSERT INTO collections
              (id, owner_user_id, name_envelope, owner_key_envelope, key_epoch,
               name_revision, epoch_statement, epoch_statement_hash, parent_collection_id)
           VALUES ($1,$2,$3,$4,1,1,$5,$6,$7)"#,
    )
    .bind(id)
    .bind(user_id)
    .bind(&req.name_envelope)
    .bind(&req.owner_key_envelope)
    .bind(&req.epoch_statement)
    .bind(&statement_hash)
    .bind(parent)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"INSERT INTO collection_key_epoch_history
              (collection_id, epoch, owner_key_envelope, epoch_statement, epoch_statement_hash)
           VALUES ($1,1,$2,$3,$4)"#,
    )
    .bind(id)
    .bind(&req.owner_key_envelope)
    .bind(&req.epoch_statement)
    .bind(&statement_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateCollectionResult { id: id.to_string() }),
    )
        .into_response())
}

/// `GET /api/collections/{id}` — mirrors `GetCollection`.
#[utoipa::path(
    get,
    path = "/api/collections/{id}",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "One collection (owned or shared view)", body = CollectionRow))
)]
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
        i32,
        i64,
        String,
        String,
        Option<Uuid>,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT id, owner_user_id, name_envelope, owner_key_envelope,
                  key_epoch, name_revision, epoch_statement, epoch_statement_hash,
                  parent_collection_id, color
           FROM collections WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    if let Some((
        cid,
        owner,
        name,
        owner_key,
        epoch,
        revision,
        statement,
        statement_hash,
        parent,
        color,
    )) = row
    {
        return Ok(Json(CollectionRow {
            id: cid.to_string(),
            owner_user_id: owner.to_string(),
            name_envelope: name,
            owner_key_envelope: Some(owner_key),
            named_share_envelope: None,
            key_epoch: epoch,
            name_revision: revision,
            epoch_statement: statement,
            epoch_statement_hash: statement_hash,
            owner_account: None,
            owner_incarnation_id: None,
            owner_drive_signing_public_key: None,
            owner_authority_public_key: None,
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
    let shared: Option<SharedCollectionDbRow> = sqlx::query_as(
        r#"SELECT c.id, c.owner_user_id, c.name_envelope, c.key_epoch, c.name_revision,
                  c.epoch_statement, c.epoch_statement_hash, c.parent_collection_id, c.color,
                  cs.named_share_envelope, cs.can_upload, cs.can_delete, cs.upload_quota_bytes,
                  owner.username AS owner_username,
                  owner.account_incarnation_id AS owner_incarnation_id,
                  owner.drive_signing_public_key AS owner_signing_public_key,
                  owner.account_authority_public_key AS owner_authority_public_key
           FROM collections c
           JOIN collection_shares cs ON cs.collection_id = c.id
           JOIN users owner ON owner.id = c.owner_user_id
           WHERE c.id = $1 AND cs.recipient_user_id = $2 AND c.deleted_at IS NULL"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = shared else {
        return Err(AppError::not_found("not found"));
    };
    let domain = state
        .federation
        .as_ref()
        .map(|federation| federation.server_name())
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| AppError::conflict("named shares require a canonical server domain"))?;
    let owner_username = row
        .owner_username
        .as_deref()
        .filter(|username| !username.is_empty())
        .ok_or_else(|| AppError::conflict("share owner identity is unavailable"))?;
    Ok(Json(CollectionRow {
        id: coll_id.to_string(),
        owner_user_id: row.owner_user_id.to_string(),
        name_envelope: row.name_envelope,
        owner_key_envelope: None,
        named_share_envelope: Some(row.named_share_envelope),
        key_epoch: row.key_epoch,
        name_revision: row.name_revision,
        epoch_statement: row.epoch_statement,
        epoch_statement_hash: row.epoch_statement_hash,
        owner_account: Some(format!("{owner_username}@{domain}")),
        owner_incarnation_id: Some(row.owner_incarnation_id),
        owner_drive_signing_public_key: Some(row.owner_signing_public_key),
        owner_authority_public_key: Some(row.owner_authority_public_key),
        parent_collection_id: row.parent_collection_id.map(|p| p.to_string()),
        color: row.color,
        can_upload: Some(row.can_upload),
        can_delete: Some(row.can_delete),
        upload_quota_bytes: row.upload_quota_bytes,
        upload_used_bytes: None,
        is_shared: true,
    })
    .into_response())
}

/// `PUT /api/collections/{id}` — mirrors `UpdateCollection` (rename).
#[utoipa::path(
    put,
    path = "/api/collections/{id}",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    request_body = UpdateCollectionRequest,
    responses((status = 200, description = "Renamed", body = MessageResponse))
)]
pub async fn update_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateCollectionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let coll_id = coll_id_or_404(&id)?;

    let mut tx = state.pool.begin().await?;
    let current: Option<(i32, i64)> = sqlx::query_as(
        "SELECT key_epoch, name_revision FROM collections
         WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((epoch, current_revision)) = current else {
        return Err(AppError::not_found("not found"));
    };
    if req.name_revision != current_revision.saturating_add(1) {
        return Err(AppError::conflict(
            "collection name revision must advance by exactly one",
        ));
    }
    validate_drive_envelope(
        &req.name_envelope,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::CollectionName,
            u32::try_from(epoch).map_err(|_| AppError::conflict("invalid collection epoch"))?,
            u64::try_from(req.name_revision)
                .map_err(|_| AppError::bad_request("invalid name revision"))?,
            &coll_id.to_string(),
            &user_id.to_string(),
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    let res = sqlx::query(
        r#"UPDATE collections SET name_envelope = $1, name_revision = $2, updated_at = NOW()
           WHERE id = $3 AND owner_user_id = $4 AND name_revision = $5 AND deleted_at IS NULL"#,
    )
    .bind(&req.name_envelope)
    .bind(req.name_revision)
    .bind(coll_id)
    .bind(user_id)
    .bind(current_revision)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            tx.commit().await?;
            Ok(Json(MessageResponse {
                message: "updated".to_string(),
            })
            .into_response())
        }
        _ => Err(AppError::not_found("not found")),
    }
}

/// `PATCH /api/collections/{id}/color` — mirrors `UpdateCollectionColor`.
#[utoipa::path(
    patch,
    path = "/api/collections/{id}/color",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    request_body = UpdateColorRequest,
    responses((status = 204, description = "Color updated"))
)]
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
#[utoipa::path(
    delete,
    path = "/api/collections/{id}",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 204, description = "Folder + subtree moved to trash"))
)]
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
#[utoipa::path(
    post,
    path = "/api/collections/{id}/share",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    request_body = ShareCollectionRequest,
    responses((status = 201, description = "Shared", body = MessageResponse))
)]
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

    let collection: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT owner_user_id, key_epoch FROM collections WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(coll_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((owner, epoch)) = collection else {
        return Err(AppError::forbidden("forbidden"));
    };
    if owner != sharer_id {
        return Err(AppError::forbidden("forbidden"));
    }

    type IdentityRow = (Option<String>, String, String, String);
    let sender: IdentityRow = sqlx::query_as(
        "SELECT username, account_incarnation_id, drive_signing_public_key, public_key
         FROM users WHERE id = $1",
    )
    .bind(sharer_id)
    .fetch_one(&state.pool)
    .await?;
    let recipient: IdentityRow = sqlx::query_as(
        "SELECT username, account_incarnation_id, drive_signing_public_key, public_key
         FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(recipient_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::bad_request("invalid recipient"))?;
    let domain = state
        .federation
        .as_ref()
        .map(|federation| federation.server_name())
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| AppError::conflict("named shares require a canonical server domain"))?;
    let sender_account = format!(
        "{}@{domain}",
        sender
            .0
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::conflict("sender identity is unavailable"))?
    );
    let recipient_account = format!(
        "{}@{domain}",
        recipient
            .0
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::conflict("recipient identity is unavailable"))?
    );
    let sender_signing_key = decode_public_key(&sender.2)?;
    let named_share = NamedShareEnvelopeV1::decode_b64(&req.named_share_envelope)
        .map_err(|_| AppError::bad_request("invalid named share envelope"))?;
    named_share
        .verify_binding_and_signature(
            &coll_id.to_string(),
            u32::try_from(epoch).map_err(|_| AppError::conflict("invalid collection epoch"))?,
            &sender_account,
            &sender.1,
            &sender_signing_key,
            &recipient_account,
            &recipient.1,
        )
        .map_err(|_| AppError::bad_request("invalid named share envelope"))?;

    sqlx::query(
        r#"INSERT INTO collection_shares (collection_id, sharer_user_id, recipient_user_id,
                                          named_share_envelope, can_upload, can_delete, upload_quota_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (collection_id, recipient_user_id)
           DO UPDATE SET named_share_envelope = $4, can_upload = $5, can_delete = $6, upload_quota_bytes = $7"#,
    )
    .bind(coll_id)
    .bind(sharer_id)
    .bind(recipient_id)
    .bind(&req.named_share_envelope)
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
