//! Who can open a folder, and taking that access away
//! (docs/plans/drive-share-revocation.md).
//!
//! A folder's keys form a chain of epochs. Removing anyone — a member on this
//! server, a member on another server, a public link — is one rotation: the
//! owner's client makes a new key and hands it to everyone who stays, and the
//! server applies all of it in one transaction or none of it. Files move to
//! the new key when they are next written (`rekey`).

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::named_share::NamedShareEnvelopeV1;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_collection, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

/// One epoch of a folder's key history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct EpochLink {
    pub epoch: i32,
    pub epoch_statement: String,
    pub epoch_statement_hash: String,
    /// The previous epoch's key sealed under this epoch's; absent for epoch 1.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub previous_key_envelope: Option<String>,
}

/// A folder's complete key history, oldest first.
pub(crate) async fn epoch_chain(pool: &PgPool, collection_id: Uuid) -> AppResult<Vec<EpochLink>> {
    Ok(sqlx::query_as(
        "SELECT epoch, epoch_statement, epoch_statement_hash, previous_key_envelope
         FROM collection_key_epoch_history WHERE collection_id = $1 ORDER BY epoch",
    )
    .bind(collection_id)
    .fetch_all(pool)
    .await?)
}

fn validate_envelope(envelope: &str, expected: DriveEnvelopeContextV1) -> AppResult<()> {
    let bytes = STANDARD
        .decode(envelope)
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?;
    if STANDARD.encode(&bytes) != envelope || drive_envelope::validate(&bytes, expected).is_err() {
        return Err(AppError::bad_request("invalid Drive envelope"));
    }
    Ok(())
}

fn context(
    purpose: DriveEnvelopePurpose,
    epoch: i32,
    revision: i64,
    object: Uuid,
    parent: Uuid,
) -> AppResult<DriveEnvelopeContextV1> {
    DriveEnvelopeContextV1::new(
        purpose,
        u32::try_from(epoch).map_err(|_| AppError::conflict("invalid epoch"))?,
        u64::try_from(revision).map_err(|_| AppError::conflict("invalid revision"))?,
        &object.to_string(),
        &parent.to_string(),
    )
    .map_err(|_| AppError::bad_request("invalid Drive envelope"))
}

fn public_key(value: &str) -> AppResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AppError::conflict("account identity is unavailable"))?;
    if bytes.len() != 32 || STANDARD.encode(&bytes) != value {
        return Err(AppError::conflict("account identity is unavailable"));
    }
    Ok(bytes)
}

/// `GET /api/collections/{id}/epochs` — the folder's key history, for the
/// owner and its members.
#[utoipa::path(
    get,
    path = "/api/collections/{id}/epochs",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "Key history, oldest first", body = Vec<EpochLink>))
)]
pub async fn epochs(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let collection_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    // The owner also opens trashed folders' files (the trash lists them).
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_user_id FROM collections WHERE id = $1")
            .bind(collection_id)
            .fetch_optional(&state.pool)
            .await?;
    if owner != Some(user_id) && !can_access_collection(&state.pool, user_id, collection_id).await {
        return Err(AppError::forbidden("forbidden"));
    }
    Ok(Json(epoch_chain(&state.pool, collection_id).await?).into_response())
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessMember {
    pub user_id: Uuid,
    pub account: String,
    pub account_incarnation_id: String,
    /// The member's Drive HPKE key, to seal them the next epoch's key.
    pub drive_public_key: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessLink {
    pub id: Uuid,
    pub token: String,
    /// The link key sealed for the owner (purpose 9); absent on links made
    /// before owners kept a copy — a rotation removes those.
    pub owner_link_key_envelope: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessFederated {
    pub id: Uuid,
    pub recipient_username: String,
    pub recipient_server: String,
    /// The incarnation the current envelope was sealed to; a re-seal must
    /// name the same one.
    pub recipient_incarnation_id: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FolderAccess {
    pub key_epoch: i32,
    pub epoch_statement_hash: String,
    pub members: Vec<AccessMember>,
    pub public_links: Vec<AccessLink>,
    pub federated_shares: Vec<AccessFederated>,
}

/// The owner's folder, locked for the transaction when `lock` is set.
async fn owned_folder(
    executor: &mut sqlx::PgConnection,
    collection_id: Uuid,
    owner: Uuid,
    lock: bool,
) -> AppResult<(i32, i64, String)> {
    let sql = format!(
        "SELECT key_epoch, name_revision, epoch_statement_hash FROM collections
         WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query_as(&sql)
        .bind(collection_id)
        .bind(owner)
        .fetch_optional(executor)
        .await?
        .ok_or_else(|| AppError::not_found("not found"))
}

/// `GET /api/collections/{id}/access` — everyone who can open the folder:
/// members here, members elsewhere, public links. Owner only.
#[utoipa::path(
    get,
    path = "/api/collections/{id}/access",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "Who has access", body = FolderAccess))
)]
pub async fn access(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let owner = trusted_uuid(&user.user_id)?;
    let collection_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let mut conn = state.pool.acquire().await?;
    let (key_epoch, _, epoch_statement_hash) =
        owned_folder(&mut conn, collection_id, owner, false).await?;
    drop(conn);
    let domain = state.config.chat_server_name.as_str();

    type MemberRow = (
        Uuid,
        Option<String>,
        String,
        String,
        bool,
        bool,
        Option<i64>,
        OffsetDateTime,
    );
    let members: Vec<MemberRow> = sqlx::query_as(
        "SELECT u.id, u.username, u.account_incarnation_id, u.public_key,
                cs.can_upload, cs.can_delete, cs.upload_quota_bytes, cs.created_at
         FROM collection_shares cs JOIN users u ON u.id = cs.recipient_user_id
         WHERE cs.collection_id = $1 ORDER BY cs.created_at",
    )
    .bind(collection_id)
    .fetch_all(&state.pool)
    .await?;
    type LinkRow = (
        Uuid,
        String,
        Option<String>,
        Option<OffsetDateTime>,
        OffsetDateTime,
    );
    let links: Vec<LinkRow> = sqlx::query_as(
        "SELECT id, token, owner_link_key_envelope, expires_at, created_at
             FROM public_shares WHERE target_id = $1 ORDER BY created_at",
    )
    .bind(collection_id)
    .fetch_all(&state.pool)
    .await?;
    type FederatedRow = (
        Uuid,
        String,
        String,
        String,
        bool,
        bool,
        Option<i64>,
        OffsetDateTime,
    );
    let federated: Vec<FederatedRow> = sqlx::query_as(
        "SELECT id, recipient_username, recipient_domain, named_share_envelope,
                can_upload, can_delete, upload_quota_bytes, created_at
         FROM federated_outgoing_shares WHERE collection_id = $1 ORDER BY created_at",
    )
    .bind(collection_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(FolderAccess {
        key_epoch,
        epoch_statement_hash,
        members: members
            .into_iter()
            .map(
                |(
                    user_id,
                    username,
                    incarnation,
                    public_key,
                    can_upload,
                    can_delete,
                    quota,
                    created_at,
                )| {
                    AccessMember {
                        user_id,
                        account: format!("{}@{domain}", username.unwrap_or_default()),
                        account_incarnation_id: incarnation,
                        drive_public_key: public_key,
                        can_upload,
                        can_delete,
                        upload_quota_bytes: quota,
                        created_at,
                    }
                },
            )
            .collect(),
        public_links: links
            .into_iter()
            .map(
                |(id, token, owner_link_key_envelope, expires_at, created_at)| AccessLink {
                    id,
                    token,
                    owner_link_key_envelope,
                    expires_at,
                    created_at,
                },
            )
            .collect(),
        federated_shares: federated
            .into_iter()
            .map(
                |(id, username, server, envelope, can_upload, can_delete, quota, created_at)| {
                    AccessFederated {
                        id,
                        recipient_username: username,
                        recipient_server: server,
                        recipient_incarnation_id: NamedShareEnvelopeV1::decode_b64(&envelope)
                            .map(|share| hex::encode(share.recipient_incarnation_id))
                            .unwrap_or_default(),
                        can_upload,
                        can_delete,
                        upload_quota_bytes: quota,
                        created_at,
                    }
                },
            )
            .collect(),
    })
    .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeptMember {
    pub user_id: Uuid,
    pub named_share_envelope: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeptLink {
    pub id: Uuid,
    pub collection_key_envelope: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeptFederated {
    pub id: Uuid,
    pub named_share_envelope: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Removed {
    #[serde(default)]
    pub members: Vec<Uuid>,
    #[serde(default)]
    pub public_links: Vec<Uuid>,
    #[serde(default)]
    pub federated_shares: Vec<Uuid>,
}

/// One rotation: the next epoch, everyone kept (with their new envelope) and
/// everyone removed. Together they must name exactly the folder's current
/// access, or nothing changes (`409`).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateRequest {
    /// The epoch the client built from; the new one is the next.
    pub from_epoch: i32,
    pub epoch_statement: String,
    pub owner_key_envelope: String,
    pub previous_key_envelope: String,
    /// The folder's name, re-sealed at the new epoch and the next name revision.
    pub name_envelope: String,
    #[serde(default)]
    pub members: Vec<KeptMember>,
    #[serde(default)]
    pub public_links: Vec<KeptLink>,
    #[serde(default)]
    pub federated_shares: Vec<KeptFederated>,
    #[serde(default)]
    pub removed: Removed,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RotateResult {
    pub key_epoch: i32,
    pub epoch_statement_hash: String,
}

/// Kept ∪ removed must be exactly `current`, with nothing in both.
fn same_membership(current: &[Uuid], kept: &[Uuid], removed: &[Uuid]) -> bool {
    let current: BTreeSet<_> = current.iter().collect();
    let kept_set: BTreeSet<_> = kept.iter().collect();
    let removed_set: BTreeSet<_> = removed.iter().collect();
    kept_set.len() == kept.len()
        && removed_set.len() == removed.len()
        && kept_set.is_disjoint(&removed_set)
        && kept_set
            .union(&removed_set)
            .cloned()
            .collect::<BTreeSet<_>>()
            == current
}

/// `POST /api/collections/{id}/rotate` — move the folder to a new key, keep
/// who is listed, remove who is listed as removed. Owner only; all or
/// nothing.
#[utoipa::path(
    post,
    path = "/api/collections/{id}/rotate",
    tag = "collections",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Collection id")),
    request_body = RotateRequest,
    responses(
        (status = 200, description = "Rotated", body = RotateResult),
        (status = 409, description = "The folder's key or access changed since the client read it")
    )
)]
pub async fn rotate(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RotateRequest>,
) -> AppResult<Response> {
    let owner = trusted_uuid(&user.user_id)?;
    let collection_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    let (epoch, name_revision, current_hash) =
        owned_folder(&mut tx, collection_id, owner, true).await?;
    if epoch != req.from_epoch {
        return Err(AppError::conflict("folder key changed; reload"));
    }
    let next = epoch
        .checked_add(1)
        .ok_or_else(|| AppError::conflict("epoch exhausted"))?;
    let next_revision = name_revision
        .checked_add(1)
        .ok_or_else(|| AppError::conflict("name revision exhausted"))?;

    // The owner's identity, which signs the chain and every share.
    let (username, incarnation, signing_key, authority_key): (
        Option<String>,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT username, account_incarnation_id, drive_signing_public_key,
                    account_authority_public_key FROM users WHERE id = $1",
    )
    .bind(owner)
    .fetch_one(&mut *tx)
    .await?;
    let username = username
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AppError::conflict("owner identity is unavailable"))?;
    let signing_key = public_key(&signing_key)?;

    let statement = CollectionEpochStatementV1::decode_b64(&req.epoch_statement)
        .map_err(|_| AppError::bad_request("invalid epoch statement"))?;
    statement
        .verify_authority(&public_key(&authority_key)?)
        .and_then(|()| {
            statement.verify_binding(
                &collection_id.to_string(),
                &owner.to_string(),
                u32::try_from(next).unwrap_or(0),
                Some(&current_hash),
            )
        })
        .map_err(|_| AppError::bad_request("invalid epoch statement"))?;
    let statement_hash = statement.statement_hash();
    validate_envelope(
        &req.owner_key_envelope,
        context(
            DriveEnvelopePurpose::CollectionKey,
            next,
            1,
            collection_id,
            owner,
        )?,
    )?;
    validate_envelope(
        &req.previous_key_envelope,
        context(
            DriveEnvelopePurpose::PreviousCollectionKey,
            next,
            1,
            collection_id,
            owner,
        )?,
    )?;
    validate_envelope(
        &req.name_envelope,
        context(
            DriveEnvelopePurpose::CollectionName,
            next,
            next_revision,
            collection_id,
            owner,
        )?,
    )?;

    // Exactly the current access, split into kept and removed.
    let members: Vec<(Uuid, Option<String>, String)> = sqlx::query_as(
        "SELECT u.id, u.username, u.account_incarnation_id
         FROM collection_shares cs JOIN users u ON u.id = cs.recipient_user_id
         WHERE cs.collection_id = $1",
    )
    .bind(collection_id)
    .fetch_all(&mut *tx)
    .await?;
    let links: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, owner_link_key_envelope FROM public_shares WHERE target_id = $1",
    )
    .bind(collection_id)
    .fetch_all(&mut *tx)
    .await?;
    let federated: Vec<(Uuid, String, String, String)> = sqlx::query_as(
        "SELECT id, recipient_username, recipient_domain, named_share_envelope
         FROM federated_outgoing_shares WHERE collection_id = $1",
    )
    .bind(collection_id)
    .fetch_all(&mut *tx)
    .await?;
    let kept_members: Vec<Uuid> = req.members.iter().map(|m| m.user_id).collect();
    let kept_links: Vec<Uuid> = req.public_links.iter().map(|l| l.id).collect();
    let kept_federated: Vec<Uuid> = req.federated_shares.iter().map(|f| f.id).collect();
    if !same_membership(
        &members.iter().map(|m| m.0).collect::<Vec<_>>(),
        &kept_members,
        &req.removed.members,
    ) || !same_membership(
        &links.iter().map(|l| l.0).collect::<Vec<_>>(),
        &kept_links,
        &req.removed.public_links,
    ) || !same_membership(
        &federated.iter().map(|f| f.0).collect::<Vec<_>>(),
        &kept_federated,
        &req.removed.federated_shares,
    ) {
        return Err(AppError::conflict("folder access changed; reload"));
    }

    // Every kept envelope must be for the new epoch and its exact recipient.
    let domain = state.config.chat_server_name.as_str();
    let sender_account = format!("{username}@{domain}");
    let member_identity: BTreeMap<Uuid, (Option<String>, String)> = members
        .into_iter()
        .map(|(id, name, incarnation)| (id, (name, incarnation)))
        .collect();
    let next_u32 = u32::try_from(next).map_err(|_| AppError::conflict("invalid epoch"))?;
    for member in &req.members {
        let (name, recipient_incarnation) = &member_identity[&member.user_id];
        let recipient = format!(
            "{}@{domain}",
            name.as_deref()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| AppError::conflict("member identity is unavailable"))?
        );
        NamedShareEnvelopeV1::decode_b64(&member.named_share_envelope)
            .and_then(|share| {
                share.verify_binding_and_signature(
                    &collection_id.to_string(),
                    next_u32,
                    &sender_account,
                    &incarnation,
                    &signing_key,
                    &recipient,
                    recipient_incarnation,
                )
            })
            .map_err(|_| AppError::bad_request("invalid named share envelope"))?;
    }
    let link_owner_copy: BTreeMap<Uuid, bool> = links
        .iter()
        .map(|(id, owner_copy)| (*id, owner_copy.is_some()))
        .collect();
    for link in &req.public_links {
        // A link the owner has no copy of cannot be re-wrapped, so it cannot stay.
        if !link_owner_copy[&link.id] {
            return Err(AppError::bad_request(
                "a link made before owners kept a copy must be removed",
            ));
        }
        validate_envelope(
            &link.collection_key_envelope,
            context(
                DriveEnvelopePurpose::PublicLinkCollectionKey,
                next,
                1,
                collection_id,
                owner,
            )?,
        )?;
    }
    if !req.federated_shares.is_empty() {
        let server_name = state
            .federation
            .as_deref()
            .map(|stack| stack.server_name().to_owned())
            .ok_or_else(|| AppError::conflict("federation is not configured"))?;
        let fed_sender = format!("{username}@{server_name}");
        let rows: BTreeMap<Uuid, (String, String, String)> = federated
            .into_iter()
            .map(|(id, name, server, envelope)| (id, (name, server, envelope)))
            .collect();
        for share in &req.federated_shares {
            let (name, server, current) = &rows[&share.id];
            // Sealed to the same account incarnation as before.
            let recipient_incarnation = NamedShareEnvelopeV1::decode_b64(current)
                .map(|share| hex::encode(share.recipient_incarnation_id))
                .map_err(|_| AppError::conflict("stored federated share is invalid"))?;
            NamedShareEnvelopeV1::decode_b64(&share.named_share_envelope)
                .and_then(|envelope| {
                    envelope.verify_binding_and_signature(
                        &collection_id.to_string(),
                        next_u32,
                        &fed_sender,
                        &incarnation,
                        &signing_key,
                        &format!("{name}@{server}"),
                        &recipient_incarnation,
                    )
                })
                .map_err(|_| AppError::bad_request("invalid named share envelope"))?;
        }
    }

    // Apply it all.
    sqlx::query(
        "UPDATE collections SET key_epoch = $2, owner_key_envelope = $3, name_envelope = $4,
                name_revision = $5, epoch_statement = $6, epoch_statement_hash = $7,
                updated_at = NOW()
         WHERE id = $1",
    )
    .bind(collection_id)
    .bind(next)
    .bind(&req.owner_key_envelope)
    .bind(&req.name_envelope)
    .bind(next_revision)
    .bind(&req.epoch_statement)
    .bind(&statement_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO collection_key_epoch_history
            (collection_id, epoch, owner_key_envelope, epoch_statement, epoch_statement_hash,
             previous_key_envelope)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(collection_id)
    .bind(next)
    .bind(&req.owner_key_envelope)
    .bind(&req.epoch_statement)
    .bind(&statement_hash)
    .bind(&req.previous_key_envelope)
    .execute(&mut *tx)
    .await?;
    for member in &req.members {
        sqlx::query(
            "UPDATE collection_shares SET named_share_envelope = $3
             WHERE collection_id = $1 AND recipient_user_id = $2",
        )
        .bind(collection_id)
        .bind(member.user_id)
        .bind(&member.named_share_envelope)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "DELETE FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = ANY($2)",
    )
    .bind(collection_id)
    .bind(&req.removed.members)
    .execute(&mut *tx)
    .await?;
    for link in &req.public_links {
        sqlx::query(
            "UPDATE public_shares SET collection_key_envelope = $2, collection_key_epoch = $3
             WHERE id = $1",
        )
        .bind(link.id)
        .bind(&link.collection_key_envelope)
        .bind(next)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM public_shares WHERE target_id = $1 AND id = ANY($2)")
        .bind(collection_id)
        .bind(&req.removed.public_links)
        .execute(&mut *tx)
        .await?;
    for share in &req.federated_shares {
        sqlx::query("UPDATE federated_outgoing_shares SET named_share_envelope = $2 WHERE id = $1")
            .bind(share.id)
            .bind(&share.named_share_envelope)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM federated_outgoing_shares WHERE collection_id = $1 AND id = ANY($2)")
        .bind(collection_id)
        .bind(&req.removed.federated_shares)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(RotateResult {
        key_epoch: next,
        epoch_statement_hash: statement_hash,
    })
    .into_response())
}

/// A new file key at the folder's current epoch, and the file's metadata
/// sealed under it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RekeyRequest {
    /// The epoch the file is leaving (compare-and-swap).
    pub from_epoch: i32,
    pub file_key_envelope: String,
    pub metadata_envelope: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RekeyResult {
    pub key_epoch: i32,
}

/// `POST /api/files/{id}/rekey` — move a file to its folder's current key
/// before writing to it. The key it leaves stays in its history, so what was
/// stored under it stays readable. Editors only.
#[utoipa::path(
    post,
    path = "/api/files/{id}/rekey",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = RekeyRequest,
    responses(
        (status = 200, description = "Re-keyed", body = RekeyResult),
        (status = 409, description = "Already moved (by another editor), or already current")
    )
)]
pub async fn rekey(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RekeyRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    if !crate::drive_writes::can_write_file(&state.pool, user_id, file_id).await {
        return Err(AppError::forbidden("forbidden"));
    }
    let mut tx = state.pool.begin().await?;
    let file: Option<(Uuid, i32, String, i64)> = sqlx::query_as(
        "SELECT collection_id, key_epoch, file_key_envelope, metadata_revision
         FROM files WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((collection_id, epoch, file_key_envelope, metadata_revision)) = file else {
        return Err(AppError::not_found("not found"));
    };
    // The folder's epoch, held until commit (a rotation waits).
    let folder_epoch: i32 =
        sqlx::query_scalar("SELECT key_epoch FROM collections WHERE id = $1 FOR SHARE")
            .bind(collection_id)
            .fetch_one(&mut *tx)
            .await?;
    if epoch != req.from_epoch {
        return Err(AppError::conflict("file key changed"));
    }
    if epoch >= folder_epoch {
        return Err(AppError::conflict("file key is already current"));
    }
    validate_envelope(
        &req.file_key_envelope,
        context(
            DriveEnvelopePurpose::FileKey,
            folder_epoch,
            1,
            file_id,
            collection_id,
        )?,
    )?;
    validate_envelope(
        &req.metadata_envelope,
        context(
            DriveEnvelopePurpose::FileMetadata,
            folder_epoch,
            metadata_revision,
            file_id,
            collection_id,
        )?,
    )?;
    sqlx::query(
        "INSERT INTO file_key_history (file_id, epoch, file_key_envelope) VALUES ($1, $2, $3)",
    )
    .bind(file_id)
    .bind(epoch)
    .bind(&file_key_envelope)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE files SET key_epoch = $2, file_key_envelope = $3, metadata_envelope = $4
         WHERE id = $1",
    )
    .bind(file_id)
    .bind(folder_epoch)
    .bind(&req.file_key_envelope)
    .bind(&req.metadata_envelope)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // Live sessions reconnect under the new key.
    state.hub.close_room(&file_id.to_string());
    Ok((
        StatusCode::OK,
        Json(RekeyResult {
            key_epoch: folder_epoch,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::same_membership;
    use uuid::Uuid;

    #[test]
    fn membership_must_match_exactly() {
        let [a, b, c] = [Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)];
        assert!(same_membership(&[a, b], &[a], &[b]));
        assert!(same_membership(&[], &[], &[]));
        // Someone added meanwhile would be silently dropped: refused.
        assert!(!same_membership(&[a, b, c], &[a], &[b]));
        // Someone no longer there, listed twice, or both kept and removed.
        assert!(!same_membership(&[a], &[a], &[b]));
        assert!(!same_membership(&[a, b], &[a, a], &[b]));
        assert!(!same_membership(&[a, b], &[a, b], &[b]));
    }
}
