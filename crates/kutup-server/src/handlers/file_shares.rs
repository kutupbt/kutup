//! Sharing a single file (docs/plans/drive-file-sharing.md), like Proton
//! Drive and CryptPad: the owner seals the file's current key to someone
//! (`FileShareEnvelopeV1`, bound to the file and its key generation, signed
//! with the owner's Drive key). The recipient opens the file, its versions
//! and its live edits with that key, and older generations through the
//! file's key history; they never get the folder's key.
//!
//! Only the owner (the owner of the file's folder) shares. Removing someone
//! moves the file to a new key, in one request, re-sealed for everyone who
//! stays.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use kutup_crypto::named_share::FileShareEnvelopeV1;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::files::{file_rows, validate_envelope};
use crate::handlers::folder_access::same_membership;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::models::FileRow;
use crate::AppState;

const MAX_ENVELOPE_CHARS: usize = 2048;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareFileRequest {
    pub recipient_user_id: Uuid,
    /// `FileShareEnvelopeV1` for the file's current key generation.
    pub share_envelope: String,
    pub can_edit: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileAccessMember {
    pub user_id: Uuid,
    pub account: String,
    pub account_incarnation_id: String,
    /// Their Drive HPKE key, to seal them the file's next key.
    pub drive_public_key: String,
    pub drive_signing_public_key: Option<String>,
    pub can_edit: bool,
    /// The generation their envelope opens; below the file's, it waits for
    /// the owner to re-seal it.
    pub key_generation: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileAccess {
    pub key_generation: i32,
    pub members: Vec<FileAccessMember>,
    /// People with edit access may share it on.
    pub editors_can_share: bool,
    /// Public links to the file (for its owner only).
    pub public_links: Vec<FileLink>,
    /// People on other servers (for its owner only).
    pub federated_shares: Vec<FederatedFileMember>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberEnvelope {
    pub user_id: Uuid,
    pub share_envelope: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResealRequest {
    /// Envelopes at the file's current generation, for members left behind.
    pub members: Vec<MemberEnvelope>,
    /// The file's links left behind, re-wrapped at the current generation.
    #[serde(default)]
    pub public_links: Vec<LinkEnvelope>,
    /// People on other servers left behind, re-sealed.
    #[serde(default)]
    pub federated_shares: Vec<FederatedEnvelope>,
}

/// A link to the file, its key sealed under the link key (purpose 11).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkEnvelope {
    pub id: Uuid,
    pub key_envelope: String,
}

/// Someone on another server the file is shared with, for its owner.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederatedFileMember {
    pub id: Uuid,
    pub recipient_username: String,
    pub recipient_server: String,
    pub recipient_incarnation_id: String,
    /// The generation their envelope opens; below the file's, it waits.
    pub key_generation: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// An envelope for someone on another server, at a new generation.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedEnvelope {
    pub id: Uuid,
    pub share_envelope: String,
}

/// A public link to the file, for its owner.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileLink {
    pub id: Uuid,
    pub token: String,
    /// The link key sealed for the owner (purpose 9), to copy and re-wrap it.
    pub owner_link_key_envelope: Option<String>,
    /// The generation its wrap opens; below the file's, it waits to be re-wrapped.
    pub key_generation: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateFileAccessRequest {
    /// The key generation the file is leaving (compare-and-swap).
    pub from_generation: i32,
    /// The new key, sealed under the folder's current key.
    pub file_key_envelope: String,
    /// The metadata, re-sealed under the new key.
    pub metadata_envelope: String,
    /// The key being left, sealed under the new one.
    pub previous_key_envelope: String,
    /// Everyone who stays, with an envelope for the new generation.
    pub members: Vec<MemberEnvelope>,
    /// Everyone removed.
    pub removed: Vec<Uuid>,
    /// Every link that stays, re-wrapped for the new generation.
    #[serde(default)]
    pub public_links: Vec<LinkEnvelope>,
    /// Links removed.
    #[serde(default)]
    pub removed_links: Vec<Uuid>,
    /// Everyone on other servers who stays, re-sealed for the new generation.
    #[serde(default)]
    pub federated_shares: Vec<FederatedEnvelope>,
    /// People on other servers removed.
    #[serde(default)]
    pub removed_federated: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MetadataAtShare {
    pub envelope: String,
    pub revision: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SharedFile {
    /// The file as a folder listing shows it.
    pub file: FileRow,
    pub share_envelope: String,
    pub can_edit: bool,
    /// The generation the envelope opens.
    pub key_generation: i32,
    /// For a share left at an older generation: the file's metadata as it
    /// was at that generation, sealed under the key the share opens (so the
    /// file can still be named while it waits for the owner).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_at_share: Option<MetadataAtShare>,
    /// The file's key is wrapped at its folder's current epoch. When it is
    /// not, or `key_generation` is behind the file's, the share waits for the
    /// owner: it can be read, not edited.
    pub folder_key_current: bool,
    pub owner_user_id: Uuid,
    pub owner_account: String,
    pub owner_incarnation_id: String,
    pub owner_signing_public_key: String,
    /// Who sealed the envelope: the owner, or an editor the owner lets share.
    pub sharer_account: String,
    pub sharer_incarnation_id: String,
    pub sharer_signing_public_key: String,
    /// People with edit access may share it on.
    pub editors_can_share: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub shared_at: OffsetDateTime,
}

struct Party {
    account: String,
    incarnation: String,
    signing_public_key: Option<String>,
}

async fn party(pool: &PgPool, user_id: Uuid, domain: &str) -> AppResult<Party> {
    let row: Option<(Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT username, account_incarnation_id, drive_signing_public_key
         FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some((Some(username), incarnation, signing_public_key)) => Ok(Party {
            account: format!("{username}@{domain}"),
            incarnation,
            signing_public_key,
        }),
        _ => Err(AppError::not_found("no such person")),
    }
}

/// The file's folder, key generation, folder epoch and metadata revision,
/// when `user_id` owns it (the file row locked until commit).
async fn owned_file(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
    user_id: Uuid,
) -> AppResult<(Uuid, i32, i32, i64)> {
    let row: Option<(Uuid, Uuid, i32, i64, i32)> = sqlx::query_as(
        "SELECT c.owner_user_id, f.collection_id, f.key_generation, f.metadata_revision, c.key_epoch
         FROM files f JOIN collections c ON c.id = f.collection_id
         WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL
         FOR UPDATE OF f",
    )
    .bind(file_id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        Some((owner, collection, generation, revision, folder_epoch)) if owner == user_id => {
            Ok((collection, generation, folder_epoch, revision))
        }
        Some(_) => Err(AppError::forbidden("only the owner shares this file")),
        None => Err(AppError::not_found("not found")),
    }
}

/// Whether `user_id`, not the owner, may share the file on: the owner allows
/// editors to share, and they edit it at its current key. Returns the key
/// generation when they may.
async fn editor_may_share(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
    user_id: Uuid,
) -> AppResult<Option<i32>> {
    let row: Option<(i32, bool)> = sqlx::query_as(&format!(
        "SELECT f.key_generation, f.editors_can_share
         FROM file_shares fs
         JOIN files f ON f.id = fs.file_id
         JOIN collections c ON c.id = f.collection_id
         WHERE fs.file_id = $1 AND fs.recipient_user_id = $2 AND fs.can_edit
           AND f.deleted_at IS NULL AND c.deleted_at IS NULL
           AND {}
         FOR UPDATE OF f",
        crate::drive_writes::FILE_SHARE_CURRENT
    ))
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.and_then(|(generation, allowed)| allowed.then_some(generation)))
}

fn verify_envelope(
    envelope: &str,
    file_id: Uuid,
    generation: i32,
    owner: &Party,
    recipient: &Party,
) -> AppResult<()> {
    if envelope.len() > MAX_ENVELOPE_CHARS {
        return Err(AppError::bad_request("invalid file share"));
    }
    let signing = owner
        .signing_public_key
        .as_deref()
        .and_then(|value| STANDARD.decode(value).ok())
        .ok_or_else(|| AppError::conflict("account identity is unavailable"))?;
    FileShareEnvelopeV1::decode_b64(envelope)
        .and_then(|decoded| {
            decoded.verify_binding_and_signature(
                &file_id.to_string(),
                u32::try_from(generation).unwrap_or(0),
                &owner.account,
                &owner.incarnation,
                &signing,
                &recipient.account,
                &recipient.incarnation,
            )
        })
        .map_err(|_| AppError::bad_request("the file share does not match the file or the person"))
}

/// `POST /api/files/{id}/share` — share a file with someone here, or change
/// what they may do. Owner only.
#[utoipa::path(
    post,
    path = "/api/files/{id}/share",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = ShareFileRequest,
    responses(
        (status = 204, description = "Shared"),
        (status = 403, description = "Not the owner"),
        (status = 404, description = "No such file or person")
    )
)]
pub async fn share_file(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ShareFileRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    if req.recipient_user_id == user_id {
        return Err(AppError::bad_request("a file is shared with someone else"));
    }
    let domain = state.config.chat_server_name.as_str();
    let sharer = party(&state.pool, user_id, domain).await?;
    let recipient = party(&state.pool, req.recipient_user_id, domain).await?;
    let mut tx = state.pool.begin().await?;
    let generation = match owned_file(&mut tx, file_id, user_id).await {
        Ok((_, generation, _, _)) => generation,
        // An editor the owner lets share: adds people, changes nobody.
        Err(error) => {
            let Some(generation) = editor_may_share(&mut tx, file_id, user_id).await? else {
                return Err(error);
            };
            let taken: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM file_shares WHERE file_id = $1 AND recipient_user_id = $2)
                     OR EXISTS(SELECT 1 FROM files f JOIN collections c ON c.id = f.collection_id
                               WHERE f.id = $1 AND c.owner_user_id = $2)",
            )
            .bind(file_id)
            .bind(req.recipient_user_id)
            .fetch_one(&mut *tx)
            .await?;
            if taken {
                return Err(AppError::conflict("they already have this file"));
            }
            generation
        }
    };
    verify_envelope(
        &req.share_envelope,
        file_id,
        generation,
        &sharer,
        &recipient,
    )?;
    sqlx::query(
        "INSERT INTO file_shares (file_id, sharer_user_id, recipient_user_id, share_envelope,
                                  key_generation, can_edit)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (file_id, recipient_user_id) DO UPDATE SET
             sharer_user_id = EXCLUDED.sharer_user_id,
             share_envelope = EXCLUDED.share_envelope,
             key_generation = EXCLUDED.key_generation,
             can_edit = EXCLUDED.can_edit",
    )
    .bind(file_id)
    .bind(user_id)
    .bind(req.recipient_user_id)
    .bind(&req.share_envelope)
    .bind(generation)
    .bind(req.can_edit)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSharingSettings {
    /// People with edit access may share the file with others.
    pub editors_can_share: bool,
}

/// `PUT /api/files/{id}/sharing` — the owner's sharing settings for a file.
#[utoipa::path(
    put,
    path = "/api/files/{id}/sharing",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = FileSharingSettings,
    responses((status = 204, description = "Saved"), (status = 403, description = "Not the owner"))
)]
pub async fn set_sharing(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<FileSharingSettings>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    owned_file(&mut tx, file_id, user_id).await?;
    sqlx::query("UPDATE files SET editors_can_share = $2 WHERE id = $1")
        .bind(file_id)
        .bind(req.editors_can_share)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn members(pool: &PgPool, file_id: Uuid, domain: &str) -> AppResult<Vec<FileAccessMember>> {
    type Row = (
        Uuid,
        Option<String>,
        String,
        String,
        Option<String>,
        bool,
        i32,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT u.id, u.username, u.account_incarnation_id, u.public_key,
                u.drive_signing_public_key, fs.can_edit, fs.key_generation, fs.created_at
         FROM file_shares fs JOIN users u ON u.id = fs.recipient_user_id
         WHERE fs.file_id = $1 ORDER BY fs.created_at",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                user_id,
                username,
                incarnation,
                public_key,
                signing,
                can_edit,
                key_generation,
                created_at,
            )| {
                FileAccessMember {
                    user_id,
                    account: format!("{}@{domain}", username.unwrap_or_default()),
                    account_incarnation_id: incarnation,
                    drive_public_key: public_key,
                    drive_signing_public_key: signing,
                    can_edit,
                    key_generation,
                    created_at,
                }
            },
        )
        .collect())
}

/// `GET /api/files/{id}/access` — who the file itself is shared with. Owner only.
#[utoipa::path(
    get,
    path = "/api/files/{id}/access",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    responses((status = 200, description = "The file's people", body = FileAccess))
)]
pub async fn file_access(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<FileAccess>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    // The owner, or an editor who may share (to see who has it already).
    let (generation, owner) = match owned_file(&mut tx, file_id, user_id).await {
        Ok((_, generation, _, _)) => (generation, true),
        Err(error) => (
            editor_may_share(&mut tx, file_id, user_id)
                .await?
                .ok_or(error)?,
            false,
        ),
    };
    tx.commit().await?;
    file_access_of(&state, file_id, generation, owner)
        .await
        .map(Json)
}

async fn file_access_of(
    state: &AppState,
    file_id: Uuid,
    generation: i32,
    owner: bool,
) -> AppResult<FileAccess> {
    let editors_can_share: bool =
        sqlx::query_scalar("SELECT editors_can_share FROM files WHERE id = $1")
            .bind(file_id)
            .fetch_one(&state.pool)
            .await?;
    let (public_links, federated_shares) = if owner {
        (
            file_links(&state.pool, file_id).await?,
            federated_members(&state.pool, file_id).await?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(FileAccess {
        key_generation: generation,
        members: members(&state.pool, file_id, &state.config.chat_server_name).await?,
        editors_can_share,
        public_links,
        federated_shares,
    })
}

async fn file_links(pool: &PgPool, file_id: Uuid) -> AppResult<Vec<FileLink>> {
    type Row = (
        Uuid,
        String,
        Option<String>,
        i32,
        Option<OffsetDateTime>,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, token, owner_link_key_envelope, collection_key_epoch, expires_at, created_at
         FROM public_shares WHERE share_type = 'file' AND target_id = $1
           AND (expires_at IS NULL OR expires_at > now())
         ORDER BY created_at",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, token, owner_link_key_envelope, key_generation, expires_at, created_at)| {
                FileLink {
                    id,
                    token,
                    owner_link_key_envelope,
                    key_generation,
                    expires_at,
                    created_at,
                }
            },
        )
        .collect())
}

async fn federated_members(pool: &PgPool, file_id: Uuid) -> AppResult<Vec<FederatedFileMember>> {
    type Row = (Uuid, String, String, String, i32, OffsetDateTime);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, recipient_username, recipient_domain, recipient_incarnation_id,
                key_generation, created_at
         FROM federated_outgoing_file_shares WHERE file_id = $1 ORDER BY created_at",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                recipient_username,
                recipient_server,
                recipient_incarnation_id,
                key_generation,
                created_at,
            )| {
                FederatedFileMember {
                    id,
                    recipient_username,
                    recipient_server,
                    recipient_incarnation_id,
                    key_generation,
                    created_at,
                }
            },
        )
        .collect())
}

/// Check and store envelopes at `generation` for people on other servers:
/// sealed by the owner to the same remote account and incarnation as before.
async fn store_federated_envelopes(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
    generation: i32,
    owner: &Party,
    envelopes: &[FederatedEnvelope],
) -> AppResult<()> {
    for member in envelopes {
        let target: Option<(String, String, String)> = sqlx::query_as(
            "SELECT recipient_username, recipient_domain, recipient_incarnation_id
             FROM federated_outgoing_file_shares WHERE id = $1 AND file_id = $2",
        )
        .bind(member.id)
        .bind(file_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((username, domain, incarnation)) = target else {
            return Err(AppError::conflict("the file's access changed; reload"));
        };
        let recipient = Party {
            account: format!("{username}@{domain}"),
            incarnation,
            signing_public_key: None,
        };
        verify_envelope(
            &member.share_envelope,
            file_id,
            generation,
            owner,
            &recipient,
        )?;
        sqlx::query(
            "UPDATE federated_outgoing_file_shares SET share_envelope = $2, key_generation = $3 WHERE id = $1",
        )
        .bind(member.id)
        .bind(&member.share_envelope)
        .bind(generation)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Check and store link wraps at `generation`.
async fn store_link_envelopes(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
    owner_id: Uuid,
    generation: i32,
    links: &[LinkEnvelope],
) -> AppResult<()> {
    let context = DriveEnvelopeContextV1::public_link_file_key(
        &file_id.to_string(),
        &owner_id.to_string(),
        u32::try_from(generation).map_err(|_| AppError::conflict("invalid key generation"))?,
    )
    .map_err(|_| AppError::bad_request("invalid Drive envelope"))?;
    for link in links {
        validate_envelope(&link.key_envelope, context)?;
        let updated = sqlx::query(
            "UPDATE public_shares SET collection_key_envelope = $3, collection_key_epoch = $4
             WHERE id = $1 AND share_type = 'file' AND target_id = $2",
        )
        .bind(link.id)
        .bind(file_id)
        .bind(&link.key_envelope)
        .bind(generation)
        .execute(&mut **tx)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::conflict("the file's links changed; reload"));
        }
    }
    Ok(())
}

/// Check and store envelopes at `generation` for existing members.
async fn store_envelopes(
    tx: &mut Transaction<'_, Postgres>,
    pool: &PgPool,
    domain: &str,
    file_id: Uuid,
    generation: i32,
    owner: &Party,
    envelopes: &[MemberEnvelope],
) -> AppResult<()> {
    for member in envelopes {
        let recipient = party(pool, member.user_id, domain).await?;
        verify_envelope(
            &member.share_envelope,
            file_id,
            generation,
            owner,
            &recipient,
        )?;
        let updated = sqlx::query(
            "UPDATE file_shares SET share_envelope = $3, key_generation = $4,
                    sharer_user_id = (SELECT c.owner_user_id FROM files f
                                      JOIN collections c ON c.id = f.collection_id WHERE f.id = $1)
             WHERE file_id = $1 AND recipient_user_id = $2",
        )
        .bind(file_id)
        .bind(member.user_id)
        .bind(&member.share_envelope)
        .bind(generation)
        .execute(&mut **tx)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::conflict("the file's access changed; reload"));
        }
    }
    Ok(())
}

/// `PUT /api/files/{id}/shares` — re-seal the shares left at an older key
/// generation (someone else moved the file to a new key). Owner only.
#[utoipa::path(
    put,
    path = "/api/files/{id}/shares",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = ResealRequest,
    responses((status = 204, description = "Re-sealed"))
)]
pub async fn reseal(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ResealRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let domain = state.config.chat_server_name.clone();
    let owner = party(&state.pool, user_id, &domain).await?;
    let mut tx = state.pool.begin().await?;
    let (_, generation, _, _) = owned_file(&mut tx, file_id, user_id).await?;
    store_envelopes(
        &mut tx,
        &state.pool,
        &domain,
        file_id,
        generation,
        &owner,
        &req.members,
    )
    .await?;
    store_link_envelopes(&mut tx, file_id, user_id, generation, &req.public_links).await?;
    store_federated_envelopes(&mut tx, file_id, generation, &owner, &req.federated_shares).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/files/{id}/rotate` — remove people from a shared file: the file
/// moves to a new key (as a folder rotation does), re-sealed for everyone who
/// stays, all at once or not at all. Owner only; the request must name
/// exactly the file's current people.
#[utoipa::path(
    post,
    path = "/api/files/{id}/rotate",
    tag = "files",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = RotateFileAccessRequest,
    responses(
        (status = 200, description = "Moved to the new key", body = FileAccess),
        (status = 409, description = "The file or its people changed; reload")
    )
)]
pub async fn rotate(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RotateFileAccessRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let domain = state.config.chat_server_name.clone();
    let owner = party(&state.pool, user_id, &domain).await?;
    let mut tx = state.pool.begin().await?;
    let (collection_id, generation, folder_epoch, revision) =
        owned_file(&mut tx, file_id, user_id).await?;
    if generation != req.from_generation {
        return Err(AppError::conflict("the file's key changed; reload"));
    }
    let current: Vec<Uuid> =
        sqlx::query_scalar("SELECT recipient_user_id FROM file_shares WHERE file_id = $1")
            .bind(file_id)
            .fetch_all(&mut *tx)
            .await?;
    let kept: Vec<Uuid> = req.members.iter().map(|m| m.user_id).collect();
    let current_links: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public_shares WHERE share_type = 'file' AND target_id = $1",
    )
    .bind(file_id)
    .fetch_all(&mut *tx)
    .await?;
    let kept_links: Vec<Uuid> = req.public_links.iter().map(|l| l.id).collect();
    let current_federated: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM federated_outgoing_file_shares WHERE file_id = $1")
            .bind(file_id)
            .fetch_all(&mut *tx)
            .await?;
    let kept_federated: Vec<Uuid> = req.federated_shares.iter().map(|f| f.id).collect();
    if !same_membership(&current, &kept, &req.removed)
        || !same_membership(&current_links, &kept_links, &req.removed_links)
        || !same_membership(&current_federated, &kept_federated, &req.removed_federated)
        || (req.removed.is_empty()
            && req.removed_links.is_empty()
            && req.removed_federated.is_empty())
    {
        return Err(AppError::conflict("the file's access changed; reload"));
    }
    let next = generation
        .checked_add(1)
        .ok_or_else(|| AppError::conflict("file key generations exhausted"))?;
    let (file_text, next_u32) = (file_id.to_string(), next as u32);
    let invalid = |_| AppError::bad_request("invalid Drive envelope");
    validate_envelope(
        &req.file_key_envelope,
        DriveEnvelopeContextV1::file_key(
            &file_text,
            &collection_id.to_string(),
            folder_epoch as u32,
            next_u32,
        )
        .map_err(invalid)?,
    )?;
    validate_envelope(
        &req.metadata_envelope,
        DriveEnvelopeContextV1::file_metadata(&file_text, next_u32, revision as u64)
            .map_err(invalid)?,
    )?;
    validate_envelope(
        &req.previous_key_envelope,
        DriveEnvelopeContextV1::previous_file_key(&file_text, next_u32).map_err(invalid)?,
    )?;
    sqlx::query(
        "INSERT INTO file_key_history (file_id, generation, previous_key_envelope,
                                       previous_metadata_envelope, previous_metadata_revision)
         SELECT $1, $2, $3, metadata_envelope, metadata_revision FROM files WHERE id = $1",
    )
    .bind(file_id)
    .bind(next)
    .bind(&req.previous_key_envelope)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE files SET key_epoch = $2, key_generation = $3, file_key_envelope = $4,
                metadata_envelope = $5
         WHERE id = $1",
    )
    .bind(file_id)
    .bind(folder_epoch)
    .bind(next)
    .bind(&req.file_key_envelope)
    .bind(&req.metadata_envelope)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM file_shares WHERE file_id = $1 AND recipient_user_id = ANY($2)")
        .bind(file_id)
        .bind(&req.removed)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM public_shares WHERE share_type = 'file' AND target_id = $1 AND id = ANY($2)",
    )
    .bind(file_id)
    .bind(&req.removed_links)
    .execute(&mut *tx)
    .await?;
    store_link_envelopes(&mut tx, file_id, user_id, next, &req.public_links).await?;
    sqlx::query("DELETE FROM federated_outgoing_file_shares WHERE file_id = $1 AND id = ANY($2)")
        .bind(file_id)
        .bind(&req.removed_federated)
        .execute(&mut *tx)
        .await?;
    store_federated_envelopes(&mut tx, file_id, next, &owner, &req.federated_shares).await?;
    store_envelopes(
        &mut tx,
        &state.pool,
        &domain,
        file_id,
        next,
        &owner,
        &req.members,
    )
    .await?;
    tx.commit().await?;
    // Live sessions reconnect under the new key; the removed are refused.
    state.hub.close_room(&file_id.to_string());
    Ok(Json(file_access_of(&state, file_id, next, true).await?).into_response())
}

/// `GET /api/shared-files` — files shared with you by themselves, with the
/// envelope and the owner's identity keys to open and check them. A file in
/// the trash is left out.
#[utoipa::path(
    get,
    path = "/api/shared-files",
    tag = "files",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Files shared with you", body = Vec<SharedFile>))
)]
pub async fn shared_with_me(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<SharedFile>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let domain = state.config.chat_server_name.as_str();
    let files = file_rows(
        &state.pool,
        "f.id IN (SELECT fs.file_id FROM file_shares fs
                  JOIN files sf ON sf.id = fs.file_id
                  JOIN collections sc ON sc.id = sf.collection_id AND sc.deleted_at IS NULL
                  WHERE fs.recipient_user_id = $1)",
        user_id,
        user_id,
    )
    .await?;
    type Row = (
        Uuid,
        String,
        bool,
        i32,
        bool,
        OffsetDateTime,
        Uuid,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        String,
        Option<String>,
        bool,
    );
    let shares: Vec<Row> = sqlx::query_as(
        "SELECT fs.file_id, fs.share_envelope, fs.can_edit, fs.key_generation,
                f.key_epoch = c.key_epoch, fs.created_at, c.owner_user_id,
                o.username, o.account_incarnation_id, o.drive_signing_public_key,
                h.previous_metadata_envelope, h.previous_metadata_revision,
                s.username, s.account_incarnation_id, s.drive_signing_public_key,
                f.editors_can_share
         FROM file_shares fs
         JOIN files f ON f.id = fs.file_id
         JOIN collections c ON c.id = f.collection_id
         JOIN users o ON o.id = c.owner_user_id
         JOIN users s ON s.id = fs.sharer_user_id
         -- Behind: the metadata of the share's generation, recorded when the
         -- file left it.
         LEFT JOIN file_key_history h
                ON h.file_id = fs.file_id AND h.generation = fs.key_generation + 1
               AND fs.key_generation < f.key_generation
         WHERE fs.recipient_user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut by_file: BTreeMap<String, Row> = shares
        .into_iter()
        .map(|row| (row.0.to_string(), row))
        .collect();
    Ok(Json(
        files
            .into_iter()
            .filter_map(|file| {
                let (
                    _,
                    envelope,
                    can_edit,
                    key_generation,
                    folder_key_current,
                    shared_at,
                    owner,
                    username,
                    incarnation,
                    signing,
                    metadata_envelope,
                    metadata_revision,
                    sharer_username,
                    sharer_incarnation,
                    sharer_signing,
                    editors_can_share,
                ) = by_file.remove(&file.id)?;
                Some(SharedFile {
                    file,
                    share_envelope: envelope,
                    can_edit,
                    key_generation,
                    folder_key_current,
                    owner_user_id: owner,
                    owner_account: format!("{}@{domain}", username?),
                    owner_incarnation_id: incarnation,
                    owner_signing_public_key: signing?,
                    sharer_account: format!("{}@{domain}", sharer_username?),
                    sharer_incarnation_id: sharer_incarnation,
                    sharer_signing_public_key: sharer_signing?,
                    editors_can_share,
                    shared_at,
                    metadata_at_share: metadata_envelope
                        .zip(metadata_revision)
                        .map(|(envelope, revision)| MetadataAtShare { envelope, revision }),
                })
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PendingFileShare {
    pub file_id: Uuid,
    pub collection_id: Uuid,
}

/// `GET /api/file-shares/pending` — your files whose shares wait for you:
/// someone else moved the file to a new key, or the folder moved past the
/// key the file is wrapped at. Your app re-keys the file if needed and
/// re-seals the shares (`PUT /api/files/{id}/shares`).
#[utoipa::path(
    get,
    path = "/api/file-shares/pending",
    tag = "files",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Files with shares to bring up to date", body = Vec<PendingFileShare>))
)]
pub async fn pending(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<PendingFileShare>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT f.id, f.collection_id
         FROM files f JOIN collections c ON c.id = f.collection_id AND c.deleted_at IS NULL
         WHERE c.owner_user_id = $1 AND f.deleted_at IS NULL
           AND (EXISTS (SELECT 1 FROM file_shares fs
                        WHERE fs.file_id = f.id
                          AND (fs.key_generation < f.key_generation OR f.key_epoch < c.key_epoch))
             OR EXISTS (SELECT 1 FROM public_shares ps
                        WHERE ps.share_type = 'file' AND ps.target_id = f.id
                          AND (ps.collection_key_epoch < f.key_generation OR f.key_epoch < c.key_epoch))
             OR EXISTS (SELECT 1 FROM federated_outgoing_file_shares fo
                        WHERE fo.file_id = f.id
                          AND (fo.key_generation < f.key_generation OR f.key_epoch < c.key_epoch)))",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(file_id, collection_id)| PendingFileShare {
                file_id,
                collection_id,
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SharedByMeItem {
    /// The folder, or the file's folder.
    pub collection_id: Uuid,
    /// Set for a file shared by itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<Uuid>,
    /// People on this server.
    pub people: i64,
    /// People on other servers.
    pub other_servers: i64,
    /// Public links.
    pub links: i64,
}

/// `GET /api/shared-by-me` — what you share: your folders shared with people
/// (here or on other servers) or by link, and your files shared by
/// themselves, with how many of each. Names stay encrypted; the app decrypts
/// them from your own folder listings. Folders and files in the trash are
/// left out.
#[utoipa::path(
    get,
    path = "/api/shared-by-me",
    tag = "files",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "What you share", body = Vec<SharedByMeItem>))
)]
pub async fn shared_by_me(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<SharedByMeItem>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    type Row = (Uuid, Option<Uuid>, i64, i64, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT c.id, NULL::uuid,
                (SELECT count(*) FROM collection_shares cs WHERE cs.collection_id = c.id),
                (SELECT count(*) FROM federated_outgoing_shares fo WHERE fo.collection_id = c.id),
                (SELECT count(*) FROM public_shares ps
                  WHERE ps.share_type = 'collection' AND ps.target_id = c.id
                    AND (ps.expires_at IS NULL OR ps.expires_at > now()))
         FROM collections c
         WHERE c.owner_user_id = $1 AND c.deleted_at IS NULL
         UNION ALL
         SELECT f.collection_id, f.id,
                (SELECT count(*) FROM file_shares fs WHERE fs.file_id = f.id),
                (SELECT count(*) FROM federated_outgoing_file_shares fo WHERE fo.file_id = f.id),
                (SELECT count(*) FROM public_shares ps
                  WHERE ps.share_type = 'file' AND ps.target_id = f.id
                    AND (ps.expires_at IS NULL OR ps.expires_at > now()))
         FROM files f JOIN collections c ON c.id = f.collection_id
         WHERE c.owner_user_id = $1 AND c.deleted_at IS NULL AND f.deleted_at IS NULL
           AND (EXISTS (SELECT 1 FROM file_shares fs WHERE fs.file_id = f.id)
             OR EXISTS (SELECT 1 FROM public_shares ps WHERE ps.share_type = 'file' AND ps.target_id = f.id)
             OR EXISTS (SELECT 1 FROM federated_outgoing_file_shares fo WHERE fo.file_id = f.id))",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .filter(|(_, _, people, other, links)| people + other + links > 0)
            .map(
                |(collection_id, file_id, people, other_servers, links)| SharedByMeItem {
                    collection_id,
                    file_id,
                    people,
                    other_servers,
                    links,
                },
            )
            .collect(),
    ))
}
