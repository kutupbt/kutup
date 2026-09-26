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
    pub owner_user_id: Uuid,
    pub owner_account: String,
    pub owner_incarnation_id: String,
    pub owner_signing_public_key: String,
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
    let owner = party(&state.pool, user_id, domain).await?;
    let recipient = party(&state.pool, req.recipient_user_id, domain).await?;
    let mut tx = state.pool.begin().await?;
    let (_, generation, _, _) = owned_file(&mut tx, file_id, user_id).await?;
    verify_envelope(&req.share_envelope, file_id, generation, &owner, &recipient)?;
    sqlx::query(
        "INSERT INTO file_shares (file_id, sharer_user_id, recipient_user_id, share_envelope,
                                  key_generation, can_edit)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (file_id, recipient_user_id) DO UPDATE SET
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
    let (_, generation, _, _) = owned_file(&mut tx, file_id, user_id).await?;
    tx.commit().await?;
    Ok(Json(FileAccess {
        key_generation: generation,
        members: members(&state.pool, file_id, &state.config.chat_server_name).await?,
    }))
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
            "UPDATE file_shares SET share_envelope = $3, key_generation = $4
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
    if !same_membership(&current, &kept, &req.removed) || req.removed.is_empty() {
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
    sqlx::query("INSERT INTO file_key_history (file_id, generation, previous_key_envelope) VALUES ($1, $2, $3)")
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
    Ok(Json(FileAccess {
        key_generation: next,
        members: members(&state.pool, file_id, &domain).await?,
    })
    .into_response())
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
    )
    .await?;
    type Row = (
        Uuid,
        String,
        bool,
        i32,
        OffsetDateTime,
        Uuid,
        Option<String>,
        String,
        Option<String>,
    );
    let shares: Vec<Row> = sqlx::query_as(
        "SELECT fs.file_id, fs.share_envelope, fs.can_edit, fs.key_generation, fs.created_at,
                c.owner_user_id, o.username, o.account_incarnation_id, o.drive_signing_public_key
         FROM file_shares fs
         JOIN files f ON f.id = fs.file_id
         JOIN collections c ON c.id = f.collection_id
         JOIN users o ON o.id = c.owner_user_id
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
                    shared_at,
                    owner,
                    username,
                    incarnation,
                    signing,
                ) = by_file.remove(&file.id)?;
                Some(SharedFile {
                    file,
                    share_envelope: envelope,
                    can_edit,
                    key_generation,
                    owner_user_id: owner,
                    owner_account: format!("{}@{domain}", username?),
                    owner_incarnation_id: incarnation,
                    owner_signing_public_key: signing?,
                    shared_at,
                })
            })
            .collect(),
    ))
}
