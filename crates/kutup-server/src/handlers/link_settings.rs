//! A public link's settings, as Proton Drive's link settings dialog
//! (docs/plans/drive-link-password.md): its password and its expiry, set by
//! the link's owner; and the password's salt and cost a viewer derives with.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::drive_envelope::{DriveEnvelopeContextV1, DriveEnvelopePurpose};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::files::validate_envelope;
use crate::middleware::AuthAccount;
use crate::AppState;

/// A password for a link: what the server keeps (the owner's client made
/// it; the server never sees the password).
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkPasswordSetting {
    /// 16 bytes, base64.
    salt: String,
    /// Argon2id passes.
    operations: i64,
    /// Argon2id memory in bytes.
    memory: i64,
    /// The proof's verifier (32 bytes, base64).
    verifier: String,
    /// The link key under the password wrap key (purpose 14, at the new key
    /// revision).
    link_key_envelope: String,
    /// The URL secret and password for the owner (purpose 15).
    owner_secret_envelope: String,
}

/// `PUT /api/v1/drive/public-links/{token}/password` body.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetLinkPasswordRequest {
    /// The link's key revision this change starts from (compare-and-swap).
    from_key_revision: i32,
    /// The folder key's epoch, or the file key's generation, the target key
    /// below is sealed at: the current one.
    key_epoch: i32,
    /// The target's key under the link's new key (purpose 5 or 11).
    target_key_envelope: String,
    /// The link's new key for its owner (purpose 9).
    owner_link_key_envelope: String,
    /// The new password, or null to remove it (the link key is then the
    /// URL secret again).
    password: Option<LinkPasswordSetting>,
}

/// The link's key revision after the change.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkKeyRevision {
    key_revision: i32,
}

fn changed() -> AppError {
    AppError::conflict("the link changed; reload")
}

/// Checks a base64 value is canonical and `len` bytes.
fn bytes_of(value: &str, len: usize) -> AppResult<()> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| bytes.len() == len && STANDARD.encode(bytes) == value)
        .map(|_| ())
        .ok_or_else(|| AppError::bad_request("invalid link password"))
}

/// `PUT /api/v1/drive/public-links/{token}/password` — sets, changes or removes
/// a link's password. The owner re-seals the target's key under a new link
/// key at its current epoch; the link's key revision rises, so a re-key
/// sealed under the old link key is refused.
#[utoipa::path(
    put,
    path = "/api/v1/drive/public-links/{token}/password",
    tag = "drive",
    security(("BearerAuth" = [])),
    params(("token" = String, Path, description = "The link's token")),
    request_body = SetLinkPasswordRequest,
    responses(
        (status = 200, description = "Changed", body = LinkKeyRevision),
        (status = 404, description = "No such link of this account"),
        (status = 409, description = "The link or its target changed; reload"),
    )
)]
pub async fn set_password(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(token): Path<String>,
    Json(req): Json<SetLinkPasswordRequest>,
) -> AppResult<Json<LinkKeyRevision>> {
    let owner =
        Uuid::parse_str(&user.account_id).map_err(|_| AppError::internal("invalid user id"))?;
    let mut tx = state.pool.begin().await?;
    // What the link reaches, unlocked: the target's row is locked first, as
    // the folder and file re-keys lock it before the link rows (one order,
    // no deadlock).
    let row: Option<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT id, share_type, target_id FROM drive_public_shares
          WHERE token = $1 AND owner_account_id = $2 AND owner_removed_at IS NULL",
    )
    .bind(&token)
    .bind(owner)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, share_type, target)) = row else {
        return Err(AppError::not_found("not found"));
    };
    // The target's key now, locked against a re-key until this commits.
    let current: Option<i32> = match share_type.as_str() {
        "collection" => {
            sqlx::query_scalar(
                "SELECT key_epoch FROM drive_collections
                  WHERE id = $1 AND owner_account_id = $2 AND deleted_at IS NULL
                  FOR UPDATE",
            )
            .bind(target)
            .bind(owner)
            .fetch_optional(&mut *tx)
            .await?
        }
        _ => {
            sqlx::query_scalar(
                "SELECT f.key_generation FROM drive_files f
                   JOIN drive_collections c ON c.id = f.collection_id
                  WHERE f.id = $1 AND c.owner_account_id = $2
                    AND f.deleted_at IS NULL AND c.deleted_at IS NULL
                  FOR UPDATE OF f",
            )
            .bind(target)
            .bind(owner)
            .fetch_optional(&mut *tx)
            .await?
        }
    };
    let Some(current) = current else {
        return Err(AppError::not_found("not found"));
    };
    // Then the link's row.
    let revision: Option<i32> = sqlx::query_scalar(
        "SELECT key_revision FROM drive_public_shares
          WHERE id = $1 AND owner_removed_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(revision) = revision else {
        return Err(AppError::not_found("not found"));
    };
    if revision != req.from_key_revision || current != req.key_epoch {
        return Err(changed());
    }
    let epoch = u32::try_from(current).map_err(|_| AppError::conflict("invalid key epoch"))?;
    let (target_s, owner_s, id_s) = (target.to_string(), owner.to_string(), id.to_string());
    let bad = |_| AppError::bad_request("invalid Drive envelope");
    let target_context = if share_type == "collection" {
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::PublicLinkCollectionKey,
            epoch,
            1,
            &target_s,
            &owner_s,
        )
    } else {
        DriveEnvelopeContextV1::public_link_file_key(&target_s, &owner_s, epoch)
    }
    .map_err(bad)?;
    validate_envelope(&req.target_key_envelope, target_context)?;
    let drive_generation = crate::account_roots::drive_generation(&mut *tx, owner).await?;
    validate_envelope(
        &req.owner_link_key_envelope,
        DriveEnvelopeContextV1::owner_link_key(&id_s, &owner_s, drive_generation).map_err(bad)?,
    )?;
    let next = revision
        .checked_add(1)
        .ok_or_else(|| AppError::conflict("too many link key changes"))?;
    let protection = match &req.password {
        None => None,
        Some(p) => {
            bytes_of(&p.salt, kutup_crypto::link_password::SALT_LEN)?;
            bytes_of(&p.verifier, kutup_crypto::link_password::PROOF_LEN)?;
            let operations = u64::try_from(p.operations)
                .map_err(|_| AppError::bad_request("invalid link password cost"))?;
            let memory = u64::try_from(p.memory)
                .map_err(|_| AppError::bad_request("invalid link password cost"))?;
            kutup_crypto::link_password::check_params(operations, memory)
                .map_err(|_| AppError::bad_request("invalid link password cost"))?;
            validate_envelope(
                &p.link_key_envelope,
                DriveEnvelopeContextV1::link_password_key(
                    &id_s,
                    &owner_s,
                    u32::try_from(next).map_err(|_| changed())?,
                )
                .map_err(bad)?,
            )?;
            validate_envelope(
                &p.owner_secret_envelope,
                DriveEnvelopeContextV1::owner_link_secret(&id_s, &owner_s, drive_generation)
                    .map_err(bad)?,
            )?;
            Some(p)
        }
    };
    let (salt, operations, memory, verifier, link_key_envelope, owner_secret_envelope) =
        match protection {
            Some(p) => (
                Some(p.salt.as_str()),
                // In range: check_params bounds both well inside an i32.
                Some(p.operations as i32),
                Some(p.memory as i32),
                Some(p.verifier.as_str()),
                Some(p.link_key_envelope.as_str()),
                Some(p.owner_secret_envelope.as_str()),
            ),
            None => (None, None, None, None, None, None),
        };
    sqlx::query(
        "UPDATE drive_public_shares
            SET key_revision = $2,
                collection_key_envelope = kutup_unb64($3),
                collection_key_epoch = $4,
                owner_link_key_envelope = kutup_unb64($5),
                password_salt = kutup_unb64($6),
                password_operations = $7,
                password_memory = $8,
                password_verifier = kutup_unb64($9),
                password_link_key_envelope = kutup_unb64($10),
                owner_secret_envelope = kutup_unb64($11)
          WHERE id = $1",
    )
    .bind(id)
    .bind(next)
    .bind(&req.target_key_envelope)
    .bind(current)
    .bind(&req.owner_link_key_envelope)
    .bind(salt)
    .bind(operations)
    .bind(memory)
    .bind(verifier)
    .bind(link_key_envelope)
    .bind(owner_secret_envelope)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(LinkKeyRevision { key_revision: next }))
}

/// `PUT /api/v1/drive/public-links/{token}/expiry` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetLinkExpiryRequest {
    /// When the link stops opening (RFC 3339), or null for never. In the
    /// future, and at most the site's `drive.public_link_max_expiry_days`
    /// ahead.
    #[serde(with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
}

/// `PUT /api/v1/drive/public-links/{token}/expiry` — sets or clears when a link
/// stops opening.
#[utoipa::path(
    put,
    path = "/api/v1/drive/public-links/{token}/expiry",
    tag = "drive",
    security(("BearerAuth" = [])),
    params(("token" = String, Path, description = "The link's token")),
    request_body = SetLinkExpiryRequest,
    responses(
        (status = 204, description = "Changed"),
        (status = 400, description = "In the past, or further ahead than the site allows"),
        (status = 404, description = "No such link of this account"),
    )
)]
pub async fn set_expiry(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(token): Path<String>,
    Json(req): Json<SetLinkExpiryRequest>,
) -> AppResult<Response> {
    let owner =
        Uuid::parse_str(&user.account_id).map_err(|_| AppError::internal("invalid user id"))?;
    match req.expires_at {
        Some(at) => check_expiry(&state, at).await?,
        // Under a cap every link expires.
        None if max_expiry_days(&state).await? > 0 => {
            return Err(AppError::bad_request("this server's links must expire")
                .with_details(serde_json::json!({ "code": "expiryRequired" })))
        }
        None => {}
    }
    let updated = sqlx::query(
        "UPDATE drive_public_shares SET expires_at = $3
          WHERE token = $1 AND owner_account_id = $2 AND owner_removed_at IS NULL",
    )
    .bind(&token)
    .bind(owner)
    .bind(req.expires_at)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::not_found("not found"));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The site's cap on how far ahead a link's expiry may be, in days; 0: none.
pub(crate) async fn max_expiry_days(state: &AppState) -> AppResult<i64> {
    Ok(crate::site_settings::DRIVE_PUBLIC_LINK_MAX_EXPIRY_DAYS
        .load(&state.pool)
        .await?)
}

/// An expiry is in the future and, under a cap, at most that far ahead.
pub(crate) async fn check_expiry(state: &AppState, at: OffsetDateTime) -> AppResult<()> {
    let days = max_expiry_days(state).await?;
    let now = OffsetDateTime::now_utc();
    if at <= now {
        return Err(AppError::bad_request("expiresAt is in the past")
            .with_details(serde_json::json!({ "code": "expiryInPast" })));
    }
    if days > 0 && at > now + time::Duration::days(days) {
        return Err(AppError::bad_request("expiresAt is too far ahead")
            .with_details(serde_json::json!({ "code": "expiryTooFar", "maxDays": days })));
    }
    Ok(())
}

/// A protected link's password salt and cost.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkPasswordParams {
    /// The link's id: the derivation is bound to it.
    link_id: Uuid,
    salt: String,
    operations: i32,
    memory: i32,
}

/// `GET /api/v1/drive/public-links/{token}/password` — what a viewer derives
/// a protected link's proof with. Anonymous; 404 for a link without a
/// password.
#[utoipa::path(
    get,
    path = "/api/v1/drive/public-links/{token}/password",
    tag = "drive",
    params(("token" = String, Path, description = "Share token (the capability)")),
    responses(
        (status = 200, description = "Salt and cost", body = LinkPasswordParams),
        (status = 404, description = "No such link, or it has no password"),
        (status = 410, description = "Expired"),
    )
)]
pub async fn password_params(
    State(state): State<AppState>,
    viewer: crate::middleware::Viewer,
    Path(token): Path<String>,
) -> AppResult<Response> {
    crate::handlers::link_reports::ensure_link_up(&state.pool, &token, viewer.signed_in).await?;
    let row: Option<(Uuid, Option<OffsetDateTime>, String, i32, i32)> = sqlx::query_as(
        "SELECT id, expires_at, kutup_b64(password_salt), password_operations, password_memory
           FROM drive_public_shares WHERE token = $1 AND password_salt IS NOT NULL",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await?;
    let Some((link_id, expires_at, salt, operations, memory)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if expires_at.is_some_and(|exp| OffsetDateTime::now_utc() > exp) {
        return Err(AppError::new(StatusCode::GONE, "link expired"));
    }
    Ok(Json(LinkPasswordParams {
        link_id,
        salt,
        operations,
        memory,
    })
    .into_response())
}
