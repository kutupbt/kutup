//! Kutup Pass vault secrets (docs/plans/pass.md, "Vault secrets").
//!
//! Each person may keep, per vault they can open, the vault's password and
//! key file sealed under their master key (`kutup_crypto::pass_vault`), so
//! Kutup Pass and `kutup sync` unlock vaults with the Kutup sign-in. The
//! server stores the envelopes and checks only their public header; whoever
//! loses access to a vault loses its record too. It also keeps the PIN lock
//! (below).

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_file, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

/// The largest envelope kept: a password and a key file at their limits,
/// with the envelope's header.
const MAX_ENVELOPE_BYTES: usize = 4096 + 512;

/// One vault's sealed secret.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultSecretRow {
    file_id: String,
    /// Base64 of the account envelope (purpose `PassVaultSecret`).
    envelope: String,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PutVaultSecretRequest {
    /// Base64 of the account envelope (purpose `PassVaultSecret`).
    envelope: String,
}

/// `GET /api/pass/vault-secrets` — the caller's vault secrets, for vaults
/// they can still open.
#[utoipa::path(
    get,
    path = "/api/pass/vault-secrets",
    tag = "pass",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's sealed vault secrets", body = Vec<VaultSecretRow>))
)]
pub async fn list_vault_secrets(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(Uuid, Vec<u8>, OffsetDateTime, bool)> = sqlx::query_as(
        "SELECT s.file_id, s.envelope, s.updated_at, f.deleted_at IS NOT NULL
           FROM pass_vault_secrets s JOIN files f ON f.id = s.file_id
          WHERE s.user_id = $1
          ORDER BY s.file_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (file_id, envelope, updated_at, trashed) in rows {
        // A vault in the trash keeps its secret for a restore, unlisted.
        if trashed {
            continue;
        }
        // Out of reach now (unshared, perhaps only for a moment): hidden,
        // never deleted on a read; a failed check fails the request. A record
        // goes only with the vault (purged: ON DELETE CASCADE) or when its
        // owner forgets it (the same fix as #171).
        if !can_access_file(&state.pool, user_id, file_id).await? {
            continue;
        }
        out.push(VaultSecretRow {
            file_id: file_id.to_string(),
            envelope: STANDARD.encode(envelope),
            updated_at,
        });
    }
    Ok(Json(out).into_response())
}

/// `PUT /api/pass/vault-secrets/{fileId}` — keep (or replace) the caller's
/// secret for a vault they can open.
#[utoipa::path(
    put,
    path = "/api/pass/vault-secrets/{fileId}",
    tag = "pass",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "The vault's file id")),
    request_body = PutVaultSecretRequest,
    responses(
        (status = 204, description = "Stored"),
        (status = 400, description = "Not this account's vault secret"),
        (status = 404, description = "No such vault, or no access to it")
    )
)]
pub async fn put_vault_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    Json(req): Json<PutVaultSecretRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let live: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM files WHERE id = $1 AND deleted_at IS NULL")
            .bind(file_id)
            .fetch_optional(&state.pool)
            .await?;
    if live.is_none() || !can_access_file(&state.pool, user_id, file_id).await? {
        return Err(AppError::not_found("not found"));
    }
    // What the account's keys are bound to (docs/plans/account-identity.md).
    let mut tx = state.pool.begin().await?;
    let binding: String =
        sqlx::query_scalar("SELECT COALESCE(key_binding, '') FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    let envelope = checked_envelope(&req.envelope, &binding, file_id)?;
    sqlx::query(
        "INSERT INTO pass_vault_secrets (user_id, file_id, envelope) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, file_id) DO UPDATE SET envelope = $3, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(file_id)
    .bind(&envelope)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The envelope in `b64` if it is canonical base64 of at most
/// [`MAX_ENVELOPE_BYTES`], a Pass vault secret, bound to `binding` and sealed
/// for vault `file_id`.
fn checked_envelope(b64: &str, binding: &str, file_id: Uuid) -> AppResult<Vec<u8>> {
    let envelope = STANDARD
        .decode(b64)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == b64)
        .ok_or_else(|| AppError::bad_request("envelope is not canonical base64"))?;
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(AppError::bad_request("envelope is too large"));
    }
    let header = account_envelope::inspect(&envelope)
        .map_err(|_| AppError::bad_request("envelope is not an account envelope"))?;
    if header.purpose != AccountEnvelopePurpose::PassVaultSecret {
        return Err(AppError::bad_request(
            "envelope is not this account's vault secret",
        ));
    }
    if Some(header.canonical_login_email) != account_envelope::canonical_login_email(binding).ok() {
        return Err(AppError::bad_request(
            "envelope is not this account's vault secret",
        ));
    }
    if header.object_id != file_id.as_bytes() {
        return Err(AppError::bad_request("envelope is not this vault's secret"));
    }
    Ok(envelope)
}

/// `DELETE /api/pass/vault-secrets/{fileId}` — forget the caller's secret
/// for a vault.
#[utoipa::path(
    delete,
    path = "/api/pass/vault-secrets/{fileId}",
    tag = "pass",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "The vault's file id")),
    responses((status = 204, description = "Forgotten (or there was none)"))
)]
pub async fn delete_vault_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    sqlx::query("DELETE FROM pass_vault_secrets WHERE user_id = $1 AND file_id = $2")
        .bind(user_id)
        .bind(file_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── The PIN lock (docs/plans/pass.md, "The PIN") ────────────────────────────
//
// As Proton Pass's PIN lock: a six-digit PIN per account, kept here as a
// bcrypt hash and checked here only. Like the password lock it releases no
// key: the app already holds the vault's kept key and opens it after a yes.
// What the server check adds is the limit: a PIN can be tried three times
// per sign-in, and the third wrong one in a row ends that sign-in (every
// session of it), so neither someone at a locked tab nor a stolen access
// token can work through the PINs. The count is per sign-in, each try is
// reserved before the check (parallel tries get no more), only that
// sign-in's right PIN clears it, and it is never reset on a lockout: a new
// sign-in, with the password, starts its own. Setting or removing the PIN
// takes the account password.

/// Wrong PINs in a row before the sign-in ends.
pub const PIN_ATTEMPTS: i16 = 3;

fn valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit())
}

/// Whether the account has a PIN.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PinStatus {
    set: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetPinRequest {
    /// The account password's login key, as for `/api/user/reauth`.
    login_key: String,
    /// Six digits.
    pin: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemovePinRequest {
    /// The account password's login key, as for `/api/user/reauth`.
    login_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPinRequest {
    pin: String,
}

/// Why a PIN was refused: `wrongPin` (with the tries left), `signedOut`
/// (that was the last one; the sign-in has ended) or `noPin` (removed,
/// perhaps on another device).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PinRefusal {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts_left: Option<i16>,
}

fn refusal(status: StatusCode, error: &'static str, attempts_left: Option<i16>) -> Response {
    (
        status,
        Json(PinRefusal {
            error,
            attempts_left,
        }),
    )
        .into_response()
}

/// `GET /api/pass/pin` — whether the account has a PIN.
#[utoipa::path(
    get,
    path = "/api/pass/pin",
    tag = "pass",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Whether a PIN is set", body = PinStatus))
)]
pub async fn pin_status(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let set: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pass_pins WHERE user_id = $1)")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    Ok(Json(PinStatus { set }).into_response())
}

/// `PUT /api/pass/pin` — sets or changes the PIN, with the account password.
#[utoipa::path(
    put,
    path = "/api/pass/pin",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = SetPinRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 400, description = "Not six digits"),
        (status = 401, description = "Wrong account password"),
        (status = 429, description = "Too many failed attempts (the sign-in lockout)")
    )
)]
pub async fn set_pin(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<SetPinRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    if !valid_pin(&req.pin) {
        return Err(AppError::bad_request("the PIN must be six digits"));
    }
    crate::handlers::auth::verify_account_login_key(&state, &user, &req.login_key).await?;
    let user_id = trusted_uuid(&user.user_id)?;
    let hash = bcrypt::hash(&req.pin, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::internal(format!("hash PIN: {e}")))?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO pass_pins (user_id, pin_hash) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET pin_hash = $2, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    // A new PIN, with the password: every sign-in's tries start again.
    sqlx::query("DELETE FROM pass_pin_failures WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/pass/pin` — removes the PIN, with the account password.
#[utoipa::path(
    delete,
    path = "/api/pass/pin",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = RemovePinRequest,
    responses(
        (status = 204, description = "Removed (or there was none)"),
        (status = 401, description = "Wrong account password"),
        (status = 429, description = "Too many failed attempts (the sign-in lockout)")
    )
)]
pub async fn remove_pin(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<RemovePinRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    crate::handlers::auth::verify_account_login_key(&state, &user, &req.login_key).await?;
    let user_id = trusted_uuid(&user.user_id)?;
    sqlx::query("DELETE FROM pass_pins WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/pass/pin/verify` — checks the PIN.
#[utoipa::path(
    post,
    path = "/api/pass/pin/verify",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = VerifyPinRequest,
    responses(
        (status = 204, description = "The PIN is right"),
        (status = 403, description = "Wrong (`wrongPin`, with the tries left), or the last try: the sign-in has ended (`signedOut`)", body = PinRefusal),
        (status = 404, description = "The account has no PIN (`noPin`)", body = PinRefusal)
    )
)]
pub async fn verify_pin(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<VerifyPinRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let hash: Option<String> =
        sqlx::query_scalar("SELECT pin_hash FROM pass_pins WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(hash) = hash else {
        return Ok(refusal(StatusCode::NOT_FOUND, "noPin", None));
    };
    // The sign-in this session belongs to (the root of its tree).
    let sign_in: Uuid = sqlx::query_scalar(
        "SELECT COALESCE(parent_session_id, id) FROM auth_sessions
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(user.session.session_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("session ended"))?;
    // Reserve a try first: of any number of tries at once, at most the
    // remaining ones reach the check.
    let reserved: Option<i16> = sqlx::query_scalar(
        "INSERT INTO pass_pin_failures (sign_in_id, user_id, failures) VALUES ($1, $2, 1)
         ON CONFLICT (sign_in_id) DO UPDATE SET failures = pass_pin_failures.failures + 1
         WHERE pass_pin_failures.failures < $3
         RETURNING failures",
    )
    .bind(sign_in)
    .bind(user_id)
    .bind(PIN_ATTEMPTS)
    .fetch_optional(&state.pool)
    .await?;
    let Some(failures) = reserved else {
        // This sign-in has used its tries (a parallel try ended it).
        crate::sessions::sign_out(&state.pool, user.session.session_id).await?;
        return Ok(refusal(StatusCode::FORBIDDEN, "signedOut", Some(0)));
    };
    if valid_pin(&req.pin) && bcrypt::verify(&req.pin, &hash).unwrap_or(false) {
        sqlx::query("DELETE FROM pass_pin_failures WHERE sign_in_id = $1")
            .bind(sign_in)
            .execute(&state.pool)
            .await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    tracing::warn!(user_id = %user_id, failures, "wrong Pass PIN");
    if failures >= PIN_ATTEMPTS {
        crate::sessions::sign_out(&state.pool, user.session.session_id).await?;
        tracing::warn!(user_id = %user_id, "Pass PIN tries used up; the sign-in was ended");
        return Ok(refusal(StatusCode::FORBIDDEN, "signedOut", Some(0)));
    }
    Ok(refusal(
        StatusCode::FORBIDDEN,
        "wrongPin",
        Some(PIN_ATTEMPTS - failures),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::pass_vault::{seal_vault_secret, VaultSecretV1};

    const ID: &str = "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90";

    fn sealed(binding: &str) -> String {
        let secret = VaultSecretV1 {
            password: Some(zeroize::Zeroizing::new("kasa".to_owned())),
            key_file: None,
        };
        STANDARD.encode(seal_vault_secret(&[7u8; 32], binding, &[1u8; 16], &secret).unwrap())
    }

    const VAULT: Uuid = Uuid::from_bytes([1u8; 16]);

    #[test]
    fn a_vault_secret_must_name_the_binding_it_is_checked_against() {
        assert!(checked_envelope(&sealed(ID), ID, VAULT).is_ok());
        assert!(checked_envelope(&sealed("Ayse@Example.org"), "ayse@example.org", VAULT).is_ok());
        assert!(checked_envelope(&sealed("ayse@example.org"), ID, VAULT).is_err());
        assert!(checked_envelope(&sealed(ID), "ayse@example.org", VAULT).is_err());
        // Sealed for another vault.
        assert!(checked_envelope(&sealed(ID), ID, Uuid::from_bytes([2u8; 16])).is_err());
        let other_purpose = STANDARD.encode(
            account_envelope::seal(b"x", &[7u8; 32], AccountEnvelopePurpose::ChatBackupRoot, ID)
                .unwrap(),
        );
        assert!(checked_envelope(&other_purpose, ID, VAULT).is_err());
        let padded = format!("{}\n", sealed(ID));
        assert!(checked_envelope(&padded, ID, VAULT).is_err());
        assert!(checked_envelope(
            &STANDARD.encode(vec![0u8; MAX_ENVELOPE_BYTES + 1]),
            ID,
            VAULT
        )
        .is_err());
    }
}
