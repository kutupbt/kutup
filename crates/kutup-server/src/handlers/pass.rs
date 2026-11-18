//! Kutup Pass on the server (docs/plans/pass.md).
//!
//! The vaults' kept keys are the account-records scope `passSecrets`
//! (docs/plans/account-records.md): one record per vault, keyed by the
//! vault's Drive file id, stored and listed by the records store under the
//! account head. Here, what has become of each kept key's vault
//! (`VaultSecretState`): a key whose vault is in the trash, out of reach now
//! (unshared, perhaps for a moment) or gone (purged) is never deleted by the
//! server; it goes only when its owner forgets it. It also keeps the PIN
//! lock (below).

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::account_records::RecordScope;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_file, trusted_uuid};
use crate::middleware::AuthAccount;
use crate::AppState;

/// What has become of a kept key's vault, for its owner now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum VaultSecretState {
    /// The owner can open the vault: its kept key is in use.
    Open,
    /// The vault is in the trash: its key waits for a restore.
    Trashed,
    /// The vault is there, but not for this person now (unshared, perhaps
    /// only for a moment).
    Unreachable,
    /// The vault was purged: its key waits for its owner to forget it.
    Gone,
}

/// One kept key's vault and its state.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultState {
    file_id: String,
    state: VaultSecretState,
}

/// `GET /api/v1/pass/vault-states` — what has become of the vault of every key
/// the account keeps (its `passSecrets` records), by file id.
#[utoipa::path(
    get,
    path = "/api/v1/pass/vault-states",
    tag = "pass",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Each kept key's vault and its state", body = Vec<VaultState>))
)]
pub async fn vault_states(State(state): State<AppState>, user: AuthAccount) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.account_id)?;
    // `exists`, `trashed`: a purged vault's file row is gone (a record has no
    // foreign key to it). The record id is the file id (canonical text).
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT r.record_id, f.id IS NOT NULL, f.deleted_at IS NOT NULL
           FROM account_records r LEFT JOIN drive_files f ON f.id::text = r.record_id
          WHERE r.account_id = $1 AND r.scope = $2
          ORDER BY r.record_id",
    )
    .bind(user_id)
    .bind(RecordScope::PassSecrets.info().number)
    .fetch_all(&state.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (file_id, exists, trashed) in rows {
        // A failed access check fails the request: never "unreachable" by
        // mistake.
        let vault = if !exists {
            VaultSecretState::Gone
        } else if trashed {
            VaultSecretState::Trashed
        } else if !can_access_file(
            &state.pool,
            user_id,
            Uuid::parse_str(&file_id)
                .map_err(|_| AppError::internal("a Pass record id is not a file id"))?,
        )
        .await?
        {
            VaultSecretState::Unreachable
        } else {
            VaultSecretState::Open
        };
        out.push(VaultState {
            file_id,
            state: vault,
        });
    }
    Ok(Json(out).into_response())
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

/// Wrong PINs in a row before the sign-in ends (`pass_pin_attempts`).
fn pin_attempts() -> i16 {
    i16::try_from(crate::ratelimit::value(
        crate::ratelimit::Limit::PassPinAttempts,
    ))
    .unwrap_or(i16::MAX)
}

fn valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit())
}

/// Whether the account has a PIN.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PinStatus {
    set: bool,
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetPinRequest {
    /// A `pass` grant from a reauth of this session (the account password,
    /// docs/plans/opaque.md).
    grant: String,
    /// Six digits.
    pin: String,
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemovePinRequest {
    /// A `pass` grant from a reauth of this session.
    grant: String,
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
    /// The same word as `code`, kept for readers of the text.
    error: &'static str,
    /// `wrongPin`, `signedOut` or `noPin` (docs/api.md, "Errors").
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts_left: Option<i16>,
}

fn refusal(status: StatusCode, error: &'static str, attempts_left: Option<i16>) -> Response {
    (
        status,
        Json(PinRefusal {
            error,
            code: error,
            attempts_left,
        }),
    )
        .into_response()
}

/// `GET /api/v1/pass/pin` — whether the account has a PIN.
#[utoipa::path(
    get,
    path = "/api/v1/pass/pin",
    tag = "pass",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Whether a PIN is set", body = PinStatus))
)]
pub async fn pin_status(State(state): State<AppState>, user: AuthAccount) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.account_id)?;
    let set: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pass_pins WHERE account_id = $1)")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    Ok(Json(PinStatus { set }).into_response())
}

/// `PUT /api/v1/pass/pin` — sets or changes the PIN, with the account password.
#[utoipa::path(
    put,
    path = "/api/v1/pass/pin",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = SetPinRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 400, description = "Not six digits"),
        (status = 403, description = "grantInvalid: no fresh pass grant of this session")
    )
)]
pub async fn set_pin(
    State(state): State<AppState>,
    user: AuthAccount,
    body: Result<Json<SetPinRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    if !valid_pin(&req.pin) {
        return Err(AppError::bad_request("the PIN must be six digits"));
    }
    let user_id = trusted_uuid(&user.account_id)?;
    let hash = bcrypt::hash(&req.pin, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::internal(format!("hash PIN: {e}")))?;
    let mut tx = state.pool.begin().await?;
    crate::grants::take_for_session(&mut *tx, &req.grant, crate::grants::Purpose::Pass, &user)
        .await?;
    sqlx::query(
        "INSERT INTO pass_pins (account_id, pin_hash) VALUES ($1, $2)
         ON CONFLICT (account_id) DO UPDATE SET pin_hash = $2, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    // A new PIN, with the password: every sign-in's tries start again.
    sqlx::query("DELETE FROM pass_pin_failures WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/v1/pass/pin` — removes the PIN, with the account password.
#[utoipa::path(
    delete,
    path = "/api/v1/pass/pin",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = RemovePinRequest,
    responses(
        (status = 204, description = "Removed (or there was none)"),
        (status = 403, description = "grantInvalid: no fresh pass grant of this session")
    )
)]
pub async fn remove_pin(
    State(state): State<AppState>,
    user: AuthAccount,
    body: Result<Json<RemovePinRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = trusted_uuid(&user.account_id)?;
    let mut tx = state.pool.begin().await?;
    crate::grants::take_for_session(&mut *tx, &req.grant, crate::grants::Purpose::Pass, &user)
        .await?;
    sqlx::query("DELETE FROM pass_pins WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/v1/pass/pin/verify` — checks the PIN.
#[utoipa::path(
    post,
    path = "/api/v1/pass/pin/verify",
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
    user: AuthAccount,
    body: Result<Json<VerifyPinRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = trusted_uuid(&user.account_id)?;
    let hash: Option<String> =
        sqlx::query_scalar("SELECT pin_hash FROM pass_pins WHERE account_id = $1")
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
        "INSERT INTO pass_pin_failures (sign_in_id, account_id, failures) VALUES ($1, $2, 1)
         ON CONFLICT (sign_in_id) DO UPDATE SET failures = pass_pin_failures.failures + 1
         WHERE pass_pin_failures.failures < $3
         RETURNING failures",
    )
    .bind(sign_in)
    .bind(user_id)
    .bind(pin_attempts())
    .fetch_optional(&state.pool)
    .await?;
    let Some(failures) = reserved else {
        // This sign-in has used its tries (a parallel try ended it).
        crate::sessions::sign_out(&state.pool, user.session.session_id).await?;
        return Ok(refusal(StatusCode::FORBIDDEN, "signedOut", Some(0)));
    };
    // Checked at full cost even when the PIN is malformed.
    let right = crate::auth_check::verify_hash(&req.pin, &hash) && valid_pin(&req.pin);
    if right {
        sqlx::query("DELETE FROM pass_pin_failures WHERE sign_in_id = $1")
            .bind(sign_in)
            .execute(&state.pool)
            .await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    tracing::warn!(user_id = %user_id, failures, "wrong Pass PIN");
    if failures >= pin_attempts() {
        crate::sessions::sign_out(&state.pool, user.session.session_id).await?;
        tracing::warn!(user_id = %user_id, "Pass PIN tries used up; the sign-in was ended");
        return Ok(refusal(StatusCode::FORBIDDEN, "signedOut", Some(0)));
    }
    Ok(refusal(
        StatusCode::FORBIDDEN,
        "wrongPin",
        Some(pin_attempts() - failures),
    ))
}
