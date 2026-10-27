//! Security keys as a second factor (docs/plans/security-keys.md §4): added,
//! renamed and removed in Account settings, and used at sign-in's second
//! step. The WebAuthn checks are kutup-crypto's adapter; the ceremonies and
//! the key rows are `crate::security_keys`.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::security_keys::{self as keys, CeremonyKind, Refused};
use crate::site_settings::{SECURITY_KEYS_PER_ACCOUNT, WEBAUTHN_CEREMONY_SECONDS};
use crate::{jwt, ratelimit, AppState};

fn relying_party(state: &AppState) -> AppResult<&kutup_crypto::webauthn::RelyingParty> {
    state.webauthn.as_deref().ok_or_else(|| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "security keys are not available on this server",
        )
        .with_details(serde_json::json!({ "code": "securityKeysOff" }))
    })
}

async fn ceremony_seconds(state: &AppState) -> AppResult<i64> {
    Ok(WEBAUTHN_CEREMONY_SECONDS.load(&state.pool).await?)
}

/// A key as Account settings lists it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyView {
    id: Uuid,
    name: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String)]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>)]
    last_used_at: Option<OffsetDateTime>,
    /// Its counter went back (it may have been cloned): no longer used.
    compromised: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeysResponse {
    keys: Vec<SecurityKeyView>,
    /// "Require PIN": user verification for adding and signing in.
    require_uv: bool,
    /// How many keys the account may have.
    limit: i64,
    /// Whether this server offers security keys at all.
    available: bool,
}

/// `GET /api/auth/security-keys` — the account's keys.
#[utoipa::path(
    get,
    path = "/api/auth/security-keys",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, body = SecurityKeysResponse))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<SecurityKeysResponse>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let keys: Vec<SecurityKeyView> = sqlx::query_as(
        "SELECT id, name, created_at, last_used_at, compromised
         FROM user_security_keys WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(SecurityKeysResponse {
        keys,
        require_uv: keys::requires_uv(&state.pool, user_id).await?,
        limit: SECURITY_KEYS_PER_ACCOUNT
            .load_for(&state.pool, user_id)
            .await?,
        available: state.webauthn.is_some(),
    }))
}

/// A reauth's grant for this session (`totp` purpose: changing second
/// factors).
/// `POST /api/auth/security-keys/register/start` — options for adding a key,
/// with the password proved again (a `totp` grant from a reauth of this
/// session) and, while two-step sign-in is on, a factor the account has
/// (`code` or `securityKey`, as removing one takes; `403
/// secondFactorRequired` without). `409 securityKeyLimit` at the account's
/// limit.
#[utoipa::path(
    post,
    path = "/api/auth/security-keys/register/start",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = crate::handlers::auth::CodeRequest,
    responses((status = 200, description = "PublicKeyCredentialCreationOptions (JSON form)"))
)]
pub async fn register_start(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<super::auth::CodeRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let rp = relying_party(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let seconds = ceremony_seconds(&state).await?;
    let mut tx = state.pool.begin().await?;
    crate::grants::take_for_session(&mut *tx, req.grant(), crate::grants::Purpose::Totp, &user)
        .await?;
    let (mut tx, second_factor_proved) =
        super::auth::second_factor_if_on(tx, &state, &user, req.code(), req.security_key.as_ref())
            .await?;
    let (count, name, require_uv): (i64, Option<String>, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM user_security_keys WHERE user_id = u.id),
                u.username, u.security_keys_require_uv
         FROM users u WHERE u.id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    check_limit(&state, user_id, count).await?;
    let existing: Vec<keys::KeyRow> = sqlx::query_as(
        "SELECT credential_id, transports FROM user_security_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    let started = kutup_crypto::webauthn::start_registration(
        rp,
        *user_id.as_bytes(),
        name.as_deref().unwrap_or("Kutup"),
        &keys::key_refs(&existing),
        require_uv,
        u32::try_from(seconds * 1000).unwrap_or(u32::MAX),
    )
    .map_err(|error| AppError::internal(format!("WebAuthn options: {error}")))?;
    keys::store_ceremony(
        &mut tx,
        &started,
        CeremonyKind::Register,
        user_id,
        &keys::binding(&user.session.session_id.to_string()),
        seconds,
        second_factor_proved,
    )
    .await?;
    tx.commit().await?;
    let options: serde_json::Value = serde_json::from_str(&started.options_json)
        .map_err(|error| AppError::internal(format!("WebAuthn options: {error}")))?;
    Ok(Json(options).into_response())
}

/// `409 securityKeyLimit` when the account has its limit of keys or more
/// (a lowered limit keeps the keys it has, and stops new ones).
async fn check_limit(state: &AppState, user_id: Uuid, count: i64) -> AppResult<()> {
    let limit = SECURITY_KEYS_PER_ACCOUNT
        .load_for(&state.pool, user_id)
        .await?;
    if count >= limit {
        return Err(
            AppError::conflict("this account has as many security keys as it may")
                .with_details(serde_json::json!({ "code": "securityKeyLimit", "limit": limit })),
        );
    }
    Ok(())
}

/// A key's name: 1 to 128 characters, none of them control or format
/// characters (Cc, Cf: bidi overrides, zero-width marks) but the zero-width
/// joiner emoji sequences use.
fn key_name(name: &str) -> AppResult<String> {
    use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(AppError::bad_request("a key's name is 1 to 128 characters"));
    }
    if name.chars().any(|c| {
        matches!(
            c.general_category(),
            GeneralCategory::Control | GeneralCategory::Format
        ) && c != '\u{200d}'
    }) {
        return Err(AppError::bad_request(
            "a key's name may not hold control or format characters",
        ));
    }
    Ok(name.to_owned())
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterFinishRequest {
    name: String,
    /// The browser's `PublicKeyCredential.toJSON()` from `create()`.
    #[schema(value_type = Object)]
    credential: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishResponse {
    key: SecurityKeyView,
    /// When this key turned two-step sign-in on: its recovery codes, shown
    /// once.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

/// `POST /api/auth/security-keys/register/finish` — adds the key the
/// browser made. `409 securityKeyExists` for a key already added. The first
/// second factor turns two-step sign-in on, with its recovery codes.
#[utoipa::path(
    post,
    path = "/api/auth/security-keys/register/finish",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = RegisterFinishRequest,
    responses((status = 200, body = RegisterFinishResponse))
)]
pub async fn register_finish(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<RegisterFinishRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let rp = relying_party(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let name = key_name(&req.name)?;
    let response = serde_json::to_vec(&req.credential)
        .map_err(|_| AppError::bad_request("invalid credential"))?;
    let refused = || {
        AppError::bad_request("the security key's answer was not accepted")
            .with_details(serde_json::json!({ "code": "securityKeyRefused" }))
    };
    let challenge =
        kutup_crypto::webauthn::registration_challenge(&response).map_err(|_| refused())?;
    let mut tx = state.pool.begin().await?;
    let factors = crate::two_factor::factors_locked(&mut tx, user_id).await?;
    let ceremony = keys::take_ceremony(
        &mut tx,
        &challenge,
        CeremonyKind::Register,
        user_id,
        &keys::binding(&user.session.session_id.to_string()),
    )
    .await?;
    // A factor turned on since a start that proved none: start again, with it.
    if factors.on() && !ceremony.second_factor_proved {
        return Err(AppError::forbidden("prove your second factor again first")
            .with_details(serde_json::json!({ "code": "secondFactorRequired" })));
    }
    let key = kutup_crypto::webauthn::finish_registration(rp, &ceremony.state, &response).map_err(
        |error| {
            tracing::info!(%error, "security key registration refused");
            refused()
        },
    )?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_security_keys WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    check_limit(&state, user_id, count).await?;
    let inserted: Option<SecurityKeyView> = sqlx::query_as(
        "INSERT INTO user_security_keys
             (user_id, credential_id, transports, static_state, dynamic_state, sign_count,
              aaguid, name)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (credential_id) DO NOTHING
         RETURNING id, name, created_at, last_used_at, compromised",
    )
    .bind(user_id)
    .bind(&key.credential_id)
    .bind(&key.transports)
    .bind(&key.static_state)
    .bind(&key.dynamic_state)
    .bind(i64::from(key.sign_count))
    .bind(&key.aaguid[..])
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(view) = inserted else {
        return Err(AppError::conflict("this security key is already added")
            .with_details(serde_json::json!({ "code": "securityKeyExists" })));
    };
    crate::security_events::record_names(
        &mut tx,
        user_id,
        crate::security_events::Kind::SecurityKeyAdded,
        Some(user.session.session_id),
        None,
        &name,
        None,
    )
    .await?;
    // The account's first second factor: two-step sign-in is on now, with
    // its recovery codes (D2).
    let recovery_codes = if factors.on() {
        None
    } else {
        let count = crate::site_settings::TWO_FACTOR_RECOVERY_CODES
            .load_for(&mut *tx, user_id)
            .await?;
        let codes = crate::two_factor::replace(&mut tx, &state.pool, user_id, count).await?;
        crate::security_events::record(
            &mut tx,
            user_id,
            crate::security_events::Kind::TwoFactorOn,
            Some(user.session.session_id),
            None,
        )
        .await?;
        Some(codes)
    };
    tx.commit().await?;
    Ok(Json(RegisterFinishResponse {
        key: view,
        recovery_codes,
    })
    .into_response())
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RenameRequest {
    name: String,
}

/// `PATCH /api/auth/security-keys/{id}` — renames a key.
#[utoipa::path(
    patch,
    path = "/api/auth/security-keys/{id}",
    tag = "auth",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    request_body = RenameRequest,
    responses((status = 204))
)]
pub async fn rename(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Result<Json<RenameRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let renamed =
        sqlx::query("UPDATE user_security_keys SET name = $3 WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .bind(key_name(&req.name)?)
            .execute(&state.pool)
            .await?;
    if renamed.rows_affected() == 0 {
        return Err(AppError::not_found("not found"));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/auth/security-keys/proof/start` — options for proving the
/// second factor again with a key, for this session (renewing recovery
/// codes, removing a factor): the answer goes in that request's
/// `securityKey`.
#[utoipa::path(
    post,
    path = "/api/auth/security-keys/proof/start",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "PublicKeyCredentialRequestOptions (JSON form)"))
)]
pub async fn proof_start(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let rp = relying_party(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let seconds = ceremony_seconds(&state).await?;
    let mut tx = state.pool.begin().await?;
    let options = keys::start_assertion(
        &mut tx,
        rp,
        CeremonyKind::Proof,
        user_id,
        &keys::binding(&user.session.session_id.to_string()),
        seconds,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(options).into_response())
}

/// `POST /api/auth/login/security-key/start` — a sign-in's second step with
/// a security key: options naming the account's keys. Only someone past the
/// password step (its pre-auth token) learns the account's credential ids.
#[utoipa::path(
    post,
    path = "/api/auth/login/security-key/start",
    tag = "auth",
    request_body = PreAuthRequest,
    responses((status = 200, description = "PublicKeyCredentialRequestOptions (JSON form)"))
)]
pub async fn login_start(
    State(state): State<AppState>,
    body: Result<Json<PreAuthRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let rp = relying_party(&state)?;
    let (user_id, _) = pre_auth(&state, &req.pre_auth_token)?;
    let seconds = ceremony_seconds(&state).await?;
    let mut tx = state.pool.begin().await?;
    let options = keys::start_assertion(
        &mut tx,
        rp,
        CeremonyKind::SignIn,
        user_id,
        &keys::binding(&req.pre_auth_token),
        seconds,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(options).into_response())
}

/// The sign-in's first step, checked: `(account, credential epoch)`.
fn pre_auth(state: &AppState, token: &str) -> AppResult<(Uuid, Vec<u8>)> {
    if ratelimit::is_totp_blocked(token) {
        return Err(AppError::too_many_requests(
            "too many failed attempts, please log in again",
        ));
    }
    let (user_id, epoch) = jwt::validate_pre_auth_token(token, &state.config.jwt_secret)
        .map_err(|_| super::auth::pre_auth_invalid())?;
    let user_id = Uuid::parse_str(&user_id).map_err(|_| super::auth::pre_auth_invalid())?;
    Ok((user_id, epoch))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct PreAuthRequest {
    pre_auth_token: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginFinishRequest {
    pre_auth_token: String,
    /// The browser's `PublicKeyCredential.toJSON()` from `get()`.
    #[schema(value_type = Object)]
    credential: serde_json::Value,
}

/// `POST /api/auth/login/security-key/finish` — checks the key's answer and
/// signs in, as `login/2fa` does for a code. Failures share the code's
/// attempt budget. A key whose counter went back is refused: marked
/// compromised (`securityKeyCompromised`), or, when it was used after this
/// sign-in's start (another tab), only refused (`409 securityKeyRetry`).
#[utoipa::path(
    post,
    path = "/api/auth/login/security-key/finish",
    tag = "auth",
    request_body = LoginFinishRequest,
    responses((status = 200, description = "The session", body = crate::handlers::auth::LoginResponse))
)]
pub async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<LoginFinishRequest>, JsonRejection>,
) -> AppResult<Response> {
    let client = super::auth::direct_sign_in_client(&headers)?;
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let rp = relying_party(&state)?;
    let (user_id, epoch) = pre_auth(&state, &req.pre_auth_token)?;
    let response = serde_json::to_vec(&req.credential)
        .map_err(|_| AppError::bad_request("invalid credential"))?;
    let mut tx = state.pool.begin().await?;
    // Still the password that was proved.
    if super::auth::credential_held(&mut tx, user_id, &epoch)
        .await?
        .is_none()
    {
        return Err(super::auth::pre_auth_invalid());
    }
    let checked = keys::finish_assertion(
        &mut tx,
        rp,
        CeremonyKind::SignIn,
        user_id,
        &keys::binding(&req.pre_auth_token),
        &response,
    )
    .await?;
    // A compromised mark (and its log entry) stays even when refused.
    tx.commit().await?;
    match checked {
        Ok(_) => {
            ratelimit::record_totp_attempt(&req.pre_auth_token, true);
            super::auth::issue_after_second_step(
                &state,
                &headers,
                client,
                &user_id.to_string(),
                &epoch,
            )
            .await
        }
        Err(refused) => {
            if !ratelimit::record_totp_attempt(&req.pre_auth_token, false) {
                return Err(AppError::too_many_requests(
                    "too many failed attempts, please log in again",
                ));
            }
            Err(match refused {
                Refused::Compromised => AppError::unauthorized(
                    "this security key may have been copied; use another factor",
                )
                .with_details(serde_json::json!({ "code": "securityKeyCompromised" })),
                Refused::Concurrent => {
                    AppError::conflict("the security key was used meanwhile; sign in again")
                        .with_details(serde_json::json!({ "code": "securityKeyRetry" }))
                }
                Refused::Invalid => AppError::unauthorized("the security key was not accepted")
                    .with_details(serde_json::json!({ "code": "invalidCredentials" })),
            })
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResponse {
    /// The last second factor went: two-step sign-in is off, and its
    /// recovery codes with it.
    two_factor_off: bool,
}

/// `DELETE /api/auth/security-keys/{id}` — removes a key, with the password
/// (a `totp` grant) and the second factor proved again (`code`: the
/// authenticator's or a recovery code; or `securityKey`: an answer to
/// `proof/start`), as turning the authenticator app off takes. Removing the
/// account's last factor turns two-step sign-in off.
#[utoipa::path(
    delete,
    path = "/api/auth/security-keys/{id}",
    tag = "auth",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    request_body = crate::handlers::auth::CodeRequest,
    responses((status = 200, body = RemoveResponse))
)]
pub async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Result<Json<super::auth::CodeRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    super::auth::second_factor_not_blocked(user_id)?;
    let mut tx = state.pool.begin().await?;
    crate::grants::take_for_session(&mut *tx, req.grant(), crate::grants::Purpose::Totp, &user)
        .await?;
    let outcome = super::auth::prove_second_factor(
        &mut tx,
        &state,
        &user,
        req.code(),
        req.security_key.as_ref(),
    )
    .await?;
    if outcome == super::auth::SecondFactor::Off {
        return Err(AppError::not_found("not found"));
    }
    let mut tx = super::auth::settle_second_factor(tx, user_id, &outcome).await?;
    let removed: Option<String> = sqlx::query_scalar(
        "DELETE FROM user_security_keys WHERE id = $1 AND user_id = $2 RETURNING name",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(name) = removed else {
        return Err(AppError::not_found("not found"));
    };
    crate::security_events::record_names(
        &mut tx,
        user_id,
        crate::security_events::Kind::SecurityKeyRemoved,
        Some(user.session.session_id),
        None,
        &name,
        None,
    )
    .await?;
    // The last key (a compromised one counts) and no authenticator app:
    // two-step sign-in goes with it.
    let two_factor_off = !crate::two_factor::factors(&mut *tx, user_id).await?.on();
    if two_factor_off {
        crate::two_factor::turn_off(&mut tx, user_id).await?;
        crate::security_events::record(
            &mut tx,
            user_id,
            crate::security_events::Kind::TwoFactorOff,
            Some(user.session.session_id),
            None,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(RemoveResponse { two_factor_off }).into_response())
}

// No Debug: it carries a one-time grant.
#[derive(Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RequireUvRequest {
    grant: String,
    require_uv: bool,
    /// Turning it off: the second factor proved again (the authenticator's
    /// or a recovery code, or `securityKey`).
    code: String,
    #[schema(value_type = Option<Object>)]
    security_key: Option<serde_json::Value>,
}

/// `PUT /api/auth/security-keys/require-uv` — Proton's "Require PIN": keys
/// verify their user (a PIN or a fingerprint) when added and at sign-in.
/// With the password proved again (a `totp` grant); turning it off takes
/// the second factor too (`403 secondFactorRequired` without).
#[utoipa::path(
    put,
    path = "/api/auth/security-keys/require-uv",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = RequireUvRequest,
    responses((status = 204))
)]
pub async fn set_require_uv(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<RequireUvRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    crate::grants::take_for_session(&mut *tx, &req.grant, crate::grants::Purpose::Totp, &user)
        .await?;
    // Weakening it is a change to the factor: proved as adding one is.
    let mut tx = if req.require_uv {
        tx
    } else {
        super::auth::second_factor_if_on(tx, &state, &user, &req.code, req.security_key.as_ref())
            .await?
            .0
    };
    sqlx::query("UPDATE users SET security_keys_require_uv = $2 WHERE id = $1")
        .bind(user_id)
        .bind(req.require_uv)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
