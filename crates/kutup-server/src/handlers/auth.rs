//! Auth + user handlers — mirrors `backend/handlers/auth.go`.
//!
//! Registration, login (+ preflight, 2FA), recovery (+ preflight), token refresh,
//! first-login setup, the `/user/*` profile + TOTP endpoints, and the by-email lookup.
//! Wire formats, status codes, and SQL match the Go handler exactly; the refresh token
//! is set as the same HttpOnly cookie scoped to `/api/auth/refresh`.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::models::{
    MeResponse, MessageResponse, OkResponse, PreflightLoginResponse, PreflightRecoverResponse,
    RefreshResponse, SettingsResponse, TotpSetupResponse, UserLookupResponse,
};
use crate::{jwt, ratelimit, totp, AppState};

/// bcrypt cost — matches Go's `bcrypt.DefaultCost` (10).
const BCRYPT_COST: u32 = 10;
/// Fixed dummy hash used to keep timing constant on the no-such-user paths — mirrors the
/// Go `bcrypt.CompareHashAndPassword([]byte("$2a$10$fakehash..."), ...)` calls.
const FAKE_BCRYPT_HASH: &str = "$2a$10$fakehashfortimingprotectiononly";

// --- request / response bodies local to auth.go ---
//
// All request bodies use container-level `#[serde(default)]` so a missing JSON field
// deserializes to its zero value — Go's `c.BodyParser` (encoding/json) never errors on
// absent fields, only on malformed JSON.

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterRequest {
    email: String,
    username: String,
    login_key: String,
    master_key_envelope: String,
    recovery_key_envelope: String,
    drive_private_key_envelope: String,
    public_key: String,
    account_authority_public_key: String,
    account_authority_key_id: String,
    account_incarnation_id: String,
    drive_signing_public_key: String,
    account_protection_suite: u16,
    account_protection_salt: String,
    argon_memory_kib: u32,
    argon_iterations: u32,
    argon_parallelism: u32,
    #[serde(default)]
    recovery_proof: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginRequest {
    email: String,
    login_key: String,
}

/// Mirrors `auth.LoginResponse`. Non-omitempty fields are always present (empty/zero on
/// the setup/2FA branches); the four omitempty fields are skipped at their defaults.
#[derive(Debug, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    access_token: String,
    user_id: String,
    username: String,
    master_key_envelope: String,
    drive_private_key_envelope: String,
    public_key: String,
    is_admin: bool,
    storage_quota_bytes: i64,
    storage_used_bytes: i64,
    color: String,
    #[serde(skip_serializing_if = "is_false")]
    requires_totp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_auth_token: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    requires_setup: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    setup_token: Option<String>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct TwoFALoginRequest {
    pre_auth_token: String,
    code: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RecoverRequest {
    email: String,
    new_login_key: String,
    new_master_key_envelope: String,
    new_account_protection_suite: u16,
    new_account_protection_salt: String,
    new_argon_memory_kib: u32,
    new_argon_iterations: u32,
    new_argon_parallelism: u32,
    #[serde(default)]
    recovery_proof: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateMeRequest {
    /// Hex color like `#ef4444`; empty string clears it; absent leaves it unchanged.
    color: Option<String>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct CodeRequest {
    code: String,
}

/// `?email=` query for the preflight endpoints.
#[derive(Debug, Deserialize)]
pub struct EmailQuery {
    #[serde(default)]
    email: Option<String>,
}

/// Mirrors the `fiber.Map` returned by `CompleteSetup`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompleteSetupResponse {
    access_token: String,
    user_id: String,
    username: String,
    is_admin: bool,
    storage_quota_bytes: i64,
    storage_used_bytes: i64,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn decode_canonical_base64_exact(
    value: &str,
    expected_len: usize,
    field: &str,
) -> AppResult<Vec<u8>> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request(format!("invalid {field} encoding")))?;
    if decoded.len() != expected_len || STANDARD.encode(&decoded) != value {
        return Err(AppError::bad_request(format!(
            "{field} must be canonical base64 for {expected_len} bytes"
        )));
    }
    Ok(decoded)
}

fn validate_account_protection(
    suite: u16,
    salt: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> AppResult<()> {
    use kutup_crypto::kdf::{
        AccountProtectionParameters, AccountProtectionSuiteId, ACCOUNT_PROTECTION_SALT_LEN,
    };
    AccountProtectionSuiteId::try_from(suite)
        .map_err(|_| AppError::bad_request("unsupported accountProtectionSuite"))?;
    decode_canonical_base64_exact(salt, ACCOUNT_PROTECTION_SALT_LEN, "accountProtectionSalt")?;
    AccountProtectionParameters {
        memory_kib,
        iterations,
        parallelism,
    }
    .validate_v1()
    .map_err(|_| AppError::bad_request("unsupported Argon2id parameters"))
}

fn validate_account_envelope(
    value: &str,
    purpose: kutup_crypto::account_envelope::AccountEnvelopePurpose,
    email: &str,
    field: &str,
) -> AppResult<()> {
    let envelope = kutup_crypto::account_envelope::decode_canonical_b64(value)
        .map_err(|_| AppError::bad_request(format!("invalid {field} encoding")))?;
    kutup_crypto::account_envelope::validate(&envelope, purpose, email, 32)
        .map_err(|_| AppError::bad_request(format!("invalid {field} binding")))
}

fn validate_account_identity(req: &RegisterRequest) -> AppResult<()> {
    let authority = decode_canonical_base64_exact(
        &req.account_authority_public_key,
        32,
        "accountAuthorityPublicKey",
    )?;
    let authority: [u8; 32] = authority.try_into().expect("validated length");
    decode_canonical_base64_exact(&req.public_key, 32, "publicKey")?;
    decode_canonical_base64_exact(&req.drive_signing_public_key, 32, "driveSigningPublicKey")?;
    if req.account_authority_key_id
        != kutup_crypto::identity::authority_key_id_from_public(&authority)
        || req.account_incarnation_id
            != kutup_crypto::identity::incarnation_id_from_authority_public(&authority)
    {
        return Err(AppError::bad_request(
            "account identity identifiers do not match the authority key",
        ));
    }
    Ok(())
}

fn hash_recovery_proof(proof: &str) -> AppResult<String> {
    if proof.is_empty() {
        return Err(AppError::bad_request("recoveryProof is required"));
    }
    let proof = decode_canonical_base64_exact(proof, 32, "recoveryProof")?;
    bcrypt::hash(proof, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))
}

// --- handlers ---

/// `GET /api/auth/settings` — mirrors `GetPublicSettings`.
#[utoipa::path(
    get,
    path = "/api/auth/settings",
    tag = "auth",
    responses((status = 200, description = "Public registration settings", body = SettingsResponse))
)]
pub async fn get_public_settings(State(state): State<AppState>) -> AppResult<Response> {
    let val: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key='registration_enabled'")
            .fetch_optional(&state.pool)
            .await?;
    let federation_enabled = match state.federation.as_ref() {
        Some(federation) => {
            federation
                .policy()
                .feature_is_publicly_enabled(crate::federation::FederationPolicyFeature::Chat)
                .await?
        }
        None => false,
    };
    let sealed_sender_policy = if federation_enabled && state.sealed_sender.is_some() {
        let federation = state
            .federation
            .as_ref()
            .expect("sealed sender requires federation");
        federation
            .feature_policies()
            .local_history(
                federation.server_name(),
                kutup_federation_proto::FederatedFeaturePolicyTypeV1::SealedSenderService,
            )
            .await?
    } else {
        None
    };
    let mls_groups = crate::chat_mls::policy::advertised_policy(&state, federation_enabled)
        .await?
        .is_some();
    let chat = kutup_chat_proto::ChatCapabilities {
        mailbox_retention_days: state
            .config
            .chat_mailbox_retention_days
            .try_into()
            .unwrap_or(u32::MAX),
        device_expiry_days: state
            .config
            .chat_device_expiry_days
            .try_into()
            .unwrap_or(u32::MAX),
        maximum_active_devices: state.config.chat_max_active_devices,
        server_name: federation_enabled.then(|| {
            state
                .federation
                .as_ref()
                .expect("federation enabled only with configured identity")
                .server_name()
                .to_string()
        }),
        federation: federation_enabled,
        sealed_sender: sealed_sender_policy.is_some(),
        mls_groups,
        media: federation_enabled
            .then(|| {
                kutup_chat_proto::ChatMediaCapabilitiesV1::v1(
                    state.config.chat_media_max_plaintext_bytes,
                )
            })
            .transpose()
            .map_err(AppError::internal)?,
        sealed_sender_policy,
        ..Default::default()
    };
    Ok(Json(SettingsResponse {
        registration_enabled: val.as_deref() != Some("false"),
        chat,
    })
    .into_response())
}

/// `POST /api/auth/register` — mirrors `Register`.
#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses((status = 201, description = "Account created", body = MessageResponse))
)]
pub async fn register(
    State(state): State<AppState>,
    body: Result<Json<RegisterRequest>, JsonRejection>,
) -> AppResult<Response> {
    let reg_enabled: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key='registration_enabled'")
            .fetch_optional(&state.pool)
            .await?;
    if reg_enabled.as_deref() == Some("false") {
        return Err(AppError::forbidden("registration disabled"));
    }

    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    if req.email.is_empty() || req.login_key.is_empty() {
        return Err(AppError::bad_request("missing required fields"));
    }
    if !is_valid_username(&req.username) {
        return Err(AppError::bad_request(
            "invalid username: must be 3-32 chars, lowercase letters, numbers, _ and -",
        ));
    }
    validate_account_protection(
        req.account_protection_suite,
        &req.account_protection_salt,
        req.argon_memory_kib,
        req.argon_iterations,
        req.argon_parallelism,
    )?;
    use kutup_crypto::account_envelope::AccountEnvelopePurpose;
    validate_account_envelope(
        &req.master_key_envelope,
        AccountEnvelopePurpose::PasswordMasterKey,
        &req.email,
        "masterKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.recovery_key_envelope,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &req.email,
        "recoveryKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.drive_private_key_envelope,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &req.email,
        "drivePrivateKeyEnvelope",
    )?;
    validate_account_identity(&req)?;

    let login_key_bytes = decode_canonical_base64_exact(&req.login_key, 32, "loginKey")?;
    let hash =
        bcrypt::hash(login_key_bytes, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))?;

    // This is an HKDF-derived authorization proof, never the recovery entropy
    // that opens recoveryKeyEnvelope.
    let recovery_verifier = hash_recovery_proof(&req.recovery_proof)?;

    let res = sqlx::query(
        r#"INSERT INTO users (
            email, username, master_key_envelope, recovery_key_envelope,
            drive_private_key_envelope,
            public_key, account_authority_public_key, account_authority_key_id,
            account_incarnation_id, drive_signing_public_key,
            account_protection_suite, account_protection_salt,
            argon_memory_kib, argon_iterations, argon_parallelism,
            login_key_hash, recovery_key_verifier
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)"#,
    )
    .bind(&req.email)
    .bind(&req.username)
    .bind(&req.master_key_envelope)
    .bind(&req.recovery_key_envelope)
    .bind(&req.drive_private_key_envelope)
    .bind(&req.public_key)
    .bind(&req.account_authority_public_key)
    .bind(&req.account_authority_key_id)
    .bind(&req.account_incarnation_id)
    .bind(&req.drive_signing_public_key)
    .bind(i16::try_from(req.account_protection_suite).unwrap_or(i16::MAX))
    .bind(&req.account_protection_salt)
    .bind(i32::try_from(req.argon_memory_kib).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.argon_iterations).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.argon_parallelism).unwrap_or(i32::MAX))
    .bind(&hash)
    .bind(&recovery_verifier)
    .execute(&state.pool)
    .await;

    if let Err(err) = res {
        return Err(map_insert_conflict(err));
    }
    Ok((
        axum::http::StatusCode::CREATED,
        Json(MessageResponse {
            message: "registered".to_string(),
        }),
    )
        .into_response())
}

/// `GET /api/auth/login/preflight` — mirrors `GetLoginPreflight`. Returns deterministic
/// fake salts for unknown emails to defeat enumeration.
#[utoipa::path(
    get,
    path = "/api/auth/login/preflight",
    tag = "auth",
    params(("email" = String, Query, description = "Account email")),
    responses((status = 200, description = "Account-protection suite and parameters", body = PreflightLoginResponse))
)]
pub async fn get_login_preflight(
    State(state): State<AppState>,
    Query(q): Query<EmailQuery>,
) -> AppResult<Response> {
    let email = q
        .email
        .filter(|e| !e.is_empty())
        .ok_or_else(|| AppError::bad_request("email required"))?;

    let row: Option<(i16, String, i32, i32, i32)> = sqlx::query_as(
        "SELECT account_protection_suite, account_protection_salt, argon_memory_kib, argon_iterations, argon_parallelism FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;

    let (suite, salt, memory_kib, iterations, parallelism) = match row {
        Some(row) => row,
        None => (
            kutup_crypto::kdf::AccountProtectionSuiteId::Argon2idHkdfSha256V1.as_u16() as i16,
            deterministic_fake_bytes(&email, "account-protection", 16),
            kutup_crypto::kdf::AccountProtectionParameters::V1.memory_kib as i32,
            kutup_crypto::kdf::AccountProtectionParameters::V1.iterations as i32,
            kutup_crypto::kdf::AccountProtectionParameters::V1.parallelism as i32,
        ),
    };

    Ok(Json(PreflightLoginResponse {
        account_protection_suite: u16::try_from(suite).unwrap_or(0),
        account_protection_salt: salt,
        argon_memory_kib: u32::try_from(memory_kib).unwrap_or(0),
        argon_iterations: u32::try_from(iterations).unwrap_or(0),
        argon_parallelism: u32::try_from(parallelism).unwrap_or(0),
    })
    .into_response())
}

/// `POST /api/auth/login` — mirrors `Login`.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses((status = 200, description = "Session, 2FA challenge, or first-login setup token", body = LoginResponse))
)]
pub async fn login(
    State(state): State<AppState>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    // Per-account lockout (on top of the per-IP route limiter): N failed password
    // attempts lock the email out for a cooldown. Checked for unknown emails too, so
    // the 429 is not an account-existence oracle.
    if ratelimit::LOGIN_LOCKOUT.is_locked(&req.email) {
        return Err(AppError::too_many_requests(
            "too many failed attempts, try again later",
        ));
    }

    type Row = (
        Uuid,
        String,
        String,
        String,
        String,
        bool,
        bool,
        i64,
        i64,
        bool,
        String,
        String,
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT id, login_key_hash, master_key_envelope,
                  drive_private_key_envelope, public_key,
                  totp_enabled, is_admin, storage_quota_bytes, storage_used_bytes, is_active,
                  account_protection_salt,
                  COALESCE(username, ''), COALESCE(color, '')
           FROM users WHERE email = $1"#,
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await?;

    let Some((
        id,
        login_key_hash,
        master_key_envelope,
        drive_private_key_envelope,
        pub_key,
        totp_enabled,
        is_admin,
        quota_bytes,
        used_bytes,
        is_active,
        account_protection_salt,
        username,
        color,
    )) = row
    else {
        // Run bcrypt anyway to keep timing constant.
        let _ = bcrypt::verify("dummy", FAKE_BCRYPT_HASH);
        ratelimit::LOGIN_LOCKOUT.record(&req.email, false);
        return Err(AppError::unauthorized("invalid credentials"));
    };

    if !is_active {
        return Err(AppError::unauthorized("account disabled"));
    }

    let login_key_bytes = STANDARD
        .decode(&req.login_key)
        .map_err(|_| AppError::bad_request("invalid loginKey"))?;

    if !bcrypt::verify(&login_key_bytes, &login_key_hash).unwrap_or(false) {
        ratelimit::LOGIN_LOCKOUT.record(&req.email, false);
        return Err(AppError::unauthorized("invalid credentials"));
    }
    ratelimit::LOGIN_LOCKOUT.record(&req.email, true);

    let user_id = id.to_string();

    // First-login account — no key material yet.
    if account_protection_salt.is_empty() {
        let setup_token = jwt::generate_setup_token(&user_id, &state.config.jwt_secret)
            .map_err(|_| AppError::internal("token"))?;
        return Ok(Json(LoginResponse {
            requires_setup: true,
            setup_token: Some(setup_token),
            ..Default::default()
        })
        .into_response());
    }

    // TOTP enabled — return a pre-auth token instead of a full session.
    if totp_enabled {
        let pre_auth = jwt::generate_pre_auth_token(&user_id, &state.config.jwt_secret)
            .map_err(|_| AppError::internal("token"))?;
        return Ok(Json(LoginResponse {
            requires_totp: true,
            pre_auth_token: Some(pre_auth),
            ..Default::default()
        })
        .into_response());
    }

    issue_tokens_and_respond(
        &state,
        &user_id,
        &username,
        &master_key_envelope,
        &drive_private_key_envelope,
        &pub_key,
        is_admin,
        quota_bytes,
        used_bytes,
        &color,
    )
}

/// `POST /api/auth/login/2fa` — mirrors `LoginTwoFA`.
#[utoipa::path(
    post,
    path = "/api/auth/login/2fa",
    tag = "auth",
    request_body = TwoFALoginRequest,
    responses((status = 200, description = "Full session after TOTP", body = LoginResponse))
)]
pub async fn login_two_fa(
    State(state): State<AppState>,
    body: Result<Json<TwoFALoginRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    if ratelimit::is_totp_blocked(&req.pre_auth_token) {
        return Err(AppError::too_many_requests(
            "too many failed attempts, please log in again",
        ));
    }

    let user_id = jwt::validate_pre_auth_token(&req.pre_auth_token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("invalid pre-auth token"))?;

    type Row = (
        Option<String>,
        String,
        String,
        String,
        bool,
        i64,
        i64,
        String,
        bool,
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT totp_secret, master_key_envelope,
                  drive_private_key_envelope, public_key,
                  is_admin, storage_quota_bytes, storage_used_bytes,
                  COALESCE(username, ''), is_active, COALESCE(color, '')
           FROM users WHERE id = $1"#,
    )
    .bind(Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("unauthorized"))?)
    .fetch_optional(&state.pool)
    .await?;

    let Some((
        totp_secret,
        master_key_envelope,
        drive_private_key_envelope,
        pub_key,
        is_admin,
        quota_bytes,
        used_bytes,
        username,
        is_active,
        color,
    )) = row
    else {
        return Err(AppError::unauthorized("unauthorized"));
    };

    if !is_active {
        return Err(AppError::unauthorized("account disabled"));
    }

    let valid = totp_secret
        .as_deref()
        .map(|s| totp::validate_totp(s, &req.code))
        .unwrap_or(false);
    if !valid {
        if !ratelimit::record_totp_attempt(&req.pre_auth_token, false) {
            return Err(AppError::too_many_requests(
                "too many failed attempts, please log in again",
            ));
        }
        return Err(AppError::unauthorized("invalid TOTP code"));
    }
    ratelimit::record_totp_attempt(&req.pre_auth_token, true);

    issue_tokens_and_respond(
        &state,
        &user_id,
        &username,
        &master_key_envelope,
        &drive_private_key_envelope,
        &pub_key,
        is_admin,
        quota_bytes,
        used_bytes,
        &color,
    )
}

/// `GET /api/auth/recover/preflight` — mirrors `GetRecoveryPreflight`.
#[utoipa::path(
    get,
    path = "/api/auth/recover/preflight",
    tag = "auth",
    params(("email" = String, Query, description = "Account email")),
    responses((status = 200, description = "Encrypted recovery key material", body = PreflightRecoverResponse))
)]
pub async fn get_recovery_preflight(
    State(state): State<AppState>,
    Query(q): Query<EmailQuery>,
) -> AppResult<Response> {
    let email = q
        .email
        .filter(|e| !e.is_empty())
        .ok_or_else(|| AppError::bad_request("email required"))?;

    let row: Option<String> =
        sqlx::query_scalar("SELECT recovery_key_envelope FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await?;

    let resp = match row {
        Some(recovery_key_envelope) => PreflightRecoverResponse {
            recovery_key_envelope,
        },
        None => PreflightRecoverResponse {
            recovery_key_envelope: deterministic_fake_account_envelope(&email),
        },
    };
    Ok(Json(resp).into_response())
}

/// `POST /api/auth/recover` — mirrors `Recover`.
#[utoipa::path(
    post,
    path = "/api/auth/recover",
    tag = "auth",
    request_body = RecoverRequest,
    responses((status = 200, description = "Password reset via recovery phrase", body = MessageResponse))
)]
pub async fn recover(
    State(state): State<AppState>,
    body: Result<Json<RecoverRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    if req.recovery_proof.is_empty() {
        return Err(AppError::bad_request("recoveryProof is required"));
    }
    validate_account_protection(
        req.new_account_protection_suite,
        &req.new_account_protection_salt,
        req.new_argon_memory_kib,
        req.new_argon_iterations,
        req.new_argon_parallelism,
    )?;
    validate_account_envelope(
        &req.new_master_key_envelope,
        kutup_crypto::account_envelope::AccountEnvelopePurpose::PasswordMasterKey,
        &req.email,
        "newMasterKeyEnvelope",
    )?;

    let stored: Option<String> =
        sqlx::query_scalar("SELECT recovery_key_verifier FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&state.pool)
            .await?;
    let Some(stored_verifier) = stored else {
        let _ = bcrypt::verify("dummy", FAKE_BCRYPT_HASH);
        return Err(AppError::not_found("user not found"));
    };

    if stored_verifier.is_empty() {
        return Err(AppError::unauthorized(
            "account has no recovery authorization verifier",
        ));
    }
    let proof = decode_canonical_base64_exact(&req.recovery_proof, 32, "recoveryProof")?;
    if !bcrypt::verify(&proof, &stored_verifier).unwrap_or(false) {
        return Err(AppError::unauthorized("invalid recovery proof"));
    }

    let login_key_bytes = decode_canonical_base64_exact(&req.new_login_key, 32, "newLoginKey")?;
    let hash =
        bcrypt::hash(login_key_bytes, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))?;

    let res = sqlx::query(
        r#"UPDATE users SET
              login_key_hash = $1,
              master_key_envelope = $2,
              account_protection_suite = $3,
              account_protection_salt = $4,
              argon_memory_kib = $5,
              argon_iterations = $6,
              argon_parallelism = $7,
              is_first_login = false,
              updated_at = NOW()
           WHERE email = $8"#,
    )
    .bind(&hash)
    .bind(&req.new_master_key_envelope)
    .bind(i16::try_from(req.new_account_protection_suite).unwrap_or(i16::MAX))
    .bind(&req.new_account_protection_salt)
    .bind(i32::try_from(req.new_argon_memory_kib).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.new_argon_iterations).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.new_argon_parallelism).unwrap_or(i32::MAX))
    .bind(&req.email)
    .execute(&state.pool)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::not_found("user not found"));
    }
    Ok(Json(MessageResponse {
        message: "password reset".to_string(),
    })
    .into_response())
}

/// `POST /api/auth/refresh` — mirrors `Refresh`. Reads the refresh token from the cookie,
/// falling back to the JSON body.
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "auth",
    request_body(content = RefreshRequest, description = "Fallback when the refresh_token cookie is absent"),
    responses((status = 200, description = "Fresh access token", body = RefreshResponse))
)]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<RefreshRequest>>,
) -> AppResult<Response> {
    let mut token = cookie_value(&headers, "refresh_token").unwrap_or_default();
    if token.is_empty() {
        token = body.map(|Json(b)| b.refresh_token).unwrap_or_default();
    }
    if token.is_empty() {
        return Err(AppError::unauthorized("missing refresh token"));
    }

    let claims = jwt::validate_token(&token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("invalid refresh token"))?;
    if !claims.sub.is_empty() {
        return Err(AppError::unauthorized("invalid refresh token"));
    }

    let row: Option<(bool, bool)> =
        sqlx::query_as("SELECT is_active, is_admin FROM users WHERE id = $1")
            .bind(
                Uuid::parse_str(&claims.user_id)
                    .map_err(|_| AppError::unauthorized("unauthorized"))?,
            )
            .fetch_optional(&state.pool)
            .await?;
    let Some((is_active, is_admin)) = row else {
        return Err(AppError::unauthorized("unauthorized"));
    };
    if !is_active {
        return Err(AppError::unauthorized("unauthorized"));
    }

    let access = jwt::generate_access_token(&claims.user_id, is_admin, &state.config.jwt_secret)
        .map_err(|_| AppError::internal("token"))?;
    Ok(Json(RefreshResponse {
        access_token: access,
    })
    .into_response())
}

/// `GET /api/user/me` — mirrors `GetMe`.
#[utoipa::path(
    get,
    path = "/api/user/me",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's profile", body = MeResponse))
)]
pub async fn get_me(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    type Row = (Uuid, String, String, String, bool, i64, i64, bool, String);
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT id, email, COALESCE(username, ''), public_key, totp_enabled,
                  storage_quota_bytes, storage_used_bytes, is_admin, COALESCE(color, '')
           FROM users WHERE id = $1"#,
    )
    .bind(parse_uuid(&user.user_id)?)
    .fetch_optional(&state.pool)
    .await?;

    let Some((id, email, username, public_key, totp_enabled, quota, used, is_admin, color)) = row
    else {
        return Err(AppError::not_found("user not found"));
    };
    Ok(Json(MeResponse {
        id: id.to_string(),
        email,
        username,
        public_key,
        totp_enabled,
        storage_quota_bytes: quota,
        storage_used_bytes: used,
        is_admin,
        color,
    })
    .into_response())
}

/// `PATCH /api/user/me` — mirrors `UpdateMe`.
#[utoipa::path(
    patch,
    path = "/api/user/me",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = UpdateMeRequest,
    responses((status = 200, description = "Profile updated", body = OkResponse))
)]
pub async fn update_me(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<UpdateMeRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request body"))?;

    if let Some(color) = req.color {
        if !color.is_empty() && !is_valid_hex_color(&color) {
            return Err(AppError::bad_request("invalid color: expected #rrggbb hex"));
        }
        let value: Option<String> = if color.is_empty() { None } else { Some(color) };
        sqlx::query("UPDATE users SET color = $1 WHERE id = $2")
            .bind(value)
            .bind(parse_uuid(&user.user_id)?)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("failed to update color"))?;
    }

    Ok(Json(OkResponse { ok: true }).into_response())
}

/// `GET /api/users/by-email/:email` — mirrors `GetUserByEmail`.
#[utoipa::path(
    get,
    path = "/api/users/by-email/{email}",
    tag = "auth",
    security(("BearerAuth" = [])),
    params(("email" = String, Path, description = "Target user's email")),
    responses((status = 200, description = "User id + public key", body = UserLookupResponse))
)]
pub async fn get_user_by_email(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(email): Path<String>,
) -> AppResult<Response> {
    let row: Option<(Uuid, Option<String>, String, String, String)> = sqlx::query_as(
        "SELECT id, username, public_key, account_incarnation_id, drive_signing_public_key
         FROM users WHERE email = $1 AND is_active = true",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((id, username, public_key, incarnation_id, signing_public_key)) = row else {
        return Err(AppError::not_found("user not found"));
    };
    let username = username
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::conflict("recipient identity is unavailable"))?;
    let domain = state
        .federation
        .as_ref()
        .map(|federation| federation.server_name())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::conflict("named shares require a canonical server domain"))?;
    Ok(Json(UserLookupResponse {
        user_id: id.to_string(),
        account: format!("{username}@{domain}"),
        drive_hpke_public_key: public_key,
        account_incarnation_id: incarnation_id,
        drive_signing_public_key: signing_public_key,
    })
    .into_response())
}

/// `POST /api/user/2fa/setup` — mirrors `SetupTOTP`.
#[utoipa::path(
    post,
    path = "/api/user/2fa/setup",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "TOTP secret + provisioning URI", body = TotpSetupResponse))
)]
pub async fn setup_totp(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(parse_uuid(&user.user_id)?)
        .fetch_optional(&state.pool)
        .await?;
    let Some(email) = email else {
        return Err(AppError::not_found("user not found"));
    };

    let (secret, qr_uri) =
        totp::generate_totp(&email, "Kutup").map_err(|_| AppError::internal("totp"))?;

    sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
        .bind(&secret)
        .bind(parse_uuid(&user.user_id)?)
        .execute(&state.pool)
        .await?;

    Ok(Json(TotpSetupResponse { secret, qr_uri }).into_response())
}

/// `POST /api/user/2fa/verify` — mirrors `VerifyTOTP`.
#[utoipa::path(
    post,
    path = "/api/user/2fa/verify",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = CodeRequest,
    responses((status = 200, description = "TOTP enabled", body = MessageResponse))
)]
pub async fn verify_totp(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<CodeRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    let secret: Option<String> = sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = $1")
        .bind(parse_uuid(&user.user_id)?)
        .fetch_optional(&state.pool)
        .await?
        .flatten();
    let Some(secret) = secret else {
        return Err(AppError::bad_request("TOTP not set up"));
    };

    if !totp::validate_totp(&secret, &req.code) {
        return Err(AppError::bad_request("invalid code"));
    }

    sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
        .bind(parse_uuid(&user.user_id)?)
        .execute(&state.pool)
        .await?;

    Ok(Json(MessageResponse {
        message: "TOTP enabled".to_string(),
    })
    .into_response())
}

/// `DELETE /api/user/2fa` — mirrors `DisableTOTP`.
#[utoipa::path(
    delete,
    path = "/api/user/2fa",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = CodeRequest,
    responses((status = 200, description = "TOTP disabled", body = MessageResponse))
)]
pub async fn disable_totp(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<CodeRequest>, JsonRejection>,
) -> AppResult<Response> {
    let code = match body {
        Ok(Json(b)) => b.code,
        Err(_) => String::new(),
    };
    if code.is_empty() {
        return Err(AppError::bad_request("totp code required"));
    }

    let secret: Option<String> =
        sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = $1 AND totp_enabled = true")
            .bind(parse_uuid(&user.user_id)?)
            .fetch_optional(&state.pool)
            .await?
            .flatten();
    let Some(secret) = secret else {
        return Err(AppError::bad_request("TOTP not enabled"));
    };

    if !totp::validate_totp(&secret, &code) {
        return Err(AppError::bad_request("invalid code"));
    }

    sqlx::query("UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1")
        .bind(parse_uuid(&user.user_id)?)
        .execute(&state.pool)
        .await?;

    Ok(Json(MessageResponse {
        message: "TOTP disabled".to_string(),
    })
    .into_response())
}

/// `POST /api/auth/complete-setup` — mirrors `CompleteSetup`. Authenticated by the
/// short-lived setup token (not a regular access token).
#[utoipa::path(
    post,
    path = "/api/auth/complete-setup",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = RegisterRequest,
    responses((status = 200, description = "Setup complete; full session issued", body = CompleteSetupResponse))
)]
pub async fn complete_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<RegisterRequest>, JsonRejection>,
) -> AppResult<Response> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let user_id = jwt::validate_setup_token(token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("invalid setup token"))?;

    let account: Option<(bool, String)> =
        sqlx::query_as("SELECT is_active, email FROM users WHERE id = $1")
            .bind(parse_uuid(&user_id).map_err(|_| AppError::unauthorized("unauthorized"))?)
            .fetch_optional(&state.pool)
            .await?;
    let Some((true, account_email)) = account else {
        return Err(AppError::unauthorized("account disabled"));
    };

    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    validate_account_protection(
        req.account_protection_suite,
        &req.account_protection_salt,
        req.argon_memory_kib,
        req.argon_iterations,
        req.argon_parallelism,
    )?;
    use kutup_crypto::account_envelope::AccountEnvelopePurpose;
    validate_account_envelope(
        &req.master_key_envelope,
        AccountEnvelopePurpose::PasswordMasterKey,
        &account_email,
        "masterKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.recovery_key_envelope,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &account_email,
        "recoveryKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.drive_private_key_envelope,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &account_email,
        "drivePrivateKeyEnvelope",
    )?;
    validate_account_identity(&req)?;
    let login_key_bytes = decode_canonical_base64_exact(&req.login_key, 32, "loginKey")?;
    let hash =
        bcrypt::hash(login_key_bytes, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))?;
    let recovery_verifier = hash_recovery_proof(&req.recovery_proof)?;

    let uid = parse_uuid(&user_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    // Only update while the account-protection salt is still empty — prevents
    // replay after setup completes.
    let res = sqlx::query(
        r#"UPDATE users SET
              login_key_hash = $1,
              master_key_envelope = $2, recovery_key_envelope = $3,
              drive_private_key_envelope = $4, public_key = $5,
              account_authority_public_key = $6, account_authority_key_id = $7,
              account_incarnation_id = $8, drive_signing_public_key = $9,
              account_protection_suite = $10, account_protection_salt = $11,
              argon_memory_kib = $12, argon_iterations = $13,
              argon_parallelism = $14, recovery_key_verifier = $15,
              is_first_login = false, updated_at = NOW()
           WHERE id = $16 AND account_protection_salt = ''"#,
    )
    .bind(&hash)
    .bind(&req.master_key_envelope)
    .bind(&req.recovery_key_envelope)
    .bind(&req.drive_private_key_envelope)
    .bind(&req.public_key)
    .bind(&req.account_authority_public_key)
    .bind(&req.account_authority_key_id)
    .bind(&req.account_incarnation_id)
    .bind(&req.drive_signing_public_key)
    .bind(i16::try_from(req.account_protection_suite).unwrap_or(i16::MAX))
    .bind(&req.account_protection_salt)
    .bind(i32::try_from(req.argon_memory_kib).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.argon_iterations).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.argon_parallelism).unwrap_or(i32::MAX))
    .bind(&recovery_verifier)
    .bind(uid)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {}
        _ => {
            return Err(AppError::bad_request(
                "setup already completed or user not found",
            ))
        }
    }

    let (is_admin, quota, used, username): (bool, i64, i64, String) = sqlx::query_as(
        "SELECT is_admin, storage_quota_bytes, storage_used_bytes, COALESCE(username, '') FROM users WHERE id = $1",
    )
    .bind(uid)
    .fetch_one(&state.pool)
    .await?;

    let access = jwt::generate_access_token(&user_id, is_admin, &state.config.jwt_secret)
        .map_err(|_| AppError::internal("token"))?;
    let refresh = jwt::generate_refresh_token(&user_id, &state.config.jwt_secret)
        .map_err(|_| AppError::internal("token"))?;
    let cookie = refresh_cookie(&refresh, state.config.app_env == "production");

    Ok((
        [(SET_COOKIE, cookie)],
        Json(CompleteSetupResponse {
            access_token: access,
            user_id,
            username,
            is_admin,
            storage_quota_bytes: quota,
            storage_used_bytes: used,
        }),
    )
        .into_response())
}

// --- helpers ---

#[allow(clippy::too_many_arguments)]
fn issue_tokens_and_respond(
    state: &AppState,
    user_id: &str,
    username: &str,
    master_key_envelope: &str,
    drive_private_key_envelope: &str,
    pub_key: &str,
    is_admin: bool,
    quota: i64,
    used: i64,
    color: &str,
) -> AppResult<Response> {
    let access = jwt::generate_access_token(user_id, is_admin, &state.config.jwt_secret)
        .map_err(|_| AppError::internal("token"))?;
    let refresh = jwt::generate_refresh_token(user_id, &state.config.jwt_secret)
        .map_err(|_| AppError::internal("token"))?;
    let cookie = refresh_cookie(&refresh, state.config.app_env == "production");

    Ok((
        [(SET_COOKIE, cookie)],
        Json(LoginResponse {
            access_token: access,
            user_id: user_id.to_string(),
            username: username.to_string(),
            master_key_envelope: master_key_envelope.to_string(),
            drive_private_key_envelope: drive_private_key_envelope.to_string(),
            public_key: pub_key.to_string(),
            is_admin,
            storage_quota_bytes: quota,
            storage_used_bytes: used,
            color: color.to_string(),
            ..Default::default()
        }),
    )
        .into_response())
}

/// Builds the refresh-token Set-Cookie value — mirrors the Fiber cookie (HttpOnly,
/// SameSite=Lax, 7-day Max-Age, scoped to `/api/auth/refresh`; Secure in production).
fn refresh_cookie(value: &str, secure: bool) -> String {
    let mut c = format!(
        "refresh_token={value}; Max-Age=604800; Path=/api/auth/refresh; HttpOnly; SameSite=Lax"
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// Reads a single cookie value from the `Cookie` header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    let prefix = format!("{name}=");
    raw.split(';')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix(&prefix).map(|v| v.to_string()))
}

fn parse_uuid(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| AppError::internal("invalid user id"))
}

/// Maps a duplicate-key INSERT error to the right 409 — mirrors `isDuplicateKeyError` +
/// the username/email branch in `Register`.
fn map_insert_conflict(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &err {
        if db.code().as_deref() == Some("23505") {
            let constraint = db.constraint().unwrap_or("");
            if constraint.contains("username") {
                return AppError::conflict("username already taken");
            }
            return AppError::conflict("email already registered");
        }
    }
    AppError::internal(format!("register: {err}"))
}

/// `^[a-z0-9_-]{3,32}$` — mirrors `usernameRegexp`.
fn is_valid_username(s: &str) -> bool {
    let len = s.chars().count();
    (3..=32).contains(&len)
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// `^#[0-9a-fA-F]{6}$` — mirrors `colorHexRegexp`.
fn is_valid_hex_color(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|b| b.is_ascii_hexdigit())
}

/// Derives a stable base64 salt from email+purpose — mirrors `deterministicFakeSalt`.
fn deterministic_fake_bytes(email: &str, purpose: &str, len: usize) -> String {
    let input = format!("{email}:{purpose}:kutup-fake-salt-2024");
    let input = input.as_bytes();
    let mut b = vec![0u8; len];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = input[i % input.len()] ^ ((i * 7 + 13) as u8);
    }
    STANDARD.encode(b)
}

fn deterministic_fake_account_envelope(email: &str) -> String {
    let key = STANDARD
        .decode(deterministic_fake_bytes(email, "recovery-envelope-key", 32))
        .expect("deterministic fake key is base64");
    let nonce = STANDARD
        .decode(deterministic_fake_bytes(
            email,
            "recovery-envelope-nonce",
            24,
        ))
        .expect("deterministic fake nonce is base64");
    let envelope = kutup_crypto::account_envelope::seal_with_nonce(
        &[0u8; 32],
        &key,
        kutup_crypto::account_envelope::AccountEnvelopePurpose::RecoveryMasterKey,
        email,
        &nonce,
    )
    .expect("fake recovery envelope inputs are valid");
    STANDARD.encode(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_validation_matches_regex() {
        assert!(is_valid_username("abc"));
        assert!(is_valid_username("a_b-c9"));
        assert!(!is_valid_username("ab")); // too short
        assert!(!is_valid_username("Abc")); // uppercase
        assert!(!is_valid_username("a".repeat(33).as_str())); // too long
        assert!(!is_valid_username("has space"));
    }

    #[test]
    fn hex_color_validation_matches_regex() {
        assert!(is_valid_hex_color("#ef4444"));
        assert!(is_valid_hex_color("#ABCDEF"));
        assert!(!is_valid_hex_color("ef4444")); // missing #
        assert!(!is_valid_hex_color("#fff")); // too short
        assert!(!is_valid_hex_color("#gggggg")); // non-hex
    }

    #[test]
    fn fake_salt_is_deterministic_and_purpose_scoped() {
        let a = deterministic_fake_bytes("x@y.z", "kdf", 16);
        let b = deterministic_fake_bytes("x@y.z", "kdf", 16);
        let c = deterministic_fake_bytes("x@y.z", "login", 16);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // 16 raw bytes → 24-char standard base64.
        assert_eq!(a.len(), 24);
    }

    #[test]
    fn fake_recovery_envelope_is_stable_and_structurally_valid() {
        let first = deterministic_fake_account_envelope("User@Example.com");
        let second = deterministic_fake_account_envelope("User@Example.com");
        assert_eq!(first, second);
        let decoded = kutup_crypto::account_envelope::decode_canonical_b64(&first).unwrap();
        kutup_crypto::account_envelope::validate(
            &decoded,
            kutup_crypto::account_envelope::AccountEnvelopePurpose::RecoveryMasterKey,
            "user@example.com",
            32,
        )
        .unwrap();
    }

    #[test]
    fn account_protection_rejects_unknown_or_modified_parameters() {
        let salt = STANDARD.encode([0u8; 16]);
        assert!(validate_account_protection(1, &salt, 65_536, 3, 1).is_ok());
        assert!(validate_account_protection(0, &salt, 65_536, 3, 1).is_err());
        assert!(validate_account_protection(1, &salt, 8_192, 3, 1).is_err());
        assert!(validate_account_protection(1, &salt, 65_536, 3, 2).is_err());
        assert!(validate_account_protection(1, &STANDARD.encode([0u8; 15]), 65_536, 3, 1).is_err());
    }

    #[test]
    fn registered_account_identity_identifiers_are_key_bound() {
        let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&[9u8; 32]).unwrap();
        let mut request = RegisterRequest {
            public_key: STANDARD.encode(identity.drive_hpke_public_key()),
            account_authority_public_key: STANDARD.encode(identity.authority_public_key()),
            account_authority_key_id: identity.authority_key_id(),
            account_incarnation_id: identity.incarnation_id(),
            drive_signing_public_key: STANDARD.encode(identity.drive_signing_public_key()),
            ..Default::default()
        };
        validate_account_identity(&request).unwrap();
        request.account_incarnation_id = "0".repeat(64);
        assert!(validate_account_identity(&request).is_err());
        request.account_incarnation_id = identity.incarnation_id();
        request.drive_signing_public_key = STANDARD.encode([0u8; 31]);
        assert!(validate_account_identity(&request).is_err());
    }

    #[test]
    fn recovery_proof_requires_canonical_32_bytes() {
        assert!(hash_recovery_proof("").is_err());
        assert!(hash_recovery_proof(&STANDARD.encode([7u8; 31])).is_err());
        assert!(hash_recovery_proof(&STANDARD.encode([7u8; 32])).is_ok());
    }

    #[test]
    fn login_setup_branch_omits_omitempty_fields() {
        let body = serde_json::to_value(LoginResponse {
            requires_setup: true,
            setup_token: Some("tok".into()),
            ..Default::default()
        })
        .unwrap();
        let obj = body.as_object().unwrap();
        // Present (non-omitempty), zero-valued:
        assert_eq!(obj["accessToken"], "");
        assert_eq!(obj["isAdmin"], false);
        assert_eq!(obj["storageQuotaBytes"], 0);
        // omitempty, absent at default:
        assert!(!obj.contains_key("requiresTotp"));
        assert!(!obj.contains_key("preAuthToken"));
        // Set on this branch:
        assert_eq!(obj["requiresSetup"], true);
        assert_eq!(obj["setupToken"], "tok");
    }
}
