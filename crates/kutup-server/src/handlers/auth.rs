//! Auth + user handlers — mirrors `backend/handlers/auth.go`.
//!
//! Registration, login (+ preflight, 2FA), recovery (+ preflight), token refresh,
//! first-login setup, the `/user/*` profile + TOTP endpoints, and the lookup by address.
//! Wire formats, status codes, and SQL match the Go handler exactly; the refresh token
//! is set as the same HttpOnly cookie scoped to `/api/auth/refresh`.

use axum::extract::rejection::JsonRejection;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::HeaderMap;
use axum::response::{AppendHeaders, IntoResponse, Response};
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
use crate::sessions::{self, ClientType};
use crate::{jwt, ratelimit, totp, AppState};

/// bcrypt cost — matches Go's `bcrypt.DefaultCost` (10).
use crate::auth_check::{self, BCRYPT_COST, FAKE_BCRYPT_HASH};

// --- request / response bodies local to auth.go ---
//
// All request bodies use container-level `#[serde(default)]` so a missing JSON field
// deserializes to its zero value — Go's `c.BodyParser` (encoding/json) never errors on
// absent fields, only on malformed JSON.

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterRequest {
    username: String,
    /// A referral code (docs/plans/registration-codes.md): required when the
    /// registration mode is `code`, optional (and recorded) when it is `on`.
    registration_code: Option<String>,
    /// The account's key binding, drawn by the browser (a UUID v4): what its
    /// envelopes are bound to, for good (docs/plans/account-identity.md).
    key_binding: String,
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
    /// The account authority's signature over the Drive keys
    /// (`kutup_crypto::drive_key_binding`), for `username@<server name>`.
    drive_key_binding: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginRequest {
    /// The username or the Kutup address.
    name: String,
    login_key: String,
}

/// Mirrors `auth.LoginResponse`. Non-omitempty fields are always present (empty/zero on
/// the setup/2FA branches); the four omitempty fields are skipped at their defaults.
#[derive(Debug, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    access_token: String,
    /// The server-side session this sign-in created (empty on the 2FA/setup branches).
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
    /// Only for non-web clients (the CLI); web clients get an HttpOnly cookie.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    user_id: String,
    username: String,
    master_key_envelope: String,
    drive_private_key_envelope: String,
    public_key: String,
    is_admin: bool,
    storage_quota_bytes: i64,
    storage_used_bytes: i64,
    color: String,
    /// The account's key binding, what its envelopes carry; given only with
    /// the session.
    #[serde(skip_serializing_if = "String::is_empty")]
    envelope_binding: String,
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
    /// As at sign-in.
    name: String,
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
    /// How long file versions are kept: 7, 30, 90, 180, 365 or 3650 days.
    version_retention_days: Option<i32>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct CodeRequest {
    code: String,
}

/// `?name=` query for the preflight endpoints.
#[derive(Debug, Deserialize)]
pub struct NameQuery {
    #[serde(default)]
    name: Option<String>,
}

impl NameQuery {
    fn name(self) -> AppResult<String> {
        self.name
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| AppError::bad_request("name required"))
    }
}

/// The account a person names at sign-in (docs/plans/account-identity.md):
/// its username, or its Kutup address on this server.
pub(crate) async fn account_by_name(state: &AppState, name: &str) -> AppResult<Option<Uuid>> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name.len() > 320 {
        return Ok(None);
    }
    let local = match name.split_once('@') {
        Some((local, domain)) if domain == state.config.chat_server_name.to_ascii_lowercase() => {
            local
        }
        Some(_) => return Ok(None),
        None => name.as_str(),
    };
    Ok(
        sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(local)
            .fetch_optional(&state.pool)
            .await?,
    )
}

/// A name as one account would answer to it: trimmed, lowercased, and an
/// address on this server reduced to its username, so `ada` and
/// `ada@<this server>` get the same fake answers and lockout as a real
/// account's do.
fn canonical_name(state: &AppState, name: &str) -> String {
    let name = name.trim().to_ascii_lowercase();
    let server = state.config.chat_server_name.to_ascii_lowercase();
    match name.rsplit_once('@') {
        Some((local, domain)) if domain == server && !local.is_empty() => local.to_owned(),
        _ => name,
    }
}

static FAKE_ACCOUNTS_KEY: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();

/// The server's own key for fake answers (stored once, as its other keys).
pub(crate) async fn fake_accounts_key(state: &AppState) -> AppResult<[u8; 32]> {
    FAKE_ACCOUNTS_KEY
        .get_or_try_init(|| async {
            crate::server_keys::load_or_create(
                &state.pool,
                crate::server_keys::GeneratedKey::FakeAccounts,
            )
            .await
        })
        .await
        .copied()
        .map_err(|_| AppError::internal("fake account key"))
}

/// A fake binding for a name that is not an account, the same each time,
/// shaped as a real one (a key binding), so preflight tells nothing.
fn fake_binding(secret: &[u8], name: &str) -> String {
    let bytes = STANDARD
        .decode(deterministic_fake_bytes(
            secret,
            name,
            "envelope-binding",
            16,
        ))
        .unwrap_or_else(|_| vec![0; 16]);
    let mut b = [0u8; 16];
    b.copy_from_slice(&bytes[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Uuid::from_bytes(b).to_string()
}

/// Mirrors the `fiber.Map` returned by `CompleteSetup`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompleteSetupResponse {
    access_token: String,
    session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    user_id: String,
    username: String,
    is_admin: bool,
    storage_quota_bytes: i64,
    storage_used_bytes: i64,
}

fn is_false(b: &bool) -> bool {
    !*b
}

pub(crate) fn decode_canonical_base64_exact(
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

/// A first-login account's temporary password as the administrator's browser
/// derived it (docs/plans/account-identity.md): the login key, with the
/// salt and parameters it came from. The server never sees the password,
/// as for any other account; sign-in derives the same way, and setup then
/// replaces all of it with the account's own.
#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct SetupKey {
    pub login_key: String,
    pub account_protection_suite: u16,
    pub account_protection_salt: String,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
}

impl SetupKey {
    /// Checked as an account's own protection is; the login key's hash to store.
    pub(crate) fn checked_hash(&self) -> AppResult<String> {
        validate_account_protection(
            self.account_protection_suite,
            &self.account_protection_salt,
            self.argon_memory_kib,
            self.argon_iterations,
            self.argon_parallelism,
        )?;
        let login_key = decode_canonical_base64_exact(&self.login_key, 32, "setup.loginKey")?;
        bcrypt::hash(login_key, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))
    }

    /// Derived here, once, from a password the server was given (the
    /// break-glass administrator in ADMIN_ACCOUNT).
    pub(crate) fn derive(password: &str) -> anyhow::Result<Self> {
        use kutup_crypto::kdf::{
            derive_account_protection_keys, AccountProtectionParameters, AccountProtectionSuiteId,
            ACCOUNT_PROTECTION_SALT_LEN,
        };
        let mut salt = [0u8; ACCOUNT_PROTECTION_SALT_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let parameters = AccountProtectionParameters::V1;
        let keys = derive_account_protection_keys(password, &salt, parameters)?;
        Ok(SetupKey {
            login_key: STANDARD.encode(keys.login_key.as_slice()),
            account_protection_suite: AccountProtectionSuiteId::Argon2idHkdfSha256V1.as_u16(),
            account_protection_salt: STANDARD.encode(salt),
            argon_memory_kib: parameters.memory_kib,
            argon_iterations: parameters.iterations,
            argon_parallelism: parameters.parallelism,
        })
    }
}

/// A key binding as drawn: a UUID v4, lowercase and hyphenated.
pub(crate) fn is_key_binding(value: &str) -> bool {
    Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.hyphenated().to_string() == value)
}

pub(crate) fn validate_account_envelope(
    value: &str,
    purpose: kutup_crypto::account_envelope::AccountEnvelopePurpose,
    binding: &str,
    field: &str,
) -> AppResult<()> {
    let envelope = kutup_crypto::account_envelope::decode_canonical_b64(value)
        .map_err(|_| AppError::bad_request(format!("invalid {field} encoding")))?;
    kutup_crypto::account_envelope::validate_for(&envelope, purpose, binding, &[])
        .map(drop)
        .map_err(|_| AppError::bad_request(format!("invalid {field} binding")))
}

/// The Drive key binding, required, checked against the keys and `account`.
fn checked_drive_key_binding(req: &RegisterRequest, account: &str) -> AppResult<String> {
    if req.drive_key_binding.is_empty() {
        return Err(AppError::bad_request("driveKeyBinding is required"));
    }
    verify_drive_key_binding(
        account,
        &req.account_authority_public_key,
        &req.public_key,
        &req.drive_signing_public_key,
        &req.drive_key_binding,
    )?;
    Ok(req.drive_key_binding.clone())
}

/// Checks that the authority vouches for these Drive keys of `account`.
pub(crate) fn verify_drive_key_binding(
    account: &str,
    authority: &str,
    hpke: &str,
    signing: &str,
    binding: &str,
) -> AppResult<()> {
    let key = |value: &str, field: &str| -> AppResult<[u8; 32]> {
        Ok(decode_canonical_base64_exact(value, 32, field)?
            .try_into()
            .expect("validated length"))
    };
    let signature = decode_canonical_base64_exact(binding, 64, "driveKeyBinding")?;
    kutup_crypto::drive_key_binding::verify(
        account,
        &key(authority, "accountAuthorityPublicKey")?,
        &key(hpke, "publicKey")?,
        &key(signing, "driveSigningPublicKey")?,
        &signature,
    )
    .map_err(|_| AppError::bad_request("driveKeyBinding does not match the account's keys"))
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

pub(crate) fn hash_recovery_proof(proof: &str) -> AppResult<String> {
    if proof.is_empty() {
        return Err(AppError::bad_request("recoveryProof is required"));
    }
    let proof = decode_canonical_base64_exact(proof, 32, "recoveryProof")?;
    bcrypt::hash(proof, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))
}

// --- handlers ---

/// Whether a sign-up may go ahead under the registration mode, and the hash
/// of the referral code it brings (to use up with the account). The code is
/// checked here, cheaply and before any other work, and taken in the
/// account's transaction. One answer for every code that admits no one.
async fn admitted(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    code: Option<&str>,
) -> AppResult<Option<[u8; 32]>> {
    use crate::registration::RegistrationMode;
    let mode = crate::registration::mode(state).await?;
    let code = code.map(str::trim).filter(|code| !code.is_empty());
    match (mode, code) {
        (RegistrationMode::Off, _) => {
            return Err(AppError::forbidden("registration is closed")
                .with_details(serde_json::json!({ "code": "registrationClosed" })))
        }
        (RegistrationMode::Code, None) => {
            return Err(AppError::forbidden("a referral code is required")
                .with_details(serde_json::json!({ "code": "registrationCodeRequired" })))
        }
        (RegistrationMode::On, None) => return Ok(None),
        (_, Some(_)) => {}
    }
    let code = code.expect("matched above");
    let client =
        crate::middleware::client_key(crate::middleware::client_ip_from_headers(headers), peer);
    Ok(Some(check_code(state, &client, code).await?))
}

/// The hash of `code` if it can admit a sign-up now; counts a code that
/// cannot against `client` (sign-ups and checks together).
async fn check_code(state: &AppState, client: &str, code: &str) -> AppResult<[u8; 32]> {
    crate::registration::attempt(client)?;
    let key = crate::registration::codes_key(&state.pool).await?;
    // Something that is no code is looked up as a hash of nothing: the same
    // work, and the same answer, as an unknown code.
    let canonical = crate::registration::canonical(code).unwrap_or_default();
    let hash = crate::registration::hash(&key, &canonical);
    if canonical.is_empty() || !crate::registration::redeemable(&state.pool, &hash).await? {
        return Err(crate::registration::invalid());
    }
    crate::registration::attempt_succeeded(client);
    Ok(hash)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCodeCheck {
    pub code: String,
}

/// `POST /api/auth/registration-code/check` — whether a referral code can
/// admit a sign-up now, before the sign-up page derives the account's keys.
/// It uses nothing up; the same answer for every code that cannot.
#[utoipa::path(
    post,
    path = "/api/auth/registration-code/check",
    tag = "auth",
    request_body = RegistrationCodeCheck,
    responses(
        (status = 204, description = "The code can admit a sign-up now"),
        (status = 403, description = "It cannot (registrationCodeInvalid), or registration is closed (registrationClosed)"),
        (status = 429, description = "Too many checks or wrong codes from this address (rateLimited)")
    )
)]
pub async fn check_registration_code(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegistrationCodeCheck>,
) -> AppResult<Response> {
    if crate::registration::mode(&state).await? == crate::registration::RegistrationMode::Off {
        return Err(AppError::forbidden("registration is closed")
            .with_details(serde_json::json!({ "code": "registrationClosed" })));
    }
    let client =
        crate::middleware::client_key(crate::middleware::client_ip_from_headers(&headers), peer);
    check_code(&state, &client, &req.code).await?;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/auth/settings` — mirrors `GetPublicSettings`.
#[utoipa::path(
    get,
    path = "/api/auth/settings",
    tag = "auth",
    responses((status = 200, description = "Public registration settings", body = SettingsResponse))
)]
pub async fn get_public_settings(State(state): State<AppState>) -> AppResult<Response> {
    let registration_mode = crate::registration::mode(&state).await?;
    let federation_enabled = match state.federation.as_ref() {
        Some(federation) => {
            federation
                .policy()
                .feature_is_publicly_enabled(crate::federation::FederationPolicyFeature::Chat)
                .await?
        }
        None => false,
    };
    // Sealed delivery between two accounts of this server needs only the
    // server's identity and its sealed-sender service. The federation policy
    // decides whether other servers can be reached, not whether this one
    // offers sealed delivery: closing federation must not switch off media in
    // direct chats on the server itself.
    let sealed_sender_policy = if state.sealed_sender.is_some() {
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
    let mls_groups = crate::chat_mls::policy::advertised_policy(&state)
        .await?
        .is_some();
    // Chat has no storage of its own: its backup and media count against the
    // account's one pool (crate::storage_pool), whose default this advertises.
    let account_default_quota_bytes = crate::storage_pool::default_quota(&state.pool).await? as u64;
    let chat_mailbox_retention_days = crate::site_settings::chat_delivery_retention_days(
        &state.pool,
        crate::site_settings::CHAT_MAILBOX_RETENTION_DAYS,
        state.config.chat_mailbox_retention_days,
    )
    .await? as u32;
    let chat_media_delivery_retention_days = crate::site_settings::chat_delivery_retention_days(
        &state.pool,
        crate::site_settings::CHAT_MEDIA_DELIVERY_RETENTION_DAYS,
        state.config.chat_media_delivery_retention_days,
    )
    .await? as u32;
    let chat = kutup_chat_proto::ChatCapabilities {
        mailbox_retention_days: chat_mailbox_retention_days,
        device_expiry_days: state
            .config
            .chat_device_expiry_days
            .try_into()
            .unwrap_or(u32::MAX),
        maximum_active_devices: state.config.chat_max_active_devices,
        server_name: Some(state.config.chat_server_name.clone()),
        federation: federation_enabled,
        sealed_sender: sealed_sender_policy.is_some(),
        mls_groups,
        link_previews: state.config.chat_link_previews,
        web_push_public_key: state
            .web_push
            .as_ref()
            .map(|push| push.public_key().to_owned()),
        group_calls: mls_groups && crate::chat_mls::hosts_group_calls(&state),
        call_links: crate::chat_mls::hosts_group_calls(&state),
        media: Some(
            kutup_chat_proto::ChatMediaCapabilitiesV1::v1(
                state.config.chat_media_max_plaintext_bytes,
            )
            .map_err(AppError::internal)?,
        ),
        backup: Some(
            kutup_chat_proto::ChatBackupCapabilitiesV1::v1(
                account_default_quota_bytes,
                chat_media_delivery_retention_days,
            )
            .map_err(AppError::internal)?,
        ),
        sealed_sender_policy,
        ..Default::default()
    };
    Ok(Json(SettingsResponse {
        registration_mode,
        chat,
        apps: state.config.apps.clone(),
        feedback: crate::models::FeedbackSettings {
            github_repository: state.config.feedback_github_repository.clone(),
        },
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<RegisterRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    // Who may register, before anything costly or visible
    // (docs/plans/registration-codes.md).
    let code_hash = admitted(&state, peer, &headers, req.registration_code.as_deref()).await?;

    if req.login_key.is_empty() {
        return Err(AppError::bad_request("missing required fields"));
    }
    if !is_key_binding(&req.key_binding) {
        return Err(AppError::bad_request("keyBinding is a lowercase UUID v4"));
    }
    if !is_valid_username(&req.username) {
        return Err(AppError::bad_request(
            "invalid username: must be 3-32 chars, lowercase letters, numbers, _ and -",
        ));
    }
    if crate::mail::RESERVED_LOCAL_PARTS.contains(&req.username.as_str()) {
        return Err(AppError::bad_request(
            "this username is reserved for the server",
        ));
    }
    if crate::mail::groups::is_group_name(
        &state.pool,
        &req.username,
        &state.config.chat_server_name,
    )
    .await?
    {
        return Err(AppError::conflict("this username is taken"));
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
        &req.key_binding,
        "masterKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.recovery_key_envelope,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &req.key_binding,
        "recoveryKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.drive_private_key_envelope,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &req.key_binding,
        "drivePrivateKeyEnvelope",
    )?;
    validate_account_identity(&req)?;
    let drive_key_binding = checked_drive_key_binding(
        &req,
        &format!("{}@{}", req.username, state.config.chat_server_name),
    )?;

    let login_key_bytes = decode_canonical_base64_exact(&req.login_key, 32, "loginKey")?;
    let hash =
        bcrypt::hash(login_key_bytes, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))?;

    // This is an HKDF-derived authorization proof, never the recovery entropy
    // that opens recoveryKeyEnvelope.
    let recovery_verifier = hash_recovery_proof(&req.recovery_proof)?;
    let storage_quota_bytes = crate::storage_pool::default_quota(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    let res: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        r#"INSERT INTO users (
            username, master_key_envelope, recovery_key_envelope,
            drive_private_key_envelope,
            public_key, account_authority_public_key, account_authority_key_id,
            account_incarnation_id, drive_signing_public_key,
            account_protection_suite, account_protection_salt,
            argon_memory_kib, argon_iterations, argon_parallelism,
            login_key_hash, recovery_key_verifier, storage_quota_bytes, drive_key_binding,
            key_binding
        ) VALUES ($2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$1)
        RETURNING id"#,
    )
    .bind(&req.key_binding)
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
    .bind(storage_quota_bytes)
    .bind(&drive_key_binding)
    .fetch_one(&mut *tx)
    .await;

    let user_id = match res {
        Ok(id) => id,
        Err(err) => return Err(map_insert_conflict(err)),
    };
    // The code is used up with the account (a failure below rolls both back):
    // checked above, taken here, where the row's lock orders concurrent
    // sign-ups, so a code with N uses admits N accounts.
    if let Some(hash) = &code_hash {
        let code_id = crate::registration::redeem(&mut tx, hash)
            .await?
            .ok_or_else(crate::registration::invalid)?;
        crate::registration::record_use(&mut tx, code_id, user_id).await?;
    }
    // The account's mail address comes with it (a GET never makes one).
    if !crate::handlers::mail_keys::create_own_address(
        &mut tx,
        &state.config.chat_server_name,
        user_id,
        &req.username,
    )
    .await?
    {
        return Err(AppError::conflict("username already taken"));
    }
    tx.commit().await?;
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
    params(("name" = String, Query, description = "The username or the Kutup address")),
    responses((status = 200, description = "Account-protection suite, parameters and envelope binding", body = PreflightLoginResponse))
)]
pub async fn get_login_preflight(
    State(state): State<AppState>,
    Query(q): Query<NameQuery>,
) -> AppResult<Response> {
    let name = q.name()?;
    let account = account_by_name(&state, &name).await?;
    // Every account has a salt, one an administrator made too (its
    // temporary password is derived as any other), so nothing here tells
    // a new account, an unknown name or a real one apart.
    let row: Option<(i16, String, i32, i32, i32)> = match account {
        Some(id) => sqlx::query_as(
            "SELECT account_protection_suite, account_protection_salt, argon_memory_kib, argon_iterations, argon_parallelism FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?,
        None => None,
    };

    let (suite, salt, memory_kib, iterations, parallelism) = match row {
        Some(row) => row,
        None => (
            kutup_crypto::kdf::AccountProtectionSuiteId::Argon2idHkdfSha256V1.as_u16() as i16,
            deterministic_fake_bytes(
                &fake_accounts_key(&state).await?,
                &canonical_name(&state, &name),
                "account-protection",
                16,
            ),
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

/// `POST /api/user/reauth` body: the login key derived from the typed
/// password, as for sign-in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReauthRequest {
    pub login_key: String,
}

/// `POST /api/user/reauth` — checks the signed-in account's password again
/// (Kutup Pass's lock, docs/plans/pass.md) exactly as sign-in checks it: the
/// login key against `login_key_hash`, under the same per-account lockout and
/// per-address rate limit. Nothing comes back but yes or no; the session
/// already holds what the password would unlock.
#[utoipa::path(
    post,
    path = "/api/user/reauth",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = ReauthRequest,
    responses(
        (status = 204, description = "The password is the account's"),
        (status = 401, description = "It is not"),
        (status = 429, description = "Too many failed attempts (the sign-in lockout)")
    )
)]
pub async fn reauth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<ReauthRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    verify_account_login_key(&state, peer, &headers, &user, &req.login_key).await?;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

/// Checks a signed-in account's password (as the login key the client
/// derived from it) the way sign-in does (`auth_check`): against
/// `login_key_hash`, under the same lockout and ceiling, misses here and at
/// sign-in counting together. The caller is signed in to the account, so it
/// is never held by the unknown-client ceiling. `Err` is 401 for a wrong
/// password, 429 while held.
pub async fn verify_account_login_key(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    user: &AuthUser,
    login_key: &str,
) -> AppResult<()> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let login_key = STANDARD
        .decode(login_key)
        .map_err(|_| AppError::bad_request("invalid loginKey"))?;
    let login_key_hash: Option<String> =
        sqlx::query_scalar("SELECT login_key_hash FROM users WHERE id = $1 AND is_active")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let client = auth_check::Client::from_headers(state, headers, peer)
        .await?
        .signed_in_as(user_id);
    let epoch = login_key_hash.as_deref().map(auth_check::credential_epoch);
    let guard = auth_check::guard(&client, Some(user_id), "", epoch.as_ref().map(|e| &e[..]))?;
    if !guard.verify(Some(&login_key), login_key_hash.as_deref()) {
        tracing::warn!(user_id = %user_id, "account password re-check failed");
        return Err(AppError::invalid_credentials());
    }
    Ok(())
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> AppResult<Response> {
    let client = direct_sign_in_client(&headers)?;
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;

    // The order of `auth_check`: the secret is read before the name is looked
    // up, the hash checked (at full cost for a name that is no account) before
    // anything about the account is said, and every miss is the same 401.
    let login_key_bytes = STANDARD
        .decode(&req.login_key)
        .map_err(|_| AppError::bad_request("invalid loginKey"))?;
    let name = req.name.trim().to_ascii_lowercase();
    let account = account_by_name(&state, &name).await?;

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
        bool,
        String,
        String,
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT id, login_key_hash, master_key_envelope,
                  drive_private_key_envelope, public_key,
                  totp_enabled, is_admin, storage_quota_bytes, storage_used_bytes, is_active,
                  is_first_login,
                  COALESCE(username, ''), COALESCE(color, ''), COALESCE(key_binding, '')
           FROM users WHERE id = $1"#,
    )
    .bind(account)
    .fetch_optional(&state.pool)
    .await?;

    let hash = row.as_ref().map(|row| row.1.as_str());
    let asker = auth_check::Client::from_headers(&state, &headers, peer).await?;
    let epoch = hash.map(auth_check::credential_epoch);
    let guard = auth_check::guard(
        &asker,
        account,
        &canonical_name(&state, &name),
        epoch.as_ref().map(|e| &e[..]),
    )?;
    if !guard.verify(Some(&login_key_bytes), hash) {
        return Err(AppError::invalid_credentials());
    }
    let Some((
        id,
        _,
        master_key_envelope,
        drive_private_key_envelope,
        pub_key,
        totp_enabled,
        is_admin,
        quota_bytes,
        used_bytes,
        is_active,
        is_first_login,
        username,
        color,
        envelope_binding,
    )) = row
    else {
        return Err(AppError::invalid_credentials());
    };
    // Said only to someone who knows the password.
    if !is_active {
        return Err(AppError::unauthorized("account disabled"));
    }

    let user_id = id.to_string();

    // First-login account — no key material yet. Its username comes along:
    // the new keys' Drive key binding names the account's address.
    if is_first_login {
        let setup_token = jwt::generate_setup_token(&user_id, &state.config.jwt_secret)
            .map_err(|_| AppError::internal("token"))?;
        return Ok(Json(LoginResponse {
            requires_setup: true,
            setup_token: Some(setup_token),
            username,
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
        &headers,
        client,
        &user_id,
        &username,
        &master_key_envelope,
        &drive_private_key_envelope,
        &pub_key,
        is_admin,
        quota_bytes,
        used_bytes,
        &color,
        &envelope_binding,
    )
    .await
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
    headers: HeaderMap,
    body: Result<Json<TwoFALoginRequest>, JsonRejection>,
) -> AppResult<Response> {
    let client = direct_sign_in_client(&headers)?;
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
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT totp_secret, master_key_envelope,
                  drive_private_key_envelope, public_key,
                  is_admin, storage_quota_bytes, storage_used_bytes,
                  COALESCE(username, ''), is_active, COALESCE(color, ''),
                  COALESCE(key_binding, '')
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
        envelope_binding,
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
        &headers,
        client,
        &user_id,
        &username,
        &master_key_envelope,
        &drive_private_key_envelope,
        &pub_key,
        is_admin,
        quota_bytes,
        used_bytes,
        &color,
        &envelope_binding,
    )
    .await
}

/// `GET /api/auth/recover/preflight` — mirrors `GetRecoveryPreflight`.
#[utoipa::path(
    get,
    path = "/api/auth/recover/preflight",
    tag = "auth",
    params(("name" = String, Query, description = "The username or the Kutup address")),
    responses((status = 200, description = "Encrypted recovery key material and its binding", body = PreflightRecoverResponse))
)]
pub async fn get_recovery_preflight(
    State(state): State<AppState>,
    Query(q): Query<NameQuery>,
) -> AppResult<Response> {
    let name = q.name()?;
    let row: Option<(String, String)> = match account_by_name(&state, &name).await? {
        Some(id) => {
            sqlx::query_as(
                "SELECT recovery_key_envelope, COALESCE(key_binding, '') FROM users
                  WHERE id = $1 AND key_binding IS NOT NULL",
            )
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
        }
        None => None,
    };

    let resp = match row {
        Some((recovery_key_envelope, envelope_binding)) => PreflightRecoverResponse {
            recovery_key_envelope,
            envelope_binding,
        },
        None => {
            let secret = fake_accounts_key(&state).await?;
            let binding = fake_binding(&secret, &canonical_name(&state, &name));
            PreflightRecoverResponse {
                recovery_key_envelope: deterministic_fake_account_envelope(&secret, &binding),
                envelope_binding: binding,
            }
        }
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
    // The proof is read before the name is looked up, and checked first, at
    // full cost: an unknown name, an account without a verifier and a wrong
    // phrase are all the same 401, and nothing about the account (its
    // binding) is checked before it.
    let proof = decode_canonical_base64_exact(&req.recovery_proof, 32, "recoveryProof")?;
    let account = account_by_name(&state, &req.name).await?;
    let stored: Option<(String, String)> =
        match account {
            Some(id) => sqlx::query_as(
                "SELECT recovery_key_verifier, COALESCE(key_binding, '') FROM users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&state.pool)
            .await?,
            None => None,
        };
    let (Some(user_id), Some((stored_verifier, binding))) = (account, stored) else {
        let _ = bcrypt::verify(&proof, &FAKE_BCRYPT_HASH);
        return Err(AppError::unauthorized("invalid recovery proof"));
    };
    if !auth_check::verify_hash(&proof, &stored_verifier) {
        return Err(AppError::unauthorized("invalid recovery proof"));
    }
    validate_account_envelope(
        &req.new_master_key_envelope,
        kutup_crypto::account_envelope::AccountEnvelopePurpose::PasswordMasterKey,
        &binding,
        "newMasterKeyEnvelope",
    )?;

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
           WHERE id = $8"#,
    )
    .bind(&hash)
    .bind(&req.new_master_key_envelope)
    .bind(i16::try_from(req.new_account_protection_suite).unwrap_or(i16::MAX))
    .bind(&req.new_account_protection_salt)
    .bind(i32::try_from(req.new_argon_memory_kib).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.new_argon_iterations).unwrap_or(i32::MAX))
    .bind(i32::try_from(req.new_argon_parallelism).unwrap_or(i32::MAX))
    .bind(user_id)
    .execute(&state.pool)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::unauthorized("invalid recovery proof"));
    }
    // New password, new key wrapping: every existing sign-in ends.
    sessions::revoke_all_for_user(&state.pool, user_id, None).await?;
    Ok(Json(MessageResponse {
        message: "password reset".to_string(),
    })
    .into_response())
}

/// `POST /api/auth/refresh` — rotates the session's refresh token. Web clients present
/// it in the HttpOnly cookie on their own origin and receive the next one the same way;
/// the CLI presents and receives it in the JSON body.
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "auth",
    request_body(content = RefreshRequest, description = "CLI only; web clients use the refresh_token cookie"),
    responses((status = 200, description = "Fresh access token", body = RefreshResponse))
)]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<RefreshRequest>>,
) -> AppResult<Response> {
    let from_cookie = cookie_value(&headers, REFRESH_COOKIE).filter(|t| !t.is_empty());
    let token = match &from_cookie {
        Some(t) => t.clone(),
        None => body.map(|Json(b)| b.refresh_token).unwrap_or_default(),
    };
    if token.is_empty() {
        return Err(AppError::unauthorized("missing refresh token"));
    }
    // A failed web refresh also clears the cookie: there is nothing left to keep.
    let outcome = match sessions::refresh(&state.pool, &token, from_cookie.is_some()).await {
        Ok(o) => o,
        Err(err) if from_cookie.is_some() => {
            return Ok((
                [(SET_COOKIE, clear_refresh_cookie(&state))],
                err.into_response(),
            )
                .into_response())
        }
        Err(err) => return Err(err),
    };
    let (session, next) = match outcome {
        sessions::RefreshOutcome::Rotated {
            session,
            refresh_token,
        } => (session, Some(refresh_token)),
        sessions::RefreshOutcome::Grace { session } => (session, None),
    };
    let access = jwt::generate_access_token(
        &session.user_id.to_string(),
        session.is_admin,
        &session.session_id.to_string(),
        &state.config.jwt_secret,
    )
    .map_err(|_| AppError::internal("token"))?;
    let body = RefreshResponse {
        access_token: access,
        session_id: session.session_id.to_string(),
        refresh_token: if session.client.uses_cookie() {
            None
        } else {
            next.clone()
        },
    };
    match (session.client.uses_cookie(), next) {
        (true, Some(next)) => {
            Ok(([(SET_COOKIE, refresh_cookie(&state, &next))], Json(body)).into_response())
        }
        _ => Ok(Json(body).into_response()),
    }
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
    type Row = (
        Uuid,
        String,
        String,
        String,
        bool,
        i64,
        i64,
        bool,
        String,
        i32,
    );
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT id, COALESCE(key_binding, ''), COALESCE(username, ''), public_key, totp_enabled,
                  storage_quota_bytes, storage_used_bytes,
                  is_admin, COALESCE(color, ''), version_retention_days
           FROM users WHERE id = $1"#,
    )
    .bind(parse_uuid(&user.user_id)?)
    .fetch_optional(&state.pool)
    .await?;

    let Some((
        id,
        envelope_binding,
        username,
        public_key,
        totp_enabled,
        quota,
        used,
        is_admin,
        color,
        version_retention_days,
    )) = row
    else {
        return Err(AppError::not_found("user not found"));
    };
    let address = if username.is_empty() {
        String::new()
    } else {
        format!("{username}@{}", state.config.chat_server_name)
    };
    Ok(Json(MeResponse {
        id: id.to_string(),
        address,
        envelope_binding,
        username,
        public_key,
        totp_enabled,
        storage_quota_bytes: quota,
        storage_used_bytes: used,
        is_admin,
        color,
        version_retention_days,
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
    let Json(req) = body.map_err(|rejection| {
        if rejection.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
            AppError::new(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            )
        } else {
            AppError::bad_request("invalid request body")
        }
    })?;

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

    if let Some(days) = req.version_retention_days {
        if !crate::version_retention::RETENTION_DAYS.contains(&days) {
            return Err(AppError::bad_request(
                "versionRetentionDays must be 7, 30, 90, 180, 365 or 3650",
            ));
        }
        sqlx::query("UPDATE users SET version_retention_days = $1 WHERE id = $2")
            .bind(days)
            .bind(parse_uuid(&user.user_id)?)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("failed to update version retention"))?;
    }

    Ok(Json(OkResponse { ok: true }).into_response())
}

/// The username in `address` when it is an account address of this server
/// (`username@<server name>`), which looks like an email address but is not
/// one.
fn local_account_username(address: &str, server_name: &str) -> Option<String> {
    let (username, server) = address.trim().rsplit_once('@')?;
    if username.is_empty() || !server.eq_ignore_ascii_case(server_name) {
        return None;
    }
    Some(username.to_ascii_lowercase())
}

/// `GET /api/users/by-address/:address` — an account here, by the address a
/// person would type to share with it: its Kutup address
/// (`username@<this server>`).
#[utoipa::path(
    get,
    path = "/api/users/by-address/{address}",
    tag = "auth",
    security(("BearerAuth" = [])),
    params(("address" = String, Path, description = "Target account's Kutup address (username@server)")),
    responses((status = 200, description = "User id + public key", body = UserLookupResponse), (status = 404, description = "No such account here"))
)]
pub async fn get_user_by_address(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(address): Path<String>,
) -> AppResult<Response> {
    type Row = (
        Uuid,
        Option<String>,
        String,
        String,
        String,
        String,
        Option<String>,
    );
    // People are found by their Kutup address (docs/plans/account-identity.md).
    let row: Option<Row> =
        match local_account_username(&address, &state.config.chat_server_name) {
            Some(username) => sqlx::query_as(
                "SELECT id, username, public_key, account_incarnation_id, drive_signing_public_key,
                        account_authority_public_key, drive_key_binding
                 FROM users WHERE username = $1 AND is_active = true",
            )
            .bind(&username)
            .fetch_optional(&state.pool)
            .await?,
            None => None,
        };
    let Some((id, username, public_key, incarnation_id, signing_public_key, authority, binding)) =
        row
    else {
        return Err(AppError::not_found("user not found"));
    };
    let username = username
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::conflict("recipient identity is unavailable"))?;
    let domain = state.config.chat_server_name.as_str();
    Ok(Json(UserLookupResponse {
        user_id: id.to_string(),
        account: format!("{username}@{domain}"),
        drive_hpke_public_key: public_key,
        account_incarnation_id: incarnation_id,
        drive_signing_public_key: signing_public_key,
        account_authority_public_key: authority,
        drive_key_binding: binding,
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
    let username: Option<Option<String>> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(parse_uuid(&user.user_id)?)
            .fetch_optional(&state.pool)
            .await?;
    let Some(username) = username else {
        return Err(AppError::not_found("user not found"));
    };
    // Labelled with the account's identity, its Kutup address.
    let label = format!(
        "{}@{}",
        username.unwrap_or_default(),
        state.config.chat_server_name
    );

    let (secret, qr_uri) =
        totp::generate_totp(&label, "Kutup").map_err(|_| AppError::internal("totp"))?;

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
    let client = direct_sign_in_client(&headers)?;
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let user_id = jwt::validate_setup_token(token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("invalid setup token"))?;

    let account: Option<(bool, String)> =
        sqlx::query_as("SELECT is_active, COALESCE(username, '') FROM users WHERE id = $1")
            .bind(parse_uuid(&user_id).map_err(|_| AppError::unauthorized("unauthorized"))?)
            .fetch_optional(&state.pool)
            .await?;
    let Some((true, account_username)) = account else {
        return Err(AppError::unauthorized("account disabled"));
    };

    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    // The keys made here are bound to the key binding the browser drew.
    if !is_key_binding(&req.key_binding) {
        return Err(AppError::bad_request("keyBinding is a lowercase UUID v4"));
    }
    let account_binding = req.key_binding.clone();

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
        &account_binding,
        "masterKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.recovery_key_envelope,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &account_binding,
        "recoveryKeyEnvelope",
    )?;
    validate_account_envelope(
        &req.drive_private_key_envelope,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &account_binding,
        "drivePrivateKeyEnvelope",
    )?;
    validate_account_identity(&req)?;
    let drive_key_binding = checked_drive_key_binding(
        &req,
        &format!("{account_username}@{}", state.config.chat_server_name),
    )?;
    let login_key_bytes = decode_canonical_base64_exact(&req.login_key, 32, "loginKey")?;
    let hash =
        bcrypt::hash(login_key_bytes, BCRYPT_COST).map_err(|_| AppError::internal("bcrypt"))?;
    let recovery_verifier = hash_recovery_proof(&req.recovery_proof)?;

    let uid = parse_uuid(&user_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    // Only while the account is still a first-login one — prevents replay
    // after setup completes.
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
              drive_key_binding = $17,
              key_binding = $18,
              is_first_login = false, updated_at = NOW()
           WHERE id = $16 AND is_first_login"#,
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
    .bind(&drive_key_binding)
    .bind(&account_binding)
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

    let issued = sessions::create(&state.pool, uid, client, None, user_agent(&headers)).await?;
    let access = jwt::generate_access_token(
        &user_id,
        is_admin,
        &issued.session_id.to_string(),
        &state.config.jwt_secret,
    )
    .map_err(|_| AppError::internal("token"))?;
    let body = CompleteSetupResponse {
        access_token: access,
        session_id: issued.session_id.to_string(),
        refresh_token: (!client.uses_cookie()).then(|| issued.refresh_token.clone()),
        user_id,
        username,
        is_admin,
        storage_quota_bytes: quota,
        storage_used_bytes: used,
    };
    if client.uses_cookie() {
        Ok((
            [(SET_COOKIE, refresh_cookie(&state, &issued.refresh_token))],
            Json(body),
        )
            .into_response())
    } else {
        Ok(Json(body).into_response())
    }
}

// --- helpers ---

/// The client a password sign-in comes from (`X-Kutup-Client`). Only clients that
/// sign in directly are accepted here; drive and chat get forked sessions.
pub(crate) fn direct_sign_in_client(headers: &HeaderMap) -> AppResult<ClientType> {
    let client = client_header(headers)
        .ok_or_else(|| AppError::bad_request("missing or unknown X-Kutup-Client header"))?;
    if !client.signs_in_directly() {
        return Err(AppError::bad_request(
            "this client signs in through the account app",
        ));
    }
    Ok(client)
}

pub(crate) fn client_header(headers: &HeaderMap) -> Option<ClientType> {
    headers
        .get(CLIENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(ClientType::parse)
}

pub(crate) fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers.get(USER_AGENT).and_then(|v| v.to_str().ok())
}

#[allow(clippy::too_many_arguments)]
async fn issue_tokens_and_respond(
    state: &AppState,
    headers: &HeaderMap,
    client: ClientType,
    user_id: &str,
    username: &str,
    master_key_envelope: &str,
    drive_private_key_envelope: &str,
    pub_key: &str,
    is_admin: bool,
    quota: i64,
    used: i64,
    color: &str,
    envelope_binding: &str,
) -> AppResult<Response> {
    let uid = parse_uuid(user_id)?;
    let issued = sessions::create(&state.pool, uid, client, None, user_agent(headers)).await?;
    let access = jwt::generate_access_token(
        user_id,
        is_admin,
        &issued.session_id.to_string(),
        &state.config.jwt_secret,
    )
    .map_err(|_| AppError::internal("token"))?;
    let body = LoginResponse {
        access_token: access,
        session_id: issued.session_id.to_string(),
        refresh_token: (!client.uses_cookie()).then(|| issued.refresh_token.clone()),
        user_id: user_id.to_string(),
        username: username.to_string(),
        master_key_envelope: master_key_envelope.to_string(),
        drive_private_key_envelope: drive_private_key_envelope.to_string(),
        public_key: pub_key.to_string(),
        is_admin,
        storage_quota_bytes: quota,
        storage_used_bytes: used,
        color: color.to_string(),
        envelope_binding: envelope_binding.to_string(),
        ..Default::default()
    };
    if client.uses_cookie() {
        Ok((
            AppendHeaders([
                (SET_COOKIE, refresh_cookie(state, &issued.refresh_token)),
                (
                    SET_COOKIE,
                    auth_check::known_client_cookie(state, uid).await?,
                ),
            ]),
            Json(body),
        )
            .into_response())
    } else {
        Ok(Json(body).into_response())
    }
}

pub(crate) const REFRESH_COOKIE: &str = "refresh_token";
pub(crate) const CLIENT_HEADER: &str = "x-kutup-client";

/// The refresh cookie: HttpOnly, host-only on the app's own origin (no `Domain`), sent
/// only to `/api/auth/refresh`, 30-day sliding lifetime; `Secure` outside development.
pub(crate) fn refresh_cookie(state: &AppState, value: &str) -> String {
    let mut c = format!(
        "{REFRESH_COOKIE}={value}; Max-Age={}; Path=/api/auth/refresh; HttpOnly; SameSite=Lax",
        sessions::SESSION_TTL.whole_seconds()
    );
    if state.config.app_env == "production" {
        c.push_str("; Secure");
    }
    c
}

pub(crate) fn clear_refresh_cookie(state: &AppState) -> String {
    let mut c =
        format!("{REFRESH_COOKIE}=; Max-Age=0; Path=/api/auth/refresh; HttpOnly; SameSite=Lax");
    if state.config.app_env == "production" {
        c.push_str("; Secure");
    }
    c
}

/// Reads a single cookie value from the `Cookie` header.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
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
/// the username branch in `Register`.
fn map_insert_conflict(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &err {
        if db.code().as_deref() == Some("23505") {
            let constraint = db.constraint().unwrap_or("");
            if constraint.contains("username") {
                return AppError::conflict("username already taken");
            }
            if constraint.contains("key_binding") {
                return AppError::conflict("keyBinding is taken; draw another");
            }
            return AppError::conflict("already registered");
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

/// `^#[0-9a-fA-F]{6}$` — mirrors `colorHexRegexp`. Shared by user and folder colours.
pub(crate) fn is_valid_hex_color(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|b| b.is_ascii_hexdigit())
}

/// Bytes that stand in for a real account's, for a name that is not one:
/// the same each time, and told from real ones by no one without the
/// server's own key for them (an HMAC under a key derived from it).
fn deterministic_fake_bytes(secret: &[u8], name: &str, purpose: &str, len: usize) -> String {
    use hmac::{Hmac, Mac};
    let key = {
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret).expect("any key length");
        mac.update(b"kutup/fake-account/v1\0");
        mac.finalize().into_bytes()
    };
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).expect("any key length");
        mac.update(purpose.as_bytes());
        mac.update(b"\0");
        mac.update(name.trim().to_lowercase().as_bytes());
        mac.update(b"\0");
        mac.update(&counter.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(len);
    STANDARD.encode(out)
}

fn deterministic_fake_account_envelope(secret: &[u8], binding: &str) -> String {
    let key = STANDARD
        .decode(deterministic_fake_bytes(
            secret,
            binding,
            "recovery-envelope-key",
            32,
        ))
        .expect("deterministic fake key is base64");
    let nonce = STANDARD
        .decode(deterministic_fake_bytes(
            secret,
            binding,
            "recovery-envelope-nonce",
            24,
        ))
        .expect("deterministic fake nonce is base64");
    let envelope = kutup_crypto::account_envelope::seal_with_nonce(
        &[0u8; 32],
        &key,
        kutup_crypto::account_envelope::AccountEnvelopePurpose::RecoveryMasterKey,
        binding,
        &nonce,
    )
    .expect("fake recovery envelope inputs are valid");
    STANDARD.encode(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_against_nothing_cost_as_much_as_real_ones() {
        // A real hash at the stored cost, so verify does the whole work.
        assert!(FAKE_BCRYPT_HASH.starts_with(&format!("$2b${BCRYPT_COST}$")));
        assert_eq!(bcrypt::verify("other", &FAKE_BCRYPT_HASH).ok(), Some(false));
        let real = bcrypt::hash("secret", BCRYPT_COST).unwrap();
        let time = |f: &dyn Fn() -> bool| {
            let started = std::time::Instant::now();
            assert!(!f());
            started.elapsed()
        };
        let checked = time(&|| auth_check::verify_hash("wrong", &real));
        // An empty (voided) hash takes about as long, not a moment.
        let voided = time(&|| auth_check::verify_hash("wrong", ""));
        assert!(
            voided * 3 > checked,
            "voided {voided:?} vs checked {checked:?}"
        );
    }

    #[test]
    fn an_account_address_of_this_server_is_told_from_others() {
        let here = "kutup.example";
        assert_eq!(
            local_account_username("ada@kutup.example", here).as_deref(),
            Some("ada")
        );
        assert_eq!(
            local_account_username(" Ada@Kutup.Example ", here).as_deref(),
            Some("ada")
        );
        // Another domain is another server's account or an outside address.
        assert_eq!(local_account_username("ada@mail.example", here), None);
        assert_eq!(local_account_username("ada@sub.kutup.example", here), None);
        assert_eq!(local_account_username("@kutup.example", here), None);
        assert_eq!(local_account_username("ada", here), None);
    }

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
        let secret = b"a-server-secret-of-at-least-32-bytes";
        let a = deterministic_fake_bytes(secret, "ada", "kdf", 16);
        let b = deterministic_fake_bytes(secret, " ADA ", "kdf", 16);
        let c = deterministic_fake_bytes(secret, "ada", "login", 16);
        let d = deterministic_fake_bytes(b"another-server-secret-of-32-bytes!!", "ada", "kdf", 16);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Without the secret nothing is told: another server answers otherwise.
        assert_ne!(a, d);
        // Longer than one HMAC block.
        assert_eq!(
            STANDARD
                .decode(deterministic_fake_bytes(secret, "ada", "long", 40))
                .unwrap()
                .len(),
            40
        );
        // 16 raw bytes → 24-char standard base64.
        assert_eq!(a.len(), 24);
    }

    #[test]
    fn fake_recovery_envelope_is_stable_and_structurally_valid() {
        // Faked under the name's fake binding, as preflight answers it.
        let binding = fake_binding(&[7u8; 32], "user");
        let first = deterministic_fake_account_envelope(&[7u8; 32], &binding);
        let second = deterministic_fake_account_envelope(&[7u8; 32], &binding);
        assert_eq!(first, second);
        let decoded = kutup_crypto::account_envelope::decode_canonical_b64(&first).unwrap();
        kutup_crypto::account_envelope::validate_for(
            &decoded,
            kutup_crypto::account_envelope::AccountEnvelopePurpose::RecoveryMasterKey,
            &binding,
            &[],
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
