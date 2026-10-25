//! OPAQUE sign-in and registration (docs/plans/opaque.md §6).
//!
//! The server never sees the password or anything it could test a guess
//! against offline: it keeps each account's OPAQUE record and answers an
//! online exchange. Sign-in is `login/start` then `login/finish`; a
//! re-authentication is the same exchange with `purpose: "reauth"`, and gives
//! a one-time grant (`crate::grants`) instead of a session. Registration is
//! `register/start` (stateless) then `register/finish` or the endpoint that
//! creates the account.
//!
//! Every start counts a failed attempt against the name before any OPAQUE
//! work (the sign-in lockout and ceilings of `auth_check`): a client checks
//! the password itself and needs no finish to learn a guess was wrong, so
//! only counting the start makes guessing cost anything. A right finish gives
//! the attempt back.

use std::net::SocketAddr;

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth_check;
use crate::error::{AppError, AppResult};
use crate::grants::{self, Purpose};
use crate::handlers::auth::{canonical_name, direct_sign_in_client, signed_in_answer};
use crate::security_events;
use crate::AppState;

/// How long a sign-in may wait between its start and its finish.
const LOGIN_MINUTES: i32 = 2;
/// The most sign-ins under way for one name, and from one source; past
/// either, the oldest goes.
const PENDING_PER_NAME: i64 = 5;
const PENDING_PER_SOURCE: i64 = 20;

fn decode(value: &str, field: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request(format!("invalid {field}")))
}

fn opaque_key_missing() -> AppError {
    AppError::internal("the account's OPAQUE setup key is not configured")
        .with_details(serde_json::json!({ "code": "opaqueKeyMissing" }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginStartRequest {
    /// The username, or the Kutup address on this server, in any spelling
    /// (`.`, `_`, `-` and case fold away). None for a reauth, which is for
    /// the session's own account.
    #[serde(default)]
    name: Option<String>,
    /// OPAQUE `CredentialRequest` (KE1), base64.
    credential_request: String,
    /// `session` (sign-in) or `reauth` (a signed-in person proving the
    /// password again, for a grant).
    #[serde(default = "session_purpose")]
    purpose: String,
    /// Reauth only: what the grant is for (`pass`, `passwordChange`, `totp`,
    /// `adminReset`), or `verify`: the password checked, no grant.
    #[serde(default, rename = "for")]
    grant_for: Option<String>,
}

/// What a reauth is for: a one-time grant for one action, or (`verify`) the
/// password checked and nothing kept (unlocking Pass on this device).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReauthFor {
    Grant(Purpose),
    Verify,
}

impl ReauthFor {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "verify" => Some(ReauthFor::Verify),
            name => Purpose::for_reauth(name).map(ReauthFor::Grant),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ReauthFor::Grant(purpose) => purpose.as_str(),
            ReauthFor::Verify => "verify",
        }
    }
}

fn session_purpose() -> String {
    "session".into()
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    login_id: Uuid,
    /// OPAQUE `CredentialResponse` (KE2), base64.
    credential_response: String,
    suite: u16,
}

/// `POST /api/auth/login/start` — the server's half of KE2. A name that is no
/// account (or one held after a rename, or another server's address) gets a
/// fake answer of the same shape, the same each time for that name, and
/// meets the same lockout.
#[utoipa::path(
    post,
    path = "/api/auth/login/start",
    tag = "auth",
    request_body = LoginStartRequest,
    responses(
        (status = 200, description = "KE2 and the login id to finish with", body = LoginStartResponse),
        (status = 429, description = "accountLocked: too many attempts for this name")
    )
)]
pub async fn login_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<LoginStartRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    // Read before the name is looked up: a malformed request is answered the
    // same for every name.
    let request = decode(&req.credential_request, "credentialRequest")?;
    let reauth = match req.purpose.as_str() {
        "session" => {
            if req.grant_for.is_some() {
                return Err(AppError::bad_request("for is for reauth only"));
            }
            direct_sign_in_client(&headers)?;
            None
        }
        "reauth" => {
            let grant_for = req
                .grant_for
                .as_deref()
                .and_then(ReauthFor::parse)
                .ok_or_else(|| AppError::bad_request("reauth needs a valid for"))?;
            let token = crate::middleware::bearer_from_headers(&headers)
                .ok_or_else(|| AppError::unauthorized("reauth needs a session"))?;
            let caller = crate::middleware::authenticate_access_token(&state, &token).await?;
            // The session's own account, by id: a name would only go stale
            // across a rename (docs/plans/username-renames.md).
            if req.name.is_some() {
                return Err(AppError::bad_request("a reauth names no account"));
            }
            Some((caller, grant_for))
        }
        _ => return Err(AppError::bad_request("purpose must be session or reauth")),
    };

    // id, key binding, record, the record's setup, and the account's folded
    // name.
    type Account = (Uuid, Option<String>, Option<Vec<u8>>, Option<i16>, String);
    let (canonical, account): (String, Option<Account>) = match &reauth {
        Some((caller, _)) => {
            let caller_id = crate::handlers::trusted_uuid(&caller.user_id)?;
            let account: Account = sqlx::query_as(
                "SELECT u.id, u.key_binding, u.opaque_record, u.opaque_server_key_id, n.folded
                   FROM users u JOIN account_names n ON n.user_id = u.id AND n.state = 'current'
                  WHERE u.id = $1",
            )
            .bind(caller_id)
            .fetch_one(&state.pool)
            .await?;
            (account.4.clone(), Some(account))
        }
        None => {
            // One canonical name for everything below: the lookup, the fake
            // answer, the lockout and the caps (an address on this server is
            // its username, folded: every spelling is one name).
            let name = req
                .name
                .as_deref()
                .ok_or_else(|| AppError::bad_request("a sign-in names its account"))?;
            let canonical =
                kutup_crypto::opaque::CanonicalName::parse(&canonical_name(&state, name))
                    .map_err(|_| AppError::bad_request("invalid name"))?
                    .as_str()
                    .to_owned();
            // Only a current username of this server is an account; an
            // address elsewhere, or a name held after a rename, is not.
            let account = if canonical.is_empty() || canonical.contains('@') || canonical.len() > 64
            {
                None
            } else {
                sqlx::query_as(
                    "SELECT u.id, u.key_binding, u.opaque_record, u.opaque_server_key_id, n.folded
                       FROM account_names n JOIN users u ON u.id = n.user_id
                      WHERE n.folded = $1 AND n.state = 'current'",
                )
                .bind(&canonical)
                .fetch_optional(&state.pool)
                .await?
            };
            (canonical, account)
        }
    };
    let canonical_name = kutup_crypto::opaque::CanonicalName::parse(&canonical)
        .map_err(|_| AppError::bad_request("invalid name"))?;
    let user_id = account.as_ref().map(|a| a.0);
    let record = account.as_ref().and_then(|a| a.2.as_deref().zip(a.3));

    // The attempt counts before any OPAQUE work.
    let mut asker = auth_check::Client::from_headers(&state, &headers, peer).await?;
    if let Some((caller, _)) = &reauth {
        asker = asker.signed_in_as(crate::handlers::trusted_uuid(&caller.user_id)?);
    }
    let epoch = record.map(|(record, _)| auth_check::credential_epoch(record));
    let guard = auth_check::guard(&asker, user_id, &canonical, epoch.as_ref().map(|e| &e[..]))?;

    // A real record under its own setup; anything else the fake, under the
    // current one.
    let (server_key_id, secrets, record, credential) = match (record, account.as_ref()) {
        (Some((record, key_id)), Some((_, Some(key_binding), _, _, _))) => {
            let key_id = u16::try_from(key_id).map_err(|_| opaque_key_missing())?;
            let secrets = state.opaque.get(key_id).ok_or_else(opaque_key_missing)?;
            let credential = kutup_crypto::opaque::credential_identifier(key_binding)
                .map_err(|_| AppError::internal("key binding"))?;
            (key_id, secrets, Some(record), credential)
        }
        _ => {
            let (key_id, secrets) = state.opaque.current();
            (
                key_id,
                secrets,
                None,
                kutup_crypto::opaque::unknown_credential_identifier(&canonical_name),
            )
        }
    };
    let started = kutup_crypto::opaque::server_login_start(secrets, record, &request, &credential)
        .map_err(|_| AppError::bad_request("invalid credentialRequest"))?;

    let login_id = Uuid::new_v4();
    let state_key = state
        .opaque
        .state_key(server_key_id)
        .ok_or_else(opaque_key_missing)?;
    let sealed =
        kutup_crypto::opaque_login_state::seal(state_key, login_id.as_bytes(), &started.state)
            .map_err(|_| AppError::internal("seal the sign-in state"))?;
    let (lockout, ceiling) = guard.slots();
    let source = asker.source();
    let mut tx = state.pool.begin().await?;
    // The newest few per name and per source stay; this one is next.
    sqlx::query(
        "DELETE FROM opaque_login_states WHERE login_id IN (
             SELECT login_id FROM opaque_login_states WHERE canonical_name = $1
             ORDER BY expires_at DESC OFFSET $2)",
    )
    .bind(&canonical)
    .bind(PENDING_PER_NAME - 1)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM opaque_login_states WHERE login_id IN (
             SELECT login_id FROM opaque_login_states WHERE source = $1
             ORDER BY expires_at DESC OFFSET $2)",
    )
    .bind(&source)
    .bind(PENDING_PER_SOURCE - 1)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO opaque_login_states (login_id, canonical_name, user_id, purpose, session_id,
             grant_for, source, lockout_key, ceiling_account, ceiling_source, server_key_id,
             sealed_state, credential_epoch, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                 now() + make_interval(mins => $14))",
    )
    .bind(login_id)
    .bind(&canonical)
    .bind(user_id)
    .bind(if reauth.is_some() {
        "reauth"
    } else {
        "session"
    })
    .bind(reauth.as_ref().map(|(caller, _)| caller.session.session_id))
    .bind(reauth.as_ref().map(|(_, grant_for)| grant_for.as_str()))
    .bind(&source)
    .bind(lockout.as_bytes())
    .bind(ceiling.as_ref().map(|c| c.0.as_str()))
    .bind(ceiling.as_ref().map(|c| c.1.as_str()))
    .bind(server_key_id as i16)
    .bind(&sealed)
    .bind(epoch.as_ref().map(|e| &e[..]))
    .bind(LOGIN_MINUTES)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(LoginStartResponse {
        login_id,
        credential_response: STANDARD.encode(&started.response),
        suite: kutup_crypto::opaque::SUITE,
    })
    .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginFinishRequest {
    login_id: Uuid,
    /// OPAQUE `CredentialFinalization` (KE3), base64.
    credential_finalization: String,
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrantResponse {
    /// A one-time grant (`kg1_…`), for the action it was asked for.
    grant: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    expires_at: time::OffsetDateTime,
}

impl GrantResponse {
    /// A grant just issued for [`grants::GRANT_MINUTES`].
    pub(crate) fn new(grant: String) -> Self {
        Self {
            grant,
            expires_at: time::OffsetDateTime::now_utc()
                + time::Duration::minutes(grants::GRANT_MINUTES),
        }
    }
}

/// `POST /api/auth/login/finish` — checks KE3. A sign-in answers as sign-in
/// always has (setup, the second factor, or the session with the account's
/// envelopes); a reauth answers a grant. Every miss is the same `401`: a
/// wrong password, an unknown name, a used or expired login id.
#[utoipa::path(
    post,
    path = "/api/auth/login/finish",
    tag = "auth",
    request_body = LoginFinishRequest,
    responses(
        (status = 200, description = "The sign-in's answer, or a reauth's grant"),
        (status = 401, description = "invalidCredentials")
    )
)]
pub async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<LoginFinishRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let finalization = decode(&req.credential_finalization, "credentialFinalization")?;
    // Taken once: a login id never finishes twice.
    type Pending = (
        Option<Uuid>,
        String,
        Option<Uuid>,
        Option<String>,
        Vec<u8>,
        Option<String>,
        Option<String>,
        i16,
        Vec<u8>,
        Option<Vec<u8>>,
    );
    let pending: Option<Pending> = sqlx::query_as(
        "DELETE FROM opaque_login_states WHERE login_id = $1 AND expires_at > now()
         RETURNING user_id, purpose, session_id, grant_for, lockout_key, ceiling_account,
                   ceiling_source, server_key_id, sealed_state, credential_epoch",
    )
    .bind(req.login_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((
        user_id,
        purpose,
        session_id,
        grant_for,
        lockout,
        ceiling_account,
        ceiling_source,
        server_key_id,
        sealed,
        epoch,
    )) = pending
    else {
        return Err(AppError::invalid_credentials());
    };
    let state_key = u16::try_from(server_key_id)
        .ok()
        .and_then(|id| state.opaque.state_key(id))
        .ok_or_else(opaque_key_missing)?;
    let server_state =
        kutup_crypto::opaque_login_state::open(state_key, req.login_id.as_bytes(), &sealed)
            .map_err(|_| AppError::invalid_credentials())?;
    match kutup_crypto::opaque::server_login_finish(&server_state, &finalization) {
        Ok(()) => {}
        // A finalization that is not one (its attempt stays counted).
        Err(kutup_crypto::error::CryptoError::InvalidInput(_)) => {
            return Err(AppError::bad_request("invalid credentialFinalization"))
        }
        // A wrong password, or a name that is no account.
        Err(_) => return Err(AppError::invalid_credentials()),
    }
    // A fake answer cannot be finished; this is a guard, not a path.
    let (Some(user_id), Some(epoch)) = (user_id, epoch) else {
        return Err(AppError::invalid_credentials());
    };
    let lockout = String::from_utf8(lockout).map_err(|_| AppError::internal("lockout key"))?;
    auth_check::Guard::succeeded(
        &lockout,
        ceiling_account.as_deref().zip(ceiling_source.as_deref()),
    );

    if purpose == "reauth" {
        // Finished by the session that started it, which is still live.
        let token = crate::middleware::bearer_from_headers(&headers)
            .ok_or_else(|| AppError::unauthorized("reauth needs a session"))?;
        let caller = crate::middleware::authenticate_access_token(&state, &token).await?;
        if Some(caller.session.session_id) != session_id {
            return Err(AppError::invalid_credentials());
        }
        let reauth_for = grant_for
            .as_deref()
            .and_then(ReauthFor::parse)
            .ok_or_else(|| AppError::internal("reauth purpose"))?;
        // Only while the password proved is still the account's.
        let mut tx = state.pool.begin().await?;
        if crate::handlers::auth::credential_held(&mut tx, user_id, &epoch)
            .await?
            .is_none()
        {
            return Err(AppError::invalid_credentials());
        }
        let ReauthFor::Grant(purpose) = reauth_for else {
            // The password checked, under the same lockout; nothing kept.
            tx.commit().await?;
            return Ok(Json(serde_json::json!({ "ok": true })).into_response());
        };
        let grant = grants::issue(
            &mut *tx,
            purpose,
            user_id,
            session_id,
            None,
            grants::GRANT_MINUTES,
        )
        .await?;
        tx.commit().await?;
        return Ok(Json(GrantResponse::new(grant)).into_response());
    }
    let client = direct_sign_in_client(&headers)?;
    signed_in_answer(&state, &headers, client, user_id, &epoch).await
}

// --- registration --------------------------------------------------------------

/// A registration's result as a client uploads it: the record, and the setup
/// it was made against.
// Serialize: utoipa's `flatten` needs it.
#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RecordUpload {
    /// OPAQUE `RegistrationUpload`, base64.
    pub opaque_record: String,
    /// The `serverKeyId` register/start answered.
    pub opaque_server_key_id: u16,
}

impl RecordUpload {
    /// The record to store, and its setup id. A record made against a setup
    /// that is no longer the current one is refused (`409 opaqueKeyStale`):
    /// the client starts again.
    pub(crate) fn checked(&self, state: &AppState) -> AppResult<(Vec<u8>, i16)> {
        let upload = decode(&self.opaque_record, "opaqueRecord")?;
        let record = kutup_crypto::opaque::server_registration_record(&upload)
            .map_err(|_| AppError::bad_request("invalid opaqueRecord"))?;
        let (current, _) = state.opaque.current();
        if self.opaque_server_key_id != current {
            return Err(
                AppError::conflict("the server's OPAQUE key changed: register again")
                    .with_details(serde_json::json!({ "code": "opaqueKeyStale" })),
            );
        }
        Ok((record, current as i16))
    }
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterStartRequest {
    /// The key binding the record is for: the account's own (a new password),
    /// or a new one (sign-up, setup, an admin reset).
    key_binding: String,
    /// OPAQUE `RegistrationRequest`, base64.
    registration_request: String,
    /// A grant: `passwordChange`, `recovery` or `rotate` for the account's
    /// own key binding; an admin reset's grant for a new one. None for a
    /// sign-up (or with the setup token as Bearer, at first sign-in).
    #[serde(default)]
    grant: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartResponse {
    /// OPAQUE `RegistrationResponse`, base64.
    registration_response: String,
    /// The setup it is answered under: given back with the record.
    server_key_id: u16,
    /// A sign-up's account id, minted now (docs/plans/account-ids.md), with
    /// its proof: the client signs its Drive key binding for this id, and
    /// gives both back with the registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id_proof: Option<String>,
}

async fn key_binding_unused(state: &AppState, key_binding: &str) -> AppResult<()> {
    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE key_binding = $1)")
            .bind(key_binding)
            .fetch_one(&state.pool)
            .await?;
    if taken {
        return Err(AppError::conflict("keyBinding is taken; draw another")
            .with_details(serde_json::json!({ "code": "keyBindingTaken" })));
    }
    Ok(())
}

/// `POST /api/auth/opaque/register/start` — the server's answer to a
/// registration request: stateless, derived from the setup and the key
/// binding. Each answer is one query of that key binding's OPRF key, so it
/// needs a grant for an existing account's, and is rate-limited as a sign-up
/// for a new one.
#[utoipa::path(
    post,
    path = "/api/auth/opaque/register/start",
    tag = "auth",
    request_body = RegisterStartRequest,
    responses(
        (status = 200, body = RegisterStartResponse),
        (status = 403, description = "grantInvalid, or registrationClosed"),
        (status = 409, description = "keyBindingTaken: draw another")
    )
)]
pub async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<RegisterStartRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let request = decode(&req.registration_request, "registrationRequest")?;
    if !crate::handlers::auth::is_key_binding(&req.key_binding) {
        return Err(AppError::bad_request("keyBinding is a lowercase UUID v4"));
    }
    let mut minted = None;
    match req.grant.as_deref() {
        Some(token) => {
            let (purpose, grant) = grants::peek(
                &state.pool,
                token,
                &[
                    Purpose::PasswordChange,
                    Purpose::Recovery,
                    Purpose::Rotate,
                    Purpose::AdminReset,
                ],
            )
            .await?
            .ok_or_else(grants::invalid)?;
            if purpose == Purpose::AdminReset {
                // A new key binding for the account the admin may reset.
                if grant.target_user_id.is_none() {
                    return Err(grants::invalid());
                }
                key_binding_unused(&state, &req.key_binding).await?;
            } else {
                // The account's own key binding: a new password for it.
                let own: Option<String> =
                    sqlx::query_scalar("SELECT key_binding FROM users WHERE id = $1")
                        .bind(grant.user_id)
                        .fetch_optional(&state.pool)
                        .await?;
                if own.as_deref() != Some(req.key_binding.as_str()) {
                    return Err(grants::invalid());
                }
            }
        }
        None => match crate::middleware::bearer_from_headers(&headers) {
            // First sign-in of an account an admin made: its own new key
            // binding, under the setup token. Or an administrator making an
            // account: its temporary password, under a new key binding.
            Some(token) => {
                if crate::jwt::validate_setup_token(&token, &state.config.jwt_secret).is_err() {
                    // A setup token past its time: sign in again.
                    if crate::jwt::is_setup_token_signed(&token, &state.config.jwt_secret) {
                        return Err(crate::handlers::auth::setup_token_invalid());
                    }
                    let caller = crate::middleware::authenticate_access_token(&state, &token)
                        .await
                        .map_err(|_| AppError::unauthorized("invalid token"))?;
                    if !caller.is_admin {
                        return Err(grants::invalid());
                    }
                }
                key_binding_unused(&state, &req.key_binding).await?;
            }
            // A sign-up: only while sign-ups are open.
            None => {
                if crate::registration::mode(&state).await?
                    == crate::registration::RegistrationMode::Off
                {
                    return Err(AppError::forbidden("registration is closed")
                        .with_details(serde_json::json!({ "code": "registrationClosed" })));
                }
                key_binding_unused(&state, &req.key_binding).await?;
                minted = Some(crate::account_ids::mint(&state, &req.key_binding).await?);
            }
        },
    }
    let (server_key_id, secrets) = state.opaque.current();
    let response =
        kutup_crypto::opaque::server_registration_response(secrets, &request, &req.key_binding)
            .map_err(|_| AppError::bad_request("invalid registrationRequest"))?;
    let (account_id, account_id_proof) = match minted {
        Some((id, proof)) => (Some(id.to_string()), Some(proof)),
        None => (None, None),
    };
    Ok(Json(RegisterStartResponse {
        registration_response: STANDARD.encode(response),
        server_key_id,
        account_id,
        account_id_proof,
    })
    .into_response())
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterFinishRequest {
    grant: String,
    key_binding: String,
    #[serde(flatten)]
    record: RecordUpload,
    /// The master key sealed under the new password's export key
    /// (`PasswordMasterKey`, bound to the key binding).
    master_key_envelope: String,
}

/// `POST /api/auth/opaque/register/finish` — a new password for an account:
/// after a password change (`passwordChange`, from this session), the
/// recovery phrase (`recovery`) or a silent re-registration under the current
/// setup at sign-in (`rotate`). The record and the password envelope change
/// together; every outstanding grant and sign-in under way ends. A password
/// change ends the account's other sign-ins, a recovery all of them.
#[utoipa::path(
    post,
    path = "/api/auth/opaque/register/finish",
    tag = "auth",
    request_body = RegisterFinishRequest,
    responses(
        (status = 204, description = "The new record is the account's"),
        (status = 403, description = "grantInvalid"),
        (status = 409, description = "opaqueKeyStale: start again")
    )
)]
pub async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<RegisterFinishRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let (record, server_key_id) = req.record.checked(&state)?;
    crate::handlers::auth::validate_account_envelope(
        &req.master_key_envelope,
        kutup_crypto::account_envelope::AccountEnvelopePurpose::PasswordMasterKey,
        &req.key_binding,
        "masterKeyEnvelope",
    )?;
    // The session asking, when there is one (a recovery has none).
    let caller = match crate::middleware::bearer_from_headers(&headers) {
        Some(token) => Some(crate::middleware::authenticate_access_token(&state, &token).await?),
        None => None,
    };
    let mut tx = state.pool.begin().await?;
    let (purpose, grant) = grants::take(
        &mut *tx,
        &req.grant,
        &[Purpose::PasswordChange, Purpose::Recovery, Purpose::Rotate],
    )
    .await?
    .ok_or_else(grants::invalid)?;
    // A session's grant is used by that session.
    if purpose != Purpose::Recovery
        && caller.as_ref().map(|c| c.session.session_id) != grant.session_id
    {
        return Err(grants::invalid());
    }
    // A rotation only moves an account off a retired setup: once per setup,
    // and never a password change in disguise for an account already on the
    // current one.
    let updated = sqlx::query(
        "UPDATE users SET opaque_record = $3, opaque_suite = $4, opaque_server_key_id = $5,
                          master_key_envelope = $6
         WHERE id = $1 AND key_binding = $2 AND is_active
           AND (NOT $7 OR opaque_server_key_id IS DISTINCT FROM $5)",
    )
    .bind(grant.user_id)
    .bind(&req.key_binding)
    .bind(&record)
    .bind(kutup_crypto::opaque::SUITE as i16)
    .bind(server_key_id)
    .bind(&req.master_key_envelope)
    .bind(purpose == Purpose::Rotate)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(grants::invalid());
    }
    grants::end_all(&mut tx, grant.user_id).await?;
    // The sign-ins it ends end with it, in this transaction.
    let kind = match purpose {
        // This sign-in goes on; the account's others end.
        Purpose::PasswordChange => {
            crate::sessions::revoke_all_for_user_in(&mut tx, grant.user_id, grant.session_id)
                .await?;
            security_events::Kind::PasswordChange
        }
        Purpose::Recovery => {
            crate::sessions::revoke_all_for_user_in(&mut tx, grant.user_id, None).await?;
            // The recovery phrase also turns every second factor off, as
            // Proton's lost-2FA path does (docs/plans/security-keys.md, D2):
            // a lost authenticator would otherwise lock the account out.
            if crate::two_factor::turn_off(&mut tx, grant.user_id).await? {
                security_events::record(
                    &mut tx,
                    grant.user_id,
                    security_events::Kind::TwoFactorOff,
                    grant.session_id,
                    None,
                )
                .await?;
            }
            security_events::Kind::Recovery
        }
        // The same password under the current setup: nobody's sign-in ends,
        // but the owner sees it (a stolen password could otherwise set a new
        // one here unseen).
        _ => security_events::Kind::Rotate,
    };
    security_events::record(&mut tx, grant.user_id, kind, grant.session_id, None).await?;
    tx.commit().await?;
    tracing::info!(user_id = %grant.user_id, kind = kind.as_str(), "account credential changed");
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}
