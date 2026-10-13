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
    /// The username, or the Kutup address on this server.
    name: String,
    /// OPAQUE `CredentialRequest` (KE1), base64.
    credential_request: String,
    /// `session` (sign-in) or `reauth` (a signed-in person proving the
    /// password again, for a grant).
    #[serde(default = "session_purpose")]
    purpose: String,
    /// Reauth only: what the grant is for (`pass`, `passwordChange`, `totp`,
    /// `deleteAccount`, `adminReset`).
    #[serde(default, rename = "for")]
    grant_for: Option<String>,
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
                .and_then(Purpose::for_reauth)
                .ok_or_else(|| AppError::bad_request("reauth needs a valid for"))?;
            let token = crate::middleware::bearer_from_headers(&headers)
                .ok_or_else(|| AppError::unauthorized("reauth needs a session"))?;
            let caller = crate::middleware::authenticate_access_token(&state, &token).await?;
            Some((caller, grant_for))
        }
        _ => return Err(AppError::bad_request("purpose must be session or reauth")),
    };

    let canonical = canonical_name(&state, &req.name);
    // Only a username of this server is an account; an address elsewhere,
    // or a name held after a rename, is not.
    let account: Option<(Uuid, String, Option<Vec<u8>>, Option<i16>)> =
        if canonical.is_empty() || canonical.contains('@') || canonical.len() > 64 {
            None
        } else {
            sqlx::query_as(
                "SELECT id, key_binding, opaque_record, opaque_server_key_id
                 FROM users WHERE username = $1",
            )
            .bind(&canonical)
            .fetch_optional(&state.pool)
            .await?
        };
    if let Some((caller, _)) = &reauth {
        // The caller's own account, by id (a rename in flight changes the
        // name, never the id).
        let caller_id = crate::handlers::trusted_uuid(&caller.user_id)?;
        if account.as_ref().map(|a| a.0) != Some(caller_id) {
            return Err(AppError::forbidden("reauth is for the signed-in account"));
        }
    }
    let user_id = account.as_ref().map(|a| a.0);
    let record = account
        .as_ref()
        .and_then(|a| a.2.as_deref().zip(a.3).map(|(record, id)| (record, id)));

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
        (Some((record, key_id)), Some((_, key_binding, _, _))) => {
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
                kutup_crypto::opaque::unknown_credential_identifier(&canonical),
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
             sealed_state, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 now() + make_interval(mins => $13))",
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
    .bind(&lockout)
    .bind(ceiling.as_ref().map(|c| c.0.as_str()))
    .bind(ceiling.as_ref().map(|c| c.1.as_str()))
    .bind(server_key_id as i16)
    .bind(&sealed)
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

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrantResponse {
    /// A one-time grant (`kg1_…`), for the action it was asked for.
    grant: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    expires_at: time::OffsetDateTime,
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
        String,
        Option<String>,
        Option<String>,
        i16,
        Vec<u8>,
    );
    let pending: Option<Pending> = sqlx::query_as(
        "DELETE FROM opaque_login_states WHERE login_id = $1 AND expires_at > now()
         RETURNING user_id, purpose, session_id, grant_for, lockout_key, ceiling_account,
                   ceiling_source, server_key_id, sealed_state",
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
    if kutup_crypto::opaque::server_login_finish(&server_state, &finalization).is_err() {
        return Err(AppError::invalid_credentials());
    }
    // A fake answer cannot be finished; this is a guard, not a path.
    let Some(user_id) = user_id else {
        return Err(AppError::invalid_credentials());
    };
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
        let purpose = grant_for
            .as_deref()
            .and_then(Purpose::for_reauth)
            .ok_or_else(|| AppError::internal("reauth purpose"))?;
        let grant = grants::issue(
            &state.pool,
            purpose,
            user_id,
            session_id,
            None,
            grants::GRANT_MINUTES,
        )
        .await?;
        return Ok(Json(GrantResponse {
            grant,
            expires_at: time::OffsetDateTime::now_utc()
                + time::Duration::minutes(grants::GRANT_MINUTES),
        })
        .into_response());
    }
    let client = direct_sign_in_client(&headers)?;
    signed_in_answer(&state, &headers, client, user_id).await
}

// --- registration --------------------------------------------------------------

/// A registration's result as a client uploads it: the record, and the setup
/// it was made against.
#[derive(Debug, Default, Deserialize, ToSchema)]
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
            return Err(AppError::conflict("the server's OPAQUE key changed: register again")
                .with_details(serde_json::json!({ "code": "opaqueKeyStale" })));
        }
        Ok((record, current as i16))
    }
}

#[derive(Debug, Deserialize, ToSchema)]
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
}

async fn key_binding_unused(state: &AppState, key_binding: &str) -> AppResult<()> {
    let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE key_binding = $1)")
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
            // binding, under the setup token.
            Some(token) => {
                crate::jwt::validate_setup_token(&token, &state.config.jwt_secret)
                    .map_err(|_| AppError::unauthorized("invalid setup token"))?;
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
            }
        },
    }
    let (server_key_id, secrets) = state.opaque.current();
    let response =
        kutup_crypto::opaque::server_registration_response(secrets, &request, &req.key_binding)
            .map_err(|_| AppError::bad_request("invalid registrationRequest"))?;
    Ok(Json(RegisterStartResponse {
        registration_response: STANDARD.encode(response),
        server_key_id,
    })
    .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
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
    let updated = sqlx::query(
        "UPDATE users SET opaque_record = $3, opaque_suite = $4, opaque_server_key_id = $5,
                          master_key_envelope = $6
         WHERE id = $1 AND key_binding = $2 AND is_active",
    )
    .bind(grant.user_id)
    .bind(&req.key_binding)
    .bind(&record)
    .bind(kutup_crypto::opaque::SUITE as i16)
    .bind(server_key_id)
    .bind(&req.master_key_envelope)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(grants::invalid());
    }
    grants::end_all(&mut tx, grant.user_id).await?;
    tx.commit().await?;
    match purpose {
        Purpose::PasswordChange => {
            tracing::info!(user_id = %grant.user_id, "password changed");
            crate::sessions::revoke_all_for_user(&state.pool, grant.user_id, grant.session_id)
                .await?;
        }
        Purpose::Recovery => {
            tracing::info!(user_id = %grant.user_id, "password set again with the recovery phrase");
            crate::sessions::revoke_all_for_user(&state.pool, grant.user_id, None).await?;
        }
        // The same password, registered under the current setup: nobody's
        // sign-in ends, and it is no password change.
        _ => tracing::info!(user_id = %grant.user_id, "OPAQUE record moved to the current setup"),
    }
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}
