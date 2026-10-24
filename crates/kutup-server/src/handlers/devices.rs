//! Collaboration devices (docs/plans/device-registration.md): the Ed25519 keys
//! a browser tab or the CLI signs collaboration frames with. Each is vouched
//! for by the account's authority (from the master key), over a one-time
//! challenge this server issued, so a session token alone cannot add one and
//! a captured registration cannot be played again. The statement carries its
//! time: renewed by the client every two weeks, it is what lets another
//! server keep the device only while it is fresh. Revoking a device takes the
//! account's signed revocation; the key never registers again.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kutup_crypto::primitives::{hash, Suite};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

use kutup_crypto::device_registration::{
    self, DeviceStatement, CHALLENGE_LEN, PURPOSE_COLLAB_FRAMES,
};

/// How long a challenge may be answered.
const CHALLENGE_MINUTES: i64 = 5;
/// The most challenges one account holds unanswered; a new one evicts the
/// oldest, so nobody can fill the table.
const MAX_OPEN_CHALLENGES: i64 = 5;
/// The most devices in use one account has (here, and per account at a
/// server elsewhere: the same rule). In use: [`DEVICE_LIVE`] and a statement
/// within the 30-day lease, so devices of ended sign-ins, or long unused,
/// drop out of the count by themselves.
pub(crate) const MAX_ACTIVE_DEVICES: i64 = 20;

/// A device the server trusts (`d` the device row, `u` its user): active
/// (not revoked), of the account's current incarnation, and registered by a
/// sign-in session still live. Ending the session (a sign-out anywhere, its
/// expiry, a password change) retires the device here; that needs no
/// signature, and the device is not revoked for good.
pub(crate) const DEVICE_LIVE: &str = "(d.is_active AND d.incarnation_id = u.account_incarnation_id
     AND EXISTS (SELECT 1 FROM auth_sessions s WHERE s.id = d.session_id
                 AND s.revoked_at IS NULL AND s.expires_at > now()))";

/// [`DEVICE_LIVE`] and within the lease: what the cap counts.
fn in_use() -> String {
    format!(
        "({DEVICE_LIVE} AND d.registration_issued_at_ms > \
           (extract(epoch FROM now()) * 1000)::bigint - {})",
        crate::remote_devices::LEASE_MS
    )
}

/// Refuses a device that would be the account's 21st in use (`except`: the
/// device being renewed, already counted if it is in use).
async fn check_cap(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    except: Option<i64>,
) -> AppResult<()> {
    // One count per account, under its row's lock.
    lock_account_devices(tx, user_id).await?;
    let in_use: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM user_devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.id <> COALESCE($2, 0) AND {}",
        in_use()
    ))
    .bind(user_id)
    .bind(except)
    .fetch_one(&mut **tx)
    .await?;
    if in_use >= MAX_ACTIVE_DEVICES {
        return Err(AppError::conflict(format!(
            "too many devices in use for this account (at most {MAX_ACTIVE_DEVICES}): remove one first"
        ))
        .with_details(serde_json::json!({ "code": "tooManyDevices" })));
    }
    Ok(())
}
/// How far a statement's time may be from this server's clock: lenient, so a
/// skewed device still registers (the challenge makes it single use).
const MAX_CLOCK_SKEW_MS: i64 = 24 * 3600 * 1000;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChallenge {
    /// 32 random bytes, canonical base64: sign it once, within five minutes.
    challenge: String,
}

/// `POST /api/devices/challenge` — a one-time challenge for registering or
/// renewing a device: what the account's statement for the device key signs.
#[utoipa::path(
    post,
    path = "/api/devices/challenge",
    tag = "devices",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "A challenge, valid five minutes, once", body = DeviceChallenge))
)]
pub async fn challenge(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    if !crate::ratelimit::DEVICE_CHALLENGES.allow(&user_id.to_string()) {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    let mut challenge = [0u8; CHALLENGE_LEN];
    kutup_crypto::primitives::random(&mut challenge);
    let mut tx = state.pool.begin().await?;
    // Expired ones go as new ones are made.
    sqlx::query("DELETE FROM device_registration_challenges WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO device_registration_challenges (challenge_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(mins => $3))",
    )
    .bind(hash(Suite::V1, challenge).to_vec())
    .bind(user_id)
    .bind(CHALLENGE_MINUTES as i32)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM device_registration_challenges WHERE challenge_hash IN (
             SELECT challenge_hash FROM device_registration_challenges WHERE user_id = $1
             ORDER BY expires_at DESC OFFSET $2)",
    )
    .bind(user_id)
    .bind(MAX_OPEN_CHALLENGES)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(DeviceChallenge {
        challenge: STANDARD.encode(challenge),
    })
    .into_response())
}

/// The account's statement for a device key, as a request carries it.
#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceStatementBody {
    /// The challenge from `POST /api/devices/challenge`, canonical base64.
    challenge: String,
    /// When the statement was made, UTC milliseconds (within a day of this
    /// server's clock).
    issued_at_ms: i64,
    /// The account authority's `DeviceRegistrationV1` signature over the
    /// incarnation, the server, the account, the device key, its purpose,
    /// the challenge and the time (`kutup_crypto::device_registration`).
    signature: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterDeviceRequest {
    /// The device's Ed25519 public key, canonical base64 (32 bytes).
    public_signing: String,
    /// What the account calls it (not signed: it can be renamed).
    label: String,
    #[serde(flatten)]
    statement: DeviceStatementBody,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    device_id: i64,
    label: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRow {
    device_id: i64,
    label: String,
    /// The device's Ed25519 public key, canonical base64: what a revocation names.
    public_signing: String,
    is_active: bool,
    /// Active, registered under the account's current incarnation, by a
    /// sign-in still live: the collaboration routes accept it. A client
    /// whose stored device is not trusted registers a new one.
    trusted: bool,
    /// Trusted and within its 30-day lease: one of the at most 20 the
    /// account has in use.
    in_use: bool,
    /// Registered (or last renewed) by the caller's own sign-in.
    this_session: bool,
    /// When its newest statement was made (UTC milliseconds): a client
    /// renews it when it is two weeks old.
    statement_issued_at_ms: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_seen_at: Option<OffsetDateTime>,
}

fn not_authorized(message: &str) -> AppError {
    AppError::forbidden(message.to_owned())
        .with_details(serde_json::json!({ "code": "deviceNotAuthorized" }))
}

fn canonical_32(value: &str, field: &str) -> AppResult<[u8; 32]> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|raw| STANDARD.encode(raw) == value)
        .and_then(|raw| raw.try_into().ok())
        .ok_or_else(|| {
            AppError::bad_request(format!("{field} must be canonical base64 of 32 bytes"))
        })
}

/// The account's authority key and current incarnation.
async fn account_authority(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<([u8; 32], String)> {
    let (authority, incarnation): (String, String) = sqlx::query_as(
        "SELECT account_authority_public_key, account_incarnation_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let authority = STANDARD
        .decode(&authority)
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or_else(|| not_authorized("the account has no authority key yet"))?;
    Ok((authority, incarnation.trim().to_owned()))
}

/// Checks a statement for `device_key`: its challenge (used up here, in the
/// caller's transaction, whatever comes next), its time, and its signature
/// under the account's authority. Returns the challenge's bytes.
async fn check_statement(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    device_key: &[u8; 32],
    body: &DeviceStatementBody,
) -> AppResult<Option<[u8; 32]>> {
    let challenge = canonical_32(&body.challenge, "challenge")?;
    // Used up in a step of its own, committed before anything is checked:
    // no refusal or error below can roll it back, so a challenge answers
    // once whatever happens. Looked up by its hash (an index lookup:
    // nothing compares the secret itself in variable time).
    let fresh: Option<bool> = sqlx::query_scalar(
        "DELETE FROM device_registration_challenges
         WHERE challenge_hash = $1 AND user_id = $2
         RETURNING expires_at >= now()",
    )
    .bind(hash(Suite::V1, challenge).to_vec())
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    if fresh != Some(true) {
        return Ok(None);
    }
    let now_ms = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    if (body.issued_at_ms - now_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Ok(None);
    }
    let (authority, _) = account_authority(tx, user_id).await?;
    let user = user_id.to_string();
    let statement = DeviceStatement {
        server: &state.config.chat_server_name,
        user_id: &user,
        device_public: device_key,
        purpose: PURPOSE_COLLAB_FRAMES,
        challenge: &challenge,
        issued_at_ms: body.issued_at_ms,
    };
    Ok(
        device_registration::verify(&authority, &statement, &body.signature)
            .ok()
            .map(|()| challenge),
    )
}

/// `POST /api/devices` — registers a device key the account vouches for.
/// `403 deviceNotAuthorized` when the statement does not verify under the
/// account's authority, is more than a day off this server's clock, or its
/// challenge is unknown, used or expired (get a new one and sign again);
/// `409` when the key is another device's (revoked ones included) or the
/// account has 20 active devices (`tooManyDevices`).
#[utoipa::path(
    post,
    path = "/api/devices",
    tag = "devices",
    operation_id = "registerDevice",
    security(("BearerAuth" = [])),
    request_body = RegisterDeviceRequest,
    responses(
        (status = 201, description = "Device signing key registered", body = RegisterDeviceResponse),
        (status = 403, description = "deviceNotAuthorized: the account's statement does not verify, or the challenge is not one to answer"),
        (status = 409, description = "The key is another device's, or tooManyDevices")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let device_key = canonical_32(&req.public_signing, "publicSigning")?;
    if req.label.chars().count() > 100 {
        return Err(AppError::bad_request("label is too long"));
    }

    let mut tx = state.pool.begin().await?;
    let Some(challenge) =
        check_statement(&state, &mut tx, user_id, &device_key, &req.statement).await?
    else {
        // The challenge stays used up.
        tx.commit().await?;
        return Err(not_authorized(
            "the account's statement for this device does not verify, or its challenge is not one to answer",
        ));
    };
    if let Err(e) = check_cap(&mut tx, user_id, None).await {
        // The challenge stays used up.
        tx.commit().await?;
        return Err(e);
    }
    let (_, incarnation_id) = account_authority(&mut tx, user_id).await?;
    let inserted: Result<(i64, OffsetDateTime), sqlx::Error> = sqlx::query_as(
        r#"INSERT INTO user_devices (user_id, public_signing, label, incarnation_id,
                                     registration_challenge, registration_issued_at_ms,
                                     registration_signature, session_id)
           VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8)
           RETURNING id, created_at"#,
    )
    .bind(user_id)
    .bind(device_key.to_vec())
    .bind(&req.label)
    .bind(&incarnation_id)
    .bind(challenge.to_vec())
    .bind(req.statement.issued_at_ms)
    .bind(&req.statement.signature)
    .bind(user.session.session_id)
    .fetch_one(&mut *tx)
    .await;
    let (id, created_at) = match inserted {
        Ok(row) => row,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::conflict("this key is another device's"));
        }
        Err(e) => return Err(e.into()),
    };
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            device_id: id,
            label: req.label,
            created_at,
        }),
    )
        .into_response())
}

/// `POST /api/devices/{id}/renew` — a newer statement for an active device of
/// the account's current incarnation (the same checks as registering). A
/// client renews when its device's statement is two weeks old; servers
/// elsewhere keep the device only while its newest statement is fresh.
#[utoipa::path(
    post,
    path = "/api/devices/{id}/renew",
    tag = "devices",
    security(("BearerAuth" = [])),
    params(("id" = i64, Path, description = "Device id")),
    request_body = DeviceStatementBody,
    responses(
        (status = 204, description = "Renewed"),
        (status = 403, description = "deviceNotAuthorized")
    )
)]
pub async fn renew(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<DeviceStatementBody>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let device_id: i64 = id
        .parse()
        .map_err(|_| AppError::bad_request("invalid id"))?;
    let mut tx = state.pool.begin().await?;
    // The account's lock first, as every device change takes it.
    lock_account_devices(&mut tx, user_id).await?;
    let key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT d.public_signing FROM user_devices d JOIN users u ON u.id = d.user_id
         WHERE d.id = $1 AND d.user_id = $2 AND d.is_active
           AND d.incarnation_id = u.account_incarnation_id
         FOR UPDATE OF d",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(key) = key else {
        return Err(not_authorized("no such trusted device: register one"));
    };
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::internal("device key"))?;
    let Some(challenge) = check_statement(&state, &mut tx, user_id, &key, &body).await? else {
        tx.commit().await?;
        return Err(not_authorized(
            "the renewal does not verify, or its challenge is not one to answer",
        ));
    };
    // Renewed, the device is in use again (if its sign-in ended, under this
    // one): it counts against the cap like a new one.
    if let Err(e) = check_cap(&mut tx, user_id, Some(device_id)).await {
        tx.commit().await?;
        return Err(e);
    }
    sqlx::query(
        "UPDATE user_devices SET
             registration_challenge = CASE WHEN registration_issued_at_ms < $3 THEN $2 ELSE registration_challenge END,
             registration_signature = CASE WHEN registration_issued_at_ms < $3 THEN $4 ELSE registration_signature END,
             registration_issued_at_ms = GREATEST(registration_issued_at_ms, $3),
             session_id = $5
         WHERE id = $1",
    )
    .bind(device_id)
    .bind(challenge.to_vec())
    .bind(body.issued_at_ms)
    .bind(&body.signature)
    .bind(user.session.session_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Every change of an account's devices (a registration's count, a renewal,
/// a revocation) holds the account's row lock, taken first: one at a time,
/// in one lock order.
pub(crate) async fn lock_account_devices(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Records a verified revocation. Its sequence number is taken under the
/// account's lock, so the account's revocations are numbered in the order
/// they commit: other servers are told them by that number, and a bridge
/// that sent number n has sent every one before it.
pub(crate) async fn record_revocation(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    device_id: i64,
    revoked_at_ms: i64,
    signature: &str,
) -> sqlx::Result<()> {
    lock_account_devices(tx, user_id).await?;
    sqlx::query(
        "UPDATE user_devices SET is_active = false, revoked_at_ms = $3, revocation_signature = $4,
                                 revocation_seq = nextval('user_devices_revocation_seq')
         WHERE id = $1 AND user_id = $2",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(revoked_at_ms)
    .bind(signature)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `GET /api/devices` — the account's devices.
#[utoipa::path(
    get,
    path = "/api/devices",
    tag = "devices",
    operation_id = "listDevices",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's devices", body = Vec<DeviceRow>))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    #[derive(sqlx::FromRow)]
    struct Row {
        id: i64,
        label: String,
        public_signing: Vec<u8>,
        is_active: bool,
        trusted: bool,
        in_use: bool,
        this_session: bool,
        issued_at_ms: i64,
        created_at: OffsetDateTime,
        last_seen_at: Option<OffsetDateTime>,
    }
    let rows: Vec<Row> = sqlx::query_as(&format!(
        r#"SELECT d.id, COALESCE(d.label, '') AS label, d.public_signing, d.is_active,
                  {DEVICE_LIVE} AS trusted, {} AS in_use,
                  d.session_id IS NOT DISTINCT FROM $2 AS this_session,
                  d.registration_issued_at_ms AS issued_at_ms, d.created_at, d.last_seen_at
           FROM user_devices d JOIN users u ON u.id = d.user_id
           WHERE d.user_id = $1 ORDER BY d.created_at DESC"#,
        in_use()
    ))
    .bind(user_id)
    .bind(user.session.session_id)
    .fetch_all(&state.pool)
    .await?;
    let out: Vec<DeviceRow> = rows
        .into_iter()
        .map(|row| DeviceRow {
            device_id: row.id,
            label: row.label,
            public_signing: STANDARD.encode(row.public_signing),
            is_active: row.is_active,
            trusted: row.trusted,
            in_use: row.in_use,
            this_session: row.this_session,
            statement_issued_at_ms: row.issued_at_ms,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
        })
        .collect();
    Ok(Json(out).into_response())
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RevokeDeviceRequest {
    /// When, in UTC milliseconds (signed).
    revoked_at_ms: i64,
    /// The account authority's `DeviceRevocationV1` signature over the
    /// incarnation, the server, the device key and `revokedAtMs`.
    signature: String,
}

/// `DELETE /api/devices/{id}` — revokes a device for good, with the account's
/// signed revocation (a session alone cannot revoke an account's devices; the
/// statement is what other servers are told). The key never registers again.
#[utoipa::path(
    delete,
    path = "/api/devices/{id}",
    tag = "devices",
    security(("BearerAuth" = [])),
    params(("id" = i64, Path, description = "Device id")),
    request_body = RevokeDeviceRequest,
    responses(
        (status = 204, description = "Device revoked; live collab connections dropped"),
        (status = 403, description = "deviceNotAuthorized: the revocation does not verify under the account's authority")
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RevokeDeviceRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let device_id: i64 = id
        .parse()
        .map_err(|_| AppError::bad_request("invalid id"))?;

    let mut tx = state.pool.begin().await?;
    lock_account_devices(&mut tx, user_id).await?;
    let key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT public_signing FROM user_devices
         WHERE id = $1 AND user_id = $2 AND is_active FOR UPDATE",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(key) = key else {
        return Err(AppError::not_found("not found"));
    };
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::internal("device key"))?;
    // Its time is the client's clock's: within a day of this server's, as a
    // statement's (it is data only; revocations are told in this server's
    // own order).
    let now_ms = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    if (req.revoked_at_ms - now_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Err(not_authorized(
            "the revocation's time is more than a day off this server's clock",
        ));
    }
    let (authority, _) = account_authority(&mut tx, user_id).await?;
    if device_registration::verify_revocation(
        &authority,
        &state.config.chat_server_name,
        &key,
        req.revoked_at_ms,
        &req.signature,
    )
    .is_err()
    {
        return Err(not_authorized("the account's revocation does not verify"));
    }
    record_revocation(
        &mut tx,
        user_id,
        device_id,
        req.revoked_at_ms,
        &req.signature,
    )
    .await?;
    tx.commit().await?;
    // Drop this device's live collab connections.
    state.hub.close_device(device_id);
    Ok(StatusCode::NO_CONTENT.into_response())
}
