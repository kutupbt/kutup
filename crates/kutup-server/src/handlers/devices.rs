//! Collaboration devices (docs/plans/device-registration.md): the Ed25519 keys
//! a browser tab or the CLI signs collaboration frames with. Each is vouched
//! for by the account's authority (from the master key), over a one-time
//! challenge this server issued, so a session token alone cannot add one and
//! a captured registration cannot be played again. Revoking a device marks it
//! inactive; open sockets close within the access recheck.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

use kutup_crypto::device_registration::{self, CHALLENGE_LEN, PURPOSE_COLLAB_FRAMES};

/// How long a challenge may be answered.
const CHALLENGE_MINUTES: i64 = 5;
/// The most challenges one account holds unanswered; a new one evicts the
/// oldest, so nobody can fill the table.
const MAX_OPEN_CHALLENGES: i64 = 5;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChallenge {
    /// 32 random bytes, canonical base64: sign it once, within five minutes.
    challenge: String,
}

/// `POST /api/devices/challenge` — a one-time challenge for registering a
/// device: what the account's statement for the device key signs.
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
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    let mut tx = state.pool.begin().await?;
    // Expired ones go as new ones are made.
    sqlx::query("DELETE FROM device_registration_challenges WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO device_registration_challenges (challenge_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(mins => $3))",
    )
    .bind(Sha256::digest(challenge).to_vec())
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

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterDeviceRequest {
    /// The device's Ed25519 public key, canonical base64 (32 bytes).
    public_signing: String,
    /// What the account calls it (not signed: it can be renamed).
    label: String,
    /// The challenge from `POST /api/devices/challenge`, canonical base64.
    challenge: String,
    /// The account authority's `DeviceRegistrationV1` signature over the
    /// incarnation, the account, the device key, its purpose and the
    /// challenge (`kutup_crypto::device_registration`), canonical base64.
    signature: String,
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
    is_active: bool,
    /// Active and registered under the account's current incarnation: the
    /// collaboration routes accept it. A client whose stored device is not
    /// trusted registers a new one.
    trusted: bool,
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

/// `POST /api/devices` — registers a device key the account vouches for.
/// `403 deviceNotAuthorized` when the statement does not verify under the
/// account's authority, or its challenge is unknown, used or expired (get a
/// new one and sign again); `409` when the key is another device's.
#[utoipa::path(
    post,
    path = "/api/devices",
    tag = "devices",
    operation_id = "registerDevice",
    security(("BearerAuth" = [])),
    request_body = RegisterDeviceRequest,
    responses(
        (status = 201, description = "Device signing key registered", body = RegisterDeviceResponse),
        (status = 403, description = "deviceNotAuthorized: the account's statement does not verify, or the challenge is not one to answer")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let device_key = canonical_32(&req.public_signing, "publicSigning")?;
    let challenge = canonical_32(&req.challenge, "challenge")?;
    if req.label.chars().count() > 100 {
        return Err(AppError::bad_request("label is too long"));
    }

    let mut tx = state.pool.begin().await?;
    // The challenge is used up whatever comes next: one answer each.
    let fresh: Option<bool> = sqlx::query_scalar(
        "DELETE FROM device_registration_challenges
         WHERE challenge_hash = $1 AND user_id = $2
         RETURNING expires_at >= now()",
    )
    .bind(Sha256::digest(challenge).to_vec())
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if fresh != Some(true) {
        tx.commit().await?;
        return Err(not_authorized("the challenge is unknown, used or expired"));
    }
    let (authority, incarnation_id): (String, String) = sqlx::query_as(
        "SELECT account_authority_public_key, account_incarnation_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let authority = STANDARD
        .decode(&authority)
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or_else(|| not_authorized("the account has no authority key yet"))?;
    // The challenge is looked up by its hash (an index lookup, so nothing
    // compares the secret itself in variable time) and used up in this
    // transaction, which also stores the device.
    if device_registration::verify(
        &authority,
        &state.config.chat_server_name,
        &user_id.to_string(),
        &device_key,
        PURPOSE_COLLAB_FRAMES,
        &challenge,
        &req.signature,
    )
    .is_err()
    {
        tx.commit().await?;
        return Err(not_authorized(
            "the account's statement for this device does not verify",
        ));
    }

    let inserted: Result<(i64, OffsetDateTime), sqlx::Error> = sqlx::query_as(
        r#"INSERT INTO user_devices (user_id, public_signing, label, incarnation_id,
                                     registration_challenge, registration_signature)
           VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)
           RETURNING id, created_at"#,
    )
    .bind(user_id)
    .bind(device_key.to_vec())
    .bind(&req.label)
    .bind(incarnation_id.trim())
    .bind(challenge.to_vec())
    .bind(&req.signature)
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

/// `GET /api/devices` — mirrors `List`.
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
    type Row = (
        i64,
        String,
        bool,
        bool,
        OffsetDateTime,
        Option<OffsetDateTime>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT d.id, COALESCE(d.label, ''), d.is_active,
                  d.is_active AND d.incarnation_id = u.account_incarnation_id,
                  d.created_at, d.last_seen_at
           FROM user_devices d JOIN users u ON u.id = d.user_id
           WHERE d.user_id = $1 ORDER BY d.created_at DESC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    let out: Vec<DeviceRow> = rows
        .into_iter()
        .map(
            |(device_id, label, is_active, trusted, created_at, last_seen_at)| DeviceRow {
                device_id,
                label,
                is_active,
                trusted,
                created_at,
                last_seen_at,
            },
        )
        .collect();
    Ok(Json(out).into_response())
}

/// `DELETE /api/devices/{id}` — mirrors `Revoke`.
#[utoipa::path(
    delete,
    path = "/api/devices/{id}",
    tag = "devices",
    security(("BearerAuth" = [])),
    params(("id" = i64, Path, description = "Device id")),
    responses((status = 204, description = "Device revoked; live collab connections dropped"))
)]
pub async fn revoke(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let device_id: i64 = id
        .parse()
        .map_err(|_| AppError::bad_request("invalid id"))?;

    let res = sqlx::query(
        "UPDATE user_devices SET is_active = false WHERE id = $1 AND user_id = $2 AND is_active = true",
    )
    .bind(device_id)
    .bind(user_id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {}
        _ => return Err(AppError::not_found("not found")),
    }
    // Drop this device's live collab WS connections — mirrors Go's hub.CloseDevice.
    state.hub.close_device(device_id);
    Ok(StatusCode::NO_CONTENT.into_response())
}
