//! Chat handlers — the local (single-server) slice of the federated E2EE chat track.
//!
//! Phase 2 of `docs/research/11-federated-chat.md`: device directory, prekey pools,
//! store-and-forward mailboxes, and the WS drain. Everything the server touches here is
//! public-key material or opaque ciphertext; there is no plaintext path.
//!
//! Trust model notes (v1, mirrors `devices.rs`): the JWT is the trust anchor for *who*
//! is calling; prekey signatures are stored and served verbatim for **clients** to
//! verify (that's where verification is meaningful under E2EE — a malicious server
//! could serve garbage regardless, and clients must not trust server-side checks).

use axum::extract::{Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use kutup_chat_proto::{
    AckRequest, ChatWsServerMessage, DeliveredEnvelope, DeviceListMismatch, DeviceManifest,
    DevicePreKeyBundle, EcPreKey, EnvelopeType, KemPreKey, MailboxPage, PreKeyCountResponse,
    RegisterChatDeviceRequest, RegisterChatDeviceResponse, ReplenishKeysRequest,
    SendMessagesRequest, SuiteId, UserPreKeyBundlesResponse,
};

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::{jwt, AppState};

/// libsignal registration ids are random values in `1..16380`.
const MAX_REGISTRATION_ID: u32 = 16380;
/// libsignal `DeviceId` fits in 7 bits on the wire.
const MAX_DEVICE_ID: i32 = 127;
/// Mailbox drain page cap.
const MAX_DRAIN_LIMIT: i64 = 500;
const DEFAULT_DRAIN_LIMIT: i64 = 100;
/// Max decoded ciphertext bytes per envelope (advertised as `maxContentBytes`).
/// Kilobyte-scale headroom over a `PreKeySignalMessage` (~1.8 KB with the PQ KEM).
const MAX_CONTENT_BYTES: usize = 65536;

/// Validates a base64 field and returns the decoded bytes (callers that only
/// need validation ignore the return).
fn b64_field(name: &'static str, value: &str) -> AppResult<Vec<u8>> {
    if value.is_empty() {
        return Err(AppError::bad_request(format!("{name} must be base64")));
    }
    STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request(format!("{name} must be base64")))
}

fn validate_ec_prekey(name: &'static str, key: &EcPreKey, need_signature: bool) -> AppResult<()> {
    b64_field(name, &key.public_key)?;
    match &key.signature {
        Some(sig) => {
            b64_field(name, sig)?;
        }
        None if need_signature => {
            return Err(AppError::bad_request(format!(
                "{name} requires a signature"
            )))
        }
        None => {}
    }
    Ok(())
}

fn validate_kem_prekey(name: &'static str, key: &KemPreKey) -> AppResult<()> {
    b64_field(name, &key.public_key)?;
    b64_field(name, &key.signature)?;
    Ok(())
}

fn envelope_type_code(t: EnvelopeType) -> i16 {
    match t {
        EnvelopeType::PreKey => 1,
        EnvelopeType::Message => 2,
    }
}

fn envelope_type_from_code(code: i16) -> EnvelopeType {
    if code == 1 {
        EnvelopeType::PreKey
    } else {
        EnvelopeType::Message
    }
}

fn validate_manifest(manifest: &DeviceManifest) -> AppResult<()> {
    if manifest.version > i64::MAX as u64 {
        return Err(AppError::bad_request("manifest version is too large"));
    }
    manifest.verify().map_err(AppError::bad_request)?;
    let issued_at = OffsetDateTime::parse(&manifest.issued_at, &Rfc3339)
        .map_err(|_| AppError::bad_request("manifest issuedAt must be RFC 3339"))?;
    if issued_at > OffsetDateTime::now_utc() + time::Duration::minutes(10) {
        return Err(AppError::bad_request(
            "manifest issuedAt is too far in the future",
        ));
    }
    Ok(())
}

/// `POST /api/chat/device` — register this client as a chat device. The server assigns
/// the lowest free device id (1..=127).
#[utoipa::path(
    post,
    path = "/api/chat/device",
    tag = "chat",
    operation_id = "registerChatDevice",
    request_body = RegisterChatDeviceRequest,
    responses(
        (status = 200, description = "Registered", body = RegisterChatDeviceResponse),
        (status = 400, description = "Malformed key material"),
        (status = 409, description = "Device limit (127) reached"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn register_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<RegisterChatDeviceRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;

    if req.registration_id == 0 || req.registration_id > MAX_REGISTRATION_ID {
        return Err(AppError::bad_request("registrationId out of range"));
    }
    b64_field("identityKey", &req.identity_key)?;
    validate_ec_prekey("signedPreKey", &req.signed_pre_key, true)?;
    validate_kem_prekey("lastResortKyberPreKey", &req.last_resort_kyber_pre_key)?;
    for k in &req.one_time_pre_keys {
        validate_ec_prekey("oneTimePreKeys", k, false)?;
    }
    for k in &req.one_time_kyber_pre_keys {
        validate_kem_prekey("oneTimeKyberPreKeys", k)?;
    }

    let mut tx = state.pool.begin().await?;

    // Serialize per-user registrations, then take the lowest free id.
    let taken: Vec<i32> = sqlx::query_scalar(
        "SELECT device_id FROM chat_devices WHERE user_id = $1 ORDER BY device_id FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut device_id: i32 = 1;
    for t in &taken {
        if *t == device_id {
            device_id += 1;
        } else {
            break;
        }
    }
    if device_id > MAX_DEVICE_ID {
        return Err(AppError::conflict("chat device limit reached"));
    }

    sqlx::query(
        r#"INSERT INTO chat_devices (
               user_id, device_id, suite, registration_id, identity_key,
               signed_pre_key_id, signed_pre_key, signed_pre_key_signature,
               last_resort_kyber_pre_key_id, last_resort_kyber_pre_key,
               last_resort_kyber_pre_key_signature, name)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(req.suite.as_u16() as i16)
    .bind(req.registration_id as i64)
    .bind(&req.identity_key)
    .bind(req.signed_pre_key.key_id as i64)
    .bind(&req.signed_pre_key.public_key)
    .bind(req.signed_pre_key.signature.as_deref().unwrap_or_default())
    .bind(req.last_resort_kyber_pre_key.key_id as i64)
    .bind(&req.last_resort_kyber_pre_key.public_key)
    .bind(&req.last_resort_kyber_pre_key.signature)
    .bind(&req.name)
    .execute(&mut *tx)
    .await?;

    insert_ec_pool(&mut tx, user_id, device_id, &req.one_time_pre_keys).await?;
    insert_kem_pool(&mut tx, user_id, device_id, &req.one_time_kyber_pre_keys).await?;

    tx.commit().await?;

    Ok(Json(RegisterChatDeviceResponse {
        device_id: device_id as u32,
    })
    .into_response())
}

/// `POST /api/chat/manifest` — publish the caller's signed current device set.
/// Updates form a strict hash-linked sequence and cannot rotate the account
/// authority key in v1. The declared devices must exactly match the server's
/// registered devices, making an injected server-side device fail closed.
#[utoipa::path(
    post,
    path = "/api/chat/manifest",
    tag = "chat",
    operation_id = "publishChatDeviceManifest",
    request_body = DeviceManifest,
    responses(
        (status = 200, description = "Published manifest", body = DeviceManifest),
        (status = 400, description = "Malformed or invalid signature"),
        (status = 409, description = "Version, chain, authority, or device-set conflict"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn publish_manifest(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(manifest): Json<DeviceManifest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    validate_manifest(&manifest)?;
    let manifest_hash = manifest.manifest_hash().map_err(AppError::bad_request)?;
    let mut tx = state.pool.begin().await?;

    let current: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT version, manifest_hash, authority_key_id
         FROM chat_device_manifests WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let mut idempotent = false;
    match current {
        None if manifest.version != 1 || manifest.previous_hash.is_some() => {
            return Err(AppError::conflict("first manifest must be version 1"));
        }
        None => {}
        Some((version, current_hash, authority_key_id)) => {
            if manifest.version == version as u64 && manifest_hash == current_hash {
                idempotent = true;
            } else if manifest.version != version as u64 + 1 {
                return Err(AppError::conflict(
                    "manifest version must advance by exactly one",
                ));
            } else if manifest.previous_hash.as_deref() != Some(current_hash.as_str()) {
                return Err(AppError::conflict("manifest previousHash mismatch"));
            }
            if manifest.authority_key_id != authority_key_id {
                return Err(AppError::conflict(
                    "account authority rotation is not supported in v1",
                ));
            }
        }
    }

    let registered: Vec<(i32, i64, String)> = sqlx::query_as(
        "SELECT device_id, registration_id, identity_key
         FROM chat_devices WHERE user_id = $1 ORDER BY device_id FOR SHARE",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    if registered.is_empty() {
        return Err(AppError::conflict("account has no registered chat devices"));
    }
    let exact_match = registered.len() == manifest.devices.len()
        && registered.iter().zip(&manifest.devices).all(
            |((device_id, registration_id, identity_key), declared)| {
                declared.device_id == *device_id as u32
                    && declared.registration_id == *registration_id as u32
                    && declared.identity_key == *identity_key
            },
        );
    if !exact_match {
        return Err(AppError::conflict(
            "manifest devices do not match registered chat devices",
        ));
    }
    if idempotent {
        tx.commit().await?;
        return Ok(Json(manifest).into_response());
    }

    let value = serde_json::to_value(&manifest)
        .map_err(|error| AppError::internal(format!("serialize chat manifest: {error}")))?;
    sqlx::query(
        "INSERT INTO chat_device_manifests
             (user_id, version, manifest_hash, authority_key_id, manifest)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (user_id) DO UPDATE SET
             version = EXCLUDED.version,
             manifest_hash = EXCLUDED.manifest_hash,
             authority_key_id = EXCLUDED.authority_key_id,
             manifest = EXCLUDED.manifest,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(manifest.version as i64)
    .bind(manifest_hash)
    .bind(&manifest.authority_key_id)
    .bind(value)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(manifest).into_response())
}

/// `GET /api/chat/users/{username}/manifest` — fetch a local account's latest
/// signed device manifest without consuming any one-time prekeys.
#[utoipa::path(
    get,
    path = "/api/chat/users/{username}/manifest",
    tag = "chat",
    operation_id = "getChatDeviceManifest",
    params(("username" = String, Path, description = "Local username")),
    responses(
        (status = 200, description = "Latest signed manifest", body = DeviceManifest),
        (status = 404, description = "Unknown user or no manifest"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_user_manifest(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(username): Path<String>,
) -> AppResult<Response> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT m.manifest
         FROM chat_device_manifests m
         JOIN users u ON u.id = m.user_id
         WHERE u.username = $1 AND u.is_active = true",
    )
    .bind(username)
    .fetch_optional(&state.pool)
    .await?;
    let value = value.ok_or_else(|| AppError::not_found("chat manifest not found"))?;
    let manifest: DeviceManifest = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("stored chat manifest is invalid: {error}")))?;
    Ok(Json(manifest).into_response())
}

async fn insert_ec_pool(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    device_id: i32,
    keys: &[EcPreKey],
) -> AppResult<()> {
    for k in keys {
        sqlx::query(
            "INSERT INTO chat_one_time_pre_keys (user_id, device_id, key_id, public_key)
             VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(k.key_id as i64)
        .bind(&k.public_key)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn insert_kem_pool(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    device_id: i32,
    keys: &[KemPreKey],
) -> AppResult<()> {
    for k in keys {
        sqlx::query(
            "INSERT INTO chat_one_time_kyber_pre_keys
                 (user_id, device_id, key_id, public_key, signature)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(k.key_id as i64)
        .bind(&k.public_key)
        .bind(&k.signature)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// `GET /api/chat/device` — the caller's registered chat devices.
#[utoipa::path(
    get,
    path = "/api/chat/device",
    tag = "chat",
    operation_id = "listChatDevices",
    responses((status = 200, description = "Devices", body = serde_json::Value)),
    security(("bearerAuth" = []))
)]
pub async fn list_devices(State(state): State<AppState>, auth: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let rows: Vec<(i32, i16, String, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT device_id, suite, name, created_at, last_seen_at
         FROM chat_devices WHERE user_id = $1 ORDER BY device_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let devices: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, suite, name, created, seen)| {
            json!({
                "deviceId": id,
                "suite": suite,
                "name": name,
                "createdAt": created.format(&Rfc3339).unwrap_or_default(),
                "lastSeenAt": seen.and_then(|t| t.format(&Rfc3339).ok()),
            })
        })
        .collect();
    Ok(Json(json!({ "devices": devices })).into_response())
}

/// `DELETE /api/chat/device/{deviceId}` — revoke a chat device. Hard-deletes the
/// directory entry; cascades wipe its prekey pools and mailbox, and any live sockets
/// are closed.
#[utoipa::path(
    delete,
    path = "/api/chat/device/{deviceId}",
    tag = "chat",
    operation_id = "revokeChatDevice",
    params(("deviceId" = u32, Path, description = "Chat device id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "No such device"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn revoke_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<i32>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let deleted = sqlx::query("DELETE FROM chat_devices WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(AppError::not_found("no such chat device"));
    }
    state.chat_hub.close_device(user_id, device_id);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    #[serde(rename = "deviceId")]
    device_id: i32,
}

/// Asserts the (user, device) pair exists; used by the device-scoped endpoints.
async fn require_device(state: &AppState, user_id: Uuid, device_id: i32) -> AppResult<()> {
    let exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM chat_devices WHERE user_id = $1 AND device_id = $2")
            .bind(user_id)
            .bind(device_id)
            .fetch_optional(&state.pool)
            .await?;
    if exists.is_none() {
        return Err(AppError::not_found("no such chat device"));
    }
    Ok(())
}

/// `PUT /api/chat/keys?deviceId=N` — rotate the signed prekey / last-resort Kyber
/// prekey and/or upload more one-time prekeys.
#[utoipa::path(
    put,
    path = "/api/chat/keys",
    tag = "chat",
    operation_id = "replenishChatKeys",
    params(("deviceId" = u32, Query, description = "Chat device id")),
    request_body = ReplenishKeysRequest,
    responses(
        (status = 200, description = "Updated"),
        (status = 404, description = "No such device"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn replenish_keys(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<DeviceQuery>,
    Json(req): Json<ReplenishKeysRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, q.device_id).await?;

    if let Some(spk) = &req.signed_pre_key {
        validate_ec_prekey("signedPreKey", spk, true)?;
    }
    if let Some(lrk) = &req.last_resort_kyber_pre_key {
        validate_kem_prekey("lastResortKyberPreKey", lrk)?;
    }
    for k in &req.one_time_pre_keys {
        validate_ec_prekey("oneTimePreKeys", k, false)?;
    }
    for k in &req.one_time_kyber_pre_keys {
        validate_kem_prekey("oneTimeKyberPreKeys", k)?;
    }

    let mut tx = state.pool.begin().await?;
    if let Some(spk) = &req.signed_pre_key {
        sqlx::query(
            "UPDATE chat_devices SET signed_pre_key_id = $3, signed_pre_key = $4,
                 signed_pre_key_signature = $5
             WHERE user_id = $1 AND device_id = $2",
        )
        .bind(user_id)
        .bind(q.device_id)
        .bind(spk.key_id as i64)
        .bind(&spk.public_key)
        .bind(spk.signature.as_deref().unwrap_or_default())
        .execute(&mut *tx)
        .await?;
    }
    if let Some(lrk) = &req.last_resort_kyber_pre_key {
        sqlx::query(
            "UPDATE chat_devices SET last_resort_kyber_pre_key_id = $3,
                 last_resort_kyber_pre_key = $4, last_resort_kyber_pre_key_signature = $5
             WHERE user_id = $1 AND device_id = $2",
        )
        .bind(user_id)
        .bind(q.device_id)
        .bind(lrk.key_id as i64)
        .bind(&lrk.public_key)
        .bind(&lrk.signature)
        .execute(&mut *tx)
        .await?;
    }
    insert_ec_pool(&mut tx, user_id, q.device_id, &req.one_time_pre_keys).await?;
    insert_kem_pool(&mut tx, user_id, q.device_id, &req.one_time_kyber_pre_keys).await?;
    tx.commit().await?;

    Ok(Json(json!({ "ok": true })).into_response())
}

/// `GET /api/chat/keys/count?deviceId=N` — remaining one-time pool sizes (clients
/// replenish below a threshold).
#[utoipa::path(
    get,
    path = "/api/chat/keys/count",
    tag = "chat",
    operation_id = "chatKeysCount",
    params(("deviceId" = u32, Query, description = "Chat device id")),
    responses((status = 200, description = "Pool sizes", body = PreKeyCountResponse)),
    security(("bearerAuth" = []))
)]
pub async fn prekey_count(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<DeviceQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, q.device_id).await?;
    let ec: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_one_time_pre_keys WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(q.device_id)
    .fetch_one(&state.pool)
    .await?;
    let kem: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_one_time_kyber_pre_keys WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(q.device_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(PreKeyCountResponse {
        one_time_pre_keys: ec.max(0) as u64,
        one_time_kyber_pre_keys: kem.max(0) as u64,
    })
    .into_response())
}

/// `GET /api/chat/users/{username}/keys` — PQXDH prekey bundles for every chat device
/// of `username`. Consumes one one-time EC and one one-time Kyber prekey per device
/// (falling back to the last-resort Kyber prekey — a bundle is never non-PQ).
/// Rate-limited (`RATE_LIMIT_CHAT_KEYS_PER_MIN`) because fetches consume pool keys.
#[utoipa::path(
    get,
    path = "/api/chat/users/{username}/keys",
    tag = "chat",
    operation_id = "chatUserPreKeyBundles",
    params(("username" = String, Path, description = "Local username")),
    responses(
        (status = 200, description = "Bundles for all devices", body = UserPreKeyBundlesResponse),
        (status = 404, description = "Unknown user or user has no chat devices"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_user_bundles(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(username): Path<String>,
) -> AppResult<Response> {
    let target: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await?;
    let Some(target_id) = target else {
        return Err(AppError::not_found("user not found"));
    };

    let mut tx = state.pool.begin().await?;

    #[allow(clippy::type_complexity)]
    let devices: Vec<(
        i32,
        i16,
        i64,
        String,
        i64,
        String,
        String,
        i64,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT device_id, suite, registration_id, identity_key,
                    signed_pre_key_id, signed_pre_key, signed_pre_key_signature,
                    last_resort_kyber_pre_key_id, last_resort_kyber_pre_key,
                    last_resort_kyber_pre_key_signature
             FROM chat_devices WHERE user_id = $1 ORDER BY device_id",
    )
    .bind(target_id)
    .fetch_all(&mut *tx)
    .await?;
    if devices.is_empty() {
        return Err(AppError::not_found("user has no chat devices"));
    }

    let mut bundles = Vec::with_capacity(devices.len());
    for (
        device_id,
        suite,
        registration_id,
        identity_key,
        spk_id,
        spk,
        spk_sig,
        lrk_id,
        lrk,
        lrk_sig,
    ) in devices
    {
        // Pop one one-time EC prekey (absent is fine — X3DH/PQXDH allow it).
        let ec: Option<(i64, String)> = sqlx::query_as(
            "DELETE FROM chat_one_time_pre_keys t
             WHERE t.ctid IN (
                 SELECT ctid FROM chat_one_time_pre_keys
                 WHERE user_id = $1 AND device_id = $2
                 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
             RETURNING key_id, public_key",
        )
        .bind(target_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Pop one one-time Kyber prekey; fall back to the (reusable) last-resort key.
        let kem: Option<(i64, String, String)> = sqlx::query_as(
            "DELETE FROM chat_one_time_kyber_pre_keys t
             WHERE t.ctid IN (
                 SELECT ctid FROM chat_one_time_kyber_pre_keys
                 WHERE user_id = $1 AND device_id = $2
                 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
             RETURNING key_id, public_key, signature",
        )
        .bind(target_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (kyber_id, kyber_pub, kyber_sig) = kem.unwrap_or((lrk_id, lrk, lrk_sig));

        bundles.push(DevicePreKeyBundle {
            device_id: device_id as u32,
            registration_id: registration_id as u32,
            suite: SuiteId::from_u16(suite as u16)
                .ok_or_else(|| AppError::internal("unknown suite in chat_devices"))?,
            identity_key,
            signed_pre_key: EcPreKey {
                key_id: spk_id as u32,
                public_key: spk,
                signature: Some(spk_sig),
            },
            kyber_pre_key: KemPreKey {
                key_id: kyber_id as u32,
                public_key: kyber_pub,
                signature: kyber_sig,
            },
            one_time_pre_key: ec.map(|(id, public_key)| EcPreKey {
                key_id: id as u32,
                public_key,
                signature: None,
            }),
        });
    }

    tx.commit().await?;

    let manifest: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT manifest FROM chat_device_manifests WHERE user_id = $1")
            .bind(target_id)
            .fetch_optional(&state.pool)
            .await?;
    let manifest = manifest
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored chat manifest is invalid: {error}")))?;

    Ok(Json(UserPreKeyBundlesResponse {
        username,
        devices: bundles,
        manifest,
    })
    .into_response())
}

/// `POST /api/chat/users/{username}/messages` — deliver one logical message as
/// per-device ciphertexts. The device set must exactly match the recipient's current
/// devices (ids and registration ids) or the send is rejected with a 409
/// [`DeviceListMismatch`] so clients can't silently skip a device.
#[utoipa::path(
    post,
    path = "/api/chat/users/{username}/messages",
    tag = "chat",
    operation_id = "chatSendMessages",
    params(("username" = String, Path, description = "Recipient (local username)")),
    request_body = SendMessagesRequest,
    responses(
        (status = 200, description = "Stored (and pushed to live sockets)"),
        (status = 404, description = "Unknown recipient"),
        (status = 409, description = "Device list out of date", body = DeviceListMismatch),
    ),
    security(("bearerAuth" = []))
)]
pub async fn send_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
    Json(req): Json<SendMessagesRequest>,
) -> AppResult<Response> {
    let sender_id = trusted_uuid(&auth.user_id)?;
    if req.envelopes.is_empty() {
        return Err(AppError::bad_request("no envelopes"));
    }
    if req.send_id.is_empty() || req.send_id.len() > 64 {
        return Err(AppError::bad_request("missing or oversized sendId"));
    }
    for e in &req.envelopes {
        let bytes = b64_field("content", &e.content)?;
        if bytes.len() > MAX_CONTENT_BYTES {
            return Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "envelope content exceeds maxContentBytes",
            ));
        }
    }
    // The sender must address from one of their own registered chat devices.
    require_device(&state, sender_id, req.sender_device_id as i32).await?;
    let sender_username: String =
        sqlx::query_scalar("SELECT COALESCE(username, '') FROM users WHERE id = $1")
            .bind(sender_id)
            .fetch_one(&state.pool)
            .await?;

    let recipient: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await?;
    let Some(recipient_id) = recipient else {
        return Err(AppError::not_found("user not found"));
    };

    // Exact device-set check (Signal's missing/stale/extra contract).
    let current: Vec<(i32, i64)> =
        sqlx::query_as("SELECT device_id, registration_id FROM chat_devices WHERE user_id = $1")
            .bind(recipient_id)
            .fetch_all(&state.pool)
            .await?;
    let mut mismatch = DeviceListMismatch::default();
    for (dev, reg) in &current {
        match req.envelopes.iter().find(|e| e.device_id == *dev as u32) {
            None => mismatch.missing_devices.push(*dev as u32),
            Some(e) if e.registration_id as i64 != *reg => mismatch.stale_devices.push(*dev as u32),
            Some(_) => {}
        }
    }
    for e in &req.envelopes {
        if !current.iter().any(|(dev, _)| *dev as u32 == e.device_id) {
            mismatch.extra_devices.push(e.device_id);
        }
    }
    if !mismatch.missing_devices.is_empty()
        || !mismatch.stale_devices.is_empty()
        || !mismatch.extra_devices.is_empty()
    {
        return Ok((StatusCode::CONFLICT, Json(mismatch)).into_response());
    }

    // Store, then push to live sockets (mailbox row first: the push is best-effort).
    let mut stored: Vec<(Uuid, i32, DeliveredEnvelope)> = Vec::with_capacity(req.envelopes.len());
    let mut tx = state.pool.begin().await?;

    // Idempotency gate: claim the sendId first (docs/chat-protocol.md §7.1). A repeat
    // of a send whose response was lost finds the row already present and returns the
    // same success without storing duplicate mailbox rows. The claim shares the
    // transaction with the inserts, so a crash can't leave a claimed id with no messages.
    let claimed: Option<(String,)> = sqlx::query_as(
        "INSERT INTO chat_sends (sender_user_id, sender_device_id, send_id)
         VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING send_id",
    )
    .bind(sender_id)
    .bind(req.sender_device_id as i32)
    .bind(&req.send_id)
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        tx.rollback().await?;
        return Ok(
            Json(json!({ "stored": req.envelopes.len(), "deduplicated": true })).into_response(),
        );
    }

    for e in &req.envelopes {
        let (id, cursor, ts): (Uuid, i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO chat_mailbox (recipient_user_id, recipient_device_id, sender,
                 sender_device_id, envelope_type, suite, content)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(e.device_id as i32)
        .bind(&sender_username)
        .bind(req.sender_device_id as i32)
        .bind(envelope_type_code(e.envelope_type))
        .bind(e.suite.as_u16() as i16)
        .bind(&e.content)
        .fetch_one(&mut *tx)
        .await?;
        stored.push((
            recipient_id,
            e.device_id as i32,
            DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender: Some(sender_username.clone()),
                sender_device_id: req.sender_device_id,
                envelope_type: e.envelope_type,
                suite: e.suite,
                content: e.content.clone(),
                server_timestamp: ts.format(&Rfc3339).unwrap_or_default(),
            },
        ));
    }
    tx.commit().await?;

    for (user, device, envelope) in stored {
        let msg = ChatWsServerMessage::Envelope { envelope };
        if let Ok(text) = serde_json::to_string(&msg) {
            for conn in state.chat_hub.connections(user, device) {
                conn.write(ChatWsOut::Text(text.clone())).await;
            }
        }
    }

    Ok(Json(json!({ "stored": req.envelopes.len() })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct DrainQuery {
    #[serde(rename = "deviceId")]
    device_id: i32,
    limit: Option<i64>,
    /// Resume paging after this cursor (exclusive). Omit for the first page.
    after: Option<i64>,
}

/// `GET /api/chat/messages?deviceId=N` — drain the device's mailbox (oldest first).
/// Envelopes stay stored until acked via `POST /api/chat/messages/ack`.
#[utoipa::path(
    get,
    path = "/api/chat/messages",
    tag = "chat",
    operation_id = "chatDrainMailbox",
    params(
        ("deviceId" = u32, Query, description = "Chat device id"),
        ("limit" = Option<i64>, Query, description = "Page size (default 100, max 500)"),
    ),
    responses((status = 200, description = "A page of envelopes", body = MailboxPage)),
    security(("bearerAuth" = []))
)]
pub async fn drain_mailbox(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<DrainQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, q.device_id).await?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_DRAIN_LIMIT)
        .clamp(1, MAX_DRAIN_LIMIT);

    // `after` is exclusive; NULL (first page) matches everything. Ordered by the
    // monotonic cursor (docs/chat-protocol.md §8.3).
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        i64,
        Option<String>,
        i32,
        i16,
        i16,
        String,
        OffsetDateTime,
    )> = sqlx::query_as(
        "SELECT id, cursor, sender, sender_device_id, envelope_type, suite, content, server_ts
             FROM chat_mailbox
             WHERE recipient_user_id = $1 AND recipient_device_id = $2
               AND ($4::BIGINT IS NULL OR cursor > $4)
             ORDER BY cursor
             LIMIT $3",
    )
    .bind(user_id)
    .bind(q.device_id)
    .bind(limit + 1)
    .bind(q.after)
    .fetch_all(&state.pool)
    .await?;

    let more = rows.len() as i64 > limit;
    let envelopes: Vec<DeliveredEnvelope> = rows
        .into_iter()
        .take(limit as usize)
        .map(
            |(id, cursor, sender, sender_dev, etype, suite, content, ts)| DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender,
                sender_device_id: sender_dev as u32,
                envelope_type: envelope_type_from_code(etype),
                suite: SuiteId::from_u16(suite as u16).unwrap_or(SuiteId::PqxdhTripleRatchetV1),
                content,
                server_timestamp: ts.format(&Rfc3339).unwrap_or_default(),
            },
        )
        .collect();

    Ok(Json(MailboxPage { envelopes, more }).into_response())
}

#[derive(Debug, Deserialize)]
pub struct AckQuery {
    #[serde(rename = "deviceId")]
    device_id: i32,
}

/// `POST /api/chat/messages/ack?deviceId=N` — delete processed envelopes.
#[utoipa::path(
    post,
    path = "/api/chat/messages/ack",
    tag = "chat",
    operation_id = "chatAckMessages",
    params(("deviceId" = u32, Query, description = "Chat device id")),
    request_body = AckRequest,
    responses((status = 200, description = "Acked (count of deleted rows)")),
    security(("bearerAuth" = []))
)]
pub async fn ack_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<AckQuery>,
    Json(req): Json<AckRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, q.device_id).await?;
    let ids: Vec<Uuid> = req
        .ids
        .iter()
        .map(|s| Uuid::parse_str(s).map_err(|_| AppError::bad_request("invalid envelope id")))
        .collect::<AppResult<_>>()?;
    let deleted = sqlx::query(
        "DELETE FROM chat_mailbox
         WHERE recipient_user_id = $1 AND recipient_device_id = $2 AND id = ANY($3)",
    )
    .bind(user_id)
    .bind(q.device_id)
    .bind(&ids)
    .execute(&state.pool)
    .await?
    .rows_affected();
    Ok(Json(json!({ "acked": deleted })).into_response())
}

#[derive(Debug, Default, Deserialize)]
pub struct ChatWsQuery {
    token: Option<String>,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
}

/// `GET /api/chat/ws` — authenticates, then upgrades. Pushes newly arrived envelopes to
/// this device; the mailbox remains the source of truth (clients ack over REST). Auth
/// mirrors the collab WS: token via `Authorization` or `?token=` (browsers can't set
/// headers on `new WebSocket`).
#[utoipa::path(
    get,
    path = "/api/chat/ws",
    tag = "chat",
    operation_id = "chatWs",
    params(
        ("token" = Option<String>, Query, description = "Access token"),
        ("deviceId" = String, Query, description = "Chat device id"),
    ),
    responses((status = 101, description = "WebSocket upgrade — JSON frames of ChatWsServerMessage"))
)]
pub async fn ws(
    State(state): State<AppState>,
    Query(q): Query<ChatWsQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or(q.token);
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return Err(AppError::unauthorized("missing token")),
    };
    let (user_id, _is_admin) = jwt::validate_access_token(&token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("invalid token"))?;
    let user_uuid =
        Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("invalid token"))?;

    let device_id: i32 = match q.device_id.as_deref().and_then(|s| s.trim().parse().ok()) {
        Some(d) if (1..=MAX_DEVICE_ID).contains(&d) => d,
        _ => return Err(AppError::unauthorized("missing or invalid deviceId")),
    };
    require_device(&state, user_uuid, device_id).await?;

    Ok(upgrade.on_upgrade(move |socket| async move {
        handle_connection(state, socket, user_uuid, device_id).await;
    }))
}

/// Per-connection coroutine: register with the hub, tell the client to drain its
/// backlog over REST, then relay pushes until the socket dies or the device is revoked.
async fn handle_connection(state: AppState, socket: WebSocket, user_id: Uuid, device_id: i32) {
    let (conn, mut rx) = state.chat_hub.join(user_id, device_id);

    let _ = sqlx::query(
        "UPDATE chat_devices SET last_seen_at = now() WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .execute(&state.pool)
    .await;

    let (mut sink, mut stream) = socket.split();

    // Writer task — drains the hub queue into the socket.
    let writer = tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            match out {
                ChatWsOut::Text(text) => {
                    if sink.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                ChatWsOut::Close => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    });

    // Anything that arrived while the device was offline is fetched over REST.
    if let Ok(text) = serde_json::to_string(&ChatWsServerMessage::DrainMailbox) {
        conn.write(ChatWsOut::Text(text)).await;
    }

    // Read loop — the client sends nothing meaningful today (acks are REST); we only
    // watch for disconnect and honour forced close.
    loop {
        tokio::select! {
            _ = conn.close.notified() => break,
            msg = stream.next() => match msg {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {} // ping/pong handled by axum; other frames ignored
            },
        }
    }

    state.chat_hub.leave(user_id, device_id, conn.conn_id);
    writer.abort();
}
