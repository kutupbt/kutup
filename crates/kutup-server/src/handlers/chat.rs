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

use std::collections::HashSet;

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
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use kutup_chat_proto::{
    AccountAddress, AckRequest, ChatProfileResponse, ChatWsServerMessage, ChatWsTicketResponse,
    DeliveredEnvelope, DeviceListMismatch, DeviceManifest, DevicePreKeyBundle, EcPreKey,
    EnvelopeType, KemPreKey, MailboxPage, OutgoingEnvelope, OwnChatProfileResponse,
    PreKeyCountResponse, PublishManifestResponse, PutChatProfileRequest, RegisterChatDeviceRequest,
    RegisterChatDeviceResponse, ReplenishKeysRequest, SendMessagesRequest,
    SubmitTransparencyWitnessRequest, SuiteId, TransparencyCheckpointResponse,
    UserPreKeyBundlesResponse,
};

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::handlers::{random_token, trusted_uuid};
use crate::middleware::AuthUser;
use crate::{jwt, ratelimit, AppState};

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
const WS_TICKET_TTL_SECONDS: i64 = 60;
const MAX_PREKEY_BATCH: usize = 100;
pub(crate) const PROFILE_ACCESS_KEY_HEADER: &str = "x-kutup-profile-access-key";
const PROFILE_ACCESS_KEY_BYTES: usize = 16;
const PROFILE_NAME_CIPHERTEXT_LENGTHS: [usize; 2] = [12 + 53 + 16, 12 + 257 + 16];
const MAX_PROFILE_AVATAR_CIPHERTEXT_BYTES: usize = 512 * 1024 + 1 + 12 + 16;
const WRAPPED_PROFILE_KEY_BYTES: usize = 12 + 32 + 16;
type PublicProfileRow = (String, i64, i32, String, Option<String>, Vec<u8>);
type OwnProfileRow = (String, i64, i32, String, Option<String>, String, Vec<u8>);

#[derive(Debug, Default, Deserialize)]
pub struct TransparencyQuery {
    #[serde(rename = "transparencyTreeSize")]
    transparency_tree_size: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CheckpointQuery {
    #[serde(rename = "fromTreeSize")]
    from_tree_size: Option<u64>,
}

/// Public signed head for client monitors and independent witnesses. This does
/// not touch a user directory or consume one-time keys.
#[utoipa::path(
    get,
    path = "/api/chat/transparency/checkpoint",
    tag = "chat",
    operation_id = "getChatTransparencyCheckpoint",
    params(("fromTreeSize" = Option<u64>, Query, description = "Previously verified tree size")),
    responses(
        (status = 200, description = "Signed head and append-only consistency proof", body = TransparencyCheckpointResponse),
        (status = 404, description = "Transparency log is empty"),
        (status = 409, description = "Requested prior head is newer than this view")
    )
)]
pub async fn get_transparency_checkpoint(
    State(state): State<AppState>,
    Query(query): Query<CheckpointQuery>,
) -> AppResult<Response> {
    let mut tx = state.pool.begin().await?;
    let response =
        crate::chat_transparency::prove_checkpoint(&mut tx, query.from_tree_size.unwrap_or(0))
            .await?;
    tx.commit().await?;
    Ok(Json(response).into_response())
}

/// Cache a statement made with an administrator-selected independent witness
/// key. Replays are idempotent; contradictory submissions fail closed.
#[utoipa::path(
    post,
    path = "/api/chat/transparency/witness",
    tag = "chat",
    operation_id = "submitChatTransparencyWitness",
    request_body = SubmitTransparencyWitnessRequest,
    responses(
        (status = 200, description = "Witness statement accepted"),
        (status = 401, description = "Witness is not in deployment policy"),
        (status = 404, description = "Checkpoint is unknown"),
        (status = 409, description = "Witness equivocated at this tree size")
    )
)]
pub async fn submit_transparency_witness(
    State(state): State<AppState>,
    Json(request): Json<SubmitTransparencyWitnessRequest>,
) -> AppResult<Response> {
    let inserted = crate::chat_transparency::submit_witness_attestation(
        &state.pool,
        &state.transparency_authority,
        &request,
    )
    .await?;
    Ok(Json(json!({ "accepted": true, "deduplicated": !inserted })).into_response())
}

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

pub(crate) fn envelope_type_code(t: EnvelopeType) -> i16 {
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

fn validate_profile(profile: &PutChatProfileRequest) -> AppResult<Vec<u8>> {
    if !canonical_profile_version(&profile.version) {
        return Err(AppError::bad_request(
            "profile version must be lowercase SHA-256 hex",
        ));
    }
    if profile.revision == 0 || profile.revision > i64::MAX as u64 {
        return Err(AppError::bad_request("profile revision is out of range"));
    }
    if profile.source_device_id == 0 || profile.source_device_id > MAX_DEVICE_ID as u32 {
        return Err(AppError::bad_request(
            "profile sourceDeviceId is out of range",
        ));
    }
    let name = b64_field("profile name", &profile.name)?;
    if !PROFILE_NAME_CIPHERTEXT_LENGTHS.contains(&name.len()) {
        return Err(AppError::bad_request(
            "encrypted profile name has an invalid padded length",
        ));
    }
    if let Some(avatar) = profile.avatar.as_deref() {
        let avatar = b64_field("profile avatar", avatar)?;
        if avatar.len() < 12 + 16 + 2 || avatar.len() > MAX_PROFILE_AVATAR_CIPHERTEXT_BYTES {
            return Err(AppError::bad_request(
                "encrypted profile avatar has an invalid size",
            ));
        }
    }
    if b64_field("wrapped profile key", &profile.wrapped_key)?.len() != WRAPPED_PROFILE_KEY_BYTES {
        return Err(AppError::bad_request(
            "wrapped profile key has an invalid length",
        ));
    }
    let verifier = hex::decode(&profile.access_key_verifier)
        .map_err(|_| AppError::bad_request("profile access verifier must be SHA-256 hex"))?;
    if verifier.len() != 32 || hex::encode(&verifier) != profile.access_key_verifier {
        return Err(AppError::bad_request(
            "profile access verifier must be lowercase SHA-256 hex",
        ));
    }
    Ok(verifier)
}

pub(crate) fn canonical_profile_version(value: &str) -> bool {
    hex::decode(value).is_ok_and(|decoded| decoded.len() == 32 && hex::encode(decoded) == value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
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
    if req.one_time_pre_keys.len() > MAX_PREKEY_BATCH
        || req.one_time_kyber_pre_keys.len() > MAX_PREKEY_BATCH
    {
        return Err(AppError::bad_request(
            "one-time prekey batches are limited to 100 keys per type",
        ));
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

    // Lock the account row, including when it has no chat devices yet. `FOR
    // UPDATE` over chat_devices alone does not lock an empty key range in
    // PostgreSQL, so two first-install requests could otherwise both choose 1.
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // The exact request is durably retried after ambiguous network outcomes.
    // Its identity key is generated once with the private store, making this a
    // stable idempotency key without adding a caller-controlled token.
    let existing: Option<i32> = sqlx::query_scalar(
        "SELECT device_id FROM chat_devices WHERE user_id = $1 AND identity_key = $2",
    )
    .bind(user_id)
    .bind(&req.identity_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(device_id) = existing {
        tx.commit().await?;
        return Ok(Json(RegisterChatDeviceResponse {
            device_id: device_id as u32,
        })
        .into_response());
    }

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
        (status = 200, description = "Published manifest and append proof", body = PublishManifestResponse),
        (status = 400, description = "Malformed or invalid signature"),
        (status = 409, description = "Version, chain, authority, or device-set conflict"),
    ),
    params(
        ("transparencyTreeSize" = Option<u64>, Query, description = "Highest verified local transparency checkpoint")
    ),
    security(("bearerAuth" = []))
)]
pub async fn publish_manifest(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<TransparencyQuery>,
    Json(manifest): Json<DeviceManifest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    validate_manifest(&manifest)?;
    let manifest_hash = manifest.manifest_hash().map_err(AppError::bad_request)?;
    let mut tx = state.pool.begin().await?;

    // This is the common serialization point for every device-set mutation and
    // observation. It also locks the first-manifest case, where selecting the
    // (not-yet-existent) manifest row `FOR UPDATE` cannot lock anything.
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    let username = username
        .filter(|username| !username.is_empty())
        .ok_or_else(|| AppError::conflict("account requires a username for chat"))?;

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
        let transparency = crate::chat_transparency::prove_manifest(
            &mut tx,
            user_id,
            query.transparency_tree_size.unwrap_or(0),
        )
        .await?;
        tx.commit().await?;
        return Ok(Json(PublishManifestResponse {
            manifest,
            transparency,
        })
        .into_response());
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
    crate::chat_transparency::append_manifest_update(
        &mut tx,
        user_id,
        &username,
        &manifest,
        &state.transparency_authority,
    )
    .await?;
    let transparency = crate::chat_transparency::prove_manifest(
        &mut tx,
        user_id,
        query.transparency_tree_size.unwrap_or(0),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(PublishManifestResponse {
        manifest,
        transparency,
    })
    .into_response())
}

/// `GET /api/chat/users/{username}/manifest` — fetch a local account's latest
/// signed device manifest without consuming any one-time prekeys.
#[utoipa::path(
    get,
    path = "/api/chat/users/{username}/manifest",
    tag = "chat",
    operation_id = "getChatDeviceManifest",
    params(
        ("username" = String, Path, description = "Local username"),
        ("syncDeviceId" = Option<u32>, Query, description = "Authenticated current device; preserves its one-time keys for own-device sync")
    ),
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

/// `PUT /api/chat/profile` — replace the caller's current opaque encrypted
/// profile. Revision/source-device ordering makes concurrent linked-device
/// writes deterministic; an exact replay is idempotent.
#[utoipa::path(
    put,
    path = "/api/chat/profile",
    tag = "chat",
    operation_id = "putChatProfile",
    request_body = PutChatProfileRequest,
    responses(
        (status = 200, description = "Encrypted profile published", body = PutChatProfileRequest),
        (status = 400, description = "Malformed encrypted profile"),
        (status = 404, description = "Source chat device is not registered"),
        (status = 409, description = "Profile revision lost a concurrent update")
    ),
    security(("bearerAuth" = []))
)]
pub async fn put_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(profile): Json<PutChatProfileRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let verifier = validate_profile(&profile)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let device_exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM chat_devices WHERE user_id = $1 AND device_id = $2")
            .bind(user_id)
            .bind(profile.source_device_id as i32)
            .fetch_optional(&mut *tx)
            .await?;
    if device_exists.is_none() {
        return Err(AppError::not_found(
            "profile source chat device is not registered",
        ));
    }

    let current = load_own_profile_in(&mut tx, user_id, true).await?;
    if let Some(current) = current {
        let incoming_order = (profile.revision, profile.source_device_id);
        let current_order = (current.revision, current.source_device_id);
        if incoming_order < current_order {
            return Err(AppError::conflict("profile revision is stale"));
        }
        if incoming_order == current_order {
            if profile == current {
                tx.commit().await?;
                return Ok(Json(profile).into_response());
            }
            return Err(AppError::conflict(
                "profile revision already contains different ciphertext",
            ));
        }
    }

    // Keep previous ciphertext versions available to holders of their old
    // capability while atomically advancing the single owner-visible head.
    sqlx::query(
        "UPDATE chat_profiles SET is_current = false
         WHERE user_id = $1 AND is_current = true",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO chat_profiles
             (user_id, version, revision, source_device_id, name_ciphertext,
              avatar_ciphertext, wrapped_key, access_key_verifier, is_current)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true)
         ON CONFLICT (user_id, version) DO UPDATE SET
             revision = EXCLUDED.revision,
             source_device_id = EXCLUDED.source_device_id,
             name_ciphertext = EXCLUDED.name_ciphertext,
             avatar_ciphertext = EXCLUDED.avatar_ciphertext,
             wrapped_key = EXCLUDED.wrapped_key,
             access_key_verifier = EXCLUDED.access_key_verifier,
             is_current = true,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(&profile.version)
    .bind(profile.revision as i64)
    .bind(profile.source_device_id as i32)
    .bind(&profile.name)
    .bind(&profile.avatar)
    .bind(&profile.wrapped_key)
    .bind(verifier)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(profile).into_response())
}

/// `GET /api/chat/profile` — owner-only linked-device recovery of the current
/// encrypted profile and master-key-wrapped random profile key.
#[utoipa::path(
    get,
    path = "/api/chat/profile",
    tag = "chat",
    operation_id = "getOwnChatProfile",
    responses(
        (status = 200, description = "Current owner encrypted profile", body = PutChatProfileRequest),
        (status = 404, description = "No encrypted profile has been published")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_own_profile(State(state): State<AppState>, auth: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let mut tx = state.pool.begin().await?;
    let profile = load_own_profile_in(&mut tx, user_id, false)
        .await?
        .ok_or_else(|| AppError::not_found("chat profile not found"))?;
    tx.commit().await?;
    Ok(Json(profile).into_response())
}

/// `GET /api/chat/users/{username}/profile/{version}` — fetch a capability-
/// gated local or federated encrypted peer profile. The access key is carried
/// in a header so it does not enter URL logs.
#[utoipa::path(
    get,
    path = "/api/chat/users/{username}/profile/{version}",
    tag = "chat",
    operation_id = "getChatProfile",
    params(
        ("username" = String, Path, description = "Canonical local or federated account"),
        ("version" = String, Path, description = "Profile-key-derived version")
    ),
    responses(
        (status = 200, description = "Opaque encrypted profile", body = ChatProfileResponse),
        (status = 404, description = "Profile/version/capability not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_user_profile(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path((username, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    if !canonical_profile_version(&version) {
        return Err(AppError::not_found("chat profile not found"));
    }
    let access_key = profile_access_key_from_headers(&headers)?;
    let address: AccountAddress =
        username
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if let Some(server) = address.server.as_deref() {
        let federation = state
            .chat_federation
            .as_ref()
            .ok_or_else(|| AppError::bad_request("chat federation is not configured"))?;
        if server != federation.server_name() {
            let profile = federation
                .fetch_remote_profile(&address, &version, &access_key)
                .await?;
            return Ok(Json(profile).into_response());
        }
    }
    let profile = load_public_profile(&state, &address.username, &version, &access_key)
        .await?
        .ok_or_else(|| AppError::not_found("chat profile not found"))?;
    Ok(Json(profile).into_response())
}

fn profile_access_key_from_headers(headers: &HeaderMap) -> AppResult<Vec<u8>> {
    let encoded = headers
        .get(PROFILE_ACCESS_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::not_found("chat profile not found"))?;
    let access_key = STANDARD
        .decode(encoded)
        .map_err(|_| AppError::not_found("chat profile not found"))?;
    if access_key.len() != PROFILE_ACCESS_KEY_BYTES {
        return Err(AppError::not_found("chat profile not found"));
    }
    Ok(access_key)
}

pub(crate) async fn load_public_profile(
    state: &AppState,
    username: &str,
    version: &str,
    access_key: &[u8],
) -> AppResult<Option<ChatProfileResponse>> {
    let row: Option<PublicProfileRow> = sqlx::query_as(
        "SELECT p.version, p.revision, p.source_device_id, p.name_ciphertext,
                p.avatar_ciphertext, p.access_key_verifier
         FROM chat_profiles p
         JOIN users u ON u.id = p.user_id
         WHERE u.username = $1 AND u.is_active = true AND p.version = $2",
    )
    .bind(username)
    .bind(version)
    .fetch_optional(&state.pool)
    .await?;
    let Some((version, revision, source_device_id, name, avatar, verifier)) = row else {
        return Ok(None);
    };
    let presented = Sha256::digest(access_key);
    if !constant_time_eq(&verifier, &presented) {
        return Ok(None);
    }
    Ok(Some(ChatProfileResponse {
        version,
        revision: revision as u64,
        source_device_id: source_device_id as u32,
        name,
        avatar,
    }))
}

async fn load_own_profile_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    lock: bool,
) -> AppResult<Option<OwnChatProfileResponse>> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT version, revision, source_device_id, name_ciphertext,
                avatar_ciphertext, wrapped_key, access_key_verifier
         FROM chat_profiles WHERE user_id = $1 AND is_current = true{suffix}"
    );
    let row: Option<OwnProfileRow> = sqlx::query_as(&sql)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(
        |(version, revision, source_device_id, name, avatar, wrapped_key, verifier)| {
            PutChatProfileRequest {
                version,
                revision: revision as u64,
                source_device_id: source_device_id as u32,
                name,
                avatar,
                wrapped_key,
                access_key_verifier: hex::encode(verifier),
            }
        },
    ))
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
    let mut tx = state.pool.begin().await?;
    // Serialize revocation with registration, manifest publication, bundle
    // snapshots, and sends that validate this account's exact device set.
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM chat_devices WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(AppError::not_found("no such chat device"));
    }
    tx.commit().await?;
    state.chat_hub.close_device(user_id, device_id);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    #[serde(rename = "deviceId")]
    device_id: i32,
}

#[derive(Debug, Default, Deserialize)]
pub struct BundleQuery {
    /// When present, this is an authenticated own-device sync fetch. The
    /// current device's public bundle is still returned for signed-manifest
    /// verification, but its one-time keys are not consumed.
    #[serde(rename = "syncDeviceId")]
    pub(crate) sync_device_id: Option<i32>,
    /// Prior verified transparency checkpoint. The response carries an RFC
    /// 6962 consistency proof from this size to its current checkpoint.
    #[serde(rename = "transparencyTreeSize")]
    pub(crate) transparency_tree_size: Option<u64>,
}

/// Asserts the (user, device) pair exists; used by the device-scoped endpoints.
async fn require_device(state: &AppState, user_id: Uuid, device_id: i32) -> AppResult<()> {
    let exists: Option<i32> = sqlx::query_scalar(
        "UPDATE chat_devices SET last_seen_at = now()
         WHERE user_id = $1 AND device_id = $2 RETURNING 1",
    )
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

    if req.one_time_pre_keys.len() > MAX_PREKEY_BATCH
        || req.one_time_kyber_pre_keys.len() > MAX_PREKEY_BATCH
    {
        return Err(AppError::bad_request(
            "one-time prekey batches are limited to 100 keys per type",
        ));
    }

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
    params(
        ("username" = String, Path, description = "Local or canonical federated username"),
        ("syncDeviceId" = Option<u32>, Query, description = "Authenticated current device for own-account sync"),
        ("transparencyTreeSize" = Option<u64>, Query, description = "Highest verified homeserver transparency checkpoint; zero on first observation")
    ),
    responses(
        (status = 200, description = "Bundles for all devices", body = UserPreKeyBundlesResponse),
        (status = 404, description = "Unknown user or user has no chat devices"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_user_bundles(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
    Query(query): Query<BundleQuery>,
) -> AppResult<Response> {
    if !ratelimit::CHAT_KEYS_ACCOUNT.allow(&auth.user_id) {
        return Err(AppError::too_many_requests(
            "too many chat key requests for this account",
        ));
    }
    let address: AccountAddress =
        username
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if let Some(server) = address.server.as_deref() {
        let federation = state
            .chat_federation
            .as_ref()
            .ok_or_else(|| AppError::bad_request("chat federation is not configured"))?;
        if server != federation.server_name() {
            if query.sync_device_id.is_some() {
                return Err(AppError::forbidden(
                    "linked-device key fetch is limited to the local account",
                ));
            }
            let bundles = federation
                .fetch_remote_bundles(&address, query.transparency_tree_size.unwrap_or(0))
                .await?;
            return Ok(Json(bundles).into_response());
        }
    }

    if query.sync_device_id.is_some() {
        let caller_id = trusted_uuid(&auth.user_id)?;
        let target_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
                .bind(&address.username)
                .fetch_optional(&state.pool)
                .await?;
        if Some(caller_id) != target_id {
            return Err(AppError::forbidden(
                "linked-device key fetch is limited to the caller's account",
            ));
        }
    }

    let bundles = load_user_bundles(
        &state,
        &address.username,
        &address.canonical(),
        query.sync_device_id,
        true,
        query.transparency_tree_size.unwrap_or(0),
    )
    .await?;
    Ok(Json(bundles).into_response())
}

/// Load one local account's signed device directory. Local client fetches
/// consume one-time keys. Federated server reads intentionally serve only the
/// reusable last-resort PQ key so replay cannot exhaust a user's prekey pool.
pub(crate) async fn load_user_bundles(
    state: &AppState,
    username: &str,
    response_username: &str,
    sync_device_id: Option<i32>,
    consume_one_time: bool,
    transparency_tree_size: u64,
) -> AppResult<UserPreKeyBundlesResponse> {
    let target: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
            .bind(username)
            .fetch_optional(&state.pool)
            .await?;
    let Some(target_id) = target else {
        return Err(AppError::not_found("user not found"));
    };

    let mut tx = state.pool.begin().await?;

    // Hold a stable account/device/manifest snapshot until the one-time keys
    // have been allocated. Writers take `FOR UPDATE` on this same row.
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR SHARE")
        .bind(target_id)
        .execute(&mut *tx)
        .await?;
    if let Some(device_id) = sync_device_id {
        let exists: Option<i32> = sqlx::query_scalar(
            "UPDATE chat_devices SET last_seen_at = now()
             WHERE user_id = $1 AND device_id = $2 RETURNING 1",
        )
        .bind(target_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(AppError::not_found("no such chat device"));
        }
    }

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
        // A self-sync fetch includes the caller's public bundle so it can be
        // checked against the complete signed manifest, but that bundle is
        // never used for encryption and must not burn a one-time prekey.
        let current_sync_device = sync_device_id == Some(device_id);
        let ec: Option<(i64, String)> = if current_sync_device || !consume_one_time {
            None
        } else {
            sqlx::query_as(
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
            .await?
        };

        // Pop one one-time Kyber prekey; fall back to the (reusable) last-resort key.
        let kem: Option<(i64, String, String)> = if current_sync_device || !consume_one_time {
            None
        } else {
            sqlx::query_as(
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
            .await?
        };
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

    let manifest: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT manifest FROM chat_device_manifests WHERE user_id = $1")
            .bind(target_id)
            .fetch_optional(&mut *tx)
            .await?;
    let manifest = manifest
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored chat manifest is invalid: {error}")))?;
    let transparency = if manifest.is_some() {
        Some(
            crate::chat_transparency::prove_manifest(&mut tx, target_id, transparency_tree_size)
                .await?,
        )
    } else {
        None
    };
    tx.commit().await?;

    Ok(UserPreKeyBundlesResponse {
        username: response_username.to_string(),
        devices: bundles,
        manifest,
        transparency,
    })
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
    validate_send_request(&req, false, None)?;
    let address: AccountAddress =
        username
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if let Some(server) = address.server.as_deref() {
        let federation = state
            .chat_federation
            .as_ref()
            .ok_or_else(|| AppError::bad_request("chat federation is not configured"))?;
        if server != federation.server_name() {
            let envelope_count = req.envelopes.len();
            return match federation
                .enqueue_send(&state, sender_id, &address, req)
                .await?
            {
                crate::chat_federation::FederatedSendOutcome::Delivered { deduplicated } => Ok(
                    Json(json!({ "stored": envelope_count, "deduplicated": deduplicated }))
                        .into_response(),
                ),
                crate::chat_federation::FederatedSendOutcome::Mismatch(mismatch) => {
                    Ok((StatusCode::CONFLICT, Json(mismatch)).into_response())
                }
                crate::chat_federation::FederatedSendOutcome::Rejected(_) => {
                    Err(AppError::not_found("remote chat recipient is unavailable"))
                }
                crate::chat_federation::FederatedSendOutcome::Pending => Err(AppError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "federated send is durably queued for retry",
                )),
            };
        }
    }
    let recipient: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE username = $1 AND is_active = true")
            .bind(&address.username)
            .fetch_optional(&state.pool)
            .await?;
    let Some((recipient_id,)) = recipient else {
        return Err(AppError::not_found("user not found"));
    };

    deliver_messages(&state, sender_id, recipient_id, req, None).await
}

/// `POST /api/chat/sync/messages` — deliver an encrypted sent transcript to
/// every other active device of the authenticated account. The sending device
/// is excluded from the exact-set check; an empty set is valid for a
/// single-device account.
#[utoipa::path(
    post,
    path = "/api/chat/sync/messages",
    tag = "chat",
    operation_id = "chatSyncMessages",
    request_body = SendMessagesRequest,
    responses(
        (status = 200, description = "Stored for every other linked device"),
        (status = 404, description = "Unknown sending device"),
        (status = 409, description = "Linked device list out of date", body = DeviceListMismatch),
    ),
    security(("bearerAuth" = []))
)]
pub async fn sync_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<SendMessagesRequest>,
) -> AppResult<Response> {
    let sender_id = trusted_uuid(&auth.user_id)?;
    let excluded_device = req.sender_device_id as i32;
    validate_send_request(&req, true, Some(excluded_device))?;
    deliver_messages(&state, sender_id, sender_id, req, Some(excluded_device)).await
}

/// Validate, idempotently store, and push one logical ciphertext fan-out. A
/// self-sync passes `excluded_device`; ordinary direct delivery passes `None`.
async fn deliver_messages(
    state: &AppState,
    sender_id: Uuid,
    recipient_id: Uuid,
    req: SendMessagesRequest,
    excluded_device: Option<i32>,
) -> AppResult<Response> {
    // Lock both accounts in deterministic UUID order, then keep the recipient
    // device set stable through mailbox insertion. Device registration,
    // revocation, and manifest publication take `FOR UPDATE` on these rows.
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 OR id = $2 ORDER BY id FOR SHARE")
        .bind(sender_id)
        .bind(recipient_id)
        .fetch_all(&mut *tx)
        .await?;

    // The sender must address from one of their own registered chat devices.
    let sender_username: Option<String> = sqlx::query_scalar(
        "UPDATE chat_devices d SET last_seen_at = now()
         FROM users u
         WHERE d.user_id = $1 AND d.device_id = $2 AND u.id = d.user_id
         RETURNING COALESCE(u.username, '')",
    )
    .bind(sender_id)
    .bind(req.sender_device_id as i32)
    .fetch_optional(&mut *tx)
    .await?;
    let sender_username =
        sender_username.ok_or_else(|| AppError::not_found("no such chat device"))?;

    // Claim before validating the *current* recipient device set. A retry of a
    // send that was already accepted must return the same success even if a
    // recipient device was added or removed after that acceptance. For a new
    // send, a later mismatch rolls this insert back with the transaction.
    let delivery_scope = if excluded_device.is_some() {
        "sync"
    } else {
        "direct"
    };
    let claimed: Option<(String,)> = sqlx::query_as(
        "INSERT INTO chat_sends (sender_user_id, sender_device_id, send_id, delivery_scope)
         VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING send_id",
    )
    .bind(sender_id)
    .bind(req.sender_device_id as i32)
    .bind(&req.send_id)
    .bind(delivery_scope)
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        tx.rollback().await?;
        return Ok(
            Json(json!({ "stored": req.envelopes.len(), "deduplicated": true })).into_response(),
        );
    }

    // Exact device-set check (Signal's missing/stale/extra contract).
    let mut current: Vec<(i32, i64)> =
        sqlx::query_as("SELECT device_id, registration_id FROM chat_devices WHERE user_id = $1")
            .bind(recipient_id)
            .fetch_all(&mut *tx)
            .await?;
    if let Some(excluded_device) = excluded_device {
        if !current
            .iter()
            .any(|(device_id, _)| *device_id == excluded_device)
        {
            return Err(AppError::not_found("no such chat device"));
        }
        current.retain(|(device_id, _)| *device_id != excluded_device);
    }
    let mismatch = device_list_mismatch(&current, &req.envelopes);
    if !mismatch.missing_devices.is_empty()
        || !mismatch.stale_devices.is_empty()
        || !mismatch.extra_devices.is_empty()
    {
        tx.rollback().await?;
        return Ok((StatusCode::CONFLICT, Json(mismatch)).into_response());
    }

    // Store, then push to live sockets (mailbox row first: the push is best-effort).
    let mut stored: Vec<(Uuid, i32, DeliveredEnvelope)> = Vec::with_capacity(req.envelopes.len());

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

pub(crate) fn validate_send_request(
    req: &SendMessagesRequest,
    allow_empty: bool,
    excluded_device: Option<i32>,
) -> AppResult<()> {
    if req.sender_device_id == 0 || req.sender_device_id > MAX_DEVICE_ID as u32 {
        return Err(AppError::bad_request("senderDeviceId out of range"));
    }
    if !allow_empty && req.envelopes.is_empty() {
        return Err(AppError::bad_request("no envelopes"));
    }
    if req.send_id.is_empty() || req.send_id.len() > 64 {
        return Err(AppError::bad_request("missing or oversized sendId"));
    }
    for envelope in &req.envelopes {
        let bytes = b64_field("content", &envelope.content)?;
        if bytes.len() > MAX_CONTENT_BYTES {
            return Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "envelope content exceeds maxContentBytes",
            ));
        }
    }
    let unique_devices: HashSet<u32> = req.envelopes.iter().map(|e| e.device_id).collect();
    if unique_devices.len() != req.envelopes.len() {
        return Err(AppError::bad_request(
            "only one envelope is allowed per recipient device",
        ));
    }
    if excluded_device.is_some_and(|device| {
        req.envelopes
            .iter()
            .any(|envelope| envelope.device_id as i32 == device)
    }) {
        return Err(AppError::bad_request(
            "a linked-device sync cannot target its sending device",
        ));
    }
    Ok(())
}

pub(crate) fn device_list_mismatch(
    current: &[(i32, i64)],
    envelopes: &[OutgoingEnvelope],
) -> DeviceListMismatch {
    let mut mismatch = DeviceListMismatch::default();
    for (device_id, registration_id) in current {
        match envelopes
            .iter()
            .find(|envelope| envelope.device_id == *device_id as u32)
        {
            None => mismatch.missing_devices.push(*device_id as u32),
            Some(envelope) if envelope.registration_id as i64 != *registration_id => {
                mismatch.stale_devices.push(*device_id as u32);
            }
            Some(_) => {}
        }
    }
    for envelope in envelopes {
        if !current
            .iter()
            .any(|(device_id, _)| *device_id as u32 == envelope.device_id)
        {
            mismatch.extra_devices.push(envelope.device_id);
        }
    }
    mismatch
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

fn ws_ticket_hash(ticket: &str) -> String {
    hex::encode(Sha256::digest(ticket.as_bytes()))
}

/// `POST /api/chat/ws-ticket?deviceId=N` — mint a single-use, short-lived
/// browser WebSocket credential. Only its hash is stored server-side.
#[utoipa::path(
    post,
    path = "/api/chat/ws-ticket",
    tag = "chat",
    operation_id = "createChatWsTicket",
    params(("deviceId" = u32, Query, description = "Chat device id")),
    responses(
        (status = 200, description = "One-time ticket", body = ChatWsTicketResponse),
        (status = 404, description = "No such chat device"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn create_ws_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<DeviceQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, q.device_id).await?;
    let ticket = random_token(32);
    let expires_at: OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO chat_ws_tickets (token_hash, user_id, device_id, expires_at)
         VALUES ($1, $2, $3, now() + ($4 * interval '1 second'))
         RETURNING expires_at",
    )
    .bind(ws_ticket_hash(&ticket))
    .bind(user_id)
    .bind(q.device_id)
    .bind(WS_TICKET_TTL_SECONDS)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(ChatWsTicketResponse {
        ticket,
        expires_at: expires_at.format(&Rfc3339).unwrap_or_default(),
    })
    .into_response())
}

async fn consume_ws_ticket(state: &AppState, ticket: &str) -> AppResult<(Uuid, i32)> {
    if ticket.is_empty() || ticket.len() > 128 {
        return Err(AppError::unauthorized("invalid WebSocket ticket"));
    }
    sqlx::query_as(
        "DELETE FROM chat_ws_tickets
         WHERE token_hash = $1 AND expires_at > now()
         RETURNING user_id, device_id",
    )
    .bind(ws_ticket_hash(ticket))
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("invalid or expired WebSocket ticket"))
}

#[derive(Debug, Default, Deserialize)]
pub struct ChatWsQuery {
    ticket: Option<String>,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
}

/// `GET /api/chat/ws` — authenticates, then upgrades. Pushes newly arrived envelopes to
/// this device; the mailbox remains the source of truth (clients ack over REST). Auth
/// uses `Authorization: Bearer` for native clients or a single-use `?ticket=`
/// minted by `POST /api/chat/ws-ticket` for browsers.
#[utoipa::path(
    get,
    path = "/api/chat/ws",
    tag = "chat",
    operation_id = "chatWs",
    params(
        ("ticket" = Option<String>, Query, description = "Single-use browser ticket"),
        ("deviceId" = Option<String>, Query, description = "Required with Authorization header"),
    ),
    responses((status = 101, description = "WebSocket upgrade — JSON frames of ChatWsServerMessage"))
)]
pub async fn ws(
    State(state): State<AppState>,
    Query(q): Query<ChatWsQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty());
    let (user_uuid, device_id) = match bearer {
        Some(token) => {
            let (user_id, _is_admin) = jwt::validate_access_token(token, &state.config.jwt_secret)
                .map_err(|_| AppError::unauthorized("invalid token"))?;
            let user_uuid =
                Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("invalid token"))?;
            let device_id: i32 = match q.device_id.as_deref().and_then(|s| s.trim().parse().ok()) {
                Some(device_id) if (1..=MAX_DEVICE_ID).contains(&device_id) => device_id,
                _ => {
                    return Err(AppError::unauthorized("missing or invalid deviceId"));
                }
            };
            require_device(&state, user_uuid, device_id).await?;
            (user_uuid, device_id)
        }
        None => match q.ticket.as_deref() {
            Some(ticket) => consume_ws_ticket(&state, ticket).await?,
            None => return Err(AppError::unauthorized("missing WebSocket credentials")),
        },
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_profile() -> PutChatProfileRequest {
        PutChatProfileRequest {
            version: "01".repeat(32),
            revision: 1,
            source_device_id: 1,
            name: STANDARD.encode(vec![0u8; PROFILE_NAME_CIPHERTEXT_LENGTHS[0]]),
            avatar: None,
            wrapped_key: STANDARD.encode(vec![0u8; WRAPPED_PROFILE_KEY_BYTES]),
            access_key_verifier: "02".repeat(32),
        }
    }

    fn envelope(device_id: u32, registration_id: u32) -> OutgoingEnvelope {
        OutgoingEnvelope {
            device_id,
            registration_id,
            envelope_type: EnvelopeType::Message,
            suite: SuiteId::PqxdhTripleRatchetV1,
            content: STANDARD.encode(b"ciphertext"),
        }
    }

    #[test]
    fn self_sync_exact_set_excludes_only_the_sending_device() {
        let all_devices = [(1, 101), (2, 202), (3, 303)];
        let linked_devices: Vec<_> = all_devices
            .into_iter()
            .filter(|(device_id, _)| *device_id != 2)
            .collect();

        let exact = device_list_mismatch(&linked_devices, &[envelope(1, 101), envelope(3, 303)]);
        assert!(exact.missing_devices.is_empty());
        assert!(exact.stale_devices.is_empty());
        assert!(exact.extra_devices.is_empty());

        let wrong = device_list_mismatch(&linked_devices, &[envelope(2, 202), envelope(3, 999)]);
        assert_eq!(wrong.missing_devices, vec![1]);
        assert_eq!(wrong.stale_devices, vec![3]);
        assert_eq!(wrong.extra_devices, vec![2]);

        let request = SendMessagesRequest {
            sender_device_id: 2,
            send_id: "note-1".into(),
            envelopes: vec![envelope(2, 202)],
            access_token: None,
        };
        let error = validate_send_request(&request, true, Some(2)).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn encrypted_profile_validation_accepts_only_bounded_opaque_fields() {
        let profile = valid_profile();
        assert_eq!(validate_profile(&profile).unwrap(), vec![2u8; 32]);

        let mut oversized_avatar = profile.clone();
        oversized_avatar.avatar =
            Some(STANDARD.encode(vec![0u8; MAX_PROFILE_AVATAR_CIPHERTEXT_BYTES + 1]));
        assert_eq!(
            validate_profile(&oversized_avatar).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );

        let mut noncanonical_version = profile;
        noncanonical_version.version = "AA".repeat(32);
        assert_eq!(
            validate_profile(&noncanonical_version).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn profile_capability_comparison_is_constant_time_for_equal_lengths() {
        assert!(constant_time_eq(&[3u8; 32], &[3u8; 32]));
        assert!(!constant_time_eq(&[3u8; 32], &[4u8; 32]));
        assert!(!constant_time_eq(&[3u8; 31], &[3u8; 32]));
    }
}
