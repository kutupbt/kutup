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

use axum::extract::{ConnectInfo, Path, Query, State};
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
    capability_hash, constant_time_capability_hash_eq, AccountManifestDeviceV1,
    AccountManifestHistoryPageV1, AccountManifestPublicationV1, AccountManifestV1, AccountRef,
    AckRequest, AnonymousPreKeyRequestV1, ChatProfileResponse, ChatWsClientMessage,
    ChatWsServerMessage, ChatWsTicketResponse, DeliveredEnvelope, DeviceListMismatch,
    DevicePreKeyBundle, DirectChatSuiteId, EcPreKey, EnvelopeType, KemPreKey, MailboxPage,
    OutgoingEnvelope, OwnChatProfileResponse, PreKeyCountResponse, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, ProfileSuiteId, PutChatProfileRequest, RegisterChatDeviceRequest,
    RegisterChatDeviceResponse, RenameChatDeviceRequest, ReplenishKeysRequest,
    SealedDeliveryResponseV1, SealedMessageSubmissionV1, SealedOutgoingEnvelopeV1,
    SendMessagesRequest, UserPreKeyBundlesResponse,
};

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::handlers::{random_token, trusted_uuid};
use crate::middleware::AuthUser;
use crate::{ratelimit, AppState};

/// libsignal registration ids are random values in `1..16380`.
const MAX_REGISTRATION_ID: u32 = 16380;
/// libsignal `DeviceId` fits in 7 bits on the wire.
const MAX_DEVICE_ID: i32 = 127;
/// Human-readable device labels are UI metadata, not cryptographic identity.
const MAX_DEVICE_NAME_CHARS: usize = 64;
/// Mailbox drain page cap.
const MAX_DRAIN_LIMIT: i64 = 500;
/// The most one drain page carries (at least one envelope, however large).
const MAX_DRAIN_BYTES: usize = 4 * 1024 * 1024;

/// Convert PostgreSQL's signed `SMALLINT` representation into the closed Direct
/// Chat suite registry without wrapping negative values or applying a default.
fn direct_chat_suite_from_db(value: i16, source: &'static str) -> AppResult<DirectChatSuiteId> {
    let code = u16::try_from(value).map_err(|_| {
        AppError::internal(format!(
            "invalid direct chat suite {value} stored in {source}"
        ))
    })?;
    DirectChatSuiteId::try_from(code).map_err(|_| {
        AppError::internal(format!(
            "unknown direct chat suite {value} stored in {source}"
        ))
    })
}

fn normalized_device_name(value: &str) -> AppResult<String> {
    let name = value.trim();
    if name.is_empty() {
        return Err(AppError::bad_request("device name is required"));
    }
    if name.chars().count() > MAX_DEVICE_NAME_CHARS {
        return Err(AppError::bad_request(
            "device name must be 64 characters or fewer",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "device name cannot contain control characters",
        ));
    }
    Ok(name.to_owned())
}

fn profile_suite_from_db(value: i16, source: &'static str) -> AppResult<ProfileSuiteId> {
    let code = u16::try_from(value).map_err(|_| {
        AppError::internal(format!(
            "invalid encrypted profile suite {value} stored in {source}"
        ))
    })?;
    ProfileSuiteId::try_from(code).map_err(|_| {
        AppError::internal(format!(
            "unknown encrypted profile suite {value} stored in {source}"
        ))
    })
}
const DEFAULT_DRAIN_LIMIT: i64 = 100;
/// Max decoded ciphertext bytes per envelope (advertised as `maxContentBytes`).
/// Kilobyte-scale headroom over a `PreKeySignalMessage` (~1.8 KB with the PQ KEM).
const MAX_CONTENT_BYTES: usize = 65536;
const WS_TICKET_TTL_SECONDS: i64 = 60;
const MAX_PREKEY_BATCH: usize = 100;
pub(crate) const PROFILE_ACCESS_KEY_HEADER: &str = "x-kutup-profile-access-key";
const PROFILE_ACCESS_KEY_BYTES: usize = 16;
type PublicProfileRow = (
    i16,
    String,
    i64,
    i32,
    String,
    Option<String>,
    Option<String>,
    Vec<u8>,
);
type OwnProfileRow = (
    i16,
    String,
    i64,
    i32,
    String,
    Option<String>,
    Option<String>,
    String,
    Vec<u8>,
    Vec<u8>,
);

/// An account on this Chat server is local. Federation is only involved when
/// the address names a different server.
/// `?server=` beside a Chat path's `:accountId`: the account's server, this
/// one when absent (docs/plans/account-ids.md).
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct AccountServerQuery {
    /// The account's server; this server when absent.
    pub server: Option<String>,
}

/// The account a Chat path names: one of ours (its user id), or another
/// server's, asked of that server through federation.
pub(crate) enum NamedAccount {
    Local(Uuid),
    Remote(AccountRef),
}

/// The account `:accountId` and `?server=` name. Ours must be an active
/// account (`404` otherwise); another server's needs federation.
pub(crate) async fn named_account(
    state: &AppState,
    account_id: &str,
    server: Option<&str>,
) -> AppResult<NamedAccount> {
    let local = &state.config.chat_server_name;
    let account = crate::account_ids::named(local, account_id, server)?;
    if account.server != *local {
        state
            .federation
            .as_ref()
            .ok_or_else(|| AppError::bad_request("chat federation is not configured"))?;
        return Ok(NamedAccount::Remote(account));
    }
    let user = crate::account_ids::local_user(&state.pool, local, &account)
        .await?
        .ok_or_else(|| AppError::not_found("no such account"))?;
    Ok(NamedAccount::Local(user))
}

#[derive(Debug, Deserialize)]
pub struct ManifestHistoryQuery {
    /// The account's server; this server when absent.
    pub server: Option<String>,
    #[serde(rename = "fromSequence")]
    pub from_sequence: u64,
    #[serde(rename = "toSequence")]
    pub to_sequence: u64,
    #[serde(rename = "pageFromSequence")]
    pub page_from_sequence: Option<u64>,
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

fn validate_manifest(manifest: &AccountManifestV1) -> AppResult<()> {
    if manifest.sequence > i64::MAX as u64 {
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

fn validate_profile(
    profile: &PutChatProfileRequest,
    expected_account: &AccountRef,
) -> AppResult<(Vec<u8>, Vec<u8>)> {
    if profile.suite != ProfileSuiteId::XChaCha20Poly1305V1 || profile.account != *expected_account
    {
        return Err(AppError::bad_request(
            "profile suite or account does not match the authenticated account",
        ));
    }
    if !canonical_profile_version(&profile.version) {
        return Err(AppError::bad_request(
            "profile version must be lowercase SHA-256 hex",
        ));
    }
    if profile.revision == 0 || profile.revision > i64::MAX as u64 {
        return Err(AppError::bad_request("profile revision is out of range"));
    }
    // A chat device (1-127), or the account app (docs/plans/unified-profile.md).
    if (profile.source_device_id == 0 || profile.source_device_id > MAX_DEVICE_ID as u32)
        && profile.source_device_id != kutup_chat_proto::ACCOUNT_PROFILE_SOURCE
    {
        return Err(AppError::bad_request(
            "profile sourceDeviceId is out of range",
        ));
    }
    validate_profile_envelope(&profile.name, ProfileEnvelopePurpose::DisplayName, profile)?;
    if let Some(avatar) = profile.avatar.as_deref() {
        validate_profile_envelope(avatar, ProfileEnvelopePurpose::Avatar, profile)?;
    }
    if let Some(about) = profile.about.as_deref() {
        validate_profile_envelope(about, ProfileEnvelopePurpose::About, profile)?;
    }
    validate_profile_envelope(
        &profile.wrapped_key,
        ProfileEnvelopePurpose::WrappedProfileKey,
        profile,
    )?;
    let verifier = hex::decode(&profile.access_key_verifier)
        .map_err(|_| AppError::bad_request("profile access verifier must be SHA-256 hex"))?;
    if verifier.len() != 32 || hex::encode(&verifier) != profile.access_key_verifier {
        return Err(AppError::bad_request(
            "profile access verifier must be lowercase SHA-256 hex",
        ));
    }
    let delivery_verifier = hex::decode(&profile.delivery_capability_verifier)
        .map_err(|_| AppError::bad_request("delivery capability verifier must be SHA-256 hex"))?;
    if delivery_verifier.len() != 32
        || hex::encode(&delivery_verifier) != profile.delivery_capability_verifier
    {
        return Err(AppError::bad_request(
            "delivery capability verifier must be lowercase SHA-256 hex",
        ));
    }
    Ok((verifier, delivery_verifier))
}

fn validate_profile_envelope(
    encoded: &str,
    purpose: ProfileEnvelopePurpose,
    profile: &PutChatProfileRequest,
) -> AppResult<()> {
    validate_profile_envelope_context(
        encoded,
        purpose,
        &profile.account,
        &profile.version,
        profile.revision,
        profile.source_device_id,
    )
}

fn validate_profile_envelope_context(
    encoded: &str,
    purpose: ProfileEnvelopePurpose,
    account: &AccountRef,
    version: &str,
    revision: u64,
    source_device_id: u32,
) -> AppResult<()> {
    let expected =
        ProfileEnvelopeContextV1::new(purpose, account, version, revision, source_device_id)
            .map_err(AppError::bad_request)?;
    let decoded =
        kutup_chat_proto::decode_profile_envelope(encoded).map_err(AppError::bad_request)?;
    if decoded.context != expected {
        return Err(AppError::bad_request(
            "encrypted profile envelope context does not match",
        ));
    }
    Ok(())
}

fn validate_public_profile_envelopes(profile: &ChatProfileResponse) -> AppResult<()> {
    validate_profile_envelope_context(
        &profile.name,
        ProfileEnvelopePurpose::DisplayName,
        &profile.account,
        &profile.version,
        profile.revision,
        profile.source_device_id,
    )?;
    if let Some(avatar) = profile.avatar.as_deref() {
        validate_profile_envelope_context(
            avatar,
            ProfileEnvelopePurpose::Avatar,
            &profile.account,
            &profile.version,
            profile.revision,
            profile.source_device_id,
        )?;
    }
    if let Some(about) = profile.about.as_deref() {
        validate_profile_envelope_context(
            about,
            ProfileEnvelopePurpose::About,
            &profile.account,
            &profile.version,
            profile.revision,
            profile.source_device_id,
        )?;
    }
    Ok(())
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
/// the lowest free device id while enforcing the configured 1..=10 active
/// device limit.
#[utoipa::path(
    post,
    path = "/api/chat/device",
    tag = "chat",
    operation_id = "registerChatDevice",
    request_body = RegisterChatDeviceRequest,
    responses(
        (status = 200, description = "Registered", body = RegisterChatDeviceResponse),
        (status = 400, description = "Malformed key material"),
        (status = 409, description = "Configured active-device limit reached"),
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
    if taken.len() >= state.config.chat_max_active_devices as usize {
        return Err(AppError::conflict("chat active-device limit reached"));
    }
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
    state.chat_hub.notify_devices_changed(user_id);

    Ok(Json(RegisterChatDeviceResponse {
        device_id: device_id as u32,
    })
    .into_response())
}

/// Whether a manifest's Drive keys may follow the stored ones: unchanged, or
/// raised once from a suite-1 (X25519) key to X-Wing with the same signing
/// key (docs/plans/pq-shares.md). The new key is the account's registered
/// one (checked by the caller), so it is the upgraded key; the caller also
/// requires the next sequence, linked to the stored manifest.
fn drive_keys_follow(
    current: &kutup_chat_proto::AccountManifestDriveKeysV1,
    next: &kutup_chat_proto::AccountManifestDriveKeysV1,
) -> bool {
    use kutup_chat_proto::{legacy_suite1_for_upgrade, AccountIdentitySuiteId};
    if current == next {
        return true;
    }
    let current_is_suite_1 = current.suite == AccountIdentitySuiteId::X25519Ed25519V1
        && STANDARD
            .decode(&current.hpke_public_key)
            .map(|key| key.len())
            == Ok(legacy_suite1_for_upgrade::HPKE_PUBLIC_KEY_LEN);
    current_is_suite_1
        && next.suite == AccountIdentitySuiteId::XWingEd25519V2
        && STANDARD.decode(&next.hpke_public_key).map(|key| key.len())
            == Ok(kutup_crypto::hpke_xwing::PUBLIC_KEY_LEN)
        && next.share_signing_public_key == current.share_signing_public_key
}

/// `POST /api/chat/manifest` — publish the caller's signed current device set.
/// Updates form a strict hash-linked sequence and cannot rotate the account
/// authority key in v1. The declared devices must exactly match the server's
/// registered devices, making an injected server-side device fail closed.
#[utoipa::path(
    post,
    path = "/api/chat/manifest",
    tag = "chat",
    operation_id = "publishChatAccountManifestV1",
    request_body = AccountManifestV1,
    responses(
        (status = 200, description = "Published manifest", body = AccountManifestPublicationV1),
        (status = 400, description = "Malformed or invalid signature"),
        (status = 409, description = "Version, chain, authority, or device-set conflict"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn publish_manifest(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(manifest): Json<AccountManifestV1>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    validate_manifest(&manifest)?;
    let manifest_hash = manifest.manifest_hash().map_err(AppError::bad_request)?;
    let mut tx = state.pool.begin().await?;

    // This is the common serialization point for every device-set mutation and
    // observation. It also locks the first-manifest case, where selecting the
    // (not-yet-existent) manifest row `FOR UPDATE` cannot lock anything.
    let account: (String, String, String, String, String) = sqlx::query_as(
        "SELECT public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key
         FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let (
        drive_public_key,
        authority_public_key,
        authority_key_id,
        incarnation_id,
        drive_signing_public_key,
    ) = account;
    // The manifest names this account by its permanent id, never a name
    // (docs/plans/account-ids.md).
    if manifest.account != crate::account_ids::local(&state.config.chat_server_name, user_id)? {
        return Err(AppError::conflict(
            "manifest account does not match the authenticated account",
        ));
    }
    if manifest.drive.hpke_public_key != drive_public_key
        || manifest.drive.share_signing_public_key != drive_signing_public_key
        || manifest.self_authority_key != authority_public_key
        || manifest.authority_key_id != authority_key_id
        || manifest.incarnation_id != incarnation_id
    {
        return Err(AppError::conflict(
            "manifest identity does not match the registered account identity",
        ));
    }

    let current: Option<(i64, String, serde_json::Value)> = sqlx::query_as(
        "SELECT version, manifest_hash, manifest
         FROM chat_device_manifests WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let mut idempotent = false;
    match current {
        None if manifest.sequence != 1 || manifest.previous_hash.is_some() => {
            return Err(AppError::conflict("first manifest must be version 1"));
        }
        None => {}
        Some((version, current_hash, current_value)) => {
            let current_manifest: AccountManifestV1 = serde_json::from_value(current_value)
                .map_err(|error| AppError::internal(format!("stored manifest: {error}")))?;
            if manifest.sequence == version as u64 && manifest_hash == current_hash {
                idempotent = true;
            } else if manifest.sequence != version as u64 + 1 {
                return Err(AppError::conflict(
                    "manifest version must advance by exactly one",
                ));
            } else if manifest.previous_hash.as_deref() != Some(current_hash.as_str()) {
                return Err(AppError::conflict("manifest previousHash mismatch"));
            }
            // Nothing of the identity changes inside one incarnation; the
            // account is its id, which never changes either. The Drive keys
            // change only by the one-way suite upgrade (checked as chat-core
            // checks it).
            if manifest.account != current_manifest.account
                || manifest.incarnation_id != current_manifest.incarnation_id
                || manifest.authority_key_id != current_manifest.authority_key_id
                || manifest.self_authority_key != current_manifest.self_authority_key
                || !drive_keys_follow(&current_manifest.drive, &manifest.drive)
            {
                return Err(AppError::conflict(
                    "stable account identity cannot change inside one incarnation",
                ));
            }
        }
    }

    let registered: Vec<(i32, i16, i64, String)> = sqlx::query_as(
        "SELECT device_id, suite, registration_id, identity_key
         FROM chat_devices WHERE user_id = $1 ORDER BY device_id FOR SHARE",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    if registered.is_empty() {
        return Err(AppError::conflict("account has no registered chat devices"));
    }
    let registered_matches =
        |(device_id, suite, registration_id, identity_key): &(i32, i16, i64, String),
         declared: &AccountManifestDeviceV1| {
            declared.device_id == *device_id as u32
                && declared.direct_chat_suite.as_u16() == *suite as u16
                && declared.registration_id == *registration_id as u32
                && declared.identity_key == *identity_key
        };
    let every_declared_device_is_registered = manifest.devices.iter().all(|declared| {
        registered
            .iter()
            .any(|registered| registered_matches(registered, declared))
    });
    if !every_declared_device_is_registered {
        return Err(AppError::conflict(
            "manifest devices do not match registered chat devices",
        ));
    }

    // Registration deliberately precedes signed-manifest publication so a
    // device can obtain its server-assigned id. A browser crash in that gap
    // must not leave an unauthenticated row that permanently blocks this
    // account. The authority-signed manifest is the source of truth: every
    // declared device must match a registered key tuple above, while rows the
    // authority did not select are pruned in this same transaction. Cascades
    // remove their prekeys, mailbox rows and WebSocket tickets. This also turns
    // a server-injected row into recoverable state rather than manifest
    // inclusion; the server still cannot invent a device accepted by clients.
    if registered.len() != manifest.devices.len() {
        let selected_device_ids = manifest
            .devices
            .iter()
            .map(|device| device.device_id as i32)
            .collect::<Vec<_>>();
        sqlx::query(
            "DELETE FROM chat_devices
             WHERE user_id = $1 AND NOT (device_id = ANY($2))",
        )
        .bind(user_id)
        .bind(&selected_device_ids)
        .execute(&mut *tx)
        .await?;
    }
    if idempotent {
        tx.commit().await?;
        return Ok(Json(AccountManifestPublicationV1 { manifest }).into_response());
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
    .bind(manifest.sequence as i64)
    .bind(&manifest_hash)
    .bind(&manifest.authority_key_id)
    .bind(value)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO chat_device_manifest_history
             (user_id, incarnation_id, version, manifest_hash, authority_key_id, manifest)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (user_id, incarnation_id, version) DO NOTHING",
    )
    .bind(user_id)
    .bind(&manifest.incarnation_id)
    .bind(manifest.sequence as i64)
    .bind(&manifest_hash)
    .bind(&manifest.authority_key_id)
    .bind(
        serde_json::to_value(&manifest).map_err(|error| {
            AppError::internal(format!("serialize chat manifest history: {error}"))
        })?,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    state.chat_hub.notify_devices_changed(user_id);
    Ok(Json(AccountManifestPublicationV1 { manifest }).into_response())
}

/// `GET /api/chat/accounts/{accountId}/manifest?server=` — fetch an
/// account's latest signed device manifest without consuming any one-time
/// prekeys.
#[utoipa::path(
    get,
    path = "/api/chat/accounts/{accountId}/manifest",
    tag = "chat",
    operation_id = "getChatAccountManifestV1",
    params(
        ("accountId" = String, Path, description = "Permanent account id"),
        AccountServerQuery
    ),
    responses(
        (status = 200, description = "Latest signed manifest", body = AccountManifestV1),
        (status = 404, description = "Unknown user or no manifest"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_user_manifest(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(account_id): Path<String>,
    Query(query): Query<AccountServerQuery>,
) -> AppResult<Response> {
    match named_account(&state, &account_id, query.server.as_deref()).await? {
        NamedAccount::Remote(account) => {
            let manifest = crate::chat_federation::fetch_remote_manifest(&state, &account).await?;
            Ok(Json(manifest).into_response())
        }
        NamedAccount::Local(user_id) => {
            Ok(Json(load_account_manifest(&state, user_id).await?).into_response())
        }
    }
}

pub(crate) async fn load_account_manifest(
    state: &AppState,
    user_id: Uuid,
) -> AppResult<AccountManifestV1> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT manifest FROM chat_device_manifests WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let manifest: AccountManifestV1 = serde_json::from_value(
        value.ok_or_else(|| AppError::not_found("chat manifest not found"))?,
    )
    .map_err(|error| AppError::internal(format!("stored chat manifest is invalid: {error}")))?;
    manifest
        .verify()
        .map_err(|error| AppError::internal(format!("stored chat manifest is invalid: {error}")))?;
    Ok(manifest)
}

/// Retrieve every skipped manifest sequence in pages of at most 64 complete,
/// individually account-signed records.
#[tracing::instrument(name = "chat.account_manifest.history", skip_all)]
pub async fn get_manifest_history(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(account_id): Path<String>,
    Query(query): Query<ManifestHistoryQuery>,
) -> AppResult<Response> {
    if query.from_sequence == 0
        || query.to_sequence < query.from_sequence
        || query
            .page_from_sequence
            .is_some_and(|page| page < query.from_sequence || page > query.to_sequence)
    {
        return Err(AppError::bad_request("invalid manifest history bounds"));
    }
    let target_id = match named_account(&state, &account_id, query.server.as_deref()).await? {
        NamedAccount::Remote(account) => {
            let page =
                crate::chat_federation::fetch_remote_manifest_history(&state, &account, &query)
                    .await?;
            return Ok(Json(page).into_response());
        }
        NamedAccount::Local(user_id) => user_id,
    };
    let incarnation_id: Option<String> = sqlx::query_scalar(
        "SELECT manifest->>'incarnationId' FROM chat_device_manifests WHERE user_id = $1",
    )
    .bind(target_id)
    .fetch_optional(&state.pool)
    .await?;
    let incarnation_id =
        incarnation_id.ok_or_else(|| AppError::not_found("chat manifest not found"))?;
    let page_from = query.page_from_sequence.unwrap_or(query.from_sequence);
    let values: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT manifest FROM chat_device_manifest_history
         WHERE user_id = $1 AND incarnation_id = $2 AND version BETWEEN $3 AND $4
         ORDER BY version LIMIT 65",
    )
    .bind(target_id)
    .bind(incarnation_id)
    .bind(page_from as i64)
    .bind(query.to_sequence as i64)
    .fetch_all(&state.pool)
    .await?;
    if values.is_empty() {
        return Err(AppError::not_found("chat manifest history not found"));
    }
    let mut manifests = values
        .into_iter()
        .map(|value| {
            serde_json::from_value::<AccountManifestV1>(value)
                .map_err(|error| AppError::internal(format!("stored chat manifest: {error}")))
        })
        .collect::<AppResult<Vec<_>>>()?;
    let next_sequence = if manifests.len() > 64 {
        manifests.truncate(64);
        Some(
            manifests
                .last()
                .expect("nonempty bounded page")
                .sequence
                .checked_add(1)
                .ok_or_else(|| AppError::internal("manifest sequence exhausted"))?,
        )
    } else {
        None
    };
    let page = AccountManifestHistoryPageV1 {
        account: manifests[0].account.clone(),
        from_sequence: page_from,
        to_sequence: query.to_sequence,
        manifests,
        next_sequence,
    };
    page.validate().map_err(AppError::internal)?;
    Ok(Json(page).into_response())
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
    let mut tx = state.pool.begin().await?;
    // The account's row is the lock every profile write takes.
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let account = crate::account_ids::local(&state.config.chat_server_name, user_id)?;
    let (verifier, delivery_verifier) = validate_profile(&profile, &account)?;
    // The account app edits the profile too, without being a chat device
    // (docs/plans/unified-profile.md); any other source must be one.
    let device_exists: Option<i32> =
        if profile.source_device_id == kutup_chat_proto::ACCOUNT_PROFILE_SOURCE {
            Some(1)
        } else {
            sqlx::query_scalar("SELECT 1 FROM chat_devices WHERE user_id = $1 AND device_id = $2")
                .bind(user_id)
                .bind(profile.source_device_id as i32)
                .fetch_optional(&mut *tx)
                .await?
        };
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
             (user_id, suite, version, revision, source_device_id, name_ciphertext,
              avatar_ciphertext, wrapped_key, access_key_verifier, is_current,
              about_ciphertext)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true,$10)
         ON CONFLICT (user_id, version) DO UPDATE SET
             suite = EXCLUDED.suite,
             revision = EXCLUDED.revision,
             source_device_id = EXCLUDED.source_device_id,
             name_ciphertext = EXCLUDED.name_ciphertext,
             avatar_ciphertext = EXCLUDED.avatar_ciphertext,
             about_ciphertext = EXCLUDED.about_ciphertext,
             wrapped_key = EXCLUDED.wrapped_key,
             access_key_verifier = EXCLUDED.access_key_verifier,
             is_current = true,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(profile.suite.as_u16() as i16)
    .bind(&profile.version)
    .bind(profile.revision as i64)
    .bind(profile.source_device_id as i32)
    .bind(&profile.name)
    .bind(&profile.avatar)
    .bind(&profile.wrapped_key)
    .bind(verifier)
    .bind(&profile.about)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO chat_delivery_capabilities
             (user_id, profile_version, profile_revision, capability_hash, rotated_at)
         VALUES ($1,$2,$3,$4,now())
         ON CONFLICT (user_id) DO UPDATE SET
             profile_version = EXCLUDED.profile_version,
             profile_revision = EXCLUDED.profile_revision,
             capability_hash = EXCLUDED.capability_hash,
             rotated_at = now()",
    )
    .bind(user_id)
    .bind(&profile.version)
    .bind(profile.revision as i64)
    .bind(delivery_verifier)
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

/// `GET /api/chat/accounts/{accountId}/profile/{version}?server=` — fetch a
/// capability-gated local or federated encrypted peer profile. The access
/// key is carried in a header so it does not enter URL logs.
#[utoipa::path(
    get,
    path = "/api/chat/accounts/{accountId}/profile/{version}",
    tag = "chat",
    operation_id = "getChatProfile",
    params(
        ("accountId" = String, Path, description = "Permanent account id"),
        ("version" = String, Path, description = "Profile-key-derived version"),
        AccountServerQuery
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
    Path((account_id, version)): Path<(String, String)>,
    Query(query): Query<AccountServerQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    if !canonical_profile_version(&version) {
        return Err(AppError::not_found("chat profile not found"));
    }
    let access_key = profile_access_key_from_headers(&headers)?;
    match named_account(&state, &account_id, query.server.as_deref()).await? {
        NamedAccount::Remote(account) => {
            let profile = crate::chat_federation::fetch_remote_profile(
                &state,
                &account,
                &version,
                &access_key,
            )
            .await?;
            Ok(Json(profile).into_response())
        }
        NamedAccount::Local(user_id) => load_public_profile(&state, user_id, &version, &access_key)
            .await?
            .map(|profile| Json(profile).into_response())
            .ok_or_else(|| AppError::not_found("chat profile not found")),
    }
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
    user_id: Uuid,
    version: &str,
    access_key: &[u8],
) -> AppResult<Option<ChatProfileResponse>> {
    let row: Option<PublicProfileRow> = sqlx::query_as(
        "SELECT p.suite, p.version, p.revision, p.source_device_id, p.name_ciphertext,
                p.avatar_ciphertext, p.about_ciphertext, p.access_key_verifier
         FROM chat_profiles p
         JOIN users u ON u.id = p.user_id
         WHERE u.id = $1 AND u.is_active = true AND p.version = $2",
    )
    .bind(user_id)
    .bind(version)
    .fetch_optional(&state.pool)
    .await?;
    let Some((suite, version, revision, source_device_id, name, avatar, about, verifier)) = row
    else {
        return Ok(None);
    };
    let presented = Sha256::digest(access_key);
    if !constant_time_eq(&verifier, &presented) {
        return Ok(None);
    }
    // Sealed for the account's permanent id: a rename leaves it valid.
    let account = crate::account_ids::local(&state.config.chat_server_name, user_id)?;
    if sealed_profile_account(&name)? != account {
        return Err(AppError::internal(
            "a stored profile is sealed for another account",
        ));
    }
    let suite = profile_suite_from_db(suite, "chat_profiles")?;
    let response = ChatProfileResponse {
        suite,
        account,
        version,
        revision: revision as u64,
        source_device_id: source_device_id as u32,
        name,
        avatar,
        about,
    };
    validate_public_profile_envelopes(&response)?;
    Ok(Some(response))
}

/// The account a stored profile was sealed for (its envelopes' context).
fn sealed_profile_account(name_envelope: &str) -> AppResult<AccountRef> {
    Ok(kutup_chat_proto::decode_profile_envelope(name_envelope)
        .map_err(AppError::bad_request)?
        .context
        .account)
}

/// The account's current profile, as it was published.
async fn load_own_profile_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    lock: bool,
) -> AppResult<Option<OwnChatProfileResponse>> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT p.suite, p.version, p.revision, p.source_device_id, p.name_ciphertext,
                p.avatar_ciphertext, p.about_ciphertext, p.wrapped_key, p.access_key_verifier,
                c.capability_hash
         FROM chat_profiles p
         JOIN chat_delivery_capabilities c ON c.user_id = p.user_id
              AND c.profile_version = p.version AND c.profile_revision = p.revision
         WHERE p.user_id = $1 AND p.is_current = true{suffix}"
    );
    let row: Option<OwnProfileRow> = sqlx::query_as(&sql)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(
        |(
            suite,
            version,
            revision,
            source_device_id,
            name,
            avatar,
            about,
            wrapped_key,
            verifier,
            delivery_verifier,
        )| {
            let profile = PutChatProfileRequest {
                suite: profile_suite_from_db(suite, "chat_profiles")?,
                account: sealed_profile_account(&name)?,
                version,
                revision: revision as u64,
                source_device_id: source_device_id as u32,
                name,
                avatar,
                about,
                wrapped_key,
                access_key_verifier: hex::encode(verifier),
                delivery_capability_verifier: hex::encode(delivery_verifier),
            };
            validate_profile_envelope(
                &profile.name,
                ProfileEnvelopePurpose::DisplayName,
                &profile,
            )?;
            if let Some(avatar) = profile.avatar.as_deref() {
                validate_profile_envelope(avatar, ProfileEnvelopePurpose::Avatar, &profile)?;
            }
            if let Some(about) = profile.about.as_deref() {
                validate_profile_envelope(about, ProfileEnvelopePurpose::About, &profile)?;
            }
            validate_profile_envelope(
                &profile.wrapped_key,
                ProfileEnvelopePurpose::WrappedProfileKey,
                &profile,
            )?;
            Ok(profile)
        },
    )
    .transpose()
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
            let suite = direct_chat_suite_from_db(suite, "chat_devices")?;
            Ok(json!({
                "deviceId": id,
                "suite": suite,
                "name": name,
                "createdAt": created.format(&Rfc3339).unwrap_or_default(),
                "lastSeenAt": seen.and_then(|t| t.format(&Rfc3339).ok()),
            }))
        })
        .collect::<AppResult<_>>()?;
    Ok(Json(json!({ "devices": devices })).into_response())
}

/// `PATCH /api/chat/device/{deviceId}` — rename one of the caller's Chat
/// installations. The label is account-private metadata and has no effect on
/// the installation's cryptographic identity.
#[utoipa::path(
    patch,
    path = "/api/chat/device/{deviceId}",
    tag = "chat",
    operation_id = "renameChatDevice",
    params(("deviceId" = u32, Path, description = "Chat device id")),
    request_body = RenameChatDeviceRequest,
    responses(
        (status = 204, description = "Renamed"),
        (status = 400, description = "Invalid device name"),
        (status = 404, description = "No such device"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn rename_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<i32>,
    Json(req): Json<RenameChatDeviceRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let name = normalized_device_name(&req.name)?;
    let updated = sqlx::query(
        "UPDATE chat_devices SET name = $3
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(name)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::not_found("no such chat device"));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
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
    // The shared payloads the device's mailbox rows name: its rows go with
    // it (cascade), and the payloads no other row names after them.
    let shared: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT shared_payload_id FROM chat_mailbox
          WHERE recipient_user_id = $1 AND recipient_device_id = $2
            AND shared_payload_id IS NOT NULL",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_all(&mut *tx)
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
    // The destination-private group-leaf history deliberately survives until
    // an ordered DeviceSync Commit removes it, but the revoked device must
    // immediately stop receiving MLS mailbox entries or contributing
    // KeyPackages. Deleting the current MLS directory row cascades those
    // ephemeral records without erasing the group control history.
    sqlx::query("DELETE FROM chat_mls_devices WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Err(error) = crate::handlers::chat_multi::collect_payloads(&state.pool, &shared).await {
        tracing::warn!(error = %error.message, "chat: shared payload collection after a device removal failed");
    }
    state.chat_hub.close_device(user_id, device_id);
    state.chat_hub.notify_devices_changed(user_id);
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
    /// The account's server; this server when absent.
    pub(crate) server: Option<String>,
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

/// `GET /api/chat/accounts/{accountId}/keys?server=` — PQXDH prekey bundles for
/// every chat device of the account. Consumes one one-time EC and one one-time Kyber prekey per device
/// (falling back to the last-resort Kyber prekey — a bundle is never non-PQ).
/// Rate-limited (`RATE_LIMIT_CHAT_KEYS_PER_MIN`) because fetches consume pool keys.
#[utoipa::path(
    get,
    path = "/api/chat/accounts/{accountId}/keys",
    tag = "chat",
    operation_id = "chatUserPreKeyBundles",
    params(
        ("accountId" = String, Path, description = "Permanent account id"),
        ("server" = Option<String>, Query, description = "The account's server; this server when absent"),
        ("syncDeviceId" = Option<u32>, Query, description = "Authenticated current device for own-account sync")
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
    Path(account_id): Path<String>,
    Query(query): Query<BundleQuery>,
) -> AppResult<Response> {
    if !ratelimit::CHAT_KEYS_ACCOUNT.allow(&auth.user_id) {
        crate::telemetry::rate_limit_rejection("prekey_account");
        return Err(AppError::too_many_requests(
            "too many chat key requests for this account",
        ));
    }
    let target_id = match named_account(&state, &account_id, query.server.as_deref()).await? {
        NamedAccount::Remote(account) => {
            if query.sync_device_id.is_some() {
                return Err(AppError::forbidden(
                    "linked-device key fetch is limited to the local account",
                ));
            }
            let bundles = crate::chat_federation::fetch_remote_bundles(&state, &account).await?;
            return Ok(Json(bundles).into_response());
        }
        NamedAccount::Local(user_id) => user_id,
    };
    if query.sync_device_id.is_some() && trusted_uuid(&auth.user_id)? != target_id {
        return Err(AppError::forbidden(
            "linked-device key fetch is limited to the caller's account",
        ));
    }
    let bundles = load_user_bundles(&state, target_id, query.sync_device_id, true, None).await?;
    Ok(Json(bundles).into_response())
}

/// Cookie- and bearer-free contacts-only prekey retrieval. Unknown users and
/// invalid/stale capabilities deliberately share the exact response.
pub async fn get_anonymous_bundles(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Query(query): Query<AccountServerQuery>,
    Json(request): Json<AnonymousPreKeyRequestV1>,
) -> AppResult<Response> {
    let unavailable = || AppError::not_found("sealed delivery unavailable");
    let capability = request.capability_bytes().map_err(|_| unavailable())?;
    let capability_hash = capability_hash(&capability);
    let local = &state.config.chat_server_name;
    let account = crate::account_ids::named(local, &account_id, query.server.as_deref())
        .map_err(|_| unavailable())?;
    if account.server != *local {
        state.federation.as_ref().ok_or_else(unavailable)?;
        let bundles =
            crate::chat_federation::fetch_remote_sealed_bundles(&state, &account, &request).await?;
        return Ok(Json(bundles).into_response());
    }
    let target_id = crate::account_ids::local_user(&state.pool, local, &account)
        .await?
        .ok_or_else(unavailable)?;
    let bundles = load_user_bundles(&state, target_id, None, true, Some(&capability_hash)).await?;
    Ok(Json(bundles).into_response())
}

/// Adds `amount` to the scope's count in the current window and returns the
/// new count (shared by every backend, in the database).
pub(crate) async fn anonymous_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope_type: &str,
    scope_digest: &[u8; 32],
    amount: i64,
    window_seconds: i64,
) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO chat_anonymous_rate_counters
             (scope_type, scope_digest, window_start, count, expires_at)
         VALUES (
             $1, $2,
             to_timestamp(floor(extract(epoch FROM now()) / $3) * $3),
             $4,
             to_timestamp(floor(extract(epoch FROM now()) / $3) * $3) + make_interval(secs => $3 * 2)
         )
         ON CONFLICT (scope_type, scope_digest, window_start)
         DO UPDATE SET count = chat_anonymous_rate_counters.count + $4
         RETURNING count",
    )
    .bind(scope_type)
    .bind(scope_digest.as_slice())
    .bind(window_seconds)
    .bind(amount)
    .fetch_one(&mut **tx)
    .await?)
}

pub(crate) async fn consume_anonymous_rate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope_type: &str,
    scope_digest: &[u8; 32],
    budget: crate::ratelimit::Limit,
) -> AppResult<()> {
    let (limit, window_seconds) = crate::ratelimit::budget(budget);
    let count = anonymous_count(tx, scope_type, scope_digest, 1, window_seconds).await?;
    if count > limit {
        let metric_scope = match scope_type {
            "capability_bundle" => "capability_bundle",
            "capability_minute" => "capability_minute",
            "capability_day" => "capability_day",
            "recipient" => "recipient",
            "federation_origin" => "federation_origin",
            _ => "unknown",
        };
        crate::telemetry::rate_limit_rejection(metric_scope);
        return Err(AppError::too_many_requests(
            "anonymous delivery rate limit exceeded",
        ));
    }
    Ok(())
}

/// Load one local account's signed device directory. Local client fetches
/// consume one-time keys. Federated server reads intentionally serve only the
/// reusable last-resort PQ key so replay cannot exhaust a user's prekey pool.
/// The bundles of `target_id`, an account of this server, one per active
/// device. With `delivery_capability` (contacts-only sealed delivery), an
/// account that is not active and a wrong capability get the same answer.
pub(crate) async fn load_user_bundles(
    state: &AppState,
    target_id: Uuid,
    sync_device_id: Option<i32>,
    consume_one_time: bool,
    delivery_capability: Option<&[u8; 32]>,
) -> AppResult<UserPreKeyBundlesResponse> {
    let mut tx = state.pool.begin().await?;
    let target: Option<Option<Vec<u8>>> = sqlx::query_scalar(
        "SELECT c.capability_hash
         FROM users u
         LEFT JOIN chat_delivery_capabilities c ON c.user_id = u.id
         WHERE u.id = $1 AND u.is_active = true",
    )
    .bind(target_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(stored_capability) = target else {
        return Err(AppError::not_found(if delivery_capability.is_some() {
            "sealed delivery unavailable"
        } else {
            "user not found"
        }));
    };
    if let Some(capability) = delivery_capability {
        let Some(stored) = stored_capability.and_then(|value| <[u8; 32]>::try_from(value).ok())
        else {
            return Err(AppError::not_found("sealed delivery unavailable"));
        };
        if !constant_time_capability_hash_eq(capability, &stored) {
            return Err(AppError::not_found("sealed delivery unavailable"));
        }
        consume_anonymous_rate(
            &mut tx,
            "capability_bundle",
            capability,
            crate::ratelimit::Limit::SealedCapabilityBundles,
        )
        .await?;
    }

    let account = crate::account_ids::local(&state.config.chat_server_name, target_id)?;
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
            suite: direct_chat_suite_from_db(suite, "chat_devices")?,
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
    tx.commit().await?;

    Ok(UserPreKeyBundlesResponse {
        account,
        devices: bundles,
        manifest,
    })
}

/// `POST /api/chat/users/{username}/messages` — deliver one logical message as
/// per-device ciphertexts. The device set must exactly match the recipient's current
/// devices (ids and registration ids) or the send is rejected with a 409
/// [`DeviceListMismatch`] so clients can't silently skip a device.
#[utoipa::path(
    post,
    path = "/api/chat/accounts/{accountId}/messages",
    tag = "chat",
    operation_id = "chatSendMessages",
    params(
        ("accountId" = String, Path, description = "Recipient's permanent account id"),
        AccountServerQuery
    ),
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
    Path(account_id): Path<String>,
    Query(query): Query<AccountServerQuery>,
    Json(req): Json<SendMessagesRequest>,
) -> AppResult<Response> {
    let sender_id = trusted_uuid(&auth.user_id)?;
    validate_send_request(&req, false, None)?;
    let recipient_id = match named_account(&state, &account_id, query.server.as_deref()).await? {
        NamedAccount::Local(user_id) => user_id,
        NamedAccount::Remote(account) => {
            let envelope_count = req.envelopes.len();
            return match crate::chat_federation::enqueue_send(&state, sender_id, &account, req)
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
                crate::chat_federation::FederatedSendOutcome::PeerUnsupported => {
                    Err(crate::chat_federation::peer_unsupported_error())
                }
            };
        }
    };
    deliver_messages(&state, sender_id, recipient_id, req, None).await
}

/// Contacts-only, cookie- and bearer-free sealed submission. There is no
/// identified fallback on this route: federation or capability failure is
/// returned to the client as-is.
pub async fn send_sealed_messages(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Query(query): Query<AccountServerQuery>,
    Json(request): Json<SealedMessageSubmissionV1>,
) -> AppResult<Response> {
    request.validate().map_err(AppError::bad_request)?;
    let unavailable = || AppError::not_found("sealed delivery unavailable");
    let local = &state.config.chat_server_name;
    let account = crate::account_ids::named(local, &account_id, query.server.as_deref())
        .map_err(|_| unavailable())?;
    if account.server != *local {
        state.federation.as_ref().ok_or_else(unavailable)?;
        let outcome =
            crate::chat_federation::enqueue_sealed_send(&state, &account, request).await?;
        return match outcome {
            crate::chat_federation::FederatedSealedOutcome::Delivered(response) => {
                Ok(Json(response).into_response())
            }
            crate::chat_federation::FederatedSealedOutcome::Mismatch(mismatch) => {
                Ok((StatusCode::CONFLICT, Json(mismatch)).into_response())
            }
            crate::chat_federation::FederatedSealedOutcome::Unavailable => Err(unavailable()),
            crate::chat_federation::FederatedSealedOutcome::Refused => {
                Err(crate::chat_federation::peer_refused_error())
            }
            crate::chat_federation::FederatedSealedOutcome::Pending => Err(AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "sealed federation delivery is durably queued",
            )),
            crate::chat_federation::FederatedSealedOutcome::PeerUnsupported => {
                Err(crate::chat_federation::peer_unsupported_error())
            }
        };
    }

    // An account that is not ours, or not active, gets the same answer as a
    // wrong capability.
    let recipient = match Uuid::parse_str(&account.account_id) {
        Ok(id) => id,
        Err(_) => return Err(unavailable()),
    };
    let mut tx = state.pool.begin().await?;
    let outcome = store_sealed_messages(&mut tx, recipient, &request, None).await?;
    match outcome {
        SealedStoreOutcome::Mismatch(mismatch) => {
            tx.rollback().await?;
            Ok((StatusCode::CONFLICT, Json(mismatch)).into_response())
        }
        SealedStoreOutcome::Delivered { response, stored } => {
            tx.commit().await?;
            push_sealed(&state, stored).await;
            Ok(Json(response).into_response())
        }
    }
}

/// `POST /api/chat/anonymous/messages/batch?server=`: several sealed sends
/// to accounts of one server in one cookie- and bearer-free request
/// (docs/plans/pairwise-groups.md §1). Each recipient's capability is checked
/// and counted on its own, and each gets its own result; for a remote server
/// the sends are queued as single sends are and delivered in one federated
/// batch.
#[utoipa::path(
    post,
    path = "/api/chat/anonymous/messages/batch",
    tag = "chat",
    params(("server" = Option<String>, Query, description = "The recipients' server; this one when absent")),
    request_body = kutup_chat_proto::SealedBatchSubmissionV1,
    responses(
        (status = 200, description = "One result per recipient, in order", body = kutup_chat_proto::SealedBatchResponseV1),
        (status = 400, description = "Malformed batch"),
        (status = 429, description = "Too many anonymous requests from this address"),
    )
)]
pub async fn send_sealed_batch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AccountServerQuery>,
    Json(batch): Json<kutup_chat_proto::SealedBatchSubmissionV1>,
) -> AppResult<Json<kutup_chat_proto::SealedBatchResponseV1>> {
    use kutup_chat_proto::{SealedBatchOutcomeV1 as Outcome, SealedBatchResultV1};
    batch.validate().map_err(AppError::bad_request)?;
    let local = state.config.chat_server_name.clone();
    let server = query.server.clone().unwrap_or_else(|| local.clone());
    let result = |account_id: &str, send_id: &str, outcome: Outcome| SealedBatchResultV1 {
        account_id: account_id.to_owned(),
        send_id: send_id.to_owned(),
        outcome,
    };
    // The address's anonymous limit counts the request once (the
    // middleware charged it) and its bytes a minute, as multi-recipient sends
    // do (docs/plans/pairwise-groups.md, slice 2 §4): a group message to many
    // members is one request, and neighbours behind one address aren't
    // starved by a recipient count.
    let address =
        crate::middleware::client_key(crate::middleware::client_ip_from_headers(&headers), peer);
    let address_digest: [u8; 32] =
        Sha256::digest([b"kutup/multi-ip-bytes/v1\0".as_slice(), address.as_bytes()].concat())
            .into();
    let bytes: usize = batch
        .recipients
        .iter()
        .flat_map(|recipient| &recipient.submission.envelopes)
        .map(|envelope| envelope.content.len())
        .sum();
    let ip_bytes_per_min = crate::site_settings::CHAT_MULTI_IP_BYTES_PER_MIN
        .load(&state.pool)
        .await?;
    {
        let mut tx = state.pool.begin().await?;
        let count = anonymous_count(
            &mut tx,
            "ip_bytes",
            &address_digest,
            i64::try_from(bytes).unwrap_or(i64::MAX),
            60,
        )
        .await?;
        tx.commit().await?;
        if count > ip_bytes_per_min {
            crate::telemetry::rate_limit_rejection("anonymous_ip");
            return Err(AppError::too_many_requests(
                "anonymous delivery rate limit exceeded",
            ));
        }
    }
    let mut results = Vec::with_capacity(batch.recipients.len());
    if server == local {
        for recipient in batch.recipients {
            let send_id = recipient.submission.send_id.clone();
            // An account that isn't ours, or not active, is a wrong capability.
            let outcome =
                match crate::account_ids::named(&local, &recipient.account_id, Some(&local))
                    .ok()
                    .and_then(|account| Uuid::parse_str(&account.account_id).ok())
                {
                    None => Outcome::Unavailable,
                    Some(id) => {
                        let mut tx = state.pool.begin().await?;
                        match store_sealed_messages(&mut tx, id, &recipient.submission, None).await
                        {
                            Ok(SealedStoreOutcome::Delivered { response, stored }) => {
                                tx.commit().await?;
                                push_sealed(&state, stored).await;
                                Outcome::Delivered {
                                    stored: response.stored,
                                    deduplicated: response.deduplicated,
                                }
                            }
                            Ok(SealedStoreOutcome::Mismatch(mismatch)) => {
                                tx.rollback().await?;
                                Outcome::DeviceMismatch { mismatch }
                            }
                            Err(error) if error.status == StatusCode::NOT_FOUND => {
                                tx.rollback().await?;
                                Outcome::Unavailable
                            }
                            // This capability's or recipient's limit: the
                            // others in the batch still go.
                            Err(error) if error.status == StatusCode::TOO_MANY_REQUESTS => {
                                tx.rollback().await?;
                                Outcome::RateLimited
                            }
                            Err(error) => return Err(error),
                        }
                    }
                };
            results.push(result(&recipient.account_id, &send_id, outcome));
        }
        return Ok(Json(kutup_chat_proto::SealedBatchResponseV1 { results }));
    }

    // A remote server: queue each send as a single one, then deliver the
    // destination's queue in one batch. Only a send that was queued reads
    // as pending.
    state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("sealed delivery unavailable"))?;
    // Each queued send is an outbox row and, at the destination, a charge on
    // this whole server's origin budget: here the address's anonymous limit
    // counts every recipient after the first (the middleware charged it), so
    // one address can't fill the outbox or spend the origin's budget.
    let mut within_wall = (0..batch.recipients.len()).map(|index| {
        index == 0 || {
            let allowed = crate::ratelimit::CHAT_ANONYMOUS_IP.allow(&address);
            if !allowed {
                crate::telemetry::rate_limit_rejection("anonymous_ip");
            }
            allowed
        }
    });
    let mut queued = Vec::with_capacity(batch.recipients.len());
    for recipient in batch.recipients {
        let send_id = recipient.submission.send_id.clone();
        let outcome = if within_wall.next() != Some(true) {
            Err(Outcome::RateLimited)
        } else {
            match crate::account_ids::named(&local, &recipient.account_id, Some(&server)) {
                Err(_) => Err(Outcome::Unavailable),
                Ok(account) => match crate::chat_federation::enqueue_sealed_row(
                    &state,
                    &account,
                    recipient.submission,
                )
                .await
                {
                    Ok(crate::chat_federation::Queued::Row(id)) => Ok(id),
                    Ok(crate::chat_federation::Queued::Settled(outcome)) => {
                        Err(batch_outcome(Ok(outcome)))
                    }
                    Err(error) => Err(not_queued_outcome(error)?),
                },
            }
        };
        queued.push((recipient.account_id, send_id, outcome));
    }
    let mut flush = if queued.iter().any(|(_, _, outcome)| outcome.is_ok()) {
        Some(
            crate::chat_federation::flush_sealed_destination(
                &state,
                &server,
                crate::chat_federation::FlushTrigger::Client,
            )
            .await?,
        )
    } else {
        None
    };
    for (account_id, send_id, outcome) in queued {
        let outcome = match (outcome, flush.as_mut()) {
            (Err(settled), _) => settled,
            (Ok(id), Some(flush)) => batch_outcome(flush.outcome(&state.pool, id).await),
            (Ok(_), None) => Outcome::Pending,
        };
        results.push(result(&account_id, &send_id, outcome));
    }
    Ok(Json(kutup_chat_proto::SealedBatchResponseV1 { results }))
}

/// A send that wasn't queued, as a batch result: this recipient's own
/// answer, or the whole request's failure. A server error fails the request,
/// which is safe to repeat: sendIds dedupe.
fn not_queued_outcome(error: AppError) -> AppResult<kutup_chat_proto::SealedBatchOutcomeV1> {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    match error.status {
        StatusCode::NOT_FOUND => Ok(Outcome::Unavailable),
        // Too large for any federated transaction: it can never go.
        StatusCode::PAYLOAD_TOO_LARGE => Ok(Outcome::Refused),
        // Other content under this sendId is still queued.
        StatusCode::CONFLICT => Ok(Outcome::Conflict),
        StatusCode::TOO_MANY_REQUESTS => Ok(Outcome::RateLimited),
        _ => Err(error),
    }
}

/// A queued send's fate, as a batch result. A failure while delivering
/// leaves it queued.
fn batch_outcome(
    outcome: AppResult<crate::chat_federation::FederatedSealedOutcome>,
) -> kutup_chat_proto::SealedBatchOutcomeV1 {
    use crate::chat_federation::FederatedSealedOutcome as Federated;
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    match outcome {
        Ok(Federated::Delivered(response)) => Outcome::Delivered {
            stored: response.stored,
            deduplicated: response.deduplicated,
        },
        Ok(Federated::Mismatch(mismatch)) => Outcome::DeviceMismatch { mismatch },
        Ok(Federated::Unavailable) => Outcome::Unavailable,
        Ok(Federated::Refused) => Outcome::Refused,
        Ok(Federated::Pending) | Err(_) => Outcome::Pending,
        Ok(Federated::PeerUnsupported) => Outcome::PeerUnsupported,
    }
}

pub(crate) enum SealedStoreOutcome {
    Mismatch(DeviceListMismatch),
    Delivered {
        response: SealedDeliveryResponseV1,
        stored: Vec<(Uuid, i32, DeliveredEnvelope)>,
    },
}

#[tracing::instrument(name = "chat.sealed_sender.store", skip_all)]
pub(crate) async fn store_sealed_messages(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    recipient: Uuid,
    request: &SealedMessageSubmissionV1,
    federation_origin: Option<&str>,
) -> AppResult<SealedStoreOutcome> {
    let metric_stage = if federation_origin.is_some() {
        "federated_destination"
    } else {
        "local_destination"
    };
    if let Err(error) = request.validate() {
        crate::telemetry::sealed_send_event(
            metric_stage,
            "malformed",
            request.envelopes.len() as u64,
        );
        return Err(AppError::bad_request(error));
    }
    let capability = match request.capability_bytes() {
        Ok(capability) => capability,
        Err(_) => {
            crate::telemetry::sealed_send_event(
                metric_stage,
                "not_found",
                request.envelopes.len() as u64,
            );
            return Err(AppError::not_found("sealed delivery unavailable"));
        }
    };
    let presented_hash = capability_hash(&capability);
    let target: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT u.id, c.capability_hash
         FROM users u
         JOIN chat_delivery_capabilities c ON c.user_id = u.id
         WHERE u.id = $1 AND u.is_active = true
         FOR SHARE OF u, c",
    )
    .bind(recipient)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((recipient_id, stored_hash)) = target else {
        crate::telemetry::sealed_send_event(
            metric_stage,
            "not_found",
            request.envelopes.len() as u64,
        );
        return Err(AppError::not_found("sealed delivery unavailable"));
    };
    let Some(stored_hash) = <[u8; 32]>::try_from(stored_hash).ok() else {
        return Err(AppError::internal(
            "stored sealed delivery verifier has an invalid length",
        ));
    };
    if !constant_time_capability_hash_eq(&presented_hash, &stored_hash) {
        crate::telemetry::sealed_send_event(
            metric_stage,
            "not_found",
            request.envelopes.len() as u64,
        );
        return Err(AppError::not_found("sealed delivery unavailable"));
    }

    consume_anonymous_rate(
        tx,
        "capability_minute",
        &presented_hash,
        crate::ratelimit::Limit::SealedCapabilityMinute,
    )
    .await?;
    consume_anonymous_rate(
        tx,
        "capability_day",
        &presented_hash,
        crate::ratelimit::Limit::SealedCapabilityDay,
    )
    .await?;
    let recipient_digest: [u8; 32] = Sha256::digest(
        [
            b"kutup/sealed-recipient-rate/v1\0".as_slice(),
            recipient_id.as_bytes(),
        ]
        .concat(),
    )
    .into();
    consume_anonymous_rate(
        tx,
        "recipient",
        &recipient_digest,
        crate::ratelimit::Limit::SealedRecipient,
    )
    .await?;
    if let Some(origin) = federation_origin {
        let origin_digest: [u8; 32] = Sha256::digest(
            [
                b"kutup/sealed-origin-rate/v1\0".as_slice(),
                origin.as_bytes(),
            ]
            .concat(),
        )
        .into();
        consume_anonymous_rate(
            tx,
            "federation_origin",
            &origin_digest,
            crate::ratelimit::Limit::SealedOrigin,
        )
        .await?;
    }

    let send_id = Uuid::parse_str(&request.send_id)
        .map_err(|_| AppError::bad_request("sealed sendId is invalid"))?;
    let claimed: Option<i32> = sqlx::query_scalar(
        "INSERT INTO chat_anonymous_send_ids
             (recipient_user_id, capability_hash, send_id, stored_count)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT DO NOTHING RETURNING stored_count",
    )
    .bind(recipient_id)
    .bind(presented_hash.as_slice())
    .bind(send_id)
    .bind(request.envelopes.len() as i32)
    .fetch_optional(&mut **tx)
    .await?;
    if claimed.is_none() {
        let stored: i32 = sqlx::query_scalar(
            "SELECT stored_count FROM chat_anonymous_send_ids
             WHERE recipient_user_id = $1 AND capability_hash = $2 AND send_id = $3",
        )
        .bind(recipient_id)
        .bind(presented_hash.as_slice())
        .bind(send_id)
        .fetch_one(&mut **tx)
        .await?;
        crate::telemetry::sealed_send_event(metric_stage, "deduplicated", stored as u64);
        return Ok(SealedStoreOutcome::Delivered {
            response: SealedDeliveryResponseV1 {
                stored: stored as usize,
                deduplicated: true,
            },
            stored: Vec::new(),
        });
    }

    let current: Vec<(i32, i64)> =
        sqlx::query_as("SELECT device_id, registration_id FROM chat_devices WHERE user_id = $1")
            .bind(recipient_id)
            .fetch_all(&mut **tx)
            .await?;
    let mismatch = sealed_device_list_mismatch(&current, &request.envelopes);
    if !mismatch.missing_devices.is_empty()
        || !mismatch.stale_devices.is_empty()
        || !mismatch.extra_devices.is_empty()
    {
        crate::telemetry::sealed_send_event(
            metric_stage,
            "device_mismatch",
            request.envelopes.len() as u64,
        );
        return Ok(SealedStoreOutcome::Mismatch(mismatch));
    }

    let mut stored = Vec::with_capacity(request.envelopes.len());
    for envelope in &request.envelopes {
        let (id, cursor, server_ts): (Uuid, i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO chat_mailbox
                (recipient_user_id, recipient_device_id, sealed_sender,
                 sender_device_id, envelope_type, suite, content, send_id)
             VALUES ($1,$2,true,0,$3,$4,$5,$6)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(envelope.device_id as i32)
        .bind(envelope_type_code(EnvelopeType::Message))
        .bind(envelope.suite.as_u16() as i16)
        .bind(&envelope.content)
        .bind(&request.send_id)
        .fetch_one(&mut **tx)
        .await?;
        stored.push((
            recipient_id,
            envelope.device_id as i32,
            DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender: None,
                sealed_sender: true,
                sender_device_id: 0,
                envelope_type: EnvelopeType::Message,
                suite: envelope.suite,
                content: envelope.content.clone(),
                server_timestamp: server_ts.format(&Rfc3339).unwrap_or_default(),
                send_id: Some(request.send_id.clone()),
            },
        ));
    }
    crate::telemetry::sealed_send_event(metric_stage, "stored", stored.len() as u64);
    Ok(SealedStoreOutcome::Delivered {
        response: SealedDeliveryResponseV1 {
            stored: stored.len(),
            deduplicated: false,
        },
        stored,
    })
}

fn sealed_device_list_mismatch(
    current: &[(i32, i64)],
    envelopes: &[SealedOutgoingEnvelopeV1],
) -> DeviceListMismatch {
    let current: std::collections::BTreeMap<u32, u32> = current
        .iter()
        .filter_map(|(device, registration)| {
            Some((
                u32::try_from(*device).ok()?,
                u32::try_from(*registration).ok()?,
            ))
        })
        .collect();
    let supplied: std::collections::BTreeMap<u32, u32> = envelopes
        .iter()
        .map(|envelope| (envelope.device_id, envelope.registration_id))
        .collect();
    DeviceListMismatch {
        missing_devices: current
            .keys()
            .filter(|device| !supplied.contains_key(device))
            .copied()
            .collect(),
        stale_devices: current
            .iter()
            .filter(|(device, registration)| {
                supplied
                    .get(device)
                    .is_some_and(|seen| seen != *registration)
            })
            .map(|(device, _)| *device)
            .collect(),
        extra_devices: supplied
            .keys()
            .filter(|device| !current.contains_key(device))
            .copied()
            .collect(),
    }
}

pub(crate) async fn push_sealed(state: &AppState, stored: Vec<(Uuid, i32, DeliveredEnvelope)>) {
    for (user, device, envelope) in stored {
        crate::web_push::wake_if_offline(state, user, device);
        let message = ChatWsServerMessage::Envelope { envelope };
        if let Ok(text) = serde_json::to_string(&message) {
            for connection in state.chat_hub.connections(user, device) {
                connection.write(ChatWsOut::Text(text.clone())).await;
            }
        }
    }
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
    let device: Option<i32> = sqlx::query_scalar(
        "UPDATE chat_devices SET last_seen_at = now()
         WHERE user_id = $1 AND device_id = $2 RETURNING 1",
    )
    .bind(sender_id)
    .bind(req.sender_device_id as i32)
    .fetch_optional(&mut *tx)
    .await?;
    device.ok_or_else(|| AppError::not_found("no such chat device"))?;
    // Mailbox rows and delivered envelopes name the sender by its account
    // (server and permanent id), never a name.
    let sender = crate::account_ids::local(&state.config.chat_server_name, sender_id)?;

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
            "INSERT INTO chat_mailbox (recipient_user_id, recipient_device_id, sender_server,
                 sender_account_id, sender_device_id, envelope_type, suite, content, send_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(e.device_id as i32)
        .bind(&sender.server)
        .bind(sender_id)
        .bind(req.sender_device_id as i32)
        .bind(envelope_type_code(e.envelope_type))
        .bind(e.suite.as_u16() as i16)
        .bind(&e.content)
        .bind(&req.send_id)
        .fetch_one(&mut *tx)
        .await?;
        stored.push((
            recipient_id,
            e.device_id as i32,
            DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender: Some(sender.clone()),
                sealed_sender: false,
                sender_device_id: req.sender_device_id,
                envelope_type: e.envelope_type,
                suite: e.suite,
                content: e.content.clone(),
                server_timestamp: ts.format(&Rfc3339).unwrap_or_default(),
                send_id: Some(req.send_id.clone()),
            },
        ));
    }
    tx.commit().await?;

    for (user, device, envelope) in stored {
        // Not for this account's own transcripts and notes to self.
        if recipient_id != sender_id {
            crate::web_push::wake_if_offline(state, user, device);
        }
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
        Option<Uuid>,
        bool,
        i32,
        i16,
        i16,
        String,
        OffsetDateTime,
        Option<String>,
        Option<Uuid>,
        Option<i32>,
    )> = sqlx::query_as(
        // A shared payload's size only: the payloads themselves are read
        // for the rows that fit the page's bytes (below).
        "SELECT m.id, m.cursor, m.sender_server, m.sender_account_id, m.sealed_sender,
                m.sender_device_id, m.envelope_type, m.suite, m.content, m.server_ts, m.send_id,
                m.shared_payload_id, octet_length(p.payload)
             FROM chat_mailbox m
             LEFT JOIN chat_shared_payloads p ON p.id = m.shared_payload_id
             WHERE m.recipient_user_id = $1 AND m.recipient_device_id = $2
               AND ($4::BIGINT IS NULL OR m.cursor > $4)
             ORDER BY m.cursor
             LIMIT $3",
    )
    .bind(user_id)
    .bind(q.device_id)
    .bind(limit + 1)
    .bind(q.after)
    .fetch_all(&state.pool)
    .await?;

    let mut more = rows.len() as i64 > limit;
    // A page is capped by bytes as well as count: a row naming a shared
    // payload (a multi-recipient send) is assembled into the device's sealed
    // envelope here, up to 96 KiB each.
    let mut rows: Vec<_> = rows.into_iter().take(limit as usize).collect();
    let mut bytes = 0usize;
    let mut fits = 0usize;
    for row in &rows {
        let shared = row
            .12
            .map_or(0, |len| usize::try_from(len).unwrap_or(usize::MAX));
        let size = row.8.len() + shared.saturating_mul(4) / 3 + 4;
        if fits > 0 && bytes + size > MAX_DRAIN_BYTES {
            break;
        }
        bytes += size;
        fits += 1;
    }
    if fits < rows.len() {
        rows.truncate(fits);
        more = true;
    }
    let mut payload_ids: Vec<Uuid> = rows.iter().filter_map(|row| row.11).collect();
    payload_ids.sort();
    payload_ids.dedup();
    let payloads: std::collections::HashMap<Uuid, Vec<u8>> = if payload_ids.is_empty() {
        Default::default()
    } else {
        sqlx::query_as::<_, (Uuid, Vec<u8>)>(
            "SELECT id, payload FROM chat_shared_payloads WHERE id = ANY($1)",
        )
        .bind(&payload_ids)
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .collect()
    };
    let envelopes: Vec<DeliveredEnvelope> = rows
        .into_iter()
        .map(
            |(
                id,
                cursor,
                sender_server,
                sender_account_id,
                sealed_sender,
                sender_dev,
                etype,
                suite,
                content,
                ts,
                send_id,
                shared,
                _,
            )| {
                let content = match shared {
                    Some(id) => {
                        let shared = payloads.get(&id).ok_or_else(|| {
                            AppError::internal("a mailbox row names a missing shared payload")
                        })?;
                        crate::handlers::chat_multi::assemble(&content, shared)?
                    }
                    None => content,
                };
                let sender = match (sender_server, sender_account_id) {
                    (Some(server), Some(account_id)) => {
                        Some(crate::account_ids::stored(&server, account_id)?)
                    }
                    _ => None,
                };
                Ok(DeliveredEnvelope {
                    id: id.to_string(),
                    cursor: cursor as u64,
                    sender,
                    sealed_sender,
                    sender_device_id: sender_dev as u32,
                    envelope_type: envelope_type_from_code(etype),
                    suite: direct_chat_suite_from_db(suite, "chat_mailbox")?,
                    content,
                    server_timestamp: ts.format(&Rfc3339).unwrap_or_default(),
                    send_id,
                })
            },
        )
        .collect::<AppResult<_>>()?;

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
    let deleted: Vec<Option<Uuid>> = sqlx::query_scalar(
        "DELETE FROM chat_mailbox
         WHERE recipient_user_id = $1 AND recipient_device_id = $2 AND id = ANY($3)
         RETURNING shared_payload_id",
    )
    .bind(user_id)
    .bind(q.device_id)
    .bind(&ids)
    .fetch_all(&state.pool)
    .await?;
    // The shared payloads the acked rows named, once no row names them; a
    // failure leaves them to the sweep.
    let mut shared: Vec<Uuid> = deleted.iter().flatten().copied().collect();
    shared.sort();
    shared.dedup();
    if let Err(error) = crate::handlers::chat_multi::collect_payloads(&state.pool, &shared).await {
        tracing::warn!(error = %error.message, "chat: shared payload collection after an ack failed");
    }
    let deleted = deleted.len() as u64;
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
            let user_id = crate::middleware::authenticate_access_token(&state, token)
                .await
                .map_err(|_| AppError::unauthorized("invalid token"))?
                .user_id;
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

    // Read loop — acks are REST; the client only sends liveness pings. We
    // answer those, watch for disconnect and honour forced close.
    loop {
        tokio::select! {
            _ = conn.close.notified() => break,
            msg = stream.next() => match msg {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(Message::Text(text))) => {
                    if let Ok(ChatWsClientMessage::Ping) = serde_json::from_str(&text) {
                        if let Ok(pong) = serde_json::to_string(&ChatWsServerMessage::Pong) {
                            conn.write(ChatWsOut::Text(pong)).await;
                        }
                    }
                }
                Some(Ok(_)) => {} // protocol ping/pong handled by axum; other frames ignored
            },
        }
    }

    state.chat_hub.leave(user_id, device_id, conn.conn_id);
    writer.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Drive keys in a manifest change only by the one-way rise from a
    /// suite-1 (32-byte X25519) key to X-Wing, signing key unchanged.
    #[test]
    fn manifest_drive_keys_only_rise_from_suite_1_to_x_wing() {
        use kutup_chat_proto::{AccountIdentitySuiteId, AccountManifestDriveKeysV1};
        let keys = |suite, key_len: usize, signing: u8| AccountManifestDriveKeysV1 {
            suite,
            hpke_public_key: STANDARD.encode(vec![7u8; key_len]),
            share_signing_public_key: STANDARD.encode([signing; 32]),
        };
        let old = keys(AccountIdentitySuiteId::X25519Ed25519V1, 32, 1);
        let new = keys(AccountIdentitySuiteId::XWingEd25519V2, 1216, 1);
        assert!(drive_keys_follow(&old, &old));
        assert!(drive_keys_follow(&new, &new));
        assert!(drive_keys_follow(&old, &new), "the rise");
        assert!(!drive_keys_follow(&new, &old), "never back");
        let other = AccountManifestDriveKeysV1 {
            hpke_public_key: STANDARD.encode(vec![8u8; 1216]),
            ..new.clone()
        };
        assert!(!drive_keys_follow(&new, &other), "no second change");
        assert!(
            !drive_keys_follow(&old, &keys(AccountIdentitySuiteId::XWingEd25519V2, 1216, 2)),
            "the signing key stays"
        );
        assert!(
            !drive_keys_follow(
                &keys(AccountIdentitySuiteId::X25519Ed25519V1, 1216, 1),
                &new
            ),
            "only from a real suite-1 key"
        );
        assert!(
            !drive_keys_follow(&old, &keys(AccountIdentitySuiteId::XWingEd25519V2, 32, 1)),
            "only to a real X-Wing key"
        );
    }

    /// Only a queued send reads as pending; a send that wasn't queued gets
    /// its own answer, or fails the whole request.
    #[test]
    fn a_batch_says_pending_only_for_a_queued_send() {
        use crate::chat_federation::FederatedSealedOutcome as Federated;
        use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
        let not_queued = |status| not_queued_outcome(AppError::new(status, "x"));
        assert_eq!(
            not_queued(StatusCode::NOT_FOUND).unwrap(),
            Outcome::Unavailable
        );
        assert_eq!(
            not_queued(StatusCode::PAYLOAD_TOO_LARGE).unwrap(),
            Outcome::Refused
        );
        assert_eq!(not_queued(StatusCode::CONFLICT).unwrap(), Outcome::Conflict);
        assert_eq!(
            not_queued(StatusCode::TOO_MANY_REQUESTS).unwrap(),
            Outcome::RateLimited
        );
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::BAD_REQUEST,
        ] {
            assert_eq!(not_queued(status).unwrap_err().status, status);
        }
        // A queued send: its answer, or still queued after a failure.
        assert_eq!(
            batch_outcome(Ok(Federated::Unavailable)),
            Outcome::Unavailable
        );
        assert_eq!(batch_outcome(Ok(Federated::Refused)), Outcome::Refused);
        assert_eq!(
            batch_outcome(Ok(Federated::PeerUnsupported)),
            Outcome::PeerUnsupported
        );
        assert_eq!(
            batch_outcome(Err(AppError::internal("x"))),
            Outcome::Pending
        );
    }

    fn profile_test_account() -> AccountRef {
        crate::account_ids::local("example.test", Uuid::from_u128(7)).unwrap()
    }

    fn opaque_profile_envelope(purpose: ProfileEnvelopePurpose, ciphertext_len: usize) -> String {
        let context =
            ProfileEnvelopeContextV1::new(purpose, &profile_test_account(), &"01".repeat(32), 1, 1)
                .unwrap();
        let mut envelope = kutup_chat_proto::encode_profile_envelope_header(
            &context,
            &[4; 24],
            ciphertext_len as u32,
        )
        .unwrap();
        envelope.extend(vec![0u8; ciphertext_len]);
        STANDARD.encode(envelope)
    }

    fn valid_profile() -> PutChatProfileRequest {
        PutChatProfileRequest {
            suite: ProfileSuiteId::XChaCha20Poly1305V1,
            account: profile_test_account(),
            version: "01".repeat(32),
            revision: 1,
            source_device_id: 1,
            name: opaque_profile_envelope(
                ProfileEnvelopePurpose::DisplayName,
                kutup_chat_proto::PROFILE_NAME_PADDED_LENGTHS[0] + 16,
            ),
            avatar: None,
            about: None,
            wrapped_key: opaque_profile_envelope(
                ProfileEnvelopePurpose::WrappedProfileKey,
                32 + 16,
            ),
            access_key_verifier: "02".repeat(32),
            delivery_capability_verifier: "03".repeat(32),
        }
    }

    fn envelope(device_id: u32, registration_id: u32) -> OutgoingEnvelope {
        OutgoingEnvelope {
            device_id,
            registration_id,
            envelope_type: EnvelopeType::Message,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content: STANDARD.encode(b"ciphertext"),
        }
    }

    #[test]
    fn a_path_names_an_account_on_this_server_unless_it_says_otherwise() {
        let id = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        let local = crate::account_ids::named("kutup.local", id, None).unwrap();
        assert_eq!(local.to_string(), format!("aci:{id}@kutup.local"));
        let remote = crate::account_ids::named("kutup.local", id, Some("remote.test")).unwrap();
        assert_eq!(remote.server, "remote.test");
        // A name is not an account id.
        assert!(crate::account_ids::named("kutup.local", "alice", None).is_err());
        assert!(crate::account_ids::named("kutup.local", id, Some("Remote.Test")).is_err());
    }

    #[test]
    fn database_suite_conversion_is_closed_and_never_wraps() {
        assert_eq!(
            direct_chat_suite_from_db(1, "test").unwrap(),
            DirectChatSuiteId::PqxdhTripleRatchetV1
        );
        for value in [-1, 0, 2, i16::MAX] {
            let error = direct_chat_suite_from_db(value, "test").unwrap_err();
            assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error.message.contains(&value.to_string()));
            assert!(error.message.contains("test"));
        }
    }

    #[test]
    fn device_names_are_trimmed_and_strictly_bounded() {
        assert_eq!(
            normalized_device_name("  Work laptop  ").unwrap(),
            "Work laptop"
        );

        for invalid in ["", "   ", "line\nbreak"] {
            assert_eq!(
                normalized_device_name(invalid).unwrap_err().status,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            normalized_device_name(&"a".repeat(MAX_DEVICE_NAME_CHARS + 1))
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        assert!(normalized_device_name(&"ü".repeat(MAX_DEVICE_NAME_CHARS)).is_ok());
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
        assert_eq!(
            validate_profile(&profile, &profile_test_account()).unwrap(),
            (vec![2u8; 32], vec![3u8; 32])
        );

        let mut oversized_avatar = profile.clone();
        let valid_avatar = opaque_profile_envelope(
            ProfileEnvelopePurpose::Avatar,
            kutup_chat_proto::MAX_PROFILE_AVATAR_BYTES + 1 + 16,
        );
        let mut decoded_avatar = STANDARD.decode(valid_avatar).unwrap();
        decoded_avatar.push(0);
        oversized_avatar.avatar = Some(STANDARD.encode(decoded_avatar));
        assert_eq!(
            validate_profile(&oversized_avatar, &profile_test_account())
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );

        let mut noncanonical_version = profile;
        noncanonical_version.version = "AA".repeat(32);
        assert_eq!(
            validate_profile(&noncanonical_version, &profile_test_account())
                .unwrap_err()
                .status,
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
