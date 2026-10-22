//! One libsignal identity per account, as Signal's ACI
//! (docs/plans/account-identity-key.md): device credentials, the account
//! identity row, prekey signature checks and the V2 manifest rules the Chat
//! handlers share.
//!
//! Signal's server checks a device's credential on every call and a signed
//! prekey's signature against the account identity on every upload
//! (`AccountAuthenticator`, `PreKeySignatureValidator`); Kutup does both.

use axum::http::HeaderMap;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    decode_identity_key, parse_device_header, repeated_use_keys_digest,
    AccountIdentityDistributionRequest, AccountManifestPublicationV2, AccountManifestV2,
    ChatKeysCheckRequest, DeviceListMismatch, DistributionError, EcPreKey, KemPreKey,
    CHAT_DEVICE_HEADER, DEVICE_CREDENTIAL_LEN,
};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

const CREDENTIAL_DOMAIN: &[u8] = b"kutup/chat-device-credential/v1\0";

/// SHA-256 over the domain, the row's salt and the device's credential: a
/// 32-byte random credential needs no slow hash (Signal's `SaltedTokenHash`).
pub(crate) fn credential_hash(salt: &[u8], credential: &[u8; DEVICE_CREDENTIAL_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_DOMAIN);
    hasher.update(salt);
    hasher.update(credential);
    hasher.finalize().into()
}

/// A new row's salt and the hash of `credential` under it.
pub(crate) fn new_credential(credential: &[u8; DEVICE_CREDENTIAL_LEN]) -> ([u8; 16], [u8; 32]) {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    (salt, credential_hash(&salt, credential))
}

fn unauthorized() -> AppError {
    AppError::unauthorized("this Chat device's credential is missing or wrong")
        .with_details(serde_json::json!({ "code": "deviceCredential" }))
}

/// The device the `X-Kutup-Chat-Device` header names, if its credential is
/// that device's (a live row of the JWT's account): `401 deviceCredential`
/// otherwise, the same answer for a wrong credential, an unknown device and
/// an expired one. Marks the device seen.
pub(crate) async fn authenticated_device(
    pool: &sqlx::PgPool,
    headers: &HeaderMap,
    user_id: Uuid,
) -> AppResult<i32> {
    let value = headers
        .get(CHAT_DEVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(unauthorized)?;
    let (device_id, credential) = parse_device_header(value).map_err(|_| unauthorized())?;
    let device_id = device_id as i32;
    let stored: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT credential_salt, credential_hash FROM chat_devices
          WHERE user_id = $1 AND device_id = $2 AND expired_at IS NULL",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    let Some((salt, hash)) = stored else {
        return Err(unauthorized());
    };
    let presented = credential_hash(&salt, &credential);
    if !crate::handlers::chat::constant_time_eq(&presented, &hash) {
        return Err(unauthorized());
    }
    sqlx::query(
        "UPDATE chat_devices SET last_seen_at = now() WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(device_id)
}

/// As [`authenticated_device`], for a call that also names the device (a
/// `deviceId` query or field): the two must agree.
pub(crate) async fn authenticate_device(
    pool: &sqlx::PgPool,
    headers: &HeaderMap,
    user_id: Uuid,
    device_id: i32,
) -> AppResult<()> {
    if authenticated_device(pool, headers, user_id).await? != device_id {
        return Err(unauthorized());
    }
    Ok(())
}

/// The account's identity key, if it has one (it has a Chat device).
pub(crate) async fn account_identity(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<Option<(String, i64)>> {
    Ok(sqlx::query_as(
        "SELECT identity_key, manifest_version FROM chat_account_identities WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?)
}

fn bad_signature(what: &str) -> AppError {
    AppError::bad_request(format!("{what} is not signed by the account identity"))
        .with_details(serde_json::json!({ "code": "badSignature" }))
}

fn decode(name: &'static str, value: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| !bytes.is_empty() && STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request(format!("{name} must be canonical base64")))
}

/// The account identity's public key, a valid point.
pub(crate) fn identity_public_key(
    identity_key: &str,
) -> AppResult<libsignal_protocol::IdentityKey> {
    let bytes = decode_identity_key("identityKey", identity_key).map_err(AppError::bad_request)?;
    libsignal_protocol::IdentityKey::decode(&bytes)
        .map_err(|_| AppError::bad_request("identityKey is not a valid Curve25519 key"))
}

/// A signed EC prekey, the last-resort Kyber key and one-time Kyber keys,
/// each signed by the account identity over its serialized public key, as
/// libsignal signs them.
pub(crate) fn verify_prekey_signatures(
    identity: &libsignal_protocol::IdentityKey,
    signed_pre_key: Option<&EcPreKey>,
    kyber_keys: &[&KemPreKey],
) -> AppResult<()> {
    if let Some(key) = signed_pre_key {
        let public = decode("signedPreKey", &key.public_key)?;
        let signature = decode(
            "signedPreKey",
            key.signature
                .as_deref()
                .ok_or_else(|| AppError::bad_request("signedPreKey requires a signature"))?,
        )?;
        if !identity.public_key().verify_signature(&public, &signature) {
            return Err(bad_signature("signedPreKey"));
        }
    }
    for key in kyber_keys {
        let public = decode("kyberPreKey", &key.public_key)?;
        let signature = decode("kyberPreKey", &key.signature)?;
        if !identity.public_key().verify_signature(&public, &signature) {
            return Err(bad_signature("a Kyber prekey"));
        }
    }
    Ok(())
}

/// The manifest's own checks and an `issuedAt` not from the future.
pub(crate) fn validate_manifest_v2(manifest: &AccountManifestV2) -> AppResult<()> {
    if manifest.sequence > i64::MAX as u64 {
        return Err(AppError::bad_request("manifest sequence is too large"));
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

/// `POST /api/chat/keys/check` (device-authenticated; Signal's
/// `/v2/keys/check`): whether the server holds what the device believes it
/// holds for it (the account identity, its signed prekey and its last-resort
/// key). `204` when they agree, `409 keysDiffer` when they don't (the device
/// then uploads its keys again).
#[utoipa::path(
    post,
    path = "/api/chat/keys/check",
    tag = "chat",
    operation_id = "checkChatKeys",
    request_body = ChatKeysCheckRequest,
    responses(
        (status = 204, description = "The server's keys are the device's"),
        (status = 401, description = "Missing or wrong device credential"),
        (status = 409, description = "The server holds other keys"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn check_keys(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    auth: crate::middleware::AuthUser,
    headers: HeaderMap,
    axum::Json(request): axum::Json<ChatKeysCheckRequest>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse as _;
    let user_id = crate::handlers::trusted_uuid(&auth.user_id)?;
    let device_id = authenticated_device(&state.pool, &headers, user_id).await?;
    let presented = hex::decode(&request.digest)
        .ok()
        .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == request.digest)
        .ok_or_else(|| AppError::bad_request("digest must be lowercase hex of 32 bytes"))?;
    let (identity_key, spk_id, spk, lrk_id, lrk): (String, i64, String, i64, String) =
        sqlx::query_as(
            "SELECT identity_key, signed_pre_key_id, signed_pre_key,
                    last_resort_kyber_pre_key_id, last_resort_kyber_pre_key
               FROM chat_devices WHERE user_id = $1 AND device_id = $2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&state.pool)
        .await?;
    let decode = |value: &str| STANDARD.decode(value).unwrap_or_default();
    let held = repeated_use_keys_digest(
        &decode(&identity_key),
        spk_id as u32,
        &decode(&spk),
        lrk_id as u32,
        &decode(&lrk),
    );
    if crate::handlers::chat::constant_time_eq(&held, &presented) {
        Ok(axum::http::StatusCode::NO_CONTENT.into_response())
    } else {
        Err(
            AppError::conflict("the server holds other keys for this device")
                .with_details(serde_json::json!({ "code": "keysDiffer" })),
        )
    }
}

/// `PUT /api/chat/account-identity` (device-authenticated; Signal's
/// `PhoneNumberIdentityKeyDistributionRequest`): a new account identity for
/// every device the manifest keeps, in one transaction. The request names
/// exactly the manifest's devices (`409` with the mismatch otherwise, and for
/// a listed device that isn't the account's), each with a signed prekey and
/// a last-resort key under the new identity (`400 badSignature`), and one
/// sealed `accountIdentity` sync per other device on its current session
/// (`410` when its registration id is no longer the device's). Rows the
/// manifest leaves out (a lost device) are dropped; every one-time key of
/// the account goes, and the devices upload new ones.
#[utoipa::path(
    put,
    path = "/api/chat/account-identity",
    tag = "chat",
    operation_id = "distributeChatAccountIdentity",
    request_body = AccountIdentityDistributionRequest,
    responses(
        (status = 200, description = "Distributed", body = AccountManifestPublicationV2),
        (status = 400, description = "Malformed, or a key not signed by the identity"),
        (status = 401, description = "Missing or wrong device credential"),
        (status = 409, description = "Devices missing or extra, or a manifest conflict", body = DeviceListMismatch),
        (status = 410, description = "A device's registration id changed", body = DeviceListMismatch),
    ),
    security(("bearerAuth" = []))
)]
pub async fn distribute_identity(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    auth: crate::middleware::AuthUser,
    headers: HeaderMap,
    axum::Json(request): axum::Json<AccountIdentityDistributionRequest>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse as _;
    use axum::Json;
    let user_id = crate::handlers::trusted_uuid(&auth.user_id)?;
    let sender = authenticated_device(&state.pool, &headers, user_id).await?;
    if !crate::ratelimit::CHAT_IDENTITY_DISTRIBUTIONS.allow(&auth.user_id) {
        return Err(
            AppError::too_many_requests("too many identity distributions")
                .with_details(serde_json::json!({ "code": "rateLimited" })),
        );
    }
    match request.validate(sender as u32) {
        Ok(()) => {}
        Err(DistributionError::Invalid(message)) => return Err(AppError::bad_request(message)),
        Err(DistributionError::Mismatched(mismatch)) => {
            return Ok((axum::http::StatusCode::CONFLICT, Json(mismatch)).into_response())
        }
    }
    validate_manifest_v2(&request.manifest)?;
    let identity = identity_public_key(&request.identity_key)?;
    for keys in &request.devices {
        verify_prekey_signatures(
            &identity,
            Some(&keys.signed_pre_key),
            &[&keys.last_resort_kyber_pre_key],
        )?;
    }
    for message in &request.device_messages {
        let content = STANDARD
            .decode(&message.content)
            .map_err(|_| AppError::bad_request("deviceMessages content must be base64"))?;
        if content.is_empty() || content.len() > crate::handlers::chat::MAX_CONTENT_BYTES {
            return Err(AppError::bad_request(
                "a device message is empty or too large",
            ));
        }
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let rows: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT device_id, registration_id FROM chat_devices
          WHERE user_id = $1 AND expired_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    // A listed device the account doesn't have: 409, as an extra device.
    let extra: Vec<u32> = request
        .devices
        .iter()
        .map(|keys| keys.device_id)
        .filter(|id| !rows.iter().any(|(row, _)| *row as u32 == *id))
        .collect();
    if !extra.is_empty() {
        let mismatch = DeviceListMismatch {
            missing_devices: Vec::new(),
            stale_devices: Vec::new(),
            extra_devices: extra,
        };
        return Ok((axum::http::StatusCode::CONFLICT, Json(mismatch)).into_response());
    }
    // A sync on a session the device no longer has: 410, as on sends.
    let stale: Vec<u32> = request
        .device_messages
        .iter()
        .filter(|message| {
            rows.iter().any(|(row, registration)| {
                *row as u32 == message.device_id && *registration as u32 != message.registration_id
            })
        })
        .map(|message| message.device_id)
        .collect();
    if !stale.is_empty() {
        let mismatch = DeviceListMismatch {
            missing_devices: Vec::new(),
            stale_devices: stale,
            extra_devices: Vec::new(),
        };
        return Ok((axum::http::StatusCode::GONE, Json(mismatch)).into_response());
    }

    crate::handlers::chat::store_manifest_v2(
        &mut tx,
        &state,
        user_id,
        &request.manifest,
        crate::handlers::chat::IdentityChange::New,
    )
    .await?;
    // The devices left out (a lost or stolen one) go now.
    let kept: Vec<i32> = request
        .devices
        .iter()
        .map(|keys| keys.device_id as i32)
        .collect();
    let dropped: Vec<i32> = sqlx::query_scalar(
        "DELETE FROM chat_devices WHERE user_id = $1 AND NOT (device_id = ANY($2))
         RETURNING device_id",
    )
    .bind(user_id)
    .bind(&kept)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM chat_mls_devices WHERE user_id = $1 AND NOT (device_id = ANY($2))")
        .bind(user_id)
        .bind(&kept)
        .execute(&mut *tx)
        .await?;
    for keys in &request.devices {
        sqlx::query(
            "UPDATE chat_devices SET identity_key = $3, registration_id = $4,
                 signed_pre_key_id = $5, signed_pre_key = $6, signed_pre_key_signature = $7,
                 last_resort_kyber_pre_key_id = $8, last_resort_kyber_pre_key = $9,
                 last_resort_kyber_pre_key_signature = $10
             WHERE user_id = $1 AND device_id = $2",
        )
        .bind(user_id)
        .bind(keys.device_id as i32)
        .bind(&request.identity_key)
        .bind(keys.registration_id as i64)
        .bind(keys.signed_pre_key.key_id as i64)
        .bind(&keys.signed_pre_key.public_key)
        .bind(keys.signed_pre_key.signature.as_deref().unwrap_or_default())
        .bind(keys.last_resort_kyber_pre_key.key_id as i64)
        .bind(&keys.last_resort_kyber_pre_key.public_key)
        .bind(&keys.last_resort_kyber_pre_key.signature)
        .execute(&mut *tx)
        .await?;
    }
    // One-time keys were signed by (or made for) the old identity: Signal's
    // deleteSingleUsePreKeys.
    sqlx::query("DELETE FROM chat_one_time_pre_keys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM chat_one_time_kyber_pre_keys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    // The syncs, from the sending device to each kept one, in this
    // transaction: they arrive with the swap or not at all.
    let account = crate::account_ids::local(&state.config.chat_server_name, user_id)?;
    let send_id = uuid::Uuid::new_v4().to_string();
    for message in &request.device_messages {
        sqlx::query(
            "INSERT INTO chat_mailbox (recipient_user_id, recipient_device_id, sender_server,
                 sender_account_id, sender_device_id, envelope_type, suite, content, send_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(user_id)
        .bind(message.device_id as i32)
        .bind(&account.server)
        .bind(user_id)
        .bind(sender)
        .bind(crate::handlers::chat::envelope_type_code(
            message.envelope_type,
        ))
        .bind(message.suite.as_u16() as i16)
        .bind(&message.content)
        .bind(&send_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    for device_id in dropped {
        state.chat_hub.close_device(user_id, device_id);
    }
    state.chat_hub.notify_devices_changed(user_id);
    Ok(Json(AccountManifestPublicationV2 {
        manifest: request.manifest,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_hashes_under_its_salt_only() {
        let credential = [7u8; DEVICE_CREDENTIAL_LEN];
        let (salt, hash) = new_credential(&credential);
        assert_eq!(credential_hash(&salt, &credential), hash);
        assert_ne!(credential_hash(&salt, &[8u8; DEVICE_CREDENTIAL_LEN]), hash);
        let (other_salt, other_hash) = new_credential(&credential);
        assert_ne!(other_salt, salt);
        assert_ne!(other_hash, hash);
    }

    #[test]
    fn prekeys_verify_only_under_the_account_identity() {
        use libsignal_protocol::{kem, IdentityKeyPair, KeyPair};
        let mut rng = rand09::rng();
        let account = IdentityKeyPair::generate(&mut rng);
        let other = IdentityKeyPair::generate(&mut rng);
        let signed = KeyPair::generate(&mut rng).public_key.serialize();
        let spk = |by: &IdentityKeyPair| EcPreKey {
            key_id: 1,
            public_key: STANDARD.encode(&signed),
            signature: Some(
                STANDARD.encode(
                    by.private_key()
                        .calculate_signature(&signed, &mut rand09::rng())
                        .unwrap(),
                ),
            ),
        };
        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng)
            .public_key
            .serialize();
        let lrk = |by: &IdentityKeyPair| KemPreKey {
            key_id: 2,
            public_key: STANDARD.encode(&kyber),
            signature: STANDARD.encode(
                by.private_key()
                    .calculate_signature(&kyber, &mut rand09::rng())
                    .unwrap(),
            ),
        };
        let identity = account.identity_key();
        verify_prekey_signatures(identity, Some(&spk(&account)), &[&lrk(&account)]).unwrap();
        assert!(verify_prekey_signatures(identity, Some(&spk(&other)), &[]).is_err());
        assert!(verify_prekey_signatures(identity, None, &[&lrk(&other)]).is_err());
        let identity_text = STANDARD.encode(identity.serialize());
        assert_eq!(identity_public_key(&identity_text).unwrap(), *identity);
        assert!(identity_public_key("AAAA").is_err());
    }
}
