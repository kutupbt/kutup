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
    decode_identity_key, parse_device_header, AccountManifestV2, EcPreKey, KemPreKey,
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
pub(crate) fn identity_public_key(identity_key: &str) -> AppResult<libsignal_protocol::IdentityKey> {
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
            signature: Some(STANDARD.encode(
                by.private_key()
                    .calculate_signature(&signed, &mut rand09::rng())
                    .unwrap(),
            )),
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
