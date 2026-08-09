//! Canonical opaque-relay wire types for one-time Chat history transfer.
//!
//! Cryptographic signing, DH, frame encryption and archive import live in the
//! clients. This module freezes the bytes they authenticate and the bounds a
//! server can enforce without seeing archive plaintext.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::AccountAddress;

pub const CHAT_HISTORY_TRANSFER_VERSION: u16 = 1;
pub const CHAT_HISTORY_TRANSFER_TTL_SECONDS: i64 = 15 * 60;
pub const MAX_CHAT_HISTORY_TRANSFER_FRAME_PLAINTEXT: u32 = 256 * 1024;
pub const MAX_CHAT_HISTORY_TRANSFER_FRAMES: u32 = 1_024;
pub const MAX_CHAT_HISTORY_TRANSFER_RECORDS: u32 = 100_000;
pub const MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT: u64 = 256 * 1024 * 1024;

const REQUEST_DOMAIN: &[u8] = b"kutup/chat/history-transfer-request/v1\0";
const ACCEPTANCE_DOMAIN: &[u8] = b"kutup/chat/history-transfer-acceptance/v1\0";
const FRAME_AAD_DOMAIN: &[u8] = b"kutup/chat/history-transfer-frame/v1\0";
const COMPLETION_DOMAIN: &[u8] = b"kutup/chat/history-transfer-completion/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatHistoryTransferRequestV1 {
    pub version: u16,
    pub transfer_id: String,
    pub account: String,
    pub requesting_device_id: u32,
    pub manifest_sequence: u64,
    /// Canonical padded base64 raw X25519 public key.
    pub ephemeral_public_key: String,
    /// Canonical padded base64 32-byte random request nonce.
    pub request_nonce: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    /// Canonical padded base64 64-byte XEdDSA signature by the requesting
    /// manifest device's libsignal identity key.
    pub device_signature: String,
}

impl ChatHistoryTransferRequestV1 {
    pub fn validate(&self, now_unix: i64) -> Result<(), String> {
        require_version(self.version)?;
        require_uuid("transferId", &self.transfer_id)?;
        require_account(&self.account)?;
        require_device_id("requestingDeviceId", self.requesting_device_id)?;
        if self.manifest_sequence == 0 {
            return Err("manifestSequence must be positive".into());
        }
        decode_base64_exact::<32>("ephemeralPublicKey", &self.ephemeral_public_key)?;
        decode_base64_exact::<32>("requestNonce", &self.request_nonce)?;
        require_window(self.created_at_unix, self.expires_at_unix, now_unix)?;
        decode_base64_exact::<64>("deviceSignature", &self.device_signature)?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        require_uuid("transferId", &self.transfer_id)?;
        require_account(&self.account)?;
        require_device_id("requestingDeviceId", self.requesting_device_id)?;
        if self.manifest_sequence == 0 {
            return Err("manifestSequence must be positive".into());
        }
        let public_key =
            decode_base64_exact::<32>("ephemeralPublicKey", &self.ephemeral_public_key)?;
        let nonce = decode_base64_exact::<32>("requestNonce", &self.request_nonce)?;
        require_window_shape(self.created_at_unix, self.expires_at_unix)?;

        let mut out = Vec::with_capacity(192);
        out.extend_from_slice(REQUEST_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_string(&mut out, &self.transfer_id)?;
        push_string(&mut out, &self.account)?;
        out.extend_from_slice(&self.requesting_device_id.to_be_bytes());
        out.extend_from_slice(&self.manifest_sequence.to_be_bytes());
        out.extend_from_slice(&public_key);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        Ok(out)
    }

    pub fn signed_hash(&self) -> Result<[u8; 32], String> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&decode_base64_exact::<64>(
            "deviceSignature",
            &self.device_signature,
        )?);
        Ok(Sha256::digest(bytes).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatHistoryTransferAcceptanceV1 {
    pub version: u16,
    pub transfer_id: String,
    pub account: String,
    pub requesting_device_id: u32,
    pub responding_device_id: u32,
    pub manifest_sequence: u64,
    /// Lowercase hex SHA-256 of the complete signed request.
    pub request_hash: String,
    /// Canonical padded base64 raw X25519 public key.
    pub ephemeral_public_key: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub record_limit: u32,
    pub plaintext_byte_limit: u64,
    /// Canonical padded base64 64-byte XEdDSA signature by the responding
    /// manifest device's libsignal identity key.
    pub device_signature: String,
}

impl ChatHistoryTransferAcceptanceV1 {
    pub fn validate(
        &self,
        request: &ChatHistoryTransferRequestV1,
        now_unix: i64,
    ) -> Result<(), String> {
        request.validate(now_unix)?;
        require_version(self.version)?;
        require_uuid("transferId", &self.transfer_id)?;
        require_account(&self.account)?;
        require_device_id("requestingDeviceId", self.requesting_device_id)?;
        require_device_id("respondingDeviceId", self.responding_device_id)?;
        if self.requesting_device_id == self.responding_device_id {
            return Err("history transfer requires two distinct devices".into());
        }
        if self.transfer_id != request.transfer_id
            || self.account != request.account
            || self.requesting_device_id != request.requesting_device_id
            || self.manifest_sequence != request.manifest_sequence
        {
            return Err("acceptance does not bind the exact transfer request".into());
        }
        require_hash("requestHash", &self.request_hash)?;
        if self.request_hash != hex::encode(request.signed_hash()?) {
            return Err("acceptance requestHash does not match the signed request".into());
        }
        decode_base64_exact::<32>("ephemeralPublicKey", &self.ephemeral_public_key)?;
        require_window(self.created_at_unix, self.expires_at_unix, now_unix)?;
        if self.created_at_unix < request.created_at_unix
            || self.expires_at_unix > request.expires_at_unix
        {
            return Err("acceptance lifetime escapes the request lifetime".into());
        }
        require_snapshot_bounds(self.record_limit, self.plaintext_byte_limit)?;
        decode_base64_exact::<64>("deviceSignature", &self.device_signature)?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        require_uuid("transferId", &self.transfer_id)?;
        require_account(&self.account)?;
        require_device_id("requestingDeviceId", self.requesting_device_id)?;
        require_device_id("respondingDeviceId", self.responding_device_id)?;
        if self.requesting_device_id == self.responding_device_id {
            return Err("history transfer requires two distinct devices".into());
        }
        if self.manifest_sequence == 0 {
            return Err("manifestSequence must be positive".into());
        }
        let request_hash = decode_hash("requestHash", &self.request_hash)?;
        let public_key =
            decode_base64_exact::<32>("ephemeralPublicKey", &self.ephemeral_public_key)?;
        require_window_shape(self.created_at_unix, self.expires_at_unix)?;
        require_snapshot_bounds(self.record_limit, self.plaintext_byte_limit)?;

        let mut out = Vec::with_capacity(224);
        out.extend_from_slice(ACCEPTANCE_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_string(&mut out, &self.transfer_id)?;
        push_string(&mut out, &self.account)?;
        out.extend_from_slice(&self.requesting_device_id.to_be_bytes());
        out.extend_from_slice(&self.responding_device_id.to_be_bytes());
        out.extend_from_slice(&self.manifest_sequence.to_be_bytes());
        out.extend_from_slice(&request_hash);
        out.extend_from_slice(&public_key);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        out.extend_from_slice(&self.record_limit.to_be_bytes());
        out.extend_from_slice(&self.plaintext_byte_limit.to_be_bytes());
        Ok(out)
    }

    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&decode_base64_exact::<64>(
            "deviceSignature",
            &self.device_signature,
        )?);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatHistoryTransferFrameV1 {
    pub version: u16,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub index: u32,
    pub final_frame: bool,
    pub plaintext_bytes: u32,
    /// Canonical padded base64 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Canonical padded base64 ciphertext including the 16-byte AEAD tag.
    pub ciphertext: String,
}

impl ChatHistoryTransferFrameV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
        require_uuid("transferId", &self.transfer_id)?;
        require_hash("transcriptHash", &self.transcript_hash)?;
        if self.index >= MAX_CHAT_HISTORY_TRANSFER_FRAMES {
            return Err("history transfer frame index exceeds the V1 limit".into());
        }
        if self.plaintext_bytes > MAX_CHAT_HISTORY_TRANSFER_FRAME_PLAINTEXT {
            return Err("history transfer frame plaintext exceeds the V1 limit".into());
        }
        decode_base64_exact::<24>("nonce", &self.nonce)?;
        let expected_ciphertext_bytes = self.plaintext_bytes as usize + 16;
        if self.ciphertext.len() != base64_encoded_len(expected_ciphertext_bytes) {
            return Err("history transfer ciphertext length does not match plaintextBytes".into());
        }
        let ciphertext = decode_base64("ciphertext", &self.ciphertext)?;
        if ciphertext.len() != expected_ciphertext_bytes {
            return Err("history transfer ciphertext length does not match plaintextBytes".into());
        }
        Ok(())
    }

    pub fn aad(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let transcript_hash = decode_hash("transcriptHash", &self.transcript_hash)?;
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(FRAME_AAD_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_string(&mut out, &self.transfer_id)?;
        out.extend_from_slice(&transcript_hash);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.push(u8::from(self.final_frame));
        out.extend_from_slice(&self.plaintext_bytes.to_be_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatHistoryTransferCompletionV1 {
    pub version: u16,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub destination_device_id: u32,
    pub frame_count: u32,
    pub record_count: u32,
    pub media_plaintext_bytes: u64,
    pub plaintext_digest: String,
    pub completed_at_unix: i64,
    pub device_signature: String,
}

impl ChatHistoryTransferCompletionV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        require_uuid("transferId", &self.transfer_id)?;
        let transcript_hash = decode_hash("transcriptHash", &self.transcript_hash)?;
        require_device_id("destinationDeviceId", self.destination_device_id)?;
        if self.frame_count == 0 || self.frame_count > MAX_CHAT_HISTORY_TRANSFER_FRAMES {
            return Err("completion frameCount is outside the V1 bounds".into());
        }
        if self.record_count > MAX_CHAT_HISTORY_TRANSFER_RECORDS {
            return Err("completion recordCount exceeds the V1 limit".into());
        }
        if self.media_plaintext_bytes > MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT {
            return Err("completion media bytes exceed the V1 limit".into());
        }
        let plaintext_digest = decode_hash("plaintextDigest", &self.plaintext_digest)?;

        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(COMPLETION_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_string(&mut out, &self.transfer_id)?;
        out.extend_from_slice(&transcript_hash);
        out.extend_from_slice(&self.destination_device_id.to_be_bytes());
        out.extend_from_slice(&self.frame_count.to_be_bytes());
        out.extend_from_slice(&self.record_count.to_be_bytes());
        out.extend_from_slice(&self.media_plaintext_bytes.to_be_bytes());
        out.extend_from_slice(&plaintext_digest);
        out.extend_from_slice(&self.completed_at_unix.to_be_bytes());
        Ok(out)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.signing_bytes()?;
        decode_base64_exact::<64>("deviceSignature", &self.device_signature)?;
        Ok(())
    }
}

pub fn chat_history_transfer_transcript_hash(
    request: &ChatHistoryTransferRequestV1,
    acceptance: &ChatHistoryTransferAcceptanceV1,
    now_unix: i64,
) -> Result<[u8; 32], String> {
    acceptance.validate(request, now_unix)?;
    let mut bytes = request.signing_bytes()?;
    bytes.extend_from_slice(&decode_base64_exact::<64>(
        "request deviceSignature",
        &request.device_signature,
    )?);
    bytes.extend_from_slice(&acceptance.signed_bytes()?);
    Ok(Sha256::digest(bytes).into())
}

fn require_version(version: u16) -> Result<(), String> {
    if version != CHAT_HISTORY_TRANSFER_VERSION {
        return Err(format!(
            "unsupported Chat history transfer version {version}"
        ));
    }
    Ok(())
}

fn require_uuid(field: &str, value: &str) -> Result<(), String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{field} must be a UUID"))?;
    if parsed.to_string() != value {
        return Err(format!("{field} must be a canonical lowercase UUID"));
    }
    Ok(())
}

fn require_account(value: &str) -> Result<(), String> {
    let address: AccountAddress = value
        .parse()
        .map_err(|_| "history transfer account is invalid".to_string())?;
    if address.canonical() != value {
        return Err("history transfer account must be canonical".into());
    }
    Ok(())
}

fn require_device_id(field: &str, value: u32) -> Result<(), String> {
    if !(1..=127).contains(&value) {
        return Err(format!("{field} must be between 1 and 127"));
    }
    Ok(())
}

fn require_window_shape(created: i64, expires: i64) -> Result<(), String> {
    let Some(lifetime) = expires.checked_sub(created) else {
        return Err("history transfer lifetime is outside the timestamp range".into());
    };
    if lifetime <= 0 || lifetime > CHAT_HISTORY_TRANSFER_TTL_SECONDS {
        return Err("history transfer lifetime must be positive and at most 15 minutes".into());
    }
    Ok(())
}

fn require_window(created: i64, expires: i64, now: i64) -> Result<(), String> {
    require_window_shape(created, expires)?;
    if created > now.saturating_add(5 * 60) {
        return Err("history transfer was created too far in the future".into());
    }
    if expires < now {
        return Err("history transfer has expired".into());
    }
    Ok(())
}

fn require_snapshot_bounds(records: u32, bytes: u64) -> Result<(), String> {
    if records == 0 || records > MAX_CHAT_HISTORY_TRANSFER_RECORDS {
        return Err("history transfer record limit is outside the V1 bounds".into());
    }
    if bytes == 0 || bytes > MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT {
        return Err("history transfer plaintext limit is outside the V1 bounds".into());
    }
    Ok(())
}

fn decode_base64(field: &str, value: &str) -> Result<Vec<u8>, String> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical base64"))?;
    if STANDARD.encode(&decoded) != value {
        return Err(format!("{field} must be canonical base64"));
    }
    Ok(decoded)
}

fn decode_base64_exact<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != base64_encoded_len(N) {
        return Err(format!("{field} must decode to exactly {N} bytes"));
    }
    decode_base64(field, value)?
        .try_into()
        .map_err(|_| format!("{field} must decode to exactly {N} bytes"))
}

const fn base64_encoded_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

fn require_hash(field: &str, value: &str) -> Result<(), String> {
    decode_hash(field, value).map(|_| ())
}

fn decode_hash(field: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be canonical lowercase SHA-256 hex"));
    }
    hex::decode(value)
        .map_err(|_| format!("{field} must be canonical lowercase SHA-256 hex"))?
        .try_into()
        .map_err(|_| format!("{field} must be canonical lowercase SHA-256 hex"))
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "canonical string is too long")?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(byte: u8, length: usize) -> String {
        STANDARD.encode(vec![byte; length])
    }

    fn request() -> ChatHistoryTransferRequestV1 {
        ChatHistoryTransferRequestV1 {
            version: 1,
            transfer_id: "11111111-1111-4111-8111-111111111111".into(),
            account: "alice@a.test".into(),
            requesting_device_id: 2,
            manifest_sequence: 4,
            ephemeral_public_key: b64(0x11, 32),
            request_nonce: b64(0x22, 32),
            created_at_unix: 1_000,
            expires_at_unix: 1_900,
            device_signature: b64(0x33, 64),
        }
    }

    fn acceptance(request: &ChatHistoryTransferRequestV1) -> ChatHistoryTransferAcceptanceV1 {
        ChatHistoryTransferAcceptanceV1 {
            version: 1,
            transfer_id: request.transfer_id.clone(),
            account: request.account.clone(),
            requesting_device_id: request.requesting_device_id,
            responding_device_id: 1,
            manifest_sequence: request.manifest_sequence,
            request_hash: hex::encode(request.signed_hash().unwrap()),
            ephemeral_public_key: b64(0x44, 32),
            created_at_unix: 1_001,
            expires_at_unix: 1_900,
            record_limit: 5_000,
            plaintext_byte_limit: 16 * 1024 * 1024,
            device_signature: b64(0x55, 64),
        }
    }

    #[test]
    fn request_and_acceptance_bind_both_exact_manifest_devices() {
        let request = request();
        let acceptance = acceptance(&request);
        request.validate(1_100).unwrap();
        acceptance.validate(&request, 1_100).unwrap();
        let first = chat_history_transfer_transcript_hash(&request, &acceptance, 1_100).unwrap();
        assert_eq!(
            hex::encode(first),
            "001f9eebf5fbecd7fe3c9601ff2e277b1fb5ea3f3fdccd7e4ae40a77fae204fe"
        );

        let mut substituted = acceptance.clone();
        substituted.responding_device_id = 3;
        let second = chat_history_transfer_transcript_hash(&request, &substituted, 1_100).unwrap();
        assert_ne!(first, second);

        let mut wrong_request = request.clone();
        wrong_request.request_nonce = b64(0x23, 32);
        assert!(acceptance.validate(&wrong_request, 1_100).is_err());
    }

    #[test]
    fn acceptance_cannot_expand_or_outlive_the_request() {
        let request = request();
        let mut outliving = acceptance(&request);
        outliving.expires_at_unix += 1;
        assert!(outliving.validate(&request, 1_100).is_err());

        let mut oversized = acceptance(&request);
        oversized.plaintext_byte_limit = MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT + 1;
        assert!(oversized.validate(&request, 1_100).is_err());
    }

    #[test]
    fn frame_aad_binds_index_finality_and_plaintext_length() {
        let frame = ChatHistoryTransferFrameV1 {
            version: 1,
            transfer_id: request().transfer_id,
            transcript_hash: "66".repeat(32),
            index: 7,
            final_frame: false,
            plaintext_bytes: 3,
            nonce: b64(0x77, 24),
            ciphertext: b64(0x88, 19),
        };
        frame.validate().unwrap();
        let aad = frame.aad().unwrap();

        let mut changed = frame.clone();
        changed.final_frame = true;
        assert_ne!(aad, changed.aad().unwrap());
        changed.plaintext_bytes = 4;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn rejects_noncanonical_and_expired_requests() {
        let mut noncanonical = request();
        noncanonical.transfer_id = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into();
        assert!(noncanonical.validate(1_100).is_err());

        assert!(request().validate(1_901).is_err());

        let mut overflowing = request();
        overflowing.created_at_unix = i64::MIN;
        overflowing.expires_at_unix = i64::MAX;
        assert!(overflowing.validate(0).is_err());
    }
}
