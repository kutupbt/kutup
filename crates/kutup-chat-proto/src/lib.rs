//! Wire types for the federated E2EE chat track ("ileti").
//!
//! Everything here is **data about ciphertext** — the server (local or federated) routes
//! these blobs without ever holding a decryption key. The actual cryptography lives in
//! the clients (`kutup-chat-core`, wrapping libsignal-protocol; see
//! `docs/research/11-federated-chat.md`).
//!
//! Conventions (matching the rest of the kutup API):
//! - JSON field names are camelCase.
//! - Binary payloads (keys, signatures, ciphertext) are base64 (STANDARD) strings.
//! - IDs the protocol layer cares about (`registrationId`, prekey ids) are `u32`, like
//!   libsignal's wire format.
//!
//! The normative contract is `docs/chat-protocol.md`; this crate is its Rust
//! encoding. Tags there ([IMPL]/[ADD]/[RSV]) map to comments below.

use serde::{Deserialize, Serialize};

pub mod content;
pub use content::{ChatContent, TextBody};

/// Registry of encryption suites — the algorithm-agility mechanism.
///
/// A suite pins the *whole* cryptographic construction: key-agreement, ratchet, KEM, and
/// wire format. Capability is advertised by publishing prekey bundles for a suite (signed
/// by the device identity key); enforcement is client policy ("require PQ"), never an
/// in-band negotiation that a middleman could bid down. Per the locked decision in
/// `docs/research/11-federated-chat.md` §4.2 there is exactly one suite at launch and it
/// is post-quantum; a future suite is a new registry entry, not a toggle on this one.
/// On the wire a suite is its registry number (like a TLS ciphersuite code point), so
/// non-Rust implementations never parse Rust variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum SuiteId {
    /// libsignal message-version 4. **PQXDH handshake:** X25519 + **ML-KEM-1024**.
    /// **Triple Ratchet messaging** (Double Ratchet + SPQR): **ML-KEM-768** — note the
    /// ongoing ratchet's KEM is 768, not 1024; 1024 is the handshake parameter only.
    PqxdhTripleRatchetV1 = 1,
}

impl SuiteId {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::PqxdhTripleRatchetV1),
            _ => None,
        }
    }
}

impl From<SuiteId> for u16 {
    fn from(s: SuiteId) -> u16 {
        s.as_u16()
    }
}

impl TryFrom<u16> for SuiteId {
    type Error = String;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        SuiteId::from_u16(v).ok_or_else(|| format!("unknown encryption suite {v}"))
    }
}

/// The libsignal ciphertext kind carried by an envelope. Mirrors
/// `CiphertextMessageType` for the two kinds a 1:1 session produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum EnvelopeType {
    /// `PreKeySignalMessage` — session-establishing (carries the PQXDH initiator
    /// material; large: ~1.8 KB with Kyber1024).
    PreKey,
    /// `SignalMessage` — steady-state Triple Ratchet message.
    Message,
}

/// An EC prekey the client publishes (signed prekey or one-time prekey).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct EcPreKey {
    pub key_id: u32,
    /// base64 serialized X25519 public key (libsignal wire form, incl. type byte).
    pub public_key: String,
    /// base64 XEd25519 signature by the device identity key. `None` for one-time EC
    /// prekeys (libsignal does not sign those); required for signed prekeys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A Kyber/ML-KEM prekey the client publishes (always signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KemPreKey {
    pub key_id: u32,
    /// base64 serialized KEM public key (libsignal wire form: type byte + key —
    /// the type byte is how a bundle says Kyber1024 vs a future KEM).
    pub public_key: String,
    /// base64 XEd25519 signature by the device identity key.
    pub signature: String,
}

/// `POST /api/chat/device` — register (or re-register) this client as a chat device.
///
/// Re-registration with fresh keys replaces the device's directory entry and mailbox
/// (the standard Signal semantics for a reinstalled client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterChatDeviceRequest {
    pub suite: SuiteId,
    /// libsignal registration id (random u32 < 16384, generated at install time).
    pub registration_id: u32,
    /// base64 serialized public `IdentityKey`.
    pub identity_key: String,
    /// The current signed EC prekey (signature required).
    pub signed_pre_key: EcPreKey,
    /// The last-resort Kyber prekey — served when the one-time pool is empty so
    /// session establishment never downgrades to non-PQ.
    pub last_resort_kyber_pre_key: KemPreKey,
    /// Initial one-time EC prekey pool (may be empty; bundles then omit the EC one-time).
    #[serde(default)]
    pub one_time_pre_keys: Vec<EcPreKey>,
    /// Initial one-time Kyber prekey pool.
    #[serde(default)]
    pub one_time_kyber_pre_keys: Vec<KemPreKey>,
    /// Human label shown in device management ("Firefox on laptop").
    #[serde(default)]
    pub name: String,
    /// [RSV] The device identity key signed by the account **self-authority
    /// key** (§5.3), binding this device to the account so a malicious server
    /// can't inject one. Absent until device-manifest support ships; MUST be
    /// accepted when present. See `docs/chat-protocol.md` §5.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<String>,
}

/// One entry in a signed [`DeviceManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestDevice {
    pub device_id: u32,
    pub identity_key: String,
    pub registration_id: u32,
}

/// The device-list-authenticity primitive (§5.3): a user's current chat
/// device set, signed by an account self-authority key the server never sees.
/// Peers verify `signature` and refuse to encrypt to a `deviceId` not in the
/// signed set — closing the malicious-homeserver device-injection vector
/// (`docs/research/13-…` §4.3). A future key-transparency log can wrap this
/// signed leaf without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeviceManifest {
    /// Monotonic; a higher version supersedes a lower one.
    pub version: u64,
    /// SHA-256 of the preceding manifest's canonical signed bytes and signature.
    /// Absent only at version 1; binds updates into a rollback-evident chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    pub devices: Vec<ManifestDevice>,
    pub issued_at: String,
    /// Stable identifier for the authority key (lowercase SHA-256 of its raw
    /// public-key bytes in v1). Allows additive authority rotation later.
    pub authority_key_id: String,
    /// base64 account self-signing PUBLIC key.
    pub self_authority_key: String,
    /// base64 signature over the canonical `version‖devices‖issuedAt`.
    pub signature: String,
}

impl DeviceManifest {
    /// Deterministic, domain-separated binary encoding signed by every client.
    /// Devices MUST be strictly ordered by `deviceId`; accepting multiple
    /// encodings for one manifest would make cross-client signatures unsafe.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-chat-device-manifest-v1\0";
        let mut out = Vec::with_capacity(256 + self.devices.len() * 96);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_optional(&mut out, self.previous_hash.as_deref())?;
        push_string(&mut out, &self.issued_at)?;
        push_string(&mut out, &self.authority_key_id)?;
        push_string(&mut out, &self.self_authority_key)?;
        let count = u32::try_from(self.devices.len()).map_err(|_| "too many devices")?;
        out.extend_from_slice(&count.to_be_bytes());
        let mut prior = None;
        for device in &self.devices {
            if prior.is_some_and(|id| device.device_id <= id) {
                return Err("manifest devices must be strictly ordered by deviceId".into());
            }
            prior = Some(device.device_id);
            out.extend_from_slice(&device.device_id.to_be_bytes());
            out.extend_from_slice(&device.registration_id.to_be_bytes());
            push_string(&mut out, &device.identity_key)?;
        }
        Ok(out)
    }

    /// Hash used by the next manifest's `previousHash` link. The signature is
    /// included so the chain commits to the exact authenticated record.
    pub fn manifest_hash(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes()?);
        hasher.update(self.signature.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verify the account authority binding, chain-shape invariants, canonical
    /// ordering, and Ed25519 signature. Version continuity against a previously
    /// observed manifest is a stateful client/server responsibility.
    pub fn verify(&self) -> Result<(), String> {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, VerifyingKey};
        use sha2::{Digest, Sha256};

        if self.version == 0 {
            return Err("manifest version must be positive".into());
        }
        if self.version == 1 && self.previous_hash.is_some() {
            return Err("manifest version 1 cannot have previousHash".into());
        }
        if self.version > 1 && self.previous_hash.is_none() {
            return Err("manifest update requires previousHash".into());
        }
        if let Some(previous_hash) = &self.previous_hash {
            let decoded = hex::decode(previous_hash)
                .map_err(|_| "previousHash must be lowercase SHA-256 hex".to_string())?;
            if decoded.len() != 32 || hex::encode(decoded) != *previous_hash {
                return Err("previousHash must be lowercase SHA-256 hex".into());
            }
        }

        let public = base64::engine::general_purpose::STANDARD
            .decode(&self.self_authority_key)
            .map_err(|_| "selfAuthorityKey must be base64".to_string())?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| "selfAuthorityKey must be 32 bytes".to_string())?;
        let expected_id = hex::encode(Sha256::digest(public));
        if self.authority_key_id != expected_id {
            return Err("authorityKeyId does not match selfAuthorityKey".into());
        }

        let signature = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|_| "manifest signature must be base64".to_string())?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| "manifest signature must be 64 bytes".to_string())?;
        let verifying = VerifyingKey::from_bytes(&public)
            .map_err(|_| "selfAuthorityKey is not a valid Ed25519 key".to_string())?;
        verifying
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| "manifest signature is invalid".to_string())
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len = u32::try_from(value.len()).map_err(|_| "manifest string is too long")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_optional(out: &mut Vec<u8>, value: Option<&str>) -> Result<(), String> {
    match value {
        Some(value) => {
            out.push(1);
            push_string(out, value)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterChatDeviceResponse {
    /// Server-assigned device id, 1..=127 per user (1 = first/primary device).
    pub device_id: u32,
}

/// `PUT /api/chat/keys` — rotate the signed prekey and/or replenish one-time pools.
/// Only the fields present are changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", default)]
pub struct ReplenishKeysRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_pre_key: Option<EcPreKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_resort_kyber_pre_key: Option<KemPreKey>,
    pub one_time_pre_keys: Vec<EcPreKey>,
    pub one_time_kyber_pre_keys: Vec<KemPreKey>,
}

/// `GET /api/chat/keys/count` — clients replenish below a threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PreKeyCountResponse {
    pub one_time_pre_keys: u64,
    pub one_time_kyber_pre_keys: u64,
}

/// One device's prekey bundle, as served by `GET /api/chat/users/{username}/keys`.
/// Field-for-field what libsignal's `PreKeyBundle::new` consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeyBundle {
    pub device_id: u32,
    pub registration_id: u32,
    pub suite: SuiteId,
    pub identity_key: String,
    pub signed_pre_key: EcPreKey,
    /// A one-time Kyber prekey when the pool has one (consumed by this fetch),
    /// otherwise the last-resort Kyber prekey. Never absent: PQ is not optional.
    pub kyber_pre_key: KemPreKey,
    /// Consumed from the one-time EC pool; absent when the pool is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_pre_key: Option<EcPreKey>,
}

/// `GET /api/chat/users/{username}/keys` — bundles for every active device.
/// A 1:1 conversation encrypts to all of the peer's devices (and the sender's other
/// devices, for sync — the client fetches its own bundle list too).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserPreKeyBundlesResponse {
    pub username: String,
    pub devices: Vec<DevicePreKeyBundle>,
    /// The signed device manifest (§5.3). A verifying client checks each
    /// returned bundle against it before establishing a session. Absence is
    /// allowed only when the server advertises `manifests: false` and the
    /// client explicitly enables development TOFU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<DeviceManifest>,
}

/// One per-device ciphertext inside a send request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OutgoingEnvelope {
    /// Which of the recipient's devices this ciphertext is for.
    pub device_id: u32,
    /// The registration id the sender believes that device has. The server rejects the
    /// whole send with `staleDevices` on mismatch — this is how clients learn a device
    /// was reinstalled and must re-establish its session.
    pub registration_id: u32,
    pub envelope_type: EnvelopeType,
    pub suite: SuiteId,
    /// base64 serialized `PreKeySignalMessage` / `SignalMessage`. Opaque to the server.
    pub content: String,
}

/// `POST /api/chat/users/{username}/messages` — deliver one logical message as
/// per-device ciphertexts. The set of `deviceId`s must exactly match the recipient's
/// active devices or the server rejects with [`DeviceListMismatch`] (Signal's
/// missing/stale/extra devices contract) so no device can be silently skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SendMessagesRequest {
    /// The sender's chat device id (must be a registered chat device of the
    /// authenticated user — recipients address replies to it).
    pub sender_device_id: u32,
    /// [ADD] Client-generated idempotency key (UUID). The server dedupes per
    /// `(senderUser, senderDevice, sendId)` within a retention window and
    /// returns the original result on a repeat — so a durable outbox can retry
    /// blindly (a send can succeed while its response is lost, the mobile
    /// norm). See `docs/chat-protocol.md` §7.1.
    pub send_id: String,
    pub envelopes: Vec<OutgoingEnvelope>,
    /// [RSV] Sealed-sender delivery token (§11). When present the server MAY
    /// accept the send without sender auth, gating delivery on this proof
    /// instead. Absent in v1; MUST be accepted when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

/// 409 body when a send's device set is out of date.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceListMismatch {
    /// Active recipient devices the request did not include.
    pub missing_devices: Vec<u32>,
    /// Devices whose `registrationId` didn't match (reinstalled clients).
    pub stale_devices: Vec<u32>,
    /// Device ids in the request that aren't active devices of the recipient.
    pub extra_devices: Vec<u32>,
}

/// A stored envelope, as delivered to its recipient device (REST drain or WS push).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeliveredEnvelope {
    /// Server-assigned mailbox id (UUID) — the ack handle.
    pub id: String,
    /// [ADD] Monotonic order key: the paging cursor (`GET …/messages?after=`)
    /// and the client-side dedup key (tolerates a WS envelope and its
    /// REST-drained twin). Server-assigned; ordered `(cursor)`.
    pub cursor: u64,
    /// [ADD→RSV] Sender address, `Option` from v1 so sealed sender (which
    /// removes it) is not a breaking change. Local phase: bare username;
    /// `user@domain` for remote senders once federation lands; `None` under
    /// sealed sender. See `docs/chat-protocol.md` §8.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    pub sender_device_id: u32,
    pub envelope_type: EnvelopeType,
    pub suite: SuiteId,
    /// base64 ciphertext, exactly as sent.
    pub content: String,
    /// Server receive time, RFC 3339 (the server clock, not the sender's).
    pub server_timestamp: String,
}

/// `GET /api/chat/messages` — a drain page. `more` tells the client to keep paging
/// before it trusts the WS stream to be the only source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MailboxPage {
    pub envelopes: Vec<DeliveredEnvelope>,
    pub more: bool,
}

/// `POST /api/chat/messages/ack` — delete processed envelopes (batch).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AckRequest {
    pub ids: Vec<String>,
}

/// Messages the server pushes down the chat WebSocket (JSON text frames).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ChatWsServerMessage {
    /// A newly arrived envelope. The client still acks over REST; WS delivery is a
    /// latency optimization, the mailbox is the source of truth.
    Envelope { envelope: DeliveredEnvelope },
    /// Sent after connect once the pre-existing mailbox backlog should be drained via
    /// REST (avoids replaying a large backlog through the socket).
    DrainMailbox,
}

/// [ADD] The `chat` block of `GET /api/auth/settings` — how a client
/// feature-gates chat per server (and never shows chat UI on a server without
/// it). See `docs/chat-protocol.md` §10.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChatCapabilities {
    pub enabled: bool,
    /// The `docs/chat-protocol.md` protocol version this server speaks.
    pub protocol_version: u16,
    /// Suites the server will route (it doesn't decrypt; this bounds bundles).
    pub suites: Vec<u16>,
    /// Max `content` bytes per envelope, enforced on send (mailbox-abuse gate
    /// and the budget for attachment-pointer payloads).
    pub max_content_bytes: u32,
    /// [RSV] flips true in the federation phase.
    #[serde(default)]
    pub federation: bool,
    /// Signed device manifests are available and included with prekey bundles.
    #[serde(default)]
    pub manifests: bool,
    /// [RSV] flips true when sealed sender ships.
    #[serde(default)]
    pub sealed_sender: bool,
}

impl Default for ChatCapabilities {
    /// The phase-2b server's advertised capabilities.
    fn default() -> Self {
        ChatCapabilities {
            enabled: true,
            protocol_version: 1,
            suites: vec![SuiteId::PqxdhTripleRatchetV1.as_u16()],
            max_content_bytes: 65536,
            federation: false,
            manifests: true,
            sealed_sender: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_id_round_trips() {
        assert_eq!(
            SuiteId::from_u16(SuiteId::PqxdhTripleRatchetV1.as_u16()),
            Some(SuiteId::PqxdhTripleRatchetV1)
        );
        assert_eq!(SuiteId::from_u16(0), None);
        assert_eq!(SuiteId::from_u16(2), None);
    }

    #[test]
    fn envelope_json_shape_is_camel_case_and_stable() {
        let env = OutgoingEnvelope {
            device_id: 1,
            registration_id: 42,
            envelope_type: EnvelopeType::PreKey,
            suite: SuiteId::PqxdhTripleRatchetV1,
            content: "AAEC".into(),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(
            json,
            r#"{"deviceId":1,"registrationId":42,"envelopeType":"preKey","suite":1,"content":"AAEC"}"#
        );
        let back: OutgoingEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.registration_id, 42);
    }

    #[test]
    fn send_request_carries_send_id_and_omits_absent_access_token() {
        let req = SendMessagesRequest {
            sender_device_id: 1,
            send_id: "11111111-1111-4111-8111-111111111111".into(),
            envelopes: vec![],
            access_token: None,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["sendId"], "11111111-1111-4111-8111-111111111111");
        assert!(
            v.get("accessToken").is_none(),
            "reserved field omitted when None"
        );
        // A v-next server populating accessToken round-trips through a v1 client.
        let with_token = r#"{"senderDeviceId":1,"sendId":"x","envelopes":[],"accessToken":"tok"}"#;
        let back: SendMessagesRequest = serde_json::from_str(with_token).unwrap();
        assert_eq!(back.access_token.as_deref(), Some("tok"));
    }

    #[test]
    fn delivered_envelope_has_cursor_and_optional_sender() {
        let src = r#"{"id":"m1","cursor":42,"sender":"alice","senderDeviceId":1,"envelopeType":"message","suite":1,"content":"AA","serverTimestamp":"2026-07-13T10:00:00Z"}"#;
        let e: DeliveredEnvelope = serde_json::from_str(src).unwrap();
        assert_eq!(e.cursor, 42);
        assert_eq!(e.sender.as_deref(), Some("alice"));
        // Sealed-sender / future: absent sender still deserializes.
        let sealed = r#"{"id":"m2","cursor":43,"senderDeviceId":1,"envelopeType":"message","suite":1,"content":"AA","serverTimestamp":"2026-07-13T10:00:00Z"}"#;
        let e2: DeliveredEnvelope = serde_json::from_str(sealed).unwrap();
        assert_eq!(e2.sender, None);
    }

    #[test]
    fn capabilities_default_shape() {
        let v: serde_json::Value = serde_json::to_value(ChatCapabilities::default()).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["protocolVersion"], 1);
        assert_eq!(v["suites"], serde_json::json!([1]));
        assert_eq!(v["maxContentBytes"], 65536);
        assert_eq!(v["sealedSender"], false);
        assert_eq!(v["manifests"], true);
    }

    #[test]
    fn manifest_signing_bytes_are_canonical_and_order_sensitive() {
        let manifest = DeviceManifest {
            version: 1,
            previous_hash: None,
            devices: vec![
                ManifestDevice {
                    device_id: 1,
                    identity_key: "identity-a".into(),
                    registration_id: 10,
                },
                ManifestDevice {
                    device_id: 2,
                    identity_key: "identity-b".into(),
                    registration_id: 20,
                },
            ],
            issued_at: "2026-07-15T12:00:00Z".into(),
            authority_key_id: "authority-1".into(),
            self_authority_key: "public-key".into(),
            signature: "signature".into(),
        };
        let bytes = manifest.signing_bytes().unwrap();
        assert!(bytes.starts_with(b"kutup-chat-device-manifest-v1\0"));
        assert_eq!(manifest.signing_bytes().unwrap(), bytes);
        assert_eq!(manifest.manifest_hash().unwrap().len(), 64);

        let mut unordered = manifest.clone();
        unordered.devices.swap(0, 1);
        assert!(unordered.signing_bytes().is_err());
    }

    #[test]
    fn manifest_verification_rejects_bad_chain_shape_before_crypto() {
        let manifest = DeviceManifest {
            version: 0,
            previous_hash: None,
            devices: vec![],
            issued_at: "2026-07-15T12:00:00Z".into(),
            authority_key_id: String::new(),
            self_authority_key: String::new(),
            signature: String::new(),
        };
        assert_eq!(
            manifest.verify().unwrap_err(),
            "manifest version must be positive"
        );
    }
}
