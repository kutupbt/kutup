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

use serde::{Deserialize, Serialize};

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
    /// libsignal message-version 4: PQXDH (X25519 + ML-KEM-1024 a.k.a. Kyber1024)
    /// handshake, Triple Ratchet (Double Ratchet + SPQR) messaging.
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
    pub envelopes: Vec<OutgoingEnvelope>,
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
    /// Sender address. Local phase: bare username. Once federation lands this becomes
    /// `user@domain` for remote senders (sealed sender is a research follow-up).
    pub sender: String,
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
}
