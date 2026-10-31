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

mod account_identity;
mod backup;
mod calls;
pub mod contact_list;
pub mod content;
mod extras;
pub mod federation;
pub mod group;
pub mod group_route;
pub mod group_send;
mod identity;
mod locations;
mod media;
mod polls;
mod profile;
mod sealed_sender;
mod security_policy;

pub use account_identity::{
    decode_device_credential, decode_frame_key, decode_identity_key, decode_link_token,
    decode_provisioning_address, device_session_hash, format_device_header, identity_binding_bytes,
    parse_device_header, repeated_use_keys_digest, reregistration_device_id, AccountDeviceV1,
    AccountIdentityBody, AccountIdentityDistributionRequest, AccountManifestDeviceV3,
    AccountManifestHistoryPageV3, AccountManifestPublicationV3, AccountManifestV3,
    AccountPreKeyBundlesResponse, ChatDeviceKeysV3, ChatKeysCheckRequest, ChatLinkTokenResponse,
    ChatProvisionV1, DeviceKind, DevicePreKeyBundleV2, DeviceRegistrationV1,
    DistributedDeviceKeysV1, DistributionError, OwnManifestPinV1, ProvisionEnvelopeV1,
    ProvisioningLinkCodeV1, ProvisioningRelayRequest, ProvisioningSocketMessage,
    RegisterChatDeviceRequestV2, RegisterDeviceRequestV1, RegisterDeviceResponseV1,
    ACCOUNT_MANIFEST_V3_VERSION, DEVICE_CREDENTIAL_LEN, DEVICE_HEADER, IDENTITY_BINDING_LEN,
    LINK_TOKEN_LEN, LINK_URI_PREFIX, MAX_ACCOUNT_MANIFEST_DEVICES, MAX_DEVICE_NAME_CHARS,
    MAX_PREKEY_RECORD_BYTES, MAX_PROVISION_BODY_BYTES, PROVISIONING_ADDRESS_LEN,
    PROVISIONING_VERSION, REREGISTRATION_DEVICE_ID,
};
pub use backup::{
    chat_backup_media_reference_set_digest, AppendChatBackupSegmentRequestV1,
    ChatBackupBasePlaintextV1, ChatBackupBaseReceiptV1, ChatBackupCapabilitiesV1,
    ChatBackupDeviceHeadV1, ChatBackupDisplayRecordV1, ChatBackupManifestCommitReceiptV1,
    ChatBackupManifestV1, ChatBackupMediaReceiptV1, ChatBackupMediaReconciliationReceiptV1,
    ChatBackupMediaReferenceV1, ChatBackupSegmentPageV1, ChatBackupSegmentPlaintextV1,
    ChatBackupSegmentReceiptV1, ChatBackupSignerAuthorizationV1, ChatBackupStatusV1,
    ChatBackupStorageUsageV1, ChatBackupWireSegmentV1, CommitChatBackupManifestRequestV1,
    CopyChatBackupMediaRequestV1, ProvisionChatBackupRequestV1, ReconcileChatBackupMediaRequestV1,
    StageChatBackupBaseRequestV1, UploadChatBackupMediaRequestV1, CHAT_BACKUP_PROTOCOL_VERSION,
    CHAT_DELIVERY_MEDIA_RETENTION_DAYS, MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES,
    MAX_CHAT_BACKUP_MEDIA_REFERENCES_PER_PAGE, MAX_CHAT_BACKUP_PAGE_SEGMENTS,
    MAX_CHAT_BACKUP_SEGMENT_CIPHERTEXT_BYTES,
};
pub use calls::{
    validate_room_id, CallLogBody, CallMediaV1, CallOutcomeV1, CallSignalKindV1, CallSignalV1,
    GroupCallBody, GroupCallEventV1, HangupReasonV1, IceCandidateV1, MAX_CALL_ICE_CANDIDATES,
    MAX_CALL_SDP_BYTES,
};
pub use content::{
    ChatContent, ContactControlBody, ContactState, ConversationStateBody, DeleteForMeBody,
    DisappearingExpiryStartBody, DisappearingTimerBody, GroupRemovalBody, GroupUpdateBody,
    GroupUpdateChange, MessageMutationBody, MessageMutationOperation, ReactionBody,
    ReadPositionBody, ReceiptBody, ReceiptState, SentTranscriptBody, StickerRemovedBody,
    StickerSavedBody, TextBody, TypingBody, ViewOnceOpenedBody, MAX_SAFE_CLOCK_MS,
};
pub use content::{
    PeerRenamedBody, ResendBody, SessionControlAction, SessionControlBody, UndecryptableBody,
    MAX_SESSION_CONTROL_SEND_IDS,
};
pub use extras::{
    LinkPreviewImageV1, LinkPreviewV1, MentionV1, StickerMarkV1, VisibleMessageExtrasV1,
};
pub use federation::{
    FederatedChatTransaction, FederationDeliveryError, FederationDeliveryRejection,
    FederationDeliveryResponse, FEDERATED_CHAT_FEATURE,
};
#[cfg(feature = "openapi")]
pub use identity::AccountRefSchema;
pub use identity::{AccountAddress, AddressError, ConversationId};
/// A person across servers: their server and permanent account id
/// (docs/plans/account-ids.md).
pub use kutup_crypto::account_ref::AccountRef;
pub use locations::{
    LiveLocationBody, LiveLocationStopBody, LocationBody, MAX_LIVE_LOCATION_MS,
    MAX_LOCATION_LABEL_CHARS,
};
pub use media::{
    ChatAttachmentDescriptorV1, ChatAttachmentLedgerDiffPageV1, ChatAttachmentLedgerEntryV1,
    ChatAttachmentLedgerPutReceiptV1, ChatAttachmentLedgerPutRequestV1,
    ChatAttachmentLedgerStateV1, ChatAttachmentLedgerWireEntityV1, ChatMediaCapabilitiesV1,
    ChatMediaClassV1, ChatMediaConversationKindV1, ChatMediaDeliveryOfferV1,
    ChatMediaDeliveryStatusV1, ChatMediaOfferResponseV1, ChatMediaPreviewV1,
    FederatedChatMediaTransactionV1, CHAT_ATTACHMENT_LEDGER_ENTRY_VERSION, CHAT_ATTACHMENT_VERSION,
    CHAT_MEDIA_PROTOCOL_VERSION, MAX_CHAT_ATTACHMENT_LEDGER_PAGE_ENTITIES,
    MAX_CHAT_MEDIA_CAPTION_BYTES, MAX_CHAT_MEDIA_DISPLAY_NAME_BYTES, MAX_CHAT_MEDIA_PREVIEW_BYTES,
};
pub use polls::{
    PollBody, PollTerminateBody, PollVoteBody, MAX_POLL_OPTIONS, MAX_POLL_OPTION_CHARS,
    MAX_POLL_QUESTION_CHARS, MIN_POLL_OPTIONS,
};
pub use profile::{
    decode_profile_envelope, encode_profile_envelope_header, ChatProfileResponse,
    DecodedProfileEnvelopeV1, OwnChatProfileResponse, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, ProfileSuiteId, PutChatProfileRequest, ACCOUNT_PROFILE_SOURCE,
    MAX_PROFILE_ABOUT_CHARS, MAX_PROFILE_AVATAR_BYTES, PROFILE_ABOUT_PADDED_LENGTHS,
    PROFILE_NAME_PADDED_LENGTHS,
};
pub use sealed_sender::{
    capability_hash, constant_time_capability_hash_eq, derive_delivery_capability,
    AnonymousPreKeyRequestV1, FederatedSealedBatchItemV1, FederatedSealedBatchResponseV1,
    FederatedSealedBatchV1, FederatedSealedTransactionV1, SealedBatchOutcomeV1,
    SealedBatchRecipientV1, SealedBatchResponseV1, SealedBatchResultV1, SealedBatchSubmissionV1,
    SealedDeliveryResponseV1, SealedMessageSubmissionV1, SealedMultiDevicesV1,
    SealedMultiResponseV1, SealedMultiStaleV1, SealedMultiSubmissionV1, SealedOutgoingEnvelopeV1,
    SenderCertificateResponseV1, DELIVERY_CAPABILITY_CONTEXT, MAX_SEALED_BATCH_BYTES,
    MAX_SEALED_BATCH_ITEMS, MAX_SEALED_MULTI_PAYLOAD_BYTES, MAX_SEALED_MULTI_RECIPIENTS,
    SEALED_FEDERATION_VERSION,
};
pub use security_policy::{
    SealedSenderRootV1, SealedSenderServerCertificateV1, SealedSenderServicePolicyV1,
    SealedSenderSuiteId,
};

/// Registry of encryption suites — the algorithm-agility mechanism.
///
/// A suite pins the *whole* cryptographic construction: key-agreement, ratchet, KEM, and
/// wire format. Server availability is advertised separately; authenticated per-device
/// suite capabilities will be added to the signed manifest before there is a second suite.
/// Until then there is no suite negotiation: the one launch suite is mandatory and
/// post-quantum. A future suite is a new registry entry, not a toggle on this one.
/// On the wire a suite is its registry number (like a TLS ciphersuite code point), so
/// non-Rust implementations never parse Rust variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum DirectChatSuiteId {
    /// libsignal message-version 4. **PQXDH handshake:** X25519 + **ML-KEM-1024**.
    /// **Triple Ratchet messaging** (Double Ratchet + SPQR): **ML-KEM-768** — note the
    /// ongoing ratchet's KEM is 768, not 1024; 1024 is the handshake parameter only.
    PqxdhTripleRatchetV1 = 1,
}

impl DirectChatSuiteId {
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

impl From<DirectChatSuiteId> for u16 {
    fn from(s: DirectChatSuiteId) -> u16 {
        s.as_u16()
    }
}

impl TryFrom<u16> for DirectChatSuiteId {
    type Error = String;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        DirectChatSuiteId::from_u16(v).ok_or_else(|| format!("unknown direct chat suite {v}"))
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

/// Closed construction for the account-scoped public keys carried by the
/// manifest. It is intentionally separate from Drive object/envelope suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum AccountIdentitySuiteId {
    /// An X25519 Drive key, from before X-Wing: readable, never sealed to,
    /// until its account upgrades ([`legacy_suite1_for_upgrade`]).
    X25519Ed25519V1 = 1,
    /// An X-Wing Drive key (docs/plans/pq-shares.md).
    XWingEd25519V2 = 2,
}

impl AccountIdentitySuiteId {
    /// The Drive HPKE public key's length in this suite.
    pub const fn hpke_public_key_len(self) -> usize {
        match self {
            Self::X25519Ed25519V1 => legacy_suite1_for_upgrade::HPKE_PUBLIC_KEY_LEN,
            Self::XWingEd25519V2 => 1216,
        }
    }

    /// Whether anything may be sealed to this suite's Drive key: X-Wing only.
    /// A suite-1 account's lookups say `keysPendingUpgrade` instead.
    pub const fn sealable(self) -> bool {
        matches!(self, Self::XWingEd25519V2)
    }
}

/// What stays of identity suite 1 (X25519 Drive keys) while accounts upgrade
/// to suite 2 at their next sign-in (docs/plans/pq-shares.md): its manifests
/// stay readable, so Chat keeps working with an account that hasn't signed in
/// since, and so a client can see the suite rise. Nothing is sealed to a
/// suite-1 key. The enforcing change, once every account is counted as
/// upgraded, deletes this module and the suite.
pub mod legacy_suite1_for_upgrade {
    /// A suite-1 Drive key: raw X25519.
    pub const HPKE_PUBLIC_KEY_LEN: usize = 32;
}

impl From<AccountIdentitySuiteId> for u16 {
    fn from(value: AccountIdentitySuiteId) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for AccountIdentitySuiteId {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::X25519Ed25519V1),
            2 => Ok(Self::XWingEd25519V2),
            _ => Err(format!("unknown account identity suite {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestDriveKeysV1 {
    pub suite: AccountIdentitySuiteId,
    /// Canonical padded base64 Drive HPKE public key: X-Wing's 1216 bytes in
    /// suite 2 (suite 1's raw X25519 key until its account upgrades).
    pub hpke_public_key: String,
    /// Canonical padded base64 raw Ed25519 public key used only to authenticate
    /// named Drive share envelopes.
    pub share_signing_public_key: String,
}

fn decode_lower_hex_32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{name} must be lowercase SHA-256 hex"))?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

fn decode_canonical_base64_exact(
    name: &str,
    value: &str,
    expected: usize,
) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if bytes.len() != expected || base64::engine::general_purpose::STANDARD.encode(&bytes) != value
    {
        return Err(format!(
            "{name} must be canonical base64 for {expected} bytes"
        ));
    }
    Ok(bytes)
}

pub const MAX_ACCOUNT_MANIFEST_HISTORY_PAGE: usize = 64;

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

/// `PATCH /api/chat/device/{deviceId}` — change the human-readable label for
/// one of the caller's registered Chat installations. This does not alter the
/// device id, keys, sessions, or signed account manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenameChatDeviceRequest {
    pub name: String,
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

/// `POST /api/device-ticket` — a single-use WebSocket credential for one
/// device of the account (browsers can't set headers on a socket): the Chat
/// socket and the collab sockets take it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeviceTicketResponse {
    pub ticket: String,
    pub expires_at: String,
}

/// One device's bundle with its account's identity key filled in: what a
/// client builds a session from once it verified an
/// [`AccountPreKeyBundlesResponse`] (which carries the identity once).
/// Field-for-field what libsignal's `PreKeyBundle::new` consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeyBundle {
    pub device_id: u32,
    pub registration_id: u32,
    pub suite: DirectChatSuiteId,
    pub identity_key: String,
    pub signed_pre_key: EcPreKey,
    /// A one-time Kyber prekey when the pool has one (consumed by this fetch),
    /// otherwise the last-resort Kyber prekey. Never absent: PQ is not optional.
    pub kyber_pre_key: KemPreKey,
    /// Consumed from the one-time EC pool; absent when the pool is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_pre_key: Option<EcPreKey>,
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
    pub suite: DirectChatSuiteId,
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The sender's account (server and account id), never a name; `None`
    /// under sealed sender. See `docs/chat-protocol.md` §8.1 and
    /// docs/plans/account-ids.md.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<AccountRefSchema>))]
    pub sender: Option<AccountRef>,
    /// True when `content` is a serialized libsignal unidentified-sender
    /// message. Such rows intentionally carry no sender metadata.
    #[serde(default)]
    pub sealed_sender: bool,
    pub sender_device_id: u32,
    pub envelope_type: EnvelopeType,
    pub suite: DirectChatSuiteId,
    /// base64 ciphertext, exactly as sent.
    pub content: String,
    /// Server receive time, RFC 3339 (the server clock, not the sender's).
    pub server_timestamp: String,
    /// The sender's logical send id, as the server received it. Not
    /// authenticated: it only lets a device that cannot decrypt this
    /// envelope name the message when asking its sender for it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_id: Option<String>,
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
    /// This account's device list changed: a device was registered or
    /// removed, or a new signed manifest was published. It says nothing
    /// more; each device fetches and verifies the list itself.
    DevicesChanged,
    /// The answer to a client [`ChatWsClientMessage::Ping`].
    Pong,
}

/// Messages a client may send up the chat WebSocket (JSON text frames).
/// Everything else a client does goes over REST.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ChatWsClientMessage {
    /// A liveness probe: the server answers [`ChatWsServerMessage::Pong`].
    /// Browsers cannot send WebSocket ping frames, and a connection that died
    /// without a close (sleep, a network change) is otherwise noticed only
    /// when the operating system gives up on it.
    Ping,
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
    pub suites: Vec<DirectChatSuiteId>,
    /// Max `content` bytes per envelope, enforced on send (mailbox-abuse gate
    /// and the budget for attachment-pointer payloads).
    pub max_content_bytes: u32,
    /// Unacknowledged mailbox ciphertext retention (`0` means server-disabled).
    pub mailbox_retention_days: u32,
    /// Inactive chat-device expiry (`0` means server-disabled).
    pub device_expiry_days: u32,
    /// Server-configured simultaneously active devices per account. V1 has a
    /// protocol hard cap of 10.
    pub maximum_active_devices: u32,
    /// Stable canonical DNS suffix in `username@server`. Present whenever Chat
    /// is enabled; federation controls whether other suffixes are reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// [RSV] flips true in the federation phase.
    #[serde(default)]
    pub federation: bool,
    /// Signed device manifests are available and included with prekey bundles.
    #[serde(default)]
    pub manifests: bool,
    /// Signal-style opaque encrypted profiles and profile-key capabilities.
    #[serde(default)]
    pub profiles: bool,
    /// [RSV] flips true when sealed sender ships.
    #[serde(default)]
    pub sealed_sender: bool,
    /// Pairwise groups (docs/plans/pairwise-groups.md): this server hosts
    /// groups behind its anonymous gateway, relays its users' group requests
    /// and takes sealed batches. On only with `CHAT_GROUPS`, federation and
    /// sealed sender all on.
    #[serde(default)]
    pub pairwise_groups: bool,
    /// `POST /api/chat/link-preview` fetches public pages for the sender's
    /// link previews.
    #[serde(default)]
    pub link_previews: bool,
    /// The VAPID application server key (base64url, uncompressed P-256)
    /// browsers subscribe to wake-up pushes with, when the server sends them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_push_public_key: Option<String>,
    /// This server hosts group calls on its SFU (accounts can start them).
    /// Off until pairwise groups' calls are built (docs/plans/pairwise-groups.md
    /// §6).
    #[serde(default)]
    pub group_calls: bool,
    /// This server hosts call links on its SFU: accounts can make links that
    /// anyone, with or without an account, joins a call through.
    #[serde(default)]
    pub call_links: bool,
    /// Immutable E2EE attachment upload, local/federated durable delivery,
    /// encrypted ledger and browser download are complete. Omitted until the
    /// entire Phase 6 path passes its gates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<ChatMediaCapabilitiesV1>,
    /// How long a client's attachment send waits for the recipient's server
    /// to store its copy before it shows as not delivered, in seconds (an
    /// administrator's setting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_send_lifetime_seconds: Option<u32>,
    /// Always-on encrypted display-history backup and dedicated Chat quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<ChatBackupCapabilitiesV1>,
    /// Complete authenticated local service-policy history. Present only when
    /// the certificate, anonymous bundle, local delivery, and federation paths
    /// are all enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_sender_policy: Option<kutup_federation_proto::FederatedFeaturePolicyHistoryV1>,
}

impl Default for ChatCapabilities {
    /// The phase-2b server's advertised capabilities.
    fn default() -> Self {
        ChatCapabilities {
            enabled: true,
            protocol_version: 1,
            suites: vec![DirectChatSuiteId::PqxdhTripleRatchetV1],
            max_content_bytes: 65536,
            mailbox_retention_days: 30,
            device_expiry_days: 90,
            maximum_active_devices: 10,
            server_name: None,
            federation: false,
            manifests: true,
            profiles: true,
            sealed_sender: false,
            pairwise_groups: false,
            link_previews: false,
            web_push_public_key: None,
            group_calls: false,
            call_links: false,
            media: None,
            attachment_send_lifetime_seconds: None,
            backup: None,
            sealed_sender_policy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_id_round_trips() {
        assert_eq!(
            DirectChatSuiteId::from_u16(DirectChatSuiteId::PqxdhTripleRatchetV1.as_u16()),
            Some(DirectChatSuiteId::PqxdhTripleRatchetV1)
        );
        assert_eq!(DirectChatSuiteId::from_u16(0), None);
        assert_eq!(DirectChatSuiteId::from_u16(2), None);
        assert_eq!(DirectChatSuiteId::from_u16(u16::MAX), None);
        assert_eq!(
            serde_json::to_string(&DirectChatSuiteId::PqxdhTripleRatchetV1).unwrap(),
            "1"
        );
        for value in ["0", "2", "65535", "-1", "1.5", "\"1\""] {
            assert!(
                serde_json::from_str::<DirectChatSuiteId>(value).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }

    #[test]
    fn envelope_json_shape_is_camel_case_and_stable() {
        let env = OutgoingEnvelope {
            device_id: 1,
            registration_id: 42,
            envelope_type: EnvelopeType::PreKey,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content: "AAEC".into(),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(
            json,
            r#"{"deviceId":1,"registrationId":42,"envelopeType":"preKey","suite":1,"content":"AAEC"}"#
        );
        let back: OutgoingEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.registration_id, 42);

        let unknown = json.replace(r#""suite":1"#, r#""suite":2"#);
        assert!(serde_json::from_str::<OutgoingEnvelope>(&unknown).is_err());
        let missing = json.replace(r#","suite":1"#, "");
        assert!(serde_json::from_str::<OutgoingEnvelope>(&missing).is_err());
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
        let src = r#"{"id":"m1","cursor":42,"sender":{"server":"a.example","accountId":"a11ce000-0000-4000-8000-000000000001"},"senderDeviceId":1,"envelopeType":"message","suite":1,"content":"AA","serverTimestamp":"2026-07-13T10:00:00Z"}"#;
        let e: DeliveredEnvelope = serde_json::from_str(src).unwrap();
        assert_eq!(e.cursor, 42);
        assert_eq!(
            e.sender.map(|sender| sender.to_string()).as_deref(),
            Some("aci:a11ce000-0000-4000-8000-000000000001@a.example")
        );
        // A sender named by a name is refused.
        let named = src.replace(
            r#"{"server":"a.example","accountId":"a11ce000-0000-4000-8000-000000000001"}"#,
            r#""alice""#,
        );
        assert!(serde_json::from_str::<DeliveredEnvelope>(&named).is_err());
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
        assert_eq!(v["mailboxRetentionDays"], 30);
        assert_eq!(v["deviceExpiryDays"], 90);
        assert_eq!(v["sealedSender"], false);
        assert_eq!(v["manifests"], true);
        assert_eq!(v["profiles"], true);
        assert!(v.get("media").is_none());
    }
}
