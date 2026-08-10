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
pub mod federation;
mod history_transfer;
mod identity;
mod media;
mod mls;
mod profile;
mod sealed_sender;
mod security_policy;

pub use content::{
    ChatContent, ContactControlBody, ContactState, MessageMutationBody, MessageMutationOperation,
    ReactionBody, SentTranscriptBody, TextBody,
};
pub use federation::{
    FederatedChatTransaction, FederationDeliveryError, FederationDeliveryRejection,
    FederationDeliveryResponse, FEDERATED_CHAT_FEATURE,
};
pub use history_transfer::{
    chat_history_transfer_transcript_hash, ChatHistoryArchiveFinalV1,
    ChatHistoryArchiveFramePlaintextV1, ChatHistoryArchiveHeaderV1, ChatHistoryArchiveRecordV1,
    ChatHistoryArchiveRecordsV1, ChatHistoryTransferAcceptanceV1, ChatHistoryTransferCompletionV1,
    ChatHistoryTransferFrameV1, ChatHistoryTransferRequestV1, CHAT_HISTORY_TRANSFER_TTL_SECONDS,
    CHAT_HISTORY_TRANSFER_VERSION, MAX_CHAT_HISTORY_TRANSFER_FRAMES,
    MAX_CHAT_HISTORY_TRANSFER_FRAME_PLAINTEXT, MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT,
    MAX_CHAT_HISTORY_TRANSFER_RECORDS,
};
pub use identity::{AccountAddress, AddressError, ConversationId};
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
pub use mls::{
    anonymous_mls_delivery_aad, derive_group_delivery_capability, mls_authority_history_digest,
    mls_transition_digest, roster_commitment, verify_mls_authority_bootstrap_history,
    verify_mls_client_control_history, verify_mls_participant_bootstrap_history, AckMlsMailboxV1,
    AnonymousMlsDeliveryResponseV1, AnonymousMlsDeviceEnvelopeV1, AnonymousMlsKeyPackageRequestV1,
    AnonymousMlsSubmissionV1, CommitMlsControlBlockResponseV1, CommitMlsControlBlockV1,
    CreateMlsConversationRequestV1, CreateMlsConversationResponseV1, Ed25519MlsControlSigner,
    Ed25519MlsOwnerSigner, FederatedAnonymousMlsTransactionV1,
    FederatedIdentifiedMlsKeyPackageRequestV1, FederatedMlsAuthorityBootstrapPageV1,
    FederatedMlsControlReplicaV1, FederatedMlsGenesisReplicaV1, FederatedMlsOrderingVoteRequestV1,
    FederatedMlsParticipantBootstrapPageV1, FederatedMlsRecoveryReplicaV1,
    IdentifiedMlsKeyPackageRequestV1, MlsAbuseLimitsV1, MlsAnonymousDeliverySuiteV1,
    MlsApplicationSenderPolicyV1, MlsAuthorityBootstrapDescriptorV1, MlsAuthorityChangeV1,
    MlsAuthoritySetV1, MlsAuthorityTransitionCertificateV1, MlsAuthorityV1, MlsCipherSuiteId,
    MlsClientControlHistoryPageV1, MlsControlActionTypeV1, MlsControlBlockV1, MlsControlProposalV1,
    MlsControlSigner, MlsConversationDeviceV1, MlsConversationGenesisV1, MlsConversationKindV1,
    MlsConversationMemberV1, MlsDeliveryCapabilityKindV1, MlsFinalizedControlBlockV1,
    MlsGroupAuthorizationPolicyV1, MlsGroupControlBodyV1, MlsGroupCryptographicPolicyV1,
    MlsIncarnationRecoveryPlanV1, MlsIncarnationRecoveryV1, MlsInvitationAcceptanceV1,
    MlsInvitationFeedbackDecisionV1, MlsInvitationFeedbackV1, MlsKeyPackageBundleV1,
    MlsKeyPackageCountResponseV1, MlsKeyPackageV1, MlsMailboxDeliveryKindV1, MlsMailboxEnvelopeV1,
    MlsMailboxPageV1, MlsManifestDeviceV1, MlsMembershipDeliveryCommitmentV1,
    MlsMembershipDeliveryV1, MlsMembershipEnvelopeKindV1, MlsMembershipEnvelopeV1,
    MlsMembershipTransitionV1, MlsOrderingQuorumCertificateV1, MlsOrderingServicePolicyV1,
    MlsOrderingVoteTypeV1, MlsOrderingVoteV1, MlsOwnerApprovalCertificateV1,
    MlsOwnerApprovalRequestV1, MlsOwnerApprovalV1, MlsOwnerCandidateV1, MlsOwnerChangeV1,
    MlsOwnerSetV1, MlsOwnerSigner, MlsOwnerV1, MlsParticipantBootstrapDescriptorV1,
    MlsPrivateControlStateV1, PendingMessageRequestPolicyV1, PendingMlsInvitationV1,
    PublishMlsDeliveryCapabilityV1, PublishMlsKeyPackagesRequestV1,
    RecoverMlsConversationRequestV1, RecoverMlsConversationResponseV1,
    RespondMlsInvitationResponseV1, RespondMlsInvitationV1, ANONYMOUS_MLS_DELIVERY_CONTEXT,
    MAX_MLS_DEVICES_PER_ACCOUNT, MAX_MLS_GROUP_ACCOUNTS, MAX_MLS_GROUP_LEAVES,
    MLS_CIPHERSUITE_X25519_CHACHA20POLY1305_SHA256_ED25519, MLS_GROUP_AUTHORIZATION_POLICY_VERSION,
    MLS_GROUP_CRYPTOGRAPHIC_POLICY_VERSION, MLS_INVITATION_FEEDBACK_VERSION,
    MLS_ORDERING_SERVICE_POLICY_VERSION, MLS_PRIVATE_CONTROL_EXTENSION_TYPE, MLS_PROTOCOL_VERSION,
};
pub use profile::{
    decode_profile_envelope, encode_profile_envelope_header, ChatProfileResponse,
    DecodedProfileEnvelopeV1, OwnChatProfileResponse, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, ProfileSuiteId, PutChatProfileRequest, MAX_PROFILE_AVATAR_BYTES,
    PROFILE_NAME_PADDED_LENGTHS,
};
pub use sealed_sender::{
    capability_hash, constant_time_capability_hash_eq, derive_delivery_capability,
    AnonymousPreKeyRequestV1, FederatedSealedTransactionV1, SealedDeliveryResponseV1,
    SealedMessageSubmissionV1, SealedOutgoingEnvelopeV1, SenderCertificateResponseV1,
    DELIVERY_CAPABILITY_CONTEXT,
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

/// `POST /api/chat/device` — register (or re-register) this client as a chat device.
///
/// Re-registration with fresh keys replaces the device's directory entry and mailbox
/// (the standard Signal semantics for a reinstalled client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterChatDeviceRequest {
    pub suite: DirectChatSuiteId,
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

/// One entry in a signed [`AccountManifestV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestDeviceV1 {
    pub device_id: u32,
    pub direct_chat_suite: DirectChatSuiteId,
    pub identity_key: String,
    pub registration_id: u32,
    /// MLS-only device keys covered by the account manifest. An MLS
    /// registration is rejected unless this binding is present and exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls: Option<MlsManifestDeviceV1>,
}

pub const ACCOUNT_MANIFEST_VERSION: u16 = 1;
pub const MAX_ACCOUNT_MANIFEST_DEVICES: usize = 10;

/// Closed construction for the account-scoped public keys carried by the
/// manifest. It is intentionally separate from Drive object/envelope suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum AccountIdentitySuiteId {
    X25519Ed25519V1 = 1,
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
            _ => Err(format!("unknown account identity suite {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestDriveKeysV1 {
    pub suite: AccountIdentitySuiteId,
    /// Canonical padded base64 raw X25519 public key.
    pub hpke_public_key: String,
    /// Canonical padded base64 raw Ed25519 public key used only to authenticate
    /// named Drive share envelopes.
    pub share_signing_public_key: String,
}

/// Complete V1 account identity: account-scoped Drive keys and every active
/// cryptographic device, signed by an account self-authority key the server
/// never sees. Clients persist every accepted sequence and fail closed on a
/// gap, rollback, equivocation, authority change or incarnation change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestV1 {
    pub manifest_version: u16,
    /// Canonical local or federated routing address; never a display name.
    pub account: String,
    /// Domain-separated SHA-256 identifier derived from the authority public
    /// key. A destructive account wipe necessarily starts another incarnation.
    pub incarnation_id: String,
    /// Monotonic within this exact authority/incarnation.
    pub sequence: u64,
    /// SHA-256 of the preceding manifest's canonical signed bytes and signature.
    /// Absent only at sequence 1; binds updates into a rollback-evident chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    pub drive: AccountManifestDriveKeysV1,
    pub devices: Vec<AccountManifestDeviceV1>,
    pub issued_at: String,
    /// Stable identifier for the authority key (lowercase SHA-256 of its raw
    /// public-key bytes in v1). Allows additive authority rotation later.
    pub authority_key_id: String,
    /// base64 account self-signing PUBLIC key.
    pub self_authority_key: String,
    /// base64 signature over the canonical `version‖devices‖issuedAt`.
    pub signature: String,
}

impl AccountManifestV1 {
    /// Deterministic, domain-separated binary encoding signed by every client.
    /// Devices MUST be strictly ordered by `deviceId`; accepting multiple
    /// encodings for one manifest would make cross-client signatures unsafe.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup/account-manifest/v1\0";
        let mut out = Vec::with_capacity(256 + self.devices.len() * 96);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.manifest_version.to_be_bytes());
        push_string(&mut out, &self.account)?;
        out.extend_from_slice(&decode_lower_hex_32("incarnationId", &self.incarnation_id)?);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        push_optional(&mut out, self.previous_hash.as_deref())?;
        push_string(&mut out, &self.issued_at)?;
        out.extend_from_slice(&decode_lower_hex_32(
            "authorityKeyId",
            &self.authority_key_id,
        )?);
        out.extend_from_slice(&decode_canonical_base64_exact(
            "selfAuthorityKey",
            &self.self_authority_key,
            32,
        )?);
        out.extend_from_slice(&u16::from(self.drive.suite).to_be_bytes());
        out.extend_from_slice(&decode_canonical_base64_exact(
            "drive.hpkePublicKey",
            &self.drive.hpke_public_key,
            32,
        )?);
        out.extend_from_slice(&decode_canonical_base64_exact(
            "drive.shareSigningPublicKey",
            &self.drive.share_signing_public_key,
            32,
        )?);
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
            out.extend_from_slice(&u16::from(device.direct_chat_suite).to_be_bytes());
            push_string(&mut out, &device.identity_key)?;
            match &device.mls {
                Some(mls) => {
                    out.push(1);
                    mls.validate()?;
                    out.extend_from_slice(&u16::from(mls.suite).to_be_bytes());
                    push_string(&mut out, &mls.credential_public_key)?;
                    push_string(&mut out, &mls.anonymous_delivery_public_key)?;
                }
                None => out.push(0),
            }
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
        use ed25519_dalek::{Signature, VerifyingKey};
        use sha2::{Digest, Sha256};

        if self.manifest_version != ACCOUNT_MANIFEST_VERSION {
            return Err("unsupported account manifest version".into());
        }
        let account: AccountAddress = self
            .account
            .parse()
            .map_err(|error: AddressError| error.to_string())?;
        if account.canonical() != self.account {
            return Err("manifest account is not canonical".into());
        }
        if self.sequence == 0 {
            return Err("manifest sequence must be positive".into());
        }
        if self.sequence == 1 && self.previous_hash.is_some() {
            return Err("manifest sequence 1 cannot have previousHash".into());
        }
        if self.sequence > 1 && self.previous_hash.is_none() {
            return Err("manifest update requires previousHash".into());
        }
        if let Some(previous_hash) = &self.previous_hash {
            let decoded = hex::decode(previous_hash)
                .map_err(|_| "previousHash must be lowercase SHA-256 hex".to_string())?;
            if decoded.len() != 32 || hex::encode(decoded) != *previous_hash {
                return Err("previousHash must be lowercase SHA-256 hex".into());
            }
        }

        if self.issued_at.is_empty() || self.issued_at.len() > 64 {
            return Err("manifest issuedAt must be 1-64 bytes".into());
        }
        if self.devices.is_empty() || self.devices.len() > MAX_ACCOUNT_MANIFEST_DEVICES {
            return Err("account manifest requires 1-10 active devices".into());
        }

        let public =
            decode_canonical_base64_exact("selfAuthorityKey", &self.self_authority_key, 32)?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| "selfAuthorityKey must be 32 bytes".to_string())?;
        let expected_id = hex::encode(Sha256::digest(public));
        if self.authority_key_id != expected_id {
            return Err("authorityKeyId does not match selfAuthorityKey".into());
        }
        let mut incarnation = Sha256::new();
        incarnation.update(b"kutup/account-incarnation/v1\0");
        incarnation.update(public);
        if self.incarnation_id != hex::encode(incarnation.finalize()) {
            return Err("incarnationId does not match selfAuthorityKey".into());
        }

        decode_canonical_base64_exact("drive.hpkePublicKey", &self.drive.hpke_public_key, 32)?;
        let drive_signing = decode_canonical_base64_exact(
            "drive.shareSigningPublicKey",
            &self.drive.share_signing_public_key,
            32,
        )?;
        VerifyingKey::from_bytes(
            &drive_signing
                .try_into()
                .map_err(|_| "Drive signing public key must be 32 bytes")?,
        )
        .map_err(|_| "Drive signing public key is not valid Ed25519")?;

        for device in &self.devices {
            if device.device_id == 0 || device.device_id > 127 || device.registration_id >= 16_384 {
                return Err("manifest device identifiers are outside V1 bounds".into());
            }
            decode_canonical_base64_exact("device.identityKey", &device.identity_key, 33)?;
        }

        let signature = decode_canonical_base64_exact("signature", &self.signature, 64)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| "manifest signature must be 64 bytes".to_string())?;
        let verifying = VerifyingKey::from_bytes(&public)
            .map_err(|_| "selfAuthorityKey is not a valid Ed25519 key".to_string())?;
        verifying
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| "manifest signature is invalid".to_string())
    }
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

/// Successful publication of one exact signed account-manifest sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestPublicationV1 {
    pub manifest: AccountManifestV1,
}

pub const MAX_ACCOUNT_MANIFEST_HISTORY_PAGE: usize = 64;

/// Bounded complete account-manifest history. Pagination is an exact sequence
/// cursor; every manifest is independently signed and hash-linked, so no
/// server-generated proof or opaque cursor is trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestHistoryPageV1 {
    pub account: String,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub manifests: Vec<AccountManifestV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_sequence: Option<u64>,
}

impl AccountManifestHistoryPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        let account: AccountAddress = self
            .account
            .parse()
            .map_err(|error: AddressError| error.to_string())?;
        if account.canonical() != self.account
            || self.from_sequence == 0
            || self.to_sequence < self.from_sequence
            || self.manifests.is_empty()
            || self.manifests.len() > MAX_ACCOUNT_MANIFEST_HISTORY_PAGE
        {
            return Err("account manifest history page has an invalid shape".into());
        }
        let mut expected = self.from_sequence;
        for manifest in &self.manifests {
            manifest.verify()?;
            if manifest.account != self.account || manifest.sequence != expected {
                return Err("account manifest history page is missing or reordered".into());
            }
            expected = expected
                .checked_add(1)
                .ok_or_else(|| "account manifest sequence is exhausted".to_string())?;
        }
        let last = expected - 1;
        match self.next_sequence {
            Some(next) if last < self.to_sequence && next == expected => Ok(()),
            None if last == self.to_sequence => Ok(()),
            _ => Err("account manifest history pagination is inconsistent".into()),
        }
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

/// `POST /api/chat/ws-ticket` — a single-use browser WebSocket credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChatWsTicketResponse {
    pub ticket: String,
    pub expires_at: String,
}

/// One device's prekey bundle, as served by `GET /api/chat/users/{username}/keys`.
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
    pub manifest: Option<AccountManifestV1>,
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
    /// [ADD→RSV] Sender address, `Option` from v1 so sealed sender (which
    /// removes it) is not a breaking change. Local phase: bare username;
    /// `user@domain` for remote senders once federation lands; `None` under
    /// sealed sender. See `docs/chat-protocol.md` §8.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
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
    /// An account-local history-transfer request or state change is available.
    /// The socket carries no archive metadata; clients fetch authenticated
    /// opaque relay state over REST.
    HistoryTransferAvailable { transfer_id: String },
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
    /// Canonical DNS suffix in `username@server`. Present exactly when
    /// federation is enabled; display names never substitute for it.
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
    /// RFC 9420 group creation, invitation, ordered membership, and anonymous
    /// application delivery are complete on the local and federated paths.
    #[serde(default)]
    pub mls_groups: bool,
    /// Immutable E2EE attachment upload, local/federated durable delivery,
    /// encrypted ledger and browser download are complete. Omitted until the
    /// entire Phase 6 path passes its gates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<ChatMediaCapabilitiesV1>,
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
            mls_groups: false,
            media: None,
            sealed_sender_policy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use sha2::{Digest, Sha256};

    fn test_manifest() -> AccountManifestV1 {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let authority_public = authority.verifying_key().to_bytes();
        let authority_key_id = hex::encode(Sha256::digest(authority_public));
        let mut incarnation = Sha256::new();
        incarnation.update(b"kutup/account-incarnation/v1\0");
        incarnation.update(authority_public);
        let drive_signing = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let mut manifest = AccountManifestV1 {
            manifest_version: ACCOUNT_MANIFEST_VERSION,
            account: "alice@example.test".into(),
            incarnation_id: hex::encode(incarnation.finalize()),
            sequence: 1,
            previous_hash: None,
            drive: AccountManifestDriveKeysV1 {
                suite: AccountIdentitySuiteId::X25519Ed25519V1,
                hpke_public_key: base64::engine::general_purpose::STANDARD.encode([9; 32]),
                share_signing_public_key: base64::engine::general_purpose::STANDARD
                    .encode(drive_signing.verifying_key().to_bytes()),
            },
            devices: vec![
                AccountManifestDeviceV1 {
                    device_id: 1,
                    direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                    identity_key: base64::engine::general_purpose::STANDARD.encode([10; 33]),
                    registration_id: 10,
                    mls: None,
                },
                AccountManifestDeviceV1 {
                    device_id: 2,
                    direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                    identity_key: base64::engine::general_purpose::STANDARD.encode([11; 33]),
                    registration_id: 20,
                    mls: None,
                },
            ],
            issued_at: "2026-07-15T12:00:00Z".into(),
            authority_key_id,
            self_authority_key: base64::engine::general_purpose::STANDARD.encode(authority_public),
            signature: String::new(),
        };
        manifest.signature = base64::engine::general_purpose::STANDARD.encode(
            authority
                .sign(&manifest.signing_bytes().unwrap())
                .to_bytes(),
        );
        manifest
    }

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
        assert_eq!(v["mailboxRetentionDays"], 30);
        assert_eq!(v["deviceExpiryDays"], 90);
        assert_eq!(v["sealedSender"], false);
        assert_eq!(v["manifests"], true);
        assert_eq!(v["profiles"], true);
        assert!(v.get("media").is_none());
    }

    #[test]
    fn manifest_signing_bytes_are_canonical_and_order_sensitive() {
        let manifest = test_manifest();
        let bytes = manifest.signing_bytes().unwrap();
        assert!(bytes.starts_with(b"kutup/account-manifest/v1\0"));
        assert_eq!(manifest.signing_bytes().unwrap(), bytes);
        assert_eq!(manifest.manifest_hash().unwrap().len(), 64);
        manifest.verify().unwrap();

        let mut unordered = manifest.clone();
        unordered.devices.swap(0, 1);
        assert!(unordered.signing_bytes().is_err());
    }

    #[test]
    fn manifest_verification_rejects_bad_chain_shape_before_crypto() {
        let mut manifest = test_manifest();
        manifest.manifest_version = 0;
        assert_eq!(
            manifest.verify().unwrap_err(),
            "unsupported account manifest version"
        );
    }
}
