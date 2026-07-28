//! Durable OpenMLS client state for SelfSync, Direct, and Group conversations.
//!
//! OpenMLS owns the MLS state machine. This module supplies the Kutup-specific
//! persistence boundary and fixes the V1 ciphersuite/configuration. A provider
//! snapshot and the exact outbound ciphertext are committed in one [`ChatDb`]
//! transaction, so a crash can neither lose a consumed secret-tree generation
//! nor regenerate different ciphertext for the same logical send.

mod application;
mod close;
mod delivery;
mod device;
mod device_sync;
mod genesis;
mod governance;
mod inbound;
mod lifecycle;
mod membership;
mod owner_approval;
mod ownership;
mod policy;
mod recovery;
mod state;
mod validation;
mod welcome;

pub use close::{FinalizedMlsClose, PendingMlsClose, PreparedMlsClose};
pub use delivery::{AnonymousMlsRecipientDevice, DerivedMlsDeliveryCapability};
pub use governance::{
    FinalizedMlsAuthorityChange, PendingMlsAuthorityChange, PreparedMlsAuthorityChange,
};
use membership::*;
pub use owner_approval::PendingMlsOwnerApprovalRequest;
pub use ownership::{FinalizedMlsOwnerChange, PendingMlsOwnerChange, PreparedMlsOwnerChange};
pub use policy::{FinalizedMlsPolicyChange, PendingMlsPolicyChange, PreparedMlsPolicyChange};
pub use recovery::{FinalizedMlsRecovery, PendingMlsRecovery, PreparedMlsRecovery};
use state::{provider_from_snapshot, snapshot_provider, KutupMlsProvider, SnapshotMetadata};
use validation::*;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use openmls::prelude::{
    Capabilities, Ciphersuite, CredentialType, Extension, ExtensionType, Extensions, GroupContext,
    GroupId, KeyPackage, KeyPackageIn, Lifetime, Member, MlsGroup, MlsGroupCreateConfig,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, ProtocolVersion,
    RequiredCapabilitiesExtension, Sender, StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::{
    signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey,
};
use p256::elliptic_curve::rand_core::{OsRng, RngCore as _};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};
use uuid::Uuid;

use crate::db::{ChatDb, MlsHistoryMessage, MlsOutboxDelivery, MlsOutboxEntry, Pending};
use crate::error::{ChatError, Result};
use kutup_chat_proto::{
    roster_commitment, verify_mls_client_control_history, AccountAddress,
    AnonymousMlsDeviceEnvelopeV1, AnonymousMlsSubmissionV1, ChatContent,
    CommitMlsControlBlockResponseV1, CommitMlsControlBlockV1, CreateMlsConversationRequestV1,
    FederatedMlsOrderingVoteRequestV1, MlsApplicationSenderPolicyV1, MlsAuthoritySetV1,
    MlsAuthorityV1, MlsCipherSuiteId, MlsClientControlHistoryPageV1, MlsControlActionTypeV1,
    MlsControlBlockV1, MlsControlProposalV1, MlsConversationDeviceV1, MlsConversationGenesisV1,
    MlsConversationKindV1, MlsConversationMemberV1, MlsFinalizedControlBlockV1,
    MlsGroupAuthorizationPolicyV1, MlsGroupControlBodyV1, MlsGroupCryptographicPolicyV1,
    MlsKeyPackageV1, MlsManifestDeviceV1, MlsMembershipDeliveryCommitmentV1,
    MlsMembershipDeliveryV1, MlsMembershipEnvelopeKindV1, MlsMembershipEnvelopeV1,
    MlsMembershipTransitionV1, MlsOrderingQuorumCertificateV1, MlsOrderingServicePolicyV1,
    MlsOwnerCandidateV1, MlsOwnerSetV1, MlsOwnerV1, MlsPrivateControlStateV1,
    RecoverMlsConversationRequestV1, RecoverMlsConversationResponseV1,
    MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256, MLS_PRIVATE_CONTROL_EXTENSION_TYPE,
    MLS_PROTOCOL_VERSION,
};

const STATE_FORMAT_VERSION: u16 = 10;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STATE_RECORDS: usize = 100_000;
const MAX_STATE_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_PENDING_COMMITS: usize = 4096;
const MAX_CREDENTIAL_IDENTITY_BYTES: usize = 512;
const MAX_APPLICATION_BYTES: usize = 1024 * 1024;
const MIN_MLS_GROUP_ID_BYTES: usize = 16;
const MAX_MLS_GROUP_ID_BYTES: usize = 255;
const MAX_KEY_PACKAGE_LIFETIME_SECONDS: i64 = 84 * 24 * 60 * 60;
const KEY_PACKAGE_CLOCK_SKEW_SECONDS: u64 = 60 * 60;

/// The one ciphersuite advertised by Kutup MLS V1 (RFC 9420 suite `0x0002`).
pub const KUTUP_MLS_V1_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

/// Maximum number of older epochs retained to tolerate a commit overtaking
/// application messages during federation. This is intentionally small to
/// retain forward secrecy.
pub const KUTUP_MLS_V1_MAX_PAST_EPOCHS: usize = 2;

/// Public, manifest-bound MLS device keys. Private keys remain exclusively in
/// the encrypted [`ChatDb`] state snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsDevicePublicMaterial {
    pub credential_public_key: Vec<u8>,
    pub anonymous_delivery_public_key: Vec<u8>,
}

impl MlsDevicePublicMaterial {
    /// Produce the exact signed-manifest binding expected by the server.
    pub fn manifest_binding(&self) -> MlsManifestDeviceV1 {
        MlsManifestDeviceV1 {
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            credential_public_key: BASE64.encode(&self.credential_public_key),
            anonymous_delivery_public_key: BASE64.encode(&self.anonymous_delivery_public_key),
        }
    }
}

/// Public result of creating or reopening one local MLS group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMlsGroupState {
    pub mls_group_id: Vec<u8>,
    pub epoch: u64,
}

/// Public half of the group-scoped owner credential. The Ed25519 seed remains
/// exclusively inside the authenticated MLS state snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsGroupOwnerCredential {
    pub owner_id: String,
    pub public_key: Vec<u8>,
}

/// Publication state for one exact locally prepared group genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMlsConversationStatus {
    PendingGenesis,
    Active,
    ReadOnly,
    Closed,
}

/// Exact durable group genesis retry record. A network failure can only leave
/// this record pending; it never regenerates an owner key, GroupId, or roster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMlsConversationRecord {
    pub request: CreateMlsConversationRequestV1,
    pub status: LocalMlsConversationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_genesis_hash: Option<String>,
    /// Present only for append-only recovered incarnations and bound to the
    /// owner-approved recovery statement that created this genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_digest: Option<String>,
    pub last_finalized_height: u64,
    pub last_finalized_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_block_hash: Option<String>,
    pub current_roster: Vec<MlsConversationMemberV1>,
    pub current_authority_set: MlsAuthoritySetV1,
    pub current_owner_set: MlsOwnerSetV1,
    pub genesis_authorization_policy: MlsGroupAuthorizationPolicyV1,
    pub genesis_cryptographic_policy: MlsGroupCryptographicPolicyV1,
    pub current_authorization_policy: MlsGroupAuthorizationPolicyV1,
    pub current_cryptographic_policy: MlsGroupCryptographicPolicyV1,
}

/// Atomic result of preparing an epoch-zero group and its exact server
/// publication request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedMlsGroupGenesis {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
}

/// Atomic result of joining a Welcome and importing its independently
/// replayed public control history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinedMlsConversation {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
}

/// One transparency-verified MLS credential. Account addresses are carried in
/// the BasicCredential only between group members; ordering authorities see
/// only the separately encrypted Kutup control proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedMlsCredential {
    pub credential_identity: String,
    pub credential_public_key: Vec<u8>,
}

/// Untrusted roster claim decrypted from an MLS Welcome before any local group
/// state is created. Callers must bind every claim to transparency-verified
/// account manifests before passing the corresponding verified roster to
/// [`MlsClient::join_from_welcome_with_control_history`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimedMlsCredential {
    pub credential_identity: String,
    pub credential_public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsWelcomeInspection {
    pub mls_group_id: Vec<u8>,
    pub epoch: u64,
    pub claimed_members: Vec<ClaimedMlsCredential>,
    pub private_control_state: MlsPrivateControlStateV1,
}

/// Untrusted-but-MLS-authenticated view of a staged inbound Commit. The caller
/// must resolve every claimed device through transparency and verify the
/// corresponding public control block before the Commit can be merged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsInboundCommitInspection {
    pub mls_group_id: Vec<u8>,
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub commit_hash: String,
    pub claimed_members: Vec<ClaimedMlsCredential>,
    pub private_control_state: MlsPrivateControlStateV1,
}

impl VerifiedMlsCredential {
    pub fn new(credential_identity: String, credential_public_key: Vec<u8>) -> Result<Self> {
        validate_credential_identity(&credential_identity)?;
        validate_credential_public_key(&credential_public_key)?;
        Ok(Self {
            credential_identity,
            credential_public_key,
        })
    }
}

/// A claimed KeyPackage paired with the credential binding independently
/// verified from the account's transparency-logged device manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedMlsKeyPackage {
    pub wire: MlsKeyPackageV1,
    pub credential: VerifiedMlsCredential,
    /// Manifest-authenticated RFC 9180 destination key for this same device.
    /// It is not inferred from the KeyPackage and must match the complete
    /// transparency-verified device manifest.
    pub anonymous_delivery_public_key: Vec<u8>,
}

/// Exact durable result of staging an outbound MLS membership commit. The
/// commit and Welcome are byte-for-byte retry material; the local epoch is not
/// advanced until the corresponding control block reaches ordering quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsCommit {
    pub mls_group_id: Vec<u8>,
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub commit_hash: String,
    pub commit: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome: Option<Vec<u8>>,
}

/// Exact durable browser retry material for one ordinary group membership
/// transition. It is committed in the same encrypted snapshot as the pending
/// OpenMLS Commit and contains everything needed to restage, recollect
/// deterministic authority votes, and submit the finalized block after a
/// restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsMembershipChange {
    pub mls_group_id: Vec<u8>,
    pub next_roster: Vec<MlsConversationMemberV1>,
    pub deliveries: Vec<MlsMembershipDeliveryV1>,
    pub transition: MlsMembershipTransitionV1,
    pub vote_request: FederatedMlsOrderingVoteRequestV1,
    pub commit_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_request: Option<CommitMlsControlBlockV1>,
}

/// Atomic result of staging the OpenMLS Commit and its complete control-plane
/// retry record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedMlsMembershipChange {
    pub pending: PendingMlsCommit,
    pub control: PendingMlsMembershipChange,
}

/// Local state returned only after the server acknowledgement matches the
/// exact quorum-certified block prepared from durable retry material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedMlsMembershipChange {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
}

/// Authenticated mailbox coordinates supplied alongside one opaque MLS
/// membership-control message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsControlEnvelopeContext {
    pub envelope_id: Uuid,
    pub cursor: String,
    pub send_id: Uuid,
}

impl MlsControlEnvelopeContext {
    fn validate(&self) -> Result<()> {
        if self.envelope_id.is_nil()
            || self.send_id.is_nil()
            || self
                .cursor
                .parse::<u64>()
                .ok()
                .filter(|cursor| *cursor > 0 && cursor.to_string() == self.cursor)
                .is_none()
        {
            return Err(ChatError::Invalid(
                "MLS mailbox envelope coordinates are invalid".into(),
            ));
        }
        Ok(())
    }
}

/// Exact durable receipt for a membership-control mailbox envelope. It is
/// written in the same encrypted snapshot as the merged OpenMLS Commit and
/// control-log head, then used to make post-crash server acknowledgement
/// retries idempotent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessedMlsControlEnvelope {
    pub envelope_id: Uuid,
    pub cursor: String,
    pub send_id: Uuid,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub height: u64,
    pub epoch: u64,
    pub block_hash: String,
}

/// Atomic result of applying or replaying one authenticated inbound
/// membership Commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppliedInboundMlsCommit {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
    pub receipt: ProcessedMlsControlEnvelope,
    pub idempotent: bool,
}

/// Authenticated application plaintext and the exact MLS device credential
/// that sent it. The caller has already supplied the transparency-verified
/// expected credential before this value can be returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecryptedMlsApplication {
    pub plaintext: Vec<u8>,
    pub epoch: u64,
    pub sender: VerifiedMlsCredential,
}

/// Non-mutating inspection of an HPKE-wrapped MLS application message. The
/// claimed sender remains untrusted until the shared transparency verifier
/// resolves it to [`VerifiedMlsCredential`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsApplicationInspection {
    pub mls_group_id: Vec<u8>,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub epoch: u64,
    pub claimed_sender: ClaimedMlsCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsApplicationEnvelopeContext {
    pub envelope_id: Uuid,
    pub cursor: String,
    pub send_id: Uuid,
    pub server_timestamp: i64,
}

impl MlsApplicationEnvelopeContext {
    fn validate(&self) -> Result<u64> {
        if self.envelope_id.is_nil() || self.send_id.is_nil() || self.server_timestamp < 0 {
            return Err(ChatError::Invalid(
                "MLS application mailbox envelope has invalid identifiers or timestamp".into(),
            ));
        }
        self.cursor
            .parse::<u64>()
            .ok()
            .filter(|cursor| *cursor > 0 && cursor.to_string() == self.cursor)
            .ok_or_else(|| {
                ChatError::Invalid(
                    "MLS application mailbox cursor is not canonical positive decimal".into(),
                )
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppliedInboundMlsApplication {
    pub message: MlsHistoryMessage,
    pub idempotent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagedMlsApplicationDelivery {
    pub entry: MlsOutboxEntry,
    pub submission: AnonymousMlsSubmissionV1,
    pub idempotent: bool,
}

/// Group-scoped outer control credential. It is intentionally unlinkable to
/// the device's account-wide manifest credential. Members bind it inside the
/// MLS-encrypted control payload before an ordering authority ever sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsGroupControlCredential {
    pub proposer_id: String,
    pub public_key: Vec<u8>,
}

/// Single-device client MLS engine. The surrounding Chat engine already
/// serializes operations for one device database; callers must preserve that
/// invariant on native and browser platforms.
pub struct MlsClient {
    db: Rc<dyn ChatDb>,
}

impl MlsClient {
    async fn load_provider(&self) -> Result<(KutupMlsProvider, SnapshotMetadata)> {
        let bytes =
            self.db.load_mls_state().await?.ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS device is not initialized".into())
            })?;
        provider_from_snapshot(&bytes)
    }
}

fn decode_canonical_base64(label: &str, value: &str, exact_len: usize) -> Result<Vec<u8>> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| ChatError::Db(format!("{label} is not canonical base64")))?;
    if BASE64.encode(&decoded) != value || (exact_len != 0 && decoded.len() != exact_len) {
        return Err(ChatError::Db(format!(
            "{label} has invalid encoding or length"
        )));
    }
    Ok(decoded)
}

fn kutup_mls_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[KUTUP_MLS_V1_CIPHERSUITE]),
        Some(&[ExtensionType::Unknown(MLS_PRIVATE_CONTROL_EXTENSION_TYPE)]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

fn private_control_extensions(
    state: &MlsPrivateControlStateV1,
) -> Result<Extensions<GroupContext>> {
    let encoded = state.canonical_bytes().map_err(ChatError::Invalid)?;
    Extensions::try_from(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(MLS_PRIVATE_CONTROL_EXTENSION_TYPE)],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(
            MLS_PRIVATE_CONTROL_EXTENSION_TYPE,
            UnknownExtension(encoded),
        ),
    ])
    .map_err(|error| ChatError::Protocol(format!("build MLS private control extensions: {error}")))
}

fn extract_private_control_state(
    extensions: &Extensions<GroupContext>,
) -> Result<MlsPrivateControlStateV1> {
    let required = extensions.required_capabilities().ok_or_else(|| {
        ChatError::Trust("MLS group omits its required-capabilities extension".into())
    })?;
    if required.extension_types() != [ExtensionType::Unknown(MLS_PRIVATE_CONTROL_EXTENSION_TYPE)]
        || !required.proposal_types().is_empty()
        || required.credential_types() != [CredentialType::Basic]
    {
        return Err(ChatError::Trust(
            "MLS group has a different mandatory capability set".into(),
        ));
    }
    let extension = extensions
        .unknown(MLS_PRIVATE_CONTROL_EXTENSION_TYPE)
        .ok_or_else(|| {
            ChatError::Trust("MLS group omits its mandatory private control extension".into())
        })?;
    MlsPrivateControlStateV1::from_canonical_bytes(&extension.0).map_err(|error| {
        ChatError::Trust(format!("invalid MLS private control extension: {error}"))
    })
}

fn ensure_exact_private_control_state(
    extensions: &Extensions<GroupContext>,
    expected: &MlsPrivateControlStateV1,
) -> Result<()> {
    if extract_private_control_state(extensions)? != *expected {
        return Err(ChatError::Trust(
            "MLS private control extension differs from the prepared state".into(),
        ));
    }
    Ok(())
}

fn genesis_private_control_state(
    record: &LocalMlsConversationRecord,
) -> Result<MlsPrivateControlStateV1> {
    if record.last_finalized_height != 0
        || record.last_finalized_epoch != 0
        || record.last_block_hash.is_some()
    {
        return Err(ChatError::Db(
            "cannot derive a genesis private control extension from an advanced record".into(),
        ));
    }
    let state = MlsPrivateControlStateV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: record.request.genesis.conversation_id,
        incarnation: record.request.genesis.incarnation,
        proposal_id: None,
        height: 0,
        initial_epoch: record.request.genesis.initial_epoch,
        epoch: record.request.genesis.initial_epoch,
        previous_block_hash: None,
        genesis_roster: record.request.members.clone(),
        genesis_authority_set: record.request.genesis.authority_set.clone(),
        genesis_owner_set: record
            .request
            .genesis
            .owner_set
            .clone()
            .ok_or_else(|| ChatError::Db("group genesis has no owner set".into()))?,
        genesis_authorization_policy: record.genesis_authorization_policy.clone(),
        genesis_cryptographic_policy: record.genesis_cryptographic_policy.clone(),
        roster: record.current_roster.clone(),
        authority_set: record.current_authority_set.clone(),
        owner_set: record.current_owner_set.clone(),
        authorization_policy: record.current_authorization_policy.clone(),
        cryptographic_policy: record.current_cryptographic_policy.clone(),
    };
    state.validate().map_err(ChatError::Db)?;
    Ok(state)
}

fn ensure_private_control_matches_record(
    extensions: &Extensions<GroupContext>,
    record: &LocalMlsConversationRecord,
) -> Result<MlsPrivateControlStateV1> {
    let state = extract_private_control_state(extensions)?;
    if state.conversation_id != record.request.genesis.conversation_id
        || state.incarnation != record.request.genesis.incarnation
        || state.height != record.last_finalized_height
        || state.epoch != record.last_finalized_epoch
        || state.genesis_roster != record.request.members
        || state.genesis_authority_set != record.request.genesis.authority_set
        || record.request.genesis.owner_set.as_ref() != Some(&state.genesis_owner_set)
        || state.genesis_authorization_policy != record.genesis_authorization_policy
        || state.genesis_cryptographic_policy != record.genesis_cryptographic_policy
        || state.roster != record.current_roster
        || state.authority_set != record.current_authority_set
        || state.owner_set != record.current_owner_set
        || state.authorization_policy != record.current_authorization_policy
        || state.cryptographic_policy != record.current_cryptographic_policy
        || (state.height == 0
            && (state.proposal_id.is_some() || state.previous_block_hash.is_some()))
        || (state.height == 1 && state.previous_block_hash.is_some())
    {
        return Err(ChatError::Trust(
            "MLS private control extension differs from the durable control pin".into(),
        ));
    }
    if state.height > 1 {
        validate_sha256_hex(
            "MLS private control predecessor",
            state.previous_block_hash.as_deref().ok_or_else(|| {
                ChatError::Trust("MLS private control predecessor is missing".into())
            })?,
        )?;
    }
    Ok(state)
}

fn active_conversation_for_group<'a>(
    metadata: &'a SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<&'a LocalMlsConversationRecord> {
    let group_key = BASE64.encode(mls_group_id);
    let mut matches = metadata.conversations.values().filter(|record| {
        record.status == LocalMlsConversationStatus::Active
            && record.request.genesis.mls_group_id == group_key
    });
    let record = matches
        .next()
        .ok_or_else(|| ChatError::Trust("active MLS conversation pin is unavailable".into()))?;
    if matches.next().is_some() {
        return Err(ChatError::Db(
            "multiple active conversations reuse one MLS GroupId".into(),
        ));
    }
    validate_local_control_state(record)?;
    Ok(record)
}

fn verify_private_control_accounts<'a>(
    state: &MlsPrivateControlStateV1,
    credential_identities: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let mut device_accounts = BTreeSet::new();
    for identity in credential_identities {
        let (account, _) = parse_device_credential_identity(identity)?;
        device_accounts.insert(account);
    }
    let control_accounts = state
        .roster
        .iter()
        .map(|member| member.address.canonical())
        .collect::<BTreeSet<_>>();
    if device_accounts != control_accounts {
        return Err(ChatError::Trust(
            "MLS private control roster differs from the cryptographic device roster".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn advance_test_private_control<'a>(
    mut state: MlsPrivateControlStateV1,
    additions: impl Iterator<Item = &'a str>,
    removals: impl Iterator<Item = &'a str>,
) -> Result<MlsPrivateControlStateV1> {
    let removed_accounts = removals
        .map(parse_device_credential_identity)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|(account, _)| account)
        .collect::<BTreeSet<_>>();
    state
        .roster
        .retain(|member| !removed_accounts.contains(&member.address.canonical()));
    for identity in additions {
        let (account, _) = parse_device_credential_identity(identity)?;
        if state
            .roster
            .iter()
            .all(|member| member.address.canonical() != account)
        {
            state.roster.push(MlsConversationMemberV1 {
                address: account
                    .parse()
                    .map_err(|error: kutup_chat_proto::AddressError| {
                        ChatError::Invalid(error.to_string())
                    })?,
                is_admin: false,
                owner_id: None,
            });
        }
    }
    state
        .roster
        .sort_by_key(|member| member.address.canonical());
    state.previous_block_hash = if state.height == 0 {
        None
    } else {
        Some(hex::encode(Sha256::digest(
            state.canonical_bytes().map_err(ChatError::Protocol)?,
        )))
    };
    state.height = state.height.saturating_add(1);
    state.epoch = state.epoch.saturating_add(1);
    state.proposal_id = Some(random_uuid());
    state.validate().map_err(ChatError::Protocol)?;
    Ok(state)
}

#[allow(clippy::too_many_arguments)]
fn sign_control_proposal_with_metadata(
    metadata: &SnapshotMetadata,
    mls_group_id: &[u8],
    conversation_id: Uuid,
    incarnation: u64,
    proposal_id: Uuid,
    base_epoch: u64,
    action_type: MlsControlActionTypeV1,
    encrypted_payload: &[u8],
    created_at_seconds: i64,
) -> Result<MlsControlProposalV1> {
    let key_bytes = ensure_group_control_key(metadata, mls_group_id)?;
    let signer = P256SigningKey::from_slice(key_bytes)
        .map_err(|_| ChatError::Db("invalid durable MLS group control key".into()))?;
    let public_key = signer.verifying_key().to_encoded_point(false);
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation,
        proposal_id,
        base_epoch,
        action_type,
        proposer_id: hex::encode(Sha256::digest(public_key.as_bytes())),
        proposer_credential_public_key: BASE64.encode(public_key.as_bytes()),
        encrypted_payload: BASE64.encode(encrypted_payload),
        payload_digest: hex::encode(Sha256::digest(encrypted_payload)),
        created_at: created_at_seconds,
        proposer_signature: String::new(),
    };
    let signature: P256Signature =
        signer.sign(&proposal.signing_bytes().map_err(ChatError::Invalid)?);
    proposal.proposer_signature = BASE64.encode(signature.to_der().as_bytes());
    proposal.verify().map_err(ChatError::Protocol)?;
    Ok(proposal)
}

fn random_uuid() -> Uuid {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn parse_verified_key_package(
    provider: &KutupMlsProvider,
    verified: &VerifiedMlsKeyPackage,
    now_seconds: i64,
) -> Result<KeyPackage> {
    AnonymousMlsRecipientDevice::new(
        verified.wire.device_id,
        verified.anonymous_delivery_public_key.clone(),
    )?;
    verified
        .wire
        .validate(now_seconds)
        .map_err(ChatError::Invalid)?;
    let bytes = BASE64
        .decode(&verified.wire.key_package)
        .map_err(|_| ChatError::Invalid("MLS KeyPackage is not canonical base64".into()))?;
    if BASE64.encode(&bytes) != verified.wire.key_package {
        return Err(ChatError::Invalid(
            "MLS KeyPackage is not canonical base64".into(),
        ));
    }
    let package = KeyPackageIn::tls_deserialize_exact(&bytes)
        .map_err(|error| mls_error("parse MLS KeyPackage", error))?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| mls_error("validate MLS KeyPackage", error))?;
    if package.ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE {
        return Err(ChatError::UnsupportedSuite(package.ciphersuite() as u16));
    }
    let reference = package
        .hash_ref(provider.crypto())
        .map_err(|error| mls_error("hash MLS KeyPackage", error))?;
    if hex::encode(reference.as_slice()) != verified.wire.key_package_ref {
        return Err(ChatError::Trust(
            "MLS KeyPackageRef does not match the claimed package".into(),
        ));
    }
    if package.leaf_node().credential().serialized_content()
        != verified.credential.credential_identity.as_bytes()
        || package.leaf_node().signature_key().as_slice()
            != verified.credential.credential_public_key
    {
        return Err(ChatError::Trust(
            "MLS KeyPackage credential differs from the transparency-verified manifest".into(),
        ));
    }
    Ok(package)
}

fn signer_for_group(provider: &KutupMlsProvider, group: &MlsGroup) -> Result<SignatureKeyPair> {
    let signature_key = group
        .own_leaf()
        .ok_or_else(|| ChatError::Trust("MLS group has no local leaf".into()))?
        .signature_key();
    SignatureKeyPair::read(
        provider.storage(),
        signature_key.as_slice(),
        group.ciphersuite().signature_algorithm(),
    )
    .ok_or_else(|| ChatError::MissingKeyMaterial("MLS leaf signing key is unavailable".into()))
}

fn insert_new_group_control_key(
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<()> {
    let key = BASE64.encode(mls_group_id);
    if metadata.group_control_private_keys.contains_key(&key) {
        return Err(ChatError::Trust(
            "refusing to replace an existing MLS group control key".into(),
        ));
    }
    let signing_key = P256SigningKey::random(&mut OsRng);
    metadata
        .group_control_private_keys
        .insert(key, signing_key.to_bytes().to_vec());
    Ok(())
}

fn authority_set_from_policies(
    authority_policies: &[MlsOrderingServicePolicyV1],
) -> Result<MlsAuthoritySetV1> {
    if !(1..=64).contains(&authority_policies.len()) {
        return Err(ChatError::Invalid(
            "MLS group genesis requires 1-64 ordering authorities".into(),
        ));
    }
    let mut policies = authority_policies.to_vec();
    for policy in &policies {
        policy.validate().map_err(ChatError::Invalid)?;
        if !policy.accepts_group_ordering {
            return Err(ChatError::Trust(format!(
                "MLS authority {} does not accept group ordering",
                policy.canonical_domain
            )));
        }
        if authority_policies.len() > usize::from(policy.maximum_authorities) {
            return Err(ChatError::Trust(format!(
                "MLS authority {} does not permit this authority-set size",
                policy.canonical_domain
            )));
        }
    }
    policies.sort_by(|left, right| left.canonical_domain.cmp(&right.canonical_domain));
    if policies
        .windows(2)
        .any(|window| window[0].canonical_domain == window[1].canonical_domain)
    {
        return Err(ChatError::Invalid(
            "MLS ordering authority domains must be unique".into(),
        ));
    }
    let authorities = policies
        .into_iter()
        .map(|policy| MlsAuthorityV1 {
            domain: policy.canonical_domain,
            key_id: policy.control_signing_key_id,
            public_key: policy.control_signing_public_key,
        })
        .collect::<Vec<_>>();
    let authority_set = MlsAuthoritySetV1 {
        sequence: 1,
        required_quorum: MlsAuthoritySetV1::quorum_for(authorities.len())
            .map_err(ChatError::Invalid)?,
        authorities,
    };
    authority_set.validate().map_err(ChatError::Invalid)?;
    Ok(authority_set)
}

fn insert_new_group_owner_key(
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<MlsGroupOwnerCredential> {
    let group_key = BASE64.encode(mls_group_id);
    if metadata.group_owner_private_keys.contains_key(&group_key) {
        return Err(ChatError::Trust(
            "refusing to replace an existing MLS group owner key".into(),
        ));
    }
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signer.verifying_key().as_bytes().to_vec();
    let credential = MlsGroupOwnerCredential {
        owner_id: hex::encode(Sha256::digest(&public_key)),
        public_key,
    };
    metadata
        .group_owner_private_keys
        .insert(group_key, seed.to_vec());
    Ok(credential)
}

fn ensure_group_owner_key<'a>(
    metadata: &'a SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<&'a [u8]> {
    metadata
        .group_owner_private_keys
        .get(&BASE64.encode(mls_group_id))
        .map(Vec::as_slice)
        .ok_or_else(|| {
            ChatError::MissingKeyMaterial("MLS group-scoped owner key is unavailable".into())
        })
}

fn group_owner_credential(
    metadata: &SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<MlsGroupOwnerCredential> {
    let private_key = ensure_group_owner_key(metadata, mls_group_id)?;
    let seed: [u8; 32] = private_key
        .try_into()
        .map_err(|_| ChatError::Db("invalid durable MLS group owner key".into()))?;
    let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .as_bytes()
        .to_vec();
    Ok(MlsGroupOwnerCredential {
        owner_id: hex::encode(Sha256::digest(&public_key)),
        public_key,
    })
}

fn ensure_group_control_key<'a>(
    metadata: &'a SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<&'a [u8]> {
    metadata
        .group_control_private_keys
        .get(&BASE64.encode(mls_group_id))
        .map(Vec::as_slice)
        .ok_or_else(|| {
            ChatError::MissingKeyMaterial("MLS group-scoped control key is unavailable".into())
        })
}

fn group_control_credential(
    metadata: &SnapshotMetadata,
    mls_group_id: &[u8],
) -> Result<MlsGroupControlCredential> {
    let private_key = ensure_group_control_key(metadata, mls_group_id)?;
    let signer = P256SigningKey::from_slice(private_key)
        .map_err(|_| ChatError::Db("invalid durable MLS group control key".into()))?;
    let public_key = signer
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    Ok(MlsGroupControlCredential {
        proposer_id: hex::encode(Sha256::digest(&public_key)),
        public_key,
    })
}

#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod tests;
