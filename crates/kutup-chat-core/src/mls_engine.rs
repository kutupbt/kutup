//! Durable OpenMLS client state for SelfSync, Direct, and Group conversations.
//!
//! OpenMLS owns the MLS state machine. This module supplies the Kutup-specific
//! persistence boundary and fixes the V1 ciphersuite/configuration. A provider
//! snapshot and the exact outbound ciphertext are committed in one [`ChatDb`]
//! transaction, so a crash can neither lose a consumed secret-tree generation
//! nor regenerate different ciphertext for the same logical send.

mod delivery;
mod state;

pub use delivery::{AnonymousMlsRecipientDevice, DerivedMlsDeliveryCapability};
use state::{provider_from_snapshot, snapshot_provider, KutupMlsProvider, SnapshotMetadata};

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use openmls::prelude::{
    Ciphersuite, Extensions, GroupId, KeyPackage, KeyPackageIn, Lifetime, Member, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, ProtocolVersion, Sender, StagedWelcome,
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

use crate::db::{ChatDb, MlsOutboxEntry, Pending};
use crate::error::{ChatError, Result};
use kutup_chat_proto::{
    roster_commitment, AccountAddress, CommitMlsControlBlockResponseV1, CommitMlsControlBlockV1,
    CreateMlsConversationRequestV1, FederatedMlsOrderingVoteRequestV1, MlsAuthoritySetV1,
    MlsAuthorityV1, MlsCipherSuiteId, MlsControlActionTypeV1, MlsControlBlockV1,
    MlsControlProposalV1, MlsConversationGenesisV1, MlsConversationKindV1, MlsConversationMemberV1,
    MlsFinalizedControlBlockV1, MlsKeyPackageV1, MlsManifestDeviceV1,
    MlsMembershipDeliveryCommitmentV1, MlsMembershipDeliveryV1, MlsMembershipEnvelopeKindV1,
    MlsMembershipEnvelopeV1, MlsMembershipTransitionV1, MlsOrderingQuorumCertificateV1,
    MlsOrderingServicePolicyV1, MlsOwnerSetV1, MlsOwnerV1,
    MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256, MLS_PROTOCOL_VERSION,
};

const STATE_FORMAT_VERSION: u16 = 4;
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
    pub last_finalized_height: u64,
    pub last_finalized_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_block_hash: Option<String>,
    pub current_roster: Vec<MlsConversationMemberV1>,
    pub current_authority_set: MlsAuthoritySetV1,
    pub current_owner_set: MlsOwnerSetV1,
}

/// Atomic result of preparing an epoch-zero group and its exact server
/// publication request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedMlsGroupGenesis {
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
/// [`MlsClient::join_from_welcome`].
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
    pub fn new(db: Rc<dyn ChatDb>) -> Self {
        Self { db }
    }

    /// Parse and authenticate an untrusted KeyPackage against the exact
    /// transparency-verified manifest credential before it is used in a
    /// membership proposal.
    pub fn validate_verified_key_package(
        verified: &VerifiedMlsKeyPackage,
        now_seconds: i64,
    ) -> Result<()> {
        parse_verified_key_package(&KutupMlsProvider::default(), verified, now_seconds).map(|_| ())
    }

    /// Install a new P-256 MLS credential and independent anonymous-delivery
    /// HPKE key, or reopen the exact existing identity. A different identity
    /// never replaces keys implicitly.
    pub async fn initialize(
        &self,
        canonical_device_identity: &str,
    ) -> Result<MlsDevicePublicMaterial> {
        validate_credential_identity(canonical_device_identity)?;
        if let Some(bytes) = self.db.load_mls_state().await? {
            let (_, metadata) = provider_from_snapshot(&bytes)?;
            if metadata.credential_identity != canonical_device_identity {
                return Err(ChatError::Trust(
                    "MLS device identity differs from the durable credential; explicit device rotation is required"
                        .into(),
                ));
            }
            return metadata.public_material();
        }

        let provider = KutupMlsProvider::default();
        let signer = SignatureKeyPair::new(KUTUP_MLS_V1_CIPHERSUITE.signature_algorithm())
            .map_err(|error| mls_error("generate MLS credential", error))?;
        signer
            .store(provider.storage())
            .map_err(|error| mls_error("store MLS credential", error))?;

        let anonymous_private_key = p256::SecretKey::random(&mut OsRng);
        let metadata = SnapshotMetadata {
            credential_identity: canonical_device_identity.to_owned(),
            credential_public_key: signer.to_public_vec(),
            anonymous_delivery_private_key: anonymous_private_key.to_bytes().to_vec(),
            pending_commits: BTreeMap::new(),
            pending_membership_changes: BTreeMap::new(),
            group_control_private_keys: BTreeMap::new(),
            group_owner_private_keys: BTreeMap::new(),
            conversations: BTreeMap::new(),
        };
        let state = snapshot_provider(&provider, &metadata)?;
        let mut pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        pending.clear();
        metadata.public_material()
    }

    /// Generate and durably retain a one-time KeyPackage before returning its
    /// public bytes. The server can therefore never receive a KeyPackage whose
    /// matching private init key was lost in a client crash.
    pub async fn generate_key_package(
        &self,
        manifest_version: u64,
        device_id: u32,
        now_seconds: i64,
        expires_at_seconds: i64,
    ) -> Result<MlsKeyPackageV1> {
        if manifest_version == 0 || device_id == 0 || now_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS KeyPackage requires a manifest, device, and valid clock".into(),
            ));
        }
        let lifetime = expires_at_seconds
            .checked_sub(now_seconds)
            .ok_or_else(|| ChatError::Invalid("MLS KeyPackage expiry overflow".into()))?;
        if lifetime <= 0 || lifetime > MAX_KEY_PACKAGE_LIFETIME_SECONDS {
            return Err(ChatError::Invalid(
                "MLS KeyPackage lifetime must be within 84 days".into(),
            ));
        }

        let (provider, metadata) = self.load_provider().await?;
        let signer = metadata.read_signer(&provider)?;
        let credential = metadata.credential();
        let not_before = u64::try_from(now_seconds)
            .map_err(|_| ChatError::Invalid("negative MLS KeyPackage clock".into()))?
            .saturating_sub(KEY_PACKAGE_CLOCK_SKEW_SECONDS);
        let not_after = u64::try_from(expires_at_seconds)
            .map_err(|_| ChatError::Invalid("negative MLS KeyPackage expiry".into()))?;
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(not_before, not_after))
            .key_package_extensions(Extensions::default())
            .build(KUTUP_MLS_V1_CIPHERSUITE, &provider, &signer, credential)
            .map_err(|error| mls_error("create MLS KeyPackage", error))?;
        let package = bundle.key_package();
        if package.ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE {
            return Err(ChatError::Protocol(
                "OpenMLS produced a KeyPackage for a non-Kutup suite".into(),
            ));
        }
        let package_bytes = package
            .tls_serialize_detached()
            .map_err(|error| mls_error("serialize MLS KeyPackage", error))?;
        let package_ref = package
            .hash_ref(provider.crypto())
            .map_err(|error| mls_error("hash MLS KeyPackage", error))?;
        let wire = MlsKeyPackageV1 {
            device_id,
            manifest_version,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            key_package_ref: hex::encode(package_ref.as_slice()),
            key_package: BASE64.encode(package_bytes),
            expires_at: expires_at_seconds,
        };
        wire.validate(now_seconds).map_err(ChatError::Invalid)?;

        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(wire)
    }

    /// Atomically create an epoch-zero group, its unlinkable owner credential,
    /// and the exact authenticated request that must be retried at the server.
    /// An OpenMLS group without the matching durable genesis record is treated
    /// as corruption and is never repaired by silently minting new metadata.
    pub async fn prepare_group_genesis(
        &self,
        conversation_id: Uuid,
        mls_group_id: &[u8],
        creator: AccountAddress,
        authority_policies: &[MlsOrderingServicePolicyV1],
        created_at_seconds: i64,
    ) -> Result<PreparedMlsGroupGenesis> {
        if conversation_id.is_nil() || created_at_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS group genesis requires a conversation id and valid clock".into(),
            ));
        }
        validate_group_id(mls_group_id)?;
        let authority_set = authority_set_from_policies(authority_policies)?;
        let group_key = BASE64.encode(mls_group_id);
        let conversation_key = conversation_id.to_string();
        let (provider, mut metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);

        if let Some(existing) = metadata.conversations.get(&conversation_key) {
            let group = MlsGroup::load(provider.storage(), &group_id)
                .map_err(|error| mls_error("load MLS group", error))?
                .ok_or_else(|| {
                    ChatError::Db("durable MLS genesis record has no matching OpenMLS group".into())
                })?;
            ensure_v1_group(&group)?;
            ensure_group_control_key(&metadata, mls_group_id)?;
            ensure_group_owner_key(&metadata, mls_group_id)?;
            if existing.request.genesis.mls_group_id != group_key
                || existing.request.genesis.created_at != created_at_seconds
                || existing.request.genesis.authority_set != authority_set
                || existing.request.members.len() != 1
                || existing.request.members[0].address != creator
            {
                return Err(ChatError::Trust(
                    "MLS conversation id is already bound to a different genesis".into(),
                ));
            }
            return Ok(PreparedMlsGroupGenesis {
                group: local_group_state(&group),
                conversation: existing.clone(),
            });
        }
        if metadata
            .conversations
            .values()
            .any(|record| record.request.genesis.mls_group_id == group_key)
        {
            return Err(ChatError::Trust(
                "MLS GroupId is already bound to another conversation".into(),
            ));
        }
        if MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .is_some()
            || metadata.group_control_private_keys.contains_key(&group_key)
            || metadata.group_owner_private_keys.contains_key(&group_key)
        {
            return Err(ChatError::Trust(
                "OpenMLS group exists without an exact durable genesis record".into(),
            ));
        }

        let signer = metadata.read_signer(&provider)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(KUTUP_MLS_V1_CIPHERSUITE)
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            group_id,
            metadata.credential(),
        )
        .map_err(|error| mls_error("create MLS group", error))?;
        ensure_v1_group(&group)?;
        insert_new_group_control_key(&mut metadata, mls_group_id)?;
        let owner = insert_new_group_owner_key(&mut metadata, mls_group_id)?;
        let member = MlsConversationMemberV1 {
            address: creator,
            is_admin: true,
            owner_id: Some(owner.owner_id.clone()),
        };
        let members = vec![member];
        let request = CreateMlsConversationRequestV1 {
            genesis: MlsConversationGenesisV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id,
                incarnation: 1,
                mls_group_id: group_key,
                kind: MlsConversationKindV1::Group,
                suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
                roster_commitment: roster_commitment(&members).map_err(ChatError::Invalid)?,
                member_count: 1,
                authority_set,
                owner_set: Some(MlsOwnerSetV1 {
                    sequence: 1,
                    owners: vec![MlsOwnerV1 {
                        owner_id: owner.owner_id,
                        public_key: BASE64.encode(owner.public_key),
                    }],
                    required_quorum: 1,
                }),
                initial_epoch: 0,
                created_at: created_at_seconds,
            },
            members,
        };
        request.validate().map_err(ChatError::Invalid)?;
        let current_owner_set = request.genesis.owner_set.clone().ok_or_else(|| {
            ChatError::Protocol("validated group genesis has no owner set".into())
        })?;
        let conversation = LocalMlsConversationRecord {
            last_finalized_height: 0,
            last_finalized_epoch: request.genesis.initial_epoch,
            last_block_hash: None,
            current_roster: request.members.clone(),
            current_authority_set: request.genesis.authority_set.clone(),
            current_owner_set,
            request,
            status: LocalMlsConversationStatus::PendingGenesis,
            server_genesis_hash: None,
        };
        metadata
            .conversations
            .insert(conversation_key, conversation.clone());
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(PreparedMlsGroupGenesis {
            group: public,
            conversation,
        })
    }

    /// Return every exact local conversation record in canonical UUID order.
    pub async fn local_conversations(&self) -> Result<Vec<LocalMlsConversationRecord>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata.conversations.values().cloned().collect())
    }

    /// Mark one pending genesis active only after the server acknowledges the
    /// exact canonical genesis digest. Replays with the same digest are
    /// idempotent; a different digest is a durable trust failure.
    pub async fn mark_group_genesis_published(
        &self,
        conversation_id: Uuid,
        server_genesis_hash: &str,
    ) -> Result<LocalMlsConversationRecord> {
        if conversation_id.is_nil() {
            return Err(ChatError::Invalid(
                "MLS conversation id must not be nil".into(),
            ));
        }
        validate_sha256_hex("MLS genesis hash", server_genesis_hash)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let record = metadata
            .conversations
            .get_mut(&conversation_id.to_string())
            .ok_or_else(|| ChatError::Trust("local MLS genesis record is unavailable".into()))?;
        let expected_hash = record
            .request
            .genesis
            .genesis_hash()
            .map_err(ChatError::Protocol)?;
        if expected_hash != server_genesis_hash {
            return Err(ChatError::Trust(
                "server acknowledged a different MLS genesis".into(),
            ));
        }
        if let Some(existing) = &record.server_genesis_hash {
            if existing != server_genesis_hash
                || record.status != LocalMlsConversationStatus::Active
            {
                return Err(ChatError::Db(
                    "durable MLS genesis acknowledgement is inconsistent".into(),
                ));
            }
            return Ok(record.clone());
        }
        record.status = LocalMlsConversationStatus::Active;
        record.server_genesis_hash = Some(server_genesis_hash.to_owned());
        let result = record.clone();
        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(result)
    }

    /// Return the public group-scoped owner credential without exposing its
    /// signing seed.
    pub async fn group_owner_credential(
        &self,
        mls_group_id: &[u8],
    ) -> Result<MlsGroupOwnerCredential> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        group_owner_credential(&metadata, mls_group_id)
    }

    /// Create an epoch-zero group using the authenticated genesis `GroupId`.
    /// Existing group state is returned idempotently and is never overwritten.
    #[cfg(test)]
    pub(crate) async fn create_group(&self, mls_group_id: &[u8]) -> Result<LocalMlsGroupState> {
        validate_group_id(mls_group_id)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        if let Some(group) = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
        {
            ensure_v1_group(&group)?;
            ensure_group_control_key(&metadata, mls_group_id)?;
            return Ok(local_group_state(&group));
        }

        let signer = metadata.read_signer(&provider)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(KUTUP_MLS_V1_CIPHERSUITE)
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            group_id,
            metadata.credential(),
        )
        .map_err(|error| mls_error("create MLS group", error))?;
        ensure_v1_group(&group)?;
        let public = local_group_state(&group);
        insert_new_group_control_key(&mut metadata, mls_group_id)?;
        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(public)
    }

    /// Return an existing group's public state without creating or replacing
    /// it. Browser orchestration uses this to resume the server half of an
    /// invitation acceptance after a crash or network failure.
    pub async fn group_state(&self, mls_group_id: &[u8]) -> Result<Option<LocalMlsGroupState>> {
        validate_group_id(mls_group_id)?;
        let (provider, metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        let Some(group) = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
        else {
            return Ok(None);
        };
        ensure_v1_group(&group)?;
        ensure_group_control_key(&metadata, mls_group_id)?;
        Ok(Some(local_group_state(&group)))
    }

    /// Atomically stage one add-only or remove-only group membership change,
    /// including the OpenMLS pending Commit and the exact pseudonymous
    /// control-plane retry material. Ordinary membership changes cannot alter
    /// administrators or owners; those use their own authorization actions.
    pub async fn prepare_membership_change(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        next_roster: &[MlsConversationMemberV1],
        additions: &[VerifiedMlsKeyPackage],
        created_at_seconds: i64,
    ) -> Result<PreparedMlsMembershipChange> {
        validate_group_id(mls_group_id)?;
        if proposal_id.is_nil() || created_at_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS membership change requires a proposal id and valid clock".into(),
            ));
        }
        validate_group_roster(next_roster)?;
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if let Some(existing) = metadata.pending_membership_changes.get(&group_key) {
            if existing.transition.proposal_id == proposal_id && existing.next_roster == next_roster
            {
                let pending = metadata
                    .pending_commits
                    .get(&group_key)
                    .ok_or_else(|| {
                        ChatError::Db("durable MLS membership control has no pending Commit".into())
                    })?
                    .clone();
                return Ok(PreparedMlsMembershipChange {
                    pending,
                    control: existing.clone(),
                });
            }
            return Err(ChatError::Trust(
                "another MLS membership control operation is already pending".into(),
            ));
        }
        let conversation = metadata
            .conversations
            .values()
            .find(|record| record.request.genesis.mls_group_id == group_key)
            .cloned()
            .ok_or_else(|| {
                ChatError::Trust("local MLS conversation control state is unavailable".into())
            })?;
        if conversation.status != LocalMlsConversationStatus::Active {
            return Err(ChatError::Trust(
                "MLS membership cannot change before exact genesis publication".into(),
            ));
        }
        validate_local_control_state(&conversation)?;
        let group_id = GroupId::from_slice(mls_group_id);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        if group.epoch().as_u64() != conversation.last_finalized_epoch {
            return Err(ChatError::Trust(
                "OpenMLS epoch differs from the pinned control-log epoch".into(),
            ));
        }
        let current_devices = group
            .members()
            .map(|member| {
                let identity = std::str::from_utf8(member.credential.serialized_content())
                    .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?;
                let (address, device_id) = parse_device_credential_identity(identity)?;
                Ok((address, device_id, identity.to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;
        let current_by_address = roster_by_address(&conversation.current_roster)?;
        let next_by_address = roster_by_address(next_roster)?;
        let added_accounts = next_by_address
            .keys()
            .filter(|address| !current_by_address.contains_key(*address))
            .cloned()
            .collect::<Vec<_>>();
        let removed_accounts = current_by_address
            .keys()
            .filter(|address| !next_by_address.contains_key(*address))
            .cloned()
            .collect::<Vec<_>>();
        if added_accounts.is_empty() == removed_accounts.is_empty()
            || (!added_accounts.is_empty() && !removed_accounts.is_empty())
        {
            return Err(ChatError::Invalid(
                "V1 MLS membership control must be exactly one add-only or remove-only change"
                    .into(),
            ));
        }
        for (address, current) in &current_by_address {
            if let Some(next) = next_by_address.get(address) {
                if current != next {
                    return Err(ChatError::Invalid(
                        "membership control cannot also change administrator or owner roles".into(),
                    ));
                }
            }
        }
        let current_owner_assignments = conversation
            .current_roster
            .iter()
            .filter_map(|member| {
                member
                    .owner_id
                    .as_ref()
                    .map(|owner_id| (member.address.canonical(), owner_id.as_str()))
            })
            .collect::<BTreeMap<_, _>>();
        let next_owner_assignments = next_roster
            .iter()
            .filter_map(|member| {
                member
                    .owner_id
                    .as_ref()
                    .map(|owner_id| (member.address.canonical(), owner_id.as_str()))
            })
            .collect::<BTreeMap<_, _>>();
        if current_owner_assignments != next_owner_assignments {
            return Err(ChatError::Invalid(
                "ordinary membership control cannot transfer, add, or remove owners".into(),
            ));
        }

        let pending = if !added_accounts.is_empty() {
            let mut packaged_accounts = BTreeMap::<String, usize>::new();
            for addition in additions {
                let (address, device_id) =
                    parse_device_credential_identity(&addition.credential.credential_identity)?;
                if addition.wire.device_id != device_id
                    || !added_accounts.iter().any(|added| added == &address)
                {
                    return Err(ChatError::Trust(
                        "MLS addition KeyPackage does not belong to an added account".into(),
                    ));
                }
                *packaged_accounts.entry(address).or_default() += 1;
            }
            if additions.is_empty()
                || added_accounts
                    .iter()
                    .any(|address| !packaged_accounts.contains_key(address))
            {
                return Err(ChatError::Invalid(
                    "every added MLS account requires at least one verified KeyPackage".into(),
                ));
            }
            stage_add_members(
                &provider,
                &mut metadata,
                mls_group_id,
                additions,
                created_at_seconds,
            )?
        } else {
            if !additions.is_empty() {
                return Err(ChatError::Invalid(
                    "remove-only MLS membership control cannot carry KeyPackages".into(),
                ));
            }
            let removed_identities = current_devices
                .iter()
                .filter(|(address, _, _)| removed_accounts.iter().any(|item| item == address))
                .map(|(_, _, identity)| identity.clone())
                .collect::<Vec<_>>();
            if removed_identities.is_empty() {
                return Err(ChatError::Trust(
                    "removed MLS account has no credential in the current group".into(),
                ));
            }
            stage_remove_members(&provider, &mut metadata, mls_group_id, &removed_identities)?
        };
        let control = build_pending_membership_change(
            &metadata,
            &conversation,
            mls_group_id,
            proposal_id,
            next_roster,
            additions,
            &current_devices,
            &pending,
            created_at_seconds,
        )?;
        metadata
            .pending_membership_changes
            .insert(group_key, control.clone());
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(PreparedMlsMembershipChange { pending, control })
    }

    /// Return every exact pending membership operation in canonical GroupId
    /// order for restart and network reconciliation.
    pub async fn pending_membership_changes(&self) -> Result<Vec<PendingMlsMembershipChange>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata
            .pending_membership_changes
            .values()
            .cloned()
            .collect())
    }

    /// Authenticate an ordering quorum certificate against the pinned
    /// authority set and construct the exact final server request. JavaScript
    /// never decides whether authority signatures meet quorum.
    pub async fn build_membership_commit_request(
        &self,
        mls_group_id: &[u8],
        quorum_certificate: MlsOrderingQuorumCertificateV1,
    ) -> Result<CommitMlsControlBlockV1> {
        validate_group_id(mls_group_id)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let control = metadata
            .pending_membership_changes
            .get_mut(&BASE64.encode(mls_group_id))
            .ok_or_else(|| {
                ChatError::Trust("pending MLS membership control is unavailable".into())
            })?;
        if let Some(request) = &control.final_request {
            return Ok(request.clone());
        }
        let block = &control.vote_request.block;
        quorum_certificate
            .verify(&control.vote_request.authority_set)
            .map_err(ChatError::Trust)?;
        if quorum_certificate.block_hash != block.block_hash().map_err(ChatError::Protocol)?
            || quorum_certificate.height != block.height
        {
            return Err(ChatError::Trust(
                "MLS quorum certificate finalizes a different control block".into(),
            ));
        }
        let request = CommitMlsControlBlockV1 {
            finalized: MlsFinalizedControlBlockV1 {
                block: block.clone(),
                quorum_certificate,
            },
            membership_transition: Some(control.transition.clone()),
            next_authority_set: None,
            authority_transition: None,
            next_owner_set: None,
        };
        request.validate_shape().map_err(ChatError::Protocol)?;
        control.final_request = Some(request.clone());
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(request)
    }

    /// Merge the staged OpenMLS Commit and advance the durable client control
    /// pin only when the server acknowledges the exact prepared block.
    pub async fn finalize_membership_change(
        &self,
        mls_group_id: &[u8],
        acknowledgement: &CommitMlsControlBlockResponseV1,
    ) -> Result<FinalizedMlsMembershipChange> {
        validate_group_id(mls_group_id)?;
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        let Some(control) = metadata.pending_membership_changes.get(&group_key).cloned() else {
            let conversation = metadata
                .conversations
                .values()
                .find(|record| record.request.genesis.mls_group_id == group_key)
                .cloned()
                .ok_or_else(|| {
                    ChatError::Trust("local MLS conversation control state is unavailable".into())
                })?;
            if conversation.last_finalized_height != acknowledgement.height
                || conversation.last_finalized_epoch != acknowledgement.epoch
                || conversation.last_block_hash.as_deref()
                    != Some(acknowledgement.block_hash.as_str())
            {
                return Err(ChatError::Trust(
                    "MLS membership acknowledgement has no matching durable operation".into(),
                ));
            }
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
                .map_err(|error| mls_error("load MLS group", error))?
                .ok_or_else(|| {
                    ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
                })?;
            return Ok(FinalizedMlsMembershipChange {
                group: local_group_state(&group),
                conversation,
            });
        };
        let block = &control.vote_request.block;
        let expected_hash = block.block_hash().map_err(ChatError::Protocol)?;
        if acknowledgement.conversation_id != block.conversation_id
            || acknowledgement.incarnation != block.incarnation
            || acknowledgement.height != block.height
            || acknowledgement.epoch != block.epoch_after
            || acknowledgement.block_hash != expected_hash
        {
            return Err(ChatError::Trust(
                "server acknowledged a different MLS membership block".into(),
            ));
        }
        let pending = metadata
            .pending_commits
            .get(&group_key)
            .ok_or_else(|| ChatError::Db("pending MLS membership Commit is unavailable".into()))?;
        if pending.commit_hash != control.commit_hash
            || pending.epoch_before != block.epoch_before
            || pending.epoch_after != block.epoch_after
        {
            return Err(ChatError::Db(
                "pending MLS Commit differs from its control retry material".into(),
            ));
        }
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        if group.epoch().as_u64() != pending.epoch_before || group.pending_commit().is_none() {
            return Err(ChatError::Trust(
                "durable MLS pending state does not match its control record".into(),
            ));
        }
        group
            .merge_pending_commit(&provider)
            .map_err(|error| mls_error("merge pending MLS membership commit", error))?;
        if group.epoch().as_u64() != block.epoch_after {
            return Err(ChatError::Trust(
                "merged MLS epoch differs from the finalized membership block".into(),
            ));
        }
        metadata.pending_commits.remove(&group_key);
        metadata.pending_membership_changes.remove(&group_key);
        let conversation = metadata
            .conversations
            .get_mut(&block.conversation_id.to_string())
            .ok_or_else(|| ChatError::Db("local MLS conversation record is unavailable".into()))?;
        if conversation.last_finalized_height.saturating_add(1) != block.height
            || conversation.last_finalized_epoch != block.epoch_before
            || conversation.last_block_hash != block.previous_block_hash
        {
            return Err(ChatError::Trust(
                "finalized MLS membership block does not extend the local control pin".into(),
            ));
        }
        conversation.last_finalized_height = block.height;
        conversation.last_finalized_epoch = block.epoch_after;
        conversation.last_block_hash = Some(expected_hash);
        conversation.current_roster = control.next_roster;
        let conversation = conversation.clone();
        let group = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(FinalizedMlsMembershipChange {
            group,
            conversation,
        })
    }

    /// Stage an add-members Commit after validating every claimed KeyPackage
    /// against a transparency-verified manifest credential. The pending
    /// OpenMLS state and exact Commit/Welcome bytes are persisted atomically.
    #[cfg(test)]
    pub(crate) async fn prepare_add_members(
        &self,
        mls_group_id: &[u8],
        additions: &[VerifiedMlsKeyPackage],
        now_seconds: i64,
    ) -> Result<PendingMlsCommit> {
        let (provider, mut metadata) = self.load_provider().await?;
        let pending = stage_add_members(
            &provider,
            &mut metadata,
            mls_group_id,
            additions,
            now_seconds,
        )?;
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(pending)
    }

    /// Stage a remove-members Commit using exact current credential
    /// identities. The same durable ordering boundary as additions applies.
    #[cfg(test)]
    pub(crate) async fn prepare_remove_members(
        &self,
        mls_group_id: &[u8],
        removed_credential_identities: &[String],
    ) -> Result<PendingMlsCommit> {
        let (provider, mut metadata) = self.load_provider().await?;
        let pending = stage_remove_members(
            &provider,
            &mut metadata,
            mls_group_id,
            removed_credential_identities,
        )?;
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(pending)
    }

    /// Return exact retry material for a staged membership commit after a
    /// restart. A missing record never causes the engine to regenerate one.
    pub async fn pending_commit(&self, mls_group_id: &[u8]) -> Result<Option<PendingMlsCommit>> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata
            .pending_commits
            .get(&BASE64.encode(mls_group_id))
            .cloned())
    }

    /// Merge the locally staged Commit only after the authenticated ordering
    /// block binds its exact SHA-256 digest.
    pub async fn merge_pending_commit(
        &self,
        mls_group_id: &[u8],
        expected_commit_hash: &str,
    ) -> Result<LocalMlsGroupState> {
        validate_group_id(mls_group_id)?;
        validate_sha256_hex("MLS commit hash", expected_commit_hash)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let pending_key = BASE64.encode(mls_group_id);
        let pending = metadata
            .pending_commits
            .get(&pending_key)
            .ok_or_else(|| ChatError::Trust("MLS commit retry material is unavailable".into()))?;
        if pending.commit_hash != expected_commit_hash {
            return Err(ChatError::Trust(
                "ordered MLS commit differs from the locally staged commit".into(),
            ));
        }
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        if group.epoch().as_u64() != pending.epoch_before || group.pending_commit().is_none() {
            return Err(ChatError::Trust(
                "durable MLS pending state does not match its retry record".into(),
            ));
        }
        group
            .merge_pending_commit(&provider)
            .map_err(|error| mls_error("merge pending MLS commit", error))?;
        if group.epoch().as_u64() != pending.epoch_after {
            return Err(ChatError::Trust(
                "merged MLS epoch differs from the ordered transition".into(),
            ));
        }
        metadata.pending_commits.remove(&pending_key);
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(public)
    }

    /// Clear a locally staged Commit only after the ordering layer has
    /// cryptographically finalized a conflicting block. This is an explicit
    /// recovery operation and never happens as an automatic fallback.
    pub async fn reject_pending_commit(
        &self,
        mls_group_id: &[u8],
        rejected_commit_hash: &str,
    ) -> Result<()> {
        validate_group_id(mls_group_id)?;
        validate_sha256_hex("MLS commit hash", rejected_commit_hash)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let pending_key = BASE64.encode(mls_group_id);
        let pending = metadata
            .pending_commits
            .get(&pending_key)
            .ok_or_else(|| ChatError::Trust("MLS commit retry material is unavailable".into()))?;
        if pending.commit_hash != rejected_commit_hash {
            return Err(ChatError::Trust(
                "refusing to clear an unrelated MLS pending commit".into(),
            ));
        }
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        group
            .clear_pending_commit(provider.storage())
            .map_err(|error| mls_error("clear rejected MLS commit", error))?;
        metadata.pending_commits.remove(&pending_key);
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await
    }

    /// Join from a Welcome only when its full resulting roster exactly matches
    /// transparency-verified MLS device credentials supplied by the caller.
    pub async fn join_from_welcome(
        &self,
        expected_group_id: &[u8],
        welcome_bytes: &[u8],
        expected_members: &[VerifiedMlsCredential],
    ) -> Result<LocalMlsGroupState> {
        validate_group_id(expected_group_id)?;
        if welcome_bytes.is_empty()
            || welcome_bytes.len() > MAX_APPLICATION_BYTES
            || expected_members.is_empty()
            || expected_members.len() > 1000
        {
            return Err(ChatError::Invalid(
                "MLS Welcome or expected roster is outside v1 bounds".into(),
            ));
        }
        let (provider, mut metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(expected_group_id);
        if MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .is_some()
        {
            return Err(ChatError::Trust(
                "refusing to replace an existing MLS group from a Welcome".into(),
            ));
        }
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|error| mls_error("parse MLS Welcome", error))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(ChatError::Invalid("expected an MLS Welcome message".into())),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|error| mls_error("stage MLS Welcome", error))?;
        if staged.group_context().group_id().as_slice() != expected_group_id
            || staged.group_context().ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE
        {
            return Err(ChatError::Trust(
                "MLS Welcome group or ciphersuite differs from authenticated genesis".into(),
            ));
        }
        verify_exact_roster(staged.members(), expected_members)?;
        let group = staged
            .into_group(&provider)
            .map_err(|error| mls_error("join MLS group", error))?;
        ensure_v1_group(&group)?;
        insert_new_group_control_key(&mut metadata, expected_group_id)?;
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(public)
    }

    /// Decrypt and inspect a Welcome without installing its group. The
    /// returned identities and keys are claims, not trust evidence.
    pub async fn inspect_welcome(
        &self,
        expected_group_id: &[u8],
        welcome_bytes: &[u8],
    ) -> Result<MlsWelcomeInspection> {
        validate_group_id(expected_group_id)?;
        if welcome_bytes.is_empty() || welcome_bytes.len() > MAX_APPLICATION_BYTES {
            return Err(ChatError::Invalid(
                "MLS Welcome is outside v1 bounds".into(),
            ));
        }
        let (provider, _) = self.load_provider().await?;
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|error| mls_error("parse MLS Welcome", error))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(ChatError::Invalid("expected an MLS Welcome message".into())),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|error| mls_error("stage MLS Welcome", error))?;
        if staged.group_context().group_id().as_slice() != expected_group_id
            || staged.group_context().ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE
        {
            return Err(ChatError::Trust(
                "MLS Welcome group or ciphersuite differs from authenticated genesis".into(),
            ));
        }
        let mut claimed_members = Vec::new();
        let mut identities = HashSet::new();
        for member in staged.members() {
            let identity = std::str::from_utf8(member.credential.serialized_content())
                .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?
                .to_owned();
            validate_credential_identity(&identity)?;
            let credential_public_key = member.signature_key.as_slice().to_vec();
            validate_credential_public_key(&credential_public_key)?;
            if !identities.insert(identity.clone()) {
                return Err(ChatError::Trust(
                    "MLS Welcome repeats a credential identity".into(),
                ));
            }
            claimed_members.push(ClaimedMlsCredential {
                credential_identity: identity,
                credential_public_key,
            });
        }
        if claimed_members.is_empty() || claimed_members.len() > 1000 {
            return Err(ChatError::Trust(
                "MLS Welcome roster is outside v1 bounds".into(),
            ));
        }
        claimed_members
            .sort_by(|left, right| left.credential_identity.cmp(&right.credential_identity));
        Ok(MlsWelcomeInspection {
            mls_group_id: expected_group_id.to_vec(),
            epoch: staged.group_context().epoch().as_u64(),
            claimed_members,
        })
    }

    /// Apply a remotely authored Commit only after the ordered encrypted
    /// control action has produced the exact expected next roster.
    pub async fn apply_inbound_commit(
        &self,
        mls_group_id: &[u8],
        commit_bytes: &[u8],
        expected_next_members: &[VerifiedMlsCredential],
    ) -> Result<LocalMlsGroupState> {
        validate_group_id(mls_group_id)?;
        if commit_bytes.is_empty()
            || commit_bytes.len() > MAX_APPLICATION_BYTES
            || expected_next_members.is_empty()
            || expected_next_members.len() > 1000
        {
            return Err(ChatError::Invalid(
                "MLS Commit or expected roster is outside v1 bounds".into(),
            ));
        }
        let (provider, metadata) = self.load_provider().await?;
        if metadata
            .pending_commits
            .contains_key(&BASE64.encode(mls_group_id))
        {
            return Err(ChatError::Trust(
                "cannot merge a remote MLS Commit while a local Commit is pending".into(),
            ));
        }
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let epoch_before = group.epoch().as_u64();
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|error| mls_error("parse MLS Commit", error))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Invalid("expected an MLS protocol message".into()))?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| mls_error("process MLS Commit", error))?;
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            _ => return Err(ChatError::Invalid("expected an MLS Commit message".into())),
        };
        if staged.epoch().as_u64() != epoch_before.saturating_add(1) {
            return Err(ChatError::Trust(
                "inbound MLS Commit does not advance exactly one epoch".into(),
            ));
        }
        group
            .merge_staged_commit(&provider, *staged)
            .map_err(|error| mls_error("merge inbound MLS Commit", error))?;
        verify_exact_roster(group.members(), expected_next_members)?;
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(public)
    }

    /// Decrypt one application message and persist the consumed secret-tree
    /// generation only after the sender's current manifest credential matches
    /// the MLS leaf exactly.
    pub async fn decrypt_application_message(
        &self,
        mls_group_id: &[u8],
        ciphertext: &[u8],
        expected_sender: &VerifiedMlsCredential,
    ) -> Result<DecryptedMlsApplication> {
        validate_group_id(mls_group_id)?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_APPLICATION_BYTES {
            return Err(ChatError::Invalid(
                "MLS application ciphertext is outside v1 bounds".into(),
            ));
        }
        let (provider, metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| mls_error("parse MLS application message", error))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Invalid("expected an MLS protocol message".into()))?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| mls_error("process MLS application message", error))?;
        let epoch = processed.epoch().as_u64();
        let sender_index = match processed.sender() {
            Sender::Member(index) => *index,
            _ => {
                return Err(ChatError::Trust(
                    "MLS application message was not sent by a group member".into(),
                ))
            }
        };
        let member = group
            .members()
            .find(|member| member.index == sender_index)
            .ok_or_else(|| ChatError::Trust("MLS sender leaf is absent".into()))?;
        verify_member_credential(&member, expected_sender)?;
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            _ => {
                return Err(ChatError::Invalid(
                    "expected an MLS application message".into(),
                ))
            }
        };
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(DecryptedMlsApplication {
            plaintext,
            epoch,
            sender: expected_sender.clone(),
        })
    }

    /// Return the unlinkable group-scoped credential that members must bind
    /// inside the MLS-encrypted control payload.
    pub async fn group_control_credential(
        &self,
        mls_group_id: &[u8],
    ) -> Result<MlsGroupControlCredential> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        group_control_credential(&metadata, mls_group_id)
    }

    /// Sign the pseudonymous outer authorization for an MLS-encrypted control
    /// payload. The proposal contains no account address or account-wide
    /// device key. Its random group-scoped key is bound inside the encrypted
    /// payload so members retain accountability without giving external
    /// authorities a cross-group correlation handle.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_control_proposal(
        &self,
        mls_group_id: &[u8],
        conversation_id: Uuid,
        incarnation: u64,
        proposal_id: Uuid,
        base_epoch: u64,
        action_type: MlsControlActionTypeV1,
        encrypted_payload: &[u8],
        created_at_seconds: i64,
    ) -> Result<MlsControlProposalV1> {
        validate_group_id(mls_group_id)?;
        if conversation_id.is_nil()
            || proposal_id.is_nil()
            || incarnation == 0
            || encrypted_payload.is_empty()
            || encrypted_payload.len() > MAX_APPLICATION_BYTES
            || created_at_seconds < 0
        {
            return Err(ChatError::Invalid(
                "MLS control proposal has invalid ids, payload, or clock".into(),
            ));
        }
        let (_, metadata) = self.load_provider().await?;
        let key_bytes = ensure_group_control_key(&metadata, mls_group_id)?;
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

    /// Encrypt one application message and atomically persist both the
    /// resulting OpenMLS secret-tree state and the exact retry ciphertext.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_application_message(
        &self,
        send_id: &str,
        conversation_id: [u8; 16],
        incarnation: u64,
        mls_group_id: &[u8],
        plaintext: &[u8],
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        validate_send(
            send_id,
            conversation_id,
            incarnation,
            mls_group_id,
            plaintext,
            created_at_ms,
        )?;
        let content_digest: [u8; 32] = Sha256::digest(plaintext).into();

        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            if existing.conversation_id != conversation_id
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || existing.content_digest != content_digest
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to different content or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (provider, metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let signer_public_key = group
            .own_leaf_node()
            .ok_or_else(|| ChatError::Trust("MLS group has no local leaf".into()))?
            .signature_key()
            .as_slice();
        let signer = SignatureKeyPair::read(
            provider.storage(),
            signer_public_key,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
        )
        .ok_or_else(|| {
            ChatError::MissingKeyMaterial("MLS leaf signing key is unavailable".into())
        })?;
        let epoch = group.epoch().as_u64();
        let ciphertext = group
            .create_message(&provider, &signer, plaintext)
            .map_err(|error| mls_error("create MLS application message", error))?
            .to_bytes()
            .map_err(|error| mls_error("serialize MLS application message", error))?;
        let entry = MlsOutboxEntry {
            send_id: send_id.to_owned(),
            conversation_id,
            incarnation,
            mls_group_id: mls_group_id.to_vec(),
            epoch,
            content_digest,
            ciphertext,
            created_at: created_at_ms,
            attempts: 0,
        };

        let state = snapshot_provider(&provider, &metadata)?;
        let mut pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        pending
            .mls_outbox
            .insert(send_id.to_owned(), Some(entry.clone()));
        self.db.apply(&pending).await?;
        Ok(entry)
    }

    /// Remove a delivered retry record. MLS state remains append-only.
    pub async fn mark_application_delivered(&self, send_id: &str) -> Result<()> {
        if self.db.load_mls_outbox(send_id).await?.is_none() {
            return Ok(());
        }
        let mut pending = Pending::default();
        pending.mls_outbox.insert(send_id.to_owned(), None);
        self.db.apply(&pending).await
    }

    /// Persist a retry attempt without changing the immutable ciphertext tuple.
    pub async fn note_application_attempt(&self, send_id: &str) -> Result<MlsOutboxEntry> {
        let mut entry = self
            .db
            .load_mls_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid("unknown MLS send id".into()))?;
        entry.attempts = entry
            .attempts
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS send attempt counter overflow".into()))?;
        let mut pending = Pending::default();
        pending
            .mls_outbox
            .insert(send_id.to_owned(), Some(entry.clone()));
        self.db.apply(&pending).await?;
        Ok(entry)
    }

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

fn stage_add_members(
    provider: &KutupMlsProvider,
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    additions: &[VerifiedMlsKeyPackage],
    now_seconds: i64,
) -> Result<PendingMlsCommit> {
    validate_group_id(mls_group_id)?;
    if additions.is_empty() || additions.len() > 1000 || now_seconds < 0 {
        return Err(ChatError::Invalid(
            "MLS member addition requires 1-1000 KeyPackages and a valid clock".into(),
        ));
    }
    let pending_key = BASE64.encode(mls_group_id);
    if metadata.pending_commits.contains_key(&pending_key) {
        return Err(ChatError::Trust(
            "another MLS membership Commit is already pending".into(),
        ));
    }
    let group_id = GroupId::from_slice(mls_group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| mls_error("load MLS group", error))?
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
    ensure_v1_group(&group)?;
    if group.pending_commit().is_some() {
        return Err(ChatError::Trust(
            "OpenMLS has a pending commit without matching durable retry material".into(),
        ));
    }
    let existing_identities = group
        .members()
        .map(|member| member.credential.serialized_content().to_vec())
        .collect::<HashSet<_>>();
    let mut new_identities = HashSet::with_capacity(additions.len());
    let mut key_packages = Vec::with_capacity(additions.len());
    for addition in additions {
        addition
            .wire
            .validate(now_seconds)
            .map_err(ChatError::Invalid)?;
        let identity = addition.credential.credential_identity.as_bytes().to_vec();
        if existing_identities.contains(&identity) || !new_identities.insert(identity) {
            return Err(ChatError::Trust(
                "MLS member addition repeats an existing credential identity".into(),
            ));
        }
        key_packages.push(parse_verified_key_package(provider, addition, now_seconds)?);
    }
    let epoch_before = group.epoch().as_u64();
    let signer = signer_for_group(provider, &group)?;
    let (commit, welcome, _group_info) = group
        .add_members(provider, &signer, &key_packages)
        .map_err(|error| mls_error("stage MLS add-members commit", error))?;
    let epoch_after = group
        .pending_commit()
        .ok_or_else(|| ChatError::Protocol("OpenMLS did not stage the membership commit".into()))?
        .epoch()
        .as_u64();
    if epoch_after != epoch_before.saturating_add(1) {
        return Err(ChatError::Protocol(
            "MLS membership commit did not advance exactly one epoch".into(),
        ));
    }
    let commit = commit
        .to_bytes()
        .map_err(|error| mls_error("serialize MLS membership commit", error))?;
    let welcome = Some(
        welcome
            .to_bytes()
            .map_err(|error| mls_error("serialize MLS Welcome", error))?,
    );
    let pending = PendingMlsCommit {
        mls_group_id: mls_group_id.to_vec(),
        epoch_before,
        epoch_after,
        commit_hash: hex::encode(Sha256::digest(&commit)),
        commit,
        welcome,
    };
    validate_pending_commit(&pending)?;
    metadata
        .pending_commits
        .insert(pending_key, pending.clone());
    Ok(pending)
}

fn stage_remove_members(
    provider: &KutupMlsProvider,
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    removed_credential_identities: &[String],
) -> Result<PendingMlsCommit> {
    validate_group_id(mls_group_id)?;
    if removed_credential_identities.is_empty() || removed_credential_identities.len() > 1000 {
        return Err(ChatError::Invalid(
            "MLS member removal requires 1-1000 credential identities".into(),
        ));
    }
    let pending_key = BASE64.encode(mls_group_id);
    if metadata.pending_commits.contains_key(&pending_key) {
        return Err(ChatError::Trust(
            "another MLS membership Commit is already pending".into(),
        ));
    }
    let group_id = GroupId::from_slice(mls_group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| mls_error("load MLS group", error))?
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
    ensure_v1_group(&group)?;
    if group.pending_commit().is_some() {
        return Err(ChatError::Trust(
            "OpenMLS has a pending commit without matching durable retry material".into(),
        ));
    }
    let mut requested = HashSet::with_capacity(removed_credential_identities.len());
    for identity in removed_credential_identities {
        validate_credential_identity(identity)?;
        if !requested.insert(identity.as_bytes().to_vec()) {
            return Err(ChatError::Invalid(
                "MLS member removal repeats a credential identity".into(),
            ));
        }
    }
    let targets = group
        .members()
        .filter_map(|member| {
            requested
                .contains(member.credential.serialized_content())
                .then_some(member.index)
        })
        .collect::<Vec<_>>();
    if targets.len() != requested.len() {
        return Err(ChatError::Trust(
            "MLS member removal names a credential absent from the current roster".into(),
        ));
    }
    let epoch_before = group.epoch().as_u64();
    let signer = signer_for_group(provider, &group)?;
    let (commit, welcome, _group_info) = group
        .remove_members(provider, &signer, &targets)
        .map_err(|error| mls_error("stage MLS remove-members commit", error))?;
    let epoch_after = group
        .pending_commit()
        .ok_or_else(|| ChatError::Protocol("OpenMLS did not stage the membership commit".into()))?
        .epoch()
        .as_u64();
    if epoch_after != epoch_before.saturating_add(1) {
        return Err(ChatError::Protocol(
            "MLS membership commit did not advance exactly one epoch".into(),
        ));
    }
    let commit = commit
        .to_bytes()
        .map_err(|error| mls_error("serialize MLS membership commit", error))?;
    let welcome = welcome
        .map(|message| {
            message
                .to_bytes()
                .map_err(|error| mls_error("serialize MLS Welcome", error))
        })
        .transpose()?;
    let pending = PendingMlsCommit {
        mls_group_id: mls_group_id.to_vec(),
        epoch_before,
        epoch_after,
        commit_hash: hex::encode(Sha256::digest(&commit)),
        commit,
        welcome,
    };
    validate_pending_commit(&pending)?;
    metadata
        .pending_commits
        .insert(pending_key, pending.clone());
    Ok(pending)
}

#[allow(clippy::too_many_arguments)]
fn build_pending_membership_change(
    metadata: &SnapshotMetadata,
    conversation: &LocalMlsConversationRecord,
    mls_group_id: &[u8],
    proposal_id: Uuid,
    next_roster: &[MlsConversationMemberV1],
    additions: &[VerifiedMlsKeyPackage],
    current_devices: &[(String, u32, String)],
    pending: &PendingMlsCommit,
    created_at_seconds: i64,
) -> Result<PendingMlsMembershipChange> {
    let next_addresses = next_roster
        .iter()
        .map(|member| member.address.canonical())
        .collect::<BTreeSet<_>>();
    let previous_participant_domains = participant_domains(&conversation.current_roster)?;
    let next_participant_domains = participant_domains(next_roster)?;
    let affected_domains = previous_participant_domains
        .iter()
        .chain(&next_participant_domains)
        .cloned()
        .collect::<BTreeSet<_>>();
    let commit_message = BASE64.encode(&pending.commit);
    let welcome_message = pending
        .welcome
        .as_ref()
        .map(|welcome| BASE64.encode(welcome));
    let mut envelopes_by_domain = BTreeMap::<String, Vec<MlsMembershipEnvelopeV1>>::new();
    for (address, device_id, _) in current_devices {
        if !next_addresses.contains(address) {
            continue;
        }
        let recipient: AccountAddress = address
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
        let destination = recipient
            .server
            .clone()
            .ok_or_else(|| ChatError::Trust("MLS member has no federation domain".into()))?;
        envelopes_by_domain
            .entry(destination)
            .or_default()
            .push(MlsMembershipEnvelopeV1 {
                envelope_id: random_uuid(),
                recipient,
                device_id: *device_id,
                kind: MlsMembershipEnvelopeKindV1::Commit,
                opaque_message: commit_message.clone(),
            });
    }
    if !additions.is_empty() {
        let welcome_message = welcome_message.ok_or_else(|| {
            ChatError::Protocol("MLS add-members operation did not produce a Welcome".into())
        })?;
        for addition in additions {
            let (address, device_id) =
                parse_device_credential_identity(&addition.credential.credential_identity)?;
            let recipient: AccountAddress =
                address
                    .parse()
                    .map_err(|error: kutup_chat_proto::AddressError| {
                        ChatError::Trust(error.to_string())
                    })?;
            let destination = recipient
                .server
                .clone()
                .ok_or_else(|| ChatError::Trust("MLS member has no federation domain".into()))?;
            envelopes_by_domain
                .entry(destination)
                .or_default()
                .push(MlsMembershipEnvelopeV1 {
                    envelope_id: random_uuid(),
                    recipient,
                    device_id,
                    kind: MlsMembershipEnvelopeKindV1::Welcome,
                    opaque_message: welcome_message.clone(),
                });
        }
    }
    let next_roster_commitment = roster_commitment(next_roster).map_err(ChatError::Invalid)?;
    let mut deliveries = Vec::with_capacity(affected_domains.len());
    for destination in affected_domains {
        let mut local_members_after = next_roster
            .iter()
            .filter(|member| member.address.server.as_deref() == Some(destination.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        local_members_after.sort_by_key(|member| member.address.canonical());
        let mut envelopes = envelopes_by_domain.remove(&destination).unwrap_or_default();
        envelopes.sort_by_key(|envelope| {
            (
                envelope.recipient.canonical(),
                envelope.device_id,
                u16::from(envelope.kind),
                envelope.envelope_id,
            )
        });
        let delivery = MlsMembershipDeliveryV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            proposal_id,
            destination,
            epoch_after: pending.epoch_after,
            next_roster_commitment: next_roster_commitment.clone(),
            next_participant_domains: next_participant_domains.clone(),
            local_members_after,
            envelopes,
        };
        delivery.validate().map_err(ChatError::Protocol)?;
        deliveries.push(delivery);
    }
    if !envelopes_by_domain.is_empty() {
        return Err(ChatError::Protocol(
            "MLS membership envelopes target a domain outside the roster transition".into(),
        ));
    }
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: conversation.request.genesis.conversation_id,
        incarnation: conversation.request.genesis.incarnation,
        proposal_id,
        previous_roster_commitment: roster_commitment(&conversation.current_roster)
            .map_err(ChatError::Db)?,
        next_roster_commitment,
        previous_member_count: conversation.current_roster.len() as u32,
        next_member_count: next_roster.len() as u32,
        previous_participant_domains,
        next_participant_domains,
        deliveries: deliveries
            .iter()
            .map(|delivery| {
                Ok(MlsMembershipDeliveryCommitmentV1 {
                    destination: delivery.destination.clone(),
                    delivery_digest: delivery.delivery_digest().map_err(ChatError::Protocol)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    transition.validate().map_err(ChatError::Protocol)?;
    let proposal = sign_control_proposal_with_metadata(
        metadata,
        mls_group_id,
        conversation.request.genesis.conversation_id,
        conversation.request.genesis.incarnation,
        proposal_id,
        pending.epoch_before,
        MlsControlActionTypeV1::MembershipChange,
        &pending.commit,
        created_at_seconds,
    )?;
    let block = MlsControlBlockV1 {
        conversation_id: conversation.request.genesis.conversation_id,
        incarnation: conversation.request.genesis.incarnation,
        height: conversation.last_finalized_height.saturating_add(1),
        previous_block_hash: conversation.last_block_hash.clone(),
        epoch_before: pending.epoch_before,
        epoch_after: pending.epoch_after,
        proposal,
        transition_digest: Some(
            transition
                .transition_digest()
                .map_err(ChatError::Protocol)?,
        ),
        owner_approval: None,
        finalized_at: created_at_seconds,
    };
    block.validate().map_err(ChatError::Protocol)?;
    let vote_request = FederatedMlsOrderingVoteRequestV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        block,
        authority_set: conversation.current_authority_set.clone(),
        previous_set_certificate: None,
    };
    vote_request.validate().map_err(ChatError::Protocol)?;
    let control = PendingMlsMembershipChange {
        mls_group_id: mls_group_id.to_vec(),
        next_roster: next_roster.to_vec(),
        deliveries,
        transition,
        vote_request,
        commit_hash: pending.commit_hash.clone(),
        final_request: None,
    };
    validate_pending_membership_change(&control)?;
    Ok(control)
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

fn validate_pending_membership_change(control: &PendingMlsMembershipChange) -> Result<()> {
    validate_group_id(&control.mls_group_id)?;
    validate_sha256_hex("MLS membership commit hash", &control.commit_hash)?;
    validate_group_roster(&control.next_roster)?;
    control
        .transition
        .validate()
        .map_err(|error| ChatError::Db(format!("invalid durable MLS transition: {error}")))?;
    control
        .vote_request
        .validate()
        .map_err(|error| ChatError::Db(format!("invalid durable MLS vote request: {error}")))?;
    let block = &control.vote_request.block;
    let transition_digest = control
        .transition
        .transition_digest()
        .map_err(ChatError::Db)?;
    if block.proposal.action_type != MlsControlActionTypeV1::MembershipChange
        || block.conversation_id != control.transition.conversation_id
        || block.incarnation != control.transition.incarnation
        || block.proposal.proposal_id != control.transition.proposal_id
        || block.transition_digest.as_deref() != Some(transition_digest.as_str())
        || block.proposal.payload_digest != control.commit_hash
        || roster_commitment(&control.next_roster).map_err(ChatError::Db)?
            != control.transition.next_roster_commitment
        || control.next_roster.len() as u32 != control.transition.next_member_count
        || control.deliveries.len() != control.transition.deliveries.len()
    {
        return Err(ChatError::Db(
            "durable MLS membership control fields are inconsistent".into(),
        ));
    }
    let mut previous_destination = None;
    for delivery in &control.deliveries {
        if previous_destination
            .as_deref()
            .is_some_and(|previous| delivery.destination.as_str() <= previous)
        {
            return Err(ChatError::Db(
                "durable MLS membership deliveries are not strictly ordered".into(),
            ));
        }
        delivery
            .verify_transition(&control.transition)
            .map_err(ChatError::Db)?;
        if delivery.epoch_after != block.epoch_after {
            return Err(ChatError::Db(
                "durable MLS membership delivery targets another epoch".into(),
            ));
        }
        previous_destination = Some(delivery.destination.clone());
    }
    if let Some(request) = &control.final_request {
        request.validate_shape().map_err(ChatError::Db)?;
        request
            .finalized
            .verify(&control.vote_request.authority_set)
            .map_err(ChatError::Db)?;
        if request.finalized.block != control.vote_request.block
            || request.membership_transition.as_ref() != Some(&control.transition)
            || request.next_authority_set.is_some()
            || request.authority_transition.is_some()
            || request.next_owner_set.is_some()
        {
            return Err(ChatError::Db(
                "durable finalized MLS membership request differs from its retry record".into(),
            ));
        }
    }
    Ok(())
}

fn validate_local_control_state(record: &LocalMlsConversationRecord) -> Result<()> {
    if record.request.genesis.kind != MlsConversationKindV1::Group
        || record.current_roster.is_empty()
        || record.current_roster.len() > 1000
    {
        return Err(ChatError::Db(
            "durable MLS group control roster is invalid".into(),
        ));
    }
    let mut previous = None;
    let mut admins = 0usize;
    let mut owner_ids = BTreeSet::new();
    for member in &record.current_roster {
        member
            .validate()
            .map_err(|error| ChatError::Db(format!("invalid durable MLS member: {error}")))?;
        let address = member.address.canonical();
        if previous
            .as_ref()
            .is_some_and(|prior: &String| address <= *prior)
        {
            return Err(ChatError::Db(
                "durable MLS group roster is not strictly ordered".into(),
            ));
        }
        previous = Some(address);
        admins += usize::from(member.is_admin);
        if let Some(owner_id) = &member.owner_id {
            owner_ids.insert(owner_id.as_str());
        }
    }
    record
        .current_authority_set
        .validate()
        .map_err(ChatError::Db)?;
    record.current_owner_set.validate().map_err(ChatError::Db)?;
    let declared_owners = record
        .current_owner_set
        .owners
        .iter()
        .map(|owner| owner.owner_id.as_str())
        .collect::<BTreeSet<_>>();
    if admins == 0
        || owner_ids != declared_owners
        || record.last_finalized_epoch
            != record
                .request
                .genesis
                .initial_epoch
                .saturating_add(record.last_finalized_height)
    {
        return Err(ChatError::Db(
            "durable MLS group roles or control epoch are inconsistent".into(),
        ));
    }
    match (record.last_finalized_height, &record.last_block_hash) {
        (0, None)
            if record.current_roster == record.request.members
                && record.current_authority_set == record.request.genesis.authority_set
                && &record.current_owner_set
                    == record.request.genesis.owner_set.as_ref().ok_or_else(|| {
                        ChatError::Db("group genesis has no owner set".into())
                    })? => {}
        (height, Some(hash)) if height > 0 => {
            validate_sha256_hex("durable MLS control block hash", hash)
                .map_err(|error| ChatError::Db(error.to_string()))?;
        }
        _ => {
            return Err(ChatError::Db(
                "durable MLS control head has an invalid predecessor shape".into(),
            ))
        }
    }
    Ok(())
}

fn validate_group_roster(roster: &[MlsConversationMemberV1]) -> Result<()> {
    if !(2..=1000).contains(&roster.len()) {
        return Err(ChatError::Invalid(
            "MLS group roster must contain 2-1000 accounts".into(),
        ));
    }
    let mut previous = None;
    let mut admins = 0usize;
    for member in roster {
        member.validate().map_err(ChatError::Invalid)?;
        let address = member.address.canonical();
        if previous
            .as_ref()
            .is_some_and(|prior: &String| address <= *prior)
        {
            return Err(ChatError::Invalid(
                "MLS group roster must be strictly ordered".into(),
            ));
        }
        previous = Some(address);
        admins += usize::from(member.is_admin);
    }
    if admins == 0 {
        return Err(ChatError::Invalid(
            "MLS group roster requires an administrator".into(),
        ));
    }
    roster_commitment(roster).map_err(ChatError::Invalid)?;
    Ok(())
}

fn roster_by_address(
    roster: &[MlsConversationMemberV1],
) -> Result<BTreeMap<String, MlsConversationMemberV1>> {
    let mut result = BTreeMap::new();
    for member in roster {
        let address = member.address.canonical();
        if result.insert(address, member.clone()).is_some() {
            return Err(ChatError::Invalid(
                "MLS group roster repeats an account".into(),
            ));
        }
    }
    Ok(result)
}

fn participant_domains(roster: &[MlsConversationMemberV1]) -> Result<Vec<String>> {
    roster
        .iter()
        .map(|member| {
            member
                .address
                .server
                .clone()
                .ok_or_else(|| ChatError::Invalid("MLS member has no federation domain".into()))
        })
        .collect::<Result<BTreeSet<_>>>()
        .map(|domains| domains.into_iter().collect())
}

fn parse_device_credential_identity(identity: &str) -> Result<(String, u32)> {
    let (account, device_id) = identity.rsplit_once('#').ok_or_else(|| {
        ChatError::Trust("MLS credential identity must be account@server#device".into())
    })?;
    let address: AccountAddress = account
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    if address.server.is_none() {
        return Err(ChatError::Trust(
            "MLS credential identity requires a federation domain".into(),
        ));
    }
    let device_id: u32 = device_id
        .parse()
        .map_err(|_| ChatError::Trust("MLS credential device id is invalid".into()))?;
    if !(1..=127).contains(&device_id) || format!("{}#{device_id}", address.canonical()) != identity
    {
        return Err(ChatError::Trust(
            "MLS credential identity is not canonical".into(),
        ));
    }
    Ok((address.canonical(), device_id))
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

fn verify_exact_roster(
    members: impl Iterator<Item = Member>,
    expected: &[VerifiedMlsCredential],
) -> Result<()> {
    let mut expected_by_identity = BTreeMap::new();
    for credential in expected {
        validate_credential_identity(&credential.credential_identity)?;
        validate_credential_public_key(&credential.credential_public_key)?;
        if expected_by_identity
            .insert(
                credential.credential_identity.as_bytes().to_vec(),
                credential.credential_public_key.as_slice(),
            )
            .is_some()
        {
            return Err(ChatError::Trust(
                "expected MLS roster contains duplicate credential identities".into(),
            ));
        }
    }
    let mut actual_count = 0usize;
    let mut actual_identities = HashSet::new();
    for member in members {
        actual_count += 1;
        let identity = member.credential.serialized_content();
        if !actual_identities.insert(identity.to_vec()) {
            return Err(ChatError::Trust(
                "MLS roster contains duplicate credential identities".into(),
            ));
        }
        let expected_key = expected_by_identity.get(identity).ok_or_else(|| {
            ChatError::Trust("MLS roster contains a credential absent from the manifest".into())
        })?;
        if member.signature_key.as_slice() != *expected_key {
            return Err(ChatError::Trust(
                "MLS roster credential key differs from the manifest".into(),
            ));
        }
    }
    if actual_count != expected_by_identity.len() {
        return Err(ChatError::Trust(
            "MLS roster omits a transparency-verified expected member".into(),
        ));
    }
    Ok(())
}

fn verify_member_credential(member: &Member, expected: &VerifiedMlsCredential) -> Result<()> {
    validate_credential_identity(&expected.credential_identity)?;
    validate_credential_public_key(&expected.credential_public_key)?;
    if member.credential.serialized_content() != expected.credential_identity.as_bytes()
        || member.signature_key != expected.credential_public_key
    {
        return Err(ChatError::Trust(
            "MLS sender credential differs from the transparency-verified manifest".into(),
        ));
    }
    Ok(())
}

fn validate_pending_commit(pending: &PendingMlsCommit) -> Result<()> {
    validate_group_id(&pending.mls_group_id)?;
    validate_sha256_hex("MLS commit hash", &pending.commit_hash)?;
    if pending.epoch_after != pending.epoch_before.saturating_add(1)
        || pending.commit.is_empty()
        || pending.commit.len() > MAX_APPLICATION_BYTES
        || pending
            .welcome
            .as_ref()
            .is_some_and(|welcome| welcome.is_empty() || welcome.len() > MAX_APPLICATION_BYTES)
        || hex::encode(Sha256::digest(&pending.commit)) != pending.commit_hash
    {
        return Err(ChatError::Db(
            "durable MLS pending Commit material is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_sha256_hex(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChatError::Invalid(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn validate_credential_public_key(key: &[u8]) -> Result<()> {
    if key.len() != 65 || key.first() != Some(&4) {
        return Err(ChatError::Invalid(
            "MLS credential key must be uncompressed P-256".into(),
        ));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
        .map_err(|_| ChatError::Invalid("MLS credential key is invalid P-256".into()))?;
    Ok(())
}

fn validate_metadata(metadata: &SnapshotMetadata) -> Result<()> {
    validate_credential_identity(&metadata.credential_identity)?;
    validate_credential_public_key(&metadata.credential_public_key)
        .map_err(|error| ChatError::Db(error.to_string()))?;
    let secret = p256::SecretKey::from_slice(&metadata.anonymous_delivery_private_key)
        .map_err(|_| ChatError::Db("invalid durable anonymous-delivery private key".into()))?;
    if secret.public_key().to_encoded_point(false).as_bytes().len() != 65 {
        return Err(ChatError::Db(
            "anonymous-delivery key is not uncompressed P-256".into(),
        ));
    }
    if metadata.pending_commits.len() > MAX_PENDING_COMMITS
        || metadata.pending_membership_changes.len() > MAX_PENDING_COMMITS
    {
        return Err(ChatError::Db(
            "too many durable MLS pending control records".into(),
        ));
    }
    if metadata.group_control_private_keys.len() > MAX_PENDING_COMMITS {
        return Err(ChatError::Db(
            "too many durable MLS group control keys".into(),
        ));
    }
    if metadata.group_owner_private_keys.len() > MAX_PENDING_COMMITS
        || metadata.conversations.len() > MAX_PENDING_COMMITS
    {
        return Err(ChatError::Db(
            "too many durable MLS owner or conversation records".into(),
        ));
    }
    for (group_id, private_key) in &metadata.group_control_private_keys {
        let decoded = decode_canonical_base64("MLS control group id", group_id, 0)?;
        validate_group_id(&decoded)?;
        if private_key.len() != 32 {
            return Err(ChatError::Db(
                "durable MLS group control key has the wrong length".into(),
            ));
        }
        P256SigningKey::from_slice(private_key)
            .map_err(|_| ChatError::Db("invalid durable MLS group control key".into()))?;
    }
    for (key, pending) in &metadata.pending_commits {
        validate_pending_commit(pending)?;
        if key != &BASE64.encode(&pending.mls_group_id) {
            return Err(ChatError::Db(
                "durable MLS pending Commit key does not match its group".into(),
            ));
        }
    }
    for (key, control) in &metadata.pending_membership_changes {
        validate_pending_membership_change(control)?;
        if key != &BASE64.encode(&control.mls_group_id)
            || !metadata.pending_commits.contains_key(key)
        {
            return Err(ChatError::Db(
                "durable MLS membership control key or pending Commit is inconsistent".into(),
            ));
        }
    }
    for (group_id, private_key) in &metadata.group_owner_private_keys {
        let decoded = decode_canonical_base64("MLS owner group id", group_id, 0)?;
        validate_group_id(&decoded)?;
        let seed: [u8; 32] = private_key.as_slice().try_into().map_err(|_| {
            ChatError::Db("durable MLS group owner key has the wrong length".into())
        })?;
        ed25519_dalek::SigningKey::from_bytes(&seed);
    }
    let mut conversation_group_ids = HashSet::with_capacity(metadata.conversations.len());
    for (conversation_id, record) in &metadata.conversations {
        record
            .request
            .validate()
            .map_err(|error| ChatError::Db(format!("invalid durable MLS genesis: {error}")))?;
        if record.request.genesis.kind != MlsConversationKindV1::Group
            || conversation_id != &record.request.genesis.conversation_id.to_string()
        {
            return Err(ChatError::Db(
                "durable MLS conversation key or kind is invalid".into(),
            ));
        }
        validate_local_control_state(record)?;
        let group_id = decode_canonical_base64(
            "durable MLS genesis group id",
            &record.request.genesis.mls_group_id,
            0,
        )?;
        let group_key = BASE64.encode(&group_id);
        if !conversation_group_ids.insert(group_key.clone()) {
            return Err(ChatError::Db(
                "durable MLS conversations contain a duplicate GroupId".into(),
            ));
        }
        if !metadata.group_control_private_keys.contains_key(&group_key) {
            return Err(ChatError::Db(
                "durable MLS genesis has no group control key".into(),
            ));
        }
        let owner = group_owner_credential(metadata, &group_id)?;
        let owner_set = record
            .request
            .genesis
            .owner_set
            .as_ref()
            .ok_or_else(|| ChatError::Db("durable group genesis has no owner set".into()))?;
        if owner_set.owners.len() != 1
            || owner_set.owners[0].owner_id != owner.owner_id
            || owner_set.owners[0].public_key != BASE64.encode(owner.public_key)
        {
            return Err(ChatError::Db(
                "durable MLS owner key differs from its group genesis".into(),
            ));
        }
        match (record.status, &record.server_genesis_hash) {
            (LocalMlsConversationStatus::PendingGenesis, None) => {}
            (LocalMlsConversationStatus::Active, Some(hash)) => {
                validate_sha256_hex("durable MLS genesis hash", hash)
                    .map_err(|error| ChatError::Db(error.to_string()))?;
                let expected = record
                    .request
                    .genesis
                    .genesis_hash()
                    .map_err(ChatError::Db)?;
                if hash != &expected {
                    return Err(ChatError::Db(
                        "durable MLS genesis hash differs from its request".into(),
                    ));
                }
            }
            _ => {
                return Err(ChatError::Db(
                    "durable MLS genesis publication state is inconsistent".into(),
                ))
            }
        }
        if let Some(control) = metadata.pending_membership_changes.get(&group_key) {
            let block = &control.vote_request.block;
            if block.conversation_id != record.request.genesis.conversation_id
                || block.incarnation != record.request.genesis.incarnation
                || block.height != record.last_finalized_height.saturating_add(1)
                || block.previous_block_hash != record.last_block_hash
                || block.epoch_before != record.last_finalized_epoch
                || control.transition.previous_roster_commitment
                    != roster_commitment(&record.current_roster).map_err(ChatError::Db)?
            {
                return Err(ChatError::Db(
                    "durable MLS membership control does not extend its conversation pin".into(),
                ));
            }
        }
    }
    for group_id in metadata.group_owner_private_keys.keys() {
        if !metadata
            .conversations
            .values()
            .any(|record| &record.request.genesis.mls_group_id == group_id)
        {
            return Err(ChatError::Db(
                "durable MLS owner key has no conversation record".into(),
            ));
        }
    }
    Ok(())
}

fn validate_credential_identity(identity: &str) -> Result<()> {
    if identity.is_empty()
        || identity.len() > MAX_CREDENTIAL_IDENTITY_BYTES
        || identity.trim() != identity
        || identity.chars().any(char::is_control)
    {
        return Err(ChatError::Invalid(
            "MLS credential identity must be canonical and at most 512 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_group_id(group_id: &[u8]) -> Result<()> {
    if !(MIN_MLS_GROUP_ID_BYTES..=MAX_MLS_GROUP_ID_BYTES).contains(&group_id.len()) {
        return Err(ChatError::Invalid(
            "MLS GroupId must contain 16-255 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_send(
    send_id: &str,
    conversation_id: [u8; 16],
    incarnation: u64,
    group_id: &[u8],
    plaintext: &[u8],
    created_at_ms: i64,
) -> Result<()> {
    Uuid::parse_str(send_id)
        .map_err(|_| ChatError::Invalid("MLS send id must be a UUID".into()))?;
    if conversation_id == [0; 16]
        || incarnation == 0
        || plaintext.is_empty()
        || plaintext.len() > MAX_APPLICATION_BYTES
        || created_at_ms < 0
    {
        return Err(ChatError::Invalid(
            "MLS application message has invalid conversation, size, or clock".into(),
        ));
    }
    validate_group_id(group_id)
}

fn ensure_v1_group(group: &MlsGroup) -> Result<()> {
    if group.ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE {
        return Err(ChatError::UnsupportedSuite(group.ciphersuite() as u16));
    }
    Ok(())
}

fn local_group_state(group: &MlsGroup) -> LocalMlsGroupState {
    LocalMlsGroupState {
        mls_group_id: group.group_id().as_slice().to_vec(),
        epoch: group.epoch().as_u64(),
    }
}

fn mls_error(context: &str, error: impl std::fmt::Display) -> ChatError {
    ChatError::Protocol(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteChatDb;

    fn ordering_policy(domain: &str, seed: u8) -> MlsOrderingServicePolicyV1 {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public_key = signer.verifying_key().to_bytes();
        MlsOrderingServicePolicyV1 {
            policy_version: kutup_chat_proto::MLS_ORDERING_SERVICE_POLICY_VERSION,
            canonical_domain: domain.into(),
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            anonymous_delivery_suite:
                kutup_chat_proto::MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
            control_signing_key_id: hex::encode(Sha256::digest(public_key)),
            control_signing_public_key: BASE64.encode(public_key),
            accepts_group_ordering: true,
            maximum_group_members: 1000,
            maximum_authorities: 64,
            maximum_control_payload_bytes: 1024 * 1024,
            pending_message_requests: kutup_chat_proto::PendingMessageRequestPolicyV1::default(),
            abuse_limits: kutup_chat_proto::MlsAbuseLimitsV1::default(),
        }
    }

    #[test]
    fn exact_suite_is_rfc9420_suite_two() {
        assert_eq!(
            KUTUP_MLS_V1_CIPHERSUITE as u16,
            MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256
        );
        assert_eq!(
            KUTUP_MLS_V1_CIPHERSUITE.signature_algorithm(),
            SignatureScheme::ECDSA_SECP256R1_SHA256
        );
    }

    #[test]
    fn group_genesis_owner_and_exact_retry_survive_restart() {
        futures_executor::block_on(async {
            let path = std::env::temp_dir().join(format!(
                "kutup-openmls-genesis-{}.db",
                crate::clock::unix_millis()
            ));
            let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let client = MlsClient::new(db.clone());
            client.initialize("alice@example.test#1").await.unwrap();
            let conversation_id = Uuid::from_u128(0x81);
            let group_id = b"group-genesis-id";
            let creator: AccountAddress = "alice@example.test".parse().unwrap();
            let policies = vec![
                ordering_policy("beta.example", 12),
                ordering_policy("alpha.example", 11),
                ordering_policy("gamma.example", 13),
            ];

            let prepared = client
                .prepare_group_genesis(
                    conversation_id,
                    group_id,
                    creator.clone(),
                    &policies,
                    1_700_000_000,
                )
                .await
                .unwrap();
            assert_eq!(prepared.group.epoch, 0);
            assert_eq!(
                prepared.conversation.status,
                LocalMlsConversationStatus::PendingGenesis
            );
            prepared.conversation.request.validate().unwrap();
            assert_eq!(
                prepared
                    .conversation
                    .request
                    .genesis
                    .authority_set
                    .required_quorum,
                3
            );
            assert_eq!(
                prepared
                    .conversation
                    .request
                    .genesis
                    .authority_set
                    .authorities
                    .iter()
                    .map(|authority| authority.domain.as_str())
                    .collect::<Vec<_>>(),
                vec!["alpha.example", "beta.example", "gamma.example"]
            );
            let owner = client.group_owner_credential(group_id).await.unwrap();
            let declared = &prepared
                .conversation
                .request
                .genesis
                .owner_set
                .as_ref()
                .unwrap()
                .owners[0];
            assert_eq!(declared.owner_id, owner.owner_id);
            assert_eq!(declared.public_key, BASE64.encode(&owner.public_key));

            drop(client);
            drop(db);
            let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let client = MlsClient::new(reopened.clone());
            client.initialize("alice@example.test#1").await.unwrap();
            let retry = client
                .prepare_group_genesis(conversation_id, group_id, creator, &policies, 1_700_000_000)
                .await
                .unwrap();
            assert_eq!(retry, prepared);
            assert_eq!(
                client.group_owner_credential(group_id).await.unwrap(),
                owner
            );

            assert!(client
                .mark_group_genesis_published(conversation_id, &"00".repeat(32))
                .await
                .is_err());
            assert_eq!(
                client.local_conversations().await.unwrap()[0].status,
                LocalMlsConversationStatus::PendingGenesis
            );
            let hash = prepared
                .conversation
                .request
                .genesis
                .genesis_hash()
                .unwrap();
            let active = client
                .mark_group_genesis_published(conversation_id, &hash)
                .await
                .unwrap();
            assert_eq!(active.status, LocalMlsConversationStatus::Active);
            assert_eq!(active.server_genesis_hash.as_deref(), Some(hash.as_str()));
            assert_eq!(
                client
                    .mark_group_genesis_published(conversation_id, &hash)
                    .await
                    .unwrap(),
                active
            );

            drop(client);
            drop(reopened);
            let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let client = MlsClient::new(reopened.clone());
            client.initialize("alice@example.test#1").await.unwrap();
            assert_eq!(client.local_conversations().await.unwrap(), vec![active]);
            drop(client);
            drop(reopened);
            std::fs::remove_file(path).unwrap();
        });
    }

    #[test]
    fn atomic_membership_control_survives_restart_and_requires_exact_quorum_ack() {
        futures_executor::block_on(async {
            let path = std::env::temp_dir().join(format!(
                "kutup-openmls-membership-control-{}.db",
                crate::clock::unix_millis()
            ));
            let alice_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let charlie_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let alice = MlsClient::new(alice_db.clone());
            let bob = MlsClient::new(bob_db);
            let charlie = MlsClient::new(charlie_db);
            alice.initialize("alice@alpha.example#1").await.unwrap();
            let bob_public = bob.initialize("bobby@beta.example#1").await.unwrap();
            let charlie_public = charlie.initialize("carol@gamma.example#1").await.unwrap();
            let now = crate::clock::unix_millis() / 1000;
            let bob_package = bob
                .generate_key_package(1, 1, now, now + 86_400)
                .await
                .unwrap();
            let charlie_package = charlie
                .generate_key_package(1, 1, now, now + 86_400)
                .await
                .unwrap();
            let verified_bob = VerifiedMlsKeyPackage {
                wire: bob_package,
                credential: VerifiedMlsCredential::new(
                    "bobby@beta.example#1".into(),
                    bob_public.credential_public_key,
                )
                .unwrap(),
            };
            let verified_charlie = VerifiedMlsKeyPackage {
                wire: charlie_package,
                credential: VerifiedMlsCredential::new(
                    "carol@gamma.example#1".into(),
                    charlie_public.credential_public_key,
                )
                .unwrap(),
            };
            let conversation_id = Uuid::from_u128(0xa1);
            let proposal_id = Uuid::from_u128(0xa2);
            let group_id = b"membership-ctrl!";
            let policy = ordering_policy("authority.example", 31);
            let genesis = alice
                .prepare_group_genesis(
                    conversation_id,
                    group_id,
                    "alice@alpha.example".parse().unwrap(),
                    std::slice::from_ref(&policy),
                    now,
                )
                .await
                .unwrap();
            let genesis_hash = genesis.conversation.request.genesis.genesis_hash().unwrap();
            let active = alice
                .mark_group_genesis_published(conversation_id, &genesis_hash)
                .await
                .unwrap();
            let next_roster = vec![
                active.current_roster[0].clone(),
                MlsConversationMemberV1 {
                    address: "bobby@beta.example".parse().unwrap(),
                    is_admin: false,
                    owner_id: None,
                },
                MlsConversationMemberV1 {
                    address: "carol@gamma.example".parse().unwrap(),
                    is_admin: false,
                    owner_id: None,
                },
            ];
            let additions = vec![verified_bob, verified_charlie];
            let mut owner_transfer = next_roster.clone();
            let owner_id = owner_transfer[0].owner_id.take().unwrap();
            owner_transfer[1].is_admin = true;
            owner_transfer[1].owner_id = Some(owner_id);
            assert!(alice
                .prepare_membership_change(
                    group_id,
                    Uuid::from_u128(0xa0),
                    &owner_transfer,
                    &additions,
                    now + 1,
                )
                .await
                .is_err());
            assert!(alice.pending_membership_changes().await.unwrap().is_empty());
            assert!(alice.pending_commit(group_id).await.unwrap().is_none());
            let prepared = alice
                .prepare_membership_change(group_id, proposal_id, &next_roster, &additions, now + 1)
                .await
                .unwrap();
            assert_eq!(prepared.pending.epoch_before, 0);
            assert_eq!(prepared.pending.epoch_after, 1);
            assert_eq!(prepared.control.deliveries.len(), 3);
            assert_eq!(
                prepared
                    .control
                    .deliveries
                    .iter()
                    .map(|delivery| delivery.destination.as_str())
                    .collect::<Vec<_>>(),
                vec!["alpha.example", "beta.example", "gamma.example"]
            );
            assert_eq!(
                prepared.control.deliveries[0].envelopes[0].kind,
                MlsMembershipEnvelopeKindV1::Commit
            );
            assert_eq!(
                prepared.control.deliveries[1].envelopes[0].kind,
                MlsMembershipEnvelopeKindV1::Welcome
            );
            assert_eq!(
                prepared.control.deliveries[2].envelopes[0].kind,
                MlsMembershipEnvelopeKindV1::Welcome
            );

            drop(alice);
            drop(alice_db);
            let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let alice = MlsClient::new(reopened.clone());
            alice.initialize("alice@alpha.example#1").await.unwrap();
            assert_eq!(
                alice.pending_membership_changes().await.unwrap(),
                vec![prepared.control.clone()]
            );
            assert_eq!(
                alice
                    .prepare_membership_change(group_id, proposal_id, &next_roster, &[], now + 2,)
                    .await
                    .unwrap(),
                prepared
            );

            let block = &prepared.control.vote_request.block;
            let block_hash = block.block_hash().unwrap();
            let authority_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
            let authority = &prepared.control.vote_request.authority_set.authorities[0];
            let mut vote = kutup_chat_proto::MlsOrderingVoteV1 {
                conversation_id,
                incarnation: 1,
                authority_set_sequence: 1,
                height: 1,
                round: 0,
                vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
                block_hash: block_hash.clone(),
                authority_domain: authority.domain.clone(),
                authority_key_id: authority.key_id.clone(),
                signature: String::new(),
            };
            let signature: ed25519_dalek::Signature =
                authority_key.sign(&vote.signing_bytes().unwrap());
            vote.signature = BASE64.encode(signature.to_bytes());
            let certificate = MlsOrderingQuorumCertificateV1 {
                authority_set_sequence: 1,
                height: 1,
                round: 0,
                block_hash: block_hash.clone(),
                votes: vec![vote],
            };
            let request = alice
                .build_membership_commit_request(group_id, certificate)
                .await
                .unwrap();
            request.validate_shape().unwrap();
            let durable_final = alice.pending_membership_changes().await.unwrap();
            assert_eq!(durable_final[0].final_request.as_ref(), Some(&request));
            drop(alice);
            drop(reopened);
            let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let alice = MlsClient::new(reopened.clone());
            alice.initialize("alice@alpha.example#1").await.unwrap();
            assert_eq!(
                alice.pending_membership_changes().await.unwrap(),
                durable_final
            );

            let wrong = CommitMlsControlBlockResponseV1 {
                conversation_id,
                incarnation: 1,
                height: 1,
                epoch: 1,
                block_hash: "00".repeat(32),
                idempotent: false,
            };
            assert!(alice
                .finalize_membership_change(group_id, &wrong)
                .await
                .is_err());
            assert_eq!(
                alice.pending_membership_changes().await.unwrap(),
                durable_final
            );

            let acknowledgement = CommitMlsControlBlockResponseV1 {
                block_hash,
                ..wrong
            };
            let finalized = alice
                .finalize_membership_change(group_id, &acknowledgement)
                .await
                .unwrap();
            assert_eq!(finalized.group.epoch, 1);
            assert_eq!(finalized.conversation.last_finalized_height, 1);
            assert_eq!(finalized.conversation.current_roster, next_roster);
            assert!(alice.pending_membership_changes().await.unwrap().is_empty());
            assert_eq!(
                alice
                    .finalize_membership_change(group_id, &acknowledgement)
                    .await
                    .unwrap(),
                finalized
            );
            let removal_roster = vec![
                finalized.conversation.current_roster[0].clone(),
                finalized.conversation.current_roster[2].clone(),
            ];
            let removal = alice
                .prepare_membership_change(
                    group_id,
                    Uuid::from_u128(0xa3),
                    &removal_roster,
                    &[],
                    now + 2,
                )
                .await
                .unwrap();
            assert!(removal.pending.welcome.is_none());
            assert_eq!(removal.control.transition.previous_member_count, 3);
            assert_eq!(removal.control.transition.next_member_count, 2);
            let removed_domain = removal
                .control
                .deliveries
                .iter()
                .find(|delivery| delivery.destination == "beta.example")
                .unwrap();
            assert!(removed_domain.local_members_after.is_empty());
            assert!(removed_domain.envelopes.is_empty());

            drop(alice);
            drop(reopened);
            let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let alice = MlsClient::new(reopened.clone());
            alice.initialize("alice@alpha.example#1").await.unwrap();
            assert_eq!(
                alice.local_conversations().await.unwrap(),
                vec![finalized.conversation]
            );
            drop(alice);
            drop(reopened);
            std::fs::remove_file(path).unwrap();
        });
    }

    #[test]
    fn group_genesis_rejects_authority_downgrade_and_identity_collisions() {
        futures_executor::block_on(async {
            let path = std::env::temp_dir().join(format!(
                "kutup-openmls-genesis-reject-{}.db",
                crate::clock::unix_millis()
            ));
            let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let client = MlsClient::new(db.clone());
            client.initialize("alice@example.test#1").await.unwrap();
            let creator: AccountAddress = "alice@example.test".parse().unwrap();
            let mut rejected = ordering_policy("alpha.example", 21);
            rejected.accepts_group_ordering = false;
            assert!(client
                .prepare_group_genesis(
                    Uuid::from_u128(0x91),
                    b"group-rejected-id",
                    creator.clone(),
                    &[rejected],
                    1_700_000_000,
                )
                .await
                .is_err());
            assert!(client.local_conversations().await.unwrap().is_empty());

            let policy = ordering_policy("alpha.example", 21);
            let prepared = client
                .prepare_group_genesis(
                    Uuid::from_u128(0x92),
                    b"group-accepted-id",
                    creator.clone(),
                    &[policy.clone()],
                    1_700_000_000,
                )
                .await
                .unwrap();
            assert!(client
                .prepare_group_genesis(
                    Uuid::from_u128(0x92),
                    b"different-group!",
                    creator.clone(),
                    &[policy.clone()],
                    1_700_000_000,
                )
                .await
                .is_err());
            assert!(client
                .prepare_group_genesis(
                    Uuid::from_u128(0x93),
                    b"group-accepted-id",
                    creator,
                    &[policy],
                    1_700_000_000,
                )
                .await
                .is_err());
            assert_eq!(
                client.local_conversations().await.unwrap(),
                vec![prepared.conversation]
            );
            drop(client);
            drop(db);
            std::fs::remove_file(path).unwrap();
        });
    }

    #[test]
    fn state_group_keypackage_and_ciphertext_survive_restart() {
        futures_executor::block_on(async {
            let path = std::env::temp_dir().join(format!(
                "kutup-openmls-restart-{}.db",
                crate::clock::unix_millis()
            ));
            let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let client = MlsClient::new(db.clone());
            let public = client.initialize("alice@example.test#1").await.unwrap();
            assert_eq!(public.credential_public_key.len(), 65);
            assert_eq!(public.anonymous_delivery_public_key.len(), 65);
            public.manifest_binding().validate().unwrap();

            let package = client
                .generate_key_package(1, 1, 1_700_000_000, 1_700_086_400)
                .await
                .unwrap();
            assert_eq!(
                u16::from(package.suite),
                MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256
            );
            assert!(!package.key_package.is_empty());
            let group_id = b"0123456789abcdef";
            assert_eq!(client.create_group(group_id).await.unwrap().epoch, 0);
            let proposal = client
                .sign_control_proposal(
                    group_id,
                    Uuid::from_u128(7),
                    1,
                    Uuid::from_u128(8),
                    0,
                    MlsControlActionTypeV1::MembershipChange,
                    b"encrypted MLS commit",
                    1_700_000_000,
                )
                .await
                .unwrap();
            proposal.verify().unwrap();
            let control = client.group_control_credential(group_id).await.unwrap();
            assert_eq!(
                proposal.proposer_id,
                hex::encode(Sha256::digest(&control.public_key))
            );
            assert_ne!(control.public_key, public.credential_public_key);
            let second_group_id = b"different-group!";
            client.create_group(second_group_id).await.unwrap();
            let second_control = client
                .group_control_credential(second_group_id)
                .await
                .unwrap();
            assert_ne!(control.public_key, second_control.public_key);
            drop(client);
            drop(db);

            let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            let client = MlsClient::new(reopened.clone());
            let reopened_public = client.initialize("alice@example.test#1").await.unwrap();
            assert_eq!(reopened_public, public);
            assert_eq!(client.create_group(group_id).await.unwrap().epoch, 0);

            let send_id = "31fc6154-7886-49a8-9d64-735e901b7554";
            let entry = client
                .create_application_message(
                    send_id,
                    *b"conversation-id!",
                    1,
                    group_id,
                    b"durable MLS message",
                    1_700_000_000_000,
                )
                .await
                .unwrap();
            assert!(!entry.ciphertext.is_empty());
            let duplicate = client
                .create_application_message(
                    send_id,
                    *b"conversation-id!",
                    1,
                    group_id,
                    b"durable MLS message",
                    1_700_000_000_001,
                )
                .await
                .unwrap();
            assert_eq!(duplicate.ciphertext, entry.ciphertext);
            drop(client);
            drop(reopened);

            let restarted: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
            assert_eq!(
                restarted
                    .load_mls_outbox(send_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .ciphertext,
                entry.ciphertext
            );
            let client = MlsClient::new(restarted.clone());
            assert_eq!(
                client
                    .note_application_attempt(send_id)
                    .await
                    .unwrap()
                    .attempts,
                1
            );
            client.mark_application_delivered(send_id).await.unwrap();
            assert!(restarted.load_mls_outbox(send_id).await.unwrap().is_none());
            drop(client);
            drop(restarted);

            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
            }
        });
    }

    #[test]
    fn identity_change_and_send_id_reuse_fail_closed() {
        futures_executor::block_on(async {
            let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let client = MlsClient::new(db);
            client.initialize("alice@example.test#1").await.unwrap();
            assert!(matches!(
                client.initialize("mallory@example.test#1").await,
                Err(ChatError::Trust(_))
            ));
            let group_id = b"fed-group-id-001";
            client.create_group(group_id).await.unwrap();
            let send_id = "f3035928-4128-46d1-a5a4-12e80ce823aa";
            client
                .create_application_message(send_id, *b"conversation-id!", 1, group_id, b"first", 1)
                .await
                .unwrap();
            assert!(matches!(
                client
                    .create_application_message(
                        send_id,
                        *b"conversation-id!",
                        1,
                        group_id,
                        b"different",
                        2,
                    )
                    .await,
                Err(ChatError::Trust(_))
            ));
        });
    }

    #[test]
    fn welcome_commit_and_application_lifecycle_is_manifest_bound() {
        futures_executor::block_on(async {
            let alice_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let charlie_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let alice = MlsClient::new(alice_db.clone());
            let bob = MlsClient::new(bob_db);
            let charlie = MlsClient::new(charlie_db);
            let alice_public = alice.initialize("alice@example.test#1").await.unwrap();
            let bob_public = bob.initialize("bob@example.test#1").await.unwrap();
            let charlie_public = charlie.initialize("charlie@example.test#1").await.unwrap();
            let now = crate::clock::unix_millis() / 1000;
            let bob_package = bob
                .generate_key_package(1, 1, now, now + 86_400)
                .await
                .unwrap();
            let charlie_package = charlie
                .generate_key_package(1, 1, now, now + 86_400)
                .await
                .unwrap();
            let alice_credential = VerifiedMlsCredential::new(
                "alice@example.test#1".into(),
                alice_public.credential_public_key,
            )
            .unwrap();
            let bob_credential = VerifiedMlsCredential::new(
                "bob@example.test#1".into(),
                bob_public.credential_public_key,
            )
            .unwrap();
            let charlie_credential = VerifiedMlsCredential::new(
                "charlie@example.test#1".into(),
                charlie_public.credential_public_key,
            )
            .unwrap();
            let group_id = b"manifest-mls-v1!";
            alice.create_group(group_id).await.unwrap();

            let pending = alice
                .prepare_add_members(
                    group_id,
                    &[VerifiedMlsKeyPackage {
                        wire: bob_package,
                        credential: bob_credential.clone(),
                    }],
                    now,
                )
                .await
                .unwrap();
            assert_eq!(pending.epoch_before, 0);
            assert_eq!(pending.epoch_after, 1);
            assert_eq!(
                alice.pending_commit(group_id).await.unwrap(),
                Some(pending.clone())
            );
            drop(alice);
            let alice = MlsClient::new(alice_db);
            assert_eq!(
                alice.pending_commit(group_id).await.unwrap(),
                Some(pending.clone())
            );

            let expected_roster = vec![alice_credential.clone(), bob_credential.clone()];
            let inspection = bob
                .inspect_welcome(group_id, pending.welcome.as_deref().unwrap())
                .await
                .unwrap();
            assert_eq!(inspection.epoch, 1);
            assert_eq!(inspection.claimed_members.len(), 2);
            assert!(bob.group_state(group_id).await.unwrap().is_none());
            assert_eq!(
                bob.join_from_welcome(
                    group_id,
                    pending.welcome.as_deref().unwrap(),
                    &expected_roster,
                )
                .await
                .unwrap()
                .epoch,
                1
            );
            assert_eq!(
                alice
                    .merge_pending_commit(group_id, &pending.commit_hash)
                    .await
                    .unwrap()
                    .epoch,
                1
            );
            assert!(alice.pending_commit(group_id).await.unwrap().is_none());
            let bob_address: kutup_chat_proto::AccountAddress = "bob@example.test".parse().unwrap();
            let alice_epoch_one_capability = alice
                .derive_delivery_capability(group_id, Uuid::from_u128(77), 1, &bob_address)
                .await
                .unwrap();
            let bob_epoch_one_capability = bob
                .derive_delivery_capability(group_id, Uuid::from_u128(77), 1, &bob_address)
                .await
                .unwrap();
            assert_eq!(alice_epoch_one_capability, bob_epoch_one_capability);

            let second_commit = alice
                .prepare_add_members(
                    group_id,
                    &[VerifiedMlsKeyPackage {
                        wire: charlie_package,
                        credential: charlie_credential.clone(),
                    }],
                    now,
                )
                .await
                .unwrap();
            let three_member_roster = vec![
                alice_credential.clone(),
                bob_credential.clone(),
                charlie_credential.clone(),
            ];
            assert_eq!(
                bob.apply_inbound_commit(group_id, &second_commit.commit, &three_member_roster,)
                    .await
                    .unwrap()
                    .epoch,
                2
            );
            assert_eq!(
                charlie
                    .join_from_welcome(
                        group_id,
                        second_commit.welcome.as_deref().unwrap(),
                        &three_member_roster,
                    )
                    .await
                    .unwrap()
                    .epoch,
                2
            );
            assert_eq!(
                alice
                    .merge_pending_commit(group_id, &second_commit.commit_hash)
                    .await
                    .unwrap()
                    .epoch,
                2
            );
            let bob_epoch_two_capability = bob
                .derive_delivery_capability(group_id, Uuid::from_u128(77), 1, &bob_address)
                .await
                .unwrap();
            assert_ne!(
                bob_epoch_two_capability.capability,
                bob_epoch_one_capability.capability
            );

            let removal = alice
                .prepare_remove_members(group_id, &["charlie@example.test#1".to_owned()])
                .await
                .unwrap();
            assert!(removal.welcome.is_none());
            assert_eq!(
                bob.apply_inbound_commit(
                    group_id,
                    &removal.commit,
                    &[alice_credential.clone(), bob_credential.clone()],
                )
                .await
                .unwrap()
                .epoch,
                3
            );
            assert_eq!(
                alice
                    .merge_pending_commit(group_id, &removal.commit_hash)
                    .await
                    .unwrap()
                    .epoch,
                3
            );

            let outbound = alice
                .create_application_message(
                    "16811fc6-27b8-4f32-81c4-c3888ca60f5e",
                    *b"conversation-id!",
                    1,
                    group_id,
                    b"hello from alice",
                    1_700_000_000_000,
                )
                .await
                .unwrap();
            let decrypted = bob
                .decrypt_application_message(group_id, &outbound.ciphertext, &alice_credential)
                .await
                .unwrap();
            assert_eq!(decrypted.plaintext, b"hello from alice");
            assert_eq!(decrypted.epoch, 3);

            let forged = VerifiedMlsCredential::new(
                "alice@example.test#1".into(),
                bob_credential.credential_public_key.clone(),
            )
            .unwrap();
            let second = alice
                .create_application_message(
                    "a7e832e9-bfc6-4560-ae65-9bce2e9c2294",
                    *b"conversation-id!",
                    1,
                    group_id,
                    b"manifest mismatch",
                    1_700_000_000_001,
                )
                .await
                .unwrap();
            assert!(matches!(
                bob.decrypt_application_message(group_id, &second.ciphertext, &forged)
                    .await,
                Err(ChatError::Trust(_))
            ));
        });
    }
}
