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

use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use openmls::prelude::{
    Ciphersuite, Extensions, GroupId, KeyPackage, KeyPackageIn, Lifetime, Member, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageIn, MlsMessageBodyIn,
    ProcessedMessageContent, ProtocolVersion, Sender, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::{signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};
use uuid::Uuid;

use crate::db::{ChatDb, MlsOutboxEntry, Pending};
use crate::error::{ChatError, Result};
use kutup_chat_proto::{
    MlsCipherSuiteId, MlsControlActionTypeV1, MlsControlProposalV1, MlsKeyPackageV1,
    MlsManifestDeviceV1, MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256, MLS_PROTOCOL_VERSION,
};

const STATE_FORMAT_VERSION: u16 = 2;
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
    pub fn new(
        credential_identity: String,
        credential_public_key: Vec<u8>,
    ) -> Result<Self> {
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

/// Single-owner client MLS engine. The surrounding Chat engine already
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
            group_control_private_keys: BTreeMap::new(),
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
            .build(
                KUTUP_MLS_V1_CIPHERSUITE,
                &provider,
                &signer,
                credential,
            )
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
        wire.validate(now_seconds)
            .map_err(ChatError::Invalid)?;

        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(wire)
    }

    /// Create an epoch-zero group using the authenticated genesis `GroupId`.
    /// Existing group state is returned idempotently and is never overwritten.
    pub async fn create_group(&self, mls_group_id: &[u8]) -> Result<LocalMlsGroupState> {
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
    pub async fn group_state(
        &self,
        mls_group_id: &[u8],
    ) -> Result<Option<LocalMlsGroupState>> {
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

    /// Stage an add-members Commit after validating every claimed KeyPackage
    /// against a transparency-verified manifest credential. The pending
    /// OpenMLS state and exact Commit/Welcome bytes are persisted atomically.
    pub async fn prepare_add_members(
        &self,
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
        let (provider, mut metadata) = self.load_provider().await?;
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
            let identity = addition
                .credential
                .credential_identity
                .as_bytes()
                .to_vec();
            if existing_identities.contains(&identity) || !new_identities.insert(identity) {
                return Err(ChatError::Trust(
                    "MLS member addition repeats an existing credential identity".into(),
                ));
            }
            key_packages.push(parse_verified_key_package(
                &provider,
                addition,
                now_seconds,
            )?);
        }

        let epoch_before = group.epoch().as_u64();
        let signer = signer_for_group(&provider, &group)?;
        let (commit, welcome, _group_info) = group
            .add_members(&provider, &signer, &key_packages)
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
    pub async fn prepare_remove_members(
        &self,
        mls_group_id: &[u8],
        removed_credential_identities: &[String],
    ) -> Result<PendingMlsCommit> {
        validate_group_id(mls_group_id)?;
        if removed_credential_identities.is_empty()
            || removed_credential_identities.len() > 1000
        {
            return Err(ChatError::Invalid(
                "MLS member removal requires 1-1000 credential identities".into(),
            ));
        }
        let (provider, mut metadata) = self.load_provider().await?;
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
        let signer = signer_for_group(&provider, &group)?;
        let (commit, welcome, _group_info) = group
            .remove_members(&provider, &signer, &targets)
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
    pub async fn pending_commit(
        &self,
        mls_group_id: &[u8],
    ) -> Result<Option<PendingMlsCommit>> {
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
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
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
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
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
        claimed_members.sort_by(|left, right| {
            left.credential_identity.cmp(&right.credential_identity)
        });
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
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
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
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
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
        validate_send(send_id, conversation_id, incarnation, mls_group_id, plaintext, created_at_ms)?;
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
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
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
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS leaf signing key is unavailable".into()))?;
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
        let bytes = self
            .db
            .load_mls_state()
            .await?
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS device is not initialized".into()))?;
        provider_from_snapshot(&bytes)
    }
}

fn decode_canonical_base64(label: &str, value: &str, exact_len: usize) -> Result<Vec<u8>> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| ChatError::Db(format!("{label} is not canonical base64")))?;
    if BASE64.encode(&decoded) != value || (exact_len != 0 && decoded.len() != exact_len) {
        return Err(ChatError::Db(format!("{label} has invalid encoding or length")));
    }
    Ok(decoded)
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

fn signer_for_group(
    provider: &KutupMlsProvider,
    group: &MlsGroup,
) -> Result<SignatureKeyPair> {
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
    if secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .len()
        != 65
    {
        return Err(ChatError::Db(
            "anonymous-delivery key is not uncompressed P-256".into(),
        ));
    }
    if metadata.pending_commits.len() > MAX_PENDING_COMMITS {
        return Err(ChatError::Db(
            "too many durable MLS pending Commit records".into(),
        ));
    }
    if metadata.group_control_private_keys.len() > MAX_PENDING_COMMITS {
        return Err(ChatError::Db(
            "too many durable MLS group control keys".into(),
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
            let reopened_public = client
                .initialize("alice@example.test#1")
                .await
                .unwrap();
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
            assert!(restarted
                .load_mls_outbox(send_id)
                .await
                .unwrap()
                .is_none());
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
                .create_application_message(
                    send_id,
                    *b"conversation-id!",
                    1,
                    group_id,
                    b"first",
                    1,
                )
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
            let charlie_public = charlie
                .initialize("charlie@example.test#1")
                .await
                .unwrap();
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
            let bob_address: kutup_chat_proto::AccountAddress =
                "bob@example.test".parse().unwrap();
            let alice_epoch_one_capability = alice
                .derive_delivery_capability(
                    group_id,
                    Uuid::from_u128(77),
                    1,
                    &bob_address,
                )
                .await
                .unwrap();
            let bob_epoch_one_capability = bob
                .derive_delivery_capability(
                    group_id,
                    Uuid::from_u128(77),
                    1,
                    &bob_address,
                )
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
                bob.apply_inbound_commit(
                    group_id,
                    &second_commit.commit,
                    &three_member_roster,
                )
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
                .derive_delivery_capability(
                    group_id,
                    Uuid::from_u128(77),
                    1,
                    &bob_address,
                )
                .await
                .unwrap();
            assert_ne!(
                bob_epoch_two_capability.capability,
                bob_epoch_one_capability.capability
            );

            let removal = alice
                .prepare_remove_members(
                    group_id,
                    &["charlie@example.test#1".to_owned()],
                )
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
                .decrypt_application_message(
                    group_id,
                    &outbound.ciphertext,
                    &alice_credential,
                )
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
