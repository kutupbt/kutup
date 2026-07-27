//! Canonical MLS conversation, ordering, and anonymous-delivery protocol.
//!
//! OpenMLS owns the MLS state machine in clients. These types deliberately
//! contain only authenticated control metadata and opaque ciphertext so Kutup
//! servers never receive epoch secrets or message plaintext.

use std::collections::BTreeSet;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256Key};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AccountAddress, DeviceManifest, ManifestTransparencyProof};

pub const MLS_PROTOCOL_VERSION: u16 = 1;
pub const MLS_ORDERING_SERVICE_POLICY_VERSION: u16 = 1;
pub const MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256: u16 = 0x0002;
/// Private-use RFC 9420 GroupContext extension carrying Kutup's
/// group-encrypted authorization/control state. Every V1 KeyPackage advertises
/// this extension and every V1 group requires it.
pub const MLS_PRIVATE_CONTROL_EXTENSION_TYPE: u16 = 0xff4b;
pub const ANONYMOUS_MLS_DELIVERY_CONTEXT: &[u8] = b"kutup/anonymous-mls-delivery/v1";
const GROUP_DELIVERY_CAPABILITY_CONTEXT: &[u8] = b"kutup/group-delivery-capability/v1";
const MAX_CANONICAL_POLICY_BYTES: usize = 256 * 1024;
const MAX_MLS_GROUP_ID_BYTES: usize = 255;
const MAX_MLS_KEY_PACKAGE_BYTES: usize = 64 * 1024;
const MAX_MLS_CONTROL_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_MLS_APPLICATION_BYTES: usize = 1024 * 1024;
const MAX_ANONYMOUS_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ANONYMOUS_ENVELOPES: usize = 32;
const MAX_AUTHORITY_BOOTSTRAP_COMMITS_PER_PAGE: usize = 64;
const MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MEMBERSHIP_DELIVERY_BYTES: usize = 8 * 1024 * 1024;
const MAX_MEMBERSHIP_ENVELOPES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsCipherSuiteId {
    Mls128DhKemP256Aes128GcmSha256P256 = MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256,
}

impl From<MlsCipherSuiteId> for u16 {
    fn from(value: MlsCipherSuiteId) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MlsCipherSuiteId {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256 => {
                Ok(Self::Mls128DhKemP256Aes128GcmSha256P256)
            }
            _ => Err(format!("unknown MLS ciphersuite {value:#06x}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsAnonymousDeliverySuiteV1 {
    DhKemP256HkdfSha256Aes128Gcm = 1,
}

impl From<MlsAnonymousDeliverySuiteV1> for u16 {
    fn from(value: MlsAnonymousDeliverySuiteV1) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MlsAnonymousDeliverySuiteV1 {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DhKemP256HkdfSha256Aes128Gcm),
            _ => Err(format!("unknown anonymous MLS delivery suite {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum MlsConversationKindV1 {
    SelfSync,
    Direct,
    Group,
}

/// MLS keys for one device, authenticated by the account's signed manifest and
/// therefore by the transparency log. Both keys are uncompressed P-256 points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsManifestDeviceV1 {
    pub suite: MlsCipherSuiteId,
    pub credential_public_key: String,
    pub anonymous_delivery_public_key: String,
}

impl MlsManifestDeviceV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_uncompressed_p256("MLS credentialPublicKey", &self.credential_public_key)?;
        validate_uncompressed_p256(
            "MLS anonymousDeliveryPublicKey",
            &self.anonymous_delivery_public_key,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthorityV1 {
    pub domain: String,
    pub key_id: String,
    /// Canonical padded base64 Ed25519 public key used only for MLS control.
    pub public_key: String,
}

impl MlsAuthorityV1 {
    pub fn validate(&self) -> Result<(), String> {
        kutup_federation_proto::validate_server_name(&self.domain)
            .map_err(|error| error.to_string())?;
        validate_ed25519_key("MLS authority", &self.key_id, &self.public_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthoritySetV1 {
    pub sequence: u64,
    pub authorities: Vec<MlsAuthorityV1>,
    pub required_quorum: u16,
}

impl MlsAuthoritySetV1 {
    pub fn quorum_for(count: usize) -> Result<u16, String> {
        if !(1..=64).contains(&count) {
            return Err("MLS authority set must contain 1-64 authorities".into());
        }
        u16::try_from((2 * count) / 3 + 1).map_err(|_| "authority quorum overflow".into())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.sequence == 0 {
            return Err("MLS authority-set sequence must be positive".into());
        }
        if self.required_quorum != Self::quorum_for(self.authorities.len())? {
            return Err("MLS authority quorum does not match floor(2N/3)+1".into());
        }
        let mut previous = None;
        let mut keys = BTreeSet::new();
        for authority in &self.authorities {
            authority.validate()?;
            if previous.is_some_and(|domain: &str| authority.domain.as_str() <= domain) {
                return Err("MLS authorities must be strictly ordered by domain".into());
            }
            previous = Some(authority.domain.as_str());
            if !keys.insert(authority.key_id.as_str()) {
                return Err("MLS authority keys must be unique".into());
            }
        }
        Ok(())
    }

    pub fn authority(&self, domain: &str) -> Option<&MlsAuthorityV1> {
        self.authorities
            .binary_search_by(|authority| authority.domain.as_str().cmp(domain))
            .ok()
            .map(|index| &self.authorities[index])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerV1 {
    /// Group-scoped pseudonym: lowercase SHA-256 hex.
    pub owner_id: String,
    /// Canonical padded base64 Ed25519 public key scoped to this group.
    pub public_key: String,
}

impl MlsOwnerV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_hash("ownerId", &self.owner_id)?;
        let bytes = decode_canonical_base64("owner publicKey", &self.public_key, 32, 32)?;
        VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| "owner publicKey must be 32 bytes")?,
        )
        .map_err(|_| "owner publicKey is not Ed25519")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerSetV1 {
    pub sequence: u64,
    pub owners: Vec<MlsOwnerV1>,
    pub required_quorum: u16,
}

impl MlsOwnerSetV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.sequence == 0 || self.owners.is_empty() || self.owners.len() > 1024 {
            return Err("MLS owner set must have a positive sequence and 1-1024 owners".into());
        }
        let expected = (2 * self.owners.len()) / 3 + 1;
        if usize::from(self.required_quorum) != expected {
            return Err("MLS owner quorum does not match floor(2N/3)+1".into());
        }
        let mut previous = None;
        let mut keys = BTreeSet::new();
        for owner in &self.owners {
            owner.validate()?;
            if previous.is_some_and(|id: &str| owner.owner_id.as_str() <= id) {
                return Err("MLS owners must be strictly ordered by ownerId".into());
            }
            previous = Some(owner.owner_id.as_str());
            if !keys.insert(owner.public_key.as_str()) {
                return Err("MLS owner public keys must be unique".into());
            }
        }
        Ok(())
    }

    pub fn owner(&self, owner_id: &str) -> Option<&MlsOwnerV1> {
        self.owners
            .binary_search_by(|owner| owner.owner_id.as_str().cmp(owner_id))
            .ok()
            .map(|index| &self.owners[index])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsConversationGenesisV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    /// Canonical padded base64 MLS Group ID.
    pub mls_group_id: String,
    pub kind: MlsConversationKindV1,
    pub suite: MlsCipherSuiteId,
    /// Commitment to the complete transparency-verified account/device roster.
    pub roster_commitment: String,
    /// Public account-member count. Device leaf count remains inside MLS.
    pub member_count: u32,
    pub authority_set: MlsAuthoritySetV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_set: Option<MlsOwnerSetV1>,
    pub initial_epoch: u64,
    pub created_at: i64,
}

impl MlsConversationGenesisV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.initial_epoch != 0
            || self.created_at < 0
        {
            return Err("MLS conversation genesis has invalid version, id, epoch, or time".into());
        }
        decode_canonical_base64(
            "MLS groupId",
            &self.mls_group_id,
            16,
            MAX_MLS_GROUP_ID_BYTES,
        )?;
        validate_hash("rosterCommitment", &self.roster_commitment)?;
        self.authority_set.validate()?;
        match self.kind {
            MlsConversationKindV1::SelfSync => {
                if self.member_count != 1
                    || self.authority_set.authorities.len() != 1
                    || self.authority_set.required_quorum != 1
                    || self.owner_set.is_some()
                {
                    return Err("self-sync MLS genesis requires one authority and no owners".into());
                }
            }
            MlsConversationKindV1::Direct => {
                if self.member_count != 2
                    || !(1..=2).contains(&self.authority_set.authorities.len())
                    || usize::from(self.authority_set.required_quorum)
                        != self.authority_set.authorities.len()
                    || self.owner_set.is_some()
                {
                    return Err(
                        "direct MLS genesis requires one or two unanimous authorities and no owners"
                            .into(),
                    );
                }
            }
            MlsConversationKindV1::Group => {
                if self.member_count != 1 {
                    return Err(
                        "group MLS genesis contains only its creator; additions use membership transitions"
                            .into(),
                    );
                }
                self.owner_set
                    .as_ref()
                    .ok_or("group MLS genesis requires an owner set")?
                    .validate()?;
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }

    pub fn genesis_hash(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
}

/// The complete account roster supplied by a creator to its own home server.
/// Ordering authorities receive only `rosterCommitment` and pseudonymous owner
/// keys, never this address-bearing structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsConversationMemberV1 {
    pub address: AccountAddress,
    pub is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

impl MlsConversationMemberV1 {
    pub fn validate(&self) -> Result<(), String> {
        let canonical: AccountAddress = self
            .address
            .canonical()
            .parse()
            .map_err(|error: crate::AddressError| error.to_string())?;
        if canonical != self.address || self.address.server.is_none() {
            return Err("MLS member address must be canonical and federated".into());
        }
        if let Some(owner_id) = &self.owner_id {
            validate_hash("ownerId", owner_id)?;
            if !self.is_admin {
                return Err("MLS owners must also be administrators".into());
            }
        }
        Ok(())
    }
}

/// Complete group-private authorization state authenticated by the MLS
/// GroupContext. Ordering servers see only the public roster commitment and
/// pseudonymous authority/owner keys; members receive this exact structure in
/// Welcome and every subsequent Commit.
///
/// `previous_block_hash` deliberately names the predecessor of `height`.
/// Including the hash of the block at `height` would create a circular
/// dependency because that block commits the MLS ciphertext containing this
/// extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsPrivateControlStateV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<Uuid>,
    pub height: u64,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_block_hash: Option<String>,
    /// Immutable epoch-zero account roster, retained so a joining client can
    /// reconstruct and verify the private genesis request without asking any
    /// server to reveal member identities.
    pub genesis_roster: Vec<MlsConversationMemberV1>,
    pub genesis_authority_set: MlsAuthoritySetV1,
    pub genesis_owner_set: MlsOwnerSetV1,
    pub roster: Vec<MlsConversationMemberV1>,
    pub authority_set: MlsAuthoritySetV1,
    pub owner_set: MlsOwnerSetV1,
}

impl MlsPrivateControlStateV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.epoch != self.height
            || self.genesis_roster.len() != 1
            || self.roster.is_empty()
            || self.roster.len() > 1000
        {
            return Err("MLS private control state has invalid identifiers or bounds".into());
        }
        match (
            self.height,
            self.proposal_id,
            self.previous_block_hash.as_deref(),
        ) {
            (0, None, None) => {}
            (1, Some(proposal_id), None) if !proposal_id.is_nil() => {}
            (height, Some(proposal_id), Some(hash)) if height > 1 && !proposal_id.is_nil() => {
                validate_hash("previousBlockHash", hash)?;
            }
            _ => {
                return Err(
                    "MLS private control state has an invalid predecessor or proposal shape".into(),
                )
            }
        }
        self.genesis_authority_set.validate()?;
        self.genesis_owner_set.validate()?;
        self.authority_set.validate()?;
        self.owner_set.validate()?;
        self.genesis_roster[0].validate()?;
        let genesis_owner_id = self.genesis_roster[0]
            .owner_id
            .as_deref()
            .ok_or("MLS private control genesis roster has no owner")?;
        if self.genesis_owner_set.owners.len() != 1
            || self.genesis_owner_set.owners[0].owner_id != genesis_owner_id
        {
            return Err(
                "MLS private control genesis roster differs from its declared owner set".into(),
            );
        }
        roster_commitment(&self.genesis_roster)?;
        let mut previous = None;
        let mut admin_count = 0usize;
        let mut roster_owner_ids = BTreeSet::new();
        for member in &self.roster {
            member.validate()?;
            let address = member.address.canonical();
            if previous
                .as_ref()
                .is_some_and(|prior: &String| address <= *prior)
            {
                return Err("MLS private control roster is not strictly ordered".into());
            }
            previous = Some(address);
            admin_count += usize::from(member.is_admin);
            if let Some(owner_id) = &member.owner_id {
                if !roster_owner_ids.insert(owner_id.as_str()) {
                    return Err("MLS private control roster repeats an owner id".into());
                }
            }
        }
        let declared_owner_ids = self
            .owner_set
            .owners
            .iter()
            .map(|owner| owner.owner_id.as_str())
            .collect::<BTreeSet<_>>();
        if admin_count == 0 || roster_owner_ids != declared_owner_ids {
            return Err(
                "MLS private control roster roles differ from the declared owner set".into(),
            );
        }
        roster_commitment(&self.roster)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMlsConversationRequestV1 {
    pub genesis: MlsConversationGenesisV1,
    pub members: Vec<MlsConversationMemberV1>,
}

impl CreateMlsConversationRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.genesis.validate()?;
        let valid_count = match self.genesis.kind {
            MlsConversationKindV1::SelfSync => self.members.len() == 1,
            MlsConversationKindV1::Direct => self.members.len() == 2,
            MlsConversationKindV1::Group => self.members.len() == 1,
        };
        if !valid_count {
            return Err("MLS roster size does not match the conversation kind".into());
        }
        if self.genesis.member_count as usize != self.members.len() {
            return Err("MLS roster size does not match genesis memberCount".into());
        }
        let mut previous = None;
        let mut member_domains = BTreeSet::new();
        let mut owner_ids = BTreeSet::new();
        let mut admins = 0usize;
        for member in &self.members {
            member.validate()?;
            let address = member.address.canonical();
            if previous.as_ref().is_some_and(|prior| &address <= prior) {
                return Err("MLS roster must be strictly ordered by canonical address".into());
            }
            previous = Some(address);
            member_domains.insert(
                member
                    .address
                    .server
                    .as_deref()
                    .expect("validated federated member"),
            );
            admins += usize::from(member.is_admin);
            if let Some(owner_id) = &member.owner_id {
                if !owner_ids.insert(owner_id.as_str()) {
                    return Err("MLS owner ids must be unique in the roster".into());
                }
            }
        }
        if self.genesis.roster_commitment != roster_commitment(&self.members)? {
            return Err("MLS roster does not match genesis rosterCommitment".into());
        }
        let authority_domains: BTreeSet<&str> = self
            .genesis
            .authority_set
            .authorities
            .iter()
            .map(|authority| authority.domain.as_str())
            .collect();
        match self.genesis.kind {
            MlsConversationKindV1::SelfSync | MlsConversationKindV1::Direct => {
                if authority_domains != member_domains || !owner_ids.is_empty() {
                    return Err(
                        "self/direct MLS authorities must be exactly the participant servers"
                            .into(),
                    );
                }
            }
            MlsConversationKindV1::Group => {
                let owners = self
                    .genesis
                    .owner_set
                    .as_ref()
                    .ok_or("group MLS genesis requires owners")?;
                let declared: BTreeSet<&str> = owners
                    .owners
                    .iter()
                    .map(|owner| owner.owner_id.as_str())
                    .collect();
                if admins == 0 || owner_ids.is_empty() || owner_ids != declared {
                    return Err(
                        "group MLS roster requires an administrator and exactly the declared owners"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMlsConversationResponseV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub genesis_hash: String,
    pub idempotent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RespondMlsInvitationV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub accept: bool,
}

impl RespondMlsInvitationV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.conversation_id.is_nil() || self.incarnation == 0 {
            return Err("MLS invitation decision has invalid identifiers".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsInvitationV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    /// Canonical padded base64 MLS GroupId from the authenticated genesis.
    pub mls_group_id: String,
    pub invited_epoch: u64,
    pub expires_at: i64,
}

impl PendingMlsInvitationV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.invited_epoch == 0
            || self.expires_at <= now
        {
            return Err("pending MLS invitation has invalid identifiers or expiry".into());
        }
        decode_canonical_base64(
            "MLS invitation groupId",
            &self.mls_group_id,
            16,
            MAX_MLS_GROUP_ID_BYTES,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RespondMlsInvitationResponseV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub status: String,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MlsMailboxDeliveryKindV1 {
    IdentifiedRequest,
    Anonymous,
    SelfSync,
    MembershipControl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsMailboxEnvelopeV1 {
    pub id: Uuid,
    /// Canonical positive decimal string; browsers never round a 64-bit cursor.
    pub cursor: String,
    pub delivery_kind: MlsMailboxDeliveryKindV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incarnation: Option<u64>,
    pub send_id: Uuid,
    pub opaque_envelope: String,
    pub server_timestamp: i64,
}

impl MlsMailboxEnvelopeV1 {
    pub fn validate(&self) -> Result<(), String> {
        let cursor = self
            .cursor
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && value.to_string() == self.cursor)
            .ok_or("MLS mailbox cursor is not canonical positive decimal")?;
        if self.id.is_nil() || self.send_id.is_nil() || self.server_timestamp < 0 {
            return Err("MLS mailbox envelope has invalid identifiers or timestamp".into());
        }
        let _ = cursor;
        decode_canonical_base64(
            "MLS mailbox opaque envelope",
            &self.opaque_envelope,
            1,
            MAX_MLS_APPLICATION_BYTES,
        )?;
        match self.delivery_kind {
            MlsMailboxDeliveryKindV1::Anonymous => {
                if self.conversation_id.is_some() || self.incarnation.is_some() {
                    return Err(
                        "anonymous MLS mailbox envelope carries conversation metadata".into(),
                    );
                }
            }
            MlsMailboxDeliveryKindV1::MembershipControl => {
                if self.conversation_id.is_none() || self.incarnation.is_none_or(|value| value == 0)
                {
                    return Err(
                        "membership MLS mailbox envelope omits its conversation incarnation".into(),
                    );
                }
            }
            MlsMailboxDeliveryKindV1::IdentifiedRequest | MlsMailboxDeliveryKindV1::SelfSync => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsMailboxPageV1 {
    pub envelopes: Vec<MlsMailboxEnvelopeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl MlsMailboxPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.envelopes.len() > 256 {
            return Err("MLS mailbox page exceeds the protocol limit".into());
        }
        let mut previous: Option<u64> = None;
        for envelope in &self.envelopes {
            envelope.validate()?;
            let cursor = envelope
                .cursor
                .parse::<u64>()
                .map_err(|_| "MLS mailbox cursor is invalid")?;
            if previous.is_some_and(|previous| cursor <= previous) {
                return Err("MLS mailbox cursors are not strictly increasing".into());
            }
            previous = Some(cursor);
        }
        if self.next_cursor.as_deref() != previous.as_ref().map(ToString::to_string).as_deref() {
            return Err("MLS mailbox page cursor does not match its final envelope".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AckMlsMailboxV1 {
    pub device_id: u32,
    pub envelope_ids: Vec<Uuid>,
}

impl AckMlsMailboxV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.device_id == 0
            || self.envelope_ids.is_empty()
            || self.envelope_ids.len() > 256
            || self.envelope_ids.iter().any(Uuid::is_nil)
            || self.envelope_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(
                "MLS mailbox acknowledgement requires sorted unique bounded identifiers".into(),
            );
        }
        Ok(())
    }
}

/// Signed federation replication of a conversation genesis. A participant
/// server receives only members hosted on that destination so it can authorize
/// its local users without learning remote usernames. An authority that hosts
/// no participant receives an empty member list and therefore learns only the
/// roster commitment, participant domains, and pseudonymous control keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsGenesisReplicaV1 {
    pub protocol_version: u16,
    pub genesis: MlsConversationGenesisV1,
    /// Sorted unique homeserver domains represented by the roster. Authority-
    /// only replicas retain this routing set without learning usernames.
    pub participant_domains: Vec<String>,
    /// Strictly ordered members for exactly one participant domain (the
    /// federation destination), or empty for an authority-only replica.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<MlsConversationMemberV1>,
}

impl FederatedMlsGenesisReplicaV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION {
            return Err("unsupported federated MLS genesis version".into());
        }
        self.genesis.validate()?;
        if self.participant_domains.is_empty() || self.participant_domains.len() > 1000 {
            return Err("federated MLS participant-domain set is empty or too large".into());
        }
        let mut previous = None;
        for domain in &self.participant_domains {
            kutup_federation_proto::validate_server_name(domain)
                .map_err(|error| error.to_string())?;
            if previous.is_some_and(|prior: &str| domain.as_str() <= prior) {
                return Err("federated MLS participant domains must be strictly ordered".into());
            }
            previous = Some(domain.as_str());
        }
        if self.members.is_empty() {
            return Ok(());
        }
        let mut destination_domain = None;
        let mut previous_address = None;
        for member in &self.members {
            member.validate()?;
            let domain = member
                .address
                .server
                .as_deref()
                .ok_or("federated MLS member is missing its server")?;
            if destination_domain.is_some_and(|expected| expected != domain) {
                return Err(
                    "federated MLS genesis contains members from multiple destinations".into(),
                );
            }
            destination_domain = Some(domain);
            let address = member.address.canonical();
            if previous_address
                .as_ref()
                .is_some_and(|previous: &String| address <= *previous)
            {
                return Err("federated MLS local members must be strictly ordered".into());
            }
            previous_address = Some(address);
        }
        if self
            .participant_domains
            .binary_search_by(|candidate| {
                candidate
                    .as_str()
                    .cmp(destination_domain.expect("non-empty member list"))
            })
            .is_err()
        {
            return Err("federated MLS member domain is absent from participant routing".into());
        }
        Ok(())
    }

    pub fn includes_member_domain(&self, domain: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.address.server.as_deref() == Some(domain))
    }
}

/// Public, username-free commitment to one destination's private membership
/// snapshot and MLS control envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsMembershipDeliveryCommitmentV1 {
    pub destination: String,
    pub delivery_digest: String,
}

/// The public part of a membership transition. Ordering authorities learn the
/// old/new participant-server sets and one opaque digest per affected server,
/// but never usernames, device ids, Welcome messages, or MLS Commit bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsMembershipTransitionV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub proposal_id: Uuid,
    pub previous_roster_commitment: String,
    pub next_roster_commitment: String,
    pub previous_member_count: u32,
    pub next_member_count: u32,
    pub previous_participant_domains: Vec<String>,
    pub next_participant_domains: Vec<String>,
    pub deliveries: Vec<MlsMembershipDeliveryCommitmentV1>,
}

impl MlsMembershipTransitionV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.proposal_id.is_nil()
        {
            return Err("MLS membership transition has invalid identifiers".into());
        }
        validate_hash("previousRosterCommitment", &self.previous_roster_commitment)?;
        validate_hash("nextRosterCommitment", &self.next_roster_commitment)?;
        if !(1..=1000).contains(&self.previous_member_count)
            || !(1..=1000).contains(&self.next_member_count)
        {
            return Err("MLS membership transition member count must be 1-1000".into());
        }
        validate_participant_domain_set(&self.previous_participant_domains)?;
        validate_participant_domain_set(&self.next_participant_domains)?;

        let affected: BTreeSet<&str> = self
            .previous_participant_domains
            .iter()
            .chain(&self.next_participant_domains)
            .map(String::as_str)
            .collect();
        if self.deliveries.len() != affected.len() {
            return Err(
                "MLS membership transition requires one delivery per affected domain".into(),
            );
        }
        let mut previous = None;
        for delivery in &self.deliveries {
            kutup_federation_proto::validate_server_name(&delivery.destination)
                .map_err(|error| error.to_string())?;
            validate_hash("membership deliveryDigest", &delivery.delivery_digest)?;
            if previous.is_some_and(|domain: &str| delivery.destination.as_str() <= domain) {
                return Err("MLS membership delivery commitments must be strictly ordered".into());
            }
            if !affected.contains(delivery.destination.as_str()) {
                return Err("MLS membership delivery commitment names an unaffected domain".into());
            }
            previous = Some(delivery.destination.as_str());
        }
        Ok(())
    }

    pub fn transition_digest(&self) -> Result<String, String> {
        self.validate()?;
        mls_transition_digest(self)
    }

    pub fn delivery_commitment(
        &self,
        destination: &str,
    ) -> Option<&MlsMembershipDeliveryCommitmentV1> {
        self.deliveries
            .binary_search_by(|delivery| delivery.destination.as_str().cmp(destination))
            .ok()
            .map(|index| &self.deliveries[index])
    }
}

/// Public verifier data for an owner-authorized ordering-authority change.
/// The unchanged-roster delivery transition commits the exact MLS Commit
/// envelope delivered to every participant server; ordering-only authorities
/// still learn no usernames or device identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthorityChangeV1 {
    pub next_authority_set: MlsAuthoritySetV1,
    pub delivery_transition: MlsMembershipTransitionV1,
}

impl MlsAuthorityChangeV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.next_authority_set.validate()?;
        self.delivery_transition.validate()?;
        if self.delivery_transition.previous_roster_commitment
            != self.delivery_transition.next_roster_commitment
            || self.delivery_transition.previous_member_count
                != self.delivery_transition.next_member_count
            || self.delivery_transition.previous_participant_domains
                != self.delivery_transition.next_participant_domains
        {
            return Err("MLS authority change must preserve the exact roster and routing".into());
        }
        Ok(())
    }

    pub fn transition_digest(&self) -> Result<String, String> {
        self.validate()?;
        mls_transition_digest(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsMembershipEnvelopeKindV1 {
    Commit = 1,
    Welcome = 2,
}

impl From<MlsMembershipEnvelopeKindV1> for u16 {
    fn from(value: MlsMembershipEnvelopeKindV1) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MlsMembershipEnvelopeKindV1 {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Welcome),
            _ => Err(format!("unknown MLS membership envelope kind {value}")),
        }
    }
}

/// One opaque MLS Commit or Welcome addressed to a device on exactly one
/// participant server. This structure is never sent to ordering-only servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsMembershipEnvelopeV1 {
    pub envelope_id: Uuid,
    pub recipient: AccountAddress,
    pub device_id: u32,
    pub kind: MlsMembershipEnvelopeKindV1,
    pub opaque_message: String,
}

impl MlsMembershipEnvelopeV1 {
    fn validate(&self, destination: &str) -> Result<usize, String> {
        if self.envelope_id.is_nil() {
            return Err("MLS membership envelope id must not be nil".into());
        }
        let canonical: AccountAddress = self
            .recipient
            .canonical()
            .parse()
            .map_err(|error: crate::AddressError| error.to_string())?;
        if canonical != self.recipient || self.recipient.server.as_deref() != Some(destination) {
            return Err(
                "MLS membership envelope recipient must be canonical and local to its destination"
                    .into(),
            );
        }
        if !(1..=127).contains(&self.device_id) {
            return Err("MLS membership envelope device id must be 1-127".into());
        }
        decode_canonical_base64(
            "opaque MLS membership message",
            &self.opaque_message,
            1,
            1024 * 1024,
        )
        .map(|bytes| bytes.len())
    }
}

/// Destination-private membership state committed by
/// `MlsMembershipTransitionV1`. The full local snapshot makes retries and
/// restart recovery deterministic and lets the destination apply add/remove/
/// administrator changes atomically with the finalized public control block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsMembershipDeliveryV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub proposal_id: Uuid,
    pub destination: String,
    pub epoch_after: u64,
    pub next_roster_commitment: String,
    pub next_participant_domains: Vec<String>,
    pub local_members_after: Vec<MlsConversationMemberV1>,
    pub envelopes: Vec<MlsMembershipEnvelopeV1>,
}

impl MlsMembershipDeliveryV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.proposal_id.is_nil()
            || self.epoch_after == 0
        {
            return Err("MLS membership delivery has invalid identifiers or epoch".into());
        }
        kutup_federation_proto::validate_server_name(&self.destination)
            .map_err(|error| error.to_string())?;
        validate_hash("nextRosterCommitment", &self.next_roster_commitment)?;
        validate_participant_domain_set(&self.next_participant_domains)?;
        if self.local_members_after.len() > 1000 || self.envelopes.len() > MAX_MEMBERSHIP_ENVELOPES
        {
            return Err("MLS membership delivery exceeds its entry limit".into());
        }
        if self.local_members_after.is_empty()
            != self
                .next_participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(&self.destination))
                .is_err()
        {
            return Err(
                "MLS membership delivery local snapshot disagrees with participant routing".into(),
            );
        }
        let mut previous_member = None;
        for member in &self.local_members_after {
            member.validate()?;
            if member.address.server.as_deref() != Some(self.destination.as_str()) {
                return Err("MLS membership delivery contains a non-local member".into());
            }
            let address = member.address.canonical();
            if previous_member
                .as_ref()
                .is_some_and(|prior: &String| address <= *prior)
            {
                return Err("MLS membership delivery members must be strictly ordered".into());
            }
            previous_member = Some(address);
        }
        let mut total_bytes = 0usize;
        let mut previous_envelope = None;
        for envelope in &self.envelopes {
            let key = (
                envelope.recipient.canonical(),
                envelope.device_id,
                u16::from(envelope.kind),
                envelope.envelope_id,
            );
            if previous_envelope
                .as_ref()
                .is_some_and(|prior| key <= *prior)
            {
                return Err("MLS membership delivery envelopes must be strictly ordered".into());
            }
            total_bytes = total_bytes
                .checked_add(envelope.validate(&self.destination)?)
                .ok_or("MLS membership delivery size overflow")?;
            previous_envelope = Some(key);
        }
        if total_bytes > MAX_MEMBERSHIP_DELIVERY_BYTES {
            return Err("MLS membership delivery exceeds 8 MiB".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn delivery_digest(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    pub fn verify_transition(&self, transition: &MlsMembershipTransitionV1) -> Result<(), String> {
        self.validate()?;
        transition.validate()?;
        if self.conversation_id != transition.conversation_id
            || self.incarnation != transition.incarnation
            || self.proposal_id != transition.proposal_id
            || self.next_roster_commitment != transition.next_roster_commitment
            || self.next_participant_domains != transition.next_participant_domains
        {
            return Err("MLS membership delivery does not match its public transition".into());
        }
        let commitment = transition
            .delivery_commitment(&self.destination)
            .ok_or("MLS membership delivery destination is not committed")?;
        if self.delivery_digest()? != commitment.delivery_digest {
            return Err("MLS membership delivery digest does not match".into());
        }
        Ok(())
    }
}

pub fn roster_commitment(members: &[MlsConversationMemberV1]) -> Result<String, String> {
    if members.is_empty() || members.len() > 1000 {
        return Err("MLS roster must contain 1-1000 members".into());
    }
    let mut bytes = Vec::with_capacity(members.len() * 160);
    bytes.extend_from_slice(b"kutup-mls-roster-v1\0");
    bytes.extend_from_slice(
        &u32::try_from(members.len())
            .map_err(|_| "MLS roster is too large")?
            .to_be_bytes(),
    );
    let mut previous: Option<String> = None;
    for member in members {
        member.validate()?;
        let address = member.address.canonical();
        if previous.as_ref().is_some_and(|prior| &address <= prior) {
            return Err("MLS roster must be strictly ordered".into());
        }
        push_string(&mut bytes, &address)?;
        bytes.push(u8::from(member.is_admin));
        match &member.owner_id {
            Some(owner_id) => {
                bytes.push(1);
                push_string(&mut bytes, owner_id)?;
            }
            None => bytes.push(0),
        }
        previous = Some(address);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsControlActionTypeV1 {
    RoutineAdmin = 1,
    MembershipChange = 2,
    OwnerSetChange = 3,
    AuthoritySetChange = 4,
    AuthorizationPolicyChange = 5,
    CryptographicPolicyChange = 6,
    CloseConversation = 7,
    ProtocolUpgrade = 8,
    RecoverIncarnation = 9,
}

impl MlsControlActionTypeV1 {
    pub fn requires_owner_quorum(self) -> bool {
        matches!(
            self,
            Self::OwnerSetChange
                | Self::AuthoritySetChange
                | Self::AuthorizationPolicyChange
                | Self::CryptographicPolicyChange
                | Self::CloseConversation
                | Self::ProtocolUpgrade
                | Self::RecoverIncarnation
        )
    }
}

impl From<MlsControlActionTypeV1> for u16 {
    fn from(value: MlsControlActionTypeV1) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MlsControlActionTypeV1 {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RoutineAdmin),
            2 => Ok(Self::MembershipChange),
            3 => Ok(Self::OwnerSetChange),
            4 => Ok(Self::AuthoritySetChange),
            5 => Ok(Self::AuthorizationPolicyChange),
            6 => Ok(Self::CryptographicPolicyChange),
            7 => Ok(Self::CloseConversation),
            8 => Ok(Self::ProtocolUpgrade),
            9 => Ok(Self::RecoverIncarnation),
            _ => Err(format!("unknown MLS control action {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsControlProposalV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub proposal_id: Uuid,
    pub base_epoch: u64,
    pub action_type: MlsControlActionTypeV1,
    /// SHA-256 of `proposerCredentialPublicKey`. The key is random and scoped
    /// to this group so external ordering authorities cannot correlate the
    /// same device across conversations.
    pub proposer_id: String,
    /// Canonical uncompressed P-256 group-control key. Members bind this key to
    /// the manifest-verified MLS sender inside `encryptedPayload`; authorities
    /// learn only the group-scoped pseudonym. The origin server separately
    /// attests local authorization without disclosing the account.
    pub proposer_credential_public_key: String,
    /// MLS-encrypted control payload; orderers do not interpret it.
    pub encrypted_payload: String,
    pub payload_digest: String,
    pub created_at: i64,
    pub proposer_signature: String,
}

impl MlsControlProposalV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.proposal_id.is_nil()
            || self.incarnation == 0
            || self.created_at < 0
        {
            return Err(
                "MLS control proposal has invalid version, id, incarnation, or time".into(),
            );
        }
        validate_hash("proposerId", &self.proposer_id)?;
        validate_uncompressed_p256(
            "proposerCredentialPublicKey",
            &self.proposer_credential_public_key,
        )?;
        let proposer_key = decode_canonical_base64(
            "proposerCredentialPublicKey",
            &self.proposer_credential_public_key,
            65,
            65,
        )?;
        if hex::encode(Sha256::digest(proposer_key)) != self.proposer_id {
            return Err("MLS proposerId does not match the credential public key".into());
        }
        let payload = decode_canonical_base64(
            "encrypted MLS control payload",
            &self.encrypted_payload,
            1,
            MAX_MLS_CONTROL_PAYLOAD_BYTES,
        )?;
        validate_hash("payloadDigest", &self.payload_digest)?;
        if hex::encode(Sha256::digest(payload)) != self.payload_digest {
            return Err("MLS control payload digest does not match".into());
        }
        let signature =
            decode_canonical_base64("proposer signature", &self.proposer_signature, 70, 72)?;
        P256Signature::from_der(&signature)
            .map_err(|_| "MLS proposer signature is not canonical P-256 DER")?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-mls-control-proposal-v1\0";
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(self.conversation_id.as_bytes());
        out.extend_from_slice(&self.incarnation.to_be_bytes());
        out.extend_from_slice(self.proposal_id.as_bytes());
        out.extend_from_slice(&self.base_epoch.to_be_bytes());
        out.extend_from_slice(&u16::from(self.action_type).to_be_bytes());
        push_string(&mut out, &self.proposer_id)?;
        push_string(&mut out, &self.payload_digest)?;
        out.extend_from_slice(&self.created_at.to_be_bytes());
        Ok(out)
    }

    pub fn verify(&self) -> Result<(), String> {
        self.validate()?;
        let public_key = decode_canonical_base64(
            "proposerCredentialPublicKey",
            &self.proposer_credential_public_key,
            65,
            65,
        )?;
        let public_key = P256Key::from_sec1_bytes(&public_key)
            .map_err(|_| "MLS proposer credential key is not P-256")?;
        let signature =
            decode_canonical_base64("proposer signature", &self.proposer_signature, 70, 72)?;
        let signature = P256Signature::from_der(&signature)
            .map_err(|_| "MLS proposer signature is not canonical P-256 DER")?;
        public_key
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| "MLS proposal signature is invalid".into())
    }

    pub fn proposal_hash(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(self.signing_bytes()?);
        hash.update(self.proposer_signature.as_bytes());
        Ok(hex::encode(hash.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerApprovalV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub owner_set_sequence: u64,
    pub proposal_hash: String,
    pub owner_id: String,
    pub approved_at: i64,
    pub signature: String,
}

impl MlsOwnerApprovalV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-mls-owner-approval-v1\0";
        if self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.owner_set_sequence == 0
            || self.approved_at < 0
        {
            return Err("MLS owner approval has invalid identifiers or time".into());
        }
        validate_hash("proposalHash", &self.proposal_hash)?;
        validate_hash("ownerId", &self.owner_id)?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(self.conversation_id.as_bytes());
        out.extend_from_slice(&self.incarnation.to_be_bytes());
        out.extend_from_slice(&self.owner_set_sequence.to_be_bytes());
        push_string(&mut out, &self.proposal_hash)?;
        push_string(&mut out, &self.owner_id)?;
        out.extend_from_slice(&self.approved_at.to_be_bytes());
        Ok(out)
    }

    pub fn verify(&self, owner: &MlsOwnerV1) -> Result<(), String> {
        if self.owner_id != owner.owner_id {
            return Err("MLS owner approval is bound to a different owner".into());
        }
        verify_ed25519_signature(
            &owner.public_key,
            &self.signing_bytes()?,
            &self.signature,
            "MLS owner approval",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerApprovalCertificateV1 {
    pub owner_set_sequence: u64,
    pub proposal_hash: String,
    pub approvals: Vec<MlsOwnerApprovalV1>,
}

impl MlsOwnerApprovalCertificateV1 {
    pub fn verify(
        &self,
        proposal: &MlsControlProposalV1,
        owners: &MlsOwnerSetV1,
    ) -> Result<(), String> {
        owners.validate()?;
        let proposal_hash = proposal.proposal_hash()?;
        if self.owner_set_sequence != owners.sequence || self.proposal_hash != proposal_hash {
            return Err("MLS owner certificate is bound to the wrong proposal or owner set".into());
        }
        let mut previous = None;
        for approval in &self.approvals {
            if previous.is_some_and(|id: &str| approval.owner_id.as_str() <= id) {
                return Err("MLS owner approvals must be strictly ordered by ownerId".into());
            }
            previous = Some(approval.owner_id.as_str());
            if approval.conversation_id != proposal.conversation_id
                || approval.incarnation != proposal.incarnation
                || approval.owner_set_sequence != owners.sequence
                || approval.proposal_hash != proposal_hash
            {
                return Err("MLS owner approval does not match its certificate".into());
            }
            approval.verify(
                owners
                    .owner(&approval.owner_id)
                    .ok_or("MLS owner approval references an unknown owner")?,
            )?;
        }
        if self.approvals.len() < usize::from(owners.required_quorum) {
            return Err("MLS owner certificate does not meet quorum".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsOrderingVoteTypeV1 {
    Prevote = 1,
    Precommit = 2,
}

impl From<MlsOrderingVoteTypeV1> for u16 {
    fn from(value: MlsOrderingVoteTypeV1) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MlsOrderingVoteTypeV1 {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Prevote),
            2 => Ok(Self::Precommit),
            _ => Err(format!("unknown MLS ordering vote type {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOrderingVoteV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub authority_set_sequence: u64,
    pub height: u64,
    pub round: u32,
    pub vote_type: MlsOrderingVoteTypeV1,
    pub block_hash: String,
    pub authority_domain: String,
    pub authority_key_id: String,
    pub signature: String,
}

impl MlsOrderingVoteV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-mls-ordering-vote-v1\0";
        if self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.authority_set_sequence == 0
            || self.height == 0
        {
            return Err("MLS ordering vote has invalid identifiers or height".into());
        }
        validate_hash("blockHash", &self.block_hash)?;
        kutup_federation_proto::validate_server_name(&self.authority_domain)
            .map_err(|error| error.to_string())?;
        validate_hash("authorityKeyId", &self.authority_key_id)?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(self.conversation_id.as_bytes());
        out.extend_from_slice(&self.incarnation.to_be_bytes());
        out.extend_from_slice(&self.authority_set_sequence.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.round.to_be_bytes());
        out.extend_from_slice(&u16::from(self.vote_type).to_be_bytes());
        push_string(&mut out, &self.block_hash)?;
        push_string(&mut out, &self.authority_domain)?;
        push_string(&mut out, &self.authority_key_id)?;
        Ok(out)
    }

    pub fn verify(&self, authorities: &MlsAuthoritySetV1) -> Result<(), String> {
        if self.authority_set_sequence != authorities.sequence {
            return Err("MLS ordering vote uses the wrong authority-set sequence".into());
        }
        let authority = authorities
            .authority(&self.authority_domain)
            .ok_or("MLS ordering vote references an unknown authority")?;
        if self.authority_key_id != authority.key_id {
            return Err("MLS ordering vote uses the wrong authority key".into());
        }
        verify_ed25519_signature(
            &authority.public_key,
            &self.signing_bytes()?,
            &self.signature,
            "MLS ordering vote",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOrderingQuorumCertificateV1 {
    pub authority_set_sequence: u64,
    pub height: u64,
    pub round: u32,
    pub block_hash: String,
    pub votes: Vec<MlsOrderingVoteV1>,
}

impl MlsOrderingQuorumCertificateV1 {
    pub fn verify(&self, authorities: &MlsAuthoritySetV1) -> Result<(), String> {
        authorities.validate()?;
        validate_hash("blockHash", &self.block_hash)?;
        if self.authority_set_sequence != authorities.sequence || self.height == 0 {
            return Err("MLS quorum certificate has the wrong authority set or height".into());
        }
        let mut previous = None;
        for vote in &self.votes {
            if previous.is_some_and(|domain: &str| vote.authority_domain.as_str() <= domain) {
                return Err("MLS quorum votes must be strictly ordered by authority domain".into());
            }
            previous = Some(vote.authority_domain.as_str());
            if vote.vote_type != MlsOrderingVoteTypeV1::Precommit
                || vote.authority_set_sequence != self.authority_set_sequence
                || vote.height != self.height
                || vote.round != self.round
                || vote.block_hash != self.block_hash
            {
                return Err("MLS quorum vote does not match its certificate".into());
            }
            vote.verify(authorities)?;
        }
        if self.votes.len() < usize::from(authorities.required_quorum) {
            return Err("MLS ordering certificate does not meet quorum".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsControlBlockV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_block_hash: Option<String>,
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub proposal: MlsControlProposalV1,
    /// SHA-256 of the canonical public authority/owner transition object.
    /// Present only for transitions whose verifier data is carried outside the
    /// MLS-encrypted proposal payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_approval: Option<MlsOwnerApprovalCertificateV1>,
    pub finalized_at: i64,
}

/// Safety-first V1 authority request. Authorities sign at most one block hash
/// per height for the lifetime of an incarnation. Round zero is fixed in V1;
/// a conflicting race fails closed and requires explicit recovery rather than
/// risking two independently finalizable histories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsOrderingVoteRequestV1 {
    pub protocol_version: u16,
    pub block: MlsControlBlockV1,
    /// Present only for authority-set changes. Both the old and new authority
    /// sets verify the same next set and destination-delivery commitments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_change: Option<MlsAuthorityChangeV1>,
    /// Exact set under which the requested vote is made. During an authority
    /// transition both the current and next set vote over the same block hash.
    pub authority_set: MlsAuthoritySetV1,
    /// Required only when requesting a vote from the next authority set. It
    /// proves that the current authority quorum already authorized this exact
    /// transition block. A new authority imports and verifies history before
    /// accepting this certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_set_certificate: Option<MlsOrderingQuorumCertificateV1>,
}

impl FederatedMlsOrderingVoteRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION {
            return Err("unsupported federated MLS vote version".into());
        }
        self.block.validate()?;
        self.block.proposal.verify()?;
        self.authority_set.validate()?;
        match self.block.proposal.action_type {
            MlsControlActionTypeV1::AuthoritySetChange => {
                let change = self
                    .authority_change
                    .as_ref()
                    .ok_or("MLS authority vote omits its public transition")?;
                change.validate()?;
                if self.block.transition_digest.as_deref()
                    != Some(change.transition_digest()?.as_str())
                {
                    return Err("MLS authority vote transition digest does not match".into());
                }
            }
            _ if self.authority_change.is_some() => {
                return Err("unrelated MLS vote carries an authority transition".into())
            }
            _ => {}
        }
        if let Some(certificate) = &self.previous_set_certificate {
            if self.block.proposal.action_type != MlsControlActionTypeV1::AuthoritySetChange
                || certificate.height != self.block.height
                || certificate.block_hash != self.block.block_hash()?
            {
                return Err(
                    "MLS previous-set certificate does not authorize the transition block".into(),
                );
            }
            if self.authority_set
                != self
                    .authority_change
                    .as_ref()
                    .expect("authority change checked above")
                    .next_authority_set
            {
                return Err("next-set MLS vote uses a different authority set".into());
            }
        }
        Ok(())
    }
}

impl MlsControlBlockV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.height == 0
            || self.epoch_after <= self.epoch_before
            || self.finalized_at < 0
            || self.proposal.conversation_id != self.conversation_id
            || self.proposal.incarnation != self.incarnation
            || self.proposal.base_epoch != self.epoch_before
        {
            return Err("MLS control block has inconsistent ids, height, epoch, or time".into());
        }
        match (&self.previous_block_hash, self.height) {
            (None, 1) => {}
            (Some(hash), height) if height > 1 => {
                validate_hash("previousBlockHash", hash)?;
            }
            _ => return Err("MLS control block predecessor shape is invalid".into()),
        }
        match self.proposal.action_type {
            MlsControlActionTypeV1::MembershipChange
            | MlsControlActionTypeV1::AuthoritySetChange
            | MlsControlActionTypeV1::OwnerSetChange => {
                validate_hash(
                    "transitionDigest",
                    self.transition_digest
                        .as_deref()
                        .ok_or("MLS set transition is missing its public digest")?,
                )?;
            }
            MlsControlActionTypeV1::RoutineAdmin => {
                if let Some(digest) = self.transition_digest.as_deref() {
                    validate_hash("transitionDigest", digest)?;
                }
            }
            _ if self.transition_digest.is_some() => {
                return Err("unrelated MLS control block carries a transition digest".into());
            }
            _ => {}
        }
        self.proposal.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn block_hash(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsFinalizedControlBlockV1 {
    pub block: MlsControlBlockV1,
    pub quorum_certificate: MlsOrderingQuorumCertificateV1,
}

impl MlsFinalizedControlBlockV1 {
    pub fn verify(&self, authorities: &MlsAuthoritySetV1) -> Result<(), String> {
        self.block.validate()?;
        if self.quorum_certificate.block_hash != self.block.block_hash()?
            || self.quorum_certificate.height != self.block.height
        {
            return Err("MLS finalized block and quorum certificate do not match".into());
        }
        self.quorum_certificate.verify(authorities)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitMlsControlBlockV1 {
    pub finalized: MlsFinalizedControlBlockV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_transition: Option<MlsMembershipTransitionV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_change: Option<MlsAuthorityChangeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_transition: Option<MlsAuthorityTransitionCertificateV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_owner_set: Option<MlsOwnerSetV1>,
}

/// Federation wrapper for one finalized public control block. Participant
/// destinations receive exactly their committed private membership delivery;
/// ordering-only destinations receive no private delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsControlReplicaV1 {
    pub commit: CommitMlsControlBlockV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_delivery: Option<MlsMembershipDeliveryV1>,
}

impl FederatedMlsControlReplicaV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.commit.validate_shape()?;
        let delivery_transition = self.commit.membership_transition.as_ref().or_else(|| {
            self.commit
                .authority_change
                .as_ref()
                .map(|change| &change.delivery_transition)
        });
        match (delivery_transition, self.membership_delivery.as_ref()) {
            (Some(transition), Some(delivery)) => {
                delivery.verify_transition(transition)?;
                if delivery.epoch_after != self.commit.finalized.block.epoch_after {
                    return Err(
                        "MLS membership delivery is bound to a different finalized epoch".into(),
                    );
                }
            }
            (None, None) | (Some(_), None) => {}
            (None, Some(_)) => {
                return Err("unrelated MLS control replica carries a membership delivery".into())
            }
        }
        Ok(())
    }
}

impl CommitMlsControlBlockV1 {
    pub fn validate_shape(&self) -> Result<(), String> {
        self.finalized.block.validate()?;
        match self.finalized.block.proposal.action_type {
            MlsControlActionTypeV1::MembershipChange | MlsControlActionTypeV1::RoutineAdmin
                if self.membership_transition.is_some() =>
            {
                let transition = self
                    .membership_transition
                    .as_ref()
                    .expect("guarded roster transition");
                if self.authority_change.is_some()
                    || self.authority_transition.is_some()
                    || self.next_owner_set.is_some()
                    || transition.conversation_id != self.finalized.block.conversation_id
                    || transition.incarnation != self.finalized.block.incarnation
                    || transition.proposal_id != self.finalized.block.proposal.proposal_id
                {
                    return Err("membership change carries inconsistent transition data".into());
                }
                let expected = transition.transition_digest()?;
                if self.finalized.block.transition_digest.as_deref() != Some(expected.as_str()) {
                    return Err("roster transition does not match the finalized block".into());
                }
                match self.finalized.block.proposal.action_type {
                    MlsControlActionTypeV1::MembershipChange
                        if transition.previous_member_count == transition.next_member_count
                            || transition.previous_roster_commitment
                                == transition.next_roster_commitment =>
                    {
                        return Err("membership change must add or remove an account".into())
                    }
                    MlsControlActionTypeV1::RoutineAdmin
                        if transition.previous_member_count != transition.next_member_count
                            || transition.previous_participant_domains
                                != transition.next_participant_domains
                            || transition.previous_roster_commitment
                                == transition.next_roster_commitment =>
                    {
                        return Err(
                            "routine administrator change cannot alter membership routing".into(),
                        )
                    }
                    _ => {}
                }
            }
            MlsControlActionTypeV1::MembershipChange => {
                return Err("membership change requires its public transition".into())
            }
            MlsControlActionTypeV1::AuthoritySetChange => {
                if self.authority_change.is_none()
                    || self.authority_transition.is_none()
                    || self.membership_transition.is_some()
                    || self.next_owner_set.is_some()
                {
                    return Err(
                        "authority-set change requires exactly its joint transition data".into(),
                    );
                }
                let change = self
                    .authority_change
                    .as_ref()
                    .expect("checked authority transition");
                let expected = change.transition_digest()?;
                if change.delivery_transition.conversation_id
                    != self.finalized.block.conversation_id
                    || change.delivery_transition.incarnation != self.finalized.block.incarnation
                    || change.delivery_transition.proposal_id
                        != self.finalized.block.proposal.proposal_id
                {
                    return Err("authority change carries inconsistent delivery data".into());
                }
                if self.finalized.block.transition_digest.as_deref() != Some(expected.as_str()) {
                    return Err(
                        "authority transition data does not match the finalized block".into(),
                    );
                }
            }
            MlsControlActionTypeV1::OwnerSetChange => {
                if self.next_owner_set.is_none()
                    || self.authority_change.is_some()
                    || self.authority_transition.is_some()
                    || self.membership_transition.is_some()
                {
                    return Err("owner-set change requires exactly the next owner set".into());
                }
                let expected = mls_transition_digest(
                    self.next_owner_set
                        .as_ref()
                        .expect("checked owner transition"),
                )?;
                if self.finalized.block.transition_digest.as_deref() != Some(expected.as_str()) {
                    return Err("owner transition data does not match the finalized block".into());
                }
            }
            _ => {
                if self.authority_change.is_some()
                    || self.authority_transition.is_some()
                    || self.next_owner_set.is_some()
                    || self.membership_transition.is_some()
                {
                    return Err("unrelated MLS control action carries transition data".into());
                }
            }
        }
        Ok(())
    }
}

/// Authenticated same-origin page of the public MLS control log. The local
/// server is only a cache: clients replay every signature, quorum,
/// predecessor, epoch, and transition themselves. Heights are canonical
/// decimal strings so browser JSON parsing cannot round a `u64`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsClientControlHistoryPageV1 {
    pub protocol_version: u16,
    pub genesis: MlsConversationGenesisV1,
    pub genesis_participant_domains: Vec<String>,
    pub after_height: String,
    pub commits: Vec<CommitMlsControlBlockV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_height: Option<String>,
}

impl MlsClientControlHistoryPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION || self.commits.len() > 64 {
            return Err("MLS client control-history page has invalid version or size".into());
        }
        self.genesis.validate()?;
        validate_participant_domain_set(&self.genesis_participant_domains)?;
        let after = parse_canonical_u64("afterHeight", &self.after_height, true)?;
        let mut expected_height = after
            .checked_add(1)
            .ok_or("MLS client control-history height overflow")?;
        for request in &self.commits {
            request.validate_shape()?;
            let block = &request.finalized.block;
            if block.conversation_id != self.genesis.conversation_id
                || block.incarnation != self.genesis.incarnation
                || block.height != expected_height
            {
                return Err("MLS client control-history page is not contiguous".into());
            }
            expected_height = expected_height
                .checked_add(1)
                .ok_or("MLS client control-history height overflow")?;
        }
        match (self.commits.last(), self.next_height.as_deref()) {
            (None, None) => {}
            (Some(last), Some(next))
                if parse_canonical_u64("nextHeight", next, false)?
                    == last.finalized.block.height => {}
            _ => return Err("MLS client control-history cursor does not match its page".into()),
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES
        {
            return Err("MLS client control-history page exceeds 8 MiB".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }
}

/// Replay a complete client-visible control history and bind its public
/// commitments to the MLS-authenticated private GroupContext state.
pub fn verify_mls_client_control_history(
    pages: &[MlsClientControlHistoryPageV1],
    private_state: &MlsPrivateControlStateV1,
) -> Result<Option<String>, String> {
    private_state.validate()?;
    let first = pages.first().ok_or("MLS client control history is empty")?;
    let genesis = &first.genesis;
    let genesis_domains = &first.genesis_participant_domains;
    if genesis.conversation_id != private_state.conversation_id
        || genesis.incarnation != private_state.incarnation
        || genesis.roster_commitment != roster_commitment(&private_state.genesis_roster)?
        || genesis.member_count as usize != private_state.genesis_roster.len()
        || genesis.authority_set != private_state.genesis_authority_set
        || genesis.owner_set.as_ref() != Some(&private_state.genesis_owner_set)
    {
        return Err("MLS private control state differs from its genesis".into());
    }
    let private_genesis_domains = private_state
        .genesis_roster
        .iter()
        .map(|member| {
            member
                .address
                .server
                .clone()
                .ok_or("MLS private genesis member has no domain")
        })
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    if &private_genesis_domains != genesis_domains {
        return Err("MLS private genesis routing differs from public genesis".into());
    }

    let mut commits = Vec::new();
    let mut expected_after = 0u64;
    for page in pages {
        page.validate()?;
        if page.genesis != *genesis
            || page.genesis_participant_domains != *genesis_domains
            || page.after_height != expected_after.to_string()
            || page.commits.is_empty()
        {
            return Err("MLS client control-history pages are incomplete or reordered".into());
        }
        expected_after = page
            .commits
            .last()
            .ok_or("MLS client control-history page is empty")?
            .finalized
            .block
            .height;
        commits.extend(page.commits.iter().cloned());
    }
    if expected_after != private_state.height || commits.len() as u64 != private_state.height {
        return Err("MLS client control history does not reach the private control head".into());
    }
    let replayed = replay_mls_control_history(genesis, genesis_domains, &commits)?;
    let current_roster_commitment = roster_commitment(&private_state.roster)?;
    let current_domains = private_state
        .roster
        .iter()
        .map(|member| {
            member
                .address
                .server
                .clone()
                .ok_or("MLS private member has no domain")
        })
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    if replayed.height != private_state.height
        || replayed.epoch != private_state.epoch
        || replayed.roster_commitment != current_roster_commitment
        || replayed.member_count as usize != private_state.roster.len()
        || replayed.participant_domains != current_domains
        || replayed.authorities != private_state.authority_set
        || replayed.owners.as_ref() != Some(&private_state.owner_set)
    {
        return Err("MLS private control state differs from replayed public history".into());
    }
    match commits.last() {
        None if private_state.height == 0
            && private_state.proposal_id.is_none()
            && private_state.previous_block_hash.is_none() => {}
        Some(request)
            if private_state.proposal_id == Some(request.finalized.block.proposal.proposal_id)
                && private_state.previous_block_hash
                    == request.finalized.block.previous_block_hash => {}
        _ => return Err("MLS private control head differs from its final public block".into()),
    }
    Ok(replayed.previous_hash)
}

pub fn mls_transition_digest(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|error| error.to_string())
}

fn parse_canonical_u64(label: &str, value: &str, allow_zero: bool) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| (allow_zero || *parsed > 0) && parsed.to_string() == value)
        .ok_or_else(|| format!("MLS {label} is not canonical decimal"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitMlsControlBlockResponseV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub height: u64,
    pub epoch: u64,
    pub block_hash: String,
    pub idempotent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthorityTransitionCertificateV1 {
    pub previous_set_certificate: MlsOrderingQuorumCertificateV1,
    pub new_set_certificate: MlsOrderingQuorumCertificateV1,
}

impl MlsAuthorityTransitionCertificateV1 {
    pub fn verify(
        &self,
        block_hash: &str,
        previous: &MlsAuthoritySetV1,
        next: &MlsAuthoritySetV1,
    ) -> Result<(), String> {
        if previous.sequence.checked_add(1) != Some(next.sequence)
            || self.previous_set_certificate.block_hash != block_hash
            || self.new_set_certificate.block_hash != block_hash
        {
            return Err("MLS authority transition is not contiguous or binds another block".into());
        }
        self.previous_set_certificate.verify(previous)?;
        self.new_set_certificate.verify(next)
    }
}

/// Immutable authorization and history commitment used to stage a newly
/// added MLS ordering authority. It contains no roster identities beyond the
/// participant domains already visible to federation routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthorityBootstrapDescriptorV1 {
    pub protocol_version: u16,
    pub genesis: MlsConversationGenesisV1,
    pub genesis_participant_domains: Vec<String>,
    /// Exact current participant routing after replaying `history_block_count`.
    pub participant_domains: Vec<String>,
    pub transition_block: MlsControlBlockV1,
    pub previous_set_certificate: MlsOrderingQuorumCertificateV1,
    pub authority_change: MlsAuthorityChangeV1,
    pub history_block_count: u64,
    pub history_digest: String,
}

impl MlsAuthorityBootstrapDescriptorV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION {
            return Err("unsupported MLS authority bootstrap version".into());
        }
        self.genesis.validate()?;
        validate_participant_domain_set(&self.genesis_participant_domains)?;
        validate_participant_domain_set(&self.participant_domains)?;
        self.transition_block.validate()?;
        self.transition_block.proposal.verify()?;
        self.authority_change.validate()?;
        validate_hash("historyDigest", &self.history_digest)?;
        let next_set_digest = self.authority_change.transition_digest()?;
        if self.transition_block.conversation_id != self.genesis.conversation_id
            || self.transition_block.incarnation != self.genesis.incarnation
            || self.transition_block.proposal.action_type
                != MlsControlActionTypeV1::AuthoritySetChange
            || self.authority_change.delivery_transition.conversation_id
                != self.transition_block.conversation_id
            || self.authority_change.delivery_transition.incarnation
                != self.transition_block.incarnation
            || self.authority_change.delivery_transition.proposal_id
                != self.transition_block.proposal.proposal_id
            || self.transition_block.height != self.history_block_count.saturating_add(1)
            || self.previous_set_certificate.height != self.transition_block.height
            || self.previous_set_certificate.block_hash != self.transition_block.block_hash()?
            || self.transition_block.transition_digest.as_deref() != Some(next_set_digest.as_str())
        {
            return Err("MLS authority bootstrap descriptor is internally inconsistent".into());
        }
        match (
            self.history_block_count,
            &self.transition_block.previous_block_hash,
        ) {
            (0, None) => {}
            (count, Some(hash)) if count > 0 => {
                validate_hash("previousBlockHash", hash)?;
            }
            _ => {
                return Err(
                    "MLS authority bootstrap transition has the wrong predecessor shape".into(),
                )
            }
        }
        Ok(())
    }

    pub fn bootstrap_id(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-authority-bootstrap-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

/// One bounded, hash-chained page of exact finalized control requests. Pages
/// can be retried independently and are not materialized until the complete
/// history digest and every quorum certificate have been verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsAuthorityBootstrapPageV1 {
    pub descriptor: MlsAuthorityBootstrapDescriptorV1,
    pub bootstrap_id: String,
    pub page_index: u32,
    pub page_count: u32,
    pub start_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page_hash: Option<String>,
    pub commits: Vec<CommitMlsControlBlockV1>,
}

impl FederatedMlsAuthorityBootstrapPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.descriptor.validate()?;
        validate_hash("bootstrapId", &self.bootstrap_id)?;
        if self.bootstrap_id != self.descriptor.bootstrap_id()?
            || self.page_count == 0
            || self.page_count > i32::MAX as u32
            || self.page_index >= self.page_count
            || self.commits.len() > MAX_AUTHORITY_BOOTSTRAP_COMMITS_PER_PAGE
            || (self.descriptor.history_block_count > 0
                && u64::from(self.page_count) > self.descriptor.history_block_count)
        {
            return Err("MLS authority bootstrap page identifiers or bounds are invalid".into());
        }
        if self.page_index == 0 {
            if self.start_height != 1 || self.previous_page_hash.is_some() {
                return Err("first MLS authority bootstrap page has a predecessor".into());
            }
        } else {
            validate_hash(
                "previousPageHash",
                self.previous_page_hash
                    .as_deref()
                    .ok_or("MLS authority bootstrap page is missing its predecessor")?,
            )?;
        }
        if self.descriptor.history_block_count == 0 {
            if self.page_count != 1
                || self.page_index != 0
                || !self.commits.is_empty()
                || self.start_height != 1
            {
                return Err("empty MLS authority history must use one empty page".into());
            }
        } else {
            if self.commits.is_empty() {
                return Err("non-empty MLS authority history has an empty page".into());
            }
            for (offset, request) in self.commits.iter().enumerate() {
                request.validate_shape()?;
                let expected_height = self
                    .start_height
                    .checked_add(offset as u64)
                    .ok_or("MLS authority bootstrap height overflow")?;
                if request.finalized.block.conversation_id
                    != self.descriptor.genesis.conversation_id
                    || request.finalized.block.incarnation != self.descriptor.genesis.incarnation
                    || request.finalized.block.height != expected_height
                {
                    return Err(
                        "MLS authority bootstrap page contains a block at the wrong height".into(),
                    );
                }
            }
            let end = self
                .start_height
                .checked_add(self.commits.len() as u64 - 1)
                .ok_or("MLS authority bootstrap height overflow")?;
            if end > self.descriptor.history_block_count
                || (self.page_index + 1 == self.page_count
                    && end != self.descriptor.history_block_count)
                || (self.page_index + 1 < self.page_count
                    && end >= self.descriptor.history_block_count)
            {
                return Err("MLS authority bootstrap page has an invalid final height".into());
            }
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES {
            return Err("MLS authority bootstrap page exceeds 8 MiB".into());
        }
        Ok(())
    }

    pub fn page_hash(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-authority-bootstrap-page-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

/// Public-history commitment used to initialize a participant server that is
/// first added after conversation genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsParticipantBootstrapDescriptorV1 {
    pub protocol_version: u16,
    pub genesis: MlsConversationGenesisV1,
    pub genesis_participant_domains: Vec<String>,
    pub destination: String,
    pub transition_request: CommitMlsControlBlockV1,
    pub delivery_digest: String,
    pub history_block_count: u64,
    pub history_digest: String,
}

impl MlsParticipantBootstrapDescriptorV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION {
            return Err("unsupported MLS participant bootstrap version".into());
        }
        self.genesis.validate()?;
        validate_participant_domain_set(&self.genesis_participant_domains)?;
        kutup_federation_proto::validate_server_name(&self.destination)
            .map_err(|error| error.to_string())?;
        validate_hash("deliveryDigest", &self.delivery_digest)?;
        validate_hash("historyDigest", &self.history_digest)?;
        self.transition_request.validate_shape()?;
        let block = &self.transition_request.finalized.block;
        let transition = self
            .transition_request
            .membership_transition
            .as_ref()
            .ok_or("MLS participant bootstrap requires a membership transition")?;
        if block.conversation_id != self.genesis.conversation_id
            || block.incarnation != self.genesis.incarnation
            || block.height != self.history_block_count.saturating_add(1)
            || transition
                .previous_participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(&self.destination))
                .is_ok()
            || transition
                .next_participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(&self.destination))
                .is_err()
            || transition
                .delivery_commitment(&self.destination)
                .map(|commitment| commitment.delivery_digest.as_str())
                != Some(self.delivery_digest.as_str())
        {
            return Err("MLS participant bootstrap descriptor is inconsistent".into());
        }
        Ok(())
    }

    pub fn bootstrap_id(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-participant-bootstrap-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

/// One bounded page of participant bootstrap history. Exactly the final page
/// carries the destination-private delivery committed by the descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsParticipantBootstrapPageV1 {
    pub descriptor: MlsParticipantBootstrapDescriptorV1,
    pub bootstrap_id: String,
    pub page_index: u32,
    pub page_count: u32,
    pub start_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page_hash: Option<String>,
    pub commits: Vec<CommitMlsControlBlockV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_delivery: Option<MlsMembershipDeliveryV1>,
}

impl FederatedMlsParticipantBootstrapPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.descriptor.validate()?;
        validate_hash("bootstrapId", &self.bootstrap_id)?;
        if self.bootstrap_id != self.descriptor.bootstrap_id()?
            || self.page_count == 0
            || self.page_count > i32::MAX as u32
            || self.page_index >= self.page_count
            || (self.descriptor.history_block_count > 0
                && u64::from(self.page_count) > self.descriptor.history_block_count)
            || self.commits.len() > MAX_AUTHORITY_BOOTSTRAP_COMMITS_PER_PAGE
        {
            return Err("MLS participant bootstrap page identifiers or bounds are invalid".into());
        }
        if self.page_index == 0 {
            if self.start_height != 1 || self.previous_page_hash.is_some() {
                return Err("first MLS participant bootstrap page has a predecessor".into());
            }
        } else {
            validate_hash(
                "previousPageHash",
                self.previous_page_hash
                    .as_deref()
                    .ok_or("MLS participant bootstrap page is missing its predecessor")?,
            )?;
        }
        if self.descriptor.history_block_count == 0 {
            if self.page_count != 1
                || self.page_index != 0
                || !self.commits.is_empty()
                || self.start_height != 1
            {
                return Err("empty MLS participant history must use one empty page".into());
            }
        } else {
            if self.commits.is_empty() {
                return Err("non-empty MLS participant history has an empty page".into());
            }
            for (offset, request) in self.commits.iter().enumerate() {
                request.validate_shape()?;
                if request.finalized.block.conversation_id
                    != self.descriptor.genesis.conversation_id
                    || request.finalized.block.incarnation != self.descriptor.genesis.incarnation
                    || request.finalized.block.height != self.start_height + offset as u64
                {
                    return Err(
                        "MLS participant bootstrap page contains a block at the wrong height"
                            .into(),
                    );
                }
            }
            let end = self
                .start_height
                .checked_add(self.commits.len() as u64 - 1)
                .ok_or("MLS participant bootstrap height overflow")?;
            if end > self.descriptor.history_block_count
                || (self.page_index + 1 == self.page_count
                    && end != self.descriptor.history_block_count)
                || (self.page_index + 1 < self.page_count
                    && end >= self.descriptor.history_block_count)
            {
                return Err("MLS participant bootstrap page has an invalid final height".into());
            }
        }
        if self.page_index + 1 == self.page_count {
            let delivery = self
                .membership_delivery
                .as_ref()
                .ok_or("final MLS participant bootstrap page omits its private delivery")?;
            delivery.verify_transition(
                self.descriptor
                    .transition_request
                    .membership_transition
                    .as_ref()
                    .expect("descriptor validated membership transition"),
            )?;
            if delivery.destination != self.descriptor.destination
                || delivery.delivery_digest()? != self.descriptor.delivery_digest
            {
                return Err("MLS participant bootstrap delivery commitment does not match".into());
            }
        } else if self.membership_delivery.is_some() {
            return Err("non-final MLS participant bootstrap page carries private delivery".into());
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES
        {
            return Err("MLS participant bootstrap page exceeds 8 MiB".into());
        }
        Ok(())
    }

    pub fn page_hash(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-participant-bootstrap-page-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

pub fn verify_mls_participant_bootstrap_history(
    descriptor: &MlsParticipantBootstrapDescriptorV1,
    commits: &[CommitMlsControlBlockV1],
    delivery: &MlsMembershipDeliveryV1,
) -> Result<(), String> {
    descriptor.validate()?;
    if commits.len() as u64 != descriptor.history_block_count
        || mls_authority_history_digest(commits)? != descriptor.history_digest
    {
        return Err("MLS participant bootstrap history commitment does not match".into());
    }
    let replayed = replay_mls_control_history(
        &descriptor.genesis,
        &descriptor.genesis_participant_domains,
        commits,
    )?;
    let request = &descriptor.transition_request;
    let block = &request.finalized.block;
    if block.height != replayed.height + 1
        || block.epoch_before != replayed.epoch
        || block.previous_block_hash != replayed.previous_hash
    {
        return Err("MLS participant bootstrap transition does not extend history".into());
    }
    request.finalized.verify(&replayed.authorities)?;
    verify_bootstrap_owner_authorization(
        &descriptor.genesis.kind,
        block,
        replayed.owners.as_ref(),
    )?;
    let transition = request
        .membership_transition
        .as_ref()
        .expect("descriptor validated membership transition");
    if transition.previous_roster_commitment != replayed.roster_commitment
        || transition.previous_member_count != replayed.member_count
        || transition.previous_participant_domains != replayed.participant_domains
    {
        return Err("MLS participant bootstrap transition is not roster-contiguous".into());
    }
    delivery.verify_transition(transition)?;
    if delivery.destination != descriptor.destination
        || delivery.delivery_digest()? != descriptor.delivery_digest
        || delivery.epoch_after != block.epoch_after
    {
        return Err("MLS participant bootstrap private delivery does not match".into());
    }
    Ok(())
}

pub fn mls_authority_history_digest(commits: &[CommitMlsControlBlockV1]) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(b"kutup-mls-authority-history-v1\0");
    hash.update(
        u64::try_from(commits.len())
            .map_err(|_| "MLS authority history is too large")?
            .to_be_bytes(),
    );
    for request in commits {
        request.validate_shape()?;
        let bytes = serde_json::to_vec(request).map_err(|error| error.to_string())?;
        hash.update(
            u64::try_from(bytes.len())
                .map_err(|_| "MLS authority history entry is too large")?
                .to_be_bytes(),
        );
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Verify the complete control history and the old-set authorization for a
/// pending authority transition. The returned set is the exact current set
/// immediately before the transition.
pub fn verify_mls_authority_bootstrap_history(
    descriptor: &MlsAuthorityBootstrapDescriptorV1,
    commits: &[CommitMlsControlBlockV1],
) -> Result<MlsAuthoritySetV1, String> {
    descriptor.validate()?;
    if commits.len() as u64 != descriptor.history_block_count
        || mls_authority_history_digest(commits)? != descriptor.history_digest
    {
        return Err("MLS authority bootstrap history commitment does not match".into());
    }

    let replayed = replay_mls_control_history(
        &descriptor.genesis,
        &descriptor.genesis_participant_domains,
        commits,
    )?;
    if replayed.participant_domains != descriptor.participant_domains {
        return Err("MLS authority bootstrap participant routing does not match history".into());
    }

    let transition = &descriptor.transition_block;
    let delivery = &descriptor.authority_change.delivery_transition;
    if transition.height != replayed.height + 1
        || transition.epoch_before != replayed.epoch
        || transition.previous_block_hash != replayed.previous_hash
        || replayed.authorities.sequence.checked_add(1)
            != Some(descriptor.authority_change.next_authority_set.sequence)
        || delivery.previous_roster_commitment != replayed.roster_commitment
        || delivery.next_roster_commitment != replayed.roster_commitment
        || delivery.previous_member_count != replayed.member_count
        || delivery.next_member_count != replayed.member_count
        || delivery.previous_participant_domains != replayed.participant_domains
        || delivery.next_participant_domains != replayed.participant_domains
    {
        return Err(
            "MLS authority bootstrap transition does not extend the verified history".into(),
        );
    }
    verify_bootstrap_owner_authorization(
        &descriptor.genesis.kind,
        transition,
        replayed.owners.as_ref(),
    )?;
    descriptor
        .previous_set_certificate
        .verify(&replayed.authorities)?;
    Ok(replayed.authorities)
}

struct ReplayedMlsControlHistory {
    authorities: MlsAuthoritySetV1,
    owners: Option<MlsOwnerSetV1>,
    height: u64,
    epoch: u64,
    previous_hash: Option<String>,
    roster_commitment: String,
    member_count: u32,
    participant_domains: Vec<String>,
}

fn replay_mls_control_history(
    genesis: &MlsConversationGenesisV1,
    genesis_participant_domains: &[String],
    commits: &[CommitMlsControlBlockV1],
) -> Result<ReplayedMlsControlHistory, String> {
    genesis.validate()?;
    validate_participant_domain_set(genesis_participant_domains)?;
    let mut replayed = ReplayedMlsControlHistory {
        authorities: genesis.authority_set.clone(),
        owners: genesis.owner_set.clone(),
        height: 0,
        epoch: genesis.initial_epoch,
        previous_hash: None,
        roster_commitment: genesis.roster_commitment.clone(),
        member_count: genesis.member_count,
        participant_domains: genesis_participant_domains.to_vec(),
    };
    for request in commits {
        request.validate_shape()?;
        let block = &request.finalized.block;
        block.proposal.verify()?;
        if block.conversation_id != genesis.conversation_id
            || block.incarnation != genesis.incarnation
            || block.height != replayed.height + 1
            || block.epoch_before != replayed.epoch
            || block.previous_block_hash != replayed.previous_hash
        {
            return Err("MLS bootstrap history is not an exact chain".into());
        }
        request.finalized.verify(&replayed.authorities)?;
        verify_bootstrap_owner_authorization(&genesis.kind, block, replayed.owners.as_ref())?;
        let block_hash = block.block_hash()?;
        if block.proposal.action_type == MlsControlActionTypeV1::AuthoritySetChange {
            let change = request
                .authority_change
                .as_ref()
                .ok_or("MLS authority history transition omits its public change")?;
            let next = &change.next_authority_set;
            let delivery = &change.delivery_transition;
            if delivery.previous_roster_commitment != replayed.roster_commitment
                || delivery.next_roster_commitment != replayed.roster_commitment
                || delivery.previous_member_count != replayed.member_count
                || delivery.next_member_count != replayed.member_count
                || delivery.previous_participant_domains != replayed.participant_domains
                || delivery.next_participant_domains != replayed.participant_domains
            {
                return Err("MLS authority history changes its roster or routing".into());
            }
            request
                .authority_transition
                .as_ref()
                .ok_or("MLS authority history transition omits its joint certificate")?
                .verify(&block_hash, &replayed.authorities, next)?;
            replayed.authorities = next.clone();
        } else if matches!(
            block.proposal.action_type,
            MlsControlActionTypeV1::MembershipChange | MlsControlActionTypeV1::RoutineAdmin
        ) && request.membership_transition.is_some()
        {
            let transition = request
                .membership_transition
                .as_ref()
                .expect("guarded transition");
            if transition.previous_roster_commitment != replayed.roster_commitment
                || transition.previous_member_count != replayed.member_count
                || replayed.participant_domains != transition.previous_participant_domains
            {
                return Err("MLS roster history is not contiguous".into());
            }
            replayed.roster_commitment = transition.next_roster_commitment.clone();
            replayed.member_count = transition.next_member_count;
            replayed.participant_domains = transition.next_participant_domains.clone();
        } else if block.proposal.action_type == MlsControlActionTypeV1::OwnerSetChange {
            let current = replayed
                .owners
                .as_ref()
                .ok_or("MLS owner history transition has no current owner set")?;
            let next = request
                .next_owner_set
                .as_ref()
                .ok_or("MLS owner history transition omits its next set")?;
            next.validate()?;
            if current.sequence.checked_add(1) != Some(next.sequence) {
                return Err("MLS owner history sequence is not contiguous".into());
            }
            replayed.owners = Some(next.clone());
        }
        replayed.height = block.height;
        replayed.epoch = block.epoch_after;
        replayed.previous_hash = Some(block_hash);
    }
    Ok(replayed)
}

fn verify_bootstrap_owner_authorization(
    kind: &MlsConversationKindV1,
    block: &MlsControlBlockV1,
    owners: Option<&MlsOwnerSetV1>,
) -> Result<(), String> {
    if *kind == MlsConversationKindV1::Group && block.proposal.action_type.requires_owner_quorum() {
        block
            .owner_approval
            .as_ref()
            .ok_or("security-sensitive MLS history block omits owner approval")?
            .verify(
                &block.proposal,
                owners.ok_or("group MLS authority history has no owner set")?,
            )
    } else if let (Some(certificate), Some(owners)) = (&block.owner_approval, owners) {
        certificate.verify(&block.proposal, owners)
    } else {
        Ok(())
    }
}

fn validate_participant_domain_set(domains: &[String]) -> Result<(), String> {
    if domains.is_empty() || domains.len() > 1000 {
        return Err("MLS participant-domain set is empty or too large".into());
    }
    let mut previous = None;
    for domain in domains {
        kutup_federation_proto::validate_server_name(domain).map_err(|error| error.to_string())?;
        if previous.is_some_and(|prior: &str| domain.as_str() <= prior) {
            return Err("MLS participant domains must be strictly ordered".into());
        }
        previous = Some(domain.as_str());
    }
    Ok(())
}

/// Purpose-specific signer for authority votes. HSM providers implement this
/// trait and must fail closed; callers never request exportable key material.
pub trait MlsControlSigner {
    fn key_id(&self) -> String;
    fn public_key(&self) -> String;
    fn sign_mls_control(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

pub struct Ed25519MlsControlSigner(SigningKey);

impl Ed25519MlsControlSigner {
    pub fn new(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }
}

impl MlsControlSigner for Ed25519MlsControlSigner {
    fn key_id(&self) -> String {
        hex::encode(Sha256::digest(self.0.verifying_key().as_bytes()))
    }

    fn public_key(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0.verifying_key().as_bytes())
    }

    fn sign_mls_control(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

/// Purpose-specific signer for owner approvals. It intentionally has no
/// federation or authority-vote methods.
pub trait MlsOwnerSigner {
    fn owner_id(&self) -> String;
    fn public_key(&self) -> String;
    fn sign_mls_owner_approval(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

pub struct Ed25519MlsOwnerSigner {
    owner_id: String,
    key: SigningKey,
}

impl Ed25519MlsOwnerSigner {
    pub fn new(owner_id: String, key: SigningKey) -> Result<Self, String> {
        validate_hash("ownerId", &owner_id)?;
        Ok(Self { owner_id, key })
    }
}

impl MlsOwnerSigner for Ed25519MlsOwnerSigner {
    fn owner_id(&self) -> String {
        self.owner_id.clone()
    }

    fn public_key(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().as_bytes())
    }

    fn sign_mls_owner_approval(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.key.sign(message).to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMessageRequestPolicyV1 {
    pub maximum_messages: u16,
    pub maximum_ciphertext_bytes: u32,
    pub expiry_seconds: u64,
}

impl Default for PendingMessageRequestPolicyV1 {
    fn default() -> Self {
        Self {
            maximum_messages: 32,
            maximum_ciphertext_bytes: 1024 * 1024,
            expiry_seconds: 30 * 24 * 60 * 60,
        }
    }
}

impl PendingMessageRequestPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=128).contains(&self.maximum_messages)
            || !(64 * 1024..=16 * 1024 * 1024).contains(&self.maximum_ciphertext_bytes)
            || !(24 * 60 * 60..=90 * 24 * 60 * 60).contains(&self.expiry_seconds)
        {
            return Err("pending message-request policy is outside the v1 bounds".into());
        }
        Ok(())
    }

    pub fn strictest(self, other: Self) -> Self {
        Self {
            maximum_messages: self.maximum_messages.min(other.maximum_messages),
            maximum_ciphertext_bytes: self
                .maximum_ciphertext_bytes
                .min(other.maximum_ciphertext_bytes),
            expiry_seconds: self.expiry_seconds.min(other.expiry_seconds),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAbuseLimitsV1 {
    pub anonymous_attempts_per_ip_minute: u32,
    pub capability_bundle_requests_per_minute: u32,
    pub sealed_sends_per_capability_minute: u32,
    pub sealed_sends_per_capability_day: u32,
    pub federated_sealed_sends_per_origin_minute: u32,
    pub maximum_envelopes_per_request: u16,
    pub maximum_request_bytes: u32,
}

impl Default for MlsAbuseLimitsV1 {
    fn default() -> Self {
        Self {
            anonymous_attempts_per_ip_minute: 60,
            capability_bundle_requests_per_minute: 30,
            sealed_sends_per_capability_minute: 120,
            sealed_sends_per_capability_day: 10_000,
            federated_sealed_sends_per_origin_minute: 600,
            maximum_envelopes_per_request: MAX_ANONYMOUS_ENVELOPES as u16,
            maximum_request_bytes: MAX_ANONYMOUS_REQUEST_BYTES as u32,
        }
    }
}

impl MlsAbuseLimitsV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.anonymous_attempts_per_ip_minute == 0
            || self.capability_bundle_requests_per_minute == 0
            || self.sealed_sends_per_capability_minute == 0
            || self.sealed_sends_per_capability_day == 0
            || self.federated_sealed_sends_per_origin_minute == 0
            || self.maximum_envelopes_per_request == 0
            || self.maximum_envelopes_per_request > MAX_ANONYMOUS_ENVELOPES as u16
            || self.maximum_request_bytes < 4096
            || self.maximum_request_bytes > MAX_ANONYMOUS_REQUEST_BYTES as u32
        {
            return Err(
                "anonymous MLS abuse limits are invalid or exceed protocol ceilings".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOrderingServicePolicyV1 {
    pub policy_version: u16,
    pub canonical_domain: String,
    pub suite: MlsCipherSuiteId,
    pub anonymous_delivery_suite: MlsAnonymousDeliverySuiteV1,
    pub control_signing_key_id: String,
    pub control_signing_public_key: String,
    pub accepts_group_ordering: bool,
    pub maximum_group_members: u16,
    pub maximum_authorities: u16,
    pub maximum_control_payload_bytes: u32,
    pub pending_message_requests: PendingMessageRequestPolicyV1,
    pub abuse_limits: MlsAbuseLimitsV1,
}

impl MlsOrderingServicePolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_version != MLS_ORDERING_SERVICE_POLICY_VERSION {
            return Err("unsupported MLS ordering service policy version".into());
        }
        kutup_federation_proto::validate_server_name(&self.canonical_domain)
            .map_err(|error| error.to_string())?;
        validate_ed25519_key(
            "MLS control signing",
            &self.control_signing_key_id,
            &self.control_signing_public_key,
        )?;
        if !(256..=1000).contains(&self.maximum_group_members)
            || !(1..=64).contains(&self.maximum_authorities)
            || !(4096..=MAX_MLS_CONTROL_PAYLOAD_BYTES as u32)
                .contains(&self.maximum_control_payload_bytes)
        {
            return Err("MLS ordering service limits are outside the v1 bounds".into());
        }
        self.pending_message_requests.validate()?;
        self.abuse_limits.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsKeyPackageV1 {
    pub device_id: u32,
    pub manifest_version: u64,
    pub suite: MlsCipherSuiteId,
    /// MLS KeyPackageRef for the SHA-256 ciphersuite, lowercase hex.
    pub key_package_ref: String,
    pub key_package: String,
    pub expires_at: i64,
}

impl MlsKeyPackageV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.device_id == 0 || self.manifest_version == 0 || self.expires_at <= now {
            return Err("MLS KeyPackage has invalid device, manifest, or expiry".into());
        }
        validate_hash("keyPackageRef", &self.key_package_ref)?;
        decode_canonical_base64(
            "MLS KeyPackage",
            &self.key_package,
            1,
            MAX_MLS_KEY_PACKAGE_BYTES,
        )?;
        Ok(())
    }
}

/// Authenticated publication of KeyPackages for a device already bound in the
/// current transparency-logged manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishMlsKeyPackagesRequestV1 {
    pub protocol_version: u16,
    pub manifest_version: u64,
    pub device_id: u32,
    pub key_packages: Vec<MlsKeyPackageV1>,
}

impl PublishMlsKeyPackagesRequestV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.manifest_version == 0
            || self.device_id == 0
            || self.key_packages.is_empty()
            || self.key_packages.len() > 100
        {
            return Err("MLS KeyPackage publication shape is invalid".into());
        }
        let mut references = BTreeSet::new();
        for package in &self.key_packages {
            package.validate(now)?;
            if package.device_id != self.device_id
                || package.manifest_version != self.manifest_version
                || !references.insert(package.key_package_ref.as_str())
            {
                return Err("MLS KeyPackages must be unique and match one device manifest".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum MlsDeliveryCapabilityKindV1 {
    Direct,
    Group,
}

/// Publishes only the verifier for an epoch-bound delivery capability. The raw
/// capability is delivered end-to-end inside MLS and is never persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishMlsDeliveryCapabilityV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub epoch: u64,
    pub capability_kind: MlsDeliveryCapabilityKindV1,
    pub capability_hash: String,
    pub policy_sequence: u64,
}

impl PublishMlsDeliveryCapabilityV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.policy_sequence == 0
        {
            return Err("MLS delivery capability identifiers are invalid".into());
        }
        validate_hash("capabilityHash", &self.capability_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsKeyPackageCountResponseV1 {
    pub device_id: u32,
    pub available: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsKeyPackageRequestV1 {
    pub protocol_version: u16,
    pub recipient: AccountAddress,
    /// Canonical padded base64 16-byte delivery capability.
    pub capability: String,
    /// Highest transparency checkpoint already pinned by the requesting
    /// client, encoded as canonical decimal to preserve all 64 bits in JS.
    pub transparency_tree_size: String,
}

/// Identified first-contact KeyPackage claim used only to construct an MLS
/// membership invitation. Unlike established application delivery, the
/// destination is allowed to learn the requester account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentifiedMlsKeyPackageRequestV1 {
    pub protocol_version: u16,
    pub recipient: AccountAddress,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub transparency_tree_size: String,
}

impl IdentifiedMlsKeyPackageRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.recipient.server.is_none()
            || self.conversation_id.is_nil()
            || self.incarnation == 0
        {
            return Err("identified MLS KeyPackage request has invalid identifiers".into());
        }
        self.known_tree_size()?;
        Ok(())
    }

    pub fn known_tree_size(&self) -> Result<u64, String> {
        let value = self
            .transparency_tree_size
            .parse::<u64>()
            .map_err(|_| "transparencyTreeSize must be canonical decimal".to_string())?;
        if value.to_string() != self.transparency_tree_size {
            return Err("transparencyTreeSize must be canonical decimal".into());
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedIdentifiedMlsKeyPackageRequestV1 {
    pub origin_domain: String,
    pub requester: AccountAddress,
    pub request: IdentifiedMlsKeyPackageRequestV1,
}

impl FederatedIdentifiedMlsKeyPackageRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        self.request.validate()?;
        if self.requester.server.as_deref() != Some(self.origin_domain.as_str()) {
            return Err("federated identified MLS request has the wrong requester identity".into());
        }
        Ok(())
    }
}

impl AnonymousMlsKeyPackageRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION || self.recipient.server.is_none() {
            return Err("anonymous MLS KeyPackage request has invalid version or recipient".into());
        }
        decode_canonical_base64("delivery capability", &self.capability, 16, 16)?;
        self.known_tree_size()?;
        Ok(())
    }

    pub fn known_tree_size(&self) -> Result<u64, String> {
        let value = self
            .transparency_tree_size
            .parse::<u64>()
            .map_err(|_| "transparencyTreeSize must be canonical decimal".to_string())?;
        if value.to_string() != self.transparency_tree_size {
            return Err("transparencyTreeSize must be canonical decimal".into());
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsKeyPackageBundleV1 {
    pub recipient: AccountAddress,
    pub manifest: DeviceManifest,
    pub transparency: ManifestTransparencyProof,
    pub key_packages: Vec<MlsKeyPackageV1>,
}

impl MlsKeyPackageBundleV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.recipient.server.is_none()
            || self.key_packages.is_empty()
            || self.key_packages.len() > MAX_ANONYMOUS_ENVELOPES
        {
            return Err("anonymous MLS KeyPackage response shape is invalid".into());
        }
        self.manifest.verify()?;
        self.transparency
            .leaf
            .matches_manifest(&self.recipient.username, &self.manifest)?;
        self.transparency.verify_inclusion()?;
        self.transparency.verify_current_map()?;
        self.transparency.verify_authentication()?;
        let mut devices = BTreeSet::new();
        for package in &self.key_packages {
            package.validate(now)?;
            if package.manifest_version != self.manifest.version
                || !devices.insert(package.device_id)
            {
                return Err(
                    "anonymous MLS KeyPackages must be unique and use one manifest version".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsDeliveryResponseV1 {
    pub accepted: bool,
    pub stored_devices: u16,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsDeviceEnvelopeV1 {
    pub device_id: u32,
    /// HPKE KEM encapsulation (uncompressed P-256 point, 65 bytes).
    pub encapsulated_key: String,
    /// HPKE ciphertext containing the entire padded MLS PrivateMessage.
    pub ciphertext: String,
}

impl AnonymousMlsDeviceEnvelopeV1 {
    fn validate(&self) -> Result<usize, String> {
        if self.device_id == 0 {
            return Err("anonymous MLS envelope device id must be positive".into());
        }
        decode_canonical_base64("HPKE encapsulated key", &self.encapsulated_key, 65, 65)?;
        let ciphertext = decode_canonical_base64(
            "anonymous MLS ciphertext",
            &self.ciphertext,
            17,
            1024 * 1024,
        )?;
        Ok(ciphertext.len() + 65)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsSubmissionV1 {
    pub protocol_version: u16,
    pub recipient: AccountAddress,
    pub send_id: Uuid,
    pub capability: String,
    pub suite: MlsAnonymousDeliverySuiteV1,
    pub envelopes: Vec<AnonymousMlsDeviceEnvelopeV1>,
}

impl AnonymousMlsSubmissionV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.recipient.server.is_none()
            || self.send_id.is_nil()
            || self.envelopes.is_empty()
            || self.envelopes.len() > MAX_ANONYMOUS_ENVELOPES
        {
            return Err("anonymous MLS submission shape is invalid".into());
        }
        decode_canonical_base64("delivery capability", &self.capability, 16, 16)?;
        let mut total = 0usize;
        let mut previous = None;
        for envelope in &self.envelopes {
            if previous.is_some_and(|device_id| envelope.device_id <= device_id) {
                return Err(
                    "anonymous MLS envelopes must be strictly ordered by destination device".into(),
                );
            }
            previous = Some(envelope.device_id);
            total = total
                .checked_add(envelope.validate()?)
                .ok_or("anonymous MLS request size overflow")?;
        }
        if total > MAX_ANONYMOUS_REQUEST_BYTES {
            return Err("anonymous MLS request exceeds the protocol size ceiling".into());
        }
        Ok(())
    }

    pub fn aad_for_device(&self, device_id: u32) -> Result<Vec<u8>, String> {
        self.validate()?;
        anonymous_mls_delivery_aad(&self.recipient, self.send_id, self.suite, device_id)
    }
}

pub fn anonymous_mls_delivery_aad(
    recipient: &AccountAddress,
    send_id: Uuid,
    suite: MlsAnonymousDeliverySuiteV1,
    device_id: u32,
) -> Result<Vec<u8>, String> {
    if recipient.server.is_none() || send_id.is_nil() || device_id == 0 {
        return Err("anonymous MLS AAD identifiers are invalid".into());
    }
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(ANONYMOUS_MLS_DELIVERY_CONTEXT);
    push_string(&mut aad, &recipient.canonical())?;
    aad.extend_from_slice(&device_id.to_be_bytes());
    aad.extend_from_slice(send_id.as_bytes());
    aad.extend_from_slice(&u16::from(suite).to_be_bytes());
    Ok(aad)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedAnonymousMlsTransactionV1 {
    pub origin_domain: String,
    pub origin_sequence: u64,
    #[serde(flatten)]
    pub submission: AnonymousMlsSubmissionV1,
}

impl FederatedAnonymousMlsTransactionV1 {
    pub fn validate(&self) -> Result<(), String> {
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        if self.origin_sequence == 0 {
            return Err("federated anonymous MLS sequence must be positive".into());
        }
        self.submission.validate()
    }
}

pub fn derive_group_delivery_capability(
    exporter_secret: &[u8],
    conversation_id: Uuid,
    incarnation: u64,
    epoch: u64,
    recipient: &AccountAddress,
) -> Result<[u8; 16], String> {
    if exporter_secret.len() < 16
        || conversation_id.is_nil()
        || incarnation == 0
        || recipient.server.is_none()
    {
        return Err("group delivery capability input is invalid".into());
    }
    let mut info = Vec::with_capacity(256);
    info.extend_from_slice(GROUP_DELIVERY_CAPABILITY_CONTEXT);
    info.extend_from_slice(conversation_id.as_bytes());
    info.extend_from_slice(&incarnation.to_be_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    push_string(&mut info, &recipient.canonical())?;
    let mut capability = [0u8; 16];
    Hkdf::<Sha256>::new(None, exporter_secret)
        .expand(&info, &mut capability)
        .map_err(|_| "group delivery capability derivation failed")?;
    Ok(capability)
}

fn decode_canonical<T>(bytes: &[u8], validate: fn(&T) -> Result<(), String>) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_CANONICAL_POLICY_BYTES {
        return Err("canonical MLS payload is too large".into());
    }
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    validate(&value)?;
    if serde_json::to_vec(&value).map_err(|error| error.to_string())? != bytes {
        return Err("MLS payload is not in canonical JSON encoding".into());
    }
    Ok(value)
}

fn validate_hash(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{name} must be lowercase SHA-256 hex"))?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{name} has the wrong length"))
}

fn validate_uncompressed_p256(name: &str, value: &str) -> Result<(), String> {
    let bytes = decode_canonical_base64(name, value, 65, 65)?;
    if bytes.first() != Some(&4) || p256::PublicKey::from_sec1_bytes(&bytes).is_err() {
        return Err(format!("{name} must be a valid uncompressed P-256 point"));
    }
    Ok(())
}

fn decode_canonical_base64(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if bytes.len() < minimum
        || bytes.len() > maximum
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != value
    {
        return Err(format!(
            "{name} must be canonical padded base64 within its size limit"
        ));
    }
    Ok(bytes)
}

fn validate_ed25519_key(name: &str, key_id: &str, encoded: &str) -> Result<(), String> {
    validate_hash(name, key_id)?;
    let bytes = decode_canonical_base64(name, encoded, 32, 32)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| format!("{name} is not Ed25519"))?;
    if hex::encode(Sha256::digest(key_bytes)) != key_id {
        return Err(format!("{name} key id does not match its public key"));
    }
    Ok(())
}

fn verify_ed25519_signature(
    public_key: &str,
    message: &[u8],
    signature: &str,
    name: &str,
) -> Result<(), String> {
    let public = decode_canonical_base64(name, public_key, 32, 32)?;
    let signature = decode_canonical_base64(name, signature, 64, 64)?;
    let verifying_key = VerifyingKey::from_bytes(
        &public
            .try_into()
            .map_err(|_| format!("{name} public key must be 32 bytes"))?,
    )
    .map_err(|_| format!("{name} public key is not Ed25519"))?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| format!("{name} signature is malformed"))?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| format!("{name} signature is invalid"))
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "MLS string is too long")?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn authority(domain: &str, seed: u8) -> (MlsAuthorityV1, SigningKey) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
        (
            MlsAuthorityV1 {
                domain: domain.into(),
                key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
                public_key,
            },
            key,
        )
    }

    fn authority_set(count: usize) -> (MlsAuthoritySetV1, BTreeMap<String, SigningKey>) {
        let mut authorities = Vec::new();
        let mut keys = BTreeMap::new();
        for index in 0..count {
            let domain = format!("a{index}.example");
            let (authority, key) = authority(&domain, (index + 1) as u8);
            keys.insert(domain, key);
            authorities.push(authority);
        }
        (
            MlsAuthoritySetV1 {
                sequence: 1,
                required_quorum: MlsAuthoritySetV1::quorum_for(count).unwrap(),
                authorities,
            },
            keys,
        )
    }

    #[test]
    fn suite_is_exactly_wire_suite_zero_x_two() {
        assert_eq!(
            serde_json::to_string(&MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256).unwrap(),
            "2"
        );
        assert!(
            serde_json::from_str::<MlsCipherSuiteId>("1").is_err(),
            "the old direct-chat suite must not be accepted as MLS"
        );
    }

    #[test]
    fn quorum_formula_covers_small_and_large_sets() {
        let expected = [(1, 1), (2, 2), (3, 3), (4, 3), (7, 5), (10, 7), (64, 43)];
        for (count, quorum) in expected {
            assert_eq!(MlsAuthoritySetV1::quorum_for(count).unwrap(), quorum);
        }
        assert!(MlsAuthoritySetV1::quorum_for(0).is_err());
        assert!(MlsAuthoritySetV1::quorum_for(65).is_err());
    }

    #[test]
    fn direct_roster_requires_exact_participant_authorities() {
        let (authorities, _) = authority_set(2);
        let members = vec![
            MlsConversationMemberV1 {
                address: "alice@a0.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
            MlsConversationMemberV1 {
                address: "bobby@a1.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
        ];
        let request = CreateMlsConversationRequestV1 {
            genesis: MlsConversationGenesisV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id: Uuid::from_u128(11),
                incarnation: 1,
                mls_group_id: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
                kind: MlsConversationKindV1::Direct,
                suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
                roster_commitment: roster_commitment(&members).unwrap(),
                member_count: 2,
                authority_set: authorities,
                owner_set: None,
                initial_epoch: 0,
                created_at: 1,
            },
            members,
        };
        request.validate().unwrap();

        let replica = FederatedMlsGenesisReplicaV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: request.genesis.clone(),
            participant_domains: vec!["a0.example".into(), "a1.example".into()],
            members: vec![request.members[0].clone()],
        };
        replica.validate().unwrap();
        let encoded = serde_json::to_string(&replica).unwrap();
        assert!(!encoded.contains("bobby"));

        let mut mixed_destination = replica;
        mixed_destination.members.push(request.members[1].clone());
        assert!(mixed_destination.validate().is_err());

        let mut wrong = request.clone();
        wrong.genesis.authority_set.authorities[1].domain = "other.example".into();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn membership_transition_commits_destination_private_snapshots() {
        let conversation_id = Uuid::from_u128(71);
        let alice = MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: true,
            owner_id: None,
        };
        let bob = MlsConversationMemberV1 {
            address: "bobby@a1.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        };
        let previous = roster_commitment(std::slice::from_ref(&alice)).unwrap();
        let next = roster_commitment(&[alice.clone(), bob.clone()]).unwrap();
        let delivery_a = MlsMembershipDeliveryV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: Uuid::from_u128(72),
            destination: "a0.example".into(),
            epoch_after: 1,
            next_roster_commitment: next.clone(),
            next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            local_members_after: vec![alice],
            envelopes: Vec::new(),
        };
        let delivery_b = MlsMembershipDeliveryV1 {
            destination: "a1.example".into(),
            local_members_after: vec![bob],
            ..delivery_a.clone()
        };
        let transition = MlsMembershipTransitionV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: delivery_a.proposal_id,
            previous_roster_commitment: previous,
            next_roster_commitment: next,
            previous_member_count: 1,
            next_member_count: 2,
            previous_participant_domains: vec!["a0.example".into()],
            next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            deliveries: vec![
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a0.example".into(),
                    delivery_digest: delivery_a.delivery_digest().unwrap(),
                },
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a1.example".into(),
                    delivery_digest: delivery_b.delivery_digest().unwrap(),
                },
            ],
        };
        transition.validate().unwrap();
        delivery_a.verify_transition(&transition).unwrap();
        delivery_b.verify_transition(&transition).unwrap();

        let public_json = serde_json::to_string(&transition).unwrap();
        assert!(!public_json.contains("alice"));
        assert!(!public_json.contains("bobby"));

        let mut tampered = delivery_b;
        tampered.local_members_after[0].is_admin = true;
        assert!(tampered.verify_transition(&transition).is_err());
        let mut missing = transition;
        missing.deliveries.pop();
        assert!(missing.validate().is_err());
    }

    #[test]
    fn authority_change_has_a_stable_composite_digest_and_rejects_roster_changes() {
        let conversation_id = Uuid::from_u128(73);
        let (mut next_authority_set, _) = authority_set(1);
        next_authority_set.sequence = 2;
        let transition = MlsMembershipTransitionV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: Uuid::from_u128(74),
            previous_roster_commitment: "aa".repeat(32),
            next_roster_commitment: "aa".repeat(32),
            previous_member_count: 2,
            next_member_count: 2,
            previous_participant_domains: vec!["a0.example".into()],
            next_participant_domains: vec!["a0.example".into()],
            deliveries: vec![MlsMembershipDeliveryCommitmentV1 {
                destination: "a0.example".into(),
                delivery_digest: "bb".repeat(32),
            }],
        };
        let change = MlsAuthorityChangeV1 {
            next_authority_set,
            delivery_transition: transition,
        };
        change.validate().unwrap();
        assert_eq!(
            change.transition_digest().unwrap(),
            "5f3cbf3bdb82c84c825c74fdee376ca018f060a07d1b44fa402fba35cddc9d9d"
        );
        let encoded = serde_json::to_vec(&change).unwrap();
        assert_eq!(
            serde_json::to_vec(&serde_json::from_slice::<MlsAuthorityChangeV1>(&encoded).unwrap())
                .unwrap(),
            encoded
        );

        let mut changed_roster = change;
        changed_roster.delivery_transition.next_roster_commitment = "cc".repeat(32);
        assert!(changed_roster.validate().is_err());
    }

    #[test]
    fn new_participant_bootstrap_requires_complete_qc_history_and_private_digest() {
        use p256::ecdsa::signature::Signer as _;

        let conversation_id = Uuid::from_u128(81);
        let proposal_id = Uuid::from_u128(82);
        let (authorities, authority_keys) = authority_set(2);
        let alice = MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: true,
            owner_id: None,
        };
        let bob = MlsConversationMemberV1 {
            address: "bobby@a1.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        };
        let carol = MlsConversationMemberV1 {
            address: "carol@a2.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        };
        let previous_roster = roster_commitment(&[alice.clone(), bob.clone()]).unwrap();
        let next_roster = roster_commitment(&[alice.clone(), bob.clone(), carol.clone()]).unwrap();
        let delivery_a0 = MlsMembershipDeliveryV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id,
            destination: "a0.example".into(),
            epoch_after: 1,
            next_roster_commitment: next_roster.clone(),
            next_participant_domains: vec![
                "a0.example".into(),
                "a1.example".into(),
                "a2.example".into(),
            ],
            local_members_after: vec![alice],
            envelopes: Vec::new(),
        };
        let delivery_a1 = MlsMembershipDeliveryV1 {
            destination: "a1.example".into(),
            local_members_after: vec![bob],
            ..delivery_a0.clone()
        };
        let delivery_a2 = MlsMembershipDeliveryV1 {
            destination: "a2.example".into(),
            local_members_after: vec![carol],
            ..delivery_a0.clone()
        };
        let transition = MlsMembershipTransitionV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id,
            previous_roster_commitment: previous_roster.clone(),
            next_roster_commitment: next_roster,
            previous_member_count: 2,
            next_member_count: 3,
            previous_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            next_participant_domains: vec![
                "a0.example".into(),
                "a1.example".into(),
                "a2.example".into(),
            ],
            deliveries: vec![
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a0.example".into(),
                    delivery_digest: delivery_a0.delivery_digest().unwrap(),
                },
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a1.example".into(),
                    delivery_digest: delivery_a1.delivery_digest().unwrap(),
                },
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a2.example".into(),
                    delivery_digest: delivery_a2.delivery_digest().unwrap(),
                },
            ],
        };
        let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[19u8; 32]).into()).unwrap();
        let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
        let payload = b"encrypted membership change";
        let mut proposal = MlsControlProposalV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id,
            base_epoch: 0,
            action_type: MlsControlActionTypeV1::MembershipChange,
            proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
            proposer_credential_public_key: base64::engine::general_purpose::STANDARD
                .encode(proposer_public.as_bytes()),
            encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
            payload_digest: hex::encode(Sha256::digest(payload)),
            created_at: 1,
            proposer_signature: String::new(),
        };
        let signature: p256::ecdsa::Signature =
            proposer_key.sign(&proposal.signing_bytes().unwrap());
        proposal.proposer_signature =
            base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
        let block = MlsControlBlockV1 {
            conversation_id,
            incarnation: 1,
            height: 1,
            previous_block_hash: None,
            epoch_before: 0,
            epoch_after: 1,
            proposal,
            transition_digest: Some(transition.transition_digest().unwrap()),
            owner_approval: None,
            finalized_at: 2,
        };
        let block_hash = block.block_hash().unwrap();
        let mut votes = Vec::new();
        for authority in &authorities.authorities {
            let mut vote = MlsOrderingVoteV1 {
                conversation_id,
                incarnation: 1,
                authority_set_sequence: authorities.sequence,
                height: 1,
                round: 0,
                vote_type: MlsOrderingVoteTypeV1::Precommit,
                block_hash: block_hash.clone(),
                authority_domain: authority.domain.clone(),
                authority_key_id: authority.key_id.clone(),
                signature: String::new(),
            };
            vote.signature = base64::engine::general_purpose::STANDARD.encode(
                authority_keys[&authority.domain]
                    .sign(&vote.signing_bytes().unwrap())
                    .to_bytes(),
            );
            votes.push(vote);
        }
        let request = CommitMlsControlBlockV1 {
            finalized: MlsFinalizedControlBlockV1 {
                block,
                quorum_certificate: MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: authorities.sequence,
                    height: 1,
                    round: 0,
                    block_hash,
                    votes,
                },
            },
            membership_transition: Some(transition),
            authority_change: None,
            authority_transition: None,
            next_owner_set: None,
        };
        let history = Vec::new();
        let descriptor = MlsParticipantBootstrapDescriptorV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: MlsConversationGenesisV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id,
                incarnation: 1,
                mls_group_id: base64::engine::general_purpose::STANDARD.encode([9u8; 16]),
                kind: MlsConversationKindV1::Direct,
                suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
                roster_commitment: previous_roster,
                member_count: 2,
                authority_set: authorities,
                owner_set: None,
                initial_epoch: 0,
                created_at: 1,
            },
            genesis_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            destination: "a2.example".into(),
            transition_request: request,
            delivery_digest: delivery_a2.delivery_digest().unwrap(),
            history_block_count: 0,
            history_digest: mls_authority_history_digest(&history).unwrap(),
        };
        verify_mls_participant_bootstrap_history(&descriptor, &history, &delivery_a2).unwrap();
        let page = FederatedMlsParticipantBootstrapPageV1 {
            bootstrap_id: descriptor.bootstrap_id().unwrap(),
            descriptor: descriptor.clone(),
            page_index: 0,
            page_count: 1,
            start_height: 1,
            previous_page_hash: None,
            commits: history,
            membership_delivery: Some(delivery_a2.clone()),
        };
        page.validate().unwrap();

        let mut tampered = delivery_a2;
        tampered.local_members_after[0].is_admin = true;
        assert!(verify_mls_participant_bootstrap_history(&descriptor, &[], &tampered).is_err());
        let mut wrong_destination = descriptor;
        wrong_destination.destination = "a1.example".into();
        assert!(wrong_destination.validate().is_err());
    }

    #[test]
    fn ordering_certificate_requires_distinct_matching_precommits() {
        let conversation_id = Uuid::from_u128(1);
        let (authorities, keys) = authority_set(4);
        let block_hash = "ab".repeat(32);
        let mut votes = Vec::new();
        for authority in authorities.authorities.iter().take(3) {
            let mut vote = MlsOrderingVoteV1 {
                conversation_id,
                incarnation: 1,
                authority_set_sequence: 1,
                height: 1,
                round: 0,
                vote_type: MlsOrderingVoteTypeV1::Precommit,
                block_hash: block_hash.clone(),
                authority_domain: authority.domain.clone(),
                authority_key_id: authority.key_id.clone(),
                signature: String::new(),
            };
            vote.signature = base64::engine::general_purpose::STANDARD.encode(
                keys[&authority.domain]
                    .sign(&vote.signing_bytes().unwrap())
                    .to_bytes(),
            );
            votes.push(vote);
        }
        let certificate = MlsOrderingQuorumCertificateV1 {
            authority_set_sequence: 1,
            height: 1,
            round: 0,
            block_hash,
            votes,
        };
        certificate.verify(&authorities).unwrap();

        let mut insufficient = certificate.clone();
        insufficient.votes.pop();
        assert!(insufficient.verify(&authorities).is_err());
    }

    #[test]
    fn new_authority_bootstrap_requires_old_quorum_and_exact_history() {
        use p256::ecdsa::signature::Signer as _;

        let conversation_id = Uuid::from_u128(31);
        let (current, current_keys) = authority_set(2);
        let (new_authority, _) = authority("a2.example", 9);
        let mut next = current.clone();
        next.sequence = 2;
        next.authorities.push(new_authority);
        next.required_quorum = MlsAuthoritySetV1::quorum_for(next.authorities.len()).unwrap();
        let delivery_transition = MlsMembershipTransitionV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: Uuid::from_u128(32),
            previous_roster_commitment: "ab".repeat(32),
            next_roster_commitment: "ab".repeat(32),
            previous_member_count: 2,
            next_member_count: 2,
            previous_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            deliveries: vec![
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a0.example".into(),
                    delivery_digest: "cd".repeat(32),
                },
                MlsMembershipDeliveryCommitmentV1 {
                    destination: "a1.example".into(),
                    delivery_digest: "ef".repeat(32),
                },
            ],
        };
        let authority_change = MlsAuthorityChangeV1 {
            next_authority_set: next,
            delivery_transition,
        };

        let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
        let payload = b"encrypted authority transition";
        let mut proposal = MlsControlProposalV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: Uuid::from_u128(32),
            base_epoch: 0,
            action_type: MlsControlActionTypeV1::AuthoritySetChange,
            proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
            proposer_credential_public_key: base64::engine::general_purpose::STANDARD
                .encode(proposer_public.as_bytes()),
            encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
            payload_digest: hex::encode(Sha256::digest(payload)),
            created_at: 1,
            proposer_signature: String::new(),
        };
        let signature: p256::ecdsa::Signature =
            proposer_key.sign(&proposal.signing_bytes().unwrap());
        proposal.proposer_signature =
            base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
        let block = MlsControlBlockV1 {
            conversation_id,
            incarnation: 1,
            height: 1,
            previous_block_hash: None,
            epoch_before: 0,
            epoch_after: 1,
            proposal,
            transition_digest: Some(authority_change.transition_digest().unwrap()),
            owner_approval: None,
            finalized_at: 2,
        };
        let block_hash = block.block_hash().unwrap();
        let mut votes = Vec::new();
        for authority in &current.authorities {
            let mut vote = MlsOrderingVoteV1 {
                conversation_id,
                incarnation: 1,
                authority_set_sequence: current.sequence,
                height: 1,
                round: 0,
                vote_type: MlsOrderingVoteTypeV1::Precommit,
                block_hash: block_hash.clone(),
                authority_domain: authority.domain.clone(),
                authority_key_id: authority.key_id.clone(),
                signature: String::new(),
            };
            vote.signature = base64::engine::general_purpose::STANDARD.encode(
                current_keys[&authority.domain]
                    .sign(&vote.signing_bytes().unwrap())
                    .to_bytes(),
            );
            votes.push(vote);
        }
        let previous_set_certificate = MlsOrderingQuorumCertificateV1 {
            authority_set_sequence: current.sequence,
            height: 1,
            round: 0,
            block_hash,
            votes,
        };
        let history = Vec::new();
        let descriptor = MlsAuthorityBootstrapDescriptorV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: MlsConversationGenesisV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id,
                incarnation: 1,
                mls_group_id: base64::engine::general_purpose::STANDARD.encode([3u8; 16]),
                kind: MlsConversationKindV1::Direct,
                suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
                roster_commitment: "ab".repeat(32),
                member_count: 2,
                authority_set: current.clone(),
                owner_set: None,
                initial_epoch: 0,
                created_at: 1,
            },
            genesis_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            participant_domains: vec!["a0.example".into(), "a1.example".into()],
            transition_block: block,
            previous_set_certificate,
            authority_change,
            history_block_count: 0,
            history_digest: mls_authority_history_digest(&history).unwrap(),
        };
        assert_eq!(
            verify_mls_authority_bootstrap_history(&descriptor, &history).unwrap(),
            current
        );
        let page = FederatedMlsAuthorityBootstrapPageV1 {
            bootstrap_id: descriptor.bootstrap_id().unwrap(),
            descriptor: descriptor.clone(),
            page_index: 0,
            page_count: 1,
            start_height: 1,
            previous_page_hash: None,
            commits: history,
        };
        page.validate().unwrap();

        let mut tampered = descriptor;
        tampered.history_digest = "00".repeat(32);
        assert!(verify_mls_authority_bootstrap_history(&tampered, &[]).is_err());
    }

    #[test]
    fn control_proposal_is_bound_to_the_pseudonymous_mls_credential() {
        use p256::ecdsa::signature::Signer as _;

        let signing_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let public_key = public_key.as_bytes();
        let mut proposal = MlsControlProposalV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: Uuid::from_u128(21),
            incarnation: 1,
            proposal_id: Uuid::from_u128(22),
            base_epoch: 3,
            action_type: MlsControlActionTypeV1::MembershipChange,
            proposer_id: hex::encode(Sha256::digest(public_key)),
            proposer_credential_public_key: base64::engine::general_purpose::STANDARD
                .encode(public_key),
            encrypted_payload: base64::engine::general_purpose::STANDARD.encode(b"opaque commit"),
            payload_digest: hex::encode(Sha256::digest(b"opaque commit")),
            created_at: 1,
            proposer_signature: String::new(),
        };
        let signature: p256::ecdsa::Signature =
            signing_key.sign(&proposal.signing_bytes().unwrap());
        proposal.proposer_signature =
            base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
        proposal.verify().unwrap();

        let mut replaced = proposal.clone();
        replaced.proposer_credential_public_key = base64::engine::general_purpose::STANDARD.encode(
            p256::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into())
                .unwrap()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        assert!(replaced.verify().is_err());
    }

    #[test]
    fn pending_policy_is_bounded_and_strictest_wins() {
        let default = PendingMessageRequestPolicyV1::default();
        default.validate().unwrap();
        let strict = PendingMessageRequestPolicyV1 {
            maximum_messages: 5,
            maximum_ciphertext_bytes: 256 * 1024,
            expiry_seconds: 7 * 24 * 60 * 60,
        };
        assert_eq!(default.clone().strictest(strict.clone()), strict);
        assert!(PendingMessageRequestPolicyV1 {
            maximum_messages: 129,
            ..default
        }
        .validate()
        .is_err());
    }

    #[test]
    fn anonymous_submission_has_stable_aad_and_hides_conversation_id() {
        let submission = AnonymousMlsSubmissionV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            recipient: "alice@example.org".parse().unwrap(),
            send_id: Uuid::from_u128(9),
            capability: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
            suite: MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
            envelopes: vec![AnonymousMlsDeviceEnvelopeV1 {
                device_id: 1,
                encapsulated_key: base64::engine::general_purpose::STANDARD.encode([4u8; 65]),
                ciphertext: base64::engine::general_purpose::STANDARD.encode([5u8; 17]),
            }],
        };
        submission.validate().unwrap();
        let aad = submission.aad_for_device(1).unwrap();
        assert!(aad.starts_with(ANONYMOUS_MLS_DELIVERY_CONTEXT));
        let json = serde_json::to_value(&submission).unwrap();
        assert!(json.get("conversationId").is_none());
        assert!(json.get("sender").is_none());
        assert!(json.get("epoch").is_none());
    }

    #[test]
    fn anonymous_key_package_checkpoint_cursor_is_lossless_and_canonical() {
        let mut request = AnonymousMlsKeyPackageRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            recipient: "alice@example.org".parse().unwrap(),
            capability: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
            transparency_tree_size: u64::MAX.to_string(),
        };
        request.validate().unwrap();
        assert_eq!(request.known_tree_size().unwrap(), u64::MAX);
        assert_eq!(
            serde_json::to_value(&request).unwrap()["transparencyTreeSize"],
            u64::MAX.to_string()
        );
        request.transparency_tree_size = "01".into();
        assert!(request.validate().is_err());
    }

    #[test]
    fn mailbox_structurally_hides_anonymous_conversation_metadata() {
        let mut envelope = MlsMailboxEnvelopeV1 {
            id: Uuid::from_u128(1),
            cursor: "9007199254740993".into(),
            delivery_kind: MlsMailboxDeliveryKindV1::Anonymous,
            conversation_id: None,
            incarnation: None,
            send_id: Uuid::from_u128(2),
            opaque_envelope: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            server_timestamp: 10,
        };
        envelope.validate().unwrap();
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["cursor"], "9007199254740993");
        assert!(json.get("conversationId").is_none());
        assert!(json.get("incarnation").is_none());

        envelope.conversation_id = Some(Uuid::from_u128(3));
        assert!(envelope.validate().is_err());
        envelope.delivery_kind = MlsMailboxDeliveryKindV1::MembershipControl;
        envelope.incarnation = Some(1);
        envelope.validate().unwrap();
    }

    #[test]
    fn group_capability_binds_epoch_and_recipient() {
        let conversation_id = Uuid::from_u128(3);
        let alice: AccountAddress = "alice@example.org".parse().unwrap();
        let first =
            derive_group_delivery_capability(&[9; 32], conversation_id, 1, 5, &alice).unwrap();
        let second =
            derive_group_delivery_capability(&[9; 32], conversation_id, 1, 6, &alice).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 16);
    }

    #[test]
    fn ordering_policy_requires_production_group_capacity() {
        let (authority, _) = authority("orderer.example", 42);
        let policy = MlsOrderingServicePolicyV1 {
            policy_version: MLS_ORDERING_SERVICE_POLICY_VERSION,
            canonical_domain: "orderer.example".into(),
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            anonymous_delivery_suite: MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
            control_signing_key_id: authority.key_id,
            control_signing_public_key: authority.public_key,
            accepts_group_ordering: true,
            maximum_group_members: 1000,
            maximum_authorities: 64,
            maximum_control_payload_bytes: 1024 * 1024,
            pending_message_requests: PendingMessageRequestPolicyV1::default(),
            abuse_limits: MlsAbuseLimitsV1::default(),
        };
        let bytes = policy.canonical_bytes().unwrap();
        assert_eq!(
            MlsOrderingServicePolicyV1::from_canonical_bytes(&bytes).unwrap(),
            policy
        );
        let pretty = serde_json::to_vec_pretty(&policy).unwrap();
        assert!(MlsOrderingServicePolicyV1::from_canonical_bytes(&pretty).is_err());
    }

    #[test]
    fn private_control_and_client_history_have_stable_canonical_vectors() {
        let (authorities, _) = authority_set(1);
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let owner_public = owner_key.verifying_key().to_bytes();
        let owner_id = hex::encode(Sha256::digest(owner_public));
        let owners = MlsOwnerSetV1 {
            sequence: 1,
            owners: vec![MlsOwnerV1 {
                owner_id: owner_id.clone(),
                public_key: base64::engine::general_purpose::STANDARD.encode(owner_public),
            }],
            required_quorum: 1,
        };
        let roster = vec![MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: true,
            owner_id: Some(owner_id),
        }];
        let private = MlsPrivateControlStateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: Uuid::from_u128(0x101),
            incarnation: 1,
            proposal_id: None,
            height: 0,
            epoch: 0,
            previous_block_hash: None,
            genesis_roster: roster.clone(),
            genesis_authority_set: authorities.clone(),
            genesis_owner_set: owners.clone(),
            roster: roster.clone(),
            authority_set: authorities.clone(),
            owner_set: owners.clone(),
        };
        let private_bytes = private.canonical_bytes().unwrap();
        assert_eq!(
            MlsPrivateControlStateV1::from_canonical_bytes(&private_bytes).unwrap(),
            private
        );
        let genesis = MlsConversationGenesisV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: private.conversation_id,
            incarnation: 1,
            mls_group_id: base64::engine::general_purpose::STANDARD.encode([6; 16]),
            kind: MlsConversationKindV1::Group,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            roster_commitment: roster_commitment(&roster).unwrap(),
            member_count: 1,
            authority_set: authorities,
            owner_set: Some(owners),
            initial_epoch: 0,
            created_at: 1_700_000_000,
        };
        let page = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis,
            genesis_participant_domains: vec!["a0.example".into()],
            after_height: "0".into(),
            commits: Vec::new(),
            next_height: None,
        };
        let page_bytes = page.canonical_bytes().unwrap();
        assert_eq!(
            MlsClientControlHistoryPageV1::from_canonical_bytes(&page_bytes).unwrap(),
            page
        );
        assert_eq!(
            hex::encode(Sha256::digest(&private_bytes)),
            "933090c87f6700eb0194709505b1dce6e56b0ac30d7c0c3ec3c83f4421b51073"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&page_bytes)),
            "8c9cc89d2276c5a1b4e73e399ec7755b5c36a1d473d6c3493238ed3211f505c4"
        );
        let pretty = serde_json::to_vec_pretty(&page).unwrap();
        assert!(MlsClientControlHistoryPageV1::from_canonical_bytes(&pretty).is_err());
        let mut unknown = serde_json::to_value(&private).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("downgrade".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<MlsPrivateControlStateV1>(unknown).is_err());
        assert!(verify_mls_client_control_history(&[], &private).is_err());
    }

    #[test]
    fn client_control_history_replays_exactly_across_page_boundaries() {
        use p256::ecdsa::signature::Signer as _;

        let (authorities, authority_keys) = authority_set(1);
        let authority = &authorities.authorities[0];
        let authority_key = &authority_keys[&authority.domain];
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[45; 32]);
        let owner_public = owner_key.verifying_key().to_bytes();
        let owner_id = hex::encode(Sha256::digest(owner_public));
        let owners = MlsOwnerSetV1 {
            sequence: 1,
            owners: vec![MlsOwnerV1 {
                owner_id: owner_id.clone(),
                public_key: base64::engine::general_purpose::STANDARD.encode(owner_public),
            }],
            required_quorum: 1,
        };
        let roster = vec![MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: true,
            owner_id: Some(owner_id),
        }];
        let conversation_id = Uuid::from_u128(0x202);
        let genesis = MlsConversationGenesisV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            mls_group_id: base64::engine::general_purpose::STANDARD.encode([7; 16]),
            kind: MlsConversationKindV1::Group,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            roster_commitment: roster_commitment(&roster).unwrap(),
            member_count: 1,
            authority_set: authorities.clone(),
            owner_set: Some(owners.clone()),
            initial_epoch: 0,
            created_at: 1_700_000_000,
        };
        let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[46; 32]).into()).unwrap();
        let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
        let proposer_id = hex::encode(Sha256::digest(proposer_public.as_bytes()));
        let proposer_public =
            base64::engine::general_purpose::STANDARD.encode(proposer_public.as_bytes());
        let mut commits = Vec::new();
        let mut previous_block_hash = None;
        for height in 1..=65 {
            let payload = format!("opaque routine-admin commit {height}");
            let mut proposal = MlsControlProposalV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id,
                incarnation: 1,
                proposal_id: Uuid::from_u128(0x1_000 + u128::from(height)),
                base_epoch: height - 1,
                action_type: MlsControlActionTypeV1::RoutineAdmin,
                proposer_id: proposer_id.clone(),
                proposer_credential_public_key: proposer_public.clone(),
                encrypted_payload: base64::engine::general_purpose::STANDARD
                    .encode(payload.as_bytes()),
                payload_digest: hex::encode(Sha256::digest(payload.as_bytes())),
                created_at: 1_700_000_000 + height as i64,
                proposer_signature: String::new(),
            };
            let signature: p256::ecdsa::Signature =
                proposer_key.sign(&proposal.signing_bytes().unwrap());
            proposal.proposer_signature =
                base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
            let block = MlsControlBlockV1 {
                conversation_id,
                incarnation: 1,
                height,
                previous_block_hash: previous_block_hash.clone(),
                epoch_before: height - 1,
                epoch_after: height,
                proposal,
                transition_digest: None,
                owner_approval: None,
                finalized_at: 1_700_000_100 + height as i64,
            };
            let block_hash = block.block_hash().unwrap();
            let mut vote = MlsOrderingVoteV1 {
                conversation_id,
                incarnation: 1,
                authority_set_sequence: authorities.sequence,
                height,
                round: 0,
                vote_type: MlsOrderingVoteTypeV1::Precommit,
                block_hash: block_hash.clone(),
                authority_domain: authority.domain.clone(),
                authority_key_id: authority.key_id.clone(),
                signature: String::new(),
            };
            vote.signature = base64::engine::general_purpose::STANDARD.encode(
                authority_key
                    .sign(&vote.signing_bytes().unwrap())
                    .to_bytes(),
            );
            commits.push(CommitMlsControlBlockV1 {
                finalized: MlsFinalizedControlBlockV1 {
                    block,
                    quorum_certificate: MlsOrderingQuorumCertificateV1 {
                        authority_set_sequence: authorities.sequence,
                        height,
                        round: 0,
                        block_hash: block_hash.clone(),
                        votes: vec![vote],
                    },
                },
                membership_transition: None,
                authority_change: None,
                authority_transition: None,
                next_owner_set: None,
            });
            previous_block_hash = Some(block_hash);
        }
        let final_block = &commits.last().unwrap().finalized.block;
        let private = MlsPrivateControlStateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: Some(final_block.proposal.proposal_id),
            height: 65,
            epoch: 65,
            previous_block_hash: final_block.previous_block_hash.clone(),
            genesis_roster: roster.clone(),
            genesis_authority_set: authorities.clone(),
            genesis_owner_set: owners.clone(),
            roster,
            authority_set: authorities,
            owner_set: owners,
        };
        let first = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: genesis.clone(),
            genesis_participant_domains: vec!["a0.example".into()],
            after_height: "0".into(),
            commits: commits[..64].to_vec(),
            next_height: Some("64".into()),
        };
        let second = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis,
            genesis_participant_domains: vec!["a0.example".into()],
            after_height: "64".into(),
            commits: commits[64..].to_vec(),
            next_height: Some("65".into()),
        };

        assert_eq!(
            verify_mls_client_control_history(&[first.clone(), second.clone()], &private).unwrap(),
            previous_block_hash
        );
        assert!(verify_mls_client_control_history(std::slice::from_ref(&first), &private).is_err());
        assert!(
            verify_mls_client_control_history(&[second.clone(), first.clone()], &private).is_err()
        );
        assert!(verify_mls_client_control_history(&[first.clone(), first], &private).is_err());
        assert!(MlsClientControlHistoryPageV1::from_canonical_bytes(
            &second.canonical_bytes().unwrap()
        )
        .is_ok());
    }
}
