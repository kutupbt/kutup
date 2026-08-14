//! Conversation identity, private roster, membership delivery, and mailbox wire types.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsCipherSuiteId {
    Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519 =
        MLS_CIPHERSUITE_X25519_CHACHA20POLY1305_SHA256_ED25519,
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
            MLS_CIPHERSUITE_X25519_CHACHA20POLY1305_SHA256_ED25519 => {
                Ok(Self::Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519)
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
    DhKemX25519HkdfSha256ChaCha20Poly1305 = 1,
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
            1 => Ok(Self::DhKemX25519HkdfSha256ChaCha20Poly1305),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum MlsApplicationSenderPolicyV1 {
    Members = 1,
    Administrators = 2,
}

impl From<MlsApplicationSenderPolicyV1> for u16 {
    fn from(value: MlsApplicationSenderPolicyV1) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MlsApplicationSenderPolicyV1 {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Members),
            2 => Ok(Self::Administrators),
            _ => Err(format!("unknown MLS application sender policy {value}")),
        }
    }
}

/// Group-private authorization policy. Administrators always retain ordinary
/// roster-management authority; this policy controls only user-visible
/// application messages and deliberately does not suppress owner-governance
/// control messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsGroupAuthorizationPolicyV1 {
    pub policy_version: u16,
    pub sequence: u64,
    pub application_senders: MlsApplicationSenderPolicyV1,
}

impl MlsGroupAuthorizationPolicyV1 {
    pub fn members_default() -> Self {
        Self {
            policy_version: MLS_GROUP_AUTHORIZATION_POLICY_VERSION,
            sequence: 1,
            application_senders: MlsApplicationSenderPolicyV1::Members,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.policy_version != MLS_GROUP_AUTHORIZATION_POLICY_VERSION || self.sequence == 0 {
            return Err("MLS authorization policy has an invalid version or sequence".into());
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

    pub fn policy_digest(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
}

/// Group-private cryptographic requirements. V1 policy changes may tighten
/// the maximum canonical application plaintext, but cannot replace the MLS
/// suite, remove anonymous delivery, weaken padding, or enlarge the retained
/// past-epoch window. Such changes require an explicit future protocol/suite
/// upgrade and a new incarnation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsGroupCryptographicPolicyV1 {
    pub policy_version: u16,
    pub sequence: u64,
    pub suite: MlsCipherSuiteId,
    pub required_private_control_extension: u16,
    pub maximum_past_epochs: u16,
    pub anonymous_delivery_required: bool,
    pub padding_block_bytes: u32,
    pub maximum_application_plaintext_bytes: u32,
}

impl MlsGroupCryptographicPolicyV1 {
    pub const MINIMUM_APPLICATION_PLAINTEXT_BYTES: u32 = 1024;
    pub const MAXIMUM_APPLICATION_PLAINTEXT_BYTES: u32 = 1024 * 1024;

    pub fn v1_default() -> Self {
        Self {
            policy_version: MLS_GROUP_CRYPTOGRAPHIC_POLICY_VERSION,
            sequence: 1,
            suite: MlsCipherSuiteId::Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519,
            required_private_control_extension: MLS_PRIVATE_CONTROL_EXTENSION_TYPE,
            maximum_past_epochs: 2,
            anonymous_delivery_required: true,
            padding_block_bytes: 1024,
            maximum_application_plaintext_bytes: Self::MAXIMUM_APPLICATION_PLAINTEXT_BYTES,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.policy_version != MLS_GROUP_CRYPTOGRAPHIC_POLICY_VERSION
            || self.sequence == 0
            || self.suite != MlsCipherSuiteId::Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519
            || self.required_private_control_extension != MLS_PRIVATE_CONTROL_EXTENSION_TYPE
            || self.maximum_past_epochs != 2
            || !self.anonymous_delivery_required
            || self.padding_block_bytes != 1024
            || !(Self::MINIMUM_APPLICATION_PLAINTEXT_BYTES
                ..=Self::MAXIMUM_APPLICATION_PLAINTEXT_BYTES)
                .contains(&self.maximum_application_plaintext_bytes)
        {
            return Err("MLS cryptographic policy is outside the supported V1 profile".into());
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

    pub fn policy_digest(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
}

/// MLS keys for one device, authenticated by the account's signed manifest and
/// durably pinned by peers. The credential key is Ed25519 and the anonymous
/// delivery key is X25519; both are canonical 32-byte public keys.
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
        validate_ed25519_public_key("MLS credentialPublicKey", &self.credential_public_key)?;
        validate_x25519_public_key(
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

/// A member-generated owner credential advertised only inside an
/// MLS-encrypted group-control application message. The signature proves
/// possession of the candidate owner key; the receiving MLS member credential
/// binds `account` to the authenticated sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerCandidateV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub account: AccountAddress,
    pub owner_id: String,
    pub public_key: String,
    pub created_at: i64,
    pub signature: String,
}

impl MlsOwnerCandidateV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-mls-owner-candidate-v1\0";
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.created_at < 0
            || self.account.server.is_none()
        {
            return Err("MLS owner candidate has invalid identifiers or account".into());
        }
        let owner = MlsOwnerV1 {
            owner_id: self.owner_id.clone(),
            public_key: self.public_key.clone(),
        };
        owner.validate()?;
        let public_key = decode_canonical_base64("owner publicKey", &self.public_key, 32, 32)?;
        if hex::encode(Sha256::digest(public_key)) != self.owner_id {
            return Err("MLS owner candidate id does not match its public key".into());
        }
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(self.conversation_id.as_bytes());
        out.extend_from_slice(&self.incarnation.to_be_bytes());
        push_string(&mut out, &self.account.canonical())?;
        push_string(&mut out, &self.owner_id)?;
        push_string(&mut out, &self.public_key)?;
        out.extend_from_slice(&self.created_at.to_be_bytes());
        Ok(out)
    }

    pub fn verify(&self) -> Result<(), String> {
        verify_ed25519_signature(
            &self.public_key,
            &self.signing_bytes()?,
            &self.signature,
            "MLS owner candidate",
        )
    }
}

/// MLS-authenticated proof that an invited member installed its Welcome and
/// published the anonymous-delivery capability for that exact join epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsInvitationAcceptanceV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    /// Exact MLS epoch at which this account was added. Binding the receipt to
    /// the join epoch prevents an old acceptance from authorizing a later
    /// remove-and-readd cycle.
    pub invited_epoch: u64,
    pub accepted_at: i64,
}

impl MlsInvitationAcceptanceV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.invited_epoch == 0
            || self.accepted_at < 0
        {
            return Err("MLS invitation acceptance has invalid metadata".into());
        }
        Ok(())
    }
}

/// Typed body carried by `ChatContent.kind == groupControl`.
// Keeping the concrete request types visible makes every variant's canonical
// wire/API shape explicit. These transient values are not stored in large
// arrays, so an extra allocation only to reduce the enum size is unnecessary.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum MlsGroupControlBodyV1 {
    OwnerCandidate {
        candidate: MlsOwnerCandidateV1,
    },
    OwnerApprovalRequest {
        request: MlsOwnerApprovalRequestV1,
    },
    OwnerApproval {
        approval: MlsOwnerApprovalV1,
    },
    InvitationAccepted {
        acceptance: MlsInvitationAcceptanceV1,
    },
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
        if self.sequence == 0
            || self.owners.is_empty()
            || self.owners.len() > MAX_MLS_GROUP_ACCOUNTS
        {
            return Err(format!(
                "MLS owner set must have a positive sequence and 1-{MAX_MLS_GROUP_ACCOUNTS} owners"
            ));
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
    /// Commitment to the complete account-manifest-verified account/device roster.
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
                if self.incarnation != 1
                    || self.initial_epoch != 0
                    || self.member_count != 1
                    || self.authority_set.authorities.len() != 1
                    || self.authority_set.required_quorum != 1
                    || self.owner_set.is_some()
                {
                    return Err("self-sync MLS genesis requires one authority and no owners".into());
                }
            }
            MlsConversationKindV1::Direct => {
                if self.incarnation != 1
                    || self.initial_epoch != 0
                    || self.member_count != 2
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
                match self.incarnation {
                    1 if self.initial_epoch == 0 && self.member_count == 1 => {}
                    incarnation
                        if incarnation > 1
                            && self.initial_epoch == 1
                            && (1..=MAX_MLS_GROUP_ACCOUNTS as u32).contains(&self.member_count) => {
                    }
                    _ => {
                        return Err(
                            "group MLS genesis is not a creator genesis or recovered incarnation"
                                .into(),
                        )
                    }
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

/// One MLS leaf identity in a destination-private device snapshot. Ordering
/// authorities receive only the digest of the containing delivery and cannot
/// correlate account or device identities across groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsConversationDeviceV1 {
    pub address: AccountAddress,
    pub device_id: u32,
}

impl MlsConversationDeviceV1 {
    pub fn validate(&self) -> Result<(), String> {
        let canonical: AccountAddress = self
            .address
            .canonical()
            .parse()
            .map_err(|error: crate::AddressError| error.to_string())?;
        if canonical != self.address
            || self.address.server.is_none()
            || !(1..=127).contains(&self.device_id)
        {
            return Err(
                "MLS conversation device must have a canonical account and id 1-127".into(),
            );
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
    /// Epoch at which this append-only incarnation began. Incarnation one
    /// begins at epoch zero; a recovered incarnation begins after the single
    /// full-roster recovery Commit at epoch one.
    pub initial_epoch: u64,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_block_hash: Option<String>,
    /// Immutable incarnation-genesis account roster, retained so a joining client can
    /// reconstruct and verify the private genesis request without asking any
    /// server to reveal member identities.
    pub genesis_roster: Vec<MlsConversationMemberV1>,
    pub genesis_authority_set: MlsAuthoritySetV1,
    pub genesis_owner_set: MlsOwnerSetV1,
    pub genesis_authorization_policy: MlsGroupAuthorizationPolicyV1,
    pub genesis_cryptographic_policy: MlsGroupCryptographicPolicyV1,
    pub roster: Vec<MlsConversationMemberV1>,
    pub authority_set: MlsAuthoritySetV1,
    pub owner_set: MlsOwnerSetV1,
    pub authorization_policy: MlsGroupAuthorizationPolicyV1,
    pub cryptographic_policy: MlsGroupCryptographicPolicyV1,
}

impl MlsPrivateControlStateV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.epoch != self.initial_epoch.saturating_add(self.height)
            || !matches!((self.incarnation, self.initial_epoch), (1, 0) | (2.., 1))
            || self.genesis_roster.is_empty()
            || self.genesis_roster.len() > MAX_MLS_GROUP_ACCOUNTS
            || self.roster.is_empty()
            || self.roster.len() > MAX_MLS_GROUP_ACCOUNTS
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
        self.genesis_authorization_policy.validate()?;
        self.genesis_cryptographic_policy.validate()?;
        self.authority_set.validate()?;
        self.owner_set.validate()?;
        self.authorization_policy.validate()?;
        self.cryptographic_policy.validate()?;
        if self.genesis_authorization_policy.sequence != 1
            || self.genesis_cryptographic_policy.sequence != 1
            || self.authorization_policy.sequence > self.height.saturating_add(1)
            || self.cryptographic_policy.sequence > self.height.saturating_add(1)
        {
            return Err("MLS private policy sequence is inconsistent with control history".into());
        }
        validate_private_roster_owner_bindings(
            "genesis",
            &self.genesis_roster,
            &self.genesis_owner_set,
        )?;
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

fn validate_private_roster_owner_bindings(
    label: &str,
    roster: &[MlsConversationMemberV1],
    owner_set: &MlsOwnerSetV1,
) -> Result<(), String> {
    let mut previous = None;
    let mut owner_ids = BTreeSet::new();
    let mut admin_count = 0usize;
    for member in roster {
        member.validate()?;
        let address = member.address.canonical();
        if previous
            .as_ref()
            .is_some_and(|prior: &String| address <= *prior)
        {
            return Err(format!(
                "MLS private control {label} roster is not strictly ordered"
            ));
        }
        previous = Some(address);
        admin_count += usize::from(member.is_admin);
        if let Some(owner_id) = member.owner_id.as_deref() {
            if !owner_ids.insert(owner_id) {
                return Err(format!(
                    "MLS private control {label} roster repeats an owner id"
                ));
            }
        }
    }
    let declared = owner_set
        .owners
        .iter()
        .map(|owner| owner.owner_id.as_str())
        .collect::<BTreeSet<_>>();
    if admin_count == 0 || owner_ids != declared {
        return Err(format!(
            "MLS private control {label} roster differs from its declared owner set"
        ));
    }
    roster_commitment(roster)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMlsConversationRequestV1 {
    pub genesis: MlsConversationGenesisV1,
    pub members: Vec<MlsConversationMemberV1>,
    /// Device leaves present at an ordinary local genesis. Federation replicas
    /// omit this destination-private list; recovery reconstructs device state
    /// from its authenticated Welcome deliveries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_devices: Vec<MlsConversationDeviceV1>,
}

impl CreateMlsConversationRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.genesis.validate()?;
        if self.genesis.incarnation != 1 || self.genesis.initial_epoch != 0 {
            return Err(
                "ordinary MLS creation only accepts an epoch-zero first incarnation".into(),
            );
        }
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
        validate_conversation_devices(&self.initial_devices, &self.members, true)?;
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

/// A destination server's durable, identified report that one of its local
/// accounts accepted, rejected, or allowed an MLS invitation to expire. The
/// report is federation-authenticated and advisory: acceptance is emitted only
/// after the recipient has installed the Welcome and published its delivery
/// capability, while only an MLS administrator can commit a rejected member's
/// cryptographic removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MlsInvitationFeedbackDecisionV1 {
    Accepted,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsInvitationFeedbackV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub member: AccountAddress,
    pub invited_epoch: u64,
    pub decision: MlsInvitationFeedbackDecisionV1,
    pub decided_at: i64,
}

impl MlsInvitationFeedbackV1 {
    pub fn validate(&self) -> Result<(), String> {
        let canonical: AccountAddress = self
            .member
            .canonical()
            .parse()
            .map_err(|error: crate::AddressError| error.to_string())?;
        if self.protocol_version != MLS_INVITATION_FEEDBACK_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.incarnation > i64::MAX as u64
            || self.invited_epoch == 0
            || self.invited_epoch > i64::MAX as u64
            || self.decided_at < 0
            || canonical != self.member
            || self.member.server.is_none()
        {
            return Err("MLS invitation feedback has invalid identifiers or member".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn feedback_digest(&self) -> Result<String, String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
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
        if self.participant_domains.is_empty()
            || self.participant_domains.len() > MAX_MLS_GROUP_ACCOUNTS
        {
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
        if !(1..=MAX_MLS_GROUP_ACCOUNTS as u32).contains(&self.previous_member_count)
            || !(1..=MAX_MLS_GROUP_ACCOUNTS as u32).contains(&self.next_member_count)
        {
            return Err("MLS membership transition member count must be 1-256".into());
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

/// Public verifier data for an owner-set change. Account-to-owner bindings
/// remain inside the MLS-encrypted private roster; ordering authorities learn
/// only the pseudonymous next owner set and exact participant delivery
/// commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerChangeV1 {
    pub next_owner_set: MlsOwnerSetV1,
    pub delivery_transition: MlsMembershipTransitionV1,
}

impl MlsOwnerChangeV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.next_owner_set.validate()?;
        self.delivery_transition.validate()?;
        if self.delivery_transition.previous_member_count
            != self.delivery_transition.next_member_count
            || self.delivery_transition.previous_participant_domains
                != self.delivery_transition.next_participant_domains
            || self.delivery_transition.previous_roster_commitment
                == self.delivery_transition.next_roster_commitment
        {
            return Err(
                "MLS owner change must alter roles without changing membership routing".into(),
            );
        }
        Ok(())
    }

    pub fn transition_digest(&self) -> Result<String, String> {
        self.validate()?;
        mls_transition_digest(self)
    }
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
    /// Exact MLS leaves hosted by this destination after the Commit. This is
    /// destination-private and lets the homeserver distinguish an existing
    /// leaf that needs a Commit from a newly linked device that needs Welcome.
    pub local_devices_after: Vec<MlsConversationDeviceV1>,
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
        if self.local_members_after.len() > MAX_MLS_GROUP_ACCOUNTS
            || self.envelopes.len() > MAX_MEMBERSHIP_ENVELOPES
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
        validate_conversation_devices(
            &self.local_devices_after,
            &self.local_members_after,
            self.local_members_after.is_empty(),
        )?;
        if self
            .local_devices_after
            .iter()
            .any(|device| device.address.server.as_deref() != Some(self.destination.as_str()))
        {
            return Err("MLS membership delivery contains a non-local device".into());
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

fn validate_conversation_devices(
    devices: &[MlsConversationDeviceV1],
    members: &[MlsConversationMemberV1],
    allow_empty: bool,
) -> Result<(), String> {
    if devices.len() > MAX_MEMBERSHIP_ENVELOPES || (!allow_empty && devices.is_empty()) {
        return Err("MLS conversation device snapshot is empty or exceeds its entry limit".into());
    }
    let member_addresses = members
        .iter()
        .map(|member| member.address.canonical())
        .collect::<BTreeSet<_>>();
    let mut covered = BTreeSet::new();
    let mut previous = None;
    let mut current_account: Option<String> = None;
    let mut current_account_devices = 0usize;
    for device in devices {
        device.validate()?;
        let address = device.address.canonical();
        if !member_addresses.contains(&address) {
            return Err("MLS conversation device is absent from the account roster".into());
        }
        let key = (address.clone(), device.device_id);
        if previous.as_ref().is_some_and(|prior| key <= *prior) {
            return Err("MLS conversation devices must be strictly ordered".into());
        }
        if current_account.as_deref() == Some(address.as_str()) {
            current_account_devices += 1;
        } else {
            current_account = Some(address.clone());
            current_account_devices = 1;
        }
        if current_account_devices > MAX_MLS_DEVICES_PER_ACCOUNT {
            return Err("MLS account exceeds the 10-device V1 leaf limit".into());
        }
        previous = Some(key);
        covered.insert(address);
    }
    if !devices.is_empty() && covered != member_addresses {
        return Err("MLS conversation devices must cover every account in the roster".into());
    }
    Ok(())
}

pub fn roster_commitment(members: &[MlsConversationMemberV1]) -> Result<String, String> {
    if members.is_empty() || members.len() > MAX_MLS_GROUP_ACCOUNTS {
        return Err("MLS roster must contain 1-256 accounts".into());
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
