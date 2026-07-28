//! Pseudonymous MLS control proposals, owner approvals, ordering votes, and history replay.

use super::*;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_digest: Option<String>,
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
        if let Some(digest) = self.transition_digest.as_deref() {
            validate_hash("owner transitionDigest", digest)?;
        }
        validate_hash("ownerId", &self.owner_id)?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(self.conversation_id.as_bytes());
        out.extend_from_slice(&self.incarnation.to_be_bytes());
        out.extend_from_slice(&self.owner_set_sequence.to_be_bytes());
        push_string(&mut out, &self.proposal_hash)?;
        match self.transition_digest.as_deref() {
            Some(digest) => {
                out.push(1);
                push_string(&mut out, digest)?;
            }
            None => out.push(0),
        }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_digest: Option<String>,
    pub approvals: Vec<MlsOwnerApprovalV1>,
}

impl MlsOwnerApprovalCertificateV1 {
    pub fn verify_partial(
        &self,
        proposal: &MlsControlProposalV1,
        transition_digest: Option<&str>,
        owners: &MlsOwnerSetV1,
    ) -> Result<(), String> {
        owners.validate()?;
        let proposal_hash = proposal.proposal_hash()?;
        if self.owner_set_sequence != owners.sequence
            || self.proposal_hash != proposal_hash
            || self.transition_digest.as_deref() != transition_digest
        {
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
                || approval.transition_digest != self.transition_digest
            {
                return Err("MLS owner approval does not match its certificate".into());
            }
            approval.verify(
                owners
                    .owner(&approval.owner_id)
                    .ok_or("MLS owner approval references an unknown owner")?,
            )?;
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &MlsControlProposalV1,
        transition_digest: Option<&str>,
        owners: &MlsOwnerSetV1,
    ) -> Result<(), String> {
        self.verify_partial(proposal, transition_digest, owners)?;
        if self.approvals.len() < usize::from(owners.required_quorum) {
            return Err("MLS owner certificate does not meet quorum".into());
        }
        Ok(())
    }
}

/// Exact security-governance proposal shown to current owners inside an
/// MLS-encrypted group-control message. Ordering authorities never receive
/// `next_roster`; the public transition exposes only its commitment and server
/// routing. Exactly one action-specific transition is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOwnerApprovalRequestV1 {
    pub protocol_version: u16,
    pub owner_set_sequence: u64,
    pub proposal: MlsControlProposalV1,
    pub transition_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_change: Option<MlsOwnerChangeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_transition: Option<MlsMembershipTransitionV1>,
    pub next_roster: Vec<MlsConversationMemberV1>,
    pub requested_at: i64,
    pub expires_at: i64,
}

impl MlsOwnerApprovalRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.owner_set_sequence == 0
            || self.requested_at < 0
            || self.expires_at <= self.requested_at
            || self.expires_at - self.requested_at > 7 * 24 * 60 * 60
            || !matches!(
                self.proposal.action_type,
                MlsControlActionTypeV1::OwnerSetChange | MlsControlActionTypeV1::CloseConversation
            )
        {
            return Err("MLS owner approval request has invalid version, sequence, or time".into());
        }
        self.proposal.verify()?;
        let transition = match self.proposal.action_type {
            MlsControlActionTypeV1::OwnerSetChange => {
                let change = self
                    .owner_change
                    .as_ref()
                    .ok_or("MLS owner-set approval omits its owner transition")?;
                if self.membership_transition.is_some() {
                    return Err("MLS owner-set approval carries a close transition".into());
                }
                change.validate()?;
                if self.owner_set_sequence.checked_add(1) != Some(change.next_owner_set.sequence)
                    || self.transition_digest != change.transition_digest()?
                {
                    return Err(
                        "MLS owner approval request differs from its owner transition".into(),
                    );
                }
                &change.delivery_transition
            }
            MlsControlActionTypeV1::CloseConversation => {
                if self.owner_change.is_some() {
                    return Err("MLS close approval carries an owner-set transition".into());
                }
                let transition = self
                    .membership_transition
                    .as_ref()
                    .ok_or("MLS close approval omits its delivery transition")?;
                transition.validate()?;
                if self.transition_digest != transition.transition_digest()?
                    || transition.previous_roster_commitment != transition.next_roster_commitment
                    || transition.previous_member_count != transition.next_member_count
                    || transition.previous_participant_domains
                        != transition.next_participant_domains
                {
                    return Err("MLS close approval must preserve the exact roster".into());
                }
                transition
            }
            _ => unreachable!("approval action checked above"),
        };
        if self.proposal.conversation_id != transition.conversation_id
            || self.proposal.incarnation != transition.incarnation
            || self.proposal.proposal_id != transition.proposal_id
            || transition.previous_member_count != transition.next_member_count
            || transition.next_member_count != self.next_roster.len() as u32
            || transition.next_roster_commitment != roster_commitment(&self.next_roster)?
        {
            return Err("MLS owner approval request differs from its exact transition".into());
        }
        let mut roster_owner_ids = BTreeSet::new();
        let participant_domains = self
            .next_roster
            .iter()
            .map(|member| {
                member.validate()?;
                if let Some(owner_id) = member.owner_id.as_deref() {
                    if !roster_owner_ids.insert(owner_id) {
                        return Err("MLS owner approval roster repeats an owner id".to_string());
                    }
                }
                member
                    .address
                    .server
                    .clone()
                    .ok_or("MLS owner approval roster has a local address".to_string())
            })
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect::<Vec<_>>();
        if participant_domains != transition.next_participant_domains {
            return Err("MLS owner approval request has inconsistent private bindings".into());
        }
        if let Some(change) = &self.owner_change {
            let declared_owner_ids = change
                .next_owner_set
                .owners
                .iter()
                .map(|owner| owner.owner_id.as_str())
                .collect::<BTreeSet<_>>();
            if roster_owner_ids != declared_owner_ids {
                return Err("MLS owner approval request has inconsistent owner bindings".into());
            }
        }
        Ok(())
    }

    pub fn delivery_transition(&self) -> Result<&MlsMembershipTransitionV1, String> {
        match self.proposal.action_type {
            MlsControlActionTypeV1::OwnerSetChange => self
                .owner_change
                .as_ref()
                .map(|change| &change.delivery_transition)
                .ok_or_else(|| "MLS owner approval omits its owner transition".into()),
            MlsControlActionTypeV1::CloseConversation => self
                .membership_transition
                .as_ref()
                .ok_or_else(|| "MLS close approval omits its delivery transition".into()),
            _ => Err("MLS owner approval has an unsupported action".into()),
        }
    }

    pub fn request_hash(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(|bytes| hex::encode(Sha256::digest(bytes)))
            .map_err(|error| error.to_string())
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
            | MlsControlActionTypeV1::OwnerSetChange
            | MlsControlActionTypeV1::CloseConversation => {
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
    pub owner_change: Option<MlsOwnerChangeV1>,
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
        let delivery_transition = self
            .commit
            .membership_transition
            .as_ref()
            .or_else(|| {
                self.commit
                    .authority_change
                    .as_ref()
                    .map(|change| &change.delivery_transition)
            })
            .or_else(|| {
                self.commit
                    .owner_change
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
                    || self.owner_change.is_some()
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
                    || self.owner_change.is_some()
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
                if self.owner_change.is_none()
                    || self.authority_change.is_some()
                    || self.authority_transition.is_some()
                    || self.membership_transition.is_some()
                {
                    return Err(
                        "owner-set change requires exactly its private delivery data".into(),
                    );
                }
                let change = self
                    .owner_change
                    .as_ref()
                    .expect("checked owner transition");
                let expected = change.transition_digest()?;
                if change.delivery_transition.conversation_id
                    != self.finalized.block.conversation_id
                    || change.delivery_transition.incarnation != self.finalized.block.incarnation
                    || change.delivery_transition.proposal_id
                        != self.finalized.block.proposal.proposal_id
                {
                    return Err("owner change carries inconsistent delivery data".into());
                }
                if self.finalized.block.transition_digest.as_deref() != Some(expected.as_str()) {
                    return Err("owner transition data does not match the finalized block".into());
                }
            }
            MlsControlActionTypeV1::CloseConversation => {
                if self.membership_transition.is_none()
                    || self.authority_change.is_some()
                    || self.authority_transition.is_some()
                    || self.owner_change.is_some()
                {
                    return Err(
                        "conversation close requires exactly its participant delivery transition"
                            .into(),
                    );
                }
                let transition = self
                    .membership_transition
                    .as_ref()
                    .expect("checked close transition");
                if transition.conversation_id != self.finalized.block.conversation_id
                    || transition.incarnation != self.finalized.block.incarnation
                    || transition.proposal_id != self.finalized.block.proposal.proposal_id
                    || transition.previous_roster_commitment != transition.next_roster_commitment
                    || transition.previous_member_count != transition.next_member_count
                    || transition.previous_participant_domains
                        != transition.next_participant_domains
                {
                    return Err("conversation close must preserve the exact roster".into());
                }
                let expected = transition.transition_digest()?;
                if self.finalized.block.transition_digest.as_deref() != Some(expected.as_str()) {
                    return Err(
                        "conversation close transition differs from its finalized block".into(),
                    );
                }
            }
            _ => {
                if self.authority_change.is_some()
                    || self.authority_transition.is_some()
                    || self.owner_change.is_some()
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
