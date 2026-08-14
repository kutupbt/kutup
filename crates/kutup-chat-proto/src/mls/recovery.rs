//! Owner-authorized, append-only MLS group incarnation recovery.
//!
//! Recovery deliberately does not pass through the unavailable old ordering
//! quorum. Current owners authorize one exact replacement genesis and every
//! destination-private Welcome delivery. The old control history remains
//! immutable and is the source of the owner keys used to verify this object.

use super::*;

/// Public recovery data visible to old/new authorities. It commits the old
/// public head, the complete replacement genesis, and one opaque private
/// delivery per participant server without exposing account addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsIncarnationRecoveryPlanV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub previous_incarnation: u64,
    pub proposal_id: Uuid,
    pub previous_genesis_hash: String,
    pub previous_height: u64,
    pub previous_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_block_hash: Option<String>,
    pub previous_roster_commitment: String,
    pub participant_domains: Vec<String>,
    pub new_genesis: MlsConversationGenesisV1,
    pub deliveries: Vec<MlsMembershipDeliveryCommitmentV1>,
}

impl MlsIncarnationRecoveryPlanV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.previous_incarnation == 0
            || self.proposal_id.is_nil()
            || self.previous_epoch < self.previous_height
        {
            return Err("MLS recovery plan has invalid identifiers or head".into());
        }
        validate_hash("previousGenesisHash", &self.previous_genesis_hash)?;
        validate_hash("previousRosterCommitment", &self.previous_roster_commitment)?;
        match (self.previous_height, self.previous_block_hash.as_deref()) {
            (0, None) => {}
            (height, Some(hash)) if height > 0 => {
                validate_hash("previousBlockHash", hash)?;
            }
            _ => return Err("MLS recovery plan has an invalid previous head".into()),
        }
        validate_participant_domain_set(&self.participant_domains)?;
        self.new_genesis.validate()?;
        if self.new_genesis.conversation_id != self.conversation_id
            || self.new_genesis.kind != MlsConversationKindV1::Group
            || self.previous_incarnation.checked_add(1) != Some(self.new_genesis.incarnation)
            || self.new_genesis.initial_epoch != 1
            || self.new_genesis.roster_commitment != self.previous_roster_commitment
        {
            return Err(
                "MLS recovery plan does not create the exact next group incarnation".into(),
            );
        }
        if self.deliveries.len() != self.participant_domains.len() {
            return Err("MLS recovery plan requires one delivery per participant domain".into());
        }
        let mut previous = None;
        for delivery in &self.deliveries {
            kutup_federation_proto::validate_server_name(&delivery.destination)
                .map_err(|error| error.to_string())?;
            validate_hash("recovery deliveryDigest", &delivery.delivery_digest)?;
            if previous.is_some_and(|domain: &str| delivery.destination.as_str() <= domain)
                || self
                    .participant_domains
                    .binary_search_by(|domain| domain.as_str().cmp(&delivery.destination))
                    .is_err()
            {
                return Err(
                    "MLS recovery delivery commitments are not the exact domain set".into(),
                );
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

    pub fn verify_delivery(&self, delivery: &MlsMembershipDeliveryV1) -> Result<(), String> {
        self.validate()?;
        delivery.validate()?;
        if delivery.conversation_id != self.conversation_id
            || delivery.incarnation != self.new_genesis.incarnation
            || delivery.proposal_id != self.proposal_id
            || delivery.epoch_after != self.new_genesis.initial_epoch
            || delivery.next_roster_commitment != self.new_genesis.roster_commitment
            || delivery.next_participant_domains != self.participant_domains
        {
            return Err("MLS recovery delivery differs from its public plan".into());
        }
        let commitment = self
            .delivery_commitment(&delivery.destination)
            .ok_or("MLS recovery delivery destination is not committed")?;
        if delivery.delivery_digest()? != commitment.delivery_digest {
            return Err("MLS recovery delivery digest does not match".into());
        }
        Ok(())
    }
}

/// Owner-signed public recovery certificate. Verification requires the exact
/// owner set reconstructed from the immutable previous-incarnation history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsIncarnationRecoveryV1 {
    pub plan: MlsIncarnationRecoveryPlanV1,
    pub proposal: MlsControlProposalV1,
    pub owner_approval: MlsOwnerApprovalCertificateV1,
}

impl MlsIncarnationRecoveryV1 {
    pub fn validate_shape(&self) -> Result<(), String> {
        self.plan.validate()?;
        self.proposal.verify()?;
        let digest = self.plan.transition_digest()?;
        if self.proposal.conversation_id != self.plan.conversation_id
            || self.proposal.incarnation != self.plan.previous_incarnation
            || self.proposal.proposal_id != self.plan.proposal_id
            || self.proposal.base_epoch != self.plan.previous_epoch
            || self.proposal.action_type != MlsControlActionTypeV1::RecoverIncarnation
            || self.owner_approval.proposal_hash != self.proposal.proposal_hash()?
            || self.owner_approval.transition_digest.as_deref() != Some(digest.as_str())
        {
            return Err("MLS recovery proposal, plan, and owner certificate differ".into());
        }
        Ok(())
    }

    pub fn verify(&self, previous_owners: &MlsOwnerSetV1) -> Result<(), String> {
        self.validate_shape()?;
        if self.plan.new_genesis.owner_set.as_ref() != Some(previous_owners) {
            return Err("MLS recovery does not preserve the exact previous owner set".into());
        }
        self.owner_approval.verify(
            &self.proposal,
            Some(&self.plan.transition_digest()?),
            previous_owners,
        )
    }
}

/// Origin-only recovery request. Full addresses and Welcome ciphertexts are
/// split into destination-private federation replicas before transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverMlsConversationRequestV1 {
    pub recovery: MlsIncarnationRecoveryV1,
    pub creator: AccountAddress,
    pub creator_device_id: u32,
    pub members: Vec<MlsConversationMemberV1>,
    pub deliveries: Vec<MlsMembershipDeliveryV1>,
}

impl RecoverMlsConversationRequestV1 {
    pub fn validate_shape(&self) -> Result<(), String> {
        self.recovery.validate_shape()?;
        let plan = &self.recovery.plan;
        let canonical_creator: AccountAddress = self
            .creator
            .canonical()
            .parse()
            .map_err(|error: crate::AddressError| error.to_string())?;
        if canonical_creator != self.creator || self.creator.server.is_none() {
            return Err("MLS recovery creator must be canonical and federated".into());
        }
        if !(1..=127).contains(&self.creator_device_id)
            || !self
                .members
                .iter()
                .any(|member| member.address == self.creator)
        {
            return Err("MLS recovery creator is not an exact preserved device".into());
        }
        if self.members.len() != plan.new_genesis.member_count as usize
            || roster_commitment(&self.members)? != plan.new_genesis.roster_commitment
        {
            return Err("MLS recovery members differ from the replacement genesis".into());
        }
        let domains = self
            .members
            .iter()
            .map(|member| {
                member.validate()?;
                member
                    .address
                    .server
                    .clone()
                    .ok_or("MLS recovery member has no domain".to_string())
            })
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect::<Vec<_>>();
        if domains != plan.participant_domains || self.deliveries.len() != domains.len() {
            return Err("MLS recovery private roster has inconsistent routing".into());
        }
        let declared_owners = plan
            .new_genesis
            .owner_set
            .as_ref()
            .ok_or("MLS recovery genesis has no owners")?
            .owners
            .iter()
            .map(|owner| owner.owner_id.as_str())
            .collect::<BTreeSet<_>>();
        let roster_owners = self
            .members
            .iter()
            .filter_map(|member| member.owner_id.as_deref())
            .collect::<BTreeSet<_>>();
        if declared_owners != roster_owners || !self.members.iter().any(|member| member.is_admin) {
            return Err(
                "MLS recovery roster differs from its owner or administrator policy".into(),
            );
        }
        let mut previous = None;
        for delivery in &self.deliveries {
            if previous.is_some_and(|domain: &str| delivery.destination.as_str() <= domain) {
                return Err("MLS recovery deliveries are not strictly ordered".into());
            }
            plan.verify_delivery(delivery)?;
            let expected_local = self
                .members
                .iter()
                .filter(|member| member.address.server.as_deref() == Some(&delivery.destination))
                .cloned()
                .collect::<Vec<_>>();
            if delivery.local_members_after != expected_local {
                return Err("MLS recovery delivery has an inexact local roster".into());
            }
            if delivery
                .envelopes
                .iter()
                .any(|envelope| envelope.kind != MlsMembershipEnvelopeKindV1::Welcome)
                || expected_local.iter().any(|member| {
                    member.address != self.creator
                        && !delivery
                            .envelopes
                            .iter()
                            .any(|envelope| envelope.recipient == member.address)
                })
                || delivery.envelopes.iter().any(|envelope| {
                    envelope.recipient == self.creator
                        && envelope.device_id == self.creator_device_id
                })
            {
                return Err(
                    "MLS recovery requires at least one Welcome for every preserved account".into(),
                );
            }
            previous = Some(delivery.destination.as_str());
        }
        Ok(())
    }
}

/// Signed federation replica carrying at most one destination-private
/// delivery. Authority-only destinations receive only the public recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsRecoveryReplicaV1 {
    pub recovery: MlsIncarnationRecoveryV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_delivery: Option<MlsMembershipDeliveryV1>,
}

impl FederatedMlsRecoveryReplicaV1 {
    pub fn validate_shape(&self) -> Result<(), String> {
        self.recovery.validate_shape()?;
        if let Some(delivery) = &self.membership_delivery {
            self.recovery.plan.verify_delivery(delivery)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverMlsConversationResponseV1 {
    pub conversation_id: Uuid,
    pub previous_incarnation: u64,
    pub incarnation: u64,
    pub recovery_digest: String,
    pub status: String,
}

impl RecoverMlsConversationResponseV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.conversation_id.is_nil()
            || self.previous_incarnation == 0
            || self.previous_incarnation.checked_add(1) != Some(self.incarnation)
            || self.status != "active"
        {
            return Err("MLS recovery response has invalid identifiers or status".into());
        }
        validate_hash("recoveryDigest", &self.recovery_digest)?;
        Ok(())
    }
}
