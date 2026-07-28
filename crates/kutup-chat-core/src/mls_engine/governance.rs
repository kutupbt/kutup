//! Owner-authorized MLS ordering-authority changes.
//!
//! Authority changes use two independently verified ordering quorums over one
//! block. The exact MLS Commit is delivered to every participant just like a
//! membership Commit, even though the roster and its public commitment remain
//! unchanged.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use kutup_chat_proto::{
    MlsAuthorityChangeV1, MlsAuthorityTransitionCertificateV1, MlsOwnerApprovalCertificateV1,
    MlsOwnerApprovalV1,
};

/// Exact durable retry material for an owner-approved authority-set change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsAuthorityChange {
    pub mls_group_id: Vec<u8>,
    pub deliveries: Vec<MlsMembershipDeliveryV1>,
    pub authority_change: MlsAuthorityChangeV1,
    pub vote_request: FederatedMlsOrderingVoteRequestV1,
    pub commit_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_set_certificate: Option<MlsOrderingQuorumCertificateV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_vote_request: Option<FederatedMlsOrderingVoteRequestV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_request: Option<CommitMlsControlBlockV1>,
}

/// Atomic result of staging the OpenMLS Commit and authority governance data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedMlsAuthorityChange {
    pub pending: PendingMlsCommit,
    pub control: PendingMlsAuthorityChange,
}

/// State returned after the server acknowledges the exact joint-certified block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedMlsAuthorityChange {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
}

impl PendingMlsAuthorityChange {
    pub(super) fn validate_durable(&self) -> Result<()> {
        validate_group_id(&self.mls_group_id)?;
        validate_sha256_hex("MLS authority commit hash", &self.commit_hash)?;
        self.authority_change
            .validate()
            .map_err(|error| ChatError::Db(format!("invalid durable authority change: {error}")))?;
        self.vote_request
            .validate()
            .map_err(|error| ChatError::Db(format!("invalid durable authority vote: {error}")))?;
        let block = &self.vote_request.block;
        if block.proposal.action_type != MlsControlActionTypeV1::AuthoritySetChange
            || self.vote_request.previous_set_certificate.is_some()
            || self.vote_request.authority_change.as_ref() != Some(&self.authority_change)
            || block.proposal.payload_digest != self.commit_hash
            || self.deliveries.len() != self.authority_change.delivery_transition.deliveries.len()
            || self.vote_request.authority_set.sequence.checked_add(1)
                != Some(self.authority_change.next_authority_set.sequence)
        {
            return Err(ChatError::Db(
                "durable MLS authority control fields are inconsistent".into(),
            ));
        }
        for (delivery, commitment) in self
            .deliveries
            .iter()
            .zip(&self.authority_change.delivery_transition.deliveries)
        {
            delivery
                .verify_transition(&self.authority_change.delivery_transition)
                .map_err(ChatError::Db)?;
            if delivery.destination != commitment.destination
                || delivery.epoch_after != block.epoch_after
            {
                return Err(ChatError::Db(
                    "durable MLS authority delivery differs from its block".into(),
                ));
            }
        }
        match (&self.previous_set_certificate, &self.new_vote_request) {
            (None, None) => {}
            (Some(previous), Some(next_request)) => {
                previous
                    .verify(&self.vote_request.authority_set)
                    .map_err(ChatError::Db)?;
                if previous.block_hash != block.block_hash().map_err(ChatError::Db)?
                    || next_request.block != *block
                    || next_request.authority_change.as_ref() != Some(&self.authority_change)
                    || next_request.authority_set != self.authority_change.next_authority_set
                    || next_request.previous_set_certificate.as_ref() != Some(previous)
                {
                    return Err(ChatError::Db(
                        "durable next-set MLS vote request is inconsistent".into(),
                    ));
                }
                next_request.validate().map_err(ChatError::Db)?;
            }
            _ => {
                return Err(ChatError::Db(
                    "durable MLS authority quorum stages are incomplete".into(),
                ))
            }
        }
        if let Some(request) = &self.final_request {
            request.validate_shape().map_err(ChatError::Db)?;
            let previous = self.previous_set_certificate.as_ref().ok_or_else(|| {
                ChatError::Db("final authority request has no old-set certificate".into())
            })?;
            if request.finalized.block != *block
                || &request.finalized.quorum_certificate != previous
                || request.authority_change.as_ref() != Some(&self.authority_change)
            {
                return Err(ChatError::Db(
                    "durable finalized authority request differs from its retry record".into(),
                ));
            }
            request
                .authority_transition
                .as_ref()
                .ok_or_else(|| ChatError::Db("authority transition certificate is absent".into()))?
                .verify(
                    &block.block_hash().map_err(ChatError::Db)?,
                    &self.vote_request.authority_set,
                    &self.authority_change.next_authority_set,
                )
                .map_err(ChatError::Db)?;
        }
        Ok(())
    }
}

impl MlsClient {
    /// Resolve authenticated ordering policies into the next contiguous set.
    /// Quorum calculation and key binding therefore remain in the shared engine.
    pub async fn prepare_authority_change_from_policies(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        authority_policies: &[MlsOrderingServicePolicyV1],
        created_at_seconds: i64,
    ) -> Result<PreparedMlsAuthorityChange> {
        validate_group_id(mls_group_id)?;
        let group_key = BASE64.encode(mls_group_id);
        let (_, metadata) = self.load_provider().await?;
        let conversation = metadata
            .conversations
            .values()
            .find(|record| record.request.genesis.mls_group_id == group_key)
            .ok_or_else(|| ChatError::Trust("local MLS conversation is unavailable".into()))?;
        let mut next = authority_set_from_policies(authority_policies)?;
        next.sequence = conversation
            .current_authority_set
            .sequence
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS authority sequence is exhausted".into()))?;
        self.prepare_authority_change(mls_group_id, proposal_id, next, created_at_seconds)
            .await
    }

    /// Stage an unchanged-roster MLS Commit, bind the next authority set to its
    /// destination deliveries, and add this device's owner approval.
    pub async fn prepare_authority_change(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        next_authority_set: MlsAuthoritySetV1,
        created_at_seconds: i64,
    ) -> Result<PreparedMlsAuthorityChange> {
        validate_group_id(mls_group_id)?;
        if proposal_id.is_nil() || created_at_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS authority change requires a proposal id and valid clock".into(),
            ));
        }
        next_authority_set.validate().map_err(ChatError::Invalid)?;
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if let Some(existing) = metadata.pending_authority_changes.get(&group_key) {
            if existing.vote_request.block.proposal.proposal_id == proposal_id
                && existing.authority_change.next_authority_set == next_authority_set
            {
                let pending = metadata.pending_commits.get(&group_key).ok_or_else(|| {
                    ChatError::Db("durable authority change has no pending Commit".into())
                })?;
                return Ok(PreparedMlsAuthorityChange {
                    pending: pending.clone(),
                    control: existing.clone(),
                });
            }
            return Err(ChatError::Trust(
                "another MLS authority change is already pending".into(),
            ));
        }
        if metadata.pending_membership_changes.contains_key(&group_key)
            || metadata.pending_commits.contains_key(&group_key)
        {
            return Err(ChatError::Trust(
                "another MLS control operation is already pending".into(),
            ));
        }
        let conversation = metadata
            .conversations
            .values()
            .find(|record| record.request.genesis.mls_group_id == group_key)
            .cloned()
            .ok_or_else(|| ChatError::Trust("local MLS conversation is unavailable".into()))?;
        if conversation.status != LocalMlsConversationStatus::Active {
            return Err(ChatError::Trust(
                "MLS authority cannot change before genesis publication".into(),
            ));
        }
        validate_local_control_state(&conversation)?;
        let next_height = conversation
            .last_finalized_height
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS control height is exhausted".into()))?;
        let next_epoch = conversation
            .last_finalized_epoch
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS epoch is exhausted".into()))?;
        let next_authority_sequence = conversation
            .current_authority_set
            .sequence
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS authority sequence is exhausted".into()))?;
        if next_authority_set.sequence != next_authority_sequence
            || next_authority_set == conversation.current_authority_set
        {
            return Err(ChatError::Invalid(
                "next MLS authority set must be changed and exactly contiguous".into(),
            ));
        }
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let local_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == local_address)
            .ok_or_else(|| {
                ChatError::Trust("local account is absent from the MLS roster".into())
            })?;
        if !local_member.is_admin {
            return Err(ChatError::Trust(
                "MLS authority control requires a current administrator".into(),
            ));
        }
        let owner = group_owner_credential(&metadata, mls_group_id)?;
        if local_member.owner_id.as_deref() != Some(owner.owner_id.as_str())
            || conversation
                .current_owner_set
                .owner(&owner.owner_id)
                .is_none()
        {
            return Err(ChatError::Trust(
                "this device has no current owner credential for the authority change".into(),
            ));
        }

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
        ensure_private_control_matches_record(group.extensions(), &conversation)?;
        let current_devices = group
            .members()
            .map(|member| {
                let identity = std::str::from_utf8(member.credential.serialized_content())
                    .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?;
                let (address, device_id) = parse_device_credential_identity(identity)?;
                Ok((address, device_id))
            })
            .collect::<Result<Vec<_>>>()?;
        let next_private_control = MlsPrivateControlStateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            proposal_id: Some(proposal_id),
            height: next_height,
            initial_epoch: conversation.request.genesis.initial_epoch,
            epoch: next_epoch,
            previous_block_hash: conversation.last_block_hash.clone(),
            genesis_roster: conversation.request.members.clone(),
            genesis_authority_set: conversation.request.genesis.authority_set.clone(),
            genesis_owner_set: conversation
                .request
                .genesis
                .owner_set
                .clone()
                .ok_or_else(|| ChatError::Db("group genesis has no owner set".into()))?,
            roster: conversation.current_roster.clone(),
            authority_set: next_authority_set.clone(),
            owner_set: conversation.current_owner_set.clone(),
        };
        next_private_control
            .validate()
            .map_err(ChatError::Invalid)?;
        let pending = stage_private_control_update(
            &provider,
            &mut metadata,
            mls_group_id,
            &next_private_control,
        )?;
        let (deliveries, delivery_transition) = build_governance_deliveries(
            &metadata,
            &conversation,
            proposal_id,
            &conversation.current_roster,
            &current_devices,
            &pending,
        )?;
        let authority_change = MlsAuthorityChangeV1 {
            next_authority_set,
            delivery_transition,
        };
        let proposal = sign_control_proposal_with_metadata(
            &metadata,
            mls_group_id,
            conversation.request.genesis.conversation_id,
            conversation.request.genesis.incarnation,
            proposal_id,
            pending.epoch_before,
            MlsControlActionTypeV1::AuthoritySetChange,
            &pending.commit,
            created_at_seconds,
        )?;
        let proposal_hash = proposal.proposal_hash().map_err(ChatError::Protocol)?;
        let transition_digest = authority_change
            .transition_digest()
            .map_err(ChatError::Protocol)?;
        let owner_seed: [u8; 32] = ensure_group_owner_key(&metadata, mls_group_id)?
            .try_into()
            .map_err(|_| ChatError::Db("invalid durable MLS owner seed".into()))?;
        let owner_signer = Ed25519SigningKey::from_bytes(&owner_seed);
        let mut approval = MlsOwnerApprovalV1 {
            conversation_id: proposal.conversation_id,
            incarnation: proposal.incarnation,
            owner_set_sequence: conversation.current_owner_set.sequence,
            proposal_hash: proposal_hash.clone(),
            transition_digest: Some(transition_digest.clone()),
            owner_id: owner.owner_id,
            approved_at: created_at_seconds,
            signature: String::new(),
        };
        approval.signature = BASE64.encode(
            owner_signer
                .sign(&approval.signing_bytes().map_err(ChatError::Protocol)?)
                .to_bytes(),
        );
        let owner_approval = MlsOwnerApprovalCertificateV1 {
            owner_set_sequence: conversation.current_owner_set.sequence,
            proposal_hash,
            transition_digest: Some(transition_digest.clone()),
            approvals: vec![approval],
        };
        owner_approval
            .verify(
                &proposal,
                Some(transition_digest.as_str()),
                &conversation.current_owner_set,
            )
            .map_err(ChatError::Trust)?;
        let block = MlsControlBlockV1 {
            conversation_id: proposal.conversation_id,
            incarnation: proposal.incarnation,
            height: next_height,
            previous_block_hash: conversation.last_block_hash.clone(),
            epoch_before: pending.epoch_before,
            epoch_after: pending.epoch_after,
            proposal,
            transition_digest: Some(transition_digest),
            owner_approval: Some(owner_approval),
            finalized_at: created_at_seconds,
        };
        block.validate().map_err(ChatError::Protocol)?;
        let vote_request = FederatedMlsOrderingVoteRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            block,
            authority_change: Some(authority_change.clone()),
            authority_set: conversation.current_authority_set.clone(),
            previous_set_certificate: None,
        };
        vote_request.validate().map_err(ChatError::Protocol)?;
        let control = PendingMlsAuthorityChange {
            mls_group_id: mls_group_id.to_vec(),
            deliveries,
            authority_change,
            vote_request,
            commit_hash: pending.commit_hash.clone(),
            previous_set_certificate: None,
            new_vote_request: None,
            final_request: None,
        };
        control.validate_durable()?;
        metadata
            .pending_authority_changes
            .insert(group_key, control.clone());
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(PreparedMlsAuthorityChange { pending, control })
    }

    pub async fn pending_authority_changes(&self) -> Result<Vec<PendingMlsAuthorityChange>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata
            .pending_authority_changes
            .values()
            .cloned()
            .collect())
    }

    /// Verify the current authority quorum and durably construct the exact
    /// vote request for the next authority set.
    pub async fn record_authority_previous_quorum(
        &self,
        mls_group_id: &[u8],
        certificate: MlsOrderingQuorumCertificateV1,
    ) -> Result<FederatedMlsOrderingVoteRequestV1> {
        validate_group_id(mls_group_id)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let control = metadata
            .pending_authority_changes
            .get_mut(&BASE64.encode(mls_group_id))
            .ok_or_else(|| {
                ChatError::Trust("pending MLS authority control is unavailable".into())
            })?;
        if let Some(request) = &control.new_vote_request {
            if control.previous_set_certificate.as_ref() != Some(&certificate) {
                return Err(ChatError::Trust(
                    "different old-set quorum already pinned for authority change".into(),
                ));
            }
            return Ok(request.clone());
        }
        certificate
            .verify(&control.vote_request.authority_set)
            .map_err(ChatError::Trust)?;
        if certificate.block_hash
            != control
                .vote_request
                .block
                .block_hash()
                .map_err(ChatError::Protocol)?
            || certificate.height != control.vote_request.block.height
        {
            return Err(ChatError::Trust(
                "old authority quorum finalized a different block".into(),
            ));
        }
        let request = FederatedMlsOrderingVoteRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            block: control.vote_request.block.clone(),
            authority_change: Some(control.authority_change.clone()),
            authority_set: control.authority_change.next_authority_set.clone(),
            previous_set_certificate: Some(certificate.clone()),
        };
        request.validate().map_err(ChatError::Protocol)?;
        control.previous_set_certificate = Some(certificate);
        control.new_vote_request = Some(request.clone());
        control.validate_durable()?;
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(request)
    }

    /// Verify the next authority quorum and build the joint-certified commit.
    pub async fn build_authority_commit_request(
        &self,
        mls_group_id: &[u8],
        new_set_certificate: MlsOrderingQuorumCertificateV1,
    ) -> Result<CommitMlsControlBlockV1> {
        validate_group_id(mls_group_id)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let control = metadata
            .pending_authority_changes
            .get_mut(&BASE64.encode(mls_group_id))
            .ok_or_else(|| {
                ChatError::Trust("pending MLS authority control is unavailable".into())
            })?;
        if let Some(request) = &control.final_request {
            let expected = request
                .authority_transition
                .as_ref()
                .map(|transition| &transition.new_set_certificate);
            if expected != Some(&new_set_certificate) {
                return Err(ChatError::Trust(
                    "different next-set quorum already pinned for authority change".into(),
                ));
            }
            return Ok(request.clone());
        }
        let previous = control.previous_set_certificate.clone().ok_or_else(|| {
            ChatError::Trust("old-set quorum must be pinned before next-set quorum".into())
        })?;
        new_set_certificate
            .verify(&control.authority_change.next_authority_set)
            .map_err(ChatError::Trust)?;
        let block_hash = control
            .vote_request
            .block
            .block_hash()
            .map_err(ChatError::Protocol)?;
        let authority_transition = MlsAuthorityTransitionCertificateV1 {
            previous_set_certificate: previous.clone(),
            new_set_certificate,
        };
        authority_transition
            .verify(
                &block_hash,
                &control.vote_request.authority_set,
                &control.authority_change.next_authority_set,
            )
            .map_err(ChatError::Trust)?;
        let request = CommitMlsControlBlockV1 {
            finalized: MlsFinalizedControlBlockV1 {
                block: control.vote_request.block.clone(),
                quorum_certificate: previous,
            },
            membership_transition: None,
            authority_change: Some(control.authority_change.clone()),
            authority_transition: Some(authority_transition),
            owner_change: None,
        };
        request.validate_shape().map_err(ChatError::Protocol)?;
        control.final_request = Some(request.clone());
        control.validate_durable()?;
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(request)
    }

    pub async fn finalize_authority_change(
        &self,
        mls_group_id: &[u8],
        acknowledgement: &CommitMlsControlBlockResponseV1,
    ) -> Result<FinalizedMlsAuthorityChange> {
        validate_group_id(mls_group_id)?;
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        let Some(control) = metadata.pending_authority_changes.get(&group_key).cloned() else {
            let conversation = metadata
                .conversations
                .values()
                .find(|record| record.request.genesis.mls_group_id == group_key)
                .cloned()
                .ok_or_else(|| ChatError::Trust("local MLS conversation is unavailable".into()))?;
            if conversation.last_finalized_height != acknowledgement.height
                || conversation.last_finalized_epoch != acknowledgement.epoch
                || conversation.last_block_hash.as_deref()
                    != Some(acknowledgement.block_hash.as_str())
            {
                return Err(ChatError::Trust(
                    "authority acknowledgement has no matching durable operation".into(),
                ));
            }
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
                .map_err(|error| mls_error("load MLS group", error))?
                .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group is unavailable".into()))?;
            return Ok(FinalizedMlsAuthorityChange {
                group: local_group_state(&group),
                conversation,
            });
        };
        let block = &control.vote_request.block;
        let block_hash = block.block_hash().map_err(ChatError::Protocol)?;
        if acknowledgement.conversation_id != block.conversation_id
            || acknowledgement.incarnation != block.incarnation
            || acknowledgement.height != block.height
            || acknowledgement.epoch != block.epoch_after
            || acknowledgement.block_hash != block_hash
        {
            return Err(ChatError::Trust(
                "server acknowledged a different MLS authority block".into(),
            ));
        }
        if control.final_request.is_none() {
            return Err(ChatError::Trust(
                "authority change was acknowledged before joint quorum was pinned".into(),
            ));
        }
        let pending = metadata
            .pending_commits
            .get(&group_key)
            .ok_or_else(|| ChatError::Db("pending MLS authority Commit is unavailable".into()))?;
        if pending.commit_hash != control.commit_hash
            || pending.epoch_before != block.epoch_before
            || pending.epoch_after != block.epoch_after
        {
            return Err(ChatError::Db(
                "pending MLS Commit differs from authority retry material".into(),
            ));
        }
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group is unavailable".into()))?;
        if group.epoch().as_u64() != pending.epoch_before || group.pending_commit().is_none() {
            return Err(ChatError::Trust(
                "durable MLS pending state does not match authority control".into(),
            ));
        }
        group
            .merge_pending_commit(&provider)
            .map_err(|error| mls_error("merge pending MLS authority commit", error))?;
        let private_control = extract_private_control_state(group.extensions())?;
        let conversation = metadata
            .conversations
            .get_mut(&block.conversation_id.to_string())
            .ok_or_else(|| ChatError::Db("local MLS conversation is unavailable".into()))?;
        if private_control.proposal_id != Some(block.proposal.proposal_id)
            || private_control.height != block.height
            || private_control.epoch != block.epoch_after
            || private_control.roster != conversation.current_roster
            || private_control.authority_set != control.authority_change.next_authority_set
            || private_control.owner_set != conversation.current_owner_set
            || conversation.last_finalized_height.checked_add(1) != Some(block.height)
            || conversation.last_finalized_epoch != block.epoch_before
            || conversation.last_block_hash != block.previous_block_hash
        {
            return Err(ChatError::Trust(
                "merged MLS private state differs from the authority block".into(),
            ));
        }
        conversation.last_finalized_height = block.height;
        conversation.last_finalized_epoch = block.epoch_after;
        conversation.last_block_hash = Some(block_hash);
        conversation.current_authority_set = control.authority_change.next_authority_set;
        let conversation = conversation.clone();
        metadata.pending_commits.remove(&group_key);
        metadata.pending_authority_changes.remove(&group_key);
        let group = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(FinalizedMlsAuthorityChange {
            group,
            conversation,
        })
    }
}

pub(super) fn build_governance_deliveries(
    metadata: &SnapshotMetadata,
    conversation: &LocalMlsConversationRecord,
    proposal_id: Uuid,
    next_roster: &[MlsConversationMemberV1],
    current_devices: &[(String, u32)],
    pending: &PendingMlsCommit,
) -> Result<(Vec<MlsMembershipDeliveryV1>, MlsMembershipTransitionV1)> {
    let previous_domains = participant_domains(&conversation.current_roster)?;
    let next_domains = participant_domains(next_roster)?;
    if previous_domains != next_domains || conversation.current_roster.len() != next_roster.len() {
        return Err(ChatError::Invalid(
            "MLS governance delivery cannot change membership routing".into(),
        ));
    }
    let previous_commitment =
        roster_commitment(&conversation.current_roster).map_err(ChatError::Db)?;
    let next_commitment = roster_commitment(next_roster).map_err(ChatError::Db)?;
    let local_device = parse_device_credential_identity(&metadata.credential_identity)?;
    let commit_message = BASE64.encode(&pending.commit);
    let mut envelopes_by_domain = BTreeMap::<String, Vec<MlsMembershipEnvelopeV1>>::new();
    for (address, device_id) in current_devices {
        if address == &local_device.0 && device_id == &local_device.1 {
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
    let mut deliveries = Vec::with_capacity(next_domains.len());
    for destination in &next_domains {
        let mut local_members_after = next_roster
            .iter()
            .filter(|member| member.address.server.as_deref() == Some(destination.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        local_members_after.sort_by_key(|member| member.address.canonical());
        let mut envelopes = envelopes_by_domain.remove(destination).unwrap_or_default();
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
            destination: destination.clone(),
            epoch_after: pending.epoch_after,
            next_roster_commitment: next_commitment.clone(),
            next_participant_domains: next_domains.clone(),
            local_members_after,
            envelopes,
        };
        delivery.validate().map_err(ChatError::Protocol)?;
        deliveries.push(delivery);
    }
    if !envelopes_by_domain.is_empty() {
        return Err(ChatError::Protocol(
            "MLS governance Commit targets a domain outside the roster".into(),
        ));
    }
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: conversation.request.genesis.conversation_id,
        incarnation: conversation.request.genesis.incarnation,
        proposal_id,
        previous_roster_commitment: previous_commitment,
        next_roster_commitment: next_commitment,
        previous_member_count: conversation.current_roster.len() as u32,
        next_member_count: conversation.current_roster.len() as u32,
        previous_participant_domains: previous_domains,
        next_participant_domains: next_domains,
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
    Ok((deliveries, transition))
}
