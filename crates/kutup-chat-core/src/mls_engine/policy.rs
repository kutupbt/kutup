//! Owner-quorum changes to group-private authorization and cryptographic policy.
//!
//! The policy value remains inside the MLS GroupContext. Ordering authorities
//! receive only the action type, the digest of the exact MLS Commit, the
//! unchanged-roster delivery transition, and pseudonymous owner approvals.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use kutup_chat_proto::{MlsOwnerApprovalCertificateV1, MlsOwnerApprovalV1};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsPolicyChange {
    pub mls_group_id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_authorization_policy: Option<MlsGroupAuthorizationPolicyV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cryptographic_policy: Option<MlsGroupCryptographicPolicyV1>,
    pub current_roster: Vec<MlsConversationMemberV1>,
    pub deliveries: Vec<MlsMembershipDeliveryV1>,
    pub transition: MlsMembershipTransitionV1,
    pub vote_request: FederatedMlsOrderingVoteRequestV1,
    pub commit_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_request: Option<CommitMlsControlBlockV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedMlsPolicyChange {
    pub pending: PendingMlsCommit,
    pub control: PendingMlsPolicyChange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedMlsPolicyChange {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
}

impl PendingMlsPolicyChange {
    fn action_type(&self) -> Result<MlsControlActionTypeV1> {
        match (
            self.next_authorization_policy.as_ref(),
            self.next_cryptographic_policy.as_ref(),
        ) {
            (Some(_), None) => Ok(MlsControlActionTypeV1::AuthorizationPolicyChange),
            (None, Some(_)) => Ok(MlsControlActionTypeV1::CryptographicPolicyChange),
            _ => Err(ChatError::Db(
                "durable MLS policy change must contain exactly one policy".into(),
            )),
        }
    }

    pub(super) fn validate_durable(&self) -> Result<()> {
        validate_group_id(&self.mls_group_id)?;
        validate_sha256_hex("MLS policy commit hash", &self.commit_hash)?;
        validate_group_roster(&self.current_roster)?;
        self.transition.validate().map_err(ChatError::Db)?;
        self.vote_request.validate().map_err(ChatError::Db)?;
        if let Some(policy) = &self.next_authorization_policy {
            policy.validate().map_err(ChatError::Db)?;
        }
        if let Some(policy) = &self.next_cryptographic_policy {
            policy.validate().map_err(ChatError::Db)?;
        }
        let block = &self.vote_request.block;
        if block.proposal.action_type != self.action_type()?
            || self.vote_request.previous_set_certificate.is_some()
            || self.vote_request.authority_change.is_some()
            || block.proposal.payload_digest != self.commit_hash
            || block.transition_digest.as_deref()
                != Some(
                    self.transition
                        .transition_digest()
                        .map_err(ChatError::Db)?
                        .as_str(),
                )
            || self.transition.previous_roster_commitment != self.transition.next_roster_commitment
            || self.transition.previous_member_count != self.transition.next_member_count
            || self.transition.previous_participant_domains
                != self.transition.next_participant_domains
            || self.transition.next_member_count != self.current_roster.len() as u32
            || self.transition.next_roster_commitment
                != roster_commitment(&self.current_roster).map_err(ChatError::Db)?
            || self.deliveries.len() != self.transition.deliveries.len()
        {
            return Err(ChatError::Db(
                "durable MLS policy control fields are inconsistent".into(),
            ));
        }
        let certificate = block
            .owner_approval
            .as_ref()
            .ok_or_else(|| ChatError::Db("durable MLS policy change has no owner approvals".into()))?;
        if certificate.owner_set_sequence == 0
            || certificate.approvals.is_empty()
            || certificate.proposal_hash != block.proposal.proposal_hash().map_err(ChatError::Db)?
            || certificate.transition_digest.as_deref() != block.transition_digest.as_deref()
        {
            return Err(ChatError::Db(
                "durable MLS policy approval certificate is inconsistent".into(),
            ));
        }
        for (delivery, commitment) in self.deliveries.iter().zip(&self.transition.deliveries) {
            delivery
                .verify_transition(&self.transition)
                .map_err(ChatError::Db)?;
            if delivery.destination != commitment.destination
                || delivery.epoch_after != block.epoch_after
            {
                return Err(ChatError::Db(
                    "durable MLS policy delivery differs from its block".into(),
                ));
            }
        }
        if let Some(request) = &self.final_request {
            request.validate_shape().map_err(ChatError::Db)?;
            if request.finalized.block != *block
                || request.membership_transition.as_ref() != Some(&self.transition)
                || request.authority_change.is_some()
                || request.authority_transition.is_some()
                || request.owner_change.is_some()
            {
                return Err(ChatError::Db(
                    "durable finalized policy request differs from its retry record".into(),
                ));
            }
            request
                .finalized
                .verify(&self.vote_request.authority_set)
                .map_err(ChatError::Db)?;
        }
        Ok(())
    }
}

impl MlsClient {
    pub async fn prepare_authorization_policy_change(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        next_policy: MlsGroupAuthorizationPolicyV1,
        created_at_seconds: i64,
    ) -> Result<PreparedMlsPolicyChange> {
        self.prepare_policy_change(
            mls_group_id,
            proposal_id,
            Some(next_policy),
            None,
            created_at_seconds,
        )
        .await
    }

    pub async fn prepare_cryptographic_policy_change(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        next_policy: MlsGroupCryptographicPolicyV1,
        created_at_seconds: i64,
    ) -> Result<PreparedMlsPolicyChange> {
        self.prepare_policy_change(
            mls_group_id,
            proposal_id,
            None,
            Some(next_policy),
            created_at_seconds,
        )
        .await
    }

    async fn prepare_policy_change(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        next_authorization_policy: Option<MlsGroupAuthorizationPolicyV1>,
        next_cryptographic_policy: Option<MlsGroupCryptographicPolicyV1>,
        created_at_seconds: i64,
    ) -> Result<PreparedMlsPolicyChange> {
        validate_group_id(mls_group_id)?;
        if proposal_id.is_nil() || created_at_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS policy change requires a proposal id and valid clock".into(),
            ));
        }
        let action_type = match (
            next_authorization_policy.as_ref(),
            next_cryptographic_policy.as_ref(),
        ) {
            (Some(policy), None) => {
                policy.validate().map_err(ChatError::Invalid)?;
                MlsControlActionTypeV1::AuthorizationPolicyChange
            }
            (None, Some(policy)) => {
                policy.validate().map_err(ChatError::Invalid)?;
                MlsControlActionTypeV1::CryptographicPolicyChange
            }
            _ => {
                return Err(ChatError::Invalid(
                    "exactly one MLS group policy may change at a time".into(),
                ))
            }
        };
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if let Some(existing) = metadata.pending_policy_changes.get(&group_key) {
            if existing.vote_request.block.proposal.proposal_id == proposal_id
                && existing.next_authorization_policy == next_authorization_policy
                && existing.next_cryptographic_policy == next_cryptographic_policy
            {
                let pending = metadata.pending_commits.get(&group_key).ok_or_else(|| {
                    ChatError::Db("durable MLS policy change has no pending Commit".into())
                })?;
                return Ok(PreparedMlsPolicyChange {
                    pending: pending.clone(),
                    control: existing.clone(),
                });
            }
            return Err(ChatError::Trust(
                "another MLS policy change is already pending".into(),
            ));
        }
        if metadata.pending_commits.contains_key(&group_key)
            || metadata.pending_membership_changes.contains_key(&group_key)
            || metadata.pending_authority_changes.contains_key(&group_key)
            || metadata.pending_owner_changes.contains_key(&group_key)
            || metadata.pending_closes.contains_key(&group_key)
            || metadata.pending_recoveries.contains_key(&group_key)
        {
            return Err(ChatError::Trust(
                "another MLS control operation is already pending".into(),
            ));
        }
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        match (
            next_authorization_policy.as_ref(),
            next_cryptographic_policy.as_ref(),
        ) {
            (Some(next), None)
                if conversation
                    .current_authorization_policy
                    .sequence
                    .checked_add(1)
                    != Some(next.sequence)
                    || next.application_senders
                        == conversation
                            .current_authorization_policy
                            .application_senders =>
            {
                return Err(ChatError::Invalid(
                    "MLS authorization policy must be a contiguous actual change".into(),
                ));
            }
            (None, Some(next))
                if conversation
                    .current_cryptographic_policy
                    .sequence
                    .checked_add(1)
                    != Some(next.sequence)
                    || next.maximum_application_plaintext_bytes
                        >= conversation
                            .current_cryptographic_policy
                            .maximum_application_plaintext_bytes =>
            {
                return Err(ChatError::Invalid(
                    "MLS cryptographic policy must be a contiguous tightening".into(),
                ));
            }
            _ => {}
        }
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let local_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == local_address)
            .ok_or_else(|| ChatError::Trust("local account is absent from the MLS roster".into()))?;
        let owner = group_owner_credential(&metadata, mls_group_id)?;
        if !local_member.is_admin
            || local_member.owner_id.as_deref() != Some(owner.owner_id.as_str())
            || conversation
                .current_owner_set
                .owner(&owner.owner_id)
                .is_none()
        {
            return Err(ChatError::Trust(
                "only a current MLS owner-administrator can change group policy".into(),
            ));
        }

        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
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
                parse_device_credential_identity(identity)
            })
            .collect::<Result<Vec<_>>>()?;
        let next_height = conversation
            .last_finalized_height
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS control height is exhausted".into()))?;
        let next_epoch = conversation
            .last_finalized_epoch
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS epoch is exhausted".into()))?;
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
            genesis_authorization_policy: conversation.genesis_authorization_policy.clone(),
            genesis_cryptographic_policy: conversation.genesis_cryptographic_policy.clone(),
            roster: conversation.current_roster.clone(),
            authority_set: conversation.current_authority_set.clone(),
            owner_set: conversation.current_owner_set.clone(),
            authorization_policy: next_authorization_policy
                .clone()
                .unwrap_or_else(|| conversation.current_authorization_policy.clone()),
            cryptographic_policy: next_cryptographic_policy
                .clone()
                .unwrap_or_else(|| conversation.current_cryptographic_policy.clone()),
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
        let (deliveries, transition) = super::governance::build_governance_deliveries(
            &metadata,
            &conversation,
            proposal_id,
            &conversation.current_roster,
            &current_devices,
            &pending,
        )?;
        let transition_digest = transition
            .transition_digest()
            .map_err(ChatError::Protocol)?;
        let proposal = sign_control_proposal_with_metadata(
            &metadata,
            mls_group_id,
            conversation.request.genesis.conversation_id,
            conversation.request.genesis.incarnation,
            proposal_id,
            pending.epoch_before,
            action_type,
            &pending.commit,
            created_at_seconds,
        )?;
        let proposal_hash = proposal.proposal_hash().map_err(ChatError::Protocol)?;
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
            .verify_partial(
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
            authority_change: None,
            authority_set: conversation.current_authority_set.clone(),
            previous_set_certificate: None,
        };
        vote_request.validate().map_err(ChatError::Protocol)?;
        let control = PendingMlsPolicyChange {
            mls_group_id: mls_group_id.to_vec(),
            next_authorization_policy,
            next_cryptographic_policy,
            current_roster: conversation.current_roster.clone(),
            deliveries,
            transition,
            vote_request,
            commit_hash: pending.commit_hash.clone(),
            final_request: None,
        };
        validate_pending_policy_change(&control, &conversation)?;
        metadata
            .pending_policy_changes
            .insert(group_key, control.clone());
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(PreparedMlsPolicyChange { pending, control })
    }

    pub async fn pending_policy_changes(&self) -> Result<Vec<PendingMlsPolicyChange>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata.pending_policy_changes.values().cloned().collect())
    }

    pub async fn policy_change_has_owner_quorum(&self, mls_group_id: &[u8]) -> Result<bool> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        let control = metadata
            .pending_policy_changes
            .get(&BASE64.encode(mls_group_id))
            .ok_or_else(|| ChatError::Trust("pending MLS policy change is unavailable".into()))?;
        let block = &control.vote_request.block;
        let certificate = block
            .owner_approval
            .as_ref()
            .ok_or_else(|| ChatError::Db("pending MLS policy change has no approvals".into()))?;
        match certificate.verify(
            &block.proposal,
            block.transition_digest.as_deref(),
            &conversation.current_owner_set,
        ) {
            Ok(()) => Ok(true),
            Err(error) if error == "MLS owner certificate does not meet quorum" => Ok(false),
            Err(error) => Err(ChatError::Trust(error)),
        }
    }

    pub async fn build_policy_commit_request(
        &self,
        mls_group_id: &[u8],
        quorum_certificate: MlsOrderingQuorumCertificateV1,
    ) -> Result<CommitMlsControlBlockV1> {
        validate_group_id(mls_group_id)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        let control = metadata
            .pending_policy_changes
            .get_mut(&BASE64.encode(mls_group_id))
            .ok_or_else(|| ChatError::Trust("pending MLS policy change is unavailable".into()))?;
        control
            .vote_request
            .block
            .owner_approval
            .as_ref()
            .ok_or_else(|| ChatError::Trust("pending MLS policy change has no approvals".into()))?
            .verify(
                &control.vote_request.block.proposal,
                control.vote_request.block.transition_digest.as_deref(),
                &conversation.current_owner_set,
            )
            .map_err(|_| {
                ChatError::Trust(
                    "MLS policy change requires additional explicit owner approvals".into(),
                )
            })?;
        if let Some(request) = &control.final_request {
            if request.finalized.quorum_certificate != quorum_certificate {
                return Err(ChatError::Trust(
                    "different authority quorum already pinned for MLS policy change".into(),
                ));
            }
            return Ok(request.clone());
        }
        quorum_certificate
            .verify(&control.vote_request.authority_set)
            .map_err(ChatError::Trust)?;
        let block = &control.vote_request.block;
        if quorum_certificate.block_hash != block.block_hash().map_err(ChatError::Protocol)?
            || quorum_certificate.height != block.height
        {
            return Err(ChatError::Trust(
                "authority quorum finalized a different MLS policy block".into(),
            ));
        }
        let request = CommitMlsControlBlockV1 {
            finalized: MlsFinalizedControlBlockV1 {
                block: block.clone(),
                quorum_certificate,
            },
            membership_transition: Some(control.transition.clone()),
            authority_change: None,
            authority_transition: None,
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

    pub async fn finalize_policy_change(
        &self,
        mls_group_id: &[u8],
        acknowledgement: &CommitMlsControlBlockResponseV1,
    ) -> Result<FinalizedMlsPolicyChange> {
        validate_group_id(mls_group_id)?;
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        let Some(control) = metadata.pending_policy_changes.get(&group_key).cloned() else {
            let conversation = metadata
                .conversations
                .values()
                .find(|record| record.request.genesis.mls_group_id == group_key)
                .cloned()
                .ok_or_else(|| ChatError::Trust("local MLS conversation is unavailable".into()))?;
            if conversation.request.genesis.conversation_id != acknowledgement.conversation_id
                || conversation.request.genesis.incarnation != acknowledgement.incarnation
                || conversation.last_finalized_height != acknowledgement.height
                || conversation.last_finalized_epoch != acknowledgement.epoch
                || conversation.last_block_hash.as_deref()
                    != Some(acknowledgement.block_hash.as_str())
            {
                return Err(ChatError::Trust(
                    "policy acknowledgement has no matching durable operation".into(),
                ));
            }
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
                .map_err(|error| mls_error("load MLS group", error))?
                .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group is unavailable".into()))?;
            return Ok(FinalizedMlsPolicyChange {
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
            || control.final_request.is_none()
        {
            return Err(ChatError::Trust(
                "server acknowledged a different or incomplete MLS policy change".into(),
            ));
        }
        let pending = metadata
            .pending_commits
            .get(&group_key)
            .ok_or_else(|| ChatError::Db("pending MLS policy Commit is unavailable".into()))?;
        if pending.commit_hash != control.commit_hash
            || pending.epoch_before != block.epoch_before
            || pending.epoch_after != block.epoch_after
        {
            return Err(ChatError::Db(
                "pending MLS Commit differs from policy retry material".into(),
            ));
        }
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group is unavailable".into()))?;
        if group.epoch().as_u64() != pending.epoch_before || group.pending_commit().is_none() {
            return Err(ChatError::Trust(
                "durable MLS pending state does not match policy control".into(),
            ));
        }
        group
            .merge_pending_commit(&provider)
            .map_err(|error| mls_error("merge pending MLS policy commit", error))?;
        let private_control = extract_private_control_state(group.extensions())?;
        let conversation = metadata
            .conversations
            .get_mut(&block.conversation_id.to_string())
            .ok_or_else(|| ChatError::Db("local MLS conversation is unavailable".into()))?;
        let expected_authorization = control
            .next_authorization_policy
            .as_ref()
            .unwrap_or(&conversation.current_authorization_policy);
        let expected_cryptographic = control
            .next_cryptographic_policy
            .as_ref()
            .unwrap_or(&conversation.current_cryptographic_policy);
        if private_control.proposal_id != Some(block.proposal.proposal_id)
            || private_control.height != block.height
            || private_control.epoch != block.epoch_after
            || private_control.roster != control.current_roster
            || private_control.authority_set != conversation.current_authority_set
            || private_control.owner_set != conversation.current_owner_set
            || &private_control.authorization_policy != expected_authorization
            || &private_control.cryptographic_policy != expected_cryptographic
            || conversation.last_finalized_height.checked_add(1) != Some(block.height)
            || conversation.last_finalized_epoch != block.epoch_before
            || conversation.last_block_hash != block.previous_block_hash
        {
            return Err(ChatError::Trust(
                "merged MLS private state differs from the policy block".into(),
            ));
        }
        conversation.last_finalized_height = block.height;
        conversation.last_finalized_epoch = block.epoch_after;
        conversation.last_block_hash = Some(block_hash);
        conversation.current_authorization_policy = private_control.authorization_policy;
        conversation.current_cryptographic_policy = private_control.cryptographic_policy;
        let conversation = conversation.clone();
        metadata.pending_commits.remove(&group_key);
        metadata.pending_policy_changes.remove(&group_key);
        metadata.owner_approval_requests.remove(&group_key);
        let group = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(FinalizedMlsPolicyChange {
            group,
            conversation,
        })
    }
}

pub(super) fn validate_pending_policy_change(
    control: &PendingMlsPolicyChange,
    conversation: &LocalMlsConversationRecord,
) -> Result<()> {
    control.validate_durable()?;
    match (
        control.next_authorization_policy.as_ref(),
        control.next_cryptographic_policy.as_ref(),
    ) {
        (Some(next), None)
            if conversation
                .current_authorization_policy
                .sequence
                .checked_add(1)
                == Some(next.sequence)
                && conversation.current_authorization_policy.application_senders
                    != next.application_senders => {}
        (None, Some(next))
            if conversation
                .current_cryptographic_policy
                .sequence
                .checked_add(1)
                == Some(next.sequence)
                && next.maximum_application_plaintext_bytes
                    < conversation
                        .current_cryptographic_policy
                        .maximum_application_plaintext_bytes => {}
        _ => {
            return Err(ChatError::Db(
                "durable MLS policy transition is not contiguous or tightening".into(),
            ))
        }
    }
    control
        .vote_request
        .block
        .owner_approval
        .as_ref()
        .ok_or_else(|| ChatError::Db("MLS policy change has no approval certificate".into()))?
        .verify_partial(
            &control.vote_request.block.proposal,
            control.vote_request.block.transition_digest.as_deref(),
            &conversation.current_owner_set,
        )
        .map_err(ChatError::Trust)
}
