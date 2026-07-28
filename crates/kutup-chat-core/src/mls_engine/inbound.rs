//! Ordered inbound MLS control commits and atomic mailbox receipts.

use super::*;

impl MlsClient {
    /// Return a durable processed-envelope receipt before attempting to parse
    /// a replayed Commit. This lets a restarted client acknowledge the exact
    /// mailbox row whose epoch was already atomically applied.
    pub async fn processed_control_envelope(
        &self,
        envelope_id: Uuid,
    ) -> Result<Option<ProcessedMlsControlEnvelope>> {
        if envelope_id.is_nil() {
            return Err(ChatError::Invalid(
                "MLS mailbox envelope id must not be nil".into(),
            ));
        }
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata
            .processed_control_envelopes
            .get(&envelope_id.to_string())
            .cloned())
    }

    /// Verify a quorum-certified public membership block, bind its payload to
    /// the exact MLS Commit, merge one epoch, advance the durable control pin,
    /// and record the mailbox cursor in one encrypted database transaction.
    pub async fn apply_ordered_inbound_membership_commit(
        &self,
        envelope: &MlsControlEnvelopeContext,
        mls_group_id: &[u8],
        commit_bytes: &[u8],
        expected_next_members: &[VerifiedMlsCredential],
        request: &CommitMlsControlBlockV1,
    ) -> Result<AppliedInboundMlsCommit> {
        validate_group_id(mls_group_id)?;
        envelope.validate()?;
        if commit_bytes.is_empty()
            || commit_bytes.len() > MAX_APPLICATION_BYTES
            || expected_next_members.is_empty()
            || expected_next_members.len() > 1000
        {
            return Err(ChatError::Invalid(
                "MLS mailbox Commit, cursor, or expected roster is outside v1 bounds".into(),
            ));
        }
        request.validate_shape().map_err(ChatError::Protocol)?;
        let block = &request.finalized.block;
        if !matches!(
            block.proposal.action_type,
            MlsControlActionTypeV1::MembershipChange
                | MlsControlActionTypeV1::RoutineAdmin
                | MlsControlActionTypeV1::DeviceSync
                | MlsControlActionTypeV1::AuthoritySetChange
                | MlsControlActionTypeV1::OwnerSetChange
                | MlsControlActionTypeV1::AuthorizationPolicyChange
                | MlsControlActionTypeV1::CryptographicPolicyChange
                | MlsControlActionTypeV1::CloseConversation
        ) {
            return Err(ChatError::Trust(
                "roster-control mailbox carried an unrelated block".into(),
            ));
        }
        block.proposal.verify().map_err(ChatError::Trust)?;
        let commit_hash = hex::encode(Sha256::digest(commit_bytes));
        if block.proposal.payload_digest != commit_hash {
            return Err(ChatError::Trust(
                "ordered MLS control block commits different ciphertext".into(),
            ));
        }
        let block_hash = block.block_hash().map_err(ChatError::Protocol)?;
        let receipt = ProcessedMlsControlEnvelope {
            envelope_id: envelope.envelope_id,
            cursor: envelope.cursor.clone(),
            send_id: envelope.send_id,
            conversation_id: block.conversation_id,
            incarnation: block.incarnation,
            height: block.height,
            epoch: block.epoch_after,
            block_hash: block_hash.clone(),
        };
        validate_processed_control_envelope(&receipt)?;

        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if let Some(existing) = metadata
            .processed_control_envelopes
            .get(&envelope.envelope_id.to_string())
        {
            if existing != &receipt {
                return Err(ChatError::Trust(
                    "MLS mailbox envelope id was replayed with different control material".into(),
                ));
            }
            let conversation = metadata
                .conversations
                .get(&block.conversation_id.to_string())
                .cloned()
                .ok_or_else(|| {
                    ChatError::Db("processed MLS Commit has no conversation record".into())
                })?;
            if conversation.request.genesis.mls_group_id != group_key
                || conversation.request.genesis.incarnation != existing.incarnation
                || conversation.last_finalized_height < existing.height
                || conversation.last_finalized_epoch < existing.epoch
            {
                return Err(ChatError::Db(
                    "processed MLS receipt differs from its current conversation".into(),
                ));
            }
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
                .map_err(|error| mls_error("load MLS group", error))?
                .ok_or_else(|| {
                    ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
                })?;
            ensure_v1_group(&group)?;
            ensure_private_control_matches_record(group.extensions(), &conversation)?;
            return Ok(AppliedInboundMlsCommit {
                group: local_group_state(&group),
                conversation,
                receipt: existing.clone(),
                idempotent: true,
            });
        }
        if metadata
            .processed_control_envelopes
            .values()
            .any(|existing| {
                existing.send_id == envelope.send_id || existing.cursor == envelope.cursor
            })
        {
            return Err(ChatError::Trust(
                "MLS mailbox reused a processed send id or cursor".into(),
            ));
        }
        if metadata.pending_commits.contains_key(&group_key)
            || metadata.pending_membership_changes.contains_key(&group_key)
            || metadata.pending_authority_changes.contains_key(&group_key)
            || metadata.pending_owner_changes.contains_key(&group_key)
            || metadata.pending_closes.contains_key(&group_key)
            || metadata.pending_policy_changes.contains_key(&group_key)
        {
            return Err(ChatError::Trust(
                "cannot merge a remote MLS Commit while a local Commit is pending".into(),
            ));
        }
        let conversation = metadata
            .conversations
            .get(&block.conversation_id.to_string())
            .cloned()
            .ok_or_else(|| {
                ChatError::Trust("local MLS conversation control state is unavailable".into())
            })?;
        if conversation.status != LocalMlsConversationStatus::Active
            || conversation.request.genesis.mls_group_id != group_key
            || conversation.request.genesis.incarnation != block.incarnation
        {
            return Err(ChatError::Trust(
                "inbound MLS block differs from the active conversation genesis".into(),
            ));
        }
        validate_local_control_state(&conversation)?;
        request
            .finalized
            .verify(&conversation.current_authority_set)
            .map_err(ChatError::Trust)?;
        if block.proposal.action_type.requires_owner_quorum() {
            block
                .owner_approval
                .as_ref()
                .ok_or_else(|| ChatError::Trust("group control has no owner quorum".into()))?
                .verify(
                    &block.proposal,
                    block.transition_digest.as_deref(),
                    &conversation.current_owner_set,
                )
                .map_err(ChatError::Trust)?;
        }
        if block.proposal.action_type == MlsControlActionTypeV1::AuthoritySetChange {
            let change = request
                .authority_change
                .as_ref()
                .expect("validated authority request");
            request
                .authority_transition
                .as_ref()
                .expect("validated authority request")
                .verify(
                    &block_hash,
                    &conversation.current_authority_set,
                    &change.next_authority_set,
                )
                .map_err(ChatError::Trust)?;
        }
        if block.height != conversation.last_finalized_height.saturating_add(1)
            || block.epoch_before != conversation.last_finalized_epoch
            || block.epoch_after != block.epoch_before.saturating_add(1)
            || block.previous_block_hash != conversation.last_block_hash
        {
            return Err(ChatError::Trust(
                "inbound MLS block does not exactly extend the durable control pin".into(),
            ));
        }
        let transition = request
            .membership_transition
            .as_ref()
            .or_else(|| {
                request
                    .authority_change
                    .as_ref()
                    .map(|change| &change.delivery_transition)
            })
            .or_else(|| {
                request
                    .owner_change
                    .as_ref()
                    .map(|change| &change.delivery_transition)
            })
            .expect("validated control delivery request");
        if transition.previous_roster_commitment
            != roster_commitment(&conversation.current_roster).map_err(ChatError::Protocol)?
            || transition.previous_member_count != conversation.current_roster.len() as u32
            || transition.previous_participant_domains
                != participant_domains(&conversation.current_roster)?
        {
            return Err(ChatError::Trust(
                "inbound MLS membership transition differs from the pinned roster".into(),
            ));
        }

        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
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
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|error| mls_error("parse MLS Commit", error))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Invalid("expected an MLS protocol message".into()))?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| mls_error("process MLS Commit", error))?;
        if !matches!(processed.sender(), Sender::Member(_)) {
            return Err(ChatError::Trust(
                "MLS roster Commit was not sent by a current member".into(),
            ));
        }
        let sender_identity = std::str::from_utf8(processed.credential().serialized_content())
            .map_err(|_| ChatError::Trust("MLS Commit sender identity is not UTF-8".into()))?;
        let (sender_address, _) = parse_device_credential_identity(sender_identity)?;
        let sender_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == sender_address)
            .ok_or_else(|| {
                ChatError::Trust("MLS Commit sender is absent from the roster".into())
            })?;
        let sender_authorized = match block.proposal.action_type {
            action if action.requires_owner_quorum() => sender_member
                .owner_id
                .as_deref()
                .is_some_and(|owner_id| conversation.current_owner_set.owner(owner_id).is_some()),
            MlsControlActionTypeV1::DeviceSync => true,
            _ => sender_member.is_admin,
        };
        if !sender_authorized {
            return Err(ChatError::Trust(
                "MLS control Commit sender lacks the required pinned role".into(),
            ));
        }
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            _ => return Err(ChatError::Invalid("expected an MLS Commit message".into())),
        };
        if staged.epoch().as_u64() != block.epoch_after {
            return Err(ChatError::Trust(
                "inbound MLS Commit epoch differs from the ordered block".into(),
            ));
        }
        let private_control = extract_private_control_state(staged.group_context().extensions())?;
        if private_control.conversation_id != block.conversation_id
            || private_control.incarnation != block.incarnation
            || private_control.proposal_id != Some(block.proposal.proposal_id)
            || private_control.height != block.height
            || private_control.epoch != block.epoch_after
            || private_control.previous_block_hash != block.previous_block_hash
            || private_control.genesis_roster != conversation.request.members
            || private_control.genesis_authority_set != conversation.request.genesis.authority_set
            || conversation.request.genesis.owner_set.as_ref()
                != Some(&private_control.genesis_owner_set)
            || private_control.genesis_authorization_policy
                != conversation.genesis_authorization_policy
            || private_control.genesis_cryptographic_policy
                != conversation.genesis_cryptographic_policy
            || &private_control.authority_set
                != request
                    .authority_change
                    .as_ref()
                    .map(|change| &change.next_authority_set)
                    .unwrap_or(&conversation.current_authority_set)
            || &private_control.owner_set
                != request
                    .owner_change
                    .as_ref()
                    .map(|change| &change.next_owner_set)
                    .unwrap_or(&conversation.current_owner_set)
            || transition.next_roster_commitment
                != roster_commitment(&private_control.roster).map_err(ChatError::Protocol)?
            || transition.next_member_count != private_control.roster.len() as u32
            || transition.next_participant_domains != participant_domains(&private_control.roster)?
        {
            return Err(ChatError::Trust(
                "inbound MLS private control state differs from the finalized transition".into(),
            ));
        }
        match block.proposal.action_type {
            MlsControlActionTypeV1::AuthorizationPolicyChange
                if private_control.cryptographic_policy
                    == conversation.current_cryptographic_policy
                    && conversation
                        .current_authorization_policy
                        .sequence
                        .checked_add(1)
                        == Some(private_control.authorization_policy.sequence)
                    && private_control.authorization_policy.application_senders
                        != conversation
                            .current_authorization_policy
                            .application_senders => {}
            MlsControlActionTypeV1::CryptographicPolicyChange
                if private_control.authorization_policy
                    == conversation.current_authorization_policy
                    && conversation
                        .current_cryptographic_policy
                        .sequence
                        .checked_add(1)
                        == Some(private_control.cryptographic_policy.sequence)
                    && private_control
                        .cryptographic_policy
                        .maximum_application_plaintext_bytes
                        < conversation
                            .current_cryptographic_policy
                            .maximum_application_plaintext_bytes => {}
            MlsControlActionTypeV1::AuthorizationPolicyChange
            | MlsControlActionTypeV1::CryptographicPolicyChange => {
                return Err(ChatError::Trust(
                    "inbound MLS private policy is not the authorized contiguous change".into(),
                ))
            }
            _ if private_control.authorization_policy
                != conversation.current_authorization_policy
                || private_control.cryptographic_policy
                    != conversation.current_cryptographic_policy =>
            {
                return Err(ChatError::Trust(
                    "unrelated MLS control action changed private policy".into(),
                ))
            }
            _ => {}
        }
        if matches!(
            block.proposal.action_type,
            MlsControlActionTypeV1::AuthoritySetChange
                | MlsControlActionTypeV1::AuthorizationPolicyChange
                | MlsControlActionTypeV1::CryptographicPolicyChange
                | MlsControlActionTypeV1::CloseConversation
        ) {
            if private_control.roster != conversation.current_roster {
                return Err(ChatError::Trust(
                    "MLS governance action altered the private roster".into(),
                ));
            }
        } else if block.proposal.action_type == MlsControlActionTypeV1::OwnerSetChange {
            ownership::validate_owner_role_transition(
                &conversation.current_roster,
                &private_control.roster,
                &conversation.current_owner_set,
                &private_control.owner_set,
            )?;
        } else {
            validate_private_roster_action(
                &conversation.current_roster,
                &private_control.roster,
                block.proposal.action_type,
            )
            .map_err(ChatError::Trust)?;
        }
        verify_private_control_accounts(
            &private_control,
            expected_next_members
                .iter()
                .map(|member| member.credential_identity.as_str()),
        )?;
        group
            .merge_staged_commit(&provider, *staged)
            .map_err(|error| mls_error("merge inbound MLS Commit", error))?;
        verify_exact_roster(group.members(), expected_next_members)?;
        ensure_exact_private_control_state(group.extensions(), &private_control)?;
        if block.proposal.action_type == MlsControlActionTypeV1::OwnerSetChange {
            ownership::promote_local_owner_candidate(
                &mut metadata,
                mls_group_id,
                &private_control,
            )?;
        }

        let conversation = metadata
            .conversations
            .get_mut(&block.conversation_id.to_string())
            .expect("conversation cloned above");
        conversation.last_finalized_height = block.height;
        conversation.last_finalized_epoch = block.epoch_after;
        conversation.last_block_hash = Some(block_hash);
        conversation.current_roster = private_control.roster;
        conversation.current_authority_set = private_control.authority_set;
        conversation.current_owner_set = private_control.owner_set;
        conversation.current_authorization_policy = private_control.authorization_policy;
        conversation.current_cryptographic_policy = private_control.cryptographic_policy;
        if block.proposal.action_type == MlsControlActionTypeV1::CloseConversation {
            conversation.status = LocalMlsConversationStatus::Closed;
        }
        let conversation = conversation.clone();
        ownership::prune_owner_candidates_for_roster(
            &mut metadata,
            mls_group_id,
            &conversation.current_roster,
        )?;
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let retained_local_owner = group_owner_credential(&metadata, mls_group_id)
            .ok()
            .is_some_and(|owner| {
                conversation.current_roster.iter().any(|member| {
                    member.address.canonical() == local_address
                        && member.owner_id.as_deref() == Some(owner.owner_id.as_str())
                })
            });
        if !retained_local_owner {
            if let Some(seed) = metadata.group_owner_private_keys.remove(&group_key) {
                metadata
                    .group_owner_candidate_private_keys
                    .entry(group_key.clone())
                    .or_insert(seed);
            }
        }
        insert_processed_control_envelope(&mut metadata, receipt.clone())?;
        let group = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(AppliedInboundMlsCommit {
            group,
            conversation,
            receipt,
            idempotent: false,
        })
    }

    /// Test-only raw OpenMLS primitive. Production callers must authenticate
    /// and pin the ordered control block with
    /// [`Self::apply_ordered_inbound_membership_commit`].
    #[cfg(test)]
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
}
