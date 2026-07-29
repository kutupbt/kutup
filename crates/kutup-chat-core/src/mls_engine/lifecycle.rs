//! Membership Commit preparation, finalization, retry, and rejection.

use super::*;

impl MlsClient {
    /// Atomically stage one add-only, remove-only, or administrator-only group
    /// roster change, including the OpenMLS pending Commit and the exact
    /// pseudonymous control-plane retry material. Owner assignments remain a
    /// separate quorum-authorized action.
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
        if metadata.pending_commits.contains_key(&group_key)
            || metadata.pending_authority_changes.contains_key(&group_key)
            || metadata.pending_owner_changes.contains_key(&group_key)
            || metadata.pending_closes.contains_key(&group_key)
            || metadata.pending_policy_changes.contains_key(&group_key)
            || metadata.pending_recoveries.contains_key(&group_key)
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
        ensure_private_control_matches_record(group.extensions(), &conversation)?;
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
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        if !current_by_address
            .get(&local_address)
            .is_some_and(|member| member.is_admin)
        {
            return Err(ChatError::Trust(
                "MLS roster control requires a current group administrator".into(),
            ));
        }
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
        let administrator_only = added_accounts.is_empty() && removed_accounts.is_empty();
        let action_type = if administrator_only {
            MlsControlActionTypeV1::RoutineAdmin
        } else {
            MlsControlActionTypeV1::MembershipChange
        };
        validate_private_roster_action(&conversation.current_roster, next_roster, action_type)
            .map_err(ChatError::Invalid)?;
        let next_private_control = MlsPrivateControlStateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            proposal_id: Some(proposal_id),
            height: conversation.last_finalized_height.saturating_add(1),
            initial_epoch: conversation.request.genesis.initial_epoch,
            epoch: conversation.last_finalized_epoch.saturating_add(1),
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
            roster: next_roster.to_vec(),
            authority_set: conversation.current_authority_set.clone(),
            owner_set: conversation.current_owner_set.clone(),
            authorization_policy: conversation.current_authorization_policy.clone(),
            cryptographic_policy: conversation.current_cryptographic_policy.clone(),
        };
        next_private_control
            .validate()
            .map_err(ChatError::Invalid)?;

        let pending = if administrator_only {
            if !additions.is_empty() {
                return Err(ChatError::Invalid(
                    "MLS routine administrator control cannot carry KeyPackages".into(),
                ));
            }
            stage_private_control_update(
                &provider,
                &mut metadata,
                mls_group_id,
                &next_private_control,
            )?
        } else if !added_accounts.is_empty() {
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
                Some(&next_private_control),
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
            stage_remove_members(
                &provider,
                &mut metadata,
                mls_group_id,
                &removed_identities,
                Some(&next_private_control),
            )?
        };
        let control = build_pending_membership_change(
            &metadata,
            &conversation,
            mls_group_id,
            proposal_id,
            next_roster,
            additions,
            &[],
            &current_devices,
            &pending,
            action_type,
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
            authority_change: None,
            authority_transition: None,
            owner_change: None,
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
        let private_control = extract_private_control_state(group.extensions())?;
        let expected_owner_set = metadata
            .conversations
            .get(&block.conversation_id.to_string())
            .ok_or_else(|| ChatError::Db("local MLS conversation record is unavailable".into()))?
            .current_owner_set
            .clone();
        if private_control.conversation_id != block.conversation_id
            || private_control.incarnation != block.incarnation
            || private_control.proposal_id != Some(block.proposal.proposal_id)
            || private_control.height != block.height
            || private_control.epoch != block.epoch_after
            || private_control.previous_block_hash != block.previous_block_hash
            || private_control.roster != control.next_roster
            || private_control.authority_set != control.vote_request.authority_set
            || private_control.owner_set != expected_owner_set
        {
            return Err(ChatError::Trust(
                "merged MLS private control extension differs from the finalized block".into(),
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
        advance_member_readiness(conversation, &control.next_roster, block.epoch_after);
        conversation.current_roster = control.next_roster;
        let conversation = conversation.clone();
        ownership::prune_owner_candidates_for_roster(
            &mut metadata,
            mls_group_id,
            &conversation.current_roster,
        )?;
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
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        let private_control = advance_test_private_control(
            extract_private_control_state(group.extensions())?,
            additions
                .iter()
                .map(|addition| addition.credential.credential_identity.as_str()),
            std::iter::empty(),
        )?;
        let pending = stage_add_members(
            &provider,
            &mut metadata,
            mls_group_id,
            additions,
            now_seconds,
            Some(&private_control),
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
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        let private_control = advance_test_private_control(
            extract_private_control_state(group.extensions())?,
            std::iter::empty(),
            removed_credential_identities.iter().map(String::as_str),
        )?;
        let pending = stage_remove_members(
            &provider,
            &mut metadata,
            mls_group_id,
            removed_credential_identities,
            Some(&private_control),
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
}
