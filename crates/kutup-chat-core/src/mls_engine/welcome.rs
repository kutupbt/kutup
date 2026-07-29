//! Welcome installation and non-mutating Welcome or Commit inspection.

use super::*;

impl MlsClient {
    /// Test-only primitive for OpenMLS lifecycle coverage. Production callers
    /// must use [`Self::join_from_welcome_with_control_history`] so installing
    /// a Welcome and its independently verified public control head is one
    /// atomic operation.
    #[cfg(test)]
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
        let private_control = extract_private_control_state(staged.group_context().extensions())?;
        if private_control.epoch != staged.group_context().epoch().as_u64() {
            return Err(ChatError::Trust(
                "MLS Welcome private control epoch differs from its GroupContext".into(),
            ));
        }
        verify_private_control_accounts(
            &private_control,
            expected_members
                .iter()
                .map(|member| member.credential_identity.as_str()),
        )?;
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

    /// Join from a Welcome and atomically pin the complete authenticated
    /// public control history represented by its private GroupContext state.
    ///
    /// A server-supplied roster or status label is never trusted here. The
    /// Welcome authenticates the group-private account/role state, callers
    /// independently bind every device credential through transparency, and
    /// the protocol verifier replays every signed ordering block from genesis.
    pub async fn join_from_welcome_with_control_history(
        &self,
        envelope: &MlsControlEnvelopeContext,
        expected_group_id: &[u8],
        welcome_bytes: &[u8],
        expected_members: &[VerifiedMlsCredential],
        history_page_bytes: &[Vec<u8>],
    ) -> Result<JoinedMlsConversation> {
        validate_group_id(expected_group_id)?;
        envelope.validate()?;
        if welcome_bytes.is_empty()
            || welcome_bytes.len() > MAX_APPLICATION_BYTES
            || expected_members.is_empty()
            || expected_members.len() > 1000
            || history_page_bytes.is_empty()
            || history_page_bytes.len() > 1024
        {
            return Err(ChatError::Invalid(
                "MLS Welcome, roster, or control history is outside v1 bounds".into(),
            ));
        }
        let mut total_history_bytes = 0usize;
        let mut history_pages = Vec::with_capacity(history_page_bytes.len());
        for bytes in history_page_bytes {
            total_history_bytes = total_history_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| ChatError::Invalid("MLS control history size overflow".into()))?;
            if bytes.is_empty() || total_history_bytes > MAX_STATE_BYTES {
                return Err(ChatError::Invalid(
                    "MLS control history is outside the 64 MiB client bound".into(),
                ));
            }
            history_pages.push(
                MlsClientControlHistoryPageV1::from_canonical_bytes(bytes)
                    .map_err(ChatError::Protocol)?,
            );
        }
        let genesis = history_pages
            .first()
            .expect("non-empty history checked above")
            .genesis
            .clone();
        if genesis.mls_group_id != BASE64.encode(expected_group_id)
            || genesis.kind != MlsConversationKindV1::Group
            || genesis.suite != MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256
        {
            return Err(ChatError::Trust(
                "MLS control history genesis differs from the expected group".into(),
            ));
        }

        let (provider, mut metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(expected_group_id);
        let group_key = BASE64.encode(expected_group_id);
        let conversation_key = genesis.conversation_id.to_string();
        if let Some(group) = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
        {
            let record = metadata
                .conversations
                .get(&conversation_key)
                .ok_or_else(|| {
                    ChatError::Db(
                        "existing OpenMLS group has no durable conversation control pin".into(),
                    )
                })?;
            if record.request.genesis != genesis
                || record.request.genesis.mls_group_id != group_key
                || record.status != LocalMlsConversationStatus::Active
            {
                return Err(ChatError::Trust(
                    "existing MLS group differs from the imported control history".into(),
                ));
            }
            ensure_v1_group(&group)?;
            let private_control =
                ensure_private_control_matches_record(group.extensions(), record)?;
            let last_hash = verify_mls_client_control_history(&history_pages, &private_control)
                .map_err(ChatError::Trust)?;
            if last_hash != record.last_block_hash {
                return Err(ChatError::Trust(
                    "replayed MLS history differs from the durable control head".into(),
                ));
            }
            let receipt = ProcessedMlsControlEnvelope {
                envelope_id: envelope.envelope_id,
                cursor: envelope.cursor.clone(),
                send_id: envelope.send_id,
                conversation_id: private_control.conversation_id,
                incarnation: private_control.incarnation,
                height: private_control.height,
                epoch: private_control.epoch,
                block_hash: last_hash
                    .clone()
                    .expect("group Welcome has a finalized adding block"),
            };
            if metadata
                .processed_control_envelopes
                .get(&envelope.envelope_id.to_string())
                != Some(&receipt)
            {
                return Err(ChatError::Db(
                    "durable joined MLS group has no matching mailbox receipt".into(),
                ));
            }
            verify_private_control_accounts(
                &private_control,
                expected_members
                    .iter()
                    .map(|member| member.credential_identity.as_str()),
            )?;
            verify_exact_roster(group.members(), expected_members)?;
            return Ok(JoinedMlsConversation {
                group: local_group_state(&group),
                conversation: record.clone(),
            });
        }
        if metadata.conversations.contains_key(&conversation_key)
            || metadata
                .conversations
                .values()
                .any(|record| record.request.genesis.mls_group_id == group_key)
            || metadata.group_control_private_keys.contains_key(&group_key)
            || metadata.group_owner_private_keys.contains_key(&group_key)
        {
            return Err(ChatError::Db(
                "durable MLS control metadata has no matching OpenMLS group".into(),
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
        let private_control = extract_private_control_state(staged.group_context().extensions())?;
        if private_control.epoch != staged.group_context().epoch().as_u64() {
            return Err(ChatError::Trust(
                "MLS Welcome private control epoch differs from its GroupContext".into(),
            ));
        }
        verify_private_control_accounts(
            &private_control,
            expected_members
                .iter()
                .map(|member| member.credential_identity.as_str()),
        )?;
        verify_exact_roster(staged.members(), expected_members)?;
        let last_block_hash = verify_mls_client_control_history(&history_pages, &private_control)
            .map_err(ChatError::Trust)?;
        if last_block_hash.is_none() {
            return Err(ChatError::Trust(
                "a group Welcome cannot be installed without its adding control block".into(),
            ));
        }
        let request = CreateMlsConversationRequestV1 {
            genesis,
            members: private_control.genesis_roster.clone(),
            initial_devices: Vec::new(),
        };
        request.validate().map_err(ChatError::Trust)?;
        let server_genesis_hash = request
            .genesis
            .genesis_hash()
            .map_err(ChatError::Protocol)?;
        let (local_address, _) =
            parse_device_credential_identity(&metadata.credential_identity)?;
        let mut member_joined_epochs = private_control
            .roster
            .iter()
            .map(|member| (member.address.canonical(), 0))
            .collect::<BTreeMap<_, _>>();
        member_joined_epochs.insert(local_address.clone(), private_control.epoch);
        let mut accepted_invitation_epochs = member_joined_epochs
            .keys()
            .map(|address| (address.clone(), 0))
            .collect::<BTreeMap<_, _>>();
        accepted_invitation_epochs.insert(local_address, private_control.epoch);
        let conversation = LocalMlsConversationRecord {
            request,
            status: LocalMlsConversationStatus::Active,
            server_genesis_hash: Some(server_genesis_hash),
            recovery_digest: None,
            last_finalized_height: private_control.height,
            last_finalized_epoch: private_control.epoch,
            last_block_hash,
            current_roster: private_control.roster.clone(),
            member_joined_epochs,
            accepted_invitation_epochs,
            current_authority_set: private_control.authority_set.clone(),
            current_owner_set: private_control.owner_set.clone(),
            genesis_authorization_policy: private_control.genesis_authorization_policy.clone(),
            genesis_cryptographic_policy: private_control.genesis_cryptographic_policy.clone(),
            current_authorization_policy: private_control.authorization_policy.clone(),
            current_cryptographic_policy: private_control.cryptographic_policy.clone(),
        };
        let receipt = ProcessedMlsControlEnvelope {
            envelope_id: envelope.envelope_id,
            cursor: envelope.cursor.clone(),
            send_id: envelope.send_id,
            conversation_id: private_control.conversation_id,
            incarnation: private_control.incarnation,
            height: private_control.height,
            epoch: private_control.epoch,
            block_hash: conversation
                .last_block_hash
                .clone()
                .expect("group Welcome has a finalized adding block"),
        };
        let group = staged
            .into_group(&provider)
            .map_err(|error| mls_error("join MLS group", error))?;
        ensure_v1_group(&group)?;
        ensure_exact_private_control_state(group.extensions(), &private_control)?;
        insert_new_group_control_key(&mut metadata, expected_group_id)?;
        metadata
            .conversations
            .insert(conversation_key, conversation.clone());
        insert_processed_control_envelope(&mut metadata, receipt)?;
        let group = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(JoinedMlsConversation {
            group,
            conversation,
        })
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
        let private_control_state =
            extract_private_control_state(staged.group_context().extensions())?;
        if private_control_state.epoch != staged.group_context().epoch().as_u64() {
            return Err(ChatError::Trust(
                "MLS Welcome private control epoch differs from its GroupContext".into(),
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
        verify_private_control_accounts(
            &private_control_state,
            claimed_members
                .iter()
                .map(|member| member.credential_identity.as_str()),
        )?;
        Ok(MlsWelcomeInspection {
            mls_group_id: expected_group_id.to_vec(),
            epoch: staged.group_context().epoch().as_u64(),
            claimed_members,
            private_control_state,
        })
    }

    /// Stage an inbound Commit in an isolated provider snapshot and expose
    /// only MLS-authenticated claims. No secret-tree generation, epoch, cursor,
    /// or durable control pin is changed by inspection.
    pub async fn inspect_inbound_commit(
        &self,
        mls_group_id: &[u8],
        commit_bytes: &[u8],
    ) -> Result<MlsInboundCommitInspection> {
        validate_group_id(mls_group_id)?;
        if commit_bytes.is_empty() || commit_bytes.len() > MAX_APPLICATION_BYTES {
            return Err(ChatError::Invalid("MLS Commit is outside v1 bounds".into()));
        }
        let (provider, metadata) = self.load_provider().await?;
        let group_key = BASE64.encode(mls_group_id);
        if metadata.pending_commits.contains_key(&group_key)
            || metadata.pending_membership_changes.contains_key(&group_key)
            || metadata.pending_authority_changes.contains_key(&group_key)
            || metadata.pending_owner_changes.contains_key(&group_key)
            || metadata.pending_closes.contains_key(&group_key)
            || metadata.pending_policy_changes.contains_key(&group_key)
            || metadata.pending_recoveries.contains_key(&group_key)
        {
            return Err(ChatError::Trust(
                "cannot inspect a remote MLS Commit while a local Commit is pending".into(),
            ));
        }
        let conversation = metadata
            .conversations
            .values()
            .find(|record| record.request.genesis.mls_group_id == group_key)
            .ok_or_else(|| {
                ChatError::Trust("local MLS conversation control state is unavailable".into())
            })?;
        if conversation.status != LocalMlsConversationStatus::Active {
            return Err(ChatError::Trust(
                "inbound MLS Commit targets an inactive conversation".into(),
            ));
        }
        validate_local_control_state(conversation)?;
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
        if !matches!(processed.sender(), Sender::Member(_)) {
            return Err(ChatError::Trust(
                "MLS roster Commit was not sent by a current member".into(),
            ));
        }
        let sender_identity = std::str::from_utf8(processed.credential().serialized_content())
            .map_err(|_| ChatError::Trust("MLS Commit sender identity is not UTF-8".into()))?;
        let (sender_address, _) = parse_device_credential_identity(sender_identity)?;
        if !conversation
            .current_roster
            .iter()
            .any(|member| member.address.canonical() == sender_address && member.is_admin)
        {
            return Err(ChatError::Trust(
                "MLS roster Commit sender is not an administrator in the pinned roster".into(),
            ));
        }
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            _ => return Err(ChatError::Invalid("expected an MLS Commit message".into())),
        };
        let epoch_after = staged.epoch().as_u64();
        if epoch_after != epoch_before.saturating_add(1) {
            return Err(ChatError::Trust(
                "inbound MLS Commit does not advance exactly one epoch".into(),
            ));
        }
        let private_control_state =
            extract_private_control_state(staged.group_context().extensions())?;
        if private_control_state.epoch != epoch_after {
            return Err(ChatError::Trust(
                "inbound MLS private control epoch differs from its Commit".into(),
            ));
        }
        group
            .merge_staged_commit(&provider, *staged)
            .map_err(|error| mls_error("inspect inbound MLS Commit", error))?;
        let mut claimed_members = Vec::new();
        let mut identities = HashSet::new();
        for member in group.members() {
            let identity = std::str::from_utf8(member.credential.serialized_content())
                .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?
                .to_owned();
            validate_credential_identity(&identity)?;
            if !identities.insert(identity.clone()) {
                return Err(ChatError::Trust(
                    "inbound MLS Commit repeats a credential identity".into(),
                ));
            }
            let credential_public_key = member.signature_key.as_slice().to_vec();
            validate_credential_public_key(&credential_public_key)?;
            claimed_members.push(ClaimedMlsCredential {
                credential_identity: identity,
                credential_public_key,
            });
        }
        claimed_members
            .sort_by(|left, right| left.credential_identity.cmp(&right.credential_identity));
        verify_private_control_accounts(
            &private_control_state,
            claimed_members
                .iter()
                .map(|member| member.credential_identity.as_str()),
        )?;
        Ok(MlsInboundCommitInspection {
            mls_group_id: mls_group_id.to_vec(),
            epoch_before,
            epoch_after,
            commit_hash: hex::encode(Sha256::digest(commit_bytes)),
            claimed_members,
            private_control_state,
        })
    }
}
