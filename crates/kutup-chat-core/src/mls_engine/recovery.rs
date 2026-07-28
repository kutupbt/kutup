//! Owner-approved append-only group-incarnation recovery.
//!
//! A recovery creates a fresh OpenMLS GroupId and a single epoch-one Commit
//! that installs the complete preserved account roster. It never asks the old
//! ordering quorum to make progress and never mutates the old public history.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use kutup_chat_proto::{
    MlsIncarnationRecoveryPlanV1, MlsIncarnationRecoveryV1, MlsOwnerApprovalCertificateV1,
    MlsOwnerApprovalV1,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsRecovery {
    /// The active previous-incarnation GroupId used for owner approval.
    pub mls_group_id: Vec<u8>,
    /// The fresh replacement GroupId holding the staged recovery Commit.
    pub new_mls_group_id: Vec<u8>,
    pub request: RecoverMlsConversationRequestV1,
    pub commit_hash: String,
}

impl PendingMlsRecovery {
    pub(super) fn validate_durable(&self) -> Result<()> {
        validate_group_id(&self.mls_group_id)?;
        validate_group_id(&self.new_mls_group_id)?;
        validate_sha256_hex("MLS recovery commit hash", &self.commit_hash)?;
        self.request.validate_shape().map_err(ChatError::Db)?;
        let recovery = &self.request.recovery;
        if BASE64.encode(&self.new_mls_group_id) != recovery.plan.new_genesis.mls_group_id
            || recovery.proposal.payload_digest != self.commit_hash
            || recovery.owner_approval.approvals.is_empty()
            || recovery.owner_approval.proposal_hash
                != recovery.proposal.proposal_hash().map_err(ChatError::Db)?
            || recovery.owner_approval.transition_digest.as_deref()
                != Some(
                    recovery
                        .plan
                        .transition_digest()
                        .map_err(ChatError::Db)?
                        .as_str(),
                )
        {
            return Err(ChatError::Db(
                "durable MLS recovery fields are inconsistent".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedMlsRecovery {
    pub pending: PendingMlsCommit,
    pub control: PendingMlsRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedMlsRecovery {
    pub group: LocalMlsGroupState,
    pub conversation: LocalMlsConversationRecord,
    pub archived_incarnation: LocalMlsConversationRecord,
}

impl MlsClient {
    /// Join a destination-private recovery Welcome after independently binding
    /// every device credential to transparency and verifying the owner-signed
    /// recovery against the exact durable previous-incarnation head.
    pub async fn join_from_recovery_welcome(
        &self,
        envelope: &MlsControlEnvelopeContext,
        expected_group_id: &[u8],
        welcome_bytes: &[u8],
        expected_members: &[VerifiedMlsCredential],
        recovery: &MlsIncarnationRecoveryV1,
    ) -> Result<JoinedMlsConversation> {
        validate_group_id(expected_group_id)?;
        envelope.validate()?;
        recovery.validate_shape().map_err(ChatError::Trust)?;
        if welcome_bytes.is_empty()
            || welcome_bytes.len() > MAX_APPLICATION_BYTES
            || expected_members.is_empty()
            || expected_members.len() > 1000
            || recovery.plan.new_genesis.mls_group_id != BASE64.encode(expected_group_id)
        {
            return Err(ChatError::Invalid(
                "MLS recovery Welcome, roster, or GroupId is outside v1 bounds".into(),
            ));
        }
        let recovery_digest = recovery
            .plan
            .transition_digest()
            .map_err(ChatError::Protocol)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let conversation_key = recovery.plan.conversation_id.to_string();
        if let Some(existing) = metadata.conversations.get(&conversation_key) {
            if existing.request.genesis == recovery.plan.new_genesis {
                let group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(expected_group_id))
                        .map_err(|error| mls_error("load recovered MLS group", error))?
                        .ok_or_else(|| {
                            ChatError::Db(
                                "durable recovered conversation has no OpenMLS group".into(),
                            )
                        })?;
                let receipt = metadata
                    .processed_control_envelopes
                    .get(&envelope.envelope_id.to_string())
                    .ok_or_else(|| {
                        ChatError::Db("recovered MLS group has no mailbox receipt".into())
                    })?;
                if existing.status != LocalMlsConversationStatus::Active
                    || existing.recovery_digest.as_deref() != Some(&recovery_digest)
                    || receipt.send_id != envelope.send_id
                    || receipt.cursor != envelope.cursor
                    || receipt.block_hash != recovery_digest
                {
                    return Err(ChatError::Trust(
                        "existing MLS recovery differs from its signed statement".into(),
                    ));
                }
                ensure_v1_group(&group)?;
                let private = ensure_private_control_matches_record(group.extensions(), existing)?;
                verify_private_control_accounts(
                    &private,
                    expected_members
                        .iter()
                        .map(|member| member.credential_identity.as_str()),
                )?;
                verify_exact_roster(group.members(), expected_members)?;
                return Ok(JoinedMlsConversation {
                    group: local_group_state(&group),
                    conversation: existing.clone(),
                });
            }
        }
        let previous = metadata
            .conversations
            .get(&conversation_key)
            .cloned()
            .ok_or_else(|| ChatError::Trust("previous MLS incarnation is unavailable".into()))?;
        if previous.status != LocalMlsConversationStatus::Active
            || previous.request.genesis.incarnation != recovery.plan.previous_incarnation
            || previous
                .request
                .genesis
                .genesis_hash()
                .map_err(ChatError::Db)?
                != recovery.plan.previous_genesis_hash
            || previous.last_finalized_height != recovery.plan.previous_height
            || previous.last_finalized_epoch != recovery.plan.previous_epoch
            || previous.last_block_hash != recovery.plan.previous_block_hash
            || roster_commitment(&previous.current_roster).map_err(ChatError::Db)?
                != recovery.plan.previous_roster_commitment
            || previous.current_roster.len() as u32 != recovery.plan.new_genesis.member_count
        {
            return Err(ChatError::Trust(
                "MLS recovery does not extend the exact durable previous head".into(),
            ));
        }
        recovery
            .verify(&previous.current_owner_set)
            .map_err(ChatError::Trust)?;
        if metadata.incarnation_history.contains_key(&format!(
            "{}:{:020}",
            recovery.plan.conversation_id, recovery.plan.previous_incarnation
        )) || metadata
            .conversations
            .values()
            .any(|record| record.request.genesis.mls_group_id == BASE64.encode(expected_group_id))
            || metadata.incarnation_history.values().any(|record| {
                record.request.genesis.mls_group_id == BASE64.encode(expected_group_id)
            })
            || metadata
                .group_control_private_keys
                .contains_key(&BASE64.encode(expected_group_id))
            || MlsGroup::load(provider.storage(), &GroupId::from_slice(expected_group_id))
                .map_err(|error| mls_error("load recovery MLS group", error))?
                .is_some()
        {
            return Err(ChatError::Trust(
                "MLS recovery attempts to replace existing durable state".into(),
            ));
        }

        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|error| mls_error("parse recovery MLS Welcome", error))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(ChatError::Invalid(
                    "expected an MLS recovery Welcome".into(),
                ))
            }
        };
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|error| mls_error("stage recovery MLS Welcome", error))?;
        if staged.group_context().group_id().as_slice() != expected_group_id
            || staged.group_context().ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE
            || staged.group_context().epoch().as_u64() != 1
        {
            return Err(ChatError::Trust(
                "MLS recovery Welcome has a different group, suite, or epoch".into(),
            ));
        }
        let private = extract_private_control_state(staged.group_context().extensions())?;
        if private.conversation_id != recovery.plan.conversation_id
            || private.incarnation != recovery.plan.new_genesis.incarnation
            || private.initial_epoch != 1
            || private.height != 0
            || private.epoch != 1
            || private.previous_block_hash.is_some()
            || private.genesis_roster != previous.current_roster
            || private.roster != previous.current_roster
            || roster_commitment(&private.roster).map_err(ChatError::Trust)?
                != recovery.plan.new_genesis.roster_commitment
            || private.genesis_authority_set != recovery.plan.new_genesis.authority_set
            || private.authority_set != recovery.plan.new_genesis.authority_set
            || private.genesis_owner_set != previous.current_owner_set
            || private.owner_set != previous.current_owner_set
        {
            return Err(ChatError::Trust(
                "MLS recovery Welcome private state differs from the signed plan".into(),
            ));
        }
        verify_private_control_accounts(
            &private,
            expected_members
                .iter()
                .map(|member| member.credential_identity.as_str()),
        )?;
        verify_exact_roster(staged.members(), expected_members)?;
        let group = staged
            .into_group(&provider)
            .map_err(|error| mls_error("join recovery MLS group", error))?;
        ensure_v1_group(&group)?;
        ensure_exact_private_control_state(group.extensions(), &private)?;
        let old_group_key = previous.request.genesis.mls_group_id.clone();
        let new_group_key = BASE64.encode(expected_group_id);
        insert_new_group_control_key(&mut metadata, expected_group_id)?;
        if let Some(owner_seed) = metadata
            .group_owner_private_keys
            .get(&old_group_key)
            .cloned()
        {
            metadata
                .group_owner_private_keys
                .insert(new_group_key.clone(), owner_seed);
        }
        let mut archived = previous.clone();
        archived.status = LocalMlsConversationStatus::ReadOnly;
        metadata.incarnation_history.insert(
            format!(
                "{}:{:020}",
                recovery.plan.conversation_id, recovery.plan.previous_incarnation
            ),
            archived,
        );
        let conversation = LocalMlsConversationRecord {
            request: CreateMlsConversationRequestV1 {
                genesis: recovery.plan.new_genesis.clone(),
                members: private.genesis_roster.clone(),
                initial_devices: Vec::new(),
            },
            status: LocalMlsConversationStatus::Active,
            server_genesis_hash: Some(
                recovery
                    .plan
                    .new_genesis
                    .genesis_hash()
                    .map_err(ChatError::Protocol)?,
            ),
            recovery_digest: Some(recovery_digest.clone()),
            last_finalized_height: 0,
            last_finalized_epoch: 1,
            last_block_hash: None,
            current_roster: private.roster,
            current_authority_set: private.authority_set,
            current_owner_set: private.owner_set,
            genesis_authorization_policy: private.genesis_authorization_policy,
            genesis_cryptographic_policy: private.genesis_cryptographic_policy,
            current_authorization_policy: private.authorization_policy,
            current_cryptographic_policy: private.cryptographic_policy,
        };
        metadata
            .conversations
            .insert(conversation_key, conversation.clone());
        metadata.group_control_private_keys.remove(&old_group_key);
        metadata.group_owner_private_keys.remove(&old_group_key);
        metadata
            .group_owner_candidate_private_keys
            .remove(&old_group_key);
        metadata.owner_candidates.remove(&old_group_key);
        metadata.owner_approval_requests.remove(&old_group_key);
        insert_processed_control_envelope(
            &mut metadata,
            ProcessedMlsControlEnvelope {
                envelope_id: envelope.envelope_id,
                cursor: envelope.cursor.clone(),
                send_id: envelope.send_id,
                conversation_id: recovery.plan.conversation_id,
                incarnation: recovery.plan.new_genesis.incarnation,
                height: 0,
                epoch: 1,
                block_hash: recovery_digest,
            },
        )?;
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(JoinedMlsConversation {
            group: public,
            conversation,
        })
    }

    /// Stage one exact replacement incarnation. `additions` must contain a
    /// fresh, transparency-verified KeyPackage for every destination device
    /// except the initiating device, which becomes the fresh group's creator.
    pub async fn prepare_group_recovery(
        &self,
        mls_group_id: &[u8],
        new_mls_group_id: &[u8],
        proposal_id: Uuid,
        authority_policies: &[MlsOrderingServicePolicyV1],
        additions: &[VerifiedMlsKeyPackage],
        created_at_seconds: i64,
    ) -> Result<PreparedMlsRecovery> {
        validate_group_id(mls_group_id)?;
        validate_group_id(new_mls_group_id)?;
        if mls_group_id == new_mls_group_id || proposal_id.is_nil() || created_at_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS recovery requires a fresh GroupId, proposal id, and valid clock".into(),
            ));
        }
        let old_group_key = BASE64.encode(mls_group_id);
        let new_group_key = BASE64.encode(new_mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if let Some(existing) = metadata.pending_recoveries.get(&old_group_key) {
            if existing.request.recovery.plan.proposal_id == proposal_id
                && existing.new_mls_group_id == new_mls_group_id
            {
                let pending = metadata
                    .pending_commits
                    .get(&new_group_key)
                    .ok_or_else(|| {
                        ChatError::Db("durable MLS recovery has no staged Commit".into())
                    })?;
                return Ok(PreparedMlsRecovery {
                    pending: pending.clone(),
                    control: existing.clone(),
                });
            }
            return Err(ChatError::Trust(
                "another MLS incarnation recovery is already pending".into(),
            ));
        }
        if metadata.pending_commits.contains_key(&old_group_key)
            || metadata
                .pending_membership_changes
                .contains_key(&old_group_key)
            || metadata
                .pending_authority_changes
                .contains_key(&old_group_key)
            || metadata.pending_owner_changes.contains_key(&old_group_key)
            || metadata.pending_closes.contains_key(&old_group_key)
            || metadata.pending_policy_changes.contains_key(&old_group_key)
        {
            return Err(ChatError::Trust(
                "another MLS control operation is already pending".into(),
            ));
        }
        if metadata.pending_commits.contains_key(&new_group_key)
            || metadata
                .group_control_private_keys
                .contains_key(&new_group_key)
            || metadata
                .group_owner_private_keys
                .contains_key(&new_group_key)
            || metadata
                .conversations
                .values()
                .chain(metadata.incarnation_history.values())
                .any(|record| record.request.genesis.mls_group_id == new_group_key)
            || MlsGroup::load(provider.storage(), &GroupId::from_slice(new_mls_group_id))
                .map_err(|error| mls_error("load replacement MLS group", error))?
                .is_some()
        {
            return Err(ChatError::Trust(
                "replacement MLS GroupId is already durably bound".into(),
            ));
        }

        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        let old_group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load previous MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("previous MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&old_group)?;
        if old_group.epoch().as_u64() != conversation.last_finalized_epoch {
            return Err(ChatError::Trust(
                "previous OpenMLS epoch differs from the pinned control head".into(),
            ));
        }
        ensure_private_control_matches_record(old_group.extensions(), &conversation)?;
        let (creator_address, creator_device_id) =
            parse_device_credential_identity(&metadata.credential_identity)?;
        let creator: AccountAddress = creator_address
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
        let creator_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address == creator)
            .ok_or_else(|| ChatError::Trust("recovery creator is absent from the roster".into()))?;
        let owner = group_owner_credential(&metadata, mls_group_id)?;
        if creator_member.owner_id.as_deref() != Some(owner.owner_id.as_str())
            || conversation
                .current_owner_set
                .owner(&owner.owner_id)
                .is_none()
        {
            return Err(ChatError::Trust(
                "only a current MLS owner can initiate recovery".into(),
            ));
        }

        let authority_set = authority_set_from_policies(authority_policies)?;
        let permitted_authorities = participant_domains(&conversation.current_roster)?
            .into_iter()
            .chain(
                conversation
                    .current_authority_set
                    .authorities
                    .iter()
                    .map(|authority| authority.domain.clone()),
            )
            .collect::<BTreeSet<_>>();
        if authority_set
            .authorities
            .iter()
            .any(|authority| !permitted_authorities.contains(&authority.domain))
        {
            return Err(ChatError::Trust(
                "V1 recovery authorities must have replicated the previous public history".into(),
            ));
        }

        let mut packaged_identities = BTreeSet::new();
        let mut packaged_accounts = BTreeSet::new();
        for addition in additions {
            let (address, device_id) =
                parse_device_credential_identity(&addition.credential.credential_identity)?;
            if (address == creator_address && device_id == creator_device_id)
                || !conversation
                    .current_roster
                    .iter()
                    .any(|member| member.address.canonical() == address)
                || !packaged_identities.insert(addition.credential.credential_identity.clone())
            {
                return Err(ChatError::Trust(
                    "MLS recovery KeyPackages repeat or name an unpreserved device".into(),
                ));
            }
            packaged_accounts.insert(address);
        }
        if conversation.current_roster.iter().any(|member| {
            member.address != creator && !packaged_accounts.contains(&member.address.canonical())
        }) {
            return Err(ChatError::Invalid(
                "every non-creator recovery account requires a verified KeyPackage".into(),
            ));
        }

        insert_new_group_control_key(&mut metadata, new_mls_group_id)?;
        let old_owner_seed = ensure_group_owner_key(&metadata, mls_group_id)?.to_vec();
        metadata
            .group_owner_private_keys
            .insert(new_group_key.clone(), old_owner_seed);
        let members = conversation.current_roster.clone();
        let new_incarnation = conversation
            .request
            .genesis
            .incarnation
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS incarnation is exhausted".into()))?;
        let new_genesis = MlsConversationGenesisV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: new_incarnation,
            mls_group_id: new_group_key.clone(),
            kind: MlsConversationKindV1::Group,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            roster_commitment: roster_commitment(&members).map_err(ChatError::Invalid)?,
            member_count: members.len() as u32,
            authority_set: authority_set.clone(),
            owner_set: Some(conversation.current_owner_set.clone()),
            initial_epoch: 1,
            created_at: created_at_seconds,
        };
        new_genesis.validate().map_err(ChatError::Invalid)?;
        let mut authorization_policy = conversation.current_authorization_policy.clone();
        authorization_policy.sequence = 1;
        let mut cryptographic_policy = conversation.current_cryptographic_policy.clone();
        cryptographic_policy.sequence = 1;
        let private_control = MlsPrivateControlStateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: new_genesis.conversation_id,
            incarnation: new_incarnation,
            proposal_id: None,
            height: 0,
            initial_epoch: 1,
            epoch: 1,
            previous_block_hash: None,
            genesis_roster: members.clone(),
            genesis_authority_set: authority_set.clone(),
            genesis_owner_set: conversation.current_owner_set.clone(),
            genesis_authorization_policy: authorization_policy.clone(),
            genesis_cryptographic_policy: cryptographic_policy.clone(),
            roster: members.clone(),
            authority_set,
            owner_set: conversation.current_owner_set.clone(),
            authorization_policy,
            cryptographic_policy,
        };
        private_control.validate().map_err(ChatError::Invalid)?;
        let signer = metadata.read_signer(&provider)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(KUTUP_MLS_V1_CIPHERSUITE)
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .capabilities(kutup_mls_capabilities())
            .with_group_context_extensions(private_control_extensions(&private_control)?)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(new_mls_group_id),
            metadata.credential(),
        )
        .map_err(|error| mls_error("create replacement MLS group", error))?;
        ensure_v1_group(&group)?;
        let pending = if additions.is_empty() {
            stage_private_control_update(
                &provider,
                &mut metadata,
                new_mls_group_id,
                &private_control,
            )?
        } else {
            stage_add_members(
                &provider,
                &mut metadata,
                new_mls_group_id,
                additions,
                created_at_seconds,
                Some(&private_control),
            )?
        };
        if pending.epoch_before != 0 || pending.epoch_after != 1 {
            return Err(ChatError::Protocol(
                "replacement MLS Commit did not create epoch one".into(),
            ));
        }

        let domains = participant_domains(&members)?;
        let welcome = pending.welcome.as_ref().map(|bytes| BASE64.encode(bytes));
        let mut envelopes_by_domain = BTreeMap::<String, Vec<MlsMembershipEnvelopeV1>>::new();
        if !additions.is_empty() {
            let welcome = welcome.ok_or_else(|| {
                ChatError::Protocol("replacement MLS Commit omitted its Welcome".into())
            })?;
            for addition in additions {
                let (address, device_id) =
                    parse_device_credential_identity(&addition.credential.credential_identity)?;
                let recipient: AccountAddress =
                    address
                        .parse()
                        .map_err(|error: kutup_chat_proto::AddressError| {
                            ChatError::Trust(error.to_string())
                        })?;
                let destination = recipient.server.clone().ok_or_else(|| {
                    ChatError::Trust("recovery recipient has no federation domain".into())
                })?;
                envelopes_by_domain
                    .entry(destination)
                    .or_default()
                    .push(MlsMembershipEnvelopeV1 {
                        envelope_id: random_uuid(),
                        recipient,
                        device_id,
                        kind: MlsMembershipEnvelopeKindV1::Welcome,
                        opaque_message: welcome.clone(),
                    });
            }
        }
        let mut deliveries = Vec::with_capacity(domains.len());
        for destination in &domains {
            let mut envelopes = envelopes_by_domain.remove(destination).unwrap_or_default();
            envelopes.sort_by_key(|envelope| {
                (
                    envelope.recipient.canonical(),
                    envelope.device_id,
                    u16::from(envelope.kind),
                    envelope.envelope_id,
                )
            });
            let mut local_devices_after = Vec::new();
            if creator.server.as_deref() == Some(destination.as_str()) {
                local_devices_after.push(MlsConversationDeviceV1 {
                    address: creator.clone(),
                    device_id: creator_device_id,
                });
            }
            for addition in additions {
                let (address, device_id) =
                    parse_device_credential_identity(&addition.credential.credential_identity)?;
                let address = address.parse::<AccountAddress>().map_err(
                    |error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()),
                )?;
                if address.server.as_deref() == Some(destination.as_str()) {
                    local_devices_after.push(MlsConversationDeviceV1 { address, device_id });
                }
            }
            local_devices_after
                .sort_by_key(|device| (device.address.canonical(), device.device_id));
            let delivery = MlsMembershipDeliveryV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id: new_genesis.conversation_id,
                incarnation: new_incarnation,
                proposal_id,
                destination: destination.clone(),
                epoch_after: 1,
                next_roster_commitment: new_genesis.roster_commitment.clone(),
                next_participant_domains: domains.clone(),
                local_members_after: members
                    .iter()
                    .filter(|member| member.address.server.as_deref() == Some(destination))
                    .cloned()
                    .collect(),
                local_devices_after,
                envelopes,
            };
            delivery.validate().map_err(ChatError::Protocol)?;
            deliveries.push(delivery);
        }
        let plan = MlsIncarnationRecoveryPlanV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: new_genesis.conversation_id,
            previous_incarnation: conversation.request.genesis.incarnation,
            proposal_id,
            previous_genesis_hash: conversation
                .request
                .genesis
                .genesis_hash()
                .map_err(ChatError::Protocol)?,
            previous_height: conversation.last_finalized_height,
            previous_epoch: conversation.last_finalized_epoch,
            previous_block_hash: conversation.last_block_hash.clone(),
            previous_roster_commitment: new_genesis.roster_commitment.clone(),
            participant_domains: domains,
            new_genesis,
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
        let transition_digest = plan.transition_digest().map_err(ChatError::Protocol)?;
        let proposal = sign_control_proposal_with_metadata(
            &metadata,
            mls_group_id,
            conversation.request.genesis.conversation_id,
            conversation.request.genesis.incarnation,
            proposal_id,
            conversation.last_finalized_epoch,
            MlsControlActionTypeV1::RecoverIncarnation,
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
                Some(&transition_digest),
                &conversation.current_owner_set,
            )
            .map_err(ChatError::Trust)?;
        let recovery = MlsIncarnationRecoveryV1 {
            plan,
            proposal,
            owner_approval,
        };
        let request = RecoverMlsConversationRequestV1 {
            recovery,
            creator,
            creator_device_id,
            members,
            deliveries,
        };
        request.validate_shape().map_err(ChatError::Protocol)?;
        let control = PendingMlsRecovery {
            mls_group_id: mls_group_id.to_vec(),
            new_mls_group_id: new_mls_group_id.to_vec(),
            request,
            commit_hash: pending.commit_hash.clone(),
        };
        validate_pending_recovery(&control, &conversation)?;
        metadata
            .pending_recoveries
            .insert(old_group_key, control.clone());
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(PreparedMlsRecovery { pending, control })
    }

    pub async fn pending_recoveries(&self) -> Result<Vec<PendingMlsRecovery>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata.pending_recoveries.values().cloned().collect())
    }

    pub async fn local_incarnation_history(&self) -> Result<Vec<LocalMlsConversationRecord>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata.incarnation_history.values().cloned().collect())
    }

    pub async fn recovery_has_owner_quorum(&self, mls_group_id: &[u8]) -> Result<bool> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        let control = metadata
            .pending_recoveries
            .get(&BASE64.encode(mls_group_id))
            .ok_or_else(|| ChatError::Trust("pending MLS recovery is unavailable".into()))?;
        match control
            .request
            .recovery
            .verify(&conversation.current_owner_set)
        {
            Ok(()) => Ok(true),
            Err(error) if error == "MLS owner certificate does not meet quorum" => Ok(false),
            Err(error) => Err(ChatError::Trust(error)),
        }
    }

    pub async fn finalize_group_recovery(
        &self,
        mls_group_id: &[u8],
        acknowledgement: &RecoverMlsConversationResponseV1,
    ) -> Result<FinalizedMlsRecovery> {
        validate_group_id(mls_group_id)?;
        acknowledgement.validate().map_err(ChatError::Protocol)?;
        let old_group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        let control = metadata
            .pending_recoveries
            .get(&old_group_key)
            .cloned()
            .ok_or_else(|| ChatError::Trust("pending MLS recovery is unavailable".into()))?;
        let plan = &control.request.recovery.plan;
        let recovery_digest = plan.transition_digest().map_err(ChatError::Protocol)?;
        if acknowledgement.conversation_id != plan.conversation_id
            || acknowledgement.previous_incarnation != plan.previous_incarnation
            || acknowledgement.incarnation != plan.new_genesis.incarnation
            || acknowledgement.recovery_digest != recovery_digest
        {
            return Err(ChatError::Trust(
                "server acknowledged a different MLS recovery".into(),
            ));
        }
        let current = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        validate_pending_recovery(&control, &current)?;
        control
            .request
            .recovery
            .verify(&current.current_owner_set)
            .map_err(|_| ChatError::Trust("MLS recovery requires owner quorum".into()))?;
        let new_group_key = BASE64.encode(&control.new_mls_group_id);
        let pending = metadata
            .pending_commits
            .get(&new_group_key)
            .ok_or_else(|| ChatError::Db("replacement MLS Commit is unavailable".into()))?;
        if pending.commit_hash != control.commit_hash
            || pending.epoch_before != 0
            || pending.epoch_after != 1
        {
            return Err(ChatError::Db(
                "replacement MLS Commit differs from its recovery".into(),
            ));
        }
        let mut group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&control.new_mls_group_id),
        )
        .map_err(|error| mls_error("load replacement MLS group", error))?
        .ok_or_else(|| {
            ChatError::MissingKeyMaterial("replacement MLS group is unavailable".into())
        })?;
        if group.epoch().as_u64() != 0 || group.pending_commit().is_none() {
            return Err(ChatError::Trust(
                "replacement OpenMLS pending state differs from recovery".into(),
            ));
        }
        group
            .merge_pending_commit(&provider)
            .map_err(|error| mls_error("merge replacement MLS Commit", error))?;
        let private_control = extract_private_control_state(group.extensions())?;
        if group.epoch().as_u64() != 1
            || private_control.conversation_id != plan.conversation_id
            || private_control.incarnation != plan.new_genesis.incarnation
            || private_control.initial_epoch != 1
            || private_control.height != 0
            || private_control.epoch != 1
            || private_control.genesis_roster != control.request.members
            || private_control.roster != control.request.members
            || private_control.authority_set != plan.new_genesis.authority_set
            || private_control.owner_set != current.current_owner_set
            || private_control.authorization_policy.sequence != 1
            || private_control.authorization_policy.application_senders
                != current.current_authorization_policy.application_senders
            || private_control.cryptographic_policy.sequence != 1
            || private_control
                .cryptographic_policy
                .maximum_application_plaintext_bytes
                != current
                    .current_cryptographic_policy
                    .maximum_application_plaintext_bytes
        {
            return Err(ChatError::Trust(
                "merged replacement MLS private state differs from recovery".into(),
            ));
        }

        let mut archived = current.clone();
        archived.status = LocalMlsConversationStatus::ReadOnly;
        let history_key = format!("{}:{:020}", plan.conversation_id, plan.previous_incarnation);
        if metadata
            .incarnation_history
            .insert(history_key, archived.clone())
            .is_some()
        {
            return Err(ChatError::Trust(
                "previous MLS incarnation is already archived".into(),
            ));
        }
        let conversation = LocalMlsConversationRecord {
            request: CreateMlsConversationRequestV1 {
                genesis: plan.new_genesis.clone(),
                members: control.request.members.clone(),
                initial_devices: Vec::new(),
            },
            status: LocalMlsConversationStatus::Active,
            server_genesis_hash: Some(
                plan.new_genesis
                    .genesis_hash()
                    .map_err(ChatError::Protocol)?,
            ),
            recovery_digest: Some(recovery_digest),
            last_finalized_height: 0,
            last_finalized_epoch: 1,
            last_block_hash: None,
            current_roster: control.request.members.clone(),
            current_authority_set: plan.new_genesis.authority_set.clone(),
            current_owner_set: current.current_owner_set,
            genesis_authorization_policy: private_control.genesis_authorization_policy.clone(),
            genesis_cryptographic_policy: private_control.genesis_cryptographic_policy.clone(),
            current_authorization_policy: private_control.authorization_policy,
            current_cryptographic_policy: private_control.cryptographic_policy,
        };
        metadata
            .conversations
            .insert(plan.conversation_id.to_string(), conversation.clone());
        metadata.pending_commits.remove(&new_group_key);
        metadata.pending_recoveries.remove(&old_group_key);
        metadata.owner_approval_requests.remove(&old_group_key);
        metadata.group_control_private_keys.remove(&old_group_key);
        metadata.group_owner_private_keys.remove(&old_group_key);
        metadata
            .group_owner_candidate_private_keys
            .remove(&old_group_key);
        metadata.owner_candidates.remove(&old_group_key);
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await?;
        Ok(FinalizedMlsRecovery {
            group: public,
            conversation,
            archived_incarnation: archived,
        })
    }
}

pub(super) fn validate_pending_recovery(
    control: &PendingMlsRecovery,
    previous: &LocalMlsConversationRecord,
) -> Result<()> {
    control.validate_durable()?;
    let recovery = &control.request.recovery;
    let plan = &recovery.plan;
    if previous.status != LocalMlsConversationStatus::Active
        || plan.conversation_id != previous.request.genesis.conversation_id
        || plan.previous_incarnation != previous.request.genesis.incarnation
        || plan.previous_genesis_hash
            != previous
                .request
                .genesis
                .genesis_hash()
                .map_err(ChatError::Db)?
        || plan.previous_height != previous.last_finalized_height
        || plan.previous_epoch != previous.last_finalized_epoch
        || plan.previous_block_hash != previous.last_block_hash
        || plan.previous_roster_commitment
            != roster_commitment(&previous.current_roster).map_err(ChatError::Db)?
        || control.request.members != previous.current_roster
        || plan.new_genesis.owner_set.as_ref() != Some(&previous.current_owner_set)
    {
        return Err(ChatError::Trust(
            "MLS recovery does not extend the exact previous incarnation".into(),
        ));
    }
    recovery
        .owner_approval
        .verify_partial(
            &recovery.proposal,
            Some(&plan.transition_digest().map_err(ChatError::Db)?),
            &previous.current_owner_set,
        )
        .map_err(ChatError::Trust)
}
