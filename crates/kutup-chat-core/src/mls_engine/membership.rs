//! OpenMLS member-add/remove staging and durable control-plane construction.

use super::*;

pub(super) fn stage_add_members(
    provider: &KutupMlsProvider,
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    additions: &[VerifiedMlsKeyPackage],
    now_seconds: i64,
    private_control: Option<&MlsPrivateControlStateV1>,
) -> Result<PendingMlsCommit> {
    validate_group_id(mls_group_id)?;
    if additions.is_empty() || additions.len() > MAX_MLS_GROUP_LEAVES || now_seconds < 0 {
        return Err(ChatError::Invalid(format!(
            "MLS member addition requires 1-{MAX_MLS_GROUP_LEAVES} KeyPackages and a valid clock"
        )));
    }
    let pending_key = BASE64.encode(mls_group_id);
    if metadata.pending_commits.contains_key(&pending_key) {
        return Err(ChatError::Trust(
            "another MLS membership Commit is already pending".into(),
        ));
    }
    let group_id = GroupId::from_slice(mls_group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| mls_error("load MLS group", error))?
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
    ensure_v1_group(&group)?;
    if group.pending_commit().is_some() {
        return Err(ChatError::Trust(
            "OpenMLS has a pending commit without matching durable retry material".into(),
        ));
    }
    let existing_identities = group
        .members()
        .map(|member| member.credential.serialized_content().to_vec())
        .collect::<HashSet<_>>();
    let mut new_identities = HashSet::with_capacity(additions.len());
    let mut key_packages = Vec::with_capacity(additions.len());
    for addition in additions {
        addition
            .wire
            .validate(now_seconds)
            .map_err(ChatError::Invalid)?;
        let identity = addition.credential.credential_identity.as_bytes().to_vec();
        if existing_identities.contains(&identity) || !new_identities.insert(identity) {
            return Err(ChatError::Trust(
                "MLS member addition repeats an existing credential identity".into(),
            ));
        }
        key_packages.push(parse_verified_key_package(provider, addition, now_seconds)?);
    }
    let epoch_before = group.epoch().as_u64();
    let signer = signer_for_group(provider, &group)?;
    let builder = group
        .commit_builder()
        .propose_adds(key_packages)
        .force_self_update(true);
    let builder = if let Some(private_control) = private_control {
        builder
            .propose_group_context_extensions(private_control_extensions(private_control)?)
            .map_err(|error| mls_error("add MLS private control proposal", error))?
    } else {
        builder
    };
    let bundle = builder
        .load_psks(provider.storage())
        .map_err(|error| mls_error("load MLS add-member PSKs", error))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|error| mls_error("build MLS add-members commit", error))?
        .stage_commit(provider)
        .map_err(|error| mls_error("stage MLS add-members commit", error))?;
    let welcome = bundle
        .to_welcome_msg()
        .ok_or_else(|| ChatError::Protocol("MLS add-members Commit omitted Welcome".into()))?;
    let (commit, _, _) = bundle.into_contents();
    let epoch_after = group
        .pending_commit()
        .ok_or_else(|| ChatError::Protocol("OpenMLS did not stage the membership commit".into()))?
        .epoch()
        .as_u64();
    if epoch_after != epoch_before.saturating_add(1) {
        return Err(ChatError::Protocol(
            "MLS membership commit did not advance exactly one epoch".into(),
        ));
    }
    let commit = commit
        .to_bytes()
        .map_err(|error| mls_error("serialize MLS membership commit", error))?;
    let welcome = Some(
        welcome
            .to_bytes()
            .map_err(|error| mls_error("serialize MLS Welcome", error))?,
    );
    let pending = PendingMlsCommit {
        mls_group_id: mls_group_id.to_vec(),
        epoch_before,
        epoch_after,
        commit_hash: hex::encode(Sha256::digest(&commit)),
        commit,
        welcome,
    };
    validate_pending_commit(&pending)?;
    metadata
        .pending_commits
        .insert(pending_key, pending.clone());
    Ok(pending)
}

pub(super) fn stage_remove_members(
    provider: &KutupMlsProvider,
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    removed_credential_identities: &[String],
    private_control: Option<&MlsPrivateControlStateV1>,
) -> Result<PendingMlsCommit> {
    validate_group_id(mls_group_id)?;
    if removed_credential_identities.is_empty()
        || removed_credential_identities.len() > MAX_MLS_GROUP_LEAVES
    {
        return Err(ChatError::Invalid(format!(
            "MLS member removal requires 1-{MAX_MLS_GROUP_LEAVES} credential identities"
        )));
    }
    let pending_key = BASE64.encode(mls_group_id);
    if metadata.pending_commits.contains_key(&pending_key) {
        return Err(ChatError::Trust(
            "another MLS membership Commit is already pending".into(),
        ));
    }
    let group_id = GroupId::from_slice(mls_group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| mls_error("load MLS group", error))?
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
    ensure_v1_group(&group)?;
    if group.pending_commit().is_some() {
        return Err(ChatError::Trust(
            "OpenMLS has a pending commit without matching durable retry material".into(),
        ));
    }
    let mut requested = HashSet::with_capacity(removed_credential_identities.len());
    for identity in removed_credential_identities {
        validate_credential_identity(identity)?;
        if !requested.insert(identity.as_bytes().to_vec()) {
            return Err(ChatError::Invalid(
                "MLS member removal repeats a credential identity".into(),
            ));
        }
    }
    let targets = group
        .members()
        .filter_map(|member| {
            requested
                .contains(member.credential.serialized_content())
                .then_some(member.index)
        })
        .collect::<Vec<_>>();
    if targets.len() != requested.len() {
        return Err(ChatError::Trust(
            "MLS member removal names a credential absent from the current roster".into(),
        ));
    }
    let epoch_before = group.epoch().as_u64();
    let signer = signer_for_group(provider, &group)?;
    let builder = group.commit_builder().propose_removals(targets);
    let builder = if let Some(private_control) = private_control {
        builder
            .propose_group_context_extensions(private_control_extensions(private_control)?)
            .map_err(|error| mls_error("add MLS private control proposal", error))?
    } else {
        builder
    };
    let bundle = builder
        .load_psks(provider.storage())
        .map_err(|error| mls_error("load MLS remove-member PSKs", error))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|error| mls_error("build MLS remove-members commit", error))?
        .stage_commit(provider)
        .map_err(|error| mls_error("stage MLS remove-members commit", error))?;
    let welcome = bundle.to_welcome_msg();
    let (commit, _, _) = bundle.into_contents();
    let epoch_after = group
        .pending_commit()
        .ok_or_else(|| ChatError::Protocol("OpenMLS did not stage the membership commit".into()))?
        .epoch()
        .as_u64();
    if epoch_after != epoch_before.saturating_add(1) {
        return Err(ChatError::Protocol(
            "MLS membership commit did not advance exactly one epoch".into(),
        ));
    }
    let commit = commit
        .to_bytes()
        .map_err(|error| mls_error("serialize MLS membership commit", error))?;
    let welcome = welcome
        .map(|message| {
            message
                .to_bytes()
                .map_err(|error| mls_error("serialize MLS Welcome", error))
        })
        .transpose()?;
    let pending = PendingMlsCommit {
        mls_group_id: mls_group_id.to_vec(),
        epoch_before,
        epoch_after,
        commit_hash: hex::encode(Sha256::digest(&commit)),
        commit,
        welcome,
    };
    validate_pending_commit(&pending)?;
    metadata
        .pending_commits
        .insert(pending_key, pending.clone());
    Ok(pending)
}

pub(super) fn stage_device_sync(
    provider: &KutupMlsProvider,
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    additions: &[VerifiedMlsKeyPackage],
    removed_credential_identities: &[String],
    now_seconds: i64,
    private_control: &MlsPrivateControlStateV1,
) -> Result<PendingMlsCommit> {
    validate_group_id(mls_group_id)?;
    if (additions.is_empty() && removed_credential_identities.is_empty())
        || additions.len() + removed_credential_identities.len() > MAX_MLS_DEVICES_PER_ACCOUNT * 2
        || now_seconds < 0
    {
        return Err(ChatError::Invalid(
            "MLS device synchronization exceeds the 10-device account limit or has an invalid clock"
                .into(),
        ));
    }
    let pending_key = BASE64.encode(mls_group_id);
    if metadata.pending_commits.contains_key(&pending_key) {
        return Err(ChatError::Trust(
            "another MLS membership Commit is already pending".into(),
        ));
    }
    let group_id = GroupId::from_slice(mls_group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| mls_error("load MLS group", error))?
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
    ensure_v1_group(&group)?;
    if group.pending_commit().is_some() {
        return Err(ChatError::Trust(
            "OpenMLS has a pending commit without matching durable retry material".into(),
        ));
    }

    let existing = group
        .members()
        .map(|member| {
            let identity = std::str::from_utf8(member.credential.serialized_content())
                .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?
                .to_owned();
            Ok((identity, member.index))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut new_identities = HashSet::with_capacity(additions.len());
    let mut key_packages = Vec::with_capacity(additions.len());
    for addition in additions {
        addition
            .wire
            .validate(now_seconds)
            .map_err(ChatError::Invalid)?;
        let identity = addition.credential.credential_identity.clone();
        if existing.contains_key(&identity) || !new_identities.insert(identity) {
            return Err(ChatError::Trust(
                "MLS device synchronization repeats an existing credential".into(),
            ));
        }
        key_packages.push(parse_verified_key_package(provider, addition, now_seconds)?);
    }
    let mut removed = HashSet::with_capacity(removed_credential_identities.len());
    let mut targets = Vec::with_capacity(removed_credential_identities.len());
    for identity in removed_credential_identities {
        validate_credential_identity(identity)?;
        if !removed.insert(identity.clone()) || new_identities.contains(identity) {
            return Err(ChatError::Invalid(
                "MLS device synchronization repeats a leaf change".into(),
            ));
        }
        targets.push(*existing.get(identity).ok_or_else(|| {
            ChatError::Trust("MLS device synchronization removes an absent credential".into())
        })?);
    }

    let epoch_before = group.epoch().as_u64();
    let signer = signer_for_group(provider, &group)?;
    let builder = group
        .commit_builder()
        .propose_removals(targets)
        .propose_adds(key_packages)
        .force_self_update(true)
        .propose_group_context_extensions(private_control_extensions(private_control)?)
        .map_err(|error| mls_error("add MLS private control proposal", error))?;
    let bundle = builder
        .load_psks(provider.storage())
        .map_err(|error| mls_error("load MLS device-sync PSKs", error))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|error| mls_error("build MLS device-sync commit", error))?
        .stage_commit(provider)
        .map_err(|error| mls_error("stage MLS device-sync commit", error))?;
    let welcome = bundle
        .to_welcome_msg()
        .map(|message| {
            message
                .to_bytes()
                .map_err(|error| mls_error("serialize MLS device-sync Welcome", error))
        })
        .transpose()?;
    if additions.is_empty() != welcome.is_none() {
        return Err(ChatError::Protocol(
            "MLS device synchronization produced an inconsistent Welcome".into(),
        ));
    }
    let (commit, _, _) = bundle.into_contents();
    let epoch_after = group
        .pending_commit()
        .ok_or_else(|| ChatError::Protocol("OpenMLS did not stage the device-sync commit".into()))?
        .epoch()
        .as_u64();
    if epoch_after != epoch_before.saturating_add(1) {
        return Err(ChatError::Protocol(
            "MLS device synchronization did not advance exactly one epoch".into(),
        ));
    }
    let commit = commit
        .to_bytes()
        .map_err(|error| mls_error("serialize MLS device-sync commit", error))?;
    let pending = PendingMlsCommit {
        mls_group_id: mls_group_id.to_vec(),
        epoch_before,
        epoch_after,
        commit_hash: hex::encode(Sha256::digest(&commit)),
        commit,
        welcome,
    };
    validate_pending_commit(&pending)?;
    metadata
        .pending_commits
        .insert(pending_key, pending.clone());
    Ok(pending)
}

pub(super) fn stage_private_control_update(
    provider: &KutupMlsProvider,
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    private_control: &MlsPrivateControlStateV1,
) -> Result<PendingMlsCommit> {
    validate_group_id(mls_group_id)?;
    let pending_key = BASE64.encode(mls_group_id);
    if metadata.pending_commits.contains_key(&pending_key) {
        return Err(ChatError::Trust(
            "another MLS roster Commit is already pending".into(),
        ));
    }
    let group_id = GroupId::from_slice(mls_group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| mls_error("load MLS group", error))?
        .ok_or_else(|| ChatError::MissingKeyMaterial("MLS group state is unavailable".into()))?;
    ensure_v1_group(&group)?;
    if group.pending_commit().is_some() {
        return Err(ChatError::Trust(
            "OpenMLS has a pending commit without matching durable retry material".into(),
        ));
    }
    let epoch_before = group.epoch().as_u64();
    let signer = signer_for_group(provider, &group)?;
    let bundle = group
        .commit_builder()
        .force_self_update(true)
        .propose_group_context_extensions(private_control_extensions(private_control)?)
        .map_err(|error| mls_error("add MLS private control proposal", error))?
        .load_psks(provider.storage())
        .map_err(|error| mls_error("load MLS administrator-change PSKs", error))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|error| mls_error("build MLS administrator-change commit", error))?
        .stage_commit(provider)
        .map_err(|error| mls_error("stage MLS administrator-change commit", error))?;
    if bundle.to_welcome_msg().is_some() {
        return Err(ChatError::Protocol(
            "MLS administrator-only Commit unexpectedly produced a Welcome".into(),
        ));
    }
    let (commit, _, _) = bundle.into_contents();
    let epoch_after = group
        .pending_commit()
        .ok_or_else(|| ChatError::Protocol("OpenMLS did not stage the roster commit".into()))?
        .epoch()
        .as_u64();
    if epoch_after != epoch_before.saturating_add(1) {
        return Err(ChatError::Protocol(
            "MLS roster commit did not advance exactly one epoch".into(),
        ));
    }
    let commit = commit
        .to_bytes()
        .map_err(|error| mls_error("serialize MLS administrator-change commit", error))?;
    let pending = PendingMlsCommit {
        mls_group_id: mls_group_id.to_vec(),
        epoch_before,
        epoch_after,
        commit_hash: hex::encode(Sha256::digest(&commit)),
        commit,
        welcome: None,
    };
    validate_pending_commit(&pending)?;
    metadata
        .pending_commits
        .insert(pending_key, pending.clone());
    Ok(pending)
}

pub(super) struct PendingMembershipChangeInput<'a> {
    pub metadata: &'a SnapshotMetadata,
    pub conversation: &'a LocalMlsConversationRecord,
    pub mls_group_id: &'a [u8],
    pub proposal_id: Uuid,
    pub next_roster: &'a [MlsConversationMemberV1],
    pub additions: &'a [VerifiedMlsKeyPackage],
    pub removed_credential_identities: &'a [String],
    pub current_devices: &'a [(String, u32, String)],
    pub pending: &'a PendingMlsCommit,
    pub action_type: MlsControlActionTypeV1,
    pub created_at_seconds: i64,
}

pub(super) fn build_pending_membership_change(
    input: PendingMembershipChangeInput<'_>,
) -> Result<PendingMlsMembershipChange> {
    let PendingMembershipChangeInput {
        metadata,
        conversation,
        mls_group_id,
        proposal_id,
        next_roster,
        additions,
        removed_credential_identities,
        current_devices,
        pending,
        action_type,
        created_at_seconds,
    } = input;
    let next_addresses = next_roster
        .iter()
        .map(|member| member.address.canonical())
        .collect::<BTreeSet<_>>();
    let previous_participant_domains = participant_domains(&conversation.current_roster)?;
    let next_participant_domains = participant_domains(next_roster)?;
    let affected_domains = previous_participant_domains
        .iter()
        .chain(&next_participant_domains)
        .cloned()
        .collect::<BTreeSet<_>>();
    let commit_message = BASE64.encode(&pending.commit);
    let welcome_message = pending
        .welcome
        .as_ref()
        .map(|welcome| BASE64.encode(welcome));
    let local_device = parse_device_credential_identity(&metadata.credential_identity)?;
    let mut envelopes_by_domain = BTreeMap::<String, Vec<MlsMembershipEnvelopeV1>>::new();
    let mut devices_by_domain = BTreeMap::<String, Vec<MlsConversationDeviceV1>>::new();
    for (address, device_id, identity) in current_devices {
        if !next_addresses.contains(address)
            || removed_credential_identities
                .iter()
                .any(|removed| removed == identity)
        {
            continue;
        }
        let recipient: AccountAddress = address
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
        let destination = recipient
            .server
            .clone()
            .ok_or_else(|| ChatError::Trust("MLS member has no federation domain".into()))?;
        devices_by_domain
            .entry(destination.clone())
            .or_default()
            .push(MlsConversationDeviceV1 {
                address: recipient.clone(),
                device_id: *device_id,
            });
        if address == &local_device.0 && device_id == &local_device.1 {
            continue;
        }
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
    if !additions.is_empty() {
        let welcome_message = welcome_message.ok_or_else(|| {
            ChatError::Protocol("MLS add-members operation did not produce a Welcome".into())
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
            let destination = recipient
                .server
                .clone()
                .ok_or_else(|| ChatError::Trust("MLS member has no federation domain".into()))?;
            devices_by_domain
                .entry(destination.clone())
                .or_default()
                .push(MlsConversationDeviceV1 {
                    address: recipient.clone(),
                    device_id,
                });
            envelopes_by_domain
                .entry(destination)
                .or_default()
                .push(MlsMembershipEnvelopeV1 {
                    envelope_id: random_uuid(),
                    recipient,
                    device_id,
                    kind: MlsMembershipEnvelopeKindV1::Welcome,
                    opaque_message: welcome_message.clone(),
                });
        }
    }
    let next_roster_commitment = roster_commitment(next_roster).map_err(ChatError::Invalid)?;
    let mut deliveries = Vec::with_capacity(affected_domains.len());
    for destination in affected_domains {
        let mut local_members_after = next_roster
            .iter()
            .filter(|member| member.address.server.as_deref() == Some(destination.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        local_members_after.sort_by_key(|member| member.address.canonical());
        let mut envelopes = envelopes_by_domain.remove(&destination).unwrap_or_default();
        envelopes.sort_by_key(|envelope| {
            (
                envelope.recipient.canonical(),
                envelope.device_id,
                u16::from(envelope.kind),
                envelope.envelope_id,
            )
        });
        let mut local_devices_after = devices_by_domain.remove(&destination).unwrap_or_default();
        local_devices_after.sort_by_key(|device| (device.address.canonical(), device.device_id));
        let delivery = MlsMembershipDeliveryV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            proposal_id,
            destination,
            epoch_after: pending.epoch_after,
            next_roster_commitment: next_roster_commitment.clone(),
            next_participant_domains: next_participant_domains.clone(),
            local_members_after,
            local_devices_after,
            envelopes,
        };
        delivery.validate().map_err(ChatError::Protocol)?;
        deliveries.push(delivery);
    }
    if !envelopes_by_domain.is_empty() {
        return Err(ChatError::Protocol(
            "MLS membership envelopes target a domain outside the roster transition".into(),
        ));
    }
    if !devices_by_domain.is_empty() {
        return Err(ChatError::Protocol(
            "MLS device snapshot targets a domain outside the roster transition".into(),
        ));
    }
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: conversation.request.genesis.conversation_id,
        incarnation: conversation.request.genesis.incarnation,
        proposal_id,
        previous_roster_commitment: roster_commitment(&conversation.current_roster)
            .map_err(ChatError::Db)?,
        next_roster_commitment,
        previous_member_count: conversation.current_roster.len() as u32,
        next_member_count: next_roster.len() as u32,
        previous_participant_domains,
        next_participant_domains,
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
    let proposal = sign_control_proposal_with_metadata(
        metadata,
        mls_group_id,
        conversation.request.genesis.conversation_id,
        conversation.request.genesis.incarnation,
        proposal_id,
        pending.epoch_before,
        action_type,
        &pending.commit,
        created_at_seconds,
    )?;
    let block = MlsControlBlockV1 {
        conversation_id: conversation.request.genesis.conversation_id,
        incarnation: conversation.request.genesis.incarnation,
        height: conversation.last_finalized_height.saturating_add(1),
        previous_block_hash: conversation.last_block_hash.clone(),
        epoch_before: pending.epoch_before,
        epoch_after: pending.epoch_after,
        proposal,
        transition_digest: Some(
            transition
                .transition_digest()
                .map_err(ChatError::Protocol)?,
        ),
        owner_approval: None,
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
    let control = PendingMlsMembershipChange {
        mls_group_id: mls_group_id.to_vec(),
        next_roster: next_roster.to_vec(),
        deliveries,
        transition,
        vote_request,
        commit_hash: pending.commit_hash.clone(),
        final_request: None,
    };
    validate_pending_membership_change(&control)?;
    Ok(control)
}
