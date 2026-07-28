//! Linked-device MLS leaf discovery and ordered reconciliation.
//!
//! A linked device is always a distinct manifest-bound MLS leaf. This module
//! never exports or clones another device's OpenMLS snapshot.

use super::*;

impl MlsClient {
    /// Return the exact account/device identities currently represented by
    /// leaves in one local group. The result is sorted and contains no key
    /// material.
    pub async fn group_devices(&self, mls_group_id: &[u8]) -> Result<Vec<MlsConversationDeviceV1>> {
        validate_group_id(mls_group_id)?;
        let (provider, _) = self.load_provider().await?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let mut devices = group
            .members()
            .map(|member| {
                let identity = std::str::from_utf8(member.credential.serialized_content())
                    .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?;
                let (address, device_id) = parse_device_credential_identity(identity)?;
                let address =
                    address
                        .parse()
                        .map_err(|error: kutup_chat_proto::AddressError| {
                            ChatError::Trust(error.to_string())
                        })?;
                Ok(MlsConversationDeviceV1 { address, device_id })
            })
            .collect::<Result<Vec<_>>>()?;
        devices.sort_by_key(|device| (device.address.canonical(), device.device_id));
        Ok(devices)
    }

    /// Stage one unchanged-account-roster Commit that adds and/or removes only
    /// this account's manifest-bound device leaves.
    pub async fn prepare_device_sync(
        &self,
        mls_group_id: &[u8],
        proposal_id: Uuid,
        additions: &[VerifiedMlsKeyPackage],
        removed_device_ids: &[u32],
        created_at_seconds: i64,
    ) -> Result<PreparedMlsMembershipChange> {
        validate_group_id(mls_group_id)?;
        if proposal_id.is_nil()
            || created_at_seconds < 0
            || additions.len() + removed_device_ids.len() > 127
            || (additions.is_empty() && removed_device_ids.is_empty())
        {
            return Err(ChatError::Invalid(
                "MLS device synchronization requires bounded changes, a proposal id, and valid clock"
                    .into(),
            ));
        }
        if removed_device_ids
            .iter()
            .any(|device_id| !(1..=127).contains(device_id))
            || removed_device_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ChatError::Invalid(
                "removed MLS device ids must be sorted, unique, and within 1-127".into(),
            ));
        }

        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if let Some(existing) = metadata.pending_membership_changes.get(&group_key) {
            if existing.transition.proposal_id == proposal_id
                && existing.vote_request.block.proposal.action_type
                    == MlsControlActionTypeV1::DeviceSync
            {
                let pending = metadata
                    .pending_commits
                    .get(&group_key)
                    .ok_or_else(|| {
                        ChatError::Db("durable MLS device sync has no pending Commit".into())
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
                "MLS devices cannot synchronize outside an active incarnation".into(),
            ));
        }
        validate_local_control_state(&conversation)?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
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
                    .map_err(|_| ChatError::Trust("MLS credential identity is not UTF-8".into()))?
                    .to_owned();
                let (address, device_id) = parse_device_credential_identity(&identity)?;
                Ok((address, device_id, identity))
            })
            .collect::<Result<Vec<_>>>()?;
        let (local_address, local_device_id) =
            parse_device_credential_identity(&metadata.credential_identity)?;
        if !conversation
            .current_roster
            .iter()
            .any(|member| member.address.canonical() == local_address)
        {
            return Err(ChatError::Trust(
                "MLS device synchronization requires a current account member".into(),
            ));
        }
        if removed_device_ids.binary_search(&local_device_id).is_ok() {
            return Err(ChatError::Trust(
                "an MLS device cannot remove its own active leaf".into(),
            ));
        }
        let current_local_ids = current_devices
            .iter()
            .filter_map(|(address, device_id, _)| (address == &local_address).then_some(*device_id))
            .collect::<BTreeSet<_>>();
        if removed_device_ids
            .iter()
            .any(|device_id| !current_local_ids.contains(device_id))
        {
            return Err(ChatError::Trust(
                "MLS device synchronization removes an absent local leaf".into(),
            ));
        }
        let mut added_ids = BTreeSet::new();
        for addition in additions {
            let (address, device_id) =
                parse_device_credential_identity(&addition.credential.credential_identity)?;
            if address != local_address
                || addition.wire.device_id != device_id
                || current_local_ids.contains(&device_id)
                || !added_ids.insert(device_id)
            {
                return Err(ChatError::Trust(
                    "MLS device synchronization may add only new leaves for the local account"
                        .into(),
                ));
            }
        }
        let remaining = current_local_ids
            .len()
            .saturating_sub(removed_device_ids.len())
            .saturating_add(added_ids.len());
        if remaining == 0 || remaining > 127 {
            return Err(ChatError::Trust(
                "MLS device synchronization must retain 1-127 local leaves".into(),
            ));
        }
        let removed_identities = removed_device_ids
            .iter()
            .map(|device_id| format!("{local_address}#{device_id}"))
            .collect::<Vec<_>>();
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
            roster: conversation.current_roster.clone(),
            authority_set: conversation.current_authority_set.clone(),
            owner_set: conversation.current_owner_set.clone(),
            authorization_policy: conversation.current_authorization_policy.clone(),
            cryptographic_policy: conversation.current_cryptographic_policy.clone(),
        };
        next_private_control
            .validate()
            .map_err(ChatError::Invalid)?;
        let pending = stage_device_sync(
            &provider,
            &mut metadata,
            mls_group_id,
            additions,
            &removed_identities,
            created_at_seconds,
            &next_private_control,
        )?;
        let control = build_pending_membership_change(
            &metadata,
            &conversation,
            mls_group_id,
            proposal_id,
            &conversation.current_roster,
            additions,
            &removed_identities,
            &current_devices,
            &pending,
            MlsControlActionTypeV1::DeviceSync,
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
}
