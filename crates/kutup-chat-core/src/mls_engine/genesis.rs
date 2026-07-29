//! Durable group genesis creation, publication, and local discovery.

use super::*;

impl MlsClient {
    /// Atomically create an epoch-zero group, its unlinkable owner credential,
    /// and the exact authenticated request that must be retried at the server.
    /// An OpenMLS group without the matching durable genesis record is treated
    /// as corruption and is never repaired by silently minting new metadata.
    pub async fn prepare_group_genesis(
        &self,
        conversation_id: Uuid,
        mls_group_id: &[u8],
        creator: AccountAddress,
        authority_policies: &[MlsOrderingServicePolicyV1],
        created_at_seconds: i64,
    ) -> Result<PreparedMlsGroupGenesis> {
        if conversation_id.is_nil() || created_at_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS group genesis requires a conversation id and valid clock".into(),
            ));
        }
        validate_group_id(mls_group_id)?;
        let authority_set = authority_set_from_policies(authority_policies)?;
        let group_key = BASE64.encode(mls_group_id);
        let conversation_key = conversation_id.to_string();
        let (provider, mut metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);

        if let Some(existing) = metadata.conversations.get(&conversation_key) {
            let group = MlsGroup::load(provider.storage(), &group_id)
                .map_err(|error| mls_error("load MLS group", error))?
                .ok_or_else(|| {
                    ChatError::Db("durable MLS genesis record has no matching OpenMLS group".into())
                })?;
            ensure_v1_group(&group)?;
            ensure_group_control_key(&metadata, mls_group_id)?;
            ensure_group_owner_key(&metadata, mls_group_id)?;
            ensure_private_control_matches_record(group.extensions(), existing)?;
            if existing.request.genesis.mls_group_id != group_key
                || existing.request.genesis.created_at != created_at_seconds
                || existing.request.genesis.authority_set != authority_set
                || existing.request.members.len() != 1
                || existing.request.members[0].address != creator
            {
                return Err(ChatError::Trust(
                    "MLS conversation id is already bound to a different genesis".into(),
                ));
            }
            return Ok(PreparedMlsGroupGenesis {
                group: local_group_state(&group),
                conversation: existing.clone(),
            });
        }
        if metadata
            .conversations
            .values()
            .any(|record| record.request.genesis.mls_group_id == group_key)
        {
            return Err(ChatError::Trust(
                "MLS GroupId is already bound to another conversation".into(),
            ));
        }
        if MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .is_some()
            || metadata.group_control_private_keys.contains_key(&group_key)
            || metadata.group_owner_private_keys.contains_key(&group_key)
        {
            return Err(ChatError::Trust(
                "OpenMLS group exists without an exact durable genesis record".into(),
            ));
        }

        insert_new_group_control_key(&mut metadata, mls_group_id)?;
        let owner = insert_new_group_owner_key(&mut metadata, mls_group_id)?;
        let member = MlsConversationMemberV1 {
            address: creator.clone(),
            is_admin: true,
            owner_id: Some(owner.owner_id.clone()),
        };
        let members = vec![member];
        let request = CreateMlsConversationRequestV1 {
            genesis: MlsConversationGenesisV1 {
                protocol_version: MLS_PROTOCOL_VERSION,
                conversation_id,
                incarnation: 1,
                mls_group_id: group_key,
                kind: MlsConversationKindV1::Group,
                suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
                roster_commitment: roster_commitment(&members).map_err(ChatError::Invalid)?,
                member_count: 1,
                authority_set,
                owner_set: Some(MlsOwnerSetV1 {
                    sequence: 1,
                    owners: vec![MlsOwnerV1 {
                        owner_id: owner.owner_id,
                        public_key: BASE64.encode(owner.public_key),
                    }],
                    required_quorum: 1,
                }),
                initial_epoch: 0,
                created_at: created_at_seconds,
            },
            members,
            initial_devices: vec![MlsConversationDeviceV1 {
                address: creator,
                device_id: parse_device_credential_identity(&metadata.credential_identity)?.1,
            }],
        };
        request.validate().map_err(ChatError::Invalid)?;
        let current_owner_set = request.genesis.owner_set.clone().ok_or_else(|| {
            ChatError::Protocol("validated group genesis has no owner set".into())
        })?;
        let conversation = LocalMlsConversationRecord {
            last_finalized_height: 0,
            last_finalized_epoch: request.genesis.initial_epoch,
            last_block_hash: None,
            current_roster: request.members.clone(),
            member_joined_epochs: request
                .members
                .iter()
                .map(|member| (member.address.canonical(), request.genesis.initial_epoch))
                .collect(),
            accepted_invitation_epochs: request
                .members
                .iter()
                .map(|member| (member.address.canonical(), request.genesis.initial_epoch))
                .collect(),
            current_authority_set: request.genesis.authority_set.clone(),
            current_owner_set,
            genesis_authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
            genesis_cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
            current_authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
            current_cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
            request,
            status: LocalMlsConversationStatus::PendingGenesis,
            server_genesis_hash: None,
            recovery_digest: None,
        };
        let private_control_state = genesis_private_control_state(&conversation)?;
        let signer = metadata.read_signer(&provider)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(KUTUP_MLS_V1_CIPHERSUITE)
            .max_past_epochs(KUTUP_MLS_V1_MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .capabilities(kutup_mls_capabilities())
            .with_group_context_extensions(private_control_extensions(&private_control_state)?)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            group_id,
            metadata.credential(),
        )
        .map_err(|error| mls_error("create MLS group", error))?;
        ensure_v1_group(&group)?;
        ensure_exact_private_control_state(group.extensions(), &private_control_state)?;
        metadata
            .conversations
            .insert(conversation_key, conversation.clone());
        let public = local_group_state(&group);
        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(PreparedMlsGroupGenesis {
            group: public,
            conversation,
        })
    }

    /// Return every exact local conversation record in canonical UUID order.
    pub async fn local_conversations(&self) -> Result<Vec<LocalMlsConversationRecord>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata.conversations.values().cloned().collect())
    }

    /// Mark one pending genesis active only after the server acknowledges the
    /// exact canonical genesis digest. Replays with the same digest are
    /// idempotent; a different digest is a durable trust failure.
    pub async fn mark_group_genesis_published(
        &self,
        conversation_id: Uuid,
        server_genesis_hash: &str,
    ) -> Result<LocalMlsConversationRecord> {
        if conversation_id.is_nil() {
            return Err(ChatError::Invalid(
                "MLS conversation id must not be nil".into(),
            ));
        }
        validate_sha256_hex("MLS genesis hash", server_genesis_hash)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let record = metadata
            .conversations
            .get_mut(&conversation_id.to_string())
            .ok_or_else(|| ChatError::Trust("local MLS genesis record is unavailable".into()))?;
        let expected_hash = record
            .request
            .genesis
            .genesis_hash()
            .map_err(ChatError::Protocol)?;
        if expected_hash != server_genesis_hash {
            return Err(ChatError::Trust(
                "server acknowledged a different MLS genesis".into(),
            ));
        }
        if let Some(existing) = &record.server_genesis_hash {
            if existing != server_genesis_hash
                || record.status != LocalMlsConversationStatus::Active
            {
                return Err(ChatError::Db(
                    "durable MLS genesis acknowledgement is inconsistent".into(),
                ));
            }
            return Ok(record.clone());
        }
        record.status = LocalMlsConversationStatus::Active;
        record.server_genesis_hash = Some(server_genesis_hash.to_owned());
        // The exact initial device set is needed only while retrying the local
        // server creation transaction. It is destination-private and must not
        // make the durable logical conversation differ from a member that
        // reconstructs the same authenticated genesis from Welcome history.
        record.request.initial_devices.clear();
        let result = record.clone();
        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(result)
    }

    /// Return the public group-scoped owner credential without exposing its
    /// signing seed.
    pub async fn group_owner_credential(
        &self,
        mls_group_id: &[u8],
    ) -> Result<MlsGroupOwnerCredential> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        group_owner_credential(&metadata, mls_group_id)
    }

    /// Create an epoch-zero group using the authenticated genesis `GroupId`.
    /// Existing group state is returned idempotently and is never overwritten.
    #[cfg(test)]
    pub(crate) async fn create_group(&self, mls_group_id: &[u8]) -> Result<LocalMlsGroupState> {
        validate_group_id(mls_group_id)?;
        let (provider, mut metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        if let Some(group) = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
        {
            ensure_v1_group(&group)?;
            ensure_group_control_key(&metadata, mls_group_id)?;
            return Ok(local_group_state(&group));
        }

        let owner_signer = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let owner_public = owner_signer.verifying_key().as_bytes().to_vec();
        let owner = MlsGroupOwnerCredential {
            owner_id: hex::encode(Sha256::digest(&owner_public)),
            public_key: owner_public,
        };
        let (account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let address: AccountAddress =
            account
                .parse()
                .map_err(|error: kutup_chat_proto::AddressError| {
                    ChatError::Invalid(error.to_string())
                })?;
        let authority_signer = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let authority_public = authority_signer.verifying_key().as_bytes().to_vec();
        let private_control = MlsPrivateControlStateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: random_uuid(),
            incarnation: 1,
            proposal_id: None,
            height: 0,
            initial_epoch: 0,
            epoch: 0,
            previous_block_hash: None,
            genesis_roster: vec![MlsConversationMemberV1 {
                address: address.clone(),
                is_admin: true,
                owner_id: Some(owner.owner_id.clone()),
            }],
            genesis_authority_set: MlsAuthoritySetV1 {
                sequence: 1,
                authorities: vec![MlsAuthorityV1 {
                    domain: "example.test".into(),
                    key_id: hex::encode(Sha256::digest(&authority_public)),
                    public_key: BASE64.encode(&authority_public),
                }],
                required_quorum: 1,
            },
            genesis_owner_set: MlsOwnerSetV1 {
                sequence: 1,
                owners: vec![MlsOwnerV1 {
                    owner_id: owner.owner_id.clone(),
                    public_key: BASE64.encode(&owner.public_key),
                }],
                required_quorum: 1,
            },
            genesis_authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
            genesis_cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
            roster: vec![MlsConversationMemberV1 {
                address,
                is_admin: true,
                owner_id: Some(owner.owner_id.clone()),
            }],
            authority_set: MlsAuthoritySetV1 {
                sequence: 1,
                authorities: vec![MlsAuthorityV1 {
                    domain: "example.test".into(),
                    key_id: hex::encode(Sha256::digest(&authority_public)),
                    public_key: BASE64.encode(authority_public),
                }],
                required_quorum: 1,
            },
            owner_set: MlsOwnerSetV1 {
                sequence: 1,
                owners: vec![MlsOwnerV1 {
                    owner_id: owner.owner_id,
                    public_key: BASE64.encode(owner.public_key),
                }],
                required_quorum: 1,
            },
            authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
            cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
        };
        private_control.validate().map_err(ChatError::Protocol)?;
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
            group_id,
            metadata.credential(),
        )
        .map_err(|error| mls_error("create MLS group", error))?;
        ensure_v1_group(&group)?;
        let public = local_group_state(&group);
        insert_new_group_control_key(&mut metadata, mls_group_id)?;
        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(public)
    }

    /// Return an existing group's public state without creating or replacing
    /// it. Browser orchestration uses this to resume the server half of an
    /// invitation acceptance after a crash or network failure.
    pub async fn group_state(&self, mls_group_id: &[u8]) -> Result<Option<LocalMlsGroupState>> {
        validate_group_id(mls_group_id)?;
        let (provider, metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        let Some(group) = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
        else {
            return Ok(None);
        };
        ensure_v1_group(&group)?;
        ensure_group_control_key(&metadata, mls_group_id)?;
        Ok(Some(local_group_state(&group)))
    }
}
