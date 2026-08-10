//! MLS application encryption, authenticated receive, durable outbox, and history.

use super::*;

impl MlsClient {
    /// Open the destination-private HPKE envelope and authenticate enough MLS
    /// framing to discover its group and claimed sender without consuming a
    /// durable secret-tree generation.
    pub async fn inspect_anonymous_application_envelope(
        &self,
        recipient: &AccountAddress,
        send_id: Uuid,
        envelope: &AnonymousMlsDeviceEnvelopeV1,
    ) -> Result<MlsApplicationInspection> {
        let ciphertext = self
            .open_anonymous_envelope(recipient, send_id, envelope)
            .await?;
        self.inspect_application_ciphertext(&ciphertext).await
    }

    pub async fn processed_application_envelope(
        &self,
        envelope_id: Uuid,
    ) -> Result<Option<MlsHistoryMessage>> {
        if envelope_id.is_nil() {
            return Err(ChatError::Invalid(
                "MLS application mailbox envelope id must not be nil".into(),
            ));
        }
        self.db.load_mls_message(&format!("in:{envelope_id}")).await
    }

    /// Commit an anonymous MLS application message, authenticated sender, and
    /// exact mailbox receipt in one encrypted client transaction. HTTP
    /// acknowledgement is safe only after this returns.
    pub async fn apply_anonymous_application_envelope(
        &self,
        context: &MlsApplicationEnvelopeContext,
        recipient: &AccountAddress,
        envelope: &AnonymousMlsDeviceEnvelopeV1,
        expected_sender: &VerifiedMlsCredential,
    ) -> Result<AppliedInboundMlsApplication> {
        let cursor = context.validate()?;
        let envelope_bytes =
            serde_json::to_vec(envelope).map_err(|error| ChatError::Wire(error.to_string()))?;
        let transport_digest: [u8; 32] = Sha256::digest(&envelope_bytes).into();
        let record_id = format!("in:{}", context.envelope_id);
        if let Some(existing) = self.db.load_mls_message(&record_id).await? {
            if existing.record_id != record_id
                || existing.message_id != context.send_id.to_string()
                || existing.outgoing
                || existing.cursor != Some(cursor)
                || existing.transport_digest != transport_digest
                || existing.sender != expected_sender.credential_identity
            {
                return Err(ChatError::Trust(
                    "MLS application mailbox id was replayed with different material".into(),
                ));
            }
            return Ok(AppliedInboundMlsApplication {
                message: existing,
                idempotent: true,
            });
        }

        let ciphertext = self
            .open_anonymous_envelope(recipient, context.send_id, envelope)
            .await?;
        let (provider, mut metadata) = self.load_provider().await?;
        let message = MlsMessageIn::tls_deserialize_exact(&ciphertext)
            .map_err(|error| mls_error("parse MLS application message", error))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Invalid("expected an MLS protocol message".into()))?;
        let mls_group_id = message.group_id().as_slice().to_vec();
        validate_group_id(&mls_group_id)?;
        let group_key = BASE64.encode(&mls_group_id);
        let conversation = active_conversation_for_group(&metadata, &mls_group_id)?.clone();
        let mut group = MlsGroup::load(provider.storage(), message.group_id())
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| mls_error("process MLS application message", error))?;
        let epoch = processed.epoch().as_u64();
        let sender_index = match processed.sender() {
            Sender::Member(index) => *index,
            _ => {
                return Err(ChatError::Trust(
                    "MLS application message was not sent by a group member".into(),
                ))
            }
        };
        let member = group
            .members()
            .find(|member| member.index == sender_index)
            .ok_or_else(|| ChatError::Trust("MLS sender leaf is absent".into()))?;
        verify_member_credential(&member, expected_sender)?;
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            _ => {
                return Err(ChatError::Invalid(
                    "expected an MLS application message".into(),
                ))
            }
        };
        let content: ChatContent = serde_json::from_slice(&plaintext)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        let expected_message_id = context.send_id.to_string();
        if content.v == 0
            || content.v > ChatContent::VERSION
            || content.message_id.as_deref() != Some(expected_message_id.as_str())
            || content.sent_at.is_empty()
            || content.sent_at.len() > 128
        {
            return Err(ChatError::Content(
                "MLS application content has invalid version, id, or clock".into(),
            ));
        }
        let expires_after_seconds = content
            .disappearing_after_seconds()
            .map_err(ChatError::Content)?;
        if content.kind == kutup_chat_proto::content::kind::DISAPPEARING_TIMER
            && content.as_disappearing_timer().is_none()
        {
            return Err(ChatError::Content(
                "MLS disappearing-message timer is invalid".into(),
            ));
        }
        let canonical_content =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        if canonical_content != plaintext {
            return Err(ChatError::Content(
                "MLS application content is not canonically encoded".into(),
            ));
        }
        let group_control = if content.kind == kutup_chat_proto::content::kind::GROUP_CONTROL {
            Some(
                serde_json::from_value::<MlsGroupControlBodyV1>(content.body.clone())
                    .map_err(|error| ChatError::Content(error.to_string()))?,
            )
        } else {
            None
        };
        let (sender, sender_device_id) =
            parse_device_credential_identity(&expected_sender.credential_identity)?;
        if group_control.is_none()
            && plaintext.len()
                > conversation
                    .current_cryptographic_policy
                    .maximum_application_plaintext_bytes as usize
        {
            return Err(ChatError::Trust(
                "MLS application plaintext exceeds the authenticated group policy".into(),
            ));
        }
        let sender_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == sender)
            .ok_or_else(|| {
                ChatError::Trust("MLS application sender is absent from the roster".into())
            })?;
        if group_control.is_none()
            && conversation
                .current_authorization_policy
                .application_senders
                == MlsApplicationSenderPolicyV1::Administrators
            && !sender_member.is_admin
        {
            return Err(ChatError::Trust(
                "MLS application sender is not permitted by group policy".into(),
            ));
        }
        if let Some(control) = group_control {
            match control {
                MlsGroupControlBodyV1::OwnerCandidate { candidate } => {
                    candidate.verify().map_err(ChatError::Trust)?;
                    if candidate.conversation_id != conversation.request.genesis.conversation_id
                        || candidate.incarnation != conversation.request.genesis.incarnation
                        || candidate.account.canonical() != sender
                        || candidate.created_at < conversation.request.genesis.created_at
                        || candidate.created_at
                            > context
                                .server_timestamp
                                .saturating_add(KEY_PACKAGE_CLOCK_SKEW_SECONDS as i64)
                        || !conversation
                            .current_roster
                            .iter()
                            .any(|member| member.address.canonical() == sender)
                    {
                        return Err(ChatError::Trust(
                            "MLS owner candidate differs from its authenticated group sender"
                                .into(),
                        ));
                    }
                    let candidates = metadata
                        .owner_candidates
                        .entry(group_key.clone())
                        .or_default();
                    if candidates
                        .get(&sender)
                        .is_some_and(|existing| existing != &candidate)
                    {
                        return Err(ChatError::Trust(
                            "MLS member attempted silent owner-candidate replacement".into(),
                        ));
                    }
                    candidates.insert(sender.clone(), candidate);
                }
                MlsGroupControlBodyV1::OwnerApprovalRequest { request } => {
                    if request.requested_at
                        > context
                            .server_timestamp
                            .saturating_add(KEY_PACKAGE_CLOCK_SKEW_SECONDS as i64)
                        || context.server_timestamp > request.expires_at
                    {
                        return Err(ChatError::Trust(
                            "MLS owner approval request is not currently valid".into(),
                        ));
                    }
                    owner_approval::record_owner_approval_request(
                        &mut metadata,
                        &mls_group_id,
                        &sender,
                        request,
                    )?;
                }
                MlsGroupControlBodyV1::OwnerApproval { approval } => {
                    if approval.approved_at
                        > context
                            .server_timestamp
                            .saturating_add(KEY_PACKAGE_CLOCK_SKEW_SECONDS as i64)
                    {
                        return Err(ChatError::Trust(
                            "MLS owner approval clock is in the future".into(),
                        ));
                    }
                    owner_approval::record_owner_approval(
                        &mut metadata,
                        &mls_group_id,
                        &sender,
                        approval,
                    )?;
                }
                MlsGroupControlBodyV1::InvitationAccepted { acceptance } => {
                    invitation_acceptance::record_invitation_acceptance(
                        &mut metadata,
                        &mls_group_id,
                        &sender,
                        acceptance,
                        context.server_timestamp,
                    )?;
                }
            }
        }
        // Disappearing messages get a full local viewing window even after a
        // receiver was offline. Preserve the authenticated server timestamp
        // for every other message so this feature does not change ordinary
        // history ordering or display clocks.
        let timestamp_ms = if expires_after_seconds.is_some() {
            crate::clock::unix_millis()
        } else {
            context.server_timestamp.saturating_mul(1_000)
        };
        let history = MlsHistoryMessage {
            record_id: record_id.clone(),
            message_id: expected_message_id,
            conversation_id: *conversation.request.genesis.conversation_id.as_bytes(),
            incarnation: conversation.request.genesis.incarnation,
            mls_group_id,
            epoch,
            sender,
            sender_device_id,
            outgoing: false,
            cursor: Some(cursor),
            transport_digest,
            content: canonical_content,
            timestamp_ms,
            delivered: true,
            deduplicated: false,
        };
        let state = snapshot_provider(&provider, &metadata)?;
        let mut writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        writes.mls_messages.insert(record_id, history.clone());
        self.db.apply(&writes).await?;
        Ok(AppliedInboundMlsApplication {
            message: history,
            idempotent: false,
        })
    }

    async fn inspect_application_ciphertext(
        &self,
        ciphertext: &[u8],
    ) -> Result<MlsApplicationInspection> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_APPLICATION_BYTES {
            return Err(ChatError::Invalid(
                "MLS application ciphertext is outside v1 bounds".into(),
            ));
        }
        let (provider, metadata) = self.load_provider().await?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| mls_error("parse MLS application message", error))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Invalid("expected an MLS protocol message".into()))?;
        let mls_group_id = message.group_id().as_slice().to_vec();
        validate_group_id(&mls_group_id)?;
        let conversation = active_conversation_for_group(&metadata, &mls_group_id)?;
        let mut group = MlsGroup::load(provider.storage(), message.group_id())
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| mls_error("inspect MLS application message", error))?;
        let epoch = processed.epoch().as_u64();
        let sender_index = match processed.sender() {
            Sender::Member(index) => *index,
            _ => {
                return Err(ChatError::Trust(
                    "MLS application message was not sent by a group member".into(),
                ))
            }
        };
        if !matches!(
            processed.content(),
            ProcessedMessageContent::ApplicationMessage(_)
        ) {
            return Err(ChatError::Invalid(
                "expected an MLS application message".into(),
            ));
        }
        let member = group
            .members()
            .find(|member| member.index == sender_index)
            .ok_or_else(|| ChatError::Trust("MLS sender leaf is absent".into()))?;
        let claimed_sender = ClaimedMlsCredential {
            credential_identity: std::str::from_utf8(member.credential.serialized_content())
                .map_err(|_| ChatError::Trust("MLS sender credential is not UTF-8".into()))?
                .to_owned(),
            credential_public_key: member.signature_key.as_slice().to_vec(),
        };
        validate_credential_identity(&claimed_sender.credential_identity)?;
        validate_credential_public_key(&claimed_sender.credential_public_key)?;
        Ok(MlsApplicationInspection {
            mls_group_id,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            epoch,
            claimed_sender,
        })
    }

    /// Decrypt one application message and persist the consumed secret-tree
    /// generation only after the sender's current manifest credential matches
    /// the MLS leaf exactly.
    pub async fn decrypt_application_message(
        &self,
        mls_group_id: &[u8],
        ciphertext: &[u8],
        expected_sender: &VerifiedMlsCredential,
    ) -> Result<DecryptedMlsApplication> {
        validate_group_id(mls_group_id)?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_APPLICATION_BYTES {
            return Err(ChatError::Invalid(
                "MLS application ciphertext is outside v1 bounds".into(),
            ));
        }
        let (provider, metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| mls_error("parse MLS application message", error))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Invalid("expected an MLS protocol message".into()))?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| mls_error("process MLS application message", error))?;
        let epoch = processed.epoch().as_u64();
        let sender_index = match processed.sender() {
            Sender::Member(index) => *index,
            _ => {
                return Err(ChatError::Trust(
                    "MLS application message was not sent by a group member".into(),
                ))
            }
        };
        let member = group
            .members()
            .find(|member| member.index == sender_index)
            .ok_or_else(|| ChatError::Trust("MLS sender leaf is absent".into()))?;
        verify_member_credential(&member, expected_sender)?;
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            _ => {
                return Err(ChatError::Invalid(
                    "expected an MLS application message".into(),
                ))
            }
        };
        if !metadata.conversations.is_empty() {
            let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
            let is_group_control = is_typed_group_control(&plaintext);
            if !is_group_control
                && plaintext.len()
                    > conversation
                        .current_cryptographic_policy
                        .maximum_application_plaintext_bytes as usize
            {
                return Err(ChatError::Trust(
                    "MLS application plaintext exceeds the authenticated group policy".into(),
                ));
            }
            let (sender, _) =
                parse_device_credential_identity(&expected_sender.credential_identity)?;
            let sender_is_admin = conversation
                .current_roster
                .iter()
                .any(|member| member.address.canonical() == sender && member.is_admin);
            if !is_group_control
                && conversation
                    .current_authorization_policy
                    .application_senders
                    == MlsApplicationSenderPolicyV1::Administrators
                && !sender_is_admin
            {
                return Err(ChatError::Trust(
                    "MLS application sender is not permitted by group policy".into(),
                ));
            }
        }
        let state = snapshot_provider(&provider, &metadata)?;
        let writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&writes).await?;
        Ok(DecryptedMlsApplication {
            plaintext,
            epoch,
            sender: expected_sender.clone(),
        })
    }

    /// Return the unlinkable group-scoped credential that members must bind
    /// inside the MLS-encrypted control payload.
    pub async fn group_control_credential(
        &self,
        mls_group_id: &[u8],
    ) -> Result<MlsGroupControlCredential> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        group_control_credential(&metadata, mls_group_id)
    }

    /// Sign the pseudonymous outer authorization for an MLS-encrypted control
    /// payload. The proposal contains no account address or account-wide
    /// device key. Its random group-scoped key is bound inside the encrypted
    /// payload so members retain accountability without giving external
    /// authorities a cross-group correlation handle.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_control_proposal(
        &self,
        mls_group_id: &[u8],
        conversation_id: Uuid,
        incarnation: u64,
        proposal_id: Uuid,
        base_epoch: u64,
        action_type: MlsControlActionTypeV1,
        encrypted_payload: &[u8],
        created_at_seconds: i64,
    ) -> Result<MlsControlProposalV1> {
        validate_group_id(mls_group_id)?;
        if conversation_id.is_nil()
            || proposal_id.is_nil()
            || incarnation == 0
            || encrypted_payload.is_empty()
            || encrypted_payload.len() > MAX_APPLICATION_BYTES
            || created_at_seconds < 0
        {
            return Err(ChatError::Invalid(
                "MLS control proposal has invalid ids, payload, or clock".into(),
            ));
        }
        let (_, metadata) = self.load_provider().await?;
        let key_bytes = ensure_group_control_key(&metadata, mls_group_id)?;
        let seed: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| ChatError::Db("invalid durable MLS group control key".into()))?;
        let signer = Ed25519SigningKey::from_bytes(&seed);
        let public_key = signer.verifying_key();
        let mut proposal = MlsControlProposalV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation,
            proposal_id,
            base_epoch,
            action_type,
            proposer_id: hex::encode(Sha256::digest(public_key.as_bytes())),
            proposer_credential_public_key: BASE64.encode(public_key.as_bytes()),
            encrypted_payload: BASE64.encode(encrypted_payload),
            payload_digest: hex::encode(Sha256::digest(encrypted_payload)),
            created_at: created_at_seconds,
            proposer_signature: String::new(),
        };
        proposal.proposer_signature = BASE64.encode(
            signer
                .sign(&proposal.signing_bytes().map_err(ChatError::Invalid)?)
                .to_bytes(),
        );
        proposal.verify().map_err(ChatError::Protocol)?;
        Ok(proposal)
    }

    /// Encrypt one application message and atomically persist both the
    /// resulting OpenMLS secret-tree state and the exact retry ciphertext.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_application_message(
        &self,
        send_id: &str,
        conversation_id: [u8; 16],
        incarnation: u64,
        mls_group_id: &[u8],
        plaintext: &[u8],
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        self.create_application_message_inner(
            send_id,
            conversation_id,
            incarnation,
            mls_group_id,
            plaintext,
            plaintext,
            Vec::new(),
            created_at_ms,
            None,
        )
        .await
    }

    /// Construct canonical text content, capture the exact authenticated
    /// account roster, consume one OpenMLS generation, and persist all retry
    /// material plus the sender sequence in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_text_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        text: &str,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        self.create_text_reply_application_message(
            send_id,
            conversation_id,
            incarnation,
            mls_group_id,
            sent_at,
            text,
            None,
            created_at_ms,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_text_reply_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        text: &str,
        reply_to: Option<&str>,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        self.create_expiring_text_reply_application_message(
            send_id,
            conversation_id,
            incarnation,
            mls_group_id,
            sent_at,
            text,
            reply_to,
            None,
            created_at_ms,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_expiring_text_reply_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        text: &str,
        reply_to: Option<&str>,
        expires_after_seconds: Option<u32>,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
            || text.is_empty()
            || text.len() > 64 * 1024
        {
            return Err(ChatError::Invalid(
                "MLS text message identifiers or content are invalid".into(),
            ));
        }
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_text().map(|body| body.text) != Some(text.to_owned())
                || content.reply_to.as_deref() != reply_to
                || content
                    .disappearing_after_seconds()
                    .map_err(ChatError::Content)?
                    != expires_after_seconds
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to different text or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS application conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let mut content = ChatContent::text_with_id(send_id, sent_at, seq, text)
            .with_reply_to(reply_to)
            .map_err(ChatError::Invalid)?;
        if let Some(seconds) = expires_after_seconds {
            content = content
                .with_disappearing_after(seconds)
                .map_err(ChatError::Invalid)?;
        }
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_reaction_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        target_message_id: &str,
        emoji: &str,
        active: bool,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS reaction send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
        {
            return Err(ChatError::Invalid(
                "MLS reaction identifiers or clock are invalid".into(),
            ));
        }
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let expected = kutup_chat_proto::ReactionBody {
                target_message_id: target_message_id.to_owned(),
                emoji: emoji.to_owned(),
                active,
            };
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_reaction() != Some(expected)
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to a different reaction or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS reaction conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let content =
            ChatContent::reaction_with_id(send_id, sent_at, seq, target_message_id, emoji, active)
                .map_err(ChatError::Invalid)?;
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_message_mutation_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        target_message_id: &str,
        operation: kutup_chat_proto::MessageMutationOperation,
        replacement_text: Option<String>,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS mutation send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
        {
            return Err(ChatError::Invalid(
                "MLS mutation identifiers or clock are invalid".into(),
            ));
        }
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let expected = kutup_chat_proto::MessageMutationBody {
                target_message_id: target_message_id.to_owned(),
                operation,
                replacement_text,
            };
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_message_mutation() != Some(expected)
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to a different mutation or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS mutation conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let content = ChatContent::message_mutation_with_id(
            send_id,
            sent_at,
            seq,
            target_message_id,
            operation,
            replacement_text,
        )
        .map_err(ChatError::Invalid)?;
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_receipt_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        message_ids: Vec<String>,
        state: kutup_chat_proto::ReceiptState,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS receipt send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
        {
            return Err(ChatError::Invalid(
                "MLS receipt identifiers or clock are invalid".into(),
            ));
        }
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let expected = kutup_chat_proto::ReceiptBody { message_ids, state };
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_receipt() != Some(expected)
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to a different receipt or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS receipt conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let content = ChatContent::receipt_with_id(send_id, sent_at, seq, message_ids, state)
            .map_err(ChatError::Invalid)?;
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_typing_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        active: bool,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS typing send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
        {
            return Err(ChatError::Invalid(
                "MLS typing identifiers or clock are invalid".into(),
            ));
        }
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_typing() != Some(kutup_chat_proto::TypingBody { active })
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to different typing state or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS typing conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let content = ChatContent::typing_with_id(send_id, sent_at, seq, active);
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_disappearing_timer_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        duration_seconds: Option<u32>,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS timer send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
        {
            return Err(ChatError::Invalid(
                "MLS timer identifiers or clock are invalid".into(),
            ));
        }
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let expected = kutup_chat_proto::DisappearingTimerBody { duration_seconds };
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_disappearing_timer() != Some(expected)
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to a different timer or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS timer conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let content =
            ChatContent::disappearing_timer_with_id(send_id, sent_at, seq, duration_seconds)
                .map_err(ChatError::Invalid)?;
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    /// Construct and strictly validate a shared Chat-media descriptor before
    /// consuming an OpenMLS generation. The object bytes remain outside MLS;
    /// only its random key, retrieval capability and immutable metadata are
    /// protected by the application ciphertext.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_attachment_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        descriptor: ChatAttachmentDescriptorV1,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        self.create_expiring_attachment_application_message(
            send_id,
            conversation_id,
            incarnation,
            mls_group_id,
            sent_at,
            descriptor,
            None,
            created_at_ms,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_expiring_attachment_application_message(
        &self,
        send_id: &str,
        conversation_id: Uuid,
        incarnation: u64,
        mls_group_id: &[u8],
        sent_at: &str,
        descriptor: ChatAttachmentDescriptorV1,
        expires_after_seconds: Option<u32>,
        created_at_ms: i64,
    ) -> Result<MlsOutboxEntry> {
        let parsed_send_id = Uuid::parse_str(send_id)
            .map_err(|_| ChatError::Invalid("MLS send id must be a UUID".into()))?;
        if parsed_send_id.is_nil()
            || conversation_id.is_nil()
            || sent_at.is_empty()
            || sent_at.len() > 128
        {
            return Err(ChatError::Invalid(
                "MLS attachment identifiers or clock are invalid".into(),
            ));
        }
        descriptor.validate().map_err(ChatError::Content)?;
        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            if existing.conversation_id != *conversation_id.as_bytes()
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || content.message_id.as_deref() != Some(send_id)
                || content.sent_at != sent_at
                || content.as_attachment() != Some(descriptor)
                || content
                    .disappearing_after_seconds()
                    .map_err(ChatError::Content)?
                    != expires_after_seconds
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to a different attachment or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        if conversation.request.genesis.conversation_id != conversation_id
            || conversation.request.genesis.incarnation != incarnation
        {
            return Err(ChatError::Trust(
                "MLS attachment conversation differs from the authenticated group".into(),
            ));
        }
        let (self_account, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &self_account)
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Invalid(
                "MLS group has no remote account recipient".into(),
            ));
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let mut content = ChatContent::attachment_with_id(send_id, sent_at, seq, descriptor)
            .map_err(ChatError::Content)?;
        if let Some(seconds) = expires_after_seconds {
            content = content
                .with_disappearing_after(seconds)
                .map_err(ChatError::Invalid)?;
        }
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        self.create_application_message_inner(
            send_id,
            *conversation_id.as_bytes(),
            incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn create_application_message_inner(
        &self,
        send_id: &str,
        conversation_id: [u8; 16],
        incarnation: u64,
        mls_group_id: &[u8],
        plaintext: &[u8],
        content: &[u8],
        expected_recipients: Vec<String>,
        created_at_ms: i64,
        last_sent_seq: Option<u64>,
    ) -> Result<MlsOutboxEntry> {
        validate_send(
            send_id,
            conversation_id,
            incarnation,
            mls_group_id,
            plaintext,
            created_at_ms,
        )?;
        let content_digest: [u8; 32] = Sha256::digest(plaintext).into();

        if let Some(existing) = self.db.load_mls_outbox(send_id).await? {
            if existing.conversation_id != conversation_id
                || existing.incarnation != incarnation
                || existing.mls_group_id != mls_group_id
                || existing.content_digest != content_digest
                || existing.content != content
                || existing.expected_recipients != expected_recipients
            {
                return Err(ChatError::Trust(
                    "MLS send id is already bound to different content or conversation".into(),
                ));
            }
            return Ok(existing);
        }

        let (provider, metadata) = self.load_provider().await?;
        let group_id = GroupId::from_slice(mls_group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| mls_error("load MLS group", error))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        let is_group_control = is_typed_group_control(plaintext);
        if group.pending_commit().is_some() && !is_group_control {
            return Err(ChatError::Trust(
                "only typed MLS group control may be sent while a Commit is pending".into(),
            ));
        }
        // Production groups always carry an authenticated conversation pin.
        // The empty branch is reachable only through the cfg(test) low-level
        // group fixture, which intentionally exercises OpenMLS primitives
        // without constructing the Kutup control log.
        if !metadata.conversations.is_empty() {
            let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
            if conversation.request.genesis.conversation_id.as_bytes() != &conversation_id
                || conversation.request.genesis.incarnation != incarnation
                || conversation.last_finalized_epoch != group.epoch().as_u64()
            {
                return Err(ChatError::Trust(
                    "OpenMLS epoch differs from the durable conversation pin".into(),
                ));
            }
            if !is_group_control
                && plaintext.len()
                    > conversation
                        .current_cryptographic_policy
                        .maximum_application_plaintext_bytes as usize
            {
                return Err(ChatError::Invalid(
                    "MLS application plaintext exceeds the authenticated group policy".into(),
                ));
            }
            if !is_group_control
                && conversation
                    .current_authorization_policy
                    .application_senders
                    == MlsApplicationSenderPolicyV1::Administrators
            {
                let (local_address, _) =
                    parse_device_credential_identity(&metadata.credential_identity)?;
                let local_is_admin = conversation
                    .current_roster
                    .iter()
                    .any(|member| member.address.canonical() == local_address && member.is_admin);
                if !local_is_admin {
                    return Err(ChatError::Trust(
                        "local MLS sender is not permitted by group policy".into(),
                    ));
                }
            }
        }
        let signer_public_key = group
            .own_leaf_node()
            .ok_or_else(|| ChatError::Trust("MLS group has no local leaf".into()))?
            .signature_key()
            .as_slice();
        let signer = SignatureKeyPair::read(
            provider.storage(),
            signer_public_key,
            SignatureScheme::ED25519,
        )
        .ok_or_else(|| {
            ChatError::MissingKeyMaterial("MLS leaf signing key is unavailable".into())
        })?;
        let epoch = group.epoch().as_u64();
        let ciphertext = group
            .create_message(&provider, &signer, plaintext)
            .map_err(|error| mls_error("create MLS application message", error))?
            .to_bytes()
            .map_err(|error| mls_error("serialize MLS application message", error))?;
        let entry = MlsOutboxEntry {
            send_id: send_id.to_owned(),
            conversation_id,
            incarnation,
            mls_group_id: mls_group_id.to_vec(),
            epoch,
            content_digest,
            content: content.to_vec(),
            ciphertext,
            expected_recipients,
            deliveries: Vec::new(),
            created_at: created_at_ms,
            attempts: 0,
        };

        let state = snapshot_provider(&provider, &metadata)?;
        let mut pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        pending
            .mls_outbox
            .insert(send_id.to_owned(), Some(entry.clone()));
        pending.last_sent_seq = last_sent_seq;
        self.db.apply(&pending).await?;
        Ok(entry)
    }

    pub async fn pending_application_messages(&self) -> Result<Vec<MlsOutboxEntry>> {
        self.db.list_mls_outbox().await
    }

    pub async fn mls_application_history(&self) -> Result<Vec<MlsHistoryMessage>> {
        self.db.list_mls_messages().await
    }

    /// Stage the exact anonymous request before its first network attempt.
    pub async fn stage_application_delivery(
        &self,
        send_id: &str,
        recipient: &AccountAddress,
        capability: [u8; 16],
        packages: &[VerifiedMlsKeyPackage],
        now_seconds: i64,
    ) -> Result<StagedMlsApplicationDelivery> {
        let mut entry = self
            .db
            .load_mls_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid("unknown MLS send id".into()))?;
        let canonical_recipient = recipient.canonical();
        if recipient.server.is_none()
            || entry
                .expected_recipients
                .binary_search(&canonical_recipient)
                .is_err()
        {
            return Err(ChatError::Trust(
                "MLS application recipient is absent from the captured roster".into(),
            ));
        }
        if let Some(existing) = entry
            .deliveries
            .iter()
            .find(|delivery| delivery.recipient == canonical_recipient)
        {
            let submission: AnonymousMlsSubmissionV1 = serde_json::from_slice(&existing.submission)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            submission.validate().map_err(ChatError::Db)?;
            return Ok(StagedMlsApplicationDelivery {
                entry,
                submission,
                idempotent: true,
            });
        }
        let conversation_id = Uuid::from_bytes(entry.conversation_id);
        let derived = self
            .derive_delivery_capability(
                &entry.mls_group_id,
                conversation_id,
                entry.incarnation,
                recipient,
            )
            .await?;
        if derived.epoch != entry.epoch || derived.capability != capability {
            return Err(ChatError::Trust(
                "MLS delivery capability differs from the immutable send epoch".into(),
            ));
        }
        if packages.is_empty() || packages.len() > 32 {
            return Err(ChatError::Invalid(
                "MLS application delivery has no destination devices".into(),
            ));
        }
        let mut devices = Vec::with_capacity(packages.len());
        let mut previous_device = None;
        for package in packages {
            Self::validate_verified_key_package(package, now_seconds)?;
            let (account, device_id) =
                parse_device_credential_identity(&package.credential.credential_identity)?;
            if account != canonical_recipient
                || package.wire.device_id != device_id
                || previous_device.is_some_and(|previous| device_id <= previous)
            {
                return Err(ChatError::Trust(
                    "MLS delivery packages do not exactly cover one canonical recipient".into(),
                ));
            }
            previous_device = Some(device_id);
            devices.push(AnonymousMlsRecipientDevice::new(
                device_id,
                package.anonymous_delivery_public_key.clone(),
            )?);
        }
        let submission = self
            .create_anonymous_submission(
                recipient.clone(),
                Uuid::parse_str(send_id)
                    .map_err(|_| ChatError::Invalid("MLS send id must be a UUID".into()))?,
                capability,
                &devices,
                &entry.ciphertext,
            )
            .await?;
        let submission_bytes =
            serde_json::to_vec(&submission).map_err(|error| ChatError::Wire(error.to_string()))?;
        entry.deliveries.push(MlsOutboxDelivery {
            recipient: canonical_recipient,
            submission: submission_bytes,
            attempts: 0,
            delivered: false,
        });
        entry
            .deliveries
            .sort_by(|left, right| left.recipient.cmp(&right.recipient));
        let mut pending = Pending::default();
        pending
            .mls_outbox
            .insert(send_id.to_owned(), Some(entry.clone()));
        self.db.apply(&pending).await?;
        Ok(StagedMlsApplicationDelivery {
            entry,
            submission,
            idempotent: false,
        })
    }

    pub async fn note_application_delivery_attempt(
        &self,
        send_id: &str,
        recipient: &str,
    ) -> Result<AnonymousMlsSubmissionV1> {
        let mut entry = self
            .db
            .load_mls_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid("unknown MLS send id".into()))?;
        let delivery = entry
            .deliveries
            .iter_mut()
            .find(|delivery| delivery.recipient == recipient)
            .ok_or_else(|| ChatError::Invalid("MLS delivery leg is not staged".into()))?;
        delivery.attempts = delivery
            .attempts
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS delivery attempt counter overflow".into()))?;
        entry.attempts = entry
            .attempts
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS send attempt counter overflow".into()))?;
        let submission: AnonymousMlsSubmissionV1 = serde_json::from_slice(&delivery.submission)
            .map_err(|error| ChatError::Db(error.to_string()))?;
        submission.validate().map_err(ChatError::Db)?;
        let mut pending = Pending::default();
        pending.mls_outbox.insert(send_id.to_owned(), Some(entry));
        self.db.apply(&pending).await?;
        Ok(submission)
    }

    pub async fn mark_application_recipient_delivered(
        &self,
        send_id: &str,
        recipient: &str,
        deduplicated: bool,
    ) -> Result<Option<MlsHistoryMessage>> {
        let record_id = format!("out:{send_id}");
        let Some(mut entry) = self.db.load_mls_outbox(send_id).await? else {
            return self
                .db
                .load_mls_message(&record_id)
                .await?
                .map(Some)
                .ok_or_else(|| ChatError::Invalid("unknown MLS send id".into()));
        };
        let delivery = entry
            .deliveries
            .iter_mut()
            .find(|delivery| delivery.recipient == recipient)
            .ok_or_else(|| ChatError::Invalid("MLS delivery leg is not staged".into()))?;
        delivery.delivered = true;
        let complete = entry.expected_recipients.iter().all(|expected| {
            entry
                .deliveries
                .iter()
                .any(|delivery| delivery.recipient == *expected && delivery.delivered)
        });
        if !complete {
            let mut pending = Pending::default();
            pending
                .mls_outbox
                .insert(send_id.to_owned(), Some(entry.clone()));
            self.db.apply(&pending).await?;
            return Ok(None);
        }
        let (_, metadata) = self.load_provider().await?;
        let (sender, sender_device_id) =
            parse_device_credential_identity(&metadata.credential_identity)?;
        let history = MlsHistoryMessage {
            record_id: record_id.clone(),
            message_id: send_id.to_owned(),
            conversation_id: entry.conversation_id,
            incarnation: entry.incarnation,
            mls_group_id: entry.mls_group_id,
            epoch: entry.epoch,
            sender,
            sender_device_id,
            outgoing: true,
            cursor: None,
            transport_digest: Sha256::digest(&entry.ciphertext).into(),
            content: entry.content,
            timestamp_ms: entry.created_at,
            delivered: true,
            deduplicated: deduplicated
                || entry
                    .deliveries
                    .iter()
                    .any(|delivery| delivery.attempts > 1),
        };
        let mut pending = Pending::default();
        pending.mls_outbox.insert(send_id.to_owned(), None);
        pending.mls_messages.insert(record_id, history.clone());
        self.db.apply(&pending).await?;
        Ok(Some(history))
    }

    /// Remove a delivered retry record. MLS state remains append-only.
    pub async fn mark_application_delivered(&self, send_id: &str) -> Result<()> {
        if self.db.load_mls_outbox(send_id).await?.is_none() {
            return Ok(());
        }
        let mut pending = Pending::default();
        pending.mls_outbox.insert(send_id.to_owned(), None);
        self.db.apply(&pending).await
    }

    /// Persist a retry attempt without changing the immutable ciphertext tuple.
    pub async fn note_application_attempt(&self, send_id: &str) -> Result<MlsOutboxEntry> {
        let mut entry = self
            .db
            .load_mls_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid("unknown MLS send id".into()))?;
        entry.attempts = entry
            .attempts
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS send attempt counter overflow".into()))?;
        let mut pending = Pending::default();
        pending
            .mls_outbox
            .insert(send_id.to_owned(), Some(entry.clone()));
        self.db.apply(&pending).await?;
        Ok(entry)
    }
}

fn is_typed_group_control(plaintext: &[u8]) -> bool {
    serde_json::from_slice::<ChatContent>(plaintext)
        .ok()
        .filter(|content| content.kind == kutup_chat_proto::content::kind::GROUP_CONTROL)
        .is_some_and(|content| {
            serde_json::from_value::<MlsGroupControlBodyV1>(content.body).is_ok()
        })
}
