//! Encrypted manual approval exchange for owner-quorum MLS transitions.
//!
//! Requests and responses are ordinary MLS application messages addressed
//! only to current owners. Ordering servers see the eventual pseudonymous
//! certificate but never the account-to-owner mapping or approval UI payload.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use kutup_chat_proto::{MlsOwnerApprovalRequestV1, MlsOwnerApprovalV1};

const OWNER_APPROVAL_REQUEST_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMlsOwnerApprovalRequest {
    pub mls_group_id: Vec<u8>,
    pub requester: AccountAddress,
    pub request: MlsOwnerApprovalRequestV1,
}

impl PendingMlsOwnerApprovalRequest {
    pub(super) fn validate_durable(&self) -> Result<()> {
        validate_group_id(&self.mls_group_id)?;
        self.request.validate().map_err(ChatError::Db)?;
        if self.requester.server.is_none()
            || self.requester.canonical() != self.requester.to_string()
        {
            return Err(ChatError::Db(
                "MLS owner approval requester is not canonical and federated".into(),
            ));
        }
        Ok(())
    }
}

impl MlsClient {
    pub async fn pending_owner_approval_requests(
        &self,
    ) -> Result<Vec<PendingMlsOwnerApprovalRequest>> {
        let (_, metadata) = self.load_provider().await?;
        Ok(metadata.owner_approval_requests.values().cloned().collect())
    }

    pub async fn owner_change_has_quorum(&self, mls_group_id: &[u8]) -> Result<bool> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?;
        let control = metadata
            .pending_owner_changes
            .get(&BASE64.encode(mls_group_id))
            .ok_or_else(|| ChatError::Trust("pending MLS owner control is unavailable".into()))?;
        let block = &control.vote_request.block;
        let certificate = block
            .owner_approval
            .as_ref()
            .ok_or_else(|| ChatError::Db("pending MLS owner control has no approvals".into()))?;
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

    pub async fn create_owner_approval_request_message(
        &self,
        mls_group_id: &[u8],
    ) -> Result<Option<MlsOutboxEntry>> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        let control = metadata
            .pending_owner_changes
            .get(&BASE64.encode(mls_group_id))
            .ok_or_else(|| ChatError::Trust("pending MLS owner control is unavailable".into()))?;
        if self.owner_change_has_quorum(mls_group_id).await? {
            return Ok(None);
        }
        let block = &control.vote_request.block;
        let expires_at = block
            .finalized_at
            .checked_add(OWNER_APPROVAL_REQUEST_LIFETIME_SECONDS)
            .ok_or_else(|| ChatError::Invalid("MLS owner approval expiry overflow".into()))?;
        let request = MlsOwnerApprovalRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            owner_set_sequence: conversation.current_owner_set.sequence,
            proposal: block.proposal.clone(),
            transition_digest: block
                .transition_digest
                .clone()
                .ok_or_else(|| ChatError::Db("owner change has no transition digest".into()))?,
            owner_change: control.owner_change.clone(),
            next_roster: control.next_roster.clone(),
            requested_at: block.finalized_at,
            expires_at,
        };
        request.validate().map_err(ChatError::Protocol)?;
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let expected_recipients = conversation
            .current_roster
            .iter()
            .filter(|member| {
                member.address.canonical() != local_address
                    && member.owner_id.as_deref().is_some_and(|owner_id| {
                        conversation.current_owner_set.owner(owner_id).is_some()
                    })
            })
            .map(|member| member.address.canonical())
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Err(ChatError::Trust(
                "MLS owner quorum is missing but no other current owner is reachable".into(),
            ));
        }
        self.create_owner_control_message(
            mls_group_id,
            &conversation,
            b"kutup/mls/owner-approval-request-message/v1\0",
            request
                .request_hash()
                .map_err(ChatError::Protocol)?
                .as_bytes(),
            request.requested_at,
            MlsGroupControlBodyV1::OwnerApprovalRequest { request },
            expected_recipients,
        )
        .await
    }

    pub async fn approve_owner_approval_request(
        &self,
        mls_group_id: &[u8],
        approved_at_seconds: i64,
    ) -> Result<Option<MlsOutboxEntry>> {
        validate_group_id(mls_group_id)?;
        let group_key = BASE64.encode(mls_group_id);
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        let pending = metadata
            .owner_approval_requests
            .get(&group_key)
            .cloned()
            .ok_or_else(|| {
                ChatError::Invalid("MLS owner approval request is unavailable".into())
            })?;
        if approved_at_seconds < pending.request.requested_at
            || approved_at_seconds > pending.request.expires_at
        {
            return Err(ChatError::Trust(
                "MLS owner approval request is expired or has an invalid clock".into(),
            ));
        }
        let owner = group_owner_credential(&metadata, mls_group_id)?;
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let local_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == local_address)
            .ok_or_else(|| {
                ChatError::Trust("local account is absent from the MLS roster".into())
            })?;
        if local_member.owner_id.as_deref() != Some(owner.owner_id.as_str())
            || conversation
                .current_owner_set
                .owner(&owner.owner_id)
                .is_none()
        {
            return Err(ChatError::Trust(
                "only a current MLS owner can approve this request".into(),
            ));
        }
        let owner_seed: [u8; 32] = ensure_group_owner_key(&metadata, mls_group_id)?
            .try_into()
            .map_err(|_| ChatError::Db("invalid durable MLS owner seed".into()))?;
        let signer = Ed25519SigningKey::from_bytes(&owner_seed);
        let mut approval = MlsOwnerApprovalV1 {
            conversation_id: pending.request.proposal.conversation_id,
            incarnation: pending.request.proposal.incarnation,
            owner_set_sequence: pending.request.owner_set_sequence,
            proposal_hash: pending
                .request
                .proposal
                .proposal_hash()
                .map_err(ChatError::Protocol)?,
            transition_digest: Some(pending.request.transition_digest.clone()),
            owner_id: owner.owner_id,
            approved_at: approved_at_seconds,
            signature: String::new(),
        };
        approval.signature = BASE64.encode(
            signer
                .sign(&approval.signing_bytes().map_err(ChatError::Protocol)?)
                .to_bytes(),
        );
        approval
            .verify(
                conversation
                    .current_owner_set
                    .owner(&approval.owner_id)
                    .expect("local owner checked above"),
            )
            .map_err(ChatError::Trust)?;
        let request_hash = pending
            .request
            .request_hash()
            .map_err(ChatError::Protocol)?;
        let entry = self
            .create_owner_control_message(
                mls_group_id,
                &conversation,
                b"kutup/mls/owner-approval-response-message/v1\0",
                format!("{request_hash}:{}", approval.owner_id).as_bytes(),
                approved_at_seconds,
                MlsGroupControlBodyV1::OwnerApproval { approval },
                vec![pending.requester.canonical()],
            )
            .await?;
        let (provider, mut metadata) = self.load_provider().await?;
        if metadata
            .owner_approval_requests
            .remove(&group_key)
            .is_some()
        {
            let state = snapshot_provider(&provider, &metadata)?;
            self.db
                .apply(&Pending {
                    mls_state: Some(state),
                    ..Pending::default()
                })
                .await?;
        }
        Ok(entry)
    }

    pub async fn reject_owner_approval_request(&self, mls_group_id: &[u8]) -> Result<()> {
        validate_group_id(mls_group_id)?;
        let group_key = BASE64.encode(mls_group_id);
        let (provider, mut metadata) = self.load_provider().await?;
        if metadata
            .owner_approval_requests
            .remove(&group_key)
            .is_none()
        {
            return Ok(());
        }
        let state = snapshot_provider(&provider, &metadata)?;
        self.db
            .apply(&Pending {
                mls_state: Some(state),
                ..Pending::default()
            })
            .await
    }

    async fn create_owner_control_message(
        &self,
        mls_group_id: &[u8],
        conversation: &LocalMlsConversationRecord,
        domain: &[u8],
        id_material: &[u8],
        sent_at_seconds: i64,
        body: MlsGroupControlBodyV1,
        expected_recipients: Vec<String>,
    ) -> Result<Option<MlsOutboxEntry>> {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(conversation.request.genesis.conversation_id.as_bytes());
        hash.update(conversation.request.genesis.incarnation.to_be_bytes());
        hash.update(id_material);
        let digest = hash.finalize();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&digest[..16]);
        uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x50;
        uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;
        let send_id = Uuid::from_bytes(uuid_bytes).to_string();
        if let Some(existing) = self.db.load_mls_outbox(&send_id).await? {
            let content: ChatContent = serde_json::from_slice(&existing.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let existing_body: MlsGroupControlBodyV1 = serde_json::from_value(content.body.clone())
                .map_err(|error| ChatError::Db(error.to_string()))?;
            if existing.conversation_id != *conversation.request.genesis.conversation_id.as_bytes()
                || existing.incarnation != conversation.request.genesis.incarnation
                || existing.mls_group_id != mls_group_id
                || existing.expected_recipients != expected_recipients
                || content.kind != kutup_chat_proto::content::kind::GROUP_CONTROL
                || content.message_id.as_deref() != Some(send_id.as_str())
                || content.sent_at != sent_at_seconds.to_string()
                || existing_body != body
            {
                return Err(ChatError::Db(
                    "durable MLS owner-approval outbox differs from its deterministic id".into(),
                ));
            }
            return Ok(Some(existing));
        }
        if let Some(history) = self.db.load_mls_message(&format!("out:{send_id}")).await? {
            let content: ChatContent = serde_json::from_slice(&history.content)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let existing_body: MlsGroupControlBodyV1 = serde_json::from_value(content.body.clone())
                .map_err(|error| ChatError::Db(error.to_string()))?;
            if !history.outgoing
                || !history.delivered
                || history.message_id != send_id
                || history.conversation_id
                    != *conversation.request.genesis.conversation_id.as_bytes()
                || history.incarnation != conversation.request.genesis.incarnation
                || history.mls_group_id != mls_group_id
                || content.kind != kutup_chat_proto::content::kind::GROUP_CONTROL
                || content.message_id.as_deref() != Some(send_id.as_str())
                || content.sent_at != sent_at_seconds.to_string()
                || existing_body != body
            {
                return Err(ChatError::Db(
                    "durable MLS owner-approval receipt differs from its deterministic id".into(),
                ));
            }
            return Ok(None);
        }
        let seq = self
            .db
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("MLS sender sequence overflow".into()))?;
        let content = ChatContent {
            v: ChatContent::VERSION,
            kind: kutup_chat_proto::content::kind::GROUP_CONTROL.into(),
            sent_at: sent_at_seconds.to_string(),
            seq,
            message_id: Some(send_id.clone()),
            profile_key: None,
            body: serde_json::to_value(body)
                .map_err(|error| ChatError::Content(error.to_string()))?,
            extra: serde_json::Map::new(),
        };
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| ChatError::Content(error.to_string()))?;
        let created_at_ms = sent_at_seconds
            .checked_mul(1000)
            .ok_or_else(|| ChatError::Invalid("MLS owner approval clock overflow".into()))?;
        self.create_application_message_inner(
            &send_id,
            *conversation.request.genesis.conversation_id.as_bytes(),
            conversation.request.genesis.incarnation,
            mls_group_id,
            &content_bytes,
            &content_bytes,
            expected_recipients,
            created_at_ms,
            Some(seq),
        )
        .await
        .map(Some)
    }
}

pub(super) fn record_owner_approval_request(
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    sender: &str,
    request: MlsOwnerApprovalRequestV1,
) -> Result<()> {
    request.validate().map_err(ChatError::Trust)?;
    let group_key = BASE64.encode(mls_group_id);
    let conversation = active_conversation_for_group(metadata, mls_group_id)?.clone();
    let sender_member = conversation
        .current_roster
        .iter()
        .find(|member| member.address.canonical() == sender)
        .ok_or_else(|| {
            ChatError::Trust("MLS approval requester is absent from the roster".into())
        })?;
    if !sender_member
        .owner_id
        .as_deref()
        .is_some_and(|owner_id| conversation.current_owner_set.owner(owner_id).is_some())
    {
        return Err(ChatError::Trust(
            "MLS approval requester is not a current owner".into(),
        ));
    }
    let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
    let local_is_owner = conversation.current_roster.iter().any(|member| {
        member.address.canonical() == local_address
            && member
                .owner_id
                .as_deref()
                .is_some_and(|owner_id| conversation.current_owner_set.owner(owner_id).is_some())
    });
    if !local_is_owner {
        return Err(ChatError::Trust(
            "MLS owner approval request was delivered to a non-owner".into(),
        ));
    }
    if metadata.pending_owner_changes.contains_key(&group_key) {
        return Err(ChatError::Trust(
            "concurrent MLS owner changes fail closed".into(),
        ));
    }
    if request.proposal.conversation_id != conversation.request.genesis.conversation_id
        || request.proposal.incarnation != conversation.request.genesis.incarnation
        || request.proposal.base_epoch != conversation.last_finalized_epoch
        || request.owner_set_sequence != conversation.current_owner_set.sequence
        || request
            .owner_change
            .delivery_transition
            .previous_roster_commitment
            != roster_commitment(&conversation.current_roster).map_err(ChatError::Trust)?
    {
        return Err(ChatError::Trust(
            "MLS owner approval request differs from the current group pin".into(),
        ));
    }
    ownership::validate_owner_role_transition(
        &conversation.current_roster,
        &request.next_roster,
        &conversation.current_owner_set,
        &request.owner_change.next_owner_set,
    )?;
    ownership::validate_new_owner_candidates(
        metadata,
        &conversation,
        &request.next_roster,
        &request.owner_change.next_owner_set,
        &group_key,
    )?;
    let requester: AccountAddress = sender
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    let pending = PendingMlsOwnerApprovalRequest {
        mls_group_id: mls_group_id.to_vec(),
        requester,
        request,
    };
    pending.validate_durable()?;
    if let Some(existing) = metadata.owner_approval_requests.get(&group_key) {
        if existing != &pending {
            return Err(ChatError::Trust(
                "MLS owner approval request was replaced without resolution".into(),
            ));
        }
        return Ok(());
    }
    metadata.owner_approval_requests.insert(group_key, pending);
    Ok(())
}

pub(super) fn record_owner_approval(
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    sender: &str,
    approval: MlsOwnerApprovalV1,
) -> Result<()> {
    let group_key = BASE64.encode(mls_group_id);
    let conversation = active_conversation_for_group(metadata, mls_group_id)?.clone();
    let sender_member = conversation
        .current_roster
        .iter()
        .find(|member| member.address.canonical() == sender)
        .ok_or_else(|| ChatError::Trust("MLS approving owner is absent from the roster".into()))?;
    if sender_member.owner_id.as_deref() != Some(approval.owner_id.as_str()) {
        return Err(ChatError::Trust(
            "MLS owner approval is bound to a different authenticated sender".into(),
        ));
    }
    let owner = conversation
        .current_owner_set
        .owner(&approval.owner_id)
        .ok_or_else(|| ChatError::Trust("MLS approval references a non-owner".into()))?;
    approval.verify(owner).map_err(ChatError::Trust)?;
    let control = match metadata.pending_owner_changes.get_mut(&group_key) {
        Some(control) => control,
        None => return Ok(()),
    };
    let block = &mut control.vote_request.block;
    let certificate = block
        .owner_approval
        .as_mut()
        .ok_or_else(|| ChatError::Db("pending MLS owner change has no certificate".into()))?;
    if approval.conversation_id != block.proposal.conversation_id
        || approval.incarnation != block.proposal.incarnation
        || approval.owner_set_sequence != conversation.current_owner_set.sequence
        || approval.proposal_hash
            != block
                .proposal
                .proposal_hash()
                .map_err(ChatError::Protocol)?
        || approval.transition_digest.as_deref() != block.transition_digest.as_deref()
    {
        return Err(ChatError::Trust(
            "MLS owner approval differs from the pending exact transition".into(),
        ));
    }
    match certificate
        .approvals
        .binary_search_by(|existing| existing.owner_id.cmp(&approval.owner_id))
    {
        Ok(index) if certificate.approvals[index] == approval => return Ok(()),
        Ok(_) => {
            return Err(ChatError::Trust(
                "MLS owner sent conflicting approvals for one proposal".into(),
            ))
        }
        Err(index) => certificate.approvals.insert(index, approval),
    }
    certificate
        .verify_partial(
            &block.proposal,
            block.transition_digest.as_deref(),
            &conversation.current_owner_set,
        )
        .map_err(ChatError::Trust)
}
