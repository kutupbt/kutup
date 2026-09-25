//! Leaving a group. An MLS member cannot commit its own removal, so the
//! member sends an authenticated leave request to the group and an
//! administrator's client commits the removal; the member's own devices
//! treat the group as left from then on.

use super::owner_approval::DeterministicGroupControlMessage;
use super::*;
use kutup_chat_proto::MlsLeaveRequestV1;

impl MlsClient {
    /// Ask to leave, and mark the group left here. Refused (with a reason a
    /// person can act on) for an owner, who must hand ownership over first,
    /// for the last administrator of a group with others in it, who must make
    /// someone else an administrator first, and for the only member, who
    /// closes the group instead. `None` when this device already left.
    pub async fn request_leave(
        &self,
        mls_group_id: &[u8],
        requested_at_seconds: i64,
    ) -> Result<Option<MlsOutboxEntry>> {
        validate_group_id(mls_group_id)?;
        if requested_at_seconds < 0 {
            return Err(ChatError::Invalid("MLS leave clock is invalid".into()));
        }
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        if conversation.left {
            return Ok(None);
        }
        let (local_address, _) = parse_device_credential_identity(&metadata.credential_identity)?;
        let me = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == local_address)
            .ok_or_else(|| ChatError::Trust("this account is not a member of the group".into()))?;
        if conversation.current_roster.len() == 1 {
            return Err(ChatError::Invalid(
                "you are the only member; close the group instead".into(),
            ));
        }
        if me.owner_id.is_some() {
            return Err(ChatError::Invalid(
                "an owner must hand ownership to another member before leaving".into(),
            ));
        }
        if me.is_admin
            && conversation
                .current_roster
                .iter()
                .filter(|member| member.is_admin)
                .count()
                == 1
        {
            return Err(ChatError::Invalid(
                "the last administrator must make another member an administrator before leaving"
                    .into(),
            ));
        }
        let request = MlsLeaveRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            requested_at: requested_at_seconds,
        };
        request.validate().map_err(ChatError::Invalid)?;
        let joined_epoch = conversation
            .member_joined_epochs
            .get(&local_address)
            .copied()
            .unwrap_or_default();
        let mut id_material = Vec::with_capacity(16);
        id_material.extend_from_slice(&joined_epoch.to_be_bytes());
        id_material.extend_from_slice(&requested_at_seconds.to_be_bytes());
        let expected_recipients = conversation
            .current_roster
            .iter()
            .map(|member| member.address.canonical())
            .filter(|address| address != &local_address)
            .collect::<Vec<_>>();
        let entry = self
            .create_deterministic_group_control_message(DeterministicGroupControlMessage {
                mls_group_id,
                conversation: &conversation,
                domain: b"kutup/mls/leave-request-message/v1\0",
                id_material: &id_material,
                sent_at_seconds: requested_at_seconds,
                body: MlsGroupControlBodyV1::LeaveRequest { request },
                expected_recipients,
            })
            .await?;
        // The request is durable in the outbox; from now on this device
        // treats the group as left.
        let (provider, mut metadata) = self.load_provider().await?;
        let record = metadata
            .conversations
            .get_mut(&conversation.request.genesis.conversation_id.to_string())
            .ok_or_else(|| ChatError::Db("local MLS conversation record is unavailable".into()))?;
        record.left = true;
        let (_, local_device) = parse_device_credential_identity(&metadata.credential_identity)?;
        let notice = left_notice_record(
            &conversation,
            &local_address,
            local_device,
            conversation.last_finalized_epoch,
        )?;
        let state = snapshot_provider(&provider, &metadata)?;
        let mut writes = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        writes.mls_messages.insert(notice.record_id.clone(), notice);
        self.db.apply(&writes).await?;
        Ok(entry)
    }
}
