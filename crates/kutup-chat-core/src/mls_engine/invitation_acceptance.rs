//! End-to-end encrypted MLS invitation acceptance.
//!
//! The server-level receipt is intentionally delivered only to the invitation
//! origin, because broadcasting a plaintext account address to every
//! participant server would expand roster metadata. This control message
//! gives every ready group member the same acceptance fact inside MLS.

use super::*;
use kutup_chat_proto::MlsInvitationAcceptanceV1;

impl MlsClient {
    pub async fn create_invitation_acceptance_message(
        &self,
        mls_group_id: &[u8],
        invited_epoch: u64,
        accepted_at_seconds: i64,
    ) -> Result<Option<MlsOutboxEntry>> {
        validate_group_id(mls_group_id)?;
        let (_, metadata) = self.load_provider().await?;
        let conversation = active_conversation_for_group(&metadata, mls_group_id)?.clone();
        let (local_address, _) =
            parse_device_credential_identity(&metadata.credential_identity)?;
        let local_member = conversation
            .current_roster
            .iter()
            .find(|member| member.address.canonical() == local_address)
            .ok_or_else(|| {
                ChatError::Trust("MLS invitation accepter is absent from the roster".into())
            })?;
        if conversation.member_joined_epochs.get(&local_address) != Some(&invited_epoch)
            || conversation.accepted_invitation_epochs.get(&local_address)
                != Some(&invited_epoch)
        {
            return Err(ChatError::Trust(
                "MLS invitation acceptance differs from the local join epoch".into(),
            ));
        }
        let acceptance = MlsInvitationAcceptanceV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: conversation.request.genesis.conversation_id,
            incarnation: conversation.request.genesis.incarnation,
            invited_epoch,
            accepted_at: accepted_at_seconds,
        };
        acceptance.validate().map_err(ChatError::Invalid)?;

        // A freshly joined client treats the Welcome roster as an accepted
        // baseline. Later additions are included only after their own
        // encrypted receipt, avoiding a delivery attempt to another pending
        // invitee while this receipt is being published.
        let expected_recipients = conversation
            .current_roster
            .iter()
            .filter_map(|member| {
                let address = member.address.canonical();
                if address == local_member.address.canonical() {
                    return None;
                }
                let joined = conversation.member_joined_epochs.get(&address)?;
                (*joined == 0
                    || conversation.accepted_invitation_epochs.get(&address) == Some(joined))
                .then_some(address)
            })
            .collect::<Vec<_>>();
        if expected_recipients.is_empty() {
            return Ok(None);
        }

        let mut id_material = local_address.into_bytes();
        id_material.extend_from_slice(&invited_epoch.to_be_bytes());
        self.create_deterministic_group_control_message(
            mls_group_id,
            &conversation,
            b"kutup/mls/invitation-acceptance-message/v1\0",
            &id_material,
            accepted_at_seconds,
            MlsGroupControlBodyV1::InvitationAccepted { acceptance },
            expected_recipients,
        )
        .await
    }
}

pub(super) fn record_invitation_acceptance(
    metadata: &mut SnapshotMetadata,
    mls_group_id: &[u8],
    sender: &str,
    acceptance: MlsInvitationAcceptanceV1,
    server_timestamp: i64,
) -> Result<()> {
    acceptance.validate().map_err(ChatError::Trust)?;
    let conversation = active_conversation_for_group(metadata, mls_group_id)?;
    if acceptance.conversation_id != conversation.request.genesis.conversation_id
        || acceptance.incarnation != conversation.request.genesis.incarnation
        || acceptance.accepted_at < conversation.request.genesis.created_at
        || acceptance.accepted_at
            > server_timestamp.saturating_add(KEY_PACKAGE_CLOCK_SKEW_SECONDS as i64)
        || !conversation
            .current_roster
            .iter()
            .any(|member| member.address.canonical() == sender)
        || conversation.member_joined_epochs.get(sender) != Some(&acceptance.invited_epoch)
    {
        return Err(ChatError::Trust(
            "MLS invitation acceptance differs from its authenticated sender or join epoch".into(),
        ));
    }
    let conversation = metadata
        .conversations
        .get_mut(&acceptance.conversation_id.to_string())
        .ok_or_else(|| ChatError::Db("MLS invitation acceptance group is unavailable".into()))?;
    conversation
        .accepted_invitation_epochs
        .insert(sender.to_owned(), acceptance.invited_epoch);
    Ok(())
}
