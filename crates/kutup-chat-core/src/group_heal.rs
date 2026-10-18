//! Healing a group (docs/plans/pairwise-groups.md §2), as Signal's retry
//! receipts do, on Kutup's direct-chat repair loop:
//!
//! - A group message this device can't read leaves a placeholder in the
//!   group's thread and asks the device that sent it, pairwise, to send it
//!   again. No pairwise session is reset: the sender key is what is missing.
//! - The sender answers from its send log, never from the server's word: the
//!   requester must be a verified member, and its device one the message went
//!   to. It sends its current key, then the message again; what it can't send
//!   is answered `unavailable`.

use std::rc::Rc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::content::{SenderKeyDistributionBody, SessionControlGroupV1};
use kutup_chat_proto::{
    ChatContent, DeliveredEnvelope, SealedMessageSubmissionV1, SessionControlAction,
    SessionControlBody,
};
use rand::{CryptoRng, Rng};

use crate::address::ChatAddress;
use crate::clock::{rfc3339, unix_millis};
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{BookDevice, GroupStatus};
use crate::session::ReceivedMessage;
use crate::transport::SendOutcome;

impl Engine {
    /// Sends `content` pairwise to one member device of `group_id`, sealed
    /// with the capability its account's profile key in the group gives.
    async fn send_to_group_device<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        to: &ChatAddress,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<()> {
        let account = to.name();
        let capability = *self
            .group_capabilities(group_id)
            .await?
            .get(&account)
            .ok_or_else(|| ChatError::Invalid("not a verified member of the group".into()))?;
        let bundles: Vec<_> = self
            .sealed_bundles_for_send(&account, &capability)
            .await?
            .into_iter()
            .filter(|bundle| bundle.device_id == to.device_id)
            .collect();
        if bundles.is_empty() {
            return Err(ChatError::Invalid(
                "the device isn't the account's now".into(),
            ));
        }
        let certificate = self.issue_verified_sender_certificate().await?;
        let envelopes = self
            .session
            .seal_pairwise(&account, &bundles, &certificate, content, rng)
            .await?;
        let request = SealedMessageSubmissionV1 {
            send_id: uuid::Uuid::new_v4().to_string(),
            capability: STANDARD.encode(capability),
            envelopes,
        };
        request.validate().map_err(ChatError::Invalid)?;
        match Rc::clone(&self.transport)
            .send_sealed(&account, &request)
            .await?
        {
            SendOutcome::Delivered { .. } | SendOutcome::Refused => Ok(()),
            SendOutcome::Mismatch(_) => {
                self.known_devices.remove(&account);
                Err(ChatError::Transport("the account's devices changed".into()))
            }
        }
    }

    /// Asks the device that sent `send_ids` in `group_id` to send them again.
    pub(crate) async fn request_group_resend<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        to: &ChatAddress,
        send_ids: Vec<String>,
        rng: &mut R,
    ) -> Result<()> {
        let content = ChatContent::session_control_with_id(
            uuid::Uuid::new_v4().to_string(),
            rfc3339(unix_millis()),
            0,
            &SessionControlBody {
                action: SessionControlAction::Refresh,
                send_ids,
                group: Some(SessionControlGroupV1 {
                    group_id: group_id.to_string(),
                }),
            },
        );
        self.send_to_group_device(group_id, to, &content, rng).await
    }

    /// A group message this device couldn't read: a placeholder in the
    /// group's thread, and a request to its sender. `None` when it isn't from
    /// a verified member of a group this account is in (the usual failure
    /// path then keeps it for attention).
    pub(crate) async fn repair_group_message<R: Rng + CryptoRng>(
        &mut self,
        envelope: &DeliveredEnvelope,
        sender: &str,
        device_id: u32,
        group_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<Option<ReceivedMessage>> {
        let group_id = kutup_chat_proto::group::encode_group_id(group_id);
        let Some(record) = self.session.db().load_group(&group_id).await? else {
            return Ok(None);
        };
        if record.status != GroupStatus::Member
            || !self
                .verified_member_accounts(&group_id)
                .await?
                .iter()
                .any(|member| member == sender)
        {
            return Ok(None);
        }
        let context = Self::group_context(&record)?;
        let content = ChatContent::undecryptable_with_id(
            format!("{}:unreadable", envelope.id),
            rfc3339(unix_millis()),
            envelope.send_id.clone(),
        )
        .with_group_context(&context);
        let from = ChatAddress::from_sender(sender, device_id)?;
        self.session
            .record_group_placeholder(envelope, &from, &content)
            .await?;
        if let Some(send_id) = envelope.send_id.clone() {
            // Best effort: the waiting record asks again later.
            let _ = self
                .request_group_resend(&group_id, &from, vec![send_id], rng)
                .await;
        }
        Ok(Some(ReceivedMessage {
            from,
            content,
            cursor: envelope.cursor,
            id: envelope.id.clone(),
        }))
    }

    /// Answers a member device's group refresh from this device's send log:
    /// its current key first, then each message it was sent; the rest is
    /// `unavailable`.
    pub(crate) async fn answer_group_refresh<R: Rng + CryptoRng>(
        &mut self,
        from: &ChatAddress,
        body: &SessionControlBody,
        rng: &mut R,
    ) -> Result<()> {
        let Some(group) = body.group.as_ref() else {
            return Ok(());
        };
        let requester = from.name();
        if body.action != SessionControlAction::Refresh {
            return Ok(());
        }
        let mut record = self.load_group_record(&group.group_id).await?;
        if record.status != GroupStatus::Member
            || !self
                .verified_member_accounts(&group.group_id)
                .await?
                .iter()
                .any(|member| *member == requester)
        {
            return Ok(());
        }
        // The current key, entered for this device in the book.
        if let Some(book) = record.sender_book.clone() {
            let distribution_id = uuid::Uuid::parse_str(&book.distribution_id)
                .map_err(|_| ChatError::Invalid("the sender book's id isn't a UUID".into()))?;
            let message = self
                .session
                .sender_key_distribution(distribution_id, rng)
                .await?;
            let content = ChatContent::sender_key_distribution_with_id(
                uuid::Uuid::new_v4().to_string(),
                rfc3339(unix_millis()),
                0,
                &SenderKeyDistributionBody {
                    group_id: group.group_id.clone(),
                    distribution_id: distribution_id.to_string(),
                    message: STANDARD.encode(&message),
                },
            );
            self.send_to_group_device(&group.group_id, from, &content, rng)
                .await?;
            if let Some(book) = record.sender_book.as_mut() {
                let held = book.devices.iter().any(|device| {
                    device.account == requester && device.device_id == from.device_id
                });
                if !held {
                    if let Some(bundle) = self
                        .known_devices
                        .get(&requester)
                        .and_then(|bundles| bundles.iter().find(|b| b.device_id == from.device_id))
                    {
                        book.devices.push(BookDevice {
                            account: requester.clone(),
                            device_id: from.device_id,
                            registration_id: bundle.registration_id,
                        });
                        book.devices.sort();
                    }
                }
            }
            self.save_group(&record).await?;
        }
        // Each message, only to a device it went to.
        let log = self.session.db().list_group_outbox().await?;
        let mut unavailable = Vec::new();
        for send_id in &body.send_ids {
            let sent_to_device = log.iter().find(|entry| {
                entry.send_id == *send_id
                    && entry.group_id == group.group_id
                    && entry.legs.iter().any(|leg| {
                        leg.account == requester && leg.devices.contains(&from.device_id)
                    })
            });
            let Some(entry) = sent_to_device else {
                unavailable.push(send_id.clone());
                continue;
            };
            let Ok(original) = serde_json::from_slice::<ChatContent>(&entry.content) else {
                unavailable.push(send_id.clone());
                continue;
            };
            match ChatContent::resend_with_id(
                uuid::Uuid::new_v4().to_string(),
                rfc3339(unix_millis()),
                0,
                original,
            ) {
                Ok(resend) => {
                    self.send_to_group_device(&group.group_id, from, &resend, rng)
                        .await?;
                }
                Err(_) => unavailable.push(send_id.clone()),
            }
        }
        if !unavailable.is_empty() {
            let content = ChatContent::session_control_with_id(
                uuid::Uuid::new_v4().to_string(),
                rfc3339(unix_millis()),
                0,
                &SessionControlBody {
                    action: SessionControlAction::Unavailable,
                    send_ids: unavailable,
                    group: Some(group.clone()),
                },
            );
            self.send_to_group_device(&group.group_id, from, &content, rng)
                .await?;
        }
        Ok(())
    }
}
