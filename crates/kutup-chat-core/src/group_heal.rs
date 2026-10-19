//! Healing a group (docs/plans/pairwise-groups.md §2), as Signal's retry
//! receipts do, on Kutup's direct-chat repair loop:
//!
//! - A group message this device can't read leaves a placeholder in the
//!   group's thread and asks the device that sent it, pairwise, to send it
//!   again. No pairwise session is reset: the sender key is what is missing.
//!   A change notice (implicit content hint) is asked for without a
//!   placeholder.
//! - The sender answers from its send log, never from the server's word: the
//!   requester must be a verified member, and its device one the message went
//!   to. It sends its current key, then the message again; what it can't send
//!   is answered `unavailable`. Each is answered at most once an hour per
//!   device, as direct resends are.

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
use crate::engine::{Engine, SESSION_RESET_INTERVAL_MS};
use crate::error::{ChatError, Result};
use crate::group::{BookDevice, GroupStatus};
use crate::session::{GroupGate, ReceivedMessage};
use crate::transport::SendOutcome;

/// What became of a group message this device couldn't read.
pub(crate) enum GroupRepair {
    /// A placeholder stands in the thread, and the sender was asked.
    Placeholder(Box<ReceivedMessage>),
    /// The sender was asked, with nothing to show (a change notice).
    Asked,
    /// Not a member's, or not a group this account is in: dropped.
    Dropped,
    /// Its sender can't be confirmed as a member now: left queued, read
    /// again on a later pass (perhaps with their key by then).
    Held,
}

impl Engine {
    /// Sends `content` sealed and pairwise to `account` (all its devices, or
    /// only `device_id`) with `capability`. Nothing is kept: no history, no
    /// outbox, no copy for this account's other devices. False when the
    /// account refused it (its capability changed: it blocked this account,
    /// or rotated its profile key).
    pub(crate) async fn send_sealed_pairwise<R: Rng + CryptoRng>(
        &mut self,
        account: &str,
        capability: &[u8; 16],
        device_id: Option<u32>,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<bool> {
        // The account's devices changed since they were read (one was linked
        // just now): read them again and send once more, as a direct send
        // does. To one named device, a mismatch means it is gone.
        let attempts = if device_id.is_none() { 2 } else { 1 };
        for attempt in 1..=attempts {
            let bundles: Vec<_> = self
                .sealed_bundles_for_send(account, capability)
                .await?
                .into_iter()
                .filter(|bundle| device_id.is_none_or(|device_id| bundle.device_id == device_id))
                .collect();
            if bundles.is_empty() {
                return Err(ChatError::Invalid(
                    "the device isn't the account's now".into(),
                ));
            }
            let certificate = self.issue_verified_sender_certificate().await?;
            let sealed = self
                .session
                .seal_pairwise(account, &bundles, &certificate, content, rng)
                .await?;
            let envelopes = self.sealed_envelopes(sealed);
            let request = SealedMessageSubmissionV1 {
                send_id: uuid::Uuid::new_v4().to_string(),
                capability: STANDARD.encode(capability),
                envelopes,
            };
            request.validate().map_err(ChatError::Invalid)?;
            match Rc::clone(&self.transport)
                .send_sealed(account, &request)
                .await?
            {
                SendOutcome::Delivered { .. } => return Ok(true),
                SendOutcome::Refused => return Ok(false),
                SendOutcome::Mismatch(_) => {
                    self.known_devices.remove(account);
                    if attempt == attempts {
                        return Err(ChatError::Transport("the account's devices changed".into()));
                    }
                }
            }
        }
        unreachable!("the last attempt returns")
    }

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
        let target = self
            .group_targets(group_id)
            .await?
            .remove(&account)
            .ok_or_else(|| ChatError::Invalid("not a verified member of the group".into()))?;
        let content = crate::group_send::named_for(content, target.pseudonym.as_deref());
        self.send_sealed_pairwise(
            &account,
            &target.capability,
            Some(to.device_id),
            &content,
            rng,
        )
        .await
        .map(|_| ())
    }

    /// Asks the device that sent `send_ids` in `group_id` to send them again.
    pub(crate) async fn request_group_resend<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        to: &ChatAddress,
        send_ids: Vec<String>,
        rng: &mut R,
    ) -> Result<()> {
        let record = self.load_group_record(group_id).await?;
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
        )
        .with_group_context(&Self::group_context(&record)?);
        self.send_to_group_device(group_id, to, &content, rng).await
    }

    /// A group message this device couldn't read: a placeholder in the
    /// group's thread (none for a change notice), and a request to its
    /// sender. A sender who isn't a member here makes this device catch up
    /// first (bounded), as a readable message would.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn repair_group_message<R: Rng + CryptoRng>(
        &mut self,
        envelope: &DeliveredEnvelope,
        sender: &str,
        device_id: u32,
        group_id: &[u8; 32],
        implicit: bool,
        received_at: i64,
        rng: &mut R,
    ) -> Result<GroupRepair> {
        let group_id = kutup_chat_proto::group::encode_group_id(group_id);
        match self
            .decide_group_content(&group_id, sender, None, false, received_at)
            .await?
        {
            GroupGate::Accept => {}
            GroupGate::Refuse => {
                self.session.ack_dropped(envelope).await?;
                return Ok(GroupRepair::Dropped);
            }
            GroupGate::Hold | GroupGate::CatchUp => return Ok(GroupRepair::Held),
        }
        let record = self.load_group_record(&group_id).await?;
        let from = ChatAddress::from_sender(sender, device_id)?;
        if implicit {
            self.session.ack_dropped(envelope).await?;
            if let Some(send_id) = envelope.send_id.clone() {
                // Best effort: the next message's context tells it again.
                let _ = self
                    .request_group_resend(&group_id, &from, vec![send_id], rng)
                    .await;
            }
            return Ok(GroupRepair::Asked);
        }
        let context = Self::group_context(&record)?;
        let content = ChatContent::undecryptable_with_id(
            format!("{}:unreadable", envelope.id),
            rfc3339(unix_millis()),
            envelope.send_id.clone(),
        )
        .with_group_context(&context);
        self.session
            .record_group_placeholder(envelope, &from, &content)
            .await?;
        if let Some(send_id) = envelope.send_id.clone() {
            // Best effort: the waiting record asks again later.
            let _ = self
                .request_group_resend(&group_id, &from, vec![send_id], rng)
                .await;
        }
        Ok(GroupRepair::Placeholder(Box::new(ReceivedMessage {
            from,
            content,
            cursor: envelope.cursor,
            id: envelope.id.clone(),
        })))
    }

    /// Which of `keys` for `device` may be answered now (at most once an
    /// hour, across reloads and tabs); those are recorded as answered, in
    /// one write before anything goes out, so a crash after the send can't
    /// let a reload send them again within the hour.
    async fn may_answer_group_refresh(
        &mut self,
        device: &ChatAddress,
        keys: Vec<String>,
    ) -> Result<Vec<bool>> {
        let now = unix_millis();
        self.load_repair_limits().await?;
        self.resent
            .retain(|_, at| now.saturating_sub(*at) < SESSION_RESET_INTERVAL_MS);
        let who = format!("{}.{}", device.name(), device.device_id);
        let answers: Vec<bool> = keys
            .into_iter()
            .map(|key| self.resent.insert((who.clone(), key), now).is_none())
            .collect();
        if answers.iter().any(|answer| *answer) {
            self.write_repair_limits().await?;
        }
        Ok(answers)
    }

    /// Answers a member device's group refresh from this device's send log:
    /// its current key first, then each message it was sent; the rest is
    /// `unavailable`. The key and each named message, sent or not, are
    /// answered to a device at most once an hour.
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
                .contains(&requester)
        {
            return Ok(());
        }
        let context = Self::group_context(&record)?;
        let key_answer = record
            .sender_book
            .as_ref()
            .map(|book| format!("groupKey:{}:{}", group.group_id, book.distribution_id));
        let mut keys: Vec<String> = body
            .send_ids
            .iter()
            .map(|send_id| format!("group:{}:{}", group.group_id, send_id))
            .collect();
        keys.extend(key_answer.clone());
        let mut answers = self.may_answer_group_refresh(from, keys).await?;
        let key_due = key_answer.is_some() && answers.pop().unwrap_or(false);
        // The current key, entered for this device in the book.
        if let (true, Some(book)) = (key_due, record.sender_book.clone()) {
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
            )
            .with_group_context(&context);
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
        for (send_id, due) in body.send_ids.iter().zip(answers) {
            if !due {
                continue;
            }
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
            )
            .with_group_context(&context);
            self.send_to_group_device(&group.group_id, from, &content, rng)
                .await?;
        }
        Ok(())
    }
}
