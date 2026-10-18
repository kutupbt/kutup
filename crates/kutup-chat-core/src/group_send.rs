//! Sending to a group (docs/plans/pairwise-groups.md §1), as Signal-Desktop's
//! `sendToGroupViaSenderKey` does: this device's sender key goes pairwise to
//! every member device that doesn't hold it yet; the message is encrypted
//! once under it and sealed per device; each member account gets its leg.
//!
//! - The members are the group's verified members (bindings checked against
//!   their manifests), and their devices come from their verified manifests,
//!   as for a direct send. This account's other devices are recipients too.
//! - The key is replaced before a send when a device holding it is no longer
//!   a current member device, or it is 90 days old ([`SenderBook`]).
//! - A message is durable before it is sent: its history row and its outbox
//!   entry are written together. A device a leg didn't cover (the server's
//!   `409`) gets the message pairwise, Signal's fallback for a device without
//!   the key; the next send gives it the key.
//! - Delivery is sealed only, with each member's capability from its profile
//!   key in the group; the capability is derived again, never stored.
//! - A send whose last catch-up with the home is a few minutes old catches up
//!   first, so a member another administrator removed meanwhile neither gets
//!   it nor keeps the key (docs/plans/pairwise-groups.md §3).
//! - Every change this device makes is followed by a change notice to the
//!   group (Signal's group update message): its context makes the other
//!   members catch up at once.

use std::collections::BTreeMap;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::content::SenderKeyDistributionBody;
use kutup_chat_proto::group::{decode_group_id, encode, GroupContextV1, GROUP_FORMAT_VERSION};
use kutup_chat_proto::{
    ChatContent, DevicePreKeyBundle, SealedBatchOutcomeV1, SealedBatchRecipientV1,
    SealedBatchSubmissionV1, SealedMessageSubmissionV1, SealedOutgoingEnvelopeV1,
    MAX_SEALED_BATCH_BYTES, MAX_SEALED_BATCH_ITEMS,
};
use rand::{CryptoRng, Rng};

use crate::clock::unix_millis;
use crate::db::{GroupOutboxEntry, GroupOutboxLeg, Pending, SentMessage};
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, BookDevice, GroupRecordV1, GroupStatus, SenderBook};
use crate::group_engine::GroupSync;

/// How many times one leg is retried after the server says the device set
/// changed.
const MAX_LEG_ATTEMPTS: u32 = 5;

/// How many `conflict` answers a leg takes before it fails.
const MAX_LEG_CONFLICTS: u32 = 2;

/// A send catches up with the home first when the last catch-up is older.
pub(crate) const SEND_CATCH_UP_AFTER_MS: i64 = 5 * 60 * 1000;

/// What a group send reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSendSummary {
    pub send_id: String,
    /// Member accounts whose leg was delivered.
    pub delivered: usize,
    /// Member accounts still pending (retried by [`Engine::flush_group_outbox`]).
    pub pending: usize,
    /// Member accounts whose server refused it for good.
    pub failed: usize,
}

/// A member account a group message goes to, with its devices and the
/// capability its profile key gives.
struct Recipient {
    account: String,
    capability: [u8; 16],
    bundles: Vec<DevicePreKeyBundle>,
}

fn group_err(error: group::GroupError) -> ChatError {
    ChatError::Invalid(error.to_string())
}

impl Engine {
    /// The group context a message of `record` carries.
    pub(crate) fn group_context(record: &GroupRecordV1) -> Result<GroupContextV1> {
        let (state, head) = record
            .verified()
            .map_err(group_err)?
            .ok_or_else(|| ChatError::Invalid("the group has no verified state yet".into()))?;
        Ok(GroupContextV1 {
            version: GROUP_FORMAT_VERSION,
            group_id: record.group_id.clone(),
            master_key: record.master_key.0.clone(),
            home: record.home.clone(),
            revision: state.revision,
            chain_hash: encode(&head),
        })
    }

    /// Every account a group message goes to: the verified members, this
    /// account included (its other devices), each with its devices and
    /// capability.
    async fn group_recipients(&mut self, group_id: &str) -> Result<Vec<Recipient>> {
        let members = self.group_members(group_id).await?;
        let me = self.session.account_ref().to_string();
        let mut recipients = Vec::new();
        // This account's other devices hear of its own changes (a leave
        // included) even when it is no longer a member.
        if !members.iter().any(|member| {
            member
                .verified
                .as_ref()
                .is_some_and(|verified| verified.account.to_string() == me)
        }) {
            let profile_key = self.own_profile_key().await?;
            let capability = kutup_chat_proto::derive_delivery_capability(
                &profile_key,
                self.session.account_ref(),
            )
            .map_err(ChatError::Trust)?;
            let own = self.session.device_id();
            let bundles = self
                .sealed_bundles_for_send(&me, &capability)
                .await?
                .into_iter()
                .filter(|bundle| bundle.device_id != own)
                .collect();
            recipients.push(Recipient {
                account: me.clone(),
                capability,
                bundles,
            });
        }
        for member in members {
            let Some(verified) = member.verified else {
                continue;
            };
            let account = verified.account.to_string();
            let capability = kutup_chat_proto::derive_delivery_capability(
                &verified.profile_key,
                &verified.account,
            )
            .map_err(ChatError::Trust)?;
            let bundles = self.sealed_bundles_for_send(&account, &capability).await?;
            let bundles = if account == me {
                // This device itself isn't a recipient.
                let own = self.session.device_id();
                bundles.into_iter().filter(|b| b.device_id != own).collect()
            } else {
                bundles
            };
            recipients.push(Recipient {
                account,
                capability,
                bundles,
            });
        }
        Ok(recipients)
    }

    /// The capability of each member account, derived again from the group's
    /// state (it is never stored).
    pub(crate) async fn group_capabilities(
        &mut self,
        group_id: &str,
    ) -> Result<BTreeMap<String, [u8; 16]>> {
        let mut capabilities = BTreeMap::new();
        let profile_key = self.own_profile_key().await?;
        let me = self.session.account_ref().clone();
        capabilities.insert(
            me.to_string(),
            kutup_chat_proto::derive_delivery_capability(&profile_key, &me)
                .map_err(ChatError::Trust)?,
        );
        for member in self.group_members(group_id).await? {
            if let Some(verified) = member.verified {
                let capability = kutup_chat_proto::derive_delivery_capability(
                    &verified.profile_key,
                    &verified.account,
                )
                .map_err(ChatError::Trust)?;
                capabilities.insert(verified.account.to_string(), capability);
            }
        }
        Ok(capabilities)
    }

    /// Gives this device's sender key to every current device that doesn't
    /// hold it, pairwise; a device is entered in the book once its account
    /// took it. Starts a new key first when the book says so.
    async fn distribute_sender_key<R: Rng + CryptoRng>(
        &mut self,
        record: &mut GroupRecordV1,
        recipients: &[Recipient],
        certificate: &libsignal_protocol::SenderCertificate,
        rng: &mut R,
    ) -> Result<uuid::Uuid> {
        let now = unix_millis();
        let current: Vec<BookDevice> = recipients
            .iter()
            .flat_map(|recipient| {
                recipient.bundles.iter().map(|bundle| BookDevice {
                    account: recipient.account.clone(),
                    device_id: bundle.device_id,
                    registration_id: bundle.registration_id,
                })
            })
            .collect();
        let rotate = record
            .sender_book
            .as_ref()
            .is_none_or(|book| book.must_rotate(now, &current));
        if rotate {
            record.sender_book = Some(SenderBook::new(now));
        }
        let context = Self::group_context(record)?;
        let book = record.sender_book.clone().expect("set above");
        let distribution_id = uuid::Uuid::parse_str(&book.distribution_id)
            .map_err(|_| ChatError::Invalid("the sender book's id isn't a UUID".into()))?;
        let missing = book.missing(&current);
        if missing.is_empty() {
            return Ok(distribution_id);
        }
        let message = self
            .session
            .sender_key_distribution(distribution_id, rng)
            .await?;
        let body = SenderKeyDistributionBody {
            group_id: record.group_id.clone(),
            distribution_id: distribution_id.to_string(),
            message: STANDARD.encode(&message),
        };
        // Each account's devices without the key, in one batch per server.
        let mut sends = Vec::new();
        let mut covered = Vec::new();
        for recipient in recipients {
            let devices: Vec<DevicePreKeyBundle> = recipient
                .bundles
                .iter()
                .filter(|bundle| {
                    missing.iter().any(|device| {
                        device.account == recipient.account && device.device_id == bundle.device_id
                    })
                })
                .cloned()
                .collect();
            if devices.is_empty() {
                continue;
            }
            let send_id = uuid::Uuid::new_v4().to_string();
            // Its context lets a member who doesn't know this device's
            // account yet (it just joined) catch up before taking the key.
            let content = ChatContent::sender_key_distribution_with_id(
                send_id.clone(),
                crate::clock::rfc3339(unix_millis()),
                0,
                &body,
            )
            .with_group_context(&context);
            let sealed = self
                .session
                .seal_pairwise(&recipient.account, &devices, certificate, &content, rng)
                .await?;
            let envelopes = self.sealed_envelopes(sealed);
            sends.push((
                recipient.account.clone(),
                SealedMessageSubmissionV1 {
                    send_id,
                    capability: STANDARD.encode(recipient.capability),
                    envelopes,
                },
            ));
            covered.push(devices);
        }
        let outcomes = self.send_sealed_batches(&sends).await?;
        for (((account, _), devices), outcome) in sends.iter().zip(covered).zip(outcomes) {
            match outcome {
                Some(SealedBatchOutcomeV1::Delivered { .. } | SealedBatchOutcomeV1::Pending) => {
                    let book = record.sender_book.as_mut().expect("set above");
                    for device in &devices {
                        book.devices.push(BookDevice {
                            account: account.clone(),
                            device_id: device.device_id,
                            registration_id: device.registration_id,
                        });
                    }
                    book.devices.sort();
                }
                // The device set moved on: the next send fetches it again.
                Some(SealedBatchOutcomeV1::DeviceMismatch { .. }) => {
                    self.forget_known_devices_of(account);
                }
                // Not taken now (a refused capability, a limit, a network
                // failure): the device stays out of the book and gets the
                // key next time; a message it can't read meanwhile asks for
                // it (§2).
                _ => {}
            }
        }
        self.save_group(record).await?;
        Ok(distribution_id)
    }

    /// Sends `content` to the group `group_id` under the logical id
    /// `send_id`: durable first, then delivered leg by leg. Sending again
    /// under the same id delivers what is left of the first, never a second
    /// message.
    pub async fn send_group_message<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        send_id: &str,
        content: ChatContent,
        rng: &mut R,
    ) -> Result<GroupSendSummary> {
        if content.message_id != send_id {
            return Err(ChatError::Invalid(
                "encrypted content messageId must match transport sendId".into(),
            ));
        }
        if let Some(entry) = self
            .session
            .db()
            .list_group_outbox()
            .await?
            .into_iter()
            .find(|entry| entry.send_id == send_id)
        {
            if entry.group_id != group_id {
                return Err(ChatError::Invalid(format!(
                    "sendId {send_id} is already bound to another conversation"
                )));
            }
            return self.deliver_group_entry(send_id, rng).await;
        }
        if let Some(sent) = self.session.sent_message(send_id).await? {
            let here = kutup_chat_proto::ConversationId::Group {
                group_id: group_id.to_string(),
            };
            if crate::timeline::conversation_of(&sent.peer, &sent.content)? != here {
                return Err(ChatError::Invalid(format!(
                    "sendId {send_id} is already bound to another conversation"
                )));
            }
            // Delivered already (its send log since cleared).
            return Ok(GroupSendSummary {
                send_id: send_id.to_string(),
                delivered: 0,
                pending: 0,
                failed: 0,
            });
        }
        let mut record = self.load_group_record(group_id).await?;
        let stale = record.synced_at_ms.is_none_or(|at| {
            crate::clock::unix_millis().saturating_sub(at) >= SEND_CATCH_UP_AFTER_MS
        });
        if record.status == GroupStatus::Member && stale {
            // Unreachable: sent on the state held.
            if let Ok(GroupSync::Gone) = self.sync_group(group_id).await {
                return Err(ChatError::Invalid(
                    "this account isn't a member of the group".into(),
                ));
            }
            record = self.load_group_record(group_id).await?;
        }
        if record.status != GroupStatus::Member {
            return Err(ChatError::Invalid(
                "this account isn't a member of the group".into(),
            ));
        }
        self.send_group_content(&mut record, send_id, content, rng)
            .await
    }

    /// Tells the group that it changed, after a change this device made: a
    /// hidden notice at the new revision, sent even after this account left.
    /// Best effort: the change itself is made, and members also learn of it
    /// from the next message's context.
    pub(crate) async fn announce_group_change<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) {
        let Ok(mut record) = self.load_group_record(group_id).await else {
            return;
        };
        let send_id = uuid::Uuid::new_v4().to_string();
        let Ok(seq) = self.session.next_sent_seq().await else {
            return;
        };
        let content = ChatContent::group_change_with_id(
            send_id.clone(),
            crate::clock::rfc3339(unix_millis()),
            seq,
        );
        let _ = self
            .send_group_content(&mut record, &send_id, content, rng)
            .await;
    }

    /// Encrypts `content` once under this device's sender key, seals it per
    /// recipient device, and keeps it (history, send log) before delivery. A
    /// change notice is never history; a delete takes the message it deletes
    /// out of the send log at once.
    async fn send_group_content<R: Rng + CryptoRng>(
        &mut self,
        record: &mut GroupRecordV1,
        send_id: &str,
        content: ChatContent,
        rng: &mut R,
    ) -> Result<GroupSendSummary> {
        let group_id = record.group_id.clone();
        let notice = content.kind == kutup_chat_proto::content::kind::GROUP_CHANGE;
        let content = content.with_group_context(&Self::group_context(record)?);
        let plaintext =
            serde_json::to_vec(&content).map_err(|e| ChatError::Content(e.to_string()))?;
        let recipients = self.group_recipients(&group_id).await?;
        let certificate = self.issue_verified_sender_certificate().await?;
        let distribution_id = self
            .distribute_sender_key(record, &recipients, &certificate, rng)
            .await?;
        let message = self
            .session
            .group_encrypt(distribution_id, &plaintext, rng)
            .await?;
        let group_bytes = decode_group_id(&group_id).map_err(ChatError::Invalid)?;
        let hint = if notice {
            libsignal_protocol::ContentHint::Implicit
        } else {
            libsignal_protocol::ContentHint::Resendable
        };
        let mut legs = Vec::with_capacity(recipients.len());
        for recipient in &recipients {
            if recipient.bundles.is_empty() {
                continue;
            }
            let sealed = self
                .session
                .seal_group_message(
                    &recipient.account,
                    &recipient.bundles,
                    &certificate,
                    &group_bytes,
                    &message,
                    hint,
                    rng,
                )
                .await?;
            let envelopes = self.sealed_envelopes(sealed);
            legs.push(GroupOutboxLeg {
                account: recipient.account.clone(),
                devices: envelopes
                    .iter()
                    .map(|envelope| envelope.device_id)
                    .collect(),
                envelopes: serde_json::to_vec(&envelopes)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                delivered: false,
                failed: false,
                conflicts: 0,
            });
        }
        let created_at = unix_millis();
        let mut pending = Pending::default();
        if !notice {
            pending.sent_messages.insert(
                send_id.to_string(),
                SentMessage {
                    send_id: send_id.to_string(),
                    peer: self.session.user().to_string(),
                    sender_device_id: self.session.device_id(),
                    content: plaintext.clone(),
                    created_at,
                    delivered_at: None,
                    delivered: legs.is_empty(),
                    deduplicated: false,
                },
            );
        }
        // Edited or deleted for everyone: the old text is never sent again.
        if let Some(mutation) = content.as_message_mutation() {
            pending
                .group_outbox
                .insert(mutation.target_message_id.clone(), None);
        }
        if !legs.is_empty() {
            pending.group_outbox.insert(
                send_id.to_string(),
                Some(GroupOutboxEntry {
                    send_id: send_id.to_string(),
                    group_id: group_id.clone(),
                    content: plaintext,
                    created_at,
                    legs,
                }),
            );
        }
        self.session.db().apply(&pending).await?;
        self.deliver_group_entry(send_id, rng).await
    }

    /// Delivers what is left of a group message: each leg sealed to its
    /// account; a device set that moved on is amended (pairwise for the
    /// devices it didn't cover) and sent again.
    pub(crate) async fn deliver_group_entry<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        rng: &mut R,
    ) -> Result<GroupSendSummary> {
        let entries = self.session.db().list_group_outbox().await?;
        let Some(mut entry) = entries
            .into_iter()
            .find(|entry| entry.send_id == send_id && entry.legs.iter().any(|leg| !leg.delivered))
        else {
            return Ok(GroupSendSummary {
                send_id: send_id.to_string(),
                delivered: 0,
                pending: 0,
                failed: 0,
            });
        };
        let capabilities = self.group_capabilities(&entry.group_id).await?;
        let content: ChatContent = serde_json::from_slice(&entry.content)
            .map_err(|e| ChatError::Content(e.to_string()))?;
        // Legs still to go, retried after a device mismatch; one left out
        // after a failed batch, a limit or a conflict waits for the next
        // flush.
        let mut retry: Vec<usize> = Vec::new();
        for index in 0..entry.legs.len() {
            if entry.legs[index].delivered {
                continue;
            }
            // A member removed since: nothing more goes to them.
            if capabilities.contains_key(&entry.legs[index].account) {
                retry.push(index);
            } else {
                entry.legs[index].delivered = true;
            }
        }
        for _ in 0..MAX_LEG_ATTEMPTS {
            if retry.is_empty() {
                break;
            }
            let mut sends = Vec::with_capacity(retry.len());
            for &index in &retry {
                let leg = &entry.legs[index];
                sends.push((
                    leg.account.clone(),
                    SealedMessageSubmissionV1 {
                        send_id: send_id.to_string(),
                        capability: STANDARD.encode(capabilities[&leg.account]),
                        envelopes: serde_json::from_slice(&leg.envelopes)
                            .map_err(|e| ChatError::Content(e.to_string()))?,
                    },
                ));
            }
            let outcomes = self.send_sealed_batches(&sends).await?;
            let mut again = Vec::new();
            for ((index, (account, submission)), outcome) in
                retry.iter().copied().zip(sends).zip(outcomes)
            {
                match outcome {
                    // Taken: stored, or queued by this server for the
                    // recipient's.
                    Some(
                        SealedBatchOutcomeV1::Delivered { .. } | SealedBatchOutcomeV1::Pending,
                    ) => {
                        entry.legs[index].delivered = true;
                    }
                    // A capability the member no longer takes (they blocked
                    // this account, or rotated their key), or a server that
                    // takes no sealed mail: the leg is done, as a refused
                    // direct send is; the group refresh brings the new key.
                    Some(
                        SealedBatchOutcomeV1::Unavailable | SealedBatchOutcomeV1::PeerUnsupported,
                    ) => {
                        entry.legs[index].delivered = true;
                    }
                    // Refused for good (too large to queue, or by the
                    // recipient's server): the leg failed, and says so.
                    Some(SealedBatchOutcomeV1::Refused) => {
                        entry.legs[index].delivered = true;
                        entry.legs[index].failed = true;
                    }
                    Some(SealedBatchOutcomeV1::DeviceMismatch { mismatch }) => {
                        let capability = capabilities[&account];
                        self.forget_known_devices_of(&account);
                        let bundles = self
                            .fetch_verified_sealed_bundles(&account, &capability)
                            .await?;
                        let mut envelopes: Vec<SealedOutgoingEnvelopeV1> = submission.envelopes;
                        envelopes.retain(|envelope| {
                            !mismatch.extra_devices.contains(&envelope.device_id)
                                && !mismatch.stale_devices.contains(&envelope.device_id)
                        });
                        let uncovered: Vec<DevicePreKeyBundle> = bundles
                            .into_iter()
                            .filter(|bundle| {
                                mismatch.missing_devices.contains(&bundle.device_id)
                                    || mismatch.stale_devices.contains(&bundle.device_id)
                            })
                            .collect();
                        // A device without the key gets the message pairwise.
                        if !uncovered.is_empty() {
                            let certificate = self.issue_verified_sender_certificate().await?;
                            let sealed = self
                                .session
                                .seal_pairwise(&account, &uncovered, &certificate, &content, rng)
                                .await?;
                            let sealed = self.sealed_envelopes(sealed);
                            envelopes.extend(sealed);
                        }
                        entry.legs[index].devices = envelopes
                            .iter()
                            .map(|envelope| envelope.device_id)
                            .collect();
                        entry.legs[index].envelopes = serde_json::to_vec(&envelopes)
                            .map_err(|e| ChatError::Content(e.to_string()))?;
                        again.push(index);
                    }
                    // Another payload is queued under this send id: once,
                    // the leg waits for it to be answered; a second time it
                    // fails, as it would conflict for ever.
                    Some(SealedBatchOutcomeV1::Conflict) => {
                        let leg = &mut entry.legs[index];
                        leg.conflicts = leg.conflicts.saturating_add(1);
                        if leg.conflicts >= MAX_LEG_CONFLICTS {
                            leg.delivered = true;
                            leg.failed = true;
                        }
                    }
                    // Over a limit, offline or a server error: the leg stays
                    // for a later flush (the same send id is safe to repeat).
                    Some(SealedBatchOutcomeV1::RateLimited) | None => {}
                }
            }
            retry = again;
        }
        let delivered = entry.legs.iter().filter(|leg| leg.delivered).count();
        let pending_legs = entry.legs.len() - delivered;
        let mut pending = Pending::default();
        if pending_legs == 0 {
            // Kept as the send log, without its ciphertexts.
            for leg in &mut entry.legs {
                leg.envelopes.clear();
            }
            pending
                .group_outbox
                .insert(send_id.to_string(), Some(entry.clone()));
            if let Some(mut sent) = self.session.db().load_sent_message(send_id).await? {
                sent.delivered = true;
                sent.delivered_at = Some(unix_millis());
                pending.sent_messages.insert(send_id.to_string(), sent);
            }
        } else {
            pending
                .group_outbox
                .insert(send_id.to_string(), Some(entry.clone()));
        }
        self.session.db().apply(&pending).await?;
        Ok(GroupSendSummary {
            send_id: send_id.to_string(),
            delivered,
            pending: pending_legs,
            failed: entry.legs.iter().filter(|leg| leg.failed).count(),
        })
    }

    /// Delivers every group message still waiting (at start, after a
    /// reconnect).
    pub async fn flush_group_outbox<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<GroupSendSummary>> {
        let mut summaries = Vec::new();
        for entry in self.session.db().list_group_outbox().await? {
            if entry.legs.iter().any(|leg| !leg.delivered) {
                summaries.push(self.deliver_group_entry(&entry.send_id, rng).await?);
            }
        }
        Ok(summaries)
    }

    /// Sends sealed submissions to their accounts in batches, one batch per
    /// destination server cut at the batch limits: each one's outcome, in
    /// order; `None` for one whose batch didn't go (offline, a server error,
    /// an answer that doesn't match it).
    pub(crate) async fn send_sealed_batches(
        &self,
        sends: &[(String, SealedMessageSubmissionV1)],
    ) -> Result<Vec<Option<SealedBatchOutcomeV1>>> {
        let mut outcomes = vec![None; sends.len()];
        // By server, keeping each one's place.
        let mut by_server: BTreeMap<String, Vec<(usize, SealedBatchRecipientV1)>> = BTreeMap::new();
        for (index, (account, submission)) in sends.iter().enumerate() {
            submission.validate().map_err(ChatError::Invalid)?;
            let account = crate::address::parse_account(account)?;
            by_server.entry(account.server.clone()).or_default().push((
                index,
                SealedBatchRecipientV1 {
                    account_id: account.account_id.to_string(),
                    submission: submission.clone(),
                },
            ));
        }
        let transport = Rc::clone(&self.transport);
        for (server, recipients) in by_server {
            for chunk in batch_chunks(recipients) {
                let (places, recipients): (Vec<usize>, Vec<SealedBatchRecipientV1>) =
                    chunk.into_iter().unzip();
                let batch = SealedBatchSubmissionV1 { recipients };
                batch.validate().map_err(ChatError::Invalid)?;
                let Ok(response) = transport.send_sealed_batch(&server, &batch).await else {
                    continue;
                };
                // Answered in order, each naming its recipient and send.
                if response.results.len() != batch.recipients.len() {
                    continue;
                }
                for ((place, recipient), result) in places
                    .into_iter()
                    .zip(&batch.recipients)
                    .zip(response.results)
                {
                    if result.account_id == recipient.account_id
                        && result.send_id == recipient.submission.send_id
                    {
                        outcomes[place] = Some(result.outcome);
                    }
                }
            }
        }
        Ok(outcomes)
    }

    /// The envelopes of a sealed send, any identity change on the way shown
    /// as for a direct send.
    pub(crate) fn sealed_envelopes(
        &mut self,
        sealed: crate::session::SealedGroupSend,
    ) -> Vec<SealedOutgoingEnvelopeV1> {
        if !sealed.safety_number_changes.is_empty() {
            self.events.push_back(crate::ChatEvent::IdentityChanged(
                sealed.safety_number_changes,
            ));
        }
        sealed.envelopes
    }

    fn forget_known_devices_of(&mut self, account: &str) {
        self.known_devices.remove(account);
        self.known_devices_at.remove(account);
        self.manifest_keys_seen.remove(account);
    }
}

/// Cuts one server's recipients into batches within the count and size
/// limits (a single recipient over the size limit still goes alone, and the
/// server answers it).
fn batch_chunks(
    recipients: Vec<(usize, SealedBatchRecipientV1)>,
) -> Vec<Vec<(usize, SealedBatchRecipientV1)>> {
    // The batch's own JSON around its recipients.
    const FRAME_BYTES: usize = 64;
    let mut chunks: Vec<Vec<(usize, SealedBatchRecipientV1)>> = Vec::new();
    let mut size = FRAME_BYTES;
    for item in recipients {
        let weight = serde_json::to_vec(&item.1).map_or(usize::MAX, |bytes| bytes.len() + 1);
        let full = chunks.last().is_none_or(|chunk| {
            chunk.len() >= MAX_SEALED_BATCH_ITEMS
                || size.saturating_add(weight) > MAX_SEALED_BATCH_BYTES
        });
        if full {
            chunks.push(Vec::new());
            size = FRAME_BYTES;
        }
        size = size.saturating_add(weight);
        chunks.last_mut().expect("pushed above").push(item);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(n: usize, body_bytes: usize) -> (usize, SealedBatchRecipientV1) {
        (
            n,
            SealedBatchRecipientV1 {
                account_id: format!("00000000-0000-4000-8000-{n:012x}"),
                submission: SealedMessageSubmissionV1 {
                    send_id: format!("10000000-0000-4000-8000-{n:012x}"),
                    capability: STANDARD.encode([1u8; 16]),
                    envelopes: vec![SealedOutgoingEnvelopeV1 {
                        device_id: 1,
                        registration_id: 1,
                        suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
                        content: "A".repeat(body_bytes),
                    }],
                },
            },
        )
    }

    #[test]
    fn batches_are_cut_at_the_count_and_size_limits_in_order() {
        let chunks = batch_chunks((0..130).map(|n| recipient(n, 10)).collect());
        let sizes: Vec<usize> = chunks.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![64, 64, 2]);
        let order: Vec<usize> = chunks.iter().flatten().map(|(n, _)| *n).collect();
        assert_eq!(order, (0..130).collect::<Vec<_>>());

        // 1.5 MiB each: two fit under 4 MiB, the third starts a new batch.
        let big = 3 * 1024 * 1024 / 2;
        let chunks = batch_chunks((0..3).map(|n| recipient(n, big)).collect());
        let sizes: Vec<usize> = chunks.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![2, 1]);
    }
}
