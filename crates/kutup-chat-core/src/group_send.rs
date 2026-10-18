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
    ChatContent, DevicePreKeyBundle, SealedMessageSubmissionV1, SealedOutgoingEnvelopeV1,
};
use rand::{CryptoRng, Rng};

use crate::clock::unix_millis;
use crate::db::{GroupOutboxEntry, GroupOutboxLeg, Pending, SentMessage};
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, BookDevice, GroupRecordV1, GroupStatus, SenderBook};
use crate::group_engine::GroupSync;
use crate::transport::SendOutcome;

/// How many times one leg is retried after the server says the device set
/// changed.
const MAX_LEG_ATTEMPTS: u32 = 5;

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
        let transport = Rc::clone(&self.transport);
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
            let content = ChatContent::sender_key_distribution_with_id(
                send_id.clone(),
                crate::clock::rfc3339(unix_millis()),
                0,
                &body,
            );
            let envelopes = self
                .session
                .seal_pairwise(&recipient.account, &devices, certificate, &content, rng)
                .await?;
            let request = SealedMessageSubmissionV1 {
                send_id,
                capability: STANDARD.encode(recipient.capability),
                envelopes,
            };
            request.validate().map_err(ChatError::Invalid)?;
            match transport.send_sealed(&recipient.account, &request).await {
                Ok(SendOutcome::Delivered { .. }) => {
                    let book = record.sender_book.as_mut().expect("set above");
                    for device in &devices {
                        book.devices.push(BookDevice {
                            account: recipient.account.clone(),
                            device_id: device.device_id,
                            registration_id: device.registration_id,
                        });
                    }
                    book.devices.sort();
                }
                // The device set moved on: the next send fetches it again.
                Ok(SendOutcome::Mismatch(_)) => {
                    self.forget_known_devices_of(&recipient.account);
                }
                // Not taken now (a refused capability, a network failure): the
                // device stays out of the book and gets the key next time; a
                // message it can't read meanwhile asks for it (§2).
                Ok(SendOutcome::Refused) | Err(_) => {}
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
            let envelopes = self
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
            legs.push(GroupOutboxLeg {
                account: recipient.account.clone(),
                devices: envelopes
                    .iter()
                    .map(|envelope| envelope.device_id)
                    .collect(),
                envelopes: serde_json::to_vec(&envelopes)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                delivered: false,
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
        // Deleted for everyone: nothing of it is sent again.
        if let Some(mutation) = content.as_message_mutation() {
            if mutation.operation == kutup_chat_proto::content::MessageMutationOperation::Delete {
                pending
                    .group_outbox
                    .insert(mutation.target_message_id.clone(), None);
            }
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
            });
        };
        let capabilities = self.group_capabilities(&entry.group_id).await?;
        let content: ChatContent = serde_json::from_slice(&entry.content)
            .map_err(|e| ChatError::Content(e.to_string()))?;
        let transport = Rc::clone(&self.transport);
        for index in 0..entry.legs.len() {
            if entry.legs[index].delivered {
                continue;
            }
            let account = entry.legs[index].account.clone();
            // A member removed since: nothing more goes to them.
            let Some(capability) = capabilities.get(&account).copied() else {
                entry.legs[index].delivered = true;
                continue;
            };
            let mut envelopes: Vec<SealedOutgoingEnvelopeV1> =
                serde_json::from_slice(&entry.legs[index].envelopes)
                    .map_err(|e| ChatError::Content(e.to_string()))?;
            for _ in 0..MAX_LEG_ATTEMPTS {
                let request = SealedMessageSubmissionV1 {
                    send_id: send_id.to_string(),
                    capability: STANDARD.encode(capability),
                    envelopes: envelopes.clone(),
                };
                request.validate().map_err(ChatError::Invalid)?;
                match transport.send_sealed(&account, &request).await {
                    Ok(SendOutcome::Delivered { .. }) => {
                        entry.legs[index].delivered = true;
                        break;
                    }
                    // A refused capability: the member's key changed (they
                    // blocked this account, or rotated it). The leg is done,
                    // as a refused direct send is; the group refresh brings
                    // the new key for the next message.
                    Ok(SendOutcome::Refused) => {
                        entry.legs[index].delivered = true;
                        break;
                    }
                    Ok(SendOutcome::Mismatch(mismatch)) => {
                        self.forget_known_devices_of(&account);
                        let bundles = self
                            .fetch_verified_sealed_bundles(&account, &capability)
                            .await?;
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
                        if !uncovered.is_empty() {
                            let certificate = self.issue_verified_sender_certificate().await?;
                            envelopes.extend(
                                self.session
                                    .seal_pairwise(
                                        &account,
                                        &uncovered,
                                        &certificate,
                                        &content,
                                        rng,
                                    )
                                    .await?,
                            );
                        }
                        entry.legs[index].devices = envelopes
                            .iter()
                            .map(|envelope| envelope.device_id)
                            .collect();
                        entry.legs[index].envelopes = serde_json::to_vec(&envelopes)
                            .map_err(|e| ChatError::Content(e.to_string()))?;
                    }
                    // Offline or a server error: the leg stays for the next flush.
                    Err(_) => break,
                }
            }
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

    fn forget_known_devices_of(&mut self, account: &str) {
        self.known_devices.remove(account);
        self.known_devices_at.remove(account);
    }
}
