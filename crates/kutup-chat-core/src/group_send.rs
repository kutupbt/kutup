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

/// How many mismatch rounds one pass runs (a device set that changes again
/// while it is amended).
const MAX_ROUNDS_PER_PASS: u32 = 5;

/// How many device mismatches a leg takes in all, across passes, before it
/// fails: a recipient whose devices never settle.
const MAX_LEG_MISMATCHES: u32 = 20;

/// The first wait of a leg left waiting, doubled each pass it still waits.
const FIRST_WAIT_MS: i64 = 10 * 1000;

/// The longest wait between two tries of one leg.
const MAX_WAIT_MS: i64 = 15 * 60 * 1000;

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
    /// Why this pass couldn't try it at all (its legs wait for the next).
    pub error: Option<String>,
}

/// What a pairwise copy to one member account needs: the capability its
/// profile key gives, and its pseudonym in the group (named in the copy's
/// context, group_recover.rs).
pub(crate) struct MemberTarget {
    pub(crate) capability: [u8; 16],
    pub(crate) pseudonym: Option<String>,
}

/// `content` naming `pseudonym` in its group context, when it has one: what
/// a copy sent pairwise to one account carries.
pub(crate) fn named_for(content: &ChatContent, pseudonym: Option<&str>) -> ChatContent {
    match content.group_context() {
        Some(context) => content
            .clone()
            .with_group_context(&context.naming(pseudonym)),
        None => content.clone(),
    }
}

/// A member account a group message goes to, with its devices and the
/// capability its profile key gives.
pub(crate) struct Recipient {
    pub(crate) account: String,
    pub(crate) capability: [u8; 16],
    pub(crate) bundles: Vec<DevicePreKeyBundle>,
    /// The account's pseudonym in the group (none for this account's own
    /// devices when it isn't a member any more).
    pub(crate) pseudonym: Option<String>,
}

fn group_err(error: group::GroupError) -> ChatError {
    ChatError::Invalid(error.to_string())
}

/// What a message pass learned for the sender-key book.
enum BookNews {
    /// A message leg was stored for these devices of `account`.
    Delivered { account: String, devices: Vec<u32> },
    /// `account`'s devices changed.
    Mismatch { account: String },
}

/// A leg that waits: tried again after a wait that doubles each pass it
/// still waits, up to [`MAX_WAIT_MS`].
fn wait(leg: &mut GroupOutboxLeg, now: i64) {
    let doublings = leg.waits.min(16);
    let wait = FIRST_WAIT_MS
        .saturating_mul(1i64 << doublings)
        .min(MAX_WAIT_MS);
    leg.waits = leg.waits.saturating_add(1);
    leg.retry_at_ms = Some(now.saturating_add(wait));
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
            recipient_pseudonym: None,
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
                pseudonym: None,
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
                pseudonym: Some(member.pseudonym.clone()),
            });
        }
        Ok(recipients)
    }

    /// Each member account a group's pairwise copies go to (this account
    /// included, for its other devices): its capability and pseudonym.
    pub(crate) async fn group_targets(
        &mut self,
        group_id: &str,
    ) -> Result<BTreeMap<String, MemberTarget>> {
        let mut targets = BTreeMap::new();
        let profile_key = self.own_profile_key().await?;
        let me = self.session.account_ref().clone();
        targets.insert(
            me.to_string(),
            MemberTarget {
                capability: kutup_chat_proto::derive_delivery_capability(&profile_key, &me)
                    .map_err(ChatError::Trust)?,
                pseudonym: None,
            },
        );
        for member in self.group_members(group_id).await? {
            if let Some(verified) = member.verified {
                let capability = kutup_chat_proto::derive_delivery_capability(
                    &verified.profile_key,
                    &verified.account,
                )
                .map_err(ChatError::Trust)?;
                targets.insert(
                    verified.account.to_string(),
                    MemberTarget {
                        capability,
                        pseudonym: Some(member.pseudonym),
                    },
                );
            }
        }
        Ok(targets)
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
        let missing = book.missing(&current, now);
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
            // Its context names the recipient's pseudonym, so a device of
            // theirs that lost the group finds its place again
            // (group_recover.rs).
            let content = ChatContent::sender_key_distribution_with_id(
                send_id.clone(),
                crate::clock::rfc3339(unix_millis()),
                0,
                &body,
            )
            .with_group_context(&context.naming(recipient.pseudonym.as_deref()));
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
        let outcomes = self.send_sealed_batches(&sends).await;
        for (((account, _), devices), outcome) in sends.iter().zip(covered).zip(outcomes) {
            match outcome {
                // Only a key the recipient's server stored is in the book: one
                // queued for another server may yet be refused there (a
                // device mismatch). It is noted as queued, and handed out
                // again only if it hasn't arrived within the hour.
                Some(SealedBatchOutcomeV1::Pending) => {
                    let book = record.sender_book.as_mut().expect("set above");
                    for device in &devices {
                        let device = BookDevice {
                            account: account.clone(),
                            device_id: device.device_id,
                            registration_id: device.registration_id,
                        };
                        book.queued.retain(|queued| queued.device != device);
                        book.queued
                            .push(crate::group::QueuedKey { device, at_ms: now });
                    }
                }
                Some(SealedBatchOutcomeV1::Delivered { .. }) => {
                    let book = record.sender_book.as_mut().expect("set above");
                    for device in &devices {
                        book.devices.push(BookDevice {
                            account: account.clone(),
                            device_id: device.device_id,
                            registration_id: device.registration_id,
                        });
                    }
                    book.devices.sort();
                    let held = book.devices.clone();
                    book.queued.retain(|queued| !held.contains(&queued.device));
                }
                // The device set moved on: the next send fetches it again,
                // and hands the key out at once (nothing of it is queued).
                Some(SealedBatchOutcomeV1::DeviceMismatch { .. }) => {
                    self.forget_known_devices_of(account);
                    let book = record.sender_book.as_mut().expect("set above");
                    book.queued
                        .retain(|queued| &queued.device.account != account);
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
                error: None,
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
        let mut content = content;
        if let Some((state, _)) = record.verified().map_err(group_err)? {
            // What every member's client drops on receipt is never sent.
            if state.terminated {
                return Err(ChatError::Invalid("the group has ended".into()));
            }
            let me = record.pseudonym_text().map_err(group_err)?;
            if state.announcements_only && !state.is_administrator(&me) {
                return Err(ChatError::Invalid(
                    "only administrators send in this group".into(),
                ));
            }
            // The group's timer goes on every visible message, as Signal's
            // `expireTimer`: a receiver keeps each message's own.
            let seconds = crate::group_settings::timer_seconds(&record);
            if seconds > 0 && content.disappearing_after_seconds().is_ok() {
                if let Ok(timed) = content.clone().with_disappearing_after(seconds) {
                    content = timed;
                }
            }
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
        // This account's capability for the multi-recipient route, to the
        // members who don't hold it yet, and the published set when it
        // changed. Best effort: the message goes either way (to this account
        // pairwise meanwhile), and both are tried again with the next one.
        let _ = self
            .hand_out_delivery(record, &recipients, &certificate, rng)
            .await;
        let _ = self.publish_group_capabilities().await;
        let me = self.session.account_ref().to_string();
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
        let mut multi = false;
        for recipient in &recipients {
            if recipient.bundles.is_empty() {
                continue;
            }
            // A member whose capability this device holds goes on the
            // multi-recipient route, sealed once with the others of its
            // server when delivered; this account's own devices (sync copies,
            // as Signal) and the rest go pairwise.
            if recipient.account != me
                && Self::held_capability(record, &recipient.account).is_some()
            {
                multi = true;
                legs.push(GroupOutboxLeg {
                    account: recipient.account.clone(),
                    devices: recipient
                        .bundles
                        .iter()
                        .map(|bundle| bundle.device_id)
                        .collect(),
                    envelopes: Vec::new(),
                    delivered: false,
                    failed: false,
                    mismatches: 0,
                    waits: 0,
                    retry_at_ms: None,
                    queued: false,
                    multi: true,
                });
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
                mismatches: 0,
                waits: 0,
                retry_at_ms: None,
                queued: false,
                multi: false,
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
                    failed_recipients: 0,
                    waiting_recipients: Some(u32::try_from(legs.len()).unwrap_or(u32::MAX)),
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
                    sender_key_message: multi.then(|| message.clone()),
                    implicit: notice,
                }),
            );
        }
        self.session.db().apply(&pending).await?;
        self.deliver_group_entry(send_id, rng).await
    }

    /// Delivers what is left of a group message: each leg sealed to its
    /// account; a device set that moved on is amended (pairwise for the
    /// devices it didn't cover) and sent again. A leg the server only
    /// queued, or that waits (a limit, a conflict, a failure), is tried
    /// again on a later pass, after a growing wait; a leg not taken within
    /// the send log's week fails. What a pass learned is always saved, even
    /// when one leg's amendment fails.
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
                error: None,
            });
        };
        let original = entry.clone();
        let now = unix_millis();
        let targets = self.group_targets(&entry.group_id).await?;
        let content: Option<ChatContent> = serde_json::from_slice(&entry.content).ok();
        let expired = now.saturating_sub(entry.created_at) >= crate::session::GROUP_UNDELIVERED_MS;
        let mut retry: Vec<usize> = Vec::new();
        for index in 0..entry.legs.len() {
            let leg = &mut entry.legs[index];
            if leg.delivered {
                continue;
            }
            if expired || content.is_none() {
                // Not taken within the week (or nothing left to send): it
                // failed, and says so.
                leg.delivered = true;
                leg.failed = true;
            } else if !targets.contains_key(&leg.account) {
                // A member removed since: nothing more goes to them.
                leg.delivered = true;
            } else if leg.retry_at_ms.is_none_or(|at| at <= now) {
                retry.push(index);
            }
        }
        let mut book_news = Vec::new();
        if let Some(content) = content {
            let mut round = 0;
            while !retry.is_empty() && round < MAX_ROUNDS_PER_PASS {
                round += 1;
                let news;
                (retry, news) = self
                    .deliver_round(&mut entry, &retry, &targets, &content, now, rng)
                    .await;
                book_news.extend(news);
            }
        }
        // A pass that changed nothing (every leg still waiting its turn)
        // writes nothing.
        if entry != original {
            self.save_group_entry(&entry).await?;
        }
        let failed = entry.legs.iter().filter(|leg| leg.failed).count();
        let delivered = entry.legs.iter().filter(|leg| leg.delivered).count();
        // What a delivered message leg tells the sender-key book, and what a
        // device mismatch does to it (see `settle_queued_keys`).
        self.settle_queued_keys(&entry.group_id, &book_news).await?;
        Ok(GroupSendSummary {
            send_id: send_id.to_string(),
            delivered: delivered - failed,
            pending: entry.legs.len() - delivered,
            failed,
            error: None,
        })
    }

    /// One batch round over the legs `retry`: their outcomes applied to
    /// `entry`, and the legs amended after a device mismatch returned for
    /// the next round, with what the round tells the sender-key book. An
    /// error on one leg leaves it waiting; it never loses what the round
    /// learned of the others.
    async fn deliver_round<R: Rng + CryptoRng>(
        &mut self,
        entry: &mut GroupOutboxEntry,
        retry: &[usize],
        targets: &BTreeMap<String, MemberTarget>,
        content: &ChatContent,
        now: i64,
        rng: &mut R,
    ) -> (Vec<usize>, Vec<BookNews>) {
        // The multi-recipient legs first: what that route can't take comes
        // back as ordinary legs, for the next round.
        let multi: Vec<usize> = retry
            .iter()
            .copied()
            .filter(|&index| entry.legs[index].multi)
            .collect();
        let (mut again, mut book_news) = if multi.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            self.deliver_multi(entry, &multi, targets, now, rng).await
        };
        let mut sends = Vec::with_capacity(retry.len());
        let mut places = Vec::with_capacity(retry.len());
        for &index in retry {
            if entry.legs[index].multi {
                continue;
            }
            let leg = &mut entry.legs[index];
            let Ok(envelopes) =
                serde_json::from_slice::<Vec<SealedOutgoingEnvelopeV1>>(&leg.envelopes)
            else {
                // Its stored ciphertexts don't read back: it can't go.
                leg.delivered = true;
                leg.failed = true;
                continue;
            };
            sends.push((
                leg.account.clone(),
                SealedMessageSubmissionV1 {
                    send_id: entry.send_id.clone(),
                    capability: STANDARD.encode(targets[&leg.account].capability),
                    envelopes,
                },
            ));
            places.push(index);
        }
        let outcomes = self.send_sealed_batches(&sends).await;
        for ((index, (account, submission)), outcome) in places.into_iter().zip(sends).zip(outcomes)
        {
            match outcome {
                // Stored at the recipient's server.
                Some(SealedBatchOutcomeV1::Delivered { .. }) => {
                    let leg = &mut entry.legs[index];
                    leg.delivered = true;
                    leg.retry_at_ms = None;
                    // A key queued for these devices went ahead of it in the
                    // same queue: they hold it now.
                    book_news.push(BookNews::Delivered {
                        account: account.clone(),
                        devices: leg.devices.clone(),
                    });
                }
                // A capability the member no longer takes (they blocked this
                // account, or rotated their key), or a server that takes no
                // sealed mail: the leg is done, as a refused direct send is
                // (the group refresh brings the new key), and the message
                // says it didn't reach them.
                Some(SealedBatchOutcomeV1::Unavailable | SealedBatchOutcomeV1::PeerUnsupported) => {
                    let leg = &mut entry.legs[index];
                    leg.delivered = true;
                    leg.failed = true;
                }
                // Refused for good (too large to queue, or by the recipient's
                // server): the leg failed, and says so.
                Some(SealedBatchOutcomeV1::Refused) => {
                    let leg = &mut entry.legs[index];
                    leg.delivered = true;
                    leg.failed = true;
                }
                Some(SealedBatchOutcomeV1::DeviceMismatch { .. }) => {
                    // What this account's server held is refused there; the
                    // amended copy is not with it yet.
                    book_news.push(BookNews::Mismatch {
                        account: account.clone(),
                    });
                    let leg = &mut entry.legs[index];
                    leg.queued = false;
                    leg.mismatches = leg.mismatches.saturating_add(1);
                    if leg.mismatches >= MAX_LEG_MISMATCHES {
                        leg.delivered = true;
                        leg.failed = true;
                        continue;
                    }
                    match self
                        .amend_leg(
                            &account,
                            &targets[&account],
                            submission.envelopes,
                            content,
                            rng,
                        )
                        .await
                    {
                        Ok((devices, envelopes)) => {
                            let leg = &mut entry.legs[index];
                            leg.devices = devices;
                            leg.envelopes = envelopes;
                            again.push(index);
                        }
                        // The devices couldn't be read or sealed to now: the
                        // leg waits for a later pass.
                        Err(_) => wait(&mut entry.legs[index], now),
                    }
                }
                // Queued at this account's server for the recipient's (which
                // may still answer that the devices changed), or our own
                // earlier copy still queued under this send id (it will go
                // out; a conflict is counted as taken because this server
                // holds that older copy, and a later device mismatch clears
                // `queued` again): this account's server has it, so the
                // message shows as sent, and the leg is still followed. It
                // waits and goes again later; the same send id is safe to
                // repeat, the server answers from its row.
                Some(SealedBatchOutcomeV1::Pending | SealedBatchOutcomeV1::Conflict) => {
                    let leg = &mut entry.legs[index];
                    leg.queued = true;
                    wait(leg, now);
                }
                // A limit, or no answer: it waits, still sending.
                Some(SealedBatchOutcomeV1::RateLimited) | None => wait(&mut entry.legs[index], now),
            }
        }
        (again, book_news)
    }

    /// One round of the legs `multi` on the multi-recipient route: one
    /// request per destination server, the entry's sender-key message
    /// sealed once for every device of its accounts (sealed sender v2).
    /// What the route can't take turns into ordinary legs, returned for the
    /// next round: a member whose capability was refused (asked for its
    /// current one), one over its budget (later), a destination that didn't
    /// answer (`503`) or a request too large. A device set that moved on
    /// (`409`, `410`) is fetched again and the leg tried again.
    async fn deliver_multi<R: Rng + CryptoRng>(
        &mut self,
        entry: &mut GroupOutboxEntry,
        multi: &[usize],
        targets: &BTreeMap<String, MemberTarget>,
        now: i64,
        rng: &mut R,
    ) -> (Vec<usize>, Vec<BookNews>) {
        let mut again = Vec::new();
        let mut news = Vec::new();
        let mut refused: Vec<String> = Vec::new();
        let hint = if entry.implicit {
            libsignal_protocol::ContentHint::Implicit
        } else {
            libsignal_protocol::ContentHint::Resendable
        };
        let record = self.load_group_record(&entry.group_id).await.ok();
        let certificate = self.issue_verified_sender_certificate().await;
        let group_bytes = decode_group_id(&entry.group_id).ok();
        let (Some(message), Some(record), Ok(certificate), Some(group_bytes)) = (
            entry.sender_key_message.clone(),
            record,
            certificate,
            group_bytes,
        ) else {
            // Nothing to seal it with now: it waits.
            for &index in multi {
                wait(&mut entry.legs[index], now);
            }
            return (again, news);
        };
        // By destination server; a member whose capability this device no
        // longer holds goes pairwise.
        let mut by_server: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut to_pairwise: Vec<usize> = Vec::new();
        for &index in multi {
            let account = entry.legs[index].account.clone();
            match (
                crate::address::parse_account(&account),
                Self::held_capability(&record, &account),
            ) {
                (Ok(parsed), Some(_)) => by_server
                    .entry(parsed.server.clone())
                    .or_default()
                    .push(index),
                _ => to_pairwise.push(index),
            }
        }
        for (server, places) in by_server {
            let mut recipients = Vec::new();
            let mut capabilities = BTreeMap::new();
            let mut going = Vec::new();
            for index in places {
                let account = entry.legs[index].account.clone();
                let Some(target) = targets.get(&account) else {
                    continue;
                };
                let (Ok(parsed), Some(capability)) = (
                    crate::address::parse_account(&account),
                    Self::held_capability(&record, &account),
                ) else {
                    continue;
                };
                match self
                    .sealed_bundles_for_send(&account, &target.capability)
                    .await
                {
                    Ok(bundles) if !bundles.is_empty() => {
                        capabilities.insert(parsed.account_id.clone(), STANDARD.encode(capability));
                        entry.legs[index].devices =
                            bundles.iter().map(|bundle| bundle.device_id).collect();
                        recipients.push((parsed, bundles));
                        going.push(index);
                    }
                    // No devices, or none readable now: it waits.
                    _ => wait(&mut entry.legs[index], now),
                }
            }
            if going.is_empty() {
                continue;
            }
            let sealed = match self
                .session
                .seal_group_multi(&recipients, &certificate, &group_bytes, &message, hint, rng)
                .await
            {
                Ok(sealed) => sealed,
                Err(_) => {
                    for index in going {
                        wait(&mut entry.legs[index], now);
                    }
                    continue;
                }
            };
            if !sealed.safety_number_changes.is_empty() {
                self.events.push_back(crate::ChatEvent::IdentityChanged(
                    sealed.safety_number_changes,
                ));
            }
            let submission = kutup_chat_proto::SealedMultiSubmissionV1 {
                send_id: entry.send_id.clone(),
                payload: STANDARD.encode(&sealed.payload),
                capabilities,
                urgent: true,
            };
            let outcome = Rc::clone(&self.transport)
                .send_sealed_multi(&server, &submission)
                .await;
            let account_id = |index: usize, entry: &GroupOutboxEntry| {
                crate::address::parse_account(&entry.legs[index].account)
                    .map(|parsed| parsed.account_id)
                    .unwrap_or_default()
            };
            match outcome {
                Ok(crate::transport::MultiSendOutcome::Answered { status, response }) => {
                    let stored = status == 200;
                    let moved: Vec<&String> = response
                        .devices
                        .iter()
                        .map(|devices| &devices.account_id)
                        .chain(response.stale.iter().map(|stale| &stale.account_id))
                        .collect();
                    for index in going {
                        let id = account_id(index, entry);
                        let account = entry.legs[index].account.clone();
                        if response.refused.contains(&id) {
                            refused.push(account);
                            to_pairwise.push(index);
                        } else if response.rate_limited.contains(&id) {
                            wait(&mut entry.legs[index], now);
                            to_pairwise.push(index);
                        } else if moved.contains(&&id) {
                            news.push(BookNews::Mismatch {
                                account: account.clone(),
                            });
                            self.forget_known_devices_of(&account);
                            let leg = &mut entry.legs[index];
                            leg.mismatches = leg.mismatches.saturating_add(1);
                            if leg.mismatches >= MAX_LEG_MISMATCHES {
                                to_pairwise.push(index);
                            } else {
                                again.push(index);
                            }
                        } else if stored {
                            let leg = &mut entry.legs[index];
                            leg.delivered = true;
                            leg.retry_at_ms = None;
                            news.push(BookNews::Delivered {
                                account,
                                devices: leg.devices.clone(),
                            });
                        } else {
                            // A 409/410 stored nothing for anyone: again.
                            again.push(index);
                        }
                    }
                }
                // The destination didn't answer in time, or one request
                // can't carry them: pairwise, the durable path.
                Ok(
                    crate::transport::MultiSendOutcome::PeerUnavailable
                    | crate::transport::MultiSendOutcome::TooLarge,
                ) => to_pairwise.extend(going),
                // This address's budget, or no answer: they wait.
                Ok(crate::transport::MultiSendOutcome::RateLimited) | Err(_) => {
                    for index in going {
                        wait(&mut entry.legs[index], now);
                    }
                }
            }
        }
        for index in to_pairwise {
            let leg_retry = entry.legs[index].retry_at_ms;
            match self
                .leg_to_pairwise(
                    entry,
                    index,
                    targets,
                    &message,
                    hint,
                    &certificate,
                    &group_bytes,
                    rng,
                )
                .await
            {
                // Now an ordinary leg: the next round, unless it waits.
                Ok(()) if leg_retry.is_none_or(|at| at <= now) => again.push(index),
                Ok(()) => {}
                Err(_) => wait(&mut entry.legs[index], now),
            }
        }
        if !refused.is_empty() {
            self.ask_for_capabilities(&entry.group_id, &refused, &certificate, rng)
                .await;
        }
        (again, news)
    }

    /// Turns a multi-recipient leg into an ordinary one: the entry's
    /// sender-key message sealed per device of its account.
    #[allow(clippy::too_many_arguments)]
    async fn leg_to_pairwise<R: Rng + CryptoRng>(
        &mut self,
        entry: &mut GroupOutboxEntry,
        index: usize,
        targets: &BTreeMap<String, MemberTarget>,
        message: &[u8],
        hint: libsignal_protocol::ContentHint,
        certificate: &libsignal_protocol::SenderCertificate,
        group_bytes: &[u8; 32],
        rng: &mut R,
    ) -> Result<()> {
        let account = entry.legs[index].account.clone();
        let target = targets
            .get(&account)
            .ok_or_else(|| ChatError::Invalid("no longer a member".into()))?;
        let bundles = self
            .sealed_bundles_for_send(&account, &target.capability)
            .await?;
        let sealed = self
            .session
            .seal_group_message(
                &account,
                &bundles,
                certificate,
                group_bytes,
                message,
                hint,
                rng,
            )
            .await?;
        let envelopes = self.sealed_envelopes(sealed);
        let leg = &mut entry.legs[index];
        leg.devices = envelopes
            .iter()
            .map(|envelope| envelope.device_id)
            .collect();
        leg.envelopes =
            serde_json::to_vec(&envelopes).map_err(|e| ChatError::Content(e.to_string()))?;
        leg.multi = false;
        Ok(())
    }

    /// The members whose capability this device held was refused: dropped
    /// here, and each asked for its current one (best effort; until then
    /// they get pairwise copies).
    async fn ask_for_capabilities<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        accounts: &[String],
        certificate: &libsignal_protocol::SenderCertificate,
        rng: &mut R,
    ) {
        let Ok(mut record) = self.load_group_record(group_id).await else {
            return;
        };
        for account in accounts {
            Self::forget_member_capability(&mut record, account);
        }
        let _ = self.save_group(&record).await;
        let Ok(targets) = self.group_targets(group_id).await else {
            return;
        };
        let body = kutup_chat_proto::content::GroupDeliveryBody {
            group_id: group_id.to_string(),
            capability: None,
            drawn_at_ms: 0,
        };
        let mut sends = Vec::new();
        for account in accounts {
            let Some(target) = targets.get(account) else {
                continue;
            };
            let Ok(bundles) = self
                .sealed_bundles_for_send(account, &target.capability)
                .await
            else {
                continue;
            };
            let send_id = uuid::Uuid::new_v4().to_string();
            let content = ChatContent::group_delivery_with_id(
                send_id.clone(),
                crate::clock::rfc3339(unix_millis()),
                0,
                &body,
            );
            let Ok(sealed) = self
                .session
                .seal_pairwise(account, &bundles, certificate, &content, rng)
                .await
            else {
                continue;
            };
            let envelopes = self.sealed_envelopes(sealed);
            sends.push((
                account.clone(),
                SealedMessageSubmissionV1 {
                    send_id,
                    capability: STANDARD.encode(target.capability),
                    envelopes,
                },
            ));
        }
        let _ = self.send_sealed_batches(&sends).await;
    }

    /// The sender-key book after a message pass: a key queued for devices
    /// whose message leg was then stored went ahead of it in the same queue,
    /// so they hold it; a device mismatch means what was queued may be
    /// refused, so the key goes out again at once. The hour in
    /// [`crate::group::QUEUED_KEY_WAIT_MS`] stays only as the fallback.
    async fn settle_queued_keys(&mut self, group_id: &str, news: &[BookNews]) -> Result<()> {
        if news.is_empty() {
            return Ok(());
        }
        let Ok(mut record) = self.load_group_record(group_id).await else {
            return Ok(());
        };
        let Some(book) = record.sender_book.as_mut() else {
            return Ok(());
        };
        let before = book.clone();
        for item in news {
            match item {
                BookNews::Delivered { account, devices } => {
                    let arrived: Vec<_> = book
                        .queued
                        .iter()
                        .filter(|queued| {
                            &queued.device.account == account
                                && devices.contains(&queued.device.device_id)
                        })
                        .map(|queued| queued.device.clone())
                        .collect();
                    for device in arrived {
                        if !book.devices.contains(&device) {
                            book.devices.push(device);
                        }
                    }
                    book.devices.sort();
                    let held = book.devices.clone();
                    book.queued.retain(|queued| !held.contains(&queued.device));
                }
                BookNews::Mismatch { account } => {
                    book.queued
                        .retain(|queued| &queued.device.account != account);
                }
            }
        }
        if *book != before {
            self.save_group(&record).await?;
        }
        Ok(())
    }

    /// A leg's envelopes after its recipient's devices changed: the
    /// recipient's verified device list decides, never the server's answer.
    /// Envelopes to devices still listed are kept; a listed device without
    /// one gets the message pairwise. Returns the devices and envelopes.
    async fn amend_leg<R: Rng + CryptoRng>(
        &mut self,
        account: &str,
        target: &MemberTarget,
        mut envelopes: Vec<SealedOutgoingEnvelopeV1>,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<(Vec<u32>, Vec<u8>)> {
        self.forget_known_devices_of(account);
        let bundles = self
            .fetch_verified_sealed_bundles(account, &target.capability)
            .await?;
        let listed: std::collections::BTreeMap<u32, u32> = bundles
            .iter()
            .map(|bundle| (bundle.device_id, bundle.registration_id))
            .collect();
        // Kept: a device still listed, under the registration it was sealed to.
        envelopes
            .retain(|envelope| listed.get(&envelope.device_id) == Some(&envelope.registration_id));
        let uncovered: Vec<DevicePreKeyBundle> = bundles
            .into_iter()
            .filter(|bundle| {
                !envelopes
                    .iter()
                    .any(|envelope| envelope.device_id == bundle.device_id)
            })
            .collect();
        if !uncovered.is_empty() {
            let certificate = self.issue_verified_sender_certificate().await?;
            // Pairwise to this account: its context names the account's
            // pseudonym (a new device of theirs may have lost the group).
            let content = named_for(content, target.pseudonym.as_deref());
            let sealed = self
                .session
                .seal_pairwise(account, &uncovered, &certificate, &content, rng)
                .await?;
            envelopes.extend(self.sealed_envelopes(sealed));
        }
        let devices = envelopes
            .iter()
            .map(|envelope| envelope.device_id)
            .collect();
        let bytes =
            serde_json::to_vec(&envelopes).map_err(|e| ChatError::Content(e.to_string()))?;
        Ok((devices, bytes))
    }

    /// Saves `entry` as the pass left it; once no leg waits, as the send
    /// log (without its ciphertexts), and the sent message says how many
    /// accounts it never reached.
    async fn save_group_entry(&mut self, entry: &GroupOutboxEntry) -> Result<()> {
        let mut entry = entry.clone();
        let mut pending = Pending::default();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let done = entry.legs.iter().all(|leg| leg.delivered);
        if done {
            for leg in &mut entry.legs {
                leg.envelopes.clear();
            }
        }
        if let Some(mut sent) = self.session.db().load_sent_message(&entry.send_id).await? {
            let before = sent.clone();
            // How many accounts this account's server hasn't taken it for yet.
            let waiting = entry
                .legs
                .iter()
                .filter(|leg| !leg.delivered && !leg.queued)
                .count();
            sent.waiting_recipients = Some(count(waiting));
            // Shown as soon as it is known, while other legs still wait.
            sent.failed_recipients = count(entry.legs.iter().filter(|leg| leg.failed).count());
            if done {
                sent.delivered = true;
                sent.delivered_at = Some(unix_millis());
            }
            if sent != before {
                pending.sent_messages.insert(entry.send_id.clone(), sent);
            }
        }
        pending
            .group_outbox
            .insert(entry.send_id.clone(), Some(entry));
        self.session.db().apply(&pending).await
    }

    /// Every waiting leg due now, as if its wait had passed (tests).
    #[cfg(test)]
    pub(crate) async fn group_legs_due_now_for_testing(&mut self) -> Result<()> {
        let mut pending = Pending::default();
        for mut entry in self.session.db().list_group_outbox().await? {
            for leg in &mut entry.legs {
                leg.retry_at_ms = None;
            }
            pending
                .group_outbox
                .insert(entry.send_id.clone(), Some(entry));
        }
        self.session.db().apply(&pending).await
    }

    /// Makes a group message as old as `age_ms` (tests).
    #[cfg(test)]
    pub(crate) async fn age_group_entry_for_testing(
        &mut self,
        send_id: &str,
        age_ms: i64,
    ) -> Result<()> {
        let mut pending = Pending::default();
        for mut entry in self.session.db().list_group_outbox().await? {
            if entry.send_id == send_id {
                entry.created_at = unix_millis() - age_ms;
                pending
                    .group_outbox
                    .insert(entry.send_id.clone(), Some(entry));
            }
        }
        self.session.db().apply(&pending).await
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
                // One message that can't go now never holds up the others; it
                // is reported with why, and its legs wait for the next pass.
                match self.deliver_group_entry(&entry.send_id, rng).await {
                    Ok(summary) => summaries.push(summary),
                    Err(error) => summaries.push(GroupSendSummary {
                        send_id: entry.send_id.clone(),
                        delivered: entry
                            .legs
                            .iter()
                            .filter(|leg| leg.delivered && !leg.failed)
                            .count(),
                        pending: entry.legs.iter().filter(|leg| !leg.delivered).count(),
                        failed: entry.legs.iter().filter(|leg| leg.failed).count(),
                        error: Some(error.to_string()),
                    }),
                }
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
    ) -> Vec<Option<SealedBatchOutcomeV1>> {
        let mut outcomes = vec![None; sends.len()];
        // By server, keeping each one's place. One that doesn't validate (or
        // names no account) goes nowhere and is answered `None`; the others
        // still go.
        let mut by_server: BTreeMap<String, Vec<(usize, SealedBatchRecipientV1)>> = BTreeMap::new();
        for (index, (account, submission)) in sends.iter().enumerate() {
            if submission.validate().is_err() {
                continue;
            }
            let Ok(account) = crate::address::parse_account(account) else {
                continue;
            };
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
                if batch.validate().is_err() {
                    continue;
                }
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
        outcomes
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
