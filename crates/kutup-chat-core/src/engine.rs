//! The engine — the async orchestration over a [`Session`] and a
//! [`ChatTransport`]. This is the surface the client apps drive: register a
//! device, send a message (with `409` device-list recovery, backed by the durable
//! `sendId` outbox), and flush the outbox after a restart.
//!
//! It interleaves the two worlds cleanly: `await` the async transport for network
//! I/O, call the synchronous [`Session`] methods (each one atomic transaction) for
//! crypto + store. The `Rc<dyn ChatTransport>` is cloned per call so a network
//! `await` never holds a borrow of `self` across the subsequent store write.

use std::collections::VecDeque;
use std::rc::Rc;

use rand::{CryptoRng, Rng};

use crate::db::{
    ChatDb, ContactRecord, InboundEnvelope, InboundFailureKind, InboundState, OutboxEntry,
    OutboxLeg, SentMessage,
};
use crate::error::{ChatError, Result};
use crate::manifest::{AccountAuthority, ManifestPolicy};
use crate::session::{
    DirectSend, ReceiveOutcome, ReceivedMessage, SendAmendment, SendSummary, Session,
};
use crate::transport::{ChatTransport, SendOutcome};
use kutup_chat_proto::{
    ChatContent, ContactControlBody, ContactState, DeviceManifest, OutgoingEnvelope,
    PreKeyCountResponse, SendMessagesRequest,
};

/// How many send/recovery rounds a single message gets before giving up. Each 409
/// consumes one; a well-behaved server converges in 1–2.
const MAX_SEND_ATTEMPTS: u32 = 5;
/// Drain page size (the contract caps it at 500).
const DRAIN_LIMIT: u32 = 500;
/// Keep used EC prekey private material for late concurrent prekey messages.
const USED_PREKEY_GRACE_MS: i64 = 14 * 24 * 60 * 60 * 1000;

/// The outcome of a reconciliation pass. Decrypt failures remain in the durable
/// inbound journal and are reported here; they are never silently acknowledged.
#[derive(Debug, Default)]
pub struct ReceiveReport {
    pub messages: Vec<ReceivedMessage>,
    /// Logical send ids imported as outgoing history from another linked
    /// device of the local account.
    pub synced: Vec<String>,
    /// Mailbox ids containing authenticated linked-device contact controls.
    pub contact_synced: Vec<String>,
    /// Mailbox ids decrypted and acknowledged without retaining plaintext
    /// because the sender is locally blocked.
    pub suppressed: Vec<String>,
    /// Ids that decrypted but whose plaintext wasn't a valid content document.
    pub undecodable: Vec<String>,
    /// Envelopes retained for repair/retry.
    pub errors: Vec<InboundFailure>,
    /// Authenticated replays that were safely moved directly to pending-ack.
    pub duplicates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InboundFailure {
    pub id: String,
    pub kind: InboundFailureKind,
    pub error: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PreKeyMaintenanceReport {
    pub before: PreKeyCountResponse,
    pub after: PreKeyCountResponse,
    pub uploaded_ec: usize,
    pub uploaded_kyber: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Stopped,
    CatchingUp,
    Live,
    Repairing,
    Degraded,
}

#[derive(Debug, Clone)]
pub enum ChatEvent {
    StateChanged(EngineState),
    MessageReceived(Box<ReceivedMessage>),
    MessageSynced(Box<SentMessage>),
    MessageSent(SendSummary),
    IdentityChanged(Vec<crate::ChatAddress>),
    InboundNeedsAttention {
        id: String,
        kind: InboundFailureKind,
        error: String,
    },
    PreKeysReplenished {
        ec: usize,
        kyber: usize,
    },
}

/// A registered chat client: one device plus its transport.
pub struct Engine {
    session: Session,
    transport: Rc<dyn ChatTransport>,
    state: EngineState,
    events: VecDeque<ChatEvent>,
    manifest_policy: ManifestPolicy,
}

impl Engine {
    /// Wrap an already-registered [`Session`] with a transport.
    pub fn new(session: Session, transport: Rc<dyn ChatTransport>) -> Self {
        Self::with_manifest_policy(session, transport, ManifestPolicy::Required)
    }

    /// Explicit escape hatch for local development against a legacy server.
    /// Any manifest that is present is still fully verified.
    pub fn new_for_development(session: Session, transport: Rc<dyn ChatTransport>) -> Self {
        Self::with_manifest_policy(
            session,
            transport,
            ManifestPolicy::AllowMissingForDevelopment,
        )
    }

    pub fn with_manifest_policy(
        session: Session,
        transport: Rc<dyn ChatTransport>,
        manifest_policy: ManifestPolicy,
    ) -> Self {
        Engine {
            session,
            transport,
            state: EngineState::Stopped,
            events: VecDeque::new(),
            manifest_policy,
        }
    }

    /// Register a brand-new device end-to-end: generate keys, `POST` the
    /// registration, and adopt the server-assigned device id.
    pub async fn register<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let user = user.into();
        // Registration is restart-safe. Generation persists both private keys
        // and the exact request atomically; a retry reuses that journal. Once a
        // device id is committed, initialization simply reopens the install.
        let mut session = match db.load_local_identity().await? {
            Some(local) => match local.device_id {
                Some(device_id) => {
                    return Self::open(db, transport, user, device_id).await;
                }
                None => Session::resume_registration(db, user, local).await?,
            },
            None => {
                // Provisional id 1 is never used for a crypto operation before
                // the server response binds the real id.
                Session::generate(db, user, 1, num_one_time, rng).await?
            }
        };
        let request = session
            .registration()
            .expect("a freshly generated session carries its registration")
            .clone();
        let device_id = transport.register_device(&request).await?;
        session.complete_registration(device_id).await?;
        session.bootstrap_contacts().await?;
        Ok(Engine::new(session, transport))
    }

    /// Reopen an installed device.
    pub async fn open(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
        device_id: u32,
    ) -> Result<Self> {
        Ok(Engine::new(
            Session::open(db, user, device_id).await?,
            transport,
        ))
    }

    /// The underlying device session (for the crypto/store primitives + the
    /// registration payload before it's published).
    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn state(&self) -> EngineState {
        self.state
    }

    /// Drain engine-owned events. Bindings expose this as their callback/stream
    /// boundary without leaking libsignal or storage operations.
    pub fn take_events(&mut self) -> Vec<ChatEvent> {
        self.events.drain(..).collect()
    }

    pub async fn inbound_attention(&self) -> Result<Vec<InboundEnvelope>> {
        Ok(self
            .session
            .pending_inbound()
            .await?
            .into_iter()
            .filter(|item| {
                !matches!(
                    item.state,
                    InboundState::PendingAck | InboundState::DeadLetterPendingAck
                )
            })
            .collect())
    }

    /// Explicitly quarantine an unrecoverable envelope. The durable state is
    /// committed before the server ack; a lost ack is retried by `receive`.
    pub async fn quarantine_inbound(&mut self, id: &str) -> Result<()> {
        self.session.quarantine_inbound(id).await?;
        let ids = vec![id.to_string()];
        self.transport.ack(self.session.device_id(), &ids).await?;
        self.session.finish_acks(&ids).await
    }

    /// Remove a locally retained dead-letter record after the application/user
    /// has inspected or exported it.
    pub async fn resolve_dead_letter(&mut self, id: &str) -> Result<()> {
        self.session.resolve_dead_letter(id).await
    }

    pub fn manifest_policy(&self) -> ManifestPolicy {
        self.manifest_policy
    }

    pub async fn mark_authority_verified(&mut self, peer: &str) -> Result<crate::ManifestTrust> {
        self.session.mark_authority_verified(peer).await
    }

    pub async fn contacts(&self) -> Result<Vec<ContactRecord>> {
        self.session.contacts().await
    }

    /// Apply a contact action locally first, then best-effort its encrypted
    /// linked-device control. A network outage must never undo a local block or
    /// leave an accepted request unusable; the durable sync marker retries.
    pub async fn accept_contact<R: Rng + CryptoRng>(
        &mut self,
        peer: &str,
        sent_at: &str,
        rng: &mut R,
    ) -> Result<ContactRecord> {
        let record = self.session.accept_contact(peer).await?;
        let _ = self.flush_contact_syncs(sent_at, rng).await;
        Ok(self.session.contact(peer).await?.unwrap_or(record))
    }

    pub async fn reject_contact<R: Rng + CryptoRng>(
        &mut self,
        peer: &str,
        sent_at: &str,
        rng: &mut R,
    ) -> Result<ContactRecord> {
        let record = self.session.reject_contact(peer).await?;
        let _ = self.flush_contact_syncs(sent_at, rng).await;
        Ok(self.session.contact(peer).await?.unwrap_or(record))
    }

    pub async fn block_contact<R: Rng + CryptoRng>(
        &mut self,
        peer: &str,
        sent_at: &str,
        rng: &mut R,
    ) -> Result<ContactRecord> {
        let record = self.session.block_contact(peer).await?;
        let _ = self.flush_contact_syncs(sent_at, rng).await;
        Ok(self.session.contact(peer).await?.unwrap_or(record))
    }

    pub async fn unblock_contact<R: Rng + CryptoRng>(
        &mut self,
        peer: &str,
        sent_at: &str,
        rng: &mut R,
    ) -> Result<ContactRecord> {
        let record = self.session.unblock_contact(peer).await?;
        let _ = self.flush_contact_syncs(sent_at, rng).await;
        Ok(self.session.contact(peer).await?.unwrap_or(record))
    }

    /// Retry every explicit contact transition that has not yet reached the
    /// account's other devices. Controls travel through the same authenticated,
    /// E2EE Note-to-Self path as sent transcripts.
    pub async fn flush_contact_syncs<R: Rng + CryptoRng>(
        &mut self,
        sent_at: &str,
        rng: &mut R,
    ) -> Result<()> {
        for contact in self.session.pending_contact_syncs().await? {
            let Some(send_id) = contact.sync_send_id.clone() else {
                continue;
            };
            let seq = self.session.next_sent_seq().await?;
            let content = ChatContent::contact_control_with_id(
                &send_id,
                sent_at,
                seq,
                ContactControlBody::from(&contact),
            );
            let user = self.session.user().to_string();
            self.send(&send_id, &user, &content, rng).await?;
            self.session
                .mark_contact_synced(&contact.peer, contact.revision, contact.source_device_id)
                .await?;
        }
        Ok(())
    }

    /// Add this local device to the account's authenticated device set without
    /// trusting a server-provided list. An existing signed manifest is the only
    /// source for other devices; this device contributes only its own locally
    /// held identity. The server enforces an exact directory match on publish.
    pub async fn sync_own_manifest(
        &mut self,
        authority: &AccountAuthority,
        issued_at: impl Into<String>,
    ) -> Result<DeviceManifest> {
        let transport = Rc::clone(&self.transport);
        let current = transport.fetch_manifest(self.session.user()).await?;
        let local = self.session.manifest_device();
        let issued_at = issued_at.into();
        let candidate = match current {
            None => authority.sign_manifest(1, None, vec![local], issued_at)?,
            Some(current) => {
                current.verify().map_err(ChatError::Trust)?;
                if current.authority_key_id != authority.key_id()
                    || current.self_authority_key != authority.public_key_base64()
                {
                    return Err(ChatError::Trust(
                        "stored account manifest belongs to a different authority".into(),
                    ));
                }
                let mut devices = current.devices.clone();
                match devices.binary_search_by_key(&local.device_id, |device| device.device_id) {
                    Ok(index)
                        if devices[index].identity_key == local.identity_key
                            && devices[index].registration_id == local.registration_id =>
                    {
                        current
                    }
                    location => {
                        match location {
                            Ok(index) => devices[index] = local,
                            Err(index) => devices.insert(index, local),
                        }
                        let next_version = current.version.checked_add(1).ok_or_else(|| {
                            ChatError::Trust("manifest version is exhausted".into())
                        })?;
                        authority.sign_manifest(
                            next_version,
                            Some(current.manifest_hash().map_err(ChatError::Trust)?),
                            devices,
                            issued_at,
                        )?
                    }
                }
            }
        };
        let expected_hash = candidate.manifest_hash().map_err(ChatError::Trust)?;
        let published = transport.publish_manifest(&candidate).await?;
        published.verify().map_err(ChatError::Trust)?;
        if published.manifest_hash().map_err(ChatError::Trust)? != expected_hash {
            return Err(ChatError::Trust(
                "server returned a different manifest after publication".into(),
            ));
        }
        Ok(published)
    }

    /// How many sends are still pending in the durable outbox (undelivered) — for a
    /// "N unsent" indicator, or to decide whether to [`flush_outbox`](Self::flush_outbox).
    pub async fn pending_send_count(&self) -> Result<usize> {
        Ok(self.session.pending_outbox().await?.len())
    }

    /// Flush any crash-surviving key upload, then refill each one-time pool when
    /// it drops below `low_watermark`. Private keys and the exact request become
    /// durable atomically before the network call, so retries never publish keys
    /// the client has lost.
    pub async fn maintain_prekeys<R: Rng + CryptoRng>(
        &mut self,
        low_watermark: usize,
        target: usize,
        rng: &mut R,
    ) -> Result<PreKeyMaintenanceReport> {
        if low_watermark == 0 || target < low_watermark || target > 100 {
            return Err(ChatError::Invalid(
                "prekey policy requires 0 < lowWatermark <= target <= 100".into(),
            ));
        }
        let transport = Rc::clone(&self.transport);
        let device_id = self.session.device_id();
        let mut uploaded_ec = 0;
        let mut uploaded_kyber = 0;

        if let Some(pending) = self.session.pending_prekey_upload().await? {
            uploaded_ec += pending.one_time_pre_keys.len();
            uploaded_kyber += pending.one_time_kyber_pre_keys.len();
            transport.replenish_prekeys(device_id, &pending).await?;
            self.session.complete_prekey_upload().await?;
        }

        let before = transport.prekey_count(device_id).await?;
        let needed_ec = if before.one_time_pre_keys < low_watermark as u64 {
            target.saturating_sub(before.one_time_pre_keys as usize)
        } else {
            0
        };
        let needed_kyber = if before.one_time_kyber_pre_keys < low_watermark as u64 {
            target.saturating_sub(before.one_time_kyber_pre_keys as usize)
        } else {
            0
        };
        if needed_ec > 0 || needed_kyber > 0 {
            let request = self
                .session
                .prepare_prekey_replenishment(needed_ec, needed_kyber, rng)
                .await?;
            transport.replenish_prekeys(device_id, &request).await?;
            self.session.complete_prekey_upload().await?;
            uploaded_ec += request.one_time_pre_keys.len();
            uploaded_kyber += request.one_time_kyber_pre_keys.len();
        }
        let after = if uploaded_ec > 0 || uploaded_kyber > 0 {
            self.events.push_back(ChatEvent::PreKeysReplenished {
                ec: uploaded_ec,
                kyber: uploaded_kyber,
            });
            transport.prekey_count(device_id).await?
        } else {
            before.clone()
        };
        Ok(PreKeyMaintenanceReport {
            before,
            after,
            uploaded_ec,
            uploaded_kyber,
        })
    }

    /// Send `content` to every active device of `peer_user`. Persists the ciphertext
    /// in a durable `sendId`-keyed outbox before hitting the network, recovers from
    /// `409 DeviceListMismatch`, and drops the outbox entry once delivered.
    pub async fn send<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<SendSummary> {
        if content
            .message_id
            .as_deref()
            .is_some_and(|message_id| message_id != send_id)
        {
            return Err(ChatError::Invalid(
                "encrypted content messageId must match transport sendId".into(),
            ));
        }
        // A caller retry with the same logical id must never advance the
        // ratchet again. Reuse the exact durable ciphertext, or no-op if its
        // delivery was already confirmed locally.
        if let Some(entry) = self.session.outbox_entry(send_id).await? {
            if entry.peer != peer_user {
                return Err(ChatError::Invalid(format!(
                    "sendId {send_id} is already bound to {}",
                    entry.peer
                )));
            }
            let summary = self
                .deliver_outbox_entry(entry, SendSummary::default(), rng)
                .await?;
            self.events
                .push_back(ChatEvent::MessageSent(summary.clone()));
            return Ok(summary);
        }
        if let Some(sent) = self.session.sent_message(send_id).await? {
            if sent.peer != peer_user {
                return Err(ChatError::Invalid(format!(
                    "sendId {send_id} is already bound to {}",
                    sent.peer
                )));
            }
            if sent.delivered {
                return Ok(SendSummary {
                    delivered: true,
                    deduplicated: true,
                    attempts: 0,
                    ..SendSummary::default()
                });
            }
            return Err(ChatError::Db(format!(
                "send {send_id} is pending but has no durable ciphertext"
            )));
        }
        let mut summary = SendSummary::default();
        if peer_user == self.session.user() {
            let bundles = self.fetch_verified_bundles(peer_user).await?;
            self.session
                .enqueue_note_to_self(send_id, &bundles, content, &mut summary, rng)
                .await?;
        } else {
            if let Some(contact) = self.session.contact(peer_user).await? {
                match contact.state {
                    ContactState::PendingIncoming => {
                        return Err(ChatError::Invalid(
                            "accept the message request before sending".into(),
                        ))
                    }
                    ContactState::Blocked => {
                        return Err(ChatError::Invalid(
                            "unblock the contact before sending".into(),
                        ))
                    }
                    ContactState::PendingOutgoing
                    | ContactState::Accepted
                    | ContactState::Rejected => {}
                }
            }
            let recipient_bundles = self.fetch_verified_bundles(peer_user).await?;
            let user = self.session.user().to_string();
            let sync_bundles = self.fetch_verified_bundles(&user).await?;
            self.session
                .enqueue_direct_send(
                    DirectSend {
                        send_id,
                        peer_user,
                        recipient_bundles: &recipient_bundles,
                        sync_bundles: &sync_bundles,
                        content,
                    },
                    &mut summary,
                    rng,
                )
                .await?;
        }
        let entry = self
            .session
            .outbox_entry(send_id)
            .await?
            .ok_or_else(|| ChatError::Db(format!("send {send_id} was not durably staged")))?;
        let summary = self.deliver_outbox_entry(entry, summary, rng).await?;
        if !summary.safety_number_changes.is_empty() {
            self.events.push_back(ChatEvent::IdentityChanged(
                summary.safety_number_changes.clone(),
            ));
        }
        self.events
            .push_back(ChatEvent::MessageSent(summary.clone()));
        Ok(summary)
    }

    /// Resend every outbox entry left over from a previous run (e.g. a crash after
    /// the ratchet advanced but before the server confirmed). Idempotent on the
    /// server via `sendId`.
    pub async fn flush_outbox<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<SendSummary>> {
        let mut summaries = Vec::new();
        for entry in self.session.pending_outbox().await? {
            summaries.push(
                self.deliver_outbox_entry(entry, SendSummary::default(), rng)
                    .await?,
            );
        }
        Ok(summaries)
    }

    /// Reconcile the durable local inbound journal and the server mailbox. Raw
    /// ciphertext is journaled before the fetch cursor advances. Only a committed
    /// decrypt (or an explicit dead-letter state) is acknowledged; repairable
    /// failures remain durable and unacked.
    pub async fn receive<R: Rng + CryptoRng>(&mut self, rng: &mut R) -> Result<ReceiveReport> {
        self.set_state(EngineState::CatchingUp);
        let transport = Rc::clone(&self.transport);
        let device_id = self.session.device_id();
        let mut after = self.session.last_cursor().await?;
        let mut report = ReceiveReport::default();

        self.process_inbound(None, &mut report, rng).await?;

        loop {
            let page = transport.drain(device_id, after, DRAIN_LIMIT).await?;
            if page.envelopes.is_empty() {
                break;
            }
            self.session.journal_envelopes(&page.envelopes).await?;
            after = self.session.last_cursor().await?;
            let ids: Vec<String> = page.envelopes.iter().map(|item| item.id.clone()).collect();
            self.process_inbound(Some(&ids), &mut report, rng).await?;
            if !page.more {
                break;
            }
        }
        if report.errors.is_empty() {
            self.set_state(EngineState::Live);
        } else {
            self.set_state(EngineState::Degraded);
        }
        let cutoff = unix_millis().saturating_sub(USED_PREKEY_GRACE_MS);
        self.session.purge_used_pre_keys(cutoff).await?;
        Ok(report)
    }

    async fn process_inbound<R: Rng + CryptoRng>(
        &mut self,
        only_ids: Option<&[String]>,
        report: &mut ReceiveReport,
        rng: &mut R,
    ) -> Result<()> {
        let mut ack_ids = Vec::new();
        for inbound in self.session.pending_inbound().await? {
            if matches!(
                inbound.state,
                InboundState::PendingAck | InboundState::DeadLetterPendingAck
            ) {
                ack_ids.push(inbound.id);
                continue;
            }
            if inbound.state == InboundState::DeadLetter {
                continue;
            }
            if only_ids.is_some_and(|ids| !ids.contains(&inbound.id)) {
                continue;
            }
            let envelope = match serde_json::from_slice(&inbound.envelope) {
                Ok(envelope) => envelope,
                Err(error) => {
                    let error = ChatError::Wire(error.to_string());
                    let state = self
                        .session
                        .record_inbound_failure(inbound.clone(), &error)
                        .await?;
                    debug_assert_eq!(state, InboundState::PendingDecrypt);
                    let kind = error.inbound_failure_kind();
                    report.errors.push(InboundFailure {
                        id: inbound.id,
                        kind,
                        error: error.to_string(),
                    });
                    continue;
                }
            };
            match self.session.receive_envelope(&envelope, rng).await {
                Ok(ReceiveOutcome::Message(message)) => {
                    ack_ids.push(message.id.clone());
                    self.events
                        .push_back(ChatEvent::MessageReceived(Box::new((*message).clone())));
                    report.messages.push(*message);
                }
                Ok(ReceiveOutcome::Synced {
                    mailbox_id,
                    message,
                }) => {
                    ack_ids.push(mailbox_id);
                    report.synced.push(message.send_id.clone());
                    self.events.push_back(ChatEvent::MessageSynced(message));
                }
                Ok(ReceiveOutcome::ContactSynced { id }) => {
                    ack_ids.push(id.clone());
                    report.contact_synced.push(id);
                }
                Ok(ReceiveOutcome::Suppressed { id }) => {
                    ack_ids.push(id.clone());
                    report.suppressed.push(id);
                }
                Ok(ReceiveOutcome::Undecodable { id }) => {
                    ack_ids.push(id.clone());
                    report.undecodable.push(id);
                }
                Err(error) => {
                    let state = self
                        .session
                        .record_inbound_failure(inbound.clone(), &error)
                        .await?;
                    let kind = error.inbound_failure_kind();
                    if state == InboundState::PendingAck {
                        ack_ids.push(inbound.id.clone());
                        report.duplicates.push(inbound.id);
                        continue;
                    }
                    self.events.push_back(ChatEvent::InboundNeedsAttention {
                        id: inbound.id.clone(),
                        kind,
                        error: error.to_string(),
                    });
                    report.errors.push(InboundFailure {
                        id: inbound.id,
                        kind,
                        error: error.to_string(),
                    });
                }
            }
        }

        if !ack_ids.is_empty() {
            self.transport
                .ack(self.session.device_id(), &ack_ids)
                .await?;
            self.session.finish_acks(&ack_ids).await?;
        }
        Ok(())
    }

    fn set_state(&mut self, state: EngineState) {
        if self.state != state {
            self.state = state;
            self.events.push_back(ChatEvent::StateChanged(state));
        }
    }

    /// Deliver every still-pending leg of one logical send. Transcript errors
    /// never turn a confirmed recipient delivery into a user-visible failure;
    /// the durable sync leg remains queued for the next reconciliation.
    async fn deliver_outbox_entry<R: Rng + CryptoRng>(
        &mut self,
        entry: OutboxEntry,
        mut summary: SendSummary,
        rng: &mut R,
    ) -> Result<SendSummary> {
        let primary = if entry.primary_delivered {
            summary.delivered = true;
            summary.deduplicated = true;
            Ok(())
        } else {
            let envelopes = serde_json::from_slice(&entry.envelopes)
                .map_err(|error| ChatError::Db(format!("decode durable outbox: {error}")))?;
            self.deliver_leg(
                &entry.send_id,
                &entry.peer,
                envelopes,
                &mut summary,
                OutboxLeg::Primary,
                rng,
            )
            .await
        };

        let sync = if let Some(sync) = entry.sync {
            let envelopes = serde_json::from_slice(&sync.envelopes)
                .map_err(|error| ChatError::Db(format!("decode durable sync outbox: {error}")))?;
            let user = self.session.user().to_string();
            let mut sync_summary = SendSummary::default();
            self.deliver_leg(
                &entry.send_id,
                &user,
                envelopes,
                &mut sync_summary,
                OutboxLeg::Sync,
                rng,
            )
            .await
        } else {
            Ok(())
        };

        // Attempt both independent legs even if one fails. Recipient delivery
        // remains the user-visible result; a sync failure stays durable and is
        // retried without blocking mailbox reconciliation.
        primary?;
        let _ = sync;
        Ok(summary)
    }

    /// The send/recover loop shared by [`send`](Self::send) and
    /// [`flush_outbox`](Self::flush_outbox): POST one current envelope set; on a
    /// mismatch, re-fetch bundles, amend that durable leg, and retry.
    async fn deliver_leg<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        mut envelopes: Vec<OutgoingEnvelope>,
        summary: &mut SendSummary,
        leg: OutboxLeg,
        rng: &mut R,
    ) -> Result<()> {
        let transport = Rc::clone(&self.transport);
        let self_sync = leg == OutboxLeg::Sync || peer_user == self.session.user();
        // A single-device Note to Self is already durable local outgoing
        // history. There is no recipient mailbox and therefore no network POST.
        if self_sync && envelopes.is_empty() {
            self.session.complete_send(send_id, leg, false).await?;
            summary.delivered = true;
            return Ok(());
        }
        for attempt in 1..=MAX_SEND_ATTEMPTS {
            summary.attempts = attempt;
            let request = SendMessagesRequest {
                sender_device_id: self.session.device_id(),
                send_id: send_id.to_string(),
                envelopes: envelopes.clone(),
                access_token: None,
            };
            let outcome = if self_sync {
                transport.send_sync(&request).await?
            } else {
                transport.send(peer_user, &request).await?
            };
            match outcome {
                SendOutcome::Delivered { deduplicated } => {
                    self.session
                        .complete_send(send_id, leg, deduplicated)
                        .await?;
                    summary.delivered = true;
                    summary.deduplicated = deduplicated;
                    return Ok(());
                }
                SendOutcome::Mismatch(mismatch) => {
                    let bundles = self.fetch_verified_bundles(peer_user).await?;
                    envelopes = self
                        .session
                        .amend_send(
                            SendAmendment {
                                send_id,
                                peer_user,
                                mismatch: &mismatch,
                                bundles: &bundles,
                                leg,
                            },
                            summary,
                            rng,
                        )
                        .await?;
                }
            }
        }
        Err(ChatError::SendNotConverged(MAX_SEND_ATTEMPTS))
    }

    async fn fetch_verified_bundles(
        &mut self,
        peer_user: &str,
    ) -> Result<Vec<kutup_chat_proto::DevicePreKeyBundle>> {
        let transport = Rc::clone(&self.transport);
        let response = if peer_user == self.session.user() {
            transport
                .fetch_sync_bundles(peer_user, self.session.device_id())
                .await?
        } else {
            transport.fetch_bundles(peer_user).await?
        };
        self.session
            .accept_bundle_response(peer_user, response, self.manifest_policy)
            .await
    }
}

fn unix_millis() -> i64 {
    crate::clock::unix_millis()
}
