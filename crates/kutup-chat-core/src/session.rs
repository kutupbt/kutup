//! The local chat device: establishes 1:1 sessions, encrypts/decrypts content,
//! and drives the atomic store transactions the send orchestration is built on.
//! Session and ratchet state live in a durable [`ChatDb`] behind the store
//! adapters (`store.rs`); this is the thin, kutup-typed layer over
//! `process_prekey_bundle` / `message_encrypt` / `message_decrypt`.
//!
//! Every crypto op runs against a [`Pending`](crate::db::Pending) unit of work and
//! commits atomically only on success. The `*_staged` cores make the writes
//! without committing, so the multi-device send path can establish + encrypt for
//! several devices AND stage the durable outbox entry in a **single** transaction
//! — which is what makes a `sendId`-keyed outbox safe (the ciphertext is persisted
//! together with the ratchet advance that produced it). The async network
//! coordination lives one layer up, in [`Engine`](crate::Engine).

use std::rc::Rc;
use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt, message_encrypt, process_prekey_bundle, IdentityChange, IdentityKeyStore,
};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};

use crate::address::ChatAddress;
use crate::db::{
    AuthorityTrust, ChatDb, ContactRecord, InboundEnvelope, InboundFailureKind, InboundState,
    InboxMessage, LocalIdentity, LocalProfile, ManifestTrust, OutboxEntry, OutboxLeg,
    OutboxSyncLeg, PeerProfile, SentMessage, TransparencyMonitorStatus, TransparencyTrust,
};
use crate::error::{ChatError, Result};
use crate::keys;
use crate::manifest::{
    transparency_scope, verify_manifest_publication, verify_transparent_bundle_response,
    ManifestPolicy, TransparencyPolicy,
};
use crate::store::ChatStore;
use crate::wire::{decode_ciphertext, decode_identity_key, encode_ciphertext, to_prekey_bundle};
use kutup_chat_proto::{
    AccountAddress, ChatContent, ContactControlBody, ContactState, DeliveredEnvelope,
    DeviceListMismatch, DevicePreKeyBundle, DirectChatSuiteId, ManifestDevice,
    ManifestTransparencyProof, OutgoingEnvelope, RegisterChatDeviceRequest, ReplenishKeysRequest,
    UserPreKeyBundlesResponse,
};

/// What a [`Engine::send`](crate::Engine::send) did: whether it landed, and any
/// safety-number changes it auto-accepted along the way (the app SHOULD surface
/// those to the user).
#[derive(Debug, Default, Clone)]
pub struct SendSummary {
    /// The server accepted the send to the full device set.
    pub delivered: bool,
    /// The server matched this `sendId` to an earlier delivery (idempotent retry).
    pub deduplicated: bool,
    /// Peers whose identity key changed and was auto-accepted (TOFU re-key) during
    /// 409 recovery — surface a "safety number changed" warning for each.
    pub safety_number_changes: Vec<ChatAddress>,
    /// Number of send/recovery rounds performed.
    pub attempts: u32,
}

pub(crate) struct DirectSend<'a> {
    pub send_id: &'a str,
    pub peer_user: &'a str,
    pub recipient_bundles: &'a [DevicePreKeyBundle],
    pub sync_bundles: &'a [DevicePreKeyBundle],
    pub content: &'a ChatContent,
}

pub(crate) struct SendAmendment<'a> {
    pub send_id: &'a str,
    pub peer_user: &'a str,
    pub mismatch: &'a DeviceListMismatch,
    pub bundles: &'a [DevicePreKeyBundle],
    pub leg: OutboxLeg,
}

/// A decrypted inbound message handed up to the app.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// The sender device (`user`/`user@domain` + device id).
    pub from: ChatAddress,
    pub content: ChatContent,
    /// The mailbox cursor (monotonic order + dedup key).
    pub cursor: u64,
    /// The mailbox id (ack handle).
    pub id: String,
}

/// The result of processing one delivered envelope. Both variants are already
/// persisted (ratchet + raw plaintext + cursor, atomically) and safe to ack; they
/// differ only in whether the plaintext parsed as a `ChatContent`.
pub(crate) enum ReceiveOutcome {
    /// Decrypted and parsed. Boxed — it dwarfs the other variant.
    Message(Box<ReceivedMessage>),
    /// An authenticated encrypted transcript from another device of the local
    /// account. Persisted as outgoing history, never as an incoming bubble.
    Synced {
        mailbox_id: String,
        message: Box<SentMessage>,
    },
    /// A linked-device contact control was authenticated and merged. It is
    /// deliberately absent from user-visible message history.
    ContactSynced { id: String },
    /// An invisible profile-key update (or linked-device transcript of one)
    /// was harvested and persisted.
    ProfileKeyUpdate {
        id: String,
        /// Present only when this device actually adopted a new peer key.
        peer: Option<String>,
    },
    /// A blocked peer's envelope was authenticated, decrypted, ratcheted, and
    /// made safe to ack, but its plaintext was deliberately not retained.
    Suppressed { id: String },
    /// Decrypted but the plaintext wasn't a valid content document (a buggy/newer
    /// sender). Stored raw so it's never dropped; the app renders a placeholder.
    Undecodable { id: String },
}

/// A registered local chat device, backed by a durable store.
pub struct Session {
    store: ChatStore,
    /// The registration payload to publish — `Some` right after [`Session::generate`],
    /// `None` for a device reloaded via [`Session::open`] (already registered).
    registration: Option<RegisterChatDeviceRequest>,
    address: ChatAddress,
}

impl Session {
    /// Generate a new device and persist its private material into `db` atomically.
    /// Returns the session; publish [`Session::registration`] to `POST
    /// /api/chat/device`, then apply the server-assigned id via
    /// [`Session::complete_registration`].
    pub async fn generate<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        user: impl Into<String>,
        device_id: u32,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let material = keys::generate("kutup device", num_one_time, rng)?;
        // Install the whole device (identity + every prekey) in one transaction.
        db.apply(&material.seed).await?;
        let store = ChatStore::attach(db, material.local)?;
        Ok(Session {
            store,
            registration: Some(material.registration),
            address: ChatAddress::local(user, device_id),
        })
    }

    /// Reopen the device already installed in `db` (e.g. on app restart).
    pub async fn open(db: Rc<dyn ChatDb>, user: impl Into<String>, device_id: u32) -> Result<Self> {
        let local = db
            .load_local_identity()
            .await?
            .ok_or_else(|| ChatError::Invalid("no chat device registered in this store".into()))?;
        match local.device_id {
            Some(stored) if stored == device_id => {}
            Some(stored) => {
                return Err(ChatError::Invalid(format!(
                    "chat store belongs to device {stored}, not {device_id}"
                )))
            }
            None => {
                return Err(ChatError::Invalid(
                    "chat device registration is not complete".into(),
                ))
            }
        }
        let store = ChatStore::attach(db, local)?;
        let mut session = Session {
            store,
            registration: None,
            address: ChatAddress::local(user, device_id),
        };
        session.bootstrap_contacts().await?;
        Ok(session)
    }

    /// Resume a fresh install whose exact registration payload was persisted
    /// before the first network attempt.
    pub(crate) async fn resume_registration(
        db: Rc<dyn ChatDb>,
        user: impl Into<String>,
        local: LocalIdentity,
    ) -> Result<Self> {
        if local.device_id.is_some() {
            return Err(ChatError::Invalid(
                "chat device is already registered".into(),
            ));
        }
        let encoded = db.load_pending_registration().await?.ok_or_else(|| {
            ChatError::Db("unregistered chat identity has no registration journal".into())
        })?;
        let registration = serde_json::from_slice(&encoded)
            .map_err(|error| ChatError::Db(format!("decode registration journal: {error}")))?;
        let store = ChatStore::attach(db, local)?;
        Ok(Self {
            store,
            registration: Some(registration),
            address: ChatAddress::local(user, 1),
        })
    }

    /// The registration request to publish, if this session was just generated.
    pub fn registration(&self) -> Option<&RegisterChatDeviceRequest> {
        self.registration.as_ref()
    }

    /// This device's id (server-assigned after registration).
    pub fn device_id(&self) -> u32 {
        self.address.device_id
    }

    pub fn user(&self) -> &str {
        &self.address.user
    }

    /// Public identity and registration id for this local device, suitable for
    /// inclusion in the account-signed device manifest.
    pub fn manifest_device(&self) -> ManifestDevice {
        self.store.local_manifest_device(self.device_id())
    }

    /// Persist and apply the server-assigned device id after registration. The
    /// exact registration journal is cleared in the same atomic commit.
    pub async fn complete_registration(&mut self, device_id: u32) -> Result<()> {
        self.store.stage_registration_complete(device_id);
        self.store.commit().await?;
        self.address.device_id = device_id;
        self.registration = None;
        Ok(())
    }

    // ----- single-op public API (each commits atomically) -----

    /// Establish an outbound session to `peer` from its served prekey bundle.
    pub async fn establish<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
        rng: &mut R,
    ) -> Result<()> {
        match self.establish_staged(peer, bundle, rng).await {
            Ok(()) => self.store.commit().await,
            Err(e) => {
                self.store.discard();
                Err(e)
            }
        }
    }

    /// Encrypt `content` for `peer` into a wire envelope. `recipient_reg_id` is the
    /// peer device's registration id from its bundle. The sender ratchet only
    /// advances durably once a wire envelope is produced.
    pub async fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        recipient_reg_id: u32,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<OutgoingEnvelope> {
        let plaintext =
            serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
        match self
            .encrypt_staged(peer, recipient_reg_id, &plaintext, rng)
            .await
        {
            Ok(env) => {
                self.store.commit().await?;
                Ok(env)
            }
            Err(e) => {
                self.store.discard();
                Err(e)
            }
        }
    }

    /// Decrypt a delivered envelope from `from` into its content document. On a
    /// successful decrypt the ratchet advance is committed **before** the plaintext
    /// is parsed and returned — so a message is never double-consumed, even if its
    /// plaintext turns out to be a content schema we can't parse.
    pub async fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        from: &ChatAddress,
        envelope: &DeliveredEnvelope,
        rng: &mut R,
    ) -> Result<ChatContent> {
        match self.decrypt_bytes_staged(from, envelope, rng).await {
            Ok(plaintext) => {
                self.store.commit().await?;
                serde_json::from_slice(&plaintext).map_err(|e| ChatError::Content(e.to_string()))
            }
            Err(e) => {
                self.store.discard();
                Err(e)
            }
        }
    }

    // ----- receive orchestration -----

    /// Journal a fetched page before attempting any decrypt. The cursor may move
    /// past failed ciphertext only because the complete raw envelope is now a
    /// durable local source of truth for repair and retry.
    pub(crate) async fn journal_envelopes(
        &mut self,
        envelopes: &[DeliveredEnvelope],
    ) -> Result<()> {
        let prior = self.store.db().list_inbound().await?;
        let existing: std::collections::HashSet<String> =
            prior.iter().map(|item| item.id.clone()).collect();
        let mut known_cursors: std::collections::HashSet<u64> =
            prior.iter().map(|item| item.cursor).collect();
        known_cursors.extend(
            self.store
                .db()
                .list_messages()
                .await?
                .into_iter()
                .map(|message| message.cursor),
        );
        for envelope in envelopes {
            if !existing.contains(&envelope.id) {
                let state = if known_cursors.insert(envelope.cursor) {
                    InboundState::PendingDecrypt
                } else {
                    // REST/WS twins share a cursor. The first copy is the crypto
                    // source of truth; later copies are ack-only and never decrypt.
                    InboundState::PendingAck
                };
                self.store.stage_inbound(InboundEnvelope {
                    id: envelope.id.clone(),
                    cursor: envelope.cursor,
                    envelope: serde_json::to_vec(envelope)
                        .map_err(|e| ChatError::Wire(e.to_string()))?,
                    state,
                    attempts: 0,
                    failure_kind: None,
                    last_error: None,
                    received_at: now_millis(),
                });
            }
            self.store.stage_cursor(envelope.cursor);
        }
        self.store.commit().await
    }

    pub(crate) async fn pending_inbound(&self) -> Result<Vec<InboundEnvelope>> {
        self.store.db().list_inbound().await
    }

    pub(crate) async fn record_inbound_failure(
        &mut self,
        mut inbound: InboundEnvelope,
        error: &ChatError,
    ) -> Result<InboundState> {
        let failure_kind = error.inbound_failure_kind();
        inbound.state = if failure_kind == InboundFailureKind::Duplicate {
            InboundState::PendingAck
        } else {
            InboundState::PendingDecrypt
        };
        inbound.attempts = inbound.attempts.saturating_add(1);
        inbound.failure_kind = Some(failure_kind);
        inbound.last_error = Some(error.to_string());
        let state = inbound.state;
        self.store.stage_inbound(inbound);
        self.store.commit().await?;
        Ok(state)
    }

    pub(crate) async fn finish_acks(&mut self, ids: &[String]) -> Result<()> {
        let inbound = self.store.db().list_inbound().await?;
        for id in ids {
            match inbound.iter().find(|item| item.id == *id) {
                Some(item) if item.state == InboundState::DeadLetterPendingAck => {
                    let mut retained = item.clone();
                    retained.state = InboundState::DeadLetter;
                    self.store.stage_inbound(retained);
                }
                _ => self.store.delete_inbound(id),
            }
        }
        self.store.commit().await
    }

    pub(crate) async fn quarantine_inbound(&mut self, id: &str) -> Result<()> {
        let mut inbound = self
            .store
            .db()
            .list_inbound()
            .await?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| ChatError::Invalid(format!("no inbound envelope {id}")))?;
        inbound.state = InboundState::DeadLetterPendingAck;
        self.store.stage_inbound(inbound);
        self.store.commit().await
    }

    pub(crate) async fn resolve_dead_letter(&mut self, id: &str) -> Result<()> {
        let inbound = self
            .store
            .db()
            .list_inbound()
            .await?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| ChatError::Invalid(format!("no inbound envelope {id}")))?;
        if inbound.state != InboundState::DeadLetter {
            return Err(ChatError::Invalid(format!(
                "inbound envelope {id} is not a dead letter"
            )));
        }
        self.store.delete_inbound(id);
        self.store.commit().await
    }

    /// Client-owned contact and message-request state. The delivery service is
    /// intentionally not involved in these reads or transitions.
    pub async fn contacts(&self) -> Result<Vec<ContactRecord>> {
        self.store.db().list_contacts().await
    }

    pub async fn contact(&self, peer: &str) -> Result<Option<ContactRecord>> {
        self.store.db().load_contact(peer).await
    }

    pub async fn local_profile(&self) -> Result<Option<LocalProfile>> {
        self.store.db().load_local_profile().await
    }

    pub async fn peer_profile(&self, peer: &str) -> Result<Option<PeerProfile>> {
        self.store.db().load_peer_profile(peer).await
    }

    pub async fn peer_profiles(&self) -> Result<Vec<PeerProfile>> {
        self.store.db().list_peer_profiles().await
    }

    pub(crate) async fn save_local_profile(&mut self, profile: LocalProfile) -> Result<()> {
        self.store.stage_local_profile(profile);
        self.store.commit().await
    }

    pub(crate) async fn save_peer_profile(&mut self, profile: PeerProfile) -> Result<()> {
        self.store.stage_peer_profile(profile);
        self.store.commit().await
    }

    pub(crate) async fn mark_profile_published(
        &mut self,
        revision: u64,
        source_device_id: u32,
    ) -> Result<()> {
        let Some(mut profile) = self.local_profile().await? else {
            return Ok(());
        };
        if (profile.revision, profile.source_device_id) != (revision, source_device_id) {
            return Ok(());
        }
        profile.pending_upload = None;
        self.store.stage_local_profile(profile);
        self.store.commit().await
    }

    pub(crate) async fn mark_profile_broadcast(
        &mut self,
        revision: u64,
        source_device_id: u32,
    ) -> Result<()> {
        let Some(mut profile) = self.local_profile().await? else {
            return Ok(());
        };
        if (profile.revision, profile.source_device_id) != (revision, source_device_id) {
            return Ok(());
        }
        profile.broadcast_pending = false;
        self.store.stage_local_profile(profile);
        self.store.commit().await
    }

    /// Upgrade stores created before contact state existed without turning
    /// established conversations into message requests after an application
    /// update. Only peers already present in durable history are accepted.
    pub(crate) async fn bootstrap_contacts(&mut self) -> Result<()> {
        let existing = self.store.db().list_contacts().await?;
        let known: std::collections::HashSet<String> =
            existing.into_iter().map(|contact| contact.peer).collect();
        let mut peers = std::collections::BTreeMap::<String, i64>::new();
        for message in self.store.db().list_messages().await? {
            peers
                .entry(message.peer)
                .and_modify(|time| *time = (*time).max(message.received_at))
                .or_insert(message.received_at);
        }
        for message in self.store.db().list_sent_messages().await? {
            peers
                .entry(message.peer)
                .and_modify(|time| *time = (*time).max(message.created_at))
                .or_insert(message.created_at);
        }
        for (peer, updated_at_ms) in peers {
            if peer != self.user() && !known.contains(&peer) {
                self.store.stage_contact(ContactRecord {
                    peer,
                    state: ContactState::Accepted,
                    previous_state: None,
                    revision: 0,
                    source_device_id: 0,
                    updated_at_ms,
                    sync_pending: false,
                    sync_send_id: None,
                });
            }
        }
        self.store.commit().await
    }

    pub async fn accept_contact(&mut self, peer: &str) -> Result<ContactRecord> {
        self.transition_contact(peer, ContactTransition::Accept)
            .await
    }

    pub async fn reject_contact(&mut self, peer: &str) -> Result<ContactRecord> {
        self.transition_contact(peer, ContactTransition::Reject)
            .await
    }

    pub async fn block_contact(&mut self, peer: &str) -> Result<ContactRecord> {
        self.transition_contact(peer, ContactTransition::Block)
            .await
    }

    pub async fn unblock_contact(&mut self, peer: &str) -> Result<ContactRecord> {
        self.transition_contact(peer, ContactTransition::Unblock)
            .await
    }

    pub(crate) async fn pending_contact_syncs(&self) -> Result<Vec<ContactRecord>> {
        Ok(self
            .contacts()
            .await?
            .into_iter()
            .filter(|contact| contact.sync_pending && contact.sync_send_id.is_some())
            .collect())
    }

    pub(crate) async fn mark_contact_synced(
        &mut self,
        peer: &str,
        revision: u64,
        source_device_id: u32,
    ) -> Result<()> {
        let Some(mut contact) = self.contact(peer).await? else {
            return Ok(());
        };
        if (contact.revision, contact.source_device_id) != (revision, source_device_id) {
            return Ok(());
        }
        contact.sync_pending = false;
        contact.sync_send_id = None;
        self.store.stage_contact(contact);
        self.store.commit().await
    }

    async fn transition_contact(
        &mut self,
        peer: &str,
        transition: ContactTransition,
    ) -> Result<ContactRecord> {
        let address = peer
            .parse::<AccountAddress>()
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        if address.canonical() != peer {
            return Err(ChatError::Invalid(
                "contact address is not canonical".into(),
            ));
        }
        if peer == self.user() {
            return Err(ChatError::Invalid(
                "Note to Self has no contact relationship state".into(),
            ));
        }
        let current = self.contact(peer).await?;
        let (state, previous_state, delete_messages) = match (transition, current.as_ref()) {
            (ContactTransition::Accept, Some(contact))
                if matches!(
                    contact.state,
                    ContactState::PendingIncoming | ContactState::PendingOutgoing
                ) =>
            {
                (ContactState::Accepted, None, false)
            }
            (ContactTransition::Accept, Some(contact))
                if contact.state == ContactState::Accepted =>
            {
                return Ok(contact.clone())
            }
            (ContactTransition::Accept, _) => {
                return Err(ChatError::Invalid(
                    "only a pending contact request can be accepted".into(),
                ))
            }
            (ContactTransition::Reject, Some(contact))
                if contact.state == ContactState::PendingIncoming =>
            {
                (ContactState::Rejected, None, true)
            }
            (ContactTransition::Reject, Some(contact))
                if contact.state == ContactState::Rejected =>
            {
                return Ok(contact.clone())
            }
            (ContactTransition::Reject, _) => {
                return Err(ChatError::Invalid(
                    "only an incoming contact request can be rejected".into(),
                ))
            }
            (ContactTransition::Block, Some(contact)) if contact.state == ContactState::Blocked => {
                return Ok(contact.clone())
            }
            (ContactTransition::Block, prior) => (
                ContactState::Blocked,
                Some(prior.map_or(ContactState::Rejected, |contact| contact.state)),
                false,
            ),
            (ContactTransition::Unblock, Some(contact))
                if contact.state == ContactState::Blocked =>
            {
                (
                    contact.previous_state.unwrap_or(ContactState::Rejected),
                    None,
                    false,
                )
            }
            (ContactTransition::Unblock, _) => {
                return Err(ChatError::Invalid("contact is not blocked".into()))
            }
        };
        let revision = current
            .as_ref()
            .map_or(Ok(1), |contact| contact.revision.checked_add(1).ok_or(()))
            .map_err(|()| ChatError::Invalid("contact revision is exhausted".into()))?;
        let source_device_id = self.device_id();
        let record = ContactRecord {
            peer: peer.to_string(),
            state,
            previous_state,
            revision,
            source_device_id,
            updated_at_ms: now_millis(),
            sync_pending: true,
            sync_send_id: Some(contact_sync_send_id(
                peer,
                state,
                revision,
                source_device_id,
            )),
        };
        self.store.stage_contact(record.clone());
        if delete_messages {
            self.store.delete_messages_for_peer(peer);
        }
        self.store.commit().await?;
        Ok(record)
    }

    /// Decrypt one delivered envelope and persist it: the ratchet advance, the raw
    /// plaintext (as an inbox message), and the drain cursor commit together in a
    /// **single** transaction — *then* the engine acks. So a crash after the commit
    /// but before the ack re-drains from a cursor past this message (never
    /// re-decrypting it, which the ratchet couldn't do), and a plaintext we can't
    /// parse is still stored (never dropped). A decrypt *failure* stages nothing.
    pub(crate) async fn receive_envelope<R: Rng + CryptoRng>(
        &mut self,
        envelope: &DeliveredEnvelope,
        rng: &mut R,
    ) -> Result<ReceiveOutcome> {
        let sender = envelope.sender.clone().ok_or(ChatError::MissingSender)?;
        let from = ChatAddress::from_sender(&sender, envelope.sender_device_id)?;
        let plaintext = match self.decrypt_bytes_staged(&from, envelope, rng).await {
            Ok(plaintext) => plaintext,
            Err(e) => {
                self.store.discard();
                return Err(e);
            }
        };
        let parsed = serde_json::from_slice::<ChatContent>(&plaintext).ok();
        let transcript = if sender == self.user() && envelope.sender_device_id != self.device_id() {
            parsed
                .as_ref()
                .and_then(ChatContent::as_sent_transcript)
                .filter(|body| {
                    !body.send_id.is_empty()
                        && body.send_id.len() <= 64
                        && !body.peer.is_empty()
                        && body
                            .content
                            .message_id
                            .as_deref()
                            .is_none_or(|message_id| message_id == body.send_id)
                        && body.content.kind != kutup_chat_proto::content::kind::SENT_TRANSCRIPT
                })
        } else {
            None
        };
        let received_at = now_millis();
        let mut contact_synced = false;
        let mut profile_control = false;
        let mut profile_key_updated: Option<String> = None;
        let mut suppressed = false;
        let synced_message = if let Some(transcript) = transcript {
            if let Some(control) = transcript.content.as_contact_control() {
                if transcript.peer != self.user()
                    || control.source_device_id != envelope.sender_device_id
                    || control.revision == 0
                    || control.peer == self.user()
                    || control.peer.parse::<AccountAddress>().is_err()
                {
                    self.store.discard();
                    return Err(ChatError::Content(
                        "invalid authenticated contact control".into(),
                    ));
                }
                let current = self.contact(&control.peer).await?;
                let incoming_order = (control.revision, control.source_device_id);
                let current_order = current
                    .as_ref()
                    .map(|contact| (contact.revision, contact.source_device_id));
                if current_order.is_none_or(|order| incoming_order > order) {
                    self.store.stage_contact(ContactRecord {
                        peer: control.peer,
                        state: control.state,
                        previous_state: control.previous_state,
                        revision: control.revision,
                        source_device_id: control.source_device_id,
                        updated_at_ms: control.updated_at_ms,
                        sync_pending: false,
                        sync_send_id: None,
                    });
                }
                contact_synced = true;
                None
            } else if transcript.content.kind == kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
            {
                // This is an outgoing control mirrored to a linked device. It
                // must remain invisible, but it does not describe the peer's
                // profile and therefore must not mutate the peer cache.
                profile_control = true;
                None
            } else {
                self.stage_transcript_contact(&transcript.peer, received_at)
                    .await?;
                let message = SentMessage {
                    send_id: transcript.send_id,
                    peer: transcript.peer,
                    content: serde_json::to_vec(&transcript.content)
                        .map_err(|e| ChatError::Content(e.to_string()))?,
                    created_at: transcript.timestamp_ms,
                    delivered_at: Some(received_at),
                    delivered: true,
                    deduplicated: false,
                };
                self.store.stage_sent_message(message.clone());
                Some(message)
            }
        } else {
            let prior_contact = self.contact(&sender).await?;
            let is_profile_update = parsed.as_ref().is_some_and(|content| {
                content.kind == kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
            });
            profile_control = is_profile_update;
            if is_profile_update {
                // A control message alone cannot create or reopen a message
                // request. Only an already outgoing/accepted relationship can
                // authorize its key; blocked and unknown controls are invisible
                // ack-only traffic after authentication.
                suppressed = prior_contact
                    .as_ref()
                    .is_some_and(|contact| contact.state == ContactState::Blocked);
                let can_accept_control = prior_contact.as_ref().is_some_and(|contact| {
                    matches!(
                        contact.state,
                        ContactState::PendingOutgoing | ContactState::Accepted
                    )
                });
                if can_accept_control {
                    if let Some(encoded_key) = parsed
                        .as_ref()
                        .and_then(|content| content.profile_key.as_deref())
                    {
                        if self.stage_peer_profile_key(&sender, encoded_key).await? {
                            profile_key_updated = Some(sender.clone());
                        }
                    }
                }
            } else {
                suppressed = self.stage_incoming_contact(&sender, received_at).await?;
                if !suppressed {
                    if let Some(encoded_key) = parsed
                        .as_ref()
                        .and_then(|content| content.profile_key.as_deref())
                    {
                        if self.stage_peer_profile_key(&sender, encoded_key).await? {
                            profile_key_updated = Some(sender.clone());
                        }
                    }
                    self.store.stage_message(InboxMessage {
                        id: envelope.id.clone(),
                        peer: sender,
                        sender_device_id: envelope.sender_device_id,
                        cursor: envelope.cursor,
                        content: plaintext.clone(),
                        received_at,
                    });
                }
            }
            None
        };
        self.store.stage_inbound(InboundEnvelope {
            id: envelope.id.clone(),
            cursor: envelope.cursor,
            envelope: serde_json::to_vec(envelope).map_err(|e| ChatError::Wire(e.to_string()))?,
            state: InboundState::PendingAck,
            attempts: 0,
            failure_kind: None,
            last_error: None,
            received_at,
        });
        self.store.commit().await?;
        if let Some(message) = synced_message {
            return Ok(ReceiveOutcome::Synced {
                mailbox_id: envelope.id.clone(),
                message: Box::new(message),
            });
        }
        if contact_synced {
            return Ok(ReceiveOutcome::ContactSynced {
                id: envelope.id.clone(),
            });
        }
        if profile_control {
            return Ok(ReceiveOutcome::ProfileKeyUpdate {
                id: envelope.id.clone(),
                peer: profile_key_updated,
            });
        }
        if suppressed {
            return Ok(ReceiveOutcome::Suppressed {
                id: envelope.id.clone(),
            });
        }
        match parsed {
            Some(content) => Ok(ReceiveOutcome::Message(Box::new(ReceivedMessage {
                from,
                content,
                cursor: envelope.cursor,
                id: envelope.id.clone(),
            }))),
            None => Ok(ReceiveOutcome::Undecodable {
                id: envelope.id.clone(),
            }),
        }
    }

    async fn stage_peer_profile_key(&mut self, peer: &str, encoded_key: &str) -> Result<bool> {
        let key = match crate::profile::decode_shared_profile_key(encoded_key) {
            Ok(key) => key,
            // Signal treats a malformed optional harvested key as non-fatal to
            // the user message. Ignore it rather than losing valid plaintext.
            Err(_) => return Ok(false),
        };
        let current = self.peer_profile(peer).await?;
        if current.as_ref().is_some_and(|profile| profile.key == key) {
            return Ok(false);
        }
        // Keep already decrypted presentation data while the new version is
        // fetched. Revision zero forces refresh; an offline rotation should
        // not make a known contact's name/avatar flicker away.
        let (display_name, avatar, avatar_content_type) = current
            .map(|profile| {
                (
                    profile.display_name,
                    profile.avatar,
                    profile.avatar_content_type,
                )
            })
            .unwrap_or((None, None, None));
        self.store.stage_peer_profile(PeerProfile {
            peer: peer.to_string(),
            key,
            display_name,
            avatar,
            avatar_content_type,
            revision: 0,
            source_device_id: 0,
        });
        Ok(true)
    }

    async fn stage_incoming_contact(&mut self, peer: &str, updated_at_ms: i64) -> Result<bool> {
        let current = self.contact(peer).await?;
        let Some(mut contact) = current else {
            self.store.stage_contact(ContactRecord {
                peer: peer.to_string(),
                state: ContactState::PendingIncoming,
                previous_state: None,
                revision: 0,
                source_device_id: 0,
                updated_at_ms,
                sync_pending: false,
                sync_send_id: None,
            });
            return Ok(false);
        };
        match contact.state {
            ContactState::Blocked => Ok(true),
            ContactState::Rejected => {
                contact.revision = next_contact_revision(contact.revision)?;
                contact.source_device_id = self.device_id();
                contact.state = ContactState::PendingIncoming;
                contact.previous_state = None;
                contact.updated_at_ms = updated_at_ms;
                contact.sync_pending = true;
                contact.sync_send_id = Some(contact_sync_send_id(
                    peer,
                    contact.state,
                    contact.revision,
                    contact.source_device_id,
                ));
                self.store.stage_contact(contact);
                Ok(false)
            }
            ContactState::PendingOutgoing => {
                contact.revision = next_contact_revision(contact.revision)?;
                contact.source_device_id = self.device_id();
                contact.state = ContactState::Accepted;
                contact.previous_state = None;
                contact.updated_at_ms = updated_at_ms;
                contact.sync_pending = true;
                contact.sync_send_id = Some(contact_sync_send_id(
                    peer,
                    contact.state,
                    contact.revision,
                    contact.source_device_id,
                ));
                self.store.stage_contact(contact);
                Ok(false)
            }
            ContactState::PendingIncoming | ContactState::Accepted => Ok(false),
        }
    }

    async fn stage_transcript_contact(&mut self, peer: &str, updated_at_ms: i64) -> Result<()> {
        if peer == self.user() {
            return Ok(());
        }
        match self.contact(peer).await? {
            None => self.store.stage_contact(ContactRecord {
                peer: peer.to_string(),
                state: ContactState::PendingOutgoing,
                previous_state: None,
                revision: 0,
                source_device_id: 0,
                updated_at_ms,
                sync_pending: false,
                sync_send_id: None,
            }),
            Some(mut contact)
                if matches!(
                    contact.state,
                    ContactState::Rejected | ContactState::PendingIncoming
                ) =>
            {
                contact.revision = next_contact_revision(contact.revision)?;
                contact.source_device_id = 0;
                contact.state = if contact.state == ContactState::PendingIncoming {
                    ContactState::Accepted
                } else {
                    ContactState::PendingOutgoing
                };
                contact.previous_state = None;
                contact.updated_at_ms = updated_at_ms;
                contact.sync_pending = false;
                contact.sync_send_id = None;
                self.store.stage_contact(contact);
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// The highest mailbox cursor processed — the drain resume point (`?after=`).
    pub(crate) async fn last_cursor(&self) -> Result<Option<u64>> {
        self.store.last_cursor().await
    }

    /// The locally persisted message history (oldest first). Content is the raw
    /// plaintext, so the caller decodes with its own placeholder handling.
    pub async fn history(&self) -> Result<Vec<InboxMessage>> {
        self.store.db().list_messages().await
    }

    /// Durable outbound history, including sends still pending in the outbox.
    pub async fn sent_history(&self) -> Result<Vec<SentMessage>> {
        self.store.db().list_sent_messages().await
    }

    /// Next content sequence for this local device. It becomes durable only
    /// when enqueueing the corresponding ratchet/outbox transaction succeeds.
    pub async fn next_sent_seq(&self) -> Result<u64> {
        self.store
            .db()
            .load_last_sent_seq()
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ChatError::Invalid("outbound sequence is exhausted".into()))
    }

    pub(crate) async fn purge_used_pre_keys(&self, used_before_ms: i64) -> Result<u64> {
        self.store.db().purge_used_pre_keys(used_before_ms).await
    }

    pub(crate) async fn pending_prekey_upload(&self) -> Result<Option<ReplenishKeysRequest>> {
        self.store
            .db()
            .load_pending_prekey_upload()
            .await?
            .map(|request| {
                serde_json::from_slice(&request).map_err(|error| ChatError::Db(error.to_string()))
            })
            .transpose()
    }

    pub(crate) async fn prepare_prekey_replenishment<R: Rng + CryptoRng>(
        &mut self,
        ec_count: usize,
        kyber_count: usize,
        rng: &mut R,
    ) -> Result<ReplenishKeysRequest> {
        if let Some(request) = self.pending_prekey_upload().await? {
            return Ok(request);
        }
        let ec_ids = self.unused_prekey_ids(ec_count, false, rng).await?;
        let kyber_ids = self.unused_prekey_ids(kyber_count, true, rng).await?;
        let material = keys::generate_replenishment(
            &self.store.local_identity_key_pair(),
            &ec_ids,
            &kyber_ids,
            rng,
        )?;
        let serialized = serde_json::to_vec(&material.request)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        for (id, record) in material.pre_keys {
            self.store.stage_generated_pre_key(id, record);
        }
        for (id, record) in material.kyber_pre_keys {
            self.store.stage_generated_kyber_pre_key(id, record);
        }
        self.store.stage_prekey_upload(serialized);
        self.store.commit().await?;
        Ok(material.request)
    }

    pub(crate) async fn complete_prekey_upload(&mut self) -> Result<()> {
        self.store.clear_prekey_upload();
        self.store.commit().await
    }

    async fn unused_prekey_ids<R: Rng + CryptoRng>(
        &self,
        count: usize,
        kyber: bool,
        rng: &mut R,
    ) -> Result<Vec<u32>> {
        let mut ids = std::collections::HashSet::with_capacity(count);
        while ids.len() < count {
            let id = rng.random_range(1_000..=u32::MAX);
            if ids.contains(&id) {
                continue;
            }
            let exists = if kyber {
                self.store.db().load_kyber_pre_key(id).await?.is_some()
            } else {
                self.store.db().load_pre_key(id).await?.is_some()
            };
            if !exists {
                ids.insert(id);
            }
        }
        let mut ids: Vec<u32> = ids.into_iter().collect();
        ids.sort_unstable();
        Ok(ids)
    }

    /// The pinned self-authority and highest manifest observed for `peer`.
    pub async fn manifest_trust(&self, peer: &str) -> Result<Option<ManifestTrust>> {
        self.store.db().load_manifest_trust(peer).await
    }

    /// Highest verified global checkpoint for the peer's homeserver.
    pub async fn transparency_trust(&self, peer: &str) -> Result<Option<TransparencyTrust>> {
        self.transparency_trust_for_scope(&transparency_scope(peer)?)
            .await
    }

    pub async fn transparency_trust_for_scope(
        &self,
        scope: &str,
    ) -> Result<Option<TransparencyTrust>> {
        self.store.db().load_transparency_trust(scope).await
    }

    pub async fn transparency_monitor_status(
        &self,
        scope: &str,
    ) -> Result<Option<TransparencyMonitorStatus>> {
        self.store
            .db()
            .load_transparency_monitor_status(scope)
            .await
    }

    pub(crate) async fn record_transparency_monitor(
        &mut self,
        status: TransparencyMonitorStatus,
        trust: Option<TransparencyTrust>,
    ) -> Result<()> {
        if let Some(trust) = trust {
            self.store.stage_transparency_trust(trust);
        }
        self.store.stage_transparency_monitor_status(status);
        self.store.commit().await
    }

    pub(crate) async fn accept_manifest_publication(
        &mut self,
        account: &str,
        manifest: &kutup_chat_proto::DeviceManifest,
        proof: &ManifestTransparencyProof,
        policy: &TransparencyPolicy,
    ) -> Result<()> {
        let scope = transparency_scope(account)?;
        let prior = self.store.db().load_transparency_trust(&scope).await?;
        let next = verify_manifest_publication(account, manifest, proof, prior.as_ref(), policy)?;
        if prior.as_ref() != Some(&next) {
            self.store.stage_transparency_trust(next);
            self.store.commit().await?;
        }
        Ok(())
    }

    /// Mark the current TOFU authority as verified after the application has
    /// completed an out-of-band safety-number or QR comparison.
    pub async fn mark_authority_verified(&mut self, peer: &str) -> Result<ManifestTrust> {
        let mut trust = self
            .manifest_trust(peer)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("no authority is pinned for {peer}")))?;
        trust.trust = AuthorityTrust::Verified;
        self.store.stage_manifest_trust(trust.clone());
        self.store.commit().await?;
        Ok(trust)
    }

    /// Validate the account-signed device set before any session or ratchet
    /// mutation, then persist the anti-rollback pin.
    pub(crate) async fn accept_bundle_response(
        &mut self,
        peer: &str,
        response: UserPreKeyBundlesResponse,
        policy: ManifestPolicy,
        transparency_policy: &TransparencyPolicy,
    ) -> Result<Vec<DevicePreKeyBundle>> {
        let prior_manifest = self.store.db().load_manifest_trust(peer).await?;
        let scope = transparency_scope(peer)?;
        let prior_transparency = self.store.db().load_transparency_trust(&scope).await?;
        let next = verify_transparent_bundle_response(
            peer,
            &response,
            policy,
            prior_manifest.as_ref(),
            prior_transparency.as_ref(),
            transparency_policy,
        )?;
        let mut changed = false;
        if let Some(manifest) = next.manifest {
            if prior_manifest.as_ref() != Some(&manifest) {
                self.store.stage_manifest_trust(manifest);
                changed = true;
            }
        }
        if let Some(transparency) = next.transparency {
            if prior_transparency.as_ref() != Some(&transparency) {
                self.store.stage_transparency_trust(transparency);
                changed = true;
            }
        }
        if changed {
            self.store.commit().await?;
        }
        Ok(response.devices)
    }

    /// Decrypt to raw plaintext bytes without committing (the staged core shared by
    /// [`decrypt`](Self::decrypt) and [`receive_envelope`](Self::receive_envelope)).
    async fn decrypt_bytes_staged<R: Rng + CryptoRng>(
        &mut self,
        from: &ChatAddress,
        envelope: &DeliveredEnvelope,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let msg = decode_ciphertext(envelope.envelope_type, &envelope.content)?;
        let from_addr = from.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        message_decrypt(
            &msg,
            &from_addr,
            &self_addr,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            rng,
        )
        .await
        .map_err(Into::into)
    }

    // ----- multi-device send orchestration (each is one atomic transaction) -----

    /// Establish (as needed) + encrypt `content` to every device in `bundles`, and
    /// stage a durable outbox entry — all in one transaction. Returns the per-device
    /// envelopes for the transport. Skips the caller's own device.
    pub(crate) async fn enqueue_direct_send<R: Rng + CryptoRng>(
        &mut self,
        send: DirectSend<'_>,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<(Vec<OutgoingEnvelope>, Option<Vec<OutgoingEnvelope>>)> {
        let DirectSend {
            send_id,
            peer_user,
            recipient_bundles,
            sync_bundles,
            content,
        } = send;
        if content.kind == kutup_chat_proto::content::kind::SENT_TRANSCRIPT {
            return Err(ChatError::Invalid(
                "a sent transcript cannot contain another sent transcript".into(),
            ));
        }
        let result = async {
            let plaintext =
                serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
            let recipient_envelopes = self
                .build_send(peer_user, recipient_bundles, &plaintext, summary, rng)
                .await?;
            let created_at = now_millis();
            let transcript =
                ChatContent::sent_transcript(send_id, peer_user, created_at, content.clone());
            let transcript_plaintext =
                serde_json::to_vec(&transcript).map_err(|e| ChatError::Content(e.to_string()))?;
            let mut sync_summary = SendSummary::default();
            let user = self.user().to_string();
            let sync_envelopes = self
                .build_send(
                    &user,
                    sync_bundles,
                    &transcript_plaintext,
                    &mut sync_summary,
                    rng,
                )
                .await?;
            let sync = if sync_envelopes.is_empty() {
                None
            } else {
                Some(OutboxSyncLeg {
                    content: transcript_plaintext,
                    envelopes: serde_json::to_vec(&sync_envelopes)
                        .map_err(|e| ChatError::Content(e.to_string()))?,
                    attempts: 1,
                })
            };
            self.store.stage_outbox(OutboxEntry {
                send_id: send_id.to_string(),
                peer: peer_user.to_string(),
                content: plaintext.clone(),
                envelopes: serde_json::to_vec(&recipient_envelopes)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                attempts: 1,
                created_at,
                primary_delivered: false,
                sync,
            });
            self.store.stage_sent_seq(content.seq);
            self.store.stage_sent_message(SentMessage {
                send_id: send_id.to_string(),
                peer: peer_user.to_string(),
                content: plaintext,
                created_at,
                delivered_at: None,
                delivered: false,
                deduplicated: false,
            });
            self.stage_outgoing_contact(peer_user, created_at).await?;
            self.store.commit().await?;
            Ok((
                recipient_envelopes,
                (!sync_envelopes.is_empty()).then_some(sync_envelopes),
            ))
        }
        .await;
        if result.is_err() {
            self.store.discard();
        }
        result
    }

    async fn stage_outgoing_contact(&mut self, peer: &str, updated_at_ms: i64) -> Result<()> {
        match self.contact(peer).await? {
            None => self.store.stage_contact(ContactRecord {
                peer: peer.to_string(),
                state: ContactState::PendingOutgoing,
                previous_state: None,
                revision: 0,
                source_device_id: self.device_id(),
                updated_at_ms,
                sync_pending: false,
                sync_send_id: None,
            }),
            Some(mut contact) if contact.state == ContactState::Rejected => {
                contact.revision = next_contact_revision(contact.revision)?;
                contact.source_device_id = 0;
                contact.state = ContactState::PendingOutgoing;
                contact.previous_state = None;
                contact.updated_at_ms = updated_at_ms;
                contact.sync_pending = false;
                contact.sync_send_id = None;
                self.store.stage_contact(contact);
            }
            Some(contact)
                if matches!(
                    contact.state,
                    ContactState::PendingIncoming | ContactState::Blocked
                ) =>
            {
                return Err(ChatError::Invalid(
                    "accept the message request or unblock the contact before sending".into(),
                ));
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Encrypt a Note to Self as a sent transcript for every other linked
    /// device while persisting the original content as local outgoing history.
    /// The wrapper and ratchet advances share the same atomic outbox commit.
    pub(crate) async fn enqueue_note_to_self<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        bundles: &[DevicePreKeyBundle],
        content: &ChatContent,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        if content.kind == kutup_chat_proto::content::kind::SENT_TRANSCRIPT {
            return Err(ChatError::Invalid(
                "a sent transcript cannot contain another sent transcript".into(),
            ));
        }
        let created_at = now_millis();
        let transcript =
            ChatContent::sent_transcript(send_id, self.user(), created_at, content.clone());
        let transcript_plaintext =
            serde_json::to_vec(&transcript).map_err(|e| ChatError::Content(e.to_string()))?;
        let user = self.user().to_string();
        match self
            .build_send(&user, bundles, &transcript_plaintext, summary, rng)
            .await
        {
            Ok(envelopes) => {
                let content_plaintext =
                    serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
                self.store.stage_outbox(OutboxEntry {
                    send_id: send_id.to_string(),
                    peer: user.clone(),
                    content: transcript_plaintext,
                    envelopes: serde_json::to_vec(&envelopes)
                        .map_err(|e| ChatError::Content(e.to_string()))?,
                    attempts: 1,
                    created_at,
                    primary_delivered: false,
                    sync: None,
                });
                self.store.stage_sent_seq(content.seq);
                self.store.stage_sent_message(SentMessage {
                    send_id: send_id.to_string(),
                    peer: user,
                    content: content_plaintext,
                    created_at,
                    delivered_at: None,
                    delivered: false,
                    deduplicated: false,
                });
                self.store.commit().await?;
                Ok(envelopes)
            }
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Apply a `409 DeviceListMismatch` to a pending send: drop extra devices,
    /// establish + encrypt for missing ones, and re-key + re-encrypt stale ones
    /// (accepting the reinstalled peer's new identity, TOFU — recording each such
    /// safety-number change into `summary`). Reuses the stored plaintext so already
    /// -encrypted devices keep their ciphertext (their ratchet is not advanced
    /// twice). Persists the updated outbox atomically and returns the corrected set.
    pub(crate) async fn amend_send<R: Rng + CryptoRng>(
        &mut self,
        amendment: SendAmendment<'_>,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        match self.build_amendment(amendment, summary, rng).await {
            Ok(envelopes) => {
                self.store.commit().await?;
                Ok(envelopes)
            }
            Err(e) => {
                self.store.discard();
                Err(e)
            }
        }
    }

    /// Mark one delivery leg complete. The logical outbox record remains until
    /// both the primary recipient and optional linked-device transcript legs
    /// have completed.
    pub(crate) async fn complete_send(
        &mut self,
        send_id: &str,
        leg: OutboxLeg,
        deduplicated: bool,
    ) -> Result<()> {
        let mut entry = self
            .store
            .db()
            .load_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Db(format!("send {send_id} has no outbox record")))?;
        match leg {
            OutboxLeg::Primary => {
                let mut message = self
                    .store
                    .db()
                    .load_sent_message(send_id)
                    .await?
                    .ok_or_else(|| {
                        ChatError::Db(format!("send {send_id} has no history record"))
                    })?;
                message.delivered = true;
                message.deduplicated = deduplicated;
                message.delivered_at = Some(now_millis());
                self.store.stage_sent_message(message);
                if entry.sync.is_some() {
                    entry.primary_delivered = true;
                    self.store.stage_outbox(entry);
                } else {
                    self.store.delete_outbox(send_id);
                }
            }
            OutboxLeg::Sync => {
                if entry.primary_delivered {
                    self.store.delete_outbox(send_id);
                } else {
                    entry.sync = None;
                    self.store.stage_outbox(entry);
                }
            }
        }
        self.store.commit().await
    }

    pub(crate) async fn outbox_entry(&self, send_id: &str) -> Result<Option<OutboxEntry>> {
        self.store.db().load_outbox(send_id).await
    }

    pub(crate) async fn sent_message(&self, send_id: &str) -> Result<Option<SentMessage>> {
        self.store.db().load_sent_message(send_id).await
    }

    /// Every still-pending outbound send (for resend-on-startup).
    pub(crate) async fn pending_outbox(&self) -> Result<Vec<OutboxEntry>> {
        self.store.db().list_outbox().await
    }

    // ----- staged (non-committing) cores -----

    async fn build_send<R: Rng + CryptoRng>(
        &mut self,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
        plaintext: &[u8],
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        let mut envelopes = Vec::with_capacity(bundles.len());
        for bundle in bundles {
            let peer = ChatAddress::from_sender(peer_user, bundle.device_id)?;
            if self.is_self(&peer) {
                continue;
            }
            envelopes.push(
                self.seal_device(&peer, bundle, plaintext, summary, rng)
                    .await?,
            );
        }
        Ok(envelopes)
    }

    async fn build_amendment<R: Rng + CryptoRng>(
        &mut self,
        amendment: SendAmendment<'_>,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        let SendAmendment {
            send_id,
            peer_user,
            mismatch,
            bundles,
            leg,
        } = amendment;
        let mut entry = self
            .store
            .db()
            .load_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid(format!("no outbox entry for send {send_id}")))?;
        let (content, encoded_envelopes) = match leg {
            OutboxLeg::Primary => (entry.content.clone(), entry.envelopes.clone()),
            OutboxLeg::Sync => {
                let sync = entry.sync.as_ref().ok_or_else(|| {
                    ChatError::Invalid(format!("send {send_id} has no pending sync leg"))
                })?;
                (sync.content.clone(), sync.envelopes.clone())
            }
        };
        let mut envelopes: Vec<OutgoingEnvelope> = serde_json::from_slice(&encoded_envelopes)
            .map_err(|e| ChatError::Content(e.to_string()))?;

        // Extra devices aren't real: drop their ciphertext and archive the session.
        for &device_id in &mismatch.extra_devices {
            envelopes.retain(|e| e.device_id != device_id);
            let peer = ChatAddress::from_sender(peer_user, device_id)?;
            self.store.delete_session(&peer.to_protocol()?.to_string());
        }

        // Missing devices: establish + encrypt from a fresh bundle, append.
        for &device_id in &mismatch.missing_devices {
            let peer = ChatAddress::from_sender(peer_user, device_id)?;
            if self.is_self(&peer) {
                continue;
            }
            let bundle = find_bundle(bundles, device_id)?;
            let env = self
                .seal_device(&peer, bundle, &content, summary, rng)
                .await?;
            envelopes.retain(|e| e.device_id != device_id);
            envelopes.push(env);
        }

        // Stale devices (reinstalled): accept the changed identity (TOFU re-key),
        // archive the old session, re-establish, re-encrypt. Surface the change.
        for &device_id in &mismatch.stale_devices {
            let peer = ChatAddress::from_sender(peer_user, device_id)?;
            if self.is_self(&peer) {
                continue;
            }
            let bundle = find_bundle(bundles, device_id)?;
            if self.accept_identity_staged(&peer, bundle).await? {
                summary.safety_number_changes.push(peer.clone());
            }
            self.store.delete_session(&peer.to_protocol()?.to_string());
            self.establish_staged(&peer, bundle, rng).await?;
            let env = self
                .encrypt_staged(&peer, bundle.registration_id, &content, rng)
                .await?;
            envelopes.retain(|e| e.device_id != device_id);
            envelopes.push(env);
        }

        let encoded =
            serde_json::to_vec(&envelopes).map_err(|e| ChatError::Content(e.to_string()))?;
        match leg {
            OutboxLeg::Primary => {
                entry.envelopes = encoded;
                entry.attempts += 1;
            }
            OutboxLeg::Sync => {
                let sync = entry.sync.as_mut().ok_or_else(|| {
                    ChatError::Invalid(format!("send {send_id} has no pending sync leg"))
                })?;
                sync.envelopes = encoded;
                sync.attempts += 1;
            }
        }
        self.store.stage_outbox(entry);
        Ok(envelopes)
    }

    /// Establish-if-needed + encrypt one device (staged). Reuses an existing
    /// session (never re-establishing it — that would reset the ratchet) *unless*
    /// the served bundle's identity key differs from the stored one, i.e. the peer
    /// reinstalled: then it re-keys (TOFU-accept + fresh session) and flags the
    /// safety-number change, so we never encrypt to a stale identity with the new
    /// registration id (which the server would accept but the peer couldn't read).
    async fn seal_device<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
        plaintext: &[u8],
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<OutgoingEnvelope> {
        let key = peer.to_protocol()?.to_string();
        if self.store.has_session(&key).await? {
            let served = decode_identity_key(&bundle.identity_key)?
                .serialize()
                .to_vec();
            if self.store.peer_identity(&key).await?.as_deref() != Some(served.as_slice()) {
                // Reinstalled peer: re-key rather than reuse the stale session.
                if self.accept_identity_staged(peer, bundle).await? {
                    summary.safety_number_changes.push(peer.clone());
                }
                self.store.delete_session(&key);
                self.establish_staged(peer, bundle, rng).await?;
            }
        } else {
            self.establish_staged(peer, bundle, rng).await?;
        }
        self.encrypt_staged(peer, bundle.registration_id, plaintext, rng)
            .await
    }

    async fn establish_staged<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
        rng: &mut R,
    ) -> Result<()> {
        let pkb = to_prekey_bundle(bundle)?;
        let peer_addr = peer.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        process_prekey_bundle(
            &peer_addr,
            &self_addr,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &pkb,
            now(),
            rng,
        )
        .await
        .map_err(Into::into)
    }

    async fn encrypt_staged<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        recipient_reg_id: u32,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<OutgoingEnvelope> {
        let peer_addr = peer.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        let msg = message_encrypt(
            plaintext,
            &peer_addr,
            &self_addr,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            now(),
            rng,
        )
        .await?;
        let (envelope_type, content) = encode_ciphertext(&msg)?;
        Ok(OutgoingEnvelope {
            device_id: peer.device_id,
            registration_id: recipient_reg_id,
            envelope_type,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content,
        })
    }

    /// Accept a peer device's identity from its bundle (TOFU), returning whether an
    /// existing key was *replaced* (i.e. a safety-number change). Staged; the caller
    /// re-establishes and commits.
    async fn accept_identity_staged(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
    ) -> Result<bool> {
        let new_identity = decode_identity_key(&bundle.identity_key)?;
        let peer_addr = peer.to_protocol()?;
        let change = self
            .store
            .identity_store
            .save_identity(&peer_addr, &new_identity)
            .await?;
        Ok(matches!(change, IdentityChange::ReplacedExisting))
    }

    fn is_self(&self, peer: &ChatAddress) -> bool {
        peer.user == self.address.user
            && peer.domain == self.address.domain
            && peer.device_id == self.address.device_id
    }
}

/// Look up the bundle for `device_id` in a served set (a 409 names a device the
/// server should also have handed us a bundle for).
fn find_bundle(bundles: &[DevicePreKeyBundle], device_id: u32) -> Result<&DevicePreKeyBundle> {
    bundles
        .iter()
        .find(|b| b.device_id == device_id)
        .ok_or(ChatError::MissingBundle(device_id))
}

/// The wall clock libsignal uses for prekey/session staleness checks. The
/// platform boundary uses JavaScript's clock in browsers because
/// `SystemTime::now()` is unsupported on `wasm32-unknown-unknown`.
fn now() -> SystemTime {
    crate::clock::now()
}

/// Unix-epoch millis, saturating to 0 before the epoch (never in practice).
fn now_millis() -> i64 {
    crate::clock::unix_millis()
}

#[derive(Clone, Copy)]
enum ContactTransition {
    Accept,
    Reject,
    Block,
    Unblock,
}

fn contact_sync_send_id(
    peer: &str,
    state: ContactState,
    revision: u64,
    source_device_id: u32,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"kutup/contact-control/v1\0");
    hash.update(peer.as_bytes());
    hash.update([0]);
    hash.update(match state {
        ContactState::PendingIncoming => b"pending-incoming".as_slice(),
        ContactState::PendingOutgoing => b"pending-outgoing".as_slice(),
        ContactState::Accepted => b"accepted".as_slice(),
        ContactState::Rejected => b"rejected".as_slice(),
        ContactState::Blocked => b"blocked".as_slice(),
    });
    hash.update(revision.to_be_bytes());
    hash.update(source_device_id.to_be_bytes());
    let digest = hash.finalize();
    format!("contact-{}", hex::encode(&digest[..16]))
}

fn next_contact_revision(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| ChatError::Invalid("contact revision is exhausted".into()))
}

impl From<&ContactRecord> for ContactControlBody {
    fn from(contact: &ContactRecord) -> Self {
        Self {
            peer: contact.peer.clone(),
            state: contact.state,
            previous_state: contact.previous_state,
            revision: contact.revision,
            source_device_id: contact.source_device_id,
            updated_at_ms: contact.updated_at_ms,
        }
    }
}
