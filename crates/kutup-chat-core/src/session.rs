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

use crate::address::ChatAddress;
use crate::db::{
    AuthorityTrust, ChatDb, InboundEnvelope, InboundState, InboxMessage, ManifestTrust, OutboxEntry,
};
use crate::error::{ChatError, Result};
use crate::keys;
use crate::manifest::{verify_bundle_response, ManifestPolicy};
use crate::store::ChatStore;
use crate::wire::{decode_ciphertext, decode_identity_key, encode_ciphertext, to_prekey_bundle};
use kutup_chat_proto::{
    ChatContent, DeliveredEnvelope, DeviceListMismatch, DevicePreKeyBundle, ManifestDevice,
    OutgoingEnvelope, RegisterChatDeviceRequest, SuiteId, UserPreKeyBundlesResponse,
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
    /// [`Session::set_device_id`].
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
        let store = ChatStore::attach(db, local)?;
        Ok(Session {
            store,
            registration: None,
            address: ChatAddress::local(user, device_id),
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

    /// Apply the server-assigned device id after registration.
    pub fn set_device_id(&mut self, device_id: u32) {
        self.address.device_id = device_id;
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
    ) -> Result<()> {
        inbound.state = InboundState::PendingDecrypt;
        inbound.attempts = inbound.attempts.saturating_add(1);
        inbound.last_error = Some(error.to_string());
        self.store.stage_inbound(inbound);
        self.store.commit().await
    }

    pub(crate) async fn clear_acked(&mut self, ids: &[String]) -> Result<()> {
        for id in ids {
            self.store.delete_inbound(id);
        }
        self.store.commit().await
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
        let sender = envelope.sender.clone().ok_or_else(|| {
            ChatError::Invalid(
                "delivered envelope has no sender (sealed sender unsupported)".into(),
            )
        })?;
        let from = ChatAddress::from_sender(&sender, envelope.sender_device_id);
        let plaintext = match self.decrypt_bytes_staged(&from, envelope, rng).await {
            Ok(plaintext) => plaintext,
            Err(e) => {
                self.store.discard();
                return Err(e);
            }
        };
        self.store.stage_message(InboxMessage {
            id: envelope.id.clone(),
            peer: sender,
            sender_device_id: envelope.sender_device_id,
            cursor: envelope.cursor,
            content: plaintext.clone(),
            received_at: now_millis(),
        });
        self.store.stage_inbound(InboundEnvelope {
            id: envelope.id.clone(),
            cursor: envelope.cursor,
            envelope: serde_json::to_vec(envelope).map_err(|e| ChatError::Wire(e.to_string()))?,
            state: InboundState::PendingAck,
            attempts: 0,
            last_error: None,
            received_at: now_millis(),
        });
        self.store.commit().await?;
        match serde_json::from_slice::<ChatContent>(&plaintext) {
            Ok(content) => Ok(ReceiveOutcome::Message(Box::new(ReceivedMessage {
                from,
                content,
                cursor: envelope.cursor,
                id: envelope.id.clone(),
            }))),
            Err(_) => Ok(ReceiveOutcome::Undecodable {
                id: envelope.id.clone(),
            }),
        }
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

    /// The pinned self-authority and highest manifest observed for `peer`.
    pub async fn manifest_trust(&self, peer: &str) -> Result<Option<ManifestTrust>> {
        self.store.db().load_manifest_trust(peer).await
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
    ) -> Result<Vec<DevicePreKeyBundle>> {
        let prior = self.store.db().load_manifest_trust(peer).await?;
        let next = verify_bundle_response(peer, &response, policy, prior.as_ref())?;
        if let Some(next) = next {
            if prior.as_ref() != Some(&next) {
                self.store.stage_manifest_trust(next);
                self.store.commit().await?;
            }
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
    pub(crate) async fn enqueue_send<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
        content: &ChatContent,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        let plaintext =
            serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
        match self
            .build_send(peer_user, bundles, &plaintext, summary, rng)
            .await
        {
            Ok(envelopes) => {
                let entry = OutboxEntry {
                    send_id: send_id.to_string(),
                    peer: peer_user.to_string(),
                    content: plaintext,
                    envelopes: serde_json::to_vec(&envelopes)
                        .map_err(|e| ChatError::Content(e.to_string()))?,
                    attempts: 1,
                    created_at: now_millis(),
                };
                self.store.stage_outbox(entry);
                self.store.commit().await?;
                Ok(envelopes)
            }
            Err(e) => {
                self.store.discard();
                Err(e)
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
        send_id: &str,
        peer_user: &str,
        mismatch: &DeviceListMismatch,
        bundles: &[DevicePreKeyBundle],
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        match self
            .build_amendment(send_id, peer_user, mismatch, bundles, summary, rng)
            .await
        {
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

    /// Mark a send delivered: drop its outbox entry (one transaction).
    pub(crate) async fn complete_send(&mut self, send_id: &str) -> Result<()> {
        self.store.delete_outbox(send_id);
        self.store.commit().await
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
            let peer = ChatAddress::local(peer_user, bundle.device_id);
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
        send_id: &str,
        peer_user: &str,
        mismatch: &DeviceListMismatch,
        bundles: &[DevicePreKeyBundle],
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        let entry = self
            .store
            .db()
            .load_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid(format!("no outbox entry for send {send_id}")))?;
        let mut envelopes: Vec<OutgoingEnvelope> = serde_json::from_slice(&entry.envelopes)
            .map_err(|e| ChatError::Content(e.to_string()))?;

        // Extra devices aren't real: drop their ciphertext and archive the session.
        for &device_id in &mismatch.extra_devices {
            envelopes.retain(|e| e.device_id != device_id);
            let peer = ChatAddress::local(peer_user, device_id);
            self.store.delete_session(&peer.to_protocol()?.to_string());
        }

        // Missing devices: establish + encrypt from a fresh bundle, append.
        for &device_id in &mismatch.missing_devices {
            let peer = ChatAddress::local(peer_user, device_id);
            if self.is_self(&peer) {
                continue;
            }
            let bundle = find_bundle(bundles, device_id)?;
            let env = self
                .seal_device(&peer, bundle, &entry.content, summary, rng)
                .await?;
            envelopes.retain(|e| e.device_id != device_id);
            envelopes.push(env);
        }

        // Stale devices (reinstalled): accept the changed identity (TOFU re-key),
        // archive the old session, re-establish, re-encrypt. Surface the change.
        for &device_id in &mismatch.stale_devices {
            let peer = ChatAddress::local(peer_user, device_id);
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
                .encrypt_staged(&peer, bundle.registration_id, &entry.content, rng)
                .await?;
            envelopes.retain(|e| e.device_id != device_id);
            envelopes.push(env);
        }

        let updated = OutboxEntry {
            envelopes: serde_json::to_vec(&envelopes)
                .map_err(|e| ChatError::Content(e.to_string()))?,
            attempts: entry.attempts + 1,
            ..entry
        };
        self.store.stage_outbox(updated);
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
            suite: SuiteId::PqxdhTripleRatchetV1,
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

/// The wall clock libsignal uses for prekey/session staleness checks. Native uses
/// the real clock; the wasm adapter will inject one when that build lands.
fn now() -> SystemTime {
    SystemTime::now()
}

/// Unix-epoch millis, saturating to 0 before the epoch (never in practice).
fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
