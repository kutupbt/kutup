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
    ChatDb, ContactRecord, InboundEnvelope, InboundFailureKind, InboundState, LocalProfile,
    OutboxEntry, OutboxLeg, PeerProfile, SentMessage, TransparencyMonitorState,
    TransparencyMonitorStatus,
};
use crate::error::{ChatError, Result};
use crate::manifest::{
    transparency_scope, verify_transparency_checkpoint_response, AccountAuthority, ManifestPolicy,
    TransparencyPolicy,
};
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
    /// Canonical peers whose invisible profile-key control was processed.
    pub profile_key_updated: Vec<String>,
    /// Canonical peers whose encrypted server profile was refreshed.
    pub profiles_refreshed: Vec<String>,
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
    transparency_policy: TransparencyPolicy,
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
            transparency_policy: TransparencyPolicy::default(),
        }
    }

    /// Install application-owned operator/witness trust roots before the first
    /// manifest publication or peer bundle fetch.
    pub fn set_transparency_policy(&mut self, policy: TransparencyPolicy) -> Result<()> {
        policy.validate()?;
        self.transparency_policy = policy;
        Ok(())
    }

    /// Poll and verify one homeserver checkpoint independently of a peer bundle
    /// fetch. Verification failures are durable security state; ordinary
    /// endpoint unavailability is recorded separately and leaves the last valid
    /// pin intact.
    pub async fn monitor_transparency(&mut self, scope: &str) -> Result<TransparencyMonitorStatus> {
        if scope.trim().is_empty() {
            return Err(ChatError::Invalid(
                "transparency monitor scope is empty".into(),
            ));
        }
        let checked_at = unix_millis();
        let prior = self.session.transparency_trust_for_scope(scope).await?;
        let previous_status = self.session.transparency_monitor_status(scope).await?;
        let from_tree_size = prior.as_ref().map_or(0, |trust| trust.tree_size);
        let response = Rc::clone(&self.transport)
            .fetch_transparency_checkpoint(scope, from_tree_size)
            .await;
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                let status = TransparencyMonitorStatus {
                    scope: scope.to_string(),
                    state: TransparencyMonitorState::Unavailable,
                    last_checked_at_ms: checked_at,
                    last_success_at_ms: previous_status
                        .as_ref()
                        .and_then(|status| status.last_success_at_ms),
                    tree_size: prior.as_ref().map(|trust| trust.tree_size),
                    detail: Some("checkpoint endpoint unavailable".into()),
                };
                self.session
                    .record_transparency_monitor(status.clone(), None)
                    .await?;
                return Ok(status);
            }
        };
        let next = match verify_transparency_checkpoint_response(
            scope,
            &response,
            prior.as_ref(),
            &self.transparency_policy,
        ) {
            Ok(next) => next,
            Err(error) => {
                let status = TransparencyMonitorStatus {
                    scope: scope.to_string(),
                    state: TransparencyMonitorState::VerificationFailed,
                    last_checked_at_ms: checked_at,
                    last_success_at_ms: previous_status
                        .as_ref()
                        .and_then(|status| status.last_success_at_ms),
                    tree_size: prior.as_ref().map(|trust| trust.tree_size),
                    detail: Some(error.to_string()),
                };
                self.session
                    .record_transparency_monitor(status.clone(), None)
                    .await?;
                return Ok(status);
            }
        };
        let status = TransparencyMonitorStatus {
            scope: scope.to_string(),
            state: TransparencyMonitorState::Healthy,
            last_checked_at_ms: checked_at,
            last_success_at_ms: Some(checked_at),
            tree_size: Some(next.tree_size),
            detail: None,
        };
        self.session
            .record_transparency_monitor(status.clone(), Some(next))
            .await?;
        Ok(status)
    }

    pub async fn transparency_monitor_status(
        &self,
        scope: &str,
    ) -> Result<Option<TransparencyMonitorStatus>> {
        self.session.transparency_monitor_status(scope).await
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

    pub async fn local_profile(&self) -> Result<Option<LocalProfile>> {
        self.session.local_profile().await
    }

    pub async fn peer_profiles(&self) -> Result<Vec<PeerProfile>> {
        self.session.peer_profiles().await
    }

    /// Initialize from the owner-only encrypted server profile or create the
    /// first random profile key and default display name. Exact pending uploads
    /// survive transport failures in the local profile record.
    pub async fn initialize_profile<R: Rng + CryptoRng>(
        &mut self,
        wrapping_key: &[u8; 32],
        default_display_name: &str,
        rng: &mut R,
    ) -> Result<LocalProfile> {
        let local = self.session.local_profile().await?;
        let remote = Rc::clone(&self.transport).fetch_own_profile().await?;
        let selected = match (local, remote) {
            (Some(local), Some(remote))
                if (remote.revision, remote.source_device_id)
                    > (local.revision, local.source_device_id) =>
            {
                crate::profile::open_own_profile(&remote, wrapping_key)?
            }
            (Some(local), _) => local,
            (None, Some(remote)) => crate::profile::open_own_profile(&remote, wrapping_key)?,
            (None, None) => crate::profile::create_local_profile(
                default_display_name,
                None,
                None,
                self.session.device_id(),
                wrapping_key,
                rng,
            )?,
        };
        self.session.save_local_profile(selected).await?;
        self.flush_profile(wrapping_key, "1970-01-01T00:00:00Z", rng)
            .await?;
        self.session
            .local_profile()
            .await?
            .ok_or_else(|| ChatError::Db("local profile disappeared after initialization".into()))
    }

    pub async fn update_profile<R: Rng + CryptoRng>(
        &mut self,
        display_name: &str,
        avatar: Option<Vec<u8>>,
        avatar_content_type: Option<String>,
        wrapping_key: &[u8; 32],
        sent_at: &str,
        rng: &mut R,
    ) -> Result<LocalProfile> {
        let current = self
            .session
            .local_profile()
            .await?
            .ok_or_else(|| ChatError::Invalid("encrypted profile is not initialized".into()))?;
        let updated = crate::profile::update_local_profile(
            &current,
            display_name,
            avatar,
            avatar_content_type,
            self.session.device_id(),
            wrapping_key,
            rng,
        )?;
        self.session.save_local_profile(updated).await?;
        self.flush_profile(wrapping_key, sent_at, rng).await?;
        self.session
            .local_profile()
            .await?
            .ok_or_else(|| ChatError::Db("local profile disappeared after update".into()))
    }

    /// Rotate the random profile key after a block, publish the new encrypted
    /// version, then redistribute only to still-authorized conversations.
    pub async fn rotate_profile_key<R: Rng + CryptoRng>(
        &mut self,
        wrapping_key: &[u8; 32],
        sent_at: &str,
        rng: &mut R,
    ) -> Result<LocalProfile> {
        let current = self
            .session
            .local_profile()
            .await?
            .ok_or_else(|| ChatError::Invalid("encrypted profile is not initialized".into()))?;
        let rotated = crate::profile::rotate_local_profile(
            &current,
            self.session.device_id(),
            wrapping_key,
            rng,
        )?;
        self.session.save_local_profile(rotated).await?;
        self.flush_profile(wrapping_key, sent_at, rng).await?;
        self.session
            .local_profile()
            .await?
            .ok_or_else(|| ChatError::Db("local profile disappeared after rotation".into()))
    }

    /// Publish a crash-surviving encrypted profile and fan out its current key.
    pub async fn flush_profile<R: Rng + CryptoRng>(
        &mut self,
        wrapping_key: &[u8; 32],
        sent_at: &str,
        rng: &mut R,
    ) -> Result<()> {
        // A linked device may have published while this device was offline.
        // Rebase a still-pending local edit on the owner-only current row and
        // retry, while preserving rotation semantics. The exact rebased upload
        // is committed before each retry.
        for conflict_attempt in 0..3 {
            let Some(profile) = self.session.local_profile().await? else {
                return Ok(());
            };
            let Some(upload) = profile.pending_upload.clone() else {
                break;
            };
            match Rc::clone(&self.transport).publish_profile(&upload).await {
                Ok(published) if published == upload => {
                    self.session
                        .mark_profile_published(profile.revision, profile.source_device_id)
                        .await?;
                    break;
                }
                Ok(_) => {
                    return Err(ChatError::Trust(
                        "server returned a different encrypted profile after publication".into(),
                    ));
                }
                Err(publish_error) => {
                    let remote = match Rc::clone(&self.transport).fetch_own_profile().await {
                        Ok(Some(remote)) => remote,
                        _ => return Err(publish_error),
                    };
                    if remote == upload {
                        self.session
                            .mark_profile_published(profile.revision, profile.source_device_id)
                            .await?;
                        break;
                    }
                    if (remote.revision, remote.source_device_id)
                        < (upload.revision, upload.source_device_id)
                        || conflict_attempt == 2
                    {
                        return Err(publish_error);
                    }
                    let remote = crate::profile::open_own_profile(&remote, wrapping_key)?;
                    let rebased = crate::profile::rebase_local_profile(
                        &profile,
                        &remote,
                        self.session.device_id(),
                        wrapping_key,
                        rng,
                    )?;
                    self.session.save_local_profile(rebased).await?;
                }
            }
        }

        let Some(profile) = self.session.local_profile().await? else {
            return Ok(());
        };
        if !profile.broadcast_pending {
            return Ok(());
        }
        for contact in self.session.contacts().await? {
            if matches!(
                contact.state,
                ContactState::PendingOutgoing | ContactState::Accepted
            ) {
                self.send_profile_key_update(&contact.peer, sent_at, rng)
                    .await?;
            }
        }
        self.session
            .mark_profile_broadcast(profile.revision, profile.source_device_id)
            .await
    }

    /// Fetch and decrypt every known, non-blocked peer profile. Missing old
    /// versions retain the last locally decrypted value, matching Signal's
    /// inability to remotely erase already received profile data.
    pub async fn refresh_profiles(&mut self) -> Result<Vec<String>> {
        let mut refreshed = Vec::new();
        for cached in self.session.peer_profiles().await? {
            if self
                .session
                .contact(&cached.peer)
                .await?
                .is_some_and(|contact| contact.state == ContactState::Blocked)
            {
                continue;
            }
            let version = crate::profile::profile_version(&cached.key)?;
            let access = crate::profile::profile_access_key(&cached.key)?;
            let Some(encrypted) = Rc::clone(&self.transport)
                .fetch_profile(&cached.peer, &version, &access)
                .await?
            else {
                continue;
            };
            if cached.display_name.is_some()
                && (encrypted.revision, encrypted.source_device_id)
                    <= (cached.revision, cached.source_device_id)
            {
                continue;
            }
            let profile =
                crate::profile::open_peer_profile(cached.peer.clone(), &encrypted, &cached.key)?;
            self.session.save_peer_profile(profile).await?;
            refreshed.push(cached.peer);
        }
        Ok(refreshed)
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
        // Signal shares the recipient's profile when a request is accepted.
        // The send path journals ciphertext before networking; a transient
        // delivery failure remains in the normal durable outbox.
        let _ = self.send_profile_key_update(peer, sent_at, rng).await;
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

    async fn send_profile_key_update<R: Rng + CryptoRng>(
        &mut self,
        peer: &str,
        sent_at: &str,
        rng: &mut R,
    ) -> Result<()> {
        let profile = self
            .session
            .local_profile()
            .await?
            .ok_or_else(|| ChatError::Invalid("encrypted profile is not initialized".into()))?;
        if profile.pending_upload.is_some() {
            return Err(ChatError::Invalid(
                "profile key cannot be shared before profile publication".into(),
            ));
        }
        let encoded_key = crate::profile::profile_key_base64(&profile)?;
        let send_id = profile_key_send_id(peer, &profile)?;
        let seq = self.session.next_sent_seq().await?;
        let content = ChatContent::profile_key_update_with_id(&send_id, sent_at, seq, encoded_key);
        self.send(&send_id, peer, &content, rng).await?;
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
        let account = self.session.user().to_string();
        let transparency_tree_size = self
            .session
            .transparency_trust(&account)
            .await?
            .map_or(0, |trust| trust.tree_size);
        let published = transport
            .publish_manifest(&candidate, transparency_tree_size)
            .await?;
        published.manifest.verify().map_err(ChatError::Trust)?;
        if published
            .manifest
            .manifest_hash()
            .map_err(ChatError::Trust)?
            != expected_hash
        {
            return Err(ChatError::Trust(
                "server returned a different manifest after publication".into(),
            ));
        }
        self.session
            .accept_manifest_publication(
                &account,
                &published.manifest,
                &published.transparency,
                &self.transparency_policy,
            )
            .await?;
        Ok(published.manifest)
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
        self.ensure_transparency_monitor_allows_new_send(peer_user)
            .await?;
        let mut content = content.clone();
        if peer_user != self.session.user() && content.profile_key.is_none() {
            if let Some(profile) = self.session.local_profile().await? {
                // Signal uploads a rotated profile before allowing the new key
                // into messages. A pending first upload/edit/rotation is not a
                // fetchable capability yet, so reconciliation must publish it
                // before new conversations receive it.
                if profile.pending_upload.is_none() {
                    content.profile_key = Some(crate::profile::profile_key_base64(&profile)?);
                }
            }
        }
        let mut summary = SendSummary::default();
        if peer_user == self.session.user() {
            let bundles = self.fetch_verified_bundles(peer_user).await?;
            self.session
                .enqueue_note_to_self(send_id, &bundles, &content, &mut summary, rng)
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
                        content: &content,
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
                Ok(ReceiveOutcome::ProfileKeyUpdate { id, peer }) => {
                    ack_ids.push(id);
                    if let Some(peer) = peer {
                        report.profile_key_updated.push(peer);
                    }
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
        let transparency_tree_size = self
            .session
            .transparency_trust(peer_user)
            .await?
            .map_or(0, |trust| trust.tree_size);
        let response = if peer_user == self.session.user() {
            transport
                .fetch_sync_bundles(peer_user, self.session.device_id(), transparency_tree_size)
                .await?
        } else {
            transport
                .fetch_bundles(peer_user, transparency_tree_size)
                .await?
        };
        self.session
            .accept_bundle_response(
                peer_user,
                response,
                self.manifest_policy,
                &self.transparency_policy,
            )
            .await
    }

    async fn ensure_transparency_monitor_allows_new_send(&self, peer_user: &str) -> Result<()> {
        let peer_scope = transparency_scope(peer_user)?;
        for scope in ["local", peer_scope.as_str()] {
            if self
                .session
                .transparency_monitor_status(scope)
                .await?
                .is_some_and(|status| status.state == TransparencyMonitorState::VerificationFailed)
            {
                return Err(ChatError::Trust(format!(
                    "transparency monitor verification failed for {scope}"
                )));
            }
        }
        Ok(())
    }
}

fn profile_key_send_id(peer: &str, profile: &LocalProfile) -> Result<String> {
    use sha2::{Digest, Sha256};
    let version = crate::profile::profile_version(&profile.key)?;
    let mut digest = Sha256::new();
    digest.update(b"kutup-profile-key-update-v1\0");
    digest.update(peer.as_bytes());
    digest.update(version.as_bytes());
    digest.update(profile.revision.to_be_bytes());
    let digest = digest.finalize();
    Ok(format!("pk:{}", hex::encode(&digest[..30])))
}

fn unix_millis() -> i64 {
    crate::clock::unix_millis()
}
