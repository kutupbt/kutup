//! The engine — the async orchestration over a [`Session`] and a
//! [`ChatTransport`]. This is the surface the client apps drive: register a
//! device, send a message (with `409` device-list recovery, backed by the durable
//! `sendId` outbox), and flush the outbox after a restart.
//!
//! It interleaves the two worlds cleanly: `await` the async transport for network
//! I/O, call the synchronous [`Session`] methods (each one atomic transaction) for
//! crypto + store. The `Rc<dyn ChatTransport>` is cloned per call so a network
//! `await` never holds a borrow of `self` across the subsequent store write.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::{CryptoRng, Rng};

use crate::db::{
    ChatDb, ContactRecord, InboundEnvelope, InboundFailureKind, InboundState, LocalProfile,
    OutboxEntry, OutboxLeg, PeerProfile, SentMessage,
};
use crate::error::{ChatError, Result};
use crate::manifest::{
    derive_safety_number, verify_bundle_trust, verify_manifest_evidence, verify_manifest_history,
    AccountAuthority, ManifestPolicy, SafetyNumberV1,
};
use crate::sealed_sender::SealedSenderPolicyPin;
use crate::session::{
    DirectSend, ReceiveOutcome, ReceivedMessage, SealedDirectSend, SendAmendment, SendSummary,
    Session,
};
use crate::transport::{ChatTransport, SendOutcome};
use kutup_chat_proto::{
    AccountAddress, AccountManifestV1, AnonymousMlsKeyPackageRequestV1, ChatContent,
    ContactControlBody, ContactState, IdentifiedMlsKeyPackageRequestV1, MlsCipherSuiteId,
    MlsKeyPackageBundleV1, OutgoingEnvelope, PreKeyCountResponse, SealedMessageSubmissionV1,
    SealedOutgoingEnvelopeV1, SendMessagesRequest, MLS_PROTOCOL_VERSION,
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
    local_server: Option<String>,
    sealed_sender_enabled: bool,
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
            local_server: None,
            sealed_sender_enabled: false,
        }
    }

    /// Bind bare local usernames to their canonical federation domain. This is
    /// required before profile publication because delivery capabilities are
    /// deliberately recipient-address-specific.
    pub fn set_local_server(&mut self, server: &str) -> Result<()> {
        kutup_chat_proto::AccountAddress::federated("validation", server)
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        self.session.bind_local_server(server)?;
        self.local_server = Some(server.to_string());
        Ok(())
    }

    /// Enable sealed delivery only after the application has received the
    /// server's fully gated capability advertisement.
    pub fn set_sealed_sender_enabled(&mut self, enabled: bool) {
        self.sealed_sender_enabled = enabled;
    }

    fn canonical_self(&self) -> Result<String> {
        let address: kutup_chat_proto::AccountAddress =
            self.session
                .user()
                .parse()
                .map_err(|error: kutup_chat_proto::AddressError| {
                    ChatError::Invalid(error.to_string())
                })?;
        if address.server.is_some() {
            return Ok(address.canonical());
        }
        let server = self.local_server.as_deref().ok_or_else(|| {
            ChatError::Invalid(
                "local federation domain is required for profile capabilities".into(),
            )
        })?;
        kutup_chat_proto::AccountAddress::federated(&address.username, server)
            .map(|address| address.canonical())
            .map_err(|error| ChatError::Invalid(error.to_string()))
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

    #[cfg(feature = "wasm")]
    pub(crate) fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    pub(crate) fn transport(&self) -> &Rc<dyn ChatTransport> {
        &self.transport
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

    /// Build the exact pair-bound safety number from the current durable pin.
    pub async fn safety_number(
        &mut self,
        authority: &AccountAuthority,
        peer: &str,
    ) -> Result<SafetyNumberV1> {
        // Receiving the first identified message establishes a Signal session,
        // but it must not treat a sender key carried by that message as an
        // account-authority pin. Fetch and authenticate the signed account
        // manifest through the normal federation transport when the user opens
        // verification before they have replied to the contact.
        if self.session.manifest_trust(peer).await?.is_none() {
            let manifest = Rc::clone(&self.transport)
                .fetch_manifest(peer)
                .await?
                .ok_or_else(|| {
                    ChatError::Trust(format!("no signed account manifest for {peer}"))
                })?;
            self.accept_current_manifest_evidence(peer, &manifest)
                .await?;
        }
        let trust = self
            .session
            .manifest_trust(peer)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("no authority is pinned for {peer}")))?;
        let retained_authority_key_id = trust.authority_key_id.clone();
        let safety_source = trust
            .pending_reset
            .as_ref()
            .map_or(&trust, |pending| &pending.candidate);
        let mut safety = derive_safety_number(
            &self.canonical_self()?,
            &authority.public_key_base64(),
            safety_source,
        )?;
        if trust.trust == crate::AuthorityTrust::Quarantined {
            safety.trust = crate::AuthorityTrust::Quarantined;
            safety.retained_authority_key_id = Some(retained_authority_key_id);
            safety.quarantine_reason = trust.quarantine_reason.clone();
        }
        Ok(safety)
    }

    /// Promote a TOFU pin only after Rust has compared the scanned QR payload
    /// against the locally derived pair/key binding.
    pub async fn verify_safety_number(
        &mut self,
        authority: &AccountAuthority,
        peer: &str,
        scanned_payload: &str,
    ) -> Result<SafetyNumberV1> {
        let expected = self.safety_number(authority, peer).await?;
        if expected.continuity_gap {
            return Err(ChatError::Trust(
                "an incomplete manifest chain cannot be manually verified".into(),
            ));
        }
        if !expected.matches_qr_payload(scanned_payload) {
            return Err(ChatError::Trust(
                "scanned safety QR does not match this account pair and authority keys".into(),
            ));
        }
        if expected.trust == crate::AuthorityTrust::Quarantined {
            self.session.accept_authority_reset(peer).await?;
        } else {
            self.session.mark_authority_verified(peer).await?;
        }
        self.safety_number(authority, peer).await
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
        let canonical_self = self.canonical_self()?;
        let remote = Rc::clone(&self.transport).fetch_own_profile().await?;
        let selected = match (local, remote) {
            (Some(local), Some(remote))
                if (remote.revision, remote.source_device_id)
                    > (local.revision, local.source_device_id) =>
            {
                crate::profile::open_own_profile(&remote, wrapping_key, &canonical_self)?
            }
            (Some(local), _) => local,
            (None, Some(remote)) => {
                crate::profile::open_own_profile(&remote, wrapping_key, &canonical_self)?
            }
            (None, None) => crate::profile::create_local_profile(
                default_display_name,
                None,
                None,
                self.session.device_id(),
                wrapping_key,
                &canonical_self,
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
        let canonical_self = self.canonical_self()?;
        let updated = crate::profile::update_local_profile(
            &current,
            crate::profile::LocalProfileUpdate {
                display_name,
                avatar,
                avatar_content_type,
                source_device_id: self.session.device_id(),
                wrapping_key,
                canonical_recipient: &canonical_self,
            },
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
        let canonical_self = self.canonical_self()?;
        let rotated = crate::profile::rotate_local_profile(
            &current,
            self.session.device_id(),
            wrapping_key,
            &canonical_self,
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
        let canonical_self = self.canonical_self()?;
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
                    let remote =
                        crate::profile::open_own_profile(&remote, wrapping_key, &canonical_self)?;
                    let rebased = crate::profile::rebase_local_profile(
                        &profile,
                        &remote,
                        self.session.device_id(),
                        wrapping_key,
                        &canonical_self,
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
        wrapping_key: &[u8; 32],
        sent_at: &str,
        rng: &mut R,
    ) -> Result<ContactRecord> {
        let record = self.session.block_contact(peer).await?;
        // The block is already durable. If a profile exists, rotate and publish
        // its capability verifier before sharing the new key with the remaining
        // contacts. A publication failure is surfaced and its exact encrypted
        // upload remains durable for reconciliation.
        if self.session.local_profile().await?.is_some() {
            self.rotate_profile_key(wrapping_key, sent_at, rng).await?;
        }
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
    ) -> Result<AccountManifestV1> {
        let transport = Rc::clone(&self.transport);
        let current = transport.fetch_manifest(self.session.user()).await?;
        let canonical_self = self.canonical_self()?;
        let mls_identity = format!("{canonical_self}#{}", self.session.device_id());
        let mls = crate::MlsClient::new(Rc::clone(self.session.db()))
            .initialize(&mls_identity)
            .await?
            .manifest_binding();
        let local = self.session.manifest_device_with_mls(mls);
        let issued_at = issued_at.into();
        let candidate = match current {
            None => {
                authority.sign_manifest(canonical_self.clone(), 1, None, vec![local], issued_at)?
            }
            Some(current) => {
                current.verify().map_err(ChatError::Trust)?;
                if current.account != canonical_self {
                    return Err(ChatError::Trust(
                        "stored account manifest belongs to another account".into(),
                    ));
                }
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
                            && devices[index].registration_id == local.registration_id
                            && devices[index].mls == local.mls =>
                    {
                        current
                    }
                    location => {
                        match location {
                            Ok(index) => devices[index] = local,
                            Err(index) => devices.insert(index, local),
                        }
                        let next_sequence = current.sequence.checked_add(1).ok_or_else(|| {
                            ChatError::Trust("manifest sequence is exhausted".into())
                        })?;
                        authority.sign_manifest(
                            canonical_self.clone(),
                            next_sequence,
                            Some(current.manifest_hash().map_err(ChatError::Trust)?),
                            devices,
                            issued_at,
                        )?
                    }
                }
            }
        };
        let expected_hash = candidate.manifest_hash().map_err(ChatError::Trust)?;
        let account = canonical_self;
        let published = transport.publish_manifest(&candidate).await?;
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
        self.accept_current_manifest_evidence(&account, &published.manifest)
            .await?;
        Ok(published.manifest)
    }

    /// Resolve untrusted MLS Welcome credential claims exclusively through
    /// authenticated, account-signed device manifests. This consumes no
    /// Signal prekeys and durably applies the same rollback/gap/operator
    /// pins as direct-message session establishment.
    pub async fn resolve_mls_credential_claims(
        &mut self,
        claims: &[crate::ClaimedMlsCredential],
    ) -> Result<Vec<crate::VerifiedMlsCredential>> {
        self.resolve_mls_credential_claims_inner(claims, true).await
    }

    /// Resolve the single leaf that authored an MLS application message.
    ///
    /// Unlike a Welcome or Commit roster, one application message carries
    /// exactly one sender leaf. The leaf must still match that exact device in
    /// the current account-manifest-verified manifest, but it must not pretend to
    /// enumerate the sender account's other linked devices.
    pub async fn resolve_mls_sender_credential(
        &mut self,
        claim: &crate::ClaimedMlsCredential,
    ) -> Result<crate::VerifiedMlsCredential> {
        self.resolve_mls_credential_claims_inner(std::slice::from_ref(claim), false)
            .await?
            .pop()
            .ok_or_else(|| ChatError::Trust("verified MLS sender is unavailable".into()))
    }

    async fn resolve_mls_credential_claims_inner(
        &mut self,
        claims: &[crate::ClaimedMlsCredential],
        require_complete_device_coverage: bool,
    ) -> Result<Vec<crate::VerifiedMlsCredential>> {
        if claims.is_empty() || claims.len() > kutup_chat_proto::MAX_MLS_GROUP_LEAVES {
            return Err(ChatError::Invalid(format!(
                "MLS roster must contain 1-{} credential claims",
                kutup_chat_proto::MAX_MLS_GROUP_LEAVES
            )));
        }

        let mut parsed = Vec::with_capacity(claims.len());
        let mut identities = HashSet::with_capacity(claims.len());
        for claim in claims {
            if !identities.insert(claim.credential_identity.as_str()) {
                return Err(ChatError::Trust(
                    "MLS Welcome repeats a credential identity".into(),
                ));
            }
            let (account, device_id) =
                parse_mls_device_credential_identity(&claim.credential_identity)?;
            parsed.push((account, device_id));
        }

        let mut manifests = BTreeMap::new();
        for (account, _) in &parsed {
            if manifests.contains_key(account) {
                continue;
            }
            let response = Rc::clone(&self.transport)
                .fetch_manifest(account)
                .await?
                .ok_or_else(|| ChatError::Trust("account manifest is missing".into()))?;
            let manifest = self
                .accept_current_manifest_evidence(account, &response)
                .await?;
            manifests.insert(account.clone(), manifest);
        }

        if require_complete_device_coverage {
            let mut claimed_devices = BTreeMap::<String, BTreeSet<u32>>::new();
            for (account, device_id) in &parsed {
                claimed_devices
                    .entry(account.clone())
                    .or_default()
                    .insert(*device_id);
            }
            for (account, manifest) in &manifests {
                let manifest_devices = manifest
                    .devices
                    .iter()
                    .map(|device| device.device_id)
                    .collect::<BTreeSet<_>>();
                if manifest.devices.iter().any(|device| device.mls.is_none())
                    || claimed_devices.get(account) != Some(&manifest_devices)
                {
                    return Err(ChatError::Trust(format!(
                        "MLS roster does not cover the complete signed device set for {account}"
                    )));
                }
            }
        }

        claims
            .iter()
            .zip(parsed)
            .map(|(claim, (account, device_id))| {
                let manifest = manifests.get(&account).ok_or_else(|| {
                    ChatError::Trust("verified MLS account manifest is unavailable".into())
                })?;
                let device = manifest
                    .devices
                    .iter()
                    .find(|device| device.device_id == device_id)
                    .ok_or_else(|| {
                        ChatError::Trust(format!(
                            "MLS credential {} is absent from the signed device manifest",
                            claim.credential_identity
                        ))
                    })?;
                let binding = device.mls.as_ref().ok_or_else(|| {
                    ChatError::Trust(format!(
                        "MLS credential {} has no signed MLS device binding",
                        claim.credential_identity
                    ))
                })?;
                if binding.suite != MlsCipherSuiteId::Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519
                {
                    return Err(ChatError::Trust(
                        "MLS credential uses a suite outside the V1 policy".into(),
                    ));
                }
                binding.validate().map_err(ChatError::Trust)?;
                let manifest_key = STANDARD
                    .decode(&binding.credential_public_key)
                    .map_err(|_| ChatError::Trust("manifest MLS key is not base64".into()))?;
                if manifest_key != claim.credential_public_key {
                    return Err(ChatError::Trust(format!(
                        "MLS credential {} differs from the account-manifest-verified manifest",
                        claim.credential_identity
                    )));
                }
                crate::VerifiedMlsCredential::new(
                    claim.credential_identity.clone(),
                    claim.credential_public_key.clone(),
                )
            })
            .collect()
    }

    /// Fetch and independently authenticate one MLS ordering authority policy
    /// through the same-origin server proxy. No client-provided remote URL or
    /// server-computed trust label is accepted.
    pub async fn fetch_verified_mls_ordering_policy(
        &self,
        domain: &str,
    ) -> Result<kutup_chat_proto::MlsOrderingServicePolicyV1> {
        let history = Rc::clone(&self.transport)
            .fetch_mls_ordering_policy(domain)
            .await?;
        crate::verify_mls_ordering_policy_history(&history, domain)
    }

    /// Fetch and independently authenticate the complete ordering-policy
    /// history, retaining exact public fingerprints for human inspection.
    pub async fn fetch_verified_mls_ordering_policy_details(
        &self,
        domain: &str,
    ) -> Result<crate::VerifiedMlsOrderingPolicyHistory> {
        let history = Rc::clone(&self.transport)
            .fetch_mls_ordering_policy(domain)
            .await?;
        crate::verify_mls_ordering_policy_history_details(&history, domain)
    }

    /// Fetch capability-gated KeyPackages without authenticated browser
    /// context, then bind every package credential to a complete,
    /// account-manifest-verified current device manifest.
    pub async fn fetch_verified_anonymous_mls_key_packages(
        &mut self,
        recipient: &AccountAddress,
        capability: &[u8; 16],
        now_seconds: i64,
    ) -> Result<Vec<crate::VerifiedMlsKeyPackage>> {
        if recipient.server.is_none() || now_seconds < 0 {
            return Err(ChatError::Invalid(
                "anonymous MLS KeyPackage retrieval requires a canonical recipient and clock"
                    .into(),
            ));
        }
        let account = recipient.canonical();
        let request = AnonymousMlsKeyPackageRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            recipient: recipient.clone(),
            capability: STANDARD.encode(capability),
        };
        request.validate().map_err(ChatError::Invalid)?;
        let response = Rc::clone(&self.transport)
            .fetch_anonymous_mls_key_packages(&request)
            .await?;
        self.verify_mls_key_package_bundle(recipient, &account, response, now_seconds)
            .await
    }

    /// Fetch first-contact KeyPackages through the authenticated, identified
    /// invitation route. The destination learns the requester; subsequent
    /// application delivery never uses this path.
    pub async fn fetch_verified_identified_mls_key_packages(
        &mut self,
        recipient: &AccountAddress,
        conversation_id: uuid::Uuid,
        incarnation: u64,
        now_seconds: i64,
    ) -> Result<Vec<crate::VerifiedMlsKeyPackage>> {
        if recipient.server.is_none()
            || conversation_id.is_nil()
            || incarnation == 0
            || now_seconds < 0
        {
            return Err(ChatError::Invalid(
                "identified MLS KeyPackage retrieval requires canonical identifiers and clock"
                    .into(),
            ));
        }
        let account = recipient.canonical();
        let request = IdentifiedMlsKeyPackageRequestV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            recipient: recipient.clone(),
            conversation_id,
            incarnation,
        };
        request.validate().map_err(ChatError::Invalid)?;
        let response = Rc::clone(&self.transport)
            .fetch_identified_mls_key_packages(&request)
            .await?;
        self.verify_mls_key_package_bundle(recipient, &account, response, now_seconds)
            .await
    }

    async fn verify_mls_key_package_bundle(
        &mut self,
        recipient: &AccountAddress,
        account: &str,
        response: MlsKeyPackageBundleV1,
        now_seconds: i64,
    ) -> Result<Vec<crate::VerifiedMlsKeyPackage>> {
        response.validate(now_seconds).map_err(ChatError::Trust)?;
        if response.recipient != *recipient {
            return Err(ChatError::Trust(
                "MLS KeyPackage response has the wrong recipient".into(),
            ));
        }
        let manifest = self
            .accept_current_manifest_evidence(account, &response.manifest)
            .await?;

        let manifest_devices: BTreeMap<u32, _> = manifest
            .devices
            .iter()
            .map(|device| (device.device_id, device))
            .collect();
        if manifest_devices.len() != response.key_packages.len()
            || manifest_devices.values().any(|device| device.mls.is_none())
        {
            return Err(ChatError::Trust(
                "anonymous MLS KeyPackages do not cover the complete signed device set".into(),
            ));
        }
        response
            .key_packages
            .into_iter()
            .map(|wire| {
                let device = manifest_devices.get(&wire.device_id).ok_or_else(|| {
                    ChatError::Trust("anonymous MLS KeyPackage names an undeclared device".into())
                })?;
                let binding = device.mls.as_ref().ok_or_else(|| {
                    ChatError::Trust("signed device has no MLS credential binding".into())
                })?;
                if binding.suite != MlsCipherSuiteId::Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519
                {
                    return Err(ChatError::Trust(
                        "MLS KeyPackage uses a suite outside the V1 policy".into(),
                    ));
                }
                binding.validate().map_err(ChatError::Trust)?;
                let credential = crate::VerifiedMlsCredential::new(
                    format!("{account}#{}", wire.device_id),
                    STANDARD
                        .decode(&binding.credential_public_key)
                        .map_err(|_| ChatError::Trust("manifest MLS key is not base64".into()))?,
                )?;
                let anonymous_delivery_public_key = STANDARD
                    .decode(&binding.anonymous_delivery_public_key)
                    .map_err(|_| {
                        ChatError::Trust("manifest MLS anonymous-delivery key is not base64".into())
                    })?;
                let verified = crate::VerifiedMlsKeyPackage {
                    wire,
                    credential,
                    anonymous_delivery_public_key,
                };
                crate::MlsClient::validate_verified_key_package(&verified, now_seconds)?;
                Ok(verified)
            })
            .collect()
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
        let is_typing = content.as_typing().is_some();
        if is_typing && peer_user == self.session.user() {
            return Err(ChatError::Invalid(
                "Note to Self does not emit typing indicators".into(),
            ));
        }
        if content.as_disappearing_timer().is_some()
            && peer_user != self.session.user()
            && !self
                .session
                .contact(peer_user)
                .await?
                .is_some_and(|contact| contact.state == ContactState::Accepted)
        {
            return Err(ChatError::Invalid(
                "disappearing-message timers require an established conversation".into(),
            ));
        }
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
        let mut content = content.clone();
        if !is_typing && peer_user != self.session.user() && content.profile_key.is_none() {
            if let Some(profile) = self.session.local_profile().await? {
                // Signal uploads a rotated profile before allowing the new key
                // into messages. A pending first upload/edit/rotation is not a
                // fetchable capability yet, so reconciliation must publish it
                // before new conversations receive it.
                if profile.pending_upload.is_none() {
                    content.profile_key = Some(crate::profile::profile_key_base64(&profile)?);
                    content.profile_suite =
                        Some(kutup_chat_proto::ProfileSuiteId::XChaCha20Poly1305V1.as_u16());
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
            if let Some(capability) = self.media_delivery_capability(peer_user).await? {
                let recipient_bundles = self
                    .fetch_verified_sealed_bundles(peer_user, &capability)
                    .await?;
                let certificate = self.issue_verified_sender_certificate().await?;
                let user = self.session.user().to_string();
                let sync_bundles = if is_typing {
                    Vec::new()
                } else {
                    self.fetch_verified_bundles(&user).await?
                };
                self.session
                    .enqueue_sealed_direct_send(
                        SealedDirectSend {
                            send_id,
                            peer_user,
                            recipient_bundles: &recipient_bundles,
                            sync_bundles: &sync_bundles,
                            content: &content,
                            sender_certificate: &certificate,
                            capability,
                        },
                        &mut summary,
                        rng,
                    )
                    .await?;
            } else {
                let recipient_bundles = self.fetch_verified_bundles(peer_user).await?;
                let user = self.session.user().to_string();
                let sync_bundles = if is_typing {
                    Vec::new()
                } else {
                    self.fetch_verified_bundles(&user).await?
                };
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

    /// Retry durable sends while treating hidden optional controls as
    /// best-effort. Receipts retain their exact ciphertext for a later retry;
    /// typing is discarded after its short usefulness window. Neither may
    /// prevent inbound mailbox processing. Ordinary messages and malformed
    /// outbox content remain fail-closed.
    pub async fn flush_outbox_deferring_optional_failures<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<SendSummary>> {
        let mut summaries = Vec::new();
        for entry in self.session.pending_outbox().await? {
            let content = serde_json::from_slice::<ChatContent>(&entry.content).ok();
            let is_receipt = content
                .as_ref()
                .is_some_and(|content| content.as_receipt().is_some());
            let is_typing = content
                .as_ref()
                .is_some_and(|content| content.as_typing().is_some());
            if is_typing && unix_millis().saturating_sub(entry.created_at) > 10_000 {
                self.session.discard_typing_outbox(&entry.send_id).await?;
                continue;
            }
            match self
                .deliver_outbox_entry(entry, SendSummary::default(), rng)
                .await
            {
                Ok(summary) => summaries.push(summary),
                Err(_) if is_receipt || is_typing => {}
                Err(error) => return Err(error),
            }
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
            let envelope: kutup_chat_proto::DeliveredEnvelope =
                match serde_json::from_slice(&inbound.envelope) {
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
            let receive_result = if envelope.sealed_sender {
                let inspection = self.session.inspect_sealed_envelope(&envelope).await;
                match inspection {
                    Ok(inspection) => {
                        let validation = self
                            .validate_inbound_sealed_envelope(&envelope, &inspection)
                            .await;
                        match validation {
                            Ok(root) => {
                                let local = self.canonical_self()?;
                                self.session
                                    .receive_sealed_envelope(&envelope, &inspection, &local, &root)
                                    .await
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            } else {
                self.session.receive_envelope(&envelope, rng).await
            };
            match receive_result {
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
        } else if entry.sealed_sender {
            let envelopes: Vec<SealedOutgoingEnvelopeV1> = serde_json::from_slice(&entry.envelopes)
                .map_err(|error| ChatError::Db(format!("decode durable sealed outbox: {error}")))?;
            let capability = entry.sealed_capability.ok_or_else(|| {
                ChatError::Db("sealed outbox entry has no delivery capability".into())
            })?;
            self.deliver_sealed_leg(
                &entry.send_id,
                &entry.peer,
                capability,
                envelopes,
                &mut summary,
                rng,
            )
            .await
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

    /// Anonymous delivery has its own recovery loop. There is deliberately no
    /// branch to the identified transport once an outbox entry is sealed.
    async fn deliver_sealed_leg<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        capability: [u8; 16],
        mut envelopes: Vec<SealedOutgoingEnvelopeV1>,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<()> {
        let transport = Rc::clone(&self.transport);
        for attempt in 1..=MAX_SEND_ATTEMPTS {
            summary.attempts = attempt;
            let request = SealedMessageSubmissionV1 {
                send_id: send_id.to_string(),
                capability: STANDARD.encode(capability),
                envelopes: envelopes.clone(),
            };
            request.validate().map_err(ChatError::Invalid)?;
            match transport.send_sealed(peer_user, &request).await? {
                SendOutcome::Delivered { deduplicated } => {
                    self.session
                        .complete_send(send_id, OutboxLeg::Primary, deduplicated)
                        .await?;
                    summary.delivered = true;
                    summary.deduplicated = deduplicated;
                    return Ok(());
                }
                SendOutcome::Mismatch(_) => {
                    let bundles = self
                        .fetch_verified_sealed_bundles(peer_user, &capability)
                        .await?;
                    let certificate = self.issue_verified_sender_certificate().await?;
                    envelopes = self
                        .session
                        .amend_sealed_send(send_id, peer_user, &bundles, &certificate, summary, rng)
                        .await?;
                }
            }
        }
        Err(ChatError::SendNotConverged(MAX_SEND_ATTEMPTS))
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
        self.accept_verified_bundle_response(peer_user, response)
            .await
    }

    async fn fetch_verified_sealed_bundles(
        &mut self,
        peer_user: &str,
        capability: &[u8; 16],
    ) -> Result<Vec<kutup_chat_proto::DevicePreKeyBundle>> {
        let response = Rc::clone(&self.transport)
            .fetch_sealed_bundles(peer_user, capability)
            .await?;
        self.accept_verified_bundle_response(peer_user, response)
            .await
    }

    async fn accept_verified_bundle_response(
        &mut self,
        peer_user: &str,
        response: kutup_chat_proto::UserPreKeyBundlesResponse,
    ) -> Result<Vec<kutup_chat_proto::DevicePreKeyBundle>> {
        let prior_manifest = self.session.manifest_trust(peer_user).await?;
        let inspected = match verify_bundle_trust(
            peer_user,
            &response,
            self.manifest_policy,
            prior_manifest.as_ref(),
        ) {
            Ok(inspected) => inspected,
            Err(error) => {
                self.quarantine_manifest_failure(
                    peer_user,
                    response.manifest.as_ref(),
                    prior_manifest.as_ref(),
                    &error,
                )
                .await?;
                return Err(error);
            }
        };
        if inspected
            .manifest
            .as_ref()
            .is_some_and(|trust| trust.continuity_gap)
        {
            let pending = response
                .manifest
                .as_ref()
                .ok_or_else(|| ChatError::Trust("manifest is missing".into()))?;
            let (trust, history) = self
                .recover_manifest_history(peer_user, pending, prior_manifest.as_ref())
                .await?;
            return self
                .session
                .accept_bundle_response_with_history(
                    peer_user,
                    response,
                    trust,
                    history,
                    self.manifest_policy,
                )
                .await;
        }
        self.session
            .accept_bundle_response(peer_user, response, self.manifest_policy)
            .await
    }

    /// Derive the contacts-only delivery capability used by sealed messages
    /// and immutable Chat media. It is unavailable until the contact is
    /// accepted and the authenticated profile key is present.
    pub async fn media_delivery_capability(&self, peer: &str) -> Result<Option<[u8; 16]>> {
        if !self.sealed_sender_enabled
            || self.local_server.is_none()
            || !self
                .session
                .contact(peer)
                .await?
                .is_some_and(|contact| contact.state == ContactState::Accepted)
        {
            return Ok(None);
        }
        let Some(profile) = self.session.peer_profile(peer).await? else {
            return Ok(None);
        };
        let profile_key: [u8; 32] = profile
            .key
            .as_slice()
            .try_into()
            .map_err(|_| ChatError::Trust("peer profile key has the wrong length".into()))?;
        let address: kutup_chat_proto::AccountAddress =
            peer.parse()
                .map_err(|error: kutup_chat_proto::AddressError| {
                    ChatError::Invalid(error.to_string())
                })?;
        let canonical_peer = if address.server.is_some() {
            address.canonical()
        } else {
            kutup_chat_proto::AccountAddress::federated(
                &address.username,
                self.local_server.as_deref().expect("checked above"),
            )
            .map_err(|error| ChatError::Invalid(error.to_string()))?
            .canonical()
        };
        kutup_chat_proto::derive_delivery_capability(&profile_key, &canonical_peer)
            .map(Some)
            .map_err(ChatError::Trust)
    }

    async fn issue_verified_sender_certificate(
        &self,
    ) -> Result<libsignal_protocol::SenderCertificate> {
        let domain = self.local_server.as_deref().ok_or_else(|| {
            ChatError::Trust("sealed sender requires the local federation domain".into())
        })?;
        let now_seconds = unix_millis().div_euclid(1000);
        let history = Rc::clone(&self.transport)
            .fetch_sealed_sender_policy(domain)
            .await?;
        let policy = SealedSenderPolicyPin::verify_history(&history, domain, now_seconds)?;
        let response = Rc::clone(&self.transport)
            .fetch_sender_certificate(self.session.device_id())
            .await?;
        policy.validate_certificate_response(
            &response,
            &self.canonical_self()?,
            self.session.device_id(),
            &self.session.local_identity_public_key(),
            now_seconds,
        )
    }

    async fn validate_inbound_sealed_envelope(
        &mut self,
        envelope: &kutup_chat_proto::DeliveredEnvelope,
        inspection: &crate::session::SealedEnvelopeInspection,
    ) -> Result<libsignal_protocol::PublicKey> {
        let sender_address: kutup_chat_proto::AccountAddress = inspection
            .sender
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
        let domain = sender_address.server.as_deref().ok_or_else(|| {
            ChatError::Trust("sealed sender certificate address is not federated".into())
        })?;

        let mut manifest_identity = self
            .session
            .manifest_identity_key(&inspection.sender, inspection.sender_device_id)
            .await?;
        if manifest_identity.is_none() {
            // Retrieve and verify the complete current manifest before touching
            // the inner ratchet. The returned prekeys are intentionally unused.
            self.fetch_verified_bundles(&inspection.sender).await?;
            manifest_identity = self
                .session
                .manifest_identity_key(&inspection.sender, inspection.sender_device_id)
                .await?;
        }
        let manifest_identity = manifest_identity.ok_or_else(|| {
            ChatError::Trust(
                "sealed sender device is absent from the account-manifest-verified manifest".into(),
            )
        })?;
        if manifest_identity.serialize() != inspection.identity_key.serialize() {
            return Err(ChatError::Trust(
                "sealed envelope identity key differs from the signed account manifest".into(),
            ));
        }

        let now_seconds = unix_millis().div_euclid(1000);
        let history = Rc::clone(&self.transport)
            .fetch_sealed_sender_policy(domain)
            .await?;
        let policy = SealedSenderPolicyPin::verify_history(&history, domain, now_seconds)?;
        if policy.policy.direct_chat_suite != envelope.suite {
            return Err(ChatError::Trust(
                "sealed envelope selected a suite outside authenticated service policy".into(),
            ));
        }
        policy.validating_root(
            &inspection.certificate,
            &inspection.sender,
            inspection.sender_device_id,
            &manifest_identity,
            now_seconds,
        )
    }

    async fn accept_current_manifest_evidence(
        &mut self,
        account: &str,
        manifest: &AccountManifestV1,
    ) -> Result<AccountManifestV1> {
        let prior_manifest = self.session.manifest_trust(account).await?;
        let manifest_trust =
            match verify_manifest_evidence(account, manifest, prior_manifest.as_ref()) {
                Ok(trust) => trust,
                Err(error) => {
                    self.quarantine_manifest_failure(
                        account,
                        Some(manifest),
                        prior_manifest.as_ref(),
                        &error,
                    )
                    .await?;
                    return Err(error);
                }
            };
        if manifest_trust.continuity_gap {
            let (trust, history) = self
                .recover_manifest_history(account, manifest, prior_manifest.as_ref())
                .await?;
            self.session
                .accept_manifest_evidence_with_history(account, manifest, trust, history)
                .await
        } else {
            self.session
                .accept_manifest_evidence(account, manifest)
                .await
        }
    }

    async fn recover_manifest_history(
        &self,
        peer: &str,
        pending_manifest: &AccountManifestV1,
        prior_trust: Option<&crate::ManifestTrust>,
    ) -> Result<(
        crate::ManifestTrust,
        Vec<crate::AccountManifestHistoryRecordV1>,
    )> {
        let from_sequence = prior_trust.map_or(1, |trust| trust.highest_sequence.saturating_add(1));
        if from_sequence > pending_manifest.sequence {
            return Err(ChatError::Trust(
                "manifest recovery bounds exceed the pending sequence".into(),
            ));
        }
        let mut page_from = from_sequence;
        let mut pages = Vec::new();
        loop {
            let page = self
                .transport
                .fetch_manifest_history(peer, from_sequence, pending_manifest.sequence, page_from)
                .await?;
            if page.account != pending_manifest.account
                || page.from_sequence != page_from
                || page.to_sequence != pending_manifest.sequence
            {
                return Err(ChatError::Trust(
                    "manifest history response changed the requested bounds".into(),
                ));
            }
            let next = page.next_sequence;
            pages.push(page);
            match next {
                Some(next) => {
                    if next <= page_from {
                        return Err(ChatError::Trust(
                            "manifest history pagination did not advance".into(),
                        ));
                    }
                    page_from = next;
                }
                None => break,
            }
        }
        verify_manifest_history(peer, &pages, prior_trust, pending_manifest)
    }

    async fn quarantine_manifest_failure(
        &mut self,
        peer: &str,
        pending_manifest: Option<&AccountManifestV1>,
        prior_trust: Option<&crate::ManifestTrust>,
        error: &ChatError,
    ) -> Result<()> {
        let Some(prior) = prior_trust else {
            return Ok(());
        };
        let ChatError::Trust(reason) = error else {
            return Ok(());
        };
        let mut pending_reset = None;
        if let Some(manifest) = pending_manifest {
            let changes_identity = manifest.incarnation_id != prior.incarnation_id
                || manifest.authority_key_id != prior.authority_key_id
                || manifest.self_authority_key != prior.self_authority_key;
            if changes_identity {
                let candidate = verify_manifest_evidence(peer, manifest, None);
                if let Ok(candidate) = candidate {
                    let recovered = if candidate.continuity_gap {
                        self.recover_manifest_history(peer, manifest, None)
                            .await
                            .ok()
                    } else {
                        Some((
                            candidate,
                            vec![crate::AccountManifestHistoryRecordV1 {
                                peer: peer.to_string(),
                                sequence: manifest.sequence,
                                manifest: manifest.clone(),
                            }],
                        ))
                    };
                    if let Some((candidate, history)) = recovered {
                        pending_reset =
                            Some(crate::PendingAccountIdentityResetV1 { candidate, history });
                    }
                }
            }
        }
        self.session
            .quarantine_authority(peer, reason, pending_reset)
            .await?;
        Ok(())
    }
}

fn parse_mls_device_credential_identity(identity: &str) -> Result<(String, u32)> {
    let (account, device_id) = identity.rsplit_once('#').ok_or_else(|| {
        ChatError::Trust("MLS credential identity must be account@server#device".into())
    })?;
    let address: AccountAddress = account
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    if address.server.is_none() {
        return Err(ChatError::Trust(
            "MLS credential identity requires a canonical federation domain".into(),
        ));
    }
    let device_id: u32 = device_id
        .parse()
        .map_err(|_| ChatError::Trust("MLS credential device id is invalid".into()))?;
    if device_id == 0
        || device_id > 127
        || format!("{}#{device_id}", address.canonical()) != identity
    {
        return Err(ChatError::Trust(
            "MLS credential identity is not canonical".into(),
        ));
    }
    Ok((address.canonical(), device_id))
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
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // This is a name-derived id: preserve stable retry/deduplication semantics
    // across crashes while using the UUID wire shape required by anonymous
    // delivery. Mark it as RFC 9562 version 5 and variant 1 rather than
    // misrepresenting these deterministic bytes as a random v4 UUID.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).hyphenated().to_string())
}

fn unix_millis() -> i64 {
    crate::clock::unix_millis()
}

#[cfg(test)]
mod tests {
    use super::{parse_mls_device_credential_identity, profile_key_send_id};
    use crate::db::LocalProfile;

    #[test]
    fn profile_key_retry_id_is_a_stable_canonical_uuid() {
        let profile = LocalProfile {
            key: vec![7; 32],
            display_name: "Alice".into(),
            avatar: None,
            avatar_content_type: None,
            revision: 9,
            source_device_id: 1,
            pending_upload: None,
            broadcast_pending: true,
        };
        let first = profile_key_send_id("bob@example.test", &profile).unwrap();
        let second = profile_key_send_id("bob@example.test", &profile).unwrap();
        let parsed = uuid::Uuid::parse_str(&first).unwrap();

        assert_eq!(first, second);
        assert_eq!(first, parsed.hyphenated().to_string());
        assert_eq!(parsed.get_version_num(), 5);
        assert_ne!(
            first,
            profile_key_send_id("carol@example.test", &profile).unwrap()
        );
    }

    #[test]
    fn mls_device_credential_identity_is_exact_and_canonical() {
        assert_eq!(
            parse_mls_device_credential_identity("alice@example.test#127").unwrap(),
            ("alice@example.test".into(), 127)
        );
        for invalid in [
            "alice#1",
            "alice@example.test",
            "alice@example.test#0",
            "alice@example.test#128",
            "alice@example.test#01",
            "Alice@example.test#1",
            "alice@EXAMPLE.test#1",
            "alice@example.test#1#2",
        ] {
            assert!(
                parse_mls_device_credential_identity(invalid).is_err(),
                "{invalid}"
            );
        }
    }
}
