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

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use libsignal_protocol::{
    message_decrypt, message_encrypt, process_prekey_bundle, sealed_sender_decrypt,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt, IdentityChange, IdentityKeyStore,
    PublicKey, SenderCertificate, Timestamp,
};
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};

use crate::address::ChatAddress;
use crate::db::{
    AccountManifestHistoryRecord, AuthorityTrust, ChatDb, ContactRecord, InboundEnvelope,
    InboundFailureKind, InboundState, InboxMessage, LocalIdentity, LocalProfile, ManifestTrust,
    OutboxEntry, OutboxLeg, OutboxSyncLeg, PeerProfile, SentMessage,
};
use crate::error::{ChatError, Result};
use crate::keys;
use crate::manifest::{verify_bundle_trust, verify_manifest_evidence, ManifestPolicy};
use crate::store::ChatStore;
use crate::wire::{decode_ciphertext, decode_identity_key, encode_ciphertext, to_prekey_bundle};
use kutup_chat_proto::{
    AccountManifestDeviceV3, AccountManifestV3, AccountPreKeyBundlesResponse, ChatContent,
    ContactControlBody, ContactState, DeliveredEnvelope, DeviceListMismatch, DevicePreKeyBundle,
    DirectChatSuiteId, DisappearingExpiryStartBody, OutgoingEnvelope, RegisterChatDeviceRequestV2,
    ReplenishKeysRequest, SealedOutgoingEnvelopeV1,
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

pub(crate) struct SealedDirectSend<'a> {
    pub send_id: &'a str,
    pub peer_user: &'a str,
    pub recipient_bundles: &'a [DevicePreKeyBundle],
    pub sync_bundles: &'a [DevicePreKeyBundle],
    pub content: &'a ChatContent,
    pub sender_certificate: &'a SenderCertificate,
    pub capability: [u8; 16],
}

/// Authenticated information exposed by libsignal's outer sealed envelope.
/// The engine must validate this certificate against authenticated service
/// policy and a manifest-pinned manifest before asking the session to
/// advance the inner Signal ratchet.
/// A record waiting for a message this device couldn't read.
pub(crate) struct WaitingRecord {
    pub peer: String,
    /// The device that sent it (a group refresh goes to that device).
    pub device_id: u32,
    pub send_id: String,
    pub received_at: i64,
    /// The group it belongs to, for a group message.
    pub group_id: Option<String>,
}

pub(crate) struct SealedEnvelopeInspection {
    pub sender: String,
    pub sender_device_id: u32,
    pub identity_key: PublicKey,
    pub certificate: SenderCertificate,
    /// The group a sender-key message names (docs/plans/pairwise-groups.md
    /// §1); `None` for a pairwise message.
    pub group_id: Option<[u8; 32]>,
    /// Sent with Signal's implicit content hint: nothing to show if it can't
    /// be read (a group change notice).
    pub implicit: bool,
}

/// What the engine decides about a group message once its context is read
/// (docs/plans/pairwise-groups.md §3), before anything of it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupGate {
    /// From a member, at a state this device can take it at: kept.
    Accept,
    /// Catch up with the home first, then read it again: nothing is kept
    /// and the envelope isn't acknowledged.
    CatchUp,
    /// Not from a member: acknowledged and dropped, nothing of it kept.
    Refuse,
    /// Can't be confirmed now: nothing is kept and the envelope stays queued,
    /// to be read again on a later pass.
    Hold,
}

/// What [`Session::repair_undecryptable`] did.
pub(crate) struct UndecryptableRepair {
    /// The current session with the sender device was set aside.
    pub reset: bool,
    /// The sender should be handed a fresh session now rather than with the
    /// next message the user happens to write.
    pub refresh_peer: bool,
    /// The message to ask the sender for again, when it could be named.
    pub request: Option<String>,
    /// The record written in the unreadable message's place.
    pub notice: Option<ReceivedMessage>,
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
    /// The sender device (account + device id).
    pub from: ChatAddress,
    pub content: ChatContent,
    /// The mailbox cursor (monotonic order + dedup key).
    pub cursor: u64,
    /// The mailbox id (ack handle).
    pub id: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryReport {
    pub expired_messages: u32,
    pub expired_attachment_ids: Vec<String>,
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
    /// The peer could not read some messages and asks for them again. The
    /// request itself is kept by nobody.
    ResendRequested {
        id: String,
        peer: String,
        send_ids: Vec<String>,
    },
    /// A blocked peer's envelope was authenticated, decrypted, ratcheted, and
    /// made safe to ack, but its plaintext was deliberately not retained.
    Suppressed { id: String },
    /// Content of a group that came pairwise (a sender key, an invitation, a
    /// group refresh, a group message's pairwise fallback or resend): the
    /// envelope is safe to ack; the engine checks the sender is a member
    /// before using it (docs/plans/pairwise-groups.md §1–§2).
    GroupContent {
        id: String,
        from: ChatAddress,
        cursor: u64,
        content: Box<ChatContent>,
    },
    /// A group message whose gate asked to catch up first: nothing was kept,
    /// and the envelope is read again after the catch-up.
    GroupCatchUp,
    /// Group content that came pairwise, read but not kept: the engine
    /// decides about its sender (`group_decisions`) and reads it again.
    GroupCheck {
        group_id: String,
        sender: String,
        context: Option<kutup_chat_proto::group::GroupContextV1>,
        /// The recipient's pseudonym the content's context names
        /// (`recipientPseudonym`, on content sent pairwise to this account):
        /// what a device that lost the group recovers it by
        /// (group_recover.rs).
        named: Option<String>,
    },
    /// Group content that can't be confirmed now: nothing was kept, and the
    /// envelope stays queued for a later pass.
    GroupHeld { group_id: String, sender: String },
    /// An identity distribution's message from another device of this
    /// account, kept to be applied (`Engine::apply_account_identity`).
    AccountIdentity { id: String },
    /// Decrypted but the plaintext wasn't a valid content document (a buggy/newer
    /// sender). Stored raw so it's never dropped; the app renders a placeholder.
    Undecodable { id: String },
}

/// How long a group's send log keeps a delivered message for resends: a
/// day, as Signal-Desktop's send log keeps them in practice
/// (`Server.node.ts:1681-1696`). A later request is answered `unavailable`.
pub(crate) const GROUP_SEND_LOG_MS: i64 = 24 * 60 * 60 * 1000;

/// How long an undelivered group message is tried: a leg still not taken
/// after a week (a server gone) fails, and its plaintext goes.
pub(crate) const GROUP_UNDELIVERED_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// A registered local chat device, backed by a durable store.
pub struct Session {
    store: ChatStore,
    /// The registration payload to publish — `Some` right after [`Session::generate`],
    /// `None` for a device reloaded via [`Session::open`] (already registered).
    registration: Option<RegisterChatDeviceRequestV2>,
    /// What this device publishes, right after it was generated.
    published: Option<keys::PublishedKeys>,
    /// This account's key (`aci:<uuid>@<server>`), used by every account-level comparison.
    /// `address` is the same account with this device's id: its libsignal address.
    account: String,
    address: ChatAddress,
    /// What the engine decided for group content that came pairwise, by
    /// `(group id, sender account)`, for the second read of an envelope
    /// (`ReceiveOutcome::GroupCheck`).
    group_decisions: std::collections::BTreeMap<(String, String), GroupGate>,
    /// Peer accounts whose identity moved with a verified manifest since the
    /// engine last looked (`take_identity_changes`): each has had its
    /// "safety number changed" line written.
    identity_changes: Vec<String>,
}

impl Session {
    /// Generate a new device and persist its private material into `db` atomically.
    /// Returns the session; publish [`Session::registration`] to `POST
    /// /api/chat/device`, then apply the server-assigned id via
    /// [`Session::complete_registration`].
    /// A device with a new identity and no registration request: for tests
    /// and tools that serve its bundle themselves ([`Self::published_keys`]).
    pub async fn generate<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        user: impl Into<String>,
        device_id: u32,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        Self::generate_device(
            db,
            user,
            device_id,
            num_one_time,
            keys::NewDevice::Standalone { identity: None },
            rng,
        )
        .await
    }

    /// Another device of `from`'s account, with its identity: the local half
    /// of linking, for tests and tools.
    pub async fn generate_linked<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        from: &Session,
        device_id: u32,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let user = from.user().to_string();
        Self::generate_device(
            db,
            user,
            device_id,
            num_one_time,
            keys::NewDevice::Standalone {
                identity: Some(from.local_identity_key_pair()),
            },
            rng,
        )
        .await
    }

    /// What this device publishes for its bundle, right after it was
    /// generated.
    pub fn published_keys(&self) -> Option<&keys::PublishedKeys> {
        self.published.as_ref()
    }

    pub(crate) async fn generate_device<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        user: impl Into<String>,
        device_id: u32,
        num_one_time: usize,
        new_device: keys::NewDevice<'_>,
        rng: &mut R,
    ) -> Result<Self> {
        let address = ChatAddress::from_sender(&user.into(), device_id)?;
        let account = address.name();
        let mut material = keys::generate("kutup device", num_one_time, new_device, rng)?;
        // This account's own chain starts again with this device; contacts'
        // pins and verified state stay.
        material.seed.forget_manifests_of.insert(account.clone());
        // Install the whole device (identity + every prekey) in one transaction.
        db.apply(&material.seed).await?;
        let store = ChatStore::attach(db, material.local)?;
        Ok(Session {
            store,
            registration: material.registration,
            account,
            address,
            group_decisions: Default::default(),
            identity_changes: Vec::new(),
            published: Some(material.published),
        })
    }

    /// Reopen the device already installed in `db` (e.g. on app restart).
    pub async fn open(db: Rc<dyn ChatDb>, user: impl Into<String>, device_id: u32) -> Result<Self> {
        let address = ChatAddress::from_sender(&user.into(), device_id)?;
        let account = address.name();
        crate::timeline::ensure_built(db.as_ref()).await?;
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
        Ok(Session {
            store,
            registration: None,
            account,
            address,
            group_decisions: Default::default(),
            identity_changes: Vec::new(),
            published: None,
        })
    }

    /// Resume a fresh install whose exact registration payload was persisted
    /// before the first network attempt.
    pub(crate) async fn resume_registration(
        db: Rc<dyn ChatDb>,
        user: impl Into<String>,
        local: LocalIdentity,
    ) -> Result<Self> {
        let address = ChatAddress::from_sender(&user.into(), 1)?;
        let account = address.name();
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
            account,
            address,
            group_decisions: Default::default(),
            identity_changes: Vec::new(),
            published: None,
        })
    }

    /// The registration request to publish, if this session was just generated.
    pub fn registration(&self) -> Option<&RegisterChatDeviceRequestV2> {
        self.registration.as_ref()
    }

    /// This device's id (server-assigned after registration).
    pub fn device_id(&self) -> u32 {
        self.address.device_id
    }

    pub fn user(&self) -> &str {
        &self.account
    }

    #[cfg_attr(not(feature = "wasm"), allow(dead_code))]
    pub(crate) async fn disappearing_expiry_starts(&self) -> Result<DisappearingExpiryStarts> {
        let outgoing = self.store.db().list_sent_messages().await?;
        collect_disappearing_expiry_starts(&outgoing, self.user())
    }

    pub(crate) async fn validate_disappearing_expiry_start(
        &self,
        start: &DisappearingExpiryStartBody,
        now_ms: i64,
    ) -> Result<()> {
        start.validate().map_err(ChatError::Content)?;
        if now_ms < 0 || start.started_at_ms > now_ms.saturating_add(5 * 60 * 1_000) {
            return Err(ChatError::Invalid(
                "disappearing expiry-start clock is too far in the future".into(),
            ));
        }
        let target_matches = |content: &[u8]| -> Result<bool> {
            let Ok(content) = serde_json::from_slice::<ChatContent>(content) else {
                return Ok(false);
            };
            Ok(content.message_id == start.target_message_id.as_str()
                && content
                    .disappearing_after_seconds()
                    .map_err(ChatError::Content)?
                    .is_some())
        };
        let db = self.store.db();
        let found = match &start.conversation {
            kutup_chat_proto::ConversationId::Direct { account } => {
                let peer = account.to_string();
                let mut found = false;
                for message in db.list_messages().await? {
                    if message.peer == peer && target_matches(&message.content)? {
                        found = true;
                        break;
                    }
                }
                found
            }
            // A group's messages sit in the same store, under their group.
            group @ kutup_chat_proto::ConversationId::Group { .. } => {
                let mut found = false;
                for message in db.list_messages().await? {
                    if crate::timeline::conversation_of(&message.peer, &message.content)? == *group
                        && target_matches(&message.content)?
                    {
                        found = true;
                        break;
                    }
                }
                found
            }
        };
        if !found {
            return Err(ChatError::Invalid(
                "disappearing expiry start does not target an incoming disappearing message".into(),
            ));
        }
        Ok(())
    }

    /// This account's home server.
    pub fn server(&self) -> &str {
        &self.address.account.server
    }

    /// This account, as groups name it.
    pub(crate) fn account_ref(&self) -> &kutup_crypto::account_ref::AccountRef {
        &self.address.account
    }

    pub(crate) fn local_identity_public_key(&self) -> PublicKey {
        *self
            .store
            .local_identity_key_pair()
            .identity_key()
            .public_key()
    }

    pub(crate) async fn manifest_identity_key(
        &self,
        peer: &str,
        device_id: u32,
    ) -> Result<Option<PublicKey>> {
        let Some(trust) = self.manifest_trust(peer).await? else {
            return Ok(None);
        };
        if trust.continuity_gap {
            return Ok(None);
        }
        let Some(history) = self
            .manifest_history(peer, &trust.incarnation_id, trust.highest_sequence)
            .await?
        else {
            return Ok(None);
        };
        if history.manifest.manifest_hash().map_err(ChatError::Trust)? != trust.manifest_hash {
            return Err(ChatError::Trust(
                "manifest history contradicts the current trust pin".into(),
            ));
        }
        // Every listed Chat device has the account's identity.
        if history.manifest.chat_device(device_id).is_none() {
            return Ok(None);
        }
        Ok(Some(
            *decode_identity_key(
                history
                    .manifest
                    .chat_identity_key()
                    .map_err(ChatError::Trust)?,
            )?
            .public_key(),
        ))
    }

    /// Public identity and registration id for this local device, suitable for
    /// inclusion in the account-signed device manifest.
    /// The device's credential (`None` only in a store from before the
    /// account identity).
    pub(crate) fn credential(&self) -> Option<&str> {
        self.store.credential()
    }

    pub(crate) fn local_identity_key_pair(&self) -> libsignal_protocol::IdentityKeyPair {
        self.store.local_identity_key_pair()
    }

    /// This device's account identity bound to `authority` (the manifest's
    /// `identityBinding`), signed with the identity key it holds; the key
    /// itself never leaves the session.
    pub fn identity_binding(&self, authority: &crate::AccountAuthority) -> Result<String> {
        authority.identity_binding(self.account_ref(), &self.local_identity_key_pair())
    }

    /// The account's identity key, as this device holds it and the manifest
    /// lists it.
    pub fn account_identity_key(&self) -> String {
        self.store.local_identity_key_base64()
    }

    /// This device's manifest entry, under its sign-in's `session` hash
    /// ([`crate::ChatTransport::fetch_device_session`]).
    pub fn manifest_device(&self, session: String) -> AccountManifestDeviceV3 {
        self.store.local_manifest_device(self.device_id(), session)
    }

    pub(crate) fn db(&self) -> &Rc<dyn ChatDb> {
        self.store.db()
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

    /// This device missed the account's identity: forget its registration
    /// (its history stays) so it is linked again.
    pub(crate) async fn forget_registration(&mut self) -> Result<()> {
        self.store.stage_registration_forgotten();
        self.store.commit().await
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
    /// `received_at` is the engine's clock (its test offset included), so
    /// how long an envelope waited is measured on one clock.
    pub(crate) async fn journal_envelopes(
        &mut self,
        envelopes: &[DeliveredEnvelope],
        received_at: i64,
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
                    received_at,
                });
            }
            self.store.stage_cursor(envelope.cursor);
        }
        self.store.commit().await
    }

    pub(crate) async fn pending_inbound(&self) -> Result<Vec<InboundEnvelope>> {
        self.store.db().list_inbound().await
    }

    /// Whether a session exists with every one of `bundles`' devices, under
    /// the identity key each bundle serves. This account's own current
    /// device is skipped: it is listed among its account's devices but is
    /// never encrypted to.
    pub(crate) async fn has_sessions_with_all(
        &self,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
    ) -> Result<bool> {
        for bundle in bundles {
            if peer_user == self.user() && bundle.device_id == self.device_id() {
                continue;
            }
            let key = ChatAddress::from_sender(peer_user, bundle.device_id)?
                .to_protocol()?
                .to_string();
            if !self.store.has_session(&key).await? {
                return Ok(false);
            }
            let served = decode_identity_key(&bundle.identity_key)?
                .serialize()
                .to_vec();
            if self.store.peer_identity(&key).await?.as_deref() != Some(served.as_slice()) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) async fn record_inbound_failure(
        &mut self,
        mut inbound: InboundEnvelope,
        error: &ChatError,
    ) -> Result<InboundState> {
        // Whatever the failed attempt staged goes: a ratchet that advanced
        // for a message whose handling then failed must not be committed with
        // the failure, or the retry would find the message already consumed,
        // take it for a duplicate, and acknowledge it away unread.
        self.store.discard();
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

    /// Give up on an envelope from a known sender device that cannot be
    /// decrypted, and make the conversation work again: with `reset`, the
    /// current session with that device is set aside so the next message to
    /// it starts a fresh one, and a local record takes the unreadable
    /// message's place in an open conversation. The envelope is acknowledged
    /// either way, since no retry can read it. One atomic unit of work.
    pub(crate) async fn repair_undecryptable(
        &mut self,
        mut inbound: InboundEnvelope,
        sender: &str,
        sender_device_id: u32,
        send_id: Option<&str>,
        reset: bool,
        error: &ChatError,
    ) -> Result<UndecryptableRepair> {
        self.store.discard();
        let result = async {
            let from = ChatAddress::from_sender(sender, sender_device_id)?;
            let reset = reset
                && self
                    .store
                    .archive_session(&from.to_protocol()?.to_string())
                    .await?;
            let received_at = now_millis();
            let open_conversation = sender != self.user()
                && self.contact(sender).await?.is_some_and(|contact| {
                    matches!(
                        contact.state,
                        ContactState::PendingOutgoing | ContactState::Accepted
                    )
                });
            // The id the server passed along names the message, so the
            // sender can be asked for exactly it and the record can give way
            // when it arrives. It is not authenticated; a wrong one gets a
            // message this device already has, or nothing.
            let named = send_id
                .filter(|id| open_conversation && !id.is_empty() && id.len() <= 64)
                .map(str::to_string);
            let mut request = named.clone();
            if let Some(send_id) = named.as_deref() {
                for message in self.store.db().list_messages().await? {
                    if message.peer != sender {
                        continue;
                    }
                    let Ok(content) = serde_json::from_slice::<ChatContent>(&message.content)
                    else {
                        continue;
                    };
                    let waiting = content
                        .as_undecryptable()
                        .is_some_and(|body| body.send_id.as_deref() == Some(send_id));
                    if waiting || content.message_id == send_id {
                        // Already here, or already waited for.
                        request = None;
                    }
                }
            }
            // Without a name there is one record per reset, not per
            // envelope: an unreadable typing indicator is indistinguishable
            // from an unreadable message, and a burst of either says nothing
            // more than the first.
            let record = match named {
                Some(_) => request.is_some(),
                None => reset && open_conversation,
            };
            let notice = if record {
                let content = ChatContent::undecryptable_with_id(
                    inbound.id.clone(),
                    crate::clock::rfc3339(received_at),
                    request.clone(),
                );
                self.store.stage_message(InboxMessage {
                    id: inbound.id.clone(),
                    peer: sender.to_string(),
                    sender_device_id,
                    cursor: inbound.cursor,
                    content: serde_json::to_vec(&content)
                        .map_err(|e| ChatError::Content(e.to_string()))?,
                    received_at,
                });
                Some(ReceivedMessage {
                    from,
                    content,
                    cursor: inbound.cursor,
                    id: inbound.id.clone(),
                })
            } else {
                None
            };
            inbound.state = InboundState::PendingAck;
            inbound.attempts = inbound.attempts.saturating_add(1);
            inbound.failure_kind = Some(error.inbound_failure_kind());
            inbound.last_error = Some(error.to_string());
            self.store.stage_inbound(inbound);
            self.store.commit().await?;
            Ok(UndecryptableRepair {
                reset,
                refresh_peer: reset && open_conversation,
                request,
                notice,
            })
        }
        .await;
        if result.is_err() {
            self.store.discard();
        }
        result
    }

    /// What this device sent `peer` as `send_id`, if it is a message that
    /// may be sent again.
    pub(crate) async fn resendable_content(
        &self,
        peer: &str,
        send_id: &str,
    ) -> Result<Option<ChatContent>> {
        Ok(self
            .sent_message(send_id)
            .await?
            .filter(|sent| sent.peer == peer)
            .and_then(|sent| serde_json::from_slice::<ChatContent>(&sent.content).ok())
            .filter(|content| content.is_resendable() && content.message_id == send_id))
    }

    /// The records still waiting for a message.
    pub(crate) async fn waiting_records(&self) -> Result<Vec<WaitingRecord>> {
        let mut waiting = Vec::new();
        for message in self.store.db().list_messages().await? {
            let Ok(content) = serde_json::from_slice::<ChatContent>(&message.content) else {
                continue;
            };
            if let Some(body) = content.as_undecryptable() {
                if let (Some(send_id), false) = (body.send_id, body.lost) {
                    waiting.push(WaitingRecord {
                        peer: message.peer,
                        device_id: message.sender_device_id,
                        send_id,
                        received_at: message.received_at,
                        group_id: content
                            .group_context()
                            .map(|context| context.group_id.clone()),
                    });
                }
            }
        }
        Ok(waiting)
    }

    /// Stop waiting for these messages from `sender` (asked for in vain).
    pub(crate) async fn give_up_waiting(
        &mut self,
        sender: &str,
        send_ids: &[String],
    ) -> Result<()> {
        let result = self.stage_lost(sender, send_ids).await;
        match result {
            Ok(()) => self.store.commit().await,
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Stage turning the records waiting for `send_ids` from `sender` into
    /// lost ones. Stored under a derived id (a record is never rewritten in
    /// place), with the send id kept, so the message still fills in if
    /// another device of the sender sends it after all.
    async fn stage_lost(&mut self, sender: &str, send_ids: &[String]) -> Result<()> {
        for message in self.store.db().list_messages().await? {
            if message.peer != sender {
                continue;
            }
            let Ok(content) = serde_json::from_slice::<ChatContent>(&message.content) else {
                continue;
            };
            let Some(body) = content.as_undecryptable() else {
                continue;
            };
            let Some(send_id) = body.send_id.filter(|id| send_ids.contains(id)) else {
                continue;
            };
            if body.lost {
                continue;
            }
            let id = format!("{}:lost", message.id);
            let mut lost = ChatContent::undecryptable_record(
                id.clone(),
                content.sent_at.clone(),
                Some(send_id),
                true,
            );
            // A group's record stays in the group's thread.
            if let Some(context) = content.group_context() {
                lost = lost.with_group_context(&context);
            }
            self.store.delete_message(&message.id);
            self.store.stage_message(InboxMessage {
                id,
                content: serde_json::to_vec(&lost)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                ..message
            });
        }
        Ok(())
    }

    /// Stage removing the records standing in for `send_ids` from `sender`.
    async fn stage_filled_in(&mut self, sender: &str, send_ids: &[String]) -> Result<bool> {
        let mut already_here = false;
        for message in self.store.db().list_messages().await? {
            if message.peer != sender {
                continue;
            }
            let Ok(content) = serde_json::from_slice::<ChatContent>(&message.content) else {
                continue;
            };
            match content.as_undecryptable() {
                Some(body) => {
                    if body.send_id.is_some_and(|id| send_ids.contains(&id)) {
                        self.store.delete_message(&message.id);
                    }
                }
                None => {
                    already_here |= send_ids.contains(&content.message_id);
                }
            }
        }
        Ok(already_here)
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

    /// The first-seen identity pins waiting for their write (JSON).
    pub(crate) async fn pins_due(&self) -> Result<Option<Vec<u8>>> {
        self.store.pins_due().await
    }

    pub(crate) async fn save_pins_due(&mut self, state: Vec<u8>) -> Result<()> {
        self.store.stage_pins_due(state);
        self.store.commit().await
    }

    /// Whether this device followed the account's contact list once, in full.
    pub(crate) async fn contact_list_followed(&self) -> Result<bool> {
        self.store.contact_list_followed().await
    }

    /// Marks the account's contact list followed (after a full sync).
    pub(crate) async fn mark_contact_list_followed(&mut self) -> Result<()> {
        self.store.stage_contact_list_followed();
        self.store.commit().await
    }

    /// Saves a contact as it is (its list entry's due moment, for one).
    pub(crate) async fn save_contact(&mut self, contact: ContactRecord) -> Result<()> {
        self.store.stage_contact(contact);
        self.store.commit().await
    }

    /// Takes a contact from the account's contact list: its state, and its
    /// profile key when this device has none for them yet.
    pub(crate) async fn restore_contact(
        &mut self,
        contact: ContactRecord,
        profile_key: Option<Vec<u8>>,
    ) -> Result<()> {
        if let Some(key) = profile_key {
            if self.peer_profile(&contact.peer).await?.is_none() {
                self.store.stage_peer_profile(PeerProfile {
                    peer: contact.peer.clone(),
                    key,
                    display_name: None,
                    avatar: None,
                    avatar_content_type: None,
                    about: None,
                    // Revision zero: the profile is fetched with this key.
                    revision: 0,
                    source_device_id: 0,
                });
            }
        }
        self.store.stage_contact(contact);
        self.store.commit().await
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
        // A contact is an account; only its canonical string form parses.
        crate::address::parse_account(peer)?;
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
            list_due_at_ms: current.as_ref().and_then(|contact| contact.list_due_at_ms),
        };
        let record = ContactRecord {
            list_due_at_ms: crate::contact_list::due_after_change(&record, now_millis()),
            ..record
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
        let delivered_sender = envelope
            .sender
            .as_ref()
            .map(ToString::to_string)
            .ok_or(ChatError::MissingSender)?;
        let (sender, from) =
            self.resolve_delivered_sender(&delivered_sender, envelope.sender_device_id)?;
        let plaintext = match self.decrypt_bytes_staged(&from, envelope, rng).await {
            Ok(plaintext) => plaintext,
            Err(e) => {
                self.store.discard();
                return Err(e);
            }
        };
        self.finish_received_envelope(envelope, sender, envelope.sender_device_id, from, plaintext)
            .await
    }

    /// A delivered envelope's sender: always an account's canonical string
    /// form (`aci:<uuid>@<server>`); anything else is refused before any
    /// ratchet is chosen.
    pub(crate) fn resolve_delivered_sender(
        &self,
        sender: &str,
        device_id: u32,
    ) -> Result<(String, ChatAddress)> {
        // Only an account's canonical string form parses.
        let account = crate::address::parse_account(sender)?;
        Ok((
            sender.to_owned(),
            ChatAddress::from_account(account, device_id),
        ))
    }

    pub(crate) async fn inspect_sealed_envelope(
        &self,
        envelope: &DeliveredEnvelope,
    ) -> Result<SealedEnvelopeInspection> {
        if !envelope.sealed_sender
            || envelope.sender.is_some()
            || envelope.sender_device_id != 0
            || envelope.envelope_type != kutup_chat_proto::EnvelopeType::Message
        {
            return Err(ChatError::Trust(
                "sealed delivery contains forbidden sender metadata or framing".into(),
            ));
        }
        let bytes = STANDARD
            .decode(&envelope.content)
            .map_err(|error| ChatError::Wire(error.to_string()))?;
        if bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || STANDARD.encode(&bytes) != envelope.content
        {
            return Err(ChatError::Wire(
                "sealed envelope is empty, oversized, or non-canonical".into(),
            ));
        }
        let content = sealed_sender_decrypt_to_usmc(&bytes, &self.store.identity_store).await?;
        let certificate = content.sender()?.clone();
        let sender = certificate.sender_uuid()?.to_string();
        let sender_device_id = u32::from(certificate.sender_device_id()?);
        let identity_key = certificate.key()?;
        ChatAddress::from_sender(&sender, sender_device_id)?;
        let group_id = match content.msg_type()? {
            libsignal_protocol::CiphertextMessageType::SenderKey => {
                let id: [u8; 32] = content
                    .group_id()?
                    .and_then(|id| id.try_into().ok())
                    .ok_or_else(|| {
                        ChatError::Trust("a sender-key message names no group".into())
                    })?;
                Some(id)
            }
            _ => None,
        };
        let implicit = content.content_hint()? == libsignal_protocol::ContentHint::Implicit;
        Ok(SealedEnvelopeInspection {
            sender,
            sender_device_id,
            identity_key,
            certificate,
            group_id,
            implicit,
        })
    }

    pub(crate) async fn receive_sealed_envelope(
        &mut self,
        envelope: &DeliveredEnvelope,
        inspection: &SealedEnvelopeInspection,
        local_canonical_address: &str,
        validating_root: &PublicKey,
    ) -> Result<ReceiveOutcome> {
        let bytes = STANDARD
            .decode(&envelope.content)
            .map_err(|error| ChatError::Wire(error.to_string()))?;
        let result = sealed_sender_decrypt(
            &bytes,
            validating_root,
            Timestamp::from_epoch_millis(
                u64::try_from(now_millis())
                    .map_err(|_| ChatError::Trust("system clock predates the epoch".into()))?,
            ),
            None,
            local_canonical_address.to_string(),
            crate::address::device_id_u8(self.device_id())?,
            &mut self.store.identity_store,
            &mut self.store.session_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
        )
        .await;
        let decrypted = match result {
            Ok(decrypted) => decrypted,
            Err(error) => {
                self.store.discard();
                return Err(error.into());
            }
        };
        let sender = decrypted.sender_uuid()?.to_string();
        let sender_device_id = u32::from(decrypted.device_id()?);
        if sender != inspection.sender || sender_device_id != inspection.sender_device_id {
            self.store.discard();
            return Err(ChatError::Trust(
                "sealed envelope identity changed between validation and decryption".into(),
            ));
        }
        let from = ChatAddress::from_sender(&sender, sender_device_id)?;
        let plaintext = match crate::padding::unpad(decrypted.message()?) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.store.discard();
                return Err(error);
            }
        };
        self.finish_received_envelope(envelope, sender, sender_device_id, from, plaintext)
            .await
    }

    /// Marks a delivered envelope as handled, to be acknowledged.
    fn stage_inbound_ack(&mut self, envelope: &DeliveredEnvelope) -> Result<()> {
        self.store.stage_inbound(InboundEnvelope {
            id: envelope.id.clone(),
            cursor: envelope.cursor,
            envelope: serde_json::to_vec(envelope).map_err(|e| ChatError::Wire(e.to_string()))?,
            state: InboundState::PendingAck,
            attempts: 0,
            failure_kind: None,
            last_error: None,
            received_at: now_millis(),
        });
        Ok(())
    }

    async fn finish_received_envelope(
        &mut self,
        envelope: &DeliveredEnvelope,
        sender: String,
        sender_device_id: u32,
        from: ChatAddress,
        plaintext: Vec<u8>,
    ) -> Result<ReceiveOutcome> {
        let mut plaintext = plaintext;
        let mut parsed = serde_json::from_slice::<ChatContent>(&plaintext).ok();
        // An identity distribution's message to this device: only from
        // another device of this account. Kept, sealed in the store, in the
        // commit that acknowledges it; the engine checks it against the
        // account's manifest and installs it (`apply_account_identity`).
        if parsed.as_ref().is_some_and(|content| {
            content.kind == kutup_chat_proto::content::kind::ACCOUNT_IDENTITY
        }) {
            let body = parsed
                .as_ref()
                .and_then(ChatContent::as_account_identity)
                .filter(|_| sender == self.user() && sender_device_id != self.device_id());
            let Some(body) = body else {
                self.store.discard();
                self.ack_dropped(envelope).await?;
                return Ok(ReceiveOutcome::Suppressed {
                    id: envelope.id.clone(),
                });
            };
            // The plaintext carries the identity's private key.
            zeroize::Zeroize::zeroize(&mut plaintext);
            let mut encoded = zeroize::Zeroizing::new(
                serde_json::to_vec(&body).map_err(|e| ChatError::Content(e.to_string()))?,
            );
            self.store
                .stage_pending_account_identity(Some(std::mem::take(&mut *encoded)));
            self.stage_inbound_ack(envelope)?;
            self.store.commit().await?;
            return Ok(ReceiveOutcome::AccountIdentity {
                id: envelope.id.clone(),
            });
        }
        // A group's content never opens a direct conversation or a message
        // request. Apart from an invitation, nothing of it is kept before the
        // engine decided about its sender (docs/plans/pairwise-groups.md §3):
        // read, set aside, and read again with the decision.
        if let Some(content) = parsed.as_ref().filter(|content| is_group_content(content)) {
            let group = group_of_content(content);
            let decision = match &group {
                None => Some(GroupGate::Accept),
                Some((group_id, _)) => self
                    .group_decisions
                    .get(&(group_id.clone(), sender.clone()))
                    .copied(),
            };
            match (decision, group) {
                (Some(GroupGate::Accept), _) => {
                    self.stage_inbound_ack(envelope)?;
                    self.store.commit().await?;
                    return Ok(ReceiveOutcome::GroupContent {
                        id: envelope.id.clone(),
                        from,
                        cursor: envelope.cursor,
                        content: Box::new(content.clone()),
                    });
                }
                (Some(GroupGate::Refuse), _) => {
                    self.store.discard();
                    self.ack_dropped(envelope).await?;
                    return Ok(ReceiveOutcome::Suppressed {
                        id: envelope.id.clone(),
                    });
                }
                (Some(GroupGate::Hold | GroupGate::CatchUp), group) => {
                    self.store.discard();
                    return Ok(ReceiveOutcome::GroupHeld {
                        group_id: group.map(|(group_id, _)| group_id).unwrap_or_default(),
                        sender,
                    });
                }
                (None, group) => {
                    self.store.discard();
                    let (group_id, context) = group.unwrap_or_default();
                    let named = context
                        .as_ref()
                        .and_then(|context| context.recipient_pseudonym.clone());
                    return Ok(ReceiveOutcome::GroupCheck {
                        group_id,
                        sender,
                        context,
                        named,
                    });
                }
            }
        }
        // A message sent again is handled as the message inside it, and
        // takes the place of the record that waited for it.
        if parsed
            .as_ref()
            .is_some_and(|content| content.kind == kutup_chat_proto::content::kind::RESEND)
        {
            let body = parsed
                .as_ref()
                .and_then(ChatContent::as_resend)
                .filter(|_| sender != self.user());
            let Some(body) = body else {
                self.store.discard();
                return Err(ChatError::Content("invalid re-sent message".into()));
            };
            let already_here = match self
                .stage_filled_in(&sender, std::slice::from_ref(&body.send_id))
                .await
            {
                Ok(already_here) => already_here,
                Err(error) => {
                    self.store.discard();
                    return Err(error);
                }
            };
            if already_here {
                // Another device of this account asked; this one read it the
                // first time.
                self.store.stage_inbound(InboundEnvelope {
                    id: envelope.id.clone(),
                    cursor: envelope.cursor,
                    envelope: serde_json::to_vec(envelope)
                        .map_err(|e| ChatError::Wire(e.to_string()))?,
                    state: InboundState::PendingAck,
                    attempts: 0,
                    failure_kind: None,
                    last_error: None,
                    received_at: now_millis(),
                });
                self.store.commit().await?;
                return Ok(ReceiveOutcome::Suppressed {
                    id: envelope.id.clone(),
                });
            }
            plaintext =
                serde_json::to_vec(&body.content).map_err(|e| ChatError::Content(e.to_string()))?;
            parsed = Some(*body.content);
        }
        let plaintext = plaintext;
        let parsed = parsed;
        let local_only = |content: &ChatContent| {
            ChatContent::is_local_only_kind(&content.kind)
                || content.as_sent_transcript().is_some_and(|transcript| {
                    ChatContent::is_local_only_kind(&transcript.content.kind)
                })
        };
        if parsed.as_ref().is_some_and(local_only) {
            self.store.discard();
            return Err(ChatError::Content(
                "local timeline notices never arrive from another device or account".into(),
            ));
        }
        let transcript = if sender == self.user() && sender_device_id != self.device_id() {
            parsed
                .as_ref()
                .and_then(ChatContent::as_sent_transcript)
                .filter(|body| {
                    !body.send_id.is_empty()
                        && body.send_id.len() <= 64
                        && body.content.message_id == body.send_id
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
        let mut resend_request: Option<Vec<String>> = None;
        if let Some(Err(error)) = transcript.as_ref().map(|body| {
            body.content
                .extras()
                .and_then(|_| match body.content.structured_content_is_valid() {
                    Some(false) => Err(format!("invalid Chat {}", body.content.kind)),
                    _ => Ok(()),
                })
                .and_then(|_| refuse_group_only(&body.content))
        }) {
            self.store.discard();
            return Err(ChatError::Content(error));
        }
        let synced_message = if let Some(transcript) = transcript {
            if ChatContent::is_account_control_kind(&transcript.content.kind)
                && (transcript.peer.to_string() != self.user()
                    || transcript.content.account_control_is_valid() != Some(true)
                    || transcript
                        .content
                        .as_conversation_state()
                        .is_some_and(|state| state.source_device_id != sender_device_id))
            {
                self.store.discard();
                return Err(ChatError::Content(format!(
                    "invalid authenticated {}",
                    transcript.content.kind
                )));
            }
            if let Some(control) = transcript.content.as_contact_control() {
                if transcript.peer.to_string() != self.user()
                    || control.source_device_id != sender_device_id
                    || control.revision == 0
                    || control.peer.to_string() == self.user()
                {
                    self.store.discard();
                    return Err(ChatError::Content(
                        "invalid authenticated contact control".into(),
                    ));
                }
                let current = self.contact(&control.peer.to_string()).await?;
                let incoming_order = crate::contact_list::contact_order(
                    control.revision,
                    control.state,
                    control.source_device_id,
                );
                let current_order = current.as_ref().map(crate::contact_list::order_of);
                if current_order.is_none_or(|order| incoming_order > order) {
                    self.store.stage_contact(ContactRecord {
                        peer: control.peer.to_string(),
                        state: control.state,
                        previous_state: control.previous_state,
                        revision: control.revision,
                        source_device_id: control.source_device_id,
                        updated_at_ms: control.updated_at_ms,
                        sync_pending: false,
                        sync_send_id: None,
                        // The device that made the change writes the list;
                        // a write due here stays due (it writes only what
                        // the list doesn't say yet).
                        list_due_at_ms: current.as_ref().and_then(|contact| contact.list_due_at_ms),
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
            } else if transcript.content.kind == kutup_chat_proto::content::kind::TYPING
                || transcript.content.kind == kutup_chat_proto::content::kind::CALL
                || transcript.content.is_session_control()
            {
                // Ephemeral controls are never linked-device history. Current
                // clients do not sync them, but older/malicious local devices
                // cannot force one into the durable transcript either.
                profile_control = true;
                None
            } else {
                self.stage_transcript_contact(&transcript.peer.to_string(), received_at)
                    .await?;
                let message = SentMessage {
                    send_id: transcript.send_id,
                    peer: transcript.peer.to_string(),
                    sender_device_id,
                    content: serde_json::to_vec(&transcript.content)
                        .map_err(|e| ChatError::Content(e.to_string()))?,
                    created_at: transcript.timestamp_ms,
                    delivered_at: Some(received_at),
                    delivered: true,
                    deduplicated: false,
                    failed_recipients: 0,
                    waiting_recipients: None,
                };
                self.store.stage_sent_message(message.clone());
                Some(message)
            }
        } else {
            let prior_contact = self.contact(&sender).await?;
            let is_profile_update = parsed.as_ref().is_some_and(|content| {
                content.kind == kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
            });
            let is_typing = parsed
                .as_ref()
                .is_some_and(|content| content.as_typing().is_some());
            let is_call = parsed
                .as_ref()
                .is_some_and(|content| content.as_call().is_some());
            let is_disappearing_timer = parsed
                .as_ref()
                .is_some_and(|content| content.as_disappearing_timer().is_some());
            let is_session_control = parsed.as_ref().is_some_and(ChatContent::is_session_control);
            let is_account_control = parsed
                .as_ref()
                .is_some_and(|content| ChatContent::is_account_control_kind(&content.kind));
            if let Some(content) = parsed.as_ref() {
                if let Err(error) = content
                    .disappearing_after_seconds()
                    .and_then(|_| content.extras())
                    .and_then(|_| match content.structured_content_is_valid() {
                        Some(false) => Err(format!("invalid Chat {}", content.kind)),
                        _ => Ok(()),
                    })
                    .and_then(|_| refuse_group_only(content))
                {
                    self.store.discard();
                    return Err(ChatError::Content(error));
                }
            }
            if parsed
                .as_ref()
                .is_some_and(|content| content.kind == kutup_chat_proto::content::kind::TYPING)
                && !is_typing
            {
                self.store.discard();
                return Err(ChatError::Content(
                    "invalid encrypted typing control".into(),
                ));
            }
            if parsed
                .as_ref()
                .is_some_and(|content| content.kind == kutup_chat_proto::content::kind::CALL)
                && !is_call
            {
                self.store.discard();
                return Err(ChatError::Content("invalid encrypted call signal".into()));
            }
            if parsed.as_ref().is_some_and(|content| {
                content.kind == kutup_chat_proto::content::kind::DISAPPEARING_TIMER
            }) && !is_disappearing_timer
            {
                self.store.discard();
                return Err(ChatError::Content(
                    "invalid encrypted disappearing-message timer".into(),
                ));
            }
            if is_account_control {
                self.store.discard();
                return Err(ChatError::Content(
                    "same-account controls are accepted only from an authenticated linked-device transcript"
                        .into(),
                ));
            }
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
                    if let Some(encoded_key) = parsed.as_ref().and_then(current_profile_key) {
                        if self.stage_peer_profile_key(&sender, encoded_key).await? {
                            profile_key_updated = Some(sender.clone());
                        }
                    }
                }
            } else if is_session_control {
                // It already did its work: decrypting it adopted the session
                // it carried. Nothing is kept, and it opens no request.
                suppressed = true;
                let open_conversation = prior_contact.as_ref().is_some_and(|contact| {
                    matches!(
                        contact.state,
                        ContactState::PendingOutgoing | ContactState::Accepted
                    )
                });
                let control = parsed
                    .as_ref()
                    .and_then(ChatContent::as_session_control)
                    .filter(|body| open_conversation && !body.send_ids.is_empty());
                match control {
                    Some(body)
                        if body.action == kutup_chat_proto::SessionControlAction::Refresh =>
                    {
                        resend_request = Some(body.send_ids);
                    }
                    Some(body) if body.action == kutup_chat_proto::SessionControlAction::Lost => {
                        // Sent, but not to be had again: no longer waited
                        // for, and saying so. Another device of the sender
                        // that still has one fills it in all the same.
                        self.stage_lost(&sender, &body.send_ids).await?;
                    }
                    Some(body) => {
                        // Nothing that device kept as history (a typing
                        // indicator can be the unreadable thing): the records
                        // simply go. A device that does have it still sends
                        // it, and it arrives as a message.
                        self.stage_filled_in(&sender, &body.send_ids).await?;
                    }
                    None => {}
                }
            } else if is_typing || is_call {
                // Typing and calls cannot create/reopen a message request and
                // are never durable plaintext history (a call from someone
                // not yet accepted does not ring, as in Signal). The ratchet mutation and mailbox
                // receipt still commit atomically before the live event emits.
                suppressed = !prior_contact.as_ref().is_some_and(|contact| {
                    matches!(
                        contact.state,
                        ContactState::PendingOutgoing | ContactState::Accepted
                    )
                });
            } else if is_disappearing_timer {
                // A timer is durable conversation state, but it cannot create
                // or reopen a request without a real user-visible message.
                suppressed = !prior_contact.as_ref().is_some_and(|contact| {
                    matches!(
                        contact.state,
                        ContactState::PendingOutgoing | ContactState::Accepted
                    )
                });
                if !suppressed {
                    self.store.stage_message(InboxMessage {
                        id: envelope.id.clone(),
                        peer: sender.clone(),
                        sender_device_id,
                        cursor: envelope.cursor,
                        content: plaintext.clone(),
                        received_at,
                    });
                }
            } else {
                suppressed = self.stage_incoming_contact(&sender, received_at).await?;
                if !suppressed {
                    if let Some(encoded_key) = parsed.as_ref().and_then(current_profile_key) {
                        if self.stage_peer_profile_key(&sender, encoded_key).await? {
                            profile_key_updated = Some(sender.clone());
                        }
                    }
                    self.store.stage_message(InboxMessage {
                        id: envelope.id.clone(),
                        peer: sender,
                        sender_device_id,
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
        if let Some(send_ids) = resend_request {
            return Ok(ReceiveOutcome::ResendRequested {
                id: envelope.id.clone(),
                peer: from.name(),
                send_ids,
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
        let (display_name, avatar, avatar_content_type, about) = current
            .map(|profile| {
                (
                    profile.display_name,
                    profile.avatar,
                    profile.avatar_content_type,
                    profile.about,
                )
            })
            .unwrap_or((None, None, None, None));
        self.store.stage_peer_profile(PeerProfile {
            peer: peer.to_string(),
            key,
            display_name,
            avatar,
            avatar_content_type,
            about,
            revision: 0,
            source_device_id: 0,
        });
        // A contact's new key goes into their list entry lazily: with the
        // next write that is due anyway, or within the hour.
        if let Some(mut contact) = self.contact(peer).await? {
            if contact.state != ContactState::PendingIncoming && contact.list_due_at_ms.is_none() {
                contact.list_due_at_ms = Some(crate::contact_list::lazy_due(now_millis()));
                self.store.stage_contact(contact);
            }
        }
        Ok(true)
    }

    async fn stage_incoming_contact(&mut self, peer: &str, updated_at_ms: i64) -> Result<bool> {
        let current = self.contact(peer).await?;
        let Some(mut contact) = current else {
            // An incoming request is the other person's: never in the list.
            self.store.stage_contact(ContactRecord {
                peer: peer.to_string(),
                state: ContactState::PendingIncoming,
                previous_state: None,
                revision: 0,
                source_device_id: 0,
                updated_at_ms,
                sync_pending: false,
                sync_send_id: None,
                list_due_at_ms: None,
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
                // The reply accepted the request: written, or the request
                // would restore as pending for good.
                contact.list_due_at_ms =
                    crate::contact_list::due_after_change(&contact, now_millis());
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
                list_due_at_ms: Some(crate::contact_list::fresh_due(now_millis())),
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
                contact.list_due_at_ms =
                    crate::contact_list::due_after_change(&contact, now_millis());
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

    /// Remove elapsed disappearing plaintext, derived mutation/reaction rows,
    /// and undelivered ciphertexts that have outlived their usefulness. The
    /// ratchet and sender-key state remain advanced; expiry never rewinds
    /// crypto.
    pub async fn purge_expired_history(&mut self, now_ms: i64) -> Result<ExpiryReport> {
        if now_ms < 0 {
            return Err(ChatError::Invalid(
                "expiry clock must not be negative".into(),
            ));
        }
        let incoming = self.store.db().list_messages().await?;
        let outgoing = self.store.db().list_sent_messages().await?;
        let starts = collect_disappearing_expiry_starts(&outgoing, self.user())?;
        let controls = collect_account_controls(&outgoing, self.user());
        let mut expired_ids = std::collections::BTreeSet::new();
        let mut attachment_ids = std::collections::BTreeSet::new();
        let mut expired_messages = 0u32;

        for message in &incoming {
            // A group's messages sit in the same store, under their group.
            let conversation = crate::timeline::conversation_of(&message.peer, &message.content)?;
            if let Some(expired) = expired_content(
                &message.content,
                &conversation,
                false,
                message.received_at,
                &starts,
                now_ms,
            )?
            .or_else(|| controls.deleted_content(&message.content, &conversation))
            {
                self.store.delete_message(&message.id);
                collect_expired(expired, &mut expired_ids, &mut attachment_ids);
                expired_messages = expired_messages.saturating_add(1);
            }
        }
        for message in &outgoing {
            let conversation = crate::timeline::conversation_of(&message.peer, &message.content)?;
            if let Some(expired) = expired_content(
                &message.content,
                &conversation,
                true,
                message.created_at,
                &starts,
                now_ms,
            )?
            .or_else(|| controls.deleted_content(&message.content, &conversation))
            {
                self.store.delete_sent_message(&message.send_id);
                collect_expired(expired, &mut expired_ids, &mut attachment_ids);
                expired_messages = expired_messages.saturating_add(1);
            } else if message.peer == self.user() && controls.is_superseded(&message.content) {
                self.store.delete_sent_message(&message.send_id);
            }
        }

        // Once a target is gone, retaining its reaction/edit operation keeps
        // no product value and unnecessarily preserves its stable identifier.
        for message in &incoming {
            if content_targets_any(&message.content, &expired_ids)? {
                self.store.delete_message(&message.id);
            }
        }
        for message in &outgoing {
            if content_targets_any(&message.content, &expired_ids)? {
                self.store.delete_sent_message(&message.send_id);
            }
        }
        for entry in self.store.db().list_outbox().await? {
            let conversation = direct_conversation(&entry.peer)?;
            if expired_content(
                &entry.content,
                &conversation,
                true,
                entry.created_at,
                &starts,
                now_ms,
            )?
            .is_some()
                || content_targets_any(&entry.content, &expired_ids)?
            {
                self.store.delete_outbox(&entry.send_id);
            }
        }
        // A group's send log keeps a delivered message a day for resends, and
        // tries an undelivered one for a week; nothing that disappeared or
        // was deleted stays (docs/plans/pairwise-groups.md §2).
        for entry in self.store.db().list_group_outbox().await? {
            let conversation = kutup_chat_proto::ConversationId::Group {
                group_id: entry.group_id.clone(),
            };
            let delivered = entry.legs.iter().all(|leg| leg.delivered);
            let age = now_ms.saturating_sub(entry.created_at);
            if (delivered && age >= GROUP_SEND_LOG_MS)
                || age >= GROUP_UNDELIVERED_MS
                || expired_content(
                    &entry.content,
                    &conversation,
                    true,
                    entry.created_at,
                    &starts,
                    now_ms,
                )?
                .is_some()
                || content_targets_any(&entry.content, &expired_ids)?
                || controls
                    .deleted_content(&entry.content, &conversation)
                    .is_some()
            {
                // Not taken within the week: the message says it never
                // reached those accounts, rather than sending for ever.
                if !delivered && age >= GROUP_UNDELIVERED_MS {
                    if let Some(mut sent) =
                        self.store.db().load_sent_message(&entry.send_id).await?
                    {
                        sent.delivered = true;
                        sent.delivered_at = Some(now_ms);
                        sent.failed_recipients = u32::try_from(
                            entry
                                .legs
                                .iter()
                                .filter(|leg| leg.failed || !leg.delivered)
                                .count(),
                        )
                        .unwrap_or(u32::MAX);
                        self.store.stage_sent_message(sent);
                    }
                }
                self.store.delete_group_outbox(&entry.send_id);
            }
        }
        self.store.commit().await?;
        Ok(ExpiryReport {
            expired_messages,
            expired_attachment_ids: attachment_ids.into_iter().collect(),
        })
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

    /// One-time keys to add, and with `rotate` a new signed and last-resort
    /// pair (`crate::prekey_rotation`): generated, made durable with the exact
    /// request, and only then published, so a retry never publishes keys this
    /// device lost. A request already waiting is returned as it is.
    pub(crate) async fn prepare_prekey_replenishment<R: Rng + CryptoRng>(
        &mut self,
        ec_count: usize,
        kyber_count: usize,
        rotate: bool,
        rng: &mut R,
    ) -> Result<ReplenishKeysRequest> {
        if let Some(request) = self.pending_prekey_upload().await? {
            return Ok(request);
        }
        let ec_ids = self.unused_prekey_ids(ec_count, false, rng).await?;
        let kyber_ids = self
            .unused_prekey_ids(kyber_count + usize::from(rotate), true, rng)
            .await?;
        let identity = self.store.local_identity_key_pair();
        let (one_time_kyber_ids, last_resort_id) = if rotate {
            let (last, rest) = kyber_ids
                .split_last()
                .expect("one id was asked for the rotation");
            (rest.to_vec(), Some(*last))
        } else {
            (kyber_ids, None)
        };
        let mut material =
            keys::generate_replenishment(&identity, &ec_ids, &one_time_kyber_ids, rng)?;
        if let Some(last_resort_id) = last_resort_id {
            let signed_id = self.unused_signed_prekey_id(rng).await?;
            let rotation = keys::generate_rotation(&identity, signed_id, last_resort_id, rng)?;
            material.request.signed_pre_key = Some(rotation.signed_pre_key);
            material.request.last_resort_kyber_pre_key = Some(rotation.last_resort_kyber_pre_key);
            self.store
                .stage_generated_signed_pre_key(signed_id, rotation.signed_record);
            self.store
                .stage_generated_kyber_pre_key(last_resort_id, rotation.last_resort_record);
            let mut state = self.store.prekey_rotation().await?;
            state.pending = Some(crate::prekey_rotation::PendingKeys {
                signed: signed_id,
                last_resort: last_resort_id,
            });
            self.store.stage_prekey_rotation(&state)?;
        }
        let serialized = serde_json::to_vec(&material.request)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        for (id, record) in material.pre_keys {
            self.store.stage_generated_pre_key(id, record);
        }
        for (id, record) in material.kyber_pre_keys {
            self.store.stage_generated_kyber_pre_key(id, record);
        }
        self.store.stage_prekey_upload(serialized);
        if let Err(error) = self.store.commit().await {
            self.store.discard();
            return Err(error);
        }
        Ok(material.request)
    }

    /// The server took the waiting request: a staged pair becomes current
    /// and the pair it replaces is retired, in the same transaction.
    pub(crate) async fn complete_prekey_upload(&mut self) -> Result<()> {
        let mut state = self.store.prekey_rotation().await?;
        if state.confirm(crate::clock::unix_millis()) {
            self.store.stage_prekey_rotation(&state)?;
        }
        self.store.clear_prekey_upload();
        self.store.commit().await
    }

    /// Whether the signed and last-resort pair is due to be replaced.
    pub(crate) async fn prekey_rotation_due(&self) -> Result<bool> {
        Ok(self
            .store
            .prekey_rotation()
            .await?
            .due(crate::clock::unix_millis()))
    }

    /// Delete prekeys no longer needed: retired pairs older than the
    /// server's mailbox retention plus a margin, and one-time Kyber keys
    /// used longer ago than `grace_ms`. Returns how many went.
    #[doc(hidden)]
    pub async fn purge_retired_pre_keys(
        &mut self,
        mailbox_retention_days: u32,
        grace_ms: i64,
    ) -> Result<usize> {
        let mut state = self.store.prekey_rotation().await?;
        let expired = state.sweep(
            crate::clock::unix_millis(),
            crate::prekey_rotation::retired_keep_ms(mailbox_retention_days),
            grace_ms,
        );
        if expired.signed.is_empty() && expired.kyber.is_empty() {
            return Ok(0);
        }
        self.store
            .stage_expired_pre_keys(&expired.signed, &expired.kyber);
        self.store.stage_prekey_rotation(&state)?;
        if let Err(error) = self.store.commit().await {
            self.store.discard();
            return Err(error);
        }
        Ok(expired.signed.len() + expired.kyber.len())
    }

    /// Replace the signed and last-resort pair now, as if the server had
    /// confirmed it; returns the published keys. Tests only.
    #[doc(hidden)]
    pub async fn rotate_prekeys_for_testing<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ReplenishKeysRequest> {
        let request = self.prepare_prekey_replenishment(0, 0, true, rng).await?;
        self.complete_prekey_upload().await?;
        Ok(request)
    }

    #[doc(hidden)]
    pub async fn age_prekey_rotation_for_testing(&mut self, ms: i64) -> Result<()> {
        let mut state = self.store.prekey_rotation().await?;
        state.signed.published_at_ms -= ms;
        state.last_resort.published_at_ms -= ms;
        for key in &mut state.retired {
            key.retired_at_ms -= ms;
        }
        for used_at in state.used_one_time_kyber.values_mut() {
            *used_at -= ms;
        }
        self.store.stage_prekey_rotation(&state)?;
        self.store.commit().await
    }

    /// The serialized session-repair limits, if any were written.
    pub(crate) async fn repair_limits(&self) -> Result<Option<Vec<u8>>> {
        self.db().load_repair_limits().await
    }

    /// Replace the serialized session-repair limits in their own commit.
    pub(crate) async fn save_repair_limits(&mut self, state: Vec<u8>) -> Result<()> {
        self.store.stage_repair_limits(state);
        if let Err(error) = self.store.commit().await {
            self.store.discard();
            return Err(error);
        }
        Ok(())
    }

    #[doc(hidden)]
    pub async fn has_kyber_pre_key_for_testing(&self, id: u32) -> Result<bool> {
        Ok(self.db().load_kyber_pre_key(id).await?.is_some())
    }

    async fn unused_signed_prekey_id<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<u32> {
        loop {
            let id = rng.random_range(1_000..=u32::MAX);
            if self.store.db().load_signed_pre_key(id).await?.is_none() {
                return Ok(id);
            }
        }
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

    pub(crate) async fn manifest_history(
        &self,
        peer: &str,
        incarnation_id: &str,
        sequence: u64,
    ) -> Result<Option<AccountManifestHistoryRecord>> {
        self.store
            .db()
            .load_manifest_history(peer, incarnation_id, sequence)
            .await
    }

    pub(crate) async fn accept_manifest_evidence(
        &mut self,
        account: &str,
        manifest: &AccountManifestV3,
    ) -> Result<AccountManifestV3> {
        let prior_manifest = self.store.db().load_manifest_trust(account).await?;
        let trust = verify_manifest_evidence(account, manifest, prior_manifest.as_ref())?;
        if trust.continuity_gap {
            return Err(ChatError::Trust(
                "current manifest requires complete history recovery".into(),
            ));
        }
        self.stage_identity_change(
            account,
            prior_manifest.as_ref(),
            &trust,
            &device_ids(manifest),
        )
        .await?;
        self.store.stage_manifest_trust(trust);
        self.store
            .stage_manifest_history(AccountManifestHistoryRecord {
                peer: account.to_string(),
                sequence: manifest.sequence,
                manifest: manifest.clone(),
            });
        self.store.commit().await?;
        Ok(manifest.clone())
    }

    pub(crate) async fn accept_manifest_evidence_with_history(
        &mut self,
        account: &str,
        pending: &AccountManifestV3,
        trust: ManifestTrust,
        history: Vec<AccountManifestHistoryRecord>,
    ) -> Result<AccountManifestV3> {
        let last = history.last().ok_or_else(|| {
            ChatError::Trust("manifest history recovery returned no complete history".into())
        })?;
        if trust.peer != account
            || trust.continuity_gap
            || last.peer != account
            || last.sequence != pending.sequence
            || last.manifest != *pending
        {
            return Err(ChatError::Trust(
                "manifest history does not terminate at the pending manifest".into(),
            ));
        }
        for record in history {
            if record.peer != account || record.sequence != record.manifest.sequence {
                return Err(ChatError::Trust(
                    "manifest history record has inconsistent ownership or sequence".into(),
                ));
            }
            self.store.stage_manifest_history(record);
        }
        let prior_manifest = self.store.db().load_manifest_trust(account).await?;
        self.stage_identity_change(
            account,
            prior_manifest.as_ref(),
            &trust,
            &device_ids(pending),
        )
        .await?;
        self.store.stage_manifest_trust(trust);
        self.store.commit().await?;
        Ok(pending.clone())
    }

    /// The peer accounts whose identity moved since the last call.
    pub(crate) fn take_identity_changes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.identity_changes)
    }

    /// When a verified manifest gives a peer account another identity than
    /// the one pinned (`prior`): stage what Signal does on a key change. Every
    /// session with the account's devices (as `prior_devices` and the new
    /// manifest list them) is archived, so the next message starts a new one
    /// under the new identity, and the thread gets its "safety number
    /// changed" line, once per identity. Staged in the caller's unit of work;
    /// nothing for this account itself (its own identity moves by a
    /// distribution, applied elsewhere) or a first pin.
    pub(crate) async fn stage_identity_change(
        &mut self,
        peer: &str,
        prior: Option<&ManifestTrust>,
        next: &ManifestTrust,
        next_devices: &[u32],
    ) -> Result<()> {
        let Some(prior) = prior else {
            return Ok(());
        };
        if prior.identity_key.is_empty() || prior.identity_key == next.identity_key {
            return Ok(());
        }
        if next.account == self.account {
            return Ok(());
        }
        let mut devices: std::collections::BTreeSet<u32> = next_devices.iter().copied().collect();
        if let Some(record) = self
            .manifest_history(peer, &prior.incarnation_id, prior.highest_sequence)
            .await?
        {
            devices.extend(
                record
                    .manifest
                    .chat_devices()
                    .map(|(device_id, _)| device_id),
            );
        }
        for device_id in devices {
            let address = ChatAddress::from_sender(&next.account, device_id)?
                .to_protocol()?
                .to_string();
            self.store.archive_session(&address).await?;
        }
        let now = now_millis();
        let content = ChatContent::safety_number_changed_with_id(
            safety_line_id(&next.identity_key),
            crate::clock::rfc3339(now),
        );
        self.store.stage_sent_message(SentMessage {
            send_id: content.message_id.clone(),
            peer: peer.to_string(),
            sender_device_id: self.device_id(),
            content: serde_json::to_vec(&content).map_err(|e| ChatError::Content(e.to_string()))?,
            created_at: now,
            delivered_at: Some(now),
            delivered: true,
            deduplicated: false,
            failed_recipients: 0,
            waiting_recipients: None,
        });
        self.identity_changes.push(peer.to_string());
        Ok(())
    }

    /// Another device of the account verified an identity of `peer` that
    /// isn't the one pinned here (`pinned_identity`, which the account's
    /// manifest lists): as Signal does when a storage record's verified
    /// identity key differs, the thread says the safety number changed,
    /// once per pinned identity, so the person compares it again.
    pub(crate) async fn note_verified_elsewhere_for_another_identity(
        &mut self,
        peer: &str,
        pinned_identity: &str,
    ) -> Result<bool> {
        let id = safety_line_id(pinned_identity);
        if self.sent_message(&id).await?.is_some() {
            return Ok(false);
        }
        let content =
            ChatContent::safety_number_changed_with_id(id, crate::clock::rfc3339(now_millis()));
        self.record_local_notice(peer, &content).await?;
        self.identity_changes.push(peer.to_string());
        Ok(true)
    }

    /// Set whether the peer's pinned identity is verified, if it is still
    /// `identity_key`.
    pub(crate) async fn set_identity_verified(
        &mut self,
        peer: &str,
        identity_key: &str,
        verified: bool,
        now_ms: i64,
    ) -> Result<ManifestTrust> {
        let mut trust = self
            .manifest_trust(peer)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("no identity is pinned for {peer}")))?;
        if trust.identity_key != identity_key {
            return Err(ChatError::Trust(
                "the safety number changed while it was being compared".into(),
            ));
        }
        trust.identity_verified = verified;
        trust.identity_verified_at_ms = now_ms;
        self.store.stage_manifest_trust(trust.clone());
        self.store.commit().await?;
        Ok(trust)
    }

    /// Mark the current TOFU authority as verified after the application has
    /// completed an out-of-band safety-number or QR comparison.
    pub(crate) async fn mark_authority_verified(&mut self, peer: &str) -> Result<ManifestTrust> {
        let mut trust = self
            .manifest_trust(peer)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("no authority is pinned for {peer}")))?;
        if trust.continuity_gap {
            return Err(ChatError::Trust(
                "an incomplete manifest chain cannot be manually verified".into(),
            ));
        }
        if trust.trust == AuthorityTrust::Quarantined {
            return Err(ChatError::Trust(
                "quarantined account identity requires an exact safety-number comparison".into(),
            ));
        }
        trust.trust = AuthorityTrust::Verified;
        self.store.stage_manifest_trust(trust.clone());
        self.store.commit().await?;
        Ok(trust)
    }

    /// Quarantines `peer`'s pinned identity and, once per change, writes the
    /// local "safety number changed" line into its thread (true when it did).
    pub(crate) async fn quarantine_authority(
        &mut self,
        peer: &str,
        reason: &str,
        pending_reset: Option<crate::PendingAccountIdentityResetV1>,
    ) -> Result<(ManifestTrust, bool)> {
        let mut trust = self
            .manifest_trust(peer)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("no authority is pinned for {peer}")))?;
        // The line in the thread, once per change: the first quarantine of
        // the pinned identity, and each new identity offered in its place.
        let offered = pending_reset
            .as_ref()
            .map(|reset| reset.candidate.incarnation_id.clone());
        let earlier = trust
            .pending_reset
            .as_ref()
            .map(|reset| reset.candidate.incarnation_id.clone());
        let line =
            trust.trust != AuthorityTrust::Quarantined || (offered.is_some() && offered != earlier);
        trust.trust = AuthorityTrust::Quarantined;
        trust.quarantine_reason = Some(reason.chars().take(256).collect());
        if let Some(pending_reset) = pending_reset {
            trust.pending_reset = Some(Box::new(pending_reset));
        }
        self.store.stage_manifest_trust(trust.clone());
        if line {
            let now = now_millis();
            let content = ChatContent::safety_number_changed_with_id(
                format!(
                    "safety:{}:{}",
                    trust.incarnation_id,
                    offered.as_deref().unwrap_or("-")
                ),
                crate::clock::rfc3339(now),
            );
            self.store.stage_sent_message(SentMessage {
                send_id: content.message_id.clone(),
                peer: peer.to_string(),
                sender_device_id: self.device_id(),
                content: serde_json::to_vec(&content)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                created_at: now,
                delivered_at: Some(now),
                delivered: true,
                deduplicated: false,
                failed_recipients: 0,
                waiting_recipients: None,
            });
        }
        if let Err(error) = self.store.commit().await {
            self.store.discard();
            return Err(error);
        }
        Ok((trust, line))
    }

    /// Lines this device writes for itself in its own timeline (a group's
    /// change notices): kept as delivered sent rows under their own ids, so
    /// writing one again replaces it. Never sent.
    pub(crate) async fn record_local_lines(&mut self, lines: Vec<ChatContent>) -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        let now = now_millis();
        let me = self.account_ref().to_string();
        for content in lines {
            self.store.stage_sent_message(SentMessage {
                send_id: content.message_id.clone(),
                peer: me.clone(),
                sender_device_id: self.device_id(),
                content: serde_json::to_vec(&content)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                created_at: now,
                delivered_at: Some(now),
                delivered: true,
                deduplicated: false,
                failed_recipients: 0,
                waiting_recipients: None,
            });
        }
        if let Err(error) = self.store.commit().await {
            self.store.discard();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) async fn accept_authority_reset(&mut self, peer: &str) -> Result<ManifestTrust> {
        let mut retained = self
            .manifest_trust(peer)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("no authority is pinned for {peer}")))?;
        if retained.trust != AuthorityTrust::Quarantined {
            return Err(ChatError::Trust(
                "account identity is not awaiting quarantine resolution".into(),
            ));
        }
        if let Some(pending) = retained.pending_reset.take() {
            let mut candidate = pending.candidate;
            let last = pending.history.last().ok_or_else(|| {
                ChatError::Trust("identity-reset candidate has no complete history".into())
            })?;
            if candidate.peer != peer
                || candidate.continuity_gap
                || last.peer != peer
                || last.sequence != candidate.highest_sequence
                || last.manifest.incarnation_id != candidate.incarnation_id
                || last.manifest.manifest_hash().map_err(ChatError::Trust)?
                    != candidate.manifest_hash
            {
                return Err(ChatError::Trust(
                    "identity-reset candidate history is incomplete or inconsistent".into(),
                ));
            }
            for record in pending.history {
                self.store.stage_manifest_history(record);
            }
            candidate.trust = AuthorityTrust::Verified;
            candidate.quarantine_reason = None;
            candidate.pending_reset = None;
            self.store.stage_manifest_trust(candidate.clone());
            self.store.commit().await?;
            return Ok(candidate);
        }
        retained.trust = AuthorityTrust::Verified;
        retained.quarantine_reason = None;
        self.store.stage_manifest_trust(retained.clone());
        self.store.commit().await?;
        Ok(retained)
    }

    /// Validate the account-signed device set before any session or ratchet
    /// mutation, then persist the anti-rollback pin.
    pub(crate) async fn accept_bundle_response(
        &mut self,
        peer: &str,
        response: AccountPreKeyBundlesResponse,
        policy: ManifestPolicy,
    ) -> Result<Vec<DevicePreKeyBundle>> {
        let prior_manifest = self.store.db().load_manifest_trust(peer).await?;
        let next = verify_bundle_trust(peer, &response, policy, prior_manifest.as_ref())?;
        if let Some(manifest) = next.manifest {
            if manifest.continuity_gap {
                return Err(ChatError::Trust(
                    "bundle manifest requires complete history recovery".into(),
                ));
            }
            if prior_manifest.as_ref() != Some(&manifest) {
                self.stage_identity_change(
                    peer,
                    prior_manifest.as_ref(),
                    &manifest,
                    &device_ids(&response.manifest),
                )
                .await?;
                self.store.stage_manifest_trust(manifest);
            }
        }
        let manifest = &response.manifest;
        self.store
            .stage_manifest_history(AccountManifestHistoryRecord {
                peer: peer.to_string(),
                sequence: manifest.sequence,
                manifest: manifest.clone(),
            });
        self.store.commit().await?;
        Ok(crate::manifest::account_bundles(&response))
    }

    /// Atomically accept a bundle only after the engine has fetched and
    /// verified every missing manifest through the range-proof endpoint.
    pub(crate) async fn accept_bundle_response_with_history(
        &mut self,
        peer: &str,
        response: AccountPreKeyBundlesResponse,
        trust: ManifestTrust,
        history: Vec<AccountManifestHistoryRecord>,
        policy: ManifestPolicy,
    ) -> Result<Vec<DevicePreKeyBundle>> {
        let prior_manifest = self.store.db().load_manifest_trust(peer).await?;
        let next = verify_bundle_trust(peer, &response, policy, prior_manifest.as_ref())?;
        let served = &response.manifest;
        let last = history.last().ok_or_else(|| {
            ChatError::Trust("manifest range recovery returned no complete history".into())
        })?;
        if last.peer != peer || last.manifest != *served || last.sequence != served.sequence {
            return Err(ChatError::Trust(
                "manifest range does not terminate at the pending bundle manifest".into(),
            ));
        }
        let inspected = next.manifest.as_ref().ok_or_else(|| {
            ChatError::Trust("range recovery did not produce a manifest trust pin".into())
        })?;
        if trust.continuity_gap
            || trust.manifest_hash != inspected.manifest_hash
            || trust.highest_sequence != inspected.highest_sequence
        {
            return Err(ChatError::Trust(
                "verified history does not match the pending bundle manifest".into(),
            ));
        }
        for record in history {
            if record.peer != peer || record.sequence != record.manifest.sequence {
                return Err(ChatError::Trust(
                    "manifest history record has inconsistent ownership or sequence".into(),
                ));
            }
            self.store.stage_manifest_history(record);
        }
        self.stage_identity_change(
            peer,
            prior_manifest.as_ref(),
            &trust,
            &device_ids(&response.manifest),
        )
        .await?;
        self.store.stage_manifest_trust(trust);
        self.store.commit().await?;
        Ok(crate::manifest::account_bundles(&response))
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
        let padded = message_decrypt(
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
        .await?;
        crate::padding::unpad(&padded)
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
        ensure_room_for_wrappers(send_id, peer_user, content)?;
        let ephemeral = content.is_ephemeral();
        let result = async {
            let plaintext =
                serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
            let recipient_envelopes = self
                .build_send(peer_user, recipient_bundles, &plaintext, summary, rng)
                .await?;
            let created_at = now_millis();
            let (sync, sync_envelopes) = if ephemeral {
                (None, Vec::new())
            } else {
                let transcript = ChatContent::sent_transcript(
                    send_id,
                    crate::address::parse_account(peer_user)?,
                    created_at,
                    content.clone(),
                );
                let transcript_plaintext = serde_json::to_vec(&transcript)
                    .map_err(|e| ChatError::Content(e.to_string()))?;
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
                let sync = (!sync_envelopes.is_empty()).then(|| OutboxSyncLeg {
                    content: transcript_plaintext,
                    envelopes: serde_json::to_vec(&sync_envelopes)
                        .expect("outgoing envelope serialization is infallible"),
                    attempts: 1,
                });
                (sync, sync_envelopes)
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
                sealed_sender: false,
                sealed_capability: None,
                sync,
            });
            self.store.stage_sent_seq(content.seq);
            if !ephemeral {
                self.store.stage_sent_message(SentMessage {
                    send_id: send_id.to_string(),
                    peer: peer_user.to_string(),
                    sender_device_id: self.device_id(),
                    content: plaintext,
                    created_at,
                    delivered_at: None,
                    delivered: false,
                    deduplicated: false,
                    failed_recipients: 0,
                    waiting_recipients: None,
                });
                self.stage_outgoing_contact(peer_user, created_at).await?;
            }
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

    pub(crate) async fn enqueue_sealed_direct_send<R: Rng + CryptoRng>(
        &mut self,
        send: SealedDirectSend<'_>,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<(Vec<SealedOutgoingEnvelopeV1>, Option<Vec<OutgoingEnvelope>>)> {
        let SealedDirectSend {
            send_id,
            peer_user,
            recipient_bundles,
            sync_bundles,
            content,
            sender_certificate,
            capability,
        } = send;
        ensure_room_for_wrappers(send_id, peer_user, content)?;
        let ephemeral = content.is_ephemeral();
        let result = async {
            let plaintext =
                serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
            let recipient_envelopes = self
                .build_sealed_send(
                    peer_user,
                    recipient_bundles,
                    sender_certificate,
                    &plaintext,
                    summary,
                    rng,
                )
                .await?;
            let created_at = now_millis();
            let (sync, sync_envelopes) = if ephemeral {
                (None, Vec::new())
            } else {
                let transcript = ChatContent::sent_transcript(
                    send_id,
                    crate::address::parse_account(peer_user)?,
                    created_at,
                    content.clone(),
                );
                let transcript_plaintext = serde_json::to_vec(&transcript)
                    .map_err(|e| ChatError::Content(e.to_string()))?;
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
                let sync = (!sync_envelopes.is_empty()).then(|| OutboxSyncLeg {
                    content: transcript_plaintext,
                    envelopes: serde_json::to_vec(&sync_envelopes)
                        .expect("outgoing envelope serialization is infallible"),
                    attempts: 1,
                });
                (sync, sync_envelopes)
            };
            self.store.stage_outbox(OutboxEntry {
                send_id: send_id.to_string(),
                peer: peer_user.to_string(),
                content: plaintext.clone(),
                envelopes: serde_json::to_vec(&recipient_envelopes)
                    .map_err(|error| ChatError::Content(error.to_string()))?,
                sealed_sender: true,
                sealed_capability: Some(capability),
                attempts: 1,
                created_at,
                primary_delivered: false,
                sync,
            });
            self.store.stage_sent_seq(content.seq);
            if !ephemeral {
                self.store.stage_sent_message(SentMessage {
                    send_id: send_id.to_string(),
                    peer: peer_user.to_string(),
                    sender_device_id: self.device_id(),
                    content: plaintext,
                    created_at,
                    delivered_at: None,
                    delivered: false,
                    deduplicated: false,
                    failed_recipients: 0,
                    waiting_recipients: None,
                });
                self.stage_outgoing_contact(peer_user, created_at).await?;
            }
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

    pub(crate) async fn amend_sealed_send<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
        sender_certificate: &SenderCertificate,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<SealedOutgoingEnvelopeV1>> {
        let mut entry = self
            .store
            .db()
            .load_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Invalid(format!("unknown pending send {send_id}")))?;
        if !entry.sealed_sender || entry.peer != peer_user {
            return Err(ChatError::Trust(
                "sealed send retry cannot fall back to identified delivery".into(),
            ));
        }
        let plaintext = entry.content.clone();
        let result = self
            .build_sealed_send(
                peer_user,
                bundles,
                sender_certificate,
                &plaintext,
                summary,
                rng,
            )
            .await;
        match result {
            Ok(envelopes) => {
                entry.envelopes = serde_json::to_vec(&envelopes)
                    .map_err(|error| ChatError::Content(error.to_string()))?;
                entry.attempts = entry.attempts.saturating_add(1);
                self.store.stage_outbox(entry);
                self.store.commit().await?;
                Ok(envelopes)
            }
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
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
                list_due_at_ms: Some(crate::contact_list::fresh_due(now_millis())),
            }),
            Some(mut contact) if contact.state == ContactState::Rejected => {
                contact.revision = next_contact_revision(contact.revision)?;
                contact.source_device_id = 0;
                contact.state = ContactState::PendingOutgoing;
                contact.previous_state = None;
                contact.updated_at_ms = updated_at_ms;
                contact.sync_pending = false;
                contact.sync_send_id = None;
                contact.list_due_at_ms =
                    crate::contact_list::due_after_change(&contact, now_millis());
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
        let user = self.user().to_string();
        // Note to Self travels only as a transcript, which must fit too.
        ensure_room_for_wrappers(send_id, &user, content)?;
        let created_at = now_millis();
        let transcript = ChatContent::sent_transcript(
            send_id,
            crate::address::parse_account(self.user())?,
            created_at,
            content.clone(),
        );
        let transcript_plaintext =
            serde_json::to_vec(&transcript).map_err(|e| ChatError::Content(e.to_string()))?;
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
                    sealed_sender: false,
                    sealed_capability: None,
                    sync: None,
                });
                self.store.stage_sent_seq(content.seq);
                self.store.stage_sent_message(SentMessage {
                    send_id: send_id.to_string(),
                    peer: user,
                    sender_device_id: self.device_id(),
                    content: content_plaintext,
                    created_at,
                    delivered_at: None,
                    delivered: false,
                    deduplicated: false,
                    failed_recipients: 0,
                    waiting_recipients: None,
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
                let ephemeral = serde_json::from_slice::<ChatContent>(&entry.content)
                    .ok()
                    .is_some_and(|content| content.is_ephemeral());
                if !ephemeral {
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
                }
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

    /// The line saying `peer` changed their username (one step of their
    /// own verified rename chain), written once: its id names the account
    /// and the rename's sequence, and a line already there stays where it
    /// is. True when it was written now.
    pub async fn record_peer_renamed(
        &mut self,
        peer: &str,
        body: &kutup_chat_proto::PeerRenamedBody,
    ) -> Result<bool> {
        crate::address::parse_account(peer)?;
        body.validate().map_err(ChatError::Invalid)?;
        let id = format!("rename:{peer}:{}", body.sequence);
        if self.sent_message(&id).await?.is_some() {
            return Ok(false);
        }
        let content =
            ChatContent::peer_renamed_with_id(id, crate::clock::rfc3339(now_millis()), body)
                .map_err(ChatError::Invalid)?;
        self.record_local_notice(peer, &content).await?;
        Ok(true)
    }

    /// Write a local-only record (a call in the timeline) into `peer`'s
    /// conversation as this device's own row. It is never sent; the same
    /// message id replaces the earlier record.
    pub async fn record_local_notice(
        &mut self,
        peer_user: &str,
        content: &ChatContent,
    ) -> Result<()> {
        if !ChatContent::is_local_only_kind(&content.kind) {
            return Err(ChatError::Invalid(
                "only a local-only record can be written without sending".into(),
            ));
        }
        if content.message_id.is_empty() {
            return Err(ChatError::Invalid("a local record needs an id".into()));
        }
        let send_id = content.message_id.clone();
        let now = now_millis();
        let result = async {
            self.store.stage_sent_message(SentMessage {
                send_id,
                peer: peer_user.to_string(),
                sender_device_id: self.device_id(),
                content: serde_json::to_vec(content)
                    .map_err(|e| ChatError::Content(e.to_string()))?,
                created_at: now,
                delivered_at: Some(now),
                delivered: true,
                deduplicated: false,
                failed_recipients: 0,
                waiting_recipients: None,
            });
            self.store.commit().await
        }
        .await;
        if result.is_err() {
            self.store.discard();
        }
        result
    }

    pub(crate) async fn discard_ephemeral_outbox(&mut self, send_id: &str) -> Result<()> {
        let entry = self
            .store
            .db()
            .load_outbox(send_id)
            .await?
            .ok_or_else(|| ChatError::Db(format!("send {send_id} has no outbox record")))?;
        let ephemeral = serde_json::from_slice::<ChatContent>(&entry.content)
            .ok()
            .is_some_and(|content| content.is_ephemeral());
        if !ephemeral {
            return Err(ChatError::Invalid(
                "only a typing or call outbox may expire".into(),
            ));
        }
        self.store.delete_outbox(send_id);
        self.store.commit().await
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

    /// A session with `peer` for a sealed send: established when there is
    /// none, and set up again when the server now serves another identity
    /// for the device (recorded as a safety-number change).
    async fn prepare_sealed_session<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<()> {
        let key = peer.to_protocol()?.to_string();
        if self.store.has_session(&key).await? {
            let served = decode_identity_key(&bundle.identity_key)?
                .serialize()
                .to_vec();
            if self.store.peer_identity(&key).await?.as_deref() != Some(served.as_slice()) {
                if self.accept_identity_staged(peer, bundle).await? {
                    summary.safety_number_changes.push(peer.clone());
                }
                self.store.delete_session(&key);
                self.establish_staged(peer, bundle, rng).await?;
            }
        } else {
            self.establish_staged(peer, bundle, rng).await?;
        }
        Ok(())
    }

    async fn build_sealed_send<R: Rng + CryptoRng>(
        &mut self,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
        sender_certificate: &SenderCertificate,
        plaintext: &[u8],
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<Vec<SealedOutgoingEnvelopeV1>> {
        let padded = crate::padding::pad(plaintext);
        let mut envelopes = Vec::with_capacity(bundles.len());
        for bundle in bundles {
            let peer = ChatAddress::from_sender(peer_user, bundle.device_id)?;
            self.prepare_sealed_session(&peer, bundle, summary, rng)
                .await?;
            let content = sealed_sender_encrypt(
                &peer.to_protocol()?,
                sender_certificate,
                &padded,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                now(),
                rng,
            )
            .await?;
            envelopes.push(SealedOutgoingEnvelopeV1 {
                device_id: bundle.device_id,
                registration_id: bundle.registration_id,
                suite: bundle.suite,
                content: STANDARD.encode(content),
            });
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
            &crate::padding::pad(plaintext),
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

    /// Seal one plaintext to each of this account's other devices, under
    /// the sessions this (old) identity has with them, for an identity
    /// distribution's request. Nothing is kept: the identity changes once the
    /// request is taken, and every session goes with it.
    pub(crate) async fn seal_to_own_devices<R: Rng + CryptoRng>(
        &mut self,
        messages: &[(&DevicePreKeyBundle, Vec<u8>)],
        rng: &mut R,
    ) -> Result<Vec<OutgoingEnvelope>> {
        let mut summary = SendSummary::default();
        let mut envelopes = Vec::with_capacity(messages.len());
        let result = async {
            for (bundle, plaintext) in messages {
                let peer =
                    ChatAddress::from_account(self.address.account.clone(), bundle.device_id);
                envelopes.push(
                    self.seal_device(&peer, bundle, plaintext, &mut summary, rng)
                        .await?,
                );
            }
            Ok::<_, ChatError>(())
        }
        .await;
        self.store.discard();
        result?;
        Ok(envelopes)
    }

    /// Install this device's part of an account identity change in one
    /// commit (`ChatStore::stage_identity_install`), clearing a kept
    /// `accountIdentity` sync with it. The caller opens the session again.
    pub(crate) async fn install_identity(
        &mut self,
        identity: &libsignal_protocol::IdentityKeyPair,
        registration_id: u32,
        signed_pre_key: (u32, Vec<u8>),
        last_resort_kyber_pre_key: (u32, Vec<u8>),
    ) -> Result<()> {
        self.store.discard();
        self.store.stage_identity_install(
            LocalIdentity {
                identity_key_pair: identity.serialize().to_vec(),
                registration_id,
                device_id: Some(self.device_id()),
                credential: self.credential().map(str::to_string),
            },
            signed_pre_key,
            last_resort_kyber_pre_key,
        );
        self.store.stage_pending_account_identity(None);
        self.store.commit().await
    }

    /// Drop a kept `accountIdentity` sync that can no longer apply.
    pub(crate) async fn drop_pending_account_identity(&mut self) -> Result<()> {
        self.store.discard();
        self.store.stage_pending_account_identity(None);
        self.store.commit().await
    }

    fn is_self(&self, peer: &ChatAddress) -> bool {
        peer.account == self.address.account && peer.device_id == self.address.device_id
    }
}

fn current_profile_key(content: &kutup_chat_proto::ChatContent) -> Option<&str> {
    let suite = content.profile_suite?;
    if kutup_chat_proto::ProfileSuiteId::try_from(suite).ok()
        != Some(kutup_chat_proto::ProfileSuiteId::XChaCha20Poly1305V1)
    {
        return None;
    }
    content.profile_key.as_deref()
}

/// Look up the bundle for `device_id` in a served set (a 409 names a device the
/// server should also have handed us a bundle for).
fn direct_conversation(value: &str) -> Result<kutup_chat_proto::ConversationId> {
    Ok(kutup_chat_proto::ConversationId::direct(
        crate::address::parse_account(value)?,
    ))
}

fn find_bundle(bundles: &[DevicePreKeyBundle], device_id: u32) -> Result<&DevicePreKeyBundle> {
    bundles
        .iter()
        .find(|b| b.device_id == device_id)
        .ok_or(ChatError::MissingBundle(device_id))
}

struct ExpiredContent {
    message_id: String,
    attachment_id: Option<String>,
}

/// What this account's same-account controls say about its history:
/// messages deleted for me (by conversation), and the list-state and
/// read-position records a newer one replaces.
#[derive(Default)]
struct AccountControls {
    deleted: std::collections::BTreeSet<(String, String)>,
    /// Control message ids no longer needed.
    superseded: std::collections::BTreeSet<String>,
}

impl AccountControls {
    fn deleted_content(
        &self,
        bytes: &[u8],
        conversation: &kutup_chat_proto::ConversationId,
    ) -> Option<ExpiredContent> {
        if self.deleted.is_empty() {
            return None;
        }
        let content = serde_json::from_slice::<ChatContent>(bytes).ok()?;
        if !self
            .deleted
            .contains(&(conversation.key(), content.message_id.clone()))
        {
            return None;
        }
        Some(ExpiredContent {
            message_id: content.message_id.clone(),
            attachment_id: content
                .as_attachment()
                .map(|attachment| attachment.attachment_id),
        })
    }

    fn is_superseded(&self, bytes: &[u8]) -> bool {
        !self.superseded.is_empty()
            && serde_json::from_slice::<ChatContent>(bytes)
                .ok()
                .is_some_and(|content| self.superseded.contains(&content.message_id))
    }
}

/// Reads this account's Note to Self controls (sent here or synced from
/// another device, live or restored). Only the newest conversation state
/// (by revision, then device) and the furthest read position (by the
/// reading device's clock) per conversation are kept; delete-for-me
/// controls are all kept so a copy arriving late is removed too.
fn collect_account_controls(outgoing: &[SentMessage], local_account: &str) -> AccountControls {
    let mut controls = AccountControls::default();
    let mut states = std::collections::BTreeMap::<String, ((u32, u32), String)>::new();
    // Stickers: the newest save of each, and which were removed.
    let mut stickers = std::collections::BTreeMap::<String, ((String, String), String)>::new();
    let mut removed_stickers = std::collections::BTreeSet::<String>::new();
    let mut positions = std::collections::BTreeMap::<String, ((i64, String), String)>::new();
    let own = outgoing
        .iter()
        .filter(|message| message.peer == local_account)
        .map(|message| message.content.as_slice());
    for bytes in own {
        let Ok(content) = serde_json::from_slice::<ChatContent>(bytes) else {
            continue;
        };
        let control_id = content.message_id.clone();
        if let Some(delete) = content.as_delete_for_me() {
            let key = delete.conversation.key();
            for message_id in delete.message_ids {
                controls.deleted.insert((key.clone(), message_id));
            }
        } else if let Some(opened) = content.as_view_once_opened() {
            // Opened once: gone like a delete-for-me; the control itself
            // stays as the "Viewed" placeholder.
            controls
                .deleted
                .insert((opened.conversation.key(), opened.message_id));
        } else if let Some(state) = content.as_conversation_state() {
            keep_newest(
                &mut states,
                state.conversation.key(),
                state.order(),
                control_id,
                &mut controls.superseded,
            );
        } else if let Some(saved) = content.as_sticker_saved() {
            let order = (content.sent_at.clone(), control_id.clone());
            keep_newest(
                &mut stickers,
                saved.sticker_id,
                order,
                control_id,
                &mut controls.superseded,
            );
        } else if let Some(removed) = content.as_sticker_removed() {
            removed_stickers.insert(removed.sticker_id);
        } else if let Some(position) = content.as_read_position() {
            let order = (position.read_through_ms, control_id.clone());
            keep_newest(
                &mut positions,
                position.conversation.key(),
                order,
                control_id,
                &mut controls.superseded,
            );
        }
    }
    // A removed sticker's image goes; the small removal stays, so a save
    // that arrives late cannot bring it back.
    for (sticker_id, (_, control_id)) in stickers {
        if removed_stickers.contains(&sticker_id) {
            controls.superseded.insert(control_id);
        }
    }
    controls
}

fn keep_newest<O: Ord>(
    newest: &mut std::collections::BTreeMap<String, (O, String)>,
    conversation: String,
    order: O,
    control_id: String,
    superseded: &mut std::collections::BTreeSet<String>,
) {
    match newest.get_mut(&conversation) {
        Some(current) if current.0 >= order => {
            if current.1 != control_id {
                superseded.insert(control_id);
            }
        }
        Some(current) => {
            superseded.insert(std::mem::replace(current, (order, control_id)).1);
        }
        None => {
            newest.insert(conversation, (order, control_id));
        }
    }
}

pub(crate) type DisappearingExpiryStarts = std::collections::BTreeMap<(String, String), i64>;

pub(crate) fn collect_disappearing_expiry_starts(
    outgoing: &[SentMessage],
    local_account: &str,
) -> Result<DisappearingExpiryStarts> {
    let mut starts = DisappearingExpiryStarts::new();
    for message in outgoing {
        if message.peer == local_account {
            collect_disappearing_expiry_start(&message.content, &mut starts)?;
        }
    }
    Ok(starts)
}

fn collect_disappearing_expiry_start(
    bytes: &[u8],
    starts: &mut DisappearingExpiryStarts,
) -> Result<()> {
    let Ok(content) = serde_json::from_slice::<ChatContent>(bytes) else {
        return Ok(());
    };
    let start = content.as_disappearing_expiry_start();
    if content.kind == kutup_chat_proto::content::kind::DISAPPEARING_EXPIRY_START && start.is_none()
    {
        return Err(ChatError::Content(
            "invalid durable disappearing expiry start".into(),
        ));
    }
    if let Some(start) = start {
        let key = (start.conversation.key(), start.target_message_id);
        starts
            .entry(key)
            .and_modify(|current| *current = (*current).min(start.started_at_ms))
            .or_insert(start.started_at_ms);
    }
    Ok(())
}

pub(crate) fn disappearing_deadline_for_content(
    content: &ChatContent,
    conversation: &kutup_chat_proto::ConversationId,
    outgoing: bool,
    timestamp_ms: i64,
    starts: &DisappearingExpiryStarts,
) -> Result<Option<i64>> {
    let Some(seconds) = content
        .disappearing_after_seconds()
        .map_err(ChatError::Content)?
    else {
        return Ok(None);
    };
    let base_ms = if outgoing {
        timestamp_ms
    } else {
        let Some(started_at_ms) = starts.get(&(conversation.key(), content.message_id.clone()))
        else {
            return Ok(None);
        };
        *started_at_ms
    };
    Ok(Some(
        base_ms.saturating_add(i64::from(seconds).saturating_mul(1_000)),
    ))
}

fn expired_content(
    bytes: &[u8],
    conversation: &kutup_chat_proto::ConversationId,
    outgoing: bool,
    timestamp_ms: i64,
    starts: &DisappearingExpiryStarts,
    now_ms: i64,
) -> Result<Option<ExpiredContent>> {
    // Direct history deliberately retains undecodable authenticated payloads
    // for forward compatibility. A future content kind must not permanently
    // block expiry maintenance for every other row.
    let Ok(content) = serde_json::from_slice::<ChatContent>(bytes) else {
        return Ok(None);
    };
    let Some(expires_at) =
        disappearing_deadline_for_content(&content, conversation, outgoing, timestamp_ms, starts)?
    else {
        return Ok(None);
    };
    if now_ms < expires_at {
        return Ok(None);
    }
    Ok(Some(ExpiredContent {
        message_id: content.message_id.clone(),
        attachment_id: content
            .as_attachment()
            .map(|attachment| attachment.attachment_id),
    }))
}

fn collect_expired(
    expired: ExpiredContent,
    message_ids: &mut std::collections::BTreeSet<String>,
    attachment_ids: &mut std::collections::BTreeSet<String>,
) {
    message_ids.insert(expired.message_id);
    if let Some(attachment_id) = expired.attachment_id {
        attachment_ids.insert(attachment_id);
    }
}

fn content_targets_any(
    bytes: &[u8],
    message_ids: &std::collections::BTreeSet<String>,
) -> Result<bool> {
    if message_ids.is_empty() {
        return Ok(false);
    }
    let Ok(content) = serde_json::from_slice::<ChatContent>(bytes) else {
        return Ok(false);
    };
    Ok(content
        .as_reaction()
        .is_some_and(|reaction| message_ids.contains(&reaction.target_message_id))
        || content
            .as_message_mutation()
            .is_some_and(|mutation| message_ids.contains(&mutation.target_message_id))
        || content
            .as_poll_vote()
            .is_some_and(|vote| message_ids.contains(&vote.target_message_id))
        || content
            .as_poll_terminate()
            .is_some_and(|end| message_ids.contains(&end.target_message_id))
        || content.as_receipt().is_some_and(|receipt| {
            receipt
                .message_ids
                .iter()
                .any(|message_id| message_ids.contains(message_id))
        })
        || content
            .as_disappearing_expiry_start()
            .is_some_and(|start| message_ids.contains(&start.target_message_id))
        || content
            .as_sent_transcript()
            .and_then(|transcript| transcript.content.as_disappearing_expiry_start())
            .is_some_and(|start| message_ids.contains(&start.target_message_id)))
}

/// The wall clock libsignal uses for prekey/session staleness checks. The
/// platform boundary uses JavaScript's clock in browsers because
/// `SystemTime::now()` is unsupported on `wasm32-unknown-unknown`.
fn now() -> SystemTime {
    crate::clock::now()
}

/// Unix-epoch millis, saturating to 0 before the epoch (never in practice).
/// The Chat devices a manifest lists: the ones messages go to.
fn device_ids(manifest: &AccountManifestV3) -> Vec<u32> {
    manifest
        .chat_devices()
        .map(|(device_id, _)| device_id)
        .collect()
}

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
    hash.update(kutup_crypto::labels::CONTACT_CONTROL_V1);
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

/// A direct message must fit an envelope not only as itself but also as
/// the two things that may carry it again later: a re-send to a device that
/// could not read it (wrapped, and sent as a first message) and the sent
/// transcript to this account's other devices. Refused here, before anything
/// is queued, rather than failing at the server when it is too late to say so.
fn ensure_room_for_wrappers(send_id: &str, peer_user: &str, content: &ChatContent) -> Result<()> {
    let size = |content: &ChatContent| -> Result<usize> {
        Ok(serde_json::to_vec(content)
            .map_err(|e| ChatError::Content(e.to_string()))?
            .len())
    };
    let mut largest = size(content)?;
    if content.is_resendable() {
        // The longest ids and time a re-send can carry.
        let wrapped = ChatContent::resend_with_id(
            "x".repeat(64),
            "0000-00-00T00:00:00.000000000+00:00",
            u64::MAX,
            content.clone(),
        )
        .map_err(ChatError::Content)?;
        largest = largest.max(size(&wrapped)?);
    }
    if !content.is_ephemeral() {
        let transcript = ChatContent::sent_transcript(
            send_id,
            crate::address::parse_account(peer_user)?,
            i64::MAX,
            content.clone(),
        );
        largest = largest.max(size(&transcript)?);
    }
    if largest > crate::padding::MAX_DIRECT_PLAINTEXT_BYTES {
        return Err(ChatError::Invalid("message is too large to send".into()));
    }
    Ok(())
}

fn next_contact_revision(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| ChatError::Invalid("contact revision is exhausted".into()))
}

impl TryFrom<&ContactRecord> for ContactControlBody {
    type Error = ChatError;

    fn try_from(contact: &ContactRecord) -> Result<Self> {
        Ok(Self {
            peer: crate::address::parse_account(&contact.peer)?,
            state: contact.state,
            previous_state: contact.previous_state,
            revision: contact.revision,
            source_device_id: contact.source_device_id,
            updated_at_ms: contact.updated_at_ms,
        })
    }
}

/// Group messages (docs/plans/pairwise-groups.md §1): sender keys over the
/// pairwise sessions, sealed per device as Signal-Desktop's
/// `encryptForSenderKey` does. Each call commits what it staged, or nothing.
impl Session {
    /// This device's sender-key distribution message for `distribution_id`,
    /// creating the key on first use.
    pub(crate) async fn sender_key_distribution<R: Rng + CryptoRng>(
        &mut self,
        distribution_id: uuid::Uuid,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let me = self.address.to_protocol()?;
        let result = libsignal_protocol::create_sender_key_distribution_message(
            &me,
            distribution_id,
            &mut self.store.sender_key_store,
            rng,
        )
        .await;
        match result {
            Ok(message) => {
                self.store.commit().await?;
                Ok(message.serialized().to_vec())
            }
            Err(error) => {
                self.store.discard();
                Err(error.into())
            }
        }
    }

    /// Takes a member device's sender key for its distribution.
    pub(crate) async fn process_sender_key_distribution(
        &mut self,
        sender: &ChatAddress,
        message: &[u8],
    ) -> Result<()> {
        let parsed = libsignal_protocol::SenderKeyDistributionMessage::try_from(message)?;
        let result = libsignal_protocol::process_sender_key_distribution_message(
            &sender.to_protocol()?,
            &parsed,
            &mut self.store.sender_key_store,
        )
        .await;
        match result {
            Ok(()) => self.store.commit().await,
            Err(error) => {
                self.store.discard();
                Err(error.into())
            }
        }
    }

    /// Encrypts `plaintext` once under this device's sender key for
    /// `distribution_id`: the `SenderKeyMessage` every member device gets.
    pub(crate) async fn group_encrypt<R: Rng + CryptoRng>(
        &mut self,
        distribution_id: uuid::Uuid,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let me = self.address.to_protocol()?;
        let padded = crate::padding::pad(plaintext);
        let result = libsignal_protocol::group_encrypt(
            &mut self.store.sender_key_store,
            &me,
            distribution_id,
            &padded,
            rng,
        )
        .await;
        match result {
            Ok(message) => {
                self.store.commit().await?;
                Ok(message.serialized().to_vec())
            }
            Err(error) => {
                self.store.discard();
                Err(error.into())
            }
        }
    }

    /// Opens a member device's sender-key message and stores what it carries,
    /// in one commit with the sender key's advance and the mailbox receipt.
    /// The engine has already checked the sender is a verified member of the
    /// group the message names. The certificate is checked here as
    /// `sealed_sender_decrypt` checks it for a pairwise message.
    pub(crate) async fn receive_sealed_group_envelope(
        &mut self,
        envelope: &DeliveredEnvelope,
        inspection: &SealedEnvelopeInspection,
        validating_root: &PublicKey,
        gate: &dyn Fn(&kutup_chat_proto::group::GroupContextV1, &str) -> GroupGate,
    ) -> Result<ReceiveOutcome> {
        let group_id = inspection
            .group_id
            .ok_or_else(|| ChatError::Trust("not a group message".into()))?;
        let now = Timestamp::from_epoch_millis(
            u64::try_from(now_millis())
                .map_err(|_| ChatError::Trust("system clock predates the epoch".into()))?,
        );
        if !inspection.certificate.validate(validating_root, now)? {
            return Err(ChatError::Trust(
                "the sender certificate is not valid".into(),
            ));
        }
        let from = ChatAddress::from_sender(&inspection.sender, inspection.sender_device_id)?;
        if self.is_self(&from) {
            return Err(ChatError::Trust(
                "a group message from this very device".into(),
            ));
        }
        let bytes = STANDARD
            .decode(&envelope.content)
            .map_err(|error| ChatError::Wire(error.to_string()))?;
        let usmc = sealed_sender_decrypt_to_usmc(&bytes, &self.store.identity_store).await?;
        let decrypted = libsignal_protocol::group_decrypt(
            usmc.contents()?,
            &mut self.store.sender_key_store,
            &from.to_protocol()?,
        )
        .await;
        let result = async {
            let plaintext = crate::padding::unpad(&decrypted?)?;
            let content: ChatContent = serde_json::from_slice(&plaintext)
                .map_err(|_| ChatError::Content("a group message doesn't read".into()))?;
            let context = content
                .group_context()
                .ok_or_else(|| ChatError::Content("a group message without its group".into()))?;
            if context.group_id != kutup_chat_proto::group::encode_group_id(&group_id) {
                return Err(ChatError::Trust(
                    "a group message names another group inside".into(),
                ));
            }
            let change = content.kind == kutup_chat_proto::content::kind::GROUP_CHANGE;
            if !change && !is_group_history_kind(&content.kind) {
                return Err(ChatError::Content(format!(
                    "{} is not sent to a whole group",
                    content.kind
                )));
            }
            let gate = gate(&context, &content.kind);
            if gate == GroupGate::Accept && !change {
                self.store.stage_message(InboxMessage {
                    id: envelope.id.clone(),
                    peer: inspection.sender.clone(),
                    sender_device_id: inspection.sender_device_id,
                    cursor: envelope.cursor,
                    content: plaintext,
                    received_at: now_millis(),
                });
            }
            Ok((gate, change, content))
        }
        .await;
        match result {
            Ok((GroupGate::Accept, change, content)) => {
                self.stage_inbound_ack(envelope)?;
                self.store.commit().await?;
                if change {
                    return Ok(ReceiveOutcome::Suppressed {
                        id: envelope.id.clone(),
                    });
                }
                Ok(ReceiveOutcome::Message(Box::new(ReceivedMessage {
                    from,
                    content,
                    cursor: envelope.cursor,
                    id: envelope.id.clone(),
                })))
            }
            // Read again after the catch-up, from the same sender key state.
            Ok((GroupGate::CatchUp, ..)) => {
                self.store.discard();
                Ok(ReceiveOutcome::GroupCatchUp)
            }
            Ok((GroupGate::Hold, ..)) => {
                self.store.discard();
                Ok(ReceiveOutcome::GroupHeld {
                    group_id: kutup_chat_proto::group::encode_group_id(&group_id),
                    sender: inspection.sender.clone(),
                })
            }
            Ok((GroupGate::Refuse, ..)) => {
                self.store.discard();
                self.ack_dropped(envelope).await?;
                Ok(ReceiveOutcome::Suppressed {
                    id: envelope.id.clone(),
                })
            }
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Sets what the engine decided for `(group id, sender)`'s pairwise
    /// group content, for the next read of its envelope.
    pub(crate) fn decide_group(&mut self, group_id: &str, sender: &str, gate: GroupGate) {
        self.group_decisions
            .insert((group_id.to_string(), sender.to_string()), gate);
    }

    /// Forgets the decisions after a pass.
    pub(crate) fn clear_group_decisions(&mut self) {
        self.group_decisions.clear();
    }

    /// Acknowledges an envelope that is dropped unread (a group message from
    /// someone who isn't a member).
    pub(crate) async fn ack_dropped(&mut self, envelope: &DeliveredEnvelope) -> Result<()> {
        self.stage_inbound_ack(envelope)?;
        self.store.commit().await
    }

    /// Keeps a group message that came pairwise (a fallback, or a resend's
    /// content) once the engine checked its sender is a member.
    pub(crate) async fn store_group_message(
        &mut self,
        id: &str,
        from: &ChatAddress,
        cursor: u64,
        content: &ChatContent,
    ) -> Result<()> {
        if content.group_context().is_none() || !is_group_history_kind(&content.kind) {
            return Err(ChatError::Content("not a group message".into()));
        }
        // It takes the place of the record that waited for it; a copy of one
        // already here is dropped.
        let sender = from.name();
        let already_here = self
            .stage_filled_in(&sender, std::slice::from_ref(&content.message_id))
            .await?;
        if already_here {
            return self.store.commit().await;
        }
        self.store.stage_message(InboxMessage {
            id: id.to_string(),
            peer: from.name(),
            sender_device_id: from.device_id,
            cursor,
            content: serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?,
            received_at: now_millis(),
        });
        self.store.commit().await
    }

    /// Settles the records waiting for `send_ids` from `sender` as a direct
    /// control does: `lost` keeps a record that says so, anything else
    /// removes them.
    pub(crate) async fn settle_waiting(
        &mut self,
        sender: &str,
        action: kutup_chat_proto::SessionControlAction,
        send_ids: &[String],
    ) -> Result<()> {
        let staged = if action == kutup_chat_proto::SessionControlAction::Lost {
            self.stage_lost(sender, send_ids).await
        } else {
            self.stage_filled_in(sender, send_ids).await.map(|_| ())
        };
        match staged {
            Ok(()) => self.store.commit().await,
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Stands a record in a group's thread for a group message this device
    /// couldn't read, and marks its envelope handled.
    pub(crate) async fn record_group_placeholder(
        &mut self,
        envelope: &DeliveredEnvelope,
        from: &ChatAddress,
        content: &ChatContent,
    ) -> Result<()> {
        self.store.stage_message(InboxMessage {
            id: envelope.id.clone(),
            peer: from.name(),
            sender_device_id: from.device_id,
            cursor: envelope.cursor,
            content: serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?,
            received_at: now_millis(),
        });
        let staged = self.stage_inbound_ack(envelope);
        match staged {
            Ok(()) => self.store.commit().await,
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Seals one sender-key message for each of `peer_user`'s `bundles`
    /// (sessions and identities established as needed): the inner content is
    /// a `SenderKey` message, resendable, naming the group.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn seal_group_message<R: Rng + CryptoRng>(
        &mut self,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
        sender_certificate: &SenderCertificate,
        group_id: &[u8; 32],
        sender_key_message: &[u8],
        hint: libsignal_protocol::ContentHint,
        rng: &mut R,
    ) -> Result<SealedGroupSend> {
        let mut summary = SendSummary::default();
        let result = async {
            let usmc = libsignal_protocol::UnidentifiedSenderMessageContent::new(
                libsignal_protocol::CiphertextMessageType::SenderKey,
                sender_certificate.clone(),
                sender_key_message.to_vec(),
                hint,
                Some(group_id.to_vec()),
            )?;
            let mut envelopes = Vec::with_capacity(bundles.len());
            for bundle in bundles {
                let peer = ChatAddress::from_sender(peer_user, bundle.device_id)?;
                if self.is_self(&peer) {
                    continue;
                }
                // The same identity check as a direct sealed send: a device
                // whose served identity changed is set up again and shown.
                self.prepare_sealed_session(&peer, bundle, &mut summary, rng)
                    .await?;
                let content = libsignal_protocol::sealed_sender_encrypt_from_usmc(
                    &peer.to_protocol()?,
                    &usmc,
                    &self.store.identity_store,
                    rng,
                )
                .await?;
                envelopes.push(SealedOutgoingEnvelopeV1 {
                    device_id: bundle.device_id,
                    registration_id: bundle.registration_id,
                    suite: bundle.suite,
                    content: STANDARD.encode(content),
                });
            }
            Ok::<_, ChatError>(envelopes)
        }
        .await;
        match result {
            Ok(envelopes) => {
                self.store.commit().await?;
                Ok(SealedGroupSend {
                    envelopes,
                    safety_number_changes: summary.safety_number_changes,
                })
            }
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Seals one sender-key message once for every device of `recipients`
    /// on one destination server: libsignal's multi-recipient sealed sender
    /// (v2, version `0x23`), which that server splits per device. Sessions
    /// and identities are checked and set up per device as for
    /// [`Self::seal_group_message`]; the payload names each account by its
    /// bare id (see `multi_seal`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn seal_group_multi<R: Rng + CryptoRng>(
        &mut self,
        recipients: &[(
            kutup_crypto::account_ref::AccountRef,
            Vec<DevicePreKeyBundle>,
        )],
        sender_certificate: &SenderCertificate,
        group_id: &[u8; 32],
        sender_key_message: &[u8],
        hint: libsignal_protocol::ContentHint,
        rng: &mut R,
    ) -> Result<SealedGroupMulti> {
        let mut summary = SendSummary::default();
        let result = async {
            let usmc = libsignal_protocol::UnidentifiedSenderMessageContent::new(
                libsignal_protocol::CiphertextMessageType::SenderKey,
                sender_certificate.clone(),
                sender_key_message.to_vec(),
                hint,
                Some(group_id.to_vec()),
            )?;
            let mut full_names = std::collections::HashMap::new();
            let mut destinations = Vec::new();
            let mut sessions = Vec::new();
            for (account, bundles) in recipients {
                let full = account.to_string();
                if full_names
                    .insert(account.account_id.clone(), full.clone())
                    .is_some()
                {
                    return Err(ChatError::Invalid(format!(
                        "account {} named twice in one send",
                        account.account_id
                    )));
                }
                let mut bundles: Vec<&DevicePreKeyBundle> = bundles.iter().collect();
                bundles.sort_by_key(|bundle| bundle.device_id);
                for bundle in bundles {
                    let peer = ChatAddress::from_sender(&full, bundle.device_id)?;
                    if self.is_self(&peer) {
                        continue;
                    }
                    self.prepare_sealed_session(&peer, bundle, &mut summary, rng)
                        .await?;
                    let session = libsignal_protocol::SessionStore::load_session(
                        &self.store.session_store,
                        &peer.to_protocol()?,
                    )
                    .await?
                    .ok_or_else(|| {
                        ChatError::Invalid(format!(
                            "no session with {}.{}",
                            peer.name(),
                            peer.device_id
                        ))
                    })?;
                    destinations.push(libsignal_protocol::ProtocolAddress::new(
                        account.account_id.clone(),
                        crate::address::device_id_u8(bundle.device_id)?,
                    ));
                    sessions.push(session);
                }
            }
            if destinations.is_empty() {
                return Err(ChatError::Invalid(
                    "a multi-recipient send names no device".into(),
                ));
            }
            let identities =
                crate::multi_seal::NamedIdentities::new(&self.store.identity_store, full_names);
            let destinations: Vec<&libsignal_protocol::ProtocolAddress> =
                destinations.iter().collect();
            let sessions: Vec<&libsignal_protocol::SessionRecord> = sessions.iter().collect();
            let payload = libsignal_protocol::sealed_sender_multi_recipient_encrypt(
                &destinations,
                &sessions,
                std::iter::empty(),
                &usmc,
                &identities,
                rng,
            )
            .await?;
            Ok::<_, ChatError>(payload)
        }
        .await;
        match result {
            Ok(payload) => {
                self.store.commit().await?;
                Ok(SealedGroupMulti {
                    payload,
                    safety_number_changes: summary.safety_number_changes,
                })
            }
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }

    /// Seals `content` pairwise for each of `peer_user`'s `bundles`: a group's
    /// hidden kinds (a sender key, an invitation, a group resend) and its
    /// pairwise fallback. Nothing is written to the direct outbox or history.
    pub(crate) async fn seal_pairwise<R: Rng + CryptoRng>(
        &mut self,
        peer_user: &str,
        bundles: &[DevicePreKeyBundle],
        sender_certificate: &SenderCertificate,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<SealedGroupSend> {
        let plaintext =
            serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
        let mut summary = SendSummary::default();
        let result = self
            .build_sealed_send(
                peer_user,
                bundles,
                sender_certificate,
                &plaintext,
                &mut summary,
                rng,
            )
            .await;
        match result {
            Ok(envelopes) => {
                self.store.commit().await?;
                Ok(SealedGroupSend {
                    envelopes,
                    safety_number_changes: summary.safety_number_changes,
                })
            }
            Err(error) => {
                self.store.discard();
                Err(error)
            }
        }
    }
}

/// Envelopes sealed for one account, and its devices whose identity changed
/// on the way (a safety-number change to show).
pub(crate) struct SealedGroupSend {
    pub envelopes: Vec<SealedOutgoingEnvelopeV1>,
    pub safety_number_changes: Vec<ChatAddress>,
}

/// One multi-recipient sealed message for one destination server: the
/// libsignal payload (`0x23`), sent once, split per device by that server.
pub(crate) struct SealedGroupMulti {
    pub payload: Vec<u8>,
    pub safety_number_changes: Vec<ChatAddress>,
}

#[cfg(all(test, feature = "sqlite"))]
mod sealed_tests {
    use super::*;
    use futures_executor::block_on;
    use libsignal_protocol::{KeyPair, ServerCertificate};
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use crate::{Pending, SqliteChatDb};
    use kutup_chat_proto::{DeliveredEnvelope, DevicePreKeyBundle, EnvelopeType};

    fn bundle(session: &Session) -> DevicePreKeyBundle {
        let registration = session.published_keys().expect("fresh keys");
        DevicePreKeyBundle {
            device_id: session.device_id(),
            registration_id: registration.registration_id,
            suite: registration.suite,
            identity_key: registration.identity_key.clone(),
            signed_pre_key: registration.signed_pre_key.clone(),
            kyber_pre_key: registration
                .one_time_kyber_pre_keys
                .first()
                .cloned()
                .unwrap_or_else(|| registration.last_resort_kyber_pre_key.clone()),
            one_time_pre_key: registration.one_time_pre_keys.first().cloned(),
        }
    }

    #[test]
    fn account_controls_delete_for_me_and_prune_superseded_state() {
        use kutup_chat_proto::{ConversationStateBody, DeleteForMeBody, ReadPositionBody};
        let mut rng = OsRng.unwrap_err();
        let db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let mut session = block_on(Session::generate(
            db.clone(),
            "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test",
            1,
            1,
            &mut rng,
        ))
        .unwrap();
        block_on(session.complete_registration(1)).unwrap();

        const KEPT: &str = "11111111-1111-4111-8111-111111111111";
        const GONE: &str = "22222222-2222-4222-8222-222222222222";
        const GROUP_GONE: &str = "33333333-3333-4333-8333-333333333333";
        let group_context = crate::group::test_context(4);
        let bob = direct_conversation("aci:00000000-0000-4000-8000-81b637d8fcd2@b.test").unwrap();
        let group = kutup_chat_proto::ConversationId::Group {
            group_id: group_context.group_id.clone(),
        };
        let text = |id: &str, seq| {
            serde_json::to_vec(&ChatContent::text_with_id(
                id,
                "2026-09-25T00:00:00Z",
                seq,
                "hi",
            ))
            .unwrap()
        };
        let control_id = |n: u32| format!("aaaaaaaa-aaaa-4aaa-8aaa-{n:012}");
        let mut pending = Pending::default();
        for (id, seq) in [(KEPT, 1), (GONE, 2)] {
            pending.messages.push(InboxMessage {
                id: format!("mailbox-{seq}"),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                sender_device_id: 1,
                cursor: seq,
                content: text(id, seq),
                received_at: 100 + seq as i64,
            });
        }
        let reaction = ChatContent::reaction_with_id(
            "55555555-5555-4555-8555-555555555555",
            "2026-09-25T00:00:00Z",
            3,
            GONE,
            "👍",
            true,
        )
        .unwrap();
        pending.messages.push(InboxMessage {
            id: "mailbox-3".into(),
            peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
            sender_device_id: 1,
            cursor: 3,
            content: serde_json::to_vec(&reaction).unwrap(),
            received_at: 103,
        });
        // A pairwise group's message: in the inbox, under its group.
        pending.messages.push(InboxMessage {
            id: "mailbox-group".into(),
            peer: "aci:00000000-0000-4000-8000-61ea0803f885@d.test".into(),
            sender_device_id: 1,
            cursor: 4,
            content: serde_json::to_vec(
                &ChatContent::text_with_id(GROUP_GONE, "2026-09-25T00:00:00Z", 4, "group")
                    .with_group_context(&group_context),
            )
            .unwrap(),
            received_at: 400,
        });
        let note = |n: u32, content: ChatContent| {
            let send_id = control_id(n);
            (
                send_id.clone(),
                SentMessage {
                    send_id,
                    peer: "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test".into(),
                    sender_device_id: 2,
                    content: serde_json::to_vec(&content).unwrap(),
                    created_at: 500 + i64::from(n),
                    delivered_at: None,
                    delivered: true,
                    deduplicated: false,
                    failed_recipients: 0,
                    waiting_recipients: None,
                },
            )
        };
        let state = |revision, pinned| ConversationStateBody {
            conversation: bob.clone(),
            revision,
            source_device_id: 2,
            updated_at_ms: 1_000,
            pinned,
            archived: false,
            muted_until_ms: None,
            marked_unread: false,
        };
        let position = |through: &str, at| ReadPositionBody {
            conversation: bob.clone(),
            through_message_id: through.into(),
            read_through_ms: at,
        };
        let t = "2026-09-25T00:00:00Z";
        for (n, content) in [
            (
                1,
                ChatContent::conversation_state_with_id(control_id(1), t, 10, state(2, true))
                    .unwrap(),
            ),
            (
                2,
                ChatContent::conversation_state_with_id(control_id(2), t, 11, state(1, false))
                    .unwrap(),
            ),
            (
                3,
                ChatContent::read_position_with_id(control_id(3), t, 12, position(GONE, 102))
                    .unwrap(),
            ),
            (
                4,
                ChatContent::read_position_with_id(control_id(4), t, 13, position(KEPT, 101))
                    .unwrap(),
            ),
            (
                5,
                ChatContent::delete_for_me_with_id(
                    control_id(5),
                    t,
                    14,
                    DeleteForMeBody {
                        conversation: bob.clone(),
                        message_ids: vec![GONE.into()],
                    },
                )
                .unwrap(),
            ),
            (
                6,
                ChatContent::delete_for_me_with_id(
                    control_id(6),
                    t,
                    15,
                    DeleteForMeBody {
                        conversation: group.clone(),
                        message_ids: vec![GROUP_GONE.into()],
                    },
                )
                .unwrap(),
            ),
        ] {
            let (id, message) = note(n, content);
            pending.sent_messages.insert(id, message);
        }
        block_on(db.apply(&pending)).unwrap();

        let report = block_on(session.purge_expired_history(1)).unwrap();
        assert_eq!(report.expired_messages, 2);

        let incoming: Vec<_> = block_on(db.list_messages())
            .unwrap()
            .into_iter()
            .map(|message| message.id)
            .collect();
        assert_eq!(
            incoming,
            vec!["mailbox-1".to_string()],
            "the deleted message and the reaction to it are gone"
        );
        let mut kept: Vec<_> = block_on(db.list_sent_messages())
            .unwrap()
            .into_iter()
            .map(|message| message.send_id)
            .collect();
        kept.sort();
        // The newer state (revision 2), the further read position and both
        // delete-for-me controls stay; the superseded two go.
        assert_eq!(
            kept,
            vec![control_id(1), control_id(3), control_id(5), control_id(6)]
        );

        // Idempotent: a second pass removes nothing more.
        let again = block_on(session.purge_expired_history(2)).unwrap();
        assert_eq!(again.expired_messages, 0);
        assert_eq!(block_on(db.list_sent_messages()).unwrap().len(), 4);

        // A view-once opened on another device: gone here too, the control
        // staying as the "Viewed" placeholder.
        let opened = ChatContent::view_once_opened_with_id(
            control_id(7),
            t,
            16,
            kutup_chat_proto::ViewOnceOpenedBody {
                conversation: bob.clone(),
                message_id: KEPT.into(),
                sender: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test"
                    .parse()
                    .unwrap(),
                timestamp_ms: 101,
                video: false,
            },
        )
        .unwrap();
        let (id, message) = note(7, opened);
        let mut pending = Pending::default();
        pending.sent_messages.insert(id, message);
        block_on(db.apply(&pending)).unwrap();
        let report = block_on(session.purge_expired_history(3)).unwrap();
        assert_eq!(report.expired_messages, 1);
        assert!(block_on(db.list_messages()).unwrap().is_empty());
        assert_eq!(block_on(db.list_sent_messages()).unwrap().len(), 5);
    }

    #[test]
    fn disappearing_history_purge_is_atomic_across_all_history_stores() {
        let mut rng = OsRng.unwrap_err();
        let db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let mut session = block_on(Session::generate(
            db.clone(),
            "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test",
            1,
            1,
            &mut rng,
        ))
        .unwrap();
        block_on(session.complete_registration(1)).unwrap();

        let expiring = |id: &str, seq: u64, text: &str| {
            serde_json::to_vec(
                &ChatContent::text_with_id(id, "2026-08-10T00:00:00Z", seq, text)
                    .with_disappearing_after(30)
                    .unwrap(),
            )
            .unwrap()
        };
        let expiry_start =
            |id: &str, seq: u64, conversation: kutup_chat_proto::ConversationId, target: &str| {
                serde_json::to_vec(
                    &ChatContent::disappearing_expiry_start_with_id(
                        id,
                        "2026-08-10T00:00:01Z",
                        seq,
                        conversation,
                        target,
                        1_000,
                    )
                    .unwrap(),
                )
                .unwrap()
            };
        let incoming_id = "10000000-0000-4000-8000-000000000001";
        let sent_id = "20000000-0000-4000-8000-000000000002";
        let mls_id = "30000000-0000-4000-8000-000000000003";
        let live_id = "50000000-0000-4000-8000-000000000005";
        let reaction_id = "60000000-0000-4000-8000-000000000006";
        let reaction = serde_json::to_vec(
            &ChatContent::reaction_with_id(
                reaction_id,
                "2026-08-10T00:00:01Z",
                6,
                incoming_id,
                "👍",
                true,
            )
            .unwrap(),
        )
        .unwrap();
        let mut pending = Pending::default();
        pending.messages.extend([
            InboxMessage {
                id: "mailbox-expiring".into(),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                sender_device_id: 1,
                cursor: 1,
                content: expiring(incoming_id, 1, "inbound"),
                received_at: 1_000,
            },
            InboxMessage {
                id: "mailbox-live".into(),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                sender_device_id: 1,
                cursor: 2,
                content: serde_json::to_vec(&ChatContent::text_with_id(
                    live_id,
                    "2026-08-10T00:00:01Z",
                    5,
                    "retained",
                ))
                .unwrap(),
                received_at: 1_000,
            },
            InboxMessage {
                id: "mailbox-reaction".into(),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                sender_device_id: 1,
                cursor: 3,
                content: reaction.clone(),
                received_at: 2_000,
            },
            InboxMessage {
                id: "mailbox-future-content".into(),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                sender_device_id: 1,
                cursor: 4,
                content: b"a future authenticated content encoding".to_vec(),
                received_at: 2_000,
            },
        ]);
        pending.sent_messages.insert(
            sent_id.into(),
            SentMessage {
                send_id: sent_id.into(),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                sender_device_id: 1,
                content: expiring(sent_id, 2, "outbound"),
                created_at: 1_000,
                delivered_at: Some(2_000),
                delivered: true,
                deduplicated: false,
                failed_recipients: 0,
                waiting_recipients: None,
            },
        );
        for (id, seq, conversation, target) in [
            (
                "71000000-0000-4000-8000-000000000001",
                7,
                direct_conversation("aci:00000000-0000-4000-8000-81b637d8fcd2@b.test").unwrap(),
                incoming_id,
            ),
            (
                "72000000-0000-4000-8000-000000000002",
                8,
                kutup_chat_proto::ConversationId::Group {
                    group_id: crate::group::test_context(4).group_id.clone(),
                },
                mls_id,
            ),
        ] {
            pending.sent_messages.insert(
                id.into(),
                SentMessage {
                    send_id: id.into(),
                    peer: "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test".into(),
                    sender_device_id: 1,
                    content: expiry_start(id, seq, conversation, target),
                    created_at: 1_000,
                    delivered_at: Some(1_001),
                    delivered: true,
                    deduplicated: false,
                    failed_recipients: 0,
                    waiting_recipients: None,
                },
            );
        }
        pending.outbox.insert(
            "direct-derived".into(),
            Some(OutboxEntry {
                send_id: "direct-derived".into(),
                peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
                content: reaction.clone(),
                envelopes: vec![1],
                sealed_sender: false,
                sealed_capability: None,
                attempts: 0,
                created_at: 2_000,
                primary_delivered: false,
                sync: None,
            }),
        );
        // A pairwise group's message: in the inbox, under its group.
        let group_content = serde_json::from_slice::<ChatContent>(&expiring(mls_id, 3, "group"))
            .unwrap()
            .with_group_context(&crate::group::test_context(4));
        pending.messages.push(InboxMessage {
            id: "mailbox-group-expiring".into(),
            peer: "aci:00000000-0000-4000-8000-81b637d8fcd2@b.test".into(),
            sender_device_id: 1,
            cursor: 5,
            content: serde_json::to_vec(&group_content).unwrap(),
            received_at: 1_000,
        });
        block_on(db.apply(&pending)).unwrap();

        assert_eq!(
            block_on(session.purge_expired_history(30_999)).unwrap(),
            ExpiryReport::default()
        );
        let report = block_on(session.purge_expired_history(31_000)).unwrap();
        assert_eq!(report.expired_messages, 3);
        assert!(report.expired_attachment_ids.is_empty());
        let remaining = block_on(db.list_messages()).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].id, "mailbox-live");
        assert_eq!(remaining[1].id, "mailbox-future-content");
        assert!(block_on(db.list_sent_messages()).unwrap().is_empty());
        assert!(block_on(db.load_outbox("direct-derived"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn the_largest_allowed_message_can_still_be_re_sent_sealed_as_a_first_message() {
        use base64::Engine as _;
        let mut rng = OsRng.unwrap_err();
        let peer = "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example";
        let send_id = "00000000-0000-4000-8000-000000000001";
        let text =
            |n: usize| ChatContent::text_with_id(send_id, "2026-07-22T00:00:00Z", 1, "x".repeat(n));
        // The largest text the check lets through, and one byte more.
        let (mut low, mut high) = (0usize, 70_000usize);
        while low + 1 < high {
            let mid = (low + high) / 2;
            if ensure_room_for_wrappers(send_id, peer, &text(mid)).is_ok() {
                low = mid
            } else {
                high = mid
            }
        }
        assert!(
            low > 60_000,
            "the limit leaves room for ordinary long messages: {low}"
        );
        assert!(matches!(
            ensure_room_for_wrappers(send_id, peer, &text(low + 1)),
            Err(ChatError::Invalid(message)) if message.contains("too large")
        ));

        // Its re-send, with real ids, sealed, as a first (PreKey) message.
        let mut alice = block_on(Session::generate(
            Rc::new(SqliteChatDb::open_in_memory().unwrap()),
            "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example",
            1,
            4,
            &mut rng,
        ))
        .unwrap();
        let bob = block_on(Session::generate(
            Rc::new(SqliteChatDb::open_in_memory().unwrap()),
            peer,
            1,
            4,
            &mut rng,
        ))
        .unwrap();
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_certificate =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .unwrap();
        let expiration =
            Timestamp::from_epoch_millis(u64::try_from(now_millis()).unwrap() + 60 * 60 * 1000);
        let sender_certificate = SenderCertificate::new(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example".into(),
            None,
            alice.local_identity_public_key(),
            crate::address::device_id_u8(1).unwrap(),
            expiration,
            server_certificate,
            &server_key.private_key,
            &mut rng,
        )
        .unwrap();
        let resend_id = "00000000-0000-4000-8000-000000000002";
        let wrapped =
            ChatContent::resend_with_id(resend_id, "2026-07-22T00:00:01.123Z", 2, text(low))
                .unwrap();
        let mut summary = SendSummary::default();
        let (outgoing, _) = block_on(alice.enqueue_sealed_direct_send(
            SealedDirectSend {
                send_id: resend_id,
                peer_user: peer,
                recipient_bundles: &[bundle(&bob)],
                sync_bundles: &[],
                content: &wrapped,
                sender_certificate: &sender_certificate,
                capability: [7; 16],
            },
            &mut summary,
            &mut rng,
        ))
        .unwrap();
        let envelope = base64::engine::general_purpose::STANDARD
            .decode(&outgoing[0].content)
            .unwrap();
        assert!(
            envelope.len() <= 65_536,
            "the re-send fits the server's limit: {}",
            envelope.len()
        );
    }

    #[test]
    fn sealed_outer_certificate_is_checked_before_inner_ratchet() {
        let mut rng = OsRng.unwrap_err();
        let alice_db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let bob_db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let mut alice = block_on(Session::generate(
            alice_db,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example",
            1,
            4,
            &mut rng,
        ))
        .unwrap();
        let mut bob = block_on(Session::generate(
            bob_db,
            "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
            1,
            4,
            &mut rng,
        ))
        .unwrap();

        let trust_root = KeyPair::generate(&mut rng);
        let wrong_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_certificate =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .unwrap();
        let expiration =
            Timestamp::from_epoch_millis(u64::try_from(now_millis()).unwrap() + 60 * 60 * 1000);
        let sender_certificate = SenderCertificate::new(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example".into(),
            None,
            alice.local_identity_public_key(),
            crate::address::device_id_u8(1).unwrap(),
            expiration,
            server_certificate,
            &server_key.private_key,
            &mut rng,
        )
        .unwrap();
        let content = ChatContent::text_with_id(
            "00000000-0000-4000-8000-000000000001",
            "2026-07-22T00:00:00Z",
            1,
            "sealed hello",
        );
        let mut summary = SendSummary::default();
        let (outgoing, _) = block_on(alice.enqueue_sealed_direct_send(
            SealedDirectSend {
                send_id: "00000000-0000-4000-8000-000000000001",
                peer_user: "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
                recipient_bundles: &[bundle(&bob)],
                sync_bundles: &[],
                content: &content,
                sender_certificate: &sender_certificate,
                capability: [7; 16],
            },
            &mut summary,
            &mut rng,
        ))
        .unwrap();
        let envelope = DeliveredEnvelope {
            id: "sealed-mailbox-1".into(),
            cursor: 1,
            sender: None,
            sealed_sender: true,
            sender_device_id: 0,
            envelope_type: EnvelopeType::Message,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content: outgoing[0].content.clone(),
            server_timestamp: "2026-07-22T00:00:01Z".into(),
            send_id: None,
        };
        let inspection = block_on(bob.inspect_sealed_envelope(&envelope)).unwrap();
        assert_eq!(
            inspection.sender,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example"
        );
        assert_eq!(inspection.identity_key, alice.local_identity_public_key());

        assert!(block_on(bob.receive_sealed_envelope(
            &envelope,
            &inspection,
            "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
            &wrong_root.public_key,
        ))
        .is_err());
        let outcome = block_on(bob.receive_sealed_envelope(
            &envelope,
            &inspection,
            "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
            &trust_root.public_key,
        ))
        .unwrap();
        let ReceiveOutcome::Message(message) = outcome else {
            panic!("sealed content should be a user message")
        };
        assert_eq!(
            message.from.name(),
            "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example"
        );
        assert_eq!(
            message.content.as_text().map(|body| body.text),
            Some("sealed hello".into())
        );
    }

    #[test]
    fn a_group_message_is_sealed_once_for_every_member_on_one_server() {
        let mut rng = OsRng.unwrap_err();
        let alice_name = "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example";
        let names = [
            "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
            "aci:00000000-0000-4000-8000-c0c0c0c0c0c0@chat.example",
        ];
        let session = |name: &str, rng: &mut _| {
            block_on(Session::generate(
                Rc::new(SqliteChatDb::open_in_memory().unwrap()),
                name,
                1,
                4,
                rng,
            ))
            .unwrap()
        };
        let mut alice = session(alice_name, &mut rng);
        let mut members: Vec<Session> = names.iter().map(|name| session(name, &mut rng)).collect();
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_certificate =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .unwrap();
        let expiration =
            Timestamp::from_epoch_millis(u64::try_from(now_millis()).unwrap() + 60 * 60 * 1000);
        let certificate = SenderCertificate::new(
            alice_name.into(),
            None,
            alice.local_identity_public_key(),
            crate::address::device_id_u8(1).unwrap(),
            expiration,
            server_certificate,
            &server_key.private_key,
            &mut rng,
        )
        .unwrap();
        let group_id = [5u8; 32];
        let group = kutup_chat_proto::group::encode_group_id(&group_id);
        let delivered = |id: &str, content: Vec<u8>| DeliveredEnvelope {
            id: id.into(),
            cursor: 1,
            sender: None,
            sealed_sender: true,
            sender_device_id: 0,
            envelope_type: EnvelopeType::Message,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content: STANDARD.encode(content),
            server_timestamp: "2026-10-18T00:00:01Z".into(),
            send_id: None,
        };

        // Every member holds Alice's sender key (handed over pairwise).
        let distribution_id = uuid::Uuid::new_v4();
        let distribution =
            block_on(alice.sender_key_distribution(distribution_id, &mut rng)).unwrap();
        for member in members.iter_mut() {
            let from = ChatAddress::from_sender(alice_name, 1).unwrap();
            // The pairwise hand-over itself is covered by the test below;
            // here the key is taken in directly.
            block_on(member.process_sender_key_distribution(&from, &distribution)).unwrap();
        }

        // One payload for both, sealed once.
        let context = kutup_chat_proto::group::GroupContextV1 {
            version: 1,
            group_id: group.clone(),
            master_key: kutup_chat_proto::group::encode(&[6u8; 32]),
            home: kutup_chat_proto::group_route::GroupHomePinV1 {
                server: "chat.example".into(),
                identity_sequence: 0,
                identity_document_hash: "9".repeat(64),
            },
            revision: 1,
            chain_hash: kutup_chat_proto::group::encode(&[7u8; 32]),
            recipient_pseudonym: None,
        };
        let plaintext = serde_json::to_vec(
            &ChatContent::text_with_id(
                "00000000-0000-4000-8000-000000000031",
                "2026-10-18T00:00:02Z",
                1,
                "merhaba ikinize",
            )
            .with_group_context(&context),
        )
        .unwrap();
        let encrypted =
            block_on(alice.group_encrypt(distribution_id, &plaintext, &mut rng)).unwrap();
        let recipients: Vec<_> = members
            .iter()
            .map(|member| (member.account_ref().clone(), vec![bundle(member)]))
            .collect();
        let sealed = block_on(alice.seal_group_multi(
            &recipients,
            &certificate,
            &group_id,
            &encrypted,
            libsignal_protocol::ContentHint::Resendable,
            &mut rng,
        ))
        .unwrap();
        assert_eq!(sealed.payload[0], 0x23, "sealed sender v2, service ids");

        // The server's split (Signal-Server's, as kutup-server does it): one
        // received message per recipient, each opened by its own device only.
        let sent = libsignal_protocol::SealedSenderV2SentMessage::parse(&sealed.payload).unwrap();
        assert_eq!(sent.recipients.len(), 2);
        let mut copies = Vec::new();
        for (service_id, recipient) in &sent.recipients {
            let parts = sent.received_message_parts_for_recipient(recipient);
            copies.push((service_id.service_id_string(), parts.as_ref().concat()));
        }
        for (member, name) in members.iter_mut().zip(names) {
            let uuid = name.trim_start_matches("aci:").split('@').next().unwrap();
            let (_, copy) = copies.iter().find(|(id, _)| id == uuid).unwrap();
            let envelope = delivered(uuid, copy.clone());
            let inspection = block_on(member.inspect_sealed_envelope(&envelope)).unwrap();
            assert_eq!(inspection.group_id, Some(group_id));
            let ReceiveOutcome::Message(message) = block_on(member.receive_sealed_group_envelope(
                &envelope,
                &inspection,
                &trust_root.public_key,
                &|_, _| GroupGate::Accept,
            ))
            .unwrap_or_else(|e| panic!("{name}: {e}")) else {
                panic!("a group message")
            };
            assert_eq!(message.content.as_text().unwrap().text, "merhaba ikinize");
            assert_eq!(message.content.group_context().unwrap(), context);
        }
        // Another member's copy opens for no one else.
        let (_, carols) = copies
            .iter()
            .find(|(id, _)| names[1].contains(id.as_str()))
            .unwrap();
        let envelope = delivered("wrong", carols.clone());
        assert!(block_on(members[0].inspect_sealed_envelope(&envelope)).is_err());
    }

    #[test]
    fn a_group_message_is_encrypted_once_and_opened_with_the_senders_key() {
        let mut rng = OsRng.unwrap_err();
        let alice_name = "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.example";
        let bob_name = "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example";
        let carol_name = "aci:00000000-0000-4000-8000-c0c0c0c0c0c0@chat.example";
        let session = |name: &str, rng: &mut _| {
            block_on(Session::generate(
                Rc::new(SqliteChatDb::open_in_memory().unwrap()),
                name,
                1,
                4,
                rng,
            ))
            .unwrap()
        };
        let mut alice = session(alice_name, &mut rng);
        let mut bob = session(bob_name, &mut rng);
        let mut carol = session(carol_name, &mut rng);
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_certificate =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .unwrap();
        let expiration =
            Timestamp::from_epoch_millis(u64::try_from(now_millis()).unwrap() + 60 * 60 * 1000);
        let certificate = SenderCertificate::new(
            alice_name.into(),
            None,
            alice.local_identity_public_key(),
            crate::address::device_id_u8(1).unwrap(),
            expiration,
            server_certificate,
            &server_key.private_key,
            &mut rng,
        )
        .unwrap();
        let group_id = [5u8; 32];
        let context = kutup_chat_proto::group::GroupContextV1 {
            version: 1,
            group_id: kutup_chat_proto::group::encode_group_id(&group_id),
            master_key: kutup_chat_proto::group::encode(&[6u8; 32]),
            home: kutup_chat_proto::group_route::GroupHomePinV1 {
                server: "chat.example".into(),
                identity_sequence: 0,
                identity_document_hash: "9".repeat(64),
            },
            revision: 1,
            chain_hash: kutup_chat_proto::group::encode(&[7u8; 32]),
            recipient_pseudonym: None,
        };
        let delivered = |id: &str, content: &str| DeliveredEnvelope {
            id: id.into(),
            cursor: 1,
            sender: None,
            sealed_sender: true,
            sender_device_id: 0,
            envelope_type: EnvelopeType::Message,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content: content.into(),
            server_timestamp: "2026-10-18T00:00:01Z".into(),
            send_id: None,
        };

        // Alice's key goes to Bob pairwise, as hidden group content.
        let distribution_id = uuid::Uuid::new_v4();
        let message = block_on(alice.sender_key_distribution(distribution_id, &mut rng)).unwrap();
        let content = ChatContent::sender_key_distribution_with_id(
            "00000000-0000-4000-8000-000000000010",
            "2026-10-18T00:00:00Z",
            0,
            &kutup_chat_proto::content::SenderKeyDistributionBody {
                group_id: context.group_id.clone(),
                distribution_id: distribution_id.to_string(),
                message: base64::engine::general_purpose::STANDARD.encode(&message),
            },
        );
        let sealed = block_on(alice.seal_pairwise(
            bob_name,
            &[bundle(&bob)],
            &certificate,
            &content,
            &mut rng,
        ))
        .unwrap();
        let envelope = delivered("pairwise-1", &sealed.envelopes[0].content);
        let inspection = block_on(bob.inspect_sealed_envelope(&envelope)).unwrap();
        assert!(
            inspection.group_id.is_none(),
            "a pairwise message names no group"
        );
        // Read once and set aside for the engine's decision about its
        // sender; nothing is kept until then.
        let ReceiveOutcome::GroupCheck {
            group_id: checked,
            sender,
            ..
        } = block_on(bob.receive_sealed_envelope(
            &envelope,
            &inspection,
            bob_name,
            &trust_root.public_key,
        ))
        .unwrap()
        else {
            panic!("a sender key is group content, never a direct message")
        };
        assert_eq!(
            (checked.as_str(), sender.as_str()),
            (context.group_id.as_str(), alice_name)
        );
        bob.decide_group(&checked, &sender, GroupGate::Accept);
        let ReceiveOutcome::GroupContent { from, content, .. } = block_on(
            bob.receive_sealed_envelope(&envelope, &inspection, bob_name, &trust_root.public_key),
        )
        .unwrap() else {
            panic!("taken once decided")
        };
        let body = content.as_sender_key_distribution().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.message)
            .unwrap();
        block_on(bob.process_sender_key_distribution(&from, &bytes)).unwrap();

        // Two messages, each encrypted once and sealed per device.
        for (n, text) in ["first", "second"].into_iter().enumerate() {
            let plaintext = serde_json::to_vec(
                &ChatContent::text_with_id(
                    format!("00000000-0000-4000-8000-00000000002{n}"),
                    "2026-10-18T00:00:02Z",
                    n as u64 + 1,
                    text,
                )
                .with_group_context(&context),
            )
            .unwrap();
            let encrypted =
                block_on(alice.group_encrypt(distribution_id, &plaintext, &mut rng)).unwrap();
            let sealed = block_on(alice.seal_group_message(
                bob_name,
                &[bundle(&bob)],
                &certificate,
                &group_id,
                &encrypted,
                libsignal_protocol::ContentHint::Resendable,
                &mut rng,
            ))
            .unwrap();
            let envelope = delivered(&format!("group-{n}"), &sealed.envelopes[0].content);
            let inspection = block_on(bob.inspect_sealed_envelope(&envelope)).unwrap();
            assert_eq!(inspection.group_id, Some(group_id));
            assert!(!inspection.implicit);
            if n == 1 {
                // Told to catch up first: nothing is kept, and the same
                // envelope reads again afterwards.
                let outcome = block_on(bob.receive_sealed_group_envelope(
                    &envelope,
                    &inspection,
                    &trust_root.public_key,
                    &|_, _| GroupGate::CatchUp,
                ))
                .unwrap();
                assert!(matches!(outcome, ReceiveOutcome::GroupCatchUp));
                assert_eq!(block_on(bob.store.db().list_messages()).unwrap().len(), 1);
            }
            let ReceiveOutcome::Message(message) = block_on(bob.receive_sealed_group_envelope(
                &envelope,
                &inspection,
                &trust_root.public_key,
                &|_, _| GroupGate::Accept,
            ))
            .unwrap() else {
                panic!("a group message is a message")
            };
            assert_eq!(message.content.as_text().unwrap().text, text);
            assert_eq!(message.content.group_context().unwrap(), context);

            // Carol never got the key: unreadable, the kind that heals.
            if n == 0 {
                let sealed = block_on(alice.seal_group_message(
                    carol_name,
                    &[bundle(&carol)],
                    &certificate,
                    &group_id,
                    &encrypted,
                    libsignal_protocol::ContentHint::Resendable,
                    &mut rng,
                ))
                .unwrap();
                let envelope = delivered("carol-1", &sealed.envelopes[0].content);
                let inspection = block_on(carol.inspect_sealed_envelope(&envelope)).unwrap();
                let Err(error) = block_on(carol.receive_sealed_group_envelope(
                    &envelope,
                    &inspection,
                    &trust_root.public_key,
                    &|_, _| GroupGate::Accept,
                )) else {
                    panic!("a message under a key never held can't be read")
                };
                assert_eq!(
                    error.inbound_failure_kind(),
                    crate::InboundFailureKind::MissingKeyMaterial
                );
            }
        }

        // A message naming another group inside than the one it was sealed for.
        let mut other = context.clone();
        other.group_id = kutup_chat_proto::group::encode_group_id(&[8u8; 32]);
        let plaintext = serde_json::to_vec(
            &ChatContent::text_with_id(
                "00000000-0000-4000-8000-000000000030",
                "2026-10-18T00:00:03Z",
                3,
                "elsewhere",
            )
            .with_group_context(&other),
        )
        .unwrap();
        let encrypted =
            block_on(alice.group_encrypt(distribution_id, &plaintext, &mut rng)).unwrap();
        let sealed = block_on(alice.seal_group_message(
            bob_name,
            &[bundle(&bob)],
            &certificate,
            &group_id,
            &encrypted,
            libsignal_protocol::ContentHint::Resendable,
            &mut rng,
        ))
        .unwrap();
        let envelope = delivered("group-x", &sealed.envelopes[0].content);
        let inspection = block_on(bob.inspect_sealed_envelope(&envelope)).unwrap();
        assert!(matches!(
            block_on(bob.receive_sealed_group_envelope(
                &envelope,
                &inspection,
                &trust_root.public_key,
                &|_, _| GroupGate::Accept,
            )),
            Err(ChatError::Trust(_))
        ));

        // From someone who isn't a member: acknowledged, nothing kept.
        let plaintext = serde_json::to_vec(
            &ChatContent::text_with_id(
                "00000000-0000-4000-8000-000000000031",
                "2026-10-18T00:00:04Z",
                4,
                "not a member",
            )
            .with_group_context(&context),
        )
        .unwrap();
        let encrypted =
            block_on(alice.group_encrypt(distribution_id, &plaintext, &mut rng)).unwrap();
        let sealed = block_on(alice.seal_group_message(
            bob_name,
            &[bundle(&bob)],
            &certificate,
            &group_id,
            &encrypted,
            libsignal_protocol::ContentHint::Implicit,
            &mut rng,
        ))
        .unwrap();
        let envelope = delivered("group-refused", &sealed.envelopes[0].content);
        let inspection = block_on(bob.inspect_sealed_envelope(&envelope)).unwrap();
        assert!(inspection.implicit);
        let kept = block_on(bob.store.db().list_messages()).unwrap().len();
        assert!(matches!(
            block_on(bob.receive_sealed_group_envelope(
                &envelope,
                &inspection,
                &trust_root.public_key,
                &|_, _| GroupGate::Refuse,
            ))
            .unwrap(),
            ReceiveOutcome::Suppressed { .. }
        ));
        assert_eq!(
            block_on(bob.store.db().list_messages()).unwrap().len(),
            kept
        );
    }
}

/// The kinds a whole group gets under a sender key (the rest, receipts,
/// typing and controls, go pairwise).
fn is_group_history_kind(kind: &str) -> bool {
    use kutup_chat_proto::content::kind;
    matches!(
        kind,
        kind::TEXT
            | kind::ATTACHMENT
            | kind::REACTION
            | kind::POLL
            | kind::POLL_VOTE
            | kind::POLL_TERMINATE
            | kind::MESSAGE_MUTATION
            | kind::LOCATION
    )
}

/// Content that belongs to a group: its hidden pairwise kinds, a group
/// refresh, and any message carrying a group context (directly or inside a
/// resend).
/// The group pairwise content belongs to, and the context it carries;
/// `None` for an invitation, which is decided on its own.
fn group_of_content(
    content: &ChatContent,
) -> Option<(String, Option<kutup_chat_proto::group::GroupContextV1>)> {
    // Both verify on their own: an invitation by what it carries, a removal
    // by the chain head and notary this device holds.
    if content.kind == kutup_chat_proto::content::kind::GROUP_INVITE
        || content.kind == kutup_chat_proto::content::kind::GROUP_REMOVAL
    {
        return None;
    }
    let context = content.group_context().or_else(|| {
        content
            .as_resend()
            .and_then(|resend| resend.content.group_context())
    });
    let group_id = context
        .as_ref()
        .map(|context| context.group_id.clone())
        .or_else(|| {
            content
                .as_sender_key_distribution()
                .map(|body| body.group_id)
        })
        .or_else(|| {
            content
                .as_session_control()
                .and_then(|control| control.group.map(|group| group.group_id))
        })
        // Names no group that reads: decided as a stranger's.
        .unwrap_or_default();
    Some((group_id, context))
}

fn is_group_content(content: &ChatContent) -> bool {
    use kutup_chat_proto::content::kind;
    content.kind == kind::SENDER_KEY_DISTRIBUTION
        || content.kind == kind::GROUP_INVITE
        || content.kind == kind::GROUP_REMOVAL
        || content.group_context().is_some()
        || content
            .as_session_control()
            .is_some_and(|control| control.group.is_some())
        || content
            .as_resend()
            .is_some_and(|resend| resend.content.group_context().is_some())
}

/// A group call is a whole group's (kept for pairwise group calls,
/// pairwise-groups.md §6); a Direct copy is refused.
fn refuse_group_only(content: &ChatContent) -> std::result::Result<(), String> {
    if content.kind == kutup_chat_proto::content::kind::GROUP_CALL {
        return Err("a group call is not Direct content".into());
    }
    Ok(())
}

/// The id of the "safety number changed" line for a peer's identity: one
/// line per identity, however often it is met.
fn safety_line_id(identity_key: &str) -> String {
    use sha2::{Digest as _, Sha256};
    format!(
        "safety:identity:{}",
        hex::encode(&Sha256::digest(identity_key.as_bytes())[..16])
    )
}
