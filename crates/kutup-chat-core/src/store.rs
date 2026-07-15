//! libsignal's six store traits, implemented over a [`ChatDb`].
//!
//! libsignal's `message_encrypt`/`message_decrypt`/`process_prekey_bundle` each
//! take a *separate* `&mut` to several sub-stores at once, so — exactly like
//! libsignal's own `InMemSignalProtocolStore` — the store is a struct of one
//! adapter per trait. All adapters share a single [`Pending`] unit-of-work behind
//! `Rc<RefCell<…>>`: every write stages there, every read consults it before the
//! durable [`ChatDb`], and [`ChatStore::commit`] flushes the whole batch atomically.
//!
//! That overlay is what gives us the decrypt→persist→ack invariant: run the crypto
//! op, and only if it returns `Ok` do we `commit` (one atomic `apply`) and then ack.
//! A failure `discard`s the batch and nothing durable moved.
//!
//! Every trait method awaits the `ChatDb` port. Native SQLite resolves
//! immediately; IndexedDB may yield without changing the unit-of-work semantics.

use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use base64::Engine as _;
use kutup_chat_proto::ManifestDevice;
use libsignal_protocol::*;
use uuid::Uuid;

use crate::db::{
    ChatDb, InboundEnvelope, InboxMessage, LocalIdentity, ManifestTrust, OutboxEntry, Pending,
};
use crate::error::{ChatError, Result as ChatResult};

/// libsignal's store traits return its own `Result` alias, which the crate does
/// not re-export at its root — so we mirror it here for the trait impls. Our own
/// fallible methods use [`ChatResult`] instead.
type Result<T> = std::result::Result<T, SignalProtocolError>;

/// Wraps a [`ChatDb`] read failure as a libsignal store-callback error, so it
/// surfaces through `message_decrypt` etc. without inventing a crypto failure.
fn cb(method: &'static str) -> impl FnOnce(ChatError) -> SignalProtocolError {
    SignalProtocolError::for_application_callback(method)
}

/// The full protocol store for one device: an adapter per libsignal trait, all
/// sharing one durable [`ChatDb`] and one [`Pending`] unit-of-work.
pub(crate) struct ChatStore {
    pending: Rc<RefCell<Pending>>,
    db: Rc<dyn ChatDb>,
    pub(crate) session_store: SessionAdapter,
    pub(crate) identity_store: IdentityAdapter,
    pub(crate) pre_key_store: PreKeyAdapter,
    pub(crate) signed_pre_key_store: SignedPreKeyAdapter,
    pub(crate) kyber_pre_key_store: KyberAdapter,
    #[allow(dead_code)] // reserved for group messaging (§12); wired, unused in 1:1.
    pub(crate) sender_key_store: SenderKeyAdapter,
}

impl ChatStore {
    /// Build a store over an already-installed device identity. Deserializes the
    /// local identity keypair once for the hot `get_identity_key_pair` path.
    pub(crate) fn attach(db: Rc<dyn ChatDb>, local: LocalIdentity) -> ChatResult<Self> {
        let key_pair = IdentityKeyPair::try_from(local.identity_key_pair.as_slice())
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        let pending = Rc::new(RefCell::new(Pending::default()));
        Ok(ChatStore {
            session_store: SessionAdapter {
                db: db.clone(),
                pending: pending.clone(),
            },
            identity_store: IdentityAdapter {
                db: db.clone(),
                pending: pending.clone(),
                key_pair,
                registration_id: local.registration_id,
            },
            pre_key_store: PreKeyAdapter {
                db: db.clone(),
                pending: pending.clone(),
            },
            signed_pre_key_store: SignedPreKeyAdapter {
                db: db.clone(),
                pending: pending.clone(),
            },
            kyber_pre_key_store: KyberAdapter {
                db: db.clone(),
                pending: pending.clone(),
            },
            sender_key_store: SenderKeyAdapter {
                db: db.clone(),
                pending: pending.clone(),
            },
            pending,
            db,
        })
    }

    /// Flush the current unit of work atomically. Clears the batch either way, so
    /// a retry after a failed commit re-derives from the last durable state.
    pub(crate) async fn commit(&self) -> ChatResult<()> {
        let pending = {
            let mut staged = self.pending.borrow_mut();
            if staged.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *staged)
        };
        if pending.is_empty() {
            return Ok(());
        }
        self.db.apply(&pending).await
    }

    /// Drop the current unit of work without touching the durable store.
    pub(crate) fn discard(&self) {
        self.pending.borrow_mut().clear();
    }

    /// Whether a session already exists for `address` (overlay before durable) —
    /// lets the engine encrypt with an existing session instead of re-establishing
    /// (which would reset the ratchet).
    pub(crate) async fn has_session(&self, address: &str) -> ChatResult<bool> {
        if let Some(opt) = self.pending.borrow().sessions.get(address) {
            return Ok(opt.is_some());
        }
        Ok(self.db.load_session(address).await?.is_some())
    }

    /// Stage a session archive (drop) for a stale/extra device.
    pub(crate) fn delete_session(&self, address: &str) {
        self.pending
            .borrow_mut()
            .sessions
            .insert(address.to_string(), None);
    }

    /// Stage an outbox upsert (the pending send for its `sendId`).
    pub(crate) fn stage_outbox(&self, entry: OutboxEntry) {
        self.pending
            .borrow_mut()
            .outbox
            .insert(entry.send_id.clone(), Some(entry));
    }

    /// Stage an outbox delete (the send was delivered).
    pub(crate) fn delete_outbox(&self, send_id: &str) {
        self.pending
            .borrow_mut()
            .outbox
            .insert(send_id.to_string(), None);
    }

    /// The durable store handle, for reads the engine makes outside a unit of work
    /// (e.g. loading the outbox on resend).
    pub(crate) fn db(&self) -> &Rc<dyn ChatDb> {
        &self.db
    }

    /// A peer device's stored public identity bytes (overlay before durable), or
    /// `None` — lets the send path detect a reinstall (changed identity key) before
    /// reusing a now-stale session.
    pub(crate) async fn peer_identity(&self, address: &str) -> ChatResult<Option<Vec<u8>>> {
        if let Some(bytes) = self.pending.borrow().identities.get(address) {
            return Ok(Some(bytes.clone()));
        }
        self.db.load_identity(address).await
    }

    /// Stage a decrypted inbound message.
    pub(crate) fn stage_message(&self, message: InboxMessage) {
        self.pending.borrow_mut().messages.push(message);
    }

    pub(crate) fn stage_inbound(&self, inbound: InboundEnvelope) {
        self.pending
            .borrow_mut()
            .inbound
            .insert(inbound.id.clone(), Some(inbound));
    }

    pub(crate) fn delete_inbound(&self, id: &str) {
        self.pending
            .borrow_mut()
            .inbound
            .insert(id.to_string(), None);
    }

    pub(crate) fn stage_manifest_trust(&self, trust: ManifestTrust) {
        self.pending
            .borrow_mut()
            .manifest_trust
            .insert(trust.peer.clone(), trust);
    }

    pub(crate) fn local_manifest_device(&self, device_id: u32) -> ManifestDevice {
        ManifestDevice {
            device_id,
            identity_key: base64::engine::general_purpose::STANDARD
                .encode(self.identity_store.key_pair.identity_key().serialize()),
            registration_id: self.identity_store.registration_id,
        }
    }

    /// Stage a drain-cursor advance (monotonic — keeps the max).
    pub(crate) fn stage_cursor(&self, cursor: u64) {
        let mut pending = self.pending.borrow_mut();
        pending.last_cursor = Some(pending.last_cursor.map_or(cursor, |c| c.max(cursor)));
    }

    /// The highest mailbox cursor processed (overlay before durable) — the drain
    /// resume point.
    pub(crate) async fn last_cursor(&self) -> ChatResult<Option<u64>> {
        if let Some(cursor) = self.pending.borrow().last_cursor {
            return Ok(Some(cursor));
        }
        self.db.load_last_cursor().await
    }
}

// ----- session -----

pub(crate) struct SessionAdapter {
    db: Rc<dyn ChatDb>,
    pending: Rc<RefCell<Pending>>,
}

#[async_trait(?Send)]
impl SessionStore for SessionAdapter {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let key = address.to_string();
        match self.pending.borrow().sessions.get(&key) {
            Some(Some(bytes)) => return Ok(Some(SessionRecord::deserialize(bytes)?)),
            Some(None) => return Ok(None), // archived earlier in this unit of work
            None => {}
        }
        match self
            .db
            .load_session(&key)
            .await
            .map_err(cb("load_session"))?
        {
            Some(bytes) => Ok(Some(SessionRecord::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        self.pending
            .borrow_mut()
            .sessions
            .insert(address.to_string(), Some(record.serialize()?));
        Ok(())
    }
}

// ----- identity -----

pub(crate) struct IdentityAdapter {
    db: Rc<dyn ChatDb>,
    pending: Rc<RefCell<Pending>>,
    key_pair: IdentityKeyPair,
    registration_id: u32,
}

impl IdentityAdapter {
    /// A peer's stored public identity (overlay first, then durable), or `None`.
    async fn stored_identity(&self, key: &str) -> Result<Option<IdentityKey>> {
        if let Some(bytes) = self.pending.borrow().identities.get(key) {
            return Ok(Some(IdentityKey::decode(bytes)?));
        }
        match self
            .db
            .load_identity(key)
            .await
            .map_err(cb("get_identity"))?
        {
            Some(bytes) => Ok(Some(IdentityKey::decode(&bytes)?)),
            None => Ok(None),
        }
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityAdapter {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange> {
        let key = address.to_string();
        // TOFU with change detection — mirrors InMemIdentityKeyStore exactly: only
        // (re)write when new or changed, and report whether an existing key moved.
        match self.stored_identity(&key).await? {
            Some(k) if &k == identity => Ok(IdentityChange::NewOrUnchanged),
            existing => {
                self.pending
                    .borrow_mut()
                    .identities
                    .insert(key, identity.serialize().to_vec());
                Ok(IdentityChange::from_changed(existing.is_some()))
            }
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool> {
        match self.stored_identity(&address.to_string()).await? {
            None => Ok(true), // trust on first use
            Some(k) => Ok(&k == identity),
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        self.stored_identity(&address.to_string()).await
    }
}

// ----- one-time EC prekeys -----

pub(crate) struct PreKeyAdapter {
    db: Rc<dyn ChatDb>,
    pending: Rc<RefCell<Pending>>,
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeyAdapter {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        let id = u32::from(prekey_id);
        match self.pending.borrow().pre_keys.get(&id) {
            Some(Some(bytes)) => return PreKeyRecord::deserialize(bytes),
            Some(None) => return Err(SignalProtocolError::InvalidPreKeyId),
            None => {}
        }
        match self.db.load_pre_key(id).await.map_err(cb("get_pre_key"))? {
            Some(bytes) => PreKeyRecord::deserialize(&bytes),
            None => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.pending
            .borrow_mut()
            .pre_keys
            .insert(u32::from(prekey_id), Some(record.serialize()?));
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        // Tombstone in the overlay so this op's later reads see the removal; the
        // atomic commit turns it into a DELETE.
        self.pending
            .borrow_mut()
            .pre_keys
            .insert(u32::from(prekey_id), None);
        Ok(())
    }
}

// ----- signed prekeys -----

pub(crate) struct SignedPreKeyAdapter {
    db: Rc<dyn ChatDb>,
    pending: Rc<RefCell<Pending>>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeyAdapter {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        let n = u32::from(id);
        if let Some(bytes) = self.pending.borrow().signed_pre_keys.get(&n) {
            return SignedPreKeyRecord::deserialize(bytes);
        }
        match self
            .db
            .load_signed_pre_key(n)
            .await
            .map_err(cb("get_signed_pre_key"))?
        {
            Some(bytes) => SignedPreKeyRecord::deserialize(&bytes),
            None => Err(SignalProtocolError::InvalidSignedPreKeyId),
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.pending
            .borrow_mut()
            .signed_pre_keys
            .insert(u32::from(id), record.serialize()?);
        Ok(())
    }
}

// ----- kyber prekeys -----

pub(crate) struct KyberAdapter {
    db: Rc<dyn ChatDb>,
    pending: Rc<RefCell<Pending>>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberAdapter {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> Result<KyberPreKeyRecord> {
        let n = u32::from(id);
        if let Some(bytes) = self.pending.borrow().kyber_pre_keys.get(&n) {
            return KyberPreKeyRecord::deserialize(bytes);
        }
        match self
            .db
            .load_kyber_pre_key(n)
            .await
            .map_err(cb("get_kyber_pre_key"))?
        {
            Some(bytes) => KyberPreKeyRecord::deserialize(&bytes),
            None => Err(SignalProtocolError::InvalidKyberPreKeyId),
        }
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.pending
            .borrow_mut()
            .kyber_pre_keys
            .insert(u32::from(id), record.serialize()?);
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()> {
        // libsignal's last-resort replay guard: a given (kyberId, ecId, baseKey)
        // triple must never be accepted twice.
        let k = u32::from(kyber_prekey_id);
        let e = u32::from(ec_prekey_id);
        let bk = base_key.serialize().to_vec();
        let seen_in_pending = self
            .pending
            .borrow()
            .kyber_seen
            .iter()
            .any(|(pk, pe, pbk)| *pk == k && *pe == e && *pbk == bk);
        let seen = seen_in_pending
            || self
                .db
                .kyber_base_key_seen(k, e, &bk)
                .await
                .map_err(cb("mark_kyber_pre_key_used"))?;
        if seen {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key".to_owned(),
            ));
        }
        self.pending.borrow_mut().kyber_seen.push((k, e, bk));
        Ok(())
    }
}

// ----- sender keys (groups; reserved) -----

pub(crate) struct SenderKeyAdapter {
    db: Rc<dyn ChatDb>,
    pending: Rc<RefCell<Pending>>,
}

#[async_trait(?Send)]
impl SenderKeyStore for SenderKeyAdapter {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<()> {
        self.pending.borrow_mut().sender_keys.insert(
            (sender.to_string(), distribution_id.to_string()),
            record.serialize()?,
        );
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>> {
        let key = (sender.to_string(), distribution_id.to_string());
        if let Some(bytes) = self.pending.borrow().sender_keys.get(&key) {
            return Ok(Some(SenderKeyRecord::deserialize(bytes)?));
        }
        match self
            .db
            .load_sender_key(&key.0, &key.1)
            .await
            .map_err(cb("load_sender_key"))?
        {
            Some(bytes) => Ok(Some(SenderKeyRecord::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }
}
