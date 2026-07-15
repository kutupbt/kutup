//! The local chat device: establishes 1:1 sessions and encrypts/decrypts
//! content. Session and ratchet state live in a durable [`ChatDb`] behind the
//! store adapters (`store.rs`); this is the thin, kutup-typed layer over
//! `process_prekey_bundle` / `message_encrypt` / `message_decrypt`.
//!
//! Every crypto op runs against a [`Pending`](crate::db::Pending) unit of work and
//! commits atomically only on success — so a crash between the crypto and the
//! commit re-runs the op from the last durable state, and a decrypt's ratchet
//! advance is persisted before its plaintext is handed up. The send/drain/ack
//! orchestration (durable outbox, 409 recovery) builds on these guarantees next.

use std::rc::Rc;
use std::time::SystemTime;

use libsignal_protocol::{message_decrypt, message_encrypt, process_prekey_bundle};
use rand::{CryptoRng, Rng};

use crate::address::ChatAddress;
use crate::db::ChatDb;
use crate::error::{ChatError, Result};
use crate::keys;
use crate::store::{sync, ChatStore};
use crate::wire::{decode_ciphertext, encode_ciphertext, to_prekey_bundle};
use kutup_chat_proto::{
    ChatContent, DeliveredEnvelope, DevicePreKeyBundle, OutgoingEnvelope,
    RegisterChatDeviceRequest, SuiteId,
};

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
    pub fn generate<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        user: impl Into<String>,
        device_id: u32,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let material = keys::generate("kutup device", num_one_time, rng)?;
        // Install the whole device (identity + every prekey) in one transaction.
        db.apply(&material.seed)?;
        let store = ChatStore::attach(db, material.local)?;
        Ok(Session {
            store,
            registration: Some(material.registration),
            address: ChatAddress::local(user, device_id),
        })
    }

    /// Reopen the device already installed in `db` (e.g. on app restart).
    pub fn open(db: Rc<dyn ChatDb>, user: impl Into<String>, device_id: u32) -> Result<Self> {
        let local = db
            .load_local_identity()?
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

    /// Apply the server-assigned device id after registration.
    pub fn set_device_id(&mut self, device_id: u32) {
        self.address.device_id = device_id;
    }

    /// Establish an outbound session to `peer` from its served prekey bundle.
    pub fn establish<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
        rng: &mut R,
    ) -> Result<()> {
        let pkb = to_prekey_bundle(bundle)?;
        let peer_addr = peer.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        let result = sync(process_prekey_bundle(
            &peer_addr,
            &self_addr,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &pkb,
            now(),
            rng,
        ));
        match result {
            Ok(()) => self.store.commit(),
            Err(e) => {
                self.store.discard();
                Err(e)
            }
        }
    }

    /// Encrypt `content` for `peer` into a wire envelope. `recipient_reg_id` is
    /// the peer device's registration id from its bundle (the server checks it
    /// for staleness). The sender ratchet only advances durably once a wire
    /// envelope is produced, so a failure leaves the session retryable.
    pub fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        recipient_reg_id: u32,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<OutgoingEnvelope> {
        let plaintext =
            serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?;
        let peer_addr = peer.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        let result = sync(message_encrypt(
            &plaintext,
            &peer_addr,
            &self_addr,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            now(),
            rng,
        ));
        // Only advance the ratchet durably once a wire envelope is in hand.
        match result.and_then(|msg| encode_ciphertext(&msg)) {
            Ok((envelope_type, content)) => {
                self.store.commit()?;
                Ok(OutgoingEnvelope {
                    device_id: peer.device_id,
                    registration_id: recipient_reg_id,
                    envelope_type,
                    suite: SuiteId::PqxdhTripleRatchetV1,
                    content,
                })
            }
            Err(e) => {
                self.store.discard();
                Err(e)
            }
        }
    }

    /// Decrypt a delivered envelope from `from` into its content document. On a
    /// successful decrypt the ratchet advance is committed **before** the
    /// plaintext is parsed and returned — so the message is never double-consumed,
    /// even if its plaintext turns out to be a content schema we can't parse.
    pub fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        from: &ChatAddress,
        envelope: &DeliveredEnvelope,
        rng: &mut R,
    ) -> Result<ChatContent> {
        let msg = decode_ciphertext(envelope.envelope_type, &envelope.content)?;
        let from_addr = from.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        let result = sync(message_decrypt(
            &msg,
            &from_addr,
            &self_addr,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            rng,
        ));
        let plaintext = match result {
            Ok(p) => {
                self.store.commit()?;
                p
            }
            Err(e) => {
                self.store.discard();
                return Err(e);
            }
        };
        serde_json::from_slice(&plaintext).map_err(|e| ChatError::Content(e.to_string()))
    }
}

/// The wall clock libsignal uses for prekey/session staleness checks. Native uses
/// the real clock; the wasm adapter will inject one when that build lands.
fn now() -> SystemTime {
    SystemTime::now()
}
