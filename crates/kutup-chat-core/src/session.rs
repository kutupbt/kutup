//! The local chat device: establishes 1:1 sessions and encrypts/decrypts
//! content. Sessions live inside the libsignal store keyed by peer address;
//! this is the thin, kutup-typed layer over `process_prekey_bundle` /
//! `message_encrypt` / `message_decrypt`.
//!
//! First slice: an in-memory store and a fixed `now` (mirroring the spike), so
//! the crypto loop is proven through the wire types. The durable store and real
//! clock arrive with the next slice; the public API here does not change.

use std::time::SystemTime;

use libsignal_protocol::{message_decrypt, message_encrypt, process_prekey_bundle};
use rand::{CryptoRng, Rng};

use crate::address::ChatAddress;
use crate::error::{ChatError, Result};
use crate::keys::{sync, DeviceKeys, GeneratedDevice};
use crate::wire::{decode_ciphertext, encode_ciphertext, to_prekey_bundle};
use kutup_chat_proto::{
    ChatContent, DeliveredEnvelope, DevicePreKeyBundle, OutgoingEnvelope, SuiteId,
};

/// A registered local chat device with its libsignal store.
pub struct Session {
    device: GeneratedDevice,
    address: ChatAddress,
}

impl Session {
    /// Generates a new device. Returns the session plus the registration to
    /// publish (`POST /api/chat/device`); the server assigns the real device
    /// id, so `address` starts with the caller's provisional id and is updated
    /// via [`Session::set_device_id`] once registered.
    pub fn generate<R: Rng + CryptoRng>(
        user: impl Into<String>,
        device_id: u32,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let device = DeviceKeys::generate("kutup device", num_one_time, rng)?;
        Ok(Session {
            device,
            address: ChatAddress::local(user, device_id),
        })
    }

    /// The registration request to publish.
    pub fn registration(&self) -> &kutup_chat_proto::RegisterChatDeviceRequest {
        &self.device.registration
    }

    /// Applies the server-assigned device id after registration.
    pub fn set_device_id(&mut self, device_id: u32) {
        self.address.device_id = device_id;
    }

    /// Establishes an outbound session to `peer` from its served prekey bundle.
    pub fn establish<R: Rng + CryptoRng>(
        &mut self,
        peer: &ChatAddress,
        bundle: &DevicePreKeyBundle,
        rng: &mut R,
    ) -> Result<()> {
        let pkb = to_prekey_bundle(bundle)?;
        let peer_addr = peer.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        sync(process_prekey_bundle(
            &peer_addr,
            &self_addr,
            &mut self.device.store.session_store,
            &mut self.device.store.identity_store,
            &pkb,
            now(),
            rng,
        ))?;
        Ok(())
    }

    /// Encrypts `content` for `peer` into a wire envelope. `recipient_reg_id` is
    /// the peer device's registration id from its bundle (the server checks it
    /// for staleness); pass it through from the fetched bundle.
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
        let msg = sync(message_encrypt(
            &plaintext,
            &peer_addr,
            &self_addr,
            &mut self.device.store.session_store,
            &mut self.device.store.identity_store,
            now(),
            rng,
        ))?;
        let (envelope_type, content) = encode_ciphertext(&msg)?;
        Ok(OutgoingEnvelope {
            device_id: peer.device_id,
            registration_id: recipient_reg_id,
            envelope_type,
            suite: SuiteId::PqxdhTripleRatchetV1,
            content,
        })
    }

    /// Decrypts a delivered envelope from `from` into its content document.
    pub fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        from: &ChatAddress,
        envelope: &DeliveredEnvelope,
        rng: &mut R,
    ) -> Result<ChatContent> {
        let msg = decode_ciphertext(envelope.envelope_type, &envelope.content)?;
        let from_addr = from.to_protocol()?;
        let self_addr = self.address.to_protocol()?;
        let plaintext = sync(message_decrypt(
            &msg,
            &from_addr,
            &self_addr,
            &mut self.device.store.session_store,
            &mut self.device.store.identity_store,
            &mut self.device.store.pre_key_store,
            &self.device.store.signed_pre_key_store,
            &mut self.device.store.kyber_pre_key_store,
            rng,
        ))?;
        serde_json::from_slice(&plaintext).map_err(|e| ChatError::Content(e.to_string()))
    }
}

/// Fixed reference time for the first slice (matches the spike). Real clients
/// pass the current time once the durable store lands.
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
}
