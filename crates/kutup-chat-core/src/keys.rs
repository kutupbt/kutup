//! Chat-device identity + prekey generation. Produces the `kutup-chat-proto`
//! wire request a client POSTs to register, and the libsignal store that holds
//! the matching private material. Mirrors libsignal test-support's bundle
//! construction (see `spikes/libsignal-wasm`), but emitting our wire types.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures_util::FutureExt as _;
// Glob like the reference spike: the store operations and `Record::new` are
// trait methods (IdentityKeyStore, SignedPreKeyStore, KyberPreKeyStore,
// PreKeyStore, GenericSignedPreKey) that must be in scope.
use libsignal_protocol::*;
use rand::{CryptoRng, Rng};

use crate::error::{crypto, Result};
use kutup_chat_proto::{EcPreKey, KemPreKey, RegisterChatDeviceRequest, SuiteId};

/// libsignal registration ids must fit the reserved range (`< 16380`).
const MAX_REGISTRATION_ID: u32 = 16380;
/// Fixed creation timestamp for generated prekeys (matches the spike; real
/// timestamps arrive with the durable-store slice).
const PREKEY_TS_MS: u64 = 42;

/// A freshly generated chat device: the private-material store plus the public
/// bundle to publish.
pub struct GeneratedDevice {
    pub(crate) store: InMemSignalProtocolStore,
    pub registration: RegisterChatDeviceRequest,
}

/// Generation entry point.
pub struct DeviceKeys;

impl DeviceKeys {
    /// Generates a new chat device with `num_one_time` one-time prekeys of each
    /// kind and a last-resort Kyber prekey. `name` is the human device label.
    pub fn generate<R: Rng + CryptoRng>(
        name: impl Into<String>,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<GeneratedDevice> {
        let registration_id = rng.random::<u32>() % MAX_REGISTRATION_ID + 1;
        let identity_pair = IdentityKeyPair::generate(rng);
        let mut store = InMemSignalProtocolStore::new(identity_pair, registration_id)?;
        let identity = sync(store.get_identity_key_pair())?;

        // Signed EC prekey (id 1).
        let spk = KeyPair::generate(rng);
        let spk_pub = spk.public_key.serialize();
        let spk_sig = crypto(identity.private_key().calculate_signature(&spk_pub, rng))?.to_vec();
        let spk_id = 1u32;
        sync(store.save_signed_pre_key(
            spk_id.into(),
            &SignedPreKeyRecord::new(
                spk_id.into(),
                Timestamp::from_epoch_millis(PREKEY_TS_MS),
                &spk,
                &spk_sig,
            ),
        ))?;

        // Last-resort Kyber prekey (id 1).
        let lrk = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let lrk_pub = lrk.public_key.serialize();
        let lrk_sig = crypto(identity.private_key().calculate_signature(&lrk_pub, rng))?.to_vec();
        let lrk_id = 1u32;
        sync(store.save_kyber_pre_key(
            lrk_id.into(),
            &KyberPreKeyRecord::new(
                lrk_id.into(),
                Timestamp::from_epoch_millis(PREKEY_TS_MS),
                &lrk,
                &lrk_sig,
            ),
        ))?;

        // One-time EC pool (ids 100..).
        let mut one_time_pre_keys = Vec::with_capacity(num_one_time);
        for i in 0..num_one_time as u32 {
            let id = 100 + i;
            let kp = KeyPair::generate(rng);
            sync(store.save_pre_key(id.into(), &PreKeyRecord::new(id.into(), &kp)))?;
            one_time_pre_keys.push(EcPreKey {
                key_id: id,
                public_key: b64(&kp.public_key.serialize()),
                signature: None,
            });
        }

        // One-time Kyber pool (ids 200..).
        let mut one_time_kyber_pre_keys = Vec::with_capacity(num_one_time);
        for i in 0..num_one_time as u32 {
            let id = 200 + i;
            let kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
            let pub_bytes = kp.public_key.serialize();
            let sig = crypto(identity.private_key().calculate_signature(&pub_bytes, rng))?.to_vec();
            sync(store.save_kyber_pre_key(
                id.into(),
                &KyberPreKeyRecord::new(
                    id.into(),
                    Timestamp::from_epoch_millis(PREKEY_TS_MS),
                    &kp,
                    &sig,
                ),
            ))?;
            one_time_kyber_pre_keys.push(KemPreKey {
                key_id: id,
                public_key: b64(&pub_bytes),
                signature: b64(&sig),
            });
        }

        let registration = RegisterChatDeviceRequest {
            suite: SuiteId::PqxdhTripleRatchetV1,
            registration_id,
            identity_key: b64(&identity.identity_key().serialize()),
            signed_pre_key: EcPreKey {
                key_id: spk_id,
                public_key: b64(&spk_pub),
                signature: Some(b64(&spk_sig)),
            },
            last_resort_kyber_pre_key: KemPreKey {
                key_id: lrk_id,
                public_key: b64(&lrk_pub),
                signature: b64(&lrk_sig),
            },
            one_time_pre_keys,
            one_time_kyber_pre_keys,
            name: name.into(),
            device_signature: None,
        };

        Ok(GeneratedDevice {
            store,
            registration,
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// libsignal's store futures resolve immediately with in-memory stores, so we
/// drive them without an executor (the same trick the spike uses in wasm).
pub(crate) fn sync<T>(
    fut: impl std::future::Future<Output = std::result::Result<T, SignalProtocolError>>,
) -> Result<T> {
    fut.now_or_never()
        .expect("in-memory store future did not resolve synchronously")
        .map_err(Into::into)
}
