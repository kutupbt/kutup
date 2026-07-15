//! Chat-device identity + prekey generation. Produces three things from one RNG
//! pass: the [`LocalIdentity`] (private identity material), a [`Pending`] seed
//! holding every generated prekey record ready to install atomically, and the
//! `kutup-chat-proto` wire request the client POSTs to register. Mirrors libsignal
//! test-support's bundle construction (see `spikes/libsignal-wasm`), but writing
//! into our durable store instead of an in-memory one.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
// Glob like the reference spike: `Record::new`, `GenericSignedPreKey::serialize`,
// and `kem::*` are trait/inherent items that must be in scope.
use libsignal_protocol::*;
use rand::{CryptoRng, Rng};

use crate::db::{LocalIdentity, Pending};
use crate::error::{crypto, Result};
use kutup_chat_proto::{
    EcPreKey, KemPreKey, RegisterChatDeviceRequest, ReplenishKeysRequest, SuiteId,
};

/// libsignal registration ids must fit the reserved range (`< 16380`).
const MAX_REGISTRATION_ID: u32 = 16380;
/// Fixed creation timestamp for generated prekeys. Prekey timestamps drive only
/// libsignal's rotation bookkeeping, not the wire; a constant keeps generation
/// deterministic given the RNG.
const PREKEY_TS_MS: u64 = 42;

/// Everything a fresh device needs: the cached private identity, the durable
/// seed to `apply`, and the one-shot registration payload to publish.
pub(crate) struct GeneratedMaterial {
    pub local: LocalIdentity,
    pub seed: Pending,
    pub registration: RegisterChatDeviceRequest,
}

pub(crate) struct ReplenishmentMaterial {
    pub request: ReplenishKeysRequest,
    pub pre_keys: Vec<(u32, Vec<u8>)>,
    pub kyber_pre_keys: Vec<(u32, Vec<u8>)>,
}

/// Generate a new chat device with `num_one_time` one-time prekeys of each kind
/// plus a last-resort Kyber prekey. `name` is the human device label.
pub(crate) fn generate<R: Rng + CryptoRng>(
    name: impl Into<String>,
    num_one_time: usize,
    rng: &mut R,
) -> Result<GeneratedMaterial> {
    let registration_id = rng.random::<u32>() % MAX_REGISTRATION_ID + 1;
    let identity_pair = IdentityKeyPair::generate(rng);
    let local = LocalIdentity {
        identity_key_pair: identity_pair.serialize().to_vec(),
        registration_id,
        device_id: None,
    };
    let private = identity_pair.private_key();

    let mut seed = Pending {
        local_identity: Some(local.clone()),
        ..Pending::default()
    };

    // Signed EC prekey (id 1).
    let spk = KeyPair::generate(rng);
    let spk_pub = spk.public_key.serialize();
    let spk_sig = crypto(private.calculate_signature(&spk_pub, rng))?.to_vec();
    let spk_id = 1u32;
    seed.signed_pre_keys.insert(
        spk_id,
        SignedPreKeyRecord::new(
            spk_id.into(),
            Timestamp::from_epoch_millis(PREKEY_TS_MS),
            &spk,
            &spk_sig,
        )
        .serialize()?,
    );

    // Last-resort Kyber prekey (id 1).
    let lrk = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let lrk_pub = lrk.public_key.serialize();
    let lrk_sig = crypto(private.calculate_signature(&lrk_pub, rng))?.to_vec();
    let lrk_id = 1u32;
    seed.kyber_pre_keys.insert(
        lrk_id,
        KyberPreKeyRecord::new(
            lrk_id.into(),
            Timestamp::from_epoch_millis(PREKEY_TS_MS),
            &lrk,
            &lrk_sig,
        )
        .serialize()?,
    );

    // One-time EC pool (ids 100..).
    let mut one_time_pre_keys = Vec::with_capacity(num_one_time);
    for i in 0..num_one_time as u32 {
        let id = 100 + i;
        let kp = KeyPair::generate(rng);
        seed.pre_keys
            .insert(id, Some(PreKeyRecord::new(id.into(), &kp).serialize()?));
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
        let sig = crypto(private.calculate_signature(&pub_bytes, rng))?.to_vec();
        seed.kyber_pre_keys.insert(
            id,
            KyberPreKeyRecord::new(
                id.into(),
                Timestamp::from_epoch_millis(PREKEY_TS_MS),
                &kp,
                &sig,
            )
            .serialize()?,
        );
        one_time_kyber_pre_keys.push(KemPreKey {
            key_id: id,
            public_key: b64(&pub_bytes),
            signature: b64(&sig),
        });
    }

    let registration = RegisterChatDeviceRequest {
        suite: SuiteId::PqxdhTripleRatchetV1,
        registration_id,
        identity_key: b64(&identity_pair.identity_key().serialize()),
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
    seed.registration_upload = Some(Some(serde_json::to_vec(&registration).map_err(
        |error| crate::ChatError::Content(format!("serialize registration request: {error}")),
    )?));

    Ok(GeneratedMaterial {
        local,
        seed,
        registration,
    })
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Generate one-time EC + Kyber keys for a low-watermark refill. The caller
/// commits `pre_keys`, `kyber_pre_keys`, and the serialized request atomically
/// before attempting publication.
pub(crate) fn generate_replenishment<R: Rng + CryptoRng>(
    identity_pair: &IdentityKeyPair,
    ec_ids: &[u32],
    kyber_ids: &[u32],
    rng: &mut R,
) -> Result<ReplenishmentMaterial> {
    let timestamp = Timestamp::from_epoch_millis(crate::clock::unix_millis() as u64);
    let private = identity_pair.private_key();
    let mut pre_keys = Vec::with_capacity(ec_ids.len());
    let mut one_time_pre_keys = Vec::with_capacity(ec_ids.len());
    for &id in ec_ids {
        let pair = KeyPair::generate(rng);
        pre_keys.push((id, PreKeyRecord::new(id.into(), &pair).serialize()?));
        one_time_pre_keys.push(EcPreKey {
            key_id: id,
            public_key: b64(&pair.public_key.serialize()),
            signature: None,
        });
    }

    let mut kyber_pre_keys = Vec::with_capacity(kyber_ids.len());
    let mut one_time_kyber_pre_keys = Vec::with_capacity(kyber_ids.len());
    for &id in kyber_ids {
        let pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let public = pair.public_key.serialize();
        let signature = crypto(private.calculate_signature(&public, rng))?.to_vec();
        kyber_pre_keys.push((
            id,
            KyberPreKeyRecord::new(id.into(), timestamp, &pair, &signature).serialize()?,
        ));
        one_time_kyber_pre_keys.push(KemPreKey {
            key_id: id,
            public_key: b64(&public),
            signature: b64(&signature),
        });
    }

    Ok(ReplenishmentMaterial {
        request: ReplenishKeysRequest {
            signed_pre_key: None,
            last_resort_kyber_pre_key: None,
            one_time_pre_keys,
            one_time_kyber_pre_keys,
        },
        pre_keys,
        kyber_pre_keys,
    })
}
