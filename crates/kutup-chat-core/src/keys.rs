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
    AccountManifestV3, DeviceRegistrationV1, DirectChatSuiteId, EcPreKey, KemPreKey,
    RegisterChatDeviceRequestV2, ReplenishKeysRequest, DEVICE_CREDENTIAL_LEN,
};

/// libsignal registration ids must fit the reserved range (`< 16380`).
const MAX_REGISTRATION_ID: u32 = 16380;

/// A libsignal registration id, 1..=16380.
pub(crate) fn random_registration_id<R: Rng + CryptoRng>(rng: &mut R) -> u32 {
    rng.random::<u32>() % MAX_REGISTRATION_ID + 1
}

/// How a new device gets the account's identity.
pub(crate) enum NewDevice<'a> {
    /// Linked: the identity came in a provisioning message, with the
    /// one-time link token.
    Linked {
        identity: IdentityKeyPair,
        link_token: String,
    },
    /// A re-registration (also an account's first device): a new identity,
    /// and the account's next manifest listing this device alone, signed by
    /// `manifest` from the new identity (which also signs its binding to the
    /// authority) and the registration id.
    Reregistration {
        manifest: &'a dyn Fn(&IdentityKeyPair, u32) -> crate::Result<AccountManifestV3>,
    },
    /// Keys alone, with no registration request: a new identity, or the one
    /// given (another device of the same account). For tests and tools that
    /// serve bundles themselves.
    Standalone { identity: Option<IdentityKeyPair> },
}

/// What a device publishes for its bundle: its registration id, the
/// account's identity key and its prekeys.
#[derive(Clone, Debug)]
pub struct PublishedKeys {
    pub registration_id: u32,
    pub suite: DirectChatSuiteId,
    pub identity_key: String,
    pub signed_pre_key: EcPreKey,
    pub last_resort_kyber_pre_key: KemPreKey,
    pub one_time_pre_keys: Vec<EcPreKey>,
    pub one_time_kyber_pre_keys: Vec<KemPreKey>,
}
/// Fixed creation timestamp for generated prekeys. Prekey timestamps drive only
/// libsignal's rotation bookkeeping, not the wire; a constant keeps generation
/// deterministic given the RNG.
const PREKEY_TS_MS: u64 = 42;

/// Everything a fresh device needs: the cached private identity, the durable
/// seed to `apply`, and the one-shot registration payload to publish.
pub(crate) struct GeneratedMaterial {
    pub local: LocalIdentity,
    pub seed: Pending,
    pub published: PublishedKeys,
    /// The request to register with; none for [`NewDevice::Standalone`].
    pub registration: Option<RegisterChatDeviceRequestV2>,
}

pub(crate) struct ReplenishmentMaterial {
    pub request: ReplenishKeysRequest,
    pub pre_keys: Vec<(u32, Vec<u8>)>,
    pub kyber_pre_keys: Vec<(u32, Vec<u8>)>,
}

/// Generate a new chat device with `num_one_time` one-time prekeys of each kind
/// plus a last-resort Kyber prekey, every signed key signed by the account's
/// identity. `name` is the human device label. The seed discards whatever
/// Chat transport state the store held before (a re-registration, or a store
/// from before the account identity) in the same commit that installs this
/// device.
pub(crate) fn generate<R: Rng + CryptoRng>(
    name: impl Into<String>,
    num_one_time: usize,
    new_device: NewDevice<'_>,
    rng: &mut R,
) -> Result<GeneratedMaterial> {
    let registration_id = random_registration_id(rng);
    let (identity_pair, link_token, manifest) = match new_device {
        NewDevice::Linked {
            identity,
            link_token,
        } => (identity, Some(link_token), None),
        NewDevice::Reregistration { manifest } => {
            (IdentityKeyPair::generate(rng), None, Some(manifest))
        }
        NewDevice::Standalone { identity } => (
            identity.unwrap_or_else(|| IdentityKeyPair::generate(rng)),
            None,
            None,
        ),
    };
    let mut credential = zeroize::Zeroizing::new([0u8; DEVICE_CREDENTIAL_LEN]);
    rng.fill_bytes(credential.as_mut());
    let credential = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential.as_ref());
    let local = LocalIdentity {
        identity_key_pair: identity_pair.serialize().to_vec(),
        registration_id,
        device_id: None,
        credential: Some(credential.clone()),
    };
    let private = identity_pair.private_key();

    let mut seed = Pending {
        reset_transport: true,
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

    let identity_key = b64(&identity_pair.identity_key().serialize());
    let published = PublishedKeys {
        registration_id,
        suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        identity_key: identity_key.clone(),
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
    };
    let registration_kind = match (link_token, manifest) {
        (Some(link_token), None) => Some(DeviceRegistrationV1::Link { link_token }),
        (None, Some(manifest)) => Some(DeviceRegistrationV1::Reregistration {
            manifest: Box::new(manifest(&identity_pair, registration_id)?),
        }),
        _ => None,
    };
    let registration = match registration_kind {
        Some(registration_kind) => {
            let registration = RegisterChatDeviceRequestV2 {
                suite: published.suite,
                registration_id,
                identity_key,
                signed_pre_key: published.signed_pre_key.clone(),
                last_resort_kyber_pre_key: published.last_resort_kyber_pre_key.clone(),
                one_time_pre_keys: published.one_time_pre_keys.clone(),
                one_time_kyber_pre_keys: published.one_time_kyber_pre_keys.clone(),
                name: name.into(),
                credential,
                registration: registration_kind,
            };
            registration.validate().map_err(|error| {
                crate::ChatError::Invalid(format!("registration request: {error}"))
            })?;
            seed.registration_upload = Some(Some(serde_json::to_vec(&registration).map_err(
                |error| {
                    crate::ChatError::Content(format!("serialize registration request: {error}"))
                },
            )?));
            Some(registration)
        }
        None => None,
    };

    Ok(GeneratedMaterial {
        local,
        seed,
        published,
        registration,
    })
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A fresh signed EC prekey and last-resort Kyber prekey, both signed by the
/// identity key, to replace the current pair (`crate::prekey_rotation`).
pub(crate) struct RotationMaterial {
    pub signed_pre_key: EcPreKey,
    pub last_resort_kyber_pre_key: KemPreKey,
    pub signed_record: Vec<u8>,
    pub last_resort_record: Vec<u8>,
}

pub(crate) fn generate_rotation<R: Rng + CryptoRng>(
    identity_pair: &IdentityKeyPair,
    signed_id: u32,
    last_resort_id: u32,
    rng: &mut R,
) -> Result<RotationMaterial> {
    let timestamp = Timestamp::from_epoch_millis(crate::clock::unix_millis() as u64);
    let private = identity_pair.private_key();
    let signed = KeyPair::generate(rng);
    let signed_public = signed.public_key.serialize();
    let signed_signature = crypto(private.calculate_signature(&signed_public, rng))?.to_vec();
    let last_resort = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let last_resort_public = last_resort.public_key.serialize();
    let last_resort_signature =
        crypto(private.calculate_signature(&last_resort_public, rng))?.to_vec();
    Ok(RotationMaterial {
        signed_pre_key: EcPreKey {
            key_id: signed_id,
            public_key: b64(&signed_public),
            signature: Some(b64(&signed_signature)),
        },
        last_resort_kyber_pre_key: KemPreKey {
            key_id: last_resort_id,
            public_key: b64(&last_resort_public),
            signature: b64(&last_resort_signature),
        },
        signed_record: SignedPreKeyRecord::new(
            signed_id.into(),
            timestamp,
            &signed,
            &signed_signature,
        )
        .serialize()?,
        last_resort_record: KyberPreKeyRecord::new(
            last_resort_id.into(),
            timestamp,
            &last_resort,
            &last_resort_signature,
        )
        .serialize()?,
    })
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
