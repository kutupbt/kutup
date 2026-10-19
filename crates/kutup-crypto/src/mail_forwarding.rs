//! End-to-end mail forwarding (docs/plans/mail-forwarding.md), as Proton has
//! it: draft-wussler-openpgp-forwarding, proxy re-encryption on Curve25519.
//!
//! - The forwarder's client makes the material ([`generate_material`]): a
//!   forwardee key with one subkey for each of the forwarder's encryption
//!   subkeys (KDF "replaced fingerprint" naming that subkey, flags 0x10 and
//!   0x40, as the draft and go-crypto), and for each a proxy factor
//!   k = dC⁻¹·dB.
//! - The forwardee gets the key in an activation ([`seal_activation`]):
//!   encrypted to their address key and signed by the forwarder's, binding
//!   the forwarding id, both addresses and an expiry. Proton locks the key
//!   under a random passphrase and sends the passphrase as the token;
//!   Kutup's address keys live unlocked inside account envelopes, so the key
//!   itself is what is sealed.
//! - The server turns each arriving key packet for the forwarder into one for
//!   the forwardee ([`transform`]), with k and the forwardee's public key
//!   only: it reads no message. The data packet is left as it is.
//! - The forwardee opens forwarded mail with [`decrypt_forwarded`]; nothing
//!   else accepts a forwardee key ([`crate::mail_key::decrypt`] refuses one).
//!
//! k with the forwardee's secret key gives the forwarder's secret key
//! (dB = k·dC), so k never reaches the forwardee.

use std::io::BufReader;

use pgp::{
    composed::{
        DecryptionOptions, Deserializable as _, KeyType, Message, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey, SignedSecretSubKey, TheRing,
    },
    crypto::{ecc_curve::ECCCurve, public_key::PublicKeyAlgorithm},
    packet::{KeyFlags, Packet, PacketParser, PubKeyInner, PublicSubkey, SecretSubkey},
    ser::Serialize as _,
    types::{
        EcdhKdfType, EcdhPublicParams, Fingerprint, KeyDetails as _, KeyVersion, Password,
        PublicParams, Timestamp,
    },
};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::mail_key::{self, backend, canonical_address, DecryptedMessage, FINGERPRINT_LEN};

/// One forwarder encryption subkey's forwarding: Proton's `ProxyInstance`.
pub struct ProxyInstance {
    /// The forwarder's encryption subkey (v4 fingerprint).
    pub forwarder_fingerprint: [u8; FINGERPRINT_LEN],
    /// The forwardee subkey that stands in for it.
    pub forwardee_fingerprint: [u8; FINGERPRINT_LEN],
    /// k = dC⁻¹·dB mod ℓ, little-endian. Secret: see the module docs.
    pub proxy_parameter: Zeroizing<[u8; 32]>,
}

/// What the forwarder's client makes to set a forwarding up.
pub struct ForwardingMaterial {
    /// The forwardee key, binary and unlocked: only ever sent sealed in an
    /// activation ([`seal_activation`]).
    pub forwardee_secret_key: Zeroizing<Vec<u8>>,
    /// Its public key, which the server keeps to transform key packets.
    pub forwardee_public_key: Vec<u8>,
    /// One per forwarder encryption subkey.
    pub instances: Vec<ProxyInstance>,
}

/// Makes the forwardee key and proxy factors for forwarding the mail of
/// `forwarder_secret_key` (an unlocked address key) to `forwardee_address`,
/// created at `created_at_secs` (Unix seconds).
///
/// Every encryption subkey of the forwarder must be v4 ECDH on Curve25519
/// (as every Kutup address key is): the draft has nothing else.
pub fn generate_material(
    forwarder_secret_key: &[u8],
    forwardee_address: &str,
    created_at_secs: u32,
) -> Result<ForwardingMaterial> {
    let address = canonical_address(forwardee_address)?;
    let forwarder = SignedSecretKey::from_bytes(forwarder_secret_key)
        .map_err(|_| CryptoError::InvalidInput("forwarder key does not parse".into()))?;
    let subkeys: Vec<&SignedSecretSubKey> = forwarder
        .secret_subkeys
        .iter()
        .filter(|subkey| subkey.key.algorithm().can_encrypt())
        .collect();
    if subkeys.is_empty() {
        return Err(CryptoError::InvalidInput(
            "the forwarder key has no encryption subkey".into(),
        ));
    }
    let created_at = Timestamp::from_secs(created_at_secs);
    let mut rng = rand::rngs::OsRng;
    let mut forwardee = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .created_at(created_at)
        .primary_user_id(mail_key::user_id(&address))
        .build()
        .map_err(backend)?
        .generate(rng)
        .map_err(backend)?;

    let mut instances = Vec::with_capacity(subkeys.len());
    for subkey in subkeys {
        let (
            Fingerprint::V4(forwarder_fingerprint),
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
                hash,
                alg_sym,
                ecdh_kdf_type: EcdhKdfType::Native,
                ..
            }),
        ) = (
            subkey.key.fingerprint(),
            subkey.key.public_key().public_params(),
        )
        else {
            return Err(CryptoError::InvalidInput(
                "only v4 Curve25519 encryption subkeys can be forwarded".into(),
            ));
        };
        let (mut public_params, secret_params) = KeyType::ECDH(ECCCurve::Curve25519Legacy)
            .generate(rng)
            .map_err(backend)?;
        let PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
            hash: ref mut new_hash,
            alg_sym: ref mut new_alg_sym,
            ref mut ecdh_kdf_type,
            ..
        }) = public_params
        else {
            return Err(CryptoError::Backend("expected a Curve25519 key".into()));
        };
        // The forwarder's KDF hash and cipher, as pmcrypto copies them, and
        // its fingerprint in place of the forwardee's.
        *new_hash = *hash;
        *new_alg_sym = *alg_sym;
        *ecdh_kdf_type = EcdhKdfType::Replaced {
            replacement_fingerprint: forwarder_fingerprint,
        };
        let public = PublicSubkey::from_inner(
            PubKeyInner::new(
                KeyVersion::V4,
                PublicKeyAlgorithm::ECDH,
                created_at,
                None,
                public_params,
            )
            .map_err(backend)?,
        )
        .map_err(backend)?;
        let mut flags = KeyFlags::default();
        flags.set_shared(true);
        flags.set_draft_decrypt_forwarded(true);
        let binding = public
            .sign(
                &mut rng,
                &forwardee.primary_key,
                forwardee.public_key(),
                &Password::empty(),
                flags,
                None,
            )
            .map_err(backend)?;
        let secret = SecretSubkey::new(public, secret_params).map_err(backend)?;
        let proxy_parameter = subkey
            .key
            .generate_proxy_parameter(&secret, &Password::empty(), &Password::empty())
            .map_err(backend)?;
        let Fingerprint::V4(forwardee_fingerprint) = secret.fingerprint() else {
            return Err(CryptoError::Backend("expected a v4 fingerprint".into()));
        };
        instances.push(ProxyInstance {
            forwarder_fingerprint,
            forwardee_fingerprint,
            proxy_parameter: Zeroizing::new(*proxy_parameter.as_ref()),
        });
        forwardee
            .secret_subkeys
            .push(SignedSecretSubKey::new(secret, vec![binding]));
    }

    let public = SignedPublicKey::from(forwardee.clone());
    Ok(ForwardingMaterial {
        forwardee_secret_key: Zeroizing::new(forwardee.to_bytes().map_err(backend)?),
        forwardee_public_key: public.to_bytes().map_err(backend)?,
        instances,
    })
}

/// The server's step: turns `key_packet` (one v3 PKESK to the forwarder's
/// subkey) into the same session key for the forwardee subkey `instance`
/// names, in `forwardee_public_key`. Store it before the unchanged data
/// packet. Refuses a key packet for another key.
pub fn transform(
    key_packet: &[u8],
    forwardee_public_key: &[u8],
    instance: &ProxyInstance,
) -> Result<Vec<u8>> {
    let mut packets = PacketParser::new(BufReader::new(key_packet));
    let pkesk = match (packets.next(), packets.next()) {
        (Some(Ok(Packet::PublicKeyEncryptedSessionKey(pkesk))), None) => pkesk,
        _ => return Err(CryptoError::InvalidInput("not a single key packet".into())),
    };
    let forwardee = SignedPublicKey::from_bytes(forwardee_public_key)
        .map_err(|_| CryptoError::InvalidInput("forwardee key does not parse".into()))?;
    let subkey = forwardee
        .public_subkeys
        .iter()
        .find(|subkey| subkey.key.fingerprint() == Fingerprint::V4(instance.forwardee_fingerprint))
        .ok_or_else(|| CryptoError::InvalidInput("the forwardee key has no such subkey".into()))?;
    // rPGP also checks that the key packet names the subkey's replacement
    // fingerprint, i.e. the forwarder's.
    let transformed = pkesk
        .forwarding_transform(&subkey.key, (*instance.proxy_parameter).into())
        .map_err(|_| CryptoError::InvalidInput("the key packet can't be forwarded".into()))?;
    Packet::PublicKeyEncryptedSessionKey(transformed)
        .to_bytes()
        .map_err(backend)
}

const ACTIVATION_MAGIC: &[u8; 8] = b"KUTPFWA1";
const MAX_ADDRESS_LEN: usize = 320;
const MAX_KEY_LEN: usize = 16 * 1024;

/// What an activation binds besides the key: which forwarding, between
/// which addresses, until when (docs/plans/mail-forwarding.md, "Accept
/// checks"). Proton's token binds none of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationTerms {
    /// The server's id of the forwarding (a UUID).
    pub forwarding_id: String,
    pub forwarder_address: String,
    pub forwardee_address: String,
    /// Unix seconds after which the forwardee refuses it.
    pub expires_at_secs: u64,
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len = u16::try_from(field.len())
        .map_err(|_| CryptoError::InvalidInput("activation field too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn activation_plaintext(terms: &ActivationTerms, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(ACTIVATION_MAGIC.to_vec());
    push_field(&mut out, terms.forwarding_id.as_bytes())?;
    push_field(
        &mut out,
        canonical_address(&terms.forwarder_address)?.as_bytes(),
    )?;
    push_field(
        &mut out,
        canonical_address(&terms.forwardee_address)?.as_bytes(),
    )?;
    out.extend_from_slice(&terms.expires_at_secs.to_be_bytes());
    let len = u32::try_from(key.len())
        .map_err(|_| CryptoError::InvalidInput("forwardee key too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(key);
    Ok(out)
}

fn parse_activation(plain: &[u8]) -> Result<(ActivationTerms, Zeroizing<Vec<u8>>)> {
    let invalid = || CryptoError::InvalidInput("not a forwarding activation".into());
    let mut rest = plain
        .strip_prefix(ACTIVATION_MAGIC.as_slice())
        .ok_or_else(invalid)?;
    let mut field = |max: usize| -> Result<String> {
        let (len, tail) = rest.split_first_chunk::<2>().ok_or_else(invalid)?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len > max || tail.len() < len {
            return Err(invalid());
        }
        let (value, tail) = tail.split_at(len);
        rest = tail;
        String::from_utf8(value.to_vec()).map_err(|_| invalid())
    };
    let forwarding_id = field(64)?;
    let forwarder_address = field(MAX_ADDRESS_LEN)?;
    let forwardee_address = field(MAX_ADDRESS_LEN)?;
    let (expires, tail) = rest.split_first_chunk::<8>().ok_or_else(invalid)?;
    let (len, key) = tail.split_first_chunk::<4>().ok_or_else(invalid)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| invalid())?;
    if len > MAX_KEY_LEN || key.len() != len {
        return Err(invalid());
    }
    Ok((
        ActivationTerms {
            forwarding_id,
            forwarder_address,
            forwardee_address,
            expires_at_secs: u64::from_be_bytes(*expires),
        },
        Zeroizing::new(key.to_vec()),
    ))
}

/// Seals the forwardee key for the forwardee under `terms`: encrypted to
/// their address key, signed by the forwarder's. Armored. Proton's locked
/// key and `ActivationToken` in one: Kutup's address keys have no
/// passphrase.
pub fn seal_activation(
    forwardee_address_public_key: &[u8],
    forwarder_secret_key: &[u8],
    terms: &ActivationTerms,
    material: &ForwardingMaterial,
) -> Result<String> {
    mail_key::encrypt(
        forwardee_address_public_key,
        Some(forwarder_secret_key),
        &activation_plaintext(terms, &material.forwardee_secret_key)?,
    )
}

/// The forwardee's client opens an activation and checks it before keeping
/// the key: signed by `forwarder_public_key` (taken from the forwarder's
/// signed key list, not from the server), for exactly the `expected`
/// forwarding and addresses, not past its expiry at `now_secs`, holding a
/// forwarding key named for the forwardee whose every subkey stands in for
/// one of the forwarder's current encryption subkeys. Returns the key
/// (binary, unlocked) to keep as an address key.
pub fn open_activation(
    forwardee_address_secret_key: &[u8],
    forwarder_public_key: &[u8],
    expected: &ActivationTerms,
    now_secs: u64,
    activation: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let opened = mail_key::decrypt(
        forwardee_address_secret_key,
        activation,
        Some(forwarder_public_key),
    )?;
    if !opened.verified {
        return Err(CryptoError::AuthFailed);
    }
    let (terms, key_bytes) = parse_activation(&opened.data)?;
    let canonical = |terms: &ActivationTerms| -> Result<(String, String, String)> {
        Ok((
            terms.forwarding_id.clone(),
            canonical_address(&terms.forwarder_address)?,
            canonical_address(&terms.forwardee_address)?,
        ))
    };
    if canonical(&terms)? != canonical(expected)? {
        return Err(CryptoError::InvalidInput(
            "the activation is for another forwarding".into(),
        ));
    }
    if now_secs > terms.expires_at_secs {
        return Err(CryptoError::InvalidInput(
            "the activation has expired".into(),
        ));
    }
    let key = SignedSecretKey::from_bytes(key_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidInput("not a forwarding key".into()))?;
    if !is_forwarding(&key) {
        return Err(CryptoError::InvalidInput("not a forwarding key".into()));
    }
    let forwardee = canonical_address(&terms.forwardee_address)?;
    if !key
        .details
        .users
        .iter()
        .any(|user| user.id.id() == mail_key::user_id(&forwardee).as_bytes())
    {
        return Err(CryptoError::InvalidInput(
            "the forwarding key is for another address".into(),
        ));
    }
    let forwarder = SignedPublicKey::from_bytes(forwarder_public_key)
        .map_err(|_| CryptoError::InvalidInput("forwarder key does not parse".into()))?;
    let forwarder_subkeys: Vec<Fingerprint> = forwarder
        .public_subkeys
        .iter()
        .filter(|subkey| subkey.key.algorithm().can_encrypt())
        .map(|subkey| subkey.key.fingerprint())
        .collect();
    let stands_in = key.secret_subkeys.iter().all(|subkey| {
        replacement_fingerprint(subkey.key.public_key().public_params())
            .is_some_and(|replaced| forwarder_subkeys.contains(&Fingerprint::V4(replaced)))
    });
    if !stands_in {
        return Err(CryptoError::InvalidInput(
            "the forwarding key isn't for the forwarder's current key".into(),
        ));
    }
    Ok(key_bytes)
}

fn replacement_fingerprint(params: &PublicParams) -> Option<[u8; FINGERPRINT_LEN]> {
    match params {
        PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
            ecdh_kdf_type:
                EcdhKdfType::Replaced {
                    replacement_fingerprint,
                },
            ..
        }) => Some(*replacement_fingerprint),
        _ => None,
    }
}

/// The subkey fingerprints of a forwardee key (public or secret, binary):
/// what the server compares with a forwarding's stored fingerprints when
/// the forwardee uploads the key at accept.
pub fn forwardee_fingerprints(key: &[u8]) -> Result<Vec<[u8; FINGERPRINT_LEN]>> {
    let public = match SignedSecretKey::from_bytes(key) {
        Ok(secret) => {
            if !is_forwarding(&secret) {
                return Err(CryptoError::InvalidInput("not a forwarding key".into()));
            }
            SignedPublicKey::from(secret)
        }
        Err(_) => SignedPublicKey::from_bytes(key)
            .map_err(|_| CryptoError::InvalidInput("key does not parse".into()))?,
    };
    public
        .public_subkeys
        .iter()
        .map(
            |subkey| match (subkey.key.fingerprint(), subkey.key.is_forwardee_key()) {
                (Fingerprint::V4(fingerprint), true) => Ok(fingerprint),
                _ => Err(CryptoError::InvalidInput("not a forwarding key".into())),
            },
        )
        .collect()
}

/// Whether `secret_key` is a forwardee key: every subkey replaces a
/// fingerprint and is bound for forwarded mail.
pub fn is_forwarding_key(secret_key: &[u8]) -> bool {
    SignedSecretKey::from_bytes(secret_key).is_ok_and(|key| is_forwarding(&key))
}

fn is_forwarding(key: &SignedSecretKey) -> bool {
    !key.secret_subkeys.is_empty()
        && key.secret_subkeys.iter().all(|subkey| {
            subkey.key.public_key().is_forwardee_key()
                && subkey
                    .signatures
                    .iter()
                    .any(|signature| signature.key_flags().draft_decrypt_forwarded())
        })
}

/// Decrypts a forwarded message with the forwardee key, and checks its
/// signature against `signer_public_key` when given. Only for messages
/// stored as forwarded (Proton's `FLAG_AUTO_FORWARDEE`).
pub fn decrypt_forwarded(
    forwardee_secret_key: &[u8],
    message: &[u8],
    signer_public_key: Option<&[u8]>,
) -> Result<DecryptedMessage> {
    let key = SignedSecretKey::from_bytes(forwardee_secret_key)
        .map_err(|_| CryptoError::InvalidInput("secret key does not parse".into()))?;
    if !is_forwarding(&key) {
        return Err(CryptoError::InvalidInput("not a forwarding key".into()));
    }
    let parsed = if message.starts_with(b"-----BEGIN PGP MESSAGE-----") {
        Message::from_armor(message).map(|(message, _)| message)
    } else {
        Message::from_bytes(message)
    }
    .map_err(|_| CryptoError::InvalidInput("message does not parse".into()))?;
    let ring = TheRing {
        decrypt_options: DecryptionOptions::new().enable_draft_forwarding(),
        secret_keys: vec![&key],
        ..Default::default()
    };
    let (decrypted, _) = parsed
        .decrypt_the_ring(ring, true)
        .map_err(|_| CryptoError::AuthFailed)?;
    mail_key::read_decrypted(decrypted, signer_public_key)
}

const SEAL_DOMAIN: &[u8] = b"kutup/mail-forwarding/proxy-parameter/v1\0";
const SEAL_NONCE_LEN: usize = 24;

fn seal_aad(
    key_id: u16,
    forwarding_id: &[u8; 16],
    forwarder_fingerprint: &[u8; FINGERPRINT_LEN],
    forwardee_fingerprint: &[u8; FINGERPRINT_LEN],
) -> Vec<u8> {
    [
        SEAL_DOMAIN,
        &key_id.to_be_bytes(),
        forwarding_id,
        forwarder_fingerprint,
        forwardee_fingerprint,
    ]
    .concat()
}

/// The server's sealing of k at rest, under a server key (`key_id` names
/// it): XChaCha20-Poly1305, the AAD binding the key id, the forwarding and
/// both fingerprints, so a sealed k moved to another row doesn't open.
/// Returns `nonce ‖ ciphertext`.
pub fn seal_proxy_parameter(
    server_key: &[u8; 32],
    key_id: u16,
    forwarding_id: &[u8; 16],
    instance: &ProxyInstance,
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    let mut nonce = [0u8; SEAL_NONCE_LEN];
    dryoc::rng::copy_randombytes(&mut nonce);
    let sealed = chacha20poly1305::XChaCha20Poly1305::new(server_key.into())
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            Payload {
                msg: instance.proxy_parameter.as_slice(),
                aad: &seal_aad(
                    key_id,
                    forwarding_id,
                    &instance.forwarder_fingerprint,
                    &instance.forwardee_fingerprint,
                ),
            },
        )
        .map_err(|_| CryptoError::Backend("seal the proxy parameter".into()))?;
    Ok([nonce.as_slice(), &sealed].concat())
}

/// Opens what [`seal_proxy_parameter`] sealed, into the instance it stands
/// for. Fails for another key, forwarding or subkey.
pub fn open_proxy_parameter(
    server_key: &[u8; 32],
    key_id: u16,
    forwarding_id: &[u8; 16],
    forwarder_fingerprint: [u8; FINGERPRINT_LEN],
    forwardee_fingerprint: [u8; FINGERPRINT_LEN],
    sealed: &[u8],
) -> Result<ProxyInstance> {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    if sealed.len() <= SEAL_NONCE_LEN {
        return Err(CryptoError::AuthFailed);
    }
    let (nonce, ciphertext) = sealed.split_at(SEAL_NONCE_LEN);
    let opened = Zeroizing::new(
        chacha20poly1305::XChaCha20Poly1305::new(server_key.into())
            .decrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &seal_aad(
                        key_id,
                        forwarding_id,
                        &forwarder_fingerprint,
                        &forwardee_fingerprint,
                    ),
                },
            )
            .map_err(|_| CryptoError::AuthFailed)?,
    );
    let proxy_parameter: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(ProxyInstance {
        forwarder_fingerprint,
        forwardee_fingerprint,
        proxy_parameter: Zeroizing::new(proxy_parameter),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::armor::Dearmor;
    use std::io::Read as _;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DraftVector {
        recipient_key: String,
        forwardee_key: String,
        encrypted_message: String,
        proxy_parameter: String,
        replacement_fingerprint: String,
        transformed_message: String,
        plaintext: String,
    }

    fn draft() -> DraftVector {
        serde_json::from_str(include_str!(
            "../tests/vectors/mail-forwarding-draft-a3.json"
        ))
        .unwrap()
    }

    fn secret_bytes(armored: &str) -> Vec<u8> {
        SignedSecretKey::from_string(armored)
            .unwrap()
            .0
            .to_bytes()
            .unwrap()
    }

    fn dearmor(armored: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        Dearmor::new(armored.as_bytes())
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    }

    /// The first packet of a binary message and the rest.
    fn first_packet(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut packets = PacketParser::new(BufReader::new(message));
        let first = packets.next().unwrap().unwrap().to_bytes().unwrap();
        (first.clone(), message[first.len()..].to_vec())
    }

    fn fingerprint(armored: &str) -> [u8; FINGERPRINT_LEN] {
        let key = SignedSecretKey::from_string(armored).unwrap().0;
        let Fingerprint::V4(fingerprint) = key.secret_subkeys[0].key.fingerprint() else {
            panic!("v4");
        };
        fingerprint
    }

    /// The draft's §A.3 vectors (shared by rPGP and go-crypto) through our
    /// wrappers: the transform gives the draft's transformed key packet byte
    /// for byte, and the forwardee opens the result.
    #[test]
    fn the_draft_vectors_transform_and_open_through_our_wrappers() {
        let v = draft();
        let forwardee = secret_bytes(&v.forwardee_key);
        assert!(is_forwarding_key(&forwardee));
        assert!(!is_forwarding_key(&secret_bytes(&v.recipient_key)));
        let forwardee_public =
            SignedPublicKey::from(SignedSecretKey::from_bytes(forwardee.as_slice()).unwrap())
                .to_bytes()
                .unwrap();
        let instance = ProxyInstance {
            forwarder_fingerprint: hex::decode(&v.replacement_fingerprint)
                .unwrap()
                .try_into()
                .unwrap(),
            forwardee_fingerprint: fingerprint(&v.forwardee_key),
            proxy_parameter: Zeroizing::new(
                hex::decode(&v.proxy_parameter).unwrap().try_into().unwrap(),
            ),
        };
        assert_eq!(
            instance.forwarder_fingerprint,
            fingerprint(&v.recipient_key)
        );
        assert_eq!(
            forwardee_fingerprints(&forwardee_public).unwrap(),
            vec![instance.forwardee_fingerprint]
        );

        let (key_packet, data) = first_packet(&dearmor(&v.encrypted_message));
        let (expected, expected_data) = first_packet(&dearmor(&v.transformed_message));
        assert_eq!(data, expected_data, "the data packet is left as it is");
        let transformed = transform(&key_packet, &forwardee_public, &instance).unwrap();
        assert_eq!(transformed, expected);

        let message = [transformed, data].concat();
        let opened = decrypt_forwarded(&forwardee, &message, None).unwrap();
        assert_eq!(opened.data.as_slice(), v.plaintext.as_bytes());
        // Only the forwarded path opens it.
        assert!(mail_key::decrypt(&forwardee, &message, None).is_err());
    }

    struct Setup {
        forwarder: mail_key::GeneratedAddressKey,
        forwardee_address_key: mail_key::GeneratedAddressKey,
        material: ForwardingMaterial,
    }

    fn setup() -> Setup {
        let forwarder = mail_key::generate_address_key("alice@kutup.test", 1_760_000_000).unwrap();
        let forwardee_address_key =
            mail_key::generate_address_key("bob@kutup.test", 1_760_000_000).unwrap();
        let material =
            generate_material(&forwarder.secret_key, "bob@kutup.test", 1_760_000_100).unwrap();
        Setup {
            forwarder,
            forwardee_address_key,
            material,
        }
    }

    /// A forwardee key made for a Kutup address key has the draft's shape:
    /// one subkey per encryption subkey, naming it, with the forwarder's KDF
    /// hash and cipher and the forwarding flags.
    #[test]
    fn material_for_an_address_key_has_the_drafts_shape() {
        let Setup {
            forwarder,
            material,
            ..
        } = setup();
        assert_eq!(material.instances.len(), 1);
        assert!(is_forwarding_key(&material.forwardee_secret_key));
        let forwarder = SignedPublicKey::from_bytes(forwarder.public_key.as_slice()).unwrap();
        let subkey = &forwarder.public_subkeys[0];
        let Fingerprint::V4(forwarder_fingerprint) = subkey.key.fingerprint() else {
            panic!("v4");
        };
        assert_eq!(
            material.instances[0].forwarder_fingerprint,
            forwarder_fingerprint
        );
        let forwardee =
            SignedSecretKey::from_bytes(material.forwardee_secret_key.as_slice()).unwrap();
        let sub = &forwardee.secret_subkeys[0];
        assert_eq!(
            replacement_fingerprint(sub.key.public_key().public_params()),
            Some(forwarder_fingerprint)
        );
        let (
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
                hash: forwarder_hash,
                alg_sym: forwarder_sym,
                ..
            }),
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { hash, alg_sym, .. }),
        ) = (
            subkey.key.public_params(),
            sub.key.public_key().public_params(),
        )
        else {
            panic!("ECDH");
        };
        assert_eq!((hash, alg_sym), (forwarder_hash, forwarder_sym));
        let flags = sub.signatures[0].key_flags();
        assert!(flags.draft_decrypt_forwarded() && flags.shared());
        assert!(!flags.encrypt_comms() && !flags.encrypt_storage());
        assert_eq!(
            forwardee_fingerprints(&material.forwardee_public_key).unwrap(),
            vec![material.instances[0].forwardee_fingerprint]
        );
    }

    /// pmcrypto's fixture with SHA-512 / AES-256 KDF parameters: copied over.
    #[test]
    fn the_kdf_hash_and_cipher_are_the_forwarders() {
        const BOB: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZR5v2hYJKwYBBAHaRw8BAQdANGEppfpOvm+WZ2q2GZxRSo8FR3eIgJxC
Caeey6SO5KUAAP9Ipt8zxY7LnnNBGzlgcGiBA4qQNBZ6VecLdNgShl8AEg35
zQ48dGVzdEB0ZXN0Lml0PsKMBBAWCgA+BYJlH8uEBAsJBwgJkHXYKIC+P8wd
AxUICgQWAAIBAhkBApsDAh4BFiEEhJYaMQwPxUSp5y0BddgogL4/zB0AAL4i
AP9UkQvVedKAxiNvr4mGQOLRlOEHw1sZjil3wm6I0mcbnQD/e5zWQj7ToEOL
Pq5wc5guttKvMi5vXO+N7SjFdV7KTwPHXQRlHm/aEgorBgEEAZdVAQUBAQdA
jNr0MP98DXFIB4Ge1ydzGV0GW2W+OrVvVSioj7p/PU0DAQoJAAD/bZITV/Pf
5Xz6Btg820PoeZY8AseQT0vOkJ5R3pOW8KgS38J4BBgWCAAqBYJlH8uECZB1
2CiAvj/MHQKbDBYhBISWGjEMD8VEqectAXXYKIC+P8wdAACdTgEA6vGgdMfI
S6CP/U6uXws66mIgL7CmFVMKqLLJaASqcQwA/isDrUVgBnhkwF+IPZvEUZY3
P0GnopWOyFNNFWK77LQN
=Lyee
-----END PGP PRIVATE KEY BLOCK-----";
        let material =
            generate_material(&secret_bytes(BOB), "charlie@kutup.test", 1_760_000_000).unwrap();
        let forwardee =
            SignedSecretKey::from_bytes(material.forwardee_secret_key.as_slice()).unwrap();
        let PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { hash, alg_sym, .. }) =
            forwardee.secret_subkeys[0].key.public_key().public_params()
        else {
            panic!("ECDH");
        };
        assert_eq!(*hash, pgp::crypto::hash::HashAlgorithm::Sha512);
        assert_eq!(*alg_sym, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
    }

    /// End to end on Kutup keys: a message from a third person to the
    /// forwarder, and one the server sealed on arrival, both reach the
    /// forwardee through the transform alone, the data packet unchanged.
    #[test]
    fn kutup_mail_reaches_the_forwardee_through_the_transform() {
        let Setup {
            forwarder,
            material,
            ..
        } = setup();
        let carol = mail_key::generate_address_key("carol@kutup.test", 1_760_000_000).unwrap();
        let sent = mail_key::encrypt_split(
            &[forwarder.public_key.as_slice()],
            &carol.secret_key,
            b"from carol",
        )
        .unwrap();
        let transformed = transform(
            &sent.key_packets[0],
            &material.forwardee_public_key,
            &material.instances[0],
        )
        .unwrap();
        assert_ne!(transformed, sent.key_packets[0]);
        let forwarded = [transformed, sent.data_packet.clone()].concat();
        let opened = decrypt_forwarded(
            &material.forwardee_secret_key,
            &forwarded,
            Some(&carol.public_key),
        )
        .unwrap();
        assert_eq!(opened.data.as_slice(), b"from carol");
        assert!(opened.verified);
        // The forwarder still opens their own copy.
        let own = [sent.key_packets[0].clone(), sent.data_packet].concat();
        assert!(mail_key::decrypt(&forwarder.secret_key, &own, None).is_ok());

        // Sealed on arrival (outside mail).
        let arrived = mail_key::encrypt_binary(&forwarder.public_key, b"from outside").unwrap();
        let (key_packet, data) = first_packet(&arrived);
        let transformed = transform(
            &key_packet,
            &material.forwardee_public_key,
            &material.instances[0],
        )
        .unwrap();
        let opened = decrypt_forwarded(
            &material.forwardee_secret_key,
            &[transformed, data].concat(),
            None,
        )
        .unwrap();
        assert_eq!(opened.data.as_slice(), b"from outside");
    }

    /// The server's step refuses what isn't a key packet to the forwarder's
    /// subkey, or an instance for another forwardee subkey.
    #[test]
    fn the_transform_refuses_other_keys() {
        let Setup {
            forwarder,
            forwardee_address_key,
            material,
        } = setup();
        let to_bob = mail_key::encrypt_binary(&forwardee_address_key.public_key, b"x").unwrap();
        let (key_packet, _) = first_packet(&to_bob);
        assert!(transform(
            &key_packet,
            &material.forwardee_public_key,
            &material.instances[0]
        )
        .is_err());
        let to_alice = mail_key::encrypt_binary(&forwarder.public_key, b"x").unwrap();
        let (key_packet, data) = first_packet(&to_alice);
        assert!(transform(
            &data,
            &material.forwardee_public_key,
            &material.instances[0]
        )
        .is_err());
        let wrong = ProxyInstance {
            forwardee_fingerprint: [0u8; FINGERPRINT_LEN],
            ..ProxyInstance {
                forwarder_fingerprint: material.instances[0].forwarder_fingerprint,
                forwardee_fingerprint: material.instances[0].forwardee_fingerprint,
                proxy_parameter: material.instances[0].proxy_parameter.clone(),
            }
        };
        assert!(transform(&key_packet, &material.forwardee_public_key, &wrong).is_err());
    }

    fn terms() -> ActivationTerms {
        ActivationTerms {
            forwarding_id: "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607".into(),
            forwarder_address: "alice@kutup.test".into(),
            forwardee_address: "bob@kutup.test".into(),
            expires_at_secs: 1_760_604_800,
        }
    }

    /// The activation opens only for its forwarding, before its expiry,
    /// signed by the forwarder's key, holding a key for the forwarder's
    /// current subkey.
    #[test]
    fn an_activation_opens_only_for_its_forwarding() {
        let Setup {
            forwarder,
            forwardee_address_key: bob,
            material,
        } = setup();
        let sealed =
            seal_activation(&bob.public_key, &forwarder.secret_key, &terms(), &material).unwrap();
        let open = |expected: &ActivationTerms, now: u64, signer: &[u8]| {
            open_activation(&bob.secret_key, signer, expected, now, sealed.as_bytes())
        };
        let key = open(&terms(), 1_760_000_200, &forwarder.public_key).unwrap();
        assert_eq!(key.as_slice(), material.forwardee_secret_key.as_slice());

        let other_id = ActivationTerms {
            forwarding_id: "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d".into(),
            ..terms()
        };
        assert!(open(&other_id, 1_760_000_200, &forwarder.public_key).is_err());
        let other_forwarder = ActivationTerms {
            forwarder_address: "mallory@kutup.test".into(),
            ..terms()
        };
        assert!(open(&other_forwarder, 1_760_000_200, &forwarder.public_key).is_err());
        assert!(
            open(&terms(), 1_760_604_801, &forwarder.public_key).is_err(),
            "expired"
        );
        // Signed by someone else, or checked against a key it doesn't stand in for.
        let mallory = mail_key::generate_address_key("mallory@kutup.test", 1_760_000_000).unwrap();
        assert!(open(&terms(), 1_760_000_200, &mallory.public_key).is_err());
        let forged =
            seal_activation(&bob.public_key, &mallory.secret_key, &terms(), &material).unwrap();
        assert!(open_activation(
            &bob.secret_key,
            &mallory.public_key,
            &terms(),
            1_760_000_200,
            forged.as_bytes()
        )
        .is_err());
        // For another address than the key was made for.
        let for_carol = ActivationTerms {
            forwardee_address: "carol@kutup.test".into(),
            ..terms()
        };
        let carol = mail_key::generate_address_key("carol@kutup.test", 1_760_000_000).unwrap();
        let misnamed = seal_activation(
            &carol.public_key,
            &forwarder.secret_key,
            &for_carol,
            &material,
        )
        .unwrap();
        assert!(open_activation(
            &carol.secret_key,
            &forwarder.public_key,
            &for_carol,
            1_760_000_200,
            misnamed.as_bytes()
        )
        .is_err());
    }

    #[test]
    fn a_truncated_activation_does_not_parse() {
        let plain = activation_plaintext(&terms(), b"key").unwrap();
        assert_eq!(parse_activation(&plain).unwrap().0, terms());
        for len in 0..plain.len() {
            assert!(parse_activation(&plain[..len]).is_err(), "{len}");
        }
        assert!(parse_activation(&[plain.as_slice(), b"x"].concat()).is_err());
    }

    /// k at rest opens only under its server key, for its forwarding and
    /// subkeys.
    #[test]
    fn a_sealed_proxy_parameter_opens_only_where_it_was_sealed() {
        let instance = ProxyInstance {
            forwarder_fingerprint: [1u8; FINGERPRINT_LEN],
            forwardee_fingerprint: [2u8; FINGERPRINT_LEN],
            proxy_parameter: Zeroizing::new([7u8; 32]),
        };
        let (key, other_key) = ([9u8; 32], [8u8; 32]);
        let forwarding = [3u8; 16];
        let sealed = seal_proxy_parameter(&key, 1, &forwarding, &instance).unwrap();
        let open = |key: &[u8; 32], id: u16, forwarding: &[u8; 16], fpr, fpe| {
            open_proxy_parameter(key, id, forwarding, fpr, fpe, &sealed)
        };
        let opened = open(&key, 1, &forwarding, [1u8; 20], [2u8; 20]).unwrap();
        assert_eq!(*opened.proxy_parameter, [7u8; 32]);
        assert!(open(&other_key, 1, &forwarding, [1u8; 20], [2u8; 20]).is_err());
        assert!(open(&key, 2, &forwarding, [1u8; 20], [2u8; 20]).is_err());
        assert!(open(&key, 1, &[4u8; 16], [1u8; 20], [2u8; 20]).is_err());
        assert!(open(&key, 1, &forwarding, [2u8; 20], [1u8; 20]).is_err());
        assert!(
            open_proxy_parameter(&key, 1, &forwarding, [1u8; 20], [2u8; 20], &sealed[..24])
                .is_err()
        );
    }
}
