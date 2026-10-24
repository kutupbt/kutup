//! The provisioning cipher: how a device of an account hands the account's
//! Chat identity to a new device it links (docs/plans/account-identity-key.md,
//! "Linking a device"). Signal's `ProvisioningCipher` exactly, with Kutup's
//! HKDF info string so neither protocol ever accepts the other's messages:
//!
//! - the new device makes an ephemeral X25519 key pair and shows the public
//!   key (in the `kutup://link` code);
//! - the linking device makes its own ephemeral key pair, agrees
//!   `X25519(its private, the new device's public)`, and derives 64 bytes
//!   with `HKDF-SHA256(salt = 32 zero bytes, info = "Kutup Provisioning
//!   Message v1")`: an AES-256 key, then an HMAC-SHA256 key;
//! - the body is `0x01 ‖ IV(16) ‖ AES-256-CBC/PKCS7(message) ‖
//!   HMAC-SHA256(version ‖ IV ‖ ciphertext)`, sent with the linking device's
//!   ephemeral public key;
//! - the new device checks the MAC, in constant time, before it decrypts
//!   anything.
//!
//! Public keys are libsignal's serialized form: the `0x05` type byte, then the
//! 32-byte X25519 key.

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use dryoc::classic::crypto_core::{crypto_scalarmult, crypto_scalarmult_base};
// Adapter: Signal's ProvisioningCipher.
#[allow(clippy::disallowed_types)]
use hkdf::Hkdf;
// Adapter: Signal's ProvisioningCipher.
#[allow(clippy::disallowed_types)]
use hmac::{Hmac, Mac};
// Adapter: Signal's ProvisioningCipher.
#[allow(clippy::disallowed_types)]
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Kutup's HKDF info; Signal's is `TextSecure Provisioning Message`.
pub const INFO: &[u8] = b"Kutup Provisioning Message v1";
pub const VERSION: u8 = 1;
/// libsignal's `DjbECPublicKey` type byte.
pub const KEY_TYPE: u8 = 0x05;
pub const PUBLIC_KEY_LEN: usize = 33;
pub const IV_LEN: usize = 16;
pub const MAC_LEN: usize = 32;
/// Version, IV, one cipher block, MAC.
pub const MIN_BODY_LEN: usize = 1 + IV_LEN + 16 + MAC_LEN;

type Encryptor = cbc::Encryptor<Aes256>;
type Decryptor = cbc::Decryptor<Aes256>;

/// The new device's ephemeral key pair, for one provisioning socket.
pub struct ProvisioningKeyPair {
    private: Zeroizing<[u8; 32]>,
    public: [u8; PUBLIC_KEY_LEN],
}

impl ProvisioningKeyPair {
    pub fn generate() -> Self {
        let mut private = Zeroizing::new([0u8; 32]);
        crate::primitives::random(private.as_mut());
        Self::from_private(*private)
    }

    /// From a fixed private key (vectors; a stored socket's key).
    pub fn from_private(private: [u8; 32]) -> Self {
        let private = Zeroizing::new(private);
        Self {
            public: public_key(&private),
            private,
        }
    }

    /// libsignal-serialized: `0x05 ‖ X25519 public key`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// Open a body sent with the linking device's ephemeral `sender_public`.
    pub fn open(&self, sender_public: &[u8], body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open_with_info(INFO, &self.private, sender_public, body)
    }
}

/// A sealed provisioning message: the linking device's ephemeral public key
/// and the body.
pub struct Sealed {
    pub sender_public: [u8; PUBLIC_KEY_LEN],
    pub body: Vec<u8>,
}

/// Seal `message` to the new device's `recipient_public` (from its link code),
/// with a fresh ephemeral key and IV.
pub fn seal(recipient_public: &[u8], message: &[u8]) -> Result<Sealed> {
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    crate::primitives::random(ephemeral.as_mut());
    let mut iv = [0u8; IV_LEN];
    crate::primitives::random(&mut iv);
    seal_with_info(INFO, &ephemeral, &iv, recipient_public, message)
}

// Adapter: Signal's ProvisioningCipher (X25519).
#[allow(clippy::disallowed_methods)]
fn public_key(private: &[u8; 32]) -> [u8; PUBLIC_KEY_LEN] {
    let mut point = [0u8; 32];
    crypto_scalarmult_base(&mut point, private);
    let mut public = [0u8; PUBLIC_KEY_LEN];
    public[0] = KEY_TYPE;
    public[1..].copy_from_slice(&point);
    public
}

fn decode_public(public: &[u8]) -> Result<[u8; 32]> {
    if public.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: PUBLIC_KEY_LEN,
            got: public.len(),
        });
    }
    if public[0] != KEY_TYPE {
        return Err(CryptoError::InvalidInput(
            "provisioning key is not a Curve25519 key".into(),
        ));
    }
    Ok(public[1..].try_into().expect("length checked"))
}

/// The AES key and the MAC key from the agreement.
// Adapter: Signal's ProvisioningCipher (X25519, HKDF-SHA256).
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
fn derive(info: &[u8], private: &[u8; 32], public: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let point = decode_public(public)?;
    let mut shared = Zeroizing::new([0u8; 32]);
    crypto_scalarmult(&mut shared, private, &point);
    // A low-order point gives the all-zero secret: refused, as libsodium's
    // crypto_scalarmult refuses it.
    if shared.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::InvalidInput(
            "provisioning key agreement failed".into(),
        ));
    }
    let mut keys = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared.as_ref())
        .expand(info, keys.as_mut())
        .map_err(|_| CryptoError::Backend("provisioning HKDF".into()))?;
    Ok(keys)
}

// Adapter: Signal's ProvisioningCipher (HMAC-SHA256).
#[allow(clippy::disallowed_types)]
fn mac(key: &[u8], data: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac
}

fn seal_with_info(
    info: &[u8],
    ephemeral: &[u8; 32],
    iv: &[u8; IV_LEN],
    recipient_public: &[u8],
    message: &[u8],
) -> Result<Sealed> {
    let keys = derive(info, ephemeral, recipient_public)?;
    let ciphertext =
        Encryptor::new(keys[..32].into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(message);
    let mut body = Vec::with_capacity(1 + IV_LEN + ciphertext.len() + MAC_LEN);
    body.push(VERSION);
    body.extend_from_slice(iv);
    body.extend_from_slice(&ciphertext);
    let tag = mac(&keys[32..], &body).finalize().into_bytes();
    body.extend_from_slice(&tag);
    Ok(Sealed {
        sender_public: public_key(ephemeral),
        body,
    })
}

fn open_with_info(
    info: &[u8],
    private: &[u8; 32],
    sender_public: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if body.len() < MIN_BODY_LEN || !(body.len() - 1 - IV_LEN - MAC_LEN).is_multiple_of(16) {
        return Err(CryptoError::TooShort);
    }
    if body[0] != VERSION {
        return Err(CryptoError::InvalidInput(
            "unsupported provisioning version".into(),
        ));
    }
    let keys = derive(info, private, sender_public)?;
    let (signed, tag) = body.split_at(body.len() - MAC_LEN);
    mac(&keys[32..], signed)
        .verify_slice(tag)
        .map_err(|_| CryptoError::AuthFailed)?;
    let iv: [u8; IV_LEN] = signed[1..1 + IV_LEN].try_into().expect("length checked");
    Decryptor::new(keys[..32].into(), (&iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&signed[1 + IV_LEN..])
        .map(Zeroizing::new)
        // Authenticated, so bad padding means a sender bug, not an oracle.
        .map_err(|_| CryptoError::AuthFailed)
}

/// The construction with a given info string, fixed ephemeral key and IV:
/// for the vectors, which also check it against Signal's own
/// (`TextSecure Provisioning Message`).
#[cfg(any(test, feature = "test-vectors"))]
pub mod vectors {
    use super::*;

    pub fn seal_with(
        info: &[u8],
        ephemeral: &[u8; 32],
        iv: &[u8; IV_LEN],
        recipient_public: &[u8],
        message: &[u8],
    ) -> Result<Sealed> {
        seal_with_info(info, ephemeral, iv, recipient_public, message)
    }

    pub fn open_with(
        info: &[u8],
        private: &[u8; 32],
        sender_public: &[u8],
        body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        open_with_info(info, private, sender_public, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let device = ProvisioningKeyPair::generate();
        let sealed = seal(&device.public_key(), b"the account identity").unwrap();
        assert_eq!(
            device
                .open(&sealed.sender_public, &sealed.body)
                .unwrap()
                .as_slice(),
            b"the account identity"
        );

        for index in [0, 1, sealed.body.len() / 2, sealed.body.len() - 1] {
            let mut body = sealed.body.clone();
            body[index] ^= 1;
            assert!(
                device.open(&sealed.sender_public, &body).is_err(),
                "{index}"
            );
        }
        let other = ProvisioningKeyPair::generate();
        assert!(matches!(
            other.open(&sealed.sender_public, &sealed.body),
            Err(CryptoError::AuthFailed)
        ));
        assert!(device.open(&other.public_key(), &sealed.body).is_err());
        assert!(device
            .open(&sealed.sender_public, &sealed.body[..MIN_BODY_LEN - 1])
            .is_err());
        assert!(device
            .open(&sealed.sender_public, &sealed.body[..sealed.body.len() - 1])
            .is_err());
    }

    #[test]
    fn refuses_other_info_and_bad_keys() {
        let device = ProvisioningKeyPair::from_private([1; 32]);
        let signal = vectors::seal_with(
            b"TextSecure Provisioning Message",
            &[2; 32],
            &[3; 16],
            &device.public_key(),
            b"hello",
        )
        .unwrap();
        assert!(matches!(
            device.open(&signal.sender_public, &signal.body),
            Err(CryptoError::AuthFailed)
        ));

        let mut untyped = device.public_key();
        untyped[0] = 0;
        assert!(seal(&untyped, b"x").is_err());
        assert!(seal(&device.public_key()[1..], b"x").is_err());
        // The identity point: the agreement would be all zero.
        let mut low_order = [0u8; PUBLIC_KEY_LEN];
        low_order[0] = KEY_TYPE;
        assert!(seal(&low_order, b"x").is_err());
    }

    #[test]
    fn empty_message_is_one_block() {
        let device = ProvisioningKeyPair::from_private([1; 32]);
        let sealed =
            vectors::seal_with(INFO, &[2; 32], &[3; 16], &device.public_key(), b"").unwrap();
        assert_eq!(sealed.body.len(), MIN_BODY_LEN);
        assert!(device
            .open(&sealed.sender_public, &sealed.body)
            .unwrap()
            .is_empty());
    }
}
