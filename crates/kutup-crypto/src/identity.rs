//! Deterministic, purpose-separated V1 account identity keys.
//!
//! The recoverable account master key is the only root. Independent HKDF
//! labels derive an account self-authority, a Drive HPKE/X25519 key and a
//! Drive share-signing Ed25519 key. Public keys may appear together in an
//! account manifest; private keys and signing purposes are never shared.

use dryoc::classic::crypto_box::crypto_box_seed_keypair;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::{CryptoError, Result};

const ACCOUNT_IDENTITY_SALT: &[u8] = b"kutup/account-identity/v1\0";
const SELF_AUTHORITY_INFO: &[u8] = b"kutup/account-identity/self-authority/v1\0";
const DRIVE_HPKE_INFO: &[u8] = b"kutup/account-identity/drive-hpke-x25519/v1\0";
const DRIVE_SIGNING_INFO: &[u8] = b"kutup/account-identity/drive-share-signing-ed25519/v1\0";
const INCARNATION_DOMAIN: &[u8] = b"kutup/account-incarnation/v1\0";

/// Complete V1 account identity derived locally from the master key.
pub struct AccountIdentityKeysV1 {
    authority: SigningKey,
    drive_hpke_public: [u8; 32],
    drive_hpke_private: Zeroizing<[u8; 32]>,
    drive_signing: SigningKey,
}

impl AccountIdentityKeysV1 {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(ACCOUNT_IDENTITY_SALT), master_key);
        let mut authority_seed = Zeroizing::new([0u8; 32]);
        let mut hpke_seed = Zeroizing::new([0u8; 32]);
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        hkdf.expand(SELF_AUTHORITY_INFO, authority_seed.as_mut_slice())
            .map_err(|_| CryptoError::Backend("account authority HKDF expand".into()))?;
        hkdf.expand(DRIVE_HPKE_INFO, hpke_seed.as_mut_slice())
            .map_err(|_| CryptoError::Backend("Drive HPKE HKDF expand".into()))?;
        hkdf.expand(DRIVE_SIGNING_INFO, signing_seed.as_mut_slice())
            .map_err(|_| CryptoError::Backend("Drive signing HKDF expand".into()))?;

        let authority = SigningKey::from_bytes(&authority_seed);
        let (drive_hpke_public, mut drive_hpke_private) =
            crypto_box_seed_keypair(hpke_seed.as_slice());
        let drive_signing = SigningKey::from_bytes(&signing_seed);
        let drive_hpke_private = Zeroizing::new({
            let private = drive_hpke_private;
            drive_hpke_private.zeroize();
            private
        });

        Ok(Self {
            authority,
            drive_hpke_public,
            drive_hpke_private,
            drive_signing,
        })
    }

    pub fn authority_signing_key(&self) -> &SigningKey {
        &self.authority
    }

    pub fn authority_public_key(&self) -> [u8; 32] {
        self.authority.verifying_key().to_bytes()
    }

    pub fn authority_key_id(&self) -> String {
        authority_key_id_from_public(&self.authority_public_key())
    }

    /// Stable identity for one cryptographic lifetime of the human-readable
    /// account address. Administrative wipe derives a different value because
    /// it creates a new master key and authority.
    pub fn incarnation_id(&self) -> String {
        incarnation_id_from_authority_public(&self.authority_public_key())
    }

    pub fn drive_hpke_public_key(&self) -> [u8; 32] {
        self.drive_hpke_public
    }

    pub fn drive_hpke_private_key(&self) -> &[u8; 32] {
        &self.drive_hpke_private
    }

    pub fn drive_signing_key(&self) -> &SigningKey {
        &self.drive_signing
    }

    pub fn drive_signing_public_key(&self) -> [u8; 32] {
        self.drive_signing.verifying_key().to_bytes()
    }
}

pub fn authority_key_id_from_public(authority_public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(authority_public_key))
}

pub fn incarnation_id_from_authority_public(authority_public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INCARNATION_DOMAIN);
    hasher.update(authority_public_key);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_deterministic_and_purpose_separated() {
        let first = AccountIdentityKeysV1::derive(&[7u8; 32]).unwrap();
        let second = AccountIdentityKeysV1::derive(&[7u8; 32]).unwrap();
        assert_eq!(first.authority_public_key(), second.authority_public_key());
        assert_eq!(first.incarnation_id(), second.incarnation_id());
        assert_eq!(
            first.drive_hpke_public_key(),
            second.drive_hpke_public_key()
        );
        assert_eq!(
            first.drive_signing_public_key(),
            second.drive_signing_public_key()
        );
        assert_ne!(
            first.authority_public_key(),
            first.drive_signing_public_key()
        );
        assert_ne!(
            first.drive_hpke_private_key().as_slice(),
            first.drive_signing_key().to_bytes().as_slice()
        );
    }

    #[test]
    fn a_new_master_key_is_a_new_incarnation() {
        let first = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        let second = AccountIdentityKeysV1::derive(&[2u8; 32]).unwrap();
        assert_ne!(first.authority_key_id(), second.authority_key_id());
        assert_ne!(first.incarnation_id(), second.incarnation_id());
    }
}
