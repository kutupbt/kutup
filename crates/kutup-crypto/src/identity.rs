//! Deterministic, purpose-separated account identity keys.
//!
//! The recoverable account master key is the only root. Independent HKDF
//! labels derive an account self-authority, a Drive HPKE key and a Drive
//! share-signing Ed25519 key. Public keys may appear together in an account
//! manifest; private keys and signing purposes are never shared.
//!
//! The Drive HPKE key is X-Wing (identity suite 2, docs/plans/pq-shares.md):
//! its private key is the 32-byte X-Wing seed the HKDF gives, its public key
//! the 1216-byte encapsulation key derived from that seed.

use crate::primitives::{hash, Hasher, Kdf, SigningKey, Suite};
use zeroize::Zeroizing;

use crate::hpke_xwing;

use crate::error::{CryptoError, Result};

const ACCOUNT_IDENTITY_SALT: &[u8] = crate::labels::ACCOUNT_IDENTITY_V1;
const SELF_AUTHORITY_INFO: &[u8] = crate::labels::ACCOUNT_IDENTITY_SELF_AUTHORITY_V1;
const DRIVE_HPKE_INFO: &[u8] = crate::labels::ACCOUNT_IDENTITY_DRIVE_HPKE_XWING_V1;
const DRIVE_SIGNING_INFO: &[u8] = crate::labels::ACCOUNT_IDENTITY_DRIVE_SHARE_SIGNING_ED25519_V1;
const INCARNATION_DOMAIN: &[u8] = crate::labels::ACCOUNT_INCARNATION_V1;

/// The account identity suite these keys are: 2, an X-Wing Drive key with
/// Ed25519 signing keys.
pub const IDENTITY_SUITE: u16 = 2;

/// Complete account identity derived locally from the master key.
pub struct AccountIdentityKeysV1 {
    authority: SigningKey,
    drive_hpke_public: [u8; hpke_xwing::PUBLIC_KEY_LEN],
    drive_hpke_private: Zeroizing<[u8; hpke_xwing::SEED_LEN]>,
    drive_signing: SigningKey,
}

impl AccountIdentityKeysV1 {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let hkdf = Kdf::new(Suite::V1, ACCOUNT_IDENTITY_SALT, master_key);
        let mut authority_seed = Zeroizing::new([0u8; 32]);
        let mut hpke_seed = Zeroizing::new([0u8; 32]);
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        hkdf.expand(SELF_AUTHORITY_INFO, authority_seed.as_mut_slice())
            .map_err(|_| CryptoError::Backend("account authority HKDF expand".into()))?;
        hkdf.expand(DRIVE_HPKE_INFO, hpke_seed.as_mut_slice())
            .map_err(|_| CryptoError::Backend("Drive HPKE HKDF expand".into()))?;
        hkdf.expand(DRIVE_SIGNING_INFO, signing_seed.as_mut_slice())
            .map_err(|_| CryptoError::Backend("Drive signing HKDF expand".into()))?;

        let authority = SigningKey::from_seed(Suite::V1, &authority_seed);
        let drive_hpke_public = hpke_xwing::public_key(&hpke_seed);
        let drive_signing = SigningKey::from_seed(Suite::V1, &signing_seed);

        Ok(Self {
            authority,
            drive_hpke_public,
            drive_hpke_private: hpke_seed,
            drive_signing,
        })
    }

    pub fn authority_signing_key(&self) -> &SigningKey {
        &self.authority
    }

    pub fn authority_public_key(&self) -> [u8; 32] {
        self.authority.verifying_key().to_array()
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

    /// The 1216-byte X-Wing encapsulation key.
    pub fn drive_hpke_public_key(&self) -> [u8; hpke_xwing::PUBLIC_KEY_LEN] {
        self.drive_hpke_public
    }

    /// The 32-byte X-Wing seed.
    pub fn drive_hpke_private_key(&self) -> &[u8; hpke_xwing::SEED_LEN] {
        &self.drive_hpke_private
    }

    pub fn drive_signing_key(&self) -> &SigningKey {
        &self.drive_signing
    }

    pub fn drive_signing_public_key(&self) -> [u8; 32] {
        self.drive_signing.verifying_key().to_array()
    }
}

pub fn authority_key_id_from_public(authority_public_key: &[u8; 32]) -> String {
    hex::encode(hash(Suite::V1, authority_public_key))
}

pub fn incarnation_id_from_authority_public(authority_public_key: &[u8; 32]) -> String {
    let mut hasher = Hasher::new(Suite::V1);
    hasher.update(INCARNATION_DOMAIN);
    hasher.update(authority_public_key);
    hex::encode(hasher.finish())
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
            first.drive_signing_key().seed().as_slice()
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
