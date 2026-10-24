use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

use super::Suite;
use crate::error::{CryptoError, Result};

/// A signing key, from its seed.
#[derive(Clone)]
pub struct SigningKey {
    suite: Suite,
    key: ed25519_dalek::SigningKey,
}

impl SigningKey {
    pub fn from_seed(suite: Suite, seed: &[u8; 32]) -> Self {
        match suite {
            Suite::V1 => Self {
                suite,
                key: ed25519_dalek::SigningKey::from_bytes(seed),
            },
        }
    }

    /// A new key and its seed (to keep, sealed).
    pub fn generate(suite: Suite) -> (Self, Zeroizing<[u8; 32]>) {
        let seed = super::random_key();
        (Self::from_seed(suite, &seed), seed)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).to_bytes().to_vec()
    }

    /// A signature as a fixed array, for a format that fixes its length
    /// (the suite's `signature_len`).
    pub fn sign_array<const N: usize>(&self, message: &[u8]) -> [u8; N] {
        self.sign(message)
            .try_into()
            .expect("the suite's signature length")
    }

    /// The seed this key was made from (to seal and keep).
    pub fn seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.key.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            suite: self.suite,
            key: self.key.verifying_key(),
        }
    }
}

/// A verifying key; it checks strictly (`SuiteParams::signature_verification`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    suite: Suite,
    key: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self> {
        match suite {
            Suite::V1 => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidLength {
                    expected: 32,
                    got: bytes.len(),
                })?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| CryptoError::InvalidInput("verifying key".into()))?;
                Ok(Self { suite, key })
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// The key as a fixed array (the suite's `verifying_key_len`).
    pub fn to_array<const N: usize>(&self) -> [u8; N] {
        self.to_bytes()
            .try_into()
            .expect("the suite's verifying key length")
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self.suite {
            Suite::V1 => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| CryptoError::AuthFailed)?;
                self.key
                    .verify_strict(message, &signature)
                    .map_err(|_| CryptoError::AuthFailed)
            }
        }
    }
}
