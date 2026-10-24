use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use super::Suite;
use crate::error::{CryptoError, Result};

/// An AEAD key, as long as the suite's (`SuiteParams::aead_key_len`).
pub type AeadKey = Zeroizing<[u8; 32]>;

/// A suite's AEAD under one key, resolved once: what a stream of blocks
/// seals and opens with.
pub struct Aead {
    suite: Suite,
    cipher: Cipher,
}

enum Cipher {
    XChaCha(XChaCha20Poly1305),
}

impl Aead {
    pub fn new(suite: Suite, key: &[u8; 32]) -> Self {
        let cipher = match suite {
            Suite::V1 => Cipher::XChaCha(XChaCha20Poly1305::new(key.into())),
        };
        Self { suite, cipher }
    }

    pub const fn nonce_len(&self) -> usize {
        self.suite.params().aead_nonce_len
    }

    pub const fn tag_len(&self) -> usize {
        self.suite.params().aead_tag_len
    }

    fn check_nonce(&self, nonce: &[u8]) -> Result<()> {
        if nonce.len() != self.nonce_len() {
            return Err(CryptoError::InvalidLength {
                expected: self.nonce_len(),
                got: nonce.len(),
            });
        }
        Ok(())
    }

    /// `ciphertext ‖ tag` of `plaintext` under `nonce`, bound to `aad`.
    pub fn seal_with_nonce(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.check_nonce(nonce)?;
        match &self.cipher {
            Cipher::XChaCha(c) => c
                .encrypt(
                    nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Backend("aead seal".into())),
        }
    }

    /// `nonce ‖ ciphertext ‖ tag`, under a fresh random nonce.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; self.nonce_len()];
        super::random(&mut nonce);
        let sealed = self.seal_with_nonce(&nonce, aad, plaintext)?;
        nonce.extend_from_slice(&sealed);
        Ok(nonce)
    }

    /// The plaintext of `ciphertext ‖ tag` under `nonce` and `aad`.
    pub fn open_with_nonce(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_nonce(nonce)?;
        if ciphertext.len() < self.tag_len() {
            return Err(CryptoError::TooShort);
        }
        match &self.cipher {
            Cipher::XChaCha(c) => c
                .decrypt(
                    nonce.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| CryptoError::AuthFailed),
        }
    }

    /// The plaintext of `nonce ‖ ciphertext ‖ tag` (from [`Aead::seal`]).
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < self.nonce_len() + self.tag_len() {
            return Err(CryptoError::TooShort);
        }
        let (nonce, ciphertext) = sealed.split_at(self.nonce_len());
        self.open_with_nonce(nonce, aad, ciphertext)
    }
}
