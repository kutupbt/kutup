//! XSalsa20-Poly1305 secretbox — mirrors `cmd/kutup/internal/crypto/secretbox.go`
//! (libsodium `crypto_secretbox_easy` / `_open_easy`, via NaCl in Go).
//!
//! Used for the master key, private key, collection keys, file keys, and
//! encrypted metadata. Wire shape: a random 24-byte nonce alongside the
//! ciphertext (`16-byte MAC` prepended to the encrypted message, libsodium-style).

use base64::Engine;
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_easy, crypto_secretbox_open_easy, Key, Nonce,
};
use dryoc::constants::{CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES};
use dryoc::rng::copy_randombytes;

use crate::error::{CryptoError, Result};

/// Secretbox key length (32 bytes).
pub const KEY_BYTES: usize = std::mem::size_of::<Key>();
/// Secretbox nonce length (24 bytes).
pub const NONCE_BYTES: usize = CRYPTO_SECRETBOX_NONCEBYTES;
/// Secretbox MAC length (16 bytes).
pub const MAC_BYTES: usize = CRYPTO_SECRETBOX_MACBYTES;

fn key_array(key: &[u8]) -> Result<Key> {
    key.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: KEY_BYTES,
        got: key.len(),
    })
}

/// Encrypts `plaintext` with `key` using XSalsa20-Poly1305.
///
/// Returns `(ciphertext, nonce)` where `nonce` is a freshly generated 24-byte
/// value. Compatible with libsodium `crypto_secretbox_easy`.
/// Mirrors `SecretBoxSeal`.
pub fn seal(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_BYTES])> {
    let k = key_array(key)?;
    let mut nonce: Nonce = [0u8; NONCE_BYTES];
    copy_randombytes(&mut nonce);

    let mut ciphertext = vec![0u8; plaintext.len() + MAC_BYTES];
    crypto_secretbox_easy(&mut ciphertext, plaintext, &nonce, &k)
        .map_err(|e| CryptoError::Backend(format!("secretbox seal: {e}")))?;
    Ok((ciphertext, nonce))
}

/// Encrypts `plaintext` with `key` and the caller-supplied `nonce`.
///
/// Exposed primarily for known-answer tests / vector generation where a fixed
/// nonce is required. Production code should prefer [`seal`].
pub fn seal_with_nonce(plaintext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let k = key_array(key)?;
    let n: Nonce = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_BYTES,
        got: nonce.len(),
    })?;
    let mut ciphertext = vec![0u8; plaintext.len() + MAC_BYTES];
    crypto_secretbox_easy(&mut ciphertext, plaintext, &n, &k)
        .map_err(|e| CryptoError::Backend(format!("secretbox seal: {e}")))?;
    Ok(ciphertext)
}

/// Decrypts `ciphertext` with `nonce` and `key` using XSalsa20-Poly1305.
///
/// Compatible with libsodium `crypto_secretbox_open_easy`. Mirrors `SecretBoxOpen`.
pub fn open(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < MAC_BYTES {
        return Err(CryptoError::TooShort);
    }
    let k = key_array(key)?;
    let n: Nonce = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_BYTES,
        got: nonce.len(),
    })?;
    let mut plaintext = vec![0u8; ciphertext.len() - MAC_BYTES];
    crypto_secretbox_open_easy(&mut plaintext, ciphertext, &n, &k)
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(plaintext)
}

/// Base64-input convenience wrapper for [`open`]. Mirrors `SecretBoxOpenB64`.
pub fn open_b64(ciphertext_b64: &str, nonce_b64: &str, key: &[u8]) -> Result<Vec<u8>> {
    let eng = base64::engine::general_purpose::STANDARD;
    let ct = eng.decode(ciphertext_b64)?;
    let n = eng.decode(nonce_b64)?;
    open(&ct, &n, key)
}
