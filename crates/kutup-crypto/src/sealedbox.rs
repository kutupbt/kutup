//! Anonymous sealed box (X25519) — mirrors `cmd/kutup/internal/crypto/box.go`
//! (libsodium `crypto_box_seal` / `crypto_box_seal_open`, NaCl in Go).
//!
//! Used to wrap a collection key for a recipient during sharing: the sender is
//! anonymous (ephemeral keypair), and only the holder of the recipient secret
//! key can open the result.

use dryoc::classic::crypto_box::{
    crypto_box_keypair, crypto_box_seal, crypto_box_seal_open, PublicKey, SecretKey,
};
use dryoc::constants::{
    CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES, CRYPTO_BOX_SECRETKEYBYTES,
};

use crate::error::{CryptoError, Result};

/// Overhead added by [`seal_anonymous`]: 32-byte ephemeral public key + 16-byte MAC.
pub const SEAL_BYTES: usize = CRYPTO_BOX_SEALBYTES;
/// X25519 public key length (32 bytes).
pub const PUBLIC_KEY_BYTES: usize = CRYPTO_BOX_PUBLICKEYBYTES;
/// X25519 secret key length (32 bytes).
pub const SECRET_KEY_BYTES: usize = CRYPTO_BOX_SECRETKEYBYTES;

/// Generates a fresh X25519 keypair `(public, secret)` — mirrors `generateKeypair`
/// (`frontend/src/crypto/asymmetric.ts`). At registration the secret key is sealed under the
/// master key and the public key is stored in plaintext.
pub fn generate_keypair() -> ([u8; PUBLIC_KEY_BYTES], [u8; SECRET_KEY_BYTES]) {
    crypto_box_keypair()
}

fn pk(public_key: &[u8]) -> Result<PublicKey> {
    public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: PUBLIC_KEY_BYTES,
            got: public_key.len(),
        })
}

/// Encrypts `message` for `recipient_public_key` using an ephemeral keypair.
///
/// Compatible with libsodium `crypto_box_seal`. Mirrors `SealAnonymous`.
pub fn seal_anonymous(message: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
    let recipient = pk(recipient_public_key)?;
    let mut sealed = vec![0u8; message.len() + SEAL_BYTES];
    crypto_box_seal(&mut sealed, message, &recipient)
        .map_err(|e| CryptoError::Backend(format!("box seal: {e}")))?;
    Ok(sealed)
}

/// Decrypts a sealed box using the recipient's keypair.
///
/// Compatible with libsodium `crypto_box_seal_open`. Mirrors `OpenAnonymous`.
pub fn open_anonymous(
    sealed: &[u8],
    recipient_public_key: &[u8],
    recipient_secret_key: &[u8],
) -> Result<Vec<u8>> {
    if sealed.len() < SEAL_BYTES {
        return Err(CryptoError::TooShort);
    }
    let recipient_pk = pk(recipient_public_key)?;
    let recipient_sk: SecretKey =
        recipient_secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: SECRET_KEY_BYTES,
                got: recipient_secret_key.len(),
            })?;
    let mut message = vec![0u8; sealed.len() - SEAL_BYTES];
    crypto_box_seal_open(&mut message, sealed, &recipient_pk, &recipient_sk)
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(message)
}
