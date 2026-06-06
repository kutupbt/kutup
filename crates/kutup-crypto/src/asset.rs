//! Asset-blob AEAD — mirrors `cmd/kutup/internal/crypto/asset.go` and
//! `frontend/src/api/whiteboardAssets.ts`.
//!
//! Format: `nonce(24) || ciphertext-and-tag`.
//! Cipher: XChaCha20-Poly1305-IETF (RustCrypto `XChaCha20Poly1305`, matching
//! Go's `chacha20poly1305.NewX`).
//! Key:    `HKDF-SHA256(collection_master, "kutup/file-content/v1", file_id)`
//!         (see [`crate::kdf::derive_content_key`]).
//! AAD:    `"kutup-asset/v1" || asset_id`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;

use crate::error::{CryptoError, Result};
use crate::kdf::derive_content_key;

/// XChaCha20-Poly1305 nonce length (24 bytes).
pub const NONCE_BYTES: usize = 24;
/// Poly1305 tag length (16 bytes).
pub const TAG_BYTES: usize = 16;

const AAD_PREFIX: &str = "kutup-asset/v1";

fn build_aad(asset_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + asset_id.len());
    aad.extend_from_slice(AAD_PREFIX.as_bytes());
    aad.extend_from_slice(asset_id.as_bytes());
    aad
}

fn cipher_for(file_id: &str, collection_master: &[u8]) -> Result<XChaCha20Poly1305> {
    let key = derive_content_key(collection_master, file_id)?;
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| CryptoError::Backend(format!("aead init: {e}")))
}

/// Encrypts `plaintext` for `(file_id, asset_id)` under the per-file content key
/// derived from `collection_master`. Returns the at-rest blob
/// (`nonce || ciphertext+tag`) ready to upload. Mirrors `EncryptAsset`.
pub fn encrypt_asset(
    plaintext: &[u8],
    file_id: &str,
    asset_id: &str,
    collection_master: &[u8],
) -> Result<Vec<u8>> {
    let cipher = cipher_for(file_id, collection_master)?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    copy_randombytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &build_aad(asset_id),
            },
        )
        .map_err(|_| CryptoError::Backend("asset seal".into()))?;

    let mut out = Vec::with_capacity(NONCE_BYTES + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Reverses [`encrypt_asset`]. Errors on a bad nonce/tag/AAD. Mirrors `DecryptAsset`.
pub fn decrypt_asset(
    blob: &[u8],
    file_id: &str,
    asset_id: &str,
    collection_master: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() < NONCE_BYTES + TAG_BYTES {
        return Err(CryptoError::TooShort);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_BYTES);
    let cipher = cipher_for(file_id, collection_master)?;
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: &build_aad(asset_id),
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}
