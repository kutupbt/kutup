//! Key derivation — mirrors `cmd/kutup/internal/crypto/kdf.go` and
//! `frontend/src/crypto/kdf.ts` (libsodium `crypto_pwhash` + HKDF-SHA256).
//!
//! Argon2id parameters are fixed and **must match the frontend exactly**:
//! opslimit (time) = 3, memlimit (memory) = 64 MiB (`64 * 1024 * 1024` bytes),
//! parallelism = 1, output = 32 bytes.
//!
//! Note on parallelism: libsodium's `crypto_pwhash` hard-codes 1 lane — the
//! "4 threads" comment in `kdf.ts` is inaccurate, which is why the Go code
//! passes `threads = 1`. All three implementations therefore agree.
//!
//! `dryoc`'s `crypto_pwhash` maps `(opslimit, memlimit)` to Argon2id the same
//! way libsodium does (memlimit in bytes, parallelism = 1), so the derived keys
//! are byte-identical across all three implementations.

use base64::Engine;
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Argon2id opslimit (iterations). Mirrors `argonTime` / `OPSLIMIT`.
pub const OPSLIMIT: u64 = 3;
/// Argon2id memlimit in bytes (64 MiB). Mirrors `argonMemory` (64*1024 KiB) / `MEMLIMIT`.
pub const MEMLIMIT: usize = 64 * 1024 * 1024;
/// Derived key length in bytes. Mirrors `argonKeyLen` / `KEYLEN`.
pub const KEY_LEN: usize = 32;

/// HKDF salt for the per-file content key. Mirrors `kutup/file-content/v1`.
const CONTENT_KEY_SALT: &[u8] = b"kutup/file-content/v1";

fn argon2id(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    crypto_pwhash(
        out.as_mut_slice(),
        password,
        salt,
        OPSLIMIT,
        MEMLIMIT,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|e| CryptoError::Backend(format!("argon2id: {e}")))?;
    Ok(out)
}

/// Derives the Key Encryption Key from `password` + `kdf_salt`.
///
/// Used to decrypt the master key returned by the server.
/// Mirrors `DeriveKEK` / `deriveKeyEncryptionKey`.
pub fn derive_kek(password: &str, kdf_salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    argon2id(password.as_bytes(), kdf_salt)
}

/// Derives the login key from `password` + `login_key_salt`.
///
/// This is sent (base64-encoded) to the server for authentication. Uses a
/// separate salt from the KEK — two independent Argon2id derivations.
/// Mirrors `DeriveLoginKey` / `deriveLoginKey`.
pub fn derive_login_key(password: &str, login_key_salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    argon2id(password.as_bytes(), login_key_salt)
}

/// Base64-input convenience wrapper for [`derive_kek`].
pub fn derive_kek_b64(password: &str, kdf_salt_b64: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let salt = base64::engine::general_purpose::STANDARD.decode(kdf_salt_b64)?;
    derive_kek(password, &salt)
}

/// Base64-input convenience wrapper for [`derive_login_key`].
pub fn derive_login_key_b64(
    password: &str,
    login_key_salt_b64: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let salt = base64::engine::general_purpose::STANDARD.decode(login_key_salt_b64)?;
    derive_login_key(password, &salt)
}

/// Derives the per-file content key used for AEAD-encrypted child blobs
/// (whiteboard asset blobs at `files/{fileId}/assets/*`).
///
/// `HKDF-SHA256(ikm = collection_master, salt = "kutup/file-content/v1",
/// info = file_id)` → 32 bytes. Mirrors `DeriveContentKey` and
/// `frontend/src/collab/cryptoFrame.ts`.
pub fn derive_content_key(
    collection_master: &[u8],
    file_id: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(CONTENT_KEY_SALT), collection_master);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(file_id.as_bytes(), out.as_mut_slice())
        .map_err(|_| CryptoError::Backend("hkdf expand".into()))?;
    Ok(out)
}
