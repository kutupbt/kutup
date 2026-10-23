use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};

use crate::error::{CryptoError, Result};

/// A password hash's cost, stored with what it protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PwhashParams {
    /// Passes over memory (libsodium's opslimit).
    pub operations: u64,
    /// Memory in bytes (libsodium's memlimit).
    pub memory: usize,
}

/// Argon2id v1.3 as libsodium's `crypto_pwhash` (one lane): `out.len()`
/// bytes from `password` and a 16-byte `salt`.
pub fn pwhash(
    params: &PwhashParams,
    password: &[u8],
    salt: &[u8; 16],
    out: &mut [u8],
) -> Result<()> {
    crypto_pwhash(
        out,
        password,
        salt,
        params.operations,
        params.memory,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|e| CryptoError::Backend(format!("argon2id: {e}")))
}
