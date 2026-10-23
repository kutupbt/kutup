use super::Suite;
use crate::error::{CryptoError, Result};

/// The suite's KDF: `out.len()` bytes from `ikm`, `salt` (may be empty) and
/// the caller's label `info` (`kutup/<area>/<purpose>/vN\0`).
pub fn kdf(suite: Suite, ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    match suite {
        Suite::V1 => hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
            .expand(info, out)
            .map_err(|_| CryptoError::InvalidLength {
                expected: suite.params().kdf_max_output,
                got: out.len(),
            }),
    }
}
