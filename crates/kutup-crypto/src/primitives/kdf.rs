use super::Suite;
use crate::error::{CryptoError, Result};

/// The suite's KDF: `out.len()` bytes from `ikm`, `salt` (may be empty) and
/// the caller's label `info` (`kutup/<area>/<purpose>/vN\0`).
pub fn kdf(suite: Suite, ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    Kdf::new(suite, salt, ikm).expand(info, out)
}

/// The suite's KDF extracted once from `ikm` and `salt`, for several keys
/// (one `expand` per label). An empty salt is the hash's zero key (RFC 5869
/// §2.2), so it is HKDF's "no salt".
#[derive(Clone)]
pub struct Kdf {
    suite: Suite,
    inner: Inner,
}

#[derive(Clone)]
enum Inner {
    HkdfSha256(hkdf::Hkdf<sha2::Sha256>),
}

impl Kdf {
    pub fn new(suite: Suite, salt: &[u8], ikm: &[u8]) -> Self {
        let inner = match suite {
            Suite::V1 => Inner::HkdfSha256(hkdf::Hkdf::new(Some(salt), ikm)),
        };
        Self { suite, inner }
    }

    /// `out.len()` bytes for the label `info`.
    pub fn expand(&self, info: &[u8], out: &mut [u8]) -> Result<()> {
        match &self.inner {
            Inner::HkdfSha256(h) => h.expand(info, out).map_err(|_| CryptoError::InvalidLength {
                expected: self.suite.params().kdf_max_output,
                got: out.len(),
            }),
        }
    }
}
