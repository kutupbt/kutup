use sha2::Digest as _;

use super::Suite;

/// A digest: as long as the suite's (`SuiteParams::digest_len`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest {
    bytes: [u8; 64],
    len: usize,
}

impl Digest {
    pub(super) fn from_slice(value: &[u8]) -> Self {
        let mut bytes = [0u8; 64];
        bytes[..value.len()].copy_from_slice(value);
        Self {
            bytes,
            len: value.len(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The digest as a fixed array, for a format that fixes its length.
    pub fn to_array<const N: usize>(&self) -> [u8; N] {
        self.as_bytes().try_into().expect("a suite's digest length")
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", hex::encode(self.as_bytes()))
    }
}

/// The suite's hash of `data`.
pub fn hash(suite: Suite, data: &[u8]) -> Digest {
    let mut hasher = Hasher::new(suite);
    hasher.update(data);
    hasher.finish()
}

/// The suite's hash, fed in parts.
#[derive(Clone)]
pub struct Hasher(Inner);

#[derive(Clone)]
enum Inner {
    Sha256(sha2::Sha256),
}

impl Hasher {
    pub fn new(suite: Suite) -> Self {
        match suite {
            Suite::V1 => Self(Inner::Sha256(sha2::Sha256::new())),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        match &mut self.0 {
            Inner::Sha256(h) => h.update(data),
        }
        self
    }

    pub fn finish(self) -> Digest {
        match self.0 {
            Inner::Sha256(h) => Digest::from_slice(&h.finalize()),
        }
    }
}
