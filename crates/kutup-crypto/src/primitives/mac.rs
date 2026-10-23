use hmac::Mac as _;
use zeroize::Zeroizing;

use super::Suite;
use crate::error::{CryptoError, Result};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// A MAC tag: as long as the suite's (`SuiteParams::mac_tag_len`).
pub type Tag = super::Digest;

fn hmac(key: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut mac =
        <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac
}

/// The suite's MAC of `parts`, in order, under `key`.
pub fn mac(suite: Suite, key: &[u8], parts: &[&[u8]]) -> Tag {
    match suite {
        Suite::V1 => super::hash::Digest::from_slice(&hmac(key, parts).finalize().into_bytes()),
    }
}

/// Checks a MAC tag in constant time.
pub fn mac_verify(suite: Suite, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> Result<()> {
    match suite {
        Suite::V1 => hmac(key, parts)
            .verify_slice(tag)
            .map_err(|_| CryptoError::AuthFailed),
    }
}

/// A key for one purpose from a root key: `MAC(root, label)`, the label the
/// caller's (`kutup/<area>/<purpose>/vN\0`).
pub fn subkey(suite: Suite, root: &[u8], label: &[u8]) -> Zeroizing<[u8; 32]> {
    match suite {
        Suite::V1 => Zeroizing::new(hmac(root, &[label]).finalize().into_bytes().into()),
    }
}

/// The suite's MAC under one key, fed in parts.
#[derive(Clone)]
pub struct Mac(MacInner);

#[derive(Clone)]
enum MacInner {
    HmacSha256(HmacSha256),
}

impl Mac {
    pub fn new(suite: Suite, key: &[u8]) -> Self {
        match suite {
            Suite::V1 => Self(MacInner::HmacSha256(hmac(key, &[]))),
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        match &mut self.0 {
            MacInner::HmacSha256(m) => m.update(data.as_ref()),
        }
        self
    }

    pub fn finish(self) -> Tag {
        match self.0 {
            MacInner::HmacSha256(m) => super::hash::Digest::from_slice(&m.finalize().into_bytes()),
        }
    }
}
