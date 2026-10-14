//! Safety numbers: what two people compare in person to know they each have
//! the other's real account (docs/plans/drive-identity-pins.md).
//!
//! The number binds both account authorities, in a fixed order, so either
//! side derives the same 80 digits and the same QR payload. It names no
//! address, as Signal's binds only the ACI and identity key: a rename keeps
//! the number, and any other account (a new holder of a released name, a new
//! incarnation) has another authority and so another number
//! (docs/plans/username-renames.md). Chat, Drive and the CLI use this one, so
//! an identity compared once is compared for every app. The bytes are V2 and
//! fixed: changing them would show everyone a new number.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use crate::error::{CryptoError, Result};

const DOMAIN: &[u8] = b"kutup/safety-number/v2\0";
/// What a safety QR code holds before the canonical bytes.
pub const QR_PREFIX: &str = "kutup://verify/v2/";
/// The largest scanned payload compared.
pub const MAX_QR_BYTES: usize = 1024;

/// The number for one pair of accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumberV2 {
    /// Sixteen groups of five digits, the full 256-bit value.
    pub fingerprint: String,
    /// `QR_PREFIX` and the canonical bytes, base64url.
    pub qr_payload: String,
}

/// The safety number of two accounts, given their authority public keys.
/// Symmetric: either side gets the same result.
pub fn derive(local_authority: &[u8; 32], peer_authority: &[u8; 32]) -> Result<SafetyNumberV2> {
    if local_authority == peer_authority {
        return Err(CryptoError::InvalidInput(
            "an account has no safety number with itself".into(),
        ));
    }
    let (low, high) = if local_authority < peer_authority {
        (local_authority, peer_authority)
    } else {
        (peer_authority, local_authority)
    };
    let mut canonical = Vec::with_capacity(DOMAIN.len() + 64);
    canonical.extend_from_slice(DOMAIN);
    canonical.extend_from_slice(low);
    canonical.extend_from_slice(high);
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    let fingerprint = (0..16)
        .map(|i| {
            format!(
                "{:05}",
                u16::from_be_bytes([digest[2 * i], digest[2 * i + 1]])
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    Ok(SafetyNumberV2 {
        fingerprint,
        qr_payload: format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(canonical)),
    })
}

/// Whether a scanned QR payload is exactly the expected one (constant time).
pub fn matches_qr_payload(expected: &SafetyNumberV2, scanned: &str) -> bool {
    if scanned.len() > MAX_QR_BYTES {
        return false;
    }
    let (left, right) = (expected.qr_payload.as_bytes(), scanned.as_bytes());
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().min(right.len()) {
        difference |= usize::from(left[index] ^ right[index]);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_number() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let left = derive(&a, &b).unwrap();
        let right = derive(&b, &a).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.fingerprint.split(' ').count(), 16);
        assert!(matches_qr_payload(&left, &right.qr_payload));
        // Another key (another account, or a new incarnation under the same
        // name): another number; its payload does not match.
        let other = derive(&a, &[3u8; 32]).unwrap();
        assert_ne!(other.fingerprint, left.fingerprint);
        assert!(!matches_qr_payload(&left, &other.qr_payload));
        assert!(derive(&a, &a).is_err());
    }
}
