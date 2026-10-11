//! Safety numbers: what two people compare in person to know they each have
//! the other's real account (docs/plans/drive-identity-pins.md).
//!
//! The number binds both canonical addresses and both account authorities, in
//! a fixed order, so either side derives the same 80 digits and the same QR
//! payload. Chat introduced it (`kutup-chat-core`); Drive and the CLI use the
//! same one, so an identity compared once is compared for every app. The
//! bytes are V1 and fixed: changing them would show everyone a new number.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use crate::error::{CryptoError, Result};

const DOMAIN: &[u8] = b"kutup/chat/safety-number/v1\0";
/// What a safety QR code holds before the canonical bytes.
pub const QR_PREFIX: &str = "kutup://verify/chat/v1/";
/// The largest scanned payload compared.
pub const MAX_QR_BYTES: usize = 1024;

/// The number for one pair of accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumberV1 {
    /// Sixteen groups of five digits, the full 256-bit value.
    pub fingerprint: String,
    /// `QR_PREFIX` and the canonical bytes, base64url.
    pub qr_payload: String,
}

fn check_account(value: &str) -> Result<()> {
    let (user, server) = value.split_once('@').ok_or_else(|| {
        CryptoError::InvalidInput("safety numbers need account@server addresses".into())
    })?;
    if user.is_empty()
        || server.is_empty()
        || server.contains('@')
        || value.len() > 512
        || value
            .bytes()
            .any(|b| b.is_ascii_uppercase() || b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(CryptoError::InvalidInput(
            "a safety-number address is not canonical".into(),
        ));
    }
    Ok(())
}

/// The safety number of `local` and `peer` (canonical `user@server`
/// addresses) with their authority public keys. Symmetric: either side gets
/// the same result.
pub fn derive(
    local_account: &str,
    local_authority: &[u8; 32],
    peer_account: &str,
    peer_authority: &[u8; 32],
) -> Result<SafetyNumberV1> {
    check_account(local_account)?;
    check_account(peer_account)?;
    if local_account == peer_account {
        return Err(CryptoError::InvalidInput(
            "an account has no safety number with itself".into(),
        ));
    }
    let mut identities = [
        (local_account, local_authority),
        (peer_account, peer_authority),
    ];
    identities.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut canonical =
        Vec::with_capacity(DOMAIN.len() + identities.iter().map(|e| e.0.len() + 36).sum::<usize>());
    canonical.extend_from_slice(DOMAIN);
    for (account, key) in identities {
        let length = u32::try_from(account.len())
            .map_err(|_| CryptoError::InvalidInput("address is too long".into()))?;
        canonical.extend_from_slice(&length.to_be_bytes());
        canonical.extend_from_slice(account.as_bytes());
        canonical.extend_from_slice(key);
    }
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
    Ok(SafetyNumberV1 {
        fingerprint,
        qr_payload: format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(canonical)),
    })
}

/// Whether a scanned QR payload is exactly the expected one (constant time).
pub fn matches_qr_payload(expected: &SafetyNumberV1, scanned: &str) -> bool {
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
        let left = derive("alice@kutup.dev", &a, "bob@example.org", &b).unwrap();
        let right = derive("bob@example.org", &b, "alice@kutup.dev", &a).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.fingerprint.split(' ').count(), 16);
        assert!(matches_qr_payload(&left, &right.qr_payload));
        // Another key, another number; a payload for another pair does not match.
        let other = derive("alice@kutup.dev", &a, "bob@example.org", &[3u8; 32]).unwrap();
        assert_ne!(other.fingerprint, left.fingerprint);
        assert!(!matches_qr_payload(&left, &other.qr_payload));
    }

    /// Fixed V1 bytes: Chat showed these before the number moved here.
    #[test]
    fn the_v1_number_does_not_change() {
        let number = derive("alice@kutup.dev", &[1u8; 32], "bob@example.org", &[2u8; 32]).unwrap();
        assert_eq!(
            number.fingerprint,
            "43287 64308 39064 62898 28602 34220 14368 04694 33524 24006 58545 00869 00480 18981 08556 55505"
        );
        assert_eq!(
            number.qr_payload,
            "kutup://verify/chat/v1/a3V0dXAvY2hhdC9zYWZldHktbnVtYmVyL3YxAAAAAA9hbGljZUBrdXR1cC5kZXYBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAA9ib2JAZXhhbXBsZS5vcmcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
        );
    }

    #[test]
    fn addresses_must_be_canonical_and_distinct() {
        let key = [1u8; 32];
        assert!(derive("Alice@kutup.dev", &key, "bob@kutup.dev", &key).is_err());
        assert!(derive("alice", &key, "bob@kutup.dev", &key).is_err());
        assert!(derive("alice@kutup.dev", &key, "alice@kutup.dev", &key).is_err());
    }
}
