//! Safety numbers: what two people compare in person to know they each have
//! the other's real account (docs/plans/drive-identity-pins.md).
//!
//! Signal's fingerprint, copied exactly (libsignal
//! `rust/protocol/src/fingerprint.rs`, version 2, 5200 iterations): each side
//! has its own half, an iterated SHA-512 over its stable id and identity key;
//! the number shows both halves as 2 × 30 digits, the lower first, and the QR
//! code carries both halves. Kutup's inputs:
//!
//! - the stable id is [`AccountRef::bytes`] (server and permanent account id),
//!   Signal's ACI; a rename keeps the number;
//! - the identity key is the account authority: its 32 raw Ed25519 bytes, with
//!   no type prefix (libsignal's Curve25519 keys carry a `0x05` byte; ours do
//!   not, so Kutup numbers never equal Signal's for the same bytes).
//!
//! Another authority for the same account (an administrator's reset, a
//! recovery) gives another number: Signal's "safety number changed". Chat,
//! Drive and the CLI use this one, so an identity compared once is compared
//! for every app. The bytes are fixed: changing them would show everyone a
//! new number.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest as _, Sha512};

use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};

/// What a safety QR code holds before the base64url protobuf.
pub const QR_PREFIX: &str = "kutup://verify/v3/";
/// The largest scanned payload compared.
pub const MAX_QR_BYTES: usize = 1024;
/// Signal's iteration count (Signal-Desktop `ts/util/safetyNumber.preload.ts`).
pub const ITERATIONS: u32 = 5200;
/// The scannable format's version (libsignal's current one).
pub const SCANNABLE_VERSION: u32 = 2;

/// The number for one pair of accounts, from one side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumberV3 {
    /// Twelve groups of five digits: both halves, the lower first. Both sides
    /// show the same.
    pub fingerprint: String,
    /// [`QR_PREFIX`] and the base64url `CombinedFingerprints` protobuf, this
    /// side's half first: the other side's payload has the halves swapped.
    pub qr_payload: String,
    local: [u8; 32],
    remote: [u8; 32],
}

/// The safety number this account (`local`) and `peer` compare, given their
/// authority public keys.
pub fn derive(
    local: &AccountRef,
    local_authority: &[u8; 32],
    peer: &AccountRef,
    peer_authority: &[u8; 32],
) -> Result<SafetyNumberV3> {
    if local == peer || local_authority == peer_authority {
        return Err(CryptoError::InvalidInput(
            "an account has no safety number with itself".into(),
        ));
    }
    let mine = signal::half(ITERATIONS, &local.bytes(), local_authority)?;
    let theirs = signal::half(ITERATIONS, &peer.bytes(), peer_authority)?;
    let display = signal::displayable(&mine, &theirs);
    let fingerprint = display
        .as_bytes()
        .chunks(5)
        .map(|group| std::str::from_utf8(group).expect("digits"))
        .collect::<Vec<_>>()
        .join(" ");
    let local: [u8; 32] = mine[..32].try_into().expect("64 bytes");
    let remote: [u8; 32] = theirs[..32].try_into().expect("64 bytes");
    Ok(SafetyNumberV3 {
        fingerprint,
        qr_payload: format!(
            "{QR_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(signal::scannable(SCANNABLE_VERSION, &local, &remote))
        ),
        local,
        remote,
    })
}

/// Whether a scanned QR payload is the other side's for exactly this pair:
/// its first half is our peer's, its second ours (constant time).
pub fn matches_qr_payload(expected: &SafetyNumberV3, scanned: &str) -> bool {
    if scanned.len() > MAX_QR_BYTES {
        return false;
    }
    let theirs = format!(
        "{QR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(signal::scannable(
            SCANNABLE_VERSION,
            &expected.remote,
            &expected.local
        ))
    );
    let (left, right) = (theirs.as_bytes(), scanned.as_bytes());
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().min(right.len()) {
        difference |= usize::from(left[index] ^ right[index]);
    }
    difference == 0
}

/// Signal's algorithm itself, for any key bytes: public so a test can feed it
/// and libsignal the same Curve25519 key and compare.
pub mod signal {
    use super::*;

    /// One side's half: `SHA-512(0x0000 ‖ key ‖ stable id ‖ key)`, then
    /// `iterations − 1` times `SHA-512(previous ‖ key)`.
    pub fn half(iterations: u32, stable_id: &[u8], key: &[u8]) -> Result<[u8; 64]> {
        if iterations <= 1 || iterations > 1_000_000 {
            return Err(CryptoError::InvalidInput(
                "fingerprint iterations are out of range".into(),
            ));
        }
        let mut hash = Sha512::new();
        hash.update([0u8, 0u8]);
        hash.update(key);
        hash.update(stable_id);
        hash.update(key);
        let mut out = hash.finalize();
        for _ in 1..iterations {
            let mut hash = Sha512::new();
            hash.update(out);
            hash.update(key);
            out = hash.finalize();
        }
        Ok(out.into())
    }

    /// Thirty digits of one half: six 5-byte big-endian chunks, each mod 100000.
    fn digits(half: &[u8; 64]) -> String {
        half[..30]
            .as_chunks::<5>()
            .0
            .iter()
            .map(|chunk| {
                let n = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                format!("{:05}", n % 100_000)
            })
            .collect()
    }

    /// The 60 digits both sides show: the two halves' digits, the lower first.
    pub fn displayable(local: &[u8; 64], remote: &[u8; 64]) -> String {
        let (a, b) = (digits(local), digits(remote));
        if a < b {
            a + &b
        } else {
            b + &a
        }
    }

    /// `CombinedFingerprints { version, local { content }, remote { content } }`
    /// in protobuf, as libsignal writes it.
    pub fn scannable(version: u32, local: &[u8; 32], remote: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0x08];
        let mut v = version;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        for (field, content) in [(0x12u8, local), (0x1a, remote)] {
            out.extend_from_slice(&[field, 0x22, 0x0a, 0x20]);
            out.extend_from_slice(content);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(n: u8) -> AccountRef {
        AccountRef::new(
            "kutup.dev",
            &format!("00000000-0000-4000-8000-0000000000{n:02x}"),
        )
        .unwrap()
    }

    /// libsignal's own vectors (`fingerprint_test_v2`, `testVectorsVersion2`
    /// in Java): the same algorithm over its Curve25519 keys.
    #[test]
    fn the_algorithm_is_libsignals() {
        let alice =
            hex::decode("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868")
                .unwrap();
        let bob = hex::decode("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b")
            .unwrap();
        let a = signal::half(5200, b"+14152222222", &alice).unwrap();
        let b = signal::half(5200, b"+14153333333", &bob).unwrap();
        let display = "300354477692869396892869876765458257569162576843440918079131";
        assert_eq!(signal::displayable(&a, &b), display);
        assert_eq!(signal::displayable(&b, &a), display);
        let half = |h: &[u8; 64]| -> [u8; 32] { h[..32].try_into().unwrap() };
        assert_eq!(
            hex::encode(signal::scannable(2, &half(&a), &half(&b))),
            "080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
        );
        assert_eq!(
            hex::encode(signal::scannable(2, &half(&b), &half(&a))),
            "080212220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"
        );
        // libsignal's encoding check.
        assert_eq!(
            hex::encode(signal::scannable(2, &[0x12; 32], &[0xba; 32])),
            "080212220a20".to_owned() + &"12".repeat(32) + "1a220a20" + &"ba".repeat(32)
        );
        assert!(signal::half(1, b"x", &alice).is_err());
    }

    #[test]
    fn both_sides_show_the_same_number_and_scan_each_other() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let left = derive(&account(1), &a, &account(2), &b).unwrap();
        let right = derive(&account(2), &b, &account(1), &a).unwrap();
        assert_eq!(left.fingerprint, right.fingerprint);
        assert_eq!(left.fingerprint.split(' ').count(), 12);
        assert!(left
            .fingerprint
            .split(' ')
            .all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
        // Each side scans the other's code; its own does not match.
        assert!(matches_qr_payload(&left, &right.qr_payload));
        assert!(matches_qr_payload(&right, &left.qr_payload));
        assert!(!matches_qr_payload(&left, &left.qr_payload));
        // Another authority for the same account (a reset): another number.
        let reset = derive(&account(1), &a, &account(2), &[3u8; 32]).unwrap();
        assert_ne!(reset.fingerprint, left.fingerprint);
        assert!(!matches_qr_payload(
            &left,
            &derive(&account(2), &[3u8; 32], &account(1), &a)
                .unwrap()
                .qr_payload
        ));
        // The same key under another account id: another number.
        let other = derive(&account(1), &a, &account(3), &b).unwrap();
        assert_ne!(other.fingerprint, left.fingerprint);
        assert!(derive(&account(1), &a, &account(1), &b).is_err());
        assert!(derive(&account(1), &a, &account(2), &a).is_err());
        assert!(!matches_qr_payload(&left, &"x".repeat(MAX_QR_BYTES + 1)));
    }
}
