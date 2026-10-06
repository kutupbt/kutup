//! Padding for Direct Chat plaintext, Signal's scheme: the content, one `0x80`
//! terminator, then zeros up to a multiple of 160 bytes, inside the Double
//! Ratchet encryption. Servers then see a message's length only in 160-byte
//! steps, so a reaction, a receipt and a short text look alike.
//! (MLS groups pad their anonymous delivery payload in the same steps:
//! `mls_engine/delivery.rs`.)

use crate::error::{ChatError, Result};

pub(crate) const PADDING_BLOCK_BYTES: usize = 160;

/// The server's limit on one envelope's content (`maxContentBytes`).
const MAX_ENVELOPE_CONTENT_BYTES: usize = 65_536;
/// What encryption adds to a padded direct plaintext, at most: measured at
/// 2,110 bytes for a sealed first message (a post-quantum PreKey message,
/// which is also what a re-send after a session repair is), rounded up.
const DIRECT_ENVELOPE_OVERHEAD_BYTES: usize = 2_560;
/// The largest direct plaintext sure to fit one envelope, sealed or not,
/// first message or not.
pub(crate) const MAX_DIRECT_PLAINTEXT_BYTES: usize =
    (MAX_ENVELOPE_CONTENT_BYTES - DIRECT_ENVELOPE_OVERHEAD_BYTES) / PADDING_BLOCK_BYTES
        * PADDING_BLOCK_BYTES
        - 1;
const TERMINATOR: u8 = 0x80;

/// The padded plaintext to encrypt.
pub(crate) fn pad(plaintext: &[u8]) -> Vec<u8> {
    let padded_len = (plaintext.len() + 1).div_ceil(PADDING_BLOCK_BYTES) * PADDING_BLOCK_BYTES;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(plaintext);
    padded.push(TERMINATOR);
    padded.resize(padded_len, 0);
    padded
}

/// The plaintext inside a decrypted message: a whole number of blocks whose
/// last non-zero byte is the terminator. Anything else is refused.
pub(crate) fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    let invalid = || ChatError::Trust("direct message padding is invalid".into());
    if padded.is_empty() || !padded.len().is_multiple_of(PADDING_BLOCK_BYTES) {
        return Err(invalid());
    }
    let end = padded
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or_else(invalid)?;
    if padded[end] != TERMINATOR || padded.len() - end > PADDING_BLOCK_BYTES {
        return Err(invalid());
    }
    Ok(padded[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_160_byte_steps_and_back() {
        for (length, padded_len) in [
            (0, 160),
            (1, 160),
            (159, 160),
            (160, 320),
            (319, 320),
            (320, 480),
        ] {
            let plaintext: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let padded = pad(&plaintext);
            assert_eq!(padded.len(), padded_len, "length {length}");
            assert_eq!(unpad(&padded).unwrap(), plaintext);
        }
        // Content that itself ends in the terminator or in zeros survives.
        for plaintext in [vec![1, 0x80], vec![1, 0, 0], vec![0x80, 0]] {
            assert_eq!(unpad(&pad(&plaintext)).unwrap(), plaintext);
        }
    }

    #[test]
    fn refuses_anything_but_exact_padding() {
        let good = pad(b"hello");
        // Not a whole block.
        assert!(unpad(&good[..159]).is_err());
        // No terminator.
        assert!(unpad(&[0u8; 160]).is_err());
        let mut no_terminator = good.clone();
        no_terminator[5] = 0x7f;
        assert!(unpad(&no_terminator).is_err());
        // A whole block of padding more than needed.
        let mut too_long = good.clone();
        too_long.extend_from_slice(&[0u8; 160]);
        assert!(unpad(&too_long).is_err());
        assert!(unpad(&[]).is_err());
    }
}
