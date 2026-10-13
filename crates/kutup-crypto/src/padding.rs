//! Length hiding for sealed values (ISO/IEC 7816-4 padding): the plaintext,
//! one `0x80` byte, then zeros up to the length the policy gives. Padding is
//! applied once, by the format that seals the value, and checked canonically
//! on open: a value whose padding is longer than its policy gives, or that
//! does not end in `0x80` and zeros, is refused.

use crate::error::{CryptoError, Result};

/// How much of a plaintext's length its sealed form shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    /// Always exactly this many bytes (a key): nothing to hide, no padding.
    Exact(usize),
    /// Padded to this many bytes, whatever the plaintext's length.
    Fixed(usize),
    /// Padded to the next multiple of this many bytes.
    Bucket(usize),
}

const MARKER: u8 = 0x80;

impl Length {
    /// The padded length of a `len`-byte plaintext; `None` if it does not fit.
    pub fn padded_len(self, len: usize) -> Option<usize> {
        match self {
            Length::Exact(n) => (len == n).then_some(n),
            Length::Fixed(n) => (len < n).then_some(n),
            Length::Bucket(b) => Some(len.checked_add(1)?.div_ceil(b).checked_mul(b)?),
        }
    }

    /// Whether `padded` bytes is a length this policy produces.
    pub fn allows_padded_len(self, padded: usize) -> bool {
        match self {
            Length::Exact(n) | Length::Fixed(n) => padded == n,
            Length::Bucket(b) => padded > 0 && padded.is_multiple_of(b),
        }
    }

    /// The plaintext padded to its policy.
    pub fn pad(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let padded_len = self
            .padded_len(plaintext.len())
            .ok_or_else(|| CryptoError::InvalidInput("plaintext length is invalid".into()))?;
        let mut out = Vec::with_capacity(padded_len);
        out.extend_from_slice(plaintext);
        if !matches!(self, Length::Exact(_)) {
            out.push(MARKER);
            out.resize(padded_len, 0);
        }
        Ok(out)
    }

    /// The plaintext inside `padded`, which must be padded exactly as
    /// [`Length::pad`] pads it.
    pub fn unpad(self, mut padded: Vec<u8>) -> Result<Vec<u8>> {
        let invalid = || CryptoError::InvalidInput("padding is invalid".into());
        if !self.allows_padded_len(padded.len()) {
            return Err(invalid());
        }
        if matches!(self, Length::Exact(_)) {
            return Ok(padded);
        }
        let marker = padded.iter().rposition(|&b| b != 0).ok_or_else(invalid)?;
        if padded[marker] != MARKER || self.padded_len(marker) != Some(padded.len()) {
            return Err(invalid());
        }
        padded.truncate(marker);
        Ok(padded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_round_trips_and_hides_the_length() {
        for (policy, len, padded) in [
            (Length::Bucket(256), 0, 256),
            (Length::Bucket(256), 255, 256),
            (Length::Bucket(256), 256, 512),
            (Length::Fixed(64), 0, 64),
            (Length::Fixed(64), 63, 64),
            (Length::Exact(32), 32, 32),
        ] {
            let plain = vec![0x80u8; len];
            let sealed = policy.pad(&plain).unwrap();
            assert_eq!(sealed.len(), padded, "{policy:?} {len}");
            assert_eq!(policy.unpad(sealed).unwrap(), plain);
        }
        assert!(Length::Fixed(64).pad(&[0; 64]).is_err());
        assert!(Length::Exact(32).pad(&[0; 31]).is_err());
    }

    #[test]
    fn non_canonical_padding_is_refused() {
        let policy = Length::Bucket(16);
        // No marker, a wrong marker, bytes after the marker.
        assert!(policy.unpad(vec![0; 16]).is_err());
        assert!(policy.unpad([vec![1; 15], vec![0x01]].concat()).is_err());
        assert!(policy
            .unpad([vec![1; 14], vec![0x80, 0x01]].concat())
            .is_err());
        // A whole bucket more padding than needed.
        assert!(policy
            .unpad([vec![1; 3], vec![0x80], vec![0; 28]].concat())
            .is_err());
        // Not a bucket's length.
        assert!(policy
            .unpad([vec![1; 3], vec![0x80], vec![0; 4]].concat())
            .is_err());
        assert!(Length::Fixed(8)
            .unpad([vec![1; 3], vec![0x80], vec![0; 5]].concat())
            .is_err());
    }
}
