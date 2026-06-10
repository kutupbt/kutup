//! BIP39 recovery-phrase encoding — mirrors `frontend/src/crypto/mnemonic.ts`.
//!
//! The 32-byte recovery-key entropy is rendered as a standard BIP39 24-word phrase (English
//! wordlist) shown once at registration. The frontend uses the `bip39` JS lib
//! (`entropyToMnemonic`); this is its byte-for-byte mirror (the same standard wordlist +
//! checksum, so a phrase produced here decodes in the browser and vice-versa). The Go CLI
//! has no mnemonic, so this is a frontend↔Rust mirror only.

use bip39::Mnemonic;

use crate::error::{CryptoError, Result};

/// Encodes 32 bytes of entropy as a 24-word BIP39 phrase. Mirrors `encodeMnemonic`.
pub fn encode(entropy: &[u8]) -> Result<String> {
    if entropy.len() != 32 {
        return Err(CryptoError::InvalidLength {
            expected: 32,
            got: entropy.len(),
        });
    }
    let m =
        Mnemonic::from_entropy(entropy).map_err(|e| CryptoError::Backend(format!("bip39: {e}")))?;
    Ok(m.to_string())
}

/// Decodes a BIP39 phrase back to its entropy. Mirrors `decodeMnemonic` (validates the
/// checksum; an invalid phrase is an error).
pub fn decode(phrase: &str) -> Result<Vec<u8>> {
    let m = Mnemonic::parse_normalized(phrase.trim()).map_err(|_| CryptoError::AuthFailed)?;
    let (arr, len) = m.to_entropy_array();
    Ok(arr[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical BIP39 test vector: 32 zero bytes → the well-known 24-word "abandon … art"
    // phrase. Asserts byte-for-byte agreement with the standard wordlist the frontend uses.
    #[test]
    fn zero_entropy_vector() {
        let phrase = encode(&[0u8; 32]).unwrap();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    #[test]
    fn roundtrip() {
        let entropy: [u8; 32] = [
            0x07, 0x1b, 0x2e, 0x44, 0x88, 0x9a, 0xfc, 0x10, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0xff,
        ];
        let phrase = encode(&entropy).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(decode(&phrase).unwrap(), entropy);
    }

    #[test]
    fn bad_length_rejected() {
        assert!(encode(&[0u8; 16]).is_err());
    }

    #[test]
    fn invalid_phrase_rejected() {
        assert!(decode("not a valid mnemonic phrase at all nope").is_err());
    }
}
