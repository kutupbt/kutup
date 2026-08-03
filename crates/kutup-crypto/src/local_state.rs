//! Typed encryption for client-local state such as the CLI session cache.
//!
//! This is not a federated protocol format, but it still uses the project-wide
//! XChaCha20-Poly1305 palette and authenticates its suite, purpose, profile and
//! exact ciphertext length. Moving a cache blob between profiles therefore
//! fails closed even when both profiles were configured with the same key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPLS1\0";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const FIXED_PREFIX_LEN: usize = MAGIC.len() + 2 + 1 + 1 + 2;
const MAX_PROFILE_LEN: usize = 128;
const MAX_PLAINTEXT_LEN: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum LocalStateSuiteId {
    XChaCha20Poly1305V1 = 1,
}

impl LocalStateSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for LocalStateSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown local-state suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalStatePurpose {
    CliSession = 1,
}

impl LocalStatePurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for LocalStatePurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::CliSession),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown local-state purpose {value}"
            ))),
        }
    }
}

struct ParsedEnvelope<'a> {
    purpose: LocalStatePurpose,
    profile: &'a str,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn validate_profile(profile: &str) -> Result<&str> {
    if profile.is_empty()
        || profile.len() > MAX_PROFILE_LEN
        || profile.as_bytes().contains(&0)
        || profile.trim() != profile
    {
        return Err(CryptoError::InvalidInput(
            "local-state profile is not canonical".into(),
        ));
    }
    Ok(profile)
}

fn header(
    purpose: LocalStatePurpose,
    profile: &str,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> Result<Vec<u8>> {
    let profile = validate_profile(profile)?;
    let profile_len = u16::try_from(profile.len())
        .map_err(|_| CryptoError::InvalidInput("local-state profile is too long".into()))?;
    let mut out = Vec::with_capacity(FIXED_PREFIX_LEN + profile.len() + NONCE_LEN + 4);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(
        &LocalStateSuiteId::XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    out.push(purpose.as_u8());
    out.push(0);
    out.extend_from_slice(&profile_len.to_be_bytes());
    out.extend_from_slice(profile.as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok(out)
}

pub fn seal(
    plaintext: &[u8],
    key: &[u8],
    purpose: LocalStatePurpose,
    profile: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(plaintext, key, purpose, profile, &nonce)
}

/// Deterministic-nonce entry point for protocol tests only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    purpose: LocalStatePurpose,
    profile: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidLength {
            expected: 32,
            got: key.len(),
        });
    }
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::InvalidInput(
            "local-state plaintext length is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("local-state plaintext is too long".into()))?;
    let aad = header(purpose, profile, &nonce, ciphertext_len)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: key.len(),
        })?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Backend("local-state seal".into()))?;
    let mut envelope = aad;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn parse(envelope: &[u8]) -> Result<ParsedEnvelope<'_>> {
    let minimum = FIXED_PREFIX_LEN + 1 + NONCE_LEN + 4 + TAG_LEN + 1;
    if envelope.len() < minimum || envelope.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(CryptoError::TooShort);
    }
    let mut cursor = MAGIC.len();
    LocalStateSuiteId::try_from(u16::from_be_bytes([envelope[cursor], envelope[cursor + 1]]))?;
    cursor += 2;
    let purpose = LocalStatePurpose::try_from(envelope[cursor])?;
    cursor += 1;
    if envelope[cursor] != 0 {
        return Err(CryptoError::InvalidInput(
            "local-state reserved byte is non-zero".into(),
        ));
    }
    cursor += 1;
    let profile_len = usize::from(u16::from_be_bytes([envelope[cursor], envelope[cursor + 1]]));
    cursor += 2;
    if profile_len == 0 || profile_len > MAX_PROFILE_LEN {
        return Err(CryptoError::InvalidInput(
            "local-state profile length is invalid".into(),
        ));
    }
    let after_profile = cursor
        .checked_add(profile_len)
        .ok_or(CryptoError::TooShort)?;
    let after_nonce = after_profile
        .checked_add(NONCE_LEN)
        .ok_or(CryptoError::TooShort)?;
    let after_length = after_nonce.checked_add(4).ok_or(CryptoError::TooShort)?;
    if after_length > envelope.len() {
        return Err(CryptoError::TooShort);
    }
    let profile = std::str::from_utf8(&envelope[cursor..after_profile])
        .map_err(|_| CryptoError::InvalidInput("local-state profile is not UTF-8".into()))?;
    validate_profile(profile)?;
    let ciphertext_len = usize::try_from(u32::from_be_bytes(
        envelope[after_nonce..after_length]
            .try_into()
            .expect("four-byte slice"),
    ))
    .map_err(|_| CryptoError::InvalidInput("local-state ciphertext is too long".into()))?;
    if !(TAG_LEN + 1..=MAX_PLAINTEXT_LEN + TAG_LEN).contains(&ciphertext_len)
        || after_length.checked_add(ciphertext_len) != Some(envelope.len())
    {
        return Err(CryptoError::InvalidInput(
            "local-state ciphertext length is invalid".into(),
        ));
    }
    Ok(ParsedEnvelope {
        purpose,
        profile,
        aad: &envelope[..after_length],
        nonce: &envelope[after_profile..after_nonce],
        ciphertext: &envelope[after_length..],
    })
}

pub fn open(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: LocalStatePurpose,
    expected_profile: &str,
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidLength {
            expected: 32,
            got: key.len(),
        });
    }
    let parsed = parse(envelope)?;
    if parsed.purpose != expected_purpose || parsed.profile != validate_profile(expected_profile)? {
        return Err(CryptoError::AuthFailed);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: key.len(),
        })?;
    cipher
        .decrypt(
            XNonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: parsed.aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_vector_and_context_binding() {
        let envelope = seal_with_nonce(
            br#"{"accessToken":"token"}"#,
            &[0x22; 32],
            LocalStatePurpose::CliSession,
            "default",
            &[0x11; 24],
        )
        .unwrap();
        assert_eq!(
            hex::encode(&envelope),
            "4b5554504c53310000010100000764656661756c741111111111111111111111111111111111111111111111110000002783a6a7fe2e758a16660bcac3bde8c5e26d3b76a5a9d30dea185fba031de125a1e853a21f8b2a08"
        );
        assert_eq!(
            open(
                &envelope,
                &[0x22; 32],
                LocalStatePurpose::CliSession,
                "default",
            )
            .unwrap(),
            br#"{"accessToken":"token"}"#
        );
        assert!(open(
            &envelope,
            &[0x22; 32],
            LocalStatePurpose::CliSession,
            "other",
        )
        .is_err());
    }

    #[test]
    fn rejects_tamper_unknown_suite_and_trailing_bytes() {
        let envelope = seal(
            b"state",
            &[0x33; 32],
            LocalStatePurpose::CliSession,
            "default",
        )
        .unwrap();
        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(
            &tampered,
            &[0x33; 32],
            LocalStatePurpose::CliSession,
            "default",
        )
        .is_err());
        let mut unknown = envelope.clone();
        unknown[MAGIC.len() + 1] = 2;
        assert!(open(
            &unknown,
            &[0x33; 32],
            LocalStatePurpose::CliSession,
            "default",
        )
        .is_err());
        let mut trailing = envelope;
        trailing.push(0);
        assert!(open(
            &trailing,
            &[0x33; 32],
            LocalStatePurpose::CliSession,
            "default",
        )
        .is_err());
    }
}
