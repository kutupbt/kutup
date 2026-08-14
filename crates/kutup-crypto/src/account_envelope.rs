//! Typed, context-bound V1 envelopes for persistent account secrets.
//!
//! The complete wire value is stored as one canonical base64 string. The
//! header is authenticated as AEAD associated data, so a server-controlled
//! database cannot relocate a wrap between accounts or purposes.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPAE1\0";
const FIXED_PREFIX_LEN: usize = MAGIC.len() + 2 + 1 + 1 + 2;
const NONCE_LEN: usize = 24;
const LENGTH_LEN: usize = 4;
const TAG_LEN: usize = 16;
const MAX_CONTEXT_LEN: usize = 320;
const MAX_PLAINTEXT_LEN: usize = 4096;

/// Closed registry for account-secret envelope encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountEnvelopeSuiteId {
    XChaCha20Poly1305V1 = 1,
}

impl AccountEnvelopeSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for AccountEnvelopeSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown account-envelope suite {value}"
            ))),
        }
    }
}

/// The secret's purpose is part of the authenticated header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountEnvelopePurpose {
    PasswordMasterKey = 1,
    RecoveryMasterKey = 2,
    DriveHpkePrivateKey = 3,
    ChatBackupRoot = 4,
}

impl AccountEnvelopePurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AccountEnvelopePurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PasswordMasterKey),
            2 => Ok(Self::RecoveryMasterKey),
            3 => Ok(Self::DriveHpkePrivateKey),
            4 => Ok(Self::ChatBackupRoot),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown account-envelope purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountEnvelopeHeader {
    pub suite: AccountEnvelopeSuiteId,
    pub purpose: AccountEnvelopePurpose,
    pub canonical_login_email: String,
    pub ciphertext_len: u32,
}

struct ParsedEnvelope<'a> {
    header: AccountEnvelopeHeader,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

pub fn canonical_login_email(value: &str) -> Result<String> {
    let canonical = value.trim().to_ascii_lowercase();
    if canonical.is_empty()
        || canonical.len() > MAX_CONTEXT_LEN
        || canonical.as_bytes().contains(&0)
    {
        return Err(CryptoError::InvalidInput(
            "account-envelope login email is invalid".into(),
        ));
    }
    Ok(canonical)
}

fn build_header(
    purpose: AccountEnvelopePurpose,
    canonical_email: &str,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> Result<Vec<u8>> {
    let context_len = u16::try_from(canonical_email.len())
        .map_err(|_| CryptoError::InvalidInput("account-envelope context is too long".into()))?;
    let mut header =
        Vec::with_capacity(FIXED_PREFIX_LEN + canonical_email.len() + NONCE_LEN + LENGTH_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(
        &AccountEnvelopeSuiteId::XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    header.push(purpose.as_u8());
    header.push(0); // reserved; non-zero is rejected to keep the encoding canonical
    header.extend_from_slice(&context_len.to_be_bytes());
    header.extend_from_slice(canonical_email.as_bytes());
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

pub fn seal(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    login_email: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(plaintext, key, purpose, login_email, &nonce)
}

/// Deterministic-nonce entry point for checked-in protocol vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    login_email: &str,
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
            "account-envelope plaintext length is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let canonical_email = canonical_login_email(login_email)?;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("account-envelope plaintext is too long".into()))?;
    let header = build_header(purpose, &canonical_email, &nonce, ciphertext_len)?;
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
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("account-envelope seal".into()))?;
    debug_assert_eq!(ciphertext.len(), ciphertext_len as usize);
    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn parse(envelope: &[u8]) -> Result<ParsedEnvelope<'_>> {
    let minimum = FIXED_PREFIX_LEN + 1 + NONCE_LEN + LENGTH_LEN + TAG_LEN;
    if envelope.len() < minimum || envelope.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(CryptoError::TooShort);
    }
    let mut cursor = MAGIC.len();
    let suite = AccountEnvelopeSuiteId::try_from(u16::from_be_bytes([
        envelope[cursor],
        envelope[cursor + 1],
    ]))?;
    cursor += 2;
    let purpose = AccountEnvelopePurpose::try_from(envelope[cursor])?;
    cursor += 1;
    if envelope[cursor] != 0 {
        return Err(CryptoError::InvalidInput(
            "account-envelope reserved byte is non-zero".into(),
        ));
    }
    cursor += 1;
    let context_len = usize::from(u16::from_be_bytes([envelope[cursor], envelope[cursor + 1]]));
    cursor += 2;
    if context_len == 0 || context_len > MAX_CONTEXT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-envelope context length is invalid".into(),
        ));
    }
    let after_context = cursor
        .checked_add(context_len)
        .ok_or(CryptoError::TooShort)?;
    let after_nonce = after_context
        .checked_add(NONCE_LEN)
        .ok_or(CryptoError::TooShort)?;
    let after_length = after_nonce
        .checked_add(LENGTH_LEN)
        .ok_or(CryptoError::TooShort)?;
    if after_length > envelope.len() {
        return Err(CryptoError::TooShort);
    }
    let context = std::str::from_utf8(&envelope[cursor..after_context])
        .map_err(|_| CryptoError::InvalidInput("account-envelope context is not UTF-8".into()))?;
    let canonical_email = canonical_login_email(context)?;
    if canonical_email != context {
        return Err(CryptoError::InvalidInput(
            "account-envelope context is not canonical".into(),
        ));
    }
    let ciphertext_len = u32::from_be_bytes(
        envelope[after_nonce..after_length]
            .try_into()
            .expect("four-byte slice"),
    );
    let ciphertext_len_usize = usize::try_from(ciphertext_len)
        .map_err(|_| CryptoError::InvalidInput("account-envelope ciphertext is too long".into()))?;
    if !(TAG_LEN + 1..=MAX_PLAINTEXT_LEN + TAG_LEN).contains(&ciphertext_len_usize)
        || after_length.checked_add(ciphertext_len_usize) != Some(envelope.len())
    {
        return Err(CryptoError::InvalidInput(
            "account-envelope ciphertext length is invalid".into(),
        ));
    }
    Ok(ParsedEnvelope {
        header: AccountEnvelopeHeader {
            suite,
            purpose,
            canonical_login_email: canonical_email,
            ciphertext_len,
        },
        aad: &envelope[..after_length],
        nonce: &envelope[after_context..after_nonce],
        ciphertext: &envelope[after_length..],
    })
}

pub fn inspect(envelope: &[u8]) -> Result<AccountEnvelopeHeader> {
    Ok(parse(envelope)?.header)
}

pub fn validate(
    envelope: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_login_email: &str,
    expected_plaintext_len: usize,
) -> Result<()> {
    let parsed = parse(envelope)?;
    if parsed.header.purpose != expected_purpose
        || parsed.header.canonical_login_email != canonical_login_email(expected_login_email)?
        || parsed.ciphertext.len() != expected_plaintext_len.saturating_add(TAG_LEN)
    {
        return Err(CryptoError::InvalidInput(
            "account-envelope binding does not match".into(),
        ));
    }
    Ok(())
}

pub fn open(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_login_email: &str,
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidLength {
            expected: 32,
            got: key.len(),
        });
    }
    let parsed = parse(envelope)?;
    if parsed.header.purpose != expected_purpose
        || parsed.header.canonical_login_email != canonical_login_email(expected_login_email)?
    {
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

pub fn seal_b64(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    login_email: &str,
) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(seal(
        plaintext,
        key,
        purpose,
        login_email,
    )?))
}

pub fn decode_canonical_b64(value: &str) -> Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "account envelope must use canonical base64".into(),
        ));
    }
    Ok(decoded)
}

pub fn open_b64(
    envelope_b64: &str,
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_login_email: &str,
) -> Result<Vec<u8>> {
    open(
        &decode_canonical_b64(envelope_b64)?,
        key,
        expected_purpose,
        expected_login_email,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        seal_with_nonce(
            &[0x42; 32],
            &[0x24; 32],
            AccountEnvelopePurpose::PasswordMasterKey,
            " Alice@Example.COM ",
            &[0x11; 24],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_is_canonical_and_context_bound() {
        let envelope = fixture();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&envelope),
            "S1VUUEFFMQAAAQEAABFhbGljZUBleGFtcGxlLmNvbREREREREREREREREREREREREREREREREQAAADCpruTQDDdBFxf+GDLYiRAh/WI7QDLdbkkaToZVid7A36K8vZ389lsyoVtSx75SLbg="
        );
        let header = inspect(&envelope).unwrap();
        assert_eq!(header.suite, AccountEnvelopeSuiteId::XChaCha20Poly1305V1);
        assert_eq!(header.canonical_login_email, "alice@example.com");
        assert_eq!(header.ciphertext_len, 48);
        validate(
            &envelope,
            AccountEnvelopePurpose::PasswordMasterKey,
            "ALICE@example.com",
            32,
        )
        .unwrap();
        assert_eq!(
            open(
                &envelope,
                &[0x24; 32],
                AccountEnvelopePurpose::PasswordMasterKey,
                "alice@example.com",
            )
            .unwrap(),
            vec![0x42; 32]
        );
    }

    #[test]
    fn relocation_purpose_tampering_and_trailing_bytes_fail_closed() {
        let envelope = fixture();
        assert!(open(
            &envelope,
            &[0x24; 32],
            AccountEnvelopePurpose::PasswordMasterKey,
            "mallory@example.com",
        )
        .is_err());
        assert!(open(
            &envelope,
            &[0x24; 32],
            AccountEnvelopePurpose::RecoveryMasterKey,
            "alice@example.com",
        )
        .is_err());

        let mut tampered = envelope.clone();
        tampered[10] = AccountEnvelopePurpose::RecoveryMasterKey.as_u8();
        assert!(open(
            &tampered,
            &[0x24; 32],
            AccountEnvelopePurpose::RecoveryMasterKey,
            "alice@example.com",
        )
        .is_err());

        let mut trailing = envelope;
        trailing.push(0);
        assert!(inspect(&trailing).is_err());
    }

    #[test]
    fn unknown_suite_reserved_byte_and_noncanonical_context_are_rejected() {
        let envelope = fixture();
        let mut unknown_suite = envelope.clone();
        unknown_suite[9] = 2;
        assert!(inspect(&unknown_suite).is_err());

        let mut reserved = envelope.clone();
        reserved[11] = 1;
        assert!(inspect(&reserved).is_err());

        let mut noncanonical = envelope;
        noncanonical[14] = b'A';
        assert!(inspect(&noncanonical).is_err());
    }
}
