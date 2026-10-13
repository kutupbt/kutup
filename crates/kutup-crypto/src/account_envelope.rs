//! Typed, context-bound envelopes for persistent account secrets.
//!
//! The complete wire value is stored as one canonical base64 string. The
//! header is authenticated as AEAD associated data, so a server-controlled
//! database cannot relocate a wrap between accounts, purposes or objects.
//!
//! Suite 1 used the wrapping key (a password's key-encryption key, the
//! recovery entropy, the master key) itself as the AEAD key, and bound the
//! account by its sign-in email. Suite 2 (docs/plans/account-identity.md,
//! review H2) derives a separate AEAD key per envelope from the wrapping key
//! (HKDF-SHA256 over the purpose, the binding and the object), so no
//! long-lived key is ever used raw, and binds the account's key binding and,
//! where one secret of a purpose exists per object, that object's id. New
//! envelopes are suite 2; suite 1 still opens, until the account re-seals.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPAE1\0";
const FIXED_PREFIX_LEN: usize = MAGIC.len() + 2 + 1 + 1 + 2;
const NONCE_LEN: usize = 24;
const LENGTH_LEN: usize = 4;
const TAG_LEN: usize = 16;
const MAX_CONTEXT_LEN: usize = 320;
/// The longest object id a suite-2 envelope names.
pub const MAX_OBJECT_LEN: usize = 64;
const MAX_PLAINTEXT_LEN: usize = 4096;
const V2_KEY_SALT: &[u8] = b"kutup/account-envelope/v2\0";
const V2_KEY_INFO: &[u8] = b"kutup/account-envelope-key/v2\0";

/// Closed registry for account-secret envelope encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountEnvelopeSuiteId {
    /// The wrapping key as the AEAD key; read only.
    XChaCha20Poly1305V1 = 1,
    /// A per-envelope AEAD key (HKDF-SHA256) and an object id.
    XChaCha20Poly1305HkdfV2 = 2,
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
            2 => Ok(Self::XChaCha20Poly1305HkdfV2),
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
    /// A mail address's OpenPGP secret key (`mail_key`).
    MailAddressPrivateKey = 5,
    /// A Kutup Pass vault's password and key file (`pass_vault`).
    PassVaultSecret = 6,
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
            5 => Ok(Self::MailAddressPrivateKey),
            6 => Ok(Self::PassVaultSecret),
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
    /// What the account is bound by: its key binding (suite 1: its sign-in
    /// email, or a binding written there), canonical.
    pub canonical_login_email: String,
    /// The object the secret belongs to (suite 2; empty when the purpose has
    /// one secret per account).
    pub object_id: Vec<u8>,
    pub ciphertext_len: u32,
}

struct ParsedEnvelope<'a> {
    header: AccountEnvelopeHeader,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

/// A binding as headers carry it: trimmed and lowercased (a key binding is
/// already; a suite-1 sign-in email is folded).
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
    suite: AccountEnvelopeSuiteId,
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> Result<Vec<u8>> {
    let context_len = u16::try_from(binding.len())
        .map_err(|_| CryptoError::InvalidInput("account-envelope context is too long".into()))?;
    let mut header = Vec::with_capacity(
        FIXED_PREFIX_LEN + binding.len() + 1 + object_id.len() + NONCE_LEN + LENGTH_LEN,
    );
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&suite.as_u16().to_be_bytes());
    header.push(purpose.as_u8());
    header.push(0); // reserved; non-zero is rejected to keep the encoding canonical
    header.extend_from_slice(&context_len.to_be_bytes());
    header.extend_from_slice(binding.as_bytes());
    if suite == AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2 {
        header.push(u8::try_from(object_id.len()).expect("checked object length"));
        header.extend_from_slice(object_id);
    }
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

/// The AEAD key of an envelope: suite 1 the wrapping key itself; suite 2 one
/// derived from it for this purpose, binding and object alone.
fn aead_key(
    suite: AccountEnvelopeSuiteId,
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    match suite {
        AccountEnvelopeSuiteId::XChaCha20Poly1305V1 => out.copy_from_slice(key),
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2 => {
            let mut info =
                Vec::with_capacity(V2_KEY_INFO.len() + 4 + binding.len() + object_id.len());
            info.extend_from_slice(V2_KEY_INFO);
            info.push(purpose.as_u8());
            info.extend_from_slice(&(binding.len() as u16).to_be_bytes());
            info.extend_from_slice(binding.as_bytes());
            info.push(object_id.len() as u8);
            info.extend_from_slice(object_id);
            Hkdf::<Sha256>::new(Some(V2_KEY_SALT), key)
                .expand(&info, out.as_mut_slice())
                .map_err(|_| CryptoError::Backend("account-envelope key".into()))?;
        }
    }
    Ok(out)
}

fn check_key(key: &[u8]) -> Result<()> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidLength {
            expected: 32,
            got: key.len(),
        });
    }
    Ok(())
}

/// Seals a secret of `purpose` for the account bound by `binding` (suite 2,
/// no object).
pub fn seal(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    login_email: &str,
) -> Result<Vec<u8>> {
    seal_object(plaintext, key, purpose, login_email, &[])
}

/// Seals a secret of `purpose` belonging to `object_id` (suite 2).
pub fn seal_object(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        plaintext,
        key,
        purpose,
        binding,
        object_id,
        &nonce,
    )
}

/// [`seal`] with a fixed nonce, for checked-in protocol vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    login_email: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        plaintext,
        key,
        purpose,
        login_email,
        &[],
        nonce,
    )
}

/// A suite-1 envelope with a fixed nonce, for the vectors that pin suite 1
/// (still read) only.
pub fn seal_v1_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    login_email: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305V1,
        plaintext,
        key,
        purpose,
        login_email,
        &[],
        nonce,
    )
}

/// Any suite, object and nonce: for checked-in vectors only.
pub fn seal_suite(
    suite: AccountEnvelopeSuiteId,
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    check_key(key)?;
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-envelope plaintext length is invalid".into(),
        ));
    }
    if object_id.len() > MAX_OBJECT_LEN
        || (suite == AccountEnvelopeSuiteId::XChaCha20Poly1305V1 && !object_id.is_empty())
    {
        return Err(CryptoError::InvalidInput(
            "account-envelope object id is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let binding = canonical_login_email(binding)?;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("account-envelope plaintext is too long".into()))?;
    let header = build_header(suite, purpose, &binding, object_id, &nonce, ciphertext_len)?;
    let aead = aead_key(suite, key, purpose, &binding, object_id)?;
    let ciphertext = XChaCha20Poly1305::new(aead.as_slice().into())
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
    if after_context >= envelope.len() {
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
    let (object_id, after_object) = match suite {
        AccountEnvelopeSuiteId::XChaCha20Poly1305V1 => (Vec::new(), after_context),
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2 => {
            let object_len = usize::from(envelope[after_context]);
            if object_len > MAX_OBJECT_LEN {
                return Err(CryptoError::InvalidInput(
                    "account-envelope object id is too long".into(),
                ));
            }
            let start = after_context + 1;
            let end = start.checked_add(object_len).ok_or(CryptoError::TooShort)?;
            if end > envelope.len() {
                return Err(CryptoError::TooShort);
            }
            (envelope[start..end].to_vec(), end)
        }
    };
    let after_nonce = after_object
        .checked_add(NONCE_LEN)
        .ok_or(CryptoError::TooShort)?;
    let after_length = after_nonce
        .checked_add(LENGTH_LEN)
        .ok_or(CryptoError::TooShort)?;
    if after_length > envelope.len() {
        return Err(CryptoError::TooShort);
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
            object_id,
            ciphertext_len,
        },
        aad: &envelope[..after_length],
        nonce: &envelope[after_object..after_nonce],
        ciphertext: &envelope[after_length..],
    })
}

pub fn inspect(envelope: &[u8]) -> Result<AccountEnvelopeHeader> {
    Ok(parse(envelope)?.header)
}

/// Checks an envelope's header (either suite) without opening it.
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

/// Opens an envelope of either suite with no object.
pub fn open(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_login_email: &str,
) -> Result<Vec<u8>> {
    open_object(envelope, key, expected_purpose, expected_login_email, &[])
}

/// Opens an envelope of either suite, sealed for `object_id` (suite 2; a
/// suite-1 envelope names no object, and opens for any).
pub fn open_object(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<Vec<u8>> {
    check_key(key)?;
    let parsed = parse(envelope)?;
    let suite = parsed.header.suite;
    if parsed.header.purpose != expected_purpose
        || parsed.header.canonical_login_email != canonical_login_email(expected_binding)?
        || (suite == AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2
            && parsed.header.object_id != object_id)
    {
        return Err(CryptoError::AuthFailed);
    }
    let aead = aead_key(
        suite,
        key,
        expected_purpose,
        &parsed.header.canonical_login_email,
        &parsed.header.object_id,
    )?;
    XChaCha20Poly1305::new(aead.as_slice().into())
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
        seal_v1_with_nonce(
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
    fn suite_two_derives_a_key_per_envelope_and_binds_its_object() {
        let binding = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        let key = [0x24; 32];
        let envelope = seal_object(
            &[0x42; 32],
            &key,
            AccountEnvelopePurpose::PassVaultSecret,
            binding,
            &[7; 16],
        )
        .unwrap();
        let header = inspect(&envelope).unwrap();
        assert_eq!(
            header.suite,
            AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2
        );
        assert_eq!(header.object_id, vec![7; 16]);
        assert_eq!(
            open_object(
                &envelope,
                &key,
                AccountEnvelopePurpose::PassVaultSecret,
                binding,
                &[7; 16]
            )
            .unwrap(),
            vec![0x42; 32]
        );
        // Another object, binding or purpose: refused.
        for (purpose, binding, object) in [
            (
                AccountEnvelopePurpose::PassVaultSecret,
                binding,
                &[8u8; 16][..],
            ),
            (
                AccountEnvelopePurpose::PassVaultSecret,
                "1b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b",
                &[7u8; 16][..],
            ),
            (
                AccountEnvelopePurpose::DriveHpkePrivateKey,
                binding,
                &[7u8; 16][..],
            ),
        ] {
            assert!(open_object(&envelope, &key, purpose, binding, object).is_err());
        }
        // The wrapping key is never the AEAD key: the same bytes under suite 1
        // do not open with it.
        let v1 = seal_v1_with_nonce(
            &[0x42; 32],
            &key,
            AccountEnvelopePurpose::PasswordMasterKey,
            binding,
            &[0x11; 24],
        )
        .unwrap();
        let v2 = seal_with_nonce(
            &[0x42; 32],
            &key,
            AccountEnvelopePurpose::PasswordMasterKey,
            binding,
            &[0x11; 24],
        )
        .unwrap();
        assert_ne!(v1[v1.len() - 48..], v2[v2.len() - 48..]);
        assert_eq!(
            open(
                &v1,
                &key,
                AccountEnvelopePurpose::PasswordMasterKey,
                binding
            )
            .unwrap(),
            open(
                &v2,
                &key,
                AccountEnvelopePurpose::PasswordMasterKey,
                binding
            )
            .unwrap()
        );
        // An object id past its limit, or one under suite 1, is refused.
        assert!(seal_object(
            &[1],
            &key,
            AccountEnvelopePurpose::PassVaultSecret,
            binding,
            &[0; 65]
        )
        .is_err());
        assert!(seal_suite(
            AccountEnvelopeSuiteId::XChaCha20Poly1305V1,
            &[1],
            &key,
            AccountEnvelopePurpose::PassVaultSecret,
            binding,
            &[1],
            &[0; 24]
        )
        .is_err());
    }

    #[test]
    fn unknown_suite_reserved_byte_and_noncanonical_context_are_rejected() {
        let envelope = fixture();
        let mut unknown_suite = envelope.clone();
        unknown_suite[9] = 3;
        assert!(inspect(&unknown_suite).is_err());

        let mut reserved = envelope.clone();
        reserved[11] = 1;
        assert!(inspect(&reserved).is_err());

        let mut noncanonical = envelope;
        noncanonical[14] = b'A';
        assert!(inspect(&noncanonical).is_err());
    }
}
