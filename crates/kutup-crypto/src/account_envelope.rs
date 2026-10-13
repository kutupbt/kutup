//! Typed, context-bound envelopes for persistent account secrets.
//!
//! The complete wire value is stored as one canonical base64 string. The
//! header is authenticated as AEAD associated data, so a server-controlled
//! database cannot relocate a wrap between accounts, purposes or objects.
//!
//! Suite 2 (docs/plans/account-identity.md, review H2) derives a separate
//! AEAD key per envelope from the wrapping key (a password's key-encryption
//! key, the recovery entropy, the master key) with HKDF-SHA256 over the
//! purpose, the binding and the object, so no long-lived key is ever used
//! raw, and binds the account's key binding and, where one secret of a
//! purpose exists per object, that object's id. Suite 1 (the wrapping key as
//! the AEAD key, bound to the sign-in email) is no longer read or written:
//! no account from before carries over (the private beta was reset).

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
pub use crate::padding::Length;

const MAGIC: &[u8; 8] = b"KUTPAE1\0";
const FIXED_PREFIX_LEN: usize = MAGIC.len() + 2 + 1 + 1 + 2;
const NONCE_LEN: usize = 24;
const LENGTH_LEN: usize = 4;
const REVISION_LEN: usize = 8;
const TAG_LEN: usize = 16;
const MAX_CONTEXT_LEN: usize = 320;
/// The longest object id a suite-2 envelope names.
pub const MAX_OBJECT_LEN: usize = 64;
const MAX_PLAINTEXT_LEN: usize = 4096;
const V2_KEY_SALT: &[u8] = b"kutup/account-envelope/v2\0";
const V2_KEY_INFO: &[u8] = b"kutup/account-envelope-key/v2\0";

/// Closed registry for account-secret envelope encryption (suite 1 retired).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountEnvelopeSuiteId {
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

/// Whether a purpose's envelopes name an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectPolicy {
    /// One secret of the purpose per account: no object id.
    None,
    /// One secret per object: an object id of exactly this many bytes.
    Required(usize),
}

/// What every envelope of a purpose must be: checked on seal, on open and by
/// the server ([`validate_for`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurposePolicy {
    pub object: ObjectPolicy,
    /// How much of the plaintext's length the envelope shows (padded once,
    /// here).
    pub length: Length,
    /// A secret that is replaced over time: its envelopes carry a revision
    /// in the authenticated header, so an older one cannot pass as newer.
    pub mutable: bool,
}

impl AccountEnvelopePurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn policy(self) -> PurposePolicy {
        const KEY: PurposePolicy = PurposePolicy {
            object: ObjectPolicy::None,
            length: Length::Exact(32),
            mutable: false,
        };
        match self {
            Self::PasswordMasterKey
            | Self::RecoveryMasterKey
            | Self::DriveHpkePrivateKey
            | Self::ChatBackupRoot => KEY,
            // The address and the key's algorithm decide its length.
            Self::MailAddressPrivateKey => PurposePolicy {
                object: ObjectPolicy::None,
                length: Length::Bucket(256),
                mutable: false,
            },
            // One per vault (its Drive file id).
            Self::PassVaultSecret => PurposePolicy {
                object: ObjectPolicy::Required(16),
                length: Length::Bucket(256),
                mutable: false,
            },
        }
    }

    /// Every purpose, for tests and vectors.
    pub const ALL: [Self; 6] = [
        Self::PasswordMasterKey,
        Self::RecoveryMasterKey,
        Self::DriveHpkePrivateKey,
        Self::ChatBackupRoot,
        Self::MailAddressPrivateKey,
        Self::PassVaultSecret,
    ];
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
    /// What the account is bound by: its key binding, canonical.
    pub canonical_binding: String,
    /// The object the secret belongs to (empty when the purpose has one
    /// secret per account).
    pub object_id: Vec<u8>,
    /// The secret's revision, for a mutable purpose (never 0).
    pub revision: Option<u64>,
    pub ciphertext_len: u32,
}

struct ParsedEnvelope<'a> {
    header: AccountEnvelopeHeader,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

/// A binding as headers carry it: exactly a key binding.
pub fn canonical_binding(value: &str) -> Result<String> {
    // Exactly a key binding (a lowercase UUID v4), nothing trimmed or folded:
    // a name, an address or any other string is refused on seal and open.
    crate::key_binding::check(value)
        .map(str::to_owned)
        .map_err(|_| CryptoError::InvalidInput("account-envelope binding is invalid".into()))
}

/// Refuses an object id or revision the purpose does not take.
fn check_shape(
    purpose: AccountEnvelopePurpose,
    object_id: &[u8],
    revision: Option<u64>,
) -> Result<()> {
    let policy = purpose.policy();
    let object_ok = match policy.object {
        ObjectPolicy::None => object_id.is_empty(),
        ObjectPolicy::Required(len) => object_id.len() == len,
    };
    if !object_ok || object_id.len() > MAX_OBJECT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-envelope object id does not fit its purpose".into(),
        ));
    }
    match (policy.mutable, revision) {
        (true, Some(revision)) if revision > 0 => Ok(()),
        (false, None) => Ok(()),
        _ => Err(CryptoError::InvalidInput(
            "account-envelope revision does not fit its purpose".into(),
        )),
    }
}

fn build_header(
    suite: AccountEnvelopeSuiteId,
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> Result<Vec<u8>> {
    let context_len = u16::try_from(binding.len())
        .map_err(|_| CryptoError::InvalidInput("account-envelope context is too long".into()))?;
    let mut header = Vec::with_capacity(
        FIXED_PREFIX_LEN
            + binding.len()
            + 1
            + object_id.len()
            + REVISION_LEN
            + NONCE_LEN
            + LENGTH_LEN,
    );
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&suite.as_u16().to_be_bytes());
    header.push(purpose.as_u8());
    header.push(0); // reserved; non-zero is rejected to keep the encoding canonical
    header.extend_from_slice(&context_len.to_be_bytes());
    header.extend_from_slice(binding.as_bytes());
    header.push(u8::try_from(object_id.len()).expect("checked object length"));
    header.extend_from_slice(object_id);
    if let Some(revision) = revision {
        header.extend_from_slice(&revision.to_be_bytes());
    }
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

/// The AEAD key of an envelope: derived from the wrapping key for this
/// purpose, binding and object alone.
fn aead_key(
    suite: AccountEnvelopeSuiteId,
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    match suite {
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

/// A suite-2 envelope's AEAD key, as derived for it: for checked-in vectors
/// only (they pin this intermediate step).
pub fn v2_aead_key_for_vectors(
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
) -> Result<[u8; 32]> {
    check_key(key)?;
    let binding = canonical_binding(binding)?;
    Ok(*aead_key(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        key,
        purpose,
        &binding,
        object_id,
    )?)
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

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    nonce
}

/// Seals a secret of `purpose` (one per account) for the account bound by
/// `binding`.
pub fn seal(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
) -> Result<Vec<u8>> {
    seal_object(plaintext, key, purpose, binding, &[])
}

/// Seals a secret of `purpose` belonging to `object_id`.
pub fn seal_object(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
) -> Result<Vec<u8>> {
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        plaintext,
        key,
        purpose,
        binding,
        object_id,
        None,
        &random_nonce(),
    )
}

/// Seals revision `revision` of a mutable secret of `purpose` (with
/// `object_id` if the purpose names one).
pub fn seal_revision(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
    revision: u64,
) -> Result<Vec<u8>> {
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        plaintext,
        key,
        purpose,
        binding,
        object_id,
        Some(revision),
        &random_nonce(),
    )
}

/// [`seal`] with a fixed nonce, for checked-in protocol vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        plaintext,
        key,
        purpose,
        binding,
        &[],
        None,
        nonce,
    )
}

/// Any suite, object, revision and nonce: for checked-in vectors only.
#[allow(clippy::too_many_arguments)]
pub fn seal_suite(
    suite: AccountEnvelopeSuiteId,
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    check_key(key)?;
    check_shape(purpose, object_id, revision)?;
    let padded = Zeroizing::new(purpose.policy().length.pad(plaintext)?);
    if padded.is_empty() || padded.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-envelope plaintext length is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let binding = canonical_binding(binding)?;
    let ciphertext_len = u32::try_from(padded.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("account-envelope plaintext is too long".into()))?;
    let header = build_header(
        suite,
        purpose,
        &binding,
        object_id,
        revision,
        &nonce,
        ciphertext_len,
    )?;
    let aead = aead_key(suite, key, purpose, &binding, object_id)?;
    let ciphertext = XChaCha20Poly1305::new(aead.as_slice().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &padded,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("account-envelope seal".into()))?;
    debug_assert_eq!(ciphertext.len(), ciphertext_len as usize);
    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// An envelope built without the purpose's checks or padding (the plaintext
/// is sealed as given): for negative vectors only, which need well-encrypted
/// envelopes of the wrong shape.
#[cfg(any(test, feature = "test-vectors"))]
#[allow(clippy::too_many_arguments)]
pub fn seal_unchecked_for_vectors(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let suite = AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("too long".into()))?;
    let header = build_header(
        suite,
        purpose,
        binding,
        object_id,
        revision,
        nonce,
        ciphertext_len,
    )?;
    let aead = aead_key(suite, key, purpose, binding, object_id)?;
    let ciphertext = XChaCha20Poly1305::new(aead.as_slice().into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("account-envelope seal".into()))?;
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
    let canonical = canonical_binding(context)?;
    if canonical != context {
        return Err(CryptoError::InvalidInput(
            "account-envelope context is not canonical".into(),
        ));
    }
    let object_len = usize::from(envelope[after_context]);
    if object_len > MAX_OBJECT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-envelope object id is too long".into(),
        ));
    }
    let after_object = (after_context + 1)
        .checked_add(object_len)
        .ok_or(CryptoError::TooShort)?;
    let revision_len = if purpose.policy().mutable {
        REVISION_LEN
    } else {
        0
    };
    let after_revision = after_object
        .checked_add(revision_len)
        .ok_or(CryptoError::TooShort)?;
    if after_revision > envelope.len() {
        return Err(CryptoError::TooShort);
    }
    let object_id = envelope[after_context + 1..after_object].to_vec();
    let revision = (revision_len > 0).then(|| {
        u64::from_be_bytes(
            envelope[after_object..after_revision]
                .try_into()
                .expect("eight-byte slice"),
        )
    });
    check_shape(purpose, &object_id, revision)?;
    let after_nonce = after_revision
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
        || !purpose
            .policy()
            .length
            .allows_padded_len(ciphertext_len_usize - TAG_LEN)
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
            canonical_binding: canonical,
            object_id,
            revision,
            ciphertext_len,
        },
        aad: &envelope[..after_length],
        nonce: &envelope[after_revision..after_nonce],
        ciphertext: &envelope[after_length..],
    })
}

/// The header of a well-formed envelope (its purpose's object, revision and
/// length rules hold), without opening it.
pub fn inspect(envelope: &[u8]) -> Result<AccountEnvelopeHeader> {
    Ok(parse(envelope)?.header)
}

/// What a server checks before it stores an envelope: well formed, of
/// `expected_purpose`, for the account bound by `expected_binding` and the
/// object `expected_object` (empty when the purpose names none). Suite 1 and
/// any unknown suite never parse. Returns the header (its revision, for a
/// mutable purpose).
pub fn validate_for(
    envelope: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_binding: &str,
    expected_object: &[u8],
) -> Result<AccountEnvelopeHeader> {
    let header = parse(envelope)?.header;
    if header.purpose != expected_purpose
        || header.canonical_binding != canonical_binding(expected_binding)?
        || header.object_id != expected_object
    {
        return Err(CryptoError::InvalidInput(
            "account-envelope binding does not match".into(),
        ));
    }
    Ok(header)
}

/// Opens an envelope of a purpose with no object and no revision.
pub fn open(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_binding: &str,
) -> Result<Vec<u8>> {
    open_object(envelope, key, expected_purpose, expected_binding, &[])
}

/// Opens an envelope sealed for `object_id` (a purpose with no revision).
pub fn open_object(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<Vec<u8>> {
    if expected_purpose.policy().mutable {
        return Err(CryptoError::InvalidInput(
            "a mutable secret opens with its revision".into(),
        ));
    }
    Ok(open_any(envelope, key, expected_purpose, expected_binding, object_id)?.0)
}

/// Opens a mutable secret: its plaintext and the revision it was sealed at
/// (the caller refuses one older than it has seen).
pub fn open_revision(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<(Vec<u8>, u64)> {
    let (plain, revision) = open_any(envelope, key, expected_purpose, expected_binding, object_id)?;
    let revision = revision.ok_or_else(|| {
        CryptoError::InvalidInput("this purpose's secrets have no revision".into())
    })?;
    Ok((plain, revision))
}

fn open_any(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountEnvelopePurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<(Vec<u8>, Option<u64>)> {
    check_key(key)?;
    let parsed = parse(envelope)?;
    let suite = parsed.header.suite;
    if parsed.header.purpose != expected_purpose
        || parsed.header.canonical_binding != canonical_binding(expected_binding)?
        || parsed.header.object_id != object_id
    {
        return Err(CryptoError::AuthFailed);
    }
    let aead = aead_key(
        suite,
        key,
        expected_purpose,
        &parsed.header.canonical_binding,
        &parsed.header.object_id,
    )?;
    let padded = XChaCha20Poly1305::new(aead.as_slice().into())
        .decrypt(
            XNonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: parsed.aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    let plain = expected_purpose.policy().length.unpad(padded)?;
    Ok((plain, parsed.header.revision))
}

pub fn seal_b64(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountEnvelopePurpose,
    binding: &str,
) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(seal(plaintext, key, purpose, binding)?))
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
    expected_binding: &str,
) -> Result<Vec<u8>> {
    open(
        &decode_canonical_b64(envelope_b64)?,
        key,
        expected_purpose,
        expected_binding,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    fn fixture() -> Vec<u8> {
        seal_with_nonce(
            &[0x42; 32],
            &[0x24; 32],
            AccountEnvelopePurpose::PasswordMasterKey,
            BINDING,
            &[0x11; 24],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_is_canonical_and_context_bound() {
        let envelope = fixture();
        let header = inspect(&envelope).unwrap();
        assert_eq!(
            header.suite,
            AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2
        );
        assert_eq!(header.canonical_binding, BINDING);
        assert!(header.object_id.is_empty());
        assert_eq!(header.ciphertext_len, 48);
        validate_for(
            &envelope,
            AccountEnvelopePurpose::PasswordMasterKey,
            BINDING,
            &[],
        )
        .unwrap();
        // Only the exact key binding: not uppercased, padded, or an address.
        for other in [
            BINDING.to_uppercase(),
            format!(" {BINDING}"),
            "ada@kutup.dev".to_owned(),
        ] {
            assert!(
                validate_for(
                    &envelope,
                    AccountEnvelopePurpose::PasswordMasterKey,
                    &other,
                    &[]
                )
                .is_err(),
                "{other}"
            );
            assert!(seal_with_nonce(
                &[0x42; 32],
                &[0x24; 32],
                AccountEnvelopePurpose::PasswordMasterKey,
                &other,
                &[0x11; 24],
            )
            .is_err());
        }
        assert_eq!(
            open(
                &envelope,
                &[0x24; 32],
                AccountEnvelopePurpose::PasswordMasterKey,
                BINDING
            )
            .unwrap(),
            vec![0x42; 32]
        );
        // The wrapping key is never the AEAD key.
        let raw = XChaCha20Poly1305::new((&[0x24u8; 32]).into());
        let header_len = envelope.len() - 48;
        assert!(raw
            .decrypt(
                XNonce::from_slice(&[0x11; 24]),
                Payload {
                    msg: &envelope[header_len..],
                    aad: &envelope[..header_len],
                },
            )
            .is_err());
    }

    #[test]
    fn relocation_purpose_object_tampering_and_trailing_bytes_fail_closed() {
        let envelope = fixture();
        let key = [0x24; 32];
        assert!(open(
            &envelope,
            &key,
            AccountEnvelopePurpose::PasswordMasterKey,
            "1b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b"
        )
        .is_err());
        assert!(open(
            &envelope,
            &key,
            AccountEnvelopePurpose::RecoveryMasterKey,
            BINDING
        )
        .is_err());
        assert!(open_object(
            &envelope,
            &key,
            AccountEnvelopePurpose::PasswordMasterKey,
            BINDING,
            &[1]
        )
        .is_err());

        let mut tampered = envelope.clone();
        tampered[10] = AccountEnvelopePurpose::RecoveryMasterKey.as_u8();
        assert!(open(
            &tampered,
            &key,
            AccountEnvelopePurpose::RecoveryMasterKey,
            BINDING
        )
        .is_err());

        let mut trailing = envelope;
        trailing.push(0);
        assert!(inspect(&trailing).is_err());
    }

    #[test]
    fn an_object_is_bound_and_its_id_is_bounded() {
        let key = [0x24; 32];
        let envelope = seal_object(
            &[0x42; 32],
            &key,
            AccountEnvelopePurpose::PassVaultSecret,
            BINDING,
            &[7; 16],
        )
        .unwrap();
        assert_eq!(inspect(&envelope).unwrap().object_id, vec![7; 16]);
        assert_eq!(
            open_object(
                &envelope,
                &key,
                AccountEnvelopePurpose::PassVaultSecret,
                BINDING,
                &[7; 16]
            )
            .unwrap(),
            vec![0x42; 32]
        );
        assert!(open_object(
            &envelope,
            &key,
            AccountEnvelopePurpose::PassVaultSecret,
            BINDING,
            &[8; 16]
        )
        .is_err());
        assert!(seal_object(
            &[1],
            &key,
            AccountEnvelopePurpose::PassVaultSecret,
            BINDING,
            &[0; 65]
        )
        .is_err());
    }

    #[test]
    fn retired_or_unknown_suites_reserved_byte_and_noncanonical_context_are_rejected() {
        let envelope = fixture();
        for suite in [0u8, 1, 3] {
            let mut other = envelope.clone();
            other[9] = suite;
            assert!(inspect(&other).is_err(), "suite {suite}");
        }

        let mut reserved = envelope.clone();
        reserved[11] = 1;
        assert!(inspect(&reserved).is_err());

        let mut noncanonical = envelope;
        noncanonical[14] = b'A';
        assert!(inspect(&noncanonical).is_err());
    }
}
