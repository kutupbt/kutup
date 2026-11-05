//! Chat profiles (docs/plans/unified-profile.md): the `KUTPPE1` envelope
//! each profile item travels in, and the keys it is sealed under. Moved here
//! from chat-core and chat-proto unchanged, byte for byte
//! (docs/plans/chat-crypto-move.md; `tests/vectors/profile-v1.json`).
//!
//! - A profile key (32 random bytes) gives the profile's version (its
//!   public name), its access key (what a fetch shows) and the key each
//!   item's envelope is sealed under, per purpose and context.
//! - The owner's own copy of the profile key is an account record (purpose
//!   `ChatProfileKeyWrap`, docs/plans/w1-account-record.md) under the master
//!   key, bound to the account's key binding, the profile version and the
//!   revision.
//! - Every envelope binds its suite, purpose, account, version, revision and
//!   source device in its AAD and in its key.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result as CryptoResult};
use crate::primitives::{hash, Aead, Kdf, Suite};

const MAGIC: &[u8; 8] = b"KUTPPE1\0";
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 1 + 8 + 4 + 32 + 2;
const NONCE_BYTES: usize = 24;
const LENGTH_BYTES: usize = 4;
const TAG_BYTES: usize = 16;
/// An account's bytes (`AccountRef::bytes`): its server, length-prefixed, and its id.
const MAX_ACCOUNT_BYTES: usize = 2 + 253 + 16;
pub const PROFILE_NAME_PADDED_LENGTHS: [usize; 2] = [53, 257];
/// Signal's padding buckets for the profile "about" text.
pub const PROFILE_ABOUT_PADDED_LENGTHS: [usize; 3] = [128, 254, 512];
/// Characters in "about", as Signal allows.
pub const MAX_PROFILE_ABOUT_CHARS: usize = 140;
pub const MAX_PROFILE_AVATAR_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum ProfileSuiteId {
    XChaCha20Poly1305V1 = 1,
}

impl ProfileSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<ProfileSuiteId> for u16 {
    fn from(value: ProfileSuiteId) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for ProfileSuiteId {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305V1),
            _ => Err(format!("unknown encrypted profile suite {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProfileEnvelopePurpose {
    DisplayName = 1,
    Avatar = 2,
    // 3 was the owner's wrapped profile key, now an account record
    // (`ChatProfileKeyWrap`): never reused.
    About = 4,
}

impl ProfileEnvelopePurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    fn validate_ciphertext_len(self, len: usize) -> Result<(), String> {
        let valid = match self {
            Self::DisplayName => PROFILE_NAME_PADDED_LENGTHS
                .iter()
                .any(|plain| len == plain + TAG_BYTES),
            Self::Avatar => {
                (2 + TAG_BYTES..=MAX_PROFILE_AVATAR_BYTES + 1 + TAG_BYTES).contains(&len)
            }
            Self::About => PROFILE_ABOUT_PADDED_LENGTHS
                .iter()
                .any(|plain| len == plain + TAG_BYTES),
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "invalid ciphertext length for encrypted profile purpose {}",
                self.as_u8()
            ))
        }
    }
}

impl TryFrom<u8> for ProfileEnvelopePurpose {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DisplayName),
            2 => Ok(Self::Avatar),
            4 => Ok(Self::About),
            _ => Err(format!("unknown encrypted profile purpose {value}")),
        }
    }
}

/// The source id the account app writes the profile with: it is not a chat
/// device (those are 1-127), and the envelope refuses zero
/// (docs/plans/unified-profile.md).
pub const ACCOUNT_PROFILE_SOURCE: u32 = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEnvelopeContextV1 {
    pub suite: ProfileSuiteId,
    pub purpose: ProfileEnvelopePurpose,
    /// The profile's owner: their server and permanent account id, never a
    /// name (docs/plans/account-ids.md).
    pub account: AccountRef,
    pub profile_version: [u8; 32],
    pub revision: u64,
    pub source_device_id: u32,
}

impl ProfileEnvelopeContextV1 {
    pub fn new(
        purpose: ProfileEnvelopePurpose,
        account: &AccountRef,
        profile_version: &str,
        revision: u64,
        source_device_id: u32,
    ) -> Result<Self, String> {
        let version = hex::decode(profile_version)
            .map_err(|_| "profile version must be lowercase SHA-256 hex".to_string())?;
        if version.len() != 32 || hex::encode(&version) != profile_version {
            return Err("profile version must be lowercase SHA-256 hex".into());
        }
        if revision == 0 || source_device_id == 0 {
            return Err("encrypted profile revision and source device must be non-zero".into());
        }
        Ok(Self {
            suite: ProfileSuiteId::XChaCha20Poly1305V1,
            purpose,
            account: account.clone(),
            profile_version: version.try_into().expect("32-byte profile version"),
            revision,
            source_device_id,
        })
    }

    pub fn profile_version_hex(&self) -> String {
        hex::encode(self.profile_version)
    }

    /// Stable context used by the profile module's purpose-specific HKDF.
    pub fn key_derivation_info(&self) -> Vec<u8> {
        let account = self.account.bytes();
        let mut info = Vec::with_capacity(2 + 1 + 8 + 4 + 32 + 2 + account.len());
        info.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        info.push(self.purpose.as_u8());
        info.extend_from_slice(&self.revision.to_be_bytes());
        info.extend_from_slice(&self.source_device_id.to_be_bytes());
        info.extend_from_slice(&self.profile_version);
        info.extend_from_slice(&(account.len() as u16).to_be_bytes());
        info.extend_from_slice(&account);
        info
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedProfileEnvelopeV1 {
    pub context: ProfileEnvelopeContextV1,
    pub aad: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

pub fn encode_profile_envelope_header(
    context: &ProfileEnvelopeContextV1,
    nonce: &[u8; NONCE_BYTES],
    ciphertext_len: u32,
) -> Result<Vec<u8>, String> {
    context
        .purpose
        .validate_ciphertext_len(ciphertext_len as usize)?;
    let account = context.account.bytes();
    let mut header =
        Vec::with_capacity(FIXED_PREFIX_BYTES + account.len() + NONCE_BYTES + LENGTH_BYTES);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&context.suite.as_u16().to_be_bytes());
    header.push(context.purpose.as_u8());
    header.push(0);
    header.extend_from_slice(&context.revision.to_be_bytes());
    header.extend_from_slice(&context.source_device_id.to_be_bytes());
    header.extend_from_slice(&context.profile_version);
    header.extend_from_slice(&(account.len() as u16).to_be_bytes());
    header.extend_from_slice(&account);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

pub fn decode_profile_envelope(encoded: &str) -> Result<DecodedProfileEnvelopeV1, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "encrypted profile envelope must be standard base64".to_string())?;
    if STANDARD.encode(&bytes) != encoded {
        return Err("encrypted profile envelope base64 is not canonical".into());
    }
    if bytes.len() < FIXED_PREFIX_BYTES + 1 + NONCE_BYTES + LENGTH_BYTES + TAG_BYTES
        || bytes.get(..MAGIC.len()) != Some(MAGIC)
    {
        return Err("encrypted profile envelope is too short".into());
    }
    let suite = ProfileSuiteId::try_from(u16::from_be_bytes([bytes[8], bytes[9]]))?;
    let purpose = ProfileEnvelopePurpose::try_from(bytes[10])?;
    if bytes[11] != 0 {
        return Err("encrypted profile reserved byte is non-zero".into());
    }
    let revision = u64::from_be_bytes(bytes[12..20].try_into().expect("eight-byte slice"));
    let source_device_id = u32::from_be_bytes(bytes[20..24].try_into().expect("four-byte slice"));
    let version: [u8; 32] = bytes[24..56].try_into().expect("32-byte slice");
    let account_len = u16::from_be_bytes([bytes[56], bytes[57]]) as usize;
    if account_len == 0 || account_len > MAX_ACCOUNT_BYTES {
        return Err("encrypted profile account length is invalid".into());
    }
    let account_end = FIXED_PREFIX_BYTES
        .checked_add(account_len)
        .ok_or_else(|| "encrypted profile account length overflow".to_string())?;
    let header_len = account_end
        .checked_add(NONCE_BYTES + LENGTH_BYTES)
        .ok_or_else(|| "encrypted profile header length overflow".to_string())?;
    if bytes.len() < header_len + TAG_BYTES {
        return Err("encrypted profile envelope is truncated".into());
    }
    let (account, read) = AccountRef::read(&bytes[FIXED_PREFIX_BYTES..account_end])
        .map_err(|_| "encrypted profile account is invalid".to_string())?;
    if read != account_len {
        return Err("encrypted profile account has trailing bytes".into());
    }
    let context = ProfileEnvelopeContextV1::new(
        purpose,
        &account,
        &hex::encode(version),
        revision,
        source_device_id,
    )?;
    if context.suite != suite {
        return Err("encrypted profile suite mismatch".into());
    }
    let ciphertext_len = u32::from_be_bytes(
        bytes[header_len - LENGTH_BYTES..header_len]
            .try_into()
            .expect("four-byte slice"),
    ) as usize;
    purpose.validate_ciphertext_len(ciphertext_len)?;
    if header_len.checked_add(ciphertext_len) != Some(bytes.len()) {
        return Err("encrypted profile ciphertext length is invalid".into());
    }
    let nonce = bytes[account_end..account_end + NONCE_BYTES]
        .try_into()
        .expect("24-byte nonce");
    Ok(DecodedProfileEnvelopeV1 {
        context,
        aad: bytes[..header_len].to_vec(),
        nonce,
        ciphertext: bytes[header_len..].to_vec(),
    })
}

/// A profile key's length.
pub const PROFILE_KEY_BYTES: usize = 32;
/// An access key's length.
pub const PROFILE_ACCESS_KEY_BYTES: usize = 16;
const KEY_SALT: &[u8] = crate::labels::CHAT_PROFILE_V1;
const VERSION_INFO: &[u8] = crate::labels::CHAT_PROFILE_VERSION_V1;
const ACCESS_INFO: &[u8] = crate::labels::CHAT_PROFILE_ACCESS_V1;
const ENVELOPE_KEY_SALT: &[u8] = crate::labels::PROFILE_ENVELOPE_KEY_V1;

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(message.into())
}

/// HKDF-SHA256 salted with the profile family's label.
fn expand<const N: usize>(ikm: &[u8], info: &[u8]) -> CryptoResult<[u8; N]> {
    let mut out = [0u8; N];
    Kdf::new(Suite::V1, KEY_SALT, ikm).expand(info, &mut out)?;
    Ok(out)
}

/// What the account's own copy of its profile key is sealed under: the
/// master key, its generation and the account's key binding.
#[derive(Clone)]
pub struct ProfileOwnerKey {
    master_key: Zeroizing<[u8; 32]>,
    generation: MasterKeyGeneration,
    binding: String,
}

impl ProfileOwnerKey {
    pub fn new(
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        binding: &str,
    ) -> CryptoResult<Self> {
        let binding = account_record::canonical_binding(binding)
            .map_err(|_| invalid("the profile key's copy needs the account's key binding"))?;
        Ok(Self {
            master_key: Zeroizing::new(*master_key),
            generation,
            binding,
        })
    }

    pub fn binding(&self) -> &str {
        &self.binding
    }
}

impl std::fmt::Debug for ProfileOwnerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileOwnerKey")
            .field("generation", &self.generation)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

const WRAP_PURPOSE: AccountRecordPurpose = AccountRecordPurpose::ChatProfileKeyWrap;

/// A profile version (lowercase hex) as a record's object: its 32 bytes.
fn version_object(version: &str) -> CryptoResult<[u8; 32]> {
    let bytes = hex::decode(version)
        .map_err(|_| invalid("profile version must be lowercase SHA-256 hex"))?;
    if hex::encode(&bytes) != version {
        return Err(invalid("profile version must be lowercase SHA-256 hex"));
    }
    bytes
        .try_into()
        .map_err(|_| invalid("profile version must be lowercase SHA-256 hex"))
}

/// The owner's copy of `key` at `revision` (standard base64): an account
/// record for the profile version the key derives.
pub fn wrap_profile_key(
    key: &[u8; PROFILE_KEY_BYTES],
    owner: &ProfileOwnerKey,
    revision: u64,
) -> CryptoResult<String> {
    let version = version_object(&profile_version(key)?)?;
    let sealed = account_record::seal_revision(
        key,
        owner.master_key.as_slice(),
        WRAP_PURPOSE,
        owner.generation,
        &owner.binding,
        &version,
        revision,
    )?;
    Ok(STANDARD.encode(sealed))
}

/// The profile key from the owner's copy: sealed for this account, this
/// profile version and this revision, and deriving that version.
pub fn unwrap_profile_key(
    wrapped: &str,
    owner: &ProfileOwnerKey,
    version: &str,
    revision: u64,
) -> CryptoResult<Zeroizing<[u8; PROFILE_KEY_BYTES]>> {
    let bytes = account_record::decode_record_b64(wrapped, WRAP_PURPOSE)?;
    let (plain, sealed_at) = account_record::open_revision(
        &bytes,
        owner.master_key.as_slice(),
        WRAP_PURPOSE,
        &owner.binding,
        &version_object(version)?,
    )?;
    let plain = Zeroizing::new(plain);
    if sealed_at != revision {
        return Err(invalid("wrapped profile key is for another revision"));
    }
    let key = Zeroizing::new(profile_key(&plain)?);
    if profile_version(key.as_slice())? != version {
        return Err(invalid(
            "wrapped profile key does not match profile version",
        ));
    }
    Ok(key)
}

/// What a server checks of the owner's copy before it stores a profile: an
/// account record of this account, for this version and this revision.
pub fn validate_wrapped_profile_key(
    wrapped: &str,
    binding: &str,
    version: &str,
    revision: u64,
) -> CryptoResult<()> {
    let bytes = account_record::decode_record_b64(wrapped, WRAP_PURPOSE)?;
    let header =
        account_record::validate_for(&bytes, WRAP_PURPOSE, binding, &version_object(version)?)?;
    if header.revision != Some(revision) {
        return Err(invalid("wrapped profile key is for another revision"));
    }
    Ok(())
}

/// A profile key, checked: exactly 32 bytes.
pub fn profile_key(key: &[u8]) -> CryptoResult<[u8; PROFILE_KEY_BYTES]> {
    key.try_into()
        .map_err(|_| invalid("profile key must be exactly 32 bytes"))
}

/// The profile's public name: lowercase hex of what the key derives.
pub fn profile_version(key: &[u8]) -> CryptoResult<String> {
    Ok(hex::encode(expand::<32>(&profile_key(key)?, VERSION_INFO)?))
}

/// What a fetch of the profile shows (the access header).
pub fn profile_access_key(key: &[u8]) -> CryptoResult<[u8; PROFILE_ACCESS_KEY_BYTES]> {
    expand(&profile_key(key)?, ACCESS_INFO)
}

/// What the server keeps to check an access key: lowercase hex SHA-256.
pub fn access_key_verifier(access_key: &[u8]) -> String {
    hex::encode(hash(Suite::V1, access_key))
}

fn envelope_key(
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Kdf::new(Suite::V1, ENVELOPE_KEY_SALT, root_key)
        .expand(&context.key_derivation_info(), out.as_mut_slice())?;
    Ok(out)
}

/// `plaintext` sealed in a `KUTPPE1` envelope for `context` under a key
/// `root_key` derives (the profile key, or the wrapping key for the wrapped
/// profile key), as standard base64.
pub fn seal_item(
    plaintext: &[u8],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
) -> CryptoResult<String> {
    let mut nonce = [0u8; NONCE_BYTES];
    crate::primitives::random(&mut nonce);
    seal_item_with_nonce(plaintext, root_key, context, &nonce)
}

/// [`seal_item`] under a given nonce (vectors).
pub fn seal_item_with_nonce(
    plaintext: &[u8],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
    nonce: &[u8; NONCE_BYTES],
) -> CryptoResult<String> {
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_BYTES)
        .map_err(|_| invalid("encrypted profile item is too large"))?;
    let header = encode_profile_envelope_header(context, nonce, ciphertext_len)
        .map_err(|error| invalid(&error))?;
    let key = envelope_key(root_key, context)?;
    let ciphertext =
        Aead::new(Suite::V1, key.as_slice())?.seal_with_nonce(nonce, &header, plaintext)?;
    let mut encoded = header;
    encoded.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(encoded))
}

/// The plaintext of an envelope [`seal_item`] made: its context must be
/// `expected`.
pub fn open_item(
    encoded: &str,
    root_key: &[u8; 32],
    expected: &ProfileEnvelopeContextV1,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let parsed = decode_profile_envelope(encoded).map_err(|error| invalid(&error))?;
    if parsed.context != *expected {
        return Err(invalid("encrypted profile envelope context does not match"));
    }
    let key = envelope_key(root_key, expected)?;
    Aead::new(Suite::V1, key.as_slice())?.open_with_nonce(
        &parsed.nonce,
        &parsed.aad,
        &parsed.ciphertext,
    )
}

/// `text` zero-padded to the smallest of `buckets` that fits (so the length
/// tells only the bucket), sealed as [`seal_item`] does.
pub fn seal_padded_text(
    text: &str,
    buckets: &[usize],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
) -> CryptoResult<String> {
    let bytes = text.as_bytes();
    let padded_len = buckets
        .iter()
        .copied()
        .find(|length| bytes.len() <= *length)
        .ok_or_else(|| invalid("profile text is too large"))?;
    let mut padded = Zeroizing::new(vec![0u8; padded_len]);
    padded[..bytes.len()].copy_from_slice(bytes);
    seal_item(&padded, root_key, context)
}

/// The text of a padded envelope ([`seal_padded_text`]).
pub fn open_padded_text(
    encoded: &str,
    buckets: &[usize],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
) -> CryptoResult<String> {
    let padded = open_item(encoded, root_key, context)?;
    if !buckets.contains(&padded.len()) {
        return Err(invalid(
            "encrypted profile text has an invalid padded length",
        ));
    }
    let end = padded
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(padded.len());
    if padded[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid("profile text padding is invalid"));
    }
    std::str::from_utf8(&padded[..end])
        .map(str::to_owned)
        .map_err(|_| invalid("profile text is not UTF-8"))
}

/// The sealed-delivery capability for `recipient` from their profile key:
/// salted with their account (server and permanent id), never a name
/// (docs/plans/account-ids.md).
pub fn derive_delivery_capability(
    profile_key: &[u8; 32],
    recipient: &AccountRef,
) -> CryptoResult<[u8; 16]> {
    let mut out = [0u8; 16];
    // Salted with the label; the recipient's account (server and permanent
    // id) is the info, never a name (docs/plans/account-ids.md).
    Kdf::new(Suite::V1, DELIVERY_CAPABILITY_CONTEXT, profile_key)
        .expand(&recipient.bytes(), &mut out)?;
    Ok(out)
}

/// Its salt label.
pub const DELIVERY_CAPABILITY_CONTEXT: &[u8] = crate::labels::SEALED_DELIVERY_CAPABILITY_V1;

/// What the server keeps to check a delivery capability: its SHA-256.
pub fn capability_hash(capability: &[u8; 16]) -> [u8; 32] {
    hash(Suite::V1, capability).into()
}

/// A display name: trimmed, 1 to 80 non-control characters.
pub fn validate_display_name(value: &str) -> CryptoResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid("profile display name is required"));
    }
    if value.chars().count() > 80
        || value.len() > PROFILE_NAME_PADDED_LENGTHS[1]
        || value.chars().any(char::is_control)
    {
        return Err(invalid(
            "profile display name must be at most 80 non-control characters",
        ));
    }
    Ok(value.to_string())
}

/// The "about" line: trimmed, at most 140 characters (Signal's limit), one
/// line; empty means none.
pub fn validate_about(value: Option<&str>) -> CryptoResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_PROFILE_ABOUT_CHARS
        || value.len() > PROFILE_ABOUT_PADDED_LENGTHS[PROFILE_ABOUT_PADDED_LENGTHS.len() - 1]
        || value.chars().any(char::is_control)
    {
        return Err(invalid(
            "profile about must be one line of at most 140 characters",
        ));
    }
    Ok(Some(value.to_string()))
}

/// An avatar: a non-empty PNG, JPEG or WebP under 512 KiB, its bytes and
/// type given together.
pub fn validate_avatar(avatar: Option<&[u8]>, content_type: Option<&str>) -> CryptoResult<()> {
    match (avatar, content_type) {
        (None, None) => Ok(()),
        (Some(bytes), Some(kind))
            if !bytes.is_empty()
                && bytes.len() <= MAX_PROFILE_AVATAR_BYTES
                && avatar_type_code(kind).is_some() =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => Err(invalid(
            "profile avatar must be a non-empty PNG, JPEG, or WebP under 512 KiB",
        )),
        _ => Err(invalid(
            "profile avatar bytes and content type must be provided together",
        )),
    }
}

fn avatar_type_code(value: &str) -> Option<u8> {
    match value {
        "image/png" => Some(1),
        "image/jpeg" => Some(2),
        "image/webp" => Some(3),
        _ => None,
    }
}

fn avatar_type_name(value: u8) -> Option<&'static str> {
    match value {
        1 => Some("image/png"),
        2 => Some("image/jpeg"),
        3 => Some("image/webp"),
        _ => None,
    }
}

/// A sealed profile as it travels: chat-proto's `PutChatProfileRequest`
/// (and, without the owner's fields, `ChatProfileResponse`) field for field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedProfile {
    pub suite: ProfileSuiteId,
    pub account: AccountRef,
    pub version: String,
    pub revision: u64,
    pub source_device_id: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// The owner's fields: empty in a profile someone else fetched.
    #[serde(default)]
    pub wrapped_key: String,
    #[serde(default)]
    pub access_key_verifier: String,
    #[serde(default)]
    pub delivery_capability_verifier: String,
}

/// A profile's contents, to seal or as opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileContents {
    pub display_name: String,
    pub avatar: Option<Vec<u8>>,
    pub avatar_content_type: Option<String>,
    pub about: Option<String>,
}

/// An opened profile: its key, contents, revision and source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedProfile {
    pub key: Zeroizing<[u8; PROFILE_KEY_BYTES]>,
    pub contents: ProfileContents,
    pub revision: u64,
    pub source_device_id: u32,
}

fn context(
    purpose: ProfileEnvelopePurpose,
    account: &AccountRef,
    version: &str,
    revision: u64,
    source_device_id: u32,
) -> CryptoResult<ProfileEnvelopeContextV1> {
    ProfileEnvelopeContextV1::new(purpose, account, version, revision, source_device_id)
        .map_err(|error| invalid(&error))
}

/// Seals `contents` under `key` (revision `revision`, from
/// `source_device_id`) for `account`, with the owner's copy of the key
/// sealed for `owner`. Validates the contents first.
pub fn seal_profile(
    key: &[u8; PROFILE_KEY_BYTES],
    contents: &ProfileContents,
    revision: u64,
    source_device_id: u32,
    owner: &ProfileOwnerKey,
    account: &AccountRef,
) -> CryptoResult<SealedProfile> {
    let display_name = validate_display_name(&contents.display_name)?;
    validate_avatar(
        contents.avatar.as_deref(),
        contents.avatar_content_type.as_deref(),
    )?;
    let about = validate_about(contents.about.as_deref())?;
    let version = profile_version(key)?;
    let name = seal_padded_text(
        &display_name,
        &PROFILE_NAME_PADDED_LENGTHS,
        key,
        &context(
            ProfileEnvelopePurpose::DisplayName,
            account,
            &version,
            revision,
            source_device_id,
        )?,
    )?;
    let avatar = match (&contents.avatar, &contents.avatar_content_type) {
        (Some(bytes), Some(kind)) => {
            let mut plaintext = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
            plaintext.push(avatar_type_code(kind).expect("validated avatar type"));
            plaintext.extend_from_slice(bytes);
            Some(seal_item(
                &plaintext,
                key,
                &context(
                    ProfileEnvelopePurpose::Avatar,
                    account,
                    &version,
                    revision,
                    source_device_id,
                )?,
            )?)
        }
        _ => None,
    };
    let about = about
        .as_deref()
        .map(|about| {
            seal_padded_text(
                about,
                &PROFILE_ABOUT_PADDED_LENGTHS,
                key,
                &context(
                    ProfileEnvelopePurpose::About,
                    account,
                    &version,
                    revision,
                    source_device_id,
                )?,
            )
        })
        .transpose()?;
    let wrapped_key = wrap_profile_key(key, owner, revision)?;
    let delivery = derive_delivery_capability(key, account)?;
    Ok(SealedProfile {
        suite: ProfileSuiteId::XChaCha20Poly1305V1,
        account: account.clone(),
        version,
        revision,
        source_device_id,
        name,
        avatar,
        about,
        wrapped_key,
        access_key_verifier: access_key_verifier(&profile_access_key(key)?),
        delivery_capability_verifier: hex::encode(capability_hash(&delivery)),
    })
}

/// The owner opens their own sealed profile: the key from its wrapped copy,
/// checked against the version and both verifiers, then the items.
pub fn open_own_profile(
    sealed: &SealedProfile,
    owner: &ProfileOwnerKey,
    account: &AccountRef,
) -> CryptoResult<OpenedProfile> {
    if sealed.suite != ProfileSuiteId::XChaCha20Poly1305V1 || sealed.account != *account {
        return Err(invalid("encrypted profile suite or account does not match"));
    }
    let key = unwrap_profile_key(&sealed.wrapped_key, owner, &sealed.version, sealed.revision)?;
    if access_key_verifier(&profile_access_key(key.as_slice())?) != sealed.access_key_verifier {
        return Err(invalid(
            "wrapped profile key does not match access verifier",
        ));
    }
    let delivery = derive_delivery_capability(&key, account)?;
    if hex::encode(capability_hash(&delivery)) != sealed.delivery_capability_verifier {
        return Err(invalid(
            "wrapped profile key does not match delivery capability verifier",
        ));
    }
    let contents = open_items(sealed, &key)?;
    Ok(OpenedProfile {
        key,
        contents,
        revision: sealed.revision,
        source_device_id: sealed.source_device_id,
    })
}

/// Someone else's fetched profile, opened with the key they gave.
pub fn open_peer_profile(
    sealed: &SealedProfile,
    account: &AccountRef,
    key: &[u8],
) -> CryptoResult<OpenedProfile> {
    if sealed.suite != ProfileSuiteId::XChaCha20Poly1305V1 || sealed.account != *account {
        return Err(invalid(
            "encrypted peer profile context does not match the requested account",
        ));
    }
    let key = Zeroizing::new(profile_key(key)?);
    if profile_version(key.as_slice())? != sealed.version {
        return Err(invalid("peer profile key does not match profile version"));
    }
    let contents = open_items(sealed, &key)?;
    Ok(OpenedProfile {
        key,
        contents,
        revision: sealed.revision,
        source_device_id: sealed.source_device_id,
    })
}

fn open_items(sealed: &SealedProfile, key: &[u8; 32]) -> CryptoResult<ProfileContents> {
    let (account, version, revision, source) = (
        &sealed.account,
        &sealed.version,
        sealed.revision,
        sealed.source_device_id,
    );
    let display_name = open_padded_text(
        &sealed.name,
        &PROFILE_NAME_PADDED_LENGTHS,
        key,
        &context(
            ProfileEnvelopePurpose::DisplayName,
            account,
            version,
            revision,
            source,
        )?,
    )
    .map_err(|_| invalid("encrypted profile name is invalid"))?;
    let display_name = validate_display_name(&display_name)?;
    let (avatar, avatar_content_type) = match &sealed.avatar {
        None => (None, None),
        Some(value) => {
            let plaintext = open_item(
                value,
                key,
                &context(
                    ProfileEnvelopePurpose::Avatar,
                    account,
                    version,
                    revision,
                    source,
                )?,
            )?;
            let (&kind, bytes) = plaintext
                .split_first()
                .ok_or_else(|| invalid("encrypted profile avatar is empty"))?;
            if bytes.is_empty() || bytes.len() > MAX_PROFILE_AVATAR_BYTES {
                return Err(invalid("encrypted profile avatar has an invalid size"));
            }
            let kind =
                avatar_type_name(kind).ok_or_else(|| invalid("profile avatar type is invalid"))?;
            (Some(bytes.to_vec()), Some(kind.to_string()))
        }
    };
    let about = match &sealed.about {
        None => None,
        Some(value) => {
            let text = open_padded_text(
                value,
                &PROFILE_ABOUT_PADDED_LENGTHS,
                key,
                &context(
                    ProfileEnvelopePurpose::About,
                    account,
                    version,
                    revision,
                    source,
                )?,
            )?;
            validate_about(Some(&text))
                .map_err(|_| invalid("encrypted profile about is invalid"))?
        }
    };
    Ok(ProfileContents {
        display_name,
        avatar,
        avatar_content_type,
        about,
    })
}

/// The account app's next profile revision: over `current` (the same key,
/// one revision later) or the first, under a fresh key. Only the owner's
/// key takes part; the source is [`ACCOUNT_PROFILE_SOURCE`].
pub fn seal_account_profile(
    owner: &ProfileOwnerKey,
    current: Option<&SealedProfile>,
    contents: &ProfileContents,
    account: &AccountRef,
) -> CryptoResult<SealedProfile> {
    let (key, revision) = match current {
        Some(current) => {
            let opened = open_own_profile(current, owner, account)?;
            let revision = opened
                .revision
                .checked_add(1)
                .ok_or_else(|| invalid("profile revision is exhausted"))?;
            (opened.key, revision)
        }
        None => (Zeroizing::new(crate::primitives::random_array::<32>()), 1),
    };
    seal_profile(
        &key,
        contents,
        revision,
        ACCOUNT_PROFILE_SOURCE,
        owner,
        account,
    )
}

#[cfg(test)]
mod tests;
