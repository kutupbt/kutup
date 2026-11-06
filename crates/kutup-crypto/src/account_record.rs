//! The one envelope for every account-private sealed value
//! (`AccountRecordV1`, docs/plans/w1-account-record.md).
//!
//! The complete wire value is stored as one canonical base64 string. The
//! header is authenticated as AEAD associated data, so a server-controlled
//! database cannot relocate a record between accounts, purposes or objects,
//! or pass an older revision as newer:
//!
//! ```text
//! magic "KUTPAR1\0" ‖ suite u16 ‖ purpose u16 ‖ master-key generation u32 ‖
//! u16 len ‖ key binding ‖ u8 len ‖ object ‖ [revision u64] ‖
//! nonce 24 ‖ ciphertext length u32 ‖ ciphertext
//! ```
//!
//! Each record has its own AEAD key, derived from the wrapping key (a
//! password's key-encryption key, the recovery entropy, the master key) with
//! the suite's KDF over the header before the nonce, so no long-lived key is
//! ever used raw. A purpose's policy fixes its object, revision, padding and
//! maximum length: these define the format, the same on every server and in
//! every client, and are never site settings.

use crate::primitives::{Aead, Kdf, Suite};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
pub use crate::padding::Length;

const MAGIC: &[u8; 8] = b"KUTPAR1\0";
const GENERATION_LEN: usize = 4;
const FIXED_PREFIX_LEN: usize = MAGIC.len() + 2 + 2 + GENERATION_LEN + 2;
const NONCE_LEN: usize = 24;
const LENGTH_LEN: usize = 4;
const REVISION_LEN: usize = 8;
const TAG_LEN: usize = 16;
/// A key binding: a canonical UUID's 36 characters.
const MAX_CONTEXT_LEN: usize = 36;
/// The longest object id a record names.
pub const MAX_OBJECT_LEN: usize = 64;
const KEY_SALT: &[u8] = crate::labels::ACCOUNT_RECORD_V1;
const KEY_INFO: &[u8] = crate::labels::ACCOUNT_RECORD_KEY_V1;
const COMMIT_INFO: &[u8] = crate::labels::ACCOUNT_RECORD_COMMIT_V1;
const OBJECT_ID_INFO: &[u8] = crate::labels::ACCOUNT_RECORD_OBJECT_ID_V1;
/// The key commitment's length (see [`record_keys`]).
const COMMITMENT_LEN: usize = 32;
/// The previous record's digest in a chained purpose's header.
const PREVIOUS_LEN: usize = 32;

/// Which master key an account secret belongs to: the generation of the MK
/// a password or recovery wrap holds, or of the MK that sealed any other
/// secret (docs/plans/w6-key-hierarchy.md §2). Every envelope names it in
/// its authenticated header, so a future MK rotation can keep the old MK in
/// a keyring sealed under the new one and re-seal lazily, with no wipe.
/// Never 0; [`MasterKeyGeneration::FIRST`] is the only one until rotation
/// is built (docs/plans/account-identity-key.md, "Device removal"). W1's
/// account records name it with this same type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MasterKeyGeneration(u32);

impl MasterKeyGeneration {
    /// An account's first master key.
    pub const FIRST: Self = Self(1);

    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            return Err(CryptoError::InvalidInput(
                "a master-key generation is never 0".into(),
            ));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Closed registry of account-record suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountRecordSuiteId {
    /// The primitives' suite V1: a per-record key from HKDF-SHA256 over the
    /// header, XChaCha20-Poly1305.
    V1 = 1,
}

impl AccountRecordSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for AccountRecordSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown account-record suite {value}"
            ))),
        }
    }
}

/// The longest record of `purpose`, its largest header included.
pub const fn max_record_len(purpose: AccountRecordPurpose) -> usize {
    FIXED_PREFIX_LEN
        + MAX_CONTEXT_LEN
        + 1
        + MAX_OBJECT_LEN
        + REVISION_LEN
        + PREVIOUS_LEN
        + COMMITMENT_LEN
        + NONCE_LEN
        + LENGTH_LEN
        + purpose.policy().max_len
        + TAG_LEN
}

/// The one length of every record of `purpose`, when its padding, object and
/// revision are all fixed (the key binding is always a canonical UUID's 36
/// characters): what a server can require exactly, so records of the purpose
/// can't be told apart by their length. None when the length varies.
pub const fn exact_record_len(purpose: AccountRecordPurpose) -> Option<usize> {
    let policy = purpose.policy();
    let padded = match policy.length {
        Length::Exact(n) | Length::Fixed(n) => n,
        Length::Bucket(_) => return None,
    };
    let object = match policy.object {
        ObjectPolicy::None => 0,
        ObjectPolicy::Required(n) => n,
    };
    let revision = if policy.mutable { REVISION_LEN } else { 0 };
    let previous = if policy.chained { PREVIOUS_LEN } else { 0 };
    Some(
        FIXED_PREFIX_LEN
            + MAX_CONTEXT_LEN
            + 1
            + object
            + revision
            + previous
            + COMMITMENT_LEN
            + NONCE_LEN
            + LENGTH_LEN
            + padded
            + TAG_LEN,
    )
}

/// The longest canonical base64 of a record of `purpose`: a server refuses a
/// longer value before decoding it.
pub const fn max_record_b64_len(purpose: AccountRecordPurpose) -> usize {
    max_record_len(purpose).div_ceil(3) * 4
}

/// [`decode_canonical_b64`] for a record of `purpose`, refusing a value too
/// long to be one before decoding it.
pub fn decode_record_b64(value: &str, purpose: AccountRecordPurpose) -> Result<Vec<u8>> {
    if value.len() > max_record_b64_len(purpose) {
        return Err(CryptoError::InvalidInput(
            "account-record is longer than its purpose allows".into(),
        ));
    }
    decode_canonical_b64(value)
}

/// What a record is, in its authenticated header: a closed registry, one
/// line per kind of account-private value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountRecordPurpose {
    PasswordMasterKey = 1,
    RecoveryMasterKey = 2,
    // 3 was the Drive X-Wing private key, which is derived from the master
    // key and never stored (docs/plans/w6-key-hierarchy.md §1): reserved,
    // never reused.
    ChatBackupRoot = 4,
    /// A mail address's OpenPGP secret key (`mail_key`).
    MailAddressPrivateKey = 5,
    /// A Kutup Pass vault's password and key file (`pass_vault`).
    PassVaultSecret = 6,
    /// An organization key's seed, an owner's or admin's own copy
    /// (docs/plans/organizations.md §3); its object is the key's id.
    OrganizationPrivateKey = 7,
    /// A contact's vCard (`contact_card`); its object is the SHA-256 of the
    /// contact's UID, which the server reads from the card's signed summary
    /// (Proton's model), so it checks the card is that contact's.
    ContactCard = 8,
    /// A mail folder's, label's or filter's name (`mail_names`); its object
    /// is the kind byte and the 16-byte id.
    MailName = 9,
    /// The account's one identity-pin list (`identity_pins`).
    IdentityPins = 10,
    /// One entry of the account's Chat group list (`chat_group_list`); its
    /// object is [`hashed_object`] of the group id, so the server never sees
    /// a group id.
    ChatGroupListEntry = 11,
    /// One entry of the account's Chat contact list (`chat_contact_list`); its
    /// object is [`hashed_object`] of the contact's account, so the server
    /// never sees whom an entry is about.
    ChatContactListEntry = 12,
    /// The account's Photos library (`photos_library`); its object is the
    /// account incarnation, and its records form a chain.
    PhotosLibrary = 13,
    /// One entry of the account's Chat attachment ledger
    /// (`chat_attachment_ledger`); its object is the account incarnation and
    /// the entry's id (48 bytes), and its records form a chain.
    ChatAttachmentLedger = 14,
    /// One meeting the account joined (`chat_call_link`); its object is the
    /// row id the client chose (16 bytes), so a record can't be swapped for
    /// another's.
    JoinedMeeting = 15,
    /// The account's own copy of its Chat profile key: the object is the
    /// profile version the key derives (32 bytes), the revision the
    /// profile's, so a copy can't be moved to another profile or revision.
    ChatProfileKeyWrap = 16,
    /// The account head (`account_head`): no object, its revision the head's
    /// sequence, chained, so the server checks a head's predecessor from the
    /// header alone.
    AccountHead = 17,
    /// A device's own account-head state (`account_head`), never sent to a
    /// server: its object is the account incarnation, so it opens for no
    /// other account or incarnation.
    AccountLocalAnchor = 18,
    /// The highest revision a device has seen of one value
    /// (`revision_guard`), never sent to a server: its object is
    /// [`hashed_object`] of the value's scope and id, which is also the name
    /// the device stores it under.
    RevisionSeen = 19,
    /// A device's mail-search store key (`mail_search`), never sent to a
    /// server: one per account.
    MailSearchStoreKey = 20,
}

/// The object of a record whose id the server must not see (a group id, the
/// account a contact entry is about): `HMAC(K_id, purpose ‖ id)`, where
/// `K_id = KDF(master key, salt kutup/account-record/v1, info
/// kutup/account-record/object-id/v1)`. Stable while the master key is, so
/// the server keeps one row per record; a master-key rotation moves every
/// such record to its new id (docs/plans/w6-key-hierarchy.md, "Rotation
/// checklist").
pub fn hashed_object(master_key: &[u8; 32], purpose: AccountRecordPurpose, id: &[u8]) -> [u8; 32] {
    let mut id_key = Zeroizing::new([0u8; 32]);
    Kdf::new(Suite::V1, KEY_SALT, master_key)
        .expand(OBJECT_ID_INFO, id_key.as_mut_slice())
        .expect("a 32-byte HKDF output is valid");
    crate::primitives::mac(
        Suite::V1,
        id_key.as_ref(),
        &[&purpose.as_u16().to_be_bytes(), id],
    )
    .to_array()
}

/// The longest padded length of `max` bytes in 256-byte buckets (`0x80`
/// marker, then zeros).
const fn bucketed(max: usize) -> usize {
    (max / 256 + 1) * 256
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
    /// The longest padded plaintext a record of the purpose holds. A format
    /// limit, not a setting (see the module doc).
    pub max_len: usize,
    /// A chain: each record names the SHA-256 of the one before it
    /// ([`record_digest`]) in its header, after the revision (zeros at
    /// revision 1), so a server can require each write to follow the one it
    /// holds, and a reader can check the history it is shown. Only for
    /// mutable purposes.
    pub chained: bool,
}

impl AccountRecordPurpose {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn policy(self) -> PurposePolicy {
        const KEY: PurposePolicy = PurposePolicy {
            object: ObjectPolicy::None,
            length: Length::Exact(32),
            mutable: false,
            max_len: 32,
            chained: false,
        };
        match self {
            Self::PasswordMasterKey | Self::RecoveryMasterKey | Self::ChatBackupRoot => KEY,
            // The address and the key's algorithm decide its length.
            Self::MailAddressPrivateKey => PurposePolicy {
                object: ObjectPolicy::None,
                length: Length::Bucket(256),
                mutable: false,
                max_len: 4096,
                chained: false,
            },
            // One per vault (its Drive file id), replaced when the vault's
            // key changes; every one the same length, so the size does not
            // tell a generated key from a chosen one or a key file's size.
            Self::PassVaultSecret => PurposePolicy {
                object: ObjectPolicy::Required(16),
                length: Length::Fixed(crate::pass_vault::MAX_PAYLOAD_LEN + 1),
                mutable: true,
                max_len: crate::pass_vault::MAX_PAYLOAD_LEN + 1,
                chained: false,
            },
            // One per organization key, named by its id.
            Self::OrganizationPrivateKey => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Exact(32),
                mutable: false,
                max_len: 32,
                chained: false,
            },
            Self::ContactCard => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Bucket(256),
                mutable: true,
                max_len: bucketed(crate::contact_card::MAX_CARD_BYTES),
                chained: false,
            },
            Self::MailName => PurposePolicy {
                object: ObjectPolicy::Required(17),
                length: Length::Bucket(256),
                mutable: true,
                max_len: bucketed(crate::mail_names::MAX_NAME_BYTES),
                chained: false,
            },
            Self::IdentityPins => PurposePolicy {
                object: ObjectPolicy::None,
                length: Length::Bucket(256),
                mutable: true,
                max_len: bucketed(crate::identity_pins::MAX_LIST_BYTES),
                chained: false,
            },
            // One size each, so an entry's length says nothing.
            Self::ChatGroupListEntry => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Fixed(crate::chat_group_list::MAX_PLAIN_LEN + 1),
                mutable: true,
                max_len: crate::chat_group_list::MAX_PLAIN_LEN + 1,
                chained: false,
            },
            Self::ChatContactListEntry => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Fixed(crate::chat_contact_list::MAX_PLAIN_LEN + 1),
                mutable: true,
                max_len: crate::chat_contact_list::MAX_PLAIN_LEN + 1,
                chained: false,
            },
            Self::PhotosLibrary => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Bucket(256),
                mutable: true,
                max_len: bucketed(crate::photos_library::MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES),
                chained: true,
            },
            Self::ChatAttachmentLedger => PurposePolicy {
                object: ObjectPolicy::Required(48),
                length: Length::Bucket(256),
                mutable: true,
                max_len: bucketed(
                    crate::chat_attachment_ledger::MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES,
                ),
                chained: true,
            },
            // One size, so a stay's length says nothing of its meeting.
            Self::JoinedMeeting => PurposePolicy {
                object: ObjectPolicy::Required(16),
                length: Length::Fixed(crate::chat_call_link::JOINED_PADDED_BYTES),
                mutable: false,
                max_len: crate::chat_call_link::JOINED_PADDED_BYTES,
                chained: false,
            },
            Self::ChatProfileKeyWrap => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Exact(32),
                mutable: true,
                max_len: 32,
                chained: false,
            },
            // A whole sealed head stays within the server's 16 KiB.
            Self::AccountHead => PurposePolicy {
                object: ObjectPolicy::None,
                length: Length::Bucket(256),
                mutable: true,
                max_len: crate::account_head::MAX_PADDED_BYTES,
                chained: true,
            },
            Self::AccountLocalAnchor => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Bucket(256),
                mutable: false,
                max_len: crate::account_head::MAX_PADDED_BYTES,
                chained: false,
            },
            Self::RevisionSeen => PurposePolicy {
                object: ObjectPolicy::Required(32),
                length: Length::Exact(8),
                mutable: false,
                max_len: 8,
                chained: false,
            },
            Self::MailSearchStoreKey => PurposePolicy {
                object: ObjectPolicy::None,
                length: Length::Exact(32),
                mutable: false,
                max_len: 32,
                chained: false,
            },
        }
    }

    /// Every purpose, for tests and vectors.
    pub const ALL: [Self; 19] = [
        Self::PasswordMasterKey,
        Self::RecoveryMasterKey,
        Self::ChatBackupRoot,
        Self::MailAddressPrivateKey,
        Self::PassVaultSecret,
        Self::OrganizationPrivateKey,
        Self::ContactCard,
        Self::MailName,
        Self::IdentityPins,
        Self::ChatGroupListEntry,
        Self::ChatContactListEntry,
        Self::PhotosLibrary,
        Self::ChatAttachmentLedger,
        Self::JoinedMeeting,
        Self::ChatProfileKeyWrap,
        Self::AccountHead,
        Self::AccountLocalAnchor,
        Self::RevisionSeen,
        Self::MailSearchStoreKey,
    ];
}

impl TryFrom<u16> for AccountRecordPurpose {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::PasswordMasterKey),
            2 => Ok(Self::RecoveryMasterKey),
            4 => Ok(Self::ChatBackupRoot),
            5 => Ok(Self::MailAddressPrivateKey),
            6 => Ok(Self::PassVaultSecret),
            7 => Ok(Self::OrganizationPrivateKey),
            8 => Ok(Self::ContactCard),
            9 => Ok(Self::MailName),
            10 => Ok(Self::IdentityPins),
            11 => Ok(Self::ChatGroupListEntry),
            12 => Ok(Self::ChatContactListEntry),
            13 => Ok(Self::PhotosLibrary),
            14 => Ok(Self::ChatAttachmentLedger),
            15 => Ok(Self::JoinedMeeting),
            16 => Ok(Self::ChatProfileKeyWrap),
            17 => Ok(Self::AccountHead),
            18 => Ok(Self::AccountLocalAnchor),
            19 => Ok(Self::RevisionSeen),
            20 => Ok(Self::MailSearchStoreKey),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown account-record purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRecordHeader {
    pub suite: AccountRecordSuiteId,
    pub purpose: AccountRecordPurpose,
    /// The master key the secret belongs to.
    pub generation: MasterKeyGeneration,
    /// What the account is bound by: its key binding, canonical.
    pub canonical_binding: String,
    /// The object the secret belongs to (empty when the purpose has one
    /// secret per account).
    pub object_id: Vec<u8>,
    /// The secret's revision, for a mutable purpose (never 0).
    pub revision: Option<u64>,
    /// The previous record's digest, for a chained purpose (zeros at
    /// revision 1).
    pub previous: Option<[u8; PREVIOUS_LEN]>,
    pub ciphertext_len: u32,
}

struct ParsedEnvelope<'a> {
    header: AccountRecordHeader,
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
        .map_err(|_| CryptoError::InvalidInput("account-record binding is invalid".into()))
}

/// Refuses an object id or revision the purpose does not take.
fn check_shape(
    purpose: AccountRecordPurpose,
    object_id: &[u8],
    revision: Option<u64>,
    previous: Option<&[u8; PREVIOUS_LEN]>,
) -> Result<()> {
    let policy = purpose.policy();
    let object_ok = match policy.object {
        ObjectPolicy::None => object_id.is_empty(),
        ObjectPolicy::Required(len) => object_id.len() == len,
    };
    if !object_ok || object_id.len() > MAX_OBJECT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-record object id does not fit its purpose".into(),
        ));
    }
    match (policy.mutable, revision) {
        (true, Some(revision)) if revision > 0 => {}
        (false, None) => {}
        _ => {
            return Err(CryptoError::InvalidInput(
                "account-record revision does not fit its purpose".into(),
            ))
        }
    }
    // A chain starts at revision 1 with no predecessor (zeros) and names one
    // at every later revision.
    match (policy.chained, previous, revision) {
        (false, None, _) => Ok(()),
        (true, Some(previous), Some(revision))
            if (revision == 1) == (previous == &[0u8; PREVIOUS_LEN]) =>
        {
            Ok(())
        }
        _ => Err(CryptoError::InvalidInput(
            "account-record chain does not fit its purpose".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_header(
    suite: AccountRecordSuiteId,
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    previous: Option<&[u8; PREVIOUS_LEN]>,
) -> Result<Vec<u8>> {
    let context_len = u16::try_from(binding.len())
        .map_err(|_| CryptoError::InvalidInput("account-record context is too long".into()))?;
    let mut header = Vec::with_capacity(
        FIXED_PREFIX_LEN
            + binding.len()
            + 1
            + object_id.len()
            + REVISION_LEN
            + PREVIOUS_LEN
            + COMMITMENT_LEN
            + NONCE_LEN
            + LENGTH_LEN,
    );
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&suite.as_u16().to_be_bytes());
    header.extend_from_slice(&purpose.as_u16().to_be_bytes());
    header.extend_from_slice(&generation.get().to_be_bytes());
    header.extend_from_slice(&context_len.to_be_bytes());
    header.extend_from_slice(binding.as_bytes());
    header.push(u8::try_from(object_id.len()).expect("checked object length"));
    header.extend_from_slice(object_id);
    if let Some(revision) = revision {
        header.extend_from_slice(&revision.to_be_bytes());
    }
    if let Some(previous) = previous {
        header.extend_from_slice(previous);
    }
    Ok(header)
}

/// The keyed part followed by the key commitment, the nonce and the
/// ciphertext length: the whole header, and the record's AEAD key.
fn finish_header(
    key: &[u8],
    keyed: Vec<u8>,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let (aead, commitment) = record_keys(key, &keyed)?;
    let mut header = keyed;
    header.extend_from_slice(&commitment);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok((header, aead))
}

/// A record's AEAD key and its key commitment, both derived from the
/// wrapping key over the header before the commitment (`keyed`), so every
/// record of another purpose, account, object, generation or revision has a
/// key of its own. XChaCha20-Poly1305 does not commit to its key: a record
/// could be crafted to open under several candidate keys (a partitioning
/// oracle on password-derived keys). The commitment, a second output of the
/// same derivation kept in the header, closes that: a record opens only
/// under the key that derives its commitment, checked before the AEAD.
fn record_keys(key: &[u8], keyed: &[u8]) -> Result<(Zeroizing<[u8; 32]>, [u8; COMMITMENT_LEN])> {
    let kdf = Kdf::new(Suite::V1, KEY_SALT, key);
    let expand = |label: &[u8], out: &mut [u8]| {
        let mut info = Vec::with_capacity(label.len() + keyed.len());
        info.extend_from_slice(label);
        info.extend_from_slice(keyed);
        kdf.expand(&info, out)
            .map_err(|_| CryptoError::Backend("account-record key".into()))
    };
    let mut aead = Zeroizing::new([0u8; 32]);
    expand(KEY_INFO, aead.as_mut_slice())?;
    let mut commitment = [0u8; COMMITMENT_LEN];
    expand(COMMIT_INFO, &mut commitment)?;
    Ok((aead, commitment))
}

/// The header before the commitment: what a record's keys are derived over.
fn keyed_part(header: &[u8]) -> &[u8] {
    &header[..header.len() - COMMITMENT_LEN - NONCE_LEN - LENGTH_LEN]
}

/// The key commitment a header carries.
fn commitment_of(header: &[u8]) -> &[u8] {
    let end = header.len() - NONCE_LEN - LENGTH_LEN;
    &header[end - COMMITMENT_LEN..end]
}

/// A record's AEAD key, as derived for it: for checked-in vectors only
/// (they pin this intermediate step).
pub fn aead_key_for_vectors(key: &[u8], record: &[u8]) -> Result<[u8; 32]> {
    check_key(key)?;
    let parsed = parse(record)?;
    Ok(*record_keys(key, keyed_part(parsed.aad))?.0)
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
    crate::primitives::random(&mut nonce);
    nonce
}

/// Seals a secret of `purpose` (one per account) for the account bound by
/// `binding`.
pub fn seal(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
) -> Result<Vec<u8>> {
    seal_object(plaintext, key, purpose, generation, binding, &[])
}

/// Seals a secret of `purpose` belonging to `object_id`.
pub fn seal_object(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
) -> Result<Vec<u8>> {
    seal_suite(
        AccountRecordSuiteId::V1,
        plaintext,
        key,
        purpose,
        generation,
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
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
    revision: u64,
) -> Result<Vec<u8>> {
    seal_suite(
        AccountRecordSuiteId::V1,
        plaintext,
        key,
        purpose,
        generation,
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
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_suite(
        AccountRecordSuiteId::V1,
        plaintext,
        key,
        purpose,
        generation,
        binding,
        &[],
        None,
        nonce,
    )
}

/// Any suite, object, revision and nonce: for checked-in vectors only.
#[allow(clippy::too_many_arguments)]
pub fn seal_suite(
    suite: AccountRecordSuiteId,
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_record(
        suite, plaintext, key, purpose, generation, binding, object_id, revision, None, nonce,
    )
}

/// Seals revision `revision` of a chained purpose's record, after the record
/// whose digest is `previous` (zeros at revision 1).
#[allow(clippy::too_many_arguments)]
pub fn seal_chained(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
    revision: u64,
    previous: &[u8; PREVIOUS_LEN],
    nonce: Option<&[u8; NONCE_LEN]>,
) -> Result<Vec<u8>> {
    let nonce = nonce.copied().unwrap_or_else(random_nonce);
    seal_record(
        AccountRecordSuiteId::V1,
        plaintext,
        key,
        purpose,
        generation,
        binding,
        object_id,
        Some(revision),
        Some(previous),
        &nonce,
    )
}

/// The digest a chained record's successor names as its `previous`: the
/// SHA-256 of the whole record.
pub fn record_digest(record: &[u8]) -> [u8; PREVIOUS_LEN] {
    crate::primitives::hash(Suite::V1, record).to_array()
}

#[allow(clippy::too_many_arguments)]
fn seal_record(
    suite: AccountRecordSuiteId,
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    previous: Option<&[u8; PREVIOUS_LEN]>,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    check_key(key)?;
    check_shape(purpose, object_id, revision, previous)?;
    let padded = Zeroizing::new(purpose.policy().length.pad(plaintext)?);
    if padded.is_empty() || padded.len() > purpose.policy().max_len {
        return Err(CryptoError::InvalidInput(
            "account-record plaintext length is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let binding = canonical_binding(binding)?;
    let ciphertext_len = u32::try_from(padded.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("account-record plaintext is too long".into()))?;
    let keyed = build_header(
        suite, purpose, generation, &binding, object_id, revision, previous,
    )?;
    let (header, aead) = finish_header(key, keyed, &nonce, ciphertext_len)?;
    let ciphertext = Aead::new(Suite::V1, aead.as_ref())?
        .seal_with_nonce(&nonce, &header, &padded)
        .map_err(|_| CryptoError::Backend("account-record seal".into()))?;
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
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
    object_id: &[u8],
    revision: Option<u64>,
    previous: Option<&[u8; PREVIOUS_LEN]>,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let suite = AccountRecordSuiteId::V1;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("too long".into()))?;
    let keyed = build_header(
        suite, purpose, generation, binding, object_id, revision, previous,
    )?;
    let (header, aead) = finish_header(key, keyed, nonce, ciphertext_len)?;
    let ciphertext = Aead::new(Suite::V1, aead.as_ref())?
        .seal_with_nonce(nonce, &header, plaintext)
        .map_err(|_| CryptoError::Backend("account-record seal".into()))?;
    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn parse(envelope: &[u8]) -> Result<ParsedEnvelope<'_>> {
    let minimum = FIXED_PREFIX_LEN + 1 + COMMITMENT_LEN + NONCE_LEN + LENGTH_LEN + TAG_LEN;
    if envelope.len() < minimum || envelope.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(CryptoError::TooShort);
    }
    let mut cursor = MAGIC.len();
    let suite = AccountRecordSuiteId::try_from(u16::from_be_bytes([
        envelope[cursor],
        envelope[cursor + 1],
    ]))?;
    cursor += 2;
    let purpose = AccountRecordPurpose::try_from(u16::from_be_bytes([
        envelope[cursor],
        envelope[cursor + 1],
    ]))?;
    cursor += 2;
    let generation = MasterKeyGeneration::new(u32::from_be_bytes(
        envelope[cursor..cursor + GENERATION_LEN]
            .try_into()
            .expect("four-byte slice"),
    ))?;
    cursor += GENERATION_LEN;
    let context_len = usize::from(u16::from_be_bytes([envelope[cursor], envelope[cursor + 1]]));
    cursor += 2;
    if context_len == 0 || context_len > MAX_CONTEXT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-record context length is invalid".into(),
        ));
    }
    let after_context = cursor
        .checked_add(context_len)
        .ok_or(CryptoError::TooShort)?;
    if after_context >= envelope.len() {
        return Err(CryptoError::TooShort);
    }
    let context = std::str::from_utf8(&envelope[cursor..after_context])
        .map_err(|_| CryptoError::InvalidInput("account-record context is not UTF-8".into()))?;
    let canonical = canonical_binding(context)?;
    if canonical != context {
        return Err(CryptoError::InvalidInput(
            "account-record context is not canonical".into(),
        ));
    }
    let object_len = usize::from(envelope[after_context]);
    if object_len > MAX_OBJECT_LEN {
        return Err(CryptoError::InvalidInput(
            "account-record object id is too long".into(),
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
    let previous_len = if purpose.policy().chained {
        PREVIOUS_LEN
    } else {
        0
    };
    let after_revision = after_object
        .checked_add(revision_len)
        .ok_or(CryptoError::TooShort)?;
    let after_previous = after_revision
        .checked_add(previous_len)
        .ok_or(CryptoError::TooShort)?;
    if after_previous > envelope.len() {
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
    let previous: Option<[u8; PREVIOUS_LEN]> = (previous_len > 0).then(|| {
        envelope[after_revision..after_previous]
            .try_into()
            .expect("32-byte slice")
    });
    check_shape(purpose, &object_id, revision, previous.as_ref())?;
    let after_commitment = after_previous
        .checked_add(COMMITMENT_LEN)
        .ok_or(CryptoError::TooShort)?;
    let after_nonce = after_commitment
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
        .map_err(|_| CryptoError::InvalidInput("account-record ciphertext is too long".into()))?;
    if !(TAG_LEN + 1..=purpose.policy().max_len + TAG_LEN).contains(&ciphertext_len_usize)
        || !purpose
            .policy()
            .length
            .allows_padded_len(ciphertext_len_usize - TAG_LEN)
        || after_length.checked_add(ciphertext_len_usize) != Some(envelope.len())
    {
        return Err(CryptoError::InvalidInput(
            "account-record ciphertext length is invalid".into(),
        ));
    }
    Ok(ParsedEnvelope {
        header: AccountRecordHeader {
            suite,
            purpose,
            generation,
            canonical_binding: canonical,
            object_id,
            revision,
            previous,
            ciphertext_len,
        },
        aad: &envelope[..after_length],
        nonce: &envelope[after_commitment..after_nonce],
        ciphertext: &envelope[after_length..],
    })
}

/// The header of a well-formed envelope (its purpose's object, revision and
/// length rules hold), without opening it.
pub fn inspect(envelope: &[u8]) -> Result<AccountRecordHeader> {
    Ok(parse(envelope)?.header)
}

/// What a server checks before it stores an envelope: well formed, of
/// `expected_purpose`, for the account bound by `expected_binding` and the
/// object `expected_object` (empty when the purpose names none). Suite 1 and
/// any unknown suite never parse. Returns the header (its revision, for a
/// mutable purpose).
pub fn validate_for(
    envelope: &[u8],
    expected_purpose: AccountRecordPurpose,
    expected_binding: &str,
    expected_object: &[u8],
) -> Result<AccountRecordHeader> {
    let header = parse(envelope)?.header;
    if header.purpose != expected_purpose
        || header.canonical_binding != canonical_binding(expected_binding)?
        || header.object_id != expected_object
    {
        return Err(CryptoError::InvalidInput(
            "account-record binding does not match".into(),
        ));
    }
    Ok(header)
}

/// Opens an envelope of a purpose with no object and no revision.
pub fn open(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountRecordPurpose,
    expected_binding: &str,
) -> Result<Vec<u8>> {
    open_object(envelope, key, expected_purpose, expected_binding, &[])
}

/// Opens an envelope sealed for `object_id` (a purpose with no revision).
pub fn open_object(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountRecordPurpose,
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
    expected_purpose: AccountRecordPurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<(Vec<u8>, u64)> {
    let (plain, header) = open_any(envelope, key, expected_purpose, expected_binding, object_id)?;
    let revision = header.revision.ok_or_else(|| {
        CryptoError::InvalidInput("this purpose's secrets have no revision".into())
    })?;
    Ok((plain, revision))
}

/// Opens a chained record: its plaintext, its revision and the digest of
/// the record it follows (zeros at revision 1). The caller checks the chain
/// (each record's `previous` is the [`record_digest`] of the one before).
pub fn open_chained(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountRecordPurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<(Vec<u8>, u64, [u8; PREVIOUS_LEN])> {
    if !expected_purpose.policy().chained {
        return Err(CryptoError::InvalidInput(
            "this purpose's records are not chained".into(),
        ));
    }
    let (plain, header) = open_any(envelope, key, expected_purpose, expected_binding, object_id)?;
    let revision = header.revision.expect("a chained purpose is mutable");
    let previous = header
        .previous
        .expect("a chained record names its predecessor");
    Ok((plain, revision, previous))
}

fn open_any(
    envelope: &[u8],
    key: &[u8],
    expected_purpose: AccountRecordPurpose,
    expected_binding: &str,
    object_id: &[u8],
) -> Result<(Vec<u8>, AccountRecordHeader)> {
    check_key(key)?;
    let parsed = parse(envelope)?;
    if parsed.header.purpose != expected_purpose
        || parsed.header.canonical_binding != canonical_binding(expected_binding)?
        || parsed.header.object_id != object_id
    {
        return Err(CryptoError::AuthFailed);
    }
    let (aead, commitment) = record_keys(key, keyed_part(parsed.aad))?;
    // The key commitment first, in constant time: a record crafted to open
    // under several keys stops here.
    if !crate::primitives::ct_eq(&commitment, commitment_of(parsed.aad)) {
        return Err(CryptoError::AuthFailed);
    }
    let padded = Aead::new(Suite::V1, aead.as_ref())?
        .open_with_nonce(parsed.nonce, parsed.aad, parsed.ciphertext)
        .map_err(|_| CryptoError::AuthFailed)
        .map(crate::primitives::into_vec)?;
    let plain = expected_purpose.policy().length.unpad(padded)?;
    Ok((plain, parsed.header))
}

pub fn seal_b64(
    plaintext: &[u8],
    key: &[u8],
    purpose: AccountRecordPurpose,
    generation: MasterKeyGeneration,
    binding: &str,
) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD
        .encode(seal(plaintext, key, purpose, generation, binding)?))
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
    expected_purpose: AccountRecordPurpose,
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
            AccountRecordPurpose::PasswordMasterKey,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[0x11; 24],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_is_canonical_and_context_bound() {
        let envelope = fixture();
        let header = inspect(&envelope).unwrap();
        assert_eq!(header.suite, AccountRecordSuiteId::V1);
        assert_eq!(header.canonical_binding, BINDING);
        assert!(header.object_id.is_empty());
        assert_eq!(header.ciphertext_len, 48);
        validate_for(
            &envelope,
            AccountRecordPurpose::PasswordMasterKey,
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
                    AccountRecordPurpose::PasswordMasterKey,
                    &other,
                    &[]
                )
                .is_err(),
                "{other}"
            );
            assert!(seal_with_nonce(
                &[0x42; 32],
                &[0x24; 32],
                AccountRecordPurpose::PasswordMasterKey,
                MasterKeyGeneration::FIRST,
                &other,
                &[0x11; 24],
            )
            .is_err());
        }
        assert_eq!(
            open(
                &envelope,
                &[0x24; 32],
                AccountRecordPurpose::PasswordMasterKey,
                BINDING
            )
            .unwrap(),
            vec![0x42; 32]
        );
        // The wrapping key is never the AEAD key.
        let raw = Aead::new(Suite::V1, [0x24u8; 32].as_ref()).unwrap();
        let header_len = envelope.len() - 48;
        assert!(raw
            .open_with_nonce(
                &[0x11; 24],
                &envelope[..header_len],
                &envelope[header_len..]
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
            AccountRecordPurpose::PasswordMasterKey,
            "1b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b"
        )
        .is_err());
        assert!(open(
            &envelope,
            &key,
            AccountRecordPurpose::RecoveryMasterKey,
            BINDING
        )
        .is_err());
        assert!(open_object(
            &envelope,
            &key,
            AccountRecordPurpose::PasswordMasterKey,
            BINDING,
            &[1]
        )
        .is_err());

        let mut tampered = envelope.clone();
        tampered[10..12].copy_from_slice(
            &AccountRecordPurpose::RecoveryMasterKey
                .as_u16()
                .to_be_bytes(),
        );
        assert!(open(
            &tampered,
            &key,
            AccountRecordPurpose::RecoveryMasterKey,
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
        let envelope = seal_revision(
            &[0x42; 32],
            &key,
            AccountRecordPurpose::PassVaultSecret,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[7; 16],
            9,
        )
        .unwrap();
        assert_eq!(inspect(&envelope).unwrap().object_id, vec![7; 16]);
        assert_eq!(
            open_revision(
                &envelope,
                &key,
                AccountRecordPurpose::PassVaultSecret,
                BINDING,
                &[7; 16]
            )
            .unwrap(),
            (vec![0x42; 32], 9)
        );
        assert!(open_revision(
            &envelope,
            &key,
            AccountRecordPurpose::PassVaultSecret,
            BINDING,
            &[8; 16]
        )
        .is_err());
        // The object id must have the purpose's length.
        assert!(seal_revision(
            &[1],
            &key,
            AccountRecordPurpose::PassVaultSecret,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[0; 17],
            9
        )
        .is_err());
    }

    #[test]
    fn a_mutable_secret_carries_its_revision_authenticated() {
        let key = [0x24; 32];
        let purpose = AccountRecordPurpose::PassVaultSecret;
        let envelope = seal_revision(
            &[0x42; 32],
            &key,
            purpose,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[7; 16],
            9,
        )
        .unwrap();
        assert_eq!(inspect(&envelope).unwrap().revision, Some(9));
        // Padded to the purpose's fixed length.
        let Length::Fixed(fixed) = purpose.policy().length else {
            panic!("fixed")
        };
        assert_eq!(
            inspect(&envelope).unwrap().ciphertext_len as usize,
            fixed + TAG_LEN
        );
        // Relabelled as another revision: refused.
        let at = envelope.len()
            - (fixed + TAG_LEN)
            - LENGTH_LEN
            - NONCE_LEN
            - COMMITMENT_LEN
            - REVISION_LEN;
        let mut relabelled = envelope.clone();
        relabelled[at + REVISION_LEN - 1] ^= 1;
        assert_eq!(inspect(&relabelled).unwrap().revision, Some(8));
        assert!(open_revision(&relabelled, &key, purpose, BINDING, &[7; 16]).is_err());
        // A mutable secret needs a revision, never 0, and opens only with it.
        assert!(seal_object(
            &[1],
            &key,
            purpose,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[7; 16]
        )
        .is_err());
        assert!(seal_revision(
            &[1],
            &key,
            purpose,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[7; 16],
            0
        )
        .is_err());
        assert!(open_object(&envelope, &key, purpose, BINDING, &[7; 16]).is_err());
        // And a revision on an immutable purpose is refused.
        assert!(seal_revision(
            &[0x42; 32],
            &key,
            AccountRecordPurpose::PasswordMasterKey,
            MasterKeyGeneration::FIRST,
            BINDING,
            &[],
            1
        )
        .is_err());
    }

    #[test]
    fn unknown_suites_purposes_and_noncanonical_context_are_rejected() {
        let envelope = fixture();
        for suite in [0u8, 2, 3] {
            let mut other = envelope.clone();
            other[9] = suite;
            assert!(inspect(&other).is_err(), "suite {suite}");
        }

        // Purpose 3 (the Drive X-Wing key, now derived only) stays refused,
        // and so does a purpose with a high byte.
        assert!(AccountRecordPurpose::try_from(3).is_err());
        for purpose in [3u16, 0x0101] {
            let mut other = envelope.clone();
            other[10..12].copy_from_slice(&purpose.to_be_bytes());
            assert!(inspect(&other).is_err(), "purpose {purpose}");
        }

        let mut noncanonical = envelope;
        noncanonical[18] = b'A';
        assert!(inspect(&noncanonical).is_err());
    }

    #[test]
    fn the_master_key_generation_is_named_and_authenticated() {
        let key = [0x24; 32];
        let purpose = AccountRecordPurpose::ChatBackupRoot;
        assert!(MasterKeyGeneration::new(0).is_err());
        let seventh = MasterKeyGeneration::new(7).unwrap();
        let envelope = seal(&[0x42; 32], &key, purpose, seventh, BINDING).unwrap();
        assert_eq!(inspect(&envelope).unwrap().generation, seventh);
        assert_eq!(
            open(&envelope, &key, purpose, BINDING).unwrap(),
            vec![0x42; 32]
        );
        // Never 0 on the wire either.
        let mut zero = envelope.clone();
        zero[12..16].copy_from_slice(&0u32.to_be_bytes());
        assert!(inspect(&zero).is_err());
        // Relabelled as another master key's: well formed, but the AEAD
        // covers it.
        let mut relabelled = envelope;
        relabelled[12..16].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            inspect(&relabelled).unwrap().generation,
            MasterKeyGeneration::FIRST
        );
        assert!(open(&relabelled, &key, purpose, BINDING).is_err());
    }
}
