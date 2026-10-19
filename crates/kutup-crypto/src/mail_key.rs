//! Mail address keys (docs/plans/mail-address-keys.md).
//!
//! Every Kutup email address has OpenPGP keys, as every Proton address does.
//! They are OpenPGP v4 keys in Proton's shape (an Ed25519 primary that
//! certifies and signs, a Curve25519 encryption subkey) so every OpenPGP
//! client reads them, generated and used through rPGP.
//!
//! - The private key is kept in an [`account_envelope`] under the master key
//!   (purpose `MailAddressPrivateKey`). Its payload binds the address and the
//!   fingerprint, so a server cannot swap one address's key for another's.
//! - Each address publishes a [`MailKeyListV1`], Proton's signed key list:
//!   its keys, which is primary, and their flags, hash-chained and signed by
//!   the account authority. Whoever has pinned the account (Chat, Drive)
//!   therefore trusts its mail keys too.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use pgp::{
    composed::{
        ArmorOptions, Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder,
        SecretKeyParamsBuilder, SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
        SubkeyParamsBuilder,
    },
    crypto::{
        aead::AeadAlgorithm, ecc_curve::ECCCurve, hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm,
    },
    ser::Serialize as _,
    types::{CompressionAlgorithm, Imprint as _, KeyDetails as _, Password, Timestamp},
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::account_envelope::{self, AccountEnvelopePurpose};
use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};
use crate::identity::{authority_key_id_from_public, incarnation_id_from_authority_public};
use crate::named_share::canonical_account;

/// The key may verify signatures (Proton's `FLAG_NOT_COMPROMISED`).
pub const FLAG_NOT_COMPROMISED: u32 = 1;
/// The key may be encrypted to (Proton's `FLAG_NOT_OBSOLETE`).
pub const FLAG_NOT_OBSOLETE: u32 = 2;
/// Mail to this address is not end-to-end encrypted (Proton's `FLAG_EMAIL_NO_ENCRYPT`).
pub const FLAG_EMAIL_NO_ENCRYPT: u32 = 4;
/// Mail from this address is not expected to be signed (Proton's `FLAG_EMAIL_NO_SIGN`).
pub const FLAG_EMAIL_NO_SIGN: u32 = 8;
/// A new key's flags: usable for everything.
pub const DEFAULT_FLAGS: u32 = FLAG_NOT_COMPROMISED | FLAG_NOT_OBSOLETE;
const KNOWN_FLAGS: u32 =
    FLAG_NOT_COMPROMISED | FLAG_NOT_OBSOLETE | FLAG_EMAIL_NO_ENCRYPT | FLAG_EMAIL_NO_SIGN;

/// A v4 fingerprint.
pub const FINGERPRINT_LEN: usize = 20;
/// Keys one address may list at once (current and older ones kept to decrypt).
pub const MAX_KEYS_PER_ADDRESS: usize = 16;
const MAX_PUBLIC_KEY_LEN: usize = 16 * 1024;
const MAX_SECRET_KEY_LEN: usize = 3 * 1024;
const MAX_ISSUED_AT_LEN: usize = 64;

const PRIVATE_KEY_DOMAIN: &[u8] = b"kutup/mail-address-key/v1\0";
const KEY_LIST_DOMAIN: &[u8] = b"kutup/mail-key-list/v1\0";
const KEY_LIST_VERSION: u16 = 1;

/// A canonical address: `local@domain`, lowercase. Phase A addresses are
/// Kutup usernames on the server name, the same canonical form as accounts.
pub fn canonical_address(value: &str) -> Result<String> {
    canonical_account(value)
        .map_err(|_| CryptoError::InvalidInput("mail address is not canonical".into()))
}

/// A freshly generated address key.
pub struct GeneratedAddressKey {
    /// The binary OpenPGP transferable secret key, unlocked. Seal it with
    /// [`seal_address_key`] at once.
    pub secret_key: Zeroizing<Vec<u8>>,
    /// The binary OpenPGP public key (certificate).
    pub public_key: Vec<u8>,
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// SHA-256 over the same bytes as the v4 fingerprint (the key imprint),
    /// so lists do not rest on SHA-1 alone.
    pub sha256_fingerprint: [u8; 32],
}

/// Generates the address key for `address`, created at `created_at_secs`
/// (Unix seconds, passed in so browsers and vectors control the clock).
pub fn generate_address_key(address: &str, created_at_secs: u32) -> Result<GeneratedAddressKey> {
    let address = canonical_address(address)?;
    let created_at = Timestamp::from_secs(created_at_secs);
    let mut encryption = SubkeyParamsBuilder::default();
    encryption
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false)
        .created_at(created_at);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .created_at(created_at)
        .primary_user_id(user_id(&address))
        .preferred_symmetric_algorithms(
            [SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128]
                .into_iter()
                .collect(),
        )
        .preferred_hash_algorithms(
            [HashAlgorithm::Sha512, HashAlgorithm::Sha256]
                .into_iter()
                .collect(),
        )
        .preferred_compression_algorithms(
            [
                CompressionAlgorithm::Uncompressed,
                CompressionAlgorithm::ZLIB,
            ]
            .into_iter()
            .collect(),
        )
        .preferred_aead_algorithms(Vec::<(SymmetricKeyAlgorithm, AeadAlgorithm)>::new().into())
        .feature_seipd_v1(true)
        .feature_seipd_v2(false)
        .subkeys(vec![encryption.build().map_err(backend)?]);
    let secret = params
        .build()
        .map_err(backend)?
        .generate(rand::rngs::OsRng)
        .map_err(backend)?;
    let public = SignedPublicKey::from(secret.clone());
    Ok(GeneratedAddressKey {
        secret_key: Zeroizing::new(secret.to_bytes().map_err(backend)?),
        public_key: public.to_bytes().map_err(backend)?,
        fingerprint: fingerprint_of(&public)?,
        sha256_fingerprint: sha256_fingerprint_of(&public)?,
    })
}

pub(crate) fn user_id(address: &str) -> String {
    let local = address.split_once('@').map_or(address, |(local, _)| local);
    format!("{local} <{address}>")
}

/// What a validated public key is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressPublicKeyInfo {
    pub fingerprint: [u8; FINGERPRINT_LEN],
    pub sha256_fingerprint: [u8; 32],
    pub created_at_secs: u32,
}

/// Checks that `public_key` is a Kutup address key for `address`: a binary
/// v4 certificate in the generated shape (Ed25519 primary, one Curve25519
/// encryption subkey), valid self-signatures, exactly one user ID whose
/// address is `address`, and no secret material.
pub fn inspect_address_public_key(
    public_key: &[u8],
    address: &str,
) -> Result<AddressPublicKeyInfo> {
    let address = canonical_address(address)?;
    if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "address public key size is invalid".into(),
        ));
    }
    let key = SignedPublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("address public key does not parse".into()))?;
    key.verify_bindings()
        .map_err(|_| CryptoError::InvalidInput("address public key is not self-signed".into()))?;
    if key.to_bytes().map_err(backend)? != public_key {
        return Err(CryptoError::InvalidInput(
            "address public key is not canonical".into(),
        ));
    }
    if key.primary_key.algorithm() != PublicKeyAlgorithm::EdDSALegacy
        || key.public_subkeys.len() != 1
        || key.public_subkeys[0].algorithm() != PublicKeyAlgorithm::ECDH
    {
        return Err(CryptoError::InvalidInput(
            "address public key has an unexpected shape".into(),
        ));
    }
    if key.details.users.len() != 1
        || user_address(key.details.users[0].id.id()) != Some(address.as_str())
    {
        return Err(CryptoError::InvalidInput(
            "address public key is for another address".into(),
        ));
    }
    Ok(AddressPublicKeyInfo {
        fingerprint: fingerprint_of(&key)?,
        sha256_fingerprint: sha256_fingerprint_of(&key)?,
        created_at_secs: key.primary_key.created_at().as_secs(),
    })
}

/// The address in a user ID such as `name <name@kutup.dev>`.
fn user_address(user_id: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(user_id).ok()?;
    let start = text.rfind('<')?;
    text[start + 1..].strip_suffix('>')
}

/// An ASCII-armored public key, for download and WKD clients that want text.
pub fn armor_public_key(public_key: &[u8]) -> Result<String> {
    let key = SignedPublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("public key does not parse".into()))?;
    key.to_armored_string(ArmorOptions::default())
        .map_err(backend)
}

/// An armored secret key, so the GnuPG interop test can import one. Not for
/// product use: Kutup secret keys only ever leave Rust sealed.
#[doc(hidden)]
pub fn armor_secret_key_for_tests(secret_key: &[u8]) -> String {
    SignedSecretKey::from_bytes(secret_key)
        .expect("secret key parses")
        .to_armored_string(ArmorOptions::default())
        .expect("secret key armors")
}

fn fingerprint_of(key: &SignedPublicKey) -> Result<[u8; FINGERPRINT_LEN]> {
    key.fingerprint()
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("not a v4 key".into()))
}

fn sha256_fingerprint_of(key: &SignedPublicKey) -> Result<[u8; 32]> {
    let imprint = key.primary_key.imprint::<Sha256>().map_err(backend)?;
    Ok(imprint.into())
}

/// Seals an address's secret key under the master key. The payload binds the
/// address and the key's own fingerprint.
pub fn seal_address_key(
    master_key: &[u8],
    binding: &str,
    address: &str,
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let payload = private_key_payload(address, secret_key)?;
    account_envelope::seal(
        &payload,
        master_key,
        AccountEnvelopePurpose::MailAddressPrivateKey,
        binding,
    )
}

/// [`seal_address_key`] with a fixed nonce, for checked-in vectors only.
pub fn seal_address_key_with_nonce(
    master_key: &[u8],
    binding: &str,
    address: &str,
    secret_key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let payload = private_key_payload(address, secret_key)?;
    account_envelope::seal_with_nonce(
        &payload,
        master_key,
        AccountEnvelopePurpose::MailAddressPrivateKey,
        binding,
        nonce,
    )
}

fn private_key_payload(address: &str, secret_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let address = canonical_address(address)?;
    let fingerprint = secret_key_fingerprint(secret_key)?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        PRIVATE_KEY_DOMAIN.len() + 2 + address.len() + FINGERPRINT_LEN + 4 + secret_key.len(),
    ));
    out.extend_from_slice(PRIVATE_KEY_DOMAIN);
    push_str(&mut out, &address)?;
    out.extend_from_slice(&fingerprint);
    out.extend_from_slice(&(secret_key.len() as u32).to_be_bytes());
    out.extend_from_slice(secret_key);
    Ok(out)
}

fn secret_key_fingerprint(secret_key: &[u8]) -> Result<[u8; FINGERPRINT_LEN]> {
    if secret_key.is_empty() || secret_key.len() > MAX_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "address secret key size is invalid".into(),
        ));
    }
    let key = SignedSecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidInput("address secret key does not parse".into()))?;
    fingerprint_of(&SignedPublicKey::from(key))
}

/// Opens an address key envelope and returns the binary secret key, after
/// checking it is the key of `address` with `fingerprint`.
pub fn open_address_key(
    envelope: &[u8],
    master_key: &[u8],
    binding: &str,
    address: &str,
    fingerprint: &[u8; FINGERPRINT_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    let address = canonical_address(address)?;
    let payload = Zeroizing::new(account_envelope::open(
        envelope,
        master_key,
        AccountEnvelopePurpose::MailAddressPrivateKey,
        binding,
    )?);
    let mut rest = payload
        .strip_prefix(PRIVATE_KEY_DOMAIN)
        .ok_or(CryptoError::AuthFailed)?;
    let bound_address = take_str(&mut rest)?;
    let bound_fingerprint = take(&mut rest, FINGERPRINT_LEN)?;
    let len = u32::from_be_bytes(take(&mut rest, 4)?.try_into().expect("four bytes")) as usize;
    let secret = take(&mut rest, len)?;
    if !rest.is_empty()
        || bound_address != address
        || bound_fingerprint != fingerprint
        || secret_key_fingerprint(secret)? != *fingerprint
    {
        return Err(CryptoError::AuthFailed);
    }
    Ok(Zeroizing::new(secret.to_vec()))
}

/// A shared mailbox's key share's version byte.
const GROUP_SHARE_VERSION: u8 = 1;
/// HPKE info and the start of the AAD of a group key share.
const GROUP_SHARE_DOMAIN: &[u8] = b"kutup/mail-group-key-share/v1\0";
const GROUP_SHARE_HEADER_LEN: usize = 1 + 32 + 32;

/// Who a group key share is for: the member's account and the account
/// incarnation whose Drive HPKE key it is sealed to.
pub struct GroupShareMember<'a> {
    pub account: &'a AccountRef,
    /// Lowercase hex of the member's account incarnation id.
    pub incarnation_id: &'a str,
}

fn group_share_aad(
    domain: &[u8],
    group_id: &[u8; 16],
    bound: &[u8],
    member: &AccountRef,
    incarnation: &[u8; 32],
) -> Vec<u8> {
    let account = member.bytes();
    let mut aad = Vec::with_capacity(domain.len() + 16 + bound.len() + account.len() + 32);
    aad.extend_from_slice(domain);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(bound);
    aad.extend_from_slice(&account);
    aad.extend_from_slice(incarnation);
    aad
}

/// A secret of a shared mailbox sealed with HPKE (`domain` as its info) to a
/// member's account-level key, its AAD binding `domain`, the group, `bound`
/// (what the secret is: a key's fingerprint or public key), the member's
/// account and its incarnation. The bytes: version, the member's
/// incarnation id, the HPKE encapsulated key, the ciphertext.
pub(crate) fn seal_group_secret(
    domain: &[u8],
    secret: &[u8],
    group_id: &str,
    bound: &[u8],
    member: &GroupShareMember<'_>,
    member_hpke_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let group_id = crate::drive_object::parse_canonical_uuid(group_id, "group")?;
    let incarnation =
        crate::named_share::parse_hex_32(member.incarnation_id, "member incarnation")?;
    let aad = group_share_aad(domain, &group_id, bound, member.account, &incarnation);
    let mut hpke = crate::named_share::hpke_suite();
    let (encapsulated, ciphertext) = hpke
        .seal(
            &hpke_rs::HpkePublicKey::new(member_hpke_public_key.to_vec()),
            domain,
            &aad,
            secret,
            None,
            None,
            None,
        )
        .map_err(|error| CryptoError::Backend(format!("group share HPKE seal: {error}")))?;
    if encapsulated.len() != 32 {
        return Err(CryptoError::Backend(
            "group share: encapsulated key length".into(),
        ));
    }
    let mut out = Vec::with_capacity(GROUP_SHARE_HEADER_LEN + ciphertext.len());
    out.push(GROUP_SHARE_VERSION);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(&encapsulated);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens [`seal_group_secret`]'s share for `member` with their account-level
/// HPKE private key.
pub(crate) fn open_group_secret(
    domain: &[u8],
    share: &[u8],
    group_id: &str,
    bound: &[u8],
    member: &AccountRef,
    member_hpke_private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    group_key_share_incarnation(share)?;
    let group_id = crate::drive_object::parse_canonical_uuid(group_id, "group")?;
    let incarnation: [u8; 32] = share[1..33].try_into().expect("32 bytes");
    let aad = group_share_aad(domain, &group_id, bound, member, &incarnation);
    let hpke = crate::named_share::hpke_suite();
    Ok(Zeroizing::new(
        hpke.open(
            &share[33..GROUP_SHARE_HEADER_LEN],
            &hpke_rs::HpkePrivateKey::new(member_hpke_private_key.to_vec()),
            domain,
            &aad,
            &share[GROUP_SHARE_HEADER_LEN..],
            None,
            None,
            None,
        )
        .map_err(|_| CryptoError::AuthFailed)?,
    ))
}

/// A shared mailbox's key for one member (docs/plans/mail-groups.md, G1b;
/// docs/plans/account-ids.md): the group's secret key sealed with HPKE to
/// the member's account-level key (their Drive HPKE key, which their Drive
/// key binding ties to their account id), bound to the group, the group
/// key, the member's account and its incarnation. One level above their
/// addresses, as Proton wraps address keys to the user key: a rename keeps
/// the share.
pub fn seal_group_key_share(
    group_secret_key: &[u8],
    group_id: &str,
    member: &GroupShareMember<'_>,
    member_hpke_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let group_fingerprint = secret_key_fingerprint(group_secret_key)?;
    seal_group_secret(
        GROUP_SHARE_DOMAIN,
        group_secret_key,
        group_id,
        &group_fingerprint,
        member,
        member_hpke_public_key,
    )
}

/// The account incarnation a group share (of a group key or of a group
/// signing key) is sealed to (lowercase hex), read without opening it: what
/// the server checks against the member's current keys.
pub fn group_key_share_incarnation(share: &[u8]) -> Result<String> {
    if share.len() <= GROUP_SHARE_HEADER_LEN || share[0] != GROUP_SHARE_VERSION {
        return Err(CryptoError::InvalidInput("not a group key share".into()));
    }
    Ok(hex::encode(&share[1..33]))
}

/// Opens a member's share of a group key with the member's account-level
/// HPKE private key, for that group, group key and member only.
pub fn open_group_key_share(
    share: &[u8],
    group_id: &str,
    group_fingerprint: &[u8; FINGERPRINT_LEN],
    member: &AccountRef,
    member_hpke_private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = open_group_secret(
        GROUP_SHARE_DOMAIN,
        share,
        group_id,
        group_fingerprint,
        member,
        member_hpke_private_key,
    )?;
    if secret_key_fingerprint(&secret)? != *group_fingerprint {
        return Err(CryptoError::AuthFailed);
    }
    Ok(secret)
}

/// Shortest passphrase an exported key may be locked with.
pub const MIN_EXPORT_PASSPHRASE_CHARS: usize = 8;

/// An address's secret key as a file to keep or move to another OpenPGP
/// program (Proton's "Export private key"): ASCII-armored, every secret part
/// locked with `passphrase` (OpenPGP's iterated and salted S2K, AES-256).
pub fn export_address_secret_key(secret_key: &[u8], passphrase: &str) -> Result<Zeroizing<String>> {
    if passphrase.chars().count() < MIN_EXPORT_PASSPHRASE_CHARS {
        return Err(CryptoError::InvalidInput(
            "the passphrase is too short".into(),
        ));
    }
    let mut key = SignedSecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidInput("address secret key does not parse".into()))?;
    let password = Password::from(passphrase);
    key.primary_key
        .set_password(rand::rngs::OsRng, &password)
        .map_err(backend)?;
    for subkey in &mut key.secret_subkeys {
        subkey
            .key
            .set_password(rand::rngs::OsRng, &password)
            .map_err(backend)?;
    }
    key.to_armored_string(ArmorOptions::default())
        .map(Zeroizing::new)
        .map_err(backend)
}

/// Reads an address key from an OpenPGP secret key file (armored or binary,
/// locked with `passphrase` or not), as exported by Kutup, Proton or GnuPG:
/// it must be a key Kutup can use for `address` (the shape
/// [`inspect_address_public_key`] checks: Ed25519 primary, one Curve25519
/// encryption subkey, one user ID for the address). Returns it unlocked, to
/// be sealed at once. A wrong passphrase is [`CryptoError::AuthFailed`].
pub fn import_address_secret_key(
    file: &[u8],
    passphrase: &str,
    address: &str,
) -> Result<GeneratedAddressKey> {
    if file.is_empty() || file.len() > 64 * 1024 {
        return Err(CryptoError::InvalidInput("key file size is invalid".into()));
    }
    let trimmed = file.trim_ascii_start();
    let mut key = if trimmed.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        SignedSecretKey::from_armor_single(trimmed).map(|(key, _)| key)
    } else {
        SignedSecretKey::from_bytes(file)
    }
    .map_err(|_| CryptoError::InvalidInput("not an OpenPGP secret key".into()))?;
    let password = Password::from(passphrase);
    key.primary_key
        .remove_password(&password)
        .map_err(|_| CryptoError::AuthFailed)?;
    for subkey in &mut key.secret_subkeys {
        subkey
            .key
            .remove_password(&password)
            .map_err(|_| CryptoError::AuthFailed)?;
    }
    let public = SignedPublicKey::from(key.clone());
    let public_key = public.to_bytes().map_err(backend)?;
    let info = inspect_address_public_key(&public_key, address)?;
    let secret_key = Zeroizing::new(key.to_bytes().map_err(backend)?);
    if secret_key.len() > MAX_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "address secret key size is invalid".into(),
        ));
    }
    Ok(GeneratedAddressKey {
        secret_key,
        public_key,
        fingerprint: info.fingerprint,
        sha256_fingerprint: info.sha256_fingerprint,
    })
}

/// Encrypts `plaintext` to `recipient_public_key` (SEIPDv1, AES-256, the
/// form every OpenPGP client reads), signed by `signer_secret_key` when given.
/// Returns an ASCII-armored message.
pub fn encrypt(
    recipient_public_key: &[u8],
    signer_secret_key: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<String> {
    let recipient = parse_recipient(recipient_public_key)?;
    let subkey = encryption_subkey(&recipient)?;
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rand::rngs::OsRng, SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(rand::rngs::OsRng, subkey)
        .map_err(backend)?;
    let signer = match signer_secret_key {
        Some(secret) => Some(
            SignedSecretKey::from_bytes(secret)
                .map_err(|_| CryptoError::InvalidInput("signing key does not parse".into()))?,
        ),
        None => None,
    };
    if let Some(signer) = &signer {
        builder.sign(
            &signer.primary_key,
            Password::empty(),
            HashAlgorithm::Sha512,
        );
    }
    builder
        .to_armored_string(rand::rngs::OsRng, ArmorOptions::default())
        .map_err(backend)
}

/// Encrypts `plaintext` to `recipient_public_key` as a binary, unsigned
/// OpenPGP message (SEIPDv1, AES-256): how mail from outside is stored when
/// it arrives, encrypted before it is written anywhere. Unsigned because the
/// server holds no key worth vouching with; binary to spare armor's third.
pub fn encrypt_binary(recipient_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = parse_recipient(recipient_public_key)?;
    let subkey = encryption_subkey(&recipient)?;
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rand::rngs::OsRng, SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(rand::rngs::OsRng, subkey)
        .map_err(backend)?;
    builder.to_vec(rand::rngs::OsRng).map_err(backend)
}

/// An outside correspondent's key (docs/plans/mail.md, C3), as found
/// through WKD, Proton's key server, keys.openpgp.org or an Autocrypt
/// header: checked and reduced to its binary form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalKeyInfo {
    /// The key, binary, as given (armor removed).
    pub public_key: Vec<u8>,
    /// Lowercase hex, 40 digits (version 4).
    pub fingerprint: String,
    pub created_at_secs: u32,
}

/// Largest outside key accepted (keys with many signatures run large).
const MAX_EXTERNAL_KEY_LEN: usize = 256 * 1024;

fn parse_public_key(bytes: &[u8]) -> Result<SignedPublicKey> {
    let invalid = || CryptoError::InvalidInput("public key does not parse".into());
    if bytes.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        SignedPublicKey::from_armor_single(bytes)
            .map(|(key, _)| key)
            .map_err(|_| invalid())
    } else {
        SignedPublicKey::from_bytes(bytes).map_err(|_| invalid())
    }
}

/// When a key or subkey stops being valid: its creation plus the
/// expiration its newest self-signature sets, if any.
fn expired(created: u32, signatures: &[pgp::packet::Signature], now_secs: u64) -> bool {
    let newest = signatures
        .iter()
        .filter_map(|sig| sig.created().map(|at| (at.as_secs(), sig)))
        .max_by_key(|(at, _)| *at);
    match newest.and_then(|(_, sig)| sig.key_expiration_time()) {
        Some(lifetime) if lifetime.as_secs() != 0 => {
            u64::from(created) + u64::from(lifetime.as_secs()) <= now_secs
        }
        _ => false,
    }
}

fn email_of(user_id: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(user_id).ok()?;
    let address = match (text.rfind('<'), text.rfind('>')) {
        (Some(open), Some(close)) if open < close => &text[open + 1..close],
        _ => text,
    };
    let address = address.trim().to_lowercase();
    (address.contains('@') && !address.contains(char::is_whitespace)).then_some(address)
}

/// Whether `signature` was issued by `key`'s primary key (by key ID or
/// fingerprint); certifications by others are not self-signatures.
fn self_issued(signature: &pgp::packet::Signature, key: &SignedPublicKey) -> bool {
    let id = key.primary_key.legacy_key_id();
    let fingerprint = key.primary_key.fingerprint();
    signature
        .issuer_key_id()
        .iter()
        .any(|issuer| **issuer == id)
        || signature
            .issuer_fingerprint()
            .iter()
            .any(|issuer| **issuer == fingerprint)
}

/// The usable encryption subkey of an outside key: bound by a valid binding
/// signature, not revoked, not expired at `now_secs`; the newest wins.
fn usable_encryption_subkey(key: &SignedPublicKey, now_secs: u64) -> Option<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|sub| sub.algorithm().can_encrypt())
        .filter(|sub| {
            let bindings: Vec<_> = sub
                .signatures
                .iter()
                .filter(|sig| sig.typ() == Some(pgp::packet::SignatureType::SubkeyBinding))
                .filter(|sig| {
                    sig.verify_subkey_binding(&key.primary_key, &sub.key)
                        .is_ok()
                })
                .cloned()
                .collect();
            let revoked = sub.signatures.iter().any(|sig| {
                sig.typ() == Some(pgp::packet::SignatureType::SubkeyRevocation)
                    && sig
                        .verify_subkey_binding(&key.primary_key, &sub.key)
                        .is_ok()
            });
            !bindings.is_empty()
                && !revoked
                && !expired(sub.created_at().as_secs(), &bindings, now_secs)
        })
        .max_by_key(|sub| sub.created_at().as_secs())
}

/// Where an outside key stands for an address, as Proton's key table shows
/// it (`ContactKeysTable`): usable to encrypt to, or why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKeyState {
    Usable,
    Expired,
    Revoked,
    /// No self-signed user ID for the address.
    OtherAddress,
    /// No encryption subkey Kutup can use.
    CannotEncrypt,
}

impl ExternalKeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalKeyState::Usable => "usable",
            ExternalKeyState::Expired => "expired",
            ExternalKeyState::Revoked => "revoked",
            ExternalKeyState::OtherAddress => "otherAddress",
            ExternalKeyState::CannotEncrypt => "cannotEncrypt",
        }
    }
}

/// An outside key as a contact's key table lists it: never refused for
/// being expired or revoked, so its history stays visible.
#[derive(Debug, Clone)]
pub struct ExternalKeyDetails {
    pub info: ExternalKeyInfo,
    /// When it stops being valid, if it does (its newest self-signature).
    pub expires_at_secs: Option<u64>,
    /// "RSA (4096)", "ECC (Curve25519)", as Proton names them.
    pub algorithm: String,
    pub state: ExternalKeyState,
}

fn algorithm_name(key: &SignedPublicKey) -> String {
    use pgp::crypto::public_key::PublicKeyAlgorithm as A;
    use pgp::types::PublicParams;
    use rsa::traits::PublicKeyParts as _;
    match key.primary_key.public_params() {
        PublicParams::RSA(params) => format!("RSA ({})", params.key.n().bits()),
        _ => match key.primary_key.algorithm() {
            A::EdDSALegacy | A::Ed25519 | A::X25519 | A::ECDH => "ECC (Curve25519)".into(),
            A::Ed448 | A::X448 => "ECC (Curve448)".into(),
            A::ECDSA => "ECC (NIST)".into(),
            A::DSA => "DSA".into(),
            other => format!("{other:?}"),
        },
    }
}

/// [`describe_external_public_key`] with what a key table shows: expiry,
/// algorithm and where the key stands for `address` at `now_secs`
/// ([`inspect_external_public_key`]'s checks, as a state).
pub fn describe_external_key_details(
    public_key: &[u8],
    address: &str,
    now_secs: u64,
) -> Result<ExternalKeyDetails> {
    let info = describe_external_public_key(public_key)?;
    let key = parse_public_key(public_key)?;
    let self_signatures: Vec<pgp::packet::Signature> = key
        .details
        .users
        .iter()
        .flat_map(|user| user.signatures.iter())
        .filter(|sig| self_issued(sig, &key))
        .filter(|sig| sig.typ() != Some(pgp::packet::SignatureType::CertRevocation))
        .cloned()
        .collect();
    let expires_at_secs = self_signatures
        .iter()
        .filter_map(|sig| sig.created().map(|at| (at.as_secs(), sig)))
        .max_by_key(|(at, _)| *at)
        .and_then(|(_, sig)| sig.key_expiration_time())
        .filter(|lifetime| lifetime.as_secs() != 0)
        .map(|lifetime| u64::from(info.created_at_secs) + u64::from(lifetime.as_secs()));
    let state = match inspect_external_public_key(public_key, address, now_secs) {
        Ok(_) => ExternalKeyState::Usable,
        Err(CryptoError::InvalidInput(reason)) if reason.contains("revoked") => {
            ExternalKeyState::Revoked
        }
        Err(CryptoError::InvalidInput(reason)) if reason.contains("expired") => {
            ExternalKeyState::Expired
        }
        Err(CryptoError::InvalidInput(reason)) if reason.contains("user ID for the address") => {
            ExternalKeyState::OtherAddress
        }
        Err(_) => ExternalKeyState::CannotEncrypt,
    };
    Ok(ExternalKeyDetails {
        info,
        expires_at_secs,
        algorithm: algorithm_name(&key),
        state,
    })
}

/// A single outside key (armored or binary) as it is, unchecked: its binary
/// form, fingerprint and creation time, for showing a key pinned to a
/// contact even once it has expired. Use [`inspect_external_public_key`]
/// before encrypting to it.
pub fn describe_external_public_key(public_key: &[u8]) -> Result<ExternalKeyInfo> {
    if public_key.is_empty() || public_key.len() > MAX_EXTERNAL_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "public key size is invalid".into(),
        ));
    }
    let key = parse_public_key(public_key)?;
    if key.primary_key.version() != pgp::types::KeyVersion::V4 {
        return Err(CryptoError::InvalidInput(
            "only version 4 keys are supported".into(),
        ));
    }
    Ok(ExternalKeyInfo {
        public_key: key.to_bytes().map_err(backend)?,
        fingerprint: hex::encode(key.fingerprint().as_bytes()),
        created_at_secs: key.primary_key.created_at().as_secs(),
    })
}

/// Every key in a key server's answer (armored or binary; WKD and HKP may
/// serve several), each checked by [`inspect_external_public_key`]; the
/// newest valid one wins.
pub fn inspect_external_public_keys(
    keys: &[u8],
    address: &str,
    now_secs: u64,
) -> Result<ExternalKeyInfo> {
    inspect_external_public_keys_all(keys, address, now_secs)?
        .into_iter()
        .next()
        .ok_or_else(|| CryptoError::InvalidInput("no usable key for the address".into()))
}

/// Every usable key in a key server's answer, newest first (Proton lists
/// them all in a contact's key table); an error when none is.
pub fn inspect_external_public_keys_all(
    keys: &[u8],
    address: &str,
    now_secs: u64,
) -> Result<Vec<ExternalKeyInfo>> {
    if keys.is_empty() || keys.len() > MAX_EXTERNAL_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "public key size is invalid".into(),
        ));
    }
    let parsed: Vec<SignedPublicKey> = if keys.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    {
        SignedPublicKey::from_armor_many(keys)
            .map(|(iter, _)| iter.filter_map(|key| key.ok()).collect())
            .map_err(|_| CryptoError::InvalidInput("public keys do not parse".into()))?
    } else {
        SignedPublicKey::from_bytes_many(keys)
            .map(|iter| iter.filter_map(|key| key.ok()).collect())
            .map_err(|_| CryptoError::InvalidInput("public keys do not parse".into()))?
    };
    let mut usable: Vec<ExternalKeyInfo> = parsed
        .iter()
        .filter_map(|key| key.to_bytes().ok())
        .filter_map(|bytes| inspect_external_public_key(&bytes, address, now_secs).ok())
        .collect();
    if usable.is_empty() {
        return Err(CryptoError::InvalidInput(
            "no usable key for the address".into(),
        ));
    }
    usable.sort_by_key(|info| std::cmp::Reverse(info.created_at_secs));
    usable.dedup_by(|a, b| a.fingerprint == b.fingerprint);
    Ok(usable)
}

/// Checks an outside key for `address` at `now_secs`: version 4, not
/// revoked, a user ID for the address with a valid self-signature that has
/// not expired or been revoked, and a bound encryption subkey Kutup can use.
/// Certifications by other keys (Proton adds one) are ignored, as OpenPGP
/// implementations do. Armored or binary in.
pub fn inspect_external_public_key(
    public_key: &[u8],
    address: &str,
    now_secs: u64,
) -> Result<ExternalKeyInfo> {
    if public_key.is_empty() || public_key.len() > MAX_EXTERNAL_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "public key size is invalid".into(),
        ));
    }
    let key = parse_public_key(public_key)?;
    if key.primary_key.version() != pgp::types::KeyVersion::V4 {
        return Err(CryptoError::InvalidInput(
            "only version 4 keys are supported".into(),
        ));
    }
    // A revocation counts when the key itself issued it and it verifies
    // (designated revokers are not honoured).
    if key
        .details
        .revocation_signatures
        .iter()
        .any(|sig| self_issued(sig, &key) && sig.verify_key(&key.primary_key).is_ok())
    {
        return Err(CryptoError::InvalidInput("public key is revoked".into()));
    }
    let created = key.primary_key.created_at().as_secs();
    let address = address.trim().to_lowercase();
    // The user ID for the address, with its valid self-signatures; other
    // people's certifications (Proton adds its own) do not count either way.
    let (_, own) = key
        .details
        .users
        .iter()
        .filter(|user| email_of(user.id.id()).as_deref() == Some(address.as_str()))
        .find_map(|user| {
            let own: Vec<_> = user
                .signatures
                .iter()
                .filter(|sig| self_issued(sig, &key))
                .filter(|sig| {
                    sig.verify_certification(&key.primary_key, pgp::types::Tag::UserId, &user.id)
                        .is_ok()
                })
                .cloned()
                .collect();
            (!own.is_empty()).then_some((user, own))
        })
        .ok_or_else(|| {
            CryptoError::InvalidInput(
                "public key has no self-signed user ID for the address".into(),
            )
        })?;
    if own
        .iter()
        .any(|sig| sig.typ() == Some(pgp::packet::SignatureType::CertRevocation))
    {
        return Err(CryptoError::InvalidInput("user ID is revoked".into()));
    }
    let certifications: Vec<_> = own
        .iter()
        .filter(|sig| sig.typ() != Some(pgp::packet::SignatureType::CertRevocation))
        .cloned()
        .collect();
    if certifications.is_empty() || expired(created, &certifications, now_secs) {
        return Err(CryptoError::InvalidInput("public key has expired".into()));
    }
    if usable_encryption_subkey(&key, now_secs).is_none() {
        return Err(CryptoError::InvalidInput(
            "public key has no usable encryption subkey".into(),
        ));
    }
    Ok(ExternalKeyInfo {
        public_key: key.to_bytes().map_err(backend)?,
        fingerprint: hex::encode(key.fingerprint().as_bytes()),
        created_at_secs: created,
    })
}

/// Encrypts `plaintext` to every outside key (each checked by
/// [`inspect_external_public_key`]) and to `own_public_key`, signed with
/// `signer_secret_key` inside the encryption, as Proton and Thunderbird
/// send PGP/MIME: an armored message for the `application/octet-stream`
/// part of RFC 3156 `multipart/encrypted`.
pub fn encrypt_armored_signed(
    recipient_public_keys: &[&[u8]],
    signer_secret_key: &[u8],
    plaintext: &[u8],
    now_secs: u64,
) -> Result<String> {
    encrypt_armored(
        recipient_public_keys,
        Some(signer_secret_key),
        plaintext,
        now_secs,
    )
}

/// [`encrypt_armored_signed`] with the signature optional: unsigned when the
/// sender turned Sign off for the message (docs/plans/mail-encrypt-sign.md).
pub fn encrypt_armored(
    recipient_public_keys: &[&[u8]],
    signer_secret_key: Option<&[u8]>,
    plaintext: &[u8],
    now_secs: u64,
) -> Result<String> {
    if recipient_public_keys.is_empty() || recipient_public_keys.len() > MAX_SPLIT_RECIPIENTS {
        return Err(CryptoError::InvalidInput(
            "a message needs 1 to 100 recipient keys".into(),
        ));
    }
    let keys = recipient_public_keys
        .iter()
        .map(|key| parse_public_key(key))
        .collect::<Result<Vec<_>>>()?;
    let signer = signer_secret_key
        .map(|secret| {
            SignedSecretKey::from_bytes(secret)
                .map_err(|_| CryptoError::InvalidInput("signing key does not parse".into()))
        })
        .transpose()?;
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rand::rngs::OsRng, SymmetricKeyAlgorithm::AES256);
    for key in &keys {
        let subkey = usable_encryption_subkey(key, now_secs).ok_or_else(|| {
            CryptoError::InvalidInput("a recipient key has no usable encryption subkey".into())
        })?;
        builder
            .encrypt_to_key(rand::rngs::OsRng, subkey)
            .map_err(backend)?;
    }
    if let Some(signer) = &signer {
        builder.sign(
            &signer.primary_key,
            Password::empty(),
            HashAlgorithm::Sha512,
        );
    }
    builder
        .to_armored_string(rand::rngs::OsRng, ArmorOptions::default())
        .map_err(backend)
}

/// A detached, armored OpenPGP signature over `content` by
/// `signer_secret_key` (binary signature type, SHA-512): the
/// `application/pgp-signature` part of an RFC 3156 `multipart/signed`
/// message, which Proton, Thunderbird and GnuPG check. `content` is the
/// signed MIME part exactly as sent, CRLF line endings included.
pub fn sign_detached(signer_secret_key: &[u8], content: &[u8]) -> Result<String> {
    let signer = SignedSecretKey::from_bytes(signer_secret_key)
        .map_err(|_| CryptoError::InvalidInput("signing key does not parse".into()))?;
    pgp::composed::DetachedSignature::sign_binary_data(
        rand::rngs::OsRng,
        &signer.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha512,
        content,
    )
    .map_err(backend)?
    .to_armored_string(ArmorOptions::default())
    .map_err(backend)
}

/// A cleartext-signed message (`-----BEGIN PGP SIGNED MESSAGE-----`) of
/// `text` by `signer_secret_key` (SHA-512): the body of an Inline PGP message
/// that is signed but not encrypted (Proton's "Inline" scheme), which GnuPG,
/// Thunderbird and Proton check.
pub fn sign_cleartext(signer_secret_key: &[u8], text: &str) -> Result<String> {
    let signer = SignedSecretKey::from_bytes(signer_secret_key)
        .map_err(|_| CryptoError::InvalidInput("signing key does not parse".into()))?;
    pgp::composed::CleartextSignedMessage::sign(
        rand::rngs::OsRng,
        text,
        &signer.primary_key,
        &Password::empty(),
    )
    .map_err(backend)?
    .to_armored_string(ArmorOptions::default())
    .map_err(backend)
}

/// Whether `signature` (armored or binary, as in a `multipart/signed`
/// message's `application/pgp-signature` part) signs `content` with
/// `signer_public_key` or one of its subkeys.
pub fn verify_detached(signature: &[u8], content: &[u8], signer_public_key: &[u8]) -> Result<bool> {
    let signature = if signature.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
        pgp::composed::DetachedSignature::from_armor_single(signature).map(|(sig, _)| sig)
    } else {
        pgp::composed::DetachedSignature::from_bytes(signature)
    }
    .map_err(|_| CryptoError::InvalidInput("signature does not parse".into()))?;
    let signer = parse_public_key(signer_public_key)?;
    if signature.verify(&signer.primary_key, content).is_ok() {
        return Ok(true);
    }
    Ok(signer
        .public_subkeys
        .iter()
        .any(|sub| signature.verify(&sub.key, content).is_ok()))
}

/// A cleartext-signed message (`-----BEGIN PGP SIGNED MESSAGE-----`): its
/// text, and whether it verifies against `signer_public_key` when given.
pub fn verify_cleartext(message: &str, signer_public_key: Option<&[u8]>) -> Result<(String, bool)> {
    let (signed, _) = pgp::composed::CleartextSignedMessage::from_string(message)
        .map_err(|_| CryptoError::InvalidInput("not a cleartext-signed message".into()))?;
    let verified = match signer_public_key {
        Some(key) => {
            let signer = parse_public_key(key)?;
            signed.verify(&signer.primary_key).is_ok()
                || signer
                    .public_subkeys
                    .iter()
                    .any(|sub| signed.verify(&sub.key).is_ok())
        }
        None => false,
    };
    Ok((signed.signed_text(), verified))
}

/// A message encrypted once for several recipients, split the way Proton
/// sends mail between its users (docs/plans/mail.md): one key packet per
/// recipient (a public-key encrypted session key, PKESK) and one data packet
/// (SEIPD) they share. The server stores `key packet || data packet` for each
/// recipient, so no copy names another recipient's key, and Bcc stays hidden.
pub struct SplitMessage {
    /// One PKESK per recipient, in the order the recipients were given.
    pub key_packets: Vec<Vec<u8>>,
    pub data_packet: Vec<u8>,
}

/// Encrypts `plaintext` once to every key in `recipient_public_keys`, signed
/// by `signer_secret_key`, and splits the result (see [`SplitMessage`]).
pub fn encrypt_split(
    recipient_public_keys: &[&[u8]],
    signer_secret_key: &[u8],
    plaintext: &[u8],
) -> Result<SplitMessage> {
    split(recipient_public_keys, Some(signer_secret_key), plaintext)
}

/// [`encrypt_split`] without a signature, for mail the server encrypts on
/// arrival to every member of a distribution list (docs/plans/mail-groups.md):
/// one data packet stored once, one key packet per member.
pub fn encrypt_split_unsigned(
    recipient_public_keys: &[&[u8]],
    plaintext: &[u8],
) -> Result<SplitMessage> {
    split(recipient_public_keys, None, plaintext)
}

fn split(
    recipient_public_keys: &[&[u8]],
    signer_secret_key: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<SplitMessage> {
    if recipient_public_keys.is_empty() || recipient_public_keys.len() > MAX_LIST_RECIPIENTS {
        return Err(CryptoError::InvalidInput(
            "a message needs 1 to 1001 recipient keys".into(),
        ));
    }
    let recipients = recipient_public_keys
        .iter()
        .map(|key| parse_recipient(key))
        .collect::<Result<Vec<_>>>()?;
    let signer = signer_secret_key
        .map(|key| {
            SignedSecretKey::from_bytes(key)
                .map_err(|_| CryptoError::InvalidInput("signing key does not parse".into()))
        })
        .transpose()?;
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rand::rngs::OsRng, SymmetricKeyAlgorithm::AES256);
    for recipient in &recipients {
        builder
            .encrypt_to_key(rand::rngs::OsRng, encryption_subkey(recipient)?)
            .map_err(backend)?;
    }
    if let Some(signer) = &signer {
        builder.sign(
            &signer.primary_key,
            Password::empty(),
            HashAlgorithm::Sha512,
        );
    }
    let message = builder.to_vec(rand::rngs::OsRng).map_err(backend)?;
    let mut rest = message.as_slice();
    let mut key_packets = Vec::with_capacity(recipients.len());
    for _ in &recipients {
        let (tag, _, length) = packet_extent(rest)?;
        if tag != TAG_PKESK {
            return Err(CryptoError::InvalidInput("expected a key packet".into()));
        }
        key_packets.push(rest[..length].to_vec());
        rest = &rest[length..];
    }
    if rest.is_empty() || packet_tag(rest[0]) != Some(TAG_SEIPD) {
        return Err(CryptoError::InvalidInput("expected a data packet".into()));
    }
    Ok(SplitMessage {
        key_packets,
        data_packet: rest.to_vec(),
    })
}

/// The 8-byte key ID a key packet is encrypted to, so a server can check it
/// names the recipient's current key without being able to open it.
pub fn key_packet_key_id(key_packet: &[u8]) -> Result<[u8; 8]> {
    let (tag, header, length) = packet_extent(key_packet)?;
    if tag != TAG_PKESK || length != key_packet.len() {
        return Err(CryptoError::InvalidInput("not a single key packet".into()));
    }
    let body = &key_packet[header..];
    // Version 3: version, 8-byte key ID, algorithm, encrypted session key.
    if body.len() < 10 || body[0] != 3 {
        return Err(CryptoError::InvalidInput("unsupported key packet".into()));
    }
    Ok(body[1..9].try_into().expect("eight bytes"))
}

/// The key ID of a whole message's first key packet: whom it is for, as far
/// as a server can tell without opening it.
pub fn message_key_id(message: &[u8]) -> Result<[u8; 8]> {
    let (tag, _, length) = packet_extent(message)?;
    if tag != TAG_PKESK {
        return Err(CryptoError::InvalidInput(
            "message does not start with a key packet".into(),
        ));
    }
    key_packet_key_id(&message[..length])
}

/// The key IDs an OpenPGP message (armored or binary) is encrypted to, as
/// far as a server can tell without opening it: its leading key packets,
/// which must be followed by encrypted data. Version 6 key packets carry no
/// key ID and are skipped; a message with none readable is still encrypted.
/// Errors when `message` is not an encrypted OpenPGP message.
pub fn pgp_message_key_ids(message: &[u8]) -> Result<Vec<[u8; 8]>> {
    let not_encrypted = || CryptoError::InvalidInput("not an encrypted OpenPGP message".into());
    let trimmed = message.trim_ascii_start();
    let binary;
    let mut rest: &[u8] = if trimmed.starts_with(b"-----BEGIN PGP MESSAGE-----") {
        let mut reader = pgp::armor::Dearmor::new(std::io::BufReader::new(trimmed));
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|_| not_encrypted())?;
        if reader.typ != Some(pgp::armor::BlockType::Message) {
            return Err(not_encrypted());
        }
        binary = bytes;
        &binary
    } else {
        message
    };
    let mut ids = Vec::new();
    let mut key_packets = 0;
    loop {
        let tag = rest
            .first()
            .and_then(|first| packet_tag(*first))
            .ok_or_else(not_encrypted)?;
        match tag {
            TAG_PKESK => {
                let (_, header, length) = packet_extent(rest).map_err(|_| not_encrypted())?;
                if rest.get(header) == Some(&3) {
                    ids.push(key_packet_key_id(&rest[..length])?);
                }
                key_packets += 1;
                if key_packets > MAX_LIST_RECIPIENTS * 2 {
                    return Err(not_encrypted());
                }
                rest = &rest[length..];
            }
            TAG_SEIPD | TAG_AEAD if key_packets > 0 => return Ok(ids),
            _ => return Err(not_encrypted()),
        }
    }
}

/// The key ID of the subkey `public_key` is encrypted to.
pub fn encryption_key_id(public_key: &[u8]) -> Result<[u8; 8]> {
    let recipient = parse_recipient(public_key)?;
    let id = encryption_subkey(&recipient)?.legacy_key_id();
    id.as_ref()
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("unexpected key ID length".into()))
}

const MAX_SPLIT_RECIPIENTS: usize = 100;
/// Key packets one split message may carry: every member of a distribution
/// list (at most 1000, docs/plans/mail-groups.md) and the sender's own.
const MAX_LIST_RECIPIENTS: usize = 1001;
const TAG_PKESK: u8 = 1;
const TAG_SEIPD: u8 = 18;
const TAG_AEAD: u8 = 20;

fn packet_tag(first: u8) -> Option<u8> {
    match first {
        b if b & 0xc0 == 0xc0 => Some(b & 0x3f),
        b if b & 0x80 == 0x80 => Some((b >> 2) & 0x0f),
        _ => None,
    }
}

/// A packet's tag, header length and whole length (header and body), for
/// packets with a definite length; key packets always have one.
fn packet_extent(bytes: &[u8]) -> Result<(u8, usize, usize)> {
    let invalid = || CryptoError::InvalidInput("malformed OpenPGP packet".into());
    let first = *bytes.first().ok_or_else(invalid)?;
    let tag = packet_tag(first).ok_or_else(invalid)?;
    let (header, body) = if first & 0x40 != 0 {
        match *bytes.get(1).ok_or_else(invalid)? {
            l @ 0..=191 => (2, l as usize),
            l @ 192..=223 => {
                let second = *bytes.get(2).ok_or_else(invalid)? as usize;
                (3, ((l as usize - 192) << 8) + second + 192)
            }
            255 => {
                let length: [u8; 4] = bytes.get(2..6).ok_or_else(invalid)?.try_into().unwrap();
                (6, u32::from_be_bytes(length) as usize)
            }
            _ => return Err(invalid()),
        }
    } else {
        match first & 0x03 {
            0 => (2, *bytes.get(1).ok_or_else(invalid)? as usize),
            1 => {
                let length: [u8; 2] = bytes.get(1..3).ok_or_else(invalid)?.try_into().unwrap();
                (3, u16::from_be_bytes(length) as usize)
            }
            2 => {
                let length: [u8; 4] = bytes.get(1..5).ok_or_else(invalid)?.try_into().unwrap();
                (5, u32::from_be_bytes(length) as usize)
            }
            _ => return Err(invalid()),
        }
    };
    let total = header + body;
    if total > bytes.len() {
        return Err(invalid());
    }
    Ok((tag, header, total))
}

fn parse_recipient(public_key: &[u8]) -> Result<SignedPublicKey> {
    SignedPublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("recipient key does not parse".into()))
}

fn encryption_subkey(recipient: &SignedPublicKey) -> Result<&SignedPublicSubKey> {
    recipient
        .public_subkeys
        .iter()
        .find(|subkey| subkey.algorithm().can_encrypt())
        .ok_or_else(|| CryptoError::InvalidInput("recipient key cannot encrypt".into()))
}

/// A decrypted message.
pub struct DecryptedMessage {
    pub data: Zeroizing<Vec<u8>>,
    /// Whether the message carried a signature at all.
    pub signed: bool,
    /// Whether the message carried a signature valid for `signer_public_key`.
    pub verified: bool,
}

/// Decrypts an armored or binary OpenPGP message with `secret_key`, and
/// checks its signature against `signer_public_key` when given.
pub fn decrypt(
    secret_key: &[u8],
    message: &[u8],
    signer_public_key: Option<&[u8]>,
) -> Result<DecryptedMessage> {
    let key = SignedSecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidInput("secret key does not parse".into()))?;
    let parsed = if message.starts_with(b"-----BEGIN PGP MESSAGE-----") {
        Message::from_armor(message).map(|(message, _)| message)
    } else {
        Message::from_bytes(message)
    }
    .map_err(|_| CryptoError::InvalidInput("message does not parse".into()))?;
    let decrypted = parsed
        .decrypt(&Password::empty(), &key)
        .map_err(|_| CryptoError::AuthFailed)?;
    read_decrypted(decrypted, signer_public_key)
}

/// The plaintext of a decrypted message, and whether its signature verifies
/// for `signer_public_key` when given.
pub(crate) fn read_decrypted(
    mut decrypted: Message<'_>,
    signer_public_key: Option<&[u8]>,
) -> Result<DecryptedMessage> {
    if decrypted.is_compressed() {
        decrypted = decrypted
            .decompress()
            .map_err(|_| CryptoError::AuthFailed)?;
    }
    let signed = decrypted.is_one_pass_signed() || decrypted.is_signed();
    let data = Zeroizing::new(
        decrypted
            .as_data_vec()
            .map_err(|_| CryptoError::AuthFailed)?,
    );
    let verified = match signer_public_key {
        Some(public) => {
            let signer = SignedPublicKey::from_bytes(public)
                .map_err(|_| CryptoError::InvalidInput("signer key does not parse".into()))?;
            decrypted.verify(&signer.primary_key).is_ok()
        }
        None => false,
    };
    Ok(DecryptedMessage {
        data,
        signed,
        verified,
    })
}

/// One key in an address's signed key list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailKeyEntryV1 {
    pub fingerprint: [u8; FINGERPRINT_LEN],
    pub sha256_fingerprint: [u8; 32],
    pub primary: bool,
    pub flags: u32,
}

/// An address's signed key list (Proton's `SignedKeyList`): the keys it may
/// be reached with and which is primary, one link of a hash chain signed by
/// the account authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailKeyListV1 {
    /// The account's current keys (its incarnation) and the authority that
    /// signs: the list names no username, so a rename never touches it
    /// (docs/plans/account-ids.md; Proton's SignedKeyList names keys only).
    pub incarnation_id: [u8; 32],
    pub authority_key_id: [u8; 32],
    pub address: String,
    /// 1 for the first list, then + 1 per change.
    pub sequence: u64,
    /// [`SignedMailKeyListV1::hash`] of the list before; absent at sequence 1.
    pub previous_hash: Option<[u8; 32]>,
    /// RFC 3339, informational.
    pub issued_at: String,
    /// Strictly ordered by fingerprint; exactly one primary.
    pub keys: Vec<MailKeyEntryV1>,
}

impl MailKeyListV1 {
    fn validate(&self) -> Result<()> {
        let invalid = |reason: &str| {
            Err(CryptoError::InvalidInput(format!(
                "mail key list: {reason}"
            )))
        };
        if canonical_address(&self.address)? != self.address {
            return invalid("address is not canonical");
        }
        if self.sequence == 0 || (self.sequence == 1) != self.previous_hash.is_none() {
            return invalid("sequence and previous hash disagree");
        }
        if self.issued_at.is_empty()
            || self.issued_at.len() > MAX_ISSUED_AT_LEN
            || !self.issued_at.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return invalid("issuedAt is invalid");
        }
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS_PER_ADDRESS {
            return invalid("key count is invalid");
        }
        if !self
            .keys
            .windows(2)
            .all(|pair| pair[0].fingerprint < pair[1].fingerprint)
        {
            return invalid("keys are not strictly ordered by fingerprint");
        }
        if self.keys.iter().any(|key| key.flags & !KNOWN_FLAGS != 0) {
            return invalid("unknown key flag");
        }
        let mut primaries = self.keys.iter().filter(|key| key.primary);
        match (primaries.next(), primaries.next()) {
            (Some(primary), None) if primary.flags & DEFAULT_FLAGS == DEFAULT_FLAGS => Ok(()),
            (Some(_), None) => invalid("the primary key must be usable"),
            _ => invalid("exactly one key must be primary"),
        }
    }

    /// The canonical bytes, which are what the authority signs.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(256 + self.keys.len() * 57);
        out.extend_from_slice(KEY_LIST_DOMAIN);
        out.extend_from_slice(&KEY_LIST_VERSION.to_be_bytes());
        out.extend_from_slice(&self.incarnation_id);
        out.extend_from_slice(&self.authority_key_id);
        push_str(&mut out, &self.address)?;
        out.extend_from_slice(&self.sequence.to_be_bytes());
        match &self.previous_hash {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(hash);
            }
            None => out.push(0),
        }
        push_str(&mut out, &self.issued_at)?;
        out.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for key in &self.keys {
            out.extend_from_slice(&key.fingerprint);
            out.extend_from_slice(&key.sha256_fingerprint);
            out.push(u8::from(key.primary));
            out.extend_from_slice(&key.flags.to_be_bytes());
        }
        Ok(out)
    }

    /// Parses canonical bytes; anything but the one canonical encoding is refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let refused = || CryptoError::InvalidInput("mail key list is not canonical".into());
        let mut rest = bytes.strip_prefix(KEY_LIST_DOMAIN).ok_or_else(refused)?;
        if take(&mut rest, 2)? != KEY_LIST_VERSION.to_be_bytes() {
            return Err(refused());
        }
        let incarnation_id = take(&mut rest, 32)?.try_into().expect("32 bytes");
        let authority_key_id = take(&mut rest, 32)?.try_into().expect("32 bytes");
        let address = take_str(&mut rest)?.to_owned();
        let sequence = u64::from_be_bytes(take(&mut rest, 8)?.try_into().expect("8 bytes"));
        let previous_hash = match take(&mut rest, 1)?[0] {
            0 => None,
            1 => Some(take(&mut rest, 32)?.try_into().expect("32 bytes")),
            _ => return Err(refused()),
        };
        let issued_at = take_str(&mut rest)?.to_owned();
        let count = u32::from_be_bytes(take(&mut rest, 4)?.try_into().expect("4 bytes")) as usize;
        if count > MAX_KEYS_PER_ADDRESS {
            return Err(refused());
        }
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            let fingerprint = take(&mut rest, FINGERPRINT_LEN)?
                .try_into()
                .expect("20 bytes");
            let sha256_fingerprint = take(&mut rest, 32)?.try_into().expect("32 bytes");
            let primary = match take(&mut rest, 1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(refused()),
            };
            let flags = u32::from_be_bytes(take(&mut rest, 4)?.try_into().expect("4 bytes"));
            keys.push(MailKeyEntryV1 {
                fingerprint,
                sha256_fingerprint,
                primary,
                flags,
            });
        }
        if !rest.is_empty() {
            return Err(refused());
        }
        let list = Self {
            incarnation_id,
            authority_key_id,
            address,
            sequence,
            previous_hash,
            issued_at,
            keys,
        };
        if list.to_bytes()? != bytes {
            return Err(refused());
        }
        Ok(list)
    }

    /// Signs the list with the account authority.
    pub fn sign(&self, authority: &SigningKey) -> Result<SignedMailKeyListV1> {
        let authority_public = authority.verifying_key().to_bytes();
        self.check_authority(&authority_public)?;
        let data = self.to_bytes()?;
        let signature = authority.sign(&data).to_bytes();
        Ok(SignedMailKeyListV1 {
            list: self.clone(),
            data,
            signature,
        })
    }

    fn check_authority(&self, authority_public: &[u8; 32]) -> Result<()> {
        let key_id = hex::decode(authority_key_id_from_public(authority_public)).expect("hex");
        let incarnation =
            hex::decode(incarnation_id_from_authority_public(authority_public)).expect("hex");
        if key_id != self.authority_key_id || incarnation != self.incarnation_id {
            return Err(CryptoError::InvalidInput(
                "mail key list is not bound to this authority".into(),
            ));
        }
        Ok(())
    }
}

/// A key list with its authority signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedMailKeyListV1 {
    pub list: MailKeyListV1,
    /// The canonical bytes ([`MailKeyListV1::to_bytes`]).
    pub data: Vec<u8>,
    pub signature: [u8; 64],
}

impl SignedMailKeyListV1 {
    /// Parses `data` and checks `signature` against the account authority
    /// that the account's verified manifest binds.
    pub fn verify(data: &[u8], signature: &[u8], authority_public: &[u8; 32]) -> Result<Self> {
        let list = MailKeyListV1::from_bytes(data)?;
        list.check_authority(authority_public)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: 64,
                got: signature.len(),
            })?;
        VerifyingKey::from_bytes(authority_public)
            .map_err(|_| CryptoError::InvalidInput("authority key is invalid".into()))?
            .verify_strict(data, &Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok(Self {
            list,
            data: data.to_vec(),
            signature,
        })
    }

    /// What the next list's `previous_hash` must be: the list and its signature.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Checks that `next` directly follows `self` in the same chain.
    pub fn check_successor(&self, next: &Self) -> Result<()> {
        let (before, after) = (&self.list, &next.list);
        if after.address != before.address
            || after.incarnation_id != before.incarnation_id
            || after.authority_key_id != before.authority_key_id
            || after.sequence != before.sequence + 1
            || after.previous_hash != Some(self.hash())
        {
            return Err(CryptoError::InvalidInput(
                "mail key list does not follow the one before".into(),
            ));
        }
        Ok(())
    }
}

fn push_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| CryptoError::InvalidInput("string is too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if rest.len() < len {
        return Err(CryptoError::TooShort);
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head)
}

fn take_str<'a>(rest: &mut &'a [u8]) -> Result<&'a str> {
    let len = u16::from_be_bytes(take(rest, 2)?.try_into().expect("two bytes")) as usize;
    std::str::from_utf8(take(rest, len)?)
        .map_err(|_| CryptoError::InvalidInput("string is not UTF-8".into()))
}

pub(crate) fn backend(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::Backend(error.to_string())
}

/// A new address's first key, sealed, with its first signed key list (the
/// key alone, primary): what an account sends to give an address its key, at
/// sign-up or in a rename.
pub struct FirstAddressKey {
    pub key: GeneratedAddressKey,
    /// The secret key sealed under the master key for the account's binding.
    pub private_key_envelope: Vec<u8>,
    pub key_list: SignedMailKeyListV1,
}

/// Generates `address`'s first key for the account `identity` (master key
/// and key binding), created at `created_at_secs`, its list issued at
/// `issued_at` (RFC 3339).
pub fn first_address_key(
    identity: &crate::identity::AccountIdentityKeysV1,
    master_key: &[u8],
    binding: &str,
    address: &str,
    created_at_secs: u32,
    issued_at: &str,
) -> Result<FirstAddressKey> {
    let address = canonical_address(address)?;
    let key = generate_address_key(&address, created_at_secs)?;
    let private_key_envelope = seal_address_key(master_key, binding, &address, &key.secret_key)?;
    let hex32 = |value: String| -> Result<[u8; 32]> {
        hex::decode(value)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| CryptoError::InvalidInput("identity id".into()))
    };
    let key_list = MailKeyListV1 {
        incarnation_id: hex32(identity.incarnation_id())?,
        authority_key_id: hex32(identity.authority_key_id())?,
        address,
        sequence: 1,
        previous_hash: None,
        issued_at: issued_at.to_owned(),
        keys: vec![MailKeyEntryV1 {
            fingerprint: key.fingerprint,
            sha256_fingerprint: key.sha256_fingerprint,
            primary: true,
            flags: DEFAULT_FLAGS,
        }],
    }
    .sign(identity.authority_signing_key())?;
    Ok(FirstAddressKey {
        key,
        private_key_envelope,
        key_list,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AccountIdentityKeysV1;

    const ADDRESS: &str = "alice@kutup.dev";

    #[test]
    fn generated_keys_round_trip_and_inspect() {
        let alice = generate_address_key(ADDRESS, 1_790_000_000).unwrap();
        let bob = generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();
        let info = inspect_address_public_key(&alice.public_key, ADDRESS).unwrap();
        assert_eq!(info.fingerprint, alice.fingerprint);
        assert_eq!(info.sha256_fingerprint, alice.sha256_fingerprint);
        assert_eq!(info.created_at_secs, 1_790_000_000);
        assert!(inspect_address_public_key(&alice.public_key, "bob@kutup.dev").is_err());

        let message = encrypt(&bob.public_key, Some(&alice.secret_key), b"hello").unwrap();
        let opened = decrypt(&bob.secret_key, message.as_bytes(), Some(&alice.public_key)).unwrap();
        assert_eq!(&opened.data[..], b"hello");
        assert!(opened.verified);
        let unverified =
            decrypt(&bob.secret_key, message.as_bytes(), Some(&bob.public_key)).unwrap();
        assert!(!unverified.verified);
        assert!(decrypt(&alice.secret_key, message.as_bytes(), None).is_err());
        assert!(armor_public_key(&alice.public_key)
            .unwrap()
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }

    #[test]
    fn cleartext_signatures_verify_and_catch_changes() {
        let alice = generate_address_key(ADDRESS, 1_790_000_000).unwrap();
        let bob = generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();
        let text = "Merhaba Bob,\n\nİmzalı ama şifresiz.\n";
        let signed = sign_cleartext(&alice.secret_key, text).unwrap();
        assert!(signed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
        let (opened, verified) = verify_cleartext(&signed, Some(&alice.public_key)).unwrap();
        assert!(verified);
        // Cleartext signatures sign lines with CRLF endings.
        assert_eq!(opened.replace("\r\n", "\n").trim_end(), text.trim_end());
        assert!(!verify_cleartext(&signed, Some(&bob.public_key)).unwrap().1);
        let changed = signed.replace("Bob", "Eve");
        assert!(
            !verify_cleartext(&changed, Some(&alice.public_key))
                .unwrap()
                .1
        );
    }

    #[test]
    fn detached_signatures_and_unsigned_encryption() {
        let alice = generate_address_key(ADDRESS, 1_790_000_000).unwrap();
        let bob = generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();
        let part = b"Content-Type: text/plain; charset=utf-8\r\n\r\nMerhaba\r\n";
        let signature = sign_detached(&alice.secret_key, part).unwrap();
        assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(verify_detached(signature.as_bytes(), part, &alice.public_key).unwrap());
        // A changed part, or another signer, does not verify.
        assert!(!verify_detached(
            signature.as_bytes(),
            b"Content-Type: text/plain\r\n\r\nMerhaba!\r\n",
            &alice.public_key
        )
        .unwrap());
        assert!(!verify_detached(signature.as_bytes(), part, &bob.public_key).unwrap());
        // Encrypted without a signature (Sign off): opens, and is not signed.
        let armored = encrypt_armored(&[&bob.public_key], None, b"gizli", 1_790_000_100).unwrap();
        let opened = decrypt(&bob.secret_key, armored.as_bytes(), Some(&alice.public_key)).unwrap();
        assert_eq!(&opened.data[..], b"gizli");
        assert!(!opened.signed && !opened.verified);
    }

    #[test]
    fn envelopes_bind_address_and_fingerprint() {
        let master = [7u8; 32];
        let key = generate_address_key(ADDRESS, 1_790_000_000).unwrap();
        let sealed = seal_address_key(
            &master,
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            ADDRESS,
            &key.secret_key,
        )
        .unwrap();
        let opened = open_address_key(
            &sealed,
            &master,
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            ADDRESS,
            &key.fingerprint,
        )
        .unwrap();
        assert_eq!(&opened[..], &key.secret_key[..]);
        assert!(open_address_key(
            &sealed,
            &master,
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            "bob@kutup.dev",
            &key.fingerprint
        )
        .is_err());
        assert!(open_address_key(
            &sealed,
            &master,
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            ADDRESS,
            &[0; 20]
        )
        .is_err());
        assert!(open_address_key(
            &sealed,
            &master,
            "1c9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e91",
            ADDRESS,
            &key.fingerprint
        )
        .is_err());
        assert!(open_address_key(
            &sealed,
            &[8; 32],
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            ADDRESS,
            &key.fingerprint
        )
        .is_err());
    }

    fn list(
        identity: &AccountIdentityKeysV1,
        sequence: u64,
        previous: Option<[u8; 32]>,
        keys: Vec<MailKeyEntryV1>,
    ) -> MailKeyListV1 {
        MailKeyListV1 {
            incarnation_id: hex::decode(identity.incarnation_id())
                .unwrap()
                .try_into()
                .unwrap(),
            authority_key_id: hex::decode(identity.authority_key_id())
                .unwrap()
                .try_into()
                .unwrap(),
            address: ADDRESS.into(),
            sequence,
            previous_hash: previous,
            issued_at: "2026-10-09T12:00:00Z".into(),
            keys,
        }
    }

    fn entry(byte: u8, primary: bool) -> MailKeyEntryV1 {
        MailKeyEntryV1 {
            fingerprint: [byte; 20],
            sha256_fingerprint: [byte; 32],
            primary,
            flags: DEFAULT_FLAGS,
        }
    }

    #[test]
    fn key_lists_sign_verify_and_chain() {
        let identity = AccountIdentityKeysV1::derive(&[3u8; 32]).unwrap();
        let other = AccountIdentityKeysV1::derive(&[4u8; 32]).unwrap();
        let authority = identity.authority_public_key();
        let first = list(&identity, 1, None, vec![entry(1, true)])
            .sign(identity.authority_signing_key())
            .unwrap();
        let verified =
            SignedMailKeyListV1::verify(&first.data, &first.signature, &authority).unwrap();
        assert_eq!(verified, first);
        assert!(SignedMailKeyListV1::verify(
            &first.data,
            &first.signature,
            &other.authority_public_key()
        )
        .is_err());
        let mut tampered = first.signature;
        tampered[0] ^= 1;
        assert!(SignedMailKeyListV1::verify(&first.data, &tampered, &authority).is_err());

        let mut older = entry(1, false);
        older.flags = FLAG_NOT_COMPROMISED;
        let second = list(
            &identity,
            2,
            Some(first.hash()),
            vec![older, entry(2, true)],
        )
        .sign(identity.authority_signing_key())
        .unwrap();
        first.check_successor(&second).unwrap();
        assert!(second.check_successor(&first).is_err());
        let fork = list(&identity, 2, Some([9; 32]), vec![entry(2, true)])
            .sign(identity.authority_signing_key())
            .unwrap();
        assert!(first.check_successor(&fork).is_err());
        // A list cannot be signed by another account's authority.
        assert!(list(&identity, 1, None, vec![entry(1, true)])
            .sign(other.authority_signing_key())
            .is_err());
    }

    #[test]
    fn key_lists_refuse_invalid_shapes() {
        let identity = AccountIdentityKeysV1::derive(&[3u8; 32]).unwrap();
        let bad = [
            list(&identity, 1, None, vec![]),
            list(&identity, 1, None, vec![entry(1, false)]),
            list(&identity, 1, None, vec![entry(1, true), entry(2, true)]),
            list(&identity, 1, None, vec![entry(2, true), entry(1, false)]),
            list(&identity, 1, Some([0; 32]), vec![entry(1, true)]),
            list(&identity, 2, None, vec![entry(1, true)]),
        ];
        for list in bad {
            assert!(list.to_bytes().is_err());
        }
        let mut obsolete_primary = entry(1, true);
        obsolete_primary.flags = FLAG_NOT_COMPROMISED;
        assert!(list(&identity, 1, None, vec![obsolete_primary])
            .to_bytes()
            .is_err());
        let good = list(&identity, 1, None, vec![entry(1, true)])
            .to_bytes()
            .unwrap();
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(MailKeyListV1::from_bytes(&trailing).is_err());
        assert_eq!(
            MailKeyListV1::from_bytes(&good)
                .unwrap()
                .to_bytes()
                .unwrap(),
            good
        );
    }
}
