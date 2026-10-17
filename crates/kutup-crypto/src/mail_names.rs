//! Sealed names of an account's mail folders, labels and filters
//! (docs/plans/mail-filters.md).
//!
//! Proton stores these names readable. Kutup seals them in the browser, as
//! Drive seals file names: the server keeps ids, colours, order and the
//! folder tree, and filters point at ids, so it never needs "Lawyer" or
//! "Job search". Each name is sealed with XChaCha20-Poly1305 under a key
//! derived from the account's master key and bound to the account, the kind
//! of thing it names and its id, so a server cannot move a name from one
//! folder to another, or from a label to a folder.
//!
//! A name changes when it is renamed, so it carries its revision (a time in
//! unix milliseconds, above every revision seen) in its header, under the
//! AAD: the server cannot pass an older name off as the newest. Names are
//! padded to a multiple of 256 bytes, so a sealed name says nothing of its
//! length.
//!
//! Suite 2 (`KUTMN2`) binds the account by its key binding
//! (docs/plans/account-identity.md), never by its address, which may change.
//! Suite 1 (bound to the address) is not read: nothing from before carries
//! over.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::key_binding;
use crate::padding::Length;

const KEY_SALT: &[u8] = b"kutup/mail-names/v1\0";
const KEY_INFO: &[u8] = b"kutup/mail-names/name-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTMN2\0\0";
const AAD_DOMAIN: &[u8] = b"kutup/mail-name/v2\0";
const SUITE: u16 = 2;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const REVISION_LEN: usize = 8;
const HEADER_LEN: usize = 8 + 2 + REVISION_LEN + NONCE_LEN;
/// How a name is padded before it is sealed.
const PADDING: Length = Length::Bucket(256);

/// The longest name, in characters.
pub const MAX_NAME_CHARS: usize = 100;
/// The longest name, in bytes (UTF-8).
pub const MAX_NAME_BYTES: usize = 400;

/// What a sealed name names; part of the authenticated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MailNameKind {
    Folder = 1,
    Label = 2,
    Filter = 3,
}

impl MailNameKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "folder" => Ok(Self::Folder),
            "label" => Ok(Self::Label),
            "filter" => Ok(Self::Filter),
            _ => Err(invalid("unknown mail name kind")),
        }
    }
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("mail name: {message}"))
}

/// The account's key for mail names, derived from the master key.
pub fn derive_names_key(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(KEY_SALT), master_key)
        .expand(KEY_INFO, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("mail names key HKDF expand".into()))?;
    Ok(key)
}

/// A name as people type it: trimmed, 1 to 100 characters, no control characters.
pub fn check_name(name: &str) -> Result<&str> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > MAX_NAME_CHARS
        || trimmed.len() > MAX_NAME_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err(invalid(
            "a name is 1 to 100 characters, without control characters",
        ));
    }
    Ok(trimmed)
}

fn check_revision(revision: u64) -> Result<()> {
    if revision == 0 {
        return Err(invalid("revisions start at 1"));
    }
    Ok(())
}

fn aad(binding: &str, kind: MailNameKind, id: &[u8; 16], revision: u64) -> Result<Vec<u8>> {
    let binding = key_binding::check(binding).map_err(|_| invalid("key binding is invalid"))?;
    check_revision(revision)?;
    let mut aad =
        Vec::with_capacity(MAGIC.len() + 2 + AAD_DOMAIN.len() + 2 + binding.len() + 1 + 16 + 8);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&SUITE.to_be_bytes());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&(binding.len() as u16).to_be_bytes());
    aad.extend_from_slice(binding.as_bytes());
    aad.push(kind as u8);
    aad.extend_from_slice(id);
    aad.extend_from_slice(&revision.to_be_bytes());
    Ok(aad)
}

/// Seals revision `revision` of a name: `magic ‖ suite ‖ revision ‖ nonce ‖
/// ciphertext`, bound to the account's key binding, the kind, the id (a
/// UUID's 16 bytes) and the revision.
pub fn seal_name(
    key: &[u8; 32],
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    revision: u64,
    name: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_name_with_nonce(key, binding, kind, id, revision, name, &nonce)
}

/// [`seal_name`] with a fixed nonce, for checked-in vectors only.
pub fn seal_name_with_nonce(
    key: &[u8; 32],
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    revision: u64,
    name: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let name = check_name(name)?;
    let aad = aad(binding, kind, id, revision)?;
    let padded = PADDING.pad(name.as_bytes())?;
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &padded,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Backend("mail name seal".into()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SUITE.to_be_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a sealed name of the account whose key binding is `binding`, for
/// `kind` and `id`: the name and the revision it was sealed at (refuse one
/// older than seen).
pub fn open_name(
    key: &[u8; 32],
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    sealed: &[u8],
) -> Result<(String, u64)> {
    let revision = inspect_name(sealed)?;
    let aad = aad(binding, kind, id, revision)?;
    let padded = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&sealed[10 + REVISION_LEN..HEADER_LEN]),
            Payload {
                msg: &sealed[HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    let plain = PADDING.unpad(padded)?;
    let name = String::from_utf8(plain).map_err(|_| invalid("name is not UTF-8"))?;
    check_name(&name)?;
    Ok((name, revision))
}

/// Checks a sealed name's framing, padded size and revision without opening
/// it (the server's view), and returns the revision.
pub fn inspect_name(sealed: &[u8]) -> Result<u64> {
    let max = PADDING.padded_len(MAX_NAME_BYTES).expect("fits") + HEADER_LEN + TAG_LEN;
    if sealed.len() <= HEADER_LEN + TAG_LEN
        || sealed.len() > max
        || !PADDING.allows_padded_len(sealed.len() - HEADER_LEN - TAG_LEN)
    {
        return Err(invalid("sealed name size is invalid"));
    }
    if &sealed[..MAGIC.len()] != MAGIC || sealed[8..10] != SUITE.to_be_bytes() {
        return Err(invalid("not a sealed mail name"));
    }
    let revision = u64::from_be_bytes(sealed[10..10 + REVISION_LEN].try_into().expect("8"));
    check_revision(revision)?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const ID: [u8; 16] = [7; 16];

    #[test]
    fn a_name_opens_only_where_it_was_sealed() {
        let key = derive_names_key(&[0x5a; 32]).unwrap();
        let sealed = seal_name(
            &key,
            ACCOUNT,
            MailNameKind::Folder,
            &ID,
            9,
            "  İş başvuruları ",
        )
        .unwrap();
        assert_eq!(inspect_name(&sealed).unwrap(), 9);
        assert_eq!(sealed.len(), HEADER_LEN + 256 + TAG_LEN);
        assert_eq!(
            open_name(&key, ACCOUNT, MailNameKind::Folder, &ID, &sealed).unwrap(),
            ("İş başvuruları".to_owned(), 9)
        );
        // An older name relabelled as newer does not open.
        let mut relabelled = sealed.clone();
        relabelled[10..18].copy_from_slice(&10u64.to_be_bytes());
        assert!(open_name(&key, ACCOUNT, MailNameKind::Folder, &ID, &relabelled).is_err());
        // Another id, kind, key binding or key, or the address: refused.
        assert!(open_name(&key, ACCOUNT, MailNameKind::Folder, &[8; 16], &sealed).is_err());
        assert!(open_name(&key, ACCOUNT, MailNameKind::Label, &ID, &sealed).is_err());
        assert!(open_name(
            &key,
            "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d",
            MailNameKind::Folder,
            &ID,
            &sealed
        )
        .is_err());
        assert!(open_name(&key, "alice@kutup.dev", MailNameKind::Folder, &ID, &sealed).is_err());
        let other = derive_names_key(&[0x5b; 32]).unwrap();
        assert!(open_name(&other, ACCOUNT, MailNameKind::Folder, &ID, &sealed).is_err());
        // Tampering is caught.
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(open_name(&key, ACCOUNT, MailNameKind::Folder, &ID, &flipped).is_err());
    }

    #[test]
    fn names_are_checked() {
        let key = derive_names_key(&[1; 32]).unwrap();
        for bad in ["", "   ", "a\nb", &"x".repeat(101)] {
            assert!(
                seal_name(&key, ACCOUNT, MailNameKind::Label, &ID, 1, bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(seal_name(&key, ACCOUNT, MailNameKind::Label, &ID, 1, &"ş".repeat(100)).is_ok());
        assert!(seal_name(&key, ACCOUNT, MailNameKind::Label, &ID, 0, "x").is_err());
        assert!(inspect_name(b"KUTMN2\0\0").is_err());
        let mut old = seal_name(&key, ACCOUNT, MailNameKind::Label, &ID, 1, "x").unwrap();
        old[..8].copy_from_slice(b"KUTMN1\0\0");
        old[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(inspect_name(&old).is_err());
        assert!(MailNameKind::parse("folder").is_ok() && MailNameKind::parse("box").is_err());
    }
}
