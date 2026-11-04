//! Sealed names of an account's mail folders, labels and filters
//! (docs/plans/mail-filters.md).
//!
//! Proton stores these names readable. Kutup seals them in the browser, as
//! Drive seals file names: the server keeps ids, colours, order and the
//! folder tree, and filters point at ids, so it never needs "Lawyer" or
//! "Job search". Each name is an account record (`account_record`, purpose
//! `MailName`) under the master key, whose object is the kind of thing it
//! names and its id, so a server cannot move a name from one folder to
//! another, or from a label to a folder.
//!
//! A name changes when it is renamed, so it carries its revision (a time in
//! unix milliseconds, above every revision seen) in its header, under the
//! AAD: the server cannot pass an older name off as the newest. Names are
//! padded to a multiple of 256 bytes, so a sealed name says nothing of its
//! length.
//!
//! The record binds the account by its key binding
//! (docs/plans/account-identity.md), never by its address, which may change.

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::error::{CryptoError, Result};

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

/// A name's object in its account record: the kind, then the id.
fn object(kind: MailNameKind, id: &[u8; 16]) -> [u8; 17] {
    let mut object = [0u8; 17];
    object[0] = kind as u8;
    object[1..].copy_from_slice(id);
    object
}

/// Seals revision `revision` of a name under the master key, bound to the
/// account's key binding, the kind, the id (a UUID's 16 bytes) and the
/// revision.
pub fn seal_name(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    revision: u64,
    name: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    crate::primitives::random(&mut nonce);
    seal_name_with_nonce(master_key, generation, binding, kind, id, revision, name, &nonce)
}

/// [`seal_name`] with a fixed nonce, for checked-in vectors only.
#[allow(clippy::too_many_arguments)]
pub fn seal_name_with_nonce(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    revision: u64,
    name: &str,
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    let name = check_name(name)?;
    check_revision(revision)?;
    account_record::seal_suite(
        account_record::AccountRecordSuiteId::V1,
        name.as_bytes(),
        master_key,
        AccountRecordPurpose::MailName,
        generation,
        binding,
        &object(kind, id),
        Some(revision),
        nonce,
    )
}

/// Opens a sealed name of the account whose key binding is `binding`, for
/// `kind` and `id`: the name and the revision it was sealed at (refuse one
/// older than seen).
pub fn open_name(
    master_key: &[u8; 32],
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    sealed: &[u8],
) -> Result<(String, u64)> {
    let (plain, revision) = account_record::open_revision(
        sealed,
        master_key,
        AccountRecordPurpose::MailName,
        binding,
        &object(kind, id),
    )?;
    let name = String::from_utf8(plain).map_err(|_| invalid("name is not UTF-8"))?;
    check_name(&name)?;
    check_revision(revision)?;
    Ok((name, revision))
}

/// What the server checks before storing a name: a well-formed name record
/// of the account bound by `binding`, for `kind` and `id`, at a valid
/// revision, which it returns.
pub fn validate_name(
    sealed: &[u8],
    binding: &str,
    kind: MailNameKind,
    id: &[u8; 16],
) -> Result<u64> {
    let header = account_record::validate_for(
        sealed,
        AccountRecordPurpose::MailName,
        binding,
        &object(kind, id),
    )?;
    let revision = header
        .revision
        .ok_or_else(|| invalid("a name has a revision"))?;
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
