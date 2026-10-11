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

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::named_share::canonical_account;

const KEY_SALT: &[u8] = b"kutup/mail-names/v1\0";
const KEY_INFO: &[u8] = b"kutup/mail-names/name-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTMN1\0\0";
const AAD_DOMAIN: &[u8] = b"kutup/mail-name/v1\0";
const SUITE_V1: u16 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 2 + NONCE_LEN;

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

fn aad(account: &str, kind: MailNameKind, id: &[u8; 16]) -> Result<Vec<u8>> {
    let account = canonical_account(account).map_err(|_| invalid("account is not canonical"))?;
    let mut aad =
        Vec::with_capacity(MAGIC.len() + 2 + AAD_DOMAIN.len() + 2 + account.len() + 1 + 16);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&SUITE_V1.to_be_bytes());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&(account.len() as u16).to_be_bytes());
    aad.extend_from_slice(account.as_bytes());
    aad.push(kind as u8);
    aad.extend_from_slice(id);
    Ok(aad)
}

/// Seals a name: `magic ‖ suite ‖ nonce ‖ ciphertext`, bound to the account,
/// the kind and the id (a UUID's 16 bytes).
pub fn seal_name(
    key: &[u8; 32],
    account: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    name: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_name_with_nonce(key, account, kind, id, name, &nonce)
}

/// [`seal_name`] with a fixed nonce, for checked-in vectors only.
pub fn seal_name_with_nonce(
    key: &[u8; 32],
    account: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    name: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let name = check_name(name)?;
    let aad = aad(account, kind, id)?;
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: name.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Backend("mail name seal".into()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SUITE_V1.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a sealed name for `account`, `kind` and `id`.
pub fn open_name(
    key: &[u8; 32],
    account: &str,
    kind: MailNameKind,
    id: &[u8; 16],
    sealed: &[u8],
) -> Result<String> {
    inspect_name(sealed)?;
    let aad = aad(account, kind, id)?;
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&sealed[10..HEADER_LEN]),
            Payload {
                msg: &sealed[HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    let name = String::from_utf8(plain).map_err(|_| invalid("name is not UTF-8"))?;
    check_name(&name)?;
    Ok(name)
}

/// Checks a sealed name's framing and size without opening it (the server's view).
pub fn inspect_name(sealed: &[u8]) -> Result<()> {
    if sealed.len() <= HEADER_LEN + TAG_LEN || sealed.len() > HEADER_LEN + MAX_NAME_BYTES + TAG_LEN
    {
        return Err(invalid("sealed name size is invalid"));
    }
    if &sealed[..MAGIC.len()] != MAGIC || sealed[8..10] != SUITE_V1.to_be_bytes() {
        return Err(invalid("not a sealed mail name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "alice@kutup.dev";
    const ID: [u8; 16] = [7; 16];

    #[test]
    fn a_name_opens_only_where_it_was_sealed() {
        let key = derive_names_key(&[0x5a; 32]).unwrap();
        let sealed = seal_name(
            &key,
            ACCOUNT,
            MailNameKind::Folder,
            &ID,
            "  İş başvuruları ",
        )
        .unwrap();
        inspect_name(&sealed).unwrap();
        assert_eq!(
            open_name(&key, ACCOUNT, MailNameKind::Folder, &ID, &sealed).unwrap(),
            "İş başvuruları"
        );
        // Another id, kind, account or key: refused.
        assert!(open_name(&key, ACCOUNT, MailNameKind::Folder, &[8; 16], &sealed).is_err());
        assert!(open_name(&key, ACCOUNT, MailNameKind::Label, &ID, &sealed).is_err());
        assert!(open_name(&key, "bob@kutup.dev", MailNameKind::Folder, &ID, &sealed).is_err());
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
                seal_name(&key, ACCOUNT, MailNameKind::Label, &ID, bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(seal_name(&key, ACCOUNT, MailNameKind::Label, &ID, &"ş".repeat(100)).is_ok());
        assert!(inspect_name(b"KUTMN1\0\0").is_err());
        assert!(MailNameKind::parse("folder").is_ok() && MailNameKind::parse("box").is_err());
    }
}
