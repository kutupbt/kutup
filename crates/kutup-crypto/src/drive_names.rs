//! Names unique in a folder without the server reading them, and files the
//! server can recognise as already there without learning their content
//! (docs/plans/drive-unique-names.md; Proton Drive's name and content
//! hashes, with SHA-256).
//!
//! Each folder has a hash key, derived from its **first** folder key (epoch
//! 1), which every member reaches by walking the folder's key chain
//! (`collection_keyring`): the same key whatever the folder has been
//! rotated to since, so a rotation rehashes nothing. From it:
//!
//! An account's top-level folders, with no folder above them, use one hash
//! key derived from the account master key.
//!
//! - a **name hash**, `HMAC-SHA256(hash key, "name" ‖ 0 ‖ canonical name)`,
//!   stored with every file and folder; the server keeps them unique in a
//!   folder;
//! - a **content hash**, `HMAC-SHA256(hash key, "content" ‖ 0 ‖ SHA-256 of
//!   the plaintext)`, stored with every file; an upload whose name hash and
//!   content hash both match a file already there is not sent.
//!
//! Both are lowercase hex. The canonical name makes names that differ only
//! in letter case or Unicode composition the same: NFC, then Unicode's
//! default (locale-independent) lowercase, then NFC again. So `Report.pdf`
//! and `report.pdf` clash; Turkish dotted capital `İ` lowercases to `i` +
//! combining dot above, so `İstanbul` and `istanbul` stay different names
//! while `ISTANBUL` and `istanbul` do not.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::{CryptoError, Result};

const HASH_KEY_INFO: &[u8] = b"kutup/drive/folder-hash-key/v1";
const TOP_LEVEL_INFO: &[u8] = b"kutup/drive/top-level-names/v1";
const NAME_LABEL: &[u8] = b"name\0";
const CONTENT_LABEL: &[u8] = b"content\0";

/// A folder's hash key, from its first (epoch 1) folder key.
pub fn folder_hash_key(first_folder_key: &[u8], collection_id: &str) -> Result<[u8; 32]> {
    if first_folder_key.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "folder key must be 32 bytes".into(),
        ));
    }
    if collection_id.is_empty() {
        return Err(CryptoError::InvalidInput("folder id is empty".into()));
    }
    let hkdf = Hkdf::<Sha256>::new(Some(collection_id.as_bytes()), first_folder_key);
    let mut key = [0u8; 32];
    hkdf.expand(HASH_KEY_INFO, &mut key)
        .map_err(|_| CryptoError::InvalidInput("folder hash key derivation failed".into()))?;
    Ok(key)
}

/// The hash key for an account's top-level folders, which have no folder
/// above them: from the account master key.
pub fn top_level_hash_key(master_key: &[u8]) -> Result<[u8; 32]> {
    if master_key.len() != 32 {
        return Err(CryptoError::InvalidInput("master key must be 32 bytes".into()));
    }
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut key = [0u8; 32];
    hkdf.expand(TOP_LEVEL_INFO, &mut key)
        .map_err(|_| CryptoError::InvalidInput("top-level hash key derivation failed".into()))?;
    Ok(key)
}

/// The form two names are compared in: case and Unicode composition do not
/// make them different.
pub fn canonical_name(name: &str) -> String {
    let composed: String = name.nfc().collect();
    composed.to_lowercase().nfc().collect()
}

fn mac(hash_key: &[u8], label: &[u8], value: &[u8]) -> Result<String> {
    if hash_key.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "folder hash key must be 32 bytes".into(),
        ));
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hash_key)
        .map_err(|_| CryptoError::InvalidInput("folder hash key must be 32 bytes".into()))?;
    mac.update(label);
    mac.update(value);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// The hash a name is kept unique by in its folder.
pub fn name_hash(hash_key: &[u8], name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(CryptoError::InvalidInput("name is empty".into()));
    }
    mac(hash_key, NAME_LABEL, canonical_name(name).as_bytes())
}

/// The hash a file's content is recognised by in its folder, from the
/// SHA-256 of its plaintext.
pub fn content_hash(hash_key: &[u8], content_sha256: &[u8]) -> Result<String> {
    if content_sha256.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "content digest must be 32 bytes".into(),
        ));
    }
    mac(hash_key, CONTENT_LABEL, content_sha256)
}

/// SHA-256 of a whole plaintext held in memory (small files, tests); large
/// files are hashed a chunk at a time by the client.
pub fn content_sha256(plaintext: &[u8]) -> [u8; 32] {
    Sha256::digest(plaintext).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn the_hash_key_belongs_to_the_folder() {
        let key = folder_hash_key(&[7u8; 32], ID).unwrap();
        assert_eq!(key, folder_hash_key(&[7u8; 32], ID).unwrap());
        assert_ne!(key, folder_hash_key(&[8u8; 32], ID).unwrap());
        assert_ne!(
            key,
            folder_hash_key(&[7u8; 32], "22222222-2222-4222-8222-222222222222").unwrap()
        );
        assert!(folder_hash_key(&[7u8; 31], ID).is_err());
        let top = top_level_hash_key(&[7u8; 32]).unwrap();
        assert_ne!(top, key);
        assert_ne!(top, top_level_hash_key(&[8u8; 32]).unwrap());
        assert!(top_level_hash_key(&[7u8; 31]).is_err());
    }

    #[test]
    fn names_differing_in_case_or_composition_clash() {
        let key = folder_hash_key(&[7u8; 32], ID).unwrap();
        let hash = |name: &str| name_hash(&key, name).unwrap();
        assert_eq!(hash("Report.pdf"), hash("report.PDF"));
        // é precomposed and e + combining acute.
        assert_eq!(hash("Caf\u{e9}.txt"), hash("Cafe\u{301}.txt"));
        assert_eq!(hash("ISTANBUL.md"), hash("istanbul.md"));
        assert_eq!(hash("ŞEKER.txt"), hash("şeker.txt"));
        assert_eq!(hash("ĞÜÖÇ"), hash("ğüöç"));
        // Turkish dotted capital İ keeps its dot: a different name.
        assert_ne!(hash("İstanbul.md"), hash("istanbul.md"));
        assert_ne!(hash("a.txt"), hash("b.txt"));
        assert_ne!(hash("a.txt"), hash(" a.txt"));
        assert!(name_hash(&key, "").is_err());
    }

    #[test]
    fn names_and_contents_never_share_a_hash() {
        let key = folder_hash_key(&[7u8; 32], ID).unwrap();
        let digest = content_sha256(b"hello");
        assert_eq!(
            content_hash(&key, &digest).unwrap(),
            content_hash(&key, &digest).unwrap()
        );
        assert_ne!(
            content_hash(&key, &digest).unwrap(),
            content_hash(&key, &content_sha256(b"hello!")).unwrap()
        );
        let other = folder_hash_key(&[9u8; 32], ID).unwrap();
        assert_ne!(
            content_hash(&key, &digest).unwrap(),
            content_hash(&other, &digest).unwrap()
        );
        assert!(content_hash(&key, &digest[..31]).is_err());
        assert_eq!(content_hash(&key, &digest).unwrap().len(), 64);
    }
}
