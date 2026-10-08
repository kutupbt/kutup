//! Names unique in a folder (docs/plans/drive-unique-names.md): the hash
//! keys and hashes the CLI sends with every write that names something,
//! from `kutup_crypto::drive_names`, which owns the format.

use anyhow::{Context, Result};
use kutup_crypto::drive_names;

use crate::keyring::Keyring;

/// A folder's hash key: from its first (epoch 1) key, which `keys` holds
/// (a keyring loaded with its history, or a folder still at epoch 1).
pub fn folder_hash_key(keys: &Keyring, collection_id: &str) -> Result<[u8; 32]> {
    let first = keys.at(1).context("the folder's first key")?;
    Ok(drive_names::folder_hash_key(first, collection_id)?)
}

/// The hash key for the account's top-level folders.
pub fn top_level_hash_key(master_key: &[u8]) -> Result<[u8; 32]> {
    Ok(drive_names::top_level_hash_key(master_key)?)
}

/// The hash `name` is kept unique by under `hash_key`.
pub fn name_hash(hash_key: &[u8; 32], name: &str) -> Result<String> {
    Ok(drive_names::name_hash(hash_key, name)?)
}

/// The hash a file's content is recognised by under `hash_key`.
pub fn content_hash(hash_key: &[u8; 32], content_sha256: &[u8; 32]) -> Result<String> {
    Ok(drive_names::content_hash(hash_key, content_sha256)?)
}

/// Names compared as the server compares them.
pub fn canonical(name: &str) -> String {
    drive_names::canonical_name(name)
}

/// `name`, or the first of `name (2)`, `name (3)`… not in `taken`
/// (canonical names); the number goes before the extension. A name already
/// ending in a number in brackets counts on from it. The web client's
/// `freeName` does the same.
pub fn free_name(name: &str, taken: &std::collections::HashSet<String>) -> String {
    if !taken.contains(&canonical(name)) {
        return name.to_string();
    }
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    let (base, start) = match numbered(stem) {
        Some((base, n)) => (base, n + 1),
        None => (stem, 2),
    };
    (start..)
        .map(|n| format!("{base} ({n}){extension}"))
        .find(|candidate| !taken.contains(&canonical(candidate)))
        .expect("an unbounded range finds a free name")
}

/// `("a", 3)` for `"a (3)"`.
fn numbered(stem: &str) -> Option<(&str, u64)> {
    let inner = stem.strip_suffix(')')?;
    let open = inner.rfind(" (")?;
    let digits = &inner[open + 2..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&inner[..open], digits.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn taken(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| canonical(n)).collect()
    }

    #[test]
    fn free_names_match_the_web_client() {
        assert_eq!(free_name("a.txt", &taken(&[])), "a.txt");
        assert_eq!(free_name("a.txt", &taken(&["A.TXT"])), "a (2).txt");
        assert_eq!(
            free_name("a.txt", &taken(&["a.txt", "a (2).txt"])),
            "a (3).txt"
        );
        assert_eq!(free_name("a (5).txt", &taken(&["a (5).txt"])), "a (6).txt");
        assert_eq!(free_name("Photos", &taken(&["photos"])), "Photos (2)");
        assert_eq!(free_name(".env", &taken(&[".env"])), ".env (2)");
        assert_eq!(
            free_name("archive.tar.gz", &taken(&["archive.tar.gz"])),
            "archive.tar (2).gz"
        );
    }

    #[test]
    fn a_folder_keeps_its_hash_key_through_rotations() {
        let first = [7u8; 32];
        let id = "11111111-1111-4111-8111-111111111111";
        let at_one = folder_hash_key(
            &crate::keyring::tests_support::keyring(&[(1, first)], 1),
            id,
        )
        .unwrap();
        let rotated = crate::keyring::tests_support::keyring(&[(1, first), (2, [9u8; 32])], 2);
        assert_eq!(folder_hash_key(&rotated, id).unwrap(), at_one);
        assert_eq!(at_one, drive_names::folder_hash_key(&first, id).unwrap());
    }
}
