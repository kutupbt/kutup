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

/// `name`, then `name (2)`, `name (3)`…: the number goes before the
/// extension, and a name already ending in a number in brackets counts on
/// from it. The web client's `freeName` tries the same names.
pub fn numbered_names(name: &str) -> impl Iterator<Item = String> {
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    let (base, start) = match numbered(stem) {
        Some((base, n)) => (base, n + 1),
        None => (stem, 2),
    };
    let (base, extension) = (base.to_string(), extension.to_string());
    std::iter::once(name.to_string())
        .chain((start..).map(move |n| format!("{base} ({n}){extension}")))
}

/// How many names [`first_available`] tries before giving up.
const MAX_TRIED: usize = 1000;

/// The first of `candidates` that no item holds in a folder (`None`: the
/// account's top level) and `skip` allows, with its hash: the server is
/// asked ten hashes at a time, as Proton Drive's `findAvailableName`.
pub fn first_available(
    client: &crate::api::Client,
    collection_id: Option<&str>,
    hash_key: &[u8; 32],
    candidates: impl Iterator<Item = String>,
    skip: impl Fn(&str) -> bool,
) -> Result<(String, String)> {
    let mut candidates = candidates.filter(|name| !skip(name)).take(MAX_TRIED);
    loop {
        let batch: Vec<(String, String)> = candidates
            .by_ref()
            .take(crate::api::MAX_ASKED_HASHES)
            .map(|name| name_hash(hash_key, &name).map(|hash| (name, hash)))
            .collect::<Result<_>>()?;
        if batch.is_empty() {
            anyhow::bail!("no free name found after {MAX_TRIED} tries");
        }
        let hashes: Vec<String> = batch.iter().map(|(_, hash)| hash.clone()).collect();
        let available = client
            .available_hashes(collection_id, &hashes)
            .context("ask which names are free")?;
        if let Some(found) = batch.into_iter().find(|(_, hash)| available.contains(hash)) {
            return Ok(found);
        }
    }
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

    fn free_name(name: &str, taken: &HashSet<String>) -> String {
        numbered_names(name)
            .find(|candidate| !taken.contains(&canonical(candidate)))
            .unwrap()
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
    fn numbered_names_count_on() {
        let names: Vec<String> = numbered_names("a (5).txt").take(3).collect();
        assert_eq!(names, ["a (5).txt", "a (6).txt", "a (7).txt"]);
        let names: Vec<String> = numbered_names("Photos").take(2).collect();
        assert_eq!(names, ["Photos", "Photos (2)"]);
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
