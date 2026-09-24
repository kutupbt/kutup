//! A file's keys across its generations (docs/plans/drive-move.md).
//!
//! A file is re-keyed before anything new is written to it once its folder
//! has rotated past it (docs/plans/drive-share-revocation.md). Each new
//! generation `g` keeps the key of `g − 1` sealed under its own
//! (`DriveEnvelopePurpose::PreviousFileKey`), so whoever holds the current
//! file key reaches every older one — in whichever folder the file is. Only
//! the current key is wrapped with a folder key; moving a file re-wraps that
//! one key.
//!
//! The chain carries no signatures: an envelope under a key the server does
//! not hold cannot be forged, and each is bound to its file and generation,
//! so a server can withhold the chain but not substitute or reorder it.

use zeroize::Zeroizing;

use crate::drive_envelope::{self, DriveEnvelopeContextV1};
use crate::error::{CryptoError, Result};

/// One generation of a file's key history as the server returns it.
#[derive(Clone, Debug)]
pub struct FileKeyLinkV1 {
    /// The generation whose key seals the previous one (≥ 2).
    pub generation: u32,
    /// The key of `generation − 1` sealed under the key of `generation`, base64.
    pub previous_key_envelope: String,
}

/// Seal the file key of `generation − 1` under the key of `generation`.
pub fn seal_previous_key(
    previous_key: &[u8],
    key: &[u8],
    file_id: &str,
    generation: u32,
) -> Result<String> {
    drive_envelope::seal_b64(
        previous_key,
        key,
        DriveEnvelopeContextV1::previous_file_key(file_id, generation)?,
    )
}

/// The file key of `wanted`, from the current key of `generation` and the
/// file's history. `chain` holds each generation from 2 to `generation` in
/// order (the server returns exactly that); only the links between the two
/// are opened.
pub fn key_at(
    current_key: &[u8],
    file_id: &str,
    generation: u32,
    chain: &[FileKeyLinkV1],
    wanted: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    if wanted == 0 || wanted > generation {
        return Err(CryptoError::InvalidInput(
            "no such file key generation".into(),
        ));
    }
    if chain.len() + 1 != generation as usize
        || chain
            .iter()
            .enumerate()
            .any(|(index, link)| link.generation as usize != index + 2)
    {
        return Err(CryptoError::InvalidInput(
            "file key history is incomplete or out of order".into(),
        ));
    }
    let mut key = Zeroizing::new(current_key.to_vec());
    for link in chain[wanted as usize - 1..].iter().rev() {
        key = Zeroizing::new(drive_envelope::open_b64(
            &link.previous_key_envelope,
            &key,
            DriveEnvelopeContextV1::previous_file_key(file_id, link.generation)?,
        )?);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "33333333-3333-4333-8333-333333333333";

    fn history() -> (Vec<[u8; 32]>, Vec<FileKeyLinkV1>) {
        let keys = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let links = (2..=3u32)
            .map(|generation| FileKeyLinkV1 {
                generation,
                previous_key_envelope: seal_previous_key(
                    &keys[generation as usize - 2],
                    &keys[generation as usize - 1],
                    FILE,
                    generation,
                )
                .unwrap(),
            })
            .collect();
        (keys, links)
    }

    #[test]
    fn walks_down_to_every_generation() {
        let (keys, links) = history();
        for wanted in 1..=3u32 {
            let key = key_at(&keys[2], FILE, 3, &links, wanted).unwrap();
            assert_eq!(key.as_slice(), keys[wanted as usize - 1]);
        }
        assert!(key_at(&keys[2], FILE, 3, &links, 4).is_err());
        assert!(key_at(&keys[2], FILE, 3, &links, 0).is_err());
    }

    #[test]
    fn a_chain_must_be_whole_ordered_and_this_files() {
        let (keys, links) = history();
        assert!(key_at(&keys[2], FILE, 3, &links[1..], 2).is_err());
        let mut swapped = links.clone();
        swapped.swap(0, 1);
        assert!(key_at(&keys[2], FILE, 3, &swapped, 1).is_err());
        assert!(key_at(&keys[2], OTHER, 3, &links, 1).is_err());
        // A key that is not the current one opens nothing.
        assert!(key_at(&keys[1], FILE, 3, &links, 1).is_err());
    }
}
