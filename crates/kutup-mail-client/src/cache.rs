//! The bridge's cache of opened messages (docs/plans/mail-bridge.md,
//! decision 7): each message, decrypted once, kept on disk in 256 KiB
//! blocks, every block sealed on its own (`local_state`, purpose
//! `MailBridgeCache`) with a fresh nonce and bound to its account, its
//! message, its place and the number of blocks. A block moved to another
//! place or message, one dropped, or the end cut off fails to open.
//!
//! Gluon's cache (Proton Bridge) uses one nonce for every block of a file
//! and binds no block to its place (gluon/store/disk.go); this doesn't.

use kutup_crypto::local_state::{open, seal, LocalStatePurpose};
use zeroize::Zeroizing;

/// The plaintext size of a block (Gluon's).
pub const BLOCK_SIZE: usize = 256 * 1024;

/// A cached message that doesn't open: tampered with, cut, or another's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a cached message does not open")]
pub struct CorruptCache;

fn profile(account: &str, message: &str, block: usize, blocks: usize) -> String {
    format!("{account}:{message}:{block}/{blocks}")
}

/// `bytes` sealed for the cache, block by block, under the bridge's 32-byte
/// local `key`. A message has headers at least: an empty one is refused.
pub fn seal_message(
    key: &[u8],
    account: &str,
    message: &str,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, CorruptCache> {
    if bytes.is_empty() {
        return Err(CorruptCache);
    }
    let chunks: Vec<&[u8]> = bytes.chunks(BLOCK_SIZE).collect();
    let blocks = chunks.len();
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            seal(
                chunk,
                key,
                LocalStatePurpose::MailBridgeCache,
                &profile(account, message, i, blocks),
            )
            .map_err(|_| CorruptCache)
        })
        .collect()
}

/// A cached message's blocks opened back into its bytes.
pub fn open_message(
    key: &[u8],
    account: &str,
    message: &str,
    sealed: &[Vec<u8>],
) -> Result<Zeroizing<Vec<u8>>, CorruptCache> {
    if sealed.is_empty() {
        return Err(CorruptCache);
    }
    let blocks = sealed.len();
    let mut out = Zeroizing::new(Vec::with_capacity(blocks * BLOCK_SIZE));
    for (i, block) in sealed.iter().enumerate() {
        let plain = Zeroizing::new(
            open(
                block,
                key,
                LocalStatePurpose::MailBridgeCache,
                &profile(account, message, i, blocks),
            )
            .map_err(|_| CorruptCache)?,
        );
        // Every block but the last is full: a short one in the middle is
        // not this message's.
        if i + 1 < blocks && plain.len() != BLOCK_SIZE {
            return Err(CorruptCache);
        }
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const ACCOUNT: &str = "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70";
    const MESSAGE: &str = "0b8e7c62-2f0d-4f43-9a51-3a1d6c8e9f01";

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn round_trips_any_length() {
        for len in [
            1,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            3 * BLOCK_SIZE + 17,
        ] {
            let bytes = message(len);
            let sealed = seal_message(&KEY, ACCOUNT, MESSAGE, &bytes).unwrap();
            assert_eq!(sealed.len(), len.div_ceil(BLOCK_SIZE));
            assert_eq!(
                open_message(&KEY, ACCOUNT, MESSAGE, &sealed)
                    .unwrap()
                    .as_slice(),
                bytes
            );
        }
    }

    #[test]
    fn an_empty_message_is_refused() {
        assert_eq!(
            seal_message(&KEY, ACCOUNT, MESSAGE, &[]).err(),
            Some(CorruptCache)
        );
    }

    #[test]
    fn every_block_has_its_own_nonce() {
        let sealed = seal_message(&KEY, ACCOUNT, MESSAGE, &vec![0u8; 2 * BLOCK_SIZE]).unwrap();
        // Two blocks of the same plaintext seal differently.
        assert_ne!(sealed[0], sealed[1]);
        let again = seal_message(&KEY, ACCOUNT, MESSAGE, &vec![0u8; 2 * BLOCK_SIZE]).unwrap();
        assert_ne!(sealed[0], again[0]);
    }

    #[test]
    fn a_block_moved_dropped_or_from_another_message_fails() {
        let bytes = message(3 * BLOCK_SIZE + 5);
        let sealed = seal_message(&KEY, ACCOUNT, MESSAGE, &bytes).unwrap();
        let swapped = vec![
            sealed[1].clone(),
            sealed[0].clone(),
            sealed[2].clone(),
            sealed[3].clone(),
        ];
        assert_eq!(
            open_message(&KEY, ACCOUNT, MESSAGE, &swapped).err(),
            Some(CorruptCache)
        );
        // The end cut off.
        assert_eq!(
            open_message(&KEY, ACCOUNT, MESSAGE, &sealed[..3]).err(),
            Some(CorruptCache)
        );
        // A middle block dropped.
        let dropped = vec![sealed[0].clone(), sealed[2].clone(), sealed[3].clone()];
        assert_eq!(
            open_message(&KEY, ACCOUNT, MESSAGE, &dropped).err(),
            Some(CorruptCache)
        );
        // Another message's, another account's, another key.
        assert!(open_message(&KEY, ACCOUNT, "other", &sealed).is_err());
        assert!(open_message(&KEY, "other", MESSAGE, &sealed).is_err());
        assert!(open_message(&[8; 32], ACCOUNT, MESSAGE, &sealed).is_err());
        assert!(open_message(&KEY, ACCOUNT, MESSAGE, &[]).is_err());
        // A flipped bit.
        let mut flipped = sealed.clone();
        let last = flipped[2].len() - 1;
        flipped[2][last] ^= 1;
        assert!(open_message(&KEY, ACCOUNT, MESSAGE, &flipped).is_err());
    }
}
