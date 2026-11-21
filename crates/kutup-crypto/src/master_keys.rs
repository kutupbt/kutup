//! The account's master keys: the current one, which seals, and every older
//! one, which still opens what was sealed before a rotation
//! (docs/plans/mk-rotation-exercise.md).
//!
//! A rotation keeps the previous master key in a keyring record
//! ([`AccountRecordPurpose::MasterKeyKeyring`]) sealed under the new one: the
//! record of generation n+1 holds key n, so one chain reaches every older
//! key. Records are re-sealed lazily, so a reader picks the key by the
//! generation the record's header names ([`MasterKeys::key_for`]). A record
//! of a generation newer than the account's current one is refused: the key
//! this client holds is out of date (another device rotated), and it signs in
//! again.
//!
//! [`MasterKeys::encode`] is how a client keeps the set in memory or hands it
//! to a worker (the web session, the WASM calls). It is not a stored format:
//! a session sealed with it is sealed under a session key as a whole.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::MasterKeyKeyring;
const ENCODED_MAGIC: &[u8; 8] = b"KUTPMKS1";
const ENTRY_LEN: usize = 4 + 32;

/// The error a client gets for a record sealed under a newer master key than
/// the one it holds: another device rotated it, and this one signs in again.
pub const MASTER_KEY_STALE: &str = "masterKeyStale";

/// The most generations a set holds: far beyond any account's rotations, a
/// bound on what a decoder allocates.
pub const MAX_GENERATIONS: usize = 1024;

/// The account's master keys, by generation; the newest is the current one.
#[derive(Clone)]
pub struct MasterKeys {
    keys: BTreeMap<u32, Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for MasterKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKeys")
            .field("generation", &self.generation().get())
            .finish_non_exhaustive()
    }
}

fn stale() -> CryptoError {
    CryptoError::InvalidInput(MASTER_KEY_STALE.into())
}

impl MasterKeys {
    /// An account's first master key: no keyring yet.
    pub fn first(master_key: &[u8; 32]) -> Self {
        Self::only(master_key, MasterKeyGeneration::FIRST)
    }

    /// `master_key` at `generation`, with no older key reachable. For a
    /// client that only seals (a new account), or a test.
    pub fn only(master_key: &[u8; 32], generation: MasterKeyGeneration) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(generation.get(), Zeroizing::new(*master_key));
        Self { keys }
    }

    /// The account's keys: `master_key` at `generation` (the one its
    /// password opened), and every older one through `keyring` (the
    /// account's keyring records, in any order). The chain must reach
    /// generation 1 with no gap; a record that doesn't open, belongs to
    /// another account, or repeats a generation is refused.
    pub fn open(
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        binding: &str,
        keyring: &[Vec<u8>],
    ) -> Result<Self> {
        let mut by_holder: BTreeMap<u32, &[u8]> = BTreeMap::new();
        for record in keyring {
            let header = account_record::inspect(record)?;
            if header.purpose != PURPOSE {
                return Err(CryptoError::InvalidInput(
                    "a keyring record of another purpose".into(),
                ));
            }
            if by_holder
                .insert(header.generation.get(), record.as_slice())
                .is_some()
            {
                return Err(CryptoError::InvalidInput(
                    "two keyring records of one generation".into(),
                ));
            }
        }
        let mut keys = BTreeMap::new();
        keys.insert(generation.get(), Zeroizing::new(*master_key));
        let mut holder = generation.get();
        while holder > 1 {
            let record = by_holder.remove(&holder).ok_or_else(|| {
                CryptoError::InvalidInput(format!(
                    "the keyring has no record for master key {}",
                    holder - 1
                ))
            })?;
            let older = holder - 1;
            let key = &keys[&holder];
            let opened = Zeroizing::new(account_record::open_object(
                record,
                key.as_slice(),
                PURPOSE,
                binding,
                &older.to_be_bytes(),
            )?);
            if account_record::inspect(record)?.generation.get() != holder {
                return Err(CryptoError::AuthFailed);
            }
            let opened: [u8; 32] = opened
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidInput("a keyring key is not 32 bytes".into()))?;
            keys.insert(older, Zeroizing::new(opened));
            holder = older;
        }
        if !by_holder.is_empty() {
            // A record past the current generation: the server holds a
            // newer key than the one this client opened.
            return Err(stale());
        }
        Ok(Self { keys })
    }

    /// The keyring record a rotation writes: `previous` (at `previous_gen`)
    /// sealed under `next`, the key of the generation after it.
    pub fn seal_keyring(
        next: &[u8; 32],
        previous: &[u8; 32],
        previous_gen: MasterKeyGeneration,
        binding: &str,
    ) -> Result<Vec<u8>> {
        let next_gen = MasterKeyGeneration::new(
            previous_gen
                .get()
                .checked_add(1)
                .ok_or_else(|| CryptoError::InvalidInput("no generation after this".into()))?,
        )?;
        account_record::seal_object(
            previous,
            next,
            PURPOSE,
            next_gen,
            binding,
            &previous_gen.get().to_be_bytes(),
        )
    }

    /// [`Self::seal_keyring`] with a fixed nonce, for checked-in vectors.
    pub fn seal_keyring_with_nonce(
        next: &[u8; 32],
        previous: &[u8; 32],
        previous_gen: MasterKeyGeneration,
        binding: &str,
        nonce: &[u8; 24],
    ) -> Result<Vec<u8>> {
        let next_gen = MasterKeyGeneration::new(previous_gen.get() + 1)?;
        account_record::seal_suite(
            account_record::AccountRecordSuiteId::V1,
            previous,
            next,
            PURPOSE,
            next_gen,
            binding,
            &previous_gen.get().to_be_bytes(),
            None,
            nonce,
        )
    }

    /// The set after a rotation to `next`: every key this one holds, and
    /// `next` as the current one.
    pub fn rotated(&self, next: &[u8; 32]) -> Result<Self> {
        let generation = self
            .generation()
            .get()
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidInput("no generation after this".into()))?;
        let mut keys = self.keys.clone();
        keys.insert(generation, Zeroizing::new(*next));
        Ok(Self { keys })
    }

    /// The current generation.
    pub fn generation(&self) -> MasterKeyGeneration {
        let newest = *self.keys.keys().next_back().expect("a set is never empty");
        MasterKeyGeneration::new(newest).expect("generations are never 0")
    }

    /// The current master key: what everything new is sealed under.
    pub fn current(&self) -> &[u8; 32] {
        self.keys
            .values()
            .next_back()
            .expect("a set is never empty")
    }

    /// The key of `generation`; a newer one than the current is
    /// [`MASTER_KEY_STALE`].
    pub fn at(&self, generation: MasterKeyGeneration) -> Result<&[u8; 32]> {
        if generation > self.generation() {
            return Err(stale());
        }
        self.keys
            .get(&generation.get())
            .map(|key| &**key)
            .ok_or_else(|| {
                CryptoError::InvalidInput(format!(
                    "master key {} is not in this set",
                    generation.get()
                ))
            })
    }

    /// The key an account record opens under: the one of the generation its
    /// header names.
    pub fn key_for(&self, record: &[u8]) -> Result<&[u8; 32]> {
        self.at(account_record::inspect(record)?.generation)
    }

    /// A device-local record (one purpose with no revision, its object
    /// `object`) sealed again under the current key when an older one sealed
    /// it; `None` when it is current already. A device calls it after a
    /// rotation, as it opens its stores, so the older key is needed less.
    pub fn reseal_if_older(
        &self,
        record: &[u8],
        purpose: AccountRecordPurpose,
        binding: &str,
        object: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if account_record::inspect(record)?.generation == self.generation() {
            return Ok(None);
        }
        let plain = Zeroizing::new(account_record::open_object(
            record,
            self.key_for(record)?,
            purpose,
            binding,
            object,
        )?);
        account_record::seal_object(
            &plain,
            self.current(),
            purpose,
            self.generation(),
            binding,
            object,
        )
        .map(Some)
    }

    /// Every key, newest first: for device-local values whose format names
    /// no generation (they are tried in turn, and sealed again under the
    /// current one).
    pub fn newest_first(&self) -> impl Iterator<Item = (MasterKeyGeneration, &[u8; 32])> {
        self.keys.iter().rev().map(|(generation, key)| {
            (
                MasterKeyGeneration::new(*generation).expect("never 0"),
                &**key,
            )
        })
    }

    /// The set as one value to keep in memory or hand to a worker:
    /// `KUTPMKS1`, a count (u16), then each generation (u32) and key, newest
    /// first.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(10 + self.keys.len() * ENTRY_LEN));
        out.extend_from_slice(ENCODED_MAGIC);
        out.extend_from_slice(&(self.keys.len() as u16).to_be_bytes());
        for (generation, key) in self.newest_first() {
            out.extend_from_slice(&generation.get().to_be_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    /// [`Self::encode`] read back: the generations contiguous, newest first,
    /// down to 1.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let invalid = || CryptoError::InvalidInput("not a master-key set".into());
        let rest = bytes
            .strip_prefix(ENCODED_MAGIC.as_slice())
            .ok_or_else(invalid)?;
        if rest.len() < 2 {
            return Err(invalid());
        }
        let count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        let entries = &rest[2..];
        if count == 0 || count > MAX_GENERATIONS || entries.len() != count * ENTRY_LEN {
            return Err(invalid());
        }
        let mut keys = BTreeMap::new();
        let mut expected: Option<u32> = None;
        for entry in entries.as_chunks::<ENTRY_LEN>().0 {
            let generation = u32::from_be_bytes(entry[..4].try_into().expect("4 bytes"));
            if generation == 0 || expected.is_some_and(|e| e != generation) {
                return Err(invalid());
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&entry[4..]);
            keys.insert(generation, key);
            expected = Some(generation - 1);
        }
        if expected != Some(0) {
            return Err(invalid());
        }
        Ok(Self { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const OTHER: &str = "1c7c6f1d-5d2f-4c9f-8d3e-7b2f4e6d8c0a";
    const GEN1: MasterKeyGeneration = MasterKeyGeneration::FIRST;

    fn gen(n: u32) -> MasterKeyGeneration {
        MasterKeyGeneration::new(n).unwrap()
    }

    fn card(key: &[u8; 32], generation: MasterKeyGeneration) -> Vec<u8> {
        account_record::seal(
            &[9; 32],
            key,
            AccountRecordPurpose::ChatBackupRoot,
            generation,
            BINDING,
        )
        .unwrap()
    }

    #[test]
    fn a_keyring_chain_reaches_every_older_key() {
        let (k1, k2, k3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let ring = vec![
            MasterKeys::seal_keyring(&k3, &k2, gen(2), BINDING).unwrap(),
            MasterKeys::seal_keyring(&k2, &k1, GEN1, BINDING).unwrap(),
        ];
        let keys = MasterKeys::open(&k3, gen(3), BINDING, &ring).unwrap();
        assert_eq!(keys.generation(), gen(3));
        assert_eq!(keys.current(), &k3);
        for (key, generation) in [(&k1, GEN1), (&k2, gen(2)), (&k3, gen(3))] {
            let record = card(key, generation);
            assert_eq!(keys.key_for(&record).unwrap(), key);
            account_record::open(
                &record,
                keys.key_for(&record).unwrap(),
                AccountRecordPurpose::ChatBackupRoot,
                BINDING,
            )
            .unwrap();
        }
        let back = MasterKeys::decode(&keys.encode()).unwrap();
        assert_eq!(back.encode().as_slice(), keys.encode().as_slice());
    }

    #[test]
    fn a_newer_record_than_the_set_is_stale() {
        let keys = MasterKeys::first(&[1; 32]);
        let error = keys.key_for(&card(&[2; 32], gen(2))).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MASTER_KEY_STALE}")
        );
        // A keyring record past the generation the password opened: stale.
        let ring = vec![MasterKeys::seal_keyring(&[2; 32], &[1; 32], GEN1, BINDING).unwrap()];
        let error = MasterKeys::open(&[1; 32], GEN1, BINDING, &ring).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MASTER_KEY_STALE}")
        );
    }

    #[test]
    fn a_broken_chain_is_refused() {
        let (k1, k2, k3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        // A gap: no record for key 1.
        let gap = vec![MasterKeys::seal_keyring(&k3, &k2, gen(2), BINDING).unwrap()];
        assert!(MasterKeys::open(&k3, gen(3), BINDING, &gap).is_err());
        // Another account's record.
        let other = vec![MasterKeys::seal_keyring(&k2, &k1, GEN1, OTHER).unwrap()];
        assert!(MasterKeys::open(&k2, gen(2), BINDING, &other).is_err());
        // Under another key than the one the password opened.
        let wrong = vec![MasterKeys::seal_keyring(&k3, &k1, GEN1, BINDING).unwrap()];
        assert!(MasterKeys::open(&k2, gen(2), BINDING, &wrong).is_err());
        // Two of one generation.
        let twice = vec![
            MasterKeys::seal_keyring(&k2, &k1, GEN1, BINDING).unwrap(),
            MasterKeys::seal_keyring(&k2, &k1, GEN1, BINDING).unwrap(),
        ];
        assert!(MasterKeys::open(&k2, gen(2), BINDING, &twice).is_err());
    }

    #[test]
    fn decode_refuses_anything_but_a_full_set() {
        let keys = MasterKeys::first(&[1; 32]).rotated(&[2; 32]).unwrap();
        let encoded = keys.encode();
        assert!(MasterKeys::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut gap = encoded.to_vec();
        // Generation 1 renamed 0.
        gap[10 + ENTRY_LEN..10 + ENTRY_LEN + 4].copy_from_slice(&0u32.to_be_bytes());
        assert!(MasterKeys::decode(&gap).is_err());
        assert!(MasterKeys::decode(&[1; 32]).is_err());
        assert!(MasterKeys::decode(&MasterKeys::only(&[1; 32], gen(2)).encode()).is_err());
    }
}
