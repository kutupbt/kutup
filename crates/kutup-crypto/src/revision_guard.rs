//! What a client keeps of the revisions it has seen (docs/plans/sealed-revisions.md):
//! for each value the account replaces over time (a contact card, a mail
//! name, the identity pin list), the highest revision seen, so an older copy
//! from the server is refused.
//!
//! The browser keeps these in IndexedDB, which anyone with the disk can read
//! and write. So the entry's name is a keyed hash of what it is about (a
//! contact's UID can be an email address; folder ids and edit times say what
//! the account does), and the revision is an account record (purpose
//! `RevisionSeen`, docs/plans/w1-account-record.md) under the master key,
//! bound to the account's key binding and to that name. A disk attacker can
//! still delete entries, which only makes the device a fresh one again (the
//! first revision read is trusted), or put back an older copy of one; it can
//! no longer read them or set one to a revision it chooses.

use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::RevisionSeen;
const MAX_PART_LEN: usize = 1024;

/// The account's keys for its revision store: its master key and key binding.
pub struct GuardKeys {
    master: Zeroizing<[u8; 32]>,
    generation: MasterKeyGeneration,
    binding: String,
}

impl GuardKeys {
    /// The keys of the account bound by `binding`, under its master key's
    /// first generation (every account's, until master-key rotation exists).
    pub fn derive(master_key: &[u8; 32], binding: &str) -> Result<Self> {
        Ok(Self {
            master: Zeroizing::new(*master_key),
            generation: MasterKeyGeneration::FIRST,
            binding: account_record::canonical_binding(binding)?,
        })
    }

    /// The store's name for `scope`/`id` (hex), revealing neither: the
    /// record's object, [`account_record::hashed_object`] of the two,
    /// length-prefixed.
    pub fn entry_id(&self, scope: &str, id: &str) -> Result<String> {
        if scope.is_empty()
            || scope.len() > MAX_PART_LEN
            || id.is_empty()
            || id.len() > MAX_PART_LEN
        {
            return Err(CryptoError::InvalidInput(
                "revision guard: scope or id is invalid".into(),
            ));
        }
        let mut named = Vec::with_capacity(4 + scope.len() + id.len());
        named.extend_from_slice(&(scope.len() as u16).to_be_bytes());
        named.extend_from_slice(scope.as_bytes());
        named.extend_from_slice(&(id.len() as u16).to_be_bytes());
        named.extend_from_slice(id.as_bytes());
        Ok(hex::encode(account_record::hashed_object(
            &self.master,
            PURPOSE,
            &named,
        )))
    }

    fn object(entry_id: &str) -> Result<[u8; 32]> {
        hex::decode(entry_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| CryptoError::InvalidInput("revision guard: entry id is invalid".into()))
    }

    /// `revision`, sealed for entry `entry_id`.
    pub fn seal_seen(&self, entry_id: &str, revision: u64) -> Result<Vec<u8>> {
        account_record::seal_object(
            &revision.to_be_bytes(),
            self.master.as_slice(),
            PURPOSE,
            self.generation,
            &self.binding,
            &Self::object(entry_id)?,
        )
    }

    /// The revision sealed for entry `entry_id`; fails for one sealed for
    /// another entry or account, or altered.
    pub fn open_seen(&self, entry_id: &str, sealed: &[u8]) -> Result<u64> {
        let plain = account_record::open_object(
            sealed,
            self.master.as_slice(),
            PURPOSE,
            &self.binding,
            &Self::object(entry_id).map_err(|_| CryptoError::AuthFailed)?,
        )
        .map_err(|_| CryptoError::AuthFailed)?;
        Ok(u64::from_be_bytes(
            plain.try_into().map_err(|_| CryptoError::AuthFailed)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    #[test]
    fn entries_hide_what_they_are_about_and_open_only_where_sealed() {
        let keys = GuardKeys::derive(&[1; 32], BINDING).unwrap();
        let entry = keys.entry_id("contact", "ayse@example.com").unwrap();
        assert_eq!(entry.len(), 64);
        assert!(!entry.contains("ayse"));
        // Stable for the account; another account's differs.
        assert_eq!(entry, keys.entry_id("contact", "ayse@example.com").unwrap());
        let other = GuardKeys::derive(&[2; 32], BINDING).unwrap();
        assert_ne!(
            entry,
            other.entry_id("contact", "ayse@example.com").unwrap()
        );
        // The parts are length-prefixed: no ambiguity between scope and id.
        assert_ne!(
            keys.entry_id("ab", "c").unwrap(),
            keys.entry_id("a", "bc").unwrap()
        );

        let sealed = keys.seal_seen(&entry, 1_791_633_600_000).unwrap();
        assert_eq!(keys.open_seen(&entry, &sealed).unwrap(), 1_791_633_600_000);
        // Moved to another entry, opened by another account (another master
        // key or key binding), or altered: refused.
        let elsewhere = keys.entry_id("contact", "bob@example.com").unwrap();
        assert!(keys.open_seen(&elsewhere, &sealed).is_err());
        assert!(other.open_seen(&entry, &sealed).is_err());
        let rebound = GuardKeys::derive(&[1; 32], "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d").unwrap();
        assert!(rebound.open_seen(&entry, &sealed).is_err());
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(keys.open_seen(&entry, &altered).is_err());
        assert!(keys.entry_id("", "x").is_err());
        assert!(GuardKeys::derive(&[1; 32], "aci:x@example.com").is_err());
    }
}
