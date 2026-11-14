//! What a device keeps of the account-private chains it has read (the Photos
//! library, the Chat attachment ledger): the newest state seen of each, its
//! revision (or cursor) and the chain's digest at that revision, so a server
//! that hands back an older state, or another state at the same revision, is
//! caught.
//!
//! Like the revision guard's entries (`revision_guard`), pins live on the
//! device's disk, where anyone with the disk can read and write them. So a
//! pin's name is a keyed hash of the chain's scope and id, and the pin is an
//! account record (purpose `LocalChainPin`, docs/plans/w1-account-record.md)
//! under the master key, bound to the account's key binding and to that name.
//! A disk attacker can delete a pin (the chain is then unseen on this device,
//! and the first state read is trusted) or put back an older copy of it; it
//! can neither read pins nor set one to a state it chooses. A pin that does
//! not open is treated as unseen.

use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::LocalChainPin;
const MAX_PART_LEN: usize = 1024;

/// A chain's newest state seen on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPin {
    /// The chain's revision or cursor.
    pub revision: u64,
    /// The chain's digest at that revision.
    pub digest: [u8; 32],
}

/// The account's keys for its chain pins: its master key and key binding.
pub struct PinKeys {
    master: Zeroizing<[u8; 32]>,
    generation: MasterKeyGeneration,
    binding: String,
}

impl PinKeys {
    /// The keys of the account bound by `binding`, under its master key's
    /// first generation (every account's, until master-key rotation exists).
    pub fn derive(master_key: &[u8; 32], binding: &str) -> Result<Self> {
        Ok(Self {
            master: Zeroizing::new(*master_key),
            generation: MasterKeyGeneration::FIRST,
            binding: account_record::canonical_binding(binding)?,
        })
    }

    /// The device's name for the pin of chain `scope`/`id` (hex), revealing
    /// neither: the record's object, [`account_record::hashed_object`] of the
    /// two, length-prefixed.
    pub fn entry_id(&self, scope: &str, id: &str) -> Result<String> {
        if scope.is_empty()
            || scope.len() > MAX_PART_LEN
            || id.is_empty()
            || id.len() > MAX_PART_LEN
        {
            return Err(CryptoError::InvalidInput(
                "chain pin: scope or id is invalid".into(),
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
            .ok_or_else(|| CryptoError::InvalidInput("chain pin: entry id is invalid".into()))
    }

    /// `pin`, sealed for entry `entry_id`.
    pub fn seal_pin(&self, entry_id: &str, pin: &ChainPin) -> Result<Vec<u8>> {
        let mut plain = Zeroizing::new([0u8; 40]);
        plain[..8].copy_from_slice(&pin.revision.to_be_bytes());
        plain[8..].copy_from_slice(&pin.digest);
        account_record::seal_object(
            plain.as_slice(),
            self.master.as_slice(),
            PURPOSE,
            self.generation,
            &self.binding,
            &Self::object(entry_id)?,
        )
    }

    /// The pin sealed for entry `entry_id`; fails ([`CryptoError::AuthFailed`])
    /// for one sealed for another entry or account, or altered, which the
    /// caller treats as unseen.
    pub fn open_pin(&self, entry_id: &str, sealed: &[u8]) -> Result<ChainPin> {
        let plain = account_record::open_object(
            sealed,
            self.master.as_slice(),
            PURPOSE,
            &self.binding,
            &Self::object(entry_id).map_err(|_| CryptoError::AuthFailed)?,
        )
        .map_err(|_| CryptoError::AuthFailed)?;
        if plain.len() != 40 {
            return Err(CryptoError::AuthFailed);
        }
        let mut revision = [0u8; 8];
        revision.copy_from_slice(&plain[..8]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&plain[8..]);
        Ok(ChainPin {
            revision: u64::from_be_bytes(revision),
            digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    #[test]
    fn pins_hide_their_chain_and_open_only_where_sealed() {
        let keys = PinKeys::derive(&[1; 32], BINDING).unwrap();
        let entry = keys.entry_id("photos-library", "incarnation-1").unwrap();
        assert_eq!(entry.len(), 64);
        assert!(!entry.contains("photos"));
        // Stable for the account; another account's, or another purpose's
        // (the revision guard's), differs.
        assert_eq!(
            entry,
            keys.entry_id("photos-library", "incarnation-1").unwrap()
        );
        let other = PinKeys::derive(&[2; 32], BINDING).unwrap();
        assert_ne!(
            entry,
            other.entry_id("photos-library", "incarnation-1").unwrap()
        );
        let guard = crate::revision_guard::GuardKeys::derive(&[1; 32], BINDING).unwrap();
        assert_ne!(
            entry,
            guard.entry_id("photos-library", "incarnation-1").unwrap()
        );

        let pin = ChainPin {
            revision: 7,
            digest: [0xab; 32],
        };
        let sealed = keys.seal_pin(&entry, &pin).unwrap();
        assert_eq!(keys.open_pin(&entry, &sealed).unwrap(), pin);
        // Moved to another entry, opened by another account (another master
        // key or key binding), or altered: refused.
        let elsewhere = keys.entry_id("photos-library", "incarnation-2").unwrap();
        assert!(keys.open_pin(&elsewhere, &sealed).is_err());
        assert!(other.open_pin(&entry, &sealed).is_err());
        let rebound = PinKeys::derive(&[1; 32], "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d").unwrap();
        assert!(rebound.open_pin(&entry, &sealed).is_err());
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(keys.open_pin(&entry, &altered).is_err());
        assert!(keys.open_pin("not hex", &sealed).is_err());
        // A revision-guard record under the same name does not open as a pin.
        let seen = guard.seal_seen(&entry, 7).unwrap();
        assert!(keys.open_pin(&entry, &seen).is_err());
        assert!(keys.entry_id("", "x").is_err());
        assert!(PinKeys::derive(&[1; 32], "aci:x@example.com").is_err());
    }
}
