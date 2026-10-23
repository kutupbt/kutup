//! What a client keeps of the revisions it has seen (docs/plans/sealed-revisions.md):
//! for each value the account replaces over time (a contact card, a mail
//! name, the identity pin list), the highest revision seen, so an older copy
//! from the server is refused.
//!
//! The browser keeps these in IndexedDB, which anyone with the disk can read
//! and write. So the entry's name is an HMAC of what it is about (a contact's
//! UID can be an email address; folder ids and edit times say what the
//! account does), and the revision is sealed with XChaCha20-Poly1305 bound to
//! that name, both under keys derived from the master key. A disk attacker
//! can still delete entries, which only makes the device a fresh one again
//! (the first revision read is trusted), or put back an older copy of one; it
//! can no longer read them or set one to a revision it chooses.

use crate::primitives::{Aead, Kdf, Suite};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const SALT: &[u8] = b"kutup/revision-guard/v1\0";
const ENTRY_KEY_INFO: &[u8] = b"kutup/revision-guard/entry-key/v1\0";
const SEAL_KEY_INFO: &[u8] = b"kutup/revision-guard/seal-key/v1\0";
const ENTRY_DOMAIN: &[u8] = b"kutup/revision-guard/entry/v1\0";
const SEAL_DOMAIN: &[u8] = b"kutup/revision-guard/seen/v1\0";
const NONCE_LEN: usize = 24;
const SEALED_LEN: usize = NONCE_LEN + 8 + 16;
const MAX_PART_LEN: usize = 1024;

/// The account's keys for its revision store, derived from the master key.
pub struct GuardKeys {
    entry: Zeroizing<[u8; 32]>,
    seal: Zeroizing<[u8; 32]>,
}

impl GuardKeys {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let hkdf = Kdf::new(Suite::V1, SALT, master_key);
        let mut entry = Zeroizing::new([0u8; 32]);
        let mut seal = Zeroizing::new([0u8; 32]);
        hkdf.expand(ENTRY_KEY_INFO, entry.as_mut_slice())
            .and_then(|_| hkdf.expand(SEAL_KEY_INFO, seal.as_mut_slice()))
            .map_err(|_| CryptoError::Backend("revision guard key".into()))?;
        Ok(Self { entry, seal })
    }

    /// The store's name for `scope`/`id` (hex), revealing neither.
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
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.entry.as_slice())
            .expect("HMAC takes any key length");
        mac.update(ENTRY_DOMAIN);
        mac.update(&(scope.len() as u16).to_be_bytes());
        mac.update(scope.as_bytes());
        mac.update(&(id.len() as u16).to_be_bytes());
        mac.update(id.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn aad(entry_id: &str) -> Vec<u8> {
        [SEAL_DOMAIN, entry_id.as_bytes()].concat()
    }

    /// `revision`, sealed for entry `entry_id`: `nonce ‖ ciphertext`.
    pub fn seal_seen(&self, entry_id: &str, revision: u64) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
        let ciphertext = Aead::new(Suite::V1, self.seal.as_ref())?
            .seal_with_nonce(&nonce, &Self::aad(entry_id), &revision.to_be_bytes())
            .map_err(|_| CryptoError::Backend("revision guard seal".into()))?;
        Ok([nonce.as_slice(), &ciphertext].concat())
    }

    /// The revision sealed for entry `entry_id`; fails for one sealed for
    /// another entry or account, or altered.
    pub fn open_seen(&self, entry_id: &str, sealed: &[u8]) -> Result<u64> {
        if sealed.len() != SEALED_LEN {
            return Err(CryptoError::AuthFailed);
        }
        let plain = Aead::new(Suite::V1, self.seal.as_ref())?
            .open_with_nonce(
                &sealed[..NONCE_LEN],
                &Self::aad(entry_id),
                &sealed[NONCE_LEN..],
            )
            .map_err(|_| CryptoError::AuthFailed)
            .map(crate::primitives::into_vec)?;
        Ok(u64::from_be_bytes(
            plain.try_into().map_err(|_| CryptoError::AuthFailed)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_hide_what_they_are_about_and_open_only_where_sealed() {
        let keys = GuardKeys::derive(&[1; 32]).unwrap();
        let entry = keys.entry_id("contact", "ayse@example.com").unwrap();
        assert_eq!(entry.len(), 64);
        assert!(!entry.contains("ayse"));
        // Stable for the account; another account's differs.
        assert_eq!(entry, keys.entry_id("contact", "ayse@example.com").unwrap());
        let other = GuardKeys::derive(&[2; 32]).unwrap();
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
        // Moved to another entry, opened by another account, or altered: refused.
        let elsewhere = keys.entry_id("contact", "bob@example.com").unwrap();
        assert!(keys.open_seen(&elsewhere, &sealed).is_err());
        assert!(other.open_seen(&entry, &sealed).is_err());
        let mut altered = sealed.clone();
        altered[NONCE_LEN] ^= 1;
        assert!(keys.open_seen(&entry, &altered).is_err());
        assert!(keys.entry_id("", "x").is_err());
    }
}
