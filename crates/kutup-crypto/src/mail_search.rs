//! The browser's Mail search index at rest (docs/plans/mail-body-search.md).
//!
//! The index holds words of opened messages, so nothing of it may be readable
//! from the browser's storage: each record's name is kept as an HMAC under a
//! key derived from the account's master key (no word start, period or id
//! shows), and its value is sealed with XChaCha20-Poly1305 under a second
//! derived key, bound to the account and that hashed name, so a record moved
//! to another name, or another account's database, does not open. The master
//! key is the same across password changes, so the index survives them, and
//! only someone who can unlock the account can open it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::named_share::canonical_account;

const KEY_SALT: &[u8] = b"kutup/mail-search/v1\0";
const RECORD_KEY_INFO: &[u8] = b"kutup/mail-search/record-key/v1\0";
const NAME_KEY_INFO: &[u8] = b"kutup/mail-search/name-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTMS1\0\0";
const AAD_DOMAIN: &[u8] = b"kutup/mail-search-record/v1\0";
const SUITE_V1: u16 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 2 + NONCE_LEN;
/// The largest record (a period's shard of one word start).
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("mail search: {message}"))
}

/// An account's keys for its search index.
pub struct MailSearchKeys {
    account: String,
    record: Zeroizing<[u8; 32]>,
    name: Zeroizing<[u8; 32]>,
}

impl MailSearchKeys {
    /// Derived from the account's master key.
    pub fn derive(master_key: &[u8; 32], account: &str) -> Result<Self> {
        let account =
            canonical_account(account).map_err(|_| invalid("account is not canonical"))?;
        let hkdf = Hkdf::<Sha256>::new(Some(KEY_SALT), master_key);
        let mut record = Zeroizing::new([0u8; 32]);
        let mut name = Zeroizing::new([0u8; 32]);
        hkdf.expand(RECORD_KEY_INFO, record.as_mut_slice())
            .map_err(|_| CryptoError::Backend("mail search key HKDF expand".into()))?;
        hkdf.expand(NAME_KEY_INFO, name.as_mut_slice())
            .map_err(|_| CryptoError::Backend("mail search key HKDF expand".into()))?;
        Ok(MailSearchKeys {
            account,
            record,
            name,
        })
    }

    /// The name a record is stored under: HMAC-SHA256 of the account and its
    /// name, as lowercase hex.
    pub fn record_id(&self, name: &str) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.name.as_slice()).expect("any key length");
        mac.update(&(self.account.len() as u16).to_be_bytes());
        mac.update(self.account.as_bytes());
        mac.update(name.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn aad(&self, record_id: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            MAGIC.len() + 2 + AAD_DOMAIN.len() + 2 + self.account.len() + record_id.len(),
        );
        aad.extend_from_slice(MAGIC);
        aad.extend_from_slice(&SUITE_V1.to_be_bytes());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(&(self.account.len() as u16).to_be_bytes());
        aad.extend_from_slice(self.account.as_bytes());
        aad.extend_from_slice(record_id.as_bytes());
        aad
    }

    /// Seals a record's value: `magic ‖ suite ‖ nonce ‖ ciphertext`, bound to
    /// the account and the record's name.
    pub fn seal(&self, name: &str, value: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        copy_randombytes(&mut nonce);
        self.seal_with_nonce(name, value, &nonce)
    }

    /// [`MailSearchKeys::seal`] with a fixed nonce, for checked-in vectors only.
    pub fn seal_with_nonce(
        &self,
        name: &str,
        value: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        if value.len() > MAX_RECORD_BYTES {
            return Err(invalid("record is too large"));
        }
        let aad = self.aad(&self.record_id(name));
        let ciphertext = XChaCha20Poly1305::new(self.record.as_slice().into())
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Backend("mail search seal".into()))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&SUITE_V1.to_be_bytes());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a record sealed under `name`.
    pub fn open(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < HEADER_LEN + TAG_LEN
            || sealed.len() > HEADER_LEN + MAX_RECORD_BYTES + TAG_LEN
        {
            return Err(invalid("sealed record size is invalid"));
        }
        if &sealed[..MAGIC.len()] != MAGIC || sealed[8..10] != SUITE_V1.to_be_bytes() {
            return Err(invalid("not a sealed mail search record"));
        }
        let aad = self.aad(&self.record_id(name));
        XChaCha20Poly1305::new(self.record.as_slice().into())
            .decrypt(
                XNonce::from_slice(&sealed[10..HEADER_LEN]),
                Payload {
                    msg: &sealed[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_opens_only_under_its_name_account_and_key() {
        let keys = MailSearchKeys::derive(&[0x5a; 32], "alice@kutup.dev").unwrap();
        let sealed = keys.seal("shard/680/fat", b"words").unwrap();
        assert_eq!(keys.open("shard/680/fat", &sealed).unwrap(), b"words");
        assert!(keys.open("shard/680/ekt", &sealed).is_err());
        let bob = MailSearchKeys::derive(&[0x5a; 32], "bob@kutup.dev").unwrap();
        assert!(bob.open("shard/680/fat", &sealed).is_err());
        let other = MailSearchKeys::derive(&[0x5b; 32], "alice@kutup.dev").unwrap();
        assert!(other.open("shard/680/fat", &sealed).is_err());
        assert!(keys.open("shard/680/fat", &sealed[..20]).is_err());
    }

    #[test]
    fn names_hide_what_they_name() {
        let keys = MailSearchKeys::derive(&[0x5a; 32], "alice@kutup.dev").unwrap();
        let id = keys.record_id("shard/680/fat");
        assert_eq!(id.len(), 64);
        assert!(!id.contains("fat"));
        assert_eq!(id, keys.record_id("shard/680/fat"));
        assert_ne!(id, keys.record_id("shard/680/fau"));
        let bob = MailSearchKeys::derive(&[0x5a; 32], "bob@kutup.dev").unwrap();
        assert_ne!(id, bob.record_id("shard/680/fat"));
    }
}
