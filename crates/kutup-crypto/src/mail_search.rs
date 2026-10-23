//! The browser's Mail search index at rest (docs/plans/mail-body-search.md,
//! docs/research/16-browser-storage-architecture.md §Design 1).
//!
//! The index holds words and list rows of opened messages, so nothing of it
//! may be readable from the browser's storage. As the chat store, it has its
//! own random **store key**, kept in the database wrapped under a key derived
//! from the account's master key (`kutup/mail-search/wrap/v1`): deleting the
//! database destroys the store key, so copies left behind (disk remnants, a
//! profile backup) stay unreadable even to someone who later has the master
//! key. From the store key come a name key (each record is stored under an
//! HMAC of its name: no word start, period or id shows) and a record key
//! (XChaCha20-Poly1305, bound to the purpose and that hashed name, so a record
//! moved to another name does not open). As Proton's keys, nothing is bound to
//! a name: the database's own name is an HMAC under a second master-derived
//! key, found before the wrapped store key is read.

use crate::primitives::{Aead, Suite};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const ACCOUNT_SALT: &[u8] = b"kutup/mail-search/wrap/v1\0";
const WRAP_KEY_INFO: &[u8] = b"kutup/mail-search/wrap-key/v1\0";
const LOCATOR_KEY_INFO: &[u8] = b"kutup/mail-search/locator-key/v1\0";
const STORE_SALT: &[u8] = b"kutup/mail-search/v1\0";
const RECORD_KEY_INFO: &[u8] = b"kutup/mail-search/record-key/v1\0";
const NAME_KEY_INFO: &[u8] = b"kutup/mail-search/name-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTMS1\0\0";
const WRAP_MAGIC: &[u8; 8] = b"KUTMSW1\0";
const AAD_DOMAIN: &[u8] = b"kutup/mail-search-record/v1\0";
const WRAP_AAD_DOMAIN: &[u8] = b"kutup/mail-search-store-key/v1\0";
const SUITE_V1: u16 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 2 + NONCE_LEN;
/// A wrapped store key: header, 32 bytes, tag.
pub const WRAPPED_STORE_KEY_LEN: usize = HEADER_LEN + 32 + TAG_LEN;
/// The largest record (a period's shard of one word start, or its documents).
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("mail search: {message}"))
}

fn expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut_slice())
        .map_err(|_| CryptoError::Backend("mail search key HKDF expand".into()))?;
    Ok(out)
}

fn header(magic: &[u8; 8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(magic);
    out.extend_from_slice(&SUITE_V1.to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

fn check_header(magic: &[u8; 8], sealed: &[u8]) -> Result<()> {
    if sealed.len() < HEADER_LEN + TAG_LEN
        || &sealed[..magic.len()] != magic
        || sealed[8..10] != SUITE_V1.to_be_bytes()
    {
        return Err(invalid("not a sealed mail search value"));
    }
    Ok(())
}

/// The browser database's name for an account: an HMAC under a
/// master-derived key, so it names no one and is found before anything is read.
pub fn store_name(master_key: &[u8; 32]) -> Result<String> {
    let locator = expand(ACCOUNT_SALT, master_key, LOCATOR_KEY_INFO)?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(locator.as_slice()).expect("any key length");
    mac.update(b"database\0");
    Ok(hex::encode(&mac.finalize().into_bytes()[..16]))
}

/// An account's keys for its search index, from its store key.
pub struct MailSearchKeys {
    record: Zeroizing<[u8; 32]>,
    name: Zeroizing<[u8; 32]>,
}

impl MailSearchKeys {
    /// A new store key, and its wrapped form to keep in the database.
    pub fn create(master_key: &[u8; 32]) -> Result<(Self, Vec<u8>)> {
        let mut store_key = Zeroizing::new([0u8; 32]);
        crate::primitives::random(store_key.as_mut_slice());
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
        let wrapped = Self::wrap_with_nonce(master_key, &store_key, &nonce)?;
        Ok((Self::from_store_key(&store_key)?, wrapped))
    }

    /// [`MailSearchKeys::create`]'s wrapping with a fixed store key and nonce,
    /// for checked-in vectors only.
    pub fn wrap_with_nonce(
        master_key: &[u8; 32],
        store_key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let wrap = expand(ACCOUNT_SALT, master_key, WRAP_KEY_INFO)?;
        let mut out = header(WRAP_MAGIC, nonce);
        let aad = [out.as_slice(), WRAP_AAD_DOMAIN].concat();
        let ciphertext = Aead::new(Suite::V1, wrap.as_ref())?
            .seal_with_nonce(nonce, &aad, store_key)
            .map_err(|_| CryptoError::Backend("mail search store key wrap".into()))?;
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// The keys of an index whose wrapped store key is `wrapped`.
    pub fn open(master_key: &[u8; 32], wrapped: &[u8]) -> Result<Self> {
        if wrapped.len() != WRAPPED_STORE_KEY_LEN {
            return Err(invalid("wrapped store key size is invalid"));
        }
        check_header(WRAP_MAGIC, wrapped)?;
        let wrap = expand(ACCOUNT_SALT, master_key, WRAP_KEY_INFO)?;
        let aad = [&wrapped[..HEADER_LEN], WRAP_AAD_DOMAIN].concat();
        let store_key = Zeroizing::new(
            Aead::new(Suite::V1, wrap.as_ref())?
                .open_with_nonce(&wrapped[10..HEADER_LEN], &aad, &wrapped[HEADER_LEN..])
                .map_err(|_| CryptoError::AuthFailed)
                .map(crate::primitives::into_vec)?,
        );
        let store_key: &[u8; 32] = store_key
            .as_slice()
            .try_into()
            .map_err(|_| invalid("store key size is invalid"))?;
        Self::from_store_key(store_key)
    }

    fn from_store_key(store_key: &[u8; 32]) -> Result<Self> {
        Ok(MailSearchKeys {
            record: expand(STORE_SALT, store_key, RECORD_KEY_INFO)?,
            name: expand(STORE_SALT, store_key, NAME_KEY_INFO)?,
        })
    }

    /// The name a record is stored under: HMAC-SHA256 of its name, as
    /// lowercase hex.
    pub fn record_id(&self, name: &str) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.name.as_slice()).expect("any key length");
        mac.update(b"record\0");
        mac.update(name.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn aad(&self, record_id: &str) -> Vec<u8> {
        [
            MAGIC.as_slice(),
            &SUITE_V1.to_be_bytes(),
            AAD_DOMAIN,
            record_id.as_bytes(),
        ]
        .concat()
    }

    /// Seals a record's value: `magic ‖ suite ‖ nonce ‖ ciphertext`, bound to
    /// its purpose and the record's hashed name.
    pub fn seal(&self, name: &str, value: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
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
        let ciphertext = Aead::new(Suite::V1, self.record.as_ref())?
            .seal_with_nonce(nonce, &aad, value)
            .map_err(|_| CryptoError::Backend("mail search seal".into()))?;
        let mut out = header(MAGIC, nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a record sealed under `name`.
    pub fn open_record(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() > HEADER_LEN + MAX_RECORD_BYTES + TAG_LEN {
            return Err(invalid("sealed record size is invalid"));
        }
        check_header(MAGIC, sealed)?;
        let aad = self.aad(&self.record_id(name));
        Aead::new(Suite::V1, self.record.as_ref())?
            .open_with_nonce(&sealed[10..HEADER_LEN], &aad, &sealed[HEADER_LEN..])
            .map_err(|_| CryptoError::AuthFailed)
            .map(crate::primitives::into_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_opens_only_under_its_name_and_store() {
        let (keys, wrapped) = MailSearchKeys::create(&[0x5a; 32]).unwrap();
        let sealed = keys.seal("shard/680/fat", b"words").unwrap();
        assert_eq!(
            keys.open_record("shard/680/fat", &sealed).unwrap(),
            b"words"
        );
        assert!(keys.open_record("shard/680/ekt", &sealed).is_err());
        assert!(keys.open_record("shard/680/fat", &sealed[..20]).is_err());
        // The wrapped store key gives the same keys back.
        let again = MailSearchKeys::open(&[0x5a; 32], &wrapped).unwrap();
        assert_eq!(
            again.open_record("shard/680/fat", &sealed).unwrap(),
            b"words"
        );
        // Another store (a new index after Delete) opens nothing of the old one.
        let (other, _) = MailSearchKeys::create(&[0x5a; 32]).unwrap();
        assert!(other.open_record("shard/680/fat", &sealed).is_err());
        // Another master key cannot unwrap it.
        assert!(MailSearchKeys::open(&[0x5b; 32], &wrapped).is_err());
    }

    #[test]
    fn names_hide_what_they_name() {
        let (keys, _) = MailSearchKeys::create(&[0x5a; 32]).unwrap();
        let id = keys.record_id("shard/680/fat");
        assert_eq!(id.len(), 64);
        assert!(!id.contains("fat"));
        assert_eq!(id, keys.record_id("shard/680/fat"));
        assert_ne!(id, keys.record_id("shard/680/fau"));
        let name = store_name(&[0x5a; 32]).unwrap();
        assert_eq!(name.len(), 32);
        assert_eq!(name, store_name(&[0x5a; 32]).unwrap());
        assert_ne!(name, store_name(&[0x5b; 32]).unwrap());
    }
}
