//! Encryption at rest for the browser chat store
//! (`docs/research/16-browser-storage-architecture.md`).
//!
//! A random 256-bit store key, wrapped under a key derived from the account
//! master key and bound to the store's name, gives two subkeys: one hashes
//! record keys (the suite's MAC), so no address or id is readable from the
//! database, and one seals record values (the suite's AEAD). A sealed value
//! carries its original key, for scans that need it, and is bound to its
//! object store and hashed key as associated data: a record moved to another
//! key or store does not open.
//!
//! [`LocalCipher`] seals small browser-side data kept outside the store under
//! a key from the master key, bound to an account scope and a purpose.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::primitives::{mac, Aead, Kdf, Suite};

const KEY_SALT: &[u8] = crate::labels::CHAT_STORE_V1;
const WRAP_INFO: &[u8] = crate::labels::CHAT_STORE_WRAP_V1;
const VALUE_INFO: &[u8] = crate::labels::CHAT_STORE_VALUE_V1;
const INDEX_INFO: &[u8] = crate::labels::CHAT_STORE_INDEX_V1;
const RECORD_AAD: &[u8] = crate::labels::CHAT_STORE_RECORD_V1;
const LOCAL_INFO: &[u8] = crate::labels::CHAT_LOCAL_V1;
const WRAPPED_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;

fn failed(message: &str) -> CryptoError {
    CryptoError::InvalidInput(message.into())
}

/// The store's two subkeys, from its store key.
pub struct StoreCipher {
    value: Aead,
    index: Zeroizing<[u8; 32]>,
}

impl StoreCipher {
    /// A new store key, and its wrapped form to keep beside the data:
    /// `version (1) || nonce (24) || AEAD(store key)`, bound to `binding`.
    pub fn create<R: RngCore + CryptoRng>(
        master_key: &[u8; 32],
        binding: &str,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>)> {
        let mut store_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(store_key.as_mut());
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut nonce);
        let sealed = wrap_cipher(master_key)?
            .seal_with_nonce(&nonce, &wrap_aad(binding), store_key.as_ref())
            .map_err(|_| failed("cannot wrap the chat store key"))?;
        let mut wrapped = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
        wrapped.push(WRAPPED_VERSION);
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&sealed);
        Ok((Self::from_store_key(&store_key)?, wrapped))
    }

    /// Open a wrapped store key. Fails, and must not be taken for an empty
    /// store, when the key belongs to another account or store.
    pub fn unwrap(master_key: &[u8; 32], binding: &str, wrapped: &[u8]) -> Result<Self> {
        if wrapped.len() != 1 + NONCE_BYTES + 32 + TAG_BYTES || wrapped[0] != WRAPPED_VERSION {
            return Err(failed("the chat store key is malformed"));
        }
        let store_key = wrap_cipher(master_key)?
            .open_with_nonce(
                &wrapped[1..=NONCE_BYTES],
                &wrap_aad(binding),
                &wrapped[1 + NONCE_BYTES..],
            )
            .map_err(|_| failed("the chat store key does not open with this account's key"))?;
        let store_key: &[u8; 32] = store_key
            .as_slice()
            .try_into()
            .map_err(|_| failed("the chat store key is malformed"))?;
        Self::from_store_key(store_key)
    }

    fn from_store_key(store_key: &[u8; 32]) -> Result<Self> {
        let value = expand(store_key, VALUE_INFO)?;
        Ok(Self {
            value: Aead::new(Suite::V1, value.as_ref())?,
            index: expand(store_key, INDEX_INFO)?,
        })
    }

    /// The key a record is stored under: a keyed hash of its object store
    /// and original key, in hex.
    pub fn hashed_key(&self, store: &str, key: &[u8]) -> String {
        hex::encode(
            mac(
                Suite::V1,
                self.index.as_ref(),
                &[store.as_bytes(), &[0], key],
            )
            .as_bytes(),
        )
    }

    /// Seal a record value together with its original key:
    /// `nonce (24) || AEAD(key length (u32 BE) || key || value)`.
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        store: &str,
        hashed_key: &str,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let key_len = u32::try_from(key.len()).map_err(|_| failed("chat store key too long"))?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + key.len() + value.len()));
        plaintext.extend_from_slice(&key_len.to_be_bytes());
        plaintext.extend_from_slice(key);
        plaintext.extend_from_slice(value);
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut nonce);
        let sealed = self
            .value
            .seal_with_nonce(&nonce, &record_aad(store, hashed_key), &plaintext)
            .map_err(|_| failed("cannot seal a chat store record"))?;
        let mut out = Vec::with_capacity(NONCE_BYTES + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open a record stored under `hashed_key` in `store`: its original key
    /// and value.
    pub fn open(
        &self,
        store: &str,
        hashed_key: &str,
        sealed: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        if sealed.len() < NONCE_BYTES + TAG_BYTES {
            return Err(failed("chat store record is malformed"));
        }
        let plaintext = self
            .value
            .open_with_nonce(
                &sealed[..NONCE_BYTES],
                &record_aad(store, hashed_key),
                &sealed[NONCE_BYTES..],
            )
            .map_err(|_| {
                CryptoError::InvalidInput(format!("chat store record in {store} does not open"))
            })?;
        let malformed = || failed("chat store record is malformed");
        let key_len = u32::from_be_bytes(
            plaintext
                .get(..4)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?,
        ) as usize;
        let key = plaintext
            .get(4..4usize.checked_add(key_len).ok_or_else(malformed)?)
            .ok_or_else(malformed)?
            .to_vec();
        if self.hashed_key(store, &key) != hashed_key {
            return Err(failed("chat store record is under the wrong key"));
        }
        let value = Zeroizing::new(plaintext[4 + key_len..].to_vec());
        Ok((key, value))
    }
}

/// Seals small browser-side data kept outside the store (drafts, read
/// positions, the backup mirror's records) under a key derived from the
/// account master key, bound to the account scope and a purpose per value:
/// what is sealed for one purpose or account does not open as another.
/// Stateless towards the engine, so the page can use it while the engine is
/// busy; one instance serves a whole batch.
pub struct LocalCipher {
    cipher: Aead,
    scope: String,
}

impl LocalCipher {
    pub fn new(master_key: &[u8; 32], scope: &str) -> Result<Self> {
        let key = expand(master_key, LOCAL_INFO)?;
        Ok(Self {
            cipher: Aead::new(Suite::V1, key.as_ref())?,
            scope: scope.to_owned(),
        })
    }

    /// `version (1) || nonce (24) || AEAD(plaintext)`.
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        purpose: &str,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut nonce);
        let sealed = self
            .cipher
            .seal_with_nonce(&nonce, &local_aad(&self.scope, purpose), plaintext)
            .map_err(|_| failed("cannot seal local chat data"))?;
        let mut out = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
        out.push(WRAPPED_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 1 + NONCE_BYTES + TAG_BYTES || sealed[0] != WRAPPED_VERSION {
            return Err(failed("local chat data is malformed"));
        }
        self.cipher
            .open_with_nonce(
                &sealed[1..=NONCE_BYTES],
                &local_aad(&self.scope, purpose),
                &sealed[1 + NONCE_BYTES..],
            )
            .map_err(|_| failed("local chat data does not open"))
    }
}

fn local_aad(scope: &str, purpose: &str) -> Vec<u8> {
    let mut aad = LOCAL_INFO.to_vec();
    aad.push(0);
    aad.extend_from_slice(scope.as_bytes());
    aad.push(0);
    aad.extend_from_slice(purpose.as_bytes());
    aad
}

fn wrap_cipher(master_key: &[u8; 32]) -> Result<Aead> {
    let key = expand(master_key, WRAP_INFO)?;
    Aead::new(Suite::V1, key.as_ref())
}

fn wrap_aad(binding: &str) -> Vec<u8> {
    let mut aad = WRAP_INFO.to_vec();
    aad.push(0);
    aad.extend_from_slice(binding.as_bytes());
    aad
}

fn record_aad(store: &str, hashed_key: &str) -> Vec<u8> {
    let mut aad = RECORD_AAD.to_vec();
    aad.push(0);
    aad.extend_from_slice(store.as_bytes());
    aad.push(0);
    aad.extend_from_slice(hashed_key.as_bytes());
    aad
}

/// The suite's KDF with no salt (HKDF's zero key) and `info` as the label.
fn expand(ikm: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Kdf::new(Suite::V1, KEY_SALT, ikm)
        .expand(info, out.as_mut())
        .map_err(|_| failed("chat store key derivation failed"))?;
    Ok(out)
}

#[cfg(test)]
mod tests;
