//! Encryption at rest for the browser chat store
//! (`docs/research/16-browser-storage-architecture.md`).
//!
//! A random 256-bit store key, wrapped under a key derived from the account
//! master key and bound to the store's name, gives two subkeys: one hashes
//! record keys (HMAC-SHA256), so no address or id is readable from the
//! database, and one seals record values (XChaCha20-Poly1305). A sealed value
//! carries its original key, for scans that need it, and is bound to its
//! object store and hashed key as associated data: a record moved to another
//! key or store does not open.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};

const WRAP_INFO: &[u8] = b"kutup/chat-store/wrap/v1";
const VALUE_INFO: &[u8] = b"kutup/chat-store/value/v1";
const INDEX_INFO: &[u8] = b"kutup/chat-store/index/v1";
const RECORD_AAD: &[u8] = b"kutup/chat-store/record/v1";
const WRAPPED_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;

pub(crate) struct StoreCipher {
    value: XChaCha20Poly1305,
    index: Zeroizing<[u8; 32]>,
}

impl StoreCipher {
    /// A new store key, and its wrapped form to keep beside the data.
    pub(crate) fn create<R: RngCore + CryptoRng>(
        master_key: &[u8; 32],
        binding: &str,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>)> {
        let mut store_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(store_key.as_mut());
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut nonce);
        let sealed = wrap_cipher(master_key)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: store_key.as_ref(),
                    aad: &wrap_aad(binding),
                },
            )
            .map_err(|_| ChatError::Db("cannot wrap the chat store key".into()))?;
        let mut wrapped = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
        wrapped.push(WRAPPED_VERSION);
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&sealed);
        Ok((Self::from_store_key(&store_key)?, wrapped))
    }

    /// Open a wrapped store key. Fails, and must not be taken for an empty
    /// store, when the key belongs to another account or store.
    pub(crate) fn unwrap(master_key: &[u8; 32], binding: &str, wrapped: &[u8]) -> Result<Self> {
        if wrapped.len() != 1 + NONCE_BYTES + 32 + 16 || wrapped[0] != WRAPPED_VERSION {
            return Err(ChatError::Db("the chat store key is malformed".into()));
        }
        let store_key = Zeroizing::new(
            wrap_cipher(master_key)?
                .decrypt(
                    XNonce::from_slice(&wrapped[1..=NONCE_BYTES]),
                    Payload {
                        msg: &wrapped[1 + NONCE_BYTES..],
                        aad: &wrap_aad(binding),
                    },
                )
                .map_err(|_| {
                    ChatError::Db("the chat store key does not open with this account's key".into())
                })?,
        );
        let store_key: &[u8; 32] = store_key
            .as_slice()
            .try_into()
            .map_err(|_| ChatError::Db("the chat store key is malformed".into()))?;
        Self::from_store_key(store_key)
    }

    fn from_store_key(store_key: &[u8; 32]) -> Result<Self> {
        let value = Zeroizing::new(expand(store_key, VALUE_INFO)?);
        let index = Zeroizing::new(expand(store_key, INDEX_INFO)?);
        Ok(Self {
            value: XChaCha20Poly1305::new(value.as_ref().into()),
            index,
        })
    }

    /// The key a record is stored under: a keyed hash of its object store
    /// and original key, in hex.
    pub(crate) fn hashed_key(&self, store: &str, key: &[u8]) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.index.as_ref()).expect("any key length");
        mac.update(store.as_bytes());
        mac.update(&[0]);
        mac.update(key);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Seal a record value together with its original key.
    pub(crate) fn seal<R: RngCore + CryptoRng>(
        &self,
        store: &str,
        hashed_key: &str,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let key_len = u32::try_from(key.len())
            .map_err(|_| ChatError::Db("chat store key too long".into()))?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + key.len() + value.len()));
        plaintext.extend_from_slice(&key_len.to_be_bytes());
        plaintext.extend_from_slice(key);
        plaintext.extend_from_slice(value);
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut nonce);
        let sealed = self
            .value
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &record_aad(store, hashed_key),
                },
            )
            .map_err(|_| ChatError::Db("cannot seal a chat store record".into()))?;
        let mut out = Vec::with_capacity(NONCE_BYTES + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open a record stored under `hashed_key` in `store`: its original key
    /// and value.
    pub(crate) fn open(
        &self,
        store: &str,
        hashed_key: &str,
        sealed: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        if sealed.len() < NONCE_BYTES + 16 {
            return Err(ChatError::Db("chat store record is malformed".into()));
        }
        let plaintext = Zeroizing::new(
            self.value
                .decrypt(
                    XNonce::from_slice(&sealed[..NONCE_BYTES]),
                    Payload {
                        msg: &sealed[NONCE_BYTES..],
                        aad: &record_aad(store, hashed_key),
                    },
                )
                .map_err(|_| {
                    ChatError::Db(format!("chat store record in {store} does not open"))
                })?,
        );
        let malformed = || ChatError::Db("chat store record is malformed".into());
        let key_len = u32::from_be_bytes(
            plaintext
                .get(..4)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?,
        ) as usize;
        let key = plaintext
            .get(4..4 + key_len)
            .ok_or_else(malformed)?
            .to_vec();
        if self.hashed_key(store, &key) != hashed_key {
            return Err(ChatError::Db(
                "chat store record is under the wrong key".into(),
            ));
        }
        let value = Zeroizing::new(plaintext[4 + key_len..].to_vec());
        Ok((key, value))
    }
}

fn wrap_cipher(master_key: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    let key = Zeroizing::new(expand(master_key, WRAP_INFO)?);
    Ok(XChaCha20Poly1305::new(key.as_ref().into()))
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

fn expand(ikm: &[u8; 32], info: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut out)
        .map_err(|_| ChatError::Db("chat store key derivation failed".into()))?;
    Ok(out)
}

/// Canonical bytes of the record keys the store uses. Each shape has its own
/// tag and length prefixes, so no two different keys encode the same.
pub(crate) mod keys {
    pub(crate) fn text(value: &str) -> Vec<u8> {
        let mut out = vec![b's'];
        out.extend_from_slice(value.as_bytes());
        out
    }

    pub(crate) fn number(value: u32) -> Vec<u8> {
        let mut out = vec![b'n'];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    pub(crate) fn pair(left: &str, right: &str) -> Vec<u8> {
        let mut out = vec![b'p'];
        prefixed(&mut out, left);
        out.extend_from_slice(right.as_bytes());
        out
    }

    pub(crate) fn text_number(left: &str, right: u32) -> Vec<u8> {
        let mut out = vec![b'q'];
        prefixed(&mut out, left);
        out.extend_from_slice(&right.to_be_bytes());
        out
    }

    pub(crate) fn triple(first: &str, second: &str, third: &str) -> Vec<u8> {
        let mut out = vec![b't'];
        prefixed(&mut out, first);
        prefixed(&mut out, second);
        out.extend_from_slice(third.as_bytes());
        out
    }

    /// The number a [`number`] key holds.
    pub(crate) fn as_number(key: &[u8]) -> Option<u32> {
        match key {
            [b'n', rest @ ..] => rest.try_into().ok().map(u32::from_be_bytes),
            _ => None,
        }
    }

    fn prefixed(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const MASTER: [u8; 32] = [7; 32];

    #[test]
    fn a_record_opens_where_it_was_sealed_and_nowhere_else() {
        let (cipher, wrapped) =
            StoreCipher::create(&MASTER, "kutup-chat-v2:abc", &mut OsRng).unwrap();
        let key = keys::text("alice@kutup.dev.1");
        let hashed = cipher.hashed_key("sessions", &key);
        assert_eq!(hashed.len(), 64);
        assert!(!hashed.contains("alice"));
        let sealed = cipher
            .seal("sessions", &hashed, &key, b"ratchet", &mut OsRng)
            .unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"alice"));

        let (opened_key, value) = cipher.open("sessions", &hashed, &sealed).unwrap();
        assert_eq!(opened_key, key);
        assert_eq!(value.as_slice(), b"ratchet");

        // Moved to another store or key, it does not open.
        assert!(cipher.open("identities", &hashed, &sealed).is_err());
        let other = cipher.hashed_key("sessions", &keys::text("bob@kutup.dev.1"));
        assert!(cipher.open("sessions", &other, &sealed).is_err());

        // The same account reopens it; another account or store name cannot.
        let reopened = StoreCipher::unwrap(&MASTER, "kutup-chat-v2:abc", &wrapped).unwrap();
        assert_eq!(
            reopened
                .open("sessions", &hashed, &sealed)
                .unwrap()
                .1
                .as_slice(),
            b"ratchet"
        );
        assert!(StoreCipher::unwrap(&[8; 32], "kutup-chat-v2:abc", &wrapped).is_err());
        assert!(StoreCipher::unwrap(&MASTER, "kutup-chat-v2:other", &wrapped).is_err());
    }

    #[test]
    fn keys_of_different_shapes_never_collide() {
        assert_ne!(keys::pair("ab", "c"), keys::pair("a", "bc"));
        assert_ne!(keys::text("1"), keys::number(1));
        assert_ne!(keys::triple("a", "b", "c"), keys::triple("a", "bc", ""));
        assert_eq!(
            keys::as_number(&keys::number(4_000_000_000)),
            Some(4_000_000_000)
        );
        assert_eq!(keys::as_number(&keys::text("7")), None);
    }
}
