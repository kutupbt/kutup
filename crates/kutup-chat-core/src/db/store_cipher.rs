//! Encryption at rest for the browser chat store
//! (`docs/research/16-browser-storage-architecture.md`).
//!
//! The formats are kutup-crypto's (`kutup_crypto::chat_store`,
//! docs/plans/chat-crypto-move.md): a random store key wrapped under the
//! account master key and bound to the store's name, record keys hashed and
//! values sealed under its subkeys, and small local data sealed per scope and
//! purpose. This module keeps the store's errors and its record-key encodings.

use kutup_crypto::chat_store;
use kutup_crypto::error::CryptoError;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};

fn db(error: CryptoError) -> ChatError {
    ChatError::Db(match error {
        CryptoError::InvalidInput(message) => message,
        other => other.to_string(),
    })
}

pub(crate) struct StoreCipher(chat_store::StoreCipher);

impl StoreCipher {
    /// A new store key, and its wrapped form to keep beside the data.
    pub(crate) fn create<R: RngCore + CryptoRng>(
        master_key: &[u8; 32],
        binding: &str,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>)> {
        let (cipher, wrapped) =
            chat_store::StoreCipher::create(master_key, binding, rng).map_err(db)?;
        Ok((Self(cipher), wrapped))
    }

    /// Open a wrapped store key. Fails, and must not be taken for an empty
    /// store, when the key belongs to another account or store.
    pub(crate) fn unwrap(master_key: &[u8; 32], binding: &str, wrapped: &[u8]) -> Result<Self> {
        chat_store::StoreCipher::unwrap(master_key, binding, wrapped)
            .map(Self)
            .map_err(db)
    }

    /// The key a record is stored under: a keyed hash of its object store
    /// and original key, in hex.
    pub(crate) fn hashed_key(&self, store: &str, key: &[u8]) -> String {
        self.0.hashed_key(store, key)
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
        self.0.seal(store, hashed_key, key, value, rng).map_err(db)
    }

    /// Open a record stored under `hashed_key` in `store`: its original key
    /// and value.
    pub(crate) fn open(
        &self,
        store: &str,
        hashed_key: &str,
        sealed: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        self.0.open(store, hashed_key, sealed).map_err(db)
    }
}

/// Seals small browser-side data kept outside the store (drafts, read
/// positions, the backup mirror's records), bound to the account scope and a
/// purpose per value. Stateless towards the engine, so the page can use it
/// while the engine is busy; one instance serves a whole batch.
pub(crate) struct LocalCipher(chat_store::LocalCipher);

impl LocalCipher {
    pub(crate) fn new(master_key: &[u8; 32], scope: &str) -> Result<Self> {
        chat_store::LocalCipher::new(master_key, scope)
            .map(Self)
            .map_err(db)
    }

    pub(crate) fn seal<R: RngCore + CryptoRng>(
        &self,
        purpose: &str,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        self.0.seal(purpose, plaintext, rng).map_err(db)
    }

    pub(crate) fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.0.open(purpose, sealed).map_err(db)
    }
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

    /// Hands out 0, 1, 2, ... so a sealing is the same every run.
    struct CountingRng(u8);

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for CountingRng {}

    /// The chat store's formats' canonical vectors
    /// (`crates/kutup-crypto/tests/vectors/chat-store-v1.json`), made from
    /// this code before it moves into kutup-crypto
    /// (docs/plans/chat-crypto-move.md, slice 2): the wrapped store key, a
    /// record's hashed key and sealed value, and local data, each sealed with
    /// a counting rng. `KUTUP_WRITE_CHAT_VECTORS=1` writes the file;
    /// otherwise this code must reproduce it byte for byte.
    #[test]
    fn store_formats_match_the_canonical_vectors() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use serde_json::json;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kutup-crypto/tests/vectors/chat-store-v1.json"
        );
        let binding = "chat:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        let mut rng = CountingRng(0);
        let (store, wrapped) = StoreCipher::create(&MASTER, binding, &mut rng).unwrap();
        let record_key = keys::text("aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.test");
        let hashed = store.hashed_key("contacts", &record_key);
        let record = store
            .seal(
                "contacts",
                &hashed,
                &record_key,
                b"{\"state\":\"accepted\"}",
                &mut rng,
            )
            .unwrap();
        let local = LocalCipher::new(&MASTER, "account:example")
            .unwrap()
            .seal("draft", b"half a message", &mut rng)
            .unwrap();
        let made = json!({
            "masterKey": STANDARD.encode(MASTER),
            "binding": binding,
            "rng": "bytes 0, 1, 2, ... in order",
            "wrappedStoreKey": STANDARD.encode(&wrapped),
            "record": {
                "store": "contacts",
                "key": STANDARD.encode(&record_key),
                "hashedKey": hashed,
                "value": STANDARD.encode(b"{\"state\":\"accepted\"}"),
                "sealed": STANDARD.encode(&record),
            },
            "local": {
                "scope": "account:example",
                "purpose": "draft",
                "plaintext": STANDARD.encode(b"half a message"),
                "sealed": STANDARD.encode(&local),
            },
        });
        if std::env::var_os("KUTUP_WRITE_CHAT_VECTORS").is_some() {
            std::fs::write(path, serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(made, v);
        let reopened = StoreCipher::unwrap(&MASTER, binding, &wrapped).unwrap();
        let (key, value) = reopened.open("contacts", &hashed, &record).unwrap();
        assert_eq!(
            (key, value.to_vec()),
            (record_key, b"{\"state\":\"accepted\"}".to_vec())
        );
    }

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
    fn local_data_opens_only_for_its_account_and_purpose() {
        let local = LocalCipher::new(&MASTER, "scope-a").unwrap();
        let sealed = local
            .seal("drafts", b"half a sentence", &mut OsRng)
            .unwrap();
        assert_eq!(
            local.open("drafts", &sealed).unwrap().as_slice(),
            b"half a sentence"
        );
        assert!(local.open("read-marks", &sealed).is_err());
        let other_scope = LocalCipher::new(&MASTER, "scope-b").unwrap();
        assert!(other_scope.open("drafts", &sealed).is_err());
        let other_account = LocalCipher::new(&[8; 32], "scope-a").unwrap();
        assert!(other_account.open("drafts", &sealed).is_err());
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
