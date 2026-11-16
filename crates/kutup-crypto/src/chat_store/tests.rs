use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use super::*;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-store-v1.json"
);

/// Hands out 0, 1, 2, ..., as the rng the vectors were made with.
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

const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
const OTHER_BINDING: &str = "1c7c6f1d-5d2f-4c9f-8d3e-7b2f4e6d8c0a";

fn b64(value: &serde_json::Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

/// The vectors chat-core's code made before the move
/// (docs/plans/chat-crypto-move.md): with the same rng, this code makes the
/// same wrapped key, hashed key and sealed values, byte for byte.
#[test]
fn the_moved_code_reproduces_the_vectors() {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
    let master: [u8; 32] = b64(&v["masterKey"]).try_into().unwrap();
    let keys = MasterKeys::first(&master);
    let binding = v["binding"].as_str().unwrap();
    let store_name = v["storeName"].as_str().unwrap();
    let mut rng = CountingRng(0);
    let (store, wrapped) = StoreCipher::create(&keys, binding, store_name, &mut rng).unwrap();
    assert_eq!(STANDARD.encode(&wrapped), v["wrappedStoreKey"]);

    let record = &v["record"];
    let name = record["store"].as_str().unwrap();
    let key = b64(&record["key"]);
    let hashed = store.hashed_key(name, &key);
    assert_eq!(hashed, record["hashedKey"]);
    let sealed = store
        .seal(name, &hashed, &key, &b64(&record["value"]), &mut rng)
        .unwrap();
    assert_eq!(STANDARD.encode(&sealed), record["sealed"]);

    let local = &v["local"];
    let cipher = LocalCipher::new(&master, local["scope"].as_str().unwrap()).unwrap();
    let purpose = local["purpose"].as_str().unwrap();
    let sealed_local = cipher
        .seal(purpose, &b64(&local["plaintext"]), &mut rng)
        .unwrap();
    assert_eq!(STANDARD.encode(&sealed_local), local["sealed"]);

    // And it opens them.
    let reopened = StoreCipher::unwrap(&keys, binding, store_name, &wrapped).unwrap();
    let (opened_key, value) = reopened.open(name, &hashed, &sealed).unwrap();
    assert_eq!((opened_key, value.to_vec()), (key, b64(&record["value"])));
    assert_eq!(
        cipher.open(purpose, &sealed_local).unwrap().to_vec(),
        b64(&local["plaintext"])
    );
}

#[test]
fn a_record_opens_only_where_it_was_sealed() {
    let master = [7u8; 32];
    let keys = MasterKeys::first(&master);
    let mut rng = CountingRng(9);
    let (store, wrapped) = StoreCipher::create(&keys, BINDING, "chat:a", &mut rng).unwrap();
    // Another account's key or binding, or another store's name: refused.
    assert!(
        StoreCipher::unwrap(&MasterKeys::first(&[8; 32]), BINDING, "chat:a", &wrapped).is_err()
    );
    assert!(StoreCipher::unwrap(&keys, OTHER_BINDING, "chat:a", &wrapped).is_err());
    assert!(StoreCipher::unwrap(&keys, BINDING, "chat:b", &wrapped).is_err());
    let hashed = store.hashed_key("contacts", b"k");
    let sealed = store
        .seal("contacts", &hashed, b"k", b"v", &mut rng)
        .unwrap();
    // Moved to another store or key: refused.
    assert!(store.open("messages", &hashed, &sealed).is_err());
    let other = store.hashed_key("contacts", b"j");
    assert!(store.open("contacts", &other, &sealed).is_err());
    assert!(store.open("contacts", &hashed, &sealed[..20]).is_err());

    let local = LocalCipher::new(&master, "account:a").unwrap();
    let draft = local.seal("draft", b"x", &mut rng).unwrap();
    assert!(local.open("read", &draft).is_err());
    assert!(LocalCipher::new(&master, "account:b")
        .unwrap()
        .open("draft", &draft)
        .is_err());
}

/// After a master-key rotation the store key still opens (under the key of
/// the generation it names) and is sealed again under the current one.
#[test]
fn the_store_key_follows_a_rotation() {
    let before = MasterKeys::first(&[7; 32]);
    let mut rng = CountingRng(3);
    let (_, wrapped) = StoreCipher::create(&before, BINDING, "chat:a", &mut rng).unwrap();
    let after = before.rotated(&[9; 32]).unwrap();
    StoreCipher::unwrap(&after, BINDING, "chat:a", &wrapped).unwrap();
    let moved = StoreCipher::rewrapped(&after, BINDING, "chat:a", &wrapped)
        .unwrap()
        .unwrap();
    assert_eq!(account_record::inspect(&moved).unwrap().generation.get(), 2);
    assert!(StoreCipher::rewrapped(&after, BINDING, "chat:a", &moved)
        .unwrap()
        .is_none());
    // The old key alone can't open the moved one: sign in again.
    assert!(StoreCipher::unwrap(&before, BINDING, "chat:a", &moved).is_err());
}
