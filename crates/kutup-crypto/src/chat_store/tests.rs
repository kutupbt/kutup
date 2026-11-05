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
    let binding = v["binding"].as_str().unwrap();
    let mut rng = CountingRng(0);
    let (store, wrapped) = StoreCipher::create(&master, binding, &mut rng).unwrap();
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
    let reopened = StoreCipher::unwrap(&master, binding, &wrapped).unwrap();
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
    let mut rng = CountingRng(9);
    let (store, wrapped) = StoreCipher::create(&master, "chat:a", &mut rng).unwrap();
    // Another account's key, or another store's binding: refused.
    assert!(StoreCipher::unwrap(&[8; 32], "chat:a", &wrapped).is_err());
    assert!(StoreCipher::unwrap(&master, "chat:b", &wrapped).is_err());
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
