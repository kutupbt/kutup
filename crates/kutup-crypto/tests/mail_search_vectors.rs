//! Checked-in vectors for the browser's Mail search index at rest
//! (docs/plans/mail-body-search.md). Regenerate only for a deliberate format
//! change:
//! `KUTUP_WRITE_MAIL_SEARCH_VECTORS=1 cargo test -p kutup-crypto --test mail_search_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::mail_search::MailSearchKeys;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-search-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    store_name: String,
    name: String,
    record_id: String,
    value: String,
    nonce: String,
    sealed: String,
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_SEARCH_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x5au8; 32];
    let keys = MailSearchKeys::derive(&master).unwrap();
    let name = "shard/680/fat";
    let value = "fatura → İş".as_bytes();
    let nonce = [0x44u8; 24];
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        store_name: keys.store_name(),
        name: name.into(),
        record_id: keys.record_id(name),
        value: STANDARD.encode(value),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(keys.seal_with_nonce(name, value, &nonce).unwrap()),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn vectors_hold() {
    let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master: [u8; 32] = STANDARD
        .decode(&vectors.master_key)
        .unwrap()
        .try_into()
        .unwrap();
    let keys = MailSearchKeys::derive(&master).unwrap();
    assert_eq!(keys.store_name(), vectors.store_name);
    assert_eq!(keys.record_id(&vectors.name), vectors.record_id);
    let nonce: [u8; 24] = STANDARD.decode(&vectors.nonce).unwrap().try_into().unwrap();
    let value = STANDARD.decode(&vectors.value).unwrap();
    let sealed = keys.seal_with_nonce(&vectors.name, &value, &nonce).unwrap();
    assert_eq!(STANDARD.encode(&sealed), vectors.sealed);
    assert_eq!(keys.open(&vectors.name, &sealed).unwrap(), value);
}
