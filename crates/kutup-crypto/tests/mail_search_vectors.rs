//! Checked-in vectors for the browser's Mail search index at rest
//! (docs/plans/mail-body-search.md), with the refusals any port must keep.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_MAIL_SEARCH_VECTORS=1 cargo test -p kutup-crypto --test mail_search_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::mail_search::{store_name, MailSearchKeys};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-search-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    store_name: String,
    store_key: String,
    wrap_nonce: String,
    wrapped_store_key: String,
    name: String,
    record_id: String,
    value: String,
    nonce: String,
    sealed: String,
    /// Each must be refused.
    refusals: Vec<Refusal>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refusal {
    why: String,
    /// `record` (opened under `name`) or `storeKey` (unwrapped with `masterKey`).
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    master_key: Option<String>,
    bytes: String,
}

fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_SEARCH_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x5au8; 32];
    let store_key = [0x33u8; 32];
    let wrap_nonce = [0x22u8; 24];
    let wrapped = MailSearchKeys::wrap_with_nonce(&master, &store_key, &wrap_nonce).unwrap();
    let keys = MailSearchKeys::open(&master, &wrapped).unwrap();
    let name = "shard/680/fat";
    let value = "fatura → İş".as_bytes();
    let nonce = [0x44u8; 24];
    let sealed = keys.seal_with_nonce(name, value, &nonce).unwrap();
    let record = |why: &str, name: &str, bytes: Vec<u8>| Refusal {
        why: why.into(),
        kind: "record".into(),
        name: Some(name.into()),
        master_key: None,
        bytes: STANDARD.encode(bytes),
    };
    let store = |why: &str, master: &[u8], bytes: Vec<u8>| Refusal {
        why: why.into(),
        kind: "storeKey".into(),
        name: None,
        master_key: Some(STANDARD.encode(master)),
        bytes: STANDARD.encode(bytes),
    };
    let tag_at = sealed.len() - 1;
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        store_name: store_name(&master).unwrap(),
        store_key: STANDARD.encode(store_key),
        wrap_nonce: STANDARD.encode(wrap_nonce),
        wrapped_store_key: STANDARD.encode(&wrapped),
        name: name.into(),
        record_id: keys.record_id(name),
        value: STANDARD.encode(value),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(&sealed),
        refusals: vec![
            record("another record name", "shard/680/fau", sealed.clone()),
            record("a flipped magic byte", name, flipped(&sealed, 0)),
            record("a flipped suite byte", name, flipped(&sealed, 9)),
            record("a flipped nonce byte", name, flipped(&sealed, 12)),
            record("a flipped tag byte", name, flipped(&sealed, tag_at)),
            record("cut short", name, sealed[..20].to_vec()),
            store("another master key", &[0x5bu8; 32], wrapped.clone()),
            store(
                "a flipped wrapped byte",
                &master,
                flipped(&wrapped, wrapped.len() - 1),
            ),
            store("a flipped suite byte", &master, flipped(&wrapped, 9)),
        ],
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn vectors_hold() {
    let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let key32 = |b64: &str| -> [u8; 32] { STANDARD.decode(b64).unwrap().try_into().unwrap() };
    let master = key32(&vectors.master_key);
    assert_eq!(store_name(&master).unwrap(), vectors.store_name);
    let wrap_nonce: [u8; 24] = STANDARD
        .decode(&vectors.wrap_nonce)
        .unwrap()
        .try_into()
        .unwrap();
    let wrapped =
        MailSearchKeys::wrap_with_nonce(&master, &key32(&vectors.store_key), &wrap_nonce).unwrap();
    assert_eq!(STANDARD.encode(&wrapped), vectors.wrapped_store_key);
    let keys = MailSearchKeys::open(&master, &wrapped).unwrap();
    assert_eq!(keys.record_id(&vectors.name), vectors.record_id);
    let nonce: [u8; 24] = STANDARD.decode(&vectors.nonce).unwrap().try_into().unwrap();
    let value = STANDARD.decode(&vectors.value).unwrap();
    let sealed = keys.seal_with_nonce(&vectors.name, &value, &nonce).unwrap();
    assert_eq!(STANDARD.encode(&sealed), vectors.sealed);
    assert_eq!(keys.open_record(&vectors.name, &sealed).unwrap(), value);
    for refusal in &vectors.refusals {
        let bytes = STANDARD.decode(&refusal.bytes).unwrap();
        let refused = match refusal.kind.as_str() {
            "record" => keys
                .open_record(refusal.name.as_deref().unwrap(), &bytes)
                .is_err(),
            "storeKey" => {
                MailSearchKeys::open(&key32(refusal.master_key.as_deref().unwrap()), &bytes)
                    .is_err()
            }
            other => panic!("unknown refusal kind {other}"),
        };
        assert!(refused, "must be refused: {}", refusal.why);
    }
}
