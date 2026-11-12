//! Checked-in vectors for lookup hashes under an account data key
//! (docs/plans/server-personal-data.md, A2, mail metadata): the key is the
//! one `server-data-v1.json` wraps. Regenerate only for a deliberate format
//! change:
//! `KUTUP_WRITE_SERVER_DATA_VECTORS=1 cargo test -p kutup-crypto --test server_data_lookup_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::server_data::{DataKey, Lookup};

const KEY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/server-data-v1.json"
);
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/server-data-lookup-v1.json"
);

const ENTRY: [u8; 32] = [0x31; 32];
const ENTRY_ID: u16 = 2;
const ACCOUNT: [u8; 16] = [0x41; 16];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    /// `mailThread` or `mailSearchToken`.
    purpose: String,
    /// The value, as UTF-8.
    value: String,
    hash: String,
}

fn key() -> DataKey {
    let vectors: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(KEY_PATH).unwrap()).unwrap();
    let wrapped = STANDARD
        .decode(vectors["wrappedKey"].as_str().unwrap())
        .unwrap();
    DataKey::unwrap(&wrapped, &ACCOUNT, |id| (id == ENTRY_ID).then_some(&ENTRY)).unwrap()
}

fn purpose(name: &str) -> Lookup {
    match name {
        "mailThread" => Lookup::MailThread,
        "mailSearchToken" => Lookup::MailSearchToken,
        other => panic!("unknown purpose {other}"),
    }
}

const INPUTS: &[(&str, &str)] = &[
    ("mailThread", "CAF1234@mail.example.org"),
    ("mailThread", "caf1234@mail.example.org"),
    ("mailSearchToken", "s\u{0}fatura"),
    ("mailSearchToken", "f\u{0}fatura"),
    ("mailSearchToken", "f\u{0}ali.veli@ornek.com.tr"),
];

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_SERVER_DATA_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let key = key();
    let cases = INPUTS
        .iter()
        .map(|(name, value)| Case {
            purpose: (*name).into(),
            value: (*value).into(),
            hash: STANDARD.encode(key.lookup_hash(purpose(name), value.as_bytes()).unwrap()),
        })
        .collect();
    let json = serde_json::to_string_pretty(&Vectors { cases }).unwrap();
    std::fs::write(PATH, format!("{json}\n")).unwrap();
}

#[test]
fn lookup_hashes_match_the_vectors() {
    let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(vectors.cases.len(), INPUTS.len());
    let key = key();
    let mut seen = std::collections::HashSet::new();
    for case in &vectors.cases {
        let hash = key
            .lookup_hash(purpose(&case.purpose), case.value.as_bytes())
            .unwrap();
        assert_eq!(STANDARD.encode(hash), case.hash, "{}", case.value);
        // Distinct values, and one value under two purposes, never collide.
        assert!(seen.insert(hash), "{}", case.value);
    }
    let thread = key.lookup_hash(Lookup::MailThread, b"x").unwrap();
    let token = key.lookup_hash(Lookup::MailSearchToken, b"x").unwrap();
    assert_ne!(thread, token);
    // Another key: other hashes.
    let other = DataKey::generate(1).unwrap();
    assert_ne!(other.lookup_hash(Lookup::MailThread, b"x").unwrap(), thread);
}
