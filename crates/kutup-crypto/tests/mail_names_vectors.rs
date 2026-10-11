//! Checked-in vectors for sealed mail names (docs/plans/mail-filters.md).
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_MAIL_NAME_VECTORS=1 cargo test -p kutup-crypto --test mail_names_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::mail_names::{derive_names_key, open_name, seal_name_with_nonce, MailNameKind};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-names-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    account: String,
    names_key: String,
    kind: String,
    id: String,
    name: String,
    nonce: String,
    sealed: String,
}

const ID: &str = "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70";

fn id_bytes() -> [u8; 16] {
    let hex: String = ID.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_NAME_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x5au8; 32];
    let key = derive_names_key(&master).unwrap();
    let nonce = [0x44u8; 24];
    let name = "İş başvuruları";
    let sealed = seal_name_with_nonce(
        &key,
        "alice@kutup.dev",
        MailNameKind::Folder,
        &id_bytes(),
        name,
        &nonce,
    )
    .unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        account: "alice@kutup.dev".into(),
        names_key: STANDARD.encode(*key),
        kind: "folder".into(),
        id: ID.into(),
        name: name.into(),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(sealed),
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
    let key = derive_names_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), vectors.names_key);
    let nonce: [u8; 24] = STANDARD.decode(&vectors.nonce).unwrap().try_into().unwrap();
    let kind = MailNameKind::parse(&vectors.kind).unwrap();
    let sealed = seal_name_with_nonce(
        &key,
        &vectors.account,
        kind,
        &id_bytes(),
        &vectors.name,
        &nonce,
    )
    .unwrap();
    assert_eq!(STANDARD.encode(&sealed), vectors.sealed);
    assert_eq!(
        open_name(&key, &vectors.account, kind, &id_bytes(), &sealed).unwrap(),
        vectors.name
    );
}
