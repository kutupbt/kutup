//! Checked-in vector for an account's group list (docs/plans/pairwise-groups.md
//! §5): the entry id of a group and an entry sealed for it, bound to the
//! account's key binding and padded to the one entry size. Every client must
//! derive the same id and open the same bytes, and the server must read the
//! same revision. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_LIST_VECTORS=1 cargo test -p kutup-crypto --test chat_group_list_vectors -- --ignored`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use kutup_crypto::chat_group::GroupMasterKey;
use kutup_crypto::chat_group_list::{self, GroupListKey, SEALED_LEN};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-group-list-v1.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    account_master_key: String,
    key_binding: String,
    group_id: String,
    entry_id: String,
    revision: u64,
    plain: String,
    nonce: String,
    /// The derived keys and the AAD, so a second implementation can find
    /// where it parts from this one.
    id_key: String,
    seal_key: String,
    aad: String,
    /// The sealed entry (4032 bytes): its header, a digest, and in full.
    sealed_header: String,
    sealed_sha256: String,
    sealed: String,
}

fn sealed() -> Vec<u8> {
    let key = GroupListKey::derive(&[0x11u8; 32]);
    let group_id = GroupMasterKey::from_bytes(&[0x22u8; 32])
        .unwrap()
        .group_id();
    key.seal_with_fixed_nonce(
        "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607",
        &key.entry_id(&group_id),
        5,
        br#"{"version":1,"groupId":"example"}"#,
        &[0x33u8; 24],
    )
    .unwrap()
}

fn computed() -> Vectors {
    let master = [0x11u8; 32];
    let key = GroupListKey::derive(&master);
    let group_id = GroupMasterKey::from_bytes(&[0x22u8; 32])
        .unwrap()
        .group_id();
    let sealed = sealed();
    let entry_id = key.entry_id(&group_id);
    let (id_key, seal_key) = key.vector_keys();
    Vectors {
        account_master_key: STANDARD.encode(master),
        key_binding: "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607".into(),
        group_id: URL_SAFE_NO_PAD.encode(group_id),
        entry_id: chat_group_list::encode_entry_id(&entry_id),
        revision: 5,
        plain: STANDARD.encode(br#"{"version":1,"groupId":"example"}"#),
        nonce: STANDARD.encode([0x33u8; 24]),
        id_key: STANDARD.encode(id_key),
        seal_key: STANDARD.encode(seal_key),
        aad: STANDARD.encode(
            chat_group_list::vector_aad(5, "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607", &entry_id)
                .unwrap(),
        ),
        sealed_header: STANDARD.encode(&sealed[..42]),
        sealed_sha256: hex::encode(Sha256::digest(&sealed)),
        sealed: STANDARD.encode(&sealed),
    }
}

#[test]
fn the_group_list_entry_matches_its_vector() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
    let sealed = sealed();
    assert_eq!(sealed.len(), SEALED_LEN);
    assert_eq!(chat_group_list::inspect(&sealed).unwrap(), stored.revision);
    // It opens, only as itself.
    let key = GroupListKey::derive(&[0x11u8; 32]);
    let entry_id = chat_group_list::decode_entry_id(&stored.entry_id).unwrap();
    let opened = key.open(&stored.key_binding, &entry_id, &sealed).unwrap();
    assert_eq!(opened.revision, stored.revision);
    assert_eq!(STANDARD.encode(&*opened.plain), stored.plain);
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_LIST_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&computed()).unwrap() + "\n",
        )
        .unwrap();
    }
}
