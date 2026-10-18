//! Checked-in vector for an account's group list (docs/plans/pairwise-groups.md
//! §5): the entry id of a group (an HMAC under the list's id key) and an entry
//! sealed for it at a revision, bound to the account's key binding. Every
//! client must derive the same id and open the same bytes. Regenerate only for
//! a deliberate format change:
//! `KUTUP_WRITE_GROUP_LIST_VECTORS=1 cargo test -p kutup-crypto --test chat_group_list_vectors -- --ignored`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::chat_group::{GroupListKey, GroupMasterKey};

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
    sealed: String,
}

fn computed() -> Vectors {
    let master = [0x11u8; 32];
    let key = GroupListKey::derive(&master);
    let group_id = GroupMasterKey::from_bytes(&[0x22u8; 32]).unwrap().group_id();
    let entry_id = key.entry_id(&group_id);
    let binding = "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607";
    let plain = br#"{"version":1,"groupId":"example"}"#;
    let nonce = [0x33u8; 24];
    let sealed = key
        .seal_with_fixed_nonce(binding, &entry_id, 5, plain, &nonce)
        .unwrap();
    Vectors {
        account_master_key: STANDARD.encode(master),
        key_binding: binding.into(),
        group_id: URL_SAFE_NO_PAD.encode(group_id),
        entry_id: URL_SAFE_NO_PAD.encode(entry_id),
        revision: 5,
        plain: STANDARD.encode(plain),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(sealed),
    }
}

#[test]
fn the_group_list_entry_matches_its_vector() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
    // And opens, only as itself.
    let key = GroupListKey::derive(&[0x11u8; 32]);
    let entry_id: [u8; 32] = URL_SAFE_NO_PAD.decode(&stored.entry_id).unwrap().try_into().unwrap();
    let sealed = STANDARD.decode(&stored.sealed).unwrap();
    let plain = key.open(&stored.key_binding, &entry_id, stored.revision, &sealed).unwrap();
    assert_eq!(STANDARD.encode(&*plain), stored.plain);
    assert!(key.open(&stored.key_binding, &entry_id, stored.revision + 1, &sealed).is_err());
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_LIST_VECTORS").as_deref() == Ok("1") {
        std::fs::write(PATH, serde_json::to_string_pretty(&computed()).unwrap() + "\n").unwrap();
    }
}
