//! Checked-in vector for a group's state key (docs/plans/pairwise-groups.md
//! §3): HKDF over the master key with `kutup/chat-group/state-key/v2\0` and
//! the group id as info, so a state key is its group's alone. The vector is
//! a field sealed under it with a fixed nonce: every client must derive the
//! same key and seal the same bytes.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_STATE_KEY_VECTORS=1 cargo test -p kutup-crypto --test chat_group_state_key_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::chat_group::{GroupHome, GroupMasterKey, SealedField};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-group-state-key-v2.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Case {
    server: String,
    group_id: String,
    /// The title "Team", sealed under the state key with `nonce`.
    sealed_title: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    identity_sequence: u64,
    identity_document_hash: String,
    nonce: String,
    plain: String,
    cases: Vec<Case>,
}

const NONCE: [u8; 24] = [0x33; 24];
const PLAIN: &[u8] = b"Team";

fn computed() -> Vectors {
    let master = [0x22u8; 32];
    let hash = "0f".repeat(32);
    let cases = ["home.example", "elsewhere.example"]
        .into_iter()
        .map(|server| {
            let key = GroupMasterKey::from_bytes(
                &master,
                GroupHome {
                    server,
                    identity_sequence: 1,
                    identity_document_hash: &hash,
                },
            )
            .unwrap();
            let sealed = key
                .state_key()
                .seal_with_fixed_nonce(SealedField::Title, b"", PLAIN, &NONCE)
                .unwrap();
            Case {
                server: server.to_string(),
                group_id: STANDARD.encode(key.group_id()),
                sealed_title: STANDARD.encode(sealed),
            }
        })
        .collect();
    Vectors {
        master_key: STANDARD.encode(master),
        identity_sequence: 1,
        identity_document_hash: hash,
        nonce: STANDARD.encode(NONCE),
        plain: String::from_utf8(PLAIN.to_vec()).unwrap(),
        cases,
    }
}

#[test]
fn the_state_key_matches_its_vector() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
    // The same master key and plaintext at two homes: two state keys.
    assert_ne!(stored.cases[0].sealed_title, stored.cases[1].sealed_title);
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_STATE_KEY_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&computed()).unwrap() + "\n",
        )
        .unwrap();
    }
}
