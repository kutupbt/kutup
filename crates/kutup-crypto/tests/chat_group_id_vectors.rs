//! Checked-in vector for a group's id (docs/plans/pairwise-groups.md §3):
//! HKDF over the master key, bound to the group's home (its server and the
//! federation identity it was pinned at), so the same master key at another
//! home is another group. Every client must derive the same id.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_ID_VECTORS=1 cargo test -p kutup-crypto --test chat_group_id_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::chat_group::{GroupHome, GroupMasterKey};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-group-id-v2.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Case {
    server: String,
    identity_sequence: u64,
    identity_document_hash: String,
    group_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    cases: Vec<Case>,
}

fn computed() -> Vectors {
    let master = [0x22u8; 32];
    let homes = [
        ("home.example", 1, "0f".repeat(32)),
        ("home.example", 2, "0f".repeat(32)),
        ("elsewhere.example", 1, "0f".repeat(32)),
    ];
    let cases = homes
        .into_iter()
        .map(|(server, identity_sequence, identity_document_hash)| {
            let home = GroupHome {
                server,
                identity_sequence,
                identity_document_hash: &identity_document_hash,
            };
            let id = GroupMasterKey::from_bytes(&master, home)
                .unwrap()
                .group_id();
            Case {
                server: server.to_string(),
                identity_sequence,
                identity_document_hash: identity_document_hash.clone(),
                group_id: STANDARD.encode(id),
            }
        })
        .collect();
    Vectors {
        master_key: STANDARD.encode(master),
        cases,
    }
}

#[test]
fn the_group_id_matches_its_vector() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
    // Three homes, three groups.
    let ids: std::collections::BTreeSet<_> =
        stored.cases.iter().map(|case| &case.group_id).collect();
    assert_eq!(ids.len(), 3);
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_ID_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&computed()).unwrap() + "\n",
        )
        .unwrap();
    }
}
