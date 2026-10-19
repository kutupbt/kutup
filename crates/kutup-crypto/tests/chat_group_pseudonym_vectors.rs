//! Checked-in vector for a member's derived group pseudonym
//! (docs/plans/pairwise-groups.md §3): every client must derive the same seed
//! and public key from the account master key, the group id and the join
//! epoch, or a new device can't find its account's place in a group again.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_PSEUDONYM_VECTORS=1 cargo test -p kutup-crypto --test chat_group_pseudonym_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::chat_group::{GroupHome, GroupMasterKey, GroupPseudonymKey};

/// The vectors' group home (the id binds it).
const HOME: GroupHome<'static> = GroupHome {
    server: "home.example",
    identity_sequence: 1,
    identity_document_hash: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-group-pseudonym-v1.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Case {
    join_epoch: u32,
    /// The HKDF info (group id, then the epoch big-endian).
    info: String,
    seed: String,
    public_key: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    account_master_key: String,
    group_id: String,
    cases: Vec<Case>,
}

fn computed() -> Vectors {
    let master = [0x11u8; 32];
    let group_id = GroupMasterKey::from_bytes(&[0x22u8; 32], HOME)
        .unwrap()
        .group_id();
    let cases = [0u32, 1, 0x0102_0304]
        .into_iter()
        .map(|join_epoch| {
            let mut info = group_id.to_vec();
            info.extend_from_slice(&join_epoch.to_be_bytes());
            let key = GroupPseudonymKey::derive(&master);
            let pair = key.pseudonym(&group_id, join_epoch);
            Case {
                join_epoch,
                info: STANDARD.encode(info),
                seed: STANDARD.encode(*key.seed(&group_id, join_epoch)),
                public_key: STANDARD.encode(pair.public_key()),
            }
        })
        .collect();
    Vectors {
        account_master_key: STANDARD.encode(master),
        group_id: STANDARD.encode(group_id),
        cases,
    }
}

#[test]
fn the_group_pseudonym_matches_its_vector() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
}

#[test]
fn pseudonyms_differ_by_account_group_and_epoch() {
    let group = GroupMasterKey::from_bytes(&[0x22u8; 32], HOME)
        .unwrap()
        .group_id();
    let other_group = GroupMasterKey::from_bytes(&[0x23u8; 32], HOME)
        .unwrap()
        .group_id();
    let key = |master: u8, group: &[u8; 32], epoch| {
        GroupPseudonymKey::derive(&[master; 32])
            .pseudonym(group, epoch)
            .public_key()
    };
    let base = key(0x11, &group, 0);
    assert_eq!(base, key(0x11, &group, 0), "deterministic");
    assert_ne!(base, key(0x12, &group, 0));
    assert_ne!(base, key(0x11, &other_group, 0));
    assert_ne!(base, key(0x11, &group, 1));
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_PSEUDONYM_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&computed()).unwrap() + "\n",
        )
        .unwrap();
    }
}
