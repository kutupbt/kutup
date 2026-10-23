//! Checked-in vector for an account's group delivery padding
//! (docs/plans/pairwise-groups.md, "Slice 2"): every device of an account
//! must derive the same dummy capability hashes from the account master key
//! and the slot, or two devices would publish different sets and undo each
//! other's.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_DELIVERY_PADDING_VECTORS=1 cargo test -p kutup-crypto --test chat_group_delivery_padding_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::chat_group::DeliveryPaddingKey;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-group-delivery-padding-v1.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Case {
    slot: u32,
    dummy: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    account_master_key: String,
    cases: Vec<Case>,
}

fn computed() -> Vectors {
    let master = [0x11u8; 32];
    let key = DeliveryPaddingKey::derive(&master);
    let cases = [0u32, 1, 7, 0x0102_0304]
        .into_iter()
        .map(|slot| Case {
            slot,
            dummy: STANDARD.encode(key.dummy(slot)),
        })
    .collect();
    Vectors {
        account_master_key: STANDARD.encode(master),
        cases,
    }
}

#[test]
fn checked_in_vectors_match() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(stored, computed());
}

#[test]
#[ignore = "writes the checked-in vectors"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_DELIVERY_PADDING_VECTORS").is_err() {
        return;
    }
    std::fs::write(
        PATH,
        serde_json::to_string_pretty(&computed()).unwrap() + "\n",
    )
    .unwrap();
}
