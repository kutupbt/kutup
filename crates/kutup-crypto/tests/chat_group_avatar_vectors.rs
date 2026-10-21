//! Checked-in vector for a group's avatar blob (docs/plans/pairwise-groups.md
//! §11): the image padded to its bucket (a 0x80 marker, then zeros), sealed
//! with XChaCha20-Poly1305 under its own key with
//! `kutup/chat-group/avatar/v1\0` as associated data, as `version ‖ nonce ‖
//! ciphertext ‖ tag`. The blob itself is 8 KiB, so the vector keeps its
//! length and SHA-256 (the hash the avatar attribute names).
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_AVATAR_VECTORS=1 cargo test -p kutup-crypto --test chat_group_avatar_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::chat_group::{
    avatar_blob_hash, open_group_avatar, seal_group_avatar_with_fixed_key,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-group-avatar-v1.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    key: String,
    nonce: String,
    image: String,
    blob_len: usize,
    blob_sha256: String,
    /// The blob's first 64 bytes: its version, nonce and the start of the
    /// ciphertext.
    blob_head: String,
}

const KEY: [u8; 32] = [0x44; 32];
const NONCE: [u8; 24] = [0x55; 24];
const IMAGE: &[u8] = b"\x89PNG\r\n\x1a\nnot really a picture";

fn computed() -> Vectors {
    let blob = seal_group_avatar_with_fixed_key(IMAGE, &KEY, &NONCE).unwrap();
    Vectors {
        key: STANDARD.encode(KEY),
        nonce: STANDARD.encode(NONCE),
        image: STANDARD.encode(IMAGE),
        blob_len: blob.len(),
        blob_sha256: STANDARD.encode(avatar_blob_hash(&blob)),
        blob_head: STANDARD.encode(&blob[..64]),
    }
}

#[test]
fn the_avatar_blob_matches_its_vector() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
    let blob = seal_group_avatar_with_fixed_key(IMAGE, &KEY, &NONCE).unwrap();
    assert_eq!(&open_group_avatar(&blob, &KEY).unwrap()[..], IMAGE);
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_AVATAR_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&computed()).unwrap() + "\n",
        )
        .unwrap();
    }
}
