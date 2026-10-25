//! Checked-in vectors for the block format (docs/plans/drive-block-format.md):
//! a Drive file (suite 2, signed), a Chat attachment (suite 2) and a Chat
//! backup media copy (suite 2), each at the size edges (empty, one full
//! block, a block and more). Blocks are sealed
//! with their synthetic nonces, the manifest with a fixed one. A 4 MiB block
//! is too big to check in, so each case keeps the derived keys, every block's
//! first bytes (its nonce first), the last block whole when it is small, the
//! sealed manifest and trailer, and the whole object's length and SHA-256.
//! The plaintext is `i * 31 % 251` for byte `i`.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_BLOCK_VECTORS=1 cargo test -p kutup-crypto --test blocks_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::blocks::{
    block_count, block_plaintext_len, BlockFamily, BlockKeys, BlockSealer, NONCE_LEN,
};
use kutup_crypto::chat_backup::ChatBackupProtectionDomainV1;
use kutup_crypto::chat_backup_media::{padded_media_plaintext_bytes, ChatBackupMediaContextV1};
use kutup_crypto::chat_media::ChatMediaObjectContextV1;
use kutup_crypto::file_metadata::ContentCommitmentV1;
use kutup_crypto::primitives::{hash, SigningKey, Suite};
use kutup_crypto::{chat_backup_media_blocks, chat_media_blocks, drive_blocks};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/blocks-v1.json");

const B: u64 = kutup_crypto::blocks::BLOCK_SIZE as u64;
const KEY: [u8; 32] = [0x42; 32];
const MANIFEST_NONCE: [u8; NONCE_LEN] = [0x5a; NONCE_LEN];
const SIGNER_SEED: [u8; 32] = [0x09; 32];
const ACCOUNT: [u8; 16] = [0x03; 16];
const FILE: &str = "11111111-1111-4111-8111-111111111111";
const REVISION: &str = "22222222-2222-4222-8222-222222222222";
const ATTACHMENT: &str = "66666666-6666-4666-8666-666666666666";
const HEAD: usize = 64;
const SMALL: usize = 1024;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    key: String,
    manifest_nonce: String,
    signer_seed: String,
    signer_public_key: String,
    account_id: String,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    /// The plaintext the blocks carry (for backup media, after padding).
    size: u64,
    header: String,
    /// The block, nonce and manifest keys.
    keys: [String; 3],
    /// Each block's first bytes: its nonce, then the ciphertext's start.
    block_heads: Vec<String>,
    /// The last block whole, when it is small.
    last_block: Option<String>,
    /// The sealed manifest and the trailer.
    tail: String,
    manifest_digest: String,
    object_len: u64,
    object_sha256: String,
}

fn pattern(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn drive_context() -> drive_blocks::DriveBlobContextV2 {
    drive_blocks::DriveBlobContextV2::new(FILE, REVISION, 4).unwrap()
}

fn chat_context() -> ChatMediaObjectContextV1 {
    ChatMediaObjectContextV1::new(ATTACHMENT).unwrap()
}

fn backup_context() -> ChatBackupMediaContextV1 {
    ChatBackupMediaContextV1 {
        account_incarnation_id: [0x01; 32],
        backup_incarnation_id: [0x02; 16],
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        media_id: [0x03; 32],
    }
}

/// Seals `plaintext` block by block: the case, the object and the sealed
/// manifest's digest (what a metadata or descriptor commits to).
fn seal(
    name: &str,
    family: &BlockFamily,
    header: &[u8],
    mut sealer: BlockSealer<'_>,
    plaintext: &[u8],
    signer: Option<(&SigningKey, [u8; 16])>,
) -> (Case, Vec<u8>, [u8; 32]) {
    let size = plaintext.len() as u64;
    let mut object = header.to_vec();
    let mut block_heads = Vec::new();
    let mut last_block = None;
    let mut at = 0usize;
    for index in 0..block_count(size).unwrap() {
        let len = block_plaintext_len(size, index).unwrap();
        let block = sealer.seal_next(&plaintext[at..at + len]).unwrap();
        at += len;
        block_heads.push(STANDARD.encode(&block[..HEAD.min(block.len())]));
        last_block = (block.len() <= SMALL).then(|| STANDARD.encode(&block));
        object.extend_from_slice(&block);
    }
    let sealed_tail = sealer
        .finish_with_fixed_nonce(signer, &MANIFEST_NONCE)
        .unwrap();
    let tail = sealed_tail.bytes;
    let manifest_len = tail.len() - kutup_crypto::blocks::TRAILER_LEN;
    let manifest_digest = hash(Suite::V1, &tail[..manifest_len]).to_array::<32>();
    assert_eq!(manifest_digest, sealed_tail.manifest_sha256);
    object.extend_from_slice(&tail);
    let case = Case {
        name: name.into(),
        size,
        header: STANDARD.encode(header),
        keys: BlockKeys::derived_bytes(family, &KEY, header)
            .unwrap()
            .map(|key| STANDARD.encode(key.as_slice())),
        block_heads,
        last_block,
        tail: STANDARD.encode(&tail),
        manifest_digest: STANDARD.encode(manifest_digest),
        object_len: object.len() as u64,
        object_sha256: STANDARD.encode(hash(Suite::V1, &object).to_array::<32>()),
    };
    (case, object, manifest_digest)
}

/// Every case and its object, each checked to open with the public readers.
fn computed() -> Vectors {
    let signer = SigningKey::from_seed(Suite::V1, &SIGNER_SEED);
    let mut cases = Vec::new();
    for (name, size) in [
        ("drive-empty", 0),
        ("drive-one-block", B),
        ("drive-two-full-and-17", 2 * B + 17),
    ] {
        let plaintext = pattern(size);
        let (case, object, digest) = seal(
            name,
            &drive_blocks::DRIVE_BLOCKS,
            &drive_blocks::header(drive_context()),
            drive_blocks::sealer(&KEY, drive_context(), size).unwrap(),
            &plaintext,
            Some((&signer, ACCOUNT)),
        );
        let content = ContentCommitmentV1::new(drive_context().revision_id, digest);
        let (opened, manifest) =
            drive_blocks::open_file(&object, &KEY, drive_context(), &content, size).unwrap();
        assert_eq!(*opened, plaintext, "{name}");
        manifest.verify_signer(&signer.verifying_key()).unwrap();
        assert_eq!(object.len() as u64, drive_blocks::blob_len(size).unwrap());
        cases.push(case);
    }
    for (name, size) in [
        ("chat-media-empty", 0),
        ("chat-media-small", 100),
        ("chat-media-one-block", B),
        ("chat-media-block-and-one", B + 1),
    ] {
        let plaintext = pattern(size);
        let (case, object, digest) = seal(
            name,
            &chat_media_blocks::CHAT_MEDIA_BLOCKS,
            &chat_media_blocks::header(chat_context()),
            chat_media_blocks::sealer(&KEY, chat_context(), size).unwrap(),
            &plaintext,
            None,
        );
        let (opened, _) =
            chat_media_blocks::open_attachment(&object, &KEY, chat_context(), &digest).unwrap();
        assert_eq!(*opened, plaintext, "{name}");
        cases.push(case);
    }
    for (name, source_bytes) in [
        ("chat-backup-media-1000", 1_000),
        ("chat-backup-media-block-and-1000", B + 1_000),
    ] {
        let source = pattern(source_bytes);
        let mut padded = source.clone();
        padded.resize(
            padded_media_plaintext_bytes(source_bytes).unwrap() as usize,
            0,
        );
        let (case, object, digest) = seal(
            name,
            &chat_backup_media_blocks::CHAT_BACKUP_MEDIA_BLOCKS,
            &chat_backup_media_blocks::header(backup_context(), source_bytes).unwrap(),
            chat_backup_media_blocks::sealer(&KEY, backup_context(), source_bytes).unwrap(),
            &padded,
            None,
        );
        let (opened, _) =
            chat_backup_media_blocks::open_media(&object, &KEY, backup_context(), &digest).unwrap();
        assert_eq!(*opened, source, "{name}");
        cases.push(case);
    }
    Vectors {
        key: STANDARD.encode(KEY),
        manifest_nonce: STANDARD.encode(MANIFEST_NONCE),
        signer_seed: STANDARD.encode(SIGNER_SEED),
        signer_public_key: STANDARD.encode(signer.verifying_key().to_bytes()),
        account_id: STANDARD.encode(ACCOUNT),
        cases,
    }
}

#[test]
fn block_objects_match_their_vectors() {
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(computed(), stored);
}

#[test]
#[ignore = "writes the vector file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_BLOCK_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&computed()).unwrap() + "\n",
        )
        .unwrap();
    }
}
