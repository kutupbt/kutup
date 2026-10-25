#![no_main]

use kutup_crypto::blocks::{
    self, BlockFamily, BlockReader, NONCE_LEN, TRAILER_LEN,
};
use kutup_crypto::chat_backup::ChatBackupProtectionDomainV1;
use kutup_crypto::chat_backup_media::ChatBackupMediaContextV1;
use kutup_crypto::chat_backup_media_blocks::{
    self, CHAT_BACKUP_MEDIA_BLOCKS, CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::chat_media::ChatMediaObjectContextV1;
use kutup_crypto::chat_media_blocks::{self, CHAT_MEDIA_BLOCKS, CHAT_MEDIA_BLOCKS_HEADER_BYTES};
use kutup_crypto::drive_blocks::{
    self, DriveBlobContextV2, DRIVE_BLOCKS, DRIVE_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::file_metadata::{self, ContentCommitmentV1};
use kutup_crypto::primitives::{SigningKey, Suite};
use libfuzzer_sys::fuzz_target;

// The block format's parsers (docs/plans/drive-block-format.md §9): headers,
// trailers, the structure check the server runs on upload, the manifest and
// whole-object readers of all three families, and V2 file metadata. The key
// and contexts are the vectors' (tests/vectors/blocks-v1.json), so the seeds,
// built from them, pass the AEAD and reach the parsers behind it; the input
// is also sealed as a manifest plaintext, as a key holder could write one.
fuzz_target!(|data: &[u8]| {
    let key = [0x42; 32];
    let drive = DriveBlobContextV2::new(
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        4,
    )
    .expect("fixed fuzz context is valid");
    let chat = ChatMediaObjectContextV1::new("66666666-6666-4666-8666-666666666666")
        .expect("fixed fuzz context is valid");
    let backup = ChatBackupMediaContextV1 {
        account_incarnation_id: [1; 32],
        backup_incarnation_id: [2; 16],
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        media_id: [3; 32],
    };

    let _ = drive_blocks::inspect_header(data);
    let _ = chat_media_blocks::validate_header(data, chat);
    let _ = chat_backup_media_blocks::inspect_header(data);
    if data.len() >= TRAILER_LEN {
        if let Ok(len) = DRIVE_BLOCKS.parse_trailer(&data[data.len() - TRAILER_LEN..]) {
            let _ = DRIVE_BLOCKS.check_structure(DRIVE_BLOCKS_HEADER_BYTES, data.len() as u64, len);
        }
    }

    // Whole objects, read as if their metadata or descriptor committed to
    // their own manifest.
    if let Ok(digest) =
        blocks::object_manifest_digest(data, DRIVE_BLOCKS_HEADER_BYTES, &DRIVE_BLOCKS)
    {
        let content = ContentCommitmentV1::new(drive.revision_id, digest);
        let manifest = &data[data.len() - TRAILER_LEN
            - DRIVE_BLOCKS
                .parse_trailer(&data[data.len() - TRAILER_LEN..])
                .expect("the digest came from this trailer")..data.len() - TRAILER_LEN];
        let size = BlockReader::open(
            &DRIVE_BLOCKS,
            &key,
            &drive_blocks::header(drive),
            manifest,
            &digest,
        )
        .map_or(0, |reader| reader.manifest().size);
        if let Ok(reader) = drive_blocks::reader(&key, drive, manifest, &content, size) {
            let _ = reader.open_block(0, data);
        }
        let _ = drive_blocks::open_file(data, &key, drive, &content, size);
    }
    if let Ok(digest) =
        blocks::object_manifest_digest(data, CHAT_MEDIA_BLOCKS_HEADER_BYTES, &CHAT_MEDIA_BLOCKS)
    {
        let _ = chat_media_blocks::open_attachment(data, &key, chat, &digest);
    }
    if let Ok(digest) = blocks::object_manifest_digest(
        data,
        CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES,
        &CHAT_BACKUP_MEDIA_BLOCKS,
    ) {
        let _ = chat_backup_media_blocks::open_media(data, &key, backup, &digest);
    }

    // The input as a manifest's plaintext, sealed under a valid header.
    let signer = SigningKey::from_seed(Suite::V1, &[0x09; 32]).verifying_key();
    let families: [(&'static BlockFamily, Vec<u8>); 2] = [
        (&DRIVE_BLOCKS, drive_blocks::header(drive).to_vec()),
        (&CHAT_MEDIA_BLOCKS, chat_media_blocks::header(chat).to_vec()),
    ];
    for (family, header) in families {
        let sealed = blocks::seal_manifest_plaintext(family, &key, &header, data, &[0x5a; NONCE_LEN])
            .expect("any plaintext seals");
        if let Ok(reader) = BlockReader::open(
            family,
            &key,
            &header,
            &sealed,
            &blocks::manifest_digest(&sealed),
        ) {
            let _ = reader.manifest().verify_signer(&signer);
            let _ = reader.object_len();
            let _ = reader.open_block(reader.manifest().count - 1, data);
        }
    }

    if let Ok(metadata) = file_metadata::decode_v2(data) {
        let _ = metadata.content.check(&[0x22; 16], &[0; 32]);
    }
});
