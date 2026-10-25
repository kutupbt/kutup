#![no_main]

use kutup_crypto::blocks::TRAILER_LEN;
use kutup_crypto::chat_backup::ChatBackupProtectionDomainV1;
use kutup_crypto::chat_backup_media::ChatBackupMediaContextV1;
use kutup_crypto::chat_media::ChatMediaObjectContextV1;
use kutup_crypto::drive_blocks::{
    self, DriveBlobContextV2, DRIVE_BLOCKS, DRIVE_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::{chat_backup_media_blocks, chat_media_blocks, file_metadata};
use libfuzzer_sys::fuzz_target;

// The block format's parsers (docs/plans/drive-block-format.md §9): headers,
// trailers, the structure check the server runs on upload, the manifest and
// whole-object readers of all three families, and V2 file metadata.
fuzz_target!(|data: &[u8]| {
    let key = [0x5a; 32];
    let drive = DriveBlobContextV2::new(
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        1,
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
        let trailer = &data[data.len() - TRAILER_LEN..];
        if let Ok(len) = DRIVE_BLOCKS.parse_trailer(trailer) {
            let _ = DRIVE_BLOCKS.check_structure(DRIVE_BLOCKS_HEADER_BYTES, data.len() as u64, len);
            if let Some(manifest) = data
                .len()
                .checked_sub(TRAILER_LEN + len)
                .map(|start| &data[start..data.len() - TRAILER_LEN])
            {
                if let Ok(reader) = drive_blocks::reader(&key, drive, manifest) {
                    let _ = reader.open_block(0, data);
                }
            }
        }
    }
    let _ = drive_blocks::open_file(data, &key, drive);
    let _ = chat_media_blocks::open_attachment(data, &key, chat);
    let _ = chat_backup_media_blocks::open_media(data, &key, backup);
    if let Ok(metadata) = file_metadata::decode_v2(data) {
        let _ = metadata.content.check(&[0x22; 16], &[0; 32]);
    }
});
