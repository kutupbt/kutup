//! Chat attachments in the block format (docs/plans/drive-block-format.md
//! §2): suite 2 of `ChatMediaSuiteId`. An attachment is immutable, so its
//! header names only the attachment; its manifest is unsigned, as the E2EE
//! descriptor that carries the attachment key commits to the manifest's
//! digest (Signal's incremental MAC in the pointer, in Kutup's framing).
//!
//! ```text
//! magic "KUTPCM2\0" ‖ u16 suite 2 ‖ u8 purpose 1 ‖ u8 0 ‖ 16-byte attachment id
//! ```

use zeroize::Zeroizing;

use crate::blocks::{self, BlockFamily, BlockReader, BlockSealer, Manifest};
use crate::chat_media::{ChatMediaObjectContextV1, ChatMediaObjectPurpose, ChatMediaSuiteId};
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCM2\0";
pub const CHAT_MEDIA_BLOCKS_HEADER_BYTES: usize = 28;
const KEY_LEN: usize = 32;

/// The Chat-media family of the block construction.
pub static CHAT_MEDIA_BLOCKS: BlockFamily = BlockFamily {
    block_key_label: b"kutup/chat-media/blocks/block-key/v1\0",
    nonce_key_label: b"kutup/chat-media/blocks/nonce-key/v1\0",
    manifest_key_label: b"kutup/chat-media/blocks/manifest-key/v1\0",
    signature_domain: b"",
    trailer_magic: b"KUTPCMM\0",
    signed: false,
};

pub fn header(context: ChatMediaObjectContextV1) -> [u8; CHAT_MEDIA_BLOCKS_HEADER_BYTES] {
    let mut header = [0u8; CHAT_MEDIA_BLOCKS_HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&ChatMediaSuiteId::KutupBlocksV1.as_u16().to_be_bytes());
    header[10] = ChatMediaObjectPurpose::AttachmentBlob.as_u8();
    header[12..28].copy_from_slice(&context.attachment_id);
    header
}

/// Checks a header against the attachment expected.
pub fn validate_header(header: &[u8], expected: ChatMediaObjectContextV1) -> Result<()> {
    if header.len() != CHAT_MEDIA_BLOCKS_HEADER_BYTES
        || header.get(..8) != Some(MAGIC)
        || ChatMediaSuiteId::try_from(u16::from_be_bytes([header[8], header[9]]))?
            != ChatMediaSuiteId::KutupBlocksV1
        || ChatMediaObjectPurpose::try_from(header[10])? != ChatMediaObjectPurpose::AttachmentBlob
        || header[11] != 0
        || header[12..28] != expected.attachment_id
    {
        return Err(CryptoError::InvalidInput(
            "Chat-media object is not this attachment's".into(),
        ));
    }
    Ok(())
}

fn attachment_key(key: &[u8]) -> Result<&[u8]> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }
    Ok(key)
}

pub fn sealer(
    key: &[u8],
    context: ChatMediaObjectContextV1,
    size: u64,
) -> Result<BlockSealer<'static>> {
    BlockSealer::new(
        &CHAT_MEDIA_BLOCKS,
        attachment_key(key)?,
        &header(context),
        size,
    )
}

pub fn reader(
    key: &[u8],
    context: ChatMediaObjectContextV1,
    sealed_manifest: &[u8],
) -> Result<BlockReader<'static>> {
    BlockReader::open(
        &CHAT_MEDIA_BLOCKS,
        attachment_key(key)?,
        &header(context),
        sealed_manifest,
    )
}

/// The whole object's length for `size` plaintext bytes.
pub fn object_len(size: u64) -> Result<u64> {
    CHAT_MEDIA_BLOCKS.object_len(CHAT_MEDIA_BLOCKS_HEADER_BYTES, size)
}

pub fn seal_attachment(
    plaintext: &[u8],
    key: &[u8],
    context: ChatMediaObjectContextV1,
) -> Result<Vec<u8>> {
    blocks::seal_object(
        &CHAT_MEDIA_BLOCKS,
        attachment_key(key)?,
        &header(context),
        plaintext,
        None,
    )
}

/// Opens a whole attachment: the plaintext, the manifest, and the sealed
/// manifest's digest (which the descriptor must name).
pub fn open_attachment(
    object: &[u8],
    key: &[u8],
    expected: ChatMediaObjectContextV1,
) -> Result<(Zeroizing<Vec<u8>>, Manifest, [u8; 32])> {
    validate_header(
        object
            .get(..CHAT_MEDIA_BLOCKS_HEADER_BYTES)
            .ok_or(CryptoError::TooShort)?,
        expected,
    )?;
    blocks::open_object(
        &CHAT_MEDIA_BLOCKS,
        attachment_key(key)?,
        CHAT_MEDIA_BLOCKS_HEADER_BYTES,
        object,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attachment_round_trips_and_is_bound_to_its_id() {
        let context =
            ChatMediaObjectContextV1::new("66666666-6666-4666-8666-666666666666").unwrap();
        let plaintext = vec![5u8; crate::blocks::BLOCK_SIZE + 1];
        let object = seal_attachment(&plaintext, &[1; 32], context).unwrap();
        assert_eq!(
            object.len() as u64,
            object_len(plaintext.len() as u64).unwrap()
        );
        let (opened, manifest, _) = open_attachment(&object, &[1; 32], context).unwrap();
        assert_eq!(*opened, plaintext);
        assert!(manifest.signer.is_none());
        let other = ChatMediaObjectContextV1::new("77777777-7777-4777-8777-777777777777").unwrap();
        assert!(open_attachment(&object, &[1; 32], other).is_err());
        assert!(open_attachment(&object, &[2; 32], context).is_err());
    }
}
