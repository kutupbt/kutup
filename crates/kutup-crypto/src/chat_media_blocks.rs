//! Chat attachments in the block format (docs/plans/drive-block-format.md
//! §2): Chat-media suite 2
//! (`CHAT_MEDIA_BLOCKS_SUITE`; `ChatMediaSuiteId`, a wire type, gains it when
//! Chat switches). An attachment is immutable, so its
//! header names only the attachment; its manifest is unsigned, as the E2EE
//! descriptor that carries the attachment key commits to the manifest's
//! digest (Signal's incremental MAC in the pointer, in Kutup's framing).
//!
//! ```text
//! magic "KUTPCM2\0" ‖ u16 suite 2 ‖ u8 purpose 1 ‖ u8 0 ‖ 16-byte attachment id
//! ```

use zeroize::Zeroizing;

use crate::blocks::{self, BlockFamily, BlockReader, BlockSealer, Manifest, SealedObject};
use crate::chat_media::{ChatMediaObjectContextV1, ChatMediaObjectPurpose};
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCM2\0";
pub const CHAT_MEDIA_BLOCKS_HEADER_BYTES: usize = 28;
/// The Chat-media suite of the block format.
pub const CHAT_MEDIA_BLOCKS_SUITE: u16 = 2;
const KEY_LEN: usize = 32;

/// The Chat-media family of the block construction.
pub static CHAT_MEDIA_BLOCKS: BlockFamily = BlockFamily {
    block_key_label: crate::labels::CHAT_MEDIA_BLOCKS_BLOCK_KEY_V1,
    nonce_key_label: crate::labels::CHAT_MEDIA_BLOCKS_NONCE_KEY_V1,
    manifest_key_label: crate::labels::CHAT_MEDIA_BLOCKS_MANIFEST_KEY_V1,
    signature_domain: b"",
    trailer_magic: b"KUTPCMM\0",
    signed: false,
};

pub fn header(context: ChatMediaObjectContextV1) -> [u8; CHAT_MEDIA_BLOCKS_HEADER_BYTES] {
    let mut header = [0u8; CHAT_MEDIA_BLOCKS_HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&CHAT_MEDIA_BLOCKS_SUITE.to_be_bytes());
    header[10] = ChatMediaObjectPurpose::AttachmentBlob.as_u8();
    header[12..28].copy_from_slice(&context.attachment_id);
    header
}

/// Checks a header against the attachment expected.
pub fn validate_header(header: &[u8], expected: ChatMediaObjectContextV1) -> Result<()> {
    if header.len() != CHAT_MEDIA_BLOCKS_HEADER_BYTES
        || header.get(..8) != Some(MAGIC)
        || u16::from_be_bytes([header[8], header[9]]) != CHAT_MEDIA_BLOCKS_SUITE
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

/// The reader of an attachment whose header was checked against `context`
/// and whose sealed manifest is the one the descriptor commits to
/// (`expected_manifest_sha256`): without that check, anyone holding the
/// attachment key could have the server hand other members other content.
pub fn reader(
    key: &[u8],
    context: ChatMediaObjectContextV1,
    sealed_manifest: &[u8],
    expected_manifest_sha256: &[u8; 32],
) -> Result<BlockReader<'static>> {
    BlockReader::open(
        &CHAT_MEDIA_BLOCKS,
        attachment_key(key)?,
        &header(context),
        sealed_manifest,
        expected_manifest_sha256,
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
) -> Result<SealedObject> {
    blocks::seal_object(
        &CHAT_MEDIA_BLOCKS,
        attachment_key(key)?,
        &header(context),
        plaintext,
        None,
    )
}

/// Opens a whole attachment whose sealed manifest is the one the descriptor
/// commits to: the plaintext and the manifest.
pub fn open_attachment(
    object: &[u8],
    key: &[u8],
    expected: ChatMediaObjectContextV1,
    expected_manifest_sha256: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Manifest)> {
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
        expected_manifest_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attachment_round_trips_and_is_bound_to_its_id_and_descriptor() {
        let context =
            ChatMediaObjectContextV1::new("66666666-6666-4666-8666-666666666666").unwrap();
        let plaintext = vec![5u8; crate::blocks::BLOCK_SIZE + 1];
        let sealed = seal_attachment(&plaintext, &[1; 32], context).unwrap();
        let (object, digest) = (&sealed.bytes, &sealed.manifest_sha256);
        assert_eq!(
            object.len() as u64,
            object_len(plaintext.len() as u64).unwrap()
        );
        let (opened, manifest) = open_attachment(object, &[1; 32], context, digest).unwrap();
        assert_eq!(*opened, plaintext);
        assert!(manifest.signer.is_none());
        let other = ChatMediaObjectContextV1::new("77777777-7777-4777-8777-777777777777").unwrap();
        assert!(open_attachment(object, &[1; 32], other, digest).is_err());
        assert!(open_attachment(object, &[2; 32], context, digest).is_err());
        // Another attachment sealed by a key holder under the same id and key:
        // valid, but not the one the descriptor names.
        let swapped = seal_attachment(b"other content", &[1; 32], context).unwrap();
        assert!(open_attachment(&swapped.bytes, &[1; 32], context, digest).is_err());
        assert!(
            open_attachment(&swapped.bytes, &[1; 32], context, &swapped.manifest_sha256).is_ok()
        );
    }
}
