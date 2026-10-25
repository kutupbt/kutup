//! Chat backup media in the block format (docs/plans/drive-block-format.md
//! §2, Q6): the already-E2EE Chat-media ciphertext, padded to its bucket as
//! today, wrapped in blocks under the backup's outer key. The header is
//! suite 1's with its own magic and suite; the manifest is unsigned, as the
//! backup's sealed index commits to the media object.

use zeroize::Zeroizing;

use crate::blocks::{self, BlockFamily, BlockReader, BlockSealer, Manifest};
use crate::chat_backup::ChatBackupProtectionDomainV1;
use crate::chat_backup_media::{padded_media_plaintext_bytes, ChatBackupMediaContextV1};
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPBM2\0";
/// Backup media's own block suite.
pub const CHAT_BACKUP_MEDIA_BLOCKS_SUITE: u16 = 2;
pub const CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES: usize = 8 + 2 + 1 + 32 + 16 + 32 + 8 + 8;
const KEY_LEN: usize = 32;

/// The backup-media family of the block construction.
pub static CHAT_BACKUP_MEDIA_BLOCKS: BlockFamily = BlockFamily {
    block_key_label: b"kutup/chat-backup-media/blocks/block-key/v1\0",
    nonce_key_label: b"kutup/chat-backup-media/blocks/nonce-key/v1\0",
    manifest_key_label: b"kutup/chat-backup-media/blocks/manifest-key/v1\0",
    signature_domain: b"",
    trailer_magic: b"KUTPBMM\0",
    signed: false,
};

/// A header and what it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBackupMediaBlocksHeader {
    pub context: ChatBackupMediaContextV1,
    pub source_ciphertext_bytes: u64,
    pub padded_plaintext_bytes: u64,
}

pub fn header(
    context: ChatBackupMediaContextV1,
    source_ciphertext_bytes: u64,
) -> Result<[u8; CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES]> {
    let padded = padded_media_plaintext_bytes(source_ciphertext_bytes)?;
    let mut header = [0u8; CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&CHAT_BACKUP_MEDIA_BLOCKS_SUITE.to_be_bytes());
    header[10] = context.protection_domain.as_u8();
    header[11..43].copy_from_slice(&context.account_incarnation_id);
    header[43..59].copy_from_slice(&context.backup_incarnation_id);
    header[59..91].copy_from_slice(&context.media_id);
    header[91..99].copy_from_slice(&source_ciphertext_bytes.to_be_bytes());
    header[99..107].copy_from_slice(&padded.to_be_bytes());
    Ok(header)
}

pub fn inspect_header(header: &[u8]) -> Result<ChatBackupMediaBlocksHeader> {
    if header.len() != CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES
        || header.get(..8) != Some(MAGIC)
        || u16::from_be_bytes([header[8], header[9]]) != CHAT_BACKUP_MEDIA_BLOCKS_SUITE
    {
        return Err(CryptoError::InvalidInput(
            "not a Chat backup media block header".into(),
        ));
    }
    let source = u64::from_be_bytes(header[91..99].try_into().expect("eight bytes"));
    let padded = u64::from_be_bytes(header[99..107].try_into().expect("eight bytes"));
    if padded != padded_media_plaintext_bytes(source)? {
        return Err(CryptoError::InvalidInput(
            "invalid Chat backup media padding bucket".into(),
        ));
    }
    Ok(ChatBackupMediaBlocksHeader {
        context: ChatBackupMediaContextV1 {
            protection_domain: ChatBackupProtectionDomainV1::try_from(header[10])?,
            account_incarnation_id: header[11..43].try_into().expect("32 bytes"),
            backup_incarnation_id: header[43..59].try_into().expect("16 bytes"),
            media_id: header[59..91].try_into().expect("32 bytes"),
        },
        source_ciphertext_bytes: source,
        padded_plaintext_bytes: padded,
    })
}

fn outer_key(key: &[u8]) -> Result<&[u8]> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }
    Ok(key)
}

/// A sealer for the padded media: the header's padded size, in blocks.
pub fn sealer(
    key: &[u8],
    context: ChatBackupMediaContextV1,
    source_ciphertext_bytes: u64,
) -> Result<BlockSealer<'static>> {
    let header = header(context, source_ciphertext_bytes)?;
    let padded = padded_media_plaintext_bytes(source_ciphertext_bytes)?;
    BlockSealer::new(&CHAT_BACKUP_MEDIA_BLOCKS, outer_key(key)?, &header, padded)
}

/// A media object's reader, block by block: each block's plaintext comes back
/// without the padding, which is checked to be zeros, so a restore streams.
pub struct MediaReader {
    reader: BlockReader<'static>,
    source_ciphertext_bytes: u64,
}

impl MediaReader {
    /// Opens the manifest of the object behind `header`, which must name
    /// `expected`, and checks the manifest's size is the header's padded size.
    pub fn open(
        key: &[u8],
        expected: ChatBackupMediaContextV1,
        header: &[u8],
        sealed_manifest: &[u8],
    ) -> Result<Self> {
        let parsed = inspect_header(header)?;
        if parsed.context != expected {
            return Err(CryptoError::InvalidInput(
                "Chat backup media is another object's".into(),
            ));
        }
        let reader = BlockReader::open(
            &CHAT_BACKUP_MEDIA_BLOCKS,
            outer_key(key)?,
            header,
            sealed_manifest,
        )?;
        if reader.manifest().size != parsed.padded_plaintext_bytes {
            return Err(CryptoError::InvalidInput(
                "Chat backup media padding is invalid".into(),
            ));
        }
        Ok(Self {
            reader,
            source_ciphertext_bytes: parsed.source_ciphertext_bytes,
        })
    }

    pub fn reader(&self) -> &BlockReader<'static> {
        &self.reader
    }

    /// The Chat-media ciphertext's length, before padding.
    pub fn source_ciphertext_bytes(&self) -> u64 {
        self.source_ciphertext_bytes
    }

    /// Block `index`'s share of the source: its padding checked and dropped
    /// (empty for a block of padding only).
    pub fn open_block(&self, index: u64, block: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut plaintext = self.reader.open_block(index, block)?;
        let start = index * blocks::BLOCK_SIZE as u64;
        let keep = self
            .source_ciphertext_bytes
            .saturating_sub(start)
            .min(plaintext.len() as u64) as usize;
        if plaintext[keep..].iter().any(|b| *b != 0) {
            return Err(CryptoError::InvalidInput(
                "Chat backup media padding is invalid".into(),
            ));
        }
        plaintext.truncate(keep);
        Ok(plaintext)
    }
}

/// The whole object's length for `source_ciphertext_bytes` before padding.
pub fn object_len(source_ciphertext_bytes: u64) -> Result<u64> {
    CHAT_BACKUP_MEDIA_BLOCKS.object_len(
        CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES,
        padded_media_plaintext_bytes(source_ciphertext_bytes)?,
    )
}

/// Pads `source` (the Chat-media ciphertext) to its bucket and seals it.
pub fn seal_media(source: &[u8], key: &[u8], context: ChatBackupMediaContextV1) -> Result<Vec<u8>> {
    let header = header(context, source.len() as u64)?;
    let padded = padded_media_plaintext_bytes(source.len() as u64)? as usize;
    let mut plaintext = Zeroizing::new(vec![0u8; padded]);
    plaintext[..source.len()].copy_from_slice(source);
    blocks::seal_object(
        &CHAT_BACKUP_MEDIA_BLOCKS,
        outer_key(key)?,
        &header,
        &plaintext,
        None,
    )
}

/// Opens a whole media object for `expected`: the source without its padding
/// (the padding checked to be zeros), and the manifest's digest.
pub fn open_media(
    object: &[u8],
    key: &[u8],
    expected: ChatBackupMediaContextV1,
) -> Result<(Zeroizing<Vec<u8>>, Manifest, [u8; 32])> {
    let parsed = inspect_header(
        object
            .get(..CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES)
            .ok_or(CryptoError::TooShort)?,
    )?;
    if parsed.context != expected {
        return Err(CryptoError::InvalidInput(
            "Chat backup media is another object's".into(),
        ));
    }
    let (mut plaintext, manifest, digest) = blocks::open_object(
        &CHAT_BACKUP_MEDIA_BLOCKS,
        outer_key(key)?,
        CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES,
        object,
    )?;
    let source = parsed.source_ciphertext_bytes as usize;
    if manifest.size != parsed.padded_plaintext_bytes || plaintext[source..].iter().any(|b| *b != 0)
    {
        return Err(CryptoError::InvalidInput(
            "Chat backup media padding is invalid".into(),
        ));
    }
    plaintext.truncate(source);
    Ok((plaintext, manifest, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ChatBackupMediaContextV1 {
        ChatBackupMediaContextV1 {
            account_incarnation_id: [1; 32],
            backup_incarnation_id: [2; 16],
            protection_domain: ChatBackupProtectionDomainV1::StandardChat,
            media_id: [3; 32],
        }
    }

    #[test]
    fn media_is_padded_sealed_and_opened_to_its_source() {
        let source = vec![9u8; 1_000];
        let object = seal_media(&source, &[4; 32], context()).unwrap();
        assert_eq!(object.len() as u64, object_len(1_000).unwrap());
        let (opened, manifest, _) = open_media(&object, &[4; 32], context()).unwrap();
        assert_eq!(*opened, source);
        assert_eq!(manifest.size, padded_media_plaintext_bytes(1_000).unwrap());
        let mut other = context();
        other.media_id = [4; 32];
        assert!(open_media(&object, &[4; 32], other).is_err());
        assert!(
            seal_media(&[], &[4; 32], context()).is_err(),
            "no empty source"
        );
    }

    #[test]
    fn the_streaming_reader_drops_padding_per_block() {
        let source = vec![9u8; blocks::BLOCK_SIZE + 3];
        let object = seal_media(&source, &[4; 32], context()).unwrap();
        let header = &object[..CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES];
        let trailer = &object[object.len() - blocks::TRAILER_LEN..];
        let len = CHAT_BACKUP_MEDIA_BLOCKS.parse_trailer(trailer).unwrap();
        let manifest =
            &object[object.len() - blocks::TRAILER_LEN - len..object.len() - blocks::TRAILER_LEN];
        let reader = MediaReader::open(&[4; 32], context(), header, manifest).unwrap();
        assert_eq!(reader.source_ciphertext_bytes(), source.len() as u64);
        let mut restored = Vec::new();
        for index in 0..reader.reader().manifest().count {
            let start = blocks::block_offset(CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES, index) as usize;
            let size = blocks::block_plaintext_len(reader.reader().manifest().size, index).unwrap();
            let block = &object[start..start + size + blocks::BLOCK_OVERHEAD];
            restored.extend_from_slice(&reader.open_block(index, block).unwrap());
        }
        assert_eq!(restored, source);
        let mut other = context();
        other.media_id = [5; 32];
        assert!(MediaReader::open(&[4; 32], other, header, manifest).is_err());
    }

    #[test]
    fn padding_that_is_not_zeros_fails() {
        let header = header(context(), 10).unwrap();
        let padded = padded_media_plaintext_bytes(10).unwrap() as usize;
        let mut plaintext = vec![0u8; padded];
        plaintext[padded - 1] = 1;
        let object = blocks::seal_object(
            &CHAT_BACKUP_MEDIA_BLOCKS,
            &[4; 32],
            &header,
            &plaintext,
            None,
        )
        .unwrap();
        assert!(open_media(&object, &[4; 32], context()).is_err());
    }
}
