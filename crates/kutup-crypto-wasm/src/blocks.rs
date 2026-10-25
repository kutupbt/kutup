//! The block format in the browser (docs/plans/drive-block-format.md §4), over
//! `kutup_crypto::blocks` and its three families: Drive files, Chat media and
//! Chat backup media. An encryptor or reader holds its object's keys in WASM
//! memory; JavaScript holds the object, never the keys, moves the bytes
//! (`Uint8Array` in and out, no base64 for 4 MiB blocks) and frees it when
//! the object is done.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use kutup_crypto::blocks::{
    block_count, block_offset, block_plaintext_len, BlockFamily, BlockReader, BlockSealer,
    SealedTail, BLOCK_OVERHEAD, BLOCK_SIZE, TRAILER_LEN,
};
use kutup_crypto::chat_backup::{self, ChatBackupContextV1};
use kutup_crypto::chat_backup_media::ChatBackupMediaContextV1;
use kutup_crypto::chat_backup_media_blocks::{
    self, MediaReader, CHAT_BACKUP_MEDIA_BLOCKS, CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::chat_media::ChatMediaObjectContextV1;
use kutup_crypto::chat_media_blocks::{self, CHAT_MEDIA_BLOCKS, CHAT_MEDIA_BLOCKS_HEADER_BYTES};
use kutup_crypto::drive_blocks::{
    self, DriveBlobContextV2, DRIVE_BLOCKS, DRIVE_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::file_metadata::ContentCommitmentV1;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::primitives::{Suite, VerifyingKey};
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use crate::{chat_backup_context, decode_canonical_base64, js_error};

fn crypto_error(error: kutup_crypto::error::CryptoError) -> JsValue {
    js_error(&error.to_string())
}

/// A byte count from JavaScript: a whole number from 0 to 2^53 − 1.
fn byte_count(value: f64, field: &str) -> Result<u64, JsValue> {
    if value.fract() != 0.0 || !(0.0..=9_007_199_254_740_991.0).contains(&value) {
        return Err(js_error(&format!(
            "{field} must be a whole number of bytes"
        )));
    }
    Ok(value as u64)
}

/// A sealed manifest's SHA-256, as metadata and descriptors carry it
/// (canonical base64).
fn manifest_sha256(value: &str) -> Result<[u8; 32], JsValue> {
    decode_canonical_base64(value, "manifest SHA-256")?
        .try_into()
        .map_err(|_| js_error("manifest SHA-256 must be 32 bytes"))
}

fn block_index(value: f64) -> Result<u64, JsValue> {
    byte_count(value, "block index")
}

fn account_id(value: &str) -> Result<[u8; 16], JsValue> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.hyphenated().to_string() == value)
        .map(|id| *id.as_bytes())
        .ok_or_else(|| js_error("account id must be a canonical non-nil UUID"))
}

fn media_id(value: &str) -> Result<[u8; 32], JsValue> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|bytes: &[u8; 32]| hex::encode(bytes) == value)
        .ok_or_else(|| js_error("backup media id must be lowercase 32-byte hex"))
}

fn backup_media_context(
    context: ChatBackupContextV1,
    media_id: [u8; 32],
) -> ChatBackupMediaContextV1 {
    ChatBackupMediaContextV1 {
        account_incarnation_id: context.account_incarnation_id,
        backup_incarnation_id: context.backup_incarnation_id,
        protection_domain: context.protection_domain,
        media_id,
    }
}

#[derive(Clone, Copy)]
enum Family {
    Drive,
    ChatMedia,
    ChatBackupMedia,
}

impl Family {
    fn parse(name: &str) -> Result<Self, JsValue> {
        match name {
            "drive" => Ok(Self::Drive),
            "chatMedia" => Ok(Self::ChatMedia),
            "chatBackupMedia" => Ok(Self::ChatBackupMedia),
            _ => Err(js_error(&format!("unknown block family {name:?}"))),
        }
    }

    fn blocks(self) -> &'static BlockFamily {
        match self {
            Self::Drive => &DRIVE_BLOCKS,
            Self::ChatMedia => &CHAT_MEDIA_BLOCKS,
            Self::ChatBackupMedia => &CHAT_BACKUP_MEDIA_BLOCKS,
        }
    }

    fn header_len(self) -> usize {
        match self {
            Self::Drive => DRIVE_BLOCKS_HEADER_BYTES,
            Self::ChatMedia => CHAT_MEDIA_BLOCKS_HEADER_BYTES,
            Self::ChatBackupMedia => CHAT_BACKUP_MEDIA_BLOCKS_HEADER_BYTES,
        }
    }
}

/// Where everything sits in an object of `family` (`drive`, `chatMedia`,
/// `chatBackupMedia`), for a reader planning its range requests.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BlockLayoutView {
    header_bytes: usize,
    block_size: usize,
    block_overhead: usize,
    trailer_bytes: usize,
}

#[wasm_bindgen(js_name = blockLayout)]
pub fn block_layout(family: &str) -> Result<JsValue, JsValue> {
    let family = Family::parse(family)?;
    serde_wasm_bindgen::to_value(&BlockLayoutView {
        header_bytes: family.header_len(),
        block_size: BLOCK_SIZE,
        block_overhead: BLOCK_OVERHEAD,
        trailer_bytes: TRAILER_LEN,
    })
    .map_err(|error| js_error(&error.to_string()))
}

/// The sealed manifest's length a trailer (the object's last bytes) names.
#[wasm_bindgen(js_name = blockTrailerManifestLength)]
pub fn block_trailer_manifest_length(family: &str, trailer: &[u8]) -> Result<usize, JsValue> {
    Family::parse(family)?
        .blocks()
        .parse_trailer(trailer)
        .map_err(crypto_error)
}

/// Encrypts one object block by block: the header first, then each block in
/// order, then `finish` (or `finishSigned` for Drive) for the sealed manifest
/// and the trailer. Re-sealing the same block gives the same bytes, so an
/// upload resumes at any block.
#[wasm_bindgen(js_name = BlockEncryptor)]
pub struct BlockEncryptorJs {
    family: Family,
    header: Vec<u8>,
    size: u64,
    sealer: Option<BlockSealer<'static>>,
    /// A backup media object's id (lowercase hex), derived from its source.
    media_id: Option<String>,
    /// Once finished: the sealed manifest's digest.
    manifest_sha256: Option<[u8; 32]>,
}

impl BlockEncryptorJs {
    fn sealer(&mut self) -> Result<&mut BlockSealer<'static>, JsValue> {
        self.sealer
            .as_mut()
            .ok_or_else(|| js_error("block encryptor already finished"))
    }

    fn finished(&mut self, tail: SealedTail) -> Vec<u8> {
        self.manifest_sha256 = Some(tail.manifest_sha256);
        tail.bytes
    }
}

#[wasm_bindgen(js_class = BlockEncryptor)]
impl BlockEncryptorJs {
    /// The object's header: the object's first bytes.
    pub fn header(&self) -> Vec<u8> {
        self.header.clone()
    }

    /// The plaintext bytes the blocks carry (padded, for backup media).
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.size as f64
    }

    #[wasm_bindgen(getter, js_name = blockCount)]
    pub fn block_count(&self) -> Result<f64, JsValue> {
        Ok(block_count(self.size).map_err(crypto_error)? as f64)
    }

    #[wasm_bindgen(getter, js_name = nextIndex)]
    pub fn next_index(&self) -> Result<f64, JsValue> {
        Ok(self
            .sealer
            .as_ref()
            .ok_or_else(|| js_error("block encryptor already finished"))?
            .next_index() as f64)
    }

    /// Block `index`'s plaintext length.
    #[wasm_bindgen(js_name = blockLength)]
    pub fn block_length(&self, index: f64) -> Result<usize, JsValue> {
        block_plaintext_len(self.size, block_index(index)?).map_err(crypto_error)
    }

    /// Block `index`'s offset in the object.
    #[wasm_bindgen(js_name = blockOffset)]
    pub fn block_offset(&self, index: f64) -> Result<f64, JsValue> {
        Ok(block_offset(self.family.header_len(), block_index(index)?) as f64)
    }

    /// The whole object's length.
    #[wasm_bindgen(getter, js_name = objectLength)]
    pub fn object_length(&self) -> Result<f64, JsValue> {
        Ok(self
            .family
            .blocks()
            .object_len(self.family.header_len(), self.size)
            .map_err(crypto_error)? as f64)
    }

    #[wasm_bindgen(getter, js_name = mediaId)]
    pub fn media_id(&self) -> Option<String> {
        self.media_id.clone()
    }

    /// Once finished, SHA-256 of the sealed manifest (canonical base64): what
    /// the metadata or descriptor commits to, and every reader requires
    /// (`content.manifestSha256` for Drive).
    #[wasm_bindgen(getter, js_name = manifestSha256)]
    pub fn manifest_sha256(&self) -> Option<String> {
        self.manifest_sha256.map(|digest| STANDARD.encode(digest))
    }

    /// Seals the next block, which must be exactly its length.
    #[wasm_bindgen(js_name = sealNext)]
    pub fn seal_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.sealer()?.seal_next(plaintext).map_err(crypto_error)
    }

    /// The sealed manifest and the trailer of an unsigned family (Chat
    /// media, backup media), once every block is sealed.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        let sealer = self
            .sealer
            .take()
            .ok_or_else(|| js_error("block encryptor already finished"))?;
        let tail = sealer.finish(None).map_err(crypto_error)?;
        Ok(self.finished(tail))
    }

    /// A Drive object's sealed manifest and trailer, signed with the
    /// uploader's Drive signing key (from the account master key) and naming
    /// the uploader's account id.
    #[wasm_bindgen(js_name = finishSigned)]
    pub fn finish_signed(
        &mut self,
        master_key_base64: &str,
        uploader_account_id: &str,
    ) -> Result<Vec<u8>, JsValue> {
        let master_key: [u8; 32] = decode_canonical_base64(master_key_base64, "master key")?
            .try_into()
            .map_err(|_| js_error("master key must be 32 bytes"))?;
        let account = account_id(uploader_account_id)?;
        let identity = AccountIdentityKeysV1::derive(&master_key).map_err(crypto_error)?;
        let sealer = self
            .sealer
            .take()
            .ok_or_else(|| js_error("block encryptor already finished"))?;
        let tail = sealer
            .finish(Some((identity.drive_signing_key(), account)))
            .map_err(crypto_error)?;
        Ok(self.finished(tail))
    }
}

/// An encryptor for a Drive file revision of `size` bytes.
#[wasm_bindgen(js_name = driveBlockEncryptor)]
pub fn drive_block_encryptor(
    file_key_base64: &str,
    file_id: &str,
    revision_id: &str,
    generation: u32,
    size: f64,
) -> Result<BlockEncryptorJs, JsValue> {
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let context =
        DriveBlobContextV2::new(file_id, revision_id, generation).map_err(crypto_error)?;
    let size = byte_count(size, "file size")?;
    Ok(BlockEncryptorJs {
        family: Family::Drive,
        header: drive_blocks::header(context).to_vec(),
        size,
        sealer: Some(drive_blocks::sealer(&file_key, context, size).map_err(crypto_error)?),
        media_id: None,
        manifest_sha256: None,
    })
}

/// An encryptor for a Chat attachment of `size` bytes.
#[wasm_bindgen(js_name = chatMediaBlockEncryptor)]
pub fn chat_media_block_encryptor(
    attachment_key_base64: &str,
    attachment_id: &str,
    size: f64,
) -> Result<BlockEncryptorJs, JsValue> {
    let key = decode_canonical_base64(attachment_key_base64, "attachment key")?;
    let context = ChatMediaObjectContextV1::new(attachment_id).map_err(crypto_error)?;
    let size = byte_count(size, "attachment size")?;
    Ok(BlockEncryptorJs {
        family: Family::ChatMedia,
        header: chat_media_blocks::header(context).to_vec(),
        size,
        sealer: Some(chat_media_blocks::sealer(&key, context, size).map_err(crypto_error)?),
        media_id: None,
        manifest_sha256: None,
    })
}

/// An encryptor for the backup copy of a Chat attachment's ciphertext
/// (`sourceBytes` long): its media id and key derived from the backup root
/// and the source's stable binding. Feed it the source, then zeros up to
/// `size` (the padded length).
#[wasm_bindgen(js_name = chatBackupMediaBlockEncryptor)]
pub fn chat_backup_media_block_encryptor(
    backup_root_base64: &str,
    account_incarnation_id: &str,
    backup_incarnation_id: &str,
    stable_source_binding: &str,
    source_bytes: f64,
) -> Result<BlockEncryptorJs, JsValue> {
    if stable_source_binding.is_empty() {
        return Err(js_error("backup media source binding is empty"));
    }
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let context = chat_backup_context(account_incarnation_id, backup_incarnation_id)?;
    let media_id = chat_backup::derive_media_id(&root, context, stable_source_binding.as_bytes())
        .map_err(crypto_error)?;
    let key = chat_backup::derive_media_encryption_key(&root, context, &media_id)
        .map_err(crypto_error)?;
    let media = backup_media_context(context, media_id);
    let source_bytes = byte_count(source_bytes, "backup media source size")?;
    let sealer = chat_backup_media_blocks::sealer(key.as_slice(), media, source_bytes)
        .map_err(crypto_error)?;
    let header = chat_backup_media_blocks::header(media, source_bytes).map_err(crypto_error)?;
    let size = chat_backup_media_blocks::inspect_header(&header)
        .map_err(crypto_error)?
        .padded_plaintext_bytes;
    Ok(BlockEncryptorJs {
        family: Family::ChatBackupMedia,
        header: header.to_vec(),
        size,
        sealer: Some(sealer),
        media_id: Some(hex::encode(media_id)),
        manifest_sha256: None,
    })
}

enum Reader {
    Blocks(BlockReader<'static>),
    BackupMedia(MediaReader),
}

/// Reads one object by block, in any order: made from the object's header
/// (checked against what the caller expects) and its sealed manifest (which
/// the trailer points at). A block is opened only after its hash matches the
/// manifest's, so nothing unverified is released.
#[wasm_bindgen(js_name = BlockReader)]
pub struct BlockReaderJs {
    family: Family,
    reader: Reader,
}

impl BlockReaderJs {
    fn blocks(&self) -> &BlockReader<'static> {
        match &self.reader {
            Reader::Blocks(reader) => reader,
            Reader::BackupMedia(reader) => reader.reader(),
        }
    }
}

#[wasm_bindgen(js_class = BlockReader)]
impl BlockReaderJs {
    /// The plaintext bytes the blocks carry (padded, for backup media).
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.blocks().manifest().size as f64
    }

    /// For backup media, the source's length without padding: what the
    /// blocks give back in all.
    #[wasm_bindgen(getter, js_name = sourceBytes)]
    pub fn source_bytes(&self) -> Option<f64> {
        match &self.reader {
            Reader::BackupMedia(reader) => Some(reader.source_ciphertext_bytes() as f64),
            Reader::Blocks(_) => None,
        }
    }

    #[wasm_bindgen(getter, js_name = blockCount)]
    pub fn block_count(&self) -> f64 {
        self.blocks().manifest().count as f64
    }

    /// Block `index`'s offset in the object.
    #[wasm_bindgen(js_name = blockOffset)]
    pub fn block_offset(&self, index: f64) -> Result<f64, JsValue> {
        Ok(block_offset(self.family.header_len(), block_index(index)?) as f64)
    }

    /// Block `index`'s sealed length (plaintext and overhead).
    #[wasm_bindgen(js_name = sealedBlockLength)]
    pub fn sealed_block_length(&self, index: f64) -> Result<usize, JsValue> {
        Ok(
            block_plaintext_len(self.blocks().manifest().size, block_index(index)?)
                .map_err(crypto_error)?
                + BLOCK_OVERHEAD,
        )
    }

    /// The whole object's length, for checking the server's.
    #[wasm_bindgen(getter, js_name = objectLength)]
    pub fn object_length(&self) -> Result<f64, JsValue> {
        Ok(self.blocks().object_len().map_err(crypto_error)? as f64)
    }

    /// The account id a Drive manifest names as its uploader.
    #[wasm_bindgen(getter, js_name = signerAccountId)]
    pub fn signer_account_id(&self) -> Option<String> {
        self.blocks()
            .manifest()
            .signer
            .as_ref()
            .map(|signer| Uuid::from_bytes(signer.account_id).hyphenated().to_string())
    }

    /// Checks a Drive manifest's signature against the uploader's pinned
    /// Drive signing public key (base64).
    #[wasm_bindgen(js_name = verifySigner)]
    pub fn verify_signer(&self, drive_signing_public_key_base64: &str) -> Result<(), JsValue> {
        let public_key =
            decode_canonical_base64(drive_signing_public_key_base64, "Drive signing public key")?;
        let key = VerifyingKey::from_bytes(Suite::V1, &public_key).map_err(crypto_error)?;
        self.blocks()
            .manifest()
            .verify_signer(&key)
            .map_err(crypto_error)
    }

    /// Block `index`'s plaintext (for backup media, without padding).
    #[wasm_bindgen(js_name = openBlock)]
    pub fn open_block(&self, index: f64, block: &[u8]) -> Result<Vec<u8>, JsValue> {
        let index = block_index(index)?;
        let plaintext = match &self.reader {
            Reader::Blocks(reader) => reader.open_block(index, block),
            Reader::BackupMedia(reader) => reader.open_block(index, block),
        }
        .map_err(crypto_error)?;
        Ok(plaintext.to_vec())
    }
}

/// A reader of the Drive file revision its metadata commits to
/// (`content.revisionId`, `content.manifestSha256`, and `size`): the header
/// must name that revision and the manifest must be that one, of that size.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = driveBlockReader)]
pub fn drive_block_reader(
    file_key_base64: &str,
    expected_file_id: &str,
    expected_generation: u32,
    content_revision_id: &str,
    content_manifest_sha256: &str,
    size: f64,
    header: &[u8],
    sealed_manifest: &[u8],
) -> Result<BlockReaderJs, JsValue> {
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let expected =
        DriveBlobContextV2::new(expected_file_id, content_revision_id, expected_generation)
            .map_err(crypto_error)?;
    let content = ContentCommitmentV1::new(
        expected.revision_id,
        manifest_sha256(content_manifest_sha256)?,
    );
    drive_blocks::validate_header(header, expected).map_err(crypto_error)?;
    Ok(BlockReaderJs {
        family: Family::Drive,
        reader: Reader::Blocks(
            drive_blocks::reader(
                &file_key,
                expected,
                sealed_manifest,
                &content,
                byte_count(size, "file size")?,
            )
            .map_err(crypto_error)?,
        ),
    })
}

/// A reader of a Chat attachment whose sealed manifest is the one its
/// descriptor names (`manifestSha256`).
#[wasm_bindgen(js_name = chatMediaBlockReader)]
pub fn chat_media_block_reader(
    attachment_key_base64: &str,
    expected_attachment_id: &str,
    expected_manifest_sha256: &str,
    header: &[u8],
    sealed_manifest: &[u8],
) -> Result<BlockReaderJs, JsValue> {
    let key = decode_canonical_base64(attachment_key_base64, "attachment key")?;
    let expected = ChatMediaObjectContextV1::new(expected_attachment_id).map_err(crypto_error)?;
    chat_media_blocks::validate_header(header, expected).map_err(crypto_error)?;
    Ok(BlockReaderJs {
        family: Family::ChatMedia,
        reader: Reader::Blocks(
            chat_media_blocks::reader(
                &key,
                expected,
                sealed_manifest,
                &manifest_sha256(expected_manifest_sha256)?,
            )
            .map_err(crypto_error)?,
        ),
    })
}

/// A reader of a backup media copy, its key derived from the backup root,
/// whose sealed manifest is the one the backup's index names.
#[wasm_bindgen(js_name = chatBackupMediaBlockReader)]
pub fn chat_backup_media_block_reader(
    backup_root_base64: &str,
    expected_account_incarnation_id: &str,
    expected_backup_incarnation_id: &str,
    expected_media_id: &str,
    expected_manifest_sha256: &str,
    header: &[u8],
    sealed_manifest: &[u8],
) -> Result<BlockReaderJs, JsValue> {
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let context = chat_backup_context(
        expected_account_incarnation_id,
        expected_backup_incarnation_id,
    )?;
    let media_id = media_id(expected_media_id)?;
    let key = chat_backup::derive_media_encryption_key(&root, context, &media_id)
        .map_err(crypto_error)?;
    Ok(BlockReaderJs {
        family: Family::ChatBackupMedia,
        reader: Reader::BackupMedia(
            MediaReader::open(
                key.as_slice(),
                backup_media_context(context, media_id),
                header,
                sealed_manifest,
                &manifest_sha256(expected_manifest_sha256)?,
            )
            .map_err(crypto_error)?,
        ),
    })
}
