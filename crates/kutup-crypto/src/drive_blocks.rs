//! Drive blobs in the block format (docs/plans/drive-block-format.md §2):
//! Drive object suite 2 (`DRIVE_BLOCKS_SUITE`; `DriveObjectSuiteId` gains it
//! when clients switch, so nothing parsing suite 1 accepts it before). Every original, version and editor
//! snapshot is a revision with its own id, chosen by the client before it
//! seals, so blocks can't move between versions, and the manifest is signed
//! by the uploader's Drive signing key.
//!
//! The header (48 bytes, in clear) is the keys' HKDF info and part of every
//! block's and the manifest's associated data:
//!
//! ```text
//! magic "KUTPDB3\0" ‖ u16 suite 2 ‖ u8 purpose 1 ‖ u8 0
//! ‖ u32 file-key generation ‖ 16-byte file id ‖ 16-byte revision id
//! ```

use zeroize::Zeroizing;

use crate::blocks::{self, BlockFamily, BlockReader, BlockSealer, Manifest, SealedObject};
use crate::drive_object::{parse_canonical_uuid, DriveObjectPurpose};
use crate::error::{CryptoError, Result};
use crate::file_metadata::ContentCommitmentV1;
use crate::primitives::SigningKey;

const MAGIC: &[u8; 8] = b"KUTPDB3\0";
pub const DRIVE_BLOCKS_HEADER_BYTES: usize = 48;
/// The Drive object suite of the block format.
pub const DRIVE_BLOCKS_SUITE: u16 = 2;
const KEY_LEN: usize = 32;

/// The Drive family of the block construction.
pub static DRIVE_BLOCKS: BlockFamily = BlockFamily {
    block_key_label: crate::labels::DRIVE_OBJECT_BLOCKS_BLOCK_KEY_V1,
    nonce_key_label: crate::labels::DRIVE_OBJECT_BLOCKS_NONCE_KEY_V1,
    manifest_key_label: crate::labels::DRIVE_OBJECT_BLOCKS_MANIFEST_KEY_V1,
    signature_domain: crate::labels::DRIVE_BLOCK_MANIFEST_V1,
    trailer_magic: b"KUTPDBM\0",
    signed: true,
};

/// What a Drive blob is bound to: the file-key generation, the file and the
/// revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriveBlobContextV2 {
    pub generation: u32,
    pub file_id: [u8; 16],
    pub revision_id: [u8; 16],
}

impl DriveBlobContextV2 {
    pub fn new(file_id: &str, revision_id: &str, generation: u32) -> Result<Self> {
        if generation == 0 {
            return Err(CryptoError::InvalidInput(
                "Drive file-blob key generation must be non-zero".into(),
            ));
        }
        Ok(Self {
            generation,
            file_id: parse_canonical_uuid(file_id, "file")?,
            revision_id: parse_canonical_uuid(revision_id, "revision")?,
        })
    }
}

pub fn header(context: DriveBlobContextV2) -> [u8; DRIVE_BLOCKS_HEADER_BYTES] {
    let mut header = [0u8; DRIVE_BLOCKS_HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&DRIVE_BLOCKS_SUITE.to_be_bytes());
    header[10] = DriveObjectPurpose::FileBlob.as_u8();
    header[12..16].copy_from_slice(&context.generation.to_be_bytes());
    header[16..32].copy_from_slice(&context.file_id);
    header[32..48].copy_from_slice(&context.revision_id);
    header
}

/// The context a header names, if it is a well-formed suite-2 file blob
/// header.
pub fn inspect_header(header: &[u8]) -> Result<DriveBlobContextV2> {
    if header.len() != DRIVE_BLOCKS_HEADER_BYTES || header.get(..8) != Some(MAGIC) {
        return Err(CryptoError::InvalidInput(
            "not a Drive block-format header".into(),
        ));
    }
    if u16::from_be_bytes([header[8], header[9]]) != DRIVE_BLOCKS_SUITE
        || DriveObjectPurpose::try_from(header[10])? != DriveObjectPurpose::FileBlob
        || header[11] != 0
    {
        return Err(CryptoError::InvalidInput(
            "Drive block-format header names another suite or purpose".into(),
        ));
    }
    let generation = u32::from_be_bytes(header[12..16].try_into().expect("four bytes"));
    if generation == 0 {
        return Err(CryptoError::InvalidInput(
            "Drive file-blob key generation must be non-zero".into(),
        ));
    }
    Ok(DriveBlobContextV2 {
        generation,
        file_id: header[16..32].try_into().expect("sixteen bytes"),
        revision_id: header[32..48].try_into().expect("sixteen bytes"),
    })
}

/// Checks a header against the file, generation and revision expected.
pub fn validate_header(header: &[u8], expected: DriveBlobContextV2) -> Result<()> {
    if inspect_header(header)? != expected {
        return Err(CryptoError::InvalidInput(
            "Drive blob is another file's, revision's or generation's".into(),
        ));
    }
    Ok(())
}

fn file_key(key: &[u8]) -> Result<&[u8]> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }
    Ok(key)
}

/// A sealer for `size` plaintext bytes; the header goes first, then each
/// block, then `finish` with the uploader's key and account.
pub fn sealer(
    file_key_bytes: &[u8],
    context: DriveBlobContextV2,
    size: u64,
) -> Result<BlockSealer<'static>> {
    BlockSealer::new(
        &DRIVE_BLOCKS,
        file_key(file_key_bytes)?,
        &header(context),
        size,
    )
}

/// The reader of a blob whose header was checked against `context`: its
/// sealed manifest must be the one `content` commits to (the file's sealed
/// metadata, or a version's record), for `context`'s revision, and fix
/// `size` plaintext bytes (what the metadata says), all checked before any
/// block opens.
pub fn reader(
    file_key_bytes: &[u8],
    context: DriveBlobContextV2,
    sealed_manifest: &[u8],
    content: &ContentCommitmentV1,
    size: u64,
) -> Result<BlockReader<'static>> {
    let digest = blocks::manifest_digest(sealed_manifest);
    content.check(&context.revision_id, &digest)?;
    let reader = BlockReader::open(
        &DRIVE_BLOCKS,
        file_key(file_key_bytes)?,
        &header(context),
        sealed_manifest,
        &digest,
    )?;
    check_size(reader.manifest(), size)?;
    Ok(reader)
}

fn check_size(manifest: &Manifest, size: u64) -> Result<()> {
    if manifest.size != size {
        return Err(CryptoError::InvalidInput(
            "the Drive blob's size is not the one its metadata names".into(),
        ));
    }
    Ok(())
}

/// The whole blob's length for `size` plaintext bytes.
pub fn blob_len(size: u64) -> Result<u64> {
    DRIVE_BLOCKS.object_len(DRIVE_BLOCKS_HEADER_BYTES, size)
}

/// Seals a whole file (snapshots, versions, small files), signed by the
/// uploader; with the digest its metadata commits to.
pub fn seal_file(
    plaintext: &[u8],
    file_key_bytes: &[u8],
    context: DriveBlobContextV2,
    signer: &SigningKey,
    account_id: [u8; 16],
) -> Result<SealedObject> {
    blocks::seal_object(
        &DRIVE_BLOCKS,
        file_key(file_key_bytes)?,
        &header(context),
        plaintext,
        Some((signer, account_id)),
    )
}

/// Opens a whole file sealed for `expected` whose sealed manifest is the one
/// `content` commits to, of `size` bytes (see [`reader`]): the plaintext and
/// the manifest (to check its signer against pins).
pub fn open_file(
    object: &[u8],
    file_key_bytes: &[u8],
    expected: DriveBlobContextV2,
    content: &ContentCommitmentV1,
    size: u64,
) -> Result<(Zeroizing<Vec<u8>>, Manifest)> {
    let prefix = object
        .get(..DRIVE_BLOCKS_HEADER_BYTES)
        .ok_or(CryptoError::TooShort)?;
    validate_header(prefix, expected)?;
    let digest = blocks::trailer_manifest_digest(object, DRIVE_BLOCKS_HEADER_BYTES, &DRIVE_BLOCKS)?;
    content.check(&expected.revision_id, &digest)?;
    let (plaintext, manifest) = blocks::open_object(
        &DRIVE_BLOCKS,
        file_key(file_key_bytes)?,
        DRIVE_BLOCKS_HEADER_BYTES,
        object,
        &digest,
    )?;
    check_size(&manifest, size)?;
    Ok((plaintext, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::{block_offset, BLOCK_OVERHEAD, BLOCK_SIZE, TRAILER_LEN};
    use crate::primitives::Suite;

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const REVISION: &str = "22222222-2222-4222-8222-222222222222";
    const KEY: [u8; 32] = [7; 32];
    const ACCOUNT: [u8; 16] = [3; 16];

    fn context() -> DriveBlobContextV2 {
        DriveBlobContextV2::new(FILE, REVISION, 4).unwrap()
    }

    fn signer() -> SigningKey {
        SigningKey::from_seed(Suite::V1, &[9; 32])
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn seal(plaintext: &[u8]) -> SealedObject {
        seal_file(plaintext, &KEY, context(), &signer(), ACCOUNT).unwrap()
    }

    /// What the file's metadata commits to for `sealed`, at `context`'s
    /// revision.
    fn commitment(context: DriveBlobContextV2, sealed: &SealedObject) -> ContentCommitmentV1 {
        ContentCommitmentV1::new(context.revision_id, sealed.manifest_sha256)
    }

    fn open(object: &[u8], content: &ContentCommitmentV1, size: usize) -> Result<Vec<u8>> {
        open_file(object, &KEY, context(), content, size as u64)
            .map(|(plaintext, _)| plaintext.to_vec())
    }

    #[test]
    fn every_size_round_trips_at_its_exact_length() {
        for size in [
            0,
            1,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            2 * BLOCK_SIZE + 17,
        ] {
            let plaintext = pattern(size);
            let sealed = seal(&plaintext);
            let object = &sealed.bytes;
            assert_eq!(
                object.len() as u64,
                blob_len(size as u64).unwrap(),
                "{size}"
            );
            let content = commitment(context(), &sealed);
            let (opened, manifest) =
                open_file(object, &KEY, context(), &content, size as u64).unwrap();
            assert_eq!(*opened, plaintext, "{size}");
            assert_eq!(manifest.size, size as u64);
            assert_eq!(
                manifest.count,
                (size as u64).div_ceil(BLOCK_SIZE as u64).max(1)
            );
            manifest.verify_signer(&signer().verifying_key()).unwrap();
            assert_eq!(manifest.signer.as_ref().unwrap().account_id, ACCOUNT);
            // The digest a metadata commits to is the sealed manifest's.
            assert_eq!(
                sealed_digest(object),
                crate::primitives::hash(Suite::V1, sealed_manifest(object)).to_array()
            );
            assert_eq!(sealed_digest(object), sealed.manifest_sha256);
            // The metadata's size must be the manifest's.
            assert!(open(object, &content, size + 1).is_err());
        }
    }

    #[test]
    fn blocks_are_deterministic_and_the_manifest_is_not() {
        let plaintext = pattern(BLOCK_SIZE + 5);
        let (a, b) = (seal(&plaintext).bytes, seal(&plaintext).bytes);
        let blocks_end = block_offset(DRIVE_BLOCKS_HEADER_BYTES, 1) as usize + 5 + BLOCK_OVERHEAD;
        // A resumed upload re-seals the same bytes.
        assert_eq!(a[..blocks_end], b[..blocks_end]);
        // A changed block gets a new nonce.
        let mut changed = plaintext.clone();
        changed[0] ^= 1;
        let c = seal(&changed).bytes;
        assert_ne!(
            a[DRIVE_BLOCKS_HEADER_BYTES..DRIVE_BLOCKS_HEADER_BYTES + 24],
            c[DRIVE_BLOCKS_HEADER_BYTES..DRIVE_BLOCKS_HEADER_BYTES + 24]
        );
    }

    fn sealed_manifest(object: &[u8]) -> &[u8] {
        let len = DRIVE_BLOCKS
            .parse_trailer(&object[object.len() - TRAILER_LEN..])
            .unwrap();
        &object[object.len() - TRAILER_LEN - len..object.len() - TRAILER_LEN]
    }

    fn sealed_digest(object: &[u8]) -> [u8; 32] {
        blocks::object_manifest_digest(object, DRIVE_BLOCKS_HEADER_BYTES, &DRIVE_BLOCKS).unwrap()
    }

    /// docs/plans/drive-block-format.md §8, one row each.
    #[test]
    fn the_attacks_in_the_plan_fail() {
        let size = 2 * BLOCK_SIZE + 17;
        let plaintext = pattern(size);
        let sealed = seal(&plaintext);
        let object = &sealed.bytes;
        let content = commitment(context(), &sealed);
        let block = |i: u64| {
            let start = block_offset(DRIVE_BLOCKS_HEADER_BYTES, i) as usize;
            let len = if i == 2 { 17 } else { BLOCK_SIZE } + BLOCK_OVERHEAD;
            start..start + len
        };
        let reader = reader(
            &KEY,
            context(),
            sealed_manifest(object),
            &content,
            size as u64,
        )
        .unwrap();
        // Reorder or duplicate: a block at another index.
        assert!(reader.open_block(1, &object[block(0)]).is_err());
        assert!(reader.open_block(0, &object[block(0)]).is_ok());
        // Splice from another file, another revision, another generation.
        for (file, revision, generation) in [
            ("33333333-3333-4333-8333-333333333333", REVISION, 4),
            (FILE, "44444444-4444-4444-8444-444444444444", 4),
            (FILE, REVISION, 5),
        ] {
            let other = DriveBlobContextV2::new(file, revision, generation).unwrap();
            assert!(open_file(object, &KEY, other, &content, size as u64).is_err());
            let foreign = seal_file(&plaintext, &KEY, other, &signer(), ACCOUNT).unwrap();
            assert!(
                reader.open_block(0, &foreign.bytes[block(0)]).is_err(),
                "{file} {revision}"
            );
        }
        // Truncate: drop the last block (and so the manifest no longer fits).
        let mut truncated = object[..block(2).start].to_vec();
        truncated.extend_from_slice(&object[block(2).end..]);
        assert!(open(&truncated, &content, size).is_err());
        // A key holder's truncation: a valid object of the first n − 1 blocks,
        // sealed and signed anew. Only the metadata's commitment refuses it.
        let shorter = seal(&plaintext[..2 * BLOCK_SIZE]);
        assert!(open(&shorter.bytes, &content, size).is_err());
        assert!(open(&shorter.bytes, &content, 2 * BLOCK_SIZE).is_err());
        assert!(open(
            &shorter.bytes,
            &commitment(context(), &shorter),
            2 * BLOCK_SIZE
        )
        .is_ok());
        // Extend: a block more before the manifest, or bytes after the trailer.
        let mut extended = object[..block(2).end].to_vec();
        extended.extend_from_slice(&object[block(1)]);
        extended.extend_from_slice(&object[block(2).end..]);
        assert!(open(&extended, &content, size).is_err());
        let mut appended = object.clone();
        appended.push(0);
        assert!(open(&appended, &content, size).is_err());
        // Swap the manifest for another revision's.
        let other =
            DriveBlobContextV2::new(FILE, "55555555-5555-4555-8555-555555555555", 4).unwrap();
        let foreign = seal_file(&plaintext, &KEY, other, &signer(), ACCOUNT).unwrap();
        let mut swapped = object[..block(2).end].to_vec();
        swapped.extend_from_slice(&foreign.bytes[block(2).end..]);
        assert!(open(&swapped, &content, size).is_err());
        // Any flipped byte: every header byte, a block, the manifest, the
        // trailer.
        for at in (0..DRIVE_BLOCKS_HEADER_BYTES).chain([
            block(1).start + 30,
            block(2).end + 5,
            object.len() - 1,
        ]) {
            let mut flipped = object.clone();
            flipped[at] ^= 1;
            assert!(open(&flipped, &content, size).is_err(), "byte {at}");
        }
        // Another holder of the file key: it can seal, not sign as you.
        let forger = SigningKey::from_seed(Suite::V1, &[10; 32]);
        let forged = seal_file(&plaintext, &KEY, context(), &forger, ACCOUNT).unwrap();
        let (_, manifest) = open_file(
            &forged.bytes,
            &KEY,
            context(),
            &commitment(context(), &forged),
            size as u64,
        )
        .unwrap();
        assert!(manifest.verify_signer(&signer().verifying_key()).is_err());
        // A wrong key opens nothing.
        assert!(open_file(object, &[8; 32], context(), &content, size as u64).is_err());
    }

    /// The server hands back an older revision of the file: its header names
    /// the older revision, and its manifest is not the one the current
    /// metadata commits to, so either check refuses it.
    #[test]
    fn an_older_revision_is_refused_under_newer_metadata() {
        let old = DriveBlobContextV2::new(FILE, "88888888-8888-4888-8888-888888888888", 4).unwrap();
        let old_sealed = seal_file(&pattern(100), &KEY, old, &signer(), ACCOUNT).unwrap();
        let new_sealed = seal(&pattern(100));
        let current = commitment(context(), &new_sealed);
        // Read as the current revision: the header names another one.
        assert!(open(&old_sealed.bytes, &current, 100).is_err());
        // Read as what its own header names: the metadata names another
        // revision and another manifest.
        assert!(open_file(&old_sealed.bytes, &KEY, old, &current, 100).is_err());
        assert!(reader(&KEY, old, sealed_manifest(&old_sealed.bytes), &current, 100).is_err());
        assert!(open(&new_sealed.bytes, &current, 100).is_ok());
    }

    #[test]
    fn the_sealer_takes_each_block_once_and_whole() {
        let mut sealer = sealer(&KEY, context(), BLOCK_SIZE as u64 + 3).unwrap();
        assert!(sealer.seal_next(&[0; 3]).is_err(), "a short first block");
        sealer.seal_next(&pattern(BLOCK_SIZE)).unwrap();
        assert!(sealer.seal_next(&[0; 4]).is_err(), "a long last block");
        sealer.seal_next(&[0; 3]).unwrap();
        assert!(sealer.seal_next(&[]).is_err(), "a block past the end");
        let early = super::sealer(&KEY, context(), 5).unwrap();
        assert!(
            early.finish(Some((&signer(), ACCOUNT))).is_err(),
            "a manifest before its blocks"
        );
        let mut unsigned = super::sealer(&KEY, context(), 0).unwrap();
        unsigned.seal_next(&[]).unwrap();
        assert!(unsigned.finish(None).is_err(), "Drive manifests are signed");
    }

    #[test]
    fn the_structure_check_counts_blocks_from_lengths() {
        for size in [0u64, 1, BLOCK_SIZE as u64, 3 * BLOCK_SIZE as u64 + 9] {
            let count = crate::blocks::block_count(size).unwrap();
            let total = blob_len(size).unwrap();
            let manifest = DRIVE_BLOCKS.sealed_manifest_len(count).unwrap();
            assert_eq!(
                DRIVE_BLOCKS
                    .check_structure(DRIVE_BLOCKS_HEADER_BYTES, total, manifest)
                    .unwrap(),
                count
            );
            // The server learns the size from the length (the body less n
            // overheads) but can check only the shape: a last block between
            // empty and full fits, one outside does not.
            let last = size - (count - 1) * BLOCK_SIZE as u64;
            let room = BLOCK_SIZE as u64 - last;
            let fits =
                |total| DRIVE_BLOCKS.check_structure(DRIVE_BLOCKS_HEADER_BYTES, total, manifest);
            assert_eq!(fits(total + room).unwrap(), count);
            assert!(fits(total + room + 1).is_err());
            assert_eq!(fits(total - last).unwrap(), count);
            assert!(fits(total - last - 1).is_err());
            assert!(DRIVE_BLOCKS
                .check_structure(DRIVE_BLOCKS_HEADER_BYTES, total, manifest + 32)
                .is_err());
        }
        assert!(DRIVE_BLOCKS
            .parse_trailer(&[0, 0, 0, 1, b'K', b'U', b'T', b'P', b'D', b'B', b'M', 0])
            .is_err());
        assert!(DRIVE_BLOCKS.parse_trailer(&[0u8; 12]).is_err());
    }

    #[test]
    fn headers_name_what_they_bind() {
        let bytes = header(context());
        assert_eq!(inspect_header(&bytes).unwrap(), context());
        assert!(DriveBlobContextV2::new(FILE, REVISION, 0).is_err());
        assert!(DriveBlobContextV2::new(FILE, "not-a-uuid", 1).is_err());
        let mut reserved = bytes;
        reserved[11] = 1;
        assert!(inspect_header(&reserved).is_err());
        let mut suite_one = bytes;
        suite_one[9] = 1;
        assert!(inspect_header(&suite_one).is_err());
    }
}
