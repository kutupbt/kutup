//! What the server checks of a Drive blob it stores: only what is public.
//! A blob in the block format (docs/plans/drive-block-format.md §3, suite 2)
//! names its revision, which the client chose and the request names too; the
//! server checks the header against the file, the key generation and that
//! revision, and the structure the trailer and the length give: the manifest
//! length fits the block count, and the count fits the length. That catches a
//! broken client early. It can't check the AEAD. A blob of the streaming
//! format (suite 1) has its header checked, as before; it goes with the wipe
//! (slice 7).

use std::io::{Read, Seek, SeekFrom};

use kutup_crypto::blocks::TRAILER_LEN;
use kutup_crypto::drive_blocks::{
    self, DriveBlobContextV2, DRIVE_BLOCKS, DRIVE_BLOCKS_HEADER_BYTES,
};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1, FILE_BLOB_HEADER_BYTES};
use tempfile::NamedTempFile;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The format of a blob being stored, from what the request names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobFormat {
    /// Suite 1: secretstream, no revision in the blob.
    Stream,
    /// Suite 2: blocks, bound to the revision the client chose.
    Blocks { revision_id: Uuid },
}

impl BlobFormat {
    /// From a request's optional `revisionId`: a canonical lowercase UUID
    /// names a block-format blob; none, a streaming one.
    pub fn from_revision(revision_id: Option<&str>) -> AppResult<Self> {
        match revision_id {
            None => Ok(Self::Stream),
            Some(text) => {
                // A random (v4) UUID only: the id is public, as an ETag, and
                // a v1 or v7 id would carry a MAC address or a time.
                let id = Uuid::parse_str(text)
                    .ok()
                    .filter(|id| id.get_version_num() == 4 && id.hyphenated().to_string() == text)
                    .ok_or_else(|| AppError::bad_request("invalid revision id"))?;
                Ok(Self::Blocks { revision_id: id })
            }
        }
    }

    /// The revision the stored content will be: the client's for blocks,
    /// else a new one.
    pub fn revision_id(self) -> Uuid {
        match self {
            Self::Blocks { revision_id } => revision_id,
            Self::Stream => Uuid::new_v4(),
        }
    }

    /// The Drive object suite, as the `uploads` row keeps it.
    pub fn suite(self) -> i16 {
        match self {
            Self::Stream => 1,
            Self::Blocks { .. } => 2,
        }
    }

    pub fn from_suite(suite: i16, revision_id: Uuid) -> AppResult<Self> {
        match suite {
            1 => Ok(Self::Stream),
            2 => Ok(Self::Blocks { revision_id }),
            _ => Err(AppError::internal("unknown Drive blob suite")),
        }
    }

    /// The shortest blob of this format: an empty file's.
    pub fn min_len(self) -> u64 {
        match self {
            Self::Stream => {
                (drive_object::FILE_BLOB_PREFIX_BYTES + kutup_crypto::stream::ABYTES) as u64
            }
            Self::Blocks { .. } => drive_blocks::blob_len(0).expect("an empty blob has a length"),
        }
    }

    /// The bytes [`Self::check_head`] needs.
    pub fn head_len(self) -> usize {
        match self {
            Self::Stream => FILE_BLOB_HEADER_BYTES,
            Self::Blocks { .. } => DRIVE_BLOCKS_HEADER_BYTES,
        }
    }

    /// Checks a blob's first bytes against the file and key generation (and,
    /// for blocks, the revision).
    pub fn check_head(self, head: &[u8], file_id: Uuid, generation: u32) -> AppResult<()> {
        let invalid = || AppError::bad_request("invalid Drive file blob");
        let head = head.get(..self.head_len()).ok_or_else(invalid)?;
        let file = file_id.hyphenated().to_string();
        let checked = match self {
            Self::Stream => DriveFileBlobContextV1::new(&file, generation)
                .and_then(|context| drive_object::validate_file_blob_header(head, context)),
            Self::Blocks { revision_id } => {
                DriveBlobContextV2::new(&file, &revision_id.hyphenated().to_string(), generation)
                    .and_then(|context| drive_blocks::validate_header(head, context))
            }
        };
        checked.map_err(|_| invalid())
    }

    /// Checks a whole blob's structure from its length and its trailer (its
    /// last [`TRAILER_LEN`] bytes); nothing to check for the streaming
    /// format.
    pub fn check_tail(self, total: u64, trailer: &[u8]) -> AppResult<()> {
        if let Self::Blocks { .. } = self {
            let manifest = DRIVE_BLOCKS
                .parse_trailer(trailer)
                .map_err(|_| AppError::bad_request("invalid Drive file blob trailer"))?;
            DRIVE_BLOCKS
                .check_structure(DRIVE_BLOCKS_HEADER_BYTES, total, manifest)
                .map_err(|_| AppError::bad_request("invalid Drive file blob structure"))?;
        }
        Ok(())
    }

    /// Checks a blob held whole in `file` (`size` bytes): its head and, for
    /// blocks, its structure.
    pub fn check_file(
        self,
        file: &NamedTempFile,
        size: u64,
        file_id: Uuid,
        generation: u32,
    ) -> AppResult<()> {
        let invalid = || AppError::bad_request("invalid Drive file blob");
        if size < self.min_len() {
            return Err(invalid());
        }
        let mut source = std::fs::File::open(file.path()).map_err(|_| invalid())?;
        let mut head = vec![0u8; self.head_len()];
        source.read_exact(&mut head).map_err(|_| invalid())?;
        self.check_head(&head, file_id, generation)?;
        let mut trailer = [0u8; TRAILER_LEN];
        source
            .seek(SeekFrom::Start(size - TRAILER_LEN as u64))
            .and_then(|_| source.read_exact(&mut trailer))
            .map_err(|_| invalid())?;
        self.check_tail(size, &trailer)
    }
}

/// Refuses (`409`) a revision id the file or an open upload already has: a
/// revision names one content, and its id is that content's ETag. The unique
/// keys (`files.content_revision_id`, `file_versions.id`) back this up.
pub async fn ensure_revision_free(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    revision: Uuid,
    leave_upload: Option<Uuid>,
) -> AppResult<()> {
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM files WHERE content_revision_id = $1)
             OR EXISTS (SELECT 1 FROM file_versions WHERE id = $1)
             OR EXISTS (SELECT 1 FROM uploads
                        WHERE revision_id = $1 AND id IS DISTINCT FROM $2)",
    )
    .bind(revision)
    .bind(leave_upload)
    .fetch_one(&mut **tx)
    .await?;
    if taken {
        return Err(AppError::conflict("revision id already in use")
            .with_details(serde_json::json!({ "code": "revisionTaken" })));
    }
    Ok(())
}

/// Counts a streamed body against a byte limit (a site setting), so a body
/// past it is refused as it arrives, before it is all stored.
pub struct BodyBudget {
    limit: u64,
    seen: u64,
}

impl BodyBudget {
    pub fn new(limit: i64) -> Self {
        Self {
            limit: u64::try_from(limit).unwrap_or(0),
            seen: 0,
        }
    }

    /// Adds `len` bytes; `413` once past the limit.
    pub fn take(&mut self, len: usize) -> AppResult<()> {
        self.seen = self.seen.saturating_add(len as u64);
        if self.seen > self.limit {
            return Err(AppError::payload_too_large(format!(
                "larger than this server's limit of {} bytes",
                self.limit
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use kutup_crypto::primitives::{SigningKey, Suite};

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const REVISION: &str = "22222222-2222-4222-8222-222222222222";

    fn blob(size: usize) -> Vec<u8> {
        let context = DriveBlobContextV2::new(FILE, REVISION, 3).unwrap();
        drive_blocks::seal_file(
            &vec![7; size],
            &[1; 32],
            context,
            &SigningKey::from_seed(Suite::V1, &[2; 32]),
            [3; 16],
        )
        .unwrap()
        .bytes
    }

    fn file_of(bytes: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn blocks() -> BlobFormat {
        BlobFormat::from_revision(Some(REVISION)).unwrap()
    }

    #[test]
    fn a_revision_id_names_the_block_format() {
        assert_eq!(BlobFormat::from_revision(None).unwrap(), BlobFormat::Stream);
        assert_eq!(
            blocks(),
            BlobFormat::Blocks {
                revision_id: Uuid::parse_str(REVISION).unwrap()
            }
        );
        for bad in [
            "22222222-2222-4222-8222-22222222222",
            "22222222-2222-4222-8222-22222222222A",
            "{22222222-2222-4222-8222-222222222222}",
            "00000000-0000-0000-0000-000000000000",
            // Not random: a v1 (time and MAC address) and a v7 (time).
            "22222222-2222-1222-8222-222222222222",
            "01890000-0000-7000-8000-000000000000",
            "",
        ] {
            assert!(BlobFormat::from_revision(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_block_blob_is_checked_by_header_and_structure() {
        let file = Uuid::parse_str(FILE).unwrap();
        for size in [0, 1, 70_000] {
            let bytes = blob(size);
            let total = bytes.len() as u64;
            blocks()
                .check_file(&file_of(&bytes), total, file, 3)
                .unwrap();
            // Another file, generation or revision.
            assert!(blocks()
                .check_head(&bytes, Uuid::from_bytes([9; 16]), 3)
                .is_err());
            assert!(blocks().check_head(&bytes, file, 4).is_err());
            let other =
                BlobFormat::from_revision(Some("33333333-3333-4333-8333-333333333333")).unwrap();
            assert!(other.check_head(&bytes, file, 3).is_err());
            // A streaming header is not a block one.
            assert!(BlobFormat::Stream.check_head(&bytes, file, 3).is_err());
            // A block's worth more, or a broken trailer. (A few bytes more
            // or less within the last block is a shape the server can't
            // tell from another size.)
            let trailer = &bytes[bytes.len() - TRAILER_LEN..];
            let mut longer = bytes.clone();
            longer.extend_from_slice(&[0; 5_000_000]);
            longer.extend_from_slice(trailer);
            assert!(blocks()
                .check_file(&file_of(&longer), longer.len() as u64, file, 3)
                .is_err());
            let mut broken = bytes.clone();
            let last = broken.len() - 1;
            broken[last] ^= 1;
            assert!(blocks()
                .check_file(&file_of(&broken), total, file, 3)
                .is_err());
            // Shorter than an empty blob.
            assert!(blocks()
                .check_file(&file_of(&bytes[..10]), 10, file, 3)
                .is_err());
        }
    }
}
