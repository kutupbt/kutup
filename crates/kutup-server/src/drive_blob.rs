//! What the server checks of a Drive blob it stores: only what is public.
//! Every blob is in the block format (docs/plans/drive-block-format.md §3,
//! suite 2) and names its revision, which the client chose and the request
//! names too; the server checks the header against the file, the key
//! generation and that revision, and the structure the trailer and the
//! length give: the manifest length fits the block count, and the count fits
//! the length. That catches a broken client early. It can't check the AEAD.

use std::io::{Read, Seek, SeekFrom};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use kutup_crypto::blocks::TRAILER_LEN;
use kutup_crypto::drive_blocks::{
    self, DriveBlobContextV2, DRIVE_BLOCKS, DRIVE_BLOCKS_HEADER_BYTES,
};
use tempfile::NamedTempFile;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The Drive object suite every stored blob is in (`blob_suite` of
/// `drive_files`, `drive_file_versions` and `drive_uploads`): the block format.
pub const BLOCK_SUITE: i16 = 2;

/// A block-format blob being stored, bound to the revision the client chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockBlob {
    pub revision_id: Uuid,
}

impl BlockBlob {
    /// From a request's `revisionId`: a canonical lowercase random UUID.
    pub fn from_revision(revision_id: Option<&str>) -> AppResult<Self> {
        let text = revision_id.ok_or_else(|| AppError::bad_request("revisionId is required"))?;
        // A random (v4) UUID only: the id is public, as an ETag, and a v1 or
        // v7 id would carry a MAC address or a time.
        let id = Uuid::parse_str(text)
            .ok()
            .filter(|id| id.get_version_num() == 4 && id.hyphenated().to_string() == text)
            .ok_or_else(|| AppError::bad_request("invalid revision id"))?;
        Ok(Self { revision_id: id })
    }

    /// The shortest blob: an empty file's.
    pub fn min_len() -> u64 {
        drive_blocks::blob_len(0).expect("an empty blob has a length")
    }

    /// Checks a blob's first bytes against the file, the key generation and
    /// the revision.
    pub fn check_head(self, head: &[u8], file_id: Uuid, generation: u32) -> AppResult<()> {
        let invalid = || AppError::bad_request("invalid Drive file blob");
        let head = head.get(..DRIVE_BLOCKS_HEADER_BYTES).ok_or_else(invalid)?;
        DriveBlobContextV2::new(
            &file_id.hyphenated().to_string(),
            &self.revision_id.hyphenated().to_string(),
            generation,
        )
        .and_then(|context| drive_blocks::validate_header(head, context))
        .map_err(|_| invalid())
    }

    /// Checks a whole blob's structure from its length and its trailer (its
    /// last [`TRAILER_LEN`] bytes).
    pub fn check_tail(total: u64, trailer: &[u8]) -> AppResult<()> {
        let manifest = DRIVE_BLOCKS
            .parse_trailer(trailer)
            .map_err(|_| AppError::bad_request("invalid Drive file blob trailer"))?;
        DRIVE_BLOCKS
            .check_structure(DRIVE_BLOCKS_HEADER_BYTES, total, manifest)
            .map_err(|_| AppError::bad_request("invalid Drive file blob structure"))?;
        Ok(())
    }

    /// Checks a blob held whole in `file` (`size` bytes): its head and its
    /// structure.
    pub fn check_file(
        self,
        file: &NamedTempFile,
        size: u64,
        file_id: Uuid,
        generation: u32,
    ) -> AppResult<()> {
        let invalid = || AppError::bad_request("invalid Drive file blob");
        if size < Self::min_len() {
            return Err(invalid());
        }
        let mut source = std::fs::File::open(file.path()).map_err(|_| invalid())?;
        let mut head = vec![0u8; DRIVE_BLOCKS_HEADER_BYTES];
        source.read_exact(&mut head).map_err(|_| invalid())?;
        self.check_head(&head, file_id, generation)?;
        let mut trailer = [0u8; TRAILER_LEN];
        source
            .seek(SeekFrom::Start(size - TRAILER_LEN as u64))
            .and_then(|_| source.read_exact(&mut trailer))
            .map_err(|_| invalid())?;
        Self::check_tail(size, &trailer)
    }
}

/// Refuses (`409`) a revision id any file, version or open upload already
/// has: a revision names one content, and its id is that content's ETag, so
/// it is unique across `drive_files.content_revision_id`, `drive_file_versions.id` and
/// `drive_uploads.revision_id` together. Each table has its unique key; across the
/// three, every claim of an id takes that id's advisory lock first (held to
/// the end of the transaction that stores it), so two claims of one id can't
/// both find it free.
pub async fn ensure_revision_free(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    revision: Uuid,
    leave_upload: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(revision.to_string())
        .bind(REVISION_ID_LOCK_SEED)
        .execute(&mut **tx)
        .await?;
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM drive_files WHERE content_revision_id = $1)
             OR EXISTS (SELECT 1 FROM drive_file_versions WHERE id = $1)
             OR EXISTS (SELECT 1 FROM drive_uploads
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

/// The advisory-lock seed of revision-id claims (`ensure_revision_free`),
/// apart from the name locks' (`drive_names::lock_place`, seed 0).
const REVISION_ID_LOCK_SEED: i64 = 0x6b72_6576; // "krev"

/// `409 objectMissing`: an uploaded revision's object is not in storage (or
/// not whole), so it can't become a file's content. The upload is lost;
/// the client sends the file again.
pub fn object_missing() -> AppError {
    AppError::conflict("the uploaded revision's object is not in storage")
        .with_details(serde_json::json!({ "code": "objectMissing" }))
}

/// Checks, with a storage HEAD, that an uploaded revision's object is there
/// and as long as its upload said, before a commit makes it current
/// (`409 objectMissing` otherwise): a row must never name content the store
/// does not hold.
pub async fn ensure_object_stored(
    storage: &crate::storage::StorageService,
    path: &str,
    total_bytes: i64,
) -> AppResult<()> {
    match storage.object_len(path).await {
        Ok(Some(len)) if len == total_bytes => Ok(()),
        Ok(found) => {
            tracing::error!(
                path,
                ?found,
                total_bytes,
                "commit: the uploaded object is missing or short"
            );
            Err(object_missing())
        }
        Err(error) => {
            tracing::error!(%error, path, "commit: storage HEAD failed");
            Err(AppError::internal("storage unavailable"))
        }
    }
}

/// `409 revisionConflict`: the metadata is not the file's next revision
/// (exactly the current one + 1, or 1 for a new file).
pub fn revision_conflict() -> AppError {
    AppError::conflict("metadata revision must advance exactly once")
        .with_details(serde_json::json!({ "code": "revisionConflict" }))
}

/// [`revisionConflict`] with the file's metadata as it is now, for a saver
/// that seals on top of it (a version save; docs/api.md).
pub fn revision_conflict_at(metadata_revision: i64, metadata_envelope: Option<&str>) -> AppError {
    let mut details = serde_json::json!({
        "code": "revisionConflict",
        "metadataRevision": metadata_revision,
    });
    if let Some(envelope) = metadata_envelope {
        details["metadataEnvelope"] = serde_json::Value::String(envelope.to_owned());
    }
    AppError::conflict("metadata revision must advance exactly once").with_details(details)
}

/// A whole-buffer upload of a new file (multipart, federated) commits inline
/// (docs/plans/drive-block-format.md §10 slice 3): it names its metadata's
/// revision, which must be 1 (`409` otherwise).
pub fn check_first_metadata_revision(revision: Option<&str>) -> AppResult<()> {
    let text = revision.ok_or_else(|| AppError::bad_request("metadataRevision is required"))?;
    match parse_metadata_revision(text)? {
        1 => Ok(()),
        _ => Err(revision_conflict()),
    }
}

/// A `metadataRevision` field: a positive integer.
pub fn parse_metadata_revision(text: &str) -> AppResult<i64> {
    text.parse::<i64>()
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| AppError::bad_request("invalid metadataRevision"))
}

/// The form field, `Upload-Metadata` key and JSON field naming a
/// block-format revision's sealed content record.
pub const REVISION_CONTENT_FIELD: &str = "revisionContentEnvelope";

/// A revision's sealed `RevisionContent` record
/// (docs/plans/drive-block-format.md §2, §10 slice 3 "History versions"):
/// required with every revision the server stores. Only its public header is
/// checked, against the file, the revision and the key generation that
/// sealed the object, and its one length; the server can't read what it
/// commits to. Returns what to store.
pub fn revision_content_envelope(
    blob: BlockBlob,
    value: Option<&str>,
    file_id: Uuid,
    generation: u32,
) -> AppResult<String> {
    let invalid = || AppError::bad_request("invalid revisionContentEnvelope");
    let text = value.ok_or_else(|| AppError::bad_request("revisionContentEnvelope is required"))?;
    // Bounded before decoding: the envelope has one length.
    if text.len() != kutup_crypto::drive_envelope::REVISION_CONTENT_ENVELOPE_BYTES.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = STANDARD.decode(text).map_err(|_| invalid())?;
    if STANDARD.encode(&bytes) != text {
        return Err(invalid());
    }
    kutup_crypto::revision_content::validate(
        &bytes,
        &file_id.hyphenated().to_string(),
        &blob.revision_id.hyphenated().to_string(),
        generation,
    )
    .map_err(|_| invalid())?;
    Ok(text.to_owned())
}

/// Frees what an upload row holds in storage: an uploaded revision's whole
/// object (its multipart completed), else its multipart's parts.
pub async fn drop_upload_bytes(
    storage: &crate::storage::StorageService,
    path: &str,
    s3_upload_id: &str,
    uploaded: bool,
) -> anyhow::Result<()> {
    if uploaded {
        storage.delete(path).await
    } else {
        storage.abort_multipart(path, s3_upload_id).await
    }
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

    #[test]
    fn a_block_revision_needs_its_own_content_record() {
        use kutup_crypto::revision_content::{seal_revision_content, RevisionContentV1};
        let key = [7u8; 32];
        let file = Uuid::parse_str(FILE).unwrap();
        let revision = Uuid::parse_str(REVISION).unwrap();
        let other = Uuid::new_v4();
        let seal = |revision: Uuid| {
            let content = RevisionContentV1::new(*revision.as_bytes(), [1; 32], 10);
            STANDARD.encode(seal_revision_content(&content, &key, FILE, 2).unwrap())
        };
        let blocks = BlockBlob {
            revision_id: revision,
        };
        let good = seal(revision);
        assert_eq!(
            revision_content_envelope(blocks, Some(&good), file, 2).unwrap(),
            good
        );
        // Missing; another revision, generation or file; not base64.
        assert!(revision_content_envelope(blocks, None, file, 2).is_err());
        assert!(revision_content_envelope(blocks, Some(&seal(other)), file, 2).is_err());
        assert!(revision_content_envelope(blocks, Some(&good), file, 1).is_err());
        assert!(revision_content_envelope(blocks, Some(&good), other, 2).is_err());
        assert!(revision_content_envelope(blocks, Some(&good[1..]), file, 2).is_err());
    }

    fn blob(size: usize) -> Vec<u8> {
        let context = DriveBlobContextV2::new(FILE, REVISION, 3).unwrap();
        drive_blocks::seal_file(
            &vec![7; size],
            &[1; 32],
            context,
            &SigningKey::from_seed(Suite::V1, &[2; 32]),
            kutup_crypto::blocks::SignerIdentity {
                account_id: [3; 16],
                incarnation_id: [4; 32],
            },
        )
        .unwrap()
        .bytes
    }

    fn file_of(bytes: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn blocks() -> BlockBlob {
        BlockBlob::from_revision(Some(REVISION)).unwrap()
    }

    #[test]
    fn a_revision_id_names_the_block_format() {
        assert!(BlockBlob::from_revision(None).is_err());
        assert_eq!(
            blocks(),
            BlockBlob {
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
            assert!(BlockBlob::from_revision(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_new_files_inline_commit_names_revision_one() {
        check_first_metadata_revision(Some("1")).unwrap();
        assert_eq!(
            check_first_metadata_revision(None).unwrap_err().status,
            axum::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            check_first_metadata_revision(Some("2")).unwrap_err().status,
            axum::http::StatusCode::CONFLICT
        );
        for bad in ["0", "-1", "x", ""] {
            assert_eq!(
                check_first_metadata_revision(Some(bad)).unwrap_err().status,
                axum::http::StatusCode::BAD_REQUEST,
                "{bad}"
            );
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
                BlockBlob::from_revision(Some("33333333-3333-4333-8333-333333333333")).unwrap();
            assert!(other.check_head(&bytes, file, 3).is_err());
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
