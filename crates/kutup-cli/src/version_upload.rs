//! A new version of a file over tus (docs/api.md, "POST /api/uploads with
//! versionOf"), as Proton Drive's revisions: resumable at any size, in the
//! block format (docs/plans/drive-block-format.md §2). The upload names the
//! revision it is (`revisionId`, also the version's and the upload's id) and
//! carries the content's hash in its folder; once its last part lands, the
//! client commits it with the file's next metadata, which commits to the
//! revision and its manifest's digest
//! (`POST /api/files/{id}/revisions/{revisionId}/commit`, `revisions.rs`).
//!
//! A local file's upload keeps a resume record in the same store as a new
//! file's (keyed `version\n{file id}\n{path}`): the revision, the content's
//! SHA-256 and, once made, the sealed tail, so a run cut short goes on from
//! whatever offset the server holds, sealing again from block 0 (synthetic
//! nonces give the same bytes), and an upload whose bytes all arrived but
//! whose commit did not is committed. The server allows one open version
//! upload per file: one of ours with no record, idle longer than the
//! request's `crashed_after_secs`, was left by a crash and is cancelled and
//! opened again; one still moving (another device of the account) or
//! someone else's is [`Landed::Busy`]: wait and try again, never treat it as
//! a conflict.
//!
//! A conflict, when the upload opens or when it commits (the file holds
//! another version than `basedOn`, its key changed, its metadata moved on
//! twice), comes back as [`Landed::Conflict`]: the caller decides (a sync
//! keeps both sides), nothing retries blindly.

use std::fs::File as LocalFile;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use indicatif::ProgressBar;

use crate::api::tus::{Patched, VersionUploadMeta};
use crate::api::{ApiError, Client, File};
use crate::revisions::{Base, CommitUpload, Commits, Draft};
use crate::session::{ResumeState, Store};
use crate::transfer::{
    BlockSource, ChangedWhileUploading, KeptTail, NotTheSameFile, UploadSigner, PATCH_BYTES,
};
use crate::uploader::{is_permanent, make_bar, mtime_parts, now_unix, Progress};
use kutup_crypto::drive_blocks::DriveBlobContextV2;

/// A vault save is one small part: an open upload of ours idle this long
/// was left by a crash, not by another device still saving.
pub(crate) const VAULT_CRASHED_AFTER_SECS: i64 = 120;

/// A Drive file's parts are two 4 MiB blocks each, and on a slow link one
/// can take minutes: only an upload of ours idle this long is taken as
/// abandoned.
pub(crate) const FILE_CRASHED_AFTER_SECS: i64 = 3600;

/// The tus calls an upload makes, and its commit.
pub(crate) trait VersionTus: Commits {
    /// Opens the upload; returns its id (the version's).
    fn create(&self, total_bytes: i64, meta: &VersionUploadMeta) -> Result<String>;
    /// `(offset, length)` of an open upload; `None` once it is gone.
    fn head(&self, upload_id: &str) -> Result<Option<(i64, i64)>>;
    fn patch(&self, upload_id: &str, offset: i64, body: Vec<u8>) -> Result<Patched>;
    fn delete(&self, upload_id: &str) -> Result<()>;
    /// Whether the file holds version `version_id` (an upload committed
    /// while its answer was lost).
    fn has_version(&self, file_id: &str, version_id: &str) -> Result<bool>;
}

impl VersionTus for Client {
    fn create(&self, total_bytes: i64, meta: &VersionUploadMeta) -> Result<String> {
        self.tus_create_version(total_bytes, meta)
    }
    fn head(&self, upload_id: &str) -> Result<Option<(i64, i64)>> {
        self.tus_head(upload_id)
    }
    fn patch(&self, upload_id: &str, offset: i64, body: Vec<u8>) -> Result<Patched> {
        self.tus_patch_landed(upload_id, offset, body)
    }
    fn delete(&self, upload_id: &str) -> Result<()> {
        self.tus_delete(upload_id)
    }
    fn has_version(&self, file_id: &str, version_id: &str) -> Result<bool> {
        Ok(self
            .list_versions(file_id)?
            .iter()
            .any(|v| v.id == version_id))
    }
}

/// Where resume records are kept.
pub(crate) trait ResumeRecords {
    fn get(&self, key: &str) -> Result<Option<ResumeState>>;
    fn save(&self, key: &str, state: &ResumeState) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

impl ResumeRecords for Store {
    fn get(&self, key: &str) -> Result<Option<ResumeState>> {
        self.get_resume(key)
    }
    fn save(&self, key: &str, state: &ResumeState) -> Result<()> {
        self.save_resume(key, state)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.delete_resume(key)
    }
}

/// No records: for content in memory, which is never resumed.
pub(crate) struct NoRecords;

impl ResumeRecords for NoRecords {
    fn get(&self, _: &str) -> Result<Option<ResumeState>> {
        Ok(None)
    }
    fn save(&self, _: &str, _: &ResumeState) -> Result<()> {
        Ok(())
    }
    fn delete(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

/// The new content.
#[derive(Clone, Copy)]
pub(crate) enum Content<'a> {
    /// A local file: streamed, and resumable.
    Path(&'a Path),
    /// Bytes in memory (a vault, a whiteboard snapshot): sent at once.
    Bytes(&'a [u8]),
}

/// One new version of `file`.
pub(crate) struct VersionRequest<'a> {
    /// The file as listed now, at the key the content is sealed under.
    pub file: &'a File,
    pub file_key: &'a [u8; 32],
    pub content: Content<'a>,
    /// The content's SHA-256.
    pub sha256: [u8; 32],
    /// The file's folder's hash key: its content hash there goes along.
    pub hash_key: Option<&'a [u8; 32]>,
    /// Stored only if the file still holds this version (an id, or
    /// `original`).
    pub based_on: Option<String>,
    pub progress: Progress,
    /// An open upload of ours, with no record, idle at least this long was
    /// left by a crash and is cancelled ([`VAULT_CRASHED_AFTER_SECS`],
    /// [`FILE_CRASHED_AFTER_SECS`]); below it, it is busy.
    pub crashed_after_secs: i64,
    /// Who signs the revision's manifest (`drive_signer::identity`).
    pub signer: UploadSigner<'a>,
}

/// How a version upload ended.
#[derive(Debug)]
pub(crate) enum Landed {
    /// Committed: the version's id.
    Stored(String),
    /// Refused because the file moved on: the server's answer.
    Conflict(anyhow::Error),
    /// Another upload of a new version of this file is under way (another
    /// device, or someone else): nothing was sent; try again later.
    Busy,
}

/// What a refusal means for a version upload.
enum Refusal {
    /// Another upload of a version of this file is open: ours when its id
    /// is given, with the seconds since its last part.
    Uploading(Option<String>, i64),
    /// The file moved on (a version, its metadata, its key).
    Conflict,
    /// tus's own `409` (plain text, no `code`): the part was not at the
    /// offset the server holds; ask it where it is and go on from there.
    OffsetMismatch,
    Other,
}

fn refusal(error: &anyhow::Error) -> Refusal {
    let Some(api) = error.chain().find_map(|c| c.downcast_ref::<ApiError>()) else {
        return Refusal::Other;
    };
    if api.status != 409 {
        return Refusal::Other;
    }
    match api.code.as_deref() {
        Some("versionUploading") => {
            Refusal::Uploading(api.upload_id.clone(), api.idle_seconds.unwrap_or(0))
        }
        // Another version than `basedOn`, metadata moved on, or the file's
        // key changed (the server's plain `conflict`).
        Some("version_conflict" | "revision_conflict" | "conflict") => Refusal::Conflict,
        None => Refusal::OffsetMismatch,
        Some(_) => Refusal::Other,
    }
}

fn record_key(request: &VersionRequest<'_>) -> Option<String> {
    match request.content {
        Content::Path(path) => {
            let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            Some(format!(
                "version\n{}\n{}",
                request.file.id,
                canonical.display()
            ))
        }
        Content::Bytes(_) => None,
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Uploads `request`'s content as a new version of its file, and commits it.
pub(crate) fn upload_version(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    request: VersionRequest<'_>,
) -> Result<Landed> {
    let file = request.file;
    let (plain_size, mtime) = match request.content {
        Content::Path(path) => {
            let stat = std::fs::metadata(path)?;
            (stat.len() as i64, mtime_parts(&stat))
        }
        Content::Bytes(bytes) => (bytes.len() as i64, (0, 0)),
    };
    let resume_key = record_key(&request);
    let bar = make_bar(&request.progress, plain_size, "new version");
    let sha256 = b64().encode(request.sha256);

    if let Some(key) = &resume_key {
        if let Some(rec) = records.get(key)? {
            let unchanged = rec.version_of == file.id
                && !rec.revision_id.is_empty()
                && rec.key_generation == file.key_generation
                && rec.plain_size == plain_size
                && rec.sha256 == sha256
                && (rec.mtime_secs, rec.mtime_nanos) == mtime;
            if unchanged {
                if let Some(landed) = resume(tus, records, key, &rec, &request, &bar)? {
                    return Ok(landed);
                }
            } else {
                // Another content than the upload started with: it goes.
                let _ = tus.delete(&rec.upload_id);
                records.delete(key)?;
            }
        }
    }

    let revision_id = uuid::Uuid::new_v4().to_string();
    let meta = VersionUploadMeta {
        version_of: file.id.clone(),
        revision_id: revision_id.clone(),
        content_hash: request
            .hash_key
            .map(|key| crate::names::content_hash(key, &request.sha256))
            .transpose()?,
        based_on: request.based_on.clone(),
    };
    let cipher_total = crate::transfer::object_len(plain_size as u64)?;
    let upload_id = match open(tus, cipher_total, &meta, request.crashed_after_secs)? {
        Opened::Upload(id) => id,
        Opened::Not(landed) => return Ok(landed),
    };
    let now = now_unix();
    let mut rec = ResumeState {
        upload_id,
        file_id: file.id.clone(),
        revision_id,
        sha256,
        plain_size,
        cipher_total,
        mtime_secs: mtime.0,
        mtime_nanos: mtime.1,
        created_at: now,
        updated_at: now,
        version_of: file.id.clone(),
        key_generation: file.key_generation,
        ..Default::default()
    };
    // Kept before the first part: a run cut short at any later point leaves
    // what resuming needs.
    if let Some(key) = &resume_key {
        records.save(key, &rec)?;
    }
    finish(
        tus,
        records,
        resume_key.as_deref(),
        &mut rec,
        &request,
        0,
        &bar,
    )
}

/// What opening the upload gave.
enum Opened {
    Upload(String),
    /// Not opened: a conflict, or busy.
    Not(Landed),
}

/// Opens the upload. An upload of ours left open by a crash (no record
/// resumed it, idle `crashed_after_secs` or more) is cancelled and the
/// upload opened again, once; one still moving, or someone else's, is busy.
fn open(
    tus: &impl VersionTus,
    cipher_total: i64,
    meta: &VersionUploadMeta,
    crashed_after_secs: i64,
) -> Result<Opened> {
    let mut cancelled = false;
    loop {
        let error = match tus.create(cipher_total, meta) {
            Ok(id) => return Ok(Opened::Upload(id)),
            Err(error) => error,
        };
        match refusal(&error) {
            // Ours (`yours`: an earlier run here; one with a record was
            // resumed before this) or, as the folder's owner, another
            // writer's: either may be cancelled, but only once it has sat
            // idle past the threshold. One moving is busy.
            Refusal::Uploading(Some(open), idle) if idle >= crashed_after_secs && !cancelled => {
                tus.delete(&open)
                    .context("cancel an abandoned upload of this file's new version")?;
                cancelled = true;
            }
            Refusal::Uploading(..) => return Ok(Opened::Not(Landed::Busy)),
            Refusal::Conflict => return Ok(Opened::Not(Landed::Conflict(error))),
            Refusal::OffsetMismatch | Refusal::Other => return Err(error),
        }
    }
}

/// The tail a record kept, if it kept one.
pub(crate) fn kept_tail(rec: &ResumeState) -> Result<Option<KeptTail>> {
    if rec.tail.is_empty() {
        return Ok(None);
    }
    KeptTail::load(&rec.tail, &rec.tail_manifest_sha256, &rec.revision_id).map(Some)
}

/// Goes on with the recorded upload. `Ok(None)`: it cannot go on (gone,
/// or no longer matching); the record is dropped and a new upload starts.
fn resume(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    key: &str,
    rec: &ResumeState,
    request: &VersionRequest<'_>,
    bar: &ProgressBar,
) -> Result<Option<Landed>> {
    let drop_it = |cancel: bool| -> Result<Option<Landed>> {
        if cancel {
            let _ = tus.delete(&rec.upload_id);
        }
        records.delete(key)?;
        Ok(None)
    };
    let Ok(tail) = kept_tail(rec) else {
        return drop_it(true);
    };
    let mut state = rec.clone();
    match tus.head(&rec.upload_id)? {
        None => {
            // Gone: committed (and the answer was lost), or refused or
            // swept. Every byte had arrived when there is a tail: committing
            // again settles which.
            if tus.has_version(&request.file.id, &rec.revision_id)? {
                records.delete(key)?;
                return Ok(Some(Landed::Stored(rec.revision_id.clone())));
            }
            match tail {
                Some(tail) => commit(tus, records, Some(key), &state, request, &tail.content)
                    .map(Some)
                    .or_else(|error| {
                        if crate::revisions::status_of(&error) == Some(404) {
                            records.delete(key)?;
                            return Ok(None);
                        }
                        Err(error)
                    }),
                None => drop_it(false),
            }
        }
        Some((offset, length)) if length != rec.cipher_total || offset > length => drop_it(true),
        // Every byte is there: only the commit is left.
        Some((offset, length)) if offset == length => match tail {
            Some(tail) => commit(tus, records, Some(key), &state, request, &tail.content).map(Some),
            None => drop_it(true),
        },
        Some((offset, _)) => {
            finish(tus, records, Some(key), &mut state, request, offset, bar).map(Some)
        }
    }
}

/// Sends the upload from `offset`, then commits it.
fn finish(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    key: Option<&str>,
    rec: &mut ResumeState,
    request: &VersionRequest<'_>,
    offset: i64,
    bar: &ProgressBar,
) -> Result<Landed> {
    let context = DriveBlobContextV2::new(&request.file.id, &rec.revision_id, rec.key_generation)?;
    let tail = kept_tail(rec)?;
    let size = rec.plain_size as u64;
    let sent = match request.content {
        Content::Path(path) => {
            let mut source = BlockSource::new(
                || Ok(LocalFile::open(path)?),
                request.file_key,
                context,
                request.signer,
                size,
                request.sha256,
                tail,
            )?;
            send_parts(tus, records, key, rec, &mut source, offset, bar)
                .map(|()| source.content().cloned())
        }
        Content::Bytes(bytes) => {
            let mut source = BlockSource::new(
                || Ok(bytes),
                request.file_key,
                context,
                request.signer,
                size,
                request.sha256,
                tail,
            )?;
            send_parts(tus, records, key, rec, &mut source, offset, bar)
                .map(|()| source.content().cloned())
        }
    };
    bar.finish_and_clear();
    let content = match sent {
        Ok(Some(content)) => content,
        Ok(None) => bail!("the upload ended before its tail was made"),
        Err(error) => return settle_send_error(tus, records, key, rec, error),
    };
    commit(tus, records, key, rec, request, &content)
}

/// What a failed send means: a changed or other file, or a refusal, ends
/// the upload; a lost connection keeps the record for a later run.
fn settle_send_error(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    key: Option<&str>,
    rec: &ResumeState,
    error: anyhow::Error,
) -> Result<Landed> {
    let drop_record = |cancel: bool| -> Result<()> {
        if cancel {
            let _ = tus.delete(&rec.upload_id);
        }
        if let Some(key) = key {
            records.delete(key)?;
        }
        Ok(())
    };
    if error.is::<ChangedWhileUploading>() || error.is::<NotTheSameFile>() {
        drop_record(true)?;
        return Err(error);
    }
    if matches!(refusal(&error), Refusal::Conflict) {
        drop_record(false)?;
        return Ok(Landed::Conflict(error));
    }
    if lost_access(&error) {
        // The server discarded the upload when the access went.
        drop_record(false)?;
        return Err(
            error.context("access to the file was lost during the upload; it was discarded")
        );
    }
    if is_permanent(&error) || key.is_none() {
        drop_record(true)?;
        return Err(error.context("upload new version"));
    }
    Err(error.context("new version interrupted — run it again to go on from there"))
}

/// Commits the uploaded revision with the file's next metadata: its size and
/// SHA-256 new, its name as it is then (a rename meanwhile is kept).
fn commit(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    key: Option<&str>,
    rec: &ResumeState,
    request: &VersionRequest<'_>,
    content: &kutup_crypto::file_metadata::ContentCommitmentV1,
) -> Result<Landed> {
    let file = request.file;
    let metadata = crate::file_crypto::open_metadata(file, request.file_key)
        .context("decrypt file metadata")?;
    let draft = Draft {
        size: rec.plain_size as u64,
        sha256: Some(rec.sha256.clone()),
        ..Draft::of(&metadata)
    };
    let committed = crate::revisions::commit_upload(
        tus,
        &CommitUpload {
            file_id: &file.id,
            revision_id: &rec.revision_id,
            file_key: request.file_key,
            key_generation: rec.key_generation,
            content,
            draft,
            base: Base::Version {
                metadata_revision: file.metadata_revision,
                collection_id: file.collection_id.clone(),
            },
            free_name: None,
        },
    );
    let forget = || -> Result<()> {
        if let Some(key) = key {
            records.delete(key)?;
        }
        Ok(())
    };
    match committed {
        Ok(_) => {
            forget()?;
            Ok(Landed::Stored(rec.revision_id.clone()))
        }
        Err(error) => match crate::revisions::conflict_code(&error) {
            // Every part has not arrived: a later run goes on with it.
            Some("notUploaded") => Err(error.context("new version not fully sent; run it again")),
            Some("version_conflict" | "revision_conflict" | "conflict") => {
                let _ = tus.delete(&rec.upload_id);
                forget()?;
                Ok(Landed::Conflict(error))
            }
            // The object is gone, or another refusal: it can never commit.
            _ if crate::revisions::status_of(&error)
                .is_some_and(|s| s < 500 && s != 408 && s != 429) =>
            {
                let _ = tus.delete(&rec.upload_id);
                forget()?;
                Err(error.context("commit new version"))
            }
            _ => Err(error.context("commit new version; run it again to commit")),
        },
    }
}

/// Sends the object from `offset` to its end, two sealed blocks a part. The
/// tail, once made, is kept in the record before any of it goes. A part
/// refused for its offset goes on from wherever the server is (any offset:
/// the source seals again from block 0). Errors come back as they came.
pub(crate) fn send_parts<R: Read>(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    key: Option<&str>,
    rec: &mut ResumeState,
    source: &mut BlockSource<'_, R>,
    mut offset: i64,
    bar: &ProgressBar,
) -> Result<()> {
    let total = source.len() as i64;
    let mut resyncs = 0;
    #[cfg(feature = "fail-inject")]
    let mut patches_done: u32 = 0;
    bar.set_position(source.plain_before(offset as u64));
    while offset < total {
        let body = source.bytes(offset as u64, offset as u64 + PATCH_BYTES)?;
        if let Some(tail) = source.take_new_tail() {
            let (bytes, digest) = tail.store();
            rec.tail = bytes;
            rec.tail_manifest_sha256 = digest;
            if let Some(key) = key {
                records.save(key, rec)?;
            }
        }
        let error = match tus.patch(&rec.upload_id, offset, body) {
            Ok(patched) => {
                offset = patched.offset;
                rec.updated_at = now_unix();
                if let Some(key) = key {
                    let _ = records.save(key, rec);
                }
                bar.set_position(source.plain_before(offset as u64));
                #[cfg(feature = "fail-inject")]
                {
                    patches_done += 1;
                    maybe_abort(patches_done);
                }
                continue;
            }
            Err(error) => error,
        };
        if matches!(refusal(&error), Refusal::OffsetMismatch) && resyncs < MAX_RESYNCS {
            resyncs += 1;
            if let Some((at, length)) = tus.head(&rec.upload_id)? {
                if length == total && at <= total {
                    offset = at;
                    continue;
                }
            }
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(feature = "fail-inject")]
fn maybe_abort(patches_done: u32) {
    if let Some(n) = std::env::var("KUTUP_TEST_ABORT_AFTER_PATCHES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        if patches_done >= n {
            eprintln!("fail-inject: aborting after {patches_done} PATCH(es)");
            std::process::exit(74);
        }
    }
}

/// A `403` on a part: the writer lost access mid-upload.
fn lost_access(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|c| c.downcast_ref::<ApiError>())
        .is_some_and(|api| api.status == 403)
}

/// How many times one run goes on from the server's offset after a part
/// was refused for its own.
const MAX_RESYNCS: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tus::CommitRevision;
    use crate::api::FileMetadata;
    use kutup_crypto::blocks::{SignerIdentity, BLOCK_SIZE};
    use kutup_crypto::drive_blocks;
    use kutup_crypto::primitives::{hash, SigningKey, Suite};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    const FOLDER: &str = "11111111-1111-4111-8111-111111111111";

    /// An open upload: its length, what arrived, its metadata.
    type Open = (i64, Vec<u8>, VersionUploadMeta);

    /// A committed version: its id, its object, its upload's metadata and
    /// the commit's body.
    type Stored = (String, Vec<u8>, VersionUploadMeta, CommitRevision);

    /// A tus server in memory: one version upload at a time.
    #[derive(Default)]
    struct FakeTus {
        uploads: RefCell<HashMap<String, Open>>,
        stored: RefCell<Vec<Stored>>,
        row: RefCell<Option<File>>,
        creates: Cell<u32>,
        patches: Cell<u32>,
        commits: Cell<u32>,
        /// Fail the PATCH with this number (1-based) once, as a dropped link.
        fail_patch: Cell<Option<u32>>,
        /// Take the PATCH with this number, but answer tus's offset
        /// mismatch (an answer that went astray, the part sent again).
        skew_patch: Cell<Option<u32>>,
        /// Fail the next commit once, as a dropped link.
        fail_commit: Cell<bool>,
        /// Refuse when the upload opens: `basedOn` is not what the file holds.
        conflict_at_open: Cell<bool>,
        /// Refuse the commit, as a file that moved on.
        conflict_at_commit: Cell<bool>,
        /// Seconds since the open upload's last part.
        idle: Cell<i64>,
        /// The open upload is someone else's.
        foreign: Cell<bool>,
        /// Someone else's upload, seen by the folder's owner (`yours: false`).
        owner_view: Cell<bool>,
        /// Answer the PATCH with this number with 403 (access lost).
        forbid_patch: Cell<Option<u32>>,
        deletes: Cell<u32>,
    }

    fn api(status: u16, body: &str) -> anyhow::Error {
        anyhow::Error::new(ApiError::from_parts(status, "", body.into()))
    }

    impl Commits for FakeTus {
        fn commit(&self, _: &str, revision_id: &str, body: &CommitRevision) -> Result<()> {
            self.commits.set(self.commits.get() + 1);
            if self.fail_commit.replace(false) {
                return Err(api(503, "unavailable"));
            }
            let mut uploads = self.uploads.borrow_mut();
            let Some((total, bytes, _)) = uploads.get(revision_id) else {
                return Err(api(404, r#"{"error":"not found"}"#));
            };
            if bytes.len() as i64 != *total {
                return Err(api(
                    409,
                    r#"{"error":"parts missing","code":"notUploaded"}"#,
                ));
            }
            if self.conflict_at_commit.get() {
                return Err(api(
                    409,
                    r#"{"error":"moved on","code":"version_conflict"}"#,
                ));
            }
            let (_, bytes, meta) = uploads.remove(revision_id).unwrap();
            self.stored
                .borrow_mut()
                .push((revision_id.to_string(), bytes, meta, body.clone()));
            Ok(())
        }
        fn file_row(&self, _: &str, _: &str) -> Result<File> {
            self.row.borrow().clone().context("no row")
        }
    }

    impl VersionTus for FakeTus {
        fn create(&self, total: i64, meta: &VersionUploadMeta) -> Result<String> {
            self.creates.set(self.creates.get() + 1);
            if self.conflict_at_open.get() {
                return Err(api(
                    409,
                    r#"{"error":"the file changed since","code":"version_conflict","current":"v7"}"#,
                ));
            }
            if let Some(open) = self.uploads.borrow().keys().next() {
                let ours = if self.foreign.get() {
                    String::new()
                } else {
                    format!(r#","uploadId":"{open}","yours":{}"#, !self.owner_view.get())
                };
                return Err(api(
                    409,
                    &format!(
                        r#"{{"error":"open","code":"versionUploading","idleSeconds":{}{ours}}}"#,
                        self.idle.get()
                    ),
                ));
            }
            // The upload's id is the revision's.
            let id = meta.revision_id.clone();
            self.uploads
                .borrow_mut()
                .insert(id.clone(), (total, Vec::new(), meta.clone()));
            Ok(id)
        }
        fn head(&self, id: &str) -> Result<Option<(i64, i64)>> {
            Ok(self
                .uploads
                .borrow()
                .get(id)
                .map(|(total, body, _)| (body.len() as i64, *total)))
        }
        fn patch(&self, id: &str, offset: i64, chunk: Vec<u8>) -> Result<Patched> {
            let n = self.patches.get() + 1;
            self.patches.set(n);
            if self.fail_patch.get() == Some(n) {
                self.fail_patch.set(None);
                return Err(api(503, "unavailable"));
            }
            if self.forbid_patch.get() == Some(n) {
                self.uploads.borrow_mut().remove(id);
                return Err(api(403, r#"{"error":"forbidden","code":"forbidden"}"#));
            }
            let mut uploads = self.uploads.borrow_mut();
            let (total, body, _) = uploads.get_mut(id).context("no upload")?;
            if offset != body.len() as i64 {
                return Err(api(409, "Upload-Offset mismatch"));
            }
            body.extend_from_slice(&chunk);
            if body.len() as i64 > *total {
                return Err(api(400, "longer than declared"));
            }
            if self.skew_patch.get() == Some(n) {
                self.skew_patch.set(None);
                return Err(api(409, "Upload-Offset mismatch"));
            }
            Ok(Patched {
                offset: body.len() as i64,
                ..Default::default()
            })
        }
        fn delete(&self, id: &str) -> Result<()> {
            self.deletes.set(self.deletes.get() + 1);
            self.uploads.borrow_mut().remove(id);
            Ok(())
        }
        fn has_version(&self, _: &str, id: &str) -> Result<bool> {
            Ok(self.stored.borrow().iter().any(|(v, ..)| v == id))
        }
    }

    #[derive(Default)]
    struct Records(RefCell<HashMap<String, ResumeState>>);

    impl ResumeRecords for Records {
        fn get(&self, key: &str) -> Result<Option<ResumeState>> {
            Ok(self.0.borrow().get(key).cloned())
        }
        fn save(&self, key: &str, state: &ResumeState) -> Result<()> {
            self.0.borrow_mut().insert(key.into(), state.clone());
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.0.borrow_mut().remove(key);
            Ok(())
        }
    }

    const ORIGINAL_REVISION: &str = "55555555-5555-4555-8555-555555555555";

    fn file() -> (File, [u8; 32]) {
        let created = crate::file_crypto::create(FOLDER, 1, &[3u8; 32]).unwrap();
        let meta = FileMetadata {
            name: "big.bin".into(),
            mime_type: "application/octet-stream".into(),
            size: 1,
            content: kutup_crypto::file_metadata::ContentCommitmentV1::new(
                *uuid::Uuid::parse_str(ORIGINAL_REVISION).unwrap().as_bytes(),
                [1; 32],
            ),
            original_revision_id: Some(ORIGINAL_REVISION.into()),
            state_revision_id: None,
            sha256: None,
            media: None,
        };
        let metadata_envelope =
            crate::file_crypto::seal_metadata(&meta, &created.file_key, &created.id, 1, 1).unwrap();
        (
            File {
                content_hash: None,
                name_hash: None,
                id: created.id,
                collection_id: FOLDER.into(),
                metadata_envelope,
                file_key_envelope: created.file_key_envelope,
                key_epoch: 1,
                key_generation: created.key_generation,
                metadata_revision: 1,
                encrypted_size_bytes: 0,
                created_at: String::new(),
                content_key_generation: 1,
                original_key_generation: 1,
                key_history: Vec::new(),
            },
            created.file_key,
        )
    }

    fn signing() -> SigningKey {
        SigningKey::from_seed(Suite::V1, &[8; 32])
    }

    fn request<'a>(
        file: &'a File,
        key: &'a [u8; 32],
        content: Content<'a>,
        hash_key: &'a [u8; 32],
        signing: &'a SigningKey,
    ) -> VersionRequest<'a> {
        let sha256 = match &content {
            Content::Path(path) => hash(Suite::V1, std::fs::read(path).unwrap()).into(),
            Content::Bytes(bytes) => hash(Suite::V1, bytes).into(),
        };
        VersionRequest {
            file,
            file_key: key,
            content,
            sha256,
            hash_key: Some(hash_key),
            based_on: None,
            progress: Progress::Quiet,
            crashed_after_secs: VAULT_CRASHED_AFTER_SECS,
            signer: (
                signing,
                SignerIdentity {
                    account_id: [2; 16],
                    incarnation_id: [3; 32],
                },
            ),
        }
    }

    /// What a committed version holds, opened as a reader would: the
    /// metadata it committed, then the object against it.
    fn opened(file: &File, key: &[u8; 32], stored: &Stored) -> (FileMetadata, Vec<u8>) {
        let (id, body, _, commit) = stored;
        let next = File {
            metadata_envelope: commit.metadata_envelope.clone(),
            metadata_revision: commit.metadata_revision,
            ..file.clone()
        };
        let metadata = crate::file_crypto::open_metadata(&next, key).unwrap();
        assert_eq!(&metadata.content.revision_id, id);
        let context =
            drive_blocks::DriveBlobContextV2::new(&file.id, id, file.key_generation).unwrap();
        let (plain, _) =
            drive_blocks::open_file(body, key, context, &metadata.content, metadata.size).unwrap();
        (metadata, plain.to_vec())
    }

    fn big(dir: &tempfile::TempDir) -> (std::path::PathBuf, Vec<u8>) {
        let plain: Vec<u8> = (0..2 * BLOCK_SIZE + 31).map(|i| (i % 247) as u8).collect();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, &plain).unwrap();
        (path, plain)
    }

    /// Two parts (two sealed blocks each), cut at the second; the next run
    /// goes on from the server's offset with the tail kept before it was
    /// sent, and the commit brings the metadata, the content hash with the
    /// upload.
    #[test]
    fn a_large_version_resumes_where_it_stopped_and_commits() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.fail_patch.set(Some(2));

        let cut = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        );
        assert!(cut.is_err(), "the dropped link stops the run");
        {
            let kept = records.0.borrow();
            let rec = kept.values().next().expect("the record stays to resume");
            assert!(!rec.tail.is_empty(), "the tail is kept before it is sent");
            assert!(!rec.revision_id.is_empty());
        }

        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .unwrap();
        let Landed::Stored(version) = landed else {
            panic!("stored: {landed:?}")
        };
        assert_eq!(tus.creates.get(), 1, "resumed, not opened again");
        assert_eq!(tus.patches.get(), 3, "one part twice, none after it");
        assert!(records.0.borrow().is_empty());

        let stored = tus.stored.borrow();
        assert_eq!(stored[0].0, version);
        let (metadata, opened_plain) = opened(&file, &key, &stored[0]);
        assert_eq!(opened_plain, plain);
        assert_eq!(metadata.size, plain.len() as u64);
        assert_eq!(metadata.name, "big.bin");
        assert_eq!(
            metadata.original_revision_id.as_deref(),
            Some(ORIGINAL_REVISION),
            "a version carries the original the file names"
        );
        assert_eq!(stored[0].3.metadata_revision, file.metadata_revision + 1);
        assert_eq!(
            stored[0].2.content_hash.as_deref(),
            Some(
                crate::names::content_hash(&hash_key, &{ hash(Suite::V1, &plain).into() })
                    .unwrap()
                    .as_str()
            )
        );
    }

    /// The server holds a prefix that ends anywhere (inside the header, a
    /// block, or the tail): the next run seals again from block 0 and sends
    /// from that exact byte.
    #[test]
    fn a_resume_goes_on_from_any_server_offset() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, plain) = big(&dir);
        let total = crate::transfer::object_len(plain.len() as u64).unwrap() as usize;
        for keep in [0usize, 20, 1000, BLOCK_SIZE + 77, total - 5] {
            let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
            tus.fail_patch.set(Some(2));
            let _ = upload_version(
                &tus,
                &records,
                request(&file, &key, Content::Path(&path), &hash_key, &signing),
            );
            // The server lost what came after `keep`.
            for (_, body, _) in tus.uploads.borrow_mut().values_mut() {
                body.truncate(keep);
            }
            let landed = upload_version(
                &tus,
                &records,
                request(&file, &key, Content::Path(&path), &hash_key, &signing),
            )
            .unwrap();
            assert!(matches!(landed, Landed::Stored(_)), "{keep}: {landed:?}");
            assert_eq!(
                opened(&file, &key, &tus.stored.borrow()[0]).1,
                plain,
                "{keep}"
            );
        }
    }

    /// Every byte arrived, but the commit's answer was lost: the next run
    /// finds the upload complete and commits it with the kept tail.
    #[test]
    fn an_upload_whose_commit_was_lost_is_committed_on_resume() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.fail_commit.set(true);
        assert!(upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .is_err());
        assert_eq!(records.0.borrow().len(), 1);
        let patches = tus.patches.get();
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)), "{landed:?}");
        assert_eq!(tus.patches.get(), patches, "nothing sent again");
        assert_eq!(opened(&file, &key, &tus.stored.borrow()[0]).1, plain);
    }

    #[test]
    fn a_conflict_at_the_commit_is_reported_not_retried() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"edited").unwrap();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.conflict_at_commit.set(true);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Conflict(_)));
        assert_eq!(tus.creates.get(), 1);
        assert_eq!(tus.commits.get(), 1);
        assert_eq!(tus.deletes.get(), 1, "the uploaded revision is cancelled");
        assert!(records.0.borrow().is_empty());
    }

    /// A run that crashed right after opening its upload (no part sent, no
    /// record kept): the next save finds it idle past the threshold,
    /// cancels it and saves.
    #[test]
    fn an_upload_left_by_a_crash_is_cancelled_and_the_save_goes_on() {
        let (file, key) = file();
        let signing = signing();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let left = tus
            .create(
                1,
                &VersionUploadMeta {
                    revision_id: "left".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        tus.idle.set(VAULT_CRASHED_AFTER_SECS);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)));
        assert!(
            tus.head(&left).unwrap().is_none(),
            "the old one is cancelled"
        );
        assert_eq!(tus.deletes.get(), 1);
        assert_eq!(opened(&file, &key, &tus.stored.borrow()[0]).1, b"v2");
    }

    /// Ours but still moving (another device of the account), or someone
    /// else's: busy, never cancelled; once the slot frees, the save lands.
    #[test]
    fn an_upload_still_moving_is_busy_and_never_cancelled() {
        let (file, key) = file();
        let signing = signing();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let other = tus
            .create(
                1,
                &VersionUploadMeta {
                    revision_id: "other".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        for (idle, foreign) in [(VAULT_CRASHED_AFTER_SECS - 1, false), (9999, true)] {
            tus.idle.set(idle);
            tus.foreign.set(foreign);
            let landed = upload_version(
                &tus,
                &records,
                request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing),
            )
            .unwrap();
            assert!(matches!(landed, Landed::Busy), "{landed:?}");
        }
        // A Drive file waits much longer before taking an upload as left.
        tus.idle.set(VAULT_CRASHED_AFTER_SECS * 5);
        tus.foreign.set(false);
        let mut slow = request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing);
        slow.crashed_after_secs = FILE_CRASHED_AFTER_SECS;
        assert!(matches!(
            upload_version(&tus, &records, slow).unwrap(),
            Landed::Busy
        ));
        assert_eq!(tus.deletes.get(), 0, "nothing cancelled");
        assert!(tus.stored.borrow().is_empty());

        // The other device finishes; the next try saves.
        tus.uploads.borrow_mut().remove(&other);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)));
        assert_eq!(tus.deletes.get(), 0);
    }

    /// The server took a part but its answer was lost and the part went
    /// again: tus's offset mismatch is not a conflict; the upload asks where
    /// the server is and goes on from there.
    #[test]
    fn an_offset_mismatch_goes_on_from_the_server_offset() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.skew_patch.set(Some(1));
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)), "{landed:?}");
        assert_eq!(tus.patches.get(), 2, "the taken part is not sent again");
        assert_eq!(opened(&file, &key, &tus.stored.borrow()[0]).1, plain);
    }

    /// A push made from a version the file no longer holds: refused when it
    /// opens, reported as a conflict (the sync then keeps both).
    #[test]
    fn a_based_on_conflict_is_a_conflict() {
        let (file, key) = file();
        let signing = signing();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.conflict_at_open.set(true);
        let mut req = request(&file, &key, Content::Bytes(b"mine"), &hash_key, &signing);
        req.based_on = Some("v3".into());
        let landed = upload_version(&tus, &records, req).unwrap();
        assert!(matches!(landed, Landed::Conflict(_)), "{landed:?}");
        assert_eq!(tus.patches.get(), 0, "nothing sent");
    }

    /// The folder's owner sees another writer's upload (`yours: false`):
    /// busy while it moves, cancelled once idle past the threshold.
    #[test]
    fn the_owner_cancels_another_writers_upload_only_when_idle() {
        let (file, key) = file();
        let signing = signing();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let other = tus
            .create(
                1,
                &VersionUploadMeta {
                    revision_id: "other".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        tus.owner_view.set(true);
        tus.idle.set(VAULT_CRASHED_AFTER_SECS - 1);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Busy), "{landed:?}");
        assert_eq!(tus.deletes.get(), 0);
        tus.idle.set(VAULT_CRASHED_AFTER_SECS);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)), "{landed:?}");
        assert!(tus.head(&other).unwrap().is_none());
        assert_eq!(tus.deletes.get(), 1);
    }

    /// Access lost mid-upload: the server discarded it; the record goes.
    #[test]
    fn lost_access_mid_upload_drops_the_record() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.forbid_patch.set(Some(2));
        let error = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("access"), "{error:#}");
        assert!(records.0.borrow().is_empty());
    }

    /// A change of the same size between the hash and the upload: the last
    /// block is held back (`NotTheSameFile`), the upload cancelled, nothing
    /// stored.
    #[test]
    fn a_same_size_change_is_not_the_same_file() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, mut plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let req = request(&file, &key, Content::Path(&path), &hash_key, &signing);
        plain[BLOCK_SIZE + 5] ^= 0xff;
        std::fs::write(&path, &plain).unwrap();
        let error = upload_version(&tus, &records, req).unwrap_err();
        assert!(error.is::<NotTheSameFile>(), "{error:#}");
        assert_eq!(
            tus.patches.get(),
            1,
            "the part holding the last block is held back"
        );
        assert_eq!(tus.deletes.get(), 1);
        assert!(tus.stored.borrow().is_empty());
        assert!(records.0.borrow().is_empty());
    }

    /// The file under the record now holds another content of the same size
    /// (and the same date): the record is not resumed, the upload starts
    /// over and the old one goes.
    #[test]
    fn another_content_under_the_record_starts_over() {
        let (file, key) = file();
        let signing = signing();
        let dir = tempfile::tempdir().unwrap();
        let (path, mut plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.fail_patch.set(Some(2));
        let _ = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        );
        let mut rec = records.0.borrow().values().next().unwrap().clone();
        plain[3] ^= 1;
        std::fs::write(&path, &plain).unwrap();
        // The same date as recorded, so only the content tells.
        let stat = std::fs::metadata(&path).unwrap();
        let (secs, nanos) = mtime_parts(&stat);
        rec.mtime_secs = secs;
        rec.mtime_nanos = nanos;
        let key_of = records.0.borrow().keys().next().unwrap().clone();
        records.0.borrow_mut().insert(key_of, rec);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)), "{landed:?}");
        assert_eq!(tus.creates.get(), 2, "started over");
        assert_eq!(opened(&file, &key, &tus.stored.borrow()[0]).1, plain);
    }

    /// A conflict at the commit when someone renamed the file meanwhile:
    /// the metadata is sealed again on top of theirs, keeping their name.
    #[test]
    fn a_rename_meanwhile_is_kept() {
        let (file, key) = file();
        let signing = signing();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let mut renamed = crate::file_crypto::open_metadata(&file, &key).unwrap();
        renamed.name = "renamed.bin".into();
        let request_rename = crate::file_crypto::rename_request(&file, &key, &renamed).unwrap();
        *tus.row.borrow_mut() = Some(File {
            metadata_envelope: request_rename.metadata_envelope,
            metadata_revision: request_rename.metadata_revision,
            ..file.clone()
        });
        // The fake refuses the first commit as a revision conflict.
        struct Conflicting<'a>(&'a FakeTus, Cell<bool>);
        impl Commits for Conflicting<'_> {
            fn commit(&self, f: &str, r: &str, body: &CommitRevision) -> Result<()> {
                if !self.1.replace(true) {
                    return Err(api(409, r#"{"error":"moved","code":"revision_conflict"}"#));
                }
                self.0.commit(f, r, body)
            }
            fn file_row(&self, c: &str, f: &str) -> Result<File> {
                self.0.file_row(c, f)
            }
        }
        impl VersionTus for Conflicting<'_> {
            fn create(&self, t: i64, m: &VersionUploadMeta) -> Result<String> {
                self.0.create(t, m)
            }
            fn head(&self, id: &str) -> Result<Option<(i64, i64)>> {
                self.0.head(id)
            }
            fn patch(&self, id: &str, o: i64, b: Vec<u8>) -> Result<Patched> {
                self.0.patch(id, o, b)
            }
            fn delete(&self, id: &str) -> Result<()> {
                self.0.delete(id)
            }
            fn has_version(&self, f: &str, v: &str) -> Result<bool> {
                self.0.has_version(f, v)
            }
        }
        let landed = upload_version(
            &Conflicting(&tus, Cell::new(false)),
            &records,
            request(&file, &key, Content::Bytes(b"v2"), &hash_key, &signing),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)), "{landed:?}");
        let stored = tus.stored.borrow();
        assert_eq!(stored[0].3.metadata_revision, 3);
        let row = tus.row.borrow().clone().unwrap();
        let (metadata, plain) = opened(&row, &key, &stored[0]);
        assert_eq!(metadata.name, "renamed.bin");
        assert_eq!(plain, b"v2");
    }
}
