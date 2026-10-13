//! A new version of a file over tus (docs/api.md, "POST /api/uploads with
//! versionOf"), as Proton Drive's revisions: resumable at any size, with the
//! file's next metadata (its new size and SHA-256) and the content's hash in
//! its folder carried by the upload, so the server stores the version, the
//! metadata and the content hash together when the last part lands.
//!
//! A local file's upload keeps a resume record in the same store as a new
//! file's (keyed `version\n{file id}\n{path}`), so a run cut short goes on
//! where it stopped. The server allows one open version upload per file:
//! one of ours with no record, idle longer than the request's
//! `crashed_after_secs`, was left by a crash and is cancelled and opened again; one still moving (another
//! device of the account) or someone else's is [`Landed::Busy`]: wait and
//! try again, never treat it as a conflict.
//!
//! A conflict, when the upload opens or when it lands (the file holds
//! another version than `basedOn`, its metadata moved on, its key changed),
//! comes back as [`Landed::Conflict`]: the caller decides (a sync keeps both
//! sides), nothing retries blindly.

use std::fs::File as LocalFile;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use indicatif::ProgressBar;
use kutup_crypto::drive_object::DriveFileBlobContextV1;
use kutup_crypto::stream::HEADER_BYTES;

use crate::api::tus::{Patched, VersionUploadMeta};
use crate::api::{ApiError, Client, File};
use crate::session::{ResumeState, Store};
use crate::transfer::{chunk_boundary, cipher_size, ChangedWhileUploading, StreamUploader};
use crate::uploader::{is_permanent, make_bar, mtime_parts, now_unix, Progress};

/// A vault save is one small part: an open upload of ours idle this long
/// was left by a crash, not by another device still saving.
pub(crate) const VAULT_CRASHED_AFTER_SECS: i64 = 120;

/// A Drive file's parts are 5 MiB each, and on a slow link one can take
/// minutes: only an upload of ours idle this long is taken as abandoned.
pub(crate) const FILE_CRASHED_AFTER_SECS: i64 = 3600;

/// The tus calls a version upload makes.
pub(crate) trait VersionTus {
    /// Opens the upload; returns its id (the version's).
    fn create(&self, total_bytes: i64, meta: &VersionUploadMeta) -> Result<String>;
    /// `(offset, length)` of an open upload; `None` once it is gone.
    fn head(&self, upload_id: &str) -> Result<Option<(i64, i64)>>;
    fn patch(&self, upload_id: &str, offset: i64, body: Vec<u8>) -> Result<Patched>;
    fn delete(&self, upload_id: &str) -> Result<()>;
    /// Whether the file holds version `version_id` (an upload that landed
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
}

/// How a version upload ended.
#[derive(Debug)]
pub(crate) enum Landed {
    /// Stored: the version's id.
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

/// Uploads `request`'s content as a new version of its file.
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
    let resume_key = match request.content {
        Content::Path(path) => {
            let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            Some(format!("version\n{}\n{}", file.id, canonical.display()))
        }
        Content::Bytes(_) => None,
    };
    let bar = make_bar(&request.progress, plain_size, "new version");

    if let Some(key) = &resume_key {
        if let Some(rec) = records.get(key)? {
            let unchanged = rec.version_of == file.id
                && rec.key_generation == file.key_generation
                && rec.plain_size == plain_size
                && (rec.mtime_secs, rec.mtime_nanos) == mtime;
            if unchanged {
                if let Some(landed) = resume(tus, records, key, &rec, &request, &bar)? {
                    return Ok(landed);
                }
            } else {
                let _ = tus.delete(&rec.upload_id);
                records.delete(key)?;
            }
        }
    }

    let meta = version_meta(&request, plain_size as u64)?;
    let cipher_total = cipher_size(plain_size);
    let upload_id = match open(tus, cipher_total, &meta, request.crashed_after_secs)? {
        Opened::Upload(id) => id,
        Opened::Not(landed) => return Ok(landed),
    };
    let context = DriveFileBlobContextV1::new(&file.id, file.key_generation)?;
    let now = now_unix();
    match request.content {
        Content::Path(path) => {
            let up = StreamUploader::new(
                LocalFile::open(path)?,
                request.file_key,
                plain_size,
                context,
            )?;
            let mut rec = ResumeState {
                upload_id,
                file_id: file.id.clone(),
                header: base64::engine::general_purpose::STANDARD.encode(up.header_bytes()),
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
            // Kept before the first part: a run cut short at any later point
            // leaves what resuming needs.
            let key = resume_key.as_deref();
            if let Some(key) = key {
                records.save(key, &rec)?;
            }
            let header = up.header_bytes();
            let rebuild = |at: i64| {
                StreamUploader::resume(
                    LocalFile::open(path)?,
                    request.file_key,
                    plain_size,
                    &header,
                    at,
                    context,
                )
            };
            send(
                tus,
                records,
                key,
                &mut rec,
                up,
                0,
                &bar,
                &request.sha256,
                rebuild,
            )
        }
        Content::Bytes(bytes) => {
            let up = StreamUploader::new(bytes, request.file_key, plain_size, context)?;
            let mut rec = ResumeState {
                upload_id,
                file_id: file.id.clone(),
                cipher_total,
                ..Default::default()
            };
            let header = up.header_bytes();
            let rebuild = |at: i64| {
                StreamUploader::resume(bytes, request.file_key, plain_size, &header, at, context)
            };
            send(
                tus,
                records,
                None,
                &mut rec,
                up,
                0,
                &bar,
                &request.sha256,
                rebuild,
            )
        }
    }
}

/// The upload's metadata: the file's next metadata revision with the new
/// size and SHA-256 (the name stays), and the content's hash in its folder.
fn version_meta(request: &VersionRequest<'_>, size: u64) -> Result<VersionUploadMeta> {
    let mut metadata = crate::file_crypto::open_metadata(request.file, request.file_key)
        .context("decrypt file metadata")?;
    metadata.size = size;
    metadata.sha256 = Some(base64::engine::general_purpose::STANDARD.encode(request.sha256));
    let sealed = crate::file_crypto::rename_request(request.file, request.file_key, &metadata)?;
    Ok(VersionUploadMeta {
        version_of: request.file.id.clone(),
        metadata_envelope: sealed.metadata_envelope,
        metadata_revision: sealed.metadata_revision,
        content_hash: request
            .hash_key
            .map(|key| crate::names::content_hash(key, &request.sha256))
            .transpose()?,
        based_on: request.based_on.clone(),
    })
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
            Refusal::Uploading(Some(ours), idle) if idle >= crashed_after_secs && !cancelled => {
                tus.delete(&ours)
                    .context("cancel an abandoned upload of this file's new version")?;
                cancelled = true;
            }
            Refusal::Uploading(..) => return Ok(Opened::Not(Landed::Busy)),
            Refusal::Conflict => return Ok(Opened::Not(Landed::Conflict(error))),
            Refusal::OffsetMismatch | Refusal::Other => return Err(error),
        }
    }
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
    let Content::Path(path) = request.content else {
        return Ok(None);
    };
    let drop_it = |cancel: bool| -> Result<Option<Landed>> {
        if cancel {
            let _ = tus.delete(&rec.upload_id);
        }
        records.delete(key)?;
        Ok(None)
    };
    let Some((offset, length)) = tus.head(&rec.upload_id)? else {
        // Gone: it landed (and the answer was lost), or it was refused or
        // swept.
        records.delete(key)?;
        if tus.has_version(&request.file.id, &rec.upload_id)? {
            return Ok(Some(Landed::Stored(rec.upload_id.clone())));
        }
        return Ok(None);
    };
    if length != rec.cipher_total || offset >= length || chunk_boundary(offset).is_none() {
        return drop_it(true);
    }
    let Some(header) = base64::engine::general_purpose::STANDARD
        .decode(&rec.header)
        .ok()
        .and_then(|h| <[u8; HEADER_BYTES]>::try_from(h).ok())
    else {
        return drop_it(true);
    };
    let context = DriveFileBlobContextV1::new(&request.file.id, rec.key_generation)?;
    let Ok(up) = StreamUploader::resume(
        LocalFile::open(path)?,
        request.file_key,
        rec.plain_size,
        &header,
        offset,
        context,
    ) else {
        return drop_it(true);
    };
    bar.set_position(up.plain_read() as u64);
    let rebuild = |at: i64| {
        StreamUploader::resume(
            LocalFile::open(path)?,
            request.file_key,
            rec.plain_size,
            &header,
            at,
            context,
        )
    };
    let mut state = rec.clone();
    send(
        tus,
        records,
        Some(key),
        &mut state,
        up,
        offset,
        bar,
        &request.sha256,
        rebuild,
    )
    .map(Some)
}

/// Sends the remaining parts. The last goes only once what was sealed is
/// what was hashed before (the SHA-256 the metadata carries): a file changed
/// meanwhile cancels the upload, as the server cannot tell. A part refused
/// for its offset goes on from where the server is (`rebuild` makes the
/// stream from an offset). A conflict when the last part lands is
/// [`Landed::Conflict`] (the server has discarded the upload); a lasting
/// refusal cancels it; anything else keeps the record for a later run.
#[allow(clippy::too_many_arguments)]
fn send<R: Read>(
    tus: &impl VersionTus,
    records: &impl ResumeRecords,
    key: Option<&str>,
    rec: &mut ResumeState,
    mut up: StreamUploader<R>,
    mut offset: i64,
    bar: &ProgressBar,
    sha256: &[u8; 32],
    rebuild: impl Fn(i64) -> Result<StreamUploader<R>>,
) -> Result<Landed> {
    let mut version_id = String::new();
    let mut resyncs = 0;
    loop {
        let next = up.next_chunk().and_then(|chunk| match chunk {
            Some(_) if up.finished() => up.check_sha256(sha256).map(|()| chunk),
            chunk => Ok(chunk),
        });
        let chunk = match next {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                bar.finish_and_clear();
                if error.is::<ChangedWhileUploading>() {
                    let _ = tus.delete(&rec.upload_id);
                    if let Some(key) = key {
                        records.delete(key)?;
                    }
                }
                return Err(error);
            }
        };
        let error = match tus.patch(&rec.upload_id, offset, chunk) {
            Ok(patched) => {
                offset = patched.offset;
                if !patched.version_id.is_empty() {
                    version_id = patched.version_id;
                }
                rec.updated_at = now_unix();
                if let Some(key) = key {
                    let _ = records.save(key, rec);
                }
                bar.set_position(up.plain_read() as u64);
                continue;
            }
            Err(error) => error,
        };
        let refused = refusal(&error);
        if matches!(refused, Refusal::OffsetMismatch) && resyncs < MAX_RESYNCS {
            resyncs += 1;
            match tus.head(&rec.upload_id)? {
                Some((at, _)) if chunk_boundary(at).is_some() && at < rec.cipher_total => {
                    up = rebuild(at)?;
                    offset = at;
                    bar.set_position(up.plain_read() as u64);
                    continue;
                }
                // Gone: it landed while the answer was lost, or it ended.
                None if tus.has_version(&rec.file_id, &rec.upload_id)? => {
                    if let Some(key) = key {
                        records.delete(key)?;
                    }
                    return Ok(Landed::Stored(rec.upload_id.clone()));
                }
                _ => {}
            }
        }
        bar.finish_and_clear();
        let conflict = matches!(refused, Refusal::Conflict);
        if let Some(key) = key {
            if conflict || is_permanent(&error) {
                records.delete(key)?;
            }
        }
        if conflict {
            return Ok(Landed::Conflict(error));
        }
        if is_permanent(&error) || key.is_none() {
            let _ = tus.delete(&rec.upload_id);
            return Err(error.context("upload new version"));
        }
        let percent = offset * 100 / rec.cipher_total.max(1);
        return Err(error.context(format!(
            "new version interrupted at {percent}% — run it again to go on from there"
        )));
    }
    bar.finish_and_clear();
    if offset != rec.cipher_total {
        bail!("the file changed while it was read; run it again");
    }
    if let Some(key) = key {
        records.delete(key)?;
    }
    // The upload's id is the version's.
    if version_id.is_empty() {
        version_id = rec.upload_id.clone();
    }
    Ok(Landed::Stored(version_id))
}

/// How many times one run goes on from the server's offset after a part
/// was refused for its own.
const MAX_RESYNCS: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::FileMetadata;
    use kutup_crypto::stream::CHUNK_SIZE;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    const FOLDER: &str = "11111111-1111-4111-8111-111111111111";

    /// An open upload: its length, what arrived, its metadata.
    type Open = (i64, Vec<u8>, VersionUploadMeta);

    /// A tus server in memory: one version upload at a time.
    #[derive(Default)]
    struct FakeTus {
        uploads: RefCell<HashMap<String, Open>>,
        stored: RefCell<Vec<(String, Vec<u8>, VersionUploadMeta)>>,
        creates: Cell<u32>,
        patches: Cell<u32>,
        /// Fail the PATCH with this number (1-based) once, as a dropped link.
        fail_patch: Cell<Option<u32>>,
        /// Take the PATCH with this number, but answer tus's offset
        /// mismatch (an answer that went astray, the part sent again).
        skew_patch: Cell<Option<u32>>,
        /// Refuse when the upload opens: `basedOn` is not what the file holds.
        conflict_at_open: Cell<bool>,
        /// Refuse when the last part lands, as a file that moved on.
        conflict_at_finish: Cell<bool>,
        /// Seconds since the open upload's last part.
        idle: Cell<i64>,
        /// The open upload is someone else's.
        foreign: Cell<bool>,
        deletes: Cell<u32>,
    }

    fn api(status: u16, body: &str) -> anyhow::Error {
        anyhow::Error::new(ApiError::from_parts(status, "", body.into()))
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
                    format!(r#","uploadId":"{open}""#)
                };
                return Err(api(
                    409,
                    &format!(
                        r#"{{"error":"open","code":"versionUploading","idleSeconds":{}{ours}}}"#,
                        self.idle.get()
                    ),
                ));
            }
            let id = uuid::Uuid::new_v4().to_string();
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
            let mut uploads = self.uploads.borrow_mut();
            let (total, body, _) = uploads.get_mut(id).context("no upload")?;
            if offset != body.len() as i64 {
                return Err(api(409, "Upload-Offset mismatch"));
            }
            body.extend_from_slice(&chunk);
            if self.skew_patch.get() == Some(n) {
                self.skew_patch.set(None);
                return Err(api(409, "Upload-Offset mismatch"));
            }
            let (total, at) = (*total, body.len() as i64);
            if at < total {
                return Ok(Patched {
                    offset: at,
                    ..Default::default()
                });
            }
            let (_, body, meta) = uploads.remove(id).unwrap();
            if self.conflict_at_finish.get() {
                return Err(api(
                    409,
                    r#"{"error":"moved on","code":"revision_conflict"}"#,
                ));
            }
            self.stored.borrow_mut().push((id.to_string(), body, meta));
            Ok(Patched {
                offset: at,
                file_id: String::new(),
                version_id: id.to_string(),
            })
        }
        fn delete(&self, id: &str) -> Result<()> {
            self.deletes.set(self.deletes.get() + 1);
            self.uploads.borrow_mut().remove(id);
            Ok(())
        }
        fn has_version(&self, _: &str, id: &str) -> Result<bool> {
            Ok(self.stored.borrow().iter().any(|(v, _, _)| v == id))
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

    fn file() -> (File, [u8; 32]) {
        let meta = FileMetadata {
            name: "big.bin".into(),
            mime_type: "application/octet-stream".into(),
            size: 1,
            sha256: None,
            media: None,
        };
        let created = crate::file_crypto::create(FOLDER, 1, &[3u8; 32], &meta).unwrap();
        (
            File {
                content_hash: None,
                name_hash: None,
                id: created.id,
                collection_id: FOLDER.into(),
                metadata_envelope: created.metadata_envelope,
                file_key_envelope: created.file_key_envelope,
                key_epoch: 1,
                key_generation: created.key_generation,
                metadata_revision: created.metadata_revision,
                encrypted_size_bytes: 0,
                created_at: String::new(),
                content_key_generation: 1,
                original_key_generation: 1,
                key_history: Vec::new(),
            },
            created.file_key,
        )
    }

    fn request<'a>(
        file: &'a File,
        key: &'a [u8; 32],
        content: Content<'a>,
        hash_key: &'a [u8; 32],
    ) -> VersionRequest<'a> {
        use sha2::Digest;
        let sha256 = match &content {
            Content::Path(path) => sha2::Sha256::digest(std::fs::read(path).unwrap()).into(),
            Content::Bytes(bytes) => sha2::Sha256::digest(bytes).into(),
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
        }
    }

    /// Three parts (the stream's chunk size is fixed by the format: 5 MiB),
    /// cut after the first; the second run goes on from there and the
    /// version, its metadata and content hash land together.
    #[test]
    fn a_large_version_resumes_where_it_stopped() {
        let (file, key) = file();
        let plain: Vec<u8> = (0..2 * CHUNK_SIZE + 777).map(|i| (i % 249) as u8).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, &plain).unwrap();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.fail_patch.set(Some(2));

        let cut = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key),
        );
        assert!(cut.is_err(), "the dropped link stops the run");
        assert_eq!(records.0.borrow().len(), 1, "the record stays to resume");

        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key),
        )
        .unwrap();
        let Landed::Stored(version) = landed else {
            panic!("stored: {landed:?}")
        };
        assert_eq!(tus.creates.get(), 1, "resumed, not opened again");
        assert_eq!(tus.patches.get(), 4, "one part twice, two more after it");
        assert!(records.0.borrow().is_empty());

        let stored = tus.stored.borrow();
        let (id, body, meta) = &stored[0];
        assert_eq!(id, &version);
        assert_eq!(body.len() as i64, cipher_size(plain.len() as i64));
        let opened = kutup_crypto::drive_object::decrypt_file_blob(
            body,
            &key,
            DriveFileBlobContextV1::new(&file.id, file.key_generation).unwrap(),
        )
        .unwrap();
        assert_eq!(opened, plain);
        assert_eq!(meta.metadata_revision, file.metadata_revision + 1);
        assert_eq!(
            meta.content_hash.as_deref(),
            Some(
                crate::names::content_hash(&hash_key, &{
                    use sha2::Digest;
                    sha2::Sha256::digest(&plain).into()
                })
                    .unwrap()
                    .as_str()
            )
        );
        let next = File {
            metadata_envelope: meta.metadata_envelope.clone(),
            metadata_revision: meta.metadata_revision,
            ..file.clone()
        };
        let metadata = crate::file_crypto::open_metadata(&next, &key).unwrap();
        assert_eq!(metadata.size, plain.len() as u64);
        assert_eq!(metadata.name, "big.bin");
    }

    #[test]
    fn a_conflict_when_it_lands_is_reported_not_retried() {
        let (file, key) = file();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"edited").unwrap();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.conflict_at_finish.set(true);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Path(&path), &hash_key),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Conflict(_)));
        assert_eq!(tus.creates.get(), 1);
        assert!(records.0.borrow().is_empty());
    }

    /// A run that crashed right after opening its upload (no part sent, no
    /// record kept): the next save finds it idle past the threshold,
    /// cancels it and saves.
    #[test]
    fn an_upload_left_by_a_crash_is_cancelled_and_the_save_goes_on() {
        let (file, key) = file();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let left = tus.create(1, &VersionUploadMeta::default()).unwrap();
        tus.idle.set(VAULT_CRASHED_AFTER_SECS);
        let landed = upload_version(
            &tus,
            &records,
            request(&file, &key, Content::Bytes(b"v2"), &hash_key),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)));
        assert!(
            tus.head(&left).unwrap().is_none(),
            "the old one is cancelled"
        );
        assert_eq!(tus.deletes.get(), 1);
        assert_eq!(tus.stored.borrow().len(), 1);
    }

    /// Ours but still moving (another device of the account), or someone
    /// else's: busy, never cancelled; once the slot frees, the save lands.
    #[test]
    fn an_upload_still_moving_is_busy_and_never_cancelled() {
        let (file, key) = file();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let other = tus.create(1, &VersionUploadMeta::default()).unwrap();
        for (idle, foreign) in [(VAULT_CRASHED_AFTER_SECS - 1, false), (9999, true)] {
            tus.idle.set(idle);
            tus.foreign.set(foreign);
            let landed = upload_version(
                &tus,
                &records,
                request(&file, &key, Content::Bytes(b"v2"), &hash_key),
            )
            .unwrap();
            assert!(matches!(landed, Landed::Busy), "{landed:?}");
        }
        // A Drive file waits much longer before taking an upload as left.
        tus.idle.set(VAULT_CRASHED_AFTER_SECS * 5);
        tus.foreign.set(false);
        let mut slow = request(&file, &key, Content::Bytes(b"v2"), &hash_key);
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
            request(&file, &key, Content::Bytes(b"v2"), &hash_key),
        )
        .unwrap();
        assert!(matches!(landed, Landed::Stored(_)));
        assert_eq!(tus.deletes.get(), 0);
    }

    fn big(dir: &tempfile::TempDir) -> (std::path::PathBuf, Vec<u8>) {
        let plain: Vec<u8> = (0..2 * CHUNK_SIZE + 31).map(|i| (i % 247) as u8).collect();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, &plain).unwrap();
        (path, plain)
    }

    /// The server took a part but its answer was lost and the part went
    /// again: tus's offset mismatch is not a conflict; the upload asks where
    /// the server is and goes on from there.
    #[test]
    fn an_offset_mismatch_goes_on_from_the_server_offset() {
        let (file, key) = file();
        let dir = tempfile::tempdir().unwrap();
        let (path, plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.skew_patch.set(Some(1));
        let landed =
            upload_version(&tus, &records, request(&file, &key, Content::Path(&path), &hash_key))
                .unwrap();
        assert!(matches!(landed, Landed::Stored(_)), "{landed:?}");
        assert_eq!(tus.patches.get(), 3, "the taken part is not sent again");
        let stored = tus.stored.borrow();
        let opened = kutup_crypto::drive_object::decrypt_file_blob(
            &stored[0].1,
            &key,
            DriveFileBlobContextV1::new(&file.id, file.key_generation).unwrap(),
        )
        .unwrap();
        assert_eq!(opened, plain);
    }

    /// A push made from a version the file no longer holds: refused when it
    /// opens, reported as a conflict (the sync then keeps both).
    #[test]
    fn a_based_on_conflict_is_a_conflict() {
        let (file, key) = file();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        tus.conflict_at_open.set(true);
        let mut req = request(&file, &key, Content::Bytes(b"mine"), &hash_key);
        req.based_on = Some("v3".into());
        let landed = upload_version(&tus, &records, req).unwrap();
        assert!(matches!(landed, Landed::Conflict(_)), "{landed:?}");
        assert_eq!(tus.patches.get(), 0, "nothing sent");
    }

    /// The file grew while it was read: never cut to the measured size.
    #[test]
    fn a_file_that_grows_while_uploading_fails() {
        let (file, key) = file();
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.bin");
        std::fs::write(&path, b"first").unwrap();
        let mut req = request(&file, &key, Content::Path(&path), &hash_key);
        // Measured and hashed, then appended to before it is read.
        std::fs::write(&path, b"first and more").unwrap();
        req.sha256 = {
            use sha2::Digest;
            sha2::Sha256::digest(b"first").into()
        };
        let error = upload_version_measured(&tus, &records, req, 5).unwrap_err();
        assert!(error.is::<ChangedWhileUploading>(), "{error:#}");
        assert!(tus.stored.borrow().is_empty());
        assert_eq!(tus.deletes.get(), 1, "the upload is cancelled");
    }

    /// A change of the same size between the hash and the upload: the last
    /// part is held back, the upload cancelled, nothing stored.
    #[test]
    fn a_same_size_change_is_caught_by_the_hash() {
        let (file, key) = file();
        let dir = tempfile::tempdir().unwrap();
        let (path, mut plain) = big(&dir);
        let (tus, records, hash_key) = (FakeTus::default(), Records::default(), [6u8; 32]);
        let req = request(&file, &key, Content::Path(&path), &hash_key);
        plain[CHUNK_SIZE + 5] ^= 0xff;
        std::fs::write(&path, &plain).unwrap();
        let error = upload_version(&tus, &records, req).unwrap_err();
        assert!(error.is::<ChangedWhileUploading>(), "{error:#}");
        assert_eq!(tus.patches.get(), 2, "the last of three parts is held back");
        assert_eq!(tus.deletes.get(), 1);
        assert!(tus.stored.borrow().is_empty());
        assert!(records.0.borrow().is_empty());
    }
}
