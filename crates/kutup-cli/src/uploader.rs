//! Shared streaming tus uploader with resume — used by `upload` (and the
//! sync engine's push path), in the block format
//! (docs/plans/drive-block-format.md §2, §10 slice 3).
//!
//! A new file is uploaded as an uploaded revision (tus with `revisionId`),
//! then committed with its first metadata, which commits to the revision and
//! its manifest's digest (`revisions::commit_upload`). Resume: an
//! interrupted upload keeps `{upload id, wrapped file key, revision id, the
//! content's SHA-256, sizes, mtime}` and, once made, the sealed tail (never
//! the raw key). A later run asks the server where it stopped (any offset),
//! seals again from block 0 (synthetic nonces give the same bytes; the last
//! block goes only if the content hashes to the recorded SHA-256, else
//! `NotTheSameFile` discards the upload), sends the rest and commits; an
//! upload whose bytes all arrived but whose commit did not is committed.

use kutup_crypto::primitives::{Hasher, Suite};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine;
use indicatif::ProgressBar;

use crate::api::{ApiError, Client};
use crate::file_crypto;
use crate::mimetype::guess_mime;
use crate::revisions::{Base, CommitUpload, Draft};
use crate::session::{ResumeState, Store};
use crate::transfer::{BlockSource, ChangedWhileUploading, NotTheSameFile};
use crate::version_upload::{kept_tail, send_parts};
use kutup_crypto::drive_blocks::DriveBlobContextV2;

/// Local resume records older than this are swept (the server reaps its
/// side at 24 h; one extra hour avoids racing it).
pub const RESUME_MAX_IDLE_SECS: i64 = 25 * 3600;

pub enum Progress {
    Bar,
    /// Silent (the sync engine narrates per-file lines itself).
    Quiet,
}

/// Exact collection context and execution policy for one upload.
pub struct UploadRequest<'a> {
    pub collection_id: &'a str,
    pub key_epoch: u32,
    pub collection_key: &'a [u8],
    pub resume: bool,
    pub progress: Progress,
    /// The folder's hash key: the name's hash goes with the upload, so the
    /// server refuses a taken name before anything is sent
    /// (docs/plans/drive-unique-names.md).
    pub hash_key: [u8; 32],
    /// The name to upload under, when not the local file's own.
    pub name: Option<&'a str>,
    /// The content's SHA-256 when the caller has it already; read from the
    /// file otherwise.
    pub sha256: Option<[u8; 32]>,
}

/// A finished upload: the server file id + the file key (the whiteboard
/// asset step re-uses the key after upload).
pub struct Uploaded {
    pub file_id: String,
    pub file_key: [u8; 32],
    /// The file key's generation (a new file's first).
    pub key_generation: u32,
    /// The name it was committed under (the next free one when its own
    /// was taken while it uploaded).
    pub name: String,
}

/// A local file's SHA-256, read in 1 MiB pieces.
pub(crate) fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Hasher::new(Suite::V1);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(digest.finish().into())
}

/// Records the finished file's content hash; best effort (without it, the
/// same file uploaded again is not recognised as already there).
pub(crate) fn record_content_hash(
    client: &Client,
    file_id: &str,
    hash_key: &[u8; 32],
    sha256: &[u8; 32],
) {
    let recorded = crate::names::content_hash(hash_key, sha256)
        .and_then(|hash| client.set_content_hash(file_id, &hash));
    if let Err(e) = recorded {
        eprintln!("warning: could not record the content hash of {file_id}: {e:#}");
    }
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Uploads one file through tus with bounded memory and commits it,
/// resuming an interrupted prior attempt when `resume` is set and the file
/// is unchanged.
pub fn upload_streaming(
    client: &Client,
    store: &Store,
    local_path: &Path,
    request: UploadRequest<'_>,
) -> Result<Uploaded> {
    let UploadRequest {
        collection_id,
        key_epoch,
        collection_key,
        resume,
        progress,
        hash_key,
        name,
        sha256,
    } = request;
    let name = name
        .map(str::to_string)
        .unwrap_or_else(|| file_name(&local_path.to_string_lossy()));
    let canonical = std::fs::canonicalize(local_path).unwrap_or_else(|_| local_path.to_path_buf());
    let resume_key = format!("{collection_id}\n{}", canonical.display());

    let meta_fs = std::fs::metadata(local_path)?;
    let plain_size = meta_fs.len() as i64;
    let (mtime_secs, mtime_nanos) = mtime_parts(&meta_fs);
    let sha256 = match sha256 {
        Some(sha256) => sha256,
        None => sha256_file(local_path)?,
    };
    let sha256_b64 = b64().encode(sha256);
    let upload = Upload {
        client,
        store,
        resume_key: &resume_key,
        local_path,
        collection_id,
        hash_key: &hash_key,
        draft: Draft {
            name: name.clone(),
            mime_type: guess_mime(local_path),
            size: plain_size as u64,
            sha256: Some(sha256_b64.clone()),
            media: None,
            original_revision_id: None,
            state_revision_id: None,
            v: kutup_crypto::file_metadata::FILE_METADATA_VERSION,
            min: None,
            extra: Default::default(),
        },
        sha256,
        progress: &progress,
    };

    if let Some(rec) = store.get_resume(&resume_key)? {
        // The same file: its size, date and content (an upload of another
        // content under this path would be another file).
        let unchanged = rec.plain_size == plain_size
            && rec.mtime_secs == mtime_secs
            && rec.mtime_nanos == mtime_nanos
            && rec.key_epoch == key_epoch
            && rec.sha256 == sha256_b64
            && !rec.revision_id.is_empty();
        if resume && unchanged {
            if let Some(done) = try_resume(&upload, &rec, collection_key)? {
                return Ok(done);
            }
            // Invalid/stale state was cleaned up — fall through to a fresh upload.
        } else {
            // --no-resume, or another content than the attempt's: abandon it.
            let _ = client.tus_delete(&rec.upload_id);
            let _ = store.delete_resume(&resume_key);
        }
    }

    // Fresh upload: the file's key now, its metadata with the commit.
    let record = file_crypto::create(collection_id, key_epoch, collection_key)?;
    let revision_id = uuid::Uuid::new_v4().to_string();
    let cipher_total = crate::transfer::object_len(plain_size as u64)?;
    let (upload_id, file_id_hint) = client
        .tus_create(
            cipher_total,
            &record.id,
            collection_id,
            &record.file_key_envelope,
            &crate::names::name_hash(&hash_key, &name)?,
            &revision_id,
        )
        .context("tus create")?;
    if file_id_hint != record.id {
        let _ = client.tus_delete(&upload_id);
        bail!("tus create returned a different file id");
    }

    let now = now_unix();
    let mut rec = ResumeState {
        upload_id,
        file_id: record.id.clone(),
        file_key_envelope: record.file_key_envelope,
        key_epoch: record.key_epoch,
        revision_id,
        sha256: sha256_b64,
        plain_size,
        cipher_total,
        mtime_secs,
        mtime_nanos,
        created_at: now,
        updated_at: now,
        ..Default::default()
    };
    // Persist BEFORE the first PATCH: a crash at any later point leaves a
    // record + server session, which is exactly what resume needs.
    store.save_resume(&resume_key, &rec)?;
    upload.finish(&mut rec, &record.file_key, 0)
}

/// One new file's upload, as it runs.
struct Upload<'a> {
    client: &'a Client,
    store: &'a Store,
    resume_key: &'a str,
    local_path: &'a Path,
    collection_id: &'a str,
    hash_key: &'a [u8; 32],
    draft: Draft,
    sha256: [u8; 32],
    progress: &'a Progress,
}

impl Upload<'_> {
    fn forget(&self, cancel: Option<&str>) {
        if let Some(upload_id) = cancel {
            let _ = self.client.tus_delete(upload_id);
        }
        let _ = self.store.delete_resume(self.resume_key);
    }

    /// Sends the object from `offset`, then commits it.
    fn finish(&self, rec: &mut ResumeState, file_key: &[u8; 32], offset: i64) -> Result<Uploaded> {
        let identity = crate::drive_signer::identity(self.client)?;
        let context = DriveBlobContextV2::new(
            &rec.file_id,
            &rec.revision_id,
            file_crypto::FIRST_GENERATION,
        )?;
        let mut source = BlockSource::new(
            || Ok(File::open(self.local_path)?),
            file_key,
            context,
            identity.signer(),
            rec.plain_size as u64,
            self.sha256,
            kept_tail(rec)?,
        )?;
        if offset > 0 {
            eprintln!(
                "Resuming upload of {} at {}%",
                self.draft.name,
                offset * 100 / rec.cipher_total.max(1)
            );
        }
        let bar = make_bar(self.progress, rec.plain_size, &self.draft.name);
        let sent = send_parts(
            self.client,
            self.store,
            Some(self.resume_key),
            rec,
            &mut source,
            offset,
            &bar,
        );
        bar.finish_and_clear();
        if let Err(err) = sent {
            if err.is::<ChangedWhileUploading>() || err.is::<NotTheSameFile>() {
                self.forget(Some(&rec.upload_id));
                return Err(err);
            }
            if is_permanent(&err) {
                self.forget(Some(&rec.upload_id));
                if matches!(err.downcast_ref::<ApiError>(), Some(e) if e.status == 403) {
                    return Err(err.context(
                        "access to the folder was lost during the upload; it was discarded",
                    ));
                }
                return Err(err);
            }
            return Err(err.context(
                "upload interrupted — rerun the same command to resume \
                 (or pass --no-resume to restart)",
            ));
        }
        let content = source
            .content()
            .cloned()
            .context("the upload ended before its tail was made")?;
        self.commit(rec, file_key, &content)
    }

    /// Commits the uploaded revision as the new file, under the next free
    /// name if its own was taken meanwhile.
    fn commit(
        &self,
        rec: &ResumeState,
        file_key: &[u8; 32],
        content: &kutup_crypto::file_metadata::ContentCommitmentV1,
    ) -> Result<Uploaded> {
        let free_name = |taken: &str| {
            crate::revisions::free_name_in(self.client, self.collection_id, self.hash_key, taken)
        };
        let committed = crate::revisions::commit_upload(
            self.client,
            &CommitUpload {
                file_id: &rec.file_id,
                revision_id: &rec.revision_id,
                file_key,
                key_generation: file_crypto::FIRST_GENERATION,
                content,
                draft: self.draft.clone(),
                base: Base::NewFile,
                free_name: Some(&free_name),
            },
        );
        let name = match committed {
            Ok(name) => name,
            Err(err) => {
                return Err(match crate::revisions::conflict_code(&err) {
                    // Parts are missing: the next run sends them.
                    Some("notUploaded") => {
                        err.context("the upload is not complete; rerun the same command")
                    }
                    // Refused for good (the object lost, the name taken, the
                    // folder gone): the upload and its quota go.
                    _ if is_permanent(&err) => {
                        self.forget(Some(&rec.upload_id));
                        err.context("commit the upload; it was discarded")
                    }
                    _ => err.context("commit the upload — rerun the same command to commit it"),
                });
            }
        };
        self.forget(None);
        record_content_hash(self.client, &rec.file_id, self.hash_key, &self.sha256);
        Ok(Uploaded {
            file_id: rec.file_id.clone(),
            file_key: *file_key,
            key_generation: file_crypto::FIRST_GENERATION,
            name,
        })
    }
}

/// Attempts to continue `rec`. `Ok(Some)` = finished (resumed to the end
/// and committed, or the prior attempt turned out to be complete).
/// `Ok(None)` = state was unusable and has been cleaned up (caller starts
/// fresh). Transient transport errors propagate with the state kept.
fn try_resume(
    upload: &Upload<'_>,
    rec: &ResumeState,
    collection_key: &[u8],
) -> Result<Option<Uploaded>> {
    let client = upload.client;
    let file_key = match unwrap_file_key(rec, upload.collection_id, collection_key) {
        Ok(k) => k,
        Err(_) => {
            upload.forget(Some(&rec.upload_id));
            return Ok(None);
        }
    };
    let Ok(tail) = kept_tail(rec) else {
        upload.forget(Some(&rec.upload_id));
        return Ok(None);
    };
    let mut rec = rec.clone();
    match client.tus_head(&rec.upload_id)? {
        None => {
            // Session gone: committed before we could clear local state, or
            // the server swept it. With every byte sent (a tail), committing
            // again settles which.
            if let Some(tail) = tail {
                return match upload.commit(&rec, &file_key, &tail.content) {
                    Ok(done) => Ok(Some(done)),
                    Err(err) if crate::revisions::status_of(&err) == Some(404) => {
                        if client
                            .list_files(upload.collection_id)
                            .is_ok_and(|files| files.iter().any(|f| f.id == rec.file_id))
                        {
                            upload.forget(None);
                            eprintln!("Previous upload had already completed.");
                            return Ok(Some(Uploaded {
                                file_id: rec.file_id.clone(),
                                file_key,
                                key_generation: file_crypto::FIRST_GENERATION,
                                name: upload.draft.name.clone(),
                            }));
                        }
                        upload.forget(None);
                        Ok(None)
                    }
                    Err(err) => Err(err),
                };
            }
            upload.forget(None);
            Ok(None)
        }
        Some((offset, length)) if length != rec.cipher_total || offset > length => {
            upload.forget(Some(&rec.upload_id));
            Ok(None)
        }
        // Every byte arrived; only the commit is left.
        Some((offset, length)) if offset == length => match tail {
            Some(tail) => upload.commit(&rec, &file_key, &tail.content).map(Some),
            None => {
                upload.forget(Some(&rec.upload_id));
                Ok(None)
            }
        },
        Some((offset, _)) => upload.finish(&mut rec, &file_key, offset).map(Some),
    }
}

/// A 4xx (other than timeout/rate-limit) means the server rejected the
/// upload outright; retrying the same session is pointless.
pub(crate) fn is_permanent(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref::<ApiError>(),
             Some(e) if e.status < 500 && e.status != 408 && e.status != 429)
}

fn unwrap_file_key(
    rec: &ResumeState,
    collection_id: &str,
    collection_key: &[u8],
) -> Result<[u8; 32]> {
    // An upload in flight is a new file: its key's first generation.
    file_crypto::open_file_key(
        &rec.file_key_envelope,
        &rec.file_id,
        collection_id,
        rec.key_epoch,
        file_crypto::FIRST_GENERATION,
        collection_key,
    )
    .context("unwrap resumed file key")
}

pub(crate) fn mtime_parts(meta: &std::fs::Metadata) -> (i64, u32) {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unwrap_or((0, 0))
}

pub(crate) fn make_bar(progress: &Progress, plain_total: i64, name: &str) -> ProgressBar {
    match progress {
        Progress::Bar => crate::output::progress_bar(Some(plain_total.max(0) as u64), name),
        Progress::Quiet => ProgressBar::hidden(),
    }
}

/// Creates a sub-collection under `parent_id` (used by `upload -r` and the
/// sync engine), its name kept unique under the parent's hash key. Returns
/// `(collection_id, collection_key)`; a taken name is the server's
/// `name_taken` (`ApiError::name_taken`).
pub fn create_sub_collection(
    client: &Client,
    name: &str,
    parent_id: &str,
    parent_hash_key: &[u8; 32],
    owner_user_id: &str,
    session: &crate::session::Session,
) -> Result<(String, [u8; 32])> {
    let (mut request, collection_key) = crate::collection_crypto::create_owned(
        name,
        Some(parent_id.to_string()),
        owner_user_id,
        session,
    )?;
    request.name_hash = Some(crate::names::name_hash(parent_hash_key, name)?);
    let resp = client.create_collection(&request)?;
    Ok((resp.id, collection_key))
}
