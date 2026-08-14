//! Shared streaming tus uploader with resume — used by `upload` (and the
//! sync engine's push path).
//!
//! Resume model: ciphertext is deterministic given (file key, stream header)
//! — see `StreamEncryptor::resume` — so an interrupted upload persists only
//! `{upload_id, wrapped file key, header, sizes, mtime}` (never the raw key)
//! and a later run re-encrypts from byte 0, discards everything the server
//! already has (per `tus_head`), and transmits the remainder. Offsets always
//! sit on chunk boundaries because the CLI ships one chunk per PATCH and the
//! server advances by whole PATCH bodies.

use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine;
use indicatif::ProgressBar;

use crate::api::{ApiError, Client, FileMetadata};
use crate::file_crypto;
use crate::mimetype::guess_mime;
use crate::session::{ResumeState, Store};
use crate::transfer::{chunk_boundary, cipher_size, StreamUploader};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::DriveFileBlobContextV1;
use kutup_crypto::stream::HEADER_BYTES;

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
}

/// A finished upload: the server file id + the file key (the whiteboard
/// asset step re-uses the key after upload).
pub struct Uploaded {
    pub file_id: String,
    pub file_key: [u8; 32],
    pub collection_id: String,
    pub key_epoch: u32,
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

/// Uploads one file through tus with bounded memory, resuming an interrupted
/// prior attempt when `resume` is set and the file is unchanged.
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
    } = request;
    let canonical = std::fs::canonicalize(local_path).unwrap_or_else(|_| local_path.to_path_buf());
    let resume_key = format!("{collection_id}\n{}", canonical.display());

    let meta_fs = std::fs::metadata(local_path)?;
    let plain_size = meta_fs.len() as i64;
    let (mtime_secs, mtime_nanos) = mtime_parts(&meta_fs);

    if let Some(rec) = store.get_resume(&resume_key)? {
        let unchanged = rec.plain_size == plain_size
            && rec.mtime_secs == mtime_secs
            && rec.mtime_nanos == mtime_nanos
            && rec.key_epoch == key_epoch;
        if resume && unchanged {
            if let Some(done) = try_resume(
                client,
                store,
                &resume_key,
                &rec,
                local_path,
                collection_id,
                collection_key,
                &progress,
            )? {
                return Ok(done);
            }
            // Invalid/stale state was cleaned up — fall through to a fresh upload.
        } else {
            // --no-resume, or the file changed since the attempt: abandon it.
            let _ = client.tus_delete(&rec.upload_id);
            let _ = store.delete_resume(&resume_key);
        }
    }

    // Fresh upload.
    let name = file_name(&local_path.to_string_lossy());
    let meta = FileMetadata {
        name: name.clone(),
        mime_type: guess_mime(local_path),
        size: plain_size,
    };
    let record = file_crypto::create(collection_id, key_epoch, collection_key, &meta)?;
    debug_assert_eq!(record.metadata_revision, 1);

    let cipher_total = cipher_size(plain_size);
    let (upload_id, file_id_hint) = client
        .tus_create(
            cipher_total,
            &record.id,
            collection_id,
            &record.metadata_envelope,
            &record.file_key_envelope,
        )
        .context("tus create")?;
    if file_id_hint != record.id {
        bail!("tus create returned a different file id");
    }

    let file = File::open(local_path)?;
    let blob_context = DriveFileBlobContextV1::new(&record.id, collection_id, record.key_epoch)?;
    let up = StreamUploader::new(file, &record.file_key, plain_size, blob_context)?;

    let now = now_unix();
    let mut rec = ResumeState {
        upload_id,
        file_id: file_id_hint,
        file_key_envelope: record.file_key_envelope,
        key_epoch: record.key_epoch,
        header: b64().encode(up.header_bytes()),
        plain_size,
        cipher_total,
        mtime_secs,
        mtime_nanos,
        created_at: now,
        updated_at: now,
    };
    // Persist BEFORE the first PATCH: a crash at any later point leaves a
    // record + server session, which is exactly what resume needs.
    store.save_resume(&resume_key, &rec)?;

    let bar = make_bar(&progress, plain_size, &name);
    let patched_id = run_patches(client, store, &resume_key, &mut rec, up, 0, &bar)?;
    let _ = store.delete_resume(&resume_key);

    let file_id = pick_file_id(patched_id, &rec)?;
    Ok(Uploaded {
        file_id,
        file_key: record.file_key,
        collection_id: collection_id.to_string(),
        key_epoch: record.key_epoch,
    })
}

/// Attempts to continue `rec`. `Ok(Some)` = finished (either resumed to the
/// end, or the prior attempt turned out to be complete). `Ok(None)` = state
/// was unusable and has been cleaned up (caller starts fresh). Transient
/// transport errors propagate with the state kept.
#[allow(clippy::too_many_arguments)]
fn try_resume(
    client: &Client,
    store: &Store,
    resume_key: &str,
    rec: &ResumeState,
    local_path: &Path,
    collection_id: &str,
    collection_key: &[u8],
    progress: &Progress,
) -> Result<Option<Uploaded>> {
    match client.tus_head(&rec.upload_id)? {
        None => {
            // Session gone: either it finished and we crashed before clearing
            // local state, or the server swept it.
            if !rec.file_id.is_empty() {
                if let Ok(files) = client.list_files(collection_id) {
                    if files.iter().any(|f| f.id == rec.file_id) {
                        let file_key = unwrap_file_key(rec, collection_id, collection_key)?;
                        let _ = store.delete_resume(resume_key);
                        eprintln!("Previous upload had already completed.");
                        return Ok(Some(Uploaded {
                            file_id: rec.file_id.clone(),
                            file_key,
                            collection_id: collection_id.to_string(),
                            key_epoch: rec.key_epoch,
                        }));
                    }
                }
            }
            let _ = store.delete_resume(resume_key);
            Ok(None)
        }
        Some((offset, length)) => {
            if length != rec.cipher_total
                || offset >= rec.cipher_total
                || chunk_boundary(offset).is_none()
            {
                let _ = client.tus_delete(&rec.upload_id);
                let _ = store.delete_resume(resume_key);
                return Ok(None);
            }

            let file_key = match unwrap_file_key(rec, collection_id, collection_key) {
                Ok(k) => k,
                Err(_) => {
                    let _ = client.tus_delete(&rec.upload_id);
                    let _ = store.delete_resume(resume_key);
                    return Ok(None);
                }
            };
            let header: [u8; HEADER_BYTES] = match b64()
                .decode(&rec.header)
                .ok()
                .and_then(|h| h.try_into().ok())
            {
                Some(h) => h,
                None => {
                    let _ = client.tus_delete(&rec.upload_id);
                    let _ = store.delete_resume(resume_key);
                    return Ok(None);
                }
            };

            let file = File::open(local_path)?;
            let blob_context =
                DriveFileBlobContextV1::new(&rec.file_id, collection_id, rec.key_epoch)?;
            let up = match StreamUploader::resume(
                file,
                &file_key,
                rec.plain_size,
                &header,
                offset,
                blob_context,
            ) {
                Ok(up) => up,
                Err(_) => {
                    let _ = client.tus_delete(&rec.upload_id);
                    let _ = store.delete_resume(resume_key);
                    return Ok(None);
                }
            };

            let name = file_name(&local_path.to_string_lossy());
            eprintln!(
                "Resuming upload of {name} at {}%",
                offset * 100 / rec.cipher_total.max(1)
            );
            let bar = make_bar(progress, rec.plain_size, &name);
            bar.set_position(up.plain_read() as u64);

            let mut rec = rec.clone();
            let patched_id = run_patches(client, store, resume_key, &mut rec, up, offset, &bar)?;
            let _ = store.delete_resume(resume_key);

            let file_id = pick_file_id(patched_id, &rec)?;
            Ok(Some(Uploaded {
                file_id,
                file_key,
                collection_id: collection_id.to_string(),
                key_epoch: rec.key_epoch,
            }))
        }
    }
}

/// Ships remaining chunks. On a permanent (4xx) rejection the session and
/// local state are dropped; on a transient failure the state is kept and the
/// error tells the user to rerun.
fn run_patches(
    client: &Client,
    store: &Store,
    resume_key: &str,
    rec: &mut ResumeState,
    mut up: StreamUploader<File>,
    mut offset: i64,
    bar: &ProgressBar,
) -> Result<String> {
    let mut file_id = String::new();
    #[cfg(feature = "fail-inject")]
    let mut patches_done: u32 = 0;
    loop {
        let Some(chunk) = up.next_chunk()? else { break };
        match client.tus_patch(&rec.upload_id, offset, chunk) {
            Ok((new_offset, final_id)) => {
                offset = new_offset;
                if !final_id.is_empty() {
                    file_id = final_id;
                }
                rec.updated_at = now_unix();
                let _ = store.save_resume(resume_key, rec);
                bar.set_position(up.plain_read() as u64);
                #[cfg(feature = "fail-inject")]
                {
                    patches_done += 1;
                    maybe_abort(patches_done);
                }
            }
            Err(err) => {
                bar.finish_and_clear();
                if is_permanent(&err) {
                    let _ = client.tus_delete(&rec.upload_id);
                    let _ = store.delete_resume(resume_key);
                    return Err(err);
                }
                let pct = offset * 100 / rec.cipher_total.max(1);
                return Err(err.context(format!(
                    "upload interrupted at {pct}% — rerun the same command to resume \
                     (or pass --no-resume to restart)"
                )));
            }
        }
    }
    bar.finish_and_clear();
    Ok(file_id)
}

/// A 4xx (other than timeout/rate-limit) means the server rejected the
/// upload outright; retrying the same session is pointless.
fn is_permanent(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref::<ApiError>(),
             Some(e) if e.status < 500 && e.status != 408 && e.status != 429)
}

fn pick_file_id(patched_id: String, rec: &ResumeState) -> Result<String> {
    if !patched_id.is_empty() {
        return Ok(patched_id);
    }
    if !rec.file_id.is_empty() {
        return Ok(rec.file_id.clone());
    }
    bail!("tus: upload completed but server returned no file id")
}

fn unwrap_file_key(
    rec: &ResumeState,
    collection_id: &str,
    collection_key: &[u8],
) -> Result<[u8; 32]> {
    let context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::FileKey,
        rec.key_epoch,
        1,
        &rec.file_id,
        collection_id,
    )?;
    let key = drive_envelope::open_b64(&rec.file_key_envelope, collection_key, context)
        .context("unwrap resumed file key")?;
    key.try_into()
        .map_err(|_| anyhow::anyhow!("resumed file key has wrong length"))
}

fn mtime_parts(meta: &std::fs::Metadata) -> (i64, u32) {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unwrap_or((0, 0))
}

fn make_bar(progress: &Progress, plain_total: i64, name: &str) -> ProgressBar {
    match progress {
        Progress::Bar => crate::output::progress_bar(Some(plain_total.max(0) as u64), name),
        Progress::Quiet => ProgressBar::hidden(),
    }
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

/// Creates a sub-collection under `parent_id` (used by `upload -r` and the
/// sync engine). Returns `(collection_id, collection_key)`.
pub fn create_sub_collection(
    client: &Client,
    name: &str,
    parent_id: &str,
    owner_user_id: &str,
    master_key: &[u8],
) -> Result<(String, [u8; 32])> {
    let (request, collection_key) = crate::collection_crypto::create_owned(
        name,
        Some(parent_id.to_string()),
        owner_user_id,
        master_key,
    )?;
    let resp = client.create_collection(&request)?;
    Ok((resp.id, collection_key))
}
