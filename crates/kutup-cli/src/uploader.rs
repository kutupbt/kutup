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
use rand::RngCore;

use crate::api::{ApiError, Client, CreateCollectionRequest, FileMetadata};
use crate::mimetype::guess_mime;
use crate::session::{ResumeState, Store};
use crate::transfer::{chunk_boundary, cipher_size, StreamUploader};
use kutup_crypto::secretbox;
use kutup_crypto::stream::HEADER_BYTES;

/// Local resume records older than this are swept (the server reaps its
/// side at 24 h; one extra hour avoids racing it).
pub const RESUME_MAX_IDLE_SECS: i64 = 25 * 3600;

pub enum Progress {
    Bar,
    /// Silent (the sync engine narrates per-file lines itself).
    #[allow(dead_code)]
    Quiet,
}

/// A finished upload: the server file id + the file key (the whiteboard
/// asset step re-uses the key after upload).
pub struct Uploaded {
    pub file_id: String,
    #[allow(dead_code)]
    pub file_key: [u8; 32],
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
    collection_id: &str,
    collection_key: &[u8],
    resume: bool,
    progress: Progress,
) -> Result<Uploaded> {
    let canonical = std::fs::canonicalize(local_path).unwrap_or_else(|_| local_path.to_path_buf());
    let resume_key = format!("{collection_id}\n{}", canonical.display());

    let meta_fs = std::fs::metadata(local_path)?;
    let plain_size = meta_fs.len() as i64;
    let (mtime_secs, mtime_nanos) = mtime_parts(&meta_fs);

    if let Some(rec) = store.get_resume(&resume_key)? {
        let unchanged = rec.plain_size == plain_size
            && rec.mtime_secs == mtime_secs
            && rec.mtime_nanos == mtime_nanos;
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
    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);

    let name = file_name(&local_path.to_string_lossy());
    let meta = FileMetadata {
        name: name.clone(),
        mime_type: guess_mime(local_path),
        size: plain_size,
    };
    let meta_bytes = serde_json::to_vec(&meta)?;
    let (enc_meta, meta_nonce) =
        secretbox::seal(&meta_bytes, &file_key).context("encrypt metadata")?;
    let (enc_file_key, file_key_nonce) =
        secretbox::seal(&file_key, collection_key).context("wrap file key")?;

    let cipher_total = cipher_size(plain_size);
    let (upload_id, file_id_hint) = client
        .tus_create(
            cipher_total,
            collection_id,
            &b64().encode(&enc_meta),
            &b64().encode(meta_nonce),
            &b64().encode(&enc_file_key),
            &b64().encode(file_key_nonce),
        )
        .context("tus create")?;

    let file = File::open(local_path)?;
    let up = StreamUploader::new(file, &file_key, plain_size)?;

    let now = now_unix();
    let mut rec = ResumeState {
        upload_id,
        file_id: file_id_hint,
        enc_file_key: b64().encode(&enc_file_key),
        file_key_nonce: b64().encode(file_key_nonce),
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
    Ok(Uploaded { file_id, file_key })
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
                        let file_key = unwrap_file_key(rec, collection_key)?;
                        let _ = store.delete_resume(resume_key);
                        eprintln!("Previous upload had already completed.");
                        return Ok(Some(Uploaded {
                            file_id: rec.file_id.clone(),
                            file_key,
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

            let file_key = match unwrap_file_key(rec, collection_key) {
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
            let up = match StreamUploader::resume(file, &file_key, rec.plain_size, &header, offset)
            {
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
            Ok(Some(Uploaded { file_id, file_key }))
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

fn unwrap_file_key(rec: &ResumeState, collection_key: &[u8]) -> Result<[u8; 32]> {
    let key = secretbox::open_b64(&rec.enc_file_key, &rec.file_key_nonce, collection_key)
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
    master_key: &[u8],
) -> Result<(String, [u8; 32])> {
    let mut collection_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut collection_key);

    let (enc_key, key_nonce) = secretbox::seal(&collection_key, master_key)?;
    let (enc_name, name_nonce) = secretbox::seal(name.as_bytes(), &collection_key)?;

    let resp = client.create_collection(&CreateCollectionRequest {
        encrypted_name: b64().encode(&enc_name),
        name_nonce: b64().encode(name_nonce),
        encrypted_key: b64().encode(&enc_key),
        encrypted_key_nonce: b64().encode(key_nonce),
        parent_collection_id: Some(parent_id.to_string()),
    })?;
    Ok((resp.id, collection_key))
}
