//! `kutup upload` — encrypt and stream-upload a file or directory via tus,
//! resuming interrupted uploads automatically (see `crate::uploader`).
//! Whiteboards (`.excalidraw`) additionally get their embedded images
//! extracted as encrypted asset blobs (see `crate::whiteboard`).
//!
//! Names are unique in a folder (docs/plans/drive-unique-names.md): a file
//! already there under its name with the same content is skipped; a
//! different one stops the upload unless `--keep-both` puts it beside as
//! `name (2)`. A directory goes into a folder of the same name when there
//! is one, so uploading it again sends only what is new or changed.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::api::{ApiError, Client, Collection, NameHolder};
use crate::context::require_session;
use crate::cryptohelpers::{
    decrypt_collection_key, decrypt_collections, decrypt_file_meta, find_collection,
};
use crate::keyring::Keyring;
use crate::session::{Session, Store};
use crate::uploader::{
    self, create_sub_collection, file_name, now_unix, Naming, Progress, UploadRequest, Uploaded,
    RESUME_MAX_IDLE_SECS,
};

#[allow(clippy::too_many_arguments)]
pub fn run(
    profile: &str,
    json: bool,
    local_path: &str,
    collection_id: &str,
    recursive: bool,
    no_resume: bool,
    keep_both: bool,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    // Sweep resume records the server has certainly reaped by now, and
    // best-effort abort their sessions.
    if let Ok(stale) = ctx.store.sweep_resume(RESUME_MAX_IDLE_SECS, now_unix()) {
        for (_, rec) in &stale {
            if !rec.upload_id.is_empty() {
                let _ = ctx.client.tus_delete(&rec.upload_id);
            }
        }
    }

    let cols = decrypt_collections(ctx.client.list_collections()?, &master_key, &ctx.session);
    let col = find_collection(&cols, collection_id)
        .ok_or_else(|| crate::errors::NotFound(format!("collection {collection_id} not found")))?;
    let up = Uploads {
        client: &ctx.client,
        store: &ctx.store,
        session: &ctx.session,
        master_key: &master_key,
        cols: &cols,
        no_resume,
        keep_both,
    };
    let target = up.target(col).context("decrypt collection key")?;

    let meta = std::fs::metadata(local_path)?;
    if meta.is_dir() {
        if !recursive {
            bail!("{local_path} is a directory — use --recursive to upload directories");
        }
        let mut stats = DirUpload::default();
        up.dir(Path::new(local_path), &target, &mut stats)?;
        if json {
            crate::output::print_json(&serde_json::json!({
                "collectionId": collection_id,
                "uploaded": stats.uploaded,
                "alreadyThere": stats.already_there,
                "warnings": stats.warnings,
            }))?;
        } else {
            let mut summary = format!("Uploaded {} file(s)", stats.uploaded.len());
            if !stats.already_there.is_empty() {
                summary += &format!(", {} already there", stats.already_there.len());
            }
            if !stats.warnings.is_empty() {
                summary += &format!(", {} warning(s)", stats.warnings.len());
            }
            println!("{summary}");
        }
        return Ok(());
    }

    match up.file(Path::new(local_path), &target, Progress::Bar)? {
        Placed::Uploaded(done) => {
            extract_whiteboard_assets(&ctx.client, &done, Path::new(local_path), &mut Vec::new());
            if json {
                crate::output::print_json(
                    &serde_json::json!({ "id": done.file_id, "name": done.name }),
                )?;
            } else {
                println!("Uploaded {}  id={}", done.name, done.file_id);
            }
        }
        Placed::AlreadyThere(id) => {
            let name = file_name(local_path);
            if json {
                crate::output::print_json(
                    &serde_json::json!({ "id": id, "name": name, "alreadyThere": true }),
                )?;
            } else {
                println!("Already there: {name}  id={id}");
            }
        }
    }
    Ok(())
}

/// A folder to upload into: its key and its names' hash key.
struct Target {
    id: String,
    key_epoch: u32,
    key: Vec<u8>,
    hash_key: [u8; 32],
}

/// What putting a file into a folder came to.
enum Placed {
    Uploaded(Uploaded),
    /// The same file is there under that name (its id).
    AlreadyThere(String),
}

struct Uploads<'a> {
    client: &'a Client,
    store: &'a Store,
    session: &'a Session,
    master_key: &'a [u8],
    cols: &'a [Collection],
    no_resume: bool,
    keep_both: bool,
}

impl Uploads<'_> {
    fn target(&self, col: &Collection) -> Result<Target> {
        let key = decrypt_collection_key(col, self.master_key, self.session)?;
        let keys = Keyring::load(self.client, col, &key, self.master_key)?;
        Ok(Target {
            id: col.id.clone(),
            key_epoch: col.key_epoch,
            hash_key: crate::names::folder_hash_key(&keys, &col.id)?,
            key,
        })
    }

    fn upload(
        &self,
        path: &Path,
        target: &Target,
        name: Option<&str>,
        progress: Progress,
    ) -> Result<Uploaded> {
        uploader::upload_streaming(
            self.client,
            self.store,
            path,
            UploadRequest {
                collection_id: &target.id,
                key_epoch: target.key_epoch,
                collection_key: &target.key,
                resume: !self.no_resume,
                progress,
                naming: Naming::Claim(target.hash_key),
                name,
            },
        )
    }

    /// One file into `target` under its name: uploaded, already there, or
    /// (`--keep-both`) beside the different file holding the name.
    fn file(&self, path: &Path, target: &Target, progress: Progress) -> Result<Placed> {
        let name = file_name(&path.to_string_lossy());
        let quiet = matches!(progress, Progress::Quiet);
        let holder = match self.upload(path, target, None, progress) {
            Ok(done) => return Ok(Placed::Uploaded(done)),
            Err(e) => match name_taken(&e) {
                Some(holder) => holder,
                None => return Err(e),
            },
        };
        if holder.kind == "file" {
            let local = content_hash_of(path, &target.hash_key)?;
            if holder.content_hash.as_deref() == Some(local.as_str()) {
                return Ok(Placed::AlreadyThere(holder.id));
            }
        }
        let mut taken = self.names_in(target)?;
        if !self.keep_both {
            bail!(
                "{name} is already in that folder ({}) — pass --keep-both to upload it as {:?}",
                if holder.kind == "folder" {
                    "a folder"
                } else {
                    "a different file"
                },
                crate::names::free_name(&name, &taken)
            );
        }
        for _ in 0..3 {
            let free = crate::names::free_name(&name, &taken);
            let progress = if quiet {
                Progress::Quiet
            } else {
                Progress::Bar
            };
            match self.upload(path, target, Some(&free), progress) {
                Ok(done) => return Ok(Placed::Uploaded(done)),
                Err(e) if name_taken(&e).is_some() => {
                    taken.insert(crate::names::canonical(&free));
                }
                Err(e) => return Err(e),
            }
        }
        bail!("no free name for {name} in that folder")
    }

    /// The names in a folder now (its files' and subfolders'), canonical.
    fn names_in(&self, target: &Target) -> Result<HashSet<String>> {
        let col = find_collection(self.cols, &target.id).context("the folder vanished")?;
        let keys = Keyring::load(self.client, col, &target.key, self.master_key)?;
        let mut names: HashSet<String> = self
            .client
            .list_files(&target.id)?
            .iter()
            .map(|f| crate::names::canonical(&decrypt_file_meta(f, &keys).0))
            .collect();
        let fresh = decrypt_collections(
            self.client.list_collections()?,
            self.master_key,
            self.session,
        );
        names.extend(
            fresh
                .iter()
                .filter(|c| c.parent_collection_id.as_deref() == Some(target.id.as_str()))
                .map(|c| crate::names::canonical(&c.name)),
        );
        Ok(names)
    }

    /// The subfolder `name` of `parent`: the one there, or a new one.
    fn subfolder(&self, parent: &Target, name: &str) -> Result<Target> {
        match create_sub_collection(
            self.client,
            name,
            &parent.id,
            &parent.hash_key,
            &self.session.user_id,
            self.master_key,
        ) {
            Ok((id, key)) => Ok(Target {
                hash_key: kutup_crypto::drive_names::folder_hash_key(&key, &id)?,
                id,
                key_epoch: 1,
                key: key.to_vec(),
            }),
            Err(e) => {
                let Some(holder) = name_taken(&e) else {
                    return Err(e);
                };
                if holder.kind != "folder" {
                    bail!("{name}: a file of that name is in the folder, where the directory would go");
                }
                // Already there: go into it.
                let fresh = self.client.list_collections()?;
                let col = fresh
                    .iter()
                    .find(|c| c.id == holder.id)
                    .with_context(|| format!("folder {name} is there but not listed"))?;
                self.target(col)
            }
        }
    }

    /// A directory into `parent`, as a folder of its name.
    fn dir(&self, dir: &Path, parent: &Target, stats: &mut DirUpload) -> Result<()> {
        let dir_name = file_name(&dir.to_string_lossy());
        let target = self
            .subfolder(parent, &dir_name)
            .with_context(|| format!("create sub-folder {dir_name}"))?;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Err(e) = self.dir(&path, &target, stats) {
                    let w = format!("{e:#}");
                    eprintln!("warning: {w}");
                    stats.warnings.push(w);
                }
                continue;
            }
            match self.file(&path, &target, Progress::Bar) {
                Ok(Placed::Uploaded(up)) => {
                    eprintln!("  ↑ {}", path.display());
                    extract_whiteboard_assets(self.client, &up, &path, &mut stats.warnings);
                    stats.uploaded.push(serde_json::json!({
                        "id": up.file_id,
                        "name": up.name,
                        "path": path.display().to_string(),
                        "collectionId": target.id,
                    }));
                }
                Ok(Placed::AlreadyThere(id)) => {
                    eprintln!("  = {}", path.display());
                    stats.already_there.push(serde_json::json!({
                        "id": id,
                        "path": path.display().to_string(),
                        "collectionId": target.id,
                    }));
                }
                Err(e) => {
                    let w = format!("upload {}: {e:#}", entry.file_name().to_string_lossy());
                    eprintln!("warning: {w}");
                    stats.warnings.push(w);
                }
            }
        }
        Ok(())
    }
}

/// The holder of a taken name, when that is why the server refused.
fn name_taken(error: &anyhow::Error) -> Option<NameHolder> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ApiError>())
        .and_then(|api| api.name_taken.clone())
}

/// The local file's content hash under a folder's hash key.
fn content_hash_of(path: &Path, hash_key: &[u8; 32]) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    crate::names::content_hash(hash_key, &digest.finalize().into())
}

/// Accumulates a recursive upload's results for the summary / `--json` doc.
#[derive(Default)]
struct DirUpload {
    uploaded: Vec<serde_json::Value>,
    already_there: Vec<serde_json::Value>,
    warnings: Vec<String>,
}

/// Best-effort whiteboard asset extraction after a successful upload — a
/// failure here never fails the main transfer.
fn extract_whiteboard_assets(
    client: &Client,
    up: &crate::uploader::Uploaded,
    path: &Path,
    warnings: &mut Vec<String>,
) {
    if !crate::whiteboard::is_excalidraw(&path.to_string_lossy()) {
        return;
    }
    if let Err(e) = crate::whiteboard::extract_and_upload(
        client,
        &up.file_id,
        &up.file_key,
        up.key_generation,
        path,
    ) {
        let w = format!("asset extraction {}: {e:#}", path.display());
        eprintln!("warning: {w}");
        warnings.push(w);
    }
}
