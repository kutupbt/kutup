//! Bidirectional sync between a local directory tree and a remote collection
//! tree, built on a three-way merge against the recorded base state
//! (`session::SyncFileState`).
//!
//! Change detection:
//! - local: `(size, mtime)` vs the base record (exact match);
//! - remote: file id (delete+recreate) or newest `file_versions` id (collab
//!   edits) vs the base record — `files.updated_at` is never bumped
//!   server-side, so it carries no signal.
//!
//! Content updates push as a NEW tus upload followed by a soft-delete of the
//! superseded file id (upload-first = crash-safe; the old content stays
//! recoverable in the trash, and web clients — which read the main blob —
//! see the new bytes). Pulls stream to a `.kutup-tmp-*` file and rename into
//! place. Conflicts never overwrite: the remote content lands in a
//! `name.sync-conflict-<ts>` copy and the local file wins the canonical name
//! on the next pass. Deletions propagate only under `--delete`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kutup_crypto::drive_object::DriveFileBlobContextV1;

use crate::api::Client;
use crate::cryptohelpers::{decrypt_collection_key, decrypt_file_meta};
use crate::session::{sync_pair_id, Session, Store, SyncDirState, SyncFileState};
use crate::transfer::{self, stream_download};
use crate::uploader::{self, now_unix, Progress, UploadRequest};
use crate::vaultsync::{
    describe, is_vault, merge_and_save, recorded, save_version, VaultFile, VaultKeys,
};

pub struct SyncOptions {
    /// Propagate deletions (both directions). Off = count + skip.
    pub delete: bool,
    /// Plan and narrate only; zero mutations anywhere.
    pub dry_run: bool,
}

/// Summary of a sync run.
#[derive(Default)]
pub struct SyncResult {
    pub uploaded: usize,
    pub downloaded: usize,
    pub conflicts: usize,
    /// Vaults merged with their remote side (docs/plans/pass.md, K1).
    pub merged: usize,
    pub deleted_local: usize,
    pub deleted_remote: usize,
    pub skipped_deletions: usize,
    pub errors: Vec<String>,
}

// --- pure planning types (unit-tested without I/O) ---

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BaseFile {
    pub file_id: String,
    /// `-1` = conflicted base (forces the local side push-dirty).
    pub local_size: i64,
    pub local_mtime_secs: i64,
    pub local_mtime_nanos: u32,
    pub remote_version_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LocalFile {
    pub size: i64,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RemoteFileSig {
    pub file_id: String,
    pub latest_version_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FileAction {
    Pull,
    PushNew,
    PushUpdate {
        old_file_id: String,
    },
    Conflict,
    /// Same rel_path exists on both sides with no base: byte-compare, adopt
    /// if identical, conflict otherwise.
    AdoptCheck,
    DeleteLocal,
    DeleteRemote {
        file_id: String,
    },
    SkipDeletion,
    Forget,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DirAction {
    MkLocal,
    MkRemote,
    Adopt,
    DeleteLocalDir,
    DeleteRemoteDir { collection_id: String },
    SkipDeletion,
    Forget,
}

/// The three-way matrix. Pure: indexes in, ordered actions out.
pub(crate) fn plan_files(
    base: &BTreeMap<String, BaseFile>,
    local: &BTreeMap<String, LocalFile>,
    remote: &BTreeMap<String, RemoteFileSig>,
    delete: bool,
) -> Vec<(String, FileAction)> {
    let mut keys: BTreeSet<&String> = BTreeSet::new();
    keys.extend(base.keys());
    keys.extend(local.keys());
    keys.extend(remote.keys());

    let mut out = Vec::new();
    for rel in keys {
        let b = base.get(rel);
        let l = local.get(rel);
        let r = remote.get(rel);
        let action = match (b, l, r) {
            (Some(b), Some(l), Some(r)) => {
                let lc = b.local_size != l.size
                    || b.local_mtime_secs != l.mtime_secs
                    || b.local_mtime_nanos != l.mtime_nanos;
                let rc = b.file_id != r.file_id || b.remote_version_id != r.latest_version_id;
                match (lc, rc) {
                    (false, false) => continue,
                    (true, false) => FileAction::PushUpdate {
                        old_file_id: r.file_id.clone(),
                    },
                    (false, true) => FileAction::Pull,
                    (true, true) => FileAction::Conflict,
                }
            }
            // Remote side vanished.
            (Some(b), Some(l), None) => {
                let lc = b.local_size != l.size
                    || b.local_mtime_secs != l.mtime_secs
                    || b.local_mtime_nanos != l.mtime_nanos;
                if lc {
                    FileAction::PushNew // modify wins over delete
                } else if delete {
                    FileAction::DeleteLocal
                } else {
                    FileAction::SkipDeletion
                }
            }
            // Local side vanished.
            (Some(b), None, Some(r)) => {
                let rc = b.file_id != r.file_id || b.remote_version_id != r.latest_version_id;
                if rc {
                    FileAction::Pull // modify wins over delete
                } else if delete {
                    FileAction::DeleteRemote {
                        file_id: r.file_id.clone(),
                    }
                } else {
                    FileAction::SkipDeletion
                }
            }
            (Some(_), None, None) => FileAction::Forget,
            (None, Some(_), Some(_)) => FileAction::AdoptCheck,
            (None, Some(_), None) => FileAction::PushNew,
            (None, None, Some(_)) => FileAction::Pull,
            (None, None, None) => continue,
        };
        out.push((rel.clone(), action));
    }
    out
}

pub(crate) fn plan_dirs(
    base: &BTreeMap<String, String>, // rel → recorded collection id
    local: &BTreeSet<String>,
    remote: &BTreeMap<String, String>, // rel → collection id
    delete: bool,
) -> Vec<(String, DirAction)> {
    let mut keys: BTreeSet<&String> = BTreeSet::new();
    keys.extend(base.keys());
    keys.extend(local.iter());
    keys.extend(remote.keys());

    let mut out = Vec::new();
    for rel in keys {
        let b = base.contains_key(rel);
        let l = local.contains(rel);
        let r = remote.get(rel);
        let action = match (b, l, r) {
            (false, true, Some(_)) => DirAction::Adopt,
            (false, true, None) => DirAction::MkRemote,
            (false, false, Some(_)) => DirAction::MkLocal,
            (true, true, Some(_)) | (false, false, None) => continue,
            (true, true, None) => {
                if delete {
                    DirAction::DeleteLocalDir
                } else {
                    DirAction::SkipDeletion
                }
            }
            (true, false, Some(cid)) => {
                if delete {
                    DirAction::DeleteRemoteDir {
                        collection_id: cid.clone(),
                    }
                } else {
                    DirAction::SkipDeletion
                }
            }
            (true, false, None) => DirAction::Forget,
        };
        out.push((rel.clone(), action));
    }
    out
}

// --- live indexes ---

struct RemoteDir {
    collection_id: String,
    key_epoch: u32,
    key: Vec<u8>,
    /// Older keys too, for files stored before the folder rotated.
    keys: crate::keyring::Keyring,
    /// Its names' hash key (docs/plans/drive-unique-names.md).
    hash_key: [u8; 32],
}

struct RemoteEntry {
    file: crate::api::File,
    rel_dir: String,
    latest_version_id: String,
}

/// Performs one bidirectional sync pass between `local_dir` and `collection_id`.
pub fn sync(
    client: &Client,
    store: &Store,
    sess: &Session,
    local_dir: &str,
    collection_id: &str,
    opts: &SyncOptions,
    vaults: &mut VaultKeys,
) -> Result<SyncResult> {
    let mut result = SyncResult::default();
    let master_key = sess.master_key_bytes().context("master key")?;
    vaults.sign_in(sess)?;
    let root = PathBuf::from(local_dir);
    let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let pair = sync_pair_id(collection_id, &canonical_root.to_string_lossy());

    // Remote tree: root collection + its (transitive) sub-collections.
    let cols = client.list_collections().context("list collections")?;
    let root_col = cols
        .iter()
        .find(|c| c.id == collection_id)
        .ok_or_else(|| crate::errors::NotFound(format!("collection {collection_id} not found")))?;
    let root_key =
        decrypt_collection_key(root_col, &master_key, sess).context("decrypt collection key")?;
    let root_keys = crate::keyring::Keyring::load(client, root_col, &root_key, &master_key)?;

    let mut children: BTreeMap<&str, Vec<&crate::api::Collection>> = BTreeMap::new();
    for c in &cols {
        if let Some(p) = c.parent_collection_id.as_deref() {
            children.entry(p).or_default().push(c);
        }
    }

    let mut remote_dirs: BTreeMap<String, RemoteDir> = BTreeMap::new();
    remote_dirs.insert(
        String::new(),
        RemoteDir {
            collection_id: collection_id.to_string(),
            key_epoch: root_col.key_epoch,
            key: root_key,
            hash_key: crate::names::folder_hash_key(&root_keys, collection_id)?,
            keys: root_keys,
        },
    );
    // Walk down, mapping decrypted sub-collection names to rel dirs.
    let mut stack: Vec<(String, String)> = vec![(String::new(), collection_id.to_string())];
    while let Some((rel, col_id)) = stack.pop() {
        for sub in children.get(col_id.as_str()).into_iter().flatten() {
            let Ok(key) = decrypt_collection_key(sub, &master_key, sess) else {
                result.errors.push(format!("decrypt folder key {}", sub.id));
                continue;
            };
            let Ok(keys) = crate::keyring::Keyring::load(client, sub, &key, &master_key) else {
                result.errors.push(format!("folder key history {}", sub.id));
                continue;
            };
            let name = match crate::collection_crypto::open_name(sub, &key) {
                Ok(name) => sanitize_name(&name),
                Err(_) => {
                    result
                        .errors
                        .push(format!("decrypt folder name {}", sub.id));
                    continue;
                }
            };
            let sub_rel = join_rel(&rel, &name);
            if remote_dirs.contains_key(&sub_rel) {
                result
                    .errors
                    .push(format!("duplicate remote folder name {sub_rel} — skipped"));
                continue;
            }
            let Ok(hash_key) = crate::names::folder_hash_key(&keys, &sub.id) else {
                result.errors.push(format!("folder hash key {}", sub.id));
                continue;
            };
            stack.push((sub_rel.clone(), sub.id.clone()));
            remote_dirs.insert(
                sub_rel,
                RemoteDir {
                    collection_id: sub.id.clone(),
                    key_epoch: sub.key_epoch,
                    key,
                    keys,
                    hash_key,
                },
            );
        }
    }

    // Base state.
    let base_files_raw = store.list_sync_files(&pair)?;
    let base_dirs_raw = store.list_sync_dirs(&pair)?;
    let base_files: BTreeMap<String, BaseFile> = base_files_raw
        .iter()
        .map(|(rel, st)| {
            (
                rel.clone(),
                BaseFile {
                    file_id: st.file_id.clone(),
                    local_size: st.local_size,
                    local_mtime_secs: st.local_mtime_secs,
                    local_mtime_nanos: st.local_mtime_nanos,
                    remote_version_id: st.remote_version_id.clone(),
                },
            )
        })
        .collect();
    let base_dirs: BTreeMap<String, String> = base_dirs_raw
        .iter()
        .map(|(rel, st)| (rel.clone(), st.collection_id.clone()))
        .collect();

    // Remote files, per known dir. The newest-version id (the remote change
    // signal) is fetched only for paths the base tracks — new files don't
    // need it for planning.
    let mut remote_entries: BTreeMap<String, RemoteEntry> = BTreeMap::new();
    for (rel_dir, dir) in &remote_dirs {
        let files = match client.list_files(&dir.collection_id) {
            Ok(f) => f,
            Err(e) => {
                result.errors.push(format!("list files {rel_dir}: {e}"));
                continue;
            }
        };
        for f in files {
            let (name, _) = decrypt_file_meta(&f, &dir.keys);
            if name.is_empty() || name == "[encrypted]" {
                if name == "[encrypted]" {
                    result
                        .errors
                        .push(format!("decrypt {}: bad metadata", f.id));
                }
                continue;
            }
            let rel = join_rel(rel_dir, &sanitize_name(&name));
            if remote_entries.contains_key(&rel) {
                result
                    .errors
                    .push(format!("duplicate remote name {rel} — first one wins"));
                continue;
            }
            let latest_version_id = if base_files.contains_key(&rel) {
                latest_version_id(client, &f.id)
            } else {
                String::new()
            };
            remote_entries.insert(
                rel,
                RemoteEntry {
                    file: f,
                    rel_dir: rel_dir.clone(),
                    latest_version_id,
                },
            );
        }
    }

    // Local tree.
    let mut local_files: BTreeMap<String, LocalFile> = BTreeMap::new();
    let mut local_dirs: BTreeSet<String> = BTreeSet::new();
    walk_local(&root, "", &mut local_files, &mut local_dirs, &mut result);

    // --- directories first (parents before children) ---
    let remote_dir_ids: BTreeMap<String, String> = remote_dirs
        .iter()
        .filter(|(rel, _)| !rel.is_empty())
        .map(|(rel, d)| (rel.clone(), d.collection_id.clone()))
        .collect();
    let mut dir_actions = plan_dirs(&base_dirs, &local_dirs, &remote_dir_ids, opts.delete);
    dir_actions.sort_by_key(|(rel, a)| {
        let depth = rel.matches('/').count();
        // Creations top-down, deletions bottom-up.
        match a {
            DirAction::DeleteLocalDir | DirAction::DeleteRemoteDir { .. } => {
                (1, usize::MAX - depth, rel.clone())
            }
            _ => (0, depth, rel.clone()),
        }
    });

    let mut deferred_dir_deletes: Vec<(String, DirAction)> = Vec::new();
    for (rel, action) in dir_actions {
        match action {
            DirAction::MkLocal => {
                eprintln!("  + {rel}/");
                if !opts.dry_run {
                    if let Err(e) = std::fs::create_dir_all(root.join(&rel)) {
                        result.errors.push(format!("mkdir {rel}: {e}"));
                        continue;
                    }
                    let cid = remote_dirs.get(&rel).map(|d| d.collection_id.clone());
                    if let Some(collection_id) = cid {
                        let _ = store.put_sync_dir(&pair, &rel, &SyncDirState { collection_id });
                    }
                    local_dirs.insert(rel);
                }
            }
            DirAction::MkRemote => {
                eprintln!("  + {rel}/ (remote)");
                if !opts.dry_run {
                    let (parent_rel, leaf) = split_rel(&rel);
                    let Some(parent) = remote_dirs.get(parent_rel) else {
                        result
                            .errors
                            .push(format!("mkdir remote {rel}: parent missing"));
                        continue;
                    };
                    match uploader::create_sub_collection(
                        client,
                        leaf,
                        &parent.collection_id,
                        &parent.hash_key,
                        &sess.user_id,
                        &master_key,
                    ) {
                        Ok((id, key)) => {
                            let _ = store.put_sync_dir(
                                &pair,
                                &rel,
                                &SyncDirState {
                                    collection_id: id.clone(),
                                },
                            );
                            remote_dirs.insert(
                                rel,
                                RemoteDir {
                                    hash_key: kutup_crypto::drive_names::folder_hash_key(
                                        &key, &id,
                                    )?,
                                    collection_id: id,
                                    key_epoch: 1,
                                    key: key.to_vec(),
                                    keys: crate::keyring::Keyring::current_only(&key, 1),
                                },
                            );
                        }
                        Err(e) => result.errors.push(format!("mkdir remote {rel}: {e:#}")),
                    }
                }
            }
            DirAction::Adopt => {
                if !opts.dry_run {
                    if let Some(d) = remote_dirs.get(&rel) {
                        let _ = store.put_sync_dir(
                            &pair,
                            &rel,
                            &SyncDirState {
                                collection_id: d.collection_id.clone(),
                            },
                        );
                    }
                }
            }
            DirAction::SkipDeletion => {
                eprintln!("  – {rel}/ (deletion not propagated; use --delete)");
                result.skipped_deletions += 1;
            }
            DirAction::Forget => {
                if !opts.dry_run {
                    let _ = store.delete_sync_dir(&pair, &rel);
                }
            }
            del => deferred_dir_deletes.push((rel, del)),
        }
    }

    // --- files ---
    let remote_sigs: BTreeMap<String, RemoteFileSig> = remote_entries
        .iter()
        .map(|(rel, e)| {
            (
                rel.clone(),
                RemoteFileSig {
                    file_id: e.file.id.clone(),
                    latest_version_id: e.latest_version_id.clone(),
                },
            )
        })
        .collect();

    for (rel, action) in plan_files(&base_files, &local_files, &remote_sigs, opts.delete) {
        let outcome = execute_file_action(
            client,
            store,
            &pair,
            &root,
            &rel,
            &action,
            &remote_dirs,
            &remote_entries,
            base_files.get(&rel),
            vaults,
            opts,
            &mut result,
        );
        if let Err(e) = outcome {
            result.errors.push(format!("{rel}: {e:#}"));
        }
    }

    // --- deferred directory deletions (bottom-up) ---
    for (rel, action) in deferred_dir_deletes {
        match action {
            DirAction::DeleteLocalDir => {
                eprintln!("  ✗ {rel}/");
                result.deleted_local += 1;
                if !opts.dry_run {
                    if let Err(e) = std::fs::remove_dir(root.join(&rel)) {
                        result.errors.push(format!("rmdir {rel}: {e}"));
                    } else {
                        let _ = store.delete_sync_dir(&pair, &rel);
                    }
                }
            }
            DirAction::DeleteRemoteDir { collection_id } => {
                eprintln!("  ✗ {rel}/ (remote)");
                result.deleted_remote += 1;
                if !opts.dry_run {
                    if let Err(e) = client.delete_collection(&collection_id) {
                        result.errors.push(format!("delete remote {rel}: {e}"));
                    } else {
                        let _ = store.delete_sync_dir(&pair, &rel);
                        // Anything the base tracked underneath is gone too.
                        for (frel, _) in &base_files_raw {
                            if frel.starts_with(&format!("{rel}/")) {
                                let _ = store.delete_sync_file(&pair, frel);
                            }
                        }
                    }
                }
            }
            _ => unreachable!("only deletions are deferred"),
        }
    }

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn execute_file_action(
    client: &Client,
    store: &Store,
    pair: &str,
    root: &Path,
    rel: &str,
    action: &FileAction,
    remote_dirs: &BTreeMap<String, RemoteDir>,
    remote_entries: &BTreeMap<String, RemoteEntry>,
    base: Option<&BaseFile>,
    vaults: &mut VaultKeys,
    opts: &SyncOptions,
    result: &mut SyncResult,
) -> Result<()> {
    if is_vault(rel) && !opts.dry_run {
        let handled = execute_vault_action(
            client,
            store,
            pair,
            root,
            rel,
            action,
            remote_entries,
            remote_dirs,
            base,
            vaults,
            result,
        )?;
        match handled {
            VaultHandled::Done => return Ok(()),
            VaultHandled::NotHandled => {}
            // The save lost a race and the vault cannot be merged here: the
            // remote side is kept as a copy, as for any other file.
            VaultHandled::AsConflict => {
                return execute_file_action(
                    client,
                    store,
                    pair,
                    root,
                    rel,
                    &FileAction::Conflict,
                    remote_dirs,
                    remote_entries,
                    None,
                    vaults,
                    opts,
                    result,
                )
            }
        }
    }
    match action {
        FileAction::Pull => {
            eprintln!("  ↓ {rel}");
            result.downloaded += 1;
            if opts.dry_run {
                return Ok(());
            }
            let entry = remote_entries.get(rel).context("remote entry vanished")?;
            let dir = remote_dirs
                .get(&entry.rel_dir)
                .context("remote dir vanished")?;
            let dest = root.join(rel);
            let version = pull_to(client, entry, &dir.keys, &dest)?;
            record_base(store, pair, rel, &dest, entry, client, version)?;
        }
        FileAction::PushNew | FileAction::PushUpdate { .. } => {
            eprintln!("  ↑ {rel}");
            result.uploaded += 1;
            if opts.dry_run {
                return Ok(());
            }
            let (parent_rel, _) = split_rel(rel);
            let dir = remote_dirs
                .get(parent_rel)
                .context("remote parent folder missing")?;
            let abs = root.join(rel);
            let stat = stat_local(&abs)?;
            let sha256 = uploader::sha256_file(&abs)?;
            // An edit goes up as a new version of the file Drive holds
            // (docs/plans/drive-unique-names.md: names are unique in a
            // folder, so the file keeps its name and id); a new file claims
            // its name as it goes.
            let (file_id, remote_version_id) = match action {
                FileAction::PushUpdate { old_file_id } => {
                    let entry = remote_entries.get(rel).context("remote entry vanished")?;
                    if transfer::cipher_size(stat.size) <= MAX_VERSION_BYTES {
                        let version = push_version(client, &abs, &entry.file, dir, &sha256)?;
                        (old_file_id.clone(), version)
                    } else {
                        let id =
                            push_replacement(client, store, &abs, entry, dir, &sha256, result)?;
                        (id, String::new())
                    }
                }
                _ => {
                    let up = uploader::upload_streaming(
                        client,
                        store,
                        &abs,
                        UploadRequest {
                            collection_id: &dir.collection_id,
                            key_epoch: dir.key_epoch,
                            collection_key: &dir.key,
                            resume: true,
                            progress: Progress::Quiet,
                            hash_key: dir.hash_key,
                            name: None,
                            sha256: Some(sha256),
                        },
                    )?;
                    (up.file_id, String::new())
                }
            };
            store.put_sync_file(
                pair,
                rel,
                &SyncFileState {
                    file_id,
                    collection_id: dir.collection_id.clone(),
                    local_size: stat.size,
                    local_mtime_secs: stat.mtime_secs,
                    local_mtime_nanos: stat.mtime_nanos,
                    remote_version_id,
                    synced_at: now_unix(),
                },
            )?;
        }
        FileAction::Conflict => {
            result.conflicts += 1;
            if opts.dry_run {
                eprintln!("  ⚠ {rel} (remote copy → {})", conflict_name(rel));
                return Ok(());
            }
            let entry = remote_entries.get(rel).context("remote entry vanished")?;
            let dir = remote_dirs
                .get(&entry.rel_dir)
                .context("remote dir vanished")?;
            let copy = free_conflict_name(client, root, rel, dir)?;
            eprintln!("  ⚠ {rel} (remote copy → {copy})");
            pull_to(client, entry, &dir.keys, &root.join(&copy))?;
            // Mark the base conflicted: remote side = current (stops the
            // conflict from re-firing), local side = dirty sentinel (the
            // canonical name pushes and wins remotely next pass).
            store.put_sync_file(
                pair,
                rel,
                &SyncFileState {
                    file_id: entry.file.id.clone(),
                    collection_id: dir.collection_id.clone(),
                    local_size: -1,
                    local_mtime_secs: 0,
                    local_mtime_nanos: 0,
                    remote_version_id: latest_version_id(client, &entry.file.id),
                    synced_at: now_unix(),
                },
            )?;
        }
        FileAction::AdoptCheck => {
            if opts.dry_run {
                eprintln!("  ? {rel} (verify same-name file)");
                return Ok(());
            }
            let entry = remote_entries.get(rel).context("remote entry vanished")?;
            let dir = remote_dirs
                .get(&entry.rel_dir)
                .context("remote dir vanished")?;
            let abs = root.join(rel);
            let tmp = temp_path(&abs);
            let version = download_decrypt(client, entry, &dir.keys, &tmp)?;
            let same = files_equal(&abs, &tmp).unwrap_or(false);
            if same {
                let _ = std::fs::remove_file(&tmp);
                record_base(store, pair, rel, &abs, entry, client, version)?;
            } else {
                let copy = free_conflict_name(client, root, rel, dir)?;
                eprintln!("  ⚠ {rel} (differs from remote; remote copy → {copy})");
                result.conflicts += 1;
                std::fs::rename(&tmp, root.join(&copy))?;
                store.put_sync_file(
                    pair,
                    rel,
                    &SyncFileState {
                        file_id: entry.file.id.clone(),
                        collection_id: dir.collection_id.clone(),
                        local_size: -1,
                        local_mtime_secs: 0,
                        local_mtime_nanos: 0,
                        remote_version_id: latest_version_id(client, &entry.file.id),
                        synced_at: now_unix(),
                    },
                )?;
            }
        }
        FileAction::DeleteLocal => {
            eprintln!("  ✗ {rel}");
            result.deleted_local += 1;
            if opts.dry_run {
                return Ok(());
            }
            std::fs::remove_file(root.join(rel))?;
            store.delete_sync_file(pair, rel)?;
        }
        FileAction::DeleteRemote { file_id } => {
            eprintln!("  ✗ {rel} (remote → trash)");
            result.deleted_remote += 1;
            if opts.dry_run {
                return Ok(());
            }
            client.delete_file(file_id)?;
            store.delete_sync_file(pair, rel)?;
        }
        FileAction::SkipDeletion => {
            eprintln!("  – {rel} (deletion not propagated; use --delete)");
            result.skipped_deletions += 1;
        }
        FileAction::Forget => {
            if !opts.dry_run {
                store.delete_sync_file(pair, rel)?;
            }
        }
    }
    Ok(())
}

/// What [`execute_vault_action`] did.
enum VaultHandled {
    Done,
    /// Not a case vaults treat differently: the ordinary file path runs.
    NotHandled,
    /// Run the conflict path instead (a copy of the remote side).
    AsConflict,
}

/// `.kdbx` vaults (docs/plans/pass.md, K1): a changed vault is saved as a
/// version of the same file, made from the version recorded as the base, and
/// when both sides changed (or a save loses a race) they are merged.
#[allow(clippy::too_many_arguments)]
fn execute_vault_action(
    client: &Client,
    store: &Store,
    pair: &str,
    root: &Path,
    rel: &str,
    action: &FileAction,
    remote_entries: &BTreeMap<String, RemoteEntry>,
    remote_dirs: &BTreeMap<String, RemoteDir>,
    base: Option<&BaseFile>,
    vaults: &mut VaultKeys,
    result: &mut SyncResult,
) -> Result<VaultHandled> {
    let Some(entry) = remote_entries.get(rel) else {
        return Ok(VaultHandled::NotHandled);
    };
    let Some(dir) = remote_dirs.get(&entry.rel_dir) else {
        return Ok(VaultHandled::NotHandled);
    };
    let vault = VaultFile {
        file_id: &entry.file.id,
        collection_id: &dir.collection_id,
        folder_epoch: dir.key_epoch,
        keys: &dir.keys,
    };
    let abs = root.join(rel);
    let target = VaultTarget {
        store,
        pair,
        rel,
        abs: &abs,
        entry,
        collection_id: &dir.collection_id,
    };
    // The recorded remote version is a merge base only if the local copy
    // started from it; after a conflict copy it did not.
    let merge_base = base
        .filter(|b| b.local_size >= 0)
        .map(|b| (b.file_id.as_str(), b.remote_version_id.as_str()));
    match action {
        FileAction::PushUpdate { .. } => {
            let Some(base) = base.filter(|b| b.file_id == entry.file.id) else {
                return Ok(VaultHandled::NotHandled);
            };
            // Stat before reading: a write after it shows as a change next
            // time, never as synced.
            let stat = stat_local(&abs)?;
            let contents = std::fs::read(&abs).context("read vault")?;
            match save_version(client, &vault, &contents, &base.remote_version_id)? {
                Some(version) => {
                    eprintln!("  ↑ {rel}");
                    result.uploaded += 1;
                    target.record(&stat, version)?;
                    Ok(VaultHandled::Done)
                }
                None if merge_vault(client, &target, &vault, merge_base, vaults, result)? => {
                    Ok(VaultHandled::Done)
                }
                None => Ok(VaultHandled::AsConflict),
            }
        }
        FileAction::Conflict => {
            if merge_vault(client, &target, &vault, merge_base, vaults, result)? {
                Ok(VaultHandled::Done)
            } else {
                Ok(VaultHandled::NotHandled)
            }
        }
        // The same vault on both sides with no base (a second machine joining
        // with its own copy): merged by KeePassXC's rules.
        FileAction::AdoptCheck => {
            if merge_vault(client, &target, &vault, None, vaults, result)? {
                Ok(VaultHandled::Done)
            } else {
                Ok(VaultHandled::NotHandled)
            }
        }
        _ => Ok(VaultHandled::NotHandled),
    }
}

/// Where a merged vault is written and recorded.
struct VaultTarget<'a> {
    store: &'a Store,
    pair: &'a str,
    rel: &'a str,
    abs: &'a Path,
    entry: &'a RemoteEntry,
    collection_id: &'a str,
}

impl VaultTarget<'_> {
    fn record(&self, stat: &LocalFile, version: String) -> Result<()> {
        self.store.put_sync_file(
            self.pair,
            self.rel,
            &SyncFileState {
                file_id: self.entry.file.id.clone(),
                collection_id: self.collection_id.to_owned(),
                local_size: stat.size,
                local_mtime_secs: stat.mtime_secs,
                local_mtime_nanos: stat.mtime_nanos,
                remote_version_id: version,
                synced_at: now_unix(),
            },
        )
    }
}

/// Merges the local vault with the remote one and writes the result to both
/// sides. False: no key opens it; nothing changed.
fn merge_vault(
    client: &Client,
    target: &VaultTarget,
    vault: &VaultFile,
    base: Option<(&str, &str)>,
    vaults: &mut VaultKeys,
    result: &mut SyncResult,
) -> Result<bool> {
    let rel = target.rel;
    let stat = stat_local(target.abs)?;
    let local = std::fs::read(target.abs).context("read vault")?;
    let Some(saved) = merge_and_save(client, vaults, rel, vault, base, &local)? else {
        eprintln!(
            "  ⚠ {rel}: merging needs the vault's key (KUTUP_VAULT_PASSWORD or \
             KUTUP_VAULT_KEY_FILE, or run in a terminal)"
        );
        return Ok(false);
    };
    result.merged += 1;
    if saved.uploaded {
        eprintln!("  ⇄ {rel} (merged: {})", describe(&saved.report));
    } else {
        eprintln!("  ⇄ {rel} (Drive already had every local change; local copy updated)");
    }
    // Edited again while merging: left alone, and merged again next time
    // (the base stays as it was, so nothing in the new edit is lost).
    if stat_local(target.abs)? != stat {
        result.errors.push(format!(
            "{rel}: changed during the merge; it is merged again next sync"
        ));
        return Ok(true);
    }
    let tmp = temp_path(target.abs);
    std::fs::write(&tmp, &saved.contents).context("write merged vault")?;
    std::fs::rename(&tmp, target.abs).context("rename into place")?;
    target.record(&stat_local(target.abs)?, saved.version)?;
    Ok(true)
}

// --- helpers ---

/// Downloads `entry` into `dest`; the version it was, when the server says.
fn pull_to(
    client: &Client,
    entry: &RemoteEntry,
    dir_keys: &crate::keyring::Keyring,
    dest: &Path,
) -> Result<Option<String>> {
    let tmp = temp_path(dest);
    let version = download_decrypt(client, entry, dir_keys, &tmp)?;
    std::fs::rename(&tmp, dest).context("rename into place")?;
    Ok(version)
}

/// Streams the newest content of `entry` decrypted into `tmp` (bounded
/// memory); the version it was (`original` for the upload), when the server
/// says.
fn download_decrypt(
    client: &Client,
    entry: &RemoteEntry,
    dir_keys: &crate::keyring::Keyring,
    tmp: &Path,
) -> Result<Option<String>> {
    let f = &entry.file;
    let file_key = crate::file_crypto::open_key(f, dir_keys).context("decrypt file key")?;
    // What the file holds now (its latest whole-file version, else the
    // upload), sealed at its own key generation.
    let (content_key, content_generation) = crate::file_crypto::content_key(f, &file_key)?;
    let (stream, version) = client.download_current_stream(&f.id)?;
    let mut out = std::fs::File::create(tmp).context("create temp file")?;
    let blob_context = DriveFileBlobContextV1::new(&f.id, content_generation)?;
    match stream_download(stream, &content_key, blob_context, &mut out, |_| {}) {
        Ok(_) => Ok(version),
        Err(e) => {
            drop(out);
            let _ = std::fs::remove_file(tmp);
            Err(e).context("decrypt-write")
        }
    }
}

/// The largest version the server stores in one request
/// (`DRIVE_VERSION_LIMIT_BYTES`); a bigger edit goes up as a new file.
const MAX_VERSION_BYTES: i64 = 2 * 1024 * 1024 * 1024;

/// Stores the local file `abs` as a new version of `file`, streamed, then
/// its metadata's size and content SHA-256 and its content hash; returns
/// the version's id.
fn push_version(
    client: &Client,
    abs: &Path,
    file: &crate::api::File,
    dir: &RemoteDir,
    sha256: &[u8; 32],
) -> Result<String> {
    let file_key = crate::file_crypto::open_key(file, &dir.keys).context("decrypt file key")?;
    // New content goes under a key only the folder's current people hold.
    let (file, file_key) = crate::cryptohelpers::rekey_file_if_behind(
        client,
        file.clone(),
        file_key,
        &dir.keys,
        &dir.collection_id,
        dir.key_epoch,
    )?;
    let size = std::fs::metadata(abs)?.len();
    let up = transfer::StreamUploader::new(
        std::fs::File::open(abs)?,
        &file_key,
        size as i64,
        DriveFileBlobContextV1::new(&file.id, file.key_generation)?,
    )?;
    let row = client
        .create_version_stream(
            &file.id,
            transfer::CipherReader::new(up),
            transfer::cipher_size(size as i64) as u64,
            &crate::api::versions::NewVersion {
                kind: "file".into(),
                doc_key_id: 1,
                ..Default::default()
            },
        )
        .context("store new version")?;
    uploader::follow_new_content(client, &file, &file_key, &dir.hash_key, size, sha256)?;
    Ok(row.id)
}

/// An edit too big for a version: uploaded as a new file under a free
/// numbered name, the old one trashed, and the new one renamed to the name.
/// Returns the new file's id.
fn push_replacement(
    client: &Client,
    store: &Store,
    abs: &Path,
    entry: &RemoteEntry,
    dir: &RemoteDir,
    sha256: &[u8; 32],
    result: &mut SyncResult,
) -> Result<String> {
    let name = crate::file_crypto::open_metadata(
        &entry.file,
        &crate::file_crypto::open_key(&entry.file, &dir.keys)?,
    )?
    .name;
    let (interim, _) = crate::names::first_available(
        client,
        Some(&dir.collection_id),
        &dir.hash_key,
        crate::names::numbered_names(&name).skip(1),
        |_| false,
    )?;
    let up = uploader::upload_streaming(
        client,
        store,
        abs,
        UploadRequest {
            collection_id: &dir.collection_id,
            key_epoch: dir.key_epoch,
            collection_key: &dir.key,
            resume: true,
            progress: Progress::Quiet,
            hash_key: dir.hash_key,
            name: Some(&interim),
            sha256: Some(*sha256),
        },
    )?;
    if let Err(e) = client.delete_file(&entry.file.id) {
        result.errors.push(format!(
            "{name}: retire old version: {e}; the new one is {interim}"
        ));
        return Ok(up.file_id);
    }
    let renamed = (|| -> Result<()> {
        let file = client
            .list_files(&dir.collection_id)?
            .into_iter()
            .find(|f| f.id == up.file_id)
            .context("the new file is not listed")?;
        let mut meta = crate::file_crypto::open_metadata(&file, &up.file_key)?;
        meta.name = name.clone();
        let mut request = crate::file_crypto::rename_request(&file, &up.file_key, &meta)?;
        request.name_hash = Some(crate::names::name_hash(&dir.hash_key, &name)?);
        client.update_file_metadata(&file.id, &request)
    })();
    if let Err(e) = renamed {
        result.errors.push(format!(
            "{name}: uploaded as {interim}, rename back failed: {e:#}"
        ));
    }
    Ok(up.file_id)
}

fn record_base(
    store: &Store,
    pair: &str,
    rel: &str,
    local_path: &Path,
    entry: &RemoteEntry,
    client: &Client,
    downloaded: Option<String>,
) -> Result<()> {
    let stat = stat_local(local_path)?;
    // A vault records the very version it got: its next save is made from
    // it (`basedOn`). Other files record the newest version of any kind,
    // which is what planning compares (a note's states are versions too).
    let remote_version_id = match downloaded {
        Some(version) if is_vault(rel) => recorded(&version),
        _ => latest_version_id(client, &entry.file.id),
    };
    store.put_sync_file(
        pair,
        rel,
        &SyncFileState {
            file_id: entry.file.id.clone(),
            collection_id: entry.file.collection_id.clone(),
            local_size: stat.size,
            local_mtime_secs: stat.mtime_secs,
            local_mtime_nanos: stat.mtime_nanos,
            remote_version_id,
            synced_at: now_unix(),
        },
    )
}

fn latest_version_id(client: &Client, file_id: &str) -> String {
    client
        .list_versions(file_id)
        .ok()
        .and_then(|v| v.first().map(|r| r.id.clone()))
        .unwrap_or_default()
}

fn stat_local(path: &Path) -> Result<LocalFile> {
    let m = std::fs::metadata(path)?;
    let (mtime_secs, mtime_nanos) = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unwrap_or((0, 0));
    Ok(LocalFile {
        size: m.len() as i64,
        mtime_secs,
        mtime_nanos,
    })
}

fn walk_local(
    root: &Path,
    rel: &str,
    files: &mut BTreeMap<String, LocalFile>,
    dirs: &mut BTreeSet<String>,
    result: &mut SyncResult,
) {
    let dir = if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            result.errors.push(format!("read dir {rel}: {e}"));
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !keep_local_name(&name) {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        let child_rel = join_rel(rel, &name);
        if ft.is_dir() {
            dirs.insert(child_rel.clone());
            walk_local(root, &child_rel, files, dirs, result);
        } else if ft.is_file() {
            match stat_local(&entry.path()) {
                Ok(st) => {
                    files.insert(child_rel, st);
                }
                Err(e) => result.errors.push(format!("stat {child_rel}: {e}")),
            }
        }
    }
}

/// Hidden/temp names the walker (and watcher) ignore. Conflict copies are
/// deliberately KEPT — they must propagate to other devices.
pub(crate) fn keep_local_name(name: &str) -> bool {
    !name.starts_with('.') && !name.ends_with('~')
}

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// `"a/b/c.txt"` → `("a/b", "c.txt")`; `"c.txt"` → `("", "c.txt")`.
fn split_rel(rel: &str) -> (&str, &str) {
    match rel.rsplit_once('/') {
        Some((dir, leaf)) => (dir, leaf),
        None => ("", rel),
    }
}

fn temp_path(dest: &Path) -> PathBuf {
    let dir = dest.parent().unwrap_or(Path::new("."));
    dir.join(format!(".kutup-tmp-{:08x}", rand::random::<u32>()))
}

/// `report.txt` → `report.sync-conflict-20260710-153012.txt` (Syncthing-style).
fn conflict_name(rel: &str) -> String {
    let t = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let (dir, leaf) = split_rel(rel);
    let renamed = match leaf.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            format!("{stem}.sync-conflict-{stamp}.{ext}")
        }
        _ => format!("{leaf}.sync-conflict-{stamp}"),
    };
    join_rel(dir, &renamed)
}

/// A conflict copy's path: [`conflict_name`], numbered on when that name is
/// already taken here or in the Drive folder the copy goes up to next
/// (asked with `available-hashes`, docs/plans/drive-unique-names.md).
fn free_conflict_name(client: &Client, root: &Path, rel: &str, dir: &RemoteDir) -> Result<String> {
    let copy = conflict_name(rel);
    let (parent, leaf) = split_rel(&copy);
    let (name, _) = crate::names::first_available(
        client,
        Some(&dir.collection_id),
        &dir.hash_key,
        crate::names::numbered_names(leaf),
        |candidate| root.join(join_rel(parent, candidate)).exists(),
    )?;
    Ok(join_rel(parent, &name))
}

/// Bounded-memory byte comparison.
fn files_equal(a: &Path, b: &Path) -> Result<bool> {
    use std::io::Read;
    let (ma, mb) = (std::fs::metadata(a)?, std::fs::metadata(b)?);
    if ma.len() != mb.len() {
        return Ok(false);
    }
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    loop {
        let na = fa.read(&mut ba)?;
        let mut filled = 0;
        while filled < na {
            let n = fb.read(&mut bb[filled..na])?;
            if n == 0 {
                return Ok(false);
            }
            filled += n;
        }
        if ba[..na] != bb[..na] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

/// Strips path separators to prevent traversal. Mirrors `sanitizeName`.
fn sanitize_name(name: &str) -> String {
    let cleaned = name.replace(['/', '\\'], "_");
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "_file".to_string();
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(entries: &[(&str, &str, i64, &str)]) -> BTreeMap<String, BaseFile> {
        entries
            .iter()
            .map(|(rel, fid, size, ver)| {
                (
                    rel.to_string(),
                    BaseFile {
                        file_id: fid.to_string(),
                        local_size: *size,
                        local_mtime_secs: 100,
                        local_mtime_nanos: 0,
                        remote_version_id: ver.to_string(),
                    },
                )
            })
            .collect()
    }

    fn local(entries: &[(&str, i64)]) -> BTreeMap<String, LocalFile> {
        entries
            .iter()
            .map(|(rel, size)| {
                (
                    rel.to_string(),
                    LocalFile {
                        size: *size,
                        mtime_secs: 100,
                        mtime_nanos: 0,
                    },
                )
            })
            .collect()
    }

    fn remote(entries: &[(&str, &str, &str)]) -> BTreeMap<String, RemoteFileSig> {
        entries
            .iter()
            .map(|(rel, fid, ver)| {
                (
                    rel.to_string(),
                    RemoteFileSig {
                        file_id: fid.to_string(),
                        latest_version_id: ver.to_string(),
                    },
                )
            })
            .collect()
    }

    fn plan1(
        b: &BTreeMap<String, BaseFile>,
        l: &BTreeMap<String, LocalFile>,
        r: &BTreeMap<String, RemoteFileSig>,
        delete: bool,
    ) -> Vec<FileAction> {
        plan_files(b, l, r, delete)
            .into_iter()
            .map(|(_, a)| a)
            .collect()
    }

    #[test]
    fn unchanged_is_noop() {
        let b = base(&[("a", "f1", 10, "")]);
        let l = local(&[("a", 10)]);
        let r = remote(&[("a", "f1", "")]);
        assert!(plan1(&b, &l, &r, false).is_empty());
    }

    #[test]
    fn local_edit_pushes_update() {
        let b = base(&[("a", "f1", 10, "")]);
        let l = local(&[("a", 22)]); // size changed
        let r = remote(&[("a", "f1", "")]);
        assert_eq!(
            plan1(&b, &l, &r, false),
            vec![FileAction::PushUpdate {
                old_file_id: "f1".into()
            }]
        );
    }

    #[test]
    fn remote_change_pulls() {
        // New snapshot version → pull; replaced file id → pull.
        let b = base(&[("a", "f1", 10, "v1"), ("b", "f2", 5, "")]);
        let l = local(&[("a", 10), ("b", 5)]);
        let r = remote(&[("a", "f1", "v2"), ("b", "f9", "")]);
        assert_eq!(
            plan1(&b, &l, &r, false),
            vec![FileAction::Pull, FileAction::Pull]
        );
    }

    #[test]
    fn both_changed_is_conflict() {
        let b = base(&[("a", "f1", 10, "v1")]);
        let l = local(&[("a", 11)]);
        let r = remote(&[("a", "f1", "v2")]);
        assert_eq!(plan1(&b, &l, &r, false), vec![FileAction::Conflict]);
    }

    #[test]
    fn conflicted_base_sentinel_forces_push() {
        // After a conflict pass: local_size = -1, remote side current.
        let b = base(&[("a", "f1", -1, "v2")]);
        let l = local(&[("a", 11)]);
        let r = remote(&[("a", "f1", "v2")]);
        assert_eq!(
            plan1(&b, &l, &r, false),
            vec![FileAction::PushUpdate {
                old_file_id: "f1".into()
            }]
        );
    }

    #[test]
    fn deletions_respect_flag_and_modify_wins() {
        // Local deleted, remote unchanged.
        let b = base(&[("gone-local", "f1", 10, "")]);
        let l = local(&[]);
        let r = remote(&[("gone-local", "f1", "")]);
        assert_eq!(plan1(&b, &l, &r, false), vec![FileAction::SkipDeletion]);
        assert_eq!(
            plan1(&b, &l, &r, true),
            vec![FileAction::DeleteRemote {
                file_id: "f1".into()
            }]
        );
        // Local deleted but remote CHANGED → modify wins, resurrect locally.
        let r2 = remote(&[("gone-local", "f1", "v9")]);
        assert_eq!(plan1(&b, &l, &r2, true), vec![FileAction::Pull]);

        // Remote deleted, local unchanged / changed.
        let b2 = base(&[("gone-remote", "f1", 10, "")]);
        let l2 = local(&[("gone-remote", 10)]);
        let r_none = remote(&[]);
        assert_eq!(
            plan1(&b2, &l2, &r_none, false),
            vec![FileAction::SkipDeletion]
        );
        assert_eq!(
            plan1(&b2, &l2, &r_none, true),
            vec![FileAction::DeleteLocal]
        );
        let l3 = local(&[("gone-remote", 42)]);
        assert_eq!(plan1(&b2, &l3, &r_none, true), vec![FileAction::PushNew]);
    }

    #[test]
    fn no_base_cases() {
        let b = base(&[]);
        let l = local(&[("only-local", 3), ("both", 4)]);
        let r = remote(&[("only-remote", "f1", ""), ("both", "f2", "")]);
        let actions = plan_files(&b, &l, &r, false);
        let get = |rel: &str| {
            actions
                .iter()
                .find(|(k, _)| k == rel)
                .map(|(_, a)| a.clone())
                .unwrap()
        };
        assert_eq!(get("only-local"), FileAction::PushNew);
        assert_eq!(get("only-remote"), FileAction::Pull);
        assert_eq!(get("both"), FileAction::AdoptCheck);
    }

    #[test]
    fn vanished_both_sides_forgets() {
        let b = base(&[("gone", "f1", 10, "")]);
        assert_eq!(
            plan1(&b, &local(&[]), &remote(&[]), false),
            vec![FileAction::Forget]
        );
    }

    #[test]
    fn dir_matrix() {
        let mut b = BTreeMap::new();
        b.insert("kept".to_string(), "c1".to_string());
        b.insert("local-gone".to_string(), "c2".to_string());
        b.insert("remote-gone".to_string(), "c3".to_string());
        b.insert("both-gone".to_string(), "c4".to_string());
        let mut l = BTreeSet::new();
        l.extend(["kept", "remote-gone", "new-local", "adopt"].map(String::from));
        let mut r = BTreeMap::new();
        for (k, v) in [
            ("kept", "c1"),
            ("local-gone", "c2"),
            ("new-remote", "c9"),
            ("adopt", "c8"),
        ] {
            r.insert(k.to_string(), v.to_string());
        }
        let actions: BTreeMap<String, DirAction> =
            plan_dirs(&b, &l, &r, true).into_iter().collect();
        assert!(!actions.contains_key("kept"));
        assert_eq!(actions["new-local"], DirAction::MkRemote);
        assert_eq!(actions["new-remote"], DirAction::MkLocal);
        assert_eq!(actions["adopt"], DirAction::Adopt);
        assert_eq!(actions["remote-gone"], DirAction::DeleteLocalDir);
        assert_eq!(
            actions["local-gone"],
            DirAction::DeleteRemoteDir {
                collection_id: "c2".into()
            }
        );
        assert_eq!(actions["both-gone"], DirAction::Forget);

        let no_delete: BTreeMap<String, DirAction> =
            plan_dirs(&b, &l, &r, false).into_iter().collect();
        assert_eq!(no_delete["remote-gone"], DirAction::SkipDeletion);
        assert_eq!(no_delete["local-gone"], DirAction::SkipDeletion);
    }

    #[test]
    fn conflict_names() {
        let c = conflict_name("dir/report.txt");
        assert!(c.starts_with("dir/report.sync-conflict-"));
        assert!(c.ends_with(".txt"));
        let c2 = conflict_name("Makefile");
        assert!(c2.starts_with("Makefile.sync-conflict-"));
    }
}
