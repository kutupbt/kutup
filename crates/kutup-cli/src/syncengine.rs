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

use anyhow::{anyhow, Context, Result};
use kutup_crypto::drive_object::DriveFileBlobContextV1;

use crate::api::Client;
use crate::cryptohelpers::{decrypt_collection_key, decrypt_file_meta};
use crate::session::{sync_pair_id, Session, Store, SyncDirState, SyncFileState};
use crate::transfer::stream_download;
use crate::uploader::{self, now_unix, Progress, UploadRequest};
use crate::vaultsync::{
    describe, is_vault, merge_and_save, recorded, save_version, VaultFile, VaultKeys,
};
use crate::version_upload;

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
    /// A note, code file or place list Drive holds as Yjs, on Drive (and
    /// maybe here): synced both ways as a collaboration peer
    /// (docs/plans/cli-yjs-sync.md). Planned whenever both sides have it,
    /// since only the log tells whether Drive's side changed.
    /// `local_changed`: the file on disk differs from the last record.
    SyncYjs {
        local_changed: bool,
    },
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

/// Paths whose Drive side a run could not read: a folder whose listing
/// failed, or a file whose versions could not be listed.
#[derive(Default)]
pub(crate) struct Unknown {
    pub dirs: BTreeSet<String>,
    pub files: BTreeSet<String>,
}

impl Unknown {
    /// Whether `rel` is one of them (its own entry, or in such a folder).
    pub fn covers(&self, rel: &str) -> bool {
        self.files.contains(rel) || self.dirs.contains(split_rel(rel).0)
    }
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
        let yjs = crate::editor_kind::edits_as_yjs(split_rel(rel).1);
        let action = match (b, l, r) {
            // The same note or list on both sides: its log decides.
            (Some(b), Some(l), Some(r)) if yjs && b.file_id == r.file_id => FileAction::SyncYjs {
                local_changed: b.local_size != l.size
                    || b.local_mtime_secs != l.mtime_secs
                    || b.local_mtime_nanos != l.mtime_nanos,
            },
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
            // Local side vanished. (A note's or list's edits are in its log,
            // not its versions: whether Drive's side changed is checked
            // before deleting it.)
            (Some(b), None, Some(r)) => {
                let rc =
                    b.file_id != r.file_id || (!yjs && b.remote_version_id != r.latest_version_id);
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
        // Its content on Drive is the editor's Yjs state, not the file: it
        // is read and edited as a peer, never pulled or replaced as bytes. A
        // new file goes up as a file (what an editor opens it from).
        let action = match action {
            FileAction::Pull
            | FileAction::PushUpdate { .. }
            | FileAction::Conflict
            | FileAction::AdoptCheck
                if yjs =>
            {
                FileAction::SyncYjs {
                    local_changed: true,
                }
            }
            action => action,
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
    let mut peer = crate::yjs_sync::Peer::new(client, store, sess);
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
    // What Drive holds is unknown this run for these: they get no action at
    // all (their base stays), never one planned as if the remote were gone.
    let mut unknown = Unknown::default();
    for (rel_dir, dir) in &remote_dirs {
        let files = match client.list_files(&dir.collection_id) {
            Ok(f) => f,
            Err(e) => {
                result
                    .errors
                    .push(format!("list files {rel_dir}: {e}; left for the next run"));
                unknown.dirs.insert(rel_dir.clone());
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
                match latest_version_id(client, &f.id) {
                    Ok(id) => id,
                    // Not known this run: the file sits it out (see `unknown`).
                    Err(e) => {
                        result
                            .errors
                            .push(format!("{rel}: {e:#}; left for the next run"));
                        unknown.files.insert(rel);
                        continue;
                    }
                }
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

    for (rel, action) in plan_files(&base_files, &local_files, &remote_sigs, opts.delete)
        .into_iter()
        .filter(|(rel, _)| !unknown.covers(rel))
    {
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
            &mut peer,
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
    peer: &mut crate::yjs_sync::Peer,
    opts: &SyncOptions,
    result: &mut SyncResult,
) -> Result<()> {
    if is_vault(rel) && !opts.dry_run {
        let handled = match execute_vault_action(
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
        ) {
            // Another device is saving it: nothing merged, nothing recorded,
            // so the next run pushes it again.
            Err(e) if e.chain().any(|c| c.is::<crate::vaultsync::VaultBusy>()) => {
                eprintln!("  ⏸ {rel}: {e:#}");
                return Ok(());
            }
            handled => handled?,
        };
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
                    peer,
                    opts,
                    result,
                )
            }
        }
    }
    match action {
        FileAction::SyncYjs { local_changed } => {
            if opts.dry_run {
                eprintln!("  ~ {rel} (live document: synced both ways on a real run)");
                return Ok(());
            }
            let entry = remote_entries.get(rel).context("remote entry vanished")?;
            let dir = remote_dirs
                .get(&entry.rel_dir)
                .context("remote dir vanished")?;
            let synced = crate::yjs_sync::sync_file(
                client,
                peer,
                &yjs_target(store, pair, root, rel, entry, dir, &|| {
                    free_conflict_name(client, root, rel, dir)
                }),
                *local_changed,
            )?;
            report_yjs(rel, &synced, result);
            if let Some(stat) = &synced.stat {
                record_yjs(store, pair, rel, stat, entry)?;
            }
        }
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
            // folder, so the file keeps its name and id), made from the
            // version the sync recorded. A new file claims its name as it
            // goes. (Files Drive keeps as Yjs are planned as SyncYjs.)
            let (file_id, remote_version_id) = match action {
                FileAction::PushUpdate { old_file_id } => {
                    let entry = remote_entries.get(rel).context("remote entry vanished")?;
                    let recorded = base.map_or("", |b| b.remote_version_id.as_str());
                    match push_version(client, store, &abs, &entry.file, dir, &sha256, recorded)? {
                        Pushed::Stored(version) => (old_file_id.clone(), version),
                        // Another upload of it is under way (another device,
                        // or someone else): not a conflict; the next run
                        // pushes it, as nothing is recorded now.
                        Pushed::Busy => {
                            result.uploaded -= 1;
                            eprintln!(
                                "  ⏸ {rel}: a new version is being uploaded elsewhere; \
                                 left for the next sync run"
                            );
                            return Ok(());
                        }
                        // Drive's side moved on since planning: keep both,
                        // as when both sides were edited.
                        Pushed::Conflict => {
                            result.uploaded -= 1;
                            return execute_file_action(
                                client,
                                store,
                                pair,
                                root,
                                rel,
                                &FileAction::Conflict,
                                remote_dirs,
                                remote_entries,
                                base,
                                vaults,
                                peer,
                                opts,
                                result,
                            );
                        }
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
                    file_id: file_id.clone(),
                    collection_id: dir.collection_id.clone(),
                    local_size: stat.size,
                    local_mtime_secs: stat.mtime_secs,
                    local_mtime_nanos: stat.mtime_nanos,
                    remote_version_id,
                    synced_at: now_unix(),
                },
            )?;
            // A new note or list: what Drive holds is the seed of what went
            // up, the base its first edit here is made against.
            if crate::editor_kind::edits_as_yjs(split_rel(rel).1) {
                let uploaded = std::fs::read(&abs)?;
                if <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&uploaded)) == sha256 {
                    crate::yjs_sync::record_upload(store, pair, rel, &file_id, &uploaded)?;
                }
            }
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
            let downloaded = pull_to(client, entry, &dir.keys, &root.join(&copy))?;
            // Mark the base conflicted: remote side = what was downloaded
            // (stops the conflict from re-firing; a version landing since is
            // a change again), local side = dirty sentinel (the canonical
            // name pushes and wins remotely next pass).
            store.put_sync_file(
                pair,
                rel,
                &SyncFileState {
                    file_id: entry.file.id.clone(),
                    collection_id: dir.collection_id.clone(),
                    local_size: -1,
                    local_mtime_secs: 0,
                    local_mtime_nanos: 0,
                    remote_version_id: downloaded_version(client, &entry.file.id, downloaded)?,
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
                        remote_version_id: downloaded_version(client, &entry.file.id, version)?,
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
        FileAction::DeleteRemote { file_id }
            if !opts.dry_run && crate::editor_kind::edits_as_yjs(split_rel(rel).1) =>
        {
            // Edited elsewhere since the last sync: the edit wins over the
            // deletion, and the file comes back.
            let entry = remote_entries.get(rel).context("remote entry vanished")?;
            let dir = remote_dirs
                .get(&entry.rel_dir)
                .context("remote dir vanished")?;
            let no_copy = || Err(anyhow!("no conflict copy for a pull"));
            let target = yjs_target(store, pair, root, rel, entry, dir, &no_copy);
            if crate::yjs_sync::unchanged_since_base(client, peer, &target)? {
                eprintln!("  ✗ {rel} (remote → trash)");
                result.deleted_remote += 1;
                client.delete_file(file_id)?;
                store.delete_sync_file(pair, rel)?;
            } else {
                eprintln!("  ↓ {rel} (edited on Drive since; kept)");
                let synced = crate::yjs_sync::sync_file(client, peer, &target, false)?;
                report_yjs(rel, &synced, result);
                if let Some(stat) = &synced.stat {
                    record_yjs(store, pair, rel, stat, entry)?;
                }
            }
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

/// A note or list of the sync, for [`crate::yjs_sync`].
fn yjs_target<'a>(
    store: &'a Store,
    pair: &'a str,
    root: &'a Path,
    rel: &'a str,
    entry: &'a RemoteEntry,
    dir: &'a RemoteDir,
    conflict_name: &'a dyn Fn() -> Result<String>,
) -> crate::yjs_sync::Target<'a> {
    crate::yjs_sync::Target {
        store,
        pair,
        rel,
        abs: root.join(rel),
        file: &entry.file,
        dir_keys: &dir.keys,
        collection_id: &dir.collection_id,
        folder_epoch: dir.key_epoch,
        conflict_name,
        root,
    }
}

/// Says what a note's or list's sync did, and counts it.
fn report_yjs(rel: &str, synced: &crate::yjs_sync::Synced, result: &mut SyncResult) {
    if let Some(copy) = &synced.conflict_copy {
        eprintln!(
            "  ⚠ {rel} (differed from Drive; Drive's copy → {copy}, yours went up as an edit)"
        );
        result.conflicts += 1;
    }
    match (synced.sent, synced.written) {
        (true, true) => {
            eprintln!("  ⇅ {rel} (merged with edits made elsewhere)");
            result.merged += 1;
        }
        (true, false) => {
            eprintln!("  ↑ {rel}");
            result.uploaded += 1;
        }
        (false, true) => {
            eprintln!("  ↓ {rel}");
            result.downloaded += 1;
        }
        (false, false) => {}
    }
    if synced.busy {
        eprintln!("  ⏸ {rel}: changed while syncing; left for the next run");
    }
}

/// Records a note or list as in sync with the file as it was compared or
/// written (`stat`, taken there: a save after it is a change next run). Its
/// Yjs base is recorded beside it by [`crate::yjs_sync`].
fn record_yjs(
    store: &Store,
    pair: &str,
    rel: &str,
    stat: &LocalFile,
    entry: &RemoteEntry,
) -> Result<()> {
    store.put_sync_file(
        pair,
        rel,
        &SyncFileState {
            file_id: entry.file.id.clone(),
            collection_id: entry.file.collection_id.clone(),
            local_size: stat.size,
            local_mtime_secs: stat.mtime_secs,
            local_mtime_nanos: stat.mtime_nanos,
            remote_version_id: entry.latest_version_id.clone(),
            synced_at: now_unix(),
        },
    )
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

/// Uploads the local file `abs` as a new version of `file` over tus,
/// resumable at any size; its metadata (size, SHA-256) and content hash land
/// with it.
fn push_version(
    client: &Client,
    store: &Store,
    abs: &Path,
    file: &crate::api::File,
    dir: &RemoteDir,
    sha256: &[u8; 32],
    recorded: &str,
) -> Result<Pushed> {
    // Made from the newest whole-file version at or before the one recorded:
    // a collaborator's version saved since is a conflict, not overwritten.
    let Some(based_on) = based_on_for(&client.list_versions(&file.id)?, recorded) else {
        eprintln!("    {}: the recorded version is gone", abs.display());
        return Ok(Pushed::Conflict);
    };
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
    let landed = version_upload::upload_version(
        client,
        store,
        version_upload::VersionRequest {
            file: &file,
            file_key: &file_key,
            content: version_upload::Content::Path(abs),
            sha256: *sha256,
            hash_key: Some(&dir.hash_key),
            based_on: Some(based_on),
            progress: Progress::Quiet,
            crashed_after_secs: crate::version_upload::FILE_CRASHED_AFTER_SECS,
        },
    )?;
    if let version_upload::Landed::Conflict(why) = &landed {
        eprintln!("    {}: {why:#}", abs.display());
    }
    Ok(pushed(landed))
}

/// What a version upload's end means for the push.
fn pushed(landed: version_upload::Landed) -> Pushed {
    match landed {
        version_upload::Landed::Stored(version) => Pushed::Stored(version),
        version_upload::Landed::Conflict(_) => Pushed::Conflict,
        version_upload::Landed::Busy => Pushed::Busy,
    }
}

/// The `basedOn` of a push: the newest whole-file version at or before
/// `recorded` (the newest version of any kind when the base was recorded;
/// `""`: none), or `original` when there is none. `None` when the recorded
/// version is no longer listed: what it was made from cannot be told.
fn based_on_for(versions: &[crate::api::versions::VersionRow], recorded: &str) -> Option<String> {
    let from = if recorded.is_empty() {
        versions.len()
    } else {
        versions.iter().position(|v| v.id == recorded)?
    };
    Some(
        versions[from..]
            .iter()
            .find(|v| v.kind.is_empty() || v.kind == "file")
            .map_or_else(
                || crate::api::versions::ORIGINAL.to_string(),
                |v| v.id.clone(),
            ),
    )
}

/// How pushing an edit as a version ended.
#[derive(Debug, PartialEq)]
enum Pushed {
    /// The version's id.
    Stored(String),
    /// The file moved on (another version, a rename, a re-key).
    Conflict,
    /// Another upload of a version of it is under way.
    Busy,
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
    let remote_version_id = downloaded_version(client, &entry.file.id, downloaded)?;
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

/// The version a download got, as the base records it: the next push is made
/// from it (`basedOn`), so a version landing after the download is a change,
/// not a base. Only when the server did not say which, the newest one now.
fn downloaded_version(
    client: &Client,
    file_id: &str,
    downloaded: Option<String>,
) -> Result<String> {
    match downloaded {
        Some(version) => Ok(recorded(&version)),
        None => latest_version_id(client, file_id),
    }
}

/// The file's newest version of any kind (`""`: none). A listing that fails
/// is an error (the run stops for this file), never "no version": that would
/// turn the next push into a conflict copy.
fn latest_version_id(client: &Client, file_id: &str) -> Result<String> {
    Ok(client
        .list_versions(file_id)
        .context("list versions")?
        .first()
        .map(|r| r.id.clone())
        .unwrap_or_default())
}

pub(crate) fn stat_local(path: &Path) -> Result<LocalFile> {
    Ok(local_file_of(&std::fs::metadata(path)?))
}

/// A file's size and modification time, as the sync records them.
pub(crate) fn local_file_of(m: &std::fs::Metadata) -> LocalFile {
    let (mtime_secs, mtime_nanos) = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unwrap_or((0, 0));
    LocalFile {
        size: m.len() as i64,
        mtime_secs,
        mtime_nanos,
    }
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

    /// A path whose Drive side could not be read this run gets no action:
    /// planned as if the remote were gone, it would be deleted locally,
    /// pushed as new, or forgotten.
    #[test]
    fn paths_not_read_this_run_sit_it_out() {
        let mut unknown = Unknown::default();
        unknown.files.insert("docs/a.dat".into());
        unknown.dirs.insert("photos".into());
        assert!(unknown.covers("docs/a.dat"));
        assert!(unknown.covers("photos/one.jpg"));
        assert!(!unknown.covers("docs/b.dat"));
        assert!(
            !unknown.covers("photos/2024/one.jpg"),
            "a subfolder is listed on its own"
        );
        assert!(!unknown.covers("photos"));
    }

    /// Until the CLI syncs Yjs-backed files as a Yjs peer, they are never
    /// pulled (a stale copy) nor updated (a fork), and nothing is recorded;
    /// a new one still goes up, and a vault or whiteboard is a whole file.
    #[test]
    fn yjs_files_sync_through_their_log_whole_files_as_versions() {
        let base_for = |rel: &str| BaseFile {
            file_id: format!("f-{rel}"),
            local_size: 1,
            local_mtime_secs: 1,
            local_mtime_nanos: 0,
            remote_version_id: "v1".into(),
        };
        let edited = LocalFile {
            size: 2,
            mtime_secs: 2,
            mtime_nanos: 0,
        };
        let same = LocalFile {
            size: 1,
            mtime_secs: 1,
            mtime_nanos: 0,
        };
        let remote_for = |rel: &str, version: &str| RemoteFileSig {
            file_id: format!("f-{rel}"),
            latest_version_id: version.into(),
        };
        let names = [
            "notes/todo.md",
            "trips/rome.kutupmap",
            "vault.kdbx",
            "board.excalidraw",
            "data.dat",
        ];
        let mut base = BTreeMap::new();
        let mut local = BTreeMap::new();
        let mut remote = BTreeMap::new();
        for name in names {
            base.insert(name.to_string(), base_for(name));
            local.insert(name.to_string(), edited.clone());
            remote.insert(name.to_string(), remote_for(name, "v1"));
        }
        // Local edits: Yjs files edited as a peer, whole files pushed as
        // versions.
        let plan: BTreeMap<_, _> = plan_files(&base, &local, &remote, false)
            .into_iter()
            .collect();
        let edit = FileAction::SyncYjs {
            local_changed: true,
        };
        assert_eq!(plan["notes/todo.md"], edit);
        assert_eq!(plan["trips/rome.kutupmap"], edit);
        for name in ["vault.kdbx", "board.excalidraw", "data.dat"] {
            assert!(
                matches!(plan[name], FileAction::PushUpdate { .. }),
                "{name}"
            );
        }
        // Remote changes: no stale pull of a Yjs file; its log is read.
        for name in names {
            local.insert(name.to_string(), same.clone());
            remote.insert(name.to_string(), remote_for(name, "v2"));
        }
        let plan: BTreeMap<_, _> = plan_files(&base, &local, &remote, false)
            .into_iter()
            .collect();
        let read = FileAction::SyncYjs {
            local_changed: false,
        };
        assert_eq!(plan["notes/todo.md"], read);
        assert_eq!(plan["vault.kdbx"], FileAction::Pull);
        // Nothing changed anywhere: a whole file is left alone, a note's log
        // is still read (edits made elsewhere are only there).
        for name in names {
            remote.insert(name.to_string(), remote_for(name, "v1"));
        }
        let plan: BTreeMap<_, _> = plan_files(&base, &local, &remote, false)
            .into_iter()
            .collect();
        assert_eq!(plan["notes/todo.md"], read);
        assert!(!plan.contains_key("data.dat"));
        // Deleted here after a version landed (the CLI's own snapshot
        // makes one): a deletion, whose content check runs before it.
        local.remove("notes/todo.md");
        remote.insert("notes/todo.md".into(), remote_for("notes/todo.md", "v9"));
        let plan: BTreeMap<_, _> = plan_files(&base, &local, &remote, true)
            .into_iter()
            .collect();
        assert!(matches!(
            plan["notes/todo.md"],
            FileAction::DeleteRemote { .. }
        ));
        // Only on Drive: pulled through its log.
        let plan = plan_files(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::from([("n.md".to_string(), remote_for("n.md", "v1"))]),
            false,
        );
        assert_eq!(
            plan,
            vec![(
                "n.md".to_string(),
                FileAction::SyncYjs {
                    local_changed: true
                }
            )]
        );
        // A new note still goes up as a new file.
        let plan = plan_files(
            &BTreeMap::new(),
            &BTreeMap::from([("new.md".to_string(), same.clone())]),
            &BTreeMap::new(),
            false,
        );
        assert_eq!(plan, vec![("new.md".to_string(), FileAction::PushNew)]);
    }

    fn row(id: &str, kind: &str) -> crate::api::versions::VersionRow {
        serde_json::from_value(serde_json::json!({ "id": id, "kind": kind, "keyGeneration": 1 }))
            .unwrap()
    }

    #[test]
    fn a_push_is_based_on_the_whole_file_version_it_started_from() {
        // Newest first.
        let versions = [
            row("y2", "yjs"),
            row("f2", "file"),
            row("y1", "yjs"),
            row("f1", "file"),
        ];
        assert_eq!(based_on_for(&versions, "y2").as_deref(), Some("f2"));
        assert_eq!(based_on_for(&versions, "y1").as_deref(), Some("f1"));
        assert_eq!(based_on_for(&versions, "f1").as_deref(), Some("f1"));
        assert_eq!(
            based_on_for(&[row("y1", "yjs")], "y1").as_deref(),
            Some("original")
        );
        assert_eq!(based_on_for(&[], "").as_deref(), Some("original"));
        // Recorded before any version: made from the original upload, so a
        // version saved since is a conflict.
        assert_eq!(based_on_for(&versions, "").as_deref(), Some("original"));
        assert_eq!(based_on_for(&versions, "gone"), None);
    }

    #[test]
    fn a_based_on_refusal_is_the_conflict_copy_path() {
        let landed = crate::version_upload::Landed::Conflict(anyhow::anyhow!("version_conflict"));
        assert_eq!(pushed(landed), Pushed::Conflict);
        assert_eq!(pushed(crate::version_upload::Landed::Busy), Pushed::Busy);
    }

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
