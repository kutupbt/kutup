//! Changing a vault as KeePass apps do (docs/plans/pass.md, K2b).
//!
//! The website changes a vault only through [`Op`]s, applied here so every
//! client edits the same way KeePassXC does: an entry's previous state goes
//! into its history before it changes (trimmed to the vault's limits),
//! deleting moves to the recycle bin, and deleting from the recycle bin (or
//! with it turned off) removes for good and records the deletion, so a
//! merge knows the object was deleted rather than never seen. Times come
//! from the caller (`now`), so the same code runs in the browser.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr as _;

use base64::Engine as _;
use chrono::NaiveDateTime;
use keepass::config::{CompressionConfig, DatabaseConfig, KdfConfig};
use keepass::db::{
    Color, CustomIcon, CustomIconId, Entry, EntryId, GroupId, History, Icon, Times, Value,
};
use keepass::Database;
use serde::{Deserialize, Serialize};

use crate::merge::{trim_history, REVIEW_KEY};
use crate::refs;
use crate::view::{group_in_recycle_bin, parse_time, recycle_bin, FieldView, STANDARD_FIELDS};

/// KeePass's built-in icons are numbered 0 to 68.
pub const BUILTIN_ICONS: usize = 69;
/// The key icon KeePass gives new entries.
const ENTRY_ICON: usize = 0;
/// The folder icon KeePass gives new groups.
const GROUP_ICON: usize = 48;
/// The recycle bin's icon.
const RECYCLE_BIN_ICON: usize = 43;
/// The longest field name, group name or tag, in characters.
const MAX_NAME_CHARS: usize = 256;
/// The largest attachment, in bytes.
pub const MAX_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;
/// The largest picture an entry or group may be given, in bytes. The
/// website sends PNGs of at most 128 px a side, far smaller.
pub const MAX_ICON_BYTES: usize = 256 * 1024;

/// One change to a vault.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Op {
    CreateEntry {
        group_id: String,
        entry: EntryInput,
    },
    /// Replaces the entry's editable data (fields, tags, icon, colours, URL
    /// override, quality check, expiry); attachments are changed on their own.
    UpdateEntry {
        id: String,
        entry: EntryInput,
    },
    DeleteEntry {
        id: String,
    },
    MoveEntry {
        id: String,
        group_id: String,
    },
    /// Moves several entries to one group, as one edit. Not into the
    /// recycle bin: that is `DeleteEntries`. All or nothing.
    MoveEntries {
        ids: Vec<String>,
        group_id: String,
    },
    /// Deletes several entries as one edit, each as `DeleteEntry` does
    /// (into the recycle bin, or for good from inside it or with it off).
    /// All or nothing.
    DeleteEntries {
        ids: Vec<String>,
    },
    /// Moves several entries into the recycle bin, as one edit, and nothing
    /// else: refused when recycling is off or an entry is in the bin
    /// already, so it never deletes for good (a drag onto the bin). All or
    /// nothing.
    RecycleEntries {
        ids: Vec<String>,
    },
    /// Takes entries out of the recycle bin, each back to the group it was
    /// in (KDBX's previous parent group), or to the top group when that one
    /// is gone or itself in the bin. All or nothing.
    RestoreEntries {
        ids: Vec<String>,
    },
    /// Makes history item `index` (oldest first) the entry's state again.
    /// Copies entries, as KeePassXC's Clone: a new id, the copy's times
    /// now, the title with `title_suffix` appended when given (" - Clone",
    /// in the person's language), and the history only when `history`.
    /// Into the group each is in, or into `group_id` (KeePassXC's
    /// Ctrl-drag, never the recycle bin). All or nothing; returns the first
    /// copy's id.
    CloneEntries {
        ids: Vec<String>,
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        title_suffix: Option<String>,
        #[serde(default)]
        history: bool,
        /// The copy's user name and password as references to the original
        /// (`{REF:U@I:…}`, `{REF:P@I:…}`), as KeePassXC's option.
        #[serde(default)]
        references: bool,
    },
    /// Deletes an entry's history items (`indexes`, oldest first as the
    /// history lists them; absent: all), remembered so a merge doesn't bring
    /// them back (`merge::HISTORY_DELETED_KEY`).
    DeleteHistory {
        id: String,
        #[serde(default)]
        indexes: Option<Vec<usize>>,
    },
    RestoreHistory {
        id: String,
        index: usize,
    },
    /// Marks the merge review of an entry done.
    ClearReview {
        id: String,
    },
    /// Adds an attachment, or replaces the one with the same name.
    AddAttachment {
        entry_id: String,
        name: String,
        /// Base64.
        data: String,
    },
    RemoveAttachment {
        entry_id: String,
        name: String,
    },
    /// Renames an attachment; refused when the entry has one of the new
    /// name already. The old name stays in the entry's history.
    RenameAttachment {
        entry_id: String,
        name: String,
        new_name: String,
    },
    /// Gives the entry its own picture (a KeePass custom icon; a PNG,
    /// base64), reusing one of the vault's with the same bytes, or with
    /// `None` the default key icon again. The previous state goes into the
    /// entry's history.
    SetEntryIcon {
        id: String,
        #[serde(default)]
        data: Option<String>,
        /// One of KeePass's built-in icons (0 to 68) instead of a picture.
        #[serde(default)]
        builtin: Option<usize>,
    },
    /// The same for a group (the default being the folder icon).
    SetGroupIcon {
        id: String,
        #[serde(default)]
        data: Option<String>,
        #[serde(default)]
        builtin: Option<usize>,
    },
    CreateGroup {
        parent_id: String,
        name: String,
    },
    UpdateGroup {
        id: String,
        name: String,
        #[serde(default)]
        notes: String,
        #[serde(default)]
        icon: Option<usize>,
    },
    DeleteGroup {
        id: String,
    },
    /// A group into the recycle bin and nothing else: refused when the bin
    /// is off or the group is in it already (a drag never deletes for good).
    RecycleGroup {
        id: String,
    },
    /// Copies a group, with every group and entry inside it, under
    /// `parent_id` (KeePassXC's Ctrl-drag, `CloneCopy`): new ids, the copies'
    /// times now, entries with their history. Never the top group or the
    /// recycle bin, nothing in the bin, and never into itself, what it holds
    /// or the bin. Returns the copy's id.
    CopyGroup {
        id: String,
        parent_id: String,
    },
    /// Moves a group (with what it holds) under another, never into the
    /// recycle bin (that is `DeleteGroup`) and never the bin itself. A group
    /// in the bin moved out of it is restored there.
    MoveGroup {
        id: String,
        parent_id: String,
    },
    /// Takes groups out of the recycle bin, each with what it holds, back
    /// under the group it was in (KDBX's previous parent group) while that is
    /// there and not itself in the bin, otherwise under the top group, as
    /// `RestoreEntries` does for entries. A group inside another one being
    /// restored comes back with it, where it is. All or nothing.
    RestoreGroups {
        ids: Vec<String>,
    },
    EmptyRecycleBin,
    /// Imports another password manager's export (`import::parse`: CSV,
    /// Bitwarden JSON, 1Password 1PUX, Proton Pass) into a new group
    /// `group_name` under the top group, its folders as groups inside, with
    /// the files a format carries. All or nothing.
    ImportCsv {
        /// The file, base64.
        data: String,
        /// `import::Provider` id; detected when absent.
        #[serde(default)]
        provider: Option<String>,
        group_name: String,
    },
    UpdateVault {
        name: String,
        #[serde(default)]
        description: String,
        #[serde(default)]
        default_user_name: String,
        /// The recycle bin on or off; absent keeps it.
        #[serde(default)]
        recycle_bin_enabled: Option<bool>,
        /// The history limits; absent keeps them. Lowering one trims every
        /// entry's history at once, as KeePassXC does.
        #[serde(default)]
        history: Option<HistoryLimits>,
    },
    /// The vault's key derivation and compression (its settings page's
    /// Encryption tab). Refused below `minimums` (the server's settings,
    /// docs/plans/pass-gaps-2.md P2) or above what any device could open.
    SetVaultConfig {
        kdf: KdfInput,
        compression: bool,
        minimums: KdfMinimums,
    },
}

/// History kept per entry; `None` is no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryLimits {
    pub max_items: Option<u32>,
    /// Bytes.
    pub max_size: Option<u64>,
}

/// A key derivation as the settings page sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum KdfInput {
    Argon2id {
        memory_mib: u64,
        iterations: u64,
        parallelism: u32,
    },
    Argon2d {
        memory_mib: u64,
        iterations: u64,
        parallelism: u32,
    },
    /// KDBX 3's AES-KDF, kept for older apps.
    AesKdf { rounds: u64 },
}

/// The weakest key derivation a vault may be set to (administrators'
/// settings; a vault already below them still opens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfMinimums {
    pub argon2_memory_mib: u64,
    pub argon2_iterations: u64,
    pub aes_kdf_rounds: u64,
}

/// The most memory a vault's Argon2 may ask of a device opening it.
pub const MAX_ARGON2_MEMORY_MIB: u64 = 2048;
/// The most Argon2 passes.
pub const MAX_ARGON2_ITERATIONS: u64 = 10_000;
/// The most Argon2 lanes.
pub const MAX_ARGON2_PARALLELISM: u32 = 16;
/// The most AES-KDF rounds.
pub const MAX_AES_KDF_ROUNDS: u64 = 1_000_000_000;
/// The most history items a limit may name.
pub const MAX_HISTORY_ITEMS: u32 = 1000;

impl KdfInput {
    /// The vault's key derivation, as `KdfConfig`.
    pub fn of(config: &KdfConfig) -> Option<Self> {
        match config {
            KdfConfig::Argon2id {
                iterations,
                memory,
                parallelism,
                ..
            } => Some(Self::Argon2id {
                memory_mib: memory / (1024 * 1024),
                iterations: *iterations,
                parallelism: *parallelism,
            }),
            KdfConfig::Argon2 {
                iterations,
                memory,
                parallelism,
                ..
            } => Some(Self::Argon2d {
                memory_mib: memory / (1024 * 1024),
                iterations: *iterations,
                parallelism: *parallelism,
            }),
            KdfConfig::Aes { rounds } => Some(Self::AesKdf { rounds: *rounds }),
            _ => None,
        }
    }

    /// Whether it is at least `minimums`.
    pub fn meets(&self, minimums: &KdfMinimums) -> bool {
        match *self {
            Self::Argon2id {
                memory_mib,
                iterations,
                ..
            }
            | Self::Argon2d {
                memory_mib,
                iterations,
                ..
            } => {
                memory_mib >= minimums.argon2_memory_mib && iterations >= minimums.argon2_iterations
            }
            Self::AesKdf { rounds } => rounds >= minimums.aes_kdf_rounds,
        }
    }

    fn config(&self) -> Result<KdfConfig, EditError> {
        let argon2 = |memory_mib: u64, iterations: u64, parallelism: u32| {
            if !(1..=MAX_ARGON2_MEMORY_MIB).contains(&memory_mib) {
                return Err(invalid(format!(
                    "Argon2 memory is at most {MAX_ARGON2_MEMORY_MIB} MiB"
                )));
            }
            if !(1..=MAX_ARGON2_ITERATIONS).contains(&iterations) {
                return Err(invalid(format!(
                    "Argon2 takes 1 to {MAX_ARGON2_ITERATIONS} iterations"
                )));
            }
            if !(1..=MAX_ARGON2_PARALLELISM).contains(&parallelism) {
                return Err(invalid(format!(
                    "Argon2 takes 1 to {MAX_ARGON2_PARALLELISM} threads"
                )));
            }
            Ok((memory_mib * 1024 * 1024, iterations, parallelism))
        };
        Ok(match *self {
            Self::Argon2id {
                memory_mib,
                iterations,
                parallelism,
            } => {
                let (memory, iterations, parallelism) =
                    argon2(memory_mib, iterations, parallelism)?;
                KdfConfig::Argon2id {
                    iterations,
                    memory,
                    parallelism,
                    version: argon2::Version::Version13,
                }
            }
            Self::Argon2d {
                memory_mib,
                iterations,
                parallelism,
            } => {
                let (memory, iterations, parallelism) =
                    argon2(memory_mib, iterations, parallelism)?;
                KdfConfig::Argon2 {
                    iterations,
                    memory,
                    parallelism,
                    version: argon2::Version::Version13,
                }
            }
            Self::AesKdf { rounds } => {
                if !(1..=MAX_AES_KDF_ROUNDS).contains(&rounds) {
                    return Err(invalid(format!(
                        "AES-KDF takes 1 to {MAX_AES_KDF_ROUNDS} rounds"
                    )));
                }
                KdfConfig::Aes { rounds }
            }
        })
    }
}

/// An entry's editable data.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryInput {
    pub fields: Vec<FieldView>,
    pub tags: Vec<String>,
    /// A built-in icon; `None` keeps the current one.
    pub icon: Option<usize>,
    /// `#rrggbb`.
    pub foreground_color: Option<String>,
    pub background_color: Option<String>,
    pub override_url: String,
    pub quality_check: bool,
    pub expires: bool,
    pub expiry: Option<String>,
}

impl Default for EntryInput {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            tags: Vec::new(),
            icon: None,
            foreground_color: None,
            background_color: None,
            override_url: String::new(),
            quality_check: true,
            expires: false,
            expiry: None,
        }
    }
}

/// What an operation made.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Applied {
    /// The new entry's or group's id.
    pub id: Option<String>,
    /// False when the operation changed nothing.
    pub changed: bool,
}

/// Why an operation was refused. Nothing was changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    #[error("no such {0}")]
    NotFound(&'static str),
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> EditError {
    EditError::Invalid(message.into())
}

fn entry_id(db: &Database, id: &str) -> Result<EntryId, EditError> {
    let id = uuid::Uuid::parse_str(id)
        .map(EntryId::from)
        .map_err(|_| EditError::NotFound("entry"))?;
    db.entries
        .contains_key(&id)
        .then_some(id)
        .ok_or(EditError::NotFound("entry"))
}

/// Every id of `ids`, each an entry of the vault, once: one unknown refuses
/// them all.
fn entry_ids(db: &Database, ids: &[String]) -> Result<Vec<EntryId>, EditError> {
    let mut seen = std::collections::HashSet::new();
    ids.iter()
        .map(|id| entry_id(db, id))
        .filter(|id| id.as_ref().map_or(true, |id| seen.insert(*id)))
        .collect()
}

fn group_id(db: &Database, id: &str) -> Result<GroupId, EditError> {
    let id = uuid::Uuid::parse_str(id)
        .map(GroupId::from)
        .map_err(|_| EditError::NotFound("group"))?;
    db.groups
        .contains_key(&id)
        .then_some(id)
        .ok_or(EditError::NotFound("group"))
}

fn check_name(name: &str, what: &str) -> Result<String, EditError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "a {what} is 1 to {MAX_NAME_CHARS} characters, without control characters"
        )));
    }
    Ok(name.to_owned())
}

/// A new, empty vault named `name`, with KeePassXC's defaults: a recycle
/// bin, ten history items of at most 6 MiB per entry, protected passwords,
/// and Argon2id key derivation light enough for a phone browser.
pub fn new_vault(name: &str, now: NaiveDateTime) -> Result<Database, EditError> {
    let name = check_name(name, "vault name")?;
    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Argon2id {
        iterations: 10,
        memory: 64 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    };
    let mut db = Database::with_config(config);
    db.meta.generator = Some("Kutup Pass".into());
    db.meta.database_name = Some(name.clone());
    db.meta.database_name_changed = Some(now);
    db.meta.recyclebin_enabled = Some(true);
    db.meta.history_max_items = Some(10);
    db.meta.history_max_size = Some(6 * 1024 * 1024);
    db.meta.settings_changed = Some(now);
    let root = db.root;
    if let Some(group) = db.groups.get_mut(&root) {
        group.name = name;
        group.icon = Some(Icon::BuiltIn(GROUP_ICON));
        set_all_times(&mut group.times, now);
    }
    Ok(db)
}

fn set_all_times(times: &mut Times, now: NaiveDateTime) {
    times.creation = Some(now);
    times.last_modification = Some(now);
    times.last_access = Some(now);
    times.location_changed = Some(now);
}

/// Applies `op` to `db`. On an error nothing was changed.
pub fn apply(db: &mut Database, op: &Op, now: NaiveDateTime) -> Result<Applied, EditError> {
    let applied = match op {
        Op::CreateEntry { group_id: g, entry } => create_entry(db, g, entry, now)?,
        Op::UpdateEntry { id, entry } => {
            let id = entry_id(db, id)?;
            let input = entry.clone();
            edit_entry(db, id, now, |db, e| fill_entry(db, e, &input))?
        }
        Op::DeleteEntry { id } => delete_entry(db, entry_id(db, id)?, now),
        Op::MoveEntry { id, group_id: g } => {
            let id = entry_id(db, id)?;
            let target = group_id(db, g)?;
            move_entry(db, id, target, now)
        }
        Op::MoveEntries { ids, group_id: g } => {
            let ids = entry_ids(db, ids)?;
            let target = group_id(db, g)?;
            if group_in_recycle_bin(db, target) {
                return Err(invalid("entries go to the recycle bin by being deleted"));
            }
            let mut changed = false;
            for id in ids {
                changed |= move_entry(db, id, target, now).changed;
            }
            Applied { id: None, changed }
        }
        Op::DeleteEntries { ids } => {
            let ids = entry_ids(db, ids)?;
            let mut changed = false;
            for id in ids {
                changed |= delete_entry(db, id, now).changed;
            }
            Applied { id: None, changed }
        }
        Op::RecycleEntries { ids } => {
            let ids = entry_ids(db, ids)?;
            if !recycle(db) {
                return Err(invalid(
                    "the recycle bin is off: entries would be deleted for good",
                ));
            }
            if ids
                .iter()
                .any(|id| group_in_recycle_bin(db, db.entries[id].parent))
            {
                return Err(invalid("an entry is in the recycle bin already"));
            }
            for &id in &ids {
                delete_entry(db, id, now);
            }
            Applied {
                id: None,
                changed: !ids.is_empty(),
            }
        }
        Op::RestoreEntries { ids } => {
            let ids = entry_ids(db, ids)?;
            if ids
                .iter()
                .any(|id| !group_in_recycle_bin(db, db.entries[id].parent))
            {
                return Err(invalid("only entries in the recycle bin are restored"));
            }
            for &id in &ids {
                let target = restore_target(db, id);
                move_entry(db, id, target, now);
            }
            Applied {
                id: None,
                changed: !ids.is_empty(),
            }
        }
        Op::CloneEntries {
            ids,
            group_id: into,
            title_suffix,
            history,
            references,
        } => {
            let ids = entry_ids(db, ids)?;
            let suffix = title_suffix.as_deref().unwrap_or("");
            if suffix.chars().count() > MAX_NAME_CHARS {
                return Err(invalid("a title suffix is too long"));
            }
            let into = into.as_deref().map(|g| group_id(db, g)).transpose()?;
            if into.is_some_and(|g| group_in_recycle_bin(db, g)) {
                return Err(invalid("nothing is copied into the recycle bin"));
            }
            let mut first = None;
            for id in ids {
                let copy = clone_entry(db, id, suffix, *history, into, now)?;
                if *references {
                    let hex = id.uuid().simple().to_string();
                    if let Some(copy) = db.entries.get_mut(&copy) {
                        for (key, field) in [("UserName", 'U'), ("Password", 'P')] {
                            let protected = copy.fields.get(key).is_some_and(Value::is_protected)
                                || key == "Password";
                            let text = format!("{{REF:{field}@I:{hex}}}");
                            copy.fields.insert(
                                key.into(),
                                if protected {
                                    Value::protected(text)
                                } else {
                                    Value::unprotected(text)
                                },
                            );
                        }
                    }
                }
                first.get_or_insert(copy);
            }
            Applied {
                id: first.map(|id| id.uuid().to_string()),
                changed: first.is_some(),
            }
        }
        Op::DeleteHistory { id, indexes } => {
            let id = entry_id(db, id)?;
            let items = db.entries[&id]
                .history
                .as_ref()
                .map(|h| h.entries.clone())
                .unwrap_or_default();
            let doomed: BTreeSet<usize> = match indexes {
                Some(indexes) => {
                    if indexes.iter().any(|i| *i >= items.len()) {
                        return Err(EditError::NotFound("history item"));
                    }
                    indexes.iter().copied().collect()
                }
                None => (0..items.len()).collect(),
            };
            if doomed.is_empty() {
                Applied::default()
            } else {
                let entry = db
                    .entries
                    .get_mut(&id)
                    .ok_or(EditError::NotFound("entry"))?;
                let mut deleted = crate::merge::deleted_history(entry);
                deleted.extend(
                    doomed
                        .iter()
                        .filter_map(|i| items[*i].times.last_modification),
                );
                let kept: Vec<Entry> = items
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| !doomed.contains(i))
                    .map(|(_, item)| item)
                    .collect();
                if let Some(history) = entry.history.as_mut() {
                    history.entries = kept;
                }
                crate::merge::set_deleted_history(entry, &deleted, Some(now));
                Applied {
                    id: None,
                    changed: true,
                }
            }
        }
        Op::RestoreHistory { id, index } => restore_history(db, entry_id(db, id)?, *index, now)?,
        Op::ClearReview { id } => {
            let id = entry_id(db, id)?;
            let entry = db
                .entries
                .get_mut(&id)
                .ok_or(EditError::NotFound("entry"))?;
            Applied {
                id: None,
                changed: entry.custom_data.remove(REVIEW_KEY).is_some(),
            }
        }
        Op::AddAttachment {
            entry_id: e,
            name,
            data,
        } => {
            let id = entry_id(db, e)?;
            let name = check_name(name, "attachment name")?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|_| invalid("an attachment's data is base64"))?;
            if data.len() > MAX_ATTACHMENT_BYTES {
                return Err(invalid("an attachment is at most 50 MiB"));
            }
            let attachment = refs::import_attachment(db, &Value::unprotected(data));
            edit_entry(db, id, now, |_, e| {
                e.attachments.insert(name.clone(), attachment);
                Ok(())
            })?
        }
        Op::RemoveAttachment { entry_id: e, name } => {
            let id = entry_id(db, e)?;
            if !db.entries[&id].attachments.contains_key(name) {
                return Err(EditError::NotFound("attachment"));
            }
            edit_entry(db, id, now, |_, e| {
                e.attachments.remove(name);
                Ok(())
            })?
        }
        Op::RenameAttachment {
            entry_id: e,
            name,
            new_name,
        } => {
            let id = entry_id(db, e)?;
            let new_name = check_name(new_name, "attachment name")?;
            let entry = &db.entries[&id];
            if !entry.attachments.contains_key(name) {
                return Err(EditError::NotFound("attachment"));
            }
            if new_name == *name {
                Applied::default()
            } else {
                if entry.attachments.contains_key(&new_name) {
                    return Err(invalid("the entry has an attachment of that name already"));
                }
                edit_entry(db, id, now, |_, e| {
                    let attachment = e.attachments.remove(name).expect("checked above");
                    e.attachments.insert(new_name.clone(), attachment);
                    Ok(())
                })?
            }
        }
        Op::SetEntryIcon { id, data, builtin } => {
            let id = entry_id(db, id)?;
            let icon = chosen_icon(db, data.as_deref(), *builtin, ENTRY_ICON, now)?;
            edit_entry(db, id, now, |_, e| {
                e.icon = Some(icon);
                Ok(())
            })?
        }
        Op::SetGroupIcon { id, data, builtin } => {
            let id = group_id(db, id)?;
            let icon = chosen_icon(db, data.as_deref(), *builtin, GROUP_ICON, now)?;
            let group = db.groups.get_mut(&id).ok_or(EditError::NotFound("group"))?;
            let changed = group.icon.as_ref() != Some(&icon);
            if changed {
                group.icon = Some(icon);
                group.times.last_modification = Some(now);
            }
            Applied { id: None, changed }
        }
        Op::CreateGroup { parent_id, name } => {
            let parent = group_id(db, parent_id)?;
            let name = check_name(name, "group name")?;
            let mut parent = db.group_mut(parent).ok_or(EditError::NotFound("group"))?;
            let mut group = parent.add_group();
            group.name = name;
            group.icon = Some(Icon::BuiltIn(GROUP_ICON));
            set_all_times(&mut group.times, now);
            Applied {
                id: Some(group.id.uuid().to_string()),
                changed: true,
            }
        }
        Op::UpdateGroup {
            id,
            name,
            notes,
            icon,
        } => {
            let id = group_id(db, id)?;
            let name = check_name(name, "group name")?;
            if icon.is_some_and(|icon| icon >= BUILTIN_ICONS) {
                return Err(invalid("no such icon"));
            }
            let group = db.groups.get_mut(&id).ok_or(EditError::NotFound("group"))?;
            let notes = Some(notes.clone()).filter(|n| !n.is_empty());
            let icon = icon.map(Icon::BuiltIn).or_else(|| group.icon.clone());
            let changed = group.name != name || group.notes != notes || group.icon != icon;
            if changed {
                group.name = name;
                group.notes = notes;
                group.icon = icon;
                group.times.last_modification = Some(now);
            }
            Applied { id: None, changed }
        }
        Op::DeleteGroup { id } => {
            let id = group_id(db, id)?;
            if id == db.root {
                return Err(invalid("the vault's top group cannot be deleted"));
            }
            delete_group(db, id, now)
        }
        Op::RecycleGroup { id } => {
            let id = group_id(db, id)?;
            if id == db.root {
                return Err(invalid("the vault's top group cannot be deleted"));
            }
            if !recycle(db) {
                return Err(invalid(
                    "the recycle bin is off: the group would be deleted for good",
                ));
            }
            if group_in_recycle_bin(db, id) {
                return Err(invalid("the group is in the recycle bin already"));
            }
            delete_group(db, id, now)
        }
        Op::CopyGroup { id, parent_id } => {
            let id = group_id(db, id)?;
            let parent = group_id(db, parent_id)?;
            if id == db.root || Some(id) == recycle_bin(db) {
                return Err(invalid("the top group and the recycle bin are not copied"));
            }
            if group_in_recycle_bin(db, id) || group_in_recycle_bin(db, parent) {
                return Err(invalid("nothing is copied from or into the recycle bin"));
            }
            if group_within(db, parent, id) {
                return Err(invalid("a group cannot be copied into itself"));
            }
            let copy = copy_group(db, id, parent, now)?;
            Applied {
                id: Some(copy.uuid().to_string()),
                changed: true,
            }
        }
        Op::MoveGroup { id, parent_id } => {
            let id = group_id(db, id)?;
            let parent = group_id(db, parent_id)?;
            if Some(id) == recycle_bin(db) {
                return Err(invalid("the recycle bin stays where it is"));
            }
            if group_in_recycle_bin(db, parent) {
                return Err(invalid("groups go to the recycle bin by being deleted"));
            }
            if db.groups[&id].parent == Some(parent) {
                Applied::default()
            } else {
                let mut group = db.group_mut(id).ok_or(EditError::NotFound("group"))?;
                group.move_to(parent).map_err(|_| {
                    invalid("a group cannot move into itself or move the top group")
                })?;
                group.times.location_changed = Some(now);
                Applied {
                    id: None,
                    changed: true,
                }
            }
        }
        Op::RestoreGroups { ids } => {
            // In the order given (restored groups land in it), each once.
            let mut ids = ids
                .iter()
                .map(|id| group_id(db, id))
                .collect::<Result<Vec<GroupId>, _>>()?;
            let mut seen = HashSet::new();
            ids.retain(|id| seen.insert(*id));
            let bin = recycle_bin(db);
            if ids
                .iter()
                .any(|id| Some(*id) == bin || !group_in_recycle_bin(db, *id))
            {
                return Err(invalid("only groups in the recycle bin are restored"));
            }
            // A group inside another one being restored comes back with it.
            let outermost: Vec<GroupId> = ids
                .iter()
                .copied()
                .filter(|id| !has_ancestor_in(db, *id, &seen))
                .collect();
            for &id in &outermost {
                let target = restore_group_target(db, id);
                if let Some(mut group) = db.group_mut(id) {
                    // Both exist and the target is outside the bin, so
                    // never inside the group itself.
                    if group.move_to(target).is_ok() {
                        group.times.location_changed = Some(now);
                    }
                }
            }
            Applied {
                id: None,
                changed: !outermost.is_empty(),
            }
        }
        Op::ImportCsv {
            data,
            provider,
            group_name,
        } => {
            // All or nothing: a refused entry undoes the whole import.
            let before = db.clone();
            let applied = import_csv(db, data, provider.as_deref(), group_name, now);
            if applied.is_err() {
                *db = before;
            }
            applied?
        }
        Op::EmptyRecycleBin => match recycle_bin(db) {
            Some(bin) => {
                let group = &db.groups[&bin];
                let groups: Vec<GroupId> = group.groups.iter().copied().collect();
                let entries: Vec<EntryId> = group.entries.iter().copied().collect();
                let changed = !groups.is_empty() || !entries.is_empty();
                for id in entries {
                    purge_entry(db, id, now);
                }
                for id in groups {
                    purge_group(db, id, now);
                }
                Applied { id: None, changed }
            }
            None => Applied::default(),
        },
        Op::UpdateVault {
            name,
            description,
            default_user_name,
            recycle_bin_enabled,
            history,
        } => {
            if history.is_some_and(|h| h.max_items.is_some_and(|n| n > MAX_HISTORY_ITEMS)) {
                return Err(invalid(format!(
                    "at most {MAX_HISTORY_ITEMS} history items"
                )));
            }
            if history.is_some_and(|h| h.max_size.is_some_and(|n| n > i64::MAX as u64)) {
                return Err(invalid("a history size is too large"));
            }
            let name = check_name(name, "vault name")?;
            let meta = &mut db.meta;
            let mut changed = false;
            if meta.database_name.as_deref() != Some(name.as_str()) {
                meta.database_name = Some(name);
                meta.database_name_changed = Some(now);
                changed = true;
            }
            let description = Some(description.clone()).filter(|d| !d.is_empty());
            if meta.database_description != description {
                meta.database_description = description;
                meta.database_description_changed = Some(now);
                changed = true;
            }
            let user = Some(default_user_name.clone()).filter(|u| !u.is_empty());
            if meta.default_username != user {
                meta.default_username = user;
                meta.default_username_changed = Some(now);
                changed = true;
            }
            if let Some(enabled) = recycle_bin_enabled {
                if meta.recyclebin_enabled.unwrap_or(true) != *enabled {
                    meta.recyclebin_enabled = Some(*enabled);
                    meta.recyclebin_changed = Some(now);
                    changed = true;
                }
            }
            if let Some(limits) = history {
                // KeePass's "no limit" is -1.
                let items = limits.max_items.map_or(-1, |n| n as isize);
                let size = limits.max_size.map_or(-1, |n| n as isize);
                if meta.history_max_items.unwrap_or(-1) != items
                    || meta.history_max_size.unwrap_or(-1) != size
                {
                    meta.history_max_items = Some(items);
                    meta.history_max_size = Some(size);
                    meta.settings_changed = Some(now);
                    changed = true;
                    trim_every_history(db);
                }
            }
            Applied { id: None, changed }
        }
        Op::SetVaultConfig {
            kdf,
            compression,
            minimums,
        } => {
            let config = kdf.config()?;
            if !kdf.meets(minimums) {
                return Err(invalid(
                    "the key derivation is weaker than this server allows",
                ));
            }
            let compression = if *compression {
                CompressionConfig::GZip
            } else {
                CompressionConfig::None
            };
            let changed =
                db.config.kdf_config != config || db.config.compression_config != compression;
            if changed {
                db.config.kdf_config = config;
                db.config.compression_config = compression;
                db.meta.settings_changed = Some(now);
            }
            Applied { id: None, changed }
        }
    };
    refs::rebuild(db);
    Ok(applied)
}

/// Derives one key with `kdf` (an empty vault saved under a throwaway
/// password), for the settings page to time: KeePassXC's "Benchmark 1 s".
pub fn derive_once(kdf: &KdfInput) -> Result<(), EditError> {
    let mut config = DatabaseConfig::default();
    config.kdf_config = kdf.config()?;
    let db = Database::with_config(config);
    crate::save(&db, &crate::VaultKey::new().with_password("benchmark"))
        .map(|_| ())
        .map_err(|error| invalid(error.to_string()))
}

/// Trims every entry's history to the vault's limits (after they changed).
fn trim_every_history(db: &mut Database) {
    let ids: Vec<EntryId> = db.entries.keys().copied().collect();
    for id in ids {
        let Some(mut items) = db.entries[&id].history.as_ref().map(|h| h.entries.clone()) else {
            continue;
        };
        let before = items.len();
        trim_history(db, &mut items);
        if items.len() != before {
            if let Some(history) = db.entries.get_mut(&id).and_then(|e| e.history.as_mut()) {
                history.entries = items;
            }
        }
    }
}

/// The icon an `Op::Set*Icon` asks for: a picture, a built-in icon, or the
/// default; never both a picture and a built-in one.
fn chosen_icon(
    db: &mut Database,
    data: Option<&str>,
    builtin: Option<usize>,
    default: usize,
    now: NaiveDateTime,
) -> Result<Icon, EditError> {
    match (data, builtin) {
        (Some(_), Some(_)) => Err(invalid("a picture or a built-in icon, not both")),
        (Some(data), None) => Ok(Icon::Custom(custom_icon(db, data, now)?)),
        (None, Some(n)) if n < BUILTIN_ICONS => Ok(Icon::BuiltIn(n)),
        (None, Some(_)) => Err(invalid("no such icon")),
        (None, None) => Ok(Icon::BuiltIn(default)),
    }
}

/// The parts of an entry an edit changes; equal when nothing changed.
fn content(entry: &Entry) -> Entry {
    let mut copy = entry.clone();
    copy.history = None;
    copy.times = Times::default();
    copy
}

/// The vault's picture with the bytes of `data` (a PNG, base64), adding it
/// if none has them, as KeePassXC does.
fn custom_icon(
    db: &mut Database,
    data: &str,
    now: NaiveDateTime,
) -> Result<CustomIconId, EditError> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| invalid("a picture's data is base64"))?;
    if data.len() > MAX_ICON_BYTES {
        return Err(invalid("a picture is at most 256 KiB"));
    }
    if crate::view::raster_kind(&data) != Some("image/png") {
        return Err(invalid("a picture is a PNG"));
    }
    let mut same: Vec<&CustomIcon> = db
        .custom_icons
        .values()
        .filter(|icon| icon.data == data)
        .collect();
    same.sort_by_key(|icon| icon.id.uuid());
    if let Some(icon) = same.first() {
        return Ok(icon.id);
    }
    let id = CustomIconId::from_uuid(uuid::Uuid::new_v4());
    db.custom_icons.insert(
        id,
        CustomIcon {
            id,
            entries: Default::default(),
            groups: Default::default(),
            name: None,
            last_modification_time: Some(now),
            data,
        },
    );
    Ok(id)
}

/// Edits entry `id` as KeePass apps do: its previous state into its history
/// (trimmed to the vault's limits) and the modification time set, unless
/// nothing changed.
fn edit_entry(
    db: &mut Database,
    id: EntryId,
    now: NaiveDateTime,
    change: impl FnOnce(&Database, &mut Entry) -> Result<(), EditError>,
) -> Result<Applied, EditError> {
    let before = db
        .entries
        .get(&id)
        .ok_or(EditError::NotFound("entry"))?
        .clone();
    let mut after = before.clone();
    change(db, &mut after)?;
    if content(&after) == content(&before) {
        return Ok(Applied::default());
    }
    let mut previous = before;
    let mut items = previous
        .history
        .take()
        .map(|h| h.entries)
        .unwrap_or_default();
    items.push(previous);
    trim_history(db, &mut items);
    after.history = Some(History { entries: items });
    after.times.last_modification = Some(now);
    after.times.last_access = Some(now);
    db.entries.insert(id, after);
    Ok(Applied {
        id: None,
        changed: true,
    })
}

/// Sets an entry's editable data from `input`.
fn fill_entry(db: &Database, entry: &mut Entry, input: &EntryInput) -> Result<(), EditError> {
    let protection = db.meta.memory_protection.clone().unwrap_or_default();
    let protect_standard = |key: &str| match key {
        "Title" => protection.protect_title,
        "UserName" => protection.protect_username,
        "Password" => protection.protect_password,
        "URL" => protection.protect_url,
        "Notes" => protection.protect_notes,
        _ => false,
    };
    let mut fields: HashMap<String, Value<String>> = HashMap::new();
    for field in &input.fields {
        let key = if STANDARD_FIELDS.contains(&field.key.as_str()) {
            field.key.clone()
        } else {
            check_name(&field.key, "field name")?
        };
        if fields.contains_key(&key) {
            return Err(invalid(format!("the field {key} is there twice")));
        }
        let value = if field.protected || protect_standard(&key) {
            Value::protected(field.value.clone())
        } else {
            Value::unprotected(field.value.clone())
        };
        fields.insert(key, value);
    }
    // The passkey fields the view never shows (crate::passkey) stay as they
    // were unless the input names them.
    for (key, value) in &entry.fields {
        if crate::passkey::is_passkey_field(key) && !fields.contains_key(key) {
            fields.insert(key.clone(), value.clone());
        }
    }
    // KeePass entries always have the standard fields.
    for key in STANDARD_FIELDS {
        fields.entry(key.to_owned()).or_insert_with(|| {
            if protect_standard(key) {
                Value::protected(String::new())
            } else {
                Value::unprotected(String::new())
            }
        });
    }
    let mut tags: BTreeSet<String> = BTreeSet::new();
    for tag in &input.tags {
        let tag = tag.trim();
        if !tag.is_empty() {
            tags.insert(check_name(tag, "tag")?);
        }
    }
    if let Some(icon) = input.icon {
        if icon >= BUILTIN_ICONS {
            return Err(invalid("no such icon"));
        }
        entry.icon = Some(Icon::BuiltIn(icon));
    }
    let colour = |value: &Option<String>| -> Result<Option<Color>, EditError> {
        value
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(|v| Color::from_str(v).map_err(|_| invalid("a colour is #rrggbb")))
            .transpose()
    };
    let expiry = match input.expiry.as_deref().filter(|e| !e.is_empty()) {
        Some(value) => Some(parse_time(value).ok_or_else(|| invalid("an expiry is a time"))?),
        None => None,
    };
    if input.expires && expiry.is_none() {
        return Err(invalid("an entry that expires needs an expiry time"));
    }
    entry.fields = fields;
    // Keep the order of tags already there; add new ones after.
    let mut ordered: Vec<String> = entry
        .tags
        .iter()
        .filter(|tag| tags.contains(*tag))
        .cloned()
        .collect();
    for tag in tags {
        if !ordered.contains(&tag) {
            ordered.push(tag);
        }
    }
    entry.tags = ordered;
    entry.foreground_color = colour(&input.foreground_color)?;
    entry.background_color = colour(&input.background_color)?;
    entry.override_url = Some(input.override_url.clone()).filter(|u| !u.is_empty());
    entry.quality_check = input.quality_check;
    entry.times.expires = Some(input.expires);
    entry.times.expiry = expiry.or(entry.times.expiry);
    Ok(())
}

fn create_entry(
    db: &mut Database,
    group: &str,
    input: &EntryInput,
    now: NaiveDateTime,
) -> Result<Applied, EditError> {
    let group = group_id(db, group)?;
    let id = EntryId::new();
    db.group_mut(group)
        .ok_or(EditError::NotFound("group"))?
        .add_entry_with_id(id)
        .map_err(|_| invalid("the entry exists"))?;
    let mut entry = db.entries[&id].clone();
    entry.icon = Some(Icon::BuiltIn(ENTRY_ICON));
    if let Err(error) = fill_entry(db, &mut entry, input) {
        // Refused: the vault is left as it was.
        if let Some(added) = db.entry_mut(id) {
            added.remove();
        }
        return Err(error);
    }
    set_all_times(&mut entry.times, now);
    db.entries.insert(id, entry);
    Ok(Applied {
        id: Some(id.uuid().to_string()),
        changed: true,
    })
}

/// Whether group `id` is `ancestor` or inside it.
fn group_within(db: &Database, id: GroupId, ancestor: GroupId) -> bool {
    let mut current = Some(id);
    while let Some(group) = current {
        if group == ancestor {
            return true;
        }
        current = db.groups.get(&group).and_then(|g| g.parent);
    }
    false
}

/// A copy of group `id` and everything in it under `parent`
/// (`Op::CopyGroup`); the caller has checked the two.
fn copy_group(
    db: &mut Database,
    id: GroupId,
    parent: GroupId,
    now: NaiveDateTime,
) -> Result<GroupId, EditError> {
    let source = db.groups[&id].clone();
    let copy_id = {
        let mut parent = db.group_mut(parent).ok_or(EditError::NotFound("group"))?;
        let mut group = parent.add_group();
        group.name = source.name.clone();
        group.notes = source.notes.clone();
        group.tags = source.tags.clone();
        group.icon = source.icon.clone();
        group.custom_data = source.custom_data.clone();
        group.is_expanded = source.is_expanded;
        group.default_autotype_sequence = source.default_autotype_sequence.clone();
        group.enable_autotype = source.enable_autotype;
        group.enable_searching = source.enable_searching;
        set_all_times(&mut group.times, now);
        group.id
    };
    // In the source's order; the lists are taken first, so the copy (made
    // outside the source) is never walked.
    for entry in source.entries.iter().copied() {
        clone_entry(db, entry, "", true, Some(copy_id), now)?;
    }
    for child in source.groups.iter().copied() {
        copy_group(db, child, copy_id, now)?;
    }
    Ok(copy_id)
}

/// A copy of entry `id`, beside it or in group `into` (`Op::CloneEntries`).
fn clone_entry(
    db: &mut Database,
    id: EntryId,
    suffix: &str,
    history: bool,
    into: Option<GroupId>,
    now: NaiveDateTime,
) -> Result<EntryId, EditError> {
    let source = db.entries[&id].clone();
    let copy_id = EntryId::new();
    db.group_mut(into.unwrap_or(source.parent))
        .ok_or(EditError::NotFound("group"))?
        .add_entry_with_id(copy_id)
        .map_err(|_| invalid("the entry exists"))?;
    let mut copy = db.entries[&copy_id].clone();
    copy.fields = source.fields.clone();
    if !suffix.is_empty() {
        if let Some(title) = copy.fields.get_mut("Title") {
            let protected = title.is_protected();
            let text = format!("{}{suffix}", title.get());
            *title = if protected {
                Value::protected(text)
            } else {
                Value::unprotected(text)
            };
        } else {
            copy.fields.insert(
                "Title".into(),
                Value::unprotected(suffix.trim_start().to_owned()),
            );
        }
    }
    copy.tags = source.tags.clone();
    copy.icon = source.icon.clone();
    copy.foreground_color = source.foreground_color.clone();
    copy.background_color = source.background_color.clone();
    copy.override_url = source.override_url.clone();
    copy.quality_check = source.quality_check;
    copy.autotype = source.autotype.clone();
    // The same attachment data, shared (refs::rebuild counts the copy).
    copy.attachments = source.attachments.clone();
    copy.custom_data = source.custom_data.clone();
    copy.custom_data.remove(REVIEW_KEY);
    copy.custom_data.remove(crate::merge::HISTORY_DELETED_KEY);
    copy.times.expires = source.times.expires;
    copy.times.expiry = source.times.expiry;
    set_all_times(&mut copy.times, now);
    if history {
        copy.history = source.history.clone().map(|mut h| {
            for item in &mut h.entries {
                item.id = copy_id;
                item.custom_data.remove(REVIEW_KEY);
            }
            h
        });
    }
    db.entries.insert(copy_id, copy);
    Ok(copy_id)
}

fn move_entry(db: &mut Database, id: EntryId, target: GroupId, now: NaiveDateTime) -> Applied {
    let Some(mut entry) = db.entry_mut(id) else {
        return Applied::default();
    };
    if entry.parent == target {
        return Applied::default();
    }
    // Both exist: checked by the caller.
    let _ = entry.move_to(target);
    entry.times.location_changed = Some(now);
    Applied {
        id: None,
        changed: true,
    }
}

/// Where a deleted entry goes back to: the group it was in, while that is
/// there and not itself in the recycle bin; otherwise the top group.
fn restore_target(db: &Database, id: EntryId) -> GroupId {
    db.entries[&id]
        .previous_parent_group
        .filter(|group| db.groups.contains_key(group) && !group_in_recycle_bin(db, *group))
        .unwrap_or(db.root)
}

/// Where a deleted group goes back to: the group it was in, while that is
/// there and not itself in the recycle bin; otherwise the top group.
fn restore_group_target(db: &Database, id: GroupId) -> GroupId {
    db.groups[&id]
        .previous_parent_group
        .filter(|group| db.groups.contains_key(group) && !group_in_recycle_bin(db, *group))
        .unwrap_or(db.root)
}

/// Whether a group above `id` is one of `ids`.
fn has_ancestor_in(db: &Database, id: GroupId, ids: &HashSet<GroupId>) -> bool {
    let mut current = db.groups.get(&id).and_then(|g| g.parent);
    while let Some(group) = current {
        if ids.contains(&group) {
            return true;
        }
        current = db.groups.get(&group).and_then(|g| g.parent);
    }
    false
}

/// The recycle bin, made if the vault has none yet.
fn ensure_recycle_bin(db: &mut Database, now: NaiveDateTime) -> GroupId {
    if let Some(bin) = recycle_bin(db) {
        return bin;
    }
    let root = db.root;
    let id = {
        #[allow(clippy::expect_used)] // the root group always exists
        let mut root = db.group_mut(root).expect("the root group");
        let mut group = root.add_group();
        group.name = "Recycle Bin".into();
        group.icon = Some(Icon::BuiltIn(RECYCLE_BIN_ICON));
        group.enable_autotype = Some(false);
        group.enable_searching = Some(false);
        set_all_times(&mut group.times, now);
        group.id
    };
    db.meta.recyclebin_uuid = Some(id.uuid());
    db.meta.recyclebin_changed = Some(now);
    id
}

fn recycle(db: &Database) -> bool {
    db.meta.recyclebin_enabled.unwrap_or(true)
}

fn delete_entry(db: &mut Database, id: EntryId, now: NaiveDateTime) -> Applied {
    let parent = db.entries[&id].parent;
    if recycle(db) && !group_in_recycle_bin(db, parent) {
        let bin = ensure_recycle_bin(db, now);
        move_entry(db, id, bin, now)
    } else {
        purge_entry(db, id, now);
        Applied {
            id: None,
            changed: true,
        }
    }
}

fn purge_entry(db: &mut Database, id: EntryId, now: NaiveDateTime) {
    if let Some(entry) = db.entry_mut(id) {
        entry.remove();
        db.deleted_objects.insert(id.uuid(), Some(now));
    }
}

fn delete_group(db: &mut Database, id: GroupId, now: NaiveDateTime) -> Applied {
    if recycle(db) && !group_in_recycle_bin(db, id) {
        let bin = ensure_recycle_bin(db, now);
        if let Some(mut group) = db.group_mut(id) {
            if group.move_to(bin).is_ok() {
                group.times.location_changed = Some(now);
            }
        }
    } else {
        purge_group(db, id, now);
    }
    Applied {
        id: None,
        changed: true,
    }
}

/// Removes a group and everything in it for good, recording each deletion.
fn purge_group(db: &mut Database, id: GroupId, now: NaiveDateTime) {
    let mut stack = vec![id];
    let mut removed = Vec::new();
    while let Some(group) = stack.pop() {
        if let Some(g) = db.groups.get(&group) {
            removed.push(group.uuid());
            removed.extend(g.entries.iter().map(|e| e.uuid()));
            stack.extend(g.groups.iter().copied());
        }
    }
    if let Some(group) = db.group_mut(id) {
        group.remove();
    }
    for uuid in removed {
        db.deleted_objects.insert(uuid, Some(now));
    }
}

fn restore_history(
    db: &mut Database,
    id: EntryId,
    index: usize,
    now: NaiveDateTime,
) -> Result<Applied, EditError> {
    let earlier = db.entries[&id]
        .history
        .as_ref()
        .and_then(|h| h.entries.get(index))
        .cloned()
        .ok_or(EditError::NotFound("history item"))?;
    edit_entry(db, id, now, |_, entry| {
        entry.fields = earlier.fields.clone();
        entry.tags = earlier.tags.clone();
        entry.icon = earlier.icon.clone();
        entry.foreground_color = earlier.foreground_color.clone();
        entry.background_color = earlier.background_color.clone();
        entry.override_url = earlier.override_url.clone();
        entry.quality_check = earlier.quality_check;
        entry.autotype = earlier.autotype.clone();
        entry.attachments = earlier.attachments.clone();
        entry.times.expires = earlier.times.expires;
        entry.times.expiry = earlier.times.expiry;
        Ok(())
    })
}

/// The group named `name` directly under `parent`, made if there is none.
fn child_group(
    db: &mut Database,
    parent: GroupId,
    name: &str,
    now: NaiveDateTime,
) -> Result<GroupId, EditError> {
    let existing = db.groups[&parent]
        .groups
        .iter()
        .copied()
        .find(|id| db.groups.get(id).is_some_and(|g| g.name == name));
    if let Some(id) = existing {
        return Ok(id);
    }
    let name = check_name(name, "group name")?;
    let mut parent = db.group_mut(parent).ok_or(EditError::NotFound("group"))?;
    let mut group = parent.add_group();
    group.name = name;
    group.icon = Some(Icon::BuiltIn(GROUP_ICON));
    set_all_times(&mut group.times, now);
    Ok(group.id)
}

/// Names cut to the longest a field or tag may be.
fn clip(name: &str) -> String {
    name.trim().chars().take(MAX_NAME_CHARS).collect()
}

/// An imported entry's fields, named so none clash: a custom field named
/// like a standard one, or twice, gets " (2)"…
fn imported_fields(entry: &crate::import::ImportedEntry) -> Vec<FieldView> {
    let mut fields = vec![
        FieldView {
            key: "Title".into(),
            value: entry.title.clone(),
            protected: false,
        },
        FieldView {
            key: "UserName".into(),
            value: entry.username.clone(),
            protected: false,
        },
        FieldView {
            key: "Password".into(),
            value: entry.password.clone(),
            protected: true,
        },
        FieldView {
            key: "URL".into(),
            value: entry.urls.first().cloned().unwrap_or_default(),
            protected: false,
        },
        FieldView {
            key: "Notes".into(),
            value: entry.notes.clone(),
            protected: false,
        },
    ];
    for (n, url) in entry.urls.iter().skip(1).enumerate() {
        fields.push(FieldView {
            key: format!("KP2A_URL_{}", n + 1),
            value: url.clone(),
            protected: false,
        });
    }
    if let Some(otp) = &entry.otp {
        fields.push(FieldView {
            key: "otp".into(),
            value: otp.clone(),
            protected: true,
        });
    }
    for field in &entry.fields {
        let base = {
            let clipped = clip(&field.key);
            if clipped.is_empty() || clipped.chars().any(char::is_control) {
                "Field".to_owned()
            } else {
                clipped
            }
        };
        let mut key = base.clone();
        let mut n = 2;
        while fields.iter().any(|f| f.key == key) {
            key = format!("{base} ({n})");
            n += 1;
        }
        fields.push(FieldView {
            key,
            value: field.value.clone(),
            protected: field.protected,
        });
    }
    fields
}

fn import_csv(
    db: &mut Database,
    data: &str,
    provider: Option<&str>,
    group_name: &str,
    now: NaiveDateTime,
) -> Result<Applied, EditError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| invalid("the file is base64"))?;
    let provider = match provider {
        Some(id) => Some(
            crate::import::Provider::from_id(id).ok_or_else(|| invalid("no such import format"))?,
        ),
        None => None,
    };
    let parsed = crate::import::parse(&bytes, provider).map_err(|e| invalid(e.to_string()))?;
    let whole_tree = parsed.provider == crate::import::Provider::KeePassXml;
    let root = db.root;
    let top = {
        let name = check_name(group_name, "group name")?;
        let mut root = db.group_mut(root).ok_or(EditError::NotFound("group"))?;
        let mut group = root.add_group();
        group.name = name;
        group.icon = Some(Icon::BuiltIn(GROUP_ICON));
        set_all_times(&mut group.times, now);
        group.id
    };
    if whole_tree {
        crate::import_xml::copy_into(db, &bytes, top, now).map_err(|e| invalid(e.to_string()))?;
        return Ok(Applied {
            id: Some(top.uuid().to_string()),
            changed: true,
        });
    }
    for entry in &parsed.entries {
        let mut group = top;
        for part in &entry.group {
            group = child_group(db, group, &clip(part), now)?;
        }
        let input = EntryInput {
            fields: imported_fields(entry),
            tags: entry
                .tags
                .iter()
                .map(|t| clip(t))
                .filter(|t| !t.is_empty())
                .collect(),
            ..EntryInput::default()
        };
        let made = create_entry(db, &group.uuid().to_string(), &input, now)?;
        if let Some(id) = made
            .id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
        {
            let id = EntryId::from(id);
            // The files a format carried (1PUX), each name once.
            for file in &entry.attachments {
                let attachment =
                    refs::import_attachment(db, &Value::unprotected(file.data.clone()));
                if let Some(made) = db.entries.get_mut(&id) {
                    let base = match clip(&file.name) {
                        name if name.is_empty() => "attachment".to_owned(),
                        name => name,
                    };
                    let mut name = base.clone();
                    let mut n = 2;
                    while made.attachments.contains_key(&name) {
                        name = format!("{base} ({n})");
                        n += 1;
                    }
                    made.attachments.insert(name, attachment);
                }
            }
            if let Some(made) = db.entries.get_mut(&id) {
                if let Some(created) = entry.created {
                    made.times.creation = Some(created);
                }
                if let Some(modified) = entry.modified.or(entry.created) {
                    made.times.last_modification = Some(modified);
                }
            }
        }
    }
    Ok(Applied {
        id: Some(top.uuid().to_string()),
        changed: true,
    })
}
