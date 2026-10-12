//! Changing a vault as KeePass apps do (docs/plans/pass.md, K2b).
//!
//! The website changes a vault only through [`Op`]s, applied here so every
//! client edits the same way KeePassXC does: an entry's previous state goes
//! into its history before it changes (trimmed to the vault's limits),
//! deleting moves to the recycle bin, and deleting from the recycle bin (or
//! with it turned off) removes for good and records the deletion, so a
//! merge knows the object was deleted rather than never seen. Times come
//! from the caller (`now`), so the same code runs in the browser.

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr as _;

use base64::Engine as _;
use chrono::NaiveDateTime;
use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::{Color, Entry, EntryId, GroupId, History, Icon, Times, Value};
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
    /// Makes history item `index` (oldest first) the entry's state again.
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
    MoveGroup {
        id: String,
        parent_id: String,
    },
    EmptyRecycleBin,
    /// Imports another password manager's CSV export (`import::parse`)
    /// into a new group `group_name` under the top group, its folders as
    /// groups inside. All or nothing.
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
    },
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
        Op::MoveGroup { id, parent_id } => {
            let id = group_id(db, id)?;
            let parent = group_id(db, parent_id)?;
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
        } => {
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
            Applied { id: None, changed }
        }
    };
    refs::rebuild(db);
    Ok(applied)
}

/// The parts of an entry an edit changes; equal when nothing changed.
fn content(entry: &Entry) -> Entry {
    let mut copy = entry.clone();
    copy.history = None;
    copy.times = Times::default();
    copy
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
            if let Some(made) = db.entries.get_mut(&EntryId::from(id)) {
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
