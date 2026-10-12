//! A vault as the website shows it (docs/plans/pass.md, K2b): groups and
//! entries as plain, serializable values. The website reads a [`VaultView`]
//! and changes the vault only through [`crate::edit`] operations.
//!
//! Times are UTC, as KeePass keeps them, written `YYYY-MM-DDTHH:MM:SSZ`.

use chrono::NaiveDateTime;
use keepass::db::{CustomDataValue, Entry, Group, GroupId, Icon};
use keepass::Database;
use serde::{Deserialize, Serialize};

use crate::merge::REVIEW_KEY;

/// The standard fields, in the order KeePass apps show them.
pub const STANDARD_FIELDS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

/// A whole vault.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    pub name: String,
    pub description: String,
    pub default_user_name: String,
    pub root_group_id: String,
    /// The recycle bin, once there is one.
    pub recycle_bin_id: Option<String>,
    pub recycle_bin_enabled: bool,
    /// `None`: unlimited.
    pub history_max_items: Option<i64>,
    /// In bytes; `None`: unlimited.
    pub history_max_size: Option<i64>,
    /// Every group, parents before children, siblings in their order.
    pub groups: Vec<GroupView>,
    /// Every entry, by group in the order above, then in the group's order.
    pub entries: Vec<EntryView>,
}

/// A group.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub parent_id: Option<String>,
    /// 0 for the root group.
    pub depth: usize,
    pub name: String,
    pub notes: String,
    /// A built-in KeePass icon number.
    pub icon: Option<usize>,
    pub has_custom_icon: bool,
    pub tags: Vec<String>,
    pub expires: bool,
    pub expiry: Option<String>,
    pub is_recycle_bin: bool,
    /// The recycle bin or a group inside it.
    pub in_recycle_bin: bool,
}

/// A field of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub key: String,
    pub value: String,
    /// Kept in memory protection by KeePass apps, and shown hidden.
    pub protected: bool,
}

/// An attachment of an entry (its contents through [`attachment`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub name: String,
    pub size: usize,
}

/// Auto-type settings, shown as they are; edited by KeePass apps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoTypeView {
    pub enabled: bool,
    pub default_sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociationView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoTypeAssociationView {
    pub window: String,
    pub sequence: String,
}

/// An entry (or, in [`history`], one of its earlier states).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub group_id: String,
    /// The standard fields first (present ones only), then custom fields by
    /// name.
    pub fields: Vec<FieldView>,
    pub tags: Vec<String>,
    pub icon: Option<usize>,
    pub has_custom_icon: bool,
    /// `#rrggbb`.
    pub foreground_color: Option<String>,
    pub background_color: Option<String>,
    pub override_url: String,
    pub quality_check: bool,
    pub expires: bool,
    pub expiry: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub attachments: Vec<AttachmentView>,
    pub auto_type: Option<AutoTypeView>,
    /// Earlier states kept (see [`history`]).
    pub history_count: usize,
    /// Fields a merge found changed on both sides: this entry holds one
    /// side, its history the other, until someone reviews it.
    pub review: Vec<String>,
    pub in_recycle_bin: bool,
}

/// A time as the views write it.
pub fn format_time(time: NaiveDateTime) -> String {
    time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Reads a time the views write (also without the `Z`, or with fractions).
pub fn parse_time(value: &str) -> Option<NaiveDateTime> {
    let value = value.trim_end_matches('Z');
    NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S"))
        .ok()
}

fn builtin(icon: Option<&Icon>) -> (Option<usize>, bool) {
    match icon {
        Some(Icon::BuiltIn(n)) => (Some(*n), false),
        Some(Icon::Custom(_)) => (None, true),
        None => (None, false),
    }
}

/// The recycle bin's id, if the vault has one that exists.
pub fn recycle_bin(db: &Database) -> Option<GroupId> {
    let id = GroupId::from(db.meta.recyclebin_uuid?);
    db.groups.contains_key(&id).then_some(id)
}

/// Whether `group` is the recycle bin or inside it.
pub fn group_in_recycle_bin(db: &Database, group: GroupId) -> bool {
    let Some(bin) = recycle_bin(db) else {
        return false;
    };
    let mut current = Some(group);
    while let Some(id) = current {
        if id == bin {
            return true;
        }
        current = db.groups.get(&id).and_then(|g| g.parent);
    }
    false
}

/// The review mark's fields.
pub fn review_fields(entry: &Entry) -> Vec<String> {
    match entry
        .custom_data
        .get(REVIEW_KEY)
        .and_then(|item| item.value.as_ref())
    {
        Some(CustomDataValue::String(fields)) => fields
            .lines()
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// An entry's fields, standard ones first.
pub fn fields(entry: &Entry) -> Vec<FieldView> {
    let mut out: Vec<FieldView> = STANDARD_FIELDS
        .iter()
        .filter_map(|key| {
            entry.fields.get(*key).map(|value| FieldView {
                key: (*key).to_owned(),
                value: value.get().clone(),
                protected: value.is_protected(),
            })
        })
        .collect();
    let mut custom: Vec<FieldView> = entry
        .fields
        .iter()
        .filter(|(key, _)| !STANDARD_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| FieldView {
            key: key.clone(),
            value: value.get().clone(),
            protected: value.is_protected(),
        })
        .collect();
    custom.sort_by(|a, b| a.key.cmp(&b.key));
    out.extend(custom);
    out
}

fn entry_view(db: &Database, entry: &Entry, history_count: usize) -> EntryView {
    let (icon, has_custom_icon) = builtin(entry.icon.as_ref());
    let mut attachments: Vec<AttachmentView> = entry
        .attachments
        .iter()
        .map(|(name, id)| AttachmentView {
            name: name.clone(),
            size: db.attachments.get(id).map_or(0, |a| a.data.get().len()),
        })
        .collect();
    attachments.sort_by(|a, b| a.name.cmp(&b.name));
    let mut tags = entry.tags.clone();
    tags.sort();
    EntryView {
        id: entry.id.uuid().to_string(),
        group_id: entry.parent.uuid().to_string(),
        fields: fields(entry),
        tags,
        icon,
        has_custom_icon,
        foreground_color: entry.foreground_color.as_ref().map(ToString::to_string),
        background_color: entry.background_color.as_ref().map(ToString::to_string),
        override_url: entry.override_url.clone().unwrap_or_default(),
        quality_check: entry.quality_check,
        expires: entry.times.expires.unwrap_or(false),
        expiry: entry.times.expiry.map(format_time),
        created: entry.times.creation.map(format_time),
        modified: entry.times.last_modification.map(format_time),
        accessed: entry.times.last_access.map(format_time),
        attachments,
        auto_type: entry.autotype.as_ref().map(|at| AutoTypeView {
            enabled: at.enabled,
            default_sequence: at.default_sequence.clone(),
            associations: at
                .associations
                .iter()
                .map(|a| AutoTypeAssociationView {
                    window: a.window.clone(),
                    sequence: a.sequence.clone(),
                })
                .collect(),
        }),
        history_count,
        review: review_fields(entry),
        in_recycle_bin: group_in_recycle_bin(db, entry.parent),
    }
}

fn group_view(db: &Database, group: &Group, depth: usize, bin: Option<GroupId>) -> GroupView {
    let (icon, has_custom_icon) = builtin(group.icon.as_ref());
    GroupView {
        id: group.id.uuid().to_string(),
        parent_id: group.parent.map(|p| p.uuid().to_string()),
        depth,
        name: group.name.clone(),
        notes: group.notes.clone().unwrap_or_default(),
        icon,
        has_custom_icon,
        tags: group.tags.clone(),
        expires: group.times.expires.unwrap_or(false),
        expiry: group.times.expiry.map(format_time),
        is_recycle_bin: Some(group.id) == bin,
        in_recycle_bin: group_in_recycle_bin(db, group.id),
    }
}

/// The whole vault.
pub fn view(db: &Database) -> VaultView {
    let bin = recycle_bin(db);
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    let mut stack = vec![(db.root, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        let Some(group) = db.groups.get(&id) else {
            continue;
        };
        groups.push(group_view(db, group, depth, bin));
        for entry_id in &group.entries {
            if let Some(entry) = db.entries.get(entry_id) {
                let count = entry.history.as_ref().map_or(0, |h| h.entries.len());
                entries.push(entry_view(db, entry, count));
            }
        }
        for child in group.groups.iter().rev() {
            stack.push((*child, depth + 1));
        }
    }
    let limit = |value: Option<isize>| value.filter(|v| *v >= 0).map(|v| v as i64);
    VaultView {
        name: db.meta.database_name.clone().unwrap_or_default(),
        description: db.meta.database_description.clone().unwrap_or_default(),
        default_user_name: db.meta.default_username.clone().unwrap_or_default(),
        root_group_id: db.root.uuid().to_string(),
        recycle_bin_id: bin.map(|id| id.uuid().to_string()),
        recycle_bin_enabled: db.meta.recyclebin_enabled.unwrap_or(true),
        history_max_items: limit(db.meta.history_max_items),
        history_max_size: limit(db.meta.history_max_size),
        groups,
        entries,
    }
}

/// An entry's earlier states, oldest first.
pub fn history(db: &Database, entry: &Entry) -> Vec<EntryView> {
    entry
        .history
        .iter()
        .flat_map(|history| &history.entries)
        .map(|item| entry_view(db, item, 0))
        .collect()
}

/// The contents of an entry's attachment.
pub fn attachment<'a>(db: &'a Database, entry: &Entry, name: &str) -> Option<&'a [u8]> {
    let id = entry.attachments.get(name)?;
    db.attachments.get(id).map(|a| a.data.get().as_slice())
}

/// A one-time code for an entry with a TOTP secret (KeePassXC's `otp`
/// field), at `unix_seconds`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpView {
    pub code: String,
    pub period: u64,
    /// Seconds until the next code.
    pub remaining: u64,
}

/// The entry's current one-time code, if it has a readable TOTP secret.
pub fn otp(entry: &Entry, unix_seconds: u64) -> Option<OtpView> {
    let totp = entry.get_otp().ok()?;
    let code = totp.value_at(unix_seconds);
    Some(OtpView {
        code: code.code,
        period: code.period.as_secs(),
        remaining: code.valid_for.as_secs(),
    })
}
