//! Moving entries between databases, and keeping the crate's back-references
//! right.
//!
//! The `keepass` model stores attachments and custom icons in database-wide
//! pools: an entry names an attachment by a numeric id local to its database
//! and a custom icon by UUID, and the pools remember which entries (and
//! history items, by index) use them. An entry copied from another database
//! must have its attachments re-pointed into this database's pool and its
//! custom icon copied, and after the merge the back-references are rebuilt
//! from scratch.

use std::collections::HashSet;

use keepass::db::{Attachment, AttachmentId, CustomIconId, Entry, History, Icon, Value};
use keepass::Database;

/// The id of an attachment in `db` holding `data`, adding it if none does.
/// Equal contents share one attachment, as KeePass does.
pub(crate) fn import_attachment(db: &mut Database, data: &Value<Vec<u8>>) -> AttachmentId {
    let mut existing: Vec<&AttachmentId> = db
        .attachments
        .iter()
        .filter(|(_, attachment)| attachment.data == *data)
        .map(|(id, _)| id)
        .collect();
    existing.sort_by_key(|id| id.id());
    if let Some(id) = existing.first() {
        return **id;
    }
    let next = db
        .attachments
        .keys()
        .map(|id| id.id() + 1)
        .max()
        .unwrap_or(0);
    let id = AttachmentId::new(next);
    db.attachments.insert(
        id,
        Attachment {
            id,
            entries: HashSet::new(),
            data: data.clone(),
        },
    );
    id
}

/// Copies custom icon `id` from `source` into `db` if `db` lacks it.
pub(crate) fn import_icon(db: &mut Database, source: &Database, id: CustomIconId) -> bool {
    if db.custom_icons.contains_key(&id) {
        return true;
    }
    match source.custom_icons.get(&id) {
        Some(icon) => {
            let mut icon = icon.clone();
            icon.entries.clear();
            icon.groups.clear();
            db.custom_icons.insert(id, icon);
            true
        }
        None => false,
    }
}

/// `entry` (from `source`), with its attachments, custom icon and history
/// re-pointed into `db`'s pools.
pub(crate) fn adopt_entry(db: &mut Database, source: &Database, entry: &Entry) -> Entry {
    let mut adopted = entry.clone();
    let mut names: Vec<&String> = entry.attachments.keys().collect();
    names.sort();
    adopted.attachments.clear();
    for name in names {
        if let Some(attachment) = source.attachments.get(&entry.attachments[name]) {
            let id = import_attachment(db, &attachment.data);
            adopted.attachments.insert(name.clone(), id);
        }
    }
    if let Some(Icon::Custom(id)) = entry.icon {
        if !import_icon(db, source, id) {
            adopted.icon = None;
        }
    }
    adopted.history = entry.history.as_ref().map(|history| History {
        entries: history
            .entries
            .iter()
            .map(|item| adopt_entry(db, source, item))
            .collect(),
    });
    adopted
}

/// Rebuilds the attachment and custom icon back-references from the entries,
/// their history and the groups, and drops attachments nothing uses.
pub(crate) fn rebuild(db: &mut Database) {
    let mut attachment_uses = Vec::new();
    let mut icon_entry_uses = Vec::new();
    let mut icon_group_uses = Vec::new();
    for (id, entry) in &db.entries {
        let mut visit = |item: &Entry, index: Option<usize>| {
            for attachment in item.attachments.values() {
                attachment_uses.push((*attachment, *id, index));
            }
            if let Some(Icon::Custom(icon)) = item.icon {
                icon_entry_uses.push((icon, *id, index));
            }
        };
        visit(entry, None);
        if let Some(history) = &entry.history {
            for (index, item) in history.entries.iter().enumerate() {
                visit(item, Some(index));
            }
        }
    }
    for (id, group) in &db.groups {
        if let Some(Icon::Custom(icon)) = group.icon {
            icon_group_uses.push((icon, *id));
        }
    }
    for attachment in db.attachments.values_mut() {
        attachment.entries.clear();
    }
    for icon in db.custom_icons.values_mut() {
        icon.entries.clear();
        icon.groups.clear();
    }
    for (attachment, entry, index) in attachment_uses {
        if let Some(attachment) = db.attachments.get_mut(&attachment) {
            attachment.entries.insert((entry, index));
        }
    }
    for (icon, entry, index) in icon_entry_uses {
        if let Some(icon) = db.custom_icons.get_mut(&icon) {
            icon.entries.insert((entry, index));
        }
    }
    for (icon, group) in icon_group_uses {
        if let Some(icon) = db.custom_icons.get_mut(&icon) {
            icon.groups.insert(group);
        }
    }
    db.attachments
        .retain(|_, attachment| !attachment.entries.is_empty());
}
