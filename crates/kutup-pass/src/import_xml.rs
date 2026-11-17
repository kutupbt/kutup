//! KeePass XML (docs/plans/pass-gaps-2.md P5b): an unencrypted KeePass XML
//! file as KeePassXC's and KeePass's XML exports write it, read through the
//! vendored crate's `from_plain_xml` (vendor/keepass/KUTUP.md). Unlike the
//! other formats, the whole tree comes in: groups, entries with their
//! history, attachments, icons, colours and custom data, each with a new id
//! (so importing a vault's own export never collides with it). The source's
//! recycle bin is left out.

use chrono::NaiveDateTime;
use keepass::db::{EntryId, GroupId, Icon};
use keepass::Database;

use crate::import::{ImportError, ImportedEntry, Parsed, Provider};
use crate::refs;

/// Whether `bytes` look like a KeePass XML file.
pub(crate) fn detect(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(4096)];
    let text = String::from_utf8_lossy(head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head));
    text.trim_start().starts_with('<') && text.contains("<KeePassFile")
}

/// The file as a database, its recycle bin with it.
pub(crate) fn read(bytes: &[u8]) -> Result<Database, ImportError> {
    keepass::from_plain_xml(bytes).map_err(|e| ImportError::Unreadable(e.to_string()))
}

fn bin(db: &Database) -> Option<GroupId> {
    let id = GroupId::from(db.meta.recyclebin_uuid?);
    db.groups.contains_key(&id).then_some(id)
}

/// Attachments the file names but doesn't hold (KeePassXC's own KDBX 4 XML
/// export leaves their contents out), per entry title.
fn missing_attachments(db: &Database) -> Vec<String> {
    let mut out = Vec::new();
    for entry in db.entries.values() {
        let missing = entry
            .attachments
            .values()
            .filter(|id| !db.attachments.contains_key(id))
            .count();
        if missing > 0 {
            let title = entry.fields.get("Title").map_or("", |v| v.get().as_str());
            out.push(format!(
                "{missing} attachment(s) not in the file, not imported: {title}"
            ));
        }
    }
    out
}

/// What an import would bring, for the preview.
pub(crate) fn preview(bytes: &[u8]) -> Result<Parsed, ImportError> {
    let source = read(bytes)?;
    let bin = bin(&source);
    let mut parsed = Parsed {
        provider: Provider::KeePassXml,
        entries: Vec::new(),
        skipped: Vec::new(),
        warnings: missing_attachments(&source),
    };
    let mut stack = vec![(source.root, Vec::<String>::new())];
    while let Some((id, path)) = stack.pop() {
        let Some(group) = source.groups.get(&id) else {
            continue;
        };
        if Some(id) == bin {
            parsed.skipped.extend(
                group
                    .entries
                    .iter()
                    .filter_map(|e| source.entries.get(e))
                    .map(|e| {
                        format!(
                            "in the recycle bin: {}",
                            e.fields.get("Title").map_or("", |v| v.get().as_str())
                        )
                    }),
            );
            continue;
        }
        for entry in group.entries.iter().filter_map(|e| source.entries.get(e)) {
            let get = |key: &str| {
                entry
                    .fields
                    .get(key)
                    .map_or(String::new(), |v| v.get().clone())
            };
            parsed.entries.push(ImportedEntry {
                group: path.clone(),
                title: get("Title"),
                username: get("UserName"),
                urls: vec![get("URL")]
                    .into_iter()
                    .filter(|u| !u.is_empty())
                    .collect(),
                ..ImportedEntry::default()
            });
        }
        for child in group.groups.iter().rev() {
            if let Some(g) = source.groups.get(child) {
                let mut sub = path.clone();
                sub.push(g.name.clone());
                stack.push((*child, sub));
            }
        }
    }
    if parsed.entries.len() > crate::import::MAX_IMPORT_ENTRIES {
        return Err(ImportError::TooMany);
    }
    if parsed.entries.is_empty() && parsed.skipped.is_empty() {
        return Err(ImportError::Empty);
    }
    Ok(parsed)
}

/// Protects what the file's Meta/MemoryProtection protects (KeePassXC's XML
/// marks a standard field protected there, not on the value), and the
/// password always, as Kutup Pass does.
fn protect(source: &Database, entry: &mut keepass::db::Entry) {
    let flags = source.meta.memory_protection.clone().unwrap_or_default();
    let keys = [
        ("Title", flags.protect_title),
        ("UserName", flags.protect_username),
        ("Password", true),
        ("URL", flags.protect_url),
        ("Notes", flags.protect_notes),
    ];
    for (key, on) in keys {
        if let Some(value) = entry.fields.get_mut(key) {
            if on && !value.is_protected() {
                *value = keepass::db::Value::protected(value.get().clone());
            }
        }
    }
}

/// Copies the file's tree under `top` in `db`, new ids throughout.
pub(crate) fn copy_into(
    db: &mut Database,
    bytes: &[u8],
    top: GroupId,
    now: NaiveDateTime,
) -> Result<(), ImportError> {
    let source = read(bytes)?;
    let source_bin = bin(&source);
    // The source's top group becomes `top` itself: its entries go there.
    let mut stack = vec![(source.root, top)];
    while let Some((from, to)) = stack.pop() {
        let Some(group) = source.groups.get(&from) else {
            continue;
        };
        for entry in group.entries.iter().filter_map(|e| source.entries.get(e)) {
            let id = EntryId::new();
            let added = match db.group_mut(to) {
                Some(mut parent) => parent.add_entry_with_id(id).is_ok(),
                None => false,
            };
            if !added {
                continue;
            }
            let mut copy = refs::adopt_entry(db, &source, entry);
            protect(&source, &mut copy);
            copy.id = id;
            copy.parent = to;
            copy.previous_parent_group = None;
            if let Some(history) = copy.history.as_mut() {
                let items = std::mem::take(&mut history.entries);
                history.entries = items
                    .iter()
                    .map(|item| {
                        let mut item = refs::adopt_entry(db, &source, item);
                        protect(&source, &mut item);
                        item.id = id;
                        item.parent = to;
                        item
                    })
                    .collect();
            }
            if copy.times.location_changed.is_none() {
                copy.times.location_changed = Some(now);
            }
            db.entries.insert(id, copy);
        }
        for child in &group.groups {
            if Some(*child) == source_bin {
                continue;
            }
            let Some(g) = source.groups.get(child) else {
                continue;
            };
            let new_id = {
                let Some(mut parent) = db.group_mut(to) else {
                    continue;
                };
                let mut made = parent.add_group();
                made.name = g.name.clone();
                made.notes = g.notes.clone();
                made.tags = g.tags.clone();
                made.times = g.times.clone();
                made.custom_data = g.custom_data.clone();
                made.icon = match g.icon {
                    Some(Icon::Custom(_)) => None,
                    ref other => other.clone(),
                };
                made.id
            };
            if let Some(Icon::Custom(icon)) = g.icon {
                if refs::import_icon(db, &source, icon) {
                    if let Some(made) = db.groups.get_mut(&new_id) {
                        made.icon = Some(Icon::Custom(icon));
                    }
                }
            }
            stack.push((*child, new_id));
        }
    }
    Ok(())
}
