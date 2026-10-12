//! The three-way merge of two edited copies of a vault (docs/plans/pass.md,
//! "The three-way merge").
//!
//! `merge(base, ours, theirs)`: `base` is the version both copies started
//! from (Drive keeps it), `ours` the local copy, `theirs` the copy found on
//! the server. Entries and groups are matched by UUID and merged field by
//! field: a change made on one side is taken; the same change on both sides
//! is no conflict; different changes to one field keep ours, put theirs into
//! the entry's history and mark the entry for review. An entry edited on one
//! side wins over its deletion on the other. Device clocks never pick a
//! winner while a base exists; without one, KeePassXC's rule applies (the
//! newer whole entry wins, the other goes into history).
//!
//! The result is deterministic: the same three inputs always give the same
//! vault and report, so two devices merging the same versions agree.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::NaiveDateTime;
use keepass::db::{
    AutoType, Color, CustomDataItem, CustomDataValue, Entry, EntryId, Group, GroupId, History,
    Icon, MemoryProtection, Value,
};
use keepass::Database;
use uuid::Uuid;

use crate::refs;

/// The custom-data key that marks an entry for review after a conflict. Its
/// value lists the conflicting fields, one per line. Other KeePass apps keep
/// unknown custom data and ignore it.
pub const REVIEW_KEY: &str = "KutupMergeReview";

/// What a merge did.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeReport {
    /// Entries only one side had, now in the result.
    pub added: Vec<Uuid>,
    /// Entries whose result differs from ours.
    pub updated: Vec<Uuid>,
    /// Entries where both sides changed the same field differently.
    pub conflicts: Vec<Conflict>,
    /// Entries one side deleted and the other edited; the edit won.
    pub restored: Vec<Uuid>,
    /// Entries deleted because one side deleted them and the other did not
    /// change them.
    pub deleted: Vec<Uuid>,
    /// Entries moved to the group the other side chose.
    pub moved: Vec<Uuid>,
    /// Groups only theirs had.
    pub groups_added: Vec<Uuid>,
    /// Groups whose own fields or place changed.
    pub groups_updated: Vec<Uuid>,
    /// Groups deleted by one side and unchanged and empty on the other.
    pub groups_deleted: Vec<Uuid>,
    /// Groups ours deleted, brought back because theirs changed them or put
    /// entries in them.
    pub groups_restored: Vec<Uuid>,
    /// Groups where both sides changed the same field differently.
    pub group_conflicts: Vec<Conflict>,
    /// Database settings both sides changed differently (ours was kept).
    pub metadata_conflicts: Vec<String>,
}

impl MergeReport {
    /// No field needs the user's review.
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
            && self.group_conflicts.is_empty()
            && self.metadata_conflicts.is_empty()
    }

    fn sort(&mut self) {
        for list in [
            &mut self.added,
            &mut self.updated,
            &mut self.restored,
            &mut self.deleted,
            &mut self.moved,
            &mut self.groups_added,
            &mut self.groups_updated,
            &mut self.groups_deleted,
            &mut self.groups_restored,
        ] {
            list.sort();
            list.dedup();
        }
        self.conflicts.sort_by_key(|conflict| conflict.id);
        self.group_conflicts.sort_by_key(|conflict| conflict.id);
    }
}

/// One entry or group whose fields both sides changed differently.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// The entry's or group's UUID.
    pub id: Uuid,
    /// Its title (entries) or name (groups) in the result.
    pub title: Option<String>,
    /// The conflicting fields: string field names as KeePass stores them
    /// (`Title`, `Password`, custom names), and `tags`, `icon`,
    /// `attachment <name>`, `custom data <key>`, `expiry`, `auto-type`,
    /// `colour`, `URL override`, `quality check`, `notes`, `name`.
    pub fields: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Pick {
    Ours,
    Theirs,
    Conflict,
}

/// The three-way decision for one value. `None` means absent.
fn pick<T: PartialEq + ?Sized>(base: Option<&T>, ours: Option<&T>, theirs: Option<&T>) -> Pick {
    if ours == theirs || theirs == base {
        Pick::Ours
    } else if ours == base {
        Pick::Theirs
    } else {
        Pick::Conflict
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IconSlot {
    BuiltIn(usize),
    Custom(Uuid),
}

fn icon_slot(icon: &Option<Icon>) -> Option<IconSlot> {
    match icon {
        Some(Icon::BuiltIn(number)) => Some(IconSlot::BuiltIn(*number)),
        Some(Icon::Custom(id)) => Some(IconSlot::Custom(id.uuid())),
        None => None,
    }
}

type Expiry = (Option<bool>, Option<NaiveDateTime>);

/// The parts of an entry the merge compares: everything a user can change,
/// without its history, its place, timestamps or the review mark.
#[derive(Debug, Clone, PartialEq)]
struct EntrySlots {
    fields: BTreeMap<String, Value<String>>,
    tags: BTreeSet<String>,
    attachments: BTreeMap<String, Value<Vec<u8>>>,
    icon: Option<IconSlot>,
    colours: (Option<Color>, Option<Color>),
    override_url: Option<String>,
    quality_check: bool,
    autotype: Option<AutoType>,
    custom_data: BTreeMap<String, Option<CustomDataValue>>,
    expiry: Expiry,
}

fn entry_slots(db: &Database, entry: &Entry) -> EntrySlots {
    EntrySlots {
        fields: entry
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        tags: entry.tags.iter().cloned().collect(),
        attachments: entry
            .attachments
            .iter()
            .filter_map(|(name, id)| {
                db.attachments
                    .get(id)
                    .map(|attachment| (name.clone(), attachment.data.clone()))
            })
            .collect(),
        icon: icon_slot(&entry.icon),
        colours: (
            entry.foreground_color.clone(),
            entry.background_color.clone(),
        ),
        override_url: entry.override_url.clone(),
        quality_check: entry.quality_check,
        autotype: entry.autotype.clone(),
        custom_data: entry
            .custom_data
            .iter()
            .filter(|(key, _)| key.as_str() != REVIEW_KEY)
            .map(|(key, item)| (key.clone(), item.value.clone()))
            .collect(),
        expiry: (entry.times.expires, entry.times.expiry),
    }
}

/// The parts of a group the merge compares.
#[derive(Debug, Clone, PartialEq)]
struct GroupSlots {
    name: String,
    notes: Option<String>,
    tags: BTreeSet<String>,
    icon: Option<IconSlot>,
    expiry: Expiry,
    custom_data: BTreeMap<String, Option<CustomDataValue>>,
    autotype: (Option<String>, Option<bool>),
    enable_searching: Option<bool>,
}

fn group_slots(group: &Group) -> GroupSlots {
    GroupSlots {
        name: group.name.clone(),
        notes: group.notes.clone(),
        tags: group.tags.iter().cloned().collect(),
        icon: icon_slot(&group.icon),
        expiry: (group.times.expires, group.times.expiry),
        custom_data: group
            .custom_data
            .iter()
            .map(|(key, item)| (key.clone(), item.value.clone()))
            .collect(),
        autotype: (
            group.default_autotype_sequence.clone(),
            group.enable_autotype,
        ),
        enable_searching: group.enable_searching,
    }
}

fn later(a: Option<NaiveDateTime>, b: Option<NaiveDateTime>) -> Option<NaiveDateTime> {
    a.max(b)
}

/// Merges `ours` and `theirs`, the two edited copies of a vault, against
/// `base`, the version both started from (`None` when it is unknown). The
/// result keeps ours' configuration (cipher, key derivation, compression).
pub fn merge(
    base: Option<&Database>,
    ours: &Database,
    theirs: &Database,
) -> (Database, MergeReport) {
    let mut merger = Merger {
        base,
        ours,
        theirs,
        out: ours.clone(),
        report: MergeReport::default(),
    };
    merger.metadata();
    merger.custom_icons();
    merger.groups();
    merger.entries();
    merger.group_deletions();
    merger.deleted_objects();
    refs::rebuild(&mut merger.out);
    merger.report.sort();
    (merger.out, merger.report)
}

struct Merger<'a> {
    base: Option<&'a Database>,
    ours: &'a Database,
    theirs: &'a Database,
    out: Database,
    report: MergeReport,
}

impl Merger<'_> {
    // ------------------------------------------------------------ helpers

    /// A group id from theirs or base, with their root mapped to ours'.
    fn map_group(&self, id: GroupId) -> GroupId {
        if id == self.theirs.root || self.base.is_some_and(|base| id == base.root) {
            self.out.root
        } else {
            id
        }
    }

    fn base_entry(&self, id: EntryId) -> Option<&Entry> {
        self.base.and_then(|base| base.entries.get(&id))
    }

    fn base_group(&self, id: GroupId) -> Option<&Group> {
        self.base.and_then(|base| base.groups.get(&id))
    }

    fn base_entry_slots(&self, id: EntryId) -> Option<EntrySlots> {
        let base = self.base?;
        base.entries.get(&id).map(|entry| entry_slots(base, entry))
    }

    fn is_within(&self, group: GroupId, ancestor: GroupId) -> bool {
        let mut current = Some(group);
        while let Some(id) = current {
            if id == ancestor {
                return true;
            }
            current = self.out.groups.get(&id).and_then(|group| group.parent);
        }
        false
    }

    fn detach_entry(&mut self, id: EntryId) {
        if let Some(parent) = self.out.entries.get(&id).map(|entry| entry.parent) {
            if let Some(group) = self.out.groups.get_mut(&parent) {
                group.entries.shift_remove(&id);
            }
        }
    }

    fn attach_entry(&mut self, id: EntryId, parent: GroupId) {
        if let Some(entry) = self.out.entries.get_mut(&id) {
            entry.parent = parent;
        }
        if let Some(group) = self.out.groups.get_mut(&parent) {
            group.entries.insert(id);
        }
    }

    fn remove_entry(&mut self, id: EntryId) {
        self.detach_entry(id);
        self.out.entries.remove(&id);
    }

    /// The group in the result standing for `id` (from theirs or base):
    /// itself if present, else brought back from theirs (with its missing
    /// ancestors), else the root.
    fn ensure_group(&mut self, id: GroupId) -> GroupId {
        let id = self.map_group(id);
        if self.out.groups.contains_key(&id) {
            return id;
        }
        let Some(source) = self.theirs.groups.get(&id) else {
            return self.out.root;
        };
        let parent = source
            .parent
            .map_or(self.out.root, |parent| self.ensure_group(parent));
        self.add_group_from_theirs(source.clone(), parent);
        self.report.groups_restored.push(id.uuid());
        id
    }

    fn add_group_from_theirs(&mut self, mut group: Group, parent: GroupId) {
        let id = group.id;
        if let Some(Icon::Custom(icon)) = group.icon {
            if !refs::import_icon(&mut self.out, self.theirs, icon) {
                group.icon = None;
            }
        }
        group.parent = Some(parent);
        group.groups.clear();
        group.entries.clear();
        group.last_top_visible_entry = None;
        group.previous_parent_group = group
            .previous_parent_group
            .filter(|previous| self.out.groups.contains_key(previous));
        self.out.groups.insert(id, group);
        if let Some(parent) = self.out.groups.get_mut(&parent) {
            parent.groups.insert(id);
        }
    }

    fn move_group(&mut self, id: GroupId, parent: GroupId) {
        let Some(old) = self.out.groups.get(&id).and_then(|group| group.parent) else {
            return;
        };
        if old == parent || self.is_within(parent, id) {
            return;
        }
        if let Some(group) = self.out.groups.get_mut(&old) {
            group.groups.shift_remove(&id);
        }
        if let Some(group) = self.out.groups.get_mut(&parent) {
            group.groups.insert(id);
        }
        if let Some(group) = self.out.groups.get_mut(&id) {
            group.parent = Some(parent);
        }
    }

    /// Theirs' groups, parents before children.
    fn theirs_groups_in_order(&self) -> Vec<GroupId> {
        let mut order = Vec::new();
        let mut queue = vec![self.theirs.root];
        while let Some(id) = queue.pop() {
            if let Some(group) = self.theirs.groups.get(&id) {
                if id != self.theirs.root {
                    order.push(id);
                }
                let mut children: Vec<GroupId> = group.groups.iter().copied().collect();
                children.reverse();
                queue.extend(children);
            }
        }
        order
    }

    // ----------------------------------------------------------- metadata

    fn metadata(&mut self) {
        let theirs = &self.theirs.meta;
        let ours = &self.ours.meta;
        let base = self.base.map(|base| &base.meta);
        let out = &mut self.out.meta;
        let conflicts = &mut self.report.metadata_conflicts;

        // A value with its change time: three-way on the value; without a
        // base, the later change time wins. The time follows the value.
        macro_rules! timed {
            ($value:ident, $changed:ident, $label:expr) => {{
                let decision = match base {
                    Some(base) => {
                        pick(Some(&base.$value), Some(&ours.$value), Some(&theirs.$value))
                    }
                    None if ours.$value != theirs.$value && theirs.$changed > ours.$changed => {
                        Pick::Theirs
                    }
                    None => Pick::Ours,
                };
                match decision {
                    Pick::Theirs => {
                        out.$value = theirs.$value.clone();
                        out.$changed = theirs.$changed;
                    }
                    Pick::Conflict => conflicts.push($label.to_owned()),
                    Pick::Ours => {}
                }
            }};
        }
        // A value without a change time: three-way; without a base, ours.
        macro_rules! plain {
            ($value:ident, $label:expr) => {{
                if let Some(base) = base {
                    match pick(Some(&base.$value), Some(&ours.$value), Some(&theirs.$value)) {
                        Pick::Theirs => out.$value = theirs.$value.clone(),
                        Pick::Conflict => conflicts.push($label.to_owned()),
                        Pick::Ours => {}
                    }
                }
            }};
        }
        timed!(database_name, database_name_changed, "database name");
        timed!(
            database_description,
            database_description_changed,
            "database description"
        );
        timed!(
            default_username,
            default_username_changed,
            "default user name"
        );
        timed!(
            entry_templates_group,
            entry_templates_group_changed,
            "templates group"
        );
        // The recycle bin's switch and group change together.
        let bin = |meta: &keepass::db::Meta| (meta.recyclebin_enabled, meta.recyclebin_uuid);
        let decision = match base {
            Some(base) => pick(Some(&bin(base)), Some(&bin(ours)), Some(&bin(theirs))),
            None if bin(ours) != bin(theirs)
                && theirs.recyclebin_changed > ours.recyclebin_changed =>
            {
                Pick::Theirs
            }
            None => Pick::Ours,
        };
        match decision {
            Pick::Theirs => {
                out.recyclebin_enabled = theirs.recyclebin_enabled;
                out.recyclebin_uuid = theirs.recyclebin_uuid;
                out.recyclebin_changed = theirs.recyclebin_changed;
            }
            Pick::Conflict => conflicts.push("recycle bin".to_owned()),
            Pick::Ours => {}
        }
        plain!(maintenance_history_days, "maintenance history days");
        plain!(color, "database colour");
        plain!(history_max_items, "history items");
        plain!(history_max_size, "history size");
        plain!(master_key_change_rec, "key change recommended");
        plain!(master_key_change_force, "key change forced");
        let protection = |meta: &keepass::db::Meta| -> Option<MemoryProtection> {
            meta.memory_protection.clone()
        };
        if let Some(base) = base {
            match pick(
                Some(&protection(base)),
                Some(&protection(ours)),
                Some(&protection(theirs)),
            ) {
                Pick::Theirs => out.memory_protection = theirs.memory_protection.clone(),
                Pick::Conflict => conflicts.push("memory protection".to_owned()),
                Pick::Ours => {}
            }
        }
        out.master_key_changed = later(ours.master_key_changed, theirs.master_key_changed);
        out.settings_changed = later(ours.settings_changed, theirs.settings_changed);
        // Custom data, key by key.
        let base_data = base.map(|base| &base.custom_data);
        merge_custom_data(
            &mut out.custom_data,
            base_data,
            &ours.custom_data,
            &theirs.custom_data,
            |key| conflicts.push(format!("custom data {key}")),
        );
    }

    // -------------------------------------------------------- custom icons

    fn custom_icons(&mut self) {
        let mut ids: Vec<_> = self.theirs.custom_icons.keys().copied().collect();
        ids.sort_by_key(|id| id.uuid());
        for id in ids {
            refs::import_icon(&mut self.out, self.theirs, id);
        }
    }

    // ------------------------------------------------------------- groups

    fn groups(&mut self) {
        for id in self.theirs_groups_in_order() {
            let theirs = self.theirs.groups[&id].clone();
            let parent = theirs
                .parent
                .map_or(self.out.root, |parent| self.map_group(parent));
            if !self.out.groups.contains_key(&id) {
                let bring_back = match (self.base, self.base_group(id)) {
                    // Added on their side.
                    (Some(_), None) => true,
                    // Ours deleted it: back only if theirs changed it.
                    (Some(_), Some(base)) => group_slots(base) != group_slots(&theirs),
                    // No base: deleted after their last change stays deleted.
                    (None, _) => !matches!(
                        self.ours.deleted_objects.get(&id.uuid()),
                        Some(deleted) if *deleted >= theirs.times.last_modification
                    ),
                };
                if bring_back {
                    let parent = if self.out.groups.contains_key(&parent) {
                        parent
                    } else {
                        self.out.root
                    };
                    let restored = self.base_group(id).is_some();
                    self.add_group_from_theirs(theirs, parent);
                    if restored {
                        self.report.groups_restored.push(id.uuid());
                    } else {
                        self.report.groups_added.push(id.uuid());
                    }
                }
                continue;
            }
            self.merge_group(id, &theirs, parent);
        }
    }

    fn merge_group(&mut self, id: GroupId, theirs: &Group, theirs_parent: GroupId) {
        let ours = self.out.groups[&id].clone();
        let base = self.base_group(id).cloned();
        let (os, ts) = (group_slots(&ours), group_slots(theirs));
        let mut result = ours.clone();
        let mut conflicts = Vec::new();
        let no_base_theirs_newer =
            self.base.is_none() && theirs.times.last_modification > ours.times.last_modification;
        if let Some(base) = &base {
            let bs = group_slots(base);
            macro_rules! slot {
                ($field:ident, $label:expr, $apply:expr) => {
                    match pick(Some(&bs.$field), Some(&os.$field), Some(&ts.$field)) {
                        Pick::Theirs => $apply(&mut result),
                        Pick::Conflict => conflicts.push($label.to_owned()),
                        Pick::Ours => {}
                    }
                };
            }
            slot!(name, "name", |r: &mut Group| r.name = theirs.name.clone());
            slot!(notes, "notes", |r: &mut Group| r.notes =
                theirs.notes.clone());
            result.tags = merge_tags(Some(&bs.tags), &ours.tags, &theirs.tags);
            slot!(expiry, "expiry", |r: &mut Group| {
                r.times.expires = theirs.times.expires;
                r.times.expiry = theirs.times.expiry;
            });
            slot!(autotype, "auto-type", |r: &mut Group| {
                r.default_autotype_sequence = theirs.default_autotype_sequence.clone();
                r.enable_autotype = theirs.enable_autotype;
            });
            slot!(enable_searching, "searching", |r: &mut Group| r
                .enable_searching =
                theirs.enable_searching);
            match pick(Some(&bs.icon), Some(&os.icon), Some(&ts.icon)) {
                Pick::Theirs => result.icon = theirs.icon.clone(),
                Pick::Conflict => conflicts.push("icon".to_owned()),
                Pick::Ours => {}
            }
            merge_custom_data(
                &mut result.custom_data,
                Some(&base.custom_data),
                &ours.custom_data,
                &theirs.custom_data,
                |key| conflicts.push(format!("custom data {key}")),
            );
        } else if no_base_theirs_newer {
            result.name = theirs.name.clone();
            result.notes = theirs.notes.clone();
            result.tags = theirs.tags.clone();
            result.icon = theirs.icon.clone();
            result.times.expires = theirs.times.expires;
            result.times.expiry = theirs.times.expiry;
            result.custom_data = theirs.custom_data.clone();
            result.default_autotype_sequence = theirs.default_autotype_sequence.clone();
            result.enable_autotype = theirs.enable_autotype;
            result.enable_searching = theirs.enable_searching;
        }
        result.times.last_modification =
            later(ours.times.last_modification, theirs.times.last_modification);
        result.times.last_access = later(ours.times.last_access, theirs.times.last_access);
        result.times.usage_count = ours.times.usage_count.max(theirs.times.usage_count);
        if let Some(Icon::Custom(icon)) = result.icon {
            if !refs::import_icon(&mut self.out, self.theirs, icon) {
                result.icon = ours.icon.clone();
            }
        }
        let changed = group_slots(&result) != os;
        self.out.groups.insert(id, result);
        if !conflicts.is_empty() {
            self.report.group_conflicts.push(Conflict {
                id: id.uuid(),
                title: Some(self.out.groups[&id].name.clone()),
                fields: conflicts,
            });
        }
        // Its place.
        if id != self.out.root {
            let ours_parent = ours.parent.unwrap_or(self.out.root);
            let decision = match &base {
                Some(base) => {
                    let base_parent = base.parent.map(|parent| self.map_group(parent));
                    pick(
                        base_parent.as_ref(),
                        Some(&ours_parent),
                        Some(&theirs_parent),
                    )
                }
                None if no_base_theirs_newer => Pick::Theirs,
                None => Pick::Ours,
            };
            if decision == Pick::Theirs && theirs_parent != ours_parent {
                let target = self.ensure_group(theirs_parent);
                self.move_group(id, target);
                if let Some(group) = self.out.groups.get_mut(&id) {
                    group.times.location_changed = theirs.times.location_changed;
                }
                self.report.groups_updated.push(id.uuid());
            }
        }
        if changed {
            self.report.groups_updated.push(id.uuid());
        }
    }

    /// Groups one side deleted: gone if the other side did not change them
    /// and nothing is left in them.
    fn group_deletions(&mut self) {
        loop {
            let mut candidates: Vec<GroupId> = self
                .out
                .groups
                .values()
                .filter(|group| {
                    group.id != self.out.root && group.entries.is_empty() && group.groups.is_empty()
                })
                .filter(|group| self.deleted_by_one_side(group))
                .map(|group| group.id)
                .collect();
            if candidates.is_empty() {
                return;
            }
            candidates.sort_by_key(|id| id.uuid());
            for id in candidates {
                let parent = self.out.groups.get(&id).and_then(|group| group.parent);
                self.out.groups.remove(&id);
                if let Some(parent) = parent.and_then(|parent| self.out.groups.get_mut(&parent)) {
                    parent.groups.shift_remove(&id);
                }
                let when = self
                    .theirs
                    .deleted_objects
                    .get(&id.uuid())
                    .copied()
                    .flatten();
                self.out.deleted_objects.insert(id.uuid(), when);
                self.report.groups_deleted.push(id.uuid());
            }
        }
    }

    fn deleted_by_one_side(&self, group: &Group) -> bool {
        if self.theirs.groups.contains_key(&group.id) {
            return false;
        }
        match self.base {
            // Theirs deleted it; ours left it as it was.
            Some(_) => self
                .base_group(group.id)
                .is_some_and(|base| group_slots(base) == group_slots(group)),
            None => matches!(
                self.theirs.deleted_objects.get(&group.id.uuid()),
                Some(deleted) if *deleted >= group.times.last_modification
            ),
        }
    }

    // ------------------------------------------------------------ entries

    fn entries(&mut self) {
        let mut ids: Vec<EntryId> = self
            .ours
            .entries
            .keys()
            .chain(self.theirs.entries.keys())
            .copied()
            .collect();
        ids.sort_by_key(|id| id.uuid());
        ids.dedup();
        for id in ids {
            match (self.ours.entries.get(&id), self.theirs.entries.get(&id)) {
                (Some(_), Some(theirs)) => self.merge_entry(id, theirs),
                (Some(ours), None) => self.only_ours(id, ours),
                (None, Some(theirs)) => self.only_theirs(id, theirs),
                (None, None) => {}
            }
        }
    }

    fn only_ours(&mut self, id: EntryId, ours: &Entry) {
        match self.base {
            Some(base) => {
                let Some(base_entry) = base.entries.get(&id) else {
                    return; // added on our side
                };
                let unchanged = entry_slots(base, base_entry) == entry_slots(self.ours, ours)
                    && self.map_group(base_entry.parent) == ours.parent;
                if unchanged {
                    self.remove_entry(id);
                    let when = self
                        .theirs
                        .deleted_objects
                        .get(&id.uuid())
                        .copied()
                        .flatten();
                    self.out.deleted_objects.insert(id.uuid(), when);
                    self.report.deleted.push(id.uuid());
                } else {
                    self.report.restored.push(id.uuid());
                }
            }
            None => {
                if matches!(
                    self.theirs.deleted_objects.get(&id.uuid()),
                    Some(deleted) if *deleted >= ours.times.last_modification
                ) {
                    self.remove_entry(id);
                    let when = self
                        .theirs
                        .deleted_objects
                        .get(&id.uuid())
                        .copied()
                        .flatten();
                    self.out.deleted_objects.insert(id.uuid(), when);
                    self.report.deleted.push(id.uuid());
                }
            }
        }
    }

    fn only_theirs(&mut self, id: EntryId, theirs: &Entry) {
        let (bring, restored) = match self.base {
            Some(base) => match base.entries.get(&id) {
                None => (true, false), // added on their side
                Some(base_entry) => {
                    let changed = entry_slots(base, base_entry) != entry_slots(self.theirs, theirs)
                        || self.map_group(base_entry.parent) != self.map_group(theirs.parent);
                    (changed, true)
                }
            },
            None => (
                !matches!(
                    self.ours.deleted_objects.get(&id.uuid()),
                    Some(deleted) if *deleted >= theirs.times.last_modification
                ),
                self.ours.deleted_objects.contains_key(&id.uuid()),
            ),
        };
        if !bring {
            return;
        }
        let parent = self.ensure_group(theirs.parent);
        let mut entry = refs::adopt_entry(&mut self.out, self.theirs, theirs);
        entry.previous_parent_group = entry
            .previous_parent_group
            .filter(|previous| self.out.groups.contains_key(previous));
        self.out.entries.insert(id, entry);
        self.attach_entry(id, parent);
        if restored {
            self.report.restored.push(id.uuid());
        } else {
            self.report.added.push(id.uuid());
        }
    }

    fn merge_entry(&mut self, id: EntryId, theirs: &Entry) {
        let ours = self.ours.entries[&id].clone();
        let os = entry_slots(self.ours, &ours);
        let ts = entry_slots(self.theirs, theirs);
        let bs = self.base_entry_slots(id);
        let base_parent = self
            .base_entry(id)
            .map(|entry| self.map_group(entry.parent));
        let theirs_parent = self.map_group(theirs.parent);

        let (mut result, conflicts, parent_pick) = match (&bs, self.base) {
            (_, Some(_)) => {
                let (result, conflicts) =
                    self.merge_entry_fields(&ours, theirs, bs.as_ref(), &os, &ts);
                let parent_pick = pick(
                    base_parent.as_ref(),
                    Some(&ours.parent),
                    Some(&theirs_parent),
                );
                (result, conflicts, parent_pick)
            }
            (_, None) => {
                // KeePassXC's rule: the newer whole entry wins.
                if theirs.times.last_modification > ours.times.last_modification && os != ts {
                    let mut result = refs::adopt_entry(&mut self.out, self.theirs, theirs);
                    result.parent = ours.parent;
                    (result, Vec::new(), Pick::Theirs)
                } else {
                    (ours.clone(), Vec::new(), Pick::Ours)
                }
            }
        };

        result.times.last_modification =
            later(ours.times.last_modification, theirs.times.last_modification);
        result.times.last_access = later(ours.times.last_access, theirs.times.last_access);
        result.times.usage_count = ours.times.usage_count.max(theirs.times.usage_count);
        self.mark_for_review(&mut result, &ours, theirs, &conflicts);
        self.merge_history(&mut result, &ours, theirs, &os, &ts);
        self.out.entries.insert(id, result);

        let mut moved = false;
        if parent_pick == Pick::Theirs && theirs_parent != ours.parent {
            let target = self.ensure_group(theirs_parent);
            if target != ours.parent {
                self.detach_entry(id);
                self.attach_entry(id, target);
                if let Some(entry) = self.out.entries.get_mut(&id) {
                    entry.times.location_changed = theirs.times.location_changed;
                    entry.previous_parent_group = theirs
                        .previous_parent_group
                        .filter(|previous| self.out.groups.contains_key(previous));
                }
                moved = true;
                self.report.moved.push(id.uuid());
            }
        }
        let result_slots = entry_slots(&self.out, &self.out.entries[&id]);
        if result_slots != os || moved {
            self.report.updated.push(id.uuid());
        }
        if !conflicts.is_empty() {
            let title = self.out.entries[&id].get_title().map(str::to_owned);
            self.report.conflicts.push(Conflict {
                id: id.uuid(),
                title,
                fields: conflicts,
            });
        }
    }

    /// Field-by-field three-way merge of an entry both sides have. Starts
    /// from ours and takes each change only theirs made.
    fn merge_entry_fields(
        &mut self,
        ours: &Entry,
        theirs: &Entry,
        bs: Option<&EntrySlots>,
        os: &EntrySlots,
        ts: &EntrySlots,
    ) -> (Entry, Vec<String>) {
        let mut result = ours.clone();
        let mut conflicts = Vec::new();

        let keys: BTreeSet<&String> = os.fields.keys().chain(ts.fields.keys()).collect();
        for key in keys {
            match pick(
                bs.and_then(|b| b.fields.get(key)),
                os.fields.get(key),
                ts.fields.get(key),
            ) {
                Pick::Theirs => match ts.fields.get(key) {
                    Some(value) => {
                        result.fields.insert(key.clone(), value.clone());
                    }
                    None => {
                        result.fields.remove(key);
                    }
                },
                Pick::Conflict => conflicts.push(key.clone()),
                Pick::Ours => {}
            }
        }

        result.tags = merge_tags(bs.map(|b| &b.tags), &ours.tags, &theirs.tags);

        let names: BTreeSet<&String> = os.attachments.keys().chain(ts.attachments.keys()).collect();
        for name in names {
            match pick(
                bs.and_then(|b| b.attachments.get(name)),
                os.attachments.get(name),
                ts.attachments.get(name),
            ) {
                Pick::Theirs => match ts.attachments.get(name) {
                    Some(data) => {
                        let attachment = refs::import_attachment(&mut self.out, data);
                        result.attachments.insert(name.clone(), attachment);
                    }
                    None => {
                        result.attachments.remove(name);
                    }
                },
                Pick::Conflict => conflicts.push(format!("attachment {name}")),
                Pick::Ours => {}
            }
        }

        macro_rules! slot {
            ($field:ident, $label:expr, $apply:expr) => {
                match pick(bs.map(|b| &b.$field), Some(&os.$field), Some(&ts.$field)) {
                    Pick::Theirs => $apply(&mut result),
                    Pick::Conflict => conflicts.push($label.to_owned()),
                    Pick::Ours => {}
                }
            };
        }
        slot!(icon, "icon", |r: &mut Entry| r.icon = theirs.icon.clone());
        slot!(colours, "colour", |r: &mut Entry| {
            r.foreground_color = theirs.foreground_color.clone();
            r.background_color = theirs.background_color.clone();
        });
        slot!(override_url, "URL override", |r: &mut Entry| r
            .override_url =
            theirs.override_url.clone());
        slot!(quality_check, "quality check", |r: &mut Entry| r
            .quality_check =
            theirs.quality_check);
        slot!(autotype, "auto-type", |r: &mut Entry| r.autotype =
            theirs.autotype.clone());
        slot!(expiry, "expiry", |r: &mut Entry| {
            r.times.expires = theirs.times.expires;
            r.times.expiry = theirs.times.expiry;
        });
        if let Some(Icon::Custom(icon)) = result.icon {
            if !refs::import_icon(&mut self.out, self.theirs, icon) {
                result.icon = ours.icon.clone();
            }
        }

        let base_data = self
            .base_entry(ours.id)
            .map(|entry| entry.custom_data.clone());
        merge_custom_data(
            &mut result.custom_data,
            base_data.as_ref(),
            &ours.custom_data,
            &theirs.custom_data,
            |key| {
                if key != REVIEW_KEY {
                    conflicts.push(format!("custom data {key}"));
                }
            },
        );
        (result, conflicts)
    }

    /// The review mark: three-way like any custom data (so a review done on
    /// one side clears it), plus this merge's conflicts.
    fn mark_for_review(
        &self,
        result: &mut Entry,
        ours: &Entry,
        theirs: &Entry,
        conflicts: &[String],
    ) {
        let marked = |entry: Option<&Entry>| -> Option<String> {
            match entry?.custom_data.get(REVIEW_KEY)?.value.as_ref()? {
                CustomDataValue::String(fields) => Some(fields.clone()),
                CustomDataValue::Binary(_) => None,
            }
        };
        let base = self.base_entry(ours.id);
        let previous = match pick(
            marked(base).as_ref(),
            marked(Some(ours)).as_ref(),
            marked(Some(theirs)).as_ref(),
        ) {
            Pick::Theirs => marked(Some(theirs)),
            Pick::Ours => marked(Some(ours)),
            Pick::Conflict => {
                let mut both: BTreeSet<String> = BTreeSet::new();
                for fields in [marked(Some(ours)), marked(Some(theirs))]
                    .into_iter()
                    .flatten()
                {
                    both.extend(fields.lines().map(str::to_owned));
                }
                Some(both.into_iter().collect::<Vec<_>>().join("\n"))
            }
        };
        let mut fields: BTreeSet<String> = previous
            .iter()
            .flat_map(|text| text.lines().map(str::to_owned))
            .collect();
        fields.extend(conflicts.iter().cloned());
        fields.retain(|field| !field.is_empty());
        if fields.is_empty() {
            result.custom_data.remove(REVIEW_KEY);
        } else {
            result.custom_data.insert(
                REVIEW_KEY.to_owned(),
                CustomDataItem {
                    value: Some(CustomDataValue::String(
                        fields.into_iter().collect::<Vec<_>>().join("\n"),
                    )),
                    last_modification_time: result.times.last_modification,
                },
            );
        }
    }

    /// Both histories, plus ours and theirs as they were when either differs
    /// from the result, so every value either side had is current or in the
    /// history; oldest first, as KeePass files store it, duplicates dropped,
    /// trimmed to the vault's history limits by dropping the oldest.
    fn merge_history(
        &mut self,
        result: &mut Entry,
        ours: &Entry,
        theirs: &Entry,
        os: &EntrySlots,
        ts: &EntrySlots,
    ) {
        let mut items: Vec<Entry> = Vec::new();
        if let Some(history) = &ours.history {
            items.extend(history.entries.iter().cloned());
        }
        if let Some(history) = &theirs.history {
            for item in &history.entries {
                items.push(refs::adopt_entry(&mut self.out, self.theirs, item));
            }
        }
        let result_slots = entry_slots(&self.out, result);
        if result_slots != *os {
            let mut snapshot = ours.clone();
            snapshot.history = None;
            items.push(snapshot);
        }
        if result_slots != *ts {
            let mut snapshot = refs::adopt_entry(&mut self.out, self.theirs, theirs);
            snapshot.history = None;
            items.push(snapshot);
        }
        for item in &mut items {
            item.history = None;
            item.custom_data.remove(REVIEW_KEY);
        }
        items.sort_by_key(|item| item.times.last_modification);
        let mut kept: Vec<Entry> = Vec::new();
        for item in items {
            let slots = entry_slots(&self.out, &item);
            let duplicate = kept.iter().any(|other| {
                other.times.last_modification == item.times.last_modification
                    && entry_slots(&self.out, other) == slots
            });
            if !duplicate {
                kept.push(item);
            }
        }
        trim_history(&self.out, &mut kept);
        result.history = Some(History { entries: kept });
    }

    // ---------------------------------------------------- deleted objects

    fn deleted_objects(&mut self) {
        let mut merged: HashMap<Uuid, Option<NaiveDateTime>> = self.out.deleted_objects.clone();
        for (id, when) in self
            .ours
            .deleted_objects
            .iter()
            .chain(self.theirs.deleted_objects.iter())
        {
            let entry = merged.entry(*id).or_insert(*when);
            *entry = (*entry).max(*when);
        }
        let present: BTreeSet<Uuid> = self
            .out
            .entries
            .keys()
            .map(|id| id.uuid())
            .chain(self.out.groups.keys().map(|id| id.uuid()))
            .chain(self.out.custom_icons.keys().map(|id| id.uuid()))
            .collect();
        merged.retain(|id, _| !present.contains(id));
        self.out.deleted_objects = merged;
    }
}

/// Tags as a set merged three-way, in ours' order with theirs' additions
/// after; without a base, the union.
fn merge_tags(base: Option<&BTreeSet<String>>, ours: &[String], theirs: &[String]) -> Vec<String> {
    let in_ours: BTreeSet<&String> = ours.iter().collect();
    let in_theirs: BTreeSet<&String> = theirs.iter().collect();
    let keep = |tag: &String| -> bool {
        let (o, t) = (in_ours.contains(tag), in_theirs.contains(tag));
        match base {
            Some(base) => {
                let b = base.contains(tag);
                if o == t {
                    o
                } else if o == b {
                    t
                } else {
                    o
                }
            }
            None => o || t,
        }
    };
    let mut result: Vec<String> = Vec::new();
    for tag in ours.iter().chain(theirs.iter()) {
        if keep(tag) && !result.contains(tag) {
            result.push(tag.clone());
        }
    }
    result
}

/// Custom data merged key by key; `conflict` is told each key both sides
/// changed differently (ours is kept). Without a base, ours wins.
fn merge_custom_data(
    out: &mut HashMap<String, CustomDataItem>,
    base: Option<&HashMap<String, CustomDataItem>>,
    ours: &HashMap<String, CustomDataItem>,
    theirs: &HashMap<String, CustomDataItem>,
    mut conflict: impl FnMut(&str),
) {
    let Some(base) = base else {
        return;
    };
    let value = |data: &HashMap<String, CustomDataItem>, key: &str| {
        data.get(key).map(|item| item.value.clone())
    };
    let keys: BTreeSet<&String> = ours
        .keys()
        .chain(theirs.keys())
        .chain(base.keys())
        .collect();
    for key in keys {
        if key == REVIEW_KEY {
            continue;
        }
        match pick(
            value(base, key).as_ref(),
            value(ours, key).as_ref(),
            value(theirs, key).as_ref(),
        ) {
            Pick::Theirs => match theirs.get(key) {
                Some(item) => {
                    out.insert(key.clone(), item.clone());
                }
                None => {
                    out.remove(key);
                }
            },
            Pick::Conflict => conflict(key),
            Pick::Ours => {}
        }
    }
}

/// An entry's size for the history size limit: its strings and attachments.
/// Trims history `items` (oldest first) to the vault's limits on the number
/// of items and their size, dropping the oldest, as KeePass apps do.
pub(crate) fn trim_history(db: &Database, items: &mut Vec<Entry>) {
    if let Some(limit) = db.meta.history_max_items.filter(|limit| *limit >= 0) {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let excess = items.len().saturating_sub(limit);
        items.drain(..excess);
    }
    if let Some(limit) = db.meta.history_max_size.filter(|limit| *limit >= 0) {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut total = 0usize;
        let mut keep = 0;
        for item in items.iter().rev() {
            total = total.saturating_add(entry_size(db, item));
            if total > limit {
                break;
            }
            keep += 1;
        }
        let excess = items.len() - keep;
        items.drain(..excess);
    }
}

fn entry_size(db: &Database, entry: &Entry) -> usize {
    let strings: usize = entry
        .fields
        .iter()
        .map(|(key, value)| key.len() + value.get().len())
        .sum();
    let attachments: usize = entry
        .attachments
        .values()
        .filter_map(|id| db.attachments.get(id))
        .map(|attachment| attachment.data.get().len())
        .sum();
    strings + attachments
}
