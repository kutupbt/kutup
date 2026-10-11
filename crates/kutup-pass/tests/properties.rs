//! Properties of the three-way merge over generated edits (docs/plans/pass.md,
//! "Tests (K0)"): nothing either side changed is lost, merging with an
//! unchanged side gives the other side, and the result is deterministic.

use chrono::{NaiveDate, NaiveDateTime};
use kutup_pass::keepass::db::{EntryId, Value};
use kutup_pass::keepass::Database;
use kutup_pass::{merge, open, save, VaultKey};
use proptest::prelude::*;

const FIELDS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
const ENTRIES: usize = 4;

fn at(minute: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 10, 11)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        + chrono::Duration::minutes(minute.into())
}

#[derive(Debug, Clone)]
enum Op {
    /// Set a field of an entry (`None` removes it).
    Set {
        entry: usize,
        field: usize,
        value: Option<u8>,
    },
    Delete {
        entry: usize,
    },
    Add {
        title: u8,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0..ENTRIES, 0..FIELDS.len(), proptest::option::of(0u8..4)).prop_map(|(entry, field, value)| Op::Set { entry, field, value }),
        1 => (0..ENTRIES).prop_map(|entry| Op::Delete { entry }),
        1 => (0u8..4).prop_map(|title| Op::Add { title }),
    ]
}

fn base() -> (Database, Vec<EntryId>) {
    let mut db = Database::new();
    db.meta.history_max_items = Some(-1); // unlimited, so "in history" is checkable
    db.meta.history_max_size = Some(-1);
    let mut ids = Vec::new();
    for index in 0..ENTRIES {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", format!("entry {index}"));
        entry.set_protected("Password", format!("base {index}"));
        entry.times.last_modification = Some(at(0));
        ids.push(entry.id());
    }
    (db, ids)
}

fn value(side: &str, v: u8) -> String {
    format!("{side}-{v}")
}

/// Applies edits as a KeePass app does: previous state into history first.
fn apply(db: &mut Database, ids: &[EntryId], ops: &[Op], side: &str, start: u32) {
    for (step, op) in ops.iter().enumerate() {
        let minute = start + u32::try_from(step).unwrap();
        match op {
            Op::Set {
                entry,
                field,
                value: v,
            } => {
                let Some(entry) = db.entries.get_mut(&ids[*entry]) else {
                    continue;
                };
                let mut previous = entry.clone();
                previous.history = None;
                entry
                    .history
                    .get_or_insert_with(Default::default)
                    .entries
                    .push(previous);
                match v {
                    Some(v) => {
                        entry.fields.insert(
                            FIELDS[*field].to_owned(),
                            Value::unprotected(value(side, *v)),
                        );
                    }
                    None => {
                        entry.fields.remove(FIELDS[*field]);
                    }
                }
                entry.times.last_modification = Some(at(minute));
            }
            Op::Delete { entry } => {
                if let Some(handle) = db.entry_mut(ids[*entry]) {
                    handle.remove();
                    db.deleted_objects
                        .insert(ids[*entry].uuid(), Some(at(minute)));
                }
            }
            Op::Add { title } => {
                let mut root = db.root_mut();
                let mut entry = root.add_entry();
                entry.set_unprotected("Title", format!("{side} new {title}"));
                entry.times.last_modification = Some(at(minute));
            }
        }
    }
}

fn fields(db: &Database, id: EntryId) -> Option<Vec<(String, String)>> {
    let entry = db.entries.get(&id)?;
    let mut fields: Vec<(String, String)> = entry
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), v.get().clone()))
        .collect();
    fields.sort();
    Some(fields)
}

/// Every field value `side` changed from base is in the result: current, or
/// in the entry's history.
fn assert_nothing_lost(base: &Database, side: &Database, merged: &Database) {
    for (id, entry) in &side.entries {
        let base_entry = base.entries.get(id);
        let changed = base_entry.is_none_or(|b| fields(base, b.id) != fields(side, *id));
        if !changed {
            continue;
        }
        let merged_entry = merged
            .entries
            .get(id)
            .unwrap_or_else(|| panic!("edited entry {id} was lost"));
        for (name, value) in &entry.fields {
            let base_value = base_entry.and_then(|b| b.fields.get(name)).map(|v| v.get());
            if base_value == Some(value.get()) {
                continue;
            }
            let current = merged_entry.fields.get(name).map(|v| v.get()) == Some(value.get());
            let in_history = merged_entry.history.as_ref().is_some_and(|history| {
                history
                    .entries
                    .iter()
                    .any(|item| item.fields.get(name).map(|v| v.get()) == Some(value.get()))
            });
            assert!(
                current || in_history,
                "{name} = {:?} of entry {id} was lost",
                value.get()
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, ..ProptestConfig::default() })]

    #[test]
    fn nothing_either_side_changed_is_lost(ours_ops in prop::collection::vec(op(), 0..8), theirs_ops in prop::collection::vec(op(), 0..8)) {
        let (base, ids) = base();
        let (mut ours, mut theirs) = (base.clone(), base.clone());
        apply(&mut ours, &ids, &ours_ops, "ours", 1);
        apply(&mut theirs, &ids, &theirs_ops, "theirs", 30);
        let (merged, _) = merge(Some(&base), &ours, &theirs);
        assert_nothing_lost(&base, &ours, &merged);
        assert_nothing_lost(&base, &theirs, &merged);
    }

    #[test]
    fn an_unchanged_side_gives_the_other(ops in prop::collection::vec(op(), 0..8)) {
        let (base, ids) = base();
        let mut edited = base.clone();
        apply(&mut edited, &ids, &ops, "ours", 1);
        let (merged, report) = merge(Some(&base), &edited, &base);
        prop_assert!(report.is_clean());
        let (theirs_merged, _) = merge(Some(&base), &base, &edited);
        for id in edited.entries.keys().chain(base.entries.keys()) {
            prop_assert_eq!(fields(&merged, *id), fields(&edited, *id));
            prop_assert_eq!(fields(&theirs_merged, *id), fields(&edited, *id));
        }
        prop_assert_eq!(merged.entries.len(), edited.entries.len());
        prop_assert_eq!(theirs_merged.entries.len(), edited.entries.len());
    }

    #[test]
    fn merging_is_deterministic_and_saveable(ours_ops in prop::collection::vec(op(), 0..6), theirs_ops in prop::collection::vec(op(), 0..6)) {
        let (base, ids) = base();
        let (mut ours, mut theirs) = (base.clone(), base.clone());
        apply(&mut ours, &ids, &ours_ops, "ours", 1);
        apply(&mut theirs, &ids, &theirs_ops, "theirs", 30);
        let first = merge(Some(&base), &ours, &theirs);
        let second = merge(Some(&base), &ours, &theirs);
        prop_assert_eq!(&first, &second);
        let key = VaultKey::new().with_password("p");
        let reopened = open(&save(&first.0, &key).unwrap(), &key).unwrap();
        prop_assert_eq!(reopened.entries.len(), first.0.entries.len());
    }
}
