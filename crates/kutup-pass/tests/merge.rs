//! The three-way merge, case by case (docs/plans/pass.md, "Tests (K0)").

use chrono::{NaiveDate, NaiveDateTime};
use kutup_pass::keepass::db::{CustomDataValue, Entry, EntryId, GroupId, Value};
use kutup_pass::keepass::Database;
use kutup_pass::{merge, open, save, VaultKey, REVIEW_KEY};

fn at(minute: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 10, 11)
        .unwrap()
        .and_hms_opt(12, minute, 0)
        .unwrap()
}

/// A vault with two entries in the root and one group holding a third.
fn base() -> (Database, EntryId, EntryId, GroupId, EntryId) {
    let mut db = Database::new();
    db.meta.database_name = Some("Family".into());
    db.meta.history_max_items = Some(10);
    let bank = add_entry(&mut db, None, "Bank", "ayse", "bank-1", 0);
    let mail = add_entry(&mut db, None, "Mail", "ayse@kutup.dev", "mail-1", 0);
    let work = {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = "Work".into();
        group.times.last_modification = Some(at(0));
        group.id()
    };
    let vpn = add_entry(&mut db, Some(work), "VPN", "ayse", "vpn-1", 0);
    (db, bank, mail, work, vpn)
}

fn add_entry(
    db: &mut Database,
    group: Option<GroupId>,
    title: &str,
    user: &str,
    password: &str,
    minute: u32,
) -> EntryId {
    let group = group.unwrap_or_else(|| db.root().id());
    let mut parent = db.group_mut(group).unwrap();
    let mut entry = parent.add_entry();
    entry.set_unprotected("Title", title);
    entry.set_unprotected("UserName", user);
    entry.set_protected("Password", password);
    entry.times.last_modification = Some(at(minute));
    entry.id()
}

/// Edits an entry the way a KeePass app does: the previous state goes to the
/// end of its history (oldest first), then the change, then a new
/// modification time.
fn edit(db: &mut Database, id: EntryId, minute: u32, change: impl FnOnce(&mut Entry)) {
    let entry = db.entries.get_mut(&id).unwrap();
    let mut previous = entry.clone();
    previous.history = None;
    entry
        .history
        .get_or_insert_with(Default::default)
        .entries
        .push(previous);
    change(entry);
    entry.times.last_modification = Some(at(minute));
}

fn set(field: &str, value: &str) -> impl FnOnce(&mut Entry) {
    let (field, value) = (field.to_owned(), value.to_owned());
    move |entry: &mut Entry| {
        let protected = field == "Password";
        entry.fields.insert(
            field,
            if protected {
                Value::protected(value)
            } else {
                Value::unprotected(value)
            },
        );
    }
}

fn field(db: &Database, id: EntryId, name: &str) -> Option<String> {
    db.entries
        .get(&id)
        .and_then(|entry| entry.fields.get(name))
        .map(|value| value.get().clone())
}

fn history_has(db: &Database, id: EntryId, name: &str, value: &str) -> bool {
    db.entries[&id].history.as_ref().is_some_and(|history| {
        history
            .entries
            .iter()
            .any(|item| item.fields.get(name).is_some_and(|v| v.get() == value))
    })
}

fn delete(db: &mut Database, id: EntryId, minute: u32) {
    db.entry_mut(id).unwrap().remove();
    db.deleted_objects.insert(id.uuid(), Some(at(minute)));
}

/// The merged vault still saves and opens.
fn assert_saves(db: &Database) {
    let key = VaultKey::new().with_password("p");
    let bytes = save(db, &key).unwrap();
    open(&bytes, &key).unwrap();
}

#[test]
fn edits_to_different_entries_both_survive() {
    let (base, bank, mail, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "bank-2"));
    edit(&mut theirs, mail, 6, set("Password", "mail-2"));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("bank-2"));
    assert_eq!(field(&merged, mail, "Password").as_deref(), Some("mail-2"));
    assert!(report.is_clean());
    assert_eq!(report.updated, vec![mail.uuid()]);
    assert_saves(&merged);
}

#[test]
fn different_fields_of_one_entry_both_survive() {
    let (base, bank, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "bank-2"));
    edit(&mut theirs, bank, 6, set("UserName", "ayse.yilmaz"));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("bank-2"));
    assert_eq!(
        field(&merged, bank, "UserName").as_deref(),
        Some("ayse.yilmaz")
    );
    assert!(report.is_clean(), "{report:?}");
    assert!(!merged.entries[&bank].custom_data.contains_key(REVIEW_KEY));
    // KeePassXC would have kept only one of the two changes as current.
    assert!(merged.entries[&bank].fields["Password"].is_protected());
    assert_saves(&merged);
}

#[test]
fn the_same_field_changed_differently_keeps_ours_and_theirs_in_history() {
    let (base, bank, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 9, set("Password", "ours"));
    edit(&mut theirs, bank, 5, set("Password", "theirs"));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("ours"));
    assert!(history_has(&merged, bank, "Password", "theirs"));
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].fields, vec!["Password".to_owned()]);
    assert_eq!(report.conflicts[0].title.as_deref(), Some("Bank"));
    let mark = &merged.entries[&bank].custom_data[REVIEW_KEY];
    assert_eq!(mark.value, Some(CustomDataValue::String("Password".into())));
    // The device clock does not decide: theirs was edited earlier, ours later,
    // and swapping the times changes nothing.
    let (mut ours2, mut theirs2) = (base.clone(), base.clone());
    edit(&mut ours2, bank, 5, set("Password", "ours"));
    edit(&mut theirs2, bank, 9, set("Password", "theirs"));
    let (merged2, _) = merge(Some(&base), &ours2, &theirs2);
    assert_eq!(field(&merged2, bank, "Password").as_deref(), Some("ours"));
    assert_saves(&merged);
}

#[test]
fn the_same_change_on_both_sides_is_no_conflict() {
    let (base, bank, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "same"));
    edit(&mut theirs, bank, 7, set("Password", "same"));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("same"));
    assert!(report.is_clean());
}

#[test]
fn an_edit_wins_over_a_deletion_on_either_side() {
    let (base, bank, ..) = base();
    // We edited, they deleted.
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "kept"));
    delete(&mut theirs, bank, 6);
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("kept"));
    assert_eq!(report.restored, vec![bank.uuid()]);
    assert!(!merged.deleted_objects.contains_key(&bank.uuid()));
    assert_saves(&merged);
    // We deleted, they edited.
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    delete(&mut ours, bank, 6);
    edit(&mut theirs, bank, 5, set("Password", "kept"));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("kept"));
    assert_eq!(report.restored, vec![bank.uuid()]);
    assert!(!merged.deleted_objects.contains_key(&bank.uuid()));
    assert_saves(&merged);
}

#[test]
fn a_deletion_of_an_unchanged_entry_applies() {
    let (base, bank, ..) = base();
    let (ours, mut theirs) = (base.clone(), base.clone());
    delete(&mut theirs, bank, 6);
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert!(!merged.entries.contains_key(&bank));
    assert!(!merged.root().entries().any(|entry| entry.id() == bank));
    assert_eq!(report.deleted, vec![bank.uuid()]);
    assert_eq!(merged.deleted_objects.get(&bank.uuid()), Some(&Some(at(6))));
    // And both deleting it is simply deleted.
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    delete(&mut ours, bank, 6);
    delete(&mut theirs, bank, 7);
    let (merged, _) = merge(Some(&base), &ours, &theirs);
    assert!(!merged.entries.contains_key(&bank));
    assert_saves(&merged);
}

#[test]
fn entries_added_on_both_sides_are_all_kept() {
    let (base, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    let wifi = add_entry(&mut ours, None, "Wi-Fi", "", "wifi", 5);
    let tax = add_entry(&mut theirs, None, "Tax office", "12345", "tax", 6);
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert!(merged.entries.contains_key(&wifi) && merged.entries.contains_key(&tax));
    assert!(merged.root().entries().any(|entry| entry.id() == tax));
    assert_eq!(report.added, vec![tax.uuid()]);
    assert_saves(&merged);
}

#[test]
fn a_move_on_one_side_and_an_edit_on_the_other_both_apply() {
    let (base, bank, _, work, _) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "bank-2"));
    theirs.entry_mut(bank).unwrap().move_to(work).unwrap();
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(merged.entries[&bank].parent, work);
    assert!(merged.groups[&work].entries.contains(&bank));
    assert!(!merged.groups[&merged.root().id()].entries.contains(&bank));
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("bank-2"));
    assert_eq!(report.moved, vec![bank.uuid()]);
    assert_saves(&merged);
}

#[test]
fn moves_on_both_sides_keep_ours() {
    let (mut base, bank, ..) = base();
    let other = {
        let mut root = base.root_mut();
        let mut group = root.add_group();
        group.name = "Other".into();
        group.id()
    };
    let work = base
        .root()
        .groups()
        .find(|group| group.name == "Work")
        .unwrap()
        .id();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    ours.entry_mut(bank).unwrap().move_to(work).unwrap();
    theirs.entry_mut(bank).unwrap().move_to(other).unwrap();
    let (merged, _) = merge(Some(&base), &ours, &theirs);
    assert_eq!(merged.entries[&bank].parent, work);
    assert_saves(&merged);
}

#[test]
fn a_group_added_on_their_side_comes_with_its_entries() {
    let (base, ..) = base();
    let (ours, mut theirs) = (base.clone(), base.clone());
    let travel = {
        let mut root = theirs.root_mut();
        let mut group = root.add_group();
        group.name = "Travel".into();
        group.id()
    };
    let airline = add_entry(&mut theirs, Some(travel), "Airline", "a", "air", 6);
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(merged.groups[&travel].name, "Travel");
    assert_eq!(merged.entries[&airline].parent, travel);
    assert!(merged.groups[&travel].entries.contains(&airline));
    assert_eq!(report.groups_added, vec![travel.uuid()]);
    assert_saves(&merged);
}

#[test]
fn a_group_deleted_on_one_side_stays_if_the_other_put_something_in_it() {
    let (base, _, _, work, vpn) = base();
    // They deleted Work with its entry; we left it alone: it goes.
    let (ours, mut theirs) = (base.clone(), base.clone());
    delete(&mut theirs, vpn, 6);
    theirs.group_mut(work).unwrap().remove();
    theirs.deleted_objects.insert(work.uuid(), Some(at(6)));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert!(!merged.groups.contains_key(&work));
    assert!(!merged.entries.contains_key(&vpn));
    assert_eq!(report.groups_deleted, vec![work.uuid()]);
    assert_saves(&merged);
    // They deleted Work; we added an entry to it: Work and both entries stay.
    let mut ours = base.clone();
    let printer = add_entry(&mut ours, Some(work), "Printer", "admin", "p", 5);
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert!(merged.groups.contains_key(&work));
    assert_eq!(merged.entries[&printer].parent, work);
    assert!(report.groups_deleted.is_empty());
    assert_saves(&merged);
}

#[test]
fn attachments_travel_with_their_data_and_conflict_by_name() {
    let (base, bank, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    theirs
        .entry_mut(bank)
        .unwrap()
        .add_attachment("statement.pdf", Value::unprotected(b"%PDF-1".to_vec()));
    ours.entry_mut(bank)
        .unwrap()
        .add_attachment("note.txt", Value::unprotected(b"ours".to_vec()));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    let entry = merged.entry(bank).unwrap();
    assert_eq!(
        entry
            .attachment_by_name("statement.pdf")
            .unwrap()
            .data
            .get(),
        b"%PDF-1"
    );
    assert_eq!(
        entry.attachment_by_name("note.txt").unwrap().data.get(),
        b"ours"
    );
    assert!(report.is_clean());
    assert_saves(&merged);
    // The same name with different contents: ours, reported.
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    ours.entry_mut(bank)
        .unwrap()
        .add_attachment("id.jpg", Value::unprotected(b"ours".to_vec()));
    theirs
        .entry_mut(bank)
        .unwrap()
        .add_attachment("id.jpg", Value::unprotected(b"theirs".to_vec()));
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(
        merged
            .entry(bank)
            .unwrap()
            .attachment_by_name("id.jpg")
            .unwrap()
            .data
            .get(),
        b"ours"
    );
    assert_eq!(
        report.conflicts[0].fields,
        vec!["attachment id.jpg".to_owned()]
    );
    assert_saves(&merged);
}

#[test]
fn history_respects_the_vault_limit() {
    let (mut base, bank, ..) = base();
    base.meta.history_max_items = Some(3);
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    for minute in 1..=5 {
        edit(
            &mut ours,
            bank,
            minute,
            set("Notes", &format!("ours {minute}")),
        );
        edit(
            &mut theirs,
            bank,
            minute + 10,
            set("URL", &format!("https://example.org/{minute}")),
        );
    }
    let (merged, _) = merge(Some(&base), &ours, &theirs);
    let history = merged.entries[&bank].history.as_ref().unwrap();
    assert!(history.entries.len() <= 3);
    let times: Vec<_> = history
        .entries
        .iter()
        .map(|item| item.times.last_modification)
        .collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted, "oldest first, as KeePass files store it");
    assert_saves(&merged);
}

#[test]
fn database_settings_merge_three_way() {
    let (base, ..) = base();
    let (ours, mut theirs) = (base.clone(), base.clone());
    theirs.meta.database_name = Some("Yılmaz family".into());
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(merged.meta.database_name.as_deref(), Some("Yılmaz family"));
    assert!(report.metadata_conflicts.is_empty());
    let mut ours = base.clone();
    ours.meta.database_name = Some("Ours".into());
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert_eq!(merged.meta.database_name.as_deref(), Some("Ours"));
    assert_eq!(report.metadata_conflicts, vec!["database name".to_owned()]);
}

#[test]
fn a_review_done_on_one_side_clears_the_mark() {
    let (base, bank, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "a"));
    edit(&mut theirs, bank, 6, set("Password", "b"));
    let (marked, _) = merge(Some(&base), &ours, &theirs);
    assert!(marked.entries[&bank].custom_data.contains_key(REVIEW_KEY));
    // Our device reviews (removes the mark); theirs syncs the marked version.
    let mut reviewed = marked.clone();
    reviewed
        .entries
        .get_mut(&bank)
        .unwrap()
        .custom_data
        .remove(REVIEW_KEY);
    let (merged, report) = merge(Some(&marked), &reviewed, &marked);
    assert!(!merged.entries[&bank].custom_data.contains_key(REVIEW_KEY));
    assert!(report.is_clean());
}

#[test]
fn without_a_base_the_newer_whole_entry_wins_as_in_keepassxc() {
    let (base, bank, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "older"));
    edit(&mut theirs, bank, 9, set("Password", "newer"));
    let (merged, _) = merge(None, &ours, &theirs);
    assert_eq!(field(&merged, bank, "Password").as_deref(), Some("newer"));
    assert!(history_has(&merged, bank, "Password", "older"));
    assert_saves(&merged);
}

#[test]
fn merging_is_deterministic() {
    let (base, bank, mail, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "x"));
    edit(&mut theirs, bank, 6, set("Password", "y"));
    edit(&mut theirs, mail, 7, set("UserName", "z"));
    add_entry(&mut theirs, None, "New", "n", "n", 8);
    let first = merge(Some(&base), &ours, &theirs);
    let second = merge(Some(&base), &ours, &theirs);
    assert_eq!(first, second);
}

#[test]
fn a_merged_vault_round_trips_through_kdbx() {
    let (base, bank, mail, ..) = base();
    let (mut ours, mut theirs) = (base.clone(), base.clone());
    edit(&mut ours, bank, 5, set("Password", "x"));
    edit(&mut theirs, bank, 6, set("Password", "y"));
    edit(&mut theirs, mail, 7, set("UserName", "z"));
    theirs
        .entry_mut(mail)
        .unwrap()
        .add_attachment("a.txt", Value::protected(b"secret".to_vec()));
    let (merged, _) = merge(Some(&base), &ours, &theirs);
    let key = VaultKey::new().with_password("p");
    let reopened = open(&save(&merged, &key).unwrap(), &key).unwrap();
    assert_eq!(field(&reopened, bank, "Password").as_deref(), Some("x"));
    assert!(history_has(&reopened, bank, "Password", "y"));
    assert_eq!(
        reopened
            .entry(mail)
            .unwrap()
            .attachment_by_name("a.txt")
            .unwrap()
            .data
            .get(),
        b"secret"
    );
    assert!(reopened.entries[&bank].custom_data.contains_key(REVIEW_KEY));
}
