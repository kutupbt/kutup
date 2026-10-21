//! Vault edits as the website makes them (docs/plans/pass.md, K2b): KeePass
//! semantics (history, recycle bin, deletions recorded), refused edits
//! changing nothing, and edits from two copies merging.

use base64::Engine as _;
use chrono::{NaiveDate, NaiveDateTime};
use kutup_pass::edit::{apply, new_vault, Applied, EditError, EntryInput, Op};
use kutup_pass::keepass::db::EntryId;
use kutup_pass::keepass::Database;
use kutup_pass::view::{self, FieldView, VaultView};
use kutup_pass::{merge, open, save, VaultKey};

fn at(minute: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 10, 12)
        .unwrap()
        .and_hms_opt(9, 0, 0)
        .unwrap()
        + chrono::Duration::minutes(minute.into())
}

fn field(key: &str, value: &str) -> FieldView {
    FieldView {
        key: key.into(),
        value: value.into(),
        protected: false,
    }
}

fn input(fields: &[(&str, &str)]) -> EntryInput {
    EntryInput {
        fields: fields.iter().map(|(k, v)| field(k, v)).collect(),
        ..EntryInput::default()
    }
}

fn run(db: &mut Database, op: Op, minute: u32) -> Applied {
    apply(db, &op, at(minute)).unwrap()
}

fn vault() -> Database {
    new_vault("Kişisel", at(0)).unwrap()
}

fn add(db: &mut Database, title: &str, minute: u32) -> String {
    let root = view::view(db).root_group_id;
    run(
        db,
        Op::CreateEntry {
            group_id: root,
            entry: input(&[("Title", title), ("Password", "p0")]),
        },
        minute,
    )
    .id
    .unwrap()
}

fn entry<'a>(v: &'a VaultView, id: &str) -> &'a view::EntryView {
    v.entries.iter().find(|e| e.id == id).unwrap()
}

fn value(v: &VaultView, id: &str, key: &str) -> String {
    entry(v, id)
        .fields
        .iter()
        .find(|f| f.key == key)
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

fn eid(id: &str) -> EntryId {
    EntryId::from(uuid::Uuid::parse_str(id).unwrap())
}

#[test]
fn a_new_vault_round_trips_with_keepassxc_defaults() {
    let db = vault();
    let key = VaultKey::new().with_password("parola");
    let reopened = open(&save(&db, &key).unwrap(), &key).unwrap();
    let v = view::view(&reopened);
    assert_eq!(v.name, "Kişisel");
    assert_eq!(v.groups.len(), 1);
    assert_eq!(v.groups[0].name, "Kişisel");
    assert!(v.recycle_bin_enabled);
    assert_eq!(v.recycle_bin_id, None);
    assert_eq!(v.history_max_items, Some(10));
    assert_eq!(v.history_max_size, Some(6 * 1024 * 1024));
    assert!(matches!(
        reopened.config.kdf_config,
        kutup_pass::keepass::config::KdfConfig::Argon2id { .. }
    ));
}

#[test]
fn a_new_entry_has_the_standard_fields_and_a_protected_password() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    let v = view::view(&db);
    let e = entry(&v, &id);
    let keys: Vec<&str> = e.fields.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys, ["Title", "UserName", "Password", "URL", "Notes"]);
    assert!(e.fields[2].protected, "the password is protected");
    assert!(!e.fields[0].protected);
    assert_eq!(e.created.as_deref(), Some("2026-10-12T09:01:00Z"));
    assert_eq!(e.group_id, v.root_group_id);
}

#[test]
fn an_edit_keeps_the_previous_state_in_history() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    let changed = run(
        &mut db,
        Op::UpdateEntry {
            id: id.clone(),
            entry: input(&[("Title", "Banka"), ("Password", "p1"), ("PIN", "1234")]),
        },
        2,
    );
    assert!(changed.changed);
    let v = view::view(&db);
    assert_eq!(value(&v, &id, "Password"), "p1");
    assert_eq!(value(&v, &id, "PIN"), "1234");
    assert_eq!(entry(&v, &id).history_count, 1);
    assert_eq!(
        entry(&v, &id).modified.as_deref(),
        Some("2026-10-12T09:02:00Z")
    );
    let history = view::history(&db, &db.entries[&eid(&id)]);
    assert_eq!(history[0].fields[2].value, "p0");

    // The same data again changes nothing and adds no history.
    let same = run(
        &mut db,
        Op::UpdateEntry {
            id: id.clone(),
            entry: input(&[("Title", "Banka"), ("Password", "p1"), ("PIN", "1234")]),
        },
        3,
    );
    assert!(!same.changed);
    assert_eq!(entry(&view::view(&db), &id).history_count, 1);
}

#[test]
fn history_is_trimmed_to_the_vault_limit() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    for n in 0..15 {
        run(
            &mut db,
            Op::UpdateEntry {
                id: id.clone(),
                entry: input(&[("Title", "Banka"), ("Password", &format!("p{n}"))]),
            },
            2 + n,
        );
    }
    let history = view::history(&db, &db.entries[&eid(&id)]);
    assert_eq!(history.len(), 10);
    // The oldest went first.
    assert_eq!(history[9].fields[2].value, "p13");
}

#[test]
fn deleting_recycles_then_removes_for_good() {
    let mut db = vault();
    let id = add(&mut db, "Eski", 1);
    run(&mut db, Op::DeleteEntry { id: id.clone() }, 2);
    let v = view::view(&db);
    let bin = v.recycle_bin_id.clone().expect("a recycle bin was made");
    assert_eq!(entry(&v, &id).group_id, bin);
    assert!(entry(&v, &id).in_recycle_bin);
    assert!(v.groups.iter().any(|g| g.id == bin && g.is_recycle_bin));
    assert!(db.deleted_objects.is_empty());

    run(&mut db, Op::DeleteEntry { id: id.clone() }, 3);
    assert!(view::view(&db).entries.iter().all(|e| e.id != id));
    assert_eq!(
        db.deleted_objects.get(&uuid::Uuid::parse_str(&id).unwrap()),
        Some(&Some(at(3)))
    );
}

#[test]
fn groups_are_made_moved_and_deleted() {
    let mut db = vault();
    let root = view::view(&db).root_group_id;
    let work = run(
        &mut db,
        Op::CreateGroup {
            parent_id: root.clone(),
            name: "İş".into(),
        },
        1,
    )
    .id
    .unwrap();
    let inner = run(
        &mut db,
        Op::CreateGroup {
            parent_id: work.clone(),
            name: "Sunucular".into(),
        },
        2,
    )
    .id
    .unwrap();
    // A group cannot move into its own subgroup; the top group stays.
    assert!(apply(
        &mut db,
        &Op::MoveGroup {
            id: work.clone(),
            parent_id: inner.clone()
        },
        at(3)
    )
    .is_err());
    assert!(apply(&mut db, &Op::DeleteGroup { id: root.clone() }, at(3)).is_err());
    run(
        &mut db,
        Op::UpdateGroup {
            id: inner.clone(),
            name: "Servers".into(),
            notes: "prod".into(),
            icon: Some(30),
        },
        4,
    );
    let v = view::view(&db);
    let g = v.groups.iter().find(|g| g.id == inner).unwrap();
    assert_eq!(
        (g.name.as_str(), g.notes.as_str(), g.icon, g.depth),
        ("Servers", "prod", Some(30), 2)
    );

    // Deleted: into the recycle bin with what it holds; emptying the bin
    // removes it for good, every object recorded.
    let server = run(
        &mut db,
        Op::CreateEntry {
            group_id: inner.clone(),
            entry: input(&[("Title", "db1")]),
        },
        5,
    )
    .id
    .unwrap();
    run(&mut db, Op::DeleteGroup { id: work.clone() }, 6);
    let v = view::view(&db);
    assert!(
        v.groups
            .iter()
            .find(|g| g.id == work)
            .unwrap()
            .in_recycle_bin
    );
    assert!(entry(&v, &server).in_recycle_bin);
    run(&mut db, Op::EmptyRecycleBin, 7);
    let v = view::view(&db);
    assert!(v.groups.iter().all(|g| g.id != work && g.id != inner));
    for id in [&work, &inner, &server] {
        assert!(db
            .deleted_objects
            .contains_key(&uuid::Uuid::parse_str(id).unwrap()));
    }
}

#[test]
fn attachments_are_added_replaced_and_removed() {
    let mut db = vault();
    let id = add(&mut db, "Sertifika", 1);
    let b64 = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);
    run(
        &mut db,
        Op::AddAttachment {
            entry_id: id.clone(),
            name: "id_ed25519".into(),
            data: b64(b"secret key"),
        },
        2,
    );
    let e = &db.entries[&eid(&id)];
    assert_eq!(
        view::attachment(&db, e, "id_ed25519"),
        Some(&b"secret key"[..])
    );
    assert_eq!(entry(&view::view(&db), &id).attachments[0].size, 10);
    run(
        &mut db,
        Op::AddAttachment {
            entry_id: id.clone(),
            name: "id_ed25519".into(),
            data: b64(b"new key"),
        },
        3,
    );
    let e = &db.entries[&eid(&id)];
    assert_eq!(
        view::attachment(&db, e, "id_ed25519"),
        Some(&b"new key"[..])
    );
    // The old contents are kept for the history item that has them.
    assert_eq!(db.attachments.len(), 2);
    run(
        &mut db,
        Op::RemoveAttachment {
            entry_id: id.clone(),
            name: "id_ed25519".into(),
        },
        4,
    );
    assert!(entry(&view::view(&db), &id).attachments.is_empty());
    let key = VaultKey::new().with_password("p");
    let reopened = open(&save(&db, &key).unwrap(), &key).unwrap();
    assert_eq!(
        view::history(&reopened, &reopened.entries[&eid(&id)]).len(),
        3
    );
}

#[test]
fn an_earlier_state_can_be_restored() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    run(
        &mut db,
        Op::UpdateEntry {
            id: id.clone(),
            entry: input(&[("Title", "Banka"), ("Password", "wrong")]),
        },
        2,
    );
    run(
        &mut db,
        Op::RestoreHistory {
            id: id.clone(),
            index: 0,
        },
        3,
    );
    let v = view::view(&db);
    assert_eq!(value(&v, &id, "Password"), "p0");
    // Restoring is an edit too: what it replaced is in the history.
    assert_eq!(entry(&v, &id).history_count, 2);
    assert!(apply(&mut db, &Op::RestoreHistory { id, index: 9 }, at(4)).is_err());
}

#[test]
fn refused_edits_change_nothing() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    let before = db.clone();
    let root = view::view(&db).root_group_id;
    let refused = [
        Op::CreateEntry {
            group_id: root.clone(),
            entry: EntryInput {
                foreground_color: Some("red".into()),
                ..input(&[("Title", "x")])
            },
        },
        Op::CreateEntry {
            group_id: root.clone(),
            entry: input(&[("Title", "x"), ("PIN", "1"), ("PIN", "2")]),
        },
        Op::UpdateEntry {
            id: id.clone(),
            entry: EntryInput {
                icon: Some(500),
                ..input(&[("Title", "x")])
            },
        },
        Op::UpdateEntry {
            id: id.clone(),
            entry: EntryInput {
                expires: true,
                ..input(&[("Title", "x")])
            },
        },
        Op::CreateGroup {
            parent_id: root.clone(),
            name: "  ".into(),
        },
        Op::AddAttachment {
            entry_id: id.clone(),
            name: "a".into(),
            data: "not base64!".into(),
        },
        Op::DeleteEntry {
            id: "00000000-0000-4000-8000-000000000000".into(),
        },
    ];
    for op in refused {
        let error = apply(&mut db, &op, at(9)).unwrap_err();
        assert!(matches!(
            error,
            EditError::Invalid(_) | EditError::NotFound(_)
        ));
        assert_eq!(db, before, "{op:?} changed the vault");
    }
}

#[test]
fn review_marks_are_cleared() {
    let base = {
        let mut db = vault();
        add(&mut db, "Banka", 1);
        db
    };
    let id = base.entries.keys().next().unwrap().uuid().to_string();
    let edit = |password: &str, minute| {
        let mut db = base.clone();
        run(
            &mut db,
            Op::UpdateEntry {
                id: id.clone(),
                entry: input(&[("Title", "Banka"), ("Password", password)]),
            },
            minute,
        );
        db
    };
    let (mut merged, report) = merge(Some(&base), &edit("ours", 2), &edit("theirs", 3));
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(entry(&view::view(&merged), &id).review, ["Password"]);
    assert!(run(&mut merged, Op::ClearReview { id: id.clone() }, 4).changed);
    assert!(entry(&view::view(&merged), &id).review.is_empty());
}

#[test]
fn edits_from_two_copies_merge() {
    let mut base = vault();
    let kept = add(&mut base, "Banka", 1);
    let gone = add(&mut base, "Eski", 2);
    let mut ours = base.clone();
    let mut theirs = base.clone();
    run(
        &mut ours,
        Op::UpdateEntry {
            id: kept.clone(),
            entry: input(&[("Title", "Banka"), ("Password", "ours")]),
        },
        3,
    );
    let added = add(&mut ours, "Yeni", 4);
    run(&mut theirs, Op::DeleteEntry { id: gone.clone() }, 5);
    run(&mut theirs, Op::DeleteEntry { id: gone.clone() }, 6);
    let (merged, report) = merge(Some(&base), &ours, &theirs);
    assert!(report.is_clean(), "{report:?}");
    let v = view::view(&merged);
    assert_eq!(value(&v, &kept, "Password"), "ours");
    assert!(v.entries.iter().any(|e| e.id == added));
    assert!(v.entries.iter().all(|e| e.id != gone));
}

#[test]
fn operations_read_from_the_websites_json() {
    let op: Op = serde_json::from_str(
        r#"{"op":"updateEntry","id":"x","entry":{"fields":[{"key":"Title","value":"a","protected":false}],"tags":["iş"],"icon":3,"expires":false}}"#,
    )
    .unwrap();
    let Op::UpdateEntry { entry, .. } = op else {
        panic!("{op:?}");
    };
    assert_eq!(entry.tags, ["iş"]);
    assert!(entry.quality_check, "absent means on");
    let op: Op = serde_json::from_str(r#"{"op":"emptyRecycleBin"}"#).unwrap();
    assert_eq!(op, Op::EmptyRecycleBin);
}

#[test]
fn one_time_codes_follow_rfc_6238() {
    let mut db = vault();
    let root = view::view(&db).root_group_id;
    let id = run(
        &mut db,
        Op::CreateEntry {
            group_id: root,
            entry: input(&[
                ("Title", "2FA"),
                (
                    "otp",
                    "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30",
                ),
            ]),
        },
        1,
    )
    .id
    .unwrap();
    let code = view::otp(&db.entries[&eid(&id)], 59).unwrap();
    assert_eq!(code.code, "94287082");
    assert_eq!((code.period, code.remaining), (30, 1));
    let plain = add(&mut db, "none", 2);
    assert!(view::otp(&db.entries[&eid(&plain)], 59).is_none());
}

/// A 1×1 PNG, base64, with byte `n` after its end, so different `n` give
/// different pictures.
fn png(n: u8) -> String {
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
        .unwrap();
    bytes.push(n);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn entries_and_groups_take_their_own_pictures() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    let root = view::view(&db).root_group_id;
    assert!(
        run(
            &mut db,
            Op::SetEntryIcon {
                id: id.clone(),
                data: Some(png(1))
            },
            2
        )
        .changed
    );
    let v = view::view(&db);
    let icon = entry(&v, &id).custom_icon.clone().unwrap();
    assert!(entry(&v, &id).has_custom_icon);
    assert_eq!(v.custom_icons.len(), 1);
    assert_eq!(v.custom_icons[0].id, icon);
    assert_eq!(v.custom_icons[0].mime, "image/png");
    assert_eq!(v.custom_icons[0].data, png(1));
    // The previous state is in the history.
    assert_eq!(entry(&v, &id).history_count, 1);
    assert_eq!(
        view::history(&db, &db.entries[&eid(&id)])[0].custom_icon,
        None
    );
    // The same picture again changes nothing; a group with it shares it.
    assert!(
        !run(
            &mut db,
            Op::SetEntryIcon {
                id: id.clone(),
                data: Some(png(1))
            },
            3
        )
        .changed
    );
    assert!(
        run(
            &mut db,
            Op::SetGroupIcon {
                id: root.clone(),
                data: Some(png(1))
            },
            4
        )
        .changed
    );
    let v = view::view(&db);
    assert_eq!(v.custom_icons.len(), 1);
    assert_eq!(v.groups[0].custom_icon.as_deref(), Some(icon.as_str()));
    // A field edit keeps the picture.
    run(
        &mut db,
        Op::UpdateEntry {
            id: id.clone(),
            entry: input(&[("Title", "Banka"), ("Password", "p1")]),
        },
        5,
    );
    assert_eq!(
        entry(&view::view(&db), &id).custom_icon.as_deref(),
        Some(icon.as_str())
    );
    // None: the default icons again; the picture stays in the vault (as
    // KeePass apps keep it), still named by the history.
    assert!(
        run(
            &mut db,
            Op::SetEntryIcon {
                id: id.clone(),
                data: None
            },
            6
        )
        .changed
    );
    assert!(
        run(
            &mut db,
            Op::SetGroupIcon {
                id: root.clone(),
                data: None
            },
            7
        )
        .changed
    );
    let v = view::view(&db);
    assert_eq!(entry(&v, &id).custom_icon, None);
    assert_eq!(entry(&v, &id).icon, Some(0));
    assert_eq!(v.groups[0].icon, Some(48));
    assert_eq!(v.custom_icons.len(), 1);

    // KeePass apps read them back, and two copies merge.
    let key = VaultKey::new().with_password("parola");
    let reopened = open(&save(&db, &key).unwrap(), &key).unwrap();
    assert_eq!(view::view(&reopened).custom_icons, v.custom_icons);
    let mut ours = reopened.clone();
    let mut theirs = reopened.clone();
    run(
        &mut ours,
        Op::SetEntryIcon {
            id: id.clone(),
            data: Some(png(2)),
        },
        8,
    );
    let other = add(&mut theirs, "Okul", 9);
    run(
        &mut theirs,
        Op::SetEntryIcon {
            id: other.clone(),
            data: Some(png(3)),
        },
        10,
    );
    let (merged, report) = merge(Some(&reopened), &ours, &theirs);
    assert!(report.is_clean(), "{report:?}");
    let m = view::view(&merged);
    let data = |entry_id: &str| {
        let icon = entry(&m, entry_id).custom_icon.clone().unwrap();
        m.custom_icons
            .iter()
            .find(|i| i.id == icon)
            .unwrap()
            .data
            .clone()
    };
    assert_eq!(data(&id), png(2));
    assert_eq!(data(&other), png(3));
}

#[test]
fn pictures_are_pngs_of_bounded_size() {
    let mut db = vault();
    let id = add(&mut db, "Banka", 1);
    let refused = |db: &mut Database, data: String| {
        apply(
            db,
            &Op::SetEntryIcon {
                id: id.clone(),
                data: Some(data),
            },
            at(2),
        )
        .unwrap_err()
    };
    let before = db.clone();
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    assert!(matches!(
        refused(&mut db, "not base64!".into()),
        EditError::Invalid(_)
    ));
    assert!(matches!(
        refused(&mut db, b64(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>")),
        EditError::Invalid(_)
    ));
    assert!(matches!(
        refused(&mut db, b64(&[0xff, 0xd8, 0xff, 0xe0, 0, 0])),
        EditError::Invalid(_)
    ));
    let mut big = base64::engine::general_purpose::STANDARD
        .decode(png(0))
        .unwrap();
    big.resize(256 * 1024 + 1, 0);
    assert!(matches!(refused(&mut db, b64(&big)), EditError::Invalid(_)));
    assert_eq!(
        apply(
            &mut db,
            &Op::SetEntryIcon {
                id: "nope".into(),
                data: None
            },
            at(2)
        )
        .unwrap_err(),
        EditError::NotFound("entry")
    );
    assert_eq!(
        apply(
            &mut db,
            &Op::SetGroupIcon {
                id: "nope".into(),
                data: None
            },
            at(2)
        )
        .unwrap_err(),
        EditError::NotFound("group")
    );
    assert_eq!(view::view(&db), view::view(&before));
    let op: Op = serde_json::from_str(&format!(
        r#"{{"op":"setEntryIcon","id":"{id}","data":"{}"}}"#,
        png(1)
    ))
    .unwrap();
    assert!(matches!(op, Op::SetEntryIcon { data: Some(_), .. }));
    let op: Op = serde_json::from_str(r#"{"op":"setGroupIcon","id":"g"}"#).unwrap();
    assert_eq!(
        op,
        Op::SetGroupIcon {
            id: "g".into(),
            data: None
        }
    );
}

fn group(db: &mut Database, parent: &str, name: &str, minute: u32) -> String {
    run(
        db,
        Op::CreateGroup {
            parent_id: parent.into(),
            name: name.into(),
        },
        minute,
    )
    .id
    .unwrap()
}

fn shown(db: &Database) -> serde_json::Value {
    serde_json::to_value(view::view(db)).unwrap()
}

#[test]
fn several_entries_move_together_and_a_bad_one_moves_none() {
    let mut db = vault();
    let root = view::view(&db).root_group_id;
    let work = group(&mut db, &root, "İş", 1);
    let (a, b, c) = (
        add(&mut db, "a", 2),
        add(&mut db, "b", 3),
        add(&mut db, "c", 4),
    );

    // One unknown id, or the recycle bin as the target: nothing changes.
    let before = shown(&db);
    let missing = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        apply(
            &mut db,
            &Op::MoveEntries {
                ids: vec![a.clone(), missing],
                group_id: work.clone()
            },
            at(5)
        ),
        Err(EditError::NotFound("entry"))
    ));
    run(&mut db, Op::DeleteEntry { id: c.clone() }, 5);
    let bin = view::view(&db).recycle_bin_id.unwrap();
    let before_bin = shown(&db);
    assert!(apply(
        &mut db,
        &Op::MoveEntries {
            ids: vec![a.clone()],
            group_id: bin
        },
        at(6)
    )
    .is_err());
    assert_eq!(shown(&db), before_bin);
    assert_ne!(before, before_bin, "only the delete changed it");

    // Moved, a repeated id counted once; already there changes nothing.
    let moved = run(
        &mut db,
        Op::MoveEntries {
            ids: vec![a.clone(), b.clone(), a.clone()],
            group_id: work.clone(),
        },
        7,
    );
    assert!(moved.changed);
    let v = view::view(&db);
    assert_eq!(entry(&v, &a).group_id, work);
    assert_eq!(entry(&v, &b).group_id, work);
    let again = run(
        &mut db,
        Op::MoveEntries {
            ids: vec![a.clone(), b.clone()],
            group_id: work.clone(),
        },
        8,
    );
    assert!(!again.changed);
}

#[test]
fn several_entries_are_deleted_and_restored_to_where_they_were() {
    let mut db = vault();
    let root = view::view(&db).root_group_id;
    let work = group(&mut db, &root, "İş", 1);
    let home = group(&mut db, &root, "Ev", 2);
    let (a, b, c) = (
        add(&mut db, "a", 3),
        add(&mut db, "b", 4),
        add(&mut db, "c", 5),
    );
    run(
        &mut db,
        Op::MoveEntries {
            ids: vec![a.clone()],
            group_id: work.clone(),
        },
        6,
    );
    run(
        &mut db,
        Op::MoveEntries {
            ids: vec![b.clone()],
            group_id: home.clone(),
        },
        7,
    );

    // Restoring one not in the bin refuses them all.
    assert!(apply(
        &mut db,
        &Op::RestoreEntries {
            ids: vec![a.clone()]
        },
        at(8)
    )
    .is_err());

    run(
        &mut db,
        Op::DeleteEntries {
            ids: vec![a.clone(), b.clone(), c.clone()],
        },
        8,
    );
    let v = view::view(&db);
    assert!([&a, &b, &c].iter().all(|id| entry(&v, id).in_recycle_bin));

    // Its group gone meanwhile: back to the top group instead.
    run(&mut db, Op::DeleteGroup { id: home.clone() }, 9);
    run(
        &mut db,
        Op::RestoreEntries {
            ids: vec![a.clone(), b.clone(), c.clone()],
        },
        10,
    );
    let v = view::view(&db);
    assert_eq!(entry(&v, &a).group_id, work, "back where it was");
    assert_eq!(entry(&v, &b).group_id, root, "its group is in the bin");
    assert_eq!(entry(&v, &c).group_id, root, "it was at the top");
    assert!(!entry(&v, &a).in_recycle_bin);

    // From inside the bin, deleted for good; a mix goes each its own way.
    run(
        &mut db,
        Op::DeleteEntries {
            ids: vec![a.clone()],
        },
        11,
    );
    run(
        &mut db,
        Op::DeleteEntries {
            ids: vec![a.clone(), c.clone()],
        },
        12,
    );
    let v = view::view(&db);
    assert!(v.entries.iter().all(|e| e.id != a), "for good from the bin");
    assert!(entry(&v, &c).in_recycle_bin, "into the bin");
    assert!(db.deleted_objects.contains_key(&eid(&a).uuid()));
}

#[test]
fn batch_operations_read_from_the_websites_json() {
    let op: Op =
        serde_json::from_str(r#"{"op":"moveEntries","ids":["a","b"],"groupId":"g"}"#).unwrap();
    assert_eq!(
        op,
        Op::MoveEntries {
            ids: vec!["a".into(), "b".into()],
            group_id: "g".into()
        }
    );
    let op: Op = serde_json::from_str(r#"{"op":"restoreEntries","ids":["a"]}"#).unwrap();
    assert_eq!(
        op,
        Op::RestoreEntries {
            ids: vec!["a".into()]
        }
    );
}
