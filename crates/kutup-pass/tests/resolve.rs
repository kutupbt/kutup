//! References and placeholders, KeePassXC's own cases (tests/TestEntry.cpp:
//! testResolveReferencePlaceholders, testResolveRecursivePlaceholders,
//! testResolveUrlPlaceholders, testResolveUuidPlaceholder).

use chrono::NaiveDate;
use kutup_pass::keepass::db::{EntryId, GroupId, Value};
use kutup_pass::keepass::Database;
use kutup_pass::resolve::{resolve, Context};

fn context() -> Context {
    let t = NaiveDate::from_ymd_opt(2026, 11, 17)
        .unwrap()
        .and_hms_opt(9, 5, 7)
        .unwrap();
    Context {
        local: t + chrono::Duration::hours(3),
        utc: t,
        unix_seconds: 59,
    }
}

fn add(db: &mut Database, group: GroupId, fields: &[(&str, &str)]) -> EntryId {
    let id = db.group_mut(group).unwrap().add_entry().id();
    let entry = db.entries.get_mut(&id).unwrap();
    for (k, v) in fields {
        entry
            .fields
            .insert((*k).into(), Value::unprotected((*v).to_string()));
    }
    id
}

fn hex(id: EntryId) -> String {
    id.uuid().simple().to_string()
}

fn r(db: &Database, id: EntryId, value: &str) -> String {
    resolve(db, &db.entries[&id], value, &context())
}

fn std_fields<'a>(n: &str, out: &'a mut Vec<(String, String)>) -> Vec<(&'a str, &'a str)> {
    *out = ["Title", "UserName", "Password", "URL", "Notes"]
        .iter()
        .map(|k| {
            (
                k.to_string(),
                format!("{}{n}", if *k == "URL" { "Url" } else { k }),
            )
        })
        .collect();
    out.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[test]
fn references_find_by_every_field() {
    let mut db = Database::new();
    let root = db.root;
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let mut f1 = std_fields("1", &mut a);
    f1.push(("CustomAttribute1", "CustomAttributeValue1"));
    let e1 = add(&mut db, root, &f1);
    let group = db.group_mut(root).unwrap().add_group().id();
    let mut f2 = std_fields("2", &mut b);
    f2.push(("CustomAttribute2", "CustomAttributeValue2"));
    let e2 = add(&mut db, group, &f2);
    let e3 = add(
        &mut db,
        group,
        &[
            ("Title", "{S:AttributeTitle}"),
            ("UserName", "{S:AttributeUsername}"),
            ("Password", "{S:AttributePassword}"),
            ("URL", "{S:AttributeUrl}"),
            ("Notes", "{S:AttributeNotes}"),
            ("AttributeTitle", "TitleValue"),
            ("AttributeUsername", "UsernameValue"),
            ("AttributePassword", "PasswordValue"),
            ("AttributeUrl", "UrlValue"),
            ("AttributeNotes", "NotesValue"),
        ],
    );
    let t = add(&mut db, root, &[]);
    for (n, e) in [("1", e1), ("2", e2)] {
        let title = format!("Title{n}");
        for search in [
            format!("{{REF:T@I:{}}}", hex(e)),
            format!("{{REF:T@T:Title{n}}}"),
            format!("{{REF:T@U:UserName{n}}}"),
            format!("{{REF:T@P:Password{n}}}"),
            format!("{{REF:T@A:Url{n}}}"),
            format!("{{REF:T@N:Notes{n}}}"),
            format!("{{REF:T@O:CustomAttributeValue{n}}}"),
        ] {
            assert_eq!(r(&db, t, &search), title, "{search}");
        }
        assert_eq!(
            r(&db, t, &format!("{{REF:U@U:UserName{n}}}")),
            format!("UserName{n}")
        );
        assert_eq!(
            r(&db, t, &format!("{{REF:P@P:Password{n}}}")),
            format!("Password{n}")
        );
        assert_eq!(r(&db, t, &format!("{{REF:A@A:Url{n}}}")), format!("Url{n}"));
        assert_eq!(
            r(&db, t, &format!("{{REF:N@N:Notes{n}}}")),
            format!("Notes{n}")
        );
    }
    // Referenced fields resolve in their own entry; any case of the id and letters.
    for (field, want) in [
        ("T", "TitleValue"),
        ("U", "UsernameValue"),
        ("P", "PasswordValue"),
        ("A", "UrlValue"),
        ("N", "NotesValue"),
    ] {
        assert_eq!(r(&db, t, &format!("{{REF:{field}@I:{}}}", hex(e3))), want);
        assert_eq!(
            r(
                &db,
                t,
                &format!("{{REF:{field}@I:{}}}", hex(e3).to_uppercase())
            ),
            want
        );
        assert_eq!(
            r(
                &db,
                t,
                &format!("{{REF:{}@i:{}}}", field.to_lowercase(), hex(e3))
            ),
            want
        );
    }
    // No entry matches: nothing, as KeePassXC.
    assert_eq!(r(&db, t, "x{REF:T@T:nobody}y"), "xy");
}

#[test]
fn placeholders_resolve_recursively() {
    let mut db = Database::new();
    let root = db.root;
    let e1 = add(
        &mut db,
        root,
        &[
            ("Title", "{USERNAME}"),
            ("UserName", "{PASSWORD}"),
            ("Password", "{URL}"),
            ("URL", "{S:CustomTitle}"),
            ("CustomTitle", "RecursiveValue"),
        ],
    );
    assert_eq!(r(&db, e1, "{USERNAME}"), "RecursiveValue");
    let p2 = format!("{{REF:P@I:{}}}", hex(e1));
    let e2 = add(
        &mut db,
        root,
        &[
            ("Title", "Entry2Title"),
            ("UserName", "{S:CustomUserNameAttribute}"),
            ("Password", &p2),
            ("URL", "http://{S:IpAddress}:{S:Port}/{S:Uri}"),
            ("CustomUserNameAttribute", "CustomUserNameValue"),
            ("IpAddress", "127.0.0.1"),
            ("Port", "1234"),
            ("Uri", "uri/path"),
        ],
    );
    let refs = |id: EntryId| {
        ["T", "U", "P", "A"]
            .iter()
            .map(|f| format!("{{REF:{f}@I:{}}}", hex(id)))
            .collect::<Vec<_>>()
    };
    let r2 = refs(e2);
    let e3 = add(
        &mut db,
        root,
        &[
            ("Title", &r2[0]),
            ("UserName", &r2[1]),
            ("Password", &r2[2]),
            ("URL", &r2[3]),
        ],
    );
    let r3 = refs(e3);
    let e4 = add(
        &mut db,
        root,
        &[
            ("Title", &r3[0]),
            ("UserName", &r3[1]),
            ("Password", &r3[2]),
            ("URL", &r3[3]),
        ],
    );
    for (e, refs) in [(e3, &r2), (e4, &r3)] {
        assert_eq!(r(&db, e, &refs[0]), "Entry2Title");
        assert_eq!(r(&db, e, &refs[1]), "CustomUserNameValue");
        assert_eq!(r(&db, e, &refs[2]), "RecursiveValue");
        assert_eq!(r(&db, e, &refs[3]), "http://127.0.0.1:1234/uri/path");
    }
    let e5 = add(
        &mut db,
        root,
        &[
            ("Scheme", "http"),
            ("Host", "host.org"),
            ("Port", "2017"),
            ("Path", "/some/path"),
            ("UserName", "username"),
            ("Password", "password"),
            ("Query", "q=e&t=s"),
            ("Fragment", "fragment"),
            ("URL", "{S:Scheme}://{S:UserName}:{S:Password}@{S:Host}:{S:Port}{S:Path}?{S:Query}#{S:Fragment}"),
        ],
    );
    assert_eq!(
        r(&db, e5, "{URL}"),
        "http://username:password@host.org:2017/some/path?q=e&t=s#fragment"
    );
    assert_eq!(
        r(&db, e5, "title+{URL:Path}+{URL:Fragment}+title"),
        "title+/some/path+fragment+title"
    );
    let e6 = add(
        &mut db,
        root,
        &[("Title", &r3[0]), ("Password", "{PASSWORD}")],
    );
    assert_eq!(r(&db, e6, "{TITLE}"), "Entry2Title");
    // Itself, again and again: given up after ten levels, as written.
    assert_eq!(r(&db, e6, "{PASSWORD}"), "{PASSWORD}");
    let e7 = add(
        &mut db,
        root,
        &[("Title", &format!("{} and something else", r3[0]))],
    );
    assert_eq!(r(&db, e7, "{TITLE}"), "Entry2Title and something else");
    assert_eq!(r(&db, e7, "{lots} {of} {braces}"), "{lots} {of} {braces}");
    assert_eq!(r(&db, e7, "\\{TITLE\\}"), "{TITLE}");
}

#[test]
fn url_parts_dates_conversions_and_the_uuid() {
    let mut db = Database::new();
    let root = db.root;
    let e = add(
        &mut db,
        root,
        &[
            (
                "URL",
                "https://user:pw@keepassxc.org:80/path/example.php?q=e&s=t+2#fragment",
            ),
            ("Notes", "Test with UUID: {UUID}"),
        ],
    );
    for (part, want) in [
        (
            "RMVSCM",
            "//user:pw@keepassxc.org:80/path/example.php?q=e&s=t+2#fragment",
        ),
        (
            "WITHOUTSCHEME",
            "//user:pw@keepassxc.org:80/path/example.php?q=e&s=t+2#fragment",
        ),
        ("SCM", "https"),
        ("SCHEME", "https"),
        ("HOST", "keepassxc.org"),
        ("PORT", "80"),
        ("PATH", "/path/example.php"),
        ("QUERY", "q=e&s=t+2"),
        ("USERINFO", "user:pw"),
        ("USERNAME", "user"),
        ("PASSWORD", "pw"),
        ("FRAGMENT", "fragment"),
    ] {
        assert_eq!(r(&db, e, &format!("{{URL:{part}}}")), want, "{part}");
    }
    let uuid = hex(e);
    assert_eq!(r(&db, e, "{NOTES}"), format!("Test with UUID: {uuid}"));
    for p in ["{UUID}", "{uuid}", "{Uuid}"] {
        assert_eq!(r(&db, e, p), uuid);
    }
    let self_ref = add(
        &mut db,
        root,
        &[("UserName", "me"), ("SelfReference", "{REF:U@I:{UUID}}")],
    );
    assert_eq!(r(&db, self_ref, "{S:SelfReference}"), "me");
    assert_eq!(r(&db, e, "{DT_SIMPLE}"), "20261117120507");
    assert_eq!(r(&db, e, "{DT_UTC_YEAR}-{DT_UTC_HOUR}"), "2026-09");
    assert_eq!(r(&db, e, "{T-CONV:/ab c/upper/}"), "AB C");
    assert_eq!(r(&db, e, "{T-CONV:/ab c/base64/}"), "YWIgYw==");
    assert_eq!(r(&db, e, "{T-CONV:/ab c/uri/}"), "ab%20c");
    // Auto-type keys and unknown ones stay.
    assert_eq!(r(&db, e, "{TAB}{ENTER}{CMD:x}"), "{TAB}{ENTER}{CMD:x}");
}
