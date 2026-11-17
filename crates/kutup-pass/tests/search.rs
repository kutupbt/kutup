//! Searching entries as KeePassXC does (docs/plans/pass-gaps-2.md P3).

use std::collections::HashSet;

use chrono::{NaiveDate, NaiveDateTime};
use kutup_pass::edit::{apply, new_vault, EntryInput, Op};
use kutup_pass::keepass::db::EntryId;
use kutup_pass::keepass::Database;
use kutup_pass::search::{parse, search, Context, Field};
use kutup_pass::view::{self, FieldView};

fn at(day: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 11, day)
        .unwrap()
        .and_hms_opt(9, 0, 0)
        .unwrap()
}

fn field(key: &str, value: &str, protected: bool) -> FieldView {
    FieldView {
        key: key.into(),
        value: value.into(),
        protected,
    }
}

struct Vault {
    db: Database,
    ids: Vec<String>,
}

fn add(
    db: &mut Database,
    group: &str,
    fields: Vec<FieldView>,
    tags: &[&str],
    expiry: Option<&str>,
) -> String {
    apply(
        db,
        &Op::CreateEntry {
            group_id: group.into(),
            entry: EntryInput {
                fields,
                tags: tags.iter().map(|t| (*t).into()).collect(),
                expires: expiry.is_some(),
                expiry: expiry.map(Into::into),
                ..EntryInput::default()
            },
        },
        at(1),
    )
    .unwrap()
    .id
    .unwrap()
}

/// Bank (tags finans, in İş/Sunucular), Mail, a server with an attachment
/// and a protected custom field, an expiring one and one with a TOTP.
fn vault() -> Vault {
    let mut db = new_vault("Kişisel", at(1)).unwrap();
    let root = view::view(&db).root_group_id;
    let work = apply(
        &mut db,
        &Op::CreateGroup {
            parent_id: root.clone(),
            name: "İş".into(),
        },
        at(1),
    )
    .unwrap()
    .id
    .unwrap();
    let servers = apply(
        &mut db,
        &Op::CreateGroup {
            parent_id: work,
            name: "Sunucular".into(),
        },
        at(1),
    )
    .unwrap()
    .id
    .unwrap();
    let bank = add(
        &mut db,
        &root,
        vec![
            field("Title", "Ziraat Bankası", false),
            field("UserName", "ayşe", false),
            field("Password", "Gizli123", true),
            field("URL", "https://www.ziraatbank.com.tr", false),
            field("Müşteri no", "445566", false),
        ],
        &["finans", "Banka"],
        None,
    );
    let mail = add(
        &mut db,
        &root,
        vec![
            field("Title", "Posta", false),
            field("UserName", "ayse@kutup.dev", false),
            field("Password", "posta-parola", true),
            field("Notes", "İstanbul ofisi", false),
        ],
        &[],
        None,
    );
    let server = add(
        &mut db,
        &servers,
        vec![
            field("Title", "db1", false),
            field("UserName", "root", false),
            field("API anahtarı", "s3cr3t", true),
        ],
        &["iş"],
        None,
    );
    apply(
        &mut db,
        &Op::AddAttachment {
            entry_id: server.clone(),
            name: "id_ed25519.pub".into(),
            data: "AAAA".into(),
        },
        at(1),
    )
    .unwrap();
    let soon = add(
        &mut db,
        &root,
        vec![
            field("Title", "Eski VPN", false),
            field("Password", "x", true),
        ],
        &[],
        Some("2026-11-05T09:00:00"),
    );
    let totp = add(
        &mut db,
        &root,
        vec![
            field("Title", "GitHub", false),
            field(
                "otp",
                "otpauth://totp/GitHub:ayse?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                true,
            ),
        ],
        &[],
        None,
    );
    Vault {
        db,
        ids: vec![bank, mail, server, soon, totp],
    }
}

fn found(v: &Vault, query: &str, weak: &[usize], day: u32) -> Vec<usize> {
    let weak: HashSet<EntryId> = weak
        .iter()
        .map(|i| EntryId::from(uuid::Uuid::parse_str(&v.ids[*i]).unwrap()))
        .collect();
    let context = Context {
        weak: &weak,
        now: at(day),
    };
    let ids = search(&v.db, query, &context);
    let mut out: Vec<usize> = ids
        .iter()
        .map(|id| v.ids.iter().position(|x| x == id).unwrap())
        .collect();
    out.sort_unstable();
    out
}

const BANK: usize = 0;
const MAIL: usize = 1;
const SERVER: usize = 2;
const SOON: usize = 3;
const TOTP: usize = 4;

#[test]
fn plain_words_look_in_the_open_fields_folded() {
    let v = vault();
    assert_eq!(found(&v, "", &[], 1), vec![BANK, MAIL, SERVER, SOON, TOTP]);
    // Turkish I's, accents and case fold away; every word must match.
    assert_eq!(found(&v, "ISTANBUL", &[], 1), vec![MAIL]);
    assert_eq!(found(&v, "ayse", &[], 1), vec![BANK, MAIL]);
    assert_eq!(found(&v, "ayse kutup", &[], 1), vec![MAIL]);
    // Tags and unprotected custom fields; never the password or a protected field.
    assert_eq!(found(&v, "finans", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "445566", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "gizli123", &[], 1), Vec::<usize>::new());
    assert_eq!(found(&v, "s3cr3t", &[], 1), Vec::<usize>::new());
    // A colon that names no field is part of the word.
    assert_eq!(found(&v, "https://www.ziraat", &[], 1), vec![BANK]);
}

#[test]
fn fields_negation_quotes_and_wildcards() {
    let v = vault();
    assert_eq!(found(&v, "title:posta", &[], 1), vec![MAIL]);
    assert_eq!(found(&v, "t:posta", &[], 1), vec![MAIL]);
    assert_eq!(found(&v, "u:root", &[], 1), vec![SERVER]);
    assert_eq!(found(&v, "user:ayse", &[], 1), vec![BANK, MAIL]);
    assert_eq!(found(&v, "password:gizli", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "url:ziraatbank", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "notes:ofis", &[], 1), vec![MAIL]);
    assert_eq!(found(&v, "attr:anahtar", &[], 1), vec![SERVER]);
    assert_eq!(found(&v, "attr:s3cr3t", &[], 1), Vec::<usize>::new());
    assert_eq!(found(&v, "attachment:ed25519", &[], 1), vec![SERVER]);
    // Any group above the entry; the vault's top group isn't one.
    assert_eq!(found(&v, "group:is", &[], 1), vec![SERVER]);
    assert_eq!(found(&v, "g:sunucu", &[], 1), vec![SERVER]);
    assert_eq!(found(&v, "group:kisisel", &[], 1), Vec::<usize>::new());
    assert_eq!(found(&v, "tag:banka", &[], 1), vec![BANK]);
    let uuid = v.ids[MAIL].clone();
    assert_eq!(found(&v, &format!("uuid:{uuid}"), &[], 1), vec![MAIL]);
    // Negation, quotes, wildcards.
    assert_eq!(found(&v, "ayse -posta", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "-tag:iş", &[], 1), vec![BANK, MAIL, SOON, TOTP]);
    assert_eq!(found(&v, "\"ziraat bankasi\"", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "ziraat bankasi", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "\"bankasi ziraat\"", &[], 1), Vec::<usize>::new());
    assert_eq!(found(&v, "url:https://*.com.tr", &[], 1), vec![BANK]);
    assert_eq!(found(&v, "t:z*bank", &[], 1), vec![BANK]);
    // Words that ask for nothing are dropped.
    assert_eq!(
        found(&v, "- title: *", &[], 1),
        vec![BANK, MAIL, SERVER, SOON, TOTP]
    );
}

#[test]
fn states_expired_weak_and_totp() {
    let v = vault();
    assert_eq!(found(&v, "is:expired", &[], 1), Vec::<usize>::new());
    assert_eq!(found(&v, "is:expired-7", &[], 1), vec![SOON]);
    assert_eq!(found(&v, "is:expired", &[], 6), vec![SOON]);
    // Weak as the caller counts it, never one without a password.
    assert_eq!(found(&v, "is:weak", &[MAIL, SERVER], 1), vec![MAIL]);
    assert_eq!(found(&v, "has:totp", &[], 1), vec![TOTP]);
    assert_eq!(
        found(&v, "-has:totp", &[], 1),
        vec![BANK, MAIL, SERVER, SOON]
    );
    assert_eq!(found(&v, "is:nothing", &[], 1), Vec::<usize>::new());
}

#[test]
fn a_query_parses_into_terms() {
    let terms = parse("  -Title:\"Ziraat Bankası\"  url:x  rest ");
    assert_eq!(terms.len(), 3);
    assert_eq!(terms[0].field, Field::Title);
    assert_eq!(terms[0].pattern, "ziraat bankasi");
    assert!(terms[0].negated);
    assert_eq!(terms[2].field, Field::Default);
}
