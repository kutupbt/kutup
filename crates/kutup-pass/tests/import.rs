//! Importing other password managers' CSV exports (docs/plans/pass.md,
//! "Import"). The samples follow each app's export header.

use base64::Engine as _;
use chrono::NaiveDate;
use kutup_pass::edit::{apply, new_vault, Op};
use kutup_pass::import::{normalize_otp, parse, ImportError, ImportedEntry, Provider};
use kutup_pass::view;

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn only(csv: &str) -> (Provider, Vec<ImportedEntry>, Vec<String>, Vec<String>) {
    let parsed = parse(csv.as_bytes(), None).unwrap();
    (
        parsed.provider,
        parsed.entries,
        parsed.skipped,
        parsed.warnings,
    )
}

fn field<'a>(entry: &'a ImportedEntry, key: &str) -> Option<&'a str> {
    entry
        .fields
        .iter()
        .find(|f| f.key == key)
        .map(|f| f.value.as_str())
}

#[test]
fn keepassxc_with_groups_from_its_root_and_iso_times() {
    let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
        \"Root/Banks\",\"Bank\",\"ayse\",\"p1\",\"https://bank.example\",\"line one\nline two\",\"otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ\",\"0\",\"2025-05-01T10:00:00Z\",\"2024-01-02T03:04:05Z\"\n\
        \"Root\",\"Mail\",\"a@example.com\",\"p2\",\"\",\"\",\"\",\"0\",\"\",\"\"\n";
    let (provider, entries, _, _) = only(csv);
    assert_eq!(provider, Provider::KeePassXc);
    assert_eq!(entries[0].group, ["Banks"], "the shared root is dropped");
    assert!(entries[1].group.is_empty());
    assert_eq!(entries[0].notes, "line one\nline two");
    assert!(entries[0].otp.as_deref().unwrap().starts_with("otpauth://"));
    assert_eq!(
        entries[0].created,
        NaiveDate::from_ymd_opt(2024, 1, 2)
            .unwrap()
            .and_hms_opt(3, 4, 5)
    );
}

#[test]
fn bitwarden_logins_notes_fields_and_folders() {
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
        Work\\Servers,1,login,Server,,\"PIN: 1234\nRegion: eu\",0,\"https://a.example,https://b.example\",root,pw,JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n\
        ,0,note,Recovery codes,\"aaaa\nbbbb\",,0,,,,\n\
        ,0,card,Visa,,,0,,,,\n";
    let (provider, entries, skipped, _) = only(csv);
    assert_eq!(provider, Provider::Bitwarden);
    let server = &entries[0];
    assert_eq!(server.group, ["Work", "Servers"]);
    assert_eq!(server.urls, ["https://a.example", "https://b.example"]);
    assert_eq!(server.tags, ["Favorite"]);
    assert_eq!(field(server, "PIN"), Some("1234"));
    assert!(
        server
            .fields
            .iter()
            .find(|f| f.key == "PIN")
            .unwrap()
            .protected
    );
    assert!(server.otp.is_some());
    assert_eq!(entries[1].notes, "aaaa\nbbbb");
    assert_eq!(skipped, ["card: Visa"]);
}

#[test]
fn chrome_firefox_safari_and_onepassword() {
    let (p, e, _, _) =
        only("name,url,username,password,note\nGitHub,https://github.com/login,ayse,gh,\n");
    assert_eq!((p, e[0].title.as_str()), (Provider::Chrome, "GitHub"));

    let (p, e, _, _) = only("\u{feff}url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nhttps://www.mozilla.org,ayse,fx,,https://www.mozilla.org,{x},1700000000000,1700000000000,1710000000000\nchrome://FirefoxAccounts,,,,,,,,\n");
    assert_eq!(p, Provider::Firefox);
    assert_eq!(e.len(), 1, "Firefox's own account row is not an entry");
    assert_eq!(e[0].title, "mozilla.org", "no title: the host name");
    assert_eq!(e[0].modified.unwrap().and_utc().timestamp(), 1_710_000_000);

    let (p, e, _, _) = only(&format!("Title,URL,Username,Password,Notes,OTPAuth\nApple,https://apple.com,ayse,ap,,otpauth://totp/Apple?secret={SECRET}\n"));
    assert_eq!(p, Provider::Safari);
    assert!(e[0].otp.is_some());

    let (p, e, _, _) = only("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes,Recovery email\nDropbox,https://dropbox.com,ayse,db,,true,false,\"cloud,work\",note,r@example.com\n");
    assert_eq!(p, Provider::OnePassword);
    assert_eq!(e[0].tags, ["cloud", "work", "Favorite"]);
    assert_eq!(field(&e[0], "Recovery email"), Some("r@example.com"));
}

#[test]
fn lastpass_secure_notes_and_groups() {
    let csv = "url,username,password,totp,extra,name,grouping,fav\n\
        https://example.com,ayse,lp,,,Example,Social\\Friends,1\n\
        http://sn,,,,\"NoteType:Credit Card\nNumber:4111\",Visa,Cards,0\n";
    let (provider, entries, _, _) = only(csv);
    assert_eq!(provider, Provider::LastPass);
    assert_eq!(entries[0].group, ["Social", "Friends"]);
    assert_eq!(entries[1].notes, "NoteType:Credit Card\nNumber:4111");
    assert!(entries[1].password.is_empty());
}

#[test]
fn proton_nordpass_and_dashlane() {
    let csv = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
        login,Proton,\"https://a.example, https://b.example\",ayse@proton.me,,pp,,,1700000000,1700000100,Personal\n\
        alias,Alias,,x@alias.me,,,,,,,Personal\n\
        creditCard,Visa,,,,,\"{\"\"cardholderName\"\":\"\"Ayşe\"\",\"\"number\"\":\"\"4111\"\"}\",,,,Personal\n";
    let (provider, entries, skipped, _) = only(csv);
    assert_eq!(provider, Provider::ProtonPass);
    assert_eq!(entries[0].username, "ayse@proton.me");
    assert_eq!(entries[0].urls.len(), 2);
    assert_eq!(entries[0].group, ["Personal"]);
    assert_eq!(skipped.len(), 1);
    assert_eq!(field(&entries[1], "number"), Some("4111"));
    assert!(
        entries[1]
            .fields
            .iter()
            .find(|f| f.key == "number")
            .unwrap()
            .protected
    );

    let csv = "name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\n\
        Work,,,,,,,,,,,,,,,,,,,,folder,\n\
        Site,https://s.example,\"[\"\"https://t.example\"\"]\",ayse,np,,,,,,,Work,,,,,,,,,password,\"[{\"\"label\"\":\"\"PIN\"\",\"\"type\"\":\"\"hidden\"\",\"\"value\"\":\"\"9\"\"}]\"\n\
        Card,,,,,,Ayşe,4111,123,01/30,,Work,,,,,,,,,credit_card,\n";
    let (provider, entries, _, _) = only(csv);
    assert_eq!(provider, Provider::NordPass);
    assert_eq!(entries.len(), 2, "the folder row is no entry");
    assert_eq!(entries[0].urls, ["https://s.example", "https://t.example"]);
    assert!(entries[0]
        .fields
        .iter()
        .any(|f| f.key == "PIN" && f.protected));
    assert!(entries[1]
        .fields
        .iter()
        .any(|f| f.key == "Card number" && f.protected));

    let csv = "username,username2,username3,title,password,note,url,category,otpSecret\nayse,alt,,Shop,ds,,https://shop.example,Shopping,\n";
    let (provider, entries, _, _) = only(csv);
    assert_eq!(provider, Provider::Dashlane);
    assert_eq!(field(&entries[0], "Other user name"), Some("alt"));
}

#[test]
fn generic_csv_semicolons_and_kept_columns() {
    let csv =
        "Account;Login;Password;Website;PIN code;Comments\nForum;ayse;fp;forum.example;1234;hi\n";
    let (provider, entries, _, _) = only(csv);
    assert_eq!(provider, Provider::Generic);
    let e = &entries[0];
    assert_eq!(
        (e.title.as_str(), e.username.as_str(), e.password.as_str()),
        ("Forum", "ayse", "fp")
    );
    assert_eq!(e.urls, ["forum.example"]);
    assert_eq!(e.notes, "hi");
    assert!(e.fields.iter().any(|f| f.key == "PIN code" && f.protected));
}

#[test]
fn one_time_codes_in_every_form_and_unreadable_ones_kept() {
    assert!(
        normalize_otp(&format!("otpauth://totp/x?secret={SECRET}"), "x")
            .unwrap()
            .starts_with("otpauth://totp/x")
    );
    assert_eq!(
        normalize_otp("gezd gnbv gy3t qojq", "Banka Ş").unwrap(),
        "otpauth://totp/Banka%20%C5%9E?secret=GEZDGNBVGY3TQOJQ&period=30&digits=6&algorithm=SHA1"
    );
    assert!(normalize_otp(&format!("key={SECRET}&size=8&step=60"), "x")
        .unwrap()
        .contains("digits=8"));
    assert_eq!(normalize_otp("not a secret", "x"), None);
    let (_, entries, _, warnings) =
        only("name,url,username,password,note,totp\nX,,u,p,,not a secret\n");
    assert_eq!(entries[0].otp, None);
    assert_eq!(field(&entries[0], "TOTP"), Some("not a secret"));
    assert_eq!(warnings.len(), 1);
}

#[test]
fn errors_say_why() {
    assert_eq!(parse(b"", None), Err(ImportError::Empty));
    assert_eq!(
        parse(b"a,b,c\n1,2,3\n", None),
        Err(ImportError::UnknownFormat)
    );
    assert_eq!(
        parse(b"name,url,username,password\n", None),
        Err(ImportError::Empty)
    );
    assert!(matches!(
        parse(
            b"name,url,username,password\nA,,u,p\n",
            Some(Provider::Bitwarden)
        ),
        Err(ImportError::MissingColumns(_, _))
    ));
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(
            "name,url,username,password\nA,,u,p\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    assert_eq!(parse(&utf16, None).unwrap().entries.len(), 1);
    assert!(matches!(
        parse(&[0xC3, 0x28, b',', b'\n'], None),
        Err(ImportError::Unreadable(_))
    ));
}

#[test]
fn an_import_lands_in_its_own_group_and_all_or_nothing() {
    let now = NaiveDate::from_ymd_opt(2026, 10, 12)
        .unwrap()
        .and_hms_opt(9, 0, 0)
        .unwrap();
    let mut db = new_vault("Kasa", now).unwrap();
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
        Work/Servers,0,login,Server,,\"Password: dup\",0,\"https://a.example,https://b.example\",root,pw,\n\
        ,0,login,Plain,,,0,,u,p,\n";
    let data = base64::engine::general_purpose::STANDARD.encode(csv);
    let applied = apply(
        &mut db,
        &Op::ImportCsv {
            data: data.clone(),
            provider: None,
            group_name: "Imported from Bitwarden".into(),
        },
        now,
    )
    .unwrap();
    let v = view::view(&db);
    let top = applied.id.unwrap();
    let names: Vec<&str> = v.groups.iter().map(|g| g.name.as_str()).collect();
    assert!(
        names.contains(&"Imported from Bitwarden")
            && names.contains(&"Work")
            && names.contains(&"Servers")
    );
    let server = v
        .entries
        .iter()
        .find(|e| e.fields.iter().any(|f| f.value == "Server"))
        .unwrap();
    let keys: Vec<&str> = server.fields.iter().map(|f| f.key.as_str()).collect();
    assert!(keys.contains(&"KP2A_URL_1"));
    assert!(
        keys.contains(&"Password (2)"),
        "a custom field named like a standard one is renamed: {keys:?}"
    );
    let plain = v
        .entries
        .iter()
        .find(|e| e.fields.iter().any(|f| f.value == "Plain"))
        .unwrap();
    assert_eq!(plain.group_id, top);

    // A refused import changes nothing.
    let before = db.clone();
    assert!(apply(
        &mut db,
        &Op::ImportCsv {
            data: "!!".into(),
            provider: None,
            group_name: "x".into()
        },
        now
    )
    .is_err());
    assert!(apply(
        &mut db,
        &Op::ImportCsv {
            data,
            provider: None,
            group_name: " ".into()
        },
        now
    )
    .is_err());
    assert_eq!(db, before);
}
