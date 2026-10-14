//! The account head chain against a live server
//! (docs/plans/rollback-protection.md §9): the chain starts on the basis an
//! index gave; every listed write carries the next head, in sequence; once
//! the account keeps one, a listed write without it is refused; the index
//! comes with its head; two chain starts at once, one wins; a folder delete
//! names what it removes; a wipe starts the chain again with nothing old in
//! it.
//!
//! The server never opens a head (it reads the sequence), so the heads here
//! are sealed under a test key.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` for the wipe and to purge).

mod common;

use common::*;
use kutup_crypto::account_head::{self, AccountHeadV1, HeadKeys, ScopeV1};
use kutup_crypto::contact_card::{self, ContactEmailV1, ContactSummaryV1};
use kutup_crypto::mail_names::{self, MailNameKind};
use kutup_crypto::pass_vault::{seal_vault_secret, VaultSecret};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// A device's view of the chain: what it last wrote, and how to make the next.
struct Chain {
    keys: HeadKeys,
    binding: String,
    writer: String,
    last: Option<(AccountHeadV1, Vec<u8>)>,
}

impl Chain {
    fn new(binding: &str) -> Self {
        let keys = HeadKeys::derive(&[0x42; 32]).unwrap();
        let writer = keys.writer("live-test").unwrap();
        Self {
            keys,
            binding: binding.to_owned(),
            writer,
            last: None,
        }
    }

    /// The next head with `scope` holding `index`: (head, sealed).
    fn make(&self, scope: &str, index: &[(&str, u64)]) -> (AccountHeadV1, Vec<u8>) {
        let index: Vec<(String, u64)> = index.iter().map(|(id, r)| (id.to_string(), *r)).collect();
        let entry: ScopeV1 = self.keys.scope_digest(scope, &index).unwrap();
        let head = match &self.last {
            Some((head, sealed)) => head.next(sealed, &self.writer, vec![entry]).unwrap(),
            None => AccountHeadV1::first(&"ab".repeat(32), &self.writer, vec![entry]).unwrap(),
        };
        let sealed = account_head::seal(&self.keys, &self.binding, &head).unwrap();
        (head, sealed)
    }

    fn keep(&mut self, made: (AccountHeadV1, Vec<u8>)) -> String {
        let sealed = b64(&made.1);
        self.last = Some(made);
        sealed
    }
}

fn code(r: reqwest::blocking::Response) -> (StatusCode, Value) {
    let status = r.status();
    let body: Value = r.json().unwrap_or(Value::Null);
    (status, body["code"].clone())
}

fn sealed_name(binding: &str, kind: MailNameKind, id: &str, revision: u64) -> String {
    let key = mail_names::derive_names_key(&[0x43; 32]).unwrap();
    let id = uuid::Uuid::parse_str(id).unwrap();
    b64(&mail_names::seal_name(&key, binding, kind, id.as_bytes(), revision, "n").unwrap())
}

fn get(c: &Client, base: &str, user: &User, path: &str) -> Value {
    let r = bearer(c.get(format!("{base}{path}")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{path}");
    r.json().unwrap()
}

/// Starts the account's chain with `head` on the basis `scope`'s index gives.
fn start(
    c: &Client,
    base: &str,
    user: &User,
    head: &str,
    basis: &str,
) -> reqwest::blocking::Response {
    bearer(c.post(format!("{base}/api/account/head")), &user.token)
        .json(&json!({ "head": head, "basis": basis }))
        .send()
        .unwrap()
}

fn basis(c: &Client, base: &str, user: &User) -> String {
    get(c, base, user, "/api/account/index/contacts")["basis"]
        .as_str()
        .expect("a basis before the first head")
        .to_owned()
}

#[test]
fn the_chain_starts_on_its_basis_and_every_write_follows_it() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let pins_key = kutup_crypto::identity_pins::derive_key(&[0x44; 32]).unwrap();
    let pins = |revision: u64| {
        b64(&kutup_crypto::identity_pins::seal(
            &pins_key,
            &user.binding,
            revision,
            &kutup_crypto::identity_pins::IdentityPinsV1 { pins: vec![] },
        )
        .unwrap())
    };
    let put_pins = |base_revision: i64, revision: u64, head: Option<&str>| {
        bearer(c.put(format!("{base}/api/user/identity-pins")), &user.token)
            .json(
                &json!({ "baseRevision": base_revision, "envelope": pins(revision), "head": head }),
            )
            .send()
            .unwrap()
    };
    let mut chain = Chain::new(&user.binding);

    // No head yet: a listed write goes in without one (not started).
    assert_eq!(
        get(&c, &base, &user, "/api/account/head")["head"],
        Value::Null
    );
    assert_eq!(put_pins(0, 1, None).status(), StatusCode::NO_CONTENT);
    let index = get(&c, &base, &user, "/api/account/index/pins");
    assert_eq!(index["head"], Value::Null);
    assert_eq!(index["values"], json!([["pins", 1]]));
    let on = index["basis"].as_str().unwrap().to_owned();

    // A head never starts the chain from a listed write; a start does, on
    // the basis it was made on (a write in between moves it).
    let first = chain.make("pins", &[("pins", 1)]);
    let first_b64 = b64(&first.1);
    assert_eq!(
        code(put_pins(1, 2, Some(&first_b64))),
        (StatusCode::CONFLICT, json!("head_conflict"))
    );
    assert_eq!(put_pins(1, 2, None).status(), StatusCode::NO_CONTENT);
    assert_eq!(
        code(start(&c, &base, &user, &first_b64, &on)),
        (StatusCode::CONFLICT, json!("head_conflict")),
        "the basis moved"
    );
    let first = chain.keep(chain.make("pins", &[("pins", 2)]));
    let on = basis(&c, &base, &user);
    assert_eq!(
        start(&c, &base, &user, &first, &on).status(),
        StatusCode::CREATED
    );
    assert_eq!(
        get(&c, &base, &user, "/api/account/head")["head"],
        json!(first)
    );
    assert_eq!(
        code(start(&c, &base, &user, &first, &on)),
        (StatusCode::CONFLICT, json!("head_conflict")),
        "once only"
    );

    // From now on: none is refused, a skipped sequence is refused.
    assert_eq!(
        code(put_pins(2, 3, None)),
        (StatusCode::CONFLICT, json!("head_required"))
    );
    let second = chain.make("pins", &[("pins", 3)]);
    let skipped = {
        let (head, sealed) = second.clone();
        let next = head.next(&sealed, &chain.writer, vec![]).unwrap();
        b64(&account_head::seal(&chain.keys, &chain.binding, &next).unwrap())
    };
    let r = put_pins(2, 3, Some(&skipped));
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["sequence"], 1);
    let second = chain.keep(second);
    assert_eq!(
        put_pins(2, 3, Some(&second)).status(),
        StatusCode::NO_CONTENT
    );

    // A label: created only with the next head; recoloured without one (not
    // sealed, not protected), never with one.
    let label = uuid::Uuid::new_v4().to_string();
    let label_id = format!("label:{label}");
    let create_label = |head: Option<&str>| {
        bearer(c.post(format!("{base}/api/mail/labels")), &user.token)
            .json(&json!({ "id": label, "name": sealed_name(&user.binding, MailNameKind::Label, &label, 1),
                           "color": "#336699", "head": head }))
            .send()
            .unwrap()
    };
    assert_eq!(
        code(create_label(None)),
        (StatusCode::CONFLICT, json!("head_required"))
    );
    let third = chain.keep(chain.make("mailNames", &[(&label_id, 1)]));
    assert_eq!(create_label(Some(&third)).status(), StatusCode::CREATED);
    let recolour = |head: Option<&str>| {
        bearer(
            c.patch(format!("{base}/api/mail/labels/{label}")),
            &user.token,
        )
        .json(&json!({ "color": "#663399", "head": head }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(recolour(Some(&third)), StatusCode::BAD_REQUEST);
    assert_eq!(recolour(None), StatusCode::NO_CONTENT);

    // A folder delete names every folder it removes, as the server finds them.
    let folder = |parent: Option<&str>, id: &str, head: &str| {
        bearer(c.post(format!("{base}/api/mail/folders")), &user.token)
            .json(
                &json!({ "id": id, "parentId": parent, "color": "#336699", "head": head,
                           "name": sealed_name(&user.binding, MailNameKind::Folder, id, 1) }),
            )
            .send()
            .unwrap()
            .status()
    };
    let (outer, inner) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    let (outer_id, inner_id) = (format!("folder:{outer}"), format!("folder:{inner}"));
    let fourth = chain.keep(chain.make("mailNames", &[(&label_id, 1), (&outer_id, 1)]));
    assert_eq!(folder(None, &outer, &fourth), StatusCode::CREATED);
    let fifth = chain.keep(chain.make(
        "mailNames",
        &[(&label_id, 1), (&outer_id, 1), (&inner_id, 1)],
    ));
    assert_eq!(folder(Some(&outer), &inner, &fifth), StatusCode::CREATED);
    let delete = |removes: Vec<&str>, head: Option<&str>| {
        bearer(
            c.delete(format!("{base}/api/mail/folders/{outer}")),
            &user.token,
        )
        .json(&json!({ "removes": removes, "head": head }))
        .send()
        .unwrap()
    };
    assert_eq!(
        code(delete(vec![&inner, &outer], None)),
        (StatusCode::CONFLICT, json!("head_required"))
    );
    let sixth = chain.make("mailNames", &[(&label_id, 1)]);
    let sixth_b64 = b64(&sixth.1);
    assert_eq!(
        code(delete(vec![&outer], Some(&sixth_b64))),
        (StatusCode::CONFLICT, json!("head_conflict")),
        "the folder inside goes too"
    );
    let sixth = chain.keep(sixth);
    assert_eq!(
        delete(vec![&inner, &outer], Some(&sixth)).status(),
        StatusCode::OK
    );

    // The chain, a page at a time, and an index with the head it goes with.
    let heads = get(&c, &base, &user, "/api/account/heads?from=1");
    assert_eq!(heads["heads"].as_array().unwrap().len(), 6);
    assert_eq!(heads["heads"][0], json!(first));
    assert_eq!(heads["heads"][5], json!(sixth));
    assert_eq!(heads["next"], Value::Null);
    assert_eq!(
        get(&c, &base, &user, "/api/account/heads?from=7"),
        json!({ "heads": [], "next": null })
    );
    let bad = bearer(
        c.get(format!("{base}/api/account/heads?from=0")),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        get(&c, &base, &user, "/api/account/index/mailNames"),
        json!({ "head": sixth, "values": [[label_id, 1]], "basis": null })
    );
    let unknown = bearer(
        c.get(format!("{base}/api/account/index/settings")),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    purge_accounts(&c, &base, &[&user]);
}

/// A contact body for `uid` at `revision`.
fn contact(user: &User, uid: &str, revision: u64) -> Value {
    let summary = ContactSummaryV1 {
        uid: uid.into(),
        name: "Ayşe".into(),
        emails: vec![ContactEmailV1 {
            address: "ayse@example.com".into(),
            label: None,
        }],
        groups: vec![],
        pinned_keys: vec![],
    };
    let (bytes, signature) = contact_card::sign_summary(
        &summary,
        &user.binding,
        revision,
        user.identity.authority_signing_key(),
    )
    .unwrap();
    let key = contact_card::derive_contacts_key(&user.master_key).unwrap();
    let vcard = format!("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{uid}\r\nFN:Ayşe\r\nEND:VCARD\r\n");
    let card =
        contact_card::seal_card(&key, &user.binding, uid, revision, vcard.as_bytes()).unwrap();
    json!({
        "summary": String::from_utf8(bytes).unwrap(),
        "signature": b64(&signature),
        "card": b64(&card),
    })
}

#[test]
fn every_kind_of_listed_write_takes_the_head() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let mut chain = Chain::new(&user.binding);
    let first = chain.keep(chain.make("contacts", &[]));
    let on = basis(&c, &base, &user);
    assert_eq!(
        start(&c, &base, &user, &first, &on).status(),
        StatusCode::CREATED
    );
    let send = |method: reqwest::Method, path: &str, mut body: Value, head: Option<&str>| {
        if let Some(head) = head {
            body["head"] = json!(head);
        }
        code(
            bearer(c.request(method, format!("{base}{path}")), &user.token)
                .json(&body)
                .send()
                .unwrap(),
        )
    };
    use reqwest::Method;
    let ok = |(status, _): (StatusCode, Value)| assert!(status.is_success(), "{status}");
    let required = (StatusCode::CONFLICT, json!("head_required"));

    // Contacts: create, update, import, delete one, delete many.
    let uid = |n: u8| format!("urn:uuid:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f{n:02x}");
    assert_eq!(
        send(
            Method::POST,
            "/api/contacts",
            contact(&user, &uid(1), 1),
            None
        ),
        required
    );
    let made = chain.make("contacts", &[]); // the id is the server's: read it back
    let r = bearer(c.post(format!("{base}/api/contacts")), &user.token)
        .json(&{
            let mut body = contact(&user, &uid(1), 1);
            body["head"] = json!(b64(&made.1));
            body
        })
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    chain.keep(made);
    let id = r.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut update = contact(&user, &uid(1), 2);
    update["baseRevision"] = json!(1);
    assert_eq!(
        send(
            Method::PUT,
            &format!("/api/contacts/{id}"),
            update.clone(),
            None
        ),
        required
    );
    let head = chain.keep(chain.make("contacts", &[(&id, 2)]));
    ok(send(
        Method::PUT,
        &format!("/api/contacts/{id}"),
        update,
        Some(&head),
    ));
    let import = json!({ "contacts": [contact(&user, &uid(2), 1), contact(&user, &uid(3), 1)] });
    assert_eq!(
        send(Method::POST, "/api/contacts/import", import.clone(), None),
        required
    );
    let head = chain.keep(chain.make("contacts", &[(&id, 2)]));
    ok(send(
        Method::POST,
        "/api/contacts/import",
        import,
        Some(&head),
    ));
    let listed: Vec<String> = get(&c, &base, &user, "/api/account/index/contacts")["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| pair[0].as_str().unwrap().to_owned())
        .filter(|other| *other != id)
        .collect();
    assert_eq!(listed.len(), 2);
    assert_eq!(
        send(
            Method::DELETE,
            &format!("/api/contacts/{id}"),
            json!({}),
            None
        ),
        required
    );
    let head = chain.keep(chain.make("contacts", &[]));
    ok(send(
        Method::DELETE,
        &format!("/api/contacts/{id}"),
        json!({}),
        Some(&head),
    ));
    let many = json!({ "ids": listed });
    assert_eq!(
        send(Method::POST, "/api/contacts/delete", many.clone(), None),
        required
    );
    let head = chain.keep(chain.make("contacts", &[]));
    ok(send(
        Method::POST,
        "/api/contacts/delete",
        many,
        Some(&head),
    ));

    // Filters: create, rename, switch off (no head, never one), delete.
    let filter = uuid::Uuid::new_v4().to_string();
    let filter_id = format!("filter:{filter}");
    let create = json!({ "id": filter, "match": "all",
        "name": sealed_name(&user.binding, MailNameKind::Filter, &filter, 1),
        "conditions": [{ "field": "subject", "op": "contains", "value": "x" }],
        "actions": { "star": true } });
    assert_eq!(
        send(Method::POST, "/api/mail/filters", create.clone(), None),
        required
    );
    let head = chain.keep(chain.make("mailNames", &[(&filter_id, 1)]));
    ok(send(Method::POST, "/api/mail/filters", create, Some(&head)));
    let rename = json!({ "baseNameRevision": 1,
        "name": sealed_name(&user.binding, MailNameKind::Filter, &filter, 2) });
    assert_eq!(
        send(
            Method::PATCH,
            &format!("/api/mail/filters/{filter}"),
            rename.clone(),
            None
        ),
        required
    );
    let head = chain.keep(chain.make("mailNames", &[(&filter_id, 2)]));
    ok(send(
        Method::PATCH,
        &format!("/api/mail/filters/{filter}"),
        rename,
        Some(&head),
    ));
    assert_eq!(
        send(
            Method::PATCH,
            &format!("/api/mail/filters/{filter}"),
            json!({ "enabled": false }),
            Some(&head)
        )
        .0,
        StatusCode::BAD_REQUEST
    );
    ok(send(
        Method::PATCH,
        &format!("/api/mail/filters/{filter}"),
        json!({ "enabled": false }),
        None,
    ));
    assert_eq!(
        send(
            Method::DELETE,
            &format!("/api/mail/filters/{filter}"),
            json!({}),
            None
        ),
        required
    );
    let head = chain.keep(chain.make("mailNames", &[]));
    ok(send(
        Method::DELETE,
        &format!("/api/mail/filters/{filter}"),
        json!({}),
        Some(&head),
    ));

    // Pass: keep a vault's key, forget it, forget several.
    let folder = create_folder(&c, &base, &user);
    let vault = seal_file(&folder, &uuid(), b"a KeePass file");
    assert!(upload(&c, &base, &user.token, &folder, &vault)
        .status()
        .is_success());
    let secret = |revision: u64| {
        let id = uuid::Uuid::parse_str(&vault.id).unwrap();
        b64(&seal_vault_secret(
            &user.master_key,
            &user.binding,
            id.as_bytes(),
            revision,
            &VaultSecret::chosen(Some("p"), None),
        )
        .unwrap())
    };
    let keep = json!({ "envelope": secret(1_791_633_600_001), "baseRevision": 0 });
    let path = format!("/api/pass/vault-secrets/{}", vault.id);
    assert_eq!(send(Method::PUT, &path, keep.clone(), None), required);
    let head = chain.keep(chain.make("passSecrets", &[(&vault.id, 1_791_633_600_001)]));
    ok(send(Method::PUT, &path, keep, Some(&head)));
    assert_eq!(send(Method::DELETE, &path, json!({}), None), required);
    let head = chain.keep(chain.make("passSecrets", &[]));
    ok(send(Method::DELETE, &path, json!({}), Some(&head)));
    let forget = json!({ "fileIds": [vault.id] });
    assert_eq!(
        send(
            Method::POST,
            "/api/pass/vault-secrets/forget",
            forget.clone(),
            None
        ),
        required
    );
    let head = chain.keep(chain.make("passSecrets", &[]));
    ok(send(
        Method::POST,
        "/api/pass/vault-secrets/forget",
        forget,
        Some(&head),
    ));
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn two_chain_starts_at_once_one_wins() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    for _ in 0..5 {
        let user = register(&c, &base);
        let on = basis(&c, &base, &user);
        let barrier = std::sync::Barrier::new(2);
        let statuses: Vec<(StatusCode, Value)> = std::thread::scope(|scope| {
            let runs: Vec<_> = (0..2)
                .map(|n| {
                    let (c, base, user, on, barrier) = (&c, &base, &user, &on, &barrier);
                    scope.spawn(move || {
                        // Two devices, each its own first head.
                        let mut chain = Chain::new(&user.binding);
                        chain.writer = chain.keys.writer(&format!("device-{n}")).unwrap();
                        let head = chain.keep(chain.make("contacts", &[]));
                        barrier.wait();
                        code(start(c, base, user, &head, on))
                    })
                })
                .collect();
            runs.into_iter().map(|run| run.join().unwrap()).collect()
        });
        let won = statuses
            .iter()
            .filter(|(s, _)| *s == StatusCode::CREATED)
            .count();
        let lost = statuses
            .iter()
            .filter(|(s, c)| *s == StatusCode::CONFLICT && c == "head_conflict")
            .count();
        assert_eq!((won, lost), (1, 1), "{statuses:?}");
        purge_accounts(&c, &base, &[&user]);
    }
}

#[test]
fn a_wipe_starts_the_chain_again_with_nothing_old_in_it() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let mut chain = Chain::new(&user.binding);
    let (folder, label) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    let (folder_id, label_id) = (format!("folder:{folder}"), format!("label:{label}"));
    let first = chain.keep(chain.make("mailNames", &[]));
    let on = basis(&c, &base, &user);
    assert_eq!(
        start(&c, &base, &user, &first, &on).status(),
        StatusCode::CREATED
    );
    let second = chain.keep(chain.make("mailNames", &[(&folder_id, 1)]));
    let r = bearer(c.post(format!("{base}/api/mail/folders")), &user.token)
        .json(
            &json!({ "id": folder, "parentId": null, "color": "#336699", "head": second,
                       "name": sealed_name(&user.binding, MailNameKind::Folder, &folder, 1) }),
        )
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let third = chain.keep(chain.make("mailNames", &[(&folder_id, 1), (&label_id, 1)]));
    let r = bearer(c.post(format!("{base}/api/mail/labels")), &user.token)
        .json(&json!({ "id": label, "color": "#336699", "head": third,
                       "name": sealed_name(&user.binding, MailNameKind::Label, &label, 1) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);

    // The administrator wipes the account; its owner sets it up again.
    let (admin_name, admin_password) = admin.split_once(':').expect("username:password");
    let admin_token = admin_token(&c, &base, admin_password, admin_name);
    let grant = admin_reset_grant(
        &c,
        &base,
        &admin_token,
        admin_name,
        admin_password,
        &user.id,
    );
    let mut setup = temp_registration(
        &c,
        &base,
        "Temporary*Password123",
        &admin_token,
        Some(&grant),
    );
    setup["grant"] = json!(grant);
    let r = bearer(
        c.post(format!("{base}/api/admin/users/{}/wipe", user.id)),
        &admin_token,
    )
    .json(&setup)
    .send()
    .unwrap();
    assert!(r.status().is_success(), "wipe: {}", r.status());
    let first_login = sign_in(&c, &base, &user.username, "Temporary*Password123");
    let (token, identity) = complete_setup(
        &c,
        &base,
        first_login["setupToken"].as_str().unwrap(),
        &user.username,
        "Another*Password456",
    );
    user.token = token;
    user.identity = identity;
    user.password = "Another*Password456".into();

    // No head; the label is gone; the folder kept its place, not its name,
    // and is left out of the index until named.
    assert_eq!(
        get(&c, &base, &user, "/api/account/head")["head"],
        Value::Null
    );
    let index = get(&c, &base, &user, "/api/account/index/mailNames");
    assert_eq!(
        (index["head"].clone(), index["values"].clone()),
        (Value::Null, json!([]))
    );
    let places = get(&c, &base, &user, "/api/mail/places");
    assert_eq!(places["labels"], json!([]));
    assert_eq!(places["folders"][0]["id"], json!(folder));
    assert_eq!(places["folders"][0]["name"], Value::Null);

    // The new incarnation's chain starts, and names the folder again from
    // revision 0 (the server reads only the sequence, so any binding seals
    // the test heads).
    let mut chain = Chain::new(&user.binding);
    let first = chain.keep(chain.make("mailNames", &[]));
    let on = basis(&c, &base, &user);
    assert_eq!(
        start(&c, &base, &user, &first, &on).status(),
        StatusCode::CREATED
    );
    let second = chain.keep(chain.make("mailNames", &[(&folder_id, 1)]));
    let r = bearer(
        c.patch(format!("{base}/api/mail/folders/{folder}")),
        &user.token,
    )
    .json(
        &json!({ "name": sealed_name(&user.binding, MailNameKind::Folder, &folder, 1),
                       "baseNameRevision": 0, "head": second }),
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get(&c, &base, &user, "/api/account/index/mailNames"),
        json!({ "head": second, "values": [[folder_id, 1]], "basis": null })
    );
    purge_accounts(&c, &base, &[&user]);
}
