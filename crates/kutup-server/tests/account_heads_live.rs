//! The account head chain against a live server
//! (docs/plans/rollback-protection.md): every listed write carries the next
//! head, in sequence; once the account keeps one, a listed write without it
//! is refused; the index comes with its head; two first heads at once meet on
//! the key; a folder delete names what it removes; a wipe starts the chain
//! again and leaves nothing sealed under the old keys in it.
//!
//! The server never opens a head (it reads the sequence), so the heads here
//! are sealed under a test key.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` for the wipe and to purge).

mod common;

use common::*;
use kutup_crypto::account_head::{self, AccountHeadV1, HeadKeys, ScopeV1};
use kutup_crypto::mail_names::{self, MailNameKind};
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

fn names_key() -> [u8; 32] {
    *mail_names::derive_names_key(&[0x43; 32]).unwrap()
}

fn sealed_name(binding: &str, kind: MailNameKind, id: &str, revision: u64) -> String {
    let id = uuid::Uuid::parse_str(id).unwrap();
    b64(&mail_names::seal_name(&names_key(), binding, kind, id.as_bytes(), revision, "n").unwrap())
}

#[test]
fn every_listed_write_carries_the_next_head() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let get = |path: &str| {
        let r = bearer(c.get(format!("{base}{path}")), &user.token)
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        r.json::<Value>().unwrap()
    };
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

    // No head yet: a listed write goes in without one (trust on first use).
    assert_eq!(get("/api/account/head")["head"], Value::Null);
    assert_eq!(put_pins(0, 1, None).status(), StatusCode::NO_CONTENT);
    let index = get("/api/account/index/pins");
    assert_eq!(index, json!({ "head": null, "values": [["pins", 1]] }));

    // The first head, with the write that makes the state it describes.
    let first = chain.keep(chain.make("pins", &[("pins", 2)]));
    assert_eq!(
        put_pins(1, 2, Some(&first)).status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(get("/api/account/head")["head"], json!(first));

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
    // sealed, not protected), and never with one.
    let label = uuid::Uuid::new_v4().to_string();
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
    let label_id = format!("label:{label}");
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
    let sixth = chain.make("mailNames", &[(&label_id, 1)]);
    let delete = |removes: Vec<&str>, head: &str| {
        bearer(
            c.delete(format!("{base}/api/mail/folders/{outer}")),
            &user.token,
        )
        .json(&json!({ "removes": removes, "head": head }))
        .send()
        .unwrap()
    };
    let sixth_b64 = b64(&sixth.1);
    assert_eq!(
        code(delete(vec![&outer], &sixth_b64)),
        (StatusCode::CONFLICT, json!("head_conflict")),
        "the folder inside goes too"
    );
    let sixth = chain.keep(sixth);
    assert_eq!(
        delete(vec![&inner, &outer], &sixth).status(),
        StatusCode::OK
    );

    // The chain, and an index with the head it goes with.
    let heads = get("/api/account/heads?from=1");
    assert_eq!(heads["heads"].as_array().unwrap().len(), 6);
    assert_eq!(heads["heads"][0], json!(first));
    assert_eq!(heads["heads"][5], json!(sixth));
    assert_eq!(get("/api/account/heads?from=7"), json!({ "heads": [] }));
    let bad = bearer(
        c.get(format!("{base}/api/account/heads?from=0")),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        get("/api/account/index/mailNames"),
        json!({ "head": sixth, "values": [[label_id, 1]] })
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

#[test]
fn two_first_heads_at_once_one_wins() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let chain = Chain::new(&user.binding);
    for round in 0..5 {
        // Two devices, each making the account's first head (or, after a
        // round, the same next one), each with its own new label.
        let barrier = std::sync::Barrier::new(2);
        let statuses: Vec<(StatusCode, Value)> = std::thread::scope(|scope| {
            let runs: Vec<_> = (0..2)
                .map(|_| {
                    let (c, base, user, chain, barrier) = (&c, &base, &user, &chain, &barrier);
                    scope.spawn(move || {
                        let label = uuid::Uuid::new_v4().to_string();
                        let (_, sealed) =
                            chain.make("mailNames", &[(&format!("label:{label}"), 1)]);
                        let body = json!({ "id": label, "color": "#336699", "head": b64(&sealed),
                            "name": sealed_name(&user.binding, MailNameKind::Label, &label, 1) });
                        barrier.wait();
                        code(
                            bearer(c.post(format!("{base}/api/mail/labels")), &user.token)
                                .json(&body)
                                .send()
                                .unwrap(),
                        )
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
        // The first round: both make sequence 1. Later rounds: both are
        // behind (sequence 1 again), so both lose.
        if round == 0 {
            assert_eq!((won, lost), (1, 1), "{statuses:?}");
        } else {
            assert_eq!((won, lost), (0, 2), "{statuses:?}");
        }
    }
    purge_accounts(&c, &base, &[&user]);
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
    let first = chain.keep(chain.make("mailNames", &[(&folder_id, 1)]));
    let r = bearer(c.post(format!("{base}/api/mail/folders")), &user.token)
        .json(
            &json!({ "id": folder, "parentId": null, "color": "#336699", "head": first,
                       "name": sealed_name(&user.binding, MailNameKind::Folder, &folder, 1) }),
        )
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let second = chain.keep(chain.make("mailNames", &[(&folder_id, 1), (&label_id, 1)]));
    let r = bearer(c.post(format!("{base}/api/mail/labels")), &user.token)
        .json(&json!({ "id": label, "color": "#336699", "head": second,
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
    let get = |path: &str| {
        let r = bearer(c.get(format!("{base}{path}")), &user.token)
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        r.json::<Value>().unwrap()
    };

    // No head; the label is gone; the folder kept its place, not its name,
    // and is left out of the index until named.
    assert_eq!(get("/api/account/head")["head"], Value::Null);
    assert_eq!(
        get("/api/account/index/mailNames"),
        json!({ "head": null, "values": [] })
    );
    let places = get("/api/mail/places");
    assert_eq!(places["labels"], json!([]));
    assert_eq!(places["folders"][0]["id"], json!(folder));
    assert_eq!(places["folders"][0]["name"], Value::Null);

    // The new incarnation's first head names it again, from revision 0 (the
    // server reads only the sequence, so any binding seals the test heads).
    let binding = user.binding.clone();
    let mut chain = Chain::new(&binding);
    let first = chain.keep(chain.make("mailNames", &[(&folder_id, 1)]));
    let r = bearer(
        c.patch(format!("{base}/api/mail/folders/{folder}")),
        &user.token,
    )
    .json(
        &json!({ "name": sealed_name(&binding, MailNameKind::Folder, &folder, 1),
                       "baseNameRevision": 0, "head": first }),
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get("/api/account/index/mailNames"),
        json!({ "head": first, "values": [[folder_id, 1]] })
    );
    purge_accounts(&c, &base, &[&user]);
}
