//! The account-records store (docs/plans/account-records.md) against a live
//! server:
//! - a batch of puts and deletes lands with the next head, all or nothing;
//! - every item is compare-and-swap on its base revision, deletes too;
//! - the revision is the sealed header's, and an envelope must be sealed for
//!   its own id;
//! - the feed pages changes by the account's counter, with the head of the
//!   same snapshot;
//! - the head's index reads the store.
//!
//! The server never opens a head (it reads the sequence), so the heads here
//! are sealed under a test key.
//!
//! Needs `KUTUP_LIVE_SERVER`.

mod common;

use common::*;
use kutup_crypto::account_head::{self, AccountHeadV1, HeadKeys, ScopeV1};
use kutup_crypto::account_record::MasterKeyGeneration;
use kutup_crypto::chat_group_list::{encode_entry_id, GroupListKey};
use kutup_crypto::pass_vault::{seal_vault_secret, VaultSecret};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

/// A device's view of the chain: what it last wrote, and how to make the next.
struct Chain {
    keys: HeadKeys,
    binding: String,
    writer: String,
    last: Option<(AccountHeadV1, Vec<u8>)>,
}

impl Chain {
    fn new(binding: &str) -> Self {
        let keys = HeadKeys::derive(
            &kutup_crypto::master_keys::MasterKeys::first(&[0x42; 32]),
            &kutup_crypto::account_roots::ObjectIdKey::from_bytes([0x43; 32]),
        )
        .unwrap();
        let writer = keys.writer("live-test").unwrap();
        Self {
            keys,
            binding: binding.to_owned(),
            writer,
            last: None,
        }
    }

    /// The next head with `chatGroups` holding `index`, kept as the last.
    fn next(&mut self, index: &[(&str, u64)]) -> String {
        let index: Vec<(String, u64)> = index.iter().map(|(id, r)| (id.to_string(), *r)).collect();
        let entry: ScopeV1 = self.keys.scope_digest("chatGroups", &index).unwrap();
        let head = match &self.last {
            Some((head, sealed)) => head.next(sealed, &self.writer, vec![entry]).unwrap(),
            None => AccountHeadV1::first(
                &"ab".repeat(32),
                MasterKeyGeneration::FIRST,
                kutup_crypto::account_head::RootGenerations {
                    identity: 1,
                    drive: 1,
                    object_id: 1,
                    pseudonym: 1,
                    call_link: 1,
                },
                &self.writer,
                vec![entry],
            )
            .unwrap(),
        };
        let sealed = account_head::seal(&self.keys, &self.binding, &head).unwrap();
        let encoded = b64(&sealed);
        self.last = Some((head, sealed));
        encoded
    }
}

struct Account<'a> {
    c: &'a Client,
    base: &'a str,
    user: &'a User,
    groups: GroupListKey,
}

impl Account<'_> {
    /// Group `n`'s record id and its sealed entry at `revision`.
    fn group(&self, n: u8, revision: u64) -> (String, String) {
        let id = self.groups.entry_id(&[n; 32]);
        let sealed = self
            .groups
            .seal(&self.user.binding, &id, revision, b"{\"g\":1}")
            .unwrap();
        (encode_entry_id(&id), b64(&sealed))
    }

    fn batch(&self, body: Value) -> (StatusCode, Value) {
        let r = bearer(
            self.c.post(format!("{}/api/account/records", self.base)),
            &self.user.token,
        )
        .json(&body)
        .send()
        .unwrap();
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    fn get(&self, path: &str) -> (StatusCode, Value) {
        let r = bearer(self.c.get(format!("{}{path}", self.base)), &self.user.token)
            .send()
            .unwrap();
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    fn feed(&self, after: i64) -> Value {
        let (status, page) = self.get(&format!("/api/account/records/chatGroups?after={after}"));
        assert_eq!(status, StatusCode::OK, "{page}");
        page
    }
}

fn put(id: &str, base: i64, envelope: &str) -> Value {
    json!({ "scope": "chatGroups", "id": id, "baseRevision": base, "envelope": envelope })
}

fn ids(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn records_land_in_batches_under_the_head() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_owned();
    let c = crate::common::client();
    let user = register(&c, &base);
    let account = Account {
        c: &c,
        base: &base,
        user: &user,
        groups: GroupListKey::new(
            &user.master_key,
            MasterKeyGeneration::FIRST,
            &user.roots.object_id,
        ),
    };
    let mut chain = Chain::new(&user.binding);

    // A new account: nothing, and the basis a first head starts on.
    let empty = account.feed(0);
    assert_eq!(empty["records"], json!([]));
    assert!(empty["head"].is_null());
    let basis = empty["basis"].as_str().unwrap().to_owned();
    let first = chain.next(&[]);
    let r = bearer(c.post(format!("{base}/api/account/head")), &user.token)
        .json(&json!({ "head": first, "basis": basis }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().unwrap());

    let (a, a1) = account.group(1, 1);
    let (_, a2) = account.group(1, 2);
    let (b, b5) = account.group(2, 5);
    let (cc, c1) = account.group(3, 1);

    // Once the account keeps a head, a batch needs the next one.
    let (status, body) = account.batch(json!({ "puts": [put(&a, 0, &a1)] }));
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("head_required"))
    );

    // Two new records with the next head; the revisions are the headers'.
    let head = chain.next(&[(&a, 1), (&b, 5)]);
    let (status, body) =
        account.batch(json!({ "head": head, "puts": [put(&a, 0, &a1), put(&b, 0, &b5)] }));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 2);

    // The feed from 0: both, the head of the same snapshot, no basis now.
    let page = account.feed(0);
    let mut listed = ids(&page["records"]);
    listed.sort();
    let mut expected = vec![a.clone(), b.clone()];
    expected.sort();
    assert_eq!(listed, expected);
    assert_eq!(page["next"], 2);
    assert_eq!(page["more"], false);
    assert_eq!(page["head"].as_str(), Some(head.as_str()));
    assert!(page["basis"].is_null());
    // The head's index reads the store.
    let (_, index) = account.get("/api/account/index/chatGroups");
    let mut values: Vec<(String, i64)> = serde_json::from_value(index["values"].clone()).unwrap();
    values.sort();
    let mut want = vec![(a.clone(), 1), (b.clone(), 5)];
    want.sort();
    assert_eq!(values, want);
    // One record.
    let (status, one) = account.get(&format!("/api/account/records/chatGroups/{b}"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(one["revision"], 5);
    assert_eq!(one["envelope"].as_str(), Some(b5.as_str()));

    // A conflict refuses the whole batch and names every record not at its
    // base: a stale put and a stale delete; the new record isn't stored.
    let stale = chain.last.clone();
    let head = chain.next(&[(&a, 2), (&cc, 1)]);
    let (status, body) = account.batch(json!({
        "head": head,
        "puts": [put(&a, 0, &a2), put(&cc, 0, &c1)],
        "deletes": [{ "scope": "chatGroups", "id": b, "baseRevision": 4 }],
    }));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "revision_conflict");
    let mut conflicts: Vec<(String, i64)> = body["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["id"].as_str().unwrap().to_owned(),
                c["revision"].as_i64().unwrap(),
            )
        })
        .collect();
    conflicts.sort();
    let mut want = vec![(a.clone(), 1), (b.clone(), 5)];
    want.sort();
    assert_eq!(conflicts, want);
    assert_eq!(
        account
            .get(&format!("/api/account/records/chatGroups/{cc}"))
            .0,
        StatusCode::NOT_FOUND
    );
    chain.last = stale;

    // At their bases: a changed, b deleted, in one batch.
    let head = chain.next(&[(&a, 2)]);
    let (status, body) = account.batch(json!({
        "head": head,
        "puts": [put(&a, 1, &a2)],
        "deletes": [{ "scope": "chatGroups", "id": b, "baseRevision": 5 }],
    }));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["seq"], 4);
    // The same batch again (a retry after it landed): a conflict.
    let landed = chain.last.clone();
    let head_again = chain.next(&[(&a, 2)]);
    chain.last = landed;
    let (status, body) = account.batch(json!({
        "head": head_again,
        "puts": [put(&a, 1, &a2)],
    }));
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("revision_conflict"))
    );

    // From 2: a's new revision and b's tombstone, in counter order.
    let page = account.feed(2);
    assert_eq!(ids(&page["deleted"]), vec![b.clone()]);
    assert_eq!(ids(&page["records"]), vec![a.clone()]);
    assert_eq!(page["records"][0]["revision"], 2);
    assert_eq!(page["next"], 4);
    // From 0 a new device sees only what is there.
    let page = account.feed(0);
    assert_eq!(ids(&page["records"]), vec![a.clone()]);
    assert_eq!(page["deleted"], json!([]));
    // A cursor this account never gave: start over.
    assert_eq!(account.feed(99)["resync"], true);

    // What the server refuses, before any head is looked at.
    let refused = |body: Value| {
        let (status, body) = account.batch(body);
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    };
    refused(json!({ "puts": [] }));
    // An id not in its scope's form, or a record named twice.
    refused(json!({ "puts": [put(&format!("{a}="), 2, &a2)] }));
    refused(json!({ "puts": [put(&a, 2, &a2), put(&a, 2, &a2)] }));
    refused(
        json!({ "puts": [{ "scope": "pins", "id": "pin", "baseRevision": 0, "envelope": a2 }] }),
    );
    // A delete names the revision it read.
    refused(json!({ "deletes": [{ "scope": "chatGroups", "id": a, "baseRevision": 0 }] }));
    // An envelope sealed for another id, or not above its base.
    refused(json!({ "puts": [put(&cc, 0, &a2)] }));
    refused(json!({ "puts": [put(&a, 2, &a2)] }));
    // An unknown scope.
    let (status, _) = account.batch(json!({
        "puts": [{ "scope": "nope", "id": "x", "baseRevision": 0, "envelope": a2 }]
    }));
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A Pass secret's vault must be a live file the caller can open.
    let file = uuid::Uuid::new_v4();
    let secret = b64(&seal_vault_secret(
        &user.master_key,
        MasterKeyGeneration::FIRST,
        &user.binding,
        file.as_bytes(),
        1,
        &VaultSecret::chosen(Some("p"), None),
    )
    .unwrap());
    let head = chain.next(&[(&a, 2)]);
    let (status, body) = account.batch(json!({
        "head": head,
        "puts": [{ "scope": "passSecrets", "id": file.to_string(), "baseRevision": 0, "envelope": secret }],
    }));
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
