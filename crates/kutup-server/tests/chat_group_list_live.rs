//! An account's group list (docs/plans/pairwise-groups.md §5) against a live
//! server with pairwise groups on: sealed entries by keyed id, the revision
//! read from each entry's authenticated header, compare-and-swap, the account
//! head's `chatGroups` scope, the limit, and what the server refuses.
//!
//! Needs `KUTUP_LIVE_GROUPS_SERVER` (a server with `CHAT_GROUPS=true` and
//! federation; the two-server gate's A).

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use kutup_crypto::account_head::{self, AccountHeadV1, HeadKeys};
use kutup_crypto::chat_group_list::{encode_entry_id, GroupListKey};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

struct List<'a> {
    c: &'a Client,
    base: &'a str,
    user: &'a User,
    key: GroupListKey,
}

impl List<'_> {
    /// The entry id of group `n` and a sealed entry for it at `revision`.
    fn entry(&self, n: u32, revision: u64) -> (String, String) {
        let mut group = [0u8; 32];
        group[..4].copy_from_slice(&n.to_be_bytes());
        let id = self.key.entry_id(&group);
        let sealed = self
            .key
            .seal(&self.user.binding, &id, revision, b"{\"g\":1}")
            .unwrap();
        (encode_entry_id(&id), STANDARD.encode(sealed))
    }

    fn put(&self, id: &str, body: Value) -> reqwest::blocking::Response {
        bearer(
            self.c
                .put(format!("{}/api/chat/group-list/{id}", self.base)),
            &self.user.token,
        )
        .json(&body)
        .send()
        .unwrap()
    }

    fn delete(&self, id: &str, body: Value) -> StatusCode {
        bearer(
            self.c
                .delete(format!("{}/api/chat/group-list/{id}", self.base)),
            &self.user.token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    }

    fn entries(&self) -> Vec<Value> {
        let list: Value = bearer(
            self.c.get(format!("{}/api/chat/group-list", self.base)),
            &self.user.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        list["entries"].as_array().unwrap().clone()
    }

    fn index(&self) -> Value {
        bearer(
            self.c
                .get(format!("{}/api/account/index/chatGroups", self.base)),
            &self.user.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap()
    }
}

fn base() -> Option<String> {
    let Ok(base) = std::env::var("KUTUP_LIVE_GROUPS_SERVER") else {
        eprintln!("KUTUP_LIVE_GROUPS_SERVER not set; skipping");
        return None;
    };
    Some(base.trim_end_matches('/').to_string())
}

#[test]
fn a_group_list_keeps_sealed_entries_by_revision() {
    let Some(base) = base() else { return };
    let c = crate::common::client();
    let user = register(&c, &base);
    let list = List {
        c: &c,
        base: &base,
        user: &user,
        key: GroupListKey::derive(&user.master_key),
    };
    let (one, one_at_1) = list.entry(1, 1);
    let (_, one_at_2) = list.entry(1, 2);
    let (two, two_at_5) = list.entry(2, 5);

    // New entries, from revision 0; the revision is the entry's own.
    let r = list.put(&one, json!({"baseRevision": 0, "envelope": one_at_1}));
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().unwrap());
    assert_eq!(
        list.put(&two, json!({"baseRevision": 0, "envelope": two_at_5}))
            .status(),
        StatusCode::OK
    );
    // A "new" entry under a taken id: the current revision.
    let r = list.put(&one, json!({"baseRevision": 0, "envelope": one_at_1}));
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "revision_conflict");
    assert_eq!(body["revision"], 1);
    // A change from the stored revision; the same one again is stale.
    assert_eq!(
        list.put(&one, json!({"baseRevision": 1, "envelope": one_at_2}))
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        list.put(&one, json!({"baseRevision": 1, "envelope": one_at_2}))
            .status(),
        StatusCode::CONFLICT
    );
    // An entry whose revision isn't above its base.
    assert_eq!(
        list.put(&one, json!({"baseRevision": 2, "envelope": one_at_2}))
            .status(),
        StatusCode::BAD_REQUEST
    );
    // The body's revision is gone: an extra field is refused.
    assert_eq!(
        list.put(
            &one,
            json!({"baseRevision": 2, "revision": 3, "envelope": one_at_2})
        )
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let entries = list.entries();
    assert_eq!(entries.len(), 2);
    let found = entries.iter().find(|e| e["id"] == one).unwrap();
    assert_eq!(found["revision"], 2);
    assert_eq!(found["envelope"], one_at_2);

    // Not an entry id, not one size: refused.
    for bad in ["short", &format!("{one}=")] {
        let r = list.put(bad, json!({"baseRevision": 0, "envelope": one_at_1}));
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{bad}");
    }
    let (three, _) = list.entry(3, 1);
    let short = STANDARD.encode(vec![0u8; 4031]);
    assert_eq!(
        list.put(&three, json!({"baseRevision": 0, "envelope": short}))
            .status(),
        StatusCode::BAD_REQUEST
    );

    // Removal from the stored revision only.
    assert_eq!(
        list.delete(&two, json!({"baseRevision": 4})),
        StatusCode::CONFLICT
    );
    assert_eq!(
        list.delete(&two, json!({"baseRevision": 5})),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        list.delete(&two, json!({"baseRevision": 5})),
        StatusCode::NOT_FOUND
    );
    assert_eq!(list.entries().len(), 1);

    // Another account sees none of it.
    let other = register(&c, &base);
    let theirs: Value = bearer(c.get(format!("{base}/api/chat/group-list")), &other.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(theirs["entries"], json!([]));
    purge_accounts(&c, &base, &[&user, &other]);
}

/// The account head covers the list: once the account keeps a head, a write
/// without the next one is refused, and the chatGroups index follows writes.
#[test]
fn the_account_head_covers_the_group_list() {
    let Some(base) = base() else { return };
    let c = crate::common::client();
    let user = register(&c, &base);
    let list = List {
        c: &c,
        base: &base,
        user: &user,
        key: GroupListKey::derive(&user.master_key),
    };
    let (one, one_at_1) = list.entry(1, 1);
    let (_, one_at_2) = list.entry(1, 2);
    assert_eq!(
        list.put(&one, json!({"baseRevision": 0, "envelope": one_at_1}))
            .status(),
        StatusCode::OK
    );

    // Start the chain on the basis the index gives.
    let index = list.index();
    assert_eq!(index["values"], json!([[one, 1]]));
    let keys = HeadKeys::derive(&user.master_key).unwrap();
    let writer = keys.writer("group-list-live").unwrap();
    let scope = |revision: u64| {
        keys.scope_digest("chatGroups", &[(one.clone(), revision)])
            .unwrap()
    };
    let first =
        AccountHeadV1::first(&user.identity.incarnation_id(), &writer, vec![scope(1)]).unwrap();
    let first_sealed = account_head::seal(&keys, &user.binding, &first).unwrap();
    let r = bearer(c.post(format!("{base}/api/account/head")), &user.token)
        .json(&json!({ "head": STANDARD.encode(&first_sealed), "basis": index["basis"] }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "start: {}", r.text().unwrap());

    // Now a write needs the next head.
    let r = list.put(&one, json!({"baseRevision": 1, "envelope": one_at_2}));
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "head_required");
    let next = first.next(&first_sealed, &writer, vec![scope(2)]).unwrap();
    let next_sealed = account_head::seal(&keys, &user.binding, &next).unwrap();
    let r = list.put(
        &one,
        json!({"baseRevision": 1, "envelope": one_at_2, "head": STANDARD.encode(&next_sealed)}),
    );
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().unwrap());
    assert_eq!(list.index()["values"], json!([[one, 2]]));
    purge_accounts(&c, &base, &[&user]);
}

/// At most 1024 entries: the next new one is refused.
#[test]
fn a_group_list_keeps_at_most_1024_entries() {
    let Some(base) = base() else { return };
    let c = crate::common::client();
    let user = register(&c, &base);
    let list = List {
        c: &c,
        base: &base,
        user: &user,
        key: GroupListKey::derive(&user.master_key),
    };
    for n in 0..1024 {
        let (id, sealed) = list.entry(n, 1);
        let r = list.put(&id, json!({"baseRevision": 0, "envelope": sealed}));
        assert_eq!(r.status(), StatusCode::OK, "entry {n}");
    }
    let (id, sealed) = list.entry(1024, 1);
    let r = list.put(&id, json!({"baseRevision": 0, "envelope": sealed}));
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    purge_accounts(&c, &base, &[&user]);
}
