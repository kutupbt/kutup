//! An account's group list (docs/plans/pairwise-groups.md §5) against a live
//! server: entries by keyed id, compare-and-swap on revisions, the head's
//! `chatGroups` index, and what the server refuses.
//!
//! Needs `KUTUP_LIVE_SERVER`.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn entry_id(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 32])
}

#[test]
fn a_group_list_keeps_sealed_entries_by_revision() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = reqwest::blocking::Client::new();
    let user = register(&c, &base);
    let put = |id: &str, body: Value| {
        bearer(
            c.put(format!("{base}/api/chat/group-list/{id}")),
            &user.token,
        )
        .json(&body)
        .send()
        .unwrap()
    };
    let list = || -> Value {
        bearer(c.get(format!("{base}/api/chat/group-list")), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let (one, two) = (entry_id(1), entry_id(2));
    let sealed = |byte: u8| STANDARD.encode([byte; 100]);

    // New entries, from revision 0.
    let r = put(
        &one,
        json!({"baseRevision": 0, "revision": 1, "envelope": sealed(1)}),
    );
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().unwrap());
    let r = put(
        &two,
        json!({"baseRevision": 0, "revision": 5, "envelope": sealed(2)}),
    );
    assert_eq!(r.status(), StatusCode::OK);
    // Another device's "new" entry under a taken id: the current revision.
    let r = put(
        &one,
        json!({"baseRevision": 0, "revision": 1, "envelope": sealed(9)}),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "revision_conflict");
    assert_eq!(body["revision"], 1);
    // A change from the stored revision; then a stale one.
    let r = put(
        &one,
        json!({"baseRevision": 1, "revision": 2, "envelope": sealed(3)}),
    );
    assert_eq!(r.status(), StatusCode::OK);
    let r = put(
        &one,
        json!({"baseRevision": 1, "revision": 3, "envelope": sealed(4)}),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    // A revision not above its base.
    let r = put(
        &one,
        json!({"baseRevision": 2, "revision": 2, "envelope": sealed(4)}),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let entries = list()["entries"].as_array().unwrap().clone();
    assert_eq!(entries.len(), 2);
    let found = entries.iter().find(|e| e["id"] == one).unwrap();
    assert_eq!(found["revision"], 2);
    assert_eq!(found["envelope"], sealed(3));

    // The head's index lists the scope's ids and revisions.
    let index: Value = bearer(
        c.get(format!("{base}/api/account/index/chatGroups")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let mut values = index["values"].as_array().unwrap().clone();
    values.sort_by_key(|v| v[0].as_str().unwrap().to_owned());
    assert_eq!(values, vec![json!([one, 2]), json!([two, 5])]);

    // Not an entry: refused without touching anything.
    for bad in ["short", &format!("{one}="), &STANDARD.encode([0xfbu8; 32])] {
        let r = put(
            bad,
            json!({"baseRevision": 0, "revision": 1, "envelope": sealed(1)}),
        );
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{bad}");
    }
    let r = put(
        &entry_id(3),
        json!({"baseRevision": 0, "revision": 1, "envelope": STANDARD.encode(vec![0u8; 4097])}),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Removal from the stored revision only.
    let delete = |id: &str, base_revision: i64| {
        bearer(
            c.delete(format!("{base}/api/chat/group-list/{id}")),
            &user.token,
        )
        .json(&json!({"baseRevision": base_revision}))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(delete(&two, 4), StatusCode::CONFLICT);
    assert_eq!(delete(&two, 5), StatusCode::NO_CONTENT);
    assert_eq!(delete(&two, 5), StatusCode::NOT_FOUND);
    assert_eq!(list()["entries"].as_array().unwrap().len(), 1);

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
