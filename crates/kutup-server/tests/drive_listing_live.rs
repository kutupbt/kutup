//! Live e2e for `GET /api/drive/files`: every file in the folders an
//! account owns or has been given, in one request, and nothing else.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test drive_listing_live -- --nocapture

use reqwest::blocking::Client;
use serde_json::Value;

mod common;
use common::*;

fn all_files(c: &Client, base: &str, user: &User) -> Vec<String> {
    let rows: Vec<Value> = bearer(c.get(format!("{base}/api/drive/files")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    rows.iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn one_listing_of_every_readable_folder() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = Client::new();
    let owner = register(&c, &base);
    let friend = register(&c, &base);
    let stranger = register(&c, &base);

    let a = create_folder(&c, &base, &owner);
    let b = create_folder_in(&c, &base, &owner, Some(&a.id));
    let in_a = seal_file(&a, &uuid(), b"a");
    let in_b = seal_file(&b, &uuid(), b"b");
    let trashed = seal_file(&a, &uuid(), b"gone");
    for (folder, file) in [(&a, &in_a), (&b, &in_b), (&a, &trashed)] {
        assert!(upload(&c, &base, &owner.token, folder, file)
            .status()
            .is_success());
    }
    let r = bearer(
        c.delete(format!("{base}/api/files/{}", trashed.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());

    // A folder of the friend's, shared with the owner.
    let theirs = create_folder(&c, &base, &friend);
    let shared_file = seal_file(&theirs, &uuid(), b"shared");
    assert!(upload(&c, &base, &friend.token, &theirs, &shared_file)
        .status()
        .is_success());
    share(&c, &base, &friend, &theirs, &owner, false);

    let mut seen = all_files(&c, &base, &owner);
    seen.sort();
    let mut expected = vec![in_a.id.clone(), in_b.id.clone(), shared_file.id.clone()];
    expected.sort();
    assert_eq!(seen, expected);

    // Each row is what the folder's own listing gives.
    let rows: Vec<Value> = bearer(c.get(format!("{base}/api/drive/files")), &owner.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let row = rows.iter().find(|r| r["id"] == in_b.id).unwrap();
    assert_eq!(row["collectionId"], b.id);
    assert_eq!(row["fileKeyEnvelope"], in_b.file_key_envelope);

    // The friend sees only their own; a stranger nothing.
    assert_eq!(all_files(&c, &base, &friend), vec![shared_file.id.clone()]);
    assert!(all_files(&c, &base, &stranger).is_empty());
    let r = c.get(format!("{base}/api/drive/files")).send().unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);
}
