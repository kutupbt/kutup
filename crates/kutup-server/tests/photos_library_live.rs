//! The Photos library record (docs/plans/photos.md) against a live server:
//! an account record of the account (its key binding) for its current
//! incarnation, chained, stored only as the successor of what is stored.
//!
//! Needs `KUTUP_LIVE_SERVER`.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use kutup_crypto::account_record::MasterKeyGeneration;
use kutup_crypto::photos_library::{self, PhotosLibraryContextV1, PhotosLibraryV1};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn base() -> Option<String> {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return None;
    };
    Some(base)
}

/// A record marking `favourite` as a favourite, sealed with `master_key` for
/// `binding` and `incarnation`, at `revision` after `previous`.
fn record(
    master_key: &[u8; 32],
    binding: &str,
    incarnation: &str,
    revision: u64,
    previous: Option<&str>,
    favourite: &str,
) -> String {
    let library = PhotosLibraryV1 {
        favourites: vec![favourite.into()],
        ..PhotosLibraryV1::default()
    };
    let context = PhotosLibraryContextV1::new(incarnation, revision, previous).unwrap();
    STANDARD.encode(
        photos_library::seal(
            &photos_library::encode_library(&library).unwrap(),
            master_key,
            MasterKeyGeneration::FIRST,
            binding,
            context,
        )
        .unwrap(),
    )
}

fn put(c: &Client, base: &str, user: &User, envelope: &str) -> (StatusCode, Value) {
    let response = bearer(c.put(format!("{base}/api/photos/library")), &user.token)
        .json(&json!({ "envelope": envelope }))
        .send()
        .unwrap();
    let status = response.status();
    (status, response.json().unwrap_or(Value::Null))
}

#[test]
fn the_library_is_this_accounts_chain_and_nothing_else() {
    let Some(base) = base() else { return };
    let c = client();
    let user = register(&c, &base);
    let other = register(&c, &base);
    let incarnation = user.identity.incarnation_id();
    let first_photo = "11111111-1111-4111-8111-111111111111";
    let second_photo = "22222222-2222-4222-8222-222222222222";

    // Another account's record, or one for another incarnation: refused
    // before anything is stored.
    let foreign = record(
        &user.master_key,
        &other.binding,
        &incarnation,
        1,
        None,
        first_photo,
    );
    assert_eq!(put(&c, &base, &user, &foreign).0, StatusCode::BAD_REQUEST);
    let other_incarnation = other.identity.incarnation_id();
    let elsewhere = record(
        &user.master_key,
        &user.binding,
        &other_incarnation,
        1,
        None,
        first_photo,
    );
    assert_eq!(put(&c, &base, &user, &elsewhere).0, StatusCode::BAD_REQUEST);

    // The first record, then its successor.
    let first = record(
        &user.master_key,
        &user.binding,
        &incarnation,
        1,
        None,
        first_photo,
    );
    let (status, stored) = put(&c, &base, &user, &first);
    assert_eq!(status, StatusCode::OK, "{stored}");
    let first_digest = stored["envelopeDigest"].as_str().unwrap().to_string();
    let second = record(
        &user.master_key,
        &user.binding,
        &incarnation,
        2,
        Some(&first_digest),
        second_photo,
    );
    assert_eq!(put(&c, &base, &user, &second).0, StatusCode::OK);

    // Another device's successor of the first record lost the race: 409 with
    // the stored record, which opens as revision 2.
    let stale = record(
        &user.master_key,
        &user.binding,
        &incarnation,
        2,
        Some(&first_digest),
        first_photo,
    );
    let (status, current) = put(&c, &base, &user, &stale);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(current["revision"], 2);
    let envelope = STANDARD
        .decode(current["envelope"].as_str().unwrap())
        .unwrap();
    let header = photos_library::inspect(&envelope).unwrap();
    let opened = photos_library::open(&envelope, &user.master_key, &user.binding, header).unwrap();
    assert_eq!(
        photos_library::decode_library(&opened).unwrap().favourites,
        vec![second_photo.to_string()]
    );

    // What GET answers is the stored record.
    let fetched: Value = bearer(c.get(format!("{base}/api/photos/library")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(fetched["envelope"], current["envelope"]);
}

#[test]
fn only_the_stored_records_successor_is_taken_and_a_replay_changes_nothing() {
    let Some(base) = base() else { return };
    let c = client();
    let user = register(&c, &base);
    let incarnation = user.identity.incarnation_id();
    let photo = "33333333-3333-4333-8333-333333333333";
    let seal = |revision: u64, previous: Option<&str>, favourite: &str| {
        record(
            &user.master_key,
            &user.binding,
            &incarnation,
            revision,
            previous,
            favourite,
        )
    };

    let first = seal(1, None, photo);
    let (status, stored) = put(&c, &base, &user, &first);
    assert_eq!(status, StatusCode::OK, "{stored}");
    let first_digest = stored["envelopeDigest"].as_str().unwrap().to_string();

    // The same record again (a retry after a lost answer): taken, unchanged.
    let (status, again) = put(&c, &base, &user, &first);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["envelopeDigest"], first_digest);

    // Another first record while one is stored: 409 with the stored one.
    let (status, current) = put(
        &c,
        &base,
        &user,
        &seal(1, None, "44444444-4444-4444-8444-444444444444"),
    );
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(current["envelopeDigest"], first_digest);

    // Revision 2 naming a predecessor that isn't the stored record: 409.
    let wrong = "55".repeat(32);
    let (status, current) = put(&c, &base, &user, &seal(2, Some(&wrong), photo));
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(current["revision"], 1);

    // Revision 3 skipping 2: 409.
    let (status, _) = put(&c, &base, &user, &seal(3, Some(&first_digest), photo));
    assert_eq!(status, StatusCode::CONFLICT);
}

#[test]
fn two_first_records_at_once_store_one() {
    let Some(base) = base() else { return };
    let c = client();
    for round in 0..5 {
        // A fresh account each round: two devices' first marks race.
        let user = register(&c, &base);
        let incarnation = user.identity.incarnation_id();
        let a = record(
            &user.master_key,
            &user.binding,
            &incarnation,
            1,
            None,
            "66666666-6666-4666-8666-666666666666",
        );
        let b = record(
            &user.master_key,
            &user.binding,
            &incarnation,
            1,
            None,
            "77777777-7777-4777-8777-777777777777",
        );
        let barrier = std::sync::Barrier::new(2);
        let statuses: Vec<StatusCode> = std::thread::scope(|scope| {
            let runs = [a, b].map(|envelope| {
                let (c, base, user, barrier) = (&c, &base, &user, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    put(c, base, user, &envelope).0
                })
            });
            runs.into_iter().map(|run| run.join().unwrap()).collect()
        });
        let mut sorted = statuses.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![StatusCode::OK, StatusCode::CONFLICT],
            "round {round}: {statuses:?}"
        );
    }
}
