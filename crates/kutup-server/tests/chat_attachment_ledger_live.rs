//! The Chat attachment ledger (docs/chat-media.md) against a live server: one
//! chained account record per entity, of this account (its key binding), for
//! its current incarnation and the entity in the URL, stored only as the
//! successor of what is stored.
//!
//! Needs `KUTUP_LIVE_SERVER`.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use kutup_crypto::account_record::MasterKeyGeneration;
use kutup_crypto::chat_attachment_ledger::{self, ChatAttachmentLedgerContextV1};
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

/// `entity`'s record at `revision` after `previous`, sealed with `user`'s
/// master key for `binding` and `incarnation`.
fn record(
    user: &User,
    binding: &str,
    incarnation: &str,
    entity: &str,
    revision: u64,
    previous: Option<&str>,
    plaintext: &[u8],
) -> String {
    let context =
        ChatAttachmentLedgerContextV1::new(incarnation, entity, revision, previous).unwrap();
    STANDARD.encode(
        chat_attachment_ledger::seal(
            plaintext,
            &user.master_key,
            MasterKeyGeneration::FIRST,
            binding,
            context,
        )
        .unwrap(),
    )
}

fn put(c: &Client, base: &str, user: &User, entity: &str, envelope: &str) -> (StatusCode, Value) {
    let operation = uuid::Uuid::new_v4().to_string();
    let response = bearer(
        c.put(format!("{base}/api/chat/media/ledger/{entity}")),
        &user.token,
    )
    .json(&json!({ "operationId": operation, "envelope": envelope }))
    .send()
    .unwrap();
    let status = response.status();
    (status, response.json().unwrap_or(Value::Null))
}

#[test]
fn a_ledger_record_is_this_accounts_for_its_entity_and_follows_the_stored_one() {
    let Some(base) = base() else { return };
    let c = client();
    let user = register(&c, &base);
    let other = register(&c, &base);
    let incarnation = user.identity.incarnation_id();
    let entity = "88888888-8888-4888-8888-888888888888";

    // Another account's record (its binding), or one for another entity than
    // the URL's: refused before anything is stored.
    let foreign = record(
        &user,
        &other.binding,
        &incarnation,
        entity,
        1,
        None,
        b"entry",
    );
    assert_eq!(
        put(&c, &base, &user, entity, &foreign).0,
        StatusCode::BAD_REQUEST
    );
    let elsewhere = record(
        &user,
        &user.binding,
        &incarnation,
        "99999999-9999-4999-8999-999999999999",
        1,
        None,
        b"entry",
    );
    assert_eq!(
        put(&c, &base, &user, entity, &elsewhere).0,
        StatusCode::BAD_REQUEST
    );

    let first = record(
        &user,
        &user.binding,
        &incarnation,
        entity,
        1,
        None,
        b"entry",
    );
    let (status, receipt) = put(&c, &base, &user, entity, &first);
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let first_digest = receipt["envelopeDigest"].as_str().unwrap().to_string();

    // A second revision naming another predecessor, or a second first one:
    // 409.
    let wrong = "55".repeat(32);
    let detached = record(
        &user,
        &user.binding,
        &incarnation,
        entity,
        2,
        Some(&wrong),
        b"later",
    );
    assert_eq!(
        put(&c, &base, &user, entity, &detached).0,
        StatusCode::CONFLICT
    );
    let again = record(
        &user,
        &user.binding,
        &incarnation,
        entity,
        1,
        None,
        b"other",
    );
    assert_eq!(
        put(&c, &base, &user, entity, &again).0,
        StatusCode::CONFLICT
    );

    // Its successor is taken.
    let second = record(
        &user,
        &user.binding,
        &incarnation,
        entity,
        2,
        Some(&first_digest),
        b"later",
    );
    assert_eq!(put(&c, &base, &user, entity, &second).0, StatusCode::OK);
}

#[test]
fn two_first_records_of_one_entity_at_once_store_one() {
    let Some(base) = base() else { return };
    let c = client();
    let user = register(&c, &base);
    let incarnation = user.identity.incarnation_id();
    for round in 0..5u32 {
        let entity = format!("aaaaaaaa-aaaa-4aaa-8aaa-{round:012}");
        let a = record(
            &user,
            &user.binding,
            &incarnation,
            &entity,
            1,
            None,
            b"from a",
        );
        let b = record(
            &user,
            &user.binding,
            &incarnation,
            &entity,
            1,
            None,
            b"from b",
        );
        let barrier = std::sync::Barrier::new(2);
        let statuses: Vec<StatusCode> = std::thread::scope(|scope| {
            let runs = [a, b].map(|envelope| {
                let (c, base, user, entity, barrier) = (&c, &base, &user, &entity, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    put(c, base, user, entity, &envelope).0
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
