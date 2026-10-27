//! The federation outbox migration (`20261027120000`,
//! docs/plans/federation-outbox.md) with deliveries mid-flight on both
//! sides: the database is migrated to the one before, given plain and sealed
//! chat rows in the old tables (pending, mismatched, delivered and rejected,
//! their sequences, and an origin's high-water marks and answers), then
//! migrated on; every row, sequence and mark must carry across, so peers
//! mid-stream see no gap.
//!
//! Needs `KUTUP_TEST_DB`: a disposable, empty database (the two-server gate
//! makes one).

use std::borrow::Cow;

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

const OUTBOX_MIGRATION: i64 = 20261027120000;

#[derive(sqlx::FromRow)]
struct OutboxRow {
    kind: String,
    sequence: i64,
    state: String,
    error_class: Option<String>,
    answer: Option<Value>,
}

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, master_key_envelope, recovery_key_envelope,
             drive_private_key_envelope, public_key, account_authority_public_key,
             account_authority_key_id, account_incarnation_id, drive_signing_public_key,
             username)
         VALUES ($1, '', '', '', '', '', '', '', '', $2)",
    )
    .bind(id)
    .bind(format!("mig{}", &id.simple().to_string()[..12]))
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn deliveries_mid_flight_carry_across() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        eprintln!("KUTUP_TEST_DB unset; skipping");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let all = sqlx::migrate!("./migrations");
    let mut before = sqlx::migrate!("./migrations");
    before.migrations = Cow::Owned(
        all.migrations
            .iter()
            .filter(|migration| migration.version < OUTBOX_MIGRATION)
            .cloned()
            .collect(),
    );
    before.run(&pool).await.unwrap();

    // Plain chat to peer.test: 1 delivered, 2 a pending mismatch (the old
    // shape), 3 pending; the next sequence to take is 4.
    let sender = user(&pool).await;
    let recipient = Uuid::new_v4();
    let request =
        |n: u32| json!({ "senderDeviceId": 1, "sendId": format!("s{n}"), "envelopes": [] });
    for (sequence, state, response) in [
        (
            1_i64,
            "delivered",
            Some(json!({ "stored": 1, "acceptedSequence": 1 })),
        ),
        (
            2,
            "mismatch",
            Some(json!({ "code": "deviceListMismatch", "missingDevices": [2] })),
        ),
        (3, "pending", None),
    ] {
        sqlx::query(
            "INSERT INTO chat_federation_outbox
                 (id, destination, sequence, sender_user_id, sender_device_id, send_id,
                  request, state, response, recipient_account_id)
             VALUES (gen_random_uuid(), 'peer.test', $1, $2, 1, $3, $4, $5, $6, $7)",
        )
        .bind(sequence)
        .bind(sender)
        .bind(format!("s{sequence}"))
        .bind(request(sequence as u32))
        .bind(state)
        .bind(response)
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO chat_federation_sequences VALUES ('peer.test', 4)")
        .execute(&pool)
        .await
        .unwrap();
    // As a receiver: origin.test's plain stream used up 7, with its answers.
    sqlx::query("INSERT INTO chat_federation_inbound_state (origin, last_sequence) VALUES ('origin.test', 7)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chat_federation_inbound_transactions (origin, sequence, transaction_id, response)
         VALUES ('origin.test', 7, 'tx7', '{\"stored\": 2, \"acceptedSequence\": 7}')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Sealed to peer.test: 4 rejected (with its answer), 5 pending; the next
    // is 6. As a receiver, origin.test's sealed stream answered 1 to 3.
    let sealed = |sequence: i64, state: &'static str, class: Option<&'static str>| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO chat_sealed_federation_outbox
                     (destination, sequence, sender_user_id, send_id, transaction, state,
                      last_error_class, answer, recipient_account_id)
                 VALUES ('peer.test', $1, $2, gen_random_uuid(), '{\"version\": 2}', $3, $4,
                         CASE WHEN $3 = 'rejected' THEN '{\"code\": \"refused\"}'::jsonb END,
                         gen_random_uuid())",
            )
            .bind(sequence)
            .bind(sender)
            .bind(state)
            .bind(class)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    sealed(4, "rejected", Some("refused")).await;
    sealed(5, "pending", Some("transport")).await;
    sqlx::query("INSERT INTO chat_sealed_federation_sequences VALUES ('peer.test', 6)")
        .execute(&pool)
        .await
        .unwrap();
    for (sequence, status) in [(1_i64, 200_i16), (2, 409), (3, 400)] {
        sqlx::query(
            "INSERT INTO chat_sealed_federation_inbound
                 (origin, sequence, send_id, response_status, response)
             VALUES ('origin.test', $1, gen_random_uuid(), $2, '{}')",
        )
        .bind(sequence)
        .bind(status)
        .execute(&pool)
        .await
        .unwrap();
    }

    all.run(&pool).await.unwrap();

    // The outgoing rows, each kind with its own sequences.
    let rows: Vec<OutboxRow> = sqlx::query_as(
        "SELECT kind, sequence, state, error_class, answer FROM federation_outbox
         WHERE destination = 'peer.test' ORDER BY kind, sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let shape: Vec<(&str, i64, &str, Option<&str>)> = rows
        .iter()
        .map(|row| {
            (
                row.kind.as_str(),
                row.sequence,
                row.state.as_str(),
                row.error_class.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        [
            ("chat", 1, "delivered", None),
            // A pending mismatch is the final answer it was.
            ("chat", 2, "rejected", Some("device_mismatch")),
            ("chat", 3, "pending", None),
            ("sealed", 4, "rejected", Some("refused")),
            ("sealed", 5, "pending", Some("transport")),
        ]
    );
    assert_eq!(
        rows[1].answer.as_ref().unwrap()["code"],
        "deviceListMismatch"
    );
    assert_eq!(rows[3].answer.as_ref().unwrap()["code"], "refused");
    // The plain rows keep their sender and request; their key is the old
    // unique triple.
    let (key, payload): (String, Value) = sqlx::query_as(
        "SELECT idempotency_key, payload FROM federation_outbox
         WHERE kind = 'chat' AND sequence = 3",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(key, format!("{sender}:1:s3"));
    assert_eq!(payload["sender"], sender.to_string());
    assert_eq!(payload["request"]["sendId"], "s3");

    // The next sequences carry on where they were.
    let next: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, next_sequence FROM federation_sequences
         WHERE destination = 'peer.test' ORDER BY kind",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(next, [("chat".to_owned(), 4), ("sealed".to_owned(), 6)]);

    // The receiving side: each stream's mark, and its answers to replay.
    let marks: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, last_sequence FROM federation_inbound_state
         WHERE origin = 'origin.test' ORDER BY kind",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(marks, [("chat".to_owned(), 7), ("sealed".to_owned(), 3)]);
    let answers: Vec<(String, i64, i16)> = sqlx::query_as(
        "SELECT kind, sequence, status FROM federation_inbound
         WHERE origin = 'origin.test' ORDER BY kind, sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        answers,
        [
            ("chat".to_owned(), 7, 200),
            ("sealed".to_owned(), 1, 200),
            ("sealed".to_owned(), 2, 409),
            ("sealed".to_owned(), 3, 400),
        ]
    );

    // The old tables are gone.
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables
         WHERE table_name IN ('chat_federation_outbox', 'chat_sealed_federation_outbox',
                              'chat_federation_inbound_state', 'chat_sealed_federation_inbound')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}
