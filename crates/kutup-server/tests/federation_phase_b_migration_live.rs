//! Live isolation test for additive federation migration 033.
//!
//! Run with a disposable PostgreSQL database URL:
//! `KUTUP_TEST_DB=postgres://... cargo test -p kutup-server --test federation_phase_b_migration_live`.

use sqlx::{Connection as _, PgConnection};
use uuid::Uuid;

const MIGRATION: &str = include_str!("../migrations/033_unified_federation_foundation.up.sql");

#[tokio::test]
async fn phase_b_migration_is_additive_and_keeps_v1_rows() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        return;
    };
    let mut connection = PgConnection::connect(&database_url).await.unwrap();
    let schema = format!("federation_phase_b_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();

    sqlx::raw_sql(
        "CREATE TABLE chat_federation_policy (marker TEXT NOT NULL);\
         CREATE TABLE chat_federation_outbox (marker TEXT NOT NULL);\
         CREATE TABLE federated_outgoing_shares (marker TEXT NOT NULL);\
         CREATE TABLE federated_incoming_shares (marker TEXT NOT NULL);\
         INSERT INTO chat_federation_policy VALUES ('policy-v1');\
         INSERT INTO chat_federation_outbox VALUES ('chat-v1');\
         INSERT INTO federated_outgoing_shares VALUES ('drive-out-v1');\
         INSERT INTO federated_incoming_shares VALUES ('drive-in-v1');",
    )
    .execute(&mut connection)
    .await
    .unwrap();

    sqlx::raw_sql(MIGRATION)
        .execute(&mut connection)
        .await
        .unwrap();

    for (table, marker) in [
        ("chat_federation_policy", "policy-v1"),
        ("chat_federation_outbox", "chat-v1"),
        ("federated_outgoing_shares", "drive-out-v1"),
        ("federated_incoming_shares", "drive-in-v1"),
    ] {
        let stored: String = sqlx::query_scalar(&format!("SELECT marker FROM {table}"))
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(stored, marker);
    }

    let generic_tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = current_schema()
           AND table_name = ANY($1)",
    )
    .bind(
        &[
            "federation_local_identity_documents",
            "federation_peer_identities",
            "federation_peer_identity_documents",
            "federation_request_replays",
            "federation_policy",
            "federation_feature_policies",
            "federation_domain_rules",
        ][..],
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(generic_tables, 7);

    let policies: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT feature, mode, minimum_trust
         FROM federation_feature_policies ORDER BY feature",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        policies,
        vec![
            ("chat".into(), "allowlist".into(), "verified".into()),
            ("drive".into(), "allowlist".into(), "verified".into()),
        ]
    );

    sqlx::query("SET search_path TO public")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .unwrap();
}

#[test]
fn phase_b_migration_contains_no_legacy_destructive_statement() {
    let normalized = MIGRATION.to_ascii_lowercase();
    for forbidden in [
        "drop table chat_federation",
        "alter table chat_federation",
        "drop table federated_outgoing_shares",
        "alter table federated_outgoing_shares",
        "drop table federated_incoming_shares",
        "alter table federated_incoming_shares",
    ] {
        assert!(!normalized.contains(forbidden), "found `{forbidden}`");
    }
}
