//! Live isolation test for the intentionally breaking Phase C migration 034.
//!
//! Run with a disposable PostgreSQL database URL in `KUTUP_TEST_DB`.

use sqlx::{Connection as _, PgConnection};
use uuid::Uuid;

const FOUNDATION: &str = include_str!("../migrations/033_unified_federation_foundation.up.sql");
const CUTOVER: &str = include_str!("../migrations/034_federation_v2_chat_cutover.up.sql");
const CUTOVER_DOWN: &str = include_str!("../migrations/034_federation_v2_chat_cutover.down.sql");

#[tokio::test]
async fn phase_c_clears_only_v1_chat_transport_and_preserves_product_and_drive_data() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        return;
    };
    let mut connection = PgConnection::connect(&database_url).await.unwrap();
    let schema = format!("federation_phase_c_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();

    sqlx::raw_sql(
        "CREATE TABLE admin_audit_log (
             id BIGSERIAL PRIMARY KEY, admin_user_id UUID NOT NULL,
             action TEXT NOT NULL, target_user_id UUID, payload JSONB NOT NULL,
             occurred_at TIMESTAMPTZ NOT NULL DEFAULT now());
         CREATE TABLE local_chat_data (marker TEXT NOT NULL);
         CREATE TABLE local_drive_data (marker TEXT NOT NULL);
         CREATE TABLE federated_outgoing_shares (marker TEXT NOT NULL);
         CREATE TABLE chat_federation_policy (singleton BOOLEAN PRIMARY KEY, mode TEXT NOT NULL);
         CREATE TABLE chat_federation_domain_rules (domain TEXT PRIMARY KEY);
         CREATE TABLE chat_federation_sequences (destination TEXT PRIMARY KEY);
         CREATE TABLE chat_federation_outbox (id UUID PRIMARY KEY);
         CREATE TABLE chat_federation_inbound_state (origin TEXT PRIMARY KEY);
         CREATE TABLE chat_federation_inbound_transactions (id UUID PRIMARY KEY);
         INSERT INTO local_chat_data VALUES ('local-chat');
         INSERT INTO local_drive_data VALUES ('local-drive');
         INSERT INTO federated_outgoing_shares VALUES ('drive-v1');
         INSERT INTO chat_federation_policy VALUES (TRUE, 'open');
         INSERT INTO chat_federation_domain_rules VALUES ('peer.example');
         INSERT INTO chat_federation_sequences VALUES ('peer.example');
         INSERT INTO chat_federation_outbox VALUES ('00000000-0000-4000-8000-000000000001');
         INSERT INTO chat_federation_inbound_state VALUES ('peer.example');
         INSERT INTO chat_federation_inbound_transactions VALUES ('00000000-0000-4000-8000-000000000002');",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::raw_sql(FOUNDATION)
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(CUTOVER)
        .execute(&mut connection)
        .await
        .unwrap();

    for (table, marker) in [
        ("local_chat_data", "local-chat"),
        ("local_drive_data", "local-drive"),
        ("federated_outgoing_shares", "drive-v1"),
    ] {
        let stored: String = sqlx::query_scalar(&format!("SELECT marker FROM {table}"))
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(stored, marker);
    }
    for table in [
        "chat_federation_sequences",
        "chat_federation_outbox",
        "chat_federation_inbound_state",
        "chat_federation_inbound_transactions",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} must be reset at the auth cut-over");
    }
    let old_policy_tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = current_schema()
           AND table_name IN ('chat_federation_policy', 'chat_federation_domain_rules')",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(old_policy_tables, 0);
    let discovery_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'federation_peer_identities'
           AND column_name IN ('current_api_base', 'capabilities',
                               'discovery_expires_at', 'last_discovery_error')",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(discovery_columns, 4);

    sqlx::raw_sql(CUTOVER_DOWN)
        .execute(&mut connection)
        .await
        .unwrap();
    let restored_policy_tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = current_schema()
           AND table_name IN ('chat_federation_policy', 'chat_federation_domain_rules')",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(restored_policy_tables, 2);
    let removed_discovery_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'federation_peer_identities'
           AND column_name IN ('current_api_base', 'capabilities',
                               'discovery_expires_at', 'last_discovery_error')",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(removed_discovery_columns, 0);
    let local_chat_after_down: String = sqlx::query_scalar("SELECT marker FROM local_chat_data")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(local_chat_after_down, "local-chat");

    sqlx::query("SET search_path TO public")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .unwrap();
}
