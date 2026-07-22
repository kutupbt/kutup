//! Live isolation test for the intentionally breaking Phase D migration 035.
//!
//! Run with a disposable PostgreSQL database URL in `KUTUP_TEST_DB`.

use sqlx::{Connection as _, PgConnection};
use uuid::Uuid;

const CUTOVER: &str = include_str!("../migrations/035_federation_v2_drive_cutover.up.sql");
const CUTOVER_DOWN: &str = include_str!("../migrations/035_federation_v2_drive_cutover.down.sql");

#[tokio::test]
async fn phase_d_replaces_only_drive_federation_state_and_preserves_local_product_data() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        return;
    };
    let mut connection = PgConnection::connect(&database_url).await.unwrap();
    let schema = format!("federation_phase_d_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();

    sqlx::raw_sql(
        "CREATE TABLE users (id UUID PRIMARY KEY, marker TEXT NOT NULL);
         CREATE TABLE collections (
             id UUID PRIMARY KEY,
             owner_user_id UUID NOT NULL REFERENCES users(id),
             marker TEXT NOT NULL);
         CREATE TABLE files (
             id UUID PRIMARY KEY,
             collection_id UUID NOT NULL REFERENCES collections(id),
             marker TEXT NOT NULL,
             created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
             deleted_at TIMESTAMPTZ);
         CREATE TABLE local_chat_data (marker TEXT NOT NULL);
         CREATE TABLE federated_outgoing_shares (marker TEXT NOT NULL);
         CREATE TABLE federated_incoming_shares (marker TEXT NOT NULL);
         INSERT INTO users VALUES
             ('00000000-0000-4000-8000-000000000001', 'local-user');
         INSERT INTO collections VALUES
             ('00000000-0000-4000-8000-000000000002',
              '00000000-0000-4000-8000-000000000001', 'local-collection');
         INSERT INTO files (id, collection_id, marker) VALUES
             ('00000000-0000-4000-8000-000000000003',
              '00000000-0000-4000-8000-000000000002', 'local-file');
         INSERT INTO local_chat_data VALUES ('local-chat');
         INSERT INTO federated_outgoing_shares VALUES ('drive-out-v1');
         INSERT INTO federated_incoming_shares VALUES ('drive-in-v1');",
    )
    .execute(&mut connection)
    .await
    .unwrap();

    sqlx::raw_sql(CUTOVER)
        .execute(&mut connection)
        .await
        .unwrap();

    for (table, marker) in [
        ("users", "local-user"),
        ("collections", "local-collection"),
        ("files", "local-file"),
        ("local_chat_data", "local-chat"),
    ] {
        let stored: String = sqlx::query_scalar(&format!("SELECT marker FROM {table}"))
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(stored, marker);
    }

    let drive_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT table_name, row_count FROM (
             SELECT 'federated_outgoing_shares'::text AS table_name,
                    COUNT(*)::bigint AS row_count FROM federated_outgoing_shares
             UNION ALL
             SELECT 'federated_incoming_shares', COUNT(*)::bigint
                    FROM federated_incoming_shares
             UNION ALL
             SELECT 'drive_federation_mutations', COUNT(*)::bigint
                    FROM drive_federation_mutations
         ) rows ORDER BY table_name",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap();
    assert!(drive_rows.iter().all(|(_, count)| *count == 0));

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND ((table_name = 'federated_outgoing_shares'
                 AND column_name IN ('recipient_domain', 'capability_hash'))
             OR (table_name = 'federated_incoming_shares'
                 AND column_name IN ('remote_domain', 'remote_capability', 'capability_hash'))
             OR (table_name = 'files' AND column_name = 'ciphertext_sha256'))
         ORDER BY column_name",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap();
    assert_eq!(columns.len(), 6);
    for forbidden in [
        "recipient_server",
        "access_token",
        "remote_server",
        "remote_access_token",
    ] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema() AND column_name = $1",
        )
        .bind(forbidden)
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(count, 0, "legacy column {forbidden} must be absent");
    }

    sqlx::raw_sql(CUTOVER_DOWN)
        .execute(&mut connection)
        .await
        .unwrap();
    let restored_legacy_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND column_name IN ('recipient_server', 'access_token',
                               'remote_server', 'remote_access_token')",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(restored_legacy_columns, 4);
    let digest_column: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'files' AND column_name = 'ciphertext_sha256'",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(digest_column, 0);
    let local_file: String = sqlx::query_scalar("SELECT marker FROM files")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(local_file, "local-file");

    sqlx::query("SET search_path TO public")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .unwrap();
}
