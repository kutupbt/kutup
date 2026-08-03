//! Clean-database gate for the pre-v1 cryptographic format cutover.
//!
//! Run only against a disposable empty database with `KUTUP_TEST_DB`.

use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn all_migrations_build_the_exact_v1_manifest_and_mls_schema() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let user_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'users'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for required in [
        "master_key_envelope",
        "recovery_key_envelope",
        "drive_private_key_envelope",
        "account_authority_public_key",
        "account_authority_key_id",
        "account_incarnation_id",
        "drive_signing_public_key",
    ] {
        assert!(user_columns.iter().any(|column| column == required));
    }
    for removed in [
        "encrypted_master_key",
        "master_key_nonce",
        "encrypted_recovery_key",
        "recovery_key_nonce",
        "encrypted_private_key",
        "private_key_nonce",
    ] {
        assert!(!user_columns.iter().any(|column| column == removed));
    }

    let collection_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'collections'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for required in [
        "name_envelope",
        "owner_key_envelope",
        "key_epoch",
        "name_revision",
        "epoch_statement",
        "epoch_statement_hash",
    ] {
        assert!(collection_columns.iter().any(|column| column == required));
    }
    for removed in [
        "encrypted_name",
        "name_nonce",
        "encrypted_key",
        "encrypted_key_nonce",
    ] {
        assert!(!collection_columns.iter().any(|column| column == removed));
    }
    let collection_id_has_default: bool = sqlx::query_scalar(
        "SELECT column_default IS NOT NULL FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'collections' AND column_name = 'id'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !collection_id_has_default,
        "collection ids must be client-generated"
    );

    for table in ["files", "uploads"] {
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table)
        .fetch_all(&pool)
        .await
        .unwrap();
        for required in [
            "file_id",
            "metadata_envelope",
            "file_key_envelope",
            "key_epoch",
            "metadata_revision",
        ] {
            if table == "files" && required == "file_id" {
                continue;
            }
            assert!(
                columns.iter().any(|column| column == required),
                "{table}.{required} must exist"
            );
        }
        for removed in [
            "encrypted_metadata",
            "metadata_nonce",
            "encrypted_file_key",
            "file_key_nonce",
        ] {
            assert!(
                !columns.iter().any(|column| column == removed),
                "{table}.{removed} must not exist"
            );
        }
    }
    let file_id_has_default: bool = sqlx::query_scalar(
        "SELECT column_default IS NOT NULL FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'files' AND column_name = 'id'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!file_id_has_default, "file ids must be client-generated");

    let epoch_history_primary_key: Vec<String> = sqlx::query_scalar(
        "SELECT a.attname
         FROM pg_index i
         JOIN pg_attribute a
           ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
         WHERE i.indrelid = 'collection_key_epoch_history'::regclass
           AND i.indisprimary
         ORDER BY array_position(i.indkey, a.attnum)",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(epoch_history_primary_key, ["collection_id", "epoch"]);

    let local_share_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'collection_shares'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(local_share_columns
        .iter()
        .any(|column| column == "named_share_envelope"));
    assert!(!local_share_columns
        .iter()
        .any(|column| column == "encrypted_collection_key"));

    let federated_share_columns: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || '.' || column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name IN ('federated_outgoing_shares', 'federated_incoming_shares')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(federated_share_columns
        .iter()
        .any(|column| column == "federated_outgoing_shares.named_share_envelope"));
    assert!(federated_share_columns
        .iter()
        .any(|column| column == "federated_incoming_shares.epoch_statement"));
    assert!(!federated_share_columns
        .iter()
        .any(|column| column.ends_with(".encrypted_collection_key")));

    let public_share_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'public_shares'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for required in [
        "collection_key_envelope",
        "collection_key_epoch",
        "owner_user_id",
    ] {
        assert!(public_share_columns.iter().any(|column| column == required));
    }
    for removed in ["encrypted_collection_key", "encrypted_collection_key_nonce"] {
        assert!(!public_share_columns.iter().any(|column| column == removed));
    }

    let history_primary_key: Vec<String> = sqlx::query_scalar(
        "SELECT a.attname
         FROM pg_index i
         JOIN pg_attribute a
           ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
         WHERE i.indrelid = 'chat_device_manifest_history'::regclass
           AND i.indisprimary
         ORDER BY array_position(i.indkey, a.attnum)",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        history_primary_key,
        ["user_id", "incarnation_id", "version"]
    );

    let constraints: Vec<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE conrelid IN (
           'chat_mls_devices'::regclass,
           'chat_mls_incarnations'::regclass
         )",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let constraints = constraints.join("\n").replace(' ', "");
    assert!(constraints.contains("suite=3"));
    assert!(constraints.contains("member_count>=1"));
    assert!(constraints.contains("member_count<=256"));

    let profile_suite_constraint: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE conrelid = 'chat_profiles'::regclass
           AND pg_get_constraintdef(oid) LIKE '%suite%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(profile_suite_constraint
        .replace(' ', "")
        .contains("suite=1"));

    let removed_tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = 'public'
           AND table_name LIKE 'chat_transparency%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(removed_tables, 0);
}
