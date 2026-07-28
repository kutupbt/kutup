//! Live isolation test for the additive unified MLS migration 037.
//!
//! Run with a disposable PostgreSQL database URL in `KUTUP_TEST_DB`.

use sqlx::{Connection as _, PgConnection};
use uuid::Uuid;

const FOUNDATION: &str = include_str!("../migrations/037_unified_mls_foundation.up.sql");
const FOUNDATION_DOWN: &str = include_str!("../migrations/037_unified_mls_foundation.down.sql");
const MAILBOX_CONSTRAINT: &str =
    include_str!("../migrations/038_mls_mailbox_incarnation_constraint.up.sql");
const MAILBOX_CONSTRAINT_DOWN: &str =
    include_str!("../migrations/038_mls_mailbox_incarnation_constraint.down.sql");
const RECOVERY: &str = include_str!("../migrations/039_mls_incarnation_recovery.up.sql");
const RECOVERY_DOWN: &str = include_str!("../migrations/039_mls_incarnation_recovery.down.sql");

#[tokio::test]
async fn mls_foundation_enforces_metadata_and_append_only_boundaries() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        return;
    };
    let mut connection = PgConnection::connect(&database_url).await.unwrap();
    let schema = format!("mls_foundation_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&mut connection)
        .await
        .unwrap();

    sqlx::raw_sql(
        "CREATE TABLE users (id UUID PRIMARY KEY);
         CREATE TABLE federation_feature_policy_documents (
             domain TEXT NOT NULL,
             feature_type SMALLINT NOT NULL,
             sequence BIGINT NOT NULL,
             CONSTRAINT federation_feature_policy_documents_feature_type_check
                 CHECK (feature_type IN (1, 2))
         );
         CREATE TABLE federation_feature_policy_failures (
             feature_type SMALLINT NOT NULL
         );",
    )
    .execute(&mut connection)
    .await
    .unwrap();

    sqlx::raw_sql(FOUNDATION)
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(MAILBOX_CONSTRAINT)
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(RECOVERY)
        .execute(&mut connection)
        .await
        .unwrap();

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = current_schema()
           AND table_name LIKE 'chat_mls_%'",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(table_count, 27);

    sqlx::query(
        "INSERT INTO federation_feature_policy_documents
             (domain, feature_type, sequence)
         VALUES ('a.example', 3, 1)",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    assert!(sqlx::query(
        "INSERT INTO federation_feature_policy_documents
                 (domain, feature_type, sequence)
             VALUES ('a.example', 4, 1)",
    )
    .execute(&mut connection)
    .await
    .is_err());

    let user_id = Uuid::from_u128(1);
    let conversation_id = Uuid::from_u128(2);
    sqlx::query("INSERT INTO users (id) VALUES ($1)")
        .bind(user_id)
        .execute(&mut connection)
        .await
        .unwrap();

    let mut transaction = connection.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO chat_mls_conversations
             (conversation_id, kind, current_incarnation)
         VALUES ($1, 1, 1)",
    )
    .bind(conversation_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat_mls_incarnations
              (conversation_id, incarnation, mls_group_id, suite,
              roster_commitment, member_count,
              genesis_participant_domains, participant_domains,
              authority_set_sequence, authority_set,
              genesis, genesis_hash)
         VALUES ($1, 1, $2, 2, $3, 1,
                 '[\"a.example\"]'::jsonb, '[\"a.example\"]'::jsonb,
                 1, '{}'::jsonb, '{}'::jsonb, $4)",
    )
    .bind(conversation_id)
    .bind(vec![7u8; 16])
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();

    sqlx::query(
        "INSERT INTO chat_mls_devices
             (user_id, device_id, manifest_version, suite,
              credential_public_key, anonymous_delivery_public_key)
         VALUES ($1, 1, 1, 2, $2, $3)",
    )
    .bind(user_id)
    .bind(vec![4u8; 65])
    .bind(vec![5u8; 65])
    .execute(&mut connection)
    .await
    .unwrap();

    assert!(
        sqlx::query(
            "INSERT INTO chat_mls_local_members
                 (conversation_id, incarnation, user_id, membership_status,
                  joined_epoch)
             VALUES ($1, 1, $2, 'pending', 0)",
        )
        .bind(conversation_id)
        .bind(user_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "pending membership must always have an invitation expiry"
    );
    sqlx::query(
        "INSERT INTO chat_mls_local_members
             (conversation_id, incarnation, user_id, membership_status,
              invitation_expires_at, joined_epoch)
         VALUES ($1, 1, $2, 'pending', now() + interval '30 days', 0)",
    )
    .bind(conversation_id)
    .bind(user_id)
    .execute(&mut connection)
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "UPDATE chat_mls_local_members
             SET membership_status = 'active'
             WHERE conversation_id = $1 AND user_id = $2",
        )
        .bind(conversation_id)
        .bind(user_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "terminal invitation state must clear its expiry atomically"
    );

    sqlx::query(
        "INSERT INTO chat_mls_mailbox
             (recipient_user_id, recipient_device_id, delivery_kind,
              send_id, opaque_envelope)
         VALUES ($1, 1, 'anonymous', $2, $3)",
    )
    .bind(user_id)
    .bind(Uuid::from_u128(3))
    .bind(vec![9u8; 32])
    .execute(&mut connection)
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "INSERT INTO chat_mls_mailbox
                 (recipient_user_id, recipient_device_id, delivery_kind,
                  conversation_id, send_id, opaque_envelope)
             VALUES ($1, 1, 'anonymous', $2, $3, $4)",
        )
        .bind(user_id)
        .bind(conversation_id)
        .bind(Uuid::from_u128(4))
        .bind(vec![9u8; 32])
        .execute(&mut connection)
        .await
        .is_err(),
        "anonymous mailbox rows must not carry a conversation id"
    );
    assert!(
        sqlx::query(
            "INSERT INTO chat_mls_mailbox
                 (recipient_user_id, recipient_device_id, delivery_kind,
                  conversation_id, send_id, opaque_envelope)
             VALUES ($1, 1, 'membership_control', $2, $3, $4)",
        )
        .bind(user_id)
        .bind(conversation_id)
        .bind(Uuid::from_u128(6))
        .bind(vec![8u8; 32])
        .execute(&mut connection)
        .await
        .is_err(),
        "membership-control mailbox rows must bind an exact incarnation"
    );
    sqlx::query(
        "INSERT INTO chat_mls_mailbox
             (recipient_user_id, recipient_device_id, delivery_kind,
              conversation_id, incarnation, send_id, opaque_envelope)
         VALUES ($1, 1, 'membership_control', $2, 1, $3, $4)",
    )
    .bind(user_id)
    .bind(conversation_id)
    .bind(Uuid::from_u128(7))
    .bind(vec![8u8; 32])
    .execute(&mut connection)
    .await
    .unwrap();

    assert!(
        sqlx::query(
            "INSERT INTO chat_mls_federation_outbox
                 (destination, sequence, recipient, send_id, transaction)
             VALUES ('b.example', 1, 'alice@b.example', $1,
                     '{\"sender\":\"mallory\"}'::jsonb)",
        )
        .bind(Uuid::from_u128(5))
        .execute(&mut connection)
        .await
        .is_err(),
        "destination transactions must reject sender metadata"
    );

    sqlx::query(
        "INSERT INTO chat_mls_control_blocks
             (conversation_id, incarnation, height, block_hash,
              epoch_before, epoch_after, block, quorum_certificate,
              commit_request, finalized_at)
         VALUES ($1, 1, 1, $2, 0, 1, '{}'::jsonb, '{}'::jsonb,
                 '{}'::jsonb, now())",
    )
    .bind(conversation_id)
    .bind("33".repeat(32))
    .execute(&mut connection)
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "UPDATE chat_mls_control_blocks SET epoch_after = 2
             WHERE conversation_id = $1",
        )
        .bind(conversation_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "finalized MLS control history must be append-only"
    );

    sqlx::query(
        "INSERT INTO chat_mls_incarnations
              (conversation_id, incarnation, mls_group_id, suite,
               roster_commitment, member_count,
               genesis_participant_domains, participant_domains,
               authority_set_sequence, authority_set,
               genesis, genesis_hash, last_finalized_epoch, status)
         VALUES ($1, 2, $2, 2, $3, 1,
                 '[\"a.example\"]'::jsonb, '[\"a.example\"]'::jsonb,
                 1, '{}'::jsonb, '{}'::jsonb, $4, 1, 'active')",
    )
    .bind(conversation_id)
    .bind(vec![8u8; 16])
    .bind("11".repeat(32))
    .bind("44".repeat(32))
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat_mls_incarnation_recoveries
             (recovery_digest, conversation_id, previous_incarnation,
              new_incarnation, proposal_id, origin_domain, recovery)
         VALUES ($1,$2,1,2,$3,'a.example','{}'::jsonb)",
    )
    .bind("55".repeat(32))
    .bind(conversation_id)
    .bind(Uuid::from_u128(8))
    .execute(&mut connection)
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "UPDATE chat_mls_incarnation_recoveries
             SET origin_domain = 'b.example'
             WHERE conversation_id = $1",
        )
        .bind(conversation_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "signed MLS recovery evidence must be append-only"
    );

    sqlx::raw_sql(RECOVERY_DOWN)
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(MAILBOX_CONSTRAINT_DOWN)
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(FOUNDATION_DOWN)
        .execute(&mut connection)
        .await
        .unwrap();
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = current_schema()
           AND table_name LIKE 'chat_mls_%'",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(remaining, 0);

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
fn mls_foundation_has_no_sender_metadata_in_anonymous_mailbox_schema() {
    let normalized = FOUNDATION.to_ascii_lowercase();
    let mailbox = normalized
        .split("create table chat_mls_mailbox")
        .nth(1)
        .and_then(|tail| {
            tail.split("create index chat_mls_mailbox_recipient_idx")
                .next()
        })
        .unwrap();
    assert!(!mailbox.contains("sender_address"));
    assert!(!mailbox.contains("sender_device"));
    assert!(mailbox.contains("delivery_kind = 'anonymous'"));
    assert!(mailbox.contains("conversation_id is null"));
    assert!(mailbox.contains("incarnation is null"));
    assert!(mailbox.contains("delivery_kind = 'membership_control'"));
    assert!(mailbox.contains("incarnation > 0"));
}
