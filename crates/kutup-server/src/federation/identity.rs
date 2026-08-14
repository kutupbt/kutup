use ed25519_dalek::SigningKey;
use kutup_federation_proto::{
    grouped_fingerprint, verify_identity_chain, FederationIdentityDocumentV1,
};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::FederationRuntimeConfig;

const LOCAL_IDENTITY_ADVISORY_LOCK: i64 = 0x4b55_5455_5046_4944;

/// The verified current document and corresponding in-memory signing key.
/// Private seed material is never persisted in PostgreSQL.
pub(crate) struct LocalFederationIdentity {
    document: FederationIdentityDocumentV1,
    signing_key: SigningKey,
}

impl LocalFederationIdentity {
    pub(super) async fn load_or_create(
        pool: &PgPool,
        config: &FederationRuntimeConfig,
        now: OffsetDateTime,
    ) -> anyhow::Result<Self> {
        let mut transaction = pool.begin().await?;
        lock_local_identity(&mut transaction).await?;
        let documents = load_local_documents(&mut transaction).await?;
        let document = if documents.is_empty() {
            let genesis = FederationIdentityDocumentV1::genesis(
                &config.server_name,
                now.unix_timestamp(),
                &config.signing_key,
            )?;
            insert_local_document(&mut transaction, &genesis, now).await?;
            insert_system_audit(
                &mut transaction,
                "federation.identity.genesis",
                json!({
                    "actorType": "system",
                    "domain": config.server_name,
                    "sequence": genesis.sequence,
                    "fingerprint": genesis.key.key_id,
                }),
                now,
            )
            .await?;
            genesis
        } else {
            validate_stored_chain(&config.server_name, &documents)?;
            documents
                .last()
                .expect("non-empty identity history has a last document")
                .clone()
        };
        if document.key.public_key_bytes()? != config.signing_key.verifying_key().to_bytes() {
            anyhow::bail!(
                "FEDERATION_SIGNING_KEY does not match persisted identity sequence {} ({})",
                document.sequence,
                document.key.key_id
            );
        }
        transaction.commit().await?;
        Ok(Self {
            document,
            signing_key: config.signing_key.clone(),
        })
    }

    pub fn document(&self) -> &FederationIdentityDocumentV1 {
        &self.document
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn fingerprint(&self) -> &str {
        &self.document.key.key_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIdentityRotationResult {
    pub document: FederationIdentityDocumentV1,
    pub already_rotated: bool,
}

/// Explicitly append one old+new-authenticated local identity document. A
/// repeated command after a committed rotation returns the same document
/// rather than creating a second rotation.
pub(crate) async fn rotate_local_identity(
    pool: &PgPool,
    config: &FederationRuntimeConfig,
    now: OffsetDateTime,
) -> anyhow::Result<LocalIdentityRotationResult> {
    let next_signing_key = config.require_next_signing_key()?;
    let mut transaction = pool.begin().await?;
    lock_local_identity(&mut transaction).await?;
    let documents = load_local_documents(&mut transaction).await?;
    if documents.is_empty() {
        anyhow::bail!(
            "local federation identity has no genesis; start the server once before rotating"
        );
    }
    validate_stored_chain(&config.server_name, &documents)?;
    let latest = documents
        .last()
        .expect("non-empty identity history has a last document");
    let configured_current = config.signing_key.verifying_key().to_bytes();
    let configured_next = next_signing_key.verifying_key().to_bytes();
    let persisted_current = latest.key.public_key_bytes()?;

    if persisted_current == configured_next {
        let predecessor = documents.get(documents.len().saturating_sub(2));
        if predecessor.is_some_and(|document| {
            document
                .key
                .public_key_bytes()
                .is_ok_and(|key| key == configured_current)
        }) {
            transaction.rollback().await?;
            return Ok(LocalIdentityRotationResult {
                document: latest.clone(),
                already_rotated: true,
            });
        }
        anyhow::bail!(
            "persisted identity uses FEDERATION_NEXT_SIGNING_KEY but was not rotated from the configured current key"
        );
    }
    if persisted_current != configured_current {
        anyhow::bail!(
            "FEDERATION_SIGNING_KEY does not match persisted identity sequence {}; refusing implicit replacement",
            latest.sequence
        );
    }

    let rotated = FederationIdentityDocumentV1::rotate(
        latest,
        now.unix_timestamp(),
        &config.signing_key,
        next_signing_key,
    )?;
    insert_local_document(&mut transaction, &rotated, now).await?;
    insert_system_audit(
        &mut transaction,
        "federation.identity.rotate-local",
        json!({
            "actorType": "operator-command",
            "domain": config.server_name,
            "sequence": rotated.sequence,
            "oldFingerprint": latest.key.key_id,
            "oldFingerprintDisplay": grouped_fingerprint(&latest.key.key_id)?,
            "newFingerprint": rotated.key.key_id,
            "newFingerprintDisplay": grouped_fingerprint(&rotated.key.key_id)?,
        }),
        now,
    )
    .await?;
    transaction.commit().await?;
    Ok(LocalIdentityRotationResult {
        document: rotated,
        already_rotated: false,
    })
}

pub(crate) async fn insert_system_audit(
    transaction: &mut Transaction<'_, Postgres>,
    action: &str,
    payload: serde_json::Value,
    occurred_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_audit_log
         (admin_user_id, action, target_user_id, payload, occurred_at)
         VALUES ($1, $2, NULL, $3, $4)",
    )
    .bind(Uuid::nil())
    .bind(action)
    .bind(payload)
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn lock_local_identity(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCAL_IDENTITY_ADVISORY_LOCK)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn load_local_documents(
    transaction: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<Vec<FederationIdentityDocumentV1>> {
    let rows: Vec<(i64, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT sequence, document_hash, key_id, document
         FROM federation_local_identity_documents ORDER BY sequence",
    )
    .fetch_all(&mut **transaction)
    .await?;
    rows.into_iter()
        .map(|(sequence, stored_hash, stored_key_id, value)| {
            let document: FederationIdentityDocumentV1 = serde_json::from_value(value)?;
            let sequence = u64::try_from(sequence)
                .map_err(|_| anyhow::anyhow!("stored local identity sequence is negative"))?;
            if document.sequence != sequence
                || document.document_hash()? != stored_hash
                || document.key.key_id != stored_key_id
            {
                anyhow::bail!("stored local identity metadata does not match its document");
            }
            Ok(document)
        })
        .collect()
}

fn validate_stored_chain(
    expected_server: &str,
    documents: &[FederationIdentityDocumentV1],
) -> anyhow::Result<()> {
    verify_identity_chain(expected_server, documents).map_err(anyhow::Error::msg)?;
    for (expected, document) in documents.iter().enumerate() {
        if document.sequence != expected as u64 {
            anyhow::bail!("stored local identity history is not contiguous from genesis");
        }
    }
    Ok(())
}

async fn insert_local_document(
    transaction: &mut Transaction<'_, Postgres>,
    document: &FederationIdentityDocumentV1,
    created_at: OffsetDateTime,
) -> anyhow::Result<()> {
    let sequence = i64::try_from(document.sequence)
        .map_err(|_| anyhow::anyhow!("local identity sequence exceeds PostgreSQL BIGINT"))?;
    sqlx::query(
        "INSERT INTO federation_local_identity_documents
         (sequence, document_hash, key_id, document, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(sequence)
    .bind(document.document_hash()?)
    .bind(&document.key.key_id)
    .bind(serde_json::to_value(document)?)
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
