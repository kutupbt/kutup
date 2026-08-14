use kutup_federation_proto::{
    validate_server_name, FederationReplayMetadata, CLOCK_SKEW_SECONDS,
    MAX_SIGNATURE_LIFETIME_SECONDS,
};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationReplayOutcome {
    FirstSeen,
    ExactReplay,
    Conflict,
}

#[derive(Clone)]
pub(crate) struct FederationReplayStore {
    pool: PgPool,
}

impl FederationReplayStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Atomically reserve a successfully verified RFC 9421 request. The
    /// unforgeable metadata supplies its signed origin, nonce, stable covered-
    /// content hash, and skew-adjusted expiry, allowing
    /// a feature to replay a previously stored response only for an exact
    /// duplicate while rejecting nonce reuse with different content.
    pub async fn reserve_verified(
        &self,
        metadata: &FederationReplayMetadata,
        now: OffsetDateTime,
    ) -> anyhow::Result<FederationReplayOutcome> {
        let expires_at = OffsetDateTime::from_unix_timestamp(metadata.store_until())
            .map_err(|_| anyhow::anyhow!("authenticated replay expiry is out of range"))?;
        self.reserve(
            metadata.origin(),
            metadata.request_id(),
            metadata.request_hash(),
            now,
            expires_at,
        )
        .await
    }

    async fn reserve(
        &self,
        origin: &str,
        request_id: &str,
        request_hash: &str,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> anyhow::Result<FederationReplayOutcome> {
        validate_server_name(origin).map_err(anyhow::Error::msg)?;
        validate_request_id(request_id)?;
        validate_request_hash(request_hash)?;
        if expires_at <= now {
            anyhow::bail!("federation replay reservation must expire after it is created");
        }
        let maximum_reservation =
            Duration::seconds(MAX_SIGNATURE_LIFETIME_SECONDS + (2 * CLOCK_SKEW_SECONDS) + 1);
        if expires_at - now > maximum_reservation {
            anyhow::bail!("federation replay reservation exceeds the authentication time window");
        }

        let mut transaction = self.pool.begin().await?;
        lock_reservation(&mut transaction, origin, request_id).await?;
        let existing: Option<(String, OffsetDateTime)> = sqlx::query_as(
            "SELECT request_hash, expires_at
             FROM federation_request_replays
             WHERE origin = $1 AND request_id = $2",
        )
        .bind(origin)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await?;

        let outcome = match existing {
            Some((stored_hash, stored_expires_at)) if stored_expires_at > now => {
                sqlx::query(
                    "UPDATE federation_request_replays
                     SET expires_at = GREATEST(expires_at, $3)
                     WHERE origin = $1 AND request_id = $2",
                )
                .bind(origin)
                .bind(request_id)
                .bind(expires_at)
                .execute(&mut *transaction)
                .await?;
                if stored_hash == request_hash {
                    FederationReplayOutcome::ExactReplay
                } else {
                    FederationReplayOutcome::Conflict
                }
            }
            _ => {
                sqlx::query(
                    "INSERT INTO federation_request_replays
                     (origin, request_id, request_hash, first_seen_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (origin, request_id) DO UPDATE
                     SET request_hash = EXCLUDED.request_hash,
                         first_seen_at = EXCLUDED.first_seen_at,
                         expires_at = EXCLUDED.expires_at",
                )
                .bind(origin)
                .bind(request_id)
                .bind(request_hash)
                .bind(now)
                .bind(expires_at)
                .execute(&mut *transaction)
                .await?;
                FederationReplayOutcome::FirstSeen
            }
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    pub async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, sqlx::Error> {
        Ok(
            sqlx::query("DELETE FROM federation_request_replays WHERE expires_at <= $1")
                .bind(now)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }
}

async fn lock_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    origin: &str,
    request_id: &str,
) -> Result<(), sqlx::Error> {
    let mut digest = Sha256::new();
    digest.update(b"kutup-federation-replay-v1\0");
    digest.update(origin.as_bytes());
    digest.update([0]);
    digest.update(request_id.as_bytes());
    let digest = digest.finalize();
    let key = i64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("a SHA-256 digest always contains eight bytes"),
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn validate_request_id(value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
    {
        anyhow::bail!("federation request ID must be 1-128 unescaped URI-safe ASCII characters");
    }
    Ok(())
}

fn validate_request_hash(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("federation request hash must be lowercase SHA-256 hex");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_keys_use_the_closed_nonce_and_hash_grammars() {
        for request_id in ["550e8400-e29b-41d4-a716-446655440000", "abc._~-123"] {
            validate_request_id(request_id).unwrap();
        }
        for request_id in ["", "space is invalid", "slash/invalid", &"x".repeat(129)] {
            assert!(validate_request_id(request_id).is_err());
        }
        validate_request_hash(&"ab".repeat(32)).unwrap();
        assert!(validate_request_hash(&"AB".repeat(32)).is_err());
        assert!(validate_request_hash(&"ab".repeat(31)).is_err());
    }
}
