//! Durable capability, recipient, and federation-origin counters.

use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use crate::error::{AppError, AppResult};

pub(super) async fn increment_counter(
    tx: &mut Transaction<'_, Postgres>,
    scope_type: &str,
    scope_digest: Vec<u8>,
    window_seconds: i64,
    limit: i64,
    now: OffsetDateTime,
) -> AppResult<()> {
    let start_unix = now.unix_timestamp() - now.unix_timestamp().rem_euclid(window_seconds);
    let window_start = OffsetDateTime::from_unix_timestamp(start_unix)
        .map_err(|_| AppError::internal("MLS rate window is outside supported time"))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(start_unix + window_seconds * 2)
        .map_err(|_| AppError::internal("MLS rate expiry is outside supported time"))?;
    let accepted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO chat_mls_rate_counters
             (scope_type, scope_digest, window_start, count, expires_at)
         VALUES ($1,$2,$3,1,$4)
         ON CONFLICT (scope_type, scope_digest, window_start)
         DO UPDATE SET
             count = chat_mls_rate_counters.count + 1,
             expires_at = EXCLUDED.expires_at
         WHERE chat_mls_rate_counters.count < $5
         RETURNING count",
    )
    .bind(scope_type)
    .bind(scope_digest)
    .bind(window_start)
    .bind(expires_at)
    .bind(limit)
    .fetch_optional(&mut **tx)
    .await?;
    if accepted.is_none() {
        return Err(AppError::too_many_requests(
            "anonymous MLS rate limit exceeded",
        ));
    }
    Ok(())
}
