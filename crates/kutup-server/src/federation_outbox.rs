//! One federation outbox (docs/plans/federation-outbox.md): every kind of
//! delivery to a peer server in `federation_outbox`, each kind with its own
//! sequence per destination (what every receiver checks, so sequences mean
//! what they meant), one backoff, one worker, and one record of the answers
//! this server gave, per kind and origin.
//!
//! The kinds ([`Kind`]) keep their own rules in their modules
//! (`chat_federation` for plain and sealed chat, `chat_media_federation`,
//! `remote_renames`): what a batch is, the route,
//! and which answers are final; the worker calls each kind's flush. Every
//! final answer, delivered or refused, uses up its sequence on both sides, so
//! one refusal never blocks the destination's queue (for plain chat that is
//! its wire version 2).

use std::time::Duration;

use serde_json::Value;
use sqlx::{PgExecutor, Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppResult;
use crate::AppState;

/// What a row delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A plain (unsealed) chat send: the engine's fallback, as Signal's.
    Chat,
    /// A sealed-sender chat send.
    Sealed,
    /// A Chat media offer (the destination then pulls the object).
    Media,
    /// An account's rename chain, announced to the servers that know it (no
    /// transport sequence: applying a chain is idempotent).
    Rename,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Chat => "chat",
            Kind::Sealed => "sealed",
            Kind::Media => "media",
            Kind::Rename => "rename",
        }
    }
}

/// The destination's next sequence of `kind`, taken for good.
pub async fn next_sequence(
    tx: &mut Transaction<'_, Postgres>,
    kind: Kind,
    destination: &str,
) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO federation_sequences (kind, destination, next_sequence)
         VALUES ($1, $2, 2)
         ON CONFLICT (kind, destination) DO UPDATE SET
             next_sequence = federation_sequences.next_sequence + 1
         RETURNING next_sequence - 1",
    )
    .bind(kind.as_str())
    .bind(destination)
    .fetch_one(&mut **tx)
    .await?)
}

/// The wait after a row's `attempts`th failed try: `base · 2^attempts`
/// seconds (the exponent at most 8), at most `cap`, with up to a second of
/// jitter so a peer coming back isn't met by every backend at once.
pub fn retry_delay(attempts: i32, base_seconds: i64, cap_seconds: i64) -> Duration {
    let exponent = attempts.clamp(0, 8) as u32;
    let seconds = base_seconds
        .max(1)
        .saturating_mul(1_i64 << exponent)
        .min(cap_seconds.max(1));
    let jitter_ms = kutup_crypto::primitives::random_below(1001);
    Duration::from_millis(seconds as u64 * 1000 + jitter_ms)
}

/// Sets a pending row (still at `sequence`) to wait and try again, with why
/// its last try failed.
pub async fn retry_later(
    pool: &sqlx::PgPool,
    id: Uuid,
    sequence: Option<i64>,
    attempts: i32,
    class: &str,
    error: &str,
) -> AppResult<()> {
    let base = crate::site_settings::FEDERATION_RETRY_BASE_SECONDS
        .load(pool)
        .await?;
    let cap = crate::site_settings::FEDERATION_RETRY_MAX_SECONDS
        .load(pool)
        .await?;
    let delay = retry_delay(attempts, base, cap);
    wait(pool, id, sequence, delay, class, error).await
}

/// Parks a pending row whose destination can't take its kind yet: tried
/// again after `federationPeerUpgradeSeconds`.
pub async fn park_for_upgrade(
    pool: &sqlx::PgPool,
    id: Uuid,
    sequence: Option<i64>,
    error: &str,
) -> AppResult<()> {
    let seconds = crate::site_settings::FEDERATION_PEER_UPGRADE_SECONDS
        .load(pool)
        .await?;
    wait(
        pool,
        id,
        sequence,
        Duration::from_secs(seconds.max(1) as u64),
        "peer_unsupported",
        error,
    )
    .await
}

async fn wait(
    pool: &sqlx::PgPool,
    id: Uuid,
    sequence: Option<i64>,
    delay: Duration,
    class: &str,
    error: &str,
) -> AppResult<()> {
    let error: String = error.chars().take(500).collect();
    sqlx::query(
        "UPDATE federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($3 * interval '1 millisecond'),
             error_class = $4, last_error = $5, updated_at = now()
         WHERE id = $1 AND state = 'pending' AND sequence IS NOT DISTINCT FROM $2",
    )
    .bind(id)
    .bind(sequence)
    .bind(delay.as_millis() as i64)
    .bind(class)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Settles a pending row (still at `sequence`) with the destination's final
/// answer: `delivered`, or `rejected` with its class. Whether it was still
/// pending there.
pub async fn settle<'e, E: PgExecutor<'e>>(
    executor: E,
    id: Uuid,
    sequence: Option<i64>,
    delivered: bool,
    class: Option<&str>,
    answer: &Value,
) -> AppResult<bool> {
    Ok(sqlx::query(
        "UPDATE federation_outbox
         SET state = $3, attempts = attempts + 1, error_class = $4, last_error = NULL,
             answer = $5, updated_at = now()
         WHERE id = $1 AND state = 'pending' AND sequence IS NOT DISTINCT FROM $2",
    )
    .bind(id)
    .bind(sequence)
    .bind(if delivered { "delivered" } else { "rejected" })
    .bind(class)
    .bind(answer)
    .execute(executor)
    .await?
    .rows_affected()
        == 1)
}

/// The destinations whose head of `kind` is due now (at most
/// `federationHeadsPerTick`): only each
/// destination's head, so a long queue for one server never fills the page
/// and starves the others, and rows behind a waiting head stay behind it.
pub async fn due_destinations(pool: &sqlx::PgPool, kind: Kind) -> AppResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT destination FROM (
                 SELECT DISTINCT ON (destination) destination, next_attempt_at
                 FROM federation_outbox
                 WHERE kind = $1 AND state = 'pending'
                 ORDER BY destination, sequence
             ) heads
         WHERE next_attempt_at <= now()
         ORDER BY destination
         LIMIT $2",
    )
    .bind(kind.as_str())
    .bind(
        crate::site_settings::FEDERATION_HEADS_PER_TICK
            .load(pool)
            .await?,
    )
    .fetch_all(pool)
    .await?)
}

/// Wakes the worker before its next tick ([`wake`]).
static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Asks the worker to look now: something was queued that peers should get
/// at once (a rename announce), not at the next tick.
pub fn wake() {
    WAKE.notify_one();
}

/// The worker: every `federationWorkerSeconds` (or at once when woken), each
/// kind's due deliveries, flushed by the kind's own rules. The client's own
/// request tries its send first; the worker takes what that left.
pub fn spawn_worker(state: AppState) {
    if state.federation.is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            let seconds = crate::site_settings::FEDERATION_WORKER_SECONDS
                .load(&state.pool)
                .await
                .unwrap_or(crate::site_settings::FEDERATION_WORKER_SECONDS.default);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(seconds.max(1) as u64)) => {}
                _ = WAKE.notified() => {}
            }
            // Each kind on its own, at once: a destination timing out for
            // one kind holds up none of the others.
            let (chat, sealed, media, renames) = tokio::join!(
                crate::chat_federation::flush_due(&state),
                crate::chat_federation::flush_due_sealed(&state),
                crate::chat_media_federation::flush_due(&state),
                crate::remote_renames::deliver_due(&state),
            );
            match chat {
                Ok(completed) if completed > 0 => {
                    tracing::info!(completed, "chat federation delivered queued sends");
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "chat federation retry failed"),
            }
            if let Err(error) = sealed {
                tracing::warn!(%error, "sealed chat federation retry failed");
            }
            if let Err(error) = media {
                tracing::warn!(%error, "Chat media federation retry failed");
            }
            if let Err(error) = renames {
                tracing::warn!(error = %error.message, "rename announces failed");
            }
        }
    });
}

/// Deletes settled deliveries of every kind, and the answers given to
/// peers, older than `federationRecordDays`. Each stream's high-water mark
/// stays, so a replay past it is still known as answered. How many rows went.
pub async fn prune(pool: &sqlx::PgPool) -> AppResult<u64> {
    let days = crate::site_settings::FEDERATION_RECORD_DAYS
        .load(pool)
        .await?;
    let outbox = sqlx::query(
        "DELETE FROM federation_outbox
         WHERE state <> 'pending' AND updated_at < now() - ($1 * interval '1 day')",
    )
    .bind(days as f64)
    .execute(pool)
    .await?
    .rows_affected();
    let inbound = sqlx::query(
        "DELETE FROM federation_inbound WHERE created_at < now() - ($1 * interval '1 day')",
    )
    .bind(days as f64)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(outbox + inbound)
}

/// One origin's stream of `kind`, locked for this transaction: the highest
/// sequence it has used up.
pub async fn lock_stream(
    tx: &mut Transaction<'_, Postgres>,
    kind: Kind,
    origin: &str,
) -> AppResult<i64> {
    sqlx::query(
        "INSERT INTO federation_inbound_state (kind, origin, last_sequence)
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(kind.as_str())
    .bind(origin)
    .execute(&mut **tx)
    .await?;
    Ok(sqlx::query_scalar(
        "SELECT last_sequence FROM federation_inbound_state
         WHERE kind = $1 AND origin = $2 FOR UPDATE",
    )
    .bind(kind.as_str())
    .bind(origin)
    .fetch_one(&mut **tx)
    .await?)
}

/// The final answer this server gave to (origin, sequence) of `kind`.
#[derive(Debug, sqlx::FromRow)]
pub struct InboundRecord {
    pub transaction_id: Option<String>,
    /// The body's digest, where a replay must be byte-identical (media).
    pub digest: Option<String>,
    pub status: i16,
    pub answer: Value,
}

pub async fn prior(
    tx: &mut Transaction<'_, Postgres>,
    kind: Kind,
    origin: &str,
    sequence: i64,
) -> AppResult<Option<InboundRecord>> {
    Ok(sqlx::query_as(
        "SELECT transaction_id, digest, status, answer FROM federation_inbound
         WHERE kind = $1 AND origin = $2 AND sequence = $3",
    )
    .bind(kind.as_str())
    .bind(origin)
    .bind(sequence)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Records a final answer to (origin, sequence) of `kind` and uses the
/// sequence up. The caller holds the stream ([`lock_stream`]) and has checked
/// that `sequence` is the next one. Whether it was recorded (not already).
#[allow(clippy::too_many_arguments)]
pub async fn record(
    tx: &mut Transaction<'_, Postgres>,
    kind: Kind,
    origin: &str,
    sequence: i64,
    transaction_id: Option<&str>,
    digest: Option<&str>,
    status: u16,
    answer: &Value,
) -> AppResult<bool> {
    let recorded = sqlx::query(
        "INSERT INTO federation_inbound
             (kind, origin, sequence, transaction_id, digest, status, answer)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(kind.as_str())
    .bind(origin)
    .bind(sequence)
    .bind(transaction_id)
    .bind(digest)
    .bind(status as i16)
    .bind(answer)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    if recorded {
        sqlx::query(
            "UPDATE federation_inbound_state
             SET last_sequence = GREATEST(last_sequence, $3), updated_at = now()
             WHERE kind = $1 AND origin = $2",
        )
        .bind(kind.as_str())
        .bind(origin)
        .bind(sequence)
        .execute(&mut **tx)
        .await?;
    }
    Ok(recorded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_to_its_cap_with_a_second_of_jitter() {
        for (attempts, seconds) in [(0, 2), (1, 4), (2, 8), (7, 256), (8, 300), (30, 300)] {
            let wait = retry_delay(attempts, 2, 300);
            assert!(
                wait >= Duration::from_secs(seconds)
                    && wait <= Duration::from_millis(seconds * 1000 + 1000),
                "{attempts}: {wait:?}"
            );
        }
        // A larger base, a smaller cap.
        assert!(retry_delay(0, 5, 900) >= Duration::from_secs(5));
        assert!(retry_delay(20, 5, 60) <= Duration::from_millis(61_000));
    }
}
