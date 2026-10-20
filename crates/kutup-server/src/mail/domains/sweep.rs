//! Custom domains' background work (docs/plans/mail-custom-domains.md §3,
//! §10), every `MAIL_DOMAINS_SWEEP_SECONDS` (5 minutes):
//! - checks the domains that are due: held ones every 6 hours, new ones
//!   every 15 minutes for their first 2 hours, others every 6 hours; each
//!   with jitter, a few at a time;
//! - drops pending domains never verified within the pending limit;
//! - makes Stalwart's domains and signatures follow the rows, one runner at
//!   a time (an advisory lock).

use std::sync::Arc;
use std::time::Duration;

use rand::Rng as _;
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::reconcile::{self, Recorded, Signature, Wanted};
use super::settings::{Mode, Settings};
use super::stalwart::StalwartApi;
use super::store::{self, Row, COLUMNS};
use super::{check, dkim};
use crate::error::AppResult;
use crate::handlers::mail_domains::{resolver, server};
use crate::AppState;

/// At most this many checks a tick, and this many at once.
const CHECKS_PER_TICK: i64 = 200;
const CHECKS_AT_ONCE: usize = 8;
/// The advisory lock the reconcile holds (an arbitrary constant).
const RECONCILE_LOCK: i64 = 0x6b75_7470_646f_6d73;

/// Whether this server can take custom domains at all.
pub fn configured(state: &AppState) -> bool {
    !state.config.mail_hostname.is_empty()
        && !state.config.mail_stalwart_domains_token.is_empty()
        && state.config.mail_dkim_keys.current().is_some()
}

pub fn spawn(state: AppState) {
    if !configured(&state) {
        return;
    }
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(Duration::from_secs(state.config.mail_domains_sweep_seconds));
        loop {
            tick.tick().await;
            if let Err(error) = run(&state).await {
                tracing::warn!(error = %error, "mail: custom domains sweep failed");
            }
        }
    });
}

/// One pass.
pub async fn run(state: &AppState) -> AppResult<()> {
    let settings = Settings::load(&state.pool).await?;
    drop_stale(state, &settings).await?;
    check_due(state, &settings).await?;
    dkim::rotate(
        &state.pool,
        resolver(state)?,
        &state.config.chat_server_name,
        &state.config.mail_dkim_keys,
    )
    .await
    .map_err(|e| crate::error::AppError::internal(format!("DKIM rotation: {e}")))?;
    reconcile_stalwart(state, &settings).await
}

async fn drop_stale(state: &AppState, settings: &Settings) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM mail_domains
          WHERE verified_at IS NULL AND state = 0 AND removed_at IS NULL
            AND created_at < now() - make_interval(days => $1::int)",
    )
    .bind(settings.pending_days as i32)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn check_due(state: &AppState, settings: &Settings) -> AppResult<()> {
    // The jitter spreads checks over the hour, so domains added together
    // aren't checked together for ever after.
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains
          WHERE removed_at IS NULL AND (
                checked_at IS NULL
             OR (created_at > now() - interval '2 hours' AND state = 0
                 AND checked_at < now() - interval '15 minutes')
             OR checked_at < now() - interval '6 hours' - (abs(hashtext(id::text)) % 3600) * interval '1 second')
          ORDER BY checked_at NULLS FIRST LIMIT $1"
    ))
    .bind(CHECKS_PER_TICK)
    .fetch_all(&state.pool)
    .await?;
    let limit = Arc::new(Semaphore::new(CHECKS_AT_ONCE));
    let resolver = resolver(state)?;
    let server = server(state);
    let mut tasks = tokio::task::JoinSet::new();
    for row in rows {
        let permit = limit.clone().acquire_owned().await.expect("never closed");
        let (pool, server, settings) = (state.pool.clone(), server.clone(), *settings);
        tasks.spawn(async move {
            // A small random wait, so a tick's checks don't all start at once.
            let wait = rand::thread_rng().gen_range(0..2000);
            tokio::time::sleep(Duration::from_millis(wait)).await;
            let user_settings = match settings.for_user(&pool, row.user_id).await {
                Ok(settings) => settings,
                Err(_) => settings,
            };
            if let Err(error) =
                store::check_and_save(&pool, resolver, &server, &user_settings, &row).await
            {
                tracing::warn!(error = %error, "mail: a custom domain's check failed");
            }
            drop(permit);
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Reconciles Stalwart now, in the background (after a domain changed
/// standing); a failure waits for the next sweep.
pub fn reconcile_soon(state: AppState) {
    tokio::spawn(async move {
        let result = match Settings::load(&state.pool).await {
            Ok(settings) => reconcile_stalwart(&state, &settings).await,
            Err(error) => Err(error.into()),
        };
        if let Err(error) = result {
            tracing::warn!(error = %error, "mail: reconciling Stalwart failed");
        }
    });
}

/// Stalwart's tagged objects follow the usable rows, under one lock.
async fn reconcile_stalwart(state: &AppState, settings: &Settings) -> AppResult<()> {
    let mut tx = state.pool.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(RECONCILE_LOCK)
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        return Ok(());
    }
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains WHERE removed_at IS NULL AND state IN (1, 2)"
    ))
    .fetch_all(&mut *tx)
    .await?;
    let active = dkim::active(&state.pool, &state.config.mail_dkim_keys)
        .await
        .map_err(|e| crate::error::AppError::internal(format!("DKIM key: {e}")))?;
    let wanted: Vec<Wanted> = rows
        .iter()
        .filter(|row| settings.mode != Mode::Off && row.usable(settings))
        .map(|row| Wanted {
            id: row.id,
            name: row.name.clone(),
            // Signed once its DKIM was good, while it isn't in ERROR.
            signature: active.as_ref().filter(|_| check::signs(&row.domain())).map(
                |(selector, pem, key_id)| Signature {
                    selector: selector.clone(),
                    private_key_pem: pem.to_string(),
                    key_id: key_id.clone(),
                },
            ),
            recorded: row
                .stalwart_signature_id
                .clone()
                .zip(row.stalwart_signature_key.clone())
                .map(|(object_id, key_id)| Recorded { object_id, key_id }),
        })
        .collect();
    let api = StalwartApi::new(
        stalwart_client()?,
        &state.config.mail_stalwart_url,
        &state.config.mail_stalwart_domains_token,
    );
    let applied = reconcile::apply(&api, &wanted)
        .await
        .map_err(|e| crate::error::AppError::internal(format!("Stalwart reconcile: {e}")))?;
    for (id, recorded) in applied.recorded {
        record_signature(&mut tx, id, recorded).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// One client for Stalwart, made once: its listener is on the internal
/// network, so short timeouts.
fn stalwart_client() -> AppResult<reqwest::Client> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = crate::tls::client_builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| crate::error::AppError::internal(format!("Stalwart client: {e}")))?;
    Ok(CLIENT.get_or_init(|| client).clone())
}

async fn record_signature(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    recorded: Option<Recorded>,
) -> AppResult<()> {
    let (object, key) = recorded.map(|r| (r.object_id, r.key_id)).unzip();
    sqlx::query(
        "UPDATE mail_domains SET stalwart_signature_id = $2, stalwart_signature_key = $3 WHERE id = $1",
    )
    .bind(id)
    .bind(object)
    .bind(key)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
