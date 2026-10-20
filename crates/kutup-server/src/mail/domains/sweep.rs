//! Custom domains' background work (docs/plans/mail-custom-domains.md §3,
//! §10), every `MAIL_DOMAINS_SWEEP_SECONDS` (5 minutes):
//! - checks the domains that are due: held ones every 6 hours, new ones
//!   every 15 minutes for their first 2 hours, others every 6 hours; each
//!   with jitter, a few at a time;
//! - drops pending domains never verified within the pending limit;
//! - makes Stalwart's domains and signatures follow the rows, one runner at
//!   a time (an advisory lock).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng as _;
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::policy::Change;
use super::reconcile::{self, Recorded, Signature, Wanted};
use super::settings::{Mode, Settings};
use super::stalwart::{Refused, StalwartApi};
use super::store::{self, Row, COLUMNS};
use super::{check, dkim};
use crate::error::AppResult;
use crate::handlers::mail_domains::{resolver, server};
use crate::AppState;

/// At most this many checks a tick, and this many at once.
const CHECKS_PER_TICK: i64 = 200;
const CHECKS_AT_ONCE: usize = 8;
/// After Stalwart refuses the account, how long the reconcile waits.
/// After Stalwart refuses the account, the reconcile waits a minute, then
/// twice as long after each further refusal, up to 30 minutes. A first
/// refusal is often only a fresh deploy whose stalwart-setup hasn't made the
/// account yet; repeated ones mean a wrong secret, and retrying fast would
/// keep the backend's address banned.
const REFUSED_FIRST_SECS: i64 = 60;
const REFUSED_MAX_SECS: i64 = 30 * 60;
static REFUSED_UNTIL: AtomicI64 = AtomicI64::new(0);
static REFUSALS: AtomicI64 = AtomicI64::new(0);

fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

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
    // Catch-all days past: only today's count limits anything.
    sqlx::query(
        "DELETE FROM mail_domain_catch_all_days
          WHERE day < (now() AT TIME ZONE 'UTC')::date - 1",
    )
    .execute(&state.pool)
    .await?;
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
        let (state, server, settings) = (state.clone(), server.clone(), *settings);
        tasks.spawn(async move {
            // A small random wait, so a tick's checks don't all start at once.
            let wait = rand::thread_rng().gen_range(0..2000);
            tokio::time::sleep(Duration::from_millis(wait)).await;
            let user_settings = match settings.for_user(&state.pool, row.user_id).await {
                Ok(settings) => settings,
                Err(_) => settings,
            };
            match store::check_and_save(&state.pool, resolver, &server, &user_settings, &row).await
            {
                Ok((checked, change, lost_holder)) => {
                    tell_losses(&state, &checked, change, lost_holder).await;
                }
                Err(error) => {
                    tracing::warn!(error = %error, "mail: a custom domain's check failed");
                }
            }
            drop(permit);
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Tells the accounts a check took a domain from, in their inboxes: the
/// owner whose domain lapsed, and a holder another account's proof moved it
/// from.
pub async fn tell_losses(
    state: &AppState,
    checked: &Row,
    change: Change,
    lost_holder: Option<Uuid>,
) {
    use crate::mail::notice::{domain_lost, DomainLost};
    if change == Change::Inactive {
        domain_lost(state, checked.user_id, &checked.name, DomainLost::Lapsed).await;
    }
    if let Some(holder) = lost_holder {
        domain_lost(state, holder, &checked.name, DomainLost::Transferred).await;
    }
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
    if now_secs() < REFUSED_UNTIL.load(Ordering::Relaxed) {
        return Ok(());
    }
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
        &state.config.chat_server_name,
        &state.config.mail_stalwart_domains_token,
    );
    let applied = match reconcile::apply(&api, &wanted).await {
        Ok(applied) => {
            REFUSALS.store(0, Ordering::Relaxed);
            applied
        }
        Err(error) => {
            if let Some(refused) = error.downcast_ref::<Refused>() {
                // Wrong secret, or the address banned after failures:
                // retrying each sweep would keep it banned.
                let refusals = REFUSALS.fetch_add(1, Ordering::Relaxed).min(10);
                let wait = (REFUSED_FIRST_SECS << refusals).min(REFUSED_MAX_SECS);
                REFUSED_UNTIL.store(now_secs() + wait, Ordering::Relaxed);
                tracing::error!(
                    status = refused.0,
                    "mail: Stalwart refused the custom domains account \
                     (MAIL_STALWART_DOMAINS_TOKEN, stalwart-setup); retried later"
                );
            }
            return Err(crate::error::AppError::internal(format!(
                "Stalwart reconcile: {error}"
            )));
        }
    };
    for (id, recorded) in applied.recorded {
        record_signature(&mut tx, id, recorded).await?;
    }
    watch_untagged(&mut tx, &applied.untagged).await?;
    tx.commit().await?;
    Ok(())
}

/// The site setting holding the last fingerprint of Stalwart's objects
/// outside Kutup's tag, and the one holding when it last changed.
pub const UNTAGGED_FINGERPRINT: &str = "mail_domains_untagged_fingerprint";
pub const UNTAGGED_CHANGED_AT: &str = "mail_domains_untagged_changed_at";

/// Alerts when `MAIL_DOMAIN`'s objects in Stalwart (anything outside Kutup's
/// tag) change: the reconcile never touches them, so a change means someone
/// else did (docs/plans/mail-custom-domains.md §10). The first run records
/// the baseline; a change logs an error and shows in the admin console.
async fn watch_untagged(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fingerprint: &str,
) -> AppResult<()> {
    let known: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(UNTAGGED_FINGERPRINT)
            .fetch_optional(&mut **tx)
            .await?;
    if known.as_deref() == Some(fingerprint) {
        return Ok(());
    }
    if known.is_some() {
        tracing::error!(
            "mail: Stalwart's domains or DKIM signatures outside Kutup's custom domains \
             changed (MAIL_DOMAIN's own, or an operator's): check Stalwart's settings"
        );
        sqlx::query(
            "INSERT INTO site_settings (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(UNTAGGED_CHANGED_AT)
        .bind(time::OffsetDateTime::now_utc().unix_timestamp().to_string())
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(UNTAGGED_FINGERPRINT)
    .bind(fingerprint)
    .execute(&mut **tx)
    .await?;
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
