//! Custom mail domains (docs/plans/mail-custom-domains.md): an account's own
//! domains, verified by a TXT record before any mail flows, checked as
//! Proton checks them, kept in step with Stalwart.
//!
//! - [`name`]: what may be added.
//! - [`records`]: each DNS record's state, in Proton's numbers.
//! - [`policy`]: what a check does to the domain (the grace by cause).
//! - [`reconcile`]: Stalwart's domains and DKIM signatures follow the
//!   database.

pub mod check;
pub mod dkim;
pub mod dns;
pub mod name;
pub mod policy;
pub mod reconcile;
pub mod records;
pub mod settings;
pub mod stalwart;
pub mod store;
pub mod sweep;

use std::sync::atomic::{AtomicI64, Ordering};

static TIME_SCALE: AtomicI64 = AtomicI64::new(1);

/// A test stack's clock for custom domains (`MAIL_DOMAINS_TIME_SCALE`,
/// `APP_ENV=test` only): every period below is divided by it, so a live
/// test sees a day's wait in seconds. 1 everywhere else.
pub fn set_time_scale(scale: i64) {
    TIME_SCALE.store(scale.max(1), Ordering::Relaxed);
}

/// `seconds` on this server's clock for custom domains.
pub fn scaled(seconds: i64) -> i64 {
    (seconds / TIME_SCALE.load(Ordering::Relaxed)).max(1)
}

/// Whether the custom domain `id` takes and sends mail now (held, approved
/// where approval is on, not turned off, the feature configured): the rule
/// RCPT, sending and key lookups share.
pub async fn usable_domain(state: &crate::AppState, id: uuid::Uuid) -> Result<bool, sqlx::Error> {
    if !sweep::configured(state) {
        return Ok(false);
    }
    let settings = settings::Settings::load(&state.pool).await?;
    let row: Option<store::Row> = sqlx::query_as(&format!(
        "SELECT {} FROM mail_domains WHERE id = $1",
        store::COLUMNS
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(row.is_some_and(|row| row.usable(&settings)))
}

/// Whether `domain` is a custom domain held here that takes mail now.
pub async fn held_here(state: &crate::AppState, domain: &str) -> Result<bool, sqlx::Error> {
    if !sweep::configured(state) {
        return Ok(false);
    }
    let settings = settings::Settings::load(&state.pool).await?;
    let row: Option<store::Row> = sqlx::query_as(&format!(
        "SELECT {} FROM mail_domains WHERE name = $1 AND state IN (1, 2) AND removed_at IS NULL",
        store::COLUMNS
    ))
    .bind(domain.to_ascii_lowercase())
    .fetch_optional(&state.pool)
    .await?;
    Ok(row.is_some_and(|row| row.usable(&settings)))
}

/// Whether `domain`'s catch-all has room for one more message today,
/// within `per_day` (the owner's setting): read at RCPT, so a full day
/// answers `452` before any data. Nothing is counted here.
pub async fn catch_all_has_room(
    pool: &sqlx::PgPool,
    domain: uuid::Uuid,
    per_day: i64,
) -> Result<bool, sqlx::Error> {
    let taken: Option<i32> = sqlx::query_scalar(
        "SELECT count FROM mail_domain_catch_all_days
          WHERE domain_id = $1 AND day = (now() AT TIME ZONE 'UTC')::date",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;
    Ok(i64::from(taken.unwrap_or(0)) < per_day)
}

/// Counts one caught message stored today, if the day has room: false when
/// it is full (another backend took the last place since RCPT).
pub async fn count_catch_all(
    pool: &sqlx::PgPool,
    domain: uuid::Uuid,
    per_day: i64,
) -> Result<bool, sqlx::Error> {
    if per_day <= 0 {
        return Ok(false);
    }
    let counted: Option<i32> = sqlx::query_scalar(
        "INSERT INTO mail_domain_catch_all_days (domain_id, day, count)
         VALUES ($1, (now() AT TIME ZONE 'UTC')::date, 1)
         ON CONFLICT (domain_id, day) DO UPDATE
            SET count = mail_domain_catch_all_days.count + 1
          WHERE mail_domain_catch_all_days.count < $2
         RETURNING count",
    )
    .bind(domain)
    .bind(per_day)
    .fetch_optional(pool)
    .await?;
    Ok(counted.is_some())
}
