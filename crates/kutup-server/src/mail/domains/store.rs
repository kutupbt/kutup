//! Custom domains in the database (docs/plans/mail-custom-domains.md §1–2,
//! 8): adding within the limits, saving a check (with the rule for a name
//! another account holds), removing, and what happens to a domain's
//! addresses when it goes.

use sqlx::{FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::check::{self, Domain};
use super::policy::{state, Change, Status};
use super::records::{self, Resolver};
use super::settings::{Mode, Settings};
use crate::error::{AppError, AppResult};
use crate::security_events::{self, Kind};

/// How long between a challenger's two checks before a held name moves.
pub const TRANSFER_CONFIRM_SECS: i64 = 3600;
/// The second check must come within this of the first, or the transfer
/// starts over: two brief hijacks of the domain's DNS weeks apart never
/// add up to one.
pub const TRANSFER_CONFIRM_WINDOW_SECS: i64 = 48 * 3600;

#[derive(Debug, Clone, FromRow)]
pub struct Row {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub verify_code: String,
    pub state: i16,
    pub verify_state: i16,
    pub mx_state: i16,
    pub spf_state: i16,
    pub dkim_state: i16,
    pub dmarc_state: i16,
    pub dkim_good_once: bool,
    pub dkim_warning_since: Option<OffsetDateTime>,
    pub approved_at: Option<OffsetDateTime>,
    pub removed_at: Option<OffsetDateTime>,
    pub catch_all_address_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub checked_at: Option<OffsetDateTime>,
    pub verified_at: Option<OffsetDateTime>,
    pub failing_since: Option<OffsetDateTime>,
    pub warned_at: Option<OffsetDateTime>,
    pub stopped_at: Option<OffsetDateTime>,
    pub transfer_seen_at: Option<OffsetDateTime>,
    pub stalwart_signature_id: Option<String>,
    pub stalwart_signature_key: Option<String>,
}

pub const COLUMNS: &str =
    "id, user_id, name, verify_code, state, verify_state, mx_state, spf_state,
    dkim_state, dmarc_state, dkim_good_once, dkim_warning_since, approved_at, removed_at,
    catch_all_address_id, created_at, checked_at, verified_at, failing_since, warned_at,
    stopped_at, transfer_seen_at, stalwart_signature_id, stalwart_signature_key";

fn secs(at: Option<OffsetDateTime>) -> Option<i64> {
    at.map(OffsetDateTime::unix_timestamp)
}

fn at(secs: Option<i64>) -> Option<OffsetDateTime> {
    secs.and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
}

impl Row {
    pub fn domain(&self) -> Domain {
        Domain {
            id: self.id,
            name: self.name.clone(),
            verify_code: self.verify_code.clone(),
            status: Status {
                state: self.state,
                verified_at: secs(self.verified_at),
                failing_since: secs(self.failing_since),
                warned_at: secs(self.warned_at),
                stopped_at: secs(self.stopped_at),
            },
            verify_state: self.verify_state,
            mx_state: self.mx_state,
            spf_state: self.spf_state,
            dkim_state: self.dkim_state,
            dmarc_state: self.dmarc_state,
            dkim_good_once: self.dkim_good_once,
            dkim_warning_since: secs(self.dkim_warning_since),
        }
    }

    /// Mail flows: held, not stopped, approved where approval is asked.
    /// Whether the domain takes and sends mail now: held, not removed,
    /// approved where approval is on, and custom domains not turned off.
    pub fn usable(&self, settings: &Settings) -> bool {
        settings.mode != Mode::Off
            && self.removed_at.is_none()
            && self.domain().status.usable()
            && (settings.mode != Mode::AdminsApprove || self.approved_at.is_some())
    }
}

/// Why adding a domain was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRefusal {
    Off,
    AccountLimit,
    DailyLimit,
    ServerFull,
    Blocked,
}

impl AddRefusal {
    pub fn code(self) -> &'static str {
        match self {
            AddRefusal::Off => "customDomainsOff",
            AddRefusal::AccountLimit => "domainLimit",
            AddRefusal::DailyLimit => "domainDailyLimit",
            AddRefusal::ServerFull => "serverDomainLimit",
            AddRefusal::Blocked => "domainBlocked",
        }
    }
}

pub async fn list(pool: &PgPool, user: Uuid) -> AppResult<Vec<Row>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains WHERE user_id = $1 AND removed_at IS NULL ORDER BY name"
    ))
    .bind(user)
    .fetch_all(pool)
    .await?)
}

pub async fn get(pool: &PgPool, user: Uuid, id: Uuid) -> AppResult<Row> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains WHERE id = $1 AND user_id = $2 AND removed_at IS NULL"
    ))
    .bind(id)
    .bind(user)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("no such domain"))
}

/// Adds `name` (normalized) for `user`, or gives back the row it removed
/// before, with its code.
pub async fn add(
    pool: &PgPool,
    user: Uuid,
    name: &str,
    settings: &Settings,
) -> AppResult<Result<Row, AddRefusal>> {
    if settings.mode == Mode::Off || settings.domains_per_account == 0 {
        return Ok(Err(AddRefusal::Off));
    }
    let mut tx = pool.begin().await?;
    // One add at a time per account, so the counts hold.
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    let existing: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains WHERE user_id = $1 AND name = $2"
    ))
    .bind(user)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = &existing {
        if row.removed_at.is_none() {
            return Ok(Ok(row.clone()));
        }
    }
    if blocked(&mut tx, name).await? {
        return Ok(Err(AddRefusal::Blocked));
    }
    let (kept, today): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE removed_at IS NULL),
                count(*) FILTER (WHERE created_at > now() - interval '1 day')
           FROM mail_domains WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(&mut *tx)
    .await?;
    if kept >= settings.domains_per_account {
        return Ok(Err(AddRefusal::AccountLimit));
    }
    if today >= settings.adds_per_day {
        return Ok(Err(AddRefusal::DailyLimit));
    }
    let on_server: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mail_domains WHERE removed_at IS NULL AND state IN (1, 2)",
    )
    .fetch_one(&mut *tx)
    .await?;
    if on_server >= settings.domains_on_server {
        return Ok(Err(AddRefusal::ServerFull));
    }
    let row: Row = match existing {
        // Added again: the same row and code, its checks started over.
        Some(row) => {
            sqlx::query_as(&format!(
            "UPDATE mail_domains SET removed_at = NULL, state = 0, verify_state = 0, mx_state = 0,
                    spf_state = 0, dkim_state = 0, dmarc_state = 0, dkim_warning_since = NULL,
                    approved_at = NULL, catch_all_address_id = NULL, checked_at = NULL,
                    failing_since = NULL, warned_at = NULL, stopped_at = NULL,
                    transfer_seen_at = NULL, created_at = now()
              WHERE id = $1 RETURNING {COLUMNS}"
        ))
            .bind(row.id)
            .fetch_one(&mut *tx)
            .await?
        }
        None => {
            sqlx::query_as(&format!(
                "INSERT INTO mail_domains (user_id, name, verify_code) VALUES ($1, $2, $3)
             RETURNING {COLUMNS}"
            ))
            .bind(user)
            .bind(name)
            .bind(records::new_verify_code())
            .fetch_one(&mut *tx)
            .await?
        }
    };
    tx.commit().await?;
    Ok(Ok(row))
}

/// Whether an administrator blocked `name` (deactivated it for abuse).
async fn blocked(tx: &mut Transaction<'_, Postgres>, name: &str) -> AppResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mail_domain_blocks WHERE name = $1)")
            .bind(name)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Who holds `name` now, other than `id`: the holder's row id, account and
/// code.
async fn holder(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    id: Uuid,
) -> AppResult<Option<(Uuid, Uuid, String)>> {
    Ok(sqlx::query_as(
        "SELECT id, user_id, verify_code FROM mail_domains
          WHERE name = $1 AND id <> $2 AND state IN (1, 2) FOR UPDATE",
    )
    .bind(name)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Checks `row` now and saves what it found. A domain another account holds
/// is verified only as a transfer: two checks at least
/// [`TRANSFER_CONFIRM_SECS`] and at most [`TRANSFER_CONFIRM_WINDOW_SECS`]
/// apart that find this account's code and not the holder's, with no check
/// in between that missed this account's code; then one transaction moves
/// it and tells the holder. The DNS is read before the row is locked; if
/// the row changed meanwhile (another check, an administrator), this check
/// is dropped and the row returned as it is, so an old read never
/// overwrites newer state.
pub async fn check_and_save(
    pool: &PgPool,
    resolver: &dyn Resolver,
    server: &check::Server,
    settings: &Settings,
    row: &Row,
) -> AppResult<(Row, Change, Option<Uuid>)> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (mut checked, mut change) =
        check::check(resolver, server, &row.domain(), settings.grace(), now).await;
    let mut tx = pool.begin().await?;
    // The row as it is now, locked: a removal or another check in between wins.
    let current: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains WHERE id = $1 AND removed_at IS NULL FOR UPDATE"
    ))
    .bind(row.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        return Err(AppError::not_found("no such domain"));
    };
    if current.state != row.state || current.checked_at != row.checked_at {
        tx.commit().await?;
        return Ok((current, Change::None, None));
    }
    // The transfer's first sighting holds only while every check finds this
    // account's code.
    // The account that lost the domain to this one, to be told.
    let mut lost_holder = None;
    let mut transfer_seen = if checked.verify_state == records::verify::GOOD {
        current.transfer_seen_at
    } else {
        None
    };
    let becomes_held = matches!(change, Change::Verified | Change::Restored)
        && !matches!(current.state, state::VERIFIED | state::WARN);
    // A name an administrator blocked is verified by nobody, nor taken over.
    if becomes_held && blocked(&mut tx, &row.name).await? {
        checked.status = current.domain().status;
        change = Change::None;
        transfer_seen = None;
    } else if becomes_held {
        if let Some((holder_id, holder_user, holder_code)) =
            holder(&mut tx, &row.name, row.id).await?
        {
            let txt = resolver.txt(&row.name).await;
            let holder_gone = records::verify_state(&txt, &holder_code)
                .is_some_and(|state| state != records::verify::GOOD);
            // A first sighting too old to pair with this one starts over.
            let seen = transfer_seen.filter(|seen| {
                now - seen.unix_timestamp() <= super::scaled(TRANSFER_CONFIRM_WINDOW_SECS)
            });
            let confirmed = holder_gone
                && seen.is_some_and(|seen| {
                    now - seen.unix_timestamp() >= super::scaled(TRANSFER_CONFIRM_SECS)
                });
            if confirmed {
                lose(&mut tx, holder_id, holder_user, &row.name).await?;
                lost_holder = Some(holder_user);
                transfer_seen = None;
            } else {
                // Not yet (or not at all): pending, the holder untouched.
                transfer_seen = if holder_gone {
                    seen.or(at(Some(now)))
                } else {
                    None
                };
                checked.status = current.domain().status;
                change = Change::None;
            }
        }
    }
    if change == Change::Inactive {
        free_addresses(&mut tx, row.id).await?;
        security_events::record_names(
            &mut tx,
            row.user_id,
            Kind::DomainLost,
            None,
            None,
            &row.name,
            None,
        )
        .await?;
    }
    let saved: Row = sqlx::query_as(&format!(
        "UPDATE mail_domains SET state = $2, verify_state = $3, mx_state = $4, spf_state = $5,
                dkim_state = $6, dmarc_state = $7, dkim_good_once = $8, dkim_warning_since = $9,
                checked_at = now(), verified_at = $10, failing_since = $11, warned_at = $12,
                stopped_at = $13, transfer_seen_at = $14
          WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(row.id)
    .bind(checked.status.state)
    .bind(checked.verify_state)
    .bind(checked.mx_state)
    .bind(checked.spf_state)
    .bind(checked.dkim_state)
    .bind(checked.dmarc_state)
    .bind(checked.dkim_good_once)
    .bind(at(checked.dkim_warning_since))
    .bind(at(checked.status.verified_at))
    .bind(at(checked.status.failing_since))
    .bind(at(checked.status.warned_at))
    .bind(at(checked.status.stopped_at))
    .bind(transfer_seen)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((saved, change, lost_holder))
}

/// The holder loses a domain another account proved: inactive, its
/// addresses freed, and told.
async fn lose(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user: Uuid,
    name: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE mail_domains SET state = 0, failing_since = NULL, warned_at = NULL,
                stopped_at = NULL, catch_all_address_id = NULL
          WHERE id = $1 AND state IN (1, 2)",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    free_addresses(tx, id).await?;
    security_events::record_names(tx, user, Kind::DomainLost, None, None, name, None).await?;
    Ok(())
}

/// A domain's addresses go `freed`: their keys stay for old mail, nothing is
/// published for them, their forwardings end, and the name may be made
/// again by whoever holds the domain next.
pub async fn free_addresses(tx: &mut Transaction<'_, Postgres>, domain: Uuid) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM mail_forwardings
          WHERE forwarder_address_id IN (SELECT id FROM mail_addresses WHERE domain_id = $1)
             OR forwardee_address_id IN (SELECT id FROM mail_addresses WHERE domain_id = $1)",
    )
    .bind(domain)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE mail_domains SET catch_all_address_id = NULL WHERE id = $1")
        .bind(domain)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE mail_addresses SET state = 'freed' WHERE domain_id = $1 AND state <> 'freed'",
    )
    .bind(domain)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The owner removes a domain: its addresses are freed (Proton: "all the
/// addresses associated with it will be disabled"), the row stays removed
/// for its code.
pub async fn remove(pool: &PgPool, user: Uuid, id: Uuid) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    let removed = sqlx::query(
        "UPDATE mail_domains SET removed_at = now(), state = 0, approved_at = NULL,
                failing_since = NULL, warned_at = NULL, stopped_at = NULL, transfer_seen_at = NULL
          WHERE id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(id)
    .bind(user)
    .execute(&mut *tx)
    .await?;
    if removed.rows_affected() == 0 {
        return Err(AppError::not_found("no such domain"));
    }
    free_addresses(&mut tx, id).await?;
    tx.commit().await?;
    Ok(())
}

/// The domain's catch-all: one of its own addresses that receives, or none.
pub async fn set_catch_all(
    pool: &PgPool,
    user: Uuid,
    id: Uuid,
    address: Option<Uuid>,
    settings: &Settings,
) -> AppResult<()> {
    if address.is_some() && !settings.catch_all {
        return Err(AppError::forbidden("catch-all addresses are off"));
    }
    let mut tx = pool.begin().await?;
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mail_domains WHERE id = $1 AND user_id = $2 AND removed_at IS NULL FOR UPDATE"
    ))
    .bind(id)
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let row = row.ok_or_else(|| AppError::not_found("no such domain"))?;
    if let Some(address) = address {
        if !row.usable(settings) {
            return Err(AppError::conflict("the domain isn't verified")
                .with_details(serde_json::json!({ "code": "domainNotVerified" })));
        }
        let fits: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM mail_addresses
                             WHERE id = $1 AND domain_id = $2 AND user_id = $3 AND state = 'active')",
        )
        .bind(address)
        .bind(id)
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
        if !fits {
            return Err(AppError::bad_request(
                "the catch-all is an active address on the domain",
            ));
        }
    }
    sqlx::query("UPDATE mail_domains SET catch_all_address_id = $2 WHERE id = $1")
        .bind(id)
        .bind(address)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// An administrator ends a domain: inactive at once, its addresses freed,
/// its owner told. The name of the domain it was.
/// An administrator deactivates a domain (abuse): inactive at once, its
/// addresses freed, its owner told, and its name blocked until an
/// administrator lifts it ([`unblock`]), so no refresh brings it back.
/// The owner and the name.
pub async fn deactivate(pool: &PgPool, id: Uuid, admin: Uuid) -> AppResult<(Uuid, String)> {
    let mut tx = pool.begin().await?;
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE mail_domains SET state = 0, failing_since = NULL, warned_at = NULL,
                stopped_at = NULL, transfer_seen_at = NULL, approved_at = NULL
          WHERE id = $1 AND removed_at IS NULL RETURNING user_id, name",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (user, name) = row.ok_or_else(|| AppError::not_found("no such domain"))?;
    sqlx::query(
        "INSERT INTO mail_domain_blocks (name, blocked_by) VALUES ($1, $2)
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(&name)
    .bind(admin)
    .execute(&mut *tx)
    .await?;
    free_addresses(&mut tx, id).await?;
    security_events::record_names(&mut tx, user, Kind::DomainLost, None, None, &name, None).await?;
    tx.commit().await?;
    Ok((user, name))
}

/// An administrator lifts the block on the name of domain `id`: its owner
/// (or anyone) may prove it again.
pub async fn unblock(pool: &PgPool, id: Uuid) -> AppResult<String> {
    let name: Option<String> = sqlx::query_scalar(
        "DELETE FROM mail_domain_blocks
          WHERE name = (SELECT name FROM mail_domains WHERE id = $1)
         RETURNING name",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    name.ok_or_else(|| AppError::not_found("no such blocked domain"))
}
