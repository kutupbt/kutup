//! Sending safety (docs/plans/mail.md): one account sending spam can get the
//! server's address blocklisted, and then nobody's mail arrives. Limits on
//! outside recipients (lower in an account's first week), refusals of mail
//! Stalwart scores as spam, bounces counted from delivery reports, and the
//! automatic pause and flag they lead to; an administrator can override all
//! of it per account. Mail between Kutup users is never limited here: it
//! never leaves the server.

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::AppState;

/// Outside recipients an account may send to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub per_hour: i64,
    pub per_day: i64,
}

/// An account's sending state, as the send path and the admin page see it.
#[derive(Debug, Clone)]
pub struct Standing {
    pub limits: Limits,
    /// Whether the limits are the new-account ones.
    pub new_account: bool,
    pub paused: Option<String>,
    pub sent_hour: i64,
    pub sent_day: i64,
}

/// Bounces in a day that pause sending when they are also this share of
/// what was sent: 10 and 10 %, as large providers start to block.
const BOUNCE_PAUSE_COUNT: i64 = 10;
const BOUNCE_PAUSE_PERCENT: i64 = 10;
/// Bounces in a day that flag the account for the administrator.
const BOUNCE_FLAG_COUNT: i64 = 5;
const BOUNCE_FLAG_PERCENT: i64 = 5;
/// Spam refusals in a day that pause sending (the first one flags).
const SPAM_PAUSE_COUNT: i64 = 3;

/// The limits, pause and today's sending of `user_id`.
pub async fn standing(state: &AppState, user_id: Uuid) -> AppResult<Standing> {
    let row: (
        time::OffsetDateTime,
        Option<i32>,
        Option<i32>,
        Option<String>,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT u.created_at, p.per_hour, p.per_day, p.paused_reason,
                COALESCE((SELECT SUM(external_recipients) FROM mail_messages
                           WHERE sender_account = u.id AND external_recipients > 0
                             AND received_at > now() - interval '1 hour'), 0)::bigint,
                COALESCE((SELECT SUM(external_recipients) FROM mail_messages
                           WHERE sender_account = u.id AND external_recipients > 0
                             AND received_at > now() - interval '1 day'), 0)::bigint
           FROM users u LEFT JOIN mail_sending_policies p ON p.user_id = u.id
          WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let (created_at, per_hour, per_day, paused, sent_hour, sent_day) = row;
    let config = &state.config;
    let new_account = time::OffsetDateTime::now_utc() - created_at
        < time::Duration::days(config.mail_new_account_days);
    let base = if new_account {
        Limits {
            per_hour: config
                .mail_new_account_per_day
                .min(config.mail_send_per_hour),
            per_day: config.mail_new_account_per_day,
        }
    } else {
        Limits {
            per_hour: config.mail_send_per_hour,
            per_day: config.mail_send_per_day,
        }
    };
    Ok(Standing {
        limits: Limits {
            per_hour: per_hour.map(i64::from).unwrap_or(base.per_hour),
            per_day: per_day.map(i64::from).unwrap_or(base.per_day),
        },
        new_account: new_account && per_hour.is_none() && per_day.is_none(),
        paused,
        sent_hour,
        sent_day,
    })
}

/// Refuses a send of `adding` outside recipients that the account may not
/// make now: paused (403 `sendingPaused`) or over a limit (429 `sendLimit`).
pub async fn check_send(state: &AppState, user_id: Uuid, adding: i64) -> AppResult<()> {
    let standing = standing(state, user_id).await?;
    if let Some(reason) = standing.paused {
        return Err(
            AppError::forbidden("sending to outside addresses is paused for this account")
                .with_details(json!({ "code": "sendingPaused", "reason": reason })),
        );
    }
    if standing.sent_hour + adding > standing.limits.per_hour
        || standing.sent_day + adding > standing.limits.per_day
    {
        return Err(
            AppError::too_many_requests("sending limit reached; try again later").with_details(
                json!({
                    "code": "sendLimit",
                    "perHour": standing.limits.per_hour,
                    "perDay": standing.limits.per_day,
                    "newAccount": standing.new_account,
                }),
            ),
        );
    }
    Ok(())
}

/// What happened to an account's mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Bounce,
    SpamRefused,
}

impl Event {
    fn kind(self) -> &'static str {
        match self {
            Event::Bounce => "bounce",
            Event::SpamRefused => "spam_refused",
        }
    }
}

/// Records `count` events of `user_id` and pauses or flags the account when
/// they pass the thresholds.
pub async fn record(pool: &PgPool, user_id: Uuid, event: Event, count: u32) -> sqlx::Result<()> {
    let count = count.clamp(1, 100) as i32;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO mail_sending_events (user_id, kind) SELECT $1, $2 FROM generate_series(1, $3)",
    )
    .bind(user_id)
    .bind(event.kind())
    .bind(count)
    .execute(&mut *tx)
    .await?;
    let (events, sent): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM mail_sending_events
                  WHERE user_id = $1 AND kind = $2 AND created_at > now() - interval '1 day'),
                COALESCE((SELECT SUM(external_recipients) FROM mail_messages
                           WHERE sender_account = $1 AND external_recipients > 0
                             AND received_at > now() - interval '1 day'), 0)::bigint",
    )
    .bind(user_id)
    .bind(event.kind())
    .fetch_one(&mut *tx)
    .await?;
    let (flag, pause): (Option<&str>, Option<&str>) = match event {
        Event::SpamRefused => (Some("spam"), (events >= SPAM_PAUSE_COUNT).then_some("spam")),
        Event::Bounce => {
            let share = |count: i64, percent: i64| count * 100 >= sent.max(1) * percent;
            (
                (events >= BOUNCE_FLAG_COUNT && share(events, BOUNCE_FLAG_PERCENT))
                    .then_some("bounces"),
                (events >= BOUNCE_PAUSE_COUNT && share(events, BOUNCE_PAUSE_PERCENT))
                    .then_some("bounces"),
            )
        }
    };
    if flag.is_some() || pause.is_some() {
        sqlx::query(
            "INSERT INTO mail_sending_policies (user_id, flagged_at, flag_reason, paused_at, paused_reason)
             VALUES ($1, CASE WHEN $2::text IS NULL THEN NULL ELSE now() END, $2,
                     CASE WHEN $3::text IS NULL THEN NULL ELSE now() END, $3)
             ON CONFLICT (user_id) DO UPDATE SET
                 flagged_at = COALESCE(mail_sending_policies.flagged_at, EXCLUDED.flagged_at),
                 flag_reason = COALESCE(mail_sending_policies.flag_reason, EXCLUDED.flag_reason),
                 paused_at = COALESCE(mail_sending_policies.paused_at, EXCLUDED.paused_at),
                 paused_reason = COALESCE(mail_sending_policies.paused_reason, EXCLUDED.paused_reason),
                 updated_at = now()",
        )
        .bind(user_id)
        .bind(flag)
        .bind(pause)
        .execute(&mut *tx)
        .await?;
        if let Some(reason) = pause {
            tracing::warn!(user = %user_id, reason, "mail: sending paused automatically");
        }
    }
    tx.commit().await
}

/// Counts a delivery report among `user_id`'s mail as bounces, but only
/// when it names a message this account sent outside through Kutup: anyone
/// can mail a forged report.
pub async fn record_bounce(
    pool: &PgPool,
    user_id: Uuid,
    original_message_id: &str,
    failures: u32,
) -> sqlx::Result<bool> {
    let ours: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_messages
                         WHERE sender_account = $1 AND message_id = $2 AND direction = 'outbound'
                           AND external_recipients > 0)",
    )
    .bind(user_id)
    .bind(original_message_id)
    .fetch_one(pool)
    .await?;
    if ours {
        record(pool, user_id, Event::Bounce, failures).await?;
    }
    Ok(ours)
}

/// Drops events older than 30 days.
pub async fn sweep(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(
        sqlx::query(
            "DELETE FROM mail_sending_events WHERE created_at < now() - interval '30 days'",
        )
        .execute(pool)
        .await?
        .rows_affected(),
    )
}
