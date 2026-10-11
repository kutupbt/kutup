//! Auto-reply settings (docs/plans/mail-parity.md, P2), as Proton's
//! AutoResponder; [`crate::mail::auto_reply`] sends the answers.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::mail::auto_reply::{self, format_local, parse_local, Schedule, MAX_MESSAGE_BYTES};
use crate::middleware::AuthUser;
use crate::AppState;

/// When it is on and what it says. Times are wall-clock times in `zone`.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutoReplySettings {
    pub enabled: bool,
    /// `fixed`, `daily`, `weekly`, `monthly` or `permanent`.
    pub repeat: String,
    /// An IANA time zone, such as `Europe/Istanbul`.
    pub zone: String,
    /// Fixed: `YYYY-MM-DDTHH:MM`.
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub end: Option<String>,
    /// Daily: the weekdays it is on, 0 Sunday to 6 Saturday.
    #[serde(default)]
    pub days: Vec<i16>,
    /// Weekly: a weekday 0–6; monthly: a day of the month 1–31.
    #[serde(default)]
    pub start_day: Option<i16>,
    #[serde(default)]
    pub end_day: Option<i16>,
    /// Daily, weekly, monthly: minutes after midnight.
    #[serde(default)]
    pub start_minute: Option<i16>,
    #[serde(default)]
    pub end_minute: Option<i16>,
    /// The message, as HTML and as plain text.
    pub message_html: String,
    pub message_text: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoReply {
    /// None until one is saved.
    pub settings: Option<AutoReplySettings>,
    /// Sending answers now: on and inside its schedule.
    pub active: bool,
}

fn settings_of(saved: &auto_reply::Saved) -> AutoReplySettings {
    let mut settings = AutoReplySettings {
        enabled: saved.enabled,
        repeat: saved.schedule.repeat().into(),
        zone: saved.zone.clone(),
        start: None,
        end: None,
        days: Vec::new(),
        start_day: None,
        end_day: None,
        start_minute: None,
        end_minute: None,
        message_html: saved.message_html.clone(),
        message_text: saved.message_text.clone(),
    };
    match &saved.schedule {
        Schedule::Fixed { start, end } => {
            settings.start = Some(format_local(*start));
            settings.end = Some(format_local(*end));
        }
        Schedule::Daily {
            days,
            start_minute,
            end_minute,
        } => {
            settings.days = days.iter().map(|d| i16::from(*d)).collect();
            settings.start_minute = i16::try_from(*start_minute).ok();
            settings.end_minute = i16::try_from(*end_minute).ok();
        }
        Schedule::Weekly {
            start_day,
            start_minute,
            end_day,
            end_minute,
        }
        | Schedule::Monthly {
            start_day,
            start_minute,
            end_day,
            end_minute,
        } => {
            settings.start_day = Some(i16::from(*start_day));
            settings.end_day = Some(i16::from(*end_day));
            settings.start_minute = i16::try_from(*start_minute).ok();
            settings.end_minute = i16::try_from(*end_minute).ok();
        }
        Schedule::Permanent => {}
    }
    settings
}

async fn current(state: &AppState, user_id: Uuid) -> AppResult<AutoReply> {
    let saved = auto_reply::load(&state.pool, user_id).await?;
    Ok(AutoReply {
        active: saved.as_ref().is_some_and(auto_reply::Saved::is_on),
        settings: saved.as_ref().map(settings_of),
    })
}

/// `GET /api/mail/auto-reply`.
#[utoipa::path(
    get,
    path = "/api/mail/auto-reply",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The account's auto-reply", body = AutoReply))
)]
pub async fn get(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<AutoReply>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(current(&state, user_id).await?))
}

fn minute(value: Option<i16>) -> AppResult<i16> {
    value
        .filter(|m| (0..24 * 60).contains(m))
        .ok_or_else(|| AppError::bad_request("times are minutes after midnight, 0 to 1439"))
}

/// `PUT /api/mail/auto-reply` — saves it whole; whoever was answered may be
/// answered again.
#[utoipa::path(
    put,
    path = "/api/mail/auto-reply",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = AutoReplySettings,
    responses(
        (status = 200, description = "Saved", body = AutoReply),
        (status = 400, description = "An unknown repeat or time zone, a schedule that does not fit it, a message over 10 KB or, when on, empty"),
    )
)]
pub async fn put(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AutoReplySettings>,
) -> AppResult<Json<AutoReply>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if request.message_html.len() > MAX_MESSAGE_BYTES
        || request.message_text.len() > MAX_MESSAGE_BYTES
    {
        return Err(AppError::bad_request("the message is 10 KB at most"));
    }
    if request.enabled && request.message_text.trim().is_empty() {
        return Err(AppError::bad_request("write the message to answer with"));
    }
    let zone_known: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)")
            .bind(&request.zone)
            .fetch_one(&state.pool)
            .await?;
    if !zone_known {
        return Err(AppError::bad_request("unknown time zone"));
    }
    let (mut start, mut end, mut days) = (None, None, Vec::new());
    let (mut start_day, mut end_day, mut start_minute, mut end_minute) = (None, None, None, None);
    match request.repeat.as_str() {
        "fixed" => {
            let parse = |value: &Option<String>| {
                value.as_deref().and_then(parse_local).ok_or_else(|| {
                    AppError::bad_request("a fixed period has a start and an end, YYYY-MM-DDTHH:MM")
                })
            };
            let (from, until) = (parse(&request.start)?, parse(&request.end)?);
            if until <= from {
                return Err(AppError::bad_request("the end comes after the start"));
            }
            (start, end) = (Some(from), Some(until));
        }
        "daily" => {
            let mut chosen = request.days.clone();
            chosen.sort_unstable();
            chosen.dedup();
            if chosen.is_empty() || chosen.iter().any(|d| !(0..=6).contains(d)) {
                return Err(AppError::bad_request(
                    "choose weekdays, 0 Sunday to 6 Saturday",
                ));
            }
            days = chosen;
            (start_minute, end_minute) = (
                Some(minute(request.start_minute)?),
                Some(minute(request.end_minute)?),
            );
        }
        "weekly" | "monthly" => {
            let range = if request.repeat == "weekly" {
                0..=6
            } else {
                1..=31
            };
            let day = |value: Option<i16>| {
                value.filter(|d| range.contains(d)).ok_or_else(|| {
                    AppError::bad_request("a weekday is 0–6, a day of the month 1–31")
                })
            };
            (start_day, end_day) = (Some(day(request.start_day)?), Some(day(request.end_day)?));
            (start_minute, end_minute) = (
                Some(minute(request.start_minute)?),
                Some(minute(request.end_minute)?),
            );
        }
        "permanent" => {}
        _ => {
            return Err(AppError::bad_request(
                "repeat is fixed, daily, weekly, monthly or permanent",
            ))
        }
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO mail_auto_replies
            (user_id, enabled, repeat, zone, start_local, end_local, days, start_day, end_day,
             start_minute, end_minute, message_html, message_text)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (user_id) DO UPDATE SET
             enabled = $2, repeat = $3, zone = $4, start_local = $5, end_local = $6, days = $7,
             start_day = $8, end_day = $9, start_minute = $10, end_minute = $11,
             message_html = $12, message_text = $13, updated_at = now()",
    )
    .bind(user_id)
    .bind(request.enabled)
    .bind(&request.repeat)
    .bind(&request.zone)
    .bind(start)
    .bind(end)
    .bind(&days)
    .bind(start_day)
    .bind(end_day)
    .bind(start_minute)
    .bind(end_minute)
    .bind(&request.message_html)
    .bind(&request.message_text)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM mail_auto_reply_sent WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(current(&state, user_id).await?))
}
