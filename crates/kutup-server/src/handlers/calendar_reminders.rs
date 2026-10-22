//! Calendar reminders' routes (docs/plans/calendar.md, E2 §4): the caller's
//! alarms in a window (Proton's `/alarms`, for the open app to fire its own),
//! the account's calendar zone (all-day reminders fire in it), and the
//! browsers that take reminder pushes.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::site_settings::CALENDAR_ALARMS_PAGE;
use crate::AppState;

fn coded(error: AppError, code: &str) -> AppError {
    error.with_details(serde_json::json!({ "code": code }))
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AlarmsQuery {
    /// RFC 3339: the window's start and end, by fire time.
    pub start: String,
    pub end: String,
    /// The last page's last alarm (its fire time and event), to go on after.
    pub after_fire: Option<String>,
    pub after_event: Option<Uuid>,
}

/// One alarm of the caller's.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlarmView {
    pub calendar_id: Uuid,
    pub event_id: Uuid,
    /// `device` or `email`.
    pub action: String,
    #[serde(with = "time::serde::rfc3339")]
    pub occurrence_start: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub fire_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Alarms {
    pub alarms: Vec<AlarmView>,
}

fn instant(text: &str, what: &str) -> AppResult<time::OffsetDateTime> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map_err(|_| AppError::bad_request(format!("{what} is an RFC 3339 time")))
}

/// `GET /api/calendar/alarms?start=&end=` — the caller's next alarms in a
/// window, by fire time, `calendarAlarmsPage` at most (Proton's `/alarms`):
/// the open app fires its own device notifications from these.
#[utoipa::path(
    get,
    path = "/api/calendar/alarms",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(AlarmsQuery),
    responses((status = 200, body = Alarms), (status = 400))
)]
pub async fn alarms(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<AlarmsQuery>,
) -> AppResult<Json<Alarms>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let start = instant(&query.start, "start")?;
    let end = instant(&query.end, "end")?;
    let after_fire = query
        .after_fire
        .as_deref()
        .map(|t| instant(t, "afterFire"))
        .transpose()?;
    if end <= start {
        return Err(AppError::bad_request("the window ends after it starts"));
    }
    let page = CALENDAR_ALARMS_PAGE.load(&state.pool).await?;
    type Row = (
        Uuid,
        Uuid,
        String,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT e.calendar_id, a.event_id, a.action, a.occurrence_start, a.fire_at
           FROM calendar_alarms a
           JOIN calendar_events e ON e.id = a.event_id
           JOIN calendar_members m ON m.calendar_id = e.calendar_id AND m.user_id = a.user_id
          WHERE a.user_id = $1 AND a.fire_at >= $2 AND a.fire_at < $3
            AND ($4::timestamptz IS NULL OR (a.fire_at, a.event_id) > ($4, $5))
          ORDER BY a.fire_at, a.event_id
          LIMIT $6",
    )
    .bind(user_id)
    .bind(start)
    .bind(end)
    .bind(after_fire)
    .bind(query.after_event.unwrap_or_default())
    .bind(page)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(Alarms {
        alarms: rows
            .into_iter()
            .map(
                |(calendar_id, event_id, action, occurrence_start, fire_at)| AlarmView {
                    calendar_id,
                    event_id,
                    action,
                    occurrence_start,
                    fire_at,
                },
            )
            .collect(),
    }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarSettings {
    /// The IANA zone the account's calendars show in; all-day reminders
    /// fire in it. Null: UTC until set.
    pub zone: Option<String>,
}

/// `GET /api/calendar/settings`
#[utoipa::path(
    get,
    path = "/api/calendar/settings",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = CalendarSettings))
)]
pub async fn settings(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<CalendarSettings>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let zone: Option<String> =
        sqlx::query_scalar("SELECT zone FROM calendar_user_settings WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(Json(CalendarSettings { zone }))
}

/// `PUT /api/calendar/settings` — the account's calendar zone; its all-day
/// reminders move with it.
#[utoipa::path(
    put,
    path = "/api/calendar/settings",
    tag = "calendar",
    security(("BearerAuth" = [])),
    request_body = CalendarSettings,
    responses((status = 200, body = CalendarSettings), (status = 400, description = "Not a known zone (unknownZone)"))
)]
pub async fn put_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<CalendarSettings>,
) -> AppResult<Json<CalendarSettings>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if let Some(zone) = &input.zone {
        // The bundled time zone database knows it.
        if kutup_crypto::calendar_event::utc_to_local("2026-01-01T00:00:00Z", zone).is_err() {
            return Err(coded(
                AppError::bad_request("not a known time zone"),
                "unknownZone",
            ));
        }
    }
    let mut tx = state.pool.begin().await?;
    match &input.zone {
        Some(zone) => {
            sqlx::query(
                "INSERT INTO calendar_user_settings (user_id, zone) VALUES ($1, $2)
                 ON CONFLICT (user_id) DO UPDATE SET zone = EXCLUDED.zone, updated_at = now()",
            )
            .bind(user_id)
            .bind(zone)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM calendar_user_settings WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    // The caller's all-day alarms fire in the new zone.
    let all_day: Vec<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM calendar_events e
           JOIN calendar_members m ON m.calendar_id = e.calendar_id AND m.user_id = $1
          WHERE e.full_day",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    for event in all_day {
        crate::calendar_alarms::recompute(&mut tx, event)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    tx.commit().await?;
    Ok(Json(input))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarPushSubscription {
    /// The browser's `PushSubscription`: its endpoint, and its keys
    /// (`p256dh`, `auth`, base64url) for RFC 8291.
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

/// `PUT /api/calendar/push-subscription` — this signed-in browser takes
/// reminder pushes (one subscription per session; signing out ends it).
/// The push services are Chat's allowlist.
#[utoipa::path(
    put,
    path = "/api/calendar/push-subscription",
    tag = "calendar",
    security(("BearerAuth" = [])),
    request_body = CalendarPushSubscription,
    responses((status = 204), (status = 400), (status = 404, description = "Web Push is off on this server"))
)]
pub async fn put_push_subscription(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<CalendarPushSubscription>,
) -> AppResult<StatusCode> {
    let push = state
        .web_push
        .as_ref()
        .ok_or_else(|| AppError::not_found("Web Push is off on this server"))?;
    if !push.allowed_endpoint(&input.endpoint) {
        return Err(AppError::bad_request(
            "this push service is not one the server sends to",
        ));
    }
    let p256dh = URL_SAFE_NO_PAD
        .decode(input.p256dh.trim_end_matches('='))
        .ok()
        .filter(|key| key.len() == 65 && p256::PublicKey::from_sec1_bytes(key).is_ok())
        .ok_or_else(|| AppError::bad_request("p256dh is a P-256 public key"))?;
    let auth = URL_SAFE_NO_PAD
        .decode(input.auth.trim_end_matches('='))
        .ok()
        .filter(|auth| auth.len() == 16)
        .ok_or_else(|| AppError::bad_request("auth is 16 bytes"))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let session = user.session.session_id;
    sqlx::query(
        "INSERT INTO calendar_push_subscriptions (session_id, user_id, endpoint, p256dh, auth)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (session_id) DO UPDATE
            SET endpoint = EXCLUDED.endpoint, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth",
    )
    .bind(session)
    .bind(user_id)
    .bind(&input.endpoint)
    .bind(&p256dh)
    .bind(&auth)
    .execute(&state.pool)
    .await
    .map_err(|error| match &error {
        // The browser's endpoint under another session of someone's.
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("this browser's subscription is another session's")
        }
        _ => error.into(),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/calendar/push-subscription` — this browser takes no more.
#[utoipa::path(
    delete,
    path = "/api/calendar/push-subscription",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 204))
)]
pub async fn delete_push_subscription(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM calendar_push_subscriptions WHERE session_id = $1")
        .bind(user.session.session_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
