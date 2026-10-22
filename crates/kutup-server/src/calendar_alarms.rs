//! Firing calendar reminders (docs/plans/calendar.md, E2 §4): each member's
//! next alarm per event and reminder, kept in `calendar_alarms`, and the job
//! that fires the due ones: a web push to the member's browsers (RFC 8291:
//! only the event's id and start, encrypted to each browser), or an email to
//! the member's own Kutup address saying only when. The server reads no
//! title, place or description: it can't.

use kutup_crypto::calendar_event::{CalendarSigned, EventTime, SharedSigned, TimeV1};
use kutup_crypto::calendar_recurrence::{Rule, Series};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::calendar_reminders::{self, Reminder, ReminderType};
use crate::site_settings::CALENDAR_REMINDER_LATENESS_SECONDS;
use crate::AppState;

/// How often the job looks for due alarms, and how many it takes at once.
const TICK: std::time::Duration = std::time::Duration::from_secs(20);
const BATCH: i64 = 200;

/// An event's series as a calendar shows it: the shared rule and both
/// parts' `EXDATE`s (E2b), and whether it is all-day.
pub fn series_of(shared: &str, calendar: &str) -> anyhow::Result<(Series, bool)> {
    let shared = SharedSigned::parse(shared)?;
    let calendar = CalendarSigned::parse(calendar)?;
    let rule = shared.rrule.as_deref().map(Rule::parse).transpose()?;
    let mut exdates = shared.exdates.clone();
    for exdate in calendar.exdates {
        if !exdates.contains(&exdate) {
            exdates.push(exdate);
        }
    }
    let all_day = shared.dtstart.is_date();
    let series = Series::new(
        &shared.dtstart,
        shared.dtend.as_ref(),
        rule.as_ref(),
        &exdates,
    )?;
    Ok((series, all_day))
}

/// When an occurrence starts for reminders: its instant; an all-day one's
/// midnight in the member's zone (it has none of its own).
fn reminder_start(start: &EventTime, start_utc: i64, zone: &str) -> anyhow::Result<i64> {
    match start {
        EventTime::Date(date) => {
            let midnight = TimeV1::Zoned {
                local: format!("{date}T00:00:00"),
                tzid: zone.to_owned(),
            };
            Ok(midnight.to_time()?.instant()?.as_second())
        }
        _ => Ok(start_utc),
    }
}

/// The first firing of a reminder `minutes` from each occurrence's start
/// at or after `from` (Unix seconds): the occurrence's start and the fire
/// time.
pub fn next_fire(
    series: &Series,
    zone: &str,
    minutes: i64,
    from: i64,
) -> anyhow::Result<Option<(i64, i64)>> {
    for occurrence in series.occurrences() {
        let occurrence = occurrence?;
        let start = reminder_start(&occurrence.start, occurrence.start_utc.as_second(), zone)?;
        let fire = start + minutes * 60;
        if fire >= from {
            return Ok(Some((occurrence.start_utc.as_second(), fire)));
        }
    }
    Ok(None)
}

fn at(seconds: i64) -> anyhow::Result<time::OffsetDateTime> {
    Ok(time::OffsetDateTime::from_unix_timestamp(seconds)?)
}

/// Sets every member's next alarms for an event: their own reminders, or
/// their calendar's defaults; none for an event gone. Called after the event
/// or a member's reminders or defaults change, under that change's
/// transaction.
pub async fn recompute(conn: &mut PgConnection, event_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM calendar_alarms WHERE event_id = $1")
        .bind(event_id)
        .execute(&mut *conn)
        .await?;
    let event: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT calendar_id, shared_signed, calendar_signed FROM calendar_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((calendar, shared, own)) = event else {
        return Ok(());
    };
    let (series, all_day) = series_of(&shared, &own)?;
    type Member = (
        Uuid,
        serde_json::Value,
        serde_json::Value,
        Option<serde_json::Value>,
        Option<String>,
    );
    let members: Vec<Member> = sqlx::query_as(
        "SELECT m.user_id, m.default_reminders_timed, m.default_reminders_all_day,
                r.reminders, s.zone
           FROM calendar_members m
           LEFT JOIN calendar_event_reminders r ON r.event_id = $2 AND r.user_id = m.user_id
           LEFT JOIN calendar_user_settings s ON s.user_id = m.user_id
          WHERE m.calendar_id = $1",
    )
    .bind(calendar)
    .bind(event_id)
    .fetch_all(&mut *conn)
    .await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (user, timed, full_day, own, zone) in members {
        let list = own.unwrap_or(if all_day { full_day } else { timed });
        // Stored as checked; a list that no longer reads fires nothing.
        let Ok(reminders) = serde_json::from_value::<Vec<Reminder>>(list) else {
            continue;
        };
        let zone = zone.unwrap_or_else(|| "UTC".into());
        for (index, reminder) in reminders.iter().enumerate() {
            let Ok(minutes) = calendar_reminders::trigger_minutes(&reminder.trigger, all_day)
            else {
                continue;
            };
            let Some((occurrence, fire)) = next_fire(&series, &zone, minutes, now)? else {
                continue;
            };
            sqlx::query(
                "INSERT INTO calendar_alarms
                   (user_id, event_id, reminder, action, occurrence_start, fire_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(user)
            .bind(event_id)
            .bind(index as i16)
            .bind(reminder.kind.as_str())
            .bind(at(occurrence)?)
            .bind(at(fire)?)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// Recomputes every event of a calendar for one member's new defaults.
pub async fn recompute_calendar(conn: &mut PgConnection, calendar: Uuid) -> anyhow::Result<()> {
    let events: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM calendar_events WHERE calendar_id = $1")
            .bind(calendar)
            .fetch_all(&mut *conn)
            .await?;
    for event in events {
        recompute(conn, event).await?;
    }
    Ok(())
}

/// One alarm the job took, to fire once its transaction committed.
struct Due {
    user: Uuid,
    event: Uuid,
    action: ReminderType,
    occurrence_start: time::OffsetDateTime,
}

/// The job: every `TICK`, the due alarms fire (each server takes its own,
/// so none fires twice), each moved to its reminder's next occurrence.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let client = crate::tls::client_builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("an HTTP client");
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = fire_due(&state, &client).await {
                tracing::warn!(error = %error, "calendar: firing reminders failed");
            }
        }
    });
}

async fn fire_due(state: &AppState, client: &reqwest::Client) -> anyhow::Result<()> {
    let lateness = CALENDAR_REMINDER_LATENESS_SECONDS.load(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    type Row = (
        Uuid,
        Uuid,
        i16,
        String,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT user_id, event_id, reminder, action, occurrence_start, fire_at
           FROM calendar_alarms WHERE fire_at <= now()
          ORDER BY fire_at LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await?;
    let now = time::OffsetDateTime::now_utc();
    let mut due = Vec::new();
    let mut moved = Vec::new();
    for (user, event, reminder, action, occurrence_start, fire_at) in rows {
        // Too late is never sent (Proton's web: a minute), only moved on.
        if (now - fire_at).whole_seconds() <= lateness {
            due.push(Due {
                user,
                event,
                action: if action == "email" {
                    ReminderType::Email
                } else {
                    ReminderType::Device
                },
                occurrence_start,
            });
        }
        moved.push((user, event, reminder, fire_at));
    }
    for (user, event, reminder, fire_at) in moved {
        advance(&mut tx, user, event, reminder, fire_at.unix_timestamp() + 1).await?;
    }
    tx.commit().await?;
    for alarm in due {
        let result = match alarm.action {
            ReminderType::Device => push(state, client, &alarm).await,
            ReminderType::Email => email(state, &alarm).await,
        };
        if let Err(error) = result {
            tracing::warn!(event = %alarm.event, error = %error, "calendar: a reminder was not sent");
        }
    }
    Ok(())
}

/// Moves one alarm to its reminder's next firing after `from`, or drops it.
async fn advance(
    conn: &mut PgConnection,
    user: Uuid,
    event: Uuid,
    reminder: i16,
    from: i64,
) -> anyhow::Result<()> {
    type Found = (
        String,
        String,
        serde_json::Value,
        serde_json::Value,
        Option<serde_json::Value>,
        Option<String>,
    );
    let found: Option<Found> = sqlx::query_as(
        "SELECT e.shared_signed, e.calendar_signed, m.default_reminders_timed,
                m.default_reminders_all_day, r.reminders, s.zone
           FROM calendar_events e
           JOIN calendar_members m ON m.calendar_id = e.calendar_id AND m.user_id = $2
           LEFT JOIN calendar_event_reminders r ON r.event_id = e.id AND r.user_id = $2
           LEFT JOIN calendar_user_settings s ON s.user_id = $2
          WHERE e.id = $1",
    )
    .bind(event)
    .bind(user)
    .fetch_optional(&mut *conn)
    .await?;
    let next = match found {
        None => None,
        Some((shared, own, timed, full_day, mine, zone)) => {
            let (series, all_day) = series_of(&shared, &own)?;
            let list = mine.unwrap_or(if all_day { full_day } else { timed });
            serde_json::from_value::<Vec<Reminder>>(list)
                .ok()
                .and_then(|reminders| reminders.into_iter().nth(reminder as usize))
                .and_then(|r| calendar_reminders::trigger_minutes(&r.trigger, all_day).ok())
                .map(|minutes| next_fire(&series, zone.as_deref().unwrap_or("UTC"), minutes, from))
                .transpose()?
                .flatten()
        }
    };
    match next {
        Some((occurrence, fire)) => {
            sqlx::query(
                "UPDATE calendar_alarms SET occurrence_start = $4, fire_at = $5
                  WHERE user_id = $1 AND event_id = $2 AND reminder = $3",
            )
            .bind(user)
            .bind(event)
            .bind(reminder)
            .bind(at(occurrence)?)
            .bind(at(fire)?)
            .execute(&mut *conn)
            .await?;
        }
        None => {
            sqlx::query(
                "DELETE FROM calendar_alarms WHERE user_id = $1 AND event_id = $2 AND reminder = $3",
            )
            .bind(user)
            .bind(event)
            .bind(reminder)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// A device reminder: to each of the member's signed-in browsers that
/// subscribed, the event's id and start only (Q-2), encrypted to the
/// browser. A subscription the push service no longer knows is dropped.
async fn push(state: &AppState, client: &reqwest::Client, alarm: &Due) -> anyhow::Result<()> {
    let Some(sender) = &state.web_push else {
        return Ok(());
    };
    let subscriptions: Vec<(Uuid, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT p.session_id, p.endpoint, p.p256dh, p.auth
           FROM calendar_push_subscriptions p
           JOIN auth_sessions a ON a.id = p.session_id
          WHERE p.user_id = $1 AND a.revoked_at IS NULL AND a.expires_at > now()",
    )
    .bind(alarm.user)
    .fetch_all(&state.pool)
    .await?;
    let start = alarm
        .occurrence_start
        .format(&time::format_description::well_known::Rfc3339)?;
    let payload = serde_json::json!({ "eventId": alarm.event, "startUtc": start }).to_string();
    for (session, endpoint, p256dh, auth) in subscriptions {
        let body = crate::web_push_payload::encrypt(&p256dh, &auth, payload.as_bytes())?;
        match sender
            .send_encrypted(client, &endpoint, body, "kutup-calendar")
            .await
        {
            Ok(status)
                if status == reqwest::StatusCode::NOT_FOUND
                    || status == reqwest::StatusCode::GONE =>
            {
                sqlx::query("DELETE FROM calendar_push_subscriptions WHERE session_id = $1")
                    .bind(session)
                    .execute(&state.pool)
                    .await?;
            }
            Ok(_) => {}
            Err(error) => tracing::debug!(error = %error, "calendar: a reminder push failed"),
        }
    }
    Ok(())
}

/// An email reminder: to the member's own Kutup address, only when (the
/// server can't read what), in their language and zone, with a link.
async fn email(state: &AppState, alarm: &Due) -> anyhow::Result<()> {
    let (language, zone): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT p.language, s.zone FROM users u
           LEFT JOIN user_ui_preferences p ON p.user_id = u.id
           LEFT JOIN calendar_user_settings s ON s.user_id = u.id
          WHERE u.id = $1",
    )
    .bind(alarm.user)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or_default();
    let zone = zone.unwrap_or_else(|| "UTC".into());
    let utc = alarm
        .occurrence_start
        .format(&time::format_description::well_known::Rfc3339)?;
    let local =
        kutup_crypto::calendar_event::utc_to_local(&utc, &zone).unwrap_or_else(|_| utc.clone());
    let when = format!("{} {} ({zone})", &local[..10], &local[11..16]);
    let link = format!("{}/?event={}", state.config.apps.calendar, alarm.event);
    let (subject, body) = if language.as_deref() == Some("tr") {
        (
            format!("Etkinlik hatırlatıcısı: {when}"),
            format!("{when} için bir etkinliğiniz var.\r\n\r\nAçmak için: {link}\r\n"),
        )
    } else {
        (
            format!("Event reminder: {when}"),
            format!("You have an event at {when}.\r\n\r\nOpen it: {link}\r\n"),
        )
    };
    crate::mail::notice::to_account(state, alarm.user, &subject, &body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(text: &str) -> i64 {
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
            .unwrap()
            .unix_timestamp()
    }

    #[test]
    fn a_reminder_fires_before_each_occurrence_in_turn() {
        let shared = SharedSigned {
            uid: "w@kutup.test".into(),
            dtstamp: "2026-10-21T08:00:00Z".parse().unwrap(),
            dtstart: TimeV1::Zoned {
                local: "2026-10-19T09:00:00".into(),
                tzid: "Europe/Berlin".into(),
            }
            .to_time()
            .unwrap(),
            dtend: Some(
                TimeV1::Zoned {
                    local: "2026-10-19T10:00:00".into(),
                    tzid: "Europe/Berlin".into(),
                }
                .to_time()
                .unwrap(),
            ),
            recurrence_id: None,
            rrule: Some("FREQ=WEEKLY;COUNT=3".into()),
            exdates: Vec::new(),
            organizer: None,
            sequence: 0,
        };
        let rule = Rule::parse("FREQ=WEEKLY;COUNT=3").unwrap();
        let series = Series::new(&shared.dtstart, shared.dtend.as_ref(), Some(&rule), &[]).unwrap();
        // 19 Oct 09:00 CEST is 07:00Z; 15 minutes before is 06:45Z.
        let first = utc("2026-10-19T06:45:00Z");
        assert_eq!(
            next_fire(&series, "UTC", -15, first).unwrap().unwrap().1,
            first
        );
        // Just past it: the next week, after the DST change (08:00Z start).
        let second = utc("2026-10-26T07:45:00Z");
        assert_eq!(
            next_fire(&series, "UTC", -15, first + 1)
                .unwrap()
                .unwrap()
                .1,
            second
        );
        // Past the last: none.
        let after = utc("2026-11-03T00:00:00Z");
        assert!(next_fire(&series, "UTC", -15, after).unwrap().is_none());
    }

    #[test]
    fn an_all_day_reminder_fires_in_the_member_s_zone() {
        let day = TimeV1::Date("2026-10-29".into()).to_time().unwrap();
        let series = Series::new(&day, None, None, &[]).unwrap();
        // 15 hours before Istanbul's midnight (21:00Z on the 28th): 06:00Z.
        let fire = next_fire(&series, "Europe/Istanbul", -15 * 60, 0)
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(fire, utc("2026-10-28T06:00:00Z"));
        let in_utc = next_fire(&series, "UTC", -15 * 60, 0).unwrap().unwrap().1;
        assert_eq!(in_utc, utc("2026-10-28T09:00:00Z"));
    }
}
