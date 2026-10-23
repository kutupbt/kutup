//! Firing calendar reminders (docs/plans/calendar.md, E2 §4): each member's
//! next alarm per event and reminder, kept in `calendar_alarms`, and the job
//! that fires the due ones: a web push to the member's browsers (RFC 8291:
//! only the event's id and start, encrypted to each browser), or an email to
//! the member's own Kutup address saying only when. The server reads no
//! title, place or description: it can't.

use std::collections::HashMap;

use futures_util::StreamExt as _;
use kutup_crypto::calendar_event::{CalendarSigned, EventTime, SharedSigned, TimeV1};
use kutup_crypto::calendar_recurrence::{Rule, Series};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::calendar_reminders::{self, Reminder, ReminderType};
use crate::site_settings::{
    CALENDAR_ALARMS_PER_ACCOUNT, CALENDAR_ALARM_BATCH, CALENDAR_ALARM_BATCH_PER_ACCOUNT,
    CALENDAR_ALARM_SENDS, CALENDAR_ALARM_TICK_SECONDS, CALENDAR_RECOMPUTE_BATCH,
    CALENDAR_REMINDER_LATENESS_SECONDS,
};
use crate::AppState;

/// A reminder push's longest life at the push service: a week (a reminder
/// for an occurrence further off is never sent that early).
const MAX_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

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
/// time. The walk starts about where that occurrence is (a series without
/// `COUNT` skips the years before it).
pub fn next_fire(
    series: &Series,
    zone: &str,
    minutes: i64,
    from: i64,
) -> anyhow::Result<Option<(i64, i64)>> {
    // An occurrence firing at `from` starts `minutes` from it; a day more
    // for an all-day start in the member's zone.
    let earliest = from - minutes * 60 - 2 * 24 * 60 * 60;
    for occurrence in series.occurrences_from(earliest) {
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
/// or a member's reminders change, under that change's transaction.
pub async fn recompute(conn: &mut PgConnection, event_id: Uuid) -> anyhow::Result<()> {
    recompute_for(conn, event_id, None).await
}

/// [`recompute`] for one member only (`Some`), or every member. An account
/// keeps at most `calendarAlarmsPerAccount` alarms: reminders past it fire
/// nothing until others are gone.
async fn recompute_for(
    conn: &mut PgConnection,
    event_id: Uuid,
    only: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "DELETE FROM calendar_alarms WHERE event_id = $1 AND ($2::uuid IS NULL OR user_id = $2)",
    )
    .bind(event_id)
    .bind(only)
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
    let most = CALENDAR_ALARMS_PER_ACCOUNT.load(&mut *conn).await?;
    type Member = (
        Uuid,
        serde_json::Value,
        serde_json::Value,
        Option<serde_json::Value>,
        Option<String>,
        i64,
    );
    let members: Vec<Member> = sqlx::query_as(
        "SELECT m.user_id, m.default_reminders_timed, m.default_reminders_all_day,
                r.reminders, s.zone,
                (SELECT count(*) FROM calendar_alarms a WHERE a.user_id = m.user_id)
           FROM calendar_members m
           LEFT JOIN calendar_event_reminders r ON r.event_id = $2 AND r.user_id = m.user_id
           LEFT JOIN calendar_user_settings s ON s.user_id = m.user_id
          WHERE m.calendar_id = $1 AND ($3::uuid IS NULL OR m.user_id = $3)",
    )
    .bind(calendar)
    .bind(event_id)
    .bind(only)
    .fetch_all(&mut *conn)
    .await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (user, timed, full_day, own, zone, held) in members {
        let list = own.unwrap_or(if all_day { full_day } else { timed });
        // Stored as checked; a list that no longer reads fires nothing.
        let Ok(reminders) = serde_json::from_value::<Vec<Reminder>>(list) else {
            continue;
        };
        let zone = zone.unwrap_or_else(|| "UTC".into());
        let mut held = held;
        for (index, reminder) in reminders.iter().enumerate() {
            if held >= most {
                break;
            }
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
            held += 1;
        }
    }
    Ok(())
}

/// Asks the job to recompute a member's alarms: in one calendar (their
/// defaults there changed), or in all of theirs (`None`: their zone
/// changed). A request already waiting starts over.
pub async fn queue_recompute(
    conn: &mut PgConnection,
    user: Uuid,
    calendar: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO calendar_alarm_recomputes (user_id, calendar_id)
         SELECT $1, m.calendar_id FROM calendar_members m
          WHERE m.user_id = $1 AND ($2::uuid IS NULL OR m.calendar_id = $2)
         ON CONFLICT (user_id, calendar_id)
            DO UPDATE SET after_event = NULL, requested_at = now()",
    )
    .bind(user)
    .bind(calendar)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// One alarm the job took, to fire once its transaction committed.
struct Due {
    user: Uuid,
    event: Uuid,
    action: ReminderType,
    occurrence_start: time::OffsetDateTime,
    all_day: bool,
}

/// The job: every `calendarAlarmTickSeconds`, the due alarms fire, batch by
/// batch until none is due (each server takes its own, so none fires
/// twice), each moved to its reminder's next occurrence; then waiting
/// recomputes go on.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        // Chat's push client: no redirects (the push service allowlist
        // holds for the URL sent to, never another), short timeouts.
        let client = match crate::tls::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, "calendar: cannot build an HTTP client; reminders are off");
                return;
            }
        };
        loop {
            let tick = CALENDAR_ALARM_TICK_SECONDS
                .load(&state.pool)
                .await
                .unwrap_or(CALENDAR_ALARM_TICK_SECONDS.default);
            tokio::time::sleep(std::time::Duration::from_secs(tick as u64)).await;
            loop {
                match fire_due(&state, &client).await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(error) => {
                        tracing::warn!(error = %error, "calendar: firing reminders failed");
                        break;
                    }
                }
            }
            if let Err(error) = recompute_queued(&state).await {
                tracing::warn!(error = %error, "calendar: recomputing reminders failed");
            }
        }
    });
}

/// One batch of due alarms: sent (at most `calendarAlarmSends` at once,
/// after the batch's transaction) unless later than the lateness, and moved
/// on. Whether the batch was full (more may be due).
async fn fire_due(state: &AppState, client: &reqwest::Client) -> anyhow::Result<bool> {
    let lateness = CALENDAR_REMINDER_LATENESS_SECONDS.load(&state.pool).await?;
    let batch = CALENDAR_ALARM_BATCH.load(&state.pool).await?;
    let per_account = CALENDAR_ALARM_BATCH_PER_ACCOUNT.load(&state.pool).await?;
    let sends = CALENDAR_ALARM_SENDS.load(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    type Row = (
        Uuid,
        Uuid,
        i16,
        String,
        time::OffsetDateTime,
        time::OffsetDateTime,
        String,
        String,
        serde_json::Value,
        serde_json::Value,
        Option<serde_json::Value>,
        Option<String>,
    );
    // The earliest due first, at most `per_account` of one account's, so
    // one account's many never make the others' late; with what moving each
    // on reads.
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.user_id, a.event_id, a.reminder, a.action, a.occurrence_start, a.fire_at,
                e.shared_signed, e.calendar_signed, m.default_reminders_timed,
                m.default_reminders_all_day, r.reminders, s.zone
           FROM calendar_alarms a
           JOIN (SELECT user_id, event_id, reminder,
                        row_number() OVER (PARTITION BY user_id ORDER BY fire_at) AS place
                   FROM calendar_alarms WHERE fire_at <= now()) d
             ON d.user_id = a.user_id AND d.event_id = a.event_id AND d.reminder = a.reminder
           JOIN calendar_events e ON e.id = a.event_id
           JOIN calendar_members m ON m.calendar_id = e.calendar_id AND m.user_id = a.user_id
           LEFT JOIN calendar_event_reminders r ON r.event_id = a.event_id AND r.user_id = a.user_id
           LEFT JOIN calendar_user_settings s ON s.user_id = a.user_id
          WHERE d.place <= $2
          ORDER BY a.fire_at
          LIMIT $1
          FOR UPDATE OF a SKIP LOCKED",
    )
    .bind(batch)
    .bind(per_account)
    .fetch_all(&mut *tx)
    .await?;
    let full = rows.len() as i64 == batch;
    let now = time::OffsetDateTime::now_utc();
    let mut due = Vec::new();
    // Each event's series read once per batch.
    let mut series: HashMap<Uuid, Option<(Series, bool)>> = HashMap::new();
    for (
        user,
        event,
        reminder,
        action,
        occurrence_start,
        fire_at,
        shared,
        own,
        timed,
        full_day,
        mine,
        zone,
    ) in rows
    {
        let parsed = series
            .entry(event)
            .or_insert_with(|| series_of(&shared, &own).ok());
        let late = (now - fire_at).whole_seconds() > lateness;
        // Too late is never sent (Proton's web: a minute), only moved on.
        if !late {
            due.push(Due {
                user,
                event,
                action: if action == "email" {
                    ReminderType::Email
                } else {
                    ReminderType::Device
                },
                occurrence_start,
                all_day: parsed.as_ref().is_some_and(|(_, all_day)| *all_day),
            });
        }
        // A late one moves past now: the occurrences it missed are skipped
        // in one step, never fired one batch at a time.
        let from = if late {
            now.unix_timestamp()
        } else {
            fire_at.unix_timestamp() + 1
        };
        let next = match parsed {
            None => None,
            Some((series, all_day)) => {
                let list = mine.unwrap_or(if *all_day { full_day } else { timed });
                serde_json::from_value::<Vec<Reminder>>(list)
                    .ok()
                    .and_then(|reminders| reminders.into_iter().nth(reminder as usize))
                    .and_then(|r| calendar_reminders::trigger_minutes(&r.trigger, *all_day).ok())
                    .map(|minutes| {
                        next_fire(series, zone.as_deref().unwrap_or("UTC"), minutes, from)
                    })
                    .transpose()?
                    .flatten()
            }
        };
        moved(&mut tx, user, event, reminder, next).await?;
    }
    tx.commit().await?;
    futures_util::stream::iter(due)
        .for_each_concurrent(sends.max(1) as usize, |alarm| async move {
            let result = match alarm.action {
                ReminderType::Device => push(state, client, &alarm, lateness).await,
                ReminderType::Email => email(state, &alarm).await,
            };
            if let Err(error) = result {
                tracing::warn!(event = %alarm.event, error = %error, "calendar: a reminder was not sent");
            }
        })
        .await;
    Ok(full)
}

/// Sets one alarm to its next firing, or drops it.
async fn moved(
    conn: &mut PgConnection,
    user: Uuid,
    event: Uuid,
    reminder: i16,
    next: Option<(i64, i64)>,
) -> anyhow::Result<()> {
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

/// Recomputes waiting members' alarms, `calendarRecomputeBatch` events at a
/// time per request, each request taken by one server.
async fn recompute_queued(state: &AppState) -> anyhow::Result<()> {
    let batch = CALENDAR_RECOMPUTE_BATCH.load(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    let waiting: Vec<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT user_id, calendar_id, after_event FROM calendar_alarm_recomputes
          ORDER BY requested_at LIMIT 10 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (user, calendar, after) in waiting {
        let events: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM calendar_events
              WHERE calendar_id = $1 AND ($2::uuid IS NULL OR id > $2)
              ORDER BY id LIMIT $3",
        )
        .bind(calendar)
        .bind(after)
        .bind(batch)
        .fetch_all(&mut *tx)
        .await?;
        for event in &events {
            recompute_for(&mut tx, *event, Some(user)).await?;
        }
        if (events.len() as i64) < batch {
            sqlx::query(
                "DELETE FROM calendar_alarm_recomputes WHERE user_id = $1 AND calendar_id = $2",
            )
            .bind(user)
            .bind(calendar)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE calendar_alarm_recomputes SET after_event = $3
                  WHERE user_id = $1 AND calendar_id = $2",
            )
            .bind(user)
            .bind(calendar)
            .bind(events.last())
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// A device reminder: to each of the member's signed-in browsers that
/// subscribed, the event's id and start only (Q-2), encrypted to the
/// browser. It lives at the push service until the occurrence starts (at
/// least the lateness), one per event (a newer replaces an older not yet
/// delivered). A subscription the push service no longer knows is dropped.
async fn push(
    state: &AppState,
    client: &reqwest::Client,
    alarm: &Due,
    lateness: i64,
) -> anyhow::Result<()> {
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
    let until_start = (alarm.occurrence_start - time::OffsetDateTime::now_utc()).whole_seconds();
    let ttl = until_start.max(lateness).clamp(1, MAX_TTL_SECONDS) as u32;
    // A Topic is at most 32 base64url characters: the event id's hex.
    let topic = alarm.event.simple().to_string();
    for (session, endpoint, p256dh, auth) in subscriptions {
        let body = crate::web_push_payload::encrypt(&p256dh, &auth, payload.as_bytes())?;
        match sender
            .send_encrypted(client, &endpoint, body, &topic, ttl)
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
/// server can't read what), in their language and zone, with a link. An
/// all-day event's says its date, "all day".
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
    let turkish = language.as_deref() == Some("tr");
    let when = if alarm.all_day {
        // Its date (the UTC instant of its midnight), in no zone.
        let date = &utc[..10];
        if turkish {
            format!("{date}, tüm gün")
        } else {
            format!("{date}, all day")
        }
    } else {
        let local =
            kutup_crypto::calendar_event::utc_to_local(&utc, &zone).unwrap_or_else(|_| utc.clone());
        format!("{} {} ({zone})", &local[..10], &local[11..16])
    };
    let link = format!("{}/?event={}", state.config.apps.calendar, alarm.event);
    let (subject, body) = if turkish {
        (
            format!("Etkinlik hatırlatıcısı: {when}"),
            format!("{when} için bir etkinliğiniz var.\r\n\r\nAçmak için: {link}\r\n"),
        )
    } else {
        (
            format!("Event reminder: {when}"),
            format!("You have an event on {when}.\r\n\r\nOpen it: {link}\r\n"),
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
