//! Busy times (docs/plans/calendar-e3.md §3 and §4): when a calendar's
//! events take time, read from the columns the server can already see (the
//! shared signed part's times and rule, the calendar signed part's `STATUS`,
//! `TRANSP` and `EXDATE`s). Nothing else of an event leaves: no title, no
//! count beyond the blocks themselves. Transparent and cancelled events take
//! no time; a changed occurrence replaces the one it changes.

use std::collections::{HashMap, HashSet};

use kutup_crypto::calendar_event::{CalendarSigned, SharedSigned, Status, Transp};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The most blocks one answer carries: a window of a few weeks holds far
/// fewer, and a daily series over a year a few hundred.
pub const MAX_BLOCKS: usize = 5000;

/// One busy block, in UTC (an all-day one runs midnight to midnight UTC of
/// its dates, as the event rows give them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BusyBlock {
    #[serde(with = "time::serde::rfc3339")]
    pub start_utc: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_utc: time::OffsetDateTime,
    pub full_day: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BusyList {
    pub busy: Vec<BusyBlock>,
}

/// One event row as the busy times read it.
struct Row {
    calendar: Uuid,
    uid: String,
    recurrence_id: Option<time::OffsetDateTime>,
    shared: String,
    own: String,
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
}

/// The blocks of `calendars` meeting `[start, end)`, in order of start.
pub async fn blocks(
    pool: &sqlx::PgPool,
    calendars: &[Uuid],
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
) -> AppResult<Vec<BusyBlock>> {
    if calendars.is_empty() {
        return Ok(Vec::new());
    }
    type Fetched = (
        Uuid,
        String,
        Option<time::OffsetDateTime>,
        String,
        String,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let fetched: Vec<Fetched> = sqlx::query_as(
        "SELECT e.calendar_id, se.uid, se.recurrence_id, se.shared_signed, e.calendar_signed,
                se.start_utc, se.end_utc
           FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
          WHERE e.calendar_id = ANY($1) AND se.start_utc < $3
            AND COALESCE(se.range_end_utc, 'infinity'::timestamptz) >= $2",
    )
    .bind(calendars)
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await?;
    let rows: Vec<Row> = fetched
        .into_iter()
        .map(
            |(calendar, uid, recurrence_id, shared, own, start, end)| Row {
                calendar,
                uid,
                recurrence_id,
                shared,
                own,
                start,
                end,
            },
        )
        .collect();
    // Every changed occurrence of the series in the window, wherever it
    // was moved to: the series no longer occurs at the instant it names.
    let series_uids: Vec<String> = rows
        .iter()
        .filter(|row| row.recurrence_id.is_none())
        .map(|row| row.uid.clone())
        .collect();
    let changed: Vec<(Uuid, String, time::OffsetDateTime)> = if series_uids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT e.calendar_id, se.uid, se.recurrence_id
               FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
              WHERE e.calendar_id = ANY($1) AND se.uid = ANY($2) AND se.recurrence_id IS NOT NULL",
        )
        .bind(calendars)
        .bind(&series_uids)
        .fetch_all(pool)
        .await?
    };
    let (from, to) = (start.unix_timestamp(), end.unix_timestamp());
    tokio::task::spawn_blocking(move || expand(&rows, &changed, from, to))
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

/// Whether the calendar's own status of an event takes time.
fn takes_time(own: &CalendarSigned) -> bool {
    own.transp != Some(Transp::Transparent) && own.status != Some(Status::Cancelled)
}

fn at(seconds: i64) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(seconds).ok()
}

fn expand(
    rows: &[Row],
    changed: &[(Uuid, String, time::OffsetDateTime)],
    from: i64,
    to: i64,
) -> Vec<BusyBlock> {
    let mut replaced: HashMap<(Uuid, &str), HashSet<i64>> = HashMap::new();
    for (calendar, uid, recurrence_id) in changed {
        replaced
            .entry((*calendar, uid.as_str()))
            .or_default()
            .insert(recurrence_id.unix_timestamp());
    }
    let mut out = Vec::new();
    for row in rows {
        // A row that no longer reads takes no time (as it fires no alarm).
        let (Ok(shared), Ok(own)) = (
            SharedSigned::parse(&row.shared),
            CalendarSigned::parse(&row.own),
        ) else {
            continue;
        };
        if !takes_time(&own) {
            continue;
        }
        let full_day = shared.dtstart.is_date();
        if row.recurrence_id.is_some() || shared.rrule.is_none() {
            let (start, end) = (row.start.unix_timestamp(), row.end.unix_timestamp());
            if start < to && (end > from || (start == end && start >= from)) {
                out.push(BusyBlock {
                    start_utc: row.start,
                    end_utc: row.end,
                    full_day,
                });
            }
            continue;
        }
        let Ok((series, _)) = crate::calendar_alarms::series_of(&row.shared, &row.own) else {
            continue;
        };
        let skip = replaced.get(&(row.calendar, row.uid.as_str()));
        // An occurrence starting before the window may still reach into it:
        // the walk starts an event's length (and two days) earlier.
        let length = (row.end - row.start).whole_seconds().max(0);
        for occurrence in series.occurrences_from(from - length - 2 * 24 * 60 * 60) {
            let Ok(occurrence) = occurrence else {
                break;
            };
            let (start, end) = (
                occurrence.start_utc.as_second(),
                occurrence.end_utc.as_second(),
            );
            if start >= to || out.len() >= MAX_BLOCKS {
                break;
            }
            let meets = end > from || (start == end && start >= from);
            if !meets || skip.is_some_and(|skip| skip.contains(&start)) {
                continue;
            }
            if let (Some(start_utc), Some(end_utc)) = (at(start), at(end)) {
                out.push(BusyBlock {
                    start_utc,
                    end_utc,
                    full_day,
                });
            }
        }
        if out.len() >= MAX_BLOCKS {
            break;
        }
    }
    out.sort_by_key(|block| (block.start_utc, block.end_utc));
    out.truncate(MAX_BLOCKS);
    merge(out)
}

/// Overlapping and touching blocks as one (in order of start): an answer
/// says when someone is busy, never how many events make it up. A merged
/// block is all-day only when every block in it is.
fn merge(blocks: Vec<BusyBlock>) -> Vec<BusyBlock> {
    let mut merged: Vec<BusyBlock> = Vec::with_capacity(blocks.len());
    for block in blocks {
        match merged.last_mut() {
            Some(last) if block.start_utc <= last.end_utc => {
                if block.end_utc > last.end_utc {
                    last.end_utc = block.end_utc;
                }
                last.full_day &= block.full_day;
            }
            _ => merged.push(block),
        }
    }
    merged
}

/// Busy blocks as an iCalendar feed (a busy-only link's `calendar.ics`):
/// one `VEVENT` per block, `SUMMARY:Busy`, as Proton's limited link.
pub fn ics(blocks: &[BusyBlock], link_id: Uuid, server: &str) -> String {
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Kutup//Calendar//EN\r\nCALSCALE:GREGORIAN\r\n",
    );
    let stamp = utc(time::OffsetDateTime::now_utc());
    for block in blocks {
        let (start, end) = (
            block.start_utc.unix_timestamp(),
            block.end_utc.unix_timestamp(),
        );
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:busy-{link_id}-{start}-{end}@{server}\r\n"));
        out.push_str(&format!("DTSTAMP:{stamp}\r\n"));
        if block.full_day {
            out.push_str(&format!("DTSTART;VALUE=DATE:{}\r\n", date(block.start_utc)));
            out.push_str(&format!("DTEND;VALUE=DATE:{}\r\n", date(block.end_utc)));
        } else {
            out.push_str(&format!("DTSTART:{}\r\n", utc(block.start_utc)));
            out.push_str(&format!("DTEND:{}\r\n", utc(block.end_utc)));
        }
        out.push_str("SUMMARY:Busy\r\nTRANSP:OPAQUE\r\nEND:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    out
}

fn utc(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

fn date(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!("{:04}{:02}{:02}", at.year(), u8::from(at.month()), at.day())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(shared: &str, own: &str, start: i64, end: i64, recurrence: Option<i64>) -> Row {
        Row {
            calendar: Uuid::nil(),
            uid: "u@kutup.test".into(),
            recurrence_id: recurrence.and_then(at),
            shared: shared.into(),
            own: own.into(),
            start: at(start).unwrap(),
            end: at(end).unwrap(),
        }
    }

    fn part(lines: &[&str]) -> String {
        let mut text = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n");
        for line in lines {
            text.push_str(line);
            text.push_str("\r\n");
        }
        text.push_str("END:VEVENT\r\nEND:VCALENDAR");
        text
    }

    #[test]
    fn a_daily_series_gives_one_block_a_day_less_its_changed_one() {
        // 2026-11-02 09:00Z for an hour, daily, five times.
        let shared = part(&[
            "UID:u@kutup.test",
            "DTSTAMP:20261101T000000Z",
            "DTSTART:20261102T090000Z",
            "DTEND:20261102T100000Z",
            "RRULE:FREQ=DAILY;COUNT=5",
            "SEQUENCE:0",
        ]);
        let own = part(&["UID:u@kutup.test", "DTSTAMP:20261101T000000Z"]);
        let first = 1_793_610_000; // 2026-11-02T09:00:00Z
        let rows = vec![row(&shared, &own, first, first + 3600, None)];
        let changed = vec![(
            Uuid::nil(),
            "u@kutup.test".to_string(),
            at(first + 86_400).unwrap(),
        )];
        let blocks = expand(&rows, &changed, first - 3600, first + 10 * 86_400);
        assert_eq!(blocks.len(), 4);
        assert!(blocks.iter().all(|block| !block.full_day));
        assert_eq!(blocks[1].start_utc, at(first + 2 * 86_400).unwrap());
    }

    #[test]
    fn overlapping_and_touching_blocks_become_one() {
        let block = |start: i64, end: i64| BusyBlock {
            start_utc: at(start).unwrap(),
            end_utc: at(end).unwrap(),
            full_day: false,
        };
        assert_eq!(
            merge(vec![
                block(0, 10),
                block(5, 20),
                block(20, 30),
                block(40, 50)
            ]),
            vec![block(0, 30), block(40, 50)]
        );
    }

    #[test]
    fn transparent_and_cancelled_events_take_no_time() {
        let shared = part(&[
            "UID:u@kutup.test",
            "DTSTAMP:20261101T000000Z",
            "DTSTART:20261102T090000Z",
            "DTEND:20261102T100000Z",
            "SEQUENCE:0",
        ]);
        let first = 1_793_610_000;
        for own in [
            part(&[
                "UID:u@kutup.test",
                "DTSTAMP:20261101T000000Z",
                "TRANSP:TRANSPARENT",
            ]),
            part(&[
                "UID:u@kutup.test",
                "DTSTAMP:20261101T000000Z",
                "STATUS:CANCELLED",
            ]),
        ] {
            let rows = vec![row(&shared, &own, first, first + 3600, None)];
            assert!(expand(&rows, &[], first - 3600, first + 86_400).is_empty());
        }
    }

    #[test]
    fn a_feed_names_its_blocks_busy_only() {
        let block = BusyBlock {
            start_utc: at(1_793_610_000).unwrap(),
            end_utc: at(1_793_613_600).unwrap(),
            full_day: false,
        };
        let text = ics(&[block], Uuid::nil(), "kutup.test");
        assert!(text.contains("DTSTART:20261102T090000Z\r\n"));
        assert!(text.contains("SUMMARY:Busy\r\n"));
        assert!(text.ends_with("END:VCALENDAR\r\n"));
    }
}
