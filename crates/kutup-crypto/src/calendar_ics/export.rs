//! A calendar as one `.ics` file (docs/plans/calendar.md, E2 §6), as
//! Proton's export (`packages/shared/lib/calendar/export/createExportIcs.ts`,
//! `withMandatoryPublishFields`): `VERSION:2.0`, `METHOD:PUBLISH`,
//! `CALSCALE:GREGORIAN`, `X-WR-TIMEZONE`, `X-WR-CALNAME`, `X-WR-CALDESC`;
//! a `VTIMEZONE` for each zone the events use, built from the bundled time
//! zone database's transitions over the years they span (Proton fetches
//! its own from its server); each event's properties and its reminders as
//! `VALARM`s (a display alarm's text the title, an email alarm's the title
//! and the member's address). The colour is not exported.

use std::collections::BTreeMap;

use jiff::tz::{Dst, Offset, TimeZone};
use jiff::{civil, Timestamp};
use serde::Deserialize;

use super::{ReminderKind, ReminderV1};
use crate::calendar_event::{escape, fold_into, time_zone, EventFieldsV1, EventTime};
use crate::calendar_recurrence::last_date;
use crate::error::{CryptoError, Result};

/// What an export writes: the calendar's name, description and zone, the
/// release in the PRODID, the title an untitled event's alarms show, the
/// member's address for email alarms, and the events.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportCalendarV1 {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub zone: String,
    pub release: String,
    pub untitled: String,
    #[serde(default)]
    pub email: Option<String>,
    pub events: Vec<ExportEventV1>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportEventV1 {
    pub fields: EventFieldsV1,
    #[serde(default)]
    pub reminders: Vec<ReminderV1>,
}

#[inline(never)]
pub(super) fn text_line(name: &str, value: &str) -> String {
    format!("{name}:{}", escape(value))
}

pub(super) fn utc_text(instant: Timestamp) -> String {
    instant.strftime("%Y%m%dT%H%M%SZ").to_string()
}

/// Writes the calendar.
pub fn export(calendar: &ExportCalendarV1) -> Result<String> {
    time_zone(&calendar.zone)?;
    if calendar.release.is_empty()
        || calendar.release.len() > 64
        || !calendar
            .release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b))
    {
        return Err(CryptoError::InvalidInput("the release is invalid".into()));
    }
    let mut events = Vec::with_capacity(calendar.events.len());
    // Each zone used and the years it must cover.
    let mut zones: BTreeMap<String, (i16, i16)> = BTreeMap::new();
    for event in &calendar.events {
        let parts = event.fields.to_parts()?;
        let shared = &parts.shared_signed;
        let series = shared.series()?;
        let first = shared.dtstart.instant()?;
        let last = match series.range_end()? {
            Some(end) => end,
            None if shared.rrule.is_some() => civil::date(last_date().year(), 12, 31)
                .to_zoned(TimeZone::UTC)
                .map_err(|_| CryptoError::InvalidInput("out of range".into()))?
                .timestamp(),
            None => first,
        };
        let year = |at: Timestamp| at.to_zoned(TimeZone::UTC).year();
        let mut times: Vec<&EventTime> = vec![&shared.dtstart];
        times.extend(shared.dtend.iter());
        times.extend(shared.recurrence_id.iter());
        times.extend(shared.exdates.iter());
        for time in times {
            if let EventTime::Zoned { tzid, .. } = time {
                let span = zones.entry(tzid.clone()).or_insert((i16::MAX, i16::MIN));
                // A year either side: an event near New Year's in another
                // zone falls in the next or the last.
                span.0 = span.0.min(year(first) - 1);
                span.1 = span.1.max(year(last) + 1);
            }
        }
        events.push((event, parts));
    }

    let mut out = String::new();
    let mut line = |text: String| fold_into(&mut out, &text);
    line("BEGIN:VCALENDAR".into());
    line(format!(
        "PRODID:-//Kutup//Calendar {}//EN",
        calendar.release
    ));
    line("VERSION:2.0".into());
    line("METHOD:PUBLISH".into());
    line("CALSCALE:GREGORIAN".into());
    line(format!("X-WR-TIMEZONE:{}", calendar.zone));
    line(text_line("X-WR-CALNAME", &calendar.name));
    if let Some(description) = calendar.description.as_deref().filter(|d| !d.is_empty()) {
        line(text_line("X-WR-CALDESC", description));
    }
    for (tzid, (from, to)) in &zones {
        for text in vtimezone(tzid, *from, *to)? {
            line(text);
        }
    }
    for (event, parts) in &events {
        let shared = &parts.shared_signed;
        let secret = &parts.shared_encrypted;
        let own = &parts.calendar_signed;
        line("BEGIN:VEVENT".into());
        line(text_line("UID", &shared.uid));
        line(format!("DTSTAMP:{}", utc_text(shared.dtstamp)));
        line(shared.dtstart.write("DTSTART"));
        if let Some(end) = &shared.dtend {
            line(end.write("DTEND"));
        }
        if let Some(id) = &shared.recurrence_id {
            line(id.write("RECURRENCE-ID"));
        }
        if let Some(rule) = &shared.rrule {
            line(format!("RRULE:{rule}"));
        }
        for exdate in &shared.exdates {
            line(exdate.write("EXDATE"));
        }
        line(format!("SEQUENCE:{}", shared.sequence));
        if let Some(created) = secret.created {
            line(format!("CREATED:{}", utc_text(created)));
        }
        let title = secret.summary.clone().unwrap_or_default();
        if let Some(summary) = &secret.summary {
            line(text_line("SUMMARY", summary));
        }
        if let Some(description) = &secret.description {
            line(text_line("DESCRIPTION", description));
        }
        if let Some(location) = &secret.location {
            line(text_line("LOCATION", location));
        }
        if let Some(status) = &event.fields.status {
            line(format!("STATUS:{}", status.to_ascii_uppercase()));
        }
        if let Some(transp) = &event.fields.transp {
            line(format!("TRANSP:{}", transp.to_ascii_uppercase()));
        }
        if let Some(comment) = parts
            .calendar_encrypted
            .as_ref()
            .and_then(|part| part.comment.as_ref())
        {
            line(text_line("COMMENT", comment));
        }
        // What an outside event or a newer Kutup carried, as it came.
        let kept = shared
            .other
            .iter()
            .chain(&secret.other)
            .chain(&own.other)
            .chain(
                parts
                    .calendar_encrypted
                    .iter()
                    .flat_map(|part| part.other.iter()),
            );
        for other in kept {
            line(other.clone());
        }
        let shown = if title.trim().is_empty() {
            calendar.untitled.clone()
        } else {
            title
        };
        for reminder in &event.reminders {
            crate::calendar_ics::import::check_trigger(&reminder.trigger)?;
            let email = calendar
                .email
                .as_deref()
                .filter(|_| reminder.kind == ReminderKind::Email);
            line("BEGIN:VALARM".into());
            line(format!(
                "ACTION:{}",
                if email.is_some() { "EMAIL" } else { "DISPLAY" }
            ));
            line(format!("TRIGGER:{}", reminder.trigger));
            line(text_line("DESCRIPTION", &shown));
            if let Some(email) = email {
                line(text_line("SUMMARY", &shown));
                line(format!("ATTENDEE:mailto:{email}"));
            }
            line("END:VALARM".into());
        }
        line("END:VEVENT".into());
    }
    line("END:VCALENDAR".into());
    Ok(out)
}

#[inline(never)]
fn offset_text(offset: Offset) -> String {
    let seconds = offset.seconds();
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.unsigned_abs();
    let (hours, minutes, rest) = (seconds / 3600, (seconds / 60) % 60, seconds % 60);
    if rest == 0 {
        format!("{sign}{hours:02}{minutes:02}")
    } else {
        format!("{sign}{hours:02}{minutes:02}{rest:02}")
    }
}

/// A `VTIMEZONE` for `tzid` covering the years `from` to `to`: the offset
/// in force when they begin, then each transition (RFC 5545 §3.6.5: its
/// `DTSTART` the local time before it, in the offset it leaves).
#[inline(never)]
pub(super) fn vtimezone(tzid: &str, from: i16, to: i16) -> Result<Vec<String>> {
    let tz = time_zone(tzid)?;
    let range = |year: i16, end: bool| {
        let date = civil::date(
            year.clamp(1900, 2100),
            if end { 12 } else { 1 },
            if end { 31 } else { 1 },
        );
        date.to_datetime(if end {
            civil::time(23, 59, 59, 0)
        } else {
            civil::Time::midnight()
        })
        .to_zoned(TimeZone::UTC)
        .map(|zoned| zoned.timestamp())
        .map_err(|_| CryptoError::InvalidInput("out of range".into()))
    };
    let (start, end) = (range(from, false)?, range(to, true)?);
    let mut lines = vec!["BEGIN:VTIMEZONE".to_owned(), format!("TZID:{tzid}")];
    let mut observance = |kind: Dst, at: civil::DateTime, from: Offset, to: Offset, name: &str| {
        let kind = if kind == Dst::Yes {
            "DAYLIGHT"
        } else {
            "STANDARD"
        };
        lines.push(format!("BEGIN:{kind}"));
        lines.push(format!("DTSTART:{}", at.strftime("%Y%m%dT%H%M%S")));
        lines.push(format!("TZOFFSETFROM:{}", offset_text(from)));
        lines.push(format!("TZOFFSETTO:{}", offset_text(to)));
        if !name.is_empty() {
            lines.push(text_line("TZNAME", name));
        }
        lines.push(format!("END:{kind}"));
    };
    let first = tz.to_offset_info(start);
    let mut offset = first.offset();
    observance(
        first.dst(),
        offset.to_datetime(start),
        offset,
        offset,
        first.abbreviation(),
    );
    for transition in tz.following(start) {
        if transition.timestamp() > end {
            break;
        }
        observance(
            transition.dst(),
            offset.to_datetime(transition.timestamp()),
            offset,
            transition.offset(),
            transition.abbreviation(),
        );
        offset = transition.offset();
    }
    lines.push("END:VTIMEZONE".into());
    Ok(lines)
}
