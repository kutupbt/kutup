//! iCalendar files as others write and read them (docs/plans/calendar.md,
//! E2 §5–6): the one place Kutup reads and writes outside `.ics` text, so
//! the import, the export, invitations (E4, docs/plans/calendar-e4.md §2)
//! and calendars added from a URL (E5) read alike.
//!
//! - [`reader`]: the lenient reader, repairing what Proton's `icsSurgery`
//!   repairs, into components and properties;
//! - [`value`]: dates, times, durations and text, read as leniently;
//! - [`zones`]: a `TZID` as others write it (Windows' names among them)
//!   mapped to an IANA zone;
//! - [`import`]: Proton's whitelist rebuild of each event into the fields
//!   the Rust core seals, with Proton's per-event reasons;
//! - [`export`]: one `VCALENDAR` in one form, with the `VTIMEZONE`s its
//!   events use, built from the bundled time zone database.
//!
//! Kutup's own event parts never pass through here: they keep their strict
//! canonical form (`calendar_event`).

pub mod export;
pub mod import;
pub mod reader;
pub mod value;
mod zone_names;
pub mod zones;

use serde::{Deserialize, Serialize};

/// Where a reminder fires (Proton's notification types).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReminderKind {
    Device,
    Email,
}

/// A reminder as the server keeps it (`calendar_reminders::Reminder`):
/// `trigger` an RFC 5545 duration from the start, as Proton's editor writes
/// it (`-PT15M`, `-P1W`, an all-day event's `-PT15H`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderV1 {
    #[serde(rename = "type")]
    pub kind: ReminderKind,
    pub trigger: String,
}

/// Minutes from the start (negative: before) as the trigger Proton's editor
/// writes, the same the Calendar app's picker writes (`minutesTrigger`).
pub fn minutes_trigger(minutes: i64) -> String {
    if minutes == 0 {
        return "PT0S".into();
    }
    let sign = if minutes < 0 { "-" } else { "" };
    let mut rest = minutes.abs();
    if rest % 10_080 == 0 {
        return format!("{sign}P{}W", rest / 10_080);
    }
    let days = rest / 1440;
    rest -= days * 1440;
    let (hours, mins) = (rest / 60, rest % 60);
    let mut text = format!("{sign}P");
    if days > 0 {
        text.push_str(&format!("{days}D"));
    }
    if hours > 0 || mins > 0 {
        text.push('T');
        if hours > 0 {
            text.push_str(&format!("{hours}H"));
        }
        if mins > 0 {
            text.push_str(&format!("{mins}M"));
        }
    }
    text
}

#[cfg(test)]
mod tests;
