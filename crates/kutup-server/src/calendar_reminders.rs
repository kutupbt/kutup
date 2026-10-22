//! Calendar reminders (docs/plans/calendar.md, E2 §4), as Proton's
//! notifications: `{ type: email | device, trigger }`, the trigger relative
//! to the event's start, readable by the server (it fires them) and never in
//! the encrypted parts. A member's own for an event, or their calendar's
//! defaults.
//!
//! The server keeps each member's next alarm per event and reminder and
//! fires it: a web push (the event's time and id, encrypted to the browser)
//! or an email to the member's own address, saying only when.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Proton's bounds before the start (`MAX_NOTIFICATION_*`): 999 weeks,
/// 6999 days, 999 hours or 9999 minutes, each in its own unit.
const MAX_WEEKS: i64 = 999;
const MAX_DAYS: i64 = 6999;
const MAX_HOURS: i64 = 999;
const MAX_MINUTES: i64 = 9999;
/// An all-day event's reminder may come up to a day after its start
/// (Proton's "on the day at 09:00": `PT9H`).
const ALL_DAY_AFTER_MINUTES: i64 = 24 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ReminderType {
    /// A notification on the member's browsers (open tab or web push).
    Device,
    /// An email to the member's own Kutup address.
    Email,
}

impl ReminderType {
    pub fn as_str(self) -> &'static str {
        match self {
            ReminderType::Device => "device",
            ReminderType::Email => "email",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reminder {
    #[serde(rename = "type")]
    pub kind: ReminderType,
    /// An RFC 5545 duration relative to the start: `-PT15M`, `-P1D`,
    /// `-PT15H`, `PT9H` (an all-day event's day at 09:00).
    pub trigger: String,
}

/// Minutes from the start a trigger names (negative: before), checked
/// against Proton's bounds for a timed or all-day event.
pub fn trigger_minutes(trigger: &str, all_day: bool) -> Result<i64, String> {
    let bad = || format!("a reminder's trigger is a duration like -PT15M, not {trigger:?}");
    let (negative, rest) = match trigger.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trigger.strip_prefix('+').unwrap_or(trigger)),
    };
    let rest = rest.strip_prefix('P').ok_or_else(bad)?;
    let (date, time) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };
    let mut minutes: i64 = 0;
    let mut units = 0;
    let mut read = |part: &str, table: &[(char, i64, i64)]| -> Result<(), String> {
        let mut number = String::new();
        let mut last = 0;
        for c in part.chars() {
            if c.is_ascii_digit() {
                number.push(c);
                continue;
            }
            let position = table
                .iter()
                .position(|(unit, _, _)| *unit == c)
                .ok_or_else(bad)?;
            // Units in order, each once, each with a number.
            if position < last || number.is_empty() || number.len() > 5 {
                return Err(bad());
            }
            last = position + 1;
            let value: i64 = number.parse().map_err(|_| bad())?;
            let (_, scale, most) = table[position];
            if value > most {
                return Err(format!("a reminder comes at most {most} {c} before"));
            }
            minutes += value * scale;
            units += 1;
            number.clear();
        }
        if number.is_empty() {
            Ok(())
        } else {
            Err(bad())
        }
    };
    read(
        date,
        &[('W', 7 * 24 * 60, MAX_WEEKS), ('D', 24 * 60, MAX_DAYS)],
    )?;
    if let Some(time) = time {
        if time.is_empty() {
            return Err(bad());
        }
        read(
            time,
            &[('H', 60, MAX_HOURS), ('M', 1, MAX_MINUTES), ('S', 0, 0)],
        )?;
    }
    if units == 0 {
        return Err(bad());
    }
    let minutes = if negative { -minutes } else { minutes };
    if all_day {
        if minutes >= ALL_DAY_AFTER_MINUTES {
            return Err("an all-day event's reminder comes before the day ends".into());
        }
    } else if minutes > 0 {
        return Err("a timed event's reminder comes at its start or before".into());
    }
    Ok(minutes)
}

/// Checks a member's reminders for an event: at most `most`, each with a
/// trigger in bounds, none twice.
pub fn check(reminders: &[Reminder], all_day: bool, most: usize) -> Result<(), String> {
    if reminders.len() > most {
        return Err(format!("at most {most} reminders"));
    }
    let mut seen = Vec::with_capacity(reminders.len());
    for reminder in reminders {
        let minutes = trigger_minutes(&reminder.trigger, all_day)?;
        if seen.contains(&(reminder.kind, minutes)) {
            return Err("the same reminder twice".into());
        }
        seen.push((reminder.kind, minutes));
    }
    Ok(())
}

/// Proton's defaults (`DefaultPartDayNotifications`,
/// `DefaultFullDayNotifications`): 15 minutes before a timed event, 15 hours
/// before an all-day one (09:00 the day before), on the device and by email.
pub fn defaults(all_day: bool) -> Vec<Reminder> {
    let trigger = if all_day { "-PT15H" } else { "-PT15M" };
    [ReminderType::Device, ReminderType::Email]
        .into_iter()
        .map(|kind| Reminder {
            kind,
            trigger: trigger.into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_read_as_proton_writes_them() {
        assert_eq!(trigger_minutes("-PT15M", false), Ok(-15));
        assert_eq!(trigger_minutes("-PT1H", false), Ok(-60));
        assert_eq!(trigger_minutes("-P1D", false), Ok(-1440));
        assert_eq!(trigger_minutes("-P2W", false), Ok(-2 * 7 * 1440));
        assert_eq!(trigger_minutes("-P1DT2H30M", false), Ok(-(1440 + 150)));
        assert_eq!(trigger_minutes("PT0S", false), Ok(0));
        assert_eq!(trigger_minutes("-PT15H", true), Ok(-900));
        assert_eq!(trigger_minutes("PT9H", true), Ok(540));
    }

    #[test]
    fn triggers_out_of_bounds_or_malformed_are_refused() {
        for (trigger, all_day) in [
            ("PT15M", false),
            ("P1D", true),
            ("-PT10000M", false),
            ("-P1000W", false),
            ("-P7000D", false),
            ("-PT1000H", false),
            ("15M", false),
            ("-P", false),
            ("-PT", false),
            ("-PT15", false),
            ("-PM15", false),
            ("-PT30M15H", false),
            ("-PT15M15M", false),
            ("-PT1S", false),
            ("-P1Y", false),
        ] {
            assert!(trigger_minutes(trigger, all_day).is_err(), "{trigger}");
        }
    }

    #[test]
    fn a_member_s_list_is_bounded_and_without_repeats() {
        let fifteen = Reminder {
            kind: ReminderType::Device,
            trigger: "-PT15M".into(),
        };
        let email = Reminder {
            kind: ReminderType::Email,
            ..fifteen.clone()
        };
        assert!(check(&[fifteen.clone(), email.clone()], false, 10).is_ok());
        assert!(check(&[fifteen.clone(), fifteen.clone()], false, 10).is_err());
        assert!(check(&[fifteen, email], false, 1).is_err());
        assert!(check(&defaults(true), true, 10).is_ok());
        assert!(check(&defaults(false), false, 10).is_ok());
    }
}
