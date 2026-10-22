//! Recurring events (docs/plans/calendar.md, E2): Proton's subset of RFC 5545
//! `RRULE`, read and written in one canonical form, and the expansion of a
//! series into its occurrences, on jiff and the bundled time zone database
//! (one database for the server and every client: no second one from a
//! recurrence library).
//!
//! The subset is Proton's (`packages/shared/lib/calendar/recurrence/rrule.ts`,
//! `getIsRruleSupported`, `getHasConsistentRrule`): DAILY, WEEKLY, MONTHLY
//! and YEARLY only; per frequency only the parts Proton's editor makes;
//! single values in monthly and yearly rules; `COUNT` or `UNTIL`, never both;
//! `DTSTART` is the first occurrence. The expansion is Proton's
//! (`recurring.ts`): the rule runs on the wall clock of `DTSTART`'s zone, so
//! 09:00 stays 09:00 across a change of offset; each occurrence lasts what
//! the first does, on that wall clock; an `EXDATE` removes the occurrence
//! starting at its wall-clock time; `COUNT` counts before `EXDATE` removes
//! (RFC 5545 §3.8.5.3).

use std::fmt::Write as _;

use jiff::civil::{self, Weekday};
use jiff::{SignedDuration, Timestamp, ToSpan};

use crate::calendar_event::{time_zone, EventFieldsV1, EventTime, TimeV1};
use crate::error::{CryptoError, Result};

/// The most occurrences a `COUNT` may ask for: Proton's ceiling for
/// invitations (`FREQUENCY_COUNT_MAX_INVITATION`). A server holds its own
/// calendars to the administrators' lower limit (49 at first, Proton's
/// `FREQUENCY_COUNT_MAX`).
pub const MAX_COUNT: u16 = 499;
/// The largest `INTERVAL` per frequency (Proton's `FREQUENCY_INTERVALS_MAX`).
pub const MAX_INTERVAL_DAILY: u16 = 999;
pub const MAX_INTERVAL_WEEKLY: u16 = 4999;
pub const MAX_INTERVAL_MONTHLY: u16 = 999;
pub const MAX_INTERVAL_YEARLY: u16 = 99;
/// The longest `RRULE` text read.
pub const MAX_RULE_LEN: usize = 256;

/// The days a repeating event may fall on (Proton's `MINIMUM_DATE` and
/// `MAXIMUM_DATE`): an expansion never runs past the last.
pub fn first_date() -> civil::Date {
    civil::date(1970, 1, 1)
}

pub fn last_date() -> civil::Date {
    civil::date(2037, 12, 31)
}

/// How often a rule repeats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl Frequency {
    fn name(self) -> &'static str {
        match self {
            Frequency::Daily => "DAILY",
            Frequency::Weekly => "WEEKLY",
            Frequency::Monthly => "MONTHLY",
            Frequency::Yearly => "YEARLY",
        }
    }

    fn max_interval(self) -> u16 {
        match self {
            Frequency::Daily => MAX_INTERVAL_DAILY,
            Frequency::Weekly => MAX_INTERVAL_WEEKLY,
            Frequency::Monthly => MAX_INTERVAL_MONTHLY,
            Frequency::Yearly => MAX_INTERVAL_YEARLY,
        }
    }
}

/// When a series ends by date: a date for an all-day series, a UTC instant
/// for a timed one (RFC 5545 §3.3.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Until {
    Date(civil::Date),
    Utc(Timestamp),
}

/// A recurrence rule in Proton's subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub frequency: Frequency,
    /// 1 or more (1 is not written).
    pub interval: u16,
    pub count: Option<u16>,
    pub until: Option<Until>,
    /// WEEKLY: the days of the week (none: `DTSTART`'s). MONTHLY: one day,
    /// with `by_set_pos` saying which of the month's.
    pub by_day: Vec<Weekday>,
    /// MONTHLY, YEARLY: one day of the month (negative: from its end).
    pub by_month_day: Option<i8>,
    /// YEARLY: one month.
    pub by_month: Option<i8>,
    /// MONTHLY with `by_day`: 1 to 4, or -1 (the last).
    pub by_set_pos: Option<i8>,
    /// YEARLY: one day of the year (negative: from its end).
    pub by_year_day: Option<i16>,
    /// The week's first day, kept only where it matters (WEEKLY with days)
    /// and is not Monday (Proton's `withRruleWkst`).
    pub wkst: Option<Weekday>,
}

const WEEKDAYS: [(Weekday, &str); 7] = [
    (Weekday::Monday, "MO"),
    (Weekday::Tuesday, "TU"),
    (Weekday::Wednesday, "WE"),
    (Weekday::Thursday, "TH"),
    (Weekday::Friday, "FR"),
    (Weekday::Saturday, "SA"),
    (Weekday::Sunday, "SU"),
];

fn weekday_name(day: Weekday) -> &'static str {
    WEEKDAYS
        .iter()
        .find(|(d, _)| *d == day)
        .map(|(_, name)| *name)
        .expect("every weekday is named")
}

fn weekday_of(name: &str) -> Result<Weekday> {
    WEEKDAYS
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(d, _)| *d)
        .ok_or_else(|| invalid(format!("{name:?} is not a day of the week")))
}

fn invalid(message: impl Into<String>) -> CryptoError {
    CryptoError::InvalidInput(format!("RRULE: {}", message.into()))
}

fn number<T: std::str::FromStr>(value: &str, part: &str) -> Result<T> {
    // RFC 5545 integers: an optional sign and digits, nothing else.
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!("{part} is not a number")));
    }
    value
        .strip_prefix('+')
        .unwrap_or(value)
        .parse()
        .map_err(|_| invalid(format!("{part} is out of range")))
}

fn single<'a>(value: &'a str, part: &str) -> Result<&'a str> {
    if value.contains(',') {
        return Err(invalid(format!("{part} takes one value")));
    }
    Ok(value)
}

impl Rule {
    /// Reads a rule in its canonical form only ([`Rule::write`] gives the
    /// same text back), as a stored event's signed part carries it.
    pub fn parse(text: &str) -> Result<Rule> {
        let rule = Rule::read(text)?;
        if rule.write() != text {
            return Err(invalid("not in its canonical form"));
        }
        Ok(rule)
    }

    /// Reads a rule as others write it (any part order, `INTERVAL=1`, an
    /// ordinal day `2TU` for `BYDAY=TU;BYSETPOS=2`, a `WKST` that changes
    /// nothing): for imports. The result is in Proton's subset or refused.
    pub fn read(text: &str) -> Result<Rule> {
        if text.is_empty() || text.len() > MAX_RULE_LEN {
            return Err(invalid("empty or too long"));
        }
        // RFC 5545 recur values are ASCII; anything else is refused before a
        // part is cut.
        if !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"=;,-+".contains(&b))
        {
            return Err(invalid("characters outside RFC 5545's recur syntax"));
        }
        let mut frequency = None;
        let mut rule = Rule {
            frequency: Frequency::Daily,
            interval: 1,
            count: None,
            until: None,
            by_day: Vec::new(),
            by_month_day: None,
            by_month: None,
            by_set_pos: None,
            by_year_day: None,
            wkst: None,
        };
        let mut seen = Vec::new();
        let mut ordinal_day: Option<(i8, Weekday)> = None;
        for part in text.split(';') {
            let (name, value) = part
                .split_once('=')
                .ok_or_else(|| invalid(format!("{part:?} has no value")))?;
            if value.is_empty() {
                return Err(invalid(format!("{name} has no value")));
            }
            if seen.contains(&name) {
                return Err(invalid(format!("{name} appears twice")));
            }
            seen.push(name);
            match name {
                "FREQ" => {
                    frequency = Some(match value {
                        "DAILY" => Frequency::Daily,
                        "WEEKLY" => Frequency::Weekly,
                        "MONTHLY" => Frequency::Monthly,
                        "YEARLY" => Frequency::Yearly,
                        _ => return Err(invalid(format!("FREQ={value} is not supported"))),
                    })
                }
                "INTERVAL" => rule.interval = number(value, "INTERVAL")?,
                "COUNT" => rule.count = Some(number(value, "COUNT")?),
                "UNTIL" => rule.until = Some(read_until(value)?),
                "WKST" => rule.wkst = Some(weekday_of(value)?),
                "BYMONTHDAY" => {
                    rule.by_month_day = Some(number(single(value, name)?, "BYMONTHDAY")?)
                }
                "BYMONTH" => rule.by_month = Some(number(single(value, name)?, "BYMONTH")?),
                "BYSETPOS" => rule.by_set_pos = Some(number(single(value, name)?, "BYSETPOS")?),
                "BYYEARDAY" => rule.by_year_day = Some(number(single(value, name)?, "BYYEARDAY")?),
                "BYDAY" => {
                    for day in value.split(',') {
                        let split = day.len().saturating_sub(2);
                        let (ordinal, name) = day.split_at(split);
                        let weekday = weekday_of(name)?;
                        if ordinal.is_empty() {
                            rule.by_day.push(weekday);
                        } else {
                            if value.contains(',') {
                                return Err(invalid("an ordinal BYDAY takes one day"));
                            }
                            ordinal_day = Some((number(ordinal, "BYDAY")?, weekday));
                        }
                    }
                }
                _ => return Err(invalid(format!("{name} is not supported"))),
            }
        }
        rule.frequency = frequency.ok_or_else(|| invalid("FREQ is missing"))?;
        if let Some((ordinal, weekday)) = ordinal_day {
            // `BYDAY=2TU` is `BYDAY=TU;BYSETPOS=2` (Proton's getDayAndSetpos).
            if rule.by_set_pos.is_some() {
                return Err(invalid("BYDAY has an ordinal and BYSETPOS is given"));
            }
            rule.by_day = vec![weekday];
            rule.by_set_pos = Some(ordinal);
        }
        // Weekdays in one order, once each.
        rule.by_day.sort_by_key(|day| day.to_monday_zero_offset());
        let before = rule.by_day.len();
        rule.by_day.dedup();
        if rule.by_day.len() != before {
            return Err(invalid("BYDAY names a day twice"));
        }
        // A WKST that changes nothing is dropped (Proton's withRruleWkst).
        if rule.wkst == Some(Weekday::Monday)
            || !(rule.frequency == Frequency::Weekly && !rule.by_day.is_empty())
        {
            rule.wkst = None;
        }
        rule.check_shape()?;
        Ok(rule)
    }

    /// The canonical text: `FREQ`, then `COUNT` or `UNTIL`, `INTERVAL` (when
    /// not 1), `BYSETPOS`, `BYDAY`, `BYMONTHDAY`, `BYMONTH`, `BYYEARDAY`,
    /// `WKST`.
    pub fn write(&self) -> String {
        let mut text = format!("FREQ={}", self.frequency.name());
        if let Some(count) = self.count {
            let _ = write!(text, ";COUNT={count}");
        }
        match self.until {
            Some(Until::Date(date)) => {
                let _ = write!(text, ";UNTIL={}", date.strftime("%Y%m%d"));
            }
            Some(Until::Utc(instant)) => {
                let _ = write!(text, ";UNTIL={}", instant.strftime("%Y%m%dT%H%M%SZ"));
            }
            None => {}
        }
        if self.interval != 1 {
            let _ = write!(text, ";INTERVAL={}", self.interval);
        }
        if let Some(position) = self.by_set_pos {
            let _ = write!(text, ";BYSETPOS={position}");
        }
        if !self.by_day.is_empty() {
            let days: Vec<&str> = self.by_day.iter().map(|day| weekday_name(*day)).collect();
            let _ = write!(text, ";BYDAY={}", days.join(","));
        }
        if let Some(day) = self.by_month_day {
            let _ = write!(text, ";BYMONTHDAY={day}");
        }
        if let Some(month) = self.by_month {
            let _ = write!(text, ";BYMONTH={month}");
        }
        if let Some(day) = self.by_year_day {
            let _ = write!(text, ";BYYEARDAY={day}");
        }
        if let Some(day) = self.wkst {
            let _ = write!(text, ";WKST={}", weekday_name(day));
        }
        text
    }

    /// Proton's subset, on the rule alone (`getIsRruleSupported` and the
    /// parts of `getHasConsistentRrule` that need no `DTSTART`).
    fn check_shape(&self) -> Result<()> {
        if self.interval == 0 || self.interval > self.frequency.max_interval() {
            return Err(invalid("INTERVAL is out of range"));
        }
        if let Some(count) = self.count {
            if count == 0 || count > MAX_COUNT {
                return Err(invalid("COUNT is out of range"));
            }
        }
        if self.count.is_some() && self.until.is_some() {
            return Err(invalid("COUNT and UNTIL together"));
        }
        if let Some(until) = self.until {
            let date = match until {
                Until::Date(date) => date,
                Until::Utc(instant) => instant.to_zoned(jiff::tz::TimeZone::UTC).date(),
            };
            if date > last_date() || date < first_date() {
                return Err(invalid("UNTIL is out of range"));
            }
        }
        let has_month_day = self.by_month_day.is_some();
        match self.frequency {
            Frequency::Daily => {
                if !self.by_day.is_empty()
                    || has_month_day
                    || self.by_month.is_some()
                    || self.by_set_pos.is_some()
                    || self.by_year_day.is_some()
                {
                    return Err(invalid("a DAILY rule takes no BY parts"));
                }
            }
            Frequency::Weekly => {
                if has_month_day
                    || self.by_month.is_some()
                    || self.by_set_pos.is_some()
                    || self.by_year_day.is_some()
                {
                    return Err(invalid("a WEEKLY rule takes BYDAY only"));
                }
            }
            Frequency::Monthly => {
                if self.by_month.is_some() || self.by_year_day.is_some() {
                    return Err(invalid("a MONTHLY rule takes no BYMONTH or BYYEARDAY"));
                }
                // BYDAY and BYSETPOS both or neither, and then no BYMONTHDAY.
                match (self.by_day.len(), self.by_set_pos) {
                    (0, None) => {}
                    (1, Some(position)) => {
                        if ![-1, 1, 2, 3, 4].contains(&position) {
                            return Err(invalid("BYSETPOS is 1 to 4 or -1"));
                        }
                        if has_month_day {
                            return Err(invalid("BYDAY and BYMONTHDAY together"));
                        }
                    }
                    _ => return Err(invalid("a MONTHLY BYDAY is one day with its position")),
                }
                if let Some(day) = self.by_month_day {
                    check_month_day(day)?;
                }
            }
            Frequency::Yearly => {
                if !self.by_day.is_empty() || self.by_set_pos.is_some() {
                    return Err(invalid("a YEARLY rule takes no BYDAY or BYSETPOS"));
                }
                if has_month_day && self.by_month.is_none() {
                    return Err(invalid("BYMONTHDAY needs BYMONTH in a YEARLY rule"));
                }
                if let Some(month) = self.by_month {
                    if !(1..=12).contains(&month) {
                        return Err(invalid("BYMONTH is 1 to 12"));
                    }
                }
                if let Some(day) = self.by_month_day {
                    check_month_day(day)?;
                }
                if let Some(day) = self.by_year_day {
                    if day == 0 || !(-366..=366).contains(&day) {
                        return Err(invalid("BYYEARDAY is 1 to 366 or -366 to -1"));
                    }
                    if self.by_month.is_some() {
                        return Err(invalid("BYYEARDAY and BYMONTH together"));
                    }
                }
            }
        }
        Ok(())
    }
}

fn check_month_day(day: i8) -> Result<()> {
    if day == 0 || !(-31..=31).contains(&day) {
        return Err(invalid("BYMONTHDAY is 1 to 31 or -31 to -1"));
    }
    Ok(())
}

fn read_until(value: &str) -> Result<Until> {
    let bad = || invalid("UNTIL is not a date or a UTC time");
    match value.len() {
        8 => civil::Date::strptime("%Y%m%d", value)
            .map(Until::Date)
            .map_err(|_| bad()),
        16 if value.ends_with('Z') => civil::DateTime::strptime("%Y%m%dT%H%M%S", &value[..15])
            .and_then(|local| local.to_zoned(jiff::tz::TimeZone::UTC))
            .map(|zoned| Until::Utc(zoned.timestamp()))
            .map_err(|_| bad()),
        _ => Err(bad()),
    }
}

/// The `UNTIL` a client writes for a series starting at `start` and ending
/// on the day of `until` (Proton's `getSupportedUntil`): a date before the
/// start is the start's; an all-day series takes the date; a timed one the
/// end of that day (23:59:59) in the start's zone, as UTC.
pub fn supported_until(start: &EventTime, until: civil::Date) -> Result<Until> {
    let start_date = local_of(start).date();
    let day = until.max(start_date);
    match start {
        EventTime::Date(_) => Ok(Until::Date(day)),
        EventTime::Zoned { tzid, .. } => {
            let end_of_day = day.at(23, 59, 59, 0);
            let zoned = end_of_day
                .to_zoned(time_zone(tzid)?)
                .map_err(|_| invalid("UNTIL is out of range"))?;
            Ok(Until::Utc(zoned.timestamp()))
        }
        EventTime::Utc(_) => Ok(Until::Utc(
            day.at(23, 59, 59, 0)
                .to_zoned(jiff::tz::TimeZone::UTC)
                .map_err(|_| invalid("UNTIL is out of range"))?
                .timestamp(),
        )),
    }
}

/// The wall-clock time an event time names (a date at midnight).
fn local_of(time: &EventTime) -> civil::DateTime {
    match time {
        EventTime::Date(date) => date.to_datetime(civil::Time::midnight()),
        EventTime::Zoned { local, .. } => *local,
        EventTime::Utc(instant) => instant.to_zoned(jiff::tz::TimeZone::UTC).datetime(),
    }
}

/// One occurrence of a series.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Occurrence {
    /// Its start in the form of the series' `DTSTART` (a date, a wall-clock
    /// time in its zone, or UTC): what a `RECURRENCE-ID` or an `EXDATE`
    /// naming it carries.
    pub start: EventTime,
    pub start_utc: Timestamp,
    /// Exclusive.
    pub end_utc: Timestamp,
    /// Its place in the series, 1 for `DTSTART` (counted before `EXDATE`).
    pub number: u32,
}

/// An event's times and how it repeats, checked: the series a client draws
/// and the server indexes.
#[derive(Clone, Debug)]
pub struct Series {
    start: EventTime,
    rule: Option<Rule>,
    /// The removed occurrences' wall-clock starts, sorted.
    excluded: Vec<civil::DateTime>,
    /// All-day: how many days each occurrence lasts. Timed: how long, on the
    /// wall clock of the start's zone.
    length: Length,
}

#[derive(Clone, Copy, Debug)]
enum Length {
    Days(i32),
    Time(SignedDuration),
}

impl Series {
    /// Checks an event's `DTSTART`, `DTEND`, `RRULE` and `EXDATE`s as a
    /// series: the rule fits the start (an `UNTIL` of its kind, after it),
    /// every `EXDATE` is of the start's form (a date, or a time in the same
    /// zone), the start is the rule's first occurrence, and at least one
    /// occurrence is left.
    pub fn new(
        start: &EventTime,
        end: Option<&EventTime>,
        rule: Option<&Rule>,
        exdates: &[EventTime],
    ) -> Result<Series> {
        start.instant()?;
        let length = match (start, end) {
            (EventTime::Date(from), Some(EventTime::Date(to))) => {
                let days = (*to - *from).get_days();
                if days < 1 {
                    return Err(CryptoError::InvalidInput(
                        "an all-day event ends after it starts".into(),
                    ));
                }
                Length::Days(days)
            }
            (EventTime::Date(_), None) => Length::Days(1),
            (EventTime::Date(_), Some(_)) | (_, Some(EventTime::Date(_))) => {
                return Err(CryptoError::InvalidInput(
                    "an event's start and end are both dates or both times".into(),
                ))
            }
            (_, Some(end)) => {
                let length = start.instant()?.duration_until(end.instant()?);
                if length.is_negative() {
                    return Err(CryptoError::InvalidInput(
                        "an event ends after it starts".into(),
                    ));
                }
                Length::Time(length)
            }
            (_, None) => Length::Time(SignedDuration::ZERO),
        };
        if exdates.len() > crate::calendar_event::MAX_EXDATES {
            return Err(CryptoError::InvalidInput("too many EXDATEs".into()));
        }
        if rule.is_none() && !exdates.is_empty() {
            return Err(CryptoError::InvalidInput("EXDATE without RRULE".into()));
        }
        let mut excluded = Vec::with_capacity(exdates.len());
        for exdate in exdates {
            let same_form = match (start, exdate) {
                (EventTime::Date(_), EventTime::Date(_))
                | (EventTime::Utc(_), EventTime::Utc(_)) => true,
                (EventTime::Zoned { tzid: a, .. }, EventTime::Zoned { tzid: b, .. }) => a == b,
                _ => false,
            };
            if !same_form {
                return Err(CryptoError::InvalidInput(
                    "an EXDATE is in the form of DTSTART".into(),
                ));
            }
            excluded.push(local_of(exdate));
        }
        excluded.sort();
        excluded.dedup();
        let series = Series {
            start: start.clone(),
            rule: rule.cloned(),
            excluded,
            length,
        };
        if let Some(rule) = rule {
            rule.check_shape()?;
            let date = local_of(start).date();
            if date < first_date() || date > last_date() {
                return Err(invalid("a repeating event starts from 1970 to 2037"));
            }
            match (rule.until, start) {
                (None, _) | (Some(Until::Date(_)), EventTime::Date(_)) => {}
                (Some(Until::Utc(_)), EventTime::Zoned { .. } | EventTime::Utc(_)) => {}
                _ => return Err(invalid("UNTIL is a date for an all-day event, else UTC")),
            }
            // UNTIL before the start (Proton writes the start instead).
            if let Some(until) = rule.until {
                let before = match until {
                    Until::Date(day) => day < date,
                    Until::Utc(instant) => instant < start.instant()?,
                };
                if before {
                    return Err(invalid("UNTIL is before DTSTART"));
                }
            }
            // DTSTART is the rule's first occurrence (getHasConsistentRrule).
            let first = series.candidates().next();
            if first.map(|(_, local)| local) != Some(local_of(start)) {
                return Err(invalid("DTSTART is not an occurrence of its rule"));
            }
            if series.occurrences().next().transpose()?.is_none() {
                return Err(invalid("every occurrence is excluded"));
            }
        }
        Ok(series)
    }

    pub fn rule(&self) -> Option<&Rule> {
        self.rule.as_ref()
    }

    /// The occurrences meeting the half-open window `[from, to)`, at most
    /// `max` (the events query's window and page).
    pub fn occurrences_between(
        &self,
        from: Timestamp,
        to: Timestamp,
        max: usize,
    ) -> Result<Vec<Occurrence>> {
        let mut found = Vec::new();
        for occurrence in self.occurrences() {
            let occurrence = occurrence?;
            if occurrence.start_utc >= to {
                break;
            }
            let meets = occurrence.end_utc > from
                || (occurrence.start_utc == occurrence.end_utc && occurrence.start_utc >= from);
            if meets {
                if found.len() == max {
                    break;
                }
                found.push(occurrence);
            }
        }
        Ok(found)
    }

    /// When the last occurrence ends, or `None` for a series without end
    /// (the server's `range_end_utc`).
    pub fn range_end(&self) -> Result<Option<Timestamp>> {
        match &self.rule {
            Some(rule) if rule.count.is_none() && rule.until.is_none() => Ok(None),
            _ => {
                let mut last = None;
                for occurrence in self.occurrences() {
                    last = Some(occurrence?.end_utc);
                }
                Ok(last)
            }
        }
    }

    /// The occurrence starting at `start` (a `RECURRENCE-ID`), if the series
    /// has one there; excluded ones have none.
    pub fn occurrence_at(&self, start: &EventTime) -> Result<Option<Occurrence>> {
        let wanted = local_of(start);
        for occurrence in self.occurrences() {
            let occurrence = occurrence?;
            let local = local_of(&occurrence.start);
            if local == wanted && occurrence.start.tzid() == start.tzid() {
                return Ok(Some(occurrence));
            }
            if local > wanted {
                break;
            }
        }
        Ok(None)
    }

    /// Every occurrence in order, `EXDATE`s removed.
    pub fn occurrences(&self) -> impl Iterator<Item = Result<Occurrence>> + '_ {
        self.candidates()
            .filter(|(_, local)| self.excluded.binary_search(local).is_err())
            .map(|(number, local)| self.occurrence(number, local))
    }

    fn occurrence(&self, number: u32, local: civil::DateTime) -> Result<Occurrence> {
        let out_of_range = || CryptoError::InvalidInput("an occurrence is out of range".into());
        let (start, start_utc, end_utc) = match (&self.start, self.length) {
            (EventTime::Date(_), Length::Days(days)) => {
                let date = local.date();
                let end = date.checked_add(days.days()).map_err(|_| out_of_range())?;
                let start = EventTime::Date(date);
                let end_utc = EventTime::Date(end).instant()?;
                (start.clone(), start.instant()?, end_utc)
            }
            (EventTime::Zoned { tzid, .. }, Length::Time(length)) => {
                let zone = time_zone(tzid)?;
                let start_utc = local.to_zoned(zone.clone()).map_err(|_| out_of_range())?;
                let end_local = local.checked_add(length).map_err(|_| out_of_range())?;
                let end_utc = end_local.to_zoned(zone).map_err(|_| out_of_range())?;
                (
                    EventTime::Zoned {
                        local,
                        tzid: tzid.clone(),
                    },
                    start_utc.timestamp(),
                    end_utc.timestamp(),
                )
            }
            (EventTime::Utc(_), Length::Time(length)) => {
                let start_utc = local
                    .to_zoned(jiff::tz::TimeZone::UTC)
                    .map_err(|_| out_of_range())?
                    .timestamp();
                let end_utc = start_utc.checked_add(length).map_err(|_| out_of_range())?;
                (EventTime::Utc(start_utc), start_utc, end_utc)
            }
            _ => unreachable!("lengths follow the start's kind"),
        };
        Ok(Occurrence {
            start,
            start_utc,
            end_utc: end_utc.max(start_utc),
            number,
        })
    }

    /// The rule's occurrences before `EXDATE`, numbered, in order, up to its
    /// `COUNT` or `UNTIL` and the last supported date.
    fn candidates(&self) -> impl Iterator<Item = (u32, civil::DateTime)> + '_ {
        let base = local_of(&self.start);
        let time = base.time();
        let rule = self.rule.clone();
        let mut period: i64 = 0;
        let mut pending: Vec<civil::Date> = Vec::new();
        let mut number: u32 = 0;
        let mut done = false;
        let until = rule.as_ref().and_then(|rule| rule.until);
        let start = self.start.clone();
        std::iter::from_fn(move || loop {
            if done {
                return None;
            }
            let Some(rule) = rule.as_ref() else {
                // A single event: one occurrence.
                done = true;
                return Some((1, base));
            };
            if let Some(date) = pending.first().copied() {
                pending.remove(0);
                if date < base.date() {
                    continue;
                }
                let local = date.to_datetime(time);
                let past_until = match until {
                    Some(Until::Date(day)) => date > day,
                    Some(Until::Utc(instant)) => match instant_of(&start, local) {
                        Some(at) => at > instant,
                        None => true,
                    },
                    None => false,
                };
                if past_until || date > last_date() {
                    done = true;
                    return None;
                }
                number += 1;
                if let Some(count) = rule.count {
                    if number > u32::from(count) {
                        done = true;
                        return None;
                    }
                }
                return Some((number, local));
            }
            match period_dates(rule, base.date(), period) {
                Some(dates) => {
                    pending = dates;
                    period += 1;
                }
                None => {
                    done = true;
                    return None;
                }
            }
        })
    }
}

/// The instant a wall-clock time in the series' zone names.
fn instant_of(start: &EventTime, local: civil::DateTime) -> Option<Timestamp> {
    match start {
        EventTime::Zoned { tzid, .. } => time_zone(tzid)
            .ok()
            .and_then(|zone| local.to_zoned(zone).ok())
            .map(|zoned| zoned.timestamp()),
        _ => local
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|zoned| zoned.timestamp()),
    }
}

/// The dates of the `period`th period (0 is `base`'s), in order; `None`
/// once the period starts past the last supported date.
fn period_dates(rule: &Rule, base: civil::Date, period: i64) -> Option<Vec<civil::Date>> {
    let step = period.checked_mul(i64::from(rule.interval))?;
    match rule.frequency {
        Frequency::Daily => {
            let date = base.checked_add(step.days()).ok()?;
            (date <= last_date()).then(|| vec![date])
        }
        Frequency::Weekly => {
            let wkst = rule.wkst.unwrap_or(Weekday::Monday);
            let back = i64::from(base.weekday().since(wkst));
            let week = base
                .checked_sub(back.days())
                .ok()?
                .checked_add((step * 7).days())
                .ok()?;
            if week > last_date() {
                return None;
            }
            let days = if rule.by_day.is_empty() {
                vec![base.weekday()]
            } else {
                rule.by_day.clone()
            };
            let mut dates: Vec<civil::Date> = days
                .iter()
                .filter_map(|day| week.checked_add(i64::from(day.since(wkst)).days()).ok())
                .collect();
            dates.sort();
            Some(dates)
        }
        Frequency::Monthly => {
            let months = i64::from(base.year()) * 12 + i64::from(base.month() - 1) + step;
            let year = i16::try_from(months.div_euclid(12)).ok()?;
            let month = i8::try_from(months.rem_euclid(12) + 1).ok()?;
            let first = civil::Date::new(year, month, 1).ok()?;
            if first > last_date() {
                return None;
            }
            let date = if let (Some(day), Some(position)) = (rule.by_day.first(), rule.by_set_pos) {
                first.nth_weekday_of_month(position, *day).ok()
            } else {
                day_of_month(first, rule.by_month_day.unwrap_or(base.day()))
            };
            Some(date.into_iter().collect())
        }
        Frequency::Yearly => {
            let year = i16::try_from(i64::from(base.year()) + step).ok()?;
            let first = civil::Date::new(year, 1, 1).ok()?;
            if first > last_date() {
                return None;
            }
            let date = if let Some(day) = rule.by_year_day {
                let days = first.days_in_year();
                let day = if day > 0 { day } else { days + 1 + day };
                (1..=days)
                    .contains(&day)
                    .then(|| first.with().day_of_year(day).build().ok())
                    .flatten()
            } else {
                let month = rule.by_month.unwrap_or(base.month());
                let in_month = civil::Date::new(year, month, 1).ok()?;
                day_of_month(in_month, rule.by_month_day.unwrap_or(base.day()))
            };
            Some(date.into_iter().collect())
        }
    }
}

/// Day `day` of `first`'s month (negative: from its end), if it has one: a
/// 31st skips the months without (RFC 5545).
fn day_of_month(first: civil::Date, day: i8) -> Option<civil::Date> {
    let days = first.days_in_month();
    let day = if day > 0 { day } else { days + 1 + day };
    if day < 1 || day > days {
        return None;
    }
    civil::Date::new(first.year(), first.month(), day).ok()
}

// ----- as a client sends and reads them -----

/// A rule as the app's editor makes it (`RuleV1`); written canonically by
/// [`RuleV1::to_text`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleV1 {
    pub frequency: FrequencyV1,
    #[serde(default = "one")]
    pub interval: u16,
    #[serde(default)]
    pub count: Option<u16>,
    /// A date for an all-day series, a UTC instant for a timed one
    /// ([`supported_until`] makes it).
    #[serde(default)]
    pub until: Option<TimeV1>,
    /// `MO` … `SU`.
    #[serde(default)]
    pub by_day: Vec<String>,
    #[serde(default)]
    pub by_month_day: Option<i8>,
    #[serde(default)]
    pub by_month: Option<i8>,
    #[serde(default)]
    pub by_set_pos: Option<i8>,
    #[serde(default)]
    pub by_year_day: Option<i16>,
    #[serde(default)]
    pub wkst: Option<String>,
}

fn one() -> u16 {
    1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FrequencyV1 {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl RuleV1 {
    /// The rule in Proton's subset, normalised as [`Rule::read`] does, or
    /// refused.
    pub fn to_rule(&self) -> Result<Rule> {
        let until = match &self.until {
            None => None,
            Some(TimeV1::Date(date)) => Some(Until::Date(
                date.parse().map_err(|_| invalid("UNTIL is not a date"))?,
            )),
            Some(TimeV1::Utc(instant)) => Some(Until::Utc(
                instant
                    .parse()
                    .map_err(|_| invalid("UNTIL is not an instant"))?,
            )),
            Some(TimeV1::Zoned { .. }) => return Err(invalid("UNTIL is a date or a UTC instant")),
        };
        let rule = Rule {
            frequency: match self.frequency {
                FrequencyV1::Daily => Frequency::Daily,
                FrequencyV1::Weekly => Frequency::Weekly,
                FrequencyV1::Monthly => Frequency::Monthly,
                FrequencyV1::Yearly => Frequency::Yearly,
            },
            interval: self.interval,
            count: self.count,
            until,
            by_day: self
                .by_day
                .iter()
                .map(|day| weekday_of(day))
                .collect::<Result<_>>()?,
            by_month_day: self.by_month_day,
            by_month: self.by_month,
            by_set_pos: self.by_set_pos,
            by_year_day: self.by_year_day,
            wkst: self.wkst.as_deref().map(weekday_of).transpose()?,
        };
        Rule::read(&rule.write())
    }

    /// The canonical `RRULE` value.
    pub fn to_text(&self) -> Result<String> {
        Ok(self.to_rule()?.write())
    }

    pub fn of(rule: &Rule) -> RuleV1 {
        RuleV1 {
            frequency: match rule.frequency {
                Frequency::Daily => FrequencyV1::Daily,
                Frequency::Weekly => FrequencyV1::Weekly,
                Frequency::Monthly => FrequencyV1::Monthly,
                Frequency::Yearly => FrequencyV1::Yearly,
            },
            interval: rule.interval,
            count: rule.count,
            until: rule.until.map(|until| match until {
                Until::Date(date) => TimeV1::Date(date.to_string()),
                Until::Utc(instant) => TimeV1::Utc(instant.to_string()),
            }),
            by_day: rule
                .by_day
                .iter()
                .map(|day| weekday_name(*day).to_owned())
                .collect(),
            by_month_day: rule.by_month_day,
            by_month: rule.by_month,
            by_set_pos: rule.by_set_pos,
            by_year_day: rule.by_year_day,
            wkst: rule.wkst.map(|day| weekday_name(day).to_owned()),
        }
    }
}

/// An occurrence as a client draws it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OccurrenceV1 {
    /// Its start in `DTSTART`'s form: what a `RECURRENCE-ID` or an
    /// `EXDATE` naming it carries.
    pub start: TimeV1,
    pub start_utc: String,
    pub end_utc: String,
    pub number: u32,
}

impl OccurrenceV1 {
    pub fn of(occurrence: &Occurrence) -> OccurrenceV1 {
        OccurrenceV1 {
            start: TimeV1::of(&occurrence.start),
            start_utc: occurrence.start_utc.to_string(),
            end_utc: occurrence.end_utc.to_string(),
            number: occurrence.number,
        }
    }
}

/// The `UNTIL` for a series starting at `start` and ending on `date`
/// (`yyyy-MM-dd`), as a client writes it ([`supported_until`]).
pub fn supported_until_v1(start: &TimeV1, date: &str) -> Result<TimeV1> {
    let date: civil::Date = date.parse().map_err(|_| invalid("UNTIL is not a date"))?;
    Ok(match supported_until(&start.to_time()?, date)? {
        Until::Date(date) => TimeV1::Date(date.to_string()),
        Until::Utc(instant) => TimeV1::Utc(instant.to_string()),
    })
}

/// The series of an event's fields after every check its shared signed part
/// makes when built (EXDATE count, RECURRENCE-ID without a rule), so the
/// browser draws only what a server would store.
fn checked_series(fields: &EventFieldsV1) -> Result<Series> {
    let shared = fields.to_parts()?.shared_signed;
    shared.build()?;
    shared.series()
}

/// An event's occurrences meeting `[from, to)` (RFC 3339), at most `max`.
pub fn occurrences_v1(
    fields: &EventFieldsV1,
    from: &str,
    to: &str,
    max: usize,
) -> Result<Vec<OccurrenceV1>> {
    let instant = |text: &str| -> Result<Timestamp> {
        text.parse()
            .map_err(|_| CryptoError::InvalidInput("instant is invalid".into()))
    };
    let series = checked_series(fields)?;
    Ok(series
        .occurrences_between(instant(from)?, instant(to)?, max)?
        .iter()
        .map(OccurrenceV1::of)
        .collect())
}

/// When an event's last occurrence ends (RFC 3339), or `None` without end.
pub fn range_end_v1(fields: &EventFieldsV1) -> Result<Option<String>> {
    let series = checked_series(fields)?;
    Ok(series.range_end()?.map(|end| end.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zoned(local: &str, tzid: &str) -> EventTime {
        EventTime::Zoned {
            local: local.parse().unwrap(),
            tzid: tzid.into(),
        }
    }

    fn starts(series: &Series, n: usize) -> Vec<String> {
        series
            .occurrences()
            .take(n)
            .map(|o| match o.unwrap().start {
                EventTime::Date(date) => date.to_string(),
                EventTime::Zoned { local, .. } => local.to_string(),
                EventTime::Utc(at) => at.to_string(),
            })
            .collect()
    }

    #[test]
    fn canonical_text_only_parses() {
        for text in [
            "FREQ=DAILY",
            "FREQ=WEEKLY;COUNT=10;BYDAY=TU,TH",
            "FREQ=MONTHLY;UNTIL=20271231T225959Z;BYSETPOS=-1;BYDAY=FR",
            "FREQ=YEARLY;INTERVAL=2;BYMONTHDAY=29;BYMONTH=2",
            "FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,SU;WKST=SU",
        ] {
            assert_eq!(Rule::parse(text).unwrap().write(), text);
        }
        for text in [
            "FREQ=DAILY;INTERVAL=1",
            "INTERVAL=2;FREQ=DAILY",
            "FREQ=WEEKLY;BYDAY=TH,TU",
            "FREQ=MONTHLY;BYDAY=2TU",
            "FREQ=WEEKLY;BYDAY=MO;WKST=MO",
        ] {
            assert!(Rule::parse(text).is_err(), "{text}");
            // Others' spellings read, and write canonically.
            Rule::read(text).unwrap();
        }
        assert_eq!(
            Rule::read("FREQ=MONTHLY;BYDAY=2TU").unwrap().write(),
            "FREQ=MONTHLY;BYSETPOS=2;BYDAY=TU"
        );
    }

    /// A multi-byte character where a weekday's two letters are cut must be
    /// refused, never panic (the server reads rules from clients and peers).
    #[test]
    fn non_ascii_is_refused_without_panicking() {
        for text in [
            "FREQ=WEEKLY;BYDAY=aéM",
            "FREQ=WEEKLY;BYDAY=é",
            "FREQ=MONTHLY;BYDAY=2é",
            "FREQ=DAİLY",
            "FREQ=WEEKLY;BYDAY=MO,ü",
        ] {
            assert!(Rule::read(text).is_err(), "{text}");
            assert!(Rule::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn only_protons_subset_reads() {
        for text in [
            "FREQ=HOURLY",
            "FREQ=DAILY;BYDAY=MO",
            "FREQ=DAILY;COUNT=2;UNTIL=20270101",
            "FREQ=DAILY;COUNT=500",
            "FREQ=YEARLY;INTERVAL=100",
            "FREQ=MONTHLY;BYDAY=MO",
            "FREQ=MONTHLY;BYDAY=MO;BYSETPOS=5",
            "FREQ=MONTHLY;BYMONTHDAY=1,15",
            "FREQ=MONTHLY;BYDAY=MO;BYSETPOS=1;BYMONTHDAY=3",
            "FREQ=YEARLY;BYMONTHDAY=3",
            "FREQ=WEEKLY;BYWEEKNO=3",
            "FREQ=DAILY;UNTIL=20380101",
            "FREQ=DAILY;FREQ=DAILY",
            "FREQ=WEEKLY;BYDAY=MO,MO",
            "",
        ] {
            assert!(Rule::read(text).is_err(), "{text}");
        }
    }

    #[test]
    fn nine_stays_nine_across_a_change_of_offset() {
        // Istanbul has no DST; Berlin changes on 2026-10-25.
        let start = zoned("2026-10-20T09:00:00", "Europe/Berlin");
        let end = zoned("2026-10-20T10:00:00", "Europe/Berlin");
        let rule = Rule::parse("FREQ=DAILY;COUNT=10").unwrap();
        let series = Series::new(&start, Some(&end), Some(&rule), &[]).unwrap();
        let all: Vec<Occurrence> = series.occurrences().map(Result::unwrap).collect();
        assert_eq!(all.len(), 10);
        assert_eq!(all[0].start_utc.to_string(), "2026-10-20T07:00:00Z");
        assert_eq!(all[9].start_utc.to_string(), "2026-10-29T08:00:00Z");
        for occurrence in &all {
            assert_eq!(
                occurrence.start_utc.duration_until(occurrence.end_utc),
                SignedDuration::from_hours(1)
            );
        }
        assert_eq!(
            series.range_end().unwrap().unwrap().to_string(),
            "2026-10-29T09:00:00Z"
        );
    }

    #[test]
    fn exdates_remove_after_count() {
        let start = zoned("2026-11-02T09:00:00", "Europe/Istanbul");
        let rule = Rule::parse("FREQ=WEEKLY;COUNT=3").unwrap();
        let removed = zoned("2026-11-09T09:00:00", "Europe/Istanbul");
        let series = Series::new(&start, None, Some(&rule), &[removed]).unwrap();
        assert_eq!(
            starts(&series, 10),
            ["2026-11-02T09:00:00", "2026-11-16T09:00:00"]
        );
        let numbers: Vec<u32> = series.occurrences().map(|o| o.unwrap().number).collect();
        assert_eq!(numbers, [1, 3]);
        // An EXDATE in another zone is refused.
        let elsewhere = zoned("2026-11-09T09:00:00", "Europe/Berlin");
        assert!(Series::new(&start, None, Some(&rule), &[elsewhere]).is_err());
        // Every occurrence removed: refused.
        let all: Vec<EventTime> = ["2026-11-02", "2026-11-09", "2026-11-16"]
            .iter()
            .map(|d| zoned(&format!("{d}T09:00:00"), "Europe/Istanbul"))
            .collect();
        assert!(Series::new(&start, None, Some(&rule), &all).is_err());
    }

    #[test]
    fn dtstart_is_the_first_occurrence() {
        // A Wednesday start for a Tuesday/Thursday rule.
        let start = zoned("2026-10-21T09:00:00", "UTC");
        let rule = Rule::parse("FREQ=WEEKLY;BYDAY=TU,TH").unwrap();
        assert!(Series::new(&start, None, Some(&rule), &[]).is_err());
        let start = zoned("2026-10-22T09:00:00", "UTC");
        let series = Series::new(&start, None, Some(&rule), &[]).unwrap();
        assert_eq!(
            starts(&series, 3),
            [
                "2026-10-22T09:00:00",
                "2026-10-27T09:00:00",
                "2026-10-29T09:00:00"
            ]
        );
        assert_eq!(series.range_end().unwrap(), None);
    }

    #[test]
    fn months_without_the_day_are_skipped() {
        let start = EventTime::Date(civil::date(2027, 1, 31));
        let rule = Rule::parse("FREQ=MONTHLY;COUNT=4").unwrap();
        let series = Series::new(&start, None, Some(&rule), &[]).unwrap();
        assert_eq!(
            starts(&series, 4),
            ["2027-01-31", "2027-03-31", "2027-05-31", "2027-07-31"]
        );
        // Leap days only in leap years.
        let start = EventTime::Date(civil::date(2028, 2, 29));
        let rule = Rule::parse("FREQ=YEARLY;COUNT=2").unwrap();
        let series = Series::new(&start, None, Some(&rule), &[]).unwrap();
        assert_eq!(starts(&series, 2), ["2028-02-29", "2032-02-29"]);
    }

    #[test]
    fn until_is_of_the_start_kind_and_inclusive() {
        let start = EventTime::Date(civil::date(2026, 12, 28));
        let until = supported_until(&start, civil::date(2026, 12, 30)).unwrap();
        assert_eq!(until, Until::Date(civil::date(2026, 12, 30)));
        let mut rule = Rule::parse("FREQ=DAILY").unwrap();
        rule.until = Some(until);
        let series = Series::new(&start, None, Some(&rule), &[]).unwrap();
        assert_eq!(
            starts(&series, 9),
            ["2026-12-28", "2026-12-29", "2026-12-30"]
        );
        // A timed series ends at the end of the day in its zone.
        let start = zoned("2026-12-28T22:30:00", "Europe/Istanbul");
        let until = supported_until(&start, civil::date(2026, 12, 29)).unwrap();
        assert_eq!(until, Until::Utc("2026-12-29T20:59:59Z".parse().unwrap()));
        rule.until = Some(until);
        let series = Series::new(&start, None, Some(&rule), &[]).unwrap();
        assert_eq!(starts(&series, 9).len(), 2);
        // A date UNTIL for a timed series: refused.
        rule.until = Some(Until::Date(civil::date(2026, 12, 29)));
        assert!(Series::new(&start, None, Some(&rule), &[]).is_err());
    }

    #[test]
    fn a_window_and_a_recurrence_id() {
        let start = zoned("2026-10-26T09:00:00", "Europe/Istanbul");
        let end = zoned("2026-10-26T10:00:00", "Europe/Istanbul");
        let rule = Rule::parse("FREQ=WEEKLY;BYDAY=MO,WE").unwrap();
        let series = Series::new(&start, Some(&end), Some(&rule), &[]).unwrap();
        let week = series
            .occurrences_between(
                "2026-11-02T00:00:00Z".parse().unwrap(),
                "2026-11-09T00:00:00Z".parse().unwrap(),
                100,
            )
            .unwrap();
        assert_eq!(week.len(), 2);
        assert_eq!(week[0].start_utc.to_string(), "2026-11-02T06:00:00Z");
        let at = zoned("2026-11-04T09:00:00", "Europe/Istanbul");
        assert_eq!(series.occurrence_at(&at).unwrap().unwrap().number, 4);
        let not = zoned("2026-11-05T09:00:00", "Europe/Istanbul");
        assert!(series.occurrence_at(&not).unwrap().is_none());
    }
}
