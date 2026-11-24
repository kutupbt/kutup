//! Importing an `.ics` file (docs/plans/calendar.md, E2 §5), as Proton's
//! web client (`packages/shared/lib/calendar/import/import.ts`,
//! `icsSurgery/vevent.ts`, `icsSurgery/valarm.ts`): the file read leniently
//! ([`super::reader`]), each event rebuilt from Proton's whitelist into the
//! fields the Rust core seals ([`EventFieldsV1`]), and every component that
//! isn't imported reported with Proton's reason.
//!
//! Kept, as Proton: UID (made from a hash of the event when missing, or for
//! an invitation), DTSTAMP, DTSTART, DTEND (`DURATION` made into one, a
//! zero-length one dropped), SEQUENCE (mod 2^31), SUMMARY, DESCRIPTION and
//! LOCATION (trimmed, cut to Proton's lengths), RRULE in Proton's subset
//! (its `UNTIL` normalised), EXDATE and RECURRENCE-ID in the start's form,
//! and VALARMs (`AUDIO` as a device reminder) within Proton's bounds.
//! `ORGANIZER`, `ATTENDEE` and every other property are dropped. Kutup also
//! keeps `STATUS` and `TRANSP` (its readable calendar part has them; busy
//! times read `TRANSP`), drops an `EXDATE` that removes no occurrence (the
//! server refuses one), and lifts a changed occurrence's `SEQUENCE` to its
//! series' (the server refuses one behind).
//!
//! Time zones: `VTIMEZONE` blocks are ignored (reported only when their
//! `TZID` maps to no zone); a `TZID` is mapped as Proton's
//! ([`super::zones`]); a floating time takes `X-WR-TIMEZONE`, else the one
//! `VTIMEZONE`'s zone, else the person's; a UTC time of a single event in a
//! calendar with `X-WR-TIMEZONE` is put in that zone (Google's exports).

use jiff::{civil, tz::TimeZone, Timestamp};
use serde::{Deserialize, Serialize};

use super::reader::{self, Component, Node, Property, ReadError};
use super::value::{self, Moment};
use super::zones::supported_time_zone;
use super::ReminderV1;
use crate::calendar_event::{
    EventFieldsV1, EventTime, TimeV1, MAX_DESCRIPTION_CHARS, MAX_EXDATES, MAX_LOCATION_CHARS,
    MAX_SUMMARY_CHARS, MAX_UID_LEN,
};
use crate::calendar_recurrence::{first_date, last_date, supported_until, Rule, Series, Until};

/// Proton's `MAX_ICAL_SEQUENCE`.
const MAX_SEQUENCE: i128 = 1 << 31;
/// Proton's reminder bounds per unit (`NOTIFICATION_UNITS_MAX`).
const MAX_WEEKS: i64 = 999;
const MAX_DAYS: i64 = 6999;
const MAX_HOURS: i64 = 999;
const MAX_MINUTES: i64 = 9999;

/// What an import may take: the site's limits (`calendar.import_max_bytes`,
/// `calendar.import_max_events`, `calendar.max_count`,
/// `calendar.reminders_per_event`), the person's zone, and now.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportOptionsV1 {
    /// For floating times when the file names no zone (Proton's primary
    /// time zone).
    pub primary_zone: String,
    pub max_bytes: u64,
    pub max_events: u32,
    pub max_count: u16,
    pub max_reminders: u16,
    /// RFC 3339: a missing or unreadable DTSTAMP is this.
    pub now: String,
}

/// Why a whole file is refused (Proton's `IMPORT_ERROR_TYPE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileError {
    FileEmpty,
    FileTooBig,
    InvalidCalendar,
    InvalidMethod,
    NoEvents,
    TooManyEvents,
}

/// Why one component isn't imported (Proton's `IMPORT_EVENT_ERROR_TYPE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorKind {
    WrongFormat,
    NonGregorian,
    TodoFormat,
    JournalFormat,
    FreebusyFormat,
    TimezoneFormat,
    UnexpectedFloatingTime,
    AlldayInconsistency,
    DtstartMissing,
    DtstartMalformed,
    DtstartOutOfBounds,
    DtendMalformed,
    DtendOutOfBounds,
    XWrTimezoneUnsupported,
    TzidUnsupported,
    RruleMalformed,
    RruleUnsupported,
    SingleEditUnsupported,
    ValidationError,
    /// A component the file never closed, or closed with another's `END`.
    ExternalError,
}

/// A component not imported: what it is (`vevent`, `vtodo`, `vtimezone`,
/// `vcalendar`, or `""` when it couldn't be read), what names it (its UID,
/// title or start, or a time zone's TZID), and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportErrorV1 {
    pub component: String,
    pub id: String,
    pub kind: ErrorKind,
}

/// An event to import: its fields and its reminders (imported events take
/// no calendar defaults, as Proton's), and what names it in a report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedEventV1 {
    pub fields: EventFieldsV1,
    pub reminders: Vec<ReminderV1>,
    pub id: String,
}

/// A file read: its method, the events to import (series before their
/// changed occurrences), what isn't imported, and how many events were
/// dropped silently for having no occurrence left (Proton's hidden errors:
/// counted as imported).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportV1 {
    pub method: String,
    pub events: Vec<ImportedEventV1>,
    pub errors: Vec<ImportErrorV1>,
    pub hidden: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportOutcomeV1 {
    Read(ImportV1),
    Refused(FileError),
}

/// Proton's methods (`ICAL_METHOD`); none written is `PUBLISH`.
const METHODS: [&str; 8] = [
    "PUBLISH",
    "REQUEST",
    "REPLY",
    "CANCEL",
    "COUNTER",
    "DECLINECOUNTER",
    "ADD",
    "REFRESH",
];

/// Reads an `.ics` file for import.
pub fn import(text: &str, options: &ImportOptionsV1) -> crate::error::Result<ImportOutcomeV1> {
    let now: Timestamp = options
        .now
        .parse()
        .map_err(|_| crate::error::CryptoError::InvalidInput("now is invalid".into()))?;
    let now = Timestamp::from_second(now.as_second()).expect("in range");
    crate::calendar_event::time_zone(&options.primary_zone)?;
    if text.len() as u64 > options.max_bytes {
        return Ok(ImportOutcomeV1::Refused(FileError::FileTooBig));
    }
    let calendar = match reader::read(text) {
        Ok(calendar) => calendar,
        Err(ReadError::Empty) => return Ok(ImportOutcomeV1::Refused(FileError::FileEmpty)),
        Err(ReadError::NotACalendar) => {
            return Ok(ImportOutcomeV1::Refused(FileError::InvalidCalendar))
        }
    };
    let method = match calendar.property("METHOD") {
        None => "PUBLISH".to_owned(),
        Some(prop) => {
            let method = value::text(&prop.value).trim().to_ascii_uppercase();
            if !METHODS.contains(&method.as_str()) {
                return Ok(ImportOutcomeV1::Refused(FileError::InvalidMethod));
            }
            method
        }
    };
    if calendar.components.is_empty() {
        return Ok(ImportOutcomeV1::Refused(FileError::NoEvents));
    }
    if calendar.components.len() as u64 > u64::from(options.max_events) {
        return Ok(ImportOutcomeV1::Refused(FileError::TooManyEvents));
    }
    let mut result = ImportV1 {
        method: method.clone(),
        events: Vec::new(),
        errors: Vec::new(),
        hidden: 0,
    };
    let gregorian = calendar.property("CALSCALE").is_none_or(|prop| {
        value::text(&prop.value)
            .trim()
            .eq_ignore_ascii_case("GREGORIAN")
    });
    if !gregorian {
        result.errors.push(ImportErrorV1 {
            component: "vcalendar".into(),
            id: String::new(),
            kind: ErrorKind::NonGregorian,
        });
        return Ok(ImportOutcomeV1::Read(result));
    }
    let x_wr = calendar
        .property("X-WR-TIMEZONE")
        .map(|prop| value::text(&prop.value).trim().to_owned())
        .filter(|zone| !zone.is_empty());
    let zones: Vec<&Component> = calendar.children("VTIMEZONE").collect();
    let guess_zone = match zones.as_slice() {
        [one] => one
            .property("TZID")
            .and_then(|prop| supported_time_zone(&value::text(&prop.value))),
        _ => None,
    }
    .unwrap_or_else(|| options.primary_zone.clone());
    let context = Context {
        publish: method == "PUBLISH",
        reply: method == "REPLY",
        has_x_wr: x_wr.is_some(),
        calendar_zone: x_wr.as_deref().and_then(supported_time_zone),
        guess_zone,
        now,
        max_count: options.max_count,
        max_reminders: usize::from(options.max_reminders),
    };

    let mut candidates = Vec::new();
    for node in &calendar.components {
        let component = match node {
            Node::Component(component) => component,
            Node::Broken { name } => {
                result.errors.push(ImportErrorV1 {
                    component: name.to_ascii_lowercase(),
                    id: String::new(),
                    kind: ErrorKind::ExternalError,
                });
                continue;
            }
        };
        let refuse = |kind| ImportErrorV1 {
            component: component.name.to_ascii_lowercase(),
            id: String::new(),
            kind,
        };
        match component.name.as_str() {
            "VEVENT" => {}
            "VTODO" => {
                result.errors.push(ImportErrorV1 {
                    id: identifier(component),
                    ..refuse(ErrorKind::TodoFormat)
                });
                continue;
            }
            "VJOURNAL" => {
                result.errors.push(ImportErrorV1 {
                    id: identifier(component),
                    ..refuse(ErrorKind::JournalFormat)
                });
                continue;
            }
            "VFREEBUSY" => {
                result.errors.push(ImportErrorV1 {
                    id: identifier(component),
                    ..refuse(ErrorKind::FreebusyFormat)
                });
                continue;
            }
            "VTIMEZONE" => {
                // Ignored, unless its zone is one Kutup can't name.
                let tzid = component
                    .property("TZID")
                    .map(|prop| value::text(&prop.value))
                    .unwrap_or_default();
                if supported_time_zone(&tzid).is_none() {
                    result.errors.push(ImportErrorV1 {
                        id: tzid,
                        ..refuse(ErrorKind::TimezoneFormat)
                    });
                }
                continue;
            }
            _ => {
                result.errors.push(ImportErrorV1 {
                    component: "unknown".into(),
                    ..refuse(ErrorKind::WrongFormat)
                });
                continue;
            }
        }
        let id = identifier(component);
        match event(component, &context) {
            Ok(candidate) => candidates.push(candidate),
            Err(Refusal::Hidden) => result.hidden += 1,
            Err(Refusal::Shown(kind)) => result.errors.push(ImportErrorV1 {
                component: "vevent".into(),
                id,
                kind,
            }),
        }
    }

    // Changed occurrences take their series' form (Proton's
    // getSupportedEventsWithRecurrenceId), when the series is in the file;
    // otherwise the server finds it in the calendar, or refuses.
    let series: Vec<(EventFieldsV1, EventTime)> = candidates
        .iter()
        .filter(|candidate| candidate.fields.recurrence_id.is_none())
        .map(|candidate| (candidate.fields.clone(), candidate.start.clone()))
        .collect();
    let (parents, children): (Vec<Candidate>, Vec<Candidate>) = candidates
        .into_iter()
        .partition(|candidate| candidate.recurrence_id.is_none());
    for candidate in parents {
        result.events.push(candidate.into_event());
    }
    for mut child in children {
        let parent = series
            .iter()
            .rev()
            .find(|(fields, _)| fields.uid == child.fields.uid);
        if let Some((fields, start)) = parent {
            if let Err(kind) = child.link(fields, start) {
                result.errors.push(ImportErrorV1 {
                    component: "vevent".into(),
                    id: child.id,
                    kind,
                });
                continue;
            }
        }
        result.events.push(child.into_event());
    }
    if result.events.is_empty() && result.hidden == 0 && result.errors.is_empty() {
        return Ok(ImportOutcomeV1::Refused(FileError::NoEvents));
    }
    Ok(ImportOutcomeV1::Read(result))
}

struct Context {
    publish: bool,
    reply: bool,
    has_x_wr: bool,
    /// `X-WR-TIMEZONE`'s zone, when it names one.
    calendar_zone: Option<String>,
    guess_zone: String,
    now: Timestamp,
    max_count: u16,
    max_reminders: usize,
}

enum Refusal {
    Shown(ErrorKind),
    /// No occurrence left: dropped without a word (Proton's hidden error).
    Hidden,
}

impl From<ErrorKind> for Refusal {
    fn from(kind: ErrorKind) -> Self {
        Refusal::Shown(kind)
    }
}

struct Candidate {
    fields: EventFieldsV1,
    reminders: Vec<ReminderV1>,
    id: String,
    start: EventTime,
    /// The RECURRENCE-ID as read, before it is put in its series' form.
    recurrence_id: Option<EventTime>,
}

impl Candidate {
    fn into_event(self) -> ImportedEventV1 {
        ImportedEventV1 {
            fields: self.fields,
            reminders: self.reminders,
            id: self.id,
        }
    }

    /// Puts a changed occurrence in its series' form and checks it is one
    /// of the series' occurrences.
    fn link(&mut self, series: &EventFieldsV1, series_start: &EventTime) -> Result<(), ErrorKind> {
        if series.rrule.is_none() {
            return Err(ErrorKind::SingleEditUnsupported);
        }
        let read = self.recurrence_id.clone().expect("a changed occurrence");
        let linked = linked_time(read, series_start)?;
        // One of the series' occurrences (an excluded one too: the change
        // replaces it), as the server checks.
        let parts = series.to_parts().map_err(|_| ErrorKind::ValidationError)?;
        let shared = parts.shared_signed;
        let rule = shared
            .rrule
            .as_deref()
            .map(Rule::parse)
            .transpose()
            .map_err(|_| ErrorKind::ValidationError)?;
        let bare = Series::new(&shared.dtstart, shared.dtend.as_ref(), rule.as_ref(), &[])
            .map_err(|_| ErrorKind::ValidationError)?;
        if !bare
            .occurs_at_all(std::slice::from_ref(&linked))
            .unwrap_or(false)
        {
            return Err(ErrorKind::ValidationError);
        }
        self.fields.recurrence_id = Some(TimeV1::of(&linked));
        self.fields.sequence = self.fields.sequence.max(series.sequence);
        check_parts(&self.fields)
    }
}

/// What names a component in a report (Proton's getComponentIdentifier):
/// its UID, else its title (cut), else its start.
#[inline(never)]
fn identifier(component: &Component) -> String {
    let text = |name| {
        component
            .property(name)
            .map(|prop| value::text(&prop.value).trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    if let Some(uid) = text("UID") {
        return original_uid(&uid).to_owned();
    }
    if let Some(summary) = text("SUMMARY") {
        return cut(&summary, 50);
    }
    text("DTSTART").unwrap_or_default()
}

/// The UID an imported event had before Kutup named it by its hash.
fn original_uid(uid: &str) -> &str {
    uid.strip_prefix(ORIGINAL_PREFIX)
        .and_then(|rest| rest.rsplit_once(&format!("-{HASH_PREFIX}")))
        .map(|(original, _)| original)
        .unwrap_or(uid)
}

/// Proton's truncate: the first `max - 1` characters and an ellipsis.
fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

const HASH_PREFIX: &str = "sha256-uid-";
const ORIGINAL_PREFIX: &str = "original-uid-";

/// Proton's generateVeventHashUID, with SHA-256 for SHA-1: an event named
/// by its own lines, the UID it had (cut from the front) kept before it.
fn hash_uid(digest: &[u8; 32], original: Option<&str>) -> String {
    let hash = format!("{HASH_PREFIX}{}", &hex::encode(digest)[..40]);
    let Some(original) = original else {
        return hash;
    };
    let room = MAX_UID_LEN - ORIGINAL_PREFIX.len() - hash.len() - 1;
    format!("{ORIGINAL_PREFIX}{}-{hash}", keep_end(original, room))
}

/// The last `max` bytes of `text`, on a character boundary (Proton's
/// getSupportedUID keeps a UID's end).
fn keep_end(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// A text value trimmed and cut to `max` characters, without the control
/// characters the parts refuse; none when empty (Proton's
/// getSupportedStringValue).
#[inline(never)]
fn supported_text(prop: Option<&Property>, max: usize) -> Option<String> {
    let text = value::text(&prop?.value)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let text: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    Some(
        text.chars()
            .take(max)
            .collect::<String>()
            .trim_end()
            .to_owned(),
    )
}

#[inline(never)]
fn utc_of(local: civil::DateTime) -> Option<Timestamp> {
    local
        .to_zoned(TimeZone::UTC)
        .ok()
        .map(|zoned| zoned.timestamp())
}

/// A date or date-time property as an event time (Proton's
/// getSupportedDateOrDateTimeProperty).
#[inline(never)]
fn supported_time(
    moment: Moment,
    prop: &Property,
    context: &Context,
    recurring: bool,
    malformed: ErrorKind,
) -> Result<EventTime, ErrorKind> {
    let zoned = |local: civil::DateTime, tzid: &str| EventTime::Zoned {
        local,
        tzid: tzid.to_owned(),
    };
    let time = match moment {
        Moment::Date(date) => EventTime::Date(date),
        Moment::Utc(local) => {
            let instant = utc_of(local).ok_or(malformed)?;
            match (&context.calendar_zone, recurring, context.has_x_wr) {
                // Google exports a single event's times in UTC beside its
                // calendar's zone: shown in that zone, as Proton.
                (Some(zone), false, true) => {
                    let tz = crate::calendar_event::time_zone(zone).map_err(|_| malformed)?;
                    zoned(instant.to_zoned(tz).datetime(), zone)
                }
                _ => EventTime::Utc(instant),
            }
        }
        Moment::Local(local) => match prop.param("TZID") {
            Some(tzid) => {
                let zone = supported_time_zone(tzid).ok_or(ErrorKind::TzidUnsupported)?;
                zoned(local, &zone)
            }
            None if !context.has_x_wr => zoned(local, &context.guess_zone),
            None => match &context.calendar_zone {
                Some(zone) => zoned(local, zone),
                None => return Err(ErrorKind::XWrTimezoneUnsupported),
            },
        },
    };
    time.instant().map_err(|_| malformed)?;
    Ok(time)
}

/// A time in the form of the start it goes with (Proton's
/// getLinkedDateTimeProperty): a date for an all-day start, else the same
/// instant in the start's zone.
#[inline(never)]
fn linked_time(time: EventTime, start: &EventTime) -> Result<EventTime, ErrorKind> {
    match start {
        EventTime::Date(_) => Ok(EventTime::Date(match &time {
            EventTime::Date(date) => *date,
            EventTime::Zoned { local, .. } => local.date(),
            EventTime::Utc(instant) => instant.to_zoned(TimeZone::UTC).date(),
        })),
        _ if time.is_date() => Err(ErrorKind::AlldayInconsistency),
        EventTime::Zoned { tzid, .. } => {
            if time.tzid() == Some(tzid.as_str()) {
                return Ok(time);
            }
            let instant = time.instant().map_err(|_| ErrorKind::ValidationError)?;
            let tz =
                crate::calendar_event::time_zone(tzid).map_err(|_| ErrorKind::ValidationError)?;
            Ok(EventTime::Zoned {
                local: instant.to_zoned(tz).datetime(),
                tzid: tzid.clone(),
            })
        }
        EventTime::Utc(_) => Ok(EventTime::Utc(
            time.instant().map_err(|_| ErrorKind::ValidationError)?,
        )),
    }
}

/// Proton's `MINIMUM_DATE_UTC` and `MAXIMUM_DATE_UTC`.
#[inline(never)]
fn out_of_bounds(time: &EventTime) -> bool {
    let bound =
        |date: civil::Date| utc_of(date.to_datetime(civil::Time::midnight())).expect("in range");
    match time.instant() {
        Ok(instant) => instant < bound(first_date()) || instant > bound(last_date()),
        Err(_) => true,
    }
}

/// Proton's getSupportedDtstamp: UTC as RFC 5545 asks; a time in a zone
/// converted; anything else, now.
#[inline(never)]
fn supported_dtstamp(prop: Option<&Property>, now: Timestamp) -> Timestamp {
    let Some(prop) = prop else { return now };
    let Some(moment) = value::moment(&prop.value, prop.param("VALUE")) else {
        return now;
    };
    let instant = match moment {
        Moment::Date(date) => utc_of(date.to_datetime(civil::Time::midnight())),
        Moment::Utc(local) => utc_of(local),
        Moment::Local(local) => match prop.param("TZID") {
            Some(tzid) => supported_time_zone(tzid)
                .and_then(|zone| crate::calendar_event::time_zone(&zone).ok())
                .and_then(|tz| local.to_zoned(tz).ok())
                .map(|zoned| zoned.timestamp()),
            None => utc_of(local),
        },
    };
    instant.unwrap_or(now)
}

/// Proton's getSupportedSequenceValue: negative is 0, past 2^31 wraps.
fn supported_sequence(prop: Option<&Property>) -> u32 {
    let value = prop
        .and_then(|prop| prop.value.trim().parse::<i128>().ok())
        .unwrap_or(0);
    if value < 0 {
        0
    } else {
        (value % MAX_SEQUENCE) as u32
    }
}

fn event(component: &Component, context: &Context) -> Result<Candidate, Refusal> {
    let id = identifier(component);
    let start_prop = component
        .property("DTSTART")
        .ok_or(ErrorKind::DtstartMissing)?;
    let dtstamp = supported_dtstamp(component.property("DTSTAMP"), context.now);

    // The UID: the file's, or made from the event's lines when it has none
    // or is an invitation (whose UID is the organizer's series').
    let read_uid = component
        .property("UID")
        .map(|prop| {
            value::text(&prop.value)
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_owned()
        })
        .filter(|uid| !uid.is_empty());
    let hashed = read_uid.is_none() || !context.publish;
    let uid = match (&read_uid, hashed) {
        (Some(uid), false) => keep_end(uid, MAX_UID_LEN).to_owned(),
        (uid, _) => hash_uid(&component.digest, uid.as_deref()),
    };

    let rrule_props: Vec<&Property> = component.all("RRULE").collect();
    let recurrence_prop = component.property("RECURRENCE-ID");
    let recurring = !rrule_props.is_empty() || recurrence_prop.is_some();

    let start = value::moment(&start_prop.value, start_prop.param("VALUE"))
        .ok_or(ErrorKind::DtstartMalformed)?;
    let start = supported_time(
        start,
        start_prop,
        context,
        recurring,
        ErrorKind::DtstartMalformed,
    )?;
    if out_of_bounds(&start) {
        return Err(ErrorKind::DtstartOutOfBounds.into());
    }
    let start_utc = start.instant().map_err(|_| ErrorKind::DtstartMalformed)?;

    let mut end = None;
    if let Some(end_prop) = component.property("DTEND") {
        let moment = value::moment(&end_prop.value, end_prop.param("VALUE"))
            .ok_or(ErrorKind::DtendMalformed)?;
        let read = supported_time(
            moment,
            end_prop,
            context,
            recurring,
            ErrorKind::DtendMalformed,
        )?;
        let end_utc = read.instant().map_err(|_| ErrorKind::DtendMalformed)?;
        // An all-day event ending on its start day (not as RFC 5545 asks)
        // is one day.
        let modified = if !read.is_date() || end_utc == start_utc {
            end_utc
        } else {
            end_utc - jiff::SignedDuration::from_hours(24)
        };
        if modified > start_utc {
            end = Some(read);
        }
    } else if let Some(seconds) = component
        .property("DURATION")
        .and_then(|prop| value::duration(&prop.value))
    {
        end = end_of_duration(&start, start_utc, seconds);
    }
    if let Some(end) = &end {
        if out_of_bounds(end) {
            return Err(ErrorKind::DtendOutOfBounds.into());
        }
        if end.is_date() != start.is_date() {
            return Err(ErrorKind::AlldayInconsistency.into());
        }
    }

    let mut exdates = Vec::new();
    let exdate_props: Vec<&Property> = component.all("EXDATE").collect();
    if !exdate_props.is_empty() {
        if rrule_props.is_empty() {
            return Err(ErrorKind::RruleMalformed.into());
        }
        for prop in exdate_props {
            for moment in value::moments(prop) {
                let moment = moment.ok_or(ErrorKind::RruleMalformed)?;
                let read = supported_time(moment, prop, context, true, ErrorKind::RruleMalformed)?;
                exdates.push(linked_time(read, &start)?);
            }
        }
    }

    let mut ignore_rule = false;
    let mut recurrence_id = None;
    // A hash UID makes a RECURRENCE-ID meaningless: it is dropped.
    if let (Some(prop), false) = (recurrence_prop, hashed) {
        if !rrule_props.is_empty() {
            if context.reply {
                // The sender forgot to take the RRULE off.
                ignore_rule = true;
            } else {
                return Err(ErrorKind::SingleEditUnsupported.into());
            }
        }
        let moment =
            value::moment(&prop.value, prop.param("VALUE")).ok_or(ErrorKind::ValidationError)?;
        recurrence_id = Some(supported_time(
            moment,
            prop,
            context,
            true,
            ErrorKind::ValidationError,
        )?);
    }

    let mut rrule = None;
    if let (Some(first), false) = (rrule_props.first(), ignore_rule) {
        if rrule_props.len() > 1 {
            return Err(ErrorKind::RruleUnsupported.into());
        }
        let rule = supported_rule(&first.value, &start, context)?;
        // DTSTART is the rule's first occurrence (getHasConsistentRrule).
        let bare = Series::new(&start, end.as_ref(), Some(&rule), &[])
            .map_err(|_| ErrorKind::RruleMalformed)?;
        // An EXDATE that removes nothing is dropped: the server refuses one.
        exdates.retain(|exdate| {
            bare.occurs_at_all(std::slice::from_ref(exdate))
                .unwrap_or(false)
        });
        exdates.sort_unstable_by_key(|exdate| exdate.instant().ok());
        exdates.dedup();
        if exdates.len() > MAX_EXDATES {
            return Err(ErrorKind::ValidationError.into());
        }
        if Series::new(&start, end.as_ref(), Some(&rule), &exdates).is_err() {
            return Err(Refusal::Hidden);
        }
        rrule = Some(rule.write());
    } else {
        exdates.clear();
    }

    let reminders = if context.publish {
        supported_alarms(component, &start, start_utc, context.max_reminders)
    } else {
        Vec::new()
    };
    let word = |name: &str, allowed: &[&str]| {
        component
            .property(name)
            .map(|prop| value::text(&prop.value).trim().to_ascii_lowercase())
            .filter(|word| allowed.contains(&word.as_str()))
    };
    let created =
        component
            .property("CREATED")
            .and_then(|prop| match value::moment(&prop.value, None) {
                Some(Moment::Utc(local)) => utc_of(local),
                _ => None,
            });
    let fields = EventFieldsV1 {
        uid,
        dtstamp: dtstamp.to_string(),
        created: created.map(|created| created.to_string()),
        start: TimeV1::of(&start),
        end: end.as_ref().map(TimeV1::of),
        recurrence_id: recurrence_id.as_ref().map(TimeV1::of),
        rrule,
        exdates: exdates.iter().map(TimeV1::of).collect(),
        organizer: None,
        sequence: supported_sequence(component.property("SEQUENCE")),
        summary: supported_text(component.property("SUMMARY"), MAX_SUMMARY_CHARS),
        description: supported_text(component.property("DESCRIPTION"), MAX_DESCRIPTION_CHARS),
        location: supported_text(component.property("LOCATION"), MAX_LOCATION_CHARS),
        status: word("STATUS", &["tentative", "confirmed", "cancelled"]),
        transp: word("TRANSP", &["opaque", "transparent"]),
        comment: None,
        other: Vec::new(),
        signed_other: Vec::new(),
        calendar_other: Vec::new(),
        comment_other: Vec::new(),
    };
    check_parts(&fields)?;
    Ok(Candidate {
        fields,
        reminders,
        id,
        start,
        recurrence_id,
    })
}

/// The fields make parts the Rust core writes (the last check before an
/// event is sealed).
#[inline(never)]
fn check_parts(fields: &EventFieldsV1) -> Result<(), ErrorKind> {
    let parts = fields.to_parts().map_err(|_| ErrorKind::ValidationError)?;
    parts
        .shared_signed
        .build()
        .and_then(|_| parts.shared_encrypted.build())
        .and_then(|_| parts.calendar_signed.build())
        .map(|_| ())
        .map_err(|_| ErrorKind::ValidationError)
}

/// Proton's getDtendPropertyFromDuration.
#[inline(never)]
fn end_of_duration(start: &EventTime, start_utc: Timestamp, seconds: i64) -> Option<EventTime> {
    let end = start_utc
        .checked_add(jiff::SignedDuration::from_secs(seconds))
        .ok()?;
    match start {
        EventTime::Date(_) => {
            if seconds <= 86_400 {
                return None;
            }
            let at = end.to_zoned(TimeZone::UTC);
            let date = if at.time() == civil::Time::midnight() {
                at.date()
            } else {
                at.date().tomorrow().ok()?
            };
            Some(EventTime::Date(date))
        }
        _ if seconds <= 0 => None,
        EventTime::Zoned { tzid, .. } => {
            let tz = crate::calendar_event::time_zone(tzid).ok()?;
            Some(EventTime::Zoned {
                local: end.to_zoned(tz).datetime(),
                tzid: tzid.clone(),
            })
        }
        EventTime::Utc(_) => Some(EventTime::Utc(end)),
    }
}

/// An `RRULE` as others write it, in Proton's subset (getSupportedRrule):
/// its `UNTIL` normalised (getSupportedUntil), `COUNT` within the site's
/// limit.
#[inline(never)]
fn supported_rule(text: &str, start: &EventTime, context: &Context) -> Result<Rule, ErrorKind> {
    let text = text.trim().to_ascii_uppercase();
    let mut parts: Vec<String> = text
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    let has = |name: &str| {
        parts
            .iter()
            .any(|part| part.starts_with(&format!("{name}=")))
    };
    if has("COUNT") && has("UNTIL") {
        return Err(ErrorKind::RruleMalformed);
    }
    if has("BYYEARDAY") && !parts.iter().any(|part| part == "FREQ=YEARLY") {
        return Err(ErrorKind::RruleMalformed);
    }
    for part in &mut parts {
        let Some(until) = part.strip_prefix("UNTIL=") else {
            continue;
        };
        let moment = value::moment(until, None).ok_or(ErrorKind::RruleUnsupported)?;
        let day = until_day(moment, start, context).ok_or(ErrorKind::RruleUnsupported)?;
        if day > last_date() {
            return Err(ErrorKind::RruleUnsupported);
        }
        let until = supported_until(start, day).map_err(|_| ErrorKind::RruleUnsupported)?;
        *part = match until {
            Until::Date(date) => format!("UNTIL={}", date.strftime("%Y%m%d")),
            Until::Utc(instant) => format!("UNTIL={}", instant.strftime("%Y%m%dT%H%M%SZ")),
        };
    }
    let rule = Rule::read(&parts.join(";")).map_err(|_| ErrorKind::RruleUnsupported)?;
    if rule.count.is_some_and(|count| count > context.max_count) {
        return Err(ErrorKind::RruleUnsupported);
    }
    Ok(rule)
}

/// The day an `UNTIL` ends on, for a series starting at `start`: a date as
/// it is; a time (UTC, or floating read as UTC, as Proton) on its day in
/// the start's zone, or for an all-day series in the guessed zone.
#[inline(never)]
fn until_day(moment: Moment, start: &EventTime, context: &Context) -> Option<civil::Date> {
    let local = match moment {
        Moment::Date(date) => return Some(date),
        Moment::Utc(local) | Moment::Local(local) => local,
    };
    let instant = utc_of(local)?;
    let zone = match start {
        EventTime::Date(_) => context.guess_zone.as_str(),
        EventTime::Zoned { tzid, .. } => tzid.as_str(),
        EventTime::Utc(_) => "UTC",
    };
    let tz = crate::calendar_event::time_zone(zone).ok()?;
    Some(instant.to_zoned(tz).date())
}

/// An event's VALARMs as reminders (Proton's getSupportedAlarms and
/// dedupeAlarmsWithNormalizedTriggers): `EMAIL` by email, `DISPLAY` and
/// `AUDIO` on the device; relative to the start only, at or before a timed
/// event's start and before an all-day event's day ends; within Proton's
/// bounds; at most `most`, none twice.
#[inline(never)]
fn supported_alarms(
    component: &Component,
    start: &EventTime,
    start_utc: Timestamp,
    most: usize,
) -> Vec<ReminderV1> {
    let all_day = start.is_date();
    let mut found: Vec<(i64, super::ReminderKind)> = component
        .children("VALARM")
        .filter_map(|alarm| {
            let action = alarm.property("ACTION")?.value.trim().to_ascii_uppercase();
            if !["DISPLAY", "EMAIL", "AUDIO"].contains(&action.as_str()) {
                return None;
            }
            let trigger = alarm.property("TRIGGER")?;
            if alarm.property("DURATION").is_some() != alarm.property("REPEAT").is_some() {
                return None;
            }
            let seconds = if trigger
                .param("VALUE")
                .is_some_and(|v| v.eq_ignore_ascii_case("DATE-TIME"))
            {
                let at = match value::moment(&trigger.value, None)? {
                    Moment::Utc(local) | Moment::Local(local) => utc_of(local)?,
                    Moment::Date(_) => return None,
                };
                // Whole minutes before the start (Proton's
                // absoluteToRelativeTrigger).
                -(start_utc.as_second() - at.as_second()).div_euclid(60) * 60
            } else {
                if trigger
                    .param("RELATED")
                    .is_some_and(|r| r.eq_ignore_ascii_case("END"))
                {
                    return None;
                }
                // A trigger that doesn't read is at the start (Proton's
                // replaceTrigger).
                value::duration(&trigger.value).unwrap_or(0)
            };
            // Seconds go (Proton normalises them away).
            let minutes = seconds / 60;
            let in_future = if all_day {
                minutes >= 24 * 60
            } else {
                minutes > 0
            };
            if in_future || !within_bounds(minutes, all_day) {
                return None;
            }
            let kind = if action == "EMAIL" {
                super::ReminderKind::Email
            } else {
                super::ReminderKind::Device
            };
            Some((minutes, kind))
        })
        .take(most)
        .collect();
    found.sort_unstable();
    found.dedup();
    found
        .into_iter()
        .map(|(minutes, kind)| ReminderV1 {
            kind,
            trigger: super::minutes_trigger(minutes),
        })
        .collect()
}

/// Proton's `NOTIFICATION_UNITS_MAX`, on the trigger as its editor writes
/// it: a timed event's in one unit, an all-day event's in days (or weeks)
/// and a time of day.
fn within_bounds(minutes: i64, all_day: bool) -> bool {
    let before = minutes.abs();
    if all_day {
        let days = before / 1440 + i64::from(minutes < 0 && before % 1440 != 0);
        return days <= MAX_DAYS && (days % 7 != 0 || days / 7 <= MAX_WEEKS);
    }
    if before % 60 != 0 {
        before <= MAX_MINUTES
    } else if (before / 60) % 24 != 0 {
        before / 60 <= MAX_HOURS
    } else if (before / 1440) % 7 != 0 {
        before / 1440 <= MAX_DAYS
    } else {
        before / 10080 <= MAX_WEEKS
    }
}

/// A reminder's trigger reads as a duration (an export writes it as kept).
pub(crate) fn check_trigger(trigger: &str) -> crate::error::Result<()> {
    if trigger.len() > 32 || value::duration(trigger).is_none() {
        return Err(crate::error::CryptoError::InvalidInput(
            "a reminder's trigger is a duration".into(),
        ));
    }
    Ok(())
}
