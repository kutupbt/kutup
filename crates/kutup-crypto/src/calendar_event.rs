//! A calendar event's parts (docs/plans/calendar.md, E1): Proton's split of
//! a VEVENT into what the server may read (signed) and what it may not
//! (encrypted and signed), each part a VCALENDAR text with one VEVENT
//! holding only its part's properties (`packages/shared/lib/calendar`,
//! `SHARED_SIGNED_FIELDS` and the others).
//!
//! The Rust core owns the text: [`build`] writes a part in one canonical
//! form (CRLF, properties in a fixed order, lines folded at 75 octets,
//! RFC 5545 escaping), and [`parse`] reads a part only if writing it again
//! gives the same bytes, so the server and every client read one format and
//! nothing can hide in a second spelling.
//!
//! Times are a date (all-day), a wall-clock time in an IANA time zone, or a
//! UTC instant, converted with the bundled time zone database
//! ([`EventTime::instant`]).

use jiff::{civil, tz::TimeZone, Timestamp};

use crate::error::{CryptoError, Result};

/// The longest UID kept (Proton's are far shorter; outside ones vary).
pub const MAX_UID_LEN: usize = 255;
/// The longest summary, location and comment, and description, in
/// characters (Proton's limits).
pub const MAX_SUMMARY_CHARS: usize = 255;
pub const MAX_LOCATION_CHARS: usize = 255;
pub const MAX_DESCRIPTION_CHARS: usize = 3000;
pub const MAX_COMMENT_CHARS: usize = 3000;
/// The most exception dates one event lists.
pub const MAX_EXDATES: usize = 500;
/// The largest part's text.
pub const MAX_PART_LEN: usize = 64 * 1024;
/// Properties of an outside event kept as they came (in the shared
/// encrypted part), and the longest of them.
pub const MAX_OTHER_PROPERTIES: usize = 64;
pub const MAX_OTHER_PROPERTY_LEN: usize = 8 * 1024;

const FOLD_AT: usize = 75;

/// When something happens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventTime {
    /// A whole day (`VALUE=DATE`), the same everywhere.
    Date(civil::Date),
    /// A wall-clock time in an IANA time zone (`TZID=`).
    Zoned {
        local: civil::DateTime,
        tzid: String,
    },
    /// A UTC instant (`…Z`).
    Utc(Timestamp),
}

impl EventTime {
    /// The instant it names. A date is that day's midnight UTC, as Proton
    /// stores all-day events (floating, the same day everywhere).
    pub fn instant(&self) -> Result<Timestamp> {
        match self {
            EventTime::Date(date) => date
                .to_zoned(TimeZone::UTC)
                .map(|zoned| zoned.timestamp())
                .map_err(|_| CryptoError::InvalidInput("date out of range".into())),
            EventTime::Zoned { local, tzid } => {
                let zone = time_zone(tzid)?;
                // A time that falls in a gap or a repeat resolves as RFC
                // 5545 asks: the earlier offset (jiff's `compatible`).
                local
                    .to_zoned(zone)
                    .map(|zoned| zoned.timestamp())
                    .map_err(|_| CryptoError::InvalidInput("time out of range".into()))
            }
            EventTime::Utc(instant) => Ok(*instant),
        }
    }

    pub fn is_date(&self) -> bool {
        matches!(self, EventTime::Date(_))
    }

    /// The time zone it is in: its TZID, `UTC`, or none for a date.
    pub fn tzid(&self) -> Option<&str> {
        match self {
            EventTime::Date(_) => None,
            EventTime::Zoned { tzid, .. } => Some(tzid),
            EventTime::Utc(_) => Some("UTC"),
        }
    }

    fn write(&self, name: &str) -> String {
        match self {
            EventTime::Date(date) => format!("{name};VALUE=DATE:{}", date.strftime("%Y%m%d")),
            EventTime::Zoned { local, tzid } => {
                format!("{name};TZID={tzid}:{}", local.strftime("%Y%m%dT%H%M%S"))
            }
            EventTime::Utc(instant) => format!("{name}:{}", utc_text(*instant)),
        }
    }
}

/// An IANA time zone from the bundled database. Aliases (`US/Eastern`) are
/// accepted as the database has them; other names are refused: clients map
/// Windows and other names first, as Proton's `getSupportedTimezone`.
pub fn time_zone(tzid: &str) -> Result<TimeZone> {
    if tzid.is_empty() || tzid.len() > 64 || !tzid.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CryptoError::InvalidInput(
            "time zone name is invalid".into(),
        ));
    }
    jiff::tz::db()
        .get(tzid)
        .map_err(|_| CryptoError::InvalidInput(format!("unknown time zone {tzid:?}")))
}

/// A UTC instant as a wall-clock time in `tzid` (`2026-10-22T09:30:00`),
/// for showing it.
pub fn utc_to_local(instant: &str, tzid: &str) -> Result<String> {
    let instant: Timestamp = instant
        .parse()
        .map_err(|_| CryptoError::InvalidInput("instant is invalid".into()))?;
    Ok(instant
        .to_zoned(time_zone(tzid)?)
        .datetime()
        .strftime("%Y-%m-%dT%H:%M:%S")
        .to_string())
}

/// A wall-clock time in `tzid` as a UTC instant, as events convert theirs.
pub fn local_to_utc(local: &str, tzid: &str) -> Result<String> {
    let local: civil::DateTime = local
        .parse()
        .map_err(|_| CryptoError::InvalidInput("time is invalid".into()))?;
    EventTime::Zoned {
        local,
        tzid: tzid.to_owned(),
    }
    .instant()
    .map(|instant| instant.to_string())
}

/// Every time zone name the bundled database knows, sorted.
pub fn time_zone_names() -> Vec<String> {
    let mut names: Vec<String> = jiff::tz::db()
        .available()
        .map(|name| name.as_str().to_owned())
        .collect();
    names.sort();
    names
}

fn utc_text(instant: Timestamp) -> String {
    instant.strftime("%Y%m%dT%H%M%SZ").to_string()
}

/// The shared signed part: when the event is and how it repeats, readable
/// by the server (Proton's `SHARED_SIGNED_FIELDS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSigned {
    pub uid: String,
    pub dtstamp: Timestamp,
    pub dtstart: EventTime,
    /// None: as long as the start says (a date: one day; a time: no length).
    pub dtend: Option<EventTime>,
    pub recurrence_id: Option<EventTime>,
    /// The RRULE value, in its canonical form
    /// ([`crate::calendar_recurrence::Rule::parse`]).
    pub rrule: Option<String>,
    pub exdates: Vec<EventTime>,
    /// `mailto:` of the organizer (invitations, E4).
    pub organizer: Option<String>,
    pub sequence: u32,
}

/// The shared encrypted part: what the event is (Proton's
/// `SHARED_ENCRYPTED_FIELDS`), plus an outside event's other properties as
/// they came.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SharedEncrypted {
    pub uid: String,
    pub dtstamp: Option<Timestamp>,
    pub created: Option<Timestamp>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    /// Unfolded content lines of properties no part names, in order.
    pub other: Vec<String>,
}

/// The calendar signed part: the event's status on this calendar
/// (Proton's `CALENDAR_SIGNED_FIELDS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalendarSigned {
    pub uid: String,
    pub dtstamp: Timestamp,
    pub exdates: Vec<EventTime>,
    pub status: Option<Status>,
    pub transp: Option<Transp>,
}

/// The calendar encrypted part (Proton's `CALENDAR_ENCRYPTED_FIELDS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalendarEncrypted {
    pub uid: String,
    pub dtstamp: Timestamp,
    pub comment: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Tentative,
    Confirmed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transp {
    Opaque,
    Transparent,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Tentative => "TENTATIVE",
            Status::Confirmed => "CONFIRMED",
            Status::Cancelled => "CANCELLED",
        }
    }
}

impl Transp {
    fn as_str(self) -> &'static str {
        match self {
            Transp::Opaque => "OPAQUE",
            Transp::Transparent => "TRANSPARENT",
        }
    }
}

/// Every property a part names: an outside property with one of these
/// names can't be kept as "other".
const KNOWN: &[&str] = &[
    "UID",
    "DTSTAMP",
    "DTSTART",
    "DTEND",
    "RECURRENCE-ID",
    "RRULE",
    "EXDATE",
    "ORGANIZER",
    "SEQUENCE",
    "CREATED",
    "SUMMARY",
    "DESCRIPTION",
    "LOCATION",
    "STATUS",
    "TRANSP",
    "COMMENT",
    "ATTENDEE",
    "BEGIN",
    "END",
    "DURATION",
    "X-PM-CONFERENCE-ID",
    "X-PM-CONFERENCE-URL",
];

impl SharedSigned {
    /// The event's times and rule as a series (one occurrence when it
    /// doesn't repeat), checked.
    pub fn series(&self) -> Result<crate::calendar_recurrence::Series> {
        let rule = self
            .rrule
            .as_deref()
            .map(crate::calendar_recurrence::Rule::parse)
            .transpose()?;
        crate::calendar_recurrence::Series::new(
            &self.dtstart,
            self.dtend.as_ref(),
            rule.as_ref(),
            &self.exdates,
        )
    }

    pub fn build(&self) -> Result<String> {
        check_uid(&self.uid)?;
        let mut lines = vec![
            format!("UID:{}", escape(&self.uid)),
            format!("DTSTAMP:{}", utc_text(self.dtstamp)),
            self.dtstart.write("DTSTART"),
        ];
        check_time(&self.dtstart)?;
        if let Some(end) = &self.dtend {
            check_time(end)?;
            if end.is_date() != self.dtstart.is_date() {
                return Err(CryptoError::InvalidInput(
                    "start and end are both dates or both times".into(),
                ));
            }
            if end.instant()? < self.dtstart.instant()? {
                return Err(CryptoError::InvalidInput(
                    "the end is before the start".into(),
                ));
            }
            lines.push(end.write("DTEND"));
        }
        if let Some(id) = &self.recurrence_id {
            check_time(id)?;
            // One occurrence changed (Proton's single edit): no rule of its own.
            if self.rrule.is_some() || !self.exdates.is_empty() {
                return Err(CryptoError::InvalidInput(
                    "an event with RECURRENCE-ID has no RRULE or EXDATE".into(),
                ));
            }
            lines.push(id.write("RECURRENCE-ID"));
        }
        if let Some(rule) = &self.rrule {
            lines.push(format!("RRULE:{rule}"));
        }
        // The EXDATE count first, then the rule in its canonical form,
        // fitting the start, and at least one occurrence left.
        push_exdates(&mut lines, &self.exdates)?;
        self.series()?;
        if let Some(organizer) = &self.organizer {
            check_mailto(organizer)?;
            lines.push(format!("ORGANIZER:{organizer}"));
        }
        lines.push(format!("SEQUENCE:{}", self.sequence));
        Ok(wrap(&lines))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let props = read(text)?;
        let mut part = SharedSigned {
            uid: String::new(),
            dtstamp: Timestamp::UNIX_EPOCH,
            dtstart: EventTime::Utc(Timestamp::UNIX_EPOCH),
            dtend: None,
            recurrence_id: None,
            rrule: None,
            exdates: Vec::new(),
            organizer: None,
            sequence: 0,
        };
        let mut start = None;
        for prop in &props {
            match prop.name.as_str() {
                "UID" => part.uid = unescape(&prop.value)?,
                "DTSTAMP" => part.dtstamp = read_utc(prop)?,
                "DTSTART" => start = Some(read_time(prop)?),
                "DTEND" => part.dtend = Some(read_time(prop)?),
                "RECURRENCE-ID" => part.recurrence_id = Some(read_time(prop)?),
                "RRULE" => part.rrule = Some(prop.value.clone()),
                "EXDATE" => part.exdates.push(read_time(prop)?),
                "ORGANIZER" => part.organizer = Some(prop.value.clone()),
                "SEQUENCE" => part.sequence = read_number(prop)?,
                _ => return Err(not_in_part(prop)),
            }
        }
        part.dtstart = start.ok_or_else(|| missing("DTSTART"))?;
        canonical(text, part.build()?)?;
        Ok(part)
    }
}

impl SharedEncrypted {
    pub fn build(&self) -> Result<String> {
        check_uid(&self.uid)?;
        let mut lines = vec![format!("UID:{}", escape(&self.uid))];
        if let Some(stamp) = self.dtstamp {
            lines.push(format!("DTSTAMP:{}", utc_text(stamp)));
        }
        if let Some(created) = self.created {
            lines.push(format!("CREATED:{}", utc_text(created)));
        }
        push_text(&mut lines, "SUMMARY", &self.summary, MAX_SUMMARY_CHARS)?;
        push_text(
            &mut lines,
            "DESCRIPTION",
            &self.description,
            MAX_DESCRIPTION_CHARS,
        )?;
        push_text(&mut lines, "LOCATION", &self.location, MAX_LOCATION_CHARS)?;
        if self.other.len() > MAX_OTHER_PROPERTIES {
            return Err(CryptoError::InvalidInput(
                "too many other properties".into(),
            ));
        }
        for line in &self.other {
            let prop = content_line(line)?;
            if line.len() > MAX_OTHER_PROPERTY_LEN || KNOWN.contains(&prop.name.as_str()) {
                return Err(CryptoError::InvalidInput(format!(
                    "{} can't be kept as another property",
                    prop.name
                )));
            }
            lines.push(line.clone());
        }
        Ok(wrap(&lines))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let props = read(text)?;
        let mut part = SharedEncrypted::default();
        for prop in &props {
            match prop.name.as_str() {
                "UID" => part.uid = unescape(&prop.value)?,
                "DTSTAMP" => part.dtstamp = Some(read_utc(prop)?),
                "CREATED" => part.created = Some(read_utc(prop)?),
                "SUMMARY" => part.summary = Some(unescape(&prop.value)?),
                "DESCRIPTION" => part.description = Some(unescape(&prop.value)?),
                "LOCATION" => part.location = Some(unescape(&prop.value)?),
                name if KNOWN.contains(&name) => return Err(not_in_part(prop)),
                _ => part.other.push(prop.line.clone()),
            }
        }
        canonical(text, part.build()?)?;
        Ok(part)
    }
}

impl CalendarSigned {
    pub fn build(&self) -> Result<String> {
        check_uid(&self.uid)?;
        let mut lines = vec![
            format!("UID:{}", escape(&self.uid)),
            format!("DTSTAMP:{}", utc_text(self.dtstamp)),
        ];
        push_exdates(&mut lines, &self.exdates)?;
        if let Some(status) = self.status {
            lines.push(format!("STATUS:{}", status.as_str()));
        }
        if let Some(transp) = self.transp {
            lines.push(format!("TRANSP:{}", transp.as_str()));
        }
        Ok(wrap(&lines))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let props = read(text)?;
        let mut part = CalendarSigned {
            uid: String::new(),
            dtstamp: Timestamp::UNIX_EPOCH,
            exdates: Vec::new(),
            status: None,
            transp: None,
        };
        for prop in &props {
            match prop.name.as_str() {
                "UID" => part.uid = unescape(&prop.value)?,
                "DTSTAMP" => part.dtstamp = read_utc(prop)?,
                "EXDATE" => part.exdates.push(read_time(prop)?),
                "STATUS" => {
                    part.status = Some(match prop.value.as_str() {
                        "TENTATIVE" => Status::Tentative,
                        "CONFIRMED" => Status::Confirmed,
                        "CANCELLED" => Status::Cancelled,
                        _ => return Err(CryptoError::InvalidInput("unknown STATUS".into())),
                    })
                }
                "TRANSP" => {
                    part.transp = Some(match prop.value.as_str() {
                        "OPAQUE" => Transp::Opaque,
                        "TRANSPARENT" => Transp::Transparent,
                        _ => return Err(CryptoError::InvalidInput("unknown TRANSP".into())),
                    })
                }
                _ => return Err(not_in_part(prop)),
            }
        }
        canonical(text, part.build()?)?;
        Ok(part)
    }
}

impl CalendarEncrypted {
    pub fn build(&self) -> Result<String> {
        check_uid(&self.uid)?;
        let mut lines = vec![
            format!("UID:{}", escape(&self.uid)),
            format!("DTSTAMP:{}", utc_text(self.dtstamp)),
        ];
        push_text(&mut lines, "COMMENT", &self.comment, MAX_COMMENT_CHARS)?;
        Ok(wrap(&lines))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let props = read(text)?;
        let mut part = CalendarEncrypted {
            uid: String::new(),
            dtstamp: Timestamp::UNIX_EPOCH,
            comment: None,
        };
        for prop in &props {
            match prop.name.as_str() {
                "UID" => part.uid = unescape(&prop.value)?,
                "DTSTAMP" => part.dtstamp = read_utc(prop)?,
                "COMMENT" => part.comment = Some(unescape(&prop.value)?),
                _ => return Err(not_in_part(prop)),
            }
        }
        canonical(text, part.build()?)?;
        Ok(part)
    }
}

// ----- the fields a client edits -----

/// A time as a client sends and reads it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum TimeV1 {
    /// `2026-10-22`
    Date(String),
    /// A wall-clock time and its IANA zone.
    Zoned { local: String, tzid: String },
    /// `2026-10-22T06:30:00Z`
    Utc(String),
}

impl TimeV1 {
    pub fn to_time(&self) -> Result<EventTime> {
        let invalid = || CryptoError::InvalidInput("time is invalid".into());
        Ok(match self {
            TimeV1::Date(date) => EventTime::Date(date.parse().map_err(|_| invalid())?),
            TimeV1::Zoned { local, tzid } => {
                time_zone(tzid)?;
                EventTime::Zoned {
                    local: local.parse().map_err(|_| invalid())?,
                    tzid: tzid.clone(),
                }
            }
            TimeV1::Utc(instant) => EventTime::Utc(instant.parse().map_err(|_| invalid())?),
        })
    }

    pub(crate) fn of(time: &EventTime) -> Self {
        match time {
            EventTime::Date(date) => TimeV1::Date(date.to_string()),
            EventTime::Zoned { local, tzid } => TimeV1::Zoned {
                local: local.strftime("%Y-%m-%dT%H:%M:%S").to_string(),
                tzid: tzid.clone(),
            },
            EventTime::Utc(instant) => TimeV1::Utc(instant.to_string()),
        }
    }
}

/// An event as a client edits it: one flat object that the Rust core
/// splits into Proton's parts ([`EventFieldsV1::to_parts`]) and joins back
/// ([`EventFieldsV1::of`]), so the split rule lives in one place.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventFieldsV1 {
    pub uid: String,
    /// When this version was made (UTC).
    pub dtstamp: String,
    pub created: Option<String>,
    pub start: TimeV1,
    pub end: Option<TimeV1>,
    pub recurrence_id: Option<TimeV1>,
    pub rrule: Option<String>,
    #[serde(default)]
    pub exdates: Vec<TimeV1>,
    pub organizer: Option<String>,
    #[serde(default)]
    pub sequence: u32,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    /// `tentative`, `confirmed` or `cancelled`.
    pub status: Option<String>,
    /// `opaque` (busy) or `transparent` (free).
    pub transp: Option<String>,
    pub comment: Option<String>,
    /// An outside event's other properties, as content lines.
    #[serde(default)]
    pub other: Vec<String>,
}

impl EventFieldsV1 {
    pub fn to_parts(&self) -> Result<crate::calendar::EventParts> {
        let stamp: Timestamp = self
            .dtstamp
            .parse()
            .map_err(|_| CryptoError::InvalidInput("dtstamp is invalid".into()))?;
        let created = self
            .created
            .as_deref()
            .map(|created| {
                created
                    .parse::<Timestamp>()
                    .map_err(|_| CryptoError::InvalidInput("created is invalid".into()))
            })
            .transpose()?;
        let exdates = self
            .exdates
            .iter()
            .map(TimeV1::to_time)
            .collect::<Result<Vec<_>>>()?;
        Ok(crate::calendar::EventParts {
            shared_signed: SharedSigned {
                uid: self.uid.clone(),
                dtstamp: stamp,
                dtstart: self.start.to_time()?,
                dtend: self.end.as_ref().map(TimeV1::to_time).transpose()?,
                recurrence_id: self
                    .recurrence_id
                    .as_ref()
                    .map(TimeV1::to_time)
                    .transpose()?,
                rrule: self.rrule.clone(),
                exdates: exdates.clone(),
                organizer: self.organizer.clone(),
                sequence: self.sequence,
            },
            shared_encrypted: SharedEncrypted {
                uid: self.uid.clone(),
                dtstamp: Some(stamp),
                created,
                summary: self.summary.clone(),
                description: self.description.clone(),
                location: self.location.clone(),
                other: self.other.clone(),
            },
            calendar_signed: CalendarSigned {
                uid: self.uid.clone(),
                dtstamp: stamp,
                exdates,
                status: self
                    .status
                    .as_deref()
                    .map(|status| match status {
                        "tentative" => Ok(Status::Tentative),
                        "confirmed" => Ok(Status::Confirmed),
                        "cancelled" => Ok(Status::Cancelled),
                        _ => Err(CryptoError::InvalidInput("status is invalid".into())),
                    })
                    .transpose()?,
                transp: self
                    .transp
                    .as_deref()
                    .map(|transp| match transp {
                        "opaque" => Ok(Transp::Opaque),
                        "transparent" => Ok(Transp::Transparent),
                        _ => Err(CryptoError::InvalidInput("transp is invalid".into())),
                    })
                    .transpose()?,
            },
            calendar_encrypted: self.comment.as_ref().map(|comment| CalendarEncrypted {
                uid: self.uid.clone(),
                dtstamp: stamp,
                comment: Some(comment.clone()),
            }),
        })
    }

    pub fn of(parts: &crate::calendar::EventParts) -> Self {
        let shared = &parts.shared_signed;
        let secret = &parts.shared_encrypted;
        let calendar = &parts.calendar_signed;
        EventFieldsV1 {
            uid: shared.uid.clone(),
            dtstamp: shared.dtstamp.to_string(),
            created: secret.created.map(|created| created.to_string()),
            start: TimeV1::of(&shared.dtstart),
            end: shared.dtend.as_ref().map(TimeV1::of),
            recurrence_id: shared.recurrence_id.as_ref().map(TimeV1::of),
            rrule: shared.rrule.clone(),
            exdates: shared.exdates.iter().map(TimeV1::of).collect(),
            organizer: shared.organizer.clone(),
            sequence: shared.sequence,
            summary: secret.summary.clone(),
            description: secret.description.clone(),
            location: secret.location.clone(),
            status: calendar.status.map(|status| status.as_str().to_lowercase()),
            transp: calendar.transp.map(|transp| transp.as_str().to_lowercase()),
            comment: parts
                .calendar_encrypted
                .as_ref()
                .and_then(|part| part.comment.clone()),
            other: secret.other.clone(),
        }
    }
}

// ----- writing -----

fn wrap(lines: &[String]) -> String {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n");
    for line in lines {
        fold_into(&mut out, line);
    }
    out.push_str("END:VEVENT\r\nEND:VCALENDAR");
    out
}

/// Folds a content line at 75 octets, never inside a character (RFC 5545
/// §3.1): continuation lines start with one space.
fn fold_into(out: &mut String, line: &str) {
    let mut width = 0;
    for ch in line.chars() {
        if width + ch.len_utf8() > FOLD_AT {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(ch);
        width += ch.len_utf8();
    }
    out.push_str("\r\n");
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

fn push_text(
    lines: &mut Vec<String>,
    name: &str,
    value: &Option<String>,
    max: usize,
) -> Result<()> {
    if let Some(value) = value {
        if value.chars().count() > max {
            return Err(CryptoError::InvalidInput(format!(
                "{name} is longer than {max} characters"
            )));
        }
        if value
            .chars()
            .any(|c| c == '\r' || (c.is_control() && c != '\n' && c != '\t'))
        {
            return Err(CryptoError::InvalidInput(format!(
                "{name} holds control characters"
            )));
        }
        lines.push(format!("{name}:{}", escape(value)));
    }
    Ok(())
}

fn push_exdates(lines: &mut Vec<String>, exdates: &[EventTime]) -> Result<()> {
    if exdates.len() > MAX_EXDATES {
        return Err(CryptoError::InvalidInput("too many exception dates".into()));
    }
    for exdate in exdates {
        check_time(exdate)?;
        lines.push(exdate.write("EXDATE"));
    }
    Ok(())
}

fn check_uid(uid: &str) -> Result<()> {
    if uid.is_empty() || uid.len() > MAX_UID_LEN || uid.chars().any(|c| c.is_control()) {
        return Err(CryptoError::InvalidInput("UID is invalid".into()));
    }
    Ok(())
}

fn check_time(time: &EventTime) -> Result<()> {
    if let EventTime::Zoned { tzid, .. } = time {
        time_zone(tzid)?;
    }
    time.instant().map(|_| ())
}

fn check_mailto(value: &str) -> Result<()> {
    let address = value
        .strip_prefix("mailto:")
        .ok_or_else(|| CryptoError::InvalidInput("ORGANIZER is a mailto: address".into()))?;
    if address.is_empty()
        || address.len() > 320
        || !address.contains('@')
        || address
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || ";:,\"".contains(c))
    {
        return Err(CryptoError::InvalidInput("ORGANIZER is invalid".into()));
    }
    Ok(())
}

// ----- reading -----

struct Prop {
    name: String,
    /// Parameters as written, `;`-joined after the name.
    params: String,
    value: String,
    /// The whole unfolded line.
    line: String,
}

/// Unfolds a part and checks its frame: exactly one VEVENT in a VCALENDAR
/// of version 2.0, nothing else.
fn read(text: &str) -> Result<Vec<Prop>> {
    if text.len() > MAX_PART_LEN {
        return Err(CryptoError::InvalidInput("event part is too large".into()));
    }
    let unfolded = text.replace("\r\n ", "");
    let lines: Vec<&str> = unfolded.split("\r\n").collect();
    let frame = |at: usize, want: &str| lines.get(at).is_some_and(|line| *line == want);
    let n = lines.len();
    if n < 5
        || !frame(0, "BEGIN:VCALENDAR")
        || !frame(1, "VERSION:2.0")
        || !frame(2, "BEGIN:VEVENT")
        || !frame(n - 2, "END:VEVENT")
        || !frame(n - 1, "END:VCALENDAR")
    {
        return Err(CryptoError::InvalidInput(
            "an event part is one VEVENT in a VCALENDAR".into(),
        ));
    }
    lines[3..n - 2]
        .iter()
        .map(|line| content_line(line))
        .collect()
}

fn content_line(line: &str) -> Result<Prop> {
    let colon = value_start(line)
        .ok_or_else(|| CryptoError::InvalidInput("content line without a value".into()))?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let (name, params) = head.split_once(';').unwrap_or((head, ""));
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        || line.chars().any(|c| c == '\r' || c == '\n')
    {
        return Err(CryptoError::InvalidInput("content line is invalid".into()));
    }
    Ok(Prop {
        name: name.to_owned(),
        params: params.to_owned(),
        value: value.to_owned(),
        line: line.to_owned(),
    })
}

/// Where a content line's value starts: the first `:` outside a quoted
/// parameter value.
fn value_start(line: &str) -> Option<usize> {
    let mut quoted = false;
    for (index, byte) in line.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b':' if !quoted => return Some(index),
            _ => {}
        }
    }
    None
}

fn read_utc(prop: &Prop) -> Result<Timestamp> {
    if !prop.params.is_empty() {
        return Err(CryptoError::InvalidInput(format!(
            "{} is a UTC time",
            prop.name
        )));
    }
    parse_utc(&prop.value)
}

fn parse_utc(value: &str) -> Result<Timestamp> {
    let local = value
        .strip_suffix('Z')
        .ok_or_else(|| CryptoError::InvalidInput("not a UTC time".into()))?;
    civil::DateTime::strptime("%Y%m%dT%H%M%S", local)
        .and_then(|time| time.to_zoned(TimeZone::UTC))
        .map(|zoned| zoned.timestamp())
        .map_err(|_| CryptoError::InvalidInput("not a UTC time".into()))
}

fn read_time(prop: &Prop) -> Result<EventTime> {
    let invalid = || CryptoError::InvalidInput(format!("{} is invalid", prop.name));
    if prop.params == "VALUE=DATE" {
        return civil::Date::strptime("%Y%m%d", &prop.value)
            .map(EventTime::Date)
            .map_err(|_| invalid());
    }
    if let Some(tzid) = prop.params.strip_prefix("TZID=") {
        let local =
            civil::DateTime::strptime("%Y%m%dT%H%M%S", &prop.value).map_err(|_| invalid())?;
        return Ok(EventTime::Zoned {
            local,
            tzid: tzid.to_owned(),
        });
    }
    if prop.params.is_empty() {
        return parse_utc(&prop.value).map(EventTime::Utc);
    }
    Err(invalid())
}

fn read_number(prop: &Prop) -> Result<u32> {
    if !prop.params.is_empty()
        || prop.value.is_empty()
        || !prop.value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(CryptoError::InvalidInput(format!(
            "{} is a number",
            prop.name
        )));
    }
    prop.value
        .parse()
        .map_err(|_| CryptoError::InvalidInput(format!("{} is too large", prop.name)))
}

fn unescape(value: &str) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some(';') => out.push(';'),
            Some(',') => out.push(','),
            Some('n') | Some('N') => out.push('\n'),
            _ => {
                return Err(CryptoError::InvalidInput(
                    "bad escape in a text value".into(),
                ))
            }
        }
    }
    Ok(out)
}

fn canonical(text: &str, rebuilt: String) -> Result<()> {
    if text != rebuilt {
        return Err(CryptoError::InvalidInput(
            "the event part is not in its canonical form".into(),
        ));
    }
    Ok(())
}

fn not_in_part(prop: &Prop) -> CryptoError {
    CryptoError::InvalidInput(format!("{} doesn't belong in this part", prop.name))
}

fn missing(name: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("{name} is missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp() -> Timestamp {
        "2026-10-21T08:00:00Z".parse().unwrap()
    }

    fn signed() -> SharedSigned {
        SharedSigned {
            uid: "4b1d2c9e-0f3a-4c31-9d2a-7e1b5a8c6f00@kutup".into(),
            dtstamp: stamp(),
            dtstart: EventTime::Zoned {
                local: "2026-10-22T09:30:00".parse().unwrap(),
                tzid: "Europe/Istanbul".into(),
            },
            dtend: Some(EventTime::Zoned {
                local: "2026-10-22T10:30:00".parse().unwrap(),
                tzid: "Europe/Istanbul".into(),
            }),
            recurrence_id: None,
            rrule: None,
            exdates: Vec::new(),
            organizer: None,
            sequence: 0,
        }
    }

    #[test]
    fn parts_round_trip_in_one_form() {
        let part = signed();
        let text = part.build().unwrap();
        assert!(text.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:"));
        assert!(text.contains("\r\nDTSTART;TZID=Europe/Istanbul:20261022T093000\r\n"));
        assert_eq!(SharedSigned::parse(&text).unwrap(), part);
        // Istanbul is UTC+3.
        assert_eq!(
            part.dtstart.instant().unwrap(),
            "2026-10-22T06:30:00Z".parse::<Timestamp>().unwrap()
        );

        let secret = SharedEncrypted {
            uid: part.uid.clone(),
            dtstamp: Some(stamp()),
            summary: Some("Planning; budget, Q4".into()),
            description: Some("Line one\nLine two — ü".repeat(20)),
            location: Some("Room 2".into()),
            other: vec!["X-ALT-DESC;FMTTYPE=text/html:<p>hi</p>".into()],
            ..Default::default()
        };
        let text = secret.build().unwrap();
        assert!(text.contains("SUMMARY:Planning\\; budget\\, Q4"));
        assert!(text.split("\r\n").all(|line| line.len() <= FOLD_AT));
        assert_eq!(SharedEncrypted::parse(&text).unwrap(), secret);
    }

    #[test]
    fn other_spellings_and_stray_properties_are_refused() {
        let text = signed().build().unwrap();
        // Lowercase, LF line ends, a property of another part, a second
        // spelling of the same time: refused.
        assert!(SharedSigned::parse(&text.to_lowercase()).is_err());
        assert!(SharedSigned::parse(&text.replace("\r\n", "\n")).is_err());
        let stray = text.replace("SEQUENCE:0", "SUMMARY:hidden\r\nSEQUENCE:0");
        assert!(SharedSigned::parse(&stray).is_err());
        let respelled = text.replace("SEQUENCE:0", "SEQUENCE:00");
        assert!(SharedSigned::parse(&respelled).is_err());
        let unknown_zone = text.replace("Europe/Istanbul", "Mars/Olympus");
        assert!(SharedSigned::parse(&unknown_zone).is_err());
        // A known property can't ride along as "other".
        let mut secret = SharedEncrypted {
            uid: "u".into(),
            ..Default::default()
        };
        secret.other.push("DTSTART:20261022T063000Z".into());
        assert!(secret.build().is_err());
    }

    #[test]
    fn fields_split_into_parts_and_back() {
        let fields: EventFieldsV1 = serde_json::from_str(
            r#"{"uid":"u@kutup","dtstamp":"2026-10-21T08:00:00Z","created":null,
                "start":{"zoned":{"local":"2026-10-22T09:30:00","tzid":"Europe/Istanbul"}},
                "end":{"zoned":{"local":"2026-10-22T10:30:00","tzid":"Europe/Istanbul"}},
                "recurrenceId":null,"rrule":null,"organizer":null,
                "summary":"Planning","description":null,"location":null,
                "status":"confirmed","transp":"opaque","comment":null}"#,
        )
        .unwrap();
        let parts = fields.to_parts().unwrap();
        assert_eq!(parts.shared_encrypted.summary.as_deref(), Some("Planning"));
        assert_eq!(parts.calendar_signed.status, Some(Status::Confirmed));
        assert!(parts.calendar_encrypted.is_none());
        assert_eq!(EventFieldsV1::of(&parts), fields);
        // Unknown fields and zones: refused.
        assert!(serde_json::from_str::<EventFieldsV1>(r#"{"uid":"u","title":"x"}"#).is_err());
        let mut far = fields.clone();
        far.start = TimeV1::Zoned {
            local: "2026-10-22T09:30:00".into(),
            tzid: "Nowhere/Else".into(),
        };
        assert!(far.to_parts().is_err());
    }

    #[test]
    fn all_day_events_are_dates_at_midnight_utc() {
        let mut part = signed();
        part.dtstart = EventTime::Date("2026-10-22".parse().unwrap());
        part.dtend = Some(EventTime::Date("2026-10-23".parse().unwrap()));
        let text = part.build().unwrap();
        assert!(text.contains("DTSTART;VALUE=DATE:20261022"));
        assert_eq!(
            part.dtstart.instant().unwrap(),
            "2026-10-22T00:00:00Z".parse::<Timestamp>().unwrap()
        );
        // A date start with a timed end: refused.
        part.dtend = Some(EventTime::Utc(stamp()));
        assert!(part.build().is_err());
    }
}
