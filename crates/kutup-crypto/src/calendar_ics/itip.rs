//! Invitations as iMIP carries them (RFC 5546, 6047; docs/plans/calendar-e4.md
//! §1–2), as Proton's Mail and Calendar read and write them
//! (`applications/mail/src/app/helpers/calendar/invite.ts`,
//! `packages/shared/lib/calendar/mailIntegration/invite.ts`).
//!
//! **Reading** ([`read_invitation`]) is lenient, as the import is: the
//! file's `METHOD` (none is `PUBLISH`), a Gregorian `CALSCALE`, the first
//! `VEVENT` rebuilt by the import's whitelist ([`super::import`]) but with
//! its UID kept (the organizer names the series by it), `ORGANIZER` and
//! each `ATTENDEE` with its name, answer, role and RSVP, and the note
//! (`COMMENT`). Proton's repairs: a UID or SEQUENCE written outside the
//! `VEVENT` is taken, a missing `DTSTAMP` is the message's time, a missing
//! `ORGANIZER` is the sender (for what an organizer sends), and an
//! attendee written as a URL takes its `EMAIL` parameter. A refusal is one
//! of Proton's (`INVITATION_ERROR_TYPE`, with its event reason).
//!
//! **Writing** ([`write_invitation`]) is one canonical form: `REQUEST`,
//! `REPLY` or `CANCEL` only (Kutup sends no other, as Proton), with the
//! `VTIMEZONE`s the event uses, `PRODID:-//Kutup//Calendar <release>//EN`,
//! and Proton's cut-down `VEVENT` for a reply (only the sender's
//! `ATTENDEE`) and a cancellation. Nothing sealed is ever written: no
//! token, no key, no answer of anyone else.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::export::{text_line, utc_text, vtimezone};
use super::import::{self, Context, Refusal, METHODS};
use super::reader::{self, Component, Property, ReadError};
use super::value;
use super::zones::supported_time_zone;
use crate::calendar_event::{
    canonical_email, check_email, fold_into, time_zone, EventFieldsV1, EventTime,
    MAX_ATTENDEE_NAME_CHARS, MAX_COMMENT_CHARS,
};
use crate::error::{CryptoError, Result};

/// What reading an invitation may take: the site's limits
/// (`calendar.invitation_ics_max_bytes`, `calendar.invitation_count_max`,
/// `calendar.attendees_per_event`), the person's zone, and the message's
/// time and sender.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvitationOptionsV1 {
    pub primary_zone: String,
    pub max_bytes: u64,
    pub max_count: u16,
    pub max_attendees: u32,
    /// RFC 3339.
    pub now: String,
    /// RFC 3339: the message's date (a missing DTSTAMP is this).
    #[serde(default)]
    pub message_date: Option<String>,
    /// The message's sender: a missing ORGANIZER of what an organizer sends.
    #[serde(default)]
    pub sender: Option<String>,
}

/// An attendee's answer (RFC 5545 `PARTSTAT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Partstat {
    NeedsAction,
    Accepted,
    Tentative,
    Declined,
    Delegated,
}

impl Partstat {
    fn read(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_uppercase).as_deref() {
            Some("ACCEPTED") => Partstat::Accepted,
            Some("TENTATIVE") => Partstat::Tentative,
            Some("DECLINED") => Partstat::Declined,
            Some("DELEGATED") => Partstat::Delegated,
            _ => Partstat::NeedsAction,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Partstat::NeedsAction => "NEEDS-ACTION",
            Partstat::Accepted => "ACCEPTED",
            Partstat::Tentative => "TENTATIVE",
            Partstat::Declined => "DECLINED",
            Partstat::Delegated => "DELEGATED",
        }
    }
}

/// The organizer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonV1 {
    /// Lowercase, without `mailto:`.
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// One attendee as an invitation lists them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvitedV1 {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    pub partstat: Partstat,
    /// `ROLE=OPT-PARTICIPANT` or `NON-PARTICIPANT`.
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub rsvp: bool,
}

/// An invitation read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationV1 {
    pub method: String,
    /// The event: its UID as the organizer named it, `organizer` its
    /// `mailto:`; no reminders, no comment.
    pub fields: EventFieldsV1,
    pub organizer: Option<PersonV1>,
    pub attendees: Vec<InvitedV1>,
    /// The `COMMENT` (a reply's note).
    pub note: Option<String>,
    pub prodid: Option<String>,
    /// A reply a Kutup client sent after writing the answer on its server
    /// (`X-KUTUP-REPLY`, Proton's `X-PM-PROTON-REPLY`). Anyone can write it:
    /// it only tells the organizer's widget that the answer may already be
    /// on the event, never what it is.
    pub kutup_reply: bool,
    /// The file held more than one VEVENT (only the first is read).
    pub more_events: bool,
    /// The VEVENT wrote its own DTSTAMP.
    pub dtstamp_given: bool,
}

/// Why an invitation is refused (Proton's `INVITATION_ERROR_TYPE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InvitationError {
    InvitationInvalid,
    InvitationUnsupported,
    InvalidMethod,
    NoComponent,
    NoVevent,
    ParsingError,
}

/// The event's reason (Proton's `EVENT_INVITATION_ERROR_TYPE`), where one
/// is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EventInvitationError {
    NonGregorian,
    InvalidMethod,
    NoVevent,
    MissingOriginalUid,
    MissingOrganizer,
    MissingAttendee,
    DuplicateAttendees,
    TooManyAttendees,
    UnexpectedFloatingTime,
    XWrTimezoneUnsupported,
    TzidUnsupported,
    DtstartMissing,
    AlldayInconsistency,
    DtstartMalformed,
    DtstartOutOfBounds,
    DtendMalformed,
    DtendOutOfBounds,
    RruleMalformed,
    RruleUnsupported,
    SingleEditUnsupported,
    NoOccurrences,
    ExternalError,
    ValidationError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InvitationOutcomeV1 {
    Read(Box<InvitationV1>),
    #[serde(rename_all = "camelCase")]
    Refused {
        error: InvitationError,
        reason: Option<EventInvitationError>,
        /// The method, when it was read: what the refusal is shown as
        /// (an invitation, a response, an event).
        method: Option<String>,
    },
}

fn refused(
    error: InvitationError,
    reason: Option<EventInvitationError>,
    method: Option<&str>,
) -> InvitationOutcomeV1 {
    InvitationOutcomeV1::Refused {
        error,
        reason,
        method: method.map(str::to_owned),
    }
}

/// What an organizer sends; the rest an attendee does.
fn from_organizer(method: &str) -> bool {
    matches!(
        method,
        "REQUEST" | "CANCEL" | "ADD" | "DECLINECOUNTER" | "PUBLISH"
    )
}

fn reason_of(kind: import::ErrorKind) -> (InvitationError, EventInvitationError) {
    use import::ErrorKind as K;
    use EventInvitationError as E;
    let reason = match kind {
        K::NonGregorian => E::NonGregorian,
        K::UnexpectedFloatingTime => E::UnexpectedFloatingTime,
        K::AlldayInconsistency => E::AlldayInconsistency,
        K::DtstartMissing => E::DtstartMissing,
        K::DtstartMalformed => E::DtstartMalformed,
        K::DtstartOutOfBounds => E::DtstartOutOfBounds,
        K::DtendMalformed => E::DtendMalformed,
        K::DtendOutOfBounds => E::DtendOutOfBounds,
        K::XWrTimezoneUnsupported => E::XWrTimezoneUnsupported,
        K::TzidUnsupported => E::TzidUnsupported,
        K::RruleMalformed => E::RruleMalformed,
        K::RruleUnsupported => E::RruleUnsupported,
        K::SingleEditUnsupported => E::SingleEditUnsupported,
        K::ExternalError => E::ExternalError,
        _ => E::ValidationError,
    };
    let error = match reason {
        E::NonGregorian
        | E::XWrTimezoneUnsupported
        | E::TzidUnsupported
        | E::RruleUnsupported
        | E::SingleEditUnsupported => InvitationError::InvitationUnsupported,
        _ => InvitationError::InvitationInvalid,
    };
    (error, reason)
}

/// A name as kept: no control characters or quotes, trimmed, cut.
fn clean_name(value: &str) -> Option<String> {
    let text: String = value
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.chars().take(MAX_ATTENDEE_NAME_CHARS).collect())
}

/// The address an ORGANIZER or ATTENDEE names: its `mailto:` value, else its
/// `EMAIL` parameter (Apple writes principal URLs); `None` when neither is
/// an address a part may carry.
fn address_of(prop: &Property) -> Option<String> {
    let value = value::text(&prop.value);
    let from_value = value
        .trim()
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("mailto:"))
        .map(|_| canonical_email(&value));
    from_value
        .into_iter()
        .chain(prop.param("EMAIL").map(canonical_email))
        .find(|email| check_email(email).is_ok())
}

/// Reads an invitation.
pub fn read_invitation(text: &str, options: &InvitationOptionsV1) -> Result<InvitationOutcomeV1> {
    let instant = |value: &str, what: &str| -> Result<jiff::Timestamp> {
        let at: jiff::Timestamp = value
            .parse()
            .map_err(|_| CryptoError::InvalidInput(format!("{what} is invalid")))?;
        Ok(jiff::Timestamp::from_second(at.as_second()).expect("in range"))
    };
    let now = instant(&options.now, "now")?;
    let message_date = options
        .message_date
        .as_deref()
        .map(|date| instant(date, "the message date"))
        .transpose()?;
    time_zone(&options.primary_zone)?;
    if text.len() as u64 > options.max_bytes {
        return Ok(refused(InvitationError::InvitationUnsupported, None, None));
    }
    let calendar = match reader::read(text) {
        Ok(calendar) => calendar,
        Err(ReadError::Empty) => return Ok(refused(InvitationError::NoComponent, None, None)),
        Err(ReadError::NotACalendar) => {
            return Ok(refused(InvitationError::ParsingError, None, None))
        }
    };
    let method = match calendar.property("METHOD") {
        None => "PUBLISH".to_owned(),
        Some(prop) => {
            let method = value::text(&prop.value).trim().to_ascii_uppercase();
            if !METHODS.contains(&method.as_str()) {
                return Ok(refused(
                    InvitationError::InvalidMethod,
                    Some(EventInvitationError::InvalidMethod),
                    None,
                ));
            }
            method
        }
    };
    let method_ref = Some(method.as_str());
    match method.as_str() {
        // Proton: "Invalid method"; ADD and REFRESH, "not supported for the
        // moment".
        "DECLINECOUNTER" => {
            return Ok(refused(
                InvitationError::InvalidMethod,
                Some(EventInvitationError::InvalidMethod),
                method_ref,
            ))
        }
        "ADD" | "REFRESH" => {
            return Ok(refused(
                InvitationError::InvitationUnsupported,
                None,
                method_ref,
            ))
        }
        _ => {}
    }
    let gregorian = calendar.property("CALSCALE").is_none_or(|prop| {
        value::text(&prop.value)
            .trim()
            .eq_ignore_ascii_case("GREGORIAN")
    });
    if !gregorian {
        return Ok(refused(
            InvitationError::InvitationUnsupported,
            Some(EventInvitationError::NonGregorian),
            method_ref,
        ));
    }
    let mut events = calendar.children("VEVENT");
    let Some(first) = events.next() else {
        return Ok(refused(
            InvitationError::NoVevent,
            Some(EventInvitationError::NoVevent),
            method_ref,
        ));
    };
    let more_events = events.next().is_some();
    // Proton's repair: UID and SEQUENCE written outside the VEVENT.
    let mut event: Component = first.clone();
    for name in ["UID", "SEQUENCE"] {
        if event.property(name).is_none() {
            if let Some(prop) = calendar.property(name) {
                event.properties.push(prop.clone());
            }
        }
    }
    let publish = method == "PUBLISH";
    let has_uid = event
        .property("UID")
        .is_some_and(|prop| !value::text(&prop.value).trim().is_empty());
    if !has_uid && !publish {
        return Ok(refused(
            InvitationError::InvitationInvalid,
            Some(EventInvitationError::MissingOriginalUid),
            method_ref,
        ));
    }
    let dtstamp_given = event.property("DTSTAMP").is_some();
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
        publish,
        reply: matches!(method.as_str(), "REPLY" | "COUNTER"),
        keep_uid: true,
        has_x_wr: x_wr.is_some(),
        calendar_zone: x_wr.as_deref().and_then(supported_time_zone),
        guess_zone,
        // A missing DTSTAMP is the message's time.
        now: message_date.unwrap_or(now),
        max_count: options.max_count,
        max_reminders: 0,
    };
    let mut fields = match import::event(&event, &context) {
        Ok(candidate) => candidate.fields,
        Err(Refusal::Hidden) => {
            return Ok(refused(
                InvitationError::InvitationInvalid,
                Some(EventInvitationError::NoOccurrences),
                method_ref,
            ))
        }
        Err(Refusal::Shown(kind)) => {
            let (error, reason) = reason_of(kind);
            return Ok(refused(error, Some(reason), method_ref));
        }
    };

    let organizer = match event.property("ORGANIZER") {
        Some(prop) => address_of(prop).map(|email| PersonV1 {
            email,
            name: prop.param("CN").and_then(clean_name),
        }),
        None if from_organizer(&method) => options
            .sender
            .as_deref()
            .map(canonical_email)
            .filter(|email| check_email(email).is_ok())
            .map(|email| PersonV1 { email, name: None }),
        None => None,
    };
    if organizer.is_none() && !publish && from_organizer(&method) {
        return Ok(refused(
            InvitationError::InvitationInvalid,
            Some(EventInvitationError::MissingOrganizer),
            method_ref,
        ));
    }
    fields.organizer = organizer
        .as_ref()
        .filter(|_| !publish)
        .map(|person| format!("mailto:{}", person.email));

    let mut attendees: Vec<InvitedV1> = Vec::new();
    for prop in event.all("ATTENDEE") {
        let Some(email) = address_of(prop) else {
            continue;
        };
        if attendees.iter().any(|seen| seen.email == email) {
            return Ok(refused(
                InvitationError::InvitationInvalid,
                Some(EventInvitationError::DuplicateAttendees),
                method_ref,
            ));
        }
        let role = prop.param("ROLE").map(str::to_ascii_uppercase);
        attendees.push(InvitedV1 {
            email,
            name: prop.param("CN").and_then(clean_name),
            partstat: Partstat::read(prop.param("PARTSTAT")),
            optional: matches!(role.as_deref(), Some("OPT-PARTICIPANT" | "NON-PARTICIPANT")),
            rsvp: prop
                .param("RSVP")
                .is_some_and(|rsvp| rsvp.eq_ignore_ascii_case("TRUE")),
        });
    }
    if attendees.len() as u64 > u64::from(options.max_attendees) {
        return Ok(refused(
            InvitationError::InvitationUnsupported,
            Some(EventInvitationError::TooManyAttendees),
            method_ref,
        ));
    }
    if attendees.is_empty() && matches!(method.as_str(), "REPLY" | "COUNTER") {
        return Ok(refused(
            InvitationError::InvitationInvalid,
            Some(EventInvitationError::MissingAttendee),
            method_ref,
        ));
    }
    let note = event
        .property("COMMENT")
        .and_then(|prop| import::supported_text(Some(prop), MAX_COMMENT_CHARS));
    let prodid = calendar
        .property("PRODID")
        .map(|prop| value::text(&prop.value).trim().to_owned())
        .filter(|prodid| !prodid.is_empty());
    let kutup_reply = event
        .property("X-KUTUP-REPLY")
        .is_some_and(|prop| value::text(&prop.value).trim().eq_ignore_ascii_case("TRUE"));
    Ok(InvitationOutcomeV1::Read(Box::new(InvitationV1 {
        method,
        fields,
        organizer,
        attendees,
        note,
        prodid,
        kutup_reply,
        more_events,
        dtstamp_given,
    })))
}

/// What [`write_invitation`] writes.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteInvitationV1 {
    /// `REQUEST`, `REPLY` or `CANCEL`.
    pub method: String,
    pub release: String,
    /// The event as the organizer has it now (its DTSTAMP when this is
    /// sent, its SEQUENCE the one to send).
    pub fields: EventFieldsV1,
    pub organizer: PersonV1,
    /// Everyone for a request or a cancellation (each with the answer the
    /// organizer holds); the sender alone, with their answer, for a reply.
    pub attendees: Vec<InvitedV1>,
    /// A reply's note (`COMMENT`).
    #[serde(default)]
    pub note: Option<String>,
    /// A reply whose answer the sender's client already wrote on the
    /// organizer's server.
    #[serde(default)]
    pub kutup_reply: bool,
}

/// A parameter value as written: quoted, nothing that ends the quote.
fn quoted(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();
    format!("\"{clean}\"")
}

/// Writes an invitation (REQUEST), a reply (REPLY) or a cancellation
/// (CANCEL).
pub fn write_invitation(invitation: &WriteInvitationV1) -> Result<String> {
    let method = invitation.method.as_str();
    if !matches!(method, "REQUEST" | "REPLY" | "CANCEL") {
        return Err(CryptoError::InvalidInput(
            "Kutup sends REQUEST, REPLY and CANCEL only".into(),
        ));
    }
    let release = &invitation.release;
    if release.is_empty()
        || release.len() > 64
        || !release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b))
    {
        return Err(CryptoError::InvalidInput("the release is invalid".into()));
    }
    check_email(&invitation.organizer.email)?;
    if invitation.attendees.is_empty() {
        return Err(CryptoError::InvalidInput(
            "an invitation has attendees".into(),
        ));
    }
    if method == "REPLY" && invitation.attendees.len() != 1 {
        return Err(CryptoError::InvalidInput(
            "a reply carries its sender's answer alone".into(),
        ));
    }
    for attendee in &invitation.attendees {
        check_email(&attendee.email)?;
    }
    if invitation
        .note
        .as_ref()
        .is_some_and(|note| note.chars().count() > MAX_COMMENT_CHARS)
    {
        return Err(CryptoError::InvalidInput("the note is too long".into()));
    }
    let parts = invitation.fields.to_parts()?;
    let shared = &parts.shared_signed;
    let secret = &parts.shared_encrypted;
    // Built as the core writes the parts: every check they make, made.
    shared.build()?;
    secret.build()?;

    let mut zones: BTreeMap<String, (i16, i16)> = BTreeMap::new();
    let mut times: Vec<&EventTime> = vec![&shared.dtstart];
    times.extend(shared.dtend.iter());
    times.extend(shared.recurrence_id.iter());
    times.extend(shared.exdates.iter());
    let year = |time: &EventTime| -> Result<i16> {
        Ok(time.instant()?.to_zoned(jiff::tz::TimeZone::UTC).year())
    };
    let last = shared
        .series()?
        .range_end()?
        .map(|at| at.to_zoned(jiff::tz::TimeZone::UTC).year());
    for time in times {
        if let EventTime::Zoned { tzid, .. } = time {
            let span = zones.entry(tzid.clone()).or_insert((i16::MAX, i16::MIN));
            span.0 = span.0.min(year(time)? - 1);
            span.1 = span.1.max(last.unwrap_or(year(time)?) + 1);
        }
    }

    let mut out = String::new();
    let mut line = |text: String| fold_into(&mut out, &text);
    line("BEGIN:VCALENDAR".into());
    line(format!("PRODID:-//Kutup//Calendar {release}//EN"));
    line("VERSION:2.0".into());
    line(format!("METHOD:{method}"));
    line("CALSCALE:GREGORIAN".into());
    for (tzid, (from, to)) in &zones {
        for text in vtimezone(tzid, *from, *to)? {
            line(text);
        }
    }
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
    // A reply to one occurrence carries no rule (Proton's
    // withoutRedundantRrule).
    if let Some(rule) = shared
        .rrule
        .as_ref()
        .filter(|_| !(method == "REPLY" && shared.recurrence_id.is_some()))
    {
        line(format!("RRULE:{rule}"));
    }
    if method != "CANCEL" {
        for exdate in &shared.exdates {
            line(exdate.write("EXDATE"));
        }
    }
    line(format!("SEQUENCE:{}", shared.sequence));
    let organizer = &invitation.organizer;
    line(
        match organizer.name.as_deref().filter(|name| !name.is_empty()) {
            Some(name) => format!("ORGANIZER;CN={}:mailto:{}", quoted(name), organizer.email),
            None => format!("ORGANIZER:mailto:{}", organizer.email),
        },
    );
    for attendee in &invitation.attendees {
        let mut text = String::from("ATTENDEE");
        if method != "CANCEL" {
            if let Some(name) = attendee.name.as_deref().filter(|name| !name.is_empty()) {
                text.push_str(&format!(";CN={}", quoted(name)));
            }
            if method == "REQUEST" {
                text.push_str(if attendee.optional {
                    ";ROLE=OPT-PARTICIPANT"
                } else {
                    ";ROLE=REQ-PARTICIPANT"
                });
            }
            text.push_str(&format!(";PARTSTAT={}", attendee.partstat.as_str()));
            if method == "REQUEST" {
                text.push_str(";RSVP=TRUE");
            }
        }
        text.push_str(&format!(":mailto:{}", attendee.email));
        line(text);
    }
    // SUMMARY is mandatory in a request (Proton's withSummary).
    let summary = secret.summary.clone().unwrap_or_default();
    line(text_line("SUMMARY", &summary));
    if method == "REQUEST" {
        if let Some(description) = &secret.description {
            line(text_line("DESCRIPTION", description));
        }
    }
    if let Some(location) = &secret.location {
        line(text_line("LOCATION", location));
    }
    // The meeting link, so every invitee can join (RFC 7986; E5c).
    if method == "REQUEST" {
        if let Some(url) = &secret.conference {
            line(format!("CONFERENCE;VALUE=URI;FEATURE=AUDIO,VIDEO:{url}"));
        }
    }
    match method {
        "CANCEL" => line("STATUS:CANCELLED".into()),
        "REQUEST" => {
            if let Some(status) = &invitation.fields.status {
                line(format!("STATUS:{}", status.to_ascii_uppercase()));
            }
            if let Some(transp) = &invitation.fields.transp {
                line(format!("TRANSP:{}", transp.to_ascii_uppercase()));
            }
        }
        _ => {}
    }
    if let Some(note) = invitation.note.as_deref().filter(|note| !note.is_empty()) {
        if note
            .chars()
            .any(|c| c == '\r' || (c.is_control() && c != '\n' && c != '\t'))
        {
            return Err(CryptoError::InvalidInput(
                "the note holds control characters".into(),
            ));
        }
        line(text_line("COMMENT", note));
    }
    if method == "REPLY" && invitation.kutup_reply {
        line("X-KUTUP-REPLY:TRUE".into());
    }
    line("END:VEVENT".into());
    line("END:VCALENDAR".into());
    Ok(out)
}

#[cfg(test)]
mod tests;
