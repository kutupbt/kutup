//! The import and export on files as Google, Outlook and Apple write them
//! (`tests/ics/*.ics`: made for these tests, in those writers' shapes), and
//! Proton's repairs and refusals one by one.

use super::export::{export, ExportCalendarV1, ExportEventV1};
use super::import::{
    import, ErrorKind, FileError, ImportOptionsV1, ImportOutcomeV1, ImportV1, ImportedEventV1,
};
use super::{minutes_trigger, ReminderKind, ReminderV1};
use crate::calendar_event::TimeV1;

const GOOGLE: &str = include_str!("../../tests/ics/google.ics");
const OUTLOOK: &str = include_str!("../../tests/ics/outlook.ics");
const APPLE: &str = include_str!("../../tests/ics/apple.ics");

fn options() -> ImportOptionsV1 {
    ImportOptionsV1 {
        primary_zone: "Europe/Istanbul".into(),
        max_bytes: 10 * 1024 * 1024,
        max_events: 15_000,
        max_count: 49,
        max_reminders: 10,
        now: "2026-11-24T10:00:00.123Z".into(),
    }
}

fn read(text: &str) -> ImportV1 {
    match import(text, &options()).unwrap() {
        ImportOutcomeV1::Read(read) => read,
        ImportOutcomeV1::Refused(why) => panic!("refused: {why:?}"),
    }
}

fn refused(text: &str) -> FileError {
    match import(text, &options()).unwrap() {
        ImportOutcomeV1::Refused(why) => why,
        ImportOutcomeV1::Read(read) => panic!("read: {read:?}"),
    }
}

fn by_title<'a>(read: &'a ImportV1, title: &str) -> &'a ImportedEventV1 {
    read.events
        .iter()
        .find(|event| event.fields.summary.as_deref() == Some(title))
        .unwrap_or_else(|| panic!("no {title}"))
}

fn zoned(local: &str, tzid: &str) -> TimeV1 {
    TimeV1::Zoned {
        local: local.into(),
        tzid: tzid.into(),
    }
}

fn device(trigger: &str) -> ReminderV1 {
    ReminderV1 {
        kind: ReminderKind::Device,
        trigger: trigger.into(),
    }
}

/// Wraps events in a calendar.
fn calendar(body: &str) -> String {
    format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n{body}END:VCALENDAR\r\n")
}

fn one(body: &str) -> ImportV1 {
    read(&calendar(&format!("BEGIN:VEVENT\r\n{body}END:VEVENT\r\n")))
}

fn kinds(read: &ImportV1) -> Vec<ErrorKind> {
    read.errors.iter().map(|error| error.kind).collect()
}

#[test]
fn a_google_export() {
    let read = read(GOOGLE);
    assert_eq!(read.method, "PUBLISH");
    assert_eq!(read.events.len(), 4);
    // The weekly series: its UNTIL to the end of that day in its zone, the
    // EXDATE that removes nothing dropped, its reminders as Proton's.
    let sync = by_title(&read, "Team sync");
    let f = &sync.fields;
    assert_eq!(f.uid, "5u8ahl9q2c0vkm0t3m1j6g1a2b@google.com");
    assert_eq!(f.start, zoned("2026-11-02T10:00:00", "Europe/Istanbul"));
    assert_eq!(
        f.rrule.as_deref(),
        Some("FREQ=WEEKLY;UNTIL=20261221T205959Z;BYDAY=MO")
    );
    assert_eq!(
        f.exdates,
        vec![zoned("2026-11-16T10:00:00", "Europe/Istanbul")]
    );
    assert_eq!(f.sequence, 2);
    assert_eq!(f.location.as_deref(), Some("Room 4, Floor 2"));
    assert!(f
        .description
        .as_deref()
        .unwrap()
        .contains("shared document; bring"));
    assert_eq!(f.status.as_deref(), Some("confirmed"));
    assert_eq!(f.dtstamp, "2026-11-01T12:00:00Z");
    assert_eq!(f.created.as_deref(), Some("2026-10-20T08:00:00Z"));
    assert_eq!(
        sync.reminders,
        vec![
            ReminderV1 {
                kind: ReminderKind::Email,
                trigger: "-P1D".into()
            },
            device("-PT10M"),
        ]
    );
    // The changed occurrence comes after its series, its SEQUENCE lifted to
    // the series'.
    let moved = read.events.last().unwrap();
    assert_eq!(moved.fields.summary.as_deref(), Some("Team sync (moved)"));
    assert_eq!(
        moved.fields.recurrence_id,
        Some(zoned("2026-11-09T10:00:00", "Europe/Istanbul"))
    );
    assert_eq!(moved.fields.sequence, 2);
    // A single event in UTC is put in the calendar's zone; its organizer
    // and attendees are dropped.
    let breakfast = by_title(&read, "Republic Day breakfast");
    assert_eq!(
        breakfast.fields.start,
        zoned("2026-10-29T09:00:00", "Europe/Istanbul")
    );
    assert_eq!(breakfast.fields.organizer, None);
    assert_eq!(breakfast.fields.description, None);
    assert_eq!(breakfast.fields.location.as_deref(), Some("Moda, İstanbul"));
    // All day, free; one day long, so no DTEND.
    let day = by_title(&read, "Republic Day");
    assert_eq!(day.fields.start, TimeV1::Date("2026-10-29".into()));
    assert_eq!(day.fields.end, None);
    assert_eq!(day.fields.transp.as_deref(), Some("transparent"));
    // An hourly rule is outside Proton's subset: reported, by its UID.
    assert_eq!(read.errors.len(), 1);
    assert_eq!(read.errors[0].kind, ErrorKind::RruleUnsupported);
    assert_eq!(read.errors[0].id, "9z8y7x6w5v4u3t2s1r0q9p8o7n@google.com");
    assert_eq!(read.errors[0].component, "vevent");
}

#[test]
fn an_outlook_export() {
    let read = read(OUTLOOK);
    assert_eq!(read.events.len(), 3);
    // Windows' zone names, the ordinal day, the HTML description dropped.
    let review = by_title(&read, "Monthly review");
    assert_eq!(
        review.fields.start,
        zoned("2026-11-10T14:00:00", "Europe/Berlin")
    );
    assert_eq!(
        review.fields.rrule.as_deref(),
        Some("FREQ=MONTHLY;COUNT=6;BYSETPOS=2;BYDAY=TU")
    );
    assert_eq!(review.fields.description, None);
    assert!(review.fields.other.is_empty());
    assert_eq!(review.reminders, vec![device("-PT15M")]);
    // A DURATION is an end; a reminder from the end is dropped.
    let call = by_title(&read, "Call with Seattle");
    assert_eq!(
        call.fields.start,
        zoned("2026-11-05T09:00:00", "America/Los_Angeles")
    );
    assert_eq!(
        call.fields.end,
        Some(zoned("2026-11-05T10:30:00", "America/Los_Angeles"))
    );
    assert_eq!(call.fields.sequence, 3);
    assert!(call.reminders.is_empty());
    let break_ = by_title(&read, "Christmas break");
    assert_eq!(break_.fields.end, Some(TimeV1::Date("2026-12-26".into())));
    assert_eq!(break_.reminders, vec![device("-PT15H")]);
    // A zone that maps to nothing.
    assert_eq!(kinds(&read), vec![ErrorKind::TzidUnsupported]);
}

#[test]
fn an_apple_export_with_lf_line_ends() {
    let read = read(APPLE);
    assert_eq!(read.events.len(), 3);
    let dentist = by_title(&read, "Dentist");
    assert_eq!(
        dentist.fields.start,
        zoned("2026-10-30T09:00:00", "America/New_York")
    );
    // AUDIO is a device reminder; Apple's "none" alarm (ACTION:NONE) goes.
    assert_eq!(dentist.reminders, vec![device("-PT30M")]);
    let birthday = by_title(&read, "Deniz's birthday");
    assert_eq!(birthday.fields.rrule.as_deref(), Some("FREQ=YEARLY"));
    assert_eq!(birthday.reminders, vec![device("PT9H")]);
    // A floating time takes X-WR-TIMEZONE.
    let concert = by_title(&read, "Concert");
    assert_eq!(
        concert.fields.start,
        zoned("2026-10-31T19:30:00", "Europe/Istanbul")
    );
    assert_eq!(kinds(&read), vec![ErrorKind::TodoFormat]);
    assert_eq!(read.errors[0].component, "vtodo");
    assert_eq!(read.errors[0].id, "1A2B3C4D-5E6F-4071-8293-A4B5C6D7E8F9");
}

#[test]
fn files_refused_as_protons() {
    assert_eq!(refused(""), FileError::FileEmpty);
    assert_eq!(
        refused("BEGIN:VCARD\r\nEND:VCARD"),
        FileError::InvalidCalendar
    );
    assert_eq!(
        refused(&calendar("METHOD:SHOUT\r\n")),
        FileError::InvalidMethod
    );
    assert_eq!(refused(&calendar("")), FileError::NoEvents);
    let mut small = options();
    small.max_events = 1;
    let two = calendar("BEGIN:VEVENT\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nEND:VEVENT\r\n");
    assert_eq!(
        import(&two, &small).unwrap(),
        ImportOutcomeV1::Refused(FileError::TooManyEvents)
    );
    small.max_bytes = 10;
    assert_eq!(
        import(GOOGLE, &small).unwrap(),
        ImportOutcomeV1::Refused(FileError::FileTooBig)
    );
    // Only time zones: nothing to import.
    let zones = calendar("BEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\nEND:VTIMEZONE\r\n");
    assert_eq!(refused(&zones), FileError::NoEvents);
    // A non-Gregorian calendar: one error, nothing imported.
    let lunar = calendar(
        "CALSCALE:CHINESE\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261101T100000Z\r\nEND:VEVENT\r\n",
    );
    assert_eq!(kinds(&read(&lunar)), vec![ErrorKind::NonGregorian]);
}

#[test]
fn proton_reasons_per_event() {
    let cases = [
        ("UID:a\r\n", ErrorKind::DtstartMissing),
        ("UID:a\r\nDTSTART:soon\r\n", ErrorKind::DtstartMalformed),
        ("UID:a\r\nDTSTART:19600101T100000Z\r\n", ErrorKind::DtstartOutOfBounds),
        (
            "UID:a\r\nDTSTART:20261101T100000Z\r\nDTEND:20400101T100000Z\r\n",
            ErrorKind::DtendOutOfBounds,
        ),
        (
            "UID:a\r\nDTSTART;VALUE=DATE:20261101\r\nDTEND:20261102T100000Z\r\n",
            ErrorKind::AlldayInconsistency,
        ),
        (
            "UID:a\r\nDTSTART;TZID=Nowhere:20261101T100000\r\n",
            ErrorKind::TzidUnsupported,
        ),
        (
            "UID:a\r\nDTSTART:20261101T100000Z\r\nEXDATE:20261102T100000Z\r\n",
            ErrorKind::RruleMalformed,
        ),
        (
            "UID:a\r\nDTSTART:20261101T100000Z\r\nRRULE:FREQ=WEEKLY;BYDAY=TU\r\n",
            ErrorKind::RruleMalformed,
        ),
        (
            "UID:a\r\nDTSTART:20261101T100000Z\r\nRRULE:FREQ=DAILY;COUNT=50\r\n",
            ErrorKind::RruleUnsupported,
        ),
        (
            "UID:a\r\nDTSTART:20261101T100000Z\r\nRRULE:FREQ=DAILY;UNTIL=20400101\r\n",
            ErrorKind::RruleUnsupported,
        ),
        (
            "UID:a\r\nDTSTART:20261101T100000Z\r\nRRULE:FREQ=DAILY\r\nRECURRENCE-ID:20261102T100000Z\r\n",
            ErrorKind::SingleEditUnsupported,
        ),
    ];
    for (body, kind) in cases {
        assert_eq!(kinds(&one(body)), vec![kind], "{body}");
    }
    // X-WR-TIMEZONE naming no zone, for a floating time.
    let floating = calendar(
        "X-WR-TIMEZONE:Atlantis\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261101T100000\r\nEND:VEVENT\r\n",
    );
    assert_eq!(
        kinds(&read(&floating)),
        vec![ErrorKind::XWrTimezoneUnsupported]
    );
    // An event with no occurrence left is dropped without a word.
    let none = one("UID:a\r\nDTSTART:20261101T100000Z\r\nRRULE:FREQ=DAILY;COUNT=1\r\nEXDATE:20261101T100000Z\r\n");
    assert!(none.events.is_empty() && none.errors.is_empty());
    assert_eq!(none.hidden, 1);
    // An event the file never closed.
    let open = read(&calendar(
        "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261101T100000Z\r\nBEGIN:VEVENT\r\nUID:b\r\nDTSTART:20261101T100000Z\r\nEND:VEVENT\r\n",
    ));
    assert_eq!(open.events.len(), 1);
    assert_eq!(kinds(&open), vec![ErrorKind::ExternalError]);
}

#[test]
fn protons_repairs() {
    // A missing UID and DTSTAMP, ISO times, a huge SEQUENCE, a long title.
    let title = "x".repeat(300);
    let read = one(&format!(
        "DTSTART:2026-11-01T10:00:00.000Z\r\nDTEND:2026-11-01T10:00:00Z\r\nSEQUENCE:4294967298\r\nSUMMARY:  {title}  \r\n"
    ));
    let event = &read.events[0];
    assert!(
        event.fields.uid.starts_with("sha256-uid-"),
        "{}",
        event.fields.uid
    );
    assert_eq!(event.fields.uid.len(), "sha256-uid-".len() + 40);
    assert_eq!(event.fields.dtstamp, "2026-11-24T10:00:00Z");
    assert_eq!(
        event.fields.start,
        TimeV1::Utc("2026-11-01T10:00:00Z".into())
    );
    // A zero-length event has no DTEND.
    assert_eq!(event.fields.end, None);
    assert_eq!(event.fields.sequence, 2);
    assert_eq!(event.fields.summary.as_ref().unwrap().chars().count(), 255);
    // Without a UID, the same lines make the same UID (a second import
    // overwrites the first).
    let again = one(&format!(
        "DTSTART:2026-11-01T10:00:00.000Z\r\nDTEND:2026-11-01T10:00:00Z\r\nSEQUENCE:4294967298\r\nSUMMARY:  {title}  \r\n"
    ));
    assert_eq!(again.events[0].fields.uid, event.fields.uid);
    // An invitation: its UID is hashed (the original kept before it), its
    // reminders and RECURRENCE-ID dropped, as Proton imports one as a
    // simple event.
    let invitation = read_with_method("REQUEST");
    let event = &invitation.events[0];
    assert!(event
        .fields
        .uid
        .starts_with("original-uid-meeting@example.com-sha256-uid-"));
    assert!(event.reminders.is_empty());
    assert_eq!(invitation.method, "REQUEST");
    // A long UID keeps its end.
    let long = format!("{}@example.com", "u".repeat(300));
    let read = one(&format!("UID:{long}\r\nDTSTART:20261101T100000Z\r\n"));
    assert_eq!(read.events[0].fields.uid.len(), 255);
    assert!(read.events[0].fields.uid.ends_with("@example.com"));
    // A floating time without X-WR-TIMEZONE: the one VTIMEZONE's zone.
    let guessed = read_text(&calendar(
        "BEGIN:VTIMEZONE\r\nTZID:Tokyo Standard Time\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261101T100000\r\nEND:VEVENT\r\n",
    ));
    assert_eq!(
        guessed.events[0].fields.start,
        zoned("2026-11-01T10:00:00", "Asia/Tokyo")
    );
    // Two: the person's.
    let primary = one("UID:a\r\nDTSTART:20261101T100000\r\n");
    assert_eq!(
        primary.events[0].fields.start,
        zoned("2026-11-01T10:00:00", "Europe/Istanbul")
    );
    // A custom VTIMEZONE is reported.
    let custom = read_text(&calendar(
        "BEGIN:VTIMEZONE\r\nTZID:Customized Time Zone\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261101T100000Z\r\nEND:VEVENT\r\n",
    ));
    assert_eq!(kinds(&custom), vec![ErrorKind::TimezoneFormat]);
    assert_eq!(custom.errors[0].id, "Customized Time Zone");
}

fn read_text(text: &str) -> ImportV1 {
    read(text)
}

fn read_with_method(method: &str) -> ImportV1 {
    read(&calendar(&format!(
        "METHOD:{method}\r\nBEGIN:VEVENT\r\nUID:meeting@example.com\r\nDTSTART:20261101T100000Z\r\nORGANIZER:mailto:o@example.com\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\n"
    )))
}

#[test]
fn reminders_within_protons_bounds() {
    let alarm = |trigger: &str| {
        format!("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER{trigger}\r\nEND:VALARM\r\n")
    };
    let body = [
        alarm(":-PT15M"),
        alarm(":-PT15M"),                           // twice: once
        alarm(":PT10M"),                            // after a timed start: dropped
        alarm(":-PT10000M"),                        // past 9999 minutes: dropped
        alarm(":-PT9999M"),                         // 6 days 22:39
        alarm(":-P1000W"),                          // past 999 weeks: dropped
        alarm(";VALUE=DATE-TIME:20261101T090000Z"), // an hour before
        alarm(":nonsense"),                         // unreadable: at the start
        alarm(":-PT1M30S"),                         // seconds go
    ]
    .concat();
    let read = one(&format!("UID:a\r\nDTSTART:20261101T100000Z\r\n{body}"));
    let triggers: Vec<&str> = read.events[0]
        .reminders
        .iter()
        .map(|r| r.trigger.as_str())
        .collect();
    assert_eq!(
        triggers,
        vec!["-P6DT22H39M", "-PT1H", "-PT15M", "-PT1M", "PT0S"]
    );
    // At most the site's.
    let mut few = options();
    few.max_reminders = 2;
    let text = calendar(&format!(
        "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261101T100000Z\r\n{}END:VEVENT\r\n",
        [alarm(":-PT1M"), alarm(":-PT2M"), alarm(":-PT3M")].concat()
    ));
    let ImportOutcomeV1::Read(read) = import(&text, &few).unwrap() else {
        panic!()
    };
    assert_eq!(read.events[0].reminders.len(), 2);
    assert_eq!(minutes_trigger(-10_080), "-P1W");
    assert_eq!(minutes_trigger(540), "PT9H");
}

#[test]
fn changed_occurrences_take_their_series_form() {
    let text = calendar(concat!(
        "BEGIN:VEVENT\r\nUID:s\r\nDTSTART;TZID=Europe/Istanbul:20261102T100000\r\nRRULE:FREQ=DAILY;COUNT=5\r\nSEQUENCE:3\r\nEND:VEVENT\r\n",
        // In UTC: put in the series' zone.
        "BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:20261103T070000Z\r\nDTSTART:20261103T080000Z\r\nSUMMARY:moved\r\nEND:VEVENT\r\n",
        // Not one of its occurrences: refused.
        "BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:20261103T080000Z\r\nDTSTART:20261103T080000Z\r\nEND:VEVENT\r\n",
        // A single event changed: refused.
        "BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20261103T080000Z\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:x\r\nRECURRENCE-ID:20261103T080000Z\r\nDTSTART:20261103T090000Z\r\nEND:VEVENT\r\n",
        // A series not in the file: left for the server.
        "BEGIN:VEVENT\r\nUID:elsewhere\r\nRECURRENCE-ID:20261103T080000Z\r\nDTSTART:20261103T090000Z\r\nEND:VEVENT\r\n",
    ));
    let read = read(&text);
    let moved = read
        .events
        .iter()
        .find(|e| e.fields.summary.as_deref() == Some("moved"))
        .unwrap();
    assert_eq!(
        moved.fields.recurrence_id,
        Some(zoned("2026-11-03T10:00:00", "Europe/Istanbul"))
    );
    assert_eq!(moved.fields.sequence, 3);
    assert_eq!(
        kinds(&read),
        vec![ErrorKind::ValidationError, ErrorKind::SingleEditUnsupported]
    );
    assert!(read
        .events
        .iter()
        .any(|e| e.fields.uid == "elsewhere" && e.fields.recurrence_id.is_some()));
    // Series first.
    let first_child = read
        .events
        .iter()
        .position(|e| e.fields.recurrence_id.is_some())
        .unwrap();
    assert!(read.events[..first_child]
        .iter()
        .all(|e| e.fields.recurrence_id.is_none()));
    assert!(read.events[first_child..]
        .iter()
        .all(|e| e.fields.recurrence_id.is_some()));
}

fn export_of(read: &ImportV1) -> String {
    export(&ExportCalendarV1 {
        name: "Work; team".into(),
        description: Some("Shared, with care".into()),
        zone: "Europe/Istanbul".into(),
        release: "2026.11.24".into(),
        untitled: "(no title)".into(),
        email: Some("me@kutup.example".into()),
        events: read
            .events
            .iter()
            .map(|event| ExportEventV1 {
                fields: event.fields.clone(),
                reminders: event.reminders.clone(),
            })
            .collect(),
    })
    .unwrap()
}

#[test]
fn exports_read_back_as_they_were() {
    for file in [GOOGLE, OUTLOOK, APPLE] {
        let first = read(file);
        let text = export_of(&first);
        assert!(text.starts_with(
            "BEGIN:VCALENDAR\r\nPRODID:-//Kutup//Calendar 2026.11.24//EN\r\nVERSION:2.0\r\nMETHOD:PUBLISH\r\nCALSCALE:GREGORIAN\r\nX-WR-TIMEZONE:Europe/Istanbul\r\nX-WR-CALNAME:Work\\; team\r\nX-WR-CALDESC:Shared\\, with care\r\n"
        ));
        assert!(text.ends_with("END:VCALENDAR\r\n"));
        assert!(text.split("\r\n").all(|line| line.len() <= 75));
        let second = read_text(&text);
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        assert_eq!(second.events.len(), first.events.len());
        for (a, b) in first.events.iter().zip(&second.events) {
            // DTSTAMP and the rest as they were; X-WR-TIMEZONE now localises
            // a UTC single event, which the first import already did.
            assert_eq!(a.fields, b.fields);
            assert_eq!(a.reminders, b.reminders);
        }
    }
}

#[test]
fn the_export_writes_zones_and_alarms() {
    let read = read(GOOGLE);
    let text = export_of(&read);
    // Istanbul has had no transition since 2016: one observance.
    assert!(text.contains("BEGIN:VTIMEZONE\r\nTZID:Europe/Istanbul\r\nBEGIN:STANDARD\r\nDTSTART:20250101T030000\r\nTZOFFSETFROM:+0300\r\nTZOFFSETTO:+0300\r\nTZNAME:+03\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n"), "{text}");
    assert!(text.contains("BEGIN:VALARM\r\nACTION:EMAIL\r\nTRIGGER:-P1D\r\nDESCRIPTION:Team sync\r\nSUMMARY:Team sync\r\nATTENDEE:mailto:me@kutup.example\r\nEND:VALARM\r\n"));
    assert!(text.contains("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nDESCRIPTION:Team sync\r\nEND:VALARM\r\n"));
    // New York's transitions over the years the event spans.
    let apple = export_of(&read_text(APPLE));
    assert!(apple.contains("BEGIN:DAYLIGHT\r\nDTSTART:20260308T020000\r\nTZOFFSETFROM:-0500\r\nTZOFFSETTO:-0400\r\nTZNAME:EDT\r\nEND:DAYLIGHT\r\n"), "{apple}");
    assert!(apple.contains("BEGIN:STANDARD\r\nDTSTART:20261101T020000\r\nTZOFFSETFROM:-0400\r\nTZOFFSETTO:-0500\r\nTZNAME:EST\r\nEND:STANDARD\r\n"));
    // A malformed event is refused, never written half.
    let mut bad = read.events[0].fields.clone();
    bad.start = TimeV1::Zoned {
        local: "2026-11-02T10:00:00".into(),
        tzid: "Nowhere/Else".into(),
    };
    let refused = export(&ExportCalendarV1 {
        name: "x".into(),
        description: None,
        zone: "UTC".into(),
        release: "1".into(),
        untitled: "(no title)".into(),
        email: None,
        events: vec![ExportEventV1 {
            fields: bad,
            reminders: Vec::new(),
        }],
    });
    assert!(refused.is_err());
}

#[test]
fn a_meeting_link_is_imported_from_conference_or_protons_property() {
    let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n\
BEGIN:VEVENT\r\nUID:a@t\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261105T090000Z\r\nSUMMARY:A\r\n\
CONFERENCE;VALUE=URI;FEATURE=VIDEO;LABEL=Meet:https://meet.example/abc\r\nEND:VEVENT\r\n\
BEGIN:VEVENT\r\nUID:b@t\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261105T090000Z\r\nSUMMARY:B\r\n\
X-PM-CONFERENCE-URL:https://meet.proton.me/join/x\r\nEND:VEVENT\r\n\
BEGIN:VEVENT\r\nUID:c@t\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261105T090000Z\r\nSUMMARY:C\r\n\
CONFERENCE;VALUE=URI:http://insecure.example/x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let read = read(text);
    assert_eq!(
        by_title(&read, "A").fields.conference.as_deref(),
        Some("https://meet.example/abc")
    );
    assert_eq!(
        by_title(&read, "B").fields.conference.as_deref(),
        Some("https://meet.proton.me/join/x")
    );
    assert_eq!(by_title(&read, "C").fields.conference, None);
}
