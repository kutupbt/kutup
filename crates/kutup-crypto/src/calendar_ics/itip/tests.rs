//! Invitations as Apple, Google, Outlook, Fastmail and Proton write them
//! (`tests/ics/itip/*.ics`; see its README for which are Proton's own test
//! files and which were written for these tests), Proton's refusals, and
//! what Kutup writes read back.

use super::*;
use crate::calendar_event::TimeV1;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/ics/itip/{name}.ics", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

fn options() -> InvitationOptionsV1 {
    InvitationOptionsV1 {
        primary_zone: "Europe/Istanbul".into(),
        max_bytes: 1024 * 1024,
        max_count: 499,
        max_attendees: 100,
        now: "2026-11-24T10:00:00Z".into(),
        message_date: Some("2026-11-20T08:00:00Z".into()),
        sender: Some("Zeynep@Fastmail.example".into()),
    }
}

fn read(text: &str) -> InvitationV1 {
    match read_invitation(text, &options()).unwrap() {
        InvitationOutcomeV1::Read(read) => *read,
        refused => panic!("refused: {refused:?}"),
    }
}

fn refusal(text: &str) -> (InvitationError, Option<EventInvitationError>) {
    match read_invitation(text, &options()).unwrap() {
        InvitationOutcomeV1::Refused { error, reason, .. } => (error, reason),
        read => panic!("read: {read:?}"),
    }
}

#[test]
fn apple_keeps_the_uid_and_the_single_edit_and_drops_alarms() {
    let invitation = read(&fixture("apple-single-edit"));
    assert_eq!(invitation.method, "REQUEST");
    assert_eq!(
        invitation.fields.uid,
        "BA3017ED-889A-4BCB-B9CB-11CE30586021"
    );
    assert_eq!(invitation.fields.sequence, 1);
    assert_eq!(
        invitation.fields.recurrence_id,
        Some(TimeV1::Zoned {
            local: "2022-09-15T09:00:00".into(),
            tzid: "Europe/Vilnius".into()
        })
    );
    assert_eq!(
        invitation.fields.organizer.as_deref(),
        Some("mailto:agmailone@gmail.com")
    );
    assert_eq!(
        invitation.organizer,
        Some(PersonV1 {
            email: "agmailone@gmail.com".into(),
            name: Some("testKrt".into())
        })
    );
    assert_eq!(invitation.attendees.len(), 2);
    assert_eq!(invitation.attendees[0].email, "testme@pm.me");
    assert_eq!(invitation.attendees[0].partstat, Partstat::NeedsAction);
    assert!(invitation.attendees[0].rsvp);
    assert_eq!(invitation.attendees[1].partstat, Partstat::Accepted);
    assert!(!invitation.attendees[1].optional);
    assert!(invitation.dtstamp_given);
    assert_eq!(
        invitation.prodid.as_deref(),
        Some("-//Apple Inc.//Mac OS X 10.13.6//EN")
    );
}

#[test]
fn google_reads_roles_and_the_description() {
    let invitation = read(&fixture("google-request"));
    assert_eq!(
        invitation.fields.uid,
        "0928j897bqah35i424dnvjdu3v12346465465@google.com"
    );
    assert_eq!(invitation.attendees.len(), 4);
    assert!(invitation.attendees[3].optional);
    assert_eq!(
        invitation.fields.summary.as_deref(),
        Some("Pacific / Niue (3)")
    );
    assert!(invitation
        .fields
        .description
        .as_deref()
        .unwrap()
        .starts_with("This event has a video call.\nJoin:"));
    assert_eq!(invitation.fields.location, None);
    assert_eq!(invitation.fields.status.as_deref(), Some("confirmed"));
}

#[test]
fn an_attendee_written_as_a_url_takes_its_email_parameter() {
    let invitation = read(&fixture("apple-principal"));
    let emails: Vec<&str> = invitation
        .attendees
        .iter()
        .map(|a| a.email.as_str())
        .collect();
    assert_eq!(emails, ["att1@protonmail.com", "att2@pm.me"]);
    assert_eq!(invitation.fields.start, TimeV1::Date("2027-01-11".into()));
}

#[test]
fn outlook_windows_zones_map_to_iana_and_the_series_reads() {
    let invitation = read(&fixture("outlook-request"));
    assert_eq!(
        invitation.fields.start,
        TimeV1::Zoned {
            local: "2027-01-04T10:00:00".into(),
            tzid: "Europe/Berlin".into()
        }
    );
    assert_eq!(
        invitation.fields.rrule.as_deref(),
        Some("FREQ=MONTHLY;COUNT=12;BYMONTHDAY=4")
    );
    assert_eq!(
        invitation.organizer.unwrap().name.as_deref(),
        Some("Jana Novak")
    );
    assert!(invitation.attendees[1].optional);
    // A COUNT past the invitation limit is refused.
    let tight = InvitationOptionsV1 {
        max_count: 10,
        ..options()
    };
    assert!(matches!(
        read_invitation(&fixture("outlook-request"), &tight).unwrap(),
        InvitationOutcomeV1::Refused { .. }
    ));
}

#[test]
fn fastmail_cancel_takes_uid_and_sequence_from_the_calendar_and_the_message_time() {
    let invitation = read(&fixture("fastmail-cancel"));
    assert_eq!(invitation.method, "CANCEL");
    assert_eq!(
        invitation.fields.uid,
        "b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e"
    );
    assert_eq!(invitation.fields.sequence, 3);
    assert!(!invitation.dtstamp_given);
    assert_eq!(invitation.fields.dtstamp, "2026-11-20T08:00:00Z");
    assert_eq!(
        invitation.fields.end,
        Some(TimeV1::Zoned {
            local: "2027-02-10T15:00:00".into(),
            tzid: "Europe/Istanbul".into()
        })
    );
}

#[test]
fn a_proton_reply_reads_its_attendee() {
    let invitation = read(&fixture("proton-reply"));
    assert_eq!(invitation.method, "REPLY");
    assert_eq!(invitation.attendees.len(), 1);
    assert_eq!(invitation.attendees[0].email, "visitor@proton.example");
    assert_eq!(invitation.attendees[0].partstat, Partstat::Tentative);
    assert!(!invitation.kutup_reply);
}

const MINIMAL: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:x@y\r\nDTSTAMP:20261120T080000Z\r\nDTSTART:20270101T100000Z\r\nORGANIZER:mailto:o@example.com\r\nATTENDEE:mailto:a@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[test]
fn proton_refusals() {
    assert_eq!(refusal("").0, InvitationError::NoComponent);
    assert_eq!(
        refusal("BEGIN:VCARD\r\nEND:VCARD").0,
        InvitationError::ParsingError
    );
    let method = |m: &str| MINIMAL.replace("METHOD:REQUEST", &format!("METHOD:{m}"));
    assert_eq!(
        refusal(&method("SOMETHING")).0,
        InvitationError::InvalidMethod
    );
    assert_eq!(
        refusal(&method("DECLINECOUNTER")).0,
        InvitationError::InvalidMethod
    );
    assert_eq!(
        refusal(&method("ADD")).0,
        InvitationError::InvitationUnsupported
    );
    assert_eq!(
        refusal(&method("REFRESH")).0,
        InvitationError::InvitationUnsupported
    );
    assert_eq!(
        refusal(&MINIMAL.replace("UID:x@y\r\n", "")),
        (
            InvitationError::InvitationInvalid,
            Some(EventInvitationError::MissingOriginalUid)
        )
    );
    assert_eq!(
        refusal(&MINIMAL.replace("VERSION:2.0\r\n", "VERSION:2.0\r\nCALSCALE:HEBREW\r\n")),
        (
            InvitationError::InvitationUnsupported,
            Some(EventInvitationError::NonGregorian)
        )
    );
    assert_eq!(
        refusal(
            &MINIMAL
                .replace("BEGIN:VEVENT", "BEGIN:VTODO")
                .replace("END:VEVENT", "END:VTODO")
        )
        .0,
        InvitationError::NoVevent
    );
    assert_eq!(
        refusal(&MINIMAL.replace(
            "ATTENDEE:mailto:a@example.com",
            "ATTENDEE:mailto:a@example.com\r\nATTENDEE:mailto:A@example.com"
        ))
        .1,
        Some(EventInvitationError::DuplicateAttendees)
    );
    let reply = method("REPLY").replace("ATTENDEE:mailto:a@example.com\r\n", "");
    assert_eq!(
        refusal(&reply).1,
        Some(EventInvitationError::MissingAttendee)
    );
    let tz = MINIMAL.replace(
        "DTSTART:20270101T100000Z",
        "DTSTART;TZID=Mars/Olympus:20270101T100000",
    );
    assert_eq!(
        refusal(&tz),
        (
            InvitationError::InvitationUnsupported,
            Some(EventInvitationError::TzidUnsupported)
        )
    );
    let many = InvitationOptionsV1 {
        max_attendees: 0,
        ..options()
    };
    assert!(matches!(
        read_invitation(MINIMAL, &many).unwrap(),
        InvitationOutcomeV1::Refused {
            reason: Some(EventInvitationError::TooManyAttendees),
            ..
        }
    ));
    // No ORGANIZER: the sender, for what an organizer sends.
    let guessed = read(&MINIMAL.replace("ORGANIZER:mailto:o@example.com\r\n", ""));
    assert_eq!(guessed.organizer.unwrap().email, "zeynep@fastmail.example");
    // A missing METHOD is PUBLISH, its UID kept.
    let publish = read(&MINIMAL.replace("METHOD:REQUEST\r\n", ""));
    assert_eq!(publish.method, "PUBLISH");
    assert_eq!(publish.fields.uid, "x@y");
    assert_eq!(publish.fields.organizer, None);
}

fn request() -> WriteInvitationV1 {
    let mut fields = read(&fixture("outlook-request")).fields;
    fields.uid = "e4-uid@kutup.example".into();
    fields.dtstamp = "2026-11-24T10:00:00Z".into();
    fields.organizer = Some("mailto:ali@kutup.example".into());
    WriteInvitationV1 {
        method: "REQUEST".into(),
        release: "2026.1124.0".into(),
        fields,
        organizer: PersonV1 {
            email: "ali@kutup.example".into(),
            name: Some("Ali \"the\" Kaya".into()),
        },
        attendees: vec![
            InvitedV1 {
                email: "bea@contoso.example".into(),
                name: Some("Bea\r\nX-EVIL:1".into()),
                partstat: Partstat::NeedsAction,
                optional: true,
                rsvp: true,
            },
            InvitedV1 {
                email: "can@kutup.example".into(),
                name: None,
                partstat: Partstat::Accepted,
                optional: false,
                rsvp: true,
            },
        ],
        note: None,
        kutup_reply: false,
    }
}

#[test]
fn a_written_request_reads_back_and_carries_no_line_break_injection() {
    let text = write_invitation(&request()).unwrap();
    assert!(text.starts_with(
        "BEGIN:VCALENDAR\r\nPRODID:-//Kutup//Calendar 2026.1124.0//EN\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nCALSCALE:GREGORIAN\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"
    ));
    assert!(!text.contains("\r\nX-EVIL"));
    assert!(text.contains("ORGANIZER;CN=\"Ali the Kaya\":mailto:ali@kutup.example\r\n"));
    let back = read(&text);
    assert_eq!(back.fields.uid, "e4-uid@kutup.example");
    assert_eq!(back.fields.rrule, request().fields.rrule);
    assert_eq!(back.fields.start, request().fields.start);
    assert_eq!(back.attendees.len(), 2);
    assert!(back.attendees[0].optional);
    assert_eq!(back.attendees[1].partstat, Partstat::Accepted);
    assert_eq!(back.organizer.unwrap().email, "ali@kutup.example");
}

#[test]
fn a_written_reply_carries_only_its_sender_and_the_marker() {
    let mut reply = request();
    reply.method = "REPLY".into();
    reply.attendees = vec![InvitedV1 {
        partstat: Partstat::Declined,
        ..reply.attendees[1].clone()
    }];
    reply.note = Some("Away, sorry".into());
    reply.kutup_reply = true;
    let text = write_invitation(&reply).unwrap();
    assert!(!text.contains("DESCRIPTION"));
    assert!(text.contains("ATTENDEE;PARTSTAT=DECLINED:mailto:can@kutup.example\r\n"));
    let back = read(&text);
    assert!(back.kutup_reply);
    assert_eq!(back.note.as_deref(), Some("Away, sorry"));
    assert_eq!(back.attendees.len(), 1);
    // Two answers in one reply are refused.
    let mut two = request();
    two.method = "REPLY".into();
    assert!(write_invitation(&two).is_err());
}

#[test]
fn a_written_cancel_is_cancelled_and_only_the_three_methods_are_sent() {
    let mut cancel = request();
    cancel.method = "CANCEL".into();
    cancel.fields.sequence = 1;
    let text = write_invitation(&cancel).unwrap();
    assert!(text.contains("STATUS:CANCELLED\r\n"));
    assert!(text.contains("SEQUENCE:1\r\n"));
    assert!(text.contains("ATTENDEE:mailto:bea@contoso.example\r\n"));
    let back = read(&text);
    assert_eq!(back.method, "CANCEL");
    assert_eq!(back.fields.status.as_deref(), Some("cancelled"));
    for method in ["PUBLISH", "COUNTER", "ADD"] {
        let mut other = request();
        other.method = method.into();
        assert!(write_invitation(&other).is_err());
    }
    let mut bad = request();
    bad.attendees[0].email = "Bea@contoso.example".into();
    assert!(write_invitation(&bad).is_err());
}
