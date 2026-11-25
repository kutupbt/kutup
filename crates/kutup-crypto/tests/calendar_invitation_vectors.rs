//! Checked-in vectors for invitations (docs/plans/calendar-e4.md §2–3,
//! §6): an organizer's event (the calendar vectors' calendar and owner)
//! with its attendee part, each attendee's keyed token, a Kutup invitee's
//! key packet (to the owner's own address key, so the browser check can
//! open it with the mail vectors' sealed key), a sealed answer, one token
//! from a fixed session key, and an invitation written by the iMIP writer.
//! OpenPGP output is random, so the sealed values are fixed ciphertexts
//! that must open (in Rust here and in the browser through
//! `scripts/test-crypto-wasm.mjs` and `scripts/test-calendar-ics-wasm.mjs`).
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_CALENDAR_INVITATION_VECTORS=1 cargo test -p kutup-crypto --features calendar --test calendar_invitation_vectors -- --ignored`

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::calendar::{
    open_key_packet, unlock_calendar_key, EventPartV1, Passphrase, SealedEventV1, SessionKey,
};
use kutup_crypto::calendar_event::{AttendeeV1, AttendeesPart, EventFieldsV1};
use kutup_crypto::calendar_ics::itip::{write_invitation, WriteInvitationV1};
use kutup_crypto::calendar_invitation::{
    attendee_token, invitee_key_packet, open_answer, open_attendees, seal_answer, seal_attendees,
    token_text, AnswerV1, ANSWER_VERSION,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/calendar-invitation-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    /// The organizer's event (organizer: the mail vectors' address), sealed
    /// to the calendar vectors' calendar.
    event: SealedEventV1,
    fields: serde_json::Value,
    attendees_text: String,
    attendees: EventPartV1,
    tokens: Vec<Token>,
    shared_event_id: String,
    /// The shared session key to the organizer's own address key.
    invitee_key_packet: String,
    /// The first attendee's answer, signed by the organizer (an outside
    /// reply written by its client).
    answer: String,
    answer_json: serde_json::Value,
    fixed: Fixed,
    write: Write,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Token {
    email: String,
    token: String,
}

/// A token from a fixed session key: the derivation, byte for byte.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixed {
    session_key: String,
    uid: String,
    email: String,
    token: String,
}

/// An invitation as the writer writes it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Write {
    input: serde_json::Value,
    text: String,
}

fn b64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("base64")
}

fn read(path: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn sources() -> (serde_json::Value, serde_json::Value) {
    (
        read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/calendar-v1.json"
        )),
        read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/mail-address-key-v1.json"
        )),
    )
}

fn attendees() -> Vec<AttendeeV1> {
    vec![
        AttendeeV1 {
            email: "bea@kutup.dev".into(),
            name: Some("Bea Kaya".into()),
            optional: false,
        },
        AttendeeV1 {
            email: "guest@outside.example".into(),
            name: None,
            optional: true,
        },
    ]
}

const SHARED_EVENT_ID: &str = "0b9b9a1e-2c3d-4e5f-8a6b-7c8d9e0f1a2b";

fn write_input(organizer: &str) -> serde_json::Value {
    serde_json::json!({
        "method": "REQUEST",
        "release": "2026.1124.0",
        "fields": {
            "uid": "e4-vector@kutup.dev", "dtstamp": "2026-11-24T10:00:00Z", "created": null,
            "start": { "zoned": { "local": "2026-12-10T10:00:00", "tzid": "Europe/Istanbul" } },
            "end": { "zoned": { "local": "2026-12-10T11:00:00", "tzid": "Europe/Istanbul" } },
            "recurrenceId": null, "rrule": "FREQ=WEEKLY;COUNT=3", "organizer": format!("mailto:{organizer}"),
            "sequence": 1, "summary": "Planlama; oda 4", "description": "Gündem:\nbütçe", "location": "Oda 4",
            "status": "confirmed", "transp": "opaque", "comment": null
        },
        "organizer": { "email": organizer, "name": "Alice" },
        "attendees": [
            { "email": "bea@kutup.dev", "name": "Bea Kaya", "partstat": "accepted", "optional": false, "rsvp": true },
            { "email": "guest@outside.example", "partstat": "needs-action", "optional": true, "rsvp": true }
        ]
    })
}

#[test]
#[ignore = "writes the vectors"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_CALENDAR_INVITATION_VECTORS").is_err() {
        return;
    }
    let (calendar, mail) = sources();
    let passphrase =
        Passphrase::from_text(calendar["passphrase"].as_str().unwrap().as_bytes()).unwrap();
    let unlocked = unlock_calendar_key(
        &b64(calendar["calendarLockedSecretKey"].as_str().unwrap()),
        &passphrase,
    )
    .unwrap();
    let owner_secret = b64(mail["secretKey"].as_str().unwrap());
    let owner_public = b64(mail["publicKey"].as_str().unwrap());
    let organizer = mail["address"].as_str().unwrap();
    let mut fields: EventFieldsV1 = serde_json::from_value(calendar["fields"].clone()).unwrap();
    fields.organizer = Some(format!("mailto:{organizer}"));
    let event = unlocked
        .seal_event(&fields.to_parts().unwrap(), &owner_secret, None, None)
        .unwrap();
    let shared = unlocked.open_key_packet(&event.shared_key_packet).unwrap();
    let part = AttendeesPart {
        uid: fields.uid.clone(),
        attendees: attendees(),
    };
    let sealed = seal_attendees(&part, &shared, &owner_secret).unwrap();
    let tokens = attendees()
        .iter()
        .map(|a| Token {
            email: a.email.clone(),
            token: token_text(&attendee_token(&shared, &fields.uid, &a.email).unwrap()),
        })
        .collect::<Vec<_>>();
    let answer = AnswerV1 {
        v: ANSWER_VERSION,
        shared_event_id: SHARED_EVENT_ID.into(),
        token: tokens[0].token.clone(),
        partstat: "tentative".into(),
        note: Some("Geç kalabilirim".into()),
        updated_at: "2026-11-24T10:00:00Z".into(),
    };
    let sealed_answer = seal_answer(&answer, &shared, &owner_secret).unwrap();
    let fixed_key = SessionKey::from_bytes(&[0x11; 32]).unwrap();
    let input = write_input(organizer);
    let text =
        write_invitation(&serde_json::from_value::<WriteInvitationV1>(input.clone()).unwrap())
            .unwrap();
    let vectors = Vectors {
        event: SealedEventV1::of(&event),
        fields: serde_json::to_value(&fields).unwrap(),
        attendees_text: part.build().unwrap(),
        attendees: EventPartV1::of(&sealed),
        tokens,
        shared_event_id: SHARED_EVENT_ID.into(),
        invitee_key_packet: STANDARD.encode(invitee_key_packet(&shared, &owner_public).unwrap()),
        answer: STANDARD.encode(sealed_answer),
        answer_json: serde_json::to_value(&answer).unwrap(),
        fixed: Fixed {
            session_key: STANDARD.encode([0x11; 32]),
            uid: "e4-vector@kutup.dev".into(),
            email: "Bea@Kutup.dev".into(),
            token: token_text(
                &attendee_token(&fixed_key, "e4-vector@kutup.dev", "Bea@Kutup.dev").unwrap(),
            ),
        },
        write: Write { input, text },
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn invitation_vectors_open_as_written() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let (calendar, mail) = sources();
    let passphrase =
        Passphrase::from_text(calendar["passphrase"].as_str().unwrap().as_bytes()).unwrap();
    let unlocked = unlock_calendar_key(
        &b64(calendar["calendarLockedSecretKey"].as_str().unwrap()),
        &passphrase,
    )
    .unwrap();
    let owner_secret = b64(mail["secretKey"].as_str().unwrap());
    let owner_public = b64(mail["publicKey"].as_str().unwrap());
    let event = v.event.to_event().unwrap();
    let opened = unlocked
        .open_event(&event, &[owner_public.as_slice()])
        .unwrap();
    assert!(opened.verified);
    assert_eq!(
        serde_json::to_value(EventFieldsV1::of(&opened.parts)).unwrap(),
        v.fields
    );
    let shared = unlocked.open_key_packet(&event.shared_key_packet).unwrap();
    let uid = &opened.parts.shared_signed.uid;
    // The attendee part: its one form, for its event, signed by the organizer.
    let (part, verified) = open_attendees(
        &v.attendees.to_part().unwrap(),
        &shared,
        uid,
        &[owner_public.as_slice()],
    )
    .unwrap();
    assert!(verified);
    assert_eq!(part.attendees, attendees());
    assert_eq!(part.build().unwrap(), v.attendees_text);
    // Every attendee's token, derived again.
    for token in &v.tokens {
        assert_eq!(
            token_text(&attendee_token(&shared, uid, &token.email).unwrap()),
            token.token
        );
    }
    // The invitee's key packet carries the same shared session key.
    let carried = open_key_packet(&b64(&v.invitee_key_packet), &owner_secret).unwrap();
    assert_eq!(carried.as_bytes(), shared.as_bytes());
    // The answer: for its row and event, signed by the organizer.
    let token: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&v.tokens[0].token)
        .unwrap()
        .try_into()
        .unwrap();
    let (answer, verified) = open_answer(
        &b64(&v.answer),
        &shared,
        &v.shared_event_id,
        &token,
        &[owner_public.as_slice()],
    )
    .unwrap();
    assert!(verified);
    assert_eq!(serde_json::to_value(&answer).unwrap(), v.answer_json);
    let other: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&v.tokens[1].token)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(open_answer(&b64(&v.answer), &shared, &v.shared_event_id, &other, &[]).is_err());
    // A token from a fixed key, byte for byte.
    let fixed = SessionKey::from_bytes(&b64(&v.fixed.session_key)).unwrap();
    assert_eq!(
        token_text(&attendee_token(&fixed, &v.fixed.uid, &v.fixed.email).unwrap()),
        v.fixed.token
    );
    // The writer's one form.
    let input: WriteInvitationV1 = serde_json::from_value(v.write.input.clone()).unwrap();
    assert_eq!(write_invitation(&input).unwrap(), v.write.text);
}
