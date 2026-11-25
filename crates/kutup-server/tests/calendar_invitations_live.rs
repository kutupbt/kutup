//! Calendar invitations (docs/plans/calendar-e4.md) against a live server:
//! an organizer's attendee rows and Kutup invitees, who may write which
//! answer, the invitations a Kutup attendee lists and adopts, an update
//! that keeps every attendee's copy and answer, removals and deletes that
//! give back what each held, and the account's invitation settings. Needs
//! `KUTUP_LIVE_SERVER`. The client side is the Rust core, as the browser
//! runs it through WASM.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

use kutup_crypto::calendar::{
    self as cal, EventPartV1, Passphrase, SealedEventV1, SealedMetadataV1, SessionKey,
    UnlockedCalendarKey, FIRST_KEY_GENERATION,
};
use kutup_crypto::calendar_event::{
    AttendeeV1, AttendeesPart, CalendarSigned, EventFieldsV1, TimeV1,
};
use kutup_crypto::calendar_invitation::{self as inv, AnswerV1, ANSWER_VERSION};
use kutup_crypto::mail_key::{self, MailKeyEntryV1, MailKeyListV1, DEFAULT_FLAGS};

mod common;
use common::*;

struct Person {
    user: User,
    address_id: String,
    address: String,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

/// A user with an address key, as the Account app sets one up.
fn person(c: &Client, base: &str) -> Person {
    let user = register(c, base);
    let addresses: Value = bearer(c.get(format!("{base}/api/v1/mail/addresses")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let id = addresses[0]["id"].as_str().unwrap().to_string();
    let address = addresses[0]["address"].as_str().unwrap().to_string();
    let key = mail_key::generate_address_key(&address, 1_790_000_000).unwrap();
    let envelope = mail_key::seal_address_key(
        &user.master_key,
        kutup_crypto::account_record::MasterKeyGeneration::FIRST,
        &user.binding,
        &address,
        &key.secret_key,
    )
    .unwrap();
    let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
    let list = MailKeyListV1 {
        incarnation_id: hex32(user.identity.incarnation_id()),
        authority_key_id: hex32(user.identity.authority_key_id()),
        address: address.clone(),
        sequence: 1,
        previous_hash: None,
        issued_at: "2026-10-21T12:00:00Z".into(),
        keys: vec![MailKeyEntryV1::v4(
            key.fingerprint,
            key.sha256_fingerprint,
            true,
            DEFAULT_FLAGS,
        )],
    }
    .sign(user.identity.authority_signing_key())
    .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/v1/mail/addresses/{id}/keys")),
        &user.token,
    )
    .json(&json!({
        "publicKey": b64(&key.public_key),
        "privateKeyEnvelope": b64(&envelope),
        "keyList": { "data": b64(&list.data), "signature": b64(&list.signature) },
    }))
    .send()
    .unwrap();
    assert!(r.status().is_success(), "add key: {}", r.status());
    Person {
        user,
        address_id: id,
        address,
        secret_key: key.secret_key.to_vec(),
        public_key: key.public_key,
    }
}

/// A calendar of `owner`'s: its id and key.
fn calendar(c: &Client, base: &str, owner: &Person) -> (String, UnlockedCalendarKey) {
    let id = uuid::Uuid::new_v4();
    let passphrase = Passphrase::generate();
    let key = cal::generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let share = cal::seal_own_passphrase(
        &passphrase,
        &id.to_string(),
        FIRST_KEY_GENERATION,
        &owner.user.person,
        &owner.user.identity,
    )
    .unwrap();
    let metadata = key
        .unlocked
        .seal_metadata(&id.to_string(), "Work", "", &owner.secret_key)
        .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/v1/calendar/calendars")),
        &owner.user.token,
    )
    .json(&json!({
        "id": id,
        "publicKey": b64(&key.public_key),
        "lockedSecretKey": b64(&key.locked_secret_key),
        "passphraseShare": share.encode_b64().unwrap(),
        "metadata": SealedMetadataV1::of(&metadata),
    }))
    .send()
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        r.text().unwrap_or_default()
    );
    (id.to_string(), key.unlocked)
}

fn fields(uid: &str, organizer: Option<&str>, start: &str, sequence: u32) -> EventFieldsV1 {
    EventFieldsV1 {
        uid: uid.into(),
        dtstamp: "2026-11-24T08:00:00Z".into(),
        created: None,
        start: TimeV1::Zoned {
            local: start.into(),
            tzid: "Europe/Istanbul".into(),
        },
        end: None,
        recurrence_id: None,
        rrule: None,
        exdates: Vec::new(),
        organizer: organizer.map(|address| format!("mailto:{address}")),
        sequence,
        summary: Some("Planning".into()),
        description: None,
        location: None,
        status: Some("confirmed".into()),
        transp: Some("opaque".into()),
        comment: None,
        other: Vec::new(),
        signed_other: Vec::new(),
        calendar_other: Vec::new(),
        comment_other: Vec::new(),
    }
}

/// An organizer's invitation, sealed as `sealInvitation` seals it: the
/// event (under `previous`'s keys when given), the attendee part, the rows
/// and each Kutup invitee's key packet.
struct Sealed {
    event: Value,
    invitation: Value,
    shared: SessionKey,
    sealed: cal::SealedEvent,
}

fn seal_invitation(
    calendar: &UnlockedCalendarKey,
    organizer: &Person,
    fields: &EventFieldsV1,
    attendees: &[AttendeeV1],
    invitees: &[(&str, &[u8])],
    previous: Option<&cal::SealedEvent>,
) -> Sealed {
    let parts = fields.to_parts().unwrap();
    let sealed = match previous {
        Some(previous) => calendar
            .seal_event_keeping(&parts, &organizer.secret_key, previous)
            .unwrap(),
        None => calendar
            .seal_event(&parts, &organizer.secret_key, None, None)
            .unwrap(),
    };
    let shared = calendar.open_key_packet(&sealed.shared_key_packet).unwrap();
    let part = inv::seal_attendees(
        &AttendeesPart {
            uid: fields.uid.clone(),
            attendees: attendees.to_vec(),
        },
        &shared,
        &organizer.secret_key,
    )
    .unwrap();
    let token =
        |email: &str| inv::token_text(&inv::attendee_token(&shared, &fields.uid, email).unwrap());
    let invitation = json!({
        "attendees": EventPartV1::of(&part),
        "rows": attendees.iter().map(|a| json!({ "token": token(&a.email), "optional": a.optional })).collect::<Vec<_>>(),
        "invitees": invitees.iter().map(|(address, key)| json!({
            "address": address,
            "keyPacket": b64(&inv::invitee_key_packet(&shared, key).unwrap()),
            "token": token(address),
        })).collect::<Vec<_>>(),
    });
    Sealed {
        event: serde_json::to_value(SealedEventV1::of(&sealed)).unwrap(),
        invitation,
        shared,
        sealed,
    }
}

fn sync(c: &Client, base: &str, who: &Person, calendar: &str, change: Value) -> Value {
    let r = bearer(
        c.post(format!(
            "{base}/api/v1/calendar/calendars/{calendar}/events/sync"
        )),
        &who.user.token,
    )
    .json(&json!({ "addressId": who.address_id, "changes": [change] }))
    .send()
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        r.text().unwrap_or_default()
    );
    r.json::<Value>().unwrap()["results"][0].clone()
}

#[allow(clippy::too_many_arguments)]
fn answer(
    c: &Client,
    base: &str,
    who: &Person,
    shared_event: &str,
    shared: &SessionKey,
    email: &str,
    uid: &str,
    partstat: &str,
    at: &str,
) -> StatusCode {
    let token = inv::attendee_token(shared, uid, email).unwrap();
    let sealed = inv::seal_answer(
        &AnswerV1 {
            v: ANSWER_VERSION,
            shared_event_id: shared_event.into(),
            token: inv::token_text(&token),
            partstat: partstat.into(),
            note: None,
            updated_at: at.into(),
        },
        shared,
        &who.secret_key,
    )
    .unwrap();
    bearer(
        c.put(format!(
            "{base}/api/v1/calendar/shared-events/{shared_event}/attendees/{}",
            inv::token_text(&token)
        )),
        &who.user.token,
    )
    .json(&json!({ "answer": b64(&sealed), "updatedAt": at }))
    .send()
    .unwrap()
    .status()
}

fn invitations(c: &Client, base: &str, who: &Person) -> Vec<Value> {
    let r = bearer(
        c.get(format!("{base}/api/v1/calendar/invitations/events")),
        &who.user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json::<Value>().unwrap()["events"]
        .as_array()
        .unwrap()
        .clone()
}

fn storage(c: &Client, base: &str, user: &User) -> i64 {
    let usage: Value = bearer(c.get(format!("{base}/api/v1/account/storage")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    usage["calendar"]["bytes"].as_i64().unwrap()
}

fn drop_calendar(c: &Client, base: &str, who: &Person, id: &str) {
    let r = bearer(
        c.delete(format!("{base}/api/v1/calendar/calendars/{id}")),
        &who.user.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
}

fn stored_answer(view: &Value, token: &str) -> Value {
    view["attendeeRows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["token"] == token)
        .map(|row| row["answer"].clone())
        .unwrap_or(Value::Null)
}

#[test]
fn invitations_between_kutup_users() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = common::client();
    let ada = person(&c, &base);
    let bea = person(&c, &base);
    let cem = person(&c, &base);
    let outside = "guest@outside.example";
    let (ada_cal, ada_key) = calendar(&c, &base, &ada);
    let (bea_cal, bea_key) = calendar(&c, &base, &bea);

    let uid = format!("{}@kutup.test", uuid::Uuid::new_v4());
    let attendees = vec![
        AttendeeV1 {
            email: bea.address.to_lowercase(),
            name: Some("Bea".into()),
            optional: false,
        },
        AttendeeV1 {
            email: outside.into(),
            name: None,
            optional: true,
        },
    ];
    let bea_address = bea.address.to_lowercase();
    let invitees: Vec<(&str, &[u8])> = vec![(bea_address.as_str(), bea.public_key.as_slice())];
    let first = fields(
        &uid,
        Some(&ada.address.to_lowercase()),
        "2026-12-10T10:00:00",
        0,
    );

    // Refused: an organizer that isn't the signing address reaching
    // invitees; a key packet to another key; an address no one holds here;
    // an event with an organizer and no attendees, or the other way round.
    let forged = seal_invitation(
        &ada_key,
        &ada,
        &fields(&uid, Some("boss@outside.example"), "2026-12-10T10:00:00", 0),
        &attendees,
        &invitees,
        None,
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": forged.event, "invitation": forged.invitation } }),
    );
    assert_eq!(
        (r["status"].as_u64(), r["code"].as_str()),
        (Some(400), Some("organizerNotAuthor"))
    );
    let wrong_key = seal_invitation(
        &ada_key,
        &ada,
        &first,
        &attendees,
        &[(bea_address.as_str(), cem.public_key.as_slice())],
        None,
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": wrong_key.event, "invitation": wrong_key.invitation } }),
    );
    assert_eq!(r["code"], "inviteeKey");
    let nobody = seal_invitation(
        &ada_key,
        &ada,
        &first,
        &attendees,
        &[(outside, bea.public_key.as_slice())],
        None,
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": nobody.event, "invitation": nobody.invitation } }),
    );
    assert_eq!(r["code"], "inviteeUnknown");
    let bare = seal_invitation(&ada_key, &ada, &first, &attendees, &[], None);
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": bare.event } }),
    );
    assert_eq!(r["code"], "invitationMismatch");

    // The invitation: two attendee rows, Bea's invitee row.
    let sealed = seal_invitation(&ada_key, &ada, &first, &attendees, &invitees, None);
    let id = uuid::Uuid::new_v4().to_string();
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "create": { "id": id, "event": sealed.event, "invitation": sealed.invitation } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    let view = &r["event"];
    assert_eq!(view["sharedEventId"], id.as_str());
    assert_eq!(view["home"], true);
    assert!(view["attendees"]["data"].is_string());
    assert_eq!(view["attendeeRows"].as_array().unwrap().len(), 2);
    let bea_token =
        inv::token_text(&inv::attendee_token(&sealed.shared, &uid, &bea_address).unwrap());
    let outside_token =
        inv::token_text(&inv::attendee_token(&sealed.shared, &uid, outside).unwrap());

    // Bea's invitations: the shared session key to her address key, her token.
    let listed = invitations(&c, &base, &bea);
    let mine = listed
        .iter()
        .find(|e| e["uid"] == uid.as_str())
        .expect("listed");
    assert_eq!(mine["token"], bea_token.as_str());
    assert_eq!(mine["copies"].as_array().unwrap().len(), 0);
    let opened = cal::open_key_packet(
        &decode(mine["keyPacket"].as_str().unwrap()),
        &bea.secret_key,
    )
    .unwrap();
    assert_eq!(opened.as_bytes(), sealed.shared.as_bytes());
    assert!(invitations(&c, &base, &cem)
        .iter()
        .all(|e| e["uid"] != uid.as_str()));

    // Answers: Bea her own row only; the organizer any; Cem none.
    assert_eq!(
        answer(
            &c,
            &base,
            &bea,
            &id,
            &opened,
            &bea_address,
            &uid,
            "accepted",
            "2026-11-24T09:00:00Z"
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        answer(
            &c,
            &base,
            &bea,
            &id,
            &opened,
            outside,
            &uid,
            "declined",
            "2026-11-24T09:00:00Z"
        ),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        answer(
            &c,
            &base,
            &cem,
            &id,
            &opened,
            &bea_address,
            &uid,
            "declined",
            "2026-11-24T09:00:00Z"
        ),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        answer(
            &c,
            &base,
            &ada,
            &id,
            &sealed.shared,
            outside,
            &uid,
            "tentative",
            "2026-11-24T09:30:00Z"
        ),
        StatusCode::NO_CONTENT
    );
    // An older answer than the one stored is refused.
    assert_eq!(
        answer(
            &c,
            &base,
            &ada,
            &id,
            &sealed.shared,
            outside,
            &uid,
            "accepted",
            "2026-11-24T09:00:00Z"
        ),
        StatusCode::CONFLICT
    );

    // Bea adopts it into her calendar: her copy, signed by her, charged to her.
    let bea_before = storage(&c, &base, &bea.user);
    let row = inv::adopt(
        &bea_key,
        &opened,
        &uid,
        &CalendarSigned {
            uid: uid.clone(),
            dtstamp: "2026-11-24T09:00:00Z".parse().unwrap(),
            exdates: Vec::new(),
            status: None,
            transp: None,
            other: Vec::new(),
        },
        None,
        &bea.secret_key,
    )
    .unwrap();
    let adopt = |who: &Person, calendar: &str, copy: &str| {
        bearer(
            c.post(format!(
                "{base}/api/v1/calendar/calendars/{calendar}/events/adopt"
            )),
            &who.user.token,
        )
        .json(&json!({
            "id": copy,
            "sharedEventId": id,
            "addressId": who.address_id,
            "sharedKeyPacket": b64(&row.shared_key_packet),
            "calendarKeyPacket": b64(&row.calendar_key_packet),
            "calendarSigned": EventPartV1::of(&row.calendar_signed),
        }))
        .send()
        .unwrap()
    };
    // Not into the organizer's calendar, nor by someone not invited.
    let copy = uuid::Uuid::new_v4().to_string();
    assert_eq!(adopt(&bea, &ada_cal, &copy).status(), StatusCode::NOT_FOUND);
    assert_eq!(adopt(&cem, &bea_cal, &copy).status(), StatusCode::NOT_FOUND);
    let r = adopt(&bea, &bea_cal, &copy);
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        r.text().unwrap_or_default()
    );
    let copy_view: Value = r.json().unwrap();
    assert_eq!(copy_view["home"], false);
    assert_eq!(copy_view["calendarAuthorAddress"], bea.address.as_str());
    let opened_copy = bea_key
        .open_event_by(
            &SealedEventV1::deserialize_value(&copy_view["event"])
                .to_event()
                .unwrap(),
            &[ada.public_key.as_slice()],
            &[bea.public_key.as_slice()],
        )
        .unwrap();
    assert!(opened_copy.verified);
    assert!(storage(&c, &base, &bea.user) > bea_before);
    // A retry answers the same copy; a second copy is refused.
    assert_eq!(adopt(&bea, &bea_cal, &copy).status(), StatusCode::OK);
    assert_eq!(
        adopt(&bea, &bea_cal, &uuid::Uuid::new_v4().to_string()).status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        invitations(&c, &base, &bea)
            .iter()
            .find(|e| e["uid"] == uid.as_str())
            .unwrap()["copies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The organizer changes the title (not the time): in place, every copy
    // and answer kept.
    let mut retitled = first.clone();
    retitled.summary = Some("Planning, room 4".into());
    let update = seal_invitation(
        &ada_key,
        &ada,
        &retitled,
        &attendees,
        &invitees,
        Some(&sealed.sealed),
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "update": { "id": id, "baseRevision": 1, "event": update.event, "invitation": update.invitation } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    assert!(!stored_answer(&r["event"], &bea_token).is_null());
    let r = bearer(
        c.get(format!(
            "{base}/api/v1/calendar/calendars/{bea_cal}/events/{copy}"
        )),
        &bea.user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let copy_view: Value = r.json().unwrap();
    let shared = bea_key
        .open_event_by(
            &SealedEventV1::deserialize_value(&copy_view["event"])
                .to_event()
                .unwrap(),
            &[ada.public_key.as_slice()],
            &[bea.public_key.as_slice()],
        )
        .unwrap();
    assert_eq!(
        shared.parts.shared_encrypted.summary.as_deref(),
        Some("Planning, room 4")
    );

    // A member of the calendar who isn't the organizer can't change it, and
    // Bea can't change the organizer's event through her copy.
    let r = sync(
        &c,
        &base,
        &bea,
        &bea_cal,
        json!({ "update": { "id": copy, "baseRevision": 1, "event": update.event, "invitation": update.invitation } }),
    );
    assert_ne!(r["status"], 200);

    // Moved (SEQUENCE + 1), every answer is asked again.
    let moved = fields(
        &uid,
        Some(&ada.address.to_lowercase()),
        "2026-12-11T10:00:00",
        1,
    );
    let mut moved_inv = seal_invitation(
        &ada_key,
        &ada,
        &moved,
        &attendees,
        &invitees,
        Some(&update.sealed),
    );
    moved_inv.invitation["resetAnswers"] = json!(true);
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "update": { "id": id, "baseRevision": 2, "event": moved_inv.event, "invitation": moved_inv.invitation } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    assert!(stored_answer(&r["event"], &bea_token).is_null());
    assert!(stored_answer(&r["event"], &outside_token).is_null());

    // Bea removed: her invitee row and her copy go, what it held comes back.
    let only_outside = vec![attendees[1].clone()];
    let removed = seal_invitation(
        &ada_key,
        &ada,
        &moved,
        &only_outside,
        &[],
        Some(&moved_inv.sealed),
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "update": { "id": id, "baseRevision": 3, "event": removed.event, "invitation": removed.invitation } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    assert!(invitations(&c, &base, &bea)
        .iter()
        .all(|e| e["uid"] != uid.as_str()));
    let r = bearer(
        c.get(format!(
            "{base}/api/v1/calendar/calendars/{bea_cal}/events/{copy}"
        )),
        &bea.user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(storage(&c, &base, &bea.user), bea_before);
    assert_eq!(
        answer(
            &c,
            &base,
            &bea,
            &id,
            &opened,
            &bea_address,
            &uid,
            "accepted",
            "2026-11-24T10:00:00Z"
        ),
        StatusCode::NOT_FOUND
    );

    // Invited again and adopted, then the organizer deletes the event:
    // Bea's copy goes with it, and her calendar holds nothing.
    let again = seal_invitation(
        &ada_key,
        &ada,
        &moved,
        &attendees,
        &invitees,
        Some(&removed.sealed),
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "update": { "id": id, "baseRevision": 4, "event": again.event, "invitation": again.invitation } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    let copy = uuid::Uuid::new_v4().to_string();
    assert_eq!(adopt(&bea, &bea_cal, &copy).status(), StatusCode::OK);

    // Security review H1: in one calendar every event with a UID comes from
    // one home, so Bea's own event can't take the invitation's UID there.
    let own = seal_invitation(
        &bea_key,
        &bea,
        &fields(&uid, None, "2026-12-11T10:00:00", 0),
        &[],
        &[],
        None,
    );
    let r = sync(
        &c,
        &base,
        &bea,
        &bea_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": own.event } }),
    );
    assert_eq!((r["status"].as_u64(), r["code"].as_str()), (Some(409), Some("uidTaken")), "{r}");

    // Security review M4: an import overwriting the invitation would strip
    // its attendees and their copies: refused.
    let import = seal_invitation(
        &ada_key,
        &ada,
        &fields(&uid, None, "2026-12-12T10:00:00", 0),
        &[],
        &[],
        None,
    );
    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": import.event, "overwrite": true } }),
    );
    assert_eq!(r["code"], "invitationOverwrite", "{r}");

    // Security review M5: Bea leaves; her copy, its storage and her invitee
    // row go, and the invitation is no longer listed for her.
    let leave = |who: &Person| {
        bearer(
            c.delete(format!("{base}/api/v1/calendar/invitations/events/{id}")),
            &who.user.token,
        )
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(leave(&cem), StatusCode::NOT_FOUND);
    assert_eq!(leave(&bea), StatusCode::NO_CONTENT);
    assert_eq!(storage(&c, &base, &bea.user), bea_before);
    assert!(invitations(&c, &base, &bea)
        .iter()
        .all(|e| e["uid"] != uid.as_str()));
    assert_eq!(leave(&bea), StatusCode::NOT_FOUND);

    let r = sync(
        &c,
        &base,
        &ada,
        &ada_cal,
        json!({ "delete": { "id": id, "baseRevision": 5 } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    assert_eq!(storage(&c, &base, &bea.user), bea_before);
    assert!(invitations(&c, &base, &bea)
        .iter()
        .all(|e| e["uid"] != uid.as_str()));

    drop_calendar(&c, &base, &ada, &ada_cal);
    drop_calendar(&c, &base, &bea, &bea_cal);
    assert_eq!(storage(&c, &base, &ada.user), 0);
    assert_eq!(storage(&c, &base, &bea.user), 0);
}

#[test]
fn an_outside_invitation_kept_by_its_attendee_and_the_settings() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = common::client();
    let bea = person(&c, &base);
    let (bea_cal, bea_key) = calendar(&c, &base, &bea);
    // An outside organizer's invitation kept as Bea's own event: allowed,
    // with its attendee list, but it reaches no Kutup invitee.
    let uid = "040000008200E00074C5B7101A82E008@outlook.example";
    let kept = fields(uid, Some("jana@contoso.example"), "2027-01-04T10:00:00", 2);
    let attendees = vec![AttendeeV1 {
        email: bea.address.to_lowercase(),
        name: None,
        optional: false,
    }];
    let sealed = seal_invitation(&bea_key, &bea, &kept, &attendees, &[], None);
    let id = uuid::Uuid::new_v4().to_string();
    let r = sync(
        &c,
        &base,
        &bea,
        &bea_cal,
        json!({ "create": { "id": id, "event": sealed.event, "invitation": sealed.invitation } }),
    );
    assert_eq!(r["status"], 200, "{r}");
    // Her own answer, written as the calendar's owner.
    assert_eq!(
        answer(
            &c,
            &base,
            &bea,
            &id,
            &sealed.shared,
            &bea.address.to_lowercase(),
            uid,
            "accepted",
            "2026-11-24T09:00:00Z"
        ),
        StatusCode::NO_CONTENT
    );
    let other = person(&c, &base);
    let reaching = seal_invitation(
        &bea_key,
        &bea,
        &kept,
        &attendees,
        &[(other.address.as_str(), other.public_key.as_slice())],
        None,
    );
    let r = sync(
        &c,
        &base,
        &bea,
        &bea_cal,
        json!({ "create": { "id": uuid::Uuid::new_v4(), "event": reaching.event, "invitation": reaching.invitation } }),
    );
    assert_eq!(r["code"], "organizerNotAuthor");

    // The account's invitation settings: Proton's defaults, then changed.
    let get = || -> Value {
        bearer(
            c.get(format!("{base}/api/v1/calendar/settings/invitations")),
            &bea.user.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap()
    };
    assert_eq!(get(), json!({ "inviteLocale": null, "autoAdd": true }));
    let put = |body: Value| {
        bearer(
            c.put(format!("{base}/api/v1/calendar/settings/invitations")),
            &bea.user.token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(
        put(json!({ "inviteLocale": "tr", "autoAdd": false })),
        StatusCode::OK
    );
    assert_eq!(get(), json!({ "inviteLocale": "tr", "autoAdd": false }));
    assert_eq!(
        put(json!({ "inviteLocale": "de", "autoAdd": false })),
        StatusCode::BAD_REQUEST
    );

    // The site's limits are published.
    let settings: Value = c
        .get(format!("{base}/api/v1/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(settings["calendar"]["attendeesPerEvent"], 100);
    assert_eq!(settings["calendar"]["invitationCountMax"], 499);
    // Busy times of an address no one holds: unknown, not an error.
    let busy: Value = bearer(
        c.get(format!("{base}/api/v1/calendar/busy?address=nobody%40outside.example&start=2026-12-01T00:00:00Z&end=2026-12-02T00:00:00Z")),
        &bea.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(busy["accessible"], false);

    drop_calendar(&c, &base, &bea, &bea_cal);
    assert_eq!(storage(&c, &base, &bea.user), 0);
}

fn decode(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

trait FromValue {
    fn deserialize_value(value: &Value) -> Self;
}

impl FromValue for SealedEventV1 {
    fn deserialize_value(value: &Value) -> Self {
        serde_json::from_value(value.clone()).unwrap()
    }
}
