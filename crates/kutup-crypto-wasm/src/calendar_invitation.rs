//! Invitations in the browser (docs/plans/calendar-e4.md §3, §6), over
//! `kutup_crypto::calendar_invitation`. The event's shared session key
//! never leaves WASM: the organizer's side works through the
//! `UnlockedCalendar` that holds the event, an attendee's through an
//! [`OpenedInvitationJs`] opened with their address key, and JavaScript gets
//! back only what the server stores (sealed parts, key packets, tokens,
//! sealed answers) and what the person reads.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use kutup_crypto::calendar::{EventPartV1, SealedEventV1, SessionKey};
use kutup_crypto::calendar_event::{
    canonical_email, AttendeeV1, AttendeesPart, CalendarEncrypted, CalendarSigned, EventFieldsV1,
    EventParts, Status, TimeV1, Transp,
};
use kutup_crypto::calendar_invitation::{
    self as invitation, attendee_token, token_text, AnswerV1, ANSWER_VERSION, TOKEN_LEN,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::calendar::{crypto_error, from_js, public_keys, to_js, UnlockedCalendarJs};
use crate::{decode_canonical_base64, js_error, open_mail_secret};

/// An address key as the browser holds it, sealed (`SealedMailKey`): WASM
/// opens it for one call.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyIn {
    master_keys: String,
    binding: String,
    address: String,
    envelope: String,
    fingerprint: String,
}

impl KeyIn {
    fn open(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, JsValue> {
        open_mail_secret(
            &self.master_keys,
            &self.binding,
            &self.address,
            &self.envelope,
            &self.fingerprint,
        )
    }
}

fn keys_of(keys: Vec<String>) -> Result<Vec<Vec<u8>>, JsValue> {
    public_keys(&keys)
}

fn slices(keys: &[Vec<u8>]) -> Vec<&[u8]> {
    keys.iter().map(Vec::as_slice).collect()
}

/// A Kutup attendee the event reaches at once: their address and its
/// public key (checked by the caller against the pinned key list).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InviteeIn {
    address: String,
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenOut {
    email: String,
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteeOut {
    address: String,
    key_packet: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedInvitation {
    event: SealedEventV1,
    attendees: Option<EventPartV1>,
    tokens: Vec<TokenOut>,
    invitees: Vec<InviteeOut>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedWith {
    fields: EventFieldsV1,
    verified: bool,
    attendees: Option<Vec<AttendeeV1>>,
    attendees_verified: bool,
    tokens: Vec<TokenOut>,
}

/// One answer row as the server lists it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AnswerRowIn {
    token: String,
    #[serde(default)]
    answer: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnswerOut {
    token: String,
    /// None: no answer yet, or one that doesn't open for this row.
    answer: Option<AnswerV1>,
    verified: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedAnswerOut {
    token: String,
    answer: String,
}

fn tokens_for(
    key: &SessionKey,
    uid: &str,
    attendees: &[AttendeeV1],
) -> Result<Vec<TokenOut>, JsValue> {
    attendees
        .iter()
        .map(|attendee| {
            Ok(TokenOut {
                email: attendee.email.clone(),
                token: token_text(
                    &attendee_token(key, uid, &attendee.email).map_err(crypto_error)?,
                ),
            })
        })
        .collect()
}

fn token_bytes(text: &str) -> Result<[u8; TOKEN_LEN], JsValue> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| js_error("a token is 32 bytes, base64url"))
}

fn open_rows(
    key: &SessionKey,
    shared_event_id: &str,
    rows: Vec<AnswerRowIn>,
    signers: &[&[u8]],
) -> Result<Vec<AnswerOut>, JsValue> {
    rows.into_iter()
        .map(|row| {
            let token = token_bytes(&row.token)?;
            let opened = row
                .answer
                .as_deref()
                .and_then(|answer| STANDARD.decode(answer).ok())
                .and_then(|answer| {
                    invitation::open_answer(&answer, key, shared_event_id, &token, signers).ok()
                });
            Ok(AnswerOut {
                token: row.token,
                verified: opened.as_ref().is_some_and(|(_, verified)| *verified),
                answer: opened.map(|(answer, _)| answer),
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn seal_answer_with(
    key: &SessionKey,
    signer: &KeyIn,
    uid: &str,
    shared_event_id: &str,
    email: &str,
    partstat: &str,
    note: Option<String>,
    updated_at: &str,
) -> Result<JsValue, JsValue> {
    let token = attendee_token(key, uid, email).map_err(crypto_error)?;
    let answer = AnswerV1 {
        v: ANSWER_VERSION,
        shared_event_id: shared_event_id.to_owned(),
        token: token_text(&token),
        partstat: partstat.to_owned(),
        note: note.filter(|note| !note.is_empty()),
        updated_at: updated_at.to_owned(),
    };
    let sealed = invitation::seal_answer(&answer, key, &signer.open()?).map_err(crypto_error)?;
    to_js(&SealedAnswerOut {
        token: answer.token,
        answer: STANDARD.encode(sealed),
    })
}

fn attendee_list(value: JsValue) -> Result<Vec<AttendeeV1>, JsValue> {
    let mut list: Vec<AttendeeV1> = from_js(value, "attendees")?;
    for attendee in &mut list {
        attendee.email = canonical_email(&attendee.email);
    }
    Ok(list)
}

#[wasm_bindgen(js_class = UnlockedCalendar)]
impl UnlockedCalendarJs {
    /// Seals an event the organizer invites people to: its parts (under the
    /// session keys of `previous`, the stored event, when it is a change),
    /// the attendee part, each attendee's token, and the shared session key
    /// to each Kutup invitee's address key. No attendees: an ordinary
    /// event, its attendee part null.
    #[wasm_bindgen(js_name = sealInvitation)]
    pub fn seal_invitation(
        &self,
        author: JsValue,
        fields: JsValue,
        attendees: JsValue,
        invitees: JsValue,
        previous: JsValue,
    ) -> Result<JsValue, JsValue> {
        let author: KeyIn = from_js(author, "author key")?;
        let secret = author.open()?;
        let fields: EventFieldsV1 = from_js(fields, "event fields")?;
        let attendees = attendee_list(attendees)?;
        let invitees: Vec<InviteeIn> = from_js(invitees, "invitees")?;
        let previous: Option<SealedEventV1> = from_js(previous, "previous event")?;
        let parts: EventParts = fields.to_parts().map_err(crypto_error)?;
        let event = match &previous {
            Some(previous) => self.key.seal_event_keeping(
                &parts,
                &secret,
                &previous.to_event().map_err(crypto_error)?,
            ),
            None => self.key.seal_event(&parts, &secret, None, None),
        }
        .map_err(crypto_error)?;
        let shared = self
            .key
            .open_key_packet(&event.shared_key_packet)
            .map_err(crypto_error)?;
        let uid = &parts.shared_signed.uid;
        let sealed_attendees = if attendees.is_empty() {
            None
        } else {
            Some(EventPartV1::of(
                &invitation::seal_attendees(
                    &AttendeesPart {
                        uid: uid.clone(),
                        attendees: attendees.clone(),
                    },
                    &shared,
                    &secret,
                )
                .map_err(crypto_error)?,
            ))
        };
        let invitees = invitees
            .iter()
            .map(|invitee| {
                let key = decode_canonical_base64(&invitee.public_key, "invitee key")?;
                Ok(InviteeOut {
                    address: canonical_email(&invitee.address),
                    key_packet: STANDARD.encode(
                        invitation::invitee_key_packet(&shared, &key).map_err(crypto_error)?,
                    ),
                })
            })
            .collect::<Result<Vec<_>, JsValue>>()?;
        to_js(&SealedInvitation {
            event: SealedEventV1::of(&event),
            attendees: sealed_attendees,
            tokens: tokens_for(&shared, uid, &attendees)?,
            invitees,
        })
    }

    /// Opens an event with its attendee part (null when it has none): the
    /// shared parts against the organizer's keys, the calendar parts
    /// against their own author's (an attendee's copy: the attendee's).
    #[wasm_bindgen(js_name = openEventWith)]
    pub fn open_event_with(
        &self,
        event: JsValue,
        attendees: JsValue,
        shared_author_public_keys: Vec<String>,
        calendar_author_public_keys: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        let event: SealedEventV1 = from_js(event, "event")?;
        let event = event.to_event().map_err(crypto_error)?;
        let part: Option<EventPartV1> = from_js(attendees, "attendees")?;
        let shared_keys = keys_of(shared_author_public_keys)?;
        let own_keys = keys_of(calendar_author_public_keys)?;
        let opened = self
            .key
            .open_event_by(&event, &slices(&shared_keys), &slices(&own_keys))
            .map_err(crypto_error)?;
        let uid = opened.parts.shared_signed.uid.clone();
        let shared = self
            .key
            .open_key_packet(&event.shared_key_packet)
            .map_err(crypto_error)?;
        let (attendees, attendees_verified) = match part {
            Some(part) => {
                let (list, verified) = invitation::open_attendees(
                    &part.to_part().map_err(crypto_error)?,
                    &shared,
                    &uid,
                    &slices(&shared_keys),
                )
                .map_err(crypto_error)?;
                (Some(list.attendees), verified)
            }
            None => (None, false),
        };
        to_js(&OpenedWith {
            fields: EventFieldsV1::of(&opened.parts),
            verified: opened.verified,
            tokens: tokens_for(&shared, &uid, attendees.as_deref().unwrap_or_default())?,
            attendees,
            attendees_verified,
        })
    }

    /// Opens an event's answer rows (`[{token, answer}]`): each answer, if
    /// it opens for its row, and whether one of `signer_public_keys` (the
    /// organizer's and the attendees' known keys) signed it.
    #[wasm_bindgen(js_name = openAnswers)]
    pub fn open_answers(
        &self,
        event: JsValue,
        shared_event_id: &str,
        rows: JsValue,
        signer_public_keys: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        let event: SealedEventV1 = from_js(event, "event")?;
        let shared = self
            .key
            .open_key_packet(&event.to_event().map_err(crypto_error)?.shared_key_packet)
            .map_err(crypto_error)?;
        let rows: Vec<AnswerRowIn> = from_js(rows, "answer rows")?;
        let signers = keys_of(signer_public_keys)?;
        to_js(&open_rows(
            &shared,
            shared_event_id,
            rows,
            &slices(&signers),
        )?)
    }

    /// Seals an answer for `email` on an event this calendar holds (the
    /// organizer writing an outside reply, or an attendee answering from
    /// their copy), signed by `signer`: `{token, answer}` for the server.
    #[wasm_bindgen(js_name = sealAnswer)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_answer(
        &self,
        signer: JsValue,
        event: JsValue,
        shared_event_id: &str,
        email: &str,
        partstat: &str,
        note: Option<String>,
        updated_at: &str,
    ) -> Result<JsValue, JsValue> {
        let signer: KeyIn = from_js(signer, "signer key")?;
        let event: SealedEventV1 = from_js(event, "event")?;
        let event = event.to_event().map_err(crypto_error)?;
        let shared = self
            .key
            .open_key_packet(&event.shared_key_packet)
            .map_err(crypto_error)?;
        let uid = std::str::from_utf8(&event.shared_signed.data)
            .ok()
            .and_then(|text| kutup_crypto::calendar_event::SharedSigned::parse(text).ok())
            .map(|part| part.uid)
            .ok_or_else(|| js_error("the event's shared part does not read"))?;
        seal_answer_with(
            &shared,
            &signer,
            &uid,
            shared_event_id,
            email,
            partstat,
            note,
            updated_at,
        )
    }
}

/// An invitation a Kutup attendee opened with their address key: the
/// shared session key stays here.
#[wasm_bindgen(js_name = OpenedInvitation)]
pub struct OpenedInvitationJs {
    key: SessionKey,
    uid: String,
    view: InvitationView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationView {
    fields: EventFieldsV1,
    verified: bool,
    attendees: Vec<AttendeeV1>,
    attendees_verified: bool,
    tokens: Vec<TokenOut>,
}

/// The shared parts as the server lists an invitation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SharedIn {
    shared_signed: EventPartV1,
    shared_encrypted: EventPartV1,
    #[serde(default)]
    attendees: Option<EventPartV1>,
}

/// What the attendee's own calendar row says.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnIn {
    dtstamp: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    transp: Option<String>,
    #[serde(default)]
    exdates: Vec<TimeV1>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptedOut {
    shared_key_packet: String,
    calendar_key_packet: String,
    calendar_signed: EventPartV1,
    calendar_encrypted: Option<EventPartV1>,
}

/// Opens an invitation's key packet (to `address_key`, the attendee's) and
/// its shared parts, checked against the organizer's keys: refused unless
/// the parts name one UID.
#[wasm_bindgen(js_name = openInvitation)]
pub fn open_invitation(
    address_key: JsValue,
    key_packet: &str,
    shared: JsValue,
    organizer_public_keys: Vec<String>,
) -> Result<OpenedInvitationJs, JsValue> {
    let address_key: KeyIn = from_js(address_key, "address key")?;
    let packet = decode_canonical_base64(key_packet, "key packet")?;
    let key = kutup_crypto::calendar::open_key_packet(&packet, &address_key.open()?)
        .map_err(crypto_error)?;
    let shared: SharedIn = from_js(shared, "shared parts")?;
    let organizer = keys_of(organizer_public_keys)?;
    let (signed, encrypted, verified) = invitation::open_shared_parts(
        &shared.shared_signed.to_part().map_err(crypto_error)?,
        &shared.shared_encrypted.to_part().map_err(crypto_error)?,
        &key,
        &slices(&organizer),
    )
    .map_err(crypto_error)?;
    let (attendees, attendees_verified) = match &shared.attendees {
        Some(part) => {
            let (list, verified) = invitation::open_attendees(
                &part.to_part().map_err(crypto_error)?,
                &key,
                &signed.uid,
                &slices(&organizer),
            )
            .map_err(crypto_error)?;
            (list.attendees, verified)
        }
        None => (Vec::new(), false),
    };
    let calendar = CalendarSigned {
        uid: signed.uid.clone(),
        dtstamp: signed.dtstamp,
        exdates: Vec::new(),
        status: None,
        transp: None,
        other: Vec::new(),
    };
    let uid = signed.uid.clone();
    let fields = EventFieldsV1::of(&EventParts {
        shared_signed: signed,
        shared_encrypted: encrypted,
        calendar_signed: calendar,
        calendar_encrypted: None,
    });
    let view = InvitationView {
        tokens: tokens_for(&key, &uid, &attendees)?,
        fields,
        verified,
        attendees,
        attendees_verified,
    };
    Ok(OpenedInvitationJs { key, uid, view })
}

#[wasm_bindgen(js_class = OpenedInvitation)]
impl OpenedInvitationJs {
    /// What was read: `{fields, verified, attendees, attendeesVerified,
    /// tokens}`.
    #[wasm_bindgen(getter)]
    pub fn view(&self) -> Result<JsValue, JsValue> {
        to_js(&self.view)
    }

    /// The token `email`'s answer is filed under.
    #[wasm_bindgen(js_name = tokenFor)]
    pub fn token_for(&self, email: &str) -> Result<String, JsValue> {
        Ok(token_text(
            &attendee_token(&self.key, &self.uid, email).map_err(crypto_error)?,
        ))
    }

    /// Seals the attendee's own answer, signed by their address key.
    #[wasm_bindgen(js_name = sealAnswer)]
    pub fn seal_answer(
        &self,
        signer: JsValue,
        shared_event_id: &str,
        email: &str,
        partstat: &str,
        note: Option<String>,
        updated_at: &str,
    ) -> Result<JsValue, JsValue> {
        let signer: KeyIn = from_js(signer, "signer key")?;
        seal_answer_with(
            &self.key,
            &signer,
            &self.uid,
            shared_event_id,
            email,
            partstat,
            note,
            updated_at,
        )
    }

    /// Opens the event's answer rows, as `UnlockedCalendar.openAnswers`.
    #[wasm_bindgen(js_name = openAnswers)]
    pub fn open_answers(
        &self,
        shared_event_id: &str,
        rows: JsValue,
        signer_public_keys: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        let rows: Vec<AnswerRowIn> = from_js(rows, "answer rows")?;
        let signers = keys_of(signer_public_keys)?;
        to_js(&open_rows(
            &self.key,
            shared_event_id,
            rows,
            &slices(&signers),
        )?)
    }

    /// The attendee's own row for their calendar `calendar`: the shared
    /// session key and a fresh one to its key, their calendar parts signed
    /// by `adopter`.
    pub fn adopt(
        &self,
        calendar: &UnlockedCalendarJs,
        adopter: JsValue,
        own: JsValue,
    ) -> Result<JsValue, JsValue> {
        let adopter: KeyIn = from_js(adopter, "adopter key")?;
        let own: OwnIn = from_js(own, "own parts")?;
        let dtstamp = own
            .dtstamp
            .parse()
            .map_err(|_| js_error("dtstamp is invalid"))?;
        let status = match own.status.as_deref() {
            None => None,
            Some("tentative") => Some(Status::Tentative),
            Some("confirmed") => Some(Status::Confirmed),
            Some("cancelled") => Some(Status::Cancelled),
            Some(_) => return Err(js_error("status is invalid")),
        };
        let transp = match own.transp.as_deref() {
            None => None,
            Some("opaque") => Some(Transp::Opaque),
            Some("transparent") => Some(Transp::Transparent),
            Some(_) => return Err(js_error("transp is invalid")),
        };
        let signed = CalendarSigned {
            uid: self.uid.clone(),
            dtstamp,
            exdates: own
                .exdates
                .iter()
                .map(TimeV1::to_time)
                .collect::<Result<_, _>>()
                .map_err(crypto_error)?,
            status,
            transp,
            other: Vec::new(),
        };
        let encrypted = own.comment.map(|comment| CalendarEncrypted {
            uid: self.uid.clone(),
            dtstamp,
            comment: Some(comment),
            other: Vec::new(),
        });
        let row = invitation::adopt(
            &calendar.key,
            &self.key,
            &self.uid,
            &signed,
            encrypted.as_ref(),
            &adopter.open()?,
        )
        .map_err(crypto_error)?;
        to_js(&AdoptedOut {
            shared_key_packet: STANDARD.encode(&row.shared_key_packet),
            calendar_key_packet: STANDARD.encode(&row.calendar_key_packet),
            calendar_signed: EventPartV1::of(&row.calendar_signed),
            calendar_encrypted: row.calendar_encrypted.as_ref().map(EventPartV1::of),
        })
    }
}
