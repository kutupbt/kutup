//! Invitations' keys (docs/plans/calendar-e4.md §3, §6): what an organizer
//! seals beside an event's shared parts, and what an attendee opens and
//! writes.
//!
//! - **The attendee part** ([`AttendeesPart`]): the attendees' `ATTENDEE`
//!   lines, a data packet under the event's shared session key, signed by
//!   the organizer's address key, as the other encrypted parts.
//! - **The token** ([`attendee_token`]): what the server files each
//!   attendee's answer under, keyed by the shared session key
//!   (`HMAC-SHA256(HKDF(session key, "kutup/calendar/attendee-token/v1"),
//!   uid ‖ email)`), so the server can't confirm a guessed address against
//!   the readable UID (Proton's is a clear `SHA1(uid ‖ email)`, Q-5).
//! - **The answer** ([`AnswerV1`]): PARTSTAT, an optional note and when it
//!   was given, sealed under the shared session key and signed by whoever
//!   wrote it (the attendee, or the organizer for an outside reply), bound
//!   to the shared event and the token, so a server can't move one
//!   attendee's answer to another's row or another event (Q-3).
//! - **The invitee's key packet** ([`invitee_key_packet`]): the shared
//!   session key to a Kutup attendee's address key (Proton's
//!   `AddedProtonAttendees`), so the event reaches them at once (§6). It is
//!   never in the `.ics` (unlike Proton's `X-PM-SESSION-KEY`).
//! - **Adopting** ([`adopt`]): an attendee's own calendar row for the
//!   shared event: the shared session key and a fresh calendar session key
//!   to their calendar's key, and their calendar parts signed by their own
//!   address key; the organizer's shared parts stay as signed.
//!
//! The session key never leaves WASM: the browser holds an opened
//! invitation as an object and asks it for tokens, answers and rows.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::calendar::{
    decrypt_data_packet, encrypt_data_packet, key_packet_to, signed_by, EventPart, SessionKey,
    UnlockedCalendarKey,
};
use crate::calendar_event::{
    canonical_email, AttendeesPart, CalendarEncrypted, CalendarSigned, SharedEncrypted,
    SharedSigned,
};
use crate::error::{CryptoError, Result};
use crate::mail_key::sign_detached;
use crate::primitives::{kdf, mac, Suite};

/// A token's length: an HMAC-SHA256.
pub const TOKEN_LEN: usize = 32;
/// The answer format's version.
pub const ANSWER_VERSION: u16 = 1;
/// The longest note an answer carries, in characters (so a sealed answer
/// stays within the server's 4096 bytes).
pub const MAX_ANSWER_NOTE_CHARS: usize = 500;
/// The largest sealed answer the server keeps.
pub const MAX_SEALED_ANSWER_LEN: usize = 4096;
const TOKEN_KEY_CONTEXT: &[u8] = &[1];

/// The token an attendee's answer is filed under: keyed by the event's
/// shared session key, over its UID and the attendee's address
/// ([`canonical_email`]).
pub fn attendee_token(shared_key: &SessionKey, uid: &str, email: &str) -> Result<[u8; TOKEN_LEN]> {
    if uid.is_empty() || uid.len() > crate::calendar_event::MAX_UID_LEN {
        return Err(CryptoError::InvalidInput("UID is invalid".into()));
    }
    let email = canonical_email(email);
    if email.is_empty() {
        return Err(CryptoError::InvalidInput("an address is empty".into()));
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    kdf(
        Suite::V1,
        shared_key.as_bytes(),
        crate::labels::CALENDAR_ATTENDEE_TOKEN_V1,
        TOKEN_KEY_CONTEXT,
        key.as_mut(),
    )?;
    // The UID's length first: no UID and address split another way.
    Ok(mac(
        Suite::V1,
        key.as_ref(),
        &[&[uid.len() as u8], uid.as_bytes(), email.as_bytes()],
    )
    .to_array())
}

/// A token as the wire carries it: base64url without padding.
pub fn token_text(token: &[u8; TOKEN_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(token)
}

/// Seals the attendee part under the shared session key, signed by the
/// organizer.
pub fn seal_attendees(
    part: &AttendeesPart,
    shared_key: &SessionKey,
    organizer_secret_key: &[u8],
) -> Result<EventPart> {
    let text = part.build()?;
    Ok(EventPart {
        signature: sign_detached(organizer_secret_key, text.as_bytes())?,
        data: encrypt_data_packet(shared_key, text.as_bytes())?,
    })
}

/// Opens the attendee part: refused unless it names `uid`; `verified` says
/// whether one of the organizer's keys signed it.
pub fn open_attendees(
    part: &EventPart,
    shared_key: &SessionKey,
    uid: &str,
    organizer_public_keys: &[&[u8]],
) -> Result<(AttendeesPart, bool)> {
    let text = decrypt_data_packet(shared_key, &part.data)?;
    let verified = signed_by(&part.signature, &text, organizer_public_keys);
    let text = std::str::from_utf8(&text)
        .map_err(|_| CryptoError::InvalidInput("the attendee part is text".into()))?;
    let attendees = AttendeesPart::parse(text)?;
    if attendees.uid != uid {
        return Err(CryptoError::InvalidInput(
            "the attendee part is another event's".into(),
        ));
    }
    Ok((attendees, verified))
}

/// An attendee's answer (Proton's attendee `Status`, `Comment` and
/// `UpdateTime`), bound to the shared event and the token it is filed
/// under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnswerV1 {
    pub v: u16,
    pub shared_event_id: String,
    /// base64url ([`token_text`]).
    pub token: String,
    /// `needs-action`, `accepted`, `tentative` or `declined`.
    pub partstat: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// RFC 3339, whole seconds: the reply's DTSTAMP, or when it was given.
    pub updated_at: String,
}

const PARTSTATS: [&str; 4] = ["needs-action", "accepted", "tentative", "declined"];

impl AnswerV1 {
    fn check(&self) -> Result<()> {
        let invalid = |what: &str| Err(CryptoError::InvalidInput(format!("an answer's {what}")));
        if self.v != ANSWER_VERSION {
            return invalid("version is unknown");
        }
        if !PARTSTATS.contains(&self.partstat.as_str()) {
            return invalid("PARTSTAT is invalid");
        }
        if self.shared_event_id.is_empty() || self.shared_event_id.len() > 64 {
            return invalid("event is invalid");
        }
        if URL_SAFE_NO_PAD
            .decode(&self.token)
            .map_or(true, |token| token.len() != TOKEN_LEN)
        {
            return invalid("token is invalid");
        }
        if let Some(note) = &self.note {
            if note.chars().count() > MAX_ANSWER_NOTE_CHARS
                || note
                    .chars()
                    .any(|c| c == '\r' || (c.is_control() && c != '\n' && c != '\t'))
            {
                return invalid("note is too long or holds control characters");
            }
        }
        if self.updated_at.parse::<jiff::Timestamp>().is_err() {
            return invalid("time is invalid");
        }
        Ok(())
    }
}

/// A sealed answer as the server stores it: the data packet and the
/// signer's detached signature, as JSON.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedAnswer {
    data: String,
    signature: String,
}

/// Seals an answer under the shared session key, signed by its writer.
pub fn seal_answer(
    answer: &AnswerV1,
    shared_key: &SessionKey,
    signer_secret_key: &[u8],
) -> Result<Vec<u8>> {
    answer.check()?;
    let json = serde_json::to_vec(answer).map_err(|e| CryptoError::Backend(e.to_string()))?;
    let sealed = SealedAnswer {
        data: base64::engine::general_purpose::STANDARD
            .encode(encrypt_data_packet(shared_key, &json)?),
        signature: sign_detached(signer_secret_key, &json)?,
    };
    let bytes = serde_json::to_vec(&sealed).map_err(|e| CryptoError::Backend(e.to_string()))?;
    if bytes.len() > MAX_SEALED_ANSWER_LEN {
        return Err(CryptoError::InvalidInput("the answer is too large".into()));
    }
    Ok(bytes)
}

/// Opens an answer: refused unless it is for `shared_event_id` and `token`
/// (the row it was read from); `verified` says whether one of the given
/// keys (the organizer's, and the attendee's own when known) signed it.
pub fn open_answer(
    sealed: &[u8],
    shared_key: &SessionKey,
    shared_event_id: &str,
    token: &[u8; TOKEN_LEN],
    signer_public_keys: &[&[u8]],
) -> Result<(AnswerV1, bool)> {
    if sealed.len() > MAX_SEALED_ANSWER_LEN {
        return Err(CryptoError::InvalidInput("the answer is too large".into()));
    }
    let sealed: SealedAnswer = serde_json::from_slice(sealed)
        .map_err(|_| CryptoError::InvalidInput("the answer does not parse".into()))?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&sealed.data)
        .map_err(|_| CryptoError::InvalidInput("the answer is not base64".into()))?;
    let json = decrypt_data_packet(shared_key, &data)?;
    crate::format::check_json_version("calendar answer", &json, ANSWER_VERSION)?;
    let answer: AnswerV1 = serde_json::from_slice(&json)
        .map_err(|_| CryptoError::InvalidInput("the answer does not parse".into()))?;
    answer.check()?;
    if answer.shared_event_id != shared_event_id || answer.token != token_text(token) {
        return Err(CryptoError::InvalidInput(
            "the answer is another attendee's or another event's".into(),
        ));
    }
    let verified = signed_by(&sealed.signature, &json, signer_public_keys);
    Ok((answer, verified))
}

/// The shared session key to a Kutup attendee's address key.
pub fn invitee_key_packet(shared_key: &SessionKey, address_public_key: &[u8]) -> Result<Vec<u8>> {
    key_packet_to(shared_key, address_public_key)
}

/// The shared parts of an invitation, opened by an attendee who holds the
/// shared session key: refused unless the parts name one UID; `verified`
/// says whether the organizer's keys signed both.
pub fn open_shared_parts(
    shared_signed: &EventPart,
    shared_encrypted: &EventPart,
    shared_key: &SessionKey,
    organizer_public_keys: &[&[u8]],
) -> Result<(SharedSigned, SharedEncrypted, bool)> {
    let signed_text = std::str::from_utf8(&shared_signed.data)
        .map_err(|_| CryptoError::InvalidInput("a signed part is text".into()))?;
    let signed = SharedSigned::parse(signed_text)?;
    let plain = decrypt_data_packet(shared_key, &shared_encrypted.data)?;
    let encrypted = SharedEncrypted::parse(
        std::str::from_utf8(&plain)
            .map_err(|_| CryptoError::InvalidInput("an event part is text".into()))?,
    )?;
    if encrypted.uid != signed.uid {
        return Err(CryptoError::InvalidInput(
            "an event's parts name one UID".into(),
        ));
    }
    let verified = signed_by(
        &shared_signed.signature,
        &shared_signed.data,
        organizer_public_keys,
    ) && signed_by(&shared_encrypted.signature, &plain, organizer_public_keys);
    Ok((signed, encrypted, verified))
}

/// An attendee's own calendar row for a shared event.
pub struct AdoptedRow {
    pub shared_key_packet: Vec<u8>,
    pub calendar_key_packet: Vec<u8>,
    pub calendar_signed: EventPart,
    pub calendar_encrypted: Option<EventPart>,
}

/// Adopts a shared event into the attendee's calendar: the shared session
/// key to the calendar's key (derived from its secret, never a listed
/// one), a fresh session key for their own encrypted part, and their
/// calendar parts signed by their address key.
pub fn adopt(
    calendar: &UnlockedCalendarKey,
    shared_key: &SessionKey,
    uid: &str,
    calendar_signed: &CalendarSigned,
    calendar_encrypted: Option<&CalendarEncrypted>,
    adopter_secret_key: &[u8],
) -> Result<AdoptedRow> {
    if calendar_signed.uid != uid || calendar_encrypted.is_some_and(|part| part.uid != uid) {
        return Err(CryptoError::InvalidInput(
            "an event's parts name one UID".into(),
        ));
    }
    let own_key = SessionKey::generate();
    let signed_text = calendar_signed.build()?;
    Ok(AdoptedRow {
        shared_key_packet: key_packet_to(shared_key, calendar.public_key())?,
        calendar_key_packet: key_packet_to(&own_key, calendar.public_key())?,
        calendar_signed: EventPart {
            signature: sign_detached(adopter_secret_key, signed_text.as_bytes())?,
            data: signed_text.into_bytes(),
        },
        calendar_encrypted: calendar_encrypted
            .map(|part| -> Result<EventPart> {
                let text = part.build()?;
                Ok(EventPart {
                    signature: sign_detached(adopter_secret_key, text.as_bytes())?,
                    data: encrypt_data_packet(&own_key, text.as_bytes())?,
                })
            })
            .transpose()?,
    })
}

/// What a server checks of an adopted row before storing it: the calendar
/// signed part in its canonical form, for `uid`, signed by one of the
/// adopter's address keys, and both key packets single packets. Returns
/// the part, which the server reads the attendee's own EXDATEs from.
pub fn check_adopted_parts(
    calendar_signed: &EventPart,
    shared_key_packet: &[u8],
    calendar_key_packet: &[u8],
    uid: &str,
    adopter_public_keys: &[&[u8]],
) -> Result<CalendarSigned> {
    if !signed_by(
        &calendar_signed.signature,
        &calendar_signed.data,
        adopter_public_keys,
    ) {
        return Err(CryptoError::AuthFailed);
    }
    let text = std::str::from_utf8(&calendar_signed.data)
        .map_err(|_| CryptoError::InvalidInput("a signed part is text".into()))?;
    let part = CalendarSigned::parse(text)?;
    if part.uid != uid {
        return Err(CryptoError::InvalidInput(
            "an event's parts name one UID".into(),
        ));
    }
    for packet in [shared_key_packet, calendar_key_packet] {
        crate::calendar::key_packet_key_id(packet)?;
    }
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::{generate_calendar_key, Passphrase};
    use crate::calendar_event::AttendeeV1;
    use crate::mail_key::generate_address_key;

    fn key() -> SessionKey {
        SessionKey::from_bytes(&[7u8; 32]).unwrap()
    }

    fn attendees() -> AttendeesPart {
        AttendeesPart {
            uid: "e4@kutup.dev".into(),
            attendees: vec![
                AttendeeV1 {
                    email: "ayse@kutup.dev".into(),
                    name: Some("Ayşe Yılmaz".into()),
                    optional: false,
                },
                AttendeeV1 {
                    email: "bob@example.com".into(),
                    name: None,
                    optional: true,
                },
            ],
        }
    }

    #[test]
    fn a_token_is_keyed_and_reads_an_address_one_way() {
        let token = attendee_token(&key(), "e4@kutup.dev", "Ayse@Kutup.dev").unwrap();
        assert_eq!(
            token,
            attendee_token(&key(), "e4@kutup.dev", "mailto:ayse@kutup.dev").unwrap()
        );
        let other = SessionKey::from_bytes(&[8u8; 32]).unwrap();
        assert_ne!(
            token,
            attendee_token(&other, "e4@kutup.dev", "ayse@kutup.dev").unwrap()
        );
        // The UID's length keeps a UID and an address from sliding.
        assert_ne!(
            attendee_token(&key(), "e4@kutup.deva", "yse@kutup.dev").unwrap(),
            token
        );
        assert!(attendee_token(&key(), "", "a@b").is_err());
    }

    #[test]
    fn the_attendee_part_opens_for_its_event_only() {
        let organizer = generate_address_key("org@kutup.dev", 1_790_000_000).unwrap();
        let sealed = seal_attendees(&attendees(), &key(), &organizer.secret_key).unwrap();
        let keys = [organizer.public_key.as_slice()];
        let (opened, verified) = open_attendees(&sealed, &key(), "e4@kutup.dev", &keys).unwrap();
        assert!(verified);
        assert_eq!(opened, attendees());
        assert!(open_attendees(&sealed, &key(), "other@kutup.dev", &keys).is_err());
        let stranger = generate_address_key("x@kutup.dev", 1_790_000_000).unwrap();
        let (_, verified) = open_attendees(
            &sealed,
            &key(),
            "e4@kutup.dev",
            &[stranger.public_key.as_slice()],
        )
        .unwrap();
        assert!(!verified);
    }

    #[test]
    fn an_answer_is_bound_to_its_row() {
        let ayse = generate_address_key("ayse@kutup.dev", 1_790_000_000).unwrap();
        let token = attendee_token(&key(), "e4@kutup.dev", "ayse@kutup.dev").unwrap();
        let answer = AnswerV1 {
            v: ANSWER_VERSION,
            shared_event_id: "5b2f0c5e-3c1d-4a8b-9f00-1d2e3f4a5b6c".into(),
            token: token_text(&token),
            partstat: "accepted".into(),
            note: Some("See you there".into()),
            updated_at: "2026-11-24T10:00:00Z".into(),
        };
        let sealed = seal_answer(&answer, &key(), &ayse.secret_key).unwrap();
        let keys = [ayse.public_key.as_slice()];
        let (opened, verified) =
            open_answer(&sealed, &key(), &answer.shared_event_id, &token, &keys).unwrap();
        assert_eq!(opened, answer);
        assert!(verified);
        let bob = attendee_token(&key(), "e4@kutup.dev", "bob@example.com").unwrap();
        assert!(open_answer(&sealed, &key(), &answer.shared_event_id, &bob, &keys).is_err());
        assert!(open_answer(&sealed, &key(), "another", &token, &keys).is_err());
        let bad = AnswerV1 {
            partstat: "delegated".into(),
            ..answer.clone()
        };
        assert!(seal_answer(&bad, &key(), &ayse.secret_key).is_err());
        let long = AnswerV1 {
            note: Some("x".repeat(MAX_ANSWER_NOTE_CHARS + 1)),
            ..answer
        };
        assert!(seal_answer(&long, &key(), &ayse.secret_key).is_err());
    }

    #[test]
    fn an_adopted_row_carries_the_shared_key_to_the_calendar() {
        let calendar = generate_calendar_key(&Passphrase::generate(), 1_790_000_000)
            .unwrap()
            .unlocked;
        let ayse = generate_address_key("ayse@kutup.dev", 1_790_000_000).unwrap();
        let signed = CalendarSigned {
            uid: "e4@kutup.dev".into(),
            dtstamp: "2026-11-24T10:00:00Z".parse().unwrap(),
            exdates: Vec::new(),
            status: None,
            transp: None,
            other: Vec::new(),
        };
        let row = adopt(
            &calendar,
            &key(),
            "e4@kutup.dev",
            &signed,
            None,
            &ayse.secret_key,
        )
        .unwrap();
        assert_eq!(
            calendar
                .open_key_packet(&row.shared_key_packet)
                .unwrap()
                .as_bytes(),
            key().as_bytes()
        );
        let part = check_adopted_parts(
            &row.calendar_signed,
            &row.shared_key_packet,
            &row.calendar_key_packet,
            "e4@kutup.dev",
            &[ayse.public_key.as_slice()],
        )
        .unwrap();
        assert_eq!(part, signed);
        assert!(check_adopted_parts(
            &row.calendar_signed,
            &row.shared_key_packet,
            &row.calendar_key_packet,
            "other",
            &[ayse.public_key.as_slice()],
        )
        .is_err());
        assert!(adopt(&calendar, &key(), "other", &signed, None, &ayse.secret_key).is_err());
    }
}
