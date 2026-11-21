//! Calendars in the browser (docs/plans/calendar.md, E1), over
//! `kutup_crypto::calendar`. A calendar's unlocked key stays in WASM memory
//! inside an [`UnlockedCalendarJs`]: JavaScript holds the object, never the
//! key or the passphrase, and frees it when the calendar closes. The
//! passphrase is shared on the account's keys, which WASM derives from the
//! identity root (docs/plans/wipe-unification.md, W4); the address key only
//! signs the metadata and events.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::calendar::{
    self, CalendarMetadataRest, CalendarShareEnvelopeV1, Passphrase, SealedEventV1,
    SealedMetadataV1, UnlockedCalendarKey, FIRST_KEY_GENERATION,
};
use kutup_crypto::calendar_event::{self, EventFieldsV1};
use kutup_crypto::calendar_recurrence;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{account_keys, decode_canonical_base64, js_error, open_mail_secret};

fn crypto_error(error: kutup_crypto::error::CryptoError) -> JsValue {
    js_error(&error.to_string())
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue, what: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|error| js_error(&format!("{what}: {error}")))
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error(&error.to_string()))
}

fn public_keys(keys: &[String]) -> Result<Vec<Vec<u8>>, JsValue> {
    keys.iter()
        .map(|key| decode_canonical_base64(key, "public key"))
        .collect()
}

/// A new calendar: what the browser posts to `POST /api/calendar/calendars`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewCalendar {
    public_key: String,
    locked_secret_key: String,
    fingerprint: String,
    /// The owner's own share of the passphrase (`CalendarShareEnvelopeV1`),
    /// at the first key generation.
    passphrase_share: String,
    metadata: SealedMetadataV1,
}

fn account_of(account: &str) -> Result<AccountRef, JsValue> {
    account
        .parse()
        .map_err(|_| js_error("an account reference is malformed"))
}

/// A calendar's name and description, as a client gives them; for a rename,
/// with the `rest` its opened metadata gave (docs/plans/format-evolution.md).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Names {
    name: String,
    description: String,
    #[serde(default)]
    rest: Option<CalendarMetadataRest>,
}

/// Makes a calendar owned by the signed-in account (`account`,
/// `aci:<uuid>@<server>`), under the id the client drew: its key, its
/// passphrase shared with the account itself (to the account key its
/// identity root derives, never one given, and signed by it), and its name
/// and description bound to the id and key, signed by the address key.
#[wasm_bindgen(js_name = createCalendar)]
#[allow(clippy::too_many_arguments)]
pub fn create_calendar(
    master_keys_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    identity_root_base64: &str,
    account: &str,
    calendar_id: &str,
    names: JsValue,
    created_at_secs: u32,
) -> Result<JsValue, JsValue> {
    let owner_secret = open_mail_secret(
        master_keys_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let identity = account_keys(identity_root_base64)?;
    let account = account_of(account)?;
    let names: Names = from_js(names, "names")?;
    let passphrase = Passphrase::generate();
    let key =
        calendar::generate_calendar_key(&passphrase, created_at_secs).map_err(crypto_error)?;
    let share = calendar::seal_own_passphrase(
        &passphrase,
        calendar_id,
        FIRST_KEY_GENERATION,
        &account,
        &identity,
    )
    .map_err(crypto_error)?;
    let metadata = key
        .unlocked
        .seal_metadata(calendar_id, &names.name, &names.description, &owner_secret)
        .map_err(crypto_error)?;
    to_js(&NewCalendar {
        public_key: STANDARD.encode(&key.public_key),
        locked_secret_key: STANDARD.encode(&key.locked_secret_key),
        fingerprint: hex::encode(key.fingerprint),
        passphrase_share: share.encode_b64().map_err(crypto_error)?,
        metadata: SealedMetadataV1::of(&metadata),
    })
}

/// A calendar's key, unlocked and kept in WASM memory. It seals to the key
/// derived from its own secret, never to one the server lists.
#[wasm_bindgen(js_name = UnlockedCalendar)]
pub struct UnlockedCalendarJs {
    key: UnlockedCalendarKey,
}

/// Opens the account's own share of a calendar's passphrase (the calendar
/// `calendar_id` at `key_generation`) with the keys its identity root
/// derives, refused unless the account itself shared and signed it, and
/// unlocks the calendar key. (Shared calendars, E3, add the owner's
/// verified keys.)
#[wasm_bindgen(js_name = unlockCalendar)]
pub fn unlock_calendar(
    identity_root_base64: &str,
    account: &str,
    calendar_id: &str,
    key_generation: u32,
    passphrase_share_base64: &str,
    locked_secret_key_base64: &str,
) -> Result<UnlockedCalendarJs, JsValue> {
    let identity = account_keys(identity_root_base64)?;
    let account = account_of(account)?;
    let share =
        CalendarShareEnvelopeV1::decode_b64(passphrase_share_base64).map_err(crypto_error)?;
    let passphrase: Passphrase =
        calendar::open_own_passphrase(&share, calendar_id, key_generation, &account, &identity)
            .map_err(crypto_error)?;
    let locked = decode_canonical_base64(locked_secret_key_base64, "calendar key")?;
    let key = calendar::unlock_calendar_key(&locked, &passphrase).map_err(crypto_error)?;
    Ok(UnlockedCalendarJs { key })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedEvent {
    fields: EventFieldsV1,
    verified: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedMetadata {
    name: String,
    description: String,
    verified: bool,
    /// The version and a newer client's fields: passed back with a rename.
    rest: CalendarMetadataRest,
}

#[wasm_bindgen(js_class = UnlockedCalendar)]
impl UnlockedCalendarJs {
    /// Opens an event (`SealedEventV1`): its fields, and whether every part
    /// is signed by one of the author's address keys.
    #[wasm_bindgen(js_name = openEvent)]
    pub fn open_event(
        &self,
        event: JsValue,
        author_public_keys_base64: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        let event: SealedEventV1 = from_js(event, "event")?;
        let authors = public_keys(&author_public_keys_base64)?;
        let authors: Vec<&[u8]> = authors.iter().map(Vec::as_slice).collect();
        let opened = self
            .key
            .open_event(&event.to_event().map_err(crypto_error)?, &authors)
            .map_err(crypto_error)?;
        to_js(&OpenedEvent {
            fields: EventFieldsV1::of(&opened.parts),
            verified: opened.verified,
        })
    }

    /// The calendar key's fingerprint (hex), derived from the unlocked secret.
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> String {
        hex::encode(self.key.fingerprint())
    }

    /// Opens the calendar's name and description (`SealedMetadataV1`),
    /// refused unless they name `calendar_id` and this key.
    #[wasm_bindgen(js_name = openMetadata)]
    pub fn open_metadata(
        &self,
        metadata: JsValue,
        calendar_id: &str,
        author_public_keys_base64: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        let sealed: SealedMetadataV1 = from_js(metadata, "metadata")?;
        let authors = public_keys(&author_public_keys_base64)?;
        let authors: Vec<&[u8]> = authors.iter().map(Vec::as_slice).collect();
        let (metadata, verified) = self
            .key
            .open_metadata(
                &sealed.to_sealed().map_err(crypto_error)?,
                calendar_id,
                &authors,
            )
            .map_err(crypto_error)?;
        to_js(&OpenedMetadata {
            rest: metadata.rest(),
            name: metadata.name,
            description: metadata.description,
            verified,
        })
    }

    /// Seals an event's fields (`EventFieldsV1`) for this calendar, signed
    /// by the author's address key: what the browser posts in an events sync.
    #[wasm_bindgen(js_name = sealEvent)]
    pub fn seal_event(
        &self,
        master_keys_base64: &str,
        binding: &str,
        address: &str,
        envelope_base64: &str,
        fingerprint_hex: &str,
        fields: JsValue,
    ) -> Result<JsValue, JsValue> {
        let author_secret = open_mail_secret(
            master_keys_base64,
            binding,
            address,
            envelope_base64,
            fingerprint_hex,
        )?;
        let fields: EventFieldsV1 = from_js(fields, "event fields")?;
        let sealed = self
            .key
            .seal_event(
                &fields.to_parts().map_err(crypto_error)?,
                &author_secret,
                None,
                None,
            )
            .map_err(crypto_error)?;
        to_js(&SealedEventV1::of(&sealed))
    }

    /// Seals this calendar's new name and description, bound to its id.
    #[wasm_bindgen(js_name = sealMetadata)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_metadata(
        &self,
        master_keys_base64: &str,
        binding: &str,
        address: &str,
        envelope_base64: &str,
        fingerprint_hex: &str,
        calendar_id: &str,
        names: JsValue,
    ) -> Result<JsValue, JsValue> {
        let author_secret = open_mail_secret(
            master_keys_base64,
            binding,
            address,
            envelope_base64,
            fingerprint_hex,
        )?;
        let names: Names = from_js(names, "names")?;
        let sealed = self
            .key
            .seal_metadata_keeping(
                calendar_id,
                &names.name,
                &names.description,
                &names.rest.unwrap_or_default(),
                &author_secret,
            )
            .map_err(crypto_error)?;
        to_js(&SealedMetadataV1::of(&sealed))
    }
}

/// A UTC instant as a wall-clock time in an IANA zone, through the bundled
/// time zone database (every client and server convert alike).
#[wasm_bindgen(js_name = calendarUtcToLocal)]
pub fn calendar_utc_to_local(instant: &str, tzid: &str) -> Result<String, JsValue> {
    calendar_event::utc_to_local(instant, tzid).map_err(crypto_error)
}

/// A wall-clock time in an IANA zone as a UTC instant.
#[wasm_bindgen(js_name = calendarLocalToUtc)]
pub fn calendar_local_to_utc(local: &str, tzid: &str) -> Result<String, JsValue> {
    calendar_event::local_to_utc(local, tzid).map_err(crypto_error)
}

/// The time zone names the bundled database knows, sorted.
#[wasm_bindgen(js_name = calendarTimeZones)]
pub fn calendar_time_zones() -> Vec<String> {
    calendar_event::time_zone_names()
}

/// A rule from the editor (`RuleV1`) as its canonical `RRULE` value, or
/// refused outside Proton's subset.
#[wasm_bindgen(js_name = calendarRuleText)]
pub fn calendar_rule_text(rule: JsValue) -> Result<String, JsValue> {
    let rule: calendar_recurrence::RuleV1 = from_js(rule, "rule")?;
    rule.to_text().map_err(crypto_error)
}

/// An `RRULE` value as the editor shows it (`RuleV1`): any spelling others
/// write, normalised, or refused outside Proton's subset.
#[wasm_bindgen(js_name = calendarReadRule)]
pub fn calendar_read_rule(text: &str) -> Result<JsValue, JsValue> {
    let rule = calendar_recurrence::Rule::read(text).map_err(crypto_error)?;
    to_js(&calendar_recurrence::RuleV1::of(&rule))
}

/// The `UNTIL` for a series starting at `start` (`TimeV1`) and ending on
/// `date` (`yyyy-MM-dd`): a date, or the end of that day in the start's zone.
#[wasm_bindgen(js_name = calendarSupportedUntil)]
pub fn calendar_supported_until(start: JsValue, date: &str) -> Result<JsValue, JsValue> {
    let start: calendar_event::TimeV1 = from_js(start, "start")?;
    to_js(&calendar_recurrence::supported_until_v1(&start, date).map_err(crypto_error)?)
}

/// An event's occurrences (`EventFieldsV1`) meeting `[from, to)`, at most
/// `max`: what the app draws.
#[wasm_bindgen(js_name = calendarOccurrences)]
pub fn calendar_occurrences(
    fields: JsValue,
    from: &str,
    to: &str,
    max: u32,
) -> Result<JsValue, JsValue> {
    let fields: EventFieldsV1 = from_js(fields, "event fields")?;
    let occurrences = calendar_recurrence::occurrences_v1(&fields, from, to, max as usize)
        .map_err(crypto_error)?;
    to_js(&occurrences)
}

/// When an event's last occurrence ends, or null for a series without end.
#[wasm_bindgen(js_name = calendarRangeEnd)]
pub fn calendar_range_end(fields: JsValue) -> Result<Option<String>, JsValue> {
    let fields: EventFieldsV1 = from_js(fields, "event fields")?;
    calendar_recurrence::range_end_v1(&fields).map_err(crypto_error)
}
