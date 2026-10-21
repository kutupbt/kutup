//! Calendars in the browser (docs/plans/calendar.md, E1), over
//! `kutup_crypto::calendar`. A calendar's unlocked key stays in WASM memory
//! inside an [`UnlockedCalendarJs`]: JavaScript holds the object, never the
//! key or the passphrase, and frees it when the calendar closes.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use kutup_crypto::calendar::{
    self, Passphrase, SealedEventV1, SealedMetadataV1, UnlockedCalendarKey,
};
use kutup_crypto::calendar_event::{self, EventFieldsV1};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{decode_canonical_base64, js_error, open_mail_secret};

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
    passphrase: SealedPassphrase,
    metadata: SealedMetadataV1,
}

/// A member's copy of a calendar's passphrase on the wire.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedPassphrase {
    data_packet: String,
    signature: String,
    key_packet: String,
}

/// A calendar's name and description, as a client gives them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Names {
    name: String,
    description: String,
}

/// Makes a calendar owned by the signed-in member's address key, under the
/// id the client drew: its key, its passphrase sealed to that key and
/// signed, and its sealed name and description bound to the id and key.
#[wasm_bindgen(js_name = createCalendar)]
#[allow(clippy::too_many_arguments)]
pub fn create_calendar(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    owner_public_key_base64: &str,
    calendar_id: &str,
    names: JsValue,
    created_at_secs: u32,
) -> Result<JsValue, JsValue> {
    let owner_secret = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let owner_public = decode_canonical_base64(owner_public_key_base64, "owner public key")?;
    let names: Names = from_js(names, "names")?;
    let passphrase = Passphrase::generate();
    let key =
        calendar::generate_calendar_key(&passphrase, created_at_secs).map_err(crypto_error)?;
    let sealed = calendar::seal_passphrase(&passphrase, &[&owner_public], &owner_secret)
        .map_err(crypto_error)?;
    let metadata = key
        .unlocked
        .seal_metadata(calendar_id, &names.name, &names.description, &owner_secret)
        .map_err(crypto_error)?;
    to_js(&NewCalendar {
        public_key: STANDARD.encode(&key.public_key),
        locked_secret_key: STANDARD.encode(&key.locked_secret_key),
        fingerprint: hex::encode(key.fingerprint),
        passphrase: SealedPassphrase {
            data_packet: STANDARD.encode(&sealed.data_packet),
            signature: sealed.signature,
            key_packet: STANDARD.encode(&sealed.key_packets[0]),
        },
        metadata: SealedMetadataV1::of(&metadata),
    })
}

/// A calendar's key, unlocked and kept in WASM memory. It seals to the key
/// derived from its own secret, never to one the server lists.
#[wasm_bindgen(js_name = UnlockedCalendar)]
pub struct UnlockedCalendarJs {
    key: UnlockedCalendarKey,
}

/// Opens the member's copy of a calendar's passphrase with the member's
/// address key, checks the owner signed it, and unlocks the calendar key.
#[wasm_bindgen(js_name = unlockCalendar)]
#[allow(clippy::too_many_arguments)]
pub fn unlock_calendar(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    passphrase: JsValue,
    owner_public_keys_base64: Vec<String>,
    locked_secret_key_base64: &str,
) -> Result<UnlockedCalendarJs, JsValue> {
    let member_secret = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let sealed: SealedPassphrase = from_js(passphrase, "passphrase")?;
    let owners = public_keys(&owner_public_keys_base64)?;
    let owners: Vec<&[u8]> = owners.iter().map(Vec::as_slice).collect();
    let passphrase = calendar::open_passphrase(
        &decode_canonical_base64(&sealed.key_packet, "key packet")?,
        &decode_canonical_base64(&sealed.data_packet, "data packet")?,
        sealed.signature.as_bytes(),
        &member_secret,
        &owners,
    )
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
        master_key_base64: &str,
        binding: &str,
        address: &str,
        envelope_base64: &str,
        fingerprint_hex: &str,
        fields: JsValue,
    ) -> Result<JsValue, JsValue> {
        let author_secret = open_mail_secret(
            master_key_base64,
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
        master_key_base64: &str,
        binding: &str,
        address: &str,
        envelope_base64: &str,
        fingerprint_hex: &str,
        calendar_id: &str,
        names: JsValue,
    ) -> Result<JsValue, JsValue> {
        let author_secret = open_mail_secret(
            master_key_base64,
            binding,
            address,
            envelope_base64,
            fingerprint_hex,
        )?;
        let names: Names = from_js(names, "names")?;
        let sealed = self
            .key
            .seal_metadata(calendar_id, &names.name, &names.description, &author_secret)
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
