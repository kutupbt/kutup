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
use kutup_crypto::calendar_link;
use kutup_crypto::calendar_recurrence;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{account_keys, decode_canonical_base64, js_error, open_mail_secret};

pub(crate) fn crypto_error(error: kutup_crypto::error::CryptoError) -> JsValue {
    js_error(&error.to_string())
}

pub(crate) fn from_js<T: for<'de> Deserialize<'de>>(
    value: JsValue,
    what: &str,
) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|error| js_error(&format!("{what}: {error}")))
}

pub(crate) fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error(&error.to_string()))
}

pub(crate) fn public_keys(keys: &[String]) -> Result<Vec<Vec<u8>>, JsValue> {
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
    pub(crate) key: UnlockedCalendarKey,
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

// ---------------------------------------------------------------- sharing (E3)
//
// docs/plans/calendar-e3.md: members get each live key generation's
// passphrase on their account key, signed by the owner; removing one makes a
// new generation; links carry a secret that opens each generation's
// passphrase. The passphrases never leave WASM: these take the owner's own
// shares and hand back only what the server stores.

fn decode_b64(text: &str, what: &str) -> Result<Vec<u8>, JsValue> {
    decode_canonical_base64(text, what)
}

/// A member the passphrase is shared with, as their verified key binding
/// names them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberIn {
    account: String,
    incarnation_id: String,
    /// Their account X-Wing Drive public key (base64).
    xwing_public_key: String,
}

/// The owner as a member checks their share, verified.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerIn {
    account: String,
    incarnation_id: String,
    /// Their account signing public key (base64).
    signing_public_key: String,
}

fn own_passphrase(
    identity: &kutup_crypto::identity::AccountIdentityKeysV1,
    owner: &AccountRef,
    calendar_id: &str,
    generation: u32,
    own_share_base64: &str,
) -> Result<Passphrase, JsValue> {
    let share = CalendarShareEnvelopeV1::decode_b64(own_share_base64).map_err(crypto_error)?;
    calendar::open_own_passphrase(&share, calendar_id, generation, owner, identity)
        .map_err(crypto_error)
}

fn share_with(
    passphrase: &Passphrase,
    identity: &kutup_crypto::identity::AccountIdentityKeysV1,
    owner: &AccountRef,
    calendar_id: &str,
    generation: u32,
    member: &MemberIn,
) -> Result<String, JsValue> {
    let account = account_of(&member.account)?;
    let xwing = decode_b64(&member.xwing_public_key, "member key")?;
    calendar::seal_passphrase(
        passphrase,
        calendar_id,
        generation,
        owner,
        identity,
        &calendar::CalendarMember {
            account: &account,
            incarnation_id: &member.incarnation_id,
            xwing_public_key: &xwing,
        },
    )
    .and_then(|share| share.encode_b64())
    .map_err(crypto_error)
}

/// The owner shares generation `key_generation`'s passphrase (opened from
/// their own share) with `member` (`{ account, incarnationId,
/// xwingPublicKey }`, checked against the member's verified key binding by the
/// caller): the member's share, base64.
#[wasm_bindgen(js_name = shareCalendarPassphrase)]
pub fn share_calendar_passphrase(
    identity_root_base64: &str,
    owner_account: &str,
    calendar_id: &str,
    key_generation: u32,
    own_share_base64: &str,
    member: JsValue,
) -> Result<String, JsValue> {
    let identity = account_keys(identity_root_base64)?;
    let owner = account_of(owner_account)?;
    let member: MemberIn = from_js(member, "member")?;
    let passphrase = own_passphrase(
        &identity,
        &owner,
        calendar_id,
        key_generation,
        own_share_base64,
    )?;
    share_with(
        &passphrase,
        &identity,
        &owner,
        calendar_id,
        key_generation,
        &member,
    )
}

/// A member opens their share of a calendar someone else owns (`owner`:
/// `{ account, incarnationId, signingPublicKey }`, verified), refused unless
/// that owner signed it for this member, calendar and generation; and
/// unlocks that generation's key.
#[wasm_bindgen(js_name = unlockSharedCalendar)]
pub fn unlock_shared_calendar(
    identity_root_base64: &str,
    member_account: &str,
    owner: JsValue,
    calendar_id: &str,
    key_generation: u32,
    passphrase_share_base64: &str,
    locked_secret_key_base64: &str,
) -> Result<UnlockedCalendarJs, JsValue> {
    let identity = account_keys(identity_root_base64)?;
    let member = account_of(member_account)?;
    let owner: OwnerIn = from_js(owner, "owner")?;
    let owner_account = account_of(&owner.account)?;
    let signing = decode_b64(&owner.signing_public_key, "owner key")?;
    let share =
        CalendarShareEnvelopeV1::decode_b64(passphrase_share_base64).map_err(crypto_error)?;
    let passphrase = calendar::open_passphrase(
        &share,
        calendar_id,
        key_generation,
        &calendar::CalendarOwner {
            account: &owner_account,
            incarnation_id: &owner.incarnation_id,
            signing_public_key: &signing,
        },
        &member,
        &identity,
    )
    .map_err(crypto_error)?;
    let locked = decode_b64(locked_secret_key_base64, "calendar key")?;
    let key = calendar::unlock_calendar_key(&locked, &passphrase).map_err(crypto_error)?;
    Ok(UnlockedCalendarJs { key })
}

/// The key ID (hex) an event's key packets are to: which generation's
/// unlocked key opens it.
#[wasm_bindgen(js_name = calendarEventKeyId)]
pub fn calendar_event_key_id(event: JsValue) -> Result<String, JsValue> {
    let event: SealedEventV1 = from_js(event, "event")?;
    let event = event.to_event().map_err(crypto_error)?;
    Ok(hex::encode(
        calendar::event_key_id(&event).map_err(crypto_error)?,
    ))
}

/// The key ID (hex) one key packet (base64) is to.
#[wasm_bindgen(js_name = calendarKeyPacketKeyId)]
pub fn calendar_key_packet_key_id(key_packet_base64: &str) -> Result<String, JsValue> {
    let packet = decode_b64(key_packet_base64, "key packet")?;
    Ok(hex::encode(
        calendar::key_packet_key_id(&packet).map_err(crypto_error)?,
    ))
}

#[wasm_bindgen(js_class = UnlockedCalendar)]
impl UnlockedCalendarJs {
    /// A key packet (base64) `older` opens, sealed again to this key
    /// (compaction: an event moves to the newest generation).
    #[wasm_bindgen(js_name = rewrapKeyPacket)]
    pub fn rewrap_key_packet(
        &self,
        older: &UnlockedCalendarJs,
        key_packet_base64: &str,
    ) -> Result<String, JsValue> {
        let packet = decode_b64(key_packet_base64, "key packet")?;
        self.key
            .rewrap_key_packet(&older.key, &packet)
            .map(|packet| STANDARD.encode(packet))
            .map_err(crypto_error)
    }

    /// The key ID (hex) key packets to this key name.
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> Result<String, JsValue> {
        Ok(hex::encode(self.key.key_id().map_err(crypto_error)?))
    }

    /// Seals a link's optional purpose (`SealedMetadataV1`) to this
    /// calendar's key, bound to the calendar and the link, signed by the
    /// owner's address key.
    #[wasm_bindgen(js_name = sealLinkPurpose)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_link_purpose(
        &self,
        master_keys_base64: &str,
        binding: &str,
        address: &str,
        envelope_base64: &str,
        fingerprint_hex: &str,
        calendar_id: &str,
        link_id: &str,
        purpose: &str,
    ) -> Result<JsValue, JsValue> {
        let author_secret = open_mail_secret(
            master_keys_base64,
            binding,
            address,
            envelope_base64,
            fingerprint_hex,
        )?;
        let sealed = self
            .key
            .seal_link_purpose(calendar_id, link_id, purpose, &author_secret)
            .map_err(crypto_error)?;
        to_js(&SealedMetadataV1::of(&sealed))
    }

    /// Opens a link's purpose: `{ purpose, verified }`, refused unless it
    /// names `calendar_id` and `link_id`.
    #[wasm_bindgen(js_name = openLinkPurpose)]
    pub fn open_link_purpose(
        &self,
        sealed: JsValue,
        calendar_id: &str,
        link_id: &str,
        author_public_keys_base64: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        let sealed: SealedMetadataV1 = from_js(sealed, "link purpose")?;
        let authors = public_keys(&author_public_keys_base64)?;
        let authors: Vec<&[u8]> = authors.iter().map(Vec::as_slice).collect();
        let (purpose, verified) = self
            .key
            .open_link_purpose(
                &sealed.to_sealed().map_err(crypto_error)?,
                calendar_id,
                link_id,
                &authors,
            )
            .map_err(crypto_error)?;
        to_js(&OpenedPurpose { purpose, verified })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedPurpose {
    purpose: String,
    verified: bool,
}

/// A link the owner holds: its id and its secret, sealed to the owner's own
/// account key (`CalendarLinkSecretEnvelopeV1`, base64).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkIn {
    link_id: String,
    secret: String,
}

/// What a rotation hands back for one link: the new generation's
/// passphrase for it (its secret stays the owner's, unchanged).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkOut {
    link_id: String,
    passphrase: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberShare {
    account: String,
    share: String,
}

/// A new key generation (docs/plans/calendar-e3.md §2): what
/// `POST …/keys/rotate` stores, in one request.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rotated {
    key_generation: u32,
    public_key: String,
    locked_secret_key: String,
    fingerprint: String,
    /// The owner's own share of the new passphrase.
    own_share: String,
    member_shares: Vec<MemberShare>,
    metadata: SealedMetadataV1,
    links: Vec<LinkOut>,
}

/// What a rotation takes: who stays, the calendar's names, and its links.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationIn {
    /// The members who keep the calendar (the owner not among them).
    members: Vec<MemberIn>,
    names: Names,
    links: Vec<LinkIn>,
}

/// Makes calendar `calendar_id`'s next key generation after
/// `key_generation` (whose own share and link secrets the owner holds): a
/// new key and passphrase; the owner's own share and one for each member
/// who stays; the name re-sealed to the new key, signed by the address
/// key; and each keyed link's passphrase for the new generation.
/// Older generations stay as they are, for older events.
#[wasm_bindgen(js_name = rotateCalendar)]
#[allow(clippy::too_many_arguments)]
pub fn rotate_calendar(
    master_keys_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    identity_root_base64: &str,
    owner_account: &str,
    calendar_id: &str,
    key_generation: u32,
    own_share_base64: &str,
    rotation: JsValue,
    created_at_secs: u32,
) -> Result<JsValue, JsValue> {
    let author_secret = open_mail_secret(
        master_keys_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let identity = account_keys(identity_root_base64)?;
    let owner = account_of(owner_account)?;
    let rotation: RotationIn = from_js(rotation, "rotation")?;
    // The owner's own share of the generation rotated from: the rotation
    // is the owner's, from where it stands.
    own_passphrase(
        &identity,
        &owner,
        calendar_id,
        key_generation,
        own_share_base64,
    )?;
    let generation = calendar::next_key_generation(key_generation).map_err(crypto_error)?;
    let passphrase = Passphrase::generate();
    let key =
        calendar::generate_calendar_key(&passphrase, created_at_secs).map_err(crypto_error)?;
    let own_share =
        calendar::seal_own_passphrase(&passphrase, calendar_id, generation, &owner, &identity)
            .and_then(|share| share.encode_b64())
            .map_err(crypto_error)?;
    let member_shares = rotation
        .members
        .iter()
        .map(|member| {
            Ok(MemberShare {
                account: member.account.clone(),
                share: share_with(
                    &passphrase,
                    &identity,
                    &owner,
                    calendar_id,
                    generation,
                    member,
                )?,
            })
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    let metadata = key
        .unlocked
        .seal_metadata_keeping(
            calendar_id,
            &rotation.names.name,
            &rotation.names.description,
            &rotation.names.rest.unwrap_or_default(),
            &author_secret,
        )
        .map_err(crypto_error)?;
    let links = rotation
        .links
        .iter()
        .map(|link| {
            let secret = owner_link_secret(&identity, &owner, &link.link_id, &link.secret)?;
            Ok(LinkOut {
                link_id: link.link_id.clone(),
                passphrase: calendar_link::encode(
                    &calendar_link::seal_link_passphrase(
                        &secret,
                        calendar_id,
                        &link.link_id,
                        generation,
                        &passphrase,
                    )
                    .map_err(crypto_error)?,
                ),
            })
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    to_js(&Rotated {
        key_generation: generation,
        public_key: STANDARD.encode(&key.public_key),
        locked_secret_key: STANDARD.encode(&key.locked_secret_key),
        fingerprint: hex::encode(key.fingerprint),
        own_share,
        member_shares,
        metadata: SealedMetadataV1::of(&metadata),
        links,
    })
}

/// One generation's own share, for a new link.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationShare {
    key_generation: u32,
    share: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationSealed {
    key_generation: u32,
    sealed: String,
}

/// A new full link.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewLink {
    /// For the URL only (its fragment, or the query of a link for other
    /// calendar apps); never stored.
    url_secret: String,
    /// The secret sealed to the owner's own account key (never to the
    /// calendar's passphrase, which the members hold).
    secret: String,
    /// Each live generation's passphrase under the link secret.
    passphrases: Vec<GenerationSealed>,
    /// What the link's page shows the server (base64url); the server keeps
    /// its hash.
    access_proof: String,
}

/// A link's secret from the owner's own envelope.
fn owner_link_secret(
    identity: &kutup_crypto::identity::AccountIdentityKeysV1,
    owner: &AccountRef,
    link_id: &str,
    envelope_base64: &str,
) -> Result<calendar_link::LinkSecret, JsValue> {
    let envelope = calendar_link::CalendarLinkSecretEnvelopeV1::decode_b64(envelope_base64)
        .map_err(crypto_error)?;
    calendar_link::open_owner_link_secret(&envelope, link_id, owner, identity).map_err(crypto_error)
}

/// Makes a full link `link_id` for calendar `calendar_id`, from the owner's
/// own share of each live generation (`[{ keyGeneration, share }]`).
#[wasm_bindgen(js_name = createCalendarLink)]
pub fn create_calendar_link(
    identity_root_base64: &str,
    owner_account: &str,
    calendar_id: &str,
    link_id: &str,
    own_shares: JsValue,
) -> Result<JsValue, JsValue> {
    let identity = account_keys(identity_root_base64)?;
    let owner = account_of(owner_account)?;
    let shares: Vec<GenerationShare> = from_js(own_shares, "own shares")?;
    if shares.is_empty() {
        return Err(js_error("a link needs at least one key generation"));
    }
    let secret = calendar_link::LinkSecret::generate();
    let mut passphrases = Vec::new();
    for share in &shares {
        let passphrase = own_passphrase(
            &identity,
            &owner,
            calendar_id,
            share.key_generation,
            &share.share,
        )?;
        passphrases.push(GenerationSealed {
            key_generation: share.key_generation,
            sealed: calendar_link::encode(
                &calendar_link::seal_link_passphrase(
                    &secret,
                    calendar_id,
                    link_id,
                    share.key_generation,
                    &passphrase,
                )
                .map_err(crypto_error)?,
            ),
        });
    }
    to_js(&NewLink {
        url_secret: secret.to_url(),
        secret: calendar_link::seal_owner_link_secret(&secret, link_id, &owner, &identity)
            .and_then(|envelope| envelope.encode_b64())
            .map_err(crypto_error)?,
        passphrases,
        access_proof: calendar_link::link_access_proof_text(&secret, link_id)
            .map_err(crypto_error)?,
    })
}

/// The owner shows a link's URL again: its secret, opened from the owner's
/// own envelope.
#[wasm_bindgen(js_name = calendarLinkUrlSecret)]
pub fn calendar_link_url_secret(
    identity_root_base64: &str,
    owner_account: &str,
    link_id: &str,
    sealed_secret_base64: &str,
) -> Result<String, JsValue> {
    let identity = account_keys(identity_root_base64)?;
    let owner = account_of(owner_account)?;
    Ok(owner_link_secret(&identity, &owner, link_id, sealed_secret_base64)?.to_url())
}

/// What a keyed link's page shows the server for link `link_id` (base64url),
/// from the URL's secret.
#[wasm_bindgen(js_name = calendarLinkAccessProof)]
pub fn calendar_link_access_proof(url_secret: &str, link_id: &str) -> Result<String, JsValue> {
    let secret = calendar_link::LinkSecret::from_url(url_secret).map_err(crypto_error)?;
    calendar_link::link_access_proof_text(&secret, link_id).map_err(crypto_error)
}

/// A link's viewer unlocks one generation's key from the URL's secret and
/// what the link's page serves.
#[wasm_bindgen(js_name = openCalendarLink)]
pub fn open_calendar_link(
    url_secret: &str,
    calendar_id: &str,
    link_id: &str,
    key_generation: u32,
    sealed_passphrase_base64: &str,
    locked_secret_key_base64: &str,
) -> Result<UnlockedCalendarJs, JsValue> {
    let secret = calendar_link::LinkSecret::from_url(url_secret).map_err(crypto_error)?;
    let sealed = calendar_link::decode(sealed_passphrase_base64).map_err(crypto_error)?;
    let passphrase =
        calendar_link::open_link_passphrase(&secret, calendar_id, link_id, key_generation, &sealed)
            .map_err(crypto_error)?;
    let locked = decode_b64(locked_secret_key_base64, "calendar key")?;
    let key = calendar::unlock_calendar_key(&locked, &passphrase).map_err(crypto_error)?;
    Ok(UnlockedCalendarJs { key })
}
