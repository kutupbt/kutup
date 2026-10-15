//! Kutup's collaboration content in Rust (docs/plans/cli-yjs-sync.md).
//!
//! Notes and code files are a Yjs document whose text is `content`; the web
//! editors use Yjs in JavaScript, and a peer without a browser (the CLI, later
//! the native apps) uses this crate, on yrs, Yjs's own Rust port, which reads
//! and writes the same updates. Offsets are UTF-16 code units, as in
//! JavaScript, so an index means the same thing on both sides.
//!
//! - [`seed_text`]: the first content of a file nobody has opened, the same
//!   bytes the web's `deterministicSeed` makes (pinned by shared vectors), so
//!   two peers seeding at once insert one item, not two.
//! - [`TextDoc`]: a document built from a saved state and the log after it,
//!   whose text a local edit replaces as minimal Yjs operations: concurrent
//!   edits elsewhere in the text merge as two tabs' do.
//! - [`ListDoc`]: a place list, whose places a local edit changes entry by
//!   entry (by the place's id), and [`parse_list_json`] / [`encode_list_json`]
//!   for its file form (`list.ts` in the web's map package).

use similar::{capture_diff_slices, Algorithm, DiffOp};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{
    Any, Doc, GetString, Map, MapPrelim, MapRef, Options, Out, ReadTxn, StateVector, Text,
    Transact, Update,
};

/// The text's name in the document (`doc.getText('content')` on the web).
pub const TEXT_NAME: &str = "content";

#[derive(Debug, thiserror::Error)]
pub enum CollabError {
    #[error("not a Yjs update: {0}")]
    Update(String),
    #[error("not a Kutup place list")]
    NotAPlaceList,
}

pub type Result<T> = std::result::Result<T, CollabError>;

/// A seed: `fill` makes the first content once under client id 0, and that
/// update fixes the client id the seed is made under
/// (`kutup_crypto::yjs_seed`), as the web's `deterministicSeed` does. Every
/// peer seeding the same file from the same content makes the same items;
/// different content makes different ones.
fn seeded(file_id: &str, fill: impl Fn(&Doc)) -> Vec<u8> {
    let encode = |client_id| {
        let doc = Doc::with_options(options(client_id));
        fill(&doc);
        let update = doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        update
    };
    encode(kutup_crypto::yjs_seed::seed_client_id(file_id, &encode(0)))
}

fn options(client_id: u64) -> Options {
    Options {
        client_id: yrs::block::ClientID::new(client_id),
        offset_kind: yrs::OffsetKind::Utf16,
        ..Options::default()
    }
}

/// The seed of a text file: its text inserted once, under the file's seed
/// client id, as a Yjs V1 update (what the web's seed applies).
pub fn seed_text(file_id: &str, text: &str) -> Vec<u8> {
    seeded(file_id, |doc| {
        let content = doc.get_or_insert_text(TEXT_NAME);
        let mut txn = doc.transact_mut();
        content.insert(&mut txn, 0, text);
    })
}

/// The map of a place list (`doc.getMap('places')` in `map/src/list.ts`).
pub const PLACES_NAME: &str = "places";

/// One place of a list, as `Place` in `map/src/list.ts`.
#[derive(Clone, Debug, PartialEq)]
pub struct Place {
    pub id: String,
    pub name: String,
    pub note: String,
    pub lat: f64,
    pub lon: f64,
    /// Who added it: their account's string form, `aci:<uuid>@<server>`
    /// (never an address, which can later be someone else's); empty when
    /// not known.
    pub added_by: String,
    /// RFC 3339.
    pub added_at: String,
}

/// A number as JavaScript's Yjs (lib0's `writeAny`) encodes it: a whole
/// number within 31 bits as an integer, anything else as a float, so the same
/// place makes the same bytes on both sides.
fn js_number(value: f64) -> yrs::Any {
    use yrs::any::Number;
    if value.fract() == 0.0 && value.abs() <= f64::from(0x7FFF_FFFF_u32) {
        yrs::Any::Number(Number::Int(value as i64))
    } else {
        yrs::Any::Number(Number::Float(value))
    }
}

/// Writes `place` as its entry: a map keyed by the place's id whose fields
/// go in in the web's order (`entryOf`: name, note, lat, lon, addedBy,
/// addedAt), so the same list makes the same items.
fn insert_place<T: Map>(places: &T, txn: &mut yrs::TransactionMut, place: &Place) {
    let entry = places.insert(txn, place.id.as_str(), MapPrelim::default());
    entry.insert(txn, "name", place.name.as_str());
    entry.insert(txn, "note", place.note.as_str());
    entry.insert(txn, "lat", js_number(place.lat));
    entry.insert(txn, "lon", js_number(place.lon));
    entry.insert(txn, "addedBy", place.added_by.as_str());
    entry.insert(txn, "addedAt", place.added_at.as_str());
}

/// The seed of a place list: its places written once, under the file's
/// seed client id, as a Yjs V1 update (what the web's seed applies).
pub fn seed_list(file_id: &str, places: &[Place]) -> Vec<u8> {
    seeded(file_id, |doc| {
        let map = doc.get_or_insert_map(PLACES_NAME);
        let mut txn = doc.transact_mut();
        for place in places {
            insert_place(&map, &mut txn, place);
        }
    })
}

/// A text document, as a peer holds it.
pub struct TextDoc {
    doc: Doc,
}

impl TextDoc {
    /// An empty document for a peer whose Yjs client id is `client_id`
    /// (random per session, as the web's is).
    pub fn new(client_id: u64) -> Self {
        let doc = Doc::with_options(options(client_id));
        doc.get_or_insert_text(TEXT_NAME);
        TextDoc { doc }
    }

    /// Applies a saved state (a version: Yjs V2, as the web encodes it).
    pub fn apply_v2(&self, update: &[u8]) -> Result<()> {
        let update = Update::decode_v2(update).map_err(|e| CollabError::Update(e.to_string()))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| CollabError::Update(e.to_string()))
    }

    /// Applies an edit from the log or a seed (Yjs V1, as frames carry it).
    pub fn apply_v1(&self, update: &[u8]) -> Result<()> {
        let update = Update::decode_v1(update).map_err(|e| CollabError::Update(e.to_string()))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| CollabError::Update(e.to_string()))
    }

    /// The text now.
    pub fn text(&self) -> String {
        let content = self.doc.get_or_insert_text(TEXT_NAME);
        content.get_string(&self.doc.transact())
    }

    /// Whether the text is empty (a seed may still go in).
    pub fn is_empty(&self) -> bool {
        self.text().is_empty()
    }

    /// The document's state vector (what it has seen), encoded.
    pub fn state_vector(&self) -> Vec<u8> {
        self.doc.transact().state_vector().encode_v1()
    }

    /// The whole state, Yjs V2 (what a saved version holds).
    pub fn state_v2(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v2(&StateVector::default())
    }

    /// Makes the text `wanted` with the fewest operations: a character diff
    /// of the current text against it, applied as deletions and insertions
    /// at their UTF-16 offsets, so text nobody touched stays the same items
    /// and concurrent edits to it merge. Returns the change as one Yjs V1
    /// update (to send as one frame), or `None` when there is nothing to do.
    pub fn set_text(&self, wanted: &str) -> Option<Vec<u8>> {
        let current = self.text();
        if current == wanted {
            return None;
        }
        let old: Vec<char> = current.chars().collect();
        let new: Vec<char> = wanted.chars().collect();
        let utf16 = |chars: &[char]| chars.iter().map(|c| c.len_utf16() as u32).sum::<u32>();
        let before = self.doc.transact().state_vector();
        let content = self.doc.get_or_insert_text(TEXT_NAME);
        {
            let mut txn = self.doc.transact_mut();
            // Where the next operation applies, in the text as it is being
            // changed (deletions and insertions so far included).
            let mut at: u32 = 0;
            for op in capture_diff_slices(Algorithm::Myers, &old, &new) {
                match op {
                    DiffOp::Equal { old_index, len, .. } => {
                        at += utf16(&old[old_index..old_index + len]);
                    }
                    DiffOp::Delete {
                        old_index, old_len, ..
                    } => {
                        content.remove_range(
                            &mut txn,
                            at,
                            utf16(&old[old_index..old_index + old_len]),
                        );
                    }
                    DiffOp::Insert {
                        new_index, new_len, ..
                    } => {
                        let text: String = new[new_index..new_index + new_len].iter().collect();
                        content.insert(&mut txn, at, &text);
                        at += utf16(&new[new_index..new_index + new_len]);
                    }
                    DiffOp::Replace {
                        old_index,
                        old_len,
                        new_index,
                        new_len,
                    } => {
                        content.remove_range(
                            &mut txn,
                            at,
                            utf16(&old[old_index..old_index + old_len]),
                        );
                        let text: String = new[new_index..new_index + new_len].iter().collect();
                        content.insert(&mut txn, at, &text);
                        at += utf16(&new[new_index..new_index + new_len]);
                    }
                }
            }
        }
        Some(self.doc.transact().encode_state_as_update_v1(&before))
    }
}

/// At most this many places in a list (`MAX_PLACES` in `list.ts`).
pub const MAX_PLACES: usize = 5000;
const MAX_NAME: usize = 200;
const MAX_NOTE: usize = 2000;
/// `new Date(0).toISOString()`: the time of a place that has none.
const NO_TIME: &str = "1970-01-01T00:00:00.000Z";

fn clamp(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A place's time: RFC 3339 exactly as `list.ts` checks it, by hand on both
/// sides (`Date.parse` and Rust's parsers each accept more, differently):
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`, upper-case `T` and `Z`, a real
/// calendar day, no leap second.
pub fn valid_time(value: &str) -> bool {
    let b = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(range)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0, |n, d| n * 10 + u32::from(d - b'0')))
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return false;
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let mut rest = &b[19..];
    if rest.first() == Some(&b'.') {
        let fraction = rest[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if fraction == 0 {
            return false;
        }
        rest = &rest[1 + fraction..];
    }
    match rest {
        [b'Z'] => true,
        [sign, h1, h2, b':', m1, m2] if (*sign == b'+' || *sign == b'-') => {
            let all = [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit());
            all && (h1 - b'0') * 10 + (h2 - b'0') <= 23 && (m1 - b'0') * 10 + (m2 - b'0') <= 59
        }
        _ => false,
    }
}

/// ECMAScript's `String.prototype.trim` (its WhiteSpace and LineTerminator
/// sets differ from Rust's `trim`: U+FEFF in, U+0085 out).
fn js_trim(value: &str) -> &str {
    let space = |c: char| {
        matches!(
            c,
            '\u{9}'
                | '\u{A}'
                | '\u{B}'
                | '\u{C}'
                | '\u{D}'
                | ' '
                | '\u{A0}'
                | '\u{1680}'
                | '\u{2000}'
                ..='\u{200A}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202F}'
                    | '\u{205F}'
                    | '\u{3000}'
                    | '\u{FEFF}'
        )
    };
    value.trim_matches(space)
}

/// A place as stored, or `None` when it is not one (no name, coordinates
/// that are not numbers in range): `normalizePlace` in `list.ts`. A place
/// without a usable id gets `id_for()`.
pub fn normalize_place(
    value: &serde_json::Value,
    id_for: impl FnOnce() -> String,
) -> Option<Place> {
    let v = value.as_object()?;
    let text = |key: &str| v.get(key).and_then(|x| x.as_str());
    let number = |key: &str| v.get(key).and_then(|x| x.as_f64());
    let lat = number("lat")?;
    let lon = number("lon")?;
    let name = clamp(js_trim(text("name").unwrap_or("")), MAX_NAME);
    if !lat.is_finite()
        || !lon.is_finite()
        || !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
        || name.is_empty()
    {
        return None;
    }
    let id = match text("id") {
        Some(id) if valid_id(id) => id.to_owned(),
        _ => id_for(),
    };
    Some(Place {
        id,
        name,
        note: clamp(text("note").unwrap_or(""), MAX_NOTE),
        lat,
        lon,
        added_by: text("addedBy")
            .filter(|by| by.parse::<kutup_crypto::account_ref::AccountRef>().is_ok())
            .unwrap_or("")
            .to_owned(),
        added_at: match text("addedAt") {
            Some(at) if valid_time(at) => at.to_owned(),
            _ => NO_TIME.to_owned(),
        },
    })
}

/// Oldest first, then by name, then by id: the order a list is shown and
/// exported in. (The web compares names by locale; here by code point, which
/// differs only for places added in the same millisecond.)
fn ordered(mut places: Vec<Place>) -> Vec<Place> {
    places.sort_by(|a, b| {
        a.added_at
            .cmp(&b.added_at)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    places
}

/// A file's bytes as text, as the web's `TextDecoder` reads them: invalid
/// UTF-8 replaced, a leading byte-order mark dropped.
pub fn text_of(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{FEFF}').unwrap_or(&text).to_owned()
}

/// JSON text as `JSON.parse` takes what serde would refuse whole, place by
/// place: a number out of range (`1e400`, `Infinity` to JavaScript, so that
/// place is dropped) becomes `null`, which drops it here too; a lone UTF-16
/// surrogate escape, which no Rust string holds, becomes U+FFFD.
fn as_javascript_reads(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let hex = |at: usize| -> Option<u32> {
        let digits: String = chars.get(at..at + 4)?.iter().collect();
        u32::from_str_radix(&digits, 16).ok()
    };
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            match c {
                '"' => {
                    in_string = false;
                    out.push(c);
                    i += 1;
                }
                '\\' if chars.get(i + 1) == Some(&'u') => match hex(i + 2) {
                    Some(high @ 0xD800..=0xDBFF) => {
                        let low = (chars.get(i + 6) == Some(&'\\')
                            && chars.get(i + 7) == Some(&'u'))
                        .then(|| hex(i + 8))
                        .flatten()
                        .filter(|low| (0xDC00..=0xDFFF).contains(low));
                        match low {
                            Some(low) => {
                                out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                                i += 12;
                            }
                            None => {
                                out.push_str("\\ufffd");
                                i += 6;
                            }
                        }
                    }
                    Some(0xDC00..=0xDFFF) => {
                        out.push_str("\\ufffd");
                        i += 6;
                    }
                    _ => {
                        out.extend(&chars[i..(i + 6).min(chars.len())]);
                        i += 6;
                    }
                },
                '\\' => {
                    out.extend(&chars[i..(i + 2).min(chars.len())]);
                    i += 2;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
        } else if c == '-' || c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && matches!(chars[i], '0'..='9' | '-' | '+' | '.' | 'e' | 'E') {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            match token.parse::<f64>() {
                Ok(n) if !n.is_finite() => out.push_str("null"),
                _ => out.push_str(&token),
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// The places in a stored list (`parseListJson`): an empty file (or a
/// one-character placeholder) is an empty list; entries that are not places,
/// and repeated ids, are dropped; a place without a usable id gets
/// `id_for(index)` (its position among the entries).
pub fn parse_list_json_with(bytes: &[u8], id_for: impl Fn(usize) -> String) -> Result<Vec<Place>> {
    let text = text_of(bytes);
    let text = js_trim(&text);
    if text.encode_utf16().count() <= 1 {
        return Ok(Vec::new());
    }
    let value: serde_json::Value =
        serde_json::from_str(&as_javascript_reads(text)).map_err(|_| CollabError::NotAPlaceList)?;
    // `version === 1` in JavaScript: `1.0` is the same number.
    let version_1 = value.get("version").and_then(|v| v.as_f64()) == Some(1.0);
    let places = match (
        value.get("format").and_then(|f| f.as_str()),
        value.get("places").and_then(|p| p.as_array()),
    ) {
        (Some("kutupmap"), Some(places)) if version_1 => places,
        _ => return Err(CollabError::NotAPlaceList),
    };
    let mut seen = std::collections::BTreeSet::new();
    Ok(places
        .iter()
        .take(MAX_PLACES)
        .enumerate()
        .filter_map(|(index, value)| normalize_place(value, || id_for(index)))
        .filter(|place| seen.insert(place.id.clone()))
        .collect())
}

/// The places in a list someone edited here: a place without an id is new,
/// and gets a random one.
pub fn parse_list_json(bytes: &[u8]) -> Result<Vec<Place>> {
    parse_list_json_with(bytes, |_| uuid::Uuid::new_v4().to_string())
}

/// The id a place without one gets in a file's first content: the same for
/// every peer seeding that file (`uploadId` in `list.ts`).
pub fn upload_place_id(file_id: &str, index: usize) -> String {
    format!("{}-{index}", file_id.replace('-', ""))
}

/// The first content of a list nobody has opened, from its file's bytes as
/// every editor makes it: its places (no place, if it is not a list).
pub fn seed_list_upload(file_id: &str, bytes: &[u8]) -> Vec<u8> {
    let places =
        parse_list_json_with(bytes, |index| upload_place_id(file_id, index)).unwrap_or_default();
    seed_list(file_id, &places)
}

/// The first content of a note or code file nobody has opened, from its
/// file's bytes as every editor makes it.
pub fn seed_text_upload(file_id: &str, bytes: &[u8]) -> Vec<u8> {
    seed_text(file_id, &text_of(bytes))
}

/// A number as `JSON.stringify` writes it: whole numbers without a fraction.
fn json_number(value: f64) -> serde_json::Value {
    if value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        serde_json::Value::from(value as i64)
    } else {
        serde_json::Value::from(value)
    }
}

/// A list's file form (`encodeListJson`): `{ "format": "kutupmap",
/// "version": 1, "places": [...] }`, places in list order, indented by one
/// space as the web writes it.
pub fn encode_list_json(places: &[Place]) -> Vec<u8> {
    let places: Vec<serde_json::Value> = ordered(places.to_vec())
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "note": p.note,
                "lat": json_number(p.lat),
                "lon": json_number(p.lon),
                "addedBy": p.added_by,
                "addedAt": p.added_at,
            })
        })
        .collect();
    let value = serde_json::json!({ "format": "kutupmap", "version": 1, "places": places });
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    serde::Serialize::serialize(&value, &mut serializer).expect("JSON of plain values");
    out
}

/// An entry's fields as JSON, the way `entry.toJSON()` gives them.
fn entry_json<T: ReadTxn>(entry: &MapRef, txn: &T) -> serde_json::Map<String, serde_json::Value> {
    entry
        .iter(txn)
        .filter_map(|(key, value)| {
            let value = match value {
                Out::Any(Any::String(s)) => serde_json::Value::from(s.as_ref()),
                Out::Any(Any::Number(yrs::any::Number::Int(n))) => serde_json::Value::from(n),
                Out::Any(Any::Number(yrs::any::Number::Float(f))) => serde_json::Value::from(f),
                _ => return None,
            };
            Some((key.to_owned(), value))
        })
        .collect()
}

/// A place list, as a peer holds it.
pub struct ListDoc {
    doc: Doc,
}

impl ListDoc {
    /// An empty list for a peer whose Yjs client id is `client_id`.
    pub fn new(client_id: u64) -> Self {
        let doc = Doc::with_options(options(client_id));
        doc.get_or_insert_map(PLACES_NAME);
        ListDoc { doc }
    }

    /// Applies a saved state (Yjs V2).
    pub fn apply_v2(&self, update: &[u8]) -> Result<()> {
        let update = Update::decode_v2(update).map_err(|e| CollabError::Update(e.to_string()))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| CollabError::Update(e.to_string()))
    }

    /// Applies an edit from the log or a seed (Yjs V1).
    pub fn apply_v1(&self, update: &[u8]) -> Result<()> {
        let update = Update::decode_v1(update).map_err(|e| CollabError::Update(e.to_string()))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| CollabError::Update(e.to_string()))
    }

    /// The places now, in list order (`placesOf`): entries that are not
    /// places are left out.
    pub fn places(&self) -> Vec<Place> {
        let map = self.doc.get_or_insert_map(PLACES_NAME);
        let txn = self.doc.transact();
        let places = map
            .iter(&txn)
            .filter_map(|(id, value)| match value {
                Out::YMap(entry) => {
                    let mut fields = entry_json(&entry, &txn);
                    fields.insert("id".into(), serde_json::Value::from(id));
                    // An id the entry is keyed by is kept as it is.
                    normalize_place(&serde_json::Value::Object(fields), || id.to_owned()).map(
                        |mut place| {
                            place.id = id.to_owned();
                            place
                        },
                    )
                }
                _ => None,
            })
            .collect();
        ordered(places)
    }

    /// Whether the list has no entries at all (a seed may still go in).
    pub fn is_empty(&self) -> bool {
        let map = self.doc.get_or_insert_map(PLACES_NAME);
        let empty = map.len(&self.doc.transact()) == 0;
        empty
    }

    /// The whole state, Yjs V2 (what a saved version holds).
    pub fn state_v2(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v2(&StateVector::default())
    }

    /// Makes the list `wanted`, entry by entry: places gone are removed, new
    /// ones added, and of the others only the fields that differ are set, so
    /// concurrent edits to other places, or other fields, merge. Returns the
    /// change as one Yjs V1 update, or `None` when there is nothing to do.
    /// Over [`MAX_PLACES`] is refused, as the editor refuses it.
    pub fn set_places(&self, wanted: &[Place]) -> Result<Option<Vec<u8>>> {
        if wanted.len() > MAX_PLACES {
            return Err(CollabError::NotAPlaceList);
        }
        let current: std::collections::BTreeMap<String, Place> = self
            .places()
            .into_iter()
            .map(|place| (place.id.clone(), place))
            .collect();
        let wanted_ids: std::collections::BTreeSet<&str> =
            wanted.iter().map(|p| p.id.as_str()).collect();
        let before = self.doc.transact().state_vector();
        let map = self.doc.get_or_insert_map(PLACES_NAME);
        let mut changed = false;
        {
            let mut txn = self.doc.transact_mut();
            for id in current.keys() {
                if !wanted_ids.contains(id.as_str()) {
                    map.remove(&mut txn, id);
                    changed = true;
                }
            }
            for place in wanted {
                let Some(old) = current.get(&place.id) else {
                    insert_place(&map, &mut txn, place);
                    changed = true;
                    continue;
                };
                if old == place {
                    continue;
                }
                let Some(Out::YMap(entry)) = map.get(&txn, &place.id) else {
                    continue;
                };
                if old.name != place.name {
                    entry.insert(&mut txn, "name", place.name.as_str());
                }
                if old.note != place.note {
                    entry.insert(&mut txn, "note", place.note.as_str());
                }
                if old.lat != place.lat {
                    entry.insert(&mut txn, "lat", js_number(place.lat));
                }
                if old.lon != place.lon {
                    entry.insert(&mut txn, "lon", js_number(place.lon));
                }
                if old.added_by != place.added_by {
                    entry.insert(&mut txn, "addedBy", place.added_by.as_str());
                }
                if old.added_at != place.added_at {
                    entry.insert(&mut txn, "addedAt", place.added_at.as_str());
                }
                changed = true;
            }
        }
        Ok(changed.then(|| self.doc.transact().encode_state_as_update_v1(&before)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merged(base: &[u8], updates: &[&[u8]]) -> String {
        let doc = TextDoc::new(99);
        doc.apply_v1(base).unwrap();
        for update in updates {
            doc.apply_v1(update).unwrap();
        }
        doc.text()
    }

    #[test]
    fn a_seed_is_the_same_wherever_it_is_made() {
        let id = "11111111-1111-4111-8111-111111111111";
        assert_eq!(seed_text(id, "hello"), seed_text(id, "hello"));
        // Two peers seeding at once insert one item: applying both is one text.
        let seed = seed_text(id, "hello");
        assert_eq!(merged(&seed, &[&seed]), "hello");
    }

    #[test]
    fn seeds_from_different_content_never_share_items() {
        // A peer seeding from an older upload and one from a newer: the two
        // seeds are different items, so every peer ends with the same
        // document whichever came first (both texts, side by side).
        let id = "11111111-1111-4111-8111-111111111111";
        let (old, new) = (seed_text(id, "version one"), seed_text(id, "version two"));
        let first = merged(&old, &[&new]);
        assert_eq!(first, merged(&new, &[&old]));
        assert!(first.contains("version one") && first.contains("version two"));
        // The same for place lists.
        let place = |id: &str, lat: f64| Place {
            id: id.into(),
            name: "P".into(),
            lat,
            lon: 0.0,
            note: String::new(),
            added_by: "aci:00000000-0000-4000-8000-000000000001@a.test".into(),
            added_at: "2026-01-01T00:00:00Z".into(),
        };
        let (a, b) = (
            seed_list(id, &[place("p", 1.0)]),
            seed_list(id, &[place("p", 2.0)]),
        );
        let state = |updates: [&[u8]; 2]| {
            let doc = ListDoc::new(99);
            for update in updates {
                doc.apply_v1(update).unwrap();
            }
            doc.places()
        };
        assert_eq!(state([&a, &b]), state([&b, &a]));
    }

    #[test]
    fn an_edit_is_the_fewest_operations_and_merges_with_a_concurrent_one() {
        let base = seed_text("f", "the quick brown fox\njumps over the lazy dog\n");
        // The CLI changes the second line; a tab meanwhile the first.
        let cli = TextDoc::new(1);
        cli.apply_v1(&base).unwrap();
        let cli_edit = cli
            .set_text("the quick brown fox\njumps over the sleepy dog\n")
            .unwrap();
        let tab = TextDoc::new(2);
        tab.apply_v1(&base).unwrap();
        let tab_edit = tab
            .set_text("the quick red fox\njumps over the lazy dog\n")
            .unwrap();
        assert_eq!(
            merged(&base, &[&cli_edit, &tab_edit]),
            "the quick red fox\njumps over the sleepy dog\n"
        );
        assert_eq!(
            merged(&base, &[&tab_edit, &cli_edit]),
            "the quick red fox\njumps over the sleepy dog\n"
        );
        assert!(cli.set_text(&cli.text()).is_none(), "no change, no update");
    }

    #[test]
    fn offsets_count_utf16_units_as_javascript_does() {
        // Emoji are two UTF-16 units; Turkish letters are one.
        let base = seed_text("f", "😀 İstanbul ılık 😀\n");
        let a = TextDoc::new(1);
        a.apply_v1(&base).unwrap();
        let edit = a.set_text("😀 İstanbul çok ılık 🎉 😀\n").unwrap();
        let b = TextDoc::new(2);
        b.apply_v1(&base).unwrap();
        let other = b.set_text("😀😀 İstanbul ılık 😀\n").unwrap();
        assert_eq!(merged(&base, &[&edit]), "😀 İstanbul çok ılık 🎉 😀\n");
        assert_eq!(
            merged(&base, &[&edit, &other]),
            "😀😀 İstanbul çok ılık 🎉 😀\n"
        );
    }

    fn place(id: &str, name: &str, lat: f64) -> Place {
        Place {
            id: id.into(),
            name: name.into(),
            note: String::new(),
            lat,
            lon: 29.0,
            added_by: "ayşe@kutup.dev".into(),
            added_at: "2026-10-13T10:00:00.000Z".into(),
        }
    }

    fn list_of(base: &[u8], updates: &[&[u8]]) -> Vec<Place> {
        let doc = ListDoc::new(99);
        doc.apply_v1(base).unwrap();
        for update in updates {
            doc.apply_v1(update).unwrap();
        }
        doc.places()
    }

    #[test]
    fn list_edits_merge_by_place() {
        let base = seed_list(
            "f",
            &[place("a", "Galata", 41.02), place("b", "Moda", 40.98)],
        );
        // The CLI renames one place and removes the other; a tab meanwhile
        // moves the first and adds a third.
        let cli = ListDoc::new(1);
        cli.apply_v1(&base).unwrap();
        let cli_edit = cli
            .set_places(&[place("a", "Galata Kulesi", 41.02)])
            .unwrap()
            .unwrap();
        let tab = ListDoc::new(2);
        tab.apply_v1(&base).unwrap();
        let mut moved = place("a", "Galata", 41.0256);
        moved.lon = 28.9742;
        let tab_edit = tab
            .set_places(&[
                moved,
                place("b", "Moda", 40.98),
                place("c", "Kadıköy", 40.99),
            ])
            .unwrap()
            .unwrap();
        for order in [[&cli_edit, &tab_edit], [&tab_edit, &cli_edit]] {
            let merged = list_of(&base, &[order[0], order[1]]);
            let names: Vec<_> = merged.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, ["Galata Kulesi", "Kadıköy"]);
            assert_eq!((merged[0].lat, merged[0].lon), (41.0256, 28.9742));
        }
        assert!(
            cli.set_places(&cli.places()).unwrap().is_none(),
            "no change, no update"
        );
    }

    #[test]
    fn list_json_reads_and_writes_the_web_form() {
        let json = br#"{"format":"kutupmap","version":1,"places":[
            {"id":"b","name":"  Moda ","lat":40.98,"lon":29,"addedAt":"2026-10-13T11:00:00.000Z"},
            {"id":"s","name":"A string","lat":"40.98","lon":29},
            {"id":"a","name":"Galata","lat":41.5,"lon":28.97,"addedAt":"2026-10-13T10:00:00.000Z"},
            {"id":"a","name":"again","lat":1,"lon":1},
            {"id":"x","name":"nowhere","lat":91,"lon":0},
            {"id":"bad id!","name":"Kept with a new id","lat":0,"lon":0}]}"#;
        let places = parse_list_json(json).unwrap();
        assert_eq!(places.len(), 3);
        assert_eq!(places[0].name, "Moda");
        assert_eq!(places[0].lat, 40.98);
        assert_eq!(places[2].added_at, NO_TIME);
        assert!(valid_id(&places[2].id) && places[2].id != "bad id!");
        let written = String::from_utf8(encode_list_json(&places[..2])).unwrap();
        // Oldest first; whole numbers without a fraction; one-space indent.
        assert_eq!(
            written,
            "{\n \"format\": \"kutupmap\",\n \"version\": 1,\n \"places\": [\n  {\n   \"id\": \"a\",\n   \"name\": \"Galata\",\n   \"note\": \"\",\n   \"lat\": 41.5,\n   \"lon\": 28.97,\n   \"addedBy\": \"\",\n   \"addedAt\": \"2026-10-13T10:00:00.000Z\"\n  },\n  {\n   \"id\": \"b\",\n   \"name\": \"Moda\",\n   \"note\": \"\",\n   \"lat\": 40.98,\n   \"lon\": 29,\n   \"addedBy\": \"\",\n   \"addedAt\": \"2026-10-13T11:00:00.000Z\"\n  }\n ]\n}"
        );
        assert_eq!(
            parse_list_json(written.as_bytes()).unwrap(),
            ordered(places[..2].to_vec())
        );
        assert!(parse_list_json(b"").unwrap().is_empty());
        // One bad place is dropped, not the list: an out-of-range number (as
        // JavaScript's Infinity) and a lone surrogate (kept, replaced).
        let odd = br#"{"format":"kutupmap","version":1,"places":[
            {"id":"inf","name":"Far","lat":1e400,"lon":0},
            {"id":"ls","name":"x\ud800y","lat":1,"lon":2},
            {"id":"ok","name":"Ok","lat":3,"lon":4}]}"#;
        let places = parse_list_json(odd).unwrap();
        let ids: Vec<_> = places.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["ls", "ok"]);
        assert_eq!(places[0].name, "x\u{fffd}y");
        assert!(parse_list_json(b"{\"format\":\"other\"}").is_err());
    }

    #[test]
    fn times_are_rfc_3339_with_a_real_day() {
        for good in [
            "2026-10-13T10:00:00Z",
            "2026-10-13T10:00:00.123Z",
            "2028-02-29T23:59:59+03:00",
            "2026-01-01T00:00:00-12:30",
        ] {
            assert!(valid_time(good), "{good}");
        }
        for bad in [
            "2026-10-13",
            "2026-10-13 10:00:00Z",
            "2026-10-13t10:00:00z",
            "2026-02-29T10:00:00Z",
            "2026-13-01T10:00:00Z",
            "2026-10-13T24:00:00Z",
            "2026-10-13T10:00:60Z",
            "2026-10-13T10:00:00.Z",
            "2026-10-13T10:00:00+24:00",
            "2026-10-13T10:00:00",
        ] {
            assert!(!valid_time(bad), "{bad}");
        }
    }

    #[test]
    fn an_upload_reads_as_the_web_reads_it() {
        let file = "11111111-1111-4111-8111-111111111111";
        // A byte-order mark is dropped, as TextDecoder drops it.
        assert_eq!(text_of(b"\xef\xbb\xbfhello"), "hello");
        assert_eq!(
            seed_text_upload(file, b"\xef\xbb\xbfhi"),
            seed_text(file, "hi")
        );
        // Places without an id get the same one on every peer.
        let list = b"\xef\xbb\xbf{\"format\":\"kutupmap\",\"version\":1.0,\"places\":[{\"name\":\"A\",\"lat\":1,\"lon\":2}]}";
        let places = parse_list_json_with(list, |i| upload_place_id(file, i)).unwrap();
        assert_eq!(places[0].id, "11111111111141118111111111111111-0");
        assert_eq!(seed_list_upload(file, list), seed_list_upload(file, list));
    }

    #[test]
    fn a_saved_state_round_trips() {
        let doc = TextDoc::new(7);
        doc.apply_v1(&seed_text("f", "kept")).unwrap();
        let copy = TextDoc::new(8);
        copy.apply_v2(&doc.state_v2()).unwrap();
        assert_eq!(copy.text(), "kept");
    }
}
