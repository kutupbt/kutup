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

use similar::{capture_diff_slices, Algorithm, DiffOp};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, GetString, Map, MapPrelim, Options, ReadTxn, StateVector, Text, Transact, Update};

/// The text's name in the document (`doc.getText('content')` on the web).
pub const TEXT_NAME: &str = "content";

#[derive(Debug, thiserror::Error)]
pub enum CollabError {
    #[error("not a Yjs update: {0}")]
    Update(String),
}

pub type Result<T> = std::result::Result<T, CollabError>;

/// The Yjs client id a seed is made under: FNV-1a over the file id's UTF-16
/// code units, as the web computes it (`deterministicSeed`). Every peer
/// seeding the same file makes the same item.
pub fn seed_client_id(file_id: &str) -> u64 {
    let mut id: u32 = 0x811c_9dc5;
    for unit in file_id.encode_utf16() {
        id = (id ^ u32::from(unit)).wrapping_mul(0x0100_0193);
    }
    u64::from(id)
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
    let doc = Doc::with_options(options(seed_client_id(file_id)));
    let content = doc.get_or_insert_text(TEXT_NAME);
    {
        let mut txn = doc.transact_mut();
        content.insert(&mut txn, 0, text);
    }
    let update = doc
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    update
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
    /// `user@server` of whoever added it.
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
    let doc = Doc::with_options(options(seed_client_id(file_id)));
    let map = doc.get_or_insert_map(PLACES_NAME);
    {
        let mut txn = doc.transact_mut();
        for place in places {
            insert_place(&map, &mut txn, place);
        }
    }
    let update = doc
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    update
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

    #[test]
    fn a_saved_state_round_trips() {
        let doc = TextDoc::new(7);
        doc.apply_v1(&seed_text("f", "kept")).unwrap();
        let copy = TextDoc::new(8);
        copy.apply_v2(&doc.state_v2()).unwrap();
        assert_eq!(copy.text(), "kept");
    }
}
