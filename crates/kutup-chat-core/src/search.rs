//! The search index (`docs/research/16-browser-storage-architecture.md`,
//! Phase 3).
//!
//! An inverted index from words to history entries, kept in the store's
//! derived-index records beside the timelines and written in the same
//! transaction as the records it indexes ([`changes`], from the timeline's,
//! which each backend's `apply` calls). Words are folded first ([`fold`]):
//! İ, I, ı and i all become i, accents are removed and everything is
//! lowercased, so a search for "istanbul" finds "İstanbul" and "cagri"
//! finds "çağrı". A query word matches every indexed word it begins
//! ("kitap" finds "kitaplar").
//!
//! The layout is SQLite FTS5's (Signal Desktop's index), on sealed records.
//! History is split into 30-day periods ([`BUCKET_MS`]). In each period an
//! entry gets a small number and is stored once, in a document chunk
//! ([`Doc`], [`DOC_CHUNK`] per record): its conversation (a position in the
//! directory's list), record, time, message id and target. Words are grouped
//! into shards by their first [`SHARD_CHARS`] characters within a period;
//! a shard maps each word to the ascending numbers of the documents holding
//! it, written as LEB128 differences, a byte or two per occurrence. The
//! directory lists each period's shards and chunks, so a shorter query word
//! finds every shard it can match.
//!
//! Splitting by period keeps writes bounded: a new message rewrites only its
//! period's chunk and its words' shards there. A query reads periods newest
//! first and stops once it has as many hits as asked, so most searches never
//! touch old periods; decoded records are kept between queries within
//! [`CACHE_BYTES`] ([`ShardCache`]), dropped as soon as the store changes.
//!
//! The index proposes candidates; it is not the last word. Besides the words
//! of an entry's text (and an edit's new text, under the edit itself), each
//! entry is indexed under its own message id and an edit or deletion under
//! the message it targets, so a query returns with its hits the entries
//! that edit or delete them ([`related`]). The client applies those, the
//! disappearing deadlines and its own matching before it shows anything.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::rc::Rc;

use kutup_chat_proto::ChatContent;
use serde::{Deserialize, Serialize};
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::db::{
    ChatDb, ImportedHistoryRecordV1, InboxMessage, MlsHistoryMessage, Pending, SentMessage,
};
use crate::error::{ChatError, Result};
use crate::timeline::{self, EntryRef, Indexed, Source, ROUTED};

/// Raised whenever what is indexed or how changes; a store with an older
/// directory is indexed again from its records.
pub(crate) const SEARCH_VERSION: u32 = 2;
/// Characters of a word that name its shard.
pub(crate) const SHARD_CHARS: usize = 3;
/// The period a shard covers (30 days).
pub(crate) const BUCKET_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Encoded size of the decoded records kept between queries.
pub(crate) const CACHE_BYTES: usize = 4 * 1024 * 1024;
/// Longer words are cut to this many characters (a query word is too).
const MAX_WORD_CHARS: usize = 64;
const DIRECTORY_KEY: &[u8] = b"search/directory";
/// Terms that are not words start with a control character, which [`words`]
/// never yields.
const MESSAGE_TERM: char = '\u{1}';
const TARGET_TERM: char = '\u{2}';

/// Folds text for searching: Turkish dotted and dotless I to i, accents
/// removed (canonical decomposition, combining marks dropped), lowercase.
pub fn fold(text: &str) -> String {
    let turkish: String = text
        .chars()
        .map(|c| match c {
            'İ' | 'I' | 'ı' => 'i',
            other => other,
        })
        .collect();
    turkish
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .collect()
}

/// The distinct folded words of `text`: runs of letters and digits.
pub fn words(text: &str) -> Vec<String> {
    let folded = fold(text);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for word in folded.split(|c: char| !c.is_alphanumeric()) {
        if word.is_empty() {
            continue;
        }
        let word: String = word.chars().take(MAX_WORD_CHARS).collect();
        if seen.insert(word.clone()) {
            out.push(word);
        }
    }
    out
}

/// One indexed entry, as a shard holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posting {
    /// The conversation's key ([`kutup_chat_proto::ConversationId::key`]).
    pub conversation: String,
    pub source: Source,
    pub id: String,
    pub ts: i64,
    /// The entry's own message id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// For an edit or deletion, the message it acts on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl Posting {
    fn identity(&self) -> (Source, &str) {
        (self.source, &self.id)
    }

    /// Where the timeline keeps it.
    pub fn entry(&self) -> EntryRef {
        EntryRef {
            ts: self.ts,
            source: self.source,
            id: self.id.clone(),
            flags: 0,
        }
    }
}

/// A period's word lists: each word and the numbers of the period's
/// documents holding it, ascending, each written as its difference from the
/// one before (LEB128, [`encode_numbers`]): a byte or two per occurrence.
type Shard = BTreeMap<String, Vec<u8>>;

/// One indexed entry, stored once in its period ([`DocChunk`]): its
/// conversation (a position in the directory's list), where its record is,
/// when, its message id and, for an edit or deletion, the message it acts
/// on. Encoded as a plain list, without field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Doc(u32, Source, String, i64, Option<String>, Option<String>);

/// Up to [`DOC_CHUNK`] of a period's documents, by number; a removed one
/// is absent (numbers are never handed out twice).
type DocChunk = BTreeMap<u32, Doc>;

/// Documents per chunk record.
const DOC_CHUNK: u32 = 256;

/// What the directory knows of one period.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Period {
    /// The number the next document gets.
    next: u32,
    /// The word prefixes it has a shard for.
    shards: BTreeSet<String>,
    /// The document chunks it has.
    chunks: BTreeSet<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Directory {
    version: u32,
    /// Every conversation key once; documents name them by position.
    #[serde(default)]
    conversations: Vec<String>,
    #[serde(default)]
    periods: BTreeMap<i64, Period>,
}

impl Directory {
    fn posting(&self, doc: &Doc) -> Posting {
        Posting {
            conversation: self
                .conversations
                .get(doc.0 as usize)
                .cloned()
                .unwrap_or_default(),
            source: doc.1,
            id: doc.2.clone(),
            ts: doc.3,
            message: doc.4.clone(),
            target: doc.5.clone(),
        }
    }
}

fn prefix(term: &str) -> String {
    term.chars().take(SHARD_CHARS).collect()
}

fn period_of(ts: i64) -> i64 {
    ts.div_euclid(BUCKET_MS)
}

fn shard_key(prefix: &str, period: i64) -> Vec<u8> {
    let mut key = b"search/shard\0".to_vec();
    key.extend_from_slice(&period.to_be_bytes());
    key.extend_from_slice(prefix.as_bytes());
    key
}

fn chunk_key(period: i64, chunk: u32) -> Vec<u8> {
    let mut key = b"search/docs\0".to_vec();
    key.extend_from_slice(&period.to_be_bytes());
    key.extend_from_slice(&chunk.to_be_bytes());
    key
}

/// Ascending numbers as LEB128 differences.
fn encode_numbers(numbers: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(numbers.len() * 2);
    let mut previous = 0u32;
    for (i, &number) in numbers.iter().enumerate() {
        let mut delta = if i == 0 { number } else { number - previous };
        previous = number;
        loop {
            let byte = (delta & 0x7f) as u8;
            delta >>= 7;
            if delta == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
    out
}

fn decode_numbers(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut current = 0u32;
    let mut value = 0u32;
    let mut shift = 0u32;
    for &byte in bytes {
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            current = if out.is_empty() {
                value
            } else {
                current + value
            };
            out.push(current);
            value = 0;
            shift = 0;
        } else {
            shift += 7;
        }
    }
    out
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)
        .map_err(|error| ChatError::Db(format!("search index encode: {error}")))?;
    Ok(out)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes)
        .map_err(|error| ChatError::Db(format!("search index decode: {error}")))
}

/// The text a person can search an entry by: its text, an attachment's name
/// and caption, a place's label, an edit's new text.
fn searchable(content: &ChatContent) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(text) = content.as_text() {
        parts.push(text.text);
    }
    if let Some(attachment) = content.as_attachment() {
        parts.push(attachment.filename);
        parts.extend(attachment.caption);
    }
    if let Some(location) = content.as_location() {
        parts.extend(location.label);
    }
    if let Some(mutation) = content.as_message_mutation() {
        parts.extend(mutation.replacement_text);
    }
    parts.join("\n")
}

/// An entry and the terms it is indexed under.
struct Document {
    posting: Posting,
    terms: Vec<String>,
}

/// The document for a record placed in the timeline: indexed under its own
/// conversation only (a routed control carries no searchable text), and
/// nothing for a record the history leaves out or that does not decode.
fn document(placed: Vec<Indexed>, content: &[u8]) -> Option<Document> {
    let own = placed
        .into_iter()
        .find(|indexed| indexed.entry.flags & ROUTED == 0)?;
    let content: ChatContent = serde_json::from_slice(content).ok()?;
    let target = content
        .as_message_mutation()
        .map(|mutation| mutation.target_message_id);
    let mut terms = words(&searchable(&content));
    if let Some(message) = &content.message_id {
        terms.push(format!("{MESSAGE_TERM}{message}"));
    }
    if let Some(target) = &target {
        terms.push(format!("{TARGET_TERM}{target}"));
    }
    if terms.is_empty() {
        return None;
    }
    Some(Document {
        posting: Posting {
            conversation: own.conversation.key(),
            source: own.entry.source,
            id: own.entry.id,
            ts: own.entry.ts,
            message: content.message_id,
            target,
        },
        terms,
    })
}

fn inbox_document(message: &InboxMessage) -> Result<Option<Document>> {
    Ok(document(timeline::place_inbox(message)?, &message.content))
}

fn sent_document(message: &SentMessage) -> Result<Option<Document>> {
    Ok(document(timeline::place_sent(message)?, &message.content))
}

fn mls_document(message: &MlsHistoryMessage) -> Option<Document> {
    document(timeline::place_mls(message), &message.content)
}

fn imported_document(message: &ImportedHistoryRecordV1) -> Option<Document> {
    document(timeline::place_imported(message), &message.content)
}

/// Shards and document chunks read and changed for one commit.
struct Writer<'a> {
    db: &'a dyn ChatDb,
    directory: Directory,
    shards: HashMap<(String, i64), Shard>,
    chunks: HashMap<(i64, u32), DocChunk>,
}

impl<'a> Writer<'a> {
    fn new(db: &'a dyn ChatDb, directory: Directory) -> Self {
        Writer {
            db,
            directory,
            shards: HashMap::new(),
            chunks: HashMap::new(),
        }
    }

    fn conversation(&mut self, key: &str) -> u32 {
        let position = match self
            .directory
            .conversations
            .iter()
            .position(|known| known == key)
        {
            Some(position) => position,
            None => {
                self.directory.conversations.push(key.to_string());
                self.directory.conversations.len() - 1
            }
        };
        u32::try_from(position).unwrap_or(u32::MAX)
    }

    async fn shard(&mut self, prefix: &str, period: i64) -> Result<&mut Shard> {
        let key = (prefix.to_string(), period);
        if !self.shards.contains_key(&key) {
            let listed = self
                .directory
                .periods
                .get(&period)
                .is_some_and(|known| known.shards.contains(prefix));
            let shard = match listed {
                true => match self.db.load_index_value(&shard_key(prefix, period)).await? {
                    Some(bytes) => decode(&bytes)?,
                    None => Shard::new(),
                },
                false => Shard::new(),
            };
            self.shards.insert(key.clone(), shard);
        }
        Ok(self.shards.get_mut(&key).expect("loaded above"))
    }

    async fn chunk(&mut self, period: i64, chunk: u32) -> Result<&mut DocChunk> {
        let key = (period, chunk);
        if !self.chunks.contains_key(&key) {
            let listed = self
                .directory
                .periods
                .get(&period)
                .is_some_and(|known| known.chunks.contains(&chunk));
            let docs = match listed {
                true => match self.db.load_index_value(&chunk_key(period, chunk)).await? {
                    Some(bytes) => decode(&bytes)?,
                    None => DocChunk::new(),
                },
                false => DocChunk::new(),
            };
            self.chunks.insert(key, docs);
        }
        Ok(self.chunks.get_mut(&key).expect("loaded above"))
    }

    /// The number `document` has in its period, if it is indexed: looked up
    /// under its most particular term (its message id, when it has one).
    async fn find(&mut self, document: &Document) -> Result<Option<u32>> {
        let period = period_of(document.posting.ts);
        let Some(term) = document
            .terms
            .iter()
            .find(|term| term.starts_with(MESSAGE_TERM))
            .or_else(|| document.terms.first())
        else {
            return Ok(None);
        };
        let numbers = match self.shard(&prefix(term), period).await?.get(term) {
            Some(list) => decode_numbers(list),
            None => return Ok(None),
        };
        for number in numbers {
            let docs = self.chunk(period, number / DOC_CHUNK).await?;
            if docs
                .get(&number)
                .is_some_and(|doc| doc.1 == document.posting.source && doc.2 == document.posting.id)
            {
                return Ok(Some(number));
            }
        }
        Ok(None)
    }

    async fn add(&mut self, document: &Document) -> Result<()> {
        // A record written again (a delivery confirmed) is indexed once.
        if self.find(document).await?.is_some() {
            return Ok(());
        }
        let posting = &document.posting;
        let period = period_of(posting.ts);
        let conversation = self.conversation(&posting.conversation);
        let number = {
            let known = self.directory.periods.entry(period).or_default();
            let number = known.next;
            known.next += 1;
            number
        };
        self.chunk(period, number / DOC_CHUNK).await?.insert(
            number,
            Doc(
                conversation,
                posting.source,
                posting.id.clone(),
                posting.ts,
                posting.message.clone(),
                posting.target.clone(),
            ),
        );
        for term in &document.terms {
            let list = self
                .shard(&prefix(term), period)
                .await?
                .entry(term.clone())
                .or_default();
            // The newest number of the period: it goes last.
            let mut numbers = decode_numbers(list);
            numbers.push(number);
            *list = encode_numbers(&numbers);
        }
        Ok(())
    }

    async fn remove(&mut self, document: &Document) -> Result<()> {
        let Some(number) = self.find(document).await? else {
            return Ok(());
        };
        let period = period_of(document.posting.ts);
        self.chunk(period, number / DOC_CHUNK)
            .await?
            .remove(&number);
        for term in &document.terms {
            let shard = self.shard(&prefix(term), period).await?;
            if let Some(list) = shard.get_mut(term) {
                let mut numbers = decode_numbers(list);
                numbers.retain(|known| *known != number);
                if numbers.is_empty() {
                    shard.remove(term);
                } else {
                    *list = encode_numbers(&numbers);
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>> {
        let mut writes = HashMap::new();
        for ((prefix, period), shard) in self.shards {
            let known = self.directory.periods.entry(period).or_default();
            if shard.is_empty() {
                known.shards.remove(&prefix);
                writes.insert(shard_key(&prefix, period), None);
            } else {
                writes.insert(shard_key(&prefix, period), Some(encode(&shard)?));
                known.shards.insert(prefix);
            }
        }
        for ((period, chunk), docs) in self.chunks {
            let known = self.directory.periods.entry(period).or_default();
            if docs.is_empty() {
                known.chunks.remove(&chunk);
                writes.insert(chunk_key(period, chunk), None);
            } else {
                writes.insert(chunk_key(period, chunk), Some(encode(&docs)?));
                known.chunks.insert(chunk);
            }
        }
        self.directory
            .periods
            .retain(|_, known| !known.shards.is_empty() || !known.chunks.is_empty());
        writes.insert(DIRECTORY_KEY.to_vec(), Some(encode(&self.directory)?));
        Ok(writes)
    }
}

async fn load_directory(db: &dyn ChatDb) -> Result<Option<Directory>> {
    db.load_index_value(DIRECTORY_KEY)
        .await?
        .map(|bytes| decode(&bytes))
        .transpose()
}

/// The record keys an index of any version holds besides its directory, to
/// remove before it is built again.
fn index_keys(directory_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    /// Version 1 named shards by "prefix\u{1f}period" under `search/shard\0`.
    #[derive(Deserialize)]
    struct First {
        #[serde(default)]
        shards: BTreeMap<String, ciborium::Value>,
    }
    let first: First = decode(directory_bytes)?;
    let mut keys: Vec<Vec<u8>> = first
        .shards
        .keys()
        .map(|name| [b"search/shard\0".as_slice(), name.as_bytes()].concat())
        .collect();
    let current: Directory = decode(directory_bytes)?;
    for (&period, known) in &current.periods {
        keys.extend(known.shards.iter().map(|prefix| shard_key(prefix, period)));
        keys.extend(known.chunks.iter().map(|&chunk| chunk_key(period, chunk)));
    }
    Ok(keys)
}

/// Index writes for `pending`, to commit with it. Nothing while the store
/// has no current directory (it is indexed whole on open, [`ensure_built`]).
pub(crate) async fn changes(
    db: &dyn ChatDb,
    pending: &Pending,
) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>> {
    let mut added: Vec<Document> = Vec::new();
    for message in &pending.messages {
        added.extend(inbox_document(message)?);
    }
    for message in pending.sent_messages.values() {
        added.extend(sent_document(message)?);
    }
    for message in pending.mls_messages.values() {
        added.extend(mls_document(message));
    }
    for message in pending.imported_history.values() {
        added.extend(imported_document(message));
    }
    let nothing_removed = pending.delete_message_ids.is_empty()
        && pending.delete_messages_for_peers.is_empty()
        && pending.delete_sent_message_ids.is_empty()
        && pending.delete_mls_message_ids.is_empty()
        && pending.delete_imported_history_ids.is_empty();
    if added.is_empty() && nothing_removed {
        return Ok(HashMap::new());
    }
    let Some(directory) = load_directory(db).await? else {
        return Ok(HashMap::new());
    };
    if directory.version != SEARCH_VERSION {
        return Ok(HashMap::new());
    }
    let mut removed: Vec<Document> = Vec::new();
    for id in &pending.delete_message_ids {
        if let Some(message) = db.load_message(id).await? {
            removed.extend(inbox_document(&message)?);
        }
    }
    if !pending.delete_messages_for_peers.is_empty() {
        // Rare (a contact is forgotten): read that peer's messages whole.
        let peers: HashSet<&String> = pending.delete_messages_for_peers.iter().collect();
        for message in db.list_messages().await? {
            if peers.contains(&message.peer) {
                removed.extend(inbox_document(&message)?);
            }
        }
    }
    for id in &pending.delete_sent_message_ids {
        if let Some(message) = db.load_sent_message(id).await? {
            removed.extend(sent_document(&message)?);
        }
    }
    for id in &pending.delete_mls_message_ids {
        if let Some(message) = db.load_mls_message(id).await? {
            removed.extend(mls_document(&message));
        }
    }
    for (transfer_id, source_record_id) in &pending.delete_imported_history_ids {
        if let Some(message) = db
            .load_imported_history(transfer_id, source_record_id)
            .await?
        {
            removed.extend(imported_document(&message));
        }
    }
    let mut writer = Writer::new(db, directory);
    for document in &removed {
        writer.remove(document).await?;
    }
    for document in &added {
        writer.add(document).await?;
    }
    writer.finish()
}

/// Index the whole store when it has no current directory: on first open
/// after this was added, and after [`SEARCH_VERSION`] moves on. Each
/// period's documents are numbered in time order.
pub(crate) async fn ensure_built(db: &dyn ChatDb) -> Result<()> {
    let existing = db.load_index_value(DIRECTORY_KEY).await?;
    if let Some(bytes) = &existing {
        if decode::<Directory>(bytes).is_ok_and(|directory| directory.version == SEARCH_VERSION) {
            return Ok(());
        }
    }
    let mut pending = Pending::default();
    if let Some(bytes) = &existing {
        for key in index_keys(bytes)? {
            pending.index_values.insert(key, None);
        }
    }
    let mut documents: Vec<Document> = Vec::new();
    for message in db.list_messages().await? {
        documents.extend(inbox_document(&message)?);
    }
    for message in db.list_sent_messages().await? {
        documents.extend(sent_document(&message)?);
    }
    for message in db.list_mls_messages().await? {
        documents.extend(mls_document(&message));
    }
    for message in db.list_imported_history().await? {
        documents.extend(imported_document(&message));
    }
    documents.sort_by(|left, right| {
        (left.posting.ts, left.posting.source, &left.posting.id).cmp(&(
            right.posting.ts,
            right.posting.source,
            &right.posting.id,
        ))
    });
    documents.dedup_by(|left, right| left.posting.identity() == right.posting.identity());

    let mut directory = Directory {
        version: SEARCH_VERSION,
        ..Directory::default()
    };
    let mut conversations: HashMap<String, u32> = HashMap::new();
    let mut shards: BTreeMap<(String, i64), BTreeMap<String, Vec<u32>>> = BTreeMap::new();
    let mut chunks: BTreeMap<(i64, u32), DocChunk> = BTreeMap::new();
    for document in &documents {
        let posting = &document.posting;
        let period = period_of(posting.ts);
        let conversation = *conversations
            .entry(posting.conversation.clone())
            .or_insert_with(|| {
                directory.conversations.push(posting.conversation.clone());
                u32::try_from(directory.conversations.len() - 1).unwrap_or(u32::MAX)
            });
        let known = directory.periods.entry(period).or_default();
        let number = known.next;
        known.next += 1;
        chunks
            .entry((period, number / DOC_CHUNK))
            .or_default()
            .insert(
                number,
                Doc(
                    conversation,
                    posting.source,
                    posting.id.clone(),
                    posting.ts,
                    posting.message.clone(),
                    posting.target.clone(),
                ),
            );
        for term in &document.terms {
            shards
                .entry((prefix(term), period))
                .or_default()
                .entry(term.clone())
                .or_default()
                .push(number);
        }
    }
    for ((prefix, period), words) in shards {
        let shard: Shard = words
            .into_iter()
            .map(|(term, numbers)| (term, encode_numbers(&numbers)))
            .collect();
        pending
            .index_values
            .insert(shard_key(&prefix, period), Some(encode(&shard)?));
        directory
            .periods
            .entry(period)
            .or_default()
            .shards
            .insert(prefix);
    }
    for ((period, chunk), docs) in chunks {
        pending
            .index_values
            .insert(chunk_key(period, chunk), Some(encode(&docs)?));
        directory
            .periods
            .entry(period)
            .or_default()
            .chunks
            .insert(chunk);
    }
    pending
        .index_values
        .insert(DIRECTORY_KEY.to_vec(), Some(encode(&directory)?));
    db.apply(&pending).await
}

/// A decoded record the cache keeps.
enum Cached {
    Shard(Shard),
    Docs(DocChunk),
}

/// Decoded shards and document chunks kept between queries, within
/// [`CACHE_BYTES`] of encoded size, valid for one store state: any commit
/// clears them.
pub struct ShardCache {
    commits: Option<u64>,
    budget: usize,
    held: usize,
    records: HashMap<Vec<u8>, (Rc<Cached>, usize)>,
    order: VecDeque<Vec<u8>>,
}

impl Default for ShardCache {
    fn default() -> Self {
        Self::with_budget(CACHE_BYTES)
    }
}

impl ShardCache {
    fn with_budget(budget: usize) -> Self {
        ShardCache {
            commits: None,
            budget,
            held: 0,
            records: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    async fn record(
        &mut self,
        db: &dyn ChatDb,
        key: Vec<u8>,
        decode_as: fn(&[u8]) -> Result<Cached>,
        empty: fn() -> Cached,
    ) -> Result<Rc<Cached>> {
        let commits = db.commit_count();
        if self.commits != Some(commits) {
            self.commits = Some(commits);
            self.records.clear();
            self.order.clear();
            self.held = 0;
        }
        if let Some((record, _)) = self.records.get(&key) {
            let record = record.clone();
            self.order.retain(|cached| *cached != key);
            self.order.push_back(key);
            return Ok(record);
        }
        let (record, size) = match db.load_index_value(&key).await? {
            Some(bytes) => (Rc::new(decode_as(&bytes)?), bytes.len()),
            None => (Rc::new(empty()), 0),
        };
        self.records.insert(key.clone(), (record.clone(), size));
        self.order.push_back(key);
        self.held += size;
        while self.held > self.budget && self.order.len() > 1 {
            if let Some(oldest) = self.order.pop_front() {
                if let Some((_, size)) = self.records.remove(&oldest) {
                    self.held -= size;
                }
            }
        }
        Ok(record)
    }

    async fn shard(&mut self, db: &dyn ChatDb, prefix: &str, period: i64) -> Result<Rc<Cached>> {
        self.record(
            db,
            shard_key(prefix, period),
            |bytes| Ok(Cached::Shard(decode(bytes)?)),
            || Cached::Shard(Shard::new()),
        )
        .await
    }

    async fn docs(&mut self, db: &dyn ChatDb, period: i64, chunk: u32) -> Result<Rc<Cached>> {
        self.record(
            db,
            chunk_key(period, chunk),
            |bytes| Ok(Cached::Docs(decode(bytes)?)),
            || Cached::Docs(DocChunk::new()),
        )
        .await
    }

    /// The postings for `numbers` of `period`.
    async fn postings(
        &mut self,
        db: &dyn ChatDb,
        directory: &Directory,
        period: i64,
        numbers: impl IntoIterator<Item = u32>,
    ) -> Result<Vec<Posting>> {
        let mut out = Vec::new();
        for number in numbers {
            if let Cached::Docs(docs) = &*self.docs(db, period, number / DOC_CHUNK).await? {
                out.extend(docs.get(&number).map(|doc| directory.posting(doc)));
            }
        }
        Ok(out)
    }
}

/// The entries every word of `text` matches the start of a word in, newest
/// first, at most `limit`. Periods are read newest first, and no further
/// than the limit needs. Nothing for a query with no words, or while the
/// store is not indexed yet.
pub(crate) async fn query(
    db: &dyn ChatDb,
    cache: &mut ShardCache,
    text: &str,
    limit: usize,
) -> Result<Vec<Posting>> {
    let query = words(text);
    if query.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }
    let Some(directory) = load_directory(db).await? else {
        return Ok(Vec::new());
    };
    if directory.version != SEARCH_VERSION {
        return Ok(Vec::new());
    }
    let mut hits: Vec<Posting> = Vec::new();
    for (&period, known) in directory.periods.iter().rev() {
        let mut matched: Option<BTreeSet<u32>> = None;
        for word in &query {
            // A word of at least SHARD_CHARS characters lives under its own
            // prefix; a shorter one under every prefix it begins.
            let prefixes: Vec<&String> = if word.chars().count() >= SHARD_CHARS {
                known.shards.get(&prefix(word)).into_iter().collect()
            } else {
                known
                    .shards
                    .iter()
                    .filter(|candidate| candidate.starts_with(word.as_str()))
                    .collect()
            };
            let mut found = BTreeSet::new();
            for candidate in prefixes {
                if let Cached::Shard(shard) = &*cache.shard(db, candidate, period).await? {
                    for (term, list) in shard.range(word.clone()..) {
                        if !term.starts_with(word.as_str()) {
                            break;
                        }
                        found.extend(decode_numbers(list));
                    }
                }
            }
            let now: BTreeSet<u32> = match matched {
                None => found,
                Some(previous) => previous.intersection(&found).copied().collect(),
            };
            let empty = now.is_empty();
            matched = Some(now);
            if empty {
                break;
            }
        }
        let numbers = matched.unwrap_or_default();
        hits.extend(cache.postings(db, &directory, period, numbers).await?);
        // Every older period is older than every hit so far.
        if hits.len() >= limit {
            break;
        }
    }
    hits.sort_by(|left, right| right.ts.cmp(&left.ts).then_with(|| right.id.cmp(&left.id)));
    hits.truncate(limit);
    Ok(hits)
}

/// For `hits`, the entries that edit or delete them and, for an edit, the
/// message it edits: what the client needs to show each hit as it stands.
pub(crate) async fn related(
    db: &dyn ChatDb,
    cache: &mut ShardCache,
    hits: &[Posting],
) -> Result<Vec<Posting>> {
    let mut terms: BTreeSet<String> = BTreeSet::new();
    for hit in hits {
        if let Some(message) = &hit.message {
            terms.insert(format!("{TARGET_TERM}{message}"));
        }
        if let Some(target) = &hit.target {
            terms.insert(format!("{MESSAGE_TERM}{target}"));
            terms.insert(format!("{TARGET_TERM}{target}"));
        }
    }
    let Some(directory) = load_directory(db).await? else {
        return Ok(Vec::new());
    };
    let known: HashSet<(Source, &str)> = hits.iter().map(Posting::identity).collect();
    let mut found: HashMap<(Source, String), Posting> = HashMap::new();
    for (&period, info) in &directory.periods {
        let mut numbers = BTreeSet::new();
        for term in &terms {
            let wanted = prefix(term);
            if !info.shards.contains(&wanted) {
                continue;
            }
            if let Cached::Shard(shard) = &*cache.shard(db, &wanted, period).await? {
                numbers.extend(
                    shard
                        .get(term)
                        .map(|list| decode_numbers(list))
                        .unwrap_or_default(),
                );
            }
        }
        for posting in cache.postings(db, &directory, period, numbers).await? {
            if !known.contains(&posting.identity()) {
                found.insert((posting.source, posting.id.clone()), posting);
            }
        }
    }
    Ok(found.into_values().collect())
}

/// How big the index is: its records (the directory included), their
/// bytes before sealing, and the largest one.
#[cfg(any(test, feature = "bench"))]
pub(crate) async fn stats(db: &dyn ChatDb) -> Result<(usize, usize, usize)> {
    let Some(bytes) = db.load_index_value(DIRECTORY_KEY).await? else {
        return Ok((0, 0, 0));
    };
    let mut sizes = vec![bytes.len()];
    for key in index_keys(&bytes)? {
        sizes.extend(db.load_index_value(&key).await?.map(|value| value.len()));
    }
    Ok((
        sizes.len(),
        sizes.iter().sum(),
        sizes.iter().copied().max().unwrap_or(0),
    ))
}

/// Removes the whole index, as if the store had never been indexed.
#[cfg(any(test, feature = "bench"))]
pub(crate) async fn clear(db: &dyn ChatDb) -> Result<()> {
    let Some(bytes) = db.load_index_value(DIRECTORY_KEY).await? else {
        return Ok(());
    };
    let mut pending = Pending::default();
    for key in index_keys(&bytes)? {
        pending.index_values.insert(key, None);
    }
    pending.index_values.insert(DIRECTORY_KEY.to_vec(), None);
    db.apply(&pending).await
}

/// A fixed workload and measurement, the same natively (the ignored
/// `scale` test) and in a browser (`benchSearchIndex`, `bench` feature), so
/// changes to the index can be compared on both.
#[cfg(any(test, feature = "bench"))]
pub(crate) mod bench {
    use super::*;

    /// One query's answer: what was asked, how many hits, and how long a
    /// first (cold cache) and a second (warm) run took, in milliseconds.
    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct QueryTime {
        pub query: String,
        pub hits: usize,
        pub cold_ms: f64,
        pub warm_ms: f64,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Report {
        pub messages: usize,
        /// All messages written with their index, in batches of [`BATCH`].
        pub written_ms: f64,
        pub slowest_batch_ms: f64,
        /// The whole history indexed at once, as on first open.
        pub rebuild_ms: f64,
        /// One more message written with its index.
        pub one_write_ms: f64,
        pub records: usize,
        pub bytes: usize,
        pub largest_record: usize,
        pub queries: Vec<QueryTime>,
    }

    pub const BATCH: usize = 100;
    const SPAN_MS: i64 = 2 * 365 * 24 * 60 * 60 * 1000;
    const COMMON: [&str; 8] = ["bir", "ve", "bu", "da", "için", "ama", "çok", "ne"];

    /// 2,000 made-up words with Turkish letters.
    fn vocabulary() -> Vec<String> {
        let syllables = [
            "ka", "le", "mi", "to", "ru", "sa", "ne", "bi", "ço", "ğü", "şa", "ır",
        ];
        (0..2_000)
            .map(|i| {
                let mut word = String::new();
                let mut n = i * 7 + 3;
                for _ in 0..(2 + i % 3) {
                    word.push_str(syllables[n % syllables.len()]);
                    n /= syllables.len();
                    n += i;
                }
                word
            })
            .collect()
    }

    fn content(id: &str, body: &str) -> Vec<u8> {
        serde_json::to_vec(&ChatContent::text_with_id(
            id,
            "2026-10-08T10:00:00Z",
            1,
            body,
        ))
        .expect("a text message encodes")
    }

    /// `count` messages over two years among 40 people: six words from the
    /// vocabulary and two common ones each, the same every time.
    pub fn messages(count: usize) -> Vec<InboxMessage> {
        let vocabulary = vocabulary();
        let mut seed: u64 = 42;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        (0..count)
            .map(|n| {
                let mut words: Vec<&str> = (0..6)
                    .map(|_| vocabulary[next() % vocabulary.len()].as_str())
                    .collect();
                words.push(COMMON[next() % COMMON.len()]);
                words.push(COMMON[next() % COMMON.len()]);
                let ts = (n as i64) * (SPAN_MS / count as i64);
                InboxMessage {
                    id: format!("in-{n}"),
                    peer: format!("peer{}@a.test", next() % 40),
                    sender_device_id: 1,
                    cursor: n as u64,
                    content: content(&format!("m-{n}"), &words.join(" ")),
                    received_at: ts,
                }
            })
            .collect()
    }

    /// Writes [`messages`] into an empty `db` and measures, with `now` a
    /// millisecond clock.
    pub async fn run(db: &dyn ChatDb, count: usize, now: impl Fn() -> f64) -> Result<Report> {
        crate::timeline::ensure_built(db).await?;
        let all = messages(count);
        let started = now();
        let mut slowest_batch_ms: f64 = 0.0;
        for batch in all.chunks(BATCH) {
            let mut pending = Pending::default();
            pending.messages.extend(batch.iter().cloned());
            let t = now();
            db.apply(&pending).await?;
            slowest_batch_ms = slowest_batch_ms.max(now() - t);
        }
        let written_ms = now() - started;
        let (records, bytes, largest_record) = stats(db).await?;

        clear(db).await?;
        let t = now();
        ensure_built(db).await?;
        let rebuild_ms = now() - t;

        let mut pending = Pending::default();
        pending.messages.push(InboxMessage {
            id: "last".into(),
            peer: "peer1@a.test".into(),
            sender_device_id: 1,
            cursor: count as u64,
            content: content("m-last", "bir yeni mesaj"),
            received_at: SPAN_MS,
        });
        let t = now();
        db.apply(&pending).await?;
        let one_write_ms = now() - t;

        let vocabulary = vocabulary();
        let rare = vocabulary[17].clone();
        let mut queries = Vec::new();
        for text in [
            "bir".to_string(),
            "bi".to_string(),
            rare.clone(),
            format!("{rare} bir"),
            "zzzz".to_string(),
        ] {
            // As a search does: the hits, then what edits or deletes them.
            let mut cache = ShardCache::default();
            let t = now();
            let found = query(db, &mut cache, &text, 200).await?;
            related(db, &mut cache, &found).await?;
            let cold_ms = now() - t;
            let hits = found.len();
            let t = now();
            let found = query(db, &mut cache, &text, 200).await?;
            related(db, &mut cache, &found).await?;
            let warm_ms = now() - t;
            queries.push(QueryTime {
                query: text,
                hits,
                cold_ms,
                warm_ms,
            });
        }
        Ok(Report {
            messages: count,
            written_ms,
            slowest_batch_ms,
            rebuild_ms,
            one_write_ms,
            records,
            bytes,
            largest_record,
            queries,
        })
    }
}

#[cfg(test)]
mod fold_tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        input: String,
        folded: String,
        words: Vec<String>,
    }

    #[test]
    fn folding_matches_the_shared_vectors() {
        let vectors: Vectors =
            serde_json::from_str(include_str!("../tests/vectors/search_fold.json")).unwrap();
        for case in vectors.cases {
            assert_eq!(fold(&case.input), case.folded, "fold {:?}", case.input);
            assert_eq!(words(&case.input), case.words, "words {:?}", case.input);
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::SqliteChatDb;
    use futures_executor::block_on;
    use kutup_chat_proto::content::kind;

    fn text(id: &str, body: &str) -> Vec<u8> {
        serde_json::to_vec(&ChatContent::text_with_id(
            id,
            "2026-10-08T10:00:00Z",
            1,
            body,
        ))
        .unwrap()
    }

    fn mutation(id: &str, target: &str, replacement: Option<&str>) -> Vec<u8> {
        let mut content = ChatContent::text_with_id(id, "2026-10-08T10:00:00Z", 1, "");
        content.kind = kind::MESSAGE_MUTATION.to_string();
        content.body = match replacement {
            Some(text) => {
                serde_json::json!({"targetMessageId": target, "operation": "edit", "replacementText": text})
            }
            None => serde_json::json!({"targetMessageId": target, "operation": "delete"}),
        };
        serde_json::to_vec(&content).unwrap()
    }

    fn inbox(id: &str, peer: &str, ts: i64, content: Vec<u8>) -> InboxMessage {
        InboxMessage {
            id: id.into(),
            peer: peer.into(),
            sender_device_id: 1,
            cursor: ts as u64,
            content,
            received_at: ts,
        }
    }

    fn sent(id: &str, peer: &str, ts: i64, content: Vec<u8>) -> SentMessage {
        SentMessage {
            send_id: id.into(),
            peer: peer.into(),
            sender_device_id: 1,
            content,
            created_at: ts,
            delivered_at: None,
            delivered: false,
            deduplicated: false,
        }
    }

    fn group(id: &str, ts: i64, content: Vec<u8>) -> MlsHistoryMessage {
        MlsHistoryMessage {
            record_id: id.into(),
            message_id: id.into(),
            conversation_id: [7; 16],
            incarnation: 1,
            mls_group_id: vec![1; 16],
            epoch: 1,
            sender: "carol@a.test".into(),
            sender_device_id: 1,
            outgoing: false,
            cursor: Some(ts as u64),
            transport_digest: [0; 32],
            content,
            timestamp_ms: ts,
            delivered: true,
            deduplicated: false,
        }
    }

    type Snapshot = BTreeMap<String, BTreeSet<(Source, String)>>;

    /// Every term and what it points to, after checking the directory
    /// describes the shards.
    fn indexed(db: &SqliteChatDb) -> Snapshot {
        let directory = block_on(load_directory(db)).unwrap().unwrap();
        assert_eq!(directory.version, SEARCH_VERSION);
        let mut out = Snapshot::new();
        let mut referenced: BTreeSet<(i64, u32)> = BTreeSet::new();
        let mut stored: BTreeSet<(i64, u32)> = BTreeSet::new();
        for (&period, known) in &directory.periods {
            let mut docs = DocChunk::new();
            for &chunk in &known.chunks {
                let part: DocChunk = decode(
                    &block_on(db.load_index_value(&chunk_key(period, chunk)))
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert!(!part.is_empty(), "no empty chunk is kept");
                for (&number, doc) in &part {
                    assert_eq!(number / DOC_CHUNK, chunk, "in its chunk");
                    assert!(number < known.next, "numbered before next");
                    assert_eq!(period_of(doc.3), period, "in its period");
                    assert!((doc.0 as usize) < directory.conversations.len());
                    stored.insert((period, number));
                }
                docs.extend(part);
            }
            for prefix_name in &known.shards {
                let shard: Shard = decode(
                    &block_on(db.load_index_value(&shard_key(prefix_name, period)))
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                for (term, list) in shard {
                    assert_eq!(prefix(&term), *prefix_name, "in its prefix's shard");
                    let numbers = decode_numbers(&list);
                    assert!(!numbers.is_empty());
                    assert!(
                        numbers.windows(2).all(|pair| pair[0] < pair[1]),
                        "ascending, once each"
                    );
                    assert_eq!(encode_numbers(&numbers), list, "encoded as written");
                    let all = out.entry(term).or_default();
                    for number in numbers {
                        let doc = docs
                            .get(&number)
                            .expect("every number names a stored document");
                        referenced.insert((period, number));
                        assert!(all.insert((doc.1, doc.2.clone())), "an entry once per term");
                    }
                }
            }
        }
        assert_eq!(
            referenced, stored,
            "every stored document is under some term"
        );
        out
    }

    /// What a rebuild from the records would hold.
    fn expected(db: &SqliteChatDb) -> Snapshot {
        let mut documents = Vec::new();
        for message in block_on(db.list_messages()).unwrap() {
            documents.extend(inbox_document(&message).unwrap());
        }
        for message in block_on(db.list_sent_messages()).unwrap() {
            documents.extend(sent_document(&message).unwrap());
        }
        for message in block_on(db.list_mls_messages()).unwrap() {
            documents.extend(mls_document(&message));
        }
        let mut out = Snapshot::new();
        for document in documents {
            for term in document.terms {
                out.entry(term)
                    .or_default()
                    .insert((document.posting.source, document.posting.id.clone()));
            }
        }
        out
    }

    fn search(db: &SqliteChatDb, cache: &mut ShardCache, query_text: &str) -> Vec<String> {
        block_on(query(db, cache, query_text, 100))
            .unwrap()
            .into_iter()
            .map(|posting| posting.id)
            .collect()
    }

    #[test]
    fn the_index_written_with_each_commit_matches_a_rebuild() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        assert!(indexed(&db).is_empty());

        let words_pool = [
            "kitap",
            "Kitaplar",
            "İstanbul",
            "çağrı",
            "rapor",
            "toplantı",
            "yarın",
            "akşam",
        ];
        let mut pending = Pending::default();
        for i in 0..300i64 {
            let body = format!(
                "{} {} {i}",
                words_pool[i as usize % 8],
                words_pool[(i as usize * 3) % 8]
            );
            let peer = if i % 2 == 0 {
                "alice@a.test"
            } else {
                "bob@a.test"
            };
            pending.messages.push(inbox(
                &format!("in-{i}"),
                peer,
                1_000 + i,
                text(&format!("m-in-{i}"), &body),
            ));
        }
        for i in 0..20i64 {
            pending.mls_messages.insert(
                format!("g-{i}"),
                group(
                    &format!("g-{i}"),
                    2_000 + i,
                    text(&format!("m-g-{i}"), "grup toplantısı"),
                ),
            );
        }
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));

        // A sent message, then written again (delivered), an edit and a
        // deletion: still one posting each, as a rebuild has it.
        let mut pending = Pending::default();
        pending.sent_messages.insert(
            "out-1".into(),
            sent(
                "out-1",
                "alice@a.test",
                3_000,
                text("m-out-1", "Rapor hazır"),
            ),
        );
        pending.sent_messages.insert(
            "edit-1".into(),
            sent(
                "edit-1",
                "alice@a.test",
                3_001,
                mutation("m-edit-1", "m-out-1", Some("Rapor yarın hazır")),
            ),
        );
        block_on(db.apply(&pending)).unwrap();
        let mut again = Pending::default();
        let mut delivered = sent(
            "out-1",
            "alice@a.test",
            3_000,
            text("m-out-1", "Rapor hazır"),
        );
        delivered.delivered = true;
        again.sent_messages.insert("out-1".into(), delivered);
        block_on(db.apply(&again)).unwrap();
        assert_eq!(indexed(&db), expected(&db));

        // Deletions of each kind, and a forgotten contact.
        let mut pending = Pending::default();
        pending
            .delete_message_ids
            .extend(["in-0".to_string(), "in-2".to_string()]);
        pending.delete_mls_message_ids.insert("g-3".into());
        pending.delete_sent_message_ids.insert("edit-1".into());
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        let mut pending = Pending::default();
        pending
            .delete_messages_for_peers
            .insert("bob@a.test".into());
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert!(!indexed(&db).values().flatten().any(|(_, id)| id == "in-1"));
    }

    #[test]
    fn built_once_on_open_from_what_is_already_stored() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut pending = Pending::default();
        pending.messages.push(inbox(
            "in-1",
            "alice@a.test",
            1,
            text("m-1", "Merhaba dünya"),
        ));
        block_on(db.apply(&pending)).unwrap();
        assert!(
            block_on(load_directory(&db)).unwrap().is_none(),
            "nothing indexed before open"
        );
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert_eq!(
            search(&db, &mut ShardCache::default(), "dunya"),
            vec!["in-1"]
        );
    }

    #[test]
    fn queries_fold_match_word_starts_and_need_every_word() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        let mut pending = Pending::default();
        for (id, ts, body) in [
            ("a", 1, "İstanbul'da toplantı"),
            ("b", 2, "Çağrı yarın akşam"),
            ("c", 3, "kitaplar geldi"),
            ("d", 4, "red apple"),
            ("e", 5, "green apple"),
            ("f", 6, "ab abc abd"),
        ] {
            pending.messages.push(inbox(
                id,
                "alice@a.test",
                ts,
                text(&format!("m-{id}"), body),
            ));
        }
        block_on(db.apply(&pending)).unwrap();
        let mut cache = ShardCache::default();
        for query_text in ["istanbul", "ISTANBUL", "ıstanbul", "İSTAN"] {
            assert_eq!(
                search(&db, &mut cache, query_text),
                vec!["a"],
                "{query_text}"
            );
        }
        assert_eq!(search(&db, &mut cache, "cagri"), vec!["b"]);
        assert_eq!(search(&db, &mut cache, "kitap"), vec!["c"]);
        assert!(
            search(&db, &mut cache, "tap").is_empty(),
            "the middle of a word does not match"
        );
        assert_eq!(
            search(&db, &mut cache, "apple"),
            vec!["e", "d"],
            "newest first"
        );
        assert_eq!(search(&db, &mut cache, "app red"), vec!["d"], "every word");
        assert!(search(&db, &mut cache, "apple blue").is_empty());
        // "a" begins akşam, apple and ab (not "da" of İstanbul'da).
        assert_eq!(
            search(&db, &mut cache, "a"),
            vec!["f", "e", "d", "b"],
            "one letter reaches every shard it can"
        );
        assert!(search(&db, &mut cache, "   ").is_empty());
        let limited = block_on(query(&db, &mut cache, "apple", 1)).unwrap();
        assert_eq!(limited.len(), 1);

        // The cache never hides a newer commit.
        let mut pending = Pending::default();
        pending
            .messages
            .push(inbox("g", "alice@a.test", 7, text("m-g", "apple pie")));
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(search(&db, &mut cache, "apple"), vec!["g", "e", "d"]);
    }

    #[test]
    fn hits_come_with_what_edits_or_deletes_them() {
        // Mutations name their targets by message UUID.
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        let mut pending = Pending::default();
        pending.messages.push(inbox(
            "one",
            "alice@a.test",
            1,
            text("11111111-1111-4111-8111-111111111111", "eski metin"),
        ));
        pending.messages.push(inbox(
            "two",
            "alice@a.test",
            2,
            text("22222222-2222-4222-8222-222222222222", "silinecek metin"),
        ));
        pending.messages.push(inbox(
            "edit",
            "alice@a.test",
            3,
            mutation(
                "33333333-3333-4333-8333-333333333333",
                "11111111-1111-4111-8111-111111111111",
                Some("yeni metin"),
            ),
        ));
        pending.messages.push(inbox(
            "delete",
            "alice@a.test",
            4,
            mutation(
                "44444444-4444-4444-8444-444444444444",
                "22222222-2222-4222-8222-222222222222",
                None,
            ),
        ));
        block_on(db.apply(&pending)).unwrap();
        let mut cache = ShardCache::default();
        let ids = |postings: Vec<Posting>| -> BTreeSet<String> {
            postings.into_iter().map(|p| p.id).collect()
        };

        // The edit's new text finds the edit; the message it edits comes along.
        let hits = block_on(query(&db, &mut cache, "yeni", 100)).unwrap();
        assert_eq!(ids(hits.clone()), BTreeSet::from(["edit".to_string()]));
        assert_eq!(
            ids(block_on(related(&db, &mut cache, &hits)).unwrap()),
            BTreeSet::from(["one".to_string()])
        );

        // The original text finds the message; its edit comes along.
        let hits = block_on(query(&db, &mut cache, "eski", 100)).unwrap();
        assert_eq!(ids(hits.clone()), BTreeSet::from(["one".to_string()]));
        assert_eq!(
            ids(block_on(related(&db, &mut cache, &hits)).unwrap()),
            BTreeSet::from(["edit".to_string()])
        );

        // A deleted message's deletion comes along.
        let hits = block_on(query(&db, &mut cache, "silinecek", 100)).unwrap();
        assert_eq!(
            ids(block_on(related(&db, &mut cache, &hits)).unwrap()),
            BTreeSet::from(["delete".to_string()])
        );
    }

    #[test]
    fn shards_split_by_period_so_a_write_touches_only_its_own() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        let mut pending = Pending::default();
        for period in 0..4i64 {
            pending.messages.push(inbox(
                &format!("old-{period}"),
                "alice@a.test",
                period * BUCKET_MS + 5,
                text(&format!("m-old-{period}"), "bir toplantı"),
            ));
        }
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        let mut cache = ShardCache::default();
        assert_eq!(
            search(&db, &mut cache, "toplanti"),
            vec!["old-3", "old-2", "old-1", "old-0"],
            "every period is read"
        );

        // A new message in the latest period rewrites that period's shards
        // and the directory, nothing older.
        let mut pending = Pending::default();
        pending.messages.push(inbox(
            "new",
            "alice@a.test",
            3 * BUCKET_MS + 9,
            text("m-new", "bir toplantı daha"),
        ));
        let writes = block_on(changes(&db, &pending)).unwrap();
        for key in writes.keys() {
            if key.as_slice() == DIRECTORY_KEY {
                continue;
            }
            // Shards and chunks name their period right after their kind.
            let rest = key
                .strip_prefix(b"search/shard\0".as_slice())
                .or_else(|| key.strip_prefix(b"search/docs\0".as_slice()))
                .expect("a search record");
            let period = i64::from_be_bytes(rest[..8].try_into().unwrap());
            assert_eq!(period, 3, "only the latest period's records");
        }
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert_eq!(search(&db, &mut cache, "toplanti daha"), vec!["new"]);
    }

    fn attachment(id: &str, filename: &str, caption: &str) -> Vec<u8> {
        use base64::Engine as _;
        use kutup_crypto::chat_media::{object_ciphertext_size, ChatMediaSuiteId};
        let descriptor = kutup_chat_proto::ChatAttachmentDescriptorV1 {
            version: 1,
            suite: ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1,
            attachment_id: "55555555-5555-4555-8555-555555555555".into(),
            origin_domain: "a.test".into(),
            retrieval_token: base64::engine::general_purpose::STANDARD.encode([1; 32]),
            ciphertext_bytes: object_ciphertext_size(7).unwrap(),
            ciphertext_sha256: "22".repeat(32),
            attachment_key: base64::engine::general_purpose::STANDARD.encode([3; 32]),
            plaintext_bytes: 7,
            filename: filename.into(),
            mime_type: "application/pdf".into(),
            media_class: kutup_chat_proto::ChatMediaClassV1::File,
            caption: Some(caption.into()),
            width: None,
            height: None,
            duration_ms: None,
            preview: None,
            backup_media_id: None,
        };
        serde_json::to_vec(
            &ChatContent::attachment_with_id(id, "2026-10-08T10:00:00Z", 1, descriptor).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn attachment_names_captions_and_place_labels_are_searchable() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        let place = kutup_chat_proto::LocationBody {
            lat: 40.99,
            lon: 29.02,
            label: Some("Kadıköy iskelesi".into()),
        };
        let mut pending = Pending::default();
        pending.messages.push(inbox(
            "file",
            "alice@a.test",
            1,
            attachment(
                "66666666-6666-4666-8666-666666666666",
                "Bütçe-2026.pdf",
                "Çeyrek raporu",
            ),
        ));
        pending.messages.push(inbox(
            "place",
            "alice@a.test",
            2,
            serde_json::to_vec(
                &ChatContent::location_with_id(
                    "77777777-7777-4777-8777-777777777777",
                    "2026-10-08T10:00:00Z",
                    1,
                    &place,
                )
                .unwrap(),
            )
            .unwrap(),
        ));
        block_on(db.apply(&pending)).unwrap();
        let mut cache = ShardCache::default();
        assert_eq!(
            search(&db, &mut cache, "butce"),
            vec!["file"],
            "a file name"
        );
        assert_eq!(
            search(&db, &mut cache, "2026 pdf"),
            vec!["file"],
            "its parts"
        );
        assert_eq!(
            search(&db, &mut cache, "ceyrek rapor"),
            vec!["file"],
            "a caption"
        );
        assert_eq!(
            search(&db, &mut cache, "kadikoy"),
            vec!["place"],
            "a place's label"
        );
        assert_eq!(indexed(&db), expected(&db));
    }

    #[test]
    fn decoded_records_are_kept_within_their_budget() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        // 30 words with 30 different prefixes, all under "a".
        let letters: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
        let mut pending = Pending::default();
        for i in 0..30usize {
            let word = format!("a{}{}x", letters[i / 26], letters[i % 26]);
            pending.messages.push(inbox(
                &format!("w-{i}"),
                "alice@a.test",
                i as i64,
                text(&format!("m-w-{i}"), &word),
            ));
        }
        block_on(db.apply(&pending)).unwrap();
        let shards = block_on(load_directory(&db)).unwrap().unwrap().periods[&0]
            .shards
            .iter()
            .filter(|known| known.starts_with('a'))
            .count();
        assert_eq!(shards, 30);
        // A budget smaller than what one query reads.
        let mut cache = ShardCache::with_budget(200);
        // One letter reads every one of them, and finds them all…
        assert_eq!(search(&db, &mut cache, "a").len(), 30);
        // …but keeps no more than the budget (or the one record just read).
        assert!(
            cache.held <= 200 || cache.records.len() == 1,
            "held {}",
            cache.held
        );
        assert!(cache.records.len() < shards);
        assert_eq!(cache.order.len(), cache.records.len());
        assert_eq!(
            search(&db, &mut cache, "a").len(),
            30,
            "and answers again the same"
        );
        // The default budget keeps them all: the 30 shards and the one
        // document chunk.
        let mut roomy = ShardCache::default();
        search(&db, &mut roomy, "a");
        assert_eq!(
            roomy.records.len(),
            shards + 1,
            "the shards and the document chunk"
        );
    }

    #[test]
    fn a_new_index_format_is_built_again_from_the_records() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        let mut pending = Pending::default();
        pending
            .messages
            .push(inbox("one", "alice@a.test", 1, text("m-1", "eski biçim")));
        block_on(db.apply(&pending)).unwrap();

        // As version 1 wrote it: a directory of named shards, each a map of
        // full postings, and none of this version's records.
        block_on(clear(&db)).unwrap();
        #[derive(Serialize)]
        struct First {
            version: u32,
            shards: BTreeMap<String, u32>,
        }
        let old_name = "esk\u{1f}0";
        let old_key = [b"search/shard\0".as_slice(), old_name.as_bytes()].concat();
        let mut old = Pending::default();
        old.index_values.insert(
            DIRECTORY_KEY.to_vec(),
            Some(
                encode(&First {
                    version: 1,
                    shards: BTreeMap::from([(old_name.to_string(), 1)]),
                })
                .unwrap(),
            ),
        );
        old.index_values.insert(
            old_key.clone(),
            Some(encode(&BTreeMap::from([("eski".to_string(), vec![0u8])])).unwrap()),
        );
        block_on(db.apply(&old)).unwrap();
        let mut cache = ShardCache::default();
        assert!(
            search(&db, &mut cache, "eski").is_empty(),
            "an index of another format is not read"
        );

        block_on(crate::timeline::ensure_built(&db)).unwrap();
        assert!(
            block_on(db.load_index_value(&old_key)).unwrap().is_none(),
            "the old shards are gone"
        );
        assert_eq!(indexed(&db), expected(&db));
        assert_eq!(search(&db, &mut cache, "bicim"), vec!["one"]);
    }

    #[test]
    fn numbers_round_trip_and_stay_small() {
        let numbers = vec![0, 1, 2, 127, 128, 300, 16_384, 1_000_000, u32::MAX];
        assert_eq!(decode_numbers(&encode_numbers(&numbers)), numbers);
        assert!(decode_numbers(&[]).is_empty());
        // A dense run costs a byte per number.
        let dense: Vec<u32> = (0..1_000).collect();
        assert_eq!(encode_numbers(&dense).len(), 1_000);
    }

    #[test]
    fn a_word_costs_bytes_not_an_identity() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        let mut pending = Pending::default();
        for i in 0..1_000i64 {
            pending.messages.push(inbox(
                &format!("in-{i}"),
                "alice@a.test",
                i,
                text(
                    &format!("33333333-3333-4333-8333-{i:012}"),
                    "bir iki üç dört beş altı yedi sekiz",
                ),
            ));
        }
        block_on(db.apply(&pending)).unwrap();
        let (_, bytes, _) = block_on(stats(&db)).unwrap();
        // About a hundred bytes per message for its document, and a byte or
        // two per word: well under the ~750 bytes of the first layout.
        assert!(bytes / 1_000 < 200, "{} bytes per message", bytes / 1_000);
    }

    /// The index at the size Proton capped theirs: 50,000 messages over two
    /// years (`bench`). Run with `cargo test --features sqlite --release
    /// --lib search::tests::scale -- --ignored --nocapture`; the browser
    /// counterpart is `scripts/bench-search-index.sh`.
    #[test]
    #[ignore]
    fn scale() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        let started = std::time::Instant::now();
        let report = block_on(bench::run(&db, 50_000, || {
            started.elapsed().as_secs_f64() * 1_000.0
        }))
        .unwrap();
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
}
