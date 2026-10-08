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
//! Words are grouped into shards by their first [`SHARD_CHARS`] characters,
//! each one sealed record; a directory lists the shards, so a shorter
//! query word finds every shard it can match. A query reads only the shards
//! it needs, and at most [`CACHED_SHARDS`] decoded shards are kept between
//! queries ([`ShardCache`]), dropped as soon as the store changes.
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
pub(crate) const SEARCH_VERSION: u32 = 1;
/// Characters of a word that name its shard.
pub(crate) const SHARD_CHARS: usize = 3;
/// Decoded shards kept between queries.
pub(crate) const CACHED_SHARDS: usize = 20;
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

type Shard = BTreeMap<String, Vec<Posting>>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Directory {
    version: u32,
    /// Shard name → how many postings it holds.
    shards: BTreeMap<String, u32>,
}

fn shard_name(term: &str) -> String {
    term.chars().take(SHARD_CHARS).collect()
}

fn shard_key(name: &str) -> Vec<u8> {
    let mut key = b"search/shard\0".to_vec();
    key.extend_from_slice(name.as_bytes());
    key
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

/// Shards read and changed for one commit.
struct Writer<'a> {
    db: &'a dyn ChatDb,
    directory: Directory,
    shards: HashMap<String, Shard>,
}

impl<'a> Writer<'a> {
    fn new(db: &'a dyn ChatDb, directory: Directory) -> Self {
        Writer {
            db,
            directory,
            shards: HashMap::new(),
        }
    }

    async fn shard(&mut self, name: &str) -> Result<&mut Shard> {
        if !self.shards.contains_key(name) {
            let shard = if self.directory.shards.contains_key(name) {
                match self.db.load_index_value(&shard_key(name)).await? {
                    Some(bytes) => decode(&bytes)?,
                    None => Shard::new(),
                }
            } else {
                Shard::new()
            };
            self.shards.insert(name.to_string(), shard);
        }
        Ok(self.shards.get_mut(name).expect("loaded above"))
    }

    async fn add(&mut self, document: &Document) -> Result<()> {
        for term in &document.terms {
            let postings = self
                .shard(&shard_name(term))
                .await?
                .entry(term.clone())
                .or_default();
            // A record written again (a delivery confirmed) is one entry.
            postings.retain(|posting| posting.identity() != document.posting.identity());
            postings.push(document.posting.clone());
        }
        Ok(())
    }

    async fn remove(&mut self, document: &Document) -> Result<()> {
        for term in &document.terms {
            let shard = self.shard(&shard_name(term)).await?;
            if let Some(postings) = shard.get_mut(term) {
                postings.retain(|posting| posting.identity() != document.posting.identity());
                if postings.is_empty() {
                    shard.remove(term);
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>> {
        let mut writes = HashMap::new();
        for (name, shard) in self.shards {
            let count: usize = shard.values().map(Vec::len).sum();
            if count == 0 {
                if self.directory.shards.remove(&name).is_some() {
                    writes.insert(shard_key(&name), None);
                }
            } else {
                self.directory
                    .shards
                    .insert(name.clone(), u32::try_from(count).unwrap_or(u32::MAX));
                writes.insert(shard_key(&name), Some(encode(&shard)?));
            }
        }
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
/// after this was added, and after [`SEARCH_VERSION`] moves on.
pub(crate) async fn ensure_built(db: &dyn ChatDb) -> Result<()> {
    let existing = load_directory(db).await?;
    if existing
        .as_ref()
        .is_some_and(|directory| directory.version == SEARCH_VERSION)
    {
        return Ok(());
    }
    let mut pending = Pending::default();
    if let Some(old) = &existing {
        for name in old.shards.keys() {
            pending.index_values.insert(shard_key(name), None);
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
    let mut shards: BTreeMap<String, Shard> = BTreeMap::new();
    for document in &documents {
        for term in &document.terms {
            let postings = shards
                .entry(shard_name(term))
                .or_default()
                .entry(term.clone())
                .or_default();
            postings.retain(|posting| posting.identity() != document.posting.identity());
            postings.push(document.posting.clone());
        }
    }
    let mut directory = Directory {
        version: SEARCH_VERSION,
        shards: BTreeMap::new(),
    };
    for (name, shard) in &shards {
        let count: usize = shard.values().map(Vec::len).sum();
        directory
            .shards
            .insert(name.clone(), u32::try_from(count).unwrap_or(u32::MAX));
        pending
            .index_values
            .insert(shard_key(name), Some(encode(shard)?));
    }
    pending
        .index_values
        .insert(DIRECTORY_KEY.to_vec(), Some(encode(&directory)?));
    db.apply(&pending).await
}

/// Decoded shards kept between queries, at most [`CACHED_SHARDS`], valid
/// for one store state: any commit clears them.
#[derive(Default)]
pub struct ShardCache {
    commits: Option<u64>,
    shards: HashMap<String, Rc<Shard>>,
    order: VecDeque<String>,
}

impl ShardCache {
    async fn shard(&mut self, db: &dyn ChatDb, name: &str) -> Result<Rc<Shard>> {
        let commits = db.commit_count();
        if self.commits != Some(commits) {
            self.commits = Some(commits);
            self.shards.clear();
            self.order.clear();
        }
        if let Some(shard) = self.shards.get(name) {
            let shard = shard.clone();
            self.order.retain(|cached| cached != name);
            self.order.push_back(name.to_string());
            return Ok(shard);
        }
        let shard: Rc<Shard> = Rc::new(match db.load_index_value(&shard_key(name)).await? {
            Some(bytes) => decode(&bytes)?,
            None => Shard::new(),
        });
        self.shards.insert(name.to_string(), shard.clone());
        self.order.push_back(name.to_string());
        while self.order.len() > CACHED_SHARDS {
            if let Some(oldest) = self.order.pop_front() {
                self.shards.remove(&oldest);
            }
        }
        Ok(shard)
    }
}

/// The entries every word of `text` matches the start of a word in, newest
/// first, at most `limit`. Nothing for a query with no words, or while the
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
    let mut matched: Option<HashMap<(Source, String), Posting>> = None;
    for word in &query {
        let names: Vec<&String> = if word.chars().count() >= SHARD_CHARS {
            let name = shard_name(word);
            directory
                .shards
                .get_key_value(&name)
                .map(|(name, _)| name)
                .into_iter()
                .collect()
        } else {
            directory
                .shards
                .keys()
                .filter(|name| name.starts_with(word.as_str()))
                .collect()
        };
        let mut found: HashMap<(Source, String), Posting> = HashMap::new();
        for name in names {
            let shard = cache.shard(db, name).await?;
            for (term, postings) in shard.range(word.clone()..) {
                if !term.starts_with(word.as_str()) {
                    break;
                }
                for posting in postings {
                    found.insert((posting.source, posting.id.clone()), posting.clone());
                }
            }
        }
        matched = Some(match matched {
            None => found,
            Some(previous) => previous
                .into_iter()
                .filter(|(key, _)| found.contains_key(key))
                .collect(),
        });
        if matched.as_ref().is_some_and(HashMap::is_empty) {
            return Ok(Vec::new());
        }
    }
    let mut hits: Vec<Posting> = matched.unwrap_or_default().into_values().collect();
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
    let known: HashSet<(Source, &str)> = hits.iter().map(Posting::identity).collect();
    let mut found: HashMap<(Source, String), Posting> = HashMap::new();
    for term in &terms {
        let shard = cache.shard(db, &shard_name(term)).await?;
        for posting in shard.get(term).into_iter().flatten() {
            if !known.contains(&posting.identity()) {
                found.insert((posting.source, posting.id.clone()), posting.clone());
            }
        }
    }
    Ok(found.into_values().collect())
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
        serde_json::to_vec(&ChatContent::text_with_id(id, "2026-10-08T10:00:00Z", 1, body)).unwrap()
    }

    fn mutation(id: &str, target: &str, replacement: Option<&str>) -> Vec<u8> {
        let mut content = ChatContent::text_with_id(id, "2026-10-08T10:00:00Z", 1, "");
        content.kind = kind::MESSAGE_MUTATION.to_string();
        content.body = match replacement {
            Some(text) => serde_json::json!({"targetMessageId": target, "operation": "edit", "replacementText": text}),
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
        for (name, count) in &directory.shards {
            let shard: Shard = decode(&block_on(db.load_index_value(&shard_key(name))).unwrap().unwrap()).unwrap();
            assert_eq!(*count as usize, shard.values().map(Vec::len).sum::<usize>());
            for (term, postings) in shard {
                assert_eq!(shard_name(&term), *name);
                assert!(!postings.is_empty());
                let set: BTreeSet<_> = postings.iter().map(|p| (p.source, p.id.clone())).collect();
                assert_eq!(set.len(), postings.len(), "one posting per entry");
                out.insert(term, set);
            }
        }
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

        let words_pool = ["kitap", "Kitaplar", "İstanbul", "çağrı", "rapor", "toplantı", "yarın", "akşam"];
        let mut pending = Pending::default();
        for i in 0..300i64 {
            let body = format!("{} {} {i}", words_pool[i as usize % 8], words_pool[(i as usize * 3) % 8]);
            let peer = if i % 2 == 0 { "alice@a.test" } else { "bob@a.test" };
            pending
                .messages
                .push(inbox(&format!("in-{i}"), peer, 1_000 + i, text(&format!("m-in-{i}"), &body)));
        }
        for i in 0..20i64 {
            pending
                .mls_messages
                .insert(format!("g-{i}"), group(&format!("g-{i}"), 2_000 + i, text(&format!("m-g-{i}"), "grup toplantısı")));
        }
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));

        // A sent message, then written again (delivered), an edit and a
        // deletion: still one posting each, as a rebuild has it.
        let mut pending = Pending::default();
        pending
            .sent_messages
            .insert("out-1".into(), sent("out-1", "alice@a.test", 3_000, text("m-out-1", "Rapor hazır")));
        pending.sent_messages.insert(
            "edit-1".into(),
            sent("edit-1", "alice@a.test", 3_001, mutation("m-edit-1", "m-out-1", Some("Rapor yarın hazır"))),
        );
        block_on(db.apply(&pending)).unwrap();
        let mut again = Pending::default();
        let mut delivered = sent("out-1", "alice@a.test", 3_000, text("m-out-1", "Rapor hazır"));
        delivered.delivered = true;
        again.sent_messages.insert("out-1".into(), delivered);
        block_on(db.apply(&again)).unwrap();
        assert_eq!(indexed(&db), expected(&db));

        // Deletions of each kind, and a forgotten contact.
        let mut pending = Pending::default();
        pending.delete_message_ids.extend(["in-0".to_string(), "in-2".to_string()]);
        pending.delete_mls_message_ids.insert("g-3".into());
        pending.delete_sent_message_ids.insert("edit-1".into());
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        let mut pending = Pending::default();
        pending.delete_messages_for_peers.insert("bob@a.test".into());
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert!(!indexed(&db).values().flatten().any(|(_, id)| id == "in-1"));
    }

    #[test]
    fn built_once_on_open_from_what_is_already_stored() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut pending = Pending::default();
        pending
            .messages
            .push(inbox("in-1", "alice@a.test", 1, text("m-1", "Merhaba dünya")));
        block_on(db.apply(&pending)).unwrap();
        assert!(block_on(load_directory(&db)).unwrap().is_none(), "nothing indexed before open");
        block_on(crate::timeline::ensure_built(&db)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert_eq!(search(&db, &mut ShardCache::default(), "dunya"), vec!["in-1"]);
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
            pending
                .messages
                .push(inbox(id, "alice@a.test", ts, text(&format!("m-{id}"), body)));
        }
        block_on(db.apply(&pending)).unwrap();
        let mut cache = ShardCache::default();
        for query_text in ["istanbul", "ISTANBUL", "ıstanbul", "İSTAN"] {
            assert_eq!(search(&db, &mut cache, query_text), vec!["a"], "{query_text}");
        }
        assert_eq!(search(&db, &mut cache, "cagri"), vec!["b"]);
        assert_eq!(search(&db, &mut cache, "kitap"), vec!["c"]);
        assert!(search(&db, &mut cache, "tap").is_empty(), "the middle of a word does not match");
        assert_eq!(search(&db, &mut cache, "apple"), vec!["e", "d"], "newest first");
        assert_eq!(search(&db, &mut cache, "app red"), vec!["d"], "every word");
        assert!(search(&db, &mut cache, "apple blue").is_empty());
        // "a" begins akşam, apple and ab (not "da" of İstanbul'da).
        assert_eq!(search(&db, &mut cache, "a"), vec!["f", "e", "d", "b"], "one letter reaches every shard it can");
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
        pending
            .messages
            .push(inbox("one", "alice@a.test", 1, text("11111111-1111-4111-8111-111111111111", "eski metin")));
        pending
            .messages
            .push(inbox("two", "alice@a.test", 2, text("22222222-2222-4222-8222-222222222222", "silinecek metin")));
        pending
            .messages
            .push(inbox("edit", "alice@a.test", 3, mutation("33333333-3333-4333-8333-333333333333", "11111111-1111-4111-8111-111111111111", Some("yeni metin"))));
        pending
            .messages
            .push(inbox("delete", "alice@a.test", 4, mutation("44444444-4444-4444-8444-444444444444", "22222222-2222-4222-8222-222222222222", None)));
        block_on(db.apply(&pending)).unwrap();
        let mut cache = ShardCache::default();
        let ids = |postings: Vec<Posting>| -> BTreeSet<String> { postings.into_iter().map(|p| p.id).collect() };

        // The edit's new text finds the edit; the message it edits comes along.
        let hits = block_on(query(&db, &mut cache, "yeni", 100)).unwrap();
        assert_eq!(ids(hits.clone()), BTreeSet::from(["edit".to_string()]));
        assert_eq!(ids(block_on(related(&db, &mut cache, &hits)).unwrap()), BTreeSet::from(["one".to_string()]));

        // The original text finds the message; its edit comes along.
        let hits = block_on(query(&db, &mut cache, "eski", 100)).unwrap();
        assert_eq!(ids(hits.clone()), BTreeSet::from(["one".to_string()]));
        assert_eq!(ids(block_on(related(&db, &mut cache, &hits)).unwrap()), BTreeSet::from(["edit".to_string()]));

        // A deleted message's deletion comes along.
        let hits = block_on(query(&db, &mut cache, "silinecek", 100)).unwrap();
        assert_eq!(ids(block_on(related(&db, &mut cache, &hits)).unwrap()), BTreeSet::from(["delete".to_string()]));
    }
}
