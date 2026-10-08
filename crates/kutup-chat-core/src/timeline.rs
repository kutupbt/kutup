//! Per-conversation timelines (`docs/research/16-browser-storage-architecture.md`,
//! Phase 2b).
//!
//! An index over the four history stores (inbound and sent direct messages,
//! group messages, imported history), kept in the store's derived-index
//! records and written in the same transaction as the records it indexes
//! ([`changes`], called from each backend's `apply`). A directory holds one
//! header per conversation; each conversation's references (time, store,
//! id, flags) sit in sorted chunks of at most [`CHUNK_LIMIT`]. Message
//! content stays in its own record and is read by point lookups, so a
//! conversation's entries are built by the same code as the full history.
//!
//! Controls that travel in Note to Self but act on another conversation
//! (read position, delete for me, view-once opened, conversation state,
//! disappearing expiry start) are indexed under that conversation as well.

use std::collections::{BTreeMap, HashMap, HashSet};

use kutup_chat_proto::content::kind;
use kutup_chat_proto::{AccountAddress, ChatContent, ConversationId};
use serde::{Deserialize, Serialize};

use crate::db::{
    ChatDb, ImportedHistoryRecordV1, InboxMessage, MlsHistoryMessage, Pending, SentMessage,
};
use crate::error::{ChatError, Result};

/// Raised whenever what is indexed or how changes; a store with an older
/// directory is indexed again from its records.
pub(crate) const TIMELINE_VERSION: u32 = 1;
/// References per chunk before it splits.
pub(crate) const CHUNK_LIMIT: usize = 256;
const DIRECTORY_KEY: &[u8] = b"timeline/directory";

/// Which history store a reference points into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Source {
    Inbox,
    Sent,
    Mls,
    Imported,
}

/// From someone else.
pub const INCOMING: u8 = 1;
/// A message a person sees (not a reaction, edit, receipt or control); the
/// time-dependent part (disappearing deadlines) is left to the reader.
pub const VISIBLE: u8 = 2;
/// A Note to Self control indexed under the conversation it acts on.
pub const ROUTED: u8 = 4;
/// A disappearing expiry start: not a history entry, but needed to work out
/// the conversation's deadlines.
pub const EXPIRY_START: u8 = 8;
/// This account's own control in Note to Self (list state, read position,
/// deletion, opened view-once media, sticker), where it travels.
pub const ACCOUNT_CONTROL: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRef {
    pub ts: i64,
    pub source: Source,
    pub id: String,
    pub flags: u8,
}

impl EntryRef {
    fn order(&self) -> (i64, Source, &str) {
        (self.ts, self.source, &self.id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub id: u32,
    pub count: u32,
    pub first_ms: i64,
    pub last_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub conversation: ConversationId,
    /// Oldest first.
    pub chunks: Vec<ChunkMeta>,
    pub next_chunk: u32,
}

impl Header {
    pub fn latest_ms(&self) -> i64 {
        self.chunks.last().map_or(0, |chunk| chunk.last_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Directory {
    pub version: u32,
    pub conversations: BTreeMap<String, Header>,
}

/// One record as the index sees it: where it goes and how it is flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Indexed {
    pub conversation: ConversationId,
    pub entry: EntryRef,
}

fn chunk_key(conversation: &str, id: u32) -> Vec<u8> {
    let mut key = b"timeline/chunk\0".to_vec();
    key.extend_from_slice(conversation.as_bytes());
    key.push(0);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)
        .map_err(|error| ChatError::Db(format!("timeline encode: {error}")))?;
    Ok(out)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|error| ChatError::Db(format!("timeline decode: {error}")))
}

pub(crate) fn direct(peer: &str) -> Result<ConversationId> {
    let address = peer
        .parse::<AccountAddress>()
        .map_err(|error| ChatError::Content(format!("invalid direct conversation: {error}")))?;
    Ok(ConversationId::direct(address))
}

/// Kinds left out of the history of direct messages (as the full history
/// does), and the wider set left out of group and imported history.
fn hidden_direct(kind_name: &str) -> bool {
    matches!(
        kind_name,
        kind::CONTACT_CONTROL | kind::PROFILE_KEY_UPDATE | kind::TYPING | kind::CALL
    )
}

fn hidden_other(kind_name: &str) -> bool {
    hidden_direct(kind_name) || kind_name == kind::GROUP_CONTROL
}

/// The UI's rule (`isVisibleChatMessage`), without the deadline.
fn visible(content: &ChatContent) -> bool {
    let hidden = matches!(
        content.kind.as_str(),
        kind::REACTION
            | kind::MESSAGE_MUTATION
            | kind::RECEIPT
            | kind::DISAPPEARING_TIMER
            | kind::GROUP_UPDATE
            | kind::POLL_VOTE
            | kind::POLL_TERMINATE
            | kind::GROUP_CALL
            | kind::CALL_LOG
            | kind::UNDECRYPTABLE
            | kind::LIVE_LOCATION_STOP
            | kind::CONVERSATION_STATE
            | kind::READ_POSITION
            | kind::DELETE_FOR_ME
            | kind::VIEW_ONCE_OPENED
            | kind::STICKER_SAVED
            | kind::STICKER_REMOVED
            | kind::DISAPPEARING_EXPIRY_START
    );
    let later_live_location = content.kind == kind::LIVE_LOCATION
        && content
            .body
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|generation| generation > 1);
    !hidden && !later_live_location
}

/// The conversation a Note to Self control acts on, if it is one.
fn routed_conversation(content: &ChatContent) -> Option<ConversationId> {
    if !matches!(
        content.kind.as_str(),
        kind::READ_POSITION
            | kind::DELETE_FOR_ME
            | kind::VIEW_ONCE_OPENED
            | kind::CONVERSATION_STATE
            | kind::DISAPPEARING_EXPIRY_START
    ) {
        return None;
    }
    serde_json::from_value(content.body.get("conversation")?.clone()).ok()
}

fn content_of(bytes: &[u8]) -> Option<ChatContent> {
    serde_json::from_slice(bytes).ok()
}

/// Where a record is indexed (once, or twice for a routed control), or
/// nowhere when the full history leaves it out. A record whose content does
/// not decode is indexed as visible, as the full history shows it.
fn place(
    conversation: ConversationId,
    source: Source,
    id: String,
    ts: i64,
    incoming: bool,
    content: &[u8],
    hidden: fn(&str) -> bool,
) -> Vec<Indexed> {
    let decoded = content_of(content);
    let kind_name = decoded.as_ref().map(|content| content.kind.as_str());
    let expiry_start = kind_name == Some(kind::DISAPPEARING_EXPIRY_START);
    if kind_name.is_some_and(hidden) {
        return Vec::new();
    }
    let mut flags = if incoming { INCOMING } else { 0 };
    if decoded.as_ref().is_none_or(visible) {
        flags |= VISIBLE;
    }
    if expiry_start {
        flags |= EXPIRY_START;
    }
    let account_control = matches!(
        kind_name,
        Some(
            kind::CONVERSATION_STATE
                | kind::READ_POSITION
                | kind::DELETE_FOR_ME
                | kind::VIEW_ONCE_OPENED
                | kind::STICKER_SAVED
                | kind::STICKER_REMOVED
        )
    );
    let entry = EntryRef {
        ts,
        source,
        id,
        flags,
    };
    let mut placed = Vec::with_capacity(2);
    if let Some(target) = decoded.as_ref().and_then(routed_conversation) {
        if target != conversation {
            placed.push(Indexed {
                conversation: target,
                entry: EntryRef {
                    flags: entry.flags | ROUTED,
                    ..entry.clone()
                },
            });
        }
    }
    // An expiry start is not a history entry where it travels.
    if !expiry_start {
        let flags = if account_control {
            entry.flags | ACCOUNT_CONTROL
        } else {
            entry.flags
        };
        placed.push(Indexed {
            conversation,
            entry: EntryRef { flags, ..entry },
        });
    }
    placed
}

pub(crate) fn place_inbox(message: &InboxMessage) -> Result<Vec<Indexed>> {
    Ok(place(
        direct(&message.peer)?,
        Source::Inbox,
        message.id.clone(),
        message.received_at,
        true,
        &message.content,
        hidden_direct,
    ))
}

pub(crate) fn place_sent(message: &SentMessage) -> Result<Vec<Indexed>> {
    Ok(place(
        direct(&message.peer)?,
        Source::Sent,
        message.send_id.clone(),
        message.created_at,
        false,
        &message.content,
        hidden_direct,
    ))
}

pub(crate) fn place_mls(message: &MlsHistoryMessage) -> Vec<Indexed> {
    place(
        ConversationId::Group {
            group_id: uuid::Uuid::from_bytes(message.conversation_id).to_string(),
        },
        Source::Mls,
        message.record_id.clone(),
        message.timestamp_ms,
        !message.outgoing,
        &message.content,
        hidden_other,
    )
}

pub(crate) fn imported_id(transfer_id: &str, source_record_id: &str) -> String {
    format!("{transfer_id}\u{0}{source_record_id}")
}

pub(crate) fn place_imported(message: &ImportedHistoryRecordV1) -> Vec<Indexed> {
    place(
        message.conversation.clone(),
        Source::Imported,
        imported_id(&message.transfer_id, &message.source_record_id),
        message.timestamp_ms,
        !message.outgoing,
        &message.content,
        hidden_other,
    )
}

/// Index writes for `pending`, to commit with it. Nothing while the store
/// has no current directory (it is indexed whole on open, [`ensure_built`]).
/// The index writes for one commit, and the conversations it touched.
#[derive(Default)]
pub(crate) struct Changes {
    pub writes: HashMap<Vec<u8>, Option<Vec<u8>>>,
    pub conversations: HashSet<String>,
}

pub(crate) async fn changes(db: &dyn ChatDb, pending: &Pending) -> Result<Changes> {
    let mut added: Vec<Indexed> = Vec::new();
    let mut removed: Vec<Indexed> = Vec::new();
    for message in &pending.messages {
        added.extend(place_inbox(message)?);
    }
    for message in pending.sent_messages.values() {
        added.extend(place_sent(message)?);
    }
    for message in pending.mls_messages.values() {
        added.extend(place_mls(message));
    }
    for message in pending.imported_history.values() {
        added.extend(place_imported(message));
    }
    let nothing_removed = pending.delete_message_ids.is_empty()
        && pending.delete_messages_for_peers.is_empty()
        && pending.delete_sent_message_ids.is_empty()
        && pending.delete_mls_message_ids.is_empty()
        && pending.delete_imported_history_ids.is_empty();
    if added.is_empty() && nothing_removed {
        return Ok(Changes::default());
    }
    let Some(mut directory) = load_directory(db).await? else {
        return Ok(Changes::default());
    };
    if directory.version != TIMELINE_VERSION {
        return Ok(Changes::default());
    }
    for id in &pending.delete_message_ids {
        if let Some(message) = db.load_message(id).await? {
            removed.extend(place_inbox(&message)?);
        }
    }
    for id in &pending.delete_sent_message_ids {
        if let Some(message) = db.load_sent_message(id).await? {
            removed.extend(place_sent(&message)?);
        }
    }
    for id in &pending.delete_mls_message_ids {
        if let Some(message) = db.load_mls_message(id).await? {
            removed.extend(place_mls(&message));
        }
    }
    for (transfer_id, source_record_id) in &pending.delete_imported_history_ids {
        if let Some(message) = db
            .load_imported_history(transfer_id, source_record_id)
            .await?
        {
            removed.extend(place_imported(&message));
        }
    }
    let mut writer = Writer::new(db, &mut directory);
    for peer in &pending.delete_messages_for_peers {
        writer
            .remove_source(&direct(peer)?.key(), Source::Inbox)
            .await?;
    }
    for indexed in removed {
        writer.remove(&indexed).await?;
    }
    for indexed in added {
        writer.add(indexed).await?;
    }
    writer.finish()
}

/// Index the whole store when it has no current directory: on first open
/// after this was added, and after [`TIMELINE_VERSION`] moves on.
pub(crate) async fn ensure_built(db: &dyn ChatDb) -> Result<()> {
    let existing = load_directory(db).await?;
    if existing
        .as_ref()
        .is_some_and(|directory| directory.version == TIMELINE_VERSION)
    {
        return Ok(());
    }
    let mut pending = Pending::default();
    // Clear what an older version wrote.
    if let Some(old) = existing {
        for (key, header) in &old.conversations {
            for chunk in &header.chunks {
                pending.index_values.insert(chunk_key(key, chunk.id), None);
            }
        }
    }
    let mut placed: Vec<Indexed> = Vec::new();
    for message in db.list_messages().await? {
        placed.extend(place_inbox(&message)?);
    }
    for message in db.list_sent_messages().await? {
        placed.extend(place_sent(&message)?);
    }
    for message in db.list_mls_messages().await? {
        placed.extend(place_mls(&message));
    }
    for message in db.list_imported_history().await? {
        placed.extend(place_imported(&message));
    }
    let mut directory = Directory {
        version: TIMELINE_VERSION,
        conversations: BTreeMap::new(),
    };
    let mut by_conversation: BTreeMap<String, (ConversationId, Vec<EntryRef>)> = BTreeMap::new();
    for indexed in placed {
        by_conversation
            .entry(indexed.conversation.key())
            .or_insert_with(|| (indexed.conversation.clone(), Vec::new()))
            .1
            .push(indexed.entry);
    }
    for (key, (conversation, mut entries)) in by_conversation {
        entries.sort_by(|left, right| left.order().cmp(&right.order()));
        entries.dedup_by(|left, right| left.order() == right.order());
        let mut header = Header {
            conversation,
            chunks: Vec::new(),
            next_chunk: 0,
        };
        for slice in entries.chunks(CHUNK_LIMIT / 2) {
            let id = header.next_chunk;
            header.next_chunk += 1;
            header.chunks.push(meta(id, slice));
            pending
                .index_values
                .insert(chunk_key(&key, id), Some(encode(&slice.to_vec())?));
        }
        directory.conversations.insert(key, header);
    }
    pending
        .index_values
        .insert(DIRECTORY_KEY.to_vec(), Some(encode(&directory)?));
    db.apply(&pending).await
}

pub(crate) async fn load_directory(db: &dyn ChatDb) -> Result<Option<Directory>> {
    db.load_index_value(DIRECTORY_KEY)
        .await?
        .map(|bytes| decode(&bytes))
        .transpose()
}

async fn load_chunk(db: &dyn ChatDb, conversation: &str, id: u32) -> Result<Vec<EntryRef>> {
    Ok(
        match db.load_index_value(&chunk_key(conversation, id)).await? {
            Some(bytes) => decode(&bytes)?,
            None => Vec::new(),
        },
    )
}

fn meta(id: u32, entries: &[EntryRef]) -> ChunkMeta {
    ChunkMeta {
        id,
        count: entries.len() as u32,
        first_ms: entries.first().map_or(0, |entry| entry.ts),
        last_ms: entries.last().map_or(0, |entry| entry.ts),
    }
}

/// References of `conversation`, newest first, older than `before` (a
/// reference returned earlier), at most `limit`.
pub(crate) async fn page(
    db: &dyn ChatDb,
    directory: &Directory,
    conversation: &str,
    before: Option<&EntryRef>,
    limit: usize,
) -> Result<Vec<EntryRef>> {
    let Some(header) = directory.conversations.get(conversation) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for chunk in header.chunks.iter().rev() {
        if out.len() >= limit {
            break;
        }
        if before.is_some_and(|before| chunk.first_ms > before.ts) {
            continue;
        }
        let entries = load_chunk(db, conversation, chunk.id).await?;
        for entry in entries.into_iter().rev() {
            if before.is_some_and(|before| entry.order() >= before.order()) {
                continue;
            }
            out.push(entry);
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}

/// Incoming visible messages newer than `read_through_ms`, counted from the
/// newest back (only as far as needed).
pub(crate) async fn unread(
    db: &dyn ChatDb,
    directory: &Directory,
    conversation: &str,
    read_through_ms: i64,
) -> Result<u32> {
    let Some(header) = directory.conversations.get(conversation) else {
        return Ok(0);
    };
    let mut count = 0;
    for chunk in header.chunks.iter().rev() {
        if chunk.last_ms <= read_through_ms {
            break;
        }
        for entry in load_chunk(db, conversation, chunk.id).await?.iter().rev() {
            if entry.ts <= read_through_ms {
                return Ok(count);
            }
            if entry.flags & (INCOMING | VISIBLE | ROUTED) == INCOMING | VISIBLE {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Where a page left off: give it back to continue with older entries.
pub(crate) fn cursor_of(entry: &EntryRef) -> Result<String> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encode(entry)?))
}

pub(crate) fn from_cursor(cursor: &str) -> Result<EntryRef> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| ChatError::Invalid("malformed history cursor".into()))?;
    decode(&bytes)
}

/// Every reference of `conversation` carrying `flag`, newest first.
pub(crate) async fn flagged(
    db: &dyn ChatDb,
    directory: &Directory,
    conversation: &str,
    flag: u8,
) -> Result<Vec<EntryRef>> {
    let Some(header) = directory.conversations.get(conversation) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for chunk in header.chunks.iter().rev() {
        for entry in load_chunk(db, conversation, chunk.id)
            .await?
            .into_iter()
            .rev()
        {
            if entry.flags & flag != 0 {
                out.push(entry);
            }
        }
    }
    Ok(out)
}

/// Which conversations each recent commit of this connection touched, so a
/// reader can reload just those. Bounded; a reader whose mark is older than
/// what is kept reloads everything.
#[derive(Default)]
pub(crate) struct Journal {
    entries: std::collections::VecDeque<(u64, HashSet<String>)>,
}

const JOURNAL_LIMIT: usize = 512;

impl Journal {
    pub(crate) fn record(&mut self, commit: u64, conversations: HashSet<String>) {
        if conversations.is_empty() {
            return;
        }
        if self.entries.len() == JOURNAL_LIMIT {
            self.entries.pop_front();
        }
        self.entries.push_back((commit, conversations));
    }

    /// The conversations touched by commits after `since` (up to `current`),
    /// or `None` when some of them are no longer kept.
    pub(crate) fn since(&self, since: u64, current: u64) -> Option<Vec<String>> {
        if since >= current {
            return Some(Vec::new());
        }
        let oldest_kept = self
            .entries
            .front()
            .map_or(current + 1, |(commit, _)| *commit);
        // Commits that touched no conversation are not recorded, so only a
        // gap below the oldest recorded commit is unknown.
        if self.entries.len() == JOURNAL_LIMIT && since + 1 < oldest_kept {
            return None;
        }
        let mut out: Vec<String> = self
            .entries
            .iter()
            .filter(|(commit, _)| *commit > since)
            .flat_map(|(_, conversations)| conversations.iter().cloned())
            .collect();
        out.sort();
        out.dedup();
        Some(out)
    }
}

/// Applies additions and removals to the chunks they fall in, loading each
/// chunk once, and gives the writes to commit.
struct Writer<'a> {
    db: &'a dyn ChatDb,
    directory: &'a mut Directory,
    chunks: HashMap<(String, u32), Vec<EntryRef>>,
    dropped: HashSet<(String, u32)>,
    touched: bool,
}

impl<'a> Writer<'a> {
    fn new(db: &'a dyn ChatDb, directory: &'a mut Directory) -> Self {
        Self {
            db,
            directory,
            chunks: HashMap::new(),
            dropped: HashSet::new(),
            touched: false,
        }
    }

    async fn chunk(&mut self, conversation: &str, id: u32) -> Result<&mut Vec<EntryRef>> {
        let key = (conversation.to_owned(), id);
        if !self.chunks.contains_key(&key) {
            let loaded = load_chunk(self.db, conversation, id).await?;
            self.chunks.insert(key.clone(), loaded);
        }
        Ok(self.chunks.get_mut(&key).expect("just loaded"))
    }

    async fn add(&mut self, indexed: Indexed) -> Result<()> {
        let key = indexed.conversation.key();
        let header = self
            .directory
            .conversations
            .entry(key.clone())
            .or_insert_with(|| Header {
                conversation: indexed.conversation.clone(),
                chunks: Vec::new(),
                next_chunk: 0,
            });
        // The chunk the time falls in: the last one starting at or before it,
        // or the first.
        let position = header
            .chunks
            .iter()
            .rposition(|chunk| chunk.first_ms <= indexed.entry.ts)
            .unwrap_or(0);
        let id = match header.chunks.get(position) {
            Some(chunk) => chunk.id,
            None => {
                let id = header.next_chunk;
                header.next_chunk += 1;
                header.chunks.push(ChunkMeta {
                    id,
                    count: 0,
                    first_ms: indexed.entry.ts,
                    last_ms: indexed.entry.ts,
                });
                id
            }
        };
        let entry = indexed.entry;
        let chunk = self.chunk(&key, id).await?;
        match chunk.binary_search_by(|probe| probe.order().cmp(&entry.order())) {
            // Already indexed (a record written again, a delivery flag).
            Ok(found) => {
                chunk[found] = entry;
            }
            Err(at) => chunk.insert(at, entry),
        }
        self.touched = true;
        self.settle(&key, position)
    }

    async fn remove(&mut self, indexed: &Indexed) -> Result<()> {
        let key = indexed.conversation.key();
        let Some(header) = self.directory.conversations.get(&key) else {
            return Ok(());
        };
        let candidates: Vec<(usize, u32)> = header
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| {
                chunk.first_ms <= indexed.entry.ts && indexed.entry.ts <= chunk.last_ms
            })
            .map(|(position, chunk)| (position, chunk.id))
            .collect();
        for (position, id) in candidates {
            let target = &indexed.entry;
            let chunk = self.chunk(&key, id).await?;
            if let Ok(found) = chunk.binary_search_by(|probe| probe.order().cmp(&target.order())) {
                chunk.remove(found);
                self.touched = true;
                return self.settle(&key, position);
            }
        }
        Ok(())
    }

    /// Remove every reference into `source` from a conversation.
    async fn remove_source(&mut self, conversation: &str, source: Source) -> Result<()> {
        let Some(header) = self.directory.conversations.get(conversation) else {
            return Ok(());
        };
        let ids: Vec<u32> = header.chunks.iter().map(|chunk| chunk.id).collect();
        for id in ids {
            let chunk = self.chunk(conversation, id).await?;
            let before = chunk.len();
            chunk.retain(|entry| entry.source != source);
            if chunk.len() != before {
                self.touched = true;
            }
        }
        let positions = self.directory.conversations[conversation].chunks.len();
        for position in (0..positions).rev() {
            if !self.directory.conversations.contains_key(conversation) {
                break;
            }
            self.settle(conversation, position)?;
        }
        Ok(())
    }

    /// Bring the header in line with the chunk at `position`: split it when
    /// full, drop it when empty, refresh its bounds otherwise.
    fn settle(&mut self, conversation: &str, position: usize) -> Result<()> {
        let header = self
            .directory
            .conversations
            .get_mut(conversation)
            .expect("settled conversation exists");
        let id = header.chunks[position].id;
        let entries = self
            .chunks
            .get_mut(&(conversation.to_owned(), id))
            .expect("settled chunk is loaded");
        if entries.is_empty() {
            header.chunks.remove(position);
            self.chunks.remove(&(conversation.to_owned(), id));
            self.dropped.insert((conversation.to_owned(), id));
            if header.chunks.is_empty() {
                self.directory.conversations.remove(conversation);
            }
            return Ok(());
        }
        if entries.len() > CHUNK_LIMIT {
            let upper = entries.split_off(entries.len() / 2);
            let new_id = header.next_chunk;
            header.next_chunk += 1;
            header.chunks[position] = meta(id, entries);
            header.chunks.insert(position + 1, meta(new_id, &upper));
            self.chunks.insert((conversation.to_owned(), new_id), upper);
            return Ok(());
        }
        header.chunks[position] = meta(id, entries);
        Ok(())
    }

    fn finish(self) -> Result<Changes> {
        let mut changes = Changes::default();
        if !self.touched {
            return Ok(changes);
        }
        for ((conversation, id), entries) in &self.chunks {
            changes
                .writes
                .insert(chunk_key(conversation, *id), Some(encode(entries)?));
            changes.conversations.insert(conversation.clone());
        }
        for (conversation, id) in &self.dropped {
            changes.writes.insert(chunk_key(conversation, *id), None);
            changes.conversations.insert(conversation.clone());
        }
        changes
            .writes
            .insert(DIRECTORY_KEY.to_vec(), Some(encode(&*self.directory)?));
        Ok(changes)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::SqliteChatDb;
    use futures_executor::block_on;

    fn text(body: &str) -> Vec<u8> {
        serde_json::to_vec(&ChatContent::text("2026-10-08T10:00:00Z", 1, body)).unwrap()
    }

    fn control(kind_name: &str, body: serde_json::Value) -> Vec<u8> {
        let mut content = ChatContent::text("2026-10-08T10:00:00Z", 1, "");
        content.kind = kind_name.to_string();
        content.body = body;
        serde_json::to_vec(&content).unwrap()
    }

    fn inbox(id: &str, peer: &str, ts: i64) -> InboxMessage {
        InboxMessage {
            id: id.into(),
            peer: peer.into(),
            sender_device_id: 1,
            cursor: ts as u64,
            content: text(id),
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

    fn group(id: &str, ts: i64) -> MlsHistoryMessage {
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
            content: text(id),
            timestamp_ms: ts,
            delivered: true,
            deduplicated: false,
        }
    }

    /// Every conversation's references as the index holds them, after
    /// checking the chunks are sorted, bounded, contiguous and described by
    /// their headers.
    fn indexed(db: &SqliteChatDb) -> BTreeMap<String, Vec<EntryRef>> {
        let directory = block_on(load_directory(db)).unwrap().unwrap();
        let mut out = BTreeMap::new();
        for (key, header) in &directory.conversations {
            let mut all = Vec::new();
            let mut previous_last = i64::MIN;
            for chunk in &header.chunks {
                let entries = block_on(load_chunk(db, key, chunk.id)).unwrap();
                assert!(!entries.is_empty() && entries.len() <= CHUNK_LIMIT);
                assert!(entries
                    .windows(2)
                    .all(|pair| pair[0].order() < pair[1].order()));
                assert_eq!(*chunk, meta(chunk.id, &entries));
                assert!(previous_last <= chunk.first_ms);
                previous_last = chunk.last_ms;
                all.extend(entries);
            }
            out.insert(key.clone(), all);
        }
        out
    }

    /// What a rebuild from the records would hold.
    fn expected(db: &SqliteChatDb) -> BTreeMap<String, Vec<EntryRef>> {
        let mut placed = Vec::new();
        for message in block_on(db.list_messages()).unwrap() {
            placed.extend(place_inbox(&message).unwrap());
        }
        for message in block_on(db.list_sent_messages()).unwrap() {
            placed.extend(place_sent(&message).unwrap());
        }
        for message in block_on(db.list_mls_messages()).unwrap() {
            placed.extend(place_mls(&message));
        }
        let mut out: BTreeMap<String, Vec<EntryRef>> = BTreeMap::new();
        for indexed in placed {
            out.entry(indexed.conversation.key())
                .or_default()
                .push(indexed.entry);
        }
        for entries in out.values_mut() {
            entries.sort_by(|left, right| left.order().cmp(&right.order()));
        }
        out
    }

    #[test]
    fn the_index_written_with_each_commit_matches_a_rebuild() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(ensure_built(&db)).unwrap();
        assert!(indexed(&db).is_empty());

        // Many messages, out of time order, enough to split chunks.
        let mut pending = Pending::default();
        for i in 0..700i64 {
            let ts = (i * 7919) % 1000 + 1_000;
            pending
                .messages
                .push(inbox(&format!("in-{i}"), "alice@a.test", ts));
        }
        block_on(db.apply(&pending)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert!(
            block_on(load_directory(&db))
                .unwrap()
                .unwrap()
                .conversations["direct:alice@a.test"]
                .chunks
                .len()
                > 2
        );

        // Other stores and conversations, a routed Note to Self control, a
        // hidden control, and a record written again.
        let mut pending = Pending::default();
        pending.sent_messages.insert(
            "out-1".into(),
            sent("out-1", "alice@a.test", 1_500, text("hi")),
        );
        pending.sent_messages.insert(
            "read-1".into(),
            sent(
                "read-1",
                "myself@a.test",
                1_600,
                control(
                    kind::READ_POSITION,
                    serde_json::json!({
                        "conversation": {"kind": "direct", "address": {"username": "alice", "server": "a.test"}},
                        "throughMessageId": "in-1",
                        "readThroughMs": 1_500
                    }),
                ),
            ),
        );
        pending.sent_messages.insert(
            "typing-1".into(),
            sent(
                "typing-1",
                "alice@a.test",
                1_601,
                control(kind::TYPING, serde_json::json!({"active": true})),
            ),
        );
        for i in 0..5 {
            pending
                .mls_messages
                .insert(format!("g-{i}"), group(&format!("g-{i}"), 2_000 + i));
        }
        block_on(db.apply(&pending)).unwrap();
        let mut again = Pending::default();
        let mut delivered = sent("out-1", "alice@a.test", 1_500, text("hi"));
        delivered.delivered = true;
        again.sent_messages.insert("out-1".into(), delivered);
        block_on(db.apply(&again)).unwrap();
        let now = indexed(&db);
        assert_eq!(now, expected(&db));
        let alice = &now["direct:alice@a.test"];
        let read = alice.iter().find(|entry| entry.id == "read-1").unwrap();
        assert_eq!(read.flags & (ROUTED | VISIBLE), ROUTED, "routed, not shown");
        let travelled = now["direct:myself@a.test"]
            .iter()
            .find(|entry| entry.id == "read-1")
            .unwrap();
        assert_ne!(
            travelled.flags & ACCOUNT_CONTROL,
            0,
            "flagged where it travels"
        );
        assert_eq!(read.flags & ACCOUNT_CONTROL, 0, "not on the routed copy");
        assert!(
            !alice.iter().any(|entry| entry.id == "typing-1"),
            "hidden kinds are not indexed"
        );
        let first = alice.iter().find(|entry| entry.id == "in-0").unwrap();
        assert_eq!(first.flags, INCOMING | VISIBLE);

        // Deletes by id and of a whole peer's inbound messages.
        let mut deletes = Pending::default();
        for i in (0..700).step_by(3) {
            deletes.delete_message_ids.insert(format!("in-{i}"));
        }
        deletes.delete_sent_message_ids.insert("read-1".into());
        deletes.delete_mls_message_ids.insert("g-2".into());
        block_on(db.apply(&deletes)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        let mut peer = Pending::default();
        peer.delete_messages_for_peers.insert("alice@a.test".into());
        block_on(db.apply(&peer)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        assert!(
            !indexed(&db).contains_key("direct:myself@a.test"),
            "an emptied conversation goes"
        );

        // Pages, newest first, continue where the last one stopped.
        let directory = block_on(load_directory(&db)).unwrap().unwrap();
        let all = &indexed(&db)["group:07070707-0707-0707-0707-070707070707"];
        let first_page = block_on(page(
            &db,
            &directory,
            "group:07070707-0707-0707-0707-070707070707",
            None,
            3,
        ))
        .unwrap();
        let rest = block_on(page(
            &db,
            &directory,
            "group:07070707-0707-0707-0707-070707070707",
            first_page.last(),
            10,
        ))
        .unwrap();
        let mut newest_first: Vec<EntryRef> = all.iter().rev().cloned().collect();
        let tail = newest_first.split_off(3);
        assert_eq!(first_page, newest_first);
        assert_eq!(rest, tail);
    }

    #[test]
    fn the_journal_tells_which_conversations_changed_since_a_mark() {
        let mut journal = Journal::default();
        journal.record(1, HashSet::from(["a".to_string()]));
        journal.record(3, HashSet::from(["b".to_string(), "a".to_string()]));
        assert_eq!(journal.since(0, 3), Some(vec!["a".into(), "b".into()]));
        assert_eq!(journal.since(1, 3), Some(vec!["a".into(), "b".into()]));
        assert_eq!(journal.since(3, 3), Some(vec![]));
        for commit in 4..(4 + JOURNAL_LIMIT as u64) {
            journal.record(commit, HashSet::from(["c".to_string()]));
        }
        let current = 3 + JOURNAL_LIMIT as u64;
        assert_eq!(journal.since(0, current), None, "older than what is kept");
        assert_eq!(journal.since(current - 1, current), Some(vec!["c".into()]));
    }

    #[test]
    fn an_existing_store_is_indexed_once_on_open() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut pending = Pending::default();
        for i in 0..300i64 {
            pending
                .messages
                .push(inbox(&format!("in-{i}"), "bob@a.test", 5_000 - i));
        }
        // Written before the index existed: nothing indexed yet.
        block_on(db.apply(&pending)).unwrap();
        assert!(block_on(load_directory(&db)).unwrap().is_none());
        block_on(ensure_built(&db)).unwrap();
        assert_eq!(indexed(&db), expected(&db));
        let commits = db.commit_count();
        block_on(ensure_built(&db)).unwrap();
        assert_eq!(db.commit_count(), commits, "a current index is left alone");
    }
}
