//! Browser [`ChatDb`] backed by IndexedDB.
//!
//! Every record is encrypted at rest (`store_cipher`,
//! `docs/research/16-browser-storage-architecture.md`): it is stored under a
//! keyed hash of its key, its value sealed under a store key wrapped by the
//! account master key. A store from before that is converted on first open.
//!
//! Each durable domain gets its own object store. A [`Pending`] unit of work is
//! queued into one IndexedDB read-write transaction spanning every store, so a
//! ratchet advance, ciphertext journal update, plaintext insert, and cursor move
//! either all commit or all abort. Records stay normalized: appending a message
//! never rewrites the rest of the local history.

use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;
use futures_util::future::join_all;
use js_sys::{Array, Uint8Array};
use rand_core::OsRng;
use rexie::{ObjectStore, Rexie, TransactionMode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::JsValue;

use crate::db::store_cipher::{keys, StoreCipher};
use crate::db::{
    AccountManifestHistoryRecordV1, ChatDb, ContactRecord, HistoryTransferJournalV1,
    ImportedHistoryRecordV1, InboundEnvelope, InboxMessage, LocalIdentity, LocalProfile,
    ManifestTrust, MlsHistoryMessage, MlsOutboxEntry, OutboxEntry, PeerProfile, Pending,
    SentMessage,
};
use crate::error::{ChatError, Result};

const LOCAL_IDENTITY: &str = "local_identity";
const SESSIONS: &str = "sessions";
const IDENTITIES: &str = "identities";
const PRE_KEYS: &str = "pre_keys";
const USED_PRE_KEYS: &str = "used_pre_keys";
const SIGNED_PRE_KEYS: &str = "signed_pre_keys";
const KYBER_PRE_KEYS: &str = "kyber_pre_keys";
const KYBER_SEEN: &str = "kyber_seen";
const SENDER_KEYS: &str = "sender_keys";
const OUTBOX: &str = "outbox";
const MLS_STATE: &str = "mls_state";
const MLS_OUTBOX: &str = "mls_outbox";
const MLS_MESSAGES: &str = "mls_messages";
const MESSAGES: &str = "messages";
const SENT_MESSAGES: &str = "sent_messages";
const IMPORTED_HISTORY: &str = "imported_history";
const HISTORY_TRANSFER_JOURNALS: &str = "history_transfer_journals";
const HISTORY_TRANSFER_FRAMES: &str = "history_transfer_frames";
const INBOUND: &str = "inbound";
const MANIFEST_TRUST: &str = "manifest_trust";
const MANIFEST_HISTORY: &str = "manifest_history";
const CONTACTS: &str = "contacts";
const LOCAL_PROFILE: &str = "local_profile";
const PEER_PROFILES: &str = "peer_profiles";
const META: &str = "meta";
/// Derived index records (conversation timelines), sealed like the rest.
const INDEX: &str = "index_values";

const ALL_STORES: [&str; 26] = [
    LOCAL_IDENTITY,
    SESSIONS,
    IDENTITIES,
    PRE_KEYS,
    USED_PRE_KEYS,
    SIGNED_PRE_KEYS,
    KYBER_PRE_KEYS,
    KYBER_SEEN,
    SENDER_KEYS,
    OUTBOX,
    MLS_STATE,
    MLS_OUTBOX,
    MLS_MESSAGES,
    MESSAGES,
    SENT_MESSAGES,
    IMPORTED_HISTORY,
    HISTORY_TRANSFER_JOURNALS,
    HISTORY_TRANSFER_FRAMES,
    INBOUND,
    MANIFEST_TRUST,
    MANIFEST_HISTORY,
    CONTACTS,
    LOCAL_PROFILE,
    PEER_PROFILES,
    META,
    INDEX,
];

const SINGLETON: &str = "value";
const LAST_CURSOR: &str = "last_cursor";
const LAST_SENT_SEQ: &str = "last_sent_seq";
const PENDING_PREKEY_UPLOAD: &str = "pending_prekey_upload";
const PREKEY_ROTATION: &str = "prekey_rotation";
const REPAIR_LIMITS: &str = "repair_limits";
const WRITER_GENERATION: &str = "writer_generation";
const PENDING_REGISTRATION: &str = "pending_registration";
/// Kept in `meta` under these plain names (not hashed, not sealed): the
/// wrapped store key, and the format the records are in.
const STORE_KEY: &str = "store_key";
const STORE_FORMAT: &str = "store_format";
const SEALED_FORMAT: &str = "sealed-v1";

/// One account/device-scoped browser chat database.
///
/// Callers must choose a stable name that is unique per authenticated account
/// and device. Sharing one database between accounts would also share identity
/// keys, sessions, and trust pins, so an empty name is rejected.
pub struct IndexedDbChatDb {
    db: Rexie,
    /// A second connection to the same database, for the write path: it
    /// opens transactions with strict durability (`commit`).
    writer: web_sys::IdbDatabase,
    /// The writer generation this tab holds (`ChatDb::claim_writer`); every
    /// write checks it inside its own transaction. `None` until claimed.
    fence: std::cell::Cell<Option<u64>>,
    cipher: StoreCipher,
    commits: std::cell::Cell<u64>,
    journal: std::cell::RefCell<crate::timeline::Journal>,
}

impl IndexedDbChatDb {
    /// Open (or create) the versioned browser database, encrypted under a key
    /// wrapped by `master_key` (the account master key). A store written
    /// before records were encrypted is converted here, in one transaction.
    pub async fn open(name: &str, master_key: &[u8; 32]) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(ChatError::Invalid(
                "IndexedDB chat database name must not be empty".into(),
            ));
        }

        let mut builder = Rexie::builder(name).version(12);
        for store in ALL_STORES {
            builder = builder.add_object_store(ObjectStore::new(store));
        }
        let db = idb(builder.build().await)?;
        // Opened after rexie created or upgraded the schema, without a
        // version: it joins the database as it now is.
        let writer = idb::Factory::new()
            .map_err(write_error)?
            .open(name, None)
            .map_err(write_error)?
            .await
            .map_err(write_error)?;
        let writer: web_sys::IdbDatabase = writer.into();
        let wrapped = plain_meta(&db, STORE_KEY)
            .await?
            .map(|value| Uint8Array::new(&value).to_vec());
        let cipher = match wrapped {
            Some(wrapped) => {
                let format = plain_meta(&db, STORE_FORMAT)
                    .await?
                    .and_then(|v| v.as_string());
                if format.as_deref() != Some(SEALED_FORMAT) {
                    return Err(ChatError::Db(
                        "the chat store is in an unknown format".into(),
                    ));
                }
                StoreCipher::unwrap(master_key, name, &wrapped)?
            }
            None => {
                let (cipher, wrapped) = StoreCipher::create(master_key, name, &mut OsRng)?;
                convert_plaintext_store(&db, &writer, &cipher, &wrapped).await?;
                cipher
            }
        };
        Ok(Self {
            db,
            writer,
            fence: std::cell::Cell::new(None),
            cipher,
            commits: std::cell::Cell::new(0),
            journal: std::cell::RefCell::new(crate::timeline::Journal::default()),
        })
    }

    /// Seal `value` for `key` in `store`, as an IndexedDB key and value.
    fn sealed(&self, store: &str, key: &[u8], value: &[u8]) -> Result<(JsValue, JsValue)> {
        let hashed = self.cipher.hashed_key(store, key);
        let sealed = self.cipher.seal(store, &hashed, key, value, &mut OsRng)?;
        Ok((
            JsValue::from_str(&hashed),
            Uint8Array::from(sealed.as_slice()).into(),
        ))
    }

    fn hashed(&self, store: &str, key: &[u8]) -> JsValue {
        JsValue::from_str(&self.cipher.hashed_key(store, key))
    }

    /// Open a stored record: its original key and value.
    fn opened(
        &self,
        store: &str,
        hashed: &JsValue,
        value: &JsValue,
    ) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)> {
        let hashed = hashed
            .as_string()
            .ok_or_else(|| ChatError::Db(format!("unexpected record key in {store}")))?;
        self.cipher
            .open(store, &hashed, &Uint8Array::new(value).to_vec())
    }

    fn put<'a>(&self, target: &'a Target, key: Vec<u8>, value: &[u8]) -> Result<Operation<'a>> {
        let (key, value) = self.sealed(target.name, &key, value)?;
        Ok(put_op(&target.store, value, key))
    }

    fn delete<'a>(&self, target: &'a Target, key: Vec<u8>) -> Operation<'a> {
        delete_op(&target.store, self.hashed(target.name, &key))
    }

    fn stage_puts<'a, K: IntoKey>(
        &self,
        operations: &mut Vec<Operation<'a>>,
        target: &'a Target,
        writes: impl IntoIterator<Item = (K, Vec<u8>)>,
    ) -> Result<()> {
        for (key, value) in writes {
            operations.push(self.put(target, key.into_key(), &value)?);
        }
        Ok(())
    }

    fn stage_map<'a, K: IntoKey>(
        &self,
        operations: &mut Vec<Operation<'a>>,
        target: &'a Target,
        writes: impl IntoIterator<Item = (K, Option<Vec<u8>>)>,
    ) -> Result<()> {
        for (key, value) in writes {
            let key = key.into_key();
            match value {
                Some(value) => operations.push(self.put(target, key, &value)?),
                None => operations.push(self.delete(target, key)),
            }
        }
        Ok(())
    }

    /// A read-write transaction over every store that commits only once the
    /// browser reports the data on disk. Without it Chrome's default lets a
    /// power loss undo a commit the code already acted on (a ratchet step
    /// after its message was sent). A browser without the option ignores it.
    /// A strict write transaction over `stores` (and the meta store) whose
    /// first request checks this tab still holds the writer generation. A
    /// tab that lost the lock to another and resumed gets nothing written.
    async fn fenced_write_transaction(&self, stores: &[&str]) -> Result<idb::Transaction> {
        let mut scope: Vec<&str> = stores.to_vec();
        if !scope.contains(&META) {
            scope.push(META);
        }
        let transaction = self.strict_write_transaction(&scope)?;
        if let Some(held) = self.fence.get() {
            let meta = transaction.object_store(META).map_err(write_error)?;
            let key = string_key(WRITER_GENERATION);
            let hashed = self.hashed(META, &key);
            let stored = meta
                .get(hashed.clone())
                .map_err(write_error)?
                .await
                .map_err(write_error)?;
            let current = match stored {
                Some(value) => decode::<u64>(&self.opened(META, &hashed, &value)?.1)?,
                None => 0,
            };
            if current != held {
                if let Ok(aborting) = transaction.abort() {
                    let _ = aborting.await;
                }
                self.fence.set(None);
                return Err(ChatError::Db(WRITER_SUPERSEDED.into()));
            }
        }
        Ok(transaction)
    }

    fn strict_write_transaction(&self, stores: &[&str]) -> Result<idb::Transaction> {
        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &"durability".into(), &"strict".into())
            .map_err(|error| ChatError::Db(format!("IndexedDB write options: {error:?}")))?;
        let names: js_sys::Array = stores.iter().map(|name| JsValue::from_str(name)).collect();
        let database: &DurableDatabase = wasm_bindgen::JsCast::unchecked_ref(&self.writer);
        let transaction = database
            .transaction_with_options(&names, "readwrite", &options)
            .map_err(|error| ChatError::Db(format!("IndexedDB write transaction: {error:?}")))?;
        Ok(transaction.into())
    }

    async fn get<T: DeserializeOwned>(&self, store_name: &str, key: Vec<u8>) -> Result<Option<T>> {
        let transaction = idb(self
            .db
            .transaction(&[store_name], TransactionMode::ReadOnly))?;
        let store = idb(transaction.store(store_name))?;
        let hashed = self.hashed(store_name, &key);
        match idb(store.get(hashed.clone()).await)? {
            Some(value) => Ok(Some(decode(&self.opened(store_name, &hashed, &value)?.1)?)),
            None => Ok(None),
        }
    }

    /// Every record of a store, opened: original key and value.
    async fn scan(&self, store_name: &str) -> Result<Vec<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)>> {
        let transaction = idb(self
            .db
            .transaction(&[store_name], TransactionMode::ReadOnly))?;
        let store = idb(transaction.store(store_name))?;
        let mut records = Vec::new();
        for (key, value) in idb(store.scan(None, None, None, None).await)? {
            // `meta` also holds the plain store key and format entries.
            if store_name == META
                && matches!(key.as_string().as_deref(), Some(STORE_KEY | STORE_FORMAT))
            {
                continue;
            }
            records.push(self.opened(store_name, &key, &value)?);
        }
        Ok(records)
    }

    async fn all<T: DeserializeOwned>(&self, store_name: &str) -> Result<Vec<T>> {
        self.scan(store_name)
            .await?
            .iter()
            .map(|(_, value)| decode(value))
            .collect()
    }
}

/// How a store keyed its records before they were sealed.
#[derive(Clone, Copy)]
enum LegacyKey {
    Text,
    Number,
    Pair,
    TextNumber,
    Triple,
}

fn legacy_key(shape: LegacyKey, key: &JsValue) -> Result<Vec<u8>> {
    let bad = || ChatError::Db("unexpected key in the plaintext chat store".into());
    let text = |value: JsValue| value.as_string().ok_or_else(bad);
    let number = |value: JsValue| {
        value
            .as_f64()
            .filter(|n| n.fract() == 0.0 && *n >= 0.0 && *n <= f64::from(u32::MAX))
            .map(|n| n as u32)
            .ok_or_else(bad)
    };
    Ok(match shape {
        LegacyKey::Text => string_key(&text(key.clone())?),
        LegacyKey::Number => number_key(number(key.clone())?),
        LegacyKey::Pair => {
            let parts = Array::from(key);
            pair_key(&text(parts.get(0))?, &text(parts.get(1))?)
        }
        LegacyKey::TextNumber => {
            let parts = Array::from(key);
            pair_number_key(&text(parts.get(0))?, number(parts.get(1))?)
        }
        LegacyKey::Triple => {
            let parts = Array::from(key);
            triple_key(
                &text(parts.get(0))?,
                &text(parts.get(1))?,
                &text(parts.get(2))?,
            )
        }
    })
}

async fn legacy_scan(db: &Rexie, name: &str) -> Result<Vec<(JsValue, JsValue)>> {
    let transaction = idb(db.transaction(&[name], TransactionMode::ReadOnly))?;
    let store = idb(transaction.store(name))?;
    idb(store.scan(None, None, None, None).await)
}

/// Convert a store written before records were sealed: read every record
/// the way it was written, then clear each object store and write it back
/// sealed, with the wrapped key and the format marker, in one durable
/// transaction. A crash leaves either the plaintext store or the sealed one.
async fn convert_plaintext_store(
    db: &Rexie,
    writer: &web_sys::IdbDatabase,
    cipher: &StoreCipher,
    wrapped: &[u8],
) -> Result<()> {
    let mut records: Vec<(&'static str, Vec<u8>, Vec<u8>)> = Vec::new();
    macro_rules! read {
        ($store:expr, $shape:expr, $ty:ty) => {
            for (key, value) in legacy_scan(db, $store).await? {
                let value: $ty = from_js(value)?;
                records.push(($store, legacy_key($shape, &key)?, encode(&value)?));
            }
        };
    }
    read!(LOCAL_IDENTITY, LegacyKey::Text, LocalIdentity);
    read!(SESSIONS, LegacyKey::Text, Vec<u8>);
    read!(IDENTITIES, LegacyKey::Text, Vec<u8>);
    read!(PRE_KEYS, LegacyKey::Number, Vec<u8>);
    read!(USED_PRE_KEYS, LegacyKey::Number, i64);
    read!(SIGNED_PRE_KEYS, LegacyKey::Number, Vec<u8>);
    read!(KYBER_PRE_KEYS, LegacyKey::Number, Vec<u8>);
    read!(KYBER_SEEN, LegacyKey::Text, bool);
    read!(SENDER_KEYS, LegacyKey::Pair, Vec<u8>);
    read!(OUTBOX, LegacyKey::Text, OutboxEntry);
    read!(MLS_STATE, LegacyKey::Text, Vec<u8>);
    read!(MLS_OUTBOX, LegacyKey::Text, MlsOutboxEntry);
    read!(MLS_MESSAGES, LegacyKey::Text, MlsHistoryMessage);
    read!(MESSAGES, LegacyKey::Text, InboxMessage);
    read!(SENT_MESSAGES, LegacyKey::Text, SentMessage);
    read!(IMPORTED_HISTORY, LegacyKey::Pair, ImportedHistoryRecordV1);
    read!(
        HISTORY_TRANSFER_JOURNALS,
        LegacyKey::Text,
        HistoryTransferJournalV1
    );
    read!(
        HISTORY_TRANSFER_FRAMES,
        LegacyKey::TextNumber,
        kutup_chat_proto::ChatHistoryTransferFrameV1
    );
    read!(INBOUND, LegacyKey::Text, InboundEnvelope);
    read!(MANIFEST_TRUST, LegacyKey::Text, ManifestTrust);
    read!(
        MANIFEST_HISTORY,
        LegacyKey::Triple,
        AccountManifestHistoryRecordV1
    );
    read!(CONTACTS, LegacyKey::Text, ContactRecord);
    read!(LOCAL_PROFILE, LegacyKey::Text, LocalProfile);
    read!(PEER_PROFILES, LegacyKey::Text, PeerProfile);
    for (key, value) in legacy_scan(db, META).await? {
        let name = key
            .as_string()
            .ok_or_else(|| ChatError::Db("unexpected key in the plaintext chat store".into()))?;
        let encoded = match name.as_str() {
            LAST_CURSOR | LAST_SENT_SEQ | WRITER_GENERATION => encode(&from_js::<u64>(value)?)?,
            PENDING_PREKEY_UPLOAD | PREKEY_ROTATION | REPAIR_LIMITS | PENDING_REGISTRATION => {
                encode(&from_js::<Vec<u8>>(value)?)?
            }
            other => {
                return Err(ChatError::Db(format!(
                    "unknown entry {other} in the plaintext chat store"
                )))
            }
        };
        records.push((META, string_key(&name), encoded));
    }

    let database: &DurableDatabase = wasm_bindgen::JsCast::unchecked_ref(writer);
    let options = js_sys::Object::new();
    js_sys::Reflect::set(&options, &"durability".into(), &"strict".into())
        .map_err(|error| ChatError::Db(format!("IndexedDB write options: {error:?}")))?;
    let names: Array = ALL_STORES
        .iter()
        .map(|name| JsValue::from_str(name))
        .collect();
    let transaction: idb::Transaction = database
        .transaction_with_options(&names, "readwrite", &options)
        .map_err(|error| ChatError::Db(format!("IndexedDB write transaction: {error:?}")))?
        .into();
    let stores = ALL_STORES
        .iter()
        .map(|name| Ok((*name, transaction.object_store(name).map_err(write_error)?)))
        .collect::<Result<std::collections::HashMap<_, _>>>()?;
    let mut clears = Vec::new();
    for store in stores.values() {
        clears.push(store.clear().map_err(write_error)?);
    }
    for clear in join_all(clears.into_iter().map(std::future::IntoFuture::into_future)).await {
        clear.map_err(write_error)?;
    }
    let mut operations = Vec::with_capacity(records.len() + 2);
    for (name, key, value) in &records {
        let hashed = cipher.hashed_key(name, key);
        let sealed = cipher.seal(name, &hashed, key, value, &mut OsRng)?;
        operations.push(put_op(
            &stores[name],
            Uint8Array::from(sealed.as_slice()).into(),
            JsValue::from_str(&hashed),
        ));
    }
    operations.push(put_op(
        &stores[META],
        Uint8Array::from(wrapped).into(),
        JsValue::from_str(STORE_KEY),
    ));
    operations.push(put_op(
        &stores[META],
        JsValue::from_str(SEALED_FORMAT),
        JsValue::from_str(STORE_FORMAT),
    ));
    finish_write(transaction, operations).await
}

/// A plain (unsealed) `meta` entry: the wrapped store key and the format.
async fn plain_meta(db: &Rexie, name: &str) -> Result<Option<JsValue>> {
    let transaction = idb(db.transaction(&[META], TransactionMode::ReadOnly))?;
    let store = idb(transaction.store(META))?;
    idb(store.get(JsValue::from_str(name)).await)
}

/// An object store in a write transaction, with the name its records are
/// sealed under.
struct Target {
    store: idb::ObjectStore,
    name: &'static str,
}

#[async_trait(?Send)]
impl ChatDb for IndexedDbChatDb {
    async fn load_local_identity(&self) -> Result<Option<LocalIdentity>> {
        self.get(LOCAL_IDENTITY, string_key(SINGLETON)).await
    }

    async fn load_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.get(SESSIONS, string_key(address)).await
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.get(IDENTITIES, string_key(address)).await
    }

    async fn load_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        self.get(PRE_KEYS, number_key(id)).await
    }

    async fn purge_used_pre_keys(&self, used_before_ms: i64) -> Result<u64> {
        // Discover candidates in a completed read transaction, then delete each
        // marker and private record together in a separate atomic transaction.
        // A single Engine owns a device DB, so there is no competing re-add.
        let candidates = self
            .scan(USED_PRE_KEYS)
            .await?
            .into_iter()
            .filter_map(|(key, value)| match decode::<i64>(&value) {
                Ok(used_at) if used_at <= used_before_ms => keys::as_number(&key),
                _ => None,
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Ok(0);
        }

        let transaction = self
            .fenced_write_transaction(&[PRE_KEYS, USED_PRE_KEYS])
            .await?;
        let pre_keys = target(&transaction, PRE_KEYS)?;
        let used = target(&transaction, USED_PRE_KEYS)?;
        let mut operations = Vec::with_capacity(candidates.len() * 2);
        for id in &candidates {
            operations.push(self.delete(&pre_keys, number_key(*id)));
            operations.push(self.delete(&used, number_key(*id)));
        }
        finish_write(transaction, operations).await?;
        Ok(candidates.len() as u64)
    }

    async fn load_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        self.get(SIGNED_PRE_KEYS, number_key(id)).await
    }

    async fn load_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        self.get(KYBER_PRE_KEYS, number_key(id)).await
    }

    async fn kyber_base_key_seen(
        &self,
        kyber_id: u32,
        ec_id: u32,
        base_key: &[u8],
    ) -> Result<bool> {
        let transaction = idb(self
            .db
            .transaction(&[KYBER_SEEN], TransactionMode::ReadOnly))?;
        let store = idb(transaction.store(KYBER_SEEN))?;
        idb(store
            .key_exists(self.hashed(
                KYBER_SEEN,
                &string_key(&kyber_seen_key(kyber_id, ec_id, base_key)),
            ))
            .await)
    }

    async fn load_sender_key(
        &self,
        address: &str,
        distribution_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.get(SENDER_KEYS, pair_key(address, distribution_id))
            .await
    }

    async fn load_outbox(&self, send_id: &str) -> Result<Option<OutboxEntry>> {
        self.get(OUTBOX, string_key(send_id)).await
    }

    async fn list_outbox(&self) -> Result<Vec<OutboxEntry>> {
        let mut entries = self.all::<OutboxEntry>(OUTBOX).await?;
        entries.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.send_id.cmp(&right.send_id))
        });
        Ok(entries)
    }

    async fn load_mls_outbox(&self, send_id: &str) -> Result<Option<MlsOutboxEntry>> {
        self.get(MLS_OUTBOX, string_key(send_id)).await
    }

    async fn list_mls_outbox(&self) -> Result<Vec<MlsOutboxEntry>> {
        let mut entries = self.all::<MlsOutboxEntry>(MLS_OUTBOX).await?;
        entries.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.send_id.cmp(&right.send_id))
        });
        Ok(entries)
    }

    async fn load_mls_message(&self, record_id: &str) -> Result<Option<MlsHistoryMessage>> {
        self.get(MLS_MESSAGES, string_key(record_id)).await
    }

    async fn list_mls_messages(&self) -> Result<Vec<MlsHistoryMessage>> {
        let mut messages = self.all::<MlsHistoryMessage>(MLS_MESSAGES).await?;
        messages.sort_by(|left, right| {
            left.timestamp_ms
                .cmp(&right.timestamp_ms)
                .then_with(|| left.record_id.cmp(&right.record_id))
        });
        Ok(messages)
    }

    async fn load_mls_state(&self) -> Result<Option<Vec<u8>>> {
        self.get(MLS_STATE, string_key(SINGLETON)).await
    }

    async fn load_last_cursor(&self) -> Result<Option<u64>> {
        self.get(META, string_key(LAST_CURSOR)).await
    }

    async fn load_last_sent_seq(&self) -> Result<Option<u64>> {
        self.get(META, string_key(LAST_SENT_SEQ)).await
    }

    async fn list_messages(&self) -> Result<Vec<InboxMessage>> {
        let mut messages = self.all::<InboxMessage>(MESSAGES).await?;
        messages.sort_by(|left, right| {
            left.cursor
                .cmp(&right.cursor)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(messages)
    }

    async fn load_message(&self, id: &str) -> Result<Option<InboxMessage>> {
        self.get(MESSAGES, string_key(id)).await
    }

    async fn load_index_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(INDEX, key.to_vec()).await
    }

    async fn load_sent_message(&self, send_id: &str) -> Result<Option<SentMessage>> {
        self.get(SENT_MESSAGES, string_key(send_id)).await
    }

    async fn list_sent_messages(&self) -> Result<Vec<SentMessage>> {
        let mut messages = self.all::<SentMessage>(SENT_MESSAGES).await?;
        messages.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.send_id.cmp(&right.send_id))
        });
        Ok(messages)
    }

    async fn load_imported_history(
        &self,
        transfer_id: &str,
        source_record_id: &str,
    ) -> Result<Option<ImportedHistoryRecordV1>> {
        self.get(IMPORTED_HISTORY, pair_key(transfer_id, source_record_id))
            .await
    }

    async fn list_imported_history(&self) -> Result<Vec<ImportedHistoryRecordV1>> {
        let mut records = self
            .all::<ImportedHistoryRecordV1>(IMPORTED_HISTORY)
            .await?;
        records.sort_by(|left, right| {
            left.timestamp_ms
                .cmp(&right.timestamp_ms)
                .then_with(|| left.transfer_id.cmp(&right.transfer_id))
                .then_with(|| left.source_record_id.cmp(&right.source_record_id))
        });
        Ok(records)
    }

    async fn load_history_transfer_journal(
        &self,
        transfer_id: &str,
    ) -> Result<Option<HistoryTransferJournalV1>> {
        self.get(HISTORY_TRANSFER_JOURNALS, string_key(transfer_id))
            .await
    }

    async fn list_history_transfer_frames(
        &self,
        transfer_id: &str,
    ) -> Result<Vec<kutup_chat_proto::ChatHistoryTransferFrameV1>> {
        let mut frames = Vec::new();
        for frame in self
            .all::<kutup_chat_proto::ChatHistoryTransferFrameV1>(HISTORY_TRANSFER_FRAMES)
            .await?
        {
            if frame.transfer_id == transfer_id {
                frames.push(frame);
            }
        }
        frames.sort_by_key(|frame: &kutup_chat_proto::ChatHistoryTransferFrameV1| frame.index);
        Ok(frames)
    }

    async fn list_inbound(&self) -> Result<Vec<InboundEnvelope>> {
        let mut inbound = self.all::<InboundEnvelope>(INBOUND).await?;
        inbound.sort_by(|left, right| {
            left.cursor
                .cmp(&right.cursor)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(inbound)
    }

    async fn load_manifest_trust(&self, peer: &str) -> Result<Option<ManifestTrust>> {
        self.get(MANIFEST_TRUST, string_key(peer)).await
    }

    async fn load_manifest_history(
        &self,
        peer: &str,
        incarnation_id: &str,
        version: u64,
    ) -> Result<Option<AccountManifestHistoryRecordV1>> {
        self.get(
            MANIFEST_HISTORY,
            triple_key(peer, incarnation_id, &version.to_string()),
        )
        .await
    }

    async fn load_contact(&self, peer: &str) -> Result<Option<ContactRecord>> {
        self.get(CONTACTS, string_key(peer)).await
    }

    async fn list_contacts(&self) -> Result<Vec<ContactRecord>> {
        let mut contacts = self.all::<ContactRecord>(CONTACTS).await?;
        contacts.sort_by(|left, right| left.peer.cmp(&right.peer));
        Ok(contacts)
    }

    async fn load_local_profile(&self) -> Result<Option<LocalProfile>> {
        self.get(LOCAL_PROFILE, string_key(SINGLETON)).await
    }

    async fn load_peer_profile(&self, peer: &str) -> Result<Option<PeerProfile>> {
        self.get(PEER_PROFILES, string_key(peer)).await
    }

    async fn list_peer_profiles(&self) -> Result<Vec<PeerProfile>> {
        let mut profiles = self.all::<PeerProfile>(PEER_PROFILES).await?;
        profiles.sort_by(|left, right| left.peer.cmp(&right.peer));
        Ok(profiles)
    }

    async fn load_pending_prekey_upload(&self) -> Result<Option<Vec<u8>>> {
        self.get(META, string_key(PENDING_PREKEY_UPLOAD)).await
    }

    async fn load_prekey_rotation(&self) -> Result<Option<Vec<u8>>> {
        self.get(META, string_key(PREKEY_ROTATION)).await
    }

    async fn load_repair_limits(&self) -> Result<Option<Vec<u8>>> {
        self.get(META, string_key(REPAIR_LIMITS)).await
    }

    async fn claim_writer(&self, take_over: bool) -> Result<u64> {
        if !take_over {
            let current = self
                .get::<u64>(META, string_key(WRITER_GENERATION))
                .await?
                .unwrap_or(0);
            self.fence.set(Some(current));
            return Ok(current);
        }
        // Read and move on the generation in one strict transaction, so two
        // tabs taking over at once still end on different generations.
        let transaction = self.strict_write_transaction(&[META])?;
        let meta = target(&transaction, META)?;
        let key = string_key(WRITER_GENERATION);
        let hashed = self.hashed(META, &key);
        let stored = meta
            .store
            .get(hashed.clone())
            .map_err(write_error)?
            .await
            .map_err(write_error)?;
        let current = match stored {
            Some(value) => decode::<u64>(&self.opened(META, &hashed, &value)?.1)?,
            None => 0,
        };
        let next = current
            .checked_add(1)
            .ok_or_else(|| ChatError::Db("writer generation exhausted".into()))?;
        let operations = vec![self.put(&meta, key, &encode(&next)?)?];
        finish_write(transaction, operations).await?;
        self.fence.set(Some(next));
        Ok(next)
    }

    async fn load_pending_registration(&self) -> Result<Option<Vec<u8>>> {
        self.get(META, string_key(PENDING_REGISTRATION)).await
    }

    async fn apply(&self, pending: &Pending) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }

        let message_deletes = if pending.delete_messages_for_peers.is_empty() {
            Vec::new()
        } else {
            self.all::<InboxMessage>(MESSAGES)
                .await?
                .into_iter()
                .filter(|message| pending.delete_messages_for_peers.contains(&message.peer))
                .map(|message| message.id)
                .collect()
        };
        let mut cascaded_transfer_frame_deletes = Vec::new();
        for (transfer_id, journal) in &pending.history_transfer_journals {
            if journal.is_none() {
                for frame in self.list_history_transfer_frames(transfer_id).await? {
                    let key = (transfer_id.clone(), frame.index);
                    if !pending.history_transfer_frames.contains_key(&key) {
                        cascaded_transfer_frame_deletes.push(key);
                    }
                }
            }
        }

        // IndexedDB has one writer in this engine. Check immutable records
        // before opening the atomic write transaction; an existing different
        // value is a durable cryptographic contradiction, never an upsert.
        for ((peer, incarnation_id, version), record) in &pending.manifest_history {
            if let Some(existing) = self
                .load_manifest_history(peer, incarnation_id, *version)
                .await?
            {
                if existing != *record {
                    return Err(ChatError::Trust(format!(
                        "immutable manifest history conflicts at {peer} version {version}"
                    )));
                }
            }
        }
        for ((transfer_id, source_record_id), record) in &pending.imported_history {
            if let Some(existing) = self
                .load_imported_history(transfer_id, source_record_id)
                .await?
            {
                if existing != *record {
                    return Err(ChatError::Trust(format!(
                        "immutable imported history conflicts at {transfer_id}/{source_record_id}"
                    )));
                }
            }
        }
        for ((transfer_id, index), frame) in &pending.history_transfer_frames {
            if let Some(existing) = self
                .get::<kutup_chat_proto::ChatHistoryTransferFrameV1>(
                    HISTORY_TRANSFER_FRAMES,
                    pair_number_key(transfer_id, *index),
                )
                .await?
            {
                if frame.as_ref().is_some_and(|frame| *frame != existing) {
                    return Err(ChatError::Trust(format!(
                        "history transfer frame {transfer_id}/{index} changed across retry"
                    )));
                }
            }
        }

        // Serialize before opening the transaction. Serialization cannot leave
        // a partially queued write-set, and 64-bit counters become JS BigInts
        // instead of lossy Numbers.
        let mut writes = PreparedWrites::from_pending(pending)?;
        // The conversation timelines move with the records they index.
        let crate::timeline::Changes {
            writes: mut index_values,
            conversations: touched,
        } = crate::timeline::changes(self, pending).await?;
        for (key, value) in &pending.index_values {
            index_values.insert(key.clone(), value.clone());
        }

        let transaction = self.fenced_write_transaction(&ALL_STORES).await?;
        let store = |name: &'static str| target(&transaction, name);
        let local_identity = store(LOCAL_IDENTITY)?;
        let sessions = store(SESSIONS)?;
        let identities = store(IDENTITIES)?;
        let pre_keys = store(PRE_KEYS)?;
        let used_pre_keys = store(USED_PRE_KEYS)?;
        let signed_pre_keys = store(SIGNED_PRE_KEYS)?;
        let kyber_pre_keys = store(KYBER_PRE_KEYS)?;
        let kyber_seen = store(KYBER_SEEN)?;
        let sender_keys = store(SENDER_KEYS)?;
        let outbox = store(OUTBOX)?;
        let mls_state = store(MLS_STATE)?;
        let mls_outbox = store(MLS_OUTBOX)?;
        let mls_messages = store(MLS_MESSAGES)?;
        let messages = store(MESSAGES)?;
        let sent_messages = store(SENT_MESSAGES)?;
        let imported_history = store(IMPORTED_HISTORY)?;
        let history_transfer_journals = store(HISTORY_TRANSFER_JOURNALS)?;
        let history_transfer_frames = store(HISTORY_TRANSFER_FRAMES)?;
        let inbound = store(INBOUND)?;
        let manifest_trust = store(MANIFEST_TRUST)?;
        let manifest_history = store(MANIFEST_HISTORY)?;
        let contacts = store(CONTACTS)?;
        let local_profile = store(LOCAL_PROFILE)?;
        let peer_profiles = store(PEER_PROFILES)?;
        let meta = store(META)?;
        let index = store(INDEX)?;

        let mut operations = Vec::new();
        for (key, value) in &index_values {
            match value {
                Some(value) => operations.push(self.put(&index, key.clone(), &encode(value)?)?),
                None => operations.push(self.delete(&index, key.clone())),
            }
        }
        if let Some(value) = writes.local_identity.take() {
            operations.push(self.put(&local_identity, string_key(SINGLETON), &value)?);
        }
        self.stage_map(&mut operations, &sessions, writes.sessions)?;
        self.stage_puts(&mut operations, &identities, writes.identities)?;
        for (id, value) in writes.pre_keys {
            match value {
                Some(value) => {
                    operations.push(self.put(&pre_keys, number_key(id), &value)?);
                    operations.push(self.delete(&used_pre_keys, number_key(id)));
                }
                None => operations.push(self.put(
                    &used_pre_keys,
                    number_key(id),
                    &encode(&crate::clock::unix_millis())?,
                )?),
            }
        }
        self.stage_puts(&mut operations, &signed_pre_keys, writes.signed_pre_keys)?;
        self.stage_puts(&mut operations, &kyber_pre_keys, writes.kyber_pre_keys)?;
        // Retired keys go; their replay-guard rows (a few bytes each) stay,
        // since they are keyed by the whole triple and cannot be ranged here.
        for id in writes.delete_signed_pre_keys {
            operations.push(self.delete(&signed_pre_keys, number_key(id)));
        }
        for id in writes.delete_kyber_pre_keys {
            operations.push(self.delete(&kyber_pre_keys, number_key(id)));
        }
        for (key, value) in writes.kyber_seen {
            operations.push(self.put(&kyber_seen, string_key(&key), &value)?);
        }
        for ((address, distribution_id), value) in writes.sender_keys {
            operations.push(self.put(
                &sender_keys,
                pair_key(&address, &distribution_id),
                &value,
            )?);
        }
        self.stage_map(&mut operations, &outbox, writes.outbox)?;
        if let Some(value) = writes.mls_state.take() {
            operations.push(self.put(&mls_state, string_key(SINGLETON), &value)?);
        }
        self.stage_map(&mut operations, &mls_outbox, writes.mls_outbox)?;
        self.stage_puts(&mut operations, &mls_messages, writes.mls_messages)?;
        for record_id in &pending.delete_mls_message_ids {
            operations.push(self.delete(&mls_messages, string_key(record_id)));
        }
        for (id, value) in writes.messages {
            operations.push(self.put(&messages, string_key(&id), &value)?);
        }
        for id in message_deletes {
            operations.push(self.delete(&messages, string_key(&id)));
        }
        for id in &pending.delete_message_ids {
            operations.push(self.delete(&messages, string_key(id)));
        }
        self.stage_puts(&mut operations, &sent_messages, writes.sent_messages)?;
        for send_id in &pending.delete_sent_message_ids {
            operations.push(self.delete(&sent_messages, string_key(send_id)));
        }
        for ((transfer_id, source_record_id), value) in writes.imported_history {
            operations.push(self.put(
                &imported_history,
                pair_key(&transfer_id, &source_record_id),
                &value,
            )?);
        }
        for (transfer_id, source_record_id) in &pending.delete_imported_history_ids {
            operations
                .push(self.delete(&imported_history, pair_key(transfer_id, source_record_id)));
        }
        self.stage_map(
            &mut operations,
            &history_transfer_journals,
            writes.history_transfer_journals,
        )?;
        for ((transfer_id, index), value) in writes.history_transfer_frames {
            let key = pair_number_key(&transfer_id, index);
            match value {
                Some(value) => operations.push(self.put(&history_transfer_frames, key, &value)?),
                None => operations.push(self.delete(&history_transfer_frames, key)),
            }
        }
        for (transfer_id, index) in cascaded_transfer_frame_deletes {
            operations.push(self.delete(
                &history_transfer_frames,
                pair_number_key(&transfer_id, index),
            ));
        }
        self.stage_map(&mut operations, &inbound, writes.inbound)?;
        self.stage_puts(&mut operations, &manifest_trust, writes.manifest_trust)?;
        for ((peer, incarnation_id, version), value) in writes.manifest_history {
            operations.push(self.put(
                &manifest_history,
                triple_key(&peer, &incarnation_id, &version.to_string()),
                &value,
            )?);
        }
        self.stage_puts(&mut operations, &contacts, writes.contacts)?;
        if let Some(value) = writes.local_profile.take() {
            operations.push(self.put(&local_profile, string_key(SINGLETON), &value)?);
        }
        self.stage_puts(&mut operations, &peer_profiles, writes.peer_profiles)?;
        if let Some(value) = writes.prekey_rotation {
            operations.push(self.put(&meta, string_key(PREKEY_ROTATION), &value)?);
        }
        if let Some(value) = writes.repair_limits {
            operations.push(self.put(&meta, string_key(REPAIR_LIMITS), &value)?);
        }
        if let Some(value) = writes.prekey_upload {
            match value {
                Some(value) => {
                    operations.push(self.put(&meta, string_key(PENDING_PREKEY_UPLOAD), &value)?)
                }
                None => operations.push(self.delete(&meta, string_key(PENDING_PREKEY_UPLOAD))),
            }
        }
        if let Some(value) = writes.registration_upload {
            match value {
                Some(value) => {
                    operations.push(self.put(&meta, string_key(PENDING_REGISTRATION), &value)?)
                }
                None => operations.push(self.delete(&meta, string_key(PENDING_REGISTRATION))),
            }
        }
        if let Some(cursor) = writes.last_cursor {
            operations.push(self.put(&meta, string_key(LAST_CURSOR), &cursor)?);
        }
        if let Some(seq) = writes.last_sent_seq {
            operations.push(self.put(&meta, string_key(LAST_SENT_SEQ), &seq)?);
        }

        finish_write(transaction, operations).await?;
        self.commits.set(self.commits.get() + 1);
        self.journal
            .borrow_mut()
            .record(self.commits.get(), touched);
        Ok(())
    }

    fn commit_count(&self) -> u64 {
        self.commits.get()
    }

    fn changed_conversations(&self, since: u64) -> Option<Vec<String>> {
        self.journal.borrow().since(since, self.commits.get())
    }
}

type Operation<'a> = Pin<Box<dyn Future<Output = std::result::Result<(), idb::Error>> + 'a>>;

fn put_op(store: &idb::ObjectStore, value: JsValue, key: JsValue) -> Operation<'_> {
    Box::pin(async move { store.put(&value, Some(&key))?.await.map(|_| ()) })
}

fn delete_op(store: &idb::ObjectStore, key: JsValue) -> Operation<'_> {
    Box::pin(async move { store.delete(idb::Query::Key(key))?.await })
}

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    /// `IDBDatabase.transaction(names, mode, options)`. web-sys exposes the
    /// options only behind its unstable-API flag; the call itself is in every
    /// current browser, and one without `durability` ignores the member.
    #[wasm_bindgen(extends = js_sys::Object)]
    type DurableDatabase;

    #[wasm_bindgen(method, catch, js_name = transaction)]
    fn transaction_with_options(
        this: &DurableDatabase,
        names: &js_sys::Array,
        mode: &str,
        options: &js_sys::Object,
    ) -> std::result::Result<web_sys::IdbTransaction, JsValue>;
}

/// The error a write gets when another tab took the store over.
pub(crate) const WRITER_SUPERSEDED: &str = "chat storage was taken over by another tab";

fn write_error(error: impl std::fmt::Display) -> ChatError {
    ChatError::Db(format!("IndexedDB write: {error}"))
}

async fn finish_write(transaction: idb::Transaction, operations: Vec<Operation<'_>>) -> Result<()> {
    let results = join_all(operations).await;
    if let Some(error) = results.into_iter().find_map(std::result::Result::err) {
        if let Ok(aborting) = transaction.abort() {
            let _ = aborting.await;
        }
        return Err(write_error(error));
    }
    // Resolves on `complete`, which with strict durability fires only once
    // the browser reports the data flushed to disk.
    let result = transaction
        .commit()
        .map_err(write_error)?
        .await
        .map_err(write_error)?;
    if result.is_committed() {
        Ok(())
    } else {
        Err(ChatError::Db("IndexedDB write was not committed".into()))
    }
}

trait IntoKey {
    fn into_key(self) -> Vec<u8>;
}

impl IntoKey for String {
    fn into_key(self) -> Vec<u8> {
        string_key(&self)
    }
}

impl IntoKey for u32 {
    fn into_key(self) -> Vec<u8> {
        number_key(self)
    }
}

#[derive(Default)]
struct PreparedWrites {
    local_identity: Option<Vec<u8>>,
    sessions: Vec<(String, Option<Vec<u8>>)>,
    identities: Vec<(String, Vec<u8>)>,
    pre_keys: Vec<(u32, Option<Vec<u8>>)>,
    signed_pre_keys: Vec<(u32, Vec<u8>)>,
    kyber_pre_keys: Vec<(u32, Vec<u8>)>,
    kyber_seen: Vec<(String, Vec<u8>)>,
    sender_keys: Vec<((String, String), Vec<u8>)>,
    outbox: Vec<(String, Option<Vec<u8>>)>,
    mls_state: Option<Vec<u8>>,
    mls_outbox: Vec<(String, Option<Vec<u8>>)>,
    mls_messages: Vec<(String, Vec<u8>)>,
    messages: Vec<(String, Vec<u8>)>,
    sent_messages: Vec<(String, Vec<u8>)>,
    imported_history: Vec<((String, String), Vec<u8>)>,
    history_transfer_journals: Vec<(String, Option<Vec<u8>>)>,
    history_transfer_frames: Vec<((String, u32), Option<Vec<u8>>)>,
    inbound: Vec<(String, Option<Vec<u8>>)>,
    manifest_trust: Vec<(String, Vec<u8>)>,
    manifest_history: Vec<((String, String, u64), Vec<u8>)>,
    contacts: Vec<(String, Vec<u8>)>,
    local_profile: Option<Vec<u8>>,
    peer_profiles: Vec<(String, Vec<u8>)>,
    prekey_upload: Option<Option<Vec<u8>>>,
    prekey_rotation: Option<Vec<u8>>,
    repair_limits: Option<Vec<u8>>,
    delete_signed_pre_keys: Vec<u32>,
    delete_kyber_pre_keys: Vec<u32>,
    registration_upload: Option<Option<Vec<u8>>>,
    last_cursor: Option<Vec<u8>>,
    last_sent_seq: Option<Vec<u8>>,
}

impl PreparedWrites {
    fn from_pending(pending: &Pending) -> Result<Self> {
        Ok(Self {
            local_identity: pending.local_identity.as_ref().map(encode).transpose()?,
            sessions: serialize_optional_map(&pending.sessions)?,
            identities: serialize_map(&pending.identities)?,
            pre_keys: serialize_optional_map(&pending.pre_keys)?,
            signed_pre_keys: serialize_map(&pending.signed_pre_keys)?,
            kyber_pre_keys: serialize_map(&pending.kyber_pre_keys)?,
            kyber_seen: pending
                .kyber_seen
                .iter()
                .map(|(kyber_id, ec_id, base_key)| {
                    Ok((kyber_seen_key(*kyber_id, *ec_id, base_key), encode(&true)?))
                })
                .collect::<Result<_>>()?,
            sender_keys: pending
                .sender_keys
                .iter()
                .map(|(key, value)| Ok((key.clone(), encode(value)?)))
                .collect::<Result<_>>()?,
            outbox: serialize_optional_map(&pending.outbox)?,
            mls_state: pending.mls_state.as_ref().map(encode).transpose()?,
            mls_outbox: serialize_optional_map(&pending.mls_outbox)?,
            mls_messages: serialize_map(&pending.mls_messages)?,
            messages: pending
                .messages
                .iter()
                .map(|message| Ok((message.id.clone(), encode(message)?)))
                .collect::<Result<_>>()?,
            sent_messages: serialize_map(&pending.sent_messages)?,
            imported_history: serialize_map(&pending.imported_history)?,
            history_transfer_journals: serialize_optional_map(&pending.history_transfer_journals)?,
            history_transfer_frames: serialize_optional_map(&pending.history_transfer_frames)?,
            inbound: serialize_optional_map(&pending.inbound)?,
            manifest_trust: serialize_map(&pending.manifest_trust)?,
            manifest_history: serialize_map(&pending.manifest_history)?,
            contacts: serialize_map(&pending.contacts)?,
            local_profile: pending.local_profile.as_ref().map(encode).transpose()?,
            peer_profiles: serialize_map(&pending.peer_profiles)?,
            prekey_upload: pending
                .prekey_upload
                .as_ref()
                .map(|value| value.as_ref().map(encode).transpose())
                .transpose()?,
            prekey_rotation: pending.prekey_rotation.as_ref().map(encode).transpose()?,
            repair_limits: pending.repair_limits.as_ref().map(encode).transpose()?,
            delete_signed_pre_keys: pending.delete_signed_pre_keys.iter().copied().collect(),
            delete_kyber_pre_keys: pending.delete_kyber_pre_keys.iter().copied().collect(),
            registration_upload: pending
                .registration_upload
                .as_ref()
                .map(|value| value.as_ref().map(encode).transpose())
                .transpose()?,
            last_cursor: pending.last_cursor.as_ref().map(encode).transpose()?,
            last_sent_seq: pending.last_sent_seq.as_ref().map(encode).transpose()?,
        })
    }
}

fn serialize_map<K, V>(values: &std::collections::HashMap<K, V>) -> Result<Vec<(K, Vec<u8>)>>
where
    K: Clone + Eq + std::hash::Hash,
    V: Serialize,
{
    values
        .iter()
        .map(|(key, value)| Ok((key.clone(), encode(value)?)))
        .collect()
}

fn serialize_optional_map<K, V>(
    values: &std::collections::HashMap<K, Option<V>>,
) -> Result<Vec<(K, Option<Vec<u8>>)>>
where
    K: Clone + Eq + std::hash::Hash,
    V: Serialize,
{
    values
        .iter()
        .map(|(key, value)| Ok((key.clone(), value.as_ref().map(encode).transpose()?)))
        .collect()
}

fn string_key(value: &str) -> Vec<u8> {
    keys::text(value)
}

fn number_key(value: u32) -> Vec<u8> {
    keys::number(value)
}

fn pair_key(left: &str, right: &str) -> Vec<u8> {
    keys::pair(left, right)
}

fn pair_number_key(left: &str, right: u32) -> Vec<u8> {
    keys::text_number(left, right)
}

fn triple_key(first: &str, second: &str, third: &str) -> Vec<u8> {
    keys::triple(first, second, third)
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)
        .map_err(|error| ChatError::Db(format!("chat store encode: {error}")))?;
    Ok(out)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes)
        .map_err(|error| ChatError::Db(format!("chat store decode: {error}")))
}

fn target(transaction: &idb::Transaction, name: &'static str) -> Result<Target> {
    Ok(Target {
        store: transaction.object_store(name).map_err(write_error)?,
        name,
    })
}

fn kyber_seen_key(kyber_id: u32, ec_id: u32, base_key: &[u8]) -> String {
    format!("{kyber_id}:{ec_id}:{}", hex::encode(base_key))
}

fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|error| ChatError::Db(format!("IndexedDB decode: {error}")))
}

fn idb<T>(result: rexie::Result<T>) -> Result<T> {
    result.map_err(|error| ChatError::Db(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AuthorityTrust, InboundFailureKind, InboundState};
    use base64::Engine as _;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn atomically_round_trips_every_durable_domain() {
        let name = format!("kutup-chat-test-{}", js_sys::Date::now());
        let db = IndexedDbChatDb::open(&name, &[3; 32]).await.unwrap();
        let mut pending = Pending::default();
        pending.local_identity = Some(LocalIdentity {
            identity_key_pair: vec![1, 2, 3],
            registration_id: 42,
            device_id: Some(3),
        });
        pending.sessions.insert("alice.1".into(), Some(vec![4]));
        pending.identities.insert("alice.1".into(), vec![5]);
        pending.pre_keys.insert(7, Some(vec![6]));
        pending.signed_pre_keys.insert(8, vec![7]);
        pending.kyber_pre_keys.insert(9, vec![8]);
        pending.kyber_seen.push((9, 7, vec![9]));
        pending
            .sender_keys
            .insert(("alice.1".into(), "distribution".into()), vec![10]);
        pending.outbox.insert(
            "send-1".into(),
            Some(OutboxEntry {
                send_id: "send-1".into(),
                peer: "alice".into(),
                content: vec![11],
                envelopes: vec![12],
                attempts: 1,
                created_at: 100,
                primary_delivered: false,
                sealed_sender: false,
                sealed_capability: None,
                sync: None,
            }),
        );
        pending.messages.push(InboxMessage {
            id: "message-1".into(),
            peer: "alice".into(),
            sender_device_id: 1,
            cursor: 12,
            content: vec![13],
            received_at: 101,
        });
        pending.sent_messages.insert(
            "sent-1".into(),
            SentMessage {
                send_id: "sent-1".into(),
                peer: "alice".into(),
                sender_device_id: 1,
                content: vec![17],
                created_at: 99,
                delivered_at: Some(103),
                delivered: true,
                deduplicated: false,
            },
        );
        let imported = ImportedHistoryRecordV1 {
            transfer_id: "11111111-1111-4111-8111-111111111111".into(),
            source_record_id: "source-1".into(),
            source_device_id: 1,
            conversation: kutup_chat_proto::ConversationId::direct(
                kutup_chat_proto::AccountAddress::federated("alice", "a.test").unwrap(),
            ),
            sender: "alice@a.test".into(),
            sender_device_id: 1,
            outgoing: false,
            content: vec![18],
            timestamp_ms: 98,
            delivered: true,
        };
        pending.imported_history.insert(
            (
                imported.transfer_id.clone(),
                imported.source_record_id.clone(),
            ),
            imported.clone(),
        );
        let b64 = |byte, len| base64::engine::general_purpose::STANDARD.encode(vec![byte; len]);
        let request = kutup_chat_proto::ChatHistoryTransferRequestV1 {
            version: 1,
            transfer_id: "11111111-1111-4111-8111-111111111111".into(),
            account: "alice@a.test".into(),
            requesting_device_id: 3,
            manifest_sequence: 1,
            ephemeral_public_key: b64(1, 32),
            request_nonce: b64(2, 32),
            created_at_unix: 1_000,
            expires_at_unix: 1_900,
            device_signature: b64(3, 64),
        };
        let journal = HistoryTransferJournalV1 {
            transfer_id: request.transfer_id.clone(),
            role: crate::HistoryTransferRoleV1::Requester,
            state: crate::HistoryTransferJournalStateV1::Requested,
            request,
            acceptance: None,
            ephemeral_secret: [4; 32],
            next_frame_index: 0,
            updated_at_unix: 1_000,
        };
        let transfer_frame = kutup_chat_proto::ChatHistoryTransferFrameV1 {
            version: 1,
            transfer_id: journal.transfer_id.clone(),
            transcript_hash: "05".repeat(32),
            index: 0,
            final_frame: true,
            plaintext_bytes: 1,
            nonce: b64(6, 24),
            ciphertext: b64(7, 17),
        };
        pending
            .history_transfer_journals
            .insert(journal.transfer_id.clone(), Some(journal.clone()));
        pending.history_transfer_frames.insert(
            (transfer_frame.transfer_id.clone(), transfer_frame.index),
            Some(transfer_frame.clone()),
        );
        pending.inbound.insert(
            "inbound-1".into(),
            Some(InboundEnvelope {
                id: "inbound-1".into(),
                cursor: 13,
                envelope: vec![14],
                state: InboundState::PendingDecrypt,
                attempts: 2,
                failure_kind: Some(InboundFailureKind::MissingKeyMaterial),
                last_error: Some("repair me".into()),
                received_at: 102,
            }),
        );
        pending.manifest_trust.insert(
            "alice".into(),
            ManifestTrust {
                peer: "alice".into(),
                account: "alice@a.test".into(),
                incarnation_id: "incarnation".into(),
                authority_key_id: "authority".into(),
                self_authority_key: "key".into(),
                drive_hpke_public_key: "drive".into(),
                drive_share_signing_public_key: "share".into(),
                highest_sequence: u64::MAX,
                manifest_hash: "hash".into(),
                trust: AuthorityTrust::Verified,
                continuity_gap: false,
                quarantine_reason: None,
                pending_reset: None,
            },
        );
        pending.prekey_upload = Some(Some(vec![15]));
        pending.registration_upload = Some(Some(vec![16]));
        pending.last_cursor = Some(u64::MAX);
        pending.last_sent_seq = Some(u64::MAX - 1);

        db.apply(&pending).await.unwrap();

        let local = db.load_local_identity().await.unwrap().unwrap();
        assert_eq!(local.registration_id, 42);
        assert_eq!(local.device_id, Some(3));
        assert_eq!(db.load_session("alice.1").await.unwrap(), Some(vec![4]));
        assert_eq!(db.load_identity("alice.1").await.unwrap(), Some(vec![5]));
        assert_eq!(db.load_pre_key(7).await.unwrap(), Some(vec![6]));
        assert_eq!(db.load_signed_pre_key(8).await.unwrap(), Some(vec![7]));
        assert_eq!(db.load_kyber_pre_key(9).await.unwrap(), Some(vec![8]));
        assert!(db.kyber_base_key_seen(9, 7, &[9]).await.unwrap());
        assert_eq!(
            db.load_sender_key("alice.1", "distribution").await.unwrap(),
            Some(vec![10])
        );
        assert_eq!(db.list_outbox().await.unwrap().len(), 1);
        assert_eq!(db.list_messages().await.unwrap().len(), 1);
        assert_eq!(db.list_sent_messages().await.unwrap().len(), 1);
        assert_eq!(db.list_imported_history().await.unwrap(), vec![imported]);
        assert_eq!(
            db.load_history_transfer_journal(&journal.transfer_id)
                .await
                .unwrap(),
            Some(journal.clone())
        );
        assert_eq!(
            db.list_history_transfer_frames(&journal.transfer_id)
                .await
                .unwrap(),
            vec![transfer_frame]
        );
        assert!(
            db.load_sent_message("sent-1")
                .await
                .unwrap()
                .unwrap()
                .delivered
        );
        assert_eq!(db.list_inbound().await.unwrap().len(), 1);
        assert_eq!(
            db.load_manifest_trust("alice")
                .await
                .unwrap()
                .unwrap()
                .highest_sequence,
            u64::MAX
        );
        assert_eq!(
            db.load_pending_prekey_upload().await.unwrap(),
            Some(vec![15])
        );
        assert_eq!(
            db.load_pending_registration().await.unwrap(),
            Some(vec![16])
        );
        assert_eq!(db.load_last_cursor().await.unwrap(), Some(u64::MAX));
        assert_eq!(db.load_last_sent_seq().await.unwrap(), Some(u64::MAX - 1));

        let mut clear_transfer = Pending::default();
        clear_transfer
            .history_transfer_journals
            .insert(journal.transfer_id.clone(), None);
        db.apply(&clear_transfer).await.unwrap();
        assert!(db
            .list_history_transfer_frames(&journal.transfer_id)
            .await
            .unwrap()
            .is_empty());

        let mut consumed = Pending::default();
        consumed.pre_keys.insert(7, None);
        db.apply(&consumed).await.unwrap();
        assert_eq!(db.load_pre_key(7).await.unwrap(), Some(vec![6]));
        assert_eq!(
            db.purge_used_pre_keys(crate::clock::unix_millis() + 1)
                .await
                .unwrap(),
            1
        );
        assert_eq!(db.load_pre_key(7).await.unwrap(), None);

        db.db.close();
        Rexie::delete(&name).await.unwrap();
    }
}
