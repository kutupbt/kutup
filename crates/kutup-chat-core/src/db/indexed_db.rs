//! Browser [`ChatDb`] backed by IndexedDB.
//!
//! Every record is encrypted at rest (`store_cipher`,
//! `docs/research/16-browser-storage-architecture.md`): it is stored under a
//! keyed hash of its key, its value sealed under a store key wrapped by the
//! account master key. A database without the wrapped key is a new store: any
//! records already in it are cleared on first open, never read.
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
    AccountManifestHistoryRecordV1, ChatDb, ContactRecord, InboundEnvelope, InboxMessage,
    LocalIdentity, LocalProfile, ManifestTrust, MlsHistoryMessage, MlsOutboxEntry, OutboxEntry,
    PeerProfile, Pending, SentMessage,
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
const INBOUND: &str = "inbound";
const MANIFEST_TRUST: &str = "manifest_trust";
const MANIFEST_HISTORY: &str = "manifest_history";
const CONTACTS: &str = "contacts";
const LOCAL_PROFILE: &str = "local_profile";
const PEER_PROFILES: &str = "peer_profiles";
const META: &str = "meta";
/// Derived index records (conversation timelines), sealed like the rest.
const INDEX: &str = "index_values";

const ALL_STORES: [&str; 23] = [
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
    /// wrapped by `master_key` (the account master key). A database with no
    /// wrapped key is started fresh here: cleared and keyed in one transaction.
    pub async fn open(name: &str, master_key: &[u8; 32]) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(ChatError::Invalid(
                "IndexedDB chat database name must not be empty".into(),
            ));
        }

        // Version 13 dropped the device-to-device history-transfer stores;
        // an upgrade deletes every object store not listed here.
        let mut builder = Rexie::builder(name).version(13);
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
                start_new_store(&writer, &wrapped).await?;
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

/// Start a store that has no wrapped key: clear every object store (records
/// from before sealing, or from an interrupted first open, are never read)
/// and write the wrapped key and the format marker, in one durable
/// transaction. A crash leaves either the old contents, cleared on the next
/// open, or the new empty sealed store.
async fn start_new_store(writer: &web_sys::IdbDatabase, wrapped: &[u8]) -> Result<()> {
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
    let mut operations = Vec::with_capacity(2);
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

fn idb<T>(result: rexie::Result<T>) -> Result<T> {
    result.map_err(|error| ChatError::Db(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AuthorityTrust, InboundFailureKind, InboundState};
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
                renames: None,
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

    #[wasm_bindgen_test]
    async fn a_database_without_a_store_key_is_started_fresh() {
        let name = format!("kutup-chat-test-unkeyed-{}", js_sys::Date::now());
        // A database with records but no wrapped store key: what a store
        // from before sealing, or one from an interrupted first open, holds.
        let mut builder = Rexie::builder(&name).version(13);
        for store in ALL_STORES {
            builder = builder.add_object_store(ObjectStore::new(store));
        }
        let raw = builder.build().await.unwrap();
        let transaction = raw
            .transaction(&[MESSAGES], TransactionMode::ReadWrite)
            .unwrap();
        transaction
            .store(MESSAGES)
            .unwrap()
            .put(
                &JsValue::from_str("plaintext"),
                Some(&JsValue::from_str("message-1")),
            )
            .await
            .unwrap();
        transaction.done().await.unwrap();
        raw.close();

        let db = IndexedDbChatDb::open(&name, &[3; 32]).await.unwrap();
        assert!(db.list_messages().await.unwrap().is_empty());
        assert!(plain_meta(&db.db, STORE_KEY).await.unwrap().is_some());
        db.db.close();
        Rexie::delete(&name).await.unwrap();
    }
}
