//! Browser [`ChatDb`] backed by IndexedDB.
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
use js_sys::Array;
use rexie::{ObjectStore, Rexie, Store, TransactionMode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::JsValue;

use crate::db::{
    ChatDb, InboundEnvelope, InboxMessage, LocalIdentity, ManifestTrust, OutboxEntry, Pending,
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
const MESSAGES: &str = "messages";
const SENT_MESSAGES: &str = "sent_messages";
const INBOUND: &str = "inbound";
const MANIFEST_TRUST: &str = "manifest_trust";
const META: &str = "meta";

const ALL_STORES: [&str; 15] = [
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
    MESSAGES,
    SENT_MESSAGES,
    INBOUND,
    MANIFEST_TRUST,
    META,
];

const SINGLETON: &str = "value";
const LAST_CURSOR: &str = "last_cursor";
const LAST_SENT_SEQ: &str = "last_sent_seq";
const PENDING_PREKEY_UPLOAD: &str = "pending_prekey_upload";
const PENDING_REGISTRATION: &str = "pending_registration";

/// One account/device-scoped browser chat database.
///
/// Callers must choose a stable name that is unique per authenticated account
/// and device. Sharing one database between accounts would also share identity
/// keys, sessions, and trust pins, so an empty name is rejected.
pub struct IndexedDbChatDb {
    db: Rexie,
}

impl IndexedDbChatDb {
    /// Open (or create) the versioned browser database.
    pub async fn open(name: &str) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(ChatError::Invalid(
                "IndexedDB chat database name must not be empty".into(),
            ));
        }

        let mut builder = Rexie::builder(name).version(2);
        for store in ALL_STORES {
            builder = builder.add_object_store(ObjectStore::new(store));
        }
        let db = idb(builder.build().await)?;
        Ok(Self { db })
    }

    async fn get<T: DeserializeOwned>(&self, store_name: &str, key: JsValue) -> Result<Option<T>> {
        let transaction = idb(self
            .db
            .transaction(&[store_name], TransactionMode::ReadOnly))?;
        let store = idb(transaction.store(store_name))?;
        idb(store.get(key).await)?.map(from_js).transpose()
    }

    async fn all<T: DeserializeOwned>(&self, store_name: &str) -> Result<Vec<T>> {
        let transaction = idb(self
            .db
            .transaction(&[store_name], TransactionMode::ReadOnly))?;
        let store = idb(transaction.store(store_name))?;
        idb(store.get_all(None, None).await)?
            .into_iter()
            .map(from_js)
            .collect()
    }
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
        let transaction = idb(self
            .db
            .transaction(&[USED_PRE_KEYS], TransactionMode::ReadOnly))?;
        let store = idb(transaction.store(USED_PRE_KEYS))?;
        let candidates = idb(store.scan(None, None, None, None).await)?
            .into_iter()
            .filter_map(|(key, value)| match from_js::<i64>(value) {
                Ok(used_at) if used_at <= used_before_ms => key.as_f64().map(|id| id as u32),
                _ => None,
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Ok(0);
        }

        let transaction = idb(self
            .db
            .transaction(&[PRE_KEYS, USED_PRE_KEYS], TransactionMode::ReadWrite))?;
        let pre_keys = idb(transaction.store(PRE_KEYS))?;
        let used = idb(transaction.store(USED_PRE_KEYS))?;
        let mut operations = Vec::with_capacity(candidates.len() * 2);
        for id in &candidates {
            operations.push(delete_op(&pre_keys, number_key(*id)));
            operations.push(delete_op(&used, number_key(*id)));
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
            .key_exists(string_key(&kyber_seen_key(kyber_id, ec_id, base_key)))
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

    async fn load_pending_prekey_upload(&self) -> Result<Option<Vec<u8>>> {
        self.get(META, string_key(PENDING_PREKEY_UPLOAD)).await
    }

    async fn load_pending_registration(&self) -> Result<Option<Vec<u8>>> {
        self.get(META, string_key(PENDING_REGISTRATION)).await
    }

    async fn apply(&self, pending: &Pending) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }

        // Serialize before opening the transaction. Serialization cannot leave
        // a partially queued write-set, and 64-bit counters become JS BigInts
        // instead of lossy Numbers.
        let mut writes = PreparedWrites::from_pending(pending)?;

        let transaction = idb(self.db.transaction(&ALL_STORES, TransactionMode::ReadWrite))?;
        let local_identity = idb(transaction.store(LOCAL_IDENTITY))?;
        let sessions = idb(transaction.store(SESSIONS))?;
        let identities = idb(transaction.store(IDENTITIES))?;
        let pre_keys = idb(transaction.store(PRE_KEYS))?;
        let used_pre_keys = idb(transaction.store(USED_PRE_KEYS))?;
        let signed_pre_keys = idb(transaction.store(SIGNED_PRE_KEYS))?;
        let kyber_pre_keys = idb(transaction.store(KYBER_PRE_KEYS))?;
        let kyber_seen = idb(transaction.store(KYBER_SEEN))?;
        let sender_keys = idb(transaction.store(SENDER_KEYS))?;
        let outbox = idb(transaction.store(OUTBOX))?;
        let messages = idb(transaction.store(MESSAGES))?;
        let sent_messages = idb(transaction.store(SENT_MESSAGES))?;
        let inbound = idb(transaction.store(INBOUND))?;
        let manifest_trust = idb(transaction.store(MANIFEST_TRUST))?;
        let meta = idb(transaction.store(META))?;

        let mut operations = Vec::new();
        if let Some(value) = writes.local_identity.take() {
            operations.push(put_op(&local_identity, value, string_key(SINGLETON)));
        }
        stage_map(&mut operations, &sessions, writes.sessions);
        stage_puts(&mut operations, &identities, writes.identities);
        for (id, value) in writes.pre_keys {
            match value {
                Some(value) => {
                    operations.push(put_op(&pre_keys, value, number_key(id)));
                    operations.push(delete_op(&used_pre_keys, number_key(id)));
                }
                None => operations.push(put_op(
                    &used_pre_keys,
                    to_js(&crate::clock::unix_millis())?,
                    number_key(id),
                )),
            }
        }
        stage_puts(&mut operations, &signed_pre_keys, writes.signed_pre_keys);
        stage_puts(&mut operations, &kyber_pre_keys, writes.kyber_pre_keys);
        for (key, value) in writes.kyber_seen {
            operations.push(put_op(&kyber_seen, value, string_key(&key)));
        }
        for ((address, distribution_id), value) in writes.sender_keys {
            operations.push(put_op(
                &sender_keys,
                value,
                pair_key(&address, &distribution_id),
            ));
        }
        stage_map(&mut operations, &outbox, writes.outbox);
        for (id, value) in writes.messages {
            operations.push(put_op(&messages, value, string_key(&id)));
        }
        stage_puts(&mut operations, &sent_messages, writes.sent_messages);
        stage_map(&mut operations, &inbound, writes.inbound);
        stage_puts(&mut operations, &manifest_trust, writes.manifest_trust);
        if let Some(value) = writes.prekey_upload {
            match value {
                Some(value) => {
                    operations.push(put_op(&meta, value, string_key(PENDING_PREKEY_UPLOAD)))
                }
                None => operations.push(delete_op(&meta, string_key(PENDING_PREKEY_UPLOAD))),
            }
        }
        if let Some(value) = writes.registration_upload {
            match value {
                Some(value) => {
                    operations.push(put_op(&meta, value, string_key(PENDING_REGISTRATION)))
                }
                None => operations.push(delete_op(&meta, string_key(PENDING_REGISTRATION))),
            }
        }
        if let Some(cursor) = writes.last_cursor {
            operations.push(put_op(&meta, cursor, string_key(LAST_CURSOR)));
        }
        if let Some(seq) = writes.last_sent_seq {
            operations.push(put_op(&meta, seq, string_key(LAST_SENT_SEQ)));
        }

        finish_write(transaction, operations).await
    }
}

type Operation<'a> = Pin<Box<dyn Future<Output = rexie::Result<()>> + 'a>>;

fn put_op(store: &Store, value: JsValue, key: JsValue) -> Operation<'_> {
    Box::pin(async move { store.put(&value, Some(&key)).await.map(|_| ()) })
}

fn delete_op(store: &Store, key: JsValue) -> Operation<'_> {
    Box::pin(async move { store.delete(key).await })
}

fn stage_puts<'a, K>(
    operations: &mut Vec<Operation<'a>>,
    store: &'a Store,
    writes: impl IntoIterator<Item = (K, JsValue)>,
) where
    K: IntoKey,
{
    for (key, value) in writes {
        operations.push(put_op(store, value, key.into_key()));
    }
}

fn stage_map<'a, K>(
    operations: &mut Vec<Operation<'a>>,
    store: &'a Store,
    writes: impl IntoIterator<Item = (K, Option<JsValue>)>,
) where
    K: IntoKey,
{
    for (key, value) in writes {
        let key = key.into_key();
        match value {
            Some(value) => operations.push(put_op(store, value, key)),
            None => operations.push(delete_op(store, key)),
        }
    }
}

async fn finish_write(
    transaction: rexie::Transaction,
    operations: Vec<Operation<'_>>,
) -> Result<()> {
    let results = join_all(operations).await;
    if let Some(error) = results.into_iter().find_map(std::result::Result::err) {
        let _ = transaction.abort().await;
        return Err(ChatError::Db(error.to_string()));
    }
    idb(transaction.commit().await)
}

trait IntoKey {
    fn into_key(self) -> JsValue;
}

impl IntoKey for String {
    fn into_key(self) -> JsValue {
        string_key(&self)
    }
}

impl IntoKey for u32 {
    fn into_key(self) -> JsValue {
        number_key(self)
    }
}

#[derive(Default)]
struct PreparedWrites {
    local_identity: Option<JsValue>,
    sessions: Vec<(String, Option<JsValue>)>,
    identities: Vec<(String, JsValue)>,
    pre_keys: Vec<(u32, Option<JsValue>)>,
    signed_pre_keys: Vec<(u32, JsValue)>,
    kyber_pre_keys: Vec<(u32, JsValue)>,
    kyber_seen: Vec<(String, JsValue)>,
    sender_keys: Vec<((String, String), JsValue)>,
    outbox: Vec<(String, Option<JsValue>)>,
    messages: Vec<(String, JsValue)>,
    sent_messages: Vec<(String, JsValue)>,
    inbound: Vec<(String, Option<JsValue>)>,
    manifest_trust: Vec<(String, JsValue)>,
    prekey_upload: Option<Option<JsValue>>,
    registration_upload: Option<Option<JsValue>>,
    last_cursor: Option<JsValue>,
    last_sent_seq: Option<JsValue>,
}

impl PreparedWrites {
    fn from_pending(pending: &Pending) -> Result<Self> {
        Ok(Self {
            local_identity: pending.local_identity.as_ref().map(to_js).transpose()?,
            sessions: serialize_optional_map(&pending.sessions)?,
            identities: serialize_map(&pending.identities)?,
            pre_keys: serialize_optional_map(&pending.pre_keys)?,
            signed_pre_keys: serialize_map(&pending.signed_pre_keys)?,
            kyber_pre_keys: serialize_map(&pending.kyber_pre_keys)?,
            kyber_seen: pending
                .kyber_seen
                .iter()
                .map(|(kyber_id, ec_id, base_key)| {
                    Ok((kyber_seen_key(*kyber_id, *ec_id, base_key), to_js(&true)?))
                })
                .collect::<Result<_>>()?,
            sender_keys: pending
                .sender_keys
                .iter()
                .map(|(key, value)| Ok((key.clone(), to_js(value)?)))
                .collect::<Result<_>>()?,
            outbox: serialize_optional_map(&pending.outbox)?,
            messages: pending
                .messages
                .iter()
                .map(|message| Ok((message.id.clone(), to_js(message)?)))
                .collect::<Result<_>>()?,
            sent_messages: serialize_map(&pending.sent_messages)?,
            inbound: serialize_optional_map(&pending.inbound)?,
            manifest_trust: serialize_map(&pending.manifest_trust)?,
            prekey_upload: pending
                .prekey_upload
                .as_ref()
                .map(|value| value.as_ref().map(to_js).transpose())
                .transpose()?,
            registration_upload: pending
                .registration_upload
                .as_ref()
                .map(|value| value.as_ref().map(to_js).transpose())
                .transpose()?,
            last_cursor: pending.last_cursor.as_ref().map(to_js).transpose()?,
            last_sent_seq: pending.last_sent_seq.as_ref().map(to_js).transpose()?,
        })
    }
}

fn serialize_map<K, V>(values: &std::collections::HashMap<K, V>) -> Result<Vec<(K, JsValue)>>
where
    K: Clone + Eq + std::hash::Hash,
    V: Serialize,
{
    values
        .iter()
        .map(|(key, value)| Ok((key.clone(), to_js(value)?)))
        .collect()
}

fn serialize_optional_map<K, V>(
    values: &std::collections::HashMap<K, Option<V>>,
) -> Result<Vec<(K, Option<JsValue>)>>
where
    K: Clone + Eq + std::hash::Hash,
    V: Serialize,
{
    values
        .iter()
        .map(|(key, value)| Ok((key.clone(), value.as_ref().map(to_js).transpose()?)))
        .collect()
}

fn string_key(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn number_key(value: u32) -> JsValue {
    JsValue::from_f64(value as f64)
}

fn pair_key(left: &str, right: &str) -> JsValue {
    Array::of2(&string_key(left), &string_key(right)).into()
}

fn kyber_seen_key(kyber_id: u32, ec_id: u32, base_key: &[u8]) -> String {
    format!("{kyber_id}:{ec_id}:{}", hex::encode(base_key))
}

fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue> {
    let serializer = Serializer::new().serialize_large_number_types_as_bigints(true);
    value
        .serialize(&serializer)
        .map_err(|error| ChatError::Db(format!("IndexedDB encode: {error}")))
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
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn atomically_round_trips_every_durable_domain() {
        let name = format!("kutup-chat-test-{}", js_sys::Date::now());
        let db = IndexedDbChatDb::open(&name).await.unwrap();
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
                authority_key_id: "authority".into(),
                self_authority_key: "key".into(),
                highest_version: u64::MAX,
                manifest_hash: "hash".into(),
                trust: AuthorityTrust::Verified,
                continuity_gap: false,
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
                .highest_version,
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
}
