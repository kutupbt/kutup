//! Browser bindings for Mail's search index (docs/plans/mail-body-search.md):
//! the word index of `kutup-search` over records sealed by
//! `kutup_crypto::mail_search`. The page keeps the sealed records in
//! IndexedDB under their record ids; it never sees a word, a record's name or
//! an unsealed value. Each change or query is two calls: `plan*` names the
//! records needed (as `{ name, id }`), the page loads them by id, and the call
//! itself returns the sealed records to store (`{ id, sealed }`).
//!
//! The database is named by [`MailSearch::store_name`] and keeps the index's
//! wrapped store key ([`MailSearch::wrapped_store_key`]); deleting the
//! database destroys that key and so everything sealed under it.

use kutup_crypto::mail_search::{store_name, MailSearchKeys};
use kutup_search::{DocRef, Found, Hit, Index, NewDoc, Records, DIRECTORY_KEY, INDEX_VERSION};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsError::new(&message.to_string()).into()
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(false),
        )
        .map_err(js_error)
}

#[derive(Serialize)]
struct Needed {
    name: String,
    id: String,
}

#[derive(Deserialize)]
struct Loaded {
    name: String,
    #[serde(with = "serde_bytes_compat")]
    sealed: Vec<u8>,
}

#[derive(Serialize)]
struct Matched {
    found: Vec<(f64, u32)>,
    needed: Vec<Needed>,
}

#[derive(Serialize)]
struct Updated {
    stored: Vec<Store>,
    missing: Vec<String>,
}

#[derive(Serialize)]
struct Store {
    id: String,
    #[serde(with = "serde_bytes_compat")]
    sealed: Vec<u8>,
}

/// `Uint8Array` in and out.
mod serde_bytes_compat {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        serde_bytes_buf(deserializer)
    }

    fn serde_bytes_buf<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    out.push(byte);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_byte_buf(Visitor)
    }
}

fn master(master_key: &[u8]) -> Result<[u8; 32], JsValue> {
    master_key
        .try_into()
        .map_err(|_| js_error("the master key is 32 bytes"))
}

/// One account's index in this browser.
#[wasm_bindgen]
pub struct MailSearch {
    keys: MailSearchKeys,
    wrapped: Vec<u8>,
    index: Index,
    /// A record needed did not open (damaged, or from another store key):
    /// it was read as missing, and the index should be built again.
    damaged: bool,
}

#[wasm_bindgen]
impl MailSearch {
    /// The browser database's name for an account (an HMAC under a key from
    /// its master key; names no one).
    #[wasm_bindgen(js_name = storeName)]
    pub fn store_name(master_key: &[u8]) -> Result<String, JsValue> {
        store_name(&master(master_key)?).map_err(js_error)
    }

    /// The account's index, empty until [`MailSearch::open_directory`]: under
    /// the store key `wrapped` (as the database keeps it), or under a new one
    /// when there is none. A wrapped key that does not open is an error; the
    /// page then deletes the database and starts again.
    #[wasm_bindgen(constructor)]
    pub fn new(master_key: &[u8], wrapped: Option<Vec<u8>>) -> Result<MailSearch, JsValue> {
        let master = master(master_key)?;
        let (keys, wrapped) = match wrapped {
            Some(wrapped) => (
                MailSearchKeys::open(&master, &wrapped).map_err(js_error)?,
                wrapped,
            ),
            None => MailSearchKeys::create(&master).map_err(js_error)?,
        };
        Ok(MailSearch {
            keys,
            wrapped,
            index: Index::open(None).map_err(js_error)?,
            damaged: false,
        })
    }

    /// The store key, wrapped, for the database to keep.
    #[wasm_bindgen(js_name = wrappedStoreKey)]
    pub fn wrapped_store_key(&self) -> Vec<u8> {
        self.wrapped.clone()
    }

    /// Whether a record needed did not open, or the directory is of another
    /// version: from then on nothing is written, and the page deletes the
    /// database and builds the index again.
    pub fn damaged(&self) -> bool {
        self.damaged
    }

    /// Whether `text` holds every word of `query` as the index would find
    /// them (Drafts, kept outside the index).
    pub fn matches(query: &str, text: &str) -> bool {
        kutup_search::matches(query, text)
    }

    /// The record id the directory is stored under.
    #[wasm_bindgen(js_name = directoryId)]
    pub fn directory_id(&self) -> String {
        self.keys.record_id(DIRECTORY_KEY)
    }

    /// Reads the stored directory (none: an empty index). One that does not
    /// open or decode, or of another version, leaves the index empty and
    /// [`MailSearch::damaged`]: its records are of no use.
    #[wasm_bindgen(js_name = openDirectory)]
    pub fn open_directory(&mut self, sealed: Option<Vec<u8>>) -> Result<bool, JsValue> {
        self.index = Index::open(None).map_err(js_error)?;
        let Some(sealed) = sealed else {
            return Ok(false);
        };
        let opened = self
            .keys
            .open_record(DIRECTORY_KEY, &sealed)
            .ok()
            .filter(|plain| Index::stored_version(plain).ok() == Some(INDEX_VERSION))
            .and_then(|plain| Index::open(Some(&plain)).ok());
        match opened {
            Some(index) => self.index = index,
            None => self.damaged = true,
        }
        Ok(!self.index.is_empty())
    }

    /// Seals a value of the page's own (its build progress) under `name`:
    /// `{ id, sealed }`.
    #[wasm_bindgen(js_name = sealRecord)]
    pub fn seal_record(&self, name: &str, value: &[u8]) -> Result<JsValue, JsValue> {
        to_js(&Store {
            id: self.keys.record_id(name),
            sealed: self.keys.seal(name, value).map_err(js_error)?,
        })
    }

    /// Opens a value [`MailSearch::seal_record`] sealed; none when it does not open.
    #[wasm_bindgen(js_name = openRecord)]
    pub fn open_record(&self, name: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        self.keys.open_record(name, sealed).ok()
    }

    /// The record id `name` is stored under.
    #[wasm_bindgen(js_name = recordId)]
    pub fn record_id(&self, name: &str) -> String {
        self.keys.record_id(name)
    }

    /// How many messages it holds.
    pub fn size(&self) -> f64 {
        self.index.len() as f64
    }

    /// When its oldest period starts (ms), if it holds anything.
    #[wasm_bindgen(js_name = oldestTime)]
    pub fn oldest_time(&self) -> Option<f64> {
        self.index.oldest_period_start().map(|t| t as f64)
    }

    fn needed(&self, names: Vec<String>) -> Result<JsValue, JsValue> {
        let needed: Vec<Needed> = names
            .into_iter()
            .map(|name| Needed {
                id: self.keys.record_id(&name),
                name,
            })
            .collect();
        to_js(&needed)
    }

    /// The loaded records, opened, to write from: refused once the index is
    /// [`MailSearch::damaged`] (an unreadable table would be written anew,
    /// and the shards would point at the wrong documents).
    fn opened_for_write(&mut self, loaded: JsValue) -> Result<Records, JsValue> {
        let records = self.opened(loaded)?;
        if self.damaged {
            return Err(js_error("the search index is damaged"));
        }
        Ok(records)
    }

    /// The loaded records, opened; one that does not open is read as
    /// missing and marks the index [`MailSearch::damaged`].
    fn opened(&mut self, loaded: JsValue) -> Result<Records, JsValue> {
        let loaded: Vec<Loaded> = serde_wasm_bindgen::from_value(loaded).map_err(js_error)?;
        let mut records = Records::new();
        for record in loaded {
            match self.keys.open_record(&record.name, &record.sealed) {
                Ok(plain) => {
                    records.insert(record.name, plain);
                }
                Err(_) => self.damaged = true,
            }
        }
        Ok(records)
    }

    fn sealed_list(&self, changed: Records) -> Result<Vec<Store>, JsValue> {
        let mut out = Vec::with_capacity(changed.len());
        for (name, plain) in changed {
            out.push(Store {
                id: self.keys.record_id(&name),
                sealed: self.keys.seal(&name, &plain).map_err(js_error)?,
            });
        }
        Ok(out)
    }

    fn sealed(&self, changed: Records) -> Result<JsValue, JsValue> {
        to_js(&self.sealed_list(changed)?)
    }

    /// The records [`MailSearch::add`] needs for `docs` (`{ id, timeMs, text, meta }[]`).
    #[wasm_bindgen(js_name = planAdd)]
    pub fn plan_add(&self, docs: JsValue) -> Result<JsValue, JsValue> {
        let docs: Vec<JsDoc> = serde_wasm_bindgen::from_value(docs).map_err(js_error)?;
        let docs: Vec<NewDoc> = docs.into_iter().map(Into::into).collect();
        self.needed(self.index.plan_add(&docs))
    }

    /// Indexes `docs` over the records loaded (`{ name, sealed }[]`); the
    /// sealed records to store, the directory among them.
    pub fn add(&mut self, docs: JsValue, loaded: JsValue) -> Result<JsValue, JsValue> {
        let docs: Vec<JsDoc> = serde_wasm_bindgen::from_value(docs).map_err(js_error)?;
        let docs: Vec<NewDoc> = docs.into_iter().map(Into::into).collect();
        let records = self.opened_for_write(loaded)?;
        let changed = self.index.add(&docs, &records).map_err(js_error)?;
        self.sealed(changed)
    }

    /// The records [`MailSearch::remove`] needs for messages (`{ id, timeMs }[]`).
    #[wasm_bindgen(js_name = planRemove)]
    pub fn plan_remove(&self, gone: JsValue) -> Result<JsValue, JsValue> {
        let gone: Vec<JsRef> = serde_wasm_bindgen::from_value(gone).map_err(js_error)?;
        let gone: Vec<DocRef> = gone.into_iter().map(Into::into).collect();
        self.needed(self.index.plan_remove(&gone))
    }

    /// Marks messages (`{ id, timeMs }[]`) gone.
    pub fn remove(&mut self, gone: JsValue, loaded: JsValue) -> Result<JsValue, JsValue> {
        let gone: Vec<JsRef> = serde_wasm_bindgen::from_value(gone).map_err(js_error)?;
        let gone: Vec<DocRef> = gone.into_iter().map(Into::into).collect();
        let records = self.opened_for_write(loaded)?;
        let changed = self.index.remove(&gone, &records).map_err(js_error)?;
        self.sealed(changed)
    }

    /// The records [`MailSearch::update_meta`] needs (`{ id, timeMs, meta }[]`).
    #[wasm_bindgen(js_name = planUpdateMeta)]
    pub fn plan_update_meta(&self, docs: JsValue) -> Result<JsValue, JsValue> {
        let docs: Vec<JsHit> = serde_wasm_bindgen::from_value(docs).map_err(js_error)?;
        let docs: Vec<Hit> = docs.into_iter().map(Into::into).collect();
        self.needed(self.index.plan_update_meta(&docs))
    }

    /// Replaces the list rows of messages held (`{ id, timeMs, meta }[]`):
    /// `{ stored, missing }`, the sealed records to store and the ids not
    /// held (new mail to index).
    #[wasm_bindgen(js_name = updateMeta)]
    pub fn update_meta(&mut self, docs: JsValue, loaded: JsValue) -> Result<JsValue, JsValue> {
        let docs: Vec<JsHit> = serde_wasm_bindgen::from_value(docs).map_err(js_error)?;
        let docs: Vec<Hit> = docs.into_iter().map(Into::into).collect();
        let records = self.opened_for_write(loaded)?;
        let (changed, missing) = self.index.update_meta(&docs, &records).map_err(js_error)?;
        let stored = self.sealed_list(changed)?;
        to_js(&Updated { stored, missing })
    }

    /// The periods a query reads next, newest first: up to `count` older than
    /// `before` (a period from an earlier answer).
    #[wasm_bindgen(js_name = nextPeriods)]
    pub fn next_periods(&self, before: Option<f64>, count: usize) -> Vec<f64> {
        self.index
            .next_periods(before.map(|b| b as i64), count)
            .into_iter()
            .map(|p| p as f64)
            .collect()
    }

    /// The shards [`MailSearch::search`] needs.
    #[wasm_bindgen(js_name = planSearch)]
    pub fn plan_search(&self, query: &str, periods: Vec<f64>) -> Result<JsValue, JsValue> {
        let periods: Vec<i64> = periods.into_iter().map(|p| p as i64).collect();
        self.needed(self.index.plan_search(query, &periods))
    }

    /// What `query` matched, from the shards loaded: `{ found, needed }`,
    /// `found` to pass to [`MailSearch::hits`] with the tables `needed`.
    pub fn search(
        &mut self,
        query: &str,
        periods: Vec<f64>,
        loaded: JsValue,
    ) -> Result<JsValue, JsValue> {
        let periods: Vec<i64> = periods.into_iter().map(|p| p as i64).collect();
        let records = self.opened(loaded)?;
        let found = self
            .index
            .search(query, &periods, &records)
            .map_err(js_error)?;
        let needed: Vec<Needed> = self
            .index
            .plan_hits(&found)
            .into_iter()
            .map(|name| Needed {
                id: self.keys.record_id(&name),
                name,
            })
            .collect();
        to_js(&Matched {
            found: found.into_iter().map(|(p, n)| (p as f64, n)).collect(),
            needed,
        })
    }

    /// The messages `found` names (`{ id, timeMs, meta }[]`, newest first).
    pub fn hits(&mut self, found: JsValue, loaded: JsValue) -> Result<JsValue, JsValue> {
        let found: Vec<(f64, u32)> = serde_wasm_bindgen::from_value(found).map_err(js_error)?;
        let found: Found = found.into_iter().map(|(p, n)| (p as i64, n)).collect();
        let records = self.opened(loaded)?;
        let hits = self.index.hits(&found, &records).map_err(js_error)?;
        to_js(&hits.into_iter().map(JsHit::from).collect::<Vec<_>>())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsDoc {
    id: String,
    time_ms: f64,
    text: String,
    meta: String,
}

impl From<JsDoc> for NewDoc {
    fn from(doc: JsDoc) -> Self {
        NewDoc {
            id: doc.id,
            time_ms: doc.time_ms as i64,
            text: doc.text,
            meta: doc.meta,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRef {
    id: String,
    time_ms: f64,
}

impl From<JsRef> for DocRef {
    fn from(doc: JsRef) -> Self {
        DocRef {
            id: doc.id,
            time_ms: doc.time_ms as i64,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsHit {
    id: String,
    time_ms: f64,
    meta: String,
}

impl From<JsHit> for Hit {
    fn from(hit: JsHit) -> Self {
        Hit {
            id: hit.id,
            time_ms: hit.time_ms as i64,
            meta: hit.meta,
        }
    }
}

impl From<Hit> for JsHit {
    fn from(hit: Hit) -> Self {
        JsHit {
            id: hit.id,
            time_ms: hit.time_ms as f64,
            meta: hit.meta,
        }
    }
}
