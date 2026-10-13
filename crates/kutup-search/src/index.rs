//! The period-sharded inverted index ([`Index`]); see the crate docs.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Bound;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::words;

/// Raised whenever what is indexed or how changes: a directory of another
/// version is not read (see [`Index::stored_version`]), and the caller
/// builds the index again.
pub const INDEX_VERSION: u32 = 3;
/// The period a document table and its shards cover (30 days).
pub const BUCKET_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Characters of a word that name its shard.
const SHARD_CHARS: usize = 3;
/// A period's documents are kept in this many tables, each document in the
/// one its id hashes to, so no table grows past what a record holds and a
/// document is found from its id alone.
const DOC_CHUNKS: u32 = 32;
/// A document's number: its table in the high bits, its place in the low.
const PLACE_BITS: u32 = 27;
/// The directory's record name.
pub const DIRECTORY_KEY: &str = "dir";

/// Named records, as the caller loads and stores them (CBOR values).
pub type Records = BTreeMap<String, Vec<u8>>;

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("a search record does not decode: {0}")]
    Decode(String),
    #[error("a search record does not encode: {0}")]
    Encode(String),
}

/// A document to index: an id (a message), its time, its text and the
/// caller's own data about it (`meta`, kept as given and returned with every
/// hit: Mail keeps a message's list row there, to filter and show hits
/// without asking the server).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewDoc {
    pub id: String,
    pub time_ms: i64,
    pub text: String,
    pub meta: String,
}

/// A document held: its id and time, which find its table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DocRef {
    pub id: String,
    pub time_ms: i64,
}

/// A document a query found, or new data for one held.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Hit {
    pub id: String,
    pub time_ms: i64,
    pub meta: String,
}

/// What a query's words matched, before the documents are read: a period
/// and a document number.
pub type Found = Vec<(i64, u32)>;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct Directory {
    version: u32,
    /// Each period's shards (by word start) and how many documents it holds.
    periods: BTreeMap<i64, PeriodInfo>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct PeriodInfo {
    prefixes: BTreeSet<String>,
    docs: u32,
    /// Of `docs`, those removed since (their entries stay until rebuilt).
    #[serde(default)]
    removed: u32,
}

/// One table of a period's documents; a document's place is its index here.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct DocTable {
    docs: Vec<DocEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DocEntry {
    id: String,
    time_ms: i64,
    live: bool,
    meta: String,
}

/// Words of one start in one period, each with the numbers of the documents
/// holding it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct Shard {
    words: BTreeMap<String, Vec<u32>>,
}

fn period_of(time_ms: i64) -> i64 {
    time_ms.div_euclid(BUCKET_MS)
}

/// The table a document id belongs to: FNV-1a, fixed for good (stored
/// numbers depend on it).
fn chunk_of(id: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in id.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash % DOC_CHUNKS
}

fn docs_key(period: i64, chunk: u32) -> String {
    format!("docs/{period}/{chunk}")
}

fn shard_key(period: i64, prefix: &str) -> String {
    format!("shard/{period}/{prefix}")
}

fn prefix_of(word: &str) -> String {
    word.chars().take(SHARD_CHARS).collect()
}

fn decode<T: DeserializeOwned + Default>(records: &Records, key: &str) -> Result<T, SearchError> {
    match records.get(key) {
        None => Ok(T::default()),
        Some(bytes) => {
            ciborium::from_reader(bytes.as_slice()).map_err(|e| SearchError::Decode(e.to_string()))
        }
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, SearchError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| SearchError::Encode(e.to_string()))?;
    Ok(out)
}

/// The index: its directory in memory, everything else in the caller's records.
#[derive(Debug, Clone, Default)]
pub struct Index {
    directory: Directory,
}

impl Index {
    /// The version a stored directory was written in.
    pub fn stored_version(directory: &[u8]) -> Result<u32, SearchError> {
        #[derive(Deserialize)]
        struct Versioned {
            version: u32,
        }
        let stored: Versioned =
            ciborium::from_reader(directory).map_err(|e| SearchError::Decode(e.to_string()))?;
        Ok(stored.version)
    }

    /// An index from its stored directory; `None` (or another version) is an
    /// empty index, to be built.
    pub fn open(directory: Option<&[u8]>) -> Result<Self, SearchError> {
        let fresh = Directory {
            version: INDEX_VERSION,
            periods: BTreeMap::new(),
        };
        let directory = match directory {
            None => fresh,
            Some(bytes) => {
                if Self::stored_version(bytes)? == INDEX_VERSION {
                    ciborium::from_reader(bytes).map_err(|e| SearchError::Decode(e.to_string()))?
                } else {
                    fresh
                }
            }
        };
        Ok(Index { directory })
    }

    /// How many documents it holds (not those removed).
    pub fn len(&self) -> u64 {
        self.directory
            .periods
            .values()
            .map(|p| u64::from(p.docs.saturating_sub(p.removed)))
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The start of the oldest period held, if any.
    pub fn oldest_period_start(&self) -> Option<i64> {
        self.directory.periods.keys().next().map(|p| p * BUCKET_MS)
    }

    /// The periods held, newest first.
    pub fn periods(&self) -> Vec<i64> {
        self.directory.periods.keys().rev().copied().collect()
    }

    /// The tables of documents with these ids and times.
    fn tables_of<'a>(docs: impl Iterator<Item = (&'a str, i64)>) -> BTreeSet<String> {
        docs.map(|(id, time)| docs_key(period_of(time), chunk_of(id)))
            .collect()
    }

    /// The records [`Index::add`] needs for `docs`.
    pub fn plan_add(&self, docs: &[NewDoc]) -> Vec<String> {
        let mut keys = Self::tables_of(docs.iter().map(|d| (d.id.as_str(), d.time_ms)));
        for doc in docs {
            let period = period_of(doc.time_ms);
            for word in words(&doc.text) {
                keys.insert(shard_key(period, &prefix_of(&word)));
            }
        }
        keys.into_iter().collect()
    }

    /// Indexes `docs` over the records [`Index::plan_add`] named; returns the
    /// records changed, the directory among them. A document already held
    /// (live, same id and period) is left as it is.
    pub fn add(&mut self, docs: &[NewDoc], records: &Records) -> Result<Records, SearchError> {
        let mut tables: BTreeMap<(i64, u32), DocTable> = BTreeMap::new();
        let mut shards: BTreeMap<(i64, String), Shard> = BTreeMap::new();
        for doc in docs {
            let period = period_of(doc.time_ms);
            let chunk = chunk_of(&doc.id);
            let table = match tables.entry((period, chunk)) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(decode(records, &docs_key(period, chunk))?)
                }
            };
            if table.docs.iter().any(|d| d.live && d.id == doc.id) {
                continue;
            }
            let place = u32::try_from(table.docs.len())
                .ok()
                .filter(|p| *p < 1 << PLACE_BITS)
                .ok_or_else(|| SearchError::Encode("too many documents".into()))?;
            let number = (chunk << PLACE_BITS) | place;
            table.docs.push(DocEntry {
                id: doc.id.clone(),
                time_ms: doc.time_ms,
                live: true,
                meta: doc.meta.clone(),
            });
            let info = self.directory.periods.entry(period).or_default();
            info.docs += 1;
            for word in words(&doc.text) {
                let prefix = prefix_of(&word);
                info.prefixes.insert(prefix.clone());
                let key = (period, prefix);
                if !shards.contains_key(&key) {
                    let loaded = decode(records, &shard_key(period, &key.1))?;
                    shards.insert(key.clone(), loaded);
                }
                shards
                    .get_mut(&key)
                    .expect("loaded")
                    .words
                    .entry(word)
                    .or_default()
                    .push(number);
            }
        }
        let mut changed = Records::new();
        for ((period, chunk), table) in &tables {
            changed.insert(docs_key(*period, *chunk), encode(table)?);
        }
        for ((period, prefix), shard) in &shards {
            changed.insert(shard_key(*period, prefix), encode(shard)?);
        }
        changed.insert(DIRECTORY_KEY.into(), encode(&self.directory)?);
        Ok(changed)
    }

    /// The records [`Index::remove`] needs.
    pub fn plan_remove(&self, docs: &[DocRef]) -> Vec<String> {
        Self::tables_of(docs.iter().map(|d| (d.id.as_str(), d.time_ms)))
            .into_iter()
            .collect()
    }

    /// Marks documents gone (a deleted message); their words stay in the
    /// shards until the index is built again, and are never found.
    pub fn remove(&mut self, docs: &[DocRef], records: &Records) -> Result<Records, SearchError> {
        let mut by_table: BTreeMap<(i64, u32), HashSet<&str>> = BTreeMap::new();
        for doc in docs {
            if self.directory.periods.contains_key(&period_of(doc.time_ms)) {
                by_table
                    .entry((period_of(doc.time_ms), chunk_of(&doc.id)))
                    .or_default()
                    .insert(doc.id.as_str());
            }
        }
        let mut changed = Records::new();
        for ((period, chunk), ids) in by_table {
            let key = docs_key(period, chunk);
            let mut table: DocTable = decode(records, &key)?;
            let mut gone = 0;
            for entry in &mut table.docs {
                if entry.live && ids.contains(entry.id.as_str()) {
                    entry.live = false;
                    gone += 1;
                }
            }
            if gone > 0 {
                changed.insert(key, encode(&table)?);
                if let Some(info) = self.directory.periods.get_mut(&period) {
                    info.removed += gone;
                }
            }
        }
        if !changed.is_empty() {
            changed.insert(DIRECTORY_KEY.into(), encode(&self.directory)?);
        }
        Ok(changed)
    }

    /// The records [`Index::update_meta`] needs.
    pub fn plan_update_meta(&self, docs: &[Hit]) -> Vec<String> {
        Self::tables_of(docs.iter().map(|d| (d.id.as_str(), d.time_ms)))
            .into_iter()
            .collect()
    }

    /// Replaces the data of documents held (a message moved, read or
    /// labelled); returns the records changed and the ids of `docs` not
    /// held (new mail, for the caller to index).
    pub fn update_meta(
        &mut self,
        docs: &[Hit],
        records: &Records,
    ) -> Result<(Records, Vec<String>), SearchError> {
        let mut by_table: BTreeMap<(i64, u32), BTreeMap<&str, &str>> = BTreeMap::new();
        for doc in docs {
            by_table
                .entry((period_of(doc.time_ms), chunk_of(&doc.id)))
                .or_default()
                .insert(doc.id.as_str(), doc.meta.as_str());
        }
        let mut changed = Records::new();
        let mut held: HashSet<&str> = HashSet::new();
        for ((period, chunk), metas) in by_table {
            if !self.directory.periods.contains_key(&period) {
                continue;
            }
            let key = docs_key(period, chunk);
            let mut table: DocTable = decode(records, &key)?;
            let mut any = false;
            for entry in &mut table.docs {
                if let Some((id, meta)) = metas
                    .get_key_value(entry.id.as_str())
                    .filter(|_| entry.live)
                {
                    held.insert(id);
                    if entry.meta != *meta {
                        entry.meta = (*meta).to_owned();
                        any = true;
                    }
                }
            }
            if any {
                changed.insert(key, encode(&table)?);
            }
        }
        let missing = docs
            .iter()
            .filter(|d| !held.contains(d.id.as_str()))
            .map(|d| d.id.clone())
            .collect();
        Ok((changed, missing))
    }

    /// The periods a query reads next: up to `count` held periods older than
    /// `before` (a period from an earlier answer), newest first.
    pub fn next_periods(&self, before: Option<i64>, count: usize) -> Vec<i64> {
        self.directory
            .periods
            .keys()
            .rev()
            .filter(|p| before.is_none_or(|b| **p < b))
            .take(count)
            .copied()
            .collect()
    }

    /// The shards [`Index::search`] reads for `query` in `periods`.
    pub fn plan_search(&self, query: &str, periods: &[i64]) -> Vec<String> {
        let terms = words(query);
        let mut keys = BTreeSet::new();
        for period in periods {
            let Some(info) = self.directory.periods.get(period) else {
                continue;
            };
            for term in &terms {
                for prefix in matching_prefixes(info, term) {
                    keys.insert(shard_key(*period, prefix));
                }
            }
        }
        keys.into_iter().collect()
    }

    /// The documents in `periods` holding every word of `query` (each as the
    /// start of a word), from the shards alone; [`Index::plan_hits`] and
    /// [`Index::hits`] read only their tables.
    pub fn search(
        &self,
        query: &str,
        periods: &[i64],
        records: &Records,
    ) -> Result<Found, SearchError> {
        let terms = words(query);
        let mut out = Found::new();
        if terms.is_empty() {
            return Ok(out);
        }
        for period in periods {
            let Some(info) = self.directory.periods.get(period) else {
                continue;
            };
            let mut found: Option<BTreeSet<u32>> = None;
            for term in &terms {
                let mut holding = BTreeSet::new();
                for prefix in matching_prefixes(info, term) {
                    let shard: Shard = decode(records, &shard_key(*period, prefix))?;
                    for (word, numbers) in shard
                        .words
                        .range::<str, _>((Bound::Included(term.as_str()), Bound::Unbounded))
                    {
                        if !word.starts_with(term.as_str()) {
                            break;
                        }
                        holding.extend(numbers.iter().copied());
                    }
                }
                found = Some(match found {
                    None => holding,
                    Some(before) => before.intersection(&holding).copied().collect(),
                });
                if found.as_ref().is_some_and(BTreeSet::is_empty) {
                    break;
                }
            }
            out.extend(found.unwrap_or_default().into_iter().map(|n| (*period, n)));
        }
        Ok(out)
    }

    /// The tables holding `found`.
    pub fn plan_hits(&self, found: &Found) -> Vec<String> {
        found
            .iter()
            .map(|(period, number)| docs_key(*period, number >> PLACE_BITS))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The live documents of `found`, newest first.
    pub fn hits(&self, found: &Found, records: &Records) -> Result<Vec<Hit>, SearchError> {
        let mut tables: BTreeMap<String, DocTable> = BTreeMap::new();
        let mut hits = Vec::new();
        for (period, number) in found {
            let key = docs_key(*period, number >> PLACE_BITS);
            if !tables.contains_key(&key) {
                tables.insert(key.clone(), decode(records, &key)?);
            }
            let place = (number & ((1 << PLACE_BITS) - 1)) as usize;
            if let Some(entry) = tables[&key].docs.get(place).filter(|e| e.live) {
                hits.push(Hit {
                    id: entry.id.clone(),
                    time_ms: entry.time_ms,
                    meta: entry.meta.clone(),
                });
            }
        }
        hits.sort_by(|a, b| b.time_ms.cmp(&a.time_ms).then_with(|| b.id.cmp(&a.id)));
        Ok(hits)
    }
}

/// The shards of a period that can hold words starting with `term`.
fn matching_prefixes<'a>(info: &'a PeriodInfo, term: &str) -> Vec<&'a str> {
    if term.chars().count() >= SHARD_CHARS {
        let prefix = prefix_of(term);
        info.prefixes
            .get(&prefix)
            .map(String::as_str)
            .into_iter()
            .collect()
    } else {
        info.prefixes
            .iter()
            .filter(|p| p.starts_with(term))
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60 * 1000;

    /// An index with its records, as a caller keeps them.
    struct Kept {
        index: Index,
        records: Records,
    }

    impl Kept {
        fn new() -> Self {
            Kept {
                index: Index::open(None).unwrap(),
                records: Records::new(),
            }
        }

        fn load(&self, keys: &[String]) -> Records {
            keys.iter()
                .filter_map(|k| self.records.get(k).map(|v| (k.clone(), v.clone())))
                .collect()
        }

        fn add(&mut self, docs: &[NewDoc]) {
            let needed = self.load(&self.index.plan_add(docs));
            let changed = self.index.add(docs, &needed).unwrap();
            self.records.extend(changed);
        }

        fn hits(&self, query: &str, periods: &[i64]) -> Vec<Hit> {
            let needed = self.load(&self.index.plan_search(query, periods));
            let found = self.index.search(query, periods, &needed).unwrap();
            let tables = self.load(&self.index.plan_hits(&found));
            self.index.hits(&found, &tables).unwrap()
        }

        fn search(&self, query: &str) -> Vec<String> {
            let periods = self.index.next_periods(None, usize::MAX);
            self.hits(query, &periods)
                .into_iter()
                .map(|h| h.id)
                .collect()
        }
    }

    fn doc(id: &str, day: i64, text: &str) -> NewDoc {
        NewDoc {
            id: id.into(),
            time_ms: 1_760_000_000_000 + day * DAY,
            text: text.into(),
            meta: format!("row:{id}"),
        }
    }

    #[test]
    fn finds_every_word_as_a_word_start_newest_first() {
        let mut kept = Kept::new();
        kept.add(&[
            doc("a", 0, "Ekim faturası ektedir"),
            doc("b", 40, "Fatura ödendi, teşekkürler"),
            doc("c", 80, "Toplantı notları"),
        ]);
        assert_eq!(kept.search("fatura"), ["b", "a"]);
        assert_eq!(kept.search("FATURA ekim"), ["a"]);
        assert_eq!(kept.search("fat"), ["b", "a"]);
        assert_eq!(kept.search("fa"), ["b", "a"]);
        assert_eq!(kept.search("tesekkur"), ["b"]);
        assert_eq!(kept.search("notlar toplanti"), ["c"]);
        assert!(kept.search("yok").is_empty());
        assert!(kept.search("  ").is_empty());
        // Every word must match.
        assert!(kept.search("fatura toplanti").is_empty());
    }

    #[test]
    fn turkish_and_accents_fold_both_ways() {
        let mut kept = Kept::new();
        kept.add(&[
            doc("a", 0, "İSTANBUL ofisi"),
            doc("b", 1, "istanbul şubesi"),
        ]);
        assert_eq!(kept.search("İstanbul"), ["b", "a"]);
        assert_eq!(kept.search("subesi"), ["b"]);
    }

    #[test]
    fn a_document_is_held_once_and_removed_ones_are_never_found() {
        let mut kept = Kept::new();
        kept.add(&[doc("a", 0, "rapor")]);
        kept.add(&[doc("a", 0, "rapor")]);
        assert_eq!(kept.index.len(), 1);
        kept.add(&[doc("b", 2, "rapor")]);
        let gone = [DocRef {
            id: "a".into(),
            time_ms: doc("a", 0, "").time_ms,
        }];
        let needed = kept.load(&kept.index.plan_remove(&gone));
        let changed = kept.index.remove(&gone, &needed).unwrap();
        kept.records.extend(changed);
        assert_eq!(kept.search("rapor"), ["b"]);
        // Counted no more, and the stored directory says so.
        assert_eq!(kept.index.len(), 1);
        let reopened = Index::open(kept.records.get(DIRECTORY_KEY).map(Vec::as_slice)).unwrap();
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn hits_carry_their_data_and_it_can_change() {
        let mut kept = Kept::new();
        kept.add(&[doc("a", 0, "rapor"), doc("b", 40, "rapor")]);
        let periods = kept.index.next_periods(None, usize::MAX);
        let found = |kept: &Kept| {
            kept.hits("rapor", &periods)
                .into_iter()
                .map(|h| h.meta)
                .collect::<Vec<_>>()
        };
        assert_eq!(found(&kept), ["row:b", "row:a"]);
        let a = doc("a", 0, "");
        let moved = [
            Hit {
                id: "a".into(),
                time_ms: a.time_ms,
                meta: "row:a moved".into(),
            },
            // Not held: left out.
            Hit {
                id: "z".into(),
                time_ms: a.time_ms,
                meta: "row:z".into(),
            },
        ];
        let needed = kept.load(&kept.index.plan_update_meta(&moved));
        let (changed, missing) = kept.index.update_meta(&moved, &needed).unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(missing, ["z"]);
        kept.records.extend(changed);
        assert_eq!(found(&kept), ["row:b", "row:a moved"]);
        assert_eq!(kept.index.len(), 2);
    }

    #[test]
    fn queries_page_by_period_and_the_directory_reopens() {
        let mut kept = Kept::new();
        kept.add(&[doc("old", 0, "proje"), doc("new", 100, "proje")]);
        let newest = kept.index.next_periods(None, 1);
        assert_eq!(newest.len(), 1);
        let first = kept.hits("proje", &newest);
        assert_eq!(
            first.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
            ["new"]
        );
        let older = kept.index.next_periods(Some(newest[0]), 1);
        let second = kept.hits("proje", &older);
        assert_eq!(
            second.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
            ["old"]
        );
        // The directory alone brings the index back.
        let reopened = Index::open(kept.records.get(DIRECTORY_KEY).map(Vec::as_slice)).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.periods(), kept.index.periods());
    }

    #[test]
    fn another_version_is_built_again() {
        let stored = Directory {
            version: INDEX_VERSION + 1,
            periods: BTreeMap::from([(1, PeriodInfo::default())]),
        };
        let bytes = encode(&stored).unwrap();
        assert!(Index::open(Some(&bytes)).unwrap().is_empty());
        assert_eq!(Index::stored_version(&bytes).unwrap(), INDEX_VERSION + 1);
        assert!(Index::open(Some(b"\xff")).is_err());
    }

    #[test]
    fn many_documents_stay_quick() {
        let mut kept = Kept::new();
        let docs: Vec<NewDoc> = (0..5_000)
            .map(|i| {
                doc(
                    &format!("m{i}"),
                    i / 10,
                    &format!("ileti {i} konu toplantı rapor fatura kelime{}", i % 50),
                )
            })
            .collect();
        for chunk in docs.chunks(50) {
            kept.add(chunk);
        }
        assert_eq!(kept.index.len(), 5_000);
        assert_eq!(kept.search("kelime7").len(), 100);
        assert_eq!(kept.search("4999")[0], "m4999");
        // No table of a period grows past a share of it.
        let largest = kept
            .records
            .iter()
            .filter(|(k, _)| k.starts_with("docs/"))
            .map(|(_, v)| v.len())
            .max()
            .unwrap();
        assert!(largest < 64 * 1024, "{largest}");
    }

    #[test]
    fn a_document_is_found_in_its_table_from_its_id() {
        assert_eq!(chunk_of("a"), chunk_of("a"));
        let chunks: BTreeSet<u32> = (0..1000).map(|i| chunk_of(&format!("m{i}"))).collect();
        assert_eq!(chunks.len(), DOC_CHUNKS as usize);
        // Fixed for good: stored numbers depend on it.
        assert_eq!(chunk_of("00000000-0000-4000-8000-000000000001"), 2);
    }
}
