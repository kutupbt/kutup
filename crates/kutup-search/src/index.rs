//! The period-sharded inverted index ([`Index`]); see the crate docs.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Bound;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::words;

/// Raised whenever what is indexed or how changes: a directory of another
/// version is not read, and the caller builds the index again.
pub const INDEX_VERSION: u32 = 1;
/// The period a document table and its shards cover (30 days).
pub const BUCKET_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Characters of a word that name its shard.
const SHARD_CHARS: usize = 3;
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

/// A document to index: an id (a message), its time and its text.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewDoc {
    pub id: String,
    pub time_ms: i64,
    pub text: String,
}

/// A document a query found.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Hit {
    pub id: String,
    pub time_ms: i64,
}

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
}

/// A period's documents; a document's number is its place here.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct DocTable {
    docs: Vec<DocEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DocEntry {
    id: String,
    time_ms: i64,
    live: bool,
}

/// Words of one start in one period, each with the ascending numbers of the
/// documents holding it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct Shard {
    words: BTreeMap<String, Vec<u32>>,
}

fn period_of(time_ms: i64) -> i64 {
    time_ms.div_euclid(BUCKET_MS)
}

fn docs_key(period: i64) -> String {
    format!("docs/{period}")
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
                let stored: Directory =
                    ciborium::from_reader(bytes).map_err(|e| SearchError::Decode(e.to_string()))?;
                if stored.version == INDEX_VERSION {
                    stored
                } else {
                    fresh
                }
            }
        };
        Ok(Index { directory })
    }

    /// How many documents it holds (removed ones included until rebuilt).
    pub fn len(&self) -> u64 {
        self.directory
            .periods
            .values()
            .map(|p| u64::from(p.docs))
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

    /// The records [`Index::add`] needs for `docs`.
    pub fn plan_add(&self, docs: &[NewDoc]) -> Vec<String> {
        let mut keys = BTreeSet::new();
        for doc in docs {
            let period = period_of(doc.time_ms);
            keys.insert(docs_key(period));
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
        let mut tables: BTreeMap<i64, DocTable> = BTreeMap::new();
        let mut shards: BTreeMap<(i64, String), Shard> = BTreeMap::new();
        for doc in docs {
            let period = period_of(doc.time_ms);
            let table = match tables.entry(period) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(decode(records, &docs_key(period))?)
                }
            };
            if table.docs.iter().any(|d| d.live && d.id == doc.id) {
                continue;
            }
            let number = u32::try_from(table.docs.len())
                .map_err(|_| SearchError::Encode("too many documents".into()))?;
            table.docs.push(DocEntry {
                id: doc.id.clone(),
                time_ms: doc.time_ms,
                live: true,
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
                let numbers = shards
                    .get_mut(&key)
                    .expect("loaded")
                    .words
                    .entry(word)
                    .or_default();
                // Numbers only grow within a period, so the list stays ascending.
                numbers.push(number);
            }
        }
        let mut changed = Records::new();
        for (period, table) in &tables {
            changed.insert(docs_key(*period), encode(table)?);
        }
        for ((period, prefix), shard) in &shards {
            changed.insert(shard_key(*period, prefix), encode(shard)?);
        }
        changed.insert(DIRECTORY_KEY.into(), encode(&self.directory)?);
        Ok(changed)
    }

    /// The records [`Index::remove`] needs for documents of these times.
    pub fn plan_remove(&self, times_ms: &[i64]) -> Vec<String> {
        let periods: BTreeSet<i64> = times_ms.iter().map(|t| period_of(*t)).collect();
        periods
            .into_iter()
            .filter(|p| self.directory.periods.contains_key(p))
            .map(docs_key)
            .collect()
    }

    /// Marks documents gone (a deleted message); their words stay in the
    /// shards until the index is built again, and are never found.
    pub fn remove(&mut self, docs: &[Hit], records: &Records) -> Result<Records, SearchError> {
        let mut changed = Records::new();
        let mut by_period: BTreeMap<i64, HashSet<&str>> = BTreeMap::new();
        for doc in docs {
            by_period
                .entry(period_of(doc.time_ms))
                .or_default()
                .insert(doc.id.as_str());
        }
        for (period, ids) in by_period {
            if !self.directory.periods.contains_key(&period) {
                continue;
            }
            let key = docs_key(period);
            let mut table: DocTable = decode(records, &key)?;
            let mut any = false;
            for entry in &mut table.docs {
                if entry.live && ids.contains(entry.id.as_str()) {
                    entry.live = false;
                    any = true;
                }
            }
            if any {
                changed.insert(key, encode(&table)?);
            }
        }
        Ok(changed)
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

    /// The records [`Index::search`] needs for `query` in `periods`.
    pub fn plan_search(&self, query: &str, periods: &[i64]) -> Vec<String> {
        let terms = words(query);
        let mut keys = BTreeSet::new();
        for period in periods {
            let Some(info) = self.directory.periods.get(period) else {
                continue;
            };
            keys.insert(docs_key(*period));
            for term in &terms {
                for prefix in matching_prefixes(info, term) {
                    keys.insert(shard_key(*period, prefix));
                }
            }
        }
        keys.into_iter().collect()
    }

    /// The live documents in `periods` holding every word of `query` (each
    /// as the start of a word), newest first.
    pub fn search(
        &self,
        query: &str,
        periods: &[i64],
        records: &Records,
    ) -> Result<Vec<Hit>, SearchError> {
        let terms = words(query);
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let mut hits = Vec::new();
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
            let Some(found) = found else { continue };
            if found.is_empty() {
                continue;
            }
            let table: DocTable = decode(records, &docs_key(*period))?;
            for number in found {
                if let Some(entry) = table.docs.get(number as usize).filter(|e| e.live) {
                    hits.push(Hit {
                        id: entry.id.clone(),
                        time_ms: entry.time_ms,
                    });
                }
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

        fn search(&self, query: &str) -> Vec<String> {
            let periods = self.index.next_periods(None, usize::MAX);
            let needed = self.load(&self.index.plan_search(query, &periods));
            self.index
                .search(query, &periods, &needed)
                .unwrap()
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
        let gone = [Hit {
            id: "a".into(),
            time_ms: doc("a", 0, "").time_ms,
        }];
        let needed = kept.load(&kept.index.plan_remove(&[gone[0].time_ms]));
        let changed = kept.index.remove(&gone, &needed).unwrap();
        kept.records.extend(changed);
        assert_eq!(kept.search("rapor"), ["b"]);
    }

    #[test]
    fn queries_page_by_period_and_the_directory_reopens() {
        let mut kept = Kept::new();
        kept.add(&[doc("old", 0, "proje"), doc("new", 100, "proje")]);
        let newest = kept.index.next_periods(None, 1);
        assert_eq!(newest.len(), 1);
        let needed = kept.load(&kept.index.plan_search("proje", &newest));
        let first = kept.index.search("proje", &newest, &needed).unwrap();
        assert_eq!(
            first.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
            ["new"]
        );
        let older = kept.index.next_periods(Some(newest[0]), 1);
        let needed = kept.load(&kept.index.plan_search("proje", &older));
        let second = kept.index.search("proje", &older, &needed).unwrap();
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
    }
}
