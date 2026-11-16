//! The account's synced private records (docs/plans/account-records.md, W3):
//! one store for every sealed list under the account head, as Signal's
//! Storage Service is one store under its manifest. This module is the scope
//! registry the server and every client share. Each scope names its number,
//! its head scope name, its record purpose and its id form; the server keeps
//! the records opaque.
//!
//! A record's id is the string the head's index names, and the bytes it
//! decodes to are the record's sealed object, so a record moved to another
//! id fails to open. Ids are never a plaintext name or id. Each is either:
//! - `hashed_object` under the object-id root, or
//! - the one fixed id of a single-record scope.
//!
//! The one exception is Pass secrets (decision 9): they keep the vault's
//! Drive file id, which the server already knows from the Drive row. It
//! reveals only that the file is a vault the account holds a key for, as
//! before. The server uses it to refuse a key for a file that is gone or not
//! the caller's, and to drop the key with the file.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::account_record::AccountRecordPurpose;
use crate::error::{CryptoError, Result};
use crate::format::{self, Extra};

/// How a scope's record ids are formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdForm {
    /// `hashed_object` under the object-id root: 32 bytes as unpadded
    /// base64url (43 characters).
    Hashed,
    /// A Drive file id, canonical lowercase UUID text; the object is its 16
    /// bytes. Pass secrets only (see the module doc).
    DriveFileId,
    /// The scope holds one record, with this id and no object.
    Single(&'static str),
}

/// A scope of the account-records store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordScope {
    PassSecrets,
    Pins,
    ChatGroups,
    ChatContacts,
}

/// One registry row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeInfo {
    /// Stored in `account_records.scope`; never reused.
    pub number: i16,
    /// The head's scope name (`ScopeV1::scope`) and the API's path segment.
    pub name: &'static str,
    pub purpose: AccountRecordPurpose,
    pub id: IdForm,
}

impl RecordScope {
    /// Every scope, in number order.
    pub const ALL: [RecordScope; 4] = [
        RecordScope::PassSecrets,
        RecordScope::Pins,
        RecordScope::ChatGroups,
        RecordScope::ChatContacts,
    ];

    pub const fn info(self) -> ScopeInfo {
        match self {
            RecordScope::PassSecrets => ScopeInfo {
                number: 1,
                name: "passSecrets",
                purpose: AccountRecordPurpose::PassVaultSecret,
                id: IdForm::DriveFileId,
            },
            RecordScope::Pins => ScopeInfo {
                number: 2,
                name: "pins",
                purpose: AccountRecordPurpose::IdentityPins,
                id: IdForm::Single("pins"),
            },
            RecordScope::ChatGroups => ScopeInfo {
                number: 3,
                name: "chatGroups",
                purpose: AccountRecordPurpose::ChatGroupListEntry,
                id: IdForm::Hashed,
            },
            RecordScope::ChatContacts => ScopeInfo {
                number: 4,
                name: "chatContacts",
                purpose: AccountRecordPurpose::ChatContactListEntry,
                id: IdForm::Hashed,
            },
        }
    }

    pub fn by_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.info().name == name)
    }

    pub fn by_number(number: i16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.info().number == number)
    }

    pub fn name(self) -> &'static str {
        self.info().name
    }

    /// Checks `id` is in this scope's form and returns the record's sealed
    /// object (empty for a single-record scope). Only the canonical spelling
    /// passes, so one record has one id.
    pub fn object(self, id: &str) -> Result<Vec<u8>> {
        let bad = || CryptoError::InvalidInput(format!("not a {} record id", self.name()));
        match self.info().id {
            IdForm::Hashed => {
                let bytes = URL_SAFE_NO_PAD.decode(id).map_err(|_| bad())?;
                if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != id {
                    return Err(bad());
                }
                Ok(bytes)
            }
            IdForm::DriveFileId => {
                let bytes = crate::drive_object::parse_canonical_uuid(id, "record id")
                    .map_err(|_| bad())?;
                Ok(bytes.to_vec())
            }
            IdForm::Single(only) if id == only => Ok(Vec::new()),
            IdForm::Single(_) => Err(bad()),
        }
    }

    /// The id of a hashed scope's record for its plaintext object.
    pub fn hashed_id(
        self,
        object_id_key: &crate::account_roots::ObjectIdKey,
        plain_id: &[u8],
    ) -> Result<String> {
        match self.info().id {
            IdForm::Hashed => Ok(URL_SAFE_NO_PAD.encode(crate::account_record::hashed_object(
                object_id_key,
                self.info().purpose,
                plain_id,
            ))),
            _ => Err(CryptoError::InvalidInput(format!(
                "{} ids are not hashed",
                self.name()
            ))),
        }
    }
}

/// The newest [`ScopeRecords`] version this reader knows.
pub const SCOPE_RECORDS_VERSION: u16 = 1;

/// One record as a device keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredRecord {
    pub revision: u64,
    /// The sealed record, canonical base64, as the server holds it.
    pub envelope: String,
}

/// A device's copy of one scope: its records and how far it has read the
/// scope's changes. Kept as JSON by the clients that persist it, under the
/// format-evolution rule (`v`, an optional `min`, unknown fields kept).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeRecords {
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
    pub scope: String,
    /// The `next` of the last page merged; 0 before the first.
    pub cursor: i64,
    pub records: BTreeMap<String, StoredRecord>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: Extra,
}

/// One page, as `GET /api/account/records/{scope}` answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub records: Vec<PageRecord>,
    pub deleted: Vec<PageDeleted>,
    pub next: i64,
    pub more: bool,
    pub resync: bool,
    /// The head of the page's snapshot (base64); none before the first.
    pub head: Option<String>,
    /// Before the account's first head, what a first head starts on.
    pub basis: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageRecord {
    pub id: String,
    pub revision: u64,
    pub envelope: String,
    pub seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageDeleted {
    pub id: String,
    pub seq: i64,
}

/// What [`ScopeRecords::merge`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merged {
    /// More pages wait: read on from the new cursor; the index is checked
    /// only after the last.
    More,
    /// Caught up: check [`ScopeRecords::index`] against the page's head
    /// (`account_head::check_index`) before keeping the copy.
    Done,
    /// The cursor was too old: the copy was emptied; read from 0 again.
    Resync,
}

/// A batch's items for one scope, made on a device's caught-up copy: each
/// item's base revision is the copy's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPlan {
    scope: RecordScope,
    puts: Vec<(String, u64, u64, String)>,
    deletes: Vec<(String, u64)>,
}

impl ScopeRecords {
    pub fn new(scope: RecordScope) -> Self {
        Self {
            v: SCOPE_RECORDS_VERSION,
            min: None,
            scope: scope.name().to_owned(),
            cursor: 0,
            records: BTreeMap::new(),
            extra: Extra::new(),
        }
    }

    /// A kept copy, read back: a newer version than this reader's is
    /// `NewerThanMe` (keep it, read the scope again from 0 meanwhile).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        format::check_json_version("scope records", bytes, SCOPE_RECORDS_VERSION)?;
        let copy: Self = serde_json::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidInput("scope records do not decode".into()))?;
        format::check_version("scope records", copy.v, copy.min, SCOPE_RECORDS_VERSION)?;
        format::check_extra("scope records", &copy.extra)?;
        let scope = copy.scope()?;
        if copy.cursor < 0 {
            return Err(CryptoError::InvalidInput(
                "scope records' cursor is negative".into(),
            ));
        }
        for id in copy.records.keys() {
            scope.object(id)?;
        }
        Ok(copy)
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("scope records encode")
    }

    pub fn scope(&self) -> Result<RecordScope> {
        RecordScope::by_name(&self.scope)
            .ok_or_else(|| CryptoError::InvalidInput("not a known records scope".into()))
    }

    /// Merges a page read from [`Self::cursor`]. Merge into a copy, and keep
    /// it only once the last page's head is verified and the index matches
    /// it: a page alone is never trusted (decision 5). Refuses a page whose
    /// changes are not in counter order after the cursor, or whose ids are
    /// not the scope's.
    pub fn merge(&mut self, page: &Page) -> Result<Merged> {
        let scope = self.scope()?;
        if page.resync {
            self.records.clear();
            self.cursor = 0;
            return Ok(Merged::Resync);
        }
        let bad = |what: &str| CryptoError::InvalidInput(format!("records page: {what}"));
        let mut changes: Vec<(i64, &str, Option<&PageRecord>)> = page
            .records
            .iter()
            .map(|r| (r.seq, r.id.as_str(), Some(r)))
            .chain(page.deleted.iter().map(|d| (d.seq, d.id.as_str(), None)))
            .collect();
        changes.sort_by_key(|change| change.0);
        let mut last = self.cursor;
        for (seq, id, record) in changes {
            if seq <= last {
                return Err(bad("changes out of order"));
            }
            last = seq;
            scope.object(id)?;
            match record {
                Some(record) => {
                    if record.revision == 0 {
                        return Err(bad("a record at revision 0"));
                    }
                    self.records.insert(
                        id.to_owned(),
                        StoredRecord {
                            revision: record.revision,
                            envelope: record.envelope.clone(),
                        },
                    );
                }
                None => {
                    self.records.remove(id);
                }
            }
        }
        if page.next < last {
            return Err(bad("the cursor goes back"));
        }
        self.cursor = page.next;
        Ok(if page.more {
            Merged::More
        } else {
            Merged::Done
        })
    }

    /// The scope's `(id, revision)` pairs, sorted: what the head's index
    /// names and `account_head::check_index` checks.
    pub fn index(&self) -> Vec<(String, u64)> {
        self.records
            .iter()
            .map(|(id, record)| (id.clone(), record.revision))
            .collect()
    }

    /// A batch on this copy: `puts` as `(id, revision, envelope)` (the
    /// revision the envelope was sealed at), `deletes` by id. Each base
    /// revision is this copy's (0 for a new record).
    pub fn plan(
        &self,
        puts: Vec<(String, u64, String)>,
        deletes: Vec<String>,
    ) -> Result<BatchPlan> {
        let scope = self.scope()?;
        let mut named = std::collections::BTreeSet::new();
        let mut plan = BatchPlan {
            scope,
            puts: Vec::new(),
            deletes: Vec::new(),
        };
        for (id, revision, envelope) in puts {
            scope.object(&id)?;
            let base = self.records.get(&id).map_or(0, |r| r.revision);
            if revision <= base {
                return Err(CryptoError::InvalidInput(
                    "a put's revision must be above the record's".into(),
                ));
            }
            if !named.insert(id.clone()) {
                return Err(CryptoError::InvalidInput("a record is named twice".into()));
            }
            plan.puts.push((id, base, revision, envelope));
        }
        for id in deletes {
            let Some(record) = self.records.get(&id) else {
                return Err(CryptoError::InvalidInput("a delete names no record".into()));
            };
            if !named.insert(id.clone()) {
                return Err(CryptoError::InvalidInput("a record is named twice".into()));
            }
            plan.deletes.push((id, record.revision));
        }
        Ok(plan)
    }

    /// After the server took `plan` (its answer's `seq`): the copy holds the
    /// batch. The cursor moves to `seq` only when the copy was caught up at
    /// the head the batch followed: that head's compare-and-swap then rules
    /// out any other write in between. Otherwise the next read fetches
    /// the batch's own changes again, which merge as no-ops.
    pub fn applied(&mut self, plan: &BatchPlan, seq: i64, caught_up: bool) {
        for (id, _, revision, envelope) in &plan.puts {
            self.records.insert(
                id.clone(),
                StoredRecord {
                    revision: *revision,
                    envelope: envelope.clone(),
                },
            );
        }
        for (id, _) in &plan.deletes {
            self.records.remove(id);
        }
        if caught_up && seq > self.cursor {
            self.cursor = seq;
        }
    }
}

impl BatchPlan {
    pub fn scope(&self) -> RecordScope {
        self.scope
    }

    pub fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.deletes.is_empty()
    }

    /// The scope's index once the batch lands: what the next head names.
    pub fn index_after(&self, copy: &ScopeRecords) -> Vec<(String, u64)> {
        let mut index: BTreeMap<String, u64> = copy.index().into_iter().collect();
        for (id, _, revision, _) in &self.puts {
            index.insert(id.clone(), *revision);
        }
        for (id, _) in &self.deletes {
            index.remove(id);
        }
        index.into_iter().collect()
    }

    /// The `POST /api/account/records` body, with the next head.
    pub fn body(&self, head: Option<&str>) -> serde_json::Value {
        let scope = self.scope.name();
        serde_json::json!({
            "head": head,
            "puts": self.puts.iter().map(|(id, base, _, envelope)| serde_json::json!({
                "scope": scope, "id": id, "baseRevision": base, "envelope": envelope,
            })).collect::<Vec<_>>(),
            "deletes": self.deletes.iter().map(|(id, base)| serde_json::json!({
                "scope": scope, "id": id, "baseRevision": base,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_is_one_to_one() {
        let mut numbers: Vec<_> = RecordScope::ALL.iter().map(|s| s.info().number).collect();
        let mut names: Vec<_> = RecordScope::ALL.iter().map(|s| s.name()).collect();
        let mut purposes: Vec<_> = RecordScope::ALL
            .iter()
            .map(|s| s.info().purpose as u16)
            .collect();
        names.sort();
        names.dedup();
        purposes.sort();
        purposes.dedup();
        numbers.sort();
        assert_eq!(names.len(), RecordScope::ALL.len());
        assert_eq!(purposes.len(), RecordScope::ALL.len());
        for scope in RecordScope::ALL {
            assert_eq!(RecordScope::by_name(scope.name()), Some(scope));
            assert_eq!(RecordScope::by_number(scope.info().number), Some(scope));
            // Every scope's purpose is mutable: a record is replaced in place.
            assert!(scope.info().purpose.policy().mutable);
        }
        assert_eq!(numbers, vec![1, 2, 3, 4]);
    }

    #[test]
    fn ids_have_one_spelling() {
        let hashed = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert_eq!(
            RecordScope::ChatGroups.object(&hashed).unwrap(),
            vec![7u8; 32]
        );
        assert!(RecordScope::ChatGroups
            .object(&format!("{hashed}="))
            .is_err());
        assert!(RecordScope::ChatGroups.object(&hashed[..42]).is_err());
        let file = "0190a7b4-1c2d-7e3f-8a9b-0c1d2e3f4a5b";
        assert_eq!(RecordScope::PassSecrets.object(file).unwrap().len(), 16);
        assert!(RecordScope::PassSecrets
            .object(&file.to_uppercase())
            .is_err());
        assert!(RecordScope::PassSecrets.object(&hashed).is_err());
        assert_eq!(RecordScope::Pins.object("pins").unwrap(), Vec::<u8>::new());
        assert!(RecordScope::Pins.object("pin").is_err());
    }

    fn page(records: &[(u8, u64, i64)], deleted: &[(u8, i64)], next: i64, more: bool) -> Page {
        Page {
            records: records
                .iter()
                .map(|(n, revision, seq)| PageRecord {
                    id: URL_SAFE_NO_PAD.encode([*n; 32]),
                    revision: *revision,
                    envelope: format!("e{n}r{revision}"),
                    seq: *seq,
                })
                .collect(),
            deleted: deleted
                .iter()
                .map(|(n, seq)| PageDeleted {
                    id: URL_SAFE_NO_PAD.encode([*n; 32]),
                    seq: *seq,
                })
                .collect(),
            next,
            more,
            resync: false,
            head: None,
            basis: None,
        }
    }

    fn id(n: u8) -> String {
        URL_SAFE_NO_PAD.encode([n; 32])
    }

    #[test]
    fn pages_merge_in_counter_order() {
        let mut copy = ScopeRecords::new(RecordScope::ChatGroups);
        assert_eq!(
            copy.merge(&page(&[(1, 1, 1), (2, 5, 2)], &[], 2, true))
                .unwrap(),
            Merged::More
        );
        assert_eq!(copy.cursor, 2);
        // A change and a deletion, read on.
        assert_eq!(
            copy.merge(&page(&[(1, 2, 4)], &[(2, 3)], 9, false))
                .unwrap(),
            Merged::Done
        );
        assert_eq!(copy.index(), vec![(id(1), 2)]);
        assert_eq!(copy.cursor, 9);
        // Out of order, at or below the cursor, another scope's id: refused.
        let mut stale = copy.clone();
        assert!(stale.merge(&page(&[(3, 1, 9)], &[], 10, false)).is_err());
        let mut wrong = ScopeRecords::new(RecordScope::Pins);
        assert!(wrong.merge(&page(&[(3, 1, 1)], &[], 1, false)).is_err());
        let mut back = copy.clone();
        assert!(back.merge(&page(&[(3, 1, 12)], &[], 11, false)).is_err());
        // Resync empties the copy.
        let mut resync = page(&[], &[], 0, false);
        resync.resync = true;
        assert_eq!(copy.clone().merge(&resync).unwrap(), Merged::Resync);
        let mut emptied = copy.clone();
        emptied.merge(&resync).unwrap();
        assert!(emptied.records.is_empty() && emptied.cursor == 0);
    }

    #[test]
    fn a_batch_is_made_on_the_copy_and_applied_after() {
        let mut copy = ScopeRecords::new(RecordScope::ChatGroups);
        copy.merge(&page(&[(1, 1, 1), (2, 5, 2)], &[], 2, false))
            .unwrap();
        let plan = copy
            .plan(
                vec![(id(1), 2, "e1r2".into()), (id(3), 1, "e3r1".into())],
                vec![id(2)],
            )
            .unwrap();
        assert_eq!(plan.index_after(&copy), vec![(id(1), 2), (id(3), 1)]);
        let body = plan.body(Some("HEAD"));
        assert_eq!(body["head"], "HEAD");
        assert_eq!(body["puts"][0]["baseRevision"], 1);
        assert_eq!(body["puts"][1]["baseRevision"], 0);
        assert_eq!(body["deletes"][0]["baseRevision"], 5);
        // Not above the copy's revision, a delete of nothing, a record twice.
        assert!(copy.plan(vec![(id(2), 5, "x".into())], vec![]).is_err());
        assert!(copy.plan(vec![], vec![id(9)]).is_err());
        assert!(copy
            .plan(vec![(id(2), 6, "x".into())], vec![id(2)])
            .is_err());
        // Applied: caught up, the cursor follows the batch; not, it stays.
        let mut behind = copy.clone();
        copy.applied(&plan, 5, true);
        assert_eq!(copy.index(), vec![(id(1), 2), (id(3), 1)]);
        assert_eq!(copy.cursor, 5);
        behind.applied(&plan, 5, false);
        assert_eq!(behind.cursor, 2);
        // The batch's own changes read again merge as no-ops.
        behind
            .merge(&page(&[(1, 2, 4), (3, 1, 5)], &[(2, 3)], 5, false))
            .unwrap();
        assert_eq!(behind.records, copy.records);
    }

    #[test]
    fn a_kept_copy_evolves_without_a_wipe() {
        let mut copy = ScopeRecords::new(RecordScope::ChatGroups);
        copy.merge(&page(&[(1, 1, 1)], &[], 1, false)).unwrap();
        copy.extra.insert("later".into(), serde_json::json!(true));
        let back = ScopeRecords::from_json(&copy.to_json()).unwrap();
        assert_eq!(back, copy);
        let mut newer: serde_json::Value = serde_json::from_slice(&copy.to_json()).unwrap();
        newer["v"] = serde_json::json!(SCOPE_RECORDS_VERSION + 1);
        let error = ScopeRecords::from_json(&serde_json::to_vec(&newer).unwrap()).unwrap_err();
        assert!(matches!(error, CryptoError::NewerThanMe(_)), "{error}");
    }
}
