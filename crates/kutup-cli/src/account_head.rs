//! The account head on the command line (docs/plans/rollback-protection.md):
//! the same checks as the web, with this profile as one device.
//!
//! - What the device keeps is one sealed `LocalHeadStateV1` file per account
//!   incarnation (`account-head-<name>` in the profile's data directory): its
//!   anchor, its device id, its log.
//! - The highest revision seen of each listed value is a sealed revision-guard
//!   file (`revisions.json`), as the web keeps in IndexedDB. It replaces the
//!   older plaintext `identity-pins-revision`, whose value it takes over.
//! - A head that rolled back or forked stops listed writes with exit code 6,
//!   until `kutup account reanchor`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_head::{
    self, HeadKeys, HeadStatus, IndexCheck, LocalHeadStateV1, VerifiedHead,
};
use kutup_crypto::revision_guard::GuardKeys;
use sha2::{Digest as _, Sha256};

use crate::api::Client;
use crate::errors::HeadBlocked;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A scope's values as the verified head vouches for them.
#[derive(Debug, Clone)]
pub struct Index {
    pub scope: String,
    pub values: Vec<(String, u64)>,
    /// The head covers the scope: values outside it, or at another revision, are refused.
    pub covered: bool,
    /// The account has no head yet: the chain starts on this basis.
    pub basis: Option<String>,
}

impl Index {
    pub fn revision(&self, id: &str) -> Option<u64> {
        self.values
            .iter()
            .find(|(value, _)| value == id)
            .map(|(_, revision)| *revision)
    }

    /// Refuses a value at another revision than the covered index lists.
    pub fn expect(&self, id: &str, revision: u64) -> Result<()> {
        if self.covered && self.revision(id) != Some(revision) {
            bail!(
                "{}: {id} is not at the revision the account's verified state lists (rolled back, or brought back)",
                self.scope
            );
        }
        Ok(())
    }

    /// Refuses a listing that is not exactly the covered index's ids.
    pub fn expect_listing<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> Result<()> {
        if !self.covered {
            return Ok(());
        }
        let mut listed: Vec<&str> = ids.into_iter().collect();
        listed.sort_unstable();
        let mut indexed: Vec<&str> = self.values.iter().map(|(id, _)| id.as_str()).collect();
        indexed.sort_unstable();
        if listed != indexed {
            bail!(
                "{}: the server's list is not the one the account's verified state lists (a value dropped or brought back)",
                self.scope
            );
        }
        Ok(())
    }
}

/// Sends a listed write with the given head; `Ok(None)` when another device wrote first.
pub type Send<'a, T> = Box<dyn FnOnce(&str) -> Result<Option<T>> + 'a>;

/// What a listed write sends: the index after it, and how to send it with a head.
pub struct Edit<'a, T> {
    /// Each id's new revision, or `None` when the write removes it.
    pub changes: Vec<(String, Option<u64>)>,
    /// Sends the write with `head`; `Ok(None)` when another device wrote first.
    pub send: Send<'a, T>,
}

/// The sealed revision guard: the highest revision this profile has seen of
/// each value, sealed to its entry (`kutup_crypto::revision_guard`).
pub struct Guard {
    keys: GuardKeys,
    path: PathBuf,
}

impl Guard {
    fn load(&self) -> BTreeMap<String, String> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// The highest revision seen (0: none, or an entry that was altered or moved).
    pub fn seen(&self, scope: &str, id: &str) -> Result<u64> {
        let entry = self.keys.entry_id(scope, id)?;
        Ok(self
            .load()
            .get(&entry)
            .and_then(|sealed| STANDARD.decode(sealed).ok())
            .and_then(|sealed| self.keys.open_seen(&entry, &sealed).ok())
            .unwrap_or(0))
    }

    /// A revision read or written: refused when older than one seen, kept when newer.
    pub fn accept(&self, scope: &str, id: &str, revision: u64) -> Result<()> {
        let seen = self.seen(scope, id)?;
        if revision < seen {
            bail!("{scope}: revision {revision} is older than {seen}, already seen on this device");
        }
        if revision > seen {
            let entry = self.keys.entry_id(scope, id)?;
            let mut all = self.load();
            all.insert(
                entry.clone(),
                STANDARD.encode(self.keys.seal_seen(&entry, revision)?),
            );
            write_private(&self.path, serde_json::to_string(&all)?.as_bytes())?;
        }
        Ok(())
    }

    /// The revision to seal a new value at, written on top of `base`.
    pub fn next(&self, scope: &str, id: &str, base: u64) -> Result<u64> {
        Ok(now_ms().max(self.seen(scope, id)? + 1).max(base + 1))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes).with_context(|| format!("write {}", temporary.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))
}

/// The account head for one signed-in profile.
pub struct CliHead<'a> {
    client: &'a Client,
    keys: HeadKeys,
    binding: String,
    incarnation: String,
    dir: PathBuf,
    verified: Option<VerifiedHead>,
    /// What the last check found that was not trusted, for `reanchor`.
    blocked: Option<Blocked>,
}

#[derive(Debug, Clone)]
enum Blocked {
    On {
        current: Vec<u8>,
        segment: Option<Vec<Vec<u8>>>,
    },
    /// The server has no head at all, though this device remembers one.
    NoHead,
}

/// What `kutup account reanchor` reports.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadReport {
    pub status: String,
    pub anchor: Option<u64>,
    pub current: Option<u64>,
}

impl<'a> CliHead<'a> {
    pub fn open(
        client: &'a Client,
        master_key: &[u8; 32],
        binding: &str,
        incarnation: &str,
        dir: PathBuf,
    ) -> Result<Self> {
        let head = Self {
            client,
            keys: HeadKeys::derive(master_key)?,
            binding: binding.to_owned(),
            incarnation: incarnation.to_owned(),
            dir,
            verified: None,
            blocked: None,
        };
        Ok(head)
    }

    /// This profile's sealed revision guard, taking over the older plaintext
    /// `identity-pins-revision` once (its value becomes the pin list's).
    pub fn guard(dir: &Path, master_key: &[u8; 32]) -> Result<Guard> {
        let guard = Guard {
            keys: GuardKeys::derive(master_key)?,
            path: dir.join("revisions.json"),
        };
        let old = dir.join("identity-pins-revision");
        if let Ok(text) = std::fs::read_to_string(&old) {
            if let Ok(revision) = text.trim().parse::<u64>() {
                if revision > 0 {
                    // Taken over as seen: an older list is refused as before.
                    let _ = guard.accept(
                        crate::identity::PINS_GUARD_SCOPE,
                        crate::identity::PINS_GUARD_ID,
                        revision,
                    );
                }
            }
            let _ = std::fs::remove_file(&old);
        }
        Ok(guard)
    }

    fn state_path(&self) -> Result<PathBuf> {
        Ok(self.dir.join(format!(
            "account-head-{}",
            self.keys.local_state_name(&self.incarnation)?
        )))
    }

    /// This device's state; one that does not open (or none) is a fresh one.
    fn load(&self) -> Result<LocalHeadStateV1> {
        let path = self.state_path()?;
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(state) = STANDARD.decode(text.trim()).ok().and_then(|sealed| {
                account_head::open_local_state(
                    &self.keys,
                    &self.binding,
                    &self.incarnation,
                    &sealed,
                )
                .ok()
            }) {
                return Ok(state);
            }
        }
        Ok(LocalHeadStateV1::new(&self.incarnation)?)
    }

    fn save(&self, state: &LocalHeadStateV1) -> Result<()> {
        let sealed = account_head::seal_local_state(&self.keys, &self.binding, state)?;
        write_private(&self.state_path()?, STANDARD.encode(sealed).as_bytes())
    }

    fn advance(&self) -> Result<()> {
        if let Some(verified) = &self.verified {
            let mut state = self.load()?;
            if state.advance(verified, now_ms()) {
                self.save(&state)?;
            }
        }
        Ok(())
    }

    /// Checks the head the server shows (`None`: none) against what this
    /// device remembers. A rollback or a fork is [`HeadBlocked`] (exit 6).
    pub fn verify(&mut self, current: Option<&str>) -> Result<()> {
        self.verified = None;
        let state = self.load()?;
        let Some(current) = current else {
            if state.anchor.is_some() {
                self.blocked = Some(Blocked::NoHead);
                return Err(HeadBlocked("rollback".into()).into());
            }
            return Ok(());
        };
        let current = STANDARD
            .decode(current)
            .context("the account head is not base64")?;
        let segment = match &state.anchor {
            Some(anchor) if hex::encode(Sha256::digest(&current)) != anchor.digest => self
                .client
                .get_account_heads(anchor.sequence)?
                .map(|heads| {
                    let mut heads = heads
                        .iter()
                        .map(|head| {
                            STANDARD
                                .decode(head)
                                .context("a head in the chain is not base64")
                        })
                        .collect::<Result<Vec<_>>>()?;
                    // The chain up to the head being checked: one written
                    // since does not belong (it would read as a fork).
                    if let Some(at) = heads.iter().position(|head| *head == current) {
                        heads.truncate(at + 1);
                    }
                    Ok::<_, anyhow::Error>(heads)
                })
                .transpose()?,
            _ => None,
        };
        let checked = account_head::check(
            &self.keys,
            &self.binding,
            &self.incarnation,
            state.anchor.as_ref(),
            &current,
            segment.as_deref(),
        )?;
        match checked.status {
            HeadStatus::Fresh | HeadStatus::Current | HeadStatus::Extends => {
                self.verified = checked.verified;
                self.advance()
            }
            HeadStatus::TooOld => {
                // Further back than the server keeps: re-anchored with a
                // notice, never blocking (docs/plans/rollback-protection.md §7).
                let anchor = state.anchor.clone().expect("too old needs an anchor");
                let (record, verified) = account_head::reanchor(
                    &self.keys,
                    &self.binding,
                    &self.incarnation,
                    &anchor,
                    &current,
                    segment.as_deref(),
                    false,
                    now_ms(),
                )?;
                let mut state = state;
                state.reanchored(&record);
                self.save(&state)?;
                self.verified = Some(verified);
                eprintln!(
                    "note: this device had not been used for a long time; it now follows the account's current data (#{})",
                    record.to.sequence
                );
                Ok(())
            }
            status @ (HeadStatus::Rollback | HeadStatus::Fork) => {
                let name = if status == HeadStatus::Fork {
                    "fork"
                } else {
                    "rollback"
                };
                self.blocked = Some(Blocked::On { current, segment });
                Err(HeadBlocked(name.into()).into())
            }
        }
    }

    /// A scope's index, checked against the head it was read with. A
    /// rollback or fork is read once more first: another device moving on
    /// between two reads is not one.
    pub fn index(&mut self, scope: &str) -> Result<Index> {
        match self.index_once(scope) {
            Err(error) if error.downcast_ref::<HeadBlocked>().is_some() => self.index_once(scope),
            other => other,
        }
    }

    fn index_once(&mut self, scope: &str) -> Result<Index> {
        let Some(record) = self.client.get_account_index(scope)? else {
            let head = self.client.get_account_head()?;
            self.verify(head.as_deref())?;
            return Ok(Index {
                scope: scope.to_owned(),
                values: Vec::new(),
                covered: false,
                basis: None,
            });
        };
        self.verify(record.head.as_deref())?;
        let covered = match &self.verified {
            None => false,
            Some(verified) => {
                match account_head::check_index(&self.keys, verified, scope, &record.values) {
                    Ok(IndexCheck::Matches) => true,
                    Ok(IndexCheck::Uncovered) => false,
                    Err(_) => bail!(
                        "{scope}: the server's list does not match the account's verified state"
                    ),
                }
            }
        };
        Ok(Index {
            scope: scope.to_owned(),
            values: record.values,
            covered,
            basis: if record.head.is_none() {
                record.basis
            } else {
                None
            },
        })
    }

    /// A listed write of `scope`: the edit made on the verified index, sent
    /// with the next head, redone (five tries) when another device wrote
    /// first; the chain started first when there is none. An edit returning
    /// `None` sends nothing.
    pub fn listed_write<'e, T>(
        &mut self,
        scope: &str,
        mut edit: impl FnMut(&Index, u32) -> Result<Option<Edit<'e, T>>>,
    ) -> Result<Option<T>> {
        for attempt in 1..=5 {
            let index = self.index(scope)?;
            let writer = self.keys.writer(&self.load()?.device_id)?;
            let Some(change) = edit(&index, attempt)? else {
                return Ok(None);
            };
            if let Some(basis) = &index.basis {
                let entry = self.keys.scope_digest(scope, &index.values)?;
                let (first, verified) = account_head::first(
                    &self.keys,
                    &self.binding,
                    &self.incarnation,
                    &writer,
                    vec![entry],
                )?;
                if !self
                    .client
                    .start_account_head(&STANDARD.encode(&first), basis)?
                {
                    continue;
                }
                self.verified = Some(verified);
                self.advance()?;
            }
            let mut values: BTreeMap<String, u64> = index.values.iter().cloned().collect();
            for (id, revision) in &change.changes {
                match revision {
                    Some(revision) => values.insert(id.clone(), *revision),
                    None => values.remove(id),
                };
            }
            let values: Vec<(String, u64)> = values.into_iter().collect();
            let entry = self.keys.scope_digest(scope, &values)?;
            let verified = self.verified.as_ref().context("no verified account head")?;
            let next = verified.next(&writer, vec![entry])?;
            let sealed = account_head::seal(&self.keys, &self.binding, &next)?;
            match (change.send)(&STANDARD.encode(&sealed))? {
                Some(done) => {
                    let committed = verified.committed(&self.keys, &self.binding, &sealed)?;
                    self.verified = Some(committed);
                    self.advance()?;
                    return Ok(Some(done));
                }
                None => continue,
            }
        }
        bail!("{scope}: another device kept writing first; try again")
    }

    /// Where this device stands: checks the head now.
    pub fn report(&mut self) -> Result<HeadReport> {
        // Read once more before a rollback or fork counts.
        let first = self.client.get_account_head()?;
        let current = match self.verify(first.as_deref()) {
            Err(error) if error.downcast_ref::<HeadBlocked>().is_some() => {
                self.client.get_account_head()?
            }
            _ => first,
        };
        let anchor = self.load()?.anchor.map(|anchor| anchor.sequence);
        let sequence = current
            .as_deref()
            .and_then(|head| STANDARD.decode(head).ok())
            .and_then(|sealed| account_head::inspect(&sealed).ok());
        let status = match self.verify(current.as_deref()) {
            Ok(()) => "trusted".to_owned(),
            Err(error) => match error.downcast_ref::<HeadBlocked>() {
                Some(blocked) => blocked.0.clone(),
                None => return Err(error),
            },
        };
        Ok(HeadReport {
            status,
            anchor,
            current: sequence,
        })
    }

    /// Continues with the server's data after a rollback or fork the person
    /// confirmed (a restore from a backup looks the same), logged locally.
    /// Returns false when there was nothing to continue from.
    pub fn continue_with_server(&mut self) -> Result<bool> {
        let mut state = self.load()?;
        match self.blocked.take() {
            None => Ok(false),
            Some(Blocked::NoHead) => {
                state.forgotten(now_ms());
                self.save(&state)?;
                Ok(true)
            }
            Some(Blocked::On {
                current, segment, ..
            }) => {
                let anchor = state
                    .anchor
                    .clone()
                    .context("nothing remembered to move from")?;
                let (record, verified) = account_head::reanchor(
                    &self.keys,
                    &self.binding,
                    &self.incarnation,
                    &anchor,
                    &current,
                    segment.as_deref(),
                    true,
                    now_ms(),
                )?;
                state.reanchored(&record);
                self.save(&state)?;
                self.verified = Some(verified);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(covered: bool, values: &[(&str, u64)]) -> Index {
        Index {
            scope: "contacts".into(),
            values: values.iter().map(|(id, r)| (id.to_string(), *r)).collect(),
            covered,
            basis: None,
        }
    }

    #[test]
    fn a_covered_index_holds_values_and_listings() {
        let index = index(true, &[("a", 1), ("b", 2)]);
        index.expect("a", 1).unwrap();
        assert!(index.expect("a", 2).is_err());
        assert!(index.expect("c", 1).is_err());
        index.expect_listing(["b", "a"]).unwrap();
        assert!(index.expect_listing(["a"]).is_err());
        assert!(index.expect_listing(["a", "b", "c"]).is_err());
        // Uncovered: nothing to hold it to yet.
        let open = super::tests::index(false, &[]);
        open.expect("x", 9).unwrap();
        open.expect_listing(["x"]).unwrap();
    }

    #[test]
    fn the_guard_is_sealed_and_only_moves_forward() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let guard = CliHead::guard(dir, &[7u8; 32]).unwrap();
        assert_eq!(guard.seen("s", "x").unwrap(), 0);
        guard.accept("s", "x", 5).unwrap();
        assert!(guard.accept("s", "x", 4).is_err());
        assert_eq!(guard.seen("s", "x").unwrap(), 5);
        assert!(guard.next("s", "x", 0).unwrap() > 5);
        // Another account's keys read nothing; an altered entry reads as none.
        assert_eq!(
            CliHead::guard(dir, &[8u8; 32])
                .unwrap()
                .seen("s", "x")
                .unwrap(),
            0
        );
        // Entries are named by an HMAC: the file says nothing of what they are about.
        let text = std::fs::read_to_string(dir.join("revisions.json")).unwrap();
        assert!(!text.contains("\"s\"") && !text.contains("\"x\""));
    }

    #[test]
    fn the_old_plaintext_pin_revision_is_taken_over_once() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        std::fs::write(dir.join("identity-pins-revision"), "1790000000000").unwrap();
        let guard = CliHead::guard(dir, &[7u8; 32]).unwrap();
        assert_eq!(
            guard
                .seen(
                    crate::identity::PINS_GUARD_SCOPE,
                    crate::identity::PINS_GUARD_ID
                )
                .unwrap(),
            1_790_000_000_000
        );
        assert!(!dir.join("identity-pins-revision").exists());
    }
}
