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

use kutup_crypto::primitives::{hash, Suite};
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
    /// No index to hold values to (the device is blocked on another history,
    /// so only its own guard holds them).
    pub fn uncovered(scope: &str) -> Self {
        Self {
            scope: scope.to_owned(),
            values: Vec::new(),
            covered: false,
            basis: None,
        }
    }

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
    fn dir(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }

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

    /// A revision read or written: refused when older than one seen, kept
    /// when newer. Read and written under the profile's lock, so two
    /// processes never lose each other's entries.
    pub fn accept(&self, scope: &str, id: &str, revision: u64) -> Result<()> {
        let _lock = lock_profile(self.dir())?;
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

/// The profile's lock (`account-head.lock`): one process at a time reads and
/// writes its head state and revision guard. Held until dropped.
fn lock_profile(dir: &Path) -> Result<std::fs::File> {
    let path = dir.join("account-head.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    file.lock()
        .with_context(|| format!("lock {}", path.display()))?;
    Ok(file)
}

/// Replaces `path` with `bytes` so that a crash leaves the old file or the new
/// one, never a torn one: a temporary of its own name, written and synced,
/// renamed over it, and the directory synced.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let temporary = path.with_file_name(format!(
        ".{name}.{}.{}.{}.tmp",
        std::process::id(),
        now_ms(),
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// What this profile keeps of the account head for one incarnation: the
/// sealed `LocalHeadStateV1` file, read and changed only under the profile's
/// lock.
pub(crate) struct StateStore {
    keys: HeadKeys,
    binding: String,
    incarnation: String,
    dir: PathBuf,
}

impl StateStore {
    pub(crate) fn new(
        master_key: &[u8; 32],
        binding: &str,
        incarnation: &str,
        dir: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            keys: HeadKeys::derive(master_key)?,
            binding: binding.to_owned(),
            incarnation: incarnation.to_owned(),
            dir,
        })
    }

    fn path(&self) -> Result<PathBuf> {
        Ok(self.dir.join(format!(
            "account-head-{}",
            self.keys.local_state_name(&self.incarnation)?
        )))
    }

    /// This device's state (under the lock briefly).
    pub(crate) fn load(&self) -> Result<LocalHeadStateV1> {
        let _lock = lock_profile(&self.dir)?;
        self.load_locked()
    }

    /// With the lock held. None stored: a fresh state. One that does not open
    /// is never dropped silently: it is kept aside, a warning says so, and the
    /// fresh state records why it started over.
    fn load_locked(&self) -> Result<LocalHeadStateV1> {
        let path = self.path()?;
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LocalHeadStateV1::new(&self.incarnation)?)
            }
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let opened = STANDARD.decode(text.trim()).ok().and_then(|sealed| {
            account_head::open_local_state(&self.keys, &self.binding, &self.incarnation, &sealed)
                .ok()
        });
        if let Some(state) = opened {
            return Ok(state);
        }
        let aside = path.with_file_name(format!(
            "{}.corrupt-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("account-head"),
            now_ms()
        ));
        std::fs::rename(&path, &aside).with_context(|| format!("keep {} aside", path.display()))?;
        eprintln!(
            "warning: this device's record of the account's history ({}) could not be read; it is kept as {}. \
             This device starts over and trusts the server's current history.",
            path.display(),
            aside.display()
        );
        let fresh = LocalHeadStateV1::new(&self.incarnation)?.starting_over("unreadable");
        self.save_locked(&fresh)?;
        Ok(fresh)
    }

    fn save_locked(&self, state: &LocalHeadStateV1) -> Result<()> {
        let sealed = account_head::seal_local_state(&self.keys, &self.binding, state)?;
        write_private(&self.path()?, STANDARD.encode(sealed).as_bytes())
    }

    /// Changes the state under the lock, read fresh inside it: `change`
    /// returns whether it changed anything (then it is saved). Another
    /// process's change made meanwhile is never overwritten by an older copy.
    pub(crate) fn update<T>(
        &self,
        change: impl FnOnce(&mut LocalHeadStateV1) -> Result<(bool, T)>,
    ) -> Result<T> {
        let _lock = lock_profile(&self.dir)?;
        let mut state = self.load_locked()?;
        let (changed, out) = change(&mut state)?;
        if changed {
            self.save_locked(&state)?;
        }
        Ok(out)
    }
}

/// The account head for one signed-in profile.
pub struct CliHead<'a> {
    client: &'a Client,
    store: StateStore,
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
    /// Why this device last started over, when it was not a first use
    /// (`unreadable`: its stored record did not open, and was kept aside).
    pub started_over: Option<String>,
}

impl<'a> CliHead<'a> {
    pub fn open(
        client: &'a Client,
        master_key: &[u8; 32],
        binding: &str,
        incarnation: &str,
        dir: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            client,
            store: StateStore::new(master_key, binding, incarnation, dir)?,
            verified: None,
            blocked: None,
        })
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
                    // The old file goes only once the guard holds it (written
                    // and synced); a failure keeps it for the next run.
                    guard
                        .accept(
                            crate::identity::PINS_GUARD_SCOPE,
                            crate::identity::PINS_GUARD_ID,
                            revision,
                        )
                        .context("taking over identity-pins-revision")?;
                }
            }
            std::fs::remove_file(&old).with_context(|| format!("remove {}", old.display()))?;
        }
        Ok(guard)
    }

    fn load(&self) -> Result<LocalHeadStateV1> {
        self.store.load()
    }

    /// The verified head becomes the anchor, never moving it back.
    fn advance(&self) -> Result<()> {
        if let Some(verified) = &self.verified {
            self.store
                .update(|state| Ok((state.advance(verified, now_ms()), ())))?;
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
            Some(anchor) if hex::encode(hash(Suite::V1, &current)) != anchor.digest => self
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
            &self.store.keys,
            &self.store.binding,
            &self.store.incarnation,
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
                    &self.store.keys,
                    &self.store.binding,
                    &self.store.incarnation,
                    &anchor,
                    &current,
                    segment.as_deref(),
                    false,
                    now_ms(),
                )?;
                // Only from the anchor it was decided on: another process
                // that moved it meanwhile is not overwritten.
                self.store.update(|state| {
                    if state.anchor.as_ref() != Some(&anchor) {
                        return Ok((false, ()));
                    }
                    state.reanchored(&record);
                    Ok((true, ()))
                })?;
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
                match account_head::check_index(&self.store.keys, verified, scope, &record.values) {
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
            let writer = self.store.keys.writer(&self.load()?.device_id)?;
            let Some(change) = edit(&index, attempt)? else {
                return Ok(None);
            };
            if let Some(basis) = &index.basis {
                let entry = self.store.keys.scope_digest(scope, &index.values)?;
                let (first, verified) = account_head::first(
                    &self.store.keys,
                    &self.store.binding,
                    &self.store.incarnation,
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
            let entry = self.store.keys.scope_digest(scope, &values)?;
            let verified = self.verified.as_ref().context("no verified account head")?;
            let next = verified.next(&writer, vec![entry])?;
            let sealed = account_head::seal(&self.store.keys, &self.store.binding, &next)?;
            match (change.send)(&STANDARD.encode(&sealed))? {
                Some(done) => {
                    let committed =
                        verified.committed(&self.store.keys, &self.store.binding, &sealed)?;
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
        let state = self.load()?;
        let anchor = state.anchor.as_ref().map(|anchor| anchor.sequence);
        let started_over = state.started_over.clone().or_else(|| {
            state.log.iter().rev().find_map(|event| match event {
                account_head::LocalHeadEvent::StartedFresh { reason, .. } => reason.clone(),
                _ => None,
            })
        });
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
            started_over,
        })
    }

    /// Continues with the server's data after a rollback or fork the person
    /// confirmed (a restore from a backup looks the same), logged locally.
    /// Returns false when there was nothing to continue from.
    pub fn continue_with_server(&mut self) -> Result<bool> {
        let Some(blocked) = self.blocked.take() else {
            return Ok(false);
        };
        // Decided and recorded under the lock, on the anchor as stored now.
        let store = &self.store;
        let verified = store.update(|state| match &blocked {
            Blocked::NoHead => Ok((state.forgotten(now_ms()), None)),
            Blocked::On { current, segment } => {
                let anchor = state
                    .anchor
                    .clone()
                    .context("nothing remembered to move from")?;
                let (record, verified) = account_head::reanchor(
                    &store.keys,
                    &store.binding,
                    &store.incarnation,
                    &anchor,
                    current,
                    segment.as_deref(),
                    true,
                    now_ms(),
                )?;
                state.reanchored(&record);
                Ok((true, Some(verified)))
            }
        })?;
        self.verified = verified;
        Ok(true)
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

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const INCARNATION: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// `n` verified heads of one account, each on the one before.
    fn verified_chain(n: usize) -> Vec<VerifiedHead> {
        let keys = HeadKeys::derive(&[7u8; 32]).unwrap();
        let writer = keys.writer("device-a").unwrap();
        let entry = |i: u64| {
            keys.scope_digest("pins", &[("pins".to_string(), i)])
                .unwrap()
        };
        let (_, first) =
            account_head::first(&keys, BINDING, INCARNATION, &writer, vec![entry(1)]).unwrap();
        let mut heads = vec![first];
        for i in 2..=n as u64 {
            let last = heads.last().unwrap();
            let next = last.next(&writer, vec![entry(i)]).unwrap();
            let sealed = account_head::seal(&keys, BINDING, &next).unwrap();
            heads.push(last.committed(&keys, BINDING, &sealed).unwrap());
        }
        heads
    }

    fn store(dir: &Path) -> StateStore {
        StateStore::new(&[7u8; 32], BINDING, INCARNATION, dir.to_path_buf()).unwrap()
    }

    #[test]
    fn two_processes_advancing_at_once_keep_the_highest_anchor_and_every_guard_entry() {
        let temp = tempfile::tempdir().unwrap();
        let heads = std::sync::Arc::new(verified_chain(40));
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let dir = temp.path().to_path_buf();
                let heads = heads.clone();
                std::thread::spawn(move || {
                    // Each its own handles, as another process would have.
                    let store = store(&dir);
                    let guard = CliHead::guard(&dir, &[7u8; 32]).unwrap();
                    for (i, head) in heads.iter().enumerate() {
                        // Out of order across threads: some go back to older heads.
                        let pick = if (i + t) % 3 == 0 {
                            &heads[i / 2]
                        } else {
                            head
                        };
                        store
                            .update(|state| Ok((state.advance(pick, 1), ())))
                            .unwrap();
                        guard
                            .accept("s", &format!("{t}-{i}"), 1 + i as u64)
                            .unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let state = store(temp.path()).load().unwrap();
        assert_eq!(
            state.anchor.unwrap().sequence,
            40,
            "the anchor never moved back"
        );
        let guard = CliHead::guard(temp.path(), &[7u8; 32]).unwrap();
        for t in 0..4 {
            for i in 0..40 {
                assert_eq!(guard.seen("s", &format!("{t}-{i}")).unwrap(), 1 + i as u64);
            }
        }
        // Nothing half-written left behind.
        let leftovers: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn an_unreadable_state_is_kept_aside_and_the_start_over_recorded() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(temp.path());
        let path = store.path().unwrap();
        std::fs::write(&path, "not a sealed state").unwrap();
        let state = store.load().unwrap();
        assert_eq!(state.anchor, None);
        assert_eq!(state.started_over.as_deref(), Some("unreadable"));
        let aside: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1);
        assert_eq!(
            std::fs::read_to_string(aside[0].path()).unwrap(),
            "not a sealed state"
        );
        // The reason is stored, and goes with the first anchor into the log.
        let heads = verified_chain(1);
        store
            .update(|state| Ok((state.advance(&heads[0], 5), ())))
            .unwrap();
        let state = store.load().unwrap();
        assert!(matches!(
            state.log.as_slice(),
            [account_head::LocalHeadEvent::StartedFresh { reason: Some(reason), .. }] if reason == "unreadable"
        ));
    }

    #[test]
    fn a_failed_takeover_keeps_the_old_revision_file() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        std::fs::write(dir.join("identity-pins-revision"), "1790000000000").unwrap();
        // The guard's file cannot be written (a directory stands in its place).
        std::fs::create_dir(dir.join("revisions.json")).unwrap();
        assert!(CliHead::guard(dir, &[7u8; 32]).is_err());
        assert!(dir.join("identity-pins-revision").exists());
    }
}
