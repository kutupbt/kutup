//! The account's group list (docs/plans/pairwise-groups.md §5), as Signal
//! keeps each group's master key in its storage service: one sealed entry per
//! group in the account head's `chatGroups` scope, so every device of the
//! account knows its groups.
//!
//! - An entry holds what another device needs to take the group up: its key,
//!   its home, the join epoch this account's pseudonym is derived at, and the
//!   revision and chain head verified when it was written. Its id is an HMAC of the group id under a
//!   key of the account's, and every sealed entry has one size
//!   (`kutup_crypto::chat_group_list`).
//! - Writes are rare and spread out, so the account's server can't line
//!   co-members up by when they write: an entry is written only when the
//!   account joins a group and when it leaves it (or is removed, or the group
//!   ends), each a random 0–10 minutes later, together with whatever else is
//!   due then. What is due is kept with the group, so it survives a reload;
//!   a device flushes it before it signs out.
//! - A device reads the list when it starts and every so often: a group it
//!   doesn't know is taken up (its whole state; its own entry is the
//!   account's, signed by its authority, so nothing is signed again); one
//!   another device left is left here too.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group::{decode_group_id, encode, GroupListEntryV1, GroupListStatus};
use kutup_crypto::chat_group_list::{self, GroupListKey};
use rand::{CryptoRng, Rng};
use rand_core::{OsRng, RngCore as _};

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{GroupRecordV1, GroupStatus, SecretText};
use crate::group_engine::GroupSync;

/// A due write waits a random time up to this long (§5).
const WRITE_DELAY_MAX_MS: i64 = 10 * 60 * 1000;

/// The list is read again at most this often by a running device.
const READ_EVERY_MS: i64 = 10 * 60 * 1000;

/// One entry as the list holds it: its revision and what it says.
#[derive(Debug, Clone, Copy)]
struct Listed {
    revision: u64,
    status: GroupListStatus,
    join_epoch: u32,
}

/// The list's keys and what this device knows of it.
pub(crate) struct GroupListSync {
    key: GroupListKey,
    binding: String,
    listed: BTreeMap<String, Listed>,
    read_at_ms: i64,
}

impl GroupListSync {
    fn entry_id(&self, group_id: &str) -> Result<String> {
        let group = decode_group_id(group_id).map_err(ChatError::Invalid)?;
        Ok(chat_group_list::encode_entry_id(&self.key.entry_id(&group)))
    }
}

/// What the list should say of a group in `status`: nothing for one this
/// account is only invited to or asking to join.
fn list_status(status: &GroupStatus) -> Option<GroupListStatus> {
    match status {
        GroupStatus::Member => Some(GroupListStatus::Member),
        GroupStatus::Gone => Some(GroupListStatus::Gone),
        GroupStatus::Invited { .. } | GroupStatus::Requesting => None,
    }
}

impl Engine {
    /// Keeps this account's groups in its group list, under keys from its
    /// `master_key`, bound to its key `binding`; and takes the account's
    /// group keys (its self-authority, its pseudonyms) from the same key.
    pub fn enable_group_list(&mut self, master_key: &[u8; 32], binding: &str) -> Result<()> {
        kutup_crypto::key_binding::check(binding)
            .map_err(|_| ChatError::Invalid("the account's key binding is invalid".into()))?;
        self.group_keys = Some(crate::group::GroupAccountKeys::derive(master_key)?);
        self.group_list = Some(GroupListSync {
            key: GroupListKey::derive(master_key),
            binding: binding.to_string(),
            listed: BTreeMap::new(),
            read_at_ms: 0,
        });
        Ok(())
    }

    /// The entry `record` should have in the list, if any: a group this
    /// account is in, or one it was in (gone).
    fn list_entry_of(record: &GroupRecordV1) -> Result<Option<GroupListEntryV1>> {
        let Some(status) = list_status(&record.status) else {
            return Ok(None);
        };
        let Some((state, head)) = record
            .verified()
            .map_err(|error| ChatError::Invalid(error.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(GroupListEntryV1 {
            version: kutup_chat_proto::group::GROUP_FORMAT_VERSION,
            group_id: record.group_id.clone(),
            master_key: record.master_key.0.clone(),
            home: record.home.clone(),
            join_epoch: record.join_epoch,
            status,
            verified_revision: state.revision,
            chain_hash: encode(&head),
        }))
    }

    /// Reads the list when this device hasn't this run (best effort): what
    /// a join's epoch must go past, after a reload too.
    pub(crate) async fn ensure_group_list_read(&mut self) {
        if self.group_list.is_some() && !self.group_list_read() {
            let _ = self.read_group_list().await;
        }
    }

    /// Whether this device read the list this run.
    pub(crate) fn group_list_read(&self) -> bool {
        self.group_list
            .as_ref()
            .is_some_and(|list| list.read_at_ms > 0)
    }

    /// What the list last said of `group_id` (as this device read or wrote
    /// it): its status and the join epoch, which a new join goes past.
    pub(crate) fn listed_join(&self, group_id: &str) -> Option<(GroupListStatus, u32)> {
        let list = self.group_list.as_ref()?;
        let id = list.entry_id(group_id).ok()?;
        list.listed
            .get(&id)
            .map(|listed| (listed.status, listed.join_epoch))
    }

    /// Makes `group_id`'s entry due when the list doesn't say what the group
    /// is now (joined, or left): at a random moment in the next ten minutes.
    /// Nothing for any other change.
    pub(crate) async fn schedule_group_entry(&mut self, group_id: &str) -> Result<()> {
        if self.group_list.is_none() {
            return Ok(());
        }
        let mut record = self.load_group_record(group_id).await?;
        let Some(status) = list_status(&record.status) else {
            return Ok(());
        };
        if record.listed_status == Some(status) || record.list_due_at_ms.is_some() {
            return Ok(());
        }
        let delay = i64::from(OsRng.next_u32()) % (WRITE_DELAY_MAX_MS + 1);
        record.list_due_at_ms = Some(self.now_ms() + delay);
        self.save_group(&record).await
    }

    /// Writes the entries that are due (all of them with `all`, before this
    /// device signs out), together. The list is read first: an entry that
    /// already says the same is not written again. Best effort for callers:
    /// what fails stays due.
    pub async fn flush_group_list(&mut self, all: bool) -> Result<usize> {
        if self.group_list.is_none() {
            return Ok(0);
        }
        let now = self.now_ms();
        let due: Vec<GroupRecordV1> = self
            .session
            .db()
            .list_groups()
            .await?
            .into_iter()
            .filter(|record| record.list_due_at_ms.is_some_and(|at| all || at <= now))
            .collect();
        if due.is_empty() {
            return Ok(0);
        }
        self.read_group_list().await?;
        let mut written = 0;
        for mut record in due {
            let Some(entry) = Self::list_entry_of(&record)? else {
                record.list_due_at_ms = None;
                self.save_group(&record).await?;
                continue;
            };
            let list = self.group_list.as_ref().expect("checked above");
            let id = list.entry_id(&record.group_id)?;
            if list.listed.get(&id).map(|listed| listed.status) != Some(entry.status) {
                self.write_group_entry(&id, &entry).await?;
                written += 1;
            }
            record.listed_status = Some(entry.status);
            record.list_due_at_ms = None;
            self.save_group(&record).await?;
        }
        Ok(written)
    }

    /// Writes one entry over the revision the list has, once more over
    /// another device's if it wrote first.
    async fn write_group_entry(&mut self, id: &str, entry: &GroupListEntryV1) -> Result<()> {
        let plain = entry.canonical_bytes().map_err(ChatError::Invalid)?;
        let entry_id = chat_group_list::decode_entry_id(id)
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        for _ in 0..2 {
            let list = self.group_list.as_ref().expect("enabled by the caller");
            let base = list.listed.get(id).map_or(0, |listed| listed.revision);
            let revision = base + 1;
            let sealed = list
                .key
                .seal(&list.binding, &entry_id, revision, &plain)
                .map_err(|error| ChatError::Invalid(error.to_string()))?;
            let envelope = STANDARD.encode(sealed);
            let transport = std::rc::Rc::clone(&self.transport);
            if transport
                .store_group_entry(id, base, revision, &envelope)
                .await?
            {
                let list = self.group_list.as_mut().expect("enabled by the caller");
                list.listed.insert(
                    id.to_string(),
                    Listed {
                        revision,
                        status: entry.status,
                        join_epoch: entry.join_epoch,
                    },
                );
                return Ok(());
            }
            // Another device wrote first: its revision, then ours on top.
            self.read_group_list().await?;
        }
        Err(ChatError::Transport(
            "the group list kept changing under this write".into(),
        ))
    }

    /// Reads the list: what each entry says, opened (an entry that doesn't
    /// open, or is filed under another group's id, is skipped).
    async fn read_group_list(&mut self) -> Result<Vec<GroupListEntryV1>> {
        let transport = std::rc::Rc::clone(&self.transport);
        let items = transport.fetch_group_list().await?;
        let now = self.now_ms();
        let Some(list) = self.group_list.as_mut() else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        for item in items {
            let Ok(id) = chat_group_list::decode_entry_id(&item.id) else {
                continue;
            };
            let Ok(sealed) = STANDARD.decode(&item.envelope) else {
                continue;
            };
            // The revision is the one the entry was sealed at, whatever the
            // server says.
            let Ok(opened) = list.key.open(&list.binding, &id, &sealed) else {
                continue;
            };
            let Ok(entry) = GroupListEntryV1::from_canonical_bytes(&opened.plain) else {
                continue;
            };
            if list.entry_id(&entry.group_id).ok().as_deref() != Some(item.id.as_str()) {
                continue;
            }
            list.listed.insert(
                item.id,
                Listed {
                    revision: opened.revision,
                    status: entry.status,
                    join_epoch: entry.join_epoch,
                },
            );
            entries.push(entry);
        }
        list.read_at_ms = now;
        Ok(entries)
    }

    /// Reads the list and follows it: takes up the groups this device
    /// doesn't know, leaves here the ones another device left, raises each
    /// group's lowest acceptable state, and writes a group this device knows
    /// that the list lacks (one another device joined and couldn't write
    /// before it went). Returns the groups taken up.
    pub async fn sync_group_list<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<String>> {
        if self.group_list.is_none() {
            return Ok(Vec::new());
        }
        let entries = self.read_group_list().await?;
        let mut taken_up = Vec::new();
        let mut listed_groups = std::collections::BTreeSet::new();
        for entry in entries {
            listed_groups.insert(entry.group_id.clone());
            match self.session.db().load_group(&entry.group_id).await? {
                None if entry.status == GroupListStatus::Member => {
                    let group = decode_group_id(&entry.group_id).map_err(ChatError::Invalid)?;
                    let pseudonym = self
                        .group_keys()?
                        .pseudonyms
                        .pseudonym(&group, entry.join_epoch);
                    let record = GroupRecordV1 {
                        version: kutup_chat_proto::group::GROUP_FORMAT_VERSION,
                        group_id: entry.group_id.clone(),
                        master_key: SecretText(entry.master_key.clone()),
                        home: entry.home.clone(),
                        pseudonym_seed: SecretText(encode(pseudonym.seed())),
                        status: GroupStatus::Member,
                        min_revision: entry.verified_revision,
                        state: None,
                        head: None,
                        notary_sequence: None,
                        gateway: Default::default(),
                        not_found_since_ms: None,
                        sender_book: None,
                        synced_at_ms: None,
                        fork_at_revision: None,
                        fork_sender: None,
                        known_since_ms: Some(self.now_ms()),
                        listed_status: Some(GroupListStatus::Member),
                        list_due_at_ms: None,
                        join_epoch: entry.join_epoch,
                    };
                    self.save_group(&record).await?;
                    // Its state, and this device's binding where needed; a
                    // home that can't be reached now is tried at the next
                    // opening.
                    let _ = self.maintain_group(&entry.group_id, rng).await;
                    taken_up.push(entry.group_id.clone());
                }
                // A group it left, never known here: its history (from the
                // backup) stays history.
                None => {}
                Some(mut record) => {
                    let mut changed = record.listed_status != Some(entry.status);
                    record.listed_status = Some(entry.status);
                    if entry.status == GroupListStatus::Gone && record.status == GroupStatus::Member
                    {
                        record.status = GroupStatus::Gone;
                        changed = true;
                    }
                    if record.min_revision < entry.verified_revision {
                        record.min_revision = entry.verified_revision;
                        changed = true;
                    }
                    if changed {
                        self.save_group(&record).await?;
                    }
                    // This device says otherwise (it joined or left since):
                    // its write follows, as any.
                    let _ = self.schedule_group_entry(&entry.group_id).await;
                }
            }
        }
        // Groups this device knows that the list lacks.
        for mut record in self.session.db().list_groups().await? {
            if listed_groups.contains(&record.group_id) || list_status(&record.status).is_none() {
                continue;
            }
            if record.listed_status.take().is_some() {
                self.save_group(&record).await?;
            }
            let _ = self.schedule_group_entry(&record.group_id).await;
        }
        Ok(taken_up)
    }

    /// [`Self::sync_group_list`] when the last read is a while ago (a running
    /// device's periodic look), then the writes that are due.
    pub async fn sync_group_list_if_due<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<String>> {
        let due = self
            .group_list
            .as_ref()
            .is_some_and(|list| self.now_ms().saturating_sub(list.read_at_ms) >= READ_EVERY_MS);
        let taken_up = if due {
            self.sync_group_list(rng).await?
        } else {
            Vec::new()
        };
        let _ = self.flush_group_list(false).await;
        Ok(taken_up)
    }

    /// After a catch-up or a change: a join or a leave makes the entry due.
    pub(crate) async fn list_after(&mut self, group_id: &str, sync: &GroupSync) {
        if matches!(sync, GroupSync::Current { .. } | GroupSync::Gone) {
            let _ = self.schedule_group_entry(group_id).await;
        }
    }
}
