//! The account's group list (docs/plans/pairwise-groups.md §5), as Signal
//! keeps each group's master key in its storage service: one sealed entry per
//! group in the account head's `chatGroups` scope, so every device of the
//! account knows its groups.
//!
//! - An entry holds what another device needs to take the group up: its key,
//!   its home, this account's pseudonym, and the newest state verified (no
//!   device then takes an older one). Its id is an HMAC of the group id under
//!   a key of the account's, so lists can't be matched across accounts.
//! - A device writes its entry when it joins, leaves or is removed, and when
//!   the verified revision moved on, at most once a minute.
//! - A device reads the list when it starts and every so often: a group it
//!   doesn't know is taken up (its whole state, then its own entry signed
//!   again by this device when the old one's device left the account); one
//!   another device left is left here too.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use kutup_chat_proto::group::{decode_group_id, encode, GroupListEntryV1, GroupListStatus};
use kutup_crypto::chat_group::{GroupListKey, LIST_ENTRY_ID_LEN};
use rand::{CryptoRng, Rng};

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{GroupRecordV1, GroupStatus, SecretText};
use crate::group_engine::GroupSync;

/// A verified revision is written at most this often (status changes at
/// once).
const REVISION_WRITE_EVERY_MS: i64 = 60 * 1000;

/// The list is read again at most this often by a running device.
const READ_EVERY_MS: i64 = 10 * 60 * 1000;

/// What this device last wrote or read of one entry.
#[derive(Debug, Clone, Copy)]
struct Listed {
    revision: u64,
    status: GroupListStatus,
    verified_revision: u64,
    at_ms: i64,
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
        Ok(URL_SAFE_NO_PAD.encode(self.key.entry_id(&group)))
    }
}

fn decode_entry_id(id: &str) -> Result<[u8; LIST_ENTRY_ID_LEN]> {
    URL_SAFE_NO_PAD
        .decode(id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ChatError::Invalid("a group list entry id isn't 32 bytes".into()))
}

impl Engine {
    /// Keeps this account's groups in its group list, under keys from its
    /// `master_key`, bound to its key `binding`.
    pub fn enable_group_list(&mut self, master_key: &[u8; 32], binding: &str) -> Result<()> {
        kutup_crypto::key_binding::check(binding)
            .map_err(|_| ChatError::Invalid("the account's key binding is invalid".into()))?;
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
        let status = match record.status {
            GroupStatus::Member => GroupListStatus::Member,
            GroupStatus::Gone => GroupListStatus::Gone,
            GroupStatus::Invited { .. } | GroupStatus::Requesting => return Ok(None),
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
            pseudonym_seed: record.pseudonym_seed.0.clone(),
            status,
            verified_revision: state.revision,
            chain_hash: encode(&head),
        }))
    }

    /// Writes `group_id`'s entry when its status changed, or its verified
    /// revision moved on and the last write is a minute old. Best effort for
    /// callers: a failed write is made again at the next chance.
    pub(crate) async fn publish_group_entry(&mut self, group_id: &str) -> Result<()> {
        let Some(list) = self.group_list.as_ref() else {
            return Ok(());
        };
        let record = self.load_group_record(group_id).await?;
        let Some(entry) = Self::list_entry_of(&record)? else {
            return Ok(());
        };
        let id = list.entry_id(group_id)?;
        let now = self.now_ms();
        let known = list.listed.get(&id).copied();
        if let Some(known) = known {
            let unchanged = known.status == entry.status
                && (entry.verified_revision <= known.verified_revision
                    || now.saturating_sub(known.at_ms) < REVISION_WRITE_EVERY_MS);
            if unchanged {
                return Ok(());
            }
        } else if entry.status == GroupListStatus::Gone {
            // Never listed here: read the list first, so a gone group isn't
            // written over an entry another device holds.
            self.read_group_list().await?;
        }
        let plain = entry.canonical_bytes().map_err(ChatError::Invalid)?;
        for _ in 0..2 {
            let list = self.group_list.as_ref().expect("checked above");
            let base = match list.listed.get(&id) {
                Some(listed) => listed.revision,
                None => 0,
            };
            let revision = base + 1;
            let sealed = list
                .key
                .seal(&list.binding, &decode_entry_id(&id)?, revision, &plain)
                .map_err(|error| ChatError::Invalid(error.to_string()))?;
            let envelope = STANDARD.encode(sealed);
            let transport = std::rc::Rc::clone(&self.transport);
            if transport
                .store_group_entry(&id, base, revision, &envelope)
                .await?
            {
                let list = self.group_list.as_mut().expect("checked above");
                list.listed.insert(
                    id.clone(),
                    Listed {
                        revision,
                        status: entry.status,
                        verified_revision: entry.verified_revision,
                        at_ms: now,
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
    /// open is skipped).
    async fn read_group_list(&mut self) -> Result<Vec<GroupListEntryV1>> {
        let transport = std::rc::Rc::clone(&self.transport);
        let items = transport.fetch_group_list().await?;
        let now = self.now_ms();
        let Some(list) = self.group_list.as_mut() else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        for item in items {
            let Ok(id) = decode_entry_id(&item.id) else {
                continue;
            };
            let Ok(sealed) = STANDARD.decode(&item.envelope) else {
                continue;
            };
            let Ok(plain) = list.key.open(&list.binding, &id, item.revision, &sealed) else {
                continue;
            };
            let Ok(entry) = GroupListEntryV1::from_canonical_bytes(&plain) else {
                continue;
            };
            // An entry filed under another group's id is the server's doing.
            if list.entry_id(&entry.group_id).ok().as_deref() != Some(item.id.as_str()) {
                continue;
            }
            list.listed.insert(
                item.id,
                Listed {
                    revision: item.revision,
                    status: entry.status,
                    verified_revision: entry.verified_revision,
                    at_ms: now,
                },
            );
            entries.push(entry);
        }
        list.read_at_ms = now;
        Ok(entries)
    }

    /// Reads the list and follows it: takes up the groups this device
    /// doesn't know, leaves here the ones another device left, and raises
    /// each group's lowest acceptable state. Returns the groups taken up.
    pub async fn sync_group_list<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<String>> {
        if self.group_list.is_none() {
            return Ok(Vec::new());
        }
        let entries = self.read_group_list().await?;
        let mut taken_up = Vec::new();
        for entry in entries {
            match self.session.db().load_group(&entry.group_id).await? {
                None if entry.status == GroupListStatus::Member => {
                    let record = GroupRecordV1 {
                        version: kutup_chat_proto::group::GROUP_FORMAT_VERSION,
                        group_id: entry.group_id.clone(),
                        master_key: SecretText(entry.master_key.clone()),
                        home: entry.home.clone(),
                        pseudonym_seed: SecretText(entry.pseudonym_seed.clone()),
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
                    let mut changed = false;
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
                }
            }
        }
        Ok(taken_up)
    }

    /// [`Self::sync_group_list`] when the last read is a while ago (a running
    /// device's periodic look).
    pub async fn sync_group_list_if_due<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<String>> {
        let due = self
            .group_list
            .as_ref()
            .is_some_and(|list| self.now_ms().saturating_sub(list.read_at_ms) >= READ_EVERY_MS);
        if !due {
            return Ok(Vec::new());
        }
        self.sync_group_list(rng).await
    }

    /// After a catch-up or a change: the list follows (best effort).
    pub(crate) async fn list_after(&mut self, group_id: &str, sync: &GroupSync) {
        if matches!(sync, GroupSync::Current { .. } | GroupSync::Gone) {
            let _ = self.publish_group_entry(group_id).await;
        }
    }
}
