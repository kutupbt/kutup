//! The account's Chat contact list (docs/plans/chat-contacts-sync.md): who
//! it accepted, asked, rejected or blocked, sealed in the account head's
//! `chatContacts` scope, so a device that lost everything restores them, as
//! Signal's storage service keeps `ContactRecord`s.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::contact_list::{
    ChatContactEntryV1, ContactEntryControlV1, CONTACT_ENTRY_VERSION,
};
use kutup_chat_proto::ContactState;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::chat_contact_list::{self, ContactListKey};
use rand_core::{OsRng, RngCore as _};

use crate::db::ContactRecord;
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::transport::ContactListWrite;

/// The list is read again at most this often by a running device.
const READ_EVERY_MS: i64 = 5 * 60 * 1000;

/// When a block is written (the user's decision: one platform setting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTiming {
    /// At once (the web): a blocked person stays blocked if the browser's
    /// data is lost a minute later.
    Immediate,
    /// With the same random delay as any other change (Signal's storage
    /// sync timing, for the native apps).
    Debounced,
}

/// How this platform times its contact list writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactListTiming {
    pub block: BlockTiming,
}

/// One entry as the list holds it: its write revision, and what it says
/// (fields of a later version included, to be written back as they came).
#[derive(Debug, Clone)]
struct Listed {
    revision: u64,
    entry: ChatContactEntryV1,
}

impl Listed {
    fn order(&self) -> (u64, bool, u32) {
        contact_order(
            self.entry.control.revision,
            self.entry.state,
            self.entry.control.source_device_id,
        )
    }
}

/// The list's keys and what this device knows of it.
pub(crate) struct ContactListSync {
    key: ContactListKey,
    binding: String,
    timing: ContactListTiming,
    listed: BTreeMap<String, Listed>,
    read_at_ms: i64,
    /// The last write found the list full, with nothing it may evict.
    full: bool,
}

/// What a flush did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContactListFlush {
    pub written: usize,
    /// Entries still due because the list is full (a block among them stays
    /// due, never dropped): the person is told.
    pub refused_full: usize,
}

/// What one contact's entry needs, against what the list says.
enum Step {
    /// The list says it already.
    Nothing,
    /// The list is newer: take it here.
    Take(Box<ContactRecord>, Option<Vec<u8>>),
    /// This device is newer: write it.
    Write(Box<ChatContactEntryV1>),
}

/// A due write waits a random time up to this long, so two accounts that
/// accept each other don't write at the same moment (the plan's "When it is
/// written").
pub(crate) const WRITE_DELAY_MAX_MS: i64 = 10 * 60 * 1000;

/// When `contact`'s entry is due after a change: an earlier due moment
/// stands, else a random one in the next ten minutes. Never for an incoming
/// request: that is the other person's, not this account's choice.
pub(crate) fn due_after_change(contact: &ContactRecord, now_ms: i64) -> Option<i64> {
    if contact.state == ContactState::PendingIncoming {
        return contact.list_due_at_ms;
    }
    Some(contact.list_due_at_ms.unwrap_or_else(|| fresh_due(now_ms)))
}

/// A profile-key-only change waits longer, up to this: it rides along with
/// the next write due anyway.
pub(crate) const LAZY_DELAY_MAX_MS: i64 = 60 * 60 * 1000;

/// A random moment within [`LAZY_DELAY_MAX_MS`].
pub(crate) fn lazy_due(now_ms: i64) -> i64 {
    now_ms + i64::from(OsRng.next_u32()) % (LAZY_DELAY_MAX_MS + 1)
}

/// A random moment in the next [`WRITE_DELAY_MAX_MS`].
pub(crate) fn fresh_due(now_ms: i64) -> i64 {
    now_ms + i64::from(OsRng.next_u32()) % (WRITE_DELAY_MAX_MS + 1)
}

/// The one order of contact states, for the Note-to-Self contact control and
/// the list alike: the higher wins. At an equal revision a block wins,
/// whatever device wrote the other, so an older accept never undoes a block.
pub(crate) fn contact_order(
    revision: u64,
    state: ContactState,
    source_device_id: u32,
) -> (u64, bool, u32) {
    (revision, state == ContactState::Blocked, source_device_id)
}

/// A local record's place in [`contact_order`].
pub(crate) fn order_of(contact: &ContactRecord) -> (u64, bool, u32) {
    contact_order(contact.revision, contact.state, contact.source_device_id)
}

fn invalid(error: impl std::fmt::Display) -> ChatError {
    ChatError::Invalid(error.to_string())
}

/// The account a contact record is about.
fn account_of(peer: &str) -> Result<AccountRef> {
    crate::address::parse_account(peer)
}

impl ContactListSync {
    fn entry_id(&self, account: &AccountRef) -> String {
        chat_contact_list::encode_entry_id(&self.key.entry_id(account))
    }
}

/// The entry a local contact makes, over what the list holds for it (its
/// unknown fields kept).
fn entry_of(
    contact: &ContactRecord,
    account: AccountRef,
    profile_key: Option<&[u8]>,
    listed: Option<&Listed>,
) -> ChatContactEntryV1 {
    let blocked = contact.state == ContactState::Blocked;
    let blocked_at_ms = blocked.then(|| {
        listed
            .filter(|listed| listed.entry.state == ContactState::Blocked)
            .and_then(|listed| listed.entry.blocked_at_ms)
            .unwrap_or(contact.updated_at_ms)
    });
    ChatContactEntryV1 {
        version: CONTACT_ENTRY_VERSION,
        account,
        state: contact.state,
        previous_state: if blocked { contact.previous_state } else { None },
        blocked_at_ms,
        profile_key: profile_key
            .map(|key| STANDARD.encode(key))
            .or_else(|| listed.and_then(|listed| listed.entry.profile_key.clone())),
        control: ContactEntryControlV1 {
            revision: contact.revision,
            source_device_id: contact.source_device_id,
            updated_at_ms: contact.updated_at_ms,
        },
        unknown: listed.map(|listed| listed.entry.unknown.clone()).unwrap_or_default(),
    }
}

impl Engine {
    /// Keeps this account's contacts in its contact list, under keys from its
    /// `master_key`, bound to its key `binding`, timed as `timing` says.
    pub fn enable_contact_list(
        &mut self,
        master_key: &[u8; 32],
        binding: &str,
        timing: ContactListTiming,
    ) -> Result<()> {
        kutup_crypto::key_binding::check(binding)
            .map_err(|_| ChatError::Invalid("the account's key binding is invalid".into()))?;
        self.contact_list = Some(ContactListSync {
            key: ContactListKey::derive(master_key),
            binding: binding.to_string(),
            timing,
            listed: BTreeMap::new(),
            read_at_ms: 0,
            full: false,
        });
        Ok(())
    }

    /// Whether this device read the list this run.
    pub(crate) fn contact_list_read(&self) -> bool {
        self.contact_list
            .as_ref()
            .is_some_and(|list| list.read_at_ms > 0)
    }

    /// Whether the list was found full with nothing it may evict: a change
    /// waits (a block too), and the person is told.
    pub fn contact_list_full(&self) -> bool {
        self.contact_list.as_ref().is_some_and(|list| list.full)
    }

    /// Reads the list: every entry that opens under its id, about the account
    /// that id is derived from (an entry filed under another contact's id is
    /// skipped).
    async fn read_contact_list(&mut self) -> Result<()> {
        let transport = std::rc::Rc::clone(&self.transport);
        let items = transport.fetch_contact_list().await?;
        let now = self.now_ms();
        let Some(list) = self.contact_list.as_mut() else {
            return Ok(());
        };
        let mut listed = BTreeMap::new();
        for item in items {
            let Ok(id) = chat_contact_list::decode_entry_id(&item.id) else {
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
            let Ok(entry) = ChatContactEntryV1::from_bytes(&opened.plain) else {
                continue;
            };
            if list.entry_id(&entry.account) != item.id {
                continue;
            }
            listed.insert(
                item.id,
                Listed {
                    revision: opened.revision,
                    entry,
                },
            );
        }
        list.listed = listed;
        list.read_at_ms = now;
        Ok(())
    }

    /// What `contact`'s entry needs against the list.
    async fn contact_step(&self, contact: &ContactRecord) -> Result<Step> {
        let list = self.contact_list.as_ref().expect("enabled by the caller");
        let account = account_of(&contact.peer)?;
        let listed = list.listed.get(&list.entry_id(&account));
        if let Some(listed) = listed {
            if listed.order() > order_of(contact) {
                return Ok(Step::Take(
                    Box::new(record_of(&contact.peer, &listed.entry)),
                    listed_profile_key(&listed.entry),
                ));
            }
        }
        // An incoming request is the other person's, never written (a
        // rejected person writing again leaves the entry "rejected").
        if contact.state == ContactState::PendingIncoming {
            return Ok(Step::Nothing);
        }
        let key = self
            .session
            .peer_profile(&contact.peer)
            .await?
            .map(|profile| profile.key);
        let entry = entry_of(contact, account, key.as_deref(), listed);
        let same = listed.is_some_and(|listed| {
            listed.order() == order_of(contact)
                && listed.entry.state == entry.state
                && listed.entry.previous_state == entry.previous_state
                && listed.entry.profile_key == entry.profile_key
        });
        Ok(if same {
            Step::Nothing
        } else {
            Step::Write(Box::new(entry))
        })
    }

    /// Writes the entries that are due (all of them with `all`, before this
    /// device signs out), or only `peer`'s (a block, written at once). The
    /// list is read first; a write another device beat is merged by the one
    /// order and written over its revision. What fails stays due.
    pub async fn flush_contact_list(&mut self, all: bool) -> Result<ContactListFlush> {
        self.flush_contacts(all, None).await
    }

    async fn flush_contacts(&mut self, all: bool, only: Option<&str>) -> Result<ContactListFlush> {
        let mut report = ContactListFlush::default();
        if self.contact_list.is_none() {
            return Ok(report);
        }
        let now = self.now_ms();
        let due: Vec<ContactRecord> = self
            .session
            .contacts()
            .await?
            .into_iter()
            .filter(|contact| match only {
                Some(peer) => contact.peer == peer,
                None => contact.list_due_at_ms.is_some_and(|at| all || at <= now),
            })
            .collect();
        if due.is_empty() {
            return Ok(report);
        }
        self.read_contact_list().await?;
        let mut full = false;
        for contact in due {
            match self.flush_contact(&contact).await? {
                ContactListWrite::Stored => report.written += 1,
                ContactListWrite::Full => {
                    report.refused_full += 1;
                    full = true;
                }
                ContactListWrite::Conflict => {}
            }
        }
        if let Some(list) = self.contact_list.as_mut() {
            list.full = full;
        }
        Ok(report)
    }

    /// One contact's entry: taken from the list, written, or left due (a full
    /// list; a list that kept changing). `Stored` also for nothing to write.
    async fn flush_contact(&mut self, contact: &ContactRecord) -> Result<ContactListWrite> {
        for _ in 0..2 {
            // The record as it is now (a newer change may have come).
            let Some(current) = self.session.contact(&contact.peer).await? else {
                return Ok(ContactListWrite::Stored);
            };
            match self.contact_step(&current).await? {
                Step::Nothing => {
                    self.session
                        .save_contact(ContactRecord {
                            list_due_at_ms: None,
                            ..current
                        })
                        .await?;
                    return Ok(ContactListWrite::Stored);
                }
                Step::Take(record, key) => {
                    self.session.restore_contact(*record, key).await?;
                    return Ok(ContactListWrite::Stored);
                }
                Step::Write(entry) => match self.write_contact_entry(&entry).await? {
                    ContactListWrite::Stored => {
                        self.session
                            .save_contact(ContactRecord {
                                list_due_at_ms: None,
                                ..current
                            })
                            .await?;
                        return Ok(ContactListWrite::Stored);
                    }
                    ContactListWrite::Full => return Ok(ContactListWrite::Full),
                    // Another device wrote first: the list was read again;
                    // merge and try once more.
                    ContactListWrite::Conflict => {}
                },
            }
        }
        Ok(ContactListWrite::Conflict)
    }

    /// Writes one entry over the revision the list has. A new entry on a
    /// full list evicts first (the oldest rejected, then the oldest asked;
    /// never a block), and says `Full` when nothing may go.
    async fn write_contact_entry(&mut self, entry: &ChatContactEntryV1) -> Result<ContactListWrite> {
        let plain = entry.canonical_bytes().map_err(invalid)?;
        let list = self.contact_list.as_ref().expect("enabled by the caller");
        let id = list.entry_id(&entry.account);
        let entry_id = chat_contact_list::decode_entry_id(&id).map_err(invalid)?;
        let mut evicted = false;
        loop {
            let list = self.contact_list.as_ref().expect("enabled by the caller");
            let base = list.listed.get(&id).map_or(0, |listed| listed.revision);
            let revision = base + 1;
            let sealed = list
                .key
                .seal(&list.binding, &entry_id, revision, &plain)
                .map_err(invalid)?;
            let envelope = STANDARD.encode(sealed);
            let transport = std::rc::Rc::clone(&self.transport);
            match transport
                .store_contact_entry(&id, base, revision, &envelope)
                .await?
            {
                ContactListWrite::Stored => {
                    let list = self.contact_list.as_mut().expect("enabled by the caller");
                    list.listed.insert(
                        id,
                        Listed {
                            revision,
                            entry: entry.clone(),
                        },
                    );
                    return Ok(ContactListWrite::Stored);
                }
                ContactListWrite::Conflict => {
                    self.read_contact_list().await?;
                    return Ok(ContactListWrite::Conflict);
                }
                ContactListWrite::Full if !evicted && self.evict_one_contact().await? => {
                    evicted = true;
                }
                ContactListWrite::Full => return Ok(ContactListWrite::Full),
            }
        }
    }

    /// Removes the list's oldest rejected entry, else its oldest asked one
    /// (a block is never evicted). False when there is none.
    async fn evict_one_contact(&mut self) -> Result<bool> {
        let list = self.contact_list.as_ref().expect("enabled by the caller");
        let oldest = |state: ContactState| {
            list.listed
                .iter()
                .filter(|(_, listed)| listed.entry.state == state)
                .min_by_key(|(_, listed)| listed.entry.control.updated_at_ms)
                .map(|(id, listed)| (id.clone(), listed.revision))
        };
        let Some((id, revision)) =
            oldest(ContactState::Rejected).or_else(|| oldest(ContactState::PendingOutgoing))
        else {
            return Ok(false);
        };
        let transport = std::rc::Rc::clone(&self.transport);
        let removed = transport.delete_contact_entry(&id, revision).await?;
        if removed {
            let list = self.contact_list.as_mut().expect("enabled by the caller");
            list.listed.remove(&id);
        } else {
            self.read_contact_list().await?;
        }
        Ok(true)
    }

    /// Reads the list and follows it: takes what is newer there (a block
    /// another device made, a contact this device never met), and makes due
    /// every contact the list lacks or is behind on (the one standing rule:
    /// it is also how contacts from before the list get into it). Returns
    /// how many contacts were taken.
    pub async fn sync_contact_list(&mut self) -> Result<usize> {
        if self.contact_list.is_none() {
            return Ok(0);
        }
        self.read_contact_list().await?;
        let local: BTreeMap<String, ContactRecord> = self
            .session
            .contacts()
            .await?
            .into_iter()
            .map(|contact| (contact.peer.clone(), contact))
            .collect();
        let listed: Vec<ChatContactEntryV1> = self
            .contact_list
            .as_ref()
            .expect("checked above")
            .listed
            .values()
            .map(|listed| listed.entry.clone())
            .collect();
        let mut taken = 0;
        for entry in listed {
            let peer = entry.account.to_string();
            if peer == self.session.user() {
                continue;
            }
            let newer = local.get(&peer).is_none_or(|contact| {
                contact_order(entry.control.revision, entry.state, entry.control.source_device_id)
                    > order_of(contact)
            });
            if newer {
                let record = record_of(&peer, &entry);
                self.session
                    .restore_contact(record, listed_profile_key(&entry))
                    .await?;
                taken += 1;
            }
        }
        // The standing rule: what the list lacks, or is behind on, is due.
        let now = self.now_ms();
        for contact in self.session.contacts().await? {
            if contact.list_due_at_ms.is_some() || contact.state == ContactState::PendingIncoming {
                continue;
            }
            if matches!(self.contact_step(&contact).await?, Step::Write(_)) {
                let due = due_after_change(&contact, now);
                self.session
                    .save_contact(ContactRecord {
                        list_due_at_ms: due,
                        ..contact
                    })
                    .await?;
            }
        }
        Ok(taken)
    }

    /// Reads and follows the list when it wasn't read for a while, then
    /// writes what is due (best effort).
    pub async fn sync_contact_list_if_due(&mut self) -> Result<()> {
        let Some(list) = self.contact_list.as_ref() else {
            return Ok(());
        };
        if list.read_at_ms == 0 || self.now_ms() - list.read_at_ms >= READ_EVERY_MS {
            self.sync_contact_list().await?;
        }
        self.flush_contact_list(false).await?;
        Ok(())
    }

    /// After an explicit change of `peer`: a block is written at once where
    /// the platform says so (the web); everything else waits its delay.
    pub(crate) async fn contact_changed(&mut self, peer: &str) {
        let Some(list) = self.contact_list.as_ref() else {
            return;
        };
        let blocked = self
            .session
            .contact(peer)
            .await
            .ok()
            .flatten()
            .is_some_and(|contact| contact.state == ContactState::Blocked);
        if blocked && list.timing.block == BlockTiming::Immediate {
            if let Ok(report) = self.flush_contacts(true, Some(peer)).await {
                if report.refused_full > 0 {
                    if let Some(list) = self.contact_list.as_mut() {
                        list.full = true;
                    }
                }
            }
        }
    }
}

/// A local record of a listed entry (taken here, so nothing is due).
fn record_of(peer: &str, entry: &ChatContactEntryV1) -> ContactRecord {
    ContactRecord {
        peer: peer.to_string(),
        state: entry.state,
        previous_state: entry.previous_state,
        revision: entry.control.revision,
        source_device_id: entry.control.source_device_id,
        updated_at_ms: entry.control.updated_at_ms,
        sync_pending: false,
        sync_send_id: None,
        list_due_at_ms: None,
    }
}

fn listed_profile_key(entry: &ChatContactEntryV1) -> Option<Vec<u8>> {
    entry
        .profile_key
        .as_ref()
        .and_then(|key| STANDARD.decode(key).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_wins_a_tie_whatever_device_wrote_the_other() {
        let accept = contact_order(5, ContactState::Accepted, 9);
        let block = contact_order(5, ContactState::Blocked, 1);
        assert!(block > accept);
        // A later revision still wins over a block.
        assert!(contact_order(6, ContactState::Accepted, 1) > block);
        // Between two of the same kind, the device id decides, as before.
        assert!(
            contact_order(5, ContactState::Accepted, 9)
                > contact_order(5, ContactState::Rejected, 1)
        );
    }
}
