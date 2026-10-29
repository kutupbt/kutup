//! Whether a logged collab frame is its sender's (docs/plans/one-device-list.md
//! §8, slice 3), as the web editors check it: a frame read from the log
//! counts only when a manifest of its sender's chain lists the frame's device
//! with the key that signed it. The rules are
//! `kutup_chat_proto::SenderManifests`; this reads what they ask for and keeps
//! the pins in the profile store.
//!
//! - A frame proven not its sender's (the manifest is held and doesn't list
//!   the device with that key) is skipped and counted; `kutup sync` warns and
//!   exits non-zero when any were.
//! - A frame that can't be checked now (the server unreadable, the account
//!   reset) fails that file's sync: nothing of it is written or saved, so no
//!   save trims the frame away, and the next run checks it again.

use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, bail, Result};
use kutup_chat_proto::{AccountManifestV3, SenderManifests, SenderVerdict};
use kutup_crypto::account_ref::AccountRef;

use crate::api::Client;
use crate::session::Store;

/// The identity pins' word on an account's authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityVerdict {
    /// Pinned to this authority.
    Pinned,
    /// Pinned to another (a reset, or a server's own keys) not accepted.
    Changed,
    /// An account the pins don't know: trusted on first use.
    Unknown,
}

/// Asks the identity pins about `account`'s authority (canonical base64).
pub type AuthorityCheck<'a> = Box<dyn FnMut(&AccountRef, &str) -> Result<AuthorityVerdict> + 'a>;

/// Where a sender's manifests come from: the account's server, through this
/// one (`Client`), or a test's.
pub trait ManifestSource {
    fn head(&self, account: &AccountRef) -> Result<Option<AccountManifestV3>>;
    fn history(&self, account: &AccountRef, from: u64, to: u64) -> Result<Vec<AccountManifestV3>>;
}

impl ManifestSource for Client {
    fn head(&self, account: &AccountRef) -> Result<Option<AccountManifestV3>> {
        self.account_manifest(account)
    }

    fn history(&self, account: &AccountRef, from: u64, to: u64) -> Result<Vec<AccountManifestV3>> {
        self.account_manifest_history(account, from, to)
    }
}

/// Where a sender's pins are kept: the profile store, or a test's.
pub trait PinStore {
    fn sender_pin(
        &self,
        account: &AccountRef,
    ) -> Result<Option<kutup_chat_proto::AccountManifestPinV1>>;
    fn put_sender_pin(&self, pin: &kutup_chat_proto::AccountManifestPinV1) -> Result<()>;
}

impl PinStore for Store {
    fn sender_pin(
        &self,
        account: &AccountRef,
    ) -> Result<Option<kutup_chat_proto::AccountManifestPinV1>> {
        Store::sender_pin(self, account)
    }

    fn put_sender_pin(&self, pin: &kutup_chat_proto::AccountManifestPinV1) -> Result<()> {
        Store::put_sender_pin(self, pin)
    }
}

/// Reads one frame's check may make.
const MAX_READS: usize = 2;

pub struct Senders<'a> {
    source: &'a dyn ManifestSource,
    store: &'a dyn PinStore,
    authority: AuthorityCheck<'a>,
    senders: HashMap<String, SenderManifests>,
    /// Senders with a frame proven not theirs, for the warning.
    pub refused: BTreeSet<String>,
    /// Frames proven not their senders', skipped this run.
    pub refused_frames: usize,
}

impl<'a> Senders<'a> {
    pub fn new(
        source: &'a dyn ManifestSource,
        store: &'a dyn PinStore,
        authority: AuthorityCheck<'a>,
    ) -> Self {
        Senders {
            source,
            store,
            authority,
            senders: HashMap::new(),
            refused: BTreeSet::new(),
            refused_frames: 0,
        }
    }

    /// Whether `raw`, a packed frame the log names `sender` for, is that
    /// sender's: `Ok(true)` to apply it, `Ok(false)` for one proven not
    /// (counted). An error when it can't be checked now: the file's sync
    /// stops there.
    pub fn verify(&mut self, sender: &str, raw: &[u8]) -> Result<bool> {
        let account: AccountRef = sender
            .parse()
            .map_err(|_| anyhow!("the log names a malformed sender"))?;
        if !self.senders.contains_key(sender) {
            let pin = self.store.sender_pin(&account)?;
            self.senders.insert(
                sender.to_owned(),
                SenderManifests::new(account.clone(), pin),
            );
        }
        for reads in 0.. {
            let verdict = self
                .senders
                .get(sender)
                .expect("added above")
                .check(raw, false);
            match verdict {
                SenderVerdict::Take => return Ok(true),
                SenderVerdict::Refuse { .. } => {
                    self.refused.insert(sender.to_owned());
                    self.refused_frames += 1;
                    return Ok(false);
                }
                _ if reads >= MAX_READS => {
                    bail!("an edit from {sender} names a manifest its server didn't give; try again later")
                }
                SenderVerdict::NeedHead => self.read_head(sender, &account)?,
                SenderVerdict::NeedManifest { sequence, through } => {
                    let run = self.source.history(&account, sequence, through)?;
                    self.senders
                        .get_mut(sender)
                        .expect("added")
                        .take_history(&run)
                        .map_err(|error| {
                            anyhow!("the manifests {sender}'s server gave don't link to its chain: {error}")
                        })?;
                }
            }
        }
        unreachable!("the loop returns")
    }

    fn read_head(&mut self, sender: &str, account: &AccountRef) -> Result<()> {
        let head = self
            .source
            .head(account)?
            .ok_or_else(|| anyhow!("{sender}'s server has no device list for it"))?;
        let verdict = (self.authority)(account, &head.self_authority_key)?;
        let manifests = self.senders.get_mut(sender).expect("added");
        let pin = manifests.pin.clone();
        let other_incarnation = pin
            .as_ref()
            .is_some_and(|pin| pin.incarnation_id != head.incarnation_id);
        if verdict == AuthorityVerdict::Changed {
            bail!(
                "{sender}'s account was reset: its edits can't be verified until you accept \
                 its new keys (`kutup identity trust <their address>`) or the file is shared again"
            );
        }
        if verdict == AuthorityVerdict::Unknown && other_incarnation {
            bail!(
                "{sender}'s account was reset: if you know it was, trust its new keys with \
                 `kutup devices forget-pin --sender {sender}`"
            );
        }
        // The identity pins hold this authority while the pin is of another
        // incarnation: the user accepted the account's reset.
        let new_incarnation = verdict == AuthorityVerdict::Pinned && other_incarnation;
        let history = match &pin {
            Some(pin) if !new_incarnation && head.sequence > pin.sequence + 1 => self
                .source
                .history(account, pin.sequence + 1, head.sequence - 1)?,
            _ => Vec::new(),
        };
        let manifests = self.senders.get_mut(sender).expect("added");
        manifests
            .take_head(head, &history, new_incarnation)
            .map_err(|error| anyhow!("{sender}'s device list can't be trusted: {error}"))?;
        if let Some(pin) = &manifests.pin {
            self.store.put_sender_pin(pin)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
