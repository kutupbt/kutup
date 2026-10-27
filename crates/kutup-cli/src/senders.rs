//! Whether a logged collab frame is its sender's (docs/plans/one-device-list.md
//! §8, slice 3), as the web editors check it: a frame read from the log
//! counts only when the manifest it names lists the frame's device with the
//! key that signed it. The rules are `kutup_chat_proto::SenderManifests`;
//! this reads what they ask for and keeps the pins in the profile store.
//!
//! A sender whose account was reset (the identity pins hold another
//! authority, not accepted) is refused. Refused frames are skipped and
//! counted; `kutup sync` warns and exits non-zero when any were.

use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, Result};
use kutup_chat_proto::{SenderManifests, SenderVerdict};
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

/// How often one frame's check may read a head or a manifest.
const MAX_READS: usize = 3;

struct Sender {
    manifests: SenderManifests,
    /// Refused for good this run (a reset, a head that doesn't follow).
    refused: bool,
}

pub struct Senders<'a> {
    client: &'a Client,
    store: &'a Store,
    authority: AuthorityCheck<'a>,
    senders: HashMap<String, Sender>,
    /// Senders with a frame refused, for the warning.
    pub refused: BTreeSet<String>,
    /// Frames refused this run.
    pub refused_frames: usize,
}

impl<'a> Senders<'a> {
    pub fn new(client: &'a Client, store: &'a Store, authority: AuthorityCheck<'a>) -> Self {
        Senders {
            client,
            store,
            authority,
            senders: HashMap::new(),
            refused: BTreeSet::new(),
            refused_frames: 0,
        }
    }

    /// Whether `raw`, a packed frame the log names `sender` for, is that
    /// sender's: true to apply it. A frame that isn't is counted. Errors
    /// only when the server can't be read.
    pub fn verify(&mut self, sender: &str, raw: &[u8]) -> Result<bool> {
        let account: AccountRef = sender
            .parse()
            .map_err(|_| anyhow!("the log names a malformed sender"))?;
        if !self.senders.contains_key(sender) {
            let pin = self.store.sender_pin(&account)?;
            self.senders.insert(
                sender.to_owned(),
                Sender {
                    manifests: SenderManifests::new(account.clone(), pin),
                    refused: false,
                },
            );
        }
        let mut reads = 0;
        loop {
            let entry = self.senders.get(sender).expect("added above");
            let verdict = if entry.refused {
                SenderVerdict::Refuse {
                    reason: "refused".into(),
                }
            } else {
                entry.manifests.check(raw, false)
            };
            match verdict {
                SenderVerdict::Take => return Ok(true),
                SenderVerdict::Refuse { .. } => return Ok(self.refuse(sender)),
                _ if reads >= MAX_READS => return Ok(self.refuse(sender)),
                SenderVerdict::NeedHead => self.read_head(sender, &account)?,
                SenderVerdict::NeedManifest { sequence } => {
                    self.read_entry(sender, &account, sequence)?
                }
            }
            reads += 1;
        }
    }

    fn refuse(&mut self, sender: &str) -> bool {
        self.refused.insert(sender.to_owned());
        self.refused_frames += 1;
        false
    }

    fn read_head(&mut self, sender: &str, account: &AccountRef) -> Result<()> {
        let Some(head) = self.client.account_manifest(account)? else {
            self.senders.get_mut(sender).expect("added").refused = true;
            return Ok(());
        };
        let verdict = (self.authority)(account, &head.self_authority_key)?;
        let entry = self.senders.get_mut(sender).expect("added");
        if verdict == AuthorityVerdict::Changed {
            entry.refused = true;
            return Ok(());
        }
        let pin = entry.manifests.pin.clone();
        // The identity pins hold this authority while the pin is of another
        // incarnation: the user accepted the account's reset.
        let new_incarnation = verdict == AuthorityVerdict::Pinned
            && pin
                .as_ref()
                .is_some_and(|pin| pin.incarnation_id != head.incarnation_id);
        let history = match &pin {
            Some(pin) if !new_incarnation && head.sequence > pin.sequence + 1 => self
                .client
                .account_manifest_history(account, pin.sequence + 1, head.sequence - 1)?,
            _ => Vec::new(),
        };
        let entry = self.senders.get_mut(sender).expect("added");
        if entry
            .manifests
            .take_head(head, &history, new_incarnation)
            .is_err()
        {
            entry.refused = true;
            return Ok(());
        }
        if let Some(pin) = &entry.manifests.pin {
            self.store.put_sender_pin(pin)?;
        }
        Ok(())
    }

    fn read_entry(&mut self, sender: &str, account: &AccountRef, sequence: u64) -> Result<()> {
        let manifests = self
            .client
            .account_manifest_history(account, sequence, sequence)?;
        let entry = self.senders.get_mut(sender).expect("added");
        let taken = manifests
            .into_iter()
            .find(|m| m.sequence == sequence)
            .is_some_and(|manifest| entry.manifests.take_entry(manifest).is_ok());
        if !taken {
            entry.refused = true;
        }
        Ok(())
    }
}
