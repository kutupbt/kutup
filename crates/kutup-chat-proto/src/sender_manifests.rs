//! Whether a collab frame is its sender's (docs/plans/one-device-list.md §8,
//! slice 3): what a recipient knows of one sender account, and the check a
//! frame goes through before it is applied. The crypto WASM and the CLI both
//! use it; they only fetch the manifests it asks for, store its pin, and
//! apply what it takes.
//!
//! - A **live** frame counts when the account's head lists its device with
//!   the key that signed it: a removed device stops as soon as the head
//!   without it is here.
//! - A **logged** frame (replayed on join, or read from the log) counts when
//!   the manifest its `manifestSequence` names lists that device and key:
//!   device ids are reused, and a removed device's past edits stay part of
//!   the document.
//! - The head only moves forward from the pin, along a verified chain; a
//!   first head is trusted on first use once it verifies.

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::envelope::{self, Frame};
use serde::{Deserialize, Serialize};

use crate::{AccountManifestPinV1, AccountManifestV3};

/// The most earlier manifests one sender's record keeps for logged frames;
/// the oldest go first. A dropped one is fetched again when a frame names it.
pub const MAX_KEPT_ENTRIES: usize = 64;

/// What a recipient does with a frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SenderVerdict {
    /// Apply it.
    Take,
    /// Read the account's head (and the history up to it), then check again.
    NeedHead,
    /// Read the account's manifests from `sequence` through `through` (the
    /// run up to one already linked to the head), then check again.
    NeedManifest { sequence: u64, through: u64 },
    /// Drop it: its sender didn't sign it with a listed device's key.
    Refuse { reason: String },
}

/// What a recipient knows of one sender account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderManifests {
    pub account: AccountRef,
    /// The newest manifest seen of the account (kept by the client).
    pub pin: Option<AccountManifestPinV1>,
    /// The head, when read in this session.
    pub head: Option<AccountManifestV3>,
    /// Earlier manifests, for logged frames, by sequence: each linked by
    /// `previous_hash` to the one after it, up to the head, so the server
    /// can't pass off a manifest the account's chain never held.
    #[serde(default)]
    pub entries: Vec<AccountManifestV3>,
}

fn refuse(reason: &str) -> SenderVerdict {
    SenderVerdict::Refuse {
        reason: reason.to_owned(),
    }
}

impl SenderManifests {
    /// A record of `account` from the client's `pin` of it, if any.
    pub fn new(account: AccountRef, pin: Option<AccountManifestPinV1>) -> Self {
        let pin = pin.filter(|pin| pin.account == account);
        Self {
            account,
            pin,
            head: None,
            entries: Vec::new(),
        }
    }

    /// Takes `head`, the account's head as its server gave it, with
    /// `history`: the manifests after the pin up to the head (any order;
    /// more is fine). The head must verify and name this account. Then:
    /// - with no pin, it is trusted on first use;
    /// - at the pin's sequence, it must be the pinned manifest;
    /// - later, every link from the pin to it must verify;
    /// - earlier, it is refused, as is another incarnation than the pin's
    ///   unless `new_incarnation` (the identity pins vouch for the head's
    ///   authority: the account was reset and the user accepted it), which
    ///   starts again from this head.
    pub fn take_head(
        &mut self,
        head: AccountManifestV3,
        history: &[AccountManifestV3],
        new_incarnation: bool,
    ) -> Result<(), String> {
        head.verify()?;
        if head.account != self.account {
            return Err("the head names another account".into());
        }
        let seen = AccountManifestPinV1::of(&head)?;
        let pin = match &self.pin {
            Some(pin) if pin.incarnation_id != head.incarnation_id => {
                if !new_incarnation {
                    return Err("the head is of another incarnation than the one pinned".into());
                }
                self.entries.clear();
                None
            }
            pin => pin.clone(),
        };
        if let Some(pin) = &pin {
            if seen.sequence < pin.sequence {
                return Err("the head is older than one this client saw".into());
            }
            if seen.sequence == pin.sequence && seen.hash != pin.hash {
                return Err("the head differs from the one this client saw at its sequence".into());
            }
            if seen.sequence > pin.sequence {
                let mut links: Vec<&AccountManifestV3> = history
                    .iter()
                    .filter(|m| m.sequence > pin.sequence && m.sequence < head.sequence)
                    .collect();
                links.sort_by_key(|m| m.sequence);
                links.dedup_by_key(|m| m.sequence);
                links.push(&head);
                let (mut sequence, mut hash) = (pin.sequence, pin.hash.clone());
                for link in &links {
                    link.verify()?;
                    if link.account != self.account
                        || link.incarnation_id != pin.incarnation_id
                        || link.sequence != sequence + 1
                        || link.previous_hash.as_deref() != Some(hash.as_str())
                    {
                        return Err(
                            "the history from the pinned manifest doesn't reach the head".into(),
                        );
                    }
                    sequence = link.sequence;
                    hash = link.manifest_hash()?;
                }
                for link in links.iter().take(links.len() - 1) {
                    self.keep((*link).clone());
                }
            }
        }
        if let Some(old) = self.head.take() {
            if old.sequence < head.sequence && old.incarnation_id == head.incarnation_id {
                self.keep(old);
            }
        }
        self.pin = Some(seen);
        self.head = Some(head);
        Ok(())
    }

    /// The lowest manifest kept (an entry or the head) above `sequence`: the
    /// one a run fetched for `sequence` must link up to.
    fn linked_above(&self, sequence: u64) -> Option<&AccountManifestV3> {
        self.entries
            .iter()
            .chain(self.head.iter())
            .filter(|m| m.sequence > sequence)
            .min_by_key(|m| m.sequence)
    }

    /// Takes `run`, earlier manifests of the account (for logged frames), as
    /// [`SenderVerdict::NeedManifest`] asked for them: a contiguous run (any
    /// order) whose links verify by `previous_hash`, the last one's up to the
    /// lowest manifest kept above it. So each is a manifest of the chain that
    /// reached the head, not one the account signed and the server never
    /// took.
    pub fn take_history(&mut self, run: &[AccountManifestV3]) -> Result<(), String> {
        let mut run: Vec<&AccountManifestV3> = run.iter().collect();
        run.sort_by_key(|m| m.sequence);
        run.dedup_by_key(|m| m.sequence);
        let Some(last) = run.last() else {
            return Err("no manifests to take".into());
        };
        let Some(above) = self.linked_above(last.sequence) else {
            return Err("no head of the account yet".into());
        };
        let (mut sequence, mut hash) = (above.sequence, above.previous_hash.clone());
        let incarnation = above.incarnation_id.clone();
        for manifest in run.iter().rev() {
            manifest.verify()?;
            if manifest.account != self.account
                || manifest.incarnation_id != incarnation
                || manifest.sequence + 1 != sequence
                || Some(manifest.manifest_hash()?) != hash
            {
                return Err("the manifests don't link to the account's chain".into());
            }
            sequence = manifest.sequence;
            hash = manifest.previous_hash.clone();
        }
        for manifest in run {
            self.keep(manifest.clone());
        }
        Ok(())
    }

    fn keep(&mut self, manifest: AccountManifestV3) {
        if self.entries.iter().any(|m| m.sequence == manifest.sequence) {
            return;
        }
        self.entries.push(manifest);
        self.entries.sort_by_key(|m| m.sequence);
        if self.entries.len() > MAX_KEPT_ENTRIES {
            self.entries.remove(0);
        }
    }

    /// What to do with `raw`, a packed frame delivered as this account's
    /// (`live`: during editing; otherwise from the log).
    pub fn check(&self, raw: &[u8], live: bool) -> SenderVerdict {
        let Ok(frame) = Frame::unpack(raw) else {
            return refuse("the frame is malformed");
        };
        let Some(head) = &self.head else {
            return SenderVerdict::NeedHead;
        };
        if frame.manifest_sequence > head.sequence {
            return SenderVerdict::NeedHead;
        }
        if frame.manifest_sequence == 0 {
            return refuse("the frame names no manifest");
        }
        let signed_under = |manifest: &AccountManifestV3| {
            manifest
                .device(frame.device_id)
                .and_then(|device| device.frame_key.as_deref())
                .and_then(|key| crate::decode_frame_key(key).ok())
                .is_some_and(|key| envelope::verify(raw, &self.account, &key).is_ok())
        };
        if live {
            // Live: only the head counts (a removed device stops at once).
            return if signed_under(head) {
                SenderVerdict::Take
            } else {
                refuse("the sender's head doesn't list the frame's device with its key")
            };
        }
        // From the log: a manifest held that lists the device with the key
        // that signed the frame says the device held that key (only it signs
        // with it), so nothing needs fetching.
        if signed_under(head) || self.entries.iter().any(signed_under) {
            return SenderVerdict::Take;
        }
        // The manifest it names is held, and doesn't list it so.
        if self
            .entries
            .iter()
            .chain(std::iter::once(head))
            .any(|m| m.sequence == frame.manifest_sequence)
        {
            return refuse("the manifest the frame names doesn't list its device with its key");
        }
        let through = self
            .linked_above(frame.manifest_sequence)
            .map_or(head.sequence, |m| m.sequence)
            - 1;
        SenderVerdict::NeedManifest {
            sequence: frame.manifest_sequence,
            through,
        }
    }
}

#[cfg(test)]
mod tests;
