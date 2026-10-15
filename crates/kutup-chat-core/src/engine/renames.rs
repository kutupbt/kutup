//! Following peers' username renames (docs/plans/username-renames.md): the
//! engine's side of `renames.rs` and `Session::move_peer`.
//!
//! A peer is followed when the server says an address is a name its account
//! left (`409 renamed`), when an address met for the first time belongs to
//! someone pinned under an earlier name, and when the authority at a pinned
//! address changes because the pinned account moved away. Each time only the
//! chain of the pinned authority moves anything.

use super::*;
use crate::renames::{self, RenameChainsV1};
use crate::{AccountAuthority, ManifestTrust};

/// A peer this device followed to another address during a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRenamed {
    pub from: String,
    pub to: String,
}

impl Engine {
    /// Follows the peer pinned at `peer` along `chains` (a `409 renamed`'s,
    /// or asked for when `None`). Returns where the peer is now when it
    /// moved; `None` when nothing was to follow.
    pub(crate) async fn follow_rename(
        &mut self,
        peer: &str,
        chains: Option<RenameChainsV1>,
    ) -> Result<Option<String>> {
        let Some(trust) = self.session.manifest_trust(peer).await? else {
            return Ok(None);
        };
        let chains = match chains {
            Some(chains) => chains,
            None => {
                Rc::clone(&self.transport)
                    .fetch_renames(peer, Some(&trust.incarnation_id))
                    .await?
            }
        };
        let Some(found) = renames::select(&trust, &chains)? else {
            return Ok(None);
        };
        let devices: Vec<u32> = self
            .known_devices
            .get(peer)
            .map(|bundles| bundles.iter().map(|bundle| bundle.device_id).collect())
            .unwrap_or_default();
        let entry = chains
            .chains
            .iter()
            .find(|entry| entry.authority_public_key == trust.self_authority_key)
            .cloned();
        if !self
            .session
            .move_peer(&found.from, &found.to, found.known, &devices)
            .await?
        {
            return Ok(None);
        }
        self.forget_peer(&found.from);
        // The account's other apps follow too (best effort: Drive and the
        // CLI follow the chain themselves when they next meet the peer).
        if let Some(entry) = entry {
            let _ = self
                .apply_rename_to_synced_pins(&entry.authority_public_key, &entry.chain)
                .await;
        }
        self.renamed.push(PeerRenamed {
            from: found.from,
            to: found.to.clone(),
        });
        Ok(Some(found.to))
    }

    /// An address met for the first time: whether it is someone pinned under
    /// an earlier name of theirs. Then their thread moves here before
    /// anything of the new address is accepted. Best effort: an answer that
    /// cannot be had leaves the address a new person.
    pub(crate) async fn adopt_renamed_peer(&mut self, peer: &str) -> Result<()> {
        if peer == self.session.user() || self.session.manifest_trust(peer).await?.is_some() {
            return Ok(());
        }
        let Ok(chains) = Rc::clone(&self.transport).fetch_renames(peer, None).await else {
            return Ok(());
        };
        if chains.version != renames::RENAME_CHAINS_VERSION || chains.unavailable {
            return Ok(());
        }
        for entry in &chains.chains {
            if entry.state != "current" || !renames::same_address(&entry.current, peer) {
                continue;
            }
            for statement in &entry.chain {
                let earlier = statement.previous.as_str();
                let Some(trust) = self.session.manifest_trust(earlier).await? else {
                    continue;
                };
                if trust.self_authority_key == entry.authority_public_key {
                    // Only the pinned authority's verified chain moves it.
                    self.follow_rename(earlier, Some(chains.clone())).await?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// The authority at a pinned address changed: when the pinned account
    /// renamed away (and this device missed it), its thread follows it and
    /// the address is someone new. Returns whether it moved.
    pub(crate) async fn follow_before_quarantine(
        &mut self,
        peer: &str,
        prior: &ManifestTrust,
    ) -> Result<bool> {
        let Ok(chains) = Rc::clone(&self.transport)
            .fetch_renames(peer, Some(&prior.incarnation_id))
            .await
        else {
            return Ok(false);
        };
        if !matches!(renames::select(prior, &chains), Ok(Some(_))) {
            return Ok(false);
        }
        Ok(self.follow_rename(peer, Some(chains)).await?.is_some())
    }

    /// A lookup's answer, once the peer is followed when the server said the
    /// address is a name it left: the `409 renamed` stays an error, and the
    /// caller asks again where the peer is now.
    pub(crate) async fn followed<T>(&mut self, peer: &str, fetched: Result<T>) -> Result<T> {
        match fetched {
            Err(ChatError::Renamed(chains)) => {
                self.follow_rename(peer, Some((*chains).clone())).await?;
                Err(ChatError::Renamed(chains))
            }
            other => other,
        }
    }

    /// This account goes by `new_address` (`/user/me` says so, or the app
    /// opened the store under it): its own records still under an earlier
    /// address of its verified chain follow it, and the device goes by the
    /// new address. Then the manifest and the profile are published under it
    /// (`republish_profile_after_rename`). Returns whether anything moved; a
    /// restart re-runs it as a no-op.
    pub async fn adopt_own_rename(
        &mut self,
        authority: &AccountAuthority,
        new_address: &str,
    ) -> Result<bool> {
        let current = self.session.user().to_string();
        let settled = renames::same_address(&current, new_address)
            && self.session.manifest_trust(&current).await?.is_some();
        if settled {
            return Ok(false);
        }
        let chains = Rc::clone(&self.transport)
            .fetch_renames(new_address, Some(&authority.incarnation_id()))
            .await?;
        if chains.version != renames::RENAME_CHAINS_VERSION || chains.unavailable {
            return Ok(false);
        }
        let Some(entry) = chains
            .chains
            .iter()
            .find(|entry| entry.authority_public_key == authority.public_key_base64())
        else {
            // Never renamed: nothing of this account is anywhere else.
            if !renames::same_address(&current, new_address) {
                return Err(ChatError::Trust(
                    "this account's new address has no rename chain of its own".into(),
                ));
            }
            return Ok(false);
        };
        // Its own records, under the newest earlier address that holds them
        // (or a pin made from its authority, for a device that never
        // published).
        let mut earlier: Vec<String> = entry.chain.iter().map(|s| s.previous.clone()).collect();
        earlier.reverse();
        let mut moved = false;
        for address in earlier {
            if renames::same_address(&address, new_address) {
                continue;
            }
            let Some(own) = self.session.manifest_trust(&address).await? else {
                continue;
            };
            if own.self_authority_key != authority.public_key_base64() {
                return Err(ChatError::Trust(
                    "this account's pin names another authority".into(),
                ));
            }
            let Some(found) = renames::select(&own, &chains)? else {
                continue;
            };
            if !renames::same_address(&found.to, new_address) {
                return Err(ChatError::Trust(
                    "this account's rename chain ends at another address".into(),
                ));
            }
            // The linked devices are those of the newest own manifest.
            moved = self
                .session
                .move_own_records(&found.from, &found.to, found.known, &[])
                .await?;
            self.forget_peer(&found.from);
            break;
        }
        if !moved {
            // No pin of this account anywhere: its chain must still lead here.
            let pinned = own_pin(authority, &current);
            let leads_here = renames::select(&pinned, &chains)?
                .is_some_and(|found| renames::same_address(&found.to, new_address))
                || renames::same_address(&current, new_address);
            if !leads_here {
                return Err(ChatError::Trust(
                    "this account's rename chain does not lead to its new address".into(),
                ));
            }
        }
        let changed = !renames::same_address(&current, new_address) || moved;
        self.session.set_user(new_address)?;
        Ok(changed)
    }

    /// After [`Self::adopt_own_rename`]: the encrypted profile again, bound
    /// to the new address (its contents unchanged), so peers open it there.
    pub async fn republish_profile_after_rename<R: Rng + CryptoRng>(
        &mut self,
        wrapping_key: &[u8; 32],
        sent_at: &str,
        rng: &mut R,
    ) -> Result<()> {
        let Some(profile) = self.session.local_profile().await? else {
            return Ok(());
        };
        self.update_profile(
            &profile.display_name,
            profile.avatar.clone(),
            profile.avatar_content_type.clone(),
            profile.about.clone(),
            wrapping_key,
            sent_at,
            rng,
        )
        .await?;
        Ok(())
    }

    /// Drops what this run holds about a peer under an address it left.
    fn forget_peer(&mut self, peer: &str) {
        self.known_devices.remove(peer);
        self.known_devices_at.remove(peer);
        self.session_resets
            .retain(|(account, _), _| account != peer);
        self.resent.retain(|(account, _), _| account != peer);
        self.asked_again.retain(|(account, _), _| account != peer);
    }

    /// Moves the account's synced pin of `authority` along `chain`.
    async fn apply_rename_to_synced_pins(
        &mut self,
        authority: &str,
        chain: &[kutup_crypto::account_rename::AccountRenameV1],
    ) -> Result<()> {
        let Some(mut sync) = self.identity_pins.take() else {
            return Ok(());
        };
        let now = (crate::clock::unix_millis().max(0) / 1000) as u64;
        let result = sync
            .apply_rename(&*self.transport, authority, chain, now)
            .await;
        self.identity_pins = Some(sync);
        result
    }

    /// The peers followed to another address since the last call.
    pub(crate) fn take_renamed(&mut self) -> Vec<PeerRenamed> {
        std::mem::take(&mut self.renamed)
    }
}

/// A pin of this account as its own authority makes it, for a device that
/// has none yet: what `renames::select` checks the chain against.
fn own_pin(authority: &AccountAuthority, address: &str) -> ManifestTrust {
    ManifestTrust {
        peer: address.to_string(),
        account: address.to_string(),
        incarnation_id: authority.incarnation_id(),
        authority_key_id: authority.key_id(),
        self_authority_key: authority.public_key_base64(),
        drive_hpke_public_key: String::new(),
        drive_share_signing_public_key: String::new(),
        highest_sequence: 0,
        manifest_hash: String::new(),
        trust: crate::AuthorityTrust::Verified,
        continuity_gap: false,
        quarantine_reason: None,
        pending_reset: None,
        renames: None,
    }
}
