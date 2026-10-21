//! Taking a group up again without the account's group list
//! (docs/plans/pairwise-groups.md §2, "A device that lost its group list").
//!
//! - A member's pseudonym is derived from the account master key, the group
//!   id and the join epoch (`kutup_crypto::chat_group::GroupPseudonymKey`),
//!   so a device that has the group's key finds its account's place in it
//!   again, even when the list entry was never written (the only device went
//!   within the write's random delay).
//! - The group's key comes with a member's next send: what goes pairwise to
//!   this account (the member's sender key, since this device isn't in the
//!   member's book yet, or the message itself) carries a context with the
//!   master key and the home, as Signal's `GroupContextV2` does, naming the
//!   account's pseudonym in the group.
//! - The named pseudonym must be one this account's key gives (epochs 0 to
//!   [`group::MAX_JOIN_EPOCHS`] − 1), found locally. Nobody who doesn't know
//!   it can make the device ask anything, and every attempt counts against
//!   the limits below before anything is asked.
//! - Then the list: a group it says this account left is never taken up
//!   again this way, and one it holds is taken up from the list. Only then
//!   does the device ask the home once, for that pseudonym.
//! - The state is kept only when it holds this account's own binding (signed
//!   by its authority: a home can't make one up) and the sender's (a
//!   verified member). Nothing is kept or signed otherwise, and nothing is
//!   signed anew for a group taken up this way: its entry is the account's
//!   own already.
//! - Once an hour per group, and at most [`MAX_RECOVERIES_PER_HOUR`] groups
//!   an hour per device, across reloads. If nobody in the group sends after
//!   the loss, the device gets the group back only once someone does.

use kutup_chat_proto::group::{decode_group_id, encode, GroupContextV1};
use kutup_crypto::account_ref::AccountRef;
use rand::{CryptoRng, Rng};

use crate::clock::unix_millis;
use crate::engine::{Engine, SESSION_RESET_INTERVAL_MS};
use crate::error::{ChatError, Result};
use crate::group::{self, GroupRecordV1, GroupStatus, SecretText};
use crate::group_engine::{group_error, GroupSync};

/// At most this many groups are taken up this way per device an hour.
pub(crate) const MAX_RECOVERIES_PER_HOUR: usize = 10;

/// The key the hourly limits are kept under (with the group id).
const RECOVERY_LIMIT: &str = "group-recovery";

impl Engine {
    /// Takes up the group `context` names when this device doesn't know it,
    /// from `sender`'s pairwise content naming this account's pseudonym
    /// `named`. True when the group was taken up (from the list,
    /// or from its home). Nothing is kept or sent otherwise.
    pub(crate) async fn recover_group<R: Rng + CryptoRng>(
        &mut self,
        context: &GroupContextV1,
        sender: &str,
        named: &str,
        rng: &mut R,
    ) -> Result<bool> {
        if self.group_keys.is_none() || self.group_list.is_none() {
            return Ok(false);
        }
        let group_id = context.group_id.clone();
        if self.session.db().load_group(&group_id).await?.is_some() {
            return Ok(false);
        }
        let group = decode_group_id(&group_id).map_err(ChatError::Invalid)?;
        // The key must be the group's at the home the context names: the id
        // binds the home, so a member who kept the key can't name a home of
        // their own (that is another group, which no binding names).
        if group::master_at(&context.master_key, &group_id, &context.home).is_err() {
            return Ok(false);
        }
        // The named pseudonym must be this account's (found here, asking
        // nobody).
        let keys = self.group_keys()?;
        let Some(join_epoch) = (0..group::MAX_JOIN_EPOCHS)
            .find(|&epoch| encode(&keys.pseudonyms.pseudonym(&group, epoch).public_key()) == named)
        else {
            return Ok(false);
        };
        let pseudonym = keys.pseudonyms.pseudonym(&group, join_epoch);
        let own_authority = keys.authority.public_key();
        let sender_account: AccountRef = sender
            .parse()
            .map_err(|_| ChatError::Invalid("the sender isn't an account".into()))?;
        // Counted before anything is asked of a server (the list included),
        // so a member sending contexts can't make this device ask more than
        // the limits allow.
        if !self.may_try_recovery(&group_id).await? {
            return Ok(false);
        }
        // The list first: read this run, it takes up what it holds.
        if !self.group_list_read() {
            let _ = self.sync_group_list(rng).await;
            if self.session.db().load_group(&group_id).await?.is_some() {
                return Ok(true);
            }
            // A list that couldn't be read may say the account left: fail
            // closed, and try again with the next message (after the hour).
            if !self.group_list_read() {
                return Ok(false);
            }
        }
        // A group the list says this account left stays left; one it holds
        // is the list's to take up (its home couldn't be reached).
        if self.listed_join(&group_id).is_some() {
            return Ok(false);
        }
        let mut record = GroupRecordV1 {
            version: kutup_chat_proto::group::GROUP_FORMAT_VERSION,
            group_id: group_id.clone(),
            master_key: SecretText(context.master_key.clone()),
            home: context.home.clone(),
            pseudonym_seed: SecretText(encode(pseudonym.seed())),
            status: GroupStatus::Member,
            // Nothing says which state this account last verified: the
            // members' contexts show a home serving an older one.
            min_revision: 0,
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
            listed_status: None,
            list_due_at_ms: None,
            join_epoch,
            delivery: None,
            member_capabilities: Default::default(),
            listed_delivery_ms: None,
        };
        if !matches!(
            self.fetch_whole_state(&mut record).await?,
            Some(GroupSync::Current { .. })
        ) {
            return Ok(false);
        }
        // This account's own binding, signed by its authority: no home can
        // make one up, so the state is the group this account was in.
        let me = self.session.account_ref().clone();
        let own = record.pseudonym_text().map_err(group_error)?;
        let bound = group::members(&record, &|account: &AccountRef| {
            (*account == me).then_some(own_authority)
        })
        .map_err(group_error)?
        .into_iter()
        .any(|member| {
            member.pseudonym == own
                && member
                    .verified
                    .is_some_and(|verified| verified.account == me)
        });
        if !bound {
            return Ok(false);
        }
        // And the sender is a verified member of it.
        let (members, _, _) = self
            .check_members(&record, std::slice::from_ref(&sender_account), &[])
            .await?;
        let from_member = members.iter().any(|member| {
            member
                .verified
                .as_ref()
                .is_some_and(|verified| verified.account == sender_account)
        });
        if !from_member {
            return Ok(false);
        }
        self.save_group(&record).await?;
        // Its entry is written back to the list with the usual delay.
        let _ = self.schedule_group_entry(&group_id).await;
        Ok(true)
    }

    /// Whether a recovery of `group_id` may be tried now: once an hour per
    /// group, and [`MAX_RECOVERIES_PER_HOUR`] groups an hour, across reloads;
    /// recorded as tried before anything is asked.
    async fn may_try_recovery(&mut self, group_id: &str) -> Result<bool> {
        let now = unix_millis();
        self.load_repair_limits().await?;
        self.resent
            .retain(|_, at| now.saturating_sub(*at) < SESSION_RESET_INTERVAL_MS);
        let tried = self
            .resent
            .keys()
            .filter(|(who, _)| who == RECOVERY_LIMIT)
            .count();
        let key = (RECOVERY_LIMIT.to_string(), group_id.to_string());
        if tried >= MAX_RECOVERIES_PER_HOUR || self.resent.contains_key(&key) {
            return Ok(false);
        }
        self.resent.insert(key, now);
        self.write_repair_limits().await?;
        Ok(true)
    }
}
