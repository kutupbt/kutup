//! Taking a group up again without the account's group list
//! (docs/plans/pairwise-groups.md §5, "A device that lost its group list").
//!
//! - A member's pseudonym is derived from the account master key, the group
//!   id and the join epoch (`kutup_crypto::chat_group::GroupPseudonymKey`),
//!   so a device that has the group's key finds its account's place in it
//!   again, even when the list entry was never written (the only device went
//!   within the write's random delay).
//! - The group's key comes with any member's pairwise message for the group:
//!   its context carries the master key and the home, as Signal's
//!   `GroupContextV2` does. A member's next send gives this device its sender
//!   key that way, since the device isn't in the member's book yet.
//! - The device asks the home for the state with the pseudonym of each join
//!   epoch from 0 on, at most [`RECOVERY_EPOCHS`], and stops at the first the
//!   home serves. The home answers a pseudonym that isn't a member exactly as
//!   it answers an unknown group, so the asking proves nothing to it.
//! - It takes the state as a member whose own entry names this account, then
//!   keeps the group as opening it would, which writes the list entry back
//!   (with the usual delay).
//! - Once an hour per group, across reloads. If nobody in the group sends
//!   after the loss, the device gets the group back only once someone does.

use kutup_chat_proto::group::{decode_exact, decode_group_id, encode, GroupContextV1};
use kutup_crypto::chat_group::GroupMasterKey;
use rand::{CryptoRng, Rng};

use crate::clock::unix_millis;
use crate::engine::{Engine, SESSION_RESET_INTERVAL_MS};
use crate::error::{ChatError, Result};
use crate::group::{self, GroupRecordV1, GroupStatus, SecretText};
use crate::group_engine::{group_error, GroupSync};

/// How many join epochs a device tries: the first join and fifteen rejoins.
pub(crate) const RECOVERY_EPOCHS: u32 = 16;

/// The key the hourly limit is kept under (with the group id).
const RECOVERY_LIMIT: &str = "group-recovery";

impl Engine {
    /// Takes up the group a member's pairwise message names (`context`) when
    /// this device doesn't know it and its account is a member. True when
    /// the group was taken up. Nothing when the account's keys aren't here,
    /// the group is known, the key isn't the group's, or it was tried within
    /// the hour.
    pub(crate) async fn recover_group<R: Rng + CryptoRng>(
        &mut self,
        context: &GroupContextV1,
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
        let master = decode_exact::<32>("masterKey", &context.master_key)
            .map_err(ChatError::Invalid)
            .and_then(|bytes| {
                GroupMasterKey::from_bytes(&bytes)
                    .map_err(|error| ChatError::Invalid(error.to_string()))
            })?;
        if master.group_id() != group {
            return Ok(false);
        }
        if !self.may_try_recovery(&group_id).await? {
            return Ok(false);
        }
        for join_epoch in 0..RECOVERY_EPOCHS {
            let pseudonym = self.group_keys()?.pseudonyms.pseudonym(&group, join_epoch);
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
            };
            match self.probe_whole_state(&mut record).await? {
                // Not a member under this epoch's pseudonym: the next.
                None => continue,
                Some(GroupSync::Current { .. }) => {}
                // The home can't be asked now: the next message an hour on.
                Some(_) => return Ok(false),
            }
            // The member entry under this account's pseudonym is its own.
            let own = group::own_entry(&record).map_err(group_error)?;
            if own.is_none_or(|entry| entry.account != *self.session.account_ref()) {
                record.status = GroupStatus::Gone;
                self.save_group(&record).await?;
                return Ok(false);
            }
            // As opening it: caught up, its entry current, the list written.
            let _ = self.maintain_group(&group_id, rng).await;
            return Ok(true);
        }
        Ok(false)
    }

    /// Whether `group_id` may be tried now (once an hour, across reloads);
    /// recorded as tried before anything is asked.
    async fn may_try_recovery(&mut self, group_id: &str) -> Result<bool> {
        let now = unix_millis();
        self.load_repair_limits().await?;
        self.resent
            .retain(|_, at| now.saturating_sub(*at) < SESSION_RESET_INTERVAL_MS);
        let key = (RECOVERY_LIMIT.to_string(), group_id.to_string());
        if self.resent.insert(key, now).is_some() {
            return Ok(false);
        }
        self.write_repair_limits().await?;
        Ok(true)
    }
}
