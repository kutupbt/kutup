//! Inviting to a group and answering an invitation
//! (docs/plans/pairwise-groups.md §4): a slot per invitee in one change, and
//! each invitee's own copy of the invitation, pairwise; accepting is a claim
//! built from the join info the slot's claim key may read, then the state.

use kutup_chat_proto::group::{decode_exact, GroupActionV1, GroupRole};
use kutup_chat_proto::group_route::{GroupJoinInfoV1, GroupOperationV1, GroupResponseStatusV1};
use kutup_chat_proto::ChatContent;
use kutup_crypto::account_ref::AccountRef;
use rand::{CryptoRng, Rng};

use crate::clock::{rfc3339, unix_millis};
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, ClaimBasis, GroupRecordV1, GroupStatus};
use crate::group_engine::{accepted_body, group_error, GroupSync};

impl Engine {
    /// Invites `accounts` to the group: one change with a slot each, then
    /// each invitee's invitation, sealed to their devices alone. The
    /// invitation carries the slot's claim key, so nothing of it is kept: no
    /// history, no outbox, no copy for this account's other devices (they
    /// learn of the slot from the log). Only contacts can be invited (their
    /// profile key is what the sealed delivery needs), as in Signal. A slot
    /// whose invitation didn't go out is revoked; returns how many went out.
    pub async fn invite_to_group<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        accounts: &[String],
        rng: &mut R,
    ) -> Result<usize> {
        let mut record = self.load_group_record(group_id).await?;
        if record.status != GroupStatus::Member {
            return Err(ChatError::Invalid(
                "this account isn't a member of the group".into(),
            ));
        }
        let mut actions = Vec::new();
        let mut invitations = Vec::new();
        for account in accounts {
            let account_ref: AccountRef = account
                .parse()
                .map_err(|_| ChatError::Invalid("not an account".into()))?;
            let capability = self
                .media_delivery_capability(account)
                .await?
                .ok_or_else(|| {
                    ChatError::Invalid("only contacts can be invited to a group".into())
                })?;
            let (action, invitation, _) =
                group::invite(&record, &account_ref, GroupRole::Member).map_err(group_error)?;
            actions.push(action);
            invitations.push((account.clone(), capability, invitation));
        }
        if actions.is_empty() {
            return Ok(0);
        }
        self.submit_group_change(&mut record, actions).await?;
        let mut sent = 0;
        let mut revoke = Vec::new();
        for (account, capability, invitation) in invitations {
            let content = ChatContent::group_invite_with_id(
                uuid::Uuid::new_v4().to_string(),
                rfc3339(unix_millis()),
                0,
                &invitation,
            );
            match self
                .send_sealed_pairwise(&account, &capability, None, &content, rng)
                .await
            {
                Ok(true) => sent += 1,
                Ok(false) | Err(_) => revoke.push(GroupActionV1::RevokeSlot {
                    slot_id: invitation.slot_id.clone(),
                }),
            }
        }
        if !revoke.is_empty() {
            // Best effort: an unclaimed slot is harmless, and an administrator
            // can revoke it later.
            let _ = self.submit_group_change(&mut record, revoke).await;
        }
        self.announce_group_change(group_id, rng).await;
        Ok(sent)
    }

    /// Accepts an invitation: the join info the slot's claim key may read,
    /// the claim, then the state as a member, and a change notice so the
    /// members know at once.
    pub async fn accept_group_invite<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) -> Result<GroupSync> {
        let sync = self.claim_group_invite(group_id).await?;
        if matches!(sync, GroupSync::Current { .. }) {
            self.announce_group_change(group_id, rng).await;
        }
        self.list_after(group_id, &sync).await;
        Ok(sync)
    }

    async fn claim_group_invite(&mut self, group_id: &str) -> Result<GroupSync> {
        let mut record = self.load_group_record(group_id).await?;
        if !matches!(record.status, GroupStatus::Invited { .. }) {
            return Err(ChatError::Invalid("no invitation to this group".into()));
        }
        let claim_key =
            zeroize::Zeroizing::new(group::claim_key_seed(&record).map_err(group_error)?);
        // The gateway key is fetched through the invitation's pin first.
        let info = match self
            .group_request_signed(&mut record, GroupOperationV1::GetJoinInfo, b"", &claim_key)
            .await?
        {
            // The slot is gone: perhaps another device of this account
            // claimed it, under the same pseudonym.
            Ok(response) if response.status == GroupResponseStatusV1::NotFound => {
                return self.claimed_elsewhere(&mut record).await;
            }
            Ok(response) => accepted_body(response)?,
            Err(failure) => return Ok(GroupSync::Unreachable(failure)),
        };
        let info = GroupJoinInfoV1::from_canonical_bytes(&info).map_err(ChatError::Invalid)?;
        let basis = ClaimBasis {
            revision: info.revision,
            head: decode_exact::<32>("head", &info.head).map_err(ChatError::Invalid)?,
        };
        let me = self.session.account_ref().clone();
        let profile_key = self.own_profile_key().await?;
        let change = group::claim(
            &mut record,
            &basis,
            &me,
            &profile_key,
            &self.group_keys()?.authority,
        )
        .map_err(group_error)?;
        let body = change.canonical_bytes().map_err(ChatError::Invalid)?;
        match self
            .group_request(&mut record, GroupOperationV1::SubmitChange, &body)
            .await?
        {
            Ok(response) if response.status != GroupResponseStatusV1::Ok => {
                // Refused: perhaps another device of this account claimed
                // the slot first.
                let refused = accepted_body(response).err();
                let sync = self.claimed_elsewhere(&mut record).await;
                return match (sync, refused) {
                    (Err(_), Some(refused)) => Err(refused),
                    (sync, _) => sync,
                };
            }
            Ok(_) => {}
            Err(failure) => return Ok(GroupSync::Unreachable(failure)),
        }
        // Saved with the claim's revision as the lowest state to take; the
        // claim key goes once the state shows this account a member.
        self.save_group(&record).await?;
        self.take_whole_state(&mut record).await
    }

    /// Whether this account is in the group already under the invitation's
    /// pseudonym: another of its devices claimed the slot at the same time,
    /// and pseudonyms are derived, so it's this device's too.
    async fn claimed_elsewhere(&mut self, record: &mut GroupRecordV1) -> Result<GroupSync> {
        match self.probe_whole_state(record).await? {
            Some(sync) => Ok(sync),
            None => Err(ChatError::Invalid(
                "the invitation was taken back or has expired".into(),
            )),
        }
    }

    /// Declines an invitation: the record is kept as gone, without its
    /// claim key, and nothing is sent.
    pub async fn decline_group_invite(&mut self, group_id: &str) -> Result<()> {
        let mut record = self.load_group_record(group_id).await?;
        if !matches!(record.status, GroupStatus::Invited { .. }) {
            return Err(ChatError::Invalid("no invitation to this group".into()));
        }
        record.status = GroupStatus::Gone;
        self.save_group(&record).await
    }

    /// Leaves the group (Signal's last-administrator rule applies: the home
    /// refuses the last administrator's leave while others remain).
    pub async fn leave_group<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) -> Result<()> {
        self.change_group(group_id, vec![GroupActionV1::Leave], rng)
            .await?;
        let _ = self.schedule_group_entry(group_id).await;
        // Nothing of the group is sent again: its send log goes, all but a
        // change notice still on its way.
        let mut pending = crate::db::Pending::default();
        for entry in self.session.db().list_group_outbox().await? {
            let notice = serde_json::from_slice::<ChatContent>(&entry.content)
                .is_ok_and(|content| content.kind == kutup_chat_proto::content::kind::GROUP_CHANGE);
            let undelivered = entry.legs.iter().any(|leg| !leg.delivered);
            if entry.group_id == group_id && !(notice && undelivered) {
                pending.group_outbox.insert(entry.send_id, None);
            }
        }
        self.session.db().apply(&pending).await
    }
}
