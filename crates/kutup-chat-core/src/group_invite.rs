//! Inviting to a group and answering an invitation
//! (docs/plans/pairwise-groups.md §4): a slot per invitee in one change, and
//! each invitee's own copy of the invitation, pairwise; accepting is a claim
//! built from the join info the slot's claim key may read, then the state.

use kutup_chat_proto::group::{decode_exact, GroupActionV1, GroupRole};
use kutup_chat_proto::group_route::{GroupJoinInfoV1, GroupOperationV1};
use kutup_chat_proto::ChatContent;
use kutup_crypto::account_ref::AccountRef;
use rand::{CryptoRng, Rng};

use crate::clock::{rfc3339, unix_millis};
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, ClaimBasis, GroupStatus};
use crate::group_engine::{accepted_body, group_error, GroupSync};

impl Engine {
    /// Invites `accounts` to the group: one change with a slot each, then
    /// each invitee's invitation, sent to them alone. Returns how many
    /// invitations went out (a failed one can be sent again).
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
            let (action, invitation, _) =
                group::invite(&record, &account_ref, GroupRole::Member).map_err(group_error)?;
            actions.push(action);
            invitations.push((account.clone(), invitation));
        }
        if actions.is_empty() {
            return Ok(0);
        }
        self.submit_group_change(&mut record, actions).await?;
        let mut sent = 0;
        for (account, invitation) in invitations {
            let send_id = uuid::Uuid::new_v4().to_string();
            let content = ChatContent::group_invite_with_id(
                send_id.clone(),
                rfc3339(unix_millis()),
                0,
                &invitation,
            );
            if self.send(&send_id, &account, &content, rng).await.is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Accepts an invitation: the join info the slot's claim key may read,
    /// the claim, then the state as a member.
    pub async fn accept_group_invite(&mut self, group_id: &str) -> Result<GroupSync> {
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
            Ok(response) => accepted_body(response)?,
            Err(failure) => return Ok(GroupSync::Unreachable(failure)),
        };
        let info = GroupJoinInfoV1::from_canonical_bytes(&info).map_err(ChatError::Invalid)?;
        let basis = ClaimBasis {
            revision: info.revision,
            head: decode_exact::<32>("head", &info.head).map_err(ChatError::Invalid)?,
        };
        let me = self.session.account_ref().clone();
        let device_id = self.session.device_id();
        let profile_key = self.own_profile_key().await?;
        let session = &self.session;
        let sign = |bytes: &[u8]| session.sign_with_identity(bytes).map_err(|e| e.to_string());
        let change = group::claim(&mut record, &basis, &me, device_id, &profile_key, &sign)
            .map_err(group_error)?;
        let body = change.canonical_bytes().map_err(ChatError::Invalid)?;
        match self
            .group_request(&mut record, GroupOperationV1::SubmitChange, &body)
            .await?
        {
            Ok(response) => {
                accepted_body(response)?;
            }
            Err(failure) => return Ok(GroupSync::Unreachable(failure)),
        }
        // Saved with the claim's revision as the lowest state to take; the
        // claim key goes once the state shows this account a member.
        self.save_group(&record).await?;
        self.take_whole_state(&mut record).await
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
    pub async fn leave_group(&mut self, group_id: &str) -> Result<()> {
        let mut record = self.load_group_record(group_id).await?;
        self.submit_group_change(&mut record, vec![GroupActionV1::Leave])
            .await?;
        Ok(())
    }
}
