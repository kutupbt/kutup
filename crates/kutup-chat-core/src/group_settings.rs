//! A pairwise group's settings and its administrators' actions
//! (docs/plans/pairwise-groups.md §4 and §11, "Slice 3"): the description and
//! timer, who may edit and add, announcements-only, requests to join through
//! the link, bans by pseudonym and by account, and ending the group. Each is
//! one change, announced to the members as any change is.

use kutup_chat_proto::group::{
    AccessRequired, GroupAccessV1, GroupActionV1, GroupAttribute, GroupBanListV1, GroupChangeError,
    GroupRole, GroupStateV1, MAX_ACTIONS_PER_CHANGE, MAX_GROUP_DESCRIPTION_CHARS,
};
use kutup_crypto::account_ref::AccountRef;
use rand::{CryptoRng, Rng};

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, GroupRecordV1, GroupRequesterView};
use crate::group_engine::group_error;
use crate::group_link::GroupLinkSettings;

/// A request to join, as an administrator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRequestView {
    pub requester: GroupRequesterView,
    /// Its account is on the ban list: it can't be approved.
    pub banned: bool,
}

/// A ban: an account (with the pseudonyms banned for it), or a pseudonym
/// whose account nobody verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBanView {
    pub account: Option<AccountRef>,
    pub pseudonyms: Vec<String>,
}

/// What a group's settings screen shows, from the last verified state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDetails {
    pub group_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// The disappearing-messages timer in seconds; 0 is off.
    pub timer_seconds: u32,
    pub announcements_only: bool,
    pub terminated: bool,
    pub access: GroupAccessV1,
    pub link: GroupLinkSettings,
    /// This account is an administrator.
    pub administrator: bool,
    pub requests: Vec<GroupRequestView>,
    pub bans: Vec<GroupBanView>,
    /// Members whose account is banned (back through the link under a new
    /// pseudonym): administrators are asked to remove them.
    pub banned_members: Vec<String>,
    /// The sealed ban list has no room for another account: a ban or a
    /// denial now holds for the person's pseudonym only, until a ban is
    /// lifted.
    pub ban_list_full: bool,
    /// The group has an avatar.
    pub has_avatar: bool,
}

fn text_attribute(record: &GroupRecordV1, attribute: GroupAttribute) -> Option<String> {
    group::attribute(record, attribute)
        .ok()
        .flatten()
        .and_then(|plain| String::from_utf8(plain).ok())
}

/// The timer's sealed form: `u32` seconds, big-endian (Signal's
/// `DisappearingMessagesTimer.duration`).
pub fn timer_seconds(record: &GroupRecordV1) -> u32 {
    group::attribute(record, GroupAttribute::Timer)
        .ok()
        .flatten()
        .and_then(|plain| <[u8; 4]>::try_from(plain.as_slice()).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0)
}

fn verified_state(record: &GroupRecordV1) -> Result<GroupStateV1> {
    Ok(record
        .verified()
        .map_err(group_error)?
        .ok_or_else(|| ChatError::Invalid("the group isn't caught up".into()))?
        .0)
}

fn limit_reached() -> ChatError {
    group_error(group::GroupError::Change(GroupChangeError::LimitReached))
}

impl Engine {
    /// The group's settings, its requests (each binding checked) and its
    /// bans.
    pub async fn group_details(&mut self, group_id: &str) -> Result<GroupDetails> {
        let record = self.load_group_record(group_id).await?;
        let state = verified_state(&record)?;
        let me = record.pseudonym_text().map_err(group_error)?;
        let bans = group::ban_list(&record).map_err(group_error)?;
        let requests = self.checked_requesters(&record).await?;
        let (members, _) = self.group_members_checked(group_id).await?;
        let banned_members = members
            .iter()
            .filter(|member| {
                member
                    .verified
                    .as_ref()
                    .is_some_and(|verified| bans.get(&verified.account).is_some())
            })
            .map(|member| member.pseudonym.clone())
            .collect();
        Ok(GroupDetails {
            group_id: group_id.to_string(),
            title: text_attribute(&record, GroupAttribute::Title),
            description: text_attribute(&record, GroupAttribute::Description),
            timer_seconds: timer_seconds(&record),
            announcements_only: state.announcements_only,
            terminated: state.terminated,
            access: state.access,
            link: self.group_link(group_id).await?,
            administrator: state.is_administrator(&me),
            requests: requests
                .into_iter()
                .map(|requester| GroupRequestView {
                    banned: requester
                        .verified
                        .as_ref()
                        .is_some_and(|verified| bans.get(&verified.account).is_some()),
                    requester,
                })
                .collect(),
            ban_list_full: group::ban_list_full(&bans),
            has_avatar: state.attributes.avatar.is_some(),
            bans: ban_views(&state, &bans),
            banned_members,
        })
    }

    async fn checked_requesters(
        &mut self,
        record: &GroupRecordV1,
    ) -> Result<Vec<GroupRequesterView>> {
        let accounts = group::request_accounts(record).map_err(group_error)?;
        let (keys, _, _) = self.authority_keys(&accounts, &[]).await?;
        group::requesters(record, &|account: &AccountRef| keys.get(account).copied())
            .map_err(group_error)
    }

    async fn requester(&mut self, group_id: &str, pseudonym: &str) -> Result<GroupRequesterView> {
        let record = self.load_group_record(group_id).await?;
        self.checked_requesters(&record)
            .await?
            .into_iter()
            .find(|requester| requester.pseudonym == pseudonym)
            .ok_or_else(|| ChatError::Invalid("no such request".into()))
    }

    /// Sets the description (Signal's limit); empty removes it.
    pub async fn set_group_description<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        description: &str,
        rng: &mut R,
    ) -> Result<()> {
        let description = description.trim();
        if description.chars().count() > MAX_GROUP_DESCRIPTION_CHARS
            || description
                .chars()
                .any(|character| character.is_control() && character != '\n')
        {
            return Err(ChatError::Invalid(format!(
                "a group description is at most {MAX_GROUP_DESCRIPTION_CHARS} characters"
            )));
        }
        let record = self.load_group_record(group_id).await?;
        let value = if description.is_empty() {
            None
        } else {
            Some(
                group::seal_attribute(&record, GroupAttribute::Description, description.as_bytes())
                    .map_err(group_error)?,
            )
        };
        self.change_group(
            group_id,
            vec![GroupActionV1::ModifyAttribute {
                attribute: GroupAttribute::Description,
                value,
                avatar_hash: None,
            }],
            rng,
        )
        .await
    }

    /// Sets the disappearing-messages timer; 0 turns it off.
    pub async fn set_group_timer<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        seconds: u32,
        rng: &mut R,
    ) -> Result<()> {
        let record = self.load_group_record(group_id).await?;
        let value = if seconds == 0 {
            None
        } else {
            Some(
                group::seal_attribute(&record, GroupAttribute::Timer, &seconds.to_be_bytes())
                    .map_err(group_error)?,
            )
        };
        self.change_group(
            group_id,
            vec![GroupActionV1::ModifyAttribute {
                attribute: GroupAttribute::Timer,
                value,
                avatar_hash: None,
            }],
            rng,
        )
        .await
    }

    /// Who may edit the group's details, and who may add members: members
    /// or administrators only.
    pub async fn set_group_access<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        attributes: AccessRequired,
        members: AccessRequired,
        rng: &mut R,
    ) -> Result<()> {
        let record = self.load_group_record(group_id).await?;
        let state = verified_state(&record)?;
        let access = GroupAccessV1 {
            attributes,
            members,
            ..state.access
        };
        if access == state.access {
            return Ok(());
        }
        self.change_group(group_id, vec![GroupActionV1::ModifyAccess { access }], rng)
            .await
    }

    /// Only administrators send, when on.
    pub async fn set_group_announcements_only<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        on: bool,
        rng: &mut R,
    ) -> Result<()> {
        self.change_group(
            group_id,
            vec![GroupActionV1::ModifyAnnouncementsOnly { on }],
            rng,
        )
        .await
    }

    /// Lets a requester in. A request whose binding names a banned account
    /// is refused here: the home can't know accounts, so this is where the
    /// ban holds.
    pub async fn approve_group_request<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        pseudonym: &str,
        rng: &mut R,
    ) -> Result<()> {
        let requester = self.requester(group_id, pseudonym).await?;
        let record = self.load_group_record(group_id).await?;
        let bans = group::ban_list(&record).map_err(group_error)?;
        if requester
            .verified
            .as_ref()
            .is_some_and(|verified| bans.get(&verified.account).is_some())
        {
            return Err(ChatError::Invalid(
                "this account is banned from the group".into(),
            ));
        }
        self.change_group(
            group_id,
            vec![GroupActionV1::ApproveRequest {
                pseudonym: pseudonym.to_string(),
            }],
            rng,
        )
        .await
    }

    /// Turns a request down and bans its pseudonym from the link, as Signal
    /// does; its account goes on the ban list when its binding verified.
    pub async fn deny_group_request<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        pseudonym: &str,
        rng: &mut R,
    ) -> Result<()> {
        let requester = self.requester(group_id, pseudonym).await?;
        let record = self.load_group_record(group_id).await?;
        let mut actions = vec![
            GroupActionV1::DenyRequest {
                pseudonym: pseudonym.to_string(),
            },
            GroupActionV1::Ban {
                pseudonym: pseudonym.to_string(),
            },
        ];
        if let Some(verified) = &requester.verified {
            actions.extend(banned_list_action(&record, &verified.account, pseudonym)?);
        }
        self.change_group(group_id, actions, rng).await
    }

    /// Removes and bans a member: its pseudonym (which the home refuses
    /// from then on) and, when its binding verified, its account. With
    /// `reset_link` (the default in the UI) the link's password changes in
    /// the same change, so a link the banned person kept stops working.
    pub async fn ban_group_member<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        pseudonym: &str,
        reset_link: bool,
        rng: &mut R,
    ) -> Result<()> {
        let account = self
            .group_members(group_id)
            .await?
            .into_iter()
            .find(|member| member.pseudonym == pseudonym)
            .ok_or_else(|| ChatError::Invalid("no such member".into()))?
            .verified
            .map(|verified| verified.account);
        let record = self.load_group_record(group_id).await?;
        let state = verified_state(&record)?;
        let mut actions = vec![GroupActionV1::Ban {
            pseudonym: pseudonym.to_string(),
        }];
        if let Some(account) = &account {
            actions.extend(banned_list_action(&record, account, pseudonym)?);
        }
        if reset_link && state.invite_link_password.is_some() {
            actions.push(GroupActionV1::ModifyInviteLink {
                password: Some(crate::group_link::new_password(rng)),
            });
        }
        self.change_group(group_id, actions, rng).await
    }

    /// Lifts a ban: an account's (with every pseudonym banned for it), or a
    /// lone pseudonym's.
    pub async fn unban_group<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        ban: &GroupBanView,
        rng: &mut R,
    ) -> Result<()> {
        let record = self.load_group_record(group_id).await?;
        let state = verified_state(&record)?;
        let mut pseudonyms = ban.pseudonyms.clone();
        let mut actions = Vec::new();
        if let Some(account) = &ban.account {
            let mut bans = group::ban_list(&record).map_err(group_error)?;
            let Some(entry) = bans.unban(account) else {
                return Err(ChatError::Invalid("this account isn't banned".into()));
            };
            pseudonyms = entry.pseudonyms;
            actions.push(GroupActionV1::ModifyBanList {
                value: group::seal_ban_list(&record, &bans).map_err(group_error)?,
            });
        }
        for pseudonym in pseudonyms {
            if state.banned.contains(&pseudonym) {
                actions.push(GroupActionV1::Unban { pseudonym });
            }
        }
        if actions.is_empty() {
            return Ok(());
        }
        if actions.len() > MAX_ACTIONS_PER_CHANGE {
            return Err(limit_reached());
        }
        self.change_group(group_id, actions, rng).await
    }

    /// Ends the group for everyone (Signal's `terminated`): no change or
    /// message after this one.
    pub async fn end_group<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) -> Result<()> {
        self.change_group(group_id, vec![GroupActionV1::Terminate], rng)
            .await
    }

    /// Removes every member whose binding didn't verify, and every member
    /// whose account is banned: the one tap against a link-join flood. Not
    /// while some member's manifest can't be fetched (they would be taken
    /// as unverified). How many were removed.
    pub async fn remove_unverified_group_members<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) -> Result<usize> {
        let (members, unconfirmed) = self.group_members_checked(group_id).await?;
        if !unconfirmed.is_empty() {
            return Err(ChatError::Transport(
                "some members can't be checked now; try again later".into(),
            ));
        }
        let record = self.load_group_record(group_id).await?;
        let me = record.pseudonym_text().map_err(group_error)?;
        let bans = group::ban_list(&record).map_err(group_error)?;
        let gone: Vec<String> = members
            .into_iter()
            .filter(|member| member.pseudonym != me && member.role != GroupRole::Administrator)
            .filter(|member| {
                member
                    .verified
                    .as_ref()
                    .is_none_or(|verified| bans.get(&verified.account).is_some())
            })
            .map(|member| member.pseudonym)
            .collect();
        for part in gone.chunks(MAX_ACTIONS_PER_CHANGE) {
            let actions = part
                .iter()
                .map(|pseudonym| GroupActionV1::RemoveMember {
                    pseudonym: pseudonym.clone(),
                })
                .collect();
            self.change_group(group_id, actions, rng).await?;
        }
        Ok(gone.len())
    }
}

/// The ban list with `account` (and `pseudonym`) added, as an action;
/// `None` when it has no room left ([`GroupDetails::ban_list_full`] says so
/// beforehand): the ban then holds for the pseudonym only, which the home
/// enforces.
fn banned_list_action(
    record: &GroupRecordV1,
    account: &AccountRef,
    pseudonym: &str,
) -> Result<Option<GroupActionV1>> {
    let mut bans = group::ban_list(record).map_err(group_error)?;
    bans.ban(account, Some(pseudonym));
    if bans.get(account).is_some_and(|banned| {
        banned.pseudonyms.len() > kutup_chat_proto::group::entry::MAX_BANNED_PSEUDONYMS_PER_ACCOUNT
    }) {
        return Ok(None);
    }
    match group::seal_ban_list(record, &bans) {
        Ok(value) => Ok(Some(GroupActionV1::ModifyBanList { value })),
        Err(group::GroupError::Change(GroupChangeError::LimitReached)) => Ok(None),
        Err(error) => Err(group_error(error)),
    }
}

/// The bans: each account on the list, then each banned pseudonym no
/// listed account holds.
fn ban_views(state: &GroupStateV1, bans: &GroupBanListV1) -> Vec<GroupBanView> {
    let mut views: Vec<GroupBanView> = bans
        .banned
        .iter()
        .map(|banned| GroupBanView {
            account: Some(banned.account.clone()),
            pseudonyms: banned.pseudonyms.clone(),
        })
        .collect();
    for pseudonym in &state.banned {
        if !bans
            .banned
            .iter()
            .any(|banned| banned.pseudonyms.contains(pseudonym))
        {
            views.push(GroupBanView {
                account: None,
                pseudonyms: vec![pseudonym.clone()],
            });
        }
    }
    views
}
