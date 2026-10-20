//! Joining a group through its invite link (docs/plans/pairwise-groups.md §4,
//! "Invite link", and §11): the link holder reads the group's join info under
//! the link's proof, then joins (`ANY`) or asks an administrator
//! (`ADMINISTRATOR`) under a new pseudonym, at the join epoch a claim would
//! take and with the same `pseudonymUsed` retry.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group::link::GroupInviteLinkV1;
use kutup_chat_proto::group::{
    decode_exact, decode_group_id, AccessRequired, GroupAccessV1, GroupActionV1,
    INVITE_LINK_PASSWORD_LEN,
};
use kutup_chat_proto::group_route::{
    GroupJoinInfoV1, GroupOperationV1, GroupRequestStateV1, GroupRequestStatusV1,
    GroupResponseStatusV1, GroupResponseV1, PSEUDONYM_USED,
};
use kutup_crypto::chat_group::SealedField;
use rand::{CryptoRng, Rng};

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, ClaimBasis, GroupRecordV1, GroupStatus};
use crate::group_client::{self, RequestSigner, RouteFailure};
use crate::group_engine::{accepted_body, group_error, now_seconds, GroupSync};

/// What a link holder sees before joining: the group's name and
/// description as its members wrote them (opened with the link's key), how
/// many are in it, and whether an administrator must approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLinkPreview {
    pub group_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub member_count: u16,
    pub requires_approval: bool,
    /// This account's place in the group already, if it has one here.
    pub status: Option<GroupStatus>,
}

/// Where this account's request to join stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupRequestOutcome {
    /// Still waiting for an administrator.
    Pending,
    /// Approved: in the group now.
    Joined(GroupSync),
    /// Turned down (or removed since): the group is `gone` here.
    Denied,
    /// Withdrawn: the group is `gone` here.
    Canceled,
    /// The home couldn't be asked now.
    Unreachable(RouteFailure),
}

/// What a join through a link came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupLinkJoin {
    /// In the group.
    Joined(GroupSync),
    /// Asked; an administrator sees it at their next sync.
    Requested,
    /// The link no longer works (reset, or turned off), or the group is gone.
    LinkInvalid,
    /// The home couldn't be asked now.
    Unreachable(RouteFailure),
}

fn opened_text(
    record: &GroupRecordV1,
    field: SealedField,
    value: &Option<String>,
) -> Option<String> {
    let value = value.as_ref()?;
    let key = record.master().ok()?.state_key();
    let plain = key.open(field, b"", &STANDARD.decode(value).ok()?).ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

/// The group a link names.
fn link_group_id(link: &GroupInviteLinkV1) -> Result<String> {
    let master = kutup_crypto::chat_group::GroupMasterKey::from_bytes(
        &link.master_key,
        group::home_of(&link.home),
    )
    .map_err(|error| ChatError::Invalid(error.to_string()))?;
    Ok(kutup_chat_proto::group::encode_group_id(&master.group_id()))
}

fn used_pseudonym(response: &GroupResponseV1) -> bool {
    response.status == GroupResponseStatusV1::Refused
        && response.code.as_deref() == Some(PSEUDONYM_USED)
}

impl Engine {
    /// The home's answer about this record's request, signed by its
    /// pseudonym.
    async fn request_status(
        &mut self,
        record: &mut GroupRecordV1,
    ) -> Result<std::result::Result<GroupRequestStatusV1, RouteFailure>> {
        match self
            .group_request(record, GroupOperationV1::GetRequestStatus, b"")
            .await?
        {
            Ok(response) => {
                let body = accepted_body(response)?;
                Ok(Ok(GroupRequestStatusV1::from_canonical_bytes(&body)
                    .map_err(ChatError::Invalid)?))
            }
            Err(failure) => Ok(Err(failure)),
        }
    }

    /// Where a request stands, settled here: an approved request takes the
    /// group's state (a member now), a denied or unknown one ends as `gone`.
    pub async fn check_group_request(&mut self, group_id: &str) -> Result<GroupRequestOutcome> {
        let mut record = self.load_group_record(group_id).await?;
        if record.status != GroupStatus::Requesting {
            return Err(ChatError::Invalid("no request to join is waiting".into()));
        }
        let status = match self.request_status(&mut record).await? {
            Ok(status) => status,
            Err(failure) => return Ok(GroupRequestOutcome::Unreachable(failure)),
        };
        self.settle_request(&mut record, status).await
    }

    /// Withdraws a waiting request (a `CancelRequest` at the revision the
    /// home's status names, so it works after a link reset too). Already
    /// approved or denied: settled as [`Self::check_group_request`] does.
    pub async fn cancel_group_request(&mut self, group_id: &str) -> Result<GroupRequestOutcome> {
        let mut record = self.load_group_record(group_id).await?;
        if record.status != GroupStatus::Requesting {
            return Err(ChatError::Invalid("no request to join is waiting".into()));
        }
        // Raced by an approval or a denial meanwhile: asked once more.
        for _ in 0..2 {
            let status = match self.request_status(&mut record).await? {
                Ok(status) => status,
                Err(failure) => return Ok(GroupRequestOutcome::Unreachable(failure)),
            };
            let (GroupRequestStateV1::Pending, Some(revision), Some(head)) =
                (status.status, status.revision, status.head.as_deref())
            else {
                return self.settle_request(&mut record, status).await;
            };
            let basis = ClaimBasis {
                revision,
                head: decode_exact::<32>("head", head).map_err(ChatError::Invalid)?,
            };
            let change = group::cancel_change(&record, &basis).map_err(group_error)?;
            let body = change.canonical_bytes().map_err(ChatError::Invalid)?;
            match self
                .group_request(&mut record, GroupOperationV1::SubmitChange, &body)
                .await?
            {
                Ok(response) if response.status == GroupResponseStatusV1::Ok => {
                    record.status = GroupStatus::Gone;
                    self.save_group(&record).await?;
                    return Ok(GroupRequestOutcome::Canceled);
                }
                // The log moved on (another change came first): again.
                Ok(response)
                    if response.status == GroupResponseStatusV1::Conflict
                        || response.code.as_deref() == Some("wrongRevision") =>
                {
                    continue
                }
                Ok(response) => {
                    accepted_body(response)?;
                }
                Err(failure) => return Ok(GroupRequestOutcome::Unreachable(failure)),
            }
        }
        Ok(GroupRequestOutcome::Pending)
    }

    async fn settle_request(
        &mut self,
        record: &mut GroupRecordV1,
        status: GroupRequestStatusV1,
    ) -> Result<GroupRequestOutcome> {
        match status.status {
            GroupRequestStateV1::Pending => Ok(GroupRequestOutcome::Pending),
            GroupRequestStateV1::Member => {
                let sync = self.take_whole_state(record).await?;
                self.list_after(&record.group_id.clone(), &sync).await;
                Ok(GroupRequestOutcome::Joined(sync))
            }
            GroupRequestStateV1::Denied | GroupRequestStateV1::Unknown => {
                record.status = GroupStatus::Gone;
                self.save_group(record).await?;
                Ok(GroupRequestOutcome::Denied)
            }
        }
    }

    /// The record a link would join with, and the link itself.
    async fn link_record(&mut self, fragment: &str) -> Result<(GroupInviteLinkV1, GroupRecordV1)> {
        let link = GroupInviteLinkV1::from_fragment(fragment).map_err(ChatError::Invalid)?;
        // The list says which epoch a join goes past, and whether another
        // device is in already.
        self.reread_group_list().await;
        let group_id = link_group_id(&link)?;
        let previous = self.session.db().load_group(&group_id).await?;
        let record = group::record_from_link(
            &link,
            previous.as_ref(),
            self.listed_join(&group_id),
            self.group_keys()?,
        )
        .map_err(group_error)?;
        Ok((link, record))
    }

    /// The group's join info under the link's proof.
    async fn link_join_info(
        &mut self,
        record: &mut GroupRecordV1,
        link: &GroupInviteLinkV1,
    ) -> Result<std::result::Result<Option<GroupJoinInfoV1>, RouteFailure>> {
        let group_id = decode_group_id(&record.group_id).map_err(ChatError::Invalid)?;
        let home = record.home.clone();
        let transport = std::rc::Rc::clone(&self.transport);
        let answer = group_client::call(
            transport.as_ref(),
            &mut record.gateway,
            &home,
            &group_id,
            GroupOperationV1::GetJoinInfo,
            b"",
            &RequestSigner::LinkPassword(&link.password),
            now_seconds(),
        )
        .await?;
        Ok(match answer {
            // The link is off, its password reset, or the group gone: the
            // home says the same for each.
            Ok(response) if response.status == GroupResponseStatusV1::NotFound => Ok(None),
            Ok(response) => {
                let body = accepted_body(response)?;
                Ok(Some(
                    GroupJoinInfoV1::from_canonical_bytes(&body).map_err(ChatError::Invalid)?,
                ))
            }
            Err(failure) => Err(failure),
        })
    }

    /// What `fragment`'s link leads to, read before joining. `None`: the link
    /// no longer works.
    pub async fn preview_group_link(
        &mut self,
        fragment: &str,
    ) -> Result<std::result::Result<Option<GroupLinkPreview>, RouteFailure>> {
        let link = GroupInviteLinkV1::from_fragment(fragment).map_err(ChatError::Invalid)?;
        let existing = self.session.db().load_group(&link_group_id(&link)?).await?;
        // A member reads the join info under the link too (what anyone with
        // it sees), with its own record's gateway; no record is made.
        let (link, mut record) = match &existing {
            Some(existing) if existing.status == GroupStatus::Member => {
                if existing.home != link.home {
                    return Err(ChatError::Invalid("the link names another group".into()));
                }
                (link, existing.clone())
            }
            _ => self.link_record(fragment).await?,
        };
        let info = match self.link_join_info(&mut record, &link).await? {
            Ok(Some(info)) => info,
            Ok(None) => return Ok(Ok(None)),
            Err(failure) => return Ok(Err(failure)),
        };
        Ok(Ok(Some(GroupLinkPreview {
            group_id: record.group_id.clone(),
            title: opened_text(&record, SealedField::Title, &info.title),
            description: opened_text(&record, SealedField::Description, &info.description),
            member_count: info.member_count,
            requires_approval: info.requires_approval.unwrap_or(false),
            status: existing.map(|existing| existing.status),
        })))
    }

    /// Joins `fragment`'s group (or asks to, when an administrator must
    /// approve): a new pseudonym at the next join epoch, moved on once more
    /// for each `pseudonymUsed`, never past the last epoch.
    pub async fn join_group_by_link<R: Rng + CryptoRng>(
        &mut self,
        fragment: &str,
        rng: &mut R,
    ) -> Result<GroupLinkJoin> {
        let (link, mut record) = self.link_record(fragment).await?;
        let info = match self.link_join_info(&mut record, &link).await? {
            Ok(Some(info)) => info,
            Ok(None) => return Ok(GroupLinkJoin::LinkInvalid),
            Err(failure) => return Ok(GroupLinkJoin::Unreachable(failure)),
        };
        let approval = info.requires_approval.unwrap_or(false);
        let basis = ClaimBasis {
            revision: info.revision,
            head: decode_exact::<32>("head", &info.head).map_err(ChatError::Invalid)?,
        };
        let me = self.session.account_ref().clone();
        let profile_key = self.own_profile_key().await?;
        // Saved first, so a reload never goes back to an epoch it used.
        self.save_group(&record).await?;
        loop {
            let change = group::link_change(
                &mut record,
                &basis,
                &link.password,
                approval,
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
                Ok(response) if used_pseudonym(&response) => {
                    let next = group::within_join_epochs(record.join_epoch.saturating_add(1))
                        .map_err(group_error)?;
                    self.move_link_epoch(&mut record, next).await?;
                }
                // The password no longer holds (reset meanwhile), or the
                // access changed: the link is no longer this one.
                Ok(response) if response.status == GroupResponseStatusV1::NotFound => {
                    return Ok(GroupLinkJoin::LinkInvalid)
                }
                Ok(response) if response.status != GroupResponseStatusV1::Ok => {
                    accepted_body(response)?;
                }
                Ok(_) => break,
                Err(failure) => return Ok(GroupLinkJoin::Unreachable(failure)),
            }
        }
        if approval {
            record.status = GroupStatus::Requesting;
            self.save_group(&record).await?;
            return Ok(GroupLinkJoin::Requested);
        }
        self.save_group(&record).await?;
        let sync = self.take_whole_state(&mut record).await?;
        if matches!(sync, GroupSync::Current { .. }) {
            let group_id = record.group_id.clone();
            self.announce_group_change(&group_id, rng).await;
        }
        self.list_after(&record.group_id.clone(), &sync).await;
        Ok(GroupLinkJoin::Joined(sync))
    }

    /// Moves a link join to `epoch`: the pseudonym the account key gives
    /// there.
    async fn move_link_epoch(&mut self, record: &mut GroupRecordV1, epoch: u32) -> Result<()> {
        let group = decode_group_id(&record.group_id).map_err(ChatError::Invalid)?;
        let pseudonym = self.group_keys()?.pseudonyms.pseudonym(&group, epoch);
        record.join_epoch = epoch;
        record.pseudonym_seed =
            group::SecretText(kutup_chat_proto::group::encode(pseudonym.seed()));
        self.save_group(record).await
    }
}

/// What a group's invite link does (Signal's `addFromInviteLink`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupLinkMode {
    Off,
    /// Anyone with the link joins.
    Join,
    /// Anyone with the link asks; an administrator approves.
    Approve,
}

impl GroupLinkMode {
    fn access(self) -> AccessRequired {
        match self {
            Self::Off => AccessRequired::Unsatisfiable,
            Self::Join => AccessRequired::Any,
            Self::Approve => AccessRequired::Administrator,
        }
    }
}

/// The link as the group's last verified state has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLinkSettings {
    pub mode: GroupLinkMode,
    /// The URL fragment to share, while the link is on.
    pub fragment: Option<String>,
}

pub(crate) fn new_password<R: Rng + CryptoRng>(rng: &mut R) -> String {
    let mut password = [0u8; INVITE_LINK_PASSWORD_LEN];
    rng.fill_bytes(&mut password);
    let text = kutup_chat_proto::group::encode(&password);
    zeroize::Zeroize::zeroize(&mut password);
    text
}

impl Engine {
    /// The group's link, from the last verified state.
    pub async fn group_link(&self, group_id: &str) -> Result<GroupLinkSettings> {
        let record = self.load_group_record(group_id).await?;
        let Some((state, _)) = record.verified().map_err(group_error)? else {
            return Ok(GroupLinkSettings {
                mode: GroupLinkMode::Off,
                fragment: None,
            });
        };
        let mode = match state.access.add_from_invite_link {
            AccessRequired::Any => GroupLinkMode::Join,
            AccessRequired::Administrator => GroupLinkMode::Approve,
            _ => GroupLinkMode::Off,
        };
        let fragment = match (&state.invite_link_password, mode) {
            (Some(password), GroupLinkMode::Join | GroupLinkMode::Approve) => {
                let master = record.master().map_err(group_error)?;
                let link = GroupInviteLinkV1 {
                    master_key: *master.as_bytes(),
                    password: decode_exact::<INVITE_LINK_PASSWORD_LEN>(
                        "inviteLinkPassword",
                        password,
                    )
                    .map_err(ChatError::Invalid)?,
                    home: record.home.clone(),
                };
                Some(link.to_fragment().map_err(ChatError::Invalid)?)
            }
            _ => None,
        };
        Ok(GroupLinkSettings { mode, fragment })
    }

    /// Turns the link on (with a password, the first time), switches
    /// between joining and asking, or turns it off; as Signal, off keeps
    /// the password, so turning it on again gives the same link.
    pub async fn set_group_link<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        mode: GroupLinkMode,
        rng: &mut R,
    ) -> Result<()> {
        let record = self.load_group_record(group_id).await?;
        let (state, _) = record
            .verified()
            .map_err(group_error)?
            .ok_or_else(|| ChatError::Invalid("the group isn't caught up".into()))?;
        let mut actions = Vec::new();
        if mode != GroupLinkMode::Off && state.invite_link_password.is_none() {
            actions.push(GroupActionV1::ModifyInviteLink {
                password: Some(new_password(rng)),
            });
        }
        if state.access.add_from_invite_link != mode.access() {
            actions.push(GroupActionV1::ModifyAccess {
                access: GroupAccessV1 {
                    add_from_invite_link: mode.access(),
                    ..state.access
                },
            });
        }
        if actions.is_empty() {
            return Ok(());
        }
        self.change_group(group_id, actions, rng).await
    }

    /// A new password: the old link stops working (Signal's "Reset link").
    pub async fn reset_group_link<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) -> Result<()> {
        let password = new_password(rng);
        self.change_group(
            group_id,
            vec![GroupActionV1::ModifyInviteLink {
                password: Some(password),
            }],
            rng,
        )
        .await
    }
}
