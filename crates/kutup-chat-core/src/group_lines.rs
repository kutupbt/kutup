//! Timeline lines for a pairwise group's changes ("Alice renamed the group",
//! "Bob joined through the group link"): derived on each device from a
//! change it verified and the states before and after it, written locally
//! as `groupUpdate` rows (the kind the MLS groups use), never sent, and
//! refused on every receive path. Only accounts whose binding verified are
//! named: a change by, or about, an unverified pseudonym gets no line about
//! it (the member list shows such members as unverified).

use std::collections::{BTreeMap, BTreeSet};

use kutup_chat_proto::group::{
    AccessRequired, GroupActionV1, GroupAttribute, GroupBanListV1, GroupChangeV1, GroupRole,
    GroupStateV1,
};
use kutup_chat_proto::{GroupUpdateBody, GroupUpdateChange};
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::chat_group::{GroupStateKey, SealedField};

use crate::group::{self, AuthorityOf, GroupRecordV1};

/// A change this device verified, with the states around it.
pub(crate) struct Applied {
    pub before: GroupStateV1,
    pub change: GroupChangeV1,
    pub after: GroupStateV1,
}

/// Every pseudonym's sealed entry in either state (members and requests).
fn entries(applied: &Applied) -> BTreeMap<&str, &str> {
    let mut entries = BTreeMap::new();
    for state in [&applied.before, &applied.after] {
        for member in &state.members {
            entries.insert(member.pseudonym.as_str(), member.entry.as_str());
        }
        for request in &state.requesting {
            entries.insert(request.pseudonym.as_str(), request.entry.as_str());
        }
    }
    entries
}

/// The accounts the entries around `applied` name, unverified: whose keys
/// to fetch before [`update_body`] checks them.
pub(crate) fn named_accounts(
    record: &GroupRecordV1,
    applied: &[Applied],
) -> Result<Vec<AccountRef>, group::GroupError> {
    let key = record.master()?.state_key();
    let mut accounts = BTreeSet::new();
    for one in applied {
        for (pseudonym, entry) in entries(one) {
            if let Some(account) = claimed_account(&key, pseudonym, entry) {
                accounts.insert(account);
            }
        }
    }
    Ok(accounts.into_iter().collect())
}

fn claimed_account(key: &GroupStateKey, pseudonym: &str, entry: &str) -> Option<AccountRef> {
    let pseudonym = kutup_chat_proto::group::decode_exact::<32>("pseudonym", pseudonym).ok()?;
    let sealed = base64_decode(entry)?;
    let plain = key
        .open(SealedField::MemberEntry, &pseudonym, &sealed)
        .ok()?;
    kutup_chat_proto::group::GroupMemberEntryV1::from_canonical_bytes(&plain)
        .ok()
        .map(|entry| entry.account)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

fn ban_accounts(key: &GroupStateKey, state: &GroupStateV1) -> BTreeSet<AccountRef> {
    state
        .ban_list
        .as_deref()
        .and_then(base64_decode)
        .and_then(|sealed| key.open(SealedField::BanList, b"", &sealed).ok())
        .and_then(|plain| GroupBanListV1::from_canonical_bytes(&plain).ok())
        .map(|list| {
            list.banned
                .into_iter()
                .map(|banned| banned.account)
                .collect()
        })
        .unwrap_or_default()
}

fn opened_text(key: &GroupStateKey, field: SealedField, value: &Option<String>) -> Option<String> {
    let plain = key
        .open(field, b"", &base64_decode(value.as_deref()?)?)
        .ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

fn timer(key: &GroupStateKey, value: &Option<String>) -> u32 {
    value
        .as_deref()
        .and_then(base64_decode)
        .and_then(|sealed| key.open(SealedField::Timer, b"", &sealed).ok())
        .and_then(|plain| <[u8; 4]>::try_from(&plain[..]).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0)
}

/// The line for one verified change, or `None` when it changes nothing a
/// member sees, or its actor's binding didn't verify.
pub(crate) fn update_body(
    record: &GroupRecordV1,
    applied: &Applied,
    authority_of: &AuthorityOf<'_>,
) -> Option<GroupUpdateBody> {
    let key = record.master().ok()?.state_key();
    let group_id = kutup_chat_proto::group::decode_group_id(&record.group_id).ok()?;
    let entries = entries(applied);
    let account = |pseudonym: &str| {
        group::open_member(
            &key,
            &group_id,
            pseudonym,
            entries.get(pseudonym)?,
            authority_of,
        )
        .map(|verified| verified.account)
    };
    let actor = account(&applied.change.actor)?;
    let (before, after) = (&applied.before, &applied.after);
    let mut changes = Vec::new();
    let mut denied = BTreeSet::new();
    let mut invited = 0u16;
    let mut revoked = 0u16;
    for action in &applied.change.actions {
        match action {
            GroupActionV1::Claim { .. } => changes.push(GroupUpdateChange::JoinedByInvitation),
            GroupActionV1::JoinFromLink { .. } => changes.push(GroupUpdateChange::JoinedFromLink),
            GroupActionV1::RequestToJoin { .. } => changes.push(GroupUpdateChange::JoinRequested),
            GroupActionV1::CancelRequest => changes.push(GroupUpdateChange::JoinRequestCanceled),
            GroupActionV1::AddSlot { .. } => invited = invited.saturating_add(1),
            GroupActionV1::RevokeSlot { .. } => revoked = revoked.saturating_add(1),
            GroupActionV1::ApproveRequest { pseudonym } => {
                if let Some(member) = account(pseudonym) {
                    changes.push(GroupUpdateChange::JoinRequestApproved { member });
                }
            }
            GroupActionV1::DenyRequest { pseudonym } => {
                if let Some(member) = account(pseudonym) {
                    denied.insert(member.clone());
                    changes.push(GroupUpdateChange::JoinRequestDenied { member });
                }
            }
            GroupActionV1::RemoveMember { pseudonym } => {
                if let Some(member) = account(pseudonym) {
                    changes.push(GroupUpdateChange::MemberRemoved { member });
                }
            }
            GroupActionV1::Leave => changes.push(GroupUpdateChange::MemberLeft {
                member: actor.clone(),
            }),
            GroupActionV1::ModifyRole { pseudonym, role } => {
                if let Some(member) = account(pseudonym) {
                    changes.push(if *role == GroupRole::Administrator {
                        GroupUpdateChange::AdminGranted { member }
                    } else {
                        GroupUpdateChange::AdminRevoked { member }
                    });
                }
            }
            GroupActionV1::ModifyAttribute { attribute, .. } => match attribute {
                GroupAttribute::Title => {
                    if let Some(name) =
                        opened_text(&key, SealedField::Title, &after.attributes.title)
                    {
                        changes.push(GroupUpdateChange::NameChanged { name });
                    }
                }
                GroupAttribute::Description => {
                    changes.push(GroupUpdateChange::DescriptionChanged {
                        description: opened_text(
                            &key,
                            SealedField::Description,
                            &after.attributes.description,
                        )
                        .unwrap_or_default(),
                    })
                }
                GroupAttribute::Avatar => changes.push(GroupUpdateChange::PictureChanged {
                    removed: after.attributes.avatar.is_none(),
                }),
                GroupAttribute::Timer => changes.push(GroupUpdateChange::TimerChanged {
                    seconds: timer(&key, &after.attributes.timer),
                }),
            },
            GroupActionV1::ModifyAccess { access } => {
                let was = before.access;
                if was.attributes != access.attributes {
                    changes.push(GroupUpdateChange::EditorsChanged {
                        administrators_only: access.attributes == AccessRequired::Administrator,
                    });
                }
                if was.members != access.members {
                    changes.push(GroupUpdateChange::AddersChanged {
                        administrators_only: access.members == AccessRequired::Administrator,
                    });
                }
                let on = |access: AccessRequired| access != AccessRequired::Unsatisfiable;
                let approval = access.add_from_invite_link == AccessRequired::Administrator;
                match (
                    on(was.add_from_invite_link),
                    on(access.add_from_invite_link),
                ) {
                    (false, true) => changes.push(GroupUpdateChange::InviteLinkEnabled {
                        approval_required: approval,
                    }),
                    (true, false) => changes.push(GroupUpdateChange::InviteLinkDisabled),
                    (true, true) if was.add_from_invite_link != access.add_from_invite_link => {
                        changes.push(GroupUpdateChange::InviteLinkApprovalChanged {
                            approval_required: approval,
                        })
                    }
                    _ => {}
                }
            }
            GroupActionV1::ModifyAnnouncementsOnly { on } => {
                if before.announcements_only != *on {
                    changes.push(GroupUpdateChange::SendersChanged {
                        administrators_only: *on,
                    });
                }
            }
            // A new password while the link is on: the old link stops
            // working. Setting the first one comes with turning it on.
            GroupActionV1::ModifyInviteLink { .. } => {
                if before.invite_link_password.is_some()
                    && before.invite_link_password != after.invite_link_password
                    && after.access.add_from_invite_link != AccessRequired::Unsatisfiable
                {
                    changes.push(GroupUpdateChange::InviteLinkReset);
                }
            }
            GroupActionV1::Terminate => changes.push(GroupUpdateChange::Closed),
            // Bans and unbans are read from the ban list below; a ban by
            // pseudonym alone names nobody.
            GroupActionV1::Ban { .. }
            | GroupActionV1::Unban { .. }
            | GroupActionV1::ModifyBanList { .. }
            | GroupActionV1::ModifyOwnEntry { .. }
            | GroupActionV1::Genesis { .. } => {}
        }
    }
    if invited > 0 {
        changes.push(GroupUpdateChange::MembersInvited { count: invited });
    }
    if revoked > 0 {
        changes.push(GroupUpdateChange::InvitationsRevoked { count: revoked });
    }
    let (was_banned, now_banned) = (ban_accounts(&key, before), ban_accounts(&key, after));
    for member in now_banned.difference(&was_banned) {
        // A denial bans too, and says so already.
        if !denied.contains(member) {
            changes.push(GroupUpdateChange::MemberBanned {
                member: member.clone(),
            });
        }
    }
    for member in was_banned.difference(&now_banned) {
        changes.push(GroupUpdateChange::MemberUnbanned {
            member: member.clone(),
        });
    }
    (!changes.is_empty()).then_some(GroupUpdateBody { actor, changes })
}
