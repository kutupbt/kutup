//! Timeline notices for applied group changes ("Alice renamed the group",
//! "Alice added Bob"). They are derived locally from the pinned conversation
//! record before and after one authenticated, ordered Commit, so a member
//! cannot forge one by sending a message: the `groupUpdate` kind is refused
//! on every receive path.

use super::*;
use kutup_chat_proto::{GroupUpdateBody, GroupUpdateChange, MlsApplicationSenderPolicyV1};

/// The parts of a pinned record a member sees change.
pub(super) struct GroupFacts<'a> {
    pub roster: &'a [MlsConversationMemberV1],
    pub info: &'a Option<MlsGroupInfoV1>,
    pub policy: &'a MlsGroupAuthorizationPolicyV1,
    pub closed: bool,
}

impl<'a> From<&'a LocalMlsConversationRecord> for GroupFacts<'a> {
    fn from(record: &'a LocalMlsConversationRecord) -> Self {
        Self {
            roster: &record.current_roster,
            info: &record.current_group_info,
            policy: &record.current_authorization_policy,
            closed: record.status == LocalMlsConversationStatus::Closed,
        }
    }
}

/// What changed between two pinned records, in the order a reader expects:
/// the group's information, then membership, then roles, then rules.
/// `departed` names members whose removal they asked for themselves.
pub(super) fn group_update_changes(
    previous: &GroupFacts<'_>,
    next: &GroupFacts<'_>,
    departed: &BTreeSet<String>,
) -> Vec<GroupUpdateChange> {
    let mut changes = Vec::new();
    let (before, after) = (previous.info, next.info);
    if before.as_ref().map(|info| &info.name) != after.as_ref().map(|info| &info.name) {
        if let Some(info) = after {
            changes.push(GroupUpdateChange::NameChanged {
                name: info.name.clone(),
            });
        }
    }
    let description = |info: &Option<MlsGroupInfoV1>| {
        info.as_ref()
            .map(|info| info.description.clone())
            .unwrap_or_default()
    };
    if description(before) != description(after) {
        changes.push(GroupUpdateChange::DescriptionChanged {
            description: description(after),
        });
    }
    let avatar = |info: &Option<MlsGroupInfoV1>| info.as_ref().and_then(|info| info.avatar.clone());
    if avatar(before) != avatar(after) {
        changes.push(GroupUpdateChange::PictureChanged {
            removed: avatar(after).is_none(),
        });
    }

    let roster = |facts: &GroupFacts<'_>| {
        facts
            .roster
            .iter()
            .map(|member| (member.address.canonical(), member.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let (before_roster, after_roster) = (roster(previous), roster(next));
    for (address, _) in after_roster
        .iter()
        .filter(|(address, _)| !before_roster.contains_key(*address))
    {
        changes.push(GroupUpdateChange::MemberAdded {
            member: address.clone(),
        });
    }
    for (address, _) in before_roster
        .iter()
        .filter(|(address, _)| !after_roster.contains_key(*address))
    {
        changes.push(if departed.contains(address) {
            GroupUpdateChange::MemberLeft {
                member: address.clone(),
            }
        } else {
            GroupUpdateChange::MemberRemoved {
                member: address.clone(),
            }
        });
    }
    for (address, after_member) in &after_roster {
        let Some(before_member) = before_roster.get(address) else {
            continue;
        };
        match (before_member.is_admin, after_member.is_admin) {
            (false, true) => changes.push(GroupUpdateChange::AdminGranted {
                member: address.clone(),
            }),
            (true, false) => changes.push(GroupUpdateChange::AdminRevoked {
                member: address.clone(),
            }),
            _ => {}
        }
        match (
            before_member.owner_id.is_some(),
            after_member.owner_id.is_some(),
        ) {
            (false, true) => changes.push(GroupUpdateChange::OwnerAdded {
                member: address.clone(),
            }),
            (true, false) => changes.push(GroupUpdateChange::OwnerRemoved {
                member: address.clone(),
            }),
            _ => {}
        }
    }

    let link =
        |info: &Option<MlsGroupInfoV1>| info.as_ref().and_then(|info| info.invite_link.clone());
    match (link(before), link(after)) {
        (None, Some(link)) => changes.push(GroupUpdateChange::InviteLinkEnabled {
            approval_required: link.approval_required,
        }),
        (Some(_), None) => changes.push(GroupUpdateChange::InviteLinkDisabled),
        (Some(old), Some(new)) => {
            if old.secret != new.secret || old.host != new.host {
                changes.push(GroupUpdateChange::InviteLinkReset);
            }
            if old.approval_required != new.approval_required {
                changes.push(GroupUpdateChange::InviteLinkApprovalChanged {
                    approval_required: new.approval_required,
                });
            }
        }
        (None, None) => {}
    }

    let (before_policy, after_policy) = (previous.policy, next.policy);
    if before_policy.application_senders != after_policy.application_senders {
        changes.push(GroupUpdateChange::SendersChanged {
            administrators_only: after_policy.application_senders
                == MlsApplicationSenderPolicyV1::Administrators,
        });
    }
    if before_policy.group_info_editors != after_policy.group_info_editors {
        changes.push(GroupUpdateChange::EditorsChanged {
            administrators_only: !after_policy.may_edit_group_info(false),
        });
    }
    if !previous.closed && next.closed {
        changes.push(GroupUpdateChange::Closed);
    }
    changes
}

/// The history row for one applied Commit's visible changes, or `None` when
/// it changed nothing a member sees (a device sync, an authority change).
/// Its id is derived from the block, so applying the same Commit twice
/// writes the same row.
pub(super) fn group_update_record(
    previous: &LocalMlsConversationRecord,
    next: &LocalMlsConversationRecord,
    block: &MlsControlBlockV1,
    actor: &str,
    actor_device_id: u32,
    local_address: &str,
    departed: &BTreeSet<String>,
) -> Result<Option<MlsHistoryMessage>> {
    let changes = group_update_changes(&previous.into(), &next.into(), departed);
    if changes.is_empty() {
        return Ok(None);
    }
    notice_record(
        next,
        format!(
            "ctl:{}:{}:{}",
            block.conversation_id, block.incarnation, block.height
        ),
        block.epoch_after,
        block.block_hash().map_err(ChatError::Protocol)?.as_bytes(),
        GroupUpdateBody {
            actor: actor.to_owned(),
            changes,
        },
        actor_device_id,
        local_address,
    )
    .map(Some)
}

/// "You left the group." on this account's devices: the removal Commit
/// never reaches the member it removes, so the notice is written when the
/// leave is asked for (here, or on another of the account's devices).
pub(super) fn left_notice_record(
    conversation: &LocalMlsConversationRecord,
    local_address: &str,
    local_device_id: u32,
    epoch: u64,
) -> Result<MlsHistoryMessage> {
    let joined = conversation
        .member_joined_epochs
        .get(local_address)
        .copied()
        .unwrap_or_default();
    let record_id = format!(
        "left:{}:{}:{}",
        conversation.request.genesis.conversation_id,
        conversation.request.genesis.incarnation,
        joined
    );
    notice_record(
        conversation,
        record_id.clone(),
        epoch,
        record_id.as_bytes(),
        GroupUpdateBody {
            actor: local_address.to_owned(),
            changes: vec![GroupUpdateChange::MemberLeft {
                member: local_address.to_owned(),
            }],
        },
        local_device_id,
        local_address,
    )
}

/// One notice row. Its id is derived from `record_id`, so writing the same
/// notice twice keeps one row.
fn notice_record(
    conversation: &LocalMlsConversationRecord,
    record_id: String,
    epoch: u64,
    digest_material: &[u8],
    body: GroupUpdateBody,
    actor_device_id: u32,
    local_address: &str,
) -> Result<MlsHistoryMessage> {
    let digest = Sha256::digest(record_id.as_bytes());
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    let message_id = Uuid::from_bytes(id).to_string();
    let now_ms = crate::clock::unix_millis();
    let content = ChatContent::group_update_with_id(&message_id, now_ms.to_string(), &body)
        .map_err(ChatError::Content)?;
    let mut transport_digest = [0_u8; 32];
    transport_digest.copy_from_slice(&Sha256::digest(digest_material));
    Ok(MlsHistoryMessage {
        record_id,
        message_id,
        conversation_id: *conversation.request.genesis.conversation_id.as_bytes(),
        incarnation: conversation.request.genesis.incarnation,
        mls_group_id: BASE64
            .decode(&conversation.request.genesis.mls_group_id)
            .map_err(|_| ChatError::Db("pinned MLS GroupId is not base64".into()))?,
        epoch,
        outgoing: body.actor == local_address,
        sender: body.actor,
        sender_device_id: actor_device_id,
        cursor: None,
        transport_digest,
        content: serde_json::to_vec(&content)
            .map_err(|error| ChatError::Content(error.to_string()))?,
        timestamp_ms: now_ms,
        delivered: true,
        deduplicated: false,
    })
}

/// The notice for a Commit this device made and the ordering finalized.
pub(super) fn local_group_update(
    metadata: &SnapshotMetadata,
    previous: &LocalMlsConversationRecord,
    next: &LocalMlsConversationRecord,
    block: &MlsControlBlockV1,
) -> Result<Option<MlsHistoryMessage>> {
    let (local_address, local_device) =
        parse_device_credential_identity(&metadata.credential_identity)?;
    group_update_record(
        previous,
        next,
        block,
        &local_address,
        local_device,
        &local_address,
        &previous.departing_members,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_chat_proto::MlsGroupInfoEditorsV1;

    fn member(address: &str, is_admin: bool, owner: Option<&str>) -> MlsConversationMemberV1 {
        MlsConversationMemberV1 {
            address: address.parse().unwrap(),
            is_admin,
            owner_id: owner.map(str::to_owned),
        }
    }

    fn info(name: &str, description: &str) -> Option<MlsGroupInfoV1> {
        Some(MlsGroupInfoV1 {
            sequence: 1,
            name: name.into(),
            description: description.into(),
            avatar: None,
            invite_link: None,
        })
    }

    #[test]
    fn describes_what_one_commit_changed() {
        let policy = MlsGroupAuthorizationPolicyV1::members_default();
        let before_roster = vec![
            member("ali@a.test", true, Some("o1")),
            member("bob@b.test", false, None),
            member("cem@c.test", false, None),
        ];
        let after_roster = vec![
            member("ali@a.test", true, Some("o1")),
            member("bob@b.test", true, None),
            member("dan@d.test", false, None),
        ];
        let (before_info, after_info) = (info("Hikers", ""), info("Hikers 2", "walks"));
        let after_policy = MlsGroupAuthorizationPolicyV1 {
            sequence: 2,
            application_senders: MlsApplicationSenderPolicyV1::Administrators,
            group_info_editors: MlsGroupInfoEditorsV1::Members,
            ..policy.clone()
        };
        let before = GroupFacts {
            roster: &before_roster,
            info: &before_info,
            policy: &policy,
            closed: false,
        };
        let after = GroupFacts {
            roster: &after_roster,
            info: &after_info,
            policy: &after_policy,
            closed: true,
        };
        let departed = BTreeSet::from(["cem@c.test".to_string()]);
        assert_eq!(
            group_update_changes(&before, &after, &departed),
            vec![
                GroupUpdateChange::NameChanged {
                    name: "Hikers 2".into()
                },
                GroupUpdateChange::DescriptionChanged {
                    description: "walks".into()
                },
                GroupUpdateChange::MemberAdded {
                    member: "dan@d.test".into()
                },
                GroupUpdateChange::MemberLeft {
                    member: "cem@c.test".into()
                },
                GroupUpdateChange::AdminGranted {
                    member: "bob@b.test".into()
                },
                GroupUpdateChange::SendersChanged {
                    administrators_only: true
                },
                GroupUpdateChange::EditorsChanged {
                    administrators_only: false
                },
                GroupUpdateChange::Closed,
            ]
        );
        assert!(group_update_changes(&before, &before, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn describes_group_link_changes() {
        let policy = MlsGroupAuthorizationPolicyV1::members_default();
        let roster = vec![member("ali@a.test", true, Some("o1"))];
        let with = |secret: u8, approval_required: bool| {
            info("Hikers", "").map(|info| MlsGroupInfoV1 {
                invite_link: Some(kutup_chat_proto::MlsGroupInviteLinkV1 {
                    secret: BASE64.encode([secret; 32]),
                    host: "a.test".into(),
                    approval_required,
                }),
                ..info
            })
        };
        let changes = |before: &Option<MlsGroupInfoV1>, after: &Option<MlsGroupInfoV1>| {
            let facts = |info| GroupFacts {
                roster: &roster,
                info,
                policy: &policy,
                closed: false,
            };
            group_update_changes(&facts(before), &facts(after), &BTreeSet::new())
        };
        let off = info("Hikers", "");
        assert_eq!(
            changes(&off, &with(1, true)),
            vec![GroupUpdateChange::InviteLinkEnabled {
                approval_required: true
            }]
        );
        assert_eq!(
            changes(&with(1, true), &with(2, false)),
            vec![
                GroupUpdateChange::InviteLinkReset,
                GroupUpdateChange::InviteLinkApprovalChanged {
                    approval_required: false
                },
            ]
        );
        assert_eq!(
            changes(&with(1, true), &off),
            vec![GroupUpdateChange::InviteLinkDisabled]
        );
    }
}
