//! The one acceptance check of a group change (docs/plans/pairwise-groups.md
//! §3, "Who accepts a change"): the group's server runs it before storing a
//! change, and every client runs it again, so a change the server stored is
//! never refused by an honest client and the group cannot freeze.
//!
//! It reads only the plain part: revisions, the chain, the actor's pseudonym
//! signature, roles under Signal's rules, slots and claims, the link, bans
//! and the last-administrator rule. Sealed fields are checked only for
//! shape and size; what they hold is for members to judge, and an unreadable
//! one never refuses a change.
//!
//! Pure: no clock, no storage. The request envelope (timestamps, nonces) and
//! the home's notary signature are checked by the layers around it.

use kutup_crypto::chat_group::{verify_change_signature, verify_claim_signature, HASH_LEN};

use super::{
    decode_exact, decode_group_id, decode_pseudonym, decode_sealed, encode, AccessRequired,
    GroupActionV1, GroupAttribute, GroupChangeV1, GroupMemberV1, GroupRequestV1, GroupRole,
    GroupSlotV1, GroupStateV1, GROUP_FORMAT_VERSION, INVITE_LINK_PASSWORD_LEN, MAX_GROUP_MEMBERS,
    MAX_SEALED_BAN_LIST_BYTES, MAX_SEALED_ENTRY_BYTES,
};

/// What a server allows (`CHAT_GROUP_MAX_MEMBERS`, at most 256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupLimits {
    /// Members plus pending slots.
    pub max_members: usize,
    /// Open requests to join.
    pub max_requesting: usize,
}

impl GroupLimits {
    pub const MAX: Self = Self {
        max_members: MAX_GROUP_MEMBERS,
        max_requesting: MAX_GROUP_MEMBERS,
    };
}

/// Why a change is refused. The codes are stable: the server maps them to
/// its answers, clients to their messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupChangeError {
    /// Not a well-formed change or state.
    Malformed(String),
    /// Another group's change.
    WrongGroup,
    /// Not exactly the next revision.
    WrongRevision,
    /// Doesn't follow the chain head.
    WrongPrevious,
    /// The actor's signature, or a claim's, doesn't verify.
    BadSignature,
    /// The actor isn't a member (or, for a newcomer's action, already is one).
    NotMember,
    /// The actor's role or the access rules don't allow it.
    NotAllowed,
    /// The only administrator can't leave or step down while others remain.
    LastAdministrator,
    /// The pseudonym is banned.
    Banned,
    /// The group is full, or too many requests are open.
    LimitReached,
    /// The link is off or its password is wrong.
    WrongPassword,
    /// The named pseudonym, slot or request doesn't exist.
    UnknownTarget,
    /// The group was ended.
    Terminated,
    /// The resulting state isn't the one the change names.
    StateMismatch,
}

impl GroupChangeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::WrongGroup => "wrongGroup",
            Self::WrongRevision => "wrongRevision",
            Self::WrongPrevious => "wrongPrevious",
            Self::BadSignature => "badSignature",
            Self::NotMember => "notMember",
            Self::NotAllowed => "notAllowed",
            Self::LastAdministrator => "lastAdministrator",
            Self::Banned => "banned",
            Self::LimitReached => "limitReached",
            Self::WrongPassword => "wrongPassword",
            Self::UnknownTarget => "unknownTarget",
            Self::Terminated => "terminated",
            Self::StateMismatch => "stateMismatch",
        }
    }
}

impl std::fmt::Display for GroupChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed group change: {reason}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for GroupChangeError {}

fn malformed(reason: impl Into<String>) -> GroupChangeError {
    GroupChangeError::Malformed(reason.into())
}

/// Checks revision 0 and returns the group's first state. `home_server` is
/// the server the change was sent to, which must be the one it names.
///
/// It doesn't check that the pin is that server's *current* identity
/// (sequence and document hash): only the server knows that, and checks it
/// before calling this. A client verifies the pin through the identity
/// history (`GroupHomePinV1::follow`).
pub fn check_genesis(
    change: &GroupChangeV1,
    home_server: &str,
    limits: &GroupLimits,
) -> Result<GroupStateV1, GroupChangeError> {
    verify_actor_signature(change)?;
    let state = genesis_state(change, home_server, limits)?;
    compare_hash(&state, change)?;
    Ok(state)
}

/// The state a genesis results in, for its author to name and sign; every
/// check but the signature and the named hash.
pub fn resulting_genesis_state(
    change: &GroupChangeV1,
    home_server: &str,
    limits: &GroupLimits,
) -> Result<GroupStateV1, GroupChangeError> {
    genesis_state(change, home_server, limits)
}

fn genesis_state(
    change: &GroupChangeV1,
    home_server: &str,
    limits: &GroupLimits,
) -> Result<GroupStateV1, GroupChangeError> {
    check_limits(limits)?;
    change.validate_shape().map_err(malformed)?;
    if change.revision != 0 {
        return Err(GroupChangeError::WrongRevision);
    }
    if change.previous_hash != encode(&[0u8; HASH_LEN]) {
        return Err(GroupChangeError::WrongPrevious);
    }
    let [GroupActionV1::Genesis {
        home,
        access,
        entry,
    }] = change.actions.as_slice()
    else {
        return Err(malformed("revision 0 carries one genesis action"));
    };
    if home.server != home_server {
        return Err(GroupChangeError::WrongGroup);
    }
    decode_sealed("entry", entry, MAX_SEALED_ENTRY_BYTES).map_err(malformed)?;
    let state = GroupStateV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: change.group_id.clone(),
        revision: 0,
        home: home.clone(),
        access: *access,
        announcements_only: false,
        terminated: false,
        invite_link_password: None,
        attributes: Default::default(),
        ban_list: None,
        members: vec![GroupMemberV1 {
            pseudonym: change.actor.clone(),
            role: GroupRole::Administrator,
            joined_at_revision: 0,
            entry: entry.clone(),
        }],
        slots: Vec::new(),
        requesting: Vec::new(),
        banned: Vec::new(),
    };
    state.validate().map_err(malformed)?;
    Ok(state)
}

/// Checks change `state.revision + 1` against `state`, whose last change
/// hashes to `head`, and returns the state it results in.
pub fn check_change(
    state: &GroupStateV1,
    head: &[u8; HASH_LEN],
    change: &GroupChangeV1,
    limits: &GroupLimits,
) -> Result<GroupStateV1, GroupChangeError> {
    verify_actor_signature(change)?;
    let next = next_state(state, head, change, limits)?;
    compare_hash(&next, change)?;
    Ok(next)
}

/// The state a change results in, for its author to name and sign; every
/// check but the signature and the named hash.
pub fn resulting_state(
    state: &GroupStateV1,
    head: &[u8; HASH_LEN],
    change: &GroupChangeV1,
    limits: &GroupLimits,
) -> Result<GroupStateV1, GroupChangeError> {
    next_state(state, head, change, limits)
}

fn next_state(
    state: &GroupStateV1,
    head: &[u8; HASH_LEN],
    change: &GroupChangeV1,
    limits: &GroupLimits,
) -> Result<GroupStateV1, GroupChangeError> {
    check_limits(limits)?;
    state.validate().map_err(malformed)?;
    change.validate_shape().map_err(malformed)?;
    if change.group_id != state.group_id {
        return Err(GroupChangeError::WrongGroup);
    }
    if Some(change.revision) != state.revision.checked_add(1) {
        return Err(GroupChangeError::WrongRevision);
    }
    if change.previous_hash != encode(head) {
        return Err(GroupChangeError::WrongPrevious);
    }
    if state.terminated {
        return Err(GroupChangeError::Terminated);
    }

    let mut next = state.clone();
    next.revision = change.revision;
    let actor = change.actor.as_str();
    // Roles are judged at the previous revision, as Signal's server does.
    let actor_was_member = state.member(actor).is_some();
    let actor_was_admin = state.is_administrator(actor);

    for action in &change.actions {
        if !action.is_by_newcomer() && !actor_was_member {
            return Err(GroupChangeError::NotMember);
        }
        apply(
            state,
            &mut next,
            change,
            actor,
            actor_was_admin,
            action,
            limits,
        )?;
    }
    sort_by_decoded(&mut next);
    next.validate().map_err(malformed)?;
    Ok(next)
}

fn check_limits(limits: &GroupLimits) -> Result<(), GroupChangeError> {
    if limits.max_members == 0
        || limits.max_members > MAX_GROUP_MEMBERS
        || limits.max_requesting == 0
    {
        return Err(malformed("server group limits are out of range"));
    }
    Ok(())
}

fn verify_actor_signature(change: &GroupChangeV1) -> Result<(), GroupChangeError> {
    let actor = decode_pseudonym(&change.actor).map_err(malformed)?;
    let signature = decode_exact::<64>("signature", &change.signature).map_err(malformed)?;
    let bytes = change.signed_bytes().map_err(malformed)?;
    verify_change_signature(&actor, &bytes, &signature).map_err(|_| GroupChangeError::BadSignature)
}

/// The state must be the one the change names.
fn compare_hash(next: &GroupStateV1, change: &GroupChangeV1) -> Result<(), GroupChangeError> {
    let hash = next.hash().map_err(malformed)?;
    require(
        encode(&hash) == change.resulting_state_hash,
        GroupChangeError::StateMismatch,
    )
}

/// Lists are ordered by their decoded bytes, not their base64 text.
fn sort_by_decoded(state: &mut GroupStateV1) {
    let key = |value: &str| decode_pseudonym(value).unwrap_or([0xff; 32]);
    state.members.sort_by_key(|member| key(&member.pseudonym));
    state
        .requesting
        .sort_by_key(|request| key(&request.pseudonym));
    state.banned.sort_by_key(|pseudonym| key(pseudonym));
    state
        .slots
        .sort_by_key(|slot| decode_exact::<16>("slotId", &slot.slot_id).unwrap_or([0xff; 16]));
}

fn require(condition: bool, error: GroupChangeError) -> Result<(), GroupChangeError> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}

/// Signal's access rule: `member` lets every member act, `administrator` only
/// administrators; anything else lets no one.
fn allowed(access: AccessRequired, actor_was_admin: bool) -> bool {
    match access {
        AccessRequired::Member | AccessRequired::Any => true,
        AccessRequired::Administrator => actor_was_admin,
        AccessRequired::Unsatisfiable => false,
    }
}

fn place_count(state: &GroupStateV1) -> usize {
    state.members.len() + state.slots.len()
}

fn is_banned(state: &GroupStateV1, pseudonym: &str) -> bool {
    state.banned.iter().any(|banned| banned == pseudonym)
}

/// The last-administrator rule (Signal-Desktop
/// `getCannotLeaveBecauseYouAreLastAdmin`): the only administrator can't
/// leave or step down while the group has other members.
fn last_administrator(state: &GroupStateV1, actor: &str) -> bool {
    state.is_administrator(actor)
        && state.members.len() > 1
        && !state
            .members
            .iter()
            .any(|member| member.pseudonym != actor && member.role == GroupRole::Administrator)
}

/// The link's password, compared in constant time: the server runs this on
/// every join attempt.
fn check_password(state: &GroupStateV1, password: &str) -> Result<(), GroupChangeError> {
    let offered =
        decode_exact::<INVITE_LINK_PASSWORD_LEN>("password", password).map_err(malformed)?;
    let Some(current) = &state.invite_link_password else {
        return Err(GroupChangeError::WrongPassword);
    };
    let current = decode_exact::<INVITE_LINK_PASSWORD_LEN>("inviteLinkPassword", current)
        .map_err(malformed)?;
    let difference = offered
        .iter()
        .zip(current.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    require(
        std::hint::black_box(difference) == 0,
        GroupChangeError::WrongPassword,
    )
}

fn check_newcomer(state: &GroupStateV1, actor: &str) -> Result<(), GroupChangeError> {
    require(!is_banned(state, actor), GroupChangeError::Banned)?;
    require(
        state.member(actor).is_none() && !state.requesting.iter().any(|r| r.pseudonym == actor),
        GroupChangeError::NotMember,
    )
}

fn apply(
    before: &GroupStateV1,
    next: &mut GroupStateV1,
    change: &GroupChangeV1,
    actor: &str,
    actor_was_admin: bool,
    action: &GroupActionV1,
    limits: &GroupLimits,
) -> Result<(), GroupChangeError> {
    use GroupActionV1 as A;
    match action {
        A::Genesis { .. } => Err(malformed("genesis only at revision 0")),

        A::AddSlot {
            slot_id,
            role,
            claim_key,
            entry,
        } => {
            require(
                allowed(before.access.members, actor_was_admin),
                GroupChangeError::NotAllowed,
            )?;
            require(
                *role == GroupRole::Member || actor_was_admin,
                GroupChangeError::NotAllowed,
            )?;
            decode_exact::<16>("slotId", slot_id).map_err(malformed)?;
            decode_pseudonym(claim_key).map_err(malformed)?;
            decode_sealed("entry", entry, MAX_SEALED_ENTRY_BYTES).map_err(malformed)?;
            require(
                !next.slots.iter().any(|s| &s.slot_id == slot_id),
                malformed("duplicate slot"),
            )?;
            require(
                place_count(next) < limits.max_members,
                GroupChangeError::LimitReached,
            )?;
            next.slots.push(GroupSlotV1 {
                slot_id: slot_id.clone(),
                role: *role,
                adder: actor.to_string(),
                claim_key: claim_key.clone(),
                entry: entry.clone(),
            });
            Ok(())
        }

        A::RevokeSlot { slot_id } => {
            let index = next
                .slots
                .iter()
                .position(|slot| &slot.slot_id == slot_id)
                .ok_or(GroupChangeError::UnknownTarget)?;
            require(
                actor_was_admin || next.slots[index].adder == actor,
                GroupChangeError::NotAllowed,
            )?;
            next.slots.remove(index);
            Ok(())
        }

        A::Claim {
            slot_id,
            claim_signature,
            entry,
        } => {
            check_newcomer(before, actor)?;
            let index = next
                .slots
                .iter()
                .position(|slot| &slot.slot_id == slot_id)
                .ok_or(GroupChangeError::UnknownTarget)?;
            let slot = next.slots[index].clone();
            let group = decode_group_id(&change.group_id).map_err(malformed)?;
            let slot_bytes = decode_exact::<16>("slotId", slot_id).map_err(malformed)?;
            let claim_key = decode_pseudonym(&slot.claim_key).map_err(malformed)?;
            let claimant = decode_pseudonym(actor).map_err(malformed)?;
            let signature =
                decode_exact::<64>("claimSignature", claim_signature).map_err(malformed)?;
            verify_claim_signature(&claim_key, &group, &slot_bytes, &claimant, &signature)
                .map_err(|_| GroupChangeError::BadSignature)?;
            decode_sealed("entry", entry, MAX_SEALED_ENTRY_BYTES).map_err(malformed)?;
            next.slots.remove(index);
            next.members.push(GroupMemberV1 {
                pseudonym: actor.to_string(),
                role: slot.role,
                joined_at_revision: change.revision,
                entry: entry.clone(),
            });
            Ok(())
        }

        A::JoinFromLink { password, entry } => {
            check_newcomer(before, actor)?;
            require(
                before.access.add_from_invite_link == AccessRequired::Any,
                GroupChangeError::WrongPassword,
            )?;
            check_password(before, password)?;
            decode_sealed("entry", entry, MAX_SEALED_ENTRY_BYTES).map_err(malformed)?;
            require(
                place_count(next) < limits.max_members,
                GroupChangeError::LimitReached,
            )?;
            next.members.push(GroupMemberV1 {
                pseudonym: actor.to_string(),
                role: GroupRole::Member,
                joined_at_revision: change.revision,
                entry: entry.clone(),
            });
            Ok(())
        }

        A::RequestToJoin { password, entry } => {
            check_newcomer(before, actor)?;
            require(
                before.access.add_from_invite_link == AccessRequired::Administrator,
                GroupChangeError::WrongPassword,
            )?;
            check_password(before, password)?;
            decode_sealed("entry", entry, MAX_SEALED_ENTRY_BYTES).map_err(malformed)?;
            require(
                next.requesting.len() < limits.max_requesting,
                GroupChangeError::LimitReached,
            )?;
            next.requesting.push(GroupRequestV1 {
                pseudonym: actor.to_string(),
                requested_at_revision: change.revision,
                entry: entry.clone(),
            });
            Ok(())
        }

        A::CancelRequest => {
            let index = next
                .requesting
                .iter()
                .position(|request| request.pseudonym == actor)
                .ok_or(GroupChangeError::NotMember)?;
            next.requesting.remove(index);
            Ok(())
        }

        A::ApproveRequest { pseudonym } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            let index = next
                .requesting
                .iter()
                .position(|request| &request.pseudonym == pseudonym)
                .ok_or(GroupChangeError::UnknownTarget)?;
            require(
                place_count(next) < limits.max_members,
                GroupChangeError::LimitReached,
            )?;
            let request = next.requesting.remove(index);
            next.members.push(GroupMemberV1 {
                pseudonym: request.pseudonym,
                role: GroupRole::Member,
                joined_at_revision: change.revision,
                entry: request.entry,
            });
            Ok(())
        }

        A::DenyRequest { pseudonym } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            let index = next
                .requesting
                .iter()
                .position(|request| &request.pseudonym == pseudonym)
                .ok_or(GroupChangeError::UnknownTarget)?;
            next.requesting.remove(index);
            Ok(())
        }

        A::RemoveMember { pseudonym } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            require(pseudonym != actor, malformed("a member leaves with leave"))?;
            remove_member(next, pseudonym)
        }

        A::Leave => {
            require(
                !last_administrator(next, actor),
                GroupChangeError::LastAdministrator,
            )?;
            remove_member(next, actor)
        }

        A::ModifyRole { pseudonym, role } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            if pseudonym == actor && *role == GroupRole::Member {
                require(
                    !last_administrator(next, actor),
                    GroupChangeError::LastAdministrator,
                )?;
            }
            let member = next
                .members
                .iter_mut()
                .find(|member| &member.pseudonym == pseudonym)
                .ok_or(GroupChangeError::UnknownTarget)?;
            member.role = *role;
            Ok(())
        }

        A::ModifyOwnEntry { entry } => {
            decode_sealed("entry", entry, MAX_SEALED_ENTRY_BYTES).map_err(malformed)?;
            let member = next
                .members
                .iter_mut()
                .find(|member| member.pseudonym == actor)
                .ok_or(GroupChangeError::NotMember)?;
            member.entry = entry.clone();
            Ok(())
        }

        A::ModifyAttribute { attribute, value } => {
            require(
                allowed(before.access.attributes, actor_was_admin),
                GroupChangeError::NotAllowed,
            )?;
            if let Some(value) = value {
                decode_sealed("attribute", value, attribute.max_sealed_bytes())
                    .map_err(malformed)?;
            }
            let slot = match attribute {
                GroupAttribute::Title => &mut next.attributes.title,
                GroupAttribute::Description => &mut next.attributes.description,
                GroupAttribute::Timer => &mut next.attributes.timer,
                GroupAttribute::Avatar => &mut next.attributes.avatar,
            };
            *slot = value.clone();
            Ok(())
        }

        A::ModifyAccess { access } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            next.access = *access;
            Ok(())
        }

        A::ModifyAnnouncementsOnly { on } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            next.announcements_only = *on;
            Ok(())
        }

        A::ModifyInviteLink { password } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            if let Some(password) = password {
                decode_exact::<INVITE_LINK_PASSWORD_LEN>("password", password)
                    .map_err(malformed)?;
            }
            next.invite_link_password = password.clone();
            Ok(())
        }

        A::Ban { pseudonym } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            require(pseudonym != actor, GroupChangeError::NotAllowed)?;
            decode_pseudonym(pseudonym).map_err(malformed)?;
            if next.member(pseudonym).is_some() {
                remove_member(next, pseudonym)?;
            }
            next.requesting
                .retain(|request| &request.pseudonym != pseudonym);
            if !is_banned(next, pseudonym) {
                next.banned.push(pseudonym.clone());
            }
            Ok(())
        }

        A::Unban { pseudonym } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            let before_len = next.banned.len();
            next.banned.retain(|banned| banned != pseudonym);
            require(
                next.banned.len() < before_len,
                GroupChangeError::UnknownTarget,
            )
        }

        A::ModifyBanList { value } => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            if let Some(value) = value {
                decode_sealed("banList", value, MAX_SEALED_BAN_LIST_BYTES).map_err(malformed)?;
            }
            next.ban_list = value.clone();
            Ok(())
        }

        A::Terminate => {
            require(actor_was_admin, GroupChangeError::NotAllowed)?;
            next.terminated = true;
            Ok(())
        }
    }
}

fn remove_member(next: &mut GroupStateV1, pseudonym: &str) -> Result<(), GroupChangeError> {
    let index = next
        .members
        .iter()
        .position(|member| member.pseudonym == pseudonym)
        .ok_or(GroupChangeError::UnknownTarget)?;
    next.members.remove(index);
    // Slots a removed member added stay: an administrator may still revoke them.
    Ok(())
}
