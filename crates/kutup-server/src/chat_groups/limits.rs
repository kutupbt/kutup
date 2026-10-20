//! The groups route's rate limits, keyed only by what each side may know:
//! the relay by its signed-in account, the gateway by relay server,
//! pseudonym and group.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::ratelimit::{
    CHAT_GROUP_CHANGES_GROUP, CHAT_GROUP_CHANGES_PSEUDONYM, CHAT_GROUP_CREATES_RELAY,
    CHAT_GROUP_FAILURES_RELAY, CHAT_GROUP_GATEWAY_RELAY, CHAT_GROUP_LINK,
    CHAT_GROUP_LINK_JOINS_RELAY, CHAT_GROUP_PSEUDONYM, CHAT_GROUP_RELAY,
};

/// A signed-in account relaying a request.
pub(crate) fn relaying_user(user_id: &str) -> bool {
    CHAT_GROUP_RELAY.allow(user_id)
}

/// A request arriving through the relay server `relay`.
pub(crate) fn relay(relay: &str) -> bool {
    CHAT_GROUP_GATEWAY_RELAY.allow(relay)
}

/// A request signed by `pseudonym`.
pub(crate) fn pseudonym(pseudonym: &str) -> bool {
    CHAT_GROUP_PSEUDONYM.allow(pseudonym)
}

/// A change by `pseudonym` to the group `group_id` that passed its checks:
/// both limits must allow it. Charged only for valid changes, so nobody can
/// spend a group's budget with changes that would be refused.
pub(crate) fn change(pseudonym: &str, group_id: &[u8; 32]) -> bool {
    CHAT_GROUP_CHANGES_PSEUDONYM.allow(pseudonym)
        && CHAT_GROUP_CHANGES_GROUP.allow(&STANDARD.encode(group_id))
}

/// A link request (join info) for the group `group_id` whose password proof
/// passed: link holders can't flood one group, and strangers can't spend
/// its budget.
pub(crate) fn link(group_id: &[u8; 32]) -> bool {
    CHAT_GROUP_LINK.allow(&STANDARD.encode(group_id))
}

/// A join from a link or a request to join through the relay server
/// `relay`, under the administrators' budget `per_minute`: one server's
/// users can't flood the groups here with newcomers.
pub(crate) fn link_join(relay: &str, per_minute: i64) -> bool {
    CHAT_GROUP_LINK_JOINS_RELAY
        .allow_up_to(relay, usize::try_from(per_minute).unwrap_or(usize::MAX))
}

/// Whether the relay server `relay` may still fail: checked before a request
/// is worked on, charged by [`failed`] when it fails.
pub(crate) fn may_fail(relay: &str) -> bool {
    CHAT_GROUP_FAILURES_RELAY.has_room(relay)
}

/// A request through `relay` failed.
pub(crate) fn failed(relay: &str) {
    CHAT_GROUP_FAILURES_RELAY.allow(relay);
}

/// A new group through `relay`.
pub(crate) fn create(relay: &str) -> bool {
    CHAT_GROUP_CREATES_RELAY.allow(relay)
}
