//! The groups route's rate limits, keyed only by what each side may know:
//! the relay by its signed-in account, the gateway by relay server,
//! pseudonym and group.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::ratelimit::{
    CHAT_GROUP_CHANGES_GROUP, CHAT_GROUP_CHANGES_PSEUDONYM, CHAT_GROUP_GATEWAY_RELAY,
    CHAT_GROUP_LINK, CHAT_GROUP_PSEUDONYM, CHAT_GROUP_RELAY,
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

/// A change by `pseudonym` to the group `group_id`: both limits must allow it.
pub(crate) fn change(pseudonym: &str, group_id: &[u8; 32]) -> bool {
    CHAT_GROUP_CHANGES_PSEUDONYM.allow(pseudonym)
        && CHAT_GROUP_CHANGES_GROUP.allow(&STANDARD.encode(group_id))
}

/// A link request (join info) for the group `group_id`: link holders can't
/// flood one group.
pub(crate) fn link(group_id: &[u8; 32]) -> bool {
    CHAT_GROUP_LINK.allow(&STANDARD.encode(group_id))
}
