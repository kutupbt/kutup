//! Calls hosted on this server's SFU: meeting links (`call_link*`) and the
//! group calls' LiveKit tokens (docs/chat-calls.md).

pub(crate) mod call_link_history;
pub(crate) mod call_link_moderation;
pub(crate) mod call_link_waiting;
pub(crate) mod call_links;
pub(crate) mod group_calls;

pub(crate) use group_calls::{
    federated_token as federated_group_call_token, hosts_group_calls, token as group_call_token,
};
