//! Chat groups on their home server (docs/plans/pairwise-groups.md): the
//! state and its change log under the home's notary, reached only through
//! the anonymous route. Members are per-group pseudonyms; nothing here holds
//! an account id. Off unless `CHAT_GROUPS` is on.

pub(crate) mod gateway;
pub(crate) mod keys;
mod limits;
pub(crate) mod routes;
