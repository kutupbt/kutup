//! Durable server-side MLS routing state.
//!
//! MLS cryptography remains client-side. Focused submodules own policy,
//! control persistence, federation, private membership delivery, mailboxes,
//! anonymous delivery, abuse limits, and operational inspection.

mod admin_routes;
mod anonymous_federation;
mod anonymous_routes;
mod authority_bootstrap;
mod control_federation;
mod control_routes;
mod control_store;
mod conversation_store;
mod delivery_store;
mod federation_control;
mod invitation_routes;
mod mailbox_routes;
mod membership;
mod package_routes;
mod package_store;
mod participant_bootstrap;
mod policy;
mod rate_limits;
mod retry;
mod util;

pub(crate) use admin_routes::{conversation as admin_conversation, status as admin_status};
pub(crate) use anonymous_federation::{
    federated_get_anonymous_key_packages, federated_submit_anonymous_message,
};
pub(crate) use anonymous_routes::{get_anonymous_key_packages, submit_anonymous_message};
pub(crate) use authority_bootstrap::federated_stage_authority_bootstrap;
use authority_bootstrap::{bootstrap_finalized_authority, bootstrap_new_authorities};
pub(crate) use control_federation::{
    federated_cast_ordering_vote, federated_commit_control_block, federated_replicate_genesis,
};
pub(crate) use control_routes::{
    collect_ordering_votes, commit_control_block, create_conversation,
};
use federation_control::{replicate_genesis, request_remote_ordering_vote};
pub(crate) use invitation_routes::{list_invitations, respond_invitation};
pub(crate) use mailbox_routes::{ack as ack_mailbox, drain as drain_mailbox};
use membership::prepare_membership_finalization;
pub(crate) use membership::stage_membership_delivery;
pub(crate) use package_routes::{
    key_package_count, publish_delivery_capability, publish_key_packages,
};
pub(crate) use participant_bootstrap::federated_stage_participant_bootstrap;
pub(crate) use policy::MlsOrderingService;
use policy::{active_policy, authenticated_remote_policy};
use rate_limits::increment_counter;
pub(crate) use retry::spawn_retry_worker;
use util::{
    decode_canonical_base64, decode_capability, ensure_anonymous_context, scoped_digest,
    unavailable, validate_participant_domains,
};

#[cfg(test)]
use axum::http::header::{AUTHORIZATION, COOKIE};
#[cfg(test)]
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::Response;
use sqlx::PgPool;

use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationStack};

const MAX_DEVICE_ID: u32 = 127;

#[derive(Clone)]
pub(crate) struct MlsRepository {
    pool: PgPool,
}

impl MlsRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn signed_federation_json<T: serde::Serialize>(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    status: StatusCode,
    value: &T,
) -> AppResult<Response> {
    let body = serde_json::to_vec(value).map_err(|error| {
        AppError::internal(format!("serialize MLS federation response: {error}"))
    })?;
    federation.signed_response(authenticated, status, "application/json", body)
}

fn signed_federation_error(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    error: AppError,
) -> AppResult<Response> {
    let message = if error.status.is_server_error() {
        tracing::error!(status = %error.status, error = %error.message, "MLS federation request failed");
        "internal server error".to_owned()
    } else {
        error.message
    };
    signed_federation_json(
        federation,
        authenticated,
        error.status,
        &serde_json::json!({ "error": message }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_context_is_explicitly_rejected() {
        let mut headers = HeaderMap::new();
        assert!(ensure_anonymous_context(&headers).is_ok());
        headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(ensure_anonymous_context(&headers).is_err());
        headers.remove(AUTHORIZATION);
        headers.insert(COOKIE, "session=secret".parse().unwrap());
        assert!(ensure_anonymous_context(&headers).is_err());
    }

    #[test]
    fn scoped_rate_digests_are_purpose_separated() {
        let value = [7u8; 32];
        assert_ne!(
            scoped_digest(b"kutup/mls/rate/minute/v1", &value),
            scoped_digest(b"kutup/mls/rate/day/v1", &value)
        );
    }
}
