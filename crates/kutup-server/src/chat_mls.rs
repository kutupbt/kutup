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
mod control_history;
mod control_routes;
mod control_store;
mod conversation_store;
mod delivery_store;
mod federation_control;
mod identified_packages;
mod invitation_feedback;
mod invitation_routes;
mod mailbox_routes;
mod membership;
mod package_routes;
mod package_store;
mod participant_bootstrap;
pub(crate) mod policy;
mod rate_limits;
mod recovery_routes;
mod recovery_store;
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
pub(crate) use control_history::get_control_history;
pub(crate) use control_routes::{
    collect_ordering_votes, commit_control_block, create_conversation,
};
use federation_control::{replicate_genesis, request_remote_ordering_vote};
pub(crate) use identified_packages::{
    federated_get_identified_key_packages, get_identified_key_packages,
};
pub(crate) use invitation_feedback::{
    federated_record_invitation_feedback, list_invitation_feedback,
};
pub(crate) use invitation_routes::{list_invitations, respond_invitation};
pub(crate) use mailbox_routes::{ack as ack_mailbox, drain as drain_mailbox};
use membership::prepare_membership_finalization;
pub(crate) use membership::stage_membership_delivery;
pub(crate) use package_routes::{
    key_package_count, publish_delivery_capability, publish_key_packages,
};
pub(crate) use participant_bootstrap::federated_stage_participant_bootstrap;
use policy::{active_policy, authenticated_remote_policy};
pub(crate) use policy::{get_policy_history, MlsOrderingService};
use rate_limits::increment_counter;
pub(crate) use recovery_routes::{
    federated_recover_conversation, get_recovery, recover_conversation,
};
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
use kutup_chat_proto::ChatWsServerMessage;
use sqlx::PgPool;
use uuid::Uuid;

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationStack};
use crate::AppState;

const MAX_DEVICE_ID: u32 = 127;
const MLS_SUITE_SQL: i16 =
    kutup_chat_proto::MLS_CIPHERSUITE_X25519_CHACHA20POLY1305_SHA256_ED25519 as i16;

#[derive(Clone)]
pub(crate) struct MlsRepository {
    pool: PgPool,
}

impl MlsRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Authenticated origin and local-policy context for one finalized MLS block.
struct CommitControlContext<'a> {
    local_domain: &'a str,
    local_submitter: Option<Uuid>,
    federated_origin: Option<&'a str>,
    incoming_membership_delivery: Option<&'a kutup_chat_proto::MlsMembershipDeliveryV1>,
    maximum_group_members: u16,
    verified_history_replay: bool,
}

/// Wake live browser sessions after durable MLS mailbox writes. The mailbox is
/// still the source of truth: this deliberately sends only a generic drain
/// hint, so neither group identifiers nor anonymous sender metadata enter the
/// WebSocket frame.
async fn notify_mls_mailbox_targets(state: &AppState, targets: Vec<(Uuid, i32)>) {
    let Ok(text) = serde_json::to_string(&ChatWsServerMessage::DrainMailbox) else {
        return;
    };
    for (user_id, device_id) in targets {
        for connection in state.chat_hub.connections(user_id, device_id) {
            connection.write(ChatWsOut::Text(text.clone())).await;
        }
    }
}

pub(super) async fn notify_mls_conversation_mailbox(state: &AppState, conversation_id: Uuid) {
    let targets: Result<Vec<(Uuid, i32)>, _> = sqlx::query_as(
        "SELECT DISTINCT recipient_user_id, recipient_device_id
         FROM chat_mls_mailbox
         WHERE conversation_id = $1
         ORDER BY recipient_user_id, recipient_device_id",
    )
    .bind(conversation_id)
    .fetch_all(&state.pool)
    .await;
    match targets {
        Ok(targets) => notify_mls_mailbox_targets(state, targets).await,
        Err(error) => tracing::warn!(error = %error, "MLS mailbox WebSocket wake-up query failed"),
    }
}

pub(super) async fn notify_mls_recipient_mailbox(state: &AppState, username: &str) {
    let targets: Result<Vec<(Uuid, i32)>, _> = sqlx::query_as(
        "SELECT DISTINCT m.recipient_user_id, m.recipient_device_id
         FROM chat_mls_mailbox m
         JOIN users u ON u.id = m.recipient_user_id
         WHERE u.username = $1
         ORDER BY m.recipient_user_id, m.recipient_device_id",
    )
    .bind(username)
    .fetch_all(&state.pool)
    .await;
    match targets {
        Ok(targets) => notify_mls_mailbox_targets(state, targets).await,
        Err(error) => tracing::warn!(error = %error, "MLS mailbox WebSocket wake-up query failed"),
    }
}

/// Wake active local administrators when durable invitation readiness or
/// refusal feedback changes. The frame remains the same identifier-free
/// mailbox hint used by ciphertext delivery; clients re-read authenticated
/// state rather than trusting a WebSocket payload.
pub(super) async fn notify_mls_administrators(state: &AppState, conversation_id: Uuid) {
    let targets: Result<Vec<(Uuid, i32)>, _> = sqlx::query_as(
        "SELECT DISTINCT d.user_id, d.device_id
         FROM chat_mls_local_members m
         JOIN chat_devices d ON d.user_id = m.user_id
         WHERE m.conversation_id = $1
           AND m.is_admin = true
           AND m.membership_status = 'active'
           AND m.removed_epoch IS NULL
         ORDER BY d.user_id, d.device_id",
    )
    .bind(conversation_id)
    .fetch_all(&state.pool)
    .await;
    match targets {
        Ok(targets) => notify_mls_mailbox_targets(state, targets).await,
        Err(error) => {
            tracing::warn!(error = %error, "MLS administrator WebSocket wake-up query failed")
        }
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
