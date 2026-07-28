//! Signed inbound federation routes for the MLS control log.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use kutup_chat_proto::{
    CreateMlsConversationRequestV1, FederatedMlsControlReplicaV1, FederatedMlsGenesisReplicaV1,
    FederatedMlsOrderingVoteRequestV1,
};
use kutup_federation_proto::FederationFeature;

use super::{
    active_policy, notify_mls_conversation_mailbox, signed_federation_error,
    signed_federation_json, MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::AppState;

pub(crate) async fn federated_replicate_genesis(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/mls/control/genesis",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let policy = match active_policy(&state).await {
        Ok(policy) => policy,
        Err(error) => return signed_federation_error(federation, &authenticated, error),
    };
    let replica: FederatedMlsGenesisReplicaV1 = match serde_json::from_slice(&body) {
        Ok(replica) => replica,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid federated MLS genesis"),
            )
        }
    };
    if let Err(error) = replica.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    let local_domain = federation.server_name();
    let local_is_authority = replica
        .genesis
        .authority_set
        .authority(local_domain)
        .is_some();
    let local_is_participant = replica
        .participant_domains
        .binary_search_by(|domain| domain.as_str().cmp(local_domain))
        .is_ok();
    let origin_is_participant = replica
        .participant_domains
        .binary_search_by(|domain| domain.as_str().cmp(authenticated.origin()))
        .is_ok();
    if authenticated.destination() != local_domain
        || !origin_is_participant
        || (!local_is_authority && !local_is_participant)
        || (local_is_participant && !replica.includes_member_domain(local_domain))
        || (!local_is_participant && !replica.members.is_empty())
    {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("federated MLS genesis routing is unauthorized"),
        );
    }
    let request = CreateMlsConversationRequestV1 {
        genesis: replica.genesis.clone(),
        members: replica.members.clone(),
        initial_devices: Vec::new(),
    };
    match MlsRepository::new(state.pool.clone())
        .create_conversation(
            None,
            local_domain,
            &request,
            &replica.participant_domains,
            policy.maximum_group_members,
        )
        .await
    {
        Ok(response) => {
            signed_federation_json(federation, &authenticated, StatusCode::OK, &response)
        }
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

pub(crate) async fn federated_cast_ordering_vote(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/mls/control/votes",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    if let Err(error) = active_policy(&state).await {
        return signed_federation_error(federation, &authenticated, error);
    }
    let request: FederatedMlsOrderingVoteRequestV1 = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid federated MLS vote request"),
            )
        }
    };
    if authenticated.destination() != federation.server_name() {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("federated MLS vote destination mismatch"),
        );
    }
    let Some(ordering) = state.mls_ordering.as_deref() else {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::not_found("MLS ordering unavailable"),
        );
    };
    match MlsRepository::new(state.pool.clone())
        .cast_ordering_vote(
            authenticated.origin(),
            federation.server_name(),
            ordering,
            &request,
        )
        .await
    {
        Ok(vote) => signed_federation_json(federation, &authenticated, StatusCode::OK, &vote),
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

pub(crate) async fn federated_commit_control_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/mls/control/blocks",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let policy = match active_policy(&state).await {
        Ok(policy) => policy,
        Err(error) => return signed_federation_error(federation, &authenticated, error),
    };
    let replica: FederatedMlsControlReplicaV1 = match serde_json::from_slice(&body) {
        Ok(replica) => replica,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid federated MLS control block"),
            )
        }
    };
    if let Err(error) = replica.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    if authenticated.destination() != federation.server_name() {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("federated MLS control destination mismatch"),
        );
    }
    match MlsRepository::new(state.pool.clone())
        .commit_control_block(
            federation.server_name(),
            None,
            Some(authenticated.origin()),
            &replica.commit,
            replica.membership_delivery.as_ref(),
            policy.maximum_group_members,
            false,
        )
        .await
    {
        Ok(response) => {
            notify_mls_conversation_mailbox(&state, replica.commit.finalized.block.conversation_id)
                .await;
            signed_federation_json(federation, &authenticated, StatusCode::OK, &response)
        }
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}
