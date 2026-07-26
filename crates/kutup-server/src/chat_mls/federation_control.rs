//! Outbound MLS control-log federation.
//!
//! Participant servers keep message delivery state. Authority servers keep
//! only the replicated control log. These helpers deliberately route through
//! the authenticated federation stack and its pinned feature policies.

use std::collections::BTreeSet;

use kutup_chat_proto::{
    CreateMlsConversationRequestV1, CreateMlsConversationResponseV1, FederatedMlsGenesisReplicaV1,
    FederatedMlsOrderingVoteRequestV1, MlsOrderingVoteV1,
};
use kutup_federation_proto::FederationFeature;
use reqwest::{Method, StatusCode};
use uuid::Uuid;

use super::authenticated_remote_policy;
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::AppState;

pub(super) async fn replicate_genesis(
    state: &AppState,
    request: &CreateMlsConversationRequestV1,
    participant_domains: &[String],
) -> AppResult<()> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let mut destinations: BTreeSet<String> = participant_domains.iter().cloned().collect();
    destinations.extend(
        request
            .genesis
            .authority_set
            .authorities
            .iter()
            .map(|authority| authority.domain.clone()),
    );
    for destination in destinations {
        if destination == federation.server_name() {
            continue;
        }
        authenticated_remote_policy(state, &destination).await?;
        let replica = FederatedMlsGenesisReplicaV1 {
            protocol_version: kutup_chat_proto::MLS_PROTOCOL_VERSION,
            genesis: request.genesis.clone(),
            participant_domains: participant_domains.to_vec(),
            members: if participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(&destination))
                .is_ok()
            {
                request
                    .members
                    .iter()
                    .filter(|member| member.address.server.as_deref() == Some(destination.as_str()))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            },
        };
        replica.validate().map_err(AppError::internal)?;
        let body = serde_json::to_vec(&replica)
            .map_err(|error| AppError::internal(format!("serialize MLS genesis: {error}")))?;
        let remote = federation
            .send(
                &destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/control/genesis".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 64 * 1024,
                },
            )
            .await
            .map_err(|error| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("remote MLS genesis replication failed: {error}"),
                )
            })?;
        if remote.status != StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "remote MLS genesis replication to {destination} returned {}",
                    remote.status
                ),
            ));
        }
        let acknowledged: CreateMlsConversationResponseV1 = serde_json::from_slice(&remote.body)
            .map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "remote MLS genesis acknowledgement is invalid",
                )
            })?;
        if acknowledged.conversation_id != request.genesis.conversation_id
            || acknowledged.incarnation != request.genesis.incarnation
            || acknowledged.genesis_hash
                != request.genesis.genesis_hash().map_err(AppError::internal)?
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS genesis acknowledgement does not match",
            ));
        }
    }
    Ok(())
}

pub(super) async fn request_remote_ordering_vote(
    state: &AppState,
    authority_domain: &str,
    request: &FederatedMlsOrderingVoteRequestV1,
) -> AppResult<MlsOrderingVoteV1> {
    let authority = request
        .authority_set
        .authority(authority_domain)
        .ok_or_else(|| AppError::bad_request("requested domain is not an MLS authority"))?;
    let remote_policy = authenticated_remote_policy(state, authority_domain).await?;
    if remote_policy.control_signing_key_id != authority.key_id
        || remote_policy.control_signing_public_key != authority.public_key
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote MLS policy does not match the authority set",
        ));
    }
    let body = serde_json::to_vec(request)
        .map_err(|error| AppError::internal(format!("serialize MLS vote request: {error}")))?;
    let response = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
        .send(
            authority_domain,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path: "/api/fed/chat/mls/control/votes".into(),
                query: None,
                content_type: "application/json".into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 64 * 1024,
            },
        )
        .await
        .map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("remote MLS vote request failed: {error}"),
            )
        })?;
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote MLS authority returned {}", response.status),
        ));
    }
    let vote: MlsOrderingVoteV1 = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote MLS authority returned an invalid vote",
        )
    })?;
    vote.verify(&request.authority_set)
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error))?;
    Ok(vote)
}
