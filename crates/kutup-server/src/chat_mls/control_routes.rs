//! Authenticated local MLS control-log routes.

use std::collections::BTreeSet;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    CommitMlsControlBlockV1, CreateMlsConversationRequestV1, FederatedMlsOrderingVoteRequestV1,
    MlsControlActionTypeV1, MlsConversationKindV1,
};
use reqwest::StatusCode;

use super::{
    active_policy, bootstrap_new_authorities, notify_mls_conversation_mailbox, replicate_genesis,
    request_remote_ordering_vote, CommitControlContext, MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::telemetry;
use crate::AppState;

#[tracing::instrument(skip_all, fields(mls_operation = "create_conversation"))]
pub(crate) async fn create_conversation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<CreateMlsConversationRequestV1>,
) -> AppResult<Response> {
    let policy = active_policy(&state).await?;
    if request.genesis.kind == MlsConversationKindV1::Group && !policy.accepts_group_ordering {
        return Err(AppError::forbidden(
            "this server does not accept group MLS ordering",
        ));
    }
    let server_name = state
        .federation
        .as_ref()
        .expect("active MLS policy requires federation")
        .server_name();
    let participant_domains: Vec<String> = request
        .members
        .iter()
        .filter_map(|member| member.address.server.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let response = MlsRepository::new(state.pool.clone())
        .create_conversation(
            Some(trusted_uuid(&auth.user_id)?),
            server_name,
            &request,
            &participant_domains,
            policy.maximum_group_members,
        )
        .await?;
    replicate_genesis(&state, &request, &participant_domains).await?;
    telemetry::mls_control_event("create_conversation", "accepted");
    Ok(Json(response).into_response())
}

#[tracing::instrument(skip_all, fields(mls_operation = "commit_control_block"))]
pub(crate) async fn commit_control_block(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<CommitMlsControlBlockV1>,
) -> AppResult<Response> {
    let policy = active_policy(&state).await?;
    if request
        .authority_change
        .as_ref()
        .map(|change| &change.next_authority_set)
        .is_some_and(|set| set.authorities.len() > usize::from(policy.maximum_authorities))
    {
        return Err(AppError::bad_request(
            "MLS authority set exceeds the local service policy",
        ));
    }
    let local_domain = state
        .federation
        .as_ref()
        .expect("active MLS policy requires federation")
        .server_name();
    let response = MlsRepository::new(state.pool.clone())
        .commit_control_block(
            &request,
            CommitControlContext {
                local_domain,
                local_submitter: Some(trusted_uuid(&auth.user_id)?),
                federated_origin: None,
                incoming_membership_delivery: None,
                maximum_group_members: policy.maximum_group_members,
                verified_history_replay: false,
            },
        )
        .await?;
    notify_mls_conversation_mailbox(&state, request.finalized.block.conversation_id).await;
    telemetry::mls_control_event("commit_control_block", "accepted");
    Ok(Json(response).into_response())
}

#[tracing::instrument(skip_all, fields(mls_operation = "collect_ordering_votes"))]
pub(crate) async fn collect_ordering_votes(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<FederatedMlsOrderingVoteRequestV1>,
) -> AppResult<Response> {
    request.validate().map_err(AppError::bad_request)?;
    let local_policy = active_policy(&state).await?;
    if request.authority_set.authorities.len() > usize::from(local_policy.maximum_authorities) {
        return Err(AppError::bad_request(
            "MLS authority set exceeds the local service policy",
        ));
    }
    let user_id = trusted_uuid(&auth.user_id)?;
    let local_member: Option<(bool, bool)> = sqlx::query_as(
        "SELECT is_admin, is_owner
         FROM chat_mls_local_members
         WHERE conversation_id = $1 AND incarnation = $2
           AND user_id = $3 AND removed_epoch IS NULL
           AND membership_status = 'active'",
    )
    .bind(request.block.conversation_id)
    .bind(request.block.incarnation as i64)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (is_admin, is_owner) =
        local_member.ok_or_else(|| AppError::forbidden("not an active local MLS member"))?;
    if matches!(
        request.block.proposal.action_type,
        MlsControlActionTypeV1::RoutineAdmin
            | MlsControlActionTypeV1::MembershipChange
            | MlsControlActionTypeV1::AuthoritySetChange
            | MlsControlActionTypeV1::AuthorizationPolicyChange
            | MlsControlActionTypeV1::CryptographicPolicyChange
    ) && !is_admin
    {
        return Err(AppError::forbidden(
            "MLS routine and membership control requires a local administrator",
        ));
    }
    if request.block.proposal.action_type.requires_owner_quorum() && !is_owner {
        return Err(AppError::forbidden(
            "MLS security governance requires a current local owner",
        ));
    }

    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    bootstrap_new_authorities(&state, &request).await?;
    let local_domain = federation.server_name();
    let mut votes = Vec::new();
    for authority in &request.authority_set.authorities {
        let result = if authority.domain == local_domain {
            let ordering = state
                .mls_ordering
                .as_deref()
                .ok_or_else(|| AppError::not_found("MLS ordering unavailable"))?;
            MlsRepository::new(state.pool.clone())
                .cast_ordering_vote(local_domain, local_domain, ordering, &request)
                .await
        } else {
            request_remote_ordering_vote(&state, &authority.domain, &request).await
        };
        match result {
            Ok(vote) => votes.push(vote),
            Err(error) => {
                tracing::warn!(
                    authority = %authority.domain,
                    status = %error.status,
                    "MLS authority vote unavailable"
                );
            }
        }
    }
    votes.sort_by(|left, right| left.authority_domain.cmp(&right.authority_domain));
    let certificate = kutup_chat_proto::MlsOrderingQuorumCertificateV1 {
        authority_set_sequence: request.authority_set.sequence,
        height: request.block.height,
        round: 0,
        block_hash: request.block.block_hash().map_err(AppError::bad_request)?,
        votes,
    };
    if certificate.verify(&request.authority_set).is_err() {
        telemetry::mls_quorum_event(
            "unavailable",
            certificate.votes.len() as u64,
            u64::from(request.authority_set.required_quorum),
        );
        return Err(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "MLS authority quorum is unavailable",
        ));
    }
    telemetry::mls_quorum_event(
        "accepted",
        certificate.votes.len() as u64,
        u64::from(request.authority_set.required_quorum),
    );
    Ok(Json(certificate).into_response())
}
