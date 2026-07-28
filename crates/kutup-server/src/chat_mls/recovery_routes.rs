//! Authenticated local and signed-federation MLS recovery routes.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{FederatedMlsRecoveryReplicaV1, RecoverMlsConversationRequestV1};
use kutup_federation_proto::FederationFeature;

use super::{
    active_policy, authenticated_remote_policy, notify_mls_conversation_mailbox,
    signed_federation_error, signed_federation_json, MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::telemetry;
use crate::AppState;

pub(crate) async fn get_recovery(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, incarnation)): Path<(uuid::Uuid, u64)>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    if incarnation <= 1 {
        return Err(AppError::bad_request(
            "MLS recovery target incarnation must be greater than one",
        ));
    }
    let user_id = trusted_uuid(&auth.user_id)?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT r.recovery
         FROM chat_mls_incarnation_recoveries r
         JOIN chat_mls_local_members m
           ON m.conversation_id = r.conversation_id
          AND m.incarnation = r.new_incarnation
         WHERE r.conversation_id = $1 AND r.new_incarnation = $2
           AND m.user_id = $3 AND m.removed_epoch IS NULL
           AND m.membership_status = 'active'",
    )
    .bind(conversation_id)
    .bind(incarnation as i64)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let value = value.ok_or_else(|| AppError::not_found("MLS recovery is unavailable"))?;
    let recovery: kutup_chat_proto::MlsIncarnationRecoveryV1 = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("stored MLS recovery is invalid: {error}")))?;
    recovery
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored MLS recovery is invalid: {error}")))?;
    if recovery.plan.conversation_id != conversation_id
        || recovery.plan.new_genesis.incarnation != incarnation
    {
        return Err(AppError::internal(
            "stored MLS recovery index is inconsistent",
        ));
    }
    Ok(Json(recovery).into_response())
}

#[tracing::instrument(skip_all, fields(mls_operation = "recover_conversation"))]
pub(crate) async fn recover_conversation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<RecoverMlsConversationRequestV1>,
) -> AppResult<Response> {
    request.validate_shape().map_err(AppError::bad_request)?;
    let policy = active_policy(&state).await?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let local_domain = federation.server_name();
    for authority in &request.recovery.plan.new_genesis.authority_set.authorities {
        let authority_policy = if authority.domain == local_domain {
            policy.clone()
        } else {
            authenticated_remote_policy(&state, &authority.domain).await?
        };
        if !authority_policy.accepts_group_ordering
            || authority_policy.control_signing_key_id != authority.key_id
            || authority_policy.control_signing_public_key != authority.public_key
        {
            return Err(AppError::bad_request(
                "MLS recovery authority differs from its authenticated service policy",
            ));
        }
    }
    let local_delivery = request
        .deliveries
        .iter()
        .find(|delivery| delivery.destination == local_domain);
    let response = MlsRepository::new(state.pool.clone())
        .recover_conversation(
            local_domain,
            Some(trusted_uuid(&auth.user_id)?),
            local_domain,
            &request.recovery,
            local_delivery,
            Some(&request.members),
            Some(&request.deliveries),
            Some((&request.creator, request.creator_device_id)),
            policy.maximum_group_members,
            policy.maximum_authorities,
        )
        .await?;
    notify_mls_conversation_mailbox(&state, request.recovery.plan.conversation_id).await;
    telemetry::mls_control_event("incarnation_recovery", "accepted");
    Ok(Json(response).into_response())
}

pub(crate) async fn federated_recover_conversation(
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
            "/api/fed/chat/mls/control/recoveries",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let policy = match active_policy(&state).await {
        Ok(policy) => policy,
        Err(error) => return signed_federation_error(federation, &authenticated, error),
    };
    let replica: FederatedMlsRecoveryReplicaV1 = match serde_json::from_slice(&body) {
        Ok(replica) => replica,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid federated MLS recovery"),
            )
        }
    };
    if let Err(error) = replica.validate_shape() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    if authenticated.destination() != federation.server_name() {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("federated MLS recovery destination mismatch"),
        );
    }
    if let Some(authority) = replica
        .recovery
        .plan
        .new_genesis
        .authority_set
        .authority(federation.server_name())
    {
        if !policy.accepts_group_ordering
            || policy.control_signing_key_id != authority.key_id
            || policy.control_signing_public_key != authority.public_key
        {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::forbidden(
                    "federated MLS recovery authority differs from local service policy",
                ),
            );
        }
    }
    match MlsRepository::new(state.pool.clone())
        .recover_conversation(
            federation.server_name(),
            None,
            authenticated.origin(),
            &replica.recovery,
            replica.membership_delivery.as_ref(),
            None,
            None,
            None,
            policy.maximum_group_members,
            policy.maximum_authorities,
        )
        .await
    {
        Ok(response) => {
            notify_mls_conversation_mailbox(&state, replica.recovery.plan.conversation_id).await;
            signed_federation_json(federation, &authenticated, StatusCode::OK, &response)
        }
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}
