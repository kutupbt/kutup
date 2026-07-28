//! Restart-safe delivery of queued anonymous MLS federation transactions.

use std::time::Duration;

use kutup_chat_proto::{
    CommitMlsControlBlockResponseV1, FederatedAnonymousMlsTransactionV1,
    FederatedMlsControlReplicaV1, FederatedMlsRecoveryReplicaV1, RecoverMlsConversationResponseV1,
};
use kutup_federation_proto::FederationFeature;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use uuid::Uuid;

use super::participant_bootstrap::bootstrap_new_participant;
use super::{authenticated_remote_policy, bootstrap_finalized_authority};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::AppState;

pub(crate) fn spawn_retry_worker(state: AppState) {
    if state.federation.is_none() || state.mls_ordering.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) = retry_federation_outbox_once(&state).await {
                tracing::warn!(error = %error, "anonymous MLS federation retry iteration failed");
            }
            if let Err(error) = retry_control_outbox_once(&state).await {
                tracing::warn!(error = %error, "MLS control federation retry iteration failed");
            }
            if let Err(error) = retry_recovery_outbox_once(&state).await {
                tracing::warn!(error = %error, "MLS recovery federation retry iteration failed");
            }
        }
    });
}

async fn retry_recovery_outbox_once(state: &AppState) -> AppResult<()> {
    let row: Option<(String, String, Uuid, i64, Value, i32)> = sqlx::query_as(
        "SELECT destination, recovery_digest, conversation_id,
                previous_incarnation, replica, attempts
         FROM chat_mls_recovery_outbox
         WHERE state = 'pending' AND next_attempt_at <= now()
         ORDER BY next_attempt_at, destination, recovery_digest
         LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some((
        destination,
        recovery_digest,
        conversation_id,
        previous_incarnation,
        value,
        attempts,
    )) = row
    else {
        return Ok(());
    };
    let replica: FederatedMlsRecoveryReplicaV1 =
        serde_json::from_value(value).map_err(|error| {
            AppError::internal(format!("stored MLS recovery replica invalid: {error}"))
        })?;
    replica.validate_shape().map_err(|error| {
        AppError::internal(format!("stored MLS recovery replica invalid: {error}"))
    })?;
    let outcome = async {
        authenticated_remote_policy(state, &destination).await?;
        let body = serde_json::to_vec(&replica).map_err(|error| {
            AppError::internal(format!("serialize MLS recovery retry: {error}"))
        })?;
        let response = state
            .federation
            .as_ref()
            .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
            .send(
                &destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/control/recoveries".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 64 * 1024,
                },
            )
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if response.status != StatusCode::OK {
            return Err(AppError::new(
                response.status,
                format!("remote MLS recovery replica returned {}", response.status),
            ));
        }
        let acknowledged: RecoverMlsConversationResponseV1 = serde_json::from_slice(&response.body)
            .map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "remote MLS recovery acknowledgement is invalid",
                )
            })?;
        acknowledged.validate().map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("remote MLS recovery acknowledgement is invalid: {error}"),
            )
        })?;
        if acknowledged.conversation_id != conversation_id
            || acknowledged.previous_incarnation != previous_incarnation as u64
            || acknowledged.incarnation != replica.recovery.plan.new_genesis.incarnation
            || acknowledged.recovery_digest != recovery_digest
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS recovery acknowledgement does not match",
            ));
        }
        Ok(())
    }
    .await;
    match outcome {
        Ok(()) => {
            sqlx::query(
                "UPDATE chat_mls_recovery_outbox
                 SET state = 'delivered', attempts = attempts + 1,
                     last_error_class = NULL, updated_at = now()
                 WHERE destination = $1 AND recovery_digest = $2
                   AND state = 'pending'",
            )
            .bind(&destination)
            .bind(&recovery_digest)
            .execute(&state.pool)
            .await?;
        }
        Err(error) => {
            let failure_class = match error.status {
                StatusCode::CONFLICT => "remote_conflict",
                StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                StatusCode::BAD_GATEWAY => "transport_or_invalid_ack",
                _ if error.status.is_server_error() => "remote_unavailable",
                _ => "remote_rejection",
            };
            let exponent = u32::try_from(attempts).unwrap_or(u32::MAX).min(8);
            let delay_seconds = 5i64.saturating_mul(1i64 << exponent).min(900);
            sqlx::query(
                "UPDATE chat_mls_recovery_outbox
                 SET attempts = attempts + 1,
                     next_attempt_at = now() + make_interval(secs => $3),
                     last_error_class = $4, updated_at = now()
                 WHERE destination = $1 AND recovery_digest = $2
                   AND state = 'pending'",
            )
            .bind(&destination)
            .bind(&recovery_digest)
            .bind(delay_seconds as f64)
            .bind(failure_class)
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(())
}

async fn retry_federation_outbox_once(state: &AppState) -> AppResult<()> {
    let row: Option<(Uuid, String, i64, Value, i32)> = sqlx::query_as(
        "SELECT o.id, o.destination, o.sequence, o.transaction, o.attempts
         FROM chat_mls_federation_outbox o
         WHERE o.state = 'pending' AND o.next_attempt_at <= now()
           AND NOT EXISTS (
               SELECT 1 FROM chat_mls_federation_outbox prior
               WHERE prior.destination = o.destination
                 AND prior.state = 'pending'
                 AND prior.sequence < o.sequence
           )
         ORDER BY o.next_attempt_at, o.destination, o.sequence
         LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some((id, destination, _sequence, value, attempts)) = row else {
        return Ok(());
    };
    let transaction: FederatedAnonymousMlsTransactionV1 = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("stored MLS transaction invalid: {error}")))?;
    transaction
        .validate()
        .map_err(|error| AppError::internal(format!("stored MLS transaction invalid: {error}")))?;
    let outcome = async {
        authenticated_remote_policy(state, &destination).await?;
        let body = serde_json::to_vec(&transaction)
            .map_err(|error| AppError::internal(format!("serialize MLS retry: {error}")))?;
        state
            .federation
            .as_ref()
            .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
            .send(
                &destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/anonymous/messages".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 64 * 1024,
                },
            )
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))
    }
    .await;
    match outcome {
        Ok(response)
            if response.status == StatusCode::OK || response.status == StatusCode::NOT_FOUND =>
        {
            sqlx::query(
                "UPDATE chat_mls_federation_outbox
                 SET state = $2, attempts = attempts + 1,
                     last_error_class = NULL, updated_at = now()
                 WHERE id = $1 AND state = 'pending'",
            )
            .bind(id)
            .bind(if response.status == StatusCode::OK {
                "delivered"
            } else {
                "rejected"
            })
            .execute(&state.pool)
            .await?;
        }
        other => {
            let failure_class = match &other {
                Ok(response) if response.status == StatusCode::CONFLICT => "sequence_conflict",
                Ok(response) if response.status == StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                Ok(_) => "remote_rejection",
                Err(error) if error.status == StatusCode::BAD_GATEWAY => "transport",
                Err(_) => "local_policy",
            };
            let exponent = u32::try_from(attempts).unwrap_or(u32::MAX).min(8);
            let delay_seconds = 5i64.saturating_mul(1i64 << exponent).min(900);
            sqlx::query(
                "UPDATE chat_mls_federation_outbox
                 SET attempts = attempts + 1,
                     next_attempt_at = now() + make_interval(secs => $2),
                     last_error_class = $3,
                     updated_at = now()
                 WHERE id = $1 AND state = 'pending'",
            )
            .bind(id)
            .bind(delay_seconds as f64)
            .bind(failure_class)
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(())
}

async fn retry_control_outbox_once(state: &AppState) -> AppResult<()> {
    let row: Option<(String, Uuid, i64, i64, String, Value, i32)> = sqlx::query_as(
        "SELECT o.destination, o.conversation_id, o.incarnation, o.height,
                o.block_hash, o.commit_request, o.attempts
         FROM chat_mls_control_outbox o
         WHERE o.state = 'pending' AND o.next_attempt_at <= now()
           AND NOT EXISTS (
               SELECT 1 FROM chat_mls_control_outbox prior
               WHERE prior.destination = o.destination
                 AND prior.conversation_id = o.conversation_id
                 AND prior.incarnation = o.incarnation
                 AND prior.state = 'pending'
                 AND prior.height < o.height
           )
         ORDER BY o.next_attempt_at, o.destination,
                  o.conversation_id, o.incarnation, o.height
         LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some((destination, conversation_id, incarnation, height, block_hash, value, attempts)) =
        row
    else {
        return Ok(());
    };
    let replica: FederatedMlsControlReplicaV1 = serde_json::from_value(value).map_err(|error| {
        AppError::internal(format!("stored MLS control block invalid: {error}"))
    })?;
    replica.validate().map_err(|error| {
        AppError::internal(format!("stored MLS control block invalid: {error}"))
    })?;
    let outcome = async {
        authenticated_remote_policy(state, &destination).await?;
        bootstrap_new_participant(state, &destination, &replica).await?;
        bootstrap_finalized_authority(state, &destination, &replica.commit).await?;
        let body = serde_json::to_vec(&replica)
            .map_err(|error| AppError::internal(format!("serialize MLS control retry: {error}")))?;
        let response = state
            .federation
            .as_ref()
            .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
            .send(
                &destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/control/blocks".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 64 * 1024,
                },
            )
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if response.status != StatusCode::OK {
            return Err(AppError::new(
                response.status,
                format!("remote MLS control replica returned {}", response.status),
            ));
        }
        let acknowledged: CommitMlsControlBlockResponseV1 = serde_json::from_slice(&response.body)
            .map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "remote MLS control acknowledgement is invalid",
                )
            })?;
        if acknowledged.conversation_id != conversation_id
            || acknowledged.incarnation != incarnation as u64
            || acknowledged.height != height as u64
            || acknowledged.block_hash != block_hash
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS control acknowledgement does not match",
            ));
        }
        Ok(())
    }
    .await;

    match outcome {
        Ok(()) => {
            sqlx::query(
                "UPDATE chat_mls_control_outbox
                 SET state = 'delivered', attempts = attempts + 1,
                     last_error_class = NULL, updated_at = now()
                 WHERE destination = $1 AND conversation_id = $2
                   AND incarnation = $3 AND height = $4
                   AND state = 'pending'",
            )
            .bind(&destination)
            .bind(conversation_id)
            .bind(incarnation)
            .bind(height)
            .execute(&state.pool)
            .await?;
        }
        Err(error) => {
            let failure_class = match error.status {
                StatusCode::CONFLICT => "remote_conflict",
                StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                StatusCode::BAD_GATEWAY => "transport_or_invalid_ack",
                _ if error.status.is_server_error() => "remote_unavailable",
                _ => "remote_rejection",
            };
            let exponent = u32::try_from(attempts).unwrap_or(u32::MAX).min(8);
            let delay_seconds = 5i64.saturating_mul(1i64 << exponent).min(900);
            sqlx::query(
                "UPDATE chat_mls_control_outbox
                 SET attempts = attempts + 1,
                     next_attempt_at = now() + make_interval(secs => $5),
                     last_error_class = $6, updated_at = now()
                 WHERE destination = $1 AND conversation_id = $2
                   AND incarnation = $3 AND height = $4
                   AND state = 'pending'",
            )
            .bind(&destination)
            .bind(conversation_id)
            .bind(incarnation)
            .bind(height)
            .bind(delay_seconds as f64)
            .bind(failure_class)
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(())
}
