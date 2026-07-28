//! Durable, federation-authenticated feedback for rejected MLS invitations.
//!
//! Feedback is advisory and identified: it is visible only to active local
//! administrators who already know the group roster. It never mutates the MLS
//! roster; an administrator must commit the cryptographic removal.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    MlsInvitationFeedbackDecisionV1, MlsInvitationFeedbackV1, MlsMembershipDeliveryV1,
    MlsMembershipEnvelopeKindV1,
};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    active_policy, authenticated_remote_policy, signed_federation_error, signed_federation_json,
};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::telemetry;
use crate::AppState;

const FEEDBACK_CLOCK_SKEW_SECONDS: i64 = 300;

pub(super) async fn persist_invitation_feedback(
    tx: &mut Transaction<'_, Postgres>,
    local_domain: &str,
    destination: &str,
    feedback: &MlsInvitationFeedbackV1,
) -> AppResult<()> {
    feedback.validate().map_err(AppError::internal)?;
    let digest = feedback.feedback_digest().map_err(AppError::internal)?;
    let value = serde_json::to_value(feedback).map_err(|error| {
        AppError::internal(format!("serialize MLS invitation feedback: {error}"))
    })?;
    if destination == local_domain {
        insert_feedback(tx, local_domain, feedback, &digest, &value).await
    } else {
        let inserted = sqlx::query(
            "INSERT INTO chat_mls_invitation_feedback_outbox
                 (destination, conversation_id, incarnation, member_address,
                  invited_epoch, feedback_digest, feedback)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (destination, conversation_id, incarnation,
                          member_address, invited_epoch)
             DO NOTHING",
        )
        .bind(destination)
        .bind(feedback.conversation_id)
        .bind(feedback.incarnation as i64)
        .bind(feedback.member.canonical())
        .bind(feedback.invited_epoch as i64)
        .bind(&digest)
        .bind(&value)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT feedback_digest
                 FROM chat_mls_invitation_feedback_outbox
                 WHERE destination = $1 AND conversation_id = $2
                   AND incarnation = $3 AND member_address = $4
                   AND invited_epoch = $5",
            )
            .bind(destination)
            .bind(feedback.conversation_id)
            .bind(feedback.incarnation as i64)
            .bind(feedback.member.canonical())
            .bind(feedback.invited_epoch as i64)
            .fetch_optional(&mut **tx)
            .await?;
            if existing.as_deref() != Some(digest.as_str()) {
                return Err(AppError::conflict(
                    "MLS invitation feedback is already bound to another decision",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) async fn list_invitation_feedback(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Response> {
    active_policy(&state).await?;
    let user_id = trusted_uuid(&auth.user_id)?;
    let rows: Vec<(Value, String)> = sqlx::query_as(
        "SELECT f.feedback, f.feedback_digest
         FROM chat_mls_invitation_feedback f
         WHERE EXISTS (
             SELECT 1 FROM chat_mls_local_members administrator
             WHERE administrator.conversation_id = f.conversation_id
               AND administrator.incarnation = f.incarnation
               AND administrator.user_id = $1
               AND administrator.is_admin = true
               AND administrator.membership_status = 'active'
               AND administrator.removed_epoch IS NULL
         )
         ORDER BY f.received_at DESC, f.conversation_id, f.member_address
         LIMIT 256",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let feedback = rows
        .into_iter()
        .map(|(value, digest)| {
            let feedback: MlsInvitationFeedbackV1 =
                serde_json::from_value(value).map_err(|error| {
                    AppError::internal(format!(
                        "stored MLS invitation feedback is invalid: {error}"
                    ))
                })?;
            feedback.validate().map_err(|error| {
                AppError::internal(format!(
                    "stored MLS invitation feedback is invalid: {error}"
                ))
            })?;
            if feedback.feedback_digest().map_err(AppError::internal)? != digest {
                return Err(AppError::internal(
                    "stored MLS invitation feedback digest differs",
                ));
            }
            Ok(feedback)
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(feedback).into_response())
}

pub(crate) async fn federated_record_invitation_feedback(
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
            "/api/fed/chat/mls/invitation-feedback",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    if let Err(error) = active_policy(&state).await {
        return signed_federation_error(federation, &authenticated, error);
    }
    let feedback: MlsInvitationFeedbackV1 = match serde_json::from_slice(&body) {
        Ok(feedback) => feedback,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid MLS invitation feedback"),
            )
        }
    };
    if let Err(error) = feedback.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    if authenticated.destination() != federation.server_name()
        || feedback.member.server.as_deref() != Some(authenticated.origin())
    {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("MLS invitation feedback routing is unauthorized"),
        );
    }
    match verify_and_store_federated_feedback(&state, authenticated.origin(), &feedback).await {
        Ok(digest) => {
            telemetry::mls_control_event("invitation_feedback_receive", "accepted");
            signed_federation_json(
                federation,
                &authenticated,
                StatusCode::OK,
                &serde_json::json!({ "feedbackDigest": digest }),
            )
        }
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

async fn verify_and_store_federated_feedback(
    state: &AppState,
    origin: &str,
    feedback: &MlsInvitationFeedbackV1,
) -> AppResult<String> {
    let rows: Vec<(Value, OffsetDateTime)> = sqlx::query_as(
        "SELECT delivery, finalized_at
         FROM chat_mls_membership_deliveries
         WHERE conversation_id = $1 AND incarnation = $2
           AND destination = $3 AND state = 'finalized'
         ORDER BY block_height",
    )
    .bind(feedback.conversation_id)
    .bind(feedback.incarnation as i64)
    .bind(origin)
    .fetch_all(&state.pool)
    .await?;
    let mut matched_finalized_at = None;
    for (value, finalized_at) in rows {
        let delivery: MlsMembershipDeliveryV1 = serde_json::from_value(value).map_err(|error| {
            AppError::internal(format!(
                "stored MLS membership delivery is invalid: {error}"
            ))
        })?;
        delivery.validate().map_err(|error| {
            AppError::internal(format!(
                "stored MLS membership delivery is invalid: {error}"
            ))
        })?;
        let welcomed = delivery.envelopes.iter().any(|envelope| {
            envelope.recipient == feedback.member
                && envelope.kind == MlsMembershipEnvelopeKindV1::Welcome
        });
        if delivery.epoch_after == feedback.invited_epoch
            && welcomed
            && delivery
                .local_members_after
                .iter()
                .any(|member| member.address == feedback.member)
        {
            matched_finalized_at = Some(finalized_at);
            break;
        }
    }
    let finalized_at = matched_finalized_at.ok_or_else(|| {
        AppError::forbidden("MLS invitation feedback has no matching finalized Welcome")
    })?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if feedback.decided_at < finalized_at.unix_timestamp()
        || feedback.decided_at > now.saturating_add(FEEDBACK_CLOCK_SKEW_SECONDS)
    {
        return Err(AppError::bad_request(
            "MLS invitation feedback decision clock is invalid",
        ));
    }

    let digest = feedback.feedback_digest().map_err(AppError::bad_request)?;
    let value = serde_json::to_value(feedback).map_err(|error| {
        AppError::internal(format!("serialize MLS invitation feedback: {error}"))
    })?;
    let mut tx = state.pool.begin().await?;
    insert_feedback(&mut tx, origin, feedback, &digest, &value).await?;
    tx.commit().await?;
    Ok(digest)
}

async fn insert_feedback(
    tx: &mut Transaction<'_, Postgres>,
    source_domain: &str,
    feedback: &MlsInvitationFeedbackV1,
    digest: &str,
    value: &Value,
) -> AppResult<()> {
    let decision = match feedback.decision {
        MlsInvitationFeedbackDecisionV1::Rejected => "rejected",
        MlsInvitationFeedbackDecisionV1::Expired => "expired",
    };
    let decided_at = OffsetDateTime::from_unix_timestamp(feedback.decided_at)
        .map_err(|_| AppError::bad_request("MLS invitation feedback clock is invalid"))?;
    let inserted = sqlx::query(
        "INSERT INTO chat_mls_invitation_feedback
             (conversation_id, incarnation, member_address, invited_epoch,
              source_domain, decision, decided_at, feedback_digest, feedback)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (conversation_id, incarnation, member_address, invited_epoch)
         DO NOTHING",
    )
    .bind(feedback.conversation_id)
    .bind(feedback.incarnation as i64)
    .bind(feedback.member.canonical())
    .bind(feedback.invited_epoch as i64)
    .bind(source_domain)
    .bind(decision)
    .bind(decided_at)
    .bind(digest)
    .bind(value)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 0 {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT feedback_digest
             FROM chat_mls_invitation_feedback
             WHERE conversation_id = $1 AND incarnation = $2
               AND member_address = $3 AND invited_epoch = $4",
        )
        .bind(feedback.conversation_id)
        .bind(feedback.incarnation as i64)
        .bind(feedback.member.canonical())
        .bind(feedback.invited_epoch as i64)
        .fetch_optional(&mut **tx)
        .await?;
        if existing.as_deref() != Some(digest) {
            return Err(AppError::conflict(
                "conflicting MLS invitation feedback is already stored",
            ));
        }
    }
    Ok(())
}

pub(super) async fn retry_invitation_feedback_once(state: &AppState) -> AppResult<()> {
    let row: Option<(String, Uuid, i64, String, i64, String, Value, i32)> = sqlx::query_as(
        "SELECT destination, conversation_id, incarnation, member_address,
                invited_epoch, feedback_digest, feedback, attempts
         FROM chat_mls_invitation_feedback_outbox
         WHERE state = 'pending' AND next_attempt_at <= now()
         ORDER BY next_attempt_at, destination, conversation_id, incarnation
         LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some((
        destination,
        conversation_id,
        incarnation,
        member_address,
        invited_epoch,
        digest,
        value,
        attempts,
    )) = row
    else {
        return Ok(());
    };
    let feedback: MlsInvitationFeedbackV1 = serde_json::from_value(value).map_err(|error| {
        AppError::internal(format!(
            "stored MLS invitation feedback is invalid: {error}"
        ))
    })?;
    feedback.validate().map_err(|error| {
        AppError::internal(format!(
            "stored MLS invitation feedback is invalid: {error}"
        ))
    })?;
    if feedback.conversation_id != conversation_id
        || feedback.incarnation != incarnation as u64
        || feedback.member.canonical() != member_address
        || feedback.invited_epoch != invited_epoch as u64
        || feedback.feedback_digest().map_err(AppError::internal)? != digest
    {
        return Err(AppError::internal(
            "stored MLS invitation feedback row differs from its canonical body",
        ));
    }
    let outcome = async {
        authenticated_remote_policy(state, &destination).await?;
        let body = feedback.canonical_bytes().map_err(AppError::internal)?;
        let response = state
            .federation
            .as_ref()
            .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
            .send(
                &destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/invitation-feedback".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 8 * 1024,
                },
            )
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if response.status != StatusCode::OK {
            return Err(AppError::new(
                response.status,
                format!(
                    "remote MLS invitation feedback returned {}",
                    response.status
                ),
            ));
        }
        let acknowledgement: Value = serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS invitation feedback acknowledgement is invalid",
            )
        })?;
        if acknowledgement
            .get("feedbackDigest")
            .and_then(Value::as_str)
            != Some(digest.as_str())
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS invitation feedback acknowledgement does not match",
            ));
        }
        Ok(())
    }
    .await;

    match outcome {
        Ok(()) => {
            sqlx::query(
                "UPDATE chat_mls_invitation_feedback_outbox
                 SET state = 'delivered', attempts = attempts + 1,
                     last_error_class = NULL, updated_at = now()
                 WHERE destination = $1 AND conversation_id = $2
                   AND incarnation = $3 AND member_address = $4
                   AND invited_epoch = $5 AND state = 'pending'",
            )
            .bind(&destination)
            .bind(conversation_id)
            .bind(incarnation)
            .bind(&member_address)
            .bind(invited_epoch)
            .execute(&state.pool)
            .await?;
            telemetry::mls_control_event("invitation_feedback_delivery", "accepted");
        }
        Err(error) => {
            let failure_class = match error.status {
                StatusCode::CONFLICT | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                    "remote_rejection"
                }
                StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                StatusCode::BAD_GATEWAY => "transport_or_invalid_ack",
                _ if error.status.is_server_error() => "remote_unavailable",
                _ => "remote_error",
            };
            let exponent = u32::try_from(attempts).unwrap_or(u32::MAX).min(8);
            let delay_seconds = 5i64.saturating_mul(1i64 << exponent).min(900);
            sqlx::query(
                "UPDATE chat_mls_invitation_feedback_outbox
                 SET attempts = attempts + 1,
                     next_attempt_at = now() + make_interval(secs => $6),
                     last_error_class = $7, updated_at = now()
                 WHERE destination = $1 AND conversation_id = $2
                   AND incarnation = $3 AND member_address = $4
                   AND invited_epoch = $5 AND state = 'pending'",
            )
            .bind(&destination)
            .bind(conversation_id)
            .bind(incarnation)
            .bind(&member_address)
            .bind(invited_epoch)
            .bind(delay_seconds as f64)
            .bind(failure_class)
            .execute(&state.pool)
            .await?;
            telemetry::mls_control_event("invitation_feedback_delivery", "retry");
        }
    }
    Ok(())
}
