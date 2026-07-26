//! Signed federation endpoints for anonymous MLS delivery.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use kutup_chat_proto::{AnonymousMlsKeyPackageRequestV1, FederatedAnonymousMlsTransactionV1};
use kutup_federation_proto::FederationFeature;
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    active_policy, decode_capability, increment_counter, scoped_digest, signed_federation_error,
    signed_federation_json, unavailable, MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::AppState;

pub(crate) async fn federated_get_anonymous_key_packages(
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
            "/api/fed/chat/mls/anonymous/key-packages",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let policy = match active_policy(&state).await {
        Ok(policy) => policy,
        Err(error) => return signed_federation_error(federation, &authenticated, error),
    };
    let request: AnonymousMlsKeyPackageRequestV1 = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid anonymous MLS KeyPackage request"),
            )
        }
    };
    if let Err(error) = request.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    if authenticated.destination() != federation.server_name()
        || request.recipient.server.as_deref() != Some(federation.server_name())
    {
        return signed_federation_error(federation, &authenticated, unavailable());
    }
    match super::anonymous_routes::claim_local_anonymous_key_packages(
        &state,
        &request,
        &policy.abuse_limits,
    )
    .await
    {
        Ok(response) => {
            signed_federation_json(federation, &authenticated, StatusCode::OK, &response)
        }
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

pub(crate) async fn federated_submit_anonymous_message(
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
            "/api/fed/chat/mls/anonymous/messages",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let policy = match active_policy(&state).await {
        Ok(policy) => policy,
        Err(error) => return signed_federation_error(federation, &authenticated, error),
    };
    let transaction: FederatedAnonymousMlsTransactionV1 = match serde_json::from_slice(&body) {
        Ok(transaction) => transaction,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid anonymous MLS federation transaction"),
            )
        }
    };
    if let Err(error) = transaction.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    if authenticated.destination() != federation.server_name()
        || transaction.origin_domain != authenticated.origin()
        || transaction.submission.recipient.server.as_deref() != Some(federation.server_name())
    {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::unauthorized("anonymous MLS federation routing mismatch"),
        );
    }
    let sequence = match i64::try_from(transaction.origin_sequence) {
        Ok(sequence) => sequence,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("anonymous MLS federation sequence is too large"),
            )
        }
    };
    let now = OffsetDateTime::now_utc();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 693071))")
        .bind(&transaction.origin_domain)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO chat_mls_federation_inbound_state (origin, last_sequence)
         VALUES ($1,0) ON CONFLICT DO NOTHING",
    )
    .bind(&transaction.origin_domain)
    .execute(&mut *tx)
    .await?;
    if let Some((status, response)) = sqlx::query_as::<_, (i16, Value)>(
        "SELECT response_status, response
         FROM chat_mls_federation_inbound_transactions
         WHERE origin = $1 AND sequence = $2",
    )
    .bind(&transaction.origin_domain)
    .bind(sequence)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.rollback().await?;
        let status = StatusCode::from_u16(status as u16)
            .map_err(|_| AppError::internal("stored MLS federation status is invalid"))?;
        return signed_federation_json(federation, &authenticated, status, &response);
    }
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT last_sequence
         FROM chat_mls_federation_inbound_state
         WHERE origin = $1 FOR UPDATE",
    )
    .bind(&transaction.origin_domain)
    .fetch_one(&mut *tx)
    .await?;
    if sequence != last_sequence + 1 {
        tx.rollback().await?;
        return signed_federation_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &serde_json::json!({ "expectedSequence": last_sequence + 1 }),
        );
    }
    if let Err(error) = increment_counter(
        &mut tx,
        "federation_origin",
        scoped_digest(
            b"kutup/mls/rate/federation-origin/v1",
            transaction.origin_domain.as_bytes(),
        ),
        60,
        policy
            .abuse_limits
            .federated_sealed_sends_per_origin_minute
            .into(),
        now,
    )
    .await
    {
        tx.rollback().await?;
        return signed_federation_error(federation, &authenticated, error);
    }
    let capability = match decode_capability(&transaction.submission.capability) {
        Ok(capability) => capability,
        Err(error) => {
            tx.rollback().await?;
            return signed_federation_error(federation, &authenticated, error);
        }
    };
    let outcome = MlsRepository::new(state.pool.clone())
        .store_anonymous_submission(
            &transaction.submission.recipient.username,
            &transaction.submission,
            &capability,
            &policy.abuse_limits,
            now,
        )
        .await;
    let (status, response) = match outcome {
        Ok(response) => (
            StatusCode::OK,
            serde_json::to_value(response)
                .map_err(|error| AppError::internal(format!("serialize MLS response: {error}")))?,
        ),
        Err(error) if error.status == StatusCode::NOT_FOUND => (
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "MLS recipient unavailable" }),
        ),
        Err(error) => {
            tx.rollback().await?;
            return signed_federation_error(federation, &authenticated, error);
        }
    };
    sqlx::query(
        "INSERT INTO chat_mls_federation_inbound_transactions
             (origin, sequence, send_id, response_status, response)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(&transaction.origin_domain)
    .bind(sequence)
    .bind(transaction.submission.send_id)
    .bind(status.as_u16() as i16)
    .bind(&response)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE chat_mls_federation_inbound_state
         SET last_sequence = $2, updated_at = now()
         WHERE origin = $1",
    )
    .bind(&transaction.origin_domain)
    .bind(sequence)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    signed_federation_json(federation, &authenticated, status, &response)
}
