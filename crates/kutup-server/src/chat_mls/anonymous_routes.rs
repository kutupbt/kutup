//! Same-origin anonymous MLS KeyPackage retrieval and message submission.
//!
//! These handlers reject cookies and bearer tokens before doing any work.
//! Remote destinations are resolved exclusively by the authenticated
//! federation stack; callers never supply a URL.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    AnonymousMlsDeliveryResponseV1, AnonymousMlsKeyPackageRequestV1,
    AnonymousMlsKeyPackageResponseV1, AnonymousMlsSubmissionV1, FederatedAnonymousMlsTransactionV1,
};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    active_policy, authenticated_remote_policy, decode_capability, ensure_anonymous_context,
    unavailable, MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::telemetry;
use crate::AppState;

pub(crate) async fn get_anonymous_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AnonymousMlsKeyPackageRequestV1>,
) -> AppResult<Response> {
    ensure_anonymous_context(&headers)?;
    request.validate().map_err(AppError::bad_request)?;
    let policy = active_policy(&state).await?;
    let server_name = state
        .federation
        .as_ref()
        .expect("active MLS policy requires federation")
        .server_name();
    if request.recipient.server.as_deref() != Some(server_name) {
        let destination = request
            .recipient
            .server
            .as_deref()
            .ok_or_else(unavailable)?;
        authenticated_remote_policy(&state, destination).await?;
        crate::chat_transparency_monitor::verify_before_remote_use(&state, destination).await?;
        let body = serde_json::to_vec(&request)
            .map_err(|error| AppError::internal(format!("serialize MLS request: {error}")))?;
        let response = state
            .federation
            .as_ref()
            .expect("active MLS policy requires federation")
            .send(
                destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/anonymous/key-packages".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 2 * 1024 * 1024,
                },
            )
            .await
            .map_err(|error| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("remote MLS KeyPackage request failed: {error}"),
                )
            })?;
        if response.status == StatusCode::NOT_FOUND {
            return Err(unavailable());
        }
        if response.status != StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("remote MLS KeyPackage request returned {}", response.status),
            ));
        }
        let bundles: AnonymousMlsKeyPackageResponseV1 = serde_json::from_slice(&response.body)
            .map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "remote MLS KeyPackage response is invalid",
                )
            })?;
        bundles
            .validate(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error))?;
        if bundles.recipient != request.recipient {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS KeyPackage response names another recipient",
            ));
        }
        if bundles.transparency.consistency_from
            != request.known_tree_size().map_err(AppError::bad_request)?
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS KeyPackage proof starts at the wrong checkpoint",
            ));
        }
        return Ok(Json(bundles).into_response());
    }
    let response =
        claim_local_anonymous_key_packages(&state, &request, &policy.abuse_limits).await?;
    Ok(Json(response).into_response())
}

pub(super) async fn claim_local_anonymous_key_packages(
    state: &AppState,
    request: &AnonymousMlsKeyPackageRequestV1,
    limits: &kutup_chat_proto::MlsAbuseLimitsV1,
) -> AppResult<AnonymousMlsKeyPackageResponseV1> {
    let capability = decode_capability(&request.capability)?;
    let username = request.recipient.username.clone();
    let now = OffsetDateTime::now_utc();
    let repository = MlsRepository::new(state.pool.clone());
    let (user_id, manifest_version) = repository
        .authorize_anonymous_key_package_claim(&username, &capability, limits, now)
        .await?;
    let publication = crate::handlers::chat::load_manifest_proof(
        state,
        user_id,
        request.known_tree_size().map_err(AppError::bad_request)?,
    )
    .await?;
    if publication.manifest.version != manifest_version {
        return Err(unavailable());
    }
    let key_packages = repository
        .claim_anonymous_key_packages(&username, &capability, user_id, manifest_version, now)
        .await?;
    let response = AnonymousMlsKeyPackageResponseV1 {
        recipient: request.recipient.clone(),
        manifest: publication.manifest,
        transparency: publication.transparency,
        key_packages,
    };
    response
        .validate(now.unix_timestamp())
        .map_err(AppError::internal)?;
    Ok(response)
}

pub(crate) async fn submit_anonymous_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(submission): Json<AnonymousMlsSubmissionV1>,
) -> AppResult<Response> {
    ensure_anonymous_context(&headers)?;
    submission.validate().map_err(AppError::bad_request)?;
    let policy = active_policy(&state).await?;
    let server_name = state
        .federation
        .as_ref()
        .expect("active MLS policy requires federation")
        .server_name();
    if submission.recipient.server.as_deref() != Some(server_name) {
        let destination = submission
            .recipient
            .server
            .as_deref()
            .ok_or_else(unavailable)?;
        authenticated_remote_policy(&state, destination).await?;
        let mut tx = state.pool.begin().await?;
        sqlx::query(
            "INSERT INTO chat_mls_federation_sequences (destination, next_sequence)
             VALUES ($1,1) ON CONFLICT DO NOTHING",
        )
        .bind(destination)
        .execute(&mut *tx)
        .await?;
        let next_sequence: i64 = sqlx::query_scalar(
            "SELECT next_sequence
             FROM chat_mls_federation_sequences
             WHERE destination = $1 FOR UPDATE",
        )
        .bind(destination)
        .fetch_one(&mut *tx)
        .await?;
        let canonical_recipient = submission.recipient.canonical();
        let existing: Option<(i64, Value)> = sqlx::query_as(
            "SELECT sequence, transaction
             FROM chat_mls_federation_outbox
             WHERE destination = $1 AND recipient = $2 AND send_id = $3
             FOR UPDATE",
        )
        .bind(destination)
        .bind(&canonical_recipient)
        .bind(submission.send_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (sequence, transaction) = if let Some((sequence, value)) = existing {
            let transaction: FederatedAnonymousMlsTransactionV1 = serde_json::from_value(value)
                .map_err(|error| {
                    AppError::internal(format!("stored MLS transaction is invalid: {error}"))
                })?;
            if transaction.submission != submission {
                return Err(AppError::conflict(
                    "anonymous MLS send id was reused with different ciphertext",
                ));
            }
            (sequence, transaction)
        } else {
            let transaction = FederatedAnonymousMlsTransactionV1 {
                origin_domain: server_name.to_owned(),
                origin_sequence: next_sequence as u64,
                submission: submission.clone(),
            };
            transaction.validate().map_err(AppError::bad_request)?;
            let value = serde_json::to_value(&transaction).map_err(|error| {
                AppError::internal(format!("serialize MLS transaction: {error}"))
            })?;
            sqlx::query(
                "INSERT INTO chat_mls_federation_outbox
                     (destination, sequence, sender_user_id, sender_device_id,
                      recipient, send_id, transaction)
                 VALUES ($1,$2,NULL,NULL,$3,$4,$5)",
            )
            .bind(destination)
            .bind(next_sequence)
            .bind(&canonical_recipient)
            .bind(submission.send_id)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE chat_mls_federation_sequences
                 SET next_sequence = next_sequence + 1
                 WHERE destination = $1",
            )
            .bind(destination)
            .execute(&mut *tx)
            .await?;
            (next_sequence, transaction)
        };
        tx.commit().await?;

        let body = serde_json::to_vec(&transaction)
            .map_err(|error| AppError::internal(format!("serialize MLS transaction: {error}")))?;
        let remote = state
            .federation
            .as_ref()
            .expect("active MLS policy requires federation")
            .send(
                destination,
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
            .await;
        let remote = match remote {
            Ok(remote) => remote,
            Err(error) => {
                tracing::warn!(
                    destination,
                    sequence,
                    error = %error,
                    "anonymous MLS federation delivery queued for retry"
                );
                return Ok((
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({
                        "accepted": true,
                        "queued": true,
                        "deduplicated": false
                    })),
                )
                    .into_response());
            }
        };
        let terminal = remote.status == StatusCode::OK || remote.status == StatusCode::NOT_FOUND;
        if terminal {
            sqlx::query(
                "UPDATE chat_mls_federation_outbox
                 SET state = $3, attempts = attempts + 1, updated_at = now()
                 WHERE destination = $1 AND sequence = $2",
            )
            .bind(destination)
            .bind(sequence)
            .bind(if remote.status == StatusCode::OK {
                "delivered"
            } else {
                "rejected"
            })
            .execute(&state.pool)
            .await?;
        }
        if remote.status == StatusCode::NOT_FOUND {
            return Err(unavailable());
        }
        if remote.status != StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("remote anonymous MLS delivery returned {}", remote.status),
            ));
        }
        let response: AnonymousMlsDeliveryResponseV1 = serde_json::from_slice(&remote.body)
            .map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "remote anonymous MLS delivery response is invalid",
                )
            })?;
        telemetry::mls_anonymous_delivery_event(
            "federated_origin",
            "delivered",
            submission.envelopes.len() as u64,
        );
        return Ok(Json(response).into_response());
    }
    let capability = decode_capability(&submission.capability)?;
    let response = MlsRepository::new(state.pool)
        .store_anonymous_submission(
            &submission.recipient.username,
            &submission,
            &capability,
            &policy.abuse_limits,
            OffsetDateTime::now_utc(),
        )
        .await?;
    telemetry::mls_anonymous_delivery_event(
        "local_destination",
        if response.deduplicated {
            "deduplicated"
        } else {
            "stored"
        },
        submission.envelopes.len() as u64,
    );
    Ok(Json(response).into_response())
}
