//! Authenticated, transport-only chat federation.
//!
//! The common federation stack owns identity, discovery, trust, admission, and
//! authenticated HTTP. This feature adapter owns the remote Chat directory,
//! encrypted-profile boundary, and durable in-order ciphertext delivery.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, AccountAddress, AnonymousPreKeyRequestV1, ChatProfileResponse,
    ChatWsServerMessage, DeliveredEnvelope, DeviceListMismatch, FederatedChatTransaction,
    FederatedSealedTransactionV1, FederationDeliveryError, FederationDeliveryRejection,
    FederationDeliveryResponse, ManifestUpdateRangeProofV1, SealedDeliveryResponseV1,
    SealedMessageSubmissionV1, SendMessagesRequest, TransparencyCheckpointResponse,
    UserPreKeyBundlesResponse,
};
use rand::Rng as _;
use reqwest::Method;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationRequestSpec};
use crate::{federation::FederationStack, AppState};
use kutup_federation_proto::FederationFeature;

const CHAT_FEDERATION_PAYLOAD_VERSION: u16 = 1;
const JSON_CONTENT_TYPE: &str = "application/json";
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEDERATION_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

fn configured_stack(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::bad_request("chat federation is not configured"))
}

pub async fn fetch_remote_bundles(
    state: &AppState,
    address: &AccountAddress,
    transparency_tree_size: u64,
) -> AppResult<UserPreKeyBundlesResponse> {
    let federation = configured_stack(state)?;
    let destination = address
        .server
        .as_deref()
        .ok_or_else(|| AppError::bad_request("remote account requires a server"))?;
    crate::chat_transparency_monitor::verify_before_remote_use(state, destination).await?;
    let path = format!("/api/fed/chat/users/{}/keys", address.username);
    let query = format!("transparencyTreeSize={transparency_tree_size}");
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::GET,
                path,
                query: Some(query),
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("remote chat user not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote chat directory returned {}", response.status),
        ));
    }
    let bundles: UserPreKeyBundlesResponse =
        serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "invalid remote chat directory response",
            )
        })?;
    if bundles.username != address.canonical() {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote chat directory returned the wrong account",
        ));
    }
    Ok(bundles)
}

pub async fn fetch_remote_sealed_bundles(
    state: &AppState,
    address: &AccountAddress,
    request: &AnonymousPreKeyRequestV1,
) -> AppResult<UserPreKeyBundlesResponse> {
    let federation = configured_stack(state)?;
    let destination = address
        .server
        .as_deref()
        .ok_or_else(|| AppError::not_found("sealed delivery unavailable"))?;
    crate::chat_transparency_monitor::verify_before_remote_use(state, destination).await?;
    let path = format!("/api/fed/chat/sealed/users/{}/keys", address.username);
    let body = serde_json::to_vec(request)
        .map_err(|error| AppError::internal(format!("encode sealed bundle request: {error}")))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path,
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status != StatusCode::OK {
        return Err(AppError::not_found("sealed delivery unavailable"));
    }
    let bundles: UserPreKeyBundlesResponse = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::not_found("sealed delivery unavailable"))?;
    if bundles.username != address.canonical() {
        return Err(AppError::not_found("sealed delivery unavailable"));
    }
    Ok(bundles)
}

pub async fn fetch_remote_manifest_range(
    state: &AppState,
    address: &AccountAddress,
    query: &crate::handlers::chat::ManifestRangeQuery,
) -> AppResult<ManifestUpdateRangeProofV1> {
    let federation = configured_stack(state)?;
    let destination = address
        .server
        .as_deref()
        .ok_or_else(|| AppError::bad_request("remote account requires a server"))?;
    let query_string = manifest_range_query_string(query);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::GET,
                path: format!("/api/fed/chat/users/{}/manifest-history", address.username),
                query: Some(query_string),
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found(
            "remote chat manifest history not found",
        ));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote manifest history returned {}", response.status),
        ));
    }
    let proof: ManifestUpdateRangeProofV1 = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest history"))?;
    if proof.account != address.canonical() || proof.from_version != query.from_version {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote manifest history returned the wrong account or range",
        ));
    }
    Ok(proof)
}

pub async fn fetch_remote_checkpoint(
    state: &AppState,
    destination: &str,
    from_tree_size: u64,
) -> AppResult<TransparencyCheckpointResponse> {
    let federation = configured_stack(state)?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::GET,
                path: "/api/fed/chat/transparency/checkpoint".into(),
                query: Some(format!("fromTreeSize={from_tree_size}")),
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!(
                "remote transparency checkpoint returned {}",
                response.status
            ),
        ));
    }
    serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "invalid remote transparency checkpoint response",
        )
    })
}

fn manifest_range_query_string(query: &crate::handlers::chat::ManifestRangeQuery) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("fromVersion", &query.from_version.to_string());
    serializer.append_pair("toVersion", &query.to_version.to_string());
    serializer.append_pair(
        "pageFromVersion",
        &query
            .page_from_version
            .unwrap_or(query.from_version)
            .to_string(),
    );
    if let Some(cursor) = &query.cursor {
        serializer.append_pair("cursor", cursor);
    }
    serializer.append_pair(
        "transparencyTreeSize",
        &query.transparency_tree_size.unwrap_or(0).to_string(),
    );
    serializer.finish()
}

pub async fn fetch_remote_profile(
    state: &AppState,
    address: &AccountAddress,
    version: &str,
    access_key: &[u8],
) -> AppResult<ChatProfileResponse> {
    let federation = configured_stack(state)?;
    let destination = address
        .server
        .as_deref()
        .ok_or_else(|| AppError::bad_request("remote account requires a server"))?;
    crate::chat_transparency_monitor::verify_before_remote_use(state, destination).await?;
    let profile_header = HeaderName::from_static(crate::handlers::chat::PROFILE_ACCESS_KEY_HEADER);
    let profile_value = HeaderValue::from_str(&STANDARD.encode(access_key))
        .map_err(|_| AppError::bad_request("invalid chat profile access key"))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::GET,
                path: format!("/api/fed/chat/users/{}/profile/{version}", address.username),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: vec![(profile_header, profile_value)],
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("remote chat profile not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote chat profile returned {}", response.status),
        ));
    }
    let profile: ChatProfileResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "invalid remote chat profile response",
        )
    })?;
    if profile.version != version {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote chat profile returned the wrong version",
        ));
    }
    Ok(profile)
}

fn federation_gateway_error(error: anyhow::Error) -> AppError {
    if error
        .downcast_ref::<crate::federation::FederationAdmissionError>()
        .is_some()
    {
        return AppError::forbidden(error.to_string());
    }
    AppError::new(
        StatusCode::BAD_GATEWAY,
        format!("federation transport failed: {error}"),
    )
}

#[derive(Debug)]
pub enum FederatedSendOutcome {
    Delivered { deduplicated: bool },
    Mismatch(DeviceListMismatch),
    Rejected(FederationDeliveryRejection),
    Pending,
}

pub enum FederatedSealedOutcome {
    Delivered(SealedDeliveryResponseV1),
    Mismatch(DeviceListMismatch),
    Pending,
}

#[derive(sqlx::FromRow)]
struct SealedFederationOutboxRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    recipient: String,
    transaction: Value,
    state: String,
    attempts: i32,
}

pub async fn enqueue_sealed_send(
    state: &AppState,
    recipient: &AccountAddress,
    request: SealedMessageSubmissionV1,
) -> AppResult<FederatedSealedOutcome> {
    request.validate().map_err(AppError::bad_request)?;
    let federation = configured_stack(state)?;
    let destination = recipient
        .server
        .as_deref()
        .ok_or_else(|| AppError::not_found("sealed delivery unavailable"))?;
    if destination == federation.server_name() {
        return Err(AppError::bad_request(
            "local sealed recipients use local mailbox delivery",
        ));
    }
    crate::chat_transparency_monitor::verify_before_remote_use(state, destination).await?;
    let send_id = Uuid::parse_str(&request.send_id)
        .map_err(|_| AppError::bad_request("sealed sendId is invalid"))?;
    let mut tx = state.pool.begin().await?;
    if let Some((id, state_name, stored_transaction)) = sqlx::query_as::<_, (Uuid, String, Value)>(
        "SELECT id, state, transaction FROM chat_sealed_federation_outbox
         WHERE destination = $1 AND recipient = $2 AND send_id = $3 FOR UPDATE",
    )
    .bind(destination)
    .bind(&recipient.username)
    .bind(send_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        let mut transaction: FederatedSealedTransactionV1 =
            serde_json::from_value(stored_transaction).map_err(|error| {
                AppError::internal(format!("stored sealed transaction is invalid: {error}"))
            })?;
        match state_name.as_str() {
            "delivered" => {
                tx.rollback().await?;
                return Ok(FederatedSealedOutcome::Delivered(
                    SealedDeliveryResponseV1 {
                        stored: request.envelopes.len(),
                        deduplicated: true,
                    },
                ));
            }
            "pending"
                if transaction.capability != request.capability
                    || transaction.envelopes != request.envelopes =>
            {
                return Err(AppError::conflict(
                    "sealed send payload changed while federation delivery is pending",
                ));
            }
            "rejected" => {
                transaction.capability = request.capability;
                transaction.envelopes = request.envelopes;
                sqlx::query(
                    "UPDATE chat_sealed_federation_outbox
                     SET transaction = $2, state = 'pending', attempts = 0,
                         next_attempt_at = now(), last_error_class = NULL, updated_at = now()
                     WHERE id = $1",
                )
                .bind(id)
                .bind(serde_json::to_value(&transaction).map_err(|error| {
                    AppError::internal(format!("encode corrected sealed transaction: {error}"))
                })?)
                .execute(&mut *tx)
                .await?;
            }
            "pending" => {}
            _ => return Err(AppError::internal("invalid sealed federation outbox state")),
        }
        tx.commit().await?;
        return attempt_sealed_outbox(state, id).await;
    }

    let sequence: i64 = sqlx::query_scalar(
        "INSERT INTO chat_sealed_federation_sequences (destination, next_sequence)
         VALUES ($1, 2)
         ON CONFLICT (destination) DO UPDATE SET
             next_sequence = chat_sealed_federation_sequences.next_sequence + 1
         RETURNING next_sequence - 1",
    )
    .bind(destination)
    .fetch_one(&mut *tx)
    .await?;
    let transaction = FederatedSealedTransactionV1 {
        version: 1,
        origin: federation.server_name().to_string(),
        recipient: recipient.username.clone(),
        sequence: u64::try_from(sequence)
            .map_err(|_| AppError::internal("sealed federation sequence is invalid"))?,
        send_id: request.send_id,
        capability: request.capability,
        envelopes: request.envelopes,
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat_sealed_federation_outbox
             (id, destination, sequence, recipient, send_id, transaction)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(destination)
    .bind(sequence)
    .bind(&recipient.username)
    .bind(send_id)
    .bind(serde_json::to_value(&transaction).map_err(|error| {
        AppError::internal(format!("encode sealed federation transaction: {error}"))
    })?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    attempt_sealed_outbox(state, id).await
}

async fn attempt_sealed_outbox(state: &AppState, id: Uuid) -> AppResult<FederatedSealedOutcome> {
    let federation = configured_stack(state)?;
    let row: SealedFederationOutboxRow = sqlx::query_as(
        "SELECT id, destination, sequence, recipient, transaction, state, attempts
         FROM chat_sealed_federation_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    if row.state == "delivered" {
        let transaction: FederatedSealedTransactionV1 = serde_json::from_value(row.transaction)
            .map_err(|error| AppError::internal(format!("stored sealed transaction: {error}")))?;
        return Ok(FederatedSealedOutcome::Delivered(
            SealedDeliveryResponseV1 {
                stored: transaction.envelopes.len(),
                deduplicated: true,
            },
        ));
    }
    if row.state == "rejected" {
        return Ok(FederatedSealedOutcome::Pending);
    }
    let head: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(sequence) FROM chat_sealed_federation_outbox
         WHERE destination = $1 AND state = 'pending'",
    )
    .bind(&row.destination)
    .fetch_one(&state.pool)
    .await?;
    if head != Some(row.sequence) {
        return Ok(FederatedSealedOutcome::Pending);
    }
    let transaction: FederatedSealedTransactionV1 = serde_json::from_value(row.transaction.clone())
        .map_err(|error| {
            AppError::internal(format!("stored sealed transaction is invalid: {error}"))
        })?;
    if transaction.recipient != row.recipient {
        return Err(AppError::internal(
            "sealed outbox recipient does not match its transaction",
        ));
    }
    let body = serde_json::to_vec(&transaction)
        .map_err(|error| AppError::internal(format!("encode sealed transaction: {error}")))?;
    let response = match federation
        .send(
            &row.destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path: "/api/fed/chat/sealed/messages".into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                request_id: row.id.to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            mark_sealed_retry(state, &row, "transport").await?;
            tracing::warn!(destination = %row.destination, error = %error, "sealed federation retry deferred");
            return Ok(FederatedSealedOutcome::Pending);
        }
    };
    match response.status {
        StatusCode::OK => {
            let delivered: SealedDeliveryResponseV1 = serde_json::from_slice(&response.body)
                .map_err(|_| {
                    AppError::new(StatusCode::BAD_GATEWAY, "invalid sealed delivery response")
                })?;
            sqlx::query(
                "UPDATE chat_sealed_federation_outbox
                 SET state = 'delivered', attempts = attempts + 1,
                     last_error_class = NULL, updated_at = now() WHERE id = $1",
            )
            .bind(row.id)
            .execute(&state.pool)
            .await?;
            Ok(FederatedSealedOutcome::Delivered(delivered))
        }
        StatusCode::CONFLICT => {
            let error: FederationDeliveryError =
                serde_json::from_slice(&response.body).map_err(|_| {
                    AppError::new(StatusCode::BAD_GATEWAY, "invalid sealed conflict response")
                })?;
            match error {
                FederationDeliveryError::DeviceListMismatch { mismatch } => {
                    sqlx::query(
                        "UPDATE chat_sealed_federation_outbox
                         SET state = 'rejected', attempts = attempts + 1,
                             last_error_class = 'device_mismatch', updated_at = now()
                         WHERE id = $1",
                    )
                    .bind(row.id)
                    .execute(&state.pool)
                    .await?;
                    Ok(FederatedSealedOutcome::Mismatch(mismatch))
                }
                FederationDeliveryError::SequenceGap { .. } => {
                    mark_sealed_retry(state, &row, "sequence_gap").await?;
                    Ok(FederatedSealedOutcome::Pending)
                }
            }
        }
        StatusCode::NOT_FOUND => {
            sqlx::query(
                "UPDATE chat_sealed_federation_outbox
                 SET state = 'rejected', attempts = attempts + 1,
                     last_error_class = 'unavailable', updated_at = now() WHERE id = $1",
            )
            .bind(row.id)
            .execute(&state.pool)
            .await?;
            Err(AppError::not_found("sealed delivery unavailable"))
        }
        _ => {
            mark_sealed_retry(state, &row, "remote_error").await?;
            Ok(FederatedSealedOutcome::Pending)
        }
    }
}

async fn mark_sealed_retry(
    state: &AppState,
    row: &SealedFederationOutboxRow,
    class: &str,
) -> AppResult<()> {
    let attempt = row.attempts.saturating_add(1).clamp(1, 30);
    let delay = (1_i64 << attempt.min(8)).min(300);
    sqlx::query(
        "UPDATE chat_sealed_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($2 * interval '1 second'),
             last_error_class = $3, updated_at = now()
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(row.id)
    .bind(delay)
    .bind(class)
    .execute(&state.pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct FederationOutboxRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    recipient: String,
    sender: String,
    request: Value,
    state: String,
    response: Option<Value>,
    attempts: i32,
}

/// Persist a remote send before attempting network I/O. A transient remote
/// failure is returned to the client so its own durable outbox remains, but
/// the server queue can make progress independently in the meantime.
pub async fn enqueue_send(
    state: &AppState,
    sender_user_id: Uuid,
    recipient: &AccountAddress,
    request: SendMessagesRequest,
) -> AppResult<FederatedSendOutcome> {
    let federation = configured_stack(state)?;
    crate::handlers::chat::validate_send_request(&request, false, None)?;
    let destination = recipient
        .server
        .as_deref()
        .ok_or_else(|| AppError::bad_request("federated recipient requires a server"))?;
    if destination == federation.server_name() {
        return Err(AppError::bad_request(
            "local recipients must use local mailbox delivery",
        ));
    }
    crate::chat_transparency_monitor::verify_before_remote_use(state, destination).await?;
    let request_value = serde_json::to_value(&request)
        .map_err(|error| AppError::internal(format!("serialize chat send: {error}")))?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR SHARE")
        .bind(sender_user_id)
        .execute(&mut *tx)
        .await?;
    let sender_username: Option<String> = sqlx::query_scalar(
        "UPDATE chat_devices d SET last_seen_at = now()
             FROM users u
             WHERE d.user_id = $1 AND d.device_id = $2 AND u.id = d.user_id
             RETURNING COALESCE(u.username, '')",
    )
    .bind(sender_user_id)
    .bind(request.sender_device_id as i32)
    .fetch_optional(&mut *tx)
    .await?;
    let sender_username =
        sender_username.ok_or_else(|| AppError::not_found("no such chat device"))?;

    let existing: Option<(Uuid, String, Value, Option<Value>, String, String)> = sqlx::query_as(
        "SELECT id, state, request, response, destination, recipient
                 FROM chat_federation_outbox
                 WHERE sender_user_id = $1 AND sender_device_id = $2 AND send_id = $3
                 FOR UPDATE",
    )
    .bind(sender_user_id)
    .bind(request.sender_device_id as i32)
    .bind(&request.send_id)
    .fetch_optional(&mut *tx)
    .await?;

    let id = if let Some((
        id,
        outbox_state,
        prior_request,
        response,
        prior_destination,
        prior_recipient,
    )) = existing
    {
        if prior_destination != destination || prior_recipient != recipient.canonical() {
            return Err(AppError::conflict(
                "sendId is already bound to another federated recipient",
            ));
        }
        match outbox_state.as_str() {
            "delivered" => {
                tx.rollback().await?;
                return delivered_outcome(response, true);
            }
            "mismatch" if prior_request == request_value => {
                tx.rollback().await?;
                let mismatch = response
                    .and_then(|value| serde_json::from_value::<FederationDeliveryError>(value).ok())
                    .and_then(|error| match error {
                        FederationDeliveryError::DeviceListMismatch { mismatch } => Some(mismatch),
                        FederationDeliveryError::SequenceGap { .. } => None,
                    })
                    .ok_or_else(|| AppError::internal("stored federation mismatch is invalid"))?;
                return Ok(FederatedSendOutcome::Mismatch(mismatch));
            }
            "mismatch" => {
                sqlx::query(
                    "UPDATE chat_federation_outbox
                         SET request = $2, state = 'pending', response = NULL,
                             attempts = 0, next_attempt_at = now(), last_error = NULL,
                             updated_at = now()
                         WHERE id = $1",
                )
                .bind(id)
                .bind(&request_value)
                .execute(&mut *tx)
                .await?;
            }
            "pending" if prior_request != request_value => {
                return Err(AppError::conflict(
                    "federated send payload changed before a device mismatch",
                ));
            }
            "pending" => {}
            _ => return Err(AppError::internal("invalid federation outbox state")),
        }
        id
    } else {
        let sequence: i64 = sqlx::query_scalar(
            "INSERT INTO chat_federation_sequences (destination, next_sequence)
                 VALUES ($1, 2)
                 ON CONFLICT (destination) DO UPDATE SET
                     next_sequence = chat_federation_sequences.next_sequence + 1
                 RETURNING next_sequence - 1",
        )
        .bind(destination)
        .fetch_one(&mut *tx)
        .await?;
        let id = Uuid::new_v4();
        let sender = format!("{sender_username}@{}", federation.server_name());
        sqlx::query(
            "INSERT INTO chat_federation_outbox
                    (id, destination, sequence, sender_user_id, sender_device_id,
                     send_id, recipient, sender, request)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(id)
        .bind(destination)
        .bind(sequence)
        .bind(sender_user_id)
        .bind(request.sender_device_id as i32)
        .bind(&request.send_id)
        .bind(recipient.canonical())
        .bind(sender)
        .bind(&request_value)
        .execute(&mut *tx)
        .await?;
        id
    };
    tx.commit().await?;
    attempt_outbox(state, id).await
}

async fn attempt_outbox(state: &AppState, id: Uuid) -> AppResult<FederatedSendOutcome> {
    let federation = configured_stack(state)?;
    let row = load_outbox(state, id)
        .await?
        .ok_or_else(|| AppError::internal("federation outbox row disappeared"))?;
    match row.state.as_str() {
        "delivered" => return delivered_outcome(row.response, true),
        "mismatch" => {
            let mismatch = row
                .response
                .and_then(|value| serde_json::from_value::<FederationDeliveryError>(value).ok())
                .and_then(|error| match error {
                    FederationDeliveryError::DeviceListMismatch { mismatch } => Some(mismatch),
                    FederationDeliveryError::SequenceGap { .. } => None,
                })
                .ok_or_else(|| AppError::internal("stored federation mismatch is invalid"))?;
            return Ok(FederatedSendOutcome::Mismatch(mismatch));
        }
        "pending" => {}
        _ => return Err(AppError::internal("invalid federation outbox state")),
    }

    let head: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(sequence) FROM chat_federation_outbox
             WHERE destination = $1 AND state <> 'delivered'",
    )
    .bind(&row.destination)
    .fetch_one(&state.pool)
    .await?;
    if head != Some(row.sequence) {
        return Ok(FederatedSendOutcome::Pending);
    }

    let message: SendMessagesRequest = serde_json::from_value(row.request.clone())
        .map_err(|error| AppError::internal(format!("invalid federation outbox: {error}")))?;
    let sequence = u64::try_from(row.sequence)
        .map_err(|_| AppError::internal("invalid federation sequence"))?;
    let transaction = FederatedChatTransaction {
        fed_version: CHAT_FEDERATION_PAYLOAD_VERSION,
        transaction_id: row.id.to_string(),
        sequence,
        origin: federation.server_name().to_owned(),
        destination: row.destination.clone(),
        recipient: row.recipient.clone(),
        sender: row.sender.clone(),
        message,
    };
    let body = serde_json::to_vec(&transaction).map_err(|error| {
        AppError::internal(format!("serialize federation transaction: {error}"))
    })?;
    let request_id = delivery_request_id(row.id, &body);
    let response = match federation
        .send(
            &row.destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path: "/api/fed/chat/messages".into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                // The Chat transaction ID is stable across a device-list
                // correction. The transport nonce is stable only for one
                // exact payload version: byte-identical network retries are
                // exact replays, while corrected ciphertext gets a distinct
                // nonce without losing Chat-level idempotency.
                request_id,
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            mark_retry(state, &row, &error.to_string()).await?;
            return Ok(FederatedSendOutcome::Pending);
        }
    };
    let status = response.status;
    let response_body = response.body;

    if status == StatusCode::OK {
        let delivered: FederationDeliveryResponse = serde_json::from_slice(&response_body)
            .map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "invalid federation delivery response",
                )
            })?;
        if delivered.accepted_sequence != sequence {
            mark_retry(state, &row, "remote acknowledged the wrong sequence").await?;
            return Ok(FederatedSendOutcome::Pending);
        }
        let value = serde_json::to_value(&delivered).map_err(|error| {
            AppError::internal(format!("serialize federation response: {error}"))
        })?;
        sqlx::query(
            "UPDATE chat_federation_outbox
                 SET state = 'delivered', response = $2, attempts = attempts + 1,
                     last_error = NULL, updated_at = now()
                 WHERE id = $1",
        )
        .bind(row.id)
        .bind(value)
        .execute(&state.pool)
        .await?;
        return match delivered.rejection {
            Some(rejection) => Ok(FederatedSendOutcome::Rejected(rejection)),
            None => Ok(FederatedSendOutcome::Delivered {
                deduplicated: delivered.deduplicated,
            }),
        };
    }

    if status == StatusCode::CONFLICT {
        let conflict: FederationDeliveryError =
            serde_json::from_slice(&response_body).map_err(|_| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "invalid federation conflict response",
                )
            })?;
        match conflict {
            FederationDeliveryError::DeviceListMismatch { ref mismatch } => {
                let value = serde_json::to_value(&conflict).map_err(|error| {
                    AppError::internal(format!("serialize federation mismatch: {error}"))
                })?;
                sqlx::query(
                    "UPDATE chat_federation_outbox
                         SET state = 'mismatch', response = $2, attempts = attempts + 1,
                             last_error = NULL, updated_at = now()
                         WHERE id = $1",
                )
                .bind(row.id)
                .bind(value)
                .execute(&state.pool)
                .await?;
                return Ok(FederatedSendOutcome::Mismatch(mismatch.clone()));
            }
            FederationDeliveryError::SequenceGap { expected_sequence } => {
                if expected_sequence < sequence {
                    let expected = i64::try_from(expected_sequence)
                        .map_err(|_| AppError::internal("remote requested an invalid sequence"))?;
                    let restored = sqlx::query(
                        "UPDATE chat_federation_outbox
                             SET state = 'pending', next_attempt_at = now(),
                                 last_error = 'remote requested replay after a sequence gap',
                                 updated_at = now()
                             WHERE destination = $1
                               AND sequence >= $2 AND sequence < $3",
                    )
                    .bind(&row.destination)
                    .bind(expected)
                    .bind(row.sequence)
                    .execute(&state.pool)
                    .await?;
                    if restored.rows_affected() == 0 {
                        tracing::error!(
                            destination = %row.destination,
                            expected_sequence,
                            "remote requested a federation transaction outside local retention"
                        );
                    }
                }
                mark_retry(
                    state,
                    &row,
                    &format!("remote expects federation sequence {expected_sequence}"),
                )
                .await?;
                return Ok(FederatedSendOutcome::Pending);
            }
        }
    }

    mark_retry(
        state,
        &row,
        &format!("remote federation delivery returned {status}"),
    )
    .await?;
    Ok(FederatedSendOutcome::Pending)
}

fn delivery_request_id(transaction_id: Uuid, body: &[u8]) -> String {
    format!("{transaction_id}.{}", hex::encode(Sha256::digest(body)))
}

async fn flush_due(state: &AppState) -> AppResult<usize> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM (
                 SELECT DISTINCT ON (destination)
                        id, destination, state, next_attempt_at, sequence
                 FROM chat_federation_outbox
                 WHERE state <> 'delivered'
                 ORDER BY destination, sequence
             ) heads
             WHERE state = 'pending' AND next_attempt_at <= now()
             ORDER BY destination
             LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut completed = 0;
    for id in ids {
        if matches!(
            attempt_outbox(state, id).await,
            Ok(FederatedSendOutcome::Delivered { .. })
        ) {
            completed += 1;
        }
    }
    Ok(completed)
}

async fn load_outbox(state: &AppState, id: Uuid) -> AppResult<Option<FederationOutboxRow>> {
    Ok(sqlx::query_as(
        "SELECT id, destination, sequence, recipient, sender, request,
                state, response, attempts
         FROM chat_federation_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?)
}

fn delivered_outcome(
    response: Option<Value>,
    deduplicated: bool,
) -> AppResult<FederatedSendOutcome> {
    let response = response
        .ok_or_else(|| AppError::internal("delivered federation outbox has no response"))?;
    let delivered: FederationDeliveryResponse = serde_json::from_value(response)
        .map_err(|error| AppError::internal(format!("stored federation response: {error}")))?;
    match delivered.rejection {
        Some(rejection) => Ok(FederatedSendOutcome::Rejected(rejection)),
        None => Ok(FederatedSendOutcome::Delivered { deduplicated }),
    }
}

async fn mark_retry(state: &AppState, row: &FederationOutboxRow, error: &str) -> AppResult<()> {
    let attempt = row.attempts.saturating_add(1).clamp(1, 30);
    let exponential_seconds = 1_i64 << attempt.min(8);
    let jitter_ms = rand::thread_rng().gen_range(0_i64..=1000);
    let delay_ms = exponential_seconds.min(300) * 1000 + jitter_ms;
    let error: String = error.chars().take(500).collect();
    sqlx::query(
        "UPDATE chat_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($2 * interval '1 millisecond'),
             last_error = $3, updated_at = now()
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(row.id)
    .bind(delay_ms)
    .bind(error)
    .execute(&state.pool)
    .await?;
    Ok(())
}

pub fn spawn_retry_worker(state: AppState) {
    if state.federation.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RETRY_INTERVAL);
        loop {
            tick.tick().await;
            match flush_due(&state).await {
                Ok(completed) if completed > 0 => {
                    tracing::info!(completed, "chat federation retry delivered queued sends");
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "chat federation retry failed"),
            }
            if let Err(error) = flush_due_sealed(&state).await {
                tracing::warn!(%error, "sealed chat federation retry failed");
            }
        }
    });
}

async fn flush_due_sealed(state: &AppState) -> AppResult<()> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM chat_sealed_federation_outbox
         WHERE state = 'pending' AND next_attempt_at <= now()
         ORDER BY destination, sequence LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;
    for id in ids {
        let _ = attempt_sealed_outbox(state, id).await;
    }
    Ok(())
}

/// Signed server-to-server directory lookup. This deliberately serves the
/// reusable last-resort PQ bundle rather than consuming one-time keys: a replay
/// of a read request cannot exhaust the recipient's prekey pool.
#[utoipa::path(
    get,
    path = "/api/fed/chat/users/{username}/keys",
    tag = "chat federation",
    params(
        ("username" = String, Path, description = "Recipient username local to this server"),
        ("transparencyTreeSize" = Option<u64>, Query, description = "Origin client's highest verified checkpoint for this destination log")
    ),
    responses(
        (status = 200, description = "Signed manifest and replay-safe PQ bundles", body = UserPreKeyBundlesResponse),
        (status = 401, description = "Invalid federation request signature or destination"),
        (status = 404, description = "Unknown user or federation disabled")
    )
)]
pub async fn get_user_bundles(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<crate::handlers::chat::BundleQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = AccountAddress::local(&username)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let transparency_tree_size = query.transparency_tree_size.unwrap_or(0);
    let path = format!("/api/fed/chat/users/{}/keys", account.username);
    let query = format!("transparencyTreeSize={transparency_tree_size}");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            Some(&query),
            &[],
            FederationFeature::ChatV1,
        )
        .await?;
    let response_username = format!("{}@{}", account.username, federation.server_name());
    let bundles = match crate::handlers::chat::load_user_bundles(
        &state,
        &account.username,
        &response_username,
        None,
        false,
        transparency_tree_size,
        None,
    )
    .await
    {
        Ok(bundles) => bundles,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &bundles)
}

pub async fn get_sealed_user_bundles(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = AccountAddress::local(&username)
        .map_err(|_| AppError::not_found("sealed delivery unavailable"))?;
    let path = format!("/api/fed/chat/sealed/users/{}/keys", account.username);
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            &path,
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let request: AnonymousPreKeyRequestV1 = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("sealed delivery unavailable"),
            )
        }
    };
    let capability = match request.capability_bytes() {
        Ok(capability) => capability,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("sealed delivery unavailable"),
            )
        }
    };
    let response_username = format!("{}@{}", account.username, federation.server_name());
    let bundles = match crate::handlers::chat::load_user_bundles(
        &state,
        &account.username,
        &response_username,
        None,
        true,
        request.transparency_tree_size,
        Some(&capability_hash(&capability)),
    )
    .await
    {
        Ok(bundles) => bundles,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &bundles)
}

/// Signed, sender-unidentified federation delivery. The authenticated origin
/// domain and contiguous sequence are retained; no sender account or device is
/// present in the transaction, mailbox row, response, or destination logs.
pub async fn deliver_sealed_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > 1024 * 1024 {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "sealed transaction exceeds 1 MiB",
        ));
    }
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/sealed/messages",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let transaction: FederatedSealedTransactionV1 = match serde_json::from_slice(&body) {
        Ok(transaction) => transaction,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid sealed federation transaction"),
            )
        }
    };
    if authenticated.destination() != federation.server_name()
        || transaction.origin != authenticated.origin()
    {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::unauthorized("sealed federation origin or destination mismatch"),
        );
    }
    if let Err(error) = transaction.validate(authenticated.origin(), federation.server_name()) {
        return signed_app_error(federation, &authenticated, AppError::bad_request(error));
    }
    let sequence = match i64::try_from(transaction.sequence) {
        Ok(sequence) => sequence,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("sealed federation sequence is too large"),
            )
        }
    };
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771943))")
        .bind(&transaction.origin)
        .execute(&mut *tx)
        .await?;
    if let Some((status, response)) = sqlx::query_as::<_, (i16, Value)>(
        "SELECT response_status, response FROM chat_sealed_federation_inbound
         WHERE origin = $1 AND sequence = $2",
    )
    .bind(&transaction.origin)
    .bind(sequence)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.rollback().await?;
        let status = StatusCode::from_u16(status as u16)
            .map_err(|_| AppError::internal("stored sealed response status is invalid"))?;
        return signed_json(federation, &authenticated, status, &response);
    }
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence), 0) FROM chat_sealed_federation_inbound
         WHERE origin = $1",
    )
    .bind(&transaction.origin)
    .fetch_one(&mut *tx)
    .await?;
    if sequence != last_sequence + 1 {
        tx.rollback().await?;
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            },
        );
    }
    let request = SealedMessageSubmissionV1 {
        send_id: transaction.send_id.clone(),
        capability: transaction.capability.clone(),
        envelopes: transaction.envelopes.clone(),
    };
    let outcome = match crate::handlers::chat::store_sealed_messages(
        &mut tx,
        &transaction.recipient,
        &request,
        Some(&transaction.origin),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            let value = serde_json::json!({ "error": "sealed delivery unavailable" });
            sqlx::query(
                "INSERT INTO chat_sealed_federation_inbound
                     (origin, sequence, send_id, response_status, response)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(&transaction.origin)
            .bind(sequence)
            .bind(
                Uuid::parse_str(&transaction.send_id)
                    .map_err(|_| AppError::bad_request("sealed sendId is invalid"))?,
            )
            .bind(StatusCode::NOT_FOUND.as_u16() as i16)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return signed_json(federation, &authenticated, StatusCode::NOT_FOUND, &value);
        }
        Err(error) => {
            tx.rollback().await?;
            return signed_app_error(federation, &authenticated, error);
        }
    };
    match outcome {
        crate::handlers::chat::SealedStoreOutcome::Mismatch(mismatch) => {
            tx.rollback().await?;
            signed_json(
                federation,
                &authenticated,
                StatusCode::CONFLICT,
                &FederationDeliveryError::DeviceListMismatch { mismatch },
            )
        }
        crate::handlers::chat::SealedStoreOutcome::Delivered { response, stored } => {
            let value = serde_json::to_value(&response).map_err(|error| {
                AppError::internal(format!("encode sealed delivery response: {error}"))
            })?;
            sqlx::query(
                "INSERT INTO chat_sealed_federation_inbound
                     (origin, sequence, send_id, response_status, response)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(&transaction.origin)
            .bind(sequence)
            .bind(
                Uuid::parse_str(&transaction.send_id)
                    .map_err(|_| AppError::bad_request("sealed sendId is invalid"))?,
            )
            .bind(StatusCode::OK.as_u16() as i16)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            crate::handlers::chat::push_sealed(&state, stored).await;
            signed_json(federation, &authenticated, StatusCode::OK, &response)
        }
    }
}

pub async fn get_transparency_checkpoint(
    State(state): State<AppState>,
    Query(query): Query<crate::handlers::chat::CheckpointQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let from_tree_size = query.from_tree_size.unwrap_or(0);
    let query_string = format!("fromTreeSize={from_tree_size}");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            "/api/fed/chat/transparency/checkpoint",
            Some(&query_string),
            &[],
            FederationFeature::ChatV1,
        )
        .await?;
    let mut tx = state.pool.begin().await?;
    let response = match crate::chat_transparency::prove_checkpoint(&mut tx, from_tree_size).await {
        Ok(response) => response,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    tx.commit().await?;
    signed_json(federation, &authenticated, StatusCode::OK, &response)
}

/// Signed server-to-server skipped-manifest recovery. The exact query is
/// reconstructed in canonical field order and is covered by the common HTTP
/// signature profile.
pub async fn get_manifest_history(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<crate::handlers::chat::ManifestRangeQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = AccountAddress::local(&username)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let path = format!("/api/fed/chat/users/{}/manifest-history", account.username);
    let query_string = manifest_range_query_string(&query);
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            Some(&query_string),
            &[],
            FederationFeature::ChatV1,
        )
        .await?;
    let target_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
            .bind(&account.username)
            .fetch_optional(&state.pool)
            .await?;
    let Some(target_id) = target_id else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest history not found"),
        );
    };
    let canonical = format!("{}@{}", account.username, federation.server_name());
    let mut tx = state.pool.begin().await?;
    let proof = match crate::chat_transparency::prove_manifest_range(
        &mut tx,
        target_id,
        &canonical,
        query.from_version,
        query.to_version,
        query.page_from_version.unwrap_or(query.from_version),
        query.cursor.as_deref(),
        query.transparency_tree_size.unwrap_or(0),
    )
    .await
    {
        Ok(proof) => proof,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    tx.commit().await?;
    signed_json(federation, &authenticated, StatusCode::OK, &proof)
}

/// Signed server-to-server encrypted profile lookup. The profile access key is
/// a separate bearer capability; the federation signature authenticates and
/// destination-binds the proxying homeserver.
#[utoipa::path(
    get,
    path = "/api/fed/chat/users/{username}/profile/{version}",
    tag = "chat federation",
    params(
        ("username" = String, Path, description = "Profile owner local to this server"),
        ("version" = String, Path, description = "Profile-key-derived version")
    ),
    responses(
        (status = 200, description = "Opaque encrypted profile", body = ChatProfileResponse),
        (status = 401, description = "Invalid federation request signature"),
        (status = 404, description = "Profile/version/capability not found")
    )
)]
pub async fn get_user_profile(
    State(state): State<AppState>,
    Path((username, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = AccountAddress::local(&username)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let uri = format!("/api/fed/chat/users/{}/profile/{version}", account.username);
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &uri, None, &[], FederationFeature::ChatV1)
        .await?;
    if !crate::handlers::chat::canonical_profile_version(&version) {
        return signed_json(
            federation,
            &authenticated,
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "chat profile not found"}),
        );
    }
    let Some(encoded) = headers
        .get(crate::handlers::chat::PROFILE_ACCESS_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat profile not found"),
        );
    };
    let Ok(access_key) = STANDARD.decode(encoded) else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat profile not found"),
        );
    };
    let profile = match crate::handlers::chat::load_public_profile(
        &state,
        &account.username,
        &version,
        &access_key,
    )
    .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("chat profile not found"),
            )
        }
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &profile)
}

/// Receive one authenticated, in-order server-to-server ciphertext
/// transaction and atomically append it to the existing per-device mailbox.
#[utoipa::path(
    post,
    path = "/api/fed/chat/messages",
    tag = "chat federation",
    request_body = FederatedChatTransaction,
    responses(
        (status = 200, description = "Transaction stored or idempotently replayed", body = FederationDeliveryResponse),
        (status = 401, description = "Invalid signature, origin, or destination"),
        (status = 409, description = "Device list mismatch or sequence gap", body = FederationDeliveryError)
    )
)]
pub async fn deliver_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_FEDERATION_TRANSACTION_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "federation transaction is too large",
        ));
    }
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/messages",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let transaction: FederatedChatTransaction = match serde_json::from_slice(&body) {
        Ok(transaction) => transaction,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid federation transaction"),
            )
        }
    };
    if let Err(error) = validate_transaction(&transaction, &authenticated, federation.server_name())
    {
        return signed_app_error(federation, &authenticated, error);
    }
    if let Err(error) =
        crate::handlers::chat::validate_send_request(&transaction.message, false, None)
    {
        return signed_app_error(federation, &authenticated, error);
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO chat_federation_inbound_state (origin, last_sequence)
         VALUES ($1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(&transaction.origin)
    .execute(&mut *tx)
    .await?;
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM chat_federation_inbound_state
         WHERE origin = $1 FOR UPDATE",
    )
    .bind(&transaction.origin)
    .fetch_one(&mut *tx)
    .await?;
    let sequence = i64::try_from(transaction.sequence)
        .map_err(|_| AppError::bad_request("federation sequence is too large"))?;

    if sequence <= last_sequence {
        let prior: Option<(String, Value)> = sqlx::query_as(
            "SELECT transaction_id, response
             FROM chat_federation_inbound_transactions
             WHERE origin = $1 AND sequence = $2",
        )
        .bind(&transaction.origin)
        .bind(sequence)
        .fetch_optional(&mut *tx)
        .await?;
        tx.rollback().await?;
        if let Some((transaction_id, response)) = prior {
            if transaction_id == transaction.transaction_id {
                let mut delivered: FederationDeliveryResponse = serde_json::from_value(response)
                    .map_err(|error| {
                        AppError::internal(format!("stored federation response: {error}"))
                    })?;
                delivered.deduplicated = true;
                return signed_json(federation, &authenticated, StatusCode::OK, &delivered);
            }
        } else {
            // The replay record may expire before the origin's outbox record.
            // The contiguous high-water mark proves this sequence was already
            // consumed, so acknowledge it without attempting old ciphertext.
            return signed_json(
                federation,
                &authenticated,
                StatusCode::OK,
                &FederationDeliveryResponse {
                    stored: 0,
                    deduplicated: true,
                    accepted_sequence: transaction.sequence,
                    rejection: None,
                },
            );
        }
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            },
        );
    }
    if sequence != last_sequence + 1 {
        tx.rollback().await?;
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            },
        );
    }

    let recipient: AccountAddress =
        transaction
            .recipient
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    let recipient_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE username = $1 AND is_active = true FOR SHARE",
    )
    .bind(&recipient.username)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(recipient_id) = recipient_id else {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: transaction.sequence,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
        tx.commit().await?;
        return signed_json(federation, &authenticated, StatusCode::OK, &response);
    };

    let current: Vec<(i32, i64)> =
        sqlx::query_as("SELECT device_id, registration_id FROM chat_devices WHERE user_id = $1")
            .bind(recipient_id)
            .fetch_all(&mut *tx)
            .await?;
    if current.is_empty() {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: transaction.sequence,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
        tx.commit().await?;
        return signed_json(federation, &authenticated, StatusCode::OK, &response);
    }
    let mismatch =
        crate::handlers::chat::device_list_mismatch(&current, &transaction.message.envelopes);
    if !mismatch.missing_devices.is_empty()
        || !mismatch.stale_devices.is_empty()
        || !mismatch.extra_devices.is_empty()
    {
        tx.rollback().await?;
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::DeviceListMismatch { mismatch },
        );
    }

    let mut stored = Vec::with_capacity(transaction.message.envelopes.len());
    for envelope in &transaction.message.envelopes {
        let (id, cursor, server_ts): (Uuid, i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO chat_mailbox
                (recipient_user_id, recipient_device_id, sender, sender_device_id,
                 envelope_type, suite, content)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(envelope.device_id as i32)
        .bind(&transaction.sender)
        .bind(transaction.message.sender_device_id as i32)
        .bind(crate::handlers::chat::envelope_type_code(
            envelope.envelope_type,
        ))
        .bind(envelope.suite.as_u16() as i16)
        .bind(&envelope.content)
        .fetch_one(&mut *tx)
        .await?;
        stored.push((
            recipient_id,
            envelope.device_id as i32,
            DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender: Some(transaction.sender.clone()),
                sealed_sender: false,
                sender_device_id: transaction.message.sender_device_id,
                envelope_type: envelope.envelope_type,
                suite: envelope.suite,
                content: envelope.content.clone(),
                server_timestamp: server_ts.format(&Rfc3339).unwrap_or_default(),
            },
        ));
    }

    let response = FederationDeliveryResponse {
        stored: stored.len(),
        deduplicated: false,
        accepted_sequence: transaction.sequence,
        rejection: None,
    };
    record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
    tx.commit().await?;

    for (user, device, envelope) in stored {
        let message = ChatWsServerMessage::Envelope { envelope };
        if let Ok(text) = serde_json::to_string(&message) {
            for connection in state.chat_hub.connections(user, device) {
                connection.write(ChatWsOut::Text(text.clone())).await;
            }
        }
    }
    signed_json(federation, &authenticated, StatusCode::OK, &response)
}

fn signed_json<T: serde::Serialize>(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    status: StatusCode,
    value: &T,
) -> AppResult<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|error| AppError::internal(format!("serialize federation response: {error}")))?;
    federation.signed_response(authenticated, status, JSON_CONTENT_TYPE, body)
}

fn signed_app_error(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    error: AppError,
) -> AppResult<Response> {
    let message = if error.status.is_server_error() {
        tracing::error!(status = %error.status, error = %error.message, "federation request failed");
        "internal server error".to_owned()
    } else {
        error.message
    };
    signed_json(
        federation,
        authenticated,
        error.status,
        &serde_json::json!({ "error": message }),
    )
}

async fn record_inbound_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatTransaction,
    sequence: i64,
    response: &FederationDeliveryResponse,
) -> AppResult<()> {
    let response_value = serde_json::to_value(response)
        .map_err(|error| AppError::internal(format!("serialize delivery response: {error}")))?;
    sqlx::query(
        "INSERT INTO chat_federation_inbound_transactions
            (origin, sequence, transaction_id, response)
         VALUES ($1,$2,$3,$4)",
    )
    .bind(&transaction.origin)
    .bind(sequence)
    .bind(&transaction.transaction_id)
    .bind(response_value)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE chat_federation_inbound_state
         SET last_sequence = $2, updated_at = now() WHERE origin = $1",
    )
    .bind(&transaction.origin)
    .bind(sequence)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn validate_transaction(
    transaction: &FederatedChatTransaction,
    authenticated: &AuthenticatedFederationRequest,
    local_server: &str,
) -> AppResult<()> {
    if transaction.fed_version != CHAT_FEDERATION_PAYLOAD_VERSION {
        return Err(AppError::bad_request("unsupported chat federation version"));
    }
    if transaction.origin != authenticated.origin()
        || transaction.destination != authenticated.destination()
        || transaction.destination != local_server
    {
        return Err(AppError::unauthorized(
            "federation transaction identity does not match authorization",
        ));
    }
    if Uuid::parse_str(&transaction.transaction_id).is_err() {
        return Err(AppError::bad_request("invalid federation transaction id"));
    }
    if transaction.sequence == 0 {
        return Err(AppError::bad_request(
            "federation sequence must be positive",
        ));
    }
    if transaction.message.sender_device_id == 0 || transaction.message.sender_device_id > 127 {
        return Err(AppError::bad_request("sender device id is out of range"));
    }
    let sender: AccountAddress =
        transaction
            .sender
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if sender.server.as_deref() != Some(transaction.origin.as_str()) {
        return Err(AppError::unauthorized(
            "federated sender does not belong to the origin server",
        ));
    }
    let recipient: AccountAddress =
        transaction
            .recipient
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if recipient.server.as_deref() != Some(transaction.destination.as_str()) {
        return Err(AppError::bad_request(
            "federated recipient does not belong to this server",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::delivery_request_id;
    use uuid::Uuid;

    #[test]
    fn delivery_transport_nonce_is_stable_only_for_one_payload_version() {
        let id = Uuid::parse_str("10000000-0000-4000-8000-000000000002").unwrap();
        let first = delivery_request_id(id, b"ciphertext-v1");
        assert_eq!(first, delivery_request_id(id, b"ciphertext-v1"));
        assert_ne!(first, delivery_request_id(id, b"ciphertext-v2"));
        assert!(first.len() <= 128);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')));
    }
}
