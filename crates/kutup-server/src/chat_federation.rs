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
    capability_hash, AccountManifestHistoryPageV1, AccountManifestV1, AccountRef,
    AnonymousPreKeyRequestV1, ChatProfileResponse, ChatWsServerMessage, DeliveredEnvelope,
    DeviceListMismatch, FederatedChatTransaction, FederatedSealedBatchItemV1,
    FederatedSealedBatchResponseV1, FederatedSealedBatchV1, FederatedSealedTransactionV1,
    FederationDeliveryError, FederationDeliveryRejection, FederationDeliveryResponse,
    SealedDeliveryResponseV1, SealedMessageSubmissionV1, SendMessagesRequest,
    UserPreKeyBundlesResponse, MAX_SEALED_BATCH_BYTES, MAX_SEALED_BATCH_ITEMS,
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

/// The active user an inbound path's `:accountId` is, on this server.
async fn inbound_user(state: &AppState, account: &AccountRef) -> AppResult<Option<Uuid>> {
    crate::account_ids::local_user(&state.pool, &state.config.chat_server_name, account).await
}

fn configured_stack(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::bad_request("chat federation is not configured"))
}

pub async fn fetch_remote_bundles(
    state: &AppState,
    account: &AccountRef,
) -> AppResult<UserPreKeyBundlesResponse> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let path = format!("/api/fed/chat/accounts/{}/keys", account.account_id);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path,
                query: None,
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
    if bundles.account != *account {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote chat directory returned the wrong account",
        ));
    }
    Ok(bundles)
}

pub async fn fetch_remote_sealed_bundles(
    state: &AppState,
    account: &AccountRef,
    request: &AnonymousPreKeyRequestV1,
) -> AppResult<UserPreKeyBundlesResponse> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let path = format!("/api/fed/chat/sealed/accounts/{}/keys", account.account_id);
    let body = serde_json::to_vec(request)
        .map_err(|error| AppError::internal(format!("encode sealed bundle request: {error}")))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
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
    if bundles.account != *account {
        return Err(AppError::not_found("sealed delivery unavailable"));
    }
    Ok(bundles)
}

pub async fn fetch_remote_manifest_history(
    state: &AppState,
    account: &AccountRef,
    query: &crate::handlers::chat::ManifestHistoryQuery,
) -> AppResult<AccountManifestHistoryPageV1> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let query_string = manifest_history_query_string(query);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path: format!(
                    "/api/fed/chat/accounts/{}/manifest-history",
                    account.account_id
                ),
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
    let page: AccountManifestHistoryPageV1 = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest history"))?;
    if page.account != *account
        || page.from_sequence != query.page_from_sequence.unwrap_or(query.from_sequence)
        || page.to_sequence != query.to_sequence
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote manifest history returned the wrong account or range",
        ));
    }
    page.validate()
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest history"))?;
    Ok(page)
}

pub async fn fetch_remote_manifest(
    state: &AppState,
    account: &AccountRef,
) -> AppResult<AccountManifestV1> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let path = format!("/api/fed/chat/accounts/{}/manifest", account.account_id);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path,
                query: None,
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
        return Err(AppError::not_found("remote chat manifest not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote manifest proof returned {}", response.status),
        ));
    }
    let manifest: AccountManifestV1 = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest response"))?;
    manifest
        .verify()
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest response"))?;
    if manifest.account != *account {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote manifest returned the wrong account",
        ));
    }
    Ok(manifest)
}

fn manifest_history_query_string(query: &crate::handlers::chat::ManifestHistoryQuery) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("fromSequence", &query.from_sequence.to_string());
    serializer.append_pair("toSequence", &query.to_sequence.to_string());
    serializer.append_pair(
        "pageFromSequence",
        &query
            .page_from_sequence
            .unwrap_or(query.from_sequence)
            .to_string(),
    );
    serializer.finish()
}

pub async fn fetch_remote_profile(
    state: &AppState,
    account: &AccountRef,
    version: &str,
    access_key: &[u8],
) -> AppResult<ChatProfileResponse> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let profile_header = HeaderName::from_static(crate::handlers::chat::PROFILE_ACCESS_KEY_HEADER);
    let profile_value = HeaderValue::from_str(&STANDARD.encode(access_key))
        .map_err(|_| AppError::bad_request("invalid chat profile access key"))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path: format!(
                    "/api/fed/chat/accounts/{}/profile/{version}",
                    account.account_id
                ),
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
    if profile.version != version || profile.account != *account {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote chat profile returned the wrong account or version",
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
    Delivered {
        deduplicated: bool,
    },
    Mismatch(DeviceListMismatch),
    Rejected(FederationDeliveryRejection),
    Pending,
    /// Queued, but the recipient's server does not speak this Chat wire
    /// (`chat.v2`): it goes once that server upgrades.
    PeerUnsupported,
}

pub enum FederatedSealedOutcome {
    Delivered(SealedDeliveryResponseV1),
    Mismatch(DeviceListMismatch),
    Pending,
    /// As [`FederatedSendOutcome::PeerUnsupported`].
    PeerUnsupported,
}

/// How long a send to a server without `chat.v2` waits before it is tried
/// again: long enough not to keep asking, short enough that an upgrade is
/// noticed within the hour. Order per destination is kept meanwhile.
const PEER_UNSUPPORTED_RETRY_SECONDS: i64 = 3600;

/// The answer to a send whose recipient's server does not speak this Chat
/// wire: 503 with `code: peerUnsupported`, so apps can say so instead of
/// showing a send that never ends.
pub fn peer_unsupported_error() -> AppError {
    AppError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "the recipient's server does not support this Chat version; the message is queued until it does",
    )
    .with_details(serde_json::json!({ "code": "peerUnsupported" }))
}

#[derive(sqlx::FromRow)]
struct SealedFederationOutboxRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    recipient_account_id: Uuid,
    transaction: Value,
    state: String,
    attempts: i32,
}

pub async fn enqueue_sealed_send(
    state: &AppState,
    recipient: &AccountRef,
    request: SealedMessageSubmissionV1,
) -> AppResult<FederatedSealedOutcome> {
    match enqueue_sealed_row(state, recipient, request).await? {
        Queued::Settled(outcome) => Ok(outcome),
        Queued::Row(id) => attempt_sealed_outbox(state, id).await,
    }
}

/// A sealed send put in its destination's outbox, or already settled there.
pub(crate) enum Queued {
    Settled(FederatedSealedOutcome),
    Row(Uuid),
}

/// Queues a sealed send for a remote recipient without trying it: a repeat
/// of a delivered send is settled, a refused one is queued again with its
/// corrected envelopes, a new one takes the destination's next sequence.
pub(crate) async fn enqueue_sealed_row(
    state: &AppState,
    recipient: &AccountRef,
    request: SealedMessageSubmissionV1,
) -> AppResult<Queued> {
    request.validate().map_err(AppError::bad_request)?;
    let federation = configured_stack(state)?;
    let destination = recipient.server.as_str();
    let recipient_id = Uuid::parse_str(&recipient.account_id)
        .map_err(|_| AppError::internal("a canonical account id is a UUID"))?;
    if destination == federation.server_name() {
        return Err(AppError::bad_request(
            "local sealed recipients use local mailbox delivery",
        ));
    }
    let send_id = Uuid::parse_str(&request.send_id)
        .map_err(|_| AppError::bad_request("sealed sendId is invalid"))?;
    let mut tx = state.pool.begin().await?;
    if let Some((id, state_name, stored_transaction)) = sqlx::query_as::<_, (Uuid, String, Value)>(
        "SELECT id, state, transaction FROM chat_sealed_federation_outbox
         WHERE destination = $1 AND recipient_account_id = $2 AND send_id = $3 FOR UPDATE",
    )
    .bind(destination)
    .bind(recipient_id)
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
                return Ok(Queued::Settled(FederatedSealedOutcome::Delivered(
                    SealedDeliveryResponseV1 {
                        stored: request.envelopes.len(),
                        deduplicated: true,
                    },
                )));
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
        return Ok(Queued::Row(id));
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
        recipient: recipient.clone(),
        sequence: u64::try_from(sequence)
            .map_err(|_| AppError::internal("sealed federation sequence is invalid"))?,
        send_id: request.send_id,
        capability: request.capability,
        envelopes: request.envelopes,
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat_sealed_federation_outbox
             (id, destination, sequence, recipient_account_id, send_id, transaction)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(destination)
    .bind(sequence)
    .bind(recipient_id)
    .bind(send_id)
    .bind(serde_json::to_value(&transaction).map_err(|error| {
        AppError::internal(format!("encode sealed federation transaction: {error}"))
    })?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Queued::Row(id))
}

async fn attempt_sealed_outbox(state: &AppState, id: Uuid) -> AppResult<FederatedSealedOutcome> {
    let federation = configured_stack(state)?;
    let row: SealedFederationOutboxRow = sqlx::query_as(
        "SELECT id, destination, sequence, recipient_account_id, transaction, state, attempts
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
        // Behind a head that waits for the server to support chat.v2: so
        // does this one, and the client is told so.
        let parked: Option<bool> = sqlx::query_scalar(
            "SELECT last_error_class = 'peer_unsupported' FROM chat_sealed_federation_outbox
              WHERE destination = $1 AND state = 'pending' AND sequence = $2",
        )
        .bind(&row.destination)
        .bind(head)
        .fetch_optional(&state.pool)
        .await?
        .flatten();
        if parked == Some(true) {
            return Ok(FederatedSealedOutcome::PeerUnsupported);
        }
        return Ok(FederatedSealedOutcome::Pending);
    }
    let transaction: FederatedSealedTransactionV1 = serde_json::from_value(row.transaction.clone())
        .map_err(|error| {
            AppError::internal(format!("stored sealed transaction is invalid: {error}"))
        })?;
    if transaction.recipient
        != crate::account_ids::stored(&row.destination, row.recipient_account_id)?
    {
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
                feature: FederationFeature::ChatV2,
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
        Err(error) if crate::federation::lacks_capability(&error) => {
            park_sealed_for_upgrade(state, &row).await?;
            tracing::warn!(destination = %row.destination, "sealed federation send waits for the peer to support chat.v2");
            return Ok(FederatedSealedOutcome::PeerUnsupported);
        }
        Err(error) => {
            mark_sealed_retry(state, &row, "transport").await?;
            tracing::warn!(destination = %row.destination, error = %error, "sealed federation retry deferred");
            return Ok(FederatedSealedOutcome::Pending);
        }
    };
    apply_sealed_answer(state, &row, response.status, &response.body).await
}

/// Records the destination's answer to the outbox row it answers, and says
/// what became of that send. One answer, single or in a batch, moves a row
/// the same way.
async fn apply_sealed_answer(
    state: &AppState,
    row: &SealedFederationOutboxRow,
    status: StatusCode,
    body: &[u8],
) -> AppResult<FederatedSealedOutcome> {
    match status {
        StatusCode::OK => {
            let delivered: SealedDeliveryResponseV1 =
                serde_json::from_slice(body).map_err(|_| {
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
            let error: FederationDeliveryError = serde_json::from_slice(body).map_err(|_| {
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
                    mark_sealed_retry(state, row, "sequence_gap").await?;
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
        // A signed refusal of this very message: sending it again cannot
        // help, and waiting on it would hold every later sealed send to that
        // server. The client learns it was refused.
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            if refused_sequence(body) == Some(row.sequence) =>
        {
            sqlx::query(
                "UPDATE chat_sealed_federation_outbox
                 SET state = 'rejected', attempts = attempts + 1,
                     last_error_class = 'refused', updated_at = now() WHERE id = $1",
            )
            .bind(row.id)
            .execute(&state.pool)
            .await?;
            Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "the recipient's server refused this message",
            )
            .with_details(serde_json::json!({ "code": "peerRefused" })))
        }
        _ => {
            mark_sealed_retry(state, row, "remote_error").await?;
            Ok(FederatedSealedOutcome::Pending)
        }
    }
}

/// Delivers a destination's queued sealed sends together: the run of
/// consecutive pending rows from its head, in one federated batch (at most
/// [`MAX_SEALED_BATCH_ITEMS`] and [`MAX_SEALED_BATCH_BYTES`]). Each answer
/// moves its row as a single send's would; rows the destination didn't reach
/// (after an answer that left its sequence open) stay pending. A destination that can't take a batch gets the
/// same rows one by one.
pub(crate) async fn attempt_sealed_batch(
    state: &AppState,
    destination: &str,
) -> AppResult<Vec<(Uuid, AppResult<FederatedSealedOutcome>)>> {
    let federation = configured_stack(state)?;
    let rows: Vec<SealedFederationOutboxRow> = sqlx::query_as(
        "SELECT id, destination, sequence, recipient_account_id, transaction, state, attempts
         FROM chat_sealed_federation_outbox
         WHERE destination = $1 AND state = 'pending'
         ORDER BY sequence LIMIT $2",
    )
    .bind(destination)
    .bind(MAX_SEALED_BATCH_ITEMS as i64)
    .fetch_all(&state.pool)
    .await?;
    // The run from the head: a gap means an earlier send waits on its client.
    let mut run: Vec<SealedFederationOutboxRow> = Vec::new();
    let mut transactions = Vec::new();
    let mut size = 0usize;
    for row in rows {
        if run
            .last()
            .is_some_and(|last| last.sequence + 1 != row.sequence)
        {
            break;
        }
        let transaction: FederatedSealedTransactionV1 =
            serde_json::from_value(row.transaction.clone()).map_err(|error| {
                AppError::internal(format!("stored sealed transaction is invalid: {error}"))
            })?;
        if transaction.recipient
            != crate::account_ids::stored(&row.destination, row.recipient_account_id)?
        {
            return Err(AppError::internal(
                "sealed outbox recipient does not match its transaction",
            ));
        }
        let weight = serde_json::to_vec(&transaction)
            .map_err(|error| AppError::internal(format!("encode sealed transaction: {error}")))?
            .len();
        if !run.is_empty() && size + weight > MAX_SEALED_BATCH_BYTES - 1024 {
            break;
        }
        size += weight;
        transactions.push(transaction);
        run.push(row);
    }
    match run.len() {
        0 => return Ok(Vec::new()),
        1 => {
            let id = run[0].id;
            return Ok(vec![(id, attempt_sealed_outbox(state, id).await)]);
        }
        _ => {}
    }
    let batch = FederatedSealedBatchV1 {
        version: 1,
        origin: federation.server_name().to_string(),
        transactions,
    };
    let body = serde_json::to_vec(&batch)
        .map_err(|error| AppError::internal(format!("encode sealed batch: {error}")))?;
    let sent = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::POST,
                path: "/api/fed/chat/sealed/batch".into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await;
    let mut outcomes = Vec::with_capacity(run.len());
    let response = match sent {
        Ok(response) if response.status == StatusCode::OK => response,
        Err(error) if crate::federation::lacks_capability(&error) => {
            park_sealed_for_upgrade(state, &run[0]).await?;
            for row in &run {
                outcomes.push((row.id, Ok(FederatedSealedOutcome::PeerUnsupported)));
            }
            return Ok(outcomes);
        }
        // Not taken as a batch (an older peer, or the transport failed):
        // the same rows one by one, each with its own retry bookkeeping.
        _ => {
            let mut delivering = true;
            for row in &run {
                let outcome = if delivering {
                    attempt_sealed_outbox(state, row.id).await
                } else {
                    Ok(FederatedSealedOutcome::Pending)
                };
                delivering = matches!(outcome, Ok(FederatedSealedOutcome::Delivered(_)));
                outcomes.push((row.id, outcome));
            }
            return Ok(outcomes);
        }
    };
    let answers: FederatedSealedBatchResponseV1 = match serde_json::from_slice(&response.body) {
        Ok(answers) => answers,
        Err(_) => {
            mark_sealed_retry(state, &run[0], "remote_error").await?;
            for row in &run {
                outcomes.push((row.id, Ok(FederatedSealedOutcome::Pending)));
            }
            return Ok(outcomes);
        }
    };
    let mut answers = answers.results.into_iter();
    for row in &run {
        let outcome = match answers.next() {
            Some(answer) if i64::try_from(answer.sequence).ok() == Some(row.sequence) => {
                let status = StatusCode::from_u16(answer.status)
                    .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid sealed answer"))?;
                let body = serde_json::to_vec(&answer.response).map_err(|error| {
                    AppError::internal(format!("encode sealed answer: {error}"))
                })?;
                apply_sealed_answer(state, row, status, &body).await
            }
            // Not reached (after an answer that left its sequence open), or
            // out of step.
            _ => Ok(FederatedSealedOutcome::Pending),
        };
        outcomes.push((row.id, outcome));
    }
    Ok(outcomes)
}

/// The sequence a signed sealed refusal names as final, if it names one.
fn refused_sequence(body: &[u8]) -> Option<i64> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("refused")?
        .get("sequence")?
        .as_i64()
}

async fn park_sealed_for_upgrade(
    state: &AppState,
    row: &SealedFederationOutboxRow,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE chat_sealed_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($2 * interval '1 second'),
             last_error_class = 'peer_unsupported', updated_at = now()
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(row.id)
    .bind(PEER_UNSUPPORTED_RETRY_SECONDS)
    .execute(&state.pool)
    .await?;
    Ok(())
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
    sender_user_id: Uuid,
    recipient_account_id: Uuid,
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
    recipient: &AccountRef,
    request: SendMessagesRequest,
) -> AppResult<FederatedSendOutcome> {
    let federation = configured_stack(state)?;
    crate::handlers::chat::validate_send_request(&request, false, None)?;
    let destination = recipient.server.as_str();
    if destination == federation.server_name() {
        return Err(AppError::bad_request(
            "local recipients must use local mailbox delivery",
        ));
    }
    let request_value = serde_json::to_value(&request)
        .map_err(|error| AppError::internal(format!("serialize chat send: {error}")))?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR SHARE")
        .bind(sender_user_id)
        .execute(&mut *tx)
        .await?;
    let device: Option<i32> = sqlx::query_scalar(
        "UPDATE chat_devices SET last_seen_at = now()
             WHERE user_id = $1 AND device_id = $2 RETURNING 1",
    )
    .bind(sender_user_id)
    .bind(request.sender_device_id as i32)
    .fetch_optional(&mut *tx)
    .await?;
    device.ok_or_else(|| AppError::not_found("no such chat device"))?;
    let recipient_id = Uuid::parse_str(&recipient.account_id)
        .map_err(|_| AppError::internal("a canonical account id is a UUID"))?;

    let existing: Option<(Uuid, String, Value, Option<Value>, String, Uuid)> = sqlx::query_as(
        "SELECT id, state, request, response, destination, recipient_account_id
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
        if prior_destination != destination || prior_recipient != recipient_id {
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
        sqlx::query(
            "INSERT INTO chat_federation_outbox
                    (id, destination, sequence, sender_user_id, sender_device_id,
                     send_id, recipient_account_id, request)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(destination)
        .bind(sequence)
        .bind(sender_user_id)
        .bind(request.sender_device_id as i32)
        .bind(&request.send_id)
        .bind(recipient_id)
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
        recipient: crate::account_ids::stored(&row.destination, row.recipient_account_id)?,
        sender: crate::account_ids::local(federation.server_name(), row.sender_user_id)?,
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
                feature: FederationFeature::ChatV2,
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
        Err(error) if crate::federation::lacks_capability(&error) => {
            park_for_upgrade(state, &row, &error.to_string()).await?;
            return Ok(FederatedSendOutcome::PeerUnsupported);
        }
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
        "SELECT id, destination, sequence, sender_user_id, recipient_account_id, request,
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

async fn park_for_upgrade(
    state: &AppState,
    row: &FederationOutboxRow,
    error: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE chat_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($2 * interval '1 second'),
             last_error = $3, updated_at = now()
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(row.id)
    .bind(PEER_UNSUPPORTED_RETRY_SECONDS)
    .bind(error)
    .execute(&state.pool)
    .await?;
    Ok(())
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

/// The sealed sends due now: only each destination's head. Rows behind a
/// waiting head (parked for an upgrade, or backing off) would only return
/// early, and a long queue for one server must not fill the page and starve
/// the others.
async fn due_sealed_destinations(pool: &sqlx::PgPool) -> AppResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT destination FROM (
                 SELECT DISTINCT ON (destination) id, destination, next_attempt_at
                 FROM chat_sealed_federation_outbox
                 WHERE state = 'pending'
                 ORDER BY destination, sequence
             ) heads
             WHERE next_attempt_at <= now()
             ORDER BY destination
             LIMIT 100",
    )
    .fetch_all(pool)
    .await?)
}

async fn flush_due_sealed(state: &AppState) -> AppResult<()> {
    for destination in due_sealed_destinations(&state.pool).await? {
        match attempt_sealed_batch(state, &destination).await {
            Ok(outcomes) => {
                for (id, outcome) in outcomes {
                    if let Err(error) = outcome {
                        tracing::warn!(%id, error = %error.message, "queued sealed federation send failed");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%destination, error = %error.message, "queued sealed federation batch failed");
            }
        }
    }
    Ok(())
}

/// Signed server-to-server directory lookup. This deliberately serves the
/// reusable last-resort PQ bundle rather than consuming one-time keys: a replay
/// of a read request cannot exhaust the recipient's prekey pool.
#[utoipa::path(
    get,
    path = "/api/fed/chat/accounts/{accountId}/keys",
    tag = "chat federation",
    params(
        ("accountId" = String, Path, description = "Recipient's account id on this server")
    ),
    responses(
        (status = 200, description = "Signed manifest and replay-safe PQ bundles", body = UserPreKeyBundlesResponse),
        (status = 401, description = "Invalid federation request signature or destination"),
        (status = 404, description = "Unknown user or federation disabled")
    )
)]
pub async fn get_user_bundles(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let path = format!("/api/fed/chat/accounts/{}/keys", account.account_id);
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &path, None, &[], FederationFeature::ChatV2)
        .await?;
    let bundles = match inbound_user(&state, &account).await {
        Ok(Some(target_id)) => {
            crate::handlers::chat::load_user_bundles(&state, target_id, None, false, None).await
        }
        Ok(None) => Err(AppError::not_found("user not found")),
        Err(error) => Err(error),
    };
    let bundles = match bundles {
        Ok(bundles) => bundles,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &bundles)
}

pub async fn get_sealed_user_bundles(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)
        .map_err(|_| AppError::not_found("sealed delivery unavailable"))?;
    let path = format!("/api/fed/chat/sealed/accounts/{}/keys", account.account_id);
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            &path,
            None,
            &body,
            FederationFeature::ChatV2,
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
    // Not ours, not active, or a wrong capability: one answer.
    let bundles = match inbound_user(&state, &account).await {
        Ok(Some(target_id)) => {
            crate::handlers::chat::load_user_bundles(
                &state,
                target_id,
                None,
                true,
                Some(&capability_hash(&capability)),
            )
            .await
        }
        Ok(None) => Err(AppError::not_found("sealed delivery unavailable")),
        Err(error) => Err(error),
    };
    let bundles = match bundles {
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
            FederationFeature::ChatV2,
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
    match deliver_sealed_one(&state, federation, authenticated.origin(), &transaction).await {
        Ok(answer) => signed_json(federation, &authenticated, answer.status, &answer.body),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `POST /api/fed/chat/sealed/batch`: several of one origin's sealed
/// transactions, in sequence order, applied one by one exactly as the single
/// route applies them. It stops after the first answer that doesn't use up
/// its sequence (the rest would only meet a gap) and answers each one it
/// tried.
#[utoipa::path(
    post,
    path = "/api/fed/chat/sealed/batch",
    tag = "chat federation",
    request_body = kutup_chat_proto::FederatedSealedBatchV1,
    responses(
        (status = 200, description = "Each tried transaction's answer, in order", body = kutup_chat_proto::FederatedSealedBatchResponseV1),
        (status = 400, description = "Malformed batch"),
        (status = 401, description = "Invalid federation request signature or destination"),
        (status = 413, description = "Batch too large"),
    )
)]
pub async fn deliver_sealed_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_SEALED_BATCH_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "sealed batch exceeds its size limit",
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
            "/api/fed/chat/sealed/batch",
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let batch: FederatedSealedBatchV1 = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid sealed federation batch"),
            )
        }
    };
    if authenticated.destination() != federation.server_name() {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::unauthorized("sealed federation destination mismatch"),
        );
    }
    if let Err(error) = batch.validate_shape(authenticated.origin()) {
        return signed_app_error(federation, &authenticated, AppError::bad_request(error));
    }
    let mut results = Vec::with_capacity(batch.transactions.len());
    for transaction in &batch.transactions {
        let answer =
            match deliver_sealed_one(&state, federation, authenticated.origin(), transaction).await
            {
                Ok(answer) => answer,
                Err(error) => SealedAnswer::from_error(error),
            };
        let used_up = answer.uses_up(transaction.sequence);
        results.push(FederatedSealedBatchItemV1 {
            sequence: transaction.sequence,
            status: answer.status.as_u16(),
            response: answer.body,
        });
        // Past an answer that didn't use up its sequence, the next would only
        // meet a gap.
        if !used_up {
            break;
        }
    }
    signed_json(
        federation,
        &authenticated,
        StatusCode::OK,
        &FederatedSealedBatchResponseV1 { results },
    )
}

/// A sealed transaction's answer at this destination: the status and body
/// the single route signs, and the batch route lists per transaction.
pub(crate) struct SealedAnswer {
    status: StatusCode,
    body: Value,
}

impl SealedAnswer {
    fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> AppResult<Self> {
        Ok(Self {
            status,
            body: serde_json::to_value(value)
                .map_err(|error| AppError::internal(format!("encode sealed answer: {error}")))?,
        })
    }

    /// Whether this answer took its sequence for good: a delivery, the
    /// uniform 404, or a refusal that names the sequence. A device mismatch,
    /// a gap or a passing error leaves the sequence to be tried again.
    fn uses_up(&self, sequence: u64) -> bool {
        match self.status {
            StatusCode::OK | StatusCode::NOT_FOUND => true,
            StatusCode::BAD_REQUEST => {
                self.body
                    .get("refused")
                    .and_then(|refused| refused.get("sequence"))
                    .and_then(Value::as_u64)
                    == Some(sequence)
            }
            _ => false,
        }
    }

    /// An error as the single route answers it (`signed_app_error`).
    fn from_error(error: AppError) -> Self {
        let message = if error.status.is_server_error() {
            tracing::error!(status = %error.status, error = %error.message, "sealed delivery failed");
            "internal server error".to_owned()
        } else {
            error.message
        };
        let mut body = error.details.unwrap_or_default();
        body.insert("error".into(), Value::String(message));
        Self {
            status: error.status,
            body: Value::Object(body),
        }
    }
}

/// Applies one sealed transaction from `origin`, in its origin's sequence
/// order: the single route's whole check, store and record.
async fn deliver_sealed_one(
    state: &AppState,
    federation: &FederationStack,
    origin: &str,
    transaction: &FederatedSealedTransactionV1,
) -> AppResult<SealedAnswer> {
    // A transaction that does not hold up is refused once its sequence is
    // next in line, and the refusal takes that sequence (below): the origin
    // treats it as final, so its later sends must not wait on it.
    let invalid = transaction
        .validate(origin, federation.server_name())
        .err()
        .map(|error| error.to_string());
    let sequence = match i64::try_from(transaction.sequence) {
        Ok(sequence) => sequence,
        Err(_) => {
            return Err(AppError::bad_request(
                "sealed federation sequence is too large",
            ))
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
        return Ok(SealedAnswer {
            status,
            body: response,
        });
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
        return SealedAnswer::json(
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            },
        );
    }
    if let Some(error) = invalid {
        return refuse_sealed(tx, transaction, sequence, error).await;
    }
    let request = SealedMessageSubmissionV1 {
        send_id: transaction.send_id.clone(),
        capability: transaction.capability.clone(),
        envelopes: transaction.envelopes.clone(),
    };
    // Checked by validate: the recipient is on this server. One that is not
    // an account here is answered as a wrong capability.
    let recipient = Uuid::parse_str(&transaction.recipient.account_id).unwrap_or(Uuid::nil());
    let outcome = match crate::handlers::chat::store_sealed_messages(
        &mut tx,
        recipient,
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
            return Ok(SealedAnswer {
                status: StatusCode::NOT_FOUND,
                body: value,
            });
        }
        Err(error)
            if matches!(
                error.status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ) =>
        {
            tx.rollback().await?;
            let tx = state.pool.begin().await?;
            return refuse_sealed(tx, transaction, sequence, error.message).await;
        }
        Err(error) => {
            tx.rollback().await?;
            return Err(error);
        }
    };
    match outcome {
        crate::handlers::chat::SealedStoreOutcome::Mismatch(mismatch) => {
            tx.rollback().await?;
            SealedAnswer::json(
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
            crate::handlers::chat::push_sealed(state, stored).await;
            Ok(SealedAnswer {
                status: StatusCode::OK,
                body: value,
            })
        }
    }
}

/// Signed server-to-server skipped-manifest recovery. The exact query is
/// reconstructed in canonical field order and is covered by the common HTTP
/// signature profile.
pub async fn get_manifest_history(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Query(query): Query<crate::handlers::chat::ManifestHistoryQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let path = format!(
        "/api/fed/chat/accounts/{}/manifest-history",
        account.account_id
    );
    let query_string = manifest_history_query_string(&query);
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            Some(&query_string),
            &[],
            FederationFeature::ChatV2,
        )
        .await?;
    let Some(target_id) = inbound_user(&state, &account).await? else {
        let error = AppError::not_found("chat manifest history not found");
        return signed_app_error(federation, &authenticated, error);
    };
    let incarnation_id: Option<String> = match sqlx::query_scalar(
        "SELECT manifest->>'incarnationId' FROM chat_device_manifests WHERE user_id = $1",
    )
    .bind(target_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(value) => value,
        Err(error) => return signed_app_error(federation, &authenticated, error.into()),
    };
    let Some(incarnation_id) = incarnation_id else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest history not found"),
        );
    };
    if query.from_sequence == 0 || query.to_sequence < query.from_sequence {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid manifest history bounds"),
        );
    }
    let page_from = query.page_from_sequence.unwrap_or(query.from_sequence);
    if page_from < query.from_sequence || page_from > query.to_sequence {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid manifest history page cursor"),
        );
    }
    let values: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT manifest FROM chat_device_manifest_history
         WHERE user_id = $1 AND incarnation_id = $2 AND version BETWEEN $3 AND $4
         ORDER BY version LIMIT 65",
    )
    .bind(target_id)
    .bind(incarnation_id)
    .bind(page_from as i64)
    .bind(query.to_sequence as i64)
    .fetch_all(&state.pool)
    .await?;
    if values.is_empty() {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest history not found"),
        );
    }
    let mut manifests = values
        .into_iter()
        .map(serde_json::from_value::<AccountManifestV1>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppError::internal(format!("stored chat manifest: {error}")))?;
    let next_sequence = if manifests.len() > 64 {
        manifests.truncate(64);
        Some(manifests.last().expect("nonempty page").sequence + 1)
    } else {
        None
    };
    let page = AccountManifestHistoryPageV1 {
        account: manifests[0].account.clone(),
        from_sequence: page_from,
        to_sequence: query.to_sequence,
        manifests,
        next_sequence,
    };
    if let Err(error) = page.validate() {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::internal(format!("stored chat manifest history: {error}")),
        );
    }
    signed_json(federation, &authenticated, StatusCode::OK, &page)
}

/// Signed server-to-server current account manifest.
pub async fn get_manifest(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let path = format!("/api/fed/chat/accounts/{}/manifest", account.account_id);
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &path, None, &[], FederationFeature::ChatV2)
        .await?;
    let Some(target_id) = inbound_user(&state, &account).await? else {
        let error = AppError::not_found("chat manifest not found");
        return signed_app_error(federation, &authenticated, error);
    };
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT manifest FROM chat_device_manifests WHERE user_id = $1")
            .bind(target_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(value) = value else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest not found"),
        );
    };
    let manifest: AccountManifestV1 = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("stored chat manifest: {error}")))?;
    signed_json(federation, &authenticated, StatusCode::OK, &manifest)
}

/// Signed server-to-server encrypted profile lookup. The profile access key is
/// a separate bearer capability; the federation signature authenticates and
/// destination-binds the proxying homeserver.
#[utoipa::path(
    get,
    path = "/api/fed/chat/accounts/{accountId}/profile/{version}",
    tag = "chat federation",
    params(
        ("accountId" = String, Path, description = "Profile owner's account id on this server"),
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
    Path((account_id, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let uri = format!(
        "/api/fed/chat/accounts/{}/profile/{version}",
        account.account_id
    );
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &uri, None, &[], FederationFeature::ChatV2)
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
    let found = match inbound_user(&state, &account).await {
        Ok(Some(target_id)) => {
            crate::handlers::chat::load_public_profile(&state, target_id, &version, &access_key)
                .await
        }
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    };
    let profile = match found {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            let error = AppError::not_found("chat profile not found");
            return signed_app_error(federation, &authenticated, error);
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
            FederationFeature::ChatV2,
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

    let recipient_id: Option<Uuid> = match Uuid::parse_str(&transaction.recipient.account_id) {
        Ok(id) => {
            sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND is_active = true FOR SHARE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
        }
        Err(_) => None,
    };
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

    let sender_account_id = Uuid::parse_str(&transaction.sender.account_id)
        .map_err(|_| AppError::bad_request("the sender's account id is not a UUID"))?;
    let mut stored = Vec::with_capacity(transaction.message.envelopes.len());
    for envelope in &transaction.message.envelopes {
        let (id, cursor, server_ts): (Uuid, i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO chat_mailbox
                (recipient_user_id, recipient_device_id, sender_server, sender_account_id,
                 sender_device_id, envelope_type, suite, content, send_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(envelope.device_id as i32)
        .bind(&transaction.sender.server)
        .bind(sender_account_id)
        .bind(transaction.message.sender_device_id as i32)
        .bind(crate::handlers::chat::envelope_type_code(
            envelope.envelope_type,
        ))
        .bind(envelope.suite.as_u16() as i16)
        .bind(&envelope.content)
        .bind(&transaction.message.send_id)
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
                send_id: Some(transaction.message.send_id.clone()),
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
        crate::web_push::wake_if_offline(&state, user, device);
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

/// Refuses a sealed transaction (400). The refusal is final only when it is
/// recorded against the transaction's sequence (that sequence is next, and
/// its sendId is a fresh UUID): then the answer names the sequence
/// (`refused.sequence`), a replay gets the same answer, and the origin's
/// later sends meet no gap. Otherwise the 400 names nothing and the origin
/// keeps the send pending. Counted in the origin's rate first, so refusals
/// cannot be written faster than deliveries.
async fn refuse_sealed(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedSealedTransactionV1,
    sequence: i64,
    error: String,
) -> AppResult<SealedAnswer> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771943))")
        .bind(&transaction.origin)
        .execute(&mut *tx)
        .await?;
    let origin_digest: [u8; 32] = sha2::Sha256::digest(
        [
            b"kutup/sealed-origin-rate/v1\0".as_slice(),
            transaction.origin.as_bytes(),
        ]
        .concat(),
    )
    .into();
    if let Err(limited) = crate::handlers::chat::consume_anonymous_rate(
        &mut tx,
        "federation_origin",
        &origin_digest,
        600,
        60,
    )
    .await
    {
        tx.rollback().await?;
        return Ok(SealedAnswer::from_error(limited));
    }
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence), 0) FROM chat_sealed_federation_inbound
         WHERE origin = $1",
    )
    .bind(&transaction.origin)
    .fetch_one(&mut *tx)
    .await?;
    let send_id = Uuid::parse_str(&transaction.send_id).ok();
    let final_value = serde_json::json!({ "error": error, "refused": { "sequence": sequence } });
    let recorded = match send_id {
        Some(send_id) if sequence == last_sequence + 1 => {
            sqlx::query(
                "INSERT INTO chat_sealed_federation_inbound
                 (origin, sequence, send_id, response_status, response)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT DO NOTHING",
            )
            .bind(&transaction.origin)
            .bind(sequence)
            .bind(send_id)
            .bind(StatusCode::BAD_REQUEST.as_u16() as i16)
            .bind(&final_value)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1
        }
        _ => false,
    };
    tx.commit().await?;
    Ok(SealedAnswer {
        status: StatusCode::BAD_REQUEST,
        body: if recorded {
            final_value
        } else {
            serde_json::json!({ "error": error })
        },
    })
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
    // A client error's details go back with it (a held name's `renamed`
    // and its chains).
    let mut body = error.details.unwrap_or_default();
    body.insert("error".into(), serde_json::Value::String(message));
    signed_json(
        federation,
        authenticated,
        error.status,
        &serde_json::Value::Object(body),
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
    check_accounts(transaction)
}

/// The sender is the origin's account (a peer speaks only for its own
/// accounts) and the recipient the destination's. Both parsed canonical:
/// AccountRef refuses anything else.
fn check_accounts(transaction: &FederatedChatTransaction) -> AppResult<()> {
    if transaction.sender.server != transaction.origin {
        return Err(AppError::unauthorized(
            "federated sender does not belong to the origin server",
        ));
    }
    if transaction.recipient.server != transaction.destination {
        return Err(AppError::bad_request(
            "federated recipient does not belong to this server",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A backlog for one server does not starve another, and a parked head
    /// holds back only its own server. Needs the database:
    /// `KUTUP_LIVE_DATABASE_URL` (the backup gate).
    #[tokio::test]
    async fn live_sealed_backlog_does_not_starve_other_destinations() {
        let Ok(database_url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let tag = Uuid::new_v4().simple().to_string();
        let (slow, other) = (
            format!("slow{}.example", &tag[..8]),
            format!("ok{}.example", &tag[..8]),
        );
        let insert = |destination: String, sequence: i64| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO chat_sealed_federation_outbox
                         (destination, sequence, recipient_account_id, send_id, transaction)
                     VALUES ($1, $2, gen_random_uuid(), gen_random_uuid(), '{}'::jsonb) RETURNING id",
                )
                .bind(destination)
                .bind(sequence)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let slow_head = insert(slow.clone(), 1).await;
        for sequence in 2..=150 {
            insert(slow.clone(), sequence).await;
        }
        insert(other.clone(), 1).await;

        let due = super::due_sealed_destinations(&pool).await.unwrap();
        let ours = due
            .iter()
            .filter(|destination| **destination == slow || **destination == other)
            .count();
        assert_eq!(ours, 2, "each destination once, however long its queue");

        // The slow server's head waits an hour for its upgrade: nothing of
        // it is due, and the other server still is.
        sqlx::query(
            "UPDATE chat_sealed_federation_outbox
                SET next_attempt_at = now() + interval '1 hour', last_error_class = 'peer_unsupported'
              WHERE id = $1",
        )
        .bind(slow_head)
        .execute(&pool)
        .await
        .unwrap();
        let due = super::due_sealed_destinations(&pool).await.unwrap();
        assert!(due.contains(&other));
        assert!(!due.contains(&slow), "a parked head holds its queue");

        sqlx::query("DELETE FROM chat_sealed_federation_outbox WHERE destination = ANY($1)")
            .bind(vec![slow, other])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn a_batch_goes_on_only_past_answers_that_use_up_their_sequence() {
        use axum::http::StatusCode;
        use serde_json::{json, Value};
        let answer = |status: StatusCode, body: Value| super::SealedAnswer { status, body };
        // A delivery, the uniform 404 and a refusal naming the sequence take it.
        assert!(answer(StatusCode::OK, json!({"stored": 1})).uses_up(7));
        assert!(answer(StatusCode::NOT_FOUND, json!({"error": "x"})).uses_up(7));
        assert!(answer(StatusCode::BAD_REQUEST, json!({"refused": {"sequence": 7}})).uses_up(7));
        // A refusal of another sequence, or naming none, leaves it open.
        assert!(!answer(StatusCode::BAD_REQUEST, json!({"refused": {"sequence": 8}})).uses_up(7));
        assert!(!answer(StatusCode::BAD_REQUEST, json!({"error": "x"})).uses_up(7));
        // So do a device mismatch, a gap, a limit and a server error.
        for status in [
            StatusCode::CONFLICT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::UNAUTHORIZED,
        ] {
            assert!(!answer(status, json!({})).uses_up(7), "{status}");
        }
    }

    #[test]
    fn only_a_refusal_naming_the_sequence_is_final() {
        let named = br#"{"error":"bad","refused":{"sequence":7}}"#;
        assert_eq!(super::refused_sequence(named), Some(7));
        // A 400 before the sequence was known names none: not final.
        assert_eq!(
            super::refused_sequence(br#"{"error":"invalid sealed federation transaction"}"#),
            None
        );
        assert_eq!(super::refused_sequence(b"not json"), None);
    }

    #[test]
    fn a_peer_speaks_only_for_its_own_accounts() {
        let account = |server: &str| {
            kutup_chat_proto::AccountRef::new(server, "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b")
                .unwrap()
        };
        let transaction =
            |sender: &str, recipient: &str| kutup_chat_proto::FederatedChatTransaction {
                fed_version: super::CHAT_FEDERATION_PAYLOAD_VERSION,
                transaction_id: Uuid::new_v4().to_string(),
                sequence: 1,
                origin: "a.example".into(),
                destination: "b.example".into(),
                recipient: account(recipient),
                sender: account(sender),
                message: kutup_chat_proto::SendMessagesRequest {
                    sender_device_id: 1,
                    send_id: Uuid::new_v4().to_string(),
                    envelopes: Vec::new(),
                    access_token: None,
                },
            };
        assert!(super::check_accounts(&transaction("a.example", "b.example")).is_ok());
        // A delivering a sender of C, or of the destination itself: refused.
        let forged = super::check_accounts(&transaction("c.example", "b.example")).unwrap_err();
        assert_eq!(forged.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(super::check_accounts(&transaction("b.example", "b.example")).is_err());
        // A recipient on another server than the destination: refused.
        assert!(super::check_accounts(&transaction("a.example", "c.example")).is_err());
    }

    #[test]
    fn federated_accounts_must_be_canonical() {
        let account = |server: &str, id: &str| {
            serde_json::from_value::<kutup_chat_proto::AccountRef>(
                serde_json::json!({ "server": server, "accountId": id }),
            )
        };
        let id = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        assert!(account("origin.example", id).is_ok());
        for (server, id) in [
            ("Origin.Example", id),
            ("origin.example.", id),
            ("origin.example", "0B6B5E0C-4C1E-4B8E-9C2D-6A1F3E5D7C9B"),
            ("origin.example", "alice"),
        ] {
            assert!(account(server, id).is_err(), "{server} {id}");
        }
    }

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
