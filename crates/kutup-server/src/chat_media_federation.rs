//! Sender-free, restart-safe federation for immutable Chat-media objects.
//!
//! The origin may retain its authenticated sender in the outbox and pull
//! grant. The signed transaction, destination receipt, destination object,
//! quota rows, and logs never contain the sender account or device.

use kutup_crypto::primitives::{hash, Suite};
use std::time::Duration;

use aws_sdk_s3::primitives::{ByteStream, Length};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, constant_time_capability_hash_eq, ChatMediaDeliveryOfferV1,
    ChatMediaDeliveryStatusV1, ChatMediaOfferResponseV1, FederatedChatMediaTransactionV1,
};
use kutup_federation_proto::{content_digest_sha256_from_digest, FederationFeature};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationRequestSpec, FederationStack};
use crate::federation_outbox;
use crate::handlers::chat_media;
use crate::AppState;

const JSON: &str = "application/json";
const OCTETS: &str = "application/octet-stream";
const OFFER_PATH: &str = "/api/fed/chat/media/offers";
const OBJECT_PATH: &str = "/api/fed/chat/media/objects";

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.hyphenated().to_string() == value)
}

fn decode_token_hash(value: &str) -> Option<[u8; 32]> {
    let decoded = STANDARD.decode(value).ok()?;
    if decoded.len() != 32 || STANDARD.encode(&decoded) != value {
        return None;
    }
    Some(hash(Suite::V1, decoded).into())
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::CONFLICT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::GATEWAY_TIMEOUT
        || status.is_server_error()
}

fn signed_json<T: Serialize>(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    status: StatusCode,
    value: &T,
) -> AppResult<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|error| AppError::internal(format!("serialize Chat-media response: {error}")))?;
    federation.signed_response(authenticated, status, JSON, body)
}

fn signed_error(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    error: AppError,
) -> AppResult<Response> {
    let message = if error.status.is_server_error() {
        // Keep the signed wire response generic, but retain the internal
        // failure class for operators. Call sites must not put account,
        // capability, certificate, or ciphertext values in AppError text.
        tracing::error!(
            status = %error.status,
            error = %error.message,
            "Chat-media federation request failed"
        );
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

fn offer_spec(transaction: &FederatedChatMediaTransactionV1) -> AppResult<FederationRequestSpec> {
    let body = serde_json::to_vec(transaction)
        .map_err(|error| AppError::internal(format!("serialize Chat-media offer: {error}")))?;
    Ok(FederationRequestSpec {
        feature: FederationFeature::ChatV2,
        method: Method::POST,
        path: OFFER_PATH.into(),
        query: None,
        content_type: JSON.into(),
        body,
        request_id: format!("chat-media-offer-{}", transaction.offer.operation_id),
        extra_headers: Vec::new(),
        response_limit: 64 * 1024,
    })
}

/// Why an offer didn't get a receipt: the destination can't take media
/// offers yet, a failure that may pass, or its final refusal.
enum OfferFailure {
    Unsupported(String),
    Retry(&'static str, String),
    Refused { status: StatusCode, message: String },
}

async fn send_offer(
    state: &AppState,
    destination: &str,
    transaction: &FederatedChatMediaTransactionV1,
) -> AppResult<Result<ChatMediaOfferResponseV1, OfferFailure>> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("Chat media federation unavailable"))?;
    let response = match federation.send(destination, offer_spec(transaction)?).await {
        Ok(response) => response,
        Err(error) if crate::federation::lacks_capability(&error) => {
            return Ok(Err(OfferFailure::Unsupported(error.to_string())));
        }
        Err(error) => return Ok(Err(OfferFailure::Retry("transport", error.to_string()))),
    };
    if response.status != StatusCode::OK {
        let message = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|body| body.get("error").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| format!("remote Chat-media offer returned {}", response.status));
        // An authentication or routing refusal is no answer to the offer:
        // the receiver records none (the sequence stays open there), so it
        // waits like a failure that may pass, never settles as refused.
        let unanswered = response.status == StatusCode::UNAUTHORIZED
            || response.status == StatusCode::FORBIDDEN;
        return Ok(Err(if unanswered || retryable_status(response.status) {
            OfferFailure::Retry(
                if response.status == StatusCode::CONFLICT {
                    "sequence_conflict"
                } else {
                    "remote_error"
                },
                message,
            )
        } else {
            OfferFailure::Refused {
                status: response.status,
                message,
            }
        }));
    }
    let receipt: Option<ChatMediaOfferResponseV1> = serde_json::from_slice(&response.body).ok();
    let Some(receipt) = receipt.filter(|receipt| {
        receipt.operation_id == transaction.offer.operation_id
            && match receipt.status {
                ChatMediaDeliveryStatusV1::Queued => false,
                ChatMediaDeliveryStatusV1::Stored | ChatMediaDeliveryStatusV1::AlreadyStored => {
                    receipt
                        .storage_reference_id
                        .as_deref()
                        .and_then(canonical_uuid)
                        .is_some()
                }
                ChatMediaDeliveryStatusV1::StorageFull => receipt.storage_reference_id.is_none(),
            }
    }) else {
        return Ok(Err(OfferFailure::Retry(
            "remote_error",
            "remote Chat-media receipt does not match the offer".into(),
        )));
    };
    Ok(Ok(receipt))
}

/// An offer's final answer at the origin, kept in its outbox row so a repeat
/// of the operation gets it again (docs/plans/federation-outbox.md).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
enum MediaAnswer {
    /// The destination's receipt: stored, already stored, or storage full.
    Receipt { receipt: ChatMediaOfferResponseV1 },
    /// The destination refused the offer for good.
    Refused { status: u16, message: String },
}

impl MediaAnswer {
    /// The answer as the client is given it.
    fn into_result(self) -> AppResult<ChatMediaOfferResponseV1> {
        match self {
            MediaAnswer::Receipt { receipt } => Ok(receipt),
            MediaAnswer::Refused { status: 404, .. } => Err(chat_media::unavailable()),
            MediaAnswer::Refused { message, .. } => Err(AppError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("the recipient's server refused the attachment: {message}"),
            )),
        }
    }

    /// Its telemetry outcome, and its row's state and class.
    fn outcome(&self) -> (&'static str, bool, Option<&'static str>) {
        match self {
            MediaAnswer::Receipt { receipt }
                if receipt.status == ChatMediaDeliveryStatusV1::StorageFull =>
            {
                ("storage_full", false, Some("storage_full"))
            }
            MediaAnswer::Receipt { .. } => ("delivered", true, None),
            MediaAnswer::Refused { status: 404, .. } => ("unavailable", false, Some("unavailable")),
            MediaAnswer::Refused { .. } => ("rejected", false, Some("remote_rejection")),
        }
    }
}

/// Settles a pending media row (still at `sequence`) with its final answer,
/// and drops its pull grant: the destination has the object, or won't.
async fn settle_media(
    state: &AppState,
    row: &MediaRow,
    operation_id: Uuid,
    answer: &MediaAnswer,
) -> AppResult<()> {
    let (_, delivered, class) = answer.outcome();
    let value = serde_json::to_value(answer)
        .map_err(|_| AppError::internal("serialize Chat-media answer"))?;
    let mut tx = state.pool.begin().await?;
    if federation_outbox::settle(
        &mut *tx,
        row.id,
        Some(row.sequence),
        delivered,
        class,
        &value,
    )
    .await?
    {
        sqlx::query(
            "DELETE FROM chat_media_federation_pull_grants
             WHERE destination=$1 AND operation_id=$2",
        )
        .bind(&row.destination)
        .bind(operation_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// An offer without what may change between a client's repeats of it (its
/// expiry): two offers of one operation must match in everything else.
fn fixed_part(offer: &ChatMediaDeliveryOfferV1) -> ChatMediaDeliveryOfferV1 {
    ChatMediaDeliveryOfferV1 {
        expires_at: 0,
        ..offer.clone()
    }
}

/// One media row as its sender tries it.
#[derive(sqlx::FromRow)]
struct MediaRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    transaction: Value,
    state: String,
    answer: Option<Value>,
    attempts: i32,
}

const MEDIA_ROW: &str = "id, destination, sequence, payload->'transaction' AS transaction, state,
     answer, attempts";

/// Stage an authenticated local sender's remote delivery, or answer a repeat
/// of it (Signal's model: the client sends its attachment message only once
/// the destination's copy is durable). A settled operation gets its final
/// answer again; a pending one `queued`, and its destination's queue goes
/// now. A new one is queued and tried at once if it is its destination's
/// head. Whatever may still pass is `queued`: the row is durable.
#[tracing::instrument(name = "chat_media.federation.stage", skip_all)]
pub(crate) async fn stage_remote_delivery(
    state: &AppState,
    origin_user_id: Uuid,
    offer: ChatMediaDeliveryOfferV1,
) -> AppResult<ChatMediaOfferResponseV1> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::conflict("Chat media federation unavailable"))?;
    let destination = offer.destination_domain.clone();
    let operation_id = canonical_uuid(&offer.operation_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat media delivery"))?;
    let attachment_id = canonical_uuid(&offer.attachment_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat media delivery"))?;
    let token_hash = decode_token_hash(&offer.retrieval_token)
        .ok_or_else(|| AppError::bad_request("invalid Chat media delivery"))?;
    let recipient = recipient_account_id(&offer)?;
    let key = format!("{origin_user_id}:{operation_id}");
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1127042))")
        .bind(&key)
        .execute(&mut *tx)
        .await?;
    let existing: Option<MediaRow> = sqlx::query_as(&format!(
        "SELECT {MEDIA_ROW} FROM federation_outbox
         WHERE kind = 'media' AND idempotency_key = $1 FOR UPDATE"
    ))
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    let id = if let Some(row) = existing {
        let transaction: FederatedChatMediaTransactionV1 =
            serde_json::from_value(row.transaction.clone())
                .map_err(|_| AppError::internal("stored Chat-media transaction is malformed"))?;
        if fixed_part(&transaction.offer) != fixed_part(&offer)
            || transaction.origin_sequence != row.sequence as u64
        {
            return Err(AppError::conflict("Chat media operation replay changed"));
        }
        if row.state != "pending" {
            tx.rollback().await?;
            let answer: MediaAnswer = row
                .answer
                .and_then(|answer| serde_json::from_value(answer).ok())
                .ok_or_else(|| AppError::internal("settled Chat-media row has no answer"))?;
            return answer.into_result();
        }
        // Asked again: the destination's queue goes now.
        sqlx::query(
            "UPDATE federation_outbox SET next_attempt_at = LEAST(next_attempt_at, now())
             WHERE kind = 'media' AND destination = $1 AND state = 'pending'",
        )
        .bind(&row.destination)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        row.id
    } else {
        type ObjectRow = (i16, i64, String, Vec<u8>);
        let object: Option<ObjectRow> = sqlx::query_as(
            "SELECT suite,ciphertext_bytes,ciphertext_sha256,retrieval_token_hash
             FROM chat_media_objects
             WHERE attachment_id=$1 AND origin_user_id=$2 AND origin_domain=$3",
        )
        .bind(attachment_id)
        .bind(origin_user_id)
        .bind(federation.server_name())
        .fetch_optional(&mut *tx)
        .await?;
        let Some((suite, bytes, digest, stored_token)) = object else {
            return Err(chat_media::unavailable());
        };
        let stored_token: [u8; 32] = stored_token
            .try_into()
            .map_err(|_| AppError::internal("stored Chat-media token is malformed"))?;
        if suite != offer.suite.as_u16() as i16
            || bytes != offer.ciphertext_bytes as i64
            || digest != offer.ciphertext_sha256
            || !constant_time_capability_hash_eq(&stored_token, &token_hash)
        {
            return Err(chat_media::unavailable());
        }
        let sequence =
            federation_outbox::next_sequence(&mut tx, federation_outbox::Kind::Media, &destination)
                .await?;
        let transaction = FederatedChatMediaTransactionV1 {
            version: 1,
            origin_domain: federation.server_name().to_owned(),
            origin_sequence: sequence as u64,
            offer: offer.clone(),
        };
        transaction
            .validate(&destination, OffsetDateTime::now_utc().unix_timestamp())
            .map_err(AppError::bad_request)?;
        let value = serde_json::to_value(&transaction)
            .map_err(|_| AppError::internal("serialize Chat-media transaction"))?;
        sqlx::query(
            "INSERT INTO chat_media_federation_pull_grants
                 (origin_user_id,destination,recipient_account_id,operation_id,attachment_id,
                  retrieval_token_hash,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7))",
        )
        .bind(origin_user_id)
        .bind(&destination)
        .bind(recipient)
        .bind(operation_id)
        .bind(attachment_id)
        .bind(token_hash.as_slice())
        .bind(offer.expires_at as f64)
        .execute(&mut *tx)
        .await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO federation_outbox
                 (kind, destination, sequence, idempotency_key, sender_user_id,
                  recipient_account_id, payload)
             VALUES ('media', $1, $2, $3, $4, $5,
                     jsonb_build_object('transaction', $6::jsonb, 'operationId', $7::text))
             RETURNING id",
        )
        .bind(&destination)
        .bind(sequence)
        .bind(&key)
        .bind(origin_user_id)
        .bind(recipient)
        .bind(value)
        .bind(operation_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        id
    };
    match attempt_media(state, id, "federation_origin").await? {
        Some(answer) => answer.into_result(),
        None => {
            crate::telemetry::chat_media_event("federation_origin", "queued");
            Ok(ChatMediaOfferResponseV1 {
                operation_id: offer.operation_id,
                status: ChatMediaDeliveryStatusV1::Queued,
                storage_reference_id: None,
            })
        }
    }
}

/// Tries a pending media row if it is its destination's head (offers keep
/// their order: the receiver takes them in sequence). Its final answer, or
/// `None` while it waits (not the head, or a try that may pass later).
async fn attempt_media(
    state: &AppState,
    id: Uuid,
    telemetry: &'static str,
) -> AppResult<Option<MediaAnswer>> {
    let Some(row) = sqlx::query_as::<_, MediaRow>(&format!(
        "SELECT {MEDIA_ROW} FROM federation_outbox WHERE id = $1 AND kind = 'media'"
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    else {
        return Err(AppError::internal("Chat-media outbox row disappeared"));
    };
    if row.state != "pending" {
        return Ok(row
            .answer
            .and_then(|answer| serde_json::from_value(answer).ok()));
    }
    let head: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(sequence) FROM federation_outbox
         WHERE kind = 'media' AND destination = $1 AND state = 'pending'",
    )
    .bind(&row.destination)
    .fetch_one(&state.pool)
    .await?;
    if head != Some(row.sequence) {
        return Ok(None);
    }
    let transaction: FederatedChatMediaTransactionV1 =
        serde_json::from_value(row.transaction.clone())
            .map_err(|_| AppError::internal("stored Chat-media transaction is malformed"))?;
    let operation_id = canonical_uuid(&transaction.offer.operation_id)
        .ok_or_else(|| AppError::internal("stored Chat-media operation is malformed"))?;
    let answer = match send_offer(state, &row.destination, &transaction).await? {
        Ok(receipt) => MediaAnswer::Receipt { receipt },
        Err(OfferFailure::Unsupported(error)) => {
            federation_outbox::park_for_upgrade(&state.pool, row.id, Some(row.sequence), &error)
                .await?;
            crate::telemetry::chat_media_event(telemetry, "rescheduled");
            return Ok(None);
        }
        Err(OfferFailure::Retry(class, error)) => {
            federation_outbox::retry_later(
                &state.pool,
                row.id,
                Some(row.sequence),
                row.attempts,
                class,
                &error,
            )
            .await?;
            crate::telemetry::chat_media_event(telemetry, "rescheduled");
            return Ok(None);
        }
        Err(OfferFailure::Refused { status, message }) => MediaAnswer::Refused {
            status: status.as_u16(),
            message,
        },
    };
    settle_media(state, &row, operation_id, &answer).await?;
    crate::telemetry::chat_media_event(telemetry, answer.outcome().0);
    Ok(Some(answer))
}

/// The media offers due now: each due destination's head, tried once.
pub(crate) async fn flush_due(state: &AppState) -> AppResult<()> {
    for destination in
        federation_outbox::due_destinations(&state.pool, federation_outbox::Kind::Media).await?
    {
        let head: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM federation_outbox
             WHERE kind = 'media' AND destination = $1 AND state = 'pending'
             ORDER BY sequence LIMIT 1",
        )
        .bind(&destination)
        .fetch_optional(&state.pool)
        .await?;
        if let Some(id) = head {
            if let Err(error) = attempt_media(state, id, "federation_retry").await {
                tracing::warn!(%error, %destination, "Chat-media federation retry failed");
            }
        }
    }
    Ok(())
}

/// Destination-side signed offer. It verifies the recipient capability before
/// allocating storage, then pulls only through the authenticated origin route.
#[tracing::instrument(name = "chat_media.federation.receive_offer", skip_all)]
pub(crate) async fn receive_offer(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("Chat media federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            OFFER_PATH,
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let result = receive_offer_inner(&state, &authenticated, &body).await;
    match result {
        Ok((status, value)) => {
            crate::telemetry::chat_media_event("federation_destination", "acknowledged");
            signed_json(federation, &authenticated, status, &value)
        }
        Err(error) => {
            crate::telemetry::chat_media_event("federation_destination", "rejected");
            signed_error(federation, &authenticated, error)
        }
    }
}

async fn receive_offer_inner(
    state: &AppState,
    authenticated: &AuthenticatedFederationRequest,
    body: &[u8],
) -> AppResult<(StatusCode, Value)> {
    let federation = state.federation.as_ref().expect("authenticated federation");
    let transaction: FederatedChatMediaTransactionV1 = serde_json::from_slice(body)
        .map_err(|_| AppError::bad_request("invalid federated Chat-media transaction"))?;
    if authenticated.origin() != transaction.origin_domain
        || authenticated.destination() != federation.server_name()
    {
        return Err(AppError::unauthorized(
            "Chat-media federation routing mismatch",
        ));
    }
    let sequence = i64::try_from(transaction.origin_sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| AppError::bad_request("invalid Chat-media sequence"))?;
    let transaction_digest = hex::encode(hash(Suite::V1, body));
    match reserve_inbound_offer(state, &transaction, &transaction_digest, sequence).await? {
        InboundReservation::Final(status, response) => Ok((status, response)),
        InboundReservation::Reserved {
            attachment_id,
            recipient_user_id,
            lease_id,
        } => {
            process_reserved_offer(
                state,
                &transaction,
                &transaction_digest,
                sequence,
                attachment_id,
                recipient_user_id,
                lease_id,
            )
            .await
        }
    }
}

enum InboundReservation {
    Final(StatusCode, Value),
    Reserved {
        attachment_id: Uuid,
        recipient_user_id: Uuid,
        lease_id: Uuid,
    },
}

/// What a valid offer names, or why it is refused for good.
fn check_offer(
    state: &AppState,
    transaction: &FederatedChatMediaTransactionV1,
) -> AppResult<(Uuid, Uuid, Uuid)> {
    let federation = state.federation.as_ref().expect("authenticated federation");
    transaction
        .validate(
            federation.server_name(),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(AppError::bad_request)?;
    let configured_ciphertext_limit = kutup_crypto::chat_media::object_ciphertext_size(
        state.config.chat_media_max_plaintext_bytes,
    )
    .map_err(|_| AppError::internal("invalid Chat-media server limit"))?;
    if transaction.offer.ciphertext_bytes > configured_ciphertext_limit {
        return Err(AppError::bad_request(
            "Chat media exceeds the destination server limit",
        ));
    }
    let operation_id = canonical_uuid(&transaction.offer.operation_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat-media operation"))?;
    let attachment_id = canonical_uuid(&transaction.offer.attachment_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat-media attachment"))?;
    let recipient =
        recipient_account_id(&transaction.offer).map_err(|_| chat_media::unavailable())?;
    decode_token_hash(&transaction.offer.retrieval_token).ok_or_else(chat_media::unavailable)?;
    Ok((operation_id, attachment_id, recipient))
}

/// Records a final refusal of the offer at its sequence (using it up, so the
/// origin's next offer is not a gap) and commits: the refusal's answer.
async fn refuse_offer(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    refusal: AppError,
) -> AppResult<InboundReservation> {
    // Only a refusal that may not pass is recorded: what may (a server
    // error) is the origin's to try again.
    if refusal.status.is_server_error() {
        return Err(refusal);
    }
    let status = refusal_status(&refusal);
    let response = serde_json::json!({ "error": refusal.message });
    // No operation: a refusal may be of an operation already answered.
    persist_inbound_response(
        &mut tx,
        transaction,
        None,
        transaction_digest,
        status,
        &response,
    )
    .await?;
    tx.commit().await?;
    Ok(InboundReservation::Final(status, response))
}

async fn reserve_inbound_offer(
    state: &AppState,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    sequence: i64,
) -> AppResult<InboundReservation> {
    let origin = transaction.origin_domain.as_str();
    let mut tx = state.pool.begin().await?;
    let last_sequence =
        federation_outbox::lock_stream(&mut tx, federation_outbox::Kind::Media, origin).await?;
    if let Some(prior) =
        federation_outbox::prior(&mut tx, federation_outbox::Kind::Media, origin, sequence).await?
    {
        if prior.digest.as_deref() != Some(transaction_digest) {
            return Err(AppError::conflict("Chat-media sequence replay changed"));
        }
        return Ok(InboundReservation::Final(
            StatusCode::from_u16(prior.status as u16)
                .map_err(|_| AppError::internal("stored Chat-media status is malformed"))?,
            prior.answer,
        ));
    }
    if sequence <= last_sequence {
        // Answered, and its record pruned (`federationRecordDays`).
        return Err(AppError::new(
            StatusCode::GONE,
            "Chat-media offer was answered and its record is gone",
        ));
    }
    if sequence != last_sequence + 1 {
        return Err(AppError::conflict(format!(
            "Chat-media sequence gap; expected {}",
            last_sequence + 1
        )));
    }
    let lease_id = Uuid::new_v4();
    type Pending = (String, Uuid, Uuid, i64);
    let pending: Option<Pending> = sqlx::query_as(
        "SELECT transaction_digest,recipient_user_id,attachment_id,ciphertext_bytes
         FROM chat_media_federation_inbound_pending
         WHERE origin=$1 AND sequence=$2",
    )
    .bind(origin)
    .bind(sequence)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((digest, recipient_user_id, attachment_id, stored_bytes)) = pending {
        if digest != transaction_digest || stored_bytes != transaction.offer.ciphertext_bytes as i64
        {
            return Err(AppError::conflict("Chat-media pending replay changed"));
        }
        let claimed = sqlx::query(
            "UPDATE chat_media_federation_inbound_pending
             SET lease_id=$3,lease_until=now()+interval '2 minutes',updated_at=now()
             WHERE origin=$1 AND sequence=$2 AND lease_until<=now()",
        )
        .bind(origin)
        .bind(sequence)
        .bind(lease_id)
        .execute(&mut *tx)
        .await?;
        if claimed.rows_affected() != 1 {
            return Err(AppError::conflict(
                "Chat-media transaction is already processing",
            ));
        }
        tx.commit().await?;
        return Ok(InboundReservation::Reserved {
            attachment_id,
            recipient_user_id,
            lease_id,
        });
    }
    let (operation_id, attachment_id, recipient) = match check_offer(state, transaction) {
        Ok(checked) => checked,
        Err(refusal) => return refuse_offer(tx, transaction, transaction_digest, refusal).await,
    };
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
           SELECT 1 FROM federation_inbound
           WHERE kind='media' AND origin=$1 AND transaction_id=$2
           UNION ALL
           SELECT 1 FROM chat_media_federation_inbound_pending
           WHERE origin=$1 AND operation_id=$3 AND sequence<>$4)",
    )
    .bind(origin)
    .bind(operation_id.to_string())
    .bind(operation_id)
    .bind(sequence)
    .fetch_one(&mut *tx)
    .await?
    {
        let refusal =
            AppError::bad_request("Chat-media operation id was reused at another sequence");
        return refuse_offer(tx, transaction, transaction_digest, refusal).await;
    }
    let capability: Option<[u8; 16]> = STANDARD
        .decode(&transaction.offer.delivery_capability)
        .ok()
        .and_then(|bytes| bytes.try_into().ok());
    let capability_digest = capability.as_ref().map(capability_hash).unwrap_or([0; 32]);
    let recipient_user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND is_active=true")
            .bind(recipient)
            .fetch_optional(&mut *tx)
            .await?;
    let capability_matches = if let Some(recipient_user_id) = recipient_user_id {
        capability.is_some()
            && chat_media::match_delivery_capability(&mut tx, recipient_user_id, &capability_digest)
                .await?
    } else {
        constant_time_capability_hash_eq(&capability_digest, &[0; 32]);
        false
    };
    let Some(recipient_user_id) = recipient_user_id.filter(|_| capability_matches) else {
        let response = serde_json::json!({ "error": "Chat media unavailable" });
        persist_inbound_response(
            &mut tx,
            transaction,
            Some(operation_id),
            transaction_digest,
            StatusCode::NOT_FOUND,
            &response,
        )
        .await?;
        tx.commit().await?;
        return Ok(InboundReservation::Final(StatusCode::NOT_FOUND, response));
    };
    chat_media::consume_media_rate(
        &mut tx,
        "capability_minute",
        &capability_digest,
        crate::ratelimit::Limit::MediaCapabilityMinute,
    )
    .await?;
    chat_media::consume_media_rate(
        &mut tx,
        "federation_origin",
        &hash(
            Suite::V1,
            [
                b"kutup/chat-media/federation-origin-rate/v1\0".as_slice(),
                origin.as_bytes(),
            ]
            .concat(),
        )
        .into(),
        crate::ratelimit::Limit::MediaOrigin,
    )
    .await?;

    if let Err(collision) = check_object_identity(&mut tx, transaction, attachment_id).await {
        return refuse_offer(tx, transaction, transaction_digest, collision).await;
    }
    let existing_reference: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM chat_media_references WHERE user_id=$1 AND attachment_id=$2",
    )
    .bind(recipient_user_id)
    .bind(attachment_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(reference_id) = existing_reference {
        let response = ChatMediaOfferResponseV1 {
            operation_id: transaction.offer.operation_id.clone(),
            status: ChatMediaDeliveryStatusV1::AlreadyStored,
            storage_reference_id: Some(reference_id.to_string()),
        };
        let value = serde_json::to_value(&response)
            .map_err(|_| AppError::internal("serialize Chat-media receipt"))?;
        persist_inbound_response(
            &mut tx,
            transaction,
            Some(operation_id),
            transaction_digest,
            StatusCode::OK,
            &value,
        )
        .await?;
        tx.commit().await?;
        return Ok(InboundReservation::Final(StatusCode::OK, value));
    }
    // The recipient's one storage pool, shared with Drive (crate::storage_pool).
    let pool = crate::storage_pool::lock(&mut tx, recipient_user_id, Default::default()).await?;
    if !pool.fits(transaction.offer.ciphertext_bytes as i64, 0) {
        let response = ChatMediaOfferResponseV1 {
            operation_id: transaction.offer.operation_id.clone(),
            status: ChatMediaDeliveryStatusV1::StorageFull,
            storage_reference_id: None,
        };
        let value = serde_json::to_value(&response)
            .map_err(|_| AppError::internal("serialize Chat-media receipt"))?;
        persist_inbound_response(
            &mut tx,
            transaction,
            Some(operation_id),
            transaction_digest,
            StatusCode::OK,
            &value,
        )
        .await?;
        tx.commit().await?;
        return Ok(InboundReservation::Final(StatusCode::OK, value));
    }
    sqlx::query(
        "INSERT INTO chat_media_federation_inbound_pending
             (origin,sequence,operation_id,transaction_digest,recipient_user_id,
              attachment_id,ciphertext_bytes,lease_id,lease_until)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '2 minutes')",
    )
    .bind(origin)
    .bind(sequence)
    .bind(operation_id)
    .bind(transaction_digest)
    .bind(recipient_user_id)
    .bind(attachment_id)
    .bind(transaction.offer.ciphertext_bytes as i64)
    .bind(lease_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(InboundReservation::Reserved {
        attachment_id,
        recipient_user_id,
        lease_id,
    })
}

/// Whether this server holds the offer's object already (its row locked for
/// the caller's transaction). An attachment id it holds as another object
/// is a final refusal: the origin's object can't be stored under that id.
async fn check_object_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatMediaTransactionV1,
    attachment_id: Uuid,
) -> AppResult<bool> {
    type ExistingObject = (String, i16, i64, String, Vec<u8>);
    let existing: Option<ExistingObject> = sqlx::query_as(
        "SELECT origin_domain,suite,ciphertext_bytes,ciphertext_sha256,retrieval_token_hash
         FROM chat_media_objects WHERE attachment_id=$1 FOR UPDATE",
    )
    .bind(attachment_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((origin, suite, bytes, digest, token)) = existing else {
        return Ok(false);
    };
    let token_hash = decode_token_hash(&transaction.offer.retrieval_token)
        .ok_or_else(chat_media::unavailable)?;
    let token: [u8; 32] = token
        .try_into()
        .map_err(|_| AppError::internal("stored Chat-media token is malformed"))?;
    if origin != transaction.origin_domain
        || suite != transaction.offer.suite.as_u16() as i16
        || bytes != transaction.offer.ciphertext_bytes as i64
        || digest != transaction.offer.ciphertext_sha256
        || !constant_time_capability_hash_eq(&token, &token_hash)
    {
        return Err(AppError::bad_request(
            "Chat-media object identity collision",
        ));
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn process_reserved_offer(
    state: &AppState,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    sequence: i64,
    attachment_id: Uuid,
    recipient_user_id: Uuid,
    lease_id: Uuid,
) -> AppResult<(StatusCode, Value)> {
    let heartbeat_pool = state.pool.clone();
    let heartbeat_origin = transaction.origin_domain.clone();
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            let renewed = sqlx::query(
                "UPDATE chat_media_federation_inbound_pending
                 SET lease_until=now()+interval '2 minutes',updated_at=now()
                 WHERE origin=$1 AND sequence=$2 AND lease_id=$3",
            )
            .bind(&heartbeat_origin)
            .bind(sequence)
            .bind(lease_id)
            .execute(&heartbeat_pool)
            .await;
            if !matches!(renewed, Ok(result) if result.rows_affected() == 1) {
                break;
            }
        }
    });
    let result = process_reserved_offer_inner(
        state,
        transaction,
        transaction_digest,
        sequence,
        attachment_id,
        recipient_user_id,
        lease_id,
    )
    .await;
    heartbeat.abort();
    if result.is_err() {
        let _ = sqlx::query(
            "UPDATE chat_media_federation_inbound_pending
             SET lease_until=now(),updated_at=now()
             WHERE origin=$1 AND sequence=$2 AND lease_id=$3",
        )
        .bind(&transaction.origin_domain)
        .bind(sequence)
        .bind(lease_id)
        .execute(&state.pool)
        .await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn process_reserved_offer_inner(
    state: &AppState,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    sequence: i64,
    attachment_id: Uuid,
    recipient_user_id: Uuid,
    lease_id: Uuid,
) -> AppResult<(StatusCode, Value)> {
    let federation = state.federation.as_ref().expect("authenticated federation");
    let token_hash = decode_token_hash(&transaction.offer.retrieval_token)
        .ok_or_else(chat_media::unavailable)?;
    let operation_id = canonical_uuid(&transaction.offer.operation_id)
        .ok_or_else(|| AppError::internal("reserved Chat-media operation is malformed"))?;
    let mut check = state.pool.begin().await?;
    let object_exists = match check_object_identity(&mut check, transaction, attachment_id).await {
        Ok(exists) => exists,
        Err(collision) => {
            drop(check);
            return refuse_reserved(state, transaction, transaction_digest, lease_id, collision)
                .await;
        }
    };
    check.rollback().await?;
    let mut uploaded_path = None;
    if !object_exists {
        let pull_body = serde_json::to_vec(transaction)
            .map_err(|_| AppError::internal("serialize Chat-media pull"))?;
        let streamed = federation
            .send_streamed(
                &transaction.origin_domain,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV2,
                    method: Method::POST,
                    path: OBJECT_PATH.into(),
                    query: None,
                    content_type: JSON.into(),
                    body: pull_body,
                    request_id: format!("chat-media-pull-{}", transaction.offer.operation_id),
                    extra_headers: Vec::new(),
                    response_limit: usize::try_from(transaction.offer.ciphertext_bytes)
                        .map_err(|_| AppError::bad_request("Chat-media object is too large"))?,
                },
            )
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        // The origin's signed "no such object" (its grant gone or revoked)
        // is final: the offer can't be stored.
        if streamed.status == StatusCode::NOT_FOUND {
            return refuse_reserved(
                state,
                transaction,
                transaction_digest,
                lease_id,
                chat_media::unavailable(),
            )
            .await;
        }
        if streamed.status != StatusCode::OK
            || streamed.content_type != OCTETS
            || streamed.content_length != transaction.offer.ciphertext_bytes
            || hex::encode(streamed.content_sha256) != transaction.offer.ciphertext_sha256
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "origin Chat-media object differs from its signed offer",
            ));
        }
        let path = format!(
            "chat-media/federated/{}/{attachment_id}",
            transaction.origin_domain
        );
        let stream = ByteStream::read_from()
            .file(streamed.file)
            .length(Length::Exact(streamed.content_length))
            .buffer_size(1024 * 1024)
            .build()
            .await
            .map_err(|_| AppError::internal("prepare Chat-media object stream"))?;
        state
            .storage
            .upload(&path, stream, transaction.offer.ciphertext_bytes as i64)
            .await
            .map_err(|_| AppError::internal("store federated Chat-media object"))?;
        uploaded_path = Some(path);
    }

    let result = async {
        let mut tx = state.pool.begin().await?;
        let last_sequence = federation_outbox::lock_stream(
            &mut tx,
            federation_outbox::Kind::Media,
            &transaction.origin_domain,
        )
        .await?;
        let pending: Option<(Uuid, Uuid, i64)> = sqlx::query_as(
            "SELECT recipient_user_id,attachment_id,ciphertext_bytes
             FROM chat_media_federation_inbound_pending
             WHERE origin=$1 AND sequence=$2 AND lease_id=$3 FOR UPDATE",
        )
        .bind(&transaction.origin_domain)
        .bind(sequence)
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await?;
        if pending
            != Some((
                recipient_user_id,
                attachment_id,
                transaction.offer.ciphertext_bytes as i64,
            ))
        {
            return Err(AppError::conflict("Chat-media reservation changed"));
        }
        if sequence != last_sequence + 1 {
            return Err(AppError::conflict(
                "Chat-media reservation sequence changed",
            ));
        }
        let stored = match check_object_identity(&mut tx, transaction, attachment_id).await {
            Ok(stored) => stored,
            Err(collision) => {
                let refused = refuse_reserved_in(
                    &mut tx,
                    transaction,
                    transaction_digest,
                    lease_id,
                    collision,
                )
                .await?;
                tx.commit().await?;
                return AppResult::Ok((refused.0, refused.1, false));
            }
        };
        if !stored {
            let path = uploaded_path
                .as_ref()
                .ok_or_else(|| AppError::internal("Chat-media object disappeared"))?;
            sqlx::query(
                "INSERT INTO chat_media_objects
                     (attachment_id,origin_user_id,origin_domain,suite,ciphertext_bytes,
                      ciphertext_sha256,retrieval_token_hash,storage_path)
                 VALUES ($1,NULL,$2,$3,$4,$5,$6,$7)",
            )
            .bind(attachment_id)
            .bind(&transaction.origin_domain)
            .bind(transaction.offer.suite.as_u16() as i16)
            .bind(transaction.offer.ciphertext_bytes as i64)
            .bind(&transaction.offer.ciphertext_sha256)
            .bind(token_hash.as_slice())
            .bind(path)
            .execute(&mut *tx)
            .await?;
        }
        // Its own pending reservation is the room it is about to use.
        let pool = crate::storage_pool::lock(
            &mut tx,
            recipient_user_id,
            crate::storage_pool::Leave {
                inbound: Some((transaction.origin_domain.as_str(), sequence)),
                ..Default::default()
            },
        )
        .await?;
        if !pool.fits(transaction.offer.ciphertext_bytes as i64, 0) {
            let response = ChatMediaOfferResponseV1 {
                operation_id: transaction.offer.operation_id.clone(),
                status: ChatMediaDeliveryStatusV1::StorageFull,
                storage_reference_id: None,
            };
            let value = serde_json::to_value(&response)
                .map_err(|_| AppError::internal("serialize Chat-media receipt"))?;
            persist_inbound_response(
                &mut tx,
                transaction,
                Some(operation_id),
                transaction_digest,
                StatusCode::OK,
                &value,
            )
            .await?;
            sqlx::query(
                "DELETE FROM chat_media_federation_inbound_pending
                 WHERE origin=$1 AND sequence=$2 AND lease_id=$3",
            )
            .bind(&transaction.origin_domain)
            .bind(sequence)
            .bind(lease_id)
            .execute(&mut *tx)
            .await?;
            // A concurrent quota change can invalidate the reservation after
            // the opaque object was pulled. If this transaction introduced
            // the object row, remove it in the same commit that records the
            // terminal storage-full receipt. The outer cleanup then removes
            // the matching blob. Keeping either half would let a later retry
            // create a reference to storage that no longer exists.
            if uploaded_path.is_some() {
                sqlx::query(
                    "DELETE FROM chat_media_objects
                     WHERE attachment_id=$1 AND NOT EXISTS (
                       SELECT 1 FROM chat_media_references WHERE attachment_id=$1
                     )",
                )
                .bind(attachment_id)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            return AppResult::Ok((StatusCode::OK, value, false));
        }
        let existing_reference: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM chat_media_references WHERE user_id=$1 AND attachment_id=$2",
        )
        .bind(recipient_user_id)
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (reference_id, status) = if let Some(reference_id) = existing_reference {
            (reference_id, ChatMediaDeliveryStatusV1::AlreadyStored)
        } else {
            let reference_id: Uuid = sqlx::query_scalar(
                "INSERT INTO chat_media_references(user_id,attachment_id,logical_bytes)
                 VALUES ($1,$2,$3) RETURNING id",
            )
            .bind(recipient_user_id)
            .bind(attachment_id)
            .bind(transaction.offer.ciphertext_bytes as i64)
            .fetch_one(&mut *tx)
            .await?;
            crate::storage_pool::charge(
                &mut *tx,
                crate::storage_pool::Payer::Account(recipient_user_id),
                transaction.offer.ciphertext_bytes as i64,
            )
            .await?;
            (reference_id, ChatMediaDeliveryStatusV1::Stored)
        };
        let response = ChatMediaOfferResponseV1 {
            operation_id: transaction.offer.operation_id.clone(),
            status,
            storage_reference_id: Some(reference_id.to_string()),
        };
        let value = serde_json::to_value(&response)
            .map_err(|_| AppError::internal("serialize Chat-media receipt"))?;
        persist_inbound_response(
            &mut tx,
            transaction,
            Some(operation_id),
            transaction_digest,
            StatusCode::OK,
            &value,
        )
        .await?;
        sqlx::query(
            "DELETE FROM chat_media_federation_inbound_pending
             WHERE origin=$1 AND sequence=$2 AND lease_id=$3",
        )
        .bind(&transaction.origin_domain)
        .bind(sequence)
        .bind(lease_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        AppResult::Ok((StatusCode::OK, value, true))
    }
    .await;
    match result {
        Ok((status, response, keep_uploaded_object)) => {
            if !keep_uploaded_object {
                if let Some(path) = uploaded_path {
                    let _ = state.storage.delete(&path).await;
                }
            }
            Ok((status, response))
        }
        Err(error) => {
            if let Some(path) = uploaded_path {
                let _ = state.storage.delete(&path).await;
            }
            Err(error)
        }
    }
}

/// Records this server's final answer to the offer at its sequence, using
/// the sequence up. `operation` is the offer's operation where the answer is
/// that operation's (not a refusal, which may be of a reused one).
async fn persist_inbound_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatMediaTransactionV1,
    operation: Option<Uuid>,
    transaction_digest: &str,
    status: StatusCode,
    response: &Value,
) -> AppResult<()> {
    let recorded = federation_outbox::record(
        tx,
        federation_outbox::Kind::Media,
        &transaction.origin_domain,
        transaction.origin_sequence as i64,
        operation.map(|operation| operation.to_string()).as_deref(),
        Some(transaction_digest),
        status.as_u16(),
        response,
    )
    .await?;
    if !recorded {
        return Err(AppError::conflict(
            "Chat-media offer was answered meanwhile",
        ));
    }
    Ok(())
}

/// [`refuse_reserved_in`] in a transaction of its own.
async fn refuse_reserved(
    state: &AppState,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    lease_id: Uuid,
    refusal: AppError,
) -> AppResult<(StatusCode, Value)> {
    let mut tx = state.pool.begin().await?;
    let last_sequence = federation_outbox::lock_stream(
        &mut tx,
        federation_outbox::Kind::Media,
        &transaction.origin_domain,
    )
    .await?;
    if transaction.origin_sequence as i64 != last_sequence + 1 {
        return Err(AppError::conflict(
            "Chat-media reservation sequence changed",
        ));
    }
    let refused =
        refuse_reserved_in(&mut tx, transaction, transaction_digest, lease_id, refusal).await?;
    tx.commit().await?;
    Ok(refused)
}

/// Ends a reserved offer with a final refusal (recorded, using up its
/// sequence), while this caller still holds its lease. The caller holds the
/// origin's stream.
async fn refuse_reserved_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    lease_id: Uuid,
    refusal: AppError,
) -> AppResult<(StatusCode, Value)> {
    let released = sqlx::query(
        "DELETE FROM chat_media_federation_inbound_pending
         WHERE origin=$1 AND sequence=$2 AND lease_id=$3",
    )
    .bind(&transaction.origin_domain)
    .bind(transaction.origin_sequence as i64)
    .bind(lease_id)
    .execute(&mut **tx)
    .await?;
    if released.rows_affected() != 1 {
        return Err(AppError::conflict("Chat-media reservation changed"));
    }
    let status = refusal_status(&refusal);
    let response = serde_json::json!({ "error": refusal.message });
    persist_inbound_response(tx, transaction, None, transaction_digest, status, &response).await?;
    Ok((status, response))
}

/// The status a final refusal is recorded with: "unavailable" (404) as it
/// is, every other one a 400, which the origin never tries again.
fn refusal_status(refusal: &AppError) -> StatusCode {
    if refusal.status == StatusCode::NOT_FOUND {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// Origin-side object pull. A valid upload token is insufficient: the signed
/// caller must be the destination bound into an unexpired staged grant.
pub(crate) async fn serve_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("Chat media federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            OBJECT_PATH,
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let result = serve_object_inner(&state, &authenticated, &body).await;
    match result {
        Ok((path, bytes, digest)) => {
            let (object, stored_bytes) = match state.storage.get_object(&path).await {
                Ok(value) => value,
                Err(_) => {
                    return signed_error(
                        federation,
                        &authenticated,
                        AppError::internal("Chat-media storage unavailable"),
                    )
                }
            };
            if stored_bytes != bytes {
                return signed_error(
                    federation,
                    &authenticated,
                    AppError::internal("Chat-media storage length mismatch"),
                );
            }
            let Some(digest): Option<[u8; 32]> = hex::decode(digest)
                .ok()
                .and_then(|value| value.try_into().ok())
            else {
                return signed_error(
                    federation,
                    &authenticated,
                    AppError::internal("stored Chat-media digest is malformed"),
                );
            };
            federation.signed_stream_response(
                &authenticated,
                StatusCode::OK,
                OCTETS,
                &content_digest_sha256_from_digest(&digest),
                bytes as u64,
                Body::from_stream(ReaderStream::new(object.into_async_read())),
            )
        }
        Err(error) => signed_error(federation, &authenticated, error),
    }
}

async fn serve_object_inner(
    state: &AppState,
    authenticated: &AuthenticatedFederationRequest,
    body: &[u8],
) -> AppResult<(String, i64, String)> {
    let federation = state.federation.as_ref().expect("authenticated federation");
    let transaction: FederatedChatMediaTransactionV1 = serde_json::from_slice(body)
        .map_err(|_| AppError::bad_request("invalid Chat-media pull"))?;
    transaction
        .validate(
            authenticated.origin(),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(AppError::bad_request)?;
    if transaction.origin_domain != federation.server_name()
        || transaction.offer.destination_domain != authenticated.origin()
        || authenticated.destination() != federation.server_name()
    {
        return Err(chat_media::unavailable());
    }
    let operation_id =
        canonical_uuid(&transaction.offer.operation_id).ok_or_else(chat_media::unavailable)?;
    let attachment_id =
        canonical_uuid(&transaction.offer.attachment_id).ok_or_else(chat_media::unavailable)?;
    let token_hash = decode_token_hash(&transaction.offer.retrieval_token)
        .ok_or_else(chat_media::unavailable)?;
    type PullRow = (Vec<u8>, String, i64, String, i16);
    let row: Option<PullRow> = sqlx::query_as(
        "SELECT g.retrieval_token_hash,o.storage_path,o.ciphertext_bytes,
                o.ciphertext_sha256,o.suite
         FROM chat_media_federation_pull_grants g
         JOIN chat_media_objects o ON o.attachment_id=g.attachment_id
         WHERE g.destination=$1 AND g.recipient_account_id=$2 AND g.operation_id=$3
           AND g.attachment_id=$4 AND g.expires_at>now()
           AND o.origin_domain=$5 AND o.origin_user_id=g.origin_user_id",
    )
    .bind(authenticated.origin())
    .bind(recipient_account_id(&transaction.offer).map_err(|_| chat_media::unavailable())?)
    .bind(operation_id)
    .bind(attachment_id)
    .bind(federation.server_name())
    .fetch_optional(&state.pool)
    .await?;
    let Some((stored_token, path, bytes, digest, suite)) = row else {
        constant_time_capability_hash_eq(&token_hash, &[0; 32]);
        return Err(chat_media::unavailable());
    };
    let stored_token: [u8; 32] = stored_token
        .try_into()
        .map_err(|_| AppError::internal("stored Chat-media grant is malformed"))?;
    if !constant_time_capability_hash_eq(&stored_token, &token_hash)
        || bytes != transaction.offer.ciphertext_bytes as i64
        || digest != transaction.offer.ciphertext_sha256
        || suite != transaction.offer.suite.as_u16() as i16
    {
        return Err(chat_media::unavailable());
    }
    Ok((path, bytes, digest))
}

/// The recipient's account id in an offer (canonical: checked as it parsed).
pub(crate) fn recipient_account_id(offer: &ChatMediaDeliveryOfferV1) -> AppResult<Uuid> {
    Uuid::parse_str(&offer.recipient.account_id)
        .map_err(|_| AppError::bad_request("the recipient's account id is not a UUID"))
}
