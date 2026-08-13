//! Sender-free, restart-safe federation for immutable Chat-media objects.
//!
//! The origin may retain its authenticated sender in the outbox and pull
//! grant. The signed transaction, destination receipt, destination object,
//! quota rows, and logs never contain the sender account or device.

use std::str::FromStr as _;
use std::time::Duration;

use aws_sdk_s3::primitives::{ByteStream, Length};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, constant_time_capability_hash_eq, AccountAddress, ChatMediaDeliveryOfferV1,
    ChatMediaDeliveryStatusV1, ChatMediaOfferResponseV1, FederatedChatMediaTransactionV1,
};
use kutup_federation_proto::{content_digest_sha256_from_digest, FederationFeature};
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationRequestSpec, FederationStack};
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
    Some(Sha256::digest(decoded).into())
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::CONFLICT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::GATEWAY_TIMEOUT
        || status.is_server_error()
}

async fn finalize_outbox(
    state: &AppState,
    destination: &str,
    sequence: i64,
    terminal_state: &'static str,
    error_class: Option<&'static str>,
) -> AppResult<()> {
    debug_assert!(matches!(terminal_state, "delivered" | "rejected"));
    let mut tx = state.pool.begin().await?;
    let operation_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE chat_media_federation_outbox
         SET state=$3,attempts=attempts+1,last_error_class=$4,updated_at=now()
         WHERE destination=$1 AND sequence=$2 AND state='pending'
         RETURNING operation_id",
    )
    .bind(destination)
    .bind(sequence)
    .bind(terminal_state)
    .bind(error_class)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(operation_id) = operation_id {
        sqlx::query(
            "DELETE FROM chat_media_federation_pull_grants
             WHERE destination=$1 AND operation_id=$2",
        )
        .bind(destination)
        .bind(operation_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
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
        feature: FederationFeature::ChatV1,
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

async fn send_offer(
    state: &AppState,
    destination: &str,
    transaction: &FederatedChatMediaTransactionV1,
) -> AppResult<ChatMediaOfferResponseV1> {
    let response = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("Chat media federation unavailable"))?
        .send(destination, offer_spec(transaction)?)
        .await
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            response.status,
            format!("remote Chat-media offer returned {}", response.status),
        ));
    }
    let receipt: ChatMediaOfferResponseV1 =
        serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote Chat-media receipt is malformed",
            )
        })?;
    if receipt.operation_id != transaction.offer.operation_id
        || receipt.status == ChatMediaDeliveryStatusV1::Queued
        || matches!(
            receipt.status,
            ChatMediaDeliveryStatusV1::Stored | ChatMediaDeliveryStatusV1::AlreadyStored
        ) && receipt
            .storage_reference_id
            .as_deref()
            .and_then(canonical_uuid)
            .is_none()
        || receipt.status == ChatMediaDeliveryStatusV1::StorageFull
            && receipt.storage_reference_id.is_some()
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote Chat-media receipt does not match the offer",
        ));
    }
    Ok(receipt)
}

/// Stage an authenticated local sender's remote delivery. Network failure is
/// represented as `queued`; immutable retry state has already committed.
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
    let mut tx = state.pool.begin().await?;
    let operation_lock = format!("{origin_user_id}:{operation_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1127042))")
        .bind(operation_lock)
        .execute(&mut *tx)
        .await?;
    let existing: Option<(i64, Value)> = sqlx::query_as(
        "SELECT sequence,transaction FROM chat_media_federation_outbox
         WHERE origin_user_id=$1 AND operation_id=$2",
    )
    .bind(origin_user_id)
    .bind(operation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let existing = if let Some((sequence, stored)) = existing {
        let transaction: FederatedChatMediaTransactionV1 = serde_json::from_value(stored)
            .map_err(|_| AppError::internal("stored Chat-media transaction is malformed"))?;
        if transaction.offer != offer || transaction.origin_sequence != sequence as u64 {
            return Err(AppError::conflict("Chat media operation replay changed"));
        }
        Some((sequence, transaction))
    } else {
        None
    };
    let (sequence, transaction) = if let Some(existing) = existing {
        existing
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
        sqlx::query(
            "INSERT INTO chat_media_federation_sequences(destination,next_sequence)
             VALUES ($1,1) ON CONFLICT DO NOTHING",
        )
        .bind(&destination)
        .execute(&mut *tx)
        .await?;
        let sequence: i64 = sqlx::query_scalar(
            "SELECT next_sequence FROM chat_media_federation_sequences
             WHERE destination=$1 FOR UPDATE",
        )
        .bind(&destination)
        .fetch_one(&mut *tx)
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
                 (origin_user_id,destination,recipient,operation_id,attachment_id,
                  retrieval_token_hash,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7))",
        )
        .bind(origin_user_id)
        .bind(&destination)
        .bind(&offer.recipient)
        .bind(operation_id)
        .bind(attachment_id)
        .bind(token_hash.as_slice())
        .bind(offer.expires_at as f64)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO chat_media_federation_outbox
                 (destination,sequence,origin_user_id,operation_id,transaction)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&destination)
        .bind(sequence)
        .bind(origin_user_id)
        .bind(operation_id)
        .bind(value)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE chat_media_federation_sequences SET next_sequence=next_sequence+1
             WHERE destination=$1",
        )
        .bind(&destination)
        .execute(&mut *tx)
        .await?;
        (sequence, transaction)
    };
    tx.commit().await?;

    match send_offer(state, &destination, &transaction).await {
        Ok(receipt) => {
            let (terminal, error_class) =
                if receipt.status == ChatMediaDeliveryStatusV1::StorageFull {
                    ("rejected", Some("storage_full"))
                } else {
                    ("delivered", None)
                };
            finalize_outbox(state, &destination, sequence, terminal, error_class).await?;
            crate::telemetry::chat_media_event(
                "federation_origin",
                if receipt.status == ChatMediaDeliveryStatusV1::StorageFull {
                    "storage_full"
                } else {
                    "delivered"
                },
            );
            Ok(receipt)
        }
        Err(error) if retryable_status(error.status) => {
            sqlx::query(
                "UPDATE chat_media_federation_outbox
                 SET attempts=attempts+1,next_attempt_at=now()+interval '5 seconds',
                     last_error_class=$3,updated_at=now()
                 WHERE destination=$1 AND sequence=$2 AND state='pending'",
            )
            .bind(&destination)
            .bind(sequence)
            .bind(if error.status == StatusCode::CONFLICT {
                "sequence_conflict"
            } else {
                "transport_or_remote"
            })
            .execute(&state.pool)
            .await?;
            crate::telemetry::chat_media_event("federation_origin", "queued");
            Ok(ChatMediaOfferResponseV1 {
                operation_id: offer.operation_id,
                status: ChatMediaDeliveryStatusV1::Queued,
                storage_reference_id: None,
            })
        }
        Err(error) => {
            finalize_outbox(
                state,
                &destination,
                sequence,
                "rejected",
                Some("remote_rejection"),
            )
            .await?;
            if error.status == StatusCode::NOT_FOUND {
                crate::telemetry::chat_media_event("federation_origin", "unavailable");
                Err(chat_media::unavailable())
            } else {
                crate::telemetry::chat_media_event("federation_origin", "rejected");
                Err(error)
            }
        }
    }
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
            FederationFeature::ChatV1,
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
    if authenticated.origin() != transaction.origin_domain
        || authenticated.destination() != federation.server_name()
    {
        return Err(AppError::unauthorized(
            "Chat-media federation routing mismatch",
        ));
    }
    let sequence = i64::try_from(transaction.origin_sequence)
        .map_err(|_| AppError::bad_request("Chat-media sequence is too large"))?;
    let operation_id = canonical_uuid(&transaction.offer.operation_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat-media operation"))?;
    let attachment_id = canonical_uuid(&transaction.offer.attachment_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat-media attachment"))?;
    let transaction_digest = hex::encode(Sha256::digest(body));
    let address = AccountAddress::from_str(&transaction.offer.recipient)
        .map_err(|_| chat_media::unavailable())?;
    let reservation = reserve_inbound_offer(
        state,
        &transaction,
        &transaction_digest,
        &address,
        sequence,
        operation_id,
        attachment_id,
    )
    .await?;
    match reservation {
        InboundReservation::Final(status, response) => Ok((status, response)),
        InboundReservation::Reserved {
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
        recipient_user_id: Uuid,
        lease_id: Uuid,
    },
}

#[allow(clippy::too_many_arguments)]
async fn reserve_inbound_offer(
    state: &AppState,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    address: &AccountAddress,
    sequence: i64,
    operation_id: Uuid,
    attachment_id: Uuid,
) -> AppResult<InboundReservation> {
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1127041))")
        .bind(&transaction.origin_domain)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO chat_media_federation_inbound_state(origin,last_sequence)
         VALUES ($1,0) ON CONFLICT DO NOTHING",
    )
    .bind(&transaction.origin_domain)
    .execute(&mut *tx)
    .await?;
    if let Some((status, response, digest)) = sqlx::query_as::<_, (i16, Value, String)>(
        "SELECT response_status,response,transaction_digest
         FROM chat_media_federation_inbound_transactions
         WHERE origin=$1 AND sequence=$2",
    )
    .bind(&transaction.origin_domain)
    .bind(sequence)
    .fetch_optional(&mut *tx)
    .await?
    {
        if digest != transaction_digest {
            return Err(AppError::conflict("Chat-media sequence replay changed"));
        }
        return Ok(InboundReservation::Final(
            StatusCode::from_u16(status as u16)
                .map_err(|_| AppError::internal("stored Chat-media status is malformed"))?,
            response,
        ));
    }
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
           SELECT 1 FROM chat_media_federation_inbound_transactions
           WHERE origin=$1 AND operation_id=$2 AND sequence<>$3
           UNION ALL
           SELECT 1 FROM chat_media_federation_inbound_pending
           WHERE origin=$1 AND operation_id=$2 AND sequence<>$3)",
    )
    .bind(&transaction.origin_domain)
    .bind(operation_id)
    .bind(sequence)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(AppError::conflict(
            "Chat-media operation id was reused at another sequence",
        ));
    }
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM chat_media_federation_inbound_state
         WHERE origin=$1 FOR UPDATE",
    )
    .bind(&transaction.origin_domain)
    .fetch_one(&mut *tx)
    .await?;
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
    .bind(&transaction.origin_domain)
    .bind(sequence)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((digest, recipient_user_id, stored_attachment, stored_bytes)) = pending {
        if digest != transaction_digest
            || stored_attachment != attachment_id
            || stored_bytes != transaction.offer.ciphertext_bytes as i64
        {
            return Err(AppError::conflict("Chat-media pending replay changed"));
        }
        let claimed = sqlx::query(
            "UPDATE chat_media_federation_inbound_pending
             SET lease_id=$3,lease_until=now()+interval '2 minutes',updated_at=now()
             WHERE origin=$1 AND sequence=$2 AND lease_until<=now()",
        )
        .bind(&transaction.origin_domain)
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
            recipient_user_id,
            lease_id,
        });
    }
    let capability: Option<[u8; 16]> = STANDARD
        .decode(&transaction.offer.delivery_capability)
        .ok()
        .and_then(|bytes| bytes.try_into().ok());
    let capability_digest = capability.as_ref().map(capability_hash).unwrap_or([0; 32]);
    let recipient_user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username=$1 AND is_active=true")
            .bind(&address.username)
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
            transaction_digest,
            StatusCode::NOT_FOUND,
            &response,
        )
        .await?;
        tx.commit().await?;
        return Ok(InboundReservation::Final(StatusCode::NOT_FOUND, response));
    };
    chat_media::consume_media_rate(&mut tx, "capability_minute", &capability_digest, 120, 60)
        .await?;
    chat_media::consume_media_rate(
        &mut tx,
        "federation_origin",
        &Sha256::digest(
            [
                b"kutup/chat-media/federation-origin-rate/v1\0".as_slice(),
                transaction.origin_domain.as_bytes(),
            ]
            .concat(),
        )
        .into(),
        600,
        60,
    )
    .await?;

    type ExistingObject = (String, i16, i64, String, Vec<u8>, String);
    let existing_object: Option<ExistingObject> = sqlx::query_as(
        "SELECT origin_domain,suite,ciphertext_bytes,ciphertext_sha256,
                retrieval_token_hash,storage_path
         FROM chat_media_objects WHERE attachment_id=$1",
    )
    .bind(attachment_id)
    .fetch_optional(&mut *tx)
    .await?;
    let token_hash = decode_token_hash(&transaction.offer.retrieval_token)
        .ok_or_else(chat_media::unavailable)?;
    if let Some((origin, suite, bytes, digest, token, _)) = &existing_object {
        let token: [u8; 32] = token
            .clone()
            .try_into()
            .map_err(|_| AppError::internal("stored Chat-media token is malformed"))?;
        if origin != &transaction.origin_domain
            || *suite != transaction.offer.suite.as_u16() as i16
            || *bytes != transaction.offer.ciphertext_bytes as i64
            || digest != &transaction.offer.ciphertext_sha256
            || !constant_time_capability_hash_eq(&token, &token_hash)
        {
            return Err(AppError::conflict("Chat-media object identity collision"));
        }
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
            transaction_digest,
            StatusCode::OK,
            &value,
        )
        .await?;
        tx.commit().await?;
        return Ok(InboundReservation::Final(StatusCode::OK, value));
    }
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT chat_storage_quota_bytes,chat_storage_used_bytes FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(recipient_user_id)
    .fetch_one(&mut *tx)
    .await?;
    let reserved: i64 = sqlx::query_scalar(
        "SELECT
           (SELECT COALESCE(SUM(total_bytes-received_bytes),0)::bigint FROM chat_media_uploads WHERE user_id=$1) +
           (SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint
              FROM chat_media_federation_inbound_pending WHERE recipient_user_id=$1)",
    )
    .bind(recipient_user_id)
    .fetch_one(&mut *tx)
    .await?;
    if used
        .checked_add(reserved)
        .and_then(|value| value.checked_add(transaction.offer.ciphertext_bytes as i64))
        .is_none_or(|value| value > quota)
    {
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
    .bind(&transaction.origin_domain)
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
        recipient_user_id,
        lease_id,
    })
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
    type ExistingObject = (String, i16, i64, String, Vec<u8>, String);
    let existing_object: Option<ExistingObject> = sqlx::query_as(
        "SELECT origin_domain,suite,ciphertext_bytes,ciphertext_sha256,
                retrieval_token_hash,storage_path
         FROM chat_media_objects WHERE attachment_id=$1",
    )
    .bind(attachment_id)
    .fetch_optional(&state.pool)
    .await?;
    let object_exists = if let Some((origin, suite, bytes, digest, token, _)) = &existing_object {
        let token: [u8; 32] = token
            .clone()
            .try_into()
            .map_err(|_| AppError::internal("stored Chat-media token is malformed"))?;
        if origin != &transaction.origin_domain
            || *suite != transaction.offer.suite.as_u16() as i16
            || *bytes != transaction.offer.ciphertext_bytes as i64
            || digest != &transaction.offer.ciphertext_sha256
            || !constant_time_capability_hash_eq(&token, &token_hash)
        {
            return Err(AppError::conflict("Chat-media object identity collision"));
        }
        true
    } else {
        false
    };
    let mut uploaded_path = None;
    if !object_exists {
        let pull_body = serde_json::to_vec(transaction)
            .map_err(|_| AppError::internal("serialize Chat-media pull"))?;
        let streamed = federation
            .send_streamed(
                &transaction.origin_domain,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
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
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1127041))")
            .bind(&transaction.origin_domain)
            .execute(&mut *tx)
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
        let last_sequence: i64 = sqlx::query_scalar(
            "SELECT last_sequence FROM chat_media_federation_inbound_state
             WHERE origin=$1 FOR UPDATE",
        )
        .bind(&transaction.origin_domain)
        .fetch_one(&mut *tx)
        .await?;
        if sequence != last_sequence + 1 {
            return Err(AppError::conflict("Chat-media reservation sequence changed"));
        }
        let stored_object: Option<ExistingObject> = sqlx::query_as(
            "SELECT origin_domain,suite,ciphertext_bytes,ciphertext_sha256,
                    retrieval_token_hash,storage_path
             FROM chat_media_objects WHERE attachment_id=$1 FOR UPDATE",
        )
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((origin, suite, bytes, digest, token, _)) = stored_object {
            let token: [u8; 32] = token
                .try_into()
                .map_err(|_| AppError::internal("stored Chat-media token is malformed"))?;
            if origin != transaction.origin_domain
                || suite != transaction.offer.suite.as_u16() as i16
                || bytes != transaction.offer.ciphertext_bytes as i64
                || digest != transaction.offer.ciphertext_sha256
                || !constant_time_capability_hash_eq(&token, &token_hash)
            {
                return Err(AppError::conflict("Chat-media object identity collision"));
            }
        } else {
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
        let (quota, used): (i64, i64) = sqlx::query_as(
            "SELECT chat_storage_quota_bytes,chat_storage_used_bytes FROM users WHERE id=$1 FOR UPDATE",
        )
            .bind(recipient_user_id)
            .fetch_one(&mut *tx)
            .await?;
        let other_reserved: i64 = sqlx::query_scalar(
            "SELECT
               (SELECT COALESCE(SUM(total_bytes-received_bytes),0)::bigint FROM chat_media_uploads WHERE user_id=$1) +
               (SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint
                  FROM chat_media_federation_inbound_pending
                  WHERE recipient_user_id=$1 AND NOT (origin=$2 AND sequence=$3))",
        )
        .bind(recipient_user_id)
        .bind(&transaction.origin_domain)
        .bind(sequence)
        .fetch_one(&mut *tx)
        .await?;
        if used
            .checked_add(other_reserved)
            .and_then(|value| value.checked_add(transaction.offer.ciphertext_bytes as i64))
            .is_none_or(|value| value > quota)
        {
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
            return AppResult::Ok((value, false));
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
            sqlx::query("UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+$1 WHERE id=$2")
                .bind(transaction.offer.ciphertext_bytes as i64)
                .bind(recipient_user_id)
                .execute(&mut *tx)
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
        AppResult::Ok((value, true))
    }
    .await;
    match result {
        Ok((response, keep_uploaded_object)) => {
            if !keep_uploaded_object {
                if let Some(path) = uploaded_path {
                    let _ = state.storage.delete(&path).await;
                }
            }
            Ok((StatusCode::OK, response))
        }
        Err(error) => {
            if let Some(path) = uploaded_path {
                let _ = state.storage.delete(&path).await;
            }
            Err(error)
        }
    }
}

async fn persist_inbound_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatMediaTransactionV1,
    transaction_digest: &str,
    status: StatusCode,
    response: &Value,
) -> AppResult<()> {
    let operation_id = canonical_uuid(&transaction.offer.operation_id)
        .ok_or_else(|| AppError::internal("Chat-media operation id changed"))?;
    sqlx::query(
        "INSERT INTO chat_media_federation_inbound_transactions
             (origin,sequence,operation_id,transaction_digest,response_status,response)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&transaction.origin_domain)
    .bind(transaction.origin_sequence as i64)
    .bind(operation_id)
    .bind(transaction_digest)
    .bind(status.as_u16() as i16)
    .bind(response)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE chat_media_federation_inbound_state
         SET last_sequence=$2,updated_at=now() WHERE origin=$1",
    )
    .bind(&transaction.origin_domain)
    .bind(transaction.origin_sequence as i64)
    .execute(&mut **tx)
    .await?;
    Ok(())
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
            FederationFeature::ChatV1,
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
         WHERE g.destination=$1 AND g.recipient=$2 AND g.operation_id=$3
           AND g.attachment_id=$4 AND g.expires_at>now()
           AND o.origin_domain=$5 AND o.origin_user_id=g.origin_user_id",
    )
    .bind(authenticated.origin())
    .bind(&transaction.offer.recipient)
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

pub(crate) fn spawn_retry_worker(state: AppState) {
    if state.federation.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) = retry_once(&state).await {
                tracing::warn!(error = %error, "Chat-media federation retry failed");
            }
        }
    });
}

#[tracing::instrument(name = "chat_media.federation.retry", skip_all)]
async fn retry_once(state: &AppState) -> AppResult<()> {
    let row: Option<(Uuid, String, Value, i32)> = sqlx::query_as(
        "SELECT o.id,o.destination,o.transaction,o.attempts
         FROM chat_media_federation_outbox o
         WHERE o.state='pending' AND o.next_attempt_at<=now()
           AND NOT EXISTS (
             SELECT 1 FROM chat_media_federation_outbox prior
             WHERE prior.destination=o.destination AND prior.state='pending'
               AND prior.sequence<o.sequence)
         ORDER BY o.next_attempt_at,o.destination,o.sequence LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some((id, destination, value, attempts)) = row else {
        return Ok(());
    };
    let transaction: FederatedChatMediaTransactionV1 = serde_json::from_value(value)
        .map_err(|_| AppError::internal("stored Chat-media retry is malformed"))?;
    let outcome = send_offer(state, &destination, &transaction).await;
    match outcome {
        Ok(receipt) => {
            let (terminal, error_class) =
                if receipt.status == ChatMediaDeliveryStatusV1::StorageFull {
                    ("rejected", Some("storage_full"))
                } else {
                    ("delivered", None)
                };
            finalize_outbox(
                state,
                &destination,
                transaction.origin_sequence as i64,
                terminal,
                error_class,
            )
            .await?;
            crate::telemetry::chat_media_event(
                "federation_retry",
                if receipt.status == ChatMediaDeliveryStatusV1::StorageFull {
                    "storage_full"
                } else {
                    "delivered"
                },
            );
        }
        Err(error) if retryable_status(error.status) => {
            let exponent = u32::try_from(attempts).unwrap_or(u32::MAX).min(8);
            let delay = 5_i64.saturating_mul(1_i64 << exponent).min(900);
            sqlx::query(
                "UPDATE chat_media_federation_outbox
                 SET attempts=attempts+1,next_attempt_at=now()+make_interval(secs=>$2),
                     last_error_class=$3,updated_at=now()
                 WHERE id=$1 AND state='pending'",
            )
            .bind(id)
            .bind(delay as f64)
            .bind(if error.status == StatusCode::CONFLICT {
                "sequence_conflict"
            } else {
                "transport_or_remote"
            })
            .execute(&state.pool)
            .await?;
            crate::telemetry::chat_media_event("federation_retry", "rescheduled");
        }
        Err(_) => {
            finalize_outbox(
                state,
                &destination,
                transaction.origin_sequence as i64,
                "rejected",
                Some("remote_rejection"),
            )
            .await?;
            crate::telemetry::chat_media_event("federation_retry", "rejected");
        }
    }
    Ok(())
}
