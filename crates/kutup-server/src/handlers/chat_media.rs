//! Durable opaque Chat-media storage and account-private attachment ledger.
//!
//! The server validates only public suite framing, lengths, digests, quota and
//! compare-and-swap metadata. Filenames, MIME types, conversations, messages
//! and attachment keys remain inside Direct/MLS ciphertext and ledger AEAD.

use std::io::ErrorKind;
use std::str::FromStr as _;

use aws_sdk_s3::primitives::ByteStream;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, constant_time_capability_hash_eq, AccountAddress,
    ChatAttachmentLedgerDiffPageV1, ChatAttachmentLedgerPutReceiptV1,
    ChatAttachmentLedgerPutRequestV1, ChatAttachmentLedgerWireEntityV1, ChatMediaDeliveryOfferV1,
    ChatMediaDeliveryStatusV1, ChatMediaOfferResponseV1,
};
use kutup_crypto::chat_attachment_ledger;
use kutup_crypto::chat_media::{
    self, ChatMediaObjectContextV1, ChatMediaSuiteId, CHAT_MEDIA_OBJECT_HEADER_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;
use utoipa::ToSchema;
use uuid::Uuid;

use super::tus::{
    header_str, parse_upload_metadata, require_tus_resumable, tus_text, MIN_PART_SIZE, TUS_VERSION,
};
use super::{octet_stream_response, trusted_uuid};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::storage::CompletedPart;
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ChatMediaUploadCreated {
    upload_id: String,
    attachment_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatMediaStorageSummary {
    total_quota_bytes: i64,
    total_used_bytes: i64,
    drive_bytes: i64,
    chat_media_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatMediaReferenceInfo {
    attachment_id: String,
    storage_reference_id: String,
    ciphertext_bytes: i64,
    ciphertext_sha256: String,
}

pub(crate) fn unavailable() -> AppError {
    AppError::not_found("Chat media unavailable")
}

pub(crate) fn delivery_offer_digest(offer: &ChatMediaDeliveryOfferV1) -> AppResult<String> {
    let encoded = serde_json::to_vec(offer)
        .map_err(|error| AppError::internal(format!("encode Chat-media offer: {error}")))?;
    let mut digest = Sha256::new();
    digest.update(b"kutup/chat-media/delivery-offer-digest/v1\0");
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

pub(crate) async fn consume_media_rate(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope_type: &'static str,
    scope_digest: &[u8; 32],
    limit: i64,
    window_seconds: i64,
) -> AppResult<()> {
    debug_assert!(matches!(
        scope_type,
        "capability_minute" | "capability_day" | "recipient" | "federation_origin"
    ));
    let count: i64 = sqlx::query_scalar(
        "INSERT INTO chat_media_rate_counters
             (scope_type, scope_digest, window_start, count, expires_at)
         VALUES (
             $1, $2,
             to_timestamp(floor(extract(epoch FROM now()) / $3) * $3),
             1,
             to_timestamp(floor(extract(epoch FROM now()) / $3) * $3)
               + make_interval(secs => $3 * 2)
         )
         ON CONFLICT (scope_type, scope_digest, window_start)
         DO UPDATE SET count = chat_media_rate_counters.count + 1
         RETURNING count",
    )
    .bind(scope_type)
    .bind(scope_digest.as_slice())
    .bind(window_seconds)
    .fetch_one(&mut **transaction)
    .await?;
    if count > limit {
        crate::telemetry::rate_limit_rejection(match scope_type {
            "capability_minute" => "chat_media_capability_minute",
            "capability_day" => "chat_media_capability_day",
            "recipient" => "chat_media_recipient",
            "federation_origin" => "chat_media_federation_origin",
            _ => "chat_media_unknown",
        });
        return Err(AppError::too_many_requests(
            "Chat-media delivery rate limit exceeded",
        ));
    }
    Ok(())
}

pub(crate) async fn match_delivery_capability(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    recipient_user_id: Uuid,
    presented: &[u8; 32],
) -> AppResult<bool> {
    let direct: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT capability_hash FROM chat_delivery_capabilities WHERE user_id=$1",
    )
    .bind(recipient_user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let mut matched = direct
        .and_then(|value| <[u8; 32]>::try_from(value).ok())
        .is_some_and(|candidate| constant_time_capability_hash_eq(&candidate, presented));

    // Scan every current active MLS capability for the recipient so matching
    // time does not reveal which private conversation authorized delivery.
    let group_candidates: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT d.capability_hash
         FROM chat_mls_delivery_capabilities d
         JOIN chat_mls_conversations c
           ON c.conversation_id=d.conversation_id AND c.current_incarnation=d.incarnation
         JOIN chat_mls_incarnations i
           ON i.conversation_id=d.conversation_id AND i.incarnation=d.incarnation
          AND i.last_finalized_epoch=d.epoch AND i.status='active'
         JOIN chat_mls_local_members m
           ON m.conversation_id=d.conversation_id AND m.incarnation=d.incarnation
          AND m.user_id=d.recipient_user_id AND m.removed_epoch IS NULL
          AND m.membership_status='active'
         WHERE d.recipient_user_id=$1 AND c.status='active'
         ORDER BY d.conversation_id",
    )
    .bind(recipient_user_id)
    .fetch_all(&mut **transaction)
    .await?;
    for candidate in group_candidates {
        let candidate: [u8; 32] = candidate
            .try_into()
            .map_err(|_| AppError::internal("stored media capability is malformed"))?;
        matched |= constant_time_capability_hash_eq(&candidate, presented);
    }
    Ok(matched)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LedgerDiffQuery {
    after: Option<String>,
    limit: Option<i64>,
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.hyphenated().to_string() == value)
}

fn canonical_token_hash(value: &str) -> Option<[u8; 32]> {
    let decoded = STANDARD.decode(value).ok()?;
    if decoded.len() != 32 || STANDARD.encode(&decoded) != value {
        return None;
    }
    Some(Sha256::digest(decoded).into())
}

fn media_context(attachment_id: Uuid) -> Option<ChatMediaObjectContextV1> {
    ChatMediaObjectContextV1::new(&attachment_id.hyphenated().to_string()).ok()
}

async fn hash_stored_object(
    state: &AppState,
    storage_path: &str,
    expected_bytes: i64,
) -> Result<String, std::io::Error> {
    let (body, declared_bytes) = state
        .storage
        .get_object(storage_path)
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if declared_bytes != expected_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "stored Chat-media length mismatch",
        ));
    }
    let mut reader = body.into_async_read();
    let mut hasher = Sha256::new();
    let mut read_bytes = 0_i64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(count as i64)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "length overflow"))?;
        if read_bytes > expected_bytes {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "stored Chat-media exceeds declared length",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if read_bytes != expected_bytes {
        return Err(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "stored Chat-media is truncated",
        ));
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Create a resumable immutable Chat-media upload. Metadata contains only
/// public object identifiers. Integrity is independently computed while the
/// client uploads and by the server after multipart completion.
#[tracing::instrument(name = "chat_media.create_upload", skip_all)]
pub async fn create_upload(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_tus_resumable(&headers) {
        return response;
    }
    let user_id = match trusted_uuid(&user.user_id) {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };
    let total_bytes = match header_str(&headers, "Upload-Length").parse::<i64>() {
        Ok(value)
            if value >= chat_media::object_ciphertext_size(0).unwrap_or(u64::MAX) as i64
                && value
                    <= chat_media::object_ciphertext_size(
                        state.config.chat_media_max_plaintext_bytes,
                    )
                    .unwrap_or(0) as i64 =>
        {
            value
        }
        _ => return tus_text(StatusCode::BAD_REQUEST, "invalid Chat-media Upload-Length"),
    };
    let metadata = match parse_upload_metadata(header_str(&headers, "Upload-Metadata")) {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::BAD_REQUEST, "invalid Upload-Metadata"),
    };
    if metadata.len() != 3 {
        return tus_text(
            StatusCode::BAD_REQUEST,
            "Upload-Metadata must contain exactly attachmentId, suite, retrievalToken",
        );
    }
    let attachment_id = match metadata
        .get("attachmentId")
        .and_then(|value| canonical_uuid(value))
    {
        Some(value) => value,
        None => return tus_text(StatusCode::BAD_REQUEST, "invalid attachment id"),
    };
    let suite = match metadata
        .get("suite")
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| ChatMediaSuiteId::try_from(value).ok())
    {
        Some(value) => value,
        None => return tus_text(StatusCode::BAD_REQUEST, "invalid Chat-media suite"),
    };
    let token_hash = match metadata
        .get("retrievalToken")
        .and_then(|value| canonical_token_hash(value))
    {
        Some(value) => value,
        None => return tus_text(StatusCode::BAD_REQUEST, "invalid retrieval token"),
    };

    let mut transaction = match state.pool.begin().await {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db begin"),
    };
    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat_media_objects WHERE attachment_id=$1 UNION ALL SELECT 1 FROM chat_media_uploads WHERE attachment_id=$1)",
    )
    .bind(attachment_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap_or(true);
    if existing {
        return tus_text(StatusCode::CONFLICT, "attachment id already exists");
    }
    let user_row: Result<(i64, i64), _> = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await;
    let (quota, used) = match user_row {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read user"),
    };
    let reserved: i64 = sqlx::query_scalar(
        "SELECT (SELECT COALESCE(SUM(total_bytes - received_bytes),0)::bigint FROM uploads WHERE user_id=$1) +
                (SELECT COALESCE(SUM(total_bytes - received_bytes),0)::bigint FROM chat_media_uploads WHERE user_id=$1) +
                (SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint
                   FROM chat_media_federation_inbound_pending WHERE recipient_user_id=$1)",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap_or(i64::MAX);
    if used
        .checked_add(reserved)
        .and_then(|value| value.checked_add(total_bytes))
        .is_none_or(|value| value > quota)
    {
        return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "storage quota exceeded");
    }

    let upload_id = Uuid::new_v4();
    let storage_path = format!("chat-media/{user_id}/{attachment_id}");
    let s3_upload_id = match state.storage.create_multipart(&storage_path).await {
        Ok(value) => value,
        Err(_) => {
            return tus_text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage create multipart",
            )
        }
    };
    let inserted = sqlx::query(
        "INSERT INTO chat_media_uploads
         (id,user_id,attachment_id,suite,total_bytes,retrieval_token_hash,storage_path,s3_upload_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(upload_id)
    .bind(user_id)
    .bind(attachment_id)
    .bind(i16::try_from(suite.as_u16()).unwrap_or_default())
    .bind(total_bytes)
    .bind(token_hash.as_slice())
    .bind(&storage_path)
    .bind(&s3_upload_id)
    .execute(&mut *transaction)
    .await;
    if inserted.is_err() || transaction.commit().await.is_err() {
        let _ = state
            .storage
            .abort_multipart(&storage_path, &s3_upload_id)
            .await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db create upload");
    }
    let body = serde_json::to_string(&ChatMediaUploadCreated {
        upload_id: upload_id.to_string(),
        attachment_id: attachment_id.to_string(),
    })
    .unwrap_or_else(|_| "{}".into());
    (
        StatusCode::CREATED,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Location", format!("/api/chat/media/uploads/{upload_id}")),
            ("Upload-Offset", "0".into()),
            ("Content-Type", "application/json".into()),
        ],
        body,
    )
        .into_response()
}

pub async fn head_upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_tus_resumable(&headers) {
        return response;
    }
    let (Some(upload_id), Ok(user_id)) = (canonical_uuid(&id), trusted_uuid(&user.user_id)) else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT total_bytes,received_bytes FROM chat_media_uploads WHERE id=$1 AND user_id=$2",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((total, received)) = row else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    (
        StatusCode::OK,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Upload-Offset", received.to_string()),
            ("Upload-Length", total.to_string()),
            ("Cache-Control", "no-store".into()),
        ],
    )
        .into_response()
}

#[tracing::instrument(name = "chat_media.patch_upload", skip_all)]
pub async fn patch_upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = require_tus_resumable(&headers) {
        return response;
    }
    if header_str(&headers, "Content-Type") != "application/offset+octet-stream" {
        return tus_text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid Content-Type");
    }
    let (Some(upload_id), Ok(user_id)) = (canonical_uuid(&id), trusted_uuid(&user.user_id)) else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    let client_offset = match header_str(&headers, "Upload-Offset").parse::<i64>() {
        Ok(value) if value >= 0 => value,
        _ => return tus_text(StatusCode::BAD_REQUEST, "invalid Upload-Offset"),
    };
    let chunk_len = body.len() as i64;
    if chunk_len == 0 {
        return tus_text(StatusCode::BAD_REQUEST, "empty body");
    }

    type UploadRow = (
        Uuid,
        i16,
        i64,
        i64,
        Vec<u8>,
        String,
        String,
        serde_json::Value,
    );
    let mut transaction = match state.pool.begin().await {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db begin"),
    };
    let row: Option<UploadRow> = sqlx::query_as(
        "SELECT attachment_id,suite,total_bytes,received_bytes,retrieval_token_hash,storage_path,s3_upload_id,s3_part_etags
         FROM chat_media_uploads WHERE id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await
    .ok()
    .flatten();
    let Some((
        attachment_id,
        suite,
        total,
        received,
        token_hash,
        storage_path,
        s3_upload_id,
        parts_json,
    )) = row
    else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    if received != client_offset {
        return (
            StatusCode::CONFLICT,
            [
                ("Tus-Resumable", TUS_VERSION.to_string()),
                ("Upload-Offset", received.to_string()),
            ],
            "Upload-Offset mismatch",
        )
            .into_response();
    }
    if received
        .checked_add(chunk_len)
        .is_none_or(|value| value > total)
    {
        return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "chunk exceeds Upload-Length");
    }
    if received == 0 {
        let Some(context) = media_context(attachment_id) else {
            return tus_text(StatusCode::BAD_REQUEST, "invalid attachment context");
        };
        if body.len() < CHAT_MEDIA_OBJECT_HEADER_BYTES
            || chat_media::validate_object_header(&body[..CHAT_MEDIA_OBJECT_HEADER_BYTES], context)
                .is_err()
        {
            return tus_text(StatusCode::BAD_REQUEST, "invalid Chat-media object header");
        }
    }
    let mut parts: Vec<CompletedPart> = match serde_json::from_value(parts_json) {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "corrupt part list"),
    };
    let new_received = received + chunk_len;
    let is_final = new_received == total;
    if !is_final && chunk_len < MIN_PART_SIZE {
        return tus_text(StatusCode::BAD_REQUEST, "non-final part is below 5 MiB");
    }
    let part_number = parts.len() as i32 + 1;
    let etag = match state
        .storage
        .upload_part(
            &storage_path,
            &s3_upload_id,
            part_number,
            ByteStream::from(body.to_vec()),
            chunk_len,
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "storage upload part"),
    };
    parts.push(CompletedPart { part_number, etag });
    let parts_json = serde_json::to_value(&parts).unwrap_or_default();
    if sqlx::query(
        "UPDATE chat_media_uploads SET received_bytes=$1,s3_part_etags=$2,updated_at=NOW() WHERE id=$3",
    )
    .bind(new_received)
    .bind(parts_json)
    .bind(upload_id)
    .execute(&mut *transaction)
    .await
    .is_err()
    {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db update upload");
    }
    if !is_final {
        if transaction.commit().await.is_err() {
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db commit");
        }
        return (
            StatusCode::NO_CONTENT,
            [
                ("Tus-Resumable", TUS_VERSION.to_string()),
                ("Upload-Offset", new_received.to_string()),
            ],
        )
            .into_response();
    }

    if state
        .storage
        .complete_multipart(&storage_path, &s3_upload_id, &parts)
        .await
        .is_err()
    {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "storage finalize");
    }
    let actual_digest = hash_stored_object(&state, &storage_path, total).await;
    let actual_digest = match actual_digest {
        Ok(value) => value,
        Err(_) => {
            let _ = state.storage.delete(&storage_path).await;
            let _ = sqlx::query("DELETE FROM chat_media_uploads WHERE id=$1")
                .bind(upload_id)
                .execute(&mut *transaction)
                .await;
            let _ = transaction.commit().await;
            return tus_text(StatusCode::BAD_REQUEST, "Chat-media length mismatch");
        }
    };
    let inserted = sqlx::query(
        "INSERT INTO chat_media_objects
         (attachment_id,origin_user_id,origin_domain,suite,ciphertext_bytes,ciphertext_sha256,retrieval_token_hash,storage_path)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(attachment_id)
    .bind(user_id)
    .bind(
        state
            .federation
            .as_ref()
            .map(|value| value.server_name())
            .unwrap_or(""),
    )
    .bind(suite)
    .bind(total)
    .bind(&actual_digest)
    .bind(&token_hash)
    .bind(&storage_path)
    .execute(&mut *transaction)
    .await;
    if inserted.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return tus_text(StatusCode::CONFLICT, "attachment finalization conflict");
    }
    let storage_reference_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO chat_media_references(user_id,attachment_id,logical_bytes)
         VALUES ($1,$2,$3) RETURNING id",
    )
    .bind(user_id)
    .bind(attachment_id)
    .bind(total)
    .fetch_optional(&mut *transaction)
    .await
    .ok()
    .flatten();
    if storage_reference_id.is_none()
        || sqlx::query("UPDATE users SET storage_used_bytes=storage_used_bytes+$1 WHERE id=$2")
            .bind(total)
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .is_err()
        || sqlx::query("DELETE FROM chat_media_uploads WHERE id=$1")
            .bind(upload_id)
            .execute(&mut *transaction)
            .await
            .is_err()
        || transaction.commit().await.is_err()
    {
        let _ = state.storage.delete(&storage_path).await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db finalize upload");
    }
    crate::telemetry::chat_media_event("upload", "stored");
    (
        StatusCode::NO_CONTENT,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Upload-Offset", new_received.to_string()),
            ("X-Kutup-Attachment-Id", attachment_id.to_string()),
            ("X-Kutup-Ciphertext-Sha256", actual_digest),
            (
                "X-Kutup-Storage-Reference-Id",
                storage_reference_id.expect("checked").to_string(),
            ),
        ],
    )
        .into_response()
}

pub async fn delete_upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_tus_resumable(&headers) {
        return response;
    }
    let (Some(upload_id), Ok(user_id)) = (canonical_uuid(&id), trusted_uuid(&user.user_id)) else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT storage_path,s3_upload_id FROM chat_media_uploads WHERE id=$1 AND user_id=$2",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((storage_path, s3_upload_id)) = row else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    if state
        .storage
        .abort_multipart(&storage_path, &s3_upload_id)
        .await
        .is_err()
    {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "storage abort");
    }
    if sqlx::query("DELETE FROM chat_media_uploads WHERE id=$1 AND user_id=$2")
        .bind(upload_id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .is_err()
    {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db delete upload");
    }
    tus_text(StatusCode::NO_CONTENT, "")
}

/// Capability-authenticated same-homeserver delivery. The authenticated
/// sender is retained only in the origin retry receipt. Recipient quota and
/// the durable reference commit atomically, while message requests simply do
/// not call this route until the recipient accepts.
#[tracing::instrument(name = "chat_media.deliver_local", skip_all)]
pub async fn deliver_local(
    State(state): State<AppState>,
    user: AuthUser,
    Json(offer): Json<ChatMediaDeliveryOfferV1>,
) -> AppResult<Json<ChatMediaOfferResponseV1>> {
    let origin_user_id = trusted_uuid(&user.user_id)?;
    let local_domain = state
        .federation
        .as_ref()
        .map(|federation| federation.server_name())
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| AppError::conflict("Chat media requires a canonical server name"))?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    offer
        .validate(&offer.destination_domain, now)
        .map_err(|_| AppError::bad_request("invalid Chat media delivery"))?;
    let configured_ciphertext_limit =
        chat_media::object_ciphertext_size(state.config.chat_media_max_plaintext_bytes)
            .map_err(|_| AppError::internal("invalid Chat-media server limit"))?;
    if offer.ciphertext_bytes > configured_ciphertext_limit {
        return Err(AppError::bad_request(
            "Chat media exceeds the destination server limit",
        ));
    }
    if offer.origin_domain != local_domain {
        return Err(AppError::bad_request("invalid Chat media delivery"));
    }
    if offer.destination_domain != local_domain {
        return crate::chat_media_federation::stage_remote_delivery(&state, origin_user_id, offer)
            .await
            .map(Json);
    }
    let operation_id = canonical_uuid(&offer.operation_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat media delivery"))?;
    let attachment_id = canonical_uuid(&offer.attachment_id)
        .ok_or_else(|| AppError::bad_request("invalid Chat media delivery"))?;
    let address = AccountAddress::from_str(&offer.recipient).map_err(|_| unavailable())?;
    let capability: [u8; 16] = STANDARD
        .decode(&offer.delivery_capability)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(unavailable)?;
    let retrieval_token: [u8; 32] = STANDARD
        .decode(&offer.retrieval_token)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(unavailable)?;
    let presented_capability_hash = capability_hash(&capability);
    let presented_token_hash: [u8; 32] = Sha256::digest(retrieval_token).into();
    let offer_digest = delivery_offer_digest(&offer)?;

    let mut transaction = state.pool.begin().await?;
    let operation_lock = format!("{origin_user_id}:{operation_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1127042))")
        .bind(operation_lock)
        .execute(&mut *transaction)
        .await?;
    let existing_operation: Option<(String, Uuid)> = sqlx::query_as(
        "SELECT offer_digest,storage_reference_id
         FROM chat_media_origin_delivery_operations
         WHERE origin_user_id=$1 AND operation_id=$2",
    )
    .bind(origin_user_id)
    .bind(operation_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((stored_offer_digest, reference_id)) = existing_operation {
        if stored_offer_digest != offer_digest {
            crate::telemetry::chat_media_event("local_delivery", "changed_replay");
            return Err(AppError::conflict("Chat media operation replay changed"));
        }
        crate::telemetry::chat_media_event("local_delivery", "already_stored");
        return Ok(Json(ChatMediaOfferResponseV1 {
            operation_id: operation_id.to_string(),
            status: ChatMediaDeliveryStatusV1::AlreadyStored,
            storage_reference_id: Some(reference_id.to_string()),
        }));
    }
    let recipient_user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username=$1 AND is_active=true")
            .bind(&address.username)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some(recipient_user_id) = recipient_user_id else {
        constant_time_capability_hash_eq(&presented_capability_hash, &[0; 32]);
        return Err(unavailable());
    };
    if !match_delivery_capability(
        &mut transaction,
        recipient_user_id,
        &presented_capability_hash,
    )
    .await?
    {
        return Err(unavailable());
    }
    type ObjectRow = (Uuid, i16, i64, String, Vec<u8>);
    let object: Option<ObjectRow> = sqlx::query_as(
        "SELECT origin_user_id,suite,ciphertext_bytes,ciphertext_sha256,retrieval_token_hash
         FROM chat_media_objects WHERE attachment_id=$1",
    )
    .bind(attachment_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((stored_origin, stored_suite, stored_bytes, stored_digest, stored_token_hash)) =
        object
    else {
        constant_time_capability_hash_eq(&presented_token_hash, &[0; 32]);
        return Err(unavailable());
    };
    let stored_token_hash: [u8; 32] = stored_token_hash
        .try_into()
        .map_err(|_| AppError::internal("stored media retrieval verifier is malformed"))?;
    if stored_origin != origin_user_id
        || stored_suite != i16::try_from(offer.suite.as_u16()).unwrap_or_default()
        || stored_bytes != offer.ciphertext_bytes as i64
        || stored_digest != offer.ciphertext_sha256
        || !constant_time_capability_hash_eq(&stored_token_hash, &presented_token_hash)
    {
        return Err(unavailable());
    }

    // Database-backed abuse limits use only blinded capability/recipient
    // digests and never metric labels containing identities.
    consume_media_rate(
        &mut transaction,
        "capability_minute",
        &presented_capability_hash,
        120,
        60,
    )
    .await?;
    consume_media_rate(
        &mut transaction,
        "capability_day",
        &presented_capability_hash,
        10_000,
        86_400,
    )
    .await?;
    let recipient_rate_digest: [u8; 32] = Sha256::digest(
        [
            b"kutup/chat-media/recipient-rate/v1\0".as_slice(),
            recipient_user_id.as_bytes(),
        ]
        .concat(),
    )
    .into();
    consume_media_rate(
        &mut transaction,
        "recipient",
        &recipient_rate_digest,
        120,
        60,
    )
    .await?;

    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes,storage_used_bytes FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(recipient_user_id)
    .fetch_one(&mut *transaction)
    .await?;
    let existing_reference: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM chat_media_references WHERE user_id=$1 AND attachment_id=$2",
    )
    .bind(recipient_user_id)
    .bind(attachment_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let (reference_id, status) = if let Some(reference_id) = existing_reference {
        (reference_id, ChatMediaDeliveryStatusV1::AlreadyStored)
    } else {
        let reserved: i64 = sqlx::query_scalar(
            "SELECT (SELECT COALESCE(SUM(total_bytes-received_bytes),0)::bigint FROM uploads WHERE user_id=$1) +
                    (SELECT COALESCE(SUM(total_bytes-received_bytes),0)::bigint FROM chat_media_uploads WHERE user_id=$1) +
                    (SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint
                       FROM chat_media_federation_inbound_pending WHERE recipient_user_id=$1)",
        )
        .bind(recipient_user_id)
        .fetch_one(&mut *transaction)
        .await?;
        if used
            .checked_add(reserved)
            .and_then(|value| value.checked_add(stored_bytes))
            .is_none_or(|value| value > quota)
        {
            crate::telemetry::chat_media_event("local_delivery", "storage_full");
            return Ok(Json(ChatMediaOfferResponseV1 {
                operation_id: operation_id.to_string(),
                status: ChatMediaDeliveryStatusV1::StorageFull,
                storage_reference_id: None,
            }));
        }
        let reference_id: Uuid = sqlx::query_scalar(
            "INSERT INTO chat_media_references(user_id,attachment_id,logical_bytes)
             VALUES ($1,$2,$3) RETURNING id",
        )
        .bind(recipient_user_id)
        .bind(attachment_id)
        .bind(stored_bytes)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query("UPDATE users SET storage_used_bytes=storage_used_bytes+$1 WHERE id=$2")
            .bind(stored_bytes)
            .bind(recipient_user_id)
            .execute(&mut *transaction)
            .await?;
        (reference_id, ChatMediaDeliveryStatusV1::Stored)
    };
    sqlx::query(
        "INSERT INTO chat_media_origin_delivery_operations
         (origin_user_id,operation_id,recipient_user_id,attachment_id,ciphertext_bytes,
          ciphertext_sha256,offer_digest,storage_reference_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(origin_user_id)
    .bind(operation_id)
    .bind(recipient_user_id)
    .bind(attachment_id)
    .bind(stored_bytes)
    .bind(&stored_digest)
    .bind(&offer_digest)
    .bind(reference_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    crate::telemetry::chat_media_event(
        "local_delivery",
        match status {
            ChatMediaDeliveryStatusV1::Stored => "stored",
            ChatMediaDeliveryStatusV1::AlreadyStored => "already_stored",
            ChatMediaDeliveryStatusV1::Queued => "queued",
            ChatMediaDeliveryStatusV1::StorageFull => "storage_full",
        },
    );
    Ok(Json(ChatMediaOfferResponseV1 {
        operation_id: operation_id.to_string(),
        status,
        storage_reference_id: Some(reference_id.to_string()),
    }))
}

#[tracing::instrument(name = "chat_media.download", skip_all)]
pub async fn download_object(
    State(state): State<AppState>,
    user: AuthUser,
    Path(attachment_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let attachment_id = canonical_uuid(&attachment_id)
        .ok_or_else(|| AppError::not_found("Chat media not found"))?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT o.storage_path,o.ciphertext_bytes
         FROM chat_media_references r JOIN chat_media_objects o ON o.attachment_id=r.attachment_id
         WHERE r.user_id=$1 AND r.attachment_id=$2",
    )
    .bind(user_id)
    .bind(attachment_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((path, expected_bytes)) = row else {
        return Err(AppError::not_found("Chat media not found"));
    };
    let (body, bytes) = state
        .storage
        .get_object(&path)
        .await
        .map_err(|_| AppError::internal("Chat media storage unavailable"))?;
    if bytes != expected_bytes {
        crate::telemetry::chat_media_event("download", "length_mismatch");
        return Err(AppError::internal("Chat media storage length mismatch"));
    }
    crate::telemetry::chat_media_event("download", "streamed");
    Ok(octet_stream_response(body, bytes, &[]))
}

/// Discard a finalized origin object before it has been offered. This is used
/// when the browser's independently computed digest does not match the final
/// tus receipt. Once any delivery grant exists, clearing follows the separate
/// per-recipient reference lifecycle and this endpoint fails closed.
pub async fn discard_origin_object(
    State(state): State<AppState>,
    user: AuthUser,
    Path(attachment_id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let attachment_id = canonical_uuid(&attachment_id)
        .ok_or_else(|| AppError::not_found("Chat media not found"))?;
    let mut tx = state.pool.begin().await?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT storage_path,ciphertext_bytes FROM chat_media_objects
         WHERE attachment_id=$1 AND origin_user_id=$2 FOR UPDATE",
    )
    .bind(attachment_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((storage_path, bytes)) = row else {
        return Err(AppError::not_found("Chat media not found"));
    };
    let offered: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat_media_federation_pull_grants WHERE attachment_id=$1)",
    )
    .bind(attachment_id)
    .fetch_one(&mut *tx)
    .await?;
    let references: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_media_references WHERE attachment_id=$1")
            .bind(attachment_id)
            .fetch_one(&mut *tx)
            .await?;
    if offered || references != 1 {
        return Err(AppError::conflict("Chat media has already been delivered"));
    }
    let removed =
        sqlx::query("DELETE FROM chat_media_references WHERE user_id=$1 AND attachment_id=$2")
            .bind(user_id)
            .bind(attachment_id)
            .execute(&mut *tx)
            .await?;
    if removed.rows_affected() != 1 {
        return Err(AppError::conflict("Chat media reference changed"));
    }
    sqlx::query(
        "UPDATE users SET storage_used_bytes=GREATEST(storage_used_bytes-$1,0) WHERE id=$2",
    )
    .bind(bytes)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM chat_media_objects WHERE attachment_id=$1")
        .bind(attachment_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state
        .storage
        .delete(&storage_path)
        .await
        .map_err(|_| AppError::internal("discarded Chat-media object requires storage sweep"))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Resolve only the authenticated account's opaque local reference. This lets
/// a client build its encrypted per-conversation ledger without downloading
/// the object and never reveals a sender or plaintext media metadata.
pub async fn reference_info(
    State(state): State<AppState>,
    user: AuthUser,
    Path(attachment_id): Path<String>,
) -> AppResult<Json<ChatMediaReferenceInfo>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let attachment_id = canonical_uuid(&attachment_id)
        .ok_or_else(|| AppError::not_found("Chat media not found"))?;
    let row: Option<(Uuid, i64, String)> = sqlx::query_as(
        "SELECT r.id,o.ciphertext_bytes,o.ciphertext_sha256
         FROM chat_media_references r JOIN chat_media_objects o ON o.attachment_id=r.attachment_id
         WHERE r.user_id=$1 AND r.attachment_id=$2",
    )
    .bind(user_id)
    .bind(attachment_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((reference_id, ciphertext_bytes, ciphertext_sha256)) = row else {
        return Err(AppError::not_found("Chat media not found"));
    };
    Ok(Json(ChatMediaReferenceInfo {
        attachment_id: attachment_id.to_string(),
        storage_reference_id: reference_id.to_string(),
        ciphertext_bytes,
        ciphertext_sha256,
    }))
}

/// Clear only the authenticated account's opaque storage reference and quota
/// charge. The physical object is removed after the final local reference;
/// an origin cannot clear its retry copy while federation delivery is pending.
#[tracing::instrument(name = "chat_media.clear_reference", skip_all)]
pub async fn clear_reference(
    State(state): State<AppState>,
    user: AuthUser,
    Path(attachment_id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let attachment_id = canonical_uuid(&attachment_id)
        .ok_or_else(|| AppError::not_found("Chat media not found"))?;
    let mut tx = state.pool.begin().await?;
    type ReferenceRow = (Uuid, i64, String, Option<Uuid>);
    let row: Option<ReferenceRow> = sqlx::query_as(
        "SELECT r.id,r.logical_bytes,o.storage_path,o.origin_user_id
         FROM chat_media_references r
         JOIN chat_media_objects o ON o.attachment_id=r.attachment_id
         WHERE r.user_id=$1 AND r.attachment_id=$2 FOR UPDATE OF r,o",
    )
    .bind(user_id)
    .bind(attachment_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((reference_id, logical_bytes, storage_path, origin_user_id)) = row else {
        return Err(AppError::not_found("Chat media not found"));
    };
    if origin_user_id == Some(user_id) {
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM chat_media_federation_outbox
               WHERE origin_user_id=$1 AND state='pending'
                 AND transaction->'offer'->>'attachmentId'=$2)",
        )
        .bind(user_id)
        .bind(attachment_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if pending {
            return Err(AppError::conflict(
                "Chat media is still queued for federation delivery",
            ));
        }
    }
    sqlx::query("DELETE FROM chat_media_references WHERE id=$1")
        .bind(reference_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE users SET storage_used_bytes=GREATEST(storage_used_bytes-$1,0) WHERE id=$2",
    )
    .bind(logical_bytes)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_media_references WHERE attachment_id=$1")
            .bind(attachment_id)
            .fetch_one(&mut *tx)
            .await?;
    let delete_object = remaining == 0;
    if delete_object {
        if origin_user_id.is_some() {
            sqlx::query("DELETE FROM chat_media_federation_pull_grants WHERE attachment_id=$1")
                .bind(attachment_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM chat_media_objects WHERE attachment_id=$1")
            .bind(attachment_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if delete_object {
        state
            .storage
            .delete(&storage_path)
            .await
            .map_err(|_| AppError::internal("cleared Chat-media object requires storage sweep"))?;
    }
    crate::telemetry::chat_media_event("reference", "cleared");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn storage_summary(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<ChatMediaStorageSummary>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (quota, used): (i64, i64) =
        sqlx::query_as("SELECT storage_quota_bytes,storage_used_bytes FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let drive: i64 = sqlx::query_scalar(
        "SELECT
          (SELECT COALESCE(SUM(encrypted_size_bytes),0)::bigint FROM files WHERE uploader_user_id=$1) +
          (SELECT COALESCE(SUM(size_bytes),0)::bigint FROM file_assets WHERE uploader_user_id=$1) +
          (SELECT COALESCE(SUM(size_bytes),0)::bigint FROM file_versions WHERE author_user_id=$1)",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let chat: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(logical_bytes),0)::bigint FROM chat_media_references WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(ChatMediaStorageSummary {
        total_quota_bytes: quota,
        total_used_bytes: used,
        drive_bytes: drive,
        chat_media_bytes: chat,
    }))
}

pub async fn put_ledger_entity(
    State(state): State<AppState>,
    user: AuthUser,
    Path(entity_id): Path<String>,
    Json(request): Json<ChatAttachmentLedgerPutRequestV1>,
) -> AppResult<Json<ChatAttachmentLedgerPutReceiptV1>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let entity_id = canonical_uuid(&entity_id)
        .ok_or_else(|| AppError::bad_request("invalid ledger entity id"))?;
    let operation_id = canonical_uuid(&request.operation_id)
        .ok_or_else(|| AppError::bad_request("invalid ledger operation id"))?;
    let envelope = chat_attachment_ledger::decode_canonical_b64(&request.envelope)
        .map_err(|_| AppError::bad_request("invalid attachment ledger envelope"))?;
    let header = chat_attachment_ledger::inspect(&envelope)
        .map_err(|_| AppError::bad_request("invalid attachment ledger envelope"))?;
    if Uuid::from_bytes(header.context.entity_id) != entity_id {
        return Err(AppError::bad_request("ledger entity binding mismatch"));
    }
    let revision = i64::try_from(header.context.revision)
        .map_err(|_| AppError::bad_request("ledger revision is too large"))?;
    let digest = chat_attachment_ledger::envelope_digest(&envelope)
        .map_err(|_| AppError::bad_request("invalid attachment ledger envelope"))?;
    let account_incarnation: String =
        sqlx::query_scalar("SELECT account_incarnation_id FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    if hex::encode(header.context.account_incarnation_id) != account_incarnation {
        return Err(AppError::conflict("ledger account incarnation mismatch"));
    }

    let mut transaction = state.pool.begin().await?;
    type Receipt = (Uuid, i64, String, i64);
    let receipt: Option<Receipt> = sqlx::query_as(
        "SELECT entity_id,revision,envelope_digest,cursor
         FROM chat_attachment_ledger_operations WHERE user_id=$1 AND operation_id=$2",
    )
    .bind(user_id)
    .bind(operation_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((stored_entity, stored_revision, stored_digest, cursor)) = receipt {
        if stored_entity != entity_id || stored_revision != revision || stored_digest != digest {
            return Err(AppError::conflict("ledger operation replay changed"));
        }
        return Ok(Json(ChatAttachmentLedgerPutReceiptV1 {
            entity_id: entity_id.to_string(),
            revision: header.context.revision.to_string(),
            envelope_digest: digest,
            cursor: cursor.to_string(),
            idempotent: true,
        }));
    }
    let current: Option<(i64, String)> = sqlx::query_as(
        "SELECT revision,envelope_digest FROM chat_attachment_ledger_entities
         WHERE user_id=$1 AND entity_id=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(entity_id)
    .fetch_optional(&mut *transaction)
    .await?;
    match &current {
        None if revision == 1 && header.context.previous_envelope_digest == [0; 32] => {}
        Some((current_revision, current_digest))
            if revision == *current_revision + 1
                && hex::encode(header.context.previous_envelope_digest) == *current_digest => {}
        _ => {
            return Err(AppError::conflict(
                "ledger revision or predecessor mismatch",
            ))
        }
    }
    let cursor: i64 = sqlx::query_scalar("SELECT nextval('chat_attachment_ledger_cursor_seq')")
        .fetch_one(&mut *transaction)
        .await?;
    if current.is_none() {
        sqlx::query(
            "INSERT INTO chat_attachment_ledger_entities
             (user_id,entity_id,revision,envelope_digest,cursor)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(user_id)
        .bind(entity_id)
        .bind(revision)
        .bind(&digest)
        .bind(cursor)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "UPDATE chat_attachment_ledger_entities
             SET revision=$3,envelope_digest=$4,cursor=$5,updated_at=NOW()
             WHERE user_id=$1 AND entity_id=$2",
        )
        .bind(user_id)
        .bind(entity_id)
        .bind(revision)
        .bind(&digest)
        .bind(cursor)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO chat_attachment_ledger_history
         (user_id,entity_id,revision,envelope_digest,envelope,cursor)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(user_id)
    .bind(entity_id)
    .bind(revision)
    .bind(&digest)
    .bind(&request.envelope)
    .bind(cursor)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO chat_attachment_ledger_operations
         (user_id,operation_id,entity_id,revision,envelope_digest,cursor)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(user_id)
    .bind(operation_id)
    .bind(entity_id)
    .bind(revision)
    .bind(&digest)
    .bind(cursor)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(ChatAttachmentLedgerPutReceiptV1 {
        entity_id: entity_id.to_string(),
        revision: header.context.revision.to_string(),
        envelope_digest: digest,
        cursor: cursor.to_string(),
        idempotent: false,
    }))
}

pub async fn ledger_diff(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<LedgerDiffQuery>,
) -> AppResult<Json<ChatAttachmentLedgerDiffPageV1>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let after_text = query.after.as_deref().unwrap_or("0");
    let after = after_text
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0 && value.to_string() == after_text)
        .ok_or_else(|| AppError::bad_request("ledger cursor must be canonical non-negative i64"))?;
    let limit = query.limit.unwrap_or(128);
    if !(1..=256).contains(&limit) {
        return Err(AppError::bad_request("ledger page limit must be 1..=256"));
    }
    let rows: Vec<(Uuid, i64, String, String, i64)> = sqlx::query_as(
        "SELECT entity_id,revision,envelope_digest,envelope,cursor
         FROM chat_attachment_ledger_history
         WHERE user_id=$1 AND cursor>$2 ORDER BY cursor ASC LIMIT $3",
    )
    .bind(user_id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let more = rows.len() as i64 > limit;
    let entities: Vec<_> = rows
        .into_iter()
        .take(limit as usize)
        .map(|(entity_id, revision, envelope_digest, envelope, cursor)| {
            Ok(ChatAttachmentLedgerWireEntityV1 {
                entity_id: entity_id.to_string(),
                revision: u64::try_from(revision)
                    .map_err(|_| AppError::internal("stored ledger revision is invalid"))?
                    .to_string(),
                envelope_digest,
                envelope,
                cursor: cursor.to_string(),
            })
        })
        .collect::<AppResult<_>>()?;
    let next_cursor = entities
        .last()
        .map_or_else(|| after.to_string(), |entity| entity.cursor.clone());
    let page = ChatAttachmentLedgerDiffPageV1 {
        entities,
        next_cursor,
        more,
    };
    page.validate(after_text)
        .map_err(|_| AppError::internal("stored attachment ledger page is invalid"))?;
    Ok(Json(page))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identifiers_are_canonical_and_tokens_are_hashed() {
        assert!(canonical_uuid("11111111-1111-4111-8111-111111111111").is_some());
        assert!(canonical_uuid("11111111111141118111111111111111").is_none());
        let token = STANDARD.encode([7_u8; 32]);
        assert_ne!(canonical_token_hash(&token).unwrap().as_slice(), [7_u8; 32]);
    }
}
