//! Account-local opaque relay for V1 Chat history transfer.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    chat_history_transfer_transcript_hash, AccountManifestV1, ChatHistoryTransferAcceptanceV1,
    ChatHistoryTransferCompletionV1, ChatHistoryTransferFrameV1, ChatHistoryTransferRequestV1,
    ChatWsServerMessage, MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    #[serde(rename = "deviceId")]
    device_id: u32,
}

#[derive(Debug, Deserialize)]
pub struct FrameDrainQuery {
    #[serde(rename = "deviceId")]
    device_id: u32,
    #[serde(default)]
    after: Option<i32>,
    #[serde(default)]
    limit: Option<i64>,
}

type TransferRow = (
    Uuid,
    i32,
    Option<i32>,
    i64,
    Value,
    Option<Value>,
    Option<String>,
    String,
    OffsetDateTime,
);

/// `POST /api/chat/history-transfers` — stage a signed request from a newly
/// registered Chat device. Existing devices receive only an opaque wake-up.
#[utoipa::path(
    post,
    path = "/api/chat/history-transfers",
    tag = "chat",
    operation_id = "createChatHistoryTransfer",
    request_body = ChatHistoryTransferRequestV1,
    responses((status = 201, description = "Transfer request staged")),
    security(("bearerAuth" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<ChatHistoryTransferRequestV1>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    request.validate(now).map_err(AppError::bad_request)?;
    let manifest = require_current_manifest(&state, user_id, request.requesting_device_id).await?;
    if request.account != manifest.account || request.manifest_sequence != manifest.sequence {
        return Err(AppError::conflict(
            "history transfer request does not match the current account manifest",
        ));
    }
    let transfer_id = parse_transfer_id(&request.transfer_id)?;
    let manifest_sequence = i64::try_from(request.manifest_sequence)
        .map_err(|_| AppError::bad_request("manifestSequence exceeds server storage"))?;
    let request_hash = hex::encode(request.signed_hash().map_err(AppError::bad_request)?);
    let value = serde_json::to_value(&request)
        .map_err(|error| AppError::internal(format!("serialize history transfer: {error}")))?;
    let inserted = sqlx::query(
        "INSERT INTO chat_history_transfers
           (transfer_id,user_id,requesting_device_id,manifest_sequence,request,request_hash,expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7)) ON CONFLICT DO NOTHING",
    )
    .bind(transfer_id)
    .bind(user_id)
    .bind(request.requesting_device_id as i32)
    .bind(manifest_sequence)
    .bind(&value)
    .bind(&request_hash)
    .bind(request.expires_at_unix as f64)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if inserted == 0 {
        let existing: Option<(Uuid, i32, String)> = sqlx::query_as(
            "SELECT user_id,requesting_device_id,request_hash
             FROM chat_history_transfers WHERE transfer_id=$1",
        )
        .bind(transfer_id)
        .fetch_optional(&state.pool)
        .await?;
        if existing != Some((user_id, request.requesting_device_id as i32, request_hash)) {
            return Err(AppError::conflict(
                "transferId is already bound to another request",
            ));
        }
    }
    if inserted == 1 {
        let hint = ChatWsServerMessage::HistoryTransferAvailable {
            transfer_id: request.transfer_id.clone(),
        };
        if let Ok(text) = serde_json::to_string(&hint) {
            for device in manifest
                .devices
                .iter()
                .filter(|device| device.device_id != request.requesting_device_id)
            {
                for connection in state.chat_hub.connections(user_id, device.device_id as i32) {
                    connection.write(ChatWsOut::Text(text.clone())).await;
                }
            }
        }
    }
    Ok((
        if inserted == 1 {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({
            "transferId": request.transfer_id,
            "idempotent": inserted == 0
        })),
    )
        .into_response())
}

/// `GET /api/chat/history-transfers?deviceId=N` — list requests visible to one
/// exact authenticated Chat device.
#[utoipa::path(
    get,
    path = "/api/chat/history-transfers",
    tag = "chat",
    operation_id = "listChatHistoryTransfers",
    params(("deviceId" = u32, Query)),
    responses((status = 200, description = "Visible active transfers")),
    security(("bearerAuth" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<DeviceQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_current_manifest(&state, user_id, query.device_id).await?;
    expire(&state).await?;
    let rows: Vec<(Uuid, Value, Option<Value>, String, i32, Option<i32>, i64)> = sqlx::query_as(
        "SELECT transfer_id,request,acceptance,state,requesting_device_id,
                responding_device_id,
                (SELECT COUNT(*) FROM chat_history_transfer_frames f
                 WHERE f.transfer_id=t.transfer_id)
         FROM chat_history_transfers t
         WHERE user_id=$1 AND expires_at>now() AND state<>'completed'
           AND (requesting_device_id=$2 OR responding_device_id=$2
                OR (state='pending' AND requesting_device_id<>$2))
         ORDER BY created_at",
    )
    .bind(user_id)
    .bind(query.device_id as i32)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "transfers": rows.into_iter().map(|row| json!({
        "transferId": row.0,
        "request": row.1,
        "acceptance": row.2,
        "state": row.3,
        "requestingDeviceId": row.4,
        "respondingDeviceId": row.5,
        "frameCount": row.6,
    })).collect::<Vec<_>>() }))
    .into_response())
}

/// `PUT /api/chat/history-transfers/{transferId}/acceptance?deviceId=N` — one
/// existing manifest device explicitly approves the exact request.
#[utoipa::path(
    put,
    path = "/api/chat/history-transfers/{transferId}/acceptance",
    tag = "chat",
    operation_id = "acceptChatHistoryTransfer",
    params(("transferId" = Uuid, Path), ("deviceId" = u32, Query)),
    request_body = ChatHistoryTransferAcceptanceV1,
    responses((status = 200, description = "Transfer accepted")),
    security(("bearerAuth" = []))
)]
pub async fn accept(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(transfer_id): Path<Uuid>,
    Query(query): Query<DeviceQuery>,
    Json(acceptance): Json<ChatHistoryTransferAcceptanceV1>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let manifest = require_current_manifest(&state, user_id, query.device_id).await?;
    let mut tx = state.pool.begin().await?;
    let row = load_transfer_for_update(&mut tx, transfer_id, user_id).await?;
    let request: ChatHistoryTransferRequestV1 = serde_json::from_value(row.4)
        .map_err(|error| AppError::internal(format!("stored transfer request: {error}")))?;
    if acceptance.responding_device_id != query.device_id
        || acceptance.manifest_sequence != manifest.sequence
    {
        return Err(AppError::conflict(
            "acceptance does not match the current responding device",
        ));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    acceptance
        .validate(&request, now)
        .map_err(AppError::bad_request)?;
    let transcript = hex::encode(
        chat_history_transfer_transcript_hash(&request, &acceptance, now)
            .map_err(AppError::bad_request)?,
    );
    let value = serde_json::to_value(&acceptance)
        .map_err(|error| AppError::internal(format!("serialize acceptance: {error}")))?;
    match row.7.as_str() {
        "pending" => {
            sqlx::query(
                "UPDATE chat_history_transfers SET responding_device_id=$1,acceptance=$2,
                   transcript_hash=$3,state='accepted',updated_at=now() WHERE transfer_id=$4",
            )
            .bind(query.device_id as i32)
            .bind(value)
            .bind(&transcript)
            .bind(transfer_id)
            .execute(&mut *tx)
            .await?;
        }
        "accepted"
            if row.2 == Some(query.device_id as i32) && row.6.as_deref() == Some(&transcript) => {}
        _ => {
            return Err(AppError::conflict(
                "history transfer was already accepted or completed",
            ))
        }
    }
    tx.commit().await?;
    Ok(Json(json!({ "transferId": transfer_id, "transcriptHash": transcript })).into_response())
}

/// `PUT /api/chat/history-transfers/{transferId}/frames/{index}?deviceId=N` —
/// upload one opaque, transcript-bound frame.
#[utoipa::path(
    put,
    path = "/api/chat/history-transfers/{transferId}/frames/{index}",
    tag = "chat",
    operation_id = "putChatHistoryTransferFrame",
    params(("transferId" = Uuid, Path), ("index" = u32, Path), ("deviceId" = u32, Query)),
    request_body = ChatHistoryTransferFrameV1,
    responses((status = 200, description = "Opaque frame stored")),
    security(("bearerAuth" = []))
)]
pub async fn put_frame(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((transfer_id, index)): Path<(Uuid, u32)>,
    Query(query): Query<DeviceQuery>,
    Json(frame): Json<ChatHistoryTransferFrameV1>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    frame.validate().map_err(AppError::bad_request)?;
    if frame.transfer_id != transfer_id.to_string() || frame.index != index {
        return Err(AppError::bad_request(
            "frame path does not match its authenticated metadata",
        ));
    }
    let mut tx = state.pool.begin().await?;
    let row = load_transfer_for_update(&mut tx, transfer_id, user_id).await?;
    if row.7 != "accepted"
        || row.2 != Some(query.device_id as i32)
        || row.6.as_deref() != Some(frame.transcript_hash.as_str())
        || row.8 <= OffsetDateTime::now_utc()
    {
        return Err(AppError::forbidden(
            "device cannot upload frames for this transfer",
        ));
    }
    let acceptance: ChatHistoryTransferAcceptanceV1 = serde_json::from_value(
        row.5
            .ok_or_else(|| AppError::internal("accepted transfer has no acceptance"))?,
    )
    .map_err(|error| AppError::internal(format!("stored acceptance: {error}")))?;
    let existing: Option<(String, String, bool, i32)> = sqlx::query_as(
        "SELECT nonce,ciphertext,final_frame,plaintext_bytes
         FROM chat_history_transfer_frames WHERE transfer_id=$1 AND frame_index=$2",
    )
    .bind(transfer_id)
    .bind(index as i32)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        if existing
            != (
                frame.nonce.clone(),
                frame.ciphertext.clone(),
                frame.final_frame,
                frame.plaintext_bytes as i32,
            )
        {
            return Err(AppError::conflict(
                "frame index already contains different ciphertext",
            ));
        }
    } else {
        let (count, total, has_final): (i64, i64, bool) = sqlx::query_as(
            "SELECT COUNT(*),COALESCE(SUM(plaintext_bytes),0),COALESCE(BOOL_OR(final_frame),false)
             FROM chat_history_transfer_frames WHERE transfer_id=$1",
        )
        .bind(transfer_id)
        .fetch_one(&mut *tx)
        .await?;
        if index as i64 != count || has_final {
            return Err(AppError::conflict(
                "history transfer frames must be contiguous and final only once",
            ));
        }
        let next_total = total
            .checked_add(frame.plaintext_bytes as i64)
            .ok_or_else(|| AppError::bad_request("history transfer byte count overflow"))?;
        if next_total as u64 > acceptance.plaintext_byte_limit
            || next_total as u64 > MAX_CHAT_HISTORY_TRANSFER_PLAINTEXT
        {
            return Err(AppError::bad_request(
                "history transfer exceeds its accepted plaintext limit",
            ));
        }
        let ciphertext_hash = hex::encode(Sha256::digest(frame.ciphertext.as_bytes()));
        sqlx::query(
            "INSERT INTO chat_history_transfer_frames
             (transfer_id,frame_index,final_frame,plaintext_bytes,nonce,ciphertext,ciphertext_hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(transfer_id)
        .bind(index as i32)
        .bind(frame.final_frame)
        .bind(frame.plaintext_bytes as i32)
        .bind(&frame.nonce)
        .bind(&frame.ciphertext)
        .bind(ciphertext_hash)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "stored": true, "index": index })).into_response())
}

/// `GET /api/chat/history-transfers/{transferId}/frames` — drain opaque frames
/// as the exact requesting device.
#[utoipa::path(
    get,
    path = "/api/chat/history-transfers/{transferId}/frames",
    tag = "chat",
    operation_id = "drainChatHistoryTransferFrames",
    params(("transferId" = Uuid, Path), ("deviceId" = u32, Query), ("after" = Option<i32>, Query), ("limit" = Option<i64>, Query)),
    responses((status = 200, description = "Opaque frame page")),
    security(("bearerAuth" = []))
)]
pub async fn drain_frames(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(transfer_id): Path<Uuid>,
    Query(query): Query<FrameDrainQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, query.device_id).await?;
    let row: Option<(i32, String, Option<String>, OffsetDateTime)> = sqlx::query_as(
        "SELECT requesting_device_id,state,transcript_hash,expires_at
         FROM chat_history_transfers WHERE transfer_id=$1 AND user_id=$2",
    )
    .bind(transfer_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or_else(|| AppError::not_found("no such history transfer"))?;
    if row.0 != query.device_id as i32 || row.1 != "accepted" || row.3 <= OffsetDateTime::now_utc()
    {
        return Err(AppError::forbidden(
            "device cannot drain this history transfer",
        ));
    }
    let after = query.after.unwrap_or(-1);
    let limit = query.limit.unwrap_or(64).clamp(1, 128);
    let frames: Vec<(i32, bool, i32, String, String)> = sqlx::query_as(
        "SELECT frame_index,final_frame,plaintext_bytes,nonce,ciphertext
         FROM chat_history_transfer_frames WHERE transfer_id=$1 AND frame_index>$2
         ORDER BY frame_index LIMIT $3",
    )
    .bind(transfer_id)
    .bind(after)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        json!({ "transcriptHash": row.2, "frames": frames.into_iter().map(|f| json!({
        "version": 1, "transferId": transfer_id, "transcriptHash": row.2,
        "index": f.0, "finalFrame": f.1, "plaintextBytes": f.2,
        "nonce": f.3, "ciphertext": f.4
    })).collect::<Vec<_>>() }),
    )
    .into_response())
}

/// `POST /api/chat/history-transfers/{transferId}/completion?deviceId=N` —
/// destination-signed completion; ciphertext frames are deleted immediately.
#[utoipa::path(
    post,
    path = "/api/chat/history-transfers/{transferId}/completion",
    tag = "chat",
    operation_id = "completeChatHistoryTransfer",
    params(("transferId" = Uuid, Path), ("deviceId" = u32, Query)),
    request_body = ChatHistoryTransferCompletionV1,
    responses((status = 200, description = "Transfer completed and frames erased")),
    security(("bearerAuth" = []))
)]
pub async fn complete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(transfer_id): Path<Uuid>,
    Query(query): Query<DeviceQuery>,
    Json(completion): Json<ChatHistoryTransferCompletionV1>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    completion.validate().map_err(AppError::bad_request)?;
    if completion.transfer_id != transfer_id.to_string()
        || completion.destination_device_id != query.device_id
    {
        return Err(AppError::bad_request(
            "completion does not match its destination path",
        ));
    }
    let mut tx = state.pool.begin().await?;
    let row = load_transfer_for_update(&mut tx, transfer_id, user_id).await?;
    if row.7 == "completed"
        && row.1 == query.device_id as i32
        && row.6.as_deref() == Some(completion.transcript_hash.as_str())
    {
        tx.commit().await?;
        return Ok(Json(json!({ "completed": true, "deduplicated": true })).into_response());
    }
    if row.7 != "accepted"
        || row.1 != query.device_id as i32
        || row.6.as_deref() != Some(completion.transcript_hash.as_str())
        || row.8 <= OffsetDateTime::now_utc()
    {
        return Err(AppError::forbidden(
            "device cannot complete this history transfer",
        ));
    }
    let acceptance: ChatHistoryTransferAcceptanceV1 = serde_json::from_value(
        row.5
            .ok_or_else(|| AppError::internal("accepted transfer has no acceptance"))?,
    )
    .map_err(|error| AppError::internal(format!("stored acceptance: {error}")))?;
    let (count, final_count, total_plaintext): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),COUNT(*) FILTER (WHERE final_frame),COALESCE(SUM(plaintext_bytes),0)
         FROM chat_history_transfer_frames WHERE transfer_id=$1",
    )
    .bind(transfer_id)
    .fetch_one(&mut *tx)
    .await?;
    if count != completion.frame_count as i64 || final_count != 1 {
        return Err(AppError::conflict(
            "completion does not match the stored final frame set",
        ));
    }
    if completion.record_count > acceptance.record_limit
        || completion.media_plaintext_bytes > total_plaintext as u64
    {
        return Err(AppError::bad_request(
            "completion exceeds the accepted archive bounds",
        ));
    }
    let value = serde_json::to_value(&completion)
        .map_err(|error| AppError::internal(format!("serialize completion: {error}")))?;
    sqlx::query("DELETE FROM chat_history_transfer_frames WHERE transfer_id=$1")
        .bind(transfer_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE chat_history_transfers SET completion=$1,state='completed',updated_at=now() WHERE transfer_id=$2")
        .bind(value).bind(transfer_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({ "completed": true })).into_response())
}

/// `DELETE /api/chat/history-transfers/{transferId}?deviceId=N` — cancel and
/// erase a transfer as either participating device.
#[utoipa::path(
    delete,
    path = "/api/chat/history-transfers/{transferId}",
    tag = "chat",
    operation_id = "cancelChatHistoryTransfer",
    params(("transferId" = Uuid, Path), ("deviceId" = u32, Query)),
    responses((status = 204, description = "Transfer erased")),
    security(("bearerAuth" = []))
)]
pub async fn cancel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(transfer_id): Path<Uuid>,
    Query(query): Query<DeviceQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, query.device_id).await?;
    let deleted = sqlx::query(
        "DELETE FROM chat_history_transfers WHERE transfer_id=$1 AND user_id=$2
         AND (requesting_device_id=$3 OR responding_device_id=$3)",
    )
    .bind(transfer_id)
    .bind(user_id)
    .bind(query.device_id as i32)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if deleted == 0 {
        return Err(AppError::not_found("no cancellable history transfer"));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn require_device(state: &AppState, user_id: Uuid, device_id: u32) -> AppResult<()> {
    let exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM chat_devices WHERE user_id=$1 AND device_id=$2")
            .bind(user_id)
            .bind(device_id as i32)
            .fetch_optional(&state.pool)
            .await?;
    if exists.is_none() {
        return Err(AppError::not_found("no such Chat device"));
    }
    Ok(())
}

async fn require_current_manifest(
    state: &AppState,
    user_id: Uuid,
    device_id: u32,
) -> AppResult<AccountManifestV1> {
    require_device(state, user_id, device_id).await?;
    let value: Option<Value> =
        sqlx::query_scalar("SELECT manifest FROM chat_device_manifests WHERE user_id=$1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let manifest: AccountManifestV1 = serde_json::from_value(
        value.ok_or_else(|| AppError::conflict("account has no signed Chat manifest"))?,
    )
    .map_err(|error| AppError::internal(format!("stored manifest: {error}")))?;
    if !manifest
        .devices
        .iter()
        .any(|device| device.device_id == device_id)
    {
        return Err(AppError::conflict(
            "Chat device is absent from the current signed manifest",
        ));
    }
    Ok(manifest)
}

async fn load_transfer_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transfer_id: Uuid,
    user_id: Uuid,
) -> AppResult<TransferRow> {
    sqlx::query_as(
        "SELECT transfer_id,requesting_device_id,responding_device_id,manifest_sequence,
                request,acceptance,transcript_hash,state,expires_at
         FROM chat_history_transfers WHERE transfer_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(transfer_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::not_found("no such history transfer"))
}

async fn expire(state: &AppState) -> AppResult<()> {
    sqlx::query("DELETE FROM chat_history_transfers WHERE expires_at<=now() OR (state='completed' AND updated_at<now()-interval '15 minutes')")
        .execute(&state.pool).await?;
    Ok(())
}

fn parse_transfer_id(value: &str) -> AppResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| AppError::bad_request("transferId must be a UUID"))
}
