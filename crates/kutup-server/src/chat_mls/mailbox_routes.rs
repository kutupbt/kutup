//! Authenticated drain and acknowledgement for the dedicated MLS mailbox.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    AckMlsMailboxV1, MlsMailboxDeliveryKindV1, MlsMailboxEnvelopeV1, MlsMailboxPageV1,
};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{active_policy, MAX_DEVICE_ID};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

const DEFAULT_PAGE_SIZE: u16 = 100;
const MAX_PAGE_SIZE: u16 = 256;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MlsMailboxQuery {
    after: Option<String>,
    limit: Option<u16>,
}

pub(crate) async fn drain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<u32>,
    Query(query): Query<MlsMailboxQuery>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    validate_device_id(device_id)?;
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, device_id).await?;
    let after = parse_cursor(query.after.as_deref())?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(AppError::bad_request("MLS mailbox limit is outside 1-256"));
    }
    type Row = (
        Uuid,
        i64,
        String,
        Option<Uuid>,
        Option<i64>,
        Uuid,
        Vec<u8>,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, cursor, delivery_kind, conversation_id, incarnation,
                send_id, opaque_envelope, server_ts
         FROM chat_mls_mailbox
         WHERE recipient_user_id = $1 AND recipient_device_id = $2
           AND cursor > $3
         ORDER BY cursor
         LIMIT $4",
    )
    .bind(user_id)
    .bind(device_id as i32)
    .bind(after)
    .bind(i64::from(limit))
    .fetch_all(&state.pool)
    .await?;
    let mut envelopes = Vec::with_capacity(rows.len());
    for (
        id,
        cursor,
        delivery_kind,
        conversation_id,
        incarnation,
        send_id,
        opaque_envelope,
        server_ts,
    ) in rows
    {
        envelopes.push(MlsMailboxEnvelopeV1 {
            id,
            cursor: checked_positive(cursor, "mailbox cursor")?.to_string(),
            delivery_kind: parse_delivery_kind(&delivery_kind)?,
            conversation_id,
            incarnation: incarnation
                .map(|value| checked_positive(value, "mailbox incarnation"))
                .transpose()?,
            send_id,
            opaque_envelope: STANDARD.encode(opaque_envelope),
            server_timestamp: server_ts.unix_timestamp(),
        });
    }
    let page = MlsMailboxPageV1 {
        next_cursor: envelopes.last().map(|envelope| envelope.cursor.clone()),
        envelopes,
    };
    page.validate()
        .map_err(|error| AppError::internal(format!("stored MLS mailbox is invalid: {error}")))?;
    Ok(Json(page).into_response())
}

pub(crate) async fn ack(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<AckMlsMailboxV1>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    request.validate().map_err(AppError::bad_request)?;
    validate_device_id(request.device_id)?;
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state, user_id, request.device_id).await?;
    sqlx::query(
        "DELETE FROM chat_mls_mailbox
         WHERE recipient_user_id = $1 AND recipient_device_id = $2
           AND id = ANY($3)",
    )
    .bind(user_id)
    .bind(request.device_id as i32)
    .bind(&request.envelope_ids)
    .execute(&state.pool)
    .await?;
    // Acknowledgement is deliberately idempotent and does not reveal which
    // caller-supplied UUIDs existed.
    Ok(Json(serde_json::json!({
        "acknowledged": request.envelope_ids.len()
    }))
    .into_response())
}

async fn require_device(state: &AppState, user_id: Uuid, device_id: u32) -> AppResult<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM chat_mls_devices
            WHERE user_id = $1 AND device_id = $2
         )",
    )
    .bind(user_id)
    .bind(device_id as i32)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(AppError::not_found("MLS device not found"));
    }
    Ok(())
}

fn validate_device_id(device_id: u32) -> AppResult<()> {
    if device_id == 0 || device_id > MAX_DEVICE_ID {
        return Err(AppError::bad_request("invalid MLS device id"));
    }
    Ok(())
}

fn parse_cursor(value: Option<&str>) -> AppResult<i64> {
    let Some(value) = value else {
        return Ok(0);
    };
    let cursor = value
        .parse::<i64>()
        .ok()
        .filter(|cursor| *cursor >= 0 && cursor.to_string() == value)
        .ok_or_else(|| AppError::bad_request("MLS mailbox cursor is not canonical decimal"))?;
    Ok(cursor)
}

fn checked_positive(value: i64, field: &str) -> AppResult<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError::internal(format!("stored MLS {field} is invalid")))
}

fn parse_delivery_kind(value: &str) -> AppResult<MlsMailboxDeliveryKindV1> {
    match value {
        "identified_request" => Ok(MlsMailboxDeliveryKindV1::IdentifiedRequest),
        "anonymous" => Ok(MlsMailboxDeliveryKindV1::Anonymous),
        "self_sync" => Ok(MlsMailboxDeliveryKindV1::SelfSync),
        "membership_control" => Ok(MlsMailboxDeliveryKindV1::MembershipControl),
        _ => Err(AppError::internal(
            "stored MLS mailbox delivery kind is invalid",
        )),
    }
}
