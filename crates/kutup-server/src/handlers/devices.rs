//! Device-key handlers — mirrors `backend/handlers/devices.go` (collab-edit v1).
//!
//! Registers/lists/revokes per-device Ed25519 signing keys. `authSig` is recorded but not
//! verified in v1 (the JWT is the trust anchor). The revoke→Hub close hook is wired with
//! the collab WebSocket slice (slice 5); revoke already flips `is_active=false` here.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterDeviceRequest {
    /// base64 32-byte Ed25519 pubkey.
    public_signing: String,
    label: String,
    /// signed by the master-derived signing key (verified in v2; recorded only in v1).
    auth_sig: String,
    /// unix seconds; rejected if > 5 min skew.
    timestamp: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    device_id: i64,
    label: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRow {
    device_id: i64,
    label: String,
    is_active: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_seen_at: Option<OffsetDateTime>,
}

/// `POST /api/devices` — mirrors `Register`.
#[utoipa::path(
    post,
    path = "/api/devices",
    tag = "devices",
    operation_id = "registerDevice",
    security(("BearerAuth" = [])),
    request_body = RegisterDeviceRequest,
    responses((status = 201, description = "Device signing key registered", body = RegisterDeviceResponse))
)]
pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;

    let pub_bytes = STANDARD.decode(&req.public_signing).unwrap_or_default();
    if pub_bytes.len() != 32 {
        return Err(AppError::bad_request(
            "publicSigning must be base64 32 bytes",
        ));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if (now - req.timestamp).abs() > 300 {
        return Err(AppError::bad_request("timestamp skew"));
    }
    // authSig recorded for v2 forward-compat; not validated in v1.
    let _ = &req.auth_sig;

    let (id, created_at): (i64, OffsetDateTime) = sqlx::query_as(
        r#"INSERT INTO user_devices (user_id, public_signing, label)
           VALUES ($1, $2, NULLIF($3, ''))
           RETURNING id, created_at"#,
    )
    .bind(user_id)
    .bind(&pub_bytes)
    .bind(&req.label)
    .fetch_one(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            device_id: id,
            label: req.label,
            created_at,
        }),
    )
        .into_response())
}

/// `GET /api/devices` — mirrors `List`.
#[utoipa::path(
    get,
    path = "/api/devices",
    tag = "devices",
    operation_id = "listDevices",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's devices", body = Vec<DeviceRow>))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(i64, String, bool, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        r#"SELECT id, COALESCE(label, ''), is_active, created_at, last_seen_at
           FROM user_devices WHERE user_id = $1 ORDER BY created_at DESC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    let out: Vec<DeviceRow> = rows
        .into_iter()
        .map(
            |(device_id, label, is_active, created_at, last_seen_at)| DeviceRow {
                device_id,
                label,
                is_active,
                created_at,
                last_seen_at,
            },
        )
        .collect();
    Ok(Json(out).into_response())
}

/// `DELETE /api/devices/{id}` — mirrors `Revoke`.
#[utoipa::path(
    delete,
    path = "/api/devices/{id}",
    tag = "devices",
    security(("BearerAuth" = [])),
    params(("id" = i64, Path, description = "Device id")),
    responses((status = 204, description = "Device revoked; live collab connections dropped"))
)]
pub async fn revoke(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let device_id: i64 = id
        .parse()
        .map_err(|_| AppError::bad_request("invalid id"))?;

    let res = sqlx::query(
        "UPDATE user_devices SET is_active = false WHERE id = $1 AND user_id = $2 AND is_active = true",
    )
    .bind(device_id)
    .bind(user_id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {}
        _ => return Err(AppError::not_found("not found")),
    }
    // Drop this device's live collab WS connections — mirrors Go's hub.CloseDevice.
    state.hub.close_device(device_id);
    Ok(StatusCode::NO_CONTENT.into_response())
}
