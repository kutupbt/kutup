//! Federation proxy endpoints — mirrors `backend/handlers/fedproxy.go`.
//!
//! These run on the *recipient's* server. The browser can't call a remote kutup server
//! directly (CORS, and it must not learn the remote access token), so it calls these
//! authenticated endpoints, which proxy to the remote `/api/fed/*` routes using the stored
//! per-share token. All outbound URLs are SSRF-validated (at accept time) and the shared
//! `FED_CLIENT` never follows redirects.

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::FED_CLIENT;
use crate::middleware::AuthUser;
use crate::{ssrf, AppState};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AddIncomingShareRequest {
    /// e.g. `https://server-b.com/invite/{token}`.
    invite_url: String,
}

/// What the remote `/api/fed/invites/{token}` returns.
#[derive(Debug, Deserialize)]
struct InviteData {
    #[serde(rename = "wrappedKey", default)]
    wrapped_key: String,
    #[serde(rename = "encryptedName", default)]
    encrypted_name: String,
    #[serde(rename = "nameNonce", default)]
    name_nonce: String,
    #[serde(rename = "canUpload", default)]
    can_upload: bool,
    #[serde(rename = "canDelete", default)]
    can_delete: bool,
    #[serde(rename = "uploadQuotaBytes", default)]
    upload_quota_bytes: Option<i64>,
}

/// The `AddIncomingShare` response (keys alphabetical, matching Go's marshalled `fiber.Map`).
#[derive(Debug, Serialize, ToSchema)]
struct AddIncomingShareResponse {
    #[serde(rename = "canDelete")]
    can_delete: bool,
    #[serde(rename = "canUpload")]
    can_upload: bool,
    #[serde(rename = "encryptedCollectionKey")]
    encrypted_collection_key: String,
    #[serde(rename = "encryptedName")]
    encrypted_name: String,
    id: Uuid,
    #[serde(rename = "nameNonce")]
    name_nonce: String,
    #[serde(rename = "remoteServer")]
    remote_server: String,
    #[serde(rename = "uploadQuotaBytes")]
    upload_quota_bytes: Option<i64>,
}

/// `POST /api/fed-proxy/incoming` — mirrors `AddIncomingShare`. Parses the invite URL,
/// SSRF-validates the remote host, fetches the invite, and stores it.
#[utoipa::path(
    post,
    path = "/api/fed-proxy/incoming",
    tag = "federation",
    security(("BearerAuth" = [])),
    request_body = crate::models::AddIncomingShareRequest,
    responses((status = 201, description = "Incoming share accepted", body = AddIncomingShareResponse))
)]
pub async fn add_incoming_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AddIncomingShareRequest>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    if req.invite_url.is_empty() {
        return Err(AppError::bad_request("inviteUrl required"));
    }

    // Split {scheme}://{host}/invite/{token}.
    let Some(idx) = req.invite_url.find("/invite/") else {
        return Err(AppError::bad_request("invalid invite URL"));
    };
    let remote_server = &req.invite_url[..idx];
    let token = &req.invite_url[idx + "/invite/".len()..];
    if remote_server.is_empty() || token.is_empty() {
        return Err(AppError::bad_request("invalid invite URL"));
    }

    let allow_http = state.config.app_env != "production";
    if let Err(e) = ssrf::validate_federation_url(remote_server, allow_http).await {
        return Err(AppError::bad_request(format!("invalid server URL: {e}")));
    }

    let fetch_url = format!("{remote_server}/api/fed/invites/{token}");
    let resp = FED_CLIENT.get(&fetch_url).send().await;
    let invite: InviteData = match resp {
        Ok(r) if r.status().as_u16() == 200 => match r.json().await {
            Ok(d) => d,
            Err(_) => {
                return Err(AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "invalid invite data",
                ))
            }
        },
        _ => {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "failed to fetch invite from remote server",
            ))
        }
    };

    let share_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO federated_incoming_shares (user_id, remote_server, remote_access_token,
               encrypted_collection_key, encrypted_name, name_nonce,
               can_upload, can_delete, upload_quota_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (user_id, remote_server, remote_access_token) DO UPDATE
               SET encrypted_collection_key = EXCLUDED.encrypted_collection_key
           RETURNING id"#,
    )
    .bind(user_id)
    .bind(remote_server)
    .bind(token)
    .bind(&invite.wrapped_key)
    .bind(&invite.encrypted_name)
    .bind(&invite.name_nonce)
    .bind(invite.can_upload)
    .bind(invite.can_delete)
    .bind(invite.upload_quota_bytes)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    Ok((
        StatusCode::CREATED,
        Json(AddIncomingShareResponse {
            can_delete: invite.can_delete,
            can_upload: invite.can_upload,
            encrypted_collection_key: invite.wrapped_key,
            encrypted_name: invite.encrypted_name,
            id: share_id,
            name_nonce: invite.name_nonce,
            remote_server: remote_server.to_string(),
            upload_quota_bytes: invite.upload_quota_bytes,
        }),
    )
        .into_response())
}

/// An incoming federated share. Field order mirrors the Go struct.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct IncomingShare {
    id: Uuid,
    remote_server: String,
    encrypted_collection_key: String,
    encrypted_name: String,
    name_nonce: String,
    can_upload: bool,
    can_delete: bool,
    upload_quota_bytes: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

/// `GET /api/fed-proxy/incoming` — mirrors `ListIncomingShares`.
#[utoipa::path(
    get,
    path = "/api/fed-proxy/incoming",
    tag = "federation",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's incoming federated shares", body = Vec<IncomingShare>))
)]
pub async fn list_incoming_shares(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    type IncomingTuple = (
        Uuid,
        String,
        String,
        String,
        String,
        bool,
        bool,
        Option<i64>,
        OffsetDateTime,
    );
    let rows: Vec<IncomingTuple> = sqlx::query_as(
        r#"SELECT id, remote_server, encrypted_collection_key, encrypted_name, name_nonce,
                  can_upload, can_delete, upload_quota_bytes, created_at
           FROM federated_incoming_shares WHERE user_id = $1 ORDER BY created_at ASC"#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let shares: Vec<IncomingShare> = rows
        .into_iter()
        .map(|(id, rs, eck, en, nn, cu, cd, uq, created)| IncomingShare {
            id,
            remote_server: rs,
            encrypted_collection_key: eck,
            encrypted_name: en,
            name_nonce: nn,
            can_upload: cu,
            can_delete: cd,
            upload_quota_bytes: uq,
            created_at: created,
        })
        .collect();
    Ok(Json(shares).into_response())
}

/// `DELETE /api/fed-proxy/incoming/{shareId}` — mirrors `RemoveIncomingShare`.
#[utoipa::path(
    delete,
    path = "/api/fed-proxy/incoming/{shareId}",
    tag = "federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path, description = "Incoming-share id")),
    responses((status = 204, description = "Incoming share removed"))
)]
pub async fn remove_incoming_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    let sid = Uuid::parse_str(&share_id).map_err(|_| AppError::not_found("not found"))?;
    let res = sqlx::query("DELETE FROM federated_incoming_shares WHERE id = $1 AND user_id = $2")
        .bind(sid)
        .bind(user_id)
        .execute(&state.pool)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => Ok(StatusCode::NO_CONTENT.into_response()),
        _ => Err(AppError::not_found("not found")),
    }
}

/// Looks up the remote server + token for an incoming share — mirrors `getShare`.
async fn get_share(state: &AppState, share_id: &str, user_id: Uuid) -> Option<(String, String)> {
    let sid = Uuid::parse_str(share_id).ok()?;
    sqlx::query_as(
        "SELECT remote_server, remote_access_token FROM federated_incoming_shares WHERE id = $1 AND user_id = $2",
    )
    .bind(sid)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
}

/// `GET /api/fed-proxy/{shareId}/files` — mirrors `ProxyListFiles`.
#[utoipa::path(
    get,
    path = "/api/fed-proxy/{shareId}/files",
    tag = "federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path, description = "Incoming-share id")),
    responses((status = 200, description = "The remote share's file list, proxied verbatim (JSON)"))
)]
pub async fn proxy_list_files(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    let Some((remote, token)) = get_share(&state, &share_id, user_id).await else {
        return Err(AppError::not_found("share not found"));
    };
    let url = format!("{remote}/api/fed/shares/{token}/files");
    let resp = FED_CLIENT
        .get(&url)
        .send()
        .await
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "remote error"))?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.unwrap_or_default();
    Ok((status, [(header::CONTENT_TYPE, "application/json")], body).into_response())
}

/// `GET /api/fed-proxy/{shareId}/files/{fileId}/download` — mirrors `ProxyDownload`. Streams
/// the remote response body straight back to the caller.
#[utoipa::path(
    get,
    path = "/api/fed-proxy/{shareId}/files/{fileId}/download",
    tag = "federation",
    security(("BearerAuth" = [])),
    params(
        ("shareId" = String, Path, description = "Incoming-share id"),
        ("fileId" = String, Path, description = "Remote file id")
    ),
    responses((status = 200, description = "The encrypted blob streamed from the remote server (application/octet-stream)"))
)]
pub async fn proxy_download(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    let Some((remote, token)) = get_share(&state, &share_id, user_id).await else {
        return Err(AppError::not_found("share not found"));
    };
    let url = format!("{remote}/api/fed/shares/{token}/files/{file_id}/download");
    let resp = match FED_CLIENT.get(&url).send().await {
        Ok(r) if r.status().as_u16() == 200 => r,
        _ => return Err(AppError::new(StatusCode::BAD_GATEWAY, "remote error")),
    };
    let content_length = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut builder = Response::builder().header(header::CONTENT_TYPE, "application/octet-stream");
    if let Some(cl) = content_length {
        if let Ok(v) = HeaderValue::from_str(&cl) {
            builder = builder.header(header::CONTENT_LENGTH, v);
        }
    }
    let stream = resp.bytes_stream();
    Ok(builder
        .body(Body::from_stream(stream))
        .expect("valid proxy-download response"))
}

/// `POST /api/fed-proxy/{shareId}/upload` — mirrors `ProxyUpload`. Forwards the raw multipart
/// body (with its Content-Type) to the remote share.
#[utoipa::path(
    post,
    path = "/api/fed-proxy/{shareId}/upload",
    tag = "federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path, description = "Incoming-share id")),
    request_body(
        content = Vec<u8>,
        content_type = "multipart/form-data",
        description = "Raw multipart body forwarded verbatim to the remote share"
    ),
    responses((status = 201, description = "The remote upload result, proxied verbatim (JSON)"))
)]
pub async fn proxy_upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    let Some((remote, token)) = get_share(&state, &share_id, user_id).await else {
        return Err(AppError::not_found("share not found"));
    };
    let url = format!("{remote}/api/fed/shares/{token}/files");
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let resp = FED_CLIENT
        .post(&url)
        .header(header::CONTENT_TYPE, content_type)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "remote error"))?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let rbody = resp.bytes().await.unwrap_or_default();
    Ok((status, [(header::CONTENT_TYPE, "application/json")], rbody).into_response())
}

/// `DELETE /api/fed-proxy/{shareId}/files/{fileId}` — mirrors `ProxyDelete`.
#[utoipa::path(
    delete,
    path = "/api/fed-proxy/{shareId}/files/{fileId}",
    tag = "federation",
    security(("BearerAuth" = [])),
    params(
        ("shareId" = String, Path, description = "Incoming-share id"),
        ("fileId" = String, Path, description = "Remote file id")
    ),
    responses((status = 204, description = "Deleted on the remote server (status proxied)"))
)]
pub async fn proxy_delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;
    let Some((remote, token)) = get_share(&state, &share_id, user_id).await else {
        return Err(AppError::not_found("share not found"));
    };
    let url = format!("{remote}/api/fed/shares/{token}/files/{file_id}");
    let resp = FED_CLIENT
        .delete(&url)
        .send()
        .await
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "remote error"))?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    Ok(status.into_response())
}
