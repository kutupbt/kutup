//! Session endpoints: sign-out, the session list, session forking and the web
//! apps' local keys. Design: `docs/plans/multi-app-web-rewrite.md`.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::header::{ORIGIN, SET_COOKIE};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::auth::{clear_refresh_cookie, client_header, refresh_cookie, user_agent};
use crate::middleware::AuthUser;
use crate::models::OkResponse;
use crate::sessions::{self, ClientType};
use crate::{jwt, AppState};

fn user_uuid(user: &AuthUser) -> AppResult<Uuid> {
    Uuid::parse_str(&user.user_id).map_err(|_| AppError::unauthorized("unauthorized"))
}

/// `POST /api/auth/logout` — ends the whole sign-in the caller belongs to: the
/// account. (or CLI) session and every session forked from it. Other apps find out on
/// their next request (401) and go back through the account app.
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Signed out", body = OkResponse))
)]
pub async fn logout(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    sessions::sign_out(&state.pool, user.session.session_id).await?;
    let body = Json(OkResponse { ok: true });
    if user.session.client.uses_cookie() {
        Ok(([(SET_COOKIE, clear_refresh_cookie(&state))], body).into_response())
    } else {
        Ok(body.into_response())
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    id: String,
    client_type: String,
    /// The sign-in this session was forked from (drive/chat under account).
    parent_id: Option<String>,
    user_agent: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    last_used_at: time::OffsetDateTime,
    /// Part of the caller's own sign-in (this session, its parent or a sibling).
    current: bool,
}

/// `GET /api/auth/sessions` — the caller's live sessions, most recently used first.
#[utoipa::path(
    get,
    path = "/api/auth/sessions",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Live sessions", body = [SessionView]))
)]
pub async fn list_sessions(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let rows = sessions::list(&state.pool, user_uuid(&user)?).await?;
    let own = user.session.session_id;
    let own_root = rows
        .iter()
        .find(|r| r.id == own)
        .and_then(|r| r.parent_session_id)
        .unwrap_or(own);
    let views: Vec<SessionView> = rows
        .into_iter()
        .map(|r| SessionView {
            current: r.id == own_root || r.parent_session_id == Some(own_root),
            id: r.id.to_string(),
            client_type: r.client_type,
            parent_id: r.parent_session_id.map(|p| p.to_string()),
            user_agent: r.user_agent,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        })
        .collect();
    Ok(Json(views).into_response())
}

/// `DELETE /api/auth/sessions/{id}` — revoke one of the caller's sessions and anything
/// forked from it.
#[utoipa::path(
    delete,
    path = "/api/auth/sessions/{id}",
    tag = "sessions",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Session id")),
    responses((status = 200, description = "Revoked", body = OkResponse), (status = 404, description = "No such session"))
)]
pub async fn revoke_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("session not found"))?;
    if !sessions::revoke_owned(&state.pool, user_uuid(&user)?, id).await? {
        return Err(AppError::not_found("session not found"));
    }
    Ok(Json(OkResponse { ok: true }).into_response())
}

/// `DELETE /api/auth/sessions` — sign out everywhere else: revoke every session except
/// the caller's own sign-in.
#[utoipa::path(
    delete,
    path = "/api/auth/sessions",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Other sessions revoked", body = OkResponse))
)]
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    sessions::revoke_all_for_user(
        &state.pool,
        user_uuid(&user)?,
        Some(user.session.session_id),
    )
    .await?;
    Ok(Json(OkResponse { ok: true }).into_response())
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateForkRequest {
    /// `web-drive` or `web-chat`.
    child_client_type: String,
    /// Canonical base64 of a `SessionFork` local-state envelope. Opaque to the server.
    payload: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateForkResponse {
    /// One-time, 60-second selector; goes in the child URL's fragment.
    selector: String,
    /// The exact origin the child must consume the fork from.
    child_origin: String,
}

/// `POST /api/auth/forks` — the account app hands a child app (drive, chat) a session.
#[utoipa::path(
    post,
    path = "/api/auth/forks",
    tag = "sessions",
    security(("BearerAuth" = [])),
    request_body = CreateForkRequest,
    responses((status = 200, description = "Fork created", body = CreateForkResponse))
)]
pub async fn create_fork(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<CreateForkRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let child = ClientType::parse(&req.child_client_type)
        .filter(|c| c.is_fork_child())
        .ok_or_else(|| AppError::bad_request("unknown child client type"))?;
    let payload = STANDARD
        .decode(&req.payload)
        .ok()
        .filter(|p| STANDARD.encode(p) == req.payload)
        .ok_or_else(|| AppError::bad_request("payload must be canonical base64"))?;
    let selector = sessions::create_fork(&state.pool, &user.session, child, &payload).await?;
    let child_origin = state
        .config
        .apps
        .for_client(child)
        .expect("fork children have an origin")
        .to_string();
    Ok(Json(CreateForkResponse {
        selector,
        child_origin,
    })
    .into_response())
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ConsumeForkRequest {
    selector: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumeForkResponse {
    access_token: String,
    session_id: String,
    user_id: String,
    /// The `SessionFork` envelope, canonical base64; the key is in the child's URL fragment.
    payload: String,
}

/// `POST /api/auth/forks/consume` — the child app (on its own origin) turns a fork into
/// its own session. Single use; the `X-Kutup-Client` type must be the one the fork was
/// minted for, and the request `Origin` must be that app's configured origin, so a fork
/// cannot be redeemed from anywhere else. The refresh cookie is set on this origin.
#[utoipa::path(
    post,
    path = "/api/auth/forks/consume",
    tag = "sessions",
    request_body = ConsumeForkRequest,
    responses((status = 200, description = "Child session created", body = ConsumeForkResponse), (status = 401, description = "Invalid, used or expired fork"))
)]
pub async fn consume_fork(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<ConsumeForkRequest>, JsonRejection>,
) -> AppResult<Response> {
    let child = client_header(&headers)
        .filter(|c| c.is_fork_child())
        .ok_or_else(|| AppError::bad_request("missing or invalid X-Kutup-Client header"))?;
    let expected_origin = state
        .config
        .apps
        .for_client(child)
        .expect("fork child origin");
    let origin = headers.get(ORIGIN).and_then(|v| v.to_str().ok());
    if origin != Some(expected_origin) {
        return Err(AppError::forbidden(
            "fork must be consumed from its own app",
        ));
    }
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let consumed =
        sessions::consume_fork(&state.pool, &req.selector, child, user_agent(&headers)).await?;
    let access = jwt::generate_access_token(
        &consumed.user_id.to_string(),
        consumed.is_admin,
        &consumed.issued.session_id.to_string(),
        &state.config.jwt_secret,
    )
    .map_err(|_| AppError::internal("token"))?;
    let body = ConsumeForkResponse {
        access_token: access,
        session_id: consumed.issued.session_id.to_string(),
        user_id: consumed.user_id.to_string(),
        payload: STANDARD.encode(&consumed.payload),
    };
    Ok((
        [(
            SET_COOKIE,
            refresh_cookie(&state, &consumed.issued.refresh_token),
        )],
        Json(body),
    )
        .into_response())
}

#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct LocalKeyBody {
    /// Canonical base64 of 32 random bytes.
    key: String,
}

/// `PUT /api/auth/sessions/current/local-key` — store the key that unlocks this web
/// session's persisted key blob. The blob stays in the browser; the key stays here,
/// released only to this live session, so neither is useful alone.
#[utoipa::path(
    put,
    path = "/api/auth/sessions/current/local-key",
    tag = "sessions",
    security(("BearerAuth" = [])),
    request_body = LocalKeyBody,
    responses((status = 200, description = "Stored", body = OkResponse))
)]
pub async fn put_local_key(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<LocalKeyBody>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let key = STANDARD
        .decode(&req.key)
        .ok()
        .filter(|k| STANDARD.encode(k) == req.key)
        .ok_or_else(|| AppError::bad_request("key must be canonical base64"))?;
    sessions::set_local_key(&state.pool, &user.session, &key).await?;
    Ok(Json(OkResponse { ok: true }).into_response())
}

/// `GET /api/auth/sessions/current/local-key`
#[utoipa::path(
    get,
    path = "/api/auth/sessions/current/local-key",
    tag = "sessions",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The session's local key", body = LocalKeyBody), (status = 404, description = "None stored"))
)]
pub async fn get_local_key(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let key = sessions::local_key(&state.pool, &user.session)
        .await?
        .ok_or_else(|| AppError::not_found("no local key"))?;
    Ok(Json(LocalKeyBody {
        key: STANDARD.encode(key),
    })
    .into_response())
}
