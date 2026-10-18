//! The groups route's HTTP side (docs/plans/pairwise-groups.md §3):
//! - a signed-in client fetches a home's gateway key config, with the home's
//!   identity history from the document its group pins;
//! - it relays sealed requests through its own server, which passes them to
//!   the home over signed federation, or to this server's own gateway;
//! - homes answer at the federated gateway.
//!
//! The relay forwards only to federation peers (the transport resolves and
//! admits them), only to the gateway path, with a body cap, and adds nothing
//! about the user. It keeps no record of what it passed.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::group_route::GroupGatewayKeyConfigV1;
use kutup_federation_proto::FederationFeature;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::gateway::{self, Opened};
use super::{keys, limits};
use crate::error::{AppError, AppResult};
use crate::federation::{FederationRequestSpec, FederationStack};
use crate::middleware::AuthUser;
use crate::AppState;

const GATEWAY_PATH: &str = "/api/fed/chat/groups/gateway";
const KEY_CONFIG_PATH: &str = "/api/fed/chat/groups/gateway-key";
const OCTET_STREAM: &str = "application/octet-stream";
const JSON: &str = "application/json";
/// The most identity documents one key-config answer carries.
const MAX_HISTORY: i64 = 64;
/// A sealed request or answer: the largest padded size plus RFC 9458's
/// header, X-Wing encapsulated key and tag (an answer is smaller).
pub(crate) const MAX_SEALED: usize = kutup_crypto::oblivious::MAX_SEALED;

/// The groups route exists only where groups are on and federation is set up.
fn enabled(state: &AppState) -> AppResult<&FederationStack> {
    if !state.config.chat_groups {
        return Err(AppError::not_found("not found"));
    }
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("not found"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayKeyQuery {
    pub server: String,
    /// The identity document the group pins; the history starts there.
    pub from_sequence: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayKeyAnswer {
    pub config: GroupGatewayKeyConfigV1,
    /// The home's identity documents from `fromSequence` on, for the client
    /// to follow from its pin; it trusts none of this without that check.
    pub identity_history: Vec<serde_json::Value>,
}

/// `GET /api/chat/groups/gateway-key?server=&fromSequence=`: a home's key
/// config and identity history, as this server got them.
#[utoipa::path(
    get,
    path = "/api/chat/groups/gateway-key",
    tag = "chat groups",
    security(("BearerAuth" = [])),
    params(
        ("server" = String, Query, description = "The group's home server"),
        ("fromSequence" = u64, Query, description = "The identity document the group pins"),
    ),
    responses(
        (status = 200, description = "`{config, identityHistory}`: the home's signed key config and its identity documents from the pin on"),
        (status = 404, description = "Groups are off"),
        (status = 502, description = "The home is unreachable or has no gateway"),
    )
)]
pub async fn gateway_key(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(query): Query<GatewayKeyQuery>,
) -> AppResult<Json<GatewayKeyAnswer>> {
    let federation = enabled(&state)?;
    let from = i64::try_from(query.from_sequence)
        .map_err(|_| AppError::bad_request("fromSequence is out of range"))?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if query.server == federation.server_name() {
        let identity = federation.local_identity();
        let config = keys::current_config(identity.document(), identity.signing_key(), now)?;
        let identity_history = sqlx::query_scalar(
            "SELECT document FROM federation_local_identity_documents
             WHERE sequence >= $1 ORDER BY sequence LIMIT $2",
        )
        .bind(from)
        .bind(MAX_HISTORY)
        .fetch_all(&state.pool)
        .await?;
        return Ok(Json(GatewayKeyAnswer {
            config,
            identity_history,
        }));
    }
    let remote = federation
        .send(
            &query.server,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path: KEY_CONFIG_PATH.into(),
                query: None,
                content_type: JSON.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 16 * 1024,
            },
        )
        .await
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "the group's server is unreachable"))?;
    if remote.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "the group's server has no gateway",
        ));
    }
    let config: GroupGatewayKeyConfigV1 = serde_json::from_slice(&remote.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "the gateway key config is invalid"))?;
    // The transport has recorded the peer's verified identity history.
    let identity_history = sqlx::query_scalar(
        "SELECT document FROM federation_peer_identity_documents
         WHERE domain = $1 AND sequence >= $2 AND acceptance IN ('accepted', 'superseded')
         ORDER BY sequence LIMIT $3",
    )
    .bind(&query.server)
    .bind(from)
    .bind(MAX_HISTORY)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(GatewayKeyAnswer {
        config,
        identity_history,
    }))
}

fn opaque(status: StatusCode, body: Vec<u8>) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, OCTET_STREAM),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

/// `POST /api/chat/groups/relay/{server}`: passes a sealed request to the home
/// `server` and its sealed answer back. The body is opaque to this server.
#[utoipa::path(
    post,
    path = "/api/chat/groups/relay/{server}",
    tag = "chat groups",
    security(("BearerAuth" = [])),
    params(("server" = String, Path, description = "The group's home server")),
    request_body(content = Vec<u8>, content_type = "message/ohttp-req", description = "A request sealed to the home's gateway key (RFC 9458)"),
    responses(
        (status = 200, description = "The sealed answer", content_type = "application/octet-stream"),
        (status = 400, description = "The home could not open the request (refetch its key config)"),
        (status = 404, description = "Groups are off"),
        (status = 429, description = "Too many relayed requests"),
        (status = 502, description = "The home is unreachable"),
    )
)]
pub async fn relay(
    State(state): State<AppState>,
    user: AuthUser,
    Path(server): Path<String>,
    body: Bytes,
) -> AppResult<Response> {
    let federation = enabled(&state)?;
    if body.is_empty() || body.len() > MAX_SEALED {
        return Err(AppError::bad_request("sealed request size is invalid"));
    }
    if !limits::relaying_user(&user.user_id) {
        return Err(AppError::too_many_requests("too many group requests"));
    }
    if server == federation.server_name() {
        return Ok(
            match gateway::handle(&state, federation, &server, &body).await? {
                Opened::Answer(answer) => opaque(StatusCode::OK, answer),
                Opened::Unopenable => opaque(StatusCode::BAD_REQUEST, Vec::new()),
            },
        );
    }
    let remote = federation
        .send(
            &server,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::POST,
                path: GATEWAY_PATH.into(),
                query: None,
                content_type: OCTET_STREAM.into(),
                body: body.to_vec(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_SEALED,
            },
        )
        .await
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "the group's server is unreachable"))?;
    Ok(match remote.status {
        StatusCode::OK => opaque(StatusCode::OK, remote.body),
        StatusCode::BAD_REQUEST => opaque(StatusCode::BAD_REQUEST, Vec::new()),
        _ => opaque(StatusCode::BAD_GATEWAY, Vec::new()),
    })
}

/// `POST /api/fed/chat/groups/gateway`: a peer relays a sealed request here.
#[utoipa::path(
    post,
    path = "/api/fed/chat/groups/gateway",
    tag = "chat federation",
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "A sealed group request, relayed"),
    responses(
        (status = 200, description = "The sealed answer (signed federation response)"),
        (status = 400, description = "Not sealed to a key of this gateway"),
        (status = 404, description = "Groups are off"),
    )
)]
pub async fn fed_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = enabled(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            GATEWAY_PATH,
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    if body.is_empty() || body.len() > MAX_SEALED {
        return federation.signed_response(
            &authenticated,
            StatusCode::BAD_REQUEST,
            OCTET_STREAM,
            Vec::new(),
        );
    }
    let relay = authenticated.origin().to_owned();
    match gateway::handle(&state, federation, &relay, &body).await? {
        Opened::Answer(answer) => {
            federation.signed_response(&authenticated, StatusCode::OK, OCTET_STREAM, answer)
        }
        Opened::Unopenable => federation.signed_response(
            &authenticated,
            StatusCode::BAD_REQUEST,
            OCTET_STREAM,
            Vec::new(),
        ),
    }
}

/// `GET /api/fed/chat/groups/gateway-key`: this home's key config, for a
/// peer's user. The config is signed by this server's identity.
#[utoipa::path(
    get,
    path = "/api/fed/chat/groups/gateway-key",
    tag = "chat federation",
    responses(
        (status = 200, description = "The gateway key config, signed by this server's identity"),
        (status = 404, description = "Groups are off"),
    )
)]
pub async fn fed_gateway_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = enabled(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            KEY_CONFIG_PATH,
            None,
            &[],
            FederationFeature::ChatV2,
        )
        .await?;
    let identity = federation.local_identity();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let config = keys::current_config(identity.document(), identity.signing_key(), now)?;
    let body = serde_json::to_vec(&config).map_err(|e| AppError::internal(e.to_string()))?;
    federation.signed_response(&authenticated, StatusCode::OK, JSON, body)
}
