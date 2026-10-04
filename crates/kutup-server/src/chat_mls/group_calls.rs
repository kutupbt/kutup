//! SFU access for group calls (docs/chat-calls.md).
//!
//! A group call's media goes through the LiveKit SFU of the server that
//! started it (its host), end-to-end encrypted with a key only the group's
//! members can derive. Joining takes a LiveKit access token for the call's
//! room, which the host mints. The room id (128 random bits, known only to
//! the group through MLS) is the capability. Accounts of other servers get
//! their token through their own server, which forwards the request over
//! signed federation. The participant identity is an opaque tag the members
//! can map to a person and the SFU cannot.

use std::sync::LazyLock;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{signed_federation_error, signed_federation_json};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;
use crate::AppState;

const FEDERATION_PATH: &str = "/api/fed/chat/group-calls/token";
/// How long a token admits its holder to the room.
const TOKEN_TTL_SECONDS: i64 = 6 * 60 * 60;

static ACCOUNT_TOKENS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(30, Duration::from_secs(60)));
static ORIGIN_TOKENS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(300, Duration::from_secs(60)));

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCallTokenRequest {
    /// The server hosting the call's SFU room.
    pub host: String,
    pub room_id: String,
    /// The joining device's opaque tag (32 lowercase hex characters).
    pub participant_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCallTokenResponse {
    /// The SFU's WebSocket URL.
    pub url: String,
    /// A LiveKit access token for the room.
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FederatedTokenRequest {
    room_id: String,
    participant_id: String,
}

fn validate_hex32(name: &str, value: &str) -> AppResult<()> {
    kutup_chat_proto::validate_room_id(value)
        .map_err(|_| AppError::bad_request(format!("{name} is 32 lowercase hex characters")))
}

/// Whether this server hosts group calls (an SFU is configured).
pub(crate) fn hosts_group_calls(state: &AppState) -> bool {
    let config = &state.config;
    !config.chat_sfu_url.is_empty()
        && !config.chat_sfu_api_key.is_empty()
        && !config.chat_sfu_api_secret.is_empty()
}

#[derive(Serialize)]
struct VideoGrant<'a> {
    room: &'a str,
    #[serde(rename = "roomJoin")]
    room_join: bool,
    #[serde(rename = "canPublish")]
    can_publish: bool,
    #[serde(rename = "canSubscribe")]
    can_subscribe: bool,
    #[serde(rename = "canPublishData")]
    can_publish_data: bool,
    /// The sources this participant may publish; absent means all of them.
    #[serde(rename = "canPublishSources", skip_serializing_if = "Option::is_none")]
    can_publish_sources: Option<&'a [&'a str]>,
}

/// What a token carries beyond the room and the identity.
#[derive(Default)]
pub(super) struct TokenExtras<'a> {
    /// An opaque value the SFU shows the other participants (a call link's
    /// sealed participant name).
    pub metadata: Option<&'a str>,
    /// The participant's name at the SFU. Only this server sets it, so the
    /// others can rely on it (a meeting's vouched-for account address).
    pub name: Option<&'a str>,
    /// The sources this participant may publish; `None` means all of them.
    pub publish_sources: Option<&'a [&'a str]>,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    nbf: i64,
    exp: i64,
    jti: String,
    /// Handed by the SFU to the room's other participants, unread.
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    video: VideoGrant<'a>,
}

/// A LiveKit access token (HS256 with the API secret) for one room.
/// `metadata` is an opaque value the SFU shows the other participants (a
/// call link's sealed participant name).
pub(super) fn livekit_token(
    api_key: &str,
    api_secret: &str,
    room_id: &str,
    participant_id: &str,
    metadata: Option<&str>,
    now: i64,
) -> AppResult<String> {
    livekit_token_with(
        api_key,
        api_secret,
        room_id,
        participant_id,
        &TokenExtras {
            metadata,
            ..TokenExtras::default()
        },
        now,
    )
}

/// A LiveKit access token for one room, with what `extras` adds to it.
pub(super) fn livekit_token_with(
    api_key: &str,
    api_secret: &str,
    room_id: &str,
    participant_id: &str,
    extras: &TokenExtras<'_>,
    now: i64,
) -> AppResult<String> {
    let claims = Claims {
        iss: api_key,
        sub: participant_id,
        nbf: now - 10,
        exp: now + TOKEN_TTL_SECONDS,
        jti: Uuid::new_v4().to_string(),
        metadata: extras.metadata,
        name: extras.name,
        video: VideoGrant {
            room: room_id,
            room_join: true,
            can_publish: true,
            can_subscribe: true,
            can_publish_data: true,
            can_publish_sources: extras.publish_sources,
        },
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(api_secret.as_bytes()),
    )
    .map_err(|error| AppError::internal(format!("sign SFU token: {error}")))
}

fn mint(
    state: &AppState,
    room_id: &str,
    participant_id: &str,
) -> AppResult<GroupCallTokenResponse> {
    if !hosts_group_calls(state) {
        return Err(AppError::not_found("this server does not host group calls"));
    }
    validate_hex32("roomId", room_id)?;
    validate_hex32("participantId", participant_id)?;
    let config = &state.config;
    Ok(GroupCallTokenResponse {
        url: config.chat_sfu_url.clone(),
        token: livekit_token(
            &config.chat_sfu_api_key,
            &config.chat_sfu_api_secret,
            room_id,
            participant_id,
            None,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )?,
    })
}

#[utoipa::path(
    post,
    path = "/api/chat/group-calls/token",
    tag = "chat",
    operation_id = "getChatGroupCallToken",
    request_body = GroupCallTokenRequest,
    responses(
        (status = 200, description = "An SFU token for the call's room", body = GroupCallTokenResponse),
        (status = 404, description = "The host does not host group calls"),
        (status = 429, description = "Too many requests"),
        (status = 502, description = "The host could not be reached"),
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn token(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<GroupCallTokenRequest>,
) -> AppResult<Json<GroupCallTokenResponse>> {
    if !ACCOUNT_TOKENS.allow(&auth.user_id) {
        return Err(AppError::too_many_requests("too many group call requests"));
    }
    validate_hex32("roomId", &request.room_id)?;
    validate_hex32("participantId", &request.participant_id)?;
    kutup_federation_proto::validate_server_name(&request.host)
        .map_err(|error| AppError::bad_request(format!("group call host: {error}")))?;
    let local = state
        .federation
        .as_ref()
        .map(|federation| federation.server_name().to_owned())
        .unwrap_or_else(|| state.config.chat_server_name.clone());
    if request.host == local {
        return Ok(Json(mint(
            &state,
            &request.room_id,
            &request.participant_id,
        )?));
    }
    let federation = state.federation.as_ref().ok_or_else(|| {
        AppError::not_found("federation is off: remote group calls are unavailable")
    })?;
    let body = serde_json::to_vec(&FederatedTokenRequest {
        room_id: request.room_id.clone(),
        participant_id: request.participant_id.clone(),
    })
    .map_err(|error| AppError::internal(format!("serialize group call request: {error}")))?;
    let response = federation
        .send(
            &request.host,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path: FEDERATION_PATH.into(),
                query: None,
                content_type: "application/json".into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 64 * 1024,
            },
        )
        .await
        .map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("the call's server could not be reached: {error}"),
            )
        })?;
    if response.status != StatusCode::OK {
        return Err(match response.status {
            StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS => {
                AppError::new(response.status, "the call's server refused the request")
            }
            status => AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("the call's server returned {status}"),
            ),
        });
    }
    let answer: GroupCallTokenResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "the call's server sent an invalid answer",
        )
    })?;
    if !(answer.url.starts_with("wss://") || answer.url.starts_with("ws://"))
        || answer.url.len() > 512
        || answer.token.is_empty()
        || answer.token.len() > 4096
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "the call's server sent an invalid answer",
        ));
    }
    Ok(Json(answer))
}

pub(crate) async fn federated_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            FEDERATION_PATH,
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    if authenticated.destination() != federation.server_name() {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::unauthorized("group call federation routing mismatch"),
        );
    }
    if !ORIGIN_TOKENS.allow(authenticated.origin()) {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::too_many_requests("too many group call requests"),
        );
    }
    let request: FederatedTokenRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid group call request"),
            )
        }
    };
    match mint(&state, &request.room_id, &request.participant_id) {
        Ok(answer) => signed_federation_json(federation, &authenticated, StatusCode::OK, &answer),
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_grant_one_room_to_one_participant() {
        let token = livekit_token(
            "APIkey",
            "a-secret-of-some-length-0123456789",
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
            None,
            1_700_000_000,
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.clear();
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"a-secret-of-some-length-0123456789"),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(decoded["iss"], "APIkey");
        assert_eq!(decoded["sub"], "fedcba9876543210fedcba9876543210");
        assert_eq!(decoded["exp"], 1_700_000_000 + TOKEN_TTL_SECONDS);
        assert_eq!(decoded["video"]["room"], "0123456789abcdef0123456789abcdef");
        assert_eq!(decoded["video"]["roomJoin"], true);
        assert!(decoded["video"].get("roomAdmin").is_none());
        assert!(decoded.get("metadata").is_none());
    }

    #[test]
    fn a_label_rides_in_the_token_as_metadata() {
        let token = livekit_token(
            "APIkey",
            "a-secret-of-some-length-0123456789",
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
            Some("c2VhbGVk"),
            1_700_000_000,
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.clear();
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"a-secret-of-some-length-0123456789"),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(decoded["metadata"], "c2VhbGVk");
        assert!(decoded["video"].get("roomAdmin").is_none());
    }
}
