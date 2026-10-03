//! Live-location streams (docs/plans/maps.md "Live location").
//!
//! A sharer's app creates a stream with a random id, a write secret and a
//! read capability, tells the conversation (end-to-end encrypted) how to read
//! it, and then writes each new position, sealed with a key only the
//! conversation has (`kutup_crypto::live_location`). This server keeps only
//! the latest update of each stream and deletes the stream when it ends. It
//! stores no account, conversation or position: only hashes of the two
//! secrets, the latest 88-byte update and the times. Readers on other servers
//! read through their own server over signed federation.

use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationRequestSpec, FederationStack};
use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;
use crate::AppState;

pub const WRITE_HEADER: &str = "x-kutup-live-write";
pub const READ_HEADER: &str = "x-kutup-live-read";
const JSON_CONTENT_TYPE: &str = "application/json";
/// A share lasts at most 8 hours; a little slack for clocks.
const MAX_LIFETIME: Duration = Duration::from_secs(8 * 3600 + 300);
/// Sharers send about every 15–30 s; faster writes are refused.
const MIN_WRITE_INTERVAL: Duration = Duration::from_secs(3);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// New streams per person: a share makes one per hour and one per leave.
static CREATE_LIMIT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(60, Duration::from_secs(3600)));
/// Reads per person across streams: one map open on a few shares.
static READ_LIMIT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(600, Duration::from_secs(60)));

fn limited() -> AppError {
    AppError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "too many live location requests",
    )
}

fn gone() -> AppError {
    AppError::not_found("live location not found")
}

fn stream_id_of(value: &str) -> AppResult<Vec<u8>> {
    hex::decode(value)
        .ok()
        .filter(|bytes| bytes.len() == 16 && hex::encode(bytes) == value)
        .ok_or_else(gone)
}

fn secret_of(value: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| bytes.len() == 32 && STANDARD.encode(bytes) == value)
}

fn hashed_secret(headers: &HeaderMap, name: &str) -> AppResult<Vec<u8>> {
    let secret = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(secret_of)
        .ok_or_else(gone)?;
    Ok(Sha256::digest(secret).to_vec())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateLiveLocationRequest {
    /// 16 random bytes, lowercase hex.
    pub stream_id: String,
    /// 32 random bytes (standard base64) the sharer's app keeps to write.
    pub write_secret: String,
    /// 32 random bytes (standard base64) readers present; they get it in the
    /// end-to-end encrypted share message.
    pub read_capability: String,
    /// When the stream ends, Unix milliseconds; within 8 hours.
    pub expires_at_ms: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteLiveLocationRequest {
    /// The sealed 88-byte update, standard base64.
    pub update: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveLocationResponse {
    /// The latest sealed update; null before the first.
    pub update: Option<String>,
    pub updated_at_ms: Option<i64>,
    pub expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct ReadQuery {
    /// The sharer's server, when it is another one.
    pub server: Option<String>,
}

fn millis(at: OffsetDateTime) -> i64 {
    (at.unix_timestamp_nanos() / 1_000_000) as i64
}

/// `POST /api/live-locations` — open a stream.
#[utoipa::path(
    post,
    path = "/api/live-locations",
    tag = "chat",
    security(("BearerAuth" = [])),
    request_body = CreateLiveLocationRequest,
    responses(
        (status = 201, description = "Created"),
        (status = 409, description = "That stream id is taken"),
        (status = 429, description = "Too many new streams")
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateLiveLocationRequest>,
) -> AppResult<Response> {
    if !CREATE_LIMIT.allow(&user.user_id) {
        return Err(limited());
    }
    let stream_id = stream_id_of(&request.stream_id)
        .map_err(|_| AppError::bad_request("invalid live location stream id"))?;
    let (Some(write), Some(read)) = (
        secret_of(&request.write_secret),
        secret_of(&request.read_capability),
    ) else {
        return Err(AppError::bad_request("invalid live location secret"));
    };
    let now = OffsetDateTime::now_utc();
    let expires_at =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(request.expires_at_ms) * 1_000_000)
            .map_err(|_| AppError::bad_request("invalid live location end"))?;
    if expires_at <= now || expires_at > now + MAX_LIFETIME {
        return Err(AppError::bad_request(
            "a live location lasts at most 8 hours",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO live_location_streams (stream_id, write_verifier, read_verifier, expires_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (stream_id) DO NOTHING",
    )
    .bind(&stream_id)
    .bind(Sha256::digest(write).to_vec())
    .bind(Sha256::digest(read).to_vec())
    .bind(expires_at)
    .execute(&state.pool)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(AppError::conflict("that live location stream exists"));
    }
    Ok(StatusCode::CREATED.into_response())
}

/// `PUT /api/live-locations/{streamId}` — replace the latest update. Needs
/// the write secret (`x-kutup-live-write`) and a counter above the stored one.
#[utoipa::path(
    put,
    path = "/api/live-locations/{streamId}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(("streamId" = String, Path)),
    request_body = WriteLiveLocationRequest,
    responses(
        (status = 204, description = "Stored"),
        (status = 404, description = "No such stream, wrong secret, or ended"),
        (status = 409, description = "Not newer than the stored update"),
        (status = 429, description = "Written too recently")
    )
)]
pub async fn write(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(stream_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<WriteLiveLocationRequest>,
) -> AppResult<Response> {
    let stream_id = stream_id_of(&stream_id)?;
    let verifier = hashed_secret(&headers, WRITE_HEADER)?;
    let update = STANDARD
        .decode(&request.update)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == request.update)
        .ok_or_else(|| AppError::bad_request("invalid live location update"))?;
    let counter = kutup_crypto::live_location::counter_of(&update)
        .map_err(|_| AppError::bad_request("invalid live location update"))?;
    let counter = i64::try_from(counter)
        .map_err(|_| AppError::bad_request("invalid live location update"))?;

    let mut tx = state.pool.begin().await?;
    let row: Option<(Vec<u8>, i64, Option<OffsetDateTime>, OffsetDateTime)> = sqlx::query_as(
        "SELECT write_verifier, counter, updated_at, expires_at FROM live_location_streams
         WHERE stream_id = $1 FOR UPDATE",
    )
    .bind(&stream_id)
    .fetch_optional(&mut *tx)
    .await?;
    let now = OffsetDateTime::now_utc();
    let Some((stored, stored_counter, updated_at, expires_at)) = row else {
        return Err(gone());
    };
    if !constant_time_eq(&stored, &verifier) || expires_at <= now {
        return Err(gone());
    }
    if counter <= stored_counter {
        return Err(AppError::conflict(
            "not newer than the stored live location",
        ));
    }
    if updated_at.is_some_and(|at| now - at < MIN_WRITE_INTERVAL) {
        return Err(limited());
    }
    sqlx::query(
        "UPDATE live_location_streams SET update_bytes = $2, counter = $3, updated_at = $4
         WHERE stream_id = $1",
    )
    .bind(&stream_id)
    .bind(&update)
    .bind(counter)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/live-locations/{streamId}` — end a stream now (write secret).
#[utoipa::path(
    delete,
    path = "/api/live-locations/{streamId}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(("streamId" = String, Path)),
    responses((status = 204, description = "Ended"), (status = 404, description = "No such stream or wrong secret"))
)]
pub async fn delete(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(stream_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let stream_id = stream_id_of(&stream_id)?;
    let verifier = hashed_secret(&headers, WRITE_HEADER)?;
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT write_verifier FROM live_location_streams WHERE stream_id = $1")
            .bind(&stream_id)
            .fetch_optional(&state.pool)
            .await?;
    if !stored.is_some_and(|stored| constant_time_eq(&stored, &verifier)) {
        return Err(gone());
    }
    sqlx::query("DELETE FROM live_location_streams WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Read verifier, latest update, when it was written, when the stream ends.
type StreamRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<OffsetDateTime>,
    OffsetDateTime,
);

async fn read_local(
    pool: &PgPool,
    stream_id: &[u8],
    verifier: &[u8],
) -> AppResult<LiveLocationResponse> {
    let row: Option<StreamRow> = sqlx::query_as(
        "SELECT read_verifier, update_bytes, updated_at, expires_at FROM live_location_streams
         WHERE stream_id = $1",
    )
    .bind(stream_id)
    .fetch_optional(pool)
    .await?;
    let Some((stored, update, updated_at, expires_at)) = row else {
        return Err(gone());
    };
    if !constant_time_eq(&stored, verifier) || expires_at <= OffsetDateTime::now_utc() {
        return Err(gone());
    }
    Ok(LiveLocationResponse {
        update: update.map(|bytes| STANDARD.encode(bytes)),
        updated_at_ms: updated_at.map(millis),
        expires_at_ms: millis(expires_at),
    })
}

/// `GET /api/live-locations/{streamId}[?server=]` — the latest update, with
/// the read capability (`x-kutup-live-read`). A stream on another server is
/// read through this one over signed federation.
#[utoipa::path(
    get,
    path = "/api/live-locations/{streamId}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(
        ("streamId" = String, Path),
        ("server" = Option<String>, Query, description = "The sharer's server, when another one")
    ),
    responses(
        (status = 200, description = "The latest update", body = LiveLocationResponse),
        (status = 404, description = "No such stream, wrong capability, or ended")
    )
)]
pub async fn read(
    State(state): State<AppState>,
    user: AuthUser,
    Path(stream_id): Path<String>,
    Query(query): Query<ReadQuery>,
    headers: HeaderMap,
) -> AppResult<Json<LiveLocationResponse>> {
    if !READ_LIMIT.allow(&user.user_id) {
        return Err(limited());
    }
    let stream = stream_id_of(&stream_id)?;
    let local = state.config.chat_server_name.as_str();
    match query.server.as_deref() {
        None => {}
        Some(server) if server == local => {}
        Some(server) => {
            let capability = headers
                .get(READ_HEADER)
                .and_then(|value| value.to_str().ok())
                .filter(|value| secret_of(value).is_some())
                .ok_or_else(gone)?;
            return fetch_remote(&state, server, &stream_id, capability)
                .await
                .map(Json);
        }
    }
    let verifier = hashed_secret(&headers, READ_HEADER)?;
    read_local(&state.pool, &stream, &verifier).await.map(Json)
}

fn stack(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("live location not found"))
}

async fn fetch_remote(
    state: &AppState,
    server: &str,
    stream_id: &str,
    capability: &str,
) -> AppResult<LiveLocationResponse> {
    kutup_federation_proto::validate_server_name(server).map_err(|_| gone())?;
    let federation = stack(state)?;
    let response = federation
        .send(
            server,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::GET,
                path: format!("/api/fed/chat/live-locations/{stream_id}"),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: vec![(
                    HeaderName::from_static(READ_HEADER),
                    HeaderValue::from_str(capability).map_err(|_| gone())?,
                )],
                response_limit: 4 * 1024,
            },
        )
        .await
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, format!("federation: {error}")))?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(gone());
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("their server answered {}", response.status),
        ));
    }
    let body: LiveLocationResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "invalid live location from their server",
        )
    })?;
    if body.update.as_deref().is_some_and(|update| {
        STANDARD.decode(update).map_or(true, |bytes| {
            bytes.len() != kutup_crypto::live_location::ENVELOPE_LEN
        })
    }) {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "invalid live location from their server",
        ));
    }
    Ok(body)
}

fn signed(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    result: AppResult<LiveLocationResponse>,
) -> AppResult<Response> {
    let (status, body) = match result {
        Ok(body) => (StatusCode::OK, serde_json::to_vec(&body)),
        Err(error) => (
            error.status,
            serde_json::to_vec(&serde_json::json!({ "error": error.message })),
        ),
    };
    let body =
        body.map_err(|error| AppError::internal(format!("serialize live location: {error}")))?;
    federation.signed_response(authenticated, status, JSON_CONTENT_TYPE, body)
}

/// Signed server-to-server read of a stream hosted here, for a reader on the
/// calling server. The read capability is a separate bearer secret; the
/// federation signature authenticates the calling server.
#[utoipa::path(
    get,
    path = "/api/fed/chat/live-locations/{streamId}",
    tag = "chat federation",
    params(("streamId" = String, Path)),
    responses(
        (status = 200, description = "The latest update", body = LiveLocationResponse),
        (status = 401, description = "Invalid federation request signature"),
        (status = 404, description = "No such stream, wrong capability, or ended")
    )
)]
pub async fn federated_read(
    State(state): State<AppState>,
    Path(stream_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = stack(&state)?;
    let uri = format!("/api/fed/chat/live-locations/{stream_id}");
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &uri, None, &[], FederationFeature::ChatV1)
        .await?;
    let result = async {
        let stream = stream_id_of(&stream_id)?;
        let verifier = hashed_secret(&headers, READ_HEADER)?;
        read_local(&state.pool, &stream, &verifier).await
    }
    .await;
    signed(federation, &authenticated, result)
}

/// Delete ended streams once a minute.
pub fn spawn_sweeper(pool: PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            if let Err(error) =
                sqlx::query("DELETE FROM live_location_streams WHERE expires_at <= now()")
                    .execute(&pool)
                    .await
            {
                tracing::warn!(%error, "live location sweep failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_ids_and_secrets_are_canonical() {
        assert!(stream_id_of("6465666768696a6b6c6d6e6f70717273").is_ok());
        assert!(stream_id_of("6465666768696A6B6C6D6E6F70717273").is_err());
        assert!(stream_id_of("6465").is_err());
        assert!(secret_of("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").is_some());
        assert!(secret_of("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").is_none());
        assert!(secret_of("AAEC").is_none());
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
