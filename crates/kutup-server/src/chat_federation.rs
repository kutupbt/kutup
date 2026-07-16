//! Authenticated, transport-only chat federation.
//!
//! This module owns server identity, `.well-known` discovery, request signing,
//! the remote device-directory boundary, and durable in-order ciphertext
//! delivery. Federation is advertised only when a persistent signing identity
//! is configured.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_chat_proto::{
    AccountAddress, ChatWsServerMessage, DeliveredEnvelope, DeviceListMismatch,
    FederatedChatTransaction, FederationAuthorization, FederationDeliveryError,
    FederationDeliveryRejection, FederationDeliveryResponse, FederationDiscovery,
    FederationRequest, FederationSigningKey, SendMessagesRequest, UserPreKeyBundlesResponse,
    FEDERATION_VERSION,
};
use rand::Rng as _;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::chat_hub::ChatWsOut;
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::handlers::FED_CLIENT;
use crate::{ssrf, AppState};

const MAX_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEDERATION_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum FederatedSendOutcome {
    Delivered { deduplicated: bool },
    Mismatch(DeviceListMismatch),
    Rejected(FederationDeliveryRejection),
    Pending,
}

#[derive(Debug, sqlx::FromRow)]
struct FederationOutboxRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    recipient: String,
    sender: String,
    request: Value,
    state: String,
    response: Option<Value>,
    attempts: i32,
}

pub struct ChatFederation {
    server_name: String,
    api_base: String,
    signing_key: SigningKey,
    allow_http: bool,
    allow_private_test_network: bool,
}

impl ChatFederation {
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        if config.chat_federation_test_allow_private && config.app_env != "test" {
            anyhow::bail!(
                "CHAT_FEDERATION_TEST_ALLOW_PRIVATE may only be enabled with APP_ENV=test"
            );
        }
        if config.chat_federation_signing_key.is_empty() {
            return Ok(None);
        }

        let api_base = normalize_api_base(&config.server_url)?;
        if config.app_env == "production" && Url::parse(&api_base)?.scheme() != "https" {
            anyhow::bail!("chat federation requires an HTTPS SERVER_URL in production");
        }
        let server_name = if config.chat_federation_server_name.is_empty() {
            Url::parse(&api_base)?
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("SERVER_URL has no host"))?
                .to_ascii_lowercase()
        } else {
            config.chat_federation_server_name.to_ascii_lowercase()
        };
        let canonical = AccountAddress::federated("server", &server_name)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if canonical.server.as_deref() != Some(server_name.as_str()) {
            anyhow::bail!("CHAT_FEDERATION_SERVER_NAME must be canonical lowercase DNS");
        }

        let seed = STANDARD
            .decode(&config.chat_federation_signing_key)
            .map_err(|_| anyhow::anyhow!("CHAT_FEDERATION_SIGNING_KEY must be base64"))?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            anyhow::anyhow!("CHAT_FEDERATION_SIGNING_KEY must decode to exactly 32 bytes")
        })?;

        Ok(Some(Self {
            server_name,
            api_base,
            signing_key: SigningKey::from_bytes(&seed),
            allow_http: config.app_env != "production",
            allow_private_test_network: config.chat_federation_test_allow_private,
        }))
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn discovery_document(&self) -> FederationDiscovery {
        let public = self.signing_key.verifying_key();
        FederationDiscovery {
            fed_version: FEDERATION_VERSION,
            server: self.server_name.clone(),
            api_base: self.api_base.clone(),
            signing_keys: vec![FederationSigningKey {
                key_id: kutup_chat_proto::server_key_id(public.as_bytes()),
                public_key: STANDARD.encode(public.as_bytes()),
            }],
        }
    }

    async fn discover_remote(&self, destination: &str) -> AppResult<FederationDiscovery> {
        let canonical = AccountAddress::federated("server", destination)
            .map_err(|error| AppError::bad_request(error.to_string()))?;
        if canonical.server.as_deref() != Some(destination) {
            return Err(AppError::bad_request(
                "federation destination must be canonical lowercase DNS",
            ));
        }

        let scheme = if self.allow_http { "http" } else { "https" };
        let discovery_url = format!("{scheme}://{destination}/.well-known/kutup/federation.json");
        ssrf::validate_chat_federation_url(
            &discovery_url,
            self.allow_http,
            self.allow_private_test_network,
        )
        .await
        .map_err(|error| AppError::bad_request(format!("invalid federation server: {error}")))?;
        let response = FED_CLIENT
            .get(&discovery_url)
            .send()
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "federation discovery failed",
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if bytes.len() > MAX_DIRECTORY_RESPONSE_BYTES {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "federation discovery response is too large",
            ));
        }
        let discovery: FederationDiscovery = serde_json::from_slice(&bytes).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "invalid federation discovery response",
            )
        })?;
        if discovery.fed_version != FEDERATION_VERSION || discovery.server != destination {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "federation discovery identity/version mismatch",
            ));
        }
        validate_discovery_keys(&discovery)?;
        ssrf::validate_chat_federation_url(
            &discovery.api_base,
            self.allow_http,
            self.allow_private_test_network,
        )
        .await
        .map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("invalid discovered federation API: {error}"),
            )
        })?;
        normalize_api_base(&discovery.api_base).map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("invalid discovered federation API: {error}"),
            )
        })?;
        Ok(discovery)
    }

    pub async fn fetch_remote_bundles(
        &self,
        address: &AccountAddress,
    ) -> AppResult<UserPreKeyBundlesResponse> {
        let destination = address
            .server
            .as_deref()
            .ok_or_else(|| AppError::bad_request("remote account requires a server"))?;
        let discovery = self.discover_remote(destination).await?;
        let uri = format!("/api/fed/chat/users/{}/keys", address.username);
        let authorization = FederationAuthorization::sign(
            self.server_name.clone(),
            destination.to_string(),
            OffsetDateTime::now_utc().unix_timestamp(),
            uuid::Uuid::new_v4().to_string(),
            FederationRequest {
                method: "GET",
                uri: &uri,
                body: &[],
            },
            &self.signing_key,
        )
        .map_err(AppError::internal)?
        .to_header_value()
        .map_err(AppError::internal)?;
        let url = format!("{}{}", discovery.api_base.trim_end_matches('/'), uri);
        let response = FED_CLIENT
            .get(url)
            .header(AUTHORIZATION.as_str(), authorization)
            .send()
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::not_found("remote chat user not found"));
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("remote chat directory returned {}", response.status()),
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if bytes.len() > MAX_DIRECTORY_RESPONSE_BYTES {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote chat directory response is too large",
            ));
        }
        let bundles: UserPreKeyBundlesResponse = serde_json::from_slice(&bytes).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "invalid remote chat directory response",
            )
        })?;
        if bundles.username != address.canonical() {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote chat directory returned the wrong account",
            ));
        }
        Ok(bundles)
    }

    /// Persist a remote send before attempting network I/O. A transient remote
    /// failure is returned to the client so its own durable outbox remains, but
    /// the server queue can make progress independently in the meantime.
    pub async fn enqueue_send(
        &self,
        state: &AppState,
        sender_user_id: Uuid,
        recipient: &AccountAddress,
        request: SendMessagesRequest,
    ) -> AppResult<FederatedSendOutcome> {
        crate::handlers::chat::validate_send_request(&request, false, None)?;
        let destination = recipient
            .server
            .as_deref()
            .ok_or_else(|| AppError::bad_request("federated recipient requires a server"))?;
        if destination == self.server_name {
            return Err(AppError::bad_request(
                "local recipients must use local mailbox delivery",
            ));
        }
        let request_value = serde_json::to_value(&request)
            .map_err(|error| AppError::internal(format!("serialize chat send: {error}")))?;

        let mut tx = state.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR SHARE")
            .bind(sender_user_id)
            .execute(&mut *tx)
            .await?;
        let sender_username: Option<String> = sqlx::query_scalar(
            "UPDATE chat_devices d SET last_seen_at = now()
             FROM users u
             WHERE d.user_id = $1 AND d.device_id = $2 AND u.id = d.user_id
             RETURNING COALESCE(u.username, '')",
        )
        .bind(sender_user_id)
        .bind(request.sender_device_id as i32)
        .fetch_optional(&mut *tx)
        .await?;
        let sender_username =
            sender_username.ok_or_else(|| AppError::not_found("no such chat device"))?;

        let existing: Option<(Uuid, String, Value, Option<Value>, String, String)> =
            sqlx::query_as(
                "SELECT id, state, request, response, destination, recipient
                 FROM chat_federation_outbox
                 WHERE sender_user_id = $1 AND sender_device_id = $2 AND send_id = $3
                 FOR UPDATE",
            )
            .bind(sender_user_id)
            .bind(request.sender_device_id as i32)
            .bind(&request.send_id)
            .fetch_optional(&mut *tx)
            .await?;

        let id = if let Some((
            id,
            outbox_state,
            prior_request,
            response,
            prior_destination,
            prior_recipient,
        )) = existing
        {
            if prior_destination != destination || prior_recipient != recipient.canonical() {
                return Err(AppError::conflict(
                    "sendId is already bound to another federated recipient",
                ));
            }
            match outbox_state.as_str() {
                "delivered" => {
                    tx.rollback().await?;
                    return delivered_outcome(response, true);
                }
                "mismatch" if prior_request == request_value => {
                    tx.rollback().await?;
                    let mismatch = response
                        .and_then(|value| {
                            serde_json::from_value::<FederationDeliveryError>(value).ok()
                        })
                        .and_then(|error| match error {
                            FederationDeliveryError::DeviceListMismatch { mismatch } => {
                                Some(mismatch)
                            }
                            FederationDeliveryError::SequenceGap { .. } => None,
                        })
                        .ok_or_else(|| {
                            AppError::internal("stored federation mismatch is invalid")
                        })?;
                    return Ok(FederatedSendOutcome::Mismatch(mismatch));
                }
                "mismatch" => {
                    sqlx::query(
                        "UPDATE chat_federation_outbox
                         SET request = $2, state = 'pending', response = NULL,
                             attempts = 0, next_attempt_at = now(), last_error = NULL,
                             updated_at = now()
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(&request_value)
                    .execute(&mut *tx)
                    .await?;
                }
                "pending" if prior_request != request_value => {
                    return Err(AppError::conflict(
                        "federated send payload changed before a device mismatch",
                    ));
                }
                "pending" => {}
                _ => return Err(AppError::internal("invalid federation outbox state")),
            }
            id
        } else {
            let sequence: i64 = sqlx::query_scalar(
                "INSERT INTO chat_federation_sequences (destination, next_sequence)
                 VALUES ($1, 2)
                 ON CONFLICT (destination) DO UPDATE SET
                     next_sequence = chat_federation_sequences.next_sequence + 1
                 RETURNING next_sequence - 1",
            )
            .bind(destination)
            .fetch_one(&mut *tx)
            .await?;
            let id = Uuid::new_v4();
            let sender = format!("{sender_username}@{}", self.server_name);
            sqlx::query(
                "INSERT INTO chat_federation_outbox
                    (id, destination, sequence, sender_user_id, sender_device_id,
                     send_id, recipient, sender, request)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(id)
            .bind(destination)
            .bind(sequence)
            .bind(sender_user_id)
            .bind(request.sender_device_id as i32)
            .bind(&request.send_id)
            .bind(recipient.canonical())
            .bind(sender)
            .bind(&request_value)
            .execute(&mut *tx)
            .await?;
            id
        };
        tx.commit().await?;
        self.attempt_outbox(state, id).await
    }

    async fn attempt_outbox(&self, state: &AppState, id: Uuid) -> AppResult<FederatedSendOutcome> {
        let row = load_outbox(state, id)
            .await?
            .ok_or_else(|| AppError::internal("federation outbox row disappeared"))?;
        match row.state.as_str() {
            "delivered" => return delivered_outcome(row.response, true),
            "mismatch" => {
                let mismatch = row
                    .response
                    .and_then(|value| serde_json::from_value::<FederationDeliveryError>(value).ok())
                    .and_then(|error| match error {
                        FederationDeliveryError::DeviceListMismatch { mismatch } => Some(mismatch),
                        FederationDeliveryError::SequenceGap { .. } => None,
                    })
                    .ok_or_else(|| AppError::internal("stored federation mismatch is invalid"))?;
                return Ok(FederatedSendOutcome::Mismatch(mismatch));
            }
            "pending" => {}
            _ => return Err(AppError::internal("invalid federation outbox state")),
        }

        let head: Option<i64> = sqlx::query_scalar(
            "SELECT MIN(sequence) FROM chat_federation_outbox
             WHERE destination = $1 AND state <> 'delivered'",
        )
        .bind(&row.destination)
        .fetch_one(&state.pool)
        .await?;
        if head != Some(row.sequence) {
            return Ok(FederatedSendOutcome::Pending);
        }

        let message: SendMessagesRequest = serde_json::from_value(row.request.clone())
            .map_err(|error| AppError::internal(format!("invalid federation outbox: {error}")))?;
        let sequence = u64::try_from(row.sequence)
            .map_err(|_| AppError::internal("invalid federation sequence"))?;
        let transaction = FederatedChatTransaction {
            fed_version: FEDERATION_VERSION,
            transaction_id: row.id.to_string(),
            sequence,
            origin: self.server_name.clone(),
            destination: row.destination.clone(),
            recipient: row.recipient.clone(),
            sender: row.sender.clone(),
            message,
        };
        let body = serde_json::to_vec(&transaction).map_err(|error| {
            AppError::internal(format!("serialize federation transaction: {error}"))
        })?;
        let uri = "/api/fed/chat/messages";
        let discovery = match self.discover_remote(&row.destination).await {
            Ok(discovery) => discovery,
            Err(error) => {
                mark_retry(state, &row, &error.to_string()).await?;
                return Ok(FederatedSendOutcome::Pending);
            }
        };
        let authorization = FederationAuthorization::sign(
            self.server_name.clone(),
            row.destination.clone(),
            OffsetDateTime::now_utc().unix_timestamp(),
            row.id.to_string(),
            FederationRequest {
                method: "POST",
                uri,
                body: &body,
            },
            &self.signing_key,
        )
        .map_err(AppError::internal)?
        .to_header_value()
        .map_err(AppError::internal)?;
        let url = format!("{}{}", discovery.api_base.trim_end_matches('/'), uri);
        let response = match FED_CLIENT
            .post(url)
            .header(AUTHORIZATION.as_str(), authorization)
            .header(CONTENT_TYPE.as_str(), "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                mark_retry(state, &row, &error.to_string()).await?;
                return Ok(FederatedSendOutcome::Pending);
            }
        };
        let status = response.status();
        let response_body = response.bytes().await.map_err(|error| {
            AppError::new(StatusCode::BAD_GATEWAY, format!("remote response: {error}"))
        })?;
        if response_body.len() > MAX_DIRECTORY_RESPONSE_BYTES {
            mark_retry(state, &row, "federation delivery response is too large").await?;
            return Ok(FederatedSendOutcome::Pending);
        }

        if status == reqwest::StatusCode::OK {
            let delivered: FederationDeliveryResponse = serde_json::from_slice(&response_body)
                .map_err(|_| {
                    AppError::new(
                        StatusCode::BAD_GATEWAY,
                        "invalid federation delivery response",
                    )
                })?;
            if delivered.accepted_sequence != sequence {
                mark_retry(state, &row, "remote acknowledged the wrong sequence").await?;
                return Ok(FederatedSendOutcome::Pending);
            }
            let value = serde_json::to_value(&delivered).map_err(|error| {
                AppError::internal(format!("serialize federation response: {error}"))
            })?;
            sqlx::query(
                "UPDATE chat_federation_outbox
                 SET state = 'delivered', response = $2, attempts = attempts + 1,
                     last_error = NULL, updated_at = now()
                 WHERE id = $1",
            )
            .bind(row.id)
            .bind(value)
            .execute(&state.pool)
            .await?;
            return match delivered.rejection {
                Some(rejection) => Ok(FederatedSendOutcome::Rejected(rejection)),
                None => Ok(FederatedSendOutcome::Delivered {
                    deduplicated: delivered.deduplicated,
                }),
            };
        }

        if status == reqwest::StatusCode::CONFLICT {
            let conflict: FederationDeliveryError = serde_json::from_slice(&response_body)
                .map_err(|_| {
                    AppError::new(
                        StatusCode::BAD_GATEWAY,
                        "invalid federation conflict response",
                    )
                })?;
            match conflict {
                FederationDeliveryError::DeviceListMismatch { ref mismatch } => {
                    let value = serde_json::to_value(&conflict).map_err(|error| {
                        AppError::internal(format!("serialize federation mismatch: {error}"))
                    })?;
                    sqlx::query(
                        "UPDATE chat_federation_outbox
                         SET state = 'mismatch', response = $2, attempts = attempts + 1,
                             last_error = NULL, updated_at = now()
                         WHERE id = $1",
                    )
                    .bind(row.id)
                    .bind(value)
                    .execute(&state.pool)
                    .await?;
                    return Ok(FederatedSendOutcome::Mismatch(mismatch.clone()));
                }
                FederationDeliveryError::SequenceGap { expected_sequence } => {
                    if expected_sequence < sequence {
                        let expected = i64::try_from(expected_sequence).map_err(|_| {
                            AppError::internal("remote requested an invalid sequence")
                        })?;
                        let restored = sqlx::query(
                            "UPDATE chat_federation_outbox
                             SET state = 'pending', next_attempt_at = now(),
                                 last_error = 'remote requested replay after a sequence gap',
                                 updated_at = now()
                             WHERE destination = $1
                               AND sequence >= $2 AND sequence < $3",
                        )
                        .bind(&row.destination)
                        .bind(expected)
                        .bind(row.sequence)
                        .execute(&state.pool)
                        .await?;
                        if restored.rows_affected() == 0 {
                            tracing::error!(
                                destination = %row.destination,
                                expected_sequence,
                                "remote requested a federation transaction outside local retention"
                            );
                        }
                    }
                    mark_retry(
                        state,
                        &row,
                        &format!("remote expects federation sequence {expected_sequence}"),
                    )
                    .await?;
                    return Ok(FederatedSendOutcome::Pending);
                }
            }
        }

        mark_retry(
            state,
            &row,
            &format!("remote federation delivery returned {status}"),
        )
        .await?;
        Ok(FederatedSendOutcome::Pending)
    }

    async fn flush_due(&self, state: &AppState) -> AppResult<usize> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM (
                 SELECT DISTINCT ON (destination)
                        id, destination, state, next_attempt_at, sequence
                 FROM chat_federation_outbox
                 WHERE state <> 'delivered'
                 ORDER BY destination, sequence
             ) heads
             WHERE state = 'pending' AND next_attempt_at <= now()
             ORDER BY destination
             LIMIT 100",
        )
        .fetch_all(&state.pool)
        .await?;
        let mut completed = 0;
        for id in ids {
            if matches!(
                self.attempt_outbox(state, id).await,
                Ok(FederatedSendOutcome::Delivered { .. })
            ) {
                completed += 1;
            }
        }
        Ok(completed)
    }

    async fn verify_inbound(
        &self,
        headers: &HeaderMap,
        method: &str,
        uri: &str,
        body: &[u8],
    ) -> AppResult<FederationAuthorization> {
        let header = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("missing federation authorization"))?;
        let authorization =
            FederationAuthorization::from_header_value(header).map_err(AppError::unauthorized)?;
        if authorization.destination != self.server_name {
            return Err(AppError::unauthorized(
                "federation destination does not match this server",
            ));
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if now.abs_diff(authorization.timestamp) > MAX_CLOCK_SKEW_SECONDS as u64 {
            return Err(AppError::unauthorized(
                "federation request timestamp is outside the allowed window",
            ));
        }

        let discovery = self
            .discover_remote(&authorization.origin)
            .await
            .map_err(|_| AppError::unauthorized("cannot authenticate federation origin"))?;
        let key = discovery
            .signing_keys
            .iter()
            .find(|key| key.key_id == authorization.key_id)
            .ok_or_else(|| AppError::unauthorized("unknown federation signing key"))?;
        let public = STANDARD
            .decode(&key.public_key)
            .map_err(|_| AppError::unauthorized("invalid federation public key"))?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| AppError::unauthorized("invalid federation public key"))?;
        authorization
            .verify(method, uri, body, &public)
            .map_err(AppError::unauthorized)?;
        Ok(authorization)
    }
}

async fn load_outbox(state: &AppState, id: Uuid) -> AppResult<Option<FederationOutboxRow>> {
    Ok(sqlx::query_as(
        "SELECT id, destination, sequence, recipient, sender, request,
                state, response, attempts
         FROM chat_federation_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?)
}

fn delivered_outcome(
    response: Option<Value>,
    deduplicated: bool,
) -> AppResult<FederatedSendOutcome> {
    let response = response
        .ok_or_else(|| AppError::internal("delivered federation outbox has no response"))?;
    let delivered: FederationDeliveryResponse = serde_json::from_value(response)
        .map_err(|error| AppError::internal(format!("stored federation response: {error}")))?;
    match delivered.rejection {
        Some(rejection) => Ok(FederatedSendOutcome::Rejected(rejection)),
        None => Ok(FederatedSendOutcome::Delivered { deduplicated }),
    }
}

async fn mark_retry(state: &AppState, row: &FederationOutboxRow, error: &str) -> AppResult<()> {
    let attempt = row.attempts.saturating_add(1).clamp(1, 30);
    let exponential_seconds = 1_i64 << attempt.min(8);
    let jitter_ms = rand::thread_rng().gen_range(0_i64..=1000);
    let delay_ms = exponential_seconds.min(300) * 1000 + jitter_ms;
    let error: String = error.chars().take(500).collect();
    sqlx::query(
        "UPDATE chat_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($2 * interval '1 millisecond'),
             last_error = $3, updated_at = now()
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(row.id)
    .bind(delay_ms)
    .bind(error)
    .execute(&state.pool)
    .await?;
    Ok(())
}

pub fn spawn_retry_worker(state: AppState) {
    let Some(federation) = state.chat_federation.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RETRY_INTERVAL);
        loop {
            tick.tick().await;
            match federation.flush_due(&state).await {
                Ok(completed) if completed > 0 => {
                    tracing::info!(completed, "chat federation retry delivered queued sends");
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "chat federation retry failed"),
            }
        }
    });
}

fn normalize_api_base(value: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        anyhow::bail!("federation API base must be an HTTP(S) origin");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("federation API base cannot contain credentials, query, or fragment");
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn validate_discovery_keys(discovery: &FederationDiscovery) -> AppResult<()> {
    if discovery.signing_keys.is_empty() || discovery.signing_keys.len() > 8 {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "federation discovery must publish 1-8 signing keys",
        ));
    }
    for key in &discovery.signing_keys {
        let public = STANDARD.decode(&key.public_key).map_err(|_| {
            AppError::new(StatusCode::BAD_GATEWAY, "invalid federation signing key")
        })?;
        let public: [u8; 32] = public.try_into().map_err(|_| {
            AppError::new(StatusCode::BAD_GATEWAY, "invalid federation signing key")
        })?;
        if kutup_chat_proto::server_key_id(&public) != key.key_id {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "federation signing key id mismatch",
            ));
        }
    }
    Ok(())
}

/// Public discovery is available only when the administrator has configured a
/// persistent server signing identity.
#[utoipa::path(
    get,
    path = "/.well-known/kutup/federation.json",
    tag = "chat federation",
    responses(
        (status = 200, description = "Federation endpoint and signing keys", body = FederationDiscovery),
        (status = 404, description = "Chat federation is not configured")
    )
)]
pub async fn discovery(State(state): State<AppState>) -> AppResult<Response> {
    let federation = state
        .chat_federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    Ok(Json(federation.discovery_document()).into_response())
}

/// Signed server-to-server directory lookup. This deliberately serves the
/// reusable last-resort PQ bundle rather than consuming one-time keys: a replay
/// of a read request cannot exhaust the recipient's prekey pool.
#[utoipa::path(
    get,
    path = "/api/fed/chat/users/{username}/keys",
    tag = "chat federation",
    params(("username" = String, Path, description = "Recipient username local to this server")),
    responses(
        (status = 200, description = "Signed manifest and replay-safe PQ bundles", body = UserPreKeyBundlesResponse),
        (status = 401, description = "Invalid federation request signature or destination"),
        (status = 404, description = "Unknown user or federation disabled")
    )
)]
pub async fn get_user_bundles(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation: Arc<ChatFederation> = state
        .chat_federation
        .clone()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = AccountAddress::local(&username)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let uri = format!("/api/fed/chat/users/{}/keys", account.username);
    federation
        .verify_inbound(&headers, "GET", &uri, &[])
        .await?;
    let response_username = format!("{}@{}", account.username, federation.server_name());
    let bundles = crate::handlers::chat::load_user_bundles(
        &state,
        &account.username,
        &response_username,
        None,
        false,
    )
    .await?;
    Ok(Json(bundles).into_response())
}

/// Receive one authenticated, in-order server-to-server ciphertext
/// transaction and atomically append it to the existing per-device mailbox.
#[utoipa::path(
    post,
    path = "/api/fed/chat/messages",
    tag = "chat federation",
    request_body = FederatedChatTransaction,
    responses(
        (status = 200, description = "Transaction stored or idempotently replayed", body = FederationDeliveryResponse),
        (status = 401, description = "Invalid signature, origin, or destination"),
        (status = 409, description = "Device list mismatch or sequence gap", body = FederationDeliveryError)
    )
)]
pub async fn deliver_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_FEDERATION_TRANSACTION_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "federation transaction is too large",
        ));
    }
    let federation = state
        .chat_federation
        .clone()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authorization = federation
        .verify_inbound(&headers, "POST", "/api/fed/chat/messages", &body)
        .await?;
    let transaction: FederatedChatTransaction = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("invalid federation transaction"))?;
    validate_transaction(&transaction, &authorization, federation.server_name())?;
    crate::handlers::chat::validate_send_request(&transaction.message, false, None)?;

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO chat_federation_inbound_state (origin, last_sequence)
         VALUES ($1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(&transaction.origin)
    .execute(&mut *tx)
    .await?;
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM chat_federation_inbound_state
         WHERE origin = $1 FOR UPDATE",
    )
    .bind(&transaction.origin)
    .fetch_one(&mut *tx)
    .await?;
    let sequence = i64::try_from(transaction.sequence)
        .map_err(|_| AppError::bad_request("federation sequence is too large"))?;

    if sequence <= last_sequence {
        let prior: Option<(String, Value)> = sqlx::query_as(
            "SELECT transaction_id, response
             FROM chat_federation_inbound_transactions
             WHERE origin = $1 AND sequence = $2",
        )
        .bind(&transaction.origin)
        .bind(sequence)
        .fetch_optional(&mut *tx)
        .await?;
        tx.rollback().await?;
        if let Some((transaction_id, response)) = prior {
            if transaction_id == transaction.transaction_id {
                let mut delivered: FederationDeliveryResponse = serde_json::from_value(response)
                    .map_err(|error| {
                        AppError::internal(format!("stored federation response: {error}"))
                    })?;
                delivered.deduplicated = true;
                return Ok(Json(delivered).into_response());
            }
        } else {
            // The replay record may expire before the origin's outbox record.
            // The contiguous high-water mark proves this sequence was already
            // consumed, so acknowledge it without attempting old ciphertext.
            return Ok(Json(FederationDeliveryResponse {
                stored: 0,
                deduplicated: true,
                accepted_sequence: transaction.sequence,
                rejection: None,
            })
            .into_response());
        }
        return Ok((
            StatusCode::CONFLICT,
            Json(FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            }),
        )
            .into_response());
    }
    if sequence != last_sequence + 1 {
        tx.rollback().await?;
        return Ok((
            StatusCode::CONFLICT,
            Json(FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            }),
        )
            .into_response());
    }

    let recipient: AccountAddress =
        transaction
            .recipient
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    let recipient_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE username = $1 AND is_active = true FOR SHARE",
    )
    .bind(&recipient.username)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(recipient_id) = recipient_id else {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: transaction.sequence,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
        tx.commit().await?;
        return Ok(Json(response).into_response());
    };

    let current: Vec<(i32, i64)> =
        sqlx::query_as("SELECT device_id, registration_id FROM chat_devices WHERE user_id = $1")
            .bind(recipient_id)
            .fetch_all(&mut *tx)
            .await?;
    if current.is_empty() {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: transaction.sequence,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
        tx.commit().await?;
        return Ok(Json(response).into_response());
    }
    let mismatch =
        crate::handlers::chat::device_list_mismatch(&current, &transaction.message.envelopes);
    if !mismatch.missing_devices.is_empty()
        || !mismatch.stale_devices.is_empty()
        || !mismatch.extra_devices.is_empty()
    {
        tx.rollback().await?;
        return Ok((
            StatusCode::CONFLICT,
            Json(FederationDeliveryError::DeviceListMismatch { mismatch }),
        )
            .into_response());
    }

    let mut stored = Vec::with_capacity(transaction.message.envelopes.len());
    for envelope in &transaction.message.envelopes {
        let (id, cursor, server_ts): (Uuid, i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO chat_mailbox
                (recipient_user_id, recipient_device_id, sender, sender_device_id,
                 envelope_type, suite, content)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(envelope.device_id as i32)
        .bind(&transaction.sender)
        .bind(transaction.message.sender_device_id as i32)
        .bind(crate::handlers::chat::envelope_type_code(
            envelope.envelope_type,
        ))
        .bind(envelope.suite.as_u16() as i16)
        .bind(&envelope.content)
        .fetch_one(&mut *tx)
        .await?;
        stored.push((
            recipient_id,
            envelope.device_id as i32,
            DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender: Some(transaction.sender.clone()),
                sender_device_id: transaction.message.sender_device_id,
                envelope_type: envelope.envelope_type,
                suite: envelope.suite,
                content: envelope.content.clone(),
                server_timestamp: server_ts.format(&Rfc3339).unwrap_or_default(),
            },
        ));
    }

    let response = FederationDeliveryResponse {
        stored: stored.len(),
        deduplicated: false,
        accepted_sequence: transaction.sequence,
        rejection: None,
    };
    record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
    tx.commit().await?;

    for (user, device, envelope) in stored {
        let message = ChatWsServerMessage::Envelope { envelope };
        if let Ok(text) = serde_json::to_string(&message) {
            for connection in state.chat_hub.connections(user, device) {
                connection.write(ChatWsOut::Text(text.clone())).await;
            }
        }
    }
    Ok(Json(response).into_response())
}

async fn record_inbound_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &FederatedChatTransaction,
    sequence: i64,
    response: &FederationDeliveryResponse,
) -> AppResult<()> {
    let response_value = serde_json::to_value(response)
        .map_err(|error| AppError::internal(format!("serialize delivery response: {error}")))?;
    sqlx::query(
        "INSERT INTO chat_federation_inbound_transactions
            (origin, sequence, transaction_id, response)
         VALUES ($1,$2,$3,$4)",
    )
    .bind(&transaction.origin)
    .bind(sequence)
    .bind(&transaction.transaction_id)
    .bind(response_value)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE chat_federation_inbound_state
         SET last_sequence = $2, updated_at = now() WHERE origin = $1",
    )
    .bind(&transaction.origin)
    .bind(sequence)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn validate_transaction(
    transaction: &FederatedChatTransaction,
    authorization: &FederationAuthorization,
    local_server: &str,
) -> AppResult<()> {
    if transaction.fed_version != FEDERATION_VERSION {
        return Err(AppError::bad_request("unsupported chat federation version"));
    }
    if transaction.origin != authorization.origin
        || transaction.destination != authorization.destination
        || transaction.destination != local_server
    {
        return Err(AppError::unauthorized(
            "federation transaction identity does not match authorization",
        ));
    }
    if transaction.transaction_id != authorization.request_id
        || Uuid::parse_str(&transaction.transaction_id).is_err()
    {
        return Err(AppError::bad_request("invalid federation transaction id"));
    }
    if transaction.sequence == 0 {
        return Err(AppError::bad_request(
            "federation sequence must be positive",
        ));
    }
    if transaction.message.sender_device_id == 0 || transaction.message.sender_device_id > 127 {
        return Err(AppError::bad_request("sender device id is out of range"));
    }
    let sender: AccountAddress =
        transaction
            .sender
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if sender.server.as_deref() != Some(transaction.origin.as_str()) {
        return Err(AppError::unauthorized(
            "federated sender does not belong to the origin server",
        ));
    }
    let recipient: AccountAddress =
        transaction
            .recipient
            .parse()
            .map_err(|error: kutup_chat_proto::AddressError| {
                AppError::bad_request(error.to_string())
            })?;
    if recipient.server.as_deref() != Some(transaction.destination.as_str()) {
        return Err(AppError::bad_request(
            "federated recipient does not belong to this server",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_identity_is_persistent_and_discoverable() {
        let signing_key = STANDARD.encode([9; 32]);
        let config = Config {
            database_url: "postgres://unused".into(),
            jwt_secret: "x".repeat(32),
            s3_endpoint: "http://unused".into(),
            s3_access_key: "unused".into(),
            s3_secret_key: "unused".into(),
            s3_bucket: "unused".into(),
            s3_region: "unused".into(),
            app_env: "test".into(),
            admin_account: String::new(),
            break_glass_admin_email: String::new(),
            server_url: "https://edge.example/base/".into(),
            allowed_origins: String::new(),
            storage_total_bytes: 0,
            seaweedfs_master_url: String::new(),
            trash_retention_days: 30,
            chat_mailbox_retention_days: 30,
            chat_send_retention_days: 30,
            chat_device_expiry_days: 90,
            chat_federation_server_name: "chat.example".into(),
            chat_federation_signing_key: signing_key,
            chat_federation_test_allow_private: false,
        };
        let federation = ChatFederation::from_config(&config).unwrap().unwrap();
        let discovery = federation.discovery_document();
        assert_eq!(discovery.server, "chat.example");
        assert_eq!(discovery.api_base, "https://edge.example/base");
        assert_eq!(discovery.signing_keys.len(), 1);
    }

    #[test]
    fn missing_signing_key_keeps_federation_disabled() {
        let mut config = test_config();
        config.chat_federation_signing_key.clear();
        assert!(ChatFederation::from_config(&config).unwrap().is_none());
    }

    #[test]
    fn private_network_escape_hatch_is_test_only() {
        let mut config = test_config();
        config.app_env = "development".into();
        config.chat_federation_test_allow_private = true;
        let error = match ChatFederation::from_config(&config) {
            Err(error) => error,
            Ok(_) => panic!("private-network escape hatch must be rejected outside tests"),
        };
        assert!(error.to_string().contains("APP_ENV=test"));
    }

    #[test]
    fn transaction_identity_is_bound_to_signed_origin_and_destination() {
        let request_id = Uuid::new_v4().to_string();
        let authorization = FederationAuthorization {
            origin: "origin.example".into(),
            destination: "dest.example".into(),
            key_id: "00".repeat(32),
            timestamp: 1,
            request_id: request_id.clone(),
            signature: String::new(),
        };
        let transaction = FederatedChatTransaction {
            fed_version: FEDERATION_VERSION,
            transaction_id: request_id,
            sequence: 1,
            origin: "origin.example".into(),
            destination: "dest.example".into(),
            recipient: "maya@dest.example".into(),
            sender: "ahmet@origin.example".into(),
            message: SendMessagesRequest {
                sender_device_id: 1,
                send_id: Uuid::new_v4().to_string(),
                envelopes: vec![],
                access_token: None,
            },
        };
        validate_transaction(&transaction, &authorization, "dest.example").unwrap();

        let mut replayed = transaction;
        replayed.destination = "other.example".into();
        assert_eq!(
            validate_transaction(&replayed, &authorization, "dest.example")
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    fn test_config() -> Config {
        Config {
            database_url: "postgres://unused".into(),
            jwt_secret: "x".repeat(32),
            s3_endpoint: "http://unused".into(),
            s3_access_key: "unused".into(),
            s3_secret_key: "unused".into(),
            s3_bucket: "unused".into(),
            s3_region: "unused".into(),
            app_env: "test".into(),
            admin_account: String::new(),
            break_glass_admin_email: String::new(),
            server_url: "https://chat.example".into(),
            allowed_origins: String::new(),
            storage_total_bytes: 0,
            seaweedfs_master_url: String::new(),
            trash_retention_days: 30,
            chat_mailbox_retention_days: 30,
            chat_send_retention_days: 30,
            chat_device_expiry_days: 90,
            chat_federation_server_name: String::new(),
            chat_federation_signing_key: STANDARD.encode([1; 32]),
            chat_federation_test_allow_private: false,
        }
    }
}
