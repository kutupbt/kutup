//! Authenticated, transport-only chat federation.
//!
//! The common federation stack owns identity, discovery, trust, admission, and
//! authenticated HTTP. This feature adapter owns the remote Chat directory,
//! encrypted-profile boundary, and durable in-order ciphertext delivery.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, AccountManifestHistoryPageV1, AccountManifestV1, AccountRef,
    AnonymousPreKeyRequestV1, ChatProfileResponse, ChatWsServerMessage, DeliveredEnvelope,
    DeviceListMismatch, FederatedChatTransaction, FederatedSealedBatchItemV1,
    FederatedSealedBatchResponseV1, FederatedSealedBatchV1, FederatedSealedTransactionV1,
    FederationDeliveryError, FederationDeliveryRejection, FederationDeliveryResponse,
    SealedDeliveryResponseV1, SealedMessageSubmissionV1, SendMessagesRequest,
    UserPreKeyBundlesResponse, MAX_SEALED_BATCH_BYTES, MAX_SEALED_BATCH_ITEMS,
};
use rand::Rng as _;
use reqwest::Method;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationRequestSpec};
use crate::{federation::FederationStack, AppState};
use kutup_federation_proto::FederationFeature;

const CHAT_FEDERATION_PAYLOAD_VERSION: u16 = 1;
const JSON_CONTENT_TYPE: &str = "application/json";
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEDERATION_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// The active user an inbound path's `:accountId` is, on this server.
async fn inbound_user(state: &AppState, account: &AccountRef) -> AppResult<Option<Uuid>> {
    crate::account_ids::local_user(&state.pool, &state.config.chat_server_name, account).await
}

fn configured_stack(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::bad_request("chat federation is not configured"))
}

pub async fn fetch_remote_bundles(
    state: &AppState,
    account: &AccountRef,
) -> AppResult<UserPreKeyBundlesResponse> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let path = format!("/api/fed/chat/accounts/{}/keys", account.account_id);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path,
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("remote chat user not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote chat directory returned {}", response.status),
        ));
    }
    let bundles: UserPreKeyBundlesResponse =
        serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "invalid remote chat directory response",
            )
        })?;
    if bundles.account != *account {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote chat directory returned the wrong account",
        ));
    }
    Ok(bundles)
}

pub async fn fetch_remote_sealed_bundles(
    state: &AppState,
    account: &AccountRef,
    request: &AnonymousPreKeyRequestV1,
) -> AppResult<UserPreKeyBundlesResponse> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let path = format!("/api/fed/chat/sealed/accounts/{}/keys", account.account_id);
    let body = serde_json::to_vec(request)
        .map_err(|error| AppError::internal(format!("encode sealed bundle request: {error}")))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::POST,
                path,
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status != StatusCode::OK {
        return Err(AppError::not_found("sealed delivery unavailable"));
    }
    let bundles: UserPreKeyBundlesResponse = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::not_found("sealed delivery unavailable"))?;
    if bundles.account != *account {
        return Err(AppError::not_found("sealed delivery unavailable"));
    }
    Ok(bundles)
}

pub async fn fetch_remote_manifest_history(
    state: &AppState,
    account: &AccountRef,
    query: &crate::handlers::chat::ManifestHistoryQuery,
) -> AppResult<AccountManifestHistoryPageV1> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let query_string = manifest_history_query_string(query);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path: format!(
                    "/api/fed/chat/accounts/{}/manifest-history",
                    account.account_id
                ),
                query: Some(query_string),
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found(
            "remote chat manifest history not found",
        ));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote manifest history returned {}", response.status),
        ));
    }
    let page: AccountManifestHistoryPageV1 = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest history"))?;
    if page.account != *account
        || page.from_sequence != query.page_from_sequence.unwrap_or(query.from_sequence)
        || page.to_sequence != query.to_sequence
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote manifest history returned the wrong account or range",
        ));
    }
    page.validate()
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest history"))?;
    Ok(page)
}

pub async fn fetch_remote_manifest(
    state: &AppState,
    account: &AccountRef,
) -> AppResult<AccountManifestV1> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let path = format!("/api/fed/chat/accounts/{}/manifest", account.account_id);
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path,
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("remote chat manifest not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote manifest proof returned {}", response.status),
        ));
    }
    let manifest: AccountManifestV1 = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest response"))?;
    manifest
        .verify()
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote manifest response"))?;
    if manifest.account != *account {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote manifest returned the wrong account",
        ));
    }
    Ok(manifest)
}

fn manifest_history_query_string(query: &crate::handlers::chat::ManifestHistoryQuery) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("fromSequence", &query.from_sequence.to_string());
    serializer.append_pair("toSequence", &query.to_sequence.to_string());
    serializer.append_pair(
        "pageFromSequence",
        &query
            .page_from_sequence
            .unwrap_or(query.from_sequence)
            .to_string(),
    );
    serializer.finish()
}

pub async fn fetch_remote_profile(
    state: &AppState,
    account: &AccountRef,
    version: &str,
    access_key: &[u8],
) -> AppResult<ChatProfileResponse> {
    let federation = configured_stack(state)?;
    let destination = account.server.as_str();
    let profile_header = HeaderName::from_static(crate::handlers::chat::PROFILE_ACCESS_KEY_HEADER);
    let profile_value = HeaderValue::from_str(&STANDARD.encode(access_key))
        .map_err(|_| AppError::bad_request("invalid chat profile access key"))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::GET,
                path: format!(
                    "/api/fed/chat/accounts/{}/profile/{version}",
                    account.account_id
                ),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: vec![(profile_header, profile_value)],
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
        .map_err(federation_gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("remote chat profile not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote chat profile returned {}", response.status),
        ));
    }
    let profile: ChatProfileResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "invalid remote chat profile response",
        )
    })?;
    if profile.version != version || profile.account != *account {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote chat profile returned the wrong account or version",
        ));
    }
    Ok(profile)
}

fn federation_gateway_error(error: anyhow::Error) -> AppError {
    if error
        .downcast_ref::<crate::federation::FederationAdmissionError>()
        .is_some()
    {
        return AppError::forbidden(error.to_string());
    }
    AppError::new(
        StatusCode::BAD_GATEWAY,
        format!("federation transport failed: {error}"),
    )
}

#[derive(Debug)]
pub enum FederatedSendOutcome {
    Delivered {
        deduplicated: bool,
    },
    Mismatch(DeviceListMismatch),
    Rejected(FederationDeliveryRejection),
    Pending,
    /// Queued, but the recipient's server does not speak this Chat wire
    /// (`chat.v2`): it goes once that server upgrades.
    PeerUnsupported,
}

pub enum FederatedSealedOutcome {
    Delivered(SealedDeliveryResponseV1),
    Mismatch(DeviceListMismatch),
    /// The destination's uniform 404: a wrong capability, or no such
    /// account.
    Unavailable,
    /// The destination refused this very message for good.
    Refused,
    Pending,
    /// As [`FederatedSendOutcome::PeerUnsupported`].
    PeerUnsupported,
}

impl FederatedSealedOutcome {
    /// Whether the destination answered for good: the answer used up the
    /// send's sequence, so the next queued send may follow it.
    fn settled(&self) -> bool {
        matches!(
            self,
            Self::Delivered(_) | Self::Mismatch(_) | Self::Unavailable | Self::Refused
        )
    }
}

/// How long a send to a server without `chat.v2` waits before it is tried
/// again: long enough not to keep asking, short enough that an upgrade is
/// noticed within the hour. Order per destination is kept meanwhile.
const PEER_UNSUPPORTED_RETRY_SECONDS: i64 = 3600;

/// The answer to a send whose recipient's server does not speak this Chat
/// wire: 503 with `code: peerUnsupported`, so apps can say so instead of
/// showing a send that never ends.
pub fn peer_unsupported_error() -> AppError {
    AppError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "the recipient's server does not support this Chat version; the message is queued until it does",
    )
    .with_details(serde_json::json!({ "code": "peerUnsupported" }))
}

/// The answer to a sealed send the recipient's server refused for good.
pub fn peer_refused_error() -> AppError {
    AppError::new(
        StatusCode::BAD_GATEWAY,
        "the recipient's server refused this message",
    )
    .with_details(serde_json::json!({ "code": "peerRefused" }))
}

/// The most one sealed transaction weighs, encoded: what the destination's
/// single route takes. A send over it is refused at once, never queued, as
/// it could never be delivered.
const MAX_SEALED_TRANSACTION_BYTES: usize = 1024 * 1024;

/// Room a federated batch keeps for its own fields around the transactions.
const SEALED_BATCH_OVERHEAD_BYTES: usize = 64 * 1024;

/// The most batches one flush of a destination sends: more only when a run
/// ended at a sequence an earlier answer already settled.
const MAX_SEALED_FLUSH_ROUNDS: usize = 4;

/// How long a destination is sent singles after it answered a single but not
/// a batch (a server from before batches).
const NO_SEALED_BATCH_ROUTE_FOR: Duration = Duration::from_secs(3600);

static NO_SEALED_BATCH_ROUTE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(Default::default);

fn lacks_sealed_batch_route(destination: &str) -> bool {
    NO_SEALED_BATCH_ROUTE
        .lock()
        .unwrap()
        .get(destination)
        .is_some_and(|since| since.elapsed() < NO_SEALED_BATCH_ROUTE_FOR)
}

fn remember_no_sealed_batch_route(destination: &str) {
    let mut known = NO_SEALED_BATCH_ROUTE.lock().unwrap();
    known.retain(|_, since| since.elapsed() < NO_SEALED_BATCH_ROUTE_FOR);
    known.insert(destination.to_owned(), std::time::Instant::now());
}

#[derive(sqlx::FromRow)]
struct SealedFederationOutboxRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    recipient_account_id: Uuid,
    transaction: Value,
    attempts: i32,
}

pub async fn enqueue_sealed_send(
    state: &AppState,
    recipient: &AccountRef,
    request: SealedMessageSubmissionV1,
) -> AppResult<FederatedSealedOutcome> {
    match enqueue_sealed_row(state, recipient, request).await? {
        Queued::Settled(outcome) => Ok(outcome),
        Queued::Row(id) => {
            flush_sealed_destination(state, &recipient.server)
                .await?
                .outcome(&state.pool, id)
                .await
        }
    }
}

/// The destination's next sealed sequence, taken for good.
async fn next_sealed_sequence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    destination: &str,
) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO chat_sealed_federation_sequences (destination, next_sequence)
         VALUES ($1, 2)
         ON CONFLICT (destination) DO UPDATE SET
             next_sequence = chat_sealed_federation_sequences.next_sequence + 1
         RETURNING next_sequence - 1",
    )
    .bind(destination)
    .fetch_one(&mut **tx)
    .await?)
}

/// A sealed transaction as stored, if it fits the destination's single
/// route: `413` otherwise.
fn sealed_transaction_value(transaction: &FederatedSealedTransactionV1) -> AppResult<Value> {
    let encoded = serde_json::to_vec(transaction)
        .map_err(|error| AppError::internal(format!("encode sealed transaction: {error}")))?;
    if encoded.len() > MAX_SEALED_TRANSACTION_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "sealed send exceeds what one federated transaction carries",
        ));
    }
    serde_json::to_value(transaction)
        .map_err(|error| AppError::internal(format!("encode sealed transaction: {error}")))
}

/// A sealed send put in its destination's outbox, or already settled there.
pub(crate) enum Queued {
    Settled(FederatedSealedOutcome),
    Row(Uuid),
}

/// Queues a sealed send for a remote recipient without trying it. An error
/// means nothing was queued.
pub(crate) async fn enqueue_sealed_row(
    state: &AppState,
    recipient: &AccountRef,
    request: SealedMessageSubmissionV1,
) -> AppResult<Queued> {
    let federation = configured_stack(state)?;
    enqueue_sealed_row_in(&state.pool, federation.server_name(), recipient, request).await
}

/// [`enqueue_sealed_row`] at the origin `server_name`: a repeat of a settled
/// send is answered from its row (a delivery, or the same answer again for
/// the same content), a rejected one with corrected content is queued again
/// under a new sequence, a new one takes the destination's next sequence.
async fn enqueue_sealed_row_in(
    pool: &sqlx::PgPool,
    server_name: &str,
    recipient: &AccountRef,
    request: SealedMessageSubmissionV1,
) -> AppResult<Queued> {
    request.validate().map_err(AppError::bad_request)?;
    let destination = recipient.server.as_str();
    let recipient_id = Uuid::parse_str(&recipient.account_id)
        .map_err(|_| AppError::internal("a canonical account id is a UUID"))?;
    if destination == server_name {
        return Err(AppError::bad_request(
            "local sealed recipients use local mailbox delivery",
        ));
    }
    let send_id = Uuid::parse_str(&request.send_id)
        .map_err(|_| AppError::bad_request("sealed sendId is invalid"))?;
    let mut tx = pool.begin().await?;
    if let Some((id, state_name, stored_transaction, class, answer)) =
        sqlx::query_as::<_, (Uuid, String, Value, Option<String>, Option<Value>)>(
            "SELECT id, state, transaction, last_error_class, answer
             FROM chat_sealed_federation_outbox
             WHERE destination = $1 AND recipient_account_id = $2 AND send_id = $3 FOR UPDATE",
        )
        .bind(destination)
        .bind(recipient_id)
        .bind(send_id)
        .fetch_optional(&mut *tx)
        .await?
    {
        let mut transaction: FederatedSealedTransactionV1 =
            serde_json::from_value(stored_transaction).map_err(|error| {
                AppError::internal(format!("stored sealed transaction is invalid: {error}"))
            })?;
        let same = transaction.capability == request.capability
            && transaction.envelopes == request.envelopes;
        match state_name.as_str() {
            "delivered" => {
                tx.rollback().await?;
                return Ok(Queued::Settled(FederatedSealedOutcome::Delivered(
                    SealedDeliveryResponseV1 {
                        stored: request.envelopes.len(),
                        deduplicated: true,
                    },
                )));
            }
            "pending" if !same => {
                return Err(AppError::conflict(
                    "sealed send payload changed while federation delivery is pending",
                ));
            }
            // The same content again: the same answer, not another send.
            "rejected" if same => {
                if let Some(outcome) =
                    settled_outcome(&state_name, class.as_deref(), answer.unwrap_or(Value::Null))
                {
                    tx.rollback().await?;
                    return Ok(Queued::Settled(outcome));
                }
                requeue_sealed(&mut tx, id, destination, &mut transaction).await?;
            }
            // Its answer used up its sequence at the destination (a device
            // mismatch, a refusal or the uniform 404): the corrected resend
            // goes under a new one, never the old.
            "rejected" => {
                transaction.capability = request.capability;
                transaction.envelopes = request.envelopes;
                requeue_sealed(&mut tx, id, destination, &mut transaction).await?;
            }
            "pending" => {}
            _ => return Err(AppError::internal("invalid sealed federation outbox state")),
        }
        tx.commit().await?;
        return Ok(Queued::Row(id));
    }

    let sequence = next_sealed_sequence(&mut tx, destination).await?;
    let transaction = FederatedSealedTransactionV1 {
        version: kutup_chat_proto::SEALED_FEDERATION_VERSION,
        origin: server_name.to_string(),
        recipient: recipient.clone(),
        sequence: u64::try_from(sequence)
            .map_err(|_| AppError::internal("sealed federation sequence is invalid"))?,
        send_id: request.send_id,
        capability: request.capability,
        envelopes: request.envelopes,
    };
    let value = sealed_transaction_value(&transaction)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat_sealed_federation_outbox
             (id, destination, sequence, recipient_account_id, send_id, transaction)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(destination)
    .bind(sequence)
    .bind(recipient_id)
    .bind(send_id)
    .bind(value)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Queued::Row(id))
}

/// Puts a rejected row back in the queue under the destination's next
/// sequence.
async fn requeue_sealed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    destination: &str,
    transaction: &mut FederatedSealedTransactionV1,
) -> AppResult<()> {
    let sequence = next_sealed_sequence(tx, destination).await?;
    transaction.sequence = u64::try_from(sequence)
        .map_err(|_| AppError::internal("sealed federation sequence is invalid"))?;
    sqlx::query(
        "UPDATE chat_sealed_federation_outbox
         SET sequence = $3, transaction = $2, state = 'pending', attempts = 0,
             next_attempt_at = now(), last_error_class = NULL, answer = NULL,
             updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(sealed_transaction_value(transaction)?)
    .bind(sequence)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A settled row's answer, as the outcome it was: `None` for a row still
/// queued, or one settled before answers were kept.
fn settled_outcome(
    state_name: &str,
    class: Option<&str>,
    answer: Value,
) -> Option<FederatedSealedOutcome> {
    match (state_name, class) {
        ("delivered", _) => serde_json::from_value(answer)
            .ok()
            .map(FederatedSealedOutcome::Delivered),
        ("rejected", Some("device_mismatch")) => match serde_json::from_value(answer) {
            Ok(FederationDeliveryError::DeviceListMismatch { mismatch }) => {
                Some(FederatedSealedOutcome::Mismatch(mismatch))
            }
            _ => None,
        },
        ("rejected", Some("unavailable")) => Some(FederatedSealedOutcome::Unavailable),
        ("rejected", Some("refused")) => Some(FederatedSealedOutcome::Refused),
        _ => None,
    }
}

/// One flush per destination at a time. In this process a set of the
/// destinations being flushed; across every backend sharing the database a
/// session advisory lock, held on a connection of its own small pool so a
/// flush never holds one of the main pool's, nor a transaction, across its
/// network calls.
pub(crate) struct SealedFlushLocks {
    flushing: std::sync::Mutex<std::collections::HashSet<String>>,
    pool: sqlx::PgPool,
}

/// Connections for held flush locks: a flush beyond these waits for the
/// next round.
const FLUSH_LOCK_CONNECTIONS: u32 = 4;

impl SealedFlushLocks {
    pub(crate) fn new(pool: &sqlx::PgPool) -> Self {
        Self {
            flushing: std::sync::Mutex::new(std::collections::HashSet::new()),
            pool: sqlx::postgres::PgPoolOptions::new()
                .max_connections(FLUSH_LOCK_CONNECTIONS)
                .min_connections(0)
                .acquire_timeout(Duration::from_secs(1))
                .connect_lazy_with((*pool.connect_options()).clone()),
        }
    }

    /// `destination`'s flush lock, or `None` at once if a flush of it is
    /// under way here or on another backend. Nobody waits for it.
    async fn try_lock(&self, destination: &str) -> AppResult<Option<FlushLock<'_>>> {
        if !self.flushing.lock().unwrap().insert(destination.to_owned()) {
            return Ok(None);
        }
        let mut lock = FlushLock {
            locks: self,
            destination: destination.to_owned(),
            connection: None,
        };
        let mut connection = match self.pool.acquire().await {
            Ok(connection) => connection,
            Err(sqlx::Error::PoolTimedOut) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let locked: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 771944))")
                .bind(destination)
                .fetch_one(&mut *connection)
                .await?;
        if !locked {
            return Ok(None);
        }
        lock.connection = Some(connection);
        Ok(Some(lock))
    }
}

/// A held flush lock. Released by [`FlushLock::release`]; one dropped while
/// held (a cancelled or failed flush) closes its connection, which ends the
/// advisory lock with the session, so a pooled connection never keeps it.
struct FlushLock<'a> {
    locks: &'a SealedFlushLocks,
    destination: String,
    connection: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
}

impl FlushLock<'_> {
    async fn release(mut self) {
        if let Some(mut connection) = self.connection.take() {
            let unlocked = sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 771944))")
                .bind(&self.destination)
                .execute(&mut *connection)
                .await;
            if unlocked.is_err() {
                connection.close_on_drop();
            }
        }
    }
}

impl Drop for FlushLock<'_> {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            connection.close_on_drop();
        }
        self.locks
            .flushing
            .lock()
            .unwrap()
            .remove(&self.destination);
    }
}

/// What one flush of a destination did with its queued sends.
pub(crate) struct SealedFlush {
    outcomes: std::collections::HashMap<Uuid, AppResult<FederatedSealedOutcome>>,
    /// The queue waits for the destination to support chat.v2.
    parked: bool,
}

impl SealedFlush {
    fn new() -> Self {
        Self {
            outcomes: std::collections::HashMap::new(),
            parked: false,
        }
    }

    /// What became of queued send `id`: this flush's answer, or else what
    /// its row says now (another flush, the retry worker's, may have settled
    /// it meanwhile), or still waiting.
    pub(crate) async fn outcome(
        &mut self,
        pool: &sqlx::PgPool,
        id: Uuid,
    ) -> AppResult<FederatedSealedOutcome> {
        if let Some(outcome) = self.outcomes.remove(&id) {
            return outcome;
        }
        let row: Option<(String, Option<String>, Option<Value>)> = sqlx::query_as(
            "SELECT state, last_error_class, answer FROM chat_sealed_federation_outbox
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        let Some((state_name, class, answer)) = row else {
            return Ok(self.waiting(None));
        };
        Ok(
            settled_outcome(&state_name, class.as_deref(), answer.unwrap_or(Value::Null))
                .unwrap_or_else(|| self.waiting(class.as_deref())),
        )
    }

    fn waiting(&self, class: Option<&str>) -> FederatedSealedOutcome {
        if self.parked || class == Some("peer_unsupported") {
            FederatedSealedOutcome::PeerUnsupported
        } else {
            FederatedSealedOutcome::Pending
        }
    }

    fn record(&mut self, id: Uuid, outcome: AppResult<FederatedSealedOutcome>) -> bool {
        let settled = matches!(&outcome, Ok(outcome) if outcome.settled());
        if matches!(outcome, Ok(FederatedSealedOutcome::PeerUnsupported)) {
            self.parked = true;
        }
        self.outcomes.insert(id, outcome);
        settled
    }
}

/// Delivers a destination's queued sealed sends, under its flush lock: the
/// run of pending rows from its head, if the head is due (not backing off,
/// not parked for an upgrade), in federated batches (at most
/// [`MAX_SEALED_BATCH_ITEMS`] and [`MAX_SEALED_BATCH_BYTES`] each). Nothing
/// is sent without the lock or a due head; sends it doesn't reach wait, and
/// with the lock taken elsewhere this flush sends nothing. The flush runs in
/// its own task, so a client that goes away doesn't cut it short.
pub(crate) async fn flush_sealed_destination(
    state: &AppState,
    destination: &str,
) -> AppResult<SealedFlush> {
    let (state, destination) = (state.clone(), destination.to_owned());
    tokio::spawn(async move { flush_locked(&state, &destination).await })
        .await
        .map_err(|error| AppError::internal(format!("sealed flush task: {error}")))?
}

async fn flush_locked(state: &AppState, destination: &str) -> AppResult<SealedFlush> {
    let mut flush = SealedFlush::new();
    let Some(lock) = state.sealed_flush.try_lock(destination).await? else {
        return Ok(flush);
    };
    for _ in 0..MAX_SEALED_FLUSH_ROUNDS {
        // Sizes first: only the rows that fit one batch are loaded.
        let queued: Vec<(Uuid, i64, i32, bool, Option<String>)> = sqlx::query_as(
            "SELECT id, sequence, octet_length(transaction::text),
                    next_attempt_at <= now(), last_error_class
             FROM chat_sealed_federation_outbox
             WHERE destination = $1 AND state = 'pending'
             ORDER BY sequence LIMIT $2",
        )
        .bind(destination)
        .bind(MAX_SEALED_BATCH_ITEMS as i64)
        .fetch_all(&state.pool)
        .await?;
        let Some((_, _, _, due, class)) = queued.first() else {
            break;
        };
        if !due {
            flush.parked = class.as_deref() == Some("peer_unsupported");
            break;
        }
        // A batch carries consecutive sequences; one an answer already
        // settled ends this run, and the next round starts after it.
        let mut run = Vec::new();
        let mut size = 0usize;
        for (id, sequence, weight, _, _) in &queued {
            let weight = usize::try_from(*weight).unwrap_or(usize::MAX);
            if let Some(&(_, last)) = run.last() {
                if last + 1 != *sequence
                    || size.saturating_add(weight)
                        > MAX_SEALED_BATCH_BYTES - SEALED_BATCH_OVERHEAD_BYTES
                {
                    break;
                }
            }
            size = size.saturating_add(weight);
            run.push((*id, *sequence));
        }
        let ids: Vec<Uuid> = run.iter().map(|(id, _)| *id).collect();
        let rows: Vec<SealedFederationOutboxRow> = sqlx::query_as(
            "SELECT id, destination, sequence, recipient_account_id, transaction, attempts
             FROM chat_sealed_federation_outbox
             WHERE id = ANY($1) AND state = 'pending'
             ORDER BY sequence",
        )
        .bind(&ids)
        .fetch_all(&state.pool)
        .await?;
        if !send_sealed_run(state, destination, &rows, &mut flush).await? {
            break;
        }
    }
    lock.release().await;
    Ok(flush)
}

/// Sends one run of a destination's queued rows: as a batch, or one by one
/// to a server without the batch route. Says whether every row was settled,
/// so the next run may follow.
async fn send_sealed_run(
    state: &AppState,
    destination: &str,
    rows: &[SealedFederationOutboxRow],
    flush: &mut SealedFlush,
) -> AppResult<bool> {
    if rows.len() < 2 || lacks_sealed_batch_route(destination) {
        return send_sealed_singles(state, rows, flush, false).await;
    }
    let federation = configured_stack(state)?;
    let mut transactions = Vec::with_capacity(rows.len());
    for row in rows {
        transactions.push(stored_sealed_transaction(row)?);
    }
    let batch = FederatedSealedBatchV1 {
        version: kutup_chat_proto::SEALED_FEDERATION_VERSION,
        origin: federation.server_name().to_string(),
        transactions,
    };
    let body = serde_json::to_vec(&batch)
        .map_err(|error| AppError::internal(format!("encode sealed batch: {error}")))?;
    let sent = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::POST,
                path: "/api/fed/chat/sealed/batch".into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await;
    let response = match sent {
        Ok(response) if response.status == StatusCode::OK => response,
        Err(error) if crate::federation::lacks_capability(&error) => {
            park_sealed_for_upgrade(&state.pool, &rows[0]).await?;
            for row in rows {
                flush.record(row.id, Ok(FederatedSealedOutcome::PeerUnsupported));
            }
            return Ok(false);
        }
        // Not taken as a batch: a server from before batches (whose answer
        // to an unknown route isn't signed, so it reads as a failed
        // transport), or a failed transport. The head alone tells which.
        _ => return send_sealed_singles(state, rows, flush, true).await,
    };
    let Ok(answers) = serde_json::from_slice::<FederatedSealedBatchResponseV1>(&response.body)
    else {
        mark_sealed_retry(&state.pool, &rows[0], "remote_error").await?;
        return Ok(false);
    };
    let mut answers = answers.results.into_iter();
    for row in rows {
        let outcome = match answers.next() {
            Some(answer) if i64::try_from(answer.sequence).ok() == Some(row.sequence) => {
                match StatusCode::from_u16(answer.status) {
                    Ok(status) => {
                        let body = serde_json::to_vec(&answer.response).map_err(|error| {
                            AppError::internal(format!("encode sealed answer: {error}"))
                        })?;
                        apply_sealed_answer(&state.pool, row, status, &body).await
                    }
                    Err(_) => {
                        mark_sealed_retry(&state.pool, row, "remote_error").await?;
                        Ok(FederatedSealedOutcome::Pending)
                    }
                }
            }
            // Not reached (after an answer that left its sequence open), or
            // out of step: it waits.
            _ => return Ok(false),
        };
        if !flush.record(row.id, outcome) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Sends rows one by one, each on past an answer that settled the one
/// before. After a batch the destination didn't take (`after_batch`), a head
/// it answers alone marks it as a server without the batch route.
async fn send_sealed_singles(
    state: &AppState,
    rows: &[SealedFederationOutboxRow],
    flush: &mut SealedFlush,
    after_batch: bool,
) -> AppResult<bool> {
    for (index, row) in rows.iter().enumerate() {
        let (outcome, reached) = attempt_sealed_single(state, row).await;
        if index == 0 && after_batch && reached {
            remember_no_sealed_batch_route(&row.destination);
            tracing::info!(destination = %row.destination, "sealed federation peer takes no batches; sending singles");
        }
        if !flush.record(row.id, outcome?) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn stored_sealed_transaction(
    row: &SealedFederationOutboxRow,
) -> AppResult<FederatedSealedTransactionV1> {
    let transaction: FederatedSealedTransactionV1 = serde_json::from_value(row.transaction.clone())
        .map_err(|error| {
            AppError::internal(format!("stored sealed transaction is invalid: {error}"))
        })?;
    if transaction.recipient
        != crate::account_ids::stored(&row.destination, row.recipient_account_id)?
    {
        return Err(AppError::internal(
            "sealed outbox recipient does not match its transaction",
        ));
    }
    Ok(transaction)
}

/// One queued row over the single route, and whether the destination
/// answered at all (not a failed transport).
async fn attempt_sealed_single(
    state: &AppState,
    row: &SealedFederationOutboxRow,
) -> (AppResult<AppResult<FederatedSealedOutcome>>, bool) {
    let attempt = async {
        let federation = configured_stack(state)?;
        let transaction = stored_sealed_transaction(row)?;
        let body = serde_json::to_vec(&transaction)
            .map_err(|error| AppError::internal(format!("encode sealed transaction: {error}")))?;
        let sent = federation
            .send(
                &row.destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV2,
                    method: Method::POST,
                    path: "/api/fed/chat/sealed/messages".into(),
                    query: None,
                    content_type: JSON_CONTENT_TYPE.into(),
                    // A retry of the same bytes keeps its request id; a resend
                    // under a new sequence (the same row, other bytes) gets
                    // its own, or the destination's replay check refuses it.
                    request_id: delivery_request_id(row.id, &body),
                    body,
                    extra_headers: Vec::new(),
                    response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
                },
            )
            .await;
        Ok::<_, AppError>(match sent {
            Ok(response) => (
                apply_sealed_answer(&state.pool, row, response.status, &response.body).await,
                true,
            ),
            Err(error) if crate::federation::lacks_capability(&error) => {
                park_sealed_for_upgrade(&state.pool, row).await?;
                tracing::warn!(destination = %row.destination, "sealed federation send waits for the peer to support chat.v2");
                (Ok(FederatedSealedOutcome::PeerUnsupported), true)
            }
            Err(error) => {
                mark_sealed_retry(&state.pool, row, "transport").await?;
                tracing::warn!(destination = %row.destination, error = %error, "sealed federation retry deferred");
                (Ok(FederatedSealedOutcome::Pending), false)
            }
        })
    };
    match attempt.await {
        Ok((outcome, reached)) => (Ok(outcome), reached),
        Err(error) => (Err(error), false),
    }
}

/// Moves a pending row to a final state, if it is still pending under the
/// sequence its answer is for: a stale answer (to a sequence the row has
/// since left) moves nothing.
async fn settle_sealed_row(
    pool: &sqlx::PgPool,
    row: &SealedFederationOutboxRow,
    state_name: &str,
    class: Option<&str>,
    answer: &[u8],
) -> AppResult<bool> {
    let answer = serde_json::from_slice::<Value>(answer).unwrap_or(Value::Null);
    Ok(sqlx::query(
        "UPDATE chat_sealed_federation_outbox
         SET state = $3, attempts = attempts + 1,
             last_error_class = $4, answer = $5, updated_at = now()
         WHERE id = $1 AND state = 'pending' AND sequence = $2",
    )
    .bind(row.id)
    .bind(row.sequence)
    .bind(state_name)
    .bind(class)
    .bind(answer)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Records the destination's answer to the outbox row it answers, and says
/// what became of that send. One answer, single or in a batch, moves a row
/// the same way; the destination reads answers alike (`SealedAnswer::uses_up`).
async fn apply_sealed_answer(
    pool: &sqlx::PgPool,
    row: &SealedFederationOutboxRow,
    status: StatusCode,
    body: &[u8],
) -> AppResult<FederatedSealedOutcome> {
    let (state_name, class, outcome) = match status {
        StatusCode::OK => match serde_json::from_slice::<SealedDeliveryResponseV1>(body) {
            Ok(delivered) => (
                "delivered",
                None,
                FederatedSealedOutcome::Delivered(delivered),
            ),
            Err(_) => {
                mark_sealed_retry(pool, row, "remote_error").await?;
                return Ok(FederatedSealedOutcome::Pending);
            }
        },
        StatusCode::CONFLICT => match serde_json::from_slice::<FederationDeliveryError>(body) {
            Ok(FederationDeliveryError::DeviceListMismatch { mismatch }) => (
                "rejected",
                Some("device_mismatch"),
                FederatedSealedOutcome::Mismatch(mismatch),
            ),
            Ok(FederationDeliveryError::SequenceGap { .. }) => {
                mark_sealed_retry(pool, row, "sequence_gap").await?;
                return Ok(FederatedSealedOutcome::Pending);
            }
            Err(_) => {
                mark_sealed_retry(pool, row, "remote_error").await?;
                return Ok(FederatedSealedOutcome::Pending);
            }
        },
        StatusCode::NOT_FOUND => (
            "rejected",
            Some("unavailable"),
            FederatedSealedOutcome::Unavailable,
        ),
        // A signed refusal of this very message: sending it again cannot
        // help, and waiting on it would hold every later sealed send to that
        // server. The client learns it was refused.
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            if refused_sequence(body) == Some(row.sequence) =>
        {
            let refusal = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
            tracing::warn!(
                destination = %row.destination,
                code = refusal.get("code").and_then(serde_json::Value::as_str).unwrap_or(""),
                error = refusal.get("error").and_then(serde_json::Value::as_str).unwrap_or(""),
                "the recipient's server refused a sealed send for good"
            );
            ("rejected", Some("refused"), FederatedSealedOutcome::Refused)
        }
        _ => {
            mark_sealed_retry(pool, row, "remote_error").await?;
            return Ok(FederatedSealedOutcome::Pending);
        }
    };
    if !settle_sealed_row(pool, row, state_name, class, body).await? {
        return Ok(FederatedSealedOutcome::Pending);
    }
    Ok(outcome)
}

/// The sequence a signed sealed refusal names as final, if it names one.
fn refused_sequence(body: &[u8]) -> Option<i64> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("refused")?
        .get("sequence")?
        .as_i64()
}

async fn park_sealed_for_upgrade(
    pool: &sqlx::PgPool,
    row: &SealedFederationOutboxRow,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE chat_sealed_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($3 * interval '1 second'),
             last_error_class = 'peer_unsupported', updated_at = now()
         WHERE id = $1 AND state = 'pending' AND sequence = $2",
    )
    .bind(row.id)
    .bind(row.sequence)
    .bind(PEER_UNSUPPORTED_RETRY_SECONDS)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_sealed_retry(
    pool: &sqlx::PgPool,
    row: &SealedFederationOutboxRow,
    class: &str,
) -> AppResult<()> {
    let attempt = row.attempts.saturating_add(1).clamp(1, 30);
    let delay = (1_i64 << attempt.min(8)).min(300);
    sqlx::query(
        "UPDATE chat_sealed_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($3 * interval '1 second'),
             last_error_class = $4, updated_at = now()
         WHERE id = $1 AND state = 'pending' AND sequence = $2",
    )
    .bind(row.id)
    .bind(row.sequence)
    .bind(delay)
    .bind(class)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct FederationOutboxRow {
    id: Uuid,
    destination: String,
    sequence: i64,
    sender_user_id: Uuid,
    recipient_account_id: Uuid,
    request: Value,
    state: String,
    response: Option<Value>,
    attempts: i32,
}

/// Persist a remote send before attempting network I/O. A transient remote
/// failure is returned to the client so its own durable outbox remains, but
/// the server queue can make progress independently in the meantime.
pub async fn enqueue_send(
    state: &AppState,
    sender_user_id: Uuid,
    recipient: &AccountRef,
    request: SendMessagesRequest,
) -> AppResult<FederatedSendOutcome> {
    let federation = configured_stack(state)?;
    crate::handlers::chat::validate_send_request(&request, false, None)?;
    let destination = recipient.server.as_str();
    if destination == federation.server_name() {
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
    let device: Option<i32> = sqlx::query_scalar(
        "UPDATE chat_devices SET last_seen_at = now()
             WHERE user_id = $1 AND device_id = $2 RETURNING 1",
    )
    .bind(sender_user_id)
    .bind(request.sender_device_id as i32)
    .fetch_optional(&mut *tx)
    .await?;
    device.ok_or_else(|| AppError::not_found("no such chat device"))?;
    let recipient_id = Uuid::parse_str(&recipient.account_id)
        .map_err(|_| AppError::internal("a canonical account id is a UUID"))?;

    let existing: Option<(Uuid, String, Value, Option<Value>, String, Uuid)> = sqlx::query_as(
        "SELECT id, state, request, response, destination, recipient_account_id
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
        if prior_destination != destination || prior_recipient != recipient_id {
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
                    .and_then(|value| serde_json::from_value::<FederationDeliveryError>(value).ok())
                    .and_then(|error| match error {
                        FederationDeliveryError::DeviceListMismatch { mismatch } => Some(mismatch),
                        FederationDeliveryError::SequenceGap { .. } => None,
                    })
                    .ok_or_else(|| AppError::internal("stored federation mismatch is invalid"))?;
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
        sqlx::query(
            "INSERT INTO chat_federation_outbox
                    (id, destination, sequence, sender_user_id, sender_device_id,
                     send_id, recipient_account_id, request)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(destination)
        .bind(sequence)
        .bind(sender_user_id)
        .bind(request.sender_device_id as i32)
        .bind(&request.send_id)
        .bind(recipient_id)
        .bind(&request_value)
        .execute(&mut *tx)
        .await?;
        id
    };
    tx.commit().await?;
    attempt_outbox(state, id).await
}

async fn attempt_outbox(state: &AppState, id: Uuid) -> AppResult<FederatedSendOutcome> {
    let federation = configured_stack(state)?;
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
        fed_version: CHAT_FEDERATION_PAYLOAD_VERSION,
        transaction_id: row.id.to_string(),
        sequence,
        origin: federation.server_name().to_owned(),
        destination: row.destination.clone(),
        recipient: crate::account_ids::stored(&row.destination, row.recipient_account_id)?,
        sender: crate::account_ids::local(federation.server_name(), row.sender_user_id)?,
        message,
    };
    let body = serde_json::to_vec(&transaction).map_err(|error| {
        AppError::internal(format!("serialize federation transaction: {error}"))
    })?;
    let request_id = delivery_request_id(row.id, &body);
    let response = match federation
        .send(
            &row.destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::POST,
                path: "/api/fed/chat/messages".into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                // The Chat transaction ID is stable across a device-list
                // correction. The transport nonce is stable only for one
                // exact payload version: byte-identical network retries are
                // exact replays, while corrected ciphertext gets a distinct
                // nonce without losing Chat-level idempotency.
                request_id,
                extra_headers: Vec::new(),
                response_limit: MAX_DIRECTORY_RESPONSE_BYTES,
            },
        )
        .await
    {
        Ok(response) => response,
        Err(error) if crate::federation::lacks_capability(&error) => {
            park_for_upgrade(state, &row, &error.to_string()).await?;
            return Ok(FederatedSendOutcome::PeerUnsupported);
        }
        Err(error) => {
            mark_retry(state, &row, &error.to_string()).await?;
            return Ok(FederatedSendOutcome::Pending);
        }
    };
    let status = response.status;
    let response_body = response.body;

    if status == StatusCode::OK {
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

    if status == StatusCode::CONFLICT {
        let conflict: FederationDeliveryError =
            serde_json::from_slice(&response_body).map_err(|_| {
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
                    let expected = i64::try_from(expected_sequence)
                        .map_err(|_| AppError::internal("remote requested an invalid sequence"))?;
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

fn delivery_request_id(transaction_id: Uuid, body: &[u8]) -> String {
    format!("{transaction_id}.{}", hex::encode(Sha256::digest(body)))
}

async fn flush_due(state: &AppState) -> AppResult<usize> {
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
            attempt_outbox(state, id).await,
            Ok(FederatedSendOutcome::Delivered { .. })
        ) {
            completed += 1;
        }
    }
    Ok(completed)
}

async fn load_outbox(state: &AppState, id: Uuid) -> AppResult<Option<FederationOutboxRow>> {
    Ok(sqlx::query_as(
        "SELECT id, destination, sequence, sender_user_id, recipient_account_id, request,
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

async fn park_for_upgrade(
    state: &AppState,
    row: &FederationOutboxRow,
    error: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE chat_federation_outbox
         SET attempts = attempts + 1,
             next_attempt_at = now() + ($2 * interval '1 second'),
             last_error = $3, updated_at = now()
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(row.id)
    .bind(PEER_UNSUPPORTED_RETRY_SECONDS)
    .bind(error)
    .execute(&state.pool)
    .await?;
    Ok(())
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
    if state.federation.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RETRY_INTERVAL);
        loop {
            tick.tick().await;
            match flush_due(&state).await {
                Ok(completed) if completed > 0 => {
                    tracing::info!(completed, "chat federation retry delivered queued sends");
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "chat federation retry failed"),
            }
            if let Err(error) = flush_due_sealed(&state).await {
                tracing::warn!(%error, "sealed chat federation retry failed");
            }
        }
    });
}

/// The sealed sends due now: only each destination's head. Rows behind a
/// waiting head (parked for an upgrade, or backing off) would only return
/// early, and a long queue for one server must not fill the page and starve
/// the others.
async fn due_sealed_destinations(pool: &sqlx::PgPool) -> AppResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT destination FROM (
                 SELECT DISTINCT ON (destination) id, destination, next_attempt_at
                 FROM chat_sealed_federation_outbox
                 WHERE state = 'pending'
                 ORDER BY destination, sequence
             ) heads
             WHERE next_attempt_at <= now()
             ORDER BY destination
             LIMIT 100",
    )
    .fetch_all(pool)
    .await?)
}

async fn flush_due_sealed(state: &AppState) -> AppResult<()> {
    for destination in due_sealed_destinations(&state.pool).await? {
        match flush_sealed_destination(state, &destination).await {
            Ok(flush) => {
                for (id, outcome) in flush.outcomes {
                    if let Err(error) = outcome {
                        tracing::warn!(%id, error = %error.message, "queued sealed federation send failed");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%destination, error = %error.message, "queued sealed federation flush failed");
            }
        }
    }
    Ok(())
}

/// Signed server-to-server directory lookup. This deliberately serves the
/// reusable last-resort PQ bundle rather than consuming one-time keys: a replay
/// of a read request cannot exhaust the recipient's prekey pool.
#[utoipa::path(
    get,
    path = "/api/fed/chat/accounts/{accountId}/keys",
    tag = "chat federation",
    params(
        ("accountId" = String, Path, description = "Recipient's account id on this server")
    ),
    responses(
        (status = 200, description = "Signed manifest and replay-safe PQ bundles", body = UserPreKeyBundlesResponse),
        (status = 401, description = "Invalid federation request signature or destination"),
        (status = 404, description = "Unknown user or federation disabled")
    )
)]
pub async fn get_user_bundles(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let path = format!("/api/fed/chat/accounts/{}/keys", account.account_id);
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &path, None, &[], FederationFeature::ChatV2)
        .await?;
    let bundles = match inbound_user(&state, &account).await {
        Ok(Some(target_id)) => {
            crate::handlers::chat::load_user_bundles(&state, target_id, None, false, None).await
        }
        Ok(None) => Err(AppError::not_found("user not found")),
        Err(error) => Err(error),
    };
    let bundles = match bundles {
        Ok(bundles) => bundles,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &bundles)
}

pub async fn get_sealed_user_bundles(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)
        .map_err(|_| AppError::not_found("sealed delivery unavailable"))?;
    let path = format!("/api/fed/chat/sealed/accounts/{}/keys", account.account_id);
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            &path,
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let request: AnonymousPreKeyRequestV1 = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("sealed delivery unavailable"),
            )
        }
    };
    let capability = match request.capability_bytes() {
        Ok(capability) => capability,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("sealed delivery unavailable"),
            )
        }
    };
    // Not ours, not active, or a wrong capability: one answer.
    let bundles = match inbound_user(&state, &account).await {
        Ok(Some(target_id)) => {
            crate::handlers::chat::load_user_bundles(
                &state,
                target_id,
                None,
                true,
                Some(&capability_hash(&capability)),
            )
            .await
        }
        Ok(None) => Err(AppError::not_found("sealed delivery unavailable")),
        Err(error) => Err(error),
    };
    let bundles = match bundles {
        Ok(bundles) => bundles,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &bundles)
}

/// Signed, sender-unidentified federation delivery. The authenticated origin
/// domain and contiguous sequence are retained; no sender account or device is
/// present in the transaction, mailbox row, response, or destination logs.
pub async fn deliver_sealed_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_SEALED_TRANSACTION_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "sealed transaction exceeds 1 MiB",
        ));
    }
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/sealed/messages",
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let transaction: FederatedSealedTransactionV1 = match serde_json::from_slice(&body) {
        Ok(transaction) => transaction,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid sealed federation transaction"),
            )
        }
    };
    if authenticated.destination() != federation.server_name()
        || transaction.origin != authenticated.origin()
    {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::unauthorized("sealed federation origin or destination mismatch"),
        );
    }
    match apply_sealed_one(
        &state.pool,
        federation.server_name(),
        authenticated.origin(),
        &transaction,
    )
    .await
    {
        Ok((answer, stored)) => {
            crate::handlers::chat::push_sealed(&state, stored).await;
            signed_json(federation, &authenticated, answer.status, &answer.body)
        }
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `POST /api/fed/chat/sealed/batch`: several of one origin's sealed
/// transactions, in sequence order, applied one by one exactly as the single
/// route applies them. It stops after the first answer that doesn't use up
/// its sequence (the rest would only meet a gap) and answers each one it
/// tried.
#[utoipa::path(
    post,
    path = "/api/fed/chat/sealed/batch",
    tag = "chat federation",
    request_body = kutup_chat_proto::FederatedSealedBatchV1,
    responses(
        (status = 200, description = "Each tried transaction's answer, in order", body = kutup_chat_proto::FederatedSealedBatchResponseV1),
        (status = 400, description = "Malformed batch"),
        (status = 401, description = "Invalid federation request signature or destination"),
        (status = 413, description = "Batch too large"),
    )
)]
pub async fn deliver_sealed_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_SEALED_BATCH_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "sealed batch exceeds its size limit",
        ));
    }
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/sealed/batch",
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let batch: FederatedSealedBatchV1 = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid sealed federation batch"),
            )
        }
    };
    if authenticated.destination() != federation.server_name() {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::unauthorized("sealed federation destination mismatch"),
        );
    }
    match apply_sealed_batch(
        &state.pool,
        federation.server_name(),
        authenticated.origin(),
        &batch,
    )
    .await
    {
        Ok((response, stored)) => {
            tracing::info!(
                origin = %authenticated.origin(),
                transactions = batch.transactions.len(),
                answered = response.results.len(),
                "sealed federation batch"
            );
            crate::handlers::chat::push_sealed(&state, stored).await;
            signed_json(federation, &authenticated, StatusCode::OK, &response)
        }
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// What a delivery stored, for the recipients' live connections and pushes.
type StoredSealed = Vec<(Uuid, i32, DeliveredEnvelope)>;

/// A batch from `origin` applied at this destination (`server_name`): its
/// shape checked first, so a malformed batch is refused before any of it is
/// applied, then each transaction as the single route applies it.
async fn apply_sealed_batch(
    pool: &sqlx::PgPool,
    server_name: &str,
    origin: &str,
    batch: &FederatedSealedBatchV1,
) -> AppResult<(FederatedSealedBatchResponseV1, StoredSealed)> {
    batch
        .validate_shape(origin)
        .map_err(AppError::bad_request)?;
    let mut results = Vec::with_capacity(batch.transactions.len());
    let mut stored = Vec::new();
    for transaction in &batch.transactions {
        let answer = match apply_sealed_one(pool, server_name, origin, transaction).await {
            Ok((answer, delivered)) => {
                stored.extend(delivered);
                answer
            }
            Err(error) => SealedAnswer::from_error(error),
        };
        let used_up = answer.uses_up(transaction.sequence);
        results.push(FederatedSealedBatchItemV1 {
            sequence: transaction.sequence,
            status: answer.status.as_u16(),
            response: answer.body,
        });
        // Past an answer that didn't use up its sequence, the next would only
        // meet a gap.
        if !used_up {
            break;
        }
    }
    Ok((FederatedSealedBatchResponseV1 { results }, stored))
}

/// A sealed transaction's answer at this destination: the status and body
/// the single route signs, and the batch route lists per transaction.
pub(crate) struct SealedAnswer {
    status: StatusCode,
    body: Value,
}

impl SealedAnswer {
    fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> AppResult<Self> {
        Ok(Self {
            status,
            body: serde_json::to_value(value)
                .map_err(|error| AppError::internal(format!("encode sealed answer: {error}")))?,
        })
    }

    /// Whether this answer took its sequence for good: a delivery, the
    /// uniform 404, a device mismatch, or a refusal that names the sequence.
    /// A gap or a passing error leaves the sequence to be tried again. The
    /// origin reads answers the same way (`apply_sealed_answer`).
    fn uses_up(&self, sequence: u64) -> bool {
        match self.status {
            StatusCode::OK | StatusCode::NOT_FOUND => true,
            StatusCode::CONFLICT => {
                self.body.get("code").and_then(Value::as_str) == Some("deviceListMismatch")
            }
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                self.body
                    .get("refused")
                    .and_then(|refused| refused.get("sequence"))
                    .and_then(Value::as_u64)
                    == Some(sequence)
            }
            _ => false,
        }
    }

    /// An error as the single route answers it (`signed_app_error`).
    fn from_error(error: AppError) -> Self {
        let message = if error.status.is_server_error() {
            tracing::error!(status = %error.status, error = %error.message, "sealed delivery failed");
            "internal server error".to_owned()
        } else {
            error.message
        };
        let mut body = error.details.unwrap_or_default();
        body.insert("error".into(), Value::String(message));
        Self {
            status: error.status,
            body: Value::Object(body),
        }
    }
}

/// Records a final answer for `origin`'s `sequence` in `tx`, which holds the
/// origin's lock and found that sequence next: a replay then gets the same
/// answer, and the next sequence may follow.
async fn record_sealed_answer(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &str,
    sequence: i64,
    send_id: &str,
    answer: &SealedAnswer,
) -> AppResult<()> {
    let send_id =
        Uuid::parse_str(send_id).map_err(|_| AppError::bad_request("sealed sendId is invalid"))?;
    sqlx::query(
        "INSERT INTO chat_sealed_federation_inbound
             (origin, sequence, send_id, response_status, response)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(origin)
    .bind(sequence)
    .bind(send_id)
    .bind(answer.status.as_u16() as i16)
    .bind(&answer.body)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Applies one sealed transaction from `origin` at this destination
/// (`server_name`), in its origin's sequence order: the single route's whole
/// check, store and record. A final answer is recorded in the same
/// transaction, under the origin's lock, as what it answers.
async fn apply_sealed_one(
    pool: &sqlx::PgPool,
    server_name: &str,
    origin: &str,
    transaction: &FederatedSealedTransactionV1,
) -> AppResult<(SealedAnswer, StoredSealed)> {
    // A transaction that does not hold up is refused once its sequence is
    // next in line, and the refusal takes that sequence (below): the origin
    // treats it as final, so its later sends must not wait on it.
    let invalid = if transaction.version != kutup_chat_proto::SEALED_FEDERATION_VERSION {
        // A peer on another sealed version reads sequences differently:
        // refused outright, never waited on (docs/self-hosting.md, Updating).
        tracing::warn!(
            %origin,
            version = transaction.version,
            expected = kutup_chat_proto::SEALED_FEDERATION_VERSION,
            "sealed federation peer runs another version; federating servers upgrade together"
        );
        Some((
            "sealed federation version is not this server's".to_owned(),
            Some("sealedVersionUnsupported"),
        ))
    } else {
        transaction
            .validate(origin, server_name)
            .err()
            .map(|error| (error.to_string(), None))
    };
    let sequence = match i64::try_from(transaction.sequence) {
        Ok(sequence) => sequence,
        Err(_) => {
            return Err(AppError::bad_request(
                "sealed federation sequence is too large",
            ))
        }
    };
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771943))")
        .bind(origin)
        .execute(&mut *tx)
        .await?;
    if let Some((status, response)) = sqlx::query_as::<_, (i16, Value)>(
        "SELECT response_status, response FROM chat_sealed_federation_inbound
         WHERE origin = $1 AND sequence = $2",
    )
    .bind(origin)
    .bind(sequence)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.rollback().await?;
        let status = StatusCode::from_u16(status as u16)
            .map_err(|_| AppError::internal("stored sealed response status is invalid"))?;
        return Ok((
            SealedAnswer {
                status,
                body: response,
            },
            Vec::new(),
        ));
    }
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence), 0) FROM chat_sealed_federation_inbound
         WHERE origin = $1",
    )
    .bind(origin)
    .fetch_one(&mut *tx)
    .await?;
    if sequence != last_sequence + 1 {
        tx.rollback().await?;
        return Ok((
            SealedAnswer::json(
                StatusCode::CONFLICT,
                &FederationDeliveryError::SequenceGap {
                    expected_sequence: (last_sequence + 1) as u64,
                },
            )?,
            Vec::new(),
        ));
    }
    if let Some((error, code)) = invalid {
        return Ok((
            refuse_sealed(tx, origin, transaction, sequence, error, code).await?,
            Vec::new(),
        ));
    }
    let request = SealedMessageSubmissionV1 {
        send_id: transaction.send_id.clone(),
        capability: transaction.capability.clone(),
        envelopes: transaction.envelopes.clone(),
    };
    // Checked by validate: the recipient is on this server. One that is not
    // an account here is answered as a wrong capability.
    let recipient = Uuid::parse_str(&transaction.recipient.account_id).unwrap_or(Uuid::nil());
    // The store runs under a savepoint: what it wrote (counters, the sendId
    // claim) is undone for an answer that stores nothing, while the origin's
    // lock is kept until that answer is recorded.
    let mut store = sqlx::Acquire::begin(&mut tx).await?;
    let outcome =
        crate::handlers::chat::store_sealed_messages(&mut store, recipient, &request, Some(origin))
            .await;
    let answer = match outcome {
        Ok(crate::handlers::chat::SealedStoreOutcome::Delivered { response, stored }) => {
            store.commit().await?;
            let answer = SealedAnswer::json(StatusCode::OK, &response)?;
            record_sealed_answer(&mut tx, origin, sequence, &transaction.send_id, &answer).await?;
            tx.commit().await?;
            return Ok((answer, stored));
        }
        // Nothing is stored for the recipient, but the answer is final: it
        // uses up the sequence like a delivery, so a send whose client never
        // corrects it can't hold the origin's later sends. The corrected
        // resend comes under a new sequence.
        Ok(crate::handlers::chat::SealedStoreOutcome::Mismatch(mismatch)) => {
            store.rollback().await?;
            if let Err(limited) = charge_sealed_origin(&mut tx, origin).await {
                tx.rollback().await?;
                return Ok((SealedAnswer::from_error(limited), Vec::new()));
            }
            SealedAnswer::json(
                StatusCode::CONFLICT,
                &FederationDeliveryError::DeviceListMismatch { mismatch },
            )?
        }
        Err(error) if error.status == StatusCode::NOT_FOUND => {
            store.rollback().await?;
            if let Err(limited) = charge_sealed_origin(&mut tx, origin).await {
                tx.rollback().await?;
                return Ok((SealedAnswer::from_error(limited), Vec::new()));
            }
            SealedAnswer {
                status: StatusCode::NOT_FOUND,
                body: serde_json::json!({ "error": "sealed delivery unavailable" }),
            }
        }
        Err(error)
            if matches!(
                error.status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ) =>
        {
            store.rollback().await?;
            return Ok((
                refuse_sealed(tx, origin, transaction, sequence, error.message, None).await?,
                Vec::new(),
            ));
        }
        // A rate limit or a passing failure: the sequence stays open.
        Err(error) => {
            store.rollback().await?;
            tx.rollback().await?;
            return Err(error);
        }
    };
    record_sealed_answer(&mut tx, origin, sequence, &transaction.send_id, &answer).await?;
    tx.commit().await?;
    Ok((answer, Vec::new()))
}

/// Signed server-to-server skipped-manifest recovery. The exact query is
/// reconstructed in canonical field order and is covered by the common HTTP
/// signature profile.
pub async fn get_manifest_history(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Query(query): Query<crate::handlers::chat::ManifestHistoryQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let path = format!(
        "/api/fed/chat/accounts/{}/manifest-history",
        account.account_id
    );
    let query_string = manifest_history_query_string(&query);
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            Some(&query_string),
            &[],
            FederationFeature::ChatV2,
        )
        .await?;
    let Some(target_id) = inbound_user(&state, &account).await? else {
        let error = AppError::not_found("chat manifest history not found");
        return signed_app_error(federation, &authenticated, error);
    };
    let incarnation_id: Option<String> = match sqlx::query_scalar(
        "SELECT manifest->>'incarnationId' FROM chat_device_manifests WHERE user_id = $1",
    )
    .bind(target_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(value) => value,
        Err(error) => return signed_app_error(federation, &authenticated, error.into()),
    };
    let Some(incarnation_id) = incarnation_id else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest history not found"),
        );
    };
    if query.from_sequence == 0 || query.to_sequence < query.from_sequence {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid manifest history bounds"),
        );
    }
    let page_from = query.page_from_sequence.unwrap_or(query.from_sequence);
    if page_from < query.from_sequence || page_from > query.to_sequence {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid manifest history page cursor"),
        );
    }
    let values: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT manifest FROM chat_device_manifest_history
         WHERE user_id = $1 AND incarnation_id = $2 AND version BETWEEN $3 AND $4
         ORDER BY version LIMIT 65",
    )
    .bind(target_id)
    .bind(incarnation_id)
    .bind(page_from as i64)
    .bind(query.to_sequence as i64)
    .fetch_all(&state.pool)
    .await?;
    if values.is_empty() {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest history not found"),
        );
    }
    let mut manifests = values
        .into_iter()
        .map(serde_json::from_value::<AccountManifestV1>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppError::internal(format!("stored chat manifest: {error}")))?;
    let next_sequence = if manifests.len() > 64 {
        manifests.truncate(64);
        Some(manifests.last().expect("nonempty page").sequence + 1)
    } else {
        None
    };
    let page = AccountManifestHistoryPageV1 {
        account: manifests[0].account.clone(),
        from_sequence: page_from,
        to_sequence: query.to_sequence,
        manifests,
        next_sequence,
    };
    if let Err(error) = page.validate() {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::internal(format!("stored chat manifest history: {error}")),
        );
    }
    signed_json(federation, &authenticated, StatusCode::OK, &page)
}

/// Signed server-to-server current account manifest.
pub async fn get_manifest(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let path = format!("/api/fed/chat/accounts/{}/manifest", account.account_id);
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &path, None, &[], FederationFeature::ChatV2)
        .await?;
    let Some(target_id) = inbound_user(&state, &account).await? else {
        let error = AppError::not_found("chat manifest not found");
        return signed_app_error(federation, &authenticated, error);
    };
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT manifest FROM chat_device_manifests WHERE user_id = $1")
            .bind(target_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(value) = value else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat manifest not found"),
        );
    };
    let manifest: AccountManifestV1 = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("stored chat manifest: {error}")))?;
    signed_json(federation, &authenticated, StatusCode::OK, &manifest)
}

/// Signed server-to-server encrypted profile lookup. The profile access key is
/// a separate bearer capability; the federation signature authenticates and
/// destination-binds the proxying homeserver.
#[utoipa::path(
    get,
    path = "/api/fed/chat/accounts/{accountId}/profile/{version}",
    tag = "chat federation",
    params(
        ("accountId" = String, Path, description = "Profile owner's account id on this server"),
        ("version" = String, Path, description = "Profile-key-derived version")
    ),
    responses(
        (status = 200, description = "Opaque encrypted profile", body = ChatProfileResponse),
        (status = 401, description = "Invalid federation request signature"),
        (status = 404, description = "Profile/version/capability not found")
    )
)]
pub async fn get_user_profile(
    State(state): State<AppState>,
    Path((account_id, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let account = crate::account_ids::remote(federation.server_name(), &account_id)?;
    let uri = format!(
        "/api/fed/chat/accounts/{}/profile/{version}",
        account.account_id
    );
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &uri, None, &[], FederationFeature::ChatV2)
        .await?;
    if !crate::handlers::chat::canonical_profile_version(&version) {
        return signed_json(
            federation,
            &authenticated,
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "chat profile not found"}),
        );
    }
    let Some(encoded) = headers
        .get(crate::handlers::chat::PROFILE_ACCESS_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat profile not found"),
        );
    };
    let Ok(access_key) = STANDARD.decode(encoded) else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("chat profile not found"),
        );
    };
    let found = match inbound_user(&state, &account).await {
        Ok(Some(target_id)) => {
            crate::handlers::chat::load_public_profile(&state, target_id, &version, &access_key)
                .await
        }
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    };
    let profile = match found {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            let error = AppError::not_found("chat profile not found");
            return signed_app_error(federation, &authenticated, error);
        }
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    signed_json(federation, &authenticated, StatusCode::OK, &profile)
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
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/messages",
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let transaction: FederatedChatTransaction = match serde_json::from_slice(&body) {
        Ok(transaction) => transaction,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid federation transaction"),
            )
        }
    };
    if let Err(error) = validate_transaction(&transaction, &authenticated, federation.server_name())
    {
        return signed_app_error(federation, &authenticated, error);
    }
    if let Err(error) =
        crate::handlers::chat::validate_send_request(&transaction.message, false, None)
    {
        return signed_app_error(federation, &authenticated, error);
    }

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
                return signed_json(federation, &authenticated, StatusCode::OK, &delivered);
            }
        } else {
            // The replay record may expire before the origin's outbox record.
            // The contiguous high-water mark proves this sequence was already
            // consumed, so acknowledge it without attempting old ciphertext.
            return signed_json(
                federation,
                &authenticated,
                StatusCode::OK,
                &FederationDeliveryResponse {
                    stored: 0,
                    deduplicated: true,
                    accepted_sequence: transaction.sequence,
                    rejection: None,
                },
            );
        }
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            },
        );
    }
    if sequence != last_sequence + 1 {
        tx.rollback().await?;
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last_sequence + 1) as u64,
            },
        );
    }

    let recipient_id: Option<Uuid> = match Uuid::parse_str(&transaction.recipient.account_id) {
        Ok(id) => {
            sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND is_active = true FOR SHARE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
        }
        Err(_) => None,
    };
    let Some(recipient_id) = recipient_id else {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: transaction.sequence,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        record_inbound_response(&mut tx, &transaction, sequence, &response).await?;
        tx.commit().await?;
        return signed_json(federation, &authenticated, StatusCode::OK, &response);
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
        return signed_json(federation, &authenticated, StatusCode::OK, &response);
    }
    let mismatch =
        crate::handlers::chat::device_list_mismatch(&current, &transaction.message.envelopes);
    if !mismatch.missing_devices.is_empty()
        || !mismatch.stale_devices.is_empty()
        || !mismatch.extra_devices.is_empty()
    {
        tx.rollback().await?;
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::DeviceListMismatch { mismatch },
        );
    }

    let sender_account_id = Uuid::parse_str(&transaction.sender.account_id)
        .map_err(|_| AppError::bad_request("the sender's account id is not a UUID"))?;
    let mut stored = Vec::with_capacity(transaction.message.envelopes.len());
    for envelope in &transaction.message.envelopes {
        let (id, cursor, server_ts): (Uuid, i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO chat_mailbox
                (recipient_user_id, recipient_device_id, sender_server, sender_account_id,
                 sender_device_id, envelope_type, suite, content, send_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING id, cursor, server_ts",
        )
        .bind(recipient_id)
        .bind(envelope.device_id as i32)
        .bind(&transaction.sender.server)
        .bind(sender_account_id)
        .bind(transaction.message.sender_device_id as i32)
        .bind(crate::handlers::chat::envelope_type_code(
            envelope.envelope_type,
        ))
        .bind(envelope.suite.as_u16() as i16)
        .bind(&envelope.content)
        .bind(&transaction.message.send_id)
        .fetch_one(&mut *tx)
        .await?;
        stored.push((
            recipient_id,
            envelope.device_id as i32,
            DeliveredEnvelope {
                id: id.to_string(),
                cursor: cursor as u64,
                sender: Some(transaction.sender.clone()),
                sealed_sender: false,
                sender_device_id: transaction.message.sender_device_id,
                envelope_type: envelope.envelope_type,
                suite: envelope.suite,
                content: envelope.content.clone(),
                server_timestamp: server_ts.format(&Rfc3339).unwrap_or_default(),
                send_id: Some(transaction.message.send_id.clone()),
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
        crate::web_push::wake_if_offline(&state, user, device);
        let message = ChatWsServerMessage::Envelope { envelope };
        if let Ok(text) = serde_json::to_string(&message) {
            for connection in state.chat_hub.connections(user, device) {
                connection.write(ChatWsOut::Text(text.clone())).await;
            }
        }
    }
    signed_json(federation, &authenticated, StatusCode::OK, &response)
}

fn signed_json<T: serde::Serialize>(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    status: StatusCode,
    value: &T,
) -> AppResult<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|error| AppError::internal(format!("serialize federation response: {error}")))?;
    federation.signed_response(authenticated, status, JSON_CONTENT_TYPE, body)
}

/// Refuses a sealed transaction (400). The refusal is final only when it is
/// recorded against the transaction's sequence (that sequence is next, and
/// its sendId is a fresh UUID): then the answer names the sequence
/// (`refused.sequence`), a replay gets the same answer, and the origin's
/// later sends meet no gap. Otherwise the 400 names nothing and the origin
/// keeps the send pending. Counted in the origin's rate first, so refusals
/// cannot be written faster than deliveries.
/// Counts one transaction against its origin's sealed rate, as a delivery
/// does: an answer that stores nothing (a refusal, a mismatch, the uniform
/// 404) is charged too, so none of them is a free probe.
async fn charge_sealed_origin(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &str,
) -> AppResult<()> {
    let origin_digest: [u8; 32] = sha2::Sha256::digest(
        [
            b"kutup/sealed-origin-rate/v1\0".as_slice(),
            origin.as_bytes(),
        ]
        .concat(),
    )
    .into();
    crate::handlers::chat::consume_anonymous_rate(tx, "federation_origin", &origin_digest, 600, 60)
        .await
}

async fn refuse_sealed(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &str,
    transaction: &FederatedSealedTransactionV1,
    sequence: i64,
    error: String,
    code: Option<&str>,
) -> AppResult<SealedAnswer> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771943))")
        .bind(origin)
        .execute(&mut *tx)
        .await?;
    if let Err(limited) = charge_sealed_origin(&mut tx, origin).await {
        tx.rollback().await?;
        return Ok(SealedAnswer::from_error(limited));
    }
    let last_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence), 0) FROM chat_sealed_federation_inbound
         WHERE origin = $1",
    )
    .bind(origin)
    .fetch_one(&mut *tx)
    .await?;
    // A refusal is final even for a sendId that doesn't parse: it is
    // recorded under the nil id, which no delivery uses.
    let send_id = Uuid::parse_str(&transaction.send_id).unwrap_or(Uuid::nil());
    let mut final_value =
        serde_json::json!({ "error": error, "refused": { "sequence": sequence } });
    if let Some(code) = code {
        final_value["code"] = Value::from(code);
    }
    let recorded = sequence == last_sequence + 1
        && sqlx::query(
            "INSERT INTO chat_sealed_federation_inbound
                 (origin, sequence, send_id, response_status, response)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT DO NOTHING",
        )
        .bind(origin)
        .bind(sequence)
        .bind(send_id)
        .bind(StatusCode::BAD_REQUEST.as_u16() as i16)
        .bind(&final_value)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
    tx.commit().await?;
    Ok(SealedAnswer {
        status: StatusCode::BAD_REQUEST,
        body: if recorded {
            final_value
        } else {
            serde_json::json!({ "error": error })
        },
    })
}

fn signed_app_error(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    error: AppError,
) -> AppResult<Response> {
    let message = if error.status.is_server_error() {
        tracing::error!(status = %error.status, error = %error.message, "federation request failed");
        "internal server error".to_owned()
    } else {
        error.message
    };
    // A client error's details go back with it (a held name's `renamed`
    // and its chains).
    let mut body = error.details.unwrap_or_default();
    body.insert("error".into(), serde_json::Value::String(message));
    signed_json(
        federation,
        authenticated,
        error.status,
        &serde_json::Value::Object(body),
    )
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
    authenticated: &AuthenticatedFederationRequest,
    local_server: &str,
) -> AppResult<()> {
    if transaction.fed_version != CHAT_FEDERATION_PAYLOAD_VERSION {
        return Err(AppError::bad_request("unsupported chat federation version"));
    }
    if transaction.origin != authenticated.origin()
        || transaction.destination != authenticated.destination()
        || transaction.destination != local_server
    {
        return Err(AppError::unauthorized(
            "federation transaction identity does not match authorization",
        ));
    }
    if Uuid::parse_str(&transaction.transaction_id).is_err() {
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
    check_accounts(transaction)
}

/// The sender is the origin's account (a peer speaks only for its own
/// accounts) and the recipient the destination's. Both parsed canonical:
/// AccountRef refuses anything else.
fn check_accounts(transaction: &FederatedChatTransaction) -> AppResult<()> {
    if transaction.sender.server != transaction.origin {
        return Err(AppError::unauthorized(
            "federated sender does not belong to the origin server",
        ));
    }
    if transaction.recipient.server != transaction.destination {
        return Err(AppError::bad_request(
            "federated recipient does not belong to this server",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A backlog for one server does not starve another, and a parked head
    /// holds back only its own server. Needs the database:
    /// `KUTUP_LIVE_DATABASE_URL` (the backup gate).
    #[tokio::test]
    async fn live_sealed_backlog_does_not_starve_other_destinations() {
        let Ok(database_url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let tag = Uuid::new_v4().simple().to_string();
        let (slow, other) = (
            format!("slow{}.example", &tag[..8]),
            format!("ok{}.example", &tag[..8]),
        );
        let insert = |destination: String, sequence: i64| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO chat_sealed_federation_outbox
                         (destination, sequence, recipient_account_id, send_id, transaction)
                     VALUES ($1, $2, gen_random_uuid(), gen_random_uuid(), '{}'::jsonb) RETURNING id",
                )
                .bind(destination)
                .bind(sequence)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let slow_head = insert(slow.clone(), 1).await;
        for sequence in 2..=150 {
            insert(slow.clone(), sequence).await;
        }
        insert(other.clone(), 1).await;

        let due = super::due_sealed_destinations(&pool).await.unwrap();
        let ours = due
            .iter()
            .filter(|destination| **destination == slow || **destination == other)
            .count();
        assert_eq!(ours, 2, "each destination once, however long its queue");

        // The slow server's head waits an hour for its upgrade: nothing of
        // it is due, and the other server still is.
        sqlx::query(
            "UPDATE chat_sealed_federation_outbox
                SET next_attempt_at = now() + interval '1 hour', last_error_class = 'peer_unsupported'
              WHERE id = $1",
        )
        .bind(slow_head)
        .execute(&pool)
        .await
        .unwrap();
        let due = super::due_sealed_destinations(&pool).await.unwrap();
        assert!(due.contains(&other));
        assert!(!due.contains(&slow), "a parked head holds its queue");

        sqlx::query("DELETE FROM chat_sealed_federation_outbox WHERE destination = ANY($1)")
            .bind(vec![slow, other])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn a_batch_goes_on_only_past_answers_that_use_up_their_sequence() {
        use axum::http::StatusCode;
        use serde_json::{json, Value};
        let answer = |status: StatusCode, body: Value| super::SealedAnswer { status, body };
        // A delivery, the uniform 404 and a refusal naming the sequence take it.
        assert!(answer(StatusCode::OK, json!({"stored": 1})).uses_up(7));
        assert!(answer(StatusCode::NOT_FOUND, json!({"error": "x"})).uses_up(7));
        assert!(answer(StatusCode::BAD_REQUEST, json!({"refused": {"sequence": 7}})).uses_up(7));
        assert!(answer(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"refused": {"sequence": 7}})
        )
        .uses_up(7));
        // A device mismatch is final for its sequence; a gap isn't.
        assert!(answer(
            StatusCode::CONFLICT,
            json!({"code": "deviceListMismatch", "staleDevices": [1]})
        )
        .uses_up(7));
        assert!(!answer(
            StatusCode::CONFLICT,
            json!({"code": "sequenceGap", "expectedSequence": 6})
        )
        .uses_up(7));
        // A refusal of another sequence, or naming none, leaves it open.
        assert!(!answer(StatusCode::BAD_REQUEST, json!({"refused": {"sequence": 8}})).uses_up(7));
        assert!(!answer(StatusCode::BAD_REQUEST, json!({"error": "x"})).uses_up(7));
        // So do a 409 that names nothing, a limit and a server error.
        for status in [
            StatusCode::CONFLICT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::UNAUTHORIZED,
        ] {
            assert!(!answer(status, json!({})).uses_up(7), "{status}");
        }
    }

    #[test]
    fn only_a_refusal_naming_the_sequence_is_final() {
        let named = br#"{"error":"bad","refused":{"sequence":7}}"#;
        assert_eq!(super::refused_sequence(named), Some(7));
        // A 400 before the sequence was known names none: not final.
        assert_eq!(
            super::refused_sequence(br#"{"error":"invalid sealed federation transaction"}"#),
            None
        );
        assert_eq!(super::refused_sequence(b"not json"), None);
    }

    #[test]
    fn a_peer_speaks_only_for_its_own_accounts() {
        let account = |server: &str| {
            kutup_chat_proto::AccountRef::new(server, "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b")
                .unwrap()
        };
        let transaction =
            |sender: &str, recipient: &str| kutup_chat_proto::FederatedChatTransaction {
                fed_version: super::CHAT_FEDERATION_PAYLOAD_VERSION,
                transaction_id: Uuid::new_v4().to_string(),
                sequence: 1,
                origin: "a.example".into(),
                destination: "b.example".into(),
                recipient: account(recipient),
                sender: account(sender),
                message: kutup_chat_proto::SendMessagesRequest {
                    sender_device_id: 1,
                    send_id: Uuid::new_v4().to_string(),
                    envelopes: Vec::new(),
                    access_token: None,
                },
            };
        assert!(super::check_accounts(&transaction("a.example", "b.example")).is_ok());
        // A delivering a sender of C, or of the destination itself: refused.
        let forged = super::check_accounts(&transaction("c.example", "b.example")).unwrap_err();
        assert_eq!(forged.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(super::check_accounts(&transaction("b.example", "b.example")).is_err());
        // A recipient on another server than the destination: refused.
        assert!(super::check_accounts(&transaction("a.example", "c.example")).is_err());
    }

    #[test]
    fn federated_accounts_must_be_canonical() {
        let account = |server: &str, id: &str| {
            serde_json::from_value::<kutup_chat_proto::AccountRef>(
                serde_json::json!({ "server": server, "accountId": id }),
            )
        };
        let id = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        assert!(account("origin.example", id).is_ok());
        for (server, id) in [
            ("Origin.Example", id),
            ("origin.example.", id),
            ("origin.example", "0B6B5E0C-4C1E-4B8E-9C2D-6A1F3E5D7C9B"),
            ("origin.example", "alice"),
        ] {
            assert!(account(server, id).is_err(), "{server} {id}");
        }
    }

    use super::delivery_request_id;
    use uuid::Uuid;

    #[test]
    fn delivery_transport_nonce_is_stable_only_for_one_payload_version() {
        let id = Uuid::parse_str("10000000-0000-4000-8000-000000000002").unwrap();
        let first = delivery_request_id(id, b"ciphertext-v1");
        assert_eq!(first, delivery_request_id(id, b"ciphertext-v1"));
        assert_ne!(first, delivery_request_id(id, b"ciphertext-v2"));
        assert!(first.len() <= 128);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')));
    }
}

/// The sealed queues against a real database (`KUTUP_LIVE_DATABASE_URL`):
/// the destination's batch below its signature check, and the origin's
/// answers to its outbox rows.
#[cfg(test)]
mod sealed_live_tests {
    use super::*;
    use serde_json::json;

    const DESTINATION: &str = "destination.test";

    async fn pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("KUTUP_LIVE_DATABASE_URL").ok()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(4)
                .connect(&url)
                .await
                .unwrap(),
        )
    }

    /// An account with one Chat device (registration id 77) and a delivery
    /// capability.
    async fn recipient(pool: &sqlx::PgPool, capability: [u8; 16]) -> Uuid {
        let id = Uuid::new_v4();
        let name = format!("sb{}", &id.simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO users (id, master_key_envelope, recovery_key_envelope,
                 drive_private_key_envelope, public_key, account_authority_public_key,
                 account_authority_key_id, account_incarnation_id, drive_signing_public_key,
                 username)
             VALUES ($1, '', '', '', '', '', '', '', '', $2)",
        )
        .bind(id)
        .bind(&name)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_devices (user_id, device_id, suite, registration_id, identity_key,
                 signed_pre_key_id, signed_pre_key, signed_pre_key_signature,
                 last_resort_kyber_pre_key_id, last_resort_kyber_pre_key,
                 last_resort_kyber_pre_key_signature)
             VALUES ($1, 1, 1, 77, 'k', 1, 'k', 's', 1, 'k', 's')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_delivery_capabilities
                 (user_id, profile_version, profile_revision, capability_hash)
             VALUES ($1, $2, 1, $3)",
        )
        .bind(id)
        .bind("71".repeat(32))
        .bind(capability_hash(&capability).as_slice())
        .execute(pool)
        .await
        .unwrap();
        id
    }

    fn transaction(
        origin: &str,
        recipient: Uuid,
        sequence: u64,
        send_id: Uuid,
        capability: [u8; 16],
        registration_id: u32,
    ) -> FederatedSealedTransactionV1 {
        serde_json::from_value(json!({
            "version": kutup_chat_proto::SEALED_FEDERATION_VERSION,
            "origin": origin,
            "recipient": {"server": DESTINATION, "accountId": recipient.to_string()},
            "sequence": sequence,
            "sendId": send_id.to_string(),
            "capability": STANDARD.encode(capability),
            "envelopes": [{
                "deviceId": 1,
                "registrationId": registration_id,
                "suite": 1,
                "content": STANDARD.encode([0x5au8; 96]),
            }],
        }))
        .unwrap()
    }

    fn batch(
        origin: &str,
        transactions: Vec<FederatedSealedTransactionV1>,
    ) -> FederatedSealedBatchV1 {
        FederatedSealedBatchV1 {
            version: kutup_chat_proto::SEALED_FEDERATION_VERSION,
            origin: origin.to_owned(),
            transactions,
        }
    }

    async fn stored(pool: &sqlx::PgPool, user: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_mailbox WHERE recipient_user_id = $1")
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn recorded(pool: &sqlx::PgPool, origin: &str) -> Vec<(i64, i16)> {
        sqlx::query_as(
            "SELECT sequence, response_status FROM chat_sealed_federation_inbound
             WHERE origin = $1 ORDER BY sequence",
        )
        .bind(origin)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn clean(pool: &sqlx::PgPool, origin: &str, users: &[Uuid]) {
        sqlx::query("DELETE FROM chat_sealed_federation_inbound WHERE origin = $1")
            .bind(origin)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(users)
            .execute(pool)
            .await
            .unwrap();
    }

    fn origin() -> String {
        format!("o{}.test", &Uuid::new_v4().simple().to_string()[..12])
    }

    /// A peer on the old sealed version is refused for good, by sequence,
    /// with a code that says why: nothing waits on it.
    #[tokio::test]
    async fn live_another_sealed_version_is_refused_for_good() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let origin = origin();
        let capability = [0x64; 16];
        let bob = recipient(&pool, capability).await;
        let mut old = transaction(&origin, bob, 1, Uuid::new_v4(), capability, 77);
        old.version = 1;
        let (answer, stored_now) = apply_sealed_one(&pool, DESTINATION, &origin, &old)
            .await
            .unwrap();
        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        assert_eq!(answer.body["code"], "sealedVersionUnsupported");
        assert_eq!(answer.body["refused"]["sequence"], 1);
        assert!(answer.uses_up(1));
        assert!(stored_now.is_empty());
        assert_eq!(recorded(&pool, &origin).await, [(1, 400)]);
        assert_eq!(stored(&pool, bob).await, 0);
        clean(&pool, &origin, &[bob]).await;
    }

    /// One flush per destination: a second try in this process, or while
    /// another backend holds the database lock, gets nothing at once; a lock
    /// dropped without its release (a cancelled flush) doesn't stay held.
    #[tokio::test]
    async fn live_one_flush_per_destination_at_a_time() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let locks = SealedFlushLocks::new(&pool);
        let destination = origin();
        let first = locks.try_lock(&destination).await.unwrap().expect("free");
        assert!(locks.try_lock(&destination).await.unwrap().is_none());
        assert!(locks.try_lock("other.test").await.unwrap().is_some());
        first.release().await;
        // Held by another backend.
        let other = SealedFlushLocks::new(&pool);
        let elsewhere = other.try_lock(&destination).await.unwrap().expect("free");
        assert!(locks.try_lock(&destination).await.unwrap().is_none());
        // Dropped without its release: its connection closes, and with it
        // the lock.
        drop(elsewhere);
        let mut again = None;
        for _ in 0..50 {
            again = locks.try_lock(&destination).await.unwrap();
            if again.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        again.expect("a dropped lock is not kept").release().await;
    }

    fn submission(send_id: Uuid, registration_id: u32) -> SealedMessageSubmissionV1 {
        serde_json::from_value(json!({
            "sendId": send_id.to_string(),
            "capability": STANDARD.encode([2u8; 16]),
            "envelopes": [{
                "deviceId": 1,
                "registrationId": registration_id,
                "suite": 1,
                "content": STANDARD.encode([0x5au8; 96]),
            }],
        }))
        .unwrap()
    }

    async fn outbox_row(pool: &sqlx::PgPool, id: Uuid) -> (String, i64, Option<String>) {
        sqlx::query_as(
            "SELECT state, sequence, last_error_class FROM chat_sealed_federation_outbox
             WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn loaded(pool: &sqlx::PgPool, id: Uuid) -> SealedFederationOutboxRow {
        sqlx::query_as(
            "SELECT id, destination, sequence, recipient_account_id, transaction, attempts
             FROM chat_sealed_federation_outbox WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    const MISMATCH: &[u8] =
        br#"{"code":"deviceListMismatch","missingDevices":[],"staleDevices":[1],"extraDevices":[]}"#;

    /// At the origin: a rejected send resent with the same content gets the
    /// same answer and isn't sent again; resent corrected, it is queued
    /// again under a new sequence with its answer cleared.
    #[tokio::test]
    async fn live_a_rejected_send_is_requeued_only_when_corrected() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let destination = origin();
        let recipient = AccountRef::new(&destination, &Uuid::new_v4().to_string()).unwrap();
        let send_id = Uuid::new_v4();
        let Queued::Row(id) =
            enqueue_sealed_row_in(&pool, "origin.test", &recipient, submission(send_id, 78))
                .await
                .unwrap()
        else {
            panic!("queued");
        };
        let (_, first_sequence, _) = outbox_row(&pool, id).await;
        let row = loaded(&pool, id).await;
        assert!(matches!(
            apply_sealed_answer(&pool, &row, StatusCode::CONFLICT, MISMATCH)
                .await
                .unwrap(),
            FederatedSealedOutcome::Mismatch(_)
        ));
        // The same content: the stored mismatch, nothing queued.
        let same = enqueue_sealed_row_in(&pool, "origin.test", &recipient, submission(send_id, 78))
            .await
            .unwrap();
        assert!(matches!(
            same,
            Queued::Settled(FederatedSealedOutcome::Mismatch(_))
        ));
        assert_eq!(outbox_row(&pool, id).await.0, "rejected");
        // Corrected: the same row, pending under a later sequence.
        let Queued::Row(again) =
            enqueue_sealed_row_in(&pool, "origin.test", &recipient, submission(send_id, 77))
                .await
                .unwrap()
        else {
            panic!("requeued");
        };
        assert_eq!(again, id);
        let (state_name, sequence, class) = outbox_row(&pool, id).await;
        assert_eq!(state_name, "pending");
        assert!(sequence > first_sequence);
        assert_eq!(class, None);
        let stored: FederatedSealedTransactionV1 =
            serde_json::from_value(loaded(&pool, id).await.transaction).unwrap();
        assert_eq!(stored.sequence, sequence as u64);
        assert_eq!(stored.envelopes[0].registration_id, 77);
        sqlx::query("DELETE FROM chat_sealed_federation_outbox WHERE destination = $1")
            .bind(&destination)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The migration's step for sends rejected on a mismatch before this
    /// version: each goes once more under its old sequence (closing it at
    /// the destination); meanwhile a corrected resend is told to wait
    /// (`conflict`), and an identical one stays queued.
    #[tokio::test]
    async fn live_the_migration_closes_old_mismatched_sequences() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let destination = origin();
        let recipient = AccountRef::new(&destination, &Uuid::new_v4().to_string()).unwrap();
        let send_id = Uuid::new_v4();
        let Queued::Row(id) =
            enqueue_sealed_row_in(&pool, "origin.test", &recipient, submission(send_id, 78))
                .await
                .unwrap()
        else {
            panic!("queued");
        };
        // As the old version left it: rejected, no answer kept.
        sqlx::query(
            "UPDATE chat_sealed_federation_outbox
             SET state = 'rejected', last_error_class = 'device_mismatch' WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        let (_, sequence, _) = outbox_row(&pool, id).await;
        let migration = include_str!("../migrations/20261018120000_sealed_sequences.up.sql");
        // The closing step: its UPDATE statement, up to its semicolon.
        let start = migration
            .find("UPDATE chat_sealed_federation_outbox")
            .expect("the closing step");
        let closing = &migration[start..start + migration[start..].find(';').unwrap()];
        assert!(closing.contains("closing_sequence"));
        // Run on this test's destination only: unscoped, it would reopen the
        // rejected rows of tests running beside it.
        sqlx::query(&format!("{closing} AND destination = $1"))
            .bind(&destination)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            outbox_row(&pool, id).await,
            (
                "pending".to_owned(),
                sequence,
                Some("closing_sequence".to_owned())
            )
        );
        let corrected =
            enqueue_sealed_row_in(&pool, "origin.test", &recipient, submission(send_id, 77)).await;
        assert_eq!(corrected.err().unwrap().status, StatusCode::CONFLICT);
        assert!(matches!(
            enqueue_sealed_row_in(&pool, "origin.test", &recipient, submission(send_id, 78))
                .await
                .unwrap(),
            Queued::Row(same) if same == id
        ));
        assert_eq!(outbox_row(&pool, id).await.1, sequence);
        sqlx::query("DELETE FROM chat_sealed_federation_outbox WHERE destination = $1")
            .bind(&destination)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// A sealed single is named by its row and its bytes: a retry of the
    /// same bytes keeps its request id (so the destination can replay its
    /// answer), and the same row resent under a new sequence gets another
    /// (or the destination's replay check refuses it, unsigned).
    #[test]
    fn a_resend_under_a_new_sequence_gets_its_own_request_id() {
        let row = Uuid::new_v4();
        let (recipient, send_id) = (Uuid::new_v4(), Uuid::new_v4());
        let body = |sequence: u64| {
            serde_json::to_vec(&transaction(
                "origin.test",
                recipient,
                sequence,
                send_id,
                [1; 16],
                77,
            ))
            .unwrap()
        };
        assert_eq!(
            delivery_request_id(row, &body(6)),
            delivery_request_id(row, &body(6))
        );
        assert_ne!(
            delivery_request_id(row, &body(6)),
            delivery_request_id(row, &body(7))
        );
    }

    /// [n mismatch, n+1 valid]: the mismatch uses up n, so n+1 is delivered
    /// in the same batch; the corrected resend comes under a new sequence
    /// with the same sendId and is delivered too.
    #[tokio::test]
    async fn live_a_mismatch_holds_nothing_behind_it() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let origin = origin();
        let capability = [0x61; 16];
        let carol = recipient(&pool, capability).await;
        let (stale, next) = (Uuid::new_v4(), Uuid::new_v4());
        let sent = batch(
            &origin,
            vec![
                transaction(&origin, carol, 1, stale, capability, 78),
                transaction(&origin, carol, 2, next, capability, 77),
            ],
        );
        let (response, delivered) = apply_sealed_batch(&pool, DESTINATION, &origin, &sent)
            .await
            .unwrap();
        let statuses: Vec<u16> = response.results.iter().map(|r| r.status).collect();
        assert_eq!(statuses, [409, 200], "{:?}", response.results);
        assert_eq!(response.results[0].response["code"], "deviceListMismatch");
        assert_eq!(response.results[0].response["staleDevices"], json!([1]));
        assert_eq!(delivered.len(), 1);
        assert_eq!(stored(&pool, carol).await, 1);
        assert_eq!(recorded(&pool, &origin).await, [(1, 409), (2, 200)]);

        // The corrected resend: same sendId, a new sequence.
        let corrected = batch(
            &origin,
            vec![transaction(&origin, carol, 3, stale, capability, 77)],
        );
        let (response, _) = apply_sealed_batch(&pool, DESTINATION, &origin, &corrected)
            .await
            .unwrap();
        assert_eq!(response.results[0].status, 200);
        assert_eq!(response.results[0].response["deduplicated"], false);
        assert_eq!(stored(&pool, carol).await, 2);
        clean(&pool, &origin, &[carol]).await;
    }

    /// A delivered batch sent again gets its stored answers, and nothing is
    /// stored again.
    #[tokio::test]
    async fn live_a_repeated_batch_gets_its_stored_answers() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let origin = origin();
        let capability = [0x62; 16];
        let bob = recipient(&pool, capability).await;
        let sent = batch(
            &origin,
            vec![
                transaction(&origin, bob, 1, Uuid::new_v4(), capability, 77),
                transaction(&origin, bob, 2, Uuid::new_v4(), capability, 77),
                // The uniform 404, recorded like the deliveries.
                transaction(&origin, Uuid::new_v4(), 3, Uuid::new_v4(), capability, 77),
            ],
        );
        let (first, delivered) = apply_sealed_batch(&pool, DESTINATION, &origin, &sent)
            .await
            .unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(stored(&pool, bob).await, 2);
        let (again, delivered) = apply_sealed_batch(&pool, DESTINATION, &origin, &sent)
            .await
            .unwrap();
        assert_eq!(again, first);
        assert!(delivered.is_empty());
        assert_eq!(stored(&pool, bob).await, 2);
        assert_eq!(
            recorded(&pool, &origin).await,
            [(1, 200), (2, 200), (3, 404)]
        );
        clean(&pool, &origin, &[bob]).await;
    }

    /// A batch of the wrong shape is refused whole: nothing of it applied.
    #[tokio::test]
    async fn live_a_malformed_batch_is_refused_before_any_of_it_applies() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let origin = origin();
        let capability = [0x63; 16];
        let bob = recipient(&pool, capability).await;
        let gap = batch(
            &origin,
            vec![
                transaction(&origin, bob, 1, Uuid::new_v4(), capability, 77),
                transaction(&origin, bob, 3, Uuid::new_v4(), capability, 77),
            ],
        );
        let foreign = batch(
            &origin,
            vec![
                transaction(&origin, bob, 1, Uuid::new_v4(), capability, 77),
                transaction("other.test", bob, 2, Uuid::new_v4(), capability, 77),
            ],
        );
        for refused in [gap, foreign] {
            let error = apply_sealed_batch(&pool, DESTINATION, &origin, &refused)
                .await
                .unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
        }
        // Signed by one origin, claiming another.
        let claimed = batch(
            "other.test",
            vec![transaction(
                "other.test",
                bob,
                1,
                Uuid::new_v4(),
                capability,
                77,
            )],
        );
        let error = apply_sealed_batch(&pool, DESTINATION, &origin, &claimed)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(recorded(&pool, &origin).await.is_empty());
        assert_eq!(stored(&pool, bob).await, 0);
        clean(&pool, &origin, &[bob]).await;
    }

    /// An answer to a sequence the row has since left (it was rejected and
    /// queued again under a new one) moves nothing.
    #[tokio::test]
    async fn live_a_stale_answer_moves_no_outbox_row() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let destination = origin();
        let id = Uuid::new_v4();
        let recipient = Uuid::new_v4();
        let current = transaction("origin.test", recipient, 5, Uuid::new_v4(), [1; 16], 77);
        sqlx::query(
            "INSERT INTO chat_sealed_federation_outbox
                 (id, destination, sequence, recipient_account_id, send_id, transaction)
             VALUES ($1, $2, 5, $3, $4, $5)",
        )
        .bind(id)
        .bind(&destination)
        .bind(recipient)
        .bind(Uuid::new_v4())
        .bind(serde_json::to_value(&current).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let row = |sequence: i64| SealedFederationOutboxRow {
            id,
            destination: destination.clone(),
            sequence,
            recipient_account_id: recipient,
            transaction: serde_json::to_value(&current).unwrap(),
            attempts: 0,
        };
        let mismatch = br#"{"code":"deviceListMismatch","missingDevices":[],"staleDevices":[1],"extraDevices":[]}"#;
        let state_of = || async {
            sqlx::query_as::<_, (String, i64)>(
                "SELECT state, sequence FROM chat_sealed_federation_outbox WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        // The answer to the old sequence 4: no change.
        let outcome = apply_sealed_answer(&pool, &row(4), StatusCode::CONFLICT, mismatch)
            .await
            .unwrap();
        assert!(matches!(outcome, FederatedSealedOutcome::Pending));
        assert_eq!(state_of().await, ("pending".to_owned(), 5));
        let outcome = apply_sealed_answer(
            &pool,
            &row(4),
            StatusCode::OK,
            br#"{"stored":1,"deduplicated":false}"#,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, FederatedSealedOutcome::Pending));
        assert_eq!(state_of().await, ("pending".to_owned(), 5));
        // The answer to its own sequence moves it.
        let outcome = apply_sealed_answer(&pool, &row(5), StatusCode::CONFLICT, mismatch)
            .await
            .unwrap();
        assert!(matches!(outcome, FederatedSealedOutcome::Mismatch(_)));
        assert_eq!(state_of().await, ("rejected".to_owned(), 5));
        // A client whose flush didn't reach it (the worker's did) reads the
        // answer from the row: the mismatch itself, not "pending".
        let read_back = SealedFlush::new().outcome(&pool, id).await.unwrap();
        match read_back {
            FederatedSealedOutcome::Mismatch(mismatch) => {
                assert_eq!(mismatch.stale_devices, [1])
            }
            _ => panic!("the stored mismatch is read back"),
        }
        sqlx::query("DELETE FROM chat_sealed_federation_outbox WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
