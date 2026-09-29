//! Live editing across servers (docs/plans/collab-federation.md), Matrix
//! style: servers push signed batches to each other; a browser only ever
//! talks to its own server.
//!
//! - **Home** (the file's server) keeps subscriptions from other servers
//!   ("bridges") and pushes every new frame to each, reading the file's log
//!   from the last position it delivered, so nothing is skipped or reordered.
//!   It takes frames, log ranges, versions and the first-content seed from
//!   bridges, authorized by the share's capability.
//! - **Bridge** (the remote editor's server) keeps a local room for the remote
//!   file, checks its users' frames as the relay does, passes them to its
//!   other local peers at once, batches them home, and hands home's pushes to
//!   its room.
//!
//! Frames stay sealed end to end; servers only check public headers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use kutup_crypto::envelope::{self, Frame};
use kutup_federation_proto::{content_digest_sha256_from_digest, FederationFeature};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Notify};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::drive_federation::{
    capability_hash, configured_stack, drive_spec, ensure_version_digest, gateway_error,
    signed_app_error, signed_json, validate_capability, JSON_CONTENT_TYPE, MAX_DRIVE_OBJECT_BYTES,
    OCTET_STREAM_CONTENT_TYPE, SHARE_CAPABILITY_HEADER,
};
use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationStack};
use crate::handlers::collab::{
    authenticate_socket, broadcast_peers, frame_binding, is_presence, log_head, peer_summaries,
    persist_frame, CollabQuery, FrameBudget, Hello, Sender, ACCESS_RECHECK,
};
use crate::handlers::file_versions::{store_version, to_version_row, VersionTuple, VERSION_SELECT};
use crate::handlers::trusted_uuid;
use crate::hub::{self, WsOut};
use crate::middleware::AuthUser;
use crate::AppState;

/// Frames arriving within this window go home (or to a bridge) together.
const BATCH_WINDOW: Duration = Duration::from_millis(50);
/// A subscription lives this long unless renewed.
const LEASE: Duration = Duration::from_secs(60);
/// Bridges renew well before the lease ends.
const RENEW_EVERY: Duration = Duration::from_secs(20);
/// Frames per push; more follow at once.
const PUSH_ROWS: i64 = 500;
/// Relayed-only frames (cursors, strokes) waiting per subscription; the
/// oldest go first when a bridge is slow (they are superseded anyway).
const MAX_EPHEMERAL: usize = 256;
/// Failed pushes in a row before a subscription is dropped (the bridge
/// subscribes again if it is still there).
const MAX_PUSH_FAILURES: u32 = 8;
/// The largest request carrying a version's sealed blob.
pub const VERSION_BODY_LIMIT: usize = 48 * 1024 * 1024;
/// A sealed asset envelope (a picture in a note or on a whiteboard).
const MAX_ASSET_ENVELOPE: usize = kutup_crypto::drive_envelope::MAX_WHITEBOARD_ASSET_ENVELOPE_BYTES;
/// An asset sent home: its envelope in base64, and the JSON around it.
pub const ASSET_BODY_LIMIT: usize = MAX_ASSET_ENVELOPE / 3 * 4 + 64 * 1024;
const MAX_VERSION_BLOB: usize = 32 * 1024 * 1024;
const MAX_LOG_RESPONSE: usize = 64 * 1024 * 1024;
const MAX_JSON_RESPONSE: usize = 4 * 1024 * 1024;

/// Both halves' in-memory state.
#[derive(Default)]
pub struct CollabFederation {
    /// Home: file → subscription id → subscriber.
    home: Mutex<HashMap<Uuid, HashMap<String, Arc<Subscriber>>>>,
    /// Bridge: room key → bridge.
    bridges: Mutex<HashMap<String, Arc<Bridge>>>,
}

// ================================================================== home

struct Subscriber {
    id: String,
    domain: String,
    file_id: Uuid,
    inner: Mutex<SubscriberState>,
    wake: Notify,
    stopped: AtomicBool,
}

struct SubscriberState {
    expires: Instant,
    /// The log position delivered so far.
    sent_through: i64,
    ephemeral: Vec<Vec<u8>>,
    /// Kept frames this bridge may send, as a connection's budget.
    budget: FrameBudget,
}

impl CollabFederation {
    /// A frame was kept in a file's log: wake its subscribers.
    pub fn kept(&self, file_id: Uuid) {
        for sub in self.subscribers(file_id) {
            sub.wake.notify_one();
        }
    }

    /// A relayed-only frame (cursor, stroke) for subscribers other than the
    /// server it came from.
    pub fn relayed(&self, file_id: Uuid, origin: Option<&str>, frame: &[u8]) {
        for sub in self.subscribers(file_id) {
            if Some(sub.domain.as_str()) == origin {
                continue;
            }
            {
                let mut inner = sub.inner.lock().unwrap();
                if inner.ephemeral.len() >= MAX_EPHEMERAL {
                    inner.ephemeral.remove(0);
                }
                inner.ephemeral.push(frame.to_vec());
            }
            sub.wake.notify_one();
        }
    }

    /// The file moved to a new key (or went away): every bridge's room closes
    /// and its editors reconnect, as local ones do.
    pub fn close_file(&self, state: &AppState, file_id: Uuid) {
        let subs = self
            .home
            .lock()
            .unwrap()
            .remove(&file_id)
            .unwrap_or_default();
        for sub in subs.into_values() {
            sub.stopped.store(true, Ordering::Relaxed);
            sub.wake.notify_one();
            let state = state.clone();
            tokio::spawn(async move {
                let _ = push(
                    &state,
                    &sub,
                    &PushBody {
                        subscription_id: sub.id.clone(),
                        file_id: sub.file_id,
                        frames: Vec::new(),
                        ephemeral: Vec::new(),
                        through_seq: 0,
                        floor: 0,
                        close: true,
                    },
                )
                .await;
            });
        }
    }

    fn subscribers(&self, file_id: Uuid) -> Vec<Arc<Subscriber>> {
        self.home
            .lock()
            .unwrap()
            .get(&file_id)
            .map(|subs| subs.values().cloned().collect())
            .unwrap_or_default()
    }

    fn subscriber(&self, file_id: Uuid, id: &str, domain: &str) -> Option<Arc<Subscriber>> {
        self.home
            .lock()
            .unwrap()
            .get(&file_id)
            .and_then(|subs| subs.get(id))
            .filter(|sub| sub.domain == domain)
            .cloned()
    }

    fn drop_subscriber(&self, sub: &Subscriber) {
        sub.stopped.store(true, Ordering::Relaxed);
        let mut home = self.home.lock().unwrap();
        if let Some(subs) = home.get_mut(&sub.file_id) {
            if subs
                .get(&sub.id)
                .is_some_and(|s| std::ptr::eq(s.as_ref(), sub))
            {
                subs.remove(&sub.id);
            }
            if subs.is_empty() {
                home.remove(&sub.file_id);
            }
        }
    }
}

/// What a share's capability allows on one file, for the calling server.
struct RemoteAccess {
    can_write: bool,
}

/// The capability on a signed request, checked against the file: a file
/// shared by itself with the calling server, or a folder shared with it that
/// holds the file. Either must be live. Editing also needs the share's edit
/// right and the file's key current (as for local editors).
async fn remote_access(
    state: &AppState,
    authenticated: &AuthenticatedFederationRequest,
    headers: &HeaderMap,
    file_id: Uuid,
) -> AppResult<RemoteAccess> {
    let capability = headers
        .get(SHARE_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::not_found("Drive share not found"))?;
    validate_capability(capability).map_err(|_| AppError::not_found("Drive share not found"))?;
    let hash = capability_hash(capability);
    let file: Option<bool> = sqlx::query_scalar(
        "SELECT s.can_edit AND s.key_generation = f.key_generation AND f.key_epoch = c.key_epoch
         FROM federated_outgoing_file_shares s
         JOIN files f ON f.id = s.file_id AND f.deleted_at IS NULL
         JOIN collections c ON c.id = f.collection_id AND c.deleted_at IS NULL
         WHERE s.capability_hash = $1 AND s.recipient_domain = $2 AND s.file_id = $3",
    )
    .bind(&hash)
    .bind(authenticated.origin())
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some(can_write) = file {
        return Ok(RemoteAccess { can_write });
    }
    let folder: Option<bool> = sqlx::query_scalar(
        "SELECT s.can_upload AND f.key_epoch = c.key_epoch
         FROM federated_outgoing_shares s
         JOIN collections c ON c.id = s.collection_id AND c.deleted_at IS NULL
         JOIN files f ON f.collection_id = c.id AND f.deleted_at IS NULL
         WHERE s.capability_hash = $1 AND s.recipient_domain = $2 AND f.id = $3",
    )
    .bind(&hash)
    .bind(authenticated.origin())
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?;
    folder
        .map(|can_write| RemoteAccess { can_write })
        .ok_or_else(|| AppError::not_found("Drive share not found"))
}

/// Authenticates a signed JSON request and parses its body.
async fn inbound<'a, T: DeserializeOwned>(
    state: &'a AppState,
    headers: &HeaderMap,
    path: &str,
    body: &Bytes,
) -> AppResult<(
    &'a FederationStack,
    AuthenticatedFederationRequest,
    AppResult<T>,
)> {
    let federation = configured_stack(state)?;
    let authenticated = federation
        .authenticate_inbound(
            headers,
            "POST",
            path,
            None,
            body,
            FederationFeature::DriveV1,
        )
        .await?;
    let parsed =
        serde_json::from_slice(body).map_err(|_| AppError::bad_request("invalid request body"));
    Ok((federation, authenticated, parsed))
}

/// Answers `result` signed; errors too.
fn answer(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    result: AppResult<Response>,
) -> AppResult<Response> {
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, authenticated, error),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscribeBody {
    file_id: Uuid,
    subscription_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscribeResponse {
    head_seq: i64,
    current_doc_key_id: i64,
    floor: i64,
    can_write: bool,
}

fn valid_subscription_id(id: &str) -> bool {
    (16..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `POST /api/fed/drive/collab/subscribe` — a bridge has people in a file's
/// room: push it every new frame from now on. Renews an existing
/// subscription. Signed, capability-authorized.
pub async fn subscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) =
        inbound::<SubscribeBody>(&state, &headers, "/api/fed/drive/collab/subscribe", &body)
            .await?;
    let result = async {
        let request = parsed?;
        if !valid_subscription_id(&request.subscription_id) {
            return Err(AppError::bad_request("invalid subscription id"));
        }
        let access = remote_access(&state, &authenticated, &headers, request.file_id).await?;
        let head = log_head(&state.pool, request.file_id).await?;
        let (doc_key, floor): (i64, i64) =
            sqlx::query_as("SELECT current_doc_key_id, collab_log_floor FROM files WHERE id = $1")
                .bind(request.file_id)
                .fetch_one(&state.pool)
                .await?;
        let domain = authenticated.origin().to_owned();
        let existing =
            state
                .collab_federation
                .subscriber(request.file_id, &request.subscription_id, &domain);
        match existing {
            Some(sub) => sub.inner.lock().unwrap().expires = Instant::now() + LEASE,
            None => {
                let sub = Arc::new(Subscriber {
                    id: request.subscription_id.clone(),
                    domain,
                    file_id: request.file_id,
                    inner: Mutex::new(SubscriberState {
                        expires: Instant::now() + LEASE,
                        sent_through: head,
                        ephemeral: Vec::new(),
                        budget: FrameBudget::new(),
                    }),
                    wake: Notify::new(),
                    stopped: AtomicBool::new(false),
                });
                state
                    .collab_federation
                    .home
                    .lock()
                    .unwrap()
                    .entry(request.file_id)
                    .or_default()
                    .insert(sub.id.clone(), sub.clone());
                tokio::spawn(pusher(state.clone(), sub));
            }
        }
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &SubscribeResponse {
                head_seq: head,
                current_doc_key_id: doc_key,
                floor,
                can_write: access.can_write,
            },
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

/// `POST /api/fed/drive/collab/unsubscribe` — nobody is left in the
/// bridge's room.
pub async fn unsubscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) =
        inbound::<SubscribeBody>(&state, &headers, "/api/fed/drive/collab/unsubscribe", &body)
            .await?;
    let result = async {
        let request = parsed?;
        if let Some(sub) = state.collab_federation.subscriber(
            request.file_id,
            &request.subscription_id,
            authenticated.origin(),
        ) {
            state.collab_federation.drop_subscriber(&sub);
            sub.wake.notify_one();
        }
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &serde_json::json!({}),
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PushedFrame {
    seq: i64,
    /// Base64.
    frame: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PushBody {
    subscription_id: String,
    file_id: Uuid,
    frames: Vec<PushedFrame>,
    /// Relayed-only frames, base64.
    ephemeral: Vec<String>,
    /// Everything up to here is delivered (some positions are the bridge's own).
    through_seq: i64,
    /// A saved version trimmed the log up to here.
    floor: i64,
    /// The room is closing (the file moved to a new key, or went away).
    #[serde(default)]
    close: bool,
}

async fn push(state: &AppState, sub: &Subscriber, body: &PushBody) -> Result<StatusCode, AppError> {
    let federation = configured_stack(state)?;
    let bytes = serde_json::to_vec(body).map_err(|_| AppError::internal("encode push"))?;
    let response = federation
        .send(
            &sub.domain,
            drive_spec(
                Method::POST,
                "/api/fed/drive/collab/push".into(),
                JSON_CONTENT_TYPE.into(),
                bytes,
                None,
                MAX_JSON_RESPONSE,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    Ok(response.status)
}

/// One subscription's sender: after each wake it reads the log from the last
/// delivered position, adds waiting relayed frames, and pushes them in one
/// signed request (after a short window, so typing is batched).
async fn pusher(state: AppState, sub: Arc<Subscriber>) {
    let mut failures: u32 = 0;
    loop {
        tokio::select! {
            _ = sub.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
        if sub.stopped.load(Ordering::Relaxed) {
            break;
        }
        if sub.inner.lock().unwrap().expires < Instant::now() {
            state.collab_federation.drop_subscriber(&sub);
            break;
        }
        tokio::time::sleep(BATCH_WINDOW).await;
        loop {
            let sent_through = sub.inner.lock().unwrap().sent_through;
            let rows: Vec<(i64, Vec<u8>, Option<String>)> = match sqlx::query_as(
                "SELECT seq, frame, remote_domain FROM file_update_log
                 WHERE file_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3",
            )
            .bind(sub.file_id)
            .bind(sent_through)
            .bind(PUSH_ROWS)
            .fetch_all(&state.pool)
            .await
            {
                Ok(rows) => rows,
                Err(_) => break,
            };
            let floor: i64 = sqlx::query_scalar("SELECT collab_log_floor FROM files WHERE id = $1")
                .bind(sub.file_id)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten()
                .unwrap_or(0);
            let ephemeral = std::mem::take(&mut sub.inner.lock().unwrap().ephemeral);
            let through = rows
                .last()
                .map_or(sent_through, |row| row.0)
                .max(sent_through);
            let full = rows.len() as i64 == PUSH_ROWS;
            let frames: Vec<PushedFrame> = rows
                .into_iter()
                // Never echo a bridge its own frames (it has them, with positions).
                .filter(|(_, _, origin)| origin.as_deref() != Some(sub.domain.as_str()))
                .map(|(seq, frame, _)| PushedFrame {
                    seq,
                    frame: STANDARD.encode(frame),
                })
                .collect();
            if frames.is_empty()
                && ephemeral.is_empty()
                && through == sent_through
                && floor <= sent_through
            {
                break;
            }
            let body = PushBody {
                subscription_id: sub.id.clone(),
                file_id: sub.file_id,
                frames,
                ephemeral: ephemeral.iter().map(|f| STANDARD.encode(f)).collect(),
                through_seq: through,
                floor,
                close: false,
            };
            match push(&state, &sub, &body).await {
                Ok(StatusCode::OK) => {
                    failures = 0;
                    let mut inner = sub.inner.lock().unwrap();
                    inner.sent_through = inner.sent_through.max(through).max(floor);
                }
                // The bridge no longer has this room.
                Ok(StatusCode::NOT_FOUND) | Ok(StatusCode::GONE) => {
                    state.collab_federation.drop_subscriber(&sub);
                    return;
                }
                _ => {
                    failures += 1;
                    if failures >= MAX_PUSH_FAILURES {
                        tracing::warn!(file = %sub.file_id, domain = %sub.domain, "collab push failing: subscription dropped");
                        state.collab_federation.drop_subscriber(&sub);
                        return;
                    }
                    // Cursors are superseded by then; kept frames are re-read.
                    tokio::time::sleep(Duration::from_secs(1 << failures.min(5))).await;
                    sub.wake.notify_one();
                    break;
                }
            }
            if !full {
                break;
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FramesBody {
    file_id: Uuid,
    subscription_id: String,
    /// Base64 sealed frames, in the order they were made.
    frames: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FramesResponse {
    /// Each frame's log position; null for relayed-only or refused frames.
    positions: Vec<Option<i64>>,
}

/// `POST /api/fed/drive/collab/frames` — frames from a bridge's editors,
/// already checked there against their devices. Home checks them against the
/// file and the share, keeps the durable ones, and sends them to its room and
/// to other bridges. Signed, capability-authorized.
pub async fn frames(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) =
        inbound::<FramesBody>(&state, &headers, "/api/fed/drive/collab/frames", &body).await?;
    let result = async {
        let request = parsed?;
        let access = remote_access(&state, &authenticated, &headers, request.file_id).await?;
        let domain = authenticated.origin().to_owned();
        let sub = state
            .collab_federation
            .subscriber(request.file_id, &request.subscription_id, &domain)
            .ok_or_else(|| AppError::not_found("subscription not found"))?;
        let room = request.file_id.to_string();
        let mut positions = Vec::with_capacity(request.frames.len());
        let mut kept_any = false;
        for encoded in &request.frames {
            let Ok(raw) = STANDARD.decode(encoded) else {
                positions.push(None);
                continue;
            };
            let Ok(frame) = Frame::unpack(&raw) else {
                positions.push(None);
                continue;
            };
            if frame.sequence > i64::MAX as u64 {
                positions.push(None);
                continue;
            }
            let Some(key_current) = frame_binding(&state, request.file_id, &frame).await else {
                positions.push(None);
                continue;
            };
            if is_presence(frame.kind) {
                state.hub.broadcast(&room, 0, &raw).await;
                state
                    .collab_federation
                    .relayed(request.file_id, Some(&domain), &raw);
                positions.push(None);
                continue;
            }
            if !access.can_write
                || !key_current
                || !sub.inner.lock().unwrap().budget.take(raw.len())
            {
                positions.push(None);
                continue;
            }
            if frame.kind == envelope::kind::EXCALIDRAW_OP {
                state.hub.broadcast(&room, 0, &raw).await;
                state
                    .collab_federation
                    .relayed(request.file_id, Some(&domain), &raw);
                positions.push(None);
                continue;
            }
            let sender = Sender::Remote {
                domain: &domain,
                device: frame.sender_device_id as i64,
            };
            match persist_frame(&state, request.file_id, sender, &frame, &raw).await {
                Ok(seq) => {
                    state.hub.broadcast(&room, 0, &raw).await;
                    state
                        .hub
                        .broadcast_text(
                            &room,
                            &serde_json::json!({ "type": "stored", "seq": seq }).to_string(),
                        )
                        .await;
                    kept_any = true;
                    positions.push(Some(seq));
                }
                Err(_) => positions.push(None),
            }
        }
        if kept_any {
            state.collab_federation.kept(request.file_id);
        }
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &FramesResponse { positions },
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogBody {
    file_id: Uuid,
    since: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogResponse {
    frames: Vec<PushedFrame>,
    through_seq: i64,
    floor: i64,
}

/// `POST /api/fed/drive/collab/log` — the kept frames after a position, for
/// a bridge's editor catching up (as a local one resumes). Signed.
pub async fn log(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) =
        inbound::<LogBody>(&state, &headers, "/api/fed/drive/collab/log", &body).await?;
    let result = async {
        let request = parsed?;
        remote_access(&state, &authenticated, &headers, request.file_id).await?;
        let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT seq, frame FROM file_update_log WHERE file_id = $1 AND seq > $2 ORDER BY seq ASC",
        )
        .bind(request.file_id)
        .bind(request.since)
        .fetch_all(&state.pool)
        .await?;
        let floor: i64 = sqlx::query_scalar("SELECT collab_log_floor FROM files WHERE id = $1")
            .bind(request.file_id)
            .fetch_one(&state.pool)
            .await?;
        let through = rows.last().map_or(request.since, |row| row.0);
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &LogResponse {
                frames: rows
                    .into_iter()
                    .map(|(seq, frame)| PushedFrame {
                        seq,
                        frame: STANDARD.encode(frame),
                    })
                    .collect(),
                through_seq: through,
                floor,
            },
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileBody {
    file_id: Uuid,
}

/// `POST /api/fed/drive/collab/versions/list` — a file's versions. Signed.
pub async fn versions_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) = inbound::<FileBody>(
        &state,
        &headers,
        "/api/fed/drive/collab/versions/list",
        &body,
    )
    .await?;
    let result = async {
        let request = parsed?;
        remote_access(&state, &authenticated, &headers, request.file_id).await?;
        let rows: Vec<VersionTuple> = sqlx::query_as(&format!(
            "{VERSION_SELECT} WHERE file_id = $1 ORDER BY created_at DESC"
        ))
        .bind(request.file_id)
        .fetch_all(&state.pool)
        .await?;
        let out: Vec<_> = rows.into_iter().map(to_version_row).collect();
        signed_json(federation, &authenticated, StatusCode::OK, &out)
    }
    .await;
    answer(federation, &authenticated, result)
}

/// `GET /api/fed/drive/collab/files/{fileId}/versions/{vid}` — one version's
/// sealed blob, as a signed stream.
pub async fn version_content(
    State(state): State<AppState>,
    Path((file_id, vid)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/collab/files/{file_id}/versions/{vid}");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result = async {
        let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
        let vid = Uuid::parse_str(&vid).map_err(|_| AppError::not_found("not found"))?;
        remote_access(&state, &authenticated, &headers, file_id).await?;
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT storage_path, s3_version_id, size_bytes FROM file_versions WHERE id = $1 AND file_id = $2",
        )
        .bind(vid)
        .bind(file_id)
        .fetch_optional(&state.pool)
        .await?;
        let (path, s3_version_id, size) = row.ok_or_else(|| AppError::not_found("not found"))?;
        let content = crate::file_content::CurrentContent {
            path,
            s3_version_id: Some(s3_version_id).filter(|v| !v.is_empty()),
            size,
            version: Some(vid),
        };
        let digest = ensure_version_digest(&state, vid, &content).await?;
        let digest: [u8; 32] = hex::decode(&digest)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| AppError::internal("invalid stored digest"))?;
        let (object, object_size) = content
            .open(&state.storage)
            .await
            .map_err(|error| AppError::internal(format!("read version: {error}")))?;
        federation.signed_stream_response(
            &authenticated,
            StatusCode::OK,
            OCTET_STREAM_CONTENT_TYPE,
            &content_digest_sha256_from_digest(&digest),
            object_size as u64,
            Body::from_stream(ReaderStream::new(object.into_async_read())),
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateVersionBody {
    file_id: Uuid,
    /// Who saved it, `user@server` on the calling server.
    author: String,
    kind: String,
    seq_at_snapshot: i64,
    doc_key_id: i64,
    label: Option<String>,
    keep_forever: bool,
    /// The sealed blob, base64.
    blob: String,
}

/// `POST /api/fed/drive/collab/versions/create` — a version saved by an
/// editor on the calling server. Checked as a local save; the file's owner
/// pays (as for uploads into shared folders across servers).
pub async fn versions_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) = inbound::<CreateVersionBody>(
        &state,
        &headers,
        "/api/fed/drive/collab/versions/create",
        &body,
    )
    .await?;
    let result = async {
        let request = parsed?;
        let access = remote_access(&state, &authenticated, &headers, request.file_id).await?;
        if !access.can_write {
            return Err(AppError::forbidden("this share does not allow editing"));
        }
        let author_ok = request.author.len() <= 320
            && request
                .author
                .rsplit_once('@')
                .is_some_and(|(user, server)| !user.is_empty() && server == authenticated.origin());
        if !author_ok {
            return Err(AppError::bad_request("invalid author"));
        }
        let blob = STANDARD
            .decode(&request.blob)
            .map_err(|_| AppError::bad_request("invalid blob"))?;
        if blob.len() > MAX_VERSION_BLOB {
            return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "version too large"));
        }
        let mut file = tempfile::NamedTempFile::new().map_err(|_| AppError::internal("temp file"))?;
        std::io::Write::write_all(&mut file, &blob).map_err(|_| AppError::internal("temp write"))?;
        let owner: Uuid = sqlx::query_scalar(
            "SELECT c.owner_user_id FROM files f JOIN collections c ON c.id = f.collection_id WHERE f.id = $1",
        )
        .bind(request.file_id)
        .fetch_one(&state.pool)
        .await?;
        let mut fields = HashMap::new();
        fields.insert("kind".to_owned(), request.kind);
        fields.insert("seqAtSnapshot".to_owned(), request.seq_at_snapshot.to_string());
        fields.insert("docKeyId".to_owned(), request.doc_key_id.to_string());
        if let Some(label) = request.label {
            fields.insert("label".to_owned(), label);
        }
        fields.insert("keepForever".to_owned(), request.keep_forever.to_string());
        let created = store_version(
            &state,
            request.file_id,
            owner,
            Some(&request.author),
            &fields,
            file,
            blob.len() as i64,
        )
        .await?;
        signed_json(federation, &authenticated, StatusCode::CREATED, &created)
    }
    .await;
    answer(federation, &authenticated, result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateAssetBody {
    file_id: Uuid,
    asset_id: String,
    /// The sealed asset envelope, base64.
    blob: String,
}

/// `POST /api/fed/drive/collab/assets/create` — a picture pasted into a note
/// (or placed on a whiteboard) by an editor on the calling server. Checked as
/// a local upload; the file's owner pays, as for versions.
pub async fn assets_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) = inbound::<CreateAssetBody>(
        &state,
        &headers,
        "/api/fed/drive/collab/assets/create",
        &body,
    )
    .await?;
    let result = async {
        let request = parsed?;
        let access = remote_access(&state, &authenticated, &headers, request.file_id).await?;
        if !access.can_write {
            return Err(AppError::forbidden("this share does not allow editing"));
        }
        let blob = STANDARD
            .decode(&request.blob)
            .map_err(|_| AppError::bad_request("invalid blob"))?;
        let owner: Uuid = sqlx::query_scalar(
            "SELECT c.owner_user_id FROM files f JOIN collections c ON c.id = f.collection_id WHERE f.id = $1",
        )
        .bind(request.file_id)
        .fetch_one(&state.pool)
        .await?;
        crate::handlers::file_assets::store_asset(&state, request.file_id, &request.asset_id, owner, blob).await?;
        signed_json(federation, &authenticated, StatusCode::CREATED, &serde_json::json!({}))
    }
    .await;
    answer(federation, &authenticated, result)
}

/// `GET /api/fed/drive/collab/files/{fileId}/assets/{assetId}` — one of a
/// file's assets (its sealed envelope), signed. The key generation it was
/// sealed at is not sent: the browser tries the file's keys, newest first.
pub async fn asset_content(
    State(state): State<AppState>,
    Path((file_id, asset_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/collab/files/{file_id}/assets/{asset_id}");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result = async {
        let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
        remote_access(&state, &authenticated, &headers, file_id).await?;
        let (bytes, _) =
            crate::handlers::file_assets::load_asset(&state, file_id, &asset_id).await?;
        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&bytes).into();
        federation.signed_stream_response(
            &authenticated,
            StatusCode::OK,
            OCTET_STREAM_CONTENT_TYPE,
            &content_digest_sha256_from_digest(&digest),
            bytes.len() as u64,
            Body::from(bytes),
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchVersionBody {
    file_id: Uuid,
    version_id: Uuid,
    label: Option<String>,
    keep_forever: Option<bool>,
}

/// `POST /api/fed/drive/collab/versions/patch` — name or pin a version.
pub async fn versions_patch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) = inbound::<PatchVersionBody>(
        &state,
        &headers,
        "/api/fed/drive/collab/versions/patch",
        &body,
    )
    .await?;
    let result = async {
        let request = parsed?;
        let access = remote_access(&state, &authenticated, &headers, request.file_id).await?;
        if !access.can_write {
            return Err(AppError::forbidden("this share does not allow editing"));
        }
        let label = request.label.map(|l| l.trim().to_string());
        if label.as_ref().is_some_and(|l| l.chars().count() > 200) {
            return Err(AppError::bad_request("label is too long"));
        }
        if let Some(label) = label {
            sqlx::query(
                "UPDATE file_versions SET label = NULLIF($1, '') WHERE id = $2 AND file_id = $3",
            )
            .bind(label)
            .bind(request.version_id)
            .bind(request.file_id)
            .execute(&state.pool)
            .await?;
        }
        if let Some(keep) = request.keep_forever {
            sqlx::query(
                "UPDATE file_versions SET keep_forever = $1 WHERE id = $2 AND file_id = $3",
            )
            .bind(keep)
            .bind(request.version_id)
            .bind(request.file_id)
            .execute(&state.pool)
            .await?;
        }
        let row: VersionTuple =
            sqlx::query_as(&format!("{VERSION_SELECT} WHERE id = $1 AND file_id = $2"))
                .bind(request.version_id)
                .bind(request.file_id)
                .fetch_optional(&state.pool)
                .await?
                .ok_or_else(|| AppError::not_found("not found"))?;
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &to_version_row(row),
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

/// `POST /api/fed/drive/collab/claim-seed` — whether the calling server's
/// editor seeds a never-saved document (as `/api/files/{id}/claim-seed`).
pub async fn claim_seed(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) =
        inbound::<FileBody>(&state, &headers, "/api/fed/drive/collab/claim-seed", &body).await?;
    let result = async {
        let request = parsed?;
        let access = remote_access(&state, &authenticated, &headers, request.file_id).await?;
        if !access.can_write {
            return Err(AppError::forbidden("this share does not allow editing"));
        }
        let claimed: Option<Uuid> = sqlx::query_scalar(
            "UPDATE files SET seed_committed = true WHERE id = $1 AND seed_committed = false RETURNING id",
        )
        .bind(request.file_id)
        .fetch_optional(&state.pool)
        .await?;
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &serde_json::json!({ "committed": claimed.is_some() }),
        )
    }
    .await;
    answer(federation, &authenticated, result)
}

// ================================================================ bridge

/// Where a remote file lives, as its bridge reaches it.
#[derive(Clone)]
struct RemoteTarget {
    domain: String,
    capability: String,
    file_id: Uuid,
}

struct Bridge {
    key: String,
    target: RemoteTarget,
    subscription_id: String,
    can_write: AtomicBool,
    /// The highest position announced to the room.
    announced: Mutex<i64>,
    outbound: mpsc::Sender<Vec<u8>>,
    stopped: AtomicBool,
    stop: Notify,
}

fn room_key(target: &RemoteTarget) -> String {
    format!("remote:{}:{}", target.domain, target.file_id)
}

impl CollabFederation {
    fn bridge_by_subscription(&self, id: &str) -> Option<Arc<Bridge>> {
        self.bridges
            .lock()
            .unwrap()
            .values()
            .find(|b| b.subscription_id == id)
            .cloned()
    }

    fn remove_bridge(&self, bridge: &Bridge) {
        bridge.stopped.store(true, Ordering::Relaxed);
        bridge.stop.notify_waiters();
        let mut bridges = self.bridges.lock().unwrap();
        if bridges
            .get(&bridge.key)
            .is_some_and(|b| std::ptr::eq(b.as_ref(), bridge))
        {
            bridges.remove(&bridge.key);
        }
    }
}

/// A signed, capability-carrying JSON request to a remote file's home.
async fn call_home<T: Serialize, R: DeserializeOwned>(
    state: &AppState,
    target: &RemoteTarget,
    path: &str,
    body: &T,
    limit: usize,
) -> AppResult<R> {
    let federation = configured_stack(state)?;
    let bytes = serde_json::to_vec(body).map_err(|_| AppError::internal("encode request"))?;
    let response = federation
        .send(
            &target.domain,
            drive_spec(
                Method::POST,
                path.to_owned(),
                JSON_CONTENT_TYPE.into(),
                bytes,
                Some(&target.capability),
                limit,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    match response.status {
        s if s.is_success() => serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "invalid answer from the file's server",
            )
        }),
        StatusCode::NOT_FOUND => Err(AppError::not_found("no longer shared")),
        StatusCode::FORBIDDEN => Err(AppError::forbidden("this share does not allow that")),
        StatusCode::PAYLOAD_TOO_LARGE => Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        )),
        StatusCode::CONFLICT => Err(AppError::conflict("the file changed; reload")),
        other => Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("the file's server answered {other}"),
        )),
    }
}

/// Joins (or starts) the bridge for a remote file: subscribes at home, and
/// answers with what a `hello` needs.
async fn bridge_join(
    state: &AppState,
    target: &RemoteTarget,
) -> AppResult<(Arc<Bridge>, SubscribeResponse)> {
    let key = room_key(target);
    let (bridge, fresh) = {
        let mut bridges = state.collab_federation.bridges.lock().unwrap();
        match bridges.get(&key) {
            Some(bridge) if !bridge.stopped.load(Ordering::Relaxed) => (bridge.clone(), None),
            _ => {
                let (tx, rx) = mpsc::channel(1024);
                let bridge = Arc::new(Bridge {
                    key: key.clone(),
                    target: target.clone(),
                    subscription_id: Uuid::new_v4().simple().to_string(),
                    can_write: AtomicBool::new(false),
                    announced: Mutex::new(0),
                    outbound: tx,
                    stopped: AtomicBool::new(false),
                    stop: Notify::new(),
                });
                bridges.insert(key, bridge.clone());
                (bridge, Some(rx))
            }
        }
    };
    let subscribed: AppResult<SubscribeResponse> = call_home(
        state,
        &bridge.target,
        "/api/fed/drive/collab/subscribe",
        &SubscribeBody {
            file_id: bridge.target.file_id,
            subscription_id: bridge.subscription_id.clone(),
        },
        MAX_JSON_RESPONSE,
    )
    .await;
    let subscribed = match subscribed {
        Ok(response) => response,
        Err(error) => {
            if fresh.is_some() {
                state.collab_federation.remove_bridge(&bridge);
            }
            return Err(error);
        }
    };
    bridge
        .can_write
        .store(subscribed.can_write, Ordering::Relaxed);
    {
        let mut announced = bridge.announced.lock().unwrap();
        *announced = (*announced).max(subscribed.head_seq);
    }
    if let Some(rx) = fresh {
        tokio::spawn(bridge_sender(state.clone(), bridge.clone(), rx));
        tokio::spawn(bridge_renewer(state.clone(), bridge.clone()));
    }
    Ok((bridge, subscribed))
}

/// Ends the bridge when its room has emptied: unsubscribes at home.
fn bridge_release(state: &AppState, bridge: &Arc<Bridge>) {
    if !state.hub.peers(&bridge.key).is_empty() {
        return;
    }
    state.collab_federation.remove_bridge(bridge);
    let (state, target, id) = (
        state.clone(),
        bridge.target.clone(),
        bridge.subscription_id.clone(),
    );
    tokio::spawn(async move {
        let _: AppResult<serde_json::Value> = call_home(
            &state,
            &target,
            "/api/fed/drive/collab/unsubscribe",
            &SubscribeBody {
                file_id: target.file_id,
                subscription_id: id,
            },
            MAX_JSON_RESPONSE,
        )
        .await;
    });
}

/// Closes a bridge's room: its editors reconnect (and resubscribe) or learn
/// the file is no longer shared.
fn bridge_close(state: &AppState, bridge: &Bridge) {
    state.collab_federation.remove_bridge(bridge);
    state.hub.close_room(&bridge.key);
}

async fn announce(state: &AppState, bridge: &Bridge, seq: i64) {
    {
        let mut announced = bridge.announced.lock().unwrap();
        *announced = (*announced).max(seq);
    }
    state
        .hub
        .broadcast_text(
            &bridge.key,
            &serde_json::json!({ "type": "stored", "seq": seq }).to_string(),
        )
        .await;
}

/// Sends the room's frames home in batches and announces their positions.
async fn bridge_sender(state: AppState, bridge: Arc<Bridge>, mut rx: mpsc::Receiver<Vec<u8>>) {
    loop {
        let first = tokio::select! {
            frame = rx.recv() => frame,
            _ = bridge.stop.notified() => None,
        };
        let Some(first) = first else { break };
        tokio::time::sleep(BATCH_WINDOW).await;
        let mut batch = vec![first];
        while batch.len() < 256 {
            match rx.try_recv() {
                Ok(frame) => batch.push(frame),
                Err(_) => break,
            }
        }
        let body = FramesBody {
            file_id: bridge.target.file_id,
            subscription_id: bridge.subscription_id.clone(),
            frames: batch.iter().map(|f| STANDARD.encode(f)).collect(),
        };
        let mut attempt = 0;
        loop {
            let sent: AppResult<FramesResponse> = call_home(
                &state,
                &bridge.target,
                "/api/fed/drive/collab/frames",
                &body,
                MAX_JSON_RESPONSE,
            )
            .await;
            match sent {
                Ok(response) => {
                    for seq in response.positions.into_iter().flatten() {
                        announce(&state, &bridge, seq).await;
                    }
                    break;
                }
                Err(error)
                    if error.status == StatusCode::NOT_FOUND
                        || error.status == StatusCode::FORBIDDEN =>
                {
                    // No longer shared, or the subscription lapsed: editors reconnect.
                    bridge_close(&state, &bridge);
                    return;
                }
                Err(_) if attempt < 3 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(250 << attempt)).await;
                }
                Err(_) => {
                    // Home is unreachable: editors reconnect and resume.
                    bridge_close(&state, &bridge);
                    return;
                }
            }
        }
    }
}

/// Keeps the subscription alive while the room has people.
async fn bridge_renewer(state: AppState, bridge: Arc<Bridge>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(RENEW_EVERY) => {}
            _ = bridge.stop.notified() => return,
        }
        if bridge.stopped.load(Ordering::Relaxed) {
            return;
        }
        if state.hub.peers(&bridge.key).is_empty() {
            bridge_release(&state, &bridge);
            return;
        }
        let renewed: AppResult<SubscribeResponse> = call_home(
            &state,
            &bridge.target,
            "/api/fed/drive/collab/subscribe",
            &SubscribeBody {
                file_id: bridge.target.file_id,
                subscription_id: bridge.subscription_id.clone(),
            },
            MAX_JSON_RESPONSE,
        )
        .await;
        match renewed {
            Ok(response) => bridge
                .can_write
                .store(response.can_write, Ordering::Relaxed),
            Err(error)
                if error.status == StatusCode::NOT_FOUND
                    || error.status == StatusCode::FORBIDDEN =>
            {
                bridge_close(&state, &bridge);
                return;
            }
            // A missed renewal is retried next time; the lease is longer.
            Err(_) => {}
        }
    }
}

/// `POST /api/fed/drive/collab/push` — home's new frames for a bridge's room.
/// Signed by home; names the subscription.
pub async fn receive_push(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let (federation, authenticated, parsed) =
        inbound::<PushBody>(&state, &headers, "/api/fed/drive/collab/push", &body).await?;
    let result = async {
        let request = parsed?;
        let bridge = state
            .collab_federation
            .bridge_by_subscription(&request.subscription_id)
            .filter(|b| b.target.domain == authenticated.origin() && b.target.file_id == request.file_id)
            .ok_or_else(|| AppError::not_found("subscription not found"))?;
        if request.close {
            bridge_close(&state, &bridge);
            return signed_json(federation, &authenticated, StatusCode::OK, &serde_json::json!({}));
        }
        // A saved version trimmed past what the room was told: editors merge it.
        let announced = *bridge.announced.lock().unwrap();
        if request.floor > announced {
            state
                .hub
                .broadcast_text(
                    &bridge.key,
                    &serde_json::json!({ "type": "replayed", "throughSeq": request.floor, "floor": request.floor })
                        .to_string(),
                )
                .await;
        }
        for pushed in &request.frames {
            let Ok(raw) = STANDARD.decode(&pushed.frame) else { continue };
            state.hub.broadcast(&bridge.key, 0, &raw).await;
            announce(&state, &bridge, pushed.seq).await;
        }
        for encoded in &request.ephemeral {
            if let Ok(raw) = STANDARD.decode(encoded) {
                state.hub.broadcast(&bridge.key, 0, &raw).await;
            }
        }
        {
            let mut announced = bridge.announced.lock().unwrap();
            *announced = (*announced).max(request.through_seq);
        }
        signed_json(federation, &authenticated, StatusCode::OK, &serde_json::json!({}))
    }
    .await;
    answer(federation, &authenticated, result)
}

/// A remote file this user reaches: through a folder shared from another
/// server, or a file shared by itself from one.
async fn target_for(
    state: &AppState,
    user_id: Uuid,
    route: &RemoteRoute,
) -> AppResult<RemoteTarget> {
    match route {
        RemoteRoute::Folder { share_id, file_id } => {
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT remote_domain, remote_capability FROM federated_incoming_shares WHERE id = $1 AND user_id = $2",
            )
            .bind(share_id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
            let (domain, capability) = row.ok_or_else(|| AppError::not_found("share not found"))?;
            Ok(RemoteTarget {
                domain,
                capability,
                file_id: *file_id,
            })
        }
        RemoteRoute::File { share_id } => {
            let row: Option<(String, String, Uuid)> = sqlx::query_as(
                "SELECT remote_domain, remote_capability, remote_file_id
                 FROM federated_incoming_file_shares WHERE id = $1 AND user_id = $2",
            )
            .bind(share_id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
            let (domain, capability, file_id) =
                row.ok_or_else(|| AppError::not_found("share not found"))?;
            Ok(RemoteTarget {
                domain,
                capability,
                file_id,
            })
        }
    }
}

enum RemoteRoute {
    Folder { share_id: Uuid, file_id: Uuid },
    File { share_id: Uuid },
}

fn folder_route(share_id: &str, file_id: &str) -> AppResult<RemoteRoute> {
    Ok(RemoteRoute::Folder {
        share_id: Uuid::parse_str(share_id).map_err(|_| AppError::not_found("share not found"))?,
        file_id: Uuid::parse_str(file_id).map_err(|_| AppError::not_found("file not found"))?,
    })
}

fn file_route(share_id: &str) -> AppResult<RemoteRoute> {
    Ok(RemoteRoute::File {
        share_id: Uuid::parse_str(share_id).map_err(|_| AppError::not_found("share not found"))?,
    })
}

/// `GET /api/drive/federation/shares/{shareId}/files/{fileId}/collab/ws` —
/// live editing of a file in a folder on another server, through this one.
pub async fn ws_folder_file(
    State(state): State<AppState>,
    Path((share_id, file_id)): Path<(String, String)>,
    Query(q): Query<CollabQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    bridge_ws(
        state,
        folder_route(&share_id, &file_id)?,
        q,
        headers,
        upgrade,
    )
    .await
}

/// `GET /api/drive/federation/file-shares/{id}/collab/ws` — live editing of a
/// file shared by itself from another server, through this one.
pub async fn ws_shared_file(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    Query(q): Query<CollabQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    bridge_ws(state, file_route(&share_id)?, q, headers, upgrade).await
}

async fn bridge_ws(
    state: AppState,
    route: RemoteRoute,
    q: CollabQuery,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    let (user_id, session_id, device_id, pub_key) =
        authenticate_socket(&state, &headers, &q).await?;
    let user_uuid =
        Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("invalid token"))?;
    let target = target_for(&state, user_uuid, &route).await?;
    // Subscribed before the upgrade: a share gone or not reachable answers here.
    let (bridge, subscribed) = bridge_join(&state, &target).await?;
    let max_frame = envelope::MAX_PLAINTEXT_BYTES + envelope::MIN_PACKED;
    Ok(upgrade
        .max_message_size(max_frame)
        .max_frame_size(max_frame)
        .on_upgrade(move |socket| async move {
            bridge_connection(
                state, socket, bridge, subscribed, route, user_uuid, session_id, device_id, pub_key,
            )
            .await;
        }))
}

#[allow(clippy::too_many_arguments)]
async fn bridge_connection(
    state: AppState,
    socket: WebSocket,
    bridge: Arc<Bridge>,
    subscribed: SubscribeResponse,
    route: RemoteRoute,
    user_uuid: Uuid,
    session_id: Uuid,
    device_id: i64,
    pub_key: Vec<u8>,
) {
    let hub = state.hub.clone();
    let key = bridge.key.clone();
    let (username, color): (String, String) = sqlx::query_as(
        "SELECT COALESCE(username, ''), COALESCE(color, '') FROM users WHERE id = $1",
    )
    .bind(user_uuid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or_default();
    let hello = Hello {
        current_doc_key_id: subscribed.current_doc_key_id,
        file_id: bridge.target.file_id.to_string(),
        head_seq: subscribed.head_seq,
        // The file's server keeps no sequence for this device; its client
        // picks a random prefix.
        my_sender_seq_high: 0,
        peers: peer_summaries(&hub, &key),
        kind: "hello",
    };
    let hello_json = serde_json::to_string(&hello).unwrap_or_else(|_| "{}".into());
    let (peer, mut rx) = hub::new_peer(&hub, device_id, user_uuid.to_string(), username, color);
    let (mut sink, mut stream) = socket.split();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let r = match msg {
                WsOut::Binary(b) => sink.send(Message::Binary(b)).await,
                WsOut::Text(t) => sink.send(Message::Text(t)).await,
                WsOut::Close => break,
            };
            if r.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    let _ = peer.write(WsOut::Text(hello_json)).await;
    hub.join(&key, peer.clone());
    broadcast_peers(&hub, &key).await;

    let mut budget = FrameBudget::new();
    let mut recheck = tokio::time::interval(ACCESS_RECHECK);
    recheck.tick().await;
    loop {
        tokio::select! {
            _ = peer.close.notified() => break,
            _ = recheck.tick() => {
                let live = crate::sessions::live(&state.pool, session_id, user_uuid).await.is_ok();
                if !live || target_for(&state, user_uuid, &route).await.is_err() {
                    break;
                }
            }
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    let Ok(f) = Frame::unpack(&data) else { continue };
                    // The relay's own checks: this device, its signature, this file.
                    if f.sender_device_id != device_id as u64
                        || envelope::verify(&data, &pub_key).is_err()
                        || f.file_id != *bridge.target.file_id.as_bytes()
                    {
                        continue;
                    }
                    if !is_presence(f.kind) {
                        if !bridge.can_write.load(Ordering::Relaxed) {
                            continue;
                        }
                        if !budget.take(data.len()) {
                            tracing::warn!(device = device_id, "bridged collab frame budget exceeded");
                            break;
                        }
                    }
                    hub.broadcast(&key, peer.conn_id, &data).await;
                    if bridge.outbound.send(data.to_vec()).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    #[derive(Deserialize)]
                    struct Ctl {
                        #[serde(rename = "type")]
                        kind: String,
                        #[serde(rename = "lastSeenSeq", default)]
                        last_seen_seq: i64,
                    }
                    if let Ok(ctl) = serde_json::from_str::<Ctl>(&text) {
                        if ctl.kind == "resume" && !bridge_replay(&state, &bridge, &peer, ctl.last_seen_seq).await {
                            break;
                        }
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
        }
    }
    hub.leave(&key, peer.conn_id);
    broadcast_peers(&hub, &key).await;
    writer.abort();
    bridge_release(&state, &bridge);
}

/// A joining editor catches up from home's log, as a local one resumes.
async fn bridge_replay(state: &AppState, bridge: &Bridge, peer: &hub::Peer, since: i64) -> bool {
    let log: AppResult<LogResponse> = call_home(
        state,
        &bridge.target,
        "/api/fed/drive/collab/log",
        &LogBody {
            file_id: bridge.target.file_id,
            since,
        },
        MAX_LOG_RESPONSE,
    )
    .await;
    let Ok(log) = log else { return false };
    for pushed in log.frames {
        let Ok(raw) = STANDARD.decode(&pushed.frame) else {
            continue;
        };
        if !peer.write(WsOut::Binary(raw)).await {
            return false;
        }
    }
    peer.write(WsOut::Text(
        serde_json::json!({ "type": "replayed", "throughSeq": log.through_seq, "floor": log.floor })
            .to_string(),
    ))
    .await
}

// -------------------------------------------- the editor's calls, relayed

async fn relayed_target(
    state: &AppState,
    user: &AuthUser,
    route: RemoteRoute,
) -> AppResult<(RemoteTarget, Uuid)> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok((target_for(state, user_id, &route).await?, user_id))
}

async fn relay_versions(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
) -> AppResult<Response> {
    let (target, _) = relayed_target(&state, &user, route).await?;
    let rows: serde_json::Value = call_home(
        &state,
        &target,
        "/api/fed/drive/collab/versions/list",
        &FileBody {
            file_id: target.file_id,
        },
        MAX_JSON_RESPONSE,
    )
    .await?;
    Ok(Json(rows).into_response())
}

async fn relay_version_download(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
    vid: String,
) -> AppResult<Response> {
    let (target, _) = relayed_target(&state, &user, route).await?;
    let vid = Uuid::parse_str(&vid).map_err(|_| AppError::not_found("not found"))?;
    let response = configured_stack(&state)?
        .send_streamed(
            &target.domain,
            drive_spec(
                Method::GET,
                format!(
                    "/api/fed/drive/collab/files/{}/versions/{vid}",
                    target.file_id
                ),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&target.capability),
                MAX_DRIVE_OBJECT_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    Response::builder()
        .status(response.status)
        .header(header::CONTENT_TYPE, response.content_type)
        .header(header::CONTENT_LENGTH, response.content_length)
        .body(Body::from_stream(ReaderStream::new(response.file)))
        .map_err(|error| AppError::internal(error.to_string()))
}

async fn relay_version_create(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let (target, user_id) = relayed_target(&state, &user, route).await?;
    let mut blob: Option<Vec<u8>> = None;
    let mut fields = HashMap::<String, String>::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid form"))?
    {
        let name = field.name().unwrap_or("").to_string();
        let mut value = Vec::new();
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|_| AppError::bad_request("invalid form"))?
        {
            let limit = if name == "file" {
                MAX_VERSION_BLOB
            } else {
                4096
            };
            if value.len() + chunk.len() > limit {
                return Err(AppError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "version too large",
                ));
            }
            value.extend_from_slice(&chunk);
        }
        if name == "file" {
            blob = Some(value);
        } else if !name.is_empty() && fields.len() < 8 {
            fields.insert(
                name,
                String::from_utf8(value).map_err(|_| AppError::bad_request("invalid form"))?,
            );
        }
    }
    let blob = blob.ok_or_else(|| AppError::bad_request("missing file"))?;
    let username: Option<String> = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    let server = configured_stack(&state)?.server_name().to_owned();
    let number = |name: &str| {
        fields
            .get(name)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0)
    };
    let created: serde_json::Value = call_home(
        &state,
        &target,
        "/api/fed/drive/collab/versions/create",
        &CreateVersionBody {
            file_id: target.file_id,
            author: format!("{}@{server}", username.unwrap_or_default()),
            kind: fields.get("kind").cloned().unwrap_or_default(),
            seq_at_snapshot: number("seqAtSnapshot"),
            doc_key_id: number("docKeyId"),
            label: fields.get("label").cloned(),
            keep_forever: fields.get("keepForever").is_some_and(|v| v == "true"),
            blob: STANDARD.encode(blob),
        },
        MAX_JSON_RESPONSE,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// A file's asset on another server, for this server's user.
async fn relay_asset_download(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
    asset_id: String,
) -> AppResult<Response> {
    let (target, _) = relayed_target(&state, &user, route).await?;
    if !valid_relayed_asset_id(&asset_id) {
        return Err(AppError::bad_request("invalid assetId"));
    }
    let response = configured_stack(&state)?
        .send_streamed(
            &target.domain,
            drive_spec(
                Method::GET,
                format!(
                    "/api/fed/drive/collab/files/{}/assets/{asset_id}",
                    target.file_id
                ),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&target.capability),
                MAX_ASSET_ENVELOPE,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    Response::builder()
        .status(response.status)
        .header(header::CONTENT_TYPE, response.content_type)
        .header(header::CONTENT_LENGTH, response.content_length)
        .body(Body::from_stream(ReaderStream::new(response.file)))
        .map_err(|error| AppError::internal(error.to_string()))
}

/// This server's user stores an asset on a file on another server (the
/// multipart `file` part, as for local assets).
async fn relay_asset_upload(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
    asset_id: String,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let (target, _) = relayed_target(&state, &user, route).await?;
    if !valid_relayed_asset_id(&asset_id) {
        return Err(AppError::bad_request("invalid assetId"));
    }
    let mut blob: Option<Vec<u8>> = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid form"))?
    {
        if field.name() != Some("file") {
            continue;
        }
        let mut value = Vec::new();
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|_| AppError::bad_request("invalid form"))?
        {
            if value.len() + chunk.len() > MAX_ASSET_ENVELOPE {
                return Err(AppError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "asset envelope too large",
                ));
            }
            value.extend_from_slice(&chunk);
        }
        blob = Some(value);
    }
    let blob = blob.ok_or_else(|| AppError::bad_request("missing file"))?;
    let _: serde_json::Value = call_home(
        &state,
        &target,
        "/api/fed/drive/collab/assets/create",
        &CreateAssetBody {
            file_id: target.file_id,
            asset_id,
            blob: STANDARD.encode(blob),
        },
        MAX_JSON_RESPONSE,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The same rule as local asset ids: short, no path separators.
fn valid_relayed_asset_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains("..")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayedPatch {
    label: Option<String>,
    keep_forever: Option<bool>,
}

async fn relay_version_patch(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
    vid: String,
    patch: RelayedPatch,
) -> AppResult<Response> {
    let (target, _) = relayed_target(&state, &user, route).await?;
    let vid = Uuid::parse_str(&vid).map_err(|_| AppError::not_found("not found"))?;
    let row: serde_json::Value = call_home(
        &state,
        &target,
        "/api/fed/drive/collab/versions/patch",
        &PatchVersionBody {
            file_id: target.file_id,
            version_id: vid,
            label: patch.label,
            keep_forever: patch.keep_forever,
        },
        MAX_JSON_RESPONSE,
    )
    .await?;
    Ok(Json(row).into_response())
}

async fn relay_claim_seed(
    state: AppState,
    user: AuthUser,
    route: RemoteRoute,
) -> AppResult<Response> {
    let (target, _) = relayed_target(&state, &user, route).await?;
    let claimed: serde_json::Value = call_home(
        &state,
        &target,
        "/api/fed/drive/collab/claim-seed",
        &FileBody {
            file_id: target.file_id,
        },
        MAX_JSON_RESPONSE,
    )
    .await?;
    Ok(Json(claimed).into_response())
}

// Routes: the same suffixes as `/api/files/{id}/…`, under a remote file's
// base (`/api/drive/federation/shares/{shareId}/files/{fileId}` or
// `/api/drive/federation/file-shares/{id}`).

pub async fn folder_versions(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid)): Path<(String, String)>,
) -> AppResult<Response> {
    relay_versions(s, u, folder_route(&sid, &fid)?).await
}
pub async fn file_versions(
    State(s): State<AppState>,
    u: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    relay_versions(s, u, file_route(&id)?).await
}
pub async fn folder_version_create(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid)): Path<(String, String)>,
    m: Multipart,
) -> AppResult<Response> {
    relay_version_create(s, u, folder_route(&sid, &fid)?, m).await
}
pub async fn file_version_create(
    State(s): State<AppState>,
    u: AuthUser,
    Path(id): Path<String>,
    m: Multipart,
) -> AppResult<Response> {
    relay_version_create(s, u, file_route(&id)?, m).await
}
pub async fn folder_version_download(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid, vid)): Path<(String, String, String)>,
) -> AppResult<Response> {
    relay_version_download(s, u, folder_route(&sid, &fid)?, vid).await
}
pub async fn file_version_download(
    State(s): State<AppState>,
    u: AuthUser,
    Path((id, vid)): Path<(String, String)>,
) -> AppResult<Response> {
    relay_version_download(s, u, file_route(&id)?, vid).await
}
pub async fn folder_version_patch(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid, vid)): Path<(String, String, String)>,
    Json(p): Json<RelayedPatch>,
) -> AppResult<Response> {
    relay_version_patch(s, u, folder_route(&sid, &fid)?, vid, p).await
}
pub async fn file_version_patch(
    State(s): State<AppState>,
    u: AuthUser,
    Path((id, vid)): Path<(String, String)>,
    Json(p): Json<RelayedPatch>,
) -> AppResult<Response> {
    relay_version_patch(s, u, file_route(&id)?, vid, p).await
}
pub async fn folder_claim_seed(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid)): Path<(String, String)>,
) -> AppResult<Response> {
    relay_claim_seed(s, u, folder_route(&sid, &fid)?).await
}
pub async fn file_claim_seed(
    State(s): State<AppState>,
    u: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    relay_claim_seed(s, u, file_route(&id)?).await
}
pub async fn folder_asset_download(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid, aid)): Path<(String, String, String)>,
) -> AppResult<Response> {
    relay_asset_download(s, u, folder_route(&sid, &fid)?, aid).await
}
pub async fn file_asset_download(
    State(s): State<AppState>,
    u: AuthUser,
    Path((id, aid)): Path<(String, String)>,
) -> AppResult<Response> {
    relay_asset_download(s, u, file_route(&id)?, aid).await
}
pub async fn folder_asset_upload(
    State(s): State<AppState>,
    u: AuthUser,
    Path((sid, fid, aid)): Path<(String, String, String)>,
    m: Multipart,
) -> AppResult<Response> {
    relay_asset_upload(s, u, folder_route(&sid, &fid)?, aid, m).await
}
pub async fn file_asset_upload(
    State(s): State<AppState>,
    u: AuthUser,
    Path((id, aid)): Path<(String, String)>,
    m: Multipart,
) -> AppResult<Response> {
    relay_asset_upload(s, u, file_route(&id)?, aid, m).await
}
