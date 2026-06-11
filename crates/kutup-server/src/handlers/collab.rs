//! Collaborative-edit WebSocket handler — mirrors `backend/handlers/collab.go`.
//!
//! The server is a blind relay: it verifies each frame's Ed25519 signature (never decrypts),
//! persists the durable kinds to `file_update_log`, and fans frames out to the other peers in
//! the file's room. Auth (token + file access + device) happens before the upgrade, mirroring
//! Go's `PreUpgrade`; `handle_connection` is the per-connection coroutine (Go's
//! `HandleConnection`): hello → join → peer broadcast → read loop → leave.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use kutup_crypto::envelope::{self, Frame};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::hub::{self, Hub, WsOut};
use crate::{jwt, AppState};

/// Query params on the WS URL. Browsers can't set headers on `new WebSocket(url)`, so the
/// token + deviceId arrive here (token may also come via `Authorization`).
#[derive(Debug, Deserialize)]
pub struct CollabQuery {
    token: Option<String>,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
}

/// One participant in the room's peer-list. Keys are emitted in the alphabetical order Go's
/// `encoding/json` produces for its `fiber.Map`; `color`/`username` are omitted when empty
/// (Go only sets them when non-empty).
#[derive(Debug, Serialize)]
struct PeerSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    color: String,
    #[serde(rename = "deviceId")]
    device_id: i64,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    username: String,
}

/// The `hello` control message (keys alphabetical, matching Go's marshalled `fiber.Map`).
#[derive(Debug, Serialize)]
struct Hello {
    #[serde(rename = "currentDocKeyId")]
    current_doc_key_id: i64,
    #[serde(rename = "fileId")]
    file_id: String,
    #[serde(rename = "headSeq")]
    head_seq: i64,
    #[serde(rename = "mySenderSeqHigh")]
    my_sender_seq_high: i64,
    peers: Vec<PeerSummary>,
    #[serde(rename = "type")]
    kind: &'static str,
}

/// The `peers` control message broadcast on join/leave.
#[derive(Debug, Serialize)]
struct PeersMsg {
    list: Vec<PeerSummary>,
    ts: i64,
    #[serde(rename = "type")]
    kind: &'static str,
}

/// `GET /api/files/{fileId}/collab/ws` — authenticates, then upgrades. Mirrors
/// `PreUpgrade` + `Upgrade`: all access checks run here so the upgraded connection trusts
/// the resolved identity.
pub async fn ws(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    Query(q): Query<CollabQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    // Token from Authorization header or ?token=.
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or(q.token);
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return Err(AppError::unauthorized("missing token")),
    };
    let (user_id, _is_admin) = jwt::validate_access_token(&token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("invalid token"))?;

    // Confirm the user can access this file's collection.
    let file_uuid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let user_uuid =
        Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("invalid token"))?;
    let access: Option<(String, String, bool)> = sqlx::query_as(
        r#"SELECT c.owner_user_id::text, c.id::text,
                  EXISTS(SELECT 1 FROM collection_shares cs
                         WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
           FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL"#,
    )
    .bind(file_uuid)
    .bind(user_uuid)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((owner_id, _coll_id, shared_with)) = access else {
        return Err(AppError::not_found("file not found"));
    };
    if owner_id != user_id && !shared_with {
        return Err(AppError::forbidden("forbidden"));
    }

    // Device validation: deviceId from query, must belong to the user + be active.
    let device_id: i64 = match q.device_id.as_deref().and_then(|s| s.trim().parse().ok()) {
        Some(d) if d != 0 => d,
        _ => return Err(AppError::unauthorized("missing or invalid deviceId")),
    };
    let dev: Option<(Vec<u8>, bool, String)> = sqlx::query_as(
        "SELECT public_signing, is_active, user_id::text FROM user_devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let pub_key = match dev {
        Some((pk, true, owner)) if owner == user_id => pk,
        _ => return Err(AppError::unauthorized("device not registered or revoked")),
    };

    Ok(upgrade.on_upgrade(move |socket| async move {
        handle_connection(
            state, socket, file_id, file_uuid, user_id, device_id, pub_key,
        )
        .await;
    }))
}

/// Per-connection coroutine — mirrors `HandleConnection`.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    state: AppState,
    socket: WebSocket,
    file_id: String,
    file_uuid: Uuid,
    user_id: String,
    device_id: i64,
    pub_key: Vec<u8>,
) {
    let hub = state.hub.clone();

    // Username + color for the peer-list (best-effort). `id` is a uuid column, so bind a
    // Uuid (a text bind would fail the comparison and silently yield empty fields).
    let user_uuid = Uuid::parse_str(&user_id).unwrap_or_default();
    let (username, color): (String, String) = sqlx::query_as(
        "SELECT COALESCE(username, ''), COALESCE(color, '') FROM users WHERE id = $1",
    )
    .bind(user_uuid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or_default();

    // Stamp last_seen_at on every successful upgrade.
    let _ = sqlx::query("UPDATE user_devices SET last_seen_at = now() WHERE id = $1")
        .bind(device_id)
        .execute(&state.pool)
        .await;

    // hello payload fields.
    let doc_key_id: i64 = sqlx::query_scalar("SELECT current_doc_key_id FROM files WHERE id = $1")
        .bind(file_uuid)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    let head_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM file_update_log WHERE file_id = $1")
            .bind(file_uuid)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);
    let my_sender_seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sender_seq), 0) FROM file_update_log \
         WHERE file_id = $1 AND sender_device = $2",
    )
    .bind(file_uuid)
    .bind(device_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    // Peer summaries BEFORE join (so the new peer isn't in its own hello list).
    let hello = Hello {
        current_doc_key_id: doc_key_id,
        file_id: file_id.clone(),
        head_seq,
        my_sender_seq_high: my_sender_seq,
        peers: peer_summaries(&hub, &file_id),
        kind: "hello",
    };
    let hello_json = serde_json::to_string(&hello).unwrap_or_else(|_| "{}".into());

    let (peer, mut rx) = hub::new_peer(&hub, device_id, user_id, username, color);

    // Writer task — the Rust analogue of writePump. Drains the outbound channel to the sink.
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

    // Send hello, then join + announce the new peer set.
    let _ = peer.write(WsOut::Text(hello_json)).await;
    hub.join(&file_id, peer.clone());
    broadcast_peers(&hub, &file_id).await;

    // Read loop.
    loop {
        tokio::select! {
            _ = peer.close.notified() => break,
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    handle_frame(&state, &peer, &file_id, file_uuid, &pub_key, &b).await;
                }
                Some(Ok(Message::Text(t))) => {
                    handle_control(&state, &peer, file_uuid, t.as_bytes()).await;
                }
                Some(Ok(_)) => {} // ping/pong/other
                Some(Err(_)) | None => break,
            },
        }
    }

    // Teardown: leave, announce, stop the writer.
    hub.leave(&file_id, peer.conn_id);
    broadcast_peers(&hub, &file_id).await;
    writer.abort();
}

/// Builds the JSON peer-list for a room — mirrors `peerSummaries`.
fn peer_summaries(hub: &Hub, file_id: &str) -> Vec<PeerSummary> {
    hub.peers(file_id)
        .into_iter()
        .map(|p| PeerSummary {
            color: p.color.clone(),
            device_id: p.device_id,
            user_id: p.user_id.clone(),
            username: p.username.clone(),
        })
        .collect()
}

/// Sends the current peer-list as a text message to every conn in the room — mirrors
/// `broadcastPeers`.
async fn broadcast_peers(hub: &Hub, file_id: &str) {
    let msg = PeersMsg {
        list: peer_summaries(hub, file_id),
        ts: (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64,
        kind: "peers",
    };
    let Ok(payload) = serde_json::to_string(&msg) else {
        return;
    };
    for p in hub.peers(file_id) {
        let _ = p.write(WsOut::Text(payload.clone())).await;
    }
}

/// Handles JSON control messages — v1 supports only `{"type":"resume","lastSeenSeq":N}`.
/// Mirrors `handleControl`.
async fn handle_control(state: &AppState, peer: &hub::Peer, file_uuid: Uuid, data: &[u8]) {
    #[derive(Deserialize)]
    struct Ctl {
        #[serde(rename = "type")]
        kind: String,
        #[serde(rename = "lastSeenSeq", default)]
        last_seen_seq: i64,
    }
    let Ok(m) = serde_json::from_slice::<Ctl>(data) else {
        return;
    };
    if m.kind != "resume" {
        return;
    }
    replay_log(state, peer, file_uuid, m.last_seen_seq).await;
}

/// Validates + persists a binary collab frame, then broadcasts it — mirrors `handleFrame`.
async fn handle_frame(
    state: &AppState,
    peer: &hub::Peer,
    file_id: &str,
    file_uuid: Uuid,
    pub_key: &[u8],
    data: &[u8],
) {
    let Ok(f) = Frame::unpack(data) else {
        return;
    };
    if f.sender_device_id != peer.device_id as u64 {
        return; // forged sender — drop
    }
    if envelope::verify(data, pub_key).is_err() {
        return;
    }

    // Epoch check: reject frames signed under an older doc_key_id than the file's current.
    let current_epoch: i64 =
        match sqlx::query_scalar("SELECT current_doc_key_id FROM files WHERE id = $1")
            .bind(file_uuid)
            .fetch_one(&state.pool)
            .await
        {
            Ok(v) => v,
            Err(_) => return,
        };
    if (f.doc_key_id as i64) < current_epoch {
        return;
    }

    // Ephemeral, broadcast-only kinds (no file_update_log entry).
    if matches!(
        f.kind,
        envelope::kind::YJS_AWARENESS
            | envelope::kind::OO_CURSOR
            | envelope::kind::EXCALIDRAW_OP
            | envelope::kind::EXCALIDRAW_CURSOR
    ) {
        state.hub.broadcast(file_id, peer.conn_id, data).await;
        return;
    }

    // Durable kinds: persist (drop on seq/sender_seq conflict), then broadcast.
    if persist_frame(state, file_uuid, peer.device_id, &f, data)
        .await
        .is_err()
    {
        return;
    }
    state.hub.broadcast(file_id, peer.conn_id, data).await;
}

/// Inserts a frame into `file_update_log`, assigning the next per-file seq — mirrors
/// `persistFrame`. The `(file_id, seq)` PK and `(file_id, sender_device, sender_seq)` UNIQUE
/// index drop replays/races (the client retransmits on resume).
async fn persist_frame(
    state: &AppState,
    file_uuid: Uuid,
    device_id: i64,
    f: &Frame,
    raw: &[u8],
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"INSERT INTO file_update_log (file_id, seq, sender_device, sender_seq, doc_key_id, kind, frame)
           VALUES (
             $1,
             COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id = $1), 0) + 1,
             $2, $3, $4, $5, $6
           )
           RETURNING seq"#,
    )
    .bind(file_uuid)
    .bind(device_id)
    .bind(f.sequence as i64)
    .bind(f.doc_key_id as i64)
    .bind(f.kind as i16)
    .bind(raw)
    .fetch_one(&state.pool)
    .await
}

/// Streams every frame with `seq > since_seq` to the joining client — mirrors `replayLog`.
async fn replay_log(state: &AppState, peer: &hub::Peer, file_uuid: Uuid, since_seq: i64) {
    let rows: Vec<(Vec<u8>,)> = match sqlx::query_as(
        "SELECT frame FROM file_update_log WHERE file_id = $1 AND seq > $2 ORDER BY seq ASC",
    )
    .bind(file_uuid)
    .bind(since_seq)
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return,
    };
    for (frame,) in rows {
        if !peer.write(WsOut::Binary(frame)).await {
            return;
        }
    }
}
