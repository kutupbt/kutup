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
use crate::AppState;

/// Query params on the WS URL. Browsers can't set headers on `new WebSocket(url)`, so the
/// token + deviceId arrive here (token may also come via `Authorization`).
#[derive(Debug, Deserialize)]
pub struct CollabQuery {
    pub(crate) token: Option<String>,
    #[serde(rename = "deviceId")]
    pub(crate) device_id: Option<String>,
}

/// One participant in the room's peer-list. Keys are emitted in the alphabetical order Go's
/// `encoding/json` produces for its `fiber.Map`; `color`/`username` are omitted when empty
/// (Go only sets them when non-empty).
#[derive(Debug, Serialize)]
pub(crate) struct PeerSummary {
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
pub(crate) struct Hello {
    #[serde(rename = "currentDocKeyId")]
    pub(crate) current_doc_key_id: i64,
    #[serde(rename = "fileId")]
    pub(crate) file_id: String,
    #[serde(rename = "headSeq")]
    pub(crate) head_seq: i64,
    #[serde(rename = "mySenderSeqHigh")]
    pub(crate) my_sender_seq_high: i64,
    pub(crate) peers: Vec<PeerSummary>,
    #[serde(rename = "type")]
    pub(crate) kind: &'static str,
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
#[utoipa::path(
    get,
    path = "/api/files/{fileId}/collab/ws",
    tag = "collab",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("token" = Option<String>, Query, description = "Access token (browsers cannot set headers on `new WebSocket`)"),
        ("deviceId" = Option<String>, Query, description = "The caller's registered device id")
    ),
    responses((status = 101, description = "WebSocket upgrade — Ed25519-signed encrypted collab frames; the server relays without decrypting"))
)]
pub async fn ws(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    Query(q): Query<CollabQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    let (user_id, session_id, device_id, pub_key) =
        authenticate_socket(&state, &headers, &q).await?;
    // Anyone who may read the file joins; only editors' edits are kept.
    let file_uuid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let user_uuid =
        Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("invalid token"))?;
    let access = file_access(&state.pool, user_uuid, file_uuid)
        .await
        .ok_or_else(|| AppError::not_found("file not found"))?;
    if access == Access::None {
        return Err(AppError::forbidden("forbidden"));
    }

    let conn = Conn {
        file_id,
        file_uuid,
        user_uuid,
        session_id,
        device_id,
        pub_key,
    };
    // One frame carries at most one envelope's plaintext.
    let max_frame = envelope::MAX_PLAINTEXT_BYTES + envelope::MIN_PACKED;
    Ok(upgrade
        .max_message_size(max_frame)
        .max_frame_size(max_frame)
        .on_upgrade(move |socket| async move {
            handle_connection(state, socket, conn, user_id).await;
        }))
}

/// The session and registered device behind a collaboration socket: the
/// access token (header or `?token=`, as browsers cannot set headers on a
/// WebSocket) and `?deviceId=`, which must be this user's active device.
pub(crate) async fn authenticate_socket(
    state: &AppState,
    headers: &HeaderMap,
    q: &CollabQuery,
) -> AppResult<(String, Uuid, i64, Vec<u8>)> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| q.token.clone());
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return Err(AppError::unauthorized("missing token")),
    };
    let auth = crate::middleware::authenticate_access_token(state, &token)
        .await
        .map_err(|_| AppError::unauthorized("invalid token"))?;
    let user_id = auth.user_id;
    let session_id = auth.session.session_id;
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
    match dev {
        Some((pk, true, owner)) if owner == user_id => Ok((user_id, session_id, device_id, pk)),
        _ => Err(AppError::unauthorized("device not registered or revoked")),
    }
}

/// What a user may do with a file's live session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    None,
    /// Receives edits and shares their cursor; sends no edits.
    Read,
    Write,
}

/// `None` when the file (or its folder) is gone.
async fn file_access(pool: &sqlx::PgPool, user_id: Uuid, file_id: Uuid) -> Option<Access> {
    // A folder share or a share of the file itself; either may allow edits.
    let row: Option<(bool, Option<bool>)> = sqlx::query_as(&format!(
        r#"SELECT c.owner_user_id = $2,
                  (SELECT bool_or(can) FROM (
                       SELECT cs.can_upload AS can FROM collection_shares cs
                        WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2
                       UNION ALL
                       SELECT fs.can_edit AND {current} FROM file_shares fs
                        WHERE fs.file_id = f.id AND fs.recipient_user_id = $2) shares)
           FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL"#,
        current = crate::drive_writes::FILE_SHARE_CURRENT,
    ))
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    row.map(|(owner, share)| match (owner, share) {
        (true, _) | (_, Some(true)) => Access::Write,
        (_, Some(false)) => Access::Read,
        _ => Access::None,
    })
}

/// A connection's fixed identity, resolved before the upgrade.
struct Conn {
    file_id: String,
    file_uuid: Uuid,
    user_uuid: Uuid,
    session_id: Uuid,
    device_id: i64,
    pub_key: Vec<u8>,
}

/// How often an open connection re-checks its session and file access, so
/// revoking a share, trashing the file or signing the session out also
/// ends live sessions.
pub(crate) const ACCESS_RECHECK: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-connection budget for kept (durable) frames: a sustained rate with a
/// burst, in frames and bytes. Typing and office edits stay far below it; a
/// client flooding the log is cut off.
pub(crate) struct FrameBudget {
    frames: f64,
    bytes: f64,
    last: std::time::Instant,
}

impl FrameBudget {
    const FRAMES_PER_SEC: f64 = 50.0;
    const FRAME_BURST: f64 = 500.0;
    const BYTES_PER_SEC: f64 = 1024.0 * 1024.0;
    const BYTE_BURST: f64 = 16.0 * 1024.0 * 1024.0;

    pub(crate) fn new() -> Self {
        FrameBudget {
            frames: Self::FRAME_BURST,
            bytes: Self::BYTE_BURST,
            last: std::time::Instant::now(),
        }
    }

    /// Takes one frame of `len` bytes from the budget, if it has room.
    pub(crate) fn take(&mut self, len: usize) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.frames = (self.frames + elapsed * Self::FRAMES_PER_SEC).min(Self::FRAME_BURST);
        self.bytes = (self.bytes + elapsed * Self::BYTES_PER_SEC).min(Self::BYTE_BURST);
        if self.frames < 1.0 || self.bytes < len as f64 {
            return false;
        }
        self.frames -= 1.0;
        self.bytes -= len as f64;
        true
    }
}

/// Per-connection coroutine — mirrors `HandleConnection`.
async fn handle_connection(state: AppState, socket: WebSocket, conn: Conn, user_id: String) {
    let hub = state.hub.clone();
    let (file_id, file_uuid, device_id) = (conn.file_id.clone(), conn.file_uuid, conn.device_id);

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
    let head_seq: i64 = log_head(&state.pool, file_uuid).await.unwrap_or(0);
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
    let mut budget = FrameBudget::new();
    let mut recheck = tokio::time::interval(ACCESS_RECHECK);
    recheck.tick().await;
    loop {
        tokio::select! {
            _ = peer.close.notified() => break,
            _ = recheck.tick() => {
                let session_live =
                    crate::sessions::live(&state.pool, conn.session_id, conn.user_uuid).await.is_ok();
                let access = file_access(&state.pool, conn.user_uuid, file_uuid).await;
                if !session_live || matches!(access, None | Some(Access::None)) {
                    break;
                }
            }
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if !handle_frame(&state, &peer, &conn, &mut budget, &b).await {
                        break;
                    }
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
pub(crate) fn peer_summaries(hub: &Hub, file_id: &str) -> Vec<PeerSummary> {
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
pub(crate) async fn broadcast_peers(hub: &Hub, file_id: &str) {
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

/// Handles JSON control messages: `{"type":"resume","lastSeenSeq":N}` and,
/// from office editors, `{"type":"base","versionId":…|null,"seq":N,"reset":bool}`
/// (docs/onlyoffice.md, "Collaboration sessions"). Mirrors `handleControl`.
async fn handle_control(state: &AppState, peer: &hub::Peer, file_uuid: Uuid, data: &[u8]) {
    #[derive(Deserialize)]
    struct Ctl {
        #[serde(rename = "type")]
        kind: String,
        #[serde(rename = "lastSeenSeq", default)]
        last_seen_seq: i64,
        #[serde(rename = "versionId", default)]
        version_id: Option<String>,
        #[serde(default)]
        seq: i64,
        #[serde(default)]
        reset: bool,
    }
    let Ok(m) = serde_json::from_slice::<Ctl>(data) else {
        return;
    };
    match m.kind.as_str() {
        "resume" => replay_log(state, peer, file_uuid, m.last_seen_seq).await,
        "base" => claim_base(state, peer, file_uuid, m.version_id, m.seq, m.reset).await,
        _ => {}
    }
}

/// An office editor says which version it loaded. The first tab in the room
/// sets the session's base (and, starting a session, trims the log up to
/// it: nobody is editing past it); a tab joining a live session learns the
/// base and, when it loaded something else, reopens from it; a restore
/// resets the base and the other tabs reopen.
async fn claim_base(
    state: &AppState,
    peer: &hub::Peer,
    file_uuid: Uuid,
    version_id: Option<String>,
    seq: i64,
    reset: bool,
) {
    // Only a real version of this file, at its recorded position, may be a
    // base (a made-up one must not trim edits); the original upload is 0.
    let version = match &version_id {
        None if seq == 0 => None,
        None => return,
        Some(v) => {
            let Ok(vid) = Uuid::parse_str(v) else { return };
            let row: Option<i64> = sqlx::query_scalar(
                "SELECT doc_key_id FROM file_versions
                 WHERE id = $1 AND file_id = $2 AND kind = 'file' AND seq_at_snapshot = $3",
            )
            .bind(vid)
            .bind(file_uuid)
            .bind(seq)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
            match row {
                Some(doc_key_id) => Some((vid, doc_key_id)),
                None => return,
            }
        }
    };
    let file_id = file_uuid.to_string();
    let claim = hub::SessionBase { version_id, seq };
    let Some(outcome) = state.hub.claim_base(&file_id, peer.conn_id, claim, reset) else {
        return;
    };
    if outcome.new_session {
        if let Some((_, doc_key_id)) = version {
            if seq > 0 {
                let _ = trim_log(&state.pool, file_uuid, seq, doc_key_id).await;
            }
        }
    }
    let base_json = |yours: bool, reset: bool| {
        serde_json::json!({
            "type": "base",
            "versionId": outcome.base.version_id,
            "seq": outcome.base.seq,
            "yours": yours,
            "reset": reset,
        })
        .to_string()
    };
    let _ = peer
        .write(WsOut::Text(base_json(outcome.yours, false)))
        .await;
    for other in &outcome.others {
        let _ = other.write(WsOut::Text(base_json(false, true))).await;
    }
}

/// Drops the log up to `seq` (under the relay's per-file lock, only for the
/// document key the log is under) and raises the floor to it.
async fn trim_log(
    pool: &sqlx::PgPool,
    file_uuid: Uuid,
    seq: i64,
    doc_key_id: i64,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(log_lock_key(file_uuid))
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM file_update_log l USING files f
         WHERE l.file_id = $1 AND f.id = $1 AND f.current_doc_key_id = $3 AND l.seq <= $2",
    )
    .bind(file_uuid)
    .bind(seq)
    .bind(doc_key_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE files SET collab_log_floor = GREATEST(collab_log_floor, $2)
         WHERE id = $1 AND current_doc_key_id = $3",
    )
    .bind(file_uuid)
    .bind(seq)
    .bind(doc_key_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Validates + persists a binary collab frame, then broadcasts it — mirrors `handleFrame`.
/// Returns `false` when the connection should close (access lost, or the
/// client exceeded its frame budget).
async fn handle_frame(
    state: &AppState,
    peer: &hub::Peer,
    conn: &Conn,
    budget: &mut FrameBudget,
    data: &[u8],
) -> bool {
    let Ok(f) = Frame::unpack(data) else {
        return true;
    };
    if f.sender_device_id != peer.device_id as u64 || f.sequence > i64::MAX as u64 {
        return true; // forged sender — drop
    }
    if envelope::verify(data, &conn.pub_key).is_err() {
        return true;
    }
    let file_uuid = conn.file_uuid;

    // The public authenticated header must name this exact file, its current
    // file-key generation and current document key. Neither stale nor future
    // values are accepted.
    let Some(key_current) = frame_binding(state, file_uuid, &f).await else {
        return true;
    };
    // Presence only: cursors and awareness, which any reader may share.
    if is_presence(f.kind) {
        state.hub.broadcast(&conn.file_id, peer.conn_id, data).await;
        state.collab_federation.relayed(file_uuid, None, data);
        return true;
    }

    // Everything else changes the document: editors only, checked per frame
    // (a share can be narrowed while the socket is open).
    match file_access(&state.pool, conn.user_uuid, file_uuid).await {
        Some(Access::Write) => {}
        Some(Access::Read) => return true,
        _ => return false,
    }
    // Edits only under a file key wrapped at the folder's current epoch: a
    // file the folder has rotated past is re-keyed before anyone writes to it
    // (docs/plans/drive-share-revocation.md).
    if !key_current {
        return true;
    }
    if !budget.take(data.len()) {
        tracing::warn!(file = %file_uuid, device = peer.device_id, "collab frame budget exceeded");
        return false;
    }

    // Scene edits are relayed, not kept.
    if f.kind == envelope::kind::EXCALIDRAW_OP {
        state.hub.broadcast(&conn.file_id, peer.conn_id, data).await;
        state.collab_federation.relayed(file_uuid, None, data);
        return true;
    }

    // Durable kinds: persist (drop only exact sender-sequence replays), then
    // broadcast, then tell everyone in the room (the sender too) the frame's
    // log position. Each connection gets the frame before its position, so a
    // client knows every frame up to a position it has seen is applied.
    let Ok(seq) = persist_frame(state, file_uuid, Sender::Device(peer.device_id), &f, data).await
    else {
        return true;
    };
    state.hub.broadcast(&conn.file_id, peer.conn_id, data).await;
    state
        .hub
        .broadcast_text(
            &conn.file_id,
            &serde_json::json!({ "type": "stored", "seq": seq }).to_string(),
        )
        .await;
    // Editors on other servers get it too.
    state.collab_federation.kept(file_uuid);
    true
}

/// Cursors and awareness: relayed to the room, never kept.
pub(crate) fn is_presence(kind: u8) -> bool {
    matches!(
        kind,
        envelope::kind::YJS_AWARENESS
            | envelope::kind::OO_CURSOR
            | envelope::kind::EXCALIDRAW_CURSOR
    )
}

/// Whether a frame names this file, its current file-key generation and
/// current document key. `Some(true)` when the file's key is also wrapped at
/// its folder's current epoch (edits are taken then only); `None` when the
/// frame does not fit the file.
pub(crate) async fn frame_binding(state: &AppState, file_uuid: Uuid, f: &Frame) -> Option<bool> {
    let binding: (i64, i32, i32, i32) = sqlx::query_as(
        "SELECT f.current_doc_key_id, f.key_generation, f.key_epoch, c.key_epoch \
         FROM files f JOIN collections c ON c.id = f.collection_id \
         WHERE f.id = $1 AND f.deleted_at IS NULL",
    )
    .bind(file_uuid)
    .fetch_one(&state.pool)
    .await
    .ok()?;
    if f.file_id != *file_uuid.as_bytes()
        || f.key_generation as i64 != binding.1 as i64
        || f.doc_key_id as i64 != binding.0
    {
        return None;
    }
    Some(binding.2 == binding.3)
}

/// Who sent a kept frame: a device here, or one on another server.
pub(crate) enum Sender<'a> {
    Device(i64),
    Remote { domain: &'a str, device: i64 },
}

/// The position of the last frame in a file's log: the newest kept frame, or
/// where a saved version trimmed it to. Positions only ever go up.
pub(crate) async fn log_head<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    file_uuid: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT GREATEST(
             COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id = $1), 0),
             COALESCE((SELECT collab_log_floor FROM files WHERE id = $1), 0))",
    )
    .bind(file_uuid)
    .fetch_one(executor)
    .await
}

/// The advisory lock that serialises a file's update log: appends here and
/// truncation when a version is saved.
pub(crate) fn log_lock_key(file_uuid: Uuid) -> i64 {
    (file_uuid.as_u128() >> 64) as u64 as i64
}

/// Inserts a frame into `file_update_log`, assigning the next per-file seq — mirrors
/// `persistFrame`. Sequence allocation is serialized per file so simultaneous frames from
/// different devices cannot both select the same `MAX(seq) + 1`; the
/// `(file_id, sender_device, sender_seq)` unique index still rejects exact replays.
pub(crate) async fn persist_frame(
    state: &AppState,
    file_uuid: Uuid,
    sender: Sender<'_>,
    f: &Frame,
    raw: &[u8],
) -> Result<i64, sqlx::Error> {
    let (device_id, remote_domain, remote_device) = match sender {
        Sender::Device(id) => (Some(id), None, None),
        Sender::Remote { domain, device } => (None, Some(domain), Some(device)),
    };
    let mut tx = state.pool.begin().await?;

    // PostgreSQL advisory locks are transaction-scoped and do not require a schema change.
    // A 64-bit prefix is sufficient as a lock namespace: a collision only serializes two
    // unrelated files briefly; it cannot mix their rows or weaken database constraints.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(log_lock_key(file_uuid))
        .execute(&mut *tx)
        .await?;

    let seq = sqlx::query_scalar(
        r#"INSERT INTO file_update_log (file_id, seq, sender_device, sender_seq, doc_key_id, kind, frame,
                                       remote_domain, remote_device)
           VALUES (
             $1,
             GREATEST(
               COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id = $1), 0),
               (SELECT collab_log_floor FROM files WHERE id = $1)
             ) + 1,
             $2, $3, $4, $5, $6, $7, $8
           )
           RETURNING seq"#,
    )
    .bind(file_uuid)
    .bind(device_id)
    .bind(f.sequence as i64)
    .bind(f.doc_key_id as i64)
    .bind(f.kind as i16)
    .bind(raw)
    .bind(remote_domain)
    .bind(remote_device)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(seq)
}

/// Streams every frame with `seq > since_seq` to the joining client — mirrors `replayLog`.
async fn replay_log(state: &AppState, peer: &hub::Peer, file_uuid: Uuid, since_seq: i64) {
    let rows: Vec<(i64, Vec<u8>)> = match sqlx::query_as(
        "SELECT seq, frame FROM file_update_log WHERE file_id = $1 AND seq > $2 ORDER BY seq ASC",
    )
    .bind(file_uuid)
    .bind(since_seq)
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut through = since_seq;
    for (seq, frame) in rows {
        if !peer.write(WsOut::Binary(frame)).await {
            return;
        }
        through = seq;
    }
    // Everything up to `through` has now been sent. A client that was behind
    // the floor (a saved version trimmed past it) also needs that version.
    let floor: i64 = sqlx::query_scalar("SELECT collab_log_floor FROM files WHERE id = $1")
        .bind(file_uuid)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(0);
    let _ = peer
        .write(WsOut::Text(
            serde_json::json!({ "type": "replayed", "throughSeq": through, "floor": floor })
                .to_string(),
        ))
        .await;
}
