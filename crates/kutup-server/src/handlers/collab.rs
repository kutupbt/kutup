//! Collaborative-edit WebSocket handler — mirrors `backend/handlers/collab.go`.
//!
//! The server is a blind relay: it verifies each frame's Ed25519 signature (never decrypts)
//! against the frame key the sender's account manifest lists for its device
//! (docs/plans/one-device-list.md), persists the durable kinds to `file_update_log`, and fans
//! frames out to the other peers in the file's room, each named by its sender account
//! (`envelope::deliver`). Auth (a device ticket or token + device credential, file access)
//! happens before the upgrade; `handle_connection` is the per-connection coroutine: hello →
//! join → peer broadcast → read loop → leave.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use kutup_crypto::envelope::{self, Frame};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::account_devices::FrameDevice;
use crate::error::{AppError, AppResult};
use crate::hub::{self, Hub, WsOut};
use crate::AppState;
use kutup_crypto::account_ref::AccountRef;

/// Query params on the WS URL. Browsers can't set headers on `new WebSocket(url)`, so a
/// device ticket (`POST /api/device-ticket`) arrives here; a native client sends its token
/// and `X-Kutup-Device` instead.
#[derive(Debug, Deserialize)]
pub struct CollabQuery {
    pub(crate) ticket: Option<String>,
    /// The tab's own random id (lowercase hex, at most 6 digits): the tabs
    /// of one browser share a device, and the room tells them apart by it
    /// (an office editor keys its participants on it).
    #[serde(default)]
    pub(crate) tab: Option<String>,
}

impl CollabQuery {
    /// The tab id, if well formed (1 to 6 lowercase hex digits, the 24 bits a client
    /// draws): empty otherwise (an older client).
    pub(crate) fn tab(&self) -> String {
        self.tab
            .as_deref()
            .filter(|tab| {
                (1..=6).contains(&tab.len())
                    && tab
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .unwrap_or_default()
            .to_owned()
    }
}

/// One participant in the room's peer-list. Keys are emitted in the alphabetical order Go's
/// `encoding/json` produces for its `fiber.Map`; `color`/`username` are omitted when empty
/// (Go only sets them when non-empty).
#[derive(Debug, Serialize)]
pub(crate) struct PeerSummary {
    /// The peer's account (`aci:<uuid>@<server>`): with `deviceId`, the
    /// sender its frames name.
    account: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    color: String,
    #[serde(rename = "deviceId")]
    device_id: u32,
    /// The tab's id (see `CollabQuery::tab`); omitted for an older client.
    #[serde(skip_serializing_if = "String::is_empty")]
    tab: String,
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
        ("ticket" = Option<String>, Query, description = "A device ticket (browsers cannot set headers on `new WebSocket`)"),
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
    let device = authenticate_socket(&state, &headers, &q).await?;
    // Anyone who may read the file joins; only editors' edits are kept.
    let file_uuid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let access = file_access(&state.pool, device.user_id, file_uuid)
        .await?
        .ok_or_else(|| AppError::not_found("file not found"))?;
    if access == Access::None {
        return Err(AppError::forbidden("forbidden"));
    }

    let conn = Conn {
        file_id,
        file_uuid,
        device,
        tab: q.tab(),
    };
    // One frame carries at most one envelope's plaintext.
    let max_frame = envelope::MAX_PLAINTEXT_BYTES + envelope::MIN_PACKED;
    Ok(upgrade
        .max_message_size(max_frame)
        .max_frame_size(max_frame)
        .on_upgrade(move |socket| async move {
            handle_connection(state, socket, conn).await;
        }))
}

/// The device behind a collaboration socket: a single-use device ticket
/// (browsers), or the access token and `X-Kutup-Device` (native clients). Its
/// frames must count now (`account_devices::frame_device`): `403
/// deviceNotAuthorized` otherwise, and the client registers again.
pub(crate) async fn authenticate_socket(
    state: &AppState,
    headers: &HeaderMap,
    q: &CollabQuery,
) -> AppResult<FrameDevice> {
    match q.ticket.as_deref() {
        Some(ticket) => {
            let (user_id, device_id) =
                crate::account_devices::consume_ticket(state, ticket).await?;
            crate::account_devices::frame_device(state, user_id, device_id).await
        }
        None => crate::account_devices::frame_device_of_request(state, headers).await,
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

/// `None` when the file (or its folder) is gone; a failed query is an error,
/// never "no access".
async fn file_access(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    file_id: Uuid,
) -> Result<Option<Access>, sqlx::Error> {
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
    .await?;
    Ok(row.map(|(owner, share)| match (owner, share) {
        (true, _) | (_, Some(true)) => Access::Write,
        (_, Some(false)) => Access::Read,
        _ => Access::None,
    }))
}

/// A connection's fixed identity, resolved before the upgrade.
struct Conn {
    file_id: String,
    file_uuid: Uuid,
    device: FrameDevice,
    tab: String,
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
    /// A registry value (`collab_frames_per_second`, `collab_frame_burst`,
    /// `collab_bytes_per_second`, `collab_byte_burst`), read at each frame.
    fn of(limit: crate::ratelimit::Limit) -> f64 {
        crate::ratelimit::value(limit) as f64
    }

    pub(crate) fn new() -> Self {
        use crate::ratelimit::Limit;
        FrameBudget {
            frames: Self::of(Limit::CollabFrameBurst),
            bytes: Self::of(Limit::CollabByteBurst),
            last: std::time::Instant::now(),
        }
    }

    /// Takes one frame of `len` bytes from the budget, if it has room.
    pub(crate) fn take(&mut self, len: usize) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        use crate::ratelimit::Limit;
        self.frames = (self.frames + elapsed * Self::of(Limit::CollabFramesPerSecond))
            .min(Self::of(Limit::CollabFrameBurst));
        self.bytes = (self.bytes + elapsed * Self::of(Limit::CollabBytesPerSecond))
            .min(Self::of(Limit::CollabByteBurst));
        if self.frames < 1.0 || self.bytes < len as f64 {
            return false;
        }
        self.frames -= 1.0;
        self.bytes -= len as f64;
        true
    }
}

/// Per-connection coroutine — mirrors `HandleConnection`.
async fn handle_connection(state: AppState, socket: WebSocket, conn: Conn) {
    let hub = state.hub.clone();
    let (file_id, file_uuid) = (conn.file_id.clone(), conn.file_uuid);
    let device = &conn.device;
    let user_uuid = device.user_id;

    // Username + color for the peer-list (best-effort).
    let (username, color): (String, String) = sqlx::query_as(
        "SELECT COALESCE(username, ''), COALESCE(color, '') FROM users WHERE id = $1",
    )
    .bind(user_uuid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or_default();

    // Stamp last_seen_at on every successful upgrade.
    let _ = sqlx::query(
        "UPDATE devices SET last_seen_at = now() WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_uuid)
    .bind(device.device_id as i32)
    .execute(&state.pool)
    .await;

    // hello payload fields. These are not best-effort: a client told a
    // wrong head or sender seq could reuse sequence numbers and have its edits
    // dropped as replays, so a failed read closes the socket before hello.
    let read = async {
        let doc_key_id: i64 =
            sqlx::query_scalar("SELECT current_doc_key_id FROM files WHERE id = $1")
                .bind(file_uuid)
                .fetch_one(&state.pool)
                .await?;
        let head_seq: i64 = log_head(&state.pool, file_uuid).await?;
        let my_sender_seq = sender_seq_high(&state.pool, file_uuid, device).await?;
        Ok::<_, sqlx::Error>((doc_key_id, head_seq, my_sender_seq))
    };
    let (doc_key_id, head_seq, my_sender_seq) = match read.await {
        Ok(values) => values,
        Err(error) => {
            tracing::error!(%error, "collab: could not read the document's state; closing");
            return;
        }
    };

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

    let (peer, mut rx) = hub::new_peer(
        &hub,
        device.device_id,
        conn.tab.clone(),
        user_uuid.to_string(),
        device.account.to_string(),
        username,
        color,
    );

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
                // Closed on a definite "no" (the session ended, the access
                // gone); a failed check is tried again at the next tick.
                let session_ended = matches!(
                    crate::sessions::live(&state.pool, device.session_id, user_uuid).await,
                    Err(ref error) if error.status == axum::http::StatusCode::UNAUTHORIZED
                );
                let access = file_access(&state.pool, user_uuid, file_uuid).await;
                if session_ended || matches!(access, Ok(None | Some(Access::None))) {
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
            account: p.account.clone(),
            color: p.color.clone(),
            device_id: p.device_id,
            tab: p.tab.clone(),
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
    let sender = FrameSender {
        device: &conn.device,
        file_uuid: conn.file_uuid,
        file_id: &conn.file_id,
        conn_id: peer.conn_id,
    };
    !matches!(
        accept_frame(state, &sender, budget, data, true).await,
        FrameOutcome::Close
    )
}

/// Who sends a frame: a socket's connection, or a device posting one over
/// HTTP (`post_frames`, conn id 0: no connection has it).
pub(crate) struct FrameSender<'a> {
    pub device: &'a FrameDevice,
    pub file_uuid: Uuid,
    pub file_id: &'a str,
    pub conn_id: u64,
}

/// What became of a frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FrameOutcome {
    /// Kept in the log at this position (and sent to the room).
    Kept(i64),
    /// Relayed to the room, not kept (presence, scene edits).
    Relayed,
    /// Dropped: not this sender's, not this file's key, a replay, read-only.
    Dropped,
    /// A definite refusal: the socket closes (access gone, budget spent).
    Close,
}

/// The one gate every collaboration frame passes, from a socket or over
/// HTTP: a frame of this device, signed by its key, naming this file, its
/// current key generation and document key; edits from editors only, under a
/// key the folder still holds, within the budget; durable kinds kept (exact
/// replays of a sender sequence dropped), then sent to the room with their
/// position. `relay` allows the kinds that are only relayed (a socket's);
/// over HTTP only kept kinds make sense.
pub(crate) async fn accept_frame(
    state: &AppState,
    sender: &FrameSender<'_>,
    budget: &mut FrameBudget,
    data: &[u8],
    relay: bool,
) -> FrameOutcome {
    let Ok(f) = Frame::unpack(data) else {
        return FrameOutcome::Dropped;
    };
    let device = sender.device;
    if f.device_id != device.device_id || f.sequence > i64::MAX as u64 {
        return FrameOutcome::Dropped; // forged sender
    }
    if envelope::verify(data, &device.account, &device.frame_key).is_err() {
        return FrameOutcome::Dropped;
    }
    // A frame sealed under a later manifest than the one the connection
    // started with: the device listed itself again since, or the frame lies.
    if f.manifest_sequence > device.manifest_sequence {
        let now =
            crate::account_devices::frame_device(state, device.user_id, device.device_id as i32)
                .await;
        if !now.is_ok_and(|now| {
            now.frame_key == device.frame_key && f.manifest_sequence <= now.manifest_sequence
        }) {
            return FrameOutcome::Dropped;
        }
    }
    let delivered = envelope::deliver(&device.account, data);
    let file_uuid = sender.file_uuid;

    // The public authenticated header must name this exact file, its current
    // file-key generation and current document key. Neither stale nor future
    // values are accepted.
    let Some(key_current) = frame_binding(state, file_uuid, &f).await else {
        return FrameOutcome::Dropped;
    };
    // Presence only: cursors and awareness, which any reader may share.
    if is_presence(f.kind) {
        if !relay {
            return FrameOutcome::Dropped;
        }
        state
            .hub
            .broadcast(sender.file_id, sender.conn_id, &delivered)
            .await;
        state
            .collab_federation
            .relayed(file_uuid, None, &device.account, data);
        return FrameOutcome::Relayed;
    }

    // Everything else changes the document: editors only, checked per frame
    // (a share can be narrowed while the socket is open).
    // A failed check never lets the edit through: it closes the socket, as
    // a definite "no" does (the client reconnects).
    match file_access(&state.pool, device.user_id, file_uuid).await {
        Ok(Some(Access::Write)) => {}
        Ok(Some(Access::Read)) => return FrameOutcome::Dropped,
        _ => return FrameOutcome::Close,
    }
    // Edits only under a file key wrapped at the folder's current epoch: a
    // file the folder has rotated past is re-keyed before anyone writes to it
    // (docs/plans/drive-share-revocation.md).
    if !key_current {
        return FrameOutcome::Dropped;
    }
    if !budget.take(data.len()) {
        tracing::warn!(file = %file_uuid, device = device.device_id, "collab frame budget exceeded");
        return FrameOutcome::Close;
    }

    // Scene edits are relayed, not kept.
    if f.kind == envelope::kind::EXCALIDRAW_OP {
        if !relay {
            return FrameOutcome::Dropped;
        }
        state
            .hub
            .broadcast(sender.file_id, sender.conn_id, &delivered)
            .await;
        state
            .collab_federation
            .relayed(file_uuid, None, &device.account, data);
        return FrameOutcome::Relayed;
    }

    // Durable kinds: persist (drop only exact sender-sequence replays), then
    // broadcast, then tell everyone in the room (the sender too) the frame's
    // log position. Each connection gets the frame before its position, so a
    // client knows every frame up to a position it has seen is applied.
    let log_sender = LogSender {
        domain: None,
        account: device.user_id,
        device: device.device_id,
    };
    let Ok(seq) = persist_frame(state, file_uuid, log_sender, &f, data).await else {
        return FrameOutcome::Dropped;
    };
    state
        .hub
        .broadcast(sender.file_id, sender.conn_id, &delivered)
        .await;
    state
        .hub
        .broadcast_text(
            sender.file_id,
            &serde_json::json!({ "type": "stored", "seq": seq }).to_string(),
        )
        .await;
    // Editors on other servers get it too.
    state.collab_federation.kept(file_uuid);
    FrameOutcome::Kept(seq)
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

/// A new version replaced a file's content outside the editor (a Replace in
/// Drive): the room's session base moves to it, and every tab with the file
/// open is told to reopen from it, as after a restore.
pub(crate) async fn replace_base(state: &AppState, file_uuid: Uuid, version_id: &str, seq: i64) {
    let base = hub::SessionBase {
        version_id: Some(version_id.to_owned()),
        seq,
    };
    let message = serde_json::json!({
        "type": "base",
        "versionId": version_id,
        "seq": seq,
        "yours": false,
        "reset": true,
    })
    .to_string();
    for peer in state.hub.replace_base(&file_uuid.to_string(), base) {
        let _ = peer.write(WsOut::Text(message.clone())).await;
    }
}

/// Who sent a kept frame: a device of an account here (`domain` none) or
/// on another server.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LogSender<'a> {
    pub domain: Option<&'a str>,
    pub account: Uuid,
    pub device: u32,
}

/// The highest frame counter `device` has kept in the file's log: its next
/// frame goes above it.
async fn sender_seq_high(
    pool: &sqlx::PgPool,
    file_uuid: Uuid,
    device: &FrameDevice,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(MAX(sender_seq), 0) FROM file_update_log
          WHERE file_id = $1 AND sender_domain = '' AND sender_account = $2
            AND sender_device = $3",
    )
    .bind(file_uuid)
    .bind(device.user_id)
    .bind(device.device_id as i32)
    .fetch_one(pool)
    .await
}

/// A logged frame as delivered: named by its sender's account (this
/// server's name for its own accounts).
pub(crate) fn delivered_from_log(
    state: &AppState,
    domain: &str,
    account: Uuid,
    frame: &[u8],
) -> Option<Vec<u8>> {
    let server = if domain.is_empty() {
        state.config.chat_server_name.as_str()
    } else {
        domain
    };
    let sender = AccountRef::new(server, &account.to_string()).ok()?;
    Some(envelope::deliver(&sender, frame))
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
/// different devices cannot both select the same `MAX(seq) + 1`; the sender's
/// `(domain, account, device, sender_seq)` unique index still rejects exact replays.
pub(crate) async fn persist_frame(
    state: &AppState,
    file_uuid: Uuid,
    sender: LogSender<'_>,
    f: &Frame,
    raw: &[u8],
) -> Result<i64, sqlx::Error> {
    let mut tx = state.pool.begin().await?;

    // PostgreSQL advisory locks are transaction-scoped and do not require a schema change.
    // A 64-bit prefix is sufficient as a lock namespace: a collision only serializes two
    // unrelated files briefly; it cannot mix their rows or weaken database constraints.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(log_lock_key(file_uuid))
        .execute(&mut *tx)
        .await?;

    let seq = sqlx::query_scalar(
        r#"INSERT INTO file_update_log (file_id, seq, sender_account, sender_seq, doc_key_id, kind,
                                       frame, sender_domain, sender_device)
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
    .bind(sender.account)
    .bind(f.sequence as i64)
    .bind(f.doc_key_id as i64)
    .bind(f.kind as i16)
    .bind(raw)
    .bind(sender.domain.unwrap_or(""))
    .bind(sender.device as i32)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(seq)
}

/// Streams every frame with `seq > since_seq` to the joining client — mirrors `replayLog`.
async fn replay_log(state: &AppState, peer: &hub::Peer, file_uuid: Uuid, since_seq: i64) {
    let rows: Vec<(i64, Vec<u8>, String, Uuid)> = match sqlx::query_as(
        "SELECT seq, frame, sender_domain, sender_account FROM file_update_log
          WHERE file_id = $1 AND seq > $2 ORDER BY seq ASC",
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
    for (seq, frame, domain, account) in rows {
        let Some(delivered) = delivered_from_log(state, &domain, account, &frame) else {
            continue;
        };
        if !peer.write(WsOut::Binary(delivered)).await {
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

// --- frames over HTTP (docs/plans/cli-yjs-sync.md) ---------------------------
//
// The CLI edits notes, code files and place lists as a Yjs peer, like a
// browser tab, without holding a socket open: it reads the log and sends its
// edits with these two requests. Both authenticate exactly as the socket does
// (the session and a registered device), and frames go through the same gate
// (`accept_frame`), so nothing reaches the log that a tab could not send.

/// The most frames one read returns.
const MAX_FRAMES_PER_READ: i64 = 500;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct FramesQuery {
    /// Frames after this log position (0: from the start).
    #[serde(default)]
    pub after: i64,
    /// At most this many (default and cap 500).
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoggedFrame {
    pub seq: i64,
    /// Its sender's account (`aci:<uuid>@<server>`), which the frame's
    /// signature covers.
    pub sender: String,
    /// The sealed frame, canonical base64.
    pub frame: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FramesPage {
    pub frames: Vec<LoggedFrame>,
    /// The log's position now.
    pub head_seq: i64,
    /// Positions up to here were trimmed into a saved version: a reader
    /// whose `after` is below it starts from that version instead.
    pub floor: i64,
    pub current_doc_key_id: i64,
    /// This device's highest sender sequence in the file's log: its next
    /// frame goes above it.
    pub my_sender_seq_high: i64,
    /// More frames follow this page.
    pub more: bool,
}

/// `GET /api/files/{fileId}/collab/frames` — the collaboration log after a
/// position, for a reader of the file (as the socket's replay).
#[utoipa::path(
    get,
    path = "/api/files/{fileId}/collab/frames",
    tag = "collab",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "File id"), FramesQuery),
    responses((status = 200, description = "Frames after `after`, oldest first", body = FramesPage))
)]
pub async fn get_frames(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    Query(q): Query<FramesQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let device = crate::account_devices::frame_device_of_request(&state, &headers).await?;
    let file_uuid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    match file_access(&state.pool, device.user_id, file_uuid).await? {
        None => return Err(AppError::not_found("file not found")),
        Some(Access::None) => return Err(AppError::forbidden("forbidden")),
        Some(_) => {}
    }
    let limit = q
        .limit
        .unwrap_or(MAX_FRAMES_PER_READ)
        .clamp(1, MAX_FRAMES_PER_READ);
    let rows: Vec<(i64, Vec<u8>, String, Uuid)> = sqlx::query_as(
        "SELECT seq, frame, sender_domain, sender_account FROM file_update_log
          WHERE file_id = $1 AND seq > $2
          ORDER BY seq ASC LIMIT $3",
    )
    .bind(file_uuid)
    .bind(q.after.max(0))
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let more = rows.len() as i64 > limit;
    let (floor, current_doc_key_id): (i64, i64) =
        sqlx::query_as("SELECT collab_log_floor, current_doc_key_id FROM files WHERE id = $1")
            .bind(file_uuid)
            .fetch_one(&state.pool)
            .await?;
    let head_seq = log_head(&state.pool, file_uuid).await?;
    let my_sender_seq_high = sender_seq_high(&state.pool, file_uuid, &device).await?;
    use base64::Engine as _;
    let own = state.config.chat_server_name.as_str();
    let frames = rows
        .into_iter()
        .take(limit as usize)
        .filter_map(|(seq, frame, domain, account)| {
            let server = if domain.is_empty() {
                own
            } else {
                domain.as_str()
            };
            Some(LoggedFrame {
                seq,
                sender: AccountRef::new(server, &account.to_string())
                    .ok()?
                    .to_string(),
                frame: base64::engine::general_purpose::STANDARD.encode(frame),
            })
        })
        .collect();
    Ok(axum::Json(FramesPage {
        frames,
        head_seq,
        floor,
        current_doc_key_id,
        my_sender_seq_high,
        more,
    })
    .into_response())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrameKept {
    /// Its position in the log.
    pub seq: i64,
}

/// `POST /api/files/{fileId}/collab/frames` — one sealed edit frame
/// (`application/octet-stream`) from a registered device: kept and sent to
/// the room, as from a socket. `409 frameRefused` when the gate drops it (not
/// this device's, a stale key or document key, a replayed sequence): read the
/// log again and rebuild. `403` without write access; `429` past the limit.
#[utoipa::path(
    post,
    path = "/api/files/{fileId}/collab/frames",
    tag = "collab",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "File id")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "One sealed collaboration frame"),
    responses(
        (status = 200, description = "Kept", body = FrameKept),
        (status = 409, description = "frameRefused: dropped by the frame gate")
    )
)]
pub async fn post_frame(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> AppResult<Response> {
    let device = crate::account_devices::frame_device_of_request(&state, &headers).await?;
    if !crate::ratelimit::COLLAB_FRAME_POSTS
        .allow(&format!("{}/{}", device.user_id, device.device_id))
    {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    let file_uuid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    match file_access(&state.pool, device.user_id, file_uuid).await? {
        None => return Err(AppError::not_found("file not found")),
        Some(Access::Write) => {}
        Some(_) => return Err(AppError::forbidden("forbidden")),
    }
    let sender = FrameSender {
        device: &device,
        file_uuid,
        file_id: &file_id,
        // No connection has id 0: the frame reaches every tab in the room.
        conn_id: 0,
    };
    // The rate limit above is this path's budget; one request is one frame.
    let mut budget = FrameBudget::new();
    match accept_frame(&state, &sender, &mut budget, &body, false).await {
        FrameOutcome::Kept(seq) => Ok(axum::Json(FrameKept { seq }).into_response()),
        FrameOutcome::Close => Err(AppError::forbidden("forbidden")),
        FrameOutcome::Relayed | FrameOutcome::Dropped => Err(AppError::conflict(
            "the frame was not kept: read the log again",
        )
        .with_details(serde_json::json!({ "code": "frameRefused" }))),
    }
}

#[cfg(test)]
mod tab_tests {
    use super::CollabQuery;

    fn tab(value: Option<&str>) -> String {
        CollabQuery {
            ticket: None,
            tab: value.map(str::to_owned),
        }
        .tab()
    }

    #[test]
    fn a_tab_id_is_short_lowercase_hex_or_nothing() {
        assert_eq!(tab(Some("0a1b2c")), "0a1b2c");
        assert_eq!(tab(Some("f")), "f");
        for bad in ["", "DEAD", "1234567", "deadbeef", "xyz", "<script>"] {
            assert_eq!(tab(Some(bad)), "", "{bad}");
        }
        assert_eq!(tab(None), "");
    }
}
