//! In-memory collab-room registry — mirrors `backend/handlers/collab_hub.go`.
//!
//! One room per `fileId`; each room holds the live peer connections. The Go hub keyed peers
//! by the `HubConn` pointer; here we key by a process-unique `conn_id` (an atomic counter)
//! so the same device can hold two connections without aliasing. The writer side of each
//! connection is an `mpsc::Sender<WsOut>` drained by a per-connection writer task (the Rust
//! analogue of `wsConn.writePump`); `close` is a `Notify` the read loop selects on so a
//! revoked device (or a backpressure timeout) can tear the connection down.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{mpsc, Notify};

/// Bounded outbound buffer per connection — mirrors `wsOutBuf`.
pub const WS_OUT_BUF: usize = 256;
/// How long a write waits for buffer room before the conn is closed — mirrors
/// `backpressureTimeout`.
pub const BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(2);

/// A message queued for delivery to a peer's socket.
pub enum WsOut {
    /// Binary collab frame.
    Binary(Vec<u8>),
    /// JSON control message (hello / peers), sent as a text frame.
    Text(String),
    /// Tear the connection down (device revoked / backpressure timeout).
    Close,
}

/// One live WebSocket connection in a room. Mirrors the fields of `wsConn` the hub needs.
pub struct Peer {
    pub conn_id: u64,
    pub device_id: i64,
    pub user_id: String,
    pub username: String,
    pub color: String,
    tx: mpsc::Sender<WsOut>,
    /// Notified to force the read loop to exit (revocation / forced close).
    pub close: Arc<Notify>,
}

impl Peer {
    /// Enqueues `msg`, waiting up to `BACKPRESSURE_TIMEOUT` for buffer room before giving up
    /// and closing the connection — mirrors `wsConn.WriteFrame`/`WriteText`. Returns `false`
    /// if the peer was closed / timed out.
    pub async fn write(&self, msg: WsOut) -> bool {
        match tokio::time::timeout(BACKPRESSURE_TIMEOUT, self.tx.send(msg)).await {
            Ok(Ok(())) => true,
            // Channel closed (conn gone) — nothing to do.
            Ok(Err(_)) => false,
            // Stuck writer: signal a close, like Go's `c.Close()` on timeout.
            Err(_) => {
                self.close.notify_waiters();
                let _ = self.tx.try_send(WsOut::Close);
                false
            }
        }
    }
}

#[derive(Default)]
struct Room {
    peers: HashMap<u64, Arc<Peer>>,
    /// The office editing session's base: the version (None: the original
    /// upload) every tab in the room started from, and its log position.
    /// Set by the first tab, reset by a restore; gone with the room.
    base: Option<SessionBase>,
}

/// Where an office editing session started (docs/onlyoffice.md,
/// "Collaboration sessions"). ONLYOFFICE's edits name objects created during
/// the session, so every tab must load this and replay the log after `seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBase {
    pub version_id: Option<String>,
    pub seq: i64,
}

/// What a claim on a room's session base came to.
pub struct BaseClaim {
    /// The room's base now.
    pub base: SessionBase,
    /// The claimant's base is the room's (it set it, or it matched).
    pub yours: bool,
    /// The claim started the session: nobody else was in the room.
    pub new_session: bool,
    /// On a reset, the other peers, to be told to reopen.
    pub others: Vec<Arc<Peer>>,
}

/// The in-memory registry of per-file collab rooms — mirrors `Hub`.
pub struct Hub {
    rooms: Mutex<HashMap<String, Room>>,
    next_conn_id: AtomicU64,
}

impl Hub {
    pub fn new() -> Hub {
        Hub {
            rooms: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
        }
    }

    /// A fresh process-unique connection id.
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Registers a peer in the file's room — mirrors `Join`.
    pub fn join(&self, file_id: &str, peer: Arc<Peer>) {
        let mut rooms = self.rooms.lock().unwrap();
        rooms
            .entry(file_id.to_string())
            .or_default()
            .peers
            .insert(peer.conn_id, peer);
    }

    /// Removes a peer; drops the room when it empties — mirrors `Leave`.
    pub fn leave(&self, file_id: &str, conn_id: u64) {
        let mut rooms = self.rooms.lock().unwrap();
        if let Some(room) = rooms.get_mut(file_id) {
            room.peers.remove(&conn_id);
            if room.peers.is_empty() {
                rooms.remove(file_id);
            }
        }
    }

    /// Claims the room's session base for `conn_id`: the first claim (or a
    /// `reset`, after a restore) sets it; later ones learn it.
    pub fn claim_base(
        &self,
        file_id: &str,
        conn_id: u64,
        claim: SessionBase,
        reset: bool,
    ) -> Option<BaseClaim> {
        let mut rooms = self.rooms.lock().unwrap();
        let room = rooms.get_mut(file_id)?;
        let alone = room.peers.len() == 1 && room.peers.contains_key(&conn_id);
        // A room keeps a base only while someone who set it is there: a
        // claimant alone in the room starts a new session.
        if reset || alone || room.base.is_none() {
            room.base = Some(claim.clone());
            let others = if reset {
                room.peers
                    .values()
                    .filter(|p| p.conn_id != conn_id)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            return Some(BaseClaim {
                base: claim,
                yours: true,
                new_session: alone && !reset,
                others,
            });
        }
        let base = room.base.clone().unwrap_or(claim.clone());
        Some(BaseClaim {
            yours: base == claim,
            base,
            new_session: false,
            others: Vec::new(),
        })
    }

    /// Snapshot of the connections currently in a file's room — mirrors `Peers`.
    pub fn peers(&self, file_id: &str) -> Vec<Arc<Peer>> {
        let rooms = self.rooms.lock().unwrap();
        match rooms.get(file_id) {
            Some(room) => room.peers.values().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// Sends a JSON control message to every peer in the room, the sender too.
    pub async fn broadcast_text(&self, file_id: &str, text: &str) {
        let targets: Vec<Arc<Peer>> = {
            let rooms = self.rooms.lock().unwrap();
            match rooms.get(file_id) {
                Some(room) => room.peers.values().cloned().collect(),
                None => Vec::new(),
            }
        };
        for p in targets {
            p.write(WsOut::Text(text.to_owned())).await;
        }
    }

    /// Sends `frame` to every peer in the room except `sender_conn_id` — mirrors `Broadcast`.
    /// Snapshots the peer set under the lock, then writes outside it (so a slow peer can't
    /// head-of-line-block the room while the lock is held).
    pub async fn broadcast(&self, file_id: &str, sender_conn_id: u64, frame: &[u8]) {
        let targets: Vec<Arc<Peer>> = {
            let rooms = self.rooms.lock().unwrap();
            match rooms.get(file_id) {
                Some(room) => room
                    .peers
                    .values()
                    .filter(|p| p.conn_id != sender_conn_id)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            }
        };
        for p in targets {
            let _ = p.write(WsOut::Binary(frame.to_vec())).await;
        }
    }

    /// Closes every connection in a file's room — after a re-key, so peers
    /// reconnect and continue under the new key.
    pub fn close_room(&self, file_id: &str) {
        let victims: Vec<Arc<Peer>> = {
            let rooms = self.rooms.lock().unwrap();
            rooms
                .get(file_id)
                .map(|room| room.peers.values().cloned().collect())
                .unwrap_or_default()
        };
        for v in victims {
            v.close.notify_waiters();
            let _ = v.tx.try_send(WsOut::Close);
        }
    }

    /// Forces every connection from a device to close, across all rooms — mirrors
    /// `CloseDevice` (device revocation). The connections' own read loops call `leave` as
    /// they exit, so this only signals; it doesn't mutate room state.
    pub fn close_device(&self, device_id: i64) {
        let victims: Vec<Arc<Peer>> = {
            let rooms = self.rooms.lock().unwrap();
            rooms
                .values()
                .flat_map(|r| r.peers.values())
                .filter(|p| p.device_id == device_id)
                .cloned()
                .collect()
        };
        for v in victims {
            v.close.notify_waiters();
            let _ = v.tx.try_send(WsOut::Close);
        }
    }
}

/// Builds a peer + its outbound channel. The caller spawns a writer task draining `rx`.
pub fn new_peer(
    hub: &Hub,
    device_id: i64,
    user_id: String,
    username: String,
    color: String,
) -> (Arc<Peer>, mpsc::Receiver<WsOut>) {
    let (tx, rx) = mpsc::channel(WS_OUT_BUF);
    let peer = Arc::new(Peer {
        conn_id: hub.next_conn_id(),
        device_id,
        user_id,
        username,
        color,
        tx,
        close: Arc::new(Notify::new()),
    });
    (peer, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(hub: &Hub, device_id: i64) -> (Arc<Peer>, mpsc::Receiver<WsOut>) {
        new_peer(hub, device_id, String::new(), String::new(), String::new())
    }

    #[test]
    fn add_remove() {
        let h = Hub::new();
        let (c1, _r1) = peer(&h, 1);
        let (c2, _r2) = peer(&h, 2);
        h.join("file-A", c1.clone());
        h.join("file-A", c2);
        assert_eq!(h.peers("file-A").len(), 2);
        h.leave("file-A", c1.conn_id);
        assert_eq!(h.peers("file-A").len(), 1);
    }

    #[tokio::test]
    async fn broadcast_skips_sender() {
        let h = Hub::new();
        let (c1, mut r1) = peer(&h, 1);
        let (c2, mut r2) = peer(&h, 2);
        h.join("f", c1.clone());
        h.join("f", c2.clone());
        h.broadcast("f", c1.conn_id, b"data").await;
        assert!(
            r1.try_recv().is_err(),
            "sender should not receive its own broadcast"
        );
        match r2.try_recv() {
            Ok(WsOut::Binary(b)) => assert_eq!(b, b"data"),
            _ => panic!("peer should receive broadcast"),
        }
    }

    #[test]
    fn close_device_leaves_other_rooms_intact() {
        let h = Hub::new();
        let (c1, _r1) = peer(&h, 1);
        let (c2, _r2) = peer(&h, 2);
        let (c1b, _r1b) = peer(&h, 1); // device 1, second connection
        h.join("f1", c1);
        h.join("f2", c2);
        h.join("f3", c1b);
        h.close_device(1);
        // close_device only signals; the conns' read loops call leave. Smoke check: it
        // doesn't panic or mutate other rooms.
        assert_eq!(h.peers("f2").len(), 1);
    }

    fn base(version: Option<&str>, seq: i64) -> SessionBase {
        SessionBase {
            version_id: version.map(String::from),
            seq,
        }
    }

    #[test]
    fn session_base_first_claim_sets_joiners_learn_it() {
        let h = Hub::new();
        let (a, _ra) = peer(&h, 1);
        let (b, _rb) = peer(&h, 2);
        h.join("f", a.clone());
        // Alone: the claim starts a session and sets the base.
        let first = h
            .claim_base("f", a.conn_id, base(Some("v1"), 10), false)
            .unwrap();
        assert!(first.yours && first.new_session);
        assert_eq!(first.base, base(Some("v1"), 10));
        // A joiner that loaded a newer save is told the session's base.
        h.join("f", b.clone());
        let joiner = h
            .claim_base("f", b.conn_id, base(Some("v2"), 20), false)
            .unwrap();
        assert!(!joiner.yours && !joiner.new_session);
        assert_eq!(joiner.base, base(Some("v1"), 10));
        // One that loaded the base matches it.
        let same = h
            .claim_base("f", b.conn_id, base(Some("v1"), 10), false)
            .unwrap();
        assert!(same.yours && !same.new_session);
    }

    #[test]
    fn session_base_reset_replaces_it_and_names_the_others() {
        let h = Hub::new();
        let (a, _ra) = peer(&h, 1);
        let (b, _rb) = peer(&h, 2);
        h.join("f", a.clone());
        h.join("f", b.clone());
        h.claim_base("f", a.conn_id, base(None, 0), false).unwrap();
        let reset = h
            .claim_base("f", a.conn_id, base(Some("restored"), 30), true)
            .unwrap();
        assert!(reset.yours && !reset.new_session);
        assert_eq!(reset.others.len(), 1);
        assert_eq!(reset.others[0].conn_id, b.conn_id);
        let joiner = h
            .claim_base("f", b.conn_id, base(Some("restored"), 30), false)
            .unwrap();
        assert!(joiner.yours);
    }

    #[test]
    fn session_base_ends_with_the_room() {
        let h = Hub::new();
        let (a, _ra) = peer(&h, 1);
        h.join("f", a.clone());
        h.claim_base("f", a.conn_id, base(Some("v1"), 10), false)
            .unwrap();
        h.leave("f", a.conn_id);
        // Nobody left: the next tab starts a new session from what it loaded.
        let (b, _rb) = peer(&h, 2);
        h.join("f", b.clone());
        let next = h
            .claim_base("f", b.conn_id, base(Some("v3"), 40), false)
            .unwrap();
        assert!(next.yours && next.new_session);
        // A claim outside any room is ignored.
        assert!(h
            .claim_base("nowhere", b.conn_id, base(None, 0), false)
            .is_none());
    }
}
