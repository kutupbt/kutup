//! In-memory registry of live chat WebSocket connections — the chat analogue of the
//! collab `hub` (same conventions: process-unique conn ids, bounded per-connection
//! outbound buffers drained by a writer task, `Notify`-based forced close).
//!
//! Keyed by (user, chat device): envelope delivery targets a specific recipient device,
//! and one device may hold several sockets (browser tabs) — all get the push. The
//! mailbox row is the source of truth; a WS push is a latency optimization, so a failed
//! push is not an error path (the client drains over REST).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use uuid::Uuid;

/// Bounded outbound buffer per connection — mirrors the collab hub's `WS_OUT_BUF`.
pub const CHAT_WS_OUT_BUF: usize = 256;
/// How long a push waits for buffer room before the conn is torn down.
pub const CHAT_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(2);

/// A message queued for a chat socket. Always JSON text
/// (`kutup_chat_proto::ChatWsServerMessage`) or a close signal.
pub enum ChatWsOut {
    Text(String),
    Close,
}

/// One live chat socket.
pub struct ChatConn {
    pub conn_id: u64,
    tx: mpsc::Sender<ChatWsOut>,
    /// Notified to force the read loop to exit (device revoked / backpressure).
    pub close: Arc<Notify>,
}

impl ChatConn {
    /// Enqueues `msg`, closing the connection on backpressure timeout. Returns `false`
    /// if the peer is gone — callers don't care (mailbox is the source of truth).
    pub async fn write(&self, msg: ChatWsOut) -> bool {
        match tokio::time::timeout(CHAT_BACKPRESSURE_TIMEOUT, self.tx.send(msg)).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => false,
            Err(_) => {
                self.close.notify_waiters();
                let _ = self.tx.try_send(ChatWsOut::Close);
                false
            }
        }
    }
}

/// Live connections of one device (a device may hold several sockets — browser tabs).
type DeviceConns = HashMap<(Uuid, i32), Vec<Arc<ChatConn>>>;

/// Registry of live chat connections, keyed by (user, device).
#[derive(Clone, Default)]
pub struct ChatHub {
    inner: Arc<Mutex<DeviceConns>>,
    next_conn_id: Arc<AtomicU64>,
}

impl ChatHub {
    /// Registers a socket; returns the connection handle plus the receiver its writer
    /// task drains.
    pub fn join(
        &self,
        user_id: Uuid,
        device_id: i32,
    ) -> (Arc<ChatConn>, mpsc::Receiver<ChatWsOut>) {
        let (tx, rx) = mpsc::channel(CHAT_WS_OUT_BUF);
        let conn = Arc::new(ChatConn {
            conn_id: self.next_conn_id.fetch_add(1, Ordering::Relaxed),
            tx,
            close: Arc::new(Notify::new()),
        });
        self.inner
            .lock()
            .expect("chat hub lock poisoned")
            .entry((user_id, device_id))
            .or_default()
            .push(conn.clone());
        (conn, rx)
    }

    /// Removes a socket (read loop exit).
    pub fn leave(&self, user_id: Uuid, device_id: i32, conn_id: u64) {
        let mut inner = self.inner.lock().expect("chat hub lock poisoned");
        if let Some(conns) = inner.get_mut(&(user_id, device_id)) {
            conns.retain(|c| c.conn_id != conn_id);
            if conns.is_empty() {
                inner.remove(&(user_id, device_id));
            }
        }
    }

    /// Snapshot of a device's live connections (push targets). Snapshotting avoids
    /// holding the lock across awaits.
    pub fn connections(&self, user_id: Uuid, device_id: i32) -> Vec<Arc<ChatConn>> {
        self.inner
            .lock()
            .expect("chat hub lock poisoned")
            .get(&(user_id, device_id))
            .cloned()
            .unwrap_or_default()
    }

    /// Force-closes every socket of a device (revocation / re-registration).
    pub fn close_device(&self, user_id: Uuid, device_id: i32) {
        let conns = {
            let mut inner = self.inner.lock().expect("chat hub lock poisoned");
            inner.remove(&(user_id, device_id)).unwrap_or_default()
        };
        for conn in conns {
            conn.close.notify_waiters();
            let _ = conn.tx.try_send(ChatWsOut::Close);
        }
    }
}
