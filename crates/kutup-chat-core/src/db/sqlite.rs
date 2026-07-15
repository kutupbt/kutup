//! Native [`ChatDb`] over bundled SQLite — the store every Signal client uses in
//! spirit (SQLCipher/GRDB). One connection per device store, guarded by a
//! `RefCell` because the engine is single-threaded and `apply` needs `&mut` for a
//! transaction while reads only need `&`.
//!
//! At-rest encryption: the schema and access go through this one type, so wrapping
//! the connection with SQLCipher (a `PRAGMA key`) or an app-layer cipher is a
//! localized change behind the same port. v1 relies on the OS app-sandbox
//! encryption of mobile private storage; SQLCipher is the tracked hardening step.

use std::cell::RefCell;
use std::path::Path;

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};

use crate::db::{
    ChatDb, InboundEnvelope, InboundState, InboxMessage, LocalIdentity, OutboxEntry, Pending,
};
use crate::error::{ChatError, Result};

/// Maps a rusqlite error into our typed [`ChatError::Db`].
fn db<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|e| ChatError::Db(e.to_string()))
}

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS local_identity (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    identity_key_pair BLOB    NOT NULL,
    registration_id   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    address TEXT PRIMARY KEY,
    record  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
    address      TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pre_keys (
    id     INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_pre_keys (
    id     INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS kyber_pre_keys (
    id     INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS kyber_base_keys_seen (
    kyber_id INTEGER NOT NULL,
    ec_id    INTEGER NOT NULL,
    base_key BLOB    NOT NULL,
    PRIMARY KEY (kyber_id, ec_id, base_key)
);
CREATE TABLE IF NOT EXISTS sender_keys (
    address         TEXT NOT NULL,
    distribution_id TEXT NOT NULL,
    record          BLOB NOT NULL,
    PRIMARY KEY (address, distribution_id)
);
CREATE TABLE IF NOT EXISTS outbox (
    send_id    TEXT PRIMARY KEY,
    peer       TEXT    NOT NULL,
    content    BLOB    NOT NULL,
    envelopes  BLOB    NOT NULL,
    attempts   INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id               TEXT PRIMARY KEY,
    peer             TEXT    NOT NULL,
    sender_device_id INTEGER NOT NULL,
    cursor           INTEGER NOT NULL,
    content          BLOB    NOT NULL,
    received_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_cursor ON messages (cursor);
CREATE TABLE IF NOT EXISTS inbound_envelopes (
    id          TEXT PRIMARY KEY,
    cursor      INTEGER NOT NULL,
    envelope    BLOB    NOT NULL,
    state       INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS inbound_by_cursor ON inbound_envelopes (cursor, id);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (2, 0);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);";

/// A device store backed by a single SQLite database.
pub struct SqliteChatDb {
    conn: RefCell<Connection>,
}

impl SqliteChatDb {
    /// Open (creating if absent) the device store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(db(Connection::open(path))?)
    }

    /// An ephemeral in-memory store — for tests and throwaway sessions. State
    /// lives only as long as the returned value.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(db(Connection::open_in_memory())?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        // WAL + NORMAL: atomic commits (never a torn transaction), at the cost of
        // possibly re-draining the last message after power loss — safe, because
        // ack happens only after the decrypt transaction commits.
        db(conn.pragma_update(None, "journal_mode", "WAL"))?;
        db(conn.pragma_update(None, "synchronous", "NORMAL"))?;
        db(conn.execute_batch(SCHEMA))?;
        Ok(Self {
            conn: RefCell::new(conn),
        })
    }
}

#[async_trait(?Send)]
impl ChatDb for SqliteChatDb {
    async fn load_local_identity(&self) -> Result<Option<LocalIdentity>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT identity_key_pair, registration_id FROM local_identity WHERE id = 1",
                [],
                |row| {
                    Ok(LocalIdentity {
                        identity_key_pair: row.get(0)?,
                        registration_id: row.get(1)?,
                    })
                },
            )
            .optional())
    }

    async fn load_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        blob(&self.conn.borrow(), "sessions", "address", address)
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT identity_key FROM identities WHERE address = ?1",
                [address],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        blob_by_id(&self.conn.borrow(), "pre_keys", id)
    }

    async fn load_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        blob_by_id(&self.conn.borrow(), "signed_pre_keys", id)
    }

    async fn load_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        blob_by_id(&self.conn.borrow(), "kyber_pre_keys", id)
    }

    async fn kyber_base_key_seen(
        &self,
        kyber_id: u32,
        ec_id: u32,
        base_key: &[u8],
    ) -> Result<bool> {
        let conn = self.conn.borrow();
        let found: Option<i64> = db(conn
            .query_row(
                "SELECT 1 FROM kyber_base_keys_seen \
                 WHERE kyber_id = ?1 AND ec_id = ?2 AND base_key = ?3",
                rusqlite::params![kyber_id, ec_id, base_key],
                |row| row.get(0),
            )
            .optional())?;
        Ok(found.is_some())
    }

    async fn load_sender_key(
        &self,
        address: &str,
        distribution_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT record FROM sender_keys WHERE address = ?1 AND distribution_id = ?2",
                rusqlite::params![address, distribution_id],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_outbox(&self, send_id: &str) -> Result<Option<OutboxEntry>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT send_id, peer, content, envelopes, attempts, created_at \
                 FROM outbox WHERE send_id = ?1",
                [send_id],
                outbox_row,
            )
            .optional())
    }

    async fn list_outbox(&self) -> Result<Vec<OutboxEntry>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT send_id, peer, content, envelopes, attempts, created_at \
             FROM outbox ORDER BY created_at, send_id",
        ))?;
        let rows = db(stmt.query_map([], outbox_row))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(db(row)?);
        }
        Ok(out)
    }

    async fn load_last_cursor(&self) -> Result<Option<u64>> {
        let conn = self.conn.borrow();
        let value: Option<i64> = db(conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'last_cursor'",
                [],
                |row| row.get(0),
            )
            .optional())?;
        Ok(value.map(|n| n as u64))
    }

    async fn list_messages(&self) -> Result<Vec<InboxMessage>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT id, peer, sender_device_id, cursor, content, received_at \
             FROM messages ORDER BY cursor, id",
        ))?;
        let rows = db(stmt.query_map([], message_row))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(db(row)?);
        }
        Ok(out)
    }

    async fn list_inbound(&self) -> Result<Vec<InboundEnvelope>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT id, cursor, envelope, state, attempts, last_error, received_at \
             FROM inbound_envelopes ORDER BY cursor, id",
        ))?;
        let rows = db(stmt.query_map([], inbound_row))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(db(row)??);
        }
        Ok(out)
    }

    async fn apply(&self, pending: &Pending) -> Result<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = db(conn.transaction())?;

        if let Some(local) = &pending.local_identity {
            db(tx.execute(
                "INSERT INTO local_identity (id, identity_key_pair, registration_id) \
                 VALUES (1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET \
                   identity_key_pair = excluded.identity_key_pair, \
                   registration_id = excluded.registration_id",
                rusqlite::params![local.identity_key_pair, local.registration_id],
            ))?;
        }
        for (address, record) in &pending.sessions {
            match record {
                Some(bytes) => db(tx.execute(
                    "INSERT INTO sessions (address, record) VALUES (?1, ?2) \
                     ON CONFLICT(address) DO UPDATE SET record = excluded.record",
                    rusqlite::params![address, bytes],
                ))?,
                None => db(tx.execute("DELETE FROM sessions WHERE address = ?1", [address]))?,
            };
        }
        for (address, key) in &pending.identities {
            db(tx.execute(
                "INSERT INTO identities (address, identity_key) VALUES (?1, ?2) \
                 ON CONFLICT(address) DO UPDATE SET identity_key = excluded.identity_key",
                rusqlite::params![address, key],
            ))?;
        }
        for (id, record) in &pending.pre_keys {
            match record {
                Some(bytes) => db(tx.execute(
                    "INSERT INTO pre_keys (id, record) VALUES (?1, ?2) \
                     ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                    rusqlite::params![id, bytes],
                ))?,
                None => db(tx.execute("DELETE FROM pre_keys WHERE id = ?1", [id]))?,
            };
        }
        for (id, record) in &pending.signed_pre_keys {
            db(tx.execute(
                "INSERT INTO signed_pre_keys (id, record) VALUES (?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                rusqlite::params![id, record],
            ))?;
        }
        for (id, record) in &pending.kyber_pre_keys {
            db(tx.execute(
                "INSERT INTO kyber_pre_keys (id, record) VALUES (?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                rusqlite::params![id, record],
            ))?;
        }
        for (kyber_id, ec_id, base_key) in &pending.kyber_seen {
            db(tx.execute(
                "INSERT OR IGNORE INTO kyber_base_keys_seen (kyber_id, ec_id, base_key) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![kyber_id, ec_id, base_key],
            ))?;
        }
        for ((address, distribution_id), record) in &pending.sender_keys {
            db(tx.execute(
                "INSERT INTO sender_keys (address, distribution_id, record) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(address, distribution_id) DO UPDATE SET record = excluded.record",
                rusqlite::params![address, distribution_id, record],
            ))?;
        }
        for (send_id, entry) in &pending.outbox {
            match entry {
                Some(e) => db(tx.execute(
                    "INSERT INTO outbox (send_id, peer, content, envelopes, attempts, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                     ON CONFLICT(send_id) DO UPDATE SET \
                       peer = excluded.peer, content = excluded.content, \
                       envelopes = excluded.envelopes, attempts = excluded.attempts",
                    rusqlite::params![
                        send_id,
                        e.peer,
                        e.content,
                        e.envelopes,
                        e.attempts,
                        e.created_at
                    ],
                ))?,
                None => db(tx.execute("DELETE FROM outbox WHERE send_id = ?1", [send_id]))?,
            };
        }
        for msg in &pending.messages {
            // INSERT OR IGNORE: redelivery of the same mailbox id is a no-op.
            db(tx.execute(
                "INSERT OR IGNORE INTO messages \
                 (id, peer, sender_device_id, cursor, content, received_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    msg.id,
                    msg.peer,
                    msg.sender_device_id,
                    msg.cursor as i64,
                    msg.content,
                    msg.received_at
                ],
            ))?;
        }
        for (id, inbound) in &pending.inbound {
            match inbound {
                Some(item) => db(tx.execute(
                    "INSERT INTO inbound_envelopes \
                     (id, cursor, envelope, state, attempts, last_error, received_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                     ON CONFLICT(id) DO UPDATE SET \
                       cursor = excluded.cursor, envelope = excluded.envelope, \
                       state = excluded.state, attempts = excluded.attempts, \
                       last_error = excluded.last_error",
                    rusqlite::params![
                        id,
                        item.cursor as i64,
                        item.envelope,
                        item.state.code(),
                        item.attempts,
                        item.last_error,
                        item.received_at
                    ],
                ))?,
                None => db(tx.execute("DELETE FROM inbound_envelopes WHERE id = ?1", [id]))?,
            };
        }
        if let Some(cursor) = pending.last_cursor {
            // MAX guards monotonicity: the drain cursor never moves backwards.
            db(tx.execute(
                "INSERT INTO meta (key, value) VALUES ('last_cursor', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)",
                [cursor as i64],
            ))?;
        }

        db(tx.commit())
    }
}

fn inbound_row(row: &rusqlite::Row) -> rusqlite::Result<Result<InboundEnvelope>> {
    let id = row.get(0)?;
    let cursor = row.get::<_, i64>(1)? as u64;
    let envelope = row.get(2)?;
    let state_code: i64 = row.get(3)?;
    let attempts = row.get(4)?;
    let last_error = row.get(5)?;
    let received_at = row.get(6)?;
    Ok(
        InboundState::from_code(state_code).map(|state| InboundEnvelope {
            id,
            cursor,
            envelope,
            state,
            attempts,
            last_error,
            received_at,
        }),
    )
}

/// Reads one row of the `messages` table into an [`InboxMessage`].
fn message_row(row: &rusqlite::Row) -> rusqlite::Result<InboxMessage> {
    Ok(InboxMessage {
        id: row.get(0)?,
        peer: row.get(1)?,
        sender_device_id: row.get(2)?,
        cursor: row.get::<_, i64>(3)? as u64,
        content: row.get(4)?,
        received_at: row.get(5)?,
    })
}

/// Reads one row of the `outbox` table into an [`OutboxEntry`].
fn outbox_row(row: &rusqlite::Row) -> rusqlite::Result<OutboxEntry> {
    Ok(OutboxEntry {
        send_id: row.get(0)?,
        peer: row.get(1)?,
        content: row.get(2)?,
        envelopes: row.get(3)?,
        attempts: row.get(4)?,
        created_at: row.get(5)?,
    })
}

/// `SELECT <col-named `record`> FROM <table> WHERE <key_col> = <key>`.
fn blob(conn: &Connection, table: &str, key_col: &str, key: &str) -> Result<Option<Vec<u8>>> {
    let sql = format!("SELECT record FROM {table} WHERE {key_col} = ?1");
    db(conn.query_row(&sql, [key], |row| row.get(0)).optional())
}

/// `blob` for the integer-keyed prekey tables.
fn blob_by_id(conn: &Connection, table: &str, id: u32) -> Result<Option<Vec<u8>>> {
    let sql = format!("SELECT record FROM {table} WHERE id = ?1");
    db(conn.query_row(&sql, [id], |row| row.get(0)).optional())
}
