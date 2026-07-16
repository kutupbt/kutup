//! Native [`ChatDb`] over bundled SQLite — the store every Signal client uses in
//! spirit (SQLCipher/GRDB). One connection per device store, guarded by a
//! `RefCell` because the engine is single-threaded and `apply` needs `&mut` for a
//! transaction while reads only need `&`.
//!
//! Public native apps select the `sqlcipher` feature and call
//! [`SqliteChatDb::open_encrypted`]. The constructor verifies SQLCipher is
//! actually linked before touching the schema; a build accidentally linked to
//! ordinary SQLite therefore fails closed. Plain [`open`](Self::open) exists for
//! tests/dev tooling and must not be used by release bindings.

use std::cell::RefCell;
use std::path::Path;

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroize as _;

use crate::db::{
    AuthorityTrust, ChatDb, InboundEnvelope, InboundFailureKind, InboundState, InboxMessage,
    LocalIdentity, ManifestTrust, OutboxEntry, Pending, SentMessage,
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
    registration_id   INTEGER NOT NULL,
    device_id          INTEGER
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
    id      INTEGER PRIMARY KEY,
    record  BLOB NOT NULL,
    used_at INTEGER
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
    send_id          TEXT PRIMARY KEY,
    peer             TEXT    NOT NULL,
    content          BLOB    NOT NULL,
    envelopes        BLOB    NOT NULL,
    attempts         INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    primary_delivered INTEGER NOT NULL DEFAULT 0,
    sync_leg         BLOB
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
CREATE TABLE IF NOT EXISTS sent_messages (
    send_id        TEXT PRIMARY KEY,
    peer           TEXT    NOT NULL,
    content        BLOB    NOT NULL,
    created_at     INTEGER NOT NULL,
    delivered_at   INTEGER,
    delivered      INTEGER NOT NULL,
    deduplicated   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sent_messages_by_created_at
    ON sent_messages (created_at, send_id);
CREATE TABLE IF NOT EXISTS inbound_envelopes (
    id          TEXT PRIMARY KEY,
    cursor      INTEGER NOT NULL,
    envelope    BLOB    NOT NULL,
    state       INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    failure_kind INTEGER,
    last_error  TEXT,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS inbound_by_cursor ON inbound_envelopes (cursor, id);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (2, 0);
CREATE TABLE IF NOT EXISTS manifest_trust (
    peer               TEXT PRIMARY KEY,
    authority_key_id   TEXT    NOT NULL,
    self_authority_key TEXT    NOT NULL,
    highest_version    INTEGER NOT NULL,
    manifest_hash      TEXT    NOT NULL,
    trust_state        INTEGER NOT NULL,
    continuity_gap     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_prekey_upload (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    request BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_chat_registration (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    request BLOB NOT NULL
);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (3, 0);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);";

/// A device store backed by a single SQLite database.
pub struct SqliteChatDb {
    conn: RefCell<Connection>,
}

impl SqliteChatDb {
    /// Open an unencrypted device store. Tests/dev only; release bindings use
    /// [`open_encrypted`](Self::open_encrypted).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(db(Connection::open(path))?)
    }

    /// Open a SQLCipher database with a raw 256-bit platform-keystore key.
    /// Fails if SQLCipher support is absent or the key cannot unlock an existing
    /// database. The key never enters SQL or logs except as a short-lived,
    /// zeroized hexadecimal PRAGMA buffer.
    pub fn open_encrypted(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self> {
        let conn = db(Connection::open(path))?;
        let mut key_hex = hex::encode(key);
        let mut pragma = format!("PRAGMA key = \"x'{key_hex}'\";");
        let keyed = conn.execute_batch(&pragma);
        pragma.zeroize();
        key_hex.zeroize();
        db(keyed)?;

        let cipher_version: Option<String> = db(conn
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .optional())?;
        if cipher_version.as_deref().is_none_or(str::is_empty) {
            return Err(ChatError::Db(
                "SQLCipher is unavailable; refusing to open chat state unencrypted".into(),
            ));
        }
        db(conn.execute_batch(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA foreign_keys = ON;",
        ))?;
        Self::from_connection(conn)
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
        ensure_schema_upgrades(&conn)?;
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
                "SELECT identity_key_pair, registration_id, device_id FROM local_identity WHERE id = 1",
                [],
                |row| {
                    Ok(LocalIdentity {
                        identity_key_pair: row.get(0)?,
                        registration_id: row.get(1)?,
                        device_id: row.get(2)?,
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

    async fn purge_used_pre_keys(&self, used_before_ms: i64) -> Result<u64> {
        let changed = db(self.conn.borrow().execute(
            "DELETE FROM pre_keys WHERE used_at IS NOT NULL AND used_at <= ?1",
            [used_before_ms],
        ))?;
        Ok(changed as u64)
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
                "SELECT send_id, peer, content, envelopes, attempts, created_at, \
                        primary_delivered, sync_leg \
                 FROM outbox WHERE send_id = ?1",
                [send_id],
                outbox_row,
            )
            .optional())
    }

    async fn list_outbox(&self) -> Result<Vec<OutboxEntry>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT send_id, peer, content, envelopes, attempts, created_at, \
                    primary_delivered, sync_leg \
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

    async fn load_last_sent_seq(&self) -> Result<Option<u64>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'last_sent_seq'",
                [],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .optional())
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

    async fn load_sent_message(&self, send_id: &str) -> Result<Option<SentMessage>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT send_id, peer, content, created_at, delivered_at, delivered, deduplicated
                 FROM sent_messages WHERE send_id = ?1",
                [send_id],
                sent_message_row,
            )
            .optional())
    }

    async fn list_sent_messages(&self) -> Result<Vec<SentMessage>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT send_id, peer, content, created_at, delivered_at, delivered, deduplicated
             FROM sent_messages ORDER BY created_at, send_id",
        ))?;
        let rows = db(stmt.query_map([], sent_message_row))?;
        rows.map(db).collect()
    }

    async fn list_inbound(&self) -> Result<Vec<InboundEnvelope>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT id, cursor, envelope, state, attempts, failure_kind, last_error, received_at \
             FROM inbound_envelopes ORDER BY cursor, id",
        ))?;
        let rows = db(stmt.query_map([], inbound_row))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(db(row)??);
        }
        Ok(out)
    }

    async fn load_manifest_trust(&self, peer: &str) -> Result<Option<ManifestTrust>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT peer, authority_key_id, self_authority_key, highest_version,
                        manifest_hash, trust_state, continuity_gap
                 FROM manifest_trust WHERE peer = ?1",
                [peer],
                |row| {
                    let trust_state: i64 = row.get(5)?;
                    let trust = AuthorityTrust::from_code(trust_state).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    Ok(ManifestTrust {
                        peer: row.get(0)?,
                        authority_key_id: row.get(1)?,
                        self_authority_key: row.get(2)?,
                        highest_version: row.get::<_, i64>(3)? as u64,
                        manifest_hash: row.get(4)?,
                        trust,
                        continuity_gap: row.get::<_, i64>(6)? != 0,
                    })
                },
            )
            .optional())
    }

    async fn load_pending_prekey_upload(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT request FROM pending_prekey_upload WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_pending_registration(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT request FROM pending_chat_registration WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional())
    }

    async fn apply(&self, pending: &Pending) -> Result<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = db(conn.transaction())?;

        if let Some(local) = &pending.local_identity {
            db(tx.execute(
                "INSERT INTO local_identity (id, identity_key_pair, registration_id, device_id) \
                 VALUES (1, ?1, ?2, ?3) \
                 ON CONFLICT(id) DO UPDATE SET \
                   identity_key_pair = excluded.identity_key_pair, \
                   registration_id = excluded.registration_id, \
                   device_id = excluded.device_id",
                rusqlite::params![
                    local.identity_key_pair,
                    local.registration_id,
                    local.device_id
                ],
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
                    "INSERT INTO pre_keys (id, record, used_at) VALUES (?1, ?2, NULL) \
                     ON CONFLICT(id) DO UPDATE SET record = excluded.record, used_at = NULL",
                    rusqlite::params![id, bytes],
                ))?,
                None => db(tx.execute(
                    "UPDATE pre_keys SET used_at = ?2 WHERE id = ?1 AND used_at IS NULL",
                    rusqlite::params![id, unix_millis()],
                ))?,
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
                    "INSERT INTO outbox (send_id, peer, content, envelopes, attempts, created_at, \
                                         primary_delivered, sync_leg) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                     ON CONFLICT(send_id) DO UPDATE SET \
                       peer = excluded.peer, content = excluded.content, \
                       envelopes = excluded.envelopes, attempts = excluded.attempts, \
                       primary_delivered = excluded.primary_delivered, \
                       sync_leg = excluded.sync_leg",
                    rusqlite::params![
                        send_id,
                        e.peer,
                        e.content,
                        e.envelopes,
                        e.attempts,
                        e.created_at,
                        i64::from(e.primary_delivered),
                        e.sync
                            .as_ref()
                            .map(serde_json::to_vec)
                            .transpose()
                            .map_err(|error| ChatError::Db(error.to_string()))?
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
        for (send_id, message) in &pending.sent_messages {
            db(tx.execute(
                "INSERT INTO sent_messages
                     (send_id, peer, content, created_at, delivered_at, delivered, deduplicated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(send_id) DO UPDATE SET
                     peer = excluded.peer, content = excluded.content,
                     delivered_at = excluded.delivered_at,
                     delivered = excluded.delivered,
                     deduplicated = excluded.deduplicated",
                rusqlite::params![
                    send_id,
                    message.peer,
                    message.content,
                    message.created_at,
                    message.delivered_at,
                    i64::from(message.delivered),
                    i64::from(message.deduplicated),
                ],
            ))?;
        }
        for (id, inbound) in &pending.inbound {
            match inbound {
                Some(item) => db(tx.execute(
                    "INSERT INTO inbound_envelopes \
                     (id, cursor, envelope, state, attempts, failure_kind, last_error, received_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                     ON CONFLICT(id) DO UPDATE SET \
                       cursor = excluded.cursor, envelope = excluded.envelope, \
                       state = excluded.state, attempts = excluded.attempts, \
                       failure_kind = excluded.failure_kind, last_error = excluded.last_error",
                    rusqlite::params![
                        id,
                        item.cursor as i64,
                        item.envelope,
                        item.state.code(),
                        item.attempts,
                        item.failure_kind.map(InboundFailureKind::code),
                        item.last_error,
                        item.received_at
                    ],
                ))?,
                None => db(tx.execute("DELETE FROM inbound_envelopes WHERE id = ?1", [id]))?,
            };
        }
        for (peer, trust) in &pending.manifest_trust {
            db(tx.execute(
                "INSERT INTO manifest_trust
                     (peer, authority_key_id, self_authority_key, highest_version,
                      manifest_hash, trust_state, continuity_gap)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(peer) DO UPDATE SET
                     authority_key_id = excluded.authority_key_id,
                     self_authority_key = excluded.self_authority_key,
                     highest_version = excluded.highest_version,
                     manifest_hash = excluded.manifest_hash,
                     trust_state = excluded.trust_state,
                     continuity_gap = excluded.continuity_gap",
                rusqlite::params![
                    peer,
                    trust.authority_key_id,
                    trust.self_authority_key,
                    trust.highest_version as i64,
                    trust.manifest_hash,
                    trust.trust.code(),
                    i64::from(trust.continuity_gap),
                ],
            ))?;
        }
        if let Some(upload) = &pending.prekey_upload {
            match upload {
                Some(request) => db(tx.execute(
                    "INSERT INTO pending_prekey_upload (id, request) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET request = excluded.request",
                    [request],
                ))?,
                None => db(tx.execute("DELETE FROM pending_prekey_upload WHERE id = 1", []))?,
            };
        }
        if let Some(upload) = &pending.registration_upload {
            match upload {
                Some(request) => db(tx.execute(
                    "INSERT INTO pending_chat_registration (id, request) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET request = excluded.request",
                    [request],
                ))?,
                None => db(tx.execute("DELETE FROM pending_chat_registration WHERE id = 1", []))?,
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
        if let Some(seq) = pending.last_sent_seq {
            db(tx.execute(
                "INSERT INTO meta (key, value) VALUES ('last_sent_seq', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)",
                [seq as i64],
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
    let failure_code: Option<i64> = row.get(5)?;
    let last_error = row.get(6)?;
    let received_at = row.get(7)?;
    let failure_kind = failure_code.map(InboundFailureKind::from_code).transpose();
    Ok(InboundState::from_code(state_code).and_then(|state| {
        failure_kind.map(|failure_kind| InboundEnvelope {
            id,
            cursor,
            envelope,
            state,
            attempts,
            failure_kind,
            last_error,
            received_at,
        })
    }))
}

/// The original proof schema predated typed inbound failures. SQLite lacks
/// `ADD COLUMN IF NOT EXISTS`, so inspect before applying the additive upgrade.
fn ensure_schema_upgrades(conn: &Connection) -> Result<()> {
    if !has_column(conn, "inbound_envelopes", "failure_kind")? {
        db(conn.execute(
            "ALTER TABLE inbound_envelopes ADD COLUMN failure_kind INTEGER",
            [],
        ))?;
    }
    if !has_column(conn, "pre_keys", "used_at")? {
        db(conn.execute("ALTER TABLE pre_keys ADD COLUMN used_at INTEGER", []))?;
    }
    if !has_column(conn, "local_identity", "device_id")? {
        db(conn.execute(
            "ALTER TABLE local_identity ADD COLUMN device_id INTEGER",
            [],
        ))?;
    }
    if !has_column(conn, "outbox", "primary_delivered")? {
        db(conn.execute(
            "ALTER TABLE outbox ADD COLUMN primary_delivered INTEGER NOT NULL DEFAULT 0",
            [],
        ))?;
    }
    if !has_column(conn, "outbox", "sync_leg")? {
        db(conn.execute("ALTER TABLE outbox ADD COLUMN sync_leg BLOB", []))?;
    }
    db(conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_chat_registration (
             id INTEGER PRIMARY KEY CHECK (id = 1), request BLOB NOT NULL
         );",
    ))?;
    db(conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at)
         VALUES (4, 0), (5, 0), (6, 0), (7, 0), (8, 0)",
        [],
    ))?;
    Ok(())
}

fn has_column(conn: &Connection, table: &str, wanted: &str) -> Result<bool> {
    let mut stmt = db(conn.prepare(&format!("PRAGMA table_info({table})")))?;
    let columns = db(stmt.query_map([], |row| row.get::<_, String>(1)))?;
    for column in columns {
        if db(column)? == wanted {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unix_millis() -> i64 {
    crate::clock::unix_millis()
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
    let sync: Option<Vec<u8>> = row.get(7)?;
    Ok(OutboxEntry {
        send_id: row.get(0)?,
        peer: row.get(1)?,
        content: row.get(2)?,
        envelopes: row.get(3)?,
        attempts: row.get(4)?,
        created_at: row.get(5)?,
        primary_delivered: row.get::<_, i64>(6)? != 0,
        sync: sync
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        bytes.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })
            })
            .transpose()?,
    })
}

fn sent_message_row(row: &rusqlite::Row) -> rusqlite::Result<SentMessage> {
    Ok(SentMessage {
        send_id: row.get(0)?,
        peer: row.get(1)?,
        content: row.get(2)?,
        created_at: row.get(3)?,
        delivered_at: row.get(4)?,
        delivered: row.get::<_, i64>(5)? != 0,
        deduplicated: row.get::<_, i64>(6)? != 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_the_pre_typed_failure_journal_in_place() {
        use futures_executor::block_on;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
             CREATE TABLE inbound_envelopes (
                 id TEXT PRIMARY KEY, cursor INTEGER NOT NULL, envelope BLOB NOT NULL,
                 state INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT, received_at INTEGER NOT NULL
             );
             CREATE TABLE pre_keys (id INTEGER PRIMARY KEY, record BLOB NOT NULL);
             CREATE TABLE outbox (
                 send_id TEXT PRIMARY KEY, peer TEXT NOT NULL, content BLOB NOT NULL,
                 envelopes BLOB NOT NULL, attempts INTEGER NOT NULL, created_at INTEGER NOT NULL
             );
             INSERT INTO outbox VALUES ('legacy-send', 'bob', X'01', X'02', 1, 123);",
        )
        .unwrap();
        let db = SqliteChatDb::from_connection(conn).unwrap();
        let count: i64 = db
            .conn
            .borrow()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('inbound_envelopes')
                 WHERE name = 'failure_kind'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert!(has_column(&db.conn.borrow(), "pre_keys", "used_at").unwrap());
        assert!(has_column(&db.conn.borrow(), "outbox", "primary_delivered").unwrap());
        assert!(has_column(&db.conn.borrow(), "outbox", "sync_leg").unwrap());
        let legacy = block_on(db.load_outbox("legacy-send")).unwrap().unwrap();
        assert!(!legacy.primary_delivered);
        assert!(legacy.sync.is_none());
    }

    #[test]
    fn used_ec_prekeys_remain_loadable_until_the_grace_sweep() {
        use futures_executor::block_on;

        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut insert = Pending::default();
        insert.pre_keys.insert(7, Some(vec![1, 2, 3]));
        block_on(db.apply(&insert)).unwrap();
        let mut used = Pending::default();
        used.pre_keys.insert(7, None);
        block_on(db.apply(&used)).unwrap();

        assert_eq!(block_on(db.load_pre_key(7)).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(block_on(db.purge_used_pre_keys(i64::MAX)).unwrap(), 1);
        assert_eq!(block_on(db.load_pre_key(7)).unwrap(), None);
    }

    #[cfg(not(feature = "sqlcipher"))]
    #[test]
    fn encrypted_open_fails_closed_when_sqlcipher_is_not_linked() {
        let path =
            std::env::temp_dir().join(format!("kutup-chat-no-sqlcipher-{}.db", unix_millis()));
        let result = SqliteChatDb::open_encrypted(&path, &[3; 32]);
        assert!(matches!(result, Err(ChatError::Db(message)) if message.contains("unavailable")));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn sqlcipher_store_reopens_with_the_key_and_rejects_a_wrong_key() {
        use futures_executor::block_on;

        let path = std::env::temp_dir().join(format!("kutup-chat-sqlcipher-{}.db", unix_millis()));
        let key = [7; 32];
        let db = SqliteChatDb::open_encrypted(&path, &key).unwrap();
        let seed = Pending {
            local_identity: Some(LocalIdentity {
                identity_key_pair: vec![1, 2, 3],
                registration_id: 42,
                device_id: Some(1),
            }),
            ..Pending::default()
        };
        block_on(db.apply(&seed)).unwrap();
        drop(db);

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw
            .windows(b"local_identity".len())
            .any(|w| w == b"local_identity"));
        let reopened = SqliteChatDb::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            block_on(reopened.load_local_identity())
                .unwrap()
                .unwrap()
                .registration_id,
            42
        );
        drop(reopened);
        assert!(SqliteChatDb::open_encrypted(&path, &[8; 32]).is_err());

        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
