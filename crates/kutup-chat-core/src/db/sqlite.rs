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
    contact_state_code, contact_state_from_code, AccountManifestHistoryRecordV1, AuthorityTrust,
    ChatDb, ContactRecord, ImportedHistoryRecordV1, InboundEnvelope, InboundFailureKind,
    InboundState, InboxMessage, LocalIdentity, LocalProfile, ManifestTrust, MlsHistoryMessage,
    MlsOutboxDelivery, MlsOutboxEntry, OutboxEntry, PeerProfile, Pending, SentMessage,
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
    sync_leg         BLOB,
    sealed_sender    INTEGER NOT NULL DEFAULT 0,
    sealed_capability BLOB
);
CREATE TABLE IF NOT EXISTS mls_state (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS mls_outbox (
    send_id          TEXT PRIMARY KEY,
    conversation_id BLOB    NOT NULL CHECK (length(conversation_id) = 16),
    incarnation      INTEGER NOT NULL CHECK (incarnation > 0),
    mls_group_id     BLOB    NOT NULL CHECK (length(mls_group_id) BETWEEN 16 AND 255),
    epoch            INTEGER NOT NULL CHECK (epoch >= 0),
    content_digest   BLOB    NOT NULL CHECK (length(content_digest) = 32),
    content          BLOB    NOT NULL DEFAULT X'',
    ciphertext       BLOB    NOT NULL,
    expected_recipients BLOB NOT NULL DEFAULT X'5B5D',
    deliveries       BLOB    NOT NULL DEFAULT X'5B5D',
    created_at       INTEGER NOT NULL,
    attempts         INTEGER NOT NULL CHECK (attempts >= 0)
);
CREATE INDEX IF NOT EXISTS mls_outbox_by_created_at
    ON mls_outbox (created_at, send_id);
CREATE TABLE IF NOT EXISTS mls_messages (
    record_id        TEXT PRIMARY KEY,
    message_id       TEXT    NOT NULL,
    conversation_id BLOB    NOT NULL CHECK (length(conversation_id) = 16),
    incarnation      INTEGER NOT NULL CHECK (incarnation > 0),
    mls_group_id     BLOB    NOT NULL CHECK (length(mls_group_id) BETWEEN 16 AND 255),
    epoch            INTEGER NOT NULL CHECK (epoch >= 0),
    sender           TEXT    NOT NULL,
    sender_device_id INTEGER NOT NULL CHECK (sender_device_id > 0),
    outgoing         INTEGER NOT NULL,
    cursor           INTEGER,
    transport_digest BLOB    NOT NULL CHECK (length(transport_digest) = 32),
    content          BLOB    NOT NULL,
    timestamp_ms     INTEGER NOT NULL,
    delivered        INTEGER NOT NULL,
    deduplicated     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mls_messages_by_time
    ON mls_messages (timestamp_ms, record_id);
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
CREATE TABLE IF NOT EXISTS imported_history (
    transfer_id       TEXT NOT NULL,
    source_record_id  TEXT NOT NULL,
    source_device_id  INTEGER NOT NULL CHECK (source_device_id > 0),
    conversation_json TEXT NOT NULL,
    sender            TEXT NOT NULL,
    sender_device_id  INTEGER NOT NULL CHECK (sender_device_id > 0),
    outgoing          INTEGER NOT NULL,
    content           BLOB NOT NULL,
    timestamp_ms      INTEGER NOT NULL,
    delivered         INTEGER NOT NULL,
    PRIMARY KEY (transfer_id, source_record_id)
);
CREATE INDEX IF NOT EXISTS imported_history_by_time
    ON imported_history (timestamp_ms, transfer_id, source_record_id);
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
    account            TEXT    NOT NULL,
    incarnation_id     TEXT    NOT NULL,
    authority_key_id   TEXT    NOT NULL,
    self_authority_key TEXT    NOT NULL,
    drive_hpke_public_key TEXT NOT NULL,
    drive_share_signing_public_key TEXT NOT NULL,
    highest_sequence    INTEGER NOT NULL,
    manifest_hash      TEXT    NOT NULL,
    trust_state        INTEGER NOT NULL,
    continuity_gap     INTEGER NOT NULL,
    quarantine_reason  TEXT,
    pending_reset_json TEXT
);
CREATE TABLE IF NOT EXISTS manifest_history (
    peer          TEXT    NOT NULL,
    incarnation_id TEXT   NOT NULL,
    sequence      INTEGER NOT NULL,
    manifest_json TEXT    NOT NULL,
    PRIMARY KEY (peer, incarnation_id, sequence)
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
CREATE TABLE IF NOT EXISTS contacts (
    peer             TEXT PRIMARY KEY,
    state            INTEGER NOT NULL,
    previous_state   INTEGER,
    revision         INTEGER NOT NULL,
    source_device_id INTEGER NOT NULL,
    updated_at_ms    INTEGER NOT NULL,
    sync_pending     INTEGER NOT NULL DEFAULT 0,
    sync_send_id     TEXT
);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (9, 0);
CREATE TABLE IF NOT EXISTS local_profile (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    profile BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS peer_profiles (
    peer    TEXT PRIMARY KEY,
    profile BLOB NOT NULL
);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (10, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (11, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (12, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (13, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (14, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (15, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (16, 0);
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (17, 0);
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
                        primary_delivered, sync_leg, sealed_sender, sealed_capability \
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
                    primary_delivered, sync_leg, sealed_sender, sealed_capability \
             FROM outbox ORDER BY created_at, send_id",
        ))?;
        let rows = db(stmt.query_map([], outbox_row))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(db(row)?);
        }
        Ok(out)
    }

    async fn load_mls_outbox(&self, send_id: &str) -> Result<Option<MlsOutboxEntry>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT send_id, conversation_id, incarnation, mls_group_id, epoch,
                        content_digest, content, ciphertext, expected_recipients,
                        deliveries, created_at, attempts
                 FROM mls_outbox WHERE send_id = ?1",
                [send_id],
                mls_outbox_row,
            )
            .optional())
    }

    async fn list_mls_outbox(&self) -> Result<Vec<MlsOutboxEntry>> {
        let conn = self.conn.borrow();
        let mut statement = db(conn.prepare(
            "SELECT send_id, conversation_id, incarnation, mls_group_id, epoch,
                    content_digest, content, ciphertext, expected_recipients,
                    deliveries, created_at, attempts
             FROM mls_outbox ORDER BY created_at, send_id",
        ))?;
        let rows = db(statement.query_map([], mls_outbox_row))?;
        rows.map(db).collect()
    }

    async fn load_mls_message(&self, record_id: &str) -> Result<Option<MlsHistoryMessage>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT record_id, message_id, conversation_id, incarnation,
                        mls_group_id, epoch, sender, sender_device_id, outgoing,
                        cursor, transport_digest, content, timestamp_ms, delivered, deduplicated
                 FROM mls_messages WHERE record_id = ?1",
                [record_id],
                mls_message_row,
            )
            .optional())
    }

    async fn list_mls_messages(&self) -> Result<Vec<MlsHistoryMessage>> {
        let conn = self.conn.borrow();
        let mut statement = db(conn.prepare(
            "SELECT record_id, message_id, conversation_id, incarnation,
                    mls_group_id, epoch, sender, sender_device_id, outgoing,
                    cursor, transport_digest, content, timestamp_ms, delivered, deduplicated
             FROM mls_messages ORDER BY timestamp_ms, record_id",
        ))?;
        let rows = db(statement.query_map([], mls_message_row))?;
        rows.map(db).collect()
    }

    async fn load_mls_state(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row("SELECT state FROM mls_state WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional())
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

    async fn load_imported_history(
        &self,
        transfer_id: &str,
        source_record_id: &str,
    ) -> Result<Option<ImportedHistoryRecordV1>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT transfer_id, source_record_id, source_device_id,
                        conversation_json, sender, sender_device_id, outgoing,
                        content, timestamp_ms, delivered
                 FROM imported_history
                 WHERE transfer_id = ?1 AND source_record_id = ?2",
                rusqlite::params![transfer_id, source_record_id],
                imported_history_row,
            )
            .optional())
    }

    async fn list_imported_history(&self) -> Result<Vec<ImportedHistoryRecordV1>> {
        let conn = self.conn.borrow();
        let mut statement = db(conn.prepare(
            "SELECT transfer_id, source_record_id, source_device_id,
                    conversation_json, sender, sender_device_id, outgoing,
                    content, timestamp_ms, delivered
             FROM imported_history
             ORDER BY timestamp_ms, transfer_id, source_record_id",
        ))?;
        let rows = db(statement.query_map([], imported_history_row))?;
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
                "SELECT peer, account, incarnation_id, authority_key_id,
                        self_authority_key, drive_hpke_public_key,
                        drive_share_signing_public_key, highest_sequence,
                        manifest_hash, trust_state, continuity_gap,
                        quarantine_reason, pending_reset_json
                 FROM manifest_trust WHERE peer = ?1",
                [peer],
                |row| {
                    let trust_state: i64 = row.get(9)?;
                    let trust = AuthorityTrust::from_code(trust_state).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            9,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    Ok(ManifestTrust {
                        peer: row.get(0)?,
                        account: row.get(1)?,
                        incarnation_id: row.get(2)?,
                        authority_key_id: row.get(3)?,
                        self_authority_key: row.get(4)?,
                        drive_hpke_public_key: row.get(5)?,
                        drive_share_signing_public_key: row.get(6)?,
                        highest_sequence: row.get::<_, i64>(7)? as u64,
                        manifest_hash: row.get(8)?,
                        trust,
                        continuity_gap: row.get::<_, i64>(10)? != 0,
                        quarantine_reason: row.get(11)?,
                        pending_reset: row
                            .get::<_, Option<String>>(12)?
                            .map(|value| serde_json::from_str(&value))
                            .transpose()
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    12,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                    })
                },
            )
            .optional())
    }

    async fn load_manifest_history(
        &self,
        peer: &str,
        incarnation_id: &str,
        sequence: u64,
    ) -> Result<Option<AccountManifestHistoryRecordV1>> {
        let conn = self.conn.borrow();
        let row: Option<String> = db(conn
            .query_row(
                "SELECT manifest_json FROM manifest_history
                 WHERE peer = ?1 AND incarnation_id = ?2 AND sequence = ?3",
                rusqlite::params![peer, incarnation_id, sequence as i64],
                |row| row.get(0),
            )
            .optional())?;
        row.map(|manifest| {
            Ok(AccountManifestHistoryRecordV1 {
                peer: peer.to_string(),
                sequence,
                manifest: serde_json::from_str(&manifest)
                    .map_err(|error| ChatError::Db(error.to_string()))?,
            })
        })
        .transpose()
    }

    async fn load_contact(&self, peer: &str) -> Result<Option<ContactRecord>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT peer, state, previous_state, revision, source_device_id,
                        updated_at_ms, sync_pending, sync_send_id
                 FROM contacts WHERE peer = ?1",
                [peer],
                contact_row,
            )
            .optional())
    }

    async fn list_contacts(&self) -> Result<Vec<ContactRecord>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT peer, state, previous_state, revision, source_device_id,
                    updated_at_ms, sync_pending, sync_send_id
             FROM contacts ORDER BY peer",
        ))?;
        let rows = db(stmt.query_map([], contact_row))?;
        rows.map(db).collect()
    }

    async fn load_local_profile(&self) -> Result<Option<LocalProfile>> {
        let conn = self.conn.borrow();
        let encoded: Option<Vec<u8>> = db(conn
            .query_row(
                "SELECT profile FROM local_profile WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional())?;
        encoded
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| ChatError::Db(format!("decode local profile: {error}")))
            })
            .transpose()
    }

    async fn load_peer_profile(&self, peer: &str) -> Result<Option<PeerProfile>> {
        let conn = self.conn.borrow();
        let encoded: Option<Vec<u8>> = db(conn
            .query_row(
                "SELECT profile FROM peer_profiles WHERE peer = ?1",
                [peer],
                |row| row.get(0),
            )
            .optional())?;
        encoded
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| ChatError::Db(format!("decode peer profile: {error}")))
            })
            .transpose()
    }

    async fn list_peer_profiles(&self) -> Result<Vec<PeerProfile>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare("SELECT profile FROM peer_profiles ORDER BY peer"))?;
        let rows = db(stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)))?;
        rows.map(|row| {
            let bytes = db(row)?;
            serde_json::from_slice(&bytes)
                .map_err(|error| ChatError::Db(format!("decode peer profile: {error}")))
        })
        .collect()
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
                                         primary_delivered, sync_leg, sealed_sender, sealed_capability) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                     ON CONFLICT(send_id) DO UPDATE SET \
                       peer = excluded.peer, content = excluded.content, \
                       envelopes = excluded.envelopes, attempts = excluded.attempts, \
                       primary_delivered = excluded.primary_delivered, \
                       sync_leg = excluded.sync_leg, sealed_sender = excluded.sealed_sender, \
                       sealed_capability = excluded.sealed_capability",
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
                            .map_err(|error| ChatError::Db(error.to_string()))?,
                        i64::from(e.sealed_sender),
                        e.sealed_capability.as_ref().map(|value| value.as_slice()),
                    ],
                ))?,
                None => db(tx.execute("DELETE FROM outbox WHERE send_id = ?1", [send_id]))?,
            };
        }
        if let Some(state) = &pending.mls_state {
            db(tx.execute(
                "INSERT INTO mls_state (id, state) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET state = excluded.state",
                [state],
            ))?;
        }
        for (send_id, entry) in &pending.mls_outbox {
            match entry {
                Some(entry) => {
                    let changed = db(tx.execute(
                        "INSERT INTO mls_outbox
                             (send_id, conversation_id, incarnation, mls_group_id, epoch,
                              content_digest, content, ciphertext, expected_recipients,
                              deliveries, created_at, attempts)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                         ON CONFLICT(send_id) DO UPDATE SET
                           attempts = excluded.attempts,
                           deliveries = excluded.deliveries
                         WHERE mls_outbox.conversation_id = excluded.conversation_id
                           AND mls_outbox.incarnation = excluded.incarnation
                           AND mls_outbox.mls_group_id = excluded.mls_group_id
                           AND mls_outbox.epoch = excluded.epoch
                           AND mls_outbox.content_digest = excluded.content_digest
                           AND mls_outbox.content = excluded.content
                           AND mls_outbox.ciphertext = excluded.ciphertext
                           AND mls_outbox.expected_recipients = excluded.expected_recipients",
                        rusqlite::params![
                            send_id,
                            entry.conversation_id.as_slice(),
                            entry.incarnation as i64,
                            entry.mls_group_id,
                            entry.epoch as i64,
                            entry.content_digest.as_slice(),
                            entry.content,
                            entry.ciphertext,
                            serde_json::to_vec(&entry.expected_recipients)
                                .map_err(|error| ChatError::Db(error.to_string()))?,
                            serde_json::to_vec(&entry.deliveries)
                                .map_err(|error| ChatError::Db(error.to_string()))?,
                            entry.created_at,
                            entry.attempts,
                        ],
                    ))?;
                    if changed != 1 {
                        return Err(ChatError::Trust(format!(
                            "MLS send id {send_id} is already bound to different ciphertext"
                        )));
                    }
                }
                None => {
                    db(tx.execute("DELETE FROM mls_outbox WHERE send_id = ?1", [send_id]))?;
                }
            };
        }
        for (record_id, message) in &pending.mls_messages {
            let changed = db(tx.execute(
                "INSERT INTO mls_messages
                     (record_id, message_id, conversation_id, incarnation,
                      mls_group_id, epoch, sender, sender_device_id, outgoing,
                      cursor, transport_digest, content, timestamp_ms, delivered, deduplicated)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                 ON CONFLICT(record_id) DO UPDATE SET
                   delivered = excluded.delivered,
                   deduplicated = excluded.deduplicated
                 WHERE mls_messages.message_id = excluded.message_id
                   AND mls_messages.conversation_id = excluded.conversation_id
                   AND mls_messages.incarnation = excluded.incarnation
                   AND mls_messages.mls_group_id = excluded.mls_group_id
                   AND mls_messages.epoch = excluded.epoch
                   AND mls_messages.sender = excluded.sender
                   AND mls_messages.sender_device_id = excluded.sender_device_id
                   AND mls_messages.outgoing = excluded.outgoing
                   AND mls_messages.cursor IS excluded.cursor
                   AND mls_messages.transport_digest = excluded.transport_digest
                   AND mls_messages.content = excluded.content
                   AND mls_messages.timestamp_ms = excluded.timestamp_ms",
                rusqlite::params![
                    record_id,
                    message.message_id,
                    message.conversation_id.as_slice(),
                    message.incarnation as i64,
                    message.mls_group_id,
                    message.epoch as i64,
                    message.sender,
                    message.sender_device_id,
                    i64::from(message.outgoing),
                    message.cursor.map(|cursor| cursor as i64),
                    message.transport_digest.as_slice(),
                    message.content,
                    message.timestamp_ms,
                    i64::from(message.delivered),
                    i64::from(message.deduplicated),
                ],
            ))?;
            if changed != 1 {
                return Err(ChatError::Trust(format!(
                    "MLS application receipt {record_id} conflicts with durable history"
                )));
            }
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
        for peer in &pending.delete_messages_for_peers {
            db(tx.execute("DELETE FROM messages WHERE peer = ?1", [peer]))?;
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
        for ((transfer_id, source_record_id), record) in &pending.imported_history {
            let conversation_json = serde_json::to_string(&record.conversation)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let changed = db(tx.execute(
                "INSERT INTO imported_history
                     (transfer_id, source_record_id, source_device_id,
                      conversation_json, sender, sender_device_id, outgoing,
                      content, timestamp_ms, delivered)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(transfer_id, source_record_id) DO UPDATE SET
                   transfer_id = excluded.transfer_id
                 WHERE imported_history.source_device_id = excluded.source_device_id
                   AND imported_history.conversation_json = excluded.conversation_json
                   AND imported_history.sender = excluded.sender
                   AND imported_history.sender_device_id = excluded.sender_device_id
                   AND imported_history.outgoing = excluded.outgoing
                   AND imported_history.content = excluded.content
                   AND imported_history.timestamp_ms = excluded.timestamp_ms
                   AND imported_history.delivered = excluded.delivered",
                rusqlite::params![
                    transfer_id,
                    source_record_id,
                    record.source_device_id,
                    conversation_json,
                    record.sender,
                    record.sender_device_id,
                    i64::from(record.outgoing),
                    record.content,
                    record.timestamp_ms,
                    i64::from(record.delivered),
                ],
            ))?;
            if changed != 1 {
                return Err(ChatError::Trust(format!(
                    "immutable imported history conflicts at {transfer_id}/{source_record_id}"
                )));
            }
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
                     (peer, account, incarnation_id, authority_key_id,
                      self_authority_key, drive_hpke_public_key,
                      drive_share_signing_public_key, highest_sequence,
                      manifest_hash, trust_state, continuity_gap,
                      quarantine_reason, pending_reset_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(peer) DO UPDATE SET
                     account = excluded.account,
                     incarnation_id = excluded.incarnation_id,
                     authority_key_id = excluded.authority_key_id,
                     self_authority_key = excluded.self_authority_key,
                     drive_hpke_public_key = excluded.drive_hpke_public_key,
                     drive_share_signing_public_key = excluded.drive_share_signing_public_key,
                     highest_sequence = excluded.highest_sequence,
                     manifest_hash = excluded.manifest_hash,
                     trust_state = excluded.trust_state,
                     continuity_gap = excluded.continuity_gap,
                     quarantine_reason = excluded.quarantine_reason,
                     pending_reset_json = excluded.pending_reset_json",
                rusqlite::params![
                    peer,
                    trust.account,
                    trust.incarnation_id,
                    trust.authority_key_id,
                    trust.self_authority_key,
                    trust.drive_hpke_public_key,
                    trust.drive_share_signing_public_key,
                    trust.highest_sequence as i64,
                    trust.manifest_hash,
                    trust.trust.code(),
                    i64::from(trust.continuity_gap),
                    trust.quarantine_reason,
                    trust
                        .pending_reset
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| ChatError::Db(error.to_string()))?,
                ],
            ))?;
        }
        for ((peer, incarnation_id, sequence), record) in &pending.manifest_history {
            let manifest_json = serde_json::to_string(&record.manifest)
                .map_err(|error| ChatError::Db(error.to_string()))?;
            let changed = db(tx.execute(
                "INSERT INTO manifest_history (peer, incarnation_id, sequence, manifest_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(peer, incarnation_id, sequence) DO UPDATE SET
                   manifest_json = excluded.manifest_json
                 WHERE manifest_history.manifest_json = excluded.manifest_json",
                rusqlite::params![peer, incarnation_id, *sequence as i64, manifest_json],
            ))?;
            if changed != 1 {
                return Err(ChatError::Trust(format!(
                    "immutable manifest history conflicts at {peer} sequence {sequence}"
                )));
            }
        }
        for (peer, contact) in &pending.contacts {
            db(tx.execute(
                "INSERT INTO contacts
                     (peer, state, previous_state, revision, source_device_id,
                      updated_at_ms, sync_pending, sync_send_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(peer) DO UPDATE SET
                     state = excluded.state,
                     previous_state = excluded.previous_state,
                     revision = excluded.revision,
                     source_device_id = excluded.source_device_id,
                     updated_at_ms = excluded.updated_at_ms,
                     sync_pending = excluded.sync_pending,
                     sync_send_id = excluded.sync_send_id",
                rusqlite::params![
                    peer,
                    contact_state_code(contact.state),
                    contact.previous_state.map(contact_state_code),
                    contact.revision as i64,
                    contact.source_device_id,
                    contact.updated_at_ms,
                    i64::from(contact.sync_pending),
                    contact.sync_send_id,
                ],
            ))?;
        }
        if let Some(profile) = &pending.local_profile {
            let encoded = serde_json::to_vec(profile)
                .map_err(|error| ChatError::Db(format!("encode local profile: {error}")))?;
            db(tx.execute(
                "INSERT INTO local_profile (id, profile) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET profile = excluded.profile",
                [encoded],
            ))?;
        }
        for (peer, profile) in &pending.peer_profiles {
            let encoded = serde_json::to_vec(profile)
                .map_err(|error| ChatError::Db(format!("encode peer profile: {error}")))?;
            db(tx.execute(
                "INSERT INTO peer_profiles (peer, profile) VALUES (?1, ?2)
                 ON CONFLICT(peer) DO UPDATE SET profile = excluded.profile",
                rusqlite::params![peer, encoded],
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
    if !has_column(conn, "outbox", "sealed_sender")? {
        db(conn.execute(
            "ALTER TABLE outbox ADD COLUMN sealed_sender INTEGER NOT NULL DEFAULT 0",
            [],
        ))?;
    }
    if !has_column(conn, "outbox", "sealed_capability")? {
        db(conn.execute("ALTER TABLE outbox ADD COLUMN sealed_capability BLOB", []))?;
    }
    if !has_column(conn, "mls_outbox", "content")? {
        db(conn.execute(
            "ALTER TABLE mls_outbox ADD COLUMN content BLOB NOT NULL DEFAULT X''",
            [],
        ))?;
    }
    if !has_column(conn, "mls_outbox", "expected_recipients")? {
        db(conn.execute(
            "ALTER TABLE mls_outbox ADD COLUMN expected_recipients BLOB NOT NULL DEFAULT X'5B5D'",
            [],
        ))?;
    }
    if !has_column(conn, "mls_outbox", "deliveries")? {
        db(conn.execute(
            "ALTER TABLE mls_outbox ADD COLUMN deliveries BLOB NOT NULL DEFAULT X'5B5D'",
            [],
        ))?;
    }
    if has_column(conn, "mls_messages", "record_id")?
        && !has_column(conn, "mls_messages", "transport_digest")?
    {
        db(conn.execute(
            "ALTER TABLE mls_messages ADD COLUMN transport_digest BLOB NOT NULL
             DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'",
            [],
        ))?;
    }
    db(conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_chat_registration (
             id INTEGER PRIMARY KEY CHECK (id = 1), request BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS mls_messages (
             record_id TEXT PRIMARY KEY,
             message_id TEXT NOT NULL,
             conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 16),
             incarnation INTEGER NOT NULL CHECK (incarnation > 0),
             mls_group_id BLOB NOT NULL CHECK (length(mls_group_id) BETWEEN 16 AND 255),
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             sender TEXT NOT NULL,
             sender_device_id INTEGER NOT NULL CHECK (sender_device_id > 0),
             outgoing INTEGER NOT NULL,
             cursor INTEGER,
             transport_digest BLOB NOT NULL CHECK (length(transport_digest) = 32),
             content BLOB NOT NULL,
             timestamp_ms INTEGER NOT NULL,
             delivered INTEGER NOT NULL,
             deduplicated INTEGER NOT NULL
         );",
    ))?;
    db(conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at)
         VALUES (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 0), (16, 0)",
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

fn contact_row(row: &rusqlite::Row) -> rusqlite::Result<ContactRecord> {
    let state_code: i64 = row.get(1)?;
    let previous_code: Option<i64> = row.get(2)?;
    let state = contact_state_from_sql(state_code, 1)?;
    let previous_state = previous_code
        .map(|code| contact_state_from_sql(code, 2))
        .transpose()?;
    Ok(ContactRecord {
        peer: row.get(0)?,
        state,
        previous_state,
        revision: row.get::<_, i64>(3)? as u64,
        source_device_id: row.get(4)?,
        updated_at_ms: row.get(5)?,
        sync_pending: row.get::<_, i64>(6)? != 0,
        sync_send_id: row.get(7)?,
    })
}

fn contact_state_from_sql(
    code: i64,
    column: usize,
) -> rusqlite::Result<kutup_chat_proto::ContactState> {
    contact_state_from_code(code).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
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
        sealed_sender: row.get::<_, i64>(8)? != 0,
        sealed_capability: row
            .get::<_, Option<Vec<u8>>>(9)?
            .map(|bytes| {
                bytes.try_into().map_err(|bytes: Vec<u8>| {
                    rusqlite::Error::FromSqlConversionFailure(
                        bytes.len(),
                        rusqlite::types::Type::Blob,
                        "sealed capability must be 16 bytes".into(),
                    )
                })
            })
            .transpose()?,
    })
}

fn mls_outbox_row(row: &rusqlite::Row) -> rusqlite::Result<MlsOutboxEntry> {
    let conversation_id: Vec<u8> = row.get(1)?;
    let conversation_id: [u8; 16] = conversation_id.try_into().map_err(|value: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Blob,
            "MLS conversation id must be 16 bytes".into(),
        )
    })?;
    let incarnation = u64::try_from(row.get::<_, i64>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let epoch = u64::try_from(row.get::<_, i64>(4)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let content_digest: Vec<u8> = row.get(5)?;
    let content_digest: [u8; 32] = content_digest.try_into().map_err(|value: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Blob,
            "MLS content digest must be 32 bytes".into(),
        )
    })?;
    Ok(MlsOutboxEntry {
        send_id: row.get(0)?,
        conversation_id,
        incarnation,
        mls_group_id: row.get(3)?,
        epoch,
        content_digest,
        content: row.get(6)?,
        ciphertext: row.get(7)?,
        expected_recipients: serde_json::from_slice(&row.get::<_, Vec<u8>>(8)?).map_err(
            |error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            },
        )?,
        deliveries: serde_json::from_slice::<Vec<MlsOutboxDelivery>>(&row.get::<_, Vec<u8>>(9)?)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?,
        created_at: row.get(10)?,
        attempts: row.get(11)?,
    })
}

fn mls_message_row(row: &rusqlite::Row) -> rusqlite::Result<MlsHistoryMessage> {
    let conversation_id: Vec<u8> = row.get(2)?;
    let conversation_id: [u8; 16] = conversation_id.try_into().map_err(|value: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Blob,
            "MLS conversation id must be 16 bytes".into(),
        )
    })?;
    let incarnation = u64::try_from(row.get::<_, i64>(3)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let epoch = u64::try_from(row.get::<_, i64>(5)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let cursor = row
        .get::<_, Option<i64>>(9)?
        .map(u64::try_from)
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?;
    Ok(MlsHistoryMessage {
        record_id: row.get(0)?,
        message_id: row.get(1)?,
        conversation_id,
        incarnation,
        mls_group_id: row.get(4)?,
        epoch,
        sender: row.get(6)?,
        sender_device_id: row.get(7)?,
        outgoing: row.get::<_, i64>(8)? != 0,
        cursor,
        transport_digest: row
            .get::<_, Vec<u8>>(10)?
            .try_into()
            .map_err(|value: Vec<u8>| {
                rusqlite::Error::FromSqlConversionFailure(
                    value.len(),
                    rusqlite::types::Type::Blob,
                    "MLS transport digest must be 32 bytes".into(),
                )
            })?,
        content: row.get(11)?,
        timestamp_ms: row.get(12)?,
        delivered: row.get::<_, i64>(13)? != 0,
        deduplicated: row.get::<_, i64>(14)? != 0,
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

fn imported_history_row(row: &rusqlite::Row) -> rusqlite::Result<ImportedHistoryRecordV1> {
    let conversation_json: String = row.get(3)?;
    let conversation = serde_json::from_str(&conversation_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(ImportedHistoryRecordV1 {
        transfer_id: row.get(0)?,
        source_record_id: row.get(1)?,
        source_device_id: row.get(2)?,
        conversation,
        sender: row.get(4)?,
        sender_device_id: row.get(5)?,
        outgoing: row.get::<_, i64>(6)? != 0,
        content: row.get(7)?,
        timestamp_ms: row.get(8)?,
        delivered: row.get::<_, i64>(9)? != 0,
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

    #[test]
    fn imported_history_is_atomic_immutable_idempotent_and_presentation_ordered() {
        use futures_executor::block_on;

        fn record(id: &str, timestamp_ms: i64) -> ImportedHistoryRecordV1 {
            ImportedHistoryRecordV1 {
                transfer_id: "11111111-1111-4111-8111-111111111111".into(),
                source_record_id: id.into(),
                source_device_id: 1,
                conversation: kutup_chat_proto::ConversationId::direct(
                    kutup_chat_proto::AccountAddress::federated("bob", "b.test").unwrap(),
                ),
                sender: "bob@b.test".into(),
                sender_device_id: 1,
                outgoing: false,
                content: serde_json::to_vec(&kutup_chat_proto::ChatContent::text(
                    "2026-08-09T00:00:00Z",
                    1,
                    "hello",
                ))
                .unwrap(),
                timestamp_ms,
                delivered: true,
            }
        }

        let db = SqliteChatDb::open_in_memory().unwrap();
        let later = record("later", 200);
        let earlier = record("earlier", 100);
        let mut initial = Pending::default();
        for record in [later.clone(), earlier.clone()] {
            initial.imported_history.insert(
                (record.transfer_id.clone(), record.source_record_id.clone()),
                record,
            );
        }
        block_on(db.apply(&initial)).unwrap();
        block_on(db.apply(&initial)).unwrap();

        assert_eq!(
            block_on(db.list_imported_history()).unwrap(),
            vec![earlier.clone(), later]
        );
        assert_eq!(
            block_on(db.load_imported_history(&earlier.transfer_id, "earlier")).unwrap(),
            Some(earlier.clone())
        );

        let mut conflicting = earlier;
        conflicting.content = serde_json::to_vec(&kutup_chat_proto::ChatContent::text(
            "2026-08-09T00:00:00Z",
            1,
            "tampered",
        ))
        .unwrap();
        let mut rejected = Pending::default();
        rejected.imported_history.insert(
            (
                conflicting.transfer_id.clone(),
                conflicting.source_record_id.clone(),
            ),
            conflicting,
        );
        rejected.last_cursor = Some(99);
        assert!(matches!(block_on(db.apply(&rejected)), Err(ChatError::Trust(_))));
        assert_eq!(block_on(db.load_last_cursor()).unwrap(), None);
    }

    #[test]
    fn quarantined_replacement_and_both_incarnation_histories_round_trip_atomically() {
        use base64::Engine as _;
        use futures_executor::block_on;
        use kutup_chat_proto::{AccountManifestDeviceV1, AccountManifestV1, DirectChatSuiteId};

        fn manifest(seed: u8) -> AccountManifestV1 {
            crate::AccountAuthority::derive(&[seed; 32])
                .unwrap()
                .sign_manifest(
                    "bob@chat.example",
                    1,
                    None,
                    vec![AccountManifestDeviceV1 {
                        device_id: 1,
                        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                        identity_key: base64::engine::general_purpose::STANDARD.encode([seed; 33]),
                        registration_id: 7,
                        mls: None,
                    }],
                    "2026-07-29T00:00:00Z",
                )
                .unwrap()
        }

        fn pin(manifest: &AccountManifestV1, trust: AuthorityTrust) -> ManifestTrust {
            ManifestTrust {
                peer: manifest.account.clone(),
                account: manifest.account.clone(),
                incarnation_id: manifest.incarnation_id.clone(),
                authority_key_id: manifest.authority_key_id.clone(),
                self_authority_key: manifest.self_authority_key.clone(),
                drive_hpke_public_key: manifest.drive.hpke_public_key.clone(),
                drive_share_signing_public_key: manifest.drive.share_signing_public_key.clone(),
                highest_sequence: manifest.sequence,
                manifest_hash: manifest.manifest_hash().unwrap(),
                trust,
                continuity_gap: false,
                quarantine_reason: None,
                pending_reset: None,
            }
        }

        let retained_manifest = manifest(3);
        let candidate_manifest = manifest(4);
        let retained_record = AccountManifestHistoryRecordV1 {
            peer: retained_manifest.account.clone(),
            sequence: 1,
            manifest: retained_manifest.clone(),
        };
        let candidate_record = AccountManifestHistoryRecordV1 {
            peer: candidate_manifest.account.clone(),
            sequence: 1,
            manifest: candidate_manifest.clone(),
        };
        let mut retained = pin(&retained_manifest, AuthorityTrust::Quarantined);
        retained.quarantine_reason = Some("authority changed".into());
        retained.pending_reset = Some(Box::new(crate::PendingAccountIdentityResetV1 {
            candidate: pin(&candidate_manifest, AuthorityTrust::Tofu),
            history: vec![candidate_record.clone()],
        }));

        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut pending = Pending::default();
        pending
            .manifest_trust
            .insert(retained.peer.clone(), retained.clone());
        pending.manifest_history.insert(
            (
                retained_record.peer.clone(),
                retained_record.manifest.incarnation_id.clone(),
                1,
            ),
            retained_record.clone(),
        );
        pending.manifest_history.insert(
            (
                candidate_record.peer.clone(),
                candidate_record.manifest.incarnation_id.clone(),
                1,
            ),
            candidate_record.clone(),
        );
        block_on(db.apply(&pending)).unwrap();

        assert_eq!(
            block_on(db.load_manifest_trust("bob@chat.example")).unwrap(),
            Some(retained)
        );
        assert_eq!(
            block_on(db.load_manifest_history(
                "bob@chat.example",
                &retained_manifest.incarnation_id,
                1,
            ))
            .unwrap(),
            Some(retained_record)
        );
        assert_eq!(
            block_on(db.load_manifest_history(
                "bob@chat.example",
                &candidate_manifest.incarnation_id,
                1,
            ))
            .unwrap(),
            Some(candidate_record)
        );
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
