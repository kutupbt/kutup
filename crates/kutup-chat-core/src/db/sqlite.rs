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
    contact_state_code, contact_state_from_code, AccountManifestHistoryRecord, AuthorityTrust,
    ChatDb, ContactRecord, InboundEnvelope, InboundFailureKind, InboundState, InboxMessage,
    LocalIdentity, LocalProfile, ManifestTrust, OutboxEntry, PeerProfile, Pending, SentMessage,
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
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (4, 0);
CREATE TABLE IF NOT EXISTS local_identity (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    identity_key_pair BLOB    NOT NULL,
    registration_id   INTEGER NOT NULL,
    device_id          INTEGER,
    credential         TEXT
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
-- The MLS groups Kutup no longer has: an older store's tables go.
DROP INDEX IF EXISTS mls_outbox_by_created_at;
DROP INDEX IF EXISTS mls_messages_by_time;
DROP TABLE IF EXISTS mls_state;
DROP TABLE IF EXISTS mls_outbox;
DROP TABLE IF EXISTS mls_messages;
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
    sender_device_id INTEGER NOT NULL DEFAULT 0,
    content        BLOB    NOT NULL,
    created_at     INTEGER NOT NULL,
    delivered_at   INTEGER,
    delivered      INTEGER NOT NULL,
    deduplicated   INTEGER NOT NULL,
    failed_recipients INTEGER NOT NULL DEFAULT 0,
    waiting_recipients INTEGER,
    media_wait     BLOB
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
    pending_reset_json TEXT,
    identity_key       TEXT    NOT NULL,
    identity_verified  INTEGER NOT NULL DEFAULT 0,
    identity_verified_at_ms INTEGER NOT NULL DEFAULT 0
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
CREATE TABLE IF NOT EXISTS prekey_rotation (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS repair_limits (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS index_values (
    key   BLOB PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_chat_registration (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    request BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_account_identity (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    body BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
    peer             TEXT PRIMARY KEY,
    state            INTEGER NOT NULL,
    previous_state   INTEGER,
    revision         INTEGER NOT NULL,
    source_device_id INTEGER NOT NULL,
    updated_at_ms    INTEGER NOT NULL,
    sync_pending     INTEGER NOT NULL DEFAULT 0,
    sync_send_id     TEXT,
    list_due_at_ms   INTEGER
);
CREATE TABLE IF NOT EXISTS group_outbox (
    send_id    TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    entry      BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_groups (
    group_id TEXT PRIMARY KEY,
    record   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS local_profile (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    profile BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS peer_profiles (
    peer    TEXT PRIMARY KEY,
    profile BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);";

/// A device store backed by a single SQLite database.
pub struct SqliteChatDb {
    conn: RefCell<Connection>,
    commits: std::cell::Cell<u64>,
    journal: std::cell::RefCell<crate::timeline::Journal>,
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
        // Disappearing-message plaintext should not remain recoverable from
        // SQLite free pages after its logical row is removed.
        db(conn.pragma_update(None, "secure_delete", "ON"))?;
        db(conn.execute_batch(SCHEMA))?;
        // One schema version, created whole (4: the device credential and
        // the account identity in manifest pins). A store from an older layout
        // (development builds only; no native app has shipped) is refused
        // rather than upgraded.
        let foreign: i64 = db(conn.query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version <> 4",
            [],
            |row| row.get(0),
        ))?;
        if foreign != 0 {
            return Err(ChatError::Db(
                "the chat store has an unknown schema version".into(),
            ));
        }
        Ok(Self {
            conn: RefCell::new(conn),
            commits: std::cell::Cell::new(0),
            journal: std::cell::RefCell::new(crate::timeline::Journal::default()),
        })
    }
}

#[async_trait(?Send)]
impl ChatDb for SqliteChatDb {
    async fn load_local_identity(&self) -> Result<Option<LocalIdentity>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT identity_key_pair, registration_id, device_id, credential \
                 FROM local_identity WHERE id = 1",
                [],
                |row| {
                    Ok(LocalIdentity {
                        identity_key_pair: row.get(0)?,
                        registration_id: row.get(1)?,
                        device_id: row.get(2)?,
                        credential: row.get(3)?,
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

    async fn load_pins_due(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row("SELECT value FROM meta WHERE key = 'pins_due'", [], |row| {
                row.get(0)
            })
            .optional())
    }

    async fn load_media_waits(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'media_waits'",
                [],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_group_send_endorsement(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'group_send_endorsement'",
                [],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_contact_list_followed(&self) -> Result<bool> {
        let conn = self.conn.borrow();
        let value: Option<i64> = db(conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'contact_list_followed'",
                [],
                |row| row.get(0),
            )
            .optional())?;
        Ok(value == Some(1))
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

    async fn load_message(&self, id: &str) -> Result<Option<InboxMessage>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT id, peer, sender_device_id, cursor, content, received_at \
                 FROM messages WHERE id = ?1",
                [id],
                message_row,
            )
            .optional())
    }

    async fn load_index_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT value FROM index_values WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_sent_message(&self, send_id: &str) -> Result<Option<SentMessage>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT send_id, peer, sender_device_id, content, created_at, delivered_at, delivered, deduplicated, failed_recipients,
                        waiting_recipients, media_wait
                 FROM sent_messages WHERE send_id = ?1",
                [send_id],
                sent_message_row,
            )
            .optional())
    }

    async fn list_sent_messages(&self) -> Result<Vec<SentMessage>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare(
            "SELECT send_id, peer, sender_device_id, content, created_at, delivered_at, delivered, deduplicated, failed_recipients,
                        waiting_recipients, media_wait
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
                "SELECT peer, account, incarnation_id, authority_key_id,
                        self_authority_key, drive_hpke_public_key,
                        drive_share_signing_public_key, highest_sequence,
                        manifest_hash, trust_state, continuity_gap,
                        quarantine_reason, pending_reset_json, identity_key,
                        identity_verified, identity_verified_at_ms
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
                        identity_key: row.get(13)?,
                        identity_verified: row.get::<_, i64>(14)? != 0,
                        identity_verified_at_ms: row.get(15)?,
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
    ) -> Result<Option<AccountManifestHistoryRecord>> {
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
            Ok(AccountManifestHistoryRecord {
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
                        updated_at_ms, sync_pending, sync_send_id, list_due_at_ms
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
                    updated_at_ms, sync_pending, sync_send_id, list_due_at_ms
             FROM contacts ORDER BY peer",
        ))?;
        let rows = db(stmt.query_map([], contact_row))?;
        rows.map(db).collect()
    }

    async fn load_group(&self, group_id: &str) -> Result<Option<crate::group::GroupRecordV1>> {
        let conn = self.conn.borrow();
        let encoded: Option<Vec<u8>> = db(conn
            .query_row(
                "SELECT record FROM chat_groups WHERE group_id = ?1",
                [group_id],
                |row| row.get(0),
            )
            .optional())?;
        encoded.map(|bytes| decode_group(&bytes)).transpose()
    }

    async fn list_groups(&self) -> Result<Vec<crate::group::GroupRecordV1>> {
        let conn = self.conn.borrow();
        let mut stmt = db(conn.prepare("SELECT record FROM chat_groups ORDER BY group_id"))?;
        let rows = db(stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)))?;
        rows.map(|row| decode_group(&db(row)?)).collect()
    }

    async fn list_group_outbox(&self) -> Result<Vec<crate::db::GroupOutboxEntry>> {
        let conn = self.conn.borrow();
        let mut stmt =
            db(conn.prepare("SELECT entry FROM group_outbox ORDER BY created_at, send_id"))?;
        let rows = db(stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)))?;
        rows.map(|row| {
            serde_json::from_slice(&db(row)?)
                .map_err(|_| ChatError::Db("a group outbox entry doesn't read".into()))
        })
        .collect()
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

    async fn load_prekey_rotation(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT state FROM prekey_rotation WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional())
    }

    async fn load_repair_limits(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row("SELECT state FROM repair_limits WHERE id = 1", [], |row| {
                row.get(0)
            })
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

    async fn load_pending_account_identity(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        db(conn
            .query_row(
                "SELECT body FROM pending_account_identity WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional())
    }

    async fn apply(&self, pending: &Pending) -> Result<()> {
        // The conversation timelines move with the records they index.
        let crate::timeline::Changes {
            writes: mut index_values,
            conversations: touched,
        } = crate::timeline::changes(self, pending).await?;
        for (key, value) in &pending.index_values {
            index_values.insert(key.clone(), value.clone());
        }
        let mut conn = self.conn.borrow_mut();
        let tx = db(conn.transaction())?;

        if pending.reset_transport || pending.reset_identity {
            db(tx.execute_batch(
                "DELETE FROM sessions;
                 DELETE FROM identities;
                 DELETE FROM pre_keys;
                 DELETE FROM signed_pre_keys;
                 DELETE FROM kyber_pre_keys;
                 DELETE FROM kyber_base_keys_seen;
                 DELETE FROM sender_keys;
                 DELETE FROM pending_prekey_upload;
                 DELETE FROM prekey_rotation;",
            ))?;
        }
        if pending.reset_transport {
            db(tx.execute_batch(
                "DELETE FROM local_identity;
                 DELETE FROM inbound_envelopes;
                 DELETE FROM repair_limits;
                 DELETE FROM pending_account_identity;
                 DELETE FROM pending_chat_registration;
                 DELETE FROM meta WHERE key = 'last_cursor';",
            ))?;
        }
        for peer in &pending.forget_manifests_of {
            db(tx.execute("DELETE FROM manifest_trust WHERE peer = ?1", [peer]))?;
            db(tx.execute("DELETE FROM manifest_history WHERE peer = ?1", [peer]))?;
        }
        if let Some(local) = &pending.local_identity {
            db(tx.execute(
                "INSERT INTO local_identity \
                   (id, identity_key_pair, registration_id, device_id, credential) \
                 VALUES (1, ?1, ?2, ?3, ?4) \
                 ON CONFLICT(id) DO UPDATE SET \
                   identity_key_pair = excluded.identity_key_pair, \
                   registration_id = excluded.registration_id, \
                   device_id = excluded.device_id, \
                   credential = excluded.credential",
                rusqlite::params![
                    local.identity_key_pair,
                    local.registration_id,
                    local.device_id,
                    local.credential
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
        for id in &pending.delete_message_ids {
            db(tx.execute("DELETE FROM messages WHERE id = ?1", [id]))?;
        }
        for (send_id, message) in &pending.sent_messages {
            db(tx.execute(
                "INSERT INTO sent_messages
                     (send_id, peer, sender_device_id, content, created_at, delivered_at, delivered, deduplicated,
                      failed_recipients, waiting_recipients, media_wait)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(send_id) DO UPDATE SET
                     peer = excluded.peer, sender_device_id = excluded.sender_device_id,
                     content = excluded.content,
                     delivered_at = excluded.delivered_at,
                     delivered = excluded.delivered,
                     deduplicated = excluded.deduplicated,
                     failed_recipients = excluded.failed_recipients,
                     waiting_recipients = excluded.waiting_recipients,
                     media_wait = excluded.media_wait",
                rusqlite::params![
                    send_id,
                    message.peer,
                    message.sender_device_id,
                    message.content,
                    message.created_at,
                    message.delivered_at,
                    i64::from(message.delivered),
                    i64::from(message.deduplicated),
                    message.failed_recipients,
                    message.waiting_recipients,
                    message
                        .media_wait
                        .as_ref()
                        .map(serde_json::to_vec)
                        .transpose()
                        .map_err(|e| ChatError::Db(e.to_string()))?,
                ],
            ))?;
        }
        for send_id in &pending.delete_sent_message_ids {
            db(tx.execute("DELETE FROM sent_messages WHERE send_id = ?1", [send_id]))?;
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
                      quarantine_reason, pending_reset_json, identity_key,
                      identity_verified, identity_verified_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
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
                     pending_reset_json = excluded.pending_reset_json,
                     identity_key = excluded.identity_key,
                     identity_verified = excluded.identity_verified,
                     identity_verified_at_ms = excluded.identity_verified_at_ms",
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
                    trust.identity_key,
                    i64::from(trust.identity_verified),
                    trust.identity_verified_at_ms,
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
                      updated_at_ms, sync_pending, sync_send_id, list_due_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(peer) DO UPDATE SET
                     state = excluded.state,
                     previous_state = excluded.previous_state,
                     revision = excluded.revision,
                     source_device_id = excluded.source_device_id,
                     updated_at_ms = excluded.updated_at_ms,
                     sync_pending = excluded.sync_pending,
                     sync_send_id = excluded.sync_send_id,
                     list_due_at_ms = excluded.list_due_at_ms",
                rusqlite::params![
                    peer,
                    contact_state_code(contact.state),
                    contact.previous_state.map(contact_state_code),
                    contact.revision as i64,
                    contact.source_device_id,
                    contact.updated_at_ms,
                    i64::from(contact.sync_pending),
                    contact.sync_send_id,
                    contact.list_due_at_ms,
                ],
            ))?;
        }
        for (send_id, entry) in &pending.group_outbox {
            match entry {
                Some(entry) => {
                    let encoded = serde_json::to_vec(entry)
                        .map_err(|error| ChatError::Db(format!("encode group outbox: {error}")))?;
                    db(tx.execute(
                        "INSERT INTO group_outbox (send_id, created_at, entry) VALUES (?1, ?2, ?3)
                         ON CONFLICT(send_id) DO UPDATE SET entry = excluded.entry",
                        rusqlite::params![send_id, entry.created_at, encoded],
                    ))?;
                }
                None => {
                    db(tx.execute("DELETE FROM group_outbox WHERE send_id = ?1", [send_id]))?;
                }
            }
        }
        for (group_id, record) in &pending.groups {
            // Never back to an older verified state, or to another one at the
            // same revision (docs/plans/pairwise-groups.md §3), checked inside
            // the write transaction.
            let existing: Option<Vec<u8>> = db(tx
                .query_row(
                    "SELECT record FROM chat_groups WHERE group_id = ?1",
                    [group_id],
                    |row| row.get(0),
                )
                .optional())?;
            if let Some(existing) = existing {
                record
                    .may_replace(&decode_group(&existing)?)
                    .map_err(|error| ChatError::Trust(error.to_string()))?;
            }
            let encoded = serde_json::to_vec(record)
                .map_err(|error| ChatError::Db(format!("encode group record: {error}")))?;
            db(tx.execute(
                "INSERT INTO chat_groups (group_id, record) VALUES (?1, ?2)
                 ON CONFLICT(group_id) DO UPDATE SET record = excluded.record",
                rusqlite::params![group_id, encoded],
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
        if let Some(state) = &pending.prekey_rotation {
            db(tx.execute(
                "INSERT INTO prekey_rotation (id, state) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET state = excluded.state",
                [state],
            ))?;
        }
        if let Some(state) = &pending.repair_limits {
            db(tx.execute(
                "INSERT INTO repair_limits (id, state) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET state = excluded.state",
                [state],
            ))?;
        }
        for (key, value) in &index_values {
            match value {
                Some(value) => db(tx.execute(
                    "INSERT INTO index_values (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    rusqlite::params![key, value],
                ))?,
                None => db(tx.execute("DELETE FROM index_values WHERE key = ?1", [key]))?,
            };
        }
        for id in &pending.delete_signed_pre_keys {
            db(tx.execute("DELETE FROM signed_pre_keys WHERE id = ?1", [id]))?;
        }
        for id in &pending.delete_kyber_pre_keys {
            db(tx.execute("DELETE FROM kyber_pre_keys WHERE id = ?1", [id]))?;
            db(tx.execute("DELETE FROM kyber_base_keys_seen WHERE kyber_id = ?1", [id]))?;
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
        if let Some(body) = &pending.pending_account_identity {
            match body {
                Some(body) => db(tx.execute(
                    "INSERT INTO pending_account_identity (id, body) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET body = excluded.body",
                    [body],
                ))?,
                None => db(tx.execute("DELETE FROM pending_account_identity WHERE id = 1", []))?,
            };
        }
        if let Some(state) = &pending.pins_due {
            db(tx.execute(
                "INSERT INTO meta (key, value) VALUES ('pins_due', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [state],
            ))?;
        }
        if let Some(state) = &pending.media_waits {
            db(tx.execute(
                "INSERT INTO meta (key, value) VALUES ('media_waits', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [state],
            ))?;
        }
        if let Some(state) = &pending.group_send_endorsement {
            db(tx.execute(
                "INSERT INTO meta (key, value) VALUES ('group_send_endorsement', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [state],
            ))?;
        }
        if pending.contact_list_followed {
            db(tx.execute(
                "INSERT INTO meta (key, value) VALUES ('contact_list_followed', 1) \
                 ON CONFLICT(key) DO UPDATE SET value = 1",
                [],
            ))?;
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

        db(tx.commit())?;
        self.commits.set(self.commits.get() + 1);
        self.journal
            .borrow_mut()
            .record(self.commits.get(), touched);
        Ok(())
    }

    fn commit_count(&self) -> u64 {
        self.commits.get()
    }

    fn changed_conversations(&self, since: u64) -> Option<Vec<String>> {
        self.journal.borrow().since(since, self.commits.get())
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
        list_due_at_ms: row.get(8)?,
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

fn sent_message_row(row: &rusqlite::Row) -> rusqlite::Result<SentMessage> {
    Ok(SentMessage {
        send_id: row.get(0)?,
        peer: row.get(1)?,
        sender_device_id: row.get(2)?,
        content: row.get(3)?,
        created_at: row.get(4)?,
        delivered_at: row.get(5)?,
        delivered: row.get::<_, i64>(6)? != 0,
        deduplicated: row.get::<_, i64>(7)? != 0,
        failed_recipients: row.get(8)?,
        waiting_recipients: row.get(9)?,
        media_wait: row
            .get::<_, Option<Vec<u8>>>(10)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?,
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

fn decode_group(bytes: &[u8]) -> Result<crate::group::GroupRecordV1> {
    // The record holds keys: the decoder's message, which may quote a
    // value, is not passed on.
    serde_json::from_slice(bytes).map_err(|_| ChatError::Db("a group record doesn't read".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn group_records_are_kept_and_replaced_by_id() {
        use crate::group::{GroupRecordV1, GroupStatus};
        use futures_executor::block_on;

        let record = |status| GroupRecordV1 {
            version: 1,
            group_id: "g".repeat(43),
            master_key: crate::group::SecretText("AAAA".into()),
            home: kutup_chat_proto::group_route::GroupHomePinV1 {
                server: "home.example".into(),
                identity_sequence: 1,
                identity_document_hash: "9".repeat(64),
            },
            pseudonym_seed: crate::group::SecretText("BBBB".into()),
            status,
            min_revision: 0,
            state: None,
            head: None,
            notary_sequence: None,
            gateway: Default::default(),
            not_found_since_ms: None,
            sender_book: None,
            synced_at_ms: None,
            fork_at_revision: None,
            fork_sender: None,
            known_since_ms: None,
            listed_status: None,
            list_due_at_ms: None,
            join_epoch: 0,
            endorsements: Default::default(),
        };
        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut first = Pending::default();
        first
            .groups
            .insert("g".repeat(43), record(GroupStatus::Requesting));
        block_on(db.apply(&first)).unwrap();
        let mut second = Pending::default();
        second
            .groups
            .insert("g".repeat(43), record(GroupStatus::Member));
        block_on(db.apply(&second)).unwrap();

        let loaded = block_on(db.load_group(&"g".repeat(43))).unwrap().unwrap();
        assert_eq!(loaded.status, GroupStatus::Member);
        assert_eq!(block_on(db.list_groups()).unwrap().len(), 1);
        assert!(block_on(db.load_group("other")).unwrap().is_none());
    }

    #[test]
    fn a_store_from_an_older_schema_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
             INSERT INTO schema_migrations VALUES (1, 0), (16, 0);",
        )
        .unwrap();
        assert!(matches!(
            SqliteChatDb::from_connection(conn),
            Err(ChatError::Db(message)) if message.contains("unknown schema version")
        ));
        // A new store opens, and opens again.
        let path = std::env::temp_dir().join(format!("kutup-chat-{}.db", uuid::Uuid::new_v4()));
        drop(SqliteChatDb::open(&path).unwrap());
        drop(SqliteChatDb::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// A signed manifest of a test account, its authority and identity from `seed`.
    fn test_manifest(seed: u8) -> kutup_chat_proto::AccountManifestV3 {
        crate::AccountAuthority::derive(&[seed; 32])
            .unwrap()
            .sign_manifest(
                "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example"
                    .parse()
                    .unwrap(),
                1,
                None,
                &{
                    let private = libsignal_protocol::PrivateKey::deserialize(&[seed; 32]).unwrap();
                    libsignal_protocol::IdentityKeyPair::new(
                        libsignal_protocol::IdentityKey::new(private.public_key().unwrap()),
                        private,
                    )
                },
                vec![kutup_chat_proto::AccountManifestDeviceV3::chat(
                    1,
                    kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
                    7,
                    "51".repeat(32),
                )],
                "2026-07-29T00:00:00Z",
            )
            .unwrap()
    }

    #[test]
    fn quarantined_replacement_and_both_incarnation_histories_round_trip_atomically() {
        use futures_executor::block_on;
        use kutup_chat_proto::AccountManifestV3;

        fn manifest(seed: u8) -> AccountManifestV3 {
            test_manifest(seed)
        }

        fn pin(manifest: &AccountManifestV3, trust: AuthorityTrust) -> ManifestTrust {
            ManifestTrust {
                peer: manifest.account.to_string(),
                account: manifest.account.to_string(),
                incarnation_id: manifest.incarnation_id.clone(),
                authority_key_id: manifest.authority_key_id.clone(),
                self_authority_key: manifest.self_authority_key.clone(),
                drive_hpke_public_key: manifest.drive.hpke_public_key.clone(),
                drive_share_signing_public_key: manifest.drive.share_signing_public_key.clone(),
                highest_sequence: manifest.sequence,
                manifest_hash: manifest.manifest_hash().unwrap(),
                identity_key: manifest.identity_key.clone().unwrap_or_default(),
                identity_verified: false,
                identity_verified_at_ms: 0,
                trust,
                continuity_gap: false,
                quarantine_reason: None,
                pending_reset: None,
            }
        }

        let retained_manifest = manifest(3);
        let candidate_manifest = manifest(4);
        let retained_record = AccountManifestHistoryRecord {
            peer: retained_manifest.account.to_string(),
            sequence: 1,
            manifest: retained_manifest.clone(),
        };
        let candidate_record = AccountManifestHistoryRecord {
            peer: candidate_manifest.account.to_string(),
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
            block_on(
                db.load_manifest_trust("aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example")
            )
            .unwrap(),
            Some(retained)
        );
        assert_eq!(
            block_on(db.load_manifest_history(
                "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
                &retained_manifest.incarnation_id,
                1,
            ))
            .unwrap(),
            Some(retained_record)
        );
        assert_eq!(
            block_on(db.load_manifest_history(
                "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example",
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

    /// The schema this build writes: 4 (the device credential, the account
    /// identity and its verified state in the pins, the kept identity sync).
    #[test]
    fn a_new_store_is_schema_four() {
        let db = SqliteChatDb::open_in_memory().unwrap();
        let versions: Vec<i64> = {
            let conn = db.conn.borrow();
            let mut statement = conn
                .prepare("SELECT version FROM schema_migrations")
                .unwrap();
            let rows = statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<i64>>>()
                .unwrap();
            rows
        };
        assert_eq!(versions, vec![4]);
    }

    /// A store with a bit of everything: transport state, pins, history,
    /// the outbox and a contact.
    fn full_store() -> SqliteChatDb {
        use futures_executor::block_on;
        let db = SqliteChatDb::open_in_memory().unwrap();
        let mut pending = Pending {
            local_identity: Some(LocalIdentity {
                identity_key_pair: vec![1, 2, 3],
                registration_id: 42,
                device_id: Some(1),
                credential: Some("credential".into()),
            }),
            last_cursor: Some(9),
            pending_account_identity: Some(Some(vec![7, 7])),
            ..Pending::default()
        };
        pending.sessions.insert("peer.1".into(), Some(vec![4]));
        pending.identities.insert("peer.1".into(), vec![5]);
        pending.pre_keys.insert(100, Some(vec![6]));
        pending.signed_pre_keys.insert(1, vec![7]);
        pending.kyber_pre_keys.insert(1, vec![8]);
        pending.manifest_trust.insert(
            "peer".into(),
            ManifestTrust {
                peer: "peer".into(),
                account: "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test".into(),
                incarnation_id: "i".into(),
                authority_key_id: "a".into(),
                self_authority_key: "k".into(),
                drive_hpke_public_key: "d".into(),
                drive_share_signing_public_key: "s".into(),
                highest_sequence: 3,
                manifest_hash: "h".into(),
                identity_key: "identity".into(),
                identity_verified: true,
                identity_verified_at_ms: 11,
                trust: AuthorityTrust::Tofu,
                continuity_gap: false,
                quarantine_reason: None,
                pending_reset: None,
            },
        );
        pending.outbox.insert(
            "send".into(),
            Some(OutboxEntry {
                send_id: "send".into(),
                peer: "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test".into(),
                content: b"{}".to_vec(),
                envelopes: b"[]".to_vec(),
                sealed_sender: false,
                sealed_capability: None,
                attempts: 0,
                created_at: 1,
                primary_delivered: false,
                sync: None,
            }),
        );
        pending.contacts.insert(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test".into(),
            ContactRecord {
                peer: "aci:00000000-0000-4000-8000-2bd806c97f0e@a.test".into(),
                state: kutup_chat_proto::ContactState::Accepted,
                previous_state: None,
                revision: 1,
                source_device_id: 1,
                updated_at_ms: 1,
                sync_pending: false,
                sync_send_id: None,
                list_due_at_ms: None,
            },
        );
        block_on(db.apply(&pending)).unwrap();
        db
    }

    #[test]
    fn a_transport_reset_keeps_history_outbox_contacts_and_their_pins() {
        use futures_executor::block_on;
        let db = full_store();
        assert_eq!(
            block_on(db.load_pending_account_identity()).unwrap(),
            Some(vec![7, 7])
        );
        block_on(db.apply(&Pending {
            reset_transport: true,
            ..Pending::default()
        }))
        .unwrap();
        assert!(block_on(db.load_local_identity()).unwrap().is_none());
        assert!(block_on(db.load_session("peer.1")).unwrap().is_none());
        assert!(block_on(db.load_identity("peer.1")).unwrap().is_none());
        assert!(block_on(db.load_pre_key(100)).unwrap().is_none());
        assert!(block_on(db.load_signed_pre_key(1)).unwrap().is_none());
        assert!(block_on(db.load_kyber_pre_key(1)).unwrap().is_none());
        // A contact's pin and verified state stay.
        let pin = block_on(db.load_manifest_trust("peer")).unwrap().unwrap();
        assert!(pin.identity_verified);
        assert!(block_on(db.load_last_cursor()).unwrap().is_none());
        assert!(block_on(db.load_pending_account_identity())
            .unwrap()
            .is_none());
        assert_eq!(block_on(db.list_outbox()).unwrap().len(), 1);
        assert_eq!(block_on(db.list_contacts()).unwrap().len(), 1);
    }

    /// The pins and history of a forgotten account go (the account's own,
    /// on a new device); another account's stay.
    #[test]
    fn forgetting_an_accounts_manifests_drops_its_pin_and_history_only() {
        use futures_executor::block_on;
        let db = full_store();
        let history = |peer: &str| crate::db::AccountManifestHistoryRecord {
            peer: peer.into(),
            sequence: 1,
            manifest: test_manifest(5),
        };
        let mut pending = Pending::default();
        for peer in ["peer", "other"] {
            pending.manifest_history.insert(
                (peer.into(), test_manifest(5).incarnation_id, 1),
                history(peer),
            );
        }
        let mut other = block_on(db.load_manifest_trust("peer")).unwrap().unwrap();
        other.peer = "other".into();
        pending.manifest_trust.insert("other".into(), other);
        block_on(db.apply(&pending)).unwrap();

        let mut forget = Pending::default();
        forget.forget_manifests_of.insert("peer".into());
        block_on(db.apply(&forget)).unwrap();
        let incarnation = test_manifest(5).incarnation_id;
        assert!(block_on(db.load_manifest_trust("peer")).unwrap().is_none());
        assert!(block_on(db.load_manifest_history("peer", &incarnation, 1))
            .unwrap()
            .is_none());
        assert!(block_on(db.load_manifest_trust("other")).unwrap().is_some());
        assert!(block_on(db.load_manifest_history("other", &incarnation, 1))
            .unwrap()
            .is_some());
    }

    #[test]
    fn an_identity_reset_keeps_the_device_and_its_pins() {
        use futures_executor::block_on;
        let db = full_store();
        block_on(db.apply(&Pending {
            reset_identity: true,
            ..Pending::default()
        }))
        .unwrap();
        assert!(block_on(db.load_session("peer.1")).unwrap().is_none());
        assert!(block_on(db.load_identity("peer.1")).unwrap().is_none());
        assert!(block_on(db.load_pre_key(100)).unwrap().is_none());
        assert!(block_on(db.load_signed_pre_key(1)).unwrap().is_none());
        assert!(block_on(db.load_kyber_pre_key(1)).unwrap().is_none());
        let local = block_on(db.load_local_identity()).unwrap().unwrap();
        assert_eq!(local.credential.as_deref(), Some("credential"));
        let pin = block_on(db.load_manifest_trust("peer")).unwrap().unwrap();
        assert_eq!(pin.identity_key, "identity");
        assert!(pin.identity_verified);
        assert_eq!(pin.identity_verified_at_ms, 11);
        assert_eq!(block_on(db.load_last_cursor()).unwrap(), Some(9));
        assert_eq!(block_on(db.list_outbox()).unwrap().len(), 1);
        assert_eq!(block_on(db.list_contacts()).unwrap().len(), 1);
        // The kept sync is cleared only by the commit that installs it.
        assert_eq!(
            block_on(db.load_pending_account_identity()).unwrap(),
            Some(vec![7, 7])
        );
        block_on(db.apply(&Pending {
            pending_account_identity: Some(None),
            ..Pending::default()
        }))
        .unwrap();
        assert!(block_on(db.load_pending_account_identity())
            .unwrap()
            .is_none());
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
                credential: Some("credential".into()),
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
