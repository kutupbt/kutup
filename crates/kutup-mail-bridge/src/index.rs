//! The bridge's index (docs/plans/mail-bridge.md, decision 7): the
//! mailboxes it shows an IMAP app, their UIDs and flags, and the change
//! feed's cursor, in one SQLCipher database under the bridge's local key,
//! so nothing of it (names, sizes, flags, which message is where) is
//! readable on disk. Opened messages are kept apart, sealed block by block
//! (`kutup_mail_client::cache`).
//!
//! UIDs follow IMAP (RFC 3501 §2.3.1.1) as Gluon keeps them: each mailbox
//! hands out increasing UIDs from its `uid_next` and never gives one twice;
//! a mailbox made again (a resync) gets a new, higher UIDVALIDITY, so an app
//! drops what it cached.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

/// The index doesn't open or answer.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("the bridge's index: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("the bridge's index does not open with this key")]
    WrongKey,
    #[error("no mailbox {0}")]
    NoMailbox(String),
}

pub type Result<T> = std::result::Result<T, IndexError>;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    -- Where the mailbox's mail comes from: a place (inbox, sent, …), a
    -- folder or a label, by the server's id.
    source TEXT NOT NULL UNIQUE,
    uid_validity INTEGER NOT NULL,
    uid_next INTEGER NOT NULL CHECK (uid_next >= 1)
);
CREATE TABLE IF NOT EXISTS messages (
    -- The server's message id.
    id TEXT PRIMARY KEY,
    size INTEGER NOT NULL CHECK (size >= 0),
    -- Seconds since the epoch, as IMAP's INTERNALDATE.
    received_at INTEGER NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    answered INTEGER NOT NULL DEFAULT 0,
    draft INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mailbox_messages (
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL CHECK (uid >= 1),
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    PRIMARY KEY (mailbox_id, uid),
    UNIQUE (mailbox_id, message_id)
);
CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// A mailbox as IMAP sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub uid_validity: u32,
    pub uid_next: u32,
}

/// One message in a mailbox, by UID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub uid: u32,
    pub message_id: String,
    pub size: u64,
    pub received_at: i64,
    pub flags: Flags,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
}

/// What the index knows of a message, as the server's list row gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub id: String,
    pub size: u64,
    pub received_at: i64,
    pub flags: Flags,
}

pub struct Index {
    db: Connection,
}

impl Index {
    /// Opens (or makes) the index at `path` under the 32-byte local `key`.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        let db = Connection::open(path)?;
        Self::keyed(db, key)
    }

    /// An index in memory (tests).
    pub fn in_memory(key: &[u8; 32]) -> Result<Self> {
        Self::keyed(Connection::open_in_memory()?, key)
    }

    fn keyed(db: Connection, key: &[u8; 32]) -> Result<Self> {
        // A raw key (SQLCipher's x'…' form), never a passphrase to derive.
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(key)));
        db.execute_batch(&pragma)?;
        // A wrong key shows on the first read.
        if db
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                r.get::<_, i64>(0)
            })
            .is_err()
        {
            return Err(IndexError::WrongKey);
        }
        db.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        db.execute_batch(SCHEMA)?;
        Ok(Self { db })
    }

    /// The mailbox `name`, made for `source` when it isn't there. A new
    /// mailbox's UIDVALIDITY is above any this index gave before.
    pub fn mailbox(&mut self, name: &str, source: &str) -> Result<Mailbox> {
        if let Some(found) = self.find(name)? {
            return Ok(found);
        }
        let validity = self.next_validity()?;
        self.db.execute(
            "INSERT INTO mailboxes (name, source, uid_validity, uid_next) VALUES (?1, ?2, ?3, 1)",
            params![name, source, validity],
        )?;
        self.find(name)?
            .ok_or_else(|| IndexError::NoMailbox(name.into()))
    }

    pub fn find(&self, name: &str) -> Result<Option<Mailbox>> {
        Ok(self
            .db
            .query_row(
                "SELECT id, name, source, uid_validity, uid_next FROM mailboxes WHERE name = ?1",
                [name],
                |r| {
                    Ok(Mailbox {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        source: r.get(2)?,
                        uid_validity: r.get(3)?,
                        uid_next: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn mailboxes(&self) -> Result<Vec<Mailbox>> {
        let mut statement = self.db.prepare(
            "SELECT id, name, source, uid_validity, uid_next FROM mailboxes ORDER BY name",
        )?;
        let rows = statement.query_map([], |r| {
            Ok(Mailbox {
                id: r.get(0)?,
                name: r.get(1)?,
                source: r.get(2)?,
                uid_validity: r.get(3)?,
                uid_next: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Strictly above every UIDVALIDITY given so far (kept in `state`, so a
    /// mailbox deleted and made again never reuses one).
    fn next_validity(&mut self) -> Result<u32> {
        let last: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM state WHERE key = 'uid_validity'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let next = last.and_then(|v| v.parse::<u32>().ok()).unwrap_or(0) + 1;
        self.db.execute(
            "INSERT INTO state (key, value) VALUES ('uid_validity', ?1)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [next.to_string()],
        )?;
        Ok(next)
    }

    /// Records `row` (its size, date and flags as the server says now).
    pub fn put_message(&mut self, row: &MessageRow) -> Result<()> {
        self.db.execute(
            "INSERT INTO messages (id, size, received_at, seen, flagged, answered, draft)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (id) DO UPDATE SET size = excluded.size, received_at = excluded.received_at,
                 seen = excluded.seen, flagged = excluded.flagged, answered = excluded.answered,
                 draft = excluded.draft",
            params![
                row.id,
                row.size as i64,
                row.received_at,
                row.flags.seen,
                row.flags.flagged,
                row.flags.answered,
                row.flags.draft
            ],
        )?;
        Ok(())
    }

    /// Puts message `message_id` in `mailbox` under the next UID, or answers
    /// the UID it has there already.
    pub fn add(&mut self, mailbox: &str, message_id: &str) -> Result<u32> {
        let tx = self.db.transaction()?;
        let (id, uid_next): (i64, u32) = tx
            .query_row(
                "SELECT id, uid_next FROM mailboxes WHERE name = ?1",
                [mailbox],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| IndexError::NoMailbox(mailbox.into()))?;
        let existing: Option<u32> = tx
            .query_row(
                "SELECT uid FROM mailbox_messages WHERE mailbox_id = ?1 AND message_id = ?2",
                params![id, message_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(uid) = existing {
            return Ok(uid);
        }
        tx.execute(
            "INSERT INTO mailbox_messages (mailbox_id, uid, message_id) VALUES (?1, ?2, ?3)",
            params![id, uid_next, message_id],
        )?;
        tx.execute(
            "UPDATE mailboxes SET uid_next = uid_next + 1 WHERE id = ?1",
            [id],
        )?;
        tx.commit()?;
        Ok(uid_next)
    }

    /// Takes message `message_id` out of `mailbox`; its UID is never given
    /// again. Answers the UID it had.
    pub fn remove(&mut self, mailbox: &str, message_id: &str) -> Result<Option<u32>> {
        let uid: Option<u32> = self
            .db
            .query_row(
                "SELECT mm.uid FROM mailbox_messages mm JOIN mailboxes m ON m.id = mm.mailbox_id
                  WHERE m.name = ?1 AND mm.message_id = ?2",
                params![mailbox, message_id],
                |r| r.get(0),
            )
            .optional()?;
        if uid.is_some() {
            self.db.execute(
                "DELETE FROM mailbox_messages WHERE message_id = ?2
                   AND mailbox_id = (SELECT id FROM mailboxes WHERE name = ?1)",
                params![mailbox, message_id],
            )?;
        }
        Ok(uid)
    }

    /// The mailbox's messages by UID: their sequence numbers are their
    /// places in this list, from 1.
    pub fn entries(&self, mailbox: &str) -> Result<Vec<Entry>> {
        let mut statement = self.db.prepare(
            "SELECT mm.uid, m.id, m.size, m.received_at, m.seen, m.flagged, m.answered, m.draft
               FROM mailbox_messages mm
               JOIN mailboxes b ON b.id = mm.mailbox_id
               JOIN messages m ON m.id = mm.message_id
              WHERE b.name = ?1
              ORDER BY mm.uid",
        )?;
        let rows = statement.query_map([mailbox], |r| {
            Ok(Entry {
                uid: r.get(0)?,
                message_id: r.get(1)?,
                size: r.get::<_, i64>(2)?.max(0) as u64,
                received_at: r.get(3)?,
                flags: Flags {
                    seen: r.get(4)?,
                    flagged: r.get(5)?,
                    answered: r.get(6)?,
                    draft: r.get(7)?,
                },
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Deletes a mailbox (its UIDs with it). Made again, it gets a new
    /// UIDVALIDITY.
    pub fn delete_mailbox(&mut self, name: &str) -> Result<()> {
        self.db
            .execute("DELETE FROM mailboxes WHERE name = ?1", [name])?;
        Ok(())
    }

    /// The change feed's cursor, once the changes before it are applied.
    pub fn cursor(&self) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row("SELECT value FROM state WHERE key = 'cursor'", [], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_cursor(&mut self, cursor: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO state (key, value) VALUES ('cursor', ?1)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [cursor],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3; 32];

    fn row(id: &str) -> MessageRow {
        MessageRow {
            id: id.into(),
            size: 120,
            received_at: 1_780_000_000,
            flags: Flags::default(),
        }
    }

    #[test]
    fn uids_increase_and_are_never_given_twice() {
        let mut index = Index::in_memory(&KEY).unwrap();
        let inbox = index.mailbox("INBOX", "place:inbox").unwrap();
        assert_eq!(inbox.uid_next, 1);
        for id in ["a", "b", "c"] {
            index.put_message(&row(id)).unwrap();
        }
        assert_eq!(index.add("INBOX", "a").unwrap(), 1);
        assert_eq!(index.add("INBOX", "b").unwrap(), 2);
        // The same message again keeps its UID.
        assert_eq!(index.add("INBOX", "a").unwrap(), 1);
        assert_eq!(index.remove("INBOX", "b").unwrap(), Some(2));
        assert_eq!(index.add("INBOX", "c").unwrap(), 3);
        // Back after it was removed: a new UID, never 2 again.
        assert_eq!(index.add("INBOX", "b").unwrap(), 4);
        let uids: Vec<u32> = index
            .entries("INBOX")
            .unwrap()
            .iter()
            .map(|e| e.uid)
            .collect();
        assert_eq!(uids, [1, 3, 4]);
        assert_eq!(index.find("INBOX").unwrap().unwrap().uid_next, 5);
    }

    #[test]
    fn a_mailbox_made_again_has_a_higher_uidvalidity() {
        let mut index = Index::in_memory(&KEY).unwrap();
        let first = index
            .mailbox("Folders/İş", "folder:1")
            .unwrap()
            .uid_validity;
        let other = index.mailbox("INBOX", "place:inbox").unwrap().uid_validity;
        index.delete_mailbox("Folders/İş").unwrap();
        let again = index.mailbox("Folders/İş", "folder:1").unwrap();
        assert!(again.uid_validity > first && again.uid_validity > other);
        assert_eq!(again.uid_next, 1);
    }

    #[test]
    fn flags_follow_the_server_and_one_message_is_in_several_mailboxes() {
        let mut index = Index::in_memory(&KEY).unwrap();
        index.mailbox("INBOX", "place:inbox").unwrap();
        index.mailbox("All Mail", "place:all").unwrap();
        index.put_message(&row("a")).unwrap();
        index.add("INBOX", "a").unwrap();
        index.add("All Mail", "a").unwrap();
        index
            .put_message(&MessageRow {
                flags: Flags {
                    seen: true,
                    flagged: true,
                    ..Flags::default()
                },
                ..row("a")
            })
            .unwrap();
        for mailbox in ["INBOX", "All Mail"] {
            let entries = index.entries(mailbox).unwrap();
            assert!(
                entries[0].flags.seen && entries[0].flags.flagged,
                "{mailbox}"
            );
        }
        assert!(index.add("Nowhere", "a").is_err());
    }

    #[test]
    fn the_file_is_encrypted_and_opens_only_with_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        {
            let mut index = Index::open(&path, &KEY).unwrap();
            index.mailbox("Folders/Gizli proje", "folder:9").unwrap();
            index
                .set_cursor("123.00000000-0000-0000-0000-000000000000")
                .unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(6).any(|w| w == b"Gizli "),
            "names are not readable on disk"
        );
        assert!(!raw.starts_with(b"SQLite format 3"));
        assert!(matches!(
            Index::open(&path, &[4; 32]),
            Err(IndexError::WrongKey)
        ));
        let index = Index::open(&path, &KEY).unwrap();
        assert_eq!(index.mailboxes().unwrap()[0].name, "Folders/Gizli proje");
        assert_eq!(
            index.cursor().unwrap().as_deref(),
            Some("123.00000000-0000-0000-0000-000000000000")
        );
    }
}
