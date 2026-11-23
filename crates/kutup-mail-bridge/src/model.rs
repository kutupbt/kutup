//! What the IMAP side and the index share: a mailbox's messages by UID.

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
