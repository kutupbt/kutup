//! Arbitrary bytes from a mail app through an IMAP session: the fuzz target
//! (`fuzz/fuzz_targets/mail_bridge_imap.rs`) and a short run in this crate's
//! tests share it. Whatever the bytes, the session must not panic, must
//! keep answering after a line it can't read, and must stop taking input
//! once it says it is closed.
//!
//! The session is logged in and has INBOX selected before the bytes come,
//! so commands past LOGIN are reached too; the bytes are fed in pieces cut
//! at places the input itself chooses, as a network would deliver them.

use crate::imap::{Backend, MailboxInfo, Session};
use crate::model::{Entry, Flags};

struct Fake;

const MESSAGE: &[u8] = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";

impl Backend for Fake {
    fn login(&mut self, user: &str, password: &[u8]) -> bool {
        user == "u" && password == b"p"
    }
    fn mailboxes(&mut self) -> Vec<MailboxInfo> {
        ["INBOX", "Sent", "Folders", "Folders/İş"]
            .iter()
            .map(|name| MailboxInfo {
                name: (*name).into(),
                special: (*name == "Sent").then_some("\\Sent"),
                no_select: *name == "Folders",
                uid_validity: 1,
                uid_next: 3,
            })
            .collect()
    }
    fn entries(&mut self, mailbox: &str) -> Option<Vec<Entry>> {
        (mailbox == "INBOX").then(|| {
            (1..=2)
                .map(|uid| Entry {
                    uid,
                    message_id: uid.to_string(),
                    size: MESSAGE.len() as u64,
                    received_at: 1_780_000_000,
                    flags: Flags::default(),
                })
                .collect()
        })
    }
    fn message(&mut self, _id: &str) -> Option<Vec<u8>> {
        Some(MESSAGE.to_vec())
    }
}

/// Runs `data` through a logged-in session with INBOX selected.
pub fn session_bytes(data: &[u8]) {
    let mut session = Session::new(Fake, true);
    session.input(b"");
    session.input(b"a LOGIN u p\r\nb SELECT INBOX\r\n");
    // The first byte says where to cut the rest.
    let Some((&step, rest)) = data.split_first() else {
        return;
    };
    let step = usize::from(step % 64) + 1;
    for piece in rest.chunks(step) {
        if session.is_closed() {
            break;
        }
        let _ = session.input(piece);
    }
    // A literal announced, IDLE or AUTHENTICATE rightly wait for more of
    // their own (the next bytes are the literal's, DONE, or the SASL data);
    // any other input leaves a session that answers the next command.
    let lower = data.to_ascii_lowercase();
    let waits = data.contains(&b'{')
        || lower.windows(4).any(|w| w == b"idle")
        || lower.windows(12).any(|w| w == b"authenticate");
    if !session.is_closed() && !waits {
        let out = session.input(b"\r\nz NOOP\r\n");
        assert!(
            out.windows(4).any(|w| w == b"z OK") || session.is_closed(),
            "the session stopped answering after {:?}",
            String::from_utf8_lossy(data)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::session_bytes;

    /// A brief fuzz run in every `cargo test` (the libFuzzer target runs
    /// longer, on demand): random bytes, and random bytes made of IMAP's own
    /// words, through the session.
    #[test]
    fn arbitrary_input_never_breaks_a_session() {
        let words: &[&[u8]] = &[
            b"a ",
            b"FETCH ",
            b"UID ",
            b"1:*",
            b"*",
            b" (",
            b")",
            b"BODY[]",
            b"BODY.PEEK[1.2]<0.10>",
            b"FLAGS",
            b"SEARCH ALL",
            b"LIST \"\" *",
            b"SELECT ",
            b"\"Folders/%\"",
            b"IDLE\r\n",
            b"DONE\r\n",
            b"{5}\r\n",
            b"{5+}\r\n",
            b"{99999999999}\r\n",
            b"\r\n",
            b"\n",
            b"\0",
            b"AUTHENTICATE PLAIN\r\n",
            b"*\r\n",
            b"LOGOUT",
            b"STORE 1 +FLAGS (\\Seen)",
            b"\xff\xfe",
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..3000 {
            let len = (next() % 400) as usize;
            let data: Vec<u8> = if round % 2 == 0 {
                (0..len).map(|_| next() as u8).collect()
            } else {
                let mut out = vec![next() as u8];
                while out.len() < len {
                    out.extend_from_slice(words[(next() % words.len() as u64) as usize]);
                }
                out
            };
            session_bytes(&data);
        }
        // The edges: nothing, one byte, a literal announced and never sent.
        session_bytes(&[]);
        session_bytes(&[0]);
        session_bytes(b"\x01a APPEND INBOX {10}\r\n");
    }
}
