//! The bridge's IMAP side (docs/plans/mail-bridge.md, B1): one session per
//! connection, sans I/O. Bytes from the mail app go in, bytes to send come
//! out; imap-next frames and parses (literals, IDLE, AUTHENTICATE), and this
//! answers each command from a [`Backend`] (the index, the cache and the
//! bridge's own login). B1 is read-only: CAPABILITY, NOOP, LOGOUT, LOGIN
//! (only over TLS), LIST, SELECT/EXAMINE, UNSELECT, CLOSE, FETCH (flags,
//! UID, size, date, the whole message), SEARCH ALL and IDLE; anything that
//! changes mail is refused until B2.

use std::num::NonZeroU32;

use imap_next::imap_types::command::{Command, CommandBody};
use imap_next::imap_types::core::{Atom, Charset, IString, NString, Tag, Text, Vec1};
use imap_next::imap_types::fetch::{
    Macro, MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Section,
};
use imap_next::imap_types::flag::{Flag, FlagFetch, FlagNameAttribute, FlagPerm};
use imap_next::imap_types::mailbox::{ListMailbox, Mailbox};
use imap_next::imap_types::response::{
    Capability, Code, CommandContinuationRequest, Data, Greeting, Status,
};
use imap_next::imap_types::search::SearchKey;
use imap_next::imap_types::sequence::SequenceSet;
use imap_next::server::{Error as ServerError, Event, Options, Server};
use imap_next::{Interrupt, Io, State as _};

use crate::model::{Entry, Flags};

/// The largest message the bridge takes from an app (a literal), as Mail's
/// own limit for a message; anything bigger is refused before it arrives.
pub const MAX_LITERAL: u32 = 50 * 1024 * 1024;

/// A mailbox as LIST shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxInfo {
    /// Its IMAP name (`INBOX`, `Sent`, `Folders/İş`), `/` between levels.
    pub name: String,
    /// RFC 6154's special use (`\Sent`, `\Trash`, …), when it has one.
    pub special: Option<&'static str>,
    /// A parent shown only to hold others (`Folders`, `Labels`).
    pub no_select: bool,
    pub uid_validity: u32,
    pub uid_next: u32,
}

/// What a session answers from.
pub trait Backend {
    /// Whether `user` and `password` are this bridge's (the app password,
    /// checked in constant time).
    fn login(&mut self, user: &str, password: &[u8]) -> bool;
    fn mailboxes(&mut self) -> Vec<MailboxInfo>;
    /// A mailbox's messages by UID, or None when there is no such mailbox.
    fn entries(&mut self, mailbox: &str) -> Option<Vec<Entry>>;
    /// A message's bytes (RFC 5322), opened from the cache or fetched.
    fn message(&mut self, message_id: &str) -> Option<Vec<u8>>;
}

enum Phase {
    NotAuthenticated,
    Authenticated,
    Selected { name: String, entries: Vec<Entry> },
}

/// One connection's session.
pub struct Session<B> {
    server: Server,
    backend: B,
    /// Whether the connection is under TLS (implicit, or after STARTTLS):
    /// LOGIN is refused before it.
    tls: bool,
    phase: Phase,
    idle_tag: Option<Tag<'static>>,
    closed: bool,
}

fn text(value: &str) -> Text<'static> {
    Text::try_from(value.to_owned()).unwrap_or_else(|_| Text::try_from("-").expect("a text"))
}

fn tagged_ok(tag: Tag<'static>, code: Option<Code<'static>>, message: &str) -> Status<'static> {
    Status::ok(Some(tag), code, text(message).to_string()).expect("a status")
}

fn tagged_no(tag: Tag<'static>, message: &str) -> Status<'static> {
    Status::no(Some(tag), None, text(message).to_string()).expect("a status")
}

fn tagged_bad(tag: Tag<'static>, message: &str) -> Status<'static> {
    Status::bad(Some(tag), None, text(message).to_string()).expect("a status")
}

fn mailbox_name(mailbox: &Mailbox<'_>) -> String {
    match mailbox {
        Mailbox::Inbox => "INBOX".to_owned(),
        Mailbox::Other(other) => String::from_utf8_lossy(other.as_ref()).into_owned(),
    }
}

fn flags_of(flags: Flags) -> Vec<FlagFetch<'static>> {
    let mut out = Vec::new();
    if flags.seen {
        out.push(FlagFetch::Flag(Flag::Seen));
    }
    if flags.flagged {
        out.push(FlagFetch::Flag(Flag::Flagged));
    }
    if flags.answered {
        out.push(FlagFetch::Flag(Flag::Answered));
    }
    if flags.draft {
        out.push(FlagFetch::Flag(Flag::Draft));
    }
    out
}

impl<B: Backend> Session<B> {
    pub fn new(backend: B, tls: bool) -> Self {
        let mut options = Options::default();
        options.max_literal_size = MAX_LITERAL;
        options.max_command_size = MAX_LITERAL + 64 * 1024;
        let greeting = Greeting::ok(None, "Kutup Mail bridge ready").expect("a greeting");
        Self {
            server: Server::new(options, greeting),
            backend,
            tls,
            phase: Phase::NotAuthenticated,
            idle_tag: None,
            closed: false,
        }
    }

    /// The connection is to be closed (LOGOUT answered, or the app broke
    /// the protocol past recovery).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Takes the app's bytes (none at first, for the greeting) and answers
    /// the bytes to write back.
    pub fn input(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.server.enqueue_input(bytes);
        let mut out = Vec::new();
        loop {
            match self.server.next() {
                Ok(Event::CommandReceived { command }) => self.command(command),
                Ok(Event::IdleCommandReceived { tag }) => {
                    let request =
                        CommandContinuationRequest::basic(None, "idling").expect("a request");
                    if self.server.idle_accept(request).is_ok() {
                        self.idle_tag = Some(tag);
                    }
                }
                Ok(Event::IdleDoneReceived) => {
                    if let Some(tag) = self.idle_tag.take() {
                        self.server
                            .enqueue_status(tagged_ok(tag, None, "IDLE done"));
                    }
                }
                // No SASL mechanism is offered: LOGIN, over TLS.
                Ok(Event::CommandAuthenticateReceived {
                    command_authenticate,
                }) => {
                    let _ = self.server.authenticate_finish(tagged_no(
                        command_authenticate.tag,
                        "use LOGIN with the bridge's app password",
                    ));
                }
                Ok(Event::AuthenticateDataReceived { .. }) => {}
                Ok(Event::GreetingSent { .. } | Event::ResponseSent { .. }) => {
                    if self.closed {
                        continue;
                    }
                }
                Err(Interrupt::Io(Io::Output(bytes))) => out.extend_from_slice(&bytes),
                Err(Interrupt::Io(Io::NeedMoreInput)) => break,
                Err(Interrupt::Error(error)) => match error {
                    // A line that doesn't parse: said so, and the session goes on.
                    ServerError::MalformedMessage { .. }
                    | ServerError::ExpectedCrlfGotLf { .. } => {
                        let status = Status::bad(None, None, "the command does not parse")
                            .expect("a status");
                        self.server.enqueue_status(status);
                    }
                    // Too big to take: the connection ends.
                    ServerError::LiteralTooLong { .. } | ServerError::CommandTooLong { .. } => {
                        let bye = Status::bye(None, "too long").expect("a status");
                        self.server.enqueue_status(bye);
                        self.closed = true;
                    }
                },
            }
        }
        out
    }

    fn command(&mut self, command: Command<'static>) {
        let tag = command.tag;
        let status = match command.body {
            CommandBody::Capability => {
                self.server
                    .enqueue_data(Data::Capability(self.capabilities()));
                tagged_ok(tag, None, "CAPABILITY done")
            }
            CommandBody::Noop => {
                self.refresh();
                tagged_ok(tag, None, "NOOP done")
            }
            CommandBody::Logout => {
                self.server
                    .enqueue_status(Status::bye(None, "logging out").expect("a status"));
                self.closed = true;
                tagged_ok(tag, None, "LOGOUT done")
            }
            CommandBody::Login { username, password } => {
                self.login(tag, &username, password.declassify())
            }
            body if matches!(self.phase, Phase::NotAuthenticated) => {
                let _ = body;
                tagged_bad(tag, "log in first")
            }
            CommandBody::List {
                reference,
                mailbox_wildcard,
            } => self.list(tag, &reference, &mailbox_wildcard),
            CommandBody::Select { mailbox, .. } => self.select(tag, &mailbox, false),
            CommandBody::Examine { mailbox, .. } => self.select(tag, &mailbox, true),
            CommandBody::Unselect | CommandBody::Close => {
                if matches!(self.phase, Phase::Selected { .. }) {
                    self.phase = Phase::Authenticated;
                    tagged_ok(tag, None, "closed")
                } else {
                    tagged_bad(tag, "no mailbox is selected")
                }
            }
            CommandBody::Fetch {
                sequence_set,
                macro_or_item_names,
                uid,
                ..
            } => self.fetch(tag, &sequence_set, macro_or_item_names, uid),
            CommandBody::Search {
                charset,
                criteria,
                uid,
            } => self.search(tag, charset.as_ref(), &criteria, uid),
            CommandBody::Check => tagged_ok(tag, None, "CHECK done"),
            _ => tagged_no(tag, "not available in this version of the bridge"),
        };
        self.server.enqueue_status(status);
    }

    fn capabilities(&self) -> Vec1<Capability<'static>> {
        let mut list = vec![
            Capability::Imap4Rev1,
            Capability::Idle,
            Capability::Unselect,
            Capability::LiteralPlus,
        ];
        if !self.tls {
            list.push(Capability::LoginDisabled);
        }
        Vec1::try_from(list).expect("not empty")
    }

    fn login(
        &mut self,
        tag: Tag<'static>,
        username: &impl AsRef<[u8]>,
        password: &impl AsRef<[u8]>,
    ) -> Status<'static> {
        if !self.tls {
            return tagged_no(tag, "log in over TLS");
        }
        if !matches!(self.phase, Phase::NotAuthenticated) {
            return tagged_bad(tag, "logged in already");
        }
        let user = String::from_utf8_lossy(username.as_ref()).into_owned();
        if self.backend.login(&user, password.as_ref()) {
            self.phase = Phase::Authenticated;
            tagged_ok(tag, None, "logged in")
        } else {
            tagged_no(tag, "wrong user or app password")
        }
    }

    fn list(
        &mut self,
        tag: Tag<'static>,
        reference: &Mailbox<'_>,
        wildcard: &ListMailbox<'_>,
    ) -> Status<'static> {
        let pattern = match wildcard {
            ListMailbox::Token(token) => String::from_utf8_lossy(token.as_ref()).into_owned(),
            ListMailbox::String(string) => String::from_utf8_lossy(string.as_ref()).into_owned(),
        };
        // `LIST "" ""`: the hierarchy delimiter only.
        if pattern.is_empty() {
            self.server.enqueue_data(Data::List {
                items: vec![FlagNameAttribute::Noselect],
                delimiter: Some('/'.try_into().expect("a delimiter")),
                mailbox: Mailbox::try_from("").unwrap_or(Mailbox::Inbox),
            });
            return tagged_ok(tag, None, "LIST done");
        }
        let prefix = match reference {
            Mailbox::Inbox => "INBOX".to_owned(),
            other => mailbox_name(other),
        };
        let full = format!("{prefix}{pattern}");
        for mailbox in self.backend.mailboxes() {
            if !wildcard_matches(&full, &mailbox.name) {
                continue;
            }
            let mut items = Vec::new();
            if mailbox.no_select {
                items.push(FlagNameAttribute::Noselect);
            }
            if let Some(special) = mailbox.special {
                if let Ok(atom) = Atom::try_from(special.trim_start_matches('\\').to_owned()) {
                    items.push(FlagNameAttribute::from(atom));
                }
            }
            let Ok(name) = Mailbox::try_from(mailbox.name.clone()) else {
                continue;
            };
            self.server.enqueue_data(Data::List {
                items,
                delimiter: Some('/'.try_into().expect("a delimiter")),
                mailbox: name,
            });
        }
        tagged_ok(tag, None, "LIST done")
    }

    fn select(
        &mut self,
        tag: Tag<'static>,
        mailbox: &Mailbox<'_>,
        read_only: bool,
    ) -> Status<'static> {
        let name = mailbox_name(mailbox);
        let info = self
            .backend
            .mailboxes()
            .into_iter()
            .find(|m| m.name == name && !m.no_select);
        let (Some(info), Some(entries)) = (info, self.backend.entries(&name)) else {
            self.phase = Phase::Authenticated;
            return tagged_no(tag, "no such mailbox");
        };
        let flags = vec![
            Flag::Seen,
            Flag::Flagged,
            Flag::Answered,
            Flag::Draft,
            Flag::Deleted,
        ];
        self.server.enqueue_data(Data::Flags(flags.clone()));
        self.server.enqueue_data(Data::Exists(entries.len() as u32));
        self.server.enqueue_data(Data::Recent(0));
        if let Some(validity) = NonZeroU32::new(info.uid_validity) {
            self.server.enqueue_status(
                Status::ok(None, Some(Code::UidValidity(validity)), "UIDs valid")
                    .expect("a status"),
            );
        }
        if let Some(next) = NonZeroU32::new(info.uid_next) {
            self.server.enqueue_status(
                Status::ok(None, Some(Code::UidNext(next)), "the next UID").expect("a status"),
            );
        }
        // B1 changes nothing: every mailbox is read-only for now.
        self.server.enqueue_status(
            Status::ok(
                None,
                Some(Code::PermanentFlags(Vec::<FlagPerm>::new())),
                "no flags change yet",
            )
            .expect("a status"),
        );
        self.phase = Phase::Selected { name, entries };
        // EXAMINE and SELECT alike until B2 writes.
        let _ = read_only;
        tagged_ok(tag, Some(Code::ReadOnly), "selected, read-only")
    }

    /// The selected mailbox seen again (NOOP): new messages are announced.
    fn refresh(&mut self) {
        let Phase::Selected { name, entries, .. } = &mut self.phase else {
            return;
        };
        let Some(now) = self.backend.entries(name) else {
            return;
        };
        // B1 announces arrivals only; expunges come with B2's writes.
        if now.len() > entries.len() && now.iter().zip(entries.iter()).all(|(a, b)| a.uid == b.uid)
        {
            *entries = now;
            self.server.enqueue_data(Data::Exists(entries.len() as u32));
        }
    }

    fn fetch(
        &mut self,
        tag: Tag<'static>,
        set: &SequenceSet,
        items: MacroOrMessageDataItemNames<'static>,
        uid: bool,
    ) -> Status<'static> {
        let Phase::Selected { entries, .. } = &self.phase else {
            return tagged_bad(tag, "select a mailbox first");
        };
        let names: Vec<MessageDataItemName<'static>> = match items {
            MacroOrMessageDataItemNames::Macro(Macro::All) => vec![
                MessageDataItemName::Flags,
                MessageDataItemName::InternalDate,
                MessageDataItemName::Rfc822Size,
            ],
            MacroOrMessageDataItemNames::Macro(Macro::Fast) => vec![
                MessageDataItemName::Flags,
                MessageDataItemName::InternalDate,
                MessageDataItemName::Rfc822Size,
            ],
            MacroOrMessageDataItemNames::Macro(Macro::Full) => vec![
                MessageDataItemName::Flags,
                MessageDataItemName::InternalDate,
                MessageDataItemName::Rfc822Size,
            ],
            MacroOrMessageDataItemNames::MessageDataItemNames(names) => names,
            _ => vec![MessageDataItemName::Flags],
        };
        let selected: Vec<(usize, Entry)> = select_entries(entries, set, uid);
        for (index, entry) in selected {
            let mut data: Vec<MessageDataItem<'static>> = Vec::new();
            if uid {
                if let Some(u) = NonZeroU32::new(entry.uid) {
                    data.push(MessageDataItem::Uid(u));
                }
            }
            for name in &names {
                match name {
                    MessageDataItemName::Uid if !uid => {
                        if let Some(u) = NonZeroU32::new(entry.uid) {
                            data.push(MessageDataItem::Uid(u));
                        }
                    }
                    MessageDataItemName::Flags => {
                        data.push(MessageDataItem::Flags(flags_of(entry.flags)))
                    }
                    MessageDataItemName::Rfc822Size => data.push(MessageDataItem::Rfc822Size(
                        u32::try_from(entry.size).unwrap_or(u32::MAX),
                    )),
                    MessageDataItemName::InternalDate => {
                        if let Some(date) = internal_date(entry.received_at) {
                            data.push(MessageDataItem::InternalDate(date));
                        }
                    }
                    MessageDataItemName::Rfc822 => {
                        let bytes = self.backend.message(&entry.message_id).unwrap_or_default();
                        data.push(MessageDataItem::Rfc822(nstring(bytes)));
                    }
                    MessageDataItemName::BodyExt {
                        section: None,
                        partial: None,
                        ..
                    } => {
                        let bytes = self.backend.message(&entry.message_id).unwrap_or_default();
                        data.push(MessageDataItem::BodyExt {
                            section: None::<Section>,
                            origin: None,
                            data: nstring(bytes),
                        });
                    }
                    // ENVELOPE, BODYSTRUCTURE, sections and partial bodies
                    // come with the message parser (B1's next step).
                    _ => {}
                }
            }
            if let (Some(seq), Ok(items)) =
                (NonZeroU32::new(index as u32 + 1), Vec1::try_from(data))
            {
                self.server.enqueue_data(Data::Fetch { seq, items });
            }
        }
        tagged_ok(tag, None, "FETCH done")
    }

    fn search(
        &mut self,
        tag: Tag<'static>,
        charset: Option<&Charset<'_>>,
        criteria: &Vec1<SearchKey<'_>>,
        uid: bool,
    ) -> Status<'static> {
        let _ = charset;
        let Phase::Selected { entries, .. } = &self.phase else {
            return tagged_bad(tag, "select a mailbox first");
        };
        if !criteria
            .as_ref()
            .iter()
            .all(|key| matches!(key, SearchKey::All))
        {
            return tagged_no(tag, "only SEARCH ALL in this version of the bridge");
        }
        let found: Vec<NonZeroU32> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| NonZeroU32::new(if uid { e.uid } else { i as u32 + 1 }))
            .collect();
        self.server.enqueue_data(Data::Search(found));
        tagged_ok(tag, None, "SEARCH done")
    }
}

fn nstring(bytes: Vec<u8>) -> NString<'static> {
    NString(Some(IString::Literal(
        imap_next::imap_types::core::Literal::try_from(bytes).unwrap_or_else(|_| {
            imap_next::imap_types::core::Literal::try_from(Vec::new()).expect("an empty literal")
        }),
    )))
}

fn internal_date(seconds: i64) -> Option<imap_next::imap_types::datetime::DateTime> {
    let date = chrono::DateTime::from_timestamp(seconds, 0)?.fixed_offset();
    imap_next::imap_types::datetime::DateTime::try_from(date).ok()
}

/// The entries `set` names, with their places (sequence number − 1).
fn select_entries(entries: &[Entry], set: &SequenceSet, uid: bool) -> Vec<(usize, Entry)> {
    let Some(largest) = NonZeroU32::new(if uid {
        entries.last().map_or(0, |e| e.uid)
    } else {
        entries.len() as u32
    }) else {
        return Vec::new();
    };
    let mut out: Vec<(usize, Entry)> = Vec::new();
    for n in set.iter(largest) {
        let n = n.get();
        let found = if uid {
            entries.iter().position(|e| e.uid == n)
        } else {
            (n as usize).checked_sub(1).filter(|i| *i < entries.len())
        };
        if let Some(i) = found {
            if !out.iter().any(|(j, _)| *j == i) {
                out.push((i, entries[i].clone()));
            }
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out
}

/// IMAP's LIST wildcards: `*` any run, `%` any run without the delimiter.
fn wildcard_matches(pattern: &str, name: &str) -> bool {
    fn go(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|i| go(&p[1..], &n[i..])),
            Some('%') => (0..=n.len())
                .take_while(|i| !n[..*i].contains(&'/'))
                .any(|i| go(&p[1..], &n[i..])),
            Some(c) => n.first() == Some(c) && go(&p[1..], &n[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    // INBOX is case-insensitive.
    if name.eq_ignore_ascii_case("INBOX") && pattern.eq_ignore_ascii_case("INBOX") {
        return true;
    }
    go(&p, &n)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;

    const MESSAGE: &[u8] = b"From: bob@example.org\r\nSubject: Merhaba\r\n\r\nSelam\r\n";

    impl Backend for Fake {
        fn login(&mut self, user: &str, password: &[u8]) -> bool {
            user == "ada@kutup.dev" && password == b"app-password"
        }
        fn mailboxes(&mut self) -> Vec<MailboxInfo> {
            let mailbox = |name: &str, special, no_select| MailboxInfo {
                name: name.into(),
                special,
                no_select,
                uid_validity: 7,
                uid_next: 4,
            };
            vec![
                mailbox("INBOX", None, false),
                mailbox("Sent", Some("\\Sent"), false),
                mailbox("Folders", None, true),
                mailbox("Folders/İş", None, false),
            ]
        }
        fn entries(&mut self, mailbox: &str) -> Option<Vec<Entry>> {
            (mailbox == "INBOX").then(|| {
                vec![
                    Entry {
                        uid: 1,
                        message_id: "a".into(),
                        size: MESSAGE.len() as u64,
                        received_at: 1_780_000_000,
                        flags: Flags {
                            seen: true,
                            ..Flags::default()
                        },
                    },
                    Entry {
                        uid: 3,
                        message_id: "b".into(),
                        size: 10,
                        received_at: 1_780_000_100,
                        flags: Flags::default(),
                    },
                ]
            })
        }
        fn message(&mut self, id: &str) -> Option<Vec<u8>> {
            (id == "a").then(|| MESSAGE.to_vec())
        }
    }

    fn say(session: &mut Session<Fake>, line: &str) -> String {
        String::from_utf8(session.input(line.as_bytes())).unwrap()
    }

    #[test]
    fn no_login_before_tls() {
        let mut s = Session::new(Fake, false);
        assert!(say(&mut s, "").starts_with("* OK"));
        let caps = say(&mut s, "a CAPABILITY\r\n");
        assert!(caps.contains("LOGINDISABLED"), "{caps}");
        let login = say(&mut s, "b LOGIN ada@kutup.dev app-password\r\n");
        assert!(login.contains("b NO"), "{login}");
        assert!(say(&mut s, "c LIST \"\" *\r\n").contains("c BAD"));
    }

    #[test]
    fn a_read_only_session_over_tls() {
        let mut s = Session::new(Fake, true);
        say(&mut s, "");
        assert!(!say(&mut s, "a CAPABILITY\r\n").contains("LOGINDISABLED"));
        assert!(say(&mut s, "b LOGIN ada@kutup.dev wrong\r\n").contains("b NO"));
        assert!(say(&mut s, "c LOGIN ada@kutup.dev app-password\r\n").contains("c OK"));

        let list = say(&mut s, "d LIST \"\" *\r\n");
        assert!(
            list.contains("\"INBOX\"") || list.contains(" INBOX"),
            "{list}"
        );
        assert!(list.contains("\\Sent"), "{list}");
        assert!(list.contains("\\Noselect"), "{list}");
        assert!(list.contains("d OK"));
        let top = say(&mut s, "d2 LIST \"\" %\r\n");
        assert!(!top.contains("Folders/"), "% stops at the delimiter: {top}");

        assert!(say(&mut s, "e SELECT Nowhere\r\n").contains("e NO"));
        let select = say(&mut s, "f SELECT INBOX\r\n");
        for want in [
            "* 2 EXISTS",
            "UIDVALIDITY 7",
            "UIDNEXT 4",
            "f OK [READ-ONLY]",
        ] {
            assert!(select.contains(want), "{want}: {select}");
        }

        let uids = say(&mut s, "g UID FETCH 1:* (FLAGS RFC822.SIZE)\r\n");
        assert!(
            uids.contains("* 1 FETCH (UID 1 FLAGS (\\Seen) RFC822.SIZE"),
            "{uids}"
        );
        assert!(
            uids.contains("* 2 FETCH (UID 3 FLAGS () RFC822.SIZE 10)"),
            "{uids}"
        );
        let body = say(&mut s, "h FETCH 1 BODY.PEEK[]\r\n");
        assert!(body.contains("Subject: Merhaba"), "{body}");
        assert!(body.contains("h OK"));

        let search = say(&mut s, "i UID SEARCH ALL\r\n");
        assert!(search.contains("* SEARCH 1 3"), "{search}");
        assert!(say(&mut s, "j STORE 1 +FLAGS (\\Seen)\r\n").contains("j NO"));

        let idle = say(&mut s, "k IDLE\r\n");
        assert!(idle.starts_with("+ "), "{idle}");
        assert!(say(&mut s, "DONE\r\n").contains("k OK"));

        assert!(say(&mut s, "this is not imap\r\n").contains("BAD"));
        assert!(
            say(&mut s, "l NOOP\r\n").contains("l OK"),
            "the session goes on"
        );
        let bye = say(&mut s, "m LOGOUT\r\n");
        assert!(bye.contains("* BYE") && bye.contains("m OK"), "{bye}");
        assert!(s.is_closed());
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_matches("*", "Folders/İş"));
        assert!(wildcard_matches("%", "INBOX"));
        assert!(!wildcard_matches("%", "Folders/İş"));
        assert!(wildcard_matches("Folders/%", "Folders/İş"));
        assert!(wildcard_matches("inbox", "INBOX"));
    }
}
