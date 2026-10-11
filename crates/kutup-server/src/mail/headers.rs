//! What the server may read of an incoming message (docs/plans/mail.md):
//! the subject, the addresses, the dates, threading ids and the attachment
//! count, Proton's readable fields, and whether the body is OpenPGP
//! encrypted. Read once on arrival, before the message is encrypted;
//! nothing from the body is kept.

use mail_parser::{Address, HeaderValue, Message, MessageParser, MimeHeaders, PartType};
use serde::{Deserialize, Serialize};

/// Column limits of `mail_messages` (migration 085).
const SUBJECT_CHARS: usize = 1000;
const ADDRESS_CHARS: usize = 320;
const NAME_CHARS: usize = 400;
const ID_CHARS: usize = 998;
const MAX_ADDRESSES: usize = 100;
const MAX_REFERENCES: usize = 50;

/// One mailbox of a From, To, Cc or Reply-To header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub address: String,
    #[serde(default)]
    pub name: String,
}

/// The readable fields of one message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Readable {
    pub subject: String,
    pub from: Option<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    /// The Date header, as seconds since the epoch.
    pub sent_at: Option<i64>,
    /// Message-ID, In-Reply-To and References, without angle brackets.
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachment_count: i32,
    /// Stalwart's spam verdict, from the topmost `X-Spam-Score` header.
    pub spam: bool,
    /// A delivery report (RFC 3464) for mail this address sent: how many
    /// recipients failed, and the Message-ID of the message they failed for.
    pub bounce: Option<Bounce>,
    /// The body is an encrypted OpenPGP message (RFC 3156
    /// `multipart/encrypted`, or inline PGP): end to end from its sender.
    pub pgp_encrypted: bool,
}

/// A delivery failure report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounce {
    pub failures: u32,
    pub original_message_id: Option<String>,
}

impl Readable {
    /// Reads `raw`. A message the parser cannot read at all still arrives,
    /// with nothing readable: refusing it would lose mail over a header.
    pub fn parse(raw: &[u8]) -> Self {
        let Some(message) = MessageParser::default().parse(raw) else {
            return Self::default();
        };
        let (in_reply_to, references) = threading(message.in_reply_to(), message.references());
        Readable {
            subject: message
                .subject()
                .map(|s| clip(single_line(s).trim(), SUBJECT_CHARS))
                .unwrap_or_default(),
            from: message.from().and_then(|a| mailboxes(a).into_iter().next()),
            to: message.to().map(mailboxes).unwrap_or_default(),
            cc: message.cc().map(mailboxes).unwrap_or_default(),
            reply_to: message.reply_to().map(mailboxes).unwrap_or_default(),
            sent_at: message.date().map(|d| d.to_timestamp()),
            message_id: message.message_id().and_then(message_id),
            in_reply_to,
            references,
            attachment_count: i32::try_from(message.attachment_count()).unwrap_or(i32::MAX),
            spam: spam_verdict(raw),
            bounce: bounce(&message),
            pgp_encrypted: pgp_encrypted(&message),
        }
    }
}

/// A `multipart/report; report-type=delivery-status` message: its failed
/// recipients and the original message's id, from the returned headers.
fn bounce(message: &Message<'_>) -> Option<Bounce> {
    let top = message.content_type()?;
    if !top.ctype().eq_ignore_ascii_case("multipart")
        || !top
            .subtype()
            .is_some_and(|s| s.eq_ignore_ascii_case("report"))
        || !top
            .attribute("report-type")
            .is_some_and(|t| t.eq_ignore_ascii_case("delivery-status"))
    {
        return None;
    }
    let mut failures = 0u32;
    let mut original = None;
    for part in &message.parts {
        let Some(kind) = part.content_type() else {
            continue;
        };
        if !kind.ctype().eq_ignore_ascii_case("message") {
            continue;
        }
        match kind.subtype().map(str::to_ascii_lowercase).as_deref() {
            Some("delivery-status") | Some("global-delivery-status") => {
                let text = part.text_contents().unwrap_or_default();
                failures += text
                    .lines()
                    .filter(|line| {
                        let line = line.trim().to_ascii_lowercase();
                        line.starts_with("action:") && line.contains("failed")
                    })
                    .count() as u32;
            }
            Some("rfc822") | Some("global") | Some("rfc822-headers") | Some("global-headers") => {
                original = original.or_else(|| match &part.body {
                    PartType::Message(returned) => returned.message_id().and_then(message_id),
                    // Returned headers alone end without a blank line.
                    _ => {
                        let mut headers = part.contents().to_vec();
                        headers.extend_from_slice(b"\r\n\r\n");
                        MessageParser::default()
                            .parse_headers(&headers)
                            .and_then(|parsed| parsed.message_id().and_then(message_id))
                    }
                });
            }
            _ => {}
        }
    }
    (failures > 0).then_some(Bounce {
        failures,
        original_message_id: original,
    })
}

/// Whether the whole body is one encrypted OpenPGP message: the
/// `application/octet-stream` part of `multipart/encrypted;
/// protocol="application/pgp-encrypted"`, or a single text part that is an
/// armored PGP message and nothing else.
fn pgp_encrypted(message: &Message<'_>) -> bool {
    let encrypted = |bytes: &[u8]| kutup_crypto::mail_key::pgp_message_key_ids(bytes).is_ok();
    let Some(top) = message.content_type() else {
        return message.parts.len() == 1 && inline_pgp(message.parts[0].contents(), encrypted);
    };
    let is = |ctype: &str, subtype: &str| {
        top.ctype().eq_ignore_ascii_case(ctype)
            && top
                .subtype()
                .is_some_and(|s| s.eq_ignore_ascii_case(subtype))
    };
    if is("multipart", "encrypted") {
        if !top
            .attribute("protocol")
            .is_some_and(|p| p.eq_ignore_ascii_case("application/pgp-encrypted"))
        {
            return false;
        }
        return message.parts.iter().skip(1).any(|part| {
            part.content_type().is_some_and(|kind| {
                kind.ctype().eq_ignore_ascii_case("application")
                    && kind
                        .subtype()
                        .is_some_and(|s| s.eq_ignore_ascii_case("octet-stream"))
            }) && encrypted(part.contents())
        });
    }
    is("text", "plain")
        && message.parts.len() == 1
        && inline_pgp(message.parts[0].contents(), encrypted)
}

fn inline_pgp(body: &[u8], encrypted: impl Fn(&[u8]) -> bool) -> bool {
    let body = body.trim_ascii();
    body.starts_with(b"-----BEGIN PGP MESSAGE-----")
        && body.ends_with(b"-----END PGP MESSAGE-----")
        && encrypted(body)
}

fn mailboxes(address: &Address<'_>) -> Vec<Mailbox> {
    address
        .iter()
        .filter_map(|addr| {
            let address = addr.address()?.trim().to_lowercase();
            if address.is_empty() || address.chars().count() > ADDRESS_CHARS {
                return None;
            }
            Some(Mailbox {
                address,
                name: addr
                    .name()
                    .map(|n| clip(single_line(n).trim(), NAME_CHARS))
                    .unwrap_or_default(),
            })
        })
        .take(MAX_ADDRESSES)
        .collect()
}

fn threading(
    in_reply_to: &HeaderValue<'_>,
    references: &HeaderValue<'_>,
) -> (Option<String>, Vec<String>) {
    let ids = |value: &HeaderValue<'_>| -> Vec<String> {
        match value {
            HeaderValue::Text(id) => message_id(id).into_iter().collect(),
            HeaderValue::TextList(ids) => ids.iter().filter_map(|id| message_id(id)).collect(),
            _ => Vec::new(),
        }
    };
    let in_reply_to = ids(in_reply_to).into_iter().next();
    // The newest references are the nearest ancestors; keep those.
    let mut references = ids(references);
    if references.len() > MAX_REFERENCES {
        references.drain(..references.len() - MAX_REFERENCES);
    }
    (in_reply_to, references)
}

pub(crate) fn message_id(value: &str) -> Option<String> {
    let id = value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    (!id.is_empty() && id.len() <= ID_CHARS && !id.chars().any(char::is_whitespace))
        .then(|| id.to_string())
}

/// Whether Stalwart judged the message spam. Stalwart prepends its headers,
/// so only the first `X-Spam-Score` counts: a sender can add more below it.
/// Its value reads `spam, score=11.00` or `ham, score=-1.20`.
fn spam_verdict(raw: &[u8]) -> bool {
    let end = find_header_end(raw);
    let mut lines = raw[..end].split(|b| *b == b'\n');
    lines
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let (name, value) = line.split_at(line.iter().position(|b| *b == b':')?);
            name.eq_ignore_ascii_case(b"x-spam-score").then(|| {
                let value = value[1..].trim_ascii_start();
                value.len() >= 4 && value[..4].eq_ignore_ascii_case(b"spam")
            })
        })
        .unwrap_or(false)
}

fn find_header_end(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len())
}

pub(crate) fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub(crate) fn clip(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"X-Spam-Score: ham, score=-1.20\r\n\
X-Spam-Score: spam, score=99\r\n\
From: =?UTF-8?Q?=C3=87a=C4=9Flar_=C3=96zt=C3=BCrk?= <Caglar@Example.ORG>\r\n\
To: alice@kutup.dev, \"Bob B\" <bob@kutup.dev>\r\n\
Cc: carol@example.org\r\n\
Reply-To: list@example.org\r\n\
Subject: =?ISO-8859-9?Q?Toplant=FD_=FEubat?=\r\n\
Date: Fri, 09 Oct 2026 10:00:00 +0300\r\n\
Message-ID: <abc@example.org>\r\n\
In-Reply-To: <parent@example.org>\r\n\
References: <root@example.org> <parent@example.org>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Merhaba\r\n\
--b\r\n\
Content-Type: application/pdf; name=a.pdf\r\n\
Content-Disposition: attachment; filename=a.pdf\r\n\
\r\n\
JVBERi0=\r\n\
--b--\r\n";

    #[test]
    fn reads_the_readable_fields() {
        let r = Readable::parse(MESSAGE);
        assert_eq!(r.subject, "Toplantı şubat");
        assert_eq!(
            r.from,
            Some(Mailbox {
                address: "caglar@example.org".into(),
                name: "Çağlar Öztürk".into()
            })
        );
        assert_eq!(
            r.to.iter().map(|m| m.address.as_str()).collect::<Vec<_>>(),
            ["alice@kutup.dev", "bob@kutup.dev"]
        );
        assert_eq!(r.to[1].name, "Bob B");
        assert_eq!(r.cc[0].address, "carol@example.org");
        assert_eq!(r.reply_to[0].address, "list@example.org");
        assert_eq!(r.sent_at, Some(1_791_529_200));
        assert_eq!(r.message_id.as_deref(), Some("abc@example.org"));
        assert_eq!(r.in_reply_to.as_deref(), Some("parent@example.org"));
        assert_eq!(r.references, ["root@example.org", "parent@example.org"]);
        assert_eq!(r.attachment_count, 1);
        // Only the topmost verdict, which Stalwart wrote, counts.
        assert!(!r.spam);
    }

    #[test]
    fn spam_verdict_reads_the_first_header_only() {
        assert!(spam_verdict(
            b"X-Spam-Score: spam, score=11.00\r\nX-Spam-Score: ham\r\n\r\nbody"
        ));
        assert!(spam_verdict(b"x-spam-score:SPAM\n\nbody"));
        assert!(!spam_verdict(b"Subject: hi\r\n\r\nX-Spam-Score: spam\r\n"));
        assert!(!spam_verdict(b"X-Spam-Score: ham, score=0\r\n\r\n"));
    }

    #[test]
    fn missing_and_hostile_headers_stay_bounded() {
        let r = Readable::parse(b"Subject: line\r\n\tfolded\x07bell\r\n\r\nbody");
        assert_eq!(r.subject, "line folded bell");
        assert_eq!(r.from, None);
        assert!(r.to.is_empty());
        assert_eq!(r.sent_at, None);
        assert_eq!(r.message_id, None);

        let long = format!(
            "Subject: {}\r\nMessage-ID: <a b@c>\r\n\r\n",
            "ş".repeat(5000)
        );
        let r = Readable::parse(long.as_bytes());
        assert_eq!(r.subject.chars().count(), SUBJECT_CHARS);
        assert_eq!(r.message_id, None, "an id with whitespace is no id");

        let many = format!(
            "To: {}\r\nReferences: {}\r\n\r\n",
            (0..150)
                .map(|i| format!("u{i}@x.org"))
                .collect::<Vec<_>>()
                .join(", "),
            (0..80)
                .map(|i| format!("<r{i}@x>"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let r = Readable::parse(many.as_bytes());
        assert_eq!(r.to.len(), MAX_ADDRESSES);
        assert_eq!(r.references.len(), MAX_REFERENCES);
        assert_eq!(r.references.last().map(String::as_str), Some("r79@x"));
    }

    #[test]
    fn delivery_reports_name_their_failures_and_original() {
        let report = b"From: MAILER-DAEMON@mail.kutup.dev\r\n\
To: alice@kutup.dev\r\n\
Subject: Undelivered Mail Returned to Sender\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
Could not deliver.\r\n\
--b\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; mail.kutup.dev\r\n\
\r\n\
Final-Recipient: rfc822; nobody@example.org\r\n\
Action: failed\r\n\
Status: 5.1.1\r\n\
\r\n\
Final-Recipient: rfc822; other@example.org\r\n\
Action: failed\r\n\
Status: 5.1.1\r\n\
\r\n\
Final-Recipient: rfc822; fine@example.org\r\n\
Action: delayed\r\n\
--b\r\n\
Content-Type: message/rfc822-headers\r\n\
\r\n\
From: alice@kutup.dev\r\n\
Message-ID: <sent-1@kutup.dev>\r\n\
--b--\r\n";
        let r = Readable::parse(report);
        assert_eq!(
            r.bounce,
            Some(Bounce {
                failures: 2,
                original_message_id: Some("sent-1@kutup.dev".into())
            })
        );
        assert_eq!(Readable::parse(MESSAGE).bounce, None);
    }

    #[test]
    fn unreadable_mail_still_arrives_empty() {
        assert_eq!(Readable::parse(b""), Readable::default());
    }

    #[test]
    fn pgp_encrypted_bodies_are_recognised() {
        use kutup_crypto::mail_key::{encrypt_armored_signed, generate_address_key};
        let alice = generate_address_key("alice@kutup.dev", 1_790_000_000).unwrap();
        let armored = encrypt_armored_signed(
            &[&alice.public_key],
            &alice.secret_key,
            b"Content-Type: text/plain\r\n\r\nhi\r\n",
            1_790_000_100,
        )
        .unwrap()
        .replace('\n', "\r\n");
        let pgp_mime = format!(
            "From: dave@example.org\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\r\n\
             --b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
             --b\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\n{armored}\r\n--b--\r\n"
        );
        assert!(Readable::parse(pgp_mime.as_bytes()).pgp_encrypted);
        // The wrong protocol, or plaintext labelled as encrypted, is not.
        let wrong = pgp_mime.replace("application/pgp-encrypted\"", "application/pkcs7-mime\"");
        assert!(!Readable::parse(wrong.as_bytes()).pgp_encrypted);
        let fake = pgp_mime.replace(
            &armored,
            "-----BEGIN PGP MESSAGE-----\r\n\r\nnot really\r\n-----END PGP MESSAGE-----",
        );
        assert!(!Readable::parse(fake.as_bytes()).pgp_encrypted);

        // Inline PGP: the whole text body is the message.
        let inline = format!("From: dave@example.org\r\nSubject: x\r\n\r\n{armored}\r\n");
        assert!(Readable::parse(inline.as_bytes()).pgp_encrypted);
        let quoted = format!("From: dave@example.org\r\n\r\nSee below\r\n{armored}\r\n");
        assert!(!Readable::parse(quoted.as_bytes()).pgp_encrypted);
        assert!(!Readable::parse(b"From: a@b.org\r\n\r\nplain\r\n").pgp_encrypted);
    }
}
