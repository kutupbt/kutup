//! A send's readable fields (`meta` in `mail-core/api.ts`; the server's
//! `MailMeta`), read from a message a mail app built, as the server reads
//! mail arriving (`kutup-server/src/mail/headers.rs`, the same parser and
//! limits): the subject, the sender's name, To, Cc and the threading ids,
//! and the attached files (not inline images).
//!
//! Bcc is what the SMTP envelope names beyond To and Cc: an app sends Bcc
//! recipients in `RCPT TO` only, never in the message.

use mail_parser::{Address, HeaderValue, MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};

const SUBJECT_CHARS: usize = 1000;
const ADDRESS_CHARS: usize = 320;
const NAME_CHARS: usize = 400;
const ID_CHARS: usize = 998;
const MAX_REFERENCES: usize = 50;
const MAX_ATTACHMENTS: usize = 100;
const ATTACHMENT_NAME_CHARS: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub address: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub name: String,
    #[serde(rename = "type")]
    pub mime_type: String,
    pub size: i64,
}

/// What `POST /api/mail/send`'s `meta` carries of the message itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFields {
    pub subject: String,
    pub from_name: String,
    /// The From address, for the caller to check it is one of the account's.
    pub from_address: Option<String>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachment_count: i32,
    pub attachments: Vec<AttachmentMeta>,
}

/// The message would not parse at all: nothing can be sent from it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the message does not parse")]
pub struct Unparsable;

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn clip(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
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
        .collect()
}

fn message_id(value: &str) -> Option<String> {
    let id = value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    (!id.is_empty() && id.len() <= ID_CHARS && !id.chars().any(char::is_whitespace))
        .then(|| id.to_string())
}

fn ids(value: &HeaderValue<'_>) -> Vec<String> {
    match value {
        HeaderValue::Text(id) => message_id(id).into_iter().collect(),
        HeaderValue::TextList(ids) => ids.iter().filter_map(|id| message_id(id)).collect(),
        _ => Vec::new(),
    }
}

/// The readable fields of `mime`, Bcc from `envelope` (the `RCPT TO`
/// addresses) beyond To and Cc.
pub fn send_fields(mime: &[u8], envelope: &[String]) -> Result<SendFields, Unparsable> {
    let message = MessageParser::default().parse(mime).ok_or(Unparsable)?;
    let from = message.from().and_then(|a| mailboxes(a).into_iter().next());
    let to = message.to().map(mailboxes).unwrap_or_default();
    let cc = message.cc().map(mailboxes).unwrap_or_default();
    let mut bcc: Vec<Mailbox> = Vec::new();
    for address in envelope {
        let address = address.trim().to_lowercase();
        let named = to
            .iter()
            .chain(&cc)
            .chain(&bcc)
            .any(|m| m.address == address);
        if !named && !address.is_empty() {
            bcc.push(Mailbox {
                address,
                name: String::new(),
            });
        }
    }
    let mut references = ids(message.references());
    // The newest references are the nearest ancestors; keep those.
    if references.len() > MAX_REFERENCES {
        references.drain(..references.len() - MAX_REFERENCES);
    }
    let attachments: Vec<AttachmentMeta> = message
        .attachments()
        .filter(|part| !part.content_disposition().is_some_and(|d| d.is_inline()))
        .take(MAX_ATTACHMENTS)
        .map(|part| {
            let mime_type = part
                .content_type()
                .map(|t| match t.subtype() {
                    Some(sub) => format!("{}/{}", t.ctype(), sub),
                    None => t.ctype().to_string(),
                })
                .unwrap_or_else(|| "application/octet-stream".into());
            AttachmentMeta {
                name: clip(
                    single_line(part.attachment_name().unwrap_or("attachment")).trim(),
                    ATTACHMENT_NAME_CHARS,
                ),
                mime_type: clip(single_line(&mime_type).trim(), ATTACHMENT_NAME_CHARS)
                    .to_ascii_lowercase(),
                size: i64::try_from(part.contents().len()).unwrap_or(i64::MAX),
            }
        })
        .collect();
    Ok(SendFields {
        subject: message
            .subject()
            .map(|s| clip(single_line(s).trim(), SUBJECT_CHARS))
            .unwrap_or_default(),
        from_name: from.as_ref().map(|m| m.name.clone()).unwrap_or_default(),
        from_address: from.map(|m| m.address),
        to,
        cc,
        bcc,
        message_id: message.message_id().and_then(message_id),
        in_reply_to: ids(message.in_reply_to()).into_iter().next(),
        references,
        attachment_count: i32::try_from(attachments.len()).unwrap_or(i32::MAX),
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: =?UTF-8?Q?=C3=87a=C4=9Flar_=C3=96zt=C3=BCrk?= <Caglar@Kutup.dev>\r\n\
To: Ada <ada@example.org>, bob@kutup.dev\r\n\
Cc: carol@example.org\r\n\
Subject: =?UTF-8?Q?Toplant=C4=B1?=\r\n\
Message-ID: <m1@kutup.dev>\r\n\
In-Reply-To: <m0@example.org>\r\n\
References: <r1@example.org> <m0@example.org>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n\
--b\r\nContent-Type: application/pdf; name=\"rapor.pdf\"\r\nContent-Disposition: attachment; filename=\"rapor.pdf\"\r\n\r\n%PDF\r\n\
--b--\r\n";

    #[test]
    fn reads_what_a_send_names_with_bcc_from_the_envelope() {
        let envelope = [
            "ADA@example.org",
            "bob@kutup.dev",
            "carol@example.org",
            "dave@example.org",
            "dave@example.org",
        ]
        .map(String::from);
        let fields = send_fields(MESSAGE, &envelope).unwrap();
        assert_eq!(fields.subject, "Toplantı");
        assert_eq!(fields.from_name, "Çağlar Öztürk");
        assert_eq!(fields.from_address.as_deref(), Some("caglar@kutup.dev"));
        assert_eq!(
            fields
                .to
                .iter()
                .map(|m| m.address.as_str())
                .collect::<Vec<_>>(),
            ["ada@example.org", "bob@kutup.dev"]
        );
        assert_eq!(fields.to[0].name, "Ada");
        assert_eq!(fields.cc[0].address, "carol@example.org");
        // Only who the envelope adds, once.
        assert_eq!(fields.bcc.len(), 1);
        assert_eq!(fields.bcc[0].address, "dave@example.org");
        assert_eq!(fields.message_id.as_deref(), Some("m1@kutup.dev"));
        assert_eq!(fields.in_reply_to.as_deref(), Some("m0@example.org"));
        assert_eq!(fields.references, ["r1@example.org", "m0@example.org"]);
        assert_eq!(fields.attachment_count, 1);
        assert_eq!(fields.attachments[0].name, "rapor.pdf");
        assert_eq!(fields.attachments[0].mime_type, "application/pdf");
    }
}
