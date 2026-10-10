//! Hands mail for outside recipients to Stalwart's submission port
//! (docs/plans/mail.md, C2): an authenticated SMTP session on the internal
//! network. Stalwart signs it with DKIM, queues it and delivers it over
//! IPv4; bounces come back as ordinary inbound mail.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Why a submission failed.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// Stalwart refused (a 4xx or 5xx reply), for one recipient or all.
    #[error("refused{}: {code} {text}", recipient.as_ref().map(|r| format!(" for {r}")).unwrap_or_default())]
    Refused {
        code: u16,
        text: String,
        recipient: Option<String>,
    },
    /// Stalwart could not be reached or the session broke.
    #[error("submission unavailable: {0}")]
    Unavailable(String),
}

impl From<std::io::Error> for SubmitError {
    fn from(error: std::io::Error) -> Self {
        SubmitError::Unavailable(error.to_string())
    }
}

/// One message to submit.
pub struct Envelope<'a> {
    pub from: &'a str,
    pub recipients: &'a [String],
    pub message: &'a [u8],
}

/// Submits `envelope` to `address` as `username`.
pub async fn submit(
    address: &str,
    username: &str,
    password: &str,
    envelope: Envelope<'_>,
) -> Result<(), SubmitError> {
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .map_err(|_| SubmitError::Unavailable("connect timed out".into()))??;
    converse(
        tokio::io::BufReader::new(stream),
        username,
        password,
        envelope,
    )
    .await
}

async fn converse<S>(
    mut stream: S,
    username: &str,
    password: &str,
    envelope: Envelope<'_>,
) -> Result<(), SubmitError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    expect(&mut stream, 220, None).await?;
    command(&mut stream, "EHLO kutup", 250, None).await?;
    let credentials = STANDARD.encode(format!("\0{username}\0{password}"));
    command(&mut stream, &format!("AUTH PLAIN {credentials}"), 235, None).await?;
    command(
        &mut stream,
        &format!(
            "MAIL FROM:<{}> SIZE={}",
            envelope.from,
            envelope.message.len()
        ),
        250,
        None,
    )
    .await?;
    for recipient in envelope.recipients {
        command(
            &mut stream,
            &format!("RCPT TO:<{recipient}>"),
            250,
            Some(recipient),
        )
        .await?;
    }
    command(&mut stream, "DATA", 354, None).await?;
    // Dot-stuffing (RFC 5321 4.5.2) and a final CRLF before the dot.
    let mut at_line_start = true;
    let mut data = Vec::with_capacity(envelope.message.len() + 64);
    for &byte in envelope.message {
        if at_line_start && byte == b'.' {
            data.push(b'.');
        }
        data.push(byte);
        at_line_start = byte == b'\n';
    }
    if !data.ends_with(b"\r\n") {
        data.extend_from_slice(b"\r\n");
    }
    data.extend_from_slice(b".\r\n");
    stream.write_all(&data).await?;
    stream.flush().await?;
    expect(&mut stream, 250, None).await?;
    // The message is queued; a failed goodbye changes nothing.
    let _ = command(&mut stream, "QUIT", 221, None).await;
    Ok(())
}

async fn command<S>(
    stream: &mut S,
    line: &str,
    expected: u16,
    recipient: Option<&String>,
) -> Result<(), SubmitError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    stream.write_all(format!("{line}\r\n").as_bytes()).await?;
    stream.flush().await?;
    expect(stream, expected, recipient).await
}

/// Reads one (possibly multi-line) reply and checks its code.
async fn expect<S>(
    stream: &mut S,
    expected: u16,
    recipient: Option<&String>,
) -> Result<(), SubmitError>
where
    S: AsyncBufRead + Unpin,
{
    let (code, text) = loop {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(120), stream.read_line(&mut line))
            .await
            .map_err(|_| SubmitError::Unavailable("reply timed out".into()))??;
        if read == 0 {
            return Err(SubmitError::Unavailable("connection closed".into()));
        }
        let line = line.trim_end();
        let code = line
            .get(..3)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| SubmitError::Unavailable("malformed reply".into()))?;
        if line.as_bytes().get(3) != Some(&b'-') {
            break (code, line.get(4..).unwrap_or_default().to_string());
        }
    };
    if code == expected || (expected == 250 && code == 251) {
        Ok(())
    } else {
        Err(SubmitError::Refused {
            code,
            text,
            recipient: recipient.cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    /// A server that answers each command (and the whole data block) with
    /// the next canned reply, and returns everything it was sent.
    async fn run(
        replies: &[&str],
        recipients: &[&str],
        message: &[u8],
    ) -> (Result<(), SubmitError>, String) {
        let (client, server) = tokio::io::duplex(1 << 16);
        let script: Vec<String> = replies.iter().map(|r| format!("{r}\r\n")).collect();
        let server = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut read = BufReader::new(read);
            let mut replies = script.into_iter();
            let mut seen = String::new();
            let mut in_data = false;
            write
                .write_all(replies.next().unwrap().as_bytes())
                .await
                .unwrap();
            loop {
                let mut line = String::new();
                if read.read_line(&mut line).await.unwrap() == 0 {
                    return seen;
                }
                seen.push_str(&line);
                if in_data && line != ".\r\n" {
                    continue;
                }
                let Some(reply) = replies.next() else {
                    return seen;
                };
                in_data = !in_data && line.starts_with("DATA") && reply.starts_with("354");
                write.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let owned: Vec<String> = recipients.iter().map(|r| r.to_string()).collect();
        let result = converse(
            BufReader::new(client),
            "kutup@kutup.test",
            "secret",
            Envelope {
                from: "alice@kutup.test",
                recipients: &owned,
                message,
            },
        )
        .await;
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn submits_with_auth_and_dot_stuffing() {
        let (result, seen) = run(
            &[
                "220 hi",
                "250-mail\r\n250 AUTH PLAIN",
                "235 ok",
                "250 ok",
                "250 ok",
                "250 ok",
                "354 go",
                "250 queued",
                "221 bye",
            ],
            &["bob@example.com", "carol@example.org"],
            b"Subject: x\r\n\r\n.dot\r\nend",
        )
        .await;
        result.unwrap();
        assert!(seen.contains("AUTH PLAIN AGt1dHVwQGt1dHVwLnRlc3QAc2VjcmV0\r\n"));
        assert!(seen.contains("MAIL FROM:<alice@kutup.test> SIZE=23\r\n"));
        assert!(seen.contains("RCPT TO:<bob@example.com>\r\nRCPT TO:<carol@example.org>\r\n"));
        assert!(seen.contains("\r\n\r\n..dot\r\nend\r\n.\r\n"));
    }

    #[tokio::test]
    async fn a_refused_recipient_is_named() {
        let (result, _) = run(
            &[
                "220 hi",
                "250 mail",
                "235 ok",
                "250 ok",
                "550 5.1.1 no such user",
            ],
            &["nobody@example.com"],
            b"x\r\n",
        )
        .await;
        match result {
            Err(SubmitError::Refused {
                code, recipient, ..
            }) => {
                assert_eq!(code, 550);
                assert_eq!(recipient.as_deref(), Some("nobody@example.com"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn bad_credentials_refuse_everything() {
        let (result, _) = run(
            &["220 hi", "250 mail", "535 5.7.8 no"],
            &["bob@example.com"],
            b"x\r\n",
        )
        .await;
        assert!(matches!(
            result,
            Err(SubmitError::Refused {
                code: 535,
                recipient: None,
                ..
            })
        ));
    }
}
