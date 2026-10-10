//! The LMTP server (RFC 2033) Stalwart delivers accepted mail to
//! (docs/plans/mail.md). LMTP is SMTP without a queue: after DATA it answers
//! once per accepted recipient, so one recipient's full pool does not fail
//! the others. Only Stalwart talks to it, over the internal network, after
//! AUTH PLAIN with the shared secret.

use std::future::Future;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// A reply line: code, enhanced status and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub status: &'static str,
    pub text: String,
}

impl Reply {
    pub fn new(code: u16, status: &'static str, text: impl Into<String>) -> Self {
        Reply {
            code,
            status,
            text: text.into(),
        }
    }

    fn line(&self) -> String {
        format!("{} {} {}\r\n", self.code, self.status, self.text)
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

/// Where accepted mail goes: checked at RCPT, delivered after DATA.
pub trait Delivery: Send + Sync {
    /// A recipient this server accepts.
    type Recipient: Send + Sync;

    /// Accepts or refuses `address` before the message is sent.
    fn check(&self, address: &str) -> impl Future<Output = Result<Self::Recipient, Reply>> + Send;

    /// Stores `message` for one recipient; the reply goes back as that
    /// recipient's LMTP answer.
    fn deliver(
        &self,
        recipient: &Self::Recipient,
        message: &[u8],
    ) -> impl Future<Output = Reply> + Send;
}

/// The server's fixed parameters.
#[derive(Debug, Clone)]
pub struct Settings {
    pub hostname: String,
    pub secret: String,
    /// Largest message accepted, in bytes.
    pub max_message_bytes: usize,
    pub max_recipients: usize,
    /// How long one command or data line may take to arrive.
    pub timeout: Duration,
}

const MAX_COMMAND_BYTES: usize = 4096;

/// Serves one connection until QUIT, EOF, a timeout or a protocol error.
pub async fn serve<S, D>(stream: S, settings: &Settings, delivery: &D) -> std::io::Result<()>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
    D: Delivery,
{
    let mut session = Session {
        stream,
        settings,
        authenticated: false,
        sender: false,
        recipients: Vec::new(),
    };
    session
        .write(&format!("220 {} LMTP ready\r\n", settings.hostname))
        .await?;
    loop {
        let Some(line) = session.read_line(MAX_COMMAND_BYTES).await? else {
            return Ok(());
        };
        let Ok(line) = std::str::from_utf8(&line) else {
            session
                .reply(&Reply::new(500, "5.5.2", "command is not UTF-8"))
                .await?;
            continue;
        };
        let line = line.trim_end_matches(['\r', '\n']);
        let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
        match verb.to_ascii_uppercase().as_str() {
            "LHLO" if !rest.trim().is_empty() => {
                session.reset();
                session
                    .write(&format!(
                        "250-{}\r\n250-PIPELINING\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-SIZE {}\r\n250 AUTH PLAIN\r\n",
                        settings.hostname, settings.max_message_bytes
                    ))
                    .await?;
            }
            "LHLO" => {
                session
                    .reply(&Reply::new(501, "5.5.4", "LHLO needs a name"))
                    .await?
            }
            "HELO" | "EHLO" => {
                session
                    .reply(&Reply::new(500, "5.5.1", "this is LMTP: use LHLO"))
                    .await?
            }
            "AUTH" => session.auth(rest).await?,
            "MAIL" => session.mail(rest).await?,
            "RCPT" => session.rcpt(rest, delivery).await?,
            "DATA" => session.data(delivery).await?,
            "RSET" => {
                session.reset();
                session.reply(&Reply::new(250, "2.0.0", "reset")).await?;
            }
            "NOOP" => session.reply(&Reply::new(250, "2.0.0", "ok")).await?,
            "VRFY" => {
                session
                    .reply(&Reply::new(252, "2.5.0", "cannot verify, send the mail"))
                    .await?
            }
            "QUIT" => {
                session.reply(&Reply::new(221, "2.0.0", "bye")).await?;
                return Ok(());
            }
            _ => {
                session
                    .reply(&Reply::new(500, "5.5.2", "unknown command"))
                    .await?
            }
        }
    }
}

struct Session<'a, S, R> {
    stream: S,
    settings: &'a Settings,
    authenticated: bool,
    sender: bool,
    recipients: Vec<R>,
}

impl<S, R> Session<'_, S, R>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    fn reset(&mut self) {
        self.sender = false;
        self.recipients.clear();
    }

    async fn write(&mut self, text: &str) -> std::io::Result<()> {
        self.stream.write_all(text.as_bytes()).await?;
        self.stream.flush().await
    }

    async fn reply(&mut self, reply: &Reply) -> std::io::Result<()> {
        self.write(&reply.line()).await
    }

    /// Reads one line, CRLF included, of at most `limit` bytes. `None` at EOF.
    async fn read_line(&mut self, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        let read = tokio::time::timeout(self.settings.timeout, async {
            loop {
                let available = self.stream.fill_buf().await?;
                if available.is_empty() {
                    return Ok::<_, std::io::Error>(());
                }
                let (take, done) = match available.iter().position(|b| *b == b'\n') {
                    Some(end) => (end + 1, true),
                    None => (available.len(), false),
                };
                if line.len() + take > limit {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "line too long",
                    ));
                }
                line.extend_from_slice(&available[..take]);
                self.stream.consume(take);
                if done {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "LMTP client too slow"))?;
        read?;
        Ok((!line.is_empty()).then_some(line))
    }

    async fn auth(&mut self, rest: &str) -> std::io::Result<()> {
        if self.authenticated {
            return self
                .reply(&Reply::new(503, "5.5.1", "already authenticated"))
                .await;
        }
        let mut parts = rest.split_whitespace();
        if !parts
            .next()
            .is_some_and(|m| m.eq_ignore_ascii_case("PLAIN"))
        {
            return self.reply(&Reply::new(504, "5.5.4", "only PLAIN")).await;
        }
        let response = match parts.next() {
            Some(initial) => initial.to_string(),
            None => {
                self.write("334 \r\n").await?;
                let Some(line) = self.read_line(MAX_COMMAND_BYTES).await? else {
                    return Ok(());
                };
                String::from_utf8_lossy(&line).trim().to_string()
            }
        };
        if response == "*" {
            return self
                .reply(&Reply::new(501, "5.0.0", "authentication cancelled"))
                .await;
        }
        // authzid \0 authcid \0 password: only the password matters.
        let password = STANDARD
            .decode(response.as_bytes())
            .ok()
            .and_then(|plain| plain.rsplit(|b| *b == 0).next().map(<[u8]>::to_vec));
        if password.is_some_and(|p| super::secret_matches(&p, self.settings.secret.as_bytes())) {
            self.authenticated = true;
            self.reply(&Reply::new(235, "2.7.0", "authenticated")).await
        } else {
            self.reply(&Reply::new(535, "5.7.8", "authentication failed"))
                .await
        }
    }

    async fn mail(&mut self, rest: &str) -> std::io::Result<()> {
        if !self.authenticated {
            return self
                .reply(&Reply::new(530, "5.7.0", "authenticate first"))
                .await;
        }
        if self.sender {
            return self
                .reply(&Reply::new(503, "5.5.1", "sender already given"))
                .await;
        }
        let Some(params) = strip_path(rest, "FROM:") else {
            return self
                .reply(&Reply::new(501, "5.5.4", "MAIL FROM:<address>"))
                .await;
        };
        let declared = params.split_whitespace().find_map(|p| {
            let (key, value) = p.split_once('=')?;
            key.eq_ignore_ascii_case("SIZE")
                .then(|| value.parse::<usize>().ok())?
        });
        if declared.is_some_and(|size| size > self.settings.max_message_bytes) {
            return self
                .reply(&Reply::new(552, "5.3.4", "message too big"))
                .await;
        }
        self.sender = true;
        self.reply(&Reply::new(250, "2.1.0", "sender ok")).await
    }

    async fn rcpt<D>(&mut self, rest: &str, delivery: &D) -> std::io::Result<()>
    where
        D: Delivery<Recipient = R>,
    {
        if !self.sender {
            return self.reply(&Reply::new(503, "5.5.1", "MAIL first")).await;
        }
        let Some(address) = strip_path(rest, "TO:").and_then(path_address) else {
            return self
                .reply(&Reply::new(501, "5.5.4", "RCPT TO:<address>"))
                .await;
        };
        if self.recipients.len() >= self.settings.max_recipients {
            return self
                .reply(&Reply::new(452, "4.5.3", "too many recipients"))
                .await;
        }
        match delivery.check(&address).await {
            Ok(recipient) => {
                self.recipients.push(recipient);
                self.reply(&Reply::new(250, "2.1.5", "recipient ok")).await
            }
            Err(reply) => self.reply(&reply).await,
        }
    }

    async fn data<D>(&mut self, delivery: &D) -> std::io::Result<()>
    where
        D: Delivery<Recipient = R>,
    {
        if !self.sender {
            return self.reply(&Reply::new(503, "5.5.1", "MAIL first")).await;
        }
        if self.recipients.is_empty() {
            return self
                .reply(&Reply::new(554, "5.5.1", "no valid recipients"))
                .await;
        }
        self.write("354 2.0.0 send the message, end with <CRLF>.<CRLF>\r\n")
            .await?;
        let max = self.settings.max_message_bytes;
        let mut message = Vec::new();
        let mut too_big = false;
        loop {
            // A line longer than the whole limit cannot belong to a message
            // we would take; it ends the connection.
            let Some(line) = self.read_line(max + 2).await? else {
                return Ok(());
            };
            if line == b".\r\n" || line == b".\n" {
                break;
            }
            // Undo dot-stuffing (RFC 5321 4.5.2).
            let line = line.strip_prefix(b".").unwrap_or(&line);
            if message.len() + line.len() > max {
                too_big = true;
                message.clear();
            }
            if !too_big {
                message.extend_from_slice(line);
            }
        }
        // Stalwart writes the message and then "\r\n.\r\n" whatever the
        // message ends with (`write_message` in its outbound client), so the
        // last CRLF is its terminator's, not the message's: dropping it gives
        // back the message byte for byte.
        if message.ends_with(b"\r\n") {
            message.truncate(message.len() - 2);
        }
        let recipients = std::mem::take(&mut self.recipients);
        self.sender = false;
        for recipient in &recipients {
            let reply = if too_big {
                Reply::new(552, "5.3.4", "message too big")
            } else {
                delivery.deliver(recipient, &message).await
            };
            if !reply.is_success() {
                tracing::info!(
                    code = reply.code,
                    status = reply.status,
                    "mail: delivery refused"
                );
            }
            self.reply(&reply).await?;
        }
        Ok(())
    }
}

/// `FROM:<a@b> SIZE=10` → `<a@b> SIZE=10`, case-insensitively.
fn strip_path<'a>(rest: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = rest.trim_start();
    (rest.len() >= prefix.len() && rest[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| rest[prefix.len()..].trim_start())
}

/// The address inside `<…>`, the path's first token.
fn path_address(path: &str) -> Option<String> {
    let inner = path.strip_prefix('<')?;
    let end = inner.find('>')?;
    let address = inner[..end].trim();
    (!address.is_empty()).then(|| address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, BufReader};

    struct Recorder {
        delivered: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl Delivery for Recorder {
        type Recipient = String;

        async fn check(&self, address: &str) -> Result<String, Reply> {
            match address {
                a if a.starts_with("alice") || a.starts_with("full") => Ok(a.to_string()),
                _ => Err(Reply::new(550, "5.1.1", "no such user")),
            }
        }

        async fn deliver(&self, recipient: &String, message: &[u8]) -> Reply {
            if recipient.starts_with("full") {
                return Reply::new(452, "4.2.2", "mailbox full");
            }
            self.delivered
                .lock()
                .unwrap()
                .push((recipient.clone(), message.to_vec()));
            Reply::new(250, "2.0.0", "stored")
        }
    }

    fn settings() -> Settings {
        Settings {
            hostname: "kutup.test".into(),
            secret: "s3cret".into(),
            max_message_bytes: 64,
            max_recipients: 3,
            timeout: Duration::from_secs(5),
        }
    }

    /// Runs a whole pipelined session and returns the server's replies.
    async fn run(input: &str) -> (String, Vec<(String, Vec<u8>)>) {
        let (client, server) = tokio::io::duplex(1 << 16);
        let recorder = Recorder {
            delivered: Mutex::new(Vec::new()),
        };
        let settings = settings();
        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write.write_all(input.as_bytes()).await.unwrap();
        client_write.shutdown().await.unwrap();
        serve(BufReader::new(server), &settings, &recorder)
            .await
            .unwrap();
        let mut out = String::new();
        client_read.read_to_string(&mut out).await.unwrap();
        (out, recorder.delivered.into_inner().unwrap())
    }

    fn codes(out: &str) -> Vec<&str> {
        out.lines()
            .filter(|l| l.len() >= 4 && l.as_bytes()[3] == b' ')
            .map(|l| &l[..3])
            .collect()
    }

    // "\0kutup\0s3cret"
    const AUTH: &str = "AUTH PLAIN AGt1dHVwAHMzY3JldA==\r\n";

    #[tokio::test]
    async fn pipelined_delivery_answers_once_per_recipient() {
        let input = format!(
            "LHLO mta\r\n{AUTH}MAIL FROM:<b@x.org> SIZE=20\r\nRCPT TO:<alice@kutup.test>\r\nRCPT TO:<nobody@kutup.test>\r\nRCPT TO:<full@kutup.test>\r\nDATA\r\nSubject: hi\r\n\r\n..dot\r\n.\r\nQUIT\r\n"
        );
        let (out, delivered) = run(&input).await;
        assert_eq!(
            codes(&out),
            ["220", "250", "235", "250", "250", "550", "250", "354", "250", "452", "221"]
        );
        assert!(out.contains("250 AUTH PLAIN\r\n") && out.contains("250-SIZE 64\r\n"));
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, "alice@kutup.test");
        assert_eq!(
            delivered[0].1, b"Subject: hi\r\n\r\n.dot",
            "dot-stuffing undone, and the CRLF Stalwart puts before the final dot taken off"
        );
    }

    #[tokio::test]
    async fn nothing_happens_without_the_secret() {
        let input = "LHLO mta\r\nMAIL FROM:<b@x.org>\r\nAUTH PLAIN AGt1dHVwAHdyb25n\r\nAUTH LOGIN\r\nQUIT\r\n";
        let (out, delivered) = run(input).await;
        assert_eq!(codes(&out), ["220", "250", "530", "535", "504", "221"]);
        assert!(delivered.is_empty());
    }

    #[tokio::test]
    async fn auth_plain_may_come_on_the_next_line() {
        let input = "LHLO mta\r\nAUTH PLAIN\r\nAGt1dHVwAHMzY3JldA==\r\nQUIT\r\n";
        let (out, _) = run(input).await;
        assert_eq!(codes(&out), ["220", "250", "334", "235", "221"]);
    }

    #[tokio::test]
    async fn order_and_limits_are_enforced() {
        let input = format!(
            "HELO mta\r\nLHLO mta\r\n{AUTH}RCPT TO:<alice@kutup.test>\r\nDATA\r\nMAIL FROM:<b@x.org> SIZE=999\r\nMAIL FROM:<>\r\nMAIL FROM:<>\r\nDATA\r\nRCPT TO:<alice1@k>\r\nRCPT TO:<alice2@k>\r\nRCPT TO:<alice3@k>\r\nRCPT TO:<alice4@k>\r\nRCPT TO:bare@k\r\nRSET\r\nNOOP\r\nFOO\r\nQUIT\r\n"
        );
        let (out, _) = run(&input).await;
        assert_eq!(
            codes(&out),
            [
                "220", "500", "250", "235", "503", "503", "552", "250", "503", "554", "250", "250",
                "250", "452", "501", "250", "250", "500", "221"
            ]
        );
    }

    #[tokio::test]
    async fn an_oversized_message_is_refused_for_every_recipient() {
        let body = "x".repeat(40);
        let input = format!(
            "LHLO mta\r\n{AUTH}MAIL FROM:<b@x.org>\r\nRCPT TO:<alice@k>\r\nRCPT TO:<alice2@k>\r\nDATA\r\n{body}\r\n{body}\r\n.\r\nMAIL FROM:<b@x.org>\r\nQUIT\r\n"
        );
        let (out, delivered) = run(&input).await;
        assert_eq!(
            codes(&out),
            ["220", "250", "235", "250", "250", "250", "354", "552", "552", "250", "221"]
        );
        assert!(delivered.is_empty());
    }

    #[test]
    fn paths_parse() {
        assert_eq!(
            strip_path(" from:<a@b> SIZE=1", "FROM:"),
            Some("<a@b> SIZE=1")
        );
        assert_eq!(path_address("<A@B.org> SIZE=1"), Some("A@B.org".into()));
        assert_eq!(path_address("<>"), None);
        assert_eq!(path_address("a@b"), None);
    }
}
