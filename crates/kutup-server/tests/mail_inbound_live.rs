//! Live e2e for mail from outside (docs/plans/mail.md, C1): SMTP into
//! Stalwart, the RCPT hook, LMTP into the backend, encryption on arrival,
//! storage and the pool. Driven by `scripts/test-mail-inbound.sh`; gated on
//! `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_SMTP` so a normal `cargo test` skips it:
//!   KUTUP_LIVE_SERVER=https://localhost:38443 KUTUP_LIVE_SMTP=127.0.0.1:2525 \
//!     cargo test -p kutup-server --test mail_inbound_live -- --nocapture

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{b64, bearer, register, User};
use kutup_crypto::mail_key::{self, MailKeyEntryV1, MailKeyListV1, DEFAULT_FLAGS};
use reqwest::blocking::Client;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Gives `user` an address key the way the Account app does at sign-in, and
/// returns the address and the secret key.
fn set_up_address(c: &Client, base: &str, user: &User) -> (String, Vec<u8>) {
    let addresses: Value = bearer(c.get(format!("{base}/api/mail/addresses")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let id = addresses[0]["id"].as_str().unwrap().to_string();
    let address = addresses[0]["address"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let key = mail_key::generate_address_key(&address, now).unwrap();
    let envelope =
        mail_key::seal_address_key(&user.master_key, &user.email, &address, &key.secret_key)
            .unwrap();
    let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
    let list = MailKeyListV1 {
        account: address.clone(),
        incarnation_id: hex32(user.identity.incarnation_id()),
        authority_key_id: hex32(user.identity.authority_key_id()),
        address: address.clone(),
        sequence: 1,
        previous_hash: None,
        issued_at: "2026-10-10T12:00:00Z".into(),
        keys: vec![MailKeyEntryV1 {
            fingerprint: key.fingerprint,
            sha256_fingerprint: key.sha256_fingerprint,
            primary: true,
            flags: DEFAULT_FLAGS,
        }],
    }
    .sign(user.identity.authority_signing_key())
    .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/mail/addresses/{id}/keys")),
        &user.token,
    )
    .json(&json!({
        "publicKey": b64(&key.public_key),
        "privateKeyEnvelope": b64(&envelope),
        "keyList": { "data": b64(&list.data), "signature": b64(&list.signature) },
    }))
    .send()
    .unwrap();
    assert!(r.status().is_success(), "add key: {}", r.status());
    (address, key.secret_key.to_vec())
}

/// A minimal SMTP client: each command's final reply code.
struct Smtp {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Smtp {
    fn connect(address: &str) -> Self {
        let stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut smtp = Smtp {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
        };
        assert_eq!(smtp.reply(), 220);
        smtp
    }

    fn reply(&mut self) -> u16 {
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            assert!(line.len() >= 4, "short reply: {line:?}");
            if line.as_bytes()[3] == b' ' {
                return line[..3].parse().unwrap();
            }
        }
    }

    fn command(&mut self, line: &str) -> u16 {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .unwrap();
        self.reply()
    }

    fn data(&mut self, message: &[u8]) -> u16 {
        assert_eq!(self.command("DATA"), 354);
        for line in message.split_inclusive(|b| *b == b'\n') {
            if line.starts_with(b".") {
                self.writer.write_all(b".").unwrap();
            }
            self.writer.write_all(line).unwrap();
        }
        self.writer.write_all(b".\r\n").unwrap();
        self.reply()
    }
}

fn messages(c: &Client, base: &str, token: &str) -> Vec<Value> {
    // Stalwart's spam filter may file a test sender under Spam (no SPF or
    // DKIM); both folders are the account's mail.
    ["inbox", "spam"]
        .iter()
        .flat_map(|folder| {
            let page: Value = bearer(
                c.get(format!("{base}/api/mail/messages?folder={folder}")),
                token,
            )
            .send()
            .unwrap()
            .json()
            .unwrap();
            page["messages"].as_array().unwrap().clone()
        })
        .collect()
}

#[test]
fn mail_from_outside_arrives_encrypted() {
    let (Ok(base), Ok(smtp_address)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_SMTP"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_SMTP not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let used_before = common::used(&c, &base, &user.token);
    let (address, secret_key) = set_up_address(&c, &base, &user);
    let (local, domain) = address.split_once('@').unwrap();
    let tag = uuid::Uuid::new_v4().simple().to_string();

    let first = format!(
        "From: =?UTF-8?Q?=C3=87a=C4=9Flar?= <caglar@example.net>\r\n\
To: {address}\r\n\
Subject: =?UTF-8?B?w4dhcsWfYW1iYSB0b3BsYW50xLFzxLE=?=\r\n\
Date: Fri, 09 Oct 2026 10:00:00 +0000\r\n\
Message-ID: <first-{tag}@example.net>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
G\u{fc}nayd\u{131}n,\r\n\
.a line that starts with a dot\r\n"
    );
    let reply = format!(
        "From: caglar@example.net\r\nTo: {address}\r\nSubject: Re: hi\r\n\
Message-ID: <reply-{tag}@example.net>\r\nIn-Reply-To: <first-{tag}@example.net>\r\n\r\nok\r\n"
    );

    let mut smtp = Smtp::connect(&smtp_address);
    assert_eq!(smtp.command("EHLO sender.example.net"), 250);
    assert_eq!(smtp.command("MAIL FROM:<caglar@example.net>"), 250);
    // Case and a +tag do not matter; an unknown address is refused at RCPT
    // by the hook, before any data is sent.
    assert_eq!(
        smtp.command(&format!(
            "RCPT TO:<{}+news@{}>",
            local.to_uppercase(),
            domain
        )),
        250
    );
    assert_eq!(
        smtp.command(&format!("RCPT TO:<nobody-{tag}@{domain}>")),
        550
    );
    assert_eq!(smtp.data(first.as_bytes()), 250);
    // The same message again (a mailing-list copy) is accepted, not stored.
    assert_eq!(smtp.command("MAIL FROM:<caglar@example.net>"), 250);
    assert_eq!(smtp.command(&format!("RCPT TO:<{address}>")), 250);
    assert_eq!(smtp.data(first.as_bytes()), 250);
    assert_eq!(smtp.command("MAIL FROM:<caglar@example.net>"), 250);
    assert_eq!(smtp.command(&format!("RCPT TO:<{address}>")), 250);
    assert_eq!(smtp.data(reply.as_bytes()), 250);
    assert_eq!(smtp.command("QUIT"), 221);

    // Stalwart queues, then delivers over LMTP.
    let deadline = Instant::now() + Duration::from_secs(90);
    while messages(&c, &base, &user.token).len() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
    }
    // A moment more, so a wrongly stored duplicate would show.
    std::thread::sleep(Duration::from_secs(3));
    let got = messages(&c, &base, &user.token);
    assert_eq!(
        got.len(),
        2,
        "two messages, the duplicate not stored: {got:?}"
    );
    let first_row = got
        .iter()
        .find(|m| m["messageId"] == format!("first-{tag}@example.net"))
        .expect("first message");
    let reply_row = got
        .iter()
        .find(|m| m["messageId"] == format!("reply-{tag}@example.net"))
        .expect("reply");
    assert_eq!(first_row["subject"], "Çarşamba toplantısı");
    assert_eq!(first_row["from"]["address"], "caglar@example.net");
    assert_eq!(first_row["from"]["name"], "Çağlar");
    assert_eq!(first_row["to"][0]["address"], address.as_str());
    assert_eq!(first_row["protection"], "zero_access");
    assert_eq!(first_row["seen"], false);
    assert_eq!(
        reply_row["threadId"], first_row["threadId"],
        "a reply joins its parent's thread"
    );

    // What is stored opens with the address key and holds the message as
    // sent, byte for byte, below the headers Stalwart prepended.
    let id = first_row["id"].as_str().unwrap();
    let stored = bearer(
        c.get(format!("{base}/api/mail/messages/{id}/content")),
        &user.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(stored.len() as i64, first_row["size"].as_i64().unwrap());
    for plain in [
        &b"a line that starts with a dot"[..],
        format!("first-{tag}").as_bytes(),
    ] {
        assert!(
            !stored.windows(plain.len()).any(|w| w == plain),
            "stored bytes hold no plaintext"
        );
    }
    let opened = mail_key::decrypt(&secret_key, &stored, None).unwrap();
    let tail = &opened.data[opened.data.len().saturating_sub(first.len())..];
    assert!(
        tail == first.as_bytes(),
        "decrypted message ends with what was sent:\n--- sent\n{first}\n--- stored\n{}",
        String::from_utf8_lossy(&opened.data)
    );

    // Another account cannot read it.
    let other = register(&c, &base);
    let r = bearer(
        c.get(format!("{base}/api/mail/messages/{id}/content")),
        &other.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 404);

    // Mail is charged to the account's one pool and shown as Mail.
    let storage: Value = bearer(c.get(format!("{base}/api/user/storage")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let sizes: i64 = got.iter().map(|m| m["size"].as_i64().unwrap()).sum();
    assert_eq!(storage["mail"]["count"], 2);
    assert_eq!(storage["mail"]["bytes"].as_i64().unwrap(), sizes);
    assert!(common::used(&c, &base, &user.token) >= used_before + sizes);

    // With an administrator: a full pool defers mail (452, the sender keeps
    // trying), a disabled account refuses it, and deleting the account
    // deletes its mail (the gate script then checks rows and objects).
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN not set; skipping the administrator checks");
        return;
    };
    let mut parts = admin.splitn(3, ':');
    let (email, username, password) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let admin = common::admin_token(&c, &base, email, password, username);
    let update = |body: Value| {
        let r = bearer(c.put(format!("{base}/api/admin/users/{}", user.id)), &admin)
            .json(&body)
            .send()
            .unwrap();
        assert!(r.status().is_success(), "admin update: {}", r.status());
    };
    let rcpt = |expected: u16| {
        let mut smtp = Smtp::connect(&smtp_address);
        assert_eq!(smtp.command("EHLO sender.example.net"), 250);
        assert_eq!(smtp.command("MAIL FROM:<caglar@example.net>"), 250);
        assert_eq!(smtp.command(&format!("RCPT TO:<{address}>")), expected);
        assert_eq!(smtp.command("QUIT"), 221);
    };
    let used_now = common::used(&c, &base, &user.token);
    update(json!({ "storageQuotaBytes": used_now }));
    rcpt(452);
    update(json!({ "storageQuotaBytes": 10_i64 << 30, "isActive": false }));
    rcpt(550);
    update(json!({ "isActive": true }));
    rcpt(250);
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", user.id)),
        &admin,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 204, "delete account");
    rcpt(550);
}
