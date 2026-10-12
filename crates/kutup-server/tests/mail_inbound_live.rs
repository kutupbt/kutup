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

/// An address with its key, as the browser holds it.
struct Address {
    address: String,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

/// Gives `user` an address key the way the Account app does at sign-in.
fn set_up_address(c: &Client, base: &str, user: &User) -> Address {
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
    Address {
        address,
        secret_key: key.secret_key.to_vec(),
        public_key: key.public_key,
    }
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
    let Address {
        address,
        secret_key,
        ..
    } = set_up_address(&c, &base, &user);
    let (local, domain) = address.split_once('@').unwrap();
    let tag = uuid::Uuid::new_v4().simple().to_string();

    let first = format!(
        "From: =?UTF-8?Q?=C3=87a=C4=9Flar?= <caglar@sender.test>\r\n\
To: {address}\r\n\
Subject: =?UTF-8?B?w4dhcsWfYW1iYSB0b3BsYW50xLFzxLE=?=\r\n\
Date: Fri, 09 Oct 2026 10:00:00 +0000\r\n\
Message-ID: <first-{tag}@sender.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
G\u{fc}nayd\u{131}n,\r\n\
.a line that starts with a dot\r\n"
    );
    let reply = format!(
        "From: caglar@sender.test\r\nTo: {address}\r\nSubject: Re: hi\r\n\
Message-ID: <reply-{tag}@sender.test>\r\nIn-Reply-To: <first-{tag}@sender.test>\r\n\r\nok\r\n"
    );

    let mut smtp = Smtp::connect(&smtp_address);
    assert_eq!(smtp.command("EHLO sender.sender.test"), 250);
    assert_eq!(smtp.command("MAIL FROM:<caglar@sender.test>"), 250);
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
    assert_eq!(smtp.command("MAIL FROM:<caglar@sender.test>"), 250);
    assert_eq!(smtp.command(&format!("RCPT TO:<{address}>")), 250);
    assert_eq!(smtp.data(first.as_bytes()), 250);
    assert_eq!(smtp.command("MAIL FROM:<caglar@sender.test>"), 250);
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
        .find(|m| m["messageId"] == format!("first-{tag}@sender.test"))
        .expect("first message");
    let reply_row = got
        .iter()
        .find(|m| m["messageId"] == format!("reply-{tag}@sender.test"))
        .expect("reply");
    assert_eq!(first_row["subject"], "Çarşamba toplantısı");
    assert_eq!(first_row["from"]["address"], "caglar@sender.test");
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
        assert_eq!(smtp.command("EHLO sender.sender.test"), 250);
        assert_eq!(smtp.command("MAIL FROM:<caglar@sender.test>"), 250);
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
    // The gate checks no row or object of this account is left.
    println!("PURGED-USER {}", user.id);
}

/// One multipart send or draft request.
fn form(parts: Vec<(&str, Vec<u8>)>) -> reqwest::blocking::multipart::Form {
    parts.into_iter().fold(
        reqwest::blocking::multipart::Form::new(),
        |form, (name, bytes)| {
            form.part(
                name.to_string(),
                reqwest::blocking::multipart::Part::bytes(bytes).file_name(name.to_string()),
            )
        },
    )
}

fn folder(c: &Client, base: &str, token: &str, name: &str) -> Vec<Value> {
    let page: Value = bearer(
        c.get(format!("{base}/api/mail/messages?folder={name}")),
        token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    page["messages"].as_array().unwrap().clone()
}

#[test]
fn mail_between_kutup_users_and_outside() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice_user = register(&c, &base);
    let bob_user = register(&c, &base);
    let alice = set_up_address(&c, &base, &alice_user);
    let bob = set_up_address(&c, &base, &bob_user);
    let domain = alice.address.split_once('@').unwrap().1.to_string();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let message_id = format!("{tag}@{domain}");
    // The message as the browser builds it: no Bcc header.
    let mime = format!(
        "From: Alice <{}>\r\nTo: Bob <{}>, dave@outside.test\r\nSubject: =?UTF-8?Q?=C3=96zel?=\r\n\
Message-ID: <{message_id}>\r\nDate: Sat, 10 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\nSadece Bob ve Dave okusun.\r\n",
        alice.address, bob.address
    );
    let split = mail_key::encrypt_split(
        &[&alice.public_key, &bob.public_key],
        &alice.secret_key,
        mime.as_bytes(),
    )
    .unwrap();
    let meta = |key_packets: Value, extra: Value| -> Vec<u8> {
        let mut meta = json!({
            "subject": "Özel",
            "fromName": "Alice",
            "to": [{ "address": bob.address, "name": "Bob" }, { "address": "dave@outside.test" }],
            "bcc": [{ "address": "carol@outside.test" }],
            "messageId": message_id,
            "keyPackets": key_packets,
        });
        meta.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::to_vec(&meta).unwrap()
    };
    let packets = json!({ "self": b64(&split.key_packets[0]), bob.address.clone(): b64(&split.key_packets[1]) });
    let send = |meta: Vec<u8>, with_mime: bool| {
        let mut parts = vec![("meta", meta), ("data", split.data_packet.clone())];
        if with_mime {
            parts.push(("mime", mime.as_bytes().to_vec()));
        }
        bearer(c.post(format!("{base}/api/mail/send")), &alice_user.token)
            .multipart(form(parts))
            .send()
            .unwrap()
    };

    // A key packet for the wrong key, an unknown Kutup address and missing
    // plaintext for outside recipients are refused before anything is sent.
    let swapped = json!({ "self": b64(&split.key_packets[0]), bob.address.clone(): b64(&split.key_packets[0]) });
    let r = send(meta(swapped, json!({})), true);
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<Value>().unwrap()["code"], "keyChanged");
    let r = send(
        meta(
            packets.clone(),
            json!({ "cc": [{ "address": format!("nobody-{tag}@{domain}") }] }),
        ),
        true,
    );
    assert_eq!(r.status(), 422);
    assert_eq!(r.json::<Value>().unwrap()["code"], "unknownRecipient");
    assert_eq!(send(meta(packets.clone(), json!({})), false).status(), 400);

    let r = send(meta(packets.clone(), json!({})), true);
    assert_eq!(r.status(), 200, "send: {}", r.text().unwrap_or_default());
    let sent: Value = send_result(r);
    let statuses: Vec<(String, String)> = sent["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["address"].as_str().unwrap().into(),
                r["status"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(statuses.contains(&(bob.address.clone(), "delivered".into())));
    assert!(statuses.contains(&("dave@outside.test".into(), "sent".into())));
    assert!(statuses.contains(&("carol@outside.test".into(), "sent".into())));
    assert_eq!(sent["message"]["folder"], "sent");
    assert_eq!(sent["message"]["bcc"][0]["address"], "carol@outside.test");
    assert_eq!(sent["message"]["protection"], "zero_access");

    // Bob's copy: in his inbox, end to end, opening with his key and signed
    // by Alice, with no Bcc anywhere.
    let inbox = folder(&c, &base, &bob_user.token, "inbox");
    let row = inbox
        .iter()
        .find(|m| m["messageId"] == message_id.as_str())
        .expect("delivered to Bob");
    assert_eq!(row["protection"], "end_to_end");
    assert_eq!(row["from"]["address"], alice.address.as_str());
    assert_eq!(row["subject"], "Özel");
    assert_eq!(row["bcc"], json!([]));
    let id = row["id"].as_str().unwrap();
    let copy = bearer(
        c.get(format!("{base}/api/mail/messages/{id}/content")),
        &bob_user.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    assert!(
        !copy.windows(8).any(|w| w == b"carol@ou"),
        "no Bcc in Bob's copy"
    );
    let opened = mail_key::decrypt(&bob.secret_key, &copy, Some(&alice.public_key)).unwrap();
    assert_eq!(&*opened.data, mime.as_bytes());
    assert!(opened.signed && opened.verified);
    // Alice's own copy opens with her key.
    let own = sent["message"]["id"].as_str().unwrap();
    let copy = bearer(
        c.get(format!("{base}/api/mail/messages/{own}/content")),
        &alice_user.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(
        &*mail_key::decrypt(&alice.secret_key, &copy, None)
            .unwrap()
            .data,
        mime.as_bytes()
    );

    // Bob answers: the reply joins the thread on both sides.
    let reply_id = format!("re-{tag}@{domain}");
    let reply_mime = format!(
        "From: {}\r\nTo: {}\r\nSubject: Re: Özel\r\nMessage-ID: <{reply_id}>\r\nIn-Reply-To: <{message_id}>\r\n\r\nTamam.\r\n",
        bob.address, alice.address
    );
    let reply = mail_key::encrypt_split(
        &[&bob.public_key, &alice.public_key],
        &bob.secret_key,
        reply_mime.as_bytes(),
    )
    .unwrap();
    let r = bearer(c.post(format!("{base}/api/mail/send")), &bob_user.token)
        .multipart(form(vec![
            (
                "meta",
                serde_json::to_vec(&json!({
                    "subject": "Re: Özel",
                    "to": [{ "address": alice.address }],
                    "messageId": reply_id,
                    "inReplyTo": message_id,
                    "references": [message_id],
                    "threadId": row["threadId"],
                    "keyPackets": { "self": b64(&reply.key_packets[0]), alice.address.clone(): b64(&reply.key_packets[1]) },
                }))
                .unwrap(),
            ),
            ("data", reply.data_packet.clone()),
        ]))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200, "reply: {}", r.text().unwrap_or_default());
    let reply_row = send_result(r)["message"].clone();
    assert_eq!(reply_row["threadId"], row["threadId"]);
    assert_eq!(reply_row["protection"], "end_to_end");
    let thread: Value = bearer(
        c.get(format!(
            "{base}/api/mail/threads/{own_thread}",
            own_thread = sent["message"]["threadId"].as_str().unwrap()
        )),
        &alice_user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(
        thread.as_array().unwrap().len(),
        2,
        "Alice's thread: her sent copy and Bob's reply"
    );

    // Filing: read, star, archive; counts follow; Trash, then gone for good
    // with its storage refunded.
    let patch = |body: Value| {
        let r = bearer(
            c.patch(format!("{base}/api/mail/messages")),
            &bob_user.token,
        )
        .json(&body)
        .send()
        .unwrap();
        assert_eq!(r.status(), 200);
        r.json::<Value>().unwrap()["updated"].as_u64().unwrap()
    };
    let counts = |token: &str| -> Value {
        bearer(c.get(format!("{base}/api/mail/counts")), token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let unread = |counts: &Value, name: &str| {
        counts
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["folder"] == name)
            .map(|f| f["unread"].as_i64().unwrap())
            .unwrap_or(0)
    };
    assert_eq!(unread(&counts(&bob_user.token), "inbox"), 1);
    assert_eq!(
        patch(json!({ "ids": [id], "seen": true, "starred": true })),
        1
    );
    assert_eq!(unread(&counts(&bob_user.token), "inbox"), 0);
    assert_eq!(folder(&c, &base, &bob_user.token, "starred").len(), 1);
    assert_eq!(
        patch(json!({ "ids": [id], "folder": "sent" })),
        0,
        "received mail cannot go to Sent"
    );
    assert_eq!(patch(json!({ "ids": [id], "folder": "archive" })), 1);
    let found: Value = bearer(
        c.get(format!("{base}/api/mail/messages?folder=all&q=%C3%B6zel")),
        &bob_user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert!(found["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["id"] == id));
    let delete = |ids: Value| -> u64 {
        let r = bearer(
            c.post(format!("{base}/api/mail/messages/delete")),
            &bob_user.token,
        )
        .json(&json!({ "ids": ids }))
        .send()
        .unwrap();
        r.json::<Value>().unwrap()["updated"].as_u64().unwrap()
    };
    assert_eq!(
        delete(json!([id])),
        0,
        "only Trash, Spam and Drafts delete for good"
    );
    let used = common::used(&c, &base, &bob_user.token);
    assert_eq!(patch(json!({ "ids": [id], "folder": "trash" })), 1);
    assert_eq!(delete(json!([id])), 1);
    assert!(common::used(&c, &base, &bob_user.token) < used);

    // Drafts: text saved and replaced, attachments uploaded once each.
    let encrypt_own = |bytes: &[u8]| {
        let split =
            mail_key::encrypt_split(&[&alice.public_key], &alice.secret_key, bytes).unwrap();
        [split.key_packets[0].as_slice(), &split.data_packet].concat()
    };
    let draft_meta = |subject: &str| {
        serde_json::to_vec(&json!({ "subject": subject, "to": [{ "address": bob.address }], "messageId": format!("d-{tag}@{domain}") })).unwrap()
    };
    let r = bearer(c.post(format!("{base}/api/mail/drafts")), &alice_user.token)
        .multipart(form(vec![
            ("meta", draft_meta("Taslak")),
            ("body", encrypt_own(b"draft one")),
        ]))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200, "draft: {}", r.text().unwrap_or_default());
    let draft: Value = r.json().unwrap();
    let draft_id = draft["id"].as_str().unwrap().to_string();
    assert_eq!(draft["folder"], "drafts");
    // Not encrypted to her own key: refused.
    let r = bearer(
        c.put(format!("{base}/api/mail/drafts/{draft_id}")),
        &alice_user.token,
    )
    .multipart(form(vec![
        ("meta", draft_meta("x")),
        ("body", b"plain".to_vec()),
    ]))
    .send()
    .unwrap();
    assert_eq!(r.status(), 400);
    let r = bearer(
        c.put(format!("{base}/api/mail/drafts/{draft_id}")),
        &alice_user.token,
    )
    .multipart(form(vec![
        ("meta", draft_meta("Taslak 2")),
        ("body", encrypt_own(b"draft two")),
    ]))
    .send()
    .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["subject"], "Taslak 2");
    let part = encrypt_own(b"Content-Type: text/plain; name=a.txt\r\n\r\nek\r\n");
    let r = bearer(
        c.post(format!("{base}/api/mail/drafts/{draft_id}/attachments")),
        &alice_user.token,
    )
    .multipart(form(vec![("part", part.clone())]))
    .send()
    .unwrap();
    assert_eq!(r.status(), 200);
    let attachment = r.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let listed: Value = bearer(
        c.get(format!("{base}/api/mail/drafts/{draft_id}/attachments")),
        &alice_user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(listed[0]["id"], attachment.as_str());
    let fetched = bearer(
        c.get(format!(
            "{base}/api/mail/drafts/{draft_id}/attachments/{attachment}"
        )),
        &alice_user.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(&fetched[..], &part[..]);
    // Deleting the draft takes its attachment with it and frees the space.
    let used = common::used(&c, &base, &alice_user.token);
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/delete")),
        &alice_user.token,
    )
    .json(&json!({ "ids": [draft_id] }))
    .send()
    .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["updated"], 1);
    assert!(common::used(&c, &base, &alice_user.token) < used);
    let r = bearer(
        c.get(format!("{base}/api/mail/drafts/{draft_id}/attachments")),
        &alice_user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 404);
    // The gate checks the sink got the outside copy, DKIM-signed, without Bcc.
    println!("OUTSIDE-MESSAGE-ID {message_id}");
}

fn send_result(response: reqwest::blocking::Response) -> Value {
    response.json().unwrap()
}

/// Sends a plain message from `user` to `to` (outside addresses get the
/// plaintext too), as the browser does.
fn send_plain(
    c: &Client,
    base: &str,
    user: &User,
    from: &Address,
    to: &[String],
    body: &str,
) -> reqwest::blocking::Response {
    let domain = from.address.split_once('@').unwrap().1;
    let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
    let mime = format!(
        "From: {}\r\nTo: {}\r\nSubject: safety\r\nMessage-ID: <{message_id}>\r\n\r\n{body}\r\n",
        from.address,
        to.join(", ")
    );
    let split =
        mail_key::encrypt_split(&[&from.public_key], &from.secret_key, mime.as_bytes()).unwrap();
    let mut parts = vec![
        (
            "meta",
            serde_json::to_vec(&json!({
                "to": to.iter().map(|a| json!({ "address": a })).collect::<Vec<_>>(),
                "subject": "safety",
                "messageId": message_id,
                // Sending to yourself takes your own key packet as a recipient too.
                "keyPackets": if to.contains(&from.address) {
                    json!({ "self": b64(&split.key_packets[0]), from.address.clone(): b64(&split.key_packets[0]) })
                } else {
                    json!({ "self": b64(&split.key_packets[0]) })
                },
            }))
            .unwrap(),
        ),
        ("data", split.data_packet),
    ];
    if to.iter().any(|a| !a.ends_with(&format!("@{domain}"))) {
        parts.push(("mime", mime.into_bytes()));
    }
    bearer(c.post(format!("{base}/api/mail/send")), &user.token)
        .multipart(form(parts))
        .send()
        .unwrap()
}

fn code(response: reqwest::blocking::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let body: Value = response.json().unwrap_or(Value::Null);
    (
        status,
        body["code"].as_str().unwrap_or_default().to_string(),
    )
}

#[test]
fn sending_safety() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let mut parts = admin.splitn(3, ':');
    let (email, username, password) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let admin = common::admin_token(&c, &base, email, password, username);
    let status = |user: &User| -> Value {
        bearer(c.get(format!("{base}/api/mail/sending")), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };

    // A new account: 50 outside recipients a day.
    let user = register(&c, &base);
    let me = set_up_address(&c, &base, &user);
    let now = status(&user);
    assert_eq!(now["newAccount"], true);
    assert_eq!(now["perDay"], 50);
    let many: Vec<String> = (0..51).map(|i| format!("r{i}@outside.test")).collect();
    assert_eq!(
        code(send_plain(&c, &base, &user, &me, &many, "too many")),
        (429, "sendLimit".into())
    );
    let r = send_plain(&c, &base, &user, &me, &["one@outside.test".into()], "hello");
    assert_eq!(r.status(), 200, "send: {}", r.text().unwrap_or_default());
    assert_eq!(status(&user)["sentDay"], 1);

    // Paused by an administrator: nothing goes outside, Kutup mail still flows.
    let update = |target: &User, body: Value| {
        let r = bearer(
            c.put(format!("{base}/api/admin/users/{}/mail-sending", target.id)),
            &admin,
        )
        .json(&body)
        .send()
        .unwrap();
        assert_eq!(r.status(), 204, "admin update");
    };
    update(&user, json!({ "paused": true }));
    assert_eq!(status(&user)["paused"], "admin");
    assert_eq!(
        code(send_plain(
            &c,
            &base,
            &user,
            &me,
            &["two@outside.test".into()],
            "paused"
        )),
        (403, "sendingPaused".into())
    );
    assert_eq!(
        send_plain(
            &c,
            &base,
            &user,
            &me,
            std::slice::from_ref(&me.address),
            "to myself"
        )
        .status(),
        200
    );
    update(
        &user,
        json!({ "paused": false, "perDay": 1000, "perHour": 1000 }),
    );
    assert_eq!(status(&user)["paused"], Value::Null);
    assert_eq!(status(&user)["perDay"], 1000);

    // Ten recipients that do not exist: Stalwart's report comes back and
    // pauses the account for its bounces.
    let bouncer = register(&c, &base);
    let bouncer_address = set_up_address(&c, &base, &bouncer);
    let missing: Vec<String> = (0..10).map(|i| format!("gone{i}@bounce.test")).collect();
    assert_eq!(
        send_plain(&c, &base, &bouncer, &bouncer_address, &missing, "hello").status(),
        200
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    while status(&bouncer)["paused"] != "bounces" && Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
    }
    assert_eq!(status(&bouncer)["paused"], "bounces");
    // The administrator sees it, paused and flagged, with its bounces.
    let senders: Value = bearer(
        c.get(format!("{base}/api/admin/mail/senders?attention=true")),
        &admin,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let row = senders
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["userId"] == bouncer.id.as_str())
        .expect("paused sender listed");
    assert_eq!(row["pausedReason"], "bounces");
    assert_eq!(row["flagReason"], "bounces");
    assert!(row["bouncesWeek"].as_i64().unwrap() >= 10);
    assert_eq!(row["sentWeek"], 10);
    // Resuming clears the pause; the flag stays until cleared.
    update(&bouncer, json!({ "paused": false }));
    assert_eq!(status(&bouncer)["paused"], Value::Null);

    // Role addresses: nobody may register them, and postmaster@ reaches an
    // administrator (here one with an address key).
    let reserved = c
        .post(format!("{base}/api/auth/register"))
        .json(&json!({ "email": "postmaster@example.com", "username": "postmaster" }))
        .send()
        .unwrap();
    assert_eq!(reserved.status(), 400);
    let Ok(smtp_address) = std::env::var("KUTUP_LIVE_SMTP") else {
        return;
    };
    let r = bearer(c.put(format!("{base}/api/admin/users/{}", user.id)), &admin)
        .json(&json!({ "isAdmin": true }))
        .send()
        .unwrap();
    assert!(r.status().is_success());
    let domain = me.address.split_once('@').unwrap().1.to_string();
    let mut smtp = Smtp::connect(&smtp_address);
    assert_eq!(smtp.command("EHLO reporter.sender.test"), 250);
    assert_eq!(smtp.command("MAIL FROM:<reporter@sender.test>"), 250);
    assert_eq!(smtp.command(&format!("RCPT TO:<postmaster@{domain}>")), 250);
    assert_eq!(smtp.command("QUIT"), 221);
}

/// GnuPG in the gate's home for Dave, the outside correspondent
/// (scripts/test-mail-inbound.sh made his key and serves it by WKD).
fn gpg(home: &str, args: &[&str], input: &[u8]) -> (bool, Vec<u8>, String) {
    let mut child = std::process::Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(["--batch", "--yes", "--quiet", "--trust-model", "always"])
        .args(["--pinentry-mode", "loopback", "--passphrase", ""])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("gpg");
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// RFC 3156 `multipart/encrypted` around `armored`.
fn pgp_mime(headers: &str, armored: &str) -> Vec<u8> {
    format!(
        "{headers}MIME-Version: 1.0\r\n\
Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"pgp\"\r\n\r\n\
--pgp\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n\
--pgp\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\n{}\r\n--pgp--\r\n",
        armored
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .trim_end()
    )
    .into_bytes()
}

#[test]
fn pgp_with_a_gnupg_correspondent() {
    let (Ok(base), Ok(smtp_address), Ok(home)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_SMTP"),
        std::env::var("KUTUP_LIVE_GPG_HOME"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_SMTP / KUTUP_LIVE_GPG_HOME not set; skipping");
        return;
    };
    let dave = "dave@outside.test";
    let c = client();
    let user = register(&c, &base);
    let alice = set_up_address(&c, &base, &user);
    let domain = alice.address.split_once('@').unwrap().1.to_string();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Dave's key is found through his domain's Web Key Directory, the one
    // GnuPG made; an address without a key is not.
    let (_, listing, _) = gpg(&home, &["--with-colons", "--list-keys", dave], b"");
    let fingerprint = String::from_utf8(listing)
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("fpr:::::::::")
                .map(|f| f.trim_end_matches(':').to_lowercase())
        })
        .expect("Dave's fingerprint");
    let found: Value = bearer(
        c.get(format!("{base}/api/mail/keys/outside?email={dave}")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(found["source"], "wkd", "found: {found}");
    assert_eq!(found["fingerprint"], fingerprint.as_str());
    // Every usable key the source served, the newest first (one here).
    assert_eq!(found["keys"].as_array().unwrap().len(), 1, "found: {found}");
    assert_eq!(found["keys"][0]["fingerprint"], fingerprint.as_str());
    let dave_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        found["publicKey"].as_str().unwrap(),
    )
    .unwrap();
    let missing = bearer(
        c.get(format!(
            "{base}/api/mail/keys/outside?email=nobody-{tag}@outside.test"
        )),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(missing.status(), 404);

    // Alice writes to Dave end to end: PGP/MIME, signed inside; her sent
    // copy is end to end. Dave trusts her key for the signature check.
    let (ok, _, err) = gpg(
        &home,
        &["--import"],
        mail_key::armor_public_key(&alice.public_key)
            .unwrap()
            .as_bytes(),
    );
    assert!(ok, "import Alice: {err}");
    let message_id = format!("pgp-{tag}@{domain}");
    let headers = format!(
        "From: Alice <{}>\r\nTo: {dave}\r\nSubject: PGP test\r\nMessage-ID: <{message_id}>\r\n\
Date: Sat, 10 Oct 2026 10:00:00 +0000\r\n",
        alice.address
    );
    let inner = format!("Content-Type: text/plain; charset=utf-8\r\n\r\nGizli PGP {tag}\r\n");
    let armored = mail_key::encrypt_armored_signed(
        &[&dave_key, &alice.public_key],
        &alice.secret_key,
        inner.as_bytes(),
        now,
    )
    .unwrap();
    let package = pgp_mime(&headers, &armored);
    let plain = format!("{headers}\r\nGizli PGP {tag}\r\n");
    let split =
        mail_key::encrypt_split(&[&alice.public_key], &alice.secret_key, plain.as_bytes()).unwrap();
    let send = |pgp: Value, parts: Vec<(&str, Vec<u8>)>| {
        let meta = serde_json::to_vec(&json!({
            "subject": "PGP test",
            "to": [{ "address": dave }],
            "messageId": message_id,
            "keyPackets": { "self": b64(&split.key_packets[0]) },
            "pgp": pgp,
        }))
        .unwrap();
        let mut all = vec![("meta", meta), ("data", split.data_packet.clone())];
        all.extend(parts);
        bearer(c.post(format!("{base}/api/mail/send")), &user.token)
            .multipart(form(all))
            .send()
            .unwrap()
    };
    let recipients = json!([{ "recipients": [dave] }]);
    // Plaintext dressed as PGP/MIME, or plaintext nobody needs, is refused.
    let fake = pgp_mime(
        &headers,
        "-----BEGIN PGP MESSAGE-----\n\nnot encrypted\n-----END PGP MESSAGE-----",
    );
    assert_eq!(send(recipients.clone(), vec![("pgp0", fake)]).status(), 400);
    assert_eq!(
        send(
            recipients.clone(),
            vec![
                ("pgp0", package.clone()),
                ("mime", plain.clone().into_bytes())
            ]
        )
        .status(),
        400
    );
    let r = send(recipients, vec![("pgp0", package)]);
    assert_eq!(r.status(), 200, "send PGP");
    let sent = send_result(r);
    assert_eq!(sent["message"]["protection"], "end_to_end", "sent: {sent}");
    assert_eq!(
        sent["recipients"],
        json!([{ "address": dave, "status": "sent" }])
    );
    // The gate decrypts what reached the sink with Dave's GnuPG.
    println!("PGP-MESSAGE-ID {message_id}");
    println!("PGP-MARKER Gizli PGP {tag}");

    // Dave writes back with GnuPG, signed and encrypted to Alice's key, over
    // SMTP: it is end to end on arrival and opens twice in the browser.
    let (ok, encrypted, err) = gpg(
        &home,
        &[
            "--armor",
            "--sign",
            "--encrypt",
            "-r",
            &alice.address,
            "-u",
            dave,
        ],
        format!("Content-Type: text/plain; charset=utf-8\r\n\r\nReply {tag}\r\n").as_bytes(),
    );
    assert!(ok, "Dave encrypts: {err}");
    let reply = pgp_mime(
        &format!(
            "From: Dave <{dave}>\r\nTo: {}\r\nSubject: Re: PGP test\r\nMessage-ID: <reply-{tag}@outside.test>\r\n\
In-Reply-To: <{message_id}>\r\nDate: Sat, 10 Oct 2026 10:05:00 +0000\r\n",
            alice.address
        ),
        &String::from_utf8(encrypted).unwrap(),
    );
    let mut smtp = Smtp::connect(&smtp_address);
    assert_eq!(smtp.command("EHLO mx.outside.test"), 250);
    assert_eq!(smtp.command(&format!("MAIL FROM:<{dave}>")), 250);
    assert_eq!(smtp.command(&format!("RCPT TO:<{}>", alice.address)), 250);
    assert_eq!(smtp.data(&reply), 250);
    assert_eq!(smtp.command("QUIT"), 221);
    let deadline = Instant::now() + Duration::from_secs(90);
    let row = loop {
        if let Some(row) = messages(&c, &base, &user.token)
            .into_iter()
            .find(|m| m["messageId"] == format!("reply-{tag}@outside.test"))
        {
            break row;
        }
        assert!(Instant::now() < deadline, "Dave's reply never arrived");
        std::thread::sleep(Duration::from_secs(1));
    };
    assert_eq!(row["protection"], "end_to_end", "reply: {row}");
    let stored = bearer(
        c.get(format!(
            "{base}/api/mail/messages/{}/content",
            row["id"].as_str().unwrap()
        )),
        &user.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    let outer = mail_key::decrypt(&alice.secret_key, &stored, None).unwrap();
    let outer = String::from_utf8(outer.data.to_vec()).unwrap();
    let start = outer
        .find("-----BEGIN PGP MESSAGE-----")
        .expect("armored part");
    let end = outer
        .find("-----END PGP MESSAGE-----")
        .expect("armored end")
        + "-----END PGP MESSAGE-----".len();
    let opened = mail_key::decrypt(
        &alice.secret_key,
        &outer.as_bytes()[start..end],
        Some(&dave_key),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&opened.data).contains(&format!("Reply {tag}")));
    assert!(
        opened.signed && opened.verified,
        "Dave's signature verifies"
    );
}

/// The address's current key list, verified.
fn current_list(c: &Client, base: &str, user: &User) -> (String, mail_key::SignedMailKeyListV1) {
    let addresses: Value = bearer(c.get(format!("{base}/api/mail/addresses")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let decode = |field: &str| {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            addresses[0]["keyList"][field].as_str().unwrap(),
        )
        .unwrap()
    };
    let signed = mail_key::SignedMailKeyListV1::verify(
        &decode("data"),
        &decode("signature"),
        &user.identity.authority_public_key(),
    )
    .unwrap();
    (addresses[0]["id"].as_str().unwrap().to_string(), signed)
}

/// The next list after `previous`, with `keys`, signed by the account.
fn next_list(
    user: &User,
    previous: &mail_key::SignedMailKeyListV1,
    keys: Vec<MailKeyEntryV1>,
) -> Value {
    let mut keys = keys;
    keys.sort_by_key(|key| key.fingerprint);
    let list = MailKeyListV1 {
        sequence: previous.list.sequence + 1,
        previous_hash: Some(previous.hash()),
        issued_at: "2026-10-10T13:00:00Z".into(),
        keys,
        ..previous.list.clone()
    }
    .sign(user.identity.authority_signing_key())
    .unwrap();
    json!({ "data": b64(&list.data), "signature": b64(&list.signature) })
}

#[test]
fn address_keys_rotate_and_change_flags() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let first = set_up_address(&c, &base, &user);
    let (id, list1) = current_list(&c, &base, &user);
    let old = list1.list.keys[0].clone();

    // A new key, primary from now on; the old one stays to open old mail.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let new = mail_key::generate_address_key(&first.address, now).unwrap();
    let envelope = mail_key::seal_address_key(
        &user.master_key,
        &user.email,
        &first.address,
        &new.secret_key,
    )
    .unwrap();
    let new_entry = MailKeyEntryV1 {
        fingerprint: new.fingerprint,
        sha256_fingerprint: new.sha256_fingerprint,
        primary: true,
        flags: DEFAULT_FLAGS,
    };
    let rotated = next_list(
        &user,
        &list1,
        vec![
            MailKeyEntryV1 {
                primary: false,
                ..old.clone()
            },
            new_entry.clone(),
        ],
    );
    let r = bearer(c.post(format!("{base}/api/mail/addresses/{id}/keys")), &user.token)
        .json(&json!({ "publicKey": b64(&new.public_key), "privateKeyEnvelope": b64(&envelope), "keyList": rotated }))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200, "rotate");
    let lookup: Value = bearer(
        c.get(format!("{base}/api/mail/keys?email={}", first.address)),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(
        lookup["keys"][0]["fingerprint"],
        hex::encode(new.fingerprint),
        "new key first: {lookup}"
    );
    assert_eq!(lookup["keys"][0]["primary"], true);
    assert_eq!(lookup["keyLists"].as_array().unwrap().len(), 2);

    // The old key marked obsolete and compromised by a list of the same keys.
    let (_, list2) = current_list(&c, &base, &user);
    let put = |list: Value| {
        bearer(
            c.put(format!("{base}/api/mail/addresses/{id}/key-list")),
            &user.token,
        )
        .json(&json!({ "keyList": list }))
        .send()
        .unwrap()
    };
    let retired = MailKeyEntryV1 {
        primary: false,
        flags: 0,
        ..old.clone()
    };
    // Leaving a key out, or a list that does not follow, is refused.
    assert_eq!(
        put(next_list(&user, &list2, vec![new_entry.clone()])).status(),
        400
    );
    assert_eq!(
        put(next_list(
            &user,
            &list1,
            vec![retired.clone(), new_entry.clone()]
        ))
        .status(),
        409
    );
    let r = put(next_list(
        &user,
        &list2,
        vec![retired.clone(), new_entry.clone()],
    ));
    assert_eq!(r.status(), 200, "mark the old key");
    let address: Value = r.json().unwrap();
    let old_row = address["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["fingerprint"] == hex::encode(old.fingerprint))
        .unwrap()
        .clone();
    assert_eq!(old_row["flags"], 0);
    assert_eq!(old_row["primary"], false);
    // Three lists in the chain now.
    let (_, list3) = current_list(&c, &base, &user);
    assert_eq!(list3.list.sequence, 3);
}

/// A name sealed the way Mail seals it in the browser.
fn sealed_name(
    user: &User,
    account: &str,
    kind: kutup_crypto::mail_names::MailNameKind,
    id: &str,
    name: &str,
) -> String {
    let key = kutup_crypto::mail_names::derive_names_key(&user.master_key).unwrap();
    let id = *uuid::Uuid::parse_str(id).unwrap().as_bytes();
    b64(&kutup_crypto::mail_names::seal_name(&key, account, kind, &id, name).unwrap())
}

#[test]
fn folders_and_labels() {
    use kutup_crypto::mail_names::MailNameKind::{Folder, Label};
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let account = address.address.clone();
    // A message to yourself: one copy in the Inbox, one in Sent.
    let r = send_plain(
        &c,
        &base,
        &user,
        &address,
        std::slice::from_ref(&account),
        "filed",
    );
    assert!(r.status().is_success(), "send: {}", r.status());
    let inbox = folder(&c, &base, &user.token, "inbox");
    let message = inbox[0]["id"].as_str().unwrap().to_string();
    assert_eq!(inbox[0]["customFolder"], Value::Null);
    assert_eq!(inbox[0]["labels"], json!([]));

    // Three folders, each inside the one before; a fourth level is refused.
    let new_folder = |parent: Option<&str>, name: &str| {
        let id = uuid::Uuid::new_v4().to_string();
        let r = bearer(c.post(format!("{base}/api/mail/folders")), &user.token)
            .json(&json!({ "id": id, "parentId": parent, "name": sealed_name(&user, &account, Folder, &id, name), "color": "#3366cc" }))
            .send()
            .unwrap();
        (id, r.status().as_u16())
    };
    let (work, status) = new_folder(None, "İş");
    assert_eq!(status, 201);
    let (clients, status) = new_folder(Some(&work), "Müşteriler");
    assert_eq!(status, 201);
    let (acme, status) = new_folder(Some(&clients), "Acme");
    assert_eq!(status, 201);
    assert_eq!(new_folder(Some(&acme), "Too deep").1, 400);
    // A name that is not sealed is refused.
    let r = bearer(c.post(format!("{base}/api/mail/folders")), &user.token)
        .json(&json!({ "id": uuid::Uuid::new_v4().to_string(), "name": b64(b"Plain name"), "color": "#3366cc" }))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // No cycles: Work cannot go inside Acme.
    let r = bearer(
        c.patch(format!("{base}/api/mail/folders/{work}")),
        &user.token,
    )
    .json(&json!({ "parentId": acme }))
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // Clients moves to the top; it brings Acme along.
    let r = bearer(
        c.patch(format!("{base}/api/mail/folders/{clients}")),
        &user.token,
    )
    .json(&json!({ "parentId": null, "color": "#cc3366" }))
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let places: Value = bearer(c.get(format!("{base}/api/mail/places")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let find = |id: &str| {
        places["folders"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(find(&clients)["parentId"], Value::Null);
    assert_eq!(find(&clients)["color"], "#cc3366");
    assert_eq!(find(&acme)["parentId"], clients.as_str());
    // The name comes back sealed, and opens only as this folder's.
    let key = kutup_crypto::mail_names::derive_names_key(&user.master_key).unwrap();
    let sealed = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        find(&acme)["name"].as_str().unwrap(),
    )
    .unwrap();
    let acme_bytes = *uuid::Uuid::parse_str(&acme).unwrap().as_bytes();
    assert_eq!(
        kutup_crypto::mail_names::open_name(&key, &account, Folder, &acme_bytes, &sealed).unwrap(),
        "Acme"
    );

    // The message goes into Acme; it is listed and counted there.
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [message], "folder": "custom", "customFolder": acme }))
        .send()
        .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["updated"], 1);
    assert!(folder(&c, &base, &user.token, "inbox")
        .iter()
        .all(|m| m["id"] != message.as_str()));
    let in_acme = folder(&c, &base, &user.token, &format!("folder:{acme}"));
    assert_eq!(in_acme.len(), 1);
    assert_eq!(in_acme[0]["folder"], "custom");
    assert_eq!(in_acme[0]["customFolder"], acme.as_str());
    let counts: Value = bearer(c.get(format!("{base}/api/mail/counts")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let count = |key: String| {
        counts
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["folder"] == key.as_str())
            .map(|row| row["total"].as_i64().unwrap())
    };
    assert_eq!(count(format!("folder:{acme}")), Some(1));
    // Someone else's folder id, or a folder that is not there, is refused.
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [message], "folder": "custom", "customFolder": uuid::Uuid::new_v4().to_string() }))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // A label on the message: listed and counted, kept through a move.
    let label = uuid::Uuid::new_v4().to_string();
    let r = bearer(c.post(format!("{base}/api/mail/labels")), &user.token)
        .json(&json!({ "id": label, "name": sealed_name(&user, &account, Label, &label, "Faturalar"), "color": "#22aa55" }))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [message], "addLabels": [label] }))
        .send()
        .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["updated"], 1);
    let labelled = folder(&c, &base, &user.token, &format!("label:{label}"));
    assert_eq!(labelled.len(), 1);
    assert_eq!(labelled[0]["labels"], json!([label]));

    // Deleting Clients (and Acme in it) moves the message to Archive, label kept.
    let r = bearer(
        c.delete(format!("{base}/api/mail/folders/{clients}")),
        &user.token,
    )
    .send()
    .unwrap();
    let deleted: Value = r.json().unwrap();
    assert_eq!(deleted, json!({ "folders": 2, "moved": 1 }));
    let archived = folder(&c, &base, &user.token, "archive");
    let moved = archived
        .iter()
        .find(|m| m["id"] == message.as_str())
        .expect("in Archive");
    assert_eq!(moved["labels"], json!([label]));
    // Deleting the label leaves the message where it is.
    let r = bearer(
        c.delete(format!("{base}/api/mail/labels/{label}")),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let archived = folder(&c, &base, &user.token, "archive");
    assert_eq!(
        archived
            .iter()
            .find(|m| m["id"] == message.as_str())
            .unwrap()["labels"],
        json!([])
    );
    let places: Value = bearer(c.get(format!("{base}/api/mail/places")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(places["folders"].as_array().unwrap().len(), 1);
    assert_eq!(places["labels"], json!([]));
}

/// Sends `subject` from `user` to themselves (an Inbox copy and a Sent copy).
fn send_to_self(c: &Client, base: &str, user: &User, address: &Address, subject: &str) {
    let domain = address.address.split_once('@').unwrap().1;
    let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
    let mime = format!(
        "From: {0}\r\nTo: {0}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\nbody\r\n",
        address.address
    );
    let split =
        mail_key::encrypt_split(&[&address.public_key], &address.secret_key, mime.as_bytes())
            .unwrap();
    let packet = b64(&split.key_packets[0]);
    let meta = json!({
        "to": [{ "address": address.address }],
        "subject": subject,
        "messageId": message_id,
        "keyPackets": { "self": packet, address.address.clone(): packet },
    });
    let r = bearer(c.post(format!("{base}/api/mail/send")), &user.token)
        .multipart(form(vec![
            ("meta", serde_json::to_vec(&meta).unwrap()),
            ("data", split.data_packet),
        ]))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "send: {}", r.status());
}

#[test]
fn filters_file_mail_on_arrival_and_on_existing_mail() {
    use kutup_crypto::mail_names::MailNameKind::{Filter, Folder, Label};
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let account = address.address.clone();
    let post = |path: &str, body: Value| {
        bearer(c.post(format!("{base}{path}")), &user.token)
            .json(&body)
            .send()
            .unwrap()
    };

    // Mail from before the filter exists, to apply it to later.
    send_to_self(&c, &base, &user, &address, "Eski fatura");

    let invoices = uuid::Uuid::new_v4().to_string();
    assert_eq!(post("/api/mail/folders", json!({ "id": invoices, "name": sealed_name(&user, &account, Folder, &invoices, "Faturalar"), "color": "#3366cc" })).status().as_u16(), 201);
    let paid = uuid::Uuid::new_v4().to_string();
    assert_eq!(post("/api/mail/labels", json!({ "id": paid, "name": sealed_name(&user, &account, Label, &paid, "Ödenecek"), "color": "#22aa55" })).status().as_u16(), 201);

    // Subject contains "FATURA" (any case, Turkish İ folded): into the folder, labelled, starred.
    let filter = uuid::Uuid::new_v4().to_string();
    let r = post(
        "/api/mail/filters",
        json!({
            "id": filter,
            "name": sealed_name(&user, &account, Filter, &filter, "Faturalar"),
            "match": "all",
            "conditions": [{ "field": "subject", "op": "contains", "value": "FATURA" }],
            "actions": { "folder": format!("custom:{invoices}"), "labels": [paid], "star": true },
        }),
    );
    assert_eq!(r.status().as_u16(), 201);
    // A filter that names no action, or someone else's folder, is refused.
    let bad = uuid::Uuid::new_v4().to_string();
    let name = sealed_name(&user, &account, Filter, &bad, "Bad");
    assert_eq!(post("/api/mail/filters", json!({ "id": bad, "name": name, "match": "all", "conditions": [{ "field": "subject", "value": "x" }], "actions": {} })).status().as_u16(), 400);
    assert_eq!(post("/api/mail/filters", json!({ "id": bad, "name": name, "match": "all", "conditions": [{ "field": "subject", "value": "x" }], "actions": { "folder": format!("custom:{}", uuid::Uuid::new_v4()) } })).status().as_u16(), 400);

    // On arrival: the Inbox copy and the Sent copy are both filed.
    send_to_self(&c, &base, &user, &address, "Ekim faturası");
    send_to_self(&c, &base, &user, &address, "Merhaba");
    let filed = folder(&c, &base, &user.token, &format!("folder:{invoices}"));
    let new: Vec<&Value> = filed
        .iter()
        .filter(|m| m["subject"] == "Ekim faturası")
        .collect();
    assert_eq!(new.len(), 2, "both copies filed: {filed:?}");
    for m in &new {
        assert_eq!(m["labels"], json!([paid]));
        assert_eq!(m["starred"], true);
    }
    assert!(
        new.iter().any(|m| m["direction"] == "inbound")
            && new.iter().any(|m| m["direction"] == "outbound")
    );
    let inbox = folder(&c, &base, &user.token, "inbox");
    assert!(inbox.iter().any(|m| m["subject"] == "Merhaba"));
    assert!(
        inbox.iter().any(|m| m["subject"] == "Eski fatura"),
        "older mail is left alone until applied"
    );

    // Apply to existing: the older invoice is filed too.
    let r = post("/api/mail/filters/apply", json!({ "ids": [filter] }));
    assert_eq!(r.status().as_u16(), 202);
    let run = r.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let started = Instant::now();
    loop {
        let status: Value = bearer(
            c.get(format!("{base}/api/mail/filters/runs/{run}")),
            &user.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        if status["finished"] == true {
            assert_eq!(status["failed"], false);
            assert!(status["changed"].as_i64().unwrap() >= 1);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "run did not finish"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let filed = folder(&c, &base, &user.token, &format!("folder:{invoices}"));
    assert!(filed.iter().any(|m| m["subject"] == "Eski fatura"));

    // Switched off, a filter does nothing.
    let r = bearer(
        c.patch(format!("{base}/api/mail/filters/{filter}")),
        &user.token,
    )
    .json(&json!({ "enabled": false }))
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    send_to_self(&c, &base, &user, &address, "Kasım faturası");
    assert!(folder(&c, &base, &user.token, "inbox")
        .iter()
        .any(|m| m["subject"] == "Kasım faturası"));

    // Deleting the folder drops it from the filter, which keeps its label and star.
    let r = bearer(
        c.delete(format!("{base}/api/mail/folders/{invoices}")),
        &user.token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());
    let filters: Value = bearer(c.get(format!("{base}/api/mail/filters")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        filters[0]["actions"],
        json!({ "labels": [paid], "star": true })
    );
    // Deleting the label too leaves only the star.
    bearer(
        c.delete(format!("{base}/api/mail/labels/{paid}")),
        &user.token,
    )
    .send()
    .unwrap();
    let filters: Value = bearer(c.get(format!("{base}/api/mail/filters")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(filters[0]["actions"], json!({ "star": true }));
}

/// Waits until `user` has the message with `message_id` (inbox or spam).
fn wait_for(c: &Client, base: &str, user: &User, message_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(row) = messages(c, base, &user.token)
            .into_iter()
            .find(|m| m["messageId"] == message_id)
        {
            return row;
        }
        assert!(Instant::now() < deadline, "{message_id} never arrived");
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// A message row's content, opened with the account's address key.
fn open_row(c: &Client, base: &str, user: &User, address: &Address, row: &Value) -> String {
    let stored = bearer(
        c.get(format!(
            "{base}/api/mail/messages/{}/content",
            row["id"].as_str().unwrap()
        )),
        &user.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    let opened = mail_key::decrypt(&address.secret_key, &stored, None).unwrap();
    String::from_utf8_lossy(&opened.data).into_owned()
}

fn smtp_send(smtp_address: &str, to: &str, message: &str) -> (u16, u16) {
    let mut smtp = Smtp::connect(smtp_address);
    assert_eq!(smtp.command("EHLO lists.sender.test"), 250);
    assert_eq!(smtp.command("MAIL FROM:<writer@sender.test>"), 250);
    let rcpt = smtp.command(&format!("RCPT TO:<{to}>"));
    let data = if rcpt == 250 {
        smtp.data(message.as_bytes())
    } else {
        0
    };
    smtp.command("QUIT");
    (rcpt, data)
}

#[test]
fn distribution_lists_and_role_groups() {
    let (Ok(base), Ok(smtp_address), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_SMTP"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_SMTP / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let mut parts = admin.splitn(3, ':');
    let (email, username, password) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let admin = common::admin_token(&c, &base, email, password, username);
    let (alice_user, bob_user, carol_user, dave_user) = (
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
    );
    let alice = set_up_address(&c, &base, &alice_user);
    let bob = set_up_address(&c, &base, &bob_user);
    let carol = set_up_address(&c, &base, &carol_user);
    // Dave receives the role group's mail as an administrator below.
    set_up_address(&c, &base, &dave_user);
    let domain = alice.address.split_once('@').unwrap().1.to_string();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("team-{}", &tag[..8]);
    let team = format!("{name}@{domain}");

    // An administrator makes the list; its name is now taken for groups and
    // accounts alike.
    let create = |name: &str| {
        bearer(c.post(format!("{base}/api/admin/mail/groups")), &admin)
            .json(&json!({
                "name": name, "displayName": "Team", "kind": "list", "postPolicy": "anyone",
                "storageQuotaBytes": 10_000_000, "owners": [alice_user.id],
            }))
            .send()
            .unwrap()
    };
    let r = create(&name);
    assert_eq!(r.status(), 200, "create group");
    let group: Value = r.json().unwrap();
    let id = group["group"]["id"].as_str().unwrap().to_string();
    assert_eq!(group["group"]["address"], team.as_str());
    assert_eq!(code(create(&name)), (409, "nameTaken".into()));
    assert_eq!(
        code(create(&alice_user.username)),
        (409, "nameTaken".into())
    );
    assert_eq!(create("postmaster").status(), 400);

    // Its owner sets the members; a member cannot.
    let set_members = |user: &User, members: Value| {
        bearer(
            c.put(format!("{base}/api/mail/groups/{id}/members")),
            &user.token,
        )
        .json(&json!({ "members": members }))
        .send()
        .unwrap()
    };
    let three = json!([
        { "userId": alice_user.id, "role": "owner" },
        { "userId": bob_user.id, "role": "member" },
        { "userId": carol_user.id, "role": "member" },
    ]);
    assert_eq!(set_members(&alice_user, three.clone()).status(), 200);
    assert_eq!(set_members(&bob_user, three.clone()).status(), 403);
    assert_eq!(
        set_members(
            &alice_user,
            json!([{ "userId": bob_user.id, "role": "member" }])
        )
        .status(),
        400,
        "a group keeps an owner"
    );

    // Mail from outside: one stored copy, each member opens their own.
    let used_before = common::used(&c, &base, &bob_user.token);
    let message_id = format!("list-{tag}@sender.test");
    let message = format!(
        "From: writer@sender.test\r\nTo: {team}\r\nSubject: Team news\r\nMessage-ID: <{message_id}>\r\n\r\nHello team {tag}\r\n"
    );
    assert_eq!(smtp_send(&smtp_address, &team, &message), (250, 250));
    for (user, address) in [
        (&alice_user, &alice),
        (&bob_user, &bob),
        (&carol_user, &carol),
    ] {
        let row = wait_for(&c, &base, user, &message_id);
        assert_eq!(row["protection"], "zero_access");
        assert!(open_row(&c, &base, user, address, &row).contains(&format!("Hello team {tag}")));
    }
    assert!(messages(&c, &base, &dave_user.token)
        .iter()
        .all(|m| m["messageId"] != message_id.as_str()));
    // The group pays, not its members.
    assert_eq!(common::used(&c, &base, &bob_user.token), used_before);
    let group_used = || -> i64 {
        let all: Value = bearer(c.get(format!("{base}/api/admin/mail/groups")), &admin)
            .send()
            .unwrap()
            .json()
            .unwrap();
        all.as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == id.as_str())
            .unwrap()["storageUsedBytes"]
            .as_i64()
            .unwrap()
    };
    assert!(group_used() > 0);
    // The same message again (a retried delivery) is not stored twice.
    assert_eq!(smtp_send(&smtp_address, &team, &message), (250, 250));
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        messages(&c, &base, &carol_user.token)
            .iter()
            .filter(|m| m["messageId"] == message_id.as_str())
            .count(),
        1
    );

    // Members only: outside mail and non-members are refused.
    let r = bearer(
        c.patch(format!("{base}/api/admin/mail/groups/{id}")),
        &admin,
    )
    .json(&json!({ "postPolicy": "members" }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(smtp_send(&smtp_address, &team, &message).0, 550);
    let recipients = |user: &User| {
        bearer(
            c.get(format!("{base}/api/mail/groups/recipients?email={team}")),
            &user.token,
        )
        .send()
        .unwrap()
    };
    assert_eq!(recipients(&dave_user).status(), 403);

    // A member writes to the list from Kutup: one key packet per other member.
    let lookup: Value = recipients(&bob_user).json().unwrap();
    let addresses: Vec<String> = lookup["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["address"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(addresses.len(), 3);
    let kutup_id = format!("kutup-{tag}@{domain}");
    let mime = format!(
        "From: {}\r\nTo: {team}\r\nSubject: From Bob\r\nMessage-ID: <{kutup_id}>\r\n\r\nBob to the team {tag}\r\n",
        bob.address
    );
    let split = mail_key::encrypt_split(
        &[&bob.public_key, &alice.public_key, &carol.public_key],
        &bob.secret_key,
        mime.as_bytes(),
    )
    .unwrap();
    let send = |packets: Value| {
        let meta = serde_json::to_vec(&json!({
            "subject": "From Bob",
            "to": [{ "address": team }],
            "messageId": kutup_id,
            "keyPackets": packets,
        }))
        .unwrap();
        bearer(c.post(format!("{base}/api/mail/send")), &bob_user.token)
            .multipart(form(vec![
                ("meta", meta),
                ("data", split.data_packet.clone()),
            ]))
            .send()
            .unwrap()
    };
    // Carol's key packet missing: the browser's view of the members is stale.
    assert_eq!(
        code(send(
            json!({ "self": b64(&split.key_packets[0]), alice.address.clone(): b64(&split.key_packets[1]) })
        )),
        (409, "groupChanged".into())
    );
    let r = send(json!({
        "self": b64(&split.key_packets[0]),
        alice.address.clone(): b64(&split.key_packets[1]),
        carol.address.clone(): b64(&split.key_packets[2]),
    }));
    assert_eq!(r.status(), 200, "send to the list");
    assert_eq!(
        send_result(r)["recipients"],
        json!([{ "address": team, "status": "delivered" }])
    );
    for (user, address) in [(&alice_user, &alice), (&carol_user, &carol)] {
        let row = wait_for(&c, &base, user, &kutup_id);
        assert_eq!(row["protection"], "end_to_end");
        assert!(
            open_row(&c, &base, user, address, &row).contains(&format!("Bob to the team {tag}"))
        );
    }
    assert!(folder(&c, &base, &bob_user.token, "inbox")
        .iter()
        .all(|m| m["messageId"] != kutup_id.as_str()));

    // Full: the group's quota, not the members', refuses at RCPT.
    let quota = |bytes: i64| {
        let r = bearer(
            c.patch(format!("{base}/api/admin/mail/groups/{id}")),
            &admin,
        )
        .json(&json!({ "storageQuotaBytes": bytes, "postPolicy": "anyone" }))
        .send()
        .unwrap();
        assert_eq!(r.status(), 200);
    };
    quota(1);
    assert_eq!(smtp_send(&smtp_address, &team, &message).0, 452);
    quota(10_000_000);

    // Once every member deleted their copies, the group's storage is free.
    for user in [&alice_user, &bob_user, &carol_user] {
        let ids: Vec<String> = messages(&c, &base, &user.token)
            .into_iter()
            .filter(|m| {
                m["messageId"] == message_id.as_str() || m["messageId"] == kutup_id.as_str()
            })
            .map(|m| m["id"].as_str().unwrap().to_string())
            .collect();
        if ids.is_empty() {
            continue;
        }
        let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
            .json(&json!({ "ids": ids, "folder": "trash" }))
            .send()
            .unwrap();
        assert!(r.status().is_success(), "to trash");
        let r = bearer(
            c.post(format!("{base}/api/mail/messages/delete")),
            &user.token,
        )
        .json(&json!({ "ids": ids }))
        .send()
        .unwrap();
        assert!(r.status().is_success(), "delete");
    }
    assert_eq!(group_used(), 0);

    // A role group without members reaches every administrator; with a
    // member, only them.
    let r = bearer(
        c.put(format!("{base}/api/admin/users/{}", dave_user.id)),
        &admin,
    )
    .json(&json!({ "isAdmin": true }))
    .send()
    .unwrap();
    assert!(r.status().is_success());
    let all: Value = bearer(c.get(format!("{base}/api/admin/mail/groups")), &admin)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let abuse = all
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["systemRole"] == "abuse")
        .expect("abuse@ is a system group")
        .clone();
    assert_eq!(abuse["postPolicy"], "anyone");
    let abuse_id = abuse["id"].as_str().unwrap();
    let abuse_address = abuse["address"].as_str().unwrap();
    let r = bearer(
        c.put(format!("{base}/api/mail/groups/{abuse_id}/members")),
        &admin,
    )
    .json(&json!({ "members": [] }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().unwrap()["goesToAdministrators"], true);
    let report = format!("abuse-{tag}@sender.test");
    let complaint = format!(
        "From: reporter@sender.test\r\nTo: {abuse_address}\r\nSubject: Spam\r\nMessage-ID: <{report}>\r\n\r\nspam report\r\n"
    );
    assert_eq!(
        smtp_send(&smtp_address, abuse_address, &complaint),
        (250, 250)
    );
    wait_for(&c, &base, &dave_user, &report);
    assert_eq!(
        bearer(
            c.delete(format!("{base}/api/admin/mail/groups/{abuse_id}")),
            &admin
        )
        .send()
        .unwrap()
        .status(),
        400,
        "a role address stays"
    );
    let r = bearer(
        c.put(format!("{base}/api/mail/groups/{abuse_id}/members")),
        &admin,
    )
    .json(&json!({ "members": [{ "userId": carol_user.id, "role": "member" }] }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 200);
    let second = format!("abuse2-{tag}@sender.test");
    let complaint = complaint.replace(&report, &second);
    assert_eq!(
        smtp_send(&smtp_address, abuse_address, &complaint),
        (250, 250)
    );
    wait_for(&c, &base, &carol_user, &second);
    std::thread::sleep(Duration::from_secs(2));
    assert!(messages(&c, &base, &dave_user.token)
        .iter()
        .all(|m| m["messageId"] != second.as_str()));
    // Leave the role group as it was, for the other tests.
    let r = bearer(
        c.put(format!("{base}/api/mail/groups/{abuse_id}/members")),
        &admin,
    )
    .json(&json!({ "members": [] }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 200);

    // security.txt names security@.
    let text = c
        .get(format!("{base}/.well-known/security.txt"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        text.contains(&format!("Contact: mailto:security@{domain}")),
        "{text}"
    );
    assert!(text.contains("Expires: "));

    // Deleting the list frees its name; members keep what they received.
    assert_eq!(
        bearer(
            c.delete(format!("{base}/api/admin/mail/groups/{id}")),
            &admin
        )
        .send()
        .unwrap()
        .status(),
        204
    );
    assert_eq!(create(&name).status(), 200);
}

/// The hex fingerprint of an address's key.
fn fingerprint_of(address: &Address) -> String {
    hex::encode(
        mail_key::inspect_address_public_key(&address.public_key, &address.address)
            .unwrap()
            .fingerprint,
    )
}

/// A shared mailbox key share for `member`, as a browser makes it.
fn share_for(group_secret: &[u8], member_user: &User, member: &Address) -> Value {
    json!({
        "userId": member_user.id,
        "share": b64(&mail_key::seal_group_key_share(&member.public_key, group_secret).unwrap()),
        "memberFingerprint": fingerprint_of(member),
    })
}

#[test]
fn shared_mailboxes() {
    let (Ok(base), Ok(smtp_address), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_SMTP"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_SMTP / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let mut parts = admin.splitn(3, ':');
    let (email, username, password) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let admin = common::admin_token(&c, &base, email, password, username);
    let (alice_user, bob_user, carol_user) = (
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
    );
    let alice = set_up_address(&c, &base, &alice_user);
    let bob = set_up_address(&c, &base, &bob_user);
    let carol = set_up_address(&c, &base, &carol_user);
    let domain = alice.address.split_once('@').unwrap().1.to_string();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("hr-{}", &tag[..8]);
    let hr = format!("{name}@{domain}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    // Made with its key, a share for its owner; without one it is refused.
    let first = mail_key::generate_address_key(&hr, now).unwrap();
    let create = |group_key: Value| {
        bearer(c.post(format!("{base}/api/admin/mail/groups")), &admin)
            .json(&json!({
                "name": name, "displayName": "HR", "kind": "shared", "postPolicy": "anyone",
                "storageQuotaBytes": 10_000_000, "owners": [alice_user.id], "groupKey": group_key,
            }))
            .send()
            .unwrap()
    };
    assert_eq!(create(Value::Null).status(), 400);
    let r = create(json!({
        "publicKey": b64(&first.public_key),
        "shares": [share_for(&first.secret_key, &alice_user, &alice)],
    }));
    assert_eq!(r.status(), 200, "create shared mailbox");
    let id = r.json::<Value>().unwrap()["group"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Its key is published with a list the server signs.
    let lookup: Value = bearer(
        c.get(format!("{base}/api/mail/keys?email={hr}")),
        &bob_user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(lookup["account"], hr.as_str());
    assert_eq!(
        lookup["keys"][0]["fingerprint"],
        hex::encode(first.fingerprint)
    );
    let authority: [u8; 32] = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        lookup["accountAuthorityPublicKey"].as_str().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let list_data = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        lookup["keyLists"][0]["data"].as_str().unwrap(),
    )
    .unwrap();
    let list_signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        lookup["keyLists"][0]["signature"].as_str().unwrap(),
    )
    .unwrap();
    let list =
        mail_key::SignedMailKeyListV1::verify(&list_data, &list_signature, &authority).unwrap();
    assert_eq!(list.list.address, hr);

    // Mail from outside: one copy, owned by the mailbox.
    let message_id = format!("hr-{tag}@sender.test");
    let message = format!(
        "From: applicant@sender.test\r\nTo: {hr}\r\nSubject: Application\r\nMessage-ID: <{message_id}>\r\n\r\nMy CV {tag}\r\n"
    );
    assert_eq!(smtp_send(&smtp_address, &hr, &message), (250, 250));
    // Received mail may be filed under Spam (no SPF or DKIM in the gate).
    let in_group = |user: &User, folder_name: &str| -> Vec<Value> {
        let folders: &[&str] = if folder_name == "inbox" {
            &["inbox", "spam"]
        } else {
            &[folder_name]
        };
        folders
            .iter()
            .flat_map(|folder_name| {
                let page: Value = bearer(
                    c.get(format!(
                        "{base}/api/mail/messages?folder={folder_name}&group={id}"
                    )),
                    &user.token,
                )
                .send()
                .unwrap()
                .json()
                .unwrap();
                page["messages"].as_array().cloned().unwrap_or_default()
            })
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    let row = loop {
        if let Some(row) = in_group(&alice_user, "inbox")
            .into_iter()
            .find(|m| m["messageId"] == message_id.as_str())
        {
            break row;
        }
        assert!(Instant::now() < deadline, "the application never arrived");
        std::thread::sleep(Duration::from_secs(1));
    };
    let content = |user: &User, row: &Value| {
        bearer(
            c.get(format!(
                "{base}/api/mail/messages/{}/content?group={id}",
                row["id"].as_str().unwrap()
            )),
            &user.token,
        )
        .send()
        .unwrap()
    };
    let stored = content(&alice_user, &row).bytes().unwrap();
    let opened = mail_key::decrypt(&first.secret_key, &stored, None).unwrap();
    assert!(String::from_utf8_lossy(&opened.data).contains(&format!("My CV {tag}")));
    // Not for a non-member, nor in anyone's own mailbox.
    assert_eq!(content(&bob_user, &row).status(), 404);
    assert!(messages(&c, &base, &alice_user.token)
        .iter()
        .all(|m| m["messageId"] != message_id.as_str()));

    // Bob joins with a share of the key; without one he is refused.
    let set_members = |members: Value, extra: Value| {
        let mut body = json!({ "members": members });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        bearer(
            c.put(format!("{base}/api/mail/groups/{id}/members")),
            &alice_user.token,
        )
        .json(&body)
        .send()
        .unwrap()
    };
    let both = json!([
        { "userId": alice_user.id, "role": "owner", "canSendAs": true },
        { "userId": bob_user.id, "role": "member" },
    ]);
    assert_eq!(code(set_members(both.clone(), json!({}))).1, "sharesNeeded");
    let bob_share = json!({ "groupFingerprint": hex::encode(first.fingerprint) });
    let mut bob_share = bob_share.as_object().unwrap().clone();
    bob_share.extend(
        share_for(&first.secret_key, &bob_user, &bob)
            .as_object()
            .unwrap()
            .clone(),
    );
    assert_eq!(
        set_members(both.clone(), json!({ "keyShares": [bob_share] })).status(),
        200
    );
    let keys: Value = bearer(
        c.get(format!("{base}/api/mail/groups/{id}/keys")),
        &bob_user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let share = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        keys[0]["share"].as_str().unwrap(),
    )
    .unwrap();
    let bobs_key =
        mail_key::open_group_key_share(&bob.secret_key, &share, &first.fingerprint).unwrap();
    assert!(mail_key::decrypt(&bobs_key, &content(&bob_user, &row).bytes().unwrap(), None).is_ok());

    // Shared state: Bob reads it, Alice sees it read.
    let r = bearer(
        c.patch(format!("{base}/api/mail/messages")),
        &bob_user.token,
    )
    .json(&json!({ "ids": [row["id"]], "seen": true, "group": id }))
    .send()
    .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["updated"], 1);
    let seen = in_group(&alice_user, "inbox")
        .into_iter()
        .find(|m| m["messageId"] == message_id.as_str())
        .unwrap();
    assert_eq!(seen["seen"], true);

    // Writing as the mailbox needs the right; Carol gets it From hr@.
    let reply_id = format!("reply-{tag}@{domain}");
    let reply = format!(
        "From: HR <{hr}>\r\nTo: {}\r\nSubject: Re: Application\r\nMessage-ID: <{reply_id}>\r\n\r\nThank you {tag}\r\n",
        carol.address
    );
    let split = mail_key::encrypt_split(
        &[&first.public_key, &carol.public_key],
        &bobs_key,
        reply.as_bytes(),
    )
    .unwrap();
    let send_as = |user: &User| {
        let meta = serde_json::to_vec(&json!({
            "subject": "Re: Application",
            "fromName": "HR",
            "to": [{ "address": carol.address }],
            "messageId": reply_id,
            "fromGroup": id,
            "keyPackets": { "self": b64(&split.key_packets[0]), carol.address.clone(): b64(&split.key_packets[1]) },
        }))
        .unwrap();
        bearer(c.post(format!("{base}/api/mail/send")), &user.token)
            .multipart(form(vec![
                ("meta", meta),
                ("data", split.data_packet.clone()),
            ]))
            .send()
            .unwrap()
    };
    assert_eq!(code(send_as(&bob_user)), (403, "notAllowedToSendAs".into()));
    let with_right = json!([
        { "userId": alice_user.id, "role": "owner", "canSendAs": true },
        { "userId": bob_user.id, "role": "member", "canSendAs": true },
    ]);
    assert_eq!(set_members(with_right.clone(), json!({})).status(), 200);
    let r = send_as(&bob_user);
    assert_eq!(r.status(), 200, "send as the mailbox");
    let sent = send_result(r);
    assert_eq!(sent["message"]["folder"], "sent");
    assert!(in_group(&alice_user, "sent")
        .iter()
        .any(|m| m["messageId"] == reply_id.as_str()));
    let carols = wait_for(&c, &base, &carol_user, &reply_id);
    assert_eq!(carols["from"]["address"], hr.as_str());
    assert!(open_row(&c, &base, &carol_user, &carol, &carols).contains(&format!("Thank you {tag}")));

    // Carol writes to the mailbox, end to end with its key.
    let carol_id = format!("carol-{tag}@{domain}");
    let to_hr = format!(
        "From: {}\r\nTo: {hr}\r\nSubject: Thanks\r\nMessage-ID: <{carol_id}>\r\n\r\nThanks back {tag}\r\n",
        carol.address
    );
    let split = mail_key::encrypt_split(
        &[&carol.public_key, &first.public_key],
        &carol.secret_key,
        to_hr.as_bytes(),
    )
    .unwrap();
    let meta = serde_json::to_vec(&json!({
        "subject": "Thanks",
        "to": [{ "address": hr }],
        "messageId": carol_id,
        "keyPackets": { "self": b64(&split.key_packets[0]), hr.clone(): b64(&split.key_packets[1]) },
    }))
    .unwrap();
    let r = bearer(c.post(format!("{base}/api/mail/send")), &carol_user.token)
        .multipart(form(vec![
            ("meta", meta),
            ("data", split.data_packet.clone()),
        ]))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200, "send to the mailbox");
    let thanks = in_group(&alice_user, "inbox")
        .into_iter()
        .find(|m| m["messageId"] == carol_id.as_str())
        .expect("Carol's mail in the mailbox");
    assert_eq!(thanks["protection"], "end_to_end");

    // Bob leaves: only with a new key, which he never gets.
    let alice_only = json!([{ "userId": alice_user.id, "role": "owner", "canSendAs": true }]);
    assert_eq!(
        code(set_members(alice_only.clone(), json!({}))).1,
        "newKeyNeeded"
    );
    // Newer than the first key, but never ahead of the clock: a key dated
    // after its own self-signatures (made at the real time) is unusable to
    // GnuPG ("public key is 1 second newer than the signature").
    let later = loop {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        if secs > now {
            break secs;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let second = mail_key::generate_address_key(&hr, later).unwrap();
    let r = set_members(
        alice_only,
        json!({ "newKey": {
            "publicKey": b64(&second.public_key),
            "shares": [share_for(&second.secret_key, &alice_user, &alice)],
        } }),
    );
    assert_eq!(r.status(), 200, "remove with a new key");
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/mail/groups/{id}/keys")),
            &bob_user.token
        )
        .send()
        .unwrap()
        .status(),
        404
    );
    let new_id = format!("hr2-{tag}@sender.test");
    let later = message.replace(&message_id, &new_id);
    assert_eq!(smtp_send(&smtp_address, &hr, &later), (250, 250));
    let deadline = Instant::now() + Duration::from_secs(90);
    let row = loop {
        if let Some(row) = in_group(&alice_user, "inbox")
            .into_iter()
            .find(|m| m["messageId"] == new_id.as_str())
        {
            break row;
        }
        assert!(
            Instant::now() < deadline,
            "the second application never arrived"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    let stored = content(&alice_user, &row).bytes().unwrap();
    assert!(mail_key::decrypt(&second.secret_key, &stored, None).is_ok());
    assert!(
        mail_key::decrypt(&first.secret_key, &stored, None).is_err(),
        "the old key cannot read new mail"
    );

    // An OpenPGP user outside finds the mailbox's key through WKD and
    // writes to it end to end; its members open it with the group key.
    if let Ok(home) = std::env::var("KUTUP_LIVE_GPG_HOME") {
        let local = hr.split_once('@').unwrap().0;
        let wkd = c
            .get(format!(
                "{base}/.well-known/openpgpkey/hu/{}?l={local}",
                wkd_hash(local)
            ))
            .send()
            .unwrap();
        assert_eq!(wkd.status(), 200, "WKD serves the mailbox's key");
        let published = wkd.bytes().unwrap();
        assert!(
            published
                .windows(second.public_key.len())
                .any(|w| w == second.public_key.as_slice()),
            "the current key is published"
        );
        let (ok, _, err) = gpg(&home, &["--import"], &published);
        assert!(ok, "import the mailbox's key: {err}");
        let (ok, encrypted, err) = gpg(
            &home,
            &["--armor", "--encrypt", "-r", &hr],
            format!("Content-Type: text/plain; charset=utf-8\r\n\r\nFrom GnuPG {tag}\r\n")
                .as_bytes(),
        );
        assert!(ok, "GnuPG encrypts to the mailbox: {err}");
        let pgp_id = format!("gpg-hr-{tag}@outside.test");
        let message = pgp_mime(
            &format!("From: dave@outside.test\r\nTo: {hr}\r\nSubject: PGP to HR\r\nMessage-ID: <{pgp_id}>\r\n"),
            &String::from_utf8(encrypted).unwrap(),
        );
        assert_eq!(
            smtp_send(&smtp_address, &hr, &String::from_utf8(message).unwrap()),
            (250, 250)
        );
        let deadline = Instant::now() + Duration::from_secs(90);
        let row = loop {
            if let Some(row) = in_group(&alice_user, "inbox")
                .into_iter()
                .find(|m| m["messageId"] == pgp_id.as_str())
            {
                break row;
            }
            assert!(Instant::now() < deadline, "the PGP message never arrived");
            std::thread::sleep(Duration::from_secs(1));
        };
        assert_eq!(row["protection"], "end_to_end");
        let outer = mail_key::decrypt(
            &second.secret_key,
            &content(&alice_user, &row).bytes().unwrap(),
            None,
        )
        .unwrap();
        let outer = String::from_utf8(outer.data.to_vec()).unwrap();
        let start = outer.find("-----BEGIN PGP MESSAGE-----").unwrap();
        let end =
            outer.find("-----END PGP MESSAGE-----").unwrap() + "-----END PGP MESSAGE-----".len();
        let inner =
            mail_key::decrypt(&second.secret_key, &outer.as_bytes()[start..end], None).unwrap();
        assert!(String::from_utf8_lossy(&inner.data).contains(&format!("From GnuPG {tag}")));
    }

    // Deleting the mailbox takes its mail with it.
    assert_eq!(
        bearer(
            c.delete(format!("{base}/api/admin/mail/groups/{id}")),
            &admin
        )
        .send()
        .unwrap()
        .status(),
        204
    );
    assert_eq!(content(&alice_user, &row).status(), 404);
}

/// The WKD hash of a local part: z-base-32 of its SHA-1.
fn wkd_hash(local: &str) -> String {
    use sha1::Digest as _;
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let digest = sha1::Sha1::digest(local.to_lowercase().as_bytes());
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0u32);
    for byte in digest {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[test]
fn mail_settings_all_mail_and_emptying() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let me = vec![address.address.clone()];
    // The defaults, as Proton's: no auto-delete, All mail with Spam and Trash.
    let settings: Value = bearer(c.get(format!("{base}/api/mail/settings")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        settings,
        json!({ "autoDeleteDays": 0, "almostAllMail": false, "viewLayout": "column", "density": "comfortable", "composerMode": "popup", "viewMode": "conversation", "signOutside": true, "attachPublicKey": false, "pgpScheme": "pgp_mime", "confirmLink": true, "pageSize": 50, "spamAction": "ask", "remoteImages": "ask", "delaySendSeconds": 10, "draftType": "html", "textDirection": "ltr", "fontFace": "arial", "fontSize": 14 })
    );
    // Proton's page sizes only.
    let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
        .json(&json!({ "spamAction": "always" }))
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
    for (size, status) in [(100, 200), (75, 400)] {
        let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
            .json(&json!({ "pageSize": size }))
            .send()
            .unwrap();
        assert_eq!(r.status(), status, "page size {size}");
    }
    let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
        .json(&json!({ "autoDeleteDays": 7 }))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
        .json(&json!({ "density": "tiny" }))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // Two messages to self (two copies each); one received copy into the Trash.
    for body in ["one", "two"] {
        assert!(send_plain(&c, &base, &user, &address, &me, body)
            .status()
            .is_success());
    }
    let inbox = folder(&c, &base, &user.token, "inbox");
    let trashed = inbox[0]["id"].as_str().unwrap().to_string();
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [trashed], "folder": "trash" }))
        .send()
        .unwrap();
    assert!(r.status().is_success());
    let all = |c: &Client| folder(c, &base, &user.token, "all");
    assert!(
        all(&c).iter().any(|m| m["id"] == trashed.as_str()),
        "All mail has the Trash by default"
    );
    let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
        .json(&json!({ "almostAllMail": true, "autoDeleteDays": 30, "viewLayout": "row", "density": "compact", "composerMode": "maximized", "viewMode": "message", "signOutside": false, "attachPublicKey": true, "pgpScheme": "inline", "confirmLink": false, "pageSize": 200, "spamAction": "spam_and_unsubscribe", "remoteImages": "always", "delaySendSeconds": 20, "draftType": "plain", "textDirection": "rtl", "fontFace": "georgia", "fontSize": 18 }))
        .send()
        .unwrap();
    assert_eq!(
        r.json::<Value>().unwrap(),
        json!({ "autoDeleteDays": 30, "almostAllMail": true, "viewLayout": "row", "density": "compact", "composerMode": "maximized", "viewMode": "message", "signOutside": false, "attachPublicKey": true, "pgpScheme": "inline", "confirmLink": false, "pageSize": 200, "spamAction": "spam_and_unsubscribe", "remoteImages": "always", "delaySendSeconds": 20, "draftType": "plain", "textDirection": "rtl", "fontFace": "georgia", "fontSize": 18 })
    );
    assert!(
        all(&c).iter().all(|m| m["id"] != trashed.as_str()),
        "Almost all mail leaves the Trash out"
    );

    // Empty the Trash: the message is gone for good and its storage freed.
    let used = common::used(&c, &base, &user.token);
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/empty")),
        &user.token,
    )
    .json(&json!({ "folder": "trash" }))
    .send()
    .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["updated"], 1);
    assert!(folder(&c, &base, &user.token, "trash").is_empty());
    assert!(common::used(&c, &base, &user.token) < used);
    // Only Trash and Spam are emptied.
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/empty")),
        &user.token,
    )
    .json(&json!({ "folder": "inbox" }))
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    assert_eq!(folder(&c, &base, &user.token, "inbox").len(), 1);
}

#[test]
fn block_spam_and_allow_lists() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let alice_address = set_up_address(&c, &base, &alice);
    let bob = register(&c, &base);
    let bob_address = set_up_address(&c, &base, &bob);
    let domain = bob_address.address.split_once('@').unwrap().1.to_string();
    let rules = |patterns: &[&str], kind: &str| {
        let r = bearer(
            c.post(format!("{base}/api/mail/sender-rules")),
            &alice.token,
        )
        .json(&json!({ "patterns": patterns, "kind": kind }))
        .send()
        .unwrap();
        assert!(r.status().is_success(), "rules: {}", r.status());
        r.json::<Value>().unwrap()
    };
    let subjects = |folder_name: &str| -> Vec<String> {
        folder(&c, &base, &alice.token, folder_name)
            .iter()
            .filter(|m| m["from"]["address"] == bob_address.address.as_str())
            .map(|m| m["subject"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    // Bob writes to Alice, encrypted to her key and his own, as Mail does.
    let send = |body: &str| {
        let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
        let mime = format!(
            "From: {}\r\nTo: {}\r\nSubject: lists\r\nMessage-ID: <{message_id}>\r\n\r\n{body}\r\n",
            bob_address.address, alice_address.address
        );
        let split = mail_key::encrypt_split(
            &[&alice_address.public_key, &bob_address.public_key],
            &bob_address.secret_key,
            mime.as_bytes(),
        )
        .unwrap();
        let meta = json!({
            "to": [{ "address": alice_address.address }],
            "subject": "lists",
            "messageId": message_id,
            "keyPackets": { "self": b64(&split.key_packets[1]), alice_address.address.clone(): b64(&split.key_packets[0]) },
        });
        let r = bearer(c.post(format!("{base}/api/mail/send")), &bob.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta).unwrap()),
                ("data", split.data_packet),
            ]))
            .send()
            .unwrap();
        assert!(r.status().is_success(), "send: {}", r.status());
        // The sender is told it was delivered, blocked or not (as Proton).
        let result = send_result(r);
        assert_eq!(result["recipients"][0]["status"], "delivered", "{result}");
    };

    // Blocked: accepted and not stored, nothing charged.
    let used_before = common::used(&c, &base, &alice.token);
    let blocked = rules(&[&bob_address.address.to_uppercase()], "block");
    assert_eq!(blocked[0]["pattern"], bob_address.address.as_str());
    send("blocked");
    assert!(
        subjects("inbox").is_empty() && subjects("spam").is_empty() && subjects("trash").is_empty()
    );
    assert_eq!(common::used(&c, &base, &alice.token), used_before);

    // Moved to spam (one entry per address: the block becomes spam).
    let spam = rules(&[&bob_address.address], "spam");
    assert_eq!(spam[0]["id"], blocked[0]["id"]);
    send("spam");
    assert_eq!(subjects("spam").len(), 1);
    assert!(subjects("inbox").is_empty());

    // The whole domain blocked, but Bob's address allowed: the address wins.
    rules(&[&format!("@{domain}")], "block");
    rules(&[&bob_address.address], "allow");
    send("allowed");
    assert_eq!(subjects("inbox").len(), 1);

    // Unblock (delete the entries): mail arrives as usual.
    let list: Value = bearer(c.get(format!("{base}/api/mail/sender-rules")), &alice.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
    let ids: Vec<Value> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].clone())
        .collect();
    let r = bearer(
        c.post(format!("{base}/api/mail/sender-rules/delete")),
        &alice.token,
    )
    .json(&json!({ "ids": ids }))
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    send("after");
    assert_eq!(subjects("inbox").len(), 2);
    // Not an address or domain: refused.
    let r = bearer(
        c.post(format!("{base}/api/mail/sender-rules")),
        &alice.token,
    )
    .json(&json!({ "patterns": ["not a domain"], "kind": "block" }))
    .send()
    .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

/// Encrypt off, Sign on (docs/plans/mail-encrypt-sign.md): Bob sends Alice a
/// readable, signed message; the server encrypts it to her on arrival
/// (zero-access), and the signature checks against Bob's key.
#[test]
fn encrypt_off_sign_on_between_kutup_users() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let alice_address = set_up_address(&c, &base, &alice);
    let bob = register(&c, &base);
    let bob_address = set_up_address(&c, &base, &bob);
    let domain = bob_address.address.split_once('@').unwrap().1.to_string();
    let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
    // The signed part and its detached signature, as the composer builds them.
    let part = "Content-Type: text/plain; charset=utf-8\r\n\r\nSifresiz ama imzali.\r\n";
    let signature = mail_key::sign_detached(&bob_address.secret_key, part.as_bytes()).unwrap();
    let mime = format!(
        "From: {}\r\nTo: {}\r\nSubject: readable\r\nMessage-ID: <{message_id}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/signed; micalg=pgp-sha512; protocol=\"application/pgp-signature\"; boundary=\"s\"\r\n\r\n\
         --s\r\n{part}\r\n--s\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\n\r\n{signature}\r\n--s--\r\n",
        bob_address.address, alice_address.address
    );
    // Bob's own copy stays end to end: encrypted to his key only.
    let split = mail_key::encrypt_split(
        &[&bob_address.public_key],
        &bob_address.secret_key,
        mime.as_bytes(),
    )
    .unwrap();
    let meta = json!({
        "to": [{ "address": alice_address.address }],
        "subject": "readable",
        "messageId": message_id,
        "keyPackets": { "self": b64(&split.key_packets[0]) },
        "readable": [alice_address.address.to_uppercase()],
    });
    let r = bearer(c.post(format!("{base}/api/mail/send")), &bob.token)
        .multipart(form(vec![
            ("meta", serde_json::to_vec(&meta).unwrap()),
            ("data", split.data_packet),
            ("mime", mime.clone().into_bytes()),
        ]))
        .send()
        .unwrap();
    assert!(
        r.status().is_success(),
        "send: {} {}",
        r.status(),
        r.text().unwrap_or_default()
    );

    let inbox = folder(&c, &base, &alice.token, "inbox");
    let message = inbox
        .iter()
        .find(|m| m["subject"] == "readable")
        .expect("delivered");
    assert_eq!(message["protection"], "zero_access");
    let stored = bearer(
        c.get(format!(
            "{base}/api/mail/messages/{}/content",
            message["id"].as_str().unwrap()
        )),
        &alice.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    let opened = mail_key::decrypt(&alice_address.secret_key, &stored, None).unwrap();
    assert_eq!(
        &opened.data[..],
        mime.as_bytes(),
        "stored exactly as sent, encrypted on arrival"
    );
    assert!(mail_key::verify_detached(
        signature.as_bytes(),
        part.as_bytes(),
        &bob_address.public_key
    )
    .unwrap());
    // Bob's Sent copy is end to end.
    let sent = folder(&c, &base, &bob.token, "sent");
    assert_eq!(
        sent.iter().find(|m| m["subject"] == "readable").unwrap()["protection"],
        "end_to_end"
    );

    // Readable without the readable message: refused.
    let split =
        mail_key::encrypt_split(&[&bob_address.public_key], &bob_address.secret_key, b"x").unwrap();
    let meta = json!({
        "to": [{ "address": alice_address.address }],
        "subject": "readable",
        "messageId": format!("{}@{domain}", uuid::Uuid::new_v4().simple()),
        "keyPackets": { "self": b64(&split.key_packets[0]) },
        "readable": [alice_address.address],
    });
    let r = bearer(c.post(format!("{base}/api/mail/send")), &bob.token)
        .multipart(form(vec![
            ("meta", serde_json::to_vec(&meta).unwrap()),
            ("data", split.data_packet),
        ]))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

#[test]
fn display_name_and_signature() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let identity: Value = bearer(c.get(format!("{base}/api/mail/identity")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(identity["address"], address.address.as_str());
    assert_eq!(
        identity["displayName"],
        address.address.split('@').next().unwrap(),
        "the username until a name is set"
    );
    assert_eq!(identity["signature"], "");
    let r = bearer(c.patch(format!("{base}/api/mail/identity")), &user.token)
        .json(&json!({ "displayName": "  Ayşe Yılmaz ", "signature": "<p><strong>Ayşe</strong><br>Kutup</p>" }))
        .send()
        .unwrap();
    let saved: Value = r.json().unwrap();
    assert_eq!(saved["displayName"], "Ayşe Yılmaz");
    assert_eq!(saved["signature"], "<p><strong>Ayşe</strong><br>Kutup</p>");
    for bad in [
        json!({ "displayName": "x".repeat(101) }),
        json!({ "displayName": "a\nb" }),
        json!({ "signature": "x".repeat(10_001) }),
    ] {
        let r = bearer(c.patch(format!("{base}/api/mail/identity")), &user.token)
            .json(&bad)
            .send()
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "{bad}");
    }
    // Only the name: the signature stays.
    let r = bearer(c.patch(format!("{base}/api/mail/identity")), &user.token)
        .json(&json!({ "displayName": "" }))
        .send()
        .unwrap();
    let saved: Value = r.json().unwrap();
    assert_eq!(
        saved["displayName"],
        address.address.split('@').next().unwrap()
    );
    assert_eq!(saved["signature"], "<p><strong>Ayşe</strong><br>Kutup</p>");
}

#[test]
fn auto_reply_answers_once_per_sender() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let alice_address = set_up_address(&c, &base, &alice);
    let bob = register(&c, &base);
    let bob_address = set_up_address(&c, &base, &bob);
    let domain = bob_address.address.split_once('@').unwrap().1.to_string();
    let put = |body: Value| {
        bearer(c.put(format!("{base}/api/mail/auto-reply")), &alice.token)
            .json(&body)
            .send()
            .unwrap()
    };
    let settings = |repeat: &str| {
        json!({
            "enabled": true, "repeat": repeat, "zone": "Europe/Istanbul",
            "messageHtml": "<p>Dışarıdayım.</p>", "messageText": "Dışarıdayım.",
        })
    };

    // Nothing saved yet.
    let none: Value = bearer(c.get(format!("{base}/api/mail/auto-reply")), &alice.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(none, json!({ "settings": null, "active": false }));
    // Refused: an unknown zone, an end before the start, an empty message.
    let mut bad = settings("permanent");
    bad["zone"] = json!("Mars/Olympus");
    assert_eq!(put(bad).status(), 400);
    let mut bad = settings("fixed");
    bad["start"] = json!("2026-10-12T09:00");
    bad["end"] = json!("2026-10-12T08:00");
    assert_eq!(put(bad).status(), 400);
    let mut bad = settings("permanent");
    bad["messageText"] = json!(" ");
    assert_eq!(put(bad).status(), 400);
    let mut bad = settings("daily");
    bad["days"] = json!([7]);
    bad["startMinute"] = json!(0);
    bad["endMinute"] = json!(0);
    assert_eq!(put(bad).status(), 400);

    // On until turned off.
    let saved: Value = put(settings("permanent")).json().unwrap();
    assert_eq!(saved["active"], true, "{saved}");
    assert_eq!(saved["settings"]["repeat"], "permanent");

    // Bob writes to Alice, as Mail does.
    let send = |subject: &str| -> String {
        let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
        let mime = format!(
            "From: {}\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\nmerhaba\r\n",
            bob_address.address, alice_address.address
        );
        let split = mail_key::encrypt_split(
            &[&alice_address.public_key, &bob_address.public_key],
            &bob_address.secret_key,
            mime.as_bytes(),
        )
        .unwrap();
        let meta = json!({
            "to": [{ "address": alice_address.address }],
            "subject": subject,
            "messageId": message_id,
            "keyPackets": { "self": b64(&split.key_packets[1]), alice_address.address.clone(): b64(&split.key_packets[0]) },
        });
        let r = bearer(c.post(format!("{base}/api/mail/send")), &bob.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta).unwrap()),
                ("data", split.data_packet),
            ]))
            .send()
            .unwrap();
        assert!(r.status().is_success(), "send: {}", r.status());
        message_id
    };
    let answers = |user: &User, name: &str| -> Vec<Value> {
        folder(&c, &base, &user.token, name)
            .into_iter()
            .filter(|m| {
                m["subject"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("Auto: ")
            })
            .collect()
    };
    let wait_answers = |user: &User, name: &str, count: usize| -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let found = answers(user, name);
            if found.len() >= count {
                return found;
            }
            assert!(
                Instant::now() < deadline,
                "{count} answers never reached {name}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    };

    let first = send("Toplantı");
    let reply = wait_answers(&bob, "inbox", 1).remove(0);
    assert_eq!(reply["subject"], "Auto: Toplantı");
    assert_eq!(reply["inReplyTo"], first.as_str());
    assert_eq!(reply["protection"], "zero_access");
    assert_eq!(reply["from"]["address"], alice_address.address.as_str());
    let content = open_row(&c, &base, &bob, &bob_address, &reply);
    assert!(
        content.contains("Auto-Submitted: auto-replied"),
        "{content}"
    );
    // Alice keeps it in Sent, in the same thread as Bob's message.
    let kept = wait_answers(&alice, "sent", 1).remove(0);
    let original = wait_for(&c, &base, &alice, &first);
    assert_eq!(kept["threadId"], original["threadId"]);

    // Once per sender: a second message gets no answer.
    send("Yine ben");
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(answers(&bob, "inbox").len(), 1);
    // Bob's own auto-reply does not answer Alice's automatic one.
    let bob_put = bearer(c.put(format!("{base}/api/mail/auto-reply")), &bob.token)
        .json(&settings("permanent"))
        .send()
        .unwrap();
    assert!(bob_put.status().is_success());

    // Saving starts it over; outside its period, nothing is sent.
    let mut past = settings("fixed");
    past["start"] = json!("2020-01-01T00:00");
    past["end"] = json!("2020-01-08T00:00");
    let saved: Value = put(past).json().unwrap();
    assert_eq!(saved["active"], false);
    assert_eq!(saved["settings"]["start"], "2020-01-01T00:00");
    send("Geçmiş");
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(answers(&bob, "inbox").len(), 1);
    // Back on: Bob is answered again, and Bob's auto-reply stays quiet.
    put(settings("permanent"));
    send("Yeniden");
    wait_answers(&bob, "inbox", 2);
    std::thread::sleep(Duration::from_secs(3));
    assert!(answers(&alice, "inbox").is_empty());

    // Mail a Kutup user sent with Encrypt off (readable on the way) is
    // answered too.
    let carol = register(&c, &base);
    let carol_address = set_up_address(&c, &base, &carol);
    let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
    let mime = format!(
        "From: {}\r\nTo: {}\r\nSubject: Okunur\r\nMessage-ID: <{message_id}>\r\n\r\nmerhaba\r\n",
        carol_address.address, alice_address.address
    );
    let split = mail_key::encrypt_split(
        &[&carol_address.public_key],
        &carol_address.secret_key,
        mime.as_bytes(),
    )
    .unwrap();
    let meta = json!({
        "to": [{ "address": alice_address.address }],
        "subject": "Okunur",
        "messageId": message_id,
        "keyPackets": { "self": b64(&split.key_packets[0]) },
        "readable": [alice_address.address],
    });
    let r = bearer(c.post(format!("{base}/api/mail/send")), &carol.token)
        .multipart(form(vec![
            ("meta", serde_json::to_vec(&meta).unwrap()),
            ("data", split.data_packet),
            ("mime", mime.into_bytes()),
        ]))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "send: {}", r.status());
    let reply = wait_answers(&carol, "inbox", 1).remove(0);
    assert_eq!(reply["subject"], "Auto: Okunur");
}

#[test]
fn conversations_group_a_thread_in_one_row() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let alice_address = set_up_address(&c, &base, &alice);
    let bob = register(&c, &base);
    let bob_address = set_up_address(&c, &base, &bob);
    let domain = bob_address.address.split_once('@').unwrap().1.to_string();
    // Bob writes to Alice; `parent` makes it a reply in that thread.
    let send = |subject: &str, parent: Option<&str>| -> String {
        let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
        let mime = format!(
            "From: {}\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\nbody\r\n",
            bob_address.address, alice_address.address
        );
        let split = mail_key::encrypt_split(
            &[&alice_address.public_key, &bob_address.public_key],
            &bob_address.secret_key,
            mime.as_bytes(),
        )
        .unwrap();
        let mut meta = json!({
            "to": [{ "address": alice_address.address }],
            "subject": subject,
            "messageId": message_id,
            "keyPackets": { "self": b64(&split.key_packets[1]), alice_address.address.clone(): b64(&split.key_packets[0]) },
        });
        if let Some(parent) = parent {
            meta["inReplyTo"] = json!(parent);
            meta["references"] = json!([parent]);
        }
        let r = bearer(c.post(format!("{base}/api/mail/send")), &bob.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta).unwrap()),
                ("data", split.data_packet),
            ]))
            .send()
            .unwrap();
        assert!(r.status().is_success(), "send: {}", r.status());
        message_id
    };
    let list = |query: &str| -> Value {
        bearer(
            c.get(format!("{base}/api/mail/messages?folder=inbox{query}")),
            &alice.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap()
    };

    let first = send("Konu", None);
    let second = send("Re: Konu", Some(&first));
    let other = send("Başka", None);
    wait_for(&c, &base, &alice, &other);
    wait_for(&c, &base, &alice, &second);

    // By message: three rows, no conversation block.
    let messages = list("");
    assert_eq!(messages["messages"].as_array().unwrap().len(), 3);
    assert!(messages["messages"][0].get("conversation").is_none());
    // By conversation: two rows, newest conversation first.
    let page = list("&conversations=true");
    let rows = page["messages"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{page}");
    assert_eq!(rows[0]["messageId"], other.as_str());
    let thread = &rows[1];
    assert_eq!(
        thread["messageId"],
        second.as_str(),
        "the newest of the thread"
    );
    let conversation = &thread["conversation"];
    assert_eq!(conversation["members"].as_array().unwrap().len(), 2);
    assert_eq!(conversation["unread"], 2);
    assert_eq!(conversation["starred"], false);
    assert_eq!(
        conversation["senders"],
        json!([{ "address": bob_address.address, "name": "" }])
    );
    // Reading one leaves one unread.
    let first_id = conversation["members"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &alice.token)
        .json(&json!({ "ids": [first_id], "seen": true }))
        .send()
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(
        list("&conversations=true")["messages"][1]["conversation"]["unread"],
        1
    );
    // Pages count conversations.
    let one = list("&conversations=true&limit=1");
    assert_eq!(one["messages"].as_array().unwrap().len(), 1);
    let next = one["next"].as_str().unwrap().to_string();
    let rest = list(&format!("&conversations=true&limit=1&before={next}"));
    assert_eq!(rest["messages"][0]["messageId"], second.as_str());
    assert!(rest["next"].is_null());
    // The counts follow: two unread messages, one unread conversation.
    let counts = |query: &str| -> Value {
        let all: Value = bearer(
            c.get(format!("{base}/api/mail/counts{query}")),
            &alice.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        all.as_array()
            .unwrap()
            .iter()
            .find(|f| f["folder"] == "inbox")
            .cloned()
            .unwrap()
    };
    assert_eq!(counts("")["unread"], 2);
    assert_eq!(counts("")["total"], 3);
    assert_eq!(counts("?conversations=true")["unread"], 2);
    assert_eq!(counts("?conversations=true")["total"], 2);
}

#[test]
fn outside_sending_is_set_by_administrators() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let mut parts = admin.splitn(3, ':');
    let (email, username, password) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let admin = common::admin_token(&c, &base, email, password, username);
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let policy = |token: &str| -> (u16, Value) {
        let r = bearer(
            c.get(format!("{base}/api/admin/mail/outside-sending")),
            token,
        )
        .send()
        .unwrap();
        let status = r.status().as_u16();
        (status, r.json().unwrap_or(Value::Null))
    };
    let set = |token: &str, value: &str| -> u16 {
        bearer(
            c.put(format!("{base}/api/admin/mail/outside-sending")),
            token,
        )
        .json(&json!({ "outsideSending": value }))
        .send()
        .unwrap()
        .status()
        .as_u16()
    };
    let allowed = |token: &str| -> bool {
        let status: Value = bearer(c.get(format!("{base}/api/mail/sending")), token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        status["outsideAllowed"].as_bool().unwrap()
    };

    // The gate starts from MAIL_OUTSIDE_SENDING=on, seeded at start.
    assert_eq!(policy(&admin), (200, json!({ "outsideSending": "on" })));
    // Administrators only.
    assert_eq!(policy(&user.token).0, 403);
    assert_eq!(set(&user.token, "off"), 403);
    assert_eq!(set(&admin, "sometimes"), 400);

    // Admins: at once, without a restart, people are told and refused.
    assert_eq!(set(&admin, "admins"), 200);
    assert!(!allowed(&user.token));
    assert!(allowed(&admin));
    let (status, body) = code(send_plain(
        &c,
        &base,
        &user,
        &address,
        &["someone@example.org".to_string()],
        "dışarı",
    ));
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("outsideSendingOff"), "{body}");
    // Off: administrators too.
    assert_eq!(set(&admin, "off"), 200);
    assert!(!allowed(&admin));
    assert_eq!(policy(&admin).1, json!({ "outsideSending": "off" }));

    // Each change is in the audit log, from and to.
    let activity: Value = bearer(c.get(format!("{base}/api/admin/activity?limit=20")), &admin)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let changes: Vec<&Value> = activity["entries"]
        .as_array()
        .or_else(|| activity.as_array())
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "mail.outside_sending.update")
        .collect();
    assert!(
        changes
            .iter()
            .any(|e| e["payload"]["from"] == "admins" && e["payload"]["to"] == "off"),
        "{activity}"
    );

    // Back as the gate had it.
    assert_eq!(set(&admin, "on"), 200);
    assert!(allowed(&user.token));
}

#[test]
fn list_filters_and_sorts() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let alice_address = set_up_address(&c, &base, &alice);
    let bob = register(&c, &base);
    let bob_address = set_up_address(&c, &base, &bob);
    let domain = bob_address.address.split_once('@').unwrap().1.to_string();
    // Bob writes to Alice: `body` sets the size, `attachments` the count.
    let send = |subject: &str, body: &str, attachments: i32| -> String {
        let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
        let mime = format!(
            "From: {}\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\n{body}\r\n",
            bob_address.address, alice_address.address
        );
        let split = mail_key::encrypt_split(
            &[&alice_address.public_key, &bob_address.public_key],
            &bob_address.secret_key,
            mime.as_bytes(),
        )
        .unwrap();
        let meta = json!({
            "to": [{ "address": alice_address.address }],
            "subject": subject,
            "messageId": message_id,
            "attachmentCount": attachments,
            "attachments": (0..attachments)
                .map(|i| json!({ "name": format!("ek{i}.pdf"), "type": "application/pdf", "size": 100 + i }))
                .collect::<Vec<_>>(),
            "keyPackets": { "self": b64(&split.key_packets[1]), alice_address.address.clone(): b64(&split.key_packets[0]) },
        });
        let r = bearer(c.post(format!("{base}/api/mail/send")), &bob.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta).unwrap()),
                ("data", split.data_packet),
            ]))
            .send()
            .unwrap();
        assert!(r.status().is_success(), "send: {}", r.status());
        message_id
    };
    let subjects = |query: &str| -> (Vec<String>, Option<String>) {
        let page: Value = bearer(
            c.get(format!("{base}/api/mail/messages?folder=inbox{query}")),
            &alice.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        (
            page["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["subject"].as_str().unwrap().to_string())
                .collect(),
            page["next"].as_str().map(str::to_string),
        )
    };

    let small = send("küçük", "a", 0);
    std::thread::sleep(Duration::from_millis(20));
    let large = send("büyük", &"b".repeat(20_000), 2);
    std::thread::sleep(Duration::from_millis(20));
    let middle = send("orta", &"c".repeat(5_000), 0);
    wait_for(&c, &base, &alice, &small);
    wait_for(&c, &base, &alice, &large);
    let middle_row = wait_for(&c, &base, &alice, &middle);
    for conversations in ["", "&conversations=true"] {
        assert_eq!(subjects(conversations).0, ["orta", "büyük", "küçük"]);
        assert_eq!(
            subjects(&format!("&sort=oldest{conversations}")).0,
            ["küçük", "büyük", "orta"]
        );
        assert_eq!(
            subjects(&format!("&sort=largest{conversations}")).0,
            ["büyük", "orta", "küçük"]
        );
        assert_eq!(
            subjects(&format!("&sort=smallest{conversations}")).0,
            ["küçük", "orta", "büyük"]
        );
        assert_eq!(
            subjects(&format!("&attachments=true{conversations}")).0,
            ["büyük"]
        );
        // Pages follow the sort.
        let (first, next) = subjects(&format!("&sort=largest&limit=2{conversations}"));
        assert_eq!(first, ["büyük", "orta"]);
        let next = next.expect("a next page");
        assert_eq!(
            subjects(&format!(
                "&sort=largest&limit=2&before={next}{conversations}"
            ))
            .0,
            ["küçük"]
        );
        // Numbered pages (Proton's paging) carry the total.
        let numbered = |query: &str| -> (Vec<String>, Value) {
            let page: Value = bearer(
                c.get(format!(
                    "{base}/api/mail/messages?folder=inbox&sort=largest&limit=2{query}{conversations}"
                )),
                &alice.token,
            )
            .send()
            .unwrap()
            .json()
            .unwrap();
            let names = page["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["subject"].as_str().unwrap().to_string())
                .collect();
            (names, page["total"].clone())
        };
        assert_eq!(
            numbered("&page=0"),
            (vec!["büyük".into(), "orta".into()], json!(3))
        );
        assert_eq!(numbered("&page=1"), (vec!["küçük".into()], json!(3)));
        assert_eq!(numbered("&page=5"), (vec![], json!(3)));
        assert_eq!(numbered("&page=0&attachments=true").1, json!(1));
        assert_eq!(numbered("").1, Value::Null);
    }
    let r = bearer(
        c.get(format!(
            "{base}/api/mail/messages?folder=inbox&page=0&before=1_{}",
            uuid::Uuid::nil()
        )),
        &alice.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 400);
    // The files, readable for the list (Proton's AttachmentsMetadata); a
    // conversation row names each one's message.
    let rows = |query: &str| -> Vec<Value> {
        let page: Value = bearer(
            c.get(format!("{base}/api/mail/messages?folder=inbox{query}")),
            &alice.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        page["messages"].as_array().unwrap().clone()
    };
    let large_row = rows("")
        .into_iter()
        .find(|m| m["subject"] == "büyük")
        .unwrap();
    assert_eq!(
        large_row["attachments"],
        json!([
            { "name": "ek0.pdf", "type": "application/pdf", "size": 100 },
            { "name": "ek1.pdf", "type": "application/pdf", "size": 101 }
        ])
    );
    let conversation = rows("&conversations=true")
        .into_iter()
        .find(|m| m["subject"] == "büyük")
        .unwrap();
    let files = conversation["conversation"]["attachments"]
        .as_array()
        .unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|f| f["message"] == large_row["id"]));
    assert_eq!(
        rows("")
            .into_iter()
            .find(|m| m["subject"] == "küçük")
            .unwrap()["attachments"],
        json!([])
    );
    // Read and unread.
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &alice.token)
        .json(&json!({ "ids": [middle_row["id"]], "seen": true }))
        .send()
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(subjects("&unread=true").0, ["büyük", "küçük"]);
    assert_eq!(subjects("&unread=false").0, ["orta"]);
    assert_eq!(
        subjects("&unread=true&conversations=true").0,
        ["büyük", "küçük"]
    );
    let r = bearer(
        c.get(format!("{base}/api/mail/messages?folder=inbox&sort=random")),
        &alice.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 400);
}

#[test]
fn one_click_unsubscribe_goes_through_the_server() {
    let (Ok(base), Ok(smtp_address), Ok(keys)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_SMTP"),
        std::env::var("KUTUP_LIVE_KEYS"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_SMTP / KUTUP_LIVE_KEYS not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let alice_address = set_up_address(&c, &base, &alice);
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let message_id = format!("list-{tag}@lists.outside.test");
    let message = format!(
        "From: News <news@lists.outside.test>\r\nTo: {}\r\nSubject: Bülten\r\nMessage-ID: <{message_id}>\r\n\
         List-Unsubscribe: <https://lists.outside.test/u?id={tag}>, <mailto:leave@lists.outside.test>\r\n\
         List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=b\r\n\r\n\
         --b\r\nContent-Type: text/html\r\n\r\n<p>Haberler.</p><img src=cid:logo>\r\n\
         --b\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=logo.png\r\nContent-ID: <logo>\r\n\r\nPNG\r\n\
         --b\r\nContent-Type: application/pdf; name=bulten.pdf\r\nContent-Disposition: attachment; filename=bulten.pdf\r\n\r\nPDF-1\r\n\
         --b--\r\n",
        alice_address.address
    );
    let (rcpt, data) = smtp_send(&smtp_address, &alice_address.address, &message);
    assert_eq!((rcpt, data), (250, 250));
    let row = wait_for(&c, &base, &alice, &message_id);
    assert_eq!(row["unsubscribed"], false);
    // Noted on arrival: list mail (Proton's SpamAction asks on Spam).
    assert_eq!(row["unsubscribable"], true);
    // Its files, not the inline image, for the list.
    assert_eq!(
        row["attachments"],
        json!([{ "name": "bulten.pdf", "type": "application/pdf", "size": 5 }])
    );
    let id = row["id"].as_str().unwrap().to_string();

    // Someone else's message: not found.
    let eve = register(&c, &base);
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/{id}/receipt")),
        &eve.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), 404, "a read receipt for someone else's message");
    // The reader's read receipt is noted on the message (Proton's "Read receipt sent").
    assert_eq!(row["receiptSent"], false);
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/{id}/receipt")),
        &alice.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        wait_for(&c, &base, &alice, &message_id)["receiptSent"],
        true
    );
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/{id}/unsubscribe")),
        &eve.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), 404);

    // One click: the server POSTs RFC 8058's body to the list's URL.
    let r = bearer(
        c.post(format!("{base}/api/mail/messages/{id}/unsubscribe")),
        &alice.token,
    )
    .json(&json!({ "oneClickUrl": format!("https://lists.outside.test/u?id={tag}") }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 204, "{}", r.text().unwrap_or_default());
    let posts: Value = c
        .get(format!("{keys}/__posts"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let post = posts
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["path"] == format!("/lists.outside.test/u?id={tag}"))
        .expect("the one-click POST");
    assert_eq!(post["body"], "List-Unsubscribe=One-Click");
    assert_eq!(post["contentType"], "application/x-www-form-urlencoded");
    let row = wait_for(&c, &base, &alice, &message_id);
    assert_eq!(row["unsubscribed"], true);
}

#[test]
fn select_all_changes_a_whole_place() {
    use kutup_crypto::mail_names::MailNameKind::Label;
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let account = address.address.clone();
    for subject in ["Bir", "İki", "Üç"] {
        send_to_self(&c, &base, &user, &address, subject);
    }
    let inbox = |c: &Client| folder(c, &base, &user.token, "inbox");
    for _ in 0..100 {
        if inbox(&c).len() == 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(inbox(&c).len(), 3);
    let batch = |body: Value| {
        bearer(
            c.post(format!("{base}/api/mail/messages/batch")),
            &user.token,
        )
        .json(&body)
        .send()
        .unwrap()
    };
    let updated = |r: reqwest::blocking::Response| -> u64 {
        assert!(r.status().is_success(), "batch: {}", r.status());
        r.json::<Value>().unwrap()["updated"].as_u64().unwrap()
    };

    // Read, then unread: every message of the Inbox, past any page.
    assert_eq!(updated(batch(json!({ "place": "inbox", "seen": true }))), 3);
    assert!(inbox(&c).iter().all(|m| m["seen"] == true));
    // Into the Archive; the copies in Sent stay.
    assert_eq!(
        updated(batch(json!({ "place": "inbox", "folder": "archive" }))),
        3
    );
    assert!(inbox(&c).is_empty());
    assert_eq!(folder(&c, &base, &user.token, "archive").len(), 3);
    assert_eq!(folder(&c, &base, &user.token, "sent").len(), 3);
    // A label on everything archived, then off.
    let label = uuid::Uuid::new_v4().to_string();
    let r = bearer(c.post(format!("{base}/api/mail/labels")), &user.token)
        .json(&json!({ "id": label, "name": sealed_name(&user, &account, Label, &label, "Hepsi"), "color": "#22aa55" }))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    assert_eq!(
        updated(batch(json!({ "place": "archive", "addLabels": [label] }))),
        3
    );
    assert_eq!(
        folder(&c, &base, &user.token, &format!("label:{label}")).len(),
        3
    );
    assert_eq!(
        updated(batch(
            json!({ "place": format!("label:{label}"), "removeLabels": [label] })
        )),
        3
    );
    assert!(folder(&c, &base, &user.token, &format!("label:{label}")).is_empty());
    // Someone else's mail is out of reach: Eve's batch changes her own
    // (empty) Inbox, a mailbox she is not a member of is not found, and
    // Alice's label is not hers to use.
    let eve = register(&c, &base);
    let as_eve = |body: Value| {
        bearer(
            c.post(format!("{base}/api/mail/messages/batch")),
            &eve.token,
        )
        .json(&body)
        .send()
        .unwrap()
    };
    assert_eq!(
        updated(as_eve(json!({ "place": "archive", "seen": false }))),
        0
    );
    assert!(folder(&c, &base, &user.token, "archive")
        .iter()
        .all(|m| m["seen"] == true));
    let r = as_eve(
        json!({ "place": "archive", "seen": false, "group": uuid::Uuid::new_v4().to_string() }),
    );
    assert_eq!(r.status(), 404);
    let r = as_eve(json!({ "place": "archive", "addLabels": [label] }));
    assert_eq!(r.status(), 400);
    let r = as_eve(json!({ "place": format!("label:{label}"), "seen": false }));
    assert_eq!(updated(r), 0);
    // All mail, an unknown place and an empty change are refused.
    for body in [
        json!({ "place": "all", "seen": true }),
        json!({ "place": "elsewhere", "seen": true }),
        json!({ "place": "archive" }),
    ] {
        assert_eq!(batch(body.clone()).status(), 400, "{body}");
    }
}

#[test]
fn senders_whose_images_always_load() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let alice = register(&c, &base);
    let eve = register(&c, &base);
    let list = |token: &str| -> Vec<String> {
        let rows: Value = bearer(c.get(format!("{base}/api/mail/image-senders")), token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .map(|r| r["address"].as_str().unwrap().to_string())
            .collect()
    };
    let post = |path: &str, token: &str, body: Value| {
        bearer(c.post(format!("{base}{path}")), token)
            .json(&body)
            .send()
            .unwrap()
            .status()
            .as_u16()
    };
    // Kept lowercase, once; a domain or nonsense is not a sender.
    assert_eq!(
        post(
            "/api/mail/image-senders",
            &alice.token,
            json!({ "address": "News@Example.org" })
        ),
        204
    );
    assert_eq!(
        post(
            "/api/mail/image-senders",
            &alice.token,
            json!({ "address": "news@example.org" })
        ),
        204
    );
    assert_eq!(list(&alice.token), ["news@example.org"]);
    assert_eq!(
        post(
            "/api/mail/image-senders",
            &alice.token,
            json!({ "address": "example.org" })
        ),
        400
    );
    assert_eq!(
        post(
            "/api/mail/image-senders",
            &alice.token,
            json!({ "address": "not an address" })
        ),
        400
    );
    // Each account's own.
    assert!(list(&eve.token).is_empty());
    assert_eq!(
        post(
            "/api/mail/image-senders/delete",
            &eve.token,
            json!({ "address": "news@example.org" })
        ),
        204
    );
    assert_eq!(list(&alice.token), ["news@example.org"]);
    assert_eq!(
        post(
            "/api/mail/image-senders/delete",
            &alice.token,
            json!({ "address": "NEWS@example.org" })
        ),
        204
    );
    assert!(list(&alice.token).is_empty());
}

#[test]
fn undo_send_holds_a_draft_then_sends_it() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let domain = address.address.split_once('@').unwrap().1.to_string();
    let settings = |body: Value| {
        let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
            .json(&body)
            .send()
            .unwrap();
        assert!(r.status().is_success(), "settings: {}", r.status());
    };
    // A draft to herself, and its send (end to end, her own key packet).
    let make_draft = |subject: &str| -> (String, String) {
        let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
        let own =
            mail_key::encrypt_split(&[&address.public_key], &address.secret_key, b"draft").unwrap();
        let r = bearer(c.post(format!("{base}/api/mail/drafts")), &user.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&json!({ "subject": subject, "to": [{ "address": address.address }], "messageId": message_id })).unwrap()),
                ("body", [own.key_packets[0].as_slice(), &own.data_packet].concat()),
            ]))
            .send()
            .unwrap();
        assert_eq!(r.status(), 200);
        let id = r.json::<Value>().unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        (id, message_id)
    };
    let send = |draft: &str, message_id: &str, subject: &str| {
        let mime = format!("From: {0}\r\nTo: {0}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\nbody\r\n", address.address);
        let split =
            mail_key::encrypt_split(&[&address.public_key], &address.secret_key, mime.as_bytes())
                .unwrap();
        let packet = b64(&split.key_packets[0]);
        let meta = json!({
            "to": [{ "address": address.address }],
            "subject": subject,
            "messageId": message_id,
            "draftId": draft,
            "keyPackets": { "self": packet, address.address.clone(): packet },
        });
        bearer(c.post(format!("{base}/api/mail/send")), &user.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta).unwrap()),
                ("data", split.data_packet),
            ]))
            .send()
            .unwrap()
    };
    let status = |id: &str, token: &str| {
        bearer(c.get(format!("{base}/api/mail/outbox/{id}")), token)
            .send()
            .unwrap()
    };
    let cancel = |id: &str| {
        bearer(
            c.post(format!("{base}/api/mail/outbox/{id}/cancel")),
            &user.token,
        )
        .send()
        .unwrap()
        .status()
        .as_u16()
    };
    let in_drafts = |id: &str| {
        folder(&c, &base, &user.token, "drafts")
            .iter()
            .any(|m| m["id"] == id)
    };
    settings(json!({ "delaySendSeconds": 5 }));

    // Held: the draft stays, cannot change, and Undo keeps it a draft.
    let (draft, message_id) = make_draft("Geri al");
    let r = send(&draft, &message_id, "Geri al");
    assert_eq!(r.status(), 202, "{}", r.text().unwrap_or_default());
    let held: Value = r.json().unwrap();
    let outbox = held["outboxId"].as_str().unwrap().to_string();
    assert!(in_drafts(&draft));
    let r = bearer(
        c.put(format!("{base}/api/mail/drafts/{draft}")),
        &user.token,
    )
    .multipart(form(vec![("meta", b"{}".to_vec())]))
    .send()
    .unwrap();
    assert_eq!(r.status(), 409, "a held draft does not change");
    // A second send of the same draft while one waits is refused.
    assert_eq!(send(&draft, &message_id, "Geri al").status(), 409);
    // Someone else's: not found.
    let eve = register(&c, &base);
    assert_eq!(status(&outbox, &eve.token).status(), 404);
    assert_eq!(cancel(&outbox), 204);
    assert_eq!(cancel(&outbox), 409, "taken back once");
    assert_eq!(
        status(&outbox, &user.token).json::<Value>().unwrap()["state"],
        "cancelled"
    );
    std::thread::sleep(Duration::from_secs(6));
    assert!(in_drafts(&draft), "a taken-back send leaves its draft");
    assert!(!folder(&c, &base, &user.token, "inbox")
        .iter()
        .any(|m| m["subject"] == "Geri al"));

    // Sent again and left alone: it goes when the delay is up.
    let r = send(&draft, &message_id, "Geri al");
    assert_eq!(r.status(), 202);
    let outbox = r.json::<Value>().unwrap()["outboxId"]
        .as_str()
        .unwrap()
        .to_string();
    let mut sent = Value::Null;
    for _ in 0..40 {
        sent = status(&outbox, &user.token).json().unwrap();
        if sent["state"] == "sent" || sent["state"] == "failed" {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(sent["state"], "sent", "{sent}");
    assert_eq!(sent["result"]["recipients"][0]["status"], "delivered");
    assert!(!in_drafts(&draft), "the draft became the sent message");
    assert!(folder(&c, &base, &user.token, "inbox")
        .iter()
        .any(|m| m["subject"] == "Geri al"));
    assert_eq!(cancel(&outbox), 409);

    // Undo send off: sent at once.
    settings(json!({ "delaySendSeconds": 0 }));
    let (draft, message_id) = make_draft("Hemen");
    assert_eq!(send(&draft, &message_id, "Hemen").status(), 200);
    let r = bearer(c.patch(format!("{base}/api/mail/settings")), &user.token)
        .json(&json!({ "delaySendSeconds": 7 }))
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[test]
fn scheduled_send_waits_in_scheduled_then_goes() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    let domain = address.address.split_once('@').unwrap().1.to_string();
    let make_draft = |subject: &str| -> (String, String) {
        let message_id = format!("{}@{domain}", uuid::Uuid::new_v4().simple());
        let own =
            mail_key::encrypt_split(&[&address.public_key], &address.secret_key, b"draft").unwrap();
        let r = bearer(c.post(format!("{base}/api/mail/drafts")), &user.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&json!({ "subject": subject, "to": [{ "address": address.address }], "messageId": message_id })).unwrap()),
                ("body", [own.key_packets[0].as_slice(), &own.data_packet].concat()),
            ]))
            .send()
            .unwrap();
        assert_eq!(r.status(), 200);
        (
            r.json::<Value>().unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string(),
            message_id,
        )
    };
    let send = |draft: &str, message_id: &str, subject: &str, at: time::OffsetDateTime| {
        let mime = format!("From: {0}\r\nTo: {0}\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n\r\nbody\r\n", address.address);
        let split =
            mail_key::encrypt_split(&[&address.public_key], &address.secret_key, mime.as_bytes())
                .unwrap();
        let packet = b64(&split.key_packets[0]);
        let meta = json!({
            "to": [{ "address": address.address }],
            "subject": subject,
            "messageId": message_id,
            "draftId": draft,
            "scheduleAt": at.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "keyPackets": { "self": packet, address.address.clone(): packet },
        });
        bearer(c.post(format!("{base}/api/mail/send")), &user.token)
            .multipart(form(vec![
                ("meta", serde_json::to_vec(&meta).unwrap()),
                ("data", split.data_packet),
            ]))
            .send()
            .unwrap()
    };
    let now = time::OffsetDateTime::now_utc;
    let in_folder = |name: &str, id: &str| {
        folder(&c, &base, &user.token, name)
            .iter()
            .any(|m| m["id"] == id)
    };

    // Too soon or too far: refused.
    let (draft, message_id) = make_draft("Sonra");
    assert_eq!(
        send(
            &draft,
            &message_id,
            "Sonra",
            now() + time::Duration::seconds(10)
        )
        .status(),
        400
    );
    assert_eq!(
        send(
            &draft,
            &message_id,
            "Sonra",
            now() + time::Duration::days(91)
        )
        .status(),
        400
    );

    // Scheduled: in Scheduled with its time; Edit takes it back to Drafts.
    let r = send(
        &draft,
        &message_id,
        "Sonra",
        now() + time::Duration::hours(2),
    );
    assert_eq!(r.status(), 202, "{}", r.text().unwrap_or_default());
    let outbox = r.json::<Value>().unwrap()["outboxId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(in_folder("scheduled", &draft) && !in_folder("drafts", &draft));
    let row = folder(&c, &base, &user.token, "scheduled")
        .into_iter()
        .find(|m| m["id"] == draft.as_str())
        .unwrap();
    assert_eq!(row["outboxId"], outbox.as_str());
    assert!(row["scheduledAt"].is_string());
    // A scheduled message is not moved away meanwhile.
    let moved = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [draft], "folder": "trash" }))
        .send()
        .unwrap();
    assert_eq!(moved.json::<Value>().unwrap()["updated"], 0);
    let r = bearer(
        c.post(format!("{base}/api/mail/outbox/{outbox}/cancel")),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 204);
    assert!(in_folder("drafts", &draft) && !in_folder("scheduled", &draft));

    // Scheduled a minute ahead and left alone: it goes then.
    let r = send(
        &draft,
        &message_id,
        "Sonra",
        now() + time::Duration::seconds(62),
    );
    assert_eq!(r.status(), 202);
    let outbox = r.json::<Value>().unwrap()["outboxId"]
        .as_str()
        .unwrap()
        .to_string();
    let mut state = Value::Null;
    for _ in 0..100 {
        state = bearer(
            c.get(format!("{base}/api/mail/outbox/{outbox}")),
            &user.token,
        )
        .send()
        .unwrap()
        .json::<Value>()
        .unwrap()["state"]
            .clone();
        if state == "sent" || state == "failed" {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    assert_eq!(state, "sent");
    assert!(!in_folder("scheduled", &draft) && !in_folder("drafts", &draft));
    assert!(folder(&c, &base, &user.token, "inbox")
        .iter()
        .any(|m| m["subject"] == "Sonra"));
}

#[test]
fn snoozed_mail_comes_back_unread() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let address = set_up_address(&c, &base, &user);
    send_to_self(&c, &base, &user, &address, "Sonra bak");
    let find = |name: &str| -> Option<Value> {
        folder(&c, &base, &user.token, name)
            .into_iter()
            .find(|m| m["subject"] == "Sonra bak" && m["direction"] == "inbound")
    };
    let mut row = None;
    for _ in 0..100 {
        row = find("inbox");
        if row.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let id = row.expect("delivered")["id"].as_str().unwrap().to_string();
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [id], "seen": true }))
        .send()
        .unwrap();
    assert!(r.status().is_success());
    let snooze = |token: &str, until: Option<time::OffsetDateTime>| {
        let until = until.map(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        });
        bearer(c.post(format!("{base}/api/mail/messages/snooze")), token)
            .json(&json!({ "ids": [id], "until": until }))
            .send()
            .unwrap()
    };
    let updated = |r: reqwest::blocking::Response| -> u64 {
        assert!(r.status().is_success(), "{}", r.status());
        r.json::<Value>().unwrap()["updated"].as_u64().unwrap()
    };
    let now = time::OffsetDateTime::now_utc;
    // Too soon or too far: refused; someone else's: untouched.
    assert_eq!(
        snooze(&user.token, Some(now() + time::Duration::seconds(5))).status(),
        400
    );
    assert_eq!(
        snooze(&user.token, Some(now() + time::Duration::days(400))).status(),
        400
    );
    let eve = register(&c, &base);
    assert_eq!(
        updated(snooze(&eve.token, Some(now() + time::Duration::hours(1)))),
        0
    );

    // Snoozed: out of the Inbox, in Snoozed with its time; Unsnooze brings it back.
    assert_eq!(
        updated(snooze(&user.token, Some(now() + time::Duration::hours(3)))),
        1
    );
    assert!(find("inbox").is_none());
    assert!(find("snoozed").expect("snoozed")["snoozedUntil"].is_string());
    assert_eq!(updated(snooze(&user.token, None)), 1);
    assert!(find("inbox").is_some() && find("snoozed").is_none());

    // Left alone: back in the Inbox at its time, unread.
    assert_eq!(
        updated(snooze(
            &user.token,
            Some(now() + time::Duration::seconds(61))
        )),
        1
    );
    let mut back = None;
    for _ in 0..120 {
        back = find("inbox");
        if back.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let back = back.expect("back in the Inbox");
    assert_eq!(back["seen"], false);
    assert!(back["snoozedUntil"].is_null());

    // Moved away while snoozed: no longer waiting.
    assert_eq!(
        updated(snooze(&user.token, Some(now() + time::Duration::hours(1)))),
        1
    );
    let r = bearer(c.patch(format!("{base}/api/mail/messages")), &user.token)
        .json(&json!({ "ids": [id], "folder": "archive" }))
        .send()
        .unwrap();
    assert_eq!(r.json::<Value>().unwrap()["updated"], 1);
    assert!(find("archive").expect("archived")["snoozedUntil"].is_null());
}
