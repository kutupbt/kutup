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
