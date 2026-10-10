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
