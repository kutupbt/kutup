//! Live e2e for the chat v1 wire contract (`docs/chat-protocol.md`).
//!
//! The server is crypto-blind — it only validates base64 and routes opaque
//! ciphertext — so this exercises the *entire* server-side contract with
//! synthetic base64 blobs, no libsignal needed. It registers/logs in real
//! accounts (full account crypto via `kutup-crypto`), then drives device
//! registration, bundle fetch, send + `sendId` idempotency, `maxContentBytes`,
//! the 409 device-list contract, cursor paging, and ack.
//!
//! Gated on `KUTUP_LIVE_SERVER` so a normal `cargo test` skips it:
//!   KUTUP_LIVE_SERVER=https://localhost:38443 KUTUP_INSECURE_TLS=1 \
//!     cargo test -p kutup-server --test chat_live -- --nocapture

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use reqwest::blocking::Client;
use serde_json::{json, Value};

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Registers a fresh account and returns `(email, username, access_token)`.
fn register_and_login(c: &Client, base: &str, tag: &str) -> (String, String, String) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("chat-{tag}-{ts}@example.com");
    let username = format!("chat{tag}{}", ts % 100000);
    let password = "chat-pw-123456";

    let mut rng = rand::thread_rng();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    let mut kdf_salt = [0u8; 16];
    let mut login_key_salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut kdf_salt);
    rng.fill_bytes(&mut login_key_salt);

    let kek = kutup_crypto::kdf::derive_kek(password, &kdf_salt).unwrap();
    let login_key = kutup_crypto::kdf::derive_login_key(password, &login_key_salt).unwrap();
    let (public_key, secret_key) = kutup_crypto::sealedbox::generate_keypair();
    let (enc_mk, mk_nonce) = kutup_crypto::secretbox::seal(&master_key, kek.as_slice()).unwrap();
    let (enc_rk, rk_nonce) = kutup_crypto::secretbox::seal(&master_key, &recovery_entropy).unwrap();
    let (enc_pk, pk_nonce) = kutup_crypto::secretbox::seal(&secret_key, &master_key).unwrap();

    let reg = json!({
        "email": email, "username": username,
        "loginKey": b64(login_key.as_slice()),
        "encryptedMasterKey": b64(&enc_mk), "masterKeyNonce": b64(&mk_nonce),
        "encryptedRecoveryKey": b64(&enc_rk), "recoveryKeyNonce": b64(&rk_nonce),
        "encryptedPrivateKey": b64(&enc_pk), "privateKeyNonce": b64(&pk_nonce),
        "publicKey": b64(&public_key),
        "kdfSalt": b64(&kdf_salt), "loginKeySalt": b64(&login_key_salt),
        "recoveryProof": b64(&recovery_entropy),
    });
    let r = c
        .post(format!("{base}/api/auth/register"))
        .json(&reg)
        .send()
        .unwrap();
    assert!(r.status().is_success(), "register {tag}: {}", r.status());

    // login: preflight → derive login key from returned salt → POST login.
    let pf: Value = c
        .get(format!("{base}/api/auth/login/preflight?email={email}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let lks = pf["loginKeySalt"].as_str().unwrap();
    let lk = kutup_crypto::kdf::derive_login_key_b64(password, lks).unwrap();
    let resp: Value = c
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "email": email, "loginKey": b64(lk.as_slice()) }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let token = resp["accessToken"].as_str().unwrap().to_string();
    (email, username, token)
}

/// A synthetic (base64-valid, crypto-meaningless) chat device registration.
fn register_chat_device(c: &Client, base: &str, token: &str) -> (u32, u32) {
    let mut rng = rand::thread_rng();
    let reg_id = (rng.next_u32() % 16000) + 1;
    let key = |n: u8| b64(&[n; 33]);
    let body = json!({
        "suite": 1, "registrationId": reg_id,
        "identityKey": key(1),
        "signedPreKey": { "keyId": 1, "publicKey": key(2), "signature": key(3) },
        "lastResortKyberPreKey": { "keyId": 1, "publicKey": key(4), "signature": key(5) },
        "oneTimePreKeys": [ { "keyId": 10, "publicKey": key(6) } ],
        "oneTimeKyberPreKeys": [ { "keyId": 20, "publicKey": key(7), "signature": key(8) } ],
        "name": "live-test-device"
    });
    let r = c
        .post(format!("{base}/api/chat/device"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .unwrap();
    assert!(r.status().is_success(), "register device: {}", r.status());
    let v: Value = r.json().unwrap();
    let device_id = v["deviceId"].as_u64().unwrap() as u32;

    // An ambiguous first response is retried with the exact durable request.
    // The identity key is install-unique, so the server must return the same id
    // without creating a second directory row.
    let retry = c
        .post(format!("{base}/api/chat/device"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .unwrap();
    assert!(
        retry.status().is_success(),
        "retry device registration: {}",
        retry.status()
    );
    let retry_body: Value = retry.json().unwrap();
    assert_eq!(retry_body["deviceId"], device_id);

    (device_id, reg_id)
}

#[test]
fn chat_v1_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset — skipping live chat test");
        return;
    };
    let c = client();

    // Capability block is unauthenticated (§10).
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let chat = &settings["chat"];
    assert_eq!(chat["enabled"], true, "chat capability advertised");
    assert_eq!(chat["protocolVersion"], 1);
    assert_eq!(chat["suites"], json!([1]));
    let max = chat["maxContentBytes"].as_u64().unwrap();
    assert_eq!(max, 65536);
    assert_eq!(chat["sealedSender"], false);
    assert_eq!(chat["manifests"], true);
    assert!(chat["mailboxRetentionDays"].is_number());
    assert!(chat["deviceExpiryDays"].is_number());
    println!("ok  - capability block");

    let (_ea, ua, ta) = register_and_login(&c, &base, "a");
    let (_eb, ub, tb) = register_and_login(&c, &base, "b");
    println!("ok  - two accounts registered + logged in");

    let (dev_a, _reg_a) = register_chat_device(&c, &base, &ta);
    let (dev_b, reg_b) = register_chat_device(&c, &base, &tb);
    println!("ok  - chat devices registered (A={dev_a} B={dev_b})");

    let ticket: Value = c
        .post(format!("{base}/api/chat/ws-ticket?deviceId={dev_a}"))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(ticket["ticket"]
        .as_str()
        .is_some_and(|value| value.len() >= 40));
    assert!(ticket["expiresAt"].is_string());
    println!("ok  - one-time chat WebSocket ticket minted");

    // A fetches B's bundles: kyber always present, one-time EC consumed.
    let bundles: Value = c
        .get(format!("{base}/api/chat/users/{ub}/keys"))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let devs = bundles["devices"].as_array().unwrap();
    assert_eq!(devs.len(), 1, "B has one device");
    let d = &devs[0];
    assert_eq!(d["deviceId"], dev_b);
    assert!(d["kyberPreKey"].is_object(), "PQ prekey never absent");
    assert!(
        d["oneTimePreKey"].is_object(),
        "one-time EC consumed by fetch"
    );
    println!("ok  - bundle fetch shape");

    let send = |send_id: &str, dev: u32, reg: u32, content: &str| {
        c.post(format!("{base}/api/chat/users/{ub}/messages"))
            .bearer_auth(&ta)
            .json(&json!({
                "senderDeviceId": dev_a,
                "sendId": send_id,
                "envelopes": [ { "deviceId": dev, "registrationId": reg,
                                 "envelopeType": "message", "suite": 1, "content": content } ],
            }))
            .send()
            .unwrap()
    };

    // Correct send.
    let sid = "11111111-1111-4111-8111-111111111111";
    let r = send(sid, dev_b, reg_b, &b64(b"ciphertext-one"));
    assert!(r.status().is_success(), "send: {}", r.status());
    let body: Value = r.json().unwrap();
    assert_eq!(body["stored"], 1);
    assert!(body.get("deduplicated").is_none());
    println!("ok  - send stored");

    // Idempotent retry: same sendId → deduplicated, no new row.
    let r = send(sid, dev_b, reg_b, &b64(b"ciphertext-one"));
    let body: Value = r.json().unwrap();
    assert_eq!(body["deduplicated"], true, "sendId dedupe");
    println!("ok  - sendId idempotency");

    // maxContentBytes: oversized content → 413.
    let big = b64(&vec![0u8; 70_000]);
    let r = send("22222222-2222-4222-8222-222222222222", dev_b, reg_b, &big);
    assert_eq!(r.status().as_u16(), 413, "oversized content rejected");
    println!("ok  - maxContentBytes enforced (413)");

    // Device-list mismatch: unknown device → 409 extraDevices.
    let r = send(
        "33333333-3333-4333-8333-333333333333",
        99,
        reg_b,
        &b64(b"x"),
    );
    assert_eq!(r.status().as_u16(), 409);
    let m: Value = r.json().unwrap();
    assert_eq!(m["extraDevices"], json!([99]));
    // (missing device 1 too, since we only addressed 99)
    assert_eq!(m["missingDevices"], json!([dev_b]));
    println!("ok  - 409 device-list mismatch");

    // Send a second real message so drain paging has 2 rows.
    let r = send(
        "44444444-4444-4444-8444-444444444444",
        dev_b,
        reg_b,
        &b64(b"ciphertext-two"),
    );
    assert!(r.status().is_success());

    // B drains: 2 envelopes, sender=A username, monotonic cursor.
    let page: Value = c
        .get(format!("{base}/api/chat/messages?deviceId={dev_b}&limit=1"))
        .bearer_auth(&tb)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let envs = page["envelopes"].as_array().unwrap();
    assert_eq!(envs.len(), 1, "limit=1 returns one");
    assert_eq!(page["more"], true, "more pages");
    let c0 = envs[0]["cursor"].as_u64().unwrap();
    assert_eq!(envs[0]["sender"], json!(ua), "sender is A's username");
    let first_id = envs[0]["id"].as_str().unwrap().to_string();
    println!("ok  - drain page 1 (cursor={c0})");

    // Page 2 via ?after=cursor.
    let page2: Value = c
        .get(format!(
            "{base}/api/chat/messages?deviceId={dev_b}&limit=10&after={c0}"
        ))
        .bearer_auth(&tb)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let envs2 = page2["envelopes"].as_array().unwrap();
    assert_eq!(envs2.len(), 1, "second (and last) message");
    assert_eq!(page2["more"], false);
    assert!(
        envs2[0]["cursor"].as_u64().unwrap() > c0,
        "cursor strictly increases"
    );
    println!("ok  - cursor paging (?after=)");

    // Ack the first; it disappears from a fresh drain.
    let r = c
        .post(format!("{base}/api/chat/messages/ack?deviceId={dev_b}"))
        .bearer_auth(&tb)
        .json(&json!({ "ids": [first_id] }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "ack: {}", r.status());
    let after_ack: Value = c
        .get(format!(
            "{base}/api/chat/messages?deviceId={dev_b}&limit=10"
        ))
        .bearer_auth(&tb)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        after_ack["envelopes"].as_array().unwrap().len(),
        1,
        "one remains after acking one of two"
    );
    println!("ok  - ack deletes");

    println!("\nALL CHAT v1 CONTRACT CHECKS PASSED");
}
