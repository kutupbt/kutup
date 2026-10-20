//! Multi-recipient sends (docs/plans/pairwise-groups.md, slice 2): one group
//! message to member accounts of one server, sent once, checked by group
//! capability, then budgets, then devices, stored once and drained by each
//! device as its ordinary sealed envelope.
//!
//! Needs `KUTUP_LIVE_GROUPS_SERVER` (`CHAT_GROUPS=true` and federation). With
//! `KUTUP_FEDERATION_SERVER_A` and `KUTUP_FEDERATION_SERVER_B` set, a send
//! through A to B's members runs too, forwarded and answered at once; with
//! `KUTUP_MULTI_PEER_DOWN` set (the gate stops B), A answers `503`. The
//! server never decrypts, so the sends here are libsignal's sent layout with
//! made-up key material and ciphertext; a real end-to-end send is the
//! client's to test.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn base() -> Option<String> {
    let Ok(base) = std::env::var("KUTUP_LIVE_GROUPS_SERVER") else {
        eprintln!("KUTUP_LIVE_GROUPS_SERVER not set; skipping");
        return None;
    };
    Some(base.trim_end_matches('/').to_string())
}

/// A member with Chat devices and a published group capability.
struct Member {
    user: User,
    account_id: String,
    /// Device id and registration id.
    devices: Vec<(u32, u32)>,
    capability: [u8; 16],
}

fn add_device(c: &Client, base: &str, user: &User, seed: u8) -> (u32, u32) {
    let registration_id = 6000 + u32::from(seed);
    let key = |offset: u8| STANDARD.encode([seed.wrapping_add(offset); 33]);
    let device: Value = bearer(c.post(format!("{base}/api/chat/device")), &user.token)
        .json(&json!({
            "suite": 1,
            "registrationId": registration_id,
            "identityKey": key(1),
            "signedPreKey": {"keyId": 1, "publicKey": key(2), "signature": key(3)},
            "lastResortKyberPreKey": {"keyId": 1, "publicKey": key(4), "signature": key(5)},
            "oneTimePreKeys": [{"keyId": 10, "publicKey": key(6)}],
            "oneTimeKyberPreKeys": [{"keyId": 20, "publicKey": key(7), "signature": key(8)}],
            "name": format!("multi-test-{seed}")
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    (
        device["deviceId"].as_u64().expect("a device id") as u32,
        registration_id,
    )
}

fn member(c: &Client, base: &str, seeds: &[u8]) -> Member {
    let user = register(c, base);
    let devices = seeds
        .iter()
        .map(|seed| add_device(c, base, &user, *seed))
        .collect();
    let capability = [seeds[0]; 16];
    let r = bearer(
        c.put(format!("{base}/api/chat/group-capabilities")),
        &user.token,
    )
    .json(&json!({ "add": [STANDARD.encode(Sha256::digest(capability))] }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "publish the capability");
    Member {
        account_id: user.person.account_id.clone(),
        user,
        devices,
        capability,
    }
}

/// libsignal's sent sealed-sender v2 layout (version `0x23`): each
/// recipient's 17-byte service id (an ACI: a zero byte and its account id),
/// its devices and its 48 bytes of key material, then the shared part.
/// A recipient as laid out here: its account id, its devices (id and
/// registration id) and the byte its key material is filled with.
type SentRecipient<'a> = (&'a str, &'a [(u32, u32)], u8);

fn sent(recipients: &[SentRecipient], shared: &[u8]) -> Vec<u8> {
    let mut message = vec![0x23, recipients.len() as u8];
    for (account, devices, fill) in recipients {
        message.push(0);
        message.extend_from_slice(Uuid::parse_str(account).unwrap().as_bytes());
        for (index, (device, registration)) in devices.iter().enumerate() {
            message.push(*device as u8);
            let more = if index + 1 < devices.len() { 0x8000 } else { 0 };
            message.extend_from_slice(&((*registration as u16) | more).to_be_bytes());
        }
        message.extend_from_slice(&[*fill; 48]);
    }
    message.extend_from_slice(shared);
    message
}

fn post(c: &Client, base: &str, body: Value) -> (StatusCode, Value) {
    let r = c
        .post(format!("{base}/api/chat/anonymous/messages/multi"))
        .json(&body)
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

fn submission(send_id: &str, payload: &[u8], capabilities: &[(&Member, [u8; 16])]) -> Value {
    json!({
        "sendId": send_id,
        "payload": STANDARD.encode(payload),
        "capabilities": capabilities
            .iter()
            .map(|(member, capability)| (member.account_id.clone(), json!(STANDARD.encode(capability))))
            .collect::<serde_json::Map<_, _>>(),
    })
}

fn drain(c: &Client, base: &str, member: &Member, device: u32) -> Vec<Value> {
    let page: Value = bearer(
        c.get(format!("{base}/api/chat/messages?deviceId={device}")),
        &member.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    page["envelopes"].as_array().unwrap().clone()
}

fn ack(c: &Client, base: &str, member: &Member, device: u32, envelopes: &[Value]) {
    let ids: Vec<&str> = envelopes
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    let r = bearer(
        c.post(format!("{base}/api/chat/messages/ack?deviceId={device}")),
        &member.user.token,
    )
    .json(&json!({ "ids": ids }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// What a device drains for a multi-recipient send: libsignal's received
/// message, `0x22 ‖ C_i ‖ AT_i ‖ shared`.
fn received(fill: u8, shared: &[u8]) -> String {
    let mut message = vec![0x22];
    message.extend_from_slice(&[fill; 48]);
    message.extend_from_slice(shared);
    STANDARD.encode(message)
}

#[test]
fn a_group_message_is_stored_once_and_drained_by_every_device() {
    let Some(base) = base() else { return };
    let c = client();
    let bob = member(&c, &base, &[31, 32]);
    let carol = member(&c, &base, &[33]);
    let shared = [0x5au8; 300];
    let payload = sent(
        &[
            (&bob.account_id, &bob.devices, 1),
            (&carol.account_id, &carol.devices, 2),
        ],
        &shared,
    );
    let send_id = Uuid::new_v4().to_string();
    let body = submission(
        &send_id,
        &payload,
        &[(&bob, bob.capability), (&carol, carol.capability)],
    );
    let (status, answer) = post(&c, &base, body.clone());
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([]));
    assert_eq!(answer["rateLimited"], json!([]));

    // Each device drains its own copy, assembled from the one stored part.
    for (device, _) in &bob.devices {
        let got = drain(&c, &base, &bob, *device);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0]["content"], received(1, &shared));
        assert_eq!(got[0]["sealedSender"], true);
        assert_eq!(got[0]["sendId"], send_id.as_str());
    }
    let carols = drain(&c, &base, &carol, carol.devices[0].0);
    assert_eq!(carols.len(), 1);
    assert_eq!(carols[0]["content"], received(2, &shared));

    // The same send again stores nothing more.
    let (status, _) = post(&c, &base, body);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(drain(&c, &base, &carol, carol.devices[0].0).len(), 1);

    // Every device acks; the shared part goes with the last (the gate then
    // checks no shared payload is left).
    for (device, _) in &bob.devices {
        let got = drain(&c, &base, &bob, *device);
        ack(&c, &base, &bob, *device, &got);
    }
    ack(&c, &base, &carol, carol.devices[0].0, &carols);
    for (device, _) in &bob.devices {
        assert!(drain(&c, &base, &bob, *device).is_empty());
    }
    purge_accounts(&c, &base, &[&bob.user, &carol.user]);
}

#[test]
fn capabilities_then_devices_answer_each_account() {
    let Some(base) = base() else { return };
    let c = client();
    let bob = member(&c, &base, &[41, 42]);
    let carol = member(&c, &base, &[43]);
    let shared = [0x6bu8; 120];

    // A wrong capability for Carol: she is refused, Bob still delivered.
    let payload = sent(
        &[
            (&bob.account_id, &bob.devices, 1),
            (&carol.account_id, &carol.devices, 2),
        ],
        &shared,
    );
    let (status, answer) = post(
        &c,
        &base,
        submission(
            &Uuid::new_v4().to_string(),
            &payload,
            &[(&bob, bob.capability), (&carol, [0xee; 16])],
        ),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([carol.account_id]));
    assert_eq!(drain(&c, &base, &bob, bob.devices[0].0).len(), 1);
    assert!(drain(&c, &base, &carol, carol.devices[0].0).is_empty());

    // An account that doesn't exist is the same refusal.
    let ghost = Uuid::new_v4().hyphenated().to_string();
    let payload = sent(&[(&ghost, &[(1, 10)], 3)], &shared);
    let (status, answer) = post(
        &c,
        &base,
        json!({
            "sendId": Uuid::new_v4().to_string(),
            "payload": STANDARD.encode(&payload),
            "capabilities": { ghost.clone(): STANDARD.encode([1u8; 16]) },
        }),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([ghost]));

    // Bob's second device left out, while Carol's capability is wrong: 409
    // for Bob, with Carol's refusal carried; nothing stored.
    let one_device = [bob.devices[0]];
    let payload = sent(
        &[
            (&bob.account_id, &one_device, 1),
            (&carol.account_id, &carol.devices, 2),
        ],
        &shared,
    );
    let (status, answer) = post(
        &c,
        &base,
        submission(
            &Uuid::new_v4().to_string(),
            &payload,
            &[(&bob, bob.capability), (&carol, [0xee; 16])],
        ),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["devices"][0]["accountId"], bob.account_id.as_str());
    assert_eq!(
        answer["devices"][0]["missingDevices"],
        json!([bob.devices[1].0])
    );
    assert_eq!(answer["refused"], json!([carol.account_id]));

    // A changed registration: 410.
    let stale = [bob.devices[0], (bob.devices[1].0, bob.devices[1].1 + 1)];
    let payload = sent(&[(&bob.account_id, &stale, 1)], &shared);
    let (status, answer) = post(
        &c,
        &base,
        submission(
            &Uuid::new_v4().to_string(),
            &payload,
            &[(&bob, bob.capability)],
        ),
    );
    assert_eq!(status, StatusCode::GONE, "{answer}");
    assert_eq!(
        answer["stale"][0]["staleDevices"],
        json!([bob.devices[1].0])
    );
    // Still the one message from the first send.
    assert_eq!(drain(&c, &base, &bob, bob.devices[0].0).len(), 1);

    // Malformed: capabilities not naming the payload's accounts, and a
    // payload that doesn't parse.
    let payload = sent(&[(&bob.account_id, &bob.devices, 1)], &shared);
    let (status, answer) = post(
        &c,
        &base,
        submission(
            &Uuid::new_v4().to_string(),
            &payload,
            &[(&bob, bob.capability), (&carol, carol.capability)],
        ),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "malformed");
    let (status, _) = post(
        &c,
        &base,
        submission(
            &Uuid::new_v4().to_string(),
            &[0x23, 0xff],
            &[(&bob, bob.capability)],
        ),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Everything delivered is acked, so no shared part is left behind.
    for (device, _) in &bob.devices {
        let got = drain(&c, &base, &bob, *device);
        ack(&c, &base, &bob, *device, &got);
    }
    purge_accounts(&c, &base, &[&bob.user, &carol.user]);
}

fn server_name(c: &Client, base: &str) -> String {
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    settings["chat"]["serverName"].as_str().unwrap().to_owned()
}

fn federation() -> Option<(String, String)> {
    match (
        std::env::var("KUTUP_FEDERATION_SERVER_A"),
        std::env::var("KUTUP_FEDERATION_SERVER_B"),
    ) {
        (Ok(a), Ok(b)) => Some((
            a.trim_end_matches('/').to_owned(),
            b.trim_end_matches('/').to_owned(),
        )),
        _ => {
            eprintln!("KUTUP_FEDERATION_SERVER_A/B not set; skipping");
            None
        }
    }
}

fn post_to(c: &Client, base: &str, server: &str, body: Value) -> (StatusCode, Value) {
    let r = c
        .post(format!(
            "{base}/api/chat/anonymous/messages/multi?server={server}"
        ))
        .json(&body)
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

/// A send through A to B's members: forwarded at once and answered by B, a
/// device mismatch relayed as it is, and B refusing an account that isn't
/// one of its own (A's).
#[test]
fn a_send_to_another_servers_members_is_forwarded_and_answered() {
    if std::env::var("KUTUP_MULTI_PEER_DOWN").is_ok() {
        return;
    }
    let Some((a, b)) = federation() else { return };
    let c = client();
    let b_name = server_name(&c, &b);
    let bob = member(&c, &b, &[51, 52]);
    let carol = member(&c, &b, &[53]);
    let alice = member(&c, &a, &[54]);
    let shared = [0x7cu8; 200];

    let payload = sent(
        &[
            (&bob.account_id, &bob.devices, 1),
            (&carol.account_id, &carol.devices, 2),
        ],
        &shared,
    );
    let send_id = Uuid::new_v4().to_string();
    let (status, answer) = post_to(
        &c,
        &a,
        &b_name,
        submission(
            &send_id,
            &payload,
            &[(&bob, bob.capability), (&carol, carol.capability)],
        ),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([]));
    for (device, _) in &bob.devices {
        let got = drain(&c, &b, &bob, *device);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0]["content"], received(1, &shared));
        ack(&c, &b, &bob, *device, &got);
    }
    let got = drain(&c, &b, &carol, carol.devices[0].0);
    assert_eq!(got[0]["content"], received(2, &shared));
    ack(&c, &b, &carol, carol.devices[0].0, &got);

    // Bob's second device left out: B's 409, relayed by A.
    let one_device = [bob.devices[0]];
    let payload = sent(&[(&bob.account_id, &one_device, 1)], &shared);
    let (status, answer) = post_to(
        &c,
        &a,
        &b_name,
        submission(
            &Uuid::new_v4().to_string(),
            &payload,
            &[(&bob, bob.capability)],
        ),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer["devices"][0]["missingDevices"],
        json!([bob.devices[1].0])
    );

    // A's own account sent to B: not one of B's, refused there.
    let payload = sent(&[(&alice.account_id, &alice.devices, 3)], &shared);
    let (status, answer) = post_to(
        &c,
        &a,
        &b_name,
        submission(
            &Uuid::new_v4().to_string(),
            &payload,
            &[(&alice, alice.capability)],
        ),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([alice.account_id]));
}

/// With B down, A answers at once that the send can't go: the client then
/// sends those members' copies one by one. Nothing is queued.
#[test]
fn a_send_to_a_server_that_is_down_is_peer_unavailable() {
    if std::env::var("KUTUP_MULTI_PEER_DOWN").is_err() {
        return;
    }
    let Some((a, _)) = federation() else { return };
    let c = client();
    let b_name = std::env::var("KUTUP_MULTI_PEER_NAME").expect("B's server name");
    let ghost = Uuid::new_v4().hyphenated().to_string();
    let payload = sent(&[(&ghost, &[(1, 10)], 1)], &[0x11u8; 64]);
    let (status, answer) = post_to(
        &c,
        &a,
        &b_name,
        json!({
            "sendId": Uuid::new_v4().to_string(),
            "payload": STANDARD.encode(&payload),
            "capabilities": { ghost: STANDARD.encode([1u8; 16]) },
        }),
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer["code"], "peerUnavailable");
}
