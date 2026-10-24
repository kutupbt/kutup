//! Multi-recipient sends (docs/plans/pairwise-groups.md, slice 2): one group
//! message to member accounts of one server, sent once, checked by its group
//! send token (docs/plans/group-send-endorsements.md), then budgets, then
//! devices, stored once and drained by each device as its ordinary sealed
//! envelope.
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
use common::chat_identity::{ChatAccount, ChatDevice};
use common::*;
use kutup_group_send::{Endorsement, EndorsementKey};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

fn base() -> Option<String> {
    let Ok(base) = std::env::var("KUTUP_LIVE_GROUPS_SERVER") else {
        eprintln!("KUTUP_LIVE_GROUPS_SERVER not set; skipping");
        return None;
    };
    Some(base.trim_end_matches('/').to_string())
}

/// A member with Chat devices and today's endorsement from its server.
struct Member {
    user: User,
    account_id: String,
    chat: ChatAccount,
    /// Device id and registration id.
    devices: Vec<(u32, u32)>,
    endorsement: Endorsement,
}

impl Member {
    fn device(&self, id: u32) -> &ChatDevice {
        self.chat.devices.iter().find(|d| d.id == id).unwrap()
    }
}

/// `seeds.len()` devices (the first re-registered, the others linked) and
/// its endorsement, checked against its server's published key.
fn member(c: &Client, base: &str, seeds: &[u8]) -> Member {
    let user = register(c, base);
    let mut chat = ChatAccount::of(&user, &user.token);
    let first = chat.reregister(c, base);
    for _ in 1..seeds.len() {
        chat.link(c, base, &first);
    }
    let devices = chat
        .devices
        .iter()
        .map(|d| (d.id, d.registration_id))
        .collect();
    let endorsement = endorse(c, base, &user);
    Member {
        account_id: user.person.account_id.clone(),
        user,
        chat,
        devices,
        endorsement,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `user`'s endorsement of today from its own server (§3.2), received with
/// the key its `params` publishes, as a client receives it.
fn endorse(c: &Client, base: &str, user: &User) -> Endorsement {
    let r = bearer(
        c.get(format!("{base}/api/chat/group-send/endorsement")),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "fetch the endorsement");
    let issued: Value = r.json().unwrap();
    let params: Value = bearer(
        c.get(format!("{base}/api/chat/group-send/params")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let key = params["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["keyId"] == issued["keyId"])
        .expect("the issuing key is published");
    let key = EndorsementKey::from_bytes(
        &STANDARD
            .decode(key["endorsementPublicKey"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let response = STANDARD
        .decode(issued["response"].as_str().unwrap())
        .unwrap();
    let account = Uuid::parse_str(&user.person.account_id).unwrap();
    kutup_group_send::receive(&response, account, now(), &key).expect("a valid endorsement")
}

/// A token over `members`' endorsements.
fn token(members: &[&Member]) -> String {
    let endorsements: Vec<Endorsement> = members
        .iter()
        .map(|member| member.endorsement.clone())
        .collect();
    STANDARD.encode(kutup_group_send::token(&endorsements).unwrap())
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

/// A send of `payload` with a token over `members`.
fn submission(send_id: &str, payload: &[u8], members: &[&Member]) -> Value {
    json!({
        "sendId": send_id,
        "payload": STANDARD.encode(payload),
        "groupSendToken": token(members),
    })
}

fn drain(c: &Client, base: &str, member: &Member, device: u32) -> Vec<Value> {
    let page: Value = bearer(
        member
            .device(device)
            .auth(c.get(format!("{base}/api/chat/messages?deviceId={device}"))),
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
        member
            .device(device)
            .auth(c.post(format!("{base}/api/chat/messages/ack?deviceId={device}"))),
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
    let body = submission(&send_id, &payload, &[&bob, &carol]);
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
fn the_token_then_devices_answer_each_account() {
    let Some(base) = base() else { return };
    let c = client();
    let bob = member(&c, &base, &[41, 42]);
    let carol = member(&c, &base, &[43]);
    let shared = [0x6bu8; 120];
    let both = sent(
        &[
            (&bob.account_id, &bob.devices, 1),
            (&carol.account_id, &carol.devices, 2),
        ],
        &shared,
    );

    // A token that doesn't name exactly the payload's accounts (Carol
    // missing, or Bob counted twice), or no token of this server's: 401
    // groupSendTokenInvalid, and nothing is stored or looked up.
    for wrong in [token(&[&bob]), token(&[&bob, &carol, &bob])] {
        let (status, answer) = post(
            &c,
            &base,
            json!({
                "sendId": Uuid::new_v4().to_string(),
                "payload": STANDARD.encode(&both),
                "groupSendToken": wrong,
            }),
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
        assert_eq!(answer["code"], "groupSendTokenInvalid");
    }
    let (status, answer) = post(
        &c,
        &base,
        json!({
            "sendId": Uuid::new_v4().to_string(),
            "payload": STANDARD.encode(&both),
            "groupSendToken": STANDARD.encode([7u8; 100]),
        }),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["code"], "groupSendTokenInvalid");
    assert!(drain(&c, &base, &bob, bob.devices[0].0).is_empty());
    // An account that doesn't exist gets the same answer: there is no
    // endorsement of it, so no token holds (no existence oracle).
    let ghost = Uuid::new_v4().hyphenated().to_string();
    let with_ghost = sent(
        &[(&bob.account_id, &bob.devices, 1), (&ghost, &[(1, 10)], 3)],
        &shared,
    );
    let (status, answer) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &with_ghost, &[&bob]),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");

    // A token over both: delivered.
    let (status, answer) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &both, &[&bob, &carol]),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([]));
    assert_eq!(drain(&c, &base, &bob, bob.devices[0].0).len(), 1);
    assert_eq!(drain(&c, &base, &carol, carol.devices[0].0).len(), 1);

    // Bob's second device left out: 409 for Bob; nothing stored.
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
        submission(&Uuid::new_v4().to_string(), &payload, &[&bob, &carol]),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["devices"][0]["accountId"], bob.account_id.as_str());
    assert_eq!(
        answer["devices"][0]["missingDevices"],
        json!([bob.devices[1].0])
    );

    // A changed registration: 410.
    let stale = [
        bob.devices[0],
        (bob.devices[1].0, bob.devices[1].1 % 16383 + 1),
    ];
    let payload = sent(&[(&bob.account_id, &stale, 1)], &shared);
    let (status, answer) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &payload, &[&bob]),
    );
    assert_eq!(status, StatusCode::GONE, "{answer}");
    assert_eq!(
        answer["stale"][0]["staleDevices"],
        json!([bob.devices[1].0])
    );
    // Still the one message from the delivered send.
    assert_eq!(drain(&c, &base, &bob, bob.devices[0].0).len(), 1);

    // Malformed: a payload that doesn't parse, a token of the wrong shape,
    // or no token at all.
    let (status, _) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &[0x23, 0xff], &[&bob]),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let payload = sent(&[(&bob.account_id, &bob.devices, 1)], &shared);
    for token in [json!("AQ"), Value::Null] {
        let mut body = submission(&Uuid::new_v4().to_string(), &payload, &[&bob]);
        body["groupSendToken"] = token;
        let (status, _) = post(&c, &base, body);
        assert!(status.is_client_error() && status != StatusCode::UNAUTHORIZED);
    }

    // Everything delivered is acked, so no shared part is left behind.
    for (device, _) in &bob.devices {
        let got = drain(&c, &base, &bob, *device);
        ack(&c, &base, &bob, *device, &got);
    }
    let got = drain(&c, &base, &carol, carol.devices[0].0);
    ack(&c, &base, &carol, carol.devices[0].0, &got);
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
        submission(&send_id, &payload, &[&bob, &carol]),
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
        submission(&Uuid::new_v4().to_string(), &payload, &[&bob]),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer["devices"][0]["missingDevices"],
        json!([bob.devices[1].0])
    );

    // A token of A's endorsements sent to B: B verifies with its own keys
    // only, so it doesn't hold there, and A relays B's 401 as it is.
    let payload = sent(&[(&alice.account_id, &alice.devices, 3)], &shared);
    let (status, answer) = post_to(
        &c,
        &a,
        &b_name,
        submission(&Uuid::new_v4().to_string(), &payload, &[&alice]),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["code"], "groupSendTokenInvalid");
    // B's discovery publishes its keys, and A serves them to its client.
    let params: Value = bearer(
        c.get(format!("{a}/api/chat/group-send/params?server={b_name}")),
        &alice.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let theirs: Value = bearer(
        c.get(format!("{b}/api/chat/group-send/params")),
        &bob.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(params, theirs);
    // KUTUP_LIVE_ADMIN is A's: B's accounts stay, as the gate's B ones do.
    purge_accounts(&c, &a, &[&alice.user]);
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
            "groupSendToken": STANDARD.encode([7u8; 100]),
        }),
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer["code"], "peerUnavailable");
}

/// An administrator of the server at `base` (`KUTUP_LIVE_ADMIN`, or
/// `KUTUP_LIVE_ADMIN_B` for B): a session, or `None` to skip.
fn admin_session(c: &Client, base: &str, variable: &str) -> Option<String> {
    let Ok(admin) = std::env::var(variable) else {
        eprintln!("{variable} unset; skipping");
        return None;
    };
    let (name, password) = admin.split_once(':').unwrap();
    Some(admin_token(c, base, password, name))
}

fn settings(c: &Client, base: &str, token: &str, body: Value) {
    let r = bearer(c.put(format!("{base}/api/admin/settings")), token)
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "settings {body}");
}

/// A device added after a send was stored gets its copy when the send is
/// retried under the same sendId; the devices that had it get nothing more.
#[test]
fn a_retry_reaches_a_device_added_since() {
    let Some(base) = base() else { return };
    let c = client();
    let mut bob = member(&c, &base, &[61]);
    let shared = [0x31u8; 80];
    let send_id = Uuid::new_v4().to_string();
    let first = sent(&[(&bob.account_id, &bob.devices, 1)], &shared);
    let (status, answer) = post(&c, &base, submission(&send_id, &first, &[&bob]));
    assert_eq!(status, StatusCode::OK, "{answer}");
    let first = bob.chat.devices[0].clone();
    let added = bob.chat.link(&c, &base, &first);
    let added = (added.id, added.registration_id);
    let both = [bob.devices[0], added];
    let retry = sent(&[(&bob.account_id, &both, 1)], &shared);
    let (status, answer) = post(&c, &base, submission(&send_id, &retry, &[&bob]));
    assert_eq!(status, StatusCode::OK, "{answer}");
    let old = drain(&c, &base, &bob, bob.devices[0].0);
    assert_eq!(old.len(), 1, "the first device has it once: {old:?}");
    let new = drain(&c, &base, &bob, added.0);
    assert_eq!(new.len(), 1, "the added device got its copy: {new:?}");
    assert_eq!(new[0]["content"], received(1, &shared));
    ack(&c, &base, &bob, bob.devices[0].0, &old);
    ack(&c, &base, &bob, added.0, &new);
    purge_accounts(&c, &base, &[&bob.user]);
}

/// A send that isn't urgent is stored and drained the same (it only skips
/// waking offline devices); a removed device's rows go with it and their
/// shared part once no row names it; two devices acking at once leave no
/// shared part behind (the gate counts what's left).
#[test]
fn shared_parts_go_with_the_last_row_naming_them() {
    let Some(base) = base() else { return };
    let c = client();
    let bob = member(&c, &base, &[63, 64]);
    let shared = [0x42u8; 90];
    let payload = sent(&[(&bob.account_id, &bob.devices, 1)], &shared);
    let mut body = submission(&Uuid::new_v4().to_string(), &payload, &[&bob]);
    body["urgent"] = json!(false);
    let (status, answer) = post(&c, &base, body);
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(drain(&c, &base, &bob, bob.devices[0].0).len(), 1);
    // The second device is removed (by the first) before it drains; the
    // first acks.
    let r = bearer(
        bob.device(bob.devices[0].0)
            .auth(c.delete(format!("{base}/api/chat/device/{}", bob.devices[1].0))),
        &bob.user.token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success(), "remove a device: {}", r.status());
    let got = drain(&c, &base, &bob, bob.devices[0].0);
    ack(&c, &base, &bob, bob.devices[0].0, &got);

    // Two devices acking at the same moment.
    let carol = member(&c, &base, &[65, 66]);
    let payload = sent(&[(&carol.account_id, &carol.devices, 2)], &shared);
    let (status, answer) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &payload, &[&carol]),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    let pages: Vec<(u32, Vec<Value>)> = carol
        .devices
        .iter()
        .map(|(device, _)| (*device, drain(&c, &base, &carol, *device)))
        .collect();
    std::thread::scope(|scope| {
        for (device, page) in &pages {
            let (c, base, carol) = (&c, &base, &carol);
            scope.spawn(move || ack(c, base, carol, *device, page));
        }
    });
    purge_accounts(&c, &base, &[&bob.user, &carol.user]);
}

/// The administrators' limits: a recipient's sends a minute
/// (`rateLimited`), one token's requests a minute (`429`), recipients per
/// send (`413`), and an inactive account refused.
#[test]
fn limits_and_inactive_accounts_answer_as_set() {
    let Some(base) = base() else { return };
    let c = client();
    let Some(admin) = admin_session(&c, &base, "KUTUP_LIVE_ADMIN") else {
        return;
    };
    let bob = member(&c, &base, &[67]);
    let carol = member(&c, &base, &[68]);
    let shared = [0x53u8; 70];
    let to_bob = || {
        let payload = sent(&[(&bob.account_id, &bob.devices, 1)], &shared);
        post(
            &c,
            &base,
            submission(&Uuid::new_v4().to_string(), &payload, &[&bob]),
        )
    };
    settings(
        &c,
        &base,
        &admin,
        json!({ "chatMultiPerRecipientPerMin": 1 }),
    );
    let (status, answer) = to_bob();
    assert_eq!(
        (status, &answer["rateLimited"]),
        (StatusCode::OK, &json!([])),
        "{answer}"
    );
    let (status, answer) = to_bob();
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["rateLimited"], json!([bob.account_id]));
    settings(
        &c,
        &base,
        &admin,
        json!({ "chatMultiPerRecipientPerMin": null }),
    );

    // One token, sent again and again: past its minute's requests, 429.
    settings(&c, &base, &admin, json!({ "chatMultiPerTokenPerMin": 1 }));
    let payload = sent(&[(&carol.account_id, &carol.devices, 2)], &shared);
    let replayed = submission(&Uuid::new_v4().to_string(), &payload, &[&carol]);
    let (status, answer) = post(&c, &base, replayed.clone());
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, _) = post(&c, &base, replayed);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    settings(
        &c,
        &base,
        &admin,
        json!({ "chatMultiPerTokenPerMin": null }),
    );
    let got = drain(&c, &base, &carol, carol.devices[0].0);
    ack(&c, &base, &carol, carol.devices[0].0, &got);

    settings(&c, &base, &admin, json!({ "chatMultiMaxRecipients": 1 }));
    let payload = sent(
        &[
            (&bob.account_id, &bob.devices, 1),
            (&carol.account_id, &carol.devices, 2),
        ],
        &shared,
    );
    let (status, _) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &payload, &[&bob, &carol]),
    );
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    settings(&c, &base, &admin, json!({ "chatMultiMaxRecipients": null }));

    let r = bearer(
        c.put(format!("{base}/api/admin/users/{}", carol.user.id)),
        &admin,
    )
    .json(&json!({ "isActive": false }))
    .send()
    .unwrap();
    assert!(r.status().is_success(), "deactivate: {}", r.status());
    let payload = sent(&[(&carol.account_id, &carol.devices, 2)], &shared);
    let (status, answer) = post(
        &c,
        &base,
        submission(&Uuid::new_v4().to_string(), &payload, &[&carol]),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["refused"], json!([carol.account_id]));
    for (device, _) in &bob.devices {
        let got = drain(&c, &base, &bob, *device);
        ack(&c, &base, &bob, *device, &got);
    }
    purge_accounts(&c, &base, &[&bob.user, &carol.user]);
}

/// B's budget for A's sends: once spent, A answers its client that B didn't
/// take the send (`503 peerUnavailable`), as for B down.
#[test]
fn a_destination_budgets_its_origins_sends() {
    if std::env::var("KUTUP_MULTI_PEER_DOWN").is_ok() {
        return;
    }
    let Some((a, b)) = federation() else { return };
    let c = client();
    let Some(admin_b) = admin_session(&c, &b, "KUTUP_LIVE_ADMIN_B") else {
        return;
    };
    let b_name = server_name(&c, &b);
    let bob = member(&c, &b, &[69]);
    let shared = [0x64u8; 60];
    let to_bob = || {
        let payload = sent(&[(&bob.account_id, &bob.devices, 1)], &shared);
        post_to(
            &c,
            &a,
            &b_name,
            submission(&Uuid::new_v4().to_string(), &payload, &[&bob]),
        )
    };
    // Past the minute's earlier sends from A.
    std::thread::sleep(std::time::Duration::from_secs(61));
    settings(
        &c,
        &b,
        &admin_b,
        json!({ "chatMultiOriginRequestsPerMin": 1 }),
    );
    let (status, answer) = to_bob();
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = to_bob();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer["code"], "peerUnavailable");
    settings(
        &c,
        &b,
        &admin_b,
        json!({ "chatMultiOriginRequestsPerMin": null }),
    );
    let got = drain(&c, &b, &bob, bob.devices[0].0);
    ack(&c, &b, &bob, bob.devices[0].0, &got);
}

/// Each account's endorsement of the day, by this server's issuing key
/// (§3.2): it checks against the key `params` and discovery publish, and an
/// account past its endorsements a day gets `429`.
#[test]
fn the_server_issues_endorsements_and_publishes_its_keys() {
    let Some(base) = base() else { return };
    let c = client();
    let user = register(&c, &base);
    // `endorse` checks the response against the published key.
    let endorsement = endorse(&c, &base, &user);
    assert_eq!(endorsement.expiration % 86_400, 0);
    assert!(endorsement.expiration > now() + 25 * 3_600 - 60);

    let params: Value = bearer(
        c.get(format!("{base}/api/chat/group-send/params")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let keys = params["keys"].as_array().unwrap();
    assert!(!keys.is_empty() && keys.len() <= 2, "{params}");
    // The issuing key: "until rotated", a number every client reads exactly.
    assert!(keys
        .iter()
        .any(|key| key["issuesUntil"] == json!(9_007_199_254_740_991u64)));
    // The same keys in the signed discovery, and for this server by name.
    let discovery: Value = c
        .get(format!("{base}/.well-known/kutup/federation.json"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(discovery["chatGroupSend"], params["keys"]);
    let name = server_name(&c, &base);
    let named: Value = bearer(
        c.get(format!("{base}/api/chat/group-send/params?server={name}")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(named, params);
    // Both routes need a signed-in account.
    for path in ["endorsement", "params"] {
        let r = c
            .get(format!("{base}/api/chat/group-send/{path}"))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
    }

    if let Some(admin) = admin_session(&c, &base, "KUTUP_LIVE_ADMIN") {
        settings(
            &c,
            &base,
            &admin,
            json!({ "chatGroupSendEndorsementsPerDay": 1 }),
        );
        let r = bearer(
            c.get(format!("{base}/api/chat/group-send/endorsement")),
            &user.token,
        )
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        settings(
            &c,
            &base,
            &admin,
            json!({ "chatGroupSendEndorsementsPerDay": null }),
        );
    }
    purge_accounts(&c, &base, &[&user]);
}
