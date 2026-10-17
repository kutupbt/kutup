//! Meetings by link against a live server (docs/chat-calls.md, "Meetings"):
//! the account a joiner shows is kept by its id, so the name the others see
//! is the account's current one, at every token and in the waiting room.
//!
//! Needs `KUTUP_LIVE_SERVER` on a server with an SFU configured (none has to
//! run: tokens are only minted), and `KUTUP_LIVE_ADMIN` to purge.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use common::*;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A meeting link of `owner`'s: its room id, access token and host token.
struct Link {
    room_id: String,
    access_token: String,
    host_token: String,
}

fn create_link(c: &Client, base: &str, owner: &User, waiting_room: bool) -> Link {
    let access = random::<32>();
    let host = random::<32>();
    let link = Link {
        room_id: hex(&random::<16>()),
        access_token: b64(&access),
        host_token: b64(&host),
    };
    let r = bearer(c.post(format!("{base}/api/chat/call-links")), &owner.token)
        .json(&json!({
            "roomId": link.room_id,
            "nonce": hex(&random::<16>()),
            "accessTokenHash": b64(&Sha256::digest(access)),
            "info": b64(&[7u8; 552]),
            "hostTokenHash": b64(&Sha256::digest(host)),
            "waitingRoom": waiting_room,
        }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().unwrap());
    link
}

/// The name a LiveKit token shows the others (its `name` claim).
fn shown_name(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1).expect("a JWT");
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["name"].as_str().map(str::to_owned)
}

fn renamed(c: &Client, base: &str, user: &mut User) -> String {
    let to = format!("meet_{}", rand::thread_rng().next_u32() % 1_000_000_000);
    let check: Value = bearer(
        c.get(format!("{base}/api/user/rename/check?name={to}")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let r = rename_account(c, base, user, &to, check["needsKey"] != true);
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    user.username = to.clone();
    to
}

fn server_name(c: &Client, base: &str) -> String {
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    settings["chat"]["serverName"]
        .as_str()
        .expect("the chat server name")
        .to_owned()
}

#[test]
fn a_seat_shows_the_accounts_current_name() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let server = server_name(&c, &base);
    let owner = register(&c, &base);
    let mut joiner = register(&c, &base);
    let link = create_link(&c, &base, &owner, false);

    let participant = hex(&random::<16>());
    let seat = b64(&random::<32>());
    let label = b64(&[1u8; 168]);
    let token = |user: Option<&User>| {
        let request = c
            .post(format!("{base}/api/chat/call-links/token"))
            .json(&json!({
                "roomId": link.room_id,
                "accessToken": link.access_token,
                "participantId": participant,
                "label": label,
                "seat": seat,
            }));
        let r = match user {
            Some(user) => bearer(request, &user.token),
            None => request,
        }
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{}", r.text().unwrap());
        let body: Value = r.json().unwrap();
        shown_name(body["token"].as_str().unwrap())
    };

    assert_eq!(
        token(Some(&joiner)),
        Some(format!("{}@{server}", joiner.username))
    );
    // The same seat, after a rename: the new name, not the one it had.
    let new = renamed(&c, &base, &mut joiner);
    assert_eq!(token(Some(&joiner)), Some(format!("{new}@{server}")));
    // Without the access token, nobody is vouched for.
    assert_eq!(token(None), None);

    purge_accounts(&c, &base, &[&owner, &joiner]);
}

#[test]
fn a_knock_shows_the_accounts_current_name() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let server = server_name(&c, &base);
    let owner = register(&c, &base);
    let mut knocker = register(&c, &base);
    let link = create_link(&c, &base, &owner, true);

    let r = bearer(
        c.post(format!("{base}/api/chat/call-links/knock")),
        &knocker.token,
    )
    .json(&json!({
        "roomId": link.room_id,
        "accessToken": link.access_token,
        "participantId": hex(&random::<16>()),
        "label": b64(&[2u8; 168]),
        "seat": b64(&random::<32>()),
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().unwrap());
    let knock: Value = r.json().unwrap();

    // The host sees the name the knocker goes by now, renamed while waiting.
    let new = renamed(&c, &base, &mut knocker);
    let host = json!({
        "roomId": link.room_id,
        "accessToken": link.access_token,
        "hostToken": link.host_token,
    });
    let waiting: Value = c
        .post(format!("{base}/api/chat/call-links/knocks"))
        .json(&host)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(waiting["knocks"].as_array().unwrap().len(), 1, "{waiting}");
    assert_eq!(
        waiting["knocks"][0]["account"],
        json!(format!("{new}@{server}"))
    );

    // Let in: the token minted then carries the current name too.
    let r = c
        .post(format!("{base}/api/chat/call-links/knocks/decide"))
        .json(&json!({
            "roomId": link.room_id,
            "accessToken": link.access_token,
            "hostToken": link.host_token,
            "knockId": knock["knockId"],
            "admit": true,
        }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().unwrap());
    let status: Value = c
        .post(format!("{base}/api/chat/call-links/knock/status"))
        .json(&json!({
            "roomId": link.room_id,
            "accessToken": link.access_token,
            "knockId": knock["knockId"],
            "ticket": knock["ticket"],
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(status["status"], "admitted", "{status}");
    assert_eq!(
        shown_name(status["token"].as_str().unwrap()),
        Some(format!("{new}@{server}"))
    );

    purge_accounts(&c, &base, &[&owner, &knocker]);
}
