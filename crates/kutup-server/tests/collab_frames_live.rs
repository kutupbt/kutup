//! Live e2e for the collaboration log over HTTP (docs/plans/cli-yjs-sync.md):
//! a frame posted is kept and read back like a socket's, and every bad frame
//! is refused the same way on both paths (one gate, `accept_frame`).
//!
//! Gated on `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` to purge its accounts):
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test collab_frames_live -- --nocapture

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use kutup_crypto::envelope::{self, kind, CollabFrameContextV1, Frame};
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

struct Device {
    id: i64,
    seed: [u8; 32],
}

fn device(c: &Client, base: &str, user: &User) -> Device {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let r: Value = bearer(c.post(format!("{base}/api/devices")), &user.token)
        .json(&json!({
            "publicSigning": STANDARD.encode(public),
            "label": "collab test",
            "authSig": STANDARD.encode([0u8; 64]),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    Device {
        id: r["deviceId"].as_i64().unwrap(),
        seed,
    }
}

/// A sealed, signed frame; `tweak` changes its context before sealing.
fn frame(
    file: &Sealed,
    signer: &[u8; 32],
    sender: i64,
    sequence: u64,
    tweak: impl FnOnce(&mut CollabFrameContextV1),
) -> Vec<u8> {
    let mut context =
        CollabFrameContextV1::new(kind::YJS_UPDATE, 1, 1, &file.id, sender as u64, sequence)
            .unwrap();
    tweak(&mut context);
    let packed = envelope::seal_unsigned(b"an edit", &file.key, context).unwrap();
    envelope::sign(&Frame::unpack(&packed).unwrap(), signer).unwrap()
}

fn post(
    c: &Client,
    base: &str,
    user: &User,
    file_id: &str,
    device: i64,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let r = bearer(
        c.post(format!(
            "{base}/api/files/{file_id}/collab/frames?deviceId={device}"
        )),
        &user.token,
    )
    .header("Content-Type", "application/octet-stream")
    .body(body)
    .send()
    .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

fn log(c: &Client, base: &str, user: &User, file_id: &str, device: i64) -> Value {
    bearer(
        c.get(format!(
            "{base}/api/files/{file_id}/collab/frames?deviceId={device}&after=0"
        )),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap()
}

#[test]
fn http_and_socket_refuse_the_same_frames() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = Client::new();
    let owner = register(&c, &base);
    let viewer = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &viewer, false);
    let file = seal_file(&folder, &uuid(), b"# notes\n");
    assert!(upload(&c, &base, &owner.token, &folder, &file)
        .status()
        .is_success());
    let other_file = seal_file(&folder, &uuid(), b"other");
    assert!(upload(&c, &base, &owner.token, &folder, &other_file)
        .status()
        .is_success());
    let mine = device(&c, &base, &owner);
    let second = device(&c, &base, &owner);
    let theirs = device(&c, &base, &viewer);

    // Kept, and read back with its position and this device's sequence.
    let (status, body) = post(
        &c,
        &base,
        &owner,
        &file.id,
        mine.id,
        frame(&file, &mine.seed, mine.id, 1, |_| {}),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    let first_seq = body["seq"].as_i64().unwrap();

    // Every bad frame, refused alike on both paths.
    let bad: Vec<(&str, Vec<u8>)> = vec![
        (
            "a replayed sequence",
            frame(&file, &mine.seed, mine.id, 1, |_| {}),
        ),
        (
            "another device's frame",
            frame(&file, &second.seed, second.id, 1, |_| {}),
        ),
        (
            "signed by another key",
            frame(&file, &second.seed, mine.id, 2, |_| {}),
        ),
        (
            "a stale document key",
            frame(&file, &mine.seed, mine.id, 3, |c| c.doc_key_id = 2),
        ),
        (
            "another key generation",
            frame(&file, &mine.seed, mine.id, 4, |c| c.key_generation = 2),
        ),
        (
            "another file's frame",
            frame(&other_file, &mine.seed, mine.id, 5, |_| {}),
        ),
        (
            "presence over HTTP",
            frame(&file, &mine.seed, mine.id, 6, |c| {
                c.kind = kind::YJS_AWARENESS
            }),
        ),
        ("not a frame", b"not a frame".to_vec()),
    ];
    for (why, bytes) in &bad {
        let (status, body) = post(&c, &base, &owner, &file.id, mine.id, bytes.clone());
        assert_eq!(status, StatusCode::CONFLICT, "{why}: {body}");
        assert_eq!(body["code"], "frameRefused", "{why}");
    }
    // A reader may not write.
    let (status, _) = post(
        &c,
        &base,
        &viewer,
        &file.id,
        theirs.id,
        frame(&file, &theirs.seed, theirs.id, 1, |_| {}),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A device that is not the caller's is not accepted at all.
    let (status, _) = post(
        &c,
        &base,
        &viewer,
        &file.id,
        mine.id,
        frame(&file, &mine.seed, mine.id, 7, |_| {}),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The same bad frames over the socket, then one good frame: only the
    // good one is kept.
    let ws_base = base.replacen("http", "ws", 1);
    let url = format!(
        "{ws_base}/api/files/{}/collab/ws?token={}&deviceId={}",
        file.id, owner.token, mine.id
    );
    let good = frame(&file, &mine.seed, mine.id, 10, |_| {});
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        use tokio_tungstenite::tungstenite::Message;
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        for (_, bytes) in bad.iter().filter(|(why, _)| *why != "presence over HTTP") {
            socket.send(Message::Binary(bytes.clone())).await.unwrap();
        }
        socket.send(Message::Binary(good.clone())).await.unwrap();
        // The server answers in order: the good frame's position comes last.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let message = tokio::time::timeout_at(deadline, socket.next())
                .await
                .expect("the good frame was stored")
                .unwrap()
                .unwrap();
            if let Message::Text(text) = message {
                if text.contains("\"stored\"") {
                    break;
                }
            }
        }
    });
    let page = log(&c, &base, &owner, &file.id, mine.id);
    let frames = page["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 2, "{page}");
    assert_eq!(frames[0]["seq"], first_seq);
    assert_eq!(
        STANDARD
            .decode(frames[1]["frame"].as_str().unwrap())
            .unwrap(),
        good
    );
    assert_eq!(page["mySenderSeqHigh"], 10);
    // A reader reads the log too.
    assert_eq!(
        log(&c, &base, &viewer, &file.id, theirs.id)["frames"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    purge_accounts(&c, &base, &[&owner, &viewer]);
}
