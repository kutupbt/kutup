//! Live e2e for the collaboration log over HTTP (docs/plans/cli-yjs-sync.md):
//! a frame posted is kept and read back like a socket's, and every bad frame
//! is refused the same way on both paths (one gate, `accept_frame`). Devices
//! are entries of their account's manifest (docs/plans/one-device-list.md):
//! a frame counts only under the frame key the manifest lists.
//!
//! Gated on `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` to purge its accounts):
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test collab_frames_live -- --nocapture

use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use kutup_crypto::envelope::{self, kind, CollabFrameContextV3, Frame};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;

mod common;
use common::*;

/// A sealed frame of `device`'s, signed with `signer`'s key; `tweak` changes
/// its context before sealing.
fn frame(
    file: &Sealed,
    device: &Device,
    signer: &Device,
    sequence: u64,
    tweak: impl FnOnce(&mut CollabFrameContextV3),
) -> Vec<u8> {
    let mut context = CollabFrameContextV3::new(
        kind::YJS_UPDATE,
        1,
        1,
        &file.id,
        device.id,
        device.manifest_sequence,
        sequence,
    )
    .unwrap();
    tweak(&mut context);
    let packed = envelope::seal_unsigned(b"an edit", &file.key, context).unwrap();
    envelope::sign(
        &Frame::unpack(&packed).unwrap(),
        &device.account,
        &signer.seed,
    )
    .unwrap()
}

fn post(
    c: &Client,
    base: &str,
    user: &User,
    file_id: &str,
    device: &str,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let r = bearer(
        c.post(format!("{base}/api/files/{file_id}/collab/frames")),
        &user.token,
    )
    .header(kutup_chat_proto::DEVICE_HEADER, device)
    .header("Content-Type", "application/octet-stream")
    .body(body)
    .send()
    .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

fn log(c: &Client, base: &str, user: &User, file_id: &str, device: &Device) -> Value {
    bearer(
        c.get(format!("{base}/api/files/{file_id}/collab/frames?after=0")),
        &user.token,
    )
    .header(kutup_chat_proto::DEVICE_HEADER, device.header())
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
    let c = crate::common::client();
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
    let mine = register_device(&c, &base, &owner);
    let second = register_device(&c, &base, &owner);
    let theirs = register_device(&c, &base, &viewer);

    // Kept, and read back with its position and this device's sequence.
    let (status, body) = post(
        &c,
        &base,
        &owner,
        &file.id,
        &mine.header(),
        frame(&file, &mine, &mine, 1, |_| {}),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    let first_seq = body["seq"].as_i64().unwrap();

    // Every bad frame, refused alike on both paths.
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("a replayed sequence", frame(&file, &mine, &mine, 1, |_| {})),
        (
            "another device's frame",
            frame(&file, &second, &second, 1, |_| {}),
        ),
        (
            "signed by another key",
            frame(&file, &mine, &second, 2, |_| {}),
        ),
        (
            "a stale document key",
            frame(&file, &mine, &mine, 3, |c| c.doc_key_id = 2),
        ),
        (
            "another key generation",
            frame(&file, &mine, &mine, 4, |c| c.key_generation = 2),
        ),
        (
            "another file's frame",
            frame(&other_file, &mine, &mine, 5, |_| {}),
        ),
        (
            "presence over HTTP",
            frame(&file, &mine, &mine, 6, |c| c.kind = kind::YJS_AWARENESS),
        ),
        (
            "a manifest the account doesn't have yet",
            frame(&file, &mine, &mine, 7, |c| c.manifest_sequence += 10),
        ),
        ("not a frame", b"not a frame".to_vec()),
    ];
    for (why, bytes) in &bad {
        let (status, body) = post(&c, &base, &owner, &file.id, &mine.header(), bytes.clone());
        assert_eq!(status, StatusCode::CONFLICT, "{why}: {body}");
        assert_eq!(body["code"], "frameRefused", "{why}");
    }
    // A reader may not write.
    let (status, _) = post(
        &c,
        &base,
        &viewer,
        &file.id,
        &theirs.header(),
        frame(&file, &theirs, &theirs, 1, |_| {}),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A device that is not the caller's is not accepted at all.
    let (status, body) = post(
        &c,
        &base,
        &viewer,
        &file.id,
        &mine.header(),
        frame(&file, &mine, &mine, 8, |_| {}),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "deviceCredential");
    // A device registered and not listed in the account's manifest
    // (deviceNotAuthorized: the client registers again, it is not signed out).
    let unlisted = {
        let mut credential = [0u8; 32];
        kutup_crypto::primitives::random(&mut credential);
        let r = bearer(c.post(format!("{base}/api/devices")), &owner.token)
            .json(&serde_json::json!({
                "kind": "editor",
                "frameKey": STANDARD.encode(
                    kutup_crypto::primitives::SigningKey::from_seed(
                        kutup_crypto::primitives::Suite::V1,
                        &[0x33; 32],
                    )
                    .verifying_key()
                    .to_array::<32>()
                ),
                "credential": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential),
            }))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let id = r.json::<Value>().unwrap()["deviceId"].as_u64().unwrap();
        format!(
            "{id}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential)
        )
    };
    let (status, body) = post(
        &c,
        &base,
        &owner,
        &file.id,
        &unlisted,
        frame(&file, &mine, &mine, 9, |_| {}),
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "deviceNotAuthorized");

    // The same bad frames over the socket, then one good frame: only the
    // good one is kept.
    let ticket: Value = bearer(c.post(format!("{base}/api/device-ticket")), &owner.token)
        .header(kutup_chat_proto::DEVICE_HEADER, mine.header())
        .send()
        .unwrap()
        .json()
        .unwrap();
    let ws_base = base.replacen("http", "ws", 1);
    let url = format!(
        "{ws_base}/api/files/{}/collab/ws?ticket={}",
        file.id,
        ticket["ticket"].as_str().unwrap()
    );
    let good = frame(&file, &mine, &mine, 10, |_| {});
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
    let page = log(&c, &base, &owner, &file.id, &mine);
    let frames = page["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 2, "{page}");
    assert_eq!(frames[0]["seq"], first_seq);
    assert_eq!(
        STANDARD
            .decode(frames[1]["frame"].as_str().unwrap())
            .unwrap(),
        good
    );
    // Each frame names its sender, which its signature covers.
    assert_eq!(frames[1]["sender"], owner.person.to_string());
    assert_eq!(page["mySenderSeqHigh"], 10);
    // A reader reads the log too.
    assert_eq!(
        log(&c, &base, &viewer, &file.id, &theirs)["frames"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    purge_accounts(&c, &base, &[&owner, &viewer]);
}
