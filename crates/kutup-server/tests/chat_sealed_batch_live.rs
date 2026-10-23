//! Sealed batches (docs/plans/pairwise-groups.md §1): several sealed sends to
//! accounts of one server in one anonymous request, each recipient checked,
//! counted and answered on its own.
//!
//! `KUTUP_LIVE_SERVER` runs the local path on one server. With
//! `KUTUP_FEDERATION_SERVER_A` and `KUTUP_FEDERATION_SERVER_B` set, the
//! federated path runs too: a client of A sends to accounts of B, A queues the
//! sends and delivers them to B in one federated batch.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::chat_identity::ChatAccount;
use common::*;
use kutup_chat_proto::{
    ProfileEnvelopeContextV1, ProfileEnvelopePurpose, ProfileSuiteId, PutChatProfileRequest,
};
use kutup_crypto::account_ref::AccountRef;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn opaque_profile_envelope(
    account: &AccountRef,
    version: &str,
    purpose: ProfileEnvelopePurpose,
    ciphertext_len: usize,
) -> String {
    let context = ProfileEnvelopeContextV1::new(purpose, account, version, 1, 1).unwrap();
    let mut envelope =
        kutup_chat_proto::encode_profile_envelope_header(&context, &[4; 24], ciphertext_len as u32)
            .unwrap();
    envelope.extend(vec![0; ciphertext_len]);
    STANDARD.encode(envelope)
}

/// A recipient with one Chat device and a published delivery capability.
struct Recipient {
    user: User,
    device_id: u32,
    registration_id: u32,
    capability: [u8; 16],
}

fn recipient(c: &Client, base: &str, seed: u8) -> Recipient {
    let user = register(c, base);
    let device = ChatAccount::of(&user, &user.token).reregister(c, base);
    let (device_id, registration_id) = (device.id, device.registration_id);
    let capability = [seed; 16];
    let version = "71".repeat(32);
    let profile = PutChatProfileRequest {
        suite: ProfileSuiteId::XChaCha20Poly1305V1,
        account: user.person.clone(),
        version: version.clone(),
        revision: 1,
        source_device_id: device_id,
        name: opaque_profile_envelope(
            &user.person,
            &version,
            ProfileEnvelopePurpose::DisplayName,
            kutup_chat_proto::PROFILE_NAME_PADDED_LENGTHS[0] + 16,
        ),
        avatar: None,
        about: None,
        wrapped_key: opaque_profile_envelope(
            &user.person,
            &version,
            ProfileEnvelopePurpose::WrappedProfileKey,
            48,
        ),
        access_key_verifier: "72".repeat(32),
        delivery_capability_verifier: hex::encode(Sha256::digest(capability)),
    };
    let r = bearer(
        device.auth(c.put(format!("{base}/api/chat/profile"))),
        &user.token,
    )
    .json(&profile)
    .send()
    .unwrap();
    assert!(
        r.status().is_success(),
        "publish profile: {}",
        r.text().unwrap()
    );
    Recipient {
        user,
        device_id,
        registration_id,
        capability,
    }
}

fn send(account_id: &str, send_id: &str, capability: &[u8], device: (u32, u32)) -> Value {
    json!({
        "accountId": account_id,
        "submission": {
            "sendId": send_id,
            "capability": STANDARD.encode(capability),
            "envelopes": [{
                "deviceId": device.0,
                "registrationId": device.1,
                "suite": 1,
                "content": STANDARD.encode([0x5au8; 96]),
            }]
        }
    })
}

fn batch(c: &Client, base: &str, server: &str, recipients: Vec<Value>) -> Vec<Value> {
    let r = c
        .post(format!(
            "{base}/api/chat/anonymous/messages/batch?server={server}"
        ))
        .json(&json!({ "recipients": recipients }))
        .send()
        .unwrap();
    let status = r.status();
    let body: Value = r.json().unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    body["results"].as_array().unwrap().clone()
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

/// Sends a wrong capability for `carol`'s account, an account that doesn't
/// exist (two uniform 404s), `bob` (deliverable, in the same batch after
/// them) and `carol` with a stale registration id, all to the accounts'
/// server `server` through `base`. Every answer uses up its sequence, a
/// device mismatch included: a send after it is delivered at once, and the
/// corrected resend (here first stale again, then right) goes under a new
/// sequence and is stored once.
fn exercise(c: &Client, base: &str, server: &str, bob: &Recipient, carol: &Recipient) {
    let bob_send = Uuid::new_v4().to_string();
    let wrong_send = Uuid::new_v4().to_string();
    let ghost_send = Uuid::new_v4().to_string();
    let carol_send = Uuid::new_v4().to_string();
    let ghost = Uuid::new_v4().to_string();
    let bob_ok = |send_id: &str| {
        send(
            &bob.user.person.account_id,
            send_id,
            &bob.capability,
            (bob.device_id, bob.registration_id),
        )
    };
    let carol_with = |registration_id: u32| {
        send(
            &carol.user.person.account_id,
            &carol_send,
            &carol.capability,
            (carol.device_id, registration_id),
        )
    };
    // Another registration id than Carol's, within range.
    let stale = |n: u32| (carol.registration_id + n - 1) % 16383 + 1;
    let outcome =
        |results: &[Value], index: usize| results[index]["outcome"].as_str().unwrap().to_owned();
    let results = batch(
        c,
        base,
        server,
        vec![
            send(
                &carol.user.person.account_id,
                &wrong_send,
                &[0xee; 16],
                (carol.device_id, carol.registration_id),
            ),
            send(&ghost, &ghost_send, &[0x11; 16], (1, 1)),
            bob_ok(&bob_send),
            carol_with(stale(1)),
        ],
    );
    assert_eq!(results.len(), 4, "{results:?}");
    // A wrong capability and an unknown account read the same.
    assert_eq!(outcome(&results, 0), "unavailable", "{results:?}");
    assert_eq!(outcome(&results, 1), "unavailable", "{results:?}");
    // Delivered after them, in the same (federated) batch.
    assert_eq!(outcome(&results, 2), "delivered", "{results:?}");
    assert_eq!(results[2]["sendId"], bob_send);
    assert_eq!(results[2]["deduplicated"], false);
    assert_eq!(outcome(&results, 3), "deviceMismatch", "{results:?}");
    assert!(results[3]["mismatch"]["staleDevices"].is_array());

    // (a) Carol's client hasn't resent: a later send isn't held behind it.
    let later_send = Uuid::new_v4().to_string();
    let later = batch(c, base, server, vec![bob_ok(&later_send)]);
    assert_eq!(outcome(&later, 0), "delivered", "{later:?}");

    // (c) A resend that is stale again is another mismatch, then the right
    // one is delivered.
    let stale_again = batch(c, base, server, vec![carol_with(stale(2))]);
    assert_eq!(
        outcome(&stale_again, 0),
        "deviceMismatch",
        "{stale_again:?}"
    );
    let corrected = batch(c, base, server, vec![carol_with(carol.registration_id)]);
    assert_eq!(outcome(&corrected, 0), "delivered", "{corrected:?}");
    assert_eq!(corrected[0]["deduplicated"], false, "{corrected:?}");

    // (b) Each was stored once: repeats are deduplicated.
    let again = batch(
        c,
        base,
        server,
        vec![
            bob_ok(&bob_send),
            bob_ok(&later_send),
            carol_with(carol.registration_id),
        ],
    );
    for result in &again {
        assert_eq!(result["outcome"], "delivered", "{again:?}");
        assert_eq!(result["deduplicated"], true, "{again:?}");
    }
}

#[test]
fn a_batch_answers_each_recipient_on_its_own() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let bob = recipient(&c, &base, 0x31);
    let carol = recipient(&c, &base, 0x32);
    let server = server_name(&c, &base);
    exercise(&c, &base, &server, &bob, &carol);

    // Malformed batches are refused whole.
    let r = c
        .post(format!("{base}/api/chat/anonymous/messages/batch"))
        .json(&json!({ "recipients": [] }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    purge_accounts(&c, &base, &[&bob.user, &carol.user]);
}

#[test]
fn a_batch_to_another_server_is_delivered_in_one_federated_request() {
    let (Ok(a), Ok(b)) = (
        std::env::var("KUTUP_FEDERATION_SERVER_A"),
        std::env::var("KUTUP_FEDERATION_SERVER_B"),
    ) else {
        eprintln!("KUTUP_FEDERATION_SERVER_A/B not set; skipping");
        return;
    };
    let (a, b) = (
        a.trim_end_matches('/').to_string(),
        b.trim_end_matches('/').to_string(),
    );
    let c = crate::common::client();
    let bob = recipient(&c, &b, 0x41);
    let carol = recipient(&c, &b, 0x42);
    let server_b = server_name(&c, &b);
    // Sent through server A: queued there, delivered to B as one batch.
    exercise(&c, &a, &server_b, &bob, &carol);

    // Within a send's 1 MiB envelope budget, but too large for one
    // federated transaction once wrapped: refused at once, never queued
    // (where it would wait at the head for good).
    let mut oversized = send(
        &bob.user.person.account_id,
        &Uuid::new_v4().to_string(),
        &bob.capability,
        (bob.device_id, bob.registration_id),
    );
    oversized["submission"]["envelopes"][0]["content"] =
        json!(STANDARD.encode(vec![0x5au8; 786_420]));
    let after = Uuid::new_v4().to_string();
    let results = batch(
        &c,
        &a,
        &server_b,
        vec![
            oversized,
            send(
                &bob.user.person.account_id,
                &after,
                &bob.capability,
                (bob.device_id, bob.registration_id),
            ),
        ],
    );
    assert_eq!(results[0]["outcome"], "refused", "{results:?}");
    assert_eq!(results[1]["outcome"], "delivered", "{results:?}");
    purge_accounts(&c, &b, &[&bob.user, &carol.user]);
}
