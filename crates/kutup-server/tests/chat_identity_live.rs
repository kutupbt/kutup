//! One libsignal identity per account (docs/plans/account-identity-key.md),
//! against a live server: re-registration, device credentials, prekey
//! signatures, linking (link tokens, the provisioning socket and relay), V2
//! bundles, keys/check, the identity distribution and a lost-device reset.
//!
//!   KUTUP_LIVE_SERVER=http://localhost:39083 \
//!     cargo test -p kutup-server --test chat_identity_live -- --nocapture

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::chat_identity::{device_keys, ChatAccount, ChatDevice};
use futures_util::StreamExt as _;
use kutup_chat_proto::{
    repeated_use_keys_digest, AccountIdentityDistributionRequest, AccountPreKeyBundlesResponse,
    DeviceRegistrationV1, DirectChatSuiteId, DistributedDeviceKeysV1, EnvelopeType,
    OutgoingEnvelope, ProvisionEnvelopeV1, ProvisioningSocketMessage, CHAT_DEVICE_HEADER,
};
use libsignal_protocol::IdentityKeyPair;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn live() -> Option<String> {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return None;
    };
    Some(base.trim_end_matches('/').to_string())
}

fn account(c: &Client, base: &str) -> ChatAccount {
    let user = common::register(c, base);
    let token = user.token.clone();
    ChatAccount::of(&user, &token)
}

fn code(response: reqwest::blocking::Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, response.json().unwrap_or_default())
}

fn bundles(
    c: &Client,
    base: &str,
    asker: &ChatAccount,
    of: &ChatAccount,
) -> AccountPreKeyBundlesResponse {
    let r = c
        .get(format!(
            "{base}/api/chat/accounts/{}/keys",
            of.account.account_id
        ))
        .bearer_auth(&asker.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().unwrap()
}

#[test]
fn a_first_device_reregisters_and_a_second_links() {
    let Some(base) = live() else { return };
    let c = common::client();
    let mut ada = account(&c, &base);

    // Without a link token or a re-registration: refused at the JSON
    // boundary (exactly one kind, by type).
    let mut body = serde_json::to_value(ada.registration(
        7,
        &[1; 32],
        DeviceRegistrationV1::Link {
            link_token: URL_SAFE_NO_PAD.encode([0u8; 32]),
        },
    ))
    .unwrap();
    body.as_object_mut().unwrap().remove("registration");
    let r = c
        .post(format!("{base}/api/chat/device"))
        .bearer_auth(&ada.token)
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 422);
    // Linking before the account has an identity: re-register first.
    let link = ada.registration(
        7,
        &[1; 32],
        DeviceRegistrationV1::Link {
            link_token: URL_SAFE_NO_PAD.encode([0u8; 32]),
        },
    );
    let (status, answer) = code(ada.post_registration(&c, &base, &link));
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "noAccountIdentity");

    // A signed prekey under another identity: refused.
    let mut forged = ada.registration(
        9,
        &[2; 32],
        DeviceRegistrationV1::Reregistration {
            manifest: Box::new(ada.next_manifest(&[&ChatDevice {
                id: 1,
                registration_id: 9,
                credential: [2; 32],
            }])),
        },
    );
    let other = IdentityKeyPair::generate(&mut rand09::rng());
    forged.signed_pre_key = device_keys(&other).0;
    let (status, answer) = code(ada.post_registration(&c, &base, &forged));
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "badSignature");

    let first = ada.reregister(&c, &base);
    assert_eq!(first.id, 1);

    // Device-bound calls need the device's credential.
    let r = c
        .post(format!("{base}/api/chat/link-tokens"))
        .bearer_auth(&ada.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let wrong = ChatDevice {
        credential: [9; 32],
        ..first.clone()
    };
    let (status, answer) = code(
        wrong
            .auth(c.post(format!("{base}/api/chat/link-tokens")))
            .bearer_auth(&ada.token)
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer["code"], "deviceCredential");

    // A second device, linked; the token works once, for this account only.
    let second = ada.link(&c, &base, &first);
    assert_eq!(second.id, 2);
    let token = ada.link_token(&c, &base, &first);
    let mut bob = account(&c, &base);
    bob.reregister(&c, &base);
    let stolen = bob.registration(
        11,
        &[3; 32],
        DeviceRegistrationV1::Link {
            link_token: token.clone(),
        },
    );
    let (status, answer) = code(bob.post_registration(&c, &base, &stolen));
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["code"], "linkToken");
    // Ada's token with another identity: refused.
    let mut wrong_identity = bob.registration(
        12,
        &[4; 32],
        DeviceRegistrationV1::Link { link_token: token },
    );
    wrong_identity.registration = DeviceRegistrationV1::Link {
        link_token: ada.link_token(&c, &base, &first),
    };
    let (status, answer) = code(ada.post_registration(&c, &base, &wrong_identity));
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "identityMismatch");

    // Bundles: the identity once, both devices, checked against the manifest.
    let fetched = bundles(&c, &base, &bob, &ada);
    fetched.check_against_manifest().unwrap();
    assert_eq!(fetched.identity_key, ada.identity_key());
    assert_eq!(fetched.devices.len(), 2);
    assert_eq!(fetched.manifest, *ada.head.as_ref().unwrap());

    // keys/check: the device's own keys match; another digest doesn't.
    let r = first
        .auth(c.post(format!("{base}/api/chat/keys/check")))
        .bearer_auth(&ada.token)
        .json(&json!({ "digest": hex::encode([0u8; 32]) }))
        .send()
        .unwrap();
    let (status, answer) = code(r);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(answer["code"], "keysDiffer");
    // (The matching case: keys_check_agrees_with_what_was_uploaded.)

    // A manifest naming another identity: only a distribution changes it.
    let mut stray = ChatAccount {
        identity: IdentityKeyPair::generate(&mut rand09::rng()),
        account: ada.account.clone(),
        token: ada.token.clone(),
        authority: ada.authority.clone(),
        drive: ada.drive.clone(),
        devices: ada.devices.clone(),
        head: ada.head.clone(),
    };
    let manifest = stray.next_manifest(&[&first, &second]);
    let (status, answer) = code(
        first
            .auth(c.post(format!("{base}/api/chat/manifest")))
            .bearer_auth(&ada.token)
            .json(&manifest)
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "identityMismatch");
    stray.devices.clear();
}

#[test]
fn keys_check_agrees_with_what_was_uploaded() {
    let Some(base) = live() else { return };
    let c = common::client();
    let mut ada = account(&c, &base);
    let first = ada.reregister(&c, &base);
    // Rotate both repeated-use keys, then check them.
    let (signed, last_resort, _, _) = device_keys(&ada.identity);
    let r = first
        .auth(c.put(format!("{base}/api/chat/keys?deviceId={}", first.id)))
        .bearer_auth(&ada.token)
        .json(&json!({ "signedPreKey": signed, "lastResortKyberPreKey": last_resort }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let digest = repeated_use_keys_digest(
        &ada.identity.identity_key().serialize(),
        signed.key_id,
        &STANDARD.decode(&signed.public_key).unwrap(),
        last_resort.key_id,
        &STANDARD.decode(&last_resort.public_key).unwrap(),
    );
    let r = first
        .auth(c.post(format!("{base}/api/chat/keys/check")))
        .bearer_auth(&ada.token)
        .json(&json!({ "digest": hex::encode(digest) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    // A replenished key under another identity: refused.
    let other = IdentityKeyPair::generate(&mut rand09::rng());
    let (foreign, _, _, _) = device_keys(&other);
    let (status, answer) = code(
        first
            .auth(c.put(format!("{base}/api/chat/keys?deviceId={}", first.id)))
            .bearer_auth(&ada.token)
            .json(&json!({ "signedPreKey": foreign }))
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(answer["code"], "badSignature");
}

fn distribution(
    ada: &ChatAccount,
    new_identity: &IdentityKeyPair,
    kept: &[(&ChatDevice, u32)],
    messages_to: &[&ChatDevice],
) -> (AccountIdentityDistributionRequest, ChatAccount) {
    let mut next = ChatAccount {
        identity: *new_identity,
        account: ada.account.clone(),
        token: ada.token.clone(),
        authority: ada.authority.clone(),
        drive: ada.drive.clone(),
        devices: kept
            .iter()
            .map(|(device, registration_id)| ChatDevice {
                registration_id: *registration_id,
                ..(*device).clone()
            })
            .collect(),
        head: ada.head.clone(),
    };
    let listed: Vec<&ChatDevice> = next.devices.iter().collect();
    let manifest = next.next_manifest(&listed);
    let devices = next
        .devices
        .iter()
        .map(|device| {
            let (signed, last_resort, _, _) = device_keys(new_identity);
            DistributedDeviceKeysV1 {
                device_id: device.id,
                registration_id: device.registration_id,
                signed_pre_key: signed,
                last_resort_kyber_pre_key: last_resort,
            }
        })
        .collect();
    let device_messages = messages_to
        .iter()
        .map(|device| OutgoingEnvelope {
            device_id: device.id,
            registration_id: device.registration_id,
            envelope_type: EnvelopeType::Message,
            suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            content: STANDARD.encode(b"an accountIdentity sync, sealed on its session"),
        })
        .collect();
    next.head = Some(manifest.clone());
    (
        AccountIdentityDistributionRequest {
            identity_key: STANDARD.encode(new_identity.identity_key().serialize()),
            devices,
            device_messages,
            manifest,
        },
        next,
    )
}

#[test]
fn a_distribution_gives_the_kept_devices_a_new_identity() {
    let Some(base) = live() else { return };
    let c = common::client();
    let mut ada = account(&c, &base);
    let first = ada.reregister(&c, &base);
    let second = ada.link(&c, &base, &first);
    let third = ada.link(&c, &base, &first);
    let bob = {
        let mut bob = account(&c, &base);
        bob.reregister(&c, &base);
        bob
    };
    let new_identity = IdentityKeyPair::generate(&mut rand09::rng());
    let put = |request: &AccountIdentityDistributionRequest| {
        first
            .auth(c.put(format!("{base}/api/chat/account-identity")))
            .bearer_auth(&ada.token)
            .json(request)
            .send()
            .unwrap()
    };

    // A message missing for a kept device: 409 with the mismatch.
    let (request, _) = distribution(
        &ada,
        &new_identity,
        &[(&first, 101), (&second, 102), (&third, 103)],
        &[&second],
    );
    let (status, answer) = code(put(&request));
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["missingDevices"], json!([3]));
    // A message on a session the device no longer has: 410.
    let stale = ChatDevice {
        registration_id: second.registration_id % 16383 + 1,
        ..second.clone()
    };
    let (request, _) = distribution(
        &ada,
        &new_identity,
        &[(&first, 101), (&second, 102), (&third, 103)],
        &[&stale, &third],
    );
    let (status, answer) = code(put(&request));
    assert_eq!(status, StatusCode::GONE, "{answer}");
    assert_eq!(answer["staleDevices"], json!([2]));

    // The lost third device left out: the kept two get the new identity, the
    // third's row goes, and every one-time key goes.
    let (request, next) = distribution(
        &ada,
        &new_identity,
        &[(&first, 101), (&second, 102)],
        &[&second],
    );
    let (status, answer) = code(put(&request));
    assert_eq!(status, StatusCode::OK, "{answer}");
    let fetched = bundles(&c, &base, &bob, &next);
    fetched.check_against_manifest().unwrap();
    assert_eq!(fetched.identity_key, next.identity_key());
    let ids: Vec<u32> = fetched.devices.iter().map(|d| d.device_id).collect();
    assert_eq!(ids, [1, 2]);
    assert!(fetched.devices.iter().all(|d| d.one_time_pre_key.is_none()));
    // The third device's credential no longer works.
    let r = third
        .auth(c.post(format!("{base}/api/chat/link-tokens")))
        .bearer_auth(&ada.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // The second device has its sync waiting in its mailbox.
    let renamed = ChatDevice {
        registration_id: 102,
        ..second.clone()
    };
    let page: Value = renamed
        .auth(c.get(format!("{base}/api/chat/messages?deviceId=2")))
        .bearer_auth(&ada.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        page["envelopes"].as_array().map(Vec::len),
        Some(1),
        "{page}"
    );
    // Taken, as the device takes it (the mailbox sweep is server-wide).
    let r = renamed
        .auth(c.post(format!("{base}/api/chat/messages/ack?deviceId=2")))
        .bearer_auth(&ada.token)
        .json(&json!({ "ids": [page["envelopes"][0]["id"]] }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "ack: {}", r.status());
}

#[test]
fn a_reregistration_drops_every_other_device() {
    let Some(base) = live() else { return };
    let c = common::client();
    let mut ada = account(&c, &base);
    let first = ada.reregister(&c, &base);
    let second = ada.link(&c, &base, &first);
    // Every device lost: a new device takes a new identity as device 1.
    ada.identity = IdentityKeyPair::generate(&mut rand09::rng());
    let again = ada.reregister(&c, &base);
    assert_eq!(again.id, 1);
    for gone in [&first, &second] {
        let r = gone
            .auth(c.post(format!("{base}/api/chat/link-tokens")))
            .bearer_auth(&ada.token)
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    let bob = {
        let mut bob = account(&c, &base);
        bob.reregister(&c, &base);
        bob
    };
    let fetched = bundles(&c, &base, &bob, &ada);
    assert_eq!(fetched.identity_key, ada.identity_key());
    assert_eq!(fetched.devices.len(), 1);
    assert_eq!(fetched.manifest.sequence, 3);
}

#[test]
fn a_provisioning_message_reaches_the_new_device_once() {
    let Some(base) = live() else { return };
    let c = common::client();
    let mut ada = account(&c, &base);
    let first = ada.reregister(&c, &base);
    let bob = {
        let mut bob = account(&c, &base);
        let device = bob.reregister(&c, &base);
        (bob, device)
    };
    let ticket: Value = c
        .post(format!("{base}/api/chat/provisioning/ticket"))
        .bearer_auth(&ada.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let url = format!(
        "{}/api/chat/provisioning?ticket={}",
        base.replacen("http", "ws", 1),
        ticket["ticket"].as_str().unwrap()
    );
    let envelope = ProvisionEnvelopeV1 {
        public_key: STANDARD.encode(
            libsignal_protocol::KeyPair::generate(&mut rand09::rng())
                .public_key
                .serialize(),
        ),
        body: STANDARD.encode([&[1u8][..], &[7u8; 16 + 32 + 32]].concat()),
    };
    let expected = ProvisioningSocketMessage::Envelope {
        envelope: envelope.clone(),
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        use tokio_tungstenite::tungstenite::Message;
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let first_message = socket.next().await.unwrap().unwrap();
        let Message::Text(text) = first_message else {
            panic!("an address first")
        };
        let ProvisioningSocketMessage::Address { address } = serde_json::from_str(&text).unwrap()
        else {
            panic!("an address first")
        };
        let relay = |device: &ChatDevice, token: &str| {
            let c = c.clone();
            let header = device.header();
            let url = format!("{base}/api/chat/provisioning/{address}");
            let token = token.to_owned();
            let body = json!({ "envelope": envelope });
            std::thread::spawn(move || {
                c.put(url)
                    .header(CHAT_DEVICE_HEADER, header)
                    .bearer_auth(token)
                    .json(&body)
                    .send()
                    .unwrap()
                    .status()
            })
            .join()
            .unwrap()
        };
        // Another account can't reach it: the same 404 as no socket.
        assert_eq!(relay(&bob.1, &bob.0.token), StatusCode::NOT_FOUND);
        assert_eq!(relay(&first, &ada.token), StatusCode::NO_CONTENT);
        let mut got = None;
        while let Some(message) = socket.next().await {
            match message.unwrap() {
                Message::Text(text) => got = Some(serde_json::from_str(&text).unwrap()),
                Message::Close(frame) => {
                    assert_eq!(frame.map(|f| u16::from(f.code)), Some(1000));
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(got, Some(expected));
        // Once only: the address is gone.
        assert_eq!(relay(&first, &ada.token), StatusCode::NOT_FOUND);
        let _ = socket.close(None).await;
    });
}

/// A registration retried after its answer was lost (the same credential)
/// answers the device it made: a re-registration once its manifest is the
/// head, and a link once its token is spent.
#[test]
fn a_retried_registration_answers_the_device_it_made() {
    let Some(base) = live() else { return };
    let c = common::client();
    let mut ada = account(&c, &base);
    let first = ChatDevice {
        id: 1,
        registration_id: 4321,
        credential: [5; 32],
    };
    let manifest = ada.next_manifest(&[&first]);
    let body = ada.registration(
        first.registration_id,
        &first.credential,
        DeviceRegistrationV1::Reregistration {
            manifest: Box::new(manifest.clone()),
        },
    );
    for _ in 0..2 {
        let (status, answer) = code(ada.post_registration(&c, &base, &body));
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["deviceId"], 1);
    }
    ada.head = Some(manifest);
    ada.devices = vec![first.clone()];

    let token = ada.link_token(&c, &base, &first);
    let body = ada.registration(
        1234,
        &[6; 32],
        DeviceRegistrationV1::Link { link_token: token },
    );
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (status, answer) = code(ada.post_registration(&c, &base, &body));
        assert_eq!(status, StatusCode::OK, "{answer}");
        ids.push(answer["deviceId"].clone());
    }
    assert_eq!(ids, [json!(2), json!(2)]);
}
