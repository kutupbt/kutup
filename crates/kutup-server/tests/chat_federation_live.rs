//! Live two-server contract for transport-only chat federation.
//!
//! Run only through `scripts/test-chat-federation.sh`. The script supplies two
//! isolated server URLs and drives three phases so it can take the destination
//! edge offline and restart the origin between queueing and verification.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use kutup_chat_proto::{
    DeviceManifest, ManifestDevice, TransparencyCheckpoint, UserPreKeyBundlesResponse,
};
use rand::RngCore;
use reqwest::blocking::{Client, Response};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

const ALICE_EMAIL: &str = "federation-alice@example.test";
const ALICE_USERNAME: &str = "alicefed";
const BOB_EMAIL: &str = "federation-bob@example.test";
const BOB_USERNAME: &str = "bobfed";
const PASSWORD: &str = "federation-live-password";
const ALICE_REGISTRATION_ID: u32 = 4101;
const BOB_REGISTRATION_ID_1: u32 = 4201;
const BOB_REGISTRATION_ID_2: u32 = 4202;

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn json_response(response: Response, context: &str) -> Value {
    let status = response.status();
    let body = response.text().unwrap();
    assert!(
        status.is_success(),
        "{context}: expected success, got {status}: {body}"
    );
    serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("{context}: invalid JSON ({error}): {body}"))
}

fn register_account(c: &Client, base: &str, email: &str, username: &str) -> String {
    let mut rng = rand::thread_rng();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    let mut kdf_salt = [0u8; 16];
    let mut login_key_salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut kdf_salt);
    rng.fill_bytes(&mut login_key_salt);

    let kek = kutup_crypto::kdf::derive_kek(PASSWORD, &kdf_salt).unwrap();
    let login_key = kutup_crypto::kdf::derive_login_key(PASSWORD, &login_key_salt).unwrap();
    let (public_key, secret_key) = kutup_crypto::sealedbox::generate_keypair();
    let (encrypted_master_key, master_key_nonce) =
        kutup_crypto::secretbox::seal(&master_key, kek.as_slice()).unwrap();
    let (encrypted_recovery_key, recovery_key_nonce) =
        kutup_crypto::secretbox::seal(&master_key, &recovery_entropy).unwrap();
    let (encrypted_private_key, private_key_nonce) =
        kutup_crypto::secretbox::seal(&secret_key, &master_key).unwrap();

    let response = c
        .post(format!("{base}/api/auth/register"))
        .json(&json!({
            "email": email,
            "username": username,
            "loginKey": b64(login_key.as_slice()),
            "encryptedMasterKey": b64(&encrypted_master_key),
            "masterKeyNonce": b64(&master_key_nonce),
            "encryptedRecoveryKey": b64(&encrypted_recovery_key),
            "recoveryKeyNonce": b64(&recovery_key_nonce),
            "encryptedPrivateKey": b64(&encrypted_private_key),
            "privateKeyNonce": b64(&private_key_nonce),
            "publicKey": b64(&public_key),
            "kdfSalt": b64(&kdf_salt),
            "loginKeySalt": b64(&login_key_salt),
            "recoveryProof": b64(&recovery_entropy),
        }))
        .send()
        .unwrap();
    json_response(response, &format!("register {username}"));
    login(c, base, email)
}

fn login(c: &Client, base: &str, email: &str) -> String {
    let preflight = json_response(
        c.get(format!("{base}/api/auth/login/preflight?email={email}"))
            .send()
            .unwrap(),
        "login preflight",
    );
    let salt = preflight["loginKeySalt"].as_str().unwrap();
    let login_key = kutup_crypto::kdf::derive_login_key_b64(PASSWORD, salt).unwrap();
    let response = json_response(
        c.post(format!("{base}/api/auth/login"))
            .json(&json!({"email": email, "loginKey": b64(login_key.as_slice())}))
            .send()
            .unwrap(),
        "login",
    );
    response["accessToken"].as_str().unwrap().to_string()
}

fn register_device(c: &Client, base: &str, token: &str, registration_id: u32, seed: u8) -> u32 {
    let key = |offset: u8| b64(&[seed.wrapping_add(offset); 33]);
    let response = json_response(
        c.post(format!("{base}/api/chat/device"))
            .bearer_auth(token)
            .json(&json!({
                "suite": 1,
                "registrationId": registration_id,
                "identityKey": key(1),
                "signedPreKey": {
                    "keyId": 1,
                    "publicKey": key(2),
                    "signature": key(3)
                },
                "lastResortKyberPreKey": {
                    "keyId": 1,
                    "publicKey": key(4),
                    "signature": key(5)
                },
                "oneTimePreKeys": [{"keyId": 10, "publicKey": key(6)}],
                "oneTimeKyberPreKeys": [{
                    "keyId": 20,
                    "publicKey": key(7),
                    "signature": key(8)
                }],
                "name": format!("federation-test-{seed}")
            }))
            .send()
            .unwrap(),
        "register chat device",
    );
    response["deviceId"].as_u64().unwrap() as u32
}

fn manifest_device(device_id: u32, registration_id: u32, seed: u8) -> ManifestDevice {
    ManifestDevice {
        device_id,
        registration_id,
        identity_key: b64(&[seed.wrapping_add(1); 33]),
    }
}

fn publish_manifest(
    c: &Client,
    base: &str,
    token: &str,
    signing: &SigningKey,
    version: u64,
    previous_hash: Option<String>,
    devices: Vec<ManifestDevice>,
) -> DeviceManifest {
    let public = signing.verifying_key();
    let mut manifest = DeviceManifest {
        version,
        previous_hash,
        devices,
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        authority_key_id: hex::encode(Sha256::digest(public.as_bytes())),
        self_authority_key: b64(public.as_bytes()),
        signature: String::new(),
    };
    manifest.signature = b64(&signing.sign(&manifest.signing_bytes().unwrap()).to_bytes());
    let response = c
        .post(format!("{base}/api/chat/manifest"))
        .bearer_auth(token)
        .json(&manifest)
        .send()
        .unwrap();
    assert!(response.status().is_success());
    manifest
}

fn envelope(device_id: u32, registration_id: u32, content: &[u8]) -> Value {
    json!({
        "deviceId": device_id,
        "registrationId": registration_id,
        "envelopeType": "message",
        "suite": 1,
        "content": b64(content)
    })
}

fn send(
    c: &Client,
    base: &str,
    token: &str,
    recipient: &str,
    send_id: &str,
    envelopes: Vec<Value>,
) -> Response {
    c.post(format!("{base}/api/chat/users/{recipient}/messages"))
        .bearer_auth(token)
        .json(&json!({
            "senderDeviceId": 1,
            "sendId": send_id,
            "envelopes": envelopes
        }))
        .send()
        .unwrap()
}

fn mailbox(c: &Client, base: &str, token: &str, device_id: u32) -> Vec<Value> {
    let page = json_response(
        c.get(format!(
            "{base}/api/chat/messages?deviceId={device_id}&limit=100"
        ))
        .bearer_auth(token)
        .send()
        .unwrap(),
        "drain mailbox",
    );
    page["envelopes"].as_array().unwrap().clone()
}

fn assert_content_once(messages: &[Value], content: &[u8]) {
    let encoded = b64(content);
    assert_eq!(
        messages
            .iter()
            .filter(|message| message["content"] == encoded)
            .count(),
        1,
        "ciphertext must appear exactly once"
    );
}

fn setup_phase(c: &Client, a: &str, b: &str) {
    let discovery_a = json_response(
        c.get(format!("{a}/.well-known/kutup/federation.json"))
            .send()
            .unwrap(),
        "server A discovery",
    );
    let discovery_b = json_response(
        c.get(format!("{b}/.well-known/kutup/federation.json"))
            .send()
            .unwrap(),
        "server B discovery",
    );
    assert_eq!(discovery_a["server"], "a.test");
    assert_eq!(discovery_a["apiBase"], "http://a.test");
    assert_eq!(discovery_b["server"], "b.test");
    assert_eq!(discovery_b["apiBase"], "http://b.test");
    assert_ne!(discovery_a["signingKeys"], discovery_b["signingKeys"]);

    let alice_token = register_account(c, a, ALICE_EMAIL, ALICE_USERNAME);
    let bob_token = register_account(c, b, BOB_EMAIL, BOB_USERNAME);
    assert_eq!(
        register_device(c, a, &alice_token, ALICE_REGISTRATION_ID, 10),
        1
    );
    assert_eq!(
        register_device(c, b, &bob_token, BOB_REGISTRATION_ID_1, 20),
        1
    );
    let bob_authority = SigningKey::from_bytes(&[82; 32]);
    let bob_manifest_v1 = publish_manifest(
        c,
        b,
        &bob_token,
        &bob_authority,
        1,
        None,
        vec![manifest_device(1, BOB_REGISTRATION_ID_1, 20)],
    );

    // The local server signs this lookup, B authenticates A through discovery,
    // and replay-safe remote reads do not consume B's one-time prekeys.
    let remote_address = format!("{BOB_USERNAME}@b.test");
    let fetch = || {
        json_response(
            c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
                .bearer_auth(&alice_token)
                .send()
                .unwrap(),
            "remote bundle fetch",
        )
    };
    let bundles_first = fetch();
    let bundles_second = fetch();
    assert_eq!(bundles_first, bundles_second);
    assert_eq!(bundles_first["username"], remote_address);
    assert_eq!(bundles_first["devices"][0]["deviceId"], 1);
    assert!(bundles_first["devices"][0].get("oneTimePreKey").is_none());
    let typed_first: UserPreKeyBundlesResponse =
        serde_json::from_value(bundles_first.clone()).unwrap();
    let first_proof = typed_first.transparency.as_ref().unwrap();
    first_proof.verify_inclusion().unwrap();
    first_proof.verify_current_map().unwrap();
    first_proof.verify_authentication().unwrap();
    first_proof.verify_consistency_from(None).unwrap();
    let first_checkpoint: TransparencyCheckpoint = first_proof.checkpoint.clone();

    let direct_content = b"federated-direct";
    let direct_id = "10000000-0000-4000-8000-000000000001";
    let response = json_response(
        send(
            c,
            a,
            &alice_token,
            &remote_address,
            direct_id,
            vec![envelope(1, BOB_REGISTRATION_ID_1, direct_content)],
        ),
        "federated direct send",
    );
    assert_eq!(response["stored"], 1);
    assert_eq!(response["deduplicated"], false);

    let retry = json_response(
        send(
            c,
            a,
            &alice_token,
            &remote_address,
            direct_id,
            vec![envelope(1, BOB_REGISTRATION_ID_1, direct_content)],
        ),
        "idempotent federated retry",
    );
    assert_eq!(retry["deduplicated"], true);
    let bob_device_1 = mailbox(c, b, &bob_token, 1);
    assert_content_once(&bob_device_1, direct_content);
    let direct = bob_device_1
        .iter()
        .find(|message| message["content"] == b64(direct_content))
        .unwrap();
    assert_eq!(direct["sender"], "alicefed@a.test");

    assert_eq!(
        register_device(c, b, &bob_token, BOB_REGISTRATION_ID_2, 30),
        2
    );
    let bob_manifest_v2 = publish_manifest(
        c,
        b,
        &bob_token,
        &bob_authority,
        2,
        Some(bob_manifest_v1.manifest_hash().unwrap()),
        vec![
            manifest_device(1, BOB_REGISTRATION_ID_1, 20),
            manifest_device(2, BOB_REGISTRATION_ID_2, 30),
        ],
    );
    let refreshed_bundles = json_response(
        c.get(format!(
            "{a}/api/chat/users/{remote_address}/keys?transparencyTreeSize={}",
            first_checkpoint.tree_size
        ))
        .bearer_auth(&alice_token)
        .send()
        .unwrap(),
        "remote bundle transparency refresh",
    );
    let typed_refreshed: UserPreKeyBundlesResponse =
        serde_json::from_value(refreshed_bundles).unwrap();
    assert_eq!(typed_refreshed.manifest.as_ref(), Some(&bob_manifest_v2));
    let refreshed_proof = typed_refreshed.transparency.as_ref().unwrap();
    refreshed_proof.verify_inclusion().unwrap();
    refreshed_proof.verify_current_map().unwrap();
    refreshed_proof.verify_authentication().unwrap();
    refreshed_proof
        .verify_consistency_from(Some(&first_checkpoint))
        .unwrap();
    let mismatch_id = "10000000-0000-4000-8000-000000000002";
    let mismatch = send(
        c,
        a,
        &alice_token,
        &remote_address,
        mismatch_id,
        vec![envelope(1, BOB_REGISTRATION_ID_1, b"stale-device-set")],
    );
    assert_eq!(mismatch.status().as_u16(), 409);
    let mismatch: Value = mismatch.json().unwrap();
    assert_eq!(mismatch["missingDevices"], json!([2]));

    let refreshed_content = b"refreshed-device-set";
    json_response(
        send(
            c,
            a,
            &alice_token,
            &remote_address,
            mismatch_id,
            vec![
                envelope(1, BOB_REGISTRATION_ID_1, refreshed_content),
                envelope(2, BOB_REGISTRATION_ID_2, refreshed_content),
            ],
        ),
        "retry after remote device mismatch",
    );
    assert_content_once(&mailbox(c, b, &bob_token, 1), refreshed_content);
    assert_content_once(&mailbox(c, b, &bob_token, 2), refreshed_content);

    // Unknown recipients consume their sequence as a terminal rejection. A
    // later valid send must not be poisoned behind that outbox entry.
    let unavailable = send(
        c,
        a,
        &alice_token,
        "missing@b.test",
        "10000000-0000-4000-8000-000000000003",
        vec![envelope(1, 999, b"unavailable")],
    );
    assert_eq!(unavailable.status().as_u16(), 404);

    let after_rejection = b"after-terminal-rejection";
    json_response(
        send(
            c,
            a,
            &alice_token,
            &remote_address,
            "10000000-0000-4000-8000-000000000004",
            vec![
                envelope(1, BOB_REGISTRATION_ID_1, after_rejection),
                envelope(2, BOB_REGISTRATION_ID_2, after_rejection),
            ],
        ),
        "valid send after terminal rejection",
    );
    assert_content_once(&mailbox(c, b, &bob_token, 1), after_rejection);
    assert_content_once(&mailbox(c, b, &bob_token, 2), after_rejection);

    let unsigned = c
        .get(format!("{b}/api/fed/chat/users/{BOB_USERNAME}/keys"))
        .send()
        .unwrap();
    assert_eq!(unsigned.status().as_u16(), 401);
}

fn queue_phase(c: &Client, a: &str) {
    let alice_token = login(c, a, ALICE_EMAIL);
    let response = send(
        c,
        a,
        &alice_token,
        &format!("{BOB_USERNAME}@b.test"),
        "10000000-0000-4000-8000-000000000005",
        vec![
            envelope(1, BOB_REGISTRATION_ID_1, b"queued-during-outage"),
            envelope(2, BOB_REGISTRATION_ID_2, b"queued-during-outage"),
        ],
    );
    assert_eq!(response.status().as_u16(), 503);
}

fn verify_retry_phase(c: &Client, a: &str, b: &str) {
    let bob_token = login(c, b, BOB_EMAIL);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let first = mailbox(c, b, &bob_token, 1);
        let second = mailbox(c, b, &bob_token, 2);
        let encoded = b64(b"queued-during-outage");
        if first.iter().any(|message| message["content"] == encoded)
            && second.iter().any(|message| message["content"] == encoded)
        {
            assert_content_once(&first, b"queued-during-outage");
            assert_content_once(&second, b"queued-during-outage");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "durably queued federation send was not retried"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    let alice_token = login(c, a, ALICE_EMAIL);
    let follow_up = b"after-origin-restart";
    json_response(
        send(
            c,
            a,
            &alice_token,
            &format!("{BOB_USERNAME}@b.test"),
            "10000000-0000-4000-8000-000000000006",
            vec![
                envelope(1, BOB_REGISTRATION_ID_1, follow_up),
                envelope(2, BOB_REGISTRATION_ID_2, follow_up),
            ],
        ),
        "send after durable retry",
    );
    assert_content_once(&mailbox(c, b, &bob_token, 1), follow_up);
    assert_content_once(&mailbox(c, b, &bob_token, 2), follow_up);
}

#[test]
fn chat_federation_live() {
    let Ok(phase) = std::env::var("KUTUP_FEDERATION_PHASE") else {
        eprintln!("KUTUP_FEDERATION_PHASE unset — skipping two-server live test");
        return;
    };
    let a = std::env::var("KUTUP_FEDERATION_SERVER_A").unwrap();
    let b = std::env::var("KUTUP_FEDERATION_SERVER_B").unwrap();
    let c = client();

    match phase.as_str() {
        "setup" => setup_phase(&c, &a, &b),
        "queue" => queue_phase(&c, &a),
        "verify-retry" => verify_retry_phase(&c, &a, &b),
        _ => panic!("unknown KUTUP_FEDERATION_PHASE: {phase}"),
    }
}
