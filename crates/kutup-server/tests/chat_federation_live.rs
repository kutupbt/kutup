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
    DeviceManifest, ManifestDevice, ManifestUpdateRangeProofV1, TransparencyCheckpoint,
    UserPreKeyBundlesResponse,
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
const ADMIN_TEMP_PASSWORD: &str = "federation-admin-temp";
const ADMIN_A_EMAIL: &str = "federation-admin-a@example.test";
const ADMIN_B_EMAIL: &str = "federation-admin-b@example.test";
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

fn federation_control_plane(c: &Client, base: &str, admin: &str, context: &str) -> Value {
    json_response(
        c.get(format!("{base}/api/admin/federation"))
            .bearer_auth(admin)
            .send()
            .unwrap(),
        context,
    )
}

fn federation_peer<'a>(control_plane: &'a Value, domain: &str) -> &'a Value {
    control_plane["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|peer| peer["domain"] == domain)
        .unwrap_or_else(|| panic!("missing federation peer {domain}"))
}

fn registration_payload(email: &str, username: &str) -> Value {
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

    json!({
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
    })
}

fn register_account(c: &Client, base: &str, email: &str, username: &str) -> String {
    let response = c
        .post(format!("{base}/api/auth/register"))
        .json(&registration_payload(email, username))
        .send()
        .unwrap();
    json_response(response, &format!("register {username}"));
    login(c, base, email)
}

fn setup_admin(c: &Client, base: &str, email: &str, username: &str) -> String {
    let login = json_response(
        c.post(format!("{base}/api/auth/login"))
            .json(&json!({
                "email": email,
                "loginKey": b64(ADMIN_TEMP_PASSWORD.as_bytes()),
            }))
            .send()
            .unwrap(),
        "bootstrap admin login",
    );
    assert_eq!(login["requiresSetup"], true);
    let setup_token = login["setupToken"].as_str().unwrap();
    let setup = json_response(
        c.post(format!("{base}/api/auth/complete-setup"))
            .bearer_auth(setup_token)
            .json(&registration_payload(email, username))
            .send()
            .unwrap(),
        "bootstrap admin setup",
    );
    assert_eq!(setup["isAdmin"], true);
    setup["accessToken"].as_str().unwrap().to_string()
}

fn update_feature_mode(c: &Client, base: &str, admin: &str, feature: &str, mode: &str) -> Value {
    update_feature_policy(c, base, admin, feature, mode, true)
}

fn update_feature_policy(
    c: &Client,
    base: &str,
    admin: &str,
    feature: &str,
    mode: &str,
    global_enabled: bool,
) -> Value {
    let response = json_response(
        c.put(format!("{base}/api/admin/federation"))
            .bearer_auth(admin)
            .json(&json!({
                "globalEnabled": global_enabled,
                "feature": feature,
                "mode": mode,
                "minimumTrust": "tofu"
            }))
            .send()
            .unwrap(),
        "update federation mode",
    );
    response["features"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["feature"] == feature)
        .unwrap()
        .clone()
}

fn drive_remote_user(c: &Client, base: &str, token: &str) -> Response {
    c.get(format!(
        "{base}/api/drive/federation/users/{BOB_USERNAME}?server=b.test"
    ))
    .bearer_auth(token)
    .send()
    .unwrap()
}

fn update_federation_mode(c: &Client, base: &str, admin: &str, mode: &str) -> Value {
    update_feature_mode(c, base, admin, "chat", mode)
}

fn upsert_federation_rule(
    c: &Client,
    base: &str,
    admin: &str,
    domain: &str,
    inbound: &str,
    outbound: &str,
) -> Value {
    upsert_feature_rule(c, base, admin, "chat", domain, inbound, outbound)
}

fn upsert_feature_rule(
    c: &Client,
    base: &str,
    admin: &str,
    feature: &str,
    domain: &str,
    inbound: &str,
    outbound: &str,
) -> Value {
    json_response(
        c.put(format!(
            "{base}/api/admin/federation/rules/{feature}/{domain}"
        ))
        .bearer_auth(admin)
        .json(&json!({
            "inbound": inbound,
            "outbound": outbound,
            "trustRequirement": "inherit"
        }))
        .send()
        .unwrap(),
        "upsert federation rule",
    )
}

fn delete_federation_rule(c: &Client, base: &str, admin: &str, domain: &str) -> Value {
    delete_feature_rule(c, base, admin, "chat", domain)
}

fn delete_feature_rule(c: &Client, base: &str, admin: &str, feature: &str, domain: &str) -> Value {
    json_response(
        c.delete(format!(
            "{base}/api/admin/federation/rules/{feature}/{domain}"
        ))
        .bearer_auth(admin)
        .send()
        .unwrap(),
        "delete federation rule",
    )
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

fn drive_upload_body(boundary: &str, ciphertext: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in [
        ("encryptedMetadata", "drive-encrypted-metadata"),
        ("metadataNonce", "drive-metadata-nonce"),
        ("encryptedFileKey", "drive-wrapped-file-key"),
        ("fileKeyNonce", "drive-file-key-nonce"),
    ] {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ciphertext\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(ciphertext);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn drive_round_trip(c: &Client, a: &str, b: &str, alice_token: &str, bob_token: &str) {
    let collection = json_response(
        c.post(format!("{a}/api/collections"))
            .bearer_auth(alice_token)
            .json(&json!({
                "encryptedName": "drive-encrypted-name",
                "nameNonce": "drive-name-nonce",
                "encryptedKey": "drive-owner-key",
                "encryptedKeyNonce": "drive-owner-key-nonce"
            }))
            .send()
            .unwrap(),
        "create Drive collection",
    );
    let collection_id = collection["id"].as_str().unwrap();

    let remote_user = json_response(
        drive_remote_user(c, a, alice_token),
        "signed Drive remote user lookup",
    );
    assert_eq!(remote_user["username"], BOB_USERNAME);
    assert_eq!(remote_user["server"], "b.test");
    assert!(!remote_user["publicKey"].as_str().unwrap().is_empty());

    let share = json_response(
        c.post(format!(
            "{a}/api/collections/{collection_id}/federated-shares"
        ))
        .bearer_auth(alice_token)
        .json(&json!({
            "recipientUsername": BOB_USERNAME,
            "recipientServer": "b.test",
            "encryptedCollectionKey": "drive-recipient-wrapped-key",
            "canUpload": true,
            "canDelete": true,
            "uploadQuotaBytes": 1048576
        }))
        .send()
        .unwrap(),
        "create federated Drive share",
    );
    let invite_url = share["inviteUrl"].as_str().unwrap();
    assert!(!invite_url.contains("/invite/"));
    let invite = url::Url::parse(invite_url).unwrap();
    assert_eq!(invite.path(), "/invite");
    let invite_values: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(invite.fragment().unwrap().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(invite_values["server"], "a.test");
    let capability = &invite_values["capability"];
    assert!(capability.len() >= 32);

    let accepted = json_response(
        c.post(format!("{b}/api/drive/federation/shares"))
            .bearer_auth(bob_token)
            .json(&json!({"server": "a.test", "capability": capability}))
            .send()
            .unwrap(),
        "accept federated Drive share",
    );
    assert_eq!(accepted["remoteDomain"], "a.test");
    let incoming_id = accepted["id"].as_str().unwrap();

    let incoming = json_response(
        c.get(format!("{b}/api/drive/federation/shares"))
            .bearer_auth(bob_token)
            .send()
            .unwrap(),
        "list incoming Drive shares",
    );
    assert_eq!(incoming.as_array().unwrap().len(), 1);
    assert!(incoming[0].get("capability").is_none());
    assert!(incoming[0].get("remoteCapability").is_none());

    let empty = json_response(
        c.get(format!(
            "{b}/api/drive/federation/shares/{incoming_id}/files"
        ))
        .bearer_auth(bob_token)
        .send()
        .unwrap(),
        "list empty remote Drive share",
    );
    assert!(empty.as_array().unwrap().is_empty());

    let boundary = "kutup-drive-live-boundary";
    let ciphertext = b"phase-d-encrypted-drive-object";
    let upload_body = drive_upload_body(boundary, ciphertext);
    let upload = |body: Vec<u8>| {
        c.post(format!(
            "{b}/api/drive/federation/shares/{incoming_id}/files"
        ))
        .bearer_auth(bob_token)
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .unwrap()
    };
    let first_upload = json_response(upload(upload_body.clone()), "federated Drive upload");
    let retried_upload = json_response(upload(upload_body), "idempotent Drive upload retry");
    assert_eq!(first_upload["id"], retried_upload["id"]);
    let file_id = first_upload["id"].as_str().unwrap();

    let files = json_response(
        c.get(format!(
            "{b}/api/drive/federation/shares/{incoming_id}/files"
        ))
        .bearer_auth(bob_token)
        .send()
        .unwrap(),
        "list populated remote Drive share",
    );
    assert_eq!(files.as_array().unwrap().len(), 1);
    assert_eq!(files[0]["id"], file_id);
    assert_eq!(files[0]["encryptedMetadata"], "drive-encrypted-metadata");

    let download = c
        .get(format!(
            "{b}/api/drive/federation/shares/{incoming_id}/files/{file_id}/content"
        ))
        .bearer_auth(bob_token)
        .send()
        .unwrap();
    assert_eq!(download.status().as_u16(), 200);
    assert_eq!(download.bytes().unwrap().as_ref(), ciphertext);

    let delete = || {
        c.delete(format!(
            "{b}/api/drive/federation/shares/{incoming_id}/files/{file_id}"
        ))
        .bearer_auth(bob_token)
        .send()
        .unwrap()
    };
    assert_eq!(delete().status().as_u16(), 204);
    assert_eq!(delete().status().as_u16(), 204);

    let raw_url_share = c
        .post(format!(
            "{a}/api/collections/{collection_id}/federated-shares"
        ))
        .bearer_auth(alice_token)
        .json(&json!({
            "recipientUsername": BOB_USERNAME,
            "recipientServer": "http://b.test",
            "encryptedCollectionKey": "wrapped",
            "canUpload": false,
            "canDelete": false
        }))
        .send()
        .unwrap();
    assert_eq!(raw_url_share.status().as_u16(), 400);
    assert_eq!(
        c.get(format!("{a}/api/fed/drive/invite"))
            .send()
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    for legacy in [
        "/api/fed/users?username=bobfed",
        "/api/fed/invites/legacy-token",
        "/api/fed/shares/legacy-token/files",
        "/api/fed-proxy/incoming",
    ] {
        assert_eq!(
            c.get(format!("{a}{legacy}"))
                .send()
                .unwrap()
                .status()
                .as_u16(),
            404,
            "legacy route {legacy} must be absent"
        );
    }
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
    assert_eq!(discovery_a["fedVersion"], 2);
    assert_eq!(discovery_b["fedVersion"], 2);
    assert!(discovery_a["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "drive.v1"));
    let identity_a = json_response(
        c.get(format!("{a}/.well-known/kutup/federation/identity/0.json"))
            .send()
            .unwrap(),
        "server A immutable identity history",
    );
    let identity_b = json_response(
        c.get(format!("{b}/.well-known/kutup/federation/identity/0.json"))
            .send()
            .unwrap(),
        "server B immutable identity history",
    );
    assert_eq!(identity_a, discovery_a["identity"]);
    assert_eq!(identity_b, discovery_b["identity"]);
    assert_ne!(
        discovery_a["identity"]["key"],
        discovery_b["identity"]["key"]
    );

    let admin_a = setup_admin(c, a, ADMIN_A_EMAIL, "admina");
    let admin_b = setup_admin(c, b, ADMIN_B_EMAIL, "adminb");
    let initial_policy = json_response(
        c.get(format!("{a}/api/admin/federation"))
            .bearer_auth(&admin_a)
            .send()
            .unwrap(),
        "get initial federation policy",
    );
    assert_eq!(initial_policy["configured"], true);
    assert_eq!(initial_policy["serverName"], "a.test");
    assert_eq!(initial_policy["features"][0]["feature"], "chat");
    assert_eq!(initial_policy["features"][0]["mode"], "allowlist");
    update_federation_mode(c, a, &admin_a, "open");
    update_federation_mode(c, b, &admin_b, "open");
    update_feature_mode(c, a, &admin_a, "drive", "open");
    update_feature_mode(c, b, &admin_b, "drive", "open");

    let alice_token = register_account(c, a, ALICE_EMAIL, ALICE_USERNAME);
    let bob_token = register_account(c, b, BOB_EMAIL, BOB_USERNAME);
    drive_round_trip(c, a, b, &alice_token, &bob_token);

    // Drive is deliberately the first feature to contact B. Capture the one
    // shared identity pin before Chat uses the same federation stack.
    let after_drive = federation_control_plane(c, a, &admin_a, "control plane after Drive");
    assert_eq!(after_drive["operational"]["peerTotal"], 1);
    assert_eq!(after_drive["operational"]["driveOutgoingShares"], 1);
    let drive_peer = federation_peer(&after_drive, "b.test");
    assert_eq!(drive_peer["trust"], "tofu");
    assert_eq!(drive_peer["diagnostics"]["driveOutgoingShares"], 1);
    let shared_fingerprint = drive_peer["fingerprint"].as_str().unwrap().to_owned();
    let shared_first_seen = drive_peer["firstSeenAt"].as_str().unwrap().to_owned();
    let drive_evidence = json_response(
        c.get(format!("{a}/api/admin/federation/peers/b.test/evidence"))
            .bearer_auth(&admin_a)
            .send()
            .unwrap(),
        "immutable identity evidence after Drive first contact",
    );
    assert_eq!(drive_evidence["domain"], "b.test");
    assert_eq!(drive_evidence["trust"], "tofu");
    assert_eq!(drive_evidence["documents"].as_array().unwrap().len(), 1);
    assert_eq!(drive_evidence["documents"][0]["acceptance"], "accepted");
    assert_eq!(
        drive_evidence["documents"][0]["document"],
        discovery_b["identity"]
    );
    assert_eq!(
        drive_evidence["documents"][0]["documentHash"],
        drive_evidence["currentDocumentHash"]
    );

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

    // Chat must reuse Drive's peer row and immutable evidence rather than
    // creating a feature-owned trust record or silently replacing the pin.
    let after_chat = federation_control_plane(c, a, &admin_a, "control plane after Chat");
    assert_eq!(after_chat["operational"]["peerTotal"], 1);
    let chat_peer = federation_peer(&after_chat, "b.test");
    assert_eq!(chat_peer["fingerprint"], shared_fingerprint);
    assert_eq!(chat_peer["firstSeenAt"], shared_first_seen);
    let chat_evidence = json_response(
        c.get(format!("{a}/api/admin/federation/peers/b.test/evidence"))
            .bearer_auth(&admin_a)
            .send()
            .unwrap(),
        "immutable identity evidence after Chat reuse",
    );
    assert_eq!(chat_evidence, drive_evidence);

    let bulk_retry = json_response(
        c.post(format!("{a}/api/admin/federation/peers/retry"))
            .bearer_auth(&admin_a)
            .json(&json!({"domains": ["b.test", "b.test"]}))
            .send()
            .unwrap(),
        "bounded deduplicated federation peer retry",
    );
    assert_eq!(bulk_retry["results"].as_array().unwrap().len(), 1);
    assert_eq!(bulk_retry["results"][0]["domain"], "b.test");
    assert_eq!(bulk_retry["results"][0]["refreshed"], true);
    assert!(bulk_retry["results"][0]["error"].is_null());

    let filtered_activity = json_response(
        c.get(format!(
            "{a}/api/admin/activity?actionPrefix=federation.&domain=b.test&limit=100"
        ))
        .bearer_auth(&admin_a)
        .send()
        .unwrap(),
        "domain-filtered federation audit activity",
    );
    let filtered_entries = filtered_activity["entries"].as_array().unwrap();
    assert!(!filtered_entries.is_empty());
    assert!(filtered_entries
        .iter()
        .all(|entry| entry["action"].as_str().unwrap().starts_with("federation.")));
    assert!(filtered_entries
        .iter()
        .any(|entry| entry["action"] == "federation.peer.retry-bulk"));

    let audit_export = c
        .get(format!(
            "{a}/api/admin/activity/export?actionPrefix=federation.&domain=b.test&limit=100"
        ))
        .bearer_auth(&admin_a)
        .send()
        .unwrap();
    assert_eq!(audit_export.status().as_u16(), 200);
    assert!(audit_export
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/csv"));
    let audit_csv = audit_export.text().unwrap();
    assert!(audit_csv.contains("federation.peer.retry-bulk"));
    assert!(audit_csv.contains("b.test"));
    assert!(!audit_csv.contains("capability"));

    // The global emergency stop withdraws the public federation surface and
    // denies both features. Preserved identity evidence remains inspectable
    // only through the authenticated local administration surface.
    update_feature_policy(c, a, &admin_a, "chat", "open", false);
    assert_eq!(
        c.get(format!("{a}/.well-known/kutup/federation.json"))
            .send()
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        c.get(format!("{a}/.well-known/kutup/federation/identity/0.json"))
            .send()
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let stopped_evidence = json_response(
        c.get(format!("{a}/api/admin/federation/peers/b.test/evidence"))
            .bearer_auth(&admin_a)
            .send()
            .unwrap(),
        "preserved peer evidence during global stop",
    );
    assert_eq!(stopped_evidence, drive_evidence);
    assert_eq!(
        c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(drive_remote_user(c, a, &alice_token).status().as_u16(), 403);
    update_feature_policy(c, a, &admin_a, "chat", "open", true);

    // Drive independently traverses the same four policy modes and
    // directional rules that Chat exercises below.
    assert_eq!(
        update_feature_mode(c, a, &admin_a, "drive", "disabled")["mode"],
        "disabled"
    );
    assert_eq!(drive_remote_user(c, a, &alice_token).status().as_u16(), 403);
    fetch(); // Disabling Drive cannot disable Chat.

    assert_eq!(
        update_feature_mode(c, a, &admin_a, "drive", "allowlist")["mode"],
        "allowlist"
    );
    assert_eq!(drive_remote_user(c, a, &alice_token).status().as_u16(), 403);
    upsert_feature_rule(c, a, &admin_a, "drive", "b.test", "inherit", "allow");
    json_response(
        drive_remote_user(c, a, &alice_token),
        "allowlisted Drive lookup",
    );

    upsert_feature_rule(c, a, &admin_a, "drive", "b.test", "allow", "block");
    assert_eq!(
        update_feature_mode(c, a, &admin_a, "drive", "open")["mode"],
        "open"
    );
    json_response(
        drive_remote_user(c, a, &alice_token),
        "open Drive lookup ignores saved block",
    );
    assert_eq!(
        update_feature_mode(c, a, &admin_a, "drive", "blocklist")["mode"],
        "blocklist"
    );
    assert_eq!(drive_remote_user(c, a, &alice_token).status().as_u16(), 403);
    upsert_feature_rule(c, a, &admin_a, "drive", "b.test", "inherit", "inherit");
    json_response(
        drive_remote_user(c, a, &alice_token),
        "unblocked Drive lookup",
    );

    update_feature_mode(c, b, &admin_b, "drive", "blocklist");
    upsert_feature_rule(c, b, &admin_b, "drive", "a.test", "block", "inherit");
    assert_eq!(drive_remote_user(c, a, &alice_token).status().as_u16(), 502);
    upsert_feature_rule(c, b, &admin_b, "drive", "a.test", "allow", "inherit");
    json_response(
        drive_remote_user(c, a, &alice_token),
        "inbound-allowed Drive lookup",
    );
    delete_feature_rule(c, a, &admin_a, "drive", "b.test");
    delete_feature_rule(c, b, &admin_b, "drive", "a.test");
    update_feature_mode(c, a, &admin_a, "drive", "open");
    update_feature_mode(c, b, &admin_b, "drive", "open");

    // The four modes and directional rules are enforced before discovery or
    // delivery. Rules remain durable and their admission actions are ignored
    // only in the explicitly open mode.
    assert_eq!(
        update_federation_mode(c, a, &admin_a, "disabled")["mode"],
        "disabled"
    );
    let drive_only_discovery = json_response(
        c.get(format!("{a}/.well-known/kutup/federation.json"))
            .send()
            .unwrap(),
        "Drive-only discovery",
    );
    assert!(drive_only_discovery["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "drive.v1"));
    assert!(!drive_only_discovery["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "chat.v1"));
    assert_eq!(
        c.get(format!("{a}/.well-known/kutup/federation/identity/0.json"))
            .send()
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    let disabled_capabilities = json_response(
        c.get(format!("{a}/api/auth/settings")).send().unwrap(),
        "disabled federation capabilities",
    );
    assert_eq!(disabled_capabilities["chat"]["federation"], false);
    json_response(
        drive_remote_user(c, a, &alice_token),
        "Drive remains enabled while Chat is disabled",
    );
    assert_eq!(
        c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    assert_eq!(
        update_federation_mode(c, a, &admin_a, "allowlist")["mode"],
        "allowlist"
    );
    assert_eq!(
        c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    upsert_federation_rule(c, a, &admin_a, "b.test", "inherit", "allow");
    fetch();

    upsert_federation_rule(c, a, &admin_a, "b.test", "allow", "block");
    assert_eq!(
        update_federation_mode(c, a, &admin_a, "open")["mode"],
        "open"
    );
    fetch(); // Open mode deliberately ignores the saved block.
    assert_eq!(
        update_federation_mode(c, a, &admin_a, "blocklist")["mode"],
        "blocklist"
    );
    assert_eq!(
        c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    upsert_federation_rule(c, a, &admin_a, "b.test", "inherit", "inherit");
    fetch();

    assert_eq!(
        update_federation_mode(c, b, &admin_b, "blocklist")["mode"],
        "blocklist"
    );
    upsert_federation_rule(c, b, &admin_b, "a.test", "block", "inherit");
    assert_eq!(
        c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        502
    );
    upsert_federation_rule(c, b, &admin_b, "a.test", "allow", "inherit");
    fetch();

    delete_federation_rule(c, a, &admin_a, "b.test");
    delete_federation_rule(c, b, &admin_b, "a.test");
    update_federation_mode(c, a, &admin_a, "open");
    update_federation_mode(c, b, &admin_b, "open");

    let activity = json_response(
        c.get(format!("{a}/api/admin/activity?limit=20"))
            .bearer_auth(&admin_a)
            .send()
            .unwrap(),
        "federation policy audit activity",
    );
    assert!(activity["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["action"] == "federation.policy.update"));
    assert!(activity["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["action"] == "federation.rule.upsert"));

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

    // Materialize enough complete, signed account history to cross the
    // protocol's 64-entry page boundary. Fetch it through A's same-origin
    // route, which in turn uses the signed federation route on B. Both pages
    // must describe one immutable checkpoint snapshot and an exact chain.
    let bob_devices = vec![
        manifest_device(1, BOB_REGISTRATION_ID_1, 20),
        manifest_device(2, BOB_REGISTRATION_ID_2, 30),
    ];
    let mut latest_manifest = bob_manifest_v2.clone();
    for version in 3..=66 {
        latest_manifest = publish_manifest(
            c,
            b,
            &bob_token,
            &bob_authority,
            version,
            Some(latest_manifest.manifest_hash().unwrap()),
            bob_devices.clone(),
        );
    }
    let history_url = format!("{a}/api/chat/users/{remote_address}/manifest-history");
    let first_page: ManifestUpdateRangeProofV1 = serde_json::from_value(json_response(
        c.get(&history_url)
            .bearer_auth(&alice_token)
            .query(&[
                ("fromVersion", "1"),
                ("toVersion", "66"),
                ("pageFromVersion", "1"),
                ("transparencyTreeSize", "0"),
            ])
            .send()
            .unwrap(),
        "first federated manifest-history page",
    ))
    .unwrap();
    assert_eq!(first_page.entries.len(), 64);
    assert_eq!(first_page.page_to_version, 64);
    assert!(!first_page.authentication.witnesses.is_empty());
    first_page
        .verify_page(&remote_address, 1, None, None)
        .unwrap();
    let cursor = first_page.next_cursor.clone().unwrap();
    let first_page_last = first_page.entries.last().unwrap().manifest.clone();
    let second_page: ManifestUpdateRangeProofV1 = serde_json::from_value(json_response(
        c.get(&history_url)
            .bearer_auth(&alice_token)
            .query(&[
                ("fromVersion", "1"),
                ("toVersion", "66"),
                ("pageFromVersion", "65"),
                ("cursor", cursor.as_str()),
                ("transparencyTreeSize", "0"),
            ])
            .send()
            .unwrap(),
        "second federated manifest-history page",
    ))
    .unwrap();
    assert_eq!(second_page.entries.len(), 2);
    assert_eq!(
        second_page.entries.last().unwrap().manifest,
        latest_manifest
    );
    assert!(second_page.next_cursor.is_none());
    assert_eq!(second_page.checkpoint, first_page.checkpoint);
    assert_eq!(second_page.authentication, first_page.authentication);
    second_page
        .verify_page(&remote_address, 1, Some(&first_page_last), None)
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
    let monitor = json_response(
        c.get(format!("{a}/api/chat/transparency/domains/b.test/status"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap(),
        "restart-restored remote transparency monitor cursor",
    );
    assert_eq!(monitor["domain"], "b.test");
    assert_eq!(monitor["policySequence"], 1);
    assert_eq!(monitor["blocked"], false);
    assert!(monitor["lastSuccessfulAt"].as_str().is_some());
    assert!(monitor["checkpoint"]["checkpoint"]["treeSize"]
        .as_u64()
        .is_some_and(|tree_size| tree_size >= 2));

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
