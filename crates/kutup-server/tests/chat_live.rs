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
use ed25519_dalek::{Signer as _, SigningKey};
use kutup_chat_proto::{
    AccountIdentitySuiteId, AccountManifestDeviceV1, AccountManifestDriveKeysV1,
    AccountManifestPublicationV1, AccountManifestV1, DirectChatSuiteId, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, UserPreKeyBundlesResponse,
};
use rand::RngCore;
use reqwest::{blocking::Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn opaque_profile_envelope(
    account: &str,
    version: &str,
    revision: u64,
    source_device_id: u32,
    purpose: ProfileEnvelopePurpose,
    ciphertext_len: usize,
    fill: u8,
) -> String {
    let context =
        ProfileEnvelopeContextV1::new(purpose, account, version, revision, source_device_id)
            .unwrap();
    let mut envelope = kutup_chat_proto::encode_profile_envelope_header(
        &context,
        &[fill; 24],
        ciphertext_len as u32,
    )
    .unwrap();
    envelope.extend(vec![fill; ciphertext_len]);
    b64(&envelope)
}

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Registers a fresh account and returns `(email, username, access_token)`.
fn register_and_login(c: &Client, base: &str, tag: &str) -> (String, String, String, String) {
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
    let mut account_protection_salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut account_protection_salt);

    let keys = kutup_crypto::kdf::derive_account_protection_keys(
        password,
        &account_protection_salt,
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    let recovery_proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, &email).unwrap();
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let master_key_envelope = account_envelope::seal_b64(
        &master_key,
        keys.key_encryption_key.as_slice(),
        AccountEnvelopePurpose::PasswordMasterKey,
        &email,
    )
    .unwrap();
    let recovery_key_envelope = account_envelope::seal_b64(
        &master_key,
        &recovery_entropy,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &email,
    )
    .unwrap();
    let drive_private_key_envelope = account_envelope::seal_b64(
        identity.drive_hpke_private_key(),
        &master_key,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &email,
    )
    .unwrap();

    let reg = json!({
        "email": email, "username": username,
        "loginKey": b64(keys.login_key.as_slice()),
        "masterKeyEnvelope": master_key_envelope,
        "recoveryKeyEnvelope": recovery_key_envelope,
        "drivePrivateKeyEnvelope": drive_private_key_envelope,
        "publicKey": b64(&identity.drive_hpke_public_key()),
        "accountAuthorityPublicKey": b64(&identity.authority_public_key()),
        "accountAuthorityKeyId": identity.authority_key_id(),
        "accountIncarnationId": identity.incarnation_id(),
        "driveSigningPublicKey": b64(&identity.drive_signing_public_key()),
        "accountProtectionSuite": 1,
        "accountProtectionSalt": b64(&account_protection_salt),
        "argonMemoryKib": 65536, "argonIterations": 3, "argonParallelism": 1,
        "recoveryProof": b64(recovery_proof.as_slice()),
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
    let keys = kutup_crypto::kdf::derive_account_protection_keys_b64(
        password,
        pf["accountProtectionSalt"].as_str().unwrap(),
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    let resp: Value = c
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "email": email, "loginKey": b64(keys.login_key.as_slice()) }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let token = resp["accessToken"].as_str().unwrap().to_string();
    (
        email,
        username,
        token,
        b64(&identity.drive_hpke_public_key()),
    )
}

/// A synthetic (base64-valid, crypto-meaningless) chat device registration.
fn register_chat_device(c: &Client, base: &str, token: &str) -> (u32, u32, String) {
    let mut rng = rand::thread_rng();
    let reg_id = (rng.next_u32() % 16000) + 1;
    let seed = rng.next_u32() as u8;
    let key = |n: u8| b64(&[seed.wrapping_add(n); 33]);
    let identity_key = key(1);
    let body = json!({
        "suite": 1, "registrationId": reg_id,
        "identityKey": identity_key,
        "signedPreKey": { "keyId": 1, "publicKey": key(2), "signature": key(3) },
        "lastResortKyberPreKey": { "keyId": 1, "publicKey": key(4), "signature": key(5) },
        "oneTimePreKeys": [ { "keyId": 10, "publicKey": key(6) } ],
        "oneTimeKyberPreKeys": [ { "keyId": 20, "publicKey": key(7), "signature": key(8) } ],
        "name": "live-test-device"
    });

    // The deployed JSON boundary must reject an unknown selected suite before
    // it can create device state or silently fall back to suite 1.
    let mut unsupported_body = body.clone();
    unsupported_body["suite"] = json!(2);
    let unsupported = c
        .post(format!("{base}/api/chat/device"))
        .bearer_auth(token)
        .json(&unsupported_body)
        .send()
        .unwrap();
    assert_eq!(
        unsupported.status().as_u16(),
        422,
        "unknown suite must fail at the JSON boundary"
    );

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

    // The database read path and public JSON shape must preserve the numeric
    // registry code rather than defaulting or serializing a Rust variant name.
    let devices: Value = c
        .get(format!("{base}/api/chat/device"))
        .bearer_auth(token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let listed = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["deviceId"] == device_id)
        .expect("registered device is listed");
    assert_eq!(listed["suite"], json!(1));

    (device_id, reg_id, identity_key)
}

#[allow(clippy::too_many_arguments)]
fn publish_manifest(
    c: &Client,
    base: &str,
    token: &str,
    signing: &SigningKey,
    account: &str,
    drive_public_key: &str,
    sequence: u64,
    previous_hash: Option<String>,
    devices: Vec<AccountManifestDeviceV1>,
) -> AccountManifestV1 {
    let public = signing.verifying_key();
    let mut incarnation = Sha256::new();
    incarnation.update(b"kutup/account-incarnation/v1\0");
    incarnation.update(public.as_bytes());
    let drive_signing = SigningKey::from_bytes(&[99; 32]);
    let mut manifest = AccountManifestV1 {
        manifest_version: 1,
        account: account.into(),
        incarnation_id: hex::encode(incarnation.finalize()),
        sequence,
        previous_hash,
        drive: AccountManifestDriveKeysV1 {
            suite: AccountIdentitySuiteId::X25519Ed25519V1,
            hpke_public_key: drive_public_key.into(),
            share_signing_public_key: b64(drive_signing.verifying_key().as_bytes()),
        },
        devices,
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        authority_key_id: hex::encode(Sha256::digest(public.as_bytes())),
        self_authority_key: b64(public.as_bytes()),
        signature: String::new(),
    };
    manifest.signature = b64(&signing.sign(&manifest.signing_bytes().unwrap()).to_bytes());
    manifest.verify().unwrap();
    // Publication is idempotent, so a transient transport failure can retry
    // the exact manifest without publishing different bytes.
    let mut response = None;
    for attempt in 0..3 {
        let candidate = c
            .post(format!("{base}/api/chat/manifest"))
            .bearer_auth(token)
            .json(&manifest)
            .send()
            .unwrap();
        if candidate.status() != StatusCode::SERVICE_UNAVAILABLE || attempt == 2 {
            response = Some(candidate);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let response = response.expect("manifest publication retry loop returns a response");
    assert!(
        response.status().is_success(),
        "publish manifest sequence {sequence}: {}",
        response.status()
    );
    let published = response.json::<AccountManifestPublicationV1>().unwrap();
    assert_eq!(published.manifest, manifest);
    manifest
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
    assert_eq!(
        chat["mlsGroups"], false,
        "MLS groups fail closed without an authenticated ordering policy"
    );
    assert_eq!(chat["manifests"], true);
    assert_eq!(chat["profiles"], true);
    assert!(chat.get("keyTransparency").is_none());
    assert!(chat["mailboxRetentionDays"].is_number());
    assert!(chat["deviceExpiryDays"].is_number());
    println!("ok  - capability block");

    let (_ea, ua, ta, drive_a) = register_and_login(&c, &base, "a");
    let (_eb, ub, tb, drive_b) = register_and_login(&c, &base, "b");
    let domain = std::env::var("KUTUP_LIVE_SERVER_NAME").unwrap_or_else(|_| "local.test".into());
    let account_a = format!("{ua}@{domain}");
    let account_b = format!("{ub}@{domain}");
    println!("ok  - two accounts registered + logged in");

    let (dev_a, reg_a, identity_a) = register_chat_device(&c, &base, &ta);
    let (interrupted_a, _, _) = register_chat_device(&c, &base, &ta);
    let (dev_b, reg_b, identity_b) = register_chat_device(&c, &base, &tb);
    println!("ok  - chat devices registered (A={dev_a} B={dev_b})");

    let authority_a = SigningKey::from_bytes(&[71; 32]);
    let authority_b = SigningKey::from_bytes(&[72; 32]);
    let manifest_a1 = publish_manifest(
        &c,
        &base,
        &ta,
        &authority_a,
        &account_a,
        &drive_a,
        1,
        None,
        vec![AccountManifestDeviceV1 {
            device_id: dev_a,
            direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            identity_key: identity_a.clone(),
            registration_id: reg_a,
            mls: None,
        }],
    );
    let devices_after_first_manifest: Value = c
        .get(format!("{base}/api/chat/device"))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        devices_after_first_manifest["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        devices_after_first_manifest["devices"][0]["deviceId"],
        dev_a
    );
    assert_ne!(interrupted_a, dev_a);
    publish_manifest(
        &c,
        &base,
        &tb,
        &authority_b,
        &account_b,
        &drive_b,
        1,
        None,
        vec![AccountManifestDeviceV1 {
            device_id: dev_b,
            direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
            identity_key: identity_b,
            registration_id: reg_b,
            mls: None,
        }],
    );

    // Opaque encrypted profiles are owner-writable and bearer-capability
    // readable. Rotation advances the owner head without deleting the old
    // ciphertext version while its key update is in flight.
    let access_v1 = [21u8; 16];
    let delivery_v1 = [23u8; 16];
    let profile_v1_version = "11".repeat(32);
    let profile_v1 = json!({
        "suite": 1,
        "account": account_a,
        "version": profile_v1_version,
        "revision": 1,
        "sourceDeviceId": dev_a,
        "name": opaque_profile_envelope(&account_a, &profile_v1_version, 1, dev_a, ProfileEnvelopePurpose::DisplayName, 53 + 16, 31),
        "wrappedKey": opaque_profile_envelope(&account_a, &profile_v1_version, 1, dev_a, ProfileEnvelopePurpose::WrappedProfileKey, 32 + 16, 41),
        "accessKeyVerifier": hex::encode(Sha256::digest(access_v1)),
        "deliveryCapabilityVerifier": hex::encode(Sha256::digest(delivery_v1)),
    });
    let put = c
        .put(format!("{base}/api/chat/profile"))
        .bearer_auth(&ta)
        .json(&profile_v1)
        .send()
        .unwrap();
    assert!(put.status().is_success(), "put profile: {}", put.status());
    assert_eq!(put.json::<Value>().unwrap(), profile_v1);

    let denied = c
        .get(format!(
            "{base}/api/chat/users/{ua}/profile/{}",
            profile_v1["version"].as_str().unwrap()
        ))
        .bearer_auth(&tb)
        .header("X-Kutup-Profile-Access-Key", b64(&[0u8; 16]))
        .send()
        .unwrap();
    assert_eq!(denied.status().as_u16(), 404);

    let visible_v1: Value = c
        .get(format!(
            "{base}/api/chat/users/{ua}/profile/{}",
            profile_v1["version"].as_str().unwrap()
        ))
        .bearer_auth(&tb)
        .header("X-Kutup-Profile-Access-Key", b64(&access_v1))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(visible_v1["name"], profile_v1["name"]);
    assert!(visible_v1.get("wrappedKey").is_none());
    assert!(visible_v1.get("accessKeyVerifier").is_none());
    assert!(visible_v1.get("deliveryCapabilityVerifier").is_none());

    let access_v2 = [22u8; 16];
    let delivery_v2 = [24u8; 16];
    let profile_v2_version = "12".repeat(32);
    let profile_v2 = json!({
        "suite": 1,
        "account": account_a,
        "version": profile_v2_version,
        "revision": 2,
        "sourceDeviceId": dev_a,
        "name": opaque_profile_envelope(&account_a, &profile_v2_version, 2, dev_a, ProfileEnvelopePurpose::DisplayName, 53 + 16, 32),
        "wrappedKey": opaque_profile_envelope(&account_a, &profile_v2_version, 2, dev_a, ProfileEnvelopePurpose::WrappedProfileKey, 32 + 16, 42),
        "accessKeyVerifier": hex::encode(Sha256::digest(access_v2)),
        "deliveryCapabilityVerifier": hex::encode(Sha256::digest(delivery_v2)),
    });
    let rotated = c
        .put(format!("{base}/api/chat/profile"))
        .bearer_auth(&ta)
        .json(&profile_v2)
        .send()
        .unwrap();
    assert!(rotated.status().is_success());
    let owner: Value = c
        .get(format!("{base}/api/chat/profile"))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(owner, profile_v2);
    let old_still_visible = c
        .get(format!(
            "{base}/api/chat/users/{ua}/profile/{}",
            profile_v1["version"].as_str().unwrap()
        ))
        .bearer_auth(&tb)
        .header("X-Kutup-Profile-Access-Key", b64(&access_v1))
        .send()
        .unwrap();
    assert!(old_still_visible.status().is_success());
    println!("ok  - encrypted profile capability + version-safe rotation");

    // A links a second device. A sync-mode bundle fetch returns the complete
    // signed-set shape, but does not consume a one-time key for the caller.
    let (interrupted_a2, _, _) = register_chat_device(&c, &base, &ta);
    let (dev_a2, reg_a2, identity_a2) = register_chat_device(&c, &base, &ta);
    let manifest_a2 = publish_manifest(
        &c,
        &base,
        &ta,
        &authority_a,
        &account_a,
        &drive_a,
        2,
        Some(manifest_a1.manifest_hash().unwrap()),
        vec![
            AccountManifestDeviceV1 {
                device_id: dev_a,
                direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                identity_key: identity_a.clone(),
                registration_id: reg_a,
                mls: None,
            },
            AccountManifestDeviceV1 {
                device_id: dev_a2,
                direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                identity_key: identity_a2,
                registration_id: reg_a2,
                mls: None,
            },
        ],
    );
    let sync_bundles_value: Value = c
        .get(format!(
            "{base}/api/chat/users/{ua}/keys?syncDeviceId={dev_a}"
        ))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let sync_bundles: UserPreKeyBundlesResponse =
        serde_json::from_value(sync_bundles_value.clone()).unwrap();
    assert_eq!(sync_bundles.manifest.as_ref().unwrap().account, account_a);
    let sync_bundles = sync_bundles_value;
    let sync_devices = sync_bundles["devices"].as_array().unwrap();
    assert_eq!(sync_devices.len(), 2);
    assert!(sync_devices
        .iter()
        .all(|device| device["deviceId"] != interrupted_a2));
    let current = sync_devices
        .iter()
        .find(|device| device["deviceId"] == dev_a)
        .unwrap();
    assert!(current.get("oneTimePreKey").is_none());
    println!("ok  - linked-device bundle fetch preserves current prekeys");

    // Advance the complete account-signed manifest history.
    publish_manifest(
        &c,
        &base,
        &ta,
        &authority_a,
        &account_a,
        &drive_a,
        3,
        Some(manifest_a2.manifest_hash().unwrap()),
        manifest_a2.devices.clone(),
    );

    let sync_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let sync = c
        .post(format!("{base}/api/chat/sync/messages"))
        .bearer_auth(&ta)
        .json(&json!({
            "senderDeviceId": dev_a,
            "sendId": sync_id,
            "envelopes": [{
                "deviceId": dev_a2,
                "registrationId": reg_a2,
                "envelopeType": "message",
                "suite": 1,
                "content": b64(b"encrypted-sent-transcript")
            }]
        }))
        .send()
        .unwrap();
    assert!(sync.status().is_success(), "self sync: {}", sync.status());
    let own_page: Value = c
        .get(format!(
            "{base}/api/chat/messages?deviceId={dev_a2}&limit=10"
        ))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let own_envelopes = own_page["envelopes"].as_array().unwrap();
    assert_eq!(own_envelopes.len(), 1);
    assert_eq!(own_envelopes[0]["sender"], ua);
    assert_eq!(own_envelopes[0]["senderDeviceId"], dev_a);
    println!("ok  - encrypted transcript routed only to the linked device");

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
    let bundles_value: Value = c
        .get(format!("{base}/api/chat/users/{ub}/keys"))
        .bearer_auth(&ta)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let typed_bundles: UserPreKeyBundlesResponse =
        serde_json::from_value(bundles_value.clone()).unwrap();
    assert_eq!(typed_bundles.manifest.as_ref().unwrap().account, account_b);
    let bundles = bundles_value;
    let devs = bundles["devices"].as_array().unwrap();
    assert_eq!(devs.len(), 1, "B has one device");
    let d = &devs[0];
    assert_eq!(d["deviceId"], dev_b);
    assert!(d["kyberPreKey"].is_object(), "PQ prekey never absent");
    assert!(
        d["oneTimePreKey"].is_object(),
        "one-time EC consumed by fetch"
    );
    println!("ok  - bundle fetch + account-signed manifest binding");

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
    // The same logical sendId was already claimed by the own-device sync
    // endpoint above. Direct and sync idempotency scopes must not collide.
    let sid = sync_id;
    let r = send(sid, dev_b, reg_b, &b64(b"ciphertext-one"));
    assert!(r.status().is_success(), "send: {}", r.status());
    let body: Value = r.json().unwrap();
    assert_eq!(body["stored"], 1);
    assert!(body.get("deduplicated").is_none());
    println!("ok  - direct send stored independently of sync scope");

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
