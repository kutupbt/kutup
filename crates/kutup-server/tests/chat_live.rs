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
    AccountManifestPublicationV1, AccountManifestV1, AppendChatBackupSegmentRequestV1,
    ChatBackupManifestV1, ChatBackupMediaReferenceV1, ChatBackupSignerAuthorizationV1,
    CommitChatBackupManifestRequestV1, DirectChatSuiteId, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, ProvisionChatBackupRequestV1, ReconcileChatBackupMediaRequestV1,
    StageChatBackupBaseRequestV1, UploadChatBackupMediaRequestV1, UserPreKeyBundlesResponse,
};
use rand::RngCore;
use reqwest::{blocking::Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

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

fn login_with_password(c: &Client, base: &str, email: &str, password: &str) -> String {
    let preflight: Value = c
        .get(format!("{base}/api/auth/login/preflight?email={email}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if preflight["accountProtectionSuite"] == 0 {
        let bootstrap: Value = c
            .post(format!("{base}/api/auth/login"))
            .json(&json!({ "email": email, "loginKey": b64(password.as_bytes()) }))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(bootstrap["requiresSetup"], true);
        let setup_token = bootstrap["setupToken"].as_str().expect("setup token");
        let mut rng = rand::thread_rng();
        let mut master_key = [0u8; 32];
        let mut recovery_entropy = [0u8; 32];
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut master_key);
        rng.fill_bytes(&mut recovery_entropy);
        rng.fill_bytes(&mut salt);
        let parameters = kutup_crypto::kdf::AccountProtectionParameters::V1;
        let keys =
            kutup_crypto::kdf::derive_account_protection_keys(password, &salt, parameters).unwrap();
        let recovery_proof =
            kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, email).unwrap();
        let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap();
        use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
        let setup = json!({
            "email": email,
            "username": "backupadmin",
            "loginKey": b64(keys.login_key.as_slice()),
            "masterKeyEnvelope": account_envelope::seal_b64(
                &master_key, keys.key_encryption_key.as_slice(),
                AccountEnvelopePurpose::PasswordMasterKey, email).unwrap(),
            "recoveryKeyEnvelope": account_envelope::seal_b64(
                &master_key, &recovery_entropy,
                AccountEnvelopePurpose::RecoveryMasterKey, email).unwrap(),
            "drivePrivateKeyEnvelope": account_envelope::seal_b64(
                identity.drive_hpke_private_key(), &master_key,
                AccountEnvelopePurpose::DriveHpkePrivateKey, email).unwrap(),
            "publicKey": b64(&identity.drive_hpke_public_key()),
            "accountAuthorityPublicKey": b64(&identity.authority_public_key()),
            "accountAuthorityKeyId": identity.authority_key_id(),
            "accountIncarnationId": identity.incarnation_id(),
            "driveSigningPublicKey": b64(&identity.drive_signing_public_key()),
            "accountProtectionSuite": 1,
            "accountProtectionSalt": b64(&salt),
            "argonMemoryKib": parameters.memory_kib,
            "argonIterations": parameters.iterations,
            "argonParallelism": parameters.parallelism,
            "recoveryProof": b64(recovery_proof.as_slice()),
        });
        let completed = c
            .post(format!("{base}/api/auth/complete-setup"))
            .bearer_auth(setup_token)
            .json(&setup)
            .send()
            .unwrap();
        assert_eq!(completed.status(), StatusCode::OK, "test admin setup");
        return completed.json::<Value>().unwrap()["accessToken"]
            .as_str()
            .unwrap()
            .to_string();
    }
    let parameters = kutup_crypto::kdf::AccountProtectionParameters {
        memory_kib: preflight["argonMemoryKib"].as_u64().unwrap() as u32,
        iterations: preflight["argonIterations"].as_u64().unwrap() as u32,
        parallelism: preflight["argonParallelism"].as_u64().unwrap() as u32,
    };
    let keys = kutup_crypto::kdf::derive_account_protection_keys_b64(
        password,
        preflight["accountProtectionSalt"].as_str().unwrap(),
        parameters,
    )
    .unwrap();
    let response = c
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "email": email, "loginKey": b64(keys.login_key.as_slice()) }))
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "test admin login");
    response.json::<Value>().unwrap()["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Registers a fresh account and returns `(email, username, access_token)`.
fn register_and_login(
    c: &Client,
    base: &str,
    tag: &str,
) -> (String, String, String, String, SigningKey, String, [u8; 32]) {
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
    let authority = identity.authority_signing_key().clone();
    let drive_signing_public_key = b64(&identity.drive_signing_public_key());
    (
        email,
        username,
        token,
        b64(&identity.drive_hpke_public_key()),
        authority,
        drive_signing_public_key,
        master_key,
    )
}

/// A synthetic (base64-valid, crypto-meaningless) chat device registration.
fn register_chat_device(c: &Client, base: &str, token: &str) -> (u32, u32, String) {
    let mut rng = rand::thread_rng();
    let reg_id = (rng.next_u32() % 16000) + 1;
    let seed = rng.next_u32();
    let key = |n: u8| {
        let mut digest = Sha256::new();
        digest.update(seed.to_be_bytes());
        digest.update([n]);
        let mut bytes = [0u8; 33];
        bytes[0] = n;
        bytes[1..].copy_from_slice(&digest.finalize());
        b64(&bytes)
    };
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
    drive_signing_public_key: &str,
    sequence: u64,
    previous_hash: Option<String>,
    devices: Vec<AccountManifestDeviceV1>,
) -> AccountManifestV1 {
    let public = signing.verifying_key();
    let mut incarnation = Sha256::new();
    incarnation.update(b"kutup/account-incarnation/v1\0");
    incarnation.update(public.as_bytes());
    let mut manifest = AccountManifestV1 {
        manifest_version: 1,
        account: account.into(),
        incarnation_id: hex::encode(incarnation.finalize()),
        sequence,
        previous_hash,
        drive: AccountManifestDriveKeysV1 {
            suite: AccountIdentitySuiteId::X25519Ed25519V1,
            hpke_public_key: drive_public_key.into(),
            share_signing_public_key: drive_signing_public_key.into(),
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
    let response_status = response.status();
    let response_body = response.text().unwrap();
    assert!(
        response_status.is_success(),
        "publish manifest sequence {sequence}: {response_status}: {response_body}",
    );
    let published = serde_json::from_str::<AccountManifestPublicationV1>(&response_body).unwrap();
    assert_eq!(published.manifest, manifest);
    manifest
}

#[allow(clippy::too_many_arguments)]
fn chat_backup_lifecycle(
    c: &Client,
    base: &str,
    email: &str,
    owner_token: &str,
    foreign_token: &str,
    master_key: &[u8; 32],
    authority: &SigningKey,
    device_id: u32,
    admin_token: Option<&str>,
) {
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    use kutup_crypto::chat_backup::{
        self, ChatBackupContextV1, ChatBackupObjectContextV1, ChatBackupObjectPurposeV1,
        ChatBackupProtectionDomainV1, ChatBackupSuiteId,
    };
    use kutup_crypto::chat_backup_media::{self, ChatBackupMediaContextV1};
    use kutup_crypto::identity::AccountIdentityKeysV1;
    use kutup_crypto::stream::{StreamEncryptor, TAG_FINAL};

    let initial: Value = c
        .get(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(initial["provisioned"], false);
    assert_eq!(initial["currentCursor"], 0);

    let identity = AccountIdentityKeysV1::derive(master_key).unwrap();
    let backup_id = Uuid::new_v4();
    let backup_root = [0x91; 32];
    let account_incarnation_id: [u8; 32] = hex::decode(identity.incarnation_id())
        .unwrap()
        .try_into()
        .unwrap();
    let backup_context = ChatBackupContextV1 {
        account_incarnation_id,
        backup_incarnation_id: *backup_id.as_bytes(),
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
    };
    let signer_seed =
        chat_backup::derive_manifest_signing_seed(&backup_root, backup_context).unwrap();
    let signer = SigningKey::from_bytes(&signer_seed);
    let mut authorization = ChatBackupSignerAuthorizationV1 {
        version: 1,
        backup_incarnation_id: backup_id.to_string(),
        account_incarnation_id: identity.incarnation_id(),
        suite: ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1,
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        manifest_signing_public_key: b64(signer.verifying_key().as_bytes()),
        account_authority_key_id: identity.authority_key_id(),
        created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        account_authority_signature: String::new(),
    };
    authorization.account_authority_signature = b64(&authority
        .sign(&authorization.signing_bytes().unwrap())
        .to_bytes());
    let operation_id = Uuid::new_v4();
    let provision = ProvisionChatBackupRequestV1 {
        operation_id: operation_id.to_string(),
        root_envelope: account_envelope::seal_b64(
            &backup_root,
            master_key,
            AccountEnvelopePurpose::ChatBackupRoot,
            email,
        )
        .unwrap(),
        signer_authorization: authorization.clone(),
    };
    let created = c
        .post(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .json(&provision)
        .send()
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body: Value = created.json().unwrap();
    assert_eq!(created_body["provisioned"], true);

    let exact_retry = c
        .post(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .json(&provision)
        .send()
        .unwrap();
    assert_eq!(exact_retry.status(), StatusCode::OK);
    let mut changed_provision = provision.clone();
    changed_provision.root_envelope = account_envelope::seal_b64(
        &[0x92; 32],
        master_key,
        AccountEnvelopePurpose::ChatBackupRoot,
        email,
    )
    .unwrap();
    assert_eq!(
        c.post(format!("{base}/api/chat/backup"))
            .bearer_auth(owner_token)
            .json(&changed_provision)
            .send()
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    let segment_operation = Uuid::new_v4();
    let segment_context = ChatBackupObjectContextV1 {
        backup: backup_context,
        purpose: ChatBackupObjectPurposeV1::EventSegment,
        object_id: *segment_operation.as_bytes(),
        source_device_id: device_id,
        device_sequence: 1,
        previous_segment_digest: [0; 32],
    };
    let ciphertext =
        chat_backup::seal_object(b"opaque canonical segment", &backup_root, segment_context)
            .unwrap();
    let append = AppendChatBackupSegmentRequestV1 {
        operation_id: segment_operation.to_string(),
        backup_incarnation_id: backup_id.to_string(),
        source_device_id: device_id,
        device_sequence: 1,
        previous_segment_digest: "00".repeat(32),
        account_manifest_sequence: 1,
        ciphertext_bytes: ciphertext.len() as u32,
        ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
        ciphertext: b64(&ciphertext),
    };
    let receipt: Value = c
        .post(format!("{base}/api/chat/backup/segments"))
        .bearer_auth(owner_token)
        .json(&append)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(receipt["cursor"], 1);
    assert_eq!(receipt["alreadyStored"], false);
    let retry: Value = c
        .post(format!("{base}/api/chat/backup/segments"))
        .bearer_auth(owner_token)
        .json(&append)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(retry["cursor"], receipt["cursor"]);
    assert_eq!(retry["alreadyStored"], true);

    let mut changed_append = append.clone();
    changed_append.account_manifest_sequence = 2;
    assert_eq!(
        c.post(format!("{base}/api/chat/backup/segments"))
            .bearer_auth(owner_token)
            .json(&changed_append)
            .send()
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let mut malformed = append.clone();
    malformed.ciphertext_sha256 = "00".repeat(32);
    assert_eq!(
        c.post(format!("{base}/api/chat/backup/segments"))
            .bearer_auth(owner_token)
            .json(&malformed)
            .send()
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        c.post(format!("{base}/api/chat/backup/segments"))
            .bearer_auth(foreign_token)
            .json(&append)
            .send()
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    let page: Value = c
        .get(format!("{base}/api/chat/backup/segments?after=0&limit=1"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(page["segments"].as_array().unwrap().len(), 1);
    assert_eq!(page["segments"][0]["ciphertext"], append.ciphertext);
    assert_eq!(page["currentCursor"], 1);
    assert_eq!(page["more"], false);

    let status: Value = c
        .get(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(status["currentCursor"], 1);
    assert_eq!(status["storage"]["messageBytes"], ciphertext.len());
    assert_eq!(status["storage"]["usedBytes"], ciphertext.len());

    // Twenty real database races on one device head: both candidates bind the
    // same predecessor, so row locking must commit exactly one without quota
    // drift or a forked chain.
    let mut previous_digest = append.ciphertext_sha256.clone();
    let mut expected_bytes = ciphertext.len();
    for sequence in 2..=21_u64 {
        let candidate = |fill: u8| {
            let operation = Uuid::new_v4();
            let previous: [u8; 32] = hex::decode(&previous_digest).unwrap().try_into().unwrap();
            let context = ChatBackupObjectContextV1 {
                backup: backup_context,
                purpose: ChatBackupObjectPurposeV1::EventSegment,
                object_id: *operation.as_bytes(),
                source_device_id: device_id,
                device_sequence: sequence,
                previous_segment_digest: previous,
            };
            let ciphertext = chat_backup::seal_object(&[fill; 32], &backup_root, context).unwrap();
            AppendChatBackupSegmentRequestV1 {
                operation_id: operation.to_string(),
                backup_incarnation_id: backup_id.to_string(),
                source_device_id: device_id,
                device_sequence: sequence,
                previous_segment_digest: previous_digest.clone(),
                account_manifest_sequence: 1,
                ciphertext_bytes: ciphertext.len() as u32,
                ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
                ciphertext: b64(&ciphertext),
            }
        };
        let left = candidate(0x31);
        let right = candidate(0x32);
        let send_candidate = |client: Client, request: AppendChatBackupSegmentRequestV1| {
            let base = base.to_string();
            let token = owner_token.to_string();
            std::thread::spawn(move || {
                client
                    .post(format!("{base}/api/chat/backup/segments"))
                    .bearer_auth(token)
                    .json(&request)
                    .send()
                    .unwrap()
                    .status()
            })
        };
        let left_task = send_candidate(c.clone(), left.clone());
        let right_task = send_candidate(c.clone(), right.clone());
        let left_status = left_task.join().unwrap();
        let right_status = right_task.join().unwrap();
        let mut statuses = [left_status.as_u16(), right_status.as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 409]);
        let winner = if left_status.is_success() {
            left
        } else {
            right
        };
        previous_digest = winner.ciphertext_sha256;
        expected_bytes += winner.ciphertext_bytes as usize;
    }
    let concurrent_status: Value = c
        .get(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(concurrent_status["currentCursor"], 21);
    assert_eq!(concurrent_status["storage"]["messageBytes"], expected_bytes);
    assert_eq!(concurrent_status["storage"]["usedBytes"], expected_bytes);

    // Protect a valid locally retained media ciphertext through the direct
    // upload fallback. This exercises typed framing, deterministic padding,
    // exact replay, changed-content conflict, lazy download, and isolation.
    let source_media = b"already encrypted Chat attachment ciphertext";
    let media_id_bytes: [u8; 32] = Sha256::digest(source_media).into();
    let media_id = hex::encode(media_id_bytes);
    let media_reference_id = Uuid::new_v4();
    let media_header = chat_backup_media::build_media_header(
        ChatBackupMediaContextV1 {
            account_incarnation_id,
            backup_incarnation_id: *backup_id.as_bytes(),
            protection_domain: ChatBackupProtectionDomainV1::StandardChat,
            media_id: media_id_bytes,
        },
        source_media.len() as u64,
    )
    .unwrap();
    let parsed_media = chat_backup_media::inspect_media_header(&media_header).unwrap();
    let mut padded_media = vec![0u8; parsed_media.padded_plaintext_bytes as usize];
    padded_media[..source_media.len()].copy_from_slice(source_media);
    let (mut media_encryptor, stream_header) =
        StreamEncryptor::new_with_aad(&[0x42; 32], &media_header).unwrap();
    let encrypted_media = media_encryptor.push(&padded_media, TAG_FINAL).unwrap();
    let mut media_ciphertext =
        Vec::with_capacity(media_header.len() + stream_header.len() + encrypted_media.len());
    media_ciphertext.extend_from_slice(&media_header);
    media_ciphertext.extend_from_slice(&stream_header);
    media_ciphertext.extend_from_slice(&encrypted_media);
    assert_eq!(
        media_ciphertext.len() as u64,
        chat_backup_media::media_object_ciphertext_bytes(parsed_media.padded_plaintext_bytes)
            .unwrap()
    );
    let media_metadata = UploadChatBackupMediaRequestV1 {
        backup_incarnation_id: backup_id.to_string(),
        media_id: media_id.clone(),
        reference_id: media_reference_id.to_string(),
        source_ciphertext_bytes: source_media.len() as u64,
        ciphertext_bytes: media_ciphertext.len() as u64,
        ciphertext_sha256: hex::encode(Sha256::digest(&media_ciphertext)),
    };
    let upload_media = |metadata: &UploadChatBackupMediaRequestV1,
                        ciphertext: Vec<u8>,
                        token: &str| {
        let form = reqwest::blocking::multipart::Form::new()
            .part(
                "metadata",
                reqwest::blocking::multipart::Part::text(serde_json::to_string(metadata).unwrap())
                    .mime_str("application/json")
                    .unwrap(),
            )
            .part(
                "ciphertext",
                reqwest::blocking::multipart::Part::bytes(ciphertext)
                    .file_name("media.bin")
                    .mime_str("application/octet-stream")
                    .unwrap(),
            );
        c.post(format!("{base}/api/chat/backup/media"))
            .bearer_auth(token)
            .multipart(form)
            .send()
            .unwrap()
    };
    let uploaded: Value = upload_media(&media_metadata, media_ciphertext.clone(), owner_token)
        .json()
        .unwrap();
    assert_eq!(uploaded["mediaId"], media_id);
    assert_eq!(uploaded["alreadyStored"], false);
    let upload_retry: Value = upload_media(&media_metadata, media_ciphertext.clone(), owner_token)
        .json()
        .unwrap();
    assert_eq!(upload_retry["alreadyStored"], true);
    let mut malformed_media = media_metadata.clone();
    malformed_media.ciphertext_sha256 = "22".repeat(32);
    assert_eq!(
        upload_media(&malformed_media, media_ciphertext.clone(), owner_token).status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        upload_media(&media_metadata, media_ciphertext.clone(), foreign_token).status(),
        StatusCode::CONFLICT
    );
    let downloaded_media = c
        .get(format!("{base}/api/chat/backup/media/{media_id}"))
        .bearer_auth(owner_token)
        .send()
        .unwrap();
    assert_eq!(downloaded_media.status(), StatusCode::OK);
    assert_eq!(
        downloaded_media.bytes().unwrap().as_ref(),
        media_ciphertext.as_slice()
    );
    assert_eq!(
        c.get(format!("{base}/api/chat/backup/media/{media_id}"))
            .bearer_auth(foreign_token)
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // Stage a real purpose-bound encrypted base through multipart, including
    // exact replay and a digest/body mismatch that must not affect quota.
    let base_object_id = Uuid::new_v4();
    let base_context = ChatBackupObjectContextV1 {
        backup: backup_context,
        purpose: ChatBackupObjectPurposeV1::BaseSnapshot,
        object_id: *base_object_id.as_bytes(),
        source_device_id: 0,
        device_sequence: 0,
        previous_segment_digest: [0; 32],
    };
    let base_ciphertext = chat_backup::seal_object(
        b"opaque canonical compacted base",
        &backup_root,
        base_context,
    )
    .unwrap();
    let base_metadata = StageChatBackupBaseRequestV1 {
        backup_incarnation_id: backup_id.to_string(),
        object_id: base_object_id.to_string(),
        generation: 1,
        covered_cursor: 21,
        ciphertext_bytes: base_ciphertext.len() as u64,
        ciphertext_sha256: hex::encode(Sha256::digest(&base_ciphertext)),
    };
    let stage = |metadata: &StageChatBackupBaseRequestV1, ciphertext: Vec<u8>| {
        let form = reqwest::blocking::multipart::Form::new()
            .part(
                "metadata",
                reqwest::blocking::multipart::Part::text(serde_json::to_string(metadata).unwrap())
                    .mime_str("application/json")
                    .unwrap(),
            )
            .part(
                "ciphertext",
                reqwest::blocking::multipart::Part::bytes(ciphertext)
                    .file_name("base.bin")
                    .mime_str("application/octet-stream")
                    .unwrap(),
            );
        c.post(format!("{base}/api/chat/backup/bases"))
            .bearer_auth(owner_token)
            .multipart(form)
            .send()
            .unwrap()
    };
    let staged: Value = stage(&base_metadata, base_ciphertext.clone())
        .json()
        .unwrap();
    assert_eq!(staged["objectId"], base_object_id.to_string());
    assert_eq!(staged["alreadyStored"], false);
    let restaged: Value = stage(&base_metadata, base_ciphertext.clone())
        .json()
        .unwrap();
    assert_eq!(restaged["alreadyStored"], true);
    let mut wrong_binding = base_metadata.clone();
    wrong_binding.ciphertext_sha256 = "11".repeat(32);
    assert_eq!(
        stage(&wrong_binding, base_ciphertext.clone()).status(),
        StatusCode::BAD_REQUEST
    );
    let staged_status: Value = c
        .get(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        staged_status["storage"]["usedBytes"],
        expected_bytes + base_ciphertext.len() + media_ciphertext.len()
    );

    let media_reference = ChatBackupMediaReferenceV1 {
        reference_id: media_reference_id.to_string(),
        media_id: media_id.clone(),
    };
    let media_reference_digest = kutup_chat_proto::chat_backup_media_reference_set_digest(
        std::slice::from_ref(&media_reference),
    )
    .expect("media set digest");
    let authorization_digest = authorization.digest().unwrap();
    let mut manifest = ChatBackupManifestV1 {
        version: 1,
        backup_incarnation_id: backup_id.to_string(),
        suite: ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1,
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        generation: 1,
        previous_manifest_digest: "00".repeat(32),
        base_object_id: base_object_id.to_string(),
        base_ciphertext_bytes: base_ciphertext.len() as u64,
        base_ciphertext_sha256: base_metadata.ciphertext_sha256.clone(),
        covered_cursor: 21,
        media_reference_set_digest: media_reference_digest.clone(),
        signer_authorization_digest: authorization_digest,
        created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        signature: String::new(),
    };
    manifest.signature = b64(&signer.sign(&manifest.signing_bytes().unwrap()).to_bytes());
    manifest.verify(&authorization).unwrap();
    let commit = CommitChatBackupManifestRequestV1 {
        expected_generation: 0,
        expected_cursor: 21,
        expected_manifest_digest: "00".repeat(32),
        manifest: manifest.clone(),
    };
    assert_eq!(
        c.put(format!("{base}/api/chat/backup/manifest"))
            .bearer_auth(owner_token)
            .json(&commit)
            .send()
            .unwrap()
            .status(),
        StatusCode::CONFLICT,
        "manifest commit must wait for media reconciliation"
    );

    let reconciliation = ReconcileChatBackupMediaRequestV1 {
        operation_id: Uuid::new_v4().to_string(),
        target_generation: 1,
        reference_set_digest: media_reference_digest,
        page_index: 0,
        final_page: true,
        references: vec![media_reference],
    };
    let reconciled: Value = c
        .post(format!("{base}/api/chat/backup/media/reconciliation"))
        .bearer_auth(owner_token)
        .json(&reconciliation)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(reconciled["nextPage"], 1);
    assert_eq!(reconciled["completed"], true);
    let reconciled_retry: Value = c
        .post(format!("{base}/api/chat/backup/media/reconciliation"))
        .bearer_auth(owner_token)
        .json(&reconciliation)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(reconciled_retry, reconciled);
    let mut changed_reconciliation = reconciliation.clone();
    changed_reconciliation.reference_set_digest = "11".repeat(32);
    assert_eq!(
        c.post(format!("{base}/api/chat/backup/media/reconciliation"))
            .bearer_auth(owner_token)
            .json(&changed_reconciliation)
            .send()
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    // Two committers race the exact same restore point. The row-locked CAS
    // publishes once; the loser observes the new generation and conflicts.
    let commit_candidate = |client: Client| {
        let base = base.to_string();
        let token = owner_token.to_string();
        let request = commit.clone();
        std::thread::spawn(move || {
            client
                .put(format!("{base}/api/chat/backup/manifest"))
                .bearer_auth(token)
                .json(&request)
                .send()
                .unwrap()
                .status()
        })
    };
    let left_task = commit_candidate(c.clone());
    let right_task = commit_candidate(c.clone());
    let left = left_task.join().unwrap();
    let right = right_task.join().unwrap();
    let mut commit_statuses = [left.as_u16(), right.as_u16()];
    commit_statuses.sort_unstable();
    assert_eq!(commit_statuses, [200, 409]);

    let downloaded = c
        .get(format!("{base}/api/chat/backup/bases/{base_object_id}"))
        .bearer_auth(owner_token)
        .send()
        .unwrap();
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(
        downloaded.bytes().unwrap().as_ref(),
        base_ciphertext.as_slice()
    );
    assert_eq!(
        c.get(format!("{base}/api/chat/backup/bases/{base_object_id}"))
            .bearer_auth(foreign_token)
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let compacted_page: Value = c
        .get(format!("{base}/api/chat/backup/segments?after=0&limit=256"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(compacted_page["segments"].as_array().unwrap().is_empty());
    assert_eq!(compacted_page["currentCursor"], 21);
    let compacted_status: Value = c
        .get(format!("{base}/api/chat/backup"))
        .bearer_auth(owner_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(compacted_status["manifest"]["generation"], 1);
    assert_eq!(
        compacted_status["storage"]["messageBytes"],
        base_ciphertext.len()
    );
    assert_eq!(
        compacted_status["storage"]["usedBytes"],
        base_ciphertext.len() + media_ciphertext.len()
    );
    assert_eq!(
        compacted_status["storage"]["historyMediaBytes"],
        media_ciphertext.len()
    );
    if let Some(admin_token) = admin_token {
        let owner: Value = c
            .get(format!("{base}/api/user/me"))
            .bearer_auth(owner_token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        let owner_id = owner["id"].as_str().expect("current user id");
        let set_quota = |quota: usize| {
            let response = c
                .put(format!("{base}/api/admin/users/{owner_id}"))
                .bearer_auth(admin_token)
                .json(&json!({ "chatStorageQuotaBytes": quota }))
                .send()
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        };
        let protected_bytes = base_ciphertext.len() + media_ciphertext.len();
        set_quota(protected_bytes);
        let mut head_digest = previous_digest.clone();
        let mut accepted_bytes = 0usize;
        let mut accepted_segments = 0u64;
        let pending = loop {
            let operation = Uuid::new_v4();
            let sequence = 22 + accepted_segments;
            let prior: [u8; 32] = hex::decode(&head_digest).unwrap().try_into().unwrap();
            let context = ChatBackupObjectContextV1 {
                backup: backup_context,
                purpose: ChatBackupObjectPurposeV1::EventSegment,
                object_id: *operation.as_bytes(),
                source_device_id: device_id,
                device_sequence: sequence,
                previous_segment_digest: prior,
            };
            let ciphertext =
                chat_backup::seal_object(&vec![0x55; 256 * 1024], &backup_root, context).unwrap();
            let candidate = AppendChatBackupSegmentRequestV1 {
                operation_id: operation.to_string(),
                backup_incarnation_id: backup_id.to_string(),
                source_device_id: device_id,
                device_sequence: sequence,
                previous_segment_digest: head_digest.clone(),
                account_manifest_sequence: 1,
                ciphertext_bytes: ciphertext.len() as u32,
                ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
                ciphertext: b64(&ciphertext),
            };
            let response = c
                .post(format!("{base}/api/chat/backup/segments"))
                .bearer_auth(owner_token)
                .json(&candidate)
                .send()
                .unwrap();
            if response.status() == StatusCode::INSUFFICIENT_STORAGE {
                break candidate;
            }
            assert_eq!(response.status(), StatusCode::OK);
            accepted_bytes += ciphertext.len();
            accepted_segments += 1;
            head_digest = candidate.ciphertext_sha256.clone();
            assert!(accepted_segments < 8, "message headroom must be bounded");
        };
        assert!(
            accepted_segments > 0,
            "deletion headroom accepts bounded work"
        );
        let full_status: Value = c
            .get(format!("{base}/api/chat/backup"))
            .bearer_auth(owner_token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(full_status["currentCursor"], 21 + accepted_segments);
        assert_eq!(
            full_status["storage"]["usedBytes"],
            protected_bytes + accepted_bytes
        );
        set_quota(protected_bytes + pending.ciphertext_bytes as usize);
        let resumed: Value = c
            .post(format!("{base}/api/chat/backup/segments"))
            .bearer_auth(owner_token)
            .json(&pending)
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(resumed["cursor"], 22 + accepted_segments);
        assert_eq!(resumed["operationId"], pending.operation_id);
        let boundary_status: Value = c
            .get(format!("{base}/api/chat/backup"))
            .bearer_auth(owner_token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(
            boundary_status["storage"]["usedBytes"],
            protected_bytes + accepted_bytes + pending.ciphertext_bytes as usize
        );

        // A later logical restore point no longer references the attachment.
        // Generation 2 must publish atomically, release the media and covered
        // tail bytes exactly, and make the old media ID unavailable.
        let cursor = boundary_status["currentCursor"].as_u64().unwrap();
        let second_base_id = Uuid::new_v4();
        let second_base = chat_backup::seal_object(
            b"compacted base after attachment deletion",
            &backup_root,
            ChatBackupObjectContextV1 {
                backup: backup_context,
                purpose: ChatBackupObjectPurposeV1::BaseSnapshot,
                object_id: *second_base_id.as_bytes(),
                source_device_id: 0,
                device_sequence: 0,
                previous_segment_digest: [0; 32],
            },
        )
        .unwrap();
        let second_metadata = StageChatBackupBaseRequestV1 {
            backup_incarnation_id: backup_id.to_string(),
            object_id: second_base_id.to_string(),
            generation: 2,
            covered_cursor: cursor,
            ciphertext_bytes: second_base.len() as u64,
            ciphertext_sha256: hex::encode(Sha256::digest(&second_base)),
        };
        assert_eq!(
            stage(&second_metadata, second_base.clone()).status(),
            StatusCode::OK
        );
        let empty_digest = kutup_chat_proto::chat_backup_media_reference_set_digest(&[]).unwrap();
        let empty_reconciliation = ReconcileChatBackupMediaRequestV1 {
            operation_id: Uuid::new_v4().to_string(),
            target_generation: 2,
            reference_set_digest: empty_digest.clone(),
            page_index: 0,
            final_page: true,
            references: Vec::new(),
        };
        assert_eq!(
            c.post(format!("{base}/api/chat/backup/media/reconciliation"))
                .bearer_auth(owner_token)
                .json(&empty_reconciliation)
                .send()
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let first_manifest_digest = manifest.digest().unwrap();
        let mut second_manifest = ChatBackupManifestV1 {
            version: 1,
            backup_incarnation_id: backup_id.to_string(),
            suite: ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1,
            protection_domain: ChatBackupProtectionDomainV1::StandardChat,
            generation: 2,
            previous_manifest_digest: first_manifest_digest.clone(),
            base_object_id: second_base_id.to_string(),
            base_ciphertext_bytes: second_base.len() as u64,
            base_ciphertext_sha256: second_metadata.ciphertext_sha256.clone(),
            covered_cursor: cursor,
            media_reference_set_digest: empty_digest,
            signer_authorization_digest: authorization.digest().unwrap(),
            created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
            signature: String::new(),
        };
        second_manifest.signature = b64(&signer
            .sign(&second_manifest.signing_bytes().unwrap())
            .to_bytes());
        let second_commit = CommitChatBackupManifestRequestV1 {
            expected_generation: 1,
            expected_cursor: cursor,
            expected_manifest_digest: first_manifest_digest,
            manifest: second_manifest,
        };
        assert_eq!(
            c.put(format!("{base}/api/chat/backup/manifest"))
                .bearer_auth(owner_token)
                .json(&second_commit)
                .send()
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let released: Value = c
            .get(format!("{base}/api/chat/backup"))
            .bearer_auth(owner_token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(released["storage"]["historyMediaBytes"], 0);
        assert_eq!(released["storage"]["messageBytes"], second_base.len());
        assert_eq!(released["storage"]["usedBytes"], second_base.len());
        assert_eq!(
            c.get(format!("{base}/api/chat/backup/media/{media_id}"))
                .bearer_auth(owner_token)
                .send()
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    println!(
        "ok  - continuous backup lifecycle provision/append/base/reconcile/CAS/download/isolation"
    );
}

#[test]
fn chat_v1_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset — skipping live chat test");
        return;
    };
    let c = client();
    let live_admin = std::env::var("KUTUP_LIVE_ADMIN").ok();
    let admin_token = live_admin.as_deref().map(|admin| {
        let (email, password) = admin
            .split_once(':')
            .expect("KUTUP_LIVE_ADMIN must be email:password");
        login_with_password(&c, &base, email, password)
    });

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
    assert!(chat["sealedSender"].is_boolean());
    assert!(chat["mlsGroups"].is_boolean());
    assert_eq!(chat["manifests"], true);
    assert_eq!(chat["profiles"], true);
    assert!(chat.get("keyTransparency").is_none());
    assert!(chat["mailboxRetentionDays"].is_number());
    assert!(chat["deviceExpiryDays"].is_number());
    println!("ok  - capability block");

    let (email_a, ua, ta, drive_a, authority_a, drive_sign_a, master_a) =
        register_and_login(&c, &base, "a");
    let (_eb, ub, tb, drive_b, authority_b, drive_sign_b, _master_b) =
        register_and_login(&c, &base, "b");
    let domain = chat["serverName"]
        .as_str()
        .expect("Chat capability has a server name")
        .to_string();
    let account_a = format!("{ua}@{domain}");
    let account_b = format!("{ub}@{domain}");
    println!("ok  - two accounts registered + logged in");

    let (dev_a, reg_a, identity_a) = register_chat_device(&c, &base, &ta);
    let (interrupted_a, _, _) = register_chat_device(&c, &base, &ta);
    let (dev_b, reg_b, identity_b) = register_chat_device(&c, &base, &tb);
    println!("ok  - chat devices registered (A={dev_a} B={dev_b})");

    let manifest_a1 = publish_manifest(
        &c,
        &base,
        &ta,
        &authority_a,
        &account_a,
        &drive_a,
        &drive_sign_a,
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
        &drive_sign_b,
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
    chat_backup_lifecycle(
        &c,
        &base,
        &email_a,
        &ta,
        &tb,
        &master_a,
        &authority_a,
        dev_a,
        admin_token.as_deref(),
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
        &drive_sign_a,
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
        &drive_sign_a,
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

    if let Some(admin_token) = admin_token {
        let owner: Value = c
            .get(format!("{base}/api/user/me"))
            .bearer_auth(&ta)
            .send()
            .unwrap()
            .json()
            .unwrap();
        let owner_id = owner["id"].as_str().expect("current user id");
        let deleted = c
            .delete(format!("{base}/api/admin/users/{owner_id}"))
            .bearer_auth(&admin_token)
            .send()
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            c.delete(format!("{base}/api/admin/users/{owner_id}"))
                .bearer_auth(&admin_token)
                .send()
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND,
            "account purge is safe to retry"
        );
        println!("ok  - account deletion purges the committed backup and is retry-safe");
    }

    println!("\nALL CHAT v1 CONTRACT CHECKS PASSED");
}

#[test]
fn chat_history_transfer_route_is_absent() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset — skipping removed-route test");
        return;
    };
    let response = client()
        .post(format!("{base}/api/chat/history-transfers"))
        .json(&json!({}))
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
