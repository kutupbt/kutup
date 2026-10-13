//! Helpers shared by the Drive live tests: accounts, folders, shares, files.
#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::named_share::NamedShareEnvelopeV1;
use rand::RngCore;
use reqwest::blocking::{multipart, Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The domain the server under test names its accounts with
/// (`CHAT_SERVER_NAME`, advertised as `chat.serverName` in the public
/// settings). Read from the server, not assumed: the gates run servers named
/// `kutup.localhost`, `kutup.test`, `backup.test`, `a.test` and `b.test`, and
/// a Drive key binding or a named share made for another domain is refused.
pub fn server_domain(c: &Client, base: &str) -> String {
    static DOMAINS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let domains = DOMAINS.get_or_init(Default::default);
    if let Some(domain) = domains.lock().unwrap().get(base) {
        return domain.clone();
    }
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let domain = settings["chat"]["serverName"]
        .as_str()
        .expect("the server advertises its name")
        .to_string();
    domains
        .lock()
        .unwrap()
        .insert(base.to_string(), domain.clone());
    domain
}

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn bearer(req: RequestBuilder, token: &str) -> RequestBuilder {
    req.header("authorization", format!("Bearer {token}"))
}

pub struct User {
    pub id: String,
    /// What the account's keys are bound to: its key binding (a UUID v4
    /// drawn at registration; docs/plans/account-identity.md).
    pub binding: String,
    pub username: String,
    /// The password's login key (base64), for re-checks and a re-seal.
    pub login_key: String,
    pub recovery_entropy: [u8; 32],
    pub token: String,
    pub identity: AccountIdentityKeysV1,
    pub master_key: [u8; 32],
    /// `username@domain`, with the domain of the server it was made on.
    pub account: String,
}

pub fn register(c: &Client, base: &str) -> User {
    register_with(c, base, true).unwrap_or_else(|status| panic!("register: {status}"))
}

/// What registering without a Drive key binding answers
/// (docs/plans/drive-identity-pins.md): it is required.
pub fn register_without_binding(c: &Client, base: &str) -> StatusCode {
    match register_with(c, base, false) {
        Ok(user) => panic!("registered {} without a binding", user.username),
        Err(status) => status,
    }
}

/// Registers `username`, answering the registration's status.
#[allow(dead_code)]
pub fn register_named(c: &Client, base: &str, username: &str) -> StatusCode {
    match register_attempt(c, base, true, username.to_owned()) {
        Ok(_) => StatusCode::CREATED,
        Err(status) => status,
    }
}

fn register_with(c: &Client, base: &str, binding: bool) -> Result<User, StatusCode> {
    let tag = rand::thread_rng().next_u64() % 1_000_000_000;
    register_attempt(c, base, binding, format!("int{tag}"))
}

fn register_attempt(
    c: &Client,
    base: &str,
    binding: bool,
    username: String,
) -> Result<User, StatusCode> {
    register_full(c, base, binding, username, None).map_err(|(status, _)| status)
}

/// Registers a fresh account with a referral code (or none): the account,
/// or the refusal's status and body.
pub fn register_coded(
    c: &Client,
    base: &str,
    code: Option<&str>,
) -> Result<User, (StatusCode, Value)> {
    let tag = rand::thread_rng().next_u64() % 1_000_000_000;
    register_full(c, base, true, format!("ref{tag}"), code)
}

fn register_full(
    c: &Client,
    base: &str,
    binding: bool,
    username: String,
    code: Option<&str>,
) -> Result<User, (StatusCode, Value)> {
    let mut rng = rand::thread_rng();
    let key_binding = uuid::Uuid::new_v4().to_string();
    let password = "integrity-pw-123456";
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut salt);
    let keys = kutup_crypto::kdf::derive_account_protection_keys(
        password,
        &salt,
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    let recovery_proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, &key_binding).unwrap();
    let identity = AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let seal = |plain: &[u8], key: &[u8], purpose| {
        account_envelope::seal_b64(plain, key, purpose, &key_binding).unwrap()
    };
    let mut body = json!({
            "keyBinding": key_binding, "username": username,
            "loginKey": b64(keys.login_key.as_slice()),
            "masterKeyEnvelope": seal(&master_key, keys.key_encryption_key.as_slice(), AccountEnvelopePurpose::PasswordMasterKey),
            "recoveryKeyEnvelope": seal(&master_key, &recovery_entropy, AccountEnvelopePurpose::RecoveryMasterKey),
            "drivePrivateKeyEnvelope": seal(identity.drive_hpke_private_key(), &master_key, AccountEnvelopePurpose::DriveHpkePrivateKey),
            "publicKey": b64(&identity.drive_hpke_public_key()),
            "accountAuthorityPublicKey": b64(&identity.authority_public_key()),
            "accountAuthorityKeyId": identity.authority_key_id(),
            "accountIncarnationId": identity.incarnation_id(),
            "driveSigningPublicKey": b64(&identity.drive_signing_public_key()),
            "accountProtectionSuite": 1,
            "accountProtectionSalt": b64(&salt),
            "argonMemoryKib": 65536, "argonIterations": 3, "argonParallelism": 1,
            "recoveryProof": b64(recovery_proof.as_slice()),
    });
    if let Some(code) = code {
        body["registrationCode"] = json!(code);
    }
    if binding {
        let account = format!("{username}@{}", server_domain(c, base));
        body["driveKeyBinding"] = json!(b64(&kutup_crypto::drive_key_binding::sign(
            &identity, &account
        )
        .unwrap()));
    }
    let r = c
        .post(format!("{base}/api/auth/register"))
        .json(&body)
        .send()
        .unwrap();
    if !r.status().is_success() {
        let status = r.status();
        return Err((status, r.json().unwrap_or(Value::Null)));
    }
    let r = c
        .post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "name": username, "loginKey": b64(keys.login_key.as_slice()) }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "login: {}", r.status());
    let token = r.json::<Value>().unwrap()["accessToken"]
        .as_str()
        .unwrap()
        .to_string();
    let id = bearer(c.get(format!("{base}/api/user/me")), &token)
        .send()
        .unwrap()
        .json::<Value>()
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let account = format!("{username}@{}", server_domain(c, base));
    Ok(User {
        id,
        binding: key_binding,
        login_key: b64(keys.login_key.as_slice()),
        recovery_entropy,
        username,
        account,
        token,
        identity,
        master_key,
    })
}

pub fn me(c: &Client, base: &str, token: &str) -> Value {
    bearer(c.get(format!("{base}/api/user/me")), token)
        .send()
        .unwrap()
        .json()
        .unwrap()
}

pub fn used(c: &Client, base: &str, token: &str) -> i64 {
    me(c, base, token)["storageUsedBytes"].as_i64().unwrap()
}

pub fn ctx(purpose: DriveEnvelopePurpose, object: &str, parent: &str) -> DriveEnvelopeContextV1 {
    DriveEnvelopeContextV1::new(purpose, 1, 1, object, parent).unwrap()
}

pub struct Folder {
    pub id: String,
    pub key: [u8; 32],
}

/// A stand-in name hash (64 lowercase hex digits) unique to `id`: the server
/// never reads names, only keeps their hashes apart.
pub fn test_name_hash(id: &str) -> String {
    id.replace('-', "").repeat(2)
}

pub fn create_folder(c: &Client, base: &str, owner: &User) -> Folder {
    create_folder_in(c, base, owner, None)
}

pub fn create_folder_in(c: &Client, base: &str, owner: &User, parent: Option<&str>) -> Folder {
    let id = uuid();
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let r = bearer(c.post(format!("{base}/api/collections")), &owner.token)
        .json(&json!({
            "id": id,
            "ownerKeyEnvelope": drive_envelope::seal_b64(&key, &owner.master_key, ctx(DriveEnvelopePurpose::CollectionKey, &id, &owner.id)).unwrap(),
            "nameEnvelope": drive_envelope::seal_b64(b"Integrity", &key, ctx(DriveEnvelopePurpose::CollectionName, &id, &owner.id)).unwrap(),
            "epochStatement": CollectionEpochStatementV1::create(&id, &owner.id, 1, None, &key, owner.identity.authority_signing_key()).unwrap().encode_b64(),
            "parentCollectionId": parent,
            "nameHash": test_name_hash(&id),
        }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "create folder: {}", r.status());
    Folder { id, key }
}

pub fn share(c: &Client, base: &str, owner: &User, folder: &Folder, to: &User, can_upload: bool) {
    let envelope = NamedShareEnvelopeV1::seal(
        &folder.key,
        &folder.id,
        1,
        &owner.account,
        &owner.identity.incarnation_id(),
        owner.identity.drive_signing_key(),
        &to.account,
        &to.identity.incarnation_id(),
        &to.identity.drive_hpke_public_key(),
    )
    .unwrap()
    .encode_b64()
    .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/share", folder.id)),
        &owner.token,
    )
    .json(&json!({
        "recipientUserId": to.id,
        "namedShareEnvelope": envelope,
        "canUpload": can_upload,
        "canDelete": false,
        "uploadQuotaBytes": null,
    }))
    .send()
    .unwrap();
    assert!(r.status().is_success(), "share: {}", r.status());
}

/// A sealed file for `folder`: (file id, file key, blob, form fields).
pub struct Sealed {
    pub id: String,
    pub key: [u8; 32],
    pub blob: Vec<u8>,
    pub metadata_envelope: String,
    pub file_key_envelope: String,
}

pub fn seal_file(folder: &Folder, id: &str, plain: &[u8]) -> Sealed {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    Sealed {
        id: id.to_string(),
        key,
        blob: drive_object::encrypt_file_blob(
            plain,
            &key,
            DriveFileBlobContextV1::new(id, 1).unwrap(),
        )
        .unwrap(),
        metadata_envelope: drive_envelope::seal_b64(
            br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#,
            &key,
            DriveEnvelopeContextV1::file_metadata(id, 1, 1).unwrap(),
        )
        .unwrap(),
        file_key_envelope: drive_envelope::seal_b64(
            &key,
            &folder.key,
            DriveEnvelopeContextV1::file_key(id, &folder.id, 1, 1).unwrap(),
        )
        .unwrap(),
    }
}

pub fn upload(c: &Client, base: &str, token: &str, folder: &Folder, file: &Sealed) -> Response {
    let form = multipart::Form::new()
        .text("fileId", file.id.clone())
        .text("collectionId", folder.id.clone())
        .text("fileKeyEnvelope", file.file_key_envelope.clone())
        .text("metadataEnvelope", file.metadata_envelope.clone())
        .text("nameHash", test_name_hash(&file.id))
        .part(
            "file",
            multipart::Part::bytes(file.blob.clone()).file_name("encrypted"),
        );
    bearer(c.post(format!("{base}/api/files/upload")), token)
        .multipart(form)
        .send()
        .unwrap()
}

pub fn download(c: &Client, base: &str, token: &str, file_id: &str) -> (StatusCode, Vec<u8>) {
    let r = bearer(c.get(format!("{base}/api/files/{file_id}/download")), token)
        .send()
        .unwrap();
    (r.status(), r.bytes().unwrap().to_vec())
}

pub fn post_version(c: &Client, base: &str, token: &str, file_id: &str, blob: Vec<u8>) -> Response {
    let form = multipart::Form::new()
        .text("kind", "file")
        .text("seqAtSnapshot", "0")
        .text("docKeyId", "1")
        .part("file", multipart::Part::bytes(blob).file_name("version"));
    bearer(
        c.post(format!("{base}/api/files/{file_id}/versions")),
        token,
    )
    .multipart(form)
    .send()
    .unwrap()
}

pub fn put_asset(
    c: &Client,
    base: &str,
    token: &str,
    file: &Sealed,
    asset_id: &str,
    plain: &[u8],
) -> Response {
    let envelope = STANDARD
        .decode(
            drive_envelope::seal_b64(
                plain,
                &file.key,
                DriveEnvelopeContextV1::whiteboard_asset(&file.id, asset_id, 1).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    bearer(
        c.put(format!("{base}/api/files/{}/assets/{asset_id}", file.id)),
        token,
    )
    .multipart(
        multipart::Form::new().part("file", multipart::Part::bytes(envelope).file_name("asset")),
    )
    .send()
    .unwrap()
}

pub fn tus_create(
    c: &Client,
    base: &str,
    token: &str,
    folder: &Folder,
    file: &Sealed,
    length: i64,
) -> Response {
    let name_hash = test_name_hash(&file.id);
    let meta = [
        ("fileId", file.id.as_str()),
        ("collectionId", folder.id.as_str()),
        ("metadataEnvelope", file.metadata_envelope.as_str()),
        ("fileKeyEnvelope", file.file_key_envelope.as_str()),
        ("nameHash", name_hash.as_str()),
    ]
    .iter()
    .map(|(k, v)| format!("{k} {}", b64(v.as_bytes())))
    .collect::<Vec<_>>()
    .join(",");
    bearer(c.post(format!("{base}/api/uploads")), token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", length.to_string())
        .header("Upload-Metadata", meta)
        .send()
        .unwrap()
}

/// A link key sealed for its owner (purpose 9), as `POST /share` takes it.
pub fn owner_link_key(link_key: &[u8; 32], owner: &User, link_id: &str) -> String {
    drive_envelope::seal_b64(
        link_key,
        &owner.master_key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::PublicLinkKey,
            1,
            1,
            link_id,
            &owner.id,
        )
        .unwrap(),
    )
    .unwrap()
}

/// The administrator's token, signing in by username as any account does
/// (its temporary password derived under the salt preflight answers),
/// completing its first-login setup on a fresh server.
/// Deletes `users` for good through the administrator (`KUTUP_LIVE_ADMIN`
/// as `name:password`), so the gate's purge checks see nothing left behind.
/// Without an administrator the accounts stay (a run outside the gate).
pub fn purge_accounts(c: &Client, base: &str, users: &[&User]) {
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN unset; test accounts are kept");
        return;
    };
    let (name, password) = admin
        .split_once(':')
        .expect("KUTUP_LIVE_ADMIN is name:password");
    let token = admin_token(c, base, password, name);
    for user in users {
        let r = bearer(
            c.delete(format!("{base}/api/admin/users/{}", user.id)),
            &token,
        )
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "purge {}", user.id);
    }
}

pub fn admin_token(c: &Client, base: &str, password: &str, username: &str) -> String {
    let preflight: Value = c
        .get(format!("{base}/api/auth/login/preflight?name={username}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let derived = kutup_crypto::kdf::derive_account_protection_keys_b64(
        password,
        preflight["accountProtectionSalt"].as_str().unwrap(),
        kutup_crypto::kdf::AccountProtectionParameters {
            memory_kib: preflight["argonMemoryKib"].as_u64().unwrap() as u32,
            iterations: preflight["argonIterations"].as_u64().unwrap() as u32,
            parallelism: preflight["argonParallelism"].as_u64().unwrap() as u32,
        },
    )
    .unwrap();
    let response = c
        .post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "name": username, "loginKey": b64(derived.login_key.as_slice()) }))
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "admin login");
    let login: Value = response.json().unwrap();
    let Some(setup_token) = login["setupToken"].as_str() else {
        return login["accessToken"].as_str().unwrap().to_string();
    };
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
    let binding = uuid::Uuid::new_v4().to_string();
    let recovery_proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, &binding).unwrap();
    let identity = AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let seal = |plain: &[u8], key: &[u8], purpose| {
        account_envelope::seal_b64(plain, key, purpose, &binding).unwrap()
    };
    let completed = c
        .post(format!("{base}/api/auth/complete-setup"))
        .header("x-kutup-client", "cli")
        .bearer_auth(setup_token)
        .json(&json!({
            "keyBinding": binding, "username": username,
            "loginKey": b64(keys.login_key.as_slice()),
            "masterKeyEnvelope": seal(&master_key, keys.key_encryption_key.as_slice(), AccountEnvelopePurpose::PasswordMasterKey),
            "recoveryKeyEnvelope": seal(&master_key, &recovery_entropy, AccountEnvelopePurpose::RecoveryMasterKey),
            "drivePrivateKeyEnvelope": seal(identity.drive_hpke_private_key(), &master_key, AccountEnvelopePurpose::DriveHpkePrivateKey),
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
            "driveKeyBinding": b64(&kutup_crypto::drive_key_binding::sign(
                &identity,
                &format!("{username}@{}", server_domain(c, base)),
            ).unwrap()),
        }))
        .send()
        .unwrap();
    let status = completed.status();
    let body: Value = completed.json().unwrap();
    assert_eq!(status, StatusCode::OK, "admin setup: {body}");
    body["accessToken"].as_str().unwrap().to_string()
}

/// A temporary password as an administrator's browser derives it (the
/// `setup` of creating, rotating or wiping an account).
pub fn setup_key(password: &str) -> Value {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let parameters = kutup_crypto::kdf::AccountProtectionParameters::V1;
    let keys =
        kutup_crypto::kdf::derive_account_protection_keys(password, &salt, parameters).unwrap();
    json!({
        "loginKey": b64(keys.login_key.as_slice()),
        "accountProtectionSuite": 1,
        "accountProtectionSalt": b64(&salt),
        "argonMemoryKib": parameters.memory_kib,
        "argonIterations": parameters.iterations,
        "argonParallelism": parameters.parallelism,
    })
}

/// A collaboration device: its id and the seed of the key it signs frames with.
pub struct Device {
    pub id: i64,
    pub seed: [u8; 32],
}

/// A one-time device registration challenge (base64).
pub fn device_challenge(c: &Client, base: &str, user: &User) -> String {
    let r: Value = bearer(c.post(format!("{base}/api/devices/challenge")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    r["challenge"].as_str().unwrap().to_string()
}

/// The registration body for `device_key`, signed by `signer`'s authority for
/// `user`'s account over `challenge`, now (docs/plans/device-registration.md).
pub fn device_registration_body(
    c: &Client,
    base: &str,
    user: &User,
    signer: &User,
    device_key: &[u8; 32],
    challenge: &str,
) -> Value {
    let raw: [u8; 32] = STANDARD.decode(challenge).unwrap().try_into().unwrap();
    let server = server_domain(c, base);
    let issued_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let statement = kutup_crypto::device_registration::DeviceStatement {
        server: &server,
        user_id: &user.id,
        device_public: device_key,
        purpose: kutup_crypto::device_registration::PURPOSE_COLLAB_FRAMES,
        challenge: &raw,
        issued_at_ms,
    };
    let signature = kutup_crypto::device_registration::sign(&signer.identity, &statement).unwrap();
    json!({
        "publicSigning": STANDARD.encode(device_key),
        "label": "test device",
        "challenge": challenge,
        "issuedAtMs": issued_at_ms,
        "signature": signature,
    })
}

/// The account's signed revocation body for `device_key`.
pub fn device_revocation_body(c: &Client, base: &str, user: &User, device_key: &[u8; 32]) -> Value {
    let revoked_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let signature = kutup_crypto::device_registration::sign_revocation(
        &user.identity,
        &server_domain(c, base),
        device_key,
        revoked_at_ms,
    )
    .unwrap();
    json!({ "revokedAtMs": revoked_at_ms, "signature": signature })
}

/// A device registered the proper way: a fresh challenge, signed by the
/// account's own authority.
/// Signs `user` in again: a new session (token) of the same account.
pub fn sign_in_again(c: &Client, base: &str, user: &User) -> String {
    let r = c
        .post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "name": user.username, "loginKey": user.login_key }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "login: {}", r.status());
    r.json::<Value>().unwrap()["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn register_device(c: &Client, base: &str, user: &User) -> Device {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let key = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let challenge = device_challenge(c, base, user);
    let r = bearer(c.post(format!("{base}/api/devices")), &user.token)
        .json(&device_registration_body(
            c, base, user, user, &key, &challenge,
        ))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "register a device");
    let body: Value = r.json().unwrap();
    Device {
        id: body["deviceId"].as_i64().unwrap(),
        seed,
    }
}
