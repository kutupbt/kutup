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

pub const DOMAIN: &str = "kutup.localhost";

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn bearer(req: RequestBuilder, token: &str) -> RequestBuilder {
    req.header("authorization", format!("Bearer {token}"))
}

pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    pub token: String,
    pub identity: AccountIdentityKeysV1,
    pub master_key: [u8; 32],
}

pub fn register(c: &Client, base: &str) -> User {
    let mut rng = rand::thread_rng();
    let tag = rng.next_u64() % 1_000_000_000;
    let email = format!("integrity-{tag}@example.com");
    let username = format!("int{tag}");
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
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, &email).unwrap();
    let identity = AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let seal = |plain: &[u8], key: &[u8], purpose| {
        account_envelope::seal_b64(plain, key, purpose, &email).unwrap()
    };
    let r = c
        .post(format!("{base}/api/auth/register"))
        .json(&json!({
            "email": email, "username": username,
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
        }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "register: {}", r.status());
    let r = c
        .post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "email": email, "loginKey": b64(keys.login_key.as_slice()) }))
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
    User {
        id,
        email,
        username,
        token,
        identity,
        master_key,
    }
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
        &format!("{}@{DOMAIN}", owner.username),
        &owner.identity.incarnation_id(),
        owner.identity.drive_signing_key(),
        &format!("{}@{DOMAIN}", to.username),
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
    let meta = [
        ("fileId", file.id.as_str()),
        ("collectionId", folder.id.as_str()),
        ("metadataEnvelope", file.metadata_envelope.as_str()),
        ("fileKeyEnvelope", file.file_key_envelope.as_str()),
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

/// Signs in as the bootstrap admin (`ADMIN_ACCOUNT`), completing its
/// first-login setup on a fresh server.
pub fn admin_token(c: &Client, base: &str, email: &str, password: &str, username: &str) -> String {
    let preflight: Value = c
        .get(format!("{base}/api/auth/login/preflight?email={email}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if preflight["accountProtectionSuite"] == 0 {
        let bootstrap: Value = c
            .post(format!("{base}/api/auth/login"))
            .header("x-kutup-client", "cli")
            .json(&json!({ "email": email, "loginKey": b64(password.as_bytes()) }))
            .send()
            .unwrap()
            .json()
            .unwrap();
        let setup_token = bootstrap["setupToken"]
            .as_str()
            .unwrap_or_else(|| panic!("admin first login: {bootstrap}"));
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
        let identity = AccountIdentityKeysV1::derive(&master_key).unwrap();
        use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
        let seal = |plain: &[u8], key: &[u8], purpose| {
            account_envelope::seal_b64(plain, key, purpose, email).unwrap()
        };
        let completed = c
            .post(format!("{base}/api/auth/complete-setup"))
            .header("x-kutup-client", "cli")
            .bearer_auth(setup_token)
            .json(&json!({
                "email": email, "username": username,
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
            }))
            .send()
            .unwrap();
        let status = completed.status();
        let body: Value = completed.json().unwrap();
        assert_eq!(status, StatusCode::OK, "admin setup: {body}");
        return body["accessToken"].as_str().unwrap().to_string();
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
        .header("x-kutup-client", "cli")
        .json(&json!({ "email": email, "loginKey": b64(keys.login_key.as_slice()) }))
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "admin login");
    response.json::<Value>().unwrap()["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}
