//! Live e2e for Drive versions v2 (`docs/plans/drive-versions-v2.md`).
//!
//! One request stores a version, charged by its measured size; downloads
//! serve the latest whole-file version; the retention setting.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test versions_live -- --nocapture

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

struct Account {
    email: String,
    login_key: String,
    master_key: [u8; 32],
}

fn register(c: &Client, base: &str) -> Account {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("versions-{ts}@example.com");
    let username = format!("ver{}", ts % 1_000_000);
    let password = "sessions-pw-123456";
    let mut rng = rand::thread_rng();
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
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let seal = |plain: &[u8], key: &[u8], purpose| {
        account_envelope::seal_b64(plain, key, purpose, &email).unwrap()
    };
    let reg = json!({
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
    });
    let r = c
        .post(format!("{base}/api/auth/register"))
        .json(&reg)
        .send()
        .unwrap();
    assert!(r.status().is_success(), "register: {}", r.status());
    Account {
        email,
        login_key: b64(keys.login_key.as_slice()),
        master_key,
    }
}

fn login(c: &Client, base: &str, a: &Account, client_type: Option<&str>) -> Response {
    let mut req = c
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "email": a.email, "loginKey": a.login_key }));
    if let Some(ct) = client_type {
        req = req.header("x-kutup-client", ct);
    }
    req.send().unwrap()
}

fn bearer(req: RequestBuilder, token: &str) -> RequestBuilder {
    req.header("authorization", format!("Bearer {token}"))
}

use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn token_of(c: &Client, base: &str, a: &Account) -> String {
    let r = login(c, base, a, Some("cli"));
    assert!(r.status().is_success(), "login: {}", r.status());
    r.json::<Value>().unwrap()["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

fn me(c: &Client, base: &str, token: &str) -> Value {
    bearer(c.get(format!("{base}/api/user/me")), token)
        .send()
        .unwrap()
        .json()
        .unwrap()
}

fn used(c: &Client, base: &str, token: &str) -> i64 {
    me(c, base, token)["storageUsedBytes"].as_i64().unwrap()
}

fn post_version(
    c: &Client,
    base: &str,
    token: &str,
    file_id: &str,
    kind: &str,
    blob: Vec<u8>,
    extra: &[(&str, &str)],
) -> Response {
    let mut form = reqwest::blocking::multipart::Form::new()
        .text("kind", kind.to_string())
        .text("seqAtSnapshot", "0")
        .text("docKeyId", "1");
    for (k, v) in extra {
        form = form.text(k.to_string(), v.to_string());
    }
    form = form.part(
        "file",
        reqwest::blocking::multipart::Part::bytes(blob).file_name("version"),
    );
    bearer(
        c.post(format!("{base}/api/files/{file_id}/versions")),
        token,
    )
    .multipart(form)
    .send()
    .unwrap()
}

#[test]
fn versions_v2_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let owner = register(&c, &base);
    let token = token_of(&c, &base, &owner);
    let user_id = me(&c, &base, &token)["id"].as_str().unwrap().to_string();
    let identity =
        kutup_crypto::identity::AccountIdentityKeysV1::derive(&owner.master_key).unwrap();

    // An owned folder, as createOwnedCollectionV1 makes it.
    let collection_id = uuid();
    let collection_key = [0x51u8; 32];
    let ctx = |purpose, object: &str, parent: &str| {
        DriveEnvelopeContextV1::new(purpose, 1, 1, object, parent).unwrap()
    };
    let created = bearer(c.post(format!("{base}/api/collections")), &token)
        .json(&json!({
            "id": collection_id,
            "ownerKeyEnvelope": drive_envelope::seal_b64(&collection_key, &owner.master_key, ctx(DriveEnvelopePurpose::CollectionKey, &collection_id, &user_id)).unwrap(),
            "nameEnvelope": drive_envelope::seal_b64(b"Thumbs", &collection_key, ctx(DriveEnvelopePurpose::CollectionName, &collection_id, &user_id)).unwrap(),
            "epochStatement": CollectionEpochStatementV1::create(&collection_id, &user_id, 1, None, &collection_key, identity.authority_signing_key()).unwrap().encode_b64(),
            "parentCollectionId": null,
        }))
        .send()
        .unwrap();
    assert!(
        created.status().is_success(),
        "create collection: {}",
        created.status()
    );

    // A file in it, as the upload path makes it.
    let file_id = uuid();
    let file_key = [0x61u8; 32];
    let blob = drive_object::encrypt_file_blob(
        b"hello thumbnails",
        &file_key,
        DriveFileBlobContextV1::new(&file_id, &collection_id, 1).unwrap(),
    )
    .unwrap();
    let form = reqwest::blocking::multipart::Form::new()
        .text("fileId", file_id.clone())
        .text("collectionId", collection_id.clone())
        .text(
            "fileKeyEnvelope",
            drive_envelope::seal_b64(
                &file_key,
                &collection_key,
                ctx(DriveEnvelopePurpose::FileKey, &file_id, &collection_id),
            )
            .unwrap(),
        )
        .text(
            "metadataEnvelope",
            drive_envelope::seal_b64(
                br#"{"name":"a.txt","mimeType":"text/plain","size":16}"#,
                &file_key,
                ctx(DriveEnvelopePurpose::FileMetadata, &file_id, &collection_id),
            )
            .unwrap(),
        )
        .part(
            "file",
            reqwest::blocking::multipart::Part::bytes(blob).file_name("encrypted"),
        );
    let uploaded = bearer(c.post(format!("{base}/api/files/upload")), &token)
        .multipart(form)
        .send()
        .unwrap();
    assert!(
        uploaded.status().is_success(),
        "upload: {}",
        uploaded.status()
    );

    let seal = |plain: &[u8]| {
        drive_object::encrypt_file_blob(
            plain,
            &file_key,
            DriveFileBlobContextV1::new(&file_id, &collection_id, 1).unwrap(),
        )
        .unwrap()
    };
    let download = |token: &str| -> Vec<u8> {
        bearer(c.get(format!("{base}/api/files/{file_id}/download")), token)
            .send()
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec()
    };
    let original = download(&token);
    let baseline = used(&c, &base, &token);

    // Charged by what arrived; a client's size claim is ignored.
    let edited = seal(&vec![7u8; 50_000]);
    let r = post_version(
        &c,
        &base,
        &token,
        &file_id,
        "file",
        edited.clone(),
        &[("sizeBytes", "1"), ("label", "Draft")],
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().unwrap();
    assert_eq!(v["kind"], "file");
    assert_eq!(v["label"], "Draft");
    assert_eq!(v["sizeBytes"], edited.len() as i64);
    assert_eq!(v["s3VersionId"], "", "a version is an object of its own");
    assert!(v["storagePath"]
        .as_str()
        .unwrap()
        .ends_with(v["id"].as_str().unwrap()));
    assert_eq!(used(&c, &base, &token), baseline + edited.len() as i64);

    // The download is the file as it is now: the latest whole-file version…
    assert_eq!(download(&token), edited);
    // …which a note-state version does not replace.
    let r = post_version(&c, &base, &token, &file_id, "yjs", seal(b"yjs state"), &[]);
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(download(&token), edited);
    assert_ne!(download(&token), original);

    // The version downloads as itself.
    let got = bearer(
        c.get(format!(
            "{base}/api/files/{file_id}/versions/{}/download",
            v["id"].as_str().unwrap()
        )),
        &token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap()
    .to_vec();
    assert_eq!(got, edited);

    // Refused: an unknown kind, no body, a blob sealed for another file.
    assert_eq!(
        post_version(&c, &base, &token, &file_id, "zip", seal(b"x"), &[]).status(),
        StatusCode::BAD_REQUEST
    );
    let other = drive_object::encrypt_file_blob(
        b"x",
        &file_key,
        DriveFileBlobContextV1::new(&uuid(), &collection_id, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        post_version(&c, &base, &token, &file_id, "file", other, &[]).status(),
        StatusCode::BAD_REQUEST
    );
    let no_file = reqwest::blocking::multipart::Form::new().text("kind", "file");
    assert_eq!(
        bearer(
            c.post(format!("{base}/api/files/{file_id}/versions")),
            &token
        )
        .multipart(no_file)
        .send()
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );

    // Someone without access cannot add one.
    let stranger = register(&c, &base);
    let stranger_token = token_of(&c, &base, &stranger);
    assert_eq!(
        post_version(
            &c,
            &base,
            &stranger_token,
            &file_id,
            "file",
            seal(b"x"),
            &[]
        )
        .status(),
        StatusCode::FORBIDDEN
    );

    // The retention setting.
    assert_eq!(me(&c, &base, &token)["versionRetentionDays"], 30);
    let set = |days: i32| {
        bearer(c.patch(format!("{base}/api/user/me")), &token)
            .json(&json!({ "versionRetentionDays": days }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(set(90), StatusCode::OK);
    assert_eq!(me(&c, &base, &token)["versionRetentionDays"], 90);
    assert_eq!(set(45), StatusCode::BAD_REQUEST);
    assert_eq!(me(&c, &base, &token)["versionRetentionDays"], 90);
}
