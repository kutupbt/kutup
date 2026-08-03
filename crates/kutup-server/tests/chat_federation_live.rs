//! Live two-server contract for transport-only chat federation.
//!
//! Run only through `scripts/test-chat-federation.sh`. The script supplies two
//! isolated server URLs and drives three phases so it can take the destination
//! edge offline and restart the origin between queueing and verification.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::Signer as _;
use kutup_chat_proto::{
    AccountIdentitySuiteId, AccountManifestDeviceV1, AccountManifestDriveKeysV1,
    AccountManifestHistoryPageV1, AccountManifestV1, DirectChatSuiteId, UserPreKeyBundlesResponse,
};
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::named_share::NamedShareEnvelopeV1;
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

fn test_master_key(email: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"kutup/two-server-live/account-master/v1\0");
    hasher.update(email.as_bytes());
    hasher.finalize().into()
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
    let master_key = test_master_key(email);
    let mut recovery_entropy = [0u8; 32];
    let mut account_protection_salt = [0u8; 16];
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut account_protection_salt);

    let keys = kutup_crypto::kdf::derive_account_protection_keys(
        PASSWORD,
        &account_protection_salt,
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    let recovery_proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, email).unwrap();
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let master_key_envelope = account_envelope::seal_b64(
        &master_key,
        keys.key_encryption_key.as_slice(),
        AccountEnvelopePurpose::PasswordMasterKey,
        email,
    )
    .unwrap();
    let recovery_key_envelope = account_envelope::seal_b64(
        &master_key,
        &recovery_entropy,
        AccountEnvelopePurpose::RecoveryMasterKey,
        email,
    )
    .unwrap();
    let drive_private_key_envelope = account_envelope::seal_b64(
        identity.drive_hpke_private_key(),
        &master_key,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        email,
    )
    .unwrap();

    json!({
        "email": email,
        "username": username,
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
        "argonMemoryKib": 65536,
        "argonIterations": 3,
        "argonParallelism": 1,
        "recoveryProof": b64(recovery_proof.as_slice()),
    })
}

fn register_account(c: &Client, base: &str, email: &str, username: &str) -> (String, String) {
    let payload = registration_payload(email, username);
    let public_key = payload["publicKey"].as_str().unwrap().to_owned();
    let response = c
        .post(format!("{base}/api/auth/register"))
        .json(&payload)
        .send()
        .unwrap();
    json_response(response, &format!("register {username}"));
    (login(c, base, email), public_key)
}

fn setup_admin(c: &Client, base: &str, email: &str, username: &str) -> String {
    let preflight = json_response(
        c.get(format!("{base}/api/auth/login/preflight?email={email}"))
            .send()
            .unwrap(),
        "bootstrap admin preflight",
    );
    if preflight["accountProtectionSalt"]
        .as_str()
        .is_some_and(|salt| !salt.is_empty())
    {
        return login(c, base, email);
    }
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
    let setup_payload = registration_payload(email, username);
    let setup = json_response(
        c.post(format!("{base}/api/auth/complete-setup"))
            .bearer_auth(setup_token)
            .json(&setup_payload)
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
    let keys = kutup_crypto::kdf::derive_account_protection_keys_b64(
        PASSWORD,
        preflight["accountProtectionSalt"].as_str().unwrap(),
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    let response = json_response(
        c.post(format!("{base}/api/auth/login"))
            .json(&json!({"email": email, "loginKey": b64(keys.login_key.as_slice())}))
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

fn manifest_device(device_id: u32, registration_id: u32, seed: u8) -> AccountManifestDeviceV1 {
    AccountManifestDeviceV1 {
        device_id,
        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        registration_id,
        identity_key: b64(&[seed.wrapping_add(1); 33]),
        mls: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_manifest(
    c: &Client,
    base: &str,
    token: &str,
    identity: &AccountIdentityKeysV1,
    account: &str,
    drive_public_key: &str,
    sequence: u64,
    previous_hash: Option<String>,
    devices: Vec<AccountManifestDeviceV1>,
) -> AccountManifestV1 {
    let public = identity.authority_signing_key().verifying_key();
    let mut manifest = AccountManifestV1 {
        manifest_version: 1,
        account: account.into(),
        incarnation_id: identity.incarnation_id(),
        sequence,
        previous_hash,
        drive: AccountManifestDriveKeysV1 {
            suite: AccountIdentitySuiteId::X25519Ed25519V1,
            hpke_public_key: drive_public_key.into(),
            share_signing_public_key: b64(&identity.drive_signing_public_key()),
        },
        devices,
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        authority_key_id: hex::encode(Sha256::digest(public.as_bytes())),
        self_authority_key: b64(public.as_bytes()),
        signature: String::new(),
    };
    manifest.signature = b64(&identity
        .authority_signing_key()
        .sign(&manifest.signing_bytes().unwrap())
        .to_bytes());
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

fn drive_upload_body(
    boundary: &str,
    file_id: &str,
    metadata_envelope: &str,
    file_key_envelope: &str,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in [
        ("fileId", file_id),
        ("metadataEnvelope", metadata_envelope),
        ("fileKeyEnvelope", file_key_envelope),
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
    let alice_master = test_master_key(ALICE_EMAIL);
    let bob_master = test_master_key(BOB_EMAIL);
    let alice_identity = AccountIdentityKeysV1::derive(&alice_master).unwrap();
    let bob_identity = AccountIdentityKeysV1::derive(&bob_master).unwrap();
    let alice_me = json_response(
        c.get(format!("{a}/api/user/me"))
            .bearer_auth(alice_token)
            .send()
            .unwrap(),
        "get Drive collection owner",
    );
    let owner_user_id = alice_me["id"].as_str().unwrap();
    let collection_id = uuid::Uuid::new_v4().to_string();
    let collection_key = [0x45; 32];
    let owner_key_context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::CollectionKey,
        1,
        1,
        &collection_id,
        owner_user_id,
    )
    .unwrap();
    let name_context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::CollectionName,
        1,
        1,
        &collection_id,
        owner_user_id,
    )
    .unwrap();
    let owner_key_envelope =
        drive_envelope::seal_b64(&collection_key, &alice_master, owner_key_context).unwrap();
    let name_envelope =
        drive_envelope::seal_b64(b"Federated V2 collection", &collection_key, name_context)
            .unwrap();
    let epoch_statement = CollectionEpochStatementV1::create(
        &collection_id,
        owner_user_id,
        1,
        None,
        &collection_key,
        alice_identity.authority_signing_key(),
    )
    .unwrap();
    let epoch_statement_hash = epoch_statement.statement_hash();
    let created = json_response(
        c.post(format!("{a}/api/collections"))
            .bearer_auth(alice_token)
            .json(&json!({
                "id": collection_id,
                "nameEnvelope": name_envelope,
                "ownerKeyEnvelope": owner_key_envelope,
                "epochStatement": epoch_statement.encode_b64()
            }))
            .send()
            .unwrap(),
        "create Drive collection",
    );
    assert_eq!(created["id"], collection_id);
    let collection = json_response(
        c.get(format!("{a}/api/collections/{collection_id}"))
            .bearer_auth(alice_token)
            .send()
            .unwrap(),
        "read owned Drive collection",
    );
    assert_eq!(collection["keyEpoch"], 1);
    assert_eq!(collection["nameRevision"], 1);
    assert_eq!(collection["epochStatementHash"], epoch_statement_hash);
    assert_eq!(
        drive_envelope::open_b64(
            collection["ownerKeyEnvelope"].as_str().unwrap(),
            &alice_master,
            owner_key_context,
        )
        .unwrap(),
        collection_key
    );
    assert_eq!(
        drive_envelope::open_b64(
            collection["nameEnvelope"].as_str().unwrap(),
            &collection_key,
            name_context,
        )
        .unwrap(),
        b"Federated V2 collection"
    );

    // Public links reuse the same typed Drive envelope implementation while
    // keeping the random link key exclusively in the URL fragment.
    let link_key = [0x4c; 32];
    let public_link_context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::PublicLinkCollectionKey,
        1,
        1,
        &collection_id,
        owner_user_id,
    )
    .unwrap();
    let public_link_envelope =
        drive_envelope::seal_b64(&collection_key, &link_key, public_link_context).unwrap();
    let public_link = json_response(
        c.post(format!("{a}/api/share/"))
            .bearer_auth(alice_token)
            .json(&json!({
                "shareType": "collection",
                "targetId": collection_id,
                "collectionKeyEnvelope": public_link_envelope,
            }))
            .send()
            .unwrap(),
        "create public Drive share",
    );
    let public_link_token = public_link["token"].as_str().unwrap();
    let public_link_record = json_response(
        c.get(format!("{a}/api/share/{public_link_token}"))
            .send()
            .unwrap(),
        "read public Drive share",
    );
    assert_eq!(public_link_record["targetId"], collection_id);
    assert_eq!(public_link_record["ownerUserId"], owner_user_id);
    assert_eq!(public_link_record["collectionKeyEpoch"], 1);
    assert_eq!(
        drive_envelope::open_b64(
            public_link_record["collectionKeyEnvelope"]
                .as_str()
                .unwrap(),
            &link_key,
            public_link_context,
        )
        .unwrap(),
        collection_key
    );
    let stale_public_envelope = drive_envelope::seal_b64(
        &collection_key,
        &link_key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::PublicLinkCollectionKey,
            2,
            1,
            &collection_id,
            owner_user_id,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        c.post(format!("{a}/api/share/"))
            .bearer_auth(alice_token)
            .json(&json!({
                "shareType": "collection",
                "targetId": collection_id,
                "collectionKeyEnvelope": stale_public_envelope,
            }))
            .send()
            .unwrap()
            .status()
            .as_u16(),
        400
    );

    let remote_user = json_response(
        drive_remote_user(c, a, alice_token),
        "signed Drive remote user lookup",
    );
    assert_eq!(remote_user["username"], BOB_USERNAME);
    assert_eq!(remote_user["server"], "b.test");
    assert_eq!(remote_user["account"], "bobfed@b.test");
    assert_eq!(
        remote_user["driveHpkePublicKey"],
        b64(&bob_identity.drive_hpke_public_key())
    );
    assert_eq!(
        remote_user["driveSigningPublicKey"],
        b64(&bob_identity.drive_signing_public_key())
    );
    assert_eq!(
        remote_user["accountAuthorityPublicKey"],
        b64(&bob_identity.authority_public_key())
    );
    assert_eq!(
        remote_user["accountIncarnationId"],
        bob_identity.incarnation_id()
    );
    let recipient_hpke = STANDARD
        .decode(remote_user["driveHpkePublicKey"].as_str().unwrap())
        .unwrap();
    let named_share = NamedShareEnvelopeV1::seal(
        &collection_key,
        &collection_id,
        1,
        "alicefed@a.test",
        &alice_identity.incarnation_id(),
        alice_identity.drive_signing_key(),
        remote_user["account"].as_str().unwrap(),
        remote_user["accountIncarnationId"].as_str().unwrap(),
        &recipient_hpke,
    )
    .unwrap()
    .encode_b64()
    .unwrap();

    let share = json_response(
        c.post(format!(
            "{a}/api/collections/{collection_id}/federated-shares"
        ))
        .bearer_auth(alice_token)
        .json(&json!({
            "recipientUsername": BOB_USERNAME,
            "recipientServer": "b.test",
            "namedShareEnvelope": named_share,
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
    assert_eq!(incoming[0]["remoteCollectionId"], collection_id);
    assert_eq!(incoming[0]["epochStatementHash"], epoch_statement_hash);
    let accepted_share =
        NamedShareEnvelopeV1::decode_b64(incoming[0]["namedShareEnvelope"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        accepted_share
            .open(
                &collection_id,
                1,
                "alicefed@a.test",
                &alice_identity.incarnation_id(),
                &alice_identity.drive_signing_public_key(),
                "bobfed@b.test",
                &bob_identity.incarnation_id(),
                bob_identity.drive_hpke_private_key(),
            )
            .unwrap(),
        collection_key
    );
    let accepted_epoch =
        CollectionEpochStatementV1::decode_b64(incoming[0]["epochStatement"].as_str().unwrap())
            .unwrap();
    accepted_epoch
        .verify_authority(&alice_identity.authority_public_key())
        .unwrap();
    accepted_epoch
        .verify_current_binding(&collection_id, owner_user_id, 1)
        .unwrap();
    accepted_epoch
        .verify_collection_key(&collection_key)
        .unwrap();
    assert_eq!(accepted_epoch.statement_hash(), epoch_statement_hash);
    assert_eq!(
        drive_envelope::open_b64(
            incoming[0]["nameEnvelope"].as_str().unwrap(),
            &collection_key,
            DriveEnvelopeContextV1::new(
                DriveEnvelopePurpose::CollectionName,
                1,
                1,
                &collection_id,
                owner_user_id,
            )
            .unwrap(),
        )
        .unwrap(),
        b"Federated V2 collection"
    );

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
    let plaintext = b"phase-d-encrypted-drive-object";
    let proposed_file_id = uuid::Uuid::new_v4().to_string();
    let file_key = [0x46; 32];
    let file_key_envelope = drive_envelope::seal_b64(
        &file_key,
        &collection_key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileKey,
            1,
            1,
            &proposed_file_id,
            &collection_id,
        )
        .unwrap(),
    )
    .unwrap();
    let metadata_plaintext = br#"{"name":"federated.txt","mimeType":"text/plain","size":31}"#;
    let metadata_envelope = drive_envelope::seal_b64(
        metadata_plaintext,
        &file_key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileMetadata,
            1,
            1,
            &proposed_file_id,
            &collection_id,
        )
        .unwrap(),
    )
    .unwrap();
    let ciphertext = drive_object::encrypt_file_blob(
        plaintext,
        &file_key,
        DriveFileBlobContextV1::new(&proposed_file_id, &collection_id, 1).unwrap(),
    )
    .unwrap();
    let upload_body = drive_upload_body(
        boundary,
        &proposed_file_id,
        &metadata_envelope,
        &file_key_envelope,
        &ciphertext,
    );
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
    let relocated = drive_upload_body(
        boundary,
        &uuid::Uuid::new_v4().to_string(),
        &metadata_envelope,
        &file_key_envelope,
        &ciphertext,
    );
    assert_eq!(upload(relocated).status().as_u16(), 400);
    let blob_relocation_id = uuid::Uuid::new_v4().to_string();
    let blob_relocation_file_key = drive_envelope::seal_b64(
        &file_key,
        &collection_key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileKey,
            1,
            1,
            &blob_relocation_id,
            &collection_id,
        )
        .unwrap(),
    )
    .unwrap();
    let blob_relocation_metadata = drive_envelope::seal_b64(
        metadata_plaintext,
        &file_key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::FileMetadata,
            1,
            1,
            &blob_relocation_id,
            &collection_id,
        )
        .unwrap(),
    )
    .unwrap();
    let relocated_blob = drive_upload_body(
        boundary,
        &blob_relocation_id,
        &blob_relocation_metadata,
        &blob_relocation_file_key,
        &ciphertext,
    );
    assert_eq!(upload(relocated_blob).status().as_u16(), 400);
    let first_upload = json_response(upload(upload_body.clone()), "federated Drive upload");
    let retried_upload = json_response(upload(upload_body), "idempotent Drive upload retry");
    assert_eq!(first_upload["id"], retried_upload["id"]);
    let file_id = first_upload["id"].as_str().unwrap();
    assert_eq!(file_id, proposed_file_id);

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
    assert_eq!(files[0]["metadataEnvelope"], metadata_envelope);
    assert_eq!(files[0]["fileKeyEnvelope"], file_key_envelope);
    assert_eq!(files[0]["keyEpoch"], 1);
    assert_eq!(files[0]["metadataRevision"], 1);
    assert_eq!(
        drive_envelope::open_b64(
            files[0]["fileKeyEnvelope"].as_str().unwrap(),
            &collection_key,
            DriveEnvelopeContextV1::new(
                DriveEnvelopePurpose::FileKey,
                1,
                1,
                file_id,
                &collection_id,
            )
            .unwrap(),
        )
        .unwrap(),
        file_key,
    );
    assert_eq!(
        drive_envelope::open_b64(
            files[0]["metadataEnvelope"].as_str().unwrap(),
            &file_key,
            DriveEnvelopeContextV1::new(
                DriveEnvelopePurpose::FileMetadata,
                1,
                1,
                file_id,
                &collection_id,
            )
            .unwrap(),
        )
        .unwrap(),
        metadata_plaintext,
    );

    let download = c
        .get(format!(
            "{b}/api/drive/federation/shares/{incoming_id}/files/{file_id}/content"
        ))
        .bearer_auth(bob_token)
        .send()
        .unwrap();
    assert_eq!(download.status().as_u16(), 200);
    assert_eq!(download.bytes().unwrap().as_ref(), ciphertext.as_slice());

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
            "namedShareEnvelope": "not-reached-because-the-domain-is-invalid",
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
    for (base, admin, domain) in [(a, &admin_a, "a.test"), (b, &admin_b, "b.test")] {
        let settings = json_response(
            c.get(format!("{base}/api/auth/settings")).send().unwrap(),
            "advertised MLS browser capability",
        );
        assert_eq!(settings["chat"]["mlsGroups"], true);
        let status = json_response(
            c.get(format!("{base}/api/admin/chat/mls/status"))
                .bearer_auth(admin)
                .send()
                .unwrap(),
            "advertised MLS administrative status",
        );
        assert_eq!(status["enabled"], true);
        assert_eq!(status["advertised"], true);
        assert_eq!(status["policy"]["canonicalDomain"], domain);
    }
    update_feature_mode(c, a, &admin_a, "drive", "open");
    update_feature_mode(c, b, &admin_b, "drive", "open");

    let (alice_token, _alice_drive_public) = register_account(c, a, ALICE_EMAIL, ALICE_USERNAME);
    let (bob_token, bob_drive_public) = register_account(c, b, BOB_EMAIL, BOB_USERNAME);
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
    let bob_identity = AccountIdentityKeysV1::derive(&test_master_key(BOB_EMAIL)).unwrap();
    let bob_manifest_v1 = publish_manifest(
        c,
        b,
        &bob_token,
        &bob_identity,
        "bobfed@b.test",
        &bob_drive_public,
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
    assert_eq!(disabled_capabilities["chat"]["mlsGroups"], false);
    let disabled_mls_status = json_response(
        c.get(format!("{a}/api/admin/chat/mls/status"))
            .bearer_auth(&admin_a)
            .send()
            .unwrap(),
        "disabled MLS administrative status",
    );
    assert_eq!(disabled_mls_status["enabled"], true);
    assert_eq!(disabled_mls_status["advertised"], false);
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
    let reenabled_capabilities = json_response(
        c.get(format!("{a}/api/auth/settings")).send().unwrap(),
        "re-enabled MLS browser capability",
    );
    assert_eq!(reenabled_capabilities["chat"]["mlsGroups"], true);
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
    assert_eq!(
        typed_first.manifest.as_ref().unwrap().account,
        remote_address
    );

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
        &bob_identity,
        "bobfed@b.test",
        &bob_drive_public,
        2,
        Some(bob_manifest_v1.manifest_hash().unwrap()),
        vec![
            manifest_device(1, BOB_REGISTRATION_ID_1, 20),
            manifest_device(2, BOB_REGISTRATION_ID_2, 30),
        ],
    );
    let refreshed_bundles = json_response(
        c.get(format!("{a}/api/chat/users/{remote_address}/keys"))
            .bearer_auth(&alice_token)
            .send()
            .unwrap(),
        "remote bundle manifest refresh",
    );
    let typed_refreshed: UserPreKeyBundlesResponse =
        serde_json::from_value(refreshed_bundles).unwrap();
    assert_eq!(typed_refreshed.manifest.as_ref(), Some(&bob_manifest_v2));

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
            &bob_identity,
            "bobfed@b.test",
            &bob_drive_public,
            version,
            Some(latest_manifest.manifest_hash().unwrap()),
            bob_devices.clone(),
        );
    }
    let history_url = format!("{a}/api/chat/users/{remote_address}/manifest-history");
    let first_page: AccountManifestHistoryPageV1 = serde_json::from_value(json_response(
        c.get(&history_url)
            .bearer_auth(&alice_token)
            .query(&[
                ("fromSequence", "1"),
                ("toSequence", "66"),
                ("pageFromSequence", "1"),
            ])
            .send()
            .unwrap(),
        "first federated manifest-history page",
    ))
    .unwrap();
    assert_eq!(first_page.manifests.len(), 64);
    first_page.validate().unwrap();
    assert_eq!(first_page.next_sequence, Some(65));
    let second_page: AccountManifestHistoryPageV1 = serde_json::from_value(json_response(
        c.get(&history_url)
            .bearer_auth(&alice_token)
            .query(&[
                ("fromSequence", "1"),
                ("toSequence", "66"),
                ("pageFromSequence", "65"),
            ])
            .send()
            .unwrap(),
        "second federated manifest-history page",
    ))
    .unwrap();
    assert_eq!(second_page.manifests.len(), 2);
    assert_eq!(*second_page.manifests.last().unwrap(), latest_manifest);
    assert!(second_page.next_sequence.is_none());
    second_page.validate().unwrap();

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

/// Minimal control-plane bootstrap for focused browser debugging. The complete
/// `setup` phase remains the release gate; this phase avoids replaying its
/// manifest-range and Drive scenarios when iterating on Playwright failures.
fn browser_setup_phase(c: &Client, a: &str, b: &str) {
    let admin_a = setup_admin(c, a, ADMIN_A_EMAIL, "admina");
    let admin_b = setup_admin(c, b, ADMIN_B_EMAIL, "adminb");
    update_federation_mode(c, a, &admin_a, "open");
    update_federation_mode(c, b, &admin_b, "open");
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
        "browser-setup" => browser_setup_phase(&c, &a, &b),
        "queue" => queue_phase(&c, &a),
        "verify-retry" => verify_retry_phase(&c, &a, &b),
        _ => panic!("unknown KUTUP_FEDERATION_PHASE: {phase}"),
    }
}
