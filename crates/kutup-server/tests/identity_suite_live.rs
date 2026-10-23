//! The one-way identity suite upgrade (docs/plans/pq-shares.md) against a
//! live server: an account still on suite 1 (an X25519 Drive key) is shown
//! as such and refused shares (`keysPendingUpgrade`) until it moves to suite
//! 2 with a binding its own authority signed; the move happens once.
//!
//! Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_DATABASE_URL` (an account is set
//! back to suite 1 in the database, as one from before X-Wing).

mod common;

use common::chat_identity::ChatAccount;
use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn identity_of(c: &reqwest::blocking::Client, base: &str, asker: &User, who: &User) -> Value {
    let found: Value = bearer(
        c.post(format!("{base}/api/users/drive-identities")),
        &asker.token,
    )
    .json(&json!({ "accounts": [who.account] }))
    .send()
    .unwrap()
    .json()
    .unwrap();
    found[0].clone()
}

#[test]
fn a_suite_1_account_upgrades_once_and_is_shared_with_only_after() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let bob_id: uuid::Uuid = bob.id.parse().unwrap();

    // Bob as an account from before X-Wing: suite 1, a 32-byte key.
    let envelope: String = runtime
        .block_on(
            sqlx::query_scalar("SELECT drive_private_key_envelope FROM users WHERE id = $1")
                .bind(bob_id)
                .fetch_one(&pool),
        )
        .unwrap();
    runtime
        .block_on(
            sqlx::query("UPDATE users SET identity_suite = 1, public_key = $2 WHERE id = $1")
                .bind(bob_id)
                .bind(b64(&[7u8; 32]))
                .execute(&pool),
        )
        .unwrap();
    assert_eq!(identity_of(&c, &base, &alice, &bob)["identitySuite"], 1);

    // Nothing is shared to him meanwhile.
    let folder = create_folder(&c, &base, &alice);
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/share", folder.id)),
        &alice.token,
    )
    .json(&json!({
        "recipientUserId": bob.id,
        "namedShareEnvelope": "AAAA",
        "canUpload": false,
        "canDelete": false,
        "uploadQuotaBytes": null,
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "keysPendingUpgrade");

    let upgrade = |user: &User, binding: [u8; 64]| {
        bearer(
            c.post(format!("{base}/api/account/identity-suite")),
            &user.token,
        )
        .json(&json!({
            "publicKey": b64(&bob.identity.drive_hpke_public_key()),
            "driveKeyBinding": b64(&binding),
            "driveKeyBindingEpoch": 1,
            "drivePrivateKeyEnvelope": envelope,
        }))
        .send()
        .unwrap()
    };
    // Someone else's authority can't vouch for Bob's keys.
    let mallory = kutup_crypto::identity::AccountIdentityKeysV1::derive(&[9u8; 32]).unwrap();
    let forged = kutup_crypto::drive_key_binding::sign(&mallory, &bob.person, 1).unwrap();
    assert_eq!(upgrade(&bob, forged).status(), StatusCode::BAD_REQUEST);

    // His own binding: upgraded, once.
    let binding = kutup_crypto::drive_key_binding::sign(&bob.identity, &bob.person, 1).unwrap();
    assert_eq!(upgrade(&bob, binding).status(), StatusCode::NO_CONTENT);
    let again = upgrade(&bob, binding);
    assert_eq!(again.status(), StatusCode::CONFLICT);
    assert_eq!(
        again.json::<Value>().unwrap()["code"],
        "identitySuiteCurrent"
    );
    let found = identity_of(&c, &base, &alice, &bob);
    assert_eq!(found["identitySuite"], 2);
    assert_eq!(found["driveKeyBindingEpoch"], 1);
    assert_eq!(
        found["driveHpkePublicKey"],
        b64(&bob.identity.drive_hpke_public_key())
    );

    // Now shared with as anyone.
    share(&c, &base, &alice, &folder, &bob, false);
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// What an account had before X-Wing (identity suite 1), made from its master
/// key the way clients made it then: the X25519 Drive key, its v1 binding,
/// the sealed private key, and every Chat manifest it published re-signed by
/// its own authority as suite 1. Nothing here is a shortcut the upgrade could
/// tell from a real old account.
mod legacy_suite1 {
    use super::*;
    use ed25519_dalek::Signer as _;
    use hkdf::Hkdf;
    use kutup_chat_proto::{AccountIdentitySuiteId, AccountManifestV2};
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    use kutup_crypto::account_ref::AccountRef;
    use kutup_crypto::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};
    use sha2::Sha256;

    /// The suite-1 Drive key pair: HKDF as `AccountIdentityKeysV1` did, then
    /// libsodium's `crypto_box_seed_keypair`.
    pub fn drive_keys(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hkdf = Hkdf::<Sha256>::new(Some(b"kutup/account-identity/v1\0"), master_key);
        let mut seed = [0u8; 32];
        hkdf.expand(b"kutup/account-identity/drive-hpke-x25519/v1\0", &mut seed)
            .unwrap();
        let (public, secret) = dryoc::classic::crypto_box::crypto_box_seed_keypair(&seed);
        (public, secret)
    }

    /// The v1 Drive key binding (no epoch), signed by the account's authority.
    pub fn binding(
        identity: &AccountIdentityKeysV1,
        account: &AccountRef,
        drive: &[u8; 32],
    ) -> [u8; 64] {
        let authority = identity.authority_public_key();
        let mut bytes = b"kutup/drive-key-binding/v1\0".to_vec();
        bytes.extend_from_slice(&account.bytes());
        bytes.extend_from_slice(
            &hex::decode(incarnation_id_from_authority_public(&authority)).unwrap(),
        );
        bytes.extend_from_slice(&authority);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(drive);
        bytes.extend_from_slice(&identity.drive_signing_public_key());
        identity.authority_signing_key().sign(&bytes).to_bytes()
    }

    /// Turns the account `user_id` into a suite-1 account in one transaction.
    pub async fn make(
        pool: &sqlx::PgPool,
        user_id: uuid::Uuid,
        master_key: &[u8; 32],
        account: &AccountRef,
    ) {
        let identity = AccountIdentityKeysV1::derive(master_key).unwrap();
        let (drive_public, drive_secret) = drive_keys(master_key);
        let mut tx = pool.begin().await.unwrap();
        let key_binding: String = sqlx::query_scalar("SELECT key_binding FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let envelope = account_envelope::seal_b64(
            &drive_secret,
            master_key,
            AccountEnvelopePurpose::DriveHpkePrivateKey,
            &key_binding,
        )
        .unwrap();
        sqlx::query(
            "UPDATE users SET identity_suite = 1, public_key = $2, drive_key_binding = $3,
                    drive_key_binding_epoch = 1, drive_private_key_envelope = $4
              WHERE id = $1",
        )
        .bind(user_id)
        .bind(b64(&drive_public))
        .bind(b64(&binding(&identity, account, &drive_public)))
        .bind(&envelope)
        .execute(&mut *tx)
        .await
        .unwrap();

        // Every manifest, oldest first, re-signed as suite 1 and re-linked.
        let history: Vec<(i64, serde_json::Value)> = sqlx::query_as(
            "SELECT version, manifest FROM chat_device_manifest_history
              WHERE user_id = $1 ORDER BY version",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        let mut previous: Option<String> = None;
        let mut last: Option<(i64, AccountManifestV2, String)> = None;
        for (version, value) in history {
            let mut manifest: AccountManifestV2 = serde_json::from_value(value).unwrap();
            manifest.drive.suite = AccountIdentitySuiteId::X25519Ed25519V1;
            manifest.drive.hpke_public_key = b64(&drive_public);
            if manifest.sequence > 1 {
                manifest.previous_hash = previous.clone();
            }
            manifest.signature = b64(&identity
                .authority_signing_key()
                .sign(&manifest.signing_bytes().unwrap())
                .to_bytes());
            manifest.verify().expect("a suite-1 manifest verifies");
            let hash = manifest.manifest_hash().unwrap();
            sqlx::query(
                "UPDATE chat_device_manifest_history SET manifest = $3, manifest_hash = $4
                  WHERE user_id = $1 AND version = $2",
            )
            .bind(user_id)
            .bind(version)
            .bind(serde_json::to_value(&manifest).unwrap())
            .bind(&hash)
            .execute(&mut *tx)
            .await
            .unwrap();
            previous = Some(hash.clone());
            last = Some((version, manifest, hash));
        }
        if let Some((version, manifest, hash)) = last {
            sqlx::query(
                "UPDATE chat_device_manifests SET manifest = $3, manifest_hash = $4
                  WHERE user_id = $1 AND version = $2",
            )
            .bind(user_id)
            .bind(version)
            .bind(serde_json::to_value(&manifest).unwrap())
            .bind(&hash)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }
}

/// Not a test: makes an existing account a suite-1 one, for the browser spec
/// (162) and the backup gate's CLI step. Signs in with the account's
/// password to open its master key. Needs `KUTUP_SUITE1_SERVER`,
/// `KUTUP_SUITE1_DATABASE_URL`, `KUTUP_SUITE1_USERNAME` and
/// `KUTUP_SUITE1_PASSWORD`:
/// `cargo test -p kutup-server --test identity_suite_live make_a_suite_1_account -- --ignored --exact`.
#[test]
#[ignore = "a tool: makes the named account a suite-1 account"]
fn make_a_suite_1_account() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    let base = var("KUTUP_SUITE1_SERVER").trim_end_matches('/').to_string();
    let (username, password) = (var("KUTUP_SUITE1_USERNAME"), var("KUTUP_SUITE1_PASSWORD"));
    let c = crate::common::client();
    let (status, session, export_key) =
        common::opaque_login(&c, &base, &username, &password, "session", None, None);
    assert_eq!(status, StatusCode::OK, "sign-in: {session}");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&var("KUTUP_SUITE1_DATABASE_URL")))
        .unwrap();
    let (user_id, key_binding, account_id): (uuid::Uuid, String, uuid::Uuid) = runtime
        .block_on(
            sqlx::query_as("SELECT id, key_binding, id FROM users WHERE username = $1")
                .bind(&username)
                .fetch_one(&pool),
        )
        .unwrap();
    let master = export_key
        .unwrap()
        .open_master_key(session["masterKeyEnvelope"].as_str().unwrap(), &key_binding)
        .unwrap();
    let account = kutup_crypto::account_ref::AccountRef::new(
        &common::server_domain(&c, &base),
        &account_id.to_string(),
    )
    .unwrap();
    runtime.block_on(legacy_suite1::make(&pool, user_id, &master, &account));
    eprintln!("{username} is a suite-1 account now");
}

/// An account from before X-Wing with Chat (a suite-1 Drive key and suite-1
/// manifests, made as clients made them) upgrades, and its next manifest
/// raises the Drive key: the server takes it (and nothing else), so Chat
/// keeps working. Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_DATABASE_URL`.
#[test]
fn a_suite_1_account_with_chat_manifests_publishes_its_next_one_after_the_upgrade() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let bob = register(&c, &base);
    let mut chat = ChatAccount::of(&bob, &bob.token);
    // Manifest 1 with the re-registration, then 2.
    let device = chat.reregister(&c, &base);
    chat.publish(&c, &base, &device);
    let publish = |chat: &ChatAccount, manifest: &kutup_chat_proto::AccountManifestV2| {
        chat.post_manifest(&c, &base, &device, manifest)
    };

    // Bob as he was before X-Wing: both manifests suite 1.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let bob_id: uuid::Uuid = bob.id.parse().unwrap();
    runtime.block_on(legacy_suite1::make(
        &pool,
        bob_id,
        &bob.master_key,
        &bob.person,
    ));
    let stored: (i64, String, Value) = runtime
        .block_on(
            sqlx::query_as(
                "SELECT version, manifest_hash, manifest FROM chat_device_manifests WHERE user_id = $1",
            )
            .bind(bob_id)
            .fetch_one(&pool),
        )
        .unwrap();
    assert_eq!(stored.0, 2);
    assert_eq!(stored.2["drive"]["suite"], 1);

    // Before the upgrade his X-Wing manifest is refused: not his key yet.
    chat.head = Some(serde_json::from_value(stored.2.clone()).unwrap());
    assert_eq!(
        chat.head.as_ref().unwrap().manifest_hash().unwrap(),
        stored.1
    );
    let early = chat.next_manifest(&[&device]);
    assert_eq!(publish(&chat, &early).status(), StatusCode::CONFLICT);

    // The upgrade takes epoch 1 only.
    let upgrade = |epoch: u32| {
        let binding =
            kutup_crypto::drive_key_binding::sign(&bob.identity, &bob.person, epoch.max(1))
                .unwrap();
        let envelope: String = runtime
            .block_on(
                sqlx::query_scalar("SELECT drive_private_key_envelope FROM users WHERE id = $1")
                    .bind(bob_id)
                    .fetch_one(&pool),
            )
            .unwrap();
        bearer(
            c.post(format!("{base}/api/account/identity-suite")),
            &bob.token,
        )
        .json(&json!({
            "publicKey": b64(&bob.identity.drive_hpke_public_key()),
            "driveKeyBinding": b64(&binding),
            "driveKeyBindingEpoch": epoch,
            "drivePrivateKeyEnvelope": envelope,
        }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(upgrade(2), StatusCode::BAD_REQUEST);
    assert_eq!(upgrade(u32::MAX), StatusCode::BAD_REQUEST);
    assert_eq!(upgrade(1), StatusCode::NO_CONTENT);

    // Now the next manifest raises the key, linked to the suite-1 one.
    assert_eq!(publish(&chat, &early).status(), StatusCode::OK, "the rise");
    chat.head = Some(early);
    // Not back, and no other key.
    let mut back = chat.next_manifest(&[&device]);
    back.drive.suite = kutup_chat_proto::AccountIdentitySuiteId::X25519Ed25519V1;
    back.drive.hpke_public_key = b64(&legacy_suite1::drive_keys(&bob.master_key).0);
    chat.sign(&mut back);
    back.verify().unwrap();
    assert_eq!(publish(&chat, &back).status(), StatusCode::CONFLICT);
    let same = chat.next_manifest(&[&device]);
    assert_eq!(publish(&chat, &same).status(), StatusCode::OK);
    purge_accounts(&c, &base, &[&bob]);
}
