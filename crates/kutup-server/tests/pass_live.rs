//! Live e2e for Kutup Pass vault secrets (docs/plans/pass.md, "Vault
//! secrets").
//!
//! Each person keeps, per vault they can open, the vault's key sealed under
//! their master key. The server checks the envelope is that account's vault
//! secret and that the vault is theirs to open; a trashed vault's secret is
//! kept but unlisted, and a purged vault takes its secrets with it.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test pass_live -- --nocapture

use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::pass_vault::{open_vault_secret, seal_vault_secret, VaultSecretV1};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use zeroize::Zeroizing;

mod common;
use common::*;

fn secret(password: &str) -> VaultSecretV1 {
    VaultSecretV1 {
        password: Some(Zeroizing::new(password.to_owned())),
        key_file: None,
    }
}

fn sealed_for(user: &User, file_id: &str, password: &str) -> String {
    let id = uuid::Uuid::parse_str(file_id).unwrap();
    b64(&seal_vault_secret(
        &user.master_key,
        &user.email,
        id.as_bytes(),
        &secret(password),
    )
    .unwrap())
}

fn put(c: &Client, base: &str, user: &User, file_id: &str, envelope: &str) -> StatusCode {
    bearer(
        c.put(format!("{base}/api/pass/vault-secrets/{file_id}")),
        &user.token,
    )
    .json(&json!({ "envelope": envelope }))
    .send()
    .unwrap()
    .status()
}

fn list(c: &Client, base: &str, user: &User) -> Vec<Value> {
    let r = bearer(c.get(format!("{base}/api/pass/vault-secrets")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().unwrap()
}

#[test]
fn vault_secrets() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let owner = register(&c, &base);
    let member = register(&c, &base);
    let stranger = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &member, true);
    let vault = seal_file(&folder, &uuid(), b"a KeePass file");
    assert!(upload(&c, &base, &owner.token, &folder, &vault)
        .status()
        .is_success());

    // Each person keeps their own; nobody sees another's.
    assert_eq!(list(&c, &base, &owner), Vec::<Value>::new());
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &vault.id,
            &sealed_for(&owner, &vault.id, "o")
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(
            &c,
            &base,
            &member,
            &vault.id,
            &sealed_for(&member, &vault.id, "m")
        ),
        StatusCode::NO_CONTENT
    );
    let mine = list(&c, &base, &owner);
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0]["fileId"], vault.id.as_str());
    let envelope =
        account_envelope::decode_canonical_b64(mine[0]["envelope"].as_str().unwrap()).unwrap();
    let id = uuid::Uuid::parse_str(&vault.id).unwrap();
    let opened =
        open_vault_secret(&envelope, &owner.master_key, &owner.email, id.as_bytes()).unwrap();
    assert_eq!(opened.password.unwrap().as_str(), "o");
    assert_eq!(list(&c, &base, &member).len(), 1);

    // Replacing one keeps one.
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &vault.id,
            &sealed_for(&owner, &vault.id, "o2")
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(list(&c, &base, &owner).len(), 1);

    // Refused: someone who cannot open the vault; another account's
    // envelope; an envelope of another purpose; not base64.
    assert_eq!(
        put(
            &c,
            &base,
            &stranger,
            &vault.id,
            &sealed_for(&stranger, &vault.id, "s")
        ),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &vault.id,
            &sealed_for(&member, &vault.id, "x")
        ),
        StatusCode::BAD_REQUEST
    );
    let other_purpose = account_envelope::seal_b64(
        b"x",
        &owner.master_key,
        AccountEnvelopePurpose::ChatBackupRoot,
        &owner.email,
    )
    .unwrap();
    assert_eq!(
        put(&c, &base, &owner, &vault.id, &other_purpose),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(&c, &base, &owner, &vault.id, "not base64!"),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &uuid(),
            &sealed_for(&owner, &vault.id, "o")
        ),
        StatusCode::NOT_FOUND
    );

    // Forgetting one leaves the other person's.
    let forgot = bearer(
        c.delete(format!("{base}/api/pass/vault-secrets/{}", vault.id)),
        &member.token,
    )
    .send()
    .unwrap();
    assert_eq!(forgot.status(), StatusCode::NO_CONTENT);
    assert_eq!(list(&c, &base, &member).len(), 0);
    assert_eq!(list(&c, &base, &owner).len(), 1);

    // In the trash: kept, unlisted; restored: listed again.
    let trashed = bearer(
        c.delete(format!("{base}/api/files/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(trashed.status().is_success(), "trash: {}", trashed.status());
    assert_eq!(list(&c, &base, &owner).len(), 0);
    let restored = bearer(
        c.post(format!("{base}/api/trash/{}/restore", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(
        restored.status().is_success(),
        "restore: {}",
        restored.status()
    );
    assert_eq!(list(&c, &base, &owner).len(), 1);

    // Purged: its secrets go with it.
    bearer(
        c.delete(format!("{base}/api/files/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    let purged = bearer(
        c.delete(format!("{base}/api/trash/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(purged.status(), StatusCode::NO_CONTENT);
    bearer(
        c.post(format!("{base}/api/trash/{}/restore", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(list(&c, &base, &owner).len(), 0);
}
