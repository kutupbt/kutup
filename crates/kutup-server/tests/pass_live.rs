//! Live e2e for Kutup Pass vault secrets (docs/plans/pass.md, "Vault
//! secrets").
//!
//! Each person keeps, per vault they can open, the vault's key sealed under
//! their master key. The server checks the envelope is that account's vault
//! secret and that the vault is theirs to open. Every secret is listed, as
//! the account head's index lists it, with what became of its vault: one in
//! the trash, out of reach or purged stays until its owner forgets it
//! (docs/plans/rollback-protection.md §9).
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test pass_live -- --nocapture

use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::pass_vault::{open_vault_secret, password_hash, seal_vault_secret, VaultSecret};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn secret(password: &str) -> VaultSecret {
    VaultSecret::chosen(Some(password), None)
}

/// A revision above every one sealed before in this test.
fn next_revision() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(1_791_633_600_000);
    LAST.fetch_add(1, Ordering::SeqCst) + 1
}

fn sealed_for(user: &User, file_id: &str, password: &str) -> String {
    let id = uuid::Uuid::parse_str(file_id).unwrap();
    b64(&seal_vault_secret(
        &user.master_key,
        &user.binding,
        id.as_bytes(),
        next_revision(),
        &secret(password),
    )
    .unwrap())
}

/// The revision of `user`'s secret for `file_id` now (0: none).
fn current_revision(c: &Client, base: &str, user: &User, file_id: &str) -> u64 {
    list(c, base, user)
        .iter()
        .find(|row| row["fileId"] == file_id)
        .map(|row| {
            let envelope =
                account_envelope::decode_canonical_b64(row["envelope"].as_str().unwrap()).unwrap();
            account_envelope::inspect(&envelope)
                .unwrap()
                .revision
                .unwrap()
        })
        .unwrap_or(0)
}

fn put_on(
    c: &Client,
    base: &str,
    user: &User,
    file_id: &str,
    envelope: &str,
    on: u64,
) -> reqwest::blocking::Response {
    bearer(
        c.put(format!("{base}/api/pass/vault-secrets/{file_id}")),
        &user.token,
    )
    .json(&json!({ "envelope": envelope, "baseRevision": on }))
    .send()
    .unwrap()
}

/// Keeps `envelope` on top of what `user` keeps now.
fn put(c: &Client, base: &str, user: &User, file_id: &str, envelope: &str) -> StatusCode {
    let on = current_revision(c, base, user, file_id);
    put_on(c, base, user, file_id, envelope, on).status()
}

/// Removes a file for good (trash, then purge): the gates check that a purged
/// account leaves nothing stored behind, so these tests leave nothing either.
fn purge_file(c: &Client, base: &str, user: &User, file_id: &str) {
    bearer(c.delete(format!("{base}/api/files/{file_id}")), &user.token)
        .send()
        .unwrap();
    let purged = bearer(c.delete(format!("{base}/api/trash/{file_id}")), &user.token)
        .send()
        .unwrap();
    assert_eq!(purged.status(), StatusCode::NO_CONTENT, "purge {file_id}");
}

fn list(c: &Client, base: &str, user: &User) -> Vec<Value> {
    let r = bearer(c.get(format!("{base}/api/pass/vault-secrets")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().unwrap()
}

/// Each listed secret's vault and what became of it.
fn states(c: &Client, base: &str, user: &User) -> Vec<(String, String)> {
    list(c, base, user)
        .into_iter()
        .map(|row| {
            (
                row["fileId"].as_str().unwrap().to_owned(),
                row["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn vault_secrets() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
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
    let (opened, _) =
        open_vault_secret(&envelope, &owner.master_key, &owner.binding, id.as_bytes()).unwrap();
    // Only the password's hash is kept.
    assert_eq!(opened.password_hash, Some(password_hash("o")));
    assert!(opened.generated_password.is_none());
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

    // Two devices keeping the first key of a vault at once: one is stored,
    // the other gets the 409, never a silent overwrite.
    let fresh = seal_file(&folder, &uuid(), b"another KeePass file");
    assert!(upload(&c, &base, &owner.token, &folder, &fresh)
        .status()
        .is_success());
    let envelopes: Vec<String> = (0..6)
        .map(|i| sealed_for(&owner, &fresh.id, &format!("first-{i}")))
        .collect();
    let statuses: Vec<StatusCode> = std::thread::scope(|scope| {
        let handles: Vec<_> = envelopes
            .iter()
            .map(|envelope| {
                let (c, base, owner, id) = (&c, &base, &owner, &fresh.id);
                scope.spawn(move || put_on(c, base, owner, id, envelope, 0).status())
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::NO_CONTENT)
            .count(),
        1,
        "{statuses:?}"
    );
    assert!(statuses
        .iter()
        .all(|s| *s == StatusCode::NO_CONTENT || *s == StatusCode::CONFLICT));
    // Removed again, its key listed as gone until forgotten: the rest of
    // this test counts the first vault's.
    purge_file(&c, &base, &owner, &fresh.id);
    assert!(states(&c, &base, &owner).contains(&(fresh.id.clone(), "gone".to_owned())));
    let forgot = bearer(
        c.delete(format!("{base}/api/pass/vault-secrets/{}", fresh.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(forgot.status(), StatusCode::NO_CONTENT);

    // Kept only on top of the key the change started from: a device that
    // read the first one does not overwrite the second, nor does an older
    // revision.
    let kept_now = current_revision(&c, &base, &owner, &vault.id);
    let late = put_on(
        &c,
        &base,
        &owner,
        &vault.id,
        &sealed_for(&owner, &vault.id, "o3"),
        0,
    );
    assert_eq!(late.status(), StatusCode::CONFLICT);
    let late: Value = late.json().unwrap();
    assert_eq!(late["code"], "revision_conflict");
    assert_eq!(late["revision"].as_u64(), Some(kept_now));
    let older = b64(&seal_vault_secret(
        &owner.master_key,
        &owner.binding,
        id.as_bytes(),
        kept_now,
        &secret("o4"),
    )
    .unwrap());
    assert_eq!(
        put_on(&c, &base, &owner, &vault.id, &older, kept_now).status(),
        StatusCode::BAD_REQUEST
    );

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
        &[1u8; 32],
        &owner.master_key,
        AccountEnvelopePurpose::ChatBackupRoot,
        &owner.binding,
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

    // In the trash: kept, listed as such (the head lists it); restored: open.
    let trashed = bearer(
        c.delete(format!("{base}/api/files/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(trashed.status().is_success(), "trash: {}", trashed.status());
    assert_eq!(
        states(&c, &base, &owner),
        vec![(vault.id.clone(), "trashed".to_owned())]
    );
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
    assert_eq!(
        states(&c, &base, &owner),
        vec![(vault.id.clone(), "open".to_owned())]
    );

    // Purged: its secret stays, listed as gone, until its owner forgets it.
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
    assert_eq!(
        states(&c, &base, &owner),
        vec![(vault.id.clone(), "gone".to_owned())]
    );
    let forgot = bearer(
        c.post(format!("{base}/api/pass/vault-secrets/forget")),
        &owner.token,
    )
    .json(&json!({ "fileIds": [vault.id] }))
    .send()
    .unwrap();
    assert_eq!(forgot.status(), StatusCode::NO_CONTENT);
    assert_eq!(list(&c, &base, &owner).len(), 0);
    // Nothing left stored by this test.
    assert_eq!(used(&c, &base, &owner.token), 0);
}

#[test]
fn reauth_checks_the_password_like_sign_in_with_its_lockout() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    // A reauth is a sign-in exchange (docs/plans/opaque.md) whose answer is a
    // one-time grant, not a session.
    let reauth = |password: &str, token: Option<&str>| {
        let (status, body, _) = opaque_login(
            &c,
            &base,
            &user.username,
            password,
            "reauth",
            Some("pass"),
            token,
        );
        (status, body)
    };
    let (status, body) = reauth(&user.password, Some(&user.token));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["grant"].as_str().unwrap().starts_with("kg1_"));
    assert!(
        body.get("accessToken").is_none(),
        "no session from a reauth"
    );
    // A wrong password fails in the client; the server never sees a finish.
    assert_eq!(
        reauth("not-the-password", Some(&user.token)).0,
        StatusCode::UNAUTHORIZED
    );
    // Signed out: refused.
    assert_eq!(reauth(&user.password, None).0, StatusCode::UNAUTHORIZED);
    // A reauth names no account (it is the session's own): naming one,
    // another account's or not, is refused.
    let other = register(&c, &base);
    let (_, ke1) = kutup_crypto::opaque::client_login_start(&other.password).unwrap();
    let named = bearer(c.post(format!("{base}/api/auth/login/start")), &user.token)
        .header("x-kutup-client", "cli")
        .json(
            &json!({ "name": other.username, "credentialRequest": b64(&ke1),
                       "purpose": "reauth", "for": "pass" }),
        )
        .send()
        .unwrap();
    assert_eq!(named.status(), StatusCode::BAD_REQUEST);
    // The sign-in lockout (LOGIN_LOCKOUT_THRESHOLD, 5 by default): every
    // start counts, finished or not, and then even the right password waits.
    let mut locked = false;
    for _ in 0..10 {
        if reauth("not-the-password", Some(&user.token)).0 == StatusCode::TOO_MANY_REQUESTS {
            locked = true;
            break;
        }
    }
    assert!(locked, "the lockout never came");
    assert_eq!(
        reauth(&user.password, Some(&user.token)).0,
        StatusCode::TOO_MANY_REQUESTS
    );
    purge_accounts(&c, &base, &[&user, &other]);
}

#[test]
fn pin_is_set_with_a_fresh_grant_and_three_misses_end_the_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let status = || -> Value {
        bearer(c.get(format!("{base}/api/pass/pin")), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let set = |grant: &str, pin: &str| {
        let response = bearer(c.put(format!("{base}/api/pass/pin")), &user.token)
            .json(&json!({ "grant": grant, "pin": pin }))
            .send()
            .unwrap();
        let code = response.status();
        (code, response.json::<Value>().unwrap_or(Value::Null))
    };
    let verify = |pin: &str| {
        let response = bearer(c.post(format!("{base}/api/pass/pin/verify")), &user.token)
            .json(&json!({ "pin": pin }))
            .send()
            .unwrap();
        let code = response.status();
        let body: Value = response.json().unwrap_or(Value::Null);
        (code, body)
    };

    assert_eq!(status()["set"], false);
    assert_eq!(verify("123456").1["error"], "noPin");
    // Six digits (checked first: no grant spent on a typo).
    let grant = reauth_grant(&c, &base, &user, "pass");
    assert_eq!(set(&grant, "12345").0, StatusCode::BAD_REQUEST);
    assert_eq!(set(&grant, "12345a").0, StatusCode::BAD_REQUEST);
    // A grant for something else, or none: refused.
    let totp = reauth_grant(&c, &base, &user, "totp");
    let (code, body) = set(&totp, "246802");
    assert_eq!(
        (code, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("grantInvalid"))
    );
    assert_eq!(set("kg1_not-a-grant", "246802").0, StatusCode::FORBIDDEN);
    assert_eq!(set(&grant, "246802").0, StatusCode::NO_CONTENT);
    // Used once.
    assert_eq!(set(&grant, "246802").0, StatusCode::FORBIDDEN);
    assert_eq!(status()["set"], true);

    assert_eq!(verify("246802").0, StatusCode::NO_CONTENT);
    let (code, body) = verify("111111");
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({ "error": "wrongPin", "code": "wrongPin", "attemptsLeft": 2 })
    );
    // A right PIN starts the count again.
    assert_eq!(verify("246802").0, StatusCode::NO_CONTENT);
    assert_eq!(verify("111111").1["attemptsLeft"], 2);
    assert_eq!(verify("222222").1["attemptsLeft"], 1);
    let (code, body) = verify("333333");
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({ "error": "signedOut", "code": "signedOut", "attemptsLeft": 0 })
    );
    // The sign-in has ended: the session is refused.
    assert_eq!(
        bearer(c.get(format!("{base}/api/pass/pin")), &user.token)
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn pin_is_removed_only_with_a_grant_of_this_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let pin = |method: reqwest::Method, token: &str, body: Value| {
        bearer(c.request(method, format!("{base}/api/pass/pin")), token)
            .json(&body)
            .send()
            .unwrap()
            .status()
    };
    let grant = reauth_grant(&c, &base, &user, "pass");
    assert_eq!(
        pin(
            reqwest::Method::PUT,
            &user.token,
            json!({ "grant": grant, "pin": "135790" })
        ),
        StatusCode::NO_CONTENT
    );
    // Another sign-in of the account cannot use this one's grant.
    let other = sign_in_token(&c, &base, &user);
    let grant = reauth_grant(&c, &base, &user, "pass");
    assert_eq!(
        pin(reqwest::Method::DELETE, &other, json!({ "grant": grant })),
        StatusCode::FORBIDDEN
    );
    let grant = reauth_grant(&c, &base, &user, "pass");
    assert_eq!(
        pin(
            reqwest::Method::DELETE,
            &user.token,
            json!({ "grant": grant })
        ),
        StatusCode::NO_CONTENT
    );
    let status: Value = bearer(c.get(format!("{base}/api/pass/pin")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(status["set"], false);
    purge_accounts(&c, &base, &[&user]);
}

/// A second sign-in of `user` (another device): its access token.
fn sign_in_token(c: &Client, base: &str, user: &User) -> String {
    sign_in(c, base, &user.username, &user.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn pin_tries_are_counted_per_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let grant = reauth_grant(&c, &base, &user, "pass");
    assert_eq!(
        bearer(c.put(format!("{base}/api/pass/pin")), &user.token)
            .json(&json!({ "grant": grant, "pin": "975310" }))
            .send()
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let other = sign_in_token(&c, &base, &user);
    let verify = |token: &str, pin: &str| -> Value {
        let response = bearer(c.post(format!("{base}/api/pass/pin/verify")), token)
            .json(&json!({ "pin": pin }))
            .send()
            .unwrap();
        if response.status() == StatusCode::NO_CONTENT {
            return json!("ok");
        }
        response.json().unwrap()
    };
    // Another sign-in's misses leave this one its three tries…
    assert_eq!(verify(&other, "000001")["attemptsLeft"], 2);
    assert_eq!(verify(&other, "000002")["attemptsLeft"], 1);
    assert_eq!(verify(&user.token, "000003")["attemptsLeft"], 2);
    // …and this one's right PIN gives the other none back.
    assert_eq!(verify(&user.token, "975310"), json!("ok"));
    assert_eq!(verify(&other, "000004")["error"], "signedOut");
    // The other sign-in has ended; this one goes on.
    assert_eq!(
        bearer(c.get(format!("{base}/api/pass/pin")), &other)
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(verify(&user.token, "975310"), json!("ok"));
}

#[test]
fn site_icons_follow_the_account_setting() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let settings = || -> Value {
        bearer(c.get(format!("{base}/api/pass/settings")), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let choose = |body: Value| {
        bearer(c.put(format!("{base}/api/pass/settings")), &user.token)
            .json(&body)
            .send()
            .unwrap()
            .status()
    };
    let icon = |domain: &str| {
        bearer(c.post(format!("{base}/api/pass/icon")), &user.token)
            .json(&json!({ "domain": domain }))
            .send()
            .unwrap()
            .status()
    };
    // Through Kutup unless chosen otherwise.
    assert_eq!(settings()["siteIcons"], "kutup");
    // Only public host names are fetched.
    for bad in [
        "localhost",
        "127.0.0.1",
        "intranet",
        "example.org:8443",
        "example.org/x",
    ] {
        assert_eq!(icon(bad), StatusCode::BAD_REQUEST, "{bad}");
    }
    // A name that cannot resolve has no icon.
    assert_eq!(icon("no-such-host.invalid"), StatusCode::NOT_FOUND);
    assert_eq!(
        choose(json!({ "siteIcons": "sideways" })),
        StatusCode::BAD_REQUEST
    );
    // As Proton Pass: through Kutup or not at all.
    assert_eq!(
        choose(json!({ "siteIcons": "direct" })),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        choose(json!({ "siteIcons": "off" })),
        StatusCode::NO_CONTENT
    );
    assert_eq!(settings()["siteIcons"], "off");
    // The server fetches nothing for an account that chose otherwise.
    assert_eq!(icon("example.org"), StatusCode::FORBIDDEN);
    assert_eq!(
        choose(json!({ "siteIcons": "kutup" })),
        StatusCode::NO_CONTENT
    );
    assert_eq!(settings()["siteIcons"], "kutup");
    // Without a sign-in, nothing.
    assert_eq!(
        c.get(format!("{base}/api/pass/settings"))
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// A kept vault key survives losing access to the vault for a while (the
/// folder unshared, then shared again): a read hides it, never deletes it.
/// Needs `KUTUP_LIVE_DATABASE_URL` too, to take the share away and give it
/// back without the Drive re-key flow.
#[test]
fn a_kept_key_is_hidden_not_deleted_while_access_is_gone() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let owner = register(&c, &base);
    let member = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &member, false);
    let vault = seal_file(&folder, &uuid(), b"a KeePass file");
    assert!(upload(&c, &base, &owner.token, &folder, &vault)
        .status()
        .is_success());
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
    assert_eq!(list(&c, &base, &member).len(), 1);

    // Against the database: the folder's share to the member, taken away
    // (kept as JSON) and given back as it was.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = rt.block_on(sqlx::PgPool::connect(&database_url)).unwrap();
    let held = || -> i64 {
        rt.block_on(
            sqlx::query_scalar(
                "SELECT count(*) FROM pass_vault_secrets WHERE file_id = $1::uuid AND user_id = $2::uuid",
            )
            .bind(&vault.id)
            .bind(&member.id)
            .fetch_one(&pool),
        )
        .unwrap()
    };
    let kept: String = rt
        .block_on(
            sqlx::query_scalar(
                "SELECT row_to_json(cs)::text FROM collection_shares cs
                  WHERE collection_id = $1::uuid AND recipient_user_id = $2::uuid",
            )
            .bind(&folder.id)
            .bind(&member.id)
            .fetch_one(&pool),
        )
        .unwrap();
    rt.block_on(
        sqlx::query(
            "DELETE FROM collection_shares WHERE collection_id = $1::uuid AND recipient_user_id = $2::uuid",
        )
        .bind(&folder.id)
        .bind(&member.id)
        .execute(&pool),
    )
    .unwrap();
    assert_eq!(
        states(&c, &base, &member),
        vec![(vault.id.clone(), "unreachable".to_owned())],
        "listed, not used, while out of reach"
    );
    assert_eq!(held(), 1, "the read deleted nothing");
    rt.block_on(
        sqlx::query(
            "INSERT INTO collection_shares
             SELECT * FROM json_populate_record(NULL::collection_shares, $1::json)",
        )
        .bind(&kept)
        .execute(&pool),
    )
    .unwrap();
    assert_eq!(
        states(&c, &base, &member),
        vec![(vault.id.clone(), "open".to_owned())]
    );

    // Purged, the vault leaves the kept key for its owner to forget (never
    // dropped by the server, which could not write a head for it): listed
    // as gone, and gone once forgotten.
    purge_file(&c, &base, &owner, &vault.id);
    assert_eq!(held(), 1, "kept until forgotten");
    assert_eq!(
        states(&c, &base, &member),
        vec![(vault.id.clone(), "gone".to_owned())]
    );
    let forgot = bearer(
        c.post(format!("{base}/api/pass/vault-secrets/forget")),
        &member.token,
    )
    .json(&json!({ "fileIds": [vault.id] }))
    .send()
    .unwrap();
    assert_eq!(forgot.status(), StatusCode::NO_CONTENT);
    assert_eq!(held(), 0, "forgotten");
    assert_eq!(used(&c, &base, &owner.token), 0);
}

/// The largest `.kdbx` Kutup Pass takes in an upload: advertised to every
/// client, and set by administrators within its bounds (1 MiB to 1 GiB).
#[test]
fn the_largest_vault_upload_is_an_administrators_setting() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let public = |c: &Client| -> i64 {
        c.get(format!("{base}/api/auth/settings"))
            .send()
            .unwrap()
            .json::<Value>()
            .unwrap()["passVaultMaxBytes"]
            .as_i64()
            .unwrap()
    };
    assert_eq!(public(&c), 64 * 1024 * 1024);
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN unset; skipping the administrator's part");
        return;
    };
    let (name, password) = admin.split_once(':').unwrap();
    let token = admin_token(&c, &base, password, name);
    let put = |value: Value| {
        bearer(c.put(format!("{base}/api/admin/settings")), &token)
            .json(&json!({ "passVaultMaxBytes": value }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(put(json!(1024)), StatusCode::BAD_REQUEST);
    assert_eq!(put(json!(2u64 << 30)), StatusCode::BAD_REQUEST);
    assert_eq!(put(json!(8 * 1024 * 1024)), StatusCode::OK);
    assert_eq!(public(&c), 8 * 1024 * 1024);
    assert_eq!(put(json!(64 * 1024 * 1024)), StatusCode::OK);
    assert_eq!(public(&c), 64 * 1024 * 1024);
}
