//! The account's stored roots (docs/plans/identity-root.md) against a live
//! server: kept at sign-up, handed back with the session and to the
//! account's own session only, refused when one is missing or doubled, and
//! replaced by a reset.
//!
//!   KUTUP_LIVE_SERVER=http://… KUTUP_LIVE_ADMIN=name:password \
//!     cargo test -p kutup-server --test account_roots_live

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

#[test]
fn the_roots_come_with_the_session_and_only_to_their_account() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let other = register(&c, &base);

    // The sign-in's answer carries them and the authority they must give.
    let session = sign_in(&c, &base, &user.username, &user.password);
    assert_eq!(
        session["accountRoots"].as_array().unwrap().len(),
        5,
        "{session}"
    );
    assert_eq!(
        session["accountAuthorityPublicKey"],
        json!(b64(&user.identity.authority_public_key()))
    );
    // They open with the master key, as the roots the account made.
    let roots = fetch_roots(&c, &base, &user.token, &user.master_key, &user.binding);
    assert_eq!(roots.identity.as_bytes(), user.roots.identity.as_bytes());
    assert_eq!(roots.object_id.as_bytes(), user.roots.object_id.as_bytes());
    assert_eq!(roots.call_link.as_bytes(), user.roots.call_link.as_bytes());

    // Another account's session gets its own, never these; no session, none.
    let theirs: Value = bearer(c.get(format!("{base}/api/account/roots")), &other.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    for record in theirs["accountRoots"].as_array().unwrap() {
        assert!(
            !session["accountRoots"].as_array().unwrap().contains(record),
            "another account's session got this one's roots"
        );
    }
    assert_eq!(
        c.get(format!("{base}/api/account/roots"))
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    purge_accounts(&c, &base, &[&user, &other]);
}

#[test]
fn a_sign_up_without_each_root_once_is_refused() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    for tweak in [
        // One missing.
        (|body: &mut Value| {
            body["accountRoots"].as_array_mut().unwrap().pop();
        }) as fn(&mut Value),
        // One twice (the count right, a purpose missing).
        |body: &mut Value| {
            let roots = body["accountRoots"].as_array_mut().unwrap();
            roots[4] = roots[3].clone();
        },
        // None.
        |body: &mut Value| {
            body["accountRoots"] = json!([]);
        },
    ] {
        let tag = kutup_crypto::primitives::random_below(1_000_000_000);
        let (refused, _) = sign_up(&c, &base, true, format!("roots{tag}"), None, None, tweak);
        let (status, body) = refused.err().expect("refused");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "accountRootsInvalid", "{body}");
    }
}

#[test]
fn a_reset_replaces_the_roots() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let (admin_name, admin_password) = admin.split_once(':').expect("username:password");
    let admin_token = admin_token(&c, &base, admin_password, admin_name);
    let grant = admin_reset_grant(
        &c,
        &base,
        &admin_token,
        admin_name,
        admin_password,
        &user.id,
    );
    let mut setup = temp_registration(
        &c,
        &base,
        "Temporary*Password123",
        &admin_token,
        Some(&grant),
    );
    setup["grant"] = json!(grant);
    let r = bearer(
        c.post(format!("{base}/api/admin/users/{}/wipe", user.id)),
        &admin_token,
    )
    .json(&setup)
    .send()
    .unwrap();
    assert!(r.status().is_success(), "wipe: {}", r.status());
    // Until the setup, the account has no roots.
    let first_login = sign_in(&c, &base, &user.username, "Temporary*Password123");
    assert!(first_login.get("accountRoots").is_none(), "{first_login}");
    let again = set_up_again(&c, &base, &first_login, &user, "Another*Password456");
    // The new roots, under the new master key; the old ones are gone.
    let roots = fetch_roots(&c, &base, &again.token, &again.master_key, &again.binding);
    assert_eq!(roots.identity.as_bytes(), again.roots.identity.as_bytes());
    assert_ne!(roots.identity.as_bytes(), user.roots.identity.as_bytes());
    let records: Value = bearer(c.get(format!("{base}/api/account/roots")), &again.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(records["accountRoots"].as_array().unwrap().len(), 5);
    purge_accounts(&c, &base, &[&again]);
}
