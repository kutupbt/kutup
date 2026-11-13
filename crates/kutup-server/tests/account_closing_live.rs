//! An account's end (docs/plans/server-personal-data.md, A5 and A7) against a
//! live server: the owner closes it after a reauth, its sessions end, a
//! sign-in is offered to keep it instead of a session, and keeping it signs
//! in; an admin's legal hold stops a deletion until it is cleared; an admin
//! closes an account and keeps it again.
//!
//!   KUTUP_LIVE_SERVER=http://… KUTUP_LIVE_ADMIN=name:password \
//!   [KUTUP_LIVE_DATABASE_URL=postgres://…] cargo test -p kutup-server --test account_closing_live

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn admin(c: &reqwest::blocking::Client, base: &str) -> Option<String> {
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN unset; skipping the admin part");
        return None;
    };
    let (name, password) = admin
        .split_once(':')
        .expect("KUTUP_LIVE_ADMIN is name:password");
    Some(admin_token(c, base, password, name))
}

fn kinds(page: &Value) -> Vec<String> {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_owner_closes_the_account_and_a_sign_in_keeps_it() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);

    // Closing needs a reauth's grant, for this purpose.
    let wrong = reauth_grant(&c, &base, &user, "rename");
    let r = bearer(c.post(format!("{base}/api/user/close")), &user.token)
        .json(&json!({ "grant": wrong }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    let grant = reauth_grant(&c, &base, &user, "close");
    let r = bearer(c.post(format!("{base}/api/user/close")), &user.token)
        .json(&json!({ "grant": grant }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let closed: Value = r.json().unwrap();
    assert!(closed["closesAt"].is_string(), "{closed}");

    // Every sign-in ended.
    let r = bearer(c.get(format!("{base}/api/user/me")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // A sign-in that passes gets no session, but the offer to keep it.
    let answer = sign_in(&c, &base, &user.username, &user.password);
    assert!(
        answer["accessToken"].as_str().unwrap_or("").is_empty(),
        "{answer}"
    );
    assert_eq!(answer["closing"]["closesAt"], closed["closesAt"]);
    let keep = answer["closing"]["grant"].as_str().unwrap().to_owned();

    let kept: Value = c
        .post(format!("{base}/api/auth/keep"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "grant": keep }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let token = kept["accessToken"].as_str().expect("a session").to_owned();
    // Once only.
    let again = c
        .post(format!("{base}/api/auth/keep"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "grant": keep }))
        .send()
        .unwrap();
    assert_eq!(again.status(), StatusCode::FORBIDDEN);

    let page = security_events(&c, &base, &token, "");
    let kinds = kinds(&page);
    assert!(kinds.contains(&"accountClosing".to_owned()), "{page}");
    assert!(kinds.contains(&"accountKept".to_owned()), "{page}");
    // Signed in as before.
    let me = me(&c, &base, &token);
    assert_eq!(me["id"], user.id.as_str());
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_legal_hold_stops_a_deletion_until_it_is_cleared() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let Some(admin) = admin(&c, &base) else {
        return;
    };
    let user = register(&c, &base);
    let users = |c: &reqwest::blocking::Client| -> Value {
        bearer(c.get(format!("{base}/api/admin/users")), &admin)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let row = |list: &Value| -> Value {
        list.as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == user.id.as_str())
            .cloned()
            .expect("the account is listed")
    };
    let hold = format!("{base}/api/admin/users/{}/legal-hold", user.id);

    let r = bearer(c.put(&hold), &admin)
        .json(&json!({ "reference": "  " }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = bearer(c.put(&hold), &admin)
        .json(&json!({ "reference": "case 2026/17" }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let listed = row(&users(&c));
    assert_eq!(listed["legalHoldReference"], "case 2026/17");
    assert_eq!(listed["state"], "active");

    // Held: no deletion.
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", user.id)),
        &admin,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "legalHold", "{body}");

    // Closed by an admin, then kept again: the hold doesn't stop that.
    let r = bearer(
        c.post(format!("{base}/api/admin/users/{}/close", user.id)),
        &admin,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(row(&users(&c))["state"], "closing");
    // A closing account isn't suspended in passing.
    let r = bearer(c.put(format!("{base}/api/admin/users/{}", user.id)), &admin)
        .json(&json!({ "isActive": false }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = bearer(c.put(format!("{base}/api/admin/users/{}", user.id)), &admin)
        .json(&json!({ "isActive": true }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(row(&users(&c))["state"], "active");

    // Suspended, with why.
    let r = bearer(c.put(format!("{base}/api/admin/users/{}", user.id)), &admin)
        .json(&json!({ "isActive": false, "suspendedReason": "operator_order" }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let listed = row(&users(&c));
    assert_eq!(
        (listed["state"].as_str(), listed["suspendedReason"].as_str()),
        (Some("suspended"), Some("operator_order"))
    );

    // Cleared: the deletion goes ahead, and the destruction log has it.
    let r = bearer(c.delete(&hold), &admin).send().unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let before = destruction_events();
    purge_accounts(&c, &base, &[&user]);
    if let (Some(before), Some(after)) = (before, destruction_events()) {
        assert!(after > before, "{before} → {after}");
    }
}

/// How many accounts the destruction log names, when the test can read the
/// database.
fn destruction_events() -> Option<i64> {
    let url = std::env::var("KUTUP_LIVE_DATABASE_URL").ok()?;
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        Some(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM account_keys.destruction_events WHERE category = 'account'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
        )
    })
}
