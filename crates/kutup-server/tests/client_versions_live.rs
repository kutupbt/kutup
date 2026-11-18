//! Client versions and the instance id against a live server
//! (docs/plans/api-surface.md §1 and §5): health names the API versions,
//! the minimums and the instance id; every API answer carries the same id;
//! a client older than an administrator's minimum gets `426 clientTooOld`
//! (a `-dev` build and a request naming no client don't); the minimum
//! can't be set by anyone else, and clears again.
//!
//! Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_ADMIN` (`username:password`).

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

#[test]
fn old_clients_are_refused_and_the_instance_is_named() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_owned();
    let c = client();
    let (name, password) = admin.split_once(':').expect("username:password");
    let admin = admin_token(&c, &base, password, name);
    let user = register(&c, &base);

    // Health: what the server serves and who it is.
    let health: Value = c
        .get(format!("{base}/api/health"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(health["apiVersions"], json!([1]));
    let instance = health["instanceId"]
        .as_str()
        .expect("instanceId")
        .to_owned();
    assert_eq!(instance.len(), 22, "{instance}");

    // Every API answer names the same instance, errors included.
    let me = bearer(c.get(format!("{base}/api/v1/account")), &user.token)
        .send()
        .unwrap();
    assert_eq!(me.headers()["x-kutup-instance"], instance.as_str());
    let missing = c.get(format!("{base}/api/v1/account")).send().unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.headers()["x-kutup-instance"], instance.as_str());

    let set = |token: &str, minimum: Value| {
        bearer(c.put(format!("{base}/api/v1/admin/client-versions")), token)
            .json(&json!({ "clientType": "cli", "minimum": minimum }))
            .send()
            .unwrap()
    };
    // Only administrators set a minimum; a malformed one is refused.
    assert_eq!(
        set(&user.token, json!("99.0.0")).status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        set(&admin, json!("ninety")).status(),
        StatusCode::BAD_REQUEST
    );
    let r = set(&admin, json!("99.0.0"));
    assert_eq!(r.status(), StatusCode::OK);
    let listed: Value = r.json().unwrap();
    let cli = listed["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|client| client["clientType"] == "cli")
        .unwrap()
        .clone();
    assert_eq!(cli["minimum"], "99.0.0");
    assert_eq!(cli["effective"], "99.0.0");

    let as_client = |client: Option<&str>| {
        let mut req = bearer(c.get(format!("{base}/api/v1/account")), &user.token);
        if let Some(client) = client {
            req = req.header("x-kutup-client", client);
        }
        req.send().unwrap()
    };
    // Older: refused, naming the minimum.
    let r = as_client(Some("cli/0.0.1"));
    assert_eq!(r.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(r.headers()["x-kutup-min-client"], "cli/99.0.0");
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "clientTooOld");
    assert_eq!(body["clientType"], "cli");
    assert_eq!(body["minimum"], "99.0.0");
    // The type alone reads as version zero.
    assert_eq!(
        as_client(Some("cli")).status(),
        StatusCode::UPGRADE_REQUIRED
    );
    // New enough, a developer's build, another type, no client named: on.
    assert_eq!(as_client(Some("cli/99.0.0")).status(), StatusCode::OK);
    assert_eq!(as_client(Some("cli/0.0.0-dev")).status(), StatusCode::OK);
    assert_eq!(as_client(Some("web-drive/0.0.1")).status(), StatusCode::OK);
    assert_eq!(as_client(None).status(), StatusCode::OK);
    // Health stays open to every version and lists the minimum.
    let health: Value = c
        .get(format!("{base}/api/health"))
        .header("x-kutup-client", "cli/0.0.1")
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(health["minimumClients"]["cli"], "99.0.0");

    // A client from before versions calls bare /api/… paths: too old. A
    // version this server doesn't serve: the server is too old.
    let bare = bearer(c.get(format!("{base}/api/user/me")), &user.token)
        .send()
        .unwrap();
    assert_eq!(bare.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(bare.json::<Value>().unwrap()["code"], "clientTooOld");
    let newer = c.get(format!("{base}/api/v2/account")).send().unwrap();
    assert_eq!(newer.status(), StatusCode::NOT_FOUND);
    let newer: Value = newer.json().unwrap();
    assert_eq!(newer["code"], "apiVersionUnsupported");
    assert_eq!(newer["supported"], json!([1]));
    let missing = c
        .get(format!("{base}/api/v1/no-such-route"))
        .send()
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(missing.json::<Value>().unwrap()["code"], "notFound");

    // Cleared: the old client is back.
    assert_eq!(set(&admin, Value::Null).status(), StatusCode::OK);
    assert_eq!(as_client(Some("cli/0.0.1")).status(), StatusCode::OK);

    purge_accounts(&c, &base, &[&user]);
}
