//! Rate limits administrators set (docs/plans/admin-rate-limits.md) against
//! a live server. Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_ADMIN`
//! (`username:password`). Uses the rename-check limit (per account), which
//! nothing else in the suites spends; it is reset at the end, also when the
//! test fails.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

const LIMIT: &str = "rename_checks";

struct Admin<'a> {
    c: &'a Client,
    base: &'a str,
    token: String,
}

impl Admin<'_> {
    fn put(&self, key: &str, value: Value) -> (StatusCode, Value) {
        let r = bearer(
            self.c
                .put(format!("{}/api/admin/rate-limits/{key}", self.base)),
            &self.token,
        )
        .json(&json!({ "value": value }))
        .send()
        .unwrap();
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    fn listed(&self, key: &str) -> Value {
        let list: Value = bearer(
            self.c.get(format!("{}/api/admin/rate-limits", self.base)),
            &self.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        list["limits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|limit| limit["key"] == key)
            .cloned()
            .expect("listed")
    }
}

/// Puts the limit back to its first value, whatever happened.
struct Reset<'a>(&'a Admin<'a>);

impl Drop for Reset<'_> {
    fn drop(&mut self) {
        let _ = self.0.put(LIMIT, Value::Null);
    }
}

fn check(c: &Client, base: &str, token: &str) -> StatusCode {
    bearer(
        c.get(format!(
            "{base}/api/user/rename/check?name=free-{}",
            &uuid()[..8]
        )),
        token,
    )
    .send()
    .unwrap()
    .status()
}

#[test]
fn administrators_set_rate_limits() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let (name, password) = admin
        .split_once(':')
        .expect("KUTUP_LIVE_ADMIN is username:password");
    let admin = Admin {
        c: &c,
        base: &base,
        token: admin_token(&c, &base, password, name),
    };
    let _reset = Reset(&admin);

    let first = admin.listed(LIMIT);
    assert_eq!(first["set"], false, "{first}");
    assert_eq!(first["per"], "account");
    assert_eq!(first["windowSeconds"], 900);
    let first_value = first["firstValue"].as_u64().unwrap();
    assert_eq!(first["value"], first_value);

    // Lowered: the next check is held to it, without a restart.
    let user = register(&c, &base);
    assert_eq!(check(&c, &base, &user.token), StatusCode::OK);
    let (status, saved) = admin.put(LIMIT, json!(2));
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["value"], 2);
    assert_eq!(saved["set"], true);
    assert_eq!(saved["firstValue"], first_value);
    assert_eq!(check(&c, &base, &user.token), StatusCode::OK);
    assert_eq!(check(&c, &base, &user.token), StatusCode::TOO_MANY_REQUESTS);
    // Per account: another account still has its own.
    let other = register(&c, &base);
    assert_eq!(check(&c, &base, &other.token), StatusCode::OK);

    // Raised: at once.
    assert_eq!(admin.put(LIMIT, json!(3)).0, StatusCode::OK);
    assert_eq!(check(&c, &base, &user.token), StatusCode::OK);
    assert_eq!(check(&c, &base, &user.token), StatusCode::TOO_MANY_REQUESTS);

    // Outside the bounds, or no such limit: refused, nothing changes.
    let max = first["max"].as_u64().unwrap();
    for refused in [json!(0), json!(max + 1), json!(-1), json!("5")] {
        let (status, _) = admin.put(LIMIT, refused.clone());
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "{refused}: {status}"
        );
    }
    assert_eq!(admin.listed(LIMIT)["value"], 3);
    assert_eq!(admin.put("not_a_limit", json!(5)).0, StatusCode::NOT_FOUND);

    // Only administrators.
    let r = bearer(
        c.put(format!("{base}/api/admin/rate-limits/{LIMIT}")),
        &user.token,
    )
    .json(&json!({ "value": 1000 }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = bearer(c.get(format!("{base}/api/admin/rate-limits")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // A reset returns to the first value.
    let (status, reset) = admin.put(LIMIT, Value::Null);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reset["set"], false);
    assert_eq!(reset["value"], first_value);
    assert_eq!(check(&c, &base, &user.token), StatusCode::OK);

    // One account's own value, over the site's: only that account is held
    // to it, and only limits counted per account take one.
    let own = register(&c, &base);
    let own_id = me(&c, &base, &own.token)["id"].as_str().unwrap().to_owned();
    let account_put = |key: &str, value: Value| {
        let r = bearer(
            c.put(format!(
                "{base}/api/admin/users/{own_id}/limits/rate_limit.{key}"
            )),
            &admin.token,
        )
        .json(&json!({ "value": value }))
        .send()
        .unwrap();
        let status = r.status();
        (status, r.json::<Value>().unwrap_or(Value::Null))
    };
    // An account can't set its own, even more generous, value.
    let r = bearer(
        c.put(format!(
            "{base}/api/admin/users/{own_id}/limits/rate_limit.{LIMIT}"
        )),
        &own.token,
    )
    .json(&json!({ "value": 3000 }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let (status, set) = account_put(LIMIT, json!(1));
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["value"], 1);
    assert_eq!(set["source"], "account");
    assert_eq!(set["siteValue"], first_value);
    assert_eq!(check(&c, &base, &own.token), StatusCode::OK);
    assert_eq!(check(&c, &base, &own.token), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(check(&c, &base, &user.token), StatusCode::OK);
    let listed: Value = bearer(
        c.get(format!("{base}/api/admin/users/{own_id}/limits")),
        &admin.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let limits = listed["rateLimits"].as_array().unwrap();
    assert!(limits.iter().all(|limit| limit["limit"] != "reports"));
    assert!(limits
        .iter()
        .any(|limit| limit["limit"] == LIMIT && limit["source"] == "account"));
    assert_eq!(account_put("reports", json!(5)).0, StatusCode::BAD_REQUEST);
    assert_eq!(account_put(LIMIT, json!(0)).0, StatusCode::BAD_REQUEST);
    let (status, taken_back) = account_put(LIMIT, Value::Null);
    assert_eq!(status, StatusCode::OK);
    assert_ne!(taken_back["source"], "account");
    assert_eq!(check(&c, &base, &own.token), StatusCode::OK);

    // Audited.
    let activity: Value = bearer(
        c.get(format!("{base}/api/admin/activity?limit=10")),
        &admin.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert!(
        activity["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "settings.rate_limit" && e["payload"]["key"] == LIMIT),
        "{activity}"
    );
    assert!(
        activity["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "user.rate_limit" && e["targetUserId"] == own_id),
        "{activity}"
    );
}
