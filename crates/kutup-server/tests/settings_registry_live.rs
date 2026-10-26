//! The settings registry and an account's own limits
//! (docs/plans/settings-registry.md) against a live server: one account's
//! Drive upload limit holds it and no one else, `/api/drive/limits` answers
//! each account its own, values out of range or settings that don't limit
//! one account are refused, a reset returns to the site's, and every change
//! is audited.
//!
//! Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_ADMIN` (`username:password`).

mod common;

use common::*;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

const MIB: i64 = 1024 * 1024;

struct Admin {
    c: Client,
    base: String,
    token: String,
}

impl Admin {
    fn put(&self, account: &str, key: &str, value: Value) -> (StatusCode, Value) {
        let r = bearer(
            self.c.put(format!(
                "{}/api/admin/users/{account}/limits/{key}",
                self.base
            )),
            &self.token,
        )
        .json(&json!({ "value": value }))
        .send()
        .unwrap();
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    fn get(&self, path: &str) -> Value {
        bearer(self.c.get(format!("{}{path}", self.base)), &self.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    }
}

fn drive_limits(c: &Client, base: &str, token: &str) -> Value {
    bearer(c.get(format!("{base}/api/drive/limits")), token)
        .send()
        .unwrap()
        .json()
        .unwrap()
}

/// A two-MiB upload's start: its status.
fn start_upload(c: &Client, base: &str, user: &User) -> StatusCode {
    let folder = create_folder(c, base, user);
    let file = seal_file(&folder, &uuid(), b"limits");
    tus_create(c, base, &user.token, &folder, &file, 2 * MIB).status()
}

#[test]
fn an_accounts_own_upload_limit_holds_it_alone() {
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
    let admin = Admin {
        token: admin_token(&c, &base, password, name),
        c: client(),
        base: base.clone(),
    };
    let small = register(&c, &base);
    let other = register(&c, &base);
    let small_id = me(&c, &base, &small.token)["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // The registry lists which settings take an account's own value.
    let registry = admin.get("/api/admin/settings/registry");
    let per_account = |key: &str| {
        registry["settings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|setting| setting["key"] == key)
            .unwrap_or_else(|| panic!("{key} in the registry"))["perAccount"]
            .clone()
    };
    assert_eq!(per_account("drive_upload_max_bytes"), true);
    assert_eq!(per_account("drive_stream_response_max_bytes"), false);

    // Only administrators set an account's own value.
    let r = bearer(
        c.put(format!(
            "{base}/api/admin/users/{small_id}/limits/drive_upload_max_bytes"
        )),
        &small.token,
    )
    .json(&json!({ "value": MIB }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // One MiB for one account: its two-MiB upload is refused, another's not.
    let site_upload = drive_limits(&c, &base, &other.token)["uploadMaxBytes"].clone();
    let (status, set) = admin.put(&small_id, "drive_upload_max_bytes", json!(MIB));
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["value"], MIB);
    assert_eq!(set["source"], "account");
    assert_eq!(set["siteValue"], site_upload);
    assert_eq!(
        start_upload(&c, &base, &small),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(start_upload(&c, &base, &other), StatusCode::CREATED);
    let small_limits = drive_limits(&c, &base, &small.token);
    let other_limits = drive_limits(&c, &base, &other.token);
    assert_eq!(small_limits["uploadMaxBytes"], MIB);
    assert_eq!(other_limits["uploadMaxBytes"], site_upload);
    assert_eq!(
        small_limits["streamResponseMaxBytes"],
        other_limits["streamResponseMaxBytes"]
    );

    // Listed on the account's page with where it comes from.
    let listed = admin.get(&format!("/api/admin/users/{small_id}/limits"));
    let upload = listed["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|setting| setting["key"] == "drive_upload_max_bytes")
        .expect("listed")
        .clone();
    assert_eq!(upload["source"], "account");
    assert!(listed["settings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|setting| setting["key"] != "drive_stream_response_max_bytes"));

    // Out of range is refused, never clamped; a setting that doesn't limit
    // one account is refused; an unknown one is not found.
    assert_eq!(
        admin.put(&small_id, "drive_upload_max_bytes", json!(1)).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin
            .put(&small_id, "drive_stream_response_max_bytes", json!(5 * MIB))
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin.put(&small_id, "no_such_setting", json!(1)).0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        admin.put(&small_id, "rate_limit.no_such_limit", json!(1)).0,
        StatusCode::NOT_FOUND
    );
    // The refused value left the account's own as it was.
    assert_eq!(drive_limits(&c, &base, &small.token)["uploadMaxBytes"], MIB);

    // Taken back: the site's again.
    let (status, reset) = admin.put(&small_id, "drive_upload_max_bytes", Value::Null);
    assert_eq!(status, StatusCode::OK);
    assert_ne!(reset["source"], "account");
    assert_eq!(reset["value"], site_upload);
    assert_eq!(start_upload(&c, &base, &small), StatusCode::CREATED);

    // Audited.
    let activity = admin.get("/api/admin/activity?limit=20");
    assert!(
        activity["entries"].as_array().unwrap().iter().any(|e| {
            e["action"] == "user.setting"
                && e["targetUserId"] == small_id
                && e["payload"]["key"] == "drive_upload_max_bytes"
        }),
        "{activity}"
    );
    purge_accounts(&c, &base, &[&small, &other]);
}
