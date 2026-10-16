//! Chat groups are off by default (`CHAT_GROUPS`; the beta launches without
//! them, until the pairwise group design replaces MLS — docs/roadmap.md):
//! the server reports no groups and no group calls, and refuses every group,
//! MLS and group-call route. Meeting links are not groups and stay.
//!
//! Needs `KUTUP_LIVE_SERVER`, a server started without `CHAT_GROUPS`.

mod common;
use common::*;

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

#[test]
fn groups_are_off_unless_switched_on() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let chat = &settings["chat"];
    assert_eq!(chat["mlsGroups"], false, "{chat}");
    assert_eq!(chat["groupCalls"], false, "{chat}");

    let user = register(&c, &base);
    let get = |path: &str| {
        bearer(c.get(format!("{base}{path}")), &user.token)
            .send()
            .unwrap()
            .status()
    };
    for path in [
        "/api/chat/mls/invitations",
        "/api/chat/mls/invitation-feedback",
        "/api/chat/mls/messages/1",
        "/api/chat/mls/key-packages/1/count",
        &format!("/api/chat/mls/domains/{}/policy", server_domain(&c, &base)),
    ] {
        assert_eq!(get(path), StatusCode::NOT_FOUND, "{path}");
    }
    // A well-formed group-call token request: refused for there being no
    // groups, not for its shape.
    let r = bearer(
        c.post(format!("{base}/api/chat/group-calls/token")),
        &user.token,
    )
    .json(&json!({
        "host": server_domain(&c, &base),
        "roomId": "11".repeat(16),
        "participantId": "22".repeat(16),
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    purge_accounts(&c, &base, &[&user]);
}
