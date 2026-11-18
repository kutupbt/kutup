//! Chat groups are off by default (`CHAT_GROUPS`; on once every pairwise
//! groups slice is done, docs/plans/pairwise-groups.md §10): the server
//! reports no groups and no group calls, and refuses every group and
//! group-call route; the removed MLS routes are gone. Meeting links are not
//! groups and stay.
//!
//! Needs `KUTUP_LIVE_SERVER`, a server started without `CHAT_GROUPS`.

mod common;
use common::*;

use reqwest::StatusCode;
use serde_json::{json, Value};

#[test]
fn groups_are_off_unless_switched_on() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let settings: Value = c
        .get(format!("{base}/api/v1/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let chat = &settings["chat"];
    assert!(
        chat.get("mlsGroups").is_none(),
        "MLS groups are gone: {chat}"
    );
    assert_eq!(chat["pairwiseGroups"], false, "{chat}");
    assert_eq!(chat["groupCalls"], false, "{chat}");

    let user = register(&c, &base);
    let get = |path: &str| {
        bearer(c.get(format!("{base}{path}")), &user.token)
            .send()
            .unwrap()
            .status()
    };
    for path in [
        // The MLS routes are gone.
        "/api/v1/chat/mls/invitations",
        "/api/v1/chat/mls/invitation-feedback",
        "/api/v1/chat/mls/messages/1",
        "/api/v1/chat/mls/key-packages/1/count",
        &format!(
            "/api/v1/chat/mls/domains/{}/policy",
            server_domain(&c, &base)
        ),
        // A peer's policy is not fetched either.
        "/api/v1/chat/mls/domains/peer.invalid/policy",
        // Nor the pairwise groups' anonymous route.
        &format!(
            "/api/v1/chat/groups/gateway-key?server={}&fromSequence=0",
            server_domain(&c, &base)
        ),
    ] {
        assert_eq!(get(path), StatusCode::NOT_FOUND, "{path}");
    }
    let r = bearer(
        c.post(format!(
            "{base}/api/v1/chat/groups/relay/{}",
            server_domain(&c, &base)
        )),
        &user.token,
    )
    .body(vec![0u8; 64])
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "the groups relay");
    // Nor the account's group list (the records scope `chatGroups`): a
    // batch naming it is no such scope, before its envelope is looked at.
    let r = bearer(
        c.post(format!("{base}/api/v1/account/records")),
        &user.token,
    )
    .json(
        &json!({ "puts": [{ "scope": "chatGroups", "id": "A".repeat(43),
            "baseRevision": 0, "envelope": "AAAA" }] }),
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "the group list");
    // The federated side too: groups off answers before any signature check.
    let r = c
        .post(format!("{base}/api/fed/chat/groups/gateway"))
        .body(vec![0u8; 64])
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "the groups gateway");
    let r = c
        .get(format!("{base}/api/fed/chat/groups/gateway-key"))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "the gateway key");
    // A well-formed group-call token request: refused for there being no
    // groups, not for its shape.
    let r = bearer(
        c.post(format!("{base}/api/v1/chat/group-calls/token")),
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
