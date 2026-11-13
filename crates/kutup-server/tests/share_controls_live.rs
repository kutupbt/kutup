//! Share-link controls (docs/plans/server-personal-data.md, A11) against a
//! live server: an operator's block (451 for a legal order, 410 otherwise),
//! the per-account switch, and the site-wide switch (`off`, `signed_in`).
//!
//!   KUTUP_LIVE_SERVER=http://… KUTUP_LIVE_ADMIN=name:password \
//!   cargo test -p kutup-server --test share_controls_live -- --test-threads 1

mod common;

use common::*;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

/// A public link to `folder` of `owner`: its id and token, or the refusal.
fn make_link(
    c: &Client,
    base: &str,
    owner: &User,
    folder: &Folder,
) -> Result<(String, String), (StatusCode, Value)> {
    let mut link_key = [0u8; 32];
    kutup_crypto::primitives::random(&mut link_key);
    let link_id = uuid();
    let context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::PublicLinkCollectionKey,
        1,
        1,
        &folder.id,
        &owner.id,
    )
    .unwrap();
    let r = bearer(c.post(format!("{base}/api/share")), &owner.token)
        .json(&json!({
            "id": link_id,
            "shareType": "collection",
            "targetId": folder.id,
            "collectionKeyEnvelope": drive_envelope::seal_b64(&folder.key, &link_key, context).unwrap(),
            "ownerLinkKeyEnvelope": owner_link_key(&link_key, owner, &link_id),
        }))
        .send()
        .unwrap();
    let status = r.status();
    let body: Value = r.json().unwrap_or(Value::Null);
    if status != StatusCode::CREATED {
        return Err((status, body));
    }
    Ok((
        body["id"].as_str().unwrap().to_owned(),
        body["token"].as_str().unwrap().to_owned(),
    ))
}

/// Opening the link: its status and the refusal's code.
fn open(c: &Client, base: &str, token: &str, viewer: Option<&str>) -> (StatusCode, Value) {
    let request = c.get(format!("{base}/api/share/{token}"));
    let r = match viewer {
        Some(viewer) => bearer(request, viewer),
        None => request,
    }
    .send()
    .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

/// Every public route of a link, each answering before it reaches anything
/// (a made-up file id is enough): what each refusal must cover.
fn every_route(
    c: &Client,
    base: &str,
    token: &str,
    viewer: Option<&str>,
) -> Vec<(String, StatusCode, Value)> {
    let file = uuid();
    let gets = [
        format!("{base}/api/share/{token}"),
        format!("{base}/api/share/{token}/files"),
        format!("{base}/api/share/{token}/epochs"),
        format!("{base}/api/share/{token}/album"),
        format!("{base}/api/share/{token}/thumbnails/{file}/sm"),
        format!("{base}/api/share/{token}/state/{file}"),
        format!("{base}/api/share/{token}/files/{file}/assets/{}", uuid()),
        format!("{base}/api/share/{token}/download/{file}"),
    ];
    let mut answers: Vec<(String, StatusCode, Value)> = gets
        .into_iter()
        .map(|url| {
            let request = c.get(&url);
            let r = match viewer {
                Some(viewer) => bearer(request, viewer),
                None => request,
            }
            .send()
            .unwrap();
            let status = r.status();
            (url, status, r.json().unwrap_or(Value::Null))
        })
        .collect();
    let url = format!("{base}/api/share/{token}/report");
    let r = c
        .post(&url)
        .json(&json!({ "reason": "other", "details": "" }))
        .send()
        .unwrap();
    let status = r.status();
    answers.push((url, status, r.json().unwrap_or(Value::Null)));
    answers
}

/// Every route refuses with `status` and `code`.
fn all_refuse(answers: &[(String, StatusCode, Value)], status: StatusCode, code: &str) {
    for (url, got, body) in answers {
        assert_eq!(
            (*got, body["code"].as_str()),
            (status, Some(code)),
            "{url}: {body}"
        );
    }
}

fn admin(c: &Client, base: &str) -> Option<String> {
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN unset; skipping");
        return None;
    };
    let (name, password) = admin.split_once(':').expect("name:password");
    Some(admin_token(c, base, password, name))
}

fn set_site(c: &Client, base: &str, admin: &str, value: &str) {
    let r = bearer(c.put(format!("{base}/api/admin/settings")), admin)
        .json(&json!({ "publicSharing": value }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{value}");
}

/// Puts the site's switch back to `on` however the test ends: the tests
/// after it share the server.
struct SiteOn<'a> {
    c: &'a Client,
    base: &'a str,
    admin: &'a str,
}

impl Drop for SiteOn<'_> {
    fn drop(&mut self) {
        let _ = bearer(
            self.c.put(format!("{}/api/admin/settings", self.base)),
            self.admin,
        )
        .json(&json!({ "publicSharing": "on" }))
        .send();
    }
}

#[test]
fn links_follow_blocks_and_both_switches() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let Some(admin) = admin(&c, &base) else {
        return;
    };
    let owner = register(&c, &base);
    let viewer = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let (link_id, token) = make_link(&c, &base, &owner, &folder).expect("a link");
    let (_, second) = make_link(&c, &base, &owner, &folder).expect("a second link");
    assert_eq!(open(&c, &base, &token, None).0, StatusCode::OK);

    // An operator's block, of what the link reaches: 451 for a legal order on
    // every route of it and of the folder's other link; no new link to it.
    let block = |reason: &str| {
        bearer(
            c.post(format!("{base}/api/admin/shares/{link_id}/block")),
            &admin,
        )
        .json(&json!({ "reason": reason, "reference": "order 17" }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(block("legal_order"), StatusCode::NO_CONTENT);
    let (status, body) = open(&c, &base, &token, None);
    assert_eq!(status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert_eq!(
        (body["code"].as_str(), body["reason"].as_str()),
        (Some("link_blocked"), Some("legal_order"))
    );
    for link in [&token, &second] {
        all_refuse(
            &every_route(&c, &base, link, None),
            StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            "link_blocked",
        );
    }
    let (status, body) = make_link(&c, &base, &owner, &folder).unwrap_err();
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("targetBlocked"))
    );
    assert_eq!(block("abuse"), StatusCode::NO_CONTENT);
    assert_eq!(open(&c, &base, &second, None).0, StatusCode::GONE);
    assert_eq!(block("whim"), StatusCode::BAD_REQUEST);
    let r = bearer(
        c.delete(format!("{base}/api/admin/shares/{link_id}/block")),
        &admin,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(open(&c, &base, &token, None).0, StatusCode::OK);
    assert_eq!(open(&c, &base, &second, None).0, StatusCode::OK);

    // The owner's account switched off: its links answer 410 on every route,
    // the holder not told whose switch it was; it makes none.
    let set_account = |value: &str| {
        bearer(
            c.put(format!("{base}/api/admin/users/{}", owner.id)),
            &admin,
        )
        .json(&json!({ "publicSharing": value }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(set_account("off"), StatusCode::OK);
    let (status, body) = open(&c, &base, &token, None);
    assert_eq!(
        (status, body["code"].as_str(), body.get("scope")),
        (StatusCode::GONE, Some("sharing_off"), None)
    );
    all_refuse(
        &every_route(&c, &base, &token, None),
        StatusCode::GONE,
        "sharing_off",
    );
    let (status, body) = make_link(&c, &base, &owner, &folder).unwrap_err();
    assert_eq!(
        (status, body["code"].as_str(), body["scope"].as_str()),
        (StatusCode::FORBIDDEN, Some("sharing_off"), Some("account"))
    );
    assert_eq!(me(&c, &base, &owner.token)["publicSharing"], "off");
    assert_eq!(set_account("on"), StatusCode::OK);

    // Site-wide: signed_in opens only for a signed-in viewer (a sign-in sent
    // but no longer good is 401, so the page refreshes it); off for nobody.
    let _restore = SiteOn {
        c: &c,
        base: &base,
        admin: &admin,
    };
    set_site(&c, &base, &admin, "signed_in");
    all_refuse(
        &every_route(&c, &base, &token, None)[..8],
        StatusCode::FORBIDDEN,
        "sign_in_required",
    );
    assert_eq!(
        open(&c, &base, &token, Some("not-a-token")).0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        open(&c, &base, &token, Some(&viewer.token)).0,
        StatusCode::OK
    );
    set_site(&c, &base, &admin, "off");
    all_refuse(
        &every_route(&c, &base, &token, Some(&viewer.token))[..8],
        StatusCode::GONE,
        "sharing_off",
    );
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(settings["publicSharing"], "off");
    set_site(&c, &base, &admin, "on");
    assert_eq!(open(&c, &base, &token, None).0, StatusCode::OK);

    purge_accounts(&c, &base, &[&owner, &viewer]);
}
