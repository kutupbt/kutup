//! The account's UI preferences against a live server (theme, language and
//! keyboard shortcuts, the same in every app). Needs `KUTUP_LIVE_SERVER`.

use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

#[test]
fn shortcuts_are_on_until_turned_off_and_a_save_without_them_keeps_them() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let path = format!("{base}/api/v1/account/ui-preferences");
    let get = || -> Value {
        bearer(c.get(&path), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let put = |body: Value| -> Value {
        let r = bearer(c.put(&path), &user.token)
            .json(&body)
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        r.json().unwrap()
    };
    // Never chosen: null, which the apps read as on.
    assert_eq!(get()["shortcuts"], Value::Null);
    assert_eq!(
        put(json!({ "theme": "dark", "language": "en", "shortcuts": false }))["shortcuts"],
        false
    );
    // An app that saves only its theme and language keeps the choice.
    assert_eq!(
        put(json!({ "theme": "light", "language": "tr" }))["shortcuts"],
        false
    );
    let now = get();
    assert_eq!(
        (now["theme"].as_str(), now["shortcuts"].as_bool()),
        (Some("light"), Some(false))
    );
    assert_eq!(
        put(json!({ "theme": "light", "language": "tr", "shortcuts": true }))["shortcuts"],
        true
    );
    assert_eq!(get()["shortcuts"], true);
}
