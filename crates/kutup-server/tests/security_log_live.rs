//! The account's security log (docs/plans/server-personal-data.md, A8)
//! against a live server: sign-ins and sign-outs recorded, wrong passwords
//! folded into one event with a count, and the retention the page reports.
//!
//!   KUTUP_LIVE_SERVER=http://… cargo test -p kutup-server --test security_log_live

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::Value;

fn events(c: &reqwest::blocking::Client, base: &str, token: &str) -> Value {
    bearer(c.get(format!("{base}/api/user/security-events")), token)
        .send()
        .unwrap()
        .json()
        .unwrap()
}

fn of_kind<'a>(page: &'a Value, kind: &str) -> Vec<&'a Value> {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == kind)
        .collect()
}

#[test]
fn sign_ins_and_wrong_passwords_are_in_the_accounts_log() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);

    // Two wrong passwords: one event, counted twice.
    for _ in 0..2 {
        let (status, _, _) = opaque_login(
            &c,
            &base,
            &user.username,
            "not the password",
            "session",
            None,
            None,
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // A sign-in, then its sign-out.
    let session = sign_in(&c, &base, &user.username, &user.password);
    let token = session["accessToken"].as_str().unwrap().to_owned();
    // Failed sign-ins are recorded off the answer's path: a moment later.
    let mut page = events(&c, &base, &token);
    for _ in 0..50 {
        if of_kind(&page, "signInFailedPassword")
            .first()
            .is_some_and(|event| event["count"] == 2)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        page = events(&c, &base, &token);
    }
    let failed = of_kind(&page, "signInFailedPassword");
    assert_eq!(failed.len(), 1, "{page}");
    assert_eq!(failed[0]["count"], 2);
    assert!(!of_kind(&page, "signIn").is_empty());
    assert_eq!(page["retentionDays"], 365);

    let out = bearer(c.post(format!("{base}/api/auth/logout")), &token)
        .send()
        .unwrap();
    assert_eq!(out.status(), StatusCode::OK);
    let page = events(&c, &base, &user.token);
    assert_eq!(of_kind(&page, "signOut").len(), 1, "{page}");
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_sessions_browser_is_its_parsed_family() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let user = register(&client(), &base);
    let firefox = client_builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
        .build()
        .unwrap();
    let session = sign_in(&firefox, &base, &user.username, &user.password);
    let token = session["accessToken"].as_str().unwrap().to_owned();
    let sessions: Value = bearer(firefox.get(format!("{base}/api/auth/sessions")), &token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let this = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|session| session["current"] == true)
        .expect("this session is listed");
    assert_eq!(this["browser"], "Firefox");
    assert_eq!(this["browserMajor"], 128);
    assert_eq!(this["os"], "Linux");
    assert!(this.get("userAgent").is_none());
    // The sign-in's event carries the same family.
    let page = events(&firefox, &base, &token);
    let sign_in_event = of_kind(&page, "signIn")
        .into_iter()
        .find(|event| event["thisSession"] == true)
        .expect("this sign-in's event");
    assert_eq!(sign_in_event["browser"], "Firefox");
    assert_eq!(sign_in_event["os"], "Linux");
    purge_accounts(&firefox, &base, &[&user]);
}
