//! Registration modes and referral codes (docs/plans/registration-codes.md)
//! against a live server. Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_ADMIN`
//! (`username:password`). One test, in order: the mode is the server's, so
//! nothing else may register meanwhile; it is put back to `on` at the end,
//! also when the test fails.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

struct Admin<'a> {
    c: &'a Client,
    base: &'a str,
    token: String,
}

impl Admin<'_> {
    fn set_mode(&self, mode: &str) {
        let r = bearer(
            self.c.put(format!("{}/api/admin/settings", self.base)),
            &self.token,
        )
        .json(&json!({ "registrationMode": mode }))
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "set mode {mode}");
        let settings: Value = self
            .c
            .get(format!("{}/api/auth/settings", self.base))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(settings["registrationMode"], mode);
    }

    fn make(&self, body: Value) -> Value {
        let r = bearer(
            self.c
                .post(format!("{}/api/admin/registration-codes", self.base)),
            &self.token,
        )
        .json(&body)
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED, "make {body}");
        r.json().unwrap()
    }

    fn list(&self) -> Vec<Value> {
        bearer(
            self.c
                .get(format!("{}/api/admin/registration-codes", self.base)),
            &self.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap()
    }

    fn row(&self, id: &str) -> Value {
        self.list()
            .into_iter()
            .find(|row| row["id"] == id)
            .expect("listed")
    }
}

/// Puts the server back to open registration, whatever happened.
struct ModeOn<'a>(&'a Admin<'a>);

impl Drop for ModeOn<'_> {
    fn drop(&mut self) {
        let _ = bearer(
            self.0.c.put(format!("{}/api/admin/settings", self.0.base)),
            &self.0.token,
        )
        .json(&json!({ "registrationMode": "on" }))
        .send();
    }
}

fn refused(result: Result<User, (StatusCode, Value)>) -> (StatusCode, String) {
    match result {
        Ok(user) => panic!("{} registered", user.username),
        Err((status, body)) => (status, body["code"].as_str().unwrap_or_default().to_owned()),
    }
}

fn check(c: &Client, base: &str, code: &str) -> (StatusCode, Value) {
    let r = c
        .post(format!("{base}/api/auth/registration-code/check"))
        .json(&json!({ "code": code }))
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

#[test]
fn registration_modes_and_codes() {
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
    let _restore = ModeOn(&admin);

    // A code is shown once; the list has its hint only.
    let one = admin.make(json!({ "note": "one person", "maxUses": 1 }));
    let code = one["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 23, "{code}");
    let id = one["id"].as_str().unwrap().to_owned();
    let listed = admin.row(&id);
    assert!(
        listed.get("code").is_none(),
        "the list never holds the code"
    );
    assert_eq!(listed["hint"], code.replace('-', "")[16..]);
    assert_eq!(listed["state"], "active");

    // Off: nobody, not even with a good code.
    admin.set_mode("off");
    assert_eq!(
        refused(register_coded(&c, &base, Some(&code))),
        (StatusCode::FORBIDDEN, "registrationClosed".into())
    );
    assert_eq!(check(&c, &base, &code).1["code"], "registrationClosed");

    // Code: one is required, a wrong one gets the one answer, a good one
    // admits exactly as many accounts as it has uses.
    admin.set_mode("code");
    assert_eq!(
        refused(register_coded(&c, &base, None)),
        (StatusCode::FORBIDDEN, "registrationCodeRequired".into())
    );
    let unknown = "00000-00000-00000-00000";
    assert_eq!(
        refused(register_coded(&c, &base, Some(unknown))),
        (StatusCode::FORBIDDEN, "registrationCodeInvalid".into())
    );
    assert_eq!(
        refused(register_coded(&c, &base, Some("not a code"))),
        (StatusCode::FORBIDDEN, "registrationCodeInvalid".into())
    );
    // Checking uses nothing up, and reads the code however it is typed.
    let typed = code.to_lowercase().replace('-', " ");
    assert_eq!(check(&c, &base, &typed).0, StatusCode::NO_CONTENT);
    assert_eq!(check(&c, &base, &typed).0, StatusCode::NO_CONTENT);
    assert_eq!(admin.row(&id)["uses"], 0);
    let first = register_coded(&c, &base, Some(&typed)).expect("the code admits one");
    assert_eq!(admin.row(&id)["uses"], 1);
    assert_eq!(admin.row(&id)["state"], "usedUp");
    // Used up: the same answer as unknown, at check and at sign-up.
    let (status, used_up) = check(&c, &base, &code);
    let (_, never) = check(&c, &base, unknown);
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(used_up, never, "used up and unknown answer alike");
    assert_eq!(
        refused(register_coded(&c, &base, Some(&code))),
        (StatusCode::FORBIDDEN, "registrationCodeInvalid".into())
    );
    // Who signed up with it, both ways.
    let uses: Vec<Value> = bearer(
        c.get(format!("{base}/api/admin/registration-codes/{id}/uses")),
        &admin.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0]["username"], first.username.as_str());
    let signed_up: Value = bearer(
        c.get(format!(
            "{base}/api/admin/users/{}/registration-code",
            first.id
        )),
        &admin.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(signed_up["codeId"], id.as_str());
    assert_eq!(signed_up["note"], "one person");

    // A code with N uses admits N accounts, however many sign up at once.
    let three = admin.make(json!({ "maxUses": 3 }));
    let three_code = three["code"].as_str().unwrap().to_owned();
    let results: Vec<bool> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (c, base, code) = (&c, &base, &three_code);
                scope.spawn(move || register_coded(c, base, Some(code)).is_ok())
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|ok| **ok).count(), 3, "{results:?}");
    assert_eq!(admin.row(three["id"].as_str().unwrap())["uses"], 3);

    // Revoked: at once, the same answer; revoking again changes nothing.
    let many = admin.make(json!({ "note": "revoked", "maxUses": null }));
    let many_code = many["code"].as_str().unwrap().to_owned();
    let many_id = many["id"].as_str().unwrap().to_owned();
    let revoke = || {
        bearer(
            c.post(format!(
                "{base}/api/admin/registration-codes/{many_id}/revoke"
            )),
            &admin.token,
        )
        .send()
        .unwrap()
    };
    assert_eq!(revoke().json::<Value>().unwrap()["state"], "revoked");
    assert_eq!(revoke().status(), StatusCode::OK);
    assert_eq!(
        refused(register_coded(&c, &base, Some(&many_code))),
        (StatusCode::FORBIDDEN, "registrationCodeInvalid".into())
    );

    // A code that expires: refused once past it; one in the past is not made.
    let past = (time::OffsetDateTime::now_utc() - time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/admin/registration-codes")),
        &admin.token,
    )
    .json(&json!({ "expiresAt": past }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let soon = (time::OffsetDateTime::now_utc() + time::Duration::seconds(2))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let expiring = admin.make(json!({ "expiresAt": soon }));
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(
        admin.row(expiring["id"].as_str().unwrap())["state"],
        "expired"
    );
    assert_eq!(
        refused(register_coded(
            &c,
            &base,
            Some(expiring["code"].as_str().unwrap())
        )),
        (StatusCode::FORBIDDEN, "registrationCodeInvalid".into())
    );

    // Out-of-range uses and long notes are refused.
    for body in [
        json!({ "maxUses": 0 }),
        json!({ "maxUses": 100_001 }),
        json!({ "note": "x".repeat(201) }),
    ] {
        let r = bearer(
            c.post(format!("{base}/api/admin/registration-codes")),
            &admin.token,
        )
        .json(&body)
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{body}");
    }

    // On: anyone; a good code is recorded and used up, a wrong one refused.
    admin.set_mode("on");
    assert!(register_coded(&c, &base, None).is_ok());
    let open = admin.make(json!({ "maxUses": 2 }));
    let recorded =
        register_coded(&c, &base, Some(open["code"].as_str().unwrap())).expect("on, with a code");
    assert_eq!(admin.row(open["id"].as_str().unwrap())["uses"], 1);
    let signed_up: Value = bearer(
        c.get(format!(
            "{base}/api/admin/users/{}/registration-code",
            recorded.id
        )),
        &admin.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(signed_up["codeId"], open["id"]);
    assert_eq!(
        refused(register_coded(&c, &base, Some(unknown))),
        (StatusCode::FORBIDDEN, "registrationCodeInvalid".into())
    );

    // The audit log names the codes by hint, never the code.
    let activity: Value = bearer(
        c.get(format!("{base}/api/admin/activity?limit=200")),
        &admin.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let text = activity.to_string();
    assert!(text.contains("registration_code.created"));
    assert!(text.contains("registration_code.revoked"));
    assert!(
        !text.contains(&code.replace('-', "")) && !text.contains(&code),
        "no code in the log"
    );
}
