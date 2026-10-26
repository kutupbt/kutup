//! Live e2e for security keys as a second factor
//! (docs/plans/security-keys.md §9), with a software authenticator
//! (kutup_crypto::webauthn::soft): adding keys (the first turns two-step
//! sign-in on, with recovery codes), the limit and duplicates, signing in
//! with a key, a cloned key's counter, renaming, "Require PIN", proving the
//! factor with a key, and removing the last factor.
//!
//! Gated on `KUTUP_LIVE_SERVER` and `KUTUP_ACCOUNT_URL` (the account app's
//! origin, which keys are bound to):
//!   KUTUP_LIVE_SERVER=http://<backend>:3000 KUTUP_ACCOUNT_URL=https://account.localhost:39643 \
//!     cargo test -p kutup-server --test security_keys_live -- --nocapture

use kutup_crypto::webauthn::soft::Authenticator;
use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

struct Stack {
    c: Client,
    base: String,
    origin: String,
}

impl Stack {
    fn post(&self, token: &str, path: &str, body: Value) -> Response {
        bearer(self.c.post(format!("{}{path}", self.base)), token)
            .json(&body)
            .send()
            .unwrap()
    }

    fn keys(&self, token: &str) -> Value {
        bearer(
            self.c.get(format!("{}/api/auth/security-keys", self.base)),
            token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap()
    }

    /// Adds a key with `authenticator`: the status and body of the finish.
    fn add(&self, user: &User, authenticator: &Authenticator, name: &str) -> (StatusCode, Value) {
        let grant = reauth_grant(&self.c, &self.base, user, "totp");
        let r = self.post(
            &user.token,
            "/api/auth/security-keys/register/start",
            json!({ "grant": grant }),
        );
        if r.status() != StatusCode::OK {
            let status = r.status();
            return (status, r.json().unwrap_or(Value::Null));
        }
        let options: Value = r.json().unwrap();
        let rp_id = rp_id(&options);
        let credential: Value = serde_json::from_slice(&authenticator.register(
            &options.to_string(),
            &rp_id,
            &self.origin,
        ))
        .unwrap();
        let r = self.post(
            &user.token,
            "/api/auth/security-keys/register/finish",
            json!({ "name": name, "credential": credential }),
        );
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    /// A sign-in's second step with `authenticator` (moving its counter on,
    /// or not, as a clone would): the status and body.
    fn sign_in_with(
        &self,
        user: &User,
        authenticator: &mut Authenticator,
        move_counter: bool,
    ) -> (StatusCode, Value) {
        let first = sign_in(&self.c, &self.base, &user.username, &user.password);
        assert_eq!(first["requiresTotp"], true, "a second step: {first}");
        let pre_auth = first["preAuthToken"].as_str().unwrap().to_owned();
        let r = self
            .c
            .post(format!("{}/api/auth/login/security-key/start", self.base))
            .json(&json!({ "preAuthToken": pre_auth }))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let options: Value = r.json().unwrap();
        let rp_id = rp_id(&options);
        let answer = if move_counter {
            authenticator.assert(&options.to_string(), &rp_id, &self.origin)
        } else {
            authenticator.assert_at(&options.to_string(), &rp_id, &self.origin)
        };
        let credential: Value = serde_json::from_slice(&answer).unwrap();
        let r = self
            .c
            .post(format!("{}/api/auth/login/security-key/finish", self.base))
            .header("x-kutup-client", "cli")
            .json(&json!({ "preAuthToken": pre_auth, "credential": credential }))
            .send()
            .unwrap();
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    /// An answer to this session's proof ceremony.
    fn proof(&self, user: &User, authenticator: &mut Authenticator) -> Value {
        let r = self.post(
            &user.token,
            "/api/auth/security-keys/proof/start",
            json!({}),
        );
        assert_eq!(r.status(), StatusCode::OK);
        let options: Value = r.json().unwrap();
        let rp_id = rp_id(&options);
        serde_json::from_slice(&authenticator.assert(&options.to_string(), &rp_id, &self.origin))
            .unwrap()
    }
}

fn rp_id(options: &Value) -> String {
    let options = options.get("publicKey").unwrap_or(options);
    options["rp"]["id"]
        .as_str()
        .or_else(|| options["rpId"].as_str())
        .expect("options name the RP")
        .to_owned()
}

#[test]
fn security_keys_add_sign_in_and_go() {
    let (Ok(base), Ok(origin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_ACCOUNT_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER or KUTUP_ACCOUNT_URL not set; skipping");
        return;
    };
    let s = Stack {
        c: client(),
        base: base.trim_end_matches('/').to_owned(),
        origin,
    };
    let user = register(&s.c, &s.base);
    let listed = s.keys(&user.token);
    if listed["available"] != true {
        eprintln!("security keys are off on this server; skipping");
        return;
    }
    assert_eq!(listed["keys"], json!([]));
    assert_eq!(listed["limit"], 10);

    // Adding takes the password proved again.
    let r = s.post(
        &user.token,
        "/api/auth/security-keys/register/start",
        json!({ "grant": "" }),
    );
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // The first key turns two-step sign-in on, with its recovery codes.
    let mut desk = Authenticator::new([1; 32], vec![0x11; 32]);
    let (status, added) = s.add(&user, &desk, "Desk key");
    assert_eq!(status, StatusCode::OK, "{added}");
    assert_eq!(added["key"]["name"], "Desk key");
    let codes = added["recoveryCodes"].as_array().expect("codes").clone();
    assert_eq!(codes.len(), 16);
    // The same key again: refused (the options exclude it too).
    let (status, body) = s.add(&user, &desk, "Again");
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "securityKeyExists");
    // A second key: no new codes.
    let mut spare = Authenticator::new([2; 32], vec![0x22; 32]);
    let (status, added) = s.add(&user, &spare, "Spare");
    assert_eq!(status, StatusCode::OK, "{added}");
    assert!(added.get("recoveryCodes").is_none());
    // An answer from another origin is refused.
    let grant = reauth_grant(&s.c, &s.base, &user, "totp");
    let options: Value = s
        .post(
            &user.token,
            "/api/auth/security-keys/register/start",
            json!({ "grant": grant }),
        )
        .json()
        .unwrap();
    let other = Authenticator::new([3; 32], vec![0x33; 32]);
    let credential: Value = serde_json::from_slice(&other.register(
        &options.to_string(),
        &rp_id(&options),
        "https://evil.example",
    ))
    .unwrap();
    let r = s.post(
        &user.token,
        "/api/auth/security-keys/register/finish",
        json!({ "name": "Evil", "credential": credential }),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Signing in: the password, then a key.
    let first = sign_in(&s.c, &s.base, &user.username, &user.password);
    assert_eq!(
        first["secondFactors"],
        json!(["securityKey", "recoveryCode"])
    );
    let (status, session) = s.sign_in_with(&user, &mut desk, true);
    assert_eq!(status, StatusCode::OK, "{session}");
    assert!(session["accessToken"].is_string());

    // A clone answering with a counter that did not move: refused, and the
    // key marked compromised; the other key still signs in.
    let (status, body) = s.sign_in_with(&user, &mut desk, false);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "securityKeyCompromised");
    let listed = s.keys(&user.token);
    let compromised: Vec<&Value> = listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["compromised"] == true)
        .collect();
    assert_eq!(compromised.len(), 1);
    assert_eq!(compromised[0]["name"], "Desk key");
    let (status, _) = s.sign_in_with(&user, &mut spare, true);
    assert_eq!(status, StatusCode::OK);

    // Renaming.
    let spare_id = listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["name"] == "Spare")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = bearer(
        s.c.patch(format!("{}/api/auth/security-keys/{spare_id}", s.base)),
        &user.token,
    )
    .json(&json!({ "name": "Spare (drawer)" }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // "Require PIN": a key that doesn't verify its user is refused, one
    // that does signs in.
    let grant = reauth_grant(&s.c, &s.base, &user, "totp");
    let r = bearer(
        s.c.put(format!("{}/api/auth/security-keys/require-uv", s.base)),
        &user.token,
    )
    .json(&json!({ "grant": grant, "requireUv": true }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let (status, _) = s.sign_in_with(&user, &mut spare, true);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    spare.verifies_user = true;
    let (status, _) = s.sign_in_with(&user, &mut spare, true);
    assert_eq!(status, StatusCode::OK);

    // Removing keys takes the password and the factor proved again (here,
    // with the key itself); the last factor's removal turns it all off.
    let desk_id = compromised[0]["id"].as_str().unwrap().to_owned();
    let remove = |id: &str, body: Value| {
        bearer(
            s.c.delete(format!("{}/api/auth/security-keys/{id}", s.base)),
            &user.token,
        )
        .json(&body)
        .send()
        .unwrap()
    };
    let grant = reauth_grant(&s.c, &s.base, &user, "totp");
    assert_eq!(
        remove(&desk_id, json!({ "grant": grant, "code": "000000" })).status(),
        StatusCode::BAD_REQUEST
    );
    let grant = reauth_grant(&s.c, &s.base, &user, "totp");
    let proof = s.proof(&user, &mut spare);
    let r = remove(&desk_id, json!({ "grant": grant, "securityKey": proof }));
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["twoFactorOff"], false);
    // The same answer again: its ceremony was taken, so it is refused.
    let grant = reauth_grant(&s.c, &s.base, &user, "totp");
    let r = remove(&spare_id, json!({ "grant": grant, "securityKey": proof }));
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let grant = reauth_grant(&s.c, &s.base, &user, "totp");
    let r = remove(
        &spare_id,
        json!({ "grant": grant, "code": codes[0].as_str().unwrap() }),
    );
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["twoFactorOff"], true);
    let session = sign_in(&s.c, &s.base, &user.username, &user.password);
    assert!(
        session["accessToken"].is_string(),
        "no second step: {session}"
    );
    assert_eq!(s.keys(&user.token)["keys"], json!([]));

    // Every step is in the security log.
    let kinds: Vec<String> = security_events(&s.c, &s.base, &user.token, "")["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap().to_owned())
        .collect();
    for kind in [
        "securityKeyAdded",
        "twoFactorOn",
        "securityKeyCompromised",
        "securityKeyRemoved",
        "twoFactorOff",
    ] {
        assert!(kinds.iter().any(|k| k == kind), "{kind} in {kinds:?}");
    }
    purge_accounts(&s.c, &s.base, &[&user]);
}
