//! Live e2e for security keys as a second factor
//! (docs/plans/security-keys.md §9), with a software authenticator
//! (kutup_crypto::webauthn::soft): adding keys (the first turns two-step
//! sign-in on, with recovery codes; later ones take a factor proved again),
//! the limit, duplicates and names, signing in with a key, answers bound to
//! their ceremony and account, a cloned key's counter (and a key used in two
//! tabs), renaming, "Require PIN", proving the factor with a key, the
//! recovery phrase, and removing the last factor.
//!
//! Gated on `KUTUP_LIVE_SERVER` and `KUTUP_ACCOUNT_URL` (the account app's
//! origin, which keys are bound to); the expired ceremony also needs
//! `KUTUP_LIVE_DATABASE_URL`:
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

/// The stack, or `None` (and why) when the live variables aren't set or the
/// server has security keys off.
fn stack() -> Option<Stack> {
    let (Ok(base), Ok(origin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_ACCOUNT_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER or KUTUP_ACCOUNT_URL not set; skipping");
        return None;
    };
    let s = Stack {
        c: client(),
        base: base.trim_end_matches('/').to_owned(),
        origin,
    };
    let probe = register(&s.c, &s.base);
    let available = s.keys(&probe.token)["available"] == true;
    purge_accounts(&s.c, &s.base, &[&probe]);
    if !available {
        eprintln!("security keys are off on this server; skipping");
        return None;
    }
    Some(s)
}

/// A software key with a credential id of its own (ids are unique across
/// accounts, so runs never meet one another's).
fn new_key(seed: u8) -> Authenticator {
    let mut credential_id = uuid::Uuid::new_v4().as_bytes().to_vec();
    credential_id.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    Authenticator::new([seed; 32], credential_id)
}

fn rp_id(options: &Value) -> String {
    let options = options.get("publicKey").unwrap_or(options);
    options["rp"]["id"]
        .as_str()
        .or_else(|| options["rpId"].as_str())
        .expect("options name the RP")
        .to_owned()
}

fn status_and_body(r: Response) -> (StatusCode, Value) {
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
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

    fn key_id(&self, user: &User, name: &str) -> String {
        self.keys(&user.token)["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["name"] == name)
            .unwrap_or_else(|| panic!("a key named {name}"))["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `register/start` with a fresh grant and `proof` (`{}`, `{"code": …}`
    /// or `{"securityKey": …}`).
    fn register_start(&self, user: &User, proof: Value) -> (StatusCode, Value) {
        let mut body = proof;
        body["grant"] = json!(reauth_grant(&self.c, &self.base, user, "totp"));
        status_and_body(self.post(&user.token, "/api/auth/security-keys/register/start", body))
    }

    fn register_finish(
        &self,
        user: &User,
        options: &Value,
        authenticator: &Authenticator,
        origin: &str,
        name: &str,
    ) -> (StatusCode, Value) {
        let credential: Value = serde_json::from_slice(&authenticator.register(
            &options.to_string(),
            &rp_id(options),
            origin,
        ))
        .unwrap();
        status_and_body(self.post(
            &user.token,
            "/api/auth/security-keys/register/finish",
            json!({ "name": name, "credential": credential }),
        ))
    }

    /// Adds a key with `authenticator` and `proof`: the status and body of
    /// the start when it fails, else of the finish.
    fn add(
        &self,
        user: &User,
        authenticator: &Authenticator,
        name: &str,
        proof: Value,
    ) -> (StatusCode, Value) {
        let (status, options) = self.register_start(user, proof);
        if status != StatusCode::OK {
            return (status, options);
        }
        self.register_finish(user, &options, authenticator, &self.origin, name)
    }

    /// A sign-in's first step: its pre-auth token.
    fn first_step(&self, user: &User) -> String {
        let first = sign_in(&self.c, &self.base, &user.username, &user.password);
        assert_eq!(first["requiresTotp"], true, "a second step: {first}");
        first["preAuthToken"].as_str().unwrap().to_owned()
    }

    /// The options of a sign-in's security-key step.
    fn sign_in_options(&self, pre_auth: &str) -> Value {
        let r = self
            .c
            .post(format!("{}/api/auth/login/security-key/start", self.base))
            .json(&json!({ "preAuthToken": pre_auth }))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        r.json().unwrap()
    }

    fn sign_in_finish(&self, pre_auth: &str, credential: &Value) -> (StatusCode, Value) {
        status_and_body(
            self.c
                .post(format!("{}/api/auth/login/security-key/finish", self.base))
                .header("x-kutup-client", "cli")
                .json(&json!({ "preAuthToken": pre_auth, "credential": credential }))
                .send()
                .unwrap(),
        )
    }

    /// An answer to `options` (moving the counter on, or not, as a clone
    /// would).
    fn answer(
        &self,
        options: &Value,
        authenticator: &mut Authenticator,
        move_counter: bool,
    ) -> Value {
        let rp_id = rp_id(options);
        let answer = if move_counter {
            authenticator.assert(&options.to_string(), &rp_id, &self.origin)
        } else {
            authenticator.assert_at(&options.to_string(), &rp_id, &self.origin)
        };
        serde_json::from_slice(&answer).unwrap()
    }

    /// A whole sign-in's second step with `authenticator`: the status and
    /// body, and the answer it sent.
    fn sign_in_with(
        &self,
        user: &User,
        authenticator: &mut Authenticator,
        move_counter: bool,
    ) -> (StatusCode, Value, String, Value) {
        let pre_auth = self.first_step(user);
        let options = self.sign_in_options(&pre_auth);
        let credential = self.answer(&options, authenticator, move_counter);
        let (status, body) = self.sign_in_finish(&pre_auth, &credential);
        (status, body, pre_auth, credential)
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
        self.answer(&options, authenticator, true)
    }

    fn remove(&self, user: &User, id: &str, proof: Value) -> Response {
        let mut body = proof;
        body["grant"] = json!(reauth_grant(&self.c, &self.base, user, "totp"));
        bearer(
            self.c
                .delete(format!("{}/api/auth/security-keys/{id}", self.base)),
            &user.token,
        )
        .json(&body)
        .send()
        .unwrap()
    }

    fn require_uv(&self, user: &User, on: bool, proof: Value) -> StatusCode {
        let mut body = proof;
        body["grant"] = json!(reauth_grant(&self.c, &self.base, user, "totp"));
        body["requireUv"] = json!(on);
        bearer(
            self.c
                .put(format!("{}/api/auth/security-keys/require-uv", self.base)),
            &user.token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    }

    fn session_version(&self, token: &str) -> String {
        bearer(self.c.get(format!("{}/api/user/me", self.base)), token)
            .send()
            .unwrap()
            .headers()
            .get("x-kutup-session-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .expect("session version header")
    }

    /// The first key: two-step sign-in turns on, with its recovery codes.
    fn first_key(&self, user: &User, authenticator: &Authenticator) -> Vec<String> {
        let (status, added) = self.add(user, authenticator, "Desk key", json!({}));
        assert_eq!(status, StatusCode::OK, "{added}");
        added["recoveryCodes"]
            .as_array()
            .expect("codes")
            .iter()
            .map(|code| code.as_str().unwrap().to_owned())
            .collect()
    }
}

#[test]
fn security_keys_add_sign_in_and_go() {
    let Some(s) = stack() else { return };
    let user = register(&s.c, &s.base);
    let listed = s.keys(&user.token);
    assert_eq!(listed["keys"], json!([]));
    assert_eq!(listed["limit"], 10);

    // Adding takes the password proved again.
    let r = s.post(
        &user.token,
        "/api/auth/security-keys/register/start",
        json!({ "grant": "" }),
    );
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // The first key turns two-step sign-in on, with its recovery codes, and
    // the account's other sessions see a new version.
    let other_session = sign_in(&s.c, &s.base, &user.username, &user.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = s.session_version(&other_session);
    let mut desk = new_key(1);
    let codes = s.first_key(&user, &desk);
    assert_eq!(codes.len(), 16);
    assert_ne!(s.session_version(&other_session), before);
    // The same key again: refused (the options exclude it too).
    let proof = s.proof(&user, &mut desk);
    let (status, body) = s.add(&user, &desk, "Again", json!({ "securityKey": proof }));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "securityKeyExists");
    // A second key, with the first proved: no new codes.
    let mut spare = new_key(2);
    let proof = s.proof(&user, &mut desk);
    let (status, added) = s.add(&user, &spare, "Spare", json!({ "securityKey": proof }));
    assert_eq!(status, StatusCode::OK, "{added}");
    assert!(added.get("recoveryCodes").is_none());
    // An answer from another origin is refused.
    let proof = s.proof(&user, &mut desk);
    let (status, options) = s.register_start(&user, json!({ "securityKey": proof }));
    assert_eq!(status, StatusCode::OK);
    let (status, _) =
        s.register_finish(&user, &options, &new_key(3), "https://evil.example", "Evil");
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Signing in: the password, then a key.
    let first = sign_in(&s.c, &s.base, &user.username, &user.password);
    assert_eq!(
        first["secondFactors"],
        json!(["securityKey", "recoveryCode"])
    );
    let (status, session, _, _) = s.sign_in_with(&user, &mut desk, true);
    assert_eq!(status, StatusCode::OK, "{session}");
    assert!(session["accessToken"].is_string());

    // A clone answering with a counter that did not move (and no other use
    // of the key in flight): refused, and the key marked compromised; the
    // other key still signs in.
    let (status, body, _, _) = s.sign_in_with(&user, &mut desk, false);
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
    let desk_id = compromised[0]["id"].as_str().unwrap().to_owned();
    let (status, _, _, _) = s.sign_in_with(&user, &mut spare, true);
    assert_eq!(status, StatusCode::OK);

    // Renaming.
    let spare_id = s.key_id(&user, "Spare");
    let rename = |name: &str| {
        bearer(
            s.c.patch(format!("{}/api/auth/security-keys/{spare_id}", s.base)),
            &user.token,
        )
        .json(&json!({ "name": name }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(rename("Spare (drawer)"), StatusCode::NO_CONTENT);
    // Control and format characters (a bidi override) are refused.
    assert_eq!(rename("Spare\u{202e}reward"), StatusCode::BAD_REQUEST);
    assert_eq!(rename("Spare\u{7}"), StatusCode::BAD_REQUEST);
    // An emoji sequence's zero-width joiner is not.
    assert_eq!(
        rename("Spare \u{1f9d1}\u{200d}\u{1f4bb}"),
        StatusCode::NO_CONTENT
    );

    // "Require PIN": a key that doesn't verify its user is refused, one
    // that does signs in.
    assert_eq!(s.require_uv(&user, true, json!({})), StatusCode::NO_CONTENT);
    let (status, _, _, _) = s.sign_in_with(&user, &mut spare, true);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    spare.verifies_user = true;
    let (status, _, _, _) = s.sign_in_with(&user, &mut spare, true);
    assert_eq!(status, StatusCode::OK);

    // Removing keys takes the password and the factor proved again (here,
    // with the key itself); the last factor's removal turns it all off.
    let r = s.remove(&user, &desk_id, json!({ "code": "000000" }));
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let proof = s.proof(&user, &mut spare);
    let r = s.remove(&user, &desk_id, json!({ "securityKey": proof }));
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["twoFactorOff"], false);
    // The same answer again: its ceremony was taken, so it is refused.
    let r = s.remove(&user, &spare_id, json!({ "securityKey": proof }));
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = s.remove(&user, &spare_id, json!({ "code": codes[0] }));
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["twoFactorOff"], true);
    let session = sign_in(&s.c, &s.base, &user.username, &user.password);
    assert!(
        session["accessToken"].is_string(),
        "no second step: {session}"
    );
    assert_eq!(s.keys(&user.token)["keys"], json!([]));

    // Every step is in the security log, a key's events by its name.
    let events = security_events(&s.c, &s.base, &user.token, "")["events"]
        .as_array()
        .unwrap()
        .clone();
    let kinds: Vec<String> = events
        .iter()
        .map(|event| event["kind"].as_str().unwrap().to_owned())
        .collect();
    let logged = |kind: &str, name: &str| {
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == kind && event["oldName"] == name),
            "{kind} naming {name} in {events:?}"
        );
    };
    logged("securityKeyAdded", "Desk key");
    logged("securityKeyCompromised", "Desk key");
    logged("securityKeyRemoved", "Desk key");
    logged("securityKeyRemoved", "Spare \u{1f9d1}\u{200d}\u{1f4bb}");
    for kind in ["twoFactorOn", "twoFactorOff"] {
        assert!(kinds.iter().any(|k| k == kind), "{kind} in {kinds:?}");
    }
    purge_accounts(&s.c, &s.base, &[&user]);
}

/// While two-step sign-in is on, a password and a session alone can't add a
/// factor (a key, the authenticator app) or weaken one ("Require PIN" off):
/// a factor the account has is proved again, as removing one takes.
#[test]
fn adding_a_factor_while_two_step_is_on_takes_one() {
    let Some(s) = stack() else { return };
    let user = register(&s.c, &s.base);
    // A start made while two-step sign-in was off ...
    let (status, early) = s.register_start(&user, json!({}));
    assert_eq!(status, StatusCode::OK);
    let mut desk = new_key(1);
    let codes = s.first_key(&user, &desk);
    // ... can't finish once it is on.
    let (status, body) = s.register_finish(&user, &early, &new_key(4), &s.origin, "Early");
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "secondFactorRequired");

    // A key: nothing proved, refused (the grant kept); a wrong code,
    // refused; the first key or a recovery code, added.
    let (status, body) = s.register_start(&user, json!({}));
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "secondFactorRequired");
    let (status, _) = s.register_start(&user, json!({ "code": "00000-00000" }));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let proof = s.proof(&user, &mut desk);
    let (status, body) = s.add(
        &user,
        &new_key(5),
        "Laptop",
        json!({ "securityKey": proof }),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = s.add(&user, &new_key(6), "Phone", json!({ "code": codes[0] }));
    assert_eq!(status, StatusCode::OK, "{body}");

    // The authenticator app beside the keys: its new code alone is refused;
    // with a recovery code (or a key) proved too, it joins them.
    let setup: Value = bearer(
        s.c.post(format!("{}/api/user/2fa/setup", s.base)),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let secret = setup["secret"].as_str().unwrap().to_owned();
    let verify = |extra: Value| {
        let mut body = extra;
        body["code"] = json!(totp_now(&secret));
        body["grant"] = json!(reauth_grant(&s.c, &s.base, &user, "totp"));
        status_and_body(
            bearer(
                s.c.post(format!("{}/api/user/2fa/verify", s.base)),
                &user.token,
            )
            .json(&body)
            .send()
            .unwrap(),
        )
    };
    let (status, body) = verify(json!({}));
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "secondFactorRequired");
    let (status, body) = verify(json!({ "recoveryCode": codes[1] }));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recoveryCodes"], json!([]));

    // "Require PIN": on with the password; off takes a factor too.
    assert_eq!(s.require_uv(&user, true, json!({})), StatusCode::NO_CONTENT);
    assert_eq!(s.require_uv(&user, false, json!({})), StatusCode::FORBIDDEN);
    assert_eq!(
        s.require_uv(&user, false, json!({ "code": totp_now(&secret) })),
        StatusCode::NO_CONTENT
    );
    purge_accounts(&s.c, &s.base, &[&user]);
}

/// A sign-in's answer is good once, for its own ceremony and account.
#[test]
fn answers_are_bound_to_their_ceremony_and_account() {
    let Some(s) = stack() else { return };
    let alice = register(&s.c, &s.base);
    let bob = register(&s.c, &s.base);
    let mut alices = new_key(1);
    let mut bobs = new_key(2);
    s.first_key(&alice, &alices);
    s.first_key(&bob, &bobs);

    // Replayed: the ceremony was taken by the first finish.
    let (status, _, pre_auth, credential) = s.sign_in_with(&alice, &mut alices, true);
    assert_eq!(status, StatusCode::OK);
    let (status, body) = s.sign_in_finish(&pre_auth, &credential);
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Bob's key answering Alice's sign-in: not one of hers.
    let pre_auth = s.first_step(&alice);
    let options = s.sign_in_options(&pre_auth);
    let credential = s.answer(&options, &mut bobs, true);
    let (status, _) = s.sign_in_finish(&pre_auth, &credential);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Alice's answer to her own ceremony, sent with Bob's pre-auth token:
    // the ceremony is bound to hers.
    let alice_pre_auth = s.first_step(&alice);
    let options = s.sign_in_options(&alice_pre_auth);
    let credential = s.answer(&options, &mut alices, true);
    let bob_pre_auth = s.first_step(&bob);
    let (status, _) = s.sign_in_finish(&bob_pre_auth, &credential);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Still good for Alice, once.
    let (status, _) = s.sign_in_finish(&alice_pre_auth, &credential);
    assert_eq!(status, StatusCode::OK);

    // A credential Alice holds can't be added to Bob's account.
    let proof = s.proof(&bob, &mut bobs);
    let (status, body) = s.add(&bob, &alices, "Borrowed", json!({ "securityKey": proof }));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "securityKeyExists");
    purge_accounts(&s.c, &s.base, &[&alice, &bob]);
}

/// Two sign-ins in flight with one key (two tabs), finished out of order:
/// the older answer's counter is behind, but the key was used after its
/// ceremony started, so it is refused to be tried again, not flagged.
#[test]
fn a_key_used_in_two_tabs_is_retried_not_flagged() {
    let Some(s) = stack() else { return };
    let user = register(&s.c, &s.base);
    let mut desk = new_key(1);
    s.first_key(&user, &desk);
    let first_tab = s.first_step(&user);
    let first_options = s.sign_in_options(&first_tab);
    let second_tab = s.first_step(&user);
    let second_options = s.sign_in_options(&second_tab);
    let older = s.answer(&first_options, &mut desk, true);
    let newer = s.answer(&second_options, &mut desk, true);
    assert_eq!(s.sign_in_finish(&second_tab, &newer).0, StatusCode::OK);
    let (status, body) = s.sign_in_finish(&first_tab, &older);
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "securityKeyRetry");
    assert_eq!(s.keys(&user.token)["keys"][0]["compromised"], false);
    let (status, _, _, _) = s.sign_in_with(&user, &mut desk, true);
    assert_eq!(status, StatusCode::OK);
    purge_accounts(&s.c, &s.base, &[&user]);
}

/// The account's limit is reached, then refused.
#[test]
fn the_limit_is_kept() {
    let Some(s) = stack() else { return };
    let user = register(&s.c, &s.base);
    let limit = s.keys(&user.token)["limit"].as_i64().unwrap();
    let mut desk = new_key(1);
    s.first_key(&user, &desk);
    for n in 1..limit {
        let proof = s.proof(&user, &mut desk);
        let (status, body) = s.add(
            &user,
            &new_key(10 + n as u8),
            &format!("Key {n}"),
            json!({ "securityKey": proof }),
        );
        assert_eq!(status, StatusCode::OK, "key {n}: {body}");
    }
    let proof = s.proof(&user, &mut desk);
    let (status, body) = s.add(
        &user,
        &new_key(99),
        "One too many",
        json!({ "securityKey": proof }),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "securityKeyLimit");
    assert_eq!(
        s.keys(&user.token)["keys"].as_array().unwrap().len() as i64,
        limit
    );
    purge_accounts(&s.c, &s.base, &[&user]);
}

/// The recovery phrase turns every second factor off, its keys included.
#[test]
fn the_recovery_phrase_removes_the_keys() {
    let Some(s) = stack() else { return };
    let mut user = register(&s.c, &s.base);
    s.first_key(&user, &new_key(1));
    let proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&user.recovery_entropy, &user.binding)
            .unwrap();
    let granted: Value =
        s.c.post(format!("{}/api/auth/recover/grant", s.base))
            .json(&json!({ "name": user.username, "recoveryProof": b64(proof.as_slice()) }))
            .send()
            .unwrap()
            .json()
            .unwrap();
    let grant = granted["grant"].as_str().unwrap().to_owned();
    let new_password = "recovered-security-keys-445566";
    assert_eq!(
        set_password(&s.c, &s.base, &user, &grant, None, new_password),
        StatusCode::NO_CONTENT
    );
    user.password = new_password.to_owned();
    let session = sign_in(&s.c, &s.base, &user.username, &user.password);
    user.token = session["accessToken"]
        .as_str()
        .unwrap_or_else(|| panic!("no second step after the phrase: {session}"))
        .to_owned();
    assert_eq!(s.keys(&user.token)["keys"], json!([]));
    purge_accounts(&s.c, &s.base, &[&user]);
}

/// A ceremony past its time is refused. Needs `KUTUP_LIVE_DATABASE_URL`, to
/// age it rather than wait.
#[test]
fn an_expired_ceremony_is_refused() {
    let Ok(database_url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
        eprintln!("KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let Some(s) = stack() else { return };
    let user = register(&s.c, &s.base);
    let mut desk = new_key(1);
    s.first_key(&user, &desk);
    let pre_auth = s.first_step(&user);
    let options = s.sign_in_options(&pre_auth);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let aged = runtime
        .block_on(
            sqlx::query(
                "UPDATE webauthn_ceremonies SET expires_at = now() - interval '1 second'
                 WHERE user_id = $1::uuid AND kind = 'signIn'",
            )
            .bind(&user.id)
            .execute(&pool),
        )
        .unwrap();
    assert_eq!(aged.rows_affected(), 1);
    let credential = s.answer(&options, &mut desk, true);
    let (status, _) = s.sign_in_finish(&pre_auth, &credential);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    purge_accounts(&s.c, &s.base, &[&user]);
}

/// An administrator lowering an account's own key limit below the keys it
/// has (docs/plans/settings-registry.md): they all stay and still sign in,
/// and no new one is added. Needs `KUTUP_LIVE_ADMIN` too.
#[test]
fn a_lowered_key_limit_keeps_the_keys() {
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let Some(s) = stack() else { return };
    let (name, password) = admin.split_once(':').expect("username:password");
    let admin_token = admin_token(&s.c, &s.base, password, name);
    let user = register(&s.c, &s.base);
    let id = me(&s.c, &s.base, &user.token)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut desk = new_key(1);
    s.first_key(&user, &desk);
    let proof = s.proof(&user, &mut desk);
    let (status, body) = s.add(&user, &new_key(2), "Spare", json!({ "securityKey": proof }));
    assert_eq!(status, StatusCode::OK, "{body}");

    let r = bearer(
        s.c.put(format!(
            "{}/api/admin/users/{id}/limits/security_keys_per_account",
            s.base
        )),
        &admin_token,
    )
    .json(&json!({ "value": 1 }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let listed = s.keys(&user.token);
    assert_eq!(listed["limit"], 1);
    assert_eq!(listed["keys"].as_array().unwrap().len(), 2);
    let proof = s.proof(&user, &mut desk);
    let (status, body) = s.add(&user, &new_key(3), "Third", json!({ "securityKey": proof }));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "securityKeyLimit");
    let (status, _, _, _) = s.sign_in_with(&user, &mut desk, true);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s.keys(&user.token)["keys"].as_array().unwrap().len(), 2);
    purge_accounts(&s.c, &s.base, &[&user]);
}
