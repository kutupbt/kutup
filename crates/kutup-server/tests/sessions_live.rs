//! Live e2e for server-side sessions and session forking
//! (`docs/plans/multi-app-web-rewrite.md`).
//!
//! Drives a running server over HTTP: sign-in per client type, refresh-token
//! rotation (cookie for web, body for the CLI) and its grace window, the fork
//! hand-off between the account app and a child app (origin binding, single
//! use, client-type binding), local keys, immediate revocation on sign-out
//! across parent and child, and "sign out everywhere else".
//!
//! Gated on `KUTUP_LIVE_SERVER` so a normal `cargo test` skips it:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test sessions_live -- --nocapture

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// The `refresh_token` cookie value a response set, if any.
fn set_refresh_cookie(r: &Response) -> Option<String> {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix("refresh_token="))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
}

struct Account {
    email: String,
    login_key: String,
}

fn register(c: &Client, base: &str) -> Account {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("sessions-{ts}@example.com");
    let username = format!("sess{}", ts % 1_000_000);
    let password = "sessions-pw-123456";
    let mut rng = rand::thread_rng();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut salt);
    let keys = kutup_crypto::kdf::derive_account_protection_keys(
        password,
        &salt,
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    let recovery_proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, &email).unwrap();
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap();
    use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
    let seal = |plain: &[u8], key: &[u8], purpose| {
        account_envelope::seal_b64(plain, key, purpose, &email).unwrap()
    };
    let reg = json!({
        "email": email, "username": username,
        "loginKey": b64(keys.login_key.as_slice()),
        "masterKeyEnvelope": seal(&master_key, keys.key_encryption_key.as_slice(), AccountEnvelopePurpose::PasswordMasterKey),
        "recoveryKeyEnvelope": seal(&master_key, &recovery_entropy, AccountEnvelopePurpose::RecoveryMasterKey),
        "drivePrivateKeyEnvelope": seal(identity.drive_hpke_private_key(), &master_key, AccountEnvelopePurpose::DriveHpkePrivateKey),
        "publicKey": b64(&identity.drive_hpke_public_key()),
        "accountAuthorityPublicKey": b64(&identity.authority_public_key()),
        "accountAuthorityKeyId": identity.authority_key_id(),
        "accountIncarnationId": identity.incarnation_id(),
        "driveSigningPublicKey": b64(&identity.drive_signing_public_key()),
        "accountProtectionSuite": 1,
        "accountProtectionSalt": b64(&salt),
        "argonMemoryKib": 65536, "argonIterations": 3, "argonParallelism": 1,
        "recoveryProof": b64(recovery_proof.as_slice()),
    });
    let r = c
        .post(format!("{base}/api/auth/register"))
        .json(&reg)
        .send()
        .unwrap();
    assert!(r.status().is_success(), "register: {}", r.status());
    Account {
        email,
        login_key: b64(keys.login_key.as_slice()),
    }
}

fn login(c: &Client, base: &str, a: &Account, client_type: Option<&str>) -> Response {
    let mut req = c
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "email": a.email, "loginKey": a.login_key }));
    if let Some(ct) = client_type {
        req = req.header("x-kutup-client", ct);
    }
    req.send().unwrap()
}

fn bearer(req: RequestBuilder, token: &str) -> RequestBuilder {
    req.header("authorization", format!("Bearer {token}"))
}

fn me_status(c: &Client, base: &str, token: &str) -> StatusCode {
    bearer(c.get(format!("{base}/api/user/me")), token)
        .send()
        .unwrap()
        .status()
}

fn refresh_with_cookie(c: &Client, base: &str, cookie: &str) -> Response {
    c.post(format!("{base}/api/auth/refresh"))
        .header("cookie", format!("refresh_token={cookie}"))
        .send()
        .unwrap()
}

#[test]
fn sessions_and_forks_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let drive_origin = settings["apps"]["drive"].as_str().unwrap().to_string();
    let chat_origin = settings["apps"]["chat"].as_str().unwrap().to_string();

    let account = register(&c, &base);

    // --- Sign-in requires a known, directly-signing-in client type.
    assert_eq!(
        login(&c, &base, &account, None).status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        login(&c, &base, &account, Some("web-drive")).status(),
        StatusCode::BAD_REQUEST,
        "drive signs in through the account app, never with a password"
    );

    // --- Web sign-in: refresh token only as an HttpOnly cookie.
    let r = login(&c, &base, &account, Some("web-account"));
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = set_refresh_cookie(&r).expect("web login sets the refresh cookie");
    let body: Value = r.json().unwrap();
    assert!(
        body.get("refreshToken").is_none(),
        "web tokens never go in the body"
    );
    let account_token = body["accessToken"].as_str().unwrap().to_string();
    let account_session = body["sessionId"].as_str().unwrap().to_string();
    assert_eq!(me_status(&c, &base, &account_token), StatusCode::OK);

    // --- Rotation: a refresh mints a new cookie; the old one still works once
    //     within the grace window (a second tab) but rotates nothing.
    let r = refresh_with_cookie(&c, &base, &cookie);
    assert_eq!(r.status(), StatusCode::OK);
    let rotated = set_refresh_cookie(&r).expect("rotation sets a new cookie");
    assert_ne!(rotated, cookie);
    let r = refresh_with_cookie(&c, &base, &cookie);
    assert_eq!(r.status(), StatusCode::OK, "grace window");
    assert!(
        set_refresh_cookie(&r).is_none(),
        "grace does not rotate again"
    );
    let account_cookie = rotated;
    // A CLI-style body refresh of a web token is refused.
    let r = c
        .post(format!("{base}/api/auth/refresh"))
        .json(&json!({ "refreshToken": account_cookie }))
        .send()
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "web tokens only via cookie"
    );
    // …and the refused attempt must not have rotated the session away from its
    // cookie: the cookie still rotates normally (not merely the grace path).
    let r = refresh_with_cookie(&c, &base, &account_cookie);
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        set_refresh_cookie(&r).is_some(),
        "a wrong-transport refresh must not rotate the token"
    );

    // --- Fork account → drive.
    let payload = b64(b"opaque local-state envelope");
    let fork = |child: &str| -> Value {
        let r = bearer(c.post(format!("{base}/api/auth/forks")), &account_token)
            .json(&json!({ "childClientType": child, "payload": payload }))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "create fork for {child}");
        r.json().unwrap()
    };
    let created = fork("web-drive");
    assert_eq!(created["childOrigin"].as_str().unwrap(), drive_origin);
    let selector = created["selector"].as_str().unwrap().to_string();
    let consume = |selector: &str, client_type: &str, origin: &str| -> Response {
        c.post(format!("{base}/api/auth/forks/consume"))
            .header("x-kutup-client", client_type)
            .header("origin", origin)
            .json(&json!({ "selector": selector }))
            .send()
            .unwrap()
    };
    // Wrong origin: refused before the fork is touched.
    assert_eq!(
        consume(&selector, "web-drive", &chat_origin).status(),
        StatusCode::FORBIDDEN
    );
    let r = consume(&selector, "web-drive", &drive_origin);
    assert_eq!(r.status(), StatusCode::OK);
    let drive_cookie = set_refresh_cookie(&r).expect("child gets its own cookie");
    let child: Value = r.json().unwrap();
    assert_eq!(child["payload"].as_str().unwrap(), payload);
    let drive_token = child["accessToken"].as_str().unwrap().to_string();
    let drive_session = child["sessionId"].as_str().unwrap().to_string();
    assert_ne!(drive_session, account_session);
    assert_eq!(me_status(&c, &base, &drive_token), StatusCode::OK);
    // Single use.
    assert_eq!(
        consume(&selector, "web-drive", &drive_origin).status(),
        StatusCode::UNAUTHORIZED
    );
    // A fork minted for chat does not open as drive.
    let chat_fork = fork("web-chat");
    assert_eq!(
        consume(
            chat_fork["selector"].as_str().unwrap(),
            "web-drive",
            &drive_origin
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Only the account app forks.
    let r = bearer(c.post(format!("{base}/api/auth/forks")), &drive_token)
        .json(&json!({ "childClientType": "web-chat", "payload": payload }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // --- Local key for the child's persisted blob.
    let key = b64(&[7u8; 32]);
    let r = bearer(
        c.put(format!("{base}/api/auth/sessions/current/local-key")),
        &drive_token,
    )
    .json(&json!({ "key": key }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let got: Value = bearer(
        c.get(format!("{base}/api/auth/sessions/current/local-key")),
        &drive_token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(got["key"].as_str().unwrap(), key);

    // --- The session list shows the sign-in as one family.
    let list: Value = bearer(c.get(format!("{base}/api/auth/sessions")), &account_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let list = list.as_array().unwrap();
    let find = |id: &str| list.iter().find(|s| s["id"] == id).cloned().unwrap();
    assert_eq!(find(&account_session)["clientType"], "web-account");
    assert_eq!(find(&drive_session)["clientType"], "web-drive");
    assert_eq!(find(&drive_session)["parentId"], account_session.as_str());
    assert_eq!(find(&drive_session)["current"], true);

    // --- CLI: tokens in the body; rotation hands back the next one.
    let r = login(&c, &base, &account, Some("cli"));
    assert_eq!(r.status(), StatusCode::OK);
    assert!(set_refresh_cookie(&r).is_none(), "the CLI gets no cookie");
    let cli: Value = r.json().unwrap();
    let cli_token = cli["accessToken"].as_str().unwrap().to_string();
    let cli_refresh = cli["refreshToken"].as_str().unwrap().to_string();
    let r = c
        .post(format!("{base}/api/auth/refresh"))
        .json(&json!({ "refreshToken": cli_refresh }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let next: Value = r.json().unwrap();
    assert_ne!(next["refreshToken"].as_str().unwrap(), cli_refresh);
    // CLI sessions hold no local key.
    let r = bearer(
        c.put(format!("{base}/api/auth/sessions/current/local-key")),
        &cli_token,
    )
    .json(&json!({ "key": key }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // --- "Sign out everywhere else" from the CLI ends the web sign-in, keeps the CLI.
    let r = bearer(c.delete(format!("{base}/api/auth/sessions")), &cli_token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(me_status(&c, &base, &cli_token), StatusCode::OK);
    assert_eq!(
        me_status(&c, &base, &account_token),
        StatusCode::UNAUTHORIZED,
        "revocation is immediate"
    );
    assert_eq!(
        me_status(&c, &base, &drive_token),
        StatusCode::UNAUTHORIZED,
        "children go with the parent"
    );
    let r = refresh_with_cookie(&c, &base, &drive_cookie);
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(
        r.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("refresh_token=;")),
        "a failed web refresh clears the cookie"
    );

    // --- Sign-out from a child ends the whole sign-in (parent and siblings).
    let r = login(&c, &base, &account, Some("web-account"));
    let body: Value = r.json().unwrap();
    let account_token = body["accessToken"].as_str().unwrap().to_string();
    let created = bearer(c.post(format!("{base}/api/auth/forks")), &account_token)
        .json(&json!({ "childClientType": "web-chat", "payload": payload }))
        .send()
        .unwrap()
        .json::<Value>()
        .unwrap();
    let child: Value = consume(
        created["selector"].as_str().unwrap(),
        "web-chat",
        &chat_origin,
    )
    .json()
    .unwrap();
    let chat_token = child["accessToken"].as_str().unwrap().to_string();
    let r = bearer(c.post(format!("{base}/api/auth/logout")), &chat_token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(me_status(&c, &base, &chat_token), StatusCode::UNAUTHORIZED);
    assert_eq!(
        me_status(&c, &base, &account_token),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        me_status(&c, &base, &cli_token),
        StatusCode::OK,
        "other sign-ins survive"
    );
}
