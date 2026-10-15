//! One identity per account (docs/plans/account-identity.md), against a live
//! server: accounts sign in by username or Kutup address, their keys are
//! bound to a key binding told only with a session, and names that are no
//! account get answers no one can tell from real ones.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` for temporary passwords).

mod common;

use common::{b64, bearer, opaque_login, register, sign_in};
use reqwest::blocking::{Client, Response};
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// One sign-in attempt from a given client (`x-real-ip`, a cookie), as the
/// web account app makes it: `login/start`, then, if the password opens the
/// answer, `login/finish`. The start's response when it is refused or the
/// password is wrong (the client never finishes then), else the finish's.
fn attempt(
    c: &Client,
    base: &str,
    name: &str,
    password: &str,
    ip: &str,
    cookie: Option<&str>,
) -> Response {
    let request = |path: &str, body: Value| {
        let mut request = c
            .post(format!("{base}/api/auth/{path}"))
            .header("x-kutup-client", "web-account")
            .header("x-real-ip", ip)
            .json(&body);
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        request.send().unwrap()
    };
    let (signing_in, ke1) = kutup_crypto::opaque::client_login_start(password).unwrap();
    let started = request(
        "login/start",
        json!({ "name": name, "credentialRequest": b64(&ke1) }),
    );
    if !started.status().is_success() {
        return started;
    }
    let body: Value = started.json().unwrap();
    let ke2 = common::b64_decode(body["credentialResponse"].as_str().unwrap());
    let Ok(signed_in) = signing_in.finish(&ke2) else {
        // A wrong password: the client stops; the start was the attempt.
        return request(
            "login/finish",
            json!({ "loginId": body["loginId"], "credentialFinalization": b64(&[0u8; 64]) }),
        );
    };
    request(
        "login/finish",
        json!({ "loginId": body["loginId"], "credentialFinalization": b64(&signed_in.finalization) }),
    )
}

#[test]
fn an_account_signs_in_by_its_name_and_its_keys_carry_its_key_binding() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    // By username or by address; the binding comes with the session.
    for name in [user.username.clone(), user.account.clone()] {
        let session = sign_in(&c, &base, &name, &user.password);
        assert_eq!(session["keyBinding"], user.binding.as_str(), "{name}");
    }
    assert_eq!(
        common::me(&c, &base, &user.token)["envelopeBinding"],
        user.binding.as_str()
    );
    // The same name at another domain is no one here: its answer cannot be
    // finished with the account's password.
    let elsewhere = format!("{}@elsewhere.example", user.username);
    let (status, _, _) = opaque_login(&c, &base, &elsewhere, &user.password, "session", None, None);
    assert_eq!(status, 401);
    // A wrong password: nothing to finish.
    let (status, _, _) = opaque_login(
        &c,
        &base,
        &user.username,
        "wrong-password",
        "session",
        None,
        None,
    );
    assert_eq!(status, 401);
    // The login preflight is gone: OPAQUE gives out nothing before the
    // exchange.
    let gone = c
        .get(format!("{base}/api/auth/login/preflight"))
        .query(&[("name", &user.username)])
        .send()
        .unwrap();
    assert!(
        gone.status() == 404 || gone.status() == 405,
        "{}",
        gone.status()
    );
    common::purge_accounts(&c, &base, &[&user]);
}

#[test]
fn unknown_names_look_like_accounts() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let name = format!("nobody{}", uuid::Uuid::new_v4().simple());
    let start = |name: &str| -> Value {
        let (_, ke1) = kutup_crypto::opaque::client_login_start("any password").unwrap();
        let r = c
            .post(format!("{base}/api/auth/login/start"))
            .header("x-kutup-client", "cli")
            .json(&json!({ "name": name, "credentialRequest": b64(&ke1) }))
            .send()
            .unwrap();
        assert_eq!(r.status(), 200, "{name}");
        r.json().unwrap()
    };
    // An answer of a real account's shape and size, nothing more.
    let account = register(&c, &base);
    let real = start(&account.username);
    let fake = start(&name);
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&fake), keys(&real));
    assert_eq!(
        fake["credentialResponse"].as_str().unwrap().len(),
        real["credentialResponse"].as_str().unwrap().len()
    );
    assert!(fake.get("keyBinding").is_none() && real.get("keyBinding").is_none());
    // At this server's address, the same as by name; it never finishes.
    let domain = account.account.split_once('@').unwrap().1.to_string();
    let at_domain = format!("{name}@{domain}");
    assert_eq!(keys(&start(&at_domain)), keys(&fake));
    let (status, _, _) = opaque_login(&c, &base, &name, "any password", "session", None, None);
    assert_eq!(status, 401);
    // A recovery's preflight: a key binding's shape and an envelope, the same
    // each time, and for the address as for the name.
    let preflight = |name: &str| -> Value {
        c.get(format!("{base}/api/auth/recover/preflight"))
            .query(&[("name", name)])
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let recovery = preflight(&name);
    assert_eq!(recovery, preflight(&name));
    assert_eq!(preflight(&at_domain), recovery);
    let binding = recovery["envelopeBinding"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(binding).is_ok_and(|id| id.get_version_num() == 4));
    // A recovery grant for it is refused as a wrong phrase is.
    let r = c
        .post(format!("{base}/api/auth/recover/grant"))
        .json(&json!({ "name": name, "recoveryProof": b64(&[3u8; 32]) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), 401);
    common::purge_accounts(&c, &base, &[&account]);
}

/// An administrator's temporary password never reaches the server (review
/// H1): the administrator's client registers it with OPAQUE under a key
/// binding it draws, and sign-in is the same exchange as anyone's. Rotating
/// or wiping takes the administrator's fresh proof for that account (a
/// reset grant). The break-glass administrator is known by its username.
#[test]
fn temporary_passwords_are_registered_by_the_administrators_client() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let (admin_name, admin_password) = admin
        .split_once(':')
        .expect("KUTUP_LIVE_ADMIN is username:password");
    let token = common::admin_token(&c, &base, admin_password, admin_name);
    let username = format!("tmp{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let create = |body: Value| {
        bearer(c.post(format!("{base}/api/admin/users")), &token)
            .json(&body)
            .send()
            .unwrap()
            .status()
            .as_u16()
    };
    // A password itself is not taken.
    assert_eq!(
        create(json!({ "username": username, "tempPassword": "Temporary*Password123" })),
        400
    );
    let mut body = common::temp_registration(&c, &base, "Temporary*Password123", &token, None);
    body["username"] = json!(username);
    assert_eq!(create(body), 201);
    // Only an administrator registers for a new account that way.
    let stranger = register(&c, &base);
    let (registering, request) = kutup_crypto::opaque::client_registration_start("x").unwrap();
    drop(registering);
    let r = bearer(
        c.post(format!("{base}/api/auth/opaque/register/start")),
        &stranger.token,
    )
    .json(&json!({
        "keyBinding": uuid::Uuid::new_v4().to_string(),
        "registrationRequest": b64(&request),
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 403);
    let users: Vec<Value> = bearer(c.get(format!("{base}/api/admin/users")), &token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let id_of = |name: &str| {
        users
            .iter()
            .find(|u| u["username"] == name)
            .unwrap_or_else(|| panic!("{name} listed"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let id = id_of(&username);
    let login =
        |password: &str| opaque_login(&c, &base, &username, password, "session", None, None);
    // A wrong password fails; the right one asks for setup.
    assert_eq!(login("Not*The*Password").0, 401);
    let (status, first, _) = login("Temporary*Password123");
    assert_eq!(status, 200);
    assert!(first["setupToken"].is_string(), "{first}");

    // Rotated, with the administrator's reset grant: the new one only.
    let rotate = |grant: &str, password: &str| {
        let mut body = common::temp_registration(&c, &base, password, &token, Some(grant));
        body["grant"] = json!(grant);
        bearer(
            c.post(format!("{base}/api/admin/users/{id}/rotate-temp-password")),
            &token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    };
    let grant = common::admin_reset_grant(&c, &base, &token, admin_name, admin_password, &id);
    assert_eq!(rotate(&grant, "Another*Temporary456"), 200);
    assert_eq!(login("Temporary*Password123").0, 401);
    // The setup token of the replaced temporary password is over.
    let (status, stale, _) =
        common::try_complete_setup(&c, &base, &first, &username, "Never*Set*Password1");
    assert_eq!(status, 401, "{stale}");
    assert_eq!(stale["code"], "setupTokenInvalid");
    assert_eq!(login("Another*Temporary456").0, 200);
    // The grant was used up.
    let mut body = json!({ "grant": grant, "keyBinding": uuid::Uuid::new_v4().to_string(),
                          "opaqueRecord": "AA==", "opaqueServerKeyId": 1 });
    body["grant"] = json!(grant);
    let reused = bearer(
        c.post(format!("{base}/api/admin/users/{id}/rotate-temp-password")),
        &token,
    )
    .json(&body)
    .send()
    .unwrap()
    .status();
    assert!(reused == 403 || reused == 400, "{reused}");

    // The break-glass administrator, known by its username, is kept.
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", id_of(admin_name))),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 403);
    let r = bearer(c.delete(format!("{base}/api/admin/users/{id}")), &token)
        .send()
        .unwrap();
    assert!(r.status().is_success(), "delete: {}", r.status());
    common::purge_accounts(&c, &base, &[&stranger]);
}

#[test]
fn the_lockout_holds_one_client_and_known_clients_pass_the_ceiling() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let try_in = |ip: &str, password: &str, cookie: Option<&str>| {
        attempt(&c, &base, &user.username, password, ip, cookie)
    };
    // A right sign-in marks the client as known (an HttpOnly cookie).
    let signed_in = try_in("192.0.2.10", &user.password, None);
    assert_eq!(signed_in.status(), 200);
    let set: Vec<String> = signed_in
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|v| v.starts_with("kutup_known="))
        .map(str::to_owned)
        .collect();
    let path_of = |cookie: &str| -> String {
        cookie
            .split(';')
            .filter_map(|part| part.trim().strip_prefix("Path="))
            .next()
            .unwrap_or("/")
            .to_owned()
    };
    let known = set
        .iter()
        .find(|v| !v.starts_with("kutup_known=;"))
        .expect("known-client cookie")
        .clone();
    assert!(known.contains("HttpOnly"), "{known}");
    // Sent to sign-in only: a browser path-matches (RFC 6265 5.1.4), so the
    // anonymous Chat routes, which refuse any cookie, never carry it.
    let path = path_of(&known);
    assert_eq!(path, "/api/auth", "{known}");
    let matches = |request: &str| {
        request == path
            || (request.starts_with(&path)
                && (path.ends_with('/') || request[path.len()..].starts_with('/')))
    };
    assert!(matches("/api/auth/login/start"));
    for route in [
        "/api/chat/mls/anonymous/key-packages",
        "/api/chat/mls/anonymous/messages",
        "/api/chat/users/x/keys",
        "/api",
    ] {
        assert!(!matches(route), "{route} would carry {known}");
    }
    // The mark a browser may hold from before, at `Path=/api`, is cleared.
    assert!(
        set.iter().any(|v| v.starts_with("kutup_known=;")
            && v.contains("Max-Age=0")
            && path_of(v) == "/api"),
        "{set:?}"
    );
    let known = known.split(';').next().unwrap().to_owned();

    // Five misses lock that client only; another address still gets in.
    for _ in 0..5 {
        assert_eq!(
            try_in("198.51.100.20", "wrong-password", None).status(),
            401
        );
    }
    assert_eq!(try_in("198.51.100.20", &user.password, None).status(), 429);
    assert_eq!(try_in("198.51.100.21", &user.password, None).status(), 200);

    // Starts alone count as wrong passwords do: a client sees a guess was
    // wrong without finishing, so five starts lock it as five misses.
    for _ in 0..5 {
        let (_, ke1) = kutup_crypto::opaque::client_login_start("a guess").unwrap();
        let r = c
            .post(format!("{base}/api/auth/login/start"))
            .header("x-kutup-client", "web-account")
            .header("x-real-ip", "198.51.100.40")
            .json(&json!({ "name": user.username, "credentialRequest": b64(&ke1) }))
            .send()
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    assert_eq!(try_in("198.51.100.40", &user.password, None).status(), 429);

    // Misses spread over many unknown addresses meet the account's ceiling
    // (LOGIN_ACCOUNT_CEILING, 20)...
    let mut held = false;
    for i in 0..40u32 {
        let ip = format!("10.77.{}.{}", i / 250, i % 250 + 1);
        if try_in(&ip, "wrong-password", None).status() == 429 {
            held = true;
            break;
        }
    }
    assert!(held, "the ceiling never came");
    assert_eq!(try_in("203.0.113.30", &user.password, None).status(), 429);
    // ...while the account's own known client still signs in.
    assert_eq!(
        try_in("203.0.113.31", &user.password, Some(&known)).status(),
        200
    );
    // A malformed request is refused before the name is looked up.
    let r = c
        .post(format!("{base}/api/auth/login/start"))
        .header("x-kutup-client", "web-account")
        .header("x-real-ip", "203.0.113.32")
        .json(&json!({ "name": user.username, "credentialRequest": "not base64!" }))
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
    common::purge_accounts(&c, &base, &[&user]);
}

#[test]
fn answers_carry_the_session_version_and_errors_a_code() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let version = |token: &str| {
        let response = bearer(c.get(format!("{base}/api/user/me")), token)
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        response
            .headers()
            .get("x-kutup-session-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .expect("session version header")
    };
    let first = version(&user.token);
    assert_eq!(first.len(), 16);
    assert_eq!(version(&user.token), first, "stable while nothing changes");
    // A client error names a code, the status's default here.
    let refused: Value = c
        .get(format!("{base}/api/user/me"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(refused["code"], "unauthorized");
}

#[test]
fn the_session_version_changes_when_the_account_does() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let (admin_name, admin_password) = admin
        .split_once(':')
        .expect("KUTUP_LIVE_ADMIN is username:password");
    let admin_token = common::admin_token(&c, &base, admin_password, admin_name);
    let user = register(&c, &base);
    let version = || {
        bearer(c.get(format!("{base}/api/user/me")), &user.token)
            .send()
            .unwrap()
            .headers()
            .get("x-kutup-session-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .expect("session version header")
    };
    let before = version();
    // Made an administrator elsewhere: every app of the account sees a new
    // version on its next answer.
    let promoted = bearer(
        c.put(format!("{base}/api/admin/users/{}", user.id)),
        &admin_token,
    )
    .json(&json!({ "isAdmin": true }))
    .send()
    .unwrap();
    assert!(
        promoted.status().is_success(),
        "promote: {}",
        promoted.status()
    );
    let after = version();
    assert_ne!(before, after);
    assert_eq!(version(), after, "stable again");
    // The value names nothing: it is not a digest anyone could recompute.
    assert!(after.chars().all(|ch| ch.is_ascii_hexdigit()) && after.len() == 16);
    let demoted = bearer(
        c.put(format!("{base}/api/admin/users/{}", user.id)),
        &admin_token,
    )
    .json(&json!({ "isAdmin": false }))
    .send()
    .unwrap();
    assert!(demoted.status().is_success());
}

#[test]
fn every_new_account_has_its_mail_address() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let addresses = |token: &str| -> Vec<Value> {
        bearer(c.get(format!("{base}/api/mail/addresses")), token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    // Registered: the address came with the account, the GET only reads it
    // (and reads the same row again).
    let user = register(&c, &base);
    let first = addresses(&user.token);
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0]["address"], user.account.as_str());
    assert_eq!(addresses(&user.token)[0]["id"], first[0]["id"]);
    // The bootstrap administrator: made at start, with its address.
    let (admin_name, admin_password) = admin.split_once(':').unwrap();
    let admin_token = common::admin_token(&c, &base, admin_password, admin_name);
    let admin_addresses = addresses(&admin_token);
    assert_eq!(admin_addresses.len(), 1, "{admin_addresses:?}");
    assert!(admin_addresses[0]["address"]
        .as_str()
        .unwrap()
        .starts_with(&format!("{admin_name}@")));
}

/// A taken address refuses the username and leaves no account behind; the
/// address list never creates a row. Needs the database:
/// `KUTUP_LIVE_DATABASE_URL`.
#[test]
fn a_taken_address_refuses_the_username_and_reads_never_write() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let someone = register(&c, &base);
    let server = someone.account.split_once('@').unwrap().1.to_owned();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let count = |sql: &str, value: &str| -> i64 {
        runtime
            .block_on(sqlx::query_scalar(sql).bind(value).fetch_one(&pool))
            .unwrap()
    };

    // An address another account holds: its name is not free.
    let taken = format!("taken{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    runtime
        .block_on(
            sqlx::query("INSERT INTO mail_addresses (user_id, address) VALUES ($1::uuid, $2)")
                .bind(&someone.id)
                .bind(format!("{taken}@{server}"))
                .execute(&pool),
        )
        .unwrap();
    assert_eq!(common::register_named(&c, &base, &taken).as_u16(), 409);
    assert_eq!(
        count("SELECT count(*) FROM users WHERE username = $1", &taken),
        0
    );

    // The list only reads: with the row gone it answers none, and makes none.
    runtime
        .block_on(
            sqlx::query("DELETE FROM mail_addresses WHERE address = $1")
                .bind(&someone.account)
                .execute(&pool),
        )
        .unwrap();
    let listed: Vec<Value> = bearer(c.get(format!("{base}/api/mail/addresses")), &someone.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    // (Only the row this test made for `taken` is left: the account's own is
    // not made again.)
    assert!(
        listed
            .iter()
            .all(|a| a["address"] != someone.account.as_str()),
        "{listed:?}"
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM mail_addresses WHERE address = $1",
            &someone.account
        ),
        0
    );
}
