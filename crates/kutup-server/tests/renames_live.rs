//! Username renames against a live server (docs/plans/username-renames.md):
//! one account per folded name, a rename that keeps everything but the name,
//! the old name held (the fake answer at sign-in, `409 renamed` at lookups,
//! deliveries still routed), the limits, and names freed for someone else.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` for the admin cases and
//! to purge).

mod common;

use common::*;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// A fresh name, `prefix` and digits.
fn name(prefix: &str) -> String {
    format!("{prefix}{}", rand::thread_rng().next_u32() % 1_000_000_000)
}

fn get(c: &Client, base: &str, token: &str, path: &str) -> reqwest::blocking::Response {
    bearer(c.get(format!("{base}{path}")), token)
        .send()
        .unwrap()
}

/// Renames `user` to `to`: the server's answer (status, body).
fn rename(c: &Client, base: &str, user: &User, to: &str) -> (StatusCode, Value) {
    let check: Value = get(
        c,
        base,
        &user.token,
        &format!("/api/user/rename/check?name={to}"),
    )
    .json()
    .unwrap();
    let renamed = rename_account(c, base, user, to, check["needsKey"] != true);
    (renamed.status, renamed.body)
}

/// A sign-in start for `name`: its answer, from `ip`.
fn start(c: &Client, base: &str, name: &str, password: &str, ip: &str) -> (StatusCode, Value) {
    let (_, ke1) = kutup_crypto::opaque::client_login_start(password).unwrap();
    let r = c
        .post(format!("{base}/api/auth/login/start"))
        .header("x-kutup-client", "cli")
        .header("x-real-ip", ip)
        .json(&json!({ "name": name, "credentialRequest": b64(&ke1) }))
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

#[test]
fn a_rename_keeps_the_account_and_holds_the_old_name() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let old = user.username.clone();
    let new = name("renamed_");
    let (status, body) = rename(&c, &base, &user, &new);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["username"], json!(new));
    assert_eq!(body["sequence"], 1);
    let me: Value = get(&c, &base, &user.token, "/api/user/me").json().unwrap();
    assert_eq!(me["username"], json!(new));
    assert_eq!(me["renames"]["sequence"], 1);
    assert!(me["renames"]["digest"]
        .as_str()
        .is_some_and(|d| d.len() == 64));

    // Another device, unaware of it, renames from the old address: the
    // chain moved, a conflict (read again and sign anew), not a wrong one.
    let domain = server_domain(&c, &base);
    let stale = kutup_crypto::account_rename::sign(
        &user.identity,
        1,
        &format!("{old}@{domain}"),
        &format!("{}@{domain}", name("elsewhere_")),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
    )
    .unwrap();
    let grant = reauth_grant(&c, &base, &user, "rename");
    let r = bearer(c.post(format!("{base}/api/user/rename")), &user.token)
        .json(&json!({ "grant": grant, "rename": stale }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let conflict: Value = r.json().unwrap();
    assert_eq!(conflict["code"], "renameConflict", "{conflict}");
    assert_eq!(conflict["sequence"], 1);

    // The new name and its variants sign in, the same account; the old one
    // is no account.
    for spelling in [new.clone(), new.to_uppercase(), new.replace('_', "")] {
        let session = sign_in(&c, &base, &spelling, &user.password);
        assert_eq!(session["userId"], json!(user.id), "{spelling}");
    }
    let (status, _, _) = opaque_login(&c, &base, &old, &user.password, "session", None, None);
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old name signs nobody in"
    );

    // Lookups of the old name say where it went, with the chain.
    let r = get(
        &c,
        &base,
        &user.token,
        &format!("/api/users/by-address/{old}@{domain}"),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let renamed: Value = r.json().unwrap();
    assert_eq!(renamed["code"], "renamed");
    let chains = &renamed["renames"];
    assert_eq!(chains["version"], 1);
    assert_eq!(
        chains["chains"][0]["current"],
        json!(format!("{new}@{domain}"))
    );
    assert_eq!(chains["chains"][0]["state"], "current");
    let chain: Vec<kutup_crypto::account_rename::AccountRenameV1> =
        serde_json::from_value(chains["chains"][0]["chain"].clone()).unwrap();
    let view =
        kutup_crypto::account_rename::verify_chain(&user.identity.authority_public_key(), &chain)
            .unwrap();
    assert_eq!(view.current, format!("{new}@{domain}"));
    let listed: Value = get(
        &c,
        &base,
        &user.token,
        &format!("/api/users/renames/{old}@{domain}"),
    )
    .json()
    .unwrap();
    assert_eq!(&listed, chains);

    // The names the account has, and the event.
    let names: Value = get(&c, &base, &user.token, "/api/user/names")
        .json()
        .unwrap();
    assert_eq!(names[0]["name"], json!(new));
    assert_eq!(names[0]["state"], "current");
    assert_eq!(names[1]["name"], json!(old));
    assert_eq!(names[1]["state"], "held");
    let events: Value = get(&c, &base, &user.token, "/api/user/security-events")
        .json()
        .unwrap();
    assert_eq!(events["events"][0]["kind"], "rename");
    assert_eq!(events["events"][0]["oldName"], json!(old));
    assert_eq!(events["events"][0]["newName"], json!(new));

    // One rename a month; the free undo back, once, restarts the clock.
    let (status, body) = rename(&c, &base, &user, &name("again_"));
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "renameTooSoon");
    let (status, body) = rename(&c, &base, &user, &old);
    assert_eq!(status, StatusCode::OK, "the free undo: {body}");
    let (status, _) = rename(&c, &base, &user, &new);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "only one free undo");
    user.username = old;
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_held_name_gets_the_fake_answer_and_shares_one_lockout() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register_as(&c, &base, &name("ada_l")).unwrap();
    let old = user.username.clone();
    let new = name("moved");
    assert_eq!(rename(&c, &base, &user, &new).0, StatusCode::OK);
    user.username = new.clone();

    // The held name's answer has the shape of any unknown name's.
    let (held_status, held) = start(&c, &base, &old, "wrong-password-1", "192.0.2.150");
    let (unknown_status, unknown) = start(
        &c,
        &base,
        &name("nobody"),
        "wrong-password-1",
        "192.0.2.151",
    );
    assert_eq!(
        (held_status, unknown_status),
        (StatusCode::OK, StatusCode::OK)
    );
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&held), keys(&unknown));
    assert_eq!(
        held["credentialResponse"].as_str().unwrap().len(),
        unknown["credentialResponse"].as_str().unwrap().len()
    );
    // Every spelling of it is one bucket: five misses lock them all.
    let spellings = [
        old.clone(),
        old.replace('_', ""),
        old.replace('_', "."),
        old.to_uppercase(),
    ];
    for spelling in spellings.iter().cycle().take(5) {
        assert_eq!(
            start(&c, &base, spelling, "wrong", "192.0.2.152").0,
            StatusCode::OK
        );
    }
    for spelling in &spellings {
        assert_eq!(
            start(&c, &base, spelling, "wrong", "192.0.2.152").0,
            StatusCode::TOO_MANY_REQUESTS,
            "{spelling}"
        );
    }
    // The new name still signs in from that address.
    let (status, _, _) = opaque_login(&c, &base, &new, &user.password, "session", None, None);
    assert_eq!(status, StatusCode::OK);
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn one_account_per_folded_name() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let taken = name("fold_");
    let user = register_as(&c, &base, &taken).unwrap();
    // Another spelling of it is the same name.
    assert_eq!(
        register_named(&c, &base, &taken.replace('_', "-")),
        StatusCode::CONFLICT
    );
    assert_eq!(
        register_named(&c, &base, &taken.replace('_', "")),
        StatusCode::CONFLICT
    );
    // So is a rename to one, by someone else.
    let other = register(&c, &base);
    let (status, body) = rename(&c, &base, &other, &taken.replace('_', ""));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "nameTaken");
    let check: Value = get(
        &c,
        &base,
        &other.token,
        &format!("/api/user/rename/check?name={}", taken.replace('_', "-")),
    )
    .json()
    .unwrap();
    assert_eq!(check, json!({ "available": false, "reason": "taken" }));
    purge_accounts(&c, &base, &[&user, &other]);
}

#[test]
fn a_deleted_accounts_name_is_held_until_freed() {
    // (The break-glass account's refusal, 403 breakGlassAccount, needs the
    // admin's own keys to sign a statement; it is checked in review.)
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let (admin_name, admin_password) = admin.split_once(':').unwrap();
    let token = admin_token(&c, &base, admin_password, admin_name);
    let gone = register(&c, &base);
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", gone.id)),
        &token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());
    // Nobody takes it while it is held...
    assert_eq!(
        register_named(&c, &base, &gone.username),
        StatusCode::CONFLICT
    );
    // ...until an administrator frees it: a new account, a new incarnation.
    let r = bearer(
        c.post(format!("{base}/api/admin/names/{}/free", gone.username)),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let taker = register_as(&c, &base, &gone.username).unwrap();
    assert_ne!(
        taker.identity.incarnation_id(),
        gone.identity.incarnation_id()
    );
    purge_accounts(&c, &base, &[&taker]);
}

#[test]
fn variant_spellings_find_the_current_account_as_stored() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let asker = register(&c, &base);
    let mut user = register(&c, &base);
    // A name with a separator, and its address's key (a rename gives one).
    let stored = name("ada_l");
    let renamed = rename_account(&c, &base, &user, &stored, false);
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    user.username = stored.clone();
    let domain = server_domain(&c, &base);
    let fingerprint = hex::encode(renamed.key.as_ref().unwrap().key.fingerprint);
    for variant in [
        stored.replace('_', "-"),
        stored.replace('_', ""),
        stored.replace('_', "."),
    ] {
        let at = format!("{variant}@{domain}");
        // The address lookup: the account, named as stored.
        let r = get(
            &c,
            &base,
            &asker.token,
            &format!("/api/users/by-address/{at}"),
        );
        assert_eq!(r.status(), StatusCode::OK, "{at}");
        let found: Value = r.json().unwrap();
        assert_eq!(found["userId"], json!(user.id), "{at}");
        assert_eq!(
            found["account"],
            json!(format!("{stored}@{domain}")),
            "{at}"
        );
        // Drive identities.
        let identities: Value = bearer(
            c.post(format!("{base}/api/users/drive-identities")),
            &asker.token,
        )
        .json(&json!({ "accounts": [at] }))
        .send()
        .unwrap()
        .json()
        .unwrap();
        assert_eq!(
            identities[0]["account"],
            json!(format!("{stored}@{domain}")),
            "{at}"
        );
        // Mail: the account a group would enrol, and the address's keys.
        let account: Value = get(
            &c,
            &base,
            &asker.token,
            &format!("/api/mail/accounts?address={at}"),
        )
        .json()
        .unwrap();
        assert_eq!(account["userId"], json!(user.id), "{at}: {account}");
        let keys: Value = get(
            &c,
            &base,
            &asker.token,
            &format!("/api/mail/keys?email={at}"),
        )
        .json()
        .unwrap();
        assert_eq!(
            keys["keys"][0]["fingerprint"],
            json!(fingerprint),
            "{at}: {keys}"
        );
    }
    purge_accounts(&c, &base, &[&asker, &user]);
}

#[test]
fn renaming_back_to_a_freed_name_gives_it_its_new_key() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let (admin_name, admin_password) = admin.split_once(':').unwrap();
    let token = admin_token(&c, &base, admin_password, admin_name);
    let mut user = register(&c, &base);
    let first = user.username.clone();
    let domain = server_domain(&c, &base);
    // x → y; x freed by an administrator; y → x again (the free undo), as a
    // new address: its old row stays freed, the new one has the new key.
    let away = name("away_");
    let renamed = rename_account(&c, &base, &user, &away, false);
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    let r = bearer(
        c.post(format!("{base}/api/admin/names/{first}/free")),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let check: Value = get(
        &c,
        &base,
        &user.token,
        &format!("/api/user/rename/check?name={first}"),
    )
    .json()
    .unwrap();
    assert_eq!(check, json!({ "available": true, "needsKey": true }));
    let back = rename_account(&c, &base, &user, &first, false);
    assert_eq!(back.status, StatusCode::OK, "{}", back.body);
    user.username = first.clone();
    let keys: Value = get(
        &c,
        &base,
        &user.token,
        &format!("/api/mail/keys?email={first}@{domain}"),
    )
    .json()
    .unwrap();
    let listed: Vec<&str> = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["fingerprint"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        vec![hex::encode(back.key.as_ref().unwrap().key.fingerprint)],
        "only the new address's key: {keys}"
    );
    // The account's addresses: the current one first, then the old ones,
    // whose keys open the mail they received (the freed first row among them).
    let own: Value = get(&c, &base, &user.token, "/api/mail/addresses")
        .json()
        .unwrap();
    let states: Vec<(&str, &str)> = own
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["address"].as_str().unwrap(), a["state"].as_str().unwrap()))
        .collect();
    let first_at = format!("{first}@{domain}");
    let away_at = format!("{away}@{domain}");
    assert_eq!(states[0], (first_at.as_str(), "active"), "{own}");
    assert!(states.contains(&(away_at.as_str(), "receiving")), "{own}");
    assert!(states.contains(&(first_at.as_str(), "freed")), "{own}");
    purge_accounts(&c, &base, &[&user]);
    // A new name without its key is refused.
    let fresh = register(&c, &base);
    let missing = rename_account(&c, &base, &fresh, &name("nokey_"), true);
    assert_eq!(missing.status, StatusCode::BAD_REQUEST, "{}", missing.body);
    assert_eq!(missing.body["code"], "renameInvalid");
    purge_accounts(&c, &base, &[&fresh]);
}

/// Dates acted on by the server's own sweep (`NAME_SWEEP_SECONDS`, seconds on
/// the test stack): a held name past its date is freed, then anyone's.
#[test]
fn the_sweep_frees_a_held_name_on_its_date() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let old = user.username.clone();
    let new = name("swept_");
    let renamed = rename_account(&c, &base, &user, &new, false);
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    user.username = new.clone();
    // Its dates brought forward, as if the hold had run.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    runtime
        .block_on(
            sqlx::query(
                "UPDATE account_names SET receive_until = now() - interval '1 second',
                        free_at = now() - interval '1 second'
                  WHERE name = $1",
            )
            .bind(&old)
            .execute(&pool),
        )
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let names: Value = get(&c, &base, &user.token, "/api/user/names")
            .json()
            .unwrap();
        if names.as_array().unwrap().len() == 1 {
            assert_eq!(names[0]["name"], json!(new));
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never swept: {names}");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // Freed: someone else takes it, a new incarnation.
    let taker = register_as(&c, &base, &old).unwrap();
    assert_ne!(
        taker.identity.incarnation_id(),
        user.identity.incarnation_id()
    );
    purge_accounts(&c, &base, &[&user, &taker]);
}

#[test]
fn dropping_names_is_limited_and_a_name_is_taken_back_as_spelled() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register_as(&c, &base, &name("spelt_a")).unwrap();
    let first = user.username.clone();
    let second = name("away_");
    assert_eq!(rename(&c, &base, &user, &second).0, StatusCode::OK);
    // Back in another spelling: refused, with the spelling to use.
    let respelled = first.replace('_', "-");
    let check: Value = get(
        &c,
        &base,
        &user.token,
        &format!("/api/user/rename/check?name={respelled}"),
    )
    .json()
    .unwrap();
    assert_eq!(check["takeBack"], true, "{check}");
    assert_eq!(check["spelling"], json!(first), "{check}");
    let refused = rename_account(&c, &base, &user, &respelled, check["needsKey"] != true);
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["spelling"], json!(first));
    // As spelled: the free undo.
    assert_eq!(rename(&c, &base, &user, &first).0, StatusCode::OK);
    user.username = first.clone();
    // One drop per 30 days.
    let drop = |held: &str| {
        let grant = reauth_grant(&c, &base, &user, "rename");
        bearer(
            c.delete(format!("{base}/api/user/names/{held}")),
            &user.token,
        )
        .json(&json!({ "grant": grant }))
        .send()
        .unwrap()
    };
    assert_eq!(drop(&second).status(), StatusCode::NO_CONTENT);
    let again = drop(&second);
    assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: Value = again.json().unwrap();
    assert_eq!(body["code"], "dropTooSoon");
    assert!(body["retryAt"].as_str().is_some_and(|at| !at.is_empty()));
    purge_accounts(&c, &base, &[&user]);
}

/// Old names that still receive are limited to five; a dropped one (held
/// until freed, receiving no more) makes room for another rename.
#[test]
fn five_old_names_receive_and_a_drop_makes_room() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    // Five old names, receiving, as five renames would have left them.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let held: Vec<String> = (0..5).map(|i| name(&format!("old{i}_"))).collect();
    for old in &held {
        runtime
            .block_on(
                sqlx::query(
                    "INSERT INTO account_names
                         (folded, name, user_id, incarnation_id, state, receive_until, free_at)
                     SELECT kutup_fold($1), $1, id, account_incarnation_id, 'held',
                            now() + interval '90 days', now() + interval '180 days'
                       FROM users WHERE id = $2::uuid",
                )
                .bind(old)
                .bind(&user.id)
                .execute(&pool),
            )
            .unwrap();
    }
    let (status, body) = rename(&c, &base, &user, &name("sixth_"));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "tooManyHeldNames");
    // One dropped: it stays held, and no longer counts.
    let grant = reauth_grant(&c, &base, &user, "rename");
    let r = bearer(
        c.delete(format!("{base}/api/user/names/{}", held[0])),
        &user.token,
    )
    .json(&json!({ "grant": grant }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let names: Value = get(&c, &base, &user.token, "/api/user/names")
        .json()
        .unwrap();
    assert!(names
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["name"] == json!(held[0]) && n["state"] == "held"));
    let new = name("sixth_");
    let (status, body) = rename(&c, &base, &user, &new);
    assert_eq!(status, StatusCode::OK, "{body}");
    user.username = new;
    purge_accounts(&c, &base, &[&user]);
}

fn profile_envelope(
    account: &str,
    version: &str,
    revision: u64,
    device: u32,
    purpose: kutup_chat_proto::ProfileEnvelopePurpose,
    len: usize,
) -> String {
    let context = kutup_chat_proto::ProfileEnvelopeContextV1::new(
        purpose, account, version, revision, device,
    )
    .unwrap();
    let mut envelope =
        kutup_chat_proto::encode_profile_envelope_header(&context, &[7; 24], len as u32).unwrap();
    envelope.extend(vec![7; len]);
    b64(&envelope)
}

/// A Chat profile is sealed for the address the account had when it was
/// published. After a rename the owner still reads it (and publishes it
/// again under the new address); others asking for the new address get none
/// until then.
#[test]
fn a_renamed_account_keeps_its_chat_profile_until_it_publishes_again() {
    use kutup_chat_proto::ProfileEnvelopePurpose as Purpose;
    use sha2::Digest as _;
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let reader = register(&c, &base);
    let domain = server_domain(&c, &base);
    // A Chat device (synthetic keys) to publish from.
    let key = |n: u8| {
        let mut bytes = [n; 33];
        bytes[1..].copy_from_slice(&rand::random::<[u8; 32]>());
        b64(&bytes)
    };
    let r = bearer(c.post(format!("{base}/api/chat/device")), &user.token)
        .json(&json!({
            "suite": 1, "registrationId": 4242, "identityKey": key(1),
            "signedPreKey": { "keyId": 1, "publicKey": key(2), "signature": key(3) },
            "lastResortKyberPreKey": { "keyId": 1, "publicKey": key(4), "signature": key(5) },
            "oneTimePreKeys": [ { "keyId": 10, "publicKey": key(6) } ],
            "oneTimeKyberPreKeys": [ { "keyId": 20, "publicKey": key(7), "signature": key(8) } ],
            "name": "rename-test"
        }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "device: {}", r.status());
    let device = r.json::<Value>().unwrap()["deviceId"].as_u64().unwrap() as u32;
    let access = [5u8; 16];
    let profile = |account: &str, version: &str, revision: u64| {
        json!({
            "suite": 1, "account": account, "version": version, "revision": revision,
            "sourceDeviceId": device,
            "name": profile_envelope(account, version, revision, device, Purpose::DisplayName, 53 + 16),
            "wrappedKey": profile_envelope(account, version, revision, device, Purpose::WrappedProfileKey, 32 + 16),
            "accessKeyVerifier": hex::encode(sha2::Sha256::digest(access)),
            "deliveryCapabilityVerifier": hex::encode(sha2::Sha256::digest([6u8; 16])),
        })
    };
    let put = |body: Value| {
        bearer(c.put(format!("{base}/api/chat/profile")), &user.token)
            .json(&body)
            .send()
            .unwrap()
    };
    let read = |name: &str, version: &str| {
        bearer(
            c.get(format!(
                "{base}/api/chat/users/{name}@{domain}/profile/{version}"
            )),
            &reader.token,
        )
        .header("X-Kutup-Profile-Access-Key", b64(&access))
        .send()
        .unwrap()
    };
    let old = format!("{}@{domain}", user.username);
    let (v1, v2) = ("12".repeat(32), "34".repeat(32));
    assert!(put(profile(&old, &v1, 1)).status().is_success());

    let new = name("chatty_");
    assert_eq!(rename(&c, &base, &user, &new).0, StatusCode::OK);
    user.username = new.clone();
    // The owner reads it as it was published (not 400).
    let own: Value = get(&c, &base, &user.token, "/api/chat/profile")
        .json()
        .unwrap();
    assert_eq!(own["account"], json!(old), "{own}");
    // Others asking for the new address: none until it is published again.
    assert_eq!(read(&new, &v1).status(), StatusCode::NOT_FOUND);
    // Published again under the new address: everyone's.
    let current = format!("{new}@{domain}");
    let r = put(profile(&current, &v2, 2));
    assert!(r.status().is_success(), "republish: {}", r.status());
    let own: Value = get(&c, &base, &user.token, "/api/chat/profile")
        .json()
        .unwrap();
    assert_eq!(own["account"], json!(current));
    let r = read(&new, &v2);
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["account"], json!(current));
    purge_accounts(&c, &base, &[&user, &reader]);
}

/// Another server's renames, looked up through this one: a name that is not
/// a plain name never reaches a signed request (`400`), and a server that
/// cannot be reached, with nothing kept of it, answers `unavailable`: no
/// news, not "no renames".
#[test]
fn remote_lookups_check_the_name_and_say_when_they_cannot_tell() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    for address in [
        "..%2f..%2fdrive%2faccounts%2fx@peer.test",
        "..@peer.test",
        "a%20b@peer.test",
    ] {
        let r = get(
            &c,
            &base,
            &user.token,
            &format!("/api/users/renames/{address}"),
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{address}");
    }
    let answer: Value = get(
        &c,
        &base,
        &user.token,
        "/api/users/renames/ada@unreachable.invalid",
    )
    .json()
    .unwrap();
    assert_eq!(
        answer,
        json!({ "version": 1, "chains": [], "unavailable": true })
    );
    purge_accounts(&c, &base, &[&user]);
}
