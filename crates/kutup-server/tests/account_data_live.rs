//! Each account's data key (docs/plans/server-personal-data.md, A2) against a
//! live server: made when the account first has something to seal (the
//! authenticator app's secret), wrapped under the server key list's current
//! entry, the secret stored sealed, still signing in; and, its key gone, the
//! app's codes refused as lost while a recovery code still signs in.
//!
//!   KUTUP_LIVE_SERVER=http://… KUTUP_LIVE_DATABASE_URL=postgres://… \
//!   KUTUP_LIVE_ADMIN=name:password cargo test -p kutup-server --test account_data_live

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::runtime::Runtime;
use uuid::Uuid;

struct Db {
    runtime: Runtime,
    pool: PgPool,
}

impl Db {
    /// The key row's entry id, when the account has a key.
    fn key_entry(&self, user_id: &str) -> Option<i16> {
        self.runtime
            .block_on(
                sqlx::query_scalar::<_, i16>(
                    "SELECT sealing_key_id FROM account_keys.account_data_keys WHERE user_id = $1",
                )
                .bind(Uuid::parse_str(user_id).unwrap())
                .fetch_optional(&self.pool),
            )
            .unwrap()
    }

    /// The account's key deleted, its sealed fields left.
    fn drop_key(&self, user_id: &str) {
        self.runtime
            .block_on(
                sqlx::query("DELETE FROM account_keys.account_data_keys WHERE user_id = $1")
                    .bind(Uuid::parse_str(user_id).unwrap())
                    .execute(&self.pool),
            )
            .unwrap();
    }

    fn sealed_secret(&self, user_id: &str) -> Option<Vec<u8>> {
        self.runtime
            .block_on(
                sqlx::query_scalar::<_, Option<Vec<u8>>>(
                    "SELECT totp_secret_sealed FROM users WHERE id = $1",
                )
                .bind(Uuid::parse_str(user_id).unwrap())
                .fetch_one(&self.pool),
            )
            .unwrap()
    }
}

#[test]
fn the_authenticator_secret_is_sealed_under_the_accounts_data_key() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER or KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let runtime = Runtime::new().unwrap();
    let pool = runtime.block_on(PgPool::connect(&database_url)).unwrap();
    let db = Db { runtime, pool };
    let c = client();
    let user = register(&c, &base);

    // Nothing sealed yet: no key.
    assert_eq!(db.key_entry(&user.id), None);

    // The authenticator app on: a key under the current entry, the secret
    // stored sealed (not as its base32 text).
    let setup: Value = bearer(c.post(format!("{base}/api/user/2fa/setup")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let secret = setup["secret"].as_str().unwrap().to_owned();
    let verify = bearer(c.post(format!("{base}/api/user/2fa/verify")), &user.token)
        .json(&json!({
            "code": totp_now(&secret),
            "grant": reauth_grant(&c, &base, &user, "totp"),
        }))
        .send()
        .unwrap();
    assert_eq!(verify.status(), StatusCode::OK);
    let enabled: Value = verify.json().unwrap();
    let recovery_code = enabled["recoveryCodes"][0].as_str().unwrap().to_owned();
    assert!(db.key_entry(&user.id).is_some());
    let sealed = db.sealed_secret(&user.id).expect("the secret is stored");
    assert!(!sealed
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()));

    // Signing in still takes the code: the server opens the sealed secret.
    let (status, body, _) = opaque_login(
        &c,
        &base,
        &user.username,
        &user.password,
        "session",
        None,
        None,
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    let pre_auth = body["preAuthToken"]
        .as_str()
        .expect("a second step")
        .to_owned();
    let second = c
        .post(format!("{base}/api/auth/login/2fa"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "preAuthToken": pre_auth, "code": totp_now(&secret) }))
        .send()
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);

    // The key gone, the sealed secret left (a restore without its key): the
    // app's codes can't be checked, and the server says so rather than
    // failing; a recovery code still signs in; no new key is made for it.
    db.drop_key(&user.id);
    let pre_auth = |c: &reqwest::blocking::Client| {
        let (status, body, _) = opaque_login(
            c,
            &base,
            &user.username,
            &user.password,
            "session",
            None,
            None,
        );
        assert_eq!(status, StatusCode::OK, "{body}");
        body["preAuthToken"].as_str().unwrap().to_owned()
    };
    let token = pre_auth(&c);
    let lost = c
        .post(format!("{base}/api/auth/login/2fa"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "preAuthToken": token, "code": totp_now(&secret) }))
        .send()
        .unwrap();
    assert_eq!(lost.status(), StatusCode::UNAUTHORIZED);
    let lost: Value = lost.json().unwrap();
    assert_eq!(lost["code"], "authenticatorLost", "{lost}");
    let recovered = c
        .post(format!("{base}/api/auth/login/2fa"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "preAuthToken": token, "code": recovery_code }))
        .send()
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    assert_eq!(db.key_entry(&user.id), None);

    // (A deleted account's key goes with it by the foreign key's cascade,
    // which the server checks at start: account_data::check_cascade.)
    purge_accounts(&c, &base, &[&user]);
}
