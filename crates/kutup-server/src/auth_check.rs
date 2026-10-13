//! One check for every secret a person proves to the server: sign-in,
//! re-authentication (`/api/user/reauth`, the Pass PIN's set and remove) and
//! recovery (docs/plans/account-identity.md, "Sign-in checks").
//!
//! - **Order.** The caller decodes the secret before it looks the name up,
//!   so a malformed secret is answered the same for every name; the hash is
//!   checked next, at full cost even when there is none (an unknown name, a
//!   voided temporary password); only a right secret learns anything about
//!   the account (disabled, awaiting setup, 2FA).
//! - **Lockout per account and client.** Five wrong secrets in a row from one
//!   client IP lock that account for that IP only (`LOGIN_LOCKOUT_*`), so a
//!   stranger elsewhere cannot lock a person out by knowing their name.
//! - **A ceiling per account for clients it does not know.** Wrong secrets
//!   from all unknown clients together are capped (`LOGIN_ACCOUNT_CEILING`
//!   in the lockout's window), which stops guessing spread over many
//!   addresses. A client the account signed in from before carries a known
//!   client cookie and is not held by the ceiling, so such an attack does not
//!   lock out the account's own devices either.
//!
//! Names that are no account get the same lockout and ceiling, keyed on the
//! canonical name, so a 429 tells nothing about whether one exists.

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::ratelimit;
use crate::AppState;

pub(crate) const BCRYPT_COST: u32 = 10;

/// A real hash at the cost every stored one has, verified when there is
/// nothing real to check against (an unknown name, an account without a
/// hash), so the answer takes as long as a real one.
pub(crate) static FAKE_BCRYPT_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    bcrypt::hash("kutup-timing-only", BCRYPT_COST).expect("bcrypt of a constant")
});

/// Verifies `secret` against `hash`, at full cost even when `hash` is empty
/// or not a hash (a voided temporary password).
pub(crate) fn verify_hash(secret: impl AsRef<[u8]>, hash: &str) -> bool {
    match bcrypt::verify(secret.as_ref(), hash) {
        Ok(ok) => ok,
        Err(_) => {
            let _ = bcrypt::verify("kutup-timing-only-not", &FAKE_BCRYPT_HASH);
            false
        }
    }
}

/// The cookie marking a client an account has signed in from: host-only on
/// each app's origin (set at sign-in and when an app takes its session from
/// the account app), so reauth and the Pass PIN from any app see it.
pub(crate) const KNOWN_CLIENT_COOKIE: &str = "kutup_known";
/// How long a known client stays known without signing in again.
const KNOWN_CLIENT_DAYS: i64 = 90;

/// Who is asking: the client's IP (as the rate limiters key it) and the
/// account its known-client cookie names, if a valid one came.
pub(crate) struct Client {
    ip: String,
    known_account: Option<Uuid>,
}

impl Client {
    pub(crate) async fn from_headers(state: &AppState, headers: &HeaderMap) -> AppResult<Self> {
        let known_account = match crate::handlers::auth::cookie_value(headers, KNOWN_CLIENT_COOKIE)
        {
            Some(value) => open_known_client(&known_client_key(state).await?, &value),
            None => None,
        };
        Ok(Self {
            ip: crate::middleware::client_ip_from_headers(headers)
                .unwrap_or_else(|| "unknown".to_owned()),
            known_account,
        })
    }
}

/// The checks one attempt runs under, from [`guard`].
pub(crate) struct Guard {
    lockout: String,
    ceiling: Option<String>,
}

/// Refuses the attempt (429) while its account (or the canonical name, when
/// it is no account) is locked for this client, or over the ceiling for an
/// unknown client; otherwise returns the guard that records the outcome.
pub(crate) fn guard(
    client: &Client,
    account: Option<Uuid>,
    canonical_name: &str,
) -> AppResult<Guard> {
    let subject = match account {
        Some(id) => format!("account:{id}"),
        None => format!("name:{canonical_name}"),
    };
    let lockout = format!("{subject}\0ip:{}", client.ip);
    let known = account.is_some() && client.known_account == account;
    let ceiling = (!known).then_some(subject);
    let over_ceiling = ceiling
        .as_deref()
        .is_some_and(|key| ratelimit::LOGIN_CEILING.is_full(key));
    if ratelimit::LOGIN_LOCKOUT.is_locked(&lockout) || over_ceiling {
        return Err(AppError::too_many_requests(
            "too many failed attempts, try again later",
        ));
    }
    Ok(Guard { lockout, ceiling })
}

impl Guard {
    /// Checks `secret` against `hash` at full cost, `None` for either paying
    /// the same cost, and records the outcome.
    pub(crate) fn verify(&self, secret: Option<&[u8]>, hash: Option<&str>) -> bool {
        let ok = match (secret, hash) {
            (Some(secret), Some(hash)) => verify_hash(secret, hash),
            _ => {
                let _ = bcrypt::verify("kutup-timing-only-not", &FAKE_BCRYPT_HASH);
                false
            }
        };
        ratelimit::LOGIN_LOCKOUT.record(&self.lockout, ok);
        if !ok {
            if let Some(key) = &self.ceiling {
                ratelimit::LOGIN_CEILING.push(key);
            }
        }
        ok
    }
}

static KNOWN_CLIENT_KEY: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();

/// The known-client cookie's key: derived, under its own label, from the
/// server's stored key for sign-in answers.
async fn known_client_key(state: &AppState) -> AppResult<[u8; 32]> {
    KNOWN_CLIENT_KEY
        .get_or_try_init(|| async {
            let root = crate::handlers::auth::fake_accounts_key(state).await?;
            let mut mac =
                <Hmac<sha2::Sha256> as Mac>::new_from_slice(&root).expect("any key length");
            mac.update(b"kutup/known-client/v1\0");
            Ok::<_, AppError>(mac.finalize().into_bytes().into())
        })
        .await
        .copied()
}

fn known_client_tag(key: &[u8; 32], user_id: Uuid, issued_at: i64) -> [u8; 16] {
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(user_id.as_bytes());
    mac.update(&issued_at.to_be_bytes());
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&mac.finalize().into_bytes()[..16]);
    tag
}

/// `user id ‖ issued at (seconds, big-endian) ‖ tag`, base64url.
fn seal_known_client(key: &[u8; 32], user_id: Uuid, issued_at: i64) -> String {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(user_id.as_bytes());
    bytes.extend_from_slice(&issued_at.to_be_bytes());
    bytes.extend_from_slice(&known_client_tag(key, user_id, issued_at));
    URL_SAFE_NO_PAD.encode(bytes)
}

fn open_known_client(key: &[u8; 32], value: &str) -> Option<Uuid> {
    open_known_client_at(key, value, time::OffsetDateTime::now_utc().unix_timestamp())
}

fn open_known_client_at(key: &[u8; 32], value: &str, now: i64) -> Option<Uuid> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    if bytes.len() != 40 {
        return None;
    }
    let user_id = Uuid::from_slice(&bytes[..16]).ok()?;
    let issued_at = i64::from_be_bytes(bytes[16..24].try_into().ok()?);
    let expected = known_client_tag(key, user_id, issued_at);
    let fresh = issued_at <= now + 60 && now - issued_at < KNOWN_CLIENT_DAYS * 86_400;
    (fresh && subtle_eq(&expected, &bytes[24..])).then_some(user_id)
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The `Set-Cookie` value marking this client as one `user_id` signed in
/// from: HttpOnly, sent only to `/api`, `Secure` in production.
pub(crate) async fn known_client_cookie(state: &AppState, user_id: Uuid) -> AppResult<String> {
    let value = seal_known_client(
        &known_client_key(state).await?,
        user_id,
        time::OffsetDateTime::now_utc().unix_timestamp(),
    );
    let mut cookie = format!(
        "{KNOWN_CLIENT_COOKIE}={value}; Max-Age={}; Path=/api; HttpOnly; SameSite=Strict",
        KNOWN_CLIENT_DAYS * 86_400
    );
    if state.config.app_env == "production" {
        cookie.push_str("; Secure");
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];
    const NOW: i64 = 1_790_000_000;

    #[test]
    fn a_known_client_cookie_names_its_account_until_it_expires() {
        let id = Uuid::from_bytes([1; 16]);
        let cookie = seal_known_client(&KEY, id, NOW);
        assert_eq!(open_known_client_at(&KEY, &cookie, NOW), Some(id));
        assert_eq!(
            open_known_client_at(&KEY, &cookie, NOW + 89 * 86_400),
            Some(id)
        );
        assert_eq!(open_known_client_at(&KEY, &cookie, NOW + 90 * 86_400), None);
        // Another key, a changed byte, a date from the future: refused.
        assert_eq!(open_known_client_at(&[8; 32], &cookie, NOW), None);
        let mut bytes = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
        bytes[3] ^= 1;
        assert_eq!(
            open_known_client_at(&KEY, &URL_SAFE_NO_PAD.encode(&bytes), NOW),
            None
        );
        assert_eq!(
            open_known_client_at(&KEY, &seal_known_client(&KEY, id, NOW + 3600), NOW),
            None
        );
        assert_eq!(open_known_client_at(&KEY, "", NOW), None);
    }

    fn client(ip: &str, known: Option<Uuid>) -> Client {
        Client {
            ip: ip.to_owned(),
            known_account: known,
        }
    }

    #[test]
    fn the_lockout_holds_one_client_and_the_ceiling_spares_known_ones() {
        let account = Some(Uuid::new_v4());
        let attacker = client("198.51.100.1", None);
        for _ in 0..5 {
            assert!(!guard(&attacker, account, "ada").unwrap().verify(None, None));
        }
        // Locked for that client only.
        assert!(guard(&attacker, account, "ada").is_err());
        assert!(guard(&client("203.0.113.9", None), account, "ada").is_ok());
        // Unknown clients together reach the ceiling...
        for i in 0..100u32 {
            let ip = format!("10.{}.{}.1", i / 200, i % 200);
            let _ = guard(&client(&ip, None), account, "ada").map(|g| g.verify(None, None));
        }
        assert!(guard(&client("192.0.2.77", None), account, "ada").is_err());
        // ...but the account's own known device still gets in to try.
        assert!(guard(&client("192.0.2.78", account), account, "ada").is_ok());
        // A cookie for another account does not count.
        assert!(guard(&client("192.0.2.79", Some(Uuid::new_v4())), account, "ada").is_err());
    }

    #[test]
    fn unknown_names_meet_the_same_lockout() {
        let attacker = client("198.51.100.2", None);
        for _ in 0..5 {
            assert!(!guard(&attacker, None, "nobody-here")
                .unwrap()
                .verify(None, None));
        }
        assert!(guard(&attacker, None, "nobody-here").is_err());
    }
}
