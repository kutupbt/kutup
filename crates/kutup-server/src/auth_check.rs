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
//! - **A ceiling per account for clients it does not know.** Attempts from
//!   all unknown clients together are capped (`LOGIN_ACCOUNT_CEILING`, 20 in
//!   the lockout's window; `LOGIN_ACCOUNT_DAILY_CEILING`, 200 a day), which
//!   bounds guessing spread over many addresses (an IPv6 client counts by
//!   its /64). A client the account signed in from before carries a known
//!   client cookie, and a caller already signed in to the account (reauth,
//!   the PIN) is known too; neither is held by the ceiling, so such an attack
//!   does not lock out the account's own devices. The CLI, with no cookie,
//!   can be held by it while an attack lasts.
//! - Every attempt takes its slots before the check, so parallel attempts
//!   get no more than the limits; a right secret gives them back.
//!
//! Names that are no account get the same lockout and ceiling, keyed on the
//! canonical name, so a 429 tells nothing about whether one exists.

use std::net::SocketAddr;

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Digest;
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

/// Who is asking: the client's rate-limit key (its IP, an IPv6 address by
/// its /64), its known-client cookie if one came, and the account it is
/// already signed in to, for checks made inside a session.
pub(crate) struct Client {
    ip: String,
    cookie: Option<KnownClient>,
    key: [u8; 32],
    signed_in_as: Option<Uuid>,
}

impl Client {
    pub(crate) async fn from_headers(
        state: &AppState,
        headers: &HeaderMap,
        peer: SocketAddr,
    ) -> AppResult<Self> {
        Ok(Self {
            ip: crate::middleware::client_key(
                crate::middleware::client_ip_from_headers(headers),
                peer,
            ),
            cookie: crate::handlers::auth::cookie_value(headers, KNOWN_CLIENT_COOKIE)
                .and_then(|value| KnownClient::parse(&value)),
            key: known_client_key(state).await?,
            signed_in_as: None,
        })
    }

    /// The caller holds a live session of `user_id` (reauth, the PIN): it is
    /// known to that account whatever cookies it sends.
    pub(crate) fn signed_in_as(mut self, user_id: Uuid) -> Self {
        self.signed_in_as = Some(user_id);
        self
    }

    fn knows(&self, account: Uuid, epoch: &[u8]) -> bool {
        self.signed_in_as == Some(account)
            || self.cookie.as_ref().is_some_and(|cookie| {
                cookie.user_id == account
                    && cookie.is_valid(
                        &self.key,
                        epoch,
                        time::OffsetDateTime::now_utc().unix_timestamp(),
                    )
            })
    }
}

/// What a known-client mark is bound to besides the account: its current
/// password hash, so a new password (or a recovery) retires every mark.
pub(crate) fn credential_epoch(login_key_hash: &str) -> [u8; 16] {
    let digest = sha2::Sha256::digest(login_key_hash.as_bytes());
    let mut epoch = [0u8; 16];
    epoch.copy_from_slice(&digest[..16]);
    epoch
}

/// The checks one attempt runs under, from [`guard`]; its slots are taken.
pub(crate) struct Guard {
    lockout: String,
    ceiling: Option<Ceiling>,
}

/// An unknown client's slots: the account's window and daily ceilings, and
/// this source's share of the day.
struct Ceiling {
    account: String,
    source: String,
}

impl Ceiling {
    fn take(&self) -> bool {
        if !ratelimit::LOGIN_SOURCE_DAILY.allow(&self.source) {
            return false;
        }
        if !ratelimit::LOGIN_CEILING.allow(&self.account) {
            ratelimit::LOGIN_SOURCE_DAILY.pop(&self.source);
            return false;
        }
        if !ratelimit::LOGIN_DAILY_CEILING.allow(&self.account) {
            ratelimit::LOGIN_CEILING.pop(&self.account);
            ratelimit::LOGIN_SOURCE_DAILY.pop(&self.source);
            return false;
        }
        true
    }

    fn give_back(&self) {
        ratelimit::LOGIN_SOURCE_DAILY.pop(&self.source);
        ratelimit::LOGIN_CEILING.pop(&self.account);
        ratelimit::LOGIN_DAILY_CEILING.pop(&self.account);
    }
}

/// Refuses the attempt (429) while its account (or the canonical name, when
/// it is no account) is locked for this client, or over a ceiling for an
/// unknown client; otherwise takes the attempt's slots and returns the guard
/// that settles them. `epoch` is the account's [`credential_epoch`] (none
/// for a name that is no account).
pub(crate) fn guard(
    client: &Client,
    account: Option<Uuid>,
    canonical_name: &str,
    epoch: Option<&[u8]>,
) -> AppResult<Guard> {
    let subject = match account {
        Some(id) => format!("account:{id}"),
        None => format!("name:{canonical_name}"),
    };
    let lockout = format!("{subject}\0ip:{}", client.ip);
    let known = match (account, epoch) {
        (Some(id), Some(epoch)) => client.knows(id, epoch),
        _ => false,
    };
    let ceiling = (!known).then(|| Ceiling {
        account: ratelimit::hash_token(&subject),
        source: ratelimit::hash_token(&lockout),
    });
    let too_many = || {
        AppError::too_many_requests("too many failed attempts, try again later")
            .with_details(serde_json::json!({ "code": "accountLocked" }))
    };
    // The ceilings first: refused there, the attempt takes nothing from this
    // client's own lockout (a person retrying while an attack holds the
    // ceiling does not lock their own address too).
    if let Some(ceiling) = &ceiling {
        if !ceiling.take() {
            return Err(too_many());
        }
    }
    if !ratelimit::LOGIN_LOCKOUT.reserve(&lockout) {
        if let Some(ceiling) = &ceiling {
            ceiling.give_back();
        }
        return Err(too_many());
    }
    Ok(Guard { lockout, ceiling })
}

impl Guard {
    /// Checks `secret` against `hash` at full cost, `None` for either paying
    /// the same cost. A right secret gives the attempt's slots back.
    pub(crate) fn verify(&self, secret: Option<&[u8]>, hash: Option<&str>) -> bool {
        let ok = match (secret, hash) {
            (Some(secret), Some(hash)) => verify_hash(secret, hash),
            _ => {
                let _ = bcrypt::verify("kutup-timing-only-not", &FAKE_BCRYPT_HASH);
                false
            }
        };
        if ok {
            ratelimit::LOGIN_LOCKOUT.succeeded(&self.lockout);
            if let Some(ceiling) = &self.ceiling {
                ceiling.give_back();
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

/// A parsed `kutup_known` value: `user id ‖ issued at (seconds, big-endian)
/// ‖ tag`, base64url; the tag is an HMAC over the account, the time and the
/// account's credential epoch.
struct KnownClient {
    user_id: Uuid,
    issued_at: i64,
    tag: [u8; 16],
}

impl KnownClient {
    fn parse(value: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        if bytes.len() != 40 {
            return None;
        }
        Some(Self {
            user_id: Uuid::from_slice(&bytes[..16]).ok()?,
            issued_at: i64::from_be_bytes(bytes[16..24].try_into().ok()?),
            tag: bytes[24..].try_into().ok()?,
        })
    }

    fn is_valid(&self, key: &[u8; 32], epoch: &[u8], now: i64) -> bool {
        let fresh = match now.checked_sub(self.issued_at) {
            Some(age) => (-60..KNOWN_CLIENT_DAYS * 86_400).contains(&age),
            None => false,
        };
        fresh
            && subtle_eq(
                &known_client_tag(key, self.user_id, self.issued_at, epoch),
                &self.tag,
            )
    }
}

fn known_client_tag(key: &[u8; 32], user_id: Uuid, issued_at: i64, epoch: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(user_id.as_bytes());
    mac.update(&issued_at.to_be_bytes());
    mac.update(epoch);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&mac.finalize().into_bytes()[..16]);
    tag
}

fn seal_known_client(key: &[u8; 32], user_id: Uuid, issued_at: i64, epoch: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(user_id.as_bytes());
    bytes.extend_from_slice(&issued_at.to_be_bytes());
    bytes.extend_from_slice(&known_client_tag(key, user_id, issued_at, epoch));
    URL_SAFE_NO_PAD.encode(bytes)
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The `Set-Cookie` value marking this client as one `user_id` signed in
/// from: HttpOnly, sent only to `/api`, `Secure` in production; bound to the
/// account's current password.
pub(crate) async fn known_client_cookie(state: &AppState, user_id: Uuid) -> AppResult<String> {
    let login_key_hash: String =
        sqlx::query_scalar("SELECT login_key_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let value = seal_known_client(
        &known_client_key(state).await?,
        user_id,
        time::OffsetDateTime::now_utc().unix_timestamp(),
        &credential_epoch(&login_key_hash),
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

/// Clears the mark on this origin (signing out).
pub(crate) fn clear_known_client_cookie(state: &AppState) -> String {
    let mut cookie =
        format!("{KNOWN_CLIENT_COOKIE}=; Max-Age=0; Path=/api; HttpOnly; SameSite=Strict");
    if state.config.app_env == "production" {
        cookie.push_str("; Secure");
    }
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];
    const NOW: i64 = 1_790_000_000;
    const EPOCH: [u8; 16] = [3; 16];

    fn opened(cookie: &str, epoch: &[u8], now: i64) -> Option<Uuid> {
        KnownClient::parse(cookie)
            .filter(|c| c.is_valid(&KEY, epoch, now))
            .map(|c| c.user_id)
    }

    #[test]
    fn a_known_client_cookie_names_its_account_until_it_expires_or_the_password_changes() {
        let id = Uuid::from_bytes([1; 16]);
        let cookie = seal_known_client(&KEY, id, NOW, &EPOCH);
        assert_eq!(opened(&cookie, &EPOCH, NOW), Some(id));
        assert_eq!(opened(&cookie, &EPOCH, NOW + 89 * 86_400), Some(id));
        assert_eq!(opened(&cookie, &EPOCH, NOW + 90 * 86_400), None);
        // A new password retires it.
        assert_eq!(opened(&cookie, &[4; 16], NOW), None);
        // A changed byte, a date from the future, an extreme date: refused.
        let mut bytes = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
        bytes[3] ^= 1;
        assert_eq!(opened(&URL_SAFE_NO_PAD.encode(&bytes), &EPOCH, NOW), None);
        assert_eq!(
            opened(
                &seal_known_client(&KEY, id, NOW + 3600, &EPOCH),
                &EPOCH,
                NOW
            ),
            None
        );
        assert_eq!(
            opened(&seal_known_client(&KEY, id, i64::MIN, &EPOCH), &EPOCH, NOW),
            None
        );
        assert_eq!(opened("", &EPOCH, NOW), None);
    }

    fn client(ip: &str, cookie: Option<(Uuid, [u8; 16])>) -> Client {
        Client {
            ip: ip.to_owned(),
            cookie: cookie.map(|(id, epoch)| {
                KnownClient::parse(&seal_known_client(
                    &KEY,
                    id,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                    &epoch,
                ))
                .unwrap()
            }),
            key: KEY,
            signed_in_as: None,
        }
    }

    #[test]
    fn the_lockout_holds_one_client_and_the_ceiling_spares_known_ones() {
        let id = Uuid::new_v4();
        let account = Some(id);
        let epoch = Some(&EPOCH[..]);
        let attacker = client("198.51.100.1", None);
        for _ in 0..5 {
            assert!(!guard(&attacker, account, "ada", epoch)
                .unwrap()
                .verify(None, None));
        }
        // Locked for that client only.
        assert!(guard(&attacker, account, "ada", epoch).is_err());
        assert!(guard(&client("203.0.113.9", None), account, "ada", epoch).is_ok());
        // Unknown clients together reach the ceiling...
        for i in 0..30u32 {
            let ip = format!("10.9.{}.1", i);
            let _ = guard(&client(&ip, None), account, "ada", epoch).map(|g| g.verify(None, None));
        }
        assert!(guard(&client("192.0.2.77", None), account, "ada", epoch).is_err());
        // ...but the account's own known device still gets to try,
        assert!(guard(
            &client("192.0.2.78", Some((id, EPOCH))),
            account,
            "ada",
            epoch
        )
        .is_ok());
        // and so does a caller signed in to it (reauth, the PIN).
        assert!(guard(
            &client("192.0.2.80", None).signed_in_as(id),
            account,
            "ada",
            epoch
        )
        .is_ok());
        // A cookie for another account, or from before a password change, does not count.
        assert!(guard(
            &client("192.0.2.79", Some((Uuid::new_v4(), EPOCH))),
            account,
            "ada",
            epoch
        )
        .is_err());
        assert!(guard(
            &client("192.0.2.81", Some((id, [4; 16]))),
            account,
            "ada",
            epoch
        )
        .is_err());
    }

    #[test]
    fn a_ceiling_refusal_takes_nothing_from_the_clients_lockout() {
        let id = Uuid::new_v4();
        let account = Some(id);
        let epoch = Some(&EPOCH[..]);
        // Spread misses fill the ceiling.
        for i in 0..25u32 {
            let ip = format!("10.33.{i}.1");
            let _ = guard(&client(&ip, None), account, "cyd", epoch).map(|g| g.verify(None, None));
        }
        // The person retries from home, refused by the ceiling each time...
        let home = client("203.0.113.50", None);
        for _ in 0..10 {
            assert!(guard(&home, account, "cyd", epoch).is_err());
        }
        // ...and their own address is not locked for it: from a known
        // device there, the attempt goes through to the check.
        assert!(guard(
            &client("203.0.113.50", Some((id, EPOCH))),
            account,
            "cyd",
            epoch
        )
        .is_ok());
    }

    #[test]
    fn a_right_secret_gives_its_slots_back() {
        let account = Some(Uuid::new_v4());
        let epoch = Some(&EPOCH[..]);
        let hash = bcrypt::hash("right", 4).unwrap();
        // Far more right answers than any limit: none of them count.
        for _ in 0..40 {
            assert!(guard(&client("198.51.100.5", None), account, "bea", epoch)
                .unwrap()
                .verify(Some(b"right"), Some(&hash)));
        }
    }

    #[test]
    fn unknown_names_meet_the_same_lockout() {
        let attacker = client("198.51.100.2", None);
        for _ in 0..5 {
            assert!(!guard(&attacker, None, "nobody-here", None)
                .unwrap()
                .verify(None, None));
        }
        assert!(guard(&attacker, None, "nobody-here", None).is_err());
    }
}
