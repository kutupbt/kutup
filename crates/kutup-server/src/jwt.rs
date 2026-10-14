//! JWT issue/verify — mirrors `backend/utils/jwt.go` (`golang-jwt/jwt/v5` → `jsonwebtoken`).
//!
//! HS256 over `JWT_SECRET`. Claims carry `userId` + `isAdmin` plus the registered
//! `exp`/`iat`, and a `sub` ("setup" | "pre-auth") that marks special-purpose tokens.
//! Access tokens have an empty subject and carry the server-side session id (`sid`);
//! the auth layer rejects any token whose subject is set and checks that the session
//! is still live (`sessions::live`). Refresh tokens are not JWTs: they are opaque
//! rotating secrets owned by `sessions`. Lifetimes: access 15m, setup 15m, pre-auth 5m.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Token claims — mirrors `utils.Claims` (the embedded `RegisteredClaims` fields are
/// flattened here as `exp`/`iat`/`sub`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "isAdmin")]
    pub is_admin: bool,
    /// Registered `sub`. Empty/absent for access & refresh tokens; "setup" / "pre-auth"
    /// for the short-lived special tokens. `omitempty` in Go ⇒ skip when empty here.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sub: String,
    /// Server-side session id; set on access tokens only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    /// Setup and pre-auth tokens: the account's credential epoch when the
    /// password was proved (base64url), so the token is good only while the
    /// account's record is still that one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ep: String,
    pub exp: i64,
    pub iat: i64,
}

const ACCESS_TTL_SECS: i64 = 15 * 60;
const SETUP_TTL_SECS: i64 = 15 * 60;
const PRE_AUTH_TTL_SECS: i64 = 5 * 60;

fn sign(claims: &Claims, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

fn base_claims(user_id: &str, is_admin: bool, sub: &str, ttl_secs: i64) -> Claims {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Claims {
        user_id: user_id.to_string(),
        is_admin,
        sub: sub.to_string(),
        sid: String::new(),
        ep: String::new(),
        exp: now + ttl_secs,
        iat: now,
    }
}

/// 15-minute access token bound to a server-side session.
pub fn generate_access_token(
    user_id: &str,
    is_admin: bool,
    session_id: &str,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut claims = base_claims(user_id, is_admin, "", ACCESS_TTL_SECS);
    claims.sid = session_id.to_string();
    sign(&claims, secret)
}

fn with_epoch(mut claims: Claims, epoch: &[u8]) -> Claims {
    use base64::Engine as _;
    claims.ep = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(epoch);
    claims
}

/// 15-minute first-login setup token, bound to the credential epoch of the
/// temporary password it was signed in with.
pub fn generate_setup_token(
    user_id: &str,
    epoch: &[u8],
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    sign(
        &with_epoch(base_claims(user_id, false, "setup", SETUP_TTL_SECS), epoch),
        secret,
    )
}

/// 5-minute TOTP-challenge token, bound to the credential epoch of the
/// password it follows.
pub fn generate_pre_auth_token(
    user_id: &str,
    epoch: &[u8],
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    sign(
        &with_epoch(
            base_claims(user_id, false, "pre-auth", PRE_AUTH_TTL_SECS),
            epoch,
        ),
        secret,
    )
}

/// A setup or pre-auth token's user id and credential epoch.
fn special(token: &str, secret: &str, sub: &str) -> Result<(String, Vec<u8>), String> {
    use base64::Engine as _;
    let claims = validate_token(token, secret).map_err(|e| e.to_string())?;
    if claims.sub != sub {
        return Err(format!("not a {sub} token"));
    }
    let epoch = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&claims.ep)
        .ok()
        .filter(|epoch| epoch.len() == 16)
        .ok_or_else(|| "token has no credential epoch".to_string())?;
    Ok((claims.user_id, epoch))
}

/// Verifies an HS256 token's signature + expiry — mirrors `ValidateToken`. Rejects
/// non-HMAC algorithms (the alg allowlist) and expired tokens. Leeway 0 + no audience
/// check matches golang-jwt's defaults for our tokens.
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    validation.validate_aud = false;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

/// Whether `token` is one this server signed as a setup token, expired or
/// not: only to say which refusal a client gets (an expired setup token
/// means signing in again), never to accept it.
pub fn is_setup_token_signed(token: &str, secret: &str) -> bool {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .is_ok_and(|data| data.claims.sub == "setup")
}

/// Validates a setup token: its user id and credential epoch.
pub fn validate_setup_token(token: &str, secret: &str) -> Result<(String, Vec<u8>), String> {
    special(token, secret, "setup")
}

/// Validates a pre-auth token: its user id and credential epoch.
pub fn validate_pre_auth_token(token: &str, secret: &str) -> Result<(String, Vec<u8>), String> {
    special(token, secret, "pre-auth")
}

/// Validates an access token (header or `?token=`) and returns `(userID, sessionID)`.
/// Rejects setup/pre-auth tokens and tokens without a session. Whether the session
/// is still live is the caller's check (`sessions::live`).
pub fn validate_access_token(token: &str, secret: &str) -> Result<(String, String), String> {
    let claims = validate_token(token, secret).map_err(|e| e.to_string())?;
    if !claims.sub.is_empty() {
        return Err("not an access token".to_string());
    }
    if claims.sid.is_empty() {
        return Err("access token has no session".to_string());
    }
    Ok((claims.user_id, claims.sid))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-that-is-at-least-32-bytes-long!!";

    #[test]
    fn access_token_roundtrips_with_claims() {
        let t = generate_access_token("u1", true, "s1", SECRET).unwrap();
        let c = validate_token(&t, SECRET).unwrap();
        assert_eq!(c.user_id, "u1");
        assert!(c.is_admin);
        assert_eq!(c.sub, "");
        assert_eq!(c.sid, "s1");
        assert_eq!(c.exp - c.iat, ACCESS_TTL_SECS);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let t = generate_access_token("u1", false, "s1", SECRET).unwrap();
        assert!(validate_token(&t, "another-secret-also-32-bytes-long-yeah").is_err());
    }

    #[test]
    fn setup_and_pre_auth_subjects_are_enforced() {
        let setup = generate_setup_token("u2", &[2; 16], SECRET).unwrap();
        assert_eq!(
            validate_setup_token(&setup, SECRET).unwrap(),
            ("u2".to_string(), vec![2; 16])
        );
        assert!(validate_pre_auth_token(&setup, SECRET).is_err());

        let pre = generate_pre_auth_token("u3", &[3; 16], SECRET).unwrap();
        assert_eq!(
            validate_pre_auth_token(&pre, SECRET).unwrap(),
            ("u3".to_string(), vec![3; 16])
        );
        assert!(validate_setup_token(&pre, SECRET).is_err());
    }

    #[test]
    fn an_expired_setup_token_is_still_known_as_one() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut claims = base_claims("u7", false, "setup", SETUP_TTL_SECS);
        claims.exp = now - 10;
        let expired = sign(&claims, SECRET).unwrap();
        assert!(validate_setup_token(&expired, SECRET).is_err());
        assert!(is_setup_token_signed(&expired, SECRET));
        let access = generate_access_token("u7", false, "s7", SECRET).unwrap();
        assert!(!is_setup_token_signed(&access, SECRET));
        assert!(!is_setup_token_signed(
            &expired,
            "another-secret-also-32-bytes-long-yeah"
        ));
    }

    #[test]
    fn access_validation_rejects_special_tokens() {
        let setup = generate_setup_token("u4", &[4; 16], SECRET).unwrap();
        assert!(validate_access_token(&setup, SECRET).is_err());
        let access = generate_access_token("u4", false, "s4", SECRET).unwrap();
        assert_eq!(
            validate_access_token(&access, SECRET).unwrap(),
            ("u4".to_string(), "s4".to_string())
        );
    }

    #[test]
    fn access_validation_requires_a_session() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            user_id: "u5".into(),
            is_admin: false,
            sub: String::new(),
            sid: String::new(),
            ep: String::new(),
            exp: now + 60,
            iat: now,
        };
        let t = sign(&claims, SECRET).unwrap();
        assert!(validate_access_token(&t, SECRET).is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        // Hand-roll an already-expired access token.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            user_id: "u6".into(),
            is_admin: false,
            sub: String::new(),
            sid: String::new(),
            ep: String::new(),
            exp: now - 10,
            iat: now - 100,
        };
        let t = sign(&claims, SECRET).unwrap();
        assert!(validate_token(&t, SECRET).is_err());
    }
}
