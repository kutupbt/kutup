//! JWT issue/verify — mirrors `backend/utils/jwt.go` (`golang-jwt/jwt/v5` → `jsonwebtoken`).
//!
//! HS256 over `JWT_SECRET`. Claims carry `userId` + `isAdmin` plus the registered
//! `exp`/`iat`, and a `sub` ("setup" | "pre-auth") that marks special-purpose tokens.
//! Plain access/refresh tokens have an empty subject; the auth middleware rejects any
//! token whose subject is set. Lifetimes are identical to Go: access 15m, refresh 7d,
//! setup 15m, pre-auth 5m.

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
    pub exp: i64,
    pub iat: i64,
}

const ACCESS_TTL_SECS: i64 = 15 * 60;
const REFRESH_TTL_SECS: i64 = 7 * 24 * 60 * 60;
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
        exp: now + ttl_secs,
        iat: now,
    }
}

/// 15-minute access token — mirrors `GenerateAccessToken`.
pub fn generate_access_token(
    user_id: &str,
    is_admin: bool,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    sign(&base_claims(user_id, is_admin, "", ACCESS_TTL_SECS), secret)
}

/// 7-day refresh token — mirrors `GenerateRefreshToken` (isAdmin omitted ⇒ false).
pub fn generate_refresh_token(
    user_id: &str,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    sign(&base_claims(user_id, false, "", REFRESH_TTL_SECS), secret)
}

/// 15-minute first-login setup token — mirrors `GenerateSetupToken`.
pub fn generate_setup_token(
    user_id: &str,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    sign(
        &base_claims(user_id, false, "setup", SETUP_TTL_SECS),
        secret,
    )
}

/// 5-minute TOTP-challenge token — mirrors `GeneratePreAuthToken`.
pub fn generate_pre_auth_token(
    user_id: &str,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    sign(
        &base_claims(user_id, false, "pre-auth", PRE_AUTH_TTL_SECS),
        secret,
    )
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

/// Validates a setup token and returns its userID — mirrors `ValidateSetupToken`.
pub fn validate_setup_token(token: &str, secret: &str) -> Result<String, String> {
    let claims = validate_token(token, secret).map_err(|e| e.to_string())?;
    if claims.sub != "setup" {
        return Err("not a setup token".to_string());
    }
    Ok(claims.user_id)
}

/// Validates a pre-auth token and returns its userID — mirrors `ValidatePreAuthToken`.
pub fn validate_pre_auth_token(token: &str, secret: &str) -> Result<String, String> {
    let claims = validate_token(token, secret).map_err(|e| e.to_string())?;
    if claims.sub != "pre-auth" {
        return Err("not a pre-auth token".to_string());
    }
    Ok(claims.user_id)
}

/// Validates an access token (header or `?token=`) and returns `(userID, isAdmin)`.
/// Rejects setup/pre-auth tokens — mirrors `AuthMiddleware.ValidateTokenString`.
pub fn validate_access_token(token: &str, secret: &str) -> Result<(String, bool), String> {
    let claims = validate_token(token, secret).map_err(|e| e.to_string())?;
    if !claims.sub.is_empty() {
        return Err("not an access token".to_string());
    }
    Ok((claims.user_id, claims.is_admin))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-that-is-at-least-32-bytes-long!!";

    #[test]
    fn access_token_roundtrips_with_claims() {
        let t = generate_access_token("u1", true, SECRET).unwrap();
        let c = validate_token(&t, SECRET).unwrap();
        assert_eq!(c.user_id, "u1");
        assert!(c.is_admin);
        assert_eq!(c.sub, "");
        assert_eq!(c.exp - c.iat, ACCESS_TTL_SECS);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let t = generate_access_token("u1", false, SECRET).unwrap();
        assert!(validate_token(&t, "another-secret-also-32-bytes-long-yeah").is_err());
    }

    #[test]
    fn setup_and_pre_auth_subjects_are_enforced() {
        let setup = generate_setup_token("u2", SECRET).unwrap();
        assert_eq!(validate_setup_token(&setup, SECRET).unwrap(), "u2");
        assert!(validate_pre_auth_token(&setup, SECRET).is_err());

        let pre = generate_pre_auth_token("u3", SECRET).unwrap();
        assert_eq!(validate_pre_auth_token(&pre, SECRET).unwrap(), "u3");
        assert!(validate_setup_token(&pre, SECRET).is_err());
    }

    #[test]
    fn access_validation_rejects_special_tokens() {
        let setup = generate_setup_token("u4", SECRET).unwrap();
        assert!(validate_access_token(&setup, SECRET).is_err());
        let access = generate_access_token("u4", false, SECRET).unwrap();
        assert_eq!(
            validate_access_token(&access, SECRET).unwrap(),
            ("u4".to_string(), false)
        );
    }

    #[test]
    fn refresh_token_has_empty_subject_and_7d_ttl() {
        let t = generate_refresh_token("u5", SECRET).unwrap();
        let c = validate_token(&t, SECRET).unwrap();
        assert_eq!(c.sub, "");
        assert!(!c.is_admin);
        assert_eq!(c.exp - c.iat, REFRESH_TTL_SECS);
    }

    #[test]
    fn expired_token_is_rejected() {
        // Hand-roll an already-expired access token.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            user_id: "u6".into(),
            is_admin: false,
            sub: String::new(),
            exp: now - 10,
            iat: now - 100,
        };
        let t = sign(&claims, SECRET).unwrap();
        assert!(validate_token(&t, SECRET).is_err());
    }
}
