//! TOTP setup/validation — mirrors `backend/services/totp.go` (`pquerna/otp` → `totp-rs`).
//!
//! SHA1, 6 digits, 30 s step, skew 1 — the defaults `pquerna/otp` uses, so codes are
//! interchangeable with the Go implementation for a given secret. Generation returns the
//! base32 secret (stored server-side) and the `otpauth://` provisioning URI (Go's
//! `key.URL()`); the client renders the QR from that URI.

use totp_rs::{Algorithm, Secret, TOTP};

/// Builds a `TOTP` from raw secret bytes with the shared parameters.
fn totp_from_bytes(
    bytes: Vec<u8>,
    issuer: Option<String>,
    account: String,
) -> Result<TOTP, String> {
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, issuer, account).map_err(|e| e.to_string())
}

/// Creates a new TOTP secret + provisioning URI — mirrors `GenerateTOTP`.
/// Returns `(base32_secret, otpauth_uri)`.
pub fn generate_totp(email: &str, issuer: &str) -> Result<(String, String), String> {
    let secret = Secret::generate_secret()
        .to_bytes()
        .map_err(|e| e.to_string())?;
    let totp = totp_from_bytes(secret, Some(issuer.to_string()), email.to_string())?;
    Ok((totp.get_secret_base32(), totp.get_url()))
}

/// Checks a code against a stored base32 secret — mirrors `ValidateTOTP`. Any decode or
/// construction failure is a non-match (the Go `totp.Validate` returns false likewise).
pub fn validate_totp(secret: &str, code: &str) -> bool {
    let bytes = match Secret::Encoded(secret.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match totp_from_bytes(bytes, None, String::new()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_validates_its_own_current_code() {
        let (secret, uri) = generate_totp("user@example.com", "Kutup").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=Kutup"));

        let bytes = Secret::Encoded(secret.clone()).to_bytes().unwrap();
        let totp = totp_from_bytes(bytes, None, String::new()).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(validate_totp(&secret, &code));
    }

    #[test]
    fn wrong_code_fails() {
        let (secret, _) = generate_totp("user@example.com", "Kutup").unwrap();
        assert!(!validate_totp(&secret, "000000"));
    }

    #[test]
    fn garbage_secret_is_non_match() {
        assert!(!validate_totp("not base32 $$$", "123456"));
    }
}
