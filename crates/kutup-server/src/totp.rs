//! TOTP setup/validation — mirrors `backend/services/totp.go` (`pquerna/otp` → `totp-rs`).
//!
//! SHA1, 6 digits, 30 s step — the parameters `pquerna/otp` uses, so codes are
//! interchangeable with the Go implementation for a given secret. Generation returns the
//! base32 secret (stored server-side) and the `otpauth://` provisioning URI (Go's
//! `key.URL()`); the client renders the QR from that URI.
//!
//! A code is checked against the steps `current - skew ..= current + skew`
//! (the skew is the `account.totp_skew_steps` setting) and the step it matched
//! is returned, so a caller accepts it only above the account's last accepted
//! step (`accounts.totp_last_step`, [`record_step`]): a code signs in once
//! (RFC 6238 §5.2).

use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

/// Seconds per step.
const STEP_SECONDS: u64 = 30;

/// Builds a `TOTP` from raw secret bytes with the shared parameters. Its own
/// skew is never used: [`matched_step_at`] walks the steps itself.
fn totp_from_bytes(
    bytes: Vec<u8>,
    issuer: Option<String>,
    account: String,
) -> Result<TOTP, String> {
    TOTP::new(Algorithm::SHA1, 6, 1, STEP_SECONDS, bytes, issuer, account)
        .map_err(|e| e.to_string())
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

/// Equal bytes, in time that depends on the lengths only.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The time step `code` belongs to at `unix_time`, for a stored base32
/// secret: each of `current - skew ..= current + skew` is compared (in
/// constant time, every one of them), and the latest that matches is
/// returned. Any decode or construction failure is a non-match (the Go
/// `totp.Validate` returns false likewise).
pub fn matched_step_at(secret: &str, code: &str, skew: u8, unix_time: u64) -> Option<i64> {
    let bytes = Secret::Encoded(secret.to_string()).to_bytes().ok()?;
    let totp = totp_from_bytes(bytes, None, String::new()).ok()?;
    let current = unix_time / STEP_SECONDS;
    let mut matched = None;
    for step in current.saturating_sub(u64::from(skew))..=current + u64::from(skew) {
        if constant_time_eq(
            totp.generate(step * STEP_SECONDS).as_bytes(),
            code.as_bytes(),
        ) {
            matched = Some(step);
        }
    }
    matched.and_then(|step| i64::try_from(step).ok())
}

/// [`matched_step_at`] now.
pub fn matched_step(secret: &str, code: &str, skew: u8) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    matched_step_at(secret, code, skew, now)
}

/// The account's skew, in steps either side of now (`account.totp_skew_steps`).
pub async fn skew_for<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    account: Uuid,
) -> Result<u8, sqlx::Error> {
    let skew = crate::site_settings::TOTP_SKEW_STEPS
        .load_for(executor, account)
        .await?;
    // The registry keeps it within 0..=2.
    Ok(u8::try_from(skew).unwrap_or(1))
}

/// Records `step` as the account's last accepted one, for the secret
/// `sealed` that matched it: whether it was above the last (a code is
/// accepted only then; `false` is a reused code, or a secret changed
/// meanwhile, and the caller answers it as a wrong one). One conditional
/// update, so of two requests with one code only one records it.
pub async fn record_step<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    account: Uuid,
    sealed: &[u8],
    step: i64,
) -> Result<bool, sqlx::Error> {
    let recorded = sqlx::query(
        "UPDATE accounts SET totp_last_step = $3
          WHERE id = $1 AND totp_secret_sealed = $2
            AND (totp_last_step IS NULL OR totp_last_step < $3)",
    )
    .bind(account)
    .bind(sealed)
    .bind(step)
    .execute(executor)
    .await?;
    Ok(recorded.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totp_for(secret: &str) -> TOTP {
        let bytes = Secret::Encoded(secret.to_string()).to_bytes().unwrap();
        totp_from_bytes(bytes, None, String::new()).unwrap()
    }

    #[test]
    fn generated_secret_validates_its_own_current_code() {
        let (secret, uri) = generate_totp("user@example.com", "Kutup").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=Kutup"));

        let code = totp_for(&secret).generate_current().unwrap();
        assert!(matched_step(&secret, &code, 1).is_some());
    }

    #[test]
    fn a_code_matches_with_its_own_step_within_the_skew() {
        let (secret, _) = generate_totp("user@example.com", "Kutup").unwrap();
        let totp = totp_for(&secret);
        // Mid-step, so the step boundaries are clear.
        let now = 1_900_000_015_u64;
        let current = (now / STEP_SECONDS) as i64;
        for offset in [-1_i64, 0, 1] {
            let step = current + offset;
            let code = totp.generate(step as u64 * STEP_SECONDS);
            // Another step with the same code (one in a million) would be
            // the latest; skip that draw.
            let unique = (-1..=1)
                .filter(|o| totp.generate((current + o) as u64 * STEP_SECONDS) == code)
                .count()
                == 1;
            if unique {
                assert_eq!(matched_step_at(&secret, &code, 1, now), Some(step));
            }
        }
    }

    #[test]
    fn a_code_outside_the_skew_does_not_match() {
        let (secret, _) = generate_totp("user@example.com", "Kutup").unwrap();
        let totp = totp_for(&secret);
        let now = 1_900_000_015_u64;
        let current = now / STEP_SECONDS;
        for step in [current - 2, current + 2] {
            let code = totp.generate(step * STEP_SECONDS);
            // Skip the one-in-a-million draw where another step near now
            // has the same code.
            let unique = (current - 2..=current + 2)
                .filter(|s| totp.generate(s * STEP_SECONDS) == code)
                .count()
                == 1;
            if unique {
                assert_eq!(matched_step_at(&secret, &code, 1, now), None);
                // A wider skew takes it, with its step.
                assert_eq!(matched_step_at(&secret, &code, 2, now), Some(step as i64));
            }
        }
        // Skew 0: only the current step.
        let previous = totp.generate((current - 1) * STEP_SECONDS);
        if previous != totp.generate(current * STEP_SECONDS) {
            assert_eq!(matched_step_at(&secret, &previous, 0, now), None);
        }
        assert_eq!(
            matched_step_at(&secret, &totp.generate(now), 0, now),
            Some(current as i64)
        );
    }

    #[test]
    fn wrong_code_fails() {
        let (secret, _) = generate_totp("user@example.com", "Kutup").unwrap();
        let now = 1_900_000_015_u64;
        let current = now / STEP_SECONDS;
        let totp = totp_for(&secret);
        let wrong = (0..10)
            .map(|d| format!("{d}{d}{d}{d}{d}{d}"))
            .find(|code| {
                (current - 1..=current + 1).all(|s| &totp.generate(s * STEP_SECONDS) != code)
            })
            .unwrap();
        assert_eq!(matched_step_at(&secret, &wrong, 1, now), None);
        assert_eq!(matched_step_at(&secret, "12345", 1, now), None);
        assert_eq!(matched_step_at(&secret, "", 1, now), None);
    }

    #[test]
    fn garbage_secret_is_non_match() {
        assert!(matched_step("not base32 $$$", "123456", 1).is_none());
    }

    /// `accounts.totp_last_step` against a live database: a step is taken
    /// once, two racing takes of one step leave exactly one winner, a later
    /// step still goes, another secret's step doesn't, and a secret turned
    /// off forgets the step. The skew is read per account.
    #[tokio::test]
    async fn live_a_step_is_taken_once() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let account = Uuid::new_v4();
        let name = format!("totp{}", &account.simple().to_string()[..12]);
        let sealed = vec![7_u8; 64];
        sqlx::query(
            "INSERT INTO accounts (id, username, identity_suite, drive_key_binding_epoch,
                                   master_key_generation, totp_secret_sealed)
             VALUES ($1, $2, 2, 1, 1, $3)",
        )
        .bind(account)
        .bind(&name)
        .bind(&sealed)
        .execute(&pool)
        .await
        .unwrap();

        let step = 63_333_333_i64;
        assert!(record_step(&pool, account, &sealed, step).await.unwrap());
        assert!(
            !record_step(&pool, account, &sealed, step).await.unwrap(),
            "the same code twice"
        );
        assert!(!record_step(&pool, account, &sealed, step - 1)
            .await
            .unwrap());
        assert!(
            record_step(&pool, account, &sealed, step + 1)
                .await
                .unwrap(),
            "the next step's code"
        );
        assert!(
            !record_step(&pool, account, &[8_u8; 64], step + 2)
                .await
                .unwrap(),
            "a step matched against a secret no longer the account's"
        );

        // Racing: of two takes of one step, exactly one wins, every time.
        for round in 2..22 {
            let (a, b) = tokio::join!(
                record_step(&pool, account, &sealed, step + round),
                record_step(&pool, account, &sealed, step + round),
            );
            assert!(a.unwrap() ^ b.unwrap(), "round {round}");
        }

        // A last step outlives no secret: turning it off forgets it (and
        // the check refuses a step without a secret).
        let mut tx = pool.begin().await.unwrap();
        crate::two_factor::turn_off(&mut tx, account).await.unwrap();
        tx.commit().await.unwrap();
        let last: Option<i64> =
            sqlx::query_scalar("SELECT totp_last_step FROM accounts WHERE id = $1")
                .bind(account)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(last, None);
        assert!(
            sqlx::query("UPDATE accounts SET totp_last_step = 1 WHERE id = $1")
                .bind(account)
                .execute(&pool)
                .await
                .is_err()
        );
        // A new secret takes its codes from any step on.
        let renewed = vec![9_u8; 64];
        sqlx::query("UPDATE accounts SET totp_secret_sealed = $2 WHERE id = $1")
            .bind(account)
            .bind(&renewed)
            .execute(&pool)
            .await
            .unwrap();
        assert!(record_step(&pool, account, &renewed, step).await.unwrap());

        // The skew: the site's (the first, 1) unless the account has its own.
        assert_eq!(skew_for(&pool, account).await.unwrap(), 1);
        sqlx::query(
            "INSERT INTO account_entitlements (account_id, key, value, source)
             VALUES ($1, 'account.totp_skew_steps', 0, 'admin')",
        )
        .bind(account)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(skew_for(&pool, account).await.unwrap(), 0);

        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn constant_time_eq_compares_bytes_and_lengths() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"123456", b"12345"));
        assert!(constant_time_eq(b"", b""));
    }
}
