//! Two-factor recovery codes (docs/plans/security-keys.md, D2; Proton's):
//! one-time codes made when two-factor sign-in is turned on, each taking the
//! second factor's place once, at sign-in or to turn it off.
//!
//! A code is 10 characters of Crockford's base32 (50 bits), shown as
//! `xxxxx-xxxxx`. Only its MAC is stored, under a key the server makes for
//! itself (`server_generated_keys`) and bound to the account, so a code is
//! found by its MAC and works for its own account only.

use kutup_crypto::primitives::{mac, random_below, Suite};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;

/// Crockford's base32, lower case: no i, l, o or u, so nothing reads as
/// another.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
/// The characters in a code, without its dash.
const CODE_CHARS: usize = 10;
const MAC_LABEL: &[u8] = kutup_crypto::labels::TWO_FACTOR_RECOVERY_CODE_V1;

static KEY: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();

async fn key(pool: &PgPool) -> AppResult<&'static [u8; 32]> {
    KEY.get_or_try_init(|| async {
        crate::server_keys::load_or_create(pool, crate::server_keys::GeneratedKey::RecoveryCodes)
            .await
            .map_err(|error| {
                crate::error::AppError::internal(format!("recovery code key: {error}"))
            })
    })
    .await
}

/// A new code, as shown.
fn generate() -> String {
    let mut code = String::with_capacity(CODE_CHARS + 1);
    for index in 0..CODE_CHARS {
        if index == CODE_CHARS / 2 {
            code.push('-');
        }
        code.push(ALPHABET[random_below(ALPHABET.len() as u64) as usize] as char);
    }
    code
}

/// A code as typed, made canonical: case, spaces and dashes ignored, I and L
/// read as 1, O as 0. `None` for anything that is not a code, such as a
/// six-digit authenticator code.
pub(crate) fn normalize(input: &str) -> Option<String> {
    let mut code = String::with_capacity(CODE_CHARS);
    for character in input.chars() {
        let character = match character.to_ascii_lowercase() {
            ' ' | '-' => continue,
            'i' | 'l' => '1',
            'o' => '0',
            other => other,
        };
        if !ALPHABET.contains(&(character as u8)) || !character.is_ascii() {
            return None;
        }
        code.push(character);
    }
    (code.len() == CODE_CHARS).then_some(code)
}

fn code_mac(key: &[u8; 32], user_id: Uuid, canonical: &str) -> [u8; 32] {
    mac(
        Suite::V1,
        key,
        &[MAC_LABEL, user_id.as_bytes(), canonical.as_bytes()],
    )
    .to_array()
}

/// Replaces the account's codes with `count` new ones, in `tx`; the codes,
/// to show once.
pub(crate) async fn replace(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    user_id: Uuid,
    count: i64,
) -> AppResult<Vec<String>> {
    let key = key(pool).await?;
    clear(tx, user_id).await?;
    let mut codes = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    while i64::try_from(codes.len()).unwrap_or(i64::MAX) < count {
        let code = generate();
        let canonical = normalize(&code).expect("a generated code is canonical");
        let stored = sqlx::query(
            "INSERT INTO two_factor_recovery_codes (user_id, code_mac) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(&code_mac(key, user_id, &canonical)[..])
        .execute(&mut **tx)
        .await?;
        // Two equal codes in one set (one chance in 2^50 per pair): draw again.
        if stored.rows_affected() == 1 {
            codes.push(code);
        }
    }
    Ok(codes)
}

/// Spends `input` if it is one of the account's codes; whether it was.
pub(crate) async fn spend(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    user_id: Uuid,
    input: &str,
) -> AppResult<bool> {
    let Some(canonical) = normalize(input) else {
        return Ok(false);
    };
    let key = key(pool).await?;
    let spent =
        sqlx::query("DELETE FROM two_factor_recovery_codes WHERE user_id = $1 AND code_mac = $2")
            .bind(user_id)
            .bind(&code_mac(key, user_id, &canonical)[..])
            .execute(&mut **tx)
            .await?;
    Ok(spent.rows_affected() == 1)
}

/// How many of the account's codes are left.
pub(crate) async fn remaining(pool: &PgPool, user_id: Uuid) -> AppResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM two_factor_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?,
    )
}

/// Drops the account's codes, in `tx`.
pub(crate) async fn clear(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM two_factor_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Turns every second factor off, in `tx` (the recovery phrase's path, an
/// administrator's reset, or the last factor removed): the authenticator
/// app, every security key and the recovery codes. Whether one was on.
pub(crate) async fn turn_off(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<bool> {
    let was_on = factors_locked(tx, user_id).await?.on();
    sqlx::query(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL,
                          security_keys_require_uv = false
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM user_security_keys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    clear(tx, user_id).await?;
    Ok(was_on)
}

/// The account's second factors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Factors {
    pub totp: bool,
    /// Security keys, compromised ones included: a key marked compromised
    /// still keeps two-step sign-in on until it is removed.
    pub keys: i64,
    /// Those still usable at sign-in.
    pub usable_keys: i64,
    pub recovery_codes: i64,
}

impl Factors {
    /// Two-factor sign-in is on while either factor is.
    pub fn on(self) -> bool {
        self.totp || self.keys > 0
    }

    /// The second steps a sign-in may take, in the order to offer them (a
    /// key first, as Proton's page does).
    pub fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.usable_keys > 0 {
            names.push("securityKey");
        }
        if self.totp {
            names.push("totp");
        }
        if self.recovery_codes > 0 {
            names.push("recoveryCode");
        }
        names
    }
}

const FACTORS: &str = "SELECT u.totp_enabled,
        (SELECT count(*) FROM user_security_keys k WHERE k.user_id = u.id),
        (SELECT count(*) FROM user_security_keys k WHERE k.user_id = u.id AND NOT k.compromised),
        (SELECT count(*) FROM two_factor_recovery_codes c WHERE c.user_id = u.id)
    FROM users u WHERE u.id = $1";

/// The account's factors.
pub(crate) async fn factors<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
) -> AppResult<Factors> {
    let row: Option<(bool, i64, i64, i64)> = sqlx::query_as(FACTORS)
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    Ok(row.map_or_else(
        Factors::default,
        |(totp, keys, usable_keys, recovery_codes)| Factors {
            totp,
            keys,
            usable_keys,
            recovery_codes,
        },
    ))
}

/// The account's factors with its row locked until `tx` ends: a change of
/// factors is made against what this read.
pub(crate) async fn factors_locked(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<Factors> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    factors(&mut **tx, user_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_code_is_canonical_and_shown_with_a_dash() {
        for _ in 0..200 {
            let code = generate();
            assert_eq!(code.len(), CODE_CHARS + 1);
            assert_eq!(code.as_bytes()[CODE_CHARS / 2], b'-');
            let canonical = normalize(&code).unwrap();
            assert_eq!(canonical, code.replace('-', ""));
        }
        assert_ne!(generate(), generate());
    }

    #[test]
    fn a_code_is_read_however_it_is_typed() {
        assert_eq!(normalize("ab1d0-xyz23").as_deref(), Some("ab1d0xyz23"));
        assert_eq!(normalize(" AB1D0 xyz23 ").as_deref(), Some("ab1d0xyz23"));
        assert_eq!(normalize("abIdO-xyz23").as_deref(), Some("ab1d0xyz23"));
        assert_eq!(normalize("abLd0xyz23").as_deref(), Some("ab1d0xyz23"));
        // Not codes: an authenticator code, a short or long one, a u, other
        // characters.
        assert_eq!(normalize("123456"), None);
        assert_eq!(normalize("ab1d0-xyz2"), None);
        assert_eq!(normalize("ab1d0-xyz234"), None);
        assert_eq!(normalize("ab1du-xyz23"), None);
        assert_eq!(normalize("ab1d0_xyz23"), None);
        assert_eq!(normalize("ab1d0-xyzé3"), None);
    }

    #[test]
    fn a_codes_mac_is_its_accounts_own() {
        let key = [7u8; 32];
        let (ada, ben) = (Uuid::from_bytes([1; 16]), Uuid::from_bytes([2; 16]));
        assert_eq!(
            code_mac(&key, ada, "ab1d0xyz23"),
            code_mac(&key, ada, "ab1d0xyz23")
        );
        assert_ne!(
            code_mac(&key, ada, "ab1d0xyz23"),
            code_mac(&key, ben, "ab1d0xyz23")
        );
        assert_ne!(
            code_mac(&key, ada, "ab1d0xyz23"),
            code_mac(&key, ada, "ab1d0xyz24")
        );
        assert_ne!(
            code_mac(&key, ada, "ab1d0xyz23"),
            code_mac(&[8; 32], ada, "ab1d0xyz23")
        );
    }
}
