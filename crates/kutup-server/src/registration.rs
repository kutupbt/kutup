//! Who may register (docs/plans/registration-codes.md): the registration
//! mode an administrator sets (`on`, `code`, `off`) and the referral codes
//! that admit a sign-up when the mode asks for one.
//!
//! A code is 20 Crockford base32 characters (100 random bits), shown to the
//! administrator once. The server keeps only its HMAC under a key of its own
//! (`server_keys`), so a dump of the table gives no usable code, and a code is
//! found by that hash, so comparing takes the same time for any input. A code
//! is redeemed in the transaction that creates the account, by one
//! conditional update, so a code with N uses admits N accounts however many
//! sign up at once.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::AppState;

/// The site setting that holds the mode.
pub const MODE_SETTING: &str = "registration_mode";

/// Who may register.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationMode {
    /// Anyone; a code may be given (and is recorded).
    On,
    /// Only with a valid referral code.
    Code,
    /// Nobody; a code admits no one either.
    Off,
}

impl RegistrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Code => "code",
            Self::Off => "off",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "on" => Some(Self::On),
            "code" => Some(Self::Code),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// The mode now. The database is the only source: [`seed_mode`] writes
/// `REGISTRATION_MODE` there once, at startup, if no mode is stored yet. A
/// missing row (which seeding prevents) reads as `off`, never as open.
pub async fn mode(state: &AppState) -> AppResult<RegistrationMode> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(MODE_SETTING)
            .fetch_optional(&state.pool)
            .await?;
    Ok(stored
        .as_deref()
        .and_then(RegistrationMode::parse)
        .unwrap_or(RegistrationMode::Off))
}

/// Writes `configured` (`REGISTRATION_MODE`, default `off`) as the mode when
/// the database has none: a new database. A stored mode is never changed, so
/// after the first start only an administrator changes it.
pub async fn seed_mode(pool: &PgPool, configured: RegistrationMode) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(MODE_SETTING)
    .bind(configured.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Stores `mode` as the administrators' choice.
pub async fn set_mode(
    tx: &mut Transaction<'_, Postgres>,
    mode: RegistrationMode,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(MODE_SETTING)
    .bind(mode.as_str())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// --- codes -------------------------------------------------------------------

/// Crockford's base32: no I, L, O or U, so a code read aloud survives.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters in a code (5 bits each: 100 bits).
pub const CODE_LEN: usize = 20;
const GROUP: usize = 5;
const HINT_LEN: usize = 4;

/// A new code, as shown: `7KQ2M-9XD4T-PAV3W-8HCNR`.
pub fn generate() -> String {
    let chars: Vec<u8> = (0..CODE_LEN)
        .map(|_| ALPHABET[kutup_crypto::primitives::random_below(ALPHABET.len() as u64) as usize])
        .collect();
    chars
        .chunks(GROUP)
        .map(|group| std::str::from_utf8(group).expect("ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// A code as typed, made canonical: case, spaces and dashes ignored, I and L
/// read as 1, O as 0. `None` for anything that is not a code.
pub fn canonical(input: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
        if out.len() > CODE_LEN {
            return None;
        }
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// What a code's row is found by: its HMAC under the server's key.
pub fn hash(key: &[u8; 32], canonical: &str) -> [u8; 32] {
    kutup_crypto::primitives::mac(
        kutup_crypto::primitives::Suite::V1,
        key,
        &[b"kutup/registration-code/v1\0", canonical.as_bytes()],
    )
    .to_array()
}

/// What the administrator sees of a code after it is made.
pub fn hint(canonical: &str) -> String {
    canonical[canonical.len() - HINT_LEN..].to_owned()
}

static CODES_KEY: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();

/// The server's own key for codes: made once and stored, rotated with no
/// other secret. Losing it (a new database) voids every open code.
pub async fn codes_key(pool: &PgPool) -> AppResult<[u8; 32]> {
    CODES_KEY
        .get_or_try_init(|| async {
            crate::server_keys::load_or_create(
                pool,
                crate::server_keys::GeneratedKey::RegistrationCodes,
            )
            .await
        })
        .await
        .copied()
        .map_err(|error| {
            tracing::error!(%error, "registration code key");
            AppError::internal("registration code key")
        })
}

/// The one answer for a code that admits no one, whatever the reason
/// (unknown, expired, revoked, used up), so the answer tells nothing.
pub fn invalid() -> AppError {
    AppError::forbidden("this referral code cannot be used")
        .with_details(serde_json::json!({ "code": "registrationCodeInvalid" }))
}

/// The SQL condition of a code that can still admit someone.
const REDEEMABLE: &str = "revoked_at IS NULL
     AND (expires_at IS NULL OR expires_at > now())
     AND (max_uses IS NULL OR uses < max_uses)";

/// Whether the code hashed as `hash` could admit a sign-up now (it uses
/// nothing up).
pub async fn redeemable(pool: &PgPool, hash: &[u8; 32]) -> AppResult<bool> {
    let found: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM registration_codes WHERE code_hash = $1 AND {REDEEMABLE}"
    ))
    .bind(hash.as_slice())
    .fetch_optional(pool)
    .await?;
    Ok(found.is_some())
}

/// Uses up one use of the code hashed as `hash`, in the transaction that
/// creates the account (rolled back with it), and returns the code's id;
/// `None` when it admits no one. The row's lock orders concurrent sign-ups.
pub async fn redeem(
    tx: &mut Transaction<'_, Postgres>,
    hash: &[u8; 32],
) -> AppResult<Option<Uuid>> {
    Ok(sqlx::query_scalar(&format!(
        "UPDATE registration_codes SET uses = uses + 1
          WHERE code_hash = $1 AND {REDEEMABLE}
          RETURNING id"
    ))
    .bind(hash.as_slice())
    .fetch_optional(&mut **tx)
    .await?)
}

/// Records which code `user_id` signed up with.
pub async fn record_use(
    tx: &mut Transaction<'_, Postgres>,
    code_id: Uuid,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO registration_code_uses (code_id, user_id) VALUES ($1, $2)")
        .bind(code_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Counts a code that admitted no one against the client's address, and
/// refuses once it has had too many: `Err` 429 before the code is even
/// looked at, so guessing is slow. A good code gives its count back
/// ([`attempt_succeeded`]).
pub fn attempt(client: &str) -> AppResult<()> {
    if !crate::ratelimit::REGISTRATION_CODE_FAILURES.allow(client) {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    Ok(())
}

pub fn attempt_succeeded(client: &str) {
    crate::ratelimit::REGISTRATION_CODE_FAILURES.pop(client);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_100_bits_in_groups_and_read_back_however_typed() {
        let code = generate();
        assert_eq!(code.len(), CODE_LEN + 3);
        assert_eq!(code.matches('-').count(), 3);
        let canon = canonical(&code).unwrap();
        assert_eq!(canon.len(), CODE_LEN);
        // Lowercase, spaces, no dashes: the same code.
        let typed = code.to_lowercase().replace('-', " ");
        assert_eq!(canonical(&typed).unwrap(), canon);
        // I, L and O read as 1 and 0.
        assert_eq!(
            canonical("ILO00-11000-00000-00000").unwrap(),
            "11000110000000000000"
        );
        // Not a code: too short, too long, a letter Crockford leaves out.
        assert!(canonical("ABC").is_none());
        assert!(canonical(&format!("{canon}0")).is_none());
        assert!(canonical("UUUUU-UUUUU-UUUUU-UUUUU").is_none());
        assert!(canonical("ÇÇÇÇÇ-00000-00000-00000").is_none());
        assert_eq!(hint(&canon), &canon[16..]);
        // Codes differ (100 bits).
        assert_ne!(generate(), generate());
    }

    #[test]
    fn a_code_is_found_by_its_keyed_hash_only() {
        let canon = canonical(&generate()).unwrap();
        let a = hash(&[1; 32], &canon);
        assert_eq!(a, hash(&[1; 32], &canon));
        assert_ne!(a, hash(&[2; 32], &canon), "another server's key");
        assert_ne!(a, hash(&[1; 32], &canonical(&generate()).unwrap()));
    }

    #[test]
    fn modes_read_back() {
        for mode in [
            RegistrationMode::On,
            RegistrationMode::Code,
            RegistrationMode::Off,
        ] {
            assert_eq!(RegistrationMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(RegistrationMode::parse("open"), None);
    }
}
