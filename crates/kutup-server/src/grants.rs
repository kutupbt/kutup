//! One-time grants (docs/plans/opaque.md §6): proof that the person just
//! proved their password (or recovery phrase), for one action of one account.
//!
//! A grant is `kg1_` and base64url of 32 random bytes; the server keeps its
//! SHA-256. It is bound to an account, a purpose, the session it was issued
//! to (none for recovery) and, for an admin reset, the account it may reset.
//! It is used once, expires within minutes, and is never a session or a
//! bearer token.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kutup_crypto::primitives::{self, Suite};
use uuid::Uuid;

/// How long a grant may wait to be used.
pub const GRANT_MINUTES: i64 = 5;
/// A rotation grant's (re-registering under the current setup at sign-in).
pub const ROTATE_MINUTES: i64 = 2;

const PREFIX: &str = "kg1_";

/// What a grant allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Setting or removing the Pass PIN.
    Pass,
    /// A new password (re-registration of the same key binding).
    PasswordChange,
    /// Turning two-step sign-in off or on.
    Totp,
    /// An admin resetting another account (`target`).
    AdminReset,
    /// A new password after the recovery phrase (no session).
    Recovery,
    /// Re-registering under the current setup at sign-in, silently.
    Rotate,
    /// A new username, or dropping a held one (docs/plans/username-renames.md).
    Rename,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Pass => "pass",
            Purpose::PasswordChange => "passwordChange",
            Purpose::Totp => "totp",
            Purpose::AdminReset => "adminReset",
            Purpose::Recovery => "recovery",
            Purpose::Rotate => "rotate",
            Purpose::Rename => "rename",
        }
    }

    /// What a reauth may ask a grant for (`for` at login/start).
    pub fn for_reauth(name: &str) -> Option<Purpose> {
        Some(match name {
            "pass" => Purpose::Pass,
            "passwordChange" => Purpose::PasswordChange,
            "totp" => Purpose::Totp,
            "adminReset" => Purpose::AdminReset,
            "rename" => Purpose::Rename,
            _ => return None,
        })
    }
}

/// A grant as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub user_id: Uuid,
    pub session_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
}

fn hash(token: &str) -> Option<Vec<u8>> {
    let raw = token.strip_prefix(PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
    (bytes.len() == 32).then(|| primitives::hash(Suite::V1, token.as_bytes()).to_vec())
}

/// Issues a grant; the token, shown once.
pub async fn issue<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    purpose: Purpose,
    user_id: Uuid,
    session_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    minutes: i64,
) -> sqlx::Result<String> {
    let mut raw = [0u8; 32];
    kutup_crypto::primitives::random(&mut raw);
    let token = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    sqlx::query(
        "INSERT INTO auth_grants (token_hash, user_id, purpose, session_id, target_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(mins => $6))",
    )
    .bind(primitives::hash(Suite::V1, token.as_bytes()).to_vec())
    .bind(user_id)
    .bind(purpose.as_str())
    .bind(session_id)
    .bind(target_user_id)
    .bind(minutes as i32)
    .execute(executor)
    .await?;
    Ok(token)
}

/// The grant behind `token` for one of `purposes`, unused and unexpired,
/// without using it (a registration's start checks what its finish uses).
pub async fn peek<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    token: &str,
    purposes: &[Purpose],
) -> sqlx::Result<Option<(Purpose, Grant)>> {
    let Some(hash) = hash(token) else {
        return Ok(None);
    };
    let row: Option<(String, Uuid, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT purpose, user_id, session_id, target_user_id FROM auth_grants
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(hash)
    .fetch_optional(executor)
    .await?;
    Ok(
        row.and_then(|(purpose, user_id, session_id, target_user_id)| {
            let purpose = purposes.iter().find(|p| p.as_str() == purpose)?;
            Some((
                *purpose,
                Grant {
                    user_id,
                    session_id,
                    target_user_id,
                },
            ))
        }),
    )
}

/// Uses the grant behind `token` for one of `purposes`, once: of two
/// concurrent uses, one gets it.
pub async fn take<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    token: &str,
    purposes: &[Purpose],
) -> sqlx::Result<Option<(Purpose, Grant)>> {
    let Some(hash) = hash(token) else {
        return Ok(None);
    };
    let names: Vec<&str> = purposes.iter().map(|p| p.as_str()).collect();
    let row: Option<(String, Uuid, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "UPDATE auth_grants SET used_at = now()
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() AND purpose = ANY($2)
         RETURNING purpose, user_id, session_id, target_user_id",
    )
    .bind(hash)
    .bind(&names)
    .fetch_optional(executor)
    .await?;
    Ok(
        row.and_then(|(purpose, user_id, session_id, target_user_id)| {
            let purpose = purposes.iter().find(|p| p.as_str() == purpose)?;
            Some((
                *purpose,
                Grant {
                    user_id,
                    session_id,
                    target_user_id,
                },
            ))
        }),
    )
}

/// A grant refused: unknown, used, expired, for another purpose, account or
/// session. One answer for all of them.
pub fn invalid() -> crate::error::AppError {
    crate::error::AppError::forbidden("the grant is not valid for this")
        .with_details(serde_json::json!({ "code": "grantInvalid" }))
}

/// Uses a grant of `purpose` that was issued to this very session (a reauth
/// moments ago), or refuses it.
pub async fn take_for_session<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    token: &str,
    purpose: Purpose,
    user: &crate::middleware::AuthUser,
) -> crate::error::AppResult<()> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    match take(executor, token, &[purpose]).await? {
        Some((_, grant))
            if grant.user_id == user_id && grant.session_id == Some(user.session.session_id) =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

/// Ends every outstanding grant of `user_id` and its sign-ins under way: a
/// password change, a recovery or a reset makes them meaningless.
pub async fn end_all(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM auth_grants WHERE user_id = $1 OR target_user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM opaque_login_states WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Drops used and expired grants and expired sign-ins.
pub async fn sweep(pool: &sqlx::PgPool) -> sqlx::Result<u64> {
    let grants = sqlx::query(
        "DELETE FROM auth_grants WHERE expires_at <= now() OR used_at < now() - interval '1 hour'",
    )
    .execute(pool)
    .await?;
    let logins = sqlx::query("DELETE FROM opaque_login_states WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(grants.rows_affected() + logins.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_well_formed_token_has_a_hash() {
        let token = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode([7u8; 32]));
        assert!(hash(&token).is_some());
        assert!(hash("kg1_short").is_none());
        assert!(hash(&token.replace(PREFIX, "kg2_")).is_none());
        assert!(hash(&format!("{token}A")).is_none());
    }

    #[test]
    fn reauth_may_ask_for_these_only() {
        for name in ["pass", "passwordChange", "totp", "adminReset", "rename"] {
            assert_eq!(Purpose::for_reauth(name).unwrap().as_str(), name);
        }
        assert_eq!(Purpose::for_reauth("recovery"), None);
        assert_eq!(Purpose::for_reauth("rotate"), None);
    }
}
