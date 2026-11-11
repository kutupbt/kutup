//! Who may open public links, and who may make them
//! (docs/plans/server-personal-data.md, A11): a site-wide switch an
//! administrator sets, a per-account one, and an operator's block on one
//! link. Meeting call links are a way into a call, not a publication, and
//! aren't covered.
//!
//! A link that may not be opened answers, whatever is asked of it:
//! - `451 link_blocked` (reason `legal_order`) or `410 link_blocked` (another
//!   reason) when an operator blocked it;
//! - `410 link_removed` when an administrator took it down, or its owner's
//!   account is not active;
//! - `410 sharing_off` while public sharing is off, site-wide or for its
//!   owner;
//! - `403 sign_in_required` while public sharing is `signed_in` and the
//!   viewer is not signed in to this server.

use axum::http::StatusCode;
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};

use crate::error::{AppError, AppResult};

/// The site setting that holds the switch.
pub const SETTING: &str = "public_sharing";

/// Who may open public links on this server.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PublicSharing {
    /// Anyone with the link.
    On,
    /// Nobody: links are neither made nor opened.
    Off,
    /// Only someone signed in to this server (a test deployment keeps its
    /// links among its own accounts).
    SignedIn,
}

impl PublicSharing {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::SignedIn => "signed_in",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            "signed_in" => Some(Self::SignedIn),
            _ => None,
        }
    }
}

/// The switch now: the stored one, `on` when none was ever set.
pub async fn site(pool: &PgPool) -> AppResult<PublicSharing> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(SETTING)
            .fetch_optional(pool)
            .await?;
    Ok(stored
        .as_deref()
        .and_then(PublicSharing::parse)
        .unwrap_or(PublicSharing::On))
}

/// Stores the administrators' choice.
pub async fn set_site(
    tx: &mut Transaction<'_, Postgres>,
    value: PublicSharing,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(SETTING)
    .bind(value.as_str())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Why links are off (`scope`: `site` or `account`): `410` for a link,
/// `403` for making one.
pub fn sharing_off(scope: &str) -> AppError {
    sharing_off_as(StatusCode::GONE, scope)
}

fn sharing_off_as(status: StatusCode, scope: &str) -> AppError {
    AppError::new(status, "public sharing is off")
        .with_details(json!({ "code": "sharing_off", "scope": scope }))
}

/// A link an operator blocked: 451 for a legal order, else 410.
pub fn link_blocked(reason: &str) -> AppError {
    let status = if reason == "legal_order" {
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    } else {
        StatusCode::GONE
    };
    AppError::new(status, "this link was blocked")
        .with_details(json!({ "code": "link_blocked", "reason": reason }))
}

/// A link that opens only for someone signed in to this server.
pub fn sign_in_required() -> AppError {
    AppError::new(StatusCode::FORBIDDEN, "sign in to open this link")
        .with_details(json!({ "code": "sign_in_required" }))
}

/// Whether `owner` may make a public link now: `403 sharing_off` while
/// sharing is off for the site or the account. `signed_in` still makes
/// links (they open for signed-in viewers).
pub async fn ensure_may_share(pool: &PgPool, owner: uuid::Uuid) -> AppResult<()> {
    if site(pool).await? == PublicSharing::Off {
        return Err(sharing_off_as(StatusCode::FORBIDDEN, "site"));
    }
    let account: Option<String> =
        sqlx::query_scalar("SELECT public_sharing FROM users WHERE id = $1")
            .bind(owner)
            .fetch_optional(pool)
            .await?;
    if account.as_deref() == Some("off") {
        return Err(sharing_off_as(StatusCode::FORBIDDEN, "account"));
    }
    Ok(())
}

/// Refuses a link that may not be opened now (the module's list). Unknown
/// tokens pass: the caller answers those itself. `signed_in`: whether the
/// viewer is signed in to this server.
pub async fn ensure_link_up(pool: &PgPool, token: &str, signed_in: bool) -> AppResult<()> {
    let row: Option<(bool, Option<String>, String)> = sqlx::query_as(
        "SELECT p.removed_at IS NOT NULL OR NOT u.is_active, p.blocked_reason, u.public_sharing
           FROM public_shares p JOIN users u ON u.id = p.owner_user_id
          WHERE p.token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    let Some((removed, blocked, account_sharing)) = row else {
        return Ok(());
    };
    if let Some(reason) = blocked {
        return Err(link_blocked(&reason));
    }
    if removed {
        return Err(crate::handlers::link_reports::link_removed());
    }
    match site(pool).await? {
        PublicSharing::Off => return Err(sharing_off("site")),
        PublicSharing::SignedIn if !signed_in => return Err(sign_in_required()),
        _ => {}
    }
    if account_sharing == "off" {
        return Err(sharing_off("account"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_reads_back_what_it_writes() {
        for value in [
            PublicSharing::On,
            PublicSharing::Off,
            PublicSharing::SignedIn,
        ] {
            assert_eq!(PublicSharing::parse(value.as_str()), Some(value));
        }
        assert_eq!(PublicSharing::parse("signedIn"), None);
    }

    #[test]
    fn a_legal_block_is_451_and_another_410() {
        assert_eq!(
            link_blocked("legal_order").status,
            StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
        );
        assert_eq!(link_blocked("abuse").status, StatusCode::GONE);
    }
}
