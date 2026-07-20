//! Administrator-managed operational admission policy for chat federation.
//!
//! This policy controls which homeservers may exchange chat traffic with the
//! local instance. It is not a cryptographic trust decision: accepted peers
//! must still pass discovery, SSRF, destination binding, and Ed25519 request
//! authentication in `chat_federation`.

use std::fmt;
use std::str::FromStr;

use kutup_chat_proto::AccountAddress;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FederationMode {
    Disabled,
    Allowlist,
    Blocklist,
    Open,
}

impl fmt::Display for FederationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Disabled => "disabled",
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
            Self::Open => "open",
        })
    }
}

impl FromStr for FederationMode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "allowlist" => Ok(Self::Allowlist),
            "blocklist" => Ok(Self::Blocklist),
            "open" => Ok(Self::Open),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FederationRuleAction {
    Inherit,
    Allow,
    Block,
}

impl fmt::Display for FederationRuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inherit => "inherit",
            Self::Allow => "allow",
            Self::Block => "block",
        })
    }
}

impl FromStr for FederationRuleAction {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "inherit" => Ok(Self::Inherit),
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationDirection {
    Inbound,
    Outbound,
}

impl fmt::Display for FederationDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        })
    }
}

/// Rules have meaning only in list modes. `open` intentionally ignores them,
/// otherwise open and blocklist would be two names for the same behavior.
pub fn evaluate(mode: FederationMode, action: FederationRuleAction) -> bool {
    match mode {
        FederationMode::Disabled => false,
        FederationMode::Open => true,
        FederationMode::Allowlist => action == FederationRuleAction::Allow,
        FederationMode::Blocklist => action != FederationRuleAction::Block,
    }
}

pub fn canonical_domain(value: &str) -> AppResult<String> {
    let domain = value.trim();
    if domain != value {
        return Err(AppError::bad_request(
            "domain must be canonical lowercase DNS",
        ));
    }
    let canonical = AccountAddress::federated("server", domain)
        .map_err(|_| AppError::bad_request("domain must be canonical lowercase DNS"))?;
    if canonical.server.as_deref() != Some(domain) {
        return Err(AppError::bad_request(
            "domain must be canonical lowercase DNS",
        ));
    }
    Ok(domain.to_string())
}

pub async fn load_mode(pool: &PgPool) -> AppResult<FederationMode> {
    let mode: String =
        sqlx::query_scalar("SELECT mode FROM chat_federation_policy WHERE singleton = TRUE")
            .fetch_one(pool)
            .await?;
    mode.parse()
        .map_err(|_| AppError::internal("invalid stored chat federation mode"))
}

pub async fn require_allowed(
    pool: &PgPool,
    direction: FederationDirection,
    domain: &str,
) -> AppResult<()> {
    let action_column = match direction {
        FederationDirection::Inbound => "inbound_action",
        FederationDirection::Outbound => "outbound_action",
    };
    let query = format!(
        "SELECT p.mode, r.{action_column} \
         FROM chat_federation_policy p \
         LEFT JOIN chat_federation_domain_rules r ON r.domain = $1 \
         WHERE p.singleton = TRUE"
    );
    let (mode, action): (String, Option<String>) =
        sqlx::query_as(&query).bind(domain).fetch_one(pool).await?;
    let mode: FederationMode = mode
        .parse()
        .map_err(|_| AppError::internal("invalid stored chat federation mode"))?;
    let action: FederationRuleAction = action
        .as_deref()
        .unwrap_or("inherit")
        .parse()
        .map_err(|_| AppError::internal("invalid stored chat federation rule"))?;

    if evaluate(mode, action) {
        Ok(())
    } else {
        Err(AppError::forbidden(format!(
            "chat federation policy denies {direction} traffic for {domain}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_have_distinct_defaults_and_rule_behavior() {
        use FederationMode::{Allowlist, Blocklist, Disabled, Open};
        use FederationRuleAction::{Allow, Block, Inherit};

        assert!(!evaluate(Disabled, Allow));
        assert!(evaluate(Open, Block));

        assert!(evaluate(Allowlist, Allow));
        assert!(!evaluate(Allowlist, Inherit));
        assert!(!evaluate(Allowlist, Block));

        assert!(evaluate(Blocklist, Allow));
        assert!(evaluate(Blocklist, Inherit));
        assert!(!evaluate(Blocklist, Block));
    }

    #[test]
    fn domains_must_be_canonical_lowercase_dns() {
        assert_eq!(canonical_domain("chat.example").unwrap(), "chat.example");
        assert!(canonical_domain("Chat.Example").is_err());
        assert!(canonical_domain("127.0.0.1").is_err());
        assert!(canonical_domain("chat.example/path").is_err());
        assert!(canonical_domain(" chat.example ").is_err());
    }
}
