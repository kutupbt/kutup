use std::{fmt, str::FromStr};

use kutup_federation_proto::validate_server_name;
use sqlx::PgPool;

use super::trust::PeerTrustState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationPolicyFeature {
    Chat,
    Drive,
}

impl FederationPolicyFeature {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Drive => "drive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationMinimumTrust {
    Tofu,
    Verified,
}

impl FromStr for FederationMinimumTrust {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tofu" => Ok(Self::Tofu),
            "verified" => Ok(Self::Verified),
            _ => anyhow::bail!("database contains unknown federation trust requirement {value:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FederationMode {
    Disabled,
    Allowlist,
    Blocklist,
    Open,
}

impl FromStr for FederationMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "allowlist" => Ok(Self::Allowlist),
            "blocklist" => Ok(Self::Blocklist),
            "open" => Ok(Self::Open),
            _ => anyhow::bail!("database contains unknown federation policy mode {value:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainAction {
    Inherit,
    Allow,
    Block,
}

impl FromStr for DomainAction {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "inherit" => Ok(Self::Inherit),
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            _ => anyhow::bail!("database contains unknown federation domain action {value:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationAdmissionDenial {
    EmergencyStop,
    FeatureDisabled,
    NotAllowlisted,
    ExplicitlyBlocked,
    UnpinnedIdentity,
    QuarantinedIdentity,
    InsufficientTrust,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct FederationAdmissionError(pub FederationAdmissionDenial);

impl fmt::Display for FederationAdmissionDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmergencyStop => "federation emergency stop is active",
            Self::FeatureDisabled => "federation is disabled for this feature",
            Self::NotAllowlisted => "peer is not allowlisted for this feature and direction",
            Self::ExplicitlyBlocked => "peer is blocked for this feature and direction",
            Self::UnpinnedIdentity => "peer has no pinned federation identity",
            Self::QuarantinedIdentity => "peer federation identity is quarantined",
            Self::InsufficientTrust => "peer identity does not meet the minimum trust policy",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationAdmissionDecision {
    Allowed { trust: PeerTrustState },
    Denied { reason: FederationAdmissionDenial },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationAdmissionPreflight {
    Allowed,
    Denied { reason: FederationAdmissionDenial },
}

impl FederationAdmissionPreflight {
    #[cfg(test)]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

impl FederationAdmissionDecision {
    #[cfg(test)]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

#[derive(Clone)]
pub(crate) struct FederationPolicyStore {
    pool: PgPool,
}

impl FederationPolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn feature_is_publicly_enabled(
        &self,
        feature: FederationPolicyFeature,
    ) -> anyhow::Result<bool> {
        let row: Option<(bool, String)> = sqlx::query_as(
            "SELECT global.global_enabled, feature.mode
             FROM federation_policy AS global
             JOIN federation_feature_policies AS feature ON feature.feature = $1
             WHERE global.singleton = TRUE",
        )
        .bind(feature.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let (global_enabled, mode) = row.ok_or_else(|| {
            anyhow::anyhow!(
                "federation policy is incomplete for feature {}",
                feature.as_str()
            )
        })?;
        Ok(global_enabled && mode.parse::<FederationMode>()? != FederationMode::Disabled)
    }

    /// Cheap admission-only check used before DNS or discovery. Trust is
    /// deliberately evaluated later, after an allowed first contact has had a
    /// chance to establish a cryptographically verified TOFU candidate.
    pub async fn check_admission(
        &self,
        domain: &str,
        feature: FederationPolicyFeature,
        direction: FederationDirection,
    ) -> anyhow::Result<FederationAdmissionPreflight> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        let row: Option<(bool, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT global.global_enabled, feature.mode,
                    rule.inbound_action, rule.outbound_action
             FROM federation_policy AS global
             JOIN federation_feature_policies AS feature ON feature.feature = $2
             LEFT JOIN federation_domain_rules AS rule
                    ON rule.domain = $1 AND rule.feature = feature.feature
             WHERE global.singleton = TRUE",
        )
        .bind(domain)
        .bind(feature.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let (global_enabled, mode, inbound_action, outbound_action) = row.ok_or_else(|| {
            anyhow::anyhow!(
                "federation policy is incomplete for feature {}",
                feature.as_str()
            )
        })?;
        let action = match direction {
            FederationDirection::Inbound => inbound_action.as_deref(),
            FederationDirection::Outbound => outbound_action.as_deref(),
        }
        .unwrap_or("inherit")
        .parse()?;
        Ok(evaluate_admission(global_enabled, mode.parse()?, action))
    }

    /// Evaluate emergency stop, feature admission, and global peer trust in a
    /// single PostgreSQL snapshot. An explicit allow never bypasses trust.
    pub async fn evaluate(
        &self,
        domain: &str,
        feature: FederationPolicyFeature,
        direction: FederationDirection,
    ) -> anyhow::Result<FederationAdmissionDecision> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        type PolicyRow = (
            bool,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let row: Option<PolicyRow> = sqlx::query_as(
            "SELECT global.global_enabled, feature.mode, feature.minimum_trust,
                    rule.inbound_action, rule.outbound_action,
                    rule.trust_requirement, peer.trust_state
             FROM federation_policy AS global
             JOIN federation_feature_policies AS feature ON feature.feature = $2
             LEFT JOIN federation_domain_rules AS rule
                    ON rule.domain = $1 AND rule.feature = feature.feature
             LEFT JOIN federation_peer_identities AS peer ON peer.domain = $1
             WHERE global.singleton = TRUE",
        )
        .bind(domain)
        .bind(feature.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let (
            global_enabled,
            mode,
            feature_minimum,
            inbound_action,
            outbound_action,
            rule_minimum,
            trust,
        ) = row.ok_or_else(|| {
            anyhow::anyhow!(
                "federation policy is incomplete for feature {}",
                feature.as_str()
            )
        })?;
        let mode = mode.parse()?;
        let action = match direction {
            FederationDirection::Inbound => inbound_action.as_deref(),
            FederationDirection::Outbound => outbound_action.as_deref(),
        }
        .unwrap_or("inherit")
        .parse()?;
        let minimum = match rule_minimum.as_deref().unwrap_or("inherit") {
            "inherit" => feature_minimum.parse()?,
            value => value.parse()?,
        };
        let trust = trust.map(|value| value.parse()).transpose()?;
        Ok(evaluate_policy(
            global_enabled,
            mode,
            action,
            minimum,
            trust,
        ))
    }
}

fn evaluate_policy(
    global_enabled: bool,
    mode: FederationMode,
    action: DomainAction,
    minimum: FederationMinimumTrust,
    trust: Option<PeerTrustState>,
) -> FederationAdmissionDecision {
    use FederationAdmissionDecision::{Allowed, Denied};
    use FederationAdmissionDenial::{InsufficientTrust, QuarantinedIdentity, UnpinnedIdentity};

    if let FederationAdmissionPreflight::Denied { reason } =
        evaluate_admission(global_enabled, mode, action)
    {
        return Denied { reason };
    }
    let Some(trust) = trust else {
        return Denied {
            reason: UnpinnedIdentity,
        };
    };
    if trust == PeerTrustState::Quarantined {
        return Denied {
            reason: QuarantinedIdentity,
        };
    }
    if minimum == FederationMinimumTrust::Verified && trust != PeerTrustState::Verified {
        return Denied {
            reason: InsufficientTrust,
        };
    }
    Allowed { trust }
}

fn evaluate_admission(
    global_enabled: bool,
    mode: FederationMode,
    action: DomainAction,
) -> FederationAdmissionPreflight {
    use FederationAdmissionDenial::{
        EmergencyStop, ExplicitlyBlocked, FeatureDisabled, NotAllowlisted,
    };
    use FederationAdmissionPreflight::{Allowed, Denied};

    if !global_enabled {
        return Denied {
            reason: EmergencyStop,
        };
    }
    match mode {
        FederationMode::Disabled => Denied {
            reason: FeatureDisabled,
        },
        FederationMode::Allowlist if action == DomainAction::Allow => Allowed,
        FederationMode::Allowlist if action == DomainAction::Block => Denied {
            reason: ExplicitlyBlocked,
        },
        FederationMode::Allowlist => Denied {
            reason: NotAllowlisted,
        },
        FederationMode::Blocklist if action == DomainAction::Block => Denied {
            reason: ExplicitlyBlocked,
        },
        FederationMode::Blocklist | FederationMode::Open => Allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emergency_stop_and_disabled_mode_cannot_be_overridden() {
        assert_eq!(
            evaluate_policy(
                false,
                FederationMode::Open,
                DomainAction::Allow,
                FederationMinimumTrust::Tofu,
                Some(PeerTrustState::Verified),
            ),
            FederationAdmissionDecision::Denied {
                reason: FederationAdmissionDenial::EmergencyStop
            }
        );
        assert_eq!(
            evaluate_policy(
                true,
                FederationMode::Disabled,
                DomainAction::Allow,
                FederationMinimumTrust::Tofu,
                Some(PeerTrustState::Verified),
            ),
            FederationAdmissionDecision::Denied {
                reason: FederationAdmissionDenial::FeatureDisabled
            }
        );
    }

    #[test]
    fn admission_never_bypasses_identity_trust() {
        for mode in [
            FederationMode::Allowlist,
            FederationMode::Blocklist,
            FederationMode::Open,
        ] {
            assert_eq!(
                evaluate_policy(
                    true,
                    mode,
                    DomainAction::Allow,
                    FederationMinimumTrust::Tofu,
                    Some(PeerTrustState::Quarantined),
                ),
                FederationAdmissionDecision::Denied {
                    reason: FederationAdmissionDenial::QuarantinedIdentity
                }
            );
        }
        assert_eq!(
            evaluate_policy(
                true,
                FederationMode::Open,
                DomainAction::Inherit,
                FederationMinimumTrust::Verified,
                Some(PeerTrustState::Tofu),
            ),
            FederationAdmissionDecision::Denied {
                reason: FederationAdmissionDenial::InsufficientTrust
            }
        );
    }

    #[test]
    fn modes_have_simple_direction_specific_admission_semantics() {
        assert!(!evaluate_policy(
            true,
            FederationMode::Allowlist,
            DomainAction::Inherit,
            FederationMinimumTrust::Tofu,
            Some(PeerTrustState::Tofu),
        )
        .is_allowed());
        assert!(evaluate_policy(
            true,
            FederationMode::Allowlist,
            DomainAction::Allow,
            FederationMinimumTrust::Tofu,
            Some(PeerTrustState::Tofu),
        )
        .is_allowed());
        assert!(evaluate_policy(
            true,
            FederationMode::Blocklist,
            DomainAction::Inherit,
            FederationMinimumTrust::Tofu,
            Some(PeerTrustState::Verified),
        )
        .is_allowed());
        assert!(!evaluate_policy(
            true,
            FederationMode::Blocklist,
            DomainAction::Block,
            FederationMinimumTrust::Tofu,
            Some(PeerTrustState::Verified),
        )
        .is_allowed());
        for action in [
            DomainAction::Inherit,
            DomainAction::Allow,
            DomainAction::Block,
        ] {
            assert!(evaluate_policy(
                true,
                FederationMode::Open,
                action,
                FederationMinimumTrust::Tofu,
                Some(PeerTrustState::Verified),
            )
            .is_allowed());
        }
    }

    #[test]
    fn admission_preflight_allows_discovery_before_trust_is_established() {
        assert_eq!(
            evaluate_admission(true, FederationMode::Allowlist, DomainAction::Allow),
            FederationAdmissionPreflight::Allowed
        );
        assert!(!evaluate_policy(
            true,
            FederationMode::Allowlist,
            DomainAction::Allow,
            FederationMinimumTrust::Verified,
            None,
        )
        .is_allowed());
    }
}
