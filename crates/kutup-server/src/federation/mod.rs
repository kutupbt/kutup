//! Shared federation v2 identity, policy, trust, replay, discovery, and
//! authenticated transport services used by feature protocols.

mod config;
pub(crate) mod discovery;
mod identity;
mod policy;
mod replay;
mod transport;
mod trust;

#[cfg(test)]
mod live_tests;

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;

pub(crate) use config::FederationRuntimeConfig;
pub(crate) use discovery::{public_discovery, public_identity_document};
pub(crate) use identity::{rotate_local_identity, LocalFederationIdentity};
use policy::FederationPolicyStore;
use replay::FederationReplayStore;
use transport::FederationTransportState;
use trust::FederationTrustStore;

pub(crate) use policy::{FederationAdmissionError, FederationDirection, FederationPolicyFeature};
pub(crate) use transport::{AuthenticatedFederationRequest, FederationRequestSpec};

use crate::config::Config;

/// One local identity and one set of shared persistence and transport services
/// for every federation feature protocol.
pub(crate) struct FederationStack {
    pool: PgPool,
    config: FederationRuntimeConfig,
    local_identity: Arc<LocalFederationIdentity>,
    trust: FederationTrustStore,
    replay: FederationReplayStore,
    policy: FederationPolicyStore,
    transport: FederationTransportState,
}

impl FederationStack {
    pub async fn from_config(
        pool: PgPool,
        config: &Config,
        now: OffsetDateTime,
    ) -> anyhow::Result<Option<Self>> {
        let Some(config) = FederationRuntimeConfig::from_server_config(config)? else {
            return Ok(None);
        };
        config.ensure_normal_startup()?;
        let local_identity =
            Arc::new(LocalFederationIdentity::load_or_create(&pool, &config, now).await?);
        Ok(Some(Self {
            trust: FederationTrustStore::new(pool.clone()),
            replay: FederationReplayStore::new(pool.clone()),
            policy: FederationPolicyStore::new(pool.clone()),
            transport: FederationTransportState::default(),
            pool,
            config,
            local_identity,
        }))
    }

    pub fn server_name(&self) -> &str {
        &self.config.server_name
    }

    pub fn local_identity(&self) -> &LocalFederationIdentity {
        &self.local_identity
    }

    pub fn trust(&self) -> &FederationTrustStore {
        &self.trust
    }

    pub fn policy(&self) -> &FederationPolicyStore {
        &self.policy
    }

    /// Remove expired transport nonces. Replay reservations are deliberately
    /// retained beyond the accepted clock-skew window, but need not become an
    /// unbounded operational table.
    pub fn spawn_maintenance(&self) {
        let replay = self.replay.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
            loop {
                tick.tick().await;
                if let Err(error) = replay.purge_expired(OffsetDateTime::now_utc()).await {
                    tracing::warn!(%error, "failed to purge expired federation replay reservations");
                }
            }
        });
    }
}
