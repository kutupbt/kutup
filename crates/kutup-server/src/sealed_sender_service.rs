//! Purpose-scoped online sender-certificate issuance.
//!
//! No root private key reaches this module. Either an operator provisions a
//! root-signed libsignal server certificate offline and configures only its
//! online private key, or, with nothing configured, the server provisions
//! itself with roots it generates, uses once and drops
//! (`crate::sealed_sender_provision`).

use std::sync::{Arc, RwLock};

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    SealedSenderServicePolicyV1, SealedSenderSuiteId, SenderCertificateResponseV1,
};
use kutup_federation_proto::FederatedFeaturePolicyTypeV1;
use libsignal_protocol::{
    DeviceId, PrivateKey, PublicKey, SenderCertificate, ServerCertificate, Timestamp,
};
use rand09::rngs::OsRng;
use rand09::TryRngCore as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// One online certificate this server can issue sender certificates under.
pub(crate) struct OnlineSigner {
    pub(crate) certificate_id: u32,
    pub(crate) activates_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) certificate: ServerCertificate,
    pub(crate) private_key: PrivateKey,
}

/// The policy this server publishes and the signers it holds for it.
pub(crate) struct ActiveSealedSender {
    pub(crate) policy: SealedSenderServicePolicyV1,
    pub(crate) signers: Vec<OnlineSigner>,
}

impl ActiveSealedSender {
    /// The signer to issue under at `now`: started, and lasting at least one
    /// sender-certificate lifetime more; the newest when two overlap.
    fn signer_at(&self, now_seconds: i64) -> Option<&OnlineSigner> {
        let lasts_until = now_seconds
            + i64::from(self.policy.sender_certificate_lifetime_seconds)
            + i64::from(self.policy.maximum_clock_skew_seconds);
        self.signers
            .iter()
            .filter(|signer| signer.activates_at <= now_seconds && signer.expires_at >= lasts_until)
            .max_by_key(|signer| signer.activates_at)
    }
}

pub(crate) struct SealedSenderService {
    /// Provisioned by the server itself (`crate::sealed_sender_provision`)
    /// rather than from an operator's offline root.
    self_provisioned: bool,
    active: RwLock<Arc<ActiveSealedSender>>,
}

impl SealedSenderService {
    /// The server's sealed-sender service: from the operator's offline-root
    /// policy and online key when both are configured, otherwise provisioned
    /// by the server itself when it has a federation identity. `rotation`
    /// is what the operator allowed (`feature-policy rotate sealed-sender`).
    pub async fn load(
        pool: &sqlx::PgPool,
        config: &Config,
        federation: Option<&crate::federation::FederationStack>,
        rotation: crate::federation::PolicyRotation,
        now: OffsetDateTime,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        let has_policy = !config.chat_sealed_sender_policy.trim().is_empty();
        let has_key = !config
            .chat_sealed_sender_online_private_key
            .trim()
            .is_empty();
        if has_policy || has_key {
            return Self::from_config(
                config,
                federation.map(|federation| federation.server_name()),
                now,
            );
        }
        let Some(federation) = federation else {
            return Ok(None);
        };
        let active =
            crate::sealed_sender_provision::maintain(pool, federation, rotation, now).await?;
        Ok(Some(Arc::new(Self {
            self_provisioned: true,
            active: RwLock::new(Arc::new(active)),
        })))
    }

    /// `server_name` is the name of this server's federation identity, when
    /// it has one: configured (`FEDERATION_SERVER_NAME`) or the one the
    /// server made for itself.
    fn from_config(
        config: &Config,
        server_name: Option<&str>,
        now: OffsetDateTime,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        let has_policy = !config.chat_sealed_sender_policy.trim().is_empty();
        let has_key = !config
            .chat_sealed_sender_online_private_key
            .trim()
            .is_empty();
        let (true, true, Some(server_name)) = (has_policy, has_key, server_name) else {
            anyhow::bail!(
                "sealed sender requires a server identity, a complete service policy, and an online private key"
            );
        };
        let policy: SealedSenderServicePolicyV1 =
            serde_json::from_str(&config.chat_sealed_sender_policy)?;
        policy.validate().map_err(anyhow::Error::msg)?;
        if policy.canonical_domain != server_name {
            anyhow::bail!(
                "sealed sender policy canonical domain does not match federation identity"
            );
        }
        let private_bytes = STANDARD.decode(&config.chat_sealed_sender_online_private_key)?;
        if private_bytes.len() != 32
            || STANDARD.encode(&private_bytes) != config.chat_sealed_sender_online_private_key
        {
            anyhow::bail!("sealed sender online private key is not canonical 32-byte base64");
        }
        let private_key = PrivateKey::deserialize(&private_bytes)?;
        let public_key = private_key.public_key()?;
        let now_seconds = now.unix_timestamp();
        let mut active = None;
        for reference in &policy.server_certificates {
            if reference.activates_at > now_seconds || reference.expires_at <= now_seconds {
                continue;
            }
            let bytes = STANDARD.decode(&reference.certificate)?;
            if STANDARD.encode(&bytes) != reference.certificate {
                anyhow::bail!("sealed sender server certificate is not canonical base64");
            }
            let certificate = ServerCertificate::deserialize(&bytes)?;
            if certificate.key_id()? != reference.certificate_id
                || certificate.public_key()?.serialize() != public_key.serialize()
            {
                continue;
            }
            let root = policy
                .roots
                .iter()
                .find(|root| root.root_id == reference.root_id)
                .ok_or_else(|| anyhow::anyhow!("server certificate references an unknown root"))?;
            if root.activates_at > now_seconds
                || root.revokes_at.is_some_and(|at| at <= now_seconds)
            {
                anyhow::bail!("sealed sender server certificate root is not active");
            }
            let root_bytes = STANDARD.decode(&root.public_key)?;
            let root_public = PublicKey::deserialize(&root_bytes)?;
            if hex::encode(Sha256::digest(&root_bytes)) != root.root_id
                || !certificate.validate(&root_public)?
            {
                anyhow::bail!("sealed sender server certificate does not validate under its root");
            }
            if reference.expires_at
                < now_seconds
                    + i64::from(policy.sender_certificate_lifetime_seconds)
                    + i64::from(policy.maximum_clock_skew_seconds)
            {
                anyhow::bail!("sealed sender server certificate is too close to expiry");
            }
            if active.is_some() {
                anyhow::bail!("multiple active server certificates match the online private key");
            }
            active = Some(OnlineSigner {
                certificate_id: reference.certificate_id,
                activates_at: reference.activates_at,
                expires_at: reference.expires_at,
                certificate,
                private_key,
            });
        }
        let signer = active.ok_or_else(|| {
            anyhow::anyhow!("no active sealed sender server certificate matches the online key")
        })?;
        Ok(Some(Arc::new(Self {
            self_provisioned: false,
            active: RwLock::new(Arc::new(ActiveSealedSender {
                policy,
                signers: vec![signer],
            })),
        })))
    }

    pub fn policy(&self) -> SealedSenderServicePolicyV1 {
        self.current().policy.clone()
    }

    fn current(&self) -> Arc<ActiveSealedSender> {
        Arc::clone(
            &self
                .active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Keep a self-provisioned service current: renew its certificate when
    /// due, publish the policy, and take up the new signers. Each instance
    /// runs this; the database lock makes them agree.
    pub fn spawn_maintenance(
        self: &Arc<Self>,
        pool: sqlx::PgPool,
        federation: Arc<crate::federation::FederationStack>,
    ) {
        if !self.self_provisioned {
            return;
        }
        let service = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval(crate::sealed_sender_provision::MAINTENANCE_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                match crate::sealed_sender_provision::maintain(
                    &pool,
                    &federation,
                    crate::federation::PolicyRotation::Refuse,
                    OffsetDateTime::now_utc(),
                )
                .await
                {
                    Ok(active) => {
                        *service
                            .active
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(active);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "self-provisioned sealed sender maintenance failed");
                    }
                }
            }
        });
    }

    fn issue(
        &self,
        canonical_sender: String,
        device_id: u32,
        identity_key: PublicKey,
        now: OffsetDateTime,
    ) -> AppResult<(Vec<u8>, i64, u32)> {
        let active = self.current();
        let expires_at = now
            .unix_timestamp()
            .checked_add(i64::from(active.policy.sender_certificate_lifetime_seconds))
            .ok_or_else(|| AppError::internal("sender certificate expiry overflow"))?;
        let signer = active.signer_at(now.unix_timestamp()).ok_or_else(|| {
            AppError::internal("no sealed sender server certificate can issue now")
        })?;
        let device_id = DeviceId::try_from(device_id)
            .map_err(|_| AppError::bad_request("chat device id is invalid"))?;
        let expiration_millis = u64::try_from(expires_at)
            .ok()
            .and_then(|value| value.checked_mul(1000))
            .ok_or_else(|| AppError::internal("sender certificate expiry is invalid"))?;
        let mut rng = OsRng.unwrap_err();
        let certificate = SenderCertificate::new(
            canonical_sender,
            None,
            identity_key,
            device_id,
            Timestamp::from_epoch_millis(expiration_millis),
            signer.certificate.clone(),
            &signer.private_key,
            &mut rng,
        )
        .map_err(|error| AppError::internal(format!("issue sender certificate: {error}")))?;
        Ok((
            certificate
                .serialized()
                .map_err(|error| AppError::internal(error.to_string()))?
                .to_vec(),
            expires_at,
            signer.certificate_id,
        ))
    }
}

#[derive(Deserialize)]
pub(crate) struct SenderCertificateQuery {
    #[serde(rename = "deviceId")]
    device_id: u32,
}

#[tracing::instrument(name = "chat.sealed_sender.certificate.issue", skip_all)]
pub(crate) async fn issue_sender_certificate(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<SenderCertificateQuery>,
) -> AppResult<Response> {
    let service = state
        .sealed_sender
        .as_ref()
        .ok_or_else(|| AppError::not_found("sealed sender is not enabled"))?;
    let user_id = trusted_uuid(&auth.user_id)?;
    let row: Option<(String, String)> = sqlx::query_as(
        "UPDATE chat_devices d SET last_seen_at = now()
         FROM users u
         WHERE d.user_id = $1 AND d.device_id = $2 AND u.id = d.user_id AND u.is_active = true
         RETURNING u.username, d.identity_key",
    )
    .bind(user_id)
    .bind(query.device_id as i32)
    .fetch_optional(&state.pool)
    .await?;
    let (username, encoded_identity) =
        row.ok_or_else(|| AppError::not_found("no such chat device"))?;
    let identity_bytes = STANDARD
        .decode(&encoded_identity)
        .map_err(|_| AppError::internal("stored chat identity key is invalid"))?;
    let identity_key = PublicKey::deserialize(&identity_bytes)
        .map_err(|error| AppError::internal(format!("stored identity key: {error}")))?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::internal("sealed sender requires federation"))?;
    let canonical_sender = format!("{username}@{}", federation.server_name());
    let (certificate, expires_at, certificate_id) = match service.issue(
        canonical_sender,
        query.device_id,
        identity_key,
        OffsetDateTime::now_utc(),
    ) {
        Ok(issued) => issued,
        Err(error) => {
            crate::telemetry::certificate_event("failed");
            return Err(error);
        }
    };
    let envelope = federation
        .feature_policies()
        .get(
            federation.server_name(),
            FederatedFeaturePolicyTypeV1::SealedSenderService,
            None,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("sealed sender policy is not published"))?;
    tracing::info!(certificate_id, "issued sealed sender certificate");
    crate::telemetry::certificate_event("issued");
    Ok(Json(SenderCertificateResponseV1 {
        suite: SealedSenderSuiteId::LibsignalV2DeliveryCapabilityV1,
        certificate: STANDARD.encode(certificate),
        expires_at,
        service_policy_sequence: envelope.sequence,
    })
    .into_response())
}

pub(crate) async fn get_domain_policy(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("sealed sender is not enabled"))?;
    let is_local = domain == federation.server_name();
    if !is_local {
        federation
            .feature_policies()
            .sync_remote(
                federation,
                &domain,
                FederatedFeaturePolicyTypeV1::SealedSenderService,
            )
            .await
            .map_err(|error| {
                AppError::new(axum::http::StatusCode::BAD_GATEWAY, error.to_string())
            })?;
    }
    let history = federation
        .feature_policies()
        .history(
            &domain,
            FederatedFeaturePolicyTypeV1::SealedSenderService,
            is_local,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("sealed sender policy not found"))?;
    Ok(Json(history).into_response())
}
