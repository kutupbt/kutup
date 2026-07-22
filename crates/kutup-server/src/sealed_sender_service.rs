//! Purpose-scoped online sender-certificate issuance.
//!
//! The offline trust root is intentionally absent from this module and normal
//! server configuration. Operators provision a root-signed libsignal server
//! certificate plus only its online private key.

use std::sync::Arc;

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
use rand09::{CryptoRng, Rng, TryRngCore as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

pub(crate) trait SealedSenderCertificateSigner: Send + Sync {
    fn issue<R: Rng + CryptoRng>(
        &self,
        sender: String,
        device_id: DeviceId,
        identity_key: PublicKey,
        expiration: Timestamp,
        rng: &mut R,
    ) -> anyhow::Result<SenderCertificate>;
}

struct LibsignalOnlineCertificateSigner {
    certificate: ServerCertificate,
    private_key: PrivateKey,
}

impl SealedSenderCertificateSigner for LibsignalOnlineCertificateSigner {
    fn issue<R: Rng + CryptoRng>(
        &self,
        sender: String,
        device_id: DeviceId,
        identity_key: PublicKey,
        expiration: Timestamp,
        rng: &mut R,
    ) -> anyhow::Result<SenderCertificate> {
        Ok(SenderCertificate::new(
            sender,
            None,
            identity_key,
            device_id,
            expiration,
            self.certificate.clone(),
            &self.private_key,
            rng,
        )?)
    }
}

pub(crate) struct SealedSenderService {
    policy: SealedSenderServicePolicyV1,
    certificate_id: u32,
    certificate_expires_at: i64,
    signer: LibsignalOnlineCertificateSigner,
}

impl SealedSenderService {
    pub fn from_config(config: &Config, now: OffsetDateTime) -> anyhow::Result<Option<Arc<Self>>> {
        let has_policy = !config.chat_sealed_sender_policy.trim().is_empty();
        let has_key = !config
            .chat_sealed_sender_online_private_key
            .trim()
            .is_empty();
        if !has_policy && !has_key {
            return Ok(None);
        }
        if !has_policy || !has_key || config.federation_server_name.is_empty() {
            anyhow::bail!(
                "sealed sender requires federation, a complete service policy, and an online private key"
            );
        }
        let policy: SealedSenderServicePolicyV1 =
            serde_json::from_str(&config.chat_sealed_sender_policy)?;
        policy.validate().map_err(anyhow::Error::msg)?;
        if policy.canonical_domain != config.federation_server_name {
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
            active = Some((reference.certificate_id, reference.expires_at, certificate));
        }
        let (certificate_id, certificate_expires_at, certificate) = active.ok_or_else(|| {
            anyhow::anyhow!("no active sealed sender server certificate matches the online key")
        })?;
        Ok(Some(Arc::new(Self {
            policy,
            certificate_id,
            certificate_expires_at,
            signer: LibsignalOnlineCertificateSigner {
                certificate,
                private_key,
            },
        })))
    }

    pub fn policy(&self) -> &SealedSenderServicePolicyV1 {
        &self.policy
    }

    fn issue(
        &self,
        canonical_sender: String,
        device_id: u32,
        identity_key: PublicKey,
        now: OffsetDateTime,
    ) -> AppResult<(Vec<u8>, i64)> {
        let expires_at = now
            .unix_timestamp()
            .checked_add(i64::from(self.policy.sender_certificate_lifetime_seconds))
            .ok_or_else(|| AppError::internal("sender certificate expiry overflow"))?;
        if expires_at > self.certificate_expires_at {
            return Err(AppError::internal(
                "online sealed sender server certificate has expired",
            ));
        }
        let device_id = DeviceId::try_from(device_id)
            .map_err(|_| AppError::bad_request("chat device id is invalid"))?;
        let expiration_millis = u64::try_from(expires_at)
            .ok()
            .and_then(|value| value.checked_mul(1000))
            .ok_or_else(|| AppError::internal("sender certificate expiry is invalid"))?;
        let mut rng = OsRng.unwrap_err();
        let certificate = self
            .signer
            .issue(
                canonical_sender,
                device_id,
                identity_key,
                Timestamp::from_epoch_millis(expiration_millis),
                &mut rng,
            )
            .map_err(|error| AppError::internal(format!("issue sender certificate: {error}")))?;
        Ok((
            certificate
                .serialized()
                .map_err(|error| AppError::internal(error.to_string()))?
                .to_vec(),
            expires_at,
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
    let (certificate, expires_at) = match service.issue(
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
    tracing::info!(
        certificate_id = service.certificate_id,
        "issued sealed sender certificate"
    );
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
                0,
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
