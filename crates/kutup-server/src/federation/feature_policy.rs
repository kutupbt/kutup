//! Durable authenticated feature-policy histories. Payload interpretation is
//! delegated to the owning feature protocol after the common envelope passes.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{ChatTransparencyPolicyV1, SealedSenderServicePolicyV1};
use kutup_federation_proto::{
    FederatedFeaturePolicyEnvelopeV1, FederatedFeaturePolicyHistoryV1,
    FederatedFeaturePolicyTypeV1, FederationIdentityDocumentV1,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::identity::insert_system_audit;
use super::{AuthenticatedFederationRequest, FederationRequestSpec, FederationStack};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;
use kutup_federation_proto::FederationFeature;
use reqwest::Method;

const FEATURE_POLICY_LOCK: i64 = 0x4b55_5455_5046_504f;
const JSON_CONTENT_TYPE: &str = "application/json";

#[derive(Clone)]
pub(crate) struct FeaturePolicyStore {
    pool: PgPool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PolicySequenceQuery {
    pub sequence: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RemotePolicySyncError {
    #[error("remote policy unavailable: {0}")]
    Unavailable(String),
    #[error("remote policy authentication failed: {0}")]
    Invalid(String),
}

impl FeaturePolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(
        &self,
        domain: &str,
        feature_type: FederatedFeaturePolicyTypeV1,
        sequence: Option<u64>,
    ) -> anyhow::Result<Option<FederatedFeaturePolicyEnvelopeV1>> {
        let value: Option<serde_json::Value> = if let Some(sequence) = sequence {
            let sequence = i64::try_from(sequence)
                .map_err(|_| anyhow::anyhow!("feature policy sequence is too large"))?;
            sqlx::query_scalar(
                "SELECT envelope FROM federation_feature_policy_documents
                 WHERE domain = $1 AND feature_type = $2 AND sequence = $3",
            )
            .bind(domain)
            .bind(feature_type.as_u16() as i16)
            .bind(sequence)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT envelope FROM federation_feature_policy_documents
                 WHERE domain = $1 AND feature_type = $2 ORDER BY sequence DESC LIMIT 1",
            )
            .bind(domain)
            .bind(feature_type.as_u16() as i16)
            .fetch_optional(&self.pool)
            .await?
        };
        value
            .map(|value| serde_json::from_value(value).map_err(anyhow::Error::from))
            .transpose()
    }

    pub async fn local_history(
        &self,
        domain: &str,
        feature_type: FederatedFeaturePolicyTypeV1,
    ) -> anyhow::Result<Option<FederatedFeaturePolicyHistoryV1>> {
        self.history(domain, feature_type, true).await
    }

    pub async fn history(
        &self,
        domain: &str,
        feature_type: FederatedFeaturePolicyTypeV1,
        is_local: bool,
    ) -> anyhow::Result<Option<FederatedFeaturePolicyHistoryV1>> {
        let identity_values: Vec<serde_json::Value> = if is_local {
            sqlx::query_scalar(
                "SELECT document FROM federation_local_identity_documents ORDER BY sequence",
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT document FROM federation_peer_identity_documents
                 WHERE domain = $1 AND acceptance IN ('accepted', 'superseded')
                 ORDER BY sequence",
            )
            .bind(domain)
            .fetch_all(&self.pool)
            .await?
        };
        let policy_values: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT envelope FROM federation_feature_policy_documents
             WHERE domain = $1 AND feature_type = $2 AND is_local = $3
             ORDER BY sequence",
        )
        .bind(domain)
        .bind(feature_type.as_u16() as i16)
        .bind(is_local)
        .fetch_all(&self.pool)
        .await?;
        if policy_values.is_empty() {
            return Ok(None);
        }
        let history = FederatedFeaturePolicyHistoryV1 {
            domain: domain.to_string(),
            feature_type,
            identities: identity_values
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<_, _>>()?,
            policies: policy_values
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<_, _>>()?,
        };
        history.verify()?;
        Ok(Some(history))
    }

    #[tracing::instrument(name = "federation.feature_policy.ensure_local", skip_all)]
    pub async fn ensure_local(
        &self,
        federation: &FederationStack,
        feature_type: FederatedFeaturePolicyTypeV1,
        payload: &[u8],
        allow_rotation: bool,
        now: OffsetDateTime,
    ) -> anyhow::Result<FederatedFeaturePolicyEnvelopeV1> {
        validate_feature_payload(feature_type, payload, 0)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(FEATURE_POLICY_LOCK)
            .execute(&mut *tx)
            .await?;
        let previous = load_latest(&mut tx, federation.server_name(), feature_type).await?;
        if let Some(previous) = &previous {
            if previous.payload_bytes()? == payload {
                tx.rollback().await?;
                return Ok(previous.clone());
            }
            if !allow_rotation {
                anyhow::bail!(
                    "configured {} policy differs from persisted sequence {}; run `kutup-server feature-policy rotate {}`",
                    feature_name(feature_type),
                    previous.sequence,
                    feature_name(feature_type)
                );
            }
        }
        let sequence = previous.as_ref().map_or(1, |value| value.sequence + 1);
        let envelope = FederatedFeaturePolicyEnvelopeV1::sign(
            federation.server_name(),
            feature_type,
            sequence,
            previous
                .as_ref()
                .map(FederatedFeaturePolicyEnvelopeV1::policy_hash)
                .transpose()?,
            federation.local_identity().document(),
            payload,
            now.unix_timestamp(),
            federation.local_identity().signing_key(),
        )?;
        envelope.verify_successor(previous.as_ref(), federation.local_identity().document())?;
        insert_envelope(&mut tx, &envelope, true).await?;
        insert_system_audit(
            &mut tx,
            if previous.is_some() {
                "federation.feature-policy.rotate"
            } else {
                "federation.feature-policy.bootstrap"
            },
            json!({
                "actorType": if allow_rotation { "operator-command" } else { "system" },
                "domain": envelope.domain,
                "featureType": envelope.feature_type.as_u16(),
                "sequence": envelope.sequence,
                "policyHash": envelope.policy_hash()?,
                "identityGeneration": envelope.federation_identity_generation,
            }),
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(envelope)
    }

    pub async fn accept_remote(
        &self,
        expected_domain: &str,
        envelope: &FederatedFeaturePolicyEnvelopeV1,
        local_witness_quorum_floor: u16,
    ) -> anyhow::Result<bool> {
        if envelope.domain != expected_domain {
            self.record_failure(envelope, "wrong_domain").await?;
            anyhow::bail!("remote feature policy has the wrong domain");
        }
        let mut tx = self.pool.begin().await?;
        let identity = load_accepted_identity(
            &mut tx,
            expected_domain,
            envelope.federation_identity_generation,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("policy identity generation is not authenticated"))?;
        let previous = load_latest(&mut tx, expected_domain, envelope.feature_type).await?;
        if let Some(existing) = load_exact(
            &mut tx,
            expected_domain,
            envelope.feature_type,
            envelope.sequence,
        )
        .await?
        {
            if existing.policy_hash()? == envelope.policy_hash()? {
                tx.rollback().await?;
                return Ok(false);
            }
            tx.rollback().await?;
            self.record_failure(envelope, "rollback").await?;
            anyhow::bail!("remote feature policy equivocated at an accepted sequence");
        }
        envelope.verify_successor(previous.as_ref(), &identity)?;
        validate_feature_payload(
            envelope.feature_type,
            &envelope.payload_bytes()?,
            local_witness_quorum_floor,
        )?;
        insert_envelope(&mut tx, envelope, false).await?;
        tx.commit().await?;
        Ok(true)
    }

    #[tracing::instrument(name = "federation.feature_policy.sync_remote", skip_all)]
    pub async fn sync_remote(
        &self,
        federation: &FederationStack,
        domain: &str,
        feature_type: FederatedFeaturePolicyTypeV1,
        local_witness_quorum_floor: u16,
    ) -> Result<FederatedFeaturePolicyEnvelopeV1, RemotePolicySyncError> {
        let current = fetch_remote_envelope(federation, domain, feature_type, None).await?;
        if current.domain != domain || current.feature_type != feature_type {
            return Err(RemotePolicySyncError::Invalid(
                "current policy has the wrong domain or feature type".into(),
            ));
        }
        let accepted = self
            .get(domain, feature_type, None)
            .await
            .map_err(|error| RemotePolicySyncError::Invalid(error.to_string()))?;
        let next = accepted.as_ref().map_or(1, |value| value.sequence + 1);
        if current.sequence < next.saturating_sub(1) {
            return Err(RemotePolicySyncError::Invalid(
                "remote policy sequence rolled back".into(),
            ));
        }
        if current.sequence == next.saturating_sub(1) {
            let accepted = accepted.ok_or_else(|| {
                RemotePolicySyncError::Invalid("remote policy history is empty".into())
            })?;
            if accepted
                .policy_hash()
                .map_err(|error| RemotePolicySyncError::Invalid(error.to_string()))?
                != current
                    .policy_hash()
                    .map_err(|error| RemotePolicySyncError::Invalid(error.to_string()))?
            {
                return Err(RemotePolicySyncError::Invalid(
                    "remote current policy conflicts with the accepted pin".into(),
                ));
            }
            return Ok(accepted);
        }
        if current.sequence > 1024 {
            return Err(RemotePolicySyncError::Invalid(
                "remote policy chain exceeds the v1 sequence bound".into(),
            ));
        }
        for sequence in next..=current.sequence {
            let candidate = if sequence == current.sequence {
                current.clone()
            } else {
                fetch_remote_envelope(federation, domain, feature_type, Some(sequence)).await?
            };
            if candidate.sequence != sequence
                || candidate.domain != domain
                || candidate.feature_type != feature_type
            {
                return Err(RemotePolicySyncError::Invalid(
                    "remote policy history has a gap or wrong typed identity".into(),
                ));
            }
            self.accept_remote(domain, &candidate, local_witness_quorum_floor)
                .await
                .map_err(|error| RemotePolicySyncError::Invalid(error.to_string()))?;
        }
        self.get(domain, feature_type, None)
            .await
            .map_err(|error| RemotePolicySyncError::Invalid(error.to_string()))?
            .ok_or_else(|| RemotePolicySyncError::Invalid("accepted policy disappeared".into()))
    }

    async fn record_failure(
        &self,
        envelope: &FederatedFeaturePolicyEnvelopeV1,
        failure_class: &str,
    ) -> anyhow::Result<()> {
        let value = serde_json::to_value(envelope)?;
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&value)?));
        sqlx::query(
            "INSERT INTO federation_feature_policy_failures
             (domain, feature_type, failure_class, evidence_digest, received_value)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&envelope.domain)
        .bind(envelope.feature_type.as_u16() as i16)
        .bind(failure_class)
        .bind(digest)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

async fn fetch_remote_envelope(
    federation: &FederationStack,
    domain: &str,
    feature_type: FederatedFeaturePolicyTypeV1,
    sequence: Option<u64>,
) -> Result<FederatedFeaturePolicyEnvelopeV1, RemotePolicySyncError> {
    let feature = feature_name(feature_type);
    let response = federation
        .send(
            domain,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::GET,
                path: format!("/api/fed/policies/{feature}"),
                query: sequence.map(|value| format!("sequence={value}")),
                content_type: JSON_CONTENT_TYPE.into(),
                body: Vec::new(),
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 512 * 1024,
            },
        )
        .await
        .map_err(|error| RemotePolicySyncError::Unavailable(error.to_string()))?;
    if response.status != StatusCode::OK {
        return Err(RemotePolicySyncError::Invalid(format!(
            "policy endpoint returned {}",
            response.status
        )));
    }
    serde_json::from_slice(&response.body)
        .map_err(|error| RemotePolicySyncError::Invalid(error.to_string()))
}

pub(crate) async fn get_local_feature_policy(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(feature): Path<String>,
    Query(query): Query<PolicySequenceQuery>,
) -> AppResult<Response> {
    let federation = configured(&state)?;
    let feature_type = parse_feature(&feature)?;
    let envelope = federation
        .feature_policies()
        .get(federation.server_name(), feature_type, query.sequence)
        .await?
        .ok_or_else(|| AppError::not_found("feature policy is not published"))?;
    Ok(Json(envelope).into_response())
}

pub(crate) async fn get_federated_feature_policy(
    State(state): State<AppState>,
    Path(feature): Path<String>,
    Query(query): Query<PolicySequenceQuery>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured(&state)?;
    let feature_type = parse_feature(&feature)?;
    let path = format!("/api/fed/policies/{feature}");
    let raw_query = query.sequence.map(|value| format!("sequence={value}"));
    let authenticated: AuthenticatedFederationRequest = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            raw_query.as_deref(),
            &[],
            FederationFeature::ChatV1,
        )
        .await?;
    let envelope = match federation
        .feature_policies()
        .get(federation.server_name(), feature_type, query.sequence)
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("feature policy is not published"),
            )
        }
        Err(error) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::internal(error.to_string()),
            )
        }
    };
    signed_json(federation, &authenticated, StatusCode::OK, &envelope)
}

fn configured(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("federation is not configured"))
}

fn parse_feature(value: &str) -> AppResult<FederatedFeaturePolicyTypeV1> {
    match value {
        "chat-transparency" => Ok(FederatedFeaturePolicyTypeV1::ChatTransparency),
        "sealed-sender" => Ok(FederatedFeaturePolicyTypeV1::SealedSenderService),
        _ => Err(AppError::not_found("unknown feature policy type")),
    }
}

fn feature_name(value: FederatedFeaturePolicyTypeV1) -> &'static str {
    match value {
        FederatedFeaturePolicyTypeV1::ChatTransparency => "chat-transparency",
        FederatedFeaturePolicyTypeV1::SealedSenderService => "sealed-sender",
    }
}

fn validate_feature_payload(
    feature_type: FederatedFeaturePolicyTypeV1,
    payload: &[u8],
    local_witness_quorum_floor: u16,
) -> anyhow::Result<()> {
    match feature_type {
        FederatedFeaturePolicyTypeV1::ChatTransparency => {
            let policy = ChatTransparencyPolicyV1::from_canonical_bytes(payload)
                .map_err(anyhow::Error::msg)?;
            if policy.required_quorum < local_witness_quorum_floor {
                anyhow::bail!(
                    "remote transparency witness quorum {} is below the local floor {}",
                    policy.required_quorum,
                    local_witness_quorum_floor
                );
            }
        }
        FederatedFeaturePolicyTypeV1::SealedSenderService => {
            SealedSenderServicePolicyV1::from_canonical_bytes(payload)
                .map_err(anyhow::Error::msg)?;
        }
    }
    Ok(())
}

async fn load_accepted_identity(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
    generation: u64,
) -> anyhow::Result<Option<FederationIdentityDocumentV1>> {
    let generation = i64::try_from(generation)
        .map_err(|_| anyhow::anyhow!("identity generation is too large"))?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT document FROM federation_peer_identity_documents
         WHERE domain = $1 AND sequence = $2
           AND acceptance IN ('accepted', 'superseded')",
    )
    .bind(domain)
    .bind(generation)
    .fetch_optional(&mut **tx)
    .await?;
    value
        .map(|value| serde_json::from_value(value).map_err(anyhow::Error::from))
        .transpose()
}

async fn load_latest(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
    feature_type: FederatedFeaturePolicyTypeV1,
) -> anyhow::Result<Option<FederatedFeaturePolicyEnvelopeV1>> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT envelope FROM federation_feature_policy_documents
         WHERE domain = $1 AND feature_type = $2 ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
    )
    .bind(domain)
    .bind(feature_type.as_u16() as i16)
    .fetch_optional(&mut **tx)
    .await?;
    value
        .map(|value| serde_json::from_value(value).map_err(anyhow::Error::from))
        .transpose()
}

async fn load_exact(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
    feature_type: FederatedFeaturePolicyTypeV1,
    sequence: u64,
) -> anyhow::Result<Option<FederatedFeaturePolicyEnvelopeV1>> {
    let sequence = i64::try_from(sequence)
        .map_err(|_| anyhow::anyhow!("feature policy sequence is too large"))?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT envelope FROM federation_feature_policy_documents
         WHERE domain = $1 AND feature_type = $2 AND sequence = $3",
    )
    .bind(domain)
    .bind(feature_type.as_u16() as i16)
    .bind(sequence)
    .fetch_optional(&mut **tx)
    .await?;
    value
        .map(|value| serde_json::from_value(value).map_err(anyhow::Error::from))
        .transpose()
}

async fn insert_envelope(
    tx: &mut Transaction<'_, Postgres>,
    envelope: &FederatedFeaturePolicyEnvelopeV1,
    is_local: bool,
) -> anyhow::Result<()> {
    let sequence = i64::try_from(envelope.sequence)
        .map_err(|_| anyhow::anyhow!("feature policy sequence is too large"))?;
    let generation = i64::try_from(envelope.federation_identity_generation)
        .map_err(|_| anyhow::anyhow!("feature policy identity generation is too large"))?;
    sqlx::query(
        "INSERT INTO federation_feature_policy_documents
         (domain, feature_type, sequence, policy_hash,
          federation_identity_generation, envelope, is_local)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&envelope.domain)
    .bind(envelope.feature_type.as_u16() as i16)
    .bind(sequence)
    .bind(envelope.policy_hash()?)
    .bind(generation)
    .bind(serde_json::to_value(envelope)?)
    .bind(is_local)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn signed_json<T: serde::Serialize>(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    status: StatusCode,
    value: &T,
) -> AppResult<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|error| AppError::internal(format!("serialize federation response: {error}")))?;
    federation.signed_response(authenticated, status, JSON_CONTENT_TYPE, body)
}

fn signed_app_error(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    error: AppError,
) -> AppResult<Response> {
    let message = if error.status.is_server_error() {
        "internal server error".to_owned()
    } else {
        error.message
    };
    signed_json(
        federation,
        authenticated,
        error.status,
        &serde_json::json!({ "error": message }),
    )
}
