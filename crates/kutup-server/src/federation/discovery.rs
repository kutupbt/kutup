use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_federation_proto::{
    verify_identity_chain, FederationCapabilityId, FederationDiscoveryTransportPolicy,
    FederationDiscoveryV2, FederationIdentityDocumentV1,
};
use time::{Duration, OffsetDateTime};

use super::{FederationPolicyFeature, FederationStack};
use crate::error::{AppError, AppResult};
use crate::AppState;

const DEFAULT_DISCOVERY_LIFETIME: Duration = Duration::hours(1);

impl FederationStack {
    /// Build the signed, short-lived v2 discovery representation.
    pub fn signed_discovery(
        &self,
        capabilities: Vec<FederationCapabilityId>,
        now: OffsetDateTime,
    ) -> anyhow::Result<FederationDiscoveryV2> {
        let expires_at = now
            .checked_add(DEFAULT_DISCOVERY_LIFETIME)
            .ok_or_else(|| anyhow::anyhow!("federation discovery expiry overflow"))?;
        let transport_policy = if self.config.allow_private_test_network {
            FederationDiscoveryTransportPolicy::AllowHttpForTesting
        } else {
            FederationDiscoveryTransportPolicy::HttpsOnly
        };
        Ok(FederationDiscoveryV2::sign_with_transport_policy(
            &self.config.server_name,
            &self.config.api_base,
            capabilities,
            self.local_identity.document().clone(),
            now.unix_timestamp(),
            expires_at.unix_timestamp(),
            self.local_identity.signing_key(),
            transport_policy,
        )?)
    }

    /// Return one immutable local identity document only after re-verifying
    /// its complete stored prefix from genesis. A corrupt or gapped database
    /// never becomes an identity-history response.
    pub async fn identity_document(
        &self,
        sequence: u64,
    ) -> anyhow::Result<Option<FederationIdentityDocumentV1>> {
        let sequence = i64::try_from(sequence)
            .map_err(|_| anyhow::anyhow!("identity sequence exceeds PostgreSQL BIGINT"))?;
        let rows: Vec<(i64, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT sequence, document_hash, key_id, document
             FROM federation_local_identity_documents
             WHERE sequence <= $1 ORDER BY sequence",
        )
        .bind(sequence)
        .fetch_all(&self.pool)
        .await?;
        let documents: Vec<FederationIdentityDocumentV1> = rows
            .into_iter()
            .map(|(stored_sequence, stored_hash, stored_key_id, value)| {
                let document: FederationIdentityDocumentV1 = serde_json::from_value(value)?;
                let document_sequence = i64::try_from(document.sequence).map_err(|_| {
                    anyhow::anyhow!("stored identity sequence exceeds PostgreSQL BIGINT")
                })?;
                if document_sequence != stored_sequence
                    || document.document_hash()? != stored_hash
                    || document.key.key_id != stored_key_id
                {
                    anyhow::bail!("stored local identity metadata does not match its document");
                }
                Ok(document)
            })
            .collect::<anyhow::Result<_>>()?;
        let Some(document) = documents.last() else {
            return Ok(None);
        };
        if i64::try_from(document.sequence).ok() != Some(sequence) {
            return Ok(None);
        }
        verify_identity_chain(&self.config.server_name, &documents).map_err(anyhow::Error::msg)?;
        if documents
            .iter()
            .enumerate()
            .any(|(expected, document)| document.sequence != expected as u64)
        {
            anyhow::bail!("stored local identity history is not contiguous from genesis");
        }
        Ok(Some(document.clone()))
    }

    #[cfg(test)]
    fn maximum_discovery_lifetime() -> Duration {
        Duration::seconds(kutup_federation_proto::MAX_DISCOVERY_LIFETIME_SECONDS)
    }
}

async fn enabled_capabilities(
    federation: &FederationStack,
) -> anyhow::Result<Vec<FederationCapabilityId>> {
    let chat = federation
        .policy()
        .feature_is_publicly_enabled(FederationPolicyFeature::Chat)
        .await?;
    let drive = federation
        .policy()
        .feature_is_publicly_enabled(FederationPolicyFeature::Drive)
        .await?;
    if !chat && !drive {
        return Ok(Vec::new());
    }
    let mut capabilities = vec![FederationCapabilityId::identity_v1()];
    if chat {
        capabilities.push(FederationCapabilityId::chat_v1());
    }
    if drive {
        capabilities.push(FederationCapabilityId::drive_v1());
    }
    capabilities.sort();
    Ok(capabilities)
}

/// Public v2 discovery is visible while at least one feature is enabled and
/// advertises only the feature capabilities admitted by the shared policy.
#[utoipa::path(
    get,
    path = "/.well-known/kutup/federation.json",
    tag = "federation",
    responses(
        (status = 200, description = "Signed unified federation v2 discovery", body = FederationDiscoveryV2),
        (status = 404, description = "Federation is not configured or globally available")
    )
)]
pub(crate) async fn public_discovery(State(state): State<AppState>) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("federation is not configured"))?;
    let capabilities = enabled_capabilities(federation).await?;
    if capabilities.is_empty() {
        return Err(AppError::not_found("federation is disabled by policy"));
    }
    let document = federation.signed_discovery(capabilities, OffsetDateTime::now_utc())?;
    Ok(Json(document).into_response())
}

#[utoipa::path(
    get,
    path = "/.well-known/kutup/federation/identity/{sequence}.json",
    tag = "federation",
    params(("sequence" = u64, Path, description = "Immutable identity sequence")),
    responses(
        (status = 200, description = "Immutable federation identity document", body = FederationIdentityDocumentV1),
        (status = 404, description = "Identity sequence is unavailable")
    )
)]
pub(crate) async fn public_identity_document(
    State(state): State<AppState>,
    Path(sequence): Path<String>,
) -> AppResult<Response> {
    let sequence = sequence
        .strip_suffix(".json")
        .ok_or_else(|| AppError::not_found("federation identity document not found"))?
        .parse::<u64>()
        .map_err(|_| AppError::not_found("federation identity document not found"))?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("federation is not configured"))?;
    if enabled_capabilities(federation).await?.is_empty() {
        return Err(AppError::not_found("federation is disabled by policy"));
    }
    let document = federation
        .identity_document(sequence)
        .await?
        .ok_or_else(|| AppError::not_found("federation identity document not found"))?;
    Ok(Json(document).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_default_is_shorter_than_the_protocol_maximum() {
        assert!(DEFAULT_DISCOVERY_LIFETIME < FederationStack::maximum_discovery_lifetime());
    }
}
