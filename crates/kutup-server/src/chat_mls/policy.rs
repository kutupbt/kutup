//! Authenticated MLS ordering policy and purpose-scoped control signer.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{Ed25519MlsControlSigner, MlsControlSigner, MlsOrderingServicePolicyV1};
use kutup_federation_proto::{FederatedFeaturePolicyHistoryV1, FederatedFeaturePolicyTypeV1};
use reqwest::StatusCode;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// Purpose-scoped online authority for one server's MLS control votes. The
/// federation identity key is never reused for this role.
pub(crate) struct MlsOrderingService {
    policy: MlsOrderingServicePolicyV1,
    signer: Ed25519MlsControlSigner,
}

impl MlsOrderingService {
    pub(crate) fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        let has_policy = !config.chat_mls_ordering_policy.trim().is_empty();
        let has_key = !config.chat_mls_control_signing_key.trim().is_empty();
        if !has_policy && !has_key {
            return Ok(None);
        }
        if !has_policy || !has_key || config.federation_server_name.is_empty() {
            anyhow::bail!(
                "MLS ordering requires federation, a complete policy, and a control signing key"
            );
        }
        let policy = MlsOrderingServicePolicyV1::from_canonical_bytes(
            config.chat_mls_ordering_policy.as_bytes(),
        )
        .map_err(anyhow::Error::msg)?;
        if policy.canonical_domain != config.federation_server_name {
            anyhow::bail!("MLS ordering policy domain does not match federation identity");
        }
        let seed = decode_canonical_base64_config(
            "CHAT_MLS_CONTROL_SIGNING_KEY",
            &config.chat_mls_control_signing_key,
        )?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("CHAT_MLS_CONTROL_SIGNING_KEY must be 32 bytes"))?;
        let signer = Ed25519MlsControlSigner::new(ed25519_dalek::SigningKey::from_bytes(&seed));
        if signer.key_id() != policy.control_signing_key_id
            || signer.public_key() != policy.control_signing_public_key
        {
            anyhow::bail!("MLS control signing key does not match the authenticated policy");
        }
        Ok(Some(Self { policy, signer }))
    }

    pub(crate) fn policy(&self) -> &MlsOrderingServicePolicyV1 {
        &self.policy
    }

    pub(crate) fn signer(&self) -> &dyn MlsControlSigner {
        &self.signer
    }
}

pub(super) async fn active_policy(state: &AppState) -> AppResult<MlsOrderingServicePolicyV1> {
    let configured = state
        .mls_ordering
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS service unavailable"))?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS service unavailable"))?;
    let history = federation
        .feature_policies()
        .local_history(
            federation.server_name(),
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
        )
        .await?
        .ok_or_else(|| AppError::not_found("MLS service unavailable"))?;
    let envelope = history.verify().map_err(|error| {
        AppError::internal(format!("invalid local MLS policy history: {error}"))
    })?;
    let payload = envelope.payload_bytes().map_err(|error| {
        AppError::internal(format!("invalid local MLS policy payload: {error}"))
    })?;
    let policy = MlsOrderingServicePolicyV1::from_canonical_bytes(&payload)
        .map_err(|error| AppError::internal(format!("invalid local MLS policy: {error}")))?;
    if &policy != configured.policy() {
        return Err(AppError::internal(
            "configured MLS policy differs from authenticated local policy",
        ));
    }
    Ok(policy)
}

/// Return the authenticated local MLS policy only while the shared federation
/// control plane publicly enables Chat. This is the single activation gate
/// used by both the public browser capability and administrative status.
pub(crate) async fn advertised_policy(
    state: &AppState,
    chat_publicly_enabled: bool,
) -> AppResult<Option<MlsOrderingServicePolicyV1>> {
    if !chat_publicly_enabled || state.mls_ordering.is_none() {
        return Ok(None);
    }
    if state.federation.is_none() {
        return Ok(None);
    }
    Ok(Some(active_policy(state).await?))
}

pub(super) async fn authenticated_remote_policy(
    state: &AppState,
    domain: &str,
) -> AppResult<MlsOrderingServicePolicyV1> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    federation
        .feature_policies()
        .sync_remote(
            federation,
            domain,
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
        )
        .await
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
    let history = federation
        .feature_policies()
        .history(
            domain,
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
            false,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::new(StatusCode::BAD_GATEWAY, "remote MLS policy is absent"))?;
    let envelope = history
        .verify()
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
    let payload = envelope
        .payload_bytes()
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
    MlsOrderingServicePolicyV1::from_canonical_bytes(&payload)
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error))
}

/// Same-origin access to a complete authenticated MLS ordering-policy history.
/// Remote domains are resolved only through the unified federation transport;
/// the browser independently verifies the returned identity and policy chains.
#[utoipa::path(
    get,
    path = "/api/chat/mls/domains/{domain}/policy",
    tag = "chat",
    operation_id = "getChatMlsOrderingPolicyHistory",
    params(
        ("domain" = String, Path, description = "Canonical MLS ordering authority domain")
    ),
    responses(
        (status = 200, description = "Complete authenticated federation identity and MLS ordering-policy history", body = FederatedFeaturePolicyHistoryV1),
        (status = 400, description = "Invalid canonical domain"),
        (status = 404, description = "MLS federation or policy unavailable"),
        (status = 502, description = "Remote policy authentication failed")
    ),
    security(("BearerAuth" = []))
)]
pub(crate) async fn get_policy_history(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("MLS federation is not configured"))?;
    let is_local = domain == federation.server_name();
    if is_local {
        active_policy(&state).await?;
    } else {
        authenticated_remote_policy(&state, &domain).await?;
    }
    let history = federation
        .feature_policies()
        .history(
            &domain,
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
            is_local,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("MLS ordering policy not found"))?;
    Ok(Json(history).into_response())
}

fn decode_canonical_base64_config(name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("{name} must be canonical padded base64"))?;
    if STANDARD.encode(&bytes) != value {
        anyhow::bail!("{name} must be canonical padded base64");
    }
    Ok(bytes)
}
