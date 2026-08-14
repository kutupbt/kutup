//! Authenticated first-contact MLS KeyPackage claims.
//!
//! This path exists only for membership invitations. It deliberately exposes
//! the requester account to the destination; established application delivery
//! uses the separate anonymous capability routes.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    FederatedIdentifiedMlsKeyPackageRequestV1, IdentifiedMlsKeyPackageRequestV1,
    MlsKeyPackageBundleV1,
};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    active_policy, authenticated_remote_policy, increment_counter, scoped_digest,
    signed_federation_error, signed_federation_json, unavailable, MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

pub(crate) async fn get_identified_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<IdentifiedMlsKeyPackageRequestV1>,
) -> AppResult<Response> {
    request.validate().map_err(AppError::bad_request)?;
    let policy = active_policy(&state).await?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let requester_user_id = trusted_uuid(&auth.user_id)?;
    let requester_username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1 AND is_active = true")
            .bind(requester_user_id)
            .fetch_optional(&state.pool)
            .await?;
    let requester = kutup_chat_proto::AccountAddress::federated(
        &requester_username.ok_or_else(|| AppError::unauthorized("unauthorized"))?,
        federation.server_name(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let incarnation = i64::try_from(request.incarnation)
        .map_err(|_| AppError::bad_request("MLS incarnation is outside the supported range"))?;

    let may_claim_membership_packages: Option<bool> = sqlx::query_scalar(
        "SELECT (m.is_admin OR m.is_owner)
         FROM chat_mls_local_members m
         JOIN chat_mls_incarnations i
           ON i.conversation_id = m.conversation_id
          AND i.incarnation = m.incarnation
         JOIN chat_mls_conversations c
           ON c.conversation_id = i.conversation_id
          AND c.current_incarnation = i.incarnation
         WHERE m.conversation_id = $1 AND m.incarnation = $2
           AND m.user_id = $3 AND m.removed_epoch IS NULL
           AND m.membership_status = 'active'
           AND i.status = 'active' AND c.status = 'active' AND c.kind = 3",
    )
    .bind(request.conversation_id)
    .bind(incarnation)
    .bind(requester_user_id)
    .fetch_optional(&state.pool)
    .await?;
    let self_device_sync = request.recipient == requester;
    if may_claim_membership_packages.is_none()
        || (may_claim_membership_packages != Some(true) && !self_device_sync)
    {
        return Err(AppError::forbidden(
            "identified MLS KeyPackage claims require an administrator or the active member's own account",
        ));
    }

    if request.recipient.server.as_deref() == Some(federation.server_name()) {
        let bundle =
            claim_local_identified_key_packages(&state, &requester, &request, &policy.abuse_limits)
                .await?;
        return Ok(Json(bundle).into_response());
    }

    let destination = request
        .recipient
        .server
        .as_deref()
        .ok_or_else(unavailable)?;
    authenticated_remote_policy(&state, destination).await?;
    let transaction = FederatedIdentifiedMlsKeyPackageRequestV1 {
        origin_domain: federation.server_name().to_owned(),
        requester,
        request: request.clone(),
    };
    transaction.validate().map_err(AppError::bad_request)?;
    let body = serde_json::to_vec(&transaction)
        .map_err(|error| AppError::internal(format!("serialize MLS claim: {error}")))?;
    let response = federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path: "/api/fed/chat/mls/key-packages/identified".into(),
                query: None,
                content_type: "application/json".into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 2 * 1024 * 1024,
            },
        )
        .await
        .map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("remote identified MLS KeyPackage request failed: {error}"),
            )
        })?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(unavailable());
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!(
                "remote identified MLS KeyPackage request returned {}",
                response.status
            ),
        ));
    }
    let bundle: MlsKeyPackageBundleV1 = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote identified MLS KeyPackage response is invalid",
        )
    })?;
    bundle
        .validate(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error))?;
    if bundle.recipient != request.recipient {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote identified MLS KeyPackage recipient is bound incorrectly",
        ));
    }
    Ok(Json(bundle).into_response())
}

pub(crate) async fn federated_get_identified_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/mls/key-packages/identified",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    let policy = match active_policy(&state).await {
        Ok(policy) => policy,
        Err(error) => return signed_federation_error(federation, &authenticated, error),
    };
    let transaction: FederatedIdentifiedMlsKeyPackageRequestV1 = match serde_json::from_slice(&body)
    {
        Ok(transaction) => transaction,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid identified MLS KeyPackage request"),
            )
        }
    };
    if let Err(error) = transaction.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    if authenticated.origin() != transaction.origin_domain
        || authenticated.destination() != federation.server_name()
        || transaction.requester.server.as_deref() != Some(authenticated.origin())
        || transaction.request.recipient.server.as_deref() != Some(federation.server_name())
    {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::unauthorized("identified MLS federation routing mismatch"),
        );
    }
    match claim_local_identified_key_packages(
        &state,
        &transaction.requester,
        &transaction.request,
        &policy.abuse_limits,
    )
    .await
    {
        Ok(bundle) => signed_federation_json(federation, &authenticated, StatusCode::OK, &bundle),
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

async fn claim_local_identified_key_packages(
    state: &AppState,
    requester: &kutup_chat_proto::AccountAddress,
    request: &IdentifiedMlsKeyPackageRequestV1,
    limits: &kutup_chat_proto::MlsAbuseLimitsV1,
) -> AppResult<MlsKeyPackageBundleV1> {
    let now = OffsetDateTime::now_utc();
    let recipient: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT u.id, m.version
         FROM users u
         JOIN chat_device_manifests m ON m.user_id = u.id
         WHERE u.username = $1 AND u.is_active = true",
    )
    .bind(&request.recipient.username)
    .fetch_optional(&state.pool)
    .await?;
    let Some((recipient_user_id, manifest_version)) = recipient else {
        return Err(unavailable());
    };
    let manifest_version =
        u64::try_from(manifest_version).map_err(|_| AppError::internal("manifest version"))?;
    let mut rate_tx = state.pool.begin().await?;
    increment_counter(
        &mut rate_tx,
        "identified_bundle",
        scoped_digest(
            b"kutup/mls/rate/identified-bundle/v1",
            format!(
                "{}\0{}",
                requester.canonical(),
                request.recipient.canonical()
            )
            .as_bytes(),
        ),
        60,
        limits.capability_bundle_requests_per_minute.into(),
        now,
    )
    .await?;
    rate_tx.commit().await?;

    let manifest = crate::handlers::chat::load_account_manifest(state, recipient_user_id).await?;
    if manifest.sequence != manifest_version {
        return Err(unavailable());
    }
    let key_packages = MlsRepository::new(state.pool.clone())
        .claim_identified_key_packages(
            recipient_user_id,
            manifest_version,
            request.conversation_id,
            now,
        )
        .await?;
    let bundle = MlsKeyPackageBundleV1 {
        recipient: request.recipient.clone(),
        manifest,
        key_packages,
    };
    bundle
        .validate(now.unix_timestamp())
        .map_err(AppError::internal)?;
    Ok(bundle)
}
