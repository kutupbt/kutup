//! Authenticated MLS KeyPackage and delivery-capability publication routes.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    MlsKeyPackageCountResponseV1, PublishMlsDeliveryCapabilityV1, PublishMlsKeyPackagesRequestV1,
};
use time::OffsetDateTime;

use super::invitation_feedback::record_ready_invitation_feedback;
use super::{active_policy, MlsRepository, MAX_DEVICE_ID};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

pub(crate) async fn publish_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<PublishMlsKeyPackagesRequestV1>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    let user_id = trusted_uuid(&auth.user_id)?;
    let available = MlsRepository::new(state.pool)
        .publish_key_packages(user_id, &request, OffsetDateTime::now_utc())
        .await?;
    Ok(Json(MlsKeyPackageCountResponseV1 {
        device_id: request.device_id,
        available,
    })
    .into_response())
}

pub(crate) async fn key_package_count(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Path(device_id): axum::extract::Path<u32>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    if device_id == 0 || device_id > MAX_DEVICE_ID {
        return Err(AppError::bad_request("invalid MLS device id"));
    }
    let available = MlsRepository::new(state.pool)
        .available_key_package_count(
            trusted_uuid(&auth.user_id)?,
            device_id,
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(Json(MlsKeyPackageCountResponseV1 {
        device_id,
        available,
    })
    .into_response())
}

pub(crate) async fn publish_delivery_capability(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<PublishMlsDeliveryCapabilityV1>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    let user_id = trusted_uuid(&auth.user_id)?;
    MlsRepository::new(state.pool.clone())
        .publish_delivery_capability(user_id, &request)
        .await?;
    record_ready_invitation_feedback(&state, user_id, &request).await?;
    Ok(Json(serde_json::json!({ "published": true })).into_response())
}
