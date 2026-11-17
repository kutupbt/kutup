//! The lowest client version an administrator allows, per client type
//! (docs/plans/api-surface.md §1.3): Administration → Server settings.
//! The compiled floor (`client_version::MIN_CLIENT_VERSIONS`) can be raised
//! here, never lowered.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::client_version::{self, Version};
use crate::error::{AppError, AppResult};
use crate::handlers::admin::audit;
use crate::middleware::AdminUser;
use crate::sessions::ClientType;
use crate::AppState;

/// One client type's minimums.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientVersionMinimum {
    pub client_type: String,
    /// What this server build requires; `null` when nothing.
    pub floor: Option<String>,
    /// What an administrator set; `null` when nothing.
    pub minimum: Option<String>,
    /// The one in force: the higher of the two.
    pub effective: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientVersionsResponse {
    /// This server's release.
    pub release: String,
    pub clients: Vec<ClientVersionMinimum>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetClientVersionRequest {
    pub client_type: String,
    /// A version (`0.0.14`, `2026.1120.0`), or `null` to clear it.
    pub minimum: Option<String>,
}

async fn list(state: &AppState) -> AppResult<ClientVersionsResponse> {
    let stored: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM site_settings WHERE key LIKE 'server.min_client_version.%'",
    )
    .fetch_all(&state.pool)
    .await?;
    let clients = ClientType::ALL
        .iter()
        .map(|&client| {
            let key = client_version::setting_key(client);
            let minimum = stored
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone());
            ClientVersionMinimum {
                client_type: client.as_str().into(),
                floor: client_version::floor(client).map(|v| v.to_string()),
                minimum,
                effective: state.client_minimums.get(client).map(|v| v.to_string()),
            }
        })
        .collect();
    Ok(ClientVersionsResponse {
        release: client_version::RELEASE.into(),
        clients,
    })
}

/// `GET /api/admin/client-versions`
#[utoipa::path(
    get,
    path = "/api/admin/client-versions",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Minimum client versions", body = ClientVersionsResponse))
)]
pub async fn get_client_versions(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<ClientVersionsResponse>> {
    Ok(Json(list(&state).await?))
}

/// `PUT /api/admin/client-versions`: sets or clears one type's minimum, at
/// once; recorded in the audit log.
#[utoipa::path(
    put,
    path = "/api/admin/client-versions",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = SetClientVersionRequest,
    responses(
        (status = 200, description = "Saved", body = ClientVersionsResponse),
        (status = 400, description = "An unknown type, a malformed version, or one below the floor"),
    )
)]
pub async fn set_client_version(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(request): Json<SetClientVersionRequest>,
) -> AppResult<Json<ClientVersionsResponse>> {
    let client = ClientType::parse(&request.client_type)
        .ok_or_else(|| AppError::bad_request("unknown client type"))?;
    let key = client_version::setting_key(client);
    match request.minimum.as_deref().map(str::trim) {
        None | Some("") => {
            sqlx::query("DELETE FROM site_settings WHERE key = $1")
                .bind(&key)
                .execute(&state.pool)
                .await?;
        }
        Some(value) => {
            let version = Version::parse(value)
                .filter(|v| !v.is_dev())
                .ok_or_else(|| AppError::bad_request("not a version (like 0.0.14)"))?;
            if let Some(floor) = client_version::floor(client) {
                if version < floor {
                    return Err(AppError::bad_request(format!(
                        "this server needs at least {floor}"
                    )));
                }
            }
            sqlx::query(
                "INSERT INTO site_settings (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(&key)
            .bind(version.to_string())
            .execute(&state.pool)
            .await?;
        }
    }
    state.client_minimums.reload(&state.pool).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "settings.update",
        None,
        json!({ "key": key, "value": request.minimum }),
    )
    .await;
    Ok(Json(list(&state).await?))
}
