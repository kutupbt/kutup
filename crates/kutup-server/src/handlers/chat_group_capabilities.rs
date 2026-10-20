//! An account's group delivery capabilities (docs/plans/pairwise-groups.md,
//! slice 2 §2): the SHA-256 of one random capability per group it is in,
//! with no group id. A sender presents a member's raw capability with a
//! multi-recipient send; the server checks its hash against the member's
//! set. Adds and removes come in one transaction, so a member replacing its
//! capability (a member left) never has neither or both.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// Changes to the account's set, applied together.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityChanges {
    /// Capability hashes (SHA-256, canonical base64) to add.
    #[serde(default)]
    pub add: Vec<String>,
    /// Capability hashes to remove; one not in the set is ignored.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// The whole set, as a device restoring from its group list has it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySet {
    pub hashes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityCount {
    /// How many capabilities the account has now.
    pub count: i64,
}

/// Where pairwise groups are (`CHAT_GROUPS` and federation); elsewhere `404`.
fn enabled(state: &AppState) -> AppResult<()> {
    if state.config.chat_groups && state.federation.is_some() {
        Ok(())
    } else {
        Err(AppError::not_found("not found"))
    }
}

/// Hashes as given: canonical base64 of 32 bytes each, at most `limit` of
/// them (more could never fit).
fn hashes(values: &[String], limit: i64) -> AppResult<Vec<Vec<u8>>> {
    if i64::try_from(values.len()).unwrap_or(i64::MAX) > limit {
        return Err(over_limit());
    }
    values
        .iter()
        .map(|value| {
            STANDARD
                .decode(value)
                .ok()
                .filter(|bytes| bytes.len() == 32 && STANDARD.encode(bytes) == *value)
                .ok_or_else(|| {
                    AppError::bad_request("a capability hash is 32 bytes, canonical base64")
                })
        })
        .collect()
}

fn over_limit() -> AppError {
    AppError::conflict("the account has all the group capabilities it may")
        .with_details(serde_json::json!({ "code": "capabilityLimit" }))
}

/// The account's count after a change in `tx`, refused whole when over the
/// limit (the transaction is then dropped, so nothing changed).
async fn checked_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: uuid::Uuid,
    limit: i64,
) -> AppResult<CapabilityCount> {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat_group_capabilities WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?;
    if count > limit {
        return Err(over_limit());
    }
    Ok(CapabilityCount { count })
}

/// `PUT /api/chat/group-capabilities` — adds and removes capability hashes
/// in one transaction; a change that would pass the account's limit is
/// refused whole (`409 capabilityLimit`).
#[utoipa::path(
    put,
    path = "/api/chat/group-capabilities",
    tag = "chat",
    security(("BearerAuth" = [])),
    request_body = CapabilityChanges,
    responses(
        (status = 200, body = CapabilityCount),
        (status = 400, description = "A hash that isn't 32 bytes of canonical base64"),
        (status = 409, description = "capabilityLimit"),
    )
)]
pub async fn change(
    State(state): State<AppState>,
    user: AuthUser,
    Json(changes): Json<CapabilityChanges>,
) -> AppResult<Json<CapabilityCount>> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let limit = crate::site_settings::chat_group_capabilities_per_account(&state.pool).await?;
    let add = hashes(&changes.add, limit)?;
    let remove = hashes(&changes.remove, limit)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "DELETE FROM chat_group_capabilities
          WHERE user_id = $1 AND capability_hash = ANY($2)",
    )
    .bind(user_id)
    .bind(&remove)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO chat_group_capabilities (user_id, capability_hash)
         SELECT $1, hash FROM unnest($2::bytea[]) AS hash
         ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(&add)
    .execute(&mut *tx)
    .await?;
    let count = checked_count(&mut tx, user_id, limit).await?;
    tx.commit().await?;
    Ok(Json(count))
}

/// `POST /api/chat/group-capabilities/set` — the account's set becomes
/// exactly these hashes (a device restoring from its group list).
#[utoipa::path(
    post,
    path = "/api/chat/group-capabilities/set",
    tag = "chat",
    security(("BearerAuth" = [])),
    request_body = CapabilitySet,
    responses(
        (status = 200, body = CapabilityCount),
        (status = 400, description = "A hash that isn't 32 bytes of canonical base64"),
        (status = 409, description = "capabilityLimit"),
    )
)]
pub async fn set(
    State(state): State<AppState>,
    user: AuthUser,
    Json(set): Json<CapabilitySet>,
) -> AppResult<Json<CapabilityCount>> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let limit = crate::site_settings::chat_group_capabilities_per_account(&state.pool).await?;
    let hashes = hashes(&set.hashes, limit)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM chat_group_capabilities WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO chat_group_capabilities (user_id, capability_hash)
         SELECT $1, hash FROM unnest($2::bytea[]) AS hash
         ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(&hashes)
    .execute(&mut *tx)
    .await?;
    let count = checked_count(&mut tx, user_id, limit).await?;
    tx.commit().await?;
    Ok(Json(count))
}
