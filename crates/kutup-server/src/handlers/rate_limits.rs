//! Administration → Rate limits (docs/plans/admin-rate-limits.md §2, §6):
//! every limit in the registry with its value, its first value and where
//! that came from, set or reset one at a time.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::AdminUser;
use crate::ratelimit::{self, FirstFrom, Per, Section, Spec, Unit};
use crate::AppState;

/// What a limit's value counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum RateLimitUnit {
    /// Events in `windowSeconds`.
    Events,
    /// Wrong attempts before a lock.
    Attempts,
    Minutes,
    /// Bytes in `windowSeconds`.
    Bytes,
    /// How many at once (or a burst).
    AtOnce,
    /// Bytes at once (a burst).
    BytesAtOnce,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitEntry {
    pub key: &'static str,
    pub section: Section,
    pub per: Per,
    pub unit: RateLimitUnit,
    /// The window events are counted in, for `events`.
    pub window_seconds: Option<u64>,
    /// What it stops.
    pub about: &'static str,
    pub value: u64,
    /// The value while administrators have set none.
    pub first_value: u64,
    pub first_from: FirstFrom,
    /// The environment variable that may set the first value.
    pub env: Option<&'static str>,
    /// Whether administrators set the value.
    pub set: bool,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RateLimitsResponse {
    pub limits: Vec<RateLimitEntry>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRateLimitRequest {
    /// The new value; `null` resets it to its first value.
    pub value: Option<u64>,
}

fn entry(spec: &Spec, stored: &HashMap<String, String>) -> RateLimitEntry {
    let (unit, window_seconds) = match spec.unit {
        Unit::Events(window) => (RateLimitUnit::Events, Some(window.as_secs())),
        Unit::EventsPerLockout => (
            RateLimitUnit::Events,
            Some(ratelimit::value(ratelimit::Limit::LoginLockoutMinutes).saturating_mul(60)),
        ),
        Unit::Attempts => (RateLimitUnit::Attempts, None),
        Unit::Minutes => (RateLimitUnit::Minutes, None),
        Unit::Bytes(window) => (RateLimitUnit::Bytes, Some(window.as_secs())),
        Unit::AtOnce => (RateLimitUnit::AtOnce, None),
        Unit::BytesAtOnce => (RateLimitUnit::BytesAtOnce, None),
    };
    let (first_value, first_from) = ratelimit::first(spec.limit);
    RateLimitEntry {
        key: spec.key,
        section: spec.section,
        per: spec.per,
        unit,
        window_seconds,
        about: spec.about,
        value: ratelimit::value(spec.limit),
        first_value,
        first_from,
        env: spec.env,
        set: stored.contains_key(spec.key),
        min: 1,
        max: ratelimit::ceiling(spec),
    }
}

/// `GET /api/admin/rate-limits` — every rate limit, read fresh (this backend
/// takes the stored values at once).
#[utoipa::path(
    get,
    path = "/api/admin/rate-limits",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Every rate limit", body = RateLimitsResponse))
)]
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<RateLimitsResponse>> {
    let stored = ratelimit::reload(&state.pool).await?;
    Ok(Json(RateLimitsResponse {
        limits: ratelimit::SPECS
            .iter()
            .map(|spec| entry(spec, &stored))
            .collect(),
    }))
}

/// `PUT /api/admin/rate-limits/{key}` — sets one limit, or resets it to its
/// first value. It applies at once on this backend and within 30 seconds on
/// the others; audited as `settings.rate_limit`.
#[utoipa::path(
    put,
    path = "/api/admin/rate-limits/{key}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("key" = String, Path, description = "The limit's key")),
    request_body = UpdateRateLimitRequest,
    responses(
        (status = 200, description = "The limit as it is now", body = RateLimitEntry),
        (status = 400, description = "Outside the limit's bounds"),
        (status = 404, description = "No such limit"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(key): Path<String>,
    Json(request): Json<UpdateRateLimitRequest>,
) -> AppResult<Json<RateLimitEntry>> {
    let spec = ratelimit::SPECS
        .iter()
        .find(|spec| spec.key == key)
        .ok_or_else(|| AppError::not_found("no such rate limit"))?;
    if let Some(value) = request.value {
        if !(1..=ratelimit::ceiling(spec)).contains(&value) {
            return Err(AppError::bad_request(format!(
                "{} is between 1 and {}",
                spec.key,
                ratelimit::ceiling(spec)
            )));
        }
    }
    let previous = ratelimit::value(spec.limit);
    let setting = format!("{}{}", ratelimit::SETTING_PREFIX, spec.key);
    match request.value {
        Some(value) => {
            sqlx::query(
                "INSERT INTO site_settings (key, value) VALUES ($1, $2) \
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(&setting)
            .bind(value.to_string())
            .execute(&state.pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM site_settings WHERE key = $1")
                .bind(&setting)
                .execute(&state.pool)
                .await?;
        }
    }
    let stored = ratelimit::reload(&state.pool).await?;
    crate::handlers::admin::audit(
        &state.pool,
        &admin.user_id,
        "settings.rate_limit",
        None,
        json!({
            "key": spec.key,
            "value": request.value,
            "previous": previous,
        }),
    )
    .await;
    Ok(Json(entry(spec, &stored)))
}

/// One limit counted per account, as it stands for one account.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountRateLimitEntry {
    pub key: &'static str,
    pub section: Section,
    pub unit: RateLimitUnit,
    pub window_seconds: Option<u64>,
    /// What the account gets: its own value, else the site's.
    pub value: u64,
    pub site_value: u64,
    /// Whether administrators gave the account its own value.
    #[serde(rename = "override")]
    pub own: bool,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountRateLimitsResponse {
    pub limits: Vec<AccountRateLimitEntry>,
}

fn account_entry(spec: &Spec, account: &str) -> AccountRateLimitEntry {
    let site = entry(spec, &HashMap::new());
    let own = ratelimit::account_override(spec.limit, account);
    AccountRateLimitEntry {
        key: spec.key,
        section: spec.section,
        unit: site.unit,
        window_seconds: site.window_seconds,
        value: own.unwrap_or(site.value),
        site_value: site.value,
        own: own.is_some(),
        min: 1,
        max: ratelimit::ceiling(spec),
    }
}

/// The account's username, or 404 when there is no such account.
async fn account_name(state: &AppState, id: Uuid) -> AppResult<String> {
    sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::not_found("user not found"))
}

/// `GET /api/admin/users/{id}/rate-limits` — the limits counted per account,
/// as they stand for this one.
#[utoipa::path(
    get,
    path = "/api/admin/users/{id}/rate-limits",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "The account")),
    responses(
        (status = 200, description = "The account's limits", body = AccountRateLimitsResponse),
        (status = 404, description = "No such account"),
    )
)]
pub async fn account_list(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AccountRateLimitsResponse>> {
    account_name(&state, id).await?;
    ratelimit::reload(&state.pool).await?;
    let account = id.to_string();
    Ok(Json(AccountRateLimitsResponse {
        limits: ratelimit::SPECS
            .iter()
            .filter(|spec| spec.overridable())
            .map(|spec| account_entry(spec, &account))
            .collect(),
    }))
}

/// `PUT /api/admin/users/{id}/rate-limits/{key}` — gives the account its own
/// value of a limit counted per account, or (`null`) takes it back. Audited
/// as `user.rate_limit`.
#[utoipa::path(
    put,
    path = "/api/admin/users/{id}/rate-limits/{key}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "The account"),
        ("key" = String, Path, description = "The limit's key"),
    ),
    request_body = UpdateRateLimitRequest,
    responses(
        (status = 200, description = "The limit as it is now for the account", body = AccountRateLimitEntry),
        (status = 400, description = "Outside the limit's bounds, or not counted per account"),
        (status = 404, description = "No such account or limit"),
    )
)]
pub async fn account_update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((id, key)): Path<(Uuid, String)>,
    Json(request): Json<UpdateRateLimitRequest>,
) -> AppResult<Json<AccountRateLimitEntry>> {
    let username = account_name(&state, id).await?;
    let spec = ratelimit::SPECS
        .iter()
        .find(|spec| spec.key == key)
        .ok_or_else(|| AppError::not_found("no such rate limit"))?;
    if !spec.overridable() {
        return Err(AppError::bad_request(format!(
            "{} is not counted per account",
            spec.key
        )));
    }
    let previous = ratelimit::account_override(spec.limit, &id.to_string());
    match request.value {
        Some(value) => {
            if !(1..=ratelimit::ceiling(spec)).contains(&value) {
                return Err(AppError::bad_request(format!(
                    "{} is between 1 and {}",
                    spec.key,
                    ratelimit::ceiling(spec)
                )));
            }
            sqlx::query(
                "INSERT INTO user_rate_limit_overrides (user_id, key, value) VALUES ($1, $2, $3) \
                 ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
            )
            .bind(id)
            .bind(spec.key)
            .bind(value as i64)
            .execute(&state.pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM user_rate_limit_overrides WHERE user_id = $1 AND key = $2")
                .bind(id)
                .bind(spec.key)
                .execute(&state.pool)
                .await?;
        }
    }
    ratelimit::reload(&state.pool).await?;
    crate::handlers::admin::audit(
        &state.pool,
        &admin.user_id,
        "user.rate_limit",
        Some(id),
        json!({
            "username": username,
            "key": spec.key,
            "value": request.value,
            "previous": previous,
        }),
    )
    .await;
    Ok(Json(account_entry(spec, &id.to_string())))
}
