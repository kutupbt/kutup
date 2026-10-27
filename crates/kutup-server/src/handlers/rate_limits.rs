//! Administration → Rate limits (docs/plans/admin-rate-limits.md §2, §6):
//! every limit in the registry with its value, its first value and where
//! that came from, set or reset one at a time. An account's own values are
//! with its other limits (`handlers::account_limits`).

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

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

pub(crate) fn entry(spec: &Spec, stored: &HashMap<String, String>) -> RateLimitEntry {
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
