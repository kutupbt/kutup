//! The settings registry and an account's own limits
//! (docs/plans/settings-registry.md): every whole-number setting as Server
//! settings shows it, and, on an account's admin page, the settings and rate
//! limits that limit one account, each with its value in effect and where it
//! comes from, set or reset one at a time.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::rate_limits::{entry, RateLimitUnit};
use crate::middleware::AdminUser;
use crate::ratelimit::{self, Section, Spec};
use crate::site_settings::{
    self, NumericSetting, SettingSection, SettingUnit, ValueSource, RATE_LIMIT_PREFIX,
};
use crate::AppState;

/// One whole-number setting, as Server settings shows it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntry {
    pub key: &'static str,
    /// Its field in `/api/admin/settings`.
    pub field: &'static str,
    pub section: SettingSection,
    pub unit: SettingUnit,
    /// The value while administrators have set none.
    pub default: i64,
    pub min: i64,
    pub max: i64,
    /// Whether one account may have its own value.
    pub per_account: bool,
    /// The site's value now.
    pub value: i64,
    /// Whether administrators set it.
    pub set: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegistryResponse {
    pub settings: Vec<RegistryEntry>,
}

/// `GET /api/admin/settings/registry` — every whole-number setting with its
/// section, unit, first value, range and value now: what Server settings
/// builds its fields from.
#[utoipa::path(
    get,
    path = "/api/admin/settings/registry",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Every whole-number setting", body = RegistryResponse))
)]
pub async fn registry(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<RegistryResponse>> {
    let stored: HashMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT key, value FROM site_settings")
            .fetch_all(&state.pool)
            .await?
            .into_iter()
            .collect();
    Ok(Json(RegistryResponse {
        settings: site_settings::registry()
            .map(|(section, setting)| {
                let site = stored.get(setting.key).cloned();
                RegistryEntry {
                    key: setting.key,
                    field: setting.field,
                    section,
                    unit: setting.unit,
                    default: setting.default,
                    min: setting.min,
                    max: setting.max,
                    per_account: setting.per_account,
                    set: site.is_some(),
                    value: setting.resolve(None, site),
                }
            })
            .collect(),
    }))
}

/// A setting that limits one account, as it stands for one account.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountSettingEntry {
    /// Its key (what `PUT …/limits/{key}` takes).
    pub key: &'static str,
    pub field: &'static str,
    pub section: SettingSection,
    pub unit: SettingUnit,
    /// The value in effect for the account.
    pub value: i64,
    /// Where `value` comes from.
    pub source: ValueSource,
    /// What the account gets without its own value.
    pub site_value: i64,
    pub min: i64,
    pub max: i64,
}

/// A rate limit counted per account, as it stands for one account.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountRateLimitEntry {
    /// `rate_limit.<key>` (what `PUT …/limits/{key}` takes).
    pub key: String,
    /// The limit's own key, as Rate limits lists it.
    pub limit: &'static str,
    pub section: Section,
    pub unit: RateLimitUnit,
    pub window_seconds: Option<u64>,
    pub value: u64,
    pub source: ValueSource,
    pub site_value: u64,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountLimitsResponse {
    pub settings: Vec<AccountSettingEntry>,
    pub rate_limits: Vec<AccountRateLimitEntry>,
}

/// The account's own values, by key, as stored.
async fn own_values(state: &AppState, account: Uuid) -> AppResult<HashMap<String, i64>> {
    Ok(sqlx::query_as::<_, (String, i64)>(
        "SELECT key, value FROM user_setting_overrides WHERE user_id = $1",
    )
    .bind(account)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .collect())
}

async fn site_value(state: &AppState, setting: &NumericSetting) -> AppResult<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(setting.key)
            .fetch_optional(&state.pool)
            .await?,
    )
}

async fn setting_entry(
    state: &AppState,
    section: SettingSection,
    setting: &'static NumericSetting,
    own: Option<i64>,
) -> AppResult<AccountSettingEntry> {
    let site = site_value(state, setting).await?;
    let (value, source) = setting.source(own, site.clone());
    Ok(AccountSettingEntry {
        key: setting.key,
        field: setting.field,
        section,
        unit: setting.unit,
        value,
        source,
        site_value: setting.resolve(None, site),
        min: setting.min,
        max: setting.max,
    })
}

fn rate_limit_entry(
    spec: &'static Spec,
    site: &HashMap<String, String>,
    account: Uuid,
) -> AccountRateLimitEntry {
    let shown = entry(spec, site);
    let own = ratelimit::account_override(spec.limit, &account.to_string());
    AccountRateLimitEntry {
        key: format!("{RATE_LIMIT_PREFIX}{}", spec.key),
        limit: spec.key,
        section: spec.section,
        unit: shown.unit,
        window_seconds: shown.window_seconds,
        value: own.unwrap_or(shown.value),
        source: match (own, shown.set) {
            (Some(_), _) => ValueSource::Account,
            (None, true) => ValueSource::Site,
            (None, false) => ValueSource::Default,
        },
        site_value: shown.value,
        min: shown.min,
        max: shown.max,
    }
}

/// The account's username, or 404 when there is no such account.
async fn account_name(state: &AppState, id: Uuid) -> AppResult<Option<String>> {
    sqlx::query_scalar::<_, Option<String>>("SELECT username FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::not_found("user not found"))
}

/// `GET /api/admin/users/{id}/limits` — the settings and rate limits that
/// limit one account, as they stand for this one.
#[utoipa::path(
    get,
    path = "/api/admin/users/{id}/limits",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "The account")),
    responses(
        (status = 200, description = "The account's limits", body = AccountLimitsResponse),
        (status = 404, description = "No such account"),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AccountLimitsResponse>> {
    account_name(&state, id).await?;
    let site = ratelimit::reload(&state.pool).await?;
    let own = own_values(&state, id).await?;
    let mut settings = Vec::new();
    for (section, setting) in site_settings::registry().filter(|(_, s)| s.per_account) {
        settings
            .push(setting_entry(&state, section, setting, own.get(setting.key).copied()).await?);
    }
    Ok(Json(AccountLimitsResponse {
        settings,
        rate_limits: ratelimit::SPECS
            .iter()
            .filter(|spec| spec.overridable())
            .map(|spec| rate_limit_entry(spec, &site, id))
            .collect(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLimitRequest {
    /// The account's own value; `null` takes it back (the site's applies).
    pub value: Option<i64>,
}

/// What `PUT …/limits/{key}` changes.
enum Target {
    Setting(SettingSection, &'static NumericSetting),
    RateLimit(&'static Spec),
}

fn target(key: &str) -> AppResult<Target> {
    if let Some(limit) = key.strip_prefix(RATE_LIMIT_PREFIX) {
        let spec = ratelimit::SPECS
            .iter()
            .find(|spec| spec.key == limit)
            .ok_or_else(|| AppError::not_found("no such limit"))?;
        if !spec.overridable() {
            return Err(AppError::bad_request(format!(
                "{} is not counted per account",
                spec.key
            )));
        }
        return Ok(Target::RateLimit(spec));
    }
    let (section, setting) = site_settings::registry()
        .find(|(_, setting)| setting.key == key)
        .ok_or_else(|| AppError::not_found("no such limit"))?;
    if !setting.per_account {
        return Err(AppError::bad_request(format!(
            "{} does not limit one account",
            setting.field
        )));
    }
    Ok(Target::Setting(section, setting))
}

/// What `PUT …/limits/{key}` answers: the limit as it is now for the
/// account.
#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum AccountLimitEntry {
    Setting(AccountSettingEntry),
    RateLimit(AccountRateLimitEntry),
}

/// `PUT /api/admin/users/{id}/limits/{key}` — gives the account its own
/// value of a setting or rate limit that limits one account (`key`: a
/// setting's key, or `rate_limit.<key>`), or (`null`) takes it back. A value
/// outside the range is refused, never clamped. Lowering it below what the
/// account already uses only stops new growth. Audited as `user.setting` or
/// `user.rate_limit`.
#[utoipa::path(
    put,
    path = "/api/admin/users/{id}/limits/{key}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "The account"),
        ("key" = String, Path, description = "A setting's key, or rate_limit.<key>"),
    ),
    request_body = UpdateLimitRequest,
    responses(
        (status = 200, description = "The limit as it is now for the account", body = AccountLimitEntry),
        (status = 400, description = "Outside its range, or not one that limits one account"),
        (status = 404, description = "No such account or limit"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((id, key)): Path<(Uuid, String)>,
    Json(request): Json<UpdateLimitRequest>,
) -> AppResult<Json<AccountLimitEntry>> {
    let username = account_name(&state, id).await?;
    let target = target(&key)?;
    let (stored_key, action) = match &target {
        Target::Setting(_, setting) => {
            if let Some(value) = request.value {
                setting.validate(value).map_err(AppError::bad_request)?;
            }
            (setting.key.to_owned(), "user.setting")
        }
        Target::RateLimit(spec) => {
            let ceiling = ratelimit::ceiling(spec);
            if let Some(value) = request.value {
                if u64::try_from(value).map_or(true, |value| !(1..=ceiling).contains(&value)) {
                    return Err(AppError::bad_request(format!(
                        "{} is between 1 and {ceiling}",
                        spec.key
                    )));
                }
            }
            (
                format!("{RATE_LIMIT_PREFIX}{}", spec.key),
                "user.rate_limit",
            )
        }
    };
    let previous = own_values(&state, id).await?.get(&stored_key).copied();
    match request.value {
        Some(value) => {
            sqlx::query(
                "INSERT INTO user_setting_overrides (user_id, key, value) VALUES ($1, $2, $3)
                 ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
            )
            .bind(id)
            .bind(&stored_key)
            .bind(value)
            .execute(&state.pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM user_setting_overrides WHERE user_id = $1 AND key = $2")
                .bind(id)
                .bind(&stored_key)
                .execute(&state.pool)
                .await?;
        }
    }
    let site = ratelimit::reload(&state.pool).await?;
    crate::handlers::admin::audit(
        &state.pool,
        &admin.user_id,
        action,
        Some(id),
        json!({
            "username": username,
            "key": stored_key,
            "value": request.value,
            "previous": previous,
        }),
    )
    .await;
    Ok(Json(match target {
        Target::Setting(section, setting) => AccountLimitEntry::Setting(
            setting_entry(&state, section, setting, request.value).await?,
        ),
        Target::RateLimit(spec) => AccountLimitEntry::RateLimit(rate_limit_entry(spec, &site, id)),
    }))
}
