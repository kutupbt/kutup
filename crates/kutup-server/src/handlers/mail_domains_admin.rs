//! Custom domains in Administration (docs/plans/mail-custom-domains.md §7,
//! §11; decided 2026-10-20): every limit and switch editable, per-user
//! overrides, every account's domains with approve (the `approve` mode) and
//! deactivate, and the DKIM records the operator publishes.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::admin::audit;
use crate::mail::domains::dkim;
use crate::mail::domains::settings::{self, Settings, KEYS, MODE_KEY};
use crate::mail::domains::store;
use crate::middleware::AdminUser;
use crate::AppState;

/// A DKIM key and the record that publishes it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DkimKeyView {
    pub selector: String,
    /// `pending` (publish it), `active`, `retiring` (keep it published).
    pub state: String,
    /// The wildcard name: `*.<selector>._dk.<server>`.
    pub host: String,
    pub txt: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub published_since: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminDomain {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub state: i16,
    pub verify_state: i16,
    pub mx_state: i16,
    pub spf_state: i16,
    pub dkim_state: i16,
    pub dmarc_state: i16,
    pub approved: bool,
    pub stopped: bool,
    /// Deactivated by an administrator: nobody may prove it until lifted.
    pub blocked: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminDomains {
    /// Stalwart's management key and MAIL_DKIM_KEYS are set: custom domains
    /// can work here at all.
    pub configured: bool,
    /// Every setting by its key (`mail_domains.*`), as in effect.
    pub settings: BTreeMap<String, String>,
    /// The server's SPF record for customers to include.
    pub spf: DkimKeyView,
    pub dkim_keys: Vec<DkimKeyView>,
    pub domains: Vec<AdminDomain>,
}

#[derive(sqlx::FromRow)]
struct AdminDomainRow {
    id: Uuid,
    name: String,
    owner: String,
    state: i16,
    verify_state: i16,
    mx_state: i16,
    spf_state: i16,
    dkim_state: i16,
    dmarc_state: i16,
    approved: bool,
    stopped: bool,
    blocked: bool,
    created_at: OffsetDateTime,
}

fn effective(settings: &Settings) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(MODE_KEY.to_owned(), settings.mode.as_str().to_owned());
    let values = [
        settings.domains_per_account,
        settings.addresses_per_account,
        settings.domains_on_server,
        settings.adds_per_day,
        settings.pending_days,
        settings.catch_all_per_day,
        settings.grace_warn_days,
        settings.grace_stopped_hours,
        i64::from(settings.catch_all),
    ];
    for ((key, _, _), value) in KEYS.iter().zip(values) {
        out.insert((*key).to_owned(), value.to_string());
    }
    out
}

/// `GET /api/admin/mail/domains`
#[utoipa::path(
    get,
    path = "/api/admin/mail/domains",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, body = AdminDomains))
)]
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<AdminDomains>> {
    let settings = Settings::load(&state.pool).await?;
    let server = &state.config.chat_server_name;
    let dkim_keys = dkim::keys(&state.pool)
        .await?
        .into_iter()
        .map(|key| DkimKeyView {
            host: format!("*.{}._dk.{server}", key.selector),
            txt: key.txt(),
            selector: key.selector,
            state: key.state,
            published_since: key.published_since,
        })
        .collect();
    let rows: Vec<AdminDomainRow> = sqlx::query_as(
        "SELECT d.id, d.name, COALESCE(u.username, u.id::text) AS owner, d.state, d.verify_state,
                d.mx_state, d.spf_state, d.dkim_state, d.dmarc_state,
                d.approved_at IS NOT NULL AS approved, d.stopped_at IS NOT NULL AS stopped,
                EXISTS (SELECT 1 FROM mail_domain_blocks b WHERE b.name = d.name) AS blocked,
                d.created_at
           FROM mail_domains d JOIN users u ON u.id = d.user_id
          WHERE d.removed_at IS NULL
          ORDER BY d.name",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(AdminDomains {
        configured: crate::mail::domains::sweep::configured(&state),
        settings: effective(&settings),
        spf: DkimKeyView {
            selector: String::new(),
            state: "spf".into(),
            host: format!("_spf.{server}"),
            txt: "v=spf1 ip4:<this server's outbound address> -all".into(),
            published_since: None,
        },
        dkim_keys,
        domains: rows
            .into_iter()
            .map(|r| AdminDomain {
                id: r.id.to_string(),
                name: r.name,
                owner: r.owner,
                state: r.state,
                verify_state: r.verify_state,
                mx_state: r.mx_state,
                spf_state: r.spf_state,
                dkim_state: r.dkim_state,
                dmarc_state: r.dmarc_state,
                approved: r.approved,
                stopped: r.stopped,
                blocked: r.blocked,
                created_at: r.created_at,
            })
            .collect(),
    }))
}

/// `PUT /api/admin/mail/domains/settings` — any of the `mail_domains.*`
/// settings, each checked against its range; applies at once.
#[utoipa::path(
    put,
    path = "/api/admin/mail/domains/settings",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = BTreeMap<String, String>,
    responses((status = 200, body = BTreeMap<String, String>), (status = 400))
)]
pub async fn set_settings(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(changes): Json<BTreeMap<String, String>>,
) -> AppResult<Json<BTreeMap<String, String>>> {
    let mut checked = Vec::with_capacity(changes.len());
    for (key, value) in &changes {
        let value = settings::validate(key, value).map_err(AppError::bad_request)?;
        checked.push((key.clone(), value));
    }
    let mut tx = state.pool.begin().await?;
    for (key, value) in &checked {
        sqlx::query(
            "INSERT INTO site_settings (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    if !checked.is_empty() {
        audit(
            &state.pool,
            &admin.user_id,
            "mail.domains.settings",
            None,
            json!(checked.iter().cloned().collect::<BTreeMap<_, _>>()),
        )
        .await;
    }
    Ok(Json(effective(&Settings::load(&state.pool).await?)))
}

/// `POST /api/admin/mail/domains/{id}/approve` — lets a verified domain
/// take mail (the `approve` mode).
#[utoipa::path(
    post,
    path = "/api/admin/mail/domains/{id}/approve",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 204), (status = 404))
)]
pub async fn approve(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such domain"))?;
    let name: Option<String> = sqlx::query_scalar(
        "UPDATE mail_domains SET approved_at = COALESCE(approved_at, now())
          WHERE id = $1 AND removed_at IS NULL RETURNING name",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let name = name.ok_or_else(|| AppError::not_found("no such domain"))?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail.domains.approve",
        None,
        json!({ "domain": name }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/admin/mail/domains/{id}/deactivate` — an administrator ends a
/// domain (abuse): inactive at once, its addresses freed, its owner told,
/// and its name blocked until `unblock`.
#[utoipa::path(
    post,
    path = "/api/admin/mail/domains/{id}/deactivate",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 204), (status = 404))
)]
pub async fn deactivate(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such domain"))?;
    let admin_id =
        Uuid::parse_str(&admin.user_id).map_err(|_| AppError::unauthorized("bad session"))?;
    let name = store::deactivate(&state.pool, id, admin_id).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail.domains.deactivate",
        None,
        json!({ "domain": name }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/admin/mail/domains/{id}/unblock` — lifts the block a
/// deactivation put on the domain's name: it may be proven again.
#[utoipa::path(
    post,
    path = "/api/admin/mail/domains/{id}/unblock",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 204), (status = 404))
)]
pub async fn unblock(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such domain"))?;
    let name = store::unblock(&state.pool, id).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail.domains.unblock",
        None,
        json!({ "domain": name }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// One account's limits over the site's; `null` keeps the site's.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainOverrides {
    pub max_domains: Option<i32>,
    pub max_addresses: Option<i32>,
    pub catch_all: Option<bool>,
}

/// `GET /api/admin/users/{id}/mail-domains`
#[utoipa::path(
    get,
    path = "/api/admin/users/{id}/mail-domains",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 200, body = DomainOverrides))
)]
pub async fn overrides(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Json<DomainOverrides>> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such user"))?;
    let row: Option<(Option<i32>, Option<i32>, Option<bool>)> = sqlx::query_as(
        "SELECT max_domains, max_addresses, catch_all FROM mail_domain_overrides WHERE user_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let (max_domains, max_addresses, catch_all) = row.unwrap_or_default();
    Ok(Json(DomainOverrides {
        max_domains,
        max_addresses,
        catch_all,
    }))
}

/// `PUT /api/admin/users/{id}/mail-domains`
#[utoipa::path(
    put,
    path = "/api/admin/users/{id}/mail-domains",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    request_body = DomainOverrides,
    responses((status = 200, body = DomainOverrides), (status = 400), (status = 404))
)]
pub async fn set_overrides(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(input): Json<DomainOverrides>,
) -> AppResult<Json<DomainOverrides>> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such user"))?;
    if input.max_domains.is_some_and(|n| !(0..=100).contains(&n))
        || input
            .max_addresses
            .is_some_and(|n| !(1..=1000).contains(&n))
    {
        return Err(AppError::bad_request(
            "maxDomains is 0 to 100, maxAddresses 1 to 1000",
        ));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    if !exists {
        return Err(AppError::not_found("no such user"));
    }
    sqlx::query(
        "INSERT INTO mail_domain_overrides (user_id, max_domains, max_addresses, catch_all)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE SET max_domains = EXCLUDED.max_domains,
             max_addresses = EXCLUDED.max_addresses, catch_all = EXCLUDED.catch_all",
    )
    .bind(id)
    .bind(input.max_domains)
    .bind(input.max_addresses)
    .bind(input.catch_all)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail.domains.overrides",
        Some(id),
        json!(input),
    )
    .await;
    Ok(Json(input))
}
