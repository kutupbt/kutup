//! Custom mail domains' API (docs/plans/mail-custom-domains.md), Proton's
//! shape under `/api/mail/domains`: add a domain, read it with its records
//! to publish and their states (`?refresh=1` checks DNS now, Proton's
//! "Refresh status"), set its catch-all, remove it. Answers 404 where the
//! server has no Mail.

use std::sync::OnceLock;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::mail::domains::check::Server;
use crate::mail::domains::dns::DnsResolver;
use crate::mail::domains::name;
use crate::mail::domains::records::{dkim_target, DKIM_SELECTORS};
use crate::mail::domains::settings::{Mode, Settings};
use crate::mail::domains::store::{self, Row};
use crate::middleware::AuthUser;
use crate::ratelimit::MAIL_DOMAIN_CHECKS;
use crate::AppState;

/// One record the owner publishes.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    /// `TXT`, `MX` or `CNAME`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Relative to the domain: `@`, `_dmarc`, `kutup1._domainkey`.
    pub host: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainRecords {
    pub verify: DnsRecord,
    pub mx: Vec<DnsRecord>,
    pub spf: DnsRecord,
    pub dkim: Vec<DnsRecord>,
    pub dmarc: DnsRecord,
}

/// A domain as its owner sees it. The states are Proton's numbers
/// (`DOMAIN_STATE`, `VERIFY_STATE`, `MX_STATE`, `SPF_STATE`, `DKIM_STATE`,
/// `DMARC_STATE`).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailDomain {
    pub id: String,
    pub name: String,
    pub state: i16,
    pub verify_state: i16,
    pub mx_state: i16,
    pub spf_state: i16,
    pub dkim_state: i16,
    pub dmarc_state: i16,
    /// Verified, waiting for an administrator (the `approve` mode).
    pub awaiting_approval: bool,
    /// Sending and delivery stopped: its TXT and MX are both gone.
    pub stopped: bool,
    pub catch_all_address_id: Option<String>,
    pub address_count: i64,
    pub records: DomainRecords,
    #[serde(with = "time::serde::rfc3339::option")]
    pub checked_at: Option<OffsetDateTime>,
    /// When a domain in `warn` stops, unless its record returns.
    #[serde(with = "time::serde::rfc3339::option")]
    pub warned_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailDomains {
    pub domains: Vec<MailDomain>,
    /// "{used} / {max} domains used".
    pub used: i64,
    pub max: i64,
    /// `everyone`, `approve` or `off`.
    pub mode: &'static str,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddDomain {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Refresh {
    #[serde(default)]
    pub refresh: Option<u8>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatchAll {
    pub address_id: Option<String>,
}

/// Mail must be on (a mail host), or there are no domains to have.
fn enabled(state: &AppState) -> AppResult<()> {
    if state.config.mail_hostname.is_empty() {
        Err(AppError::not_found("not found"))
    } else {
        Ok(())
    }
}

pub fn server(state: &AppState) -> Server {
    Server {
        name: state.config.chat_server_name.clone(),
        mx_host: state.config.mail_hostname.clone(),
        backup_mx: state.config.mail_backup_mx.clone(),
    }
}

/// The resolver the checks use, made once.
pub fn resolver(state: &AppState) -> AppResult<&'static DnsResolver> {
    static RESOLVER: OnceLock<DnsResolver> = OnceLock::new();
    if let Some(resolver) = RESOLVER.get() {
        return Ok(resolver);
    }
    let made = DnsResolver::new(state.config.mail_dns_resolver)
        .map_err(|e| AppError::internal(format!("DNS resolver: {e}")))?;
    Ok(RESOLVER.get_or_init(|| made))
}

fn records(row: &Row, server: &Server) -> DomainRecords {
    let txt = |host: &str, value: String| DnsRecord {
        kind: "TXT",
        host: host.into(),
        value,
        priority: None,
    };
    DomainRecords {
        verify: txt("@", row.verify_code.clone()),
        mx: vec![DnsRecord {
            kind: "MX",
            host: "@".into(),
            value: server.mx_host.clone(),
            priority: Some(10),
        }],
        spf: txt("@", format!("v=spf1 include:{} ~all", server.spf_include())),
        dkim: DKIM_SELECTORS
            .iter()
            .map(|selector| DnsRecord {
                kind: "CNAME",
                host: format!("{selector}._domainkey"),
                value: format!("{}.", dkim_target(&row.id, selector, &server.name)),
                priority: None,
            })
            .collect(),
        dmarc: txt("_dmarc", "v=DMARC1; p=quarantine".into()),
    }
}

async fn view(state: &AppState, row: &Row, settings: &Settings) -> AppResult<MailDomain> {
    let address_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mail_addresses WHERE domain_id = $1 AND state <> 'freed'",
    )
    .bind(row.id)
    .fetch_one(&state.pool)
    .await?;
    let held = matches!(row.state, 1 | 2);
    Ok(MailDomain {
        id: row.id.to_string(),
        name: row.name.clone(),
        state: row.state,
        verify_state: row.verify_state,
        mx_state: row.mx_state,
        spf_state: row.spf_state,
        dkim_state: row.dkim_state,
        dmarc_state: row.dmarc_state,
        awaiting_approval: held
            && settings.mode == Mode::AdminsApprove
            && row.approved_at.is_none(),
        stopped: row.stopped_at.is_some(),
        catch_all_address_id: row.catch_all_address_id.map(|id| id.to_string()),
        address_count,
        records: records(row, &server(state)),
        checked_at: row.checked_at,
        warned_at: row.warned_at,
    })
}

/// `GET /api/mail/domains` — the account's domains and its limit.
#[utoipa::path(
    get,
    path = "/api/mail/domains",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, body = MailDomains), (status = 404, description = "No Mail here"))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<MailDomains>> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let settings = Settings::load(&state.pool)
        .await?
        .for_user(&state.pool, user_id)
        .await?;
    let rows = store::list(&state.pool, user_id).await?;
    let mut domains = Vec::with_capacity(rows.len());
    for row in &rows {
        domains.push(view(&state, row, &settings).await?);
    }
    Ok(Json(MailDomains {
        used: rows.len() as i64,
        max: settings.domains_per_account,
        mode: settings.mode.as_str(),
        domains,
    }))
}

/// `POST /api/mail/domains` — adds a domain (or gives back one the account
/// removed, with its code). Nothing flows until it is verified.
#[utoipa::path(
    post,
    path = "/api/mail/domains",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = AddDomain,
    responses(
        (status = 201, body = MailDomain),
        (status = 400, description = "invalidDomain, domainIsAddress, serverDomain or publicSuffix"),
        (status = 403, description = "customDomainsOff"),
        (status = 409, description = "domainLimit, domainDailyLimit or serverDomainLimit"),
    )
)]
pub async fn add(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<AddDomain>,
) -> AppResult<(StatusCode, Json<MailDomain>)> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let name = name::normalize(&input.name, &state.config.chat_server_name)
        .map_err(|refusal| AppError::bad_request(refusal.code()))?;
    let settings = Settings::load(&state.pool)
        .await?
        .for_user(&state.pool, user_id)
        .await?;
    let row = match store::add(&state.pool, user_id, &name, &settings).await? {
        Ok(row) => row,
        Err(refusal @ store::AddRefusal::Off) => return Err(AppError::forbidden(refusal.code())),
        Err(refusal) => return Err(AppError::conflict(refusal.code())),
    };
    Ok((
        StatusCode::CREATED,
        Json(view(&state, &row, &settings).await?),
    ))
}

/// `GET /api/mail/domains/{id}` — one domain; `?refresh=1` checks its DNS
/// now (uncached; 30 an hour per account).
#[utoipa::path(
    get,
    path = "/api/mail/domains/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path), ("refresh" = Option<u8>, Query)),
    responses((status = 200, body = MailDomain), (status = 404), (status = 429))
)]
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<Refresh>,
) -> AppResult<Json<MailDomain>> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such domain"))?;
    let settings = Settings::load(&state.pool)
        .await?
        .for_user(&state.pool, user_id)
        .await?;
    let mut row = store::get(&state.pool, user_id, id).await?;
    if query.refresh == Some(1) {
        if !MAIL_DOMAIN_CHECKS.allow(&user_id.to_string()) {
            return Err(AppError::too_many_requests(
                "too many checks; try again later",
            ));
        }
        let (checked, _) = store::check_and_save(
            &state.pool,
            resolver(&state)?,
            &server(&state),
            &settings,
            &row,
        )
        .await?;
        row = checked;
    }
    Ok(Json(view(&state, &row, &settings).await?))
}

/// `DELETE /api/mail/domains/{id}` — removes the domain; its addresses are
/// freed (Proton: "all the addresses associated with it will be disabled").
#[utoipa::path(
    delete,
    path = "/api/mail/domains/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 204), (status = 404))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such domain"))?;
    store::remove(&state.pool, user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/mail/domains/{id}/catch-all` — one active address on the
/// domain that takes mail for unknown names on it, or none.
#[utoipa::path(
    put,
    path = "/api/mail/domains/{id}/catch-all",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    request_body = CatchAll,
    responses((status = 204), (status = 400), (status = 403), (status = 404), (status = 409))
)]
pub async fn catch_all(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<CatchAll>,
) -> AppResult<StatusCode> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such domain"))?;
    let address = input
        .address_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| AppError::bad_request("addressId"))?;
    let settings = Settings::load(&state.pool)
        .await?
        .for_user(&state.pool, user_id)
        .await?;
    store::set_catch_all(&state.pool, user_id, id, address, &settings).await?;
    Ok(StatusCode::NO_CONTENT)
}
