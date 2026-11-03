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
    /// When Stalwart's objects outside Kutup's custom domains (`MAIL_DOMAIN`'s
    /// own) last changed, as the reconcile saw it: something to look into.
    #[serde(with = "time::serde::rfc3339::option")]
    pub stalwart_drift_at: Option<OffsetDateTime>,
    /// Stalwart's management key and MAIL_DKIM_KEYS are set: custom domains
    /// can work here at all.
    pub configured: bool,
    /// Every setting by its key (`mail_domains.*`), as in effect.
    pub settings: BTreeMap<String, String>,
    /// Each numeric setting's range by its key: what the page offers.
    pub ranges: BTreeMap<String, SettingRange>,
    /// The server's SPF record for customers to include.
    pub spf: DkimKeyView,
    pub dkim_keys: Vec<DkimKeyView>,
    pub domains: Vec<AdminDomain>,
}

/// A whole-number setting's range, both ends included.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
pub struct SettingRange {
    pub min: i64,
    pub max: i64,
}

/// Every numeric setting's range, by key (the server's `KEYS`).
fn ranges() -> BTreeMap<String, SettingRange> {
    KEYS.iter()
        .map(|(key, min, max)| {
            (
                (*key).to_owned(),
                SettingRange {
                    min: *min,
                    max: *max,
                },
            )
        })
        .collect()
}

/// One setting's range (a key of `KEYS`).
fn range_of(key: &str) -> SettingRange {
    let (_, min, max) = KEYS
        .iter()
        .find(|(k, _, _)| *k == key)
        .expect("a key of KEYS");
    SettingRange {
        min: *min,
        max: *max,
    }
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
        settings.domains_per_organization,
        settings.addresses_per_account,
        settings.domains_on_server,
        settings.adds_per_day,
        settings.pending_days,
        settings.catch_all_per_day,
        settings.grace_warn_days,
        settings.grace_stopped_hours,
        i64::from(settings.catch_all),
        settings.refreshes_at_once,
        settings.check_timeout_seconds,
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
        "SELECT d.id, d.name, o.name AS owner, d.state, d.verify_state,
                d.mx_state, d.spf_state, d.dkim_state, d.dmarc_state,
                d.approved_at IS NOT NULL AS approved, d.stopped_at IS NOT NULL AS stopped,
                EXISTS (SELECT 1 FROM mail_domain_blocks b
                         WHERE b.name = d.name OR d.name LIKE '%.' || b.name) AS blocked,
                d.created_at
           FROM mail_domains d JOIN organizations o ON o.id = d.organization_id
          WHERE d.removed_at IS NULL
          ORDER BY d.name",
    )
    .fetch_all(&state.pool)
    .await?;
    let untagged_changed_at: Option<i64> =
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key = $1")
            .bind(crate::mail::domains::sweep::UNTAGGED_CHANGED_AT)
            .fetch_optional(&state.pool)
            .await?
            .and_then(|value| value.parse().ok());
    Ok(Json(AdminDomains {
        configured: crate::mail::domains::sweep::configured(&state),
        stalwart_drift_at: untagged_changed_at
            .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok()),
        settings: effective(&settings),
        ranges: ranges(),
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
    let (organization, name) = store::deactivate(&state.pool, id, admin_id).await?;
    crate::mail::notice::domain_lost_to_owners(
        &state,
        organization,
        &name,
        crate::mail::notice::DomainLost::Deactivated,
    )
    .await;
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

/// A name an administrator blocked.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainBlock {
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub blocked_at: OffsetDateTime,
    /// The administrator who blocked it, while their account exists.
    pub blocked_by: Option<String>,
}

/// `GET /api/admin/mail/domains/blocks` — the blocked names (each covers
/// the names under it), whether or not a domain row is left for them.
#[utoipa::path(
    get,
    path = "/api/admin/mail/domains/blocks",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, body = Vec<DomainBlock>))
)]
pub async fn blocks(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<Vec<DomainBlock>>> {
    Ok(Json(
        store::blocks(&state.pool)
            .await?
            .into_iter()
            .map(|(name, blocked_at, blocked_by)| DomainBlock {
                name,
                blocked_at,
                blocked_by,
            })
            .collect(),
    ))
}

/// `DELETE /api/admin/mail/domains/blocks/{name}` — lifts a block: the name
/// and those under it may be proven again.
#[utoipa::path(
    delete,
    path = "/api/admin/mail/domains/blocks/{name}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("name" = String, Path)),
    responses((status = 204), (status = 404))
)]
pub async fn unblock(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(name): Path<String>,
) -> AppResult<StatusCode> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    store::unblock(&state.pool, &name).await?;
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

/// One account's custom-domain limits over the site's; `null` keeps the
/// site's. The domain count and the catch-all are its organization's
/// (docs/plans/organizations.md §7), the address count its own.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainOverrides {
    pub max_domains: Option<i32>,
    pub max_addresses: Option<i32>,
    pub catch_all: Option<bool>,
}

/// The organization an account's domain limits belong to.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRef {
    pub id: String,
    pub name: String,
    /// The account's role in it.
    pub role: String,
}

/// An account's limits as the page shows them, with each one's range (the
/// site settings they override) and the organization the domain ones
/// belong to (none until the account holds a domain or joins one).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainOverridesView {
    #[serde(flatten)]
    pub overrides: DomainOverrides,
    pub max_domains_range: SettingRange,
    pub max_addresses_range: SettingRange,
    pub organization: Option<OrganizationRef>,
}

const DOMAINS_KEY: &str = "mail_domains.per_organization";
const CATCH_ALL_KEY: &str = "mail_domains.catch_all";
const ADDRESSES_KEY: &str = "mail_domains.addresses_per_account";

/// The account's organization (enabled or invited member) with its role.
async fn organization_of(
    pool: &sqlx::PgPool,
    account: Uuid,
) -> AppResult<Option<(Uuid, String, String)>> {
    Ok(sqlx::query_as(
        "SELECT o.id, o.name, m.role FROM organization_members m
           JOIN organizations o ON o.id = m.organization_id
          WHERE m.account_id = $1 AND m.state IN (1, 2)",
    )
    .bind(account)
    .fetch_optional(pool)
    .await?)
}

/// `GET /api/admin/users/{id}/mail-domains`
#[utoipa::path(
    get,
    path = "/api/admin/users/{id}/mail-domains",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 200, body = DomainOverridesView))
)]
pub async fn overrides(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Json<DomainOverridesView>> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such user"))?;
    let organization = organization_of(&state.pool, id).await?;
    let max_addresses: Option<i64> = sqlx::query_scalar(
        "SELECT value FROM user_setting_overrides WHERE user_id = $1 AND key = $2",
    )
    .bind(id)
    .bind(ADDRESSES_KEY)
    .fetch_optional(&state.pool)
    .await?;
    let (mut max_domains, mut catch_all) = (None, None);
    if let Some((organization, _, _)) = &organization {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT key, value FROM organization_setting_overrides
              WHERE organization_id = $1 AND key = ANY($2)",
        )
        .bind(organization)
        .bind(&[DOMAINS_KEY, CATCH_ALL_KEY][..])
        .fetch_all(&state.pool)
        .await?;
        for (key, value) in rows {
            if key == DOMAINS_KEY {
                max_domains = i32::try_from(value).ok();
            } else {
                catch_all = Some(value == 1);
            }
        }
    }
    Ok(Json(DomainOverridesView {
        overrides: DomainOverrides {
            max_domains,
            max_addresses: max_addresses.and_then(|v| i32::try_from(v).ok()),
            catch_all,
        },
        max_domains_range: range_of(DOMAINS_KEY),
        max_addresses_range: range_of(ADDRESSES_KEY),
        organization: organization.map(|(id, name, role)| OrganizationRef {
            id: id.to_string(),
            name,
            role,
        }),
    }))
}

/// `PUT /api/admin/users/{id}/mail-domains`: the address count on the
/// account, the domain count and the catch-all on its organization; an
/// account with none yet gets its organization of one, so an administrator
/// can limit (or block, with 0) custom domains before the first one.
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
    let (domains, addresses) = (range_of(DOMAINS_KEY), range_of(ADDRESSES_KEY));
    let outside = |value: Option<i32>, range: SettingRange| {
        value.is_some_and(|n| !(range.min..=range.max).contains(&i64::from(n)))
    };
    if outside(input.max_domains, domains) || outside(input.max_addresses, addresses) {
        return Err(AppError::bad_request(format!(
            "maxDomains is {} to {}, maxAddresses {} to {}",
            domains.min, domains.max, addresses.min, addresses.max
        )));
    }
    let mut tx = state.pool.begin().await?;
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(AppError::not_found("no such user"));
    }
    // An organization-wide limit needs the organization: one of one if the
    // account has none yet.
    let organization = if input.max_domains.is_some() || input.catch_all.is_some() {
        Some(crate::organizations::of_account(&mut tx, id).await?)
    } else {
        organization_of(&state.pool, id).await?.map(|(id, _, _)| id)
    };
    set_or_clear(
        &mut tx,
        "user_setting_overrides",
        "user_id",
        id,
        ADDRESSES_KEY,
        input.max_addresses.map(i64::from),
    )
    .await?;
    if let Some(organization) = organization {
        set_or_clear(
            &mut tx,
            "organization_setting_overrides",
            "organization_id",
            organization,
            DOMAINS_KEY,
            input.max_domains.map(i64::from),
        )
        .await?;
        set_or_clear(
            &mut tx,
            "organization_setting_overrides",
            "organization_id",
            organization,
            CATCH_ALL_KEY,
            input.catch_all.map(i64::from),
        )
        .await?;
    }
    tx.commit().await?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail.domains.overrides",
        Some(id),
        json!({ "limits": input, "organization": organization.map(|o| o.to_string()) }),
    )
    .await;
    Ok(Json(input))
}

/// Sets `key` to `value` in `table` for `owner`, or removes it (`None`: the
/// site's again). `table` and `column` are this module's constants.
async fn set_or_clear(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &'static str,
    column: &'static str,
    owner: Uuid,
    key: &str,
    value: Option<i64>,
) -> AppResult<()> {
    match value {
        Some(value) => {
            sqlx::query(&format!(
                "INSERT INTO {table} ({column}, key, value) VALUES ($1, $2, $3)
                 ON CONFLICT ({column}, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()"
            ))
            .bind(owner)
            .bind(key)
            .bind(value)
            .execute(&mut **tx)
            .await?;
        }
        None => {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE {column} = $1 AND key = $2"
            ))
            .bind(owner)
            .bind(key)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}
