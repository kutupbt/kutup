//! Mail filters (docs/plans/mail-filters.md, F2): made, ordered, switched
//! on and off, and applied to the mail already there. Matching is in
//! `mail::filters`; it runs on arrival from `insert_message`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::mail::filters::{self, Actions, Condition, Destination, Match};
use crate::mail::headers::Mailbox;
use crate::middleware::AuthUser;
use crate::AppState;

/// Messages one batch of "apply to existing" reads and files.
const RUN_BATCH: i64 = 500;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailFilter {
    pub id: String,
    /// Sealed in the browser; base64.
    pub name: String,
    pub enabled: bool,
    pub position: i32,
    #[serde(rename = "match")]
    pub rule: Match,
    pub conditions: Vec<Condition>,
    pub actions: Actions,
    /// `manual`, or `sender` ("Always move/label sender's emails").
    pub source: String,
}

fn check_sealed(name: &str) -> AppResult<()> {
    let bytes = STANDARD
        .decode(name)
        .map_err(|_| AppError::bad_request("name is not base64"))?;
    kutup_crypto::mail_names::inspect_name(&bytes)
        .map_err(|_| AppError::bad_request("name is not a sealed mail name"))
}

/// The folder and labels a filter names are the account's own.
async fn check_places(state: &AppState, user_id: Uuid, actions: &Actions) -> AppResult<()> {
    if let Some(Destination::Custom(folder)) = actions.destination() {
        let mine: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM mail_folders WHERE user_id = $1 AND id = $2)",
        )
        .bind(user_id)
        .bind(folder)
        .fetch_one(&state.pool)
        .await?;
        if !mine {
            return Err(AppError::bad_request("no such folder"));
        }
    }
    if !actions.labels.is_empty() {
        let mut wanted = actions.labels.clone();
        wanted.sort();
        wanted.dedup();
        let found: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mail_labels WHERE user_id = $1 AND id = ANY($2)",
        )
        .bind(user_id)
        .bind(&wanted)
        .fetch_one(&state.pool)
        .await?;
        if found != wanted.len() as i64 {
            return Err(AppError::bad_request("no such label"));
        }
    }
    Ok(())
}

type FilterRow = (
    Uuid,
    String,
    bool,
    i32,
    String,
    serde_json::Value,
    serde_json::Value,
    String,
);

/// `GET /api/mail/filters` — the account's filters, in order.
#[utoipa::path(
    get,
    path = "/api/mail/filters",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Filters", body = [MailFilter]))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<MailFilter>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<FilterRow> = sqlx::query_as(
        "SELECT id, name_sealed, enabled, position, match, conditions, actions, source
           FROM mail_filters WHERE user_id = $1 ORDER BY position, created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .filter_map(
                |(id, name, enabled, position, rule, conditions, actions, source)| {
                    Some(MailFilter {
                        id: id.to_string(),
                        name,
                        enabled,
                        position,
                        rule: if rule == "any" {
                            Match::Any
                        } else {
                            Match::All
                        },
                        conditions: serde_json::from_value(conditions).ok()?,
                        actions: serde_json::from_value(actions).ok()?,
                        source,
                    })
                },
            )
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMailFilter {
    /// A new UUID, chosen by the browser: the sealed name is bound to it.
    pub id: String,
    pub name: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(rename = "match")]
    pub rule: Match,
    pub conditions: Vec<Condition>,
    pub actions: Actions,
    /// `manual` (the default) or `sender`.
    pub source: Option<String>,
}

fn enabled() -> bool {
    true
}

async fn check_enabled_limit(
    state: &AppState,
    user_id: Uuid,
    except: Option<Uuid>,
) -> AppResult<()> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_filters WHERE user_id = $1 AND enabled AND id IS DISTINCT FROM $2",
    )
    .bind(user_id)
    .bind(except)
    .fetch_one(&state.pool)
    .await?;
    if count >= state.config.mail_filters_per_account {
        return Err(AppError::conflict(
            "this account has its most filters switched on",
        ));
    }
    Ok(())
}

/// `POST /api/mail/filters` — a new filter, last in order.
#[utoipa::path(
    post,
    path = "/api/mail/filters",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = CreateMailFilter,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "No condition or action, a bad value, a folder or label not yours"),
        (status = 409, description = "The id is taken, or the account has its most filters on"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateMailFilter>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&request.id).map_err(|_| AppError::bad_request("not an id"))?;
    check_sealed(&request.name)?;
    filters::check(&request.conditions, &request.actions).map_err(AppError::bad_request)?;
    check_places(&state, user_id, &request.actions).await?;
    let source = request.source.as_deref().unwrap_or("manual");
    if !["manual", "sender"].contains(&source) {
        return Err(AppError::bad_request("unknown source"));
    }
    if request.enabled {
        check_enabled_limit(&state, user_id, None).await?;
    }
    let inserted = sqlx::query(
        "INSERT INTO mail_filters (id, user_id, name_sealed, enabled, position, match, conditions, actions, source)
         SELECT $1, $2, $3, $4, COALESCE(MAX(position) + 1, 0), $5, $6, $7, $8
           FROM mail_filters WHERE user_id = $2
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(user_id)
    .bind(&request.name)
    .bind(request.enabled)
    .bind(if request.rule == Match::Any { "any" } else { "all" })
    .bind(serde_json::to_value(&request.conditions).expect("serialisable"))
    .bind(serde_json::to_value(&request.actions).expect("serialisable"))
    .bind(source)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::conflict("that id is taken"));
    }
    Ok(StatusCode::CREATED)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailFilter {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(rename = "match")]
    pub rule: Option<Match>,
    pub conditions: Option<Vec<Condition>>,
    pub actions: Option<Actions>,
}

/// `PATCH /api/mail/filters/{id}` — rename, switch on or off, change what it matches or does.
#[utoipa::path(
    patch,
    path = "/api/mail/filters/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Filter id")),
    request_body = UpdateMailFilter,
    responses(
        (status = 204, description = "Saved"),
        (status = 400, description = "No condition or action, a bad value"),
        (status = 404, description = "No such filter"),
        (status = 409, description = "The account has its most filters on"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateMailFilter>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such filter"))?;
    let current: Option<(serde_json::Value, serde_json::Value)> = sqlx::query_as(
        "SELECT conditions, actions FROM mail_filters WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let (conditions, actions) = current.ok_or_else(|| AppError::not_found("no such filter"))?;
    if let Some(name) = &request.name {
        check_sealed(name)?;
    }
    let conditions: Vec<Condition> = match request.conditions {
        Some(conditions) => conditions,
        None => serde_json::from_value(conditions).unwrap_or_default(),
    };
    let actions: Actions = match request.actions {
        Some(actions) => {
            check_places(&state, user_id, &actions).await?;
            actions
        }
        None => serde_json::from_value(actions).unwrap_or_default(),
    };
    filters::check(&conditions, &actions).map_err(AppError::bad_request)?;
    if request.enabled == Some(true) {
        check_enabled_limit(&state, user_id, Some(id)).await?;
    }
    sqlx::query(
        "UPDATE mail_filters SET
             name_sealed = COALESCE($3, name_sealed),
             enabled = COALESCE($4, enabled),
             match = COALESCE($5, match),
             conditions = $6,
             actions = $7
          WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .bind(request.name.as_deref())
    .bind(request.enabled)
    .bind(
        request
            .rule
            .map(|rule| if rule == Match::Any { "any" } else { "all" }),
    )
    .bind(serde_json::to_value(&conditions).expect("serialisable"))
    .bind(serde_json::to_value(&actions).expect("serialisable"))
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/mail/filters/{id}`.
#[utoipa::path(
    delete,
    path = "/api/mail/filters/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Filter id")),
    responses((status = 204, description = "Deleted"), (status = 404, description = "No such filter"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such filter"))?;
    let removed = sqlx::query("DELETE FROM mail_filters WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::not_found("no such filter"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrderMailFilters {
    /// Every filter of the account, in the new order (first runs first).
    pub ids: Vec<String>,
}

/// `PUT /api/mail/filters/order` — the order filters run in (Proton: drag to reorder).
#[utoipa::path(
    put,
    path = "/api/mail/filters/order",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = OrderMailFilters,
    responses((status = 204, description = "Saved"), (status = 400, description = "Not the account's filters"))
)]
pub async fn order(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<OrderMailFilters>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let ids: Vec<Uuid> = request
        .ids
        .iter()
        .map(|id| Uuid::parse_str(id).map_err(|_| AppError::bad_request("not an id")))
        .collect::<AppResult<_>>()?;
    let updated = sqlx::query(
        "UPDATE mail_filters f SET position = o.position
           FROM UNNEST($2::uuid[]) WITH ORDINALITY AS o(id, position)
          WHERE f.user_id = $1 AND f.id = o.id",
    )
    .bind(user_id)
    .bind(&ids)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if updated != ids.len() as u64 {
        return Err(AppError::bad_request("not the account's filters"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyMailFilters {
    /// Filters to run; all switched-on filters when left out.
    pub ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailFilterRun {
    pub id: String,
    pub total: i32,
    pub done: i32,
    /// Messages a filter changed.
    pub changed: i32,
    pub finished: bool,
    pub failed: bool,
}

/// `POST /api/mail/filters/apply` — runs filters over the mail already there
/// (outside Drafts, Spam and Trash), in the background; nothing is sent.
#[utoipa::path(
    post,
    path = "/api/mail/filters/apply",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = ApplyMailFilters,
    responses(
        (status = 202, description = "Started", body = MailFilterRun),
        (status = 409, description = "A run is already going"),
    )
)]
pub async fn apply(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<ApplyMailFilters>,
) -> AppResult<(StatusCode, Json<MailFilterRun>)> {
    let user_id = trusted_uuid(&user.user_id)?;
    let ids: Option<Vec<Uuid>> = request
        .ids
        .map(|ids| {
            ids.iter()
                .map(|id| Uuid::parse_str(id).map_err(|_| AppError::bad_request("not an id")))
                .collect::<AppResult<_>>()
        })
        .transpose()?;
    // A run that a restart cut short is over.
    sqlx::query(
        "UPDATE mail_filter_runs SET finished_at = now(), failed = true
          WHERE user_id = $1 AND finished_at IS NULL AND started_at < now() - interval '1 hour'",
    )
    .bind(user_id)
    .execute(&state.pool)
    .await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_messages WHERE user_id = $1 AND folder NOT IN ('drafts', 'spam', 'trash')",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let run: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO mail_filter_runs (user_id, filter_ids, total) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) WHERE finished_at IS NULL DO NOTHING RETURNING id",
    )
    .bind(user_id)
    .bind(ids.clone().unwrap_or_default())
    .bind(total as i32)
    .fetch_optional(&state.pool)
    .await?;
    let run = run.ok_or_else(|| AppError::conflict("filters are already being applied"))?;
    let task_state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = run_filters(&task_state, user_id, run, ids.as_deref()).await {
            tracing::warn!(error = %error, "mail: applying filters failed");
            let _ = sqlx::query(
                "UPDATE mail_filter_runs SET finished_at = now(), failed = true WHERE id = $1",
            )
            .bind(run)
            .execute(&task_state.pool)
            .await;
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(MailFilterRun {
            id: run.to_string(),
            total: total as i32,
            done: 0,
            changed: 0,
            finished: false,
            failed: false,
        }),
    ))
}

type RunRow = (
    Uuid,
    String,
    String,
    String,
    serde_json::Value,
    serde_json::Value,
    String,
    String,
    i32,
);

async fn run_filters(
    state: &AppState,
    user_id: Uuid,
    run: Uuid,
    only: Option<&[Uuid]>,
) -> anyhow::Result<()> {
    let mut after = Uuid::nil();
    let (mut done, mut changed) = (0i32, 0i32);
    loop {
        let mut tx = state.pool.begin().await?;
        let loaded = filters::load(&mut tx, user_id, only).await?;
        let rows: Vec<RunRow> = sqlx::query_as(
            "SELECT m.id, m.direction, m.from_address, m.from_name, m.to_list, m.cc_list, m.subject,
                    COALESCE(a.address, ''), m.attachment_count
               FROM mail_messages m LEFT JOIN mail_addresses a ON a.id = m.address_id
              WHERE m.user_id = $1 AND m.folder NOT IN ('drafts', 'spam', 'trash') AND m.id > $2
              ORDER BY m.id LIMIT $3",
        )
        .bind(user_id)
        .bind(after)
        .bind(RUN_BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() || loaded.is_empty() {
            tx.commit().await?;
            break;
        }
        for (id, direction, from_address, from_name, to, cc, subject, address, attachments) in &rows
        {
            let from = (!from_address.is_empty()).then(|| Mailbox {
                address: from_address.clone(),
                name: from_name.clone(),
            });
            let to: Vec<Mailbox> = serde_json::from_value(to.clone()).unwrap_or_default();
            let cc: Vec<Mailbox> = serde_json::from_value(cc.clone()).unwrap_or_default();
            let message = filters::Subject {
                from: from.as_ref(),
                to: &to,
                cc: &cc,
                address,
                subject,
                attachments: *attachments,
            };
            let outcome = filters::outcome(&loaded, &message);
            if filters::apply(&mut tx, user_id, *id, direction, &outcome).await? {
                changed += 1;
            }
        }
        done += rows.len() as i32;
        after = rows.last().map(|row| row.0).unwrap_or(after);
        sqlx::query("UPDATE mail_filter_runs SET done = $2, changed = $3 WHERE id = $1")
            .bind(run)
            .bind(done)
            .bind(changed)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    sqlx::query("UPDATE mail_filter_runs SET finished_at = now(), done = GREATEST(done, total) WHERE id = $1")
        .bind(run)
        .execute(&state.pool)
        .await?;
    Ok(())
}

/// `GET /api/mail/filters/runs/{id}` — how far "apply to existing" got.
#[utoipa::path(
    get,
    path = "/api/mail/filters/runs/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Run id")),
    responses((status = 200, description = "Progress", body = MailFilterRun), (status = 404, description = "No such run"))
)]
pub async fn run_status(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailFilterRun>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such run"))?;
    let row: Option<(i32, i32, i32, Option<OffsetDateTime>, bool)> = sqlx::query_as(
        "SELECT total, done, changed, finished_at, failed FROM mail_filter_runs WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let (total, done, changed, finished, failed) =
        row.ok_or_else(|| AppError::not_found("no such run"))?;
    Ok(Json(MailFilterRun {
        id: id.to_string(),
        total,
        done,
        changed,
        finished: finished.is_some(),
        failed,
    }))
}
