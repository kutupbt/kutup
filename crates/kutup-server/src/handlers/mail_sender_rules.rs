//! Block, spam and allow lists (docs/plans/mail-filters.md, F3): Proton's
//! "incoming defaults", by address or domain. Applied in `insert_message`
//! (`mail::sender_rules`).

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::mail::sender_rules::{normalise_for, Kind};
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailSenderRule {
    pub id: String,
    /// A lowercase address, or a domain.
    pub pattern: String,
    /// `spam`, `block` or `allow`.
    pub kind: String,
}

fn kind(value: &str) -> AppResult<Kind> {
    Kind::parse(value).ok_or_else(|| AppError::bad_request("kind is spam, block or allow"))
}

/// `GET /api/mail/sender-rules` — the account's block, spam and allow entries.
#[utoipa::path(
    get,
    path = "/api/mail/sender-rules",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Entries, newest first", body = [MailSenderRule]))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<MailSenderRule>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, pattern, kind FROM mail_sender_rules WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, pattern, kind)| MailSenderRule {
                id: id.to_string(),
                pattern,
                kind,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetMailSenderRules {
    /// Addresses or domains (`@example.com` is the domain), up to 100.
    pub patterns: Vec<String>,
    pub kind: String,
}

/// `POST /api/mail/sender-rules` — puts addresses or domains on a list; one
/// already on another list moves to this one (Proton's overwrite).
#[utoipa::path(
    post,
    path = "/api/mail/sender-rules",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = SetMailSenderRules,
    responses(
        (status = 200, description = "The entries as saved", body = [MailSenderRule]),
        (status = 400, description = "Not an address or domain, or an unknown kind"),
        (status = 409, description = "The account has its most entries"),
    )
)]
pub async fn set(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<SetMailSenderRules>,
) -> AppResult<Json<Vec<MailSenderRule>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let kind = kind(&request.kind)?;
    if request.patterns.is_empty() || request.patterns.len() > 100 {
        return Err(AppError::bad_request("1 to 100 addresses or domains"));
    }
    let mut patterns: Vec<String> = request
        .patterns
        .iter()
        .map(|p| {
            normalise_for(&state.config.chat_server_name, p)
                .ok_or_else(|| AppError::bad_request(format!("not an address or domain: {p}")))
        })
        .collect::<AppResult<_>>()?;
    patterns.sort();
    patterns.dedup();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_sender_rules WHERE user_id = $1 AND pattern <> ALL($2)",
    )
    .bind(user_id)
    .bind(&patterns)
    .fetch_one(&mut *tx)
    .await?;
    if count + patterns.len() as i64 > state.config.mail_sender_rules_per_account {
        return Err(AppError::conflict(
            "this account has its most block and allow entries",
        ));
    }
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "INSERT INTO mail_sender_rules (user_id, pattern, kind)
         SELECT $1, p, $3 FROM UNNEST($2::text[]) p
         ON CONFLICT (user_id, pattern) DO UPDATE SET kind = EXCLUDED.kind
         RETURNING id, pattern, kind",
    )
    .bind(user_id)
    .bind(&patterns)
    .bind(kind.as_str())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, pattern, kind)| MailSenderRule {
                id: id.to_string(),
                pattern,
                kind,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailSenderRule {
    pub kind: String,
}

/// `PATCH /api/mail/sender-rules/{id}` — moves an entry to another list.
#[utoipa::path(
    patch,
    path = "/api/mail/sender-rules/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Entry id")),
    request_body = UpdateMailSenderRule,
    responses((status = 204, description = "Saved"), (status = 404, description = "No such entry"))
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateMailSenderRule>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("no such entry"))?;
    let kind = kind(&request.kind)?;
    let updated =
        sqlx::query("UPDATE mail_sender_rules SET kind = $3 WHERE user_id = $1 AND id = $2")
            .bind(user_id)
            .bind(id)
            .bind(kind.as_str())
            .execute(&state.pool)
            .await?
            .rows_affected();
    if updated == 0 {
        return Err(AppError::not_found("no such entry"));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteMailSenderRules {
    pub ids: Vec<String>,
}

/// `POST /api/mail/sender-rules/delete` — removes entries ("Unblock").
#[utoipa::path(
    post,
    path = "/api/mail/sender-rules/delete",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = DeleteMailSenderRules,
    responses((status = 204, description = "Removed"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<DeleteMailSenderRules>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let ids: Vec<Uuid> = request
        .ids
        .iter()
        .take(1000)
        .map(|id| Uuid::parse_str(id).map_err(|_| AppError::bad_request("not an id")))
        .collect::<AppResult<_>>()?;
    sqlx::query("DELETE FROM mail_sender_rules WHERE user_id = $1 AND id = ANY($2)")
        .bind(user_id)
        .bind(&ids)
        .execute(&state.pool)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
