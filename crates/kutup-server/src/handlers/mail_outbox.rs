//! Undo send's endpoints (docs/plans/mail-parity.md, P4): how a held send
//! went, and taking it back while it waits (`mail::outbox`).

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailOutboxStatus {
    /// pending, sending, sent, cancelled or failed.
    pub state: String,
    /// Sent: `{ recipients }`, as a send answers; failed: the send's error
    /// body (`status`, `error`, `code`…).
    pub result: Option<serde_json::Value>,
}

fn id_of(value: &str) -> AppResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| AppError::not_found("not found"))
}

/// `GET /api/mail/outbox/{id}` — how a held send went.
#[utoipa::path(
    get,
    path = "/api/mail/outbox/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "The held send")),
    responses(
        (status = 200, description = "Its state", body = MailOutboxStatus),
        (status = 404, description = "Not a send of yours"),
    )
)]
pub async fn status(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailOutboxStatus>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let row: Option<(String, Option<serde_json::Value>)> =
        sqlx::query_as("SELECT state, result FROM mail_outbox WHERE id = $1 AND user_id = $2")
            .bind(id_of(&id)?)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let (state, result) = row.ok_or_else(|| AppError::not_found("not found"))?;
    Ok(Json(MailOutboxStatus { state, result }))
}

/// `POST /api/mail/outbox/{id}/cancel` — Undo: the send does not go, its
/// draft stays. 409 once it has gone out.
#[utoipa::path(
    post,
    path = "/api/mail/outbox/{id}/cancel",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "The held send")),
    responses(
        (status = 204, description = "Taken back"),
        (status = 404, description = "Not a send of yours"),
        (status = 409, description = "Already sent"),
    )
)]
pub async fn cancel(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = id_of(&id)?;
    if crate::mail::outbox::cancel(&state, user_id, id).await? {
        return Ok(axum::http::StatusCode::NO_CONTENT);
    }
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_outbox WHERE id = $1 AND user_id = $2)",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    if known {
        Err(AppError::conflict("already sent"))
    } else {
        Err(AppError::not_found("not found"))
    }
}

/// Whether `draft` is waiting in the outbox (it cannot change meanwhile).
pub(crate) async fn draft_held(state: &AppState, draft: Uuid) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_outbox WHERE draft_id = $1 AND state IN ('pending', 'sending'))",
    )
    .bind(draft)
    .fetch_one(&state.pool)
    .await?)
}
