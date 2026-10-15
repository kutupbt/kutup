//! Senders whose remote images always load (docs/plans/mail-parity.md, P5):
//! chosen in the reader's "Load images" question, removed in Settings →
//! General. Only the client reads the list; the server never loads images.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::mail::sender_rules::normalise_for;
use crate::middleware::AuthUser;
use crate::AppState;

/// Senders one account may list.
const MAX_IMAGE_SENDERS: i64 = 1000;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailImageSender {
    pub address: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// `GET /api/mail/image-senders` — senders whose images always load, newest first.
#[utoipa::path(
    get,
    path = "/api/mail/image-senders",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Senders", body = [MailImageSender]))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<MailImageSender>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(String, OffsetDateTime)> = sqlx::query_as(
        "SELECT address, created_at FROM mail_image_senders WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(address, created_at)| MailImageSender {
                address,
                created_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailImageSenderAddress {
    pub address: String,
}

/// The lowercase address, or 400: one sender, not a domain.
fn address(state: &AppState, value: &str) -> AppResult<String> {
    normalise_for(&state.config.chat_server_name, value)
        .filter(|a| a.contains('@'))
        .ok_or_else(|| AppError::bad_request("not an address"))
}

/// `POST /api/mail/image-senders` — this sender's images always load.
#[utoipa::path(
    post,
    path = "/api/mail/image-senders",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = MailImageSenderAddress,
    responses(
        (status = 204, description = "Listed"),
        (status = 400, description = "Not an address, or the list is full"),
    )
)]
pub async fn add(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<MailImageSenderAddress>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address = address(&state, &request.address)?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mail_image_senders WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    if count >= MAX_IMAGE_SENDERS {
        return Err(AppError::bad_request("1000 senders at most"));
    }
    sqlx::query(
        "INSERT INTO mail_image_senders (user_id, address) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(&address)
    .execute(&state.pool)
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/mail/image-senders/delete` — images from this sender are asked for again.
#[utoipa::path(
    post,
    path = "/api/mail/image-senders/delete",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = MailImageSenderAddress,
    responses((status = 204, description = "Removed"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<MailImageSenderAddress>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address = address(&state, &request.address)?;
    sqlx::query("DELETE FROM mail_image_senders WHERE user_id = $1 AND address = $2")
        .bind(user_id)
        .bind(&address)
        .execute(&state.pool)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
