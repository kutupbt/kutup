//! `GET /api/user/security-events`: what changed the caller's sign-in, for
//! Account → Security (`crate::security_events`).

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventsQuery {
    /// At most this many (default 50, at most 100).
    limit: Option<i64>,
    /// The `next` of the previous page.
    cursor: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventView {
    id: Uuid,
    /// `passwordChange`, `recovery`, `rotate`, `adminReset` or
    /// `accountReset`; more kinds will come (show an unknown one generally).
    kind: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    at: time::OffsetDateTime,
    /// Made from the caller's own sign-in.
    this_session: bool,
    /// What made it, as the session list shows a session (none for a
    /// recovery or an administrator's).
    client: Option<String>,
    user_agent: Option<String>,
    /// For a name event: the name it was about (the old one, for a rename).
    #[serde(skip_serializing_if = "Option::is_none")]
    old_name: Option<String>,
    /// For a rename: the new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    new_name: Option<String>,
    /// An administrator's reset of this account.
    by_admin: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventsPage {
    events: Vec<SecurityEventView>,
    /// The cursor for older events; none when there are no more.
    next: Option<Uuid>,
}

/// `GET /api/user/security-events` — the caller's account security events,
/// newest first.
#[utoipa::path(
    get,
    path = "/api/user/security-events",
    tag = "user",
    security(("BearerAuth" = [])),
    params(SecurityEventsQuery),
    responses((status = 200, body = SecurityEventsPage))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<SecurityEventsQuery>,
) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(AppError::bad_request("limit is 1 to 100"));
    }
    // A cursor is one of the caller's own events, as a page handed it out.
    if let Some(cursor) = query.cursor {
        let known: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM account_security_events WHERE id = $1 AND user_id = $2)",
        )
        .bind(cursor)
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
        if !known {
            return Err(AppError::bad_request(
                "unknown cursor: start from the first page",
            ));
        }
    }
    // One more than asked: whether there is a next page.
    let mut events =
        crate::security_events::list(&state.pool, user_id, query.cursor, limit + 1).await?;
    let more = events.len() as i64 > limit;
    events.truncate(limit as usize);
    let own = user.session.session_id;
    let own_root: Uuid = sqlx::query_scalar(
        "SELECT COALESCE(parent_session_id, id) FROM auth_sessions WHERE id = $1",
    )
    .bind(own)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or(own);
    let next = more.then(|| events.last().map(|e| e.id)).flatten();
    let events = events
        .into_iter()
        .map(|e| SecurityEventView {
            id: e.id,
            kind: e.kind,
            at: e.at,
            this_session: e
                .acting_session_id
                .is_some_and(|s| s == own || s == own_root),
            client: e.acting_client,
            user_agent: e.acting_user_agent,
            by_admin: e.by_admin,
            old_name: e.old_name,
            new_name: e.new_name,
        })
        .collect();
    Ok(Json(SecurityEventsPage { events, next }).into_response())
}
