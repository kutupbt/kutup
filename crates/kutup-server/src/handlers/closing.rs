//! Closing an account and keeping it (docs/plans/server-personal-data.md, A5).
//!
//! - `POST /api/user/close`: the owner, after a reauth (grant `close`), asks
//!   for the account to be deleted. It is `closing` for
//!   `account_closing_days`; every sign-in ends.
//! - A sign-in that passes every step of a closing account gets no session
//!   but a grant (`keep`, no session); `POST /api/auth/keep` with it keeps
//!   the account and answers as the sign-in would have.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::account_closing::{self, ClosingBy};
use crate::error::{AppError, AppResult};
use crate::grants::{self, Purpose};
use crate::middleware::AuthUser;
use crate::security_events::{self, Kind};
use crate::AppState;

/// A grant, as `close` and `keep` take it.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct GrantRequest {
    grant: String,
}

/// When a closing account is deleted.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Closed {
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String)]
    closes_at: time::OffsetDateTime,
}

impl Closed {
    pub fn new(closes_at: time::OffsetDateTime) -> Self {
        Closed { closes_at }
    }
}

/// `POST /api/user/close` — asks for this account to be deleted.
#[utoipa::path(
    post,
    path = "/api/user/close",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = GrantRequest,
    responses(
        (status = 200, description = "Closing; every sign-in ended", body = Closed),
        (status = 403, description = "The grant is not valid, or the account may not close"),
    )
)]
pub async fn close(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<GrantRequest>,
) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let (protected, last_admin): (bool, bool) = sqlx::query_as(
        "SELECT is_break_glass,
                is_admin AND NOT EXISTS (SELECT 1 FROM users o
                                          WHERE o.is_admin AND o.is_active AND o.id <> u.id)
           FROM users u WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    if protected {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }
    if last_admin {
        return Err(
            AppError::forbidden("the last admin can't close their account")
                .with_details(serde_json::json!({ "code": "lastAdmin" })),
        );
    }
    let days = crate::site_settings::ACCOUNT_CLOSING_DAYS
        .load(&state.pool)
        .await?;
    let mut tx = state.pool.begin().await?;
    grants::take_for_session(&mut *tx, &req.grant, Purpose::Close, &user).await?;
    security_events::record(
        &mut tx,
        user_id,
        Kind::AccountClosing,
        Some(user.session.session_id),
        None,
    )
    .await?;
    let closes_at = account_closing::close(&mut tx, user_id, ClosingBy::User, days)
        .await?
        .ok_or_else(grants::invalid)?;
    tx.commit().await?;
    Ok(Json(Closed::new(closes_at)).into_response())
}

/// `POST /api/auth/keep` — keeps a closing account, with the grant its
/// sign-in got; answers as that sign-in would have (a session).
#[utoipa::path(
    post,
    path = "/api/auth/keep",
    tag = "auth",
    request_body = GrantRequest,
    responses(
        (status = 200, description = "Kept; the session", body = crate::handlers::auth::LoginResponse),
        (status = 403, description = "The grant is not valid"),
    )
)]
pub async fn keep(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GrantRequest>,
) -> AppResult<Response> {
    let client = crate::handlers::auth::direct_sign_in_client(&headers)?;
    let mut tx = state.pool.begin().await?;
    let Some((_, grant)) = grants::take(&mut *tx, &req.grant, &[Purpose::Keep]).await? else {
        return Err(grants::invalid());
    };
    let account: Uuid = grant.user_id;
    if !account_closing::keep(&mut tx, account).await? {
        return Err(grants::invalid());
    }
    security_events::record(&mut tx, account, Kind::AccountKept, None, None).await?;
    let record: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT opaque_record FROM users WHERE id = $1")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    let record = record.ok_or_else(grants::invalid)?;
    let epoch = crate::auth_check::credential_epoch(&record);
    crate::handlers::auth::issue_after_second_step(
        &state,
        &headers,
        client,
        &account.to_string(),
        &epoch,
    )
    .await
}
