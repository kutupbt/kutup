//! Sending safety's endpoints (docs/plans/mail.md): an account's own limits
//! and pause, for Mail's notice, and the administrator's view of who sends
//! how much, with per-account limits, pause and resume. Counts only: the
//! administrator never sees what was sent.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::admin::audit;
use crate::handlers::trusted_uuid;
use crate::mail::safety;
use crate::middleware::{AdminUser, AuthUser};
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailSendingStatus {
    /// Outside recipients allowed per hour and per day.
    pub per_hour: i64,
    pub per_day: i64,
    /// Outside recipients sent to in the last hour and day.
    pub sent_hour: i64,
    pub sent_day: i64,
    /// The lower limits of an account's first week apply.
    pub new_account: bool,
    /// Why sending to outside addresses is paused (`admin`, `bounces`,
    /// `spam`); absent when it is not.
    pub paused: Option<String>,
    /// Whether this server sends your mail to addresses outside Kutup
    /// (`MAIL_OUTSIDE_SENDING`); mail between Kutup users always goes.
    pub outside_allowed: bool,
}

/// `GET /api/mail/sending` — your limits on mail to outside addresses, and
/// whether sending is paused.
#[utoipa::path(
    get,
    path = "/api/mail/sending",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Your sending limits", body = MailSendingStatus))
)]
pub async fn own_status(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<MailSendingStatus>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let standing = safety::standing(&state, user_id).await?;
    Ok(Json(MailSendingStatus {
        per_hour: standing.limits.per_hour,
        per_day: standing.limits.per_day,
        sent_hour: standing.sent_hour,
        sent_day: standing.sent_day,
        new_account: standing.new_account,
        paused: standing.paused,
        outside_allowed: state.config.mail_outside_sending.allows(user.is_admin),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailSender {
    pub user_id: String,
    pub email: String,
    pub username: String,
    /// Outside recipients in the last day and week.
    pub sent_day: i64,
    pub sent_week: i64,
    pub bounces_week: i64,
    pub spam_refused_week: i64,
    /// Overrides; null: the server's limits.
    pub per_hour: Option<i32>,
    pub per_day: Option<i32>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub paused_at: Option<OffsetDateTime>,
    pub paused_reason: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub flagged_at: Option<OffsetDateTime>,
    pub flag_reason: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct MailSendersQuery {
    /// Only paused or flagged accounts.
    pub attention: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct SenderRow {
    id: Uuid,
    email: String,
    username: Option<String>,
    sent_day: i64,
    sent_week: i64,
    bounces_week: i64,
    spam_week: i64,
    per_hour: Option<i32>,
    per_day: Option<i32>,
    paused_at: Option<OffsetDateTime>,
    paused_reason: Option<String>,
    flagged_at: Option<OffsetDateTime>,
    flag_reason: Option<String>,
}

/// `GET /api/admin/mail/senders?attention=` — accounts that sent outside in
/// the last week, or have limits, a pause or a flag: paused and flagged
/// first, then by volume.
#[utoipa::path(
    get,
    path = "/api/admin/mail/senders",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(MailSendersQuery),
    responses((status = 200, description = "Senders", body = [MailSender]))
)]
pub async fn senders(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<MailSendersQuery>,
) -> AppResult<Json<Vec<MailSender>>> {
    let rows = load(&state, query.attention.unwrap_or(false), None).await?;
    Ok(Json(rows.into_iter().map(MailSender::from).collect()))
}

impl From<SenderRow> for MailSender {
    fn from(row: SenderRow) -> Self {
        MailSender {
            user_id: row.id.to_string(),
            email: row.email,
            username: row.username.unwrap_or_default(),
            sent_day: row.sent_day,
            sent_week: row.sent_week,
            bounces_week: row.bounces_week,
            spam_refused_week: row.spam_week,
            per_hour: row.per_hour,
            per_day: row.per_day,
            paused_at: row.paused_at,
            paused_reason: row.paused_reason,
            flagged_at: row.flagged_at,
            flag_reason: row.flag_reason,
        }
    }
}

async fn load(state: &AppState, attention: bool, user: Option<Uuid>) -> AppResult<Vec<SenderRow>> {
    Ok(sqlx::query_as(
        "WITH sent AS (
             SELECT user_id,
                    SUM(external_recipients) FILTER (WHERE received_at > now() - interval '1 day')::bigint AS day,
                    SUM(external_recipients)::bigint AS week
               FROM mail_messages
              WHERE external_recipients > 0 AND received_at > now() - interval '7 days'
              GROUP BY user_id),
         events AS (
             SELECT user_id,
                    COUNT(*) FILTER (WHERE kind = 'bounce') AS bounces,
                    COUNT(*) FILTER (WHERE kind = 'spam_refused') AS spam
               FROM mail_sending_events
              WHERE created_at > now() - interval '7 days'
              GROUP BY user_id)
         SELECT u.id, u.email, u.username,
                COALESCE(s.day, 0) AS sent_day, COALESCE(s.week, 0) AS sent_week,
                COALESCE(e.bounces, 0) AS bounces_week, COALESCE(e.spam, 0) AS spam_week,
                p.per_hour, p.per_day, p.paused_at, p.paused_reason, p.flagged_at, p.flag_reason
           FROM users u
           LEFT JOIN sent s ON s.user_id = u.id
           LEFT JOIN events e ON e.user_id = u.id
           LEFT JOIN mail_sending_policies p ON p.user_id = u.id
          WHERE CASE WHEN $2::uuid IS NOT NULL THEN u.id = $2
                     ELSE (s.user_id IS NOT NULL OR e.user_id IS NOT NULL OR p.user_id IS NOT NULL)
                          AND (NOT $1 OR p.paused_at IS NOT NULL OR p.flagged_at IS NOT NULL) END
          ORDER BY (p.paused_at IS NOT NULL OR p.flagged_at IS NOT NULL) DESC,
                   COALESCE(s.week, 0) DESC, u.email
          LIMIT 500",
    )
    .bind(attention)
    .bind(user)
    .fetch_all(&state.pool)
    .await?)
}

/// `GET /api/admin/users/{id}/mail-sending` — one account's sending, even
/// before it has sent anything.
#[utoipa::path(
    get,
    path = "/api/admin/users/{id}/mail-sending",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    responses((status = 200, description = "The account's sending", body = MailSender), (status = 404, description = "No such user"))
)]
pub async fn one(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailSender>> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    load(&state, false, Some(target))
        .await?
        .into_iter()
        .next()
        .map(|row| Json(MailSender::from(row)))
        .ok_or_else(|| AppError::not_found("not found"))
}

/// A limit override: absent leaves it, null clears it (the server's limit).
fn limit(value: &Option<Option<i32>>) -> AppResult<()> {
    if let Some(Some(n)) = value {
        if !(0..=100_000).contains(n) {
            return Err(AppError::bad_request("limits are 0 to 100000"));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailSending {
    /// A number, or null for the server's limit.
    #[serde(default, deserialize_with = "crate::handlers::files::present")]
    #[schema(value_type = Option<i32>)]
    pub per_hour: Option<Option<i32>>,
    #[serde(default, deserialize_with = "crate::handlers::files::present")]
    #[schema(value_type = Option<i32>)]
    pub per_day: Option<Option<i32>>,
    pub paused: Option<bool>,
    /// Clears the flag (the administrator has looked).
    pub clear_flag: Option<bool>,
}

/// `PUT /api/admin/users/{id}/mail-sending` — an account's limits, pause and
/// flag. Resuming clears the pause whatever set it.
#[utoipa::path(
    put,
    path = "/api/admin/users/{id}/mail-sending",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    request_body = UpdateMailSending,
    responses((status = 204, description = "Updated"), (status = 404, description = "No such user"))
)]
pub async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateMailSending>,
) -> AppResult<axum::http::StatusCode> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    limit(&request.per_hour)?;
    limit(&request.per_day)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(target)
        .fetch_one(&state.pool)
        .await?;
    if !exists {
        return Err(AppError::not_found("not found"));
    }
    sqlx::query(
        "INSERT INTO mail_sending_policies (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(target)
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "UPDATE mail_sending_policies SET
             per_hour = CASE WHEN $2 THEN $3 ELSE per_hour END,
             per_day = CASE WHEN $4 THEN $5 ELSE per_day END,
             paused_at = CASE WHEN $6::bool IS NULL THEN paused_at
                              WHEN $6 THEN COALESCE(paused_at, now()) ELSE NULL END,
             paused_reason = CASE WHEN $6::bool IS NULL THEN paused_reason
                                  WHEN $6 THEN COALESCE(paused_reason, 'admin') ELSE NULL END,
             flagged_at = CASE WHEN $7 THEN NULL ELSE flagged_at END,
             flag_reason = CASE WHEN $7 THEN NULL ELSE flag_reason END,
             updated_at = now()
          WHERE user_id = $1",
    )
    .bind(target)
    .bind(request.per_hour.is_some())
    .bind(request.per_hour.flatten())
    .bind(request.per_day.is_some())
    .bind(request.per_day.flatten())
    .bind(request.paused)
    .bind(request.clear_flag.unwrap_or(false))
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail.sending.update",
        Some(target),
        json!({
            "perHour": request.per_hour,
            "perDay": request.per_day,
            "paused": request.paused,
            "clearFlag": request.clear_flag,
        }),
    )
    .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
