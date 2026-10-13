//! Feedback from the people on this server: bugs, feature requests and
//! anything else, sent from the sidebar of any app (docs/api.md, "Feedback").
//!
//! It goes to this server's administrators, not to a public tracker: people
//! describing a problem often mention files, addresses or messages. An
//! administrator reads it and marks it done, dismisses it, or forwards it to
//! the public tracker (`FEEDBACK_GITHUB_REPOSITORY`) by opening a prefilled
//! issue themselves; the server never posts anywhere.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::admin::audit;
use crate::middleware::{AdminUser, AuthUser};
use crate::{ratelimit, AppState};

/// What a person sends.
pub(crate) const KINDS: [&str; 3] = ["bug", "feature", "other"];
/// The apps whose sidebar has the form.
const APPS: [&str; 10] = [
    "account", "chat", "contacts", "drive", "mail", "maps", "office", "pass", "photos", "editor",
];
const MAX_MESSAGE_CHARS: usize = 5000;
/// What the form may add, each shown to the person before sending.
const DETAIL_KEYS: [&str; 4] = ["version", "browser", "language", "screen"];
const MAX_DETAIL_CHARS: usize = 300;
/// What an administrator may do with it.
pub(crate) const RESOLUTIONS: [&str; 3] = ["done", "dismissed", "forwarded"];

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendFeedbackRequest {
    /// `bug`, `feature` or `other`.
    kind: String,
    /// The app it was sent from (`drive`, `chat`, `mail`, …).
    app: String,
    message: String,
    /// Technical details the person chose to include: `version`, `browser`,
    /// `language`, `screen` (strings). Nothing else is accepted.
    #[serde(default)]
    details: Option<Map<String, Value>>,
}

fn clean_details(details: Option<Map<String, Value>>) -> AppResult<Option<Value>> {
    let Some(details) = details else {
        return Ok(None);
    };
    let mut kept = Map::new();
    for (key, value) in details {
        if !DETAIL_KEYS.contains(&key.as_str()) {
            return Err(AppError::bad_request("unknown detail"));
        }
        let Value::String(text) = value else {
            return Err(AppError::bad_request("details are text"));
        };
        if text.chars().count() > MAX_DETAIL_CHARS {
            return Err(AppError::bad_request("a detail is too long"));
        }
        kept.insert(key, Value::String(text));
    }
    Ok((!kept.is_empty()).then_some(Value::Object(kept)))
}

/// `POST /api/feedback` — send feedback to this server's administrators.
#[utoipa::path(
    post,
    path = "/api/feedback",
    tag = "feedback",
    security(("BearerAuth" = [])),
    request_body = SendFeedbackRequest,
    responses(
        (status = 204, description = "Sent"),
        (status = 400, description = "Invalid feedback"),
        (status = 429, description = "Too much feedback from this account")
    )
)]
pub async fn send_feedback(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SendFeedbackRequest>,
) -> AppResult<Response> {
    if !KINDS.contains(&req.kind.as_str()) {
        return Err(AppError::bad_request("unknown kind"));
    }
    if !APPS.contains(&req.app.as_str()) {
        return Err(AppError::bad_request("unknown app"));
    }
    let message = req.message.trim();
    if message.is_empty() {
        return Err(AppError::bad_request("the message is empty"));
    }
    if message.chars().count() > MAX_MESSAGE_CHARS {
        return Err(AppError::bad_request("the message is too long"));
    }
    let details = clean_details(req.details)?;
    if !ratelimit::FEEDBACK.allow(&user.user_id) {
        return Err(AppError::too_many_requests(
            "too much feedback; try again later",
        ));
    }
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    sqlx::query(
        "INSERT INTO feedback (user_id, kind, app, message, details) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(&req.kind)
    .bind(&req.app)
    .bind(message)
    .bind(details)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// One piece of feedback, with who sent it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackItem {
    id: Uuid,
    kind: String,
    app: String,
    message: String,
    #[schema(value_type = Option<Object>)]
    details: Option<Value>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// Absent when the account was deleted since.
    user_id: Option<Uuid>,
    user_username: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    resolved_at: Option<OffsetDateTime>,
    /// `done`, `dismissed` or `forwarded`.
    resolution: Option<String>,
    /// The public issue it was forwarded to.
    github_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackQuery {
    /// `open` (default) or `resolved` (the latest 100).
    #[serde(default)]
    status: Option<String>,
}

type FeedbackRow = (
    Uuid,
    String,
    String,
    String,
    Option<Value>,
    OffsetDateTime,
    Option<Uuid>,
    Option<String>,
    Option<OffsetDateTime>,
    Option<String>,
    Option<String>,
);

/// `GET /api/admin/feedback` — feedback, oldest open first (or the latest resolved).
#[utoipa::path(
    get,
    path = "/api/admin/feedback",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("status" = Option<String>, Query, description = "`open` (default) or `resolved`")),
    responses((status = 200, description = "Feedback", body = [FeedbackItem]))
)]
pub async fn list_feedback(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<FeedbackQuery>,
) -> AppResult<Response> {
    let resolved = match q.status.as_deref() {
        None | Some("open") => false,
        Some("resolved") => true,
        Some(_) => return Err(AppError::bad_request("unknown status")),
    };
    let rows: Vec<FeedbackRow> = sqlx::query_as(if resolved {
        "SELECT f.id, f.kind, f.app, f.message, f.details, f.created_at,
                u.id, u.username, f.resolved_at, f.resolution, f.github_url
           FROM feedback f LEFT JOIN users u ON u.id = f.user_id
          WHERE f.resolved_at IS NOT NULL
          ORDER BY f.resolved_at DESC LIMIT 100"
    } else {
        "SELECT f.id, f.kind, f.app, f.message, f.details, f.created_at,
                u.id, u.username, f.resolved_at, f.resolution, f.github_url
           FROM feedback f LEFT JOIN users u ON u.id = f.user_id
          WHERE f.resolved_at IS NULL
          ORDER BY f.created_at ASC LIMIT 500"
    })
    .fetch_all(&state.pool)
    .await?;
    let items: Vec<FeedbackItem> = rows
        .into_iter()
        .map(
            |(
                id,
                kind,
                app,
                message,
                details,
                created_at,
                user_id,
                user_username,
                resolved_at,
                resolution,
                github_url,
            )| FeedbackItem {
                id,
                kind,
                app,
                message,
                details,
                created_at,
                user_id,
                user_username,
                resolved_at,
                resolution,
                github_url,
            },
        )
        .collect();
    Ok(Json(items).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResolveFeedbackRequest {
    /// `done`, `dismissed` or `forwarded`.
    resolution: String,
    /// For `forwarded`: the issue on the public tracker
    /// (`https://github.com/<FEEDBACK_GITHUB_REPOSITORY>/issues/<n>`).
    #[serde(default)]
    github_url: Option<String>,
}

/// Whether `url` is an issue in the configured repository.
fn is_issue_of(url: &str, repository: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://github.com/") else {
        return false;
    };
    let Some((repo, number)) = rest.rsplit_once("/issues/") else {
        return false;
    };
    repo.eq_ignore_ascii_case(repository)
        && !number.is_empty()
        && number.len() <= 12
        && number.chars().all(|c| c.is_ascii_digit())
}

/// `POST /api/admin/feedback/{id}/resolve` — mark open feedback done,
/// dismissed, or forwarded to the public tracker.
#[utoipa::path(
    post,
    path = "/api/admin/feedback/{id}/resolve",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Feedback id")),
    request_body = ResolveFeedbackRequest,
    responses(
        (status = 204, description = "Resolved"),
        (status = 400, description = "Unknown resolution, or not an issue of the tracker"),
        (status = 404, description = "No such open feedback")
    )
)]
pub async fn resolve_feedback(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(req): Json<ResolveFeedbackRequest>,
) -> AppResult<Response> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    if !RESOLUTIONS.contains(&req.resolution.as_str()) {
        return Err(AppError::bad_request("unknown resolution"));
    }
    let github_url = match (
        req.resolution.as_str(),
        req.github_url.as_deref().map(str::trim),
    ) {
        ("forwarded", Some(url)) if !url.is_empty() => {
            let repository = state
                .config
                .feedback_github_repository
                .as_deref()
                .ok_or_else(|| AppError::bad_request("this server has no public tracker"))?;
            if !is_issue_of(url, repository) {
                return Err(AppError::bad_request("not an issue of the public tracker"));
            }
            Some(url.to_string())
        }
        (_, Some(url)) if !url.is_empty() => {
            return Err(AppError::bad_request(
                "only forwarded feedback has an issue",
            ))
        }
        _ => None,
    };
    let admin_uuid =
        Uuid::parse_str(&admin.user_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "UPDATE feedback
            SET resolved_at = NOW(), resolved_by = $2, resolution = $3, github_url = $4
          WHERE id = $1 AND resolved_at IS NULL
      RETURNING user_id",
    )
    .bind(id)
    .bind(admin_uuid)
    .bind(&req.resolution)
    .bind(&github_url)
    .fetch_optional(&state.pool)
    .await?;
    let Some(owner) = owner else {
        return Err(AppError::not_found("not found"));
    };
    audit(
        &state.pool,
        &admin.user_id,
        "feedback.resolve",
        owner,
        json!({ "feedbackId": id, "resolution": req.resolution, "githubUrl": github_url }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/admin/feedback/{id}` — delete feedback for good.
#[utoipa::path(
    delete,
    path = "/api/admin/feedback/{id}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Feedback id")),
    responses((status = 204, description = "Deleted"), (status = 404, description = "No such feedback"))
)]
pub async fn delete_feedback(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let owner: Option<Option<Uuid>> =
        sqlx::query_scalar("DELETE FROM feedback WHERE id = $1 RETURNING user_id")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(owner) = owner else {
        return Err(AppError::not_found("not found"));
    };
    audit(
        &state.pool,
        &admin.user_id,
        "feedback.delete",
        owner,
        json!({ "feedbackId": id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_resolutions_match_the_schema() {
        let schema = include_str!("../../migrations/130_feedback.up.sql");
        for value in KINDS.iter().chain(RESOLUTIONS.iter()) {
            assert!(schema.contains(&format!("'{value}'")), "{value}");
        }
    }

    #[test]
    fn only_issues_of_the_tracker_are_accepted() {
        assert!(is_issue_of(
            "https://github.com/kutupbt/kutup/issues/12",
            "kutupbt/kutup"
        ));
        assert!(is_issue_of(
            "https://github.com/KutupBT/kutup/issues/1",
            "kutupbt/kutup"
        ));
        assert!(!is_issue_of(
            "https://github.com/other/kutup/issues/12",
            "kutupbt/kutup"
        ));
        assert!(!is_issue_of(
            "https://github.com/kutupbt/kutup/pull/12",
            "kutupbt/kutup"
        ));
        assert!(!is_issue_of(
            "https://github.com/kutupbt/kutup/issues/12x",
            "kutupbt/kutup"
        ));
        assert!(!is_issue_of(
            "http://github.com/kutupbt/kutup/issues/12",
            "kutupbt/kutup"
        ));
        assert!(!is_issue_of(
            "https://evil.example/kutupbt/kutup/issues/12",
            "kutupbt/kutup"
        ));
    }

    #[test]
    fn details_keep_only_what_the_form_shows() {
        let ok = serde_json::from_value::<Map<String, Value>>(
            json!({ "browser": "Firefox 140", "screen": "1280×800" }),
        )
        .unwrap();
        assert_eq!(
            clean_details(Some(ok)).unwrap(),
            Some(json!({ "browser": "Firefox 140", "screen": "1280×800" }))
        );
        let extra =
            serde_json::from_value::<Map<String, Value>>(json!({ "path": "/c/direct:alice" }))
                .unwrap();
        assert!(clean_details(Some(extra)).is_err());
        let nested =
            serde_json::from_value::<Map<String, Value>>(json!({ "browser": { "x": 1 } })).unwrap();
        assert!(clean_details(Some(nested)).is_err());
        assert_eq!(clean_details(Some(Map::new())).unwrap(), None);
    }
}
