//! Moderation of public links: reports from anyone who opened one, and what
//! an administrator does with them (docs/architecture.md, "File editor
//! route").
//!
//! The server cannot read what a link shows. A reporter may hand over the
//! whole link, key included, so an administrator can look; it is kept only
//! while the report is open. An administrator dismisses a report, takes the
//! link down, or disables its owner's account (`PUT /api/admin/users/{id}`),
//! which takes every link of theirs down with it. A link that is down answers
//! `410` with `code: "link_removed"`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::admin::audit;
use crate::middleware::AdminUser;
use crate::AppState;

/// Why someone reports a link.
const REASONS: [&str; 5] = ["phishing", "malware", "illegal", "abuse", "other"];
const MAX_DETAILS_CHARS: usize = 2000;
const MAX_LINK_CHARS: usize = 2048;
/// Open reports kept per link: more say nothing new, and a script could
/// otherwise fill the table through one token.
const MAX_OPEN_REPORTS_PER_LINK: i64 = 50;

/// The `410` a link that was taken down answers, whatever is asked of it.
pub(crate) fn link_removed() -> AppError {
    AppError::new(StatusCode::GONE, "this link was removed")
        .with_details(json!({ "code": "link_removed" }))
}

/// Refuses a link that may not be opened now (`crate::public_sharing`).
pub(crate) async fn ensure_link_up(pool: &PgPool, token: &str, signed_in: bool) -> AppResult<()> {
    crate::public_sharing::ensure_link_up(pool, token, signed_in).await
}

/// Resolves every open report on `owner`'s links (their account was disabled).
pub(crate) async fn resolve_reports_of_owner(
    pool: &PgPool,
    owner: Uuid,
    admin: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE public_link_reports r
            SET resolved_at = NOW(), resolved_by = $2, resolution = 'disabled', link = NULL
           FROM public_shares p
          WHERE r.share_id = p.id AND p.owner_user_id = $1 AND r.resolved_at IS NULL",
    )
    .bind(owner)
    .bind(admin)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportLinkRequest {
    /// `phishing`, `malware`, `illegal`, `abuse` or `other`.
    reason: String,
    #[serde(default)]
    details: String,
    /// The whole link, key included, when the reporter lets administrators
    /// look: a public page of this server's for this token.
    #[serde(default)]
    link: Option<String>,
}

/// Whether `link` is one of this server's public pages for `token`: an
/// administrator opens it, so it must not lead anywhere else.
fn is_link_to(state: &AppState, link: &str, token: &str) -> bool {
    let Ok(url) = url::Url::parse(link) else {
        return false;
    };
    let origin = url.origin().ascii_serialization();
    let apps = &state.config.apps;
    let ours = [&apps.drive, &apps.office, &apps.photos]
        .iter()
        .any(|app| app.trim_end_matches('/') == origin);
    let mut path = url.path_segments().into_iter().flatten();
    ours && url.username().is_empty()
        && url.password().is_none()
        && path.next() == Some("s")
        && path.next() == Some(token)
        // A link to one file in a folder's: `/s/<token>/<fileId>`.
        && path.next().is_none_or(|file| Uuid::parse_str(file).is_ok() && path.next().is_none())
}

/// `POST /api/share/{token}/report` — report a public link to the server's
/// administrators. Anonymous; rate-limited per address, which is not kept.
#[utoipa::path(
    post,
    path = "/api/share/{token}/report",
    tag = "shares",
    params(("token" = String, Path, description = "Share token (the capability)")),
    request_body = ReportLinkRequest,
    responses(
        (status = 204, description = "Reported"),
        (status = 404, description = "No such link"),
        (status = 410, description = "The link was removed")
    )
)]
pub async fn report_public_link(
    State(state): State<AppState>,
    viewer: crate::middleware::Viewer,
    Path(token): Path<String>,
    Json(req): Json<ReportLinkRequest>,
) -> AppResult<Response> {
    if !REASONS.contains(&req.reason.as_str()) {
        return Err(AppError::bad_request("unknown reason"));
    }
    let details = req.details.trim();
    if details.chars().count() > MAX_DETAILS_CHARS {
        return Err(AppError::bad_request("details are too long"));
    }
    let link = match req.link.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
        Some(link)
            if link.chars().count() > MAX_LINK_CHARS || !is_link_to(&state, link, &token) =>
        {
            return Err(AppError::bad_request("the link is not this public link"))
        }
        other => other,
    };
    ensure_link_up(&state.pool, &token, viewer.signed_in).await?;
    let share: Option<Uuid> = sqlx::query_scalar("SELECT id FROM public_shares WHERE token = $1")
        .bind(&token)
        .fetch_optional(&state.pool)
        .await?;
    let Some(share) = share else {
        return Err(AppError::not_found("not found"));
    };
    // Past the cap, a report is accepted and not stored: the link is already
    // waiting for an administrator.
    sqlx::query(
        "INSERT INTO public_link_reports (share_id, reason, details, link)
         SELECT $1, $2, $3, $4
          WHERE (SELECT COUNT(*) FROM public_link_reports WHERE share_id = $1 AND resolved_at IS NULL) < $5",
    )
    .bind(share)
    .bind(&req.reason)
    .bind(details)
    .bind(link)
    .bind(MAX_OPEN_REPORTS_PER_LINK)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// One report, with the link and account it is about.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkReport {
    id: Uuid,
    reason: String,
    details: String,
    /// The whole link, when the reporter gave it (open reports only).
    link: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    resolved_at: Option<OffsetDateTime>,
    /// `dismissed`, `removed`, `disabled` or `blocked`.
    resolution: Option<String>,
    share_id: Uuid,
    /// `collection` (a folder or album) or `file`.
    share_type: String,
    #[serde(with = "time::serde::rfc3339")]
    share_created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    share_removed_at: Option<OffsetDateTime>,
    /// Why an operator blocked the link (`legal_order`, `abuse`, `other`);
    /// none while it isn't blocked.
    share_blocked_reason: Option<String>,
    owner_user_id: Uuid,
    owner_username: String,
    owner_is_active: bool,
    /// Open reports on the same link, this one included.
    open_reports_on_link: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportsQuery {
    /// `open` (default) or `resolved` (the latest 100).
    #[serde(default)]
    status: Option<String>,
}

type ReportRow = (
    Uuid,
    String,
    String,
    Option<String>,
    OffsetDateTime,
    Option<OffsetDateTime>,
    Option<String>,
    Uuid,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
    Option<String>,
    Uuid,
    Option<String>,
    bool,
    i64,
);

/// `GET /api/admin/reports` — reports on public links, oldest open first
/// (or the latest resolved).
#[utoipa::path(
    get,
    path = "/api/admin/reports",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("status" = Option<String>, Query, description = "`open` (default) or `resolved`")),
    responses((status = 200, description = "Reports", body = [LinkReport]))
)]
pub async fn list_reports(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ReportsQuery>,
) -> AppResult<Response> {
    let resolved = match q.status.as_deref() {
        None | Some("open") => false,
        Some("resolved") => true,
        Some(_) => return Err(AppError::bad_request("unknown status")),
    };
    let rows: Vec<ReportRow> = sqlx::query_as(if resolved {
        "SELECT r.id, r.reason, r.details, r.link, r.created_at, r.resolved_at, r.resolution,
                p.id, p.share_type, p.created_at, p.removed_at, p.blocked_reason,
                u.id, u.username, u.is_active,
                (SELECT COUNT(*) FROM public_link_reports o WHERE o.share_id = p.id AND o.resolved_at IS NULL)
           FROM public_link_reports r
           JOIN public_shares p ON p.id = r.share_id
           JOIN users u ON u.id = p.owner_user_id
          WHERE r.resolved_at IS NOT NULL
          ORDER BY r.resolved_at DESC LIMIT 100"
    } else {
        "SELECT r.id, r.reason, r.details, r.link, r.created_at, r.resolved_at, r.resolution,
                p.id, p.share_type, p.created_at, p.removed_at, p.blocked_reason,
                u.id, u.username, u.is_active,
                (SELECT COUNT(*) FROM public_link_reports o WHERE o.share_id = p.id AND o.resolved_at IS NULL)
           FROM public_link_reports r
           JOIN public_shares p ON p.id = r.share_id
           JOIN users u ON u.id = p.owner_user_id
          WHERE r.resolved_at IS NULL
          ORDER BY r.created_at ASC LIMIT 500"
    })
    .fetch_all(&state.pool)
    .await?;
    let reports: Vec<LinkReport> = rows
        .into_iter()
        .map(
            |(
                id,
                reason,
                details,
                link,
                created_at,
                resolved_at,
                resolution,
                share_id,
                share_type,
                share_created_at,
                share_removed_at,
                share_blocked_reason,
                owner_user_id,
                owner_username,
                owner_is_active,
                open_reports_on_link,
            )| LinkReport {
                id,
                reason,
                details,
                link,
                created_at,
                resolved_at,
                resolution,
                share_id,
                share_type,
                share_created_at,
                share_removed_at,
                share_blocked_reason,
                owner_user_id,
                owner_username: owner_username.unwrap_or_default(),
                owner_is_active,
                open_reports_on_link,
            },
        )
        .collect();
    Ok(Json(reports).into_response())
}

/// The open report `id`'s link and its owner.
async fn open_report(pool: &PgPool, id: &str) -> AppResult<(Uuid, Uuid, Uuid, String)> {
    let id = Uuid::parse_str(id).map_err(|_| AppError::not_found("not found"))?;
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT p.id, p.owner_user_id, COALESCE(u.username, '')
           FROM public_link_reports r
           JOIN public_shares p ON p.id = r.share_id
           JOIN users u ON u.id = p.owner_user_id
          WHERE r.id = $1 AND r.resolved_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let (share, owner, username) = row.ok_or_else(|| AppError::not_found("not found"))?;
    Ok((id, share, owner, username))
}

fn admin_id(admin: &AdminUser) -> AppResult<Uuid> {
    Uuid::parse_str(&admin.user_id).map_err(|_| AppError::unauthorized("unauthorized"))
}

/// `POST /api/admin/reports/{id}/dismiss` — nothing wrong: close the report.
#[utoipa::path(
    post,
    path = "/api/admin/reports/{id}/dismiss",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Report id")),
    responses((status = 204, description = "Dismissed"), (status = 404, description = "No such open report"))
)]
pub async fn dismiss_report(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let (report, share, owner, username) = open_report(&state.pool, &id).await?;
    sqlx::query(
        "UPDATE public_link_reports
            SET resolved_at = NOW(), resolved_by = $2, resolution = 'dismissed', link = NULL
          WHERE id = $1 AND resolved_at IS NULL",
    )
    .bind(report)
    .bind(admin_id(&admin)?)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        &admin.user_id,
        "report.dismiss",
        Some(owner),
        json!({ "username": username, "reportId": report, "shareId": share }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/admin/reports/{id}/remove-link` — take the reported link down
/// and close every open report on it.
#[utoipa::path(
    post,
    path = "/api/admin/reports/{id}/remove-link",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Report id")),
    responses((status = 204, description = "Link removed"), (status = 404, description = "No such open report"))
)]
pub async fn remove_reported_link(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let (report, share, owner, username) = open_report(&state.pool, &id).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE public_shares SET removed_at = COALESCE(removed_at, NOW()) WHERE id = $1")
        .bind(share)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE public_link_reports
            SET resolved_at = NOW(), resolved_by = $2, resolution = 'removed', link = NULL
          WHERE share_id = $1 AND resolved_at IS NULL",
    )
    .bind(share)
    .bind(admin_id(&admin)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit(
        &state.pool,
        &admin.user_id,
        "share.remove",
        Some(owner),
        json!({ "username": username, "reportId": report, "shareId": share }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Why an operator blocks a link (docs/plans/server-personal-data.md, A11).
const BLOCK_REASONS: [&str; 3] = ["legal_order", "abuse", "other"];

/// `POST /api/admin/shares/{id}/block` body.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct BlockLinkRequest {
    /// `legal_order` (the link answers 451), `abuse` or `other` (410).
    reason: String,
    /// An order's number or another reference, for the administrators only.
    reference: Option<String>,
}

/// `POST /api/admin/shares/{id}/block` — block one public link: it answers
/// `451` (a legal order) or `410` (another reason) with `link_blocked`, and
/// its open reports are closed as `blocked`. Blocking again changes the
/// reason. Audited.
#[utoipa::path(
    post,
    path = "/api/admin/shares/{id}/block",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Public link (share) id")),
    request_body = BlockLinkRequest,
    responses((status = 204, description = "Blocked"), (status = 404, description = "No such link"))
)]
pub async fn block_link(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(req): Json<BlockLinkRequest>,
) -> AppResult<Response> {
    let share = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    if !BLOCK_REASONS.contains(&req.reason.as_str()) {
        return Err(AppError::bad_request(
            "reason must be legal_order, abuse or other",
        ));
    }
    let reference = req
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    if reference.is_some_and(|r| r.chars().count() > 200) {
        return Err(AppError::bad_request("the reference is too long"));
    }
    let admin_uuid = admin_id(&admin)?;
    let mut tx = state.pool.begin().await?;
    let owner: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "UPDATE public_shares p
            SET blocked_at = now(), blocked_reason = $2, blocked_reference = $3, blocked_by = $4
           FROM users u
          WHERE p.id = $1 AND u.id = p.owner_user_id
          RETURNING p.owner_user_id, u.username",
    )
    .bind(share)
    .bind(&req.reason)
    .bind(reference)
    .bind(admin_uuid)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((owner, username)) = owner else {
        return Err(AppError::not_found("not found"));
    };
    sqlx::query(
        // The reporter's link stays: under a legal order it may be evidence.
        "UPDATE public_link_reports
            SET resolved_at = NOW(), resolved_by = $2, resolution = 'blocked'
          WHERE share_id = $1 AND resolved_at IS NULL",
    )
    .bind(share)
    .bind(admin_uuid)
    .execute(&mut *tx)
    .await?;
    // In the block's own transaction: the record of who blocked what, why.
    crate::audit_log::append_in(
        &mut tx,
        admin_uuid,
        "share.block",
        Some(owner),
        &json!({
            "username": username.unwrap_or_default(),
            "shareId": share,
            "reason": req.reason,
            "reference": reference,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/admin/shares/{id}/block` — lift a link's block. Audited.
#[utoipa::path(
    delete,
    path = "/api/admin/shares/{id}/block",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Public link (share) id")),
    responses((status = 204, description = "Unblocked"), (status = 404, description = "No such link"))
)]
pub async fn unblock_link(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let share = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let admin_uuid = admin_id(&admin)?;
    let mut tx = state.pool.begin().await?;
    let row: Option<(Uuid, Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT p.owner_user_id, u.username, p.blocked_reason, p.owner_removed_at IS NOT NULL
           FROM public_shares p JOIN users u ON u.id = p.owner_user_id
          WHERE p.id = $1 FOR UPDATE OF p",
    )
    .bind(share)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((owner, username, was, owner_removed)) = row else {
        return Err(AppError::not_found("not found"));
    };
    let Some(reason) = was else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    if owner_removed {
        // Its owner removed it while it was blocked: kept only for the block.
        sqlx::query("DELETE FROM public_shares WHERE id = $1")
            .bind(share)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query(
            "UPDATE public_shares
                SET blocked_at = NULL, blocked_reason = NULL, blocked_reference = NULL,
                    blocked_by = NULL
              WHERE id = $1",
        )
        .bind(share)
        .execute(&mut *tx)
        .await?;
    }
    crate::audit_log::append_in(
        &mut tx,
        admin_uuid,
        "share.unblock",
        Some(owner),
        &json!({ "username": username.unwrap_or_default(), "shareId": share, "reason": reason }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reasons_match_the_schema() {
        let schema = include_str!("../../migrations/20261013000000_baseline.up.sql");
        for reason in super::REASONS {
            assert!(schema.contains(&format!("'{reason}'")), "{reason}");
        }
    }

    #[test]
    fn block_reasons_match_the_schema() {
        let schema = include_str!("../../migrations/20261109100000_share_controls.up.sql");
        for reason in super::BLOCK_REASONS {
            assert!(schema.contains(&format!("'{reason}'")), "{reason}");
        }
    }
}
