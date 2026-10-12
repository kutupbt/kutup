//! `POST /api/chat/link-preview` — fetch one public web page or image for a
//! Chat link preview made by the sender.
//!
//! Browsers cannot read another site's page, so the sender's own homeserver
//! fetches it; the preview then travels end-to-end encrypted inside the
//! message and recipients never contact the site. The server sees the link
//! (never the message) and returns the raw bytes: the browser parses the page
//! with `DOMParser` (no scripts run) and resizes the image itself.
//!
//! The fetch goes through `public_fetch`, which is deliberately narrow since
//! it runs inside the server's network, with a per-account rate limit here.

use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::public_fetch;
use crate::ratelimit::RateLimiter;
use crate::AppState;

const PAGE_LIMIT_BYTES: usize = 512 * 1024;
const IMAGE_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(8);
const USER_AGENT: &str = "Mozilla/5.0 (compatible; KutupLinkPreview/1.0)";

/// 30 fetches a minute per account: a preview is one page and one image.
pub(crate) static LINK_PREVIEWS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(30, Duration::from_secs(60)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum LinkPreviewFetchKind {
    Page,
    Image,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkPreviewFetchRequest {
    pub url: String,
    pub kind: LinkPreviewFetchKind,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkPreviewFetchResponse {
    /// Where the content came from after redirects.
    pub final_url: String,
    pub content_type: String,
    /// Standard base64 of at most 512 KiB (page) or 2 MiB (image).
    pub body: String,
}

#[utoipa::path(
    post,
    path = "/api/chat/link-preview",
    tag = "chat",
    operation_id = "fetchChatLinkPreview",
    request_body = LinkPreviewFetchRequest,
    responses(
        (status = 200, description = "The page or image", body = LinkPreviewFetchResponse),
        (status = 400, description = "Not a public https URL"),
        (status = 404, description = "Link previews are off on this server"),
        (status = 422, description = "The site did not answer with a usable page or image"),
        (status = 429, description = "Too many previews"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn fetch(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<LinkPreviewFetchRequest>,
) -> AppResult<Json<LinkPreviewFetchResponse>> {
    if !state.config.chat_link_previews {
        return Err(AppError::not_found("link previews are off on this server"));
    }
    if !LINK_PREVIEWS.allow(&auth.user_id) {
        return Err(AppError::too_many_requests(
            "too many link previews; try again shortly",
        ));
    }
    let url = public_fetch::parse_public_https(&request.url)?;
    let fetched = match request.kind {
        LinkPreviewFetchKind::Page => public_fetch::Request {
            accept: "text/html,application/xhtml+xml;q=0.9",
            user_agent: USER_AGENT,
            timeout: TOTAL_TIMEOUT,
            limit: PAGE_LIMIT_BYTES,
            // A page is cut at the limit: its head, where preview tags
            // live, comes first.
            truncate: true,
            wanted: &|kind| kind == "text/html" || kind == "application/xhtml+xml",
        },
        LinkPreviewFetchKind::Image => public_fetch::Request {
            accept: "image/webp,image/png,image/jpeg,image/gif;q=0.8",
            user_agent: USER_AGENT,
            timeout: TOTAL_TIMEOUT,
            limit: IMAGE_LIMIT_BYTES,
            truncate: false,
            wanted: &|kind| {
                matches!(
                    kind,
                    "image/jpeg" | "image/png" | "image/webp" | "image/gif"
                )
            },
        },
    };
    let fetched = public_fetch::get(url, &fetched).await?;
    Ok(Json(LinkPreviewFetchResponse {
        final_url: fetched.final_url.to_string(),
        content_type: fetched.content_type,
        body: STANDARD.encode(fetched.body),
    }))
}
