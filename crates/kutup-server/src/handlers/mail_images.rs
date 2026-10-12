//! The mail image proxy (docs/plans/mail-parity.md, P5), as Proton's
//! `core/v4/images`: when a reader loads a message's remote images, the
//! Kutup server fetches each one and hands the bytes back. The sender then
//! sees the server, not the reader's address, browser or the moment each
//! reader looked again; nothing is stored, and the response is not cached.
//!
//! - `POST /api/mail/images/check`: which of a message's image addresses are
//!   known tracking pixels (Proton's dry run). Nothing is fetched, so the
//!   reader sees "N trackers blocked" before loading anything.
//! - `GET /api/mail/images?url=`: one image. A known tracker answers 204 with
//!   `X-Kutup-Tracker` and is never fetched.
//!
//! The fetch goes through `public_fetch` (public addresses only, pinned,
//! redirects checked again, size and time limits), with http on port 80
//! allowed too and no redirect followed to a tracker; a per-account rate
//! limit; and only raster images, recognised by their bytes (never SVG,
//! which could run script if opened on its own).

use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::public_fetch::{self, Checks, Options};
use crate::ratelimit::RateLimiter;
use crate::AppState;

const IMAGE_LIMIT_BYTES: usize = 5 * 1024 * 1024;
/// Bytes fetched a minute per account, for all its images.
const BYTES_PER_MINUTE: u64 = 64 * 1024 * 1024;
const MAX_CHECK_URLS: usize = 500;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT: &str = "Mozilla/5.0 (compatible; KutupImageProxy/1.0)";
/// The header that names a blocked tracker's provider (Proton's
/// `x-pm-tracker-provider`).
pub const TRACKER_HEADER: &str = "x-kutup-tracker";

/// 300 images a minute per account: a newsletter carries a few dozen. Nothing
/// is cached, so each one is a fetch.
static MAIL_IMAGES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(300, Duration::from_secs(60)));
/// What each account fetched in its current minute ([`BYTES_PER_MINUTE`]).
static BYTES: LazyLock<ByteBudget> = LazyLock::new(ByteBudget::default);
/// Images fetched at once on this server, for all accounts.
static FETCHING: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(32));

/// Known open-tracking addresses: a host (or its subdomains) and, when the
/// host also serves real images, the path where its pixels live.
const TRACKERS: &[(&str, &str, &str)] = &[
    ("list-manage.com", "/track/open", "Mailchimp"),
    ("mandrillapp.com", "/track/open", "Mandrill"),
    ("sendgrid.net", "/wf/open", "SendGrid"),
    ("hubspotemail.net", "", "HubSpot"),
    ("hubspotlinks.com", "", "HubSpot"),
    ("track.hubspot.com", "", "HubSpot"),
    ("t.sidekickopen01.com", "", "HubSpot"),
    ("exct.net", "/open.aspx", "Salesforce Marketing Cloud"),
    ("rs6.net", "/on.jsp", "Constant Contact"),
    ("createsend1.com", "/t/", "Campaign Monitor"),
    ("cmail19.com", "/t/", "Campaign Monitor"),
    ("cmail20.com", "/t/", "Campaign Monitor"),
    ("mjt.lu", "/oo/", "Mailjet"),
    ("sendibt3.com", "", "Brevo"),
    ("sendibw.com", "", "Brevo"),
    ("awstrack.me", "/I0/", "Amazon SES"),
    ("pstmrk.it", "/open", "Postmark"),
    ("customeriomail.com", "/e/o/", "Customer.io"),
    ("klaviyomail.com", "", "Klaviyo"),
    ("via.intercom.io", "/o/", "Intercom"),
    ("emltrk.com", "", "Litmus"),
    ("mailtrack.io", "", "Mailtrack"),
    ("t.yesware.com", "", "Yesware"),
    ("mailfoogae.appspot.com", "", "Streak"),
    ("bananatag.com", "", "Bananatag"),
    ("getnotify.com", "", "GetNotify"),
    ("api.mixpanel.com", "/track", "Mixpanel"),
    ("google-analytics.com", "/collect", "Google Analytics"),
    ("facebook.com", "/tr", "Meta"),
];

/// The provider of a known tracking pixel at `url`.
pub fn tracker_of(url: &Url) -> Option<&'static str> {
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let path = url.path();
    TRACKERS
        .iter()
        .find(|(domain, prefix, _)| {
            (host == *domain || host.ends_with(&format!(".{domain}")))
                && (prefix.is_empty() || path.starts_with(prefix))
        })
        .map(|(_, _, name)| *name)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCheckRequest {
    /// The message's remote image addresses (at most 500).
    pub urls: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageTracker {
    pub url: String,
    pub provider: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageCheckResponse {
    /// The addresses that are known tracking pixels; they never load.
    pub trackers: Vec<ImageTracker>,
}

#[utoipa::path(
    post,
    path = "/api/mail/images/check",
    tag = "mail",
    operation_id = "checkMailImages",
    request_body = ImageCheckRequest,
    responses(
        (status = 200, description = "Which addresses are known trackers", body = ImageCheckResponse),
        (status = 400, description = "More than 500 addresses"),
    ),
    security(("BearerAuth" = []))
)]
pub async fn check(
    _auth: AuthUser,
    Json(request): Json<ImageCheckRequest>,
) -> AppResult<Json<ImageCheckResponse>> {
    if request.urls.len() > MAX_CHECK_URLS {
        return Err(AppError::bad_request("at most 500 image addresses"));
    }
    let trackers = request
        .urls
        .into_iter()
        .filter_map(|value| {
            let url = Url::parse(value.trim()).ok()?;
            let provider = tracker_of(&url)?;
            Some(ImageTracker {
                url: value,
                provider: provider.to_owned(),
            })
        })
        .collect();
    Ok(Json(ImageCheckResponse { trackers }))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ImageQuery {
    /// The image's address in the message: http or https.
    pub url: String,
}

#[utoipa::path(
    get,
    path = "/api/mail/images",
    tag = "mail",
    operation_id = "fetchMailImage",
    params(ImageQuery),
    responses(
        (status = 200, description = "The image's bytes, with its type"),
        (status = 204, description = "A known tracking pixel, never fetched; X-Kutup-Tracker names it"),
        (status = 400, description = "Not a public http or https address"),
        (status = 422, description = "The site did not answer with an image"),
        (status = 429, description = "Too many images"),
        (status = 503, description = "The proxy is busy"),
    ),
    security(("BearerAuth" = []))
)]
pub async fn fetch(
    State(_state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<ImageQuery>,
) -> AppResult<Response> {
    if !MAIL_IMAGES.allow(&auth.user_id) {
        return Err(AppError::too_many_requests(
            "too many images; try again shortly",
        ));
    }
    let url = public_fetch::parse_public(query.url.trim(), true)?;
    if let Some(provider) = tracker_of(&url) {
        return Ok(tracker_response(provider));
    }
    if !BYTES.has_room(&auth.user_id) {
        return Err(AppError::too_many_requests(
            "too many image bytes this minute; try again shortly",
        ));
    }
    // Busy for longer than one fetch may take: try again later.
    let _permit = tokio::time::timeout(TOTAL_TIMEOUT, FETCHING.acquire())
        .await
        .map_err(|_| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "the image proxy is busy; try again shortly",
            )
        })?
        .map_err(|_| AppError::internal("image fetches closed"))?;
    let (mime, body) = fetch_image(url, &Checks::PUBLIC).await?;
    BYTES.charge(&auth.user_id, body.len());
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(mime)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'; sandbox"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("inline"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body,
    )
        .into_response())
}

/// Bytes fetched per account in one-minute windows: a fetch starts only while
/// the account is under its budget, and what it brought back is counted.
#[derive(Default)]
struct ByteBudget {
    used: std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u64)>>,
}

impl ByteBudget {
    fn has_room(&self, account: &str) -> bool {
        let now = std::time::Instant::now();
        let mut used = self.used.lock().expect("byte budget lock");
        used.retain(|_, (since, _)| now.duration_since(*since) < Duration::from_secs(60));
        used.get(account)
            .is_none_or(|(_, bytes)| *bytes < BYTES_PER_MINUTE)
    }

    fn charge(&self, account: &str, bytes: usize) {
        let mut used = self.used.lock().expect("byte budget lock");
        let entry = used
            .entry(account.to_owned())
            .or_insert((std::time::Instant::now(), 0));
        entry.1 = entry.1.saturating_add(bytes as u64);
    }
}

fn tracker_response(provider: &str) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(provider) {
        response.headers_mut().insert(TRACKER_HEADER, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Fetches one image; a redirect to a tracker is not followed.
async fn fetch_image(url: Url, checks: &Checks) -> AppResult<(&'static str, Vec<u8>)> {
    let fetched = public_fetch::fetch(
        url,
        &public_fetch::Request {
            accept: "image/avif,image/webp,image/png,image/jpeg,image/gif;q=0.9,image/*;q=0.8",
            user_agent: USER_AGENT,
            timeout: TOTAL_TIMEOUT,
            limit: IMAGE_LIMIT_BYTES,
            truncate: false,
            // Sites often send images under another type; the bytes decide.
            wanted: &|_| true,
        },
        &Options {
            allow_http: true,
            follow: &|next| tracker_of(next).is_none(),
        },
        checks,
    )
    .await?;
    let mime = sniff_image(&fetched.body)
        .ok_or_else(|| public_fetch::unusable("the site did not return an image"))?;
    Ok((mime, fetched.body))
}

/// The raster type the bytes start with; anything else (SVG, HTML, a type a
/// site claims but does not send) is refused.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    let starts = |magic: &[u8]| bytes.starts_with(magic);
    if starts(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if starts(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.len() >= 12
        && &bytes[4..8] == b"ftyp"
        && matches!(&bytes[8..12], b"avif" | b"avis")
    {
        Some("image/avif")
    } else if starts(b"BM") && bytes.len() > 26 {
        Some("image/bmp")
    } else if starts(b"\x00\x00\x01\x00") {
        Some("image/x-icon")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const LOCAL: Checks = Checks {
        public: |_| true,
        any_port: true,
    };

    #[test]
    fn only_public_http_and_https_on_default_ports() {
        for ok in [
            "https://example.org/a.png?b=1",
            "http://example.org/a.png",
            "https://93.184.215.14/x.gif",
        ] {
            assert!(public_fetch::parse_public(ok, true).is_ok(), "{ok}");
        }
        for bad in [
            "https://example.org:8443/a.png",
            "http://example.org:8080/a.png",
            "https://user:pw@example.org/a.png",
            "ftp://example.org/a.png",
            "data:image/png;base64,AAAA",
            "http://127.0.0.1/a.png",
            "http://10.1.2.3/a.png",
            "http://169.254.169.254/latest/meta-data",
            "https://[::1]/a.png",
            "https://[fd00::1]/a.png",
            "https://[::ffff:192.168.1.1]/a.png",
            "http://0.0.0.0/a.png",
        ] {
            assert!(public_fetch::parse_public(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn known_trackers_are_named() {
        for (url, provider) in [
            (
                "https://example.us1.list-manage.com/track/open.php?u=1",
                "Mailchimp",
            ),
            ("https://u123.ct.sendgrid.net/wf/open?upn=x", "SendGrid"),
            ("https://r.us-east-1.awstrack.me/I0/0100/abc", "Amazon SES"),
            ("https://t.hubspotemail.net/e2t/to/abc", "HubSpot"),
            ("https://mailtrack.io/trace/mail/abc.png", "Mailtrack"),
        ] {
            assert_eq!(
                tracker_of(&Url::parse(url).unwrap()),
                Some(provider),
                "{url}"
            );
        }
        for url in [
            "https://mcusercontent.com/abc/images/logo.png",
            "https://example.us1.list-manage.com/images/logo.png",
            "https://cdn.example.org/track/open.png",
            "https://notsendgrid.net/wf/open",
        ] {
            assert_eq!(tracker_of(&Url::parse(url).unwrap()), None, "{url}");
        }
    }

    #[test]
    fn only_raster_images_pass() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(sniff_image(b"\xff\xd8\xff\xe0...."), Some("image/jpeg"));
        assert_eq!(sniff_image(b"GIF89a\x01\x00"), Some("image/gif"));
        assert_eq!(
            sniff_image(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            Some("image/webp")
        );
        assert_eq!(sniff_image(b"\x00\x00\x00\x1cftypavif"), Some("image/avif"));
        assert_eq!(
            sniff_image(b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
            None
        );
        assert_eq!(sniff_image(b"<!doctype html><script>"), None);
        assert_eq!(sniff_image(b""), None);
    }

    #[test]
    fn each_account_has_a_byte_budget() {
        let budget = ByteBudget::default();
        assert!(budget.has_room("a"));
        budget.charge("a", BYTES_PER_MINUTE as usize - 1);
        assert!(budget.has_room("a"));
        budget.charge("a", 1);
        assert!(!budget.has_room("a"));
        assert!(budget.has_room("b"));
    }

    /// Serves `responses` in turn on a local port, one per connection.
    async fn serve(responses: Vec<Vec<u8>>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = socket.read(&mut request).await;
                socket.write_all(&response).await.unwrap();
                let _ = socket.shutdown().await;
            }
        });
        address
    }

    fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn fetches_an_image_and_follows_a_redirect() {
        let png = b"\x89PNG\r\n\x1a\nrest-of-image".to_vec();
        let address = serve(vec![
            http("302 Found", "Location: /real.png\r\n", b""),
            http("200 OK", "Content-Type: application/octet-stream\r\n", &png),
        ])
        .await;
        let url = Url::parse(&format!("http://{address}/start.png")).unwrap();
        let (mime, body) = fetch_image(url, &LOCAL).await.unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(body, png);
    }

    #[tokio::test]
    async fn refuses_what_is_not_an_image() {
        let address = serve(vec![http(
            "200 OK",
            "Content-Type: image/png\r\n",
            b"<svg onload=alert(1)>",
        )])
        .await;
        let url = Url::parse(&format!("http://{address}/x.png")).unwrap();
        assert!(fetch_image(url, &LOCAL).await.is_err());
    }

    #[tokio::test]
    async fn a_redirect_to_a_tracker_stops() {
        let address = serve(vec![http(
            "302 Found",
            "Location: https://x.list-manage.com/track/open.php?u=1\r\n",
            b"",
        )])
        .await;
        let url = Url::parse(&format!("http://{address}/x.png")).unwrap();
        assert!(fetch_image(url, &LOCAL).await.is_err());
    }

    #[tokio::test]
    async fn private_addresses_are_never_fetched() {
        let address = serve(vec![http("200 OK", "", b"GIF89a")]).await;
        let url = Url::parse(&format!("http://{address}/x.gif")).unwrap();
        assert!(fetch_image(url, &Checks::PUBLIC).await.is_err());
    }
}
