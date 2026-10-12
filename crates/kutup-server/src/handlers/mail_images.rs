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
//! The fetcher runs inside the server's network, so it is narrow, as the Chat
//! link preview's: http on port 80 or https on 443, every resolved address
//! public, the connection pinned to the checked address (no DNS rebinding),
//! redirects followed by hand and checked again, size and time limits, a
//! per-account rate limit, and only raster images, recognised by their bytes
//! (never SVG, which could run script if opened on its own).

use std::net::{IpAddr, SocketAddr};
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
use crate::ratelimit::RateLimiter;
use crate::AppState;

const IMAGE_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_URL_BYTES: usize = 4096;
const MAX_CHECK_URLS: usize = 500;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const USER_AGENT: &str = "Mozilla/5.0 (compatible; KutupImageProxy/1.0)";
/// The header that names a blocked tracker's provider (Proton's
/// `x-pm-tracker-provider`).
pub const TRACKER_HEADER: &str = "x-kutup-tracker";

/// 600 images a minute per account: a newsletter can carry a hundred.
static MAIL_IMAGES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(600, Duration::from_secs(60)));

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
    let url = parse_public(query.url.trim(), false)?;
    if let Some(provider) = tracker_of(&url) {
        return Ok(tracker_response(provider));
    }
    let (mime, body) = fetch_image(url, false).await?;
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
        ],
        body,
    )
        .into_response())
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

fn unusable(message: &'static str) -> AppError {
    AppError::new(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// Fetches one image, following redirects by hand; a redirect to a tracker
/// or to a private address stops it. `allow_private` is for tests only.
async fn fetch_image(mut url: Url, allow_private: bool) -> AppResult<(&'static str, Vec<u8>)> {
    for _ in 0..=MAX_REDIRECTS {
        let address = resolve(&url, allow_private).await?;
        let host = url.host_str().expect("checked host").to_owned();
        let client = reqwest::Client::builder()
            .resolve(&host, address)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| AppError::internal("image proxy client"))?;
        let response = client
            .get(url.clone())
            .header(
                reqwest::header::ACCEPT,
                "image/avif,image/webp,image/png,image/jpeg,image/gif;q=0.9,image/*;q=0.8",
            )
            .send()
            .await
            .map_err(|_| unusable("the site did not answer"))?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| unusable("the site redirected nowhere"))?;
            let next = url
                .join(location)
                .map_err(|_| unusable("the site redirected to an invalid address"))?;
            url = parse_public(next.as_str(), allow_private)
                .map_err(|_| unusable("the site redirected to an address that is not public"))?;
            if tracker_of(&url).is_some() {
                return Err(unusable("the site redirected to a tracker"));
            }
            continue;
        }
        if !response.status().is_success() {
            return Err(unusable("the site did not return the image"));
        }
        if response
            .content_length()
            .is_some_and(|length| length > IMAGE_LIMIT_BYTES as u64)
        {
            return Err(unusable("the image is too large"));
        }
        let body = read_limited(response).await?;
        let mime =
            sniff_image(&body).ok_or_else(|| unusable("the site did not return an image"))?;
        return Ok((mime, body));
    }
    Err(unusable("the site redirected too many times"))
}

async fn read_limited(mut response: reqwest::Response) -> AppResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| unusable("the site stopped answering"))?
    {
        if body.len() + chunk.len() > IMAGE_LIMIT_BYTES {
            return Err(unusable("the image is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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

/// An http URL on port 80 or https on 443, with a host name or a public IP
/// and no credentials.
fn parse_public(value: &str, allow_private: bool) -> AppResult<Url> {
    if value.len() > MAX_URL_BYTES {
        return Err(AppError::bad_request("the image address is too long"));
    }
    let url =
        Url::parse(value).map_err(|_| AppError::bad_request("the image address is not a URL"))?;
    let port_ok = match url.scheme() {
        "https" => url.port_or_known_default() == Some(443),
        "http" => url.port_or_known_default() == Some(80) || allow_private,
        _ => false,
    };
    if !port_ok
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none_or(str::is_empty)
    {
        return Err(not_public());
    }
    if !allow_private {
        if let Some(url::Host::Ipv4(ip)) = url.host() {
            ensure_public(IpAddr::V4(ip))?;
        }
        if let Some(url::Host::Ipv6(ip)) = url.host() {
            ensure_public(IpAddr::V6(ip))?;
        }
    }
    Ok(url)
}

/// Resolves the host and checks every address; the fetch then connects to
/// the first one only, so a second lookup cannot swap in a private address.
async fn resolve(url: &Url, allow_private: bool) -> AppResult<SocketAddr> {
    let host = url.host_str().expect("checked host");
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| unusable("the site's name did not resolve"))?
        .collect();
    if addresses.is_empty() {
        return Err(unusable("the site's name did not resolve"));
    }
    if !allow_private {
        for address in &addresses {
            ensure_public(address.ip())?;
        }
    }
    Ok(addresses[0])
}

fn ensure_public(ip: IpAddr) -> AppResult<()> {
    if crate::ssrf::is_public(ip) {
        Ok(())
    } else {
        Err(not_public())
    }
}

fn not_public() -> AppError {
    AppError::bad_request("only public http and https images load through the proxy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn only_public_http_and_https_on_default_ports() {
        for ok in [
            "https://example.org/a.png?b=1",
            "http://example.org/a.png",
            "https://93.184.215.14/x.gif",
        ] {
            assert!(parse_public(ok, false).is_ok(), "{ok}");
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
            assert!(parse_public(bad, false).is_err(), "{bad}");
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
        let (mime, body) = fetch_image(url, true).await.unwrap();
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
        assert!(fetch_image(url, true).await.is_err());
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
        assert!(fetch_image(url, true).await.is_err());
    }

    #[tokio::test]
    async fn private_addresses_are_never_fetched() {
        let address = serve(vec![http("200 OK", "", b"GIF89a")]).await;
        let url = Url::parse(&format!("http://{address}/x.gif")).unwrap();
        assert!(fetch_image(url, false).await.is_err());
    }
}
