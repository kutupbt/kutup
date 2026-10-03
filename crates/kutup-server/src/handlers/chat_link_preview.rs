//! `POST /api/chat/link-preview` — fetch one public web page or image for a
//! Chat link preview made by the sender.
//!
//! Browsers cannot read another site's page, so the sender's own homeserver
//! fetches it; the preview then travels end-to-end encrypted inside the
//! message and recipients never contact the site. The server sees the link
//! (never the message) and returns the raw bytes: the browser parses the page
//! with `DOMParser` (no scripts run) and resizes the image itself.
//!
//! The fetcher is deliberately narrow, since it runs inside the server's
//! network: https on port 443 only, every resolved address public (no
//! loopback, private, link-local, multicast, carrier-grade NAT, documentation
//! or mapped ranges), the connection pinned to the checked address (no DNS
//! rebinding), redirects followed by hand and checked again, strict size and
//! time limits, and a per-account rate limit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;
use crate::AppState;

const PAGE_LIMIT_BYTES: usize = 512 * 1024;
const IMAGE_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_URL_BYTES: usize = 2048;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const USER_AGENT: &str = "Mozilla/5.0 (compatible; KutupLinkPreview/1.0)";

/// 30 fetches a minute per account: a preview is one page and one image.
static LINK_PREVIEWS: LazyLock<RateLimiter> =
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
    let mut url = parse_public_https(&request.url)?;
    for _ in 0..=MAX_REDIRECTS {
        let address = resolve_public(&url).await?;
        let host = url.host_str().expect("checked host").to_owned();
        let client = reqwest::Client::builder()
            .resolve(&host, address)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| AppError::internal("link preview client"))?;
        let accept = match request.kind {
            LinkPreviewFetchKind::Page => "text/html,application/xhtml+xml;q=0.9",
            LinkPreviewFetchKind::Image => "image/webp,image/png,image/jpeg,image/gif;q=0.8",
        };
        let response = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, accept)
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
            url = parse_public_https(next.as_str())?;
            continue;
        }
        if !response.status().is_success() {
            return Err(unusable("the site did not return the page"));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let (allowed, limit) = match request.kind {
            LinkPreviewFetchKind::Page => (
                content_type == "text/html" || content_type == "application/xhtml+xml",
                PAGE_LIMIT_BYTES,
            ),
            LinkPreviewFetchKind::Image => (
                matches!(
                    content_type.as_str(),
                    "image/jpeg" | "image/png" | "image/webp" | "image/gif"
                ),
                IMAGE_LIMIT_BYTES,
            ),
        };
        if !allowed {
            return Err(unusable("the site did not return a page or image"));
        }
        let body = read_limited(response, limit, request.kind).await?;
        return Ok(Json(LinkPreviewFetchResponse {
            final_url: url.to_string(),
            content_type,
            body: STANDARD.encode(body),
        }));
    }
    Err(unusable("the site redirected too many times"))
}

fn unusable(message: &'static str) -> AppError {
    AppError::new(axum::http::StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// Reads at most `limit` bytes. A page is cut there (its head, where preview
/// tags live, comes first); an image over the limit is refused.
async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
    kind: LinkPreviewFetchKind,
) -> AppResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| unusable("the site stopped answering"))?
    {
        if body.len() + chunk.len() > limit {
            if kind == LinkPreviewFetchKind::Image {
                return Err(unusable("the image is too large"));
            }
            body.extend_from_slice(&chunk[..limit - body.len()]);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// An https URL on port 443 with a host name or a public IP and no
/// credentials.
fn parse_public_https(value: &str) -> AppResult<Url> {
    if value.len() > MAX_URL_BYTES {
        return Err(AppError::bad_request("the link is too long"));
    }
    let url = Url::parse(value).map_err(|_| AppError::bad_request("the link is not a URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.host_str().is_none_or(str::is_empty)
    {
        return Err(AppError::bad_request(
            "only public https links get a preview",
        ));
    }
    if let Some(url::Host::Ipv4(ip)) = url.host() {
        ensure_public(IpAddr::V4(ip))?;
    }
    if let Some(url::Host::Ipv6(ip)) = url.host() {
        ensure_public(IpAddr::V6(ip))?;
    }
    Ok(url)
}

/// Resolves the host and checks every address; the fetch then connects to
/// the first one only, so a second lookup cannot swap in a private address.
async fn resolve_public(url: &Url) -> AppResult<SocketAddr> {
    let host = url.host_str().expect("checked host");
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| unusable("the site's name did not resolve"))?
        .collect();
    if addresses.is_empty() {
        return Err(unusable("the site's name did not resolve"));
    }
    for address in &addresses {
        ensure_public(address.ip())?;
    }
    Ok(addresses[0])
}

fn ensure_public(ip: IpAddr) -> AppResult<()> {
    if is_public(ip) {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "only public https links get a preview",
        ))
    }
}

/// Globally routable unicast: not loopback, private, link-local, shared
/// (CGNAT), multicast, broadcast, documentation, benchmarking, reserved,
/// unique-local, or an IPv4 address wrapped in IPv6.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            let segments = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                // fc00::/7 unique local, fe80::/10 link-local
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                // 2001:db8::/32 documentation
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                // 64:ff9b::/96 NAT64 and ::/96 IPv4-compatible can reach IPv4 space
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || segments[..6] == [0, 0, 0, 0, 0, 0])
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        // 100.64.0.0/10 shared address space
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 protocol assignments
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15 benchmarking
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4 reserved
        || a >= 240)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_https_on_443_is_fetched() {
        for ok in [
            "https://example.org/a?b=1",
            "https://93.184.215.14/",
            "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/",
        ] {
            assert!(parse_public_https(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://example.org/",
            "https://example.org:8443/",
            "https://user:pw@example.org/",
            "ftp://example.org/",
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://[::ffff:192.168.1.1]/",
            "https://100.64.1.1/",
            "https://0.0.0.0/",
        ] {
            assert!(parse_public_https(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn private_and_special_ranges_are_not_public() {
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "100.100.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "64:ff9b::a00:1",
            "::a00:1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "93.184.215.14", "2606:4700:4700::1111"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }
}
