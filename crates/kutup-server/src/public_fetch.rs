//! A narrow fetcher for public web content the server gets on a user's
//! behalf: Chat link previews, Kutup Pass site icons and Mail's image proxy.
//!
//! It runs inside the server's network, so it fetches only https on port
//! 443 (and, when a caller asks, http on port 80: mail images), every
//! resolved address public (no loopback, private, link-local,
//! multicast, carrier-grade NAT, documentation or mapped ranges), with the
//! connection pinned to the checked address (no DNS rebinding), redirects
//! followed by hand and checked again, no credentials or cookies, and strict
//! size and time limits. Callers add their own rate limits.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::http::StatusCode;
use url::Url;

use crate::error::{AppError, AppResult};

const MAX_REDIRECTS: usize = 3;
const MAX_URL_BYTES: usize = 2048;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// What to fetch and how much of it.
pub struct Request<'a> {
    pub accept: &'a str,
    pub user_agent: &'a str,
    pub timeout: Duration,
    /// The most bytes read.
    pub limit: usize,
    /// Over the limit: cut the body there (a page, whose head comes first)
    /// rather than refuse it (an image).
    pub truncate: bool,
    /// Whether the answer's media type (lowercase, without parameters) is
    /// wanted; checked before the body is read.
    pub wanted: &'a (dyn Fn(&str) -> bool + Sync),
}

pub struct Fetched {
    /// Where the content came from after redirects.
    pub final_url: Url,
    /// Lowercase, without parameters.
    pub content_type: String,
    pub body: Vec<u8>,
}

/// The site could not give what was asked (422).
pub fn unusable(message: &'static str) -> AppError {
    AppError::new(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// More than most callers need.
pub struct Options<'a> {
    /// http on port 80 too, for the first address and redirects.
    pub allow_http: bool,
    /// Whether a redirect's target may be followed; refused, nothing is fetched from it.
    pub follow: &'a (dyn Fn(&Url) -> bool + Sync),
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            allow_http: false,
            follow: &|_| true,
        }
    }
}

/// Fetches `url`, following at most three redirects, each checked again.
pub async fn get(url: Url, request: &Request<'_>) -> AppResult<Fetched> {
    get_with(url, request, &Options::default()).await
}

/// [`get`], with [`Options`].
pub async fn get_with(
    url: Url,
    request: &Request<'_>,
    options: &Options<'_>,
) -> AppResult<Fetched> {
    fetch(url, request, options, &Checks::PUBLIC).await
}

/// Which addresses may be reached: always [`Checks::PUBLIC`] but in tests,
/// which reach a local listener on any port.
pub(crate) struct Checks {
    pub public: fn(IpAddr) -> bool,
    pub any_port: bool,
}

impl Checks {
    pub(crate) const PUBLIC: Checks = Checks {
        public: crate::ssrf::is_public,
        any_port: false,
    };
}

/// The fetch, with the [`Checks`] given.
pub(crate) async fn fetch(
    mut url: Url,
    request: &Request<'_>,
    options: &Options<'_>,
    checks: &Checks,
) -> AppResult<Fetched> {
    for _ in 0..=MAX_REDIRECTS {
        let address = resolve_public(&url, checks.public).await?;
        let host = url.host_str().expect("checked host").to_owned();
        let client = reqwest::Client::builder()
            .resolve(&host, address)
            // A proxy from the environment would resolve the name again.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(request.timeout)
            .user_agent(request.user_agent)
            .build()
            .map_err(|_| AppError::internal("public fetch client"))?;
        let response = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, request.accept)
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
            url = parse_checked(next.as_str(), options.allow_http, checks)?;
            if !(options.follow)(&url) {
                return Err(unusable("the site redirected somewhere refused"));
            }
            continue;
        }
        if !response.status().is_success() {
            return Err(unusable("the site did not return it"));
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
        if !(request.wanted)(&content_type) {
            return Err(unusable("the site returned something else"));
        }
        let body = read_limited(response, request.limit, request.truncate).await?;
        return Ok(Fetched {
            final_url: url,
            content_type,
            body,
        });
    }
    Err(unusable("the site redirected too many times"))
}

async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
    truncate: bool,
) -> AppResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| unusable("the site stopped answering"))?
    {
        if body.len() + chunk.len() > limit {
            if !truncate {
                return Err(unusable("the answer is too large"));
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
pub fn parse_public_https(value: &str) -> AppResult<Url> {
    parse_checked(value, false, &Checks::PUBLIC)
}

/// [`parse_public_https`], or http on port 80 as well.
pub fn parse_public(value: &str, allow_http: bool) -> AppResult<Url> {
    parse_checked(value, allow_http, &Checks::PUBLIC)
}

fn parse_checked(value: &str, allow_http: bool, checks: &Checks) -> AppResult<Url> {
    if value.len() > MAX_URL_BYTES {
        return Err(AppError::bad_request("the address is too long"));
    }
    let url = Url::parse(value).map_err(|_| AppError::bad_request("not a URL"))?;
    let scheme_ok = match url.scheme() {
        "https" => checks.any_port || url.port_or_known_default() == Some(443),
        "http" => allow_http && (checks.any_port || url.port_or_known_default() == Some(80)),
        _ => false,
    };
    if !scheme_ok
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none_or(str::is_empty)
    {
        return Err(not_public());
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ensure_public(IpAddr::V4(ip), checks.public)?,
        Some(url::Host::Ipv6(ip)) => ensure_public(IpAddr::V6(ip), checks.public)?,
        _ => {}
    }
    Ok(url)
}

/// Resolves the host and checks every address; the fetch then connects to
/// the first one only, so a second lookup cannot swap in a private address.
async fn resolve_public(url: &Url, public: fn(IpAddr) -> bool) -> AppResult<SocketAddr> {
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
    for address in &addresses {
        ensure_public(address.ip(), public)?;
    }
    Ok(addresses[0])
}

fn ensure_public(ip: IpAddr, public: fn(IpAddr) -> bool) -> AppResult<()> {
    if public(ip) {
        Ok(())
    } else {
        Err(not_public())
    }
}

fn not_public() -> AppError {
    AppError::bad_request("only public addresses are fetched")
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
            assert!(
                !crate::ssrf::is_public(private.parse().unwrap()),
                "{private}"
            );
        }
        for public in ["1.1.1.1", "93.184.215.14", "2606:4700:4700::1111"] {
            assert!(crate::ssrf::is_public(public.parse().unwrap()), "{public}");
        }
    }
}
