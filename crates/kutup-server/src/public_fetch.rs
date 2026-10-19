//! The one narrow fetcher for public web content the server gets on a
//! user's behalf: Chat link previews, Kutup Pass site icons, Mail's image
//! proxy, outside mail keys (WKD and keyservers) and one-click unsubscribe.
//! Nothing else in the server makes outbound requests to addresses a user
//! gave, except federation, whose transport checks peers with the same
//! address list (`ssrf::is_public`), and Web Push, which reaches only the
//! push services on the operator's host allow-list.
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
/// One-click unsubscribe addresses carry long signed tokens.
pub const MAX_LONG_URL_BYTES: usize = 8192;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// What to fetch and how much of it.
pub struct Request<'a> {
    pub accept: &'a str,
    pub user_agent: &'a str,
    pub timeout: Duration,
    /// The most bytes read; 0: the status only, the body is not read (one
    /// whose content does not matter cannot then hold the answer back).
    pub limit: usize,
    /// Over the limit: cut the body there (a page, whose head comes first)
    /// rather than refuse it (an image).
    pub truncate: bool,
    /// Whether the answer's media type (lowercase, without parameters) is
    /// wanted; checked before the body is read.
    pub wanted: &'a (dyn Fn(&str) -> bool + Sync),
    /// A POST with this body (its media type and bytes) instead of a GET.
    pub body: Option<(&'a str, &'a [u8])>,
}

pub struct Fetched {
    /// The answer's status: a success, or a redirect when [`Redirects::Stop`].
    pub status: StatusCode,
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

/// What a fetch does with a redirect.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Redirects {
    /// Followed (at most three), each target checked again.
    Follow,
    /// Not followed: the redirect is the answer (one-click unsubscribe,
    /// where a redirect means the request was taken).
    Stop,
}

/// More than most callers need.
pub struct Options<'a> {
    /// http on port 80 too, for the first address and redirects.
    pub allow_http: bool,
    pub redirects: Redirects,
    /// Whether a redirect's target may be followed; refused, nothing is fetched from it.
    pub follow: &'a (dyn Fn(&Url) -> bool + Sync),
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            allow_http: false,
            redirects: Redirects::Follow,
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
    // A POST is not sent again to wherever a redirect points.
    if request.body.is_some() && options.redirects == Redirects::Follow {
        return Err(AppError::internal("a POST does not follow redirects"));
    }
    for _ in 0..=MAX_REDIRECTS {
        let address = resolve_public(&url, checks.public).await?;
        let host = url.host_str().expect("checked host").to_owned();
        let client = crate::tls::client_builder()
            .resolve(&host, address)
            // A proxy from the environment would resolve the name again.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(request.timeout)
            .user_agent(request.user_agent)
            .build()
            .map_err(|_| AppError::internal("public fetch client"))?;
        let builder = match request.body {
            Some((media_type, bytes)) => client
                .post(url.clone())
                .header(reqwest::header::CONTENT_TYPE, media_type)
                .body(bytes.to_vec()),
            None => client.get(url.clone()),
        };
        let response = builder
            .header(reqwest::header::ACCEPT, request.accept)
            .send()
            .await
            .map_err(|_| unusable("the site did not answer"))?;
        let status = StatusCode::from_u16(response.status().as_u16())
            .map_err(|_| unusable("the site answered oddly"))?;
        if response.status().is_redirection() && options.redirects == Redirects::Stop {
            return Ok(Fetched {
                status,
                final_url: url,
                content_type: String::new(),
                body: Vec::new(),
            });
        }
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| unusable("the site redirected nowhere"))?;
            let next = url
                .join(location)
                .map_err(|_| unusable("the site redirected to an invalid address"))?;
            url = parse_checked(next.as_str(), options.allow_http, checks, MAX_URL_BYTES)?;
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
        let body = if request.limit == 0 {
            Vec::new()
        } else {
            read_limited(response, request.limit, request.truncate).await?
        };
        return Ok(Fetched {
            status,
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
    parse_checked(value, false, &Checks::PUBLIC, MAX_URL_BYTES)
}

/// [`parse_public_https`] for an address up to [`MAX_LONG_URL_BYTES`].
pub fn parse_long_public_https(value: &str) -> AppResult<Url> {
    parse_checked(value, false, &Checks::PUBLIC, MAX_LONG_URL_BYTES)
}

/// [`parse_public_https`], or http on port 80 as well.
pub fn parse_public(value: &str, allow_http: bool) -> AppResult<Url> {
    parse_checked(value, allow_http, &Checks::PUBLIC, MAX_URL_BYTES)
}

fn parse_checked(
    value: &str,
    allow_http: bool,
    checks: &Checks,
    max_bytes: usize,
) -> AppResult<Url> {
    if value.len() > max_bytes {
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
    fn only_unsubscribe_addresses_may_be_long() {
        let long = format!("https://example.org/u?t={}", "a".repeat(4000));
        assert!(parse_public_https(&long).is_err());
        assert!(parse_long_public_https(&long).is_ok());
        let too_long = format!("https://example.org/u?t={}", "a".repeat(MAX_LONG_URL_BYTES));
        assert!(parse_long_public_https(&too_long).is_err());
        assert!(parse_long_public_https("https://127.0.0.1/u").is_err());
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

    mod served {
        use super::super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const LOCAL: Checks = Checks {
            public: |_| true,
            any_port: true,
        };

        /// Serves `responses` in turn, one per connection; the requests it
        /// read come back on the channel.
        async fn serve(
            responses: Vec<String>,
        ) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (seen, requests) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                for response in responses {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = vec![0u8; 8192];
                    let n = socket.read(&mut request).await.unwrap_or(0);
                    let _ = seen.send(String::from_utf8_lossy(&request[..n]).into_owned());
                    socket.write_all(response.as_bytes()).await.unwrap();
                    let _ = socket.shutdown().await;
                }
            });
            (address, requests)
        }

        fn http(status: &str, headers: &str, body: &str) -> String {
            format!(
                "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        fn request<'a>(body: Option<(&'a str, &'a [u8])>) -> Request<'a> {
            Request {
                accept: "*/*",
                user_agent: "test",
                timeout: Duration::from_secs(5),
                limit: 1024,
                truncate: false,
                wanted: &|_| true,
                body,
            }
        }

        fn local(options: Redirects) -> Options<'static> {
            Options {
                allow_http: true,
                redirects: options,
                follow: &|_| true,
            }
        }

        #[tokio::test]
        async fn a_post_carries_its_body_and_a_stopped_redirect_is_the_answer() {
            let (address, mut requests) =
                serve(vec![http("302 Found", "Location: /elsewhere\r\n", "")]).await;
            let url = Url::parse(&format!("http://{address}/unsubscribe")).unwrap();
            let answer = fetch(
                url,
                &request(Some((
                    "application/x-www-form-urlencoded",
                    b"List-Unsubscribe=One-Click",
                ))),
                &local(Redirects::Stop),
                &LOCAL,
            )
            .await
            .unwrap();
            assert_eq!(answer.status, StatusCode::FOUND);
            let sent = requests.recv().await.unwrap();
            assert!(sent.starts_with("POST /unsubscribe "), "{sent}");
            assert!(sent.contains("application/x-www-form-urlencoded"), "{sent}");
            assert!(sent.ends_with("List-Unsubscribe=One-Click"), "{sent}");
            // Not followed: nothing else was asked.
            assert!(requests.try_recv().is_err());
        }

        #[tokio::test]
        async fn a_get_follows_redirects_by_default() {
            let (address, mut requests) = serve(vec![
                http("302 Found", "Location: /there\r\n", ""),
                http("200 OK", "Content-Type: text/plain\r\n", "arrived"),
            ])
            .await;
            let url = Url::parse(&format!("http://{address}/here")).unwrap();
            let answer = fetch(url, &request(None), &local(Redirects::Follow), &LOCAL)
                .await
                .unwrap();
            assert_eq!(answer.status, StatusCode::OK);
            assert_eq!(answer.body, b"arrived");
            assert!(requests.recv().await.unwrap().starts_with("GET /here "));
            assert!(requests.recv().await.unwrap().starts_with("GET /there "));
        }

        #[tokio::test]
        async fn a_post_never_follows_redirects() {
            let url = Url::parse("http://127.0.0.1:9/unsubscribe").unwrap();
            let refused = fetch(
                url,
                &request(Some(("text/plain", b"x"))),
                &local(Redirects::Follow),
                &LOCAL,
            )
            .await;
            assert!(refused.is_err());
        }

        #[tokio::test]
        async fn the_status_alone_does_not_read_the_body() {
            // Promises far more than it sends: reading the body would fail.
            let (address, _requests) = serve(vec![
                "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\npartial"
                    .to_owned(),
            ])
            .await;
            let url = Url::parse(&format!("http://{address}/u")).unwrap();
            let answer = fetch(
                url,
                &Request {
                    limit: 0,
                    ..request(Some(("text/plain", b"x")))
                },
                &local(Redirects::Stop),
                &LOCAL,
            )
            .await
            .unwrap();
            assert_eq!(answer.status, StatusCode::OK);
            assert!(answer.body.is_empty());
        }

        #[tokio::test]
        async fn an_error_answer_is_unusable() {
            let (address, _requests) = serve(vec![http("500 Internal Server Error", "", "")]).await;
            let url = Url::parse(&format!("http://{address}/x")).unwrap();
            assert!(
                fetch(url, &request(None), &local(Redirects::Follow), &LOCAL)
                    .await
                    .is_err()
            );
        }
    }
}
