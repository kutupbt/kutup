//! The mail image proxy (docs/plans/mail-parity.md, P5), as Proton's
//! `core/v4/images`: when a reader loads a message's remote images, the
//! Kutup server fetches each one and hands the bytes back. The sender then
//! sees the server, not the reader's address or browser; it still learns that
//! and when the message was read. Nothing is stored or cached.
//!
//! `POST /api/mail/images` with `{ url }`: one image. The address travels in
//! the body, never in a URL that a proxy or access log would keep. A known
//! tracker answers 204 with `X-Kutup-Tracker` and is never fetched, nor
//! followed to by a redirect. The reader checks the same list
//! (`mail-core/src/trackers.json`) before asking, so nothing is sent for an
//! image that is not loaded.
//!
//! The fetch goes through `public_fetch` (public addresses only, pinned,
//! redirects checked again), with http on port 80 allowed too, one deadline
//! for the whole fetch, and only raster images, recognised by their bytes
//! (never SVG, which could run script if opened on its own). An account may
//! ask 120 images a minute, fetch 6 at once and 64 MiB a minute (each fetch
//! reserves the most it may bring); the server fetches 32 at once.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use url::Url;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::public_fetch::{self, Checks, Options};
use crate::ratelimit::{Limit, RateLimiter};

const IMAGE_LIMIT_BYTES: usize = 5 * 1024 * 1024;
/// Bytes an account may fetch a minute, refilled evenly
/// (`mail_image_bytes`; the account's own where set).
fn bytes_per_minute(account: &str) -> f64 {
    crate::ratelimit::value_for(Limit::MailImageBytes, account) as f64
}
/// Images an account fetches at once (`mail_images_at_once`, 6 at first:
/// the reader asks six at a time).
fn per_account_at_once(account: &str) -> usize {
    usize::try_from(crate::ratelimit::value_for(
        Limit::MailImagesAtOnce,
        account,
    ))
    .unwrap_or(usize::MAX)
}
/// The whole fetch, redirects included.
const DEADLINE: Duration = Duration::from_secs(10);
const USER_AGENT: &str = "Mozilla/5.0 (compatible; KutupImageProxy/1.0)";
/// The header that names a blocked tracker's provider (Proton's
/// `x-pm-tracker-provider`).
pub const TRACKER_HEADER: &str = "x-kutup-tracker";

/// 120 images a minute per account, as Pass icons' fetches.
pub(crate) static MAIL_IMAGES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::MailImages));
static BYTES: LazyLock<ByteBudget> = LazyLock::new(ByteBudget::default);
static AT_ONCE: LazyLock<AccountSlots> = LazyLock::new(AccountSlots::default);
static FETCHING: LazyLock<ServerSlots> = LazyLock::new(ServerSlots::default);

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
pub struct ImageRequest {
    /// The image's address in the message: http or https.
    pub url: String,
}

#[utoipa::path(
    post,
    path = "/api/mail/images",
    tag = "mail",
    operation_id = "fetchMailImage",
    request_body = ImageRequest,
    responses(
        (status = 200, description = "The image's bytes, with its type"),
        (status = 204, description = "A known tracking pixel, never fetched; X-Kutup-Tracker names it"),
        (status = 400, description = "Not a public http or https address"),
        (status = 422, description = "The site did not answer with an image in time"),
        (status = 429, description = "Too many images, or bytes, for now"),
        (status = 503, description = "The proxy is busy"),
    ),
    security(("BearerAuth" = []))
)]
pub async fn fetch(auth: AuthUser, Json(request): Json<ImageRequest>) -> AppResult<Response> {
    if !MAIL_IMAGES.allow(&auth.user_id) {
        return Err(AppError::too_many_requests(
            "too many images; try again shortly",
        ));
    }
    let url = public_fetch::parse_public(request.url.trim(), true)?;
    if let Some(provider) = tracker_of(&url) {
        return Ok(tracker_response(provider));
    }
    let _slot = AT_ONCE
        .take(&auth.user_id)
        .ok_or_else(|| AppError::too_many_requests("too many images at once; try again shortly"))?;
    // The most this fetch may bring, held until it is known; never given back on failure.
    if !BYTES.reserve(&auth.user_id, IMAGE_LIMIT_BYTES as f64) {
        return Err(AppError::too_many_requests(
            "too many image bytes this minute; try again shortly",
        ));
    }
    let _permit = tokio::time::timeout(DEADLINE, FETCHING.acquire())
        .await
        .map_err(|_| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "the image proxy is busy; try again shortly",
            )
        })?;
    let fetched = tokio::time::timeout(DEADLINE, fetch_image(url, &Checks::PUBLIC))
        .await
        .map_err(|_| public_fetch::unusable("the site did not answer in time"))??;
    let (mime, body) = match fetched {
        Fetched::Image(mime, body) => (mime, body),
        Fetched::Tracker(provider) => return Ok(tracker_response(provider)),
    };
    BYTES.give_back(&auth.user_id, (IMAGE_LIMIT_BYTES - body.len()) as f64);
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

/// Bytes per account as a bucket refilled evenly ([`bytes_per_minute`]): a
/// fetch takes the most it may bring before it starts, under one lock, and
/// what it did not use comes back when it succeeds.
#[derive(Default)]
struct ByteBudget {
    buckets: Mutex<HashMap<String, (Instant, f64)>>,
}

impl ByteBudget {
    fn reserve(&self, account: &str, bytes: f64) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("byte budget lock");
        let per_minute = bytes_per_minute(account);
        let (at, left) = buckets
            .entry(account.to_owned())
            .or_insert((now, per_minute));
        *left = (*left + now.duration_since(*at).as_secs_f64() * per_minute / 60.0).min(per_minute);
        *at = now;
        if *left < bytes {
            return false;
        }
        *left -= bytes;
        true
    }

    fn give_back(&self, account: &str, bytes: f64) {
        let mut buckets = self.buckets.lock().expect("byte budget lock");
        if let Some((_, left)) = buckets.get_mut(account) {
            *left = (*left + bytes).min(bytes_per_minute(account));
        }
    }

    /// Forgets buckets that would be full again.
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();
        self.buckets
            .lock()
            .expect("byte budget lock")
            .retain(|account, (at, left)| {
                let per_minute = bytes_per_minute(account);
                *left + now.duration_since(*at).as_secs_f64() * per_minute / 60.0 < per_minute
            });
    }
}

/// Fetches under way per account ([`per_account_at_once`]).
#[derive(Default)]
struct AccountSlots {
    taken: Mutex<HashMap<String, usize>>,
}

struct Slot<'a> {
    slots: &'a AccountSlots,
    account: String,
}

impl AccountSlots {
    fn take(&self, account: &str) -> Option<Slot<'_>> {
        let mut taken = self.taken.lock().expect("image slots lock");
        let count = taken.entry(account.to_owned()).or_insert(0);
        if *count >= per_account_at_once(account) {
            return None;
        }
        *count += 1;
        Some(Slot {
            slots: self,
            account: account.to_owned(),
        })
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut taken = self.slots.taken.lock().expect("image slots lock");
        if let Some(count) = taken.get_mut(&self.account) {
            *count -= 1;
            if *count == 0 {
                taken.remove(&self.account);
            }
        }
    }
}

/// Fetches under way on this server, for all accounts
/// (`mail_images_server_at_once`, read at each try so a change applies at
/// once); the others wait their turn.
#[derive(Default)]
struct ServerSlots {
    taken: Mutex<usize>,
    freed: tokio::sync::Notify,
}

struct ServerSlot<'a>(&'a ServerSlots);

impl ServerSlots {
    async fn acquire(&self) -> ServerSlot<'_> {
        loop {
            // Asked for before the check, so a slot freed in between wakes it.
            let freed = self.freed.notified();
            {
                let mut taken = self.taken.lock().expect("server slots lock");
                let limit = usize::try_from(crate::ratelimit::value(Limit::MailImagesServerAtOnce))
                    .unwrap_or(usize::MAX);
                if *taken < limit {
                    *taken += 1;
                    return ServerSlot(self);
                }
            }
            freed.await;
        }
    }
}

impl Drop for ServerSlot<'_> {
    fn drop(&mut self) {
        *self.0.taken.lock().expect("server slots lock") -= 1;
        self.0.freed.notify_one();
    }
}

/// Run by `ratelimit::spawn_cleanup`.
pub(crate) fn cleanup() {
    BYTES.cleanup();
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

enum Fetched {
    Image(&'static str, Vec<u8>),
    /// A redirect led to a known tracker, which was not followed.
    Tracker(&'static str),
}

/// Fetches one image; a redirect to a tracker is not followed.
async fn fetch_image(url: Url, checks: &Checks) -> AppResult<Fetched> {
    let tracker: Mutex<Option<&'static str>> = Mutex::new(None);
    let follow = |next: &Url| match tracker_of(next) {
        Some(provider) => {
            *tracker.lock().expect("tracker lock") = Some(provider);
            false
        }
        None => true,
    };
    let fetched = public_fetch::fetch(
        url,
        &public_fetch::Request {
            accept: "image/avif,image/webp,image/png,image/jpeg,image/gif;q=0.9,image/*;q=0.8",
            user_agent: USER_AGENT,
            timeout: DEADLINE,
            limit: IMAGE_LIMIT_BYTES,
            truncate: false,
            // Sites often send images under another type; the bytes decide.
            wanted: &|_| true,
            body: None,
        },
        &Options {
            allow_http: true,
            redirects: public_fetch::Redirects::Follow,
            follow: &follow,
        },
        checks,
    )
    .await;
    if let Some(provider) = *tracker.lock().expect("tracker lock") {
        return Ok(Fetched::Tracker(provider));
    }
    let fetched = fetched?;
    let mime = sniff_image(&fetched.body)
        .ok_or_else(|| public_fetch::unusable("the site did not return an image"))?;
    Ok(Fetched::Image(mime, fetched.body))
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
        let Fetched::Image(mime, body) = fetch_image(url, &LOCAL).await.unwrap() else {
            panic!("an image");
        };
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
    async fn a_redirect_to_a_tracker_is_that_tracker() {
        let address = serve(vec![http(
            "302 Found",
            "Location: https://x.list-manage.com/track/open.php?u=1\r\n",
            b"",
        )])
        .await;
        let url = Url::parse(&format!("http://{address}/x.png")).unwrap();
        assert!(matches!(
            fetch_image(url, &LOCAL).await,
            Ok(Fetched::Tracker("Mailchimp"))
        ));
    }

    #[tokio::test]
    async fn private_addresses_are_never_fetched() {
        let address = serve(vec![http("200 OK", "", b"GIF89a")]).await;
        let url = Url::parse(&format!("http://{address}/x.gif")).unwrap();
        assert!(fetch_image(url, &Checks::PUBLIC).await.is_err());
    }

    #[test]
    fn the_byte_budget_is_reserved_first_and_refills() {
        let budget = ByteBudget::default();
        let image = IMAGE_LIMIT_BYTES as f64;
        let mut taken = 0;
        while budget.reserve("a", image) {
            taken += 1;
        }
        // 64 MiB holds twelve 5 MiB reservations, not thirteen.
        assert_eq!(taken, 12);
        assert!(budget.reserve("b", image));
        // A small image gives back what it did not use.
        budget.give_back("a", image);
        assert!(budget.reserve("a", image));
        assert!(!budget.reserve("a", image));
    }

    #[test]
    fn an_account_fetches_six_at_once() {
        let slots = AccountSlots::default();
        let held: Vec<_> = (0..per_account_at_once("a"))
            .map(|_| slots.take("a").unwrap())
            .collect();
        assert!(slots.take("a").is_none());
        assert!(slots.take("b").is_some());
        drop(held);
        assert!(slots.take("a").is_some());
    }

    /// The reader checks the same list before it asks (`trackers.json`).
    #[test]
    fn the_reader_has_the_same_tracker_list() {
        #[derive(Deserialize)]
        struct Row {
            host: String,
            path: String,
            provider: String,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../frontend/packages/mail-core/src/trackers.json");
        let rows: Vec<Row> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let theirs: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|r| (r.host.as_str(), r.path.as_str(), r.provider.as_str()))
            .collect();
        assert_eq!(theirs, TRACKERS);
    }
}
