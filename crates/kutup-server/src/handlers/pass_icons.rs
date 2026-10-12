//! Kutup Pass site icons (docs/plans/pass.md, "Site icons"), as Proton
//! Pass's website favicons through its image proxy: the Kutup server fetches
//! an entry's website icon, so the browser never contacts the site. The
//! server then sees the domain (not the entry or the rest of its address).
//!
//! Each account chooses, as in Proton Pass, between icons through Kutup (the
//! default) and none (`pass_settings`). The browser never asks a website
//! itself, so the Pass page loads no outside images.
//!
//! - `GET/PUT /api/pass/settings`: that choice.
//! - `POST /api/pass/icon`: one domain's icon, refused unless the account
//!   chose Kutup. The domain travels in the body, so it stays out of access
//!   logs; icons are kept in memory only, never written down, and per
//!   account: a quick answer must not tell one account that another has
//!   asked for a domain.
//!
//! Each fetch that the cache cannot answer is limited per account, at most
//! a few run at once on the server, and asking again for a domain being
//! fetched waits for that fetch.
//!
//! Fetching goes through `public_fetch` (https, public addresses only). The
//! site's home page is read for its `<link rel="icon">` tags, then
//! `/favicon.ico` is tried; only raster images are returned, recognised by
//! their bytes (never SVG, which could run script if opened on its own).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::public_fetch;
use crate::ratelimit::RateLimiter;
use crate::AppState;

const PAGE_LIMIT_BYTES: usize = 512 * 1024;
const ICON_LIMIT_BYTES: usize = 512 * 1024;
const MAX_DOMAIN_BYTES: usize = 253;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// For one domain's whole search (page and icons).
const TOTAL_TIMEOUT: Duration = Duration::from_secs(12);
/// Icons the page names that are tried before `/favicon.ico`.
const MAX_LINKED_TRIES: usize = 2;
/// The CSS size icons show at is 32 px; twice that is sharp on dense screens.
const WANTED_PIXELS: u32 = 64;
const USER_AGENT: &str = "Mozilla/5.0 (compatible; KutupPassIcons/1.0)";

/// Found icons are kept a day, and a site without one an hour.
const FOUND_FOR: Duration = Duration::from_secs(24 * 60 * 60);
const MISSING_FOR: Duration = Duration::from_secs(60 * 60);
const CACHE_ENTRIES: usize = 16 * 1024;
const CACHE_BYTES: usize = 64 * 1024 * 1024;

/// 600 answers a minute per account: opening a large vault asks for many.
pub(crate) static PASS_ICONS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(600, Duration::from_secs(60)));
/// 120 domains fetched a minute per account (each a page and a few icons);
/// what the cache answers does not count.
pub(crate) static PASS_ICON_FETCHES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(120, Duration::from_secs(60)));
/// Domains fetched at once on this server, for all accounts.
static FETCHING: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(16));
/// The fetch under way per account and domain, which a second ask waits for.
static IN_FLIGHT: LazyLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// How an account's entries get their website's icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SiteIcons {
    /// Fetched by the Kutup server, which sees the domain.
    Kutup,
    Off,
}

impl SiteIcons {
    fn as_str(self) -> &'static str {
        match self {
            Self::Kutup => "kutup",
            Self::Off => "off",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "off" => Self::Off,
            _ => Self::Kutup,
        }
    }
}

/// The account's Kutup Pass settings, the same on every device.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassSettings {
    pub site_icons: SiteIcons,
}

async fn site_icons(state: &AppState, user: &AuthUser) -> AppResult<SiteIcons> {
    let user_id = trusted_uuid(&user.user_id)?;
    let stored: Option<String> =
        sqlx::query_scalar("SELECT site_icons FROM pass_settings WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(stored.map_or(SiteIcons::Kutup, |value| SiteIcons::parse(&value)))
}

/// `GET /api/pass/settings` — the account's Kutup Pass settings.
#[utoipa::path(
    get,
    path = "/api/pass/settings",
    tag = "pass",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The settings", body = PassSettings))
)]
pub async fn get_settings(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<PassSettings>> {
    Ok(Json(PassSettings {
        site_icons: site_icons(&state, &user).await?,
    }))
}

/// `PUT /api/pass/settings` — changes them.
#[utoipa::path(
    put,
    path = "/api/pass/settings",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = PassSettings,
    responses(
        (status = 204, description = "Saved"),
        (status = 400, description = "Not a known setting")
    )
)]
pub async fn put_settings(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<PassSettings>, JsonRejection>,
) -> AppResult<StatusCode> {
    let Json(settings) = body.map_err(|_| AppError::bad_request("invalid settings"))?;
    let user_id = trusted_uuid(&user.user_id)?;
    sqlx::query(
        "INSERT INTO pass_settings (user_id, site_icons) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET site_icons = $2, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(settings.site_icons.as_str())
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IconRequest {
    /// The entry's website, as a host name only (`accounts.example.org`).
    pub domain: String,
}

/// `POST /api/pass/icon` — one website's icon, through Kutup.
#[utoipa::path(
    post,
    path = "/api/pass/icon",
    tag = "pass",
    security(("BearerAuth" = [])),
    request_body = IconRequest,
    responses(
        (status = 200, description = "The icon's bytes: PNG, JPEG, GIF, WebP or ICO"),
        (status = 400, description = "Not a public host name"),
        (status = 403, description = "The account chose not to fetch icons through Kutup (`siteIconsNotKutup`)"),
        (status = 404, description = "The site has no usable icon"),
        (status = 429, description = "Too many icons")
    )
)]
pub async fn icon(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<IconRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(request) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    if !PASS_ICONS.allow(&user.user_id) {
        return Err(AppError::too_many_requests(
            "too many icons; try again shortly",
        ));
    }
    let domain = normalize_domain(&request.domain)
        .ok_or_else(|| AppError::bad_request("not a public host name"))?;
    if site_icons(&state, &user).await? != SiteIcons::Kutup {
        return Err(AppError::forbidden("siteIconsNotKutup"));
    }
    let key = cache_key(&user.user_id, &domain);
    let found = match cached(&key) {
        Some(found) => found,
        None => fetch_once(&key, &user.user_id, &domain).await?,
    };
    let Some(icon) = found else {
        return Err(AppError::not_found("no icon"));
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(icon.mime)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'; sandbox"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        icon.bytes.as_ref().clone(),
    )
        .into_response())
}

/// Answers are kept per account, so how fast one comes says nothing about
/// what other accounts asked for.
fn cache_key(user_id: &str, domain: &str) -> String {
    format!("{user_id}\n{domain}")
}

/// Fetches `domain` for the account behind `key`, unless a fetch of it is
/// already under way, whose answer is then taken.
async fn fetch_once(key: &str, user_id: &str, domain: &str) -> AppResult<Option<Icon>> {
    let gate = IN_FLIGHT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(key.to_owned())
        .or_default()
        .clone();
    let answer = async {
        let _turn = gate.lock().await;
        if let Some(found) = cached(key) {
            return Ok(found);
        }
        if !PASS_ICON_FETCHES.allow(user_id) {
            return Err(AppError::too_many_requests(
                "too many icons; try again shortly",
            ));
        }
        let _permit = FETCHING
            .acquire()
            .await
            .map_err(|_| AppError::internal("icon fetches closed"))?;
        let found = tokio::time::timeout(TOTAL_TIMEOUT, find_icon(domain))
            .await
            .ok()
            .flatten();
        remember(key, found.clone());
        Ok(found)
    }
    .await;
    let mut in_flight = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    // The map's and this one: nobody else waits.
    if Arc::strong_count(&gate) <= 2 {
        in_flight.remove(key);
    }
    answer
}

/// A lowercase host name with at least one dot, as a URL's host after IDNA
/// (`bücher.example` → `xn--bcher-kva.example`); never an IP address.
fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty()
        || value.len() > MAX_DOMAIN_BYTES
        || value.bytes().any(|b| {
            matches!(
                b,
                b'/' | b'\\' | b':' | b'@' | b'?' | b'#' | b'%' | b'[' | b']'
            )
        })
        || value.chars().any(char::is_whitespace)
    {
        return None;
    }
    let url = Url::parse(&format!("https://{value}/")).ok()?;
    match url.host()? {
        url::Host::Domain(host)
            if host.contains('.') && !host.ends_with(".localhost") && host != "localhost" =>
        {
            Some(host.to_owned())
        }
        _ => None,
    }
}

#[derive(Clone)]
struct Icon {
    mime: &'static str,
    bytes: std::sync::Arc<Vec<u8>>,
}

async fn find_icon(domain: &str) -> Option<Icon> {
    let home = Url::parse(&format!("https://{domain}/")).ok()?;
    let mut tries: Vec<Url> = Vec::new();
    if let Ok(page) = public_fetch::get(
        home.clone(),
        &public_fetch::Request {
            accept: "text/html,application/xhtml+xml;q=0.9",
            user_agent: USER_AGENT,
            timeout: FETCH_TIMEOUT,
            limit: PAGE_LIMIT_BYTES,
            truncate: true,
            wanted: &|kind| kind == "text/html" || kind == "application/xhtml+xml",
        },
    )
    .await
    {
        let html = String::from_utf8_lossy(&page.body);
        tries.extend(
            best_links(&html, &page.final_url)
                .into_iter()
                .take(MAX_LINKED_TRIES),
        );
        // A home page that moved (example.org → www.example.org) keeps its
        // favicon at the new host.
        if let Ok(favicon) = page.final_url.join("/favicon.ico") {
            tries.push(favicon);
        }
    }
    if let Ok(favicon) = home.join("/favicon.ico") {
        tries.push(favicon);
    }
    let mut seen = Vec::new();
    for url in tries {
        if seen.contains(&url) {
            continue;
        }
        seen.push(url.clone());
        let Ok(url) = public_fetch::parse_public_https(url.as_str()) else {
            continue;
        };
        let Ok(fetched) = public_fetch::get(
            url,
            &public_fetch::Request {
                accept: "image/png,image/x-icon,image/webp,image/jpeg,image/gif;q=0.8",
                user_agent: USER_AGENT,
                timeout: FETCH_TIMEOUT,
                limit: ICON_LIMIT_BYTES,
                truncate: false,
                // Icons often come with a wrong type; their bytes decide.
                wanted: &|kind| !kind.starts_with("text/") && kind != "image/svg+xml",
            },
        )
        .await
        else {
            continue;
        };
        if let Some(mime) = raster_kind(&fetched.body) {
            return Some(Icon {
                mime,
                bytes: std::sync::Arc::new(fetched.body),
            });
        }
    }
    None
}

/// The image type of `bytes`, from their first bytes; only raster formats a
/// browser shows in `<img>` (never SVG).
fn raster_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.len() >= 6 && bytes[..4] == [0, 0, 1, 0] && bytes[4..6] != [0, 0] {
        Some("image/x-icon")
    } else {
        None
    }
}

/// One `<link>` tag that names an icon.
#[derive(Debug, PartialEq)]
struct IconLink {
    href: String,
    /// The largest side it declares; `None` when unknown.
    pixels: Option<u32>,
}

/// The page's icon links, best first: the smallest at least 64 px, then
/// the rest from the largest down. SVG and mask icons are left out.
fn best_links(html: &str, base: &Url) -> Vec<Url> {
    let mut links = icon_links(html);
    links.sort_by_key(|link| {
        let pixels = link.pixels.unwrap_or(0);
        if pixels >= WANTED_PIXELS {
            (0, pixels)
        } else {
            (1, u32::MAX - pixels)
        }
    });
    links
        .into_iter()
        .filter_map(|link| base.join(&link.href).ok())
        .filter(|url| url.scheme() == "https")
        .collect()
}

/// The `<link rel="…icon…">` tags in the page's head.
fn icon_links(html: &str) -> Vec<IconLink> {
    let lower = html.to_ascii_lowercase();
    let head_end = ["</head", "<body"]
        .iter()
        .filter_map(|tag| lower.find(tag))
        .min()
        .unwrap_or(lower.len());
    let mut links = Vec::new();
    let mut at = 0;
    while at < head_end {
        let Some(found) = lower[at..head_end].find("<link") else {
            break;
        };
        let start = at + found + "<link".len();
        let Some(length) = lower[start..].find('>') else {
            break;
        };
        let attributes = parse_attributes(&html[start..start + length]);
        at = start + length;
        let get = |name: &str| {
            attributes
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        let rel = get("rel").unwrap_or_default().to_ascii_lowercase();
        let rels: Vec<&str> = rel.split_ascii_whitespace().collect();
        let apple = rels.iter().any(|r| r.starts_with("apple-touch-icon"));
        if !(apple || rels.contains(&"icon")) {
            continue;
        }
        let Some(href) = get("href").map(decode_entities).filter(|h| !h.is_empty()) else {
            continue;
        };
        let kind = get("type").unwrap_or_default().to_ascii_lowercase();
        let path = href
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if kind.contains("svg") || path.ends_with(".svg") || href.starts_with("data:") {
            continue;
        }
        let declared = get("sizes").and_then(|sizes| {
            sizes
                .split_ascii_whitespace()
                .filter_map(|size| {
                    let (w, h) = size
                        .to_ascii_lowercase()
                        .split_once('x')
                        .map(|(w, h)| (w.to_owned(), h.to_owned()))?;
                    Some(w.parse::<u32>().ok()?.max(h.parse::<u32>().ok()?))
                })
                .max()
        });
        // Apple touch icons are 180 px unless they say otherwise.
        let pixels = declared.or(apple.then_some(180));
        links.push(IconLink { href, pixels });
    }
    links
}

/// A tag's attributes as lowercase names and raw values.
fn parse_attributes(tag: &str) -> Vec<(String, String)> {
    let bytes = tag.as_bytes();
    let mut attributes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/')
        {
            i += 1;
        }
        if name_start == i {
            break;
        }
        let name = tag[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
                let quote = bytes[i];
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = tag[start..i].to_owned();
                i += 1;
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = tag[start..i].to_owned();
            }
        }
        attributes.push((name, value));
    }
    attributes
}

/// The entities an address in an attribute carries in practice.
fn decode_entities(value: &str) -> String {
    value
        .trim()
        .replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&#x2f;", "/")
        .replace("&#x2F;", "/")
        .replace("&#47;", "/")
}

struct CacheEntry {
    until: Instant,
    icon: Option<Icon>,
}

static CACHE: LazyLock<Mutex<HashMap<String, CacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cached(key: &str) -> Option<Option<Icon>> {
    let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .get(key)
        .filter(|entry| entry.until > Instant::now())
        .map(|entry| entry.icon.clone())
}

fn remember(key: &str, icon: Option<Icon>) {
    let now = Instant::now();
    let until = now
        + if icon.is_some() {
            FOUND_FOR
        } else {
            MISSING_FOR
        };
    let bytes = |entry: &CacheEntry| entry.icon.as_ref().map_or(0, |icon| icon.bytes.len());
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|_, entry| entry.until > now);
    if let Some(old) = cache.remove(key) {
        drop(old);
    }
    let mut size: usize = cache.values().map(bytes).sum();
    let incoming = icon.as_ref().map_or(0, |icon| icon.bytes.len());
    while !cache.is_empty() && (cache.len() >= CACHE_ENTRIES || size + incoming > CACHE_BYTES) {
        // The one that would expire first goes.
        let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.until)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        if let Some(gone) = cache.remove(&oldest) {
            size -= bytes(&gone);
        }
    }
    cache.insert(key.to_owned(), CacheEntry { until, icon });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_host_names_only() {
        assert_eq!(
            normalize_domain("Example.ORG").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            normalize_domain(" accounts.example.org. ").as_deref(),
            Some("accounts.example.org")
        );
        assert_eq!(
            normalize_domain("bücher.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        for bad in [
            "",
            "localhost",
            "intranet",
            "app.localhost",
            "127.0.0.1",
            "93.184.215.14",
            "[::1]",
            "example.org:8443",
            "example.org/path",
            "user@example.org",
            "example.org?x",
            "exa mple.org",
            "https://example.org",
            "%65xample.org",
        ] {
            assert_eq!(normalize_domain(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_raster_images_are_returned() {
        assert_eq!(raster_kind(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(raster_kind(&[0xff, 0xd8, 0xff, 0xe0]), Some("image/jpeg"));
        assert_eq!(raster_kind(b"GIF89a...."), Some("image/gif"));
        assert_eq!(raster_kind(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(
            raster_kind(&[0, 0, 1, 0, 1, 0, 16, 16]),
            Some("image/x-icon")
        );
        assert_eq!(raster_kind(&[0, 0, 1, 0, 0, 0]), None);
        assert_eq!(
            raster_kind(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
            None
        );
        assert_eq!(raster_kind(b"<!doctype html><html>"), None);
        assert_eq!(raster_kind(b""), None);
    }

    #[test]
    fn the_head_names_the_icons() {
        let html = r##"<!doctype html><html><head>
            <LINK REL="stylesheet" href="/a.css">
            <link rel="icon" type="image/svg+xml" href="/icon.svg">
            <link rel="mask-icon" href="/mask.svg" color="#000">
            <link rel='shortcut icon' href='/favicon-16.png' sizes='16x16'>
            <link rel=icon href=/favicon-32.png sizes=32x32>
            <link href="https://cdn.example.net/i.png?a=1&amp;b=2" rel="icon" sizes="96x96 192x192">
            <link rel="apple-touch-icon" href="/apple.png">
            <link rel="icon" href="data:image/png;base64,AAAA">
            </head><body><link rel="icon" href="/late.png"></body></html>"##;
        assert_eq!(
            icon_links(html),
            vec![
                IconLink {
                    href: "/favicon-16.png".into(),
                    pixels: Some(16)
                },
                IconLink {
                    href: "/favicon-32.png".into(),
                    pixels: Some(32)
                },
                IconLink {
                    href: "https://cdn.example.net/i.png?a=1&b=2".into(),
                    pixels: Some(192)
                },
                IconLink {
                    href: "/apple.png".into(),
                    pixels: Some(180)
                },
            ]
        );
        let base = Url::parse("https://www.example.org/start").unwrap();
        let best: Vec<String> = best_links(html, &base).iter().map(Url::to_string).collect();
        assert_eq!(
            best,
            vec![
                "https://www.example.org/apple.png",
                "https://cdn.example.net/i.png?a=1&b=2",
                "https://www.example.org/favicon-32.png",
                "https://www.example.org/favicon-16.png",
            ]
        );
    }

    #[test]
    fn a_tag_running_past_the_head_ends_the_search() {
        for html in [
            r#"<head><link rel="icon" href="a</head>"><link rel="icon" href="/b.png"></head>"#,
            r#"<head><link rel=icon href=x<body>"#,
            r#"<head><link rel="icon" href="/c.png"<body><link rel="icon" href="/d.png">"#,
            "<head><link",
            "<link rel=icon href=/e.png></head>",
        ] {
            let _ = icon_links(html);
        }
        assert_eq!(
            icon_links(r#"<head><link rel="icon" href="a</head>"></head>"#),
            vec![IconLink {
                // The tag ends at its first `>`, quoted or not.
                href: "a</head".into(),
                pixels: None
            }]
        );
    }

    #[test]
    fn plain_http_icons_are_not_followed() {
        let html =
            r#"<head><link rel="icon" href="http://example.org/i.png" sizes="64x64"></head>"#;
        let base = Url::parse("https://example.org/").unwrap();
        assert!(best_links(html, &base).is_empty());
    }

    #[test]
    fn the_cache_forgets_and_stays_bounded() {
        let icon = Icon {
            mime: "image/png",
            bytes: std::sync::Arc::new(vec![0; 10]),
        };
        remember("cache-test.example", Some(icon));
        assert_eq!(
            cached("cache-test.example")
                .flatten()
                .map(|i| i.bytes.len()),
            Some(10)
        );
        remember("cache-miss.example", None);
        assert!(matches!(cached("cache-miss.example"), Some(None)));
        assert!(cached("never-asked.example").is_none());
        // Another account's answer is not this one's.
        remember(&cache_key("ayse", "vpn.example"), None);
        assert!(cached(&cache_key("ayse", "vpn.example")).is_some());
        assert!(cached(&cache_key("mehmet", "vpn.example")).is_none());
    }
}
