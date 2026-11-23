//! A calendar's public links (docs/plans/calendar-e3.md §3), as anyone with
//! one opens them, without an account:
//! - a **full** link's page (`/l/{id}#secret`): the sealed name, each
//!   generation's key and passphrase sealed under the link's secret, and the
//!   sealed events, served only to a page that shows the link's access proof
//!   (derived from the secret; the server keeps its hash), so the link's id
//!   alone opens nothing. The secret stays in the URL's fragment; the server
//!   never opens anything.
//! - a **query** link's feed (`…/calendar.ics?key=<secret>`), for other
//!   calendar apps, while the site allows them: the server opens the
//!   calendar with the secret on each fetch (the events of a window around
//!   now) and serves it as iCalendar. It has no page. The query is never
//!   logged (`crate::redact_uri`, and nginx's `kutup` log format and its
//!   error log off for these paths).
//! - a **busy** link's page and feed: merged busy blocks from the readable
//!   times, no key at all. Only a busy link answers busy blocks.
//!
//! Each fetch counts against the caller's address and against the link.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::calendar::{self as cal, SealedEventV1, SealedMetadataV1};
use kutup_crypto::calendar_link::{self, LinkSecret};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::calendar_busy::BusyList;
use crate::error::{AppError, AppResult};
use crate::handlers::calendar::{coded, event_view, event_view_sql, instant, EventCursor};
use crate::middleware::AuthAccount;
use crate::site_settings::{
    CALENDAR_BUSY_WINDOW_DAYS, CALENDAR_EVENTS_PAGE, CALENDAR_QUERY_LINKS_ALLOWED,
    CALENDAR_WINDOW_DAYS,
};
use crate::AppState;

/// Fetches per address (`calendar.rate.link_fetches`).
pub(crate) static LINK_FETCHES: std::sync::LazyLock<crate::ratelimit::RateLimiter> =
    std::sync::LazyLock::new(|| {
        crate::ratelimit::RateLimiter::registered(crate::ratelimit::Limit::CalendarLinkFetches)
    });
/// Fetches per link, from every address together.
pub(crate) static LINK_FETCHES_PER_LINK: std::sync::LazyLock<crate::ratelimit::RateLimiter> =
    std::sync::LazyLock::new(|| {
        crate::ratelimit::RateLimiter::registered(
            crate::ratelimit::Limit::CalendarLinkFetchesPerLink,
        )
    });

/// How far a feed reaches: a month back to a year ahead (busy blocks, and a
/// query link's events).
const FEED_PAST_DAYS: i64 = 31;
const FEED_AHEAD_DAYS: i64 = 366;

fn not_found() -> AppError {
    AppError::not_found("this calendar link does not exist")
}

/// A link as its fetch sees it, checked: counted, its owner's sharing on.
struct Link {
    id: Uuid,
    calendar: Uuid,
    kind: String,
    /// A keyed link's access proof's SHA-256.
    proof_hash: Option<Vec<u8>>,
}

/// Whether `proof` is the link's (its hash compared in constant time).
fn proof_matches(link: &Link, proof: &[u8; 32]) -> bool {
    link.proof_hash.as_deref().is_some_and(|hash| {
        kutup_crypto::primitives::ct_eq(
            hash,
            &crate::handlers::calendar_sharing::proof_digest(proof),
        )
    })
}

/// The header a keyed link's page shows its access proof in.
const PROOF_HEADER: &str = "x-kutup-link-proof";

/// Whether the request proves it holds a keyed link's secret: `None` when
/// it shows no proof, `Some(false)` for a wrong one.
fn proven(headers: &HeaderMap, link: &Link) -> Option<bool> {
    let shown = headers.get(PROOF_HEADER)?.to_str().ok()?;
    let Some(proof) = crate::handlers::calendar_sharing::access_proof(shown) else {
        return Some(false);
    };
    Some(proof_matches(link, &proof))
}

async fn open_link(
    state: &AppState,
    addr: SocketAddr,
    headers: &HeaderMap,
    viewer: &Option<AuthAccount>,
    link: Uuid,
) -> AppResult<Link> {
    let address =
        crate::middleware::client_key(crate::middleware::client_ip_from_headers(headers), addr);
    if !LINK_FETCHES.allow(&address) || !LINK_FETCHES_PER_LINK.allow(&link.to_string()) {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    let row: Option<(Uuid, String, Uuid, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT l.calendar_id, l.kind, c.owner_account_id, l.access_proof_hash
           FROM calendar_links l JOIN calendars c ON c.id = l.calendar_id
          WHERE l.id = $1",
    )
    .bind(link)
    .fetch_optional(&state.pool)
    .await?;
    let Some((calendar, kind, owner, proof_hash)) = row else {
        return Err(not_found());
    };
    crate::public_sharing::ensure_calendar_link_up(&state.pool, owner, viewer.is_some()).await?;
    Ok(Link {
        id: link,
        calendar,
        kind,
        proof_hash,
    })
}

/// One generation as a keyed link serves it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyView {
    pub key_generation: i32,
    pub fingerprint: String,
    pub locked_secret_key: String,
    /// This generation's passphrase, sealed under the link's secret.
    pub passphrase: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicLinkView {
    /// None on a keyed link asked without its access proof: only its kind
    /// is told (so its page can say the link is incomplete, or for apps).
    pub calendar_id: Option<Uuid>,
    /// `full`, `query` or `busy`.
    pub kind: String,
    /// A keyed link's sealed name; none on a busy link.
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<SealedMetadataV1>,
    /// A keyed link's generations, oldest first; none on a busy link.
    pub keys: Option<Vec<PublicKeyView>>,
}

/// `GET /api/v1/calendar/links/{id}` — what a link's page opens: never the
/// calendar's members or owner. A full link's keys and name go only with its
/// access proof (`X-Kutup-Link-Proof`); without one only the kind is told, a
/// wrong one is `404`. A query link has no page (`404 feedOnly` with its
/// proof).
#[utoipa::path(
    get,
    path = "/api/v1/calendar/links/{id}",
    tag = "calendar",
    params(("id" = Uuid, Path)),
    responses((status = 200, body = PublicLinkView), (status = 404), (status = 410), (status = 429))
)]
pub async fn link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    viewer: Option<AuthAccount>,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let link = open_link(&state, addr, &headers, &viewer, id).await?;
    if link.kind != "busy" {
        match proven(&headers, &link) {
            None => {
                return Ok(no_store(
                    Json(PublicLinkView {
                        calendar_id: None,
                        kind: link.kind,
                        metadata: None,
                        keys: None,
                    })
                    .into_response(),
                ))
            }
            Some(false) => return Err(not_found()),
            Some(true) if link.kind == "query" => {
                return Err(coded(
                    AppError::not_found("this link is for calendar apps"),
                    "feedOnly",
                ))
            }
            Some(true) => {}
        }
    }
    let (metadata, keys) = if link.kind == "busy" {
        (None, None)
    } else {
        let (key_packet, data_packet, signature): (Vec<u8>, Vec<u8>, String) = sqlx::query_as(
            "SELECT metadata_key_packet, metadata_data_packet, metadata_signature
               FROM calendars WHERE id = $1",
        )
        .bind(link.calendar)
        .fetch_one(&state.pool)
        .await?;
        let keys: Vec<(i32, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT k.key_generation, k.fingerprint, k.locked_secret_key, p.passphrase
               FROM calendar_keys k JOIN calendar_link_passphrases p
                 ON p.calendar_id = k.calendar_id AND p.key_generation = k.key_generation
              WHERE p.link_id = $1 ORDER BY k.key_generation",
        )
        .bind(link.id)
        .fetch_all(&state.pool)
        .await?;
        (
            Some(SealedMetadataV1 {
                key_packet: STANDARD.encode(key_packet),
                data_packet: STANDARD.encode(data_packet),
                signature,
            }),
            Some(
                keys.into_iter()
                    .map(
                        |(generation, fingerprint, locked, passphrase)| PublicKeyView {
                            key_generation: generation,
                            fingerprint,
                            locked_secret_key: STANDARD.encode(locked),
                            passphrase: STANDARD.encode(passphrase),
                        },
                    )
                    .collect(),
            ),
        )
    };
    Ok(no_store(
        Json(PublicLinkView {
            calendar_id: Some(link.calendar),
            kind: link.kind,
            metadata,
            keys,
        })
        .into_response(),
    ))
}

/// An event as a keyed link serves it: no author, no reminders, no UID
/// beyond what the sealed parts hold.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicEventView {
    pub id: Uuid,
    #[schema(value_type = Object)]
    pub event: SealedEventV1,
    #[serde(with = "time::serde::rfc3339")]
    pub start_utc: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_utc: time::OffsetDateTime,
    pub full_day: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublicEventPage {
    pub events: Vec<PublicEventView>,
    pub next: Option<EventCursor>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct LinkEventsQuery {
    pub start: String,
    pub end: String,
    pub after_start: Option<String>,
    pub after_id: Option<Uuid>,
}

/// `GET /api/v1/calendar/links/{id}/events?start&end` — a full link's
/// sealed events meeting a window, paged as the members' listing, with the
/// link's access proof only.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/links/{id}/events",
    tag = "calendar",
    params(("id" = Uuid, Path), LinkEventsQuery),
    responses((status = 200, body = PublicEventPage), (status = 404), (status = 410), (status = 429))
)]
pub async fn events(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    viewer: Option<AuthAccount>,
    Path(id): Path<Uuid>,
    Query(query): Query<LinkEventsQuery>,
) -> AppResult<Response> {
    let link = open_link(&state, addr, &headers, &viewer, id).await?;
    if link.kind != "full" || proven(&headers, &link) != Some(true) {
        return Err(not_found());
    }
    let (start, end) = (instant(&query.start, "start")?, instant(&query.end, "end")?);
    let window_days = CALENDAR_WINDOW_DAYS.load(&state.pool).await?;
    if end <= start || end - start > time::Duration::days(window_days) {
        return Err(AppError::bad_request(format!(
            "the window is up to {window_days} days, end after start"
        )));
    }
    let after = match (&query.after_start, query.after_id) {
        (Some(at), Some(id)) => Some((instant(at, "afterStart")?, id)),
        (None, None) => None,
        _ => return Err(AppError::bad_request("afterStart and afterId go together")),
    };
    let limit = CALENDAR_EVENTS_PAGE.load(&state.pool).await?;
    let rows: Vec<crate::handlers::calendar::EventRow> = sqlx::query_as(&format!(
        "{}
          WHERE e.calendar_id = $1 AND se.start_utc < $3
            AND COALESCE(se.range_end_utc, 'infinity'::timestamptz) >= $2
            AND ($4::timestamptz IS NULL OR (se.start_utc, e.id) > ($4, $5))
          ORDER BY se.start_utc, e.id
          LIMIT $6",
        event_view_sql(7)
    ))
    .bind(link.calendar)
    .bind(start)
    .bind(end)
    .bind(after.map(|(at, _)| at))
    .bind(after.map(|(_, id)| id))
    .bind(limit + 1)
    // No account's reminders: none is anyone's here.
    .bind(Uuid::nil())
    .fetch_all(&state.pool)
    .await?;
    let mut events: Vec<PublicEventView> = rows
        .into_iter()
        .map(event_view)
        .map(|view| PublicEventView {
            id: view.id,
            event: view.event,
            start_utc: view.start_utc,
            end_utc: view.end_utc,
            full_day: view.full_day,
        })
        .collect();
    let next = if events.len() as i64 > limit {
        events.truncate(limit as usize);
        events.last().map(|last| EventCursor {
            after_start: last.start_utc,
            after_id: last.id,
        })
    } else {
        None
    };
    Ok(no_store(
        Json(PublicEventPage { events, next }).into_response(),
    ))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct BusyWindow {
    pub start: String,
    pub end: String,
}

/// `GET /api/v1/calendar/links/{id}/busy?start&end` — when a busy link's
/// calendar is busy: merged blocks, times only. A keyed link answers none.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/links/{id}/busy",
    tag = "calendar",
    params(("id" = Uuid, Path), BusyWindow),
    responses((status = 200, body = BusyList), (status = 404), (status = 410), (status = 429))
)]
pub async fn busy(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    viewer: Option<AuthAccount>,
    Path(id): Path<Uuid>,
    Query(query): Query<BusyWindow>,
) -> AppResult<Response> {
    let link = open_link(&state, addr, &headers, &viewer, id).await?;
    if link.kind != "busy" {
        return Err(not_found());
    }
    let (start, end) = (instant(&query.start, "start")?, instant(&query.end, "end")?);
    let days = CALENDAR_BUSY_WINDOW_DAYS.load(&state.pool).await?;
    if end <= start || end - start > time::Duration::days(days) {
        return Err(coded(
            AppError::bad_request(format!("the window is up to {days} days, end after start")),
            "busyWindowTooLong",
        ));
    }
    let busy = crate::calendar_busy::blocks(&state.pool, &[link.calendar], start, end).await?;
    Ok(no_store(Json(BusyList { busy }).into_response()))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct FeedQuery {
    /// A query link's secret (base64url). Never logged.
    pub key: Option<String>,
}

/// `GET /api/v1/calendar/links/{id}/calendar.ics` — the link as a feed for
/// other calendar apps: a busy link's blocks, or a query link's events,
/// opened by the server with the `key` in the query (the UI says so). A
/// full link has no feed: its key never reaches the server.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/links/{id}/calendar.ics",
    tag = "calendar",
    params(("id" = Uuid, Path), FeedQuery),
    responses(
        (status = 200, description = "text/calendar"),
        (status = 404, description = "No such link, no feed, or not its key"),
        (status = 410),
        (status = 429),
    )
)]
pub async fn feed(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    viewer: Option<AuthAccount>,
    Path(id): Path<Uuid>,
    Query(query): Query<FeedQuery>,
) -> AppResult<Response> {
    let link = open_link(&state, addr, &headers, &viewer, id).await?;
    let body = match link.kind.as_str() {
        "busy" => {
            let now = time::OffsetDateTime::now_utc();
            let blocks = crate::calendar_busy::blocks(
                &state.pool,
                &[link.calendar],
                now - time::Duration::days(FEED_PAST_DAYS),
                now + time::Duration::days(FEED_AHEAD_DAYS),
            )
            .await?;
            crate::calendar_busy::ics(&blocks, link.id, &state.config.chat_server_name)
        }
        "query" => {
            // Turned off by the administrators: existing links stop too.
            if CALENDAR_QUERY_LINKS_ALLOWED.load(&state.pool).await? == 0 {
                return Err(coded(
                    AppError::new(
                        StatusCode::GONE,
                        "this server no longer allows links with the key in the address",
                    ),
                    "queryLinksOff",
                ));
            }
            let secret = query
                .key
                .as_deref()
                .and_then(|key| LinkSecret::from_url(key).ok())
                .ok_or_else(not_found)?;
            // The key is checked against the link's proof before anything
            // is opened with it.
            let proof = calendar_link::link_access_proof(&secret, &link.id.to_string())
                .map_err(|_| not_found())?;
            if !proof_matches(&link, &proof) {
                return Err(not_found());
            }
            query_feed(&state, &link, secret).await?
        }
        _ => return Err(not_found()),
    };
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/calendar; charset=utf-8"),
    );
    Ok(no_store(response))
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// A query link's events as iCalendar (those meeting a month back to a year
/// ahead), opened with its secret: every generation's key from the link's
/// copy of its passphrase.
async fn query_feed(state: &AppState, link: &Link, secret: LinkSecret) -> AppResult<String> {
    let now = time::OffsetDateTime::now_utc();
    let keys: Vec<(i32, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT k.key_generation, k.locked_secret_key, p.passphrase
           FROM calendar_keys k JOIN calendar_link_passphrases p
             ON p.calendar_id = k.calendar_id AND p.key_generation = k.key_generation
          WHERE p.link_id = $1 ORDER BY k.key_generation",
    )
    .bind(link.id)
    .fetch_all(&state.pool)
    .await?;
    let metadata: (Vec<u8>, Vec<u8>, String) = sqlx::query_as(
        "SELECT metadata_key_packet, metadata_data_packet, metadata_signature
           FROM calendars WHERE id = $1",
    )
    .bind(link.calendar)
    .fetch_one(&state.pool)
    .await?;
    type Row = (
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        Option<Vec<u8>>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT e.shared_key_packet, e.calendar_key_packet,
                se.shared_signed, se.shared_signed_signature,
                se.shared_encrypted, se.shared_encrypted_signature,
                e.calendar_signed, e.calendar_signed_signature,
                e.calendar_encrypted, e.calendar_encrypted_signature
           FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
          WHERE e.calendar_id = $1 AND se.start_utc < $3
            AND COALESCE(se.range_end_utc, 'infinity'::timestamptz) >= $2
          ORDER BY se.start_utc, e.id",
    )
    .bind(link.calendar)
    .bind(now - time::Duration::days(FEED_PAST_DAYS))
    .bind(now + time::Duration::days(FEED_AHEAD_DAYS))
    .fetch_all(&state.pool)
    .await?;
    let (calendar, link_id) = (link.calendar, link.id);
    tokio::task::spawn_blocking(move || {
        build_feed(calendar, link_id, &secret, &keys, metadata, &rows)
    })
    .await
    .map_err(|error| AppError::internal(error.to_string()))?
}

#[allow(clippy::type_complexity)]
fn build_feed(
    calendar: Uuid,
    link: Uuid,
    secret: &LinkSecret,
    keys: &[(i32, Vec<u8>, Vec<u8>)],
    metadata: (Vec<u8>, Vec<u8>, String),
    rows: &[(
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        Option<Vec<u8>>,
        Option<String>,
    )],
) -> AppResult<String> {
    let (calendar_id, link_id) = (calendar.to_string(), link.to_string());
    let mut keyring = HashMap::new();
    let mut newest = None;
    for (generation, locked, sealed) in keys {
        let generation = u32::try_from(*generation).map_err(|_| not_found())?;
        let passphrase =
            calendar_link::open_link_passphrase(secret, &calendar_id, &link_id, generation, sealed)
                .map_err(|_| not_found())?;
        let key = cal::unlock_calendar_key(locked, &passphrase)
            .map_err(|_| AppError::internal("a stored calendar key does not unlock"))?;
        let key_id = key
            .key_id()
            .map_err(|_| AppError::internal("a calendar key"))?;
        keyring.insert(key_id, key);
        newest = Some(key_id);
    }
    let newest = newest
        .and_then(|id| keyring.get(&id))
        .ok_or_else(not_found)?;
    let name = newest
        .open_metadata(
            &cal::SealedMetadata {
                key_packet: metadata.0,
                data_packet: metadata.1,
                signature: metadata.2,
            },
            &calendar_id,
            &[],
        )
        .map(|(metadata, _)| metadata.name)
        .unwrap_or_default();
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Kutup//Calendar//EN\r\nCALSCALE:GREGORIAN\r\n",
    );
    if !name.is_empty() {
        fold_into(&mut out, &format!("X-WR-CALNAME:{}", escape(&name)));
    }
    for row in rows {
        let event = SealedEventV1 {
            shared_key_packet: STANDARD.encode(&row.0),
            calendar_key_packet: STANDARD.encode(&row.1),
            shared_signed: cal::EventPartV1 {
                data: STANDARD.encode(row.2.as_bytes()),
                signature: row.3.clone(),
            },
            shared_encrypted: cal::EventPartV1 {
                data: STANDARD.encode(&row.4),
                signature: row.5.clone(),
            },
            calendar_signed: cal::EventPartV1 {
                data: STANDARD.encode(row.6.as_bytes()),
                signature: row.7.clone(),
            },
            calendar_encrypted: row.8.as_ref().zip(row.9.as_ref()).map(|(data, signature)| {
                cal::EventPartV1 {
                    data: STANDARD.encode(data),
                    signature: signature.clone(),
                }
            }),
        };
        // An event that doesn't open is left out of the feed.
        let Ok(sealed) = event.to_event() else {
            continue;
        };
        let Some(key) = cal::event_key_id(&sealed)
            .ok()
            .and_then(|id| keyring.get(&id))
        else {
            continue;
        };
        let Ok(opened) = key.open_event(&sealed, &[]) else {
            continue;
        };
        let parts = &opened.parts;
        let texts = [
            parts.shared_signed.build().ok(),
            parts.shared_encrypted.build().ok(),
            parts.calendar_signed.build().ok(),
            parts
                .calendar_encrypted
                .as_ref()
                .and_then(|part| part.build().ok()),
        ];
        out.push_str("BEGIN:VEVENT\r\n");
        for line in merge_parts(texts.iter().flatten().map(String::as_str)) {
            fold_into(&mut out, &line);
        }
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    Ok(out)
}

/// One `VEVENT`'s properties from its parts (each a VCALENDAR with one
/// VEVENT): their content lines unfolded, in part order, `UID` and
/// `DTSTAMP` once.
fn merge_parts<'a>(parts: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out = Vec::new();
    let (mut uid, mut stamp) = (false, false);
    for text in parts {
        let unfolded = text.replace("\r\n ", "").replace("\r\n\t", "");
        for line in unfolded.split("\r\n") {
            if line.is_empty()
                || matches!(
                    line,
                    "BEGIN:VCALENDAR"
                        | "END:VCALENDAR"
                        | "VERSION:2.0"
                        | "BEGIN:VEVENT"
                        | "END:VEVENT"
                )
            {
                continue;
            }
            let name = line
                .split([':', ';'])
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            let seen = match name.as_str() {
                "UID" => &mut uid,
                "DTSTAMP" => &mut stamp,
                _ => {
                    out.push(line.to_owned());
                    continue;
                }
            };
            if !*seen {
                *seen = true;
                out.push(line.to_owned());
            }
        }
    }
    out
}

/// RFC 5545 TEXT escaping.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
}

/// Folds a content line at 75 octets, never inside a character.
fn fold_into(out: &mut String, line: &str) {
    let mut width = 0;
    for ch in line.chars() {
        let len = ch.len_utf8();
        if width + len > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(ch);
        width += len;
    }
    out.push_str("\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_merge_into_one_event_with_one_uid() {
        let shared = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:a@b\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261102T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR";
        let secret = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:a@b\r\nSUMMARY:Lunch with a\r\n  long name\r\nEND:VEVENT\r\nEND:VCALENDAR";
        let lines = merge_parts([shared, secret].into_iter());
        assert_eq!(
            lines,
            vec![
                "UID:a@b",
                "DTSTAMP:20261101T000000Z",
                "DTSTART:20261102T090000Z",
                "SUMMARY:Lunch with a long name",
            ]
        );
    }

    #[test]
    fn long_lines_fold_at_75_octets() {
        let mut out = String::new();
        fold_into(&mut out, &format!("SUMMARY:{}", "ş".repeat(60)));
        for line in out.trim_end().split("\r\n") {
            assert!(line.len() <= 75, "{line}");
        }
    }
}
