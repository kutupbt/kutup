//! Auth extractors + rate-limit layers — mirrors `backend/middleware/{auth,admin,ratelimit}.go`.
//!
//! Fiber set `c.Locals("userId"/"isAdmin")` in an `authMW.Required()` handler; in Axum the
//! equivalent is a `FromRequestParts` extractor. `AuthUser` validates the Bearer access
//! token (rejecting setup/pre-auth tokens, like `Required()`), `AdminUser` additionally
//! requires `isAdmin` (like `AdminRequired()`). The rate-limit functions are `from_fn`
//! layers keyed on the peer IP (Fiber's `c.IP()`).

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use uuid::Uuid;

use crate::{jwt, ratelimit, sessions, AppState};

/// An authenticated caller: a valid access token whose server-side session is still
/// live (not revoked, not expired, user active). `is_admin` comes from the database,
/// not the token, so a demotion applies at once.
pub struct AuthUser {
    pub user_id: String,
    pub is_admin: bool,
    pub session: sessions::LiveSession,
}

/// Validates an access token and its session — the one path every authenticated
/// entry point uses (REST extractor, collab and chat WebSocket upgrades).
pub async fn authenticate_access_token(
    state: &AppState,
    token: &str,
) -> Result<AuthUser, AppError> {
    let (user_id, session_id) = jwt::validate_access_token(token, &state.config.jwt_secret)
        .map_err(|_| AppError::unauthorized("unauthorized"))?;
    let user_uuid =
        Uuid::parse_str(&user_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    let session_uuid =
        Uuid::parse_str(&session_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    let session = sessions::live(&state.pool, session_uuid, user_uuid).await?;
    Ok(AuthUser {
        user_id,
        is_admin: session.is_admin,
        session,
    })
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or_else(|| AppError::unauthorized("unauthorized"))?;
        let user = authenticate_access_token(state, &token).await?;
        if let Some(slot) = parts.extensions.get::<SessionVersionSlot>() {
            *slot.0.lock().unwrap() = Some(session_version(state, &user.session.version).await?);
        }
        Ok(user)
    }
}

static SESSION_VERSION_KEY: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();

/// The header's value: an HMAC of the account's state digest under a key
/// only this server holds (derived, under its own label, from its stored
/// sign-in key), 16 hex digits. It changes when the state does, and tells
/// nothing else to anyone who sees headers: not the password hash, not
/// which of 2FA or role changed, and nothing linkable across servers.
async fn session_version(state: &AppState, digest: &str) -> Result<String, AppError> {
    use hmac::{Hmac, Mac};
    let key = SESSION_VERSION_KEY
        .get_or_try_init(|| async {
            let root = crate::handlers::auth::fake_accounts_key(state).await?;
            let mut mac =
                <Hmac<sha2::Sha256> as Mac>::new_from_slice(&root).expect("any key length");
            mac.update(b"kutup/session-version/v1\0");
            Ok::<_, AppError>(mac.finalize().into_bytes().into())
        })
        .await?;
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(digest.as_bytes());
    Ok(hex::encode(&mac.finalize().into_bytes()[..8]))
}

/// Where an authenticated request leaves its account's session version for
/// [`session_version_header`] to send back.
#[derive(Clone, Default)]
pub struct SessionVersionSlot(std::sync::Arc<std::sync::Mutex<Option<String>>>);

pub const SESSION_VERSION_HEADER: &str = "x-kutup-session-version";

/// Stamps `X-Kutup-Session-Version` on every authenticated answer, so each
/// app (on its own origin) notices a password, 2FA, role or key binding
/// change made anywhere and re-reads its account (docs/api.md, "Session
/// version"). Read in the same query that checks the session, so it is as
/// fresh as the request's own authority.
pub async fn session_version_header(mut req: Request, next: Next) -> Response {
    let slot = SessionVersionSlot::default();
    req.extensions_mut().insert(slot.clone());
    let mut response = next.run(req).await;
    // Not on an answer a cache keeps (thumbnails, map tiles): an old copy
    // would bring back an old version and send apps re-reading their account.
    let cacheable = response
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("immutable")
                || value.split(',').any(|part| {
                    part.trim()
                        .strip_prefix("max-age=")
                        .and_then(|age| age.parse::<u64>().ok())
                        .is_some_and(|age| age > 0)
                })
        });
    if cacheable {
        return response;
    }
    if let Some(version) = slot.0.lock().unwrap().take() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&version) {
            response.headers_mut().insert(SESSION_VERSION_HEADER, value);
        }
    }
    response
}

/// An authenticated admin — mirrors `Required()` + `AdminRequired()`.
/// Consumed by the admin handlers (server slice 7).
#[allow(dead_code)]
pub struct AdminUser {
    pub user_id: String,
    /// The admin's own sign-in (what their reauth grants are bound to).
    pub session_id: uuid::Uuid,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin {
            return Err(AppError::forbidden("forbidden"));
        }
        Ok(AdminUser {
            user_id: user.user_id,
            session_id: user.session.session_id,
        })
    }
}

/// Extracts the `Bearer <token>` value from the `Authorization` header — mirrors
/// `extractToken`.
fn bearer_token(parts: &Parts) -> Option<String> {
    bearer_from_headers(&parts.headers)
}

/// The `Bearer <token>` value of a request's headers.
pub(crate) fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let auth = headers.get(AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|t| t.to_string())
}

/// Client-IP string used as the rate-limit key.
///
/// kutup's deployment model puts nginx in front of the backend (the backend port is
/// never published), so the TCP peer is the proxy for every request and the socket
/// address alone would give ALL clients one shared bucket. Prefer the proxy-set
/// `X-Real-IP`, then the first `X-Forwarded-For` hop, then the socket address.
/// Trust note: these headers are only meaningful because the backend is not directly
/// reachable; nginx overwrites them on every request (see `nginx/nginx.conf`).
fn client_ip(addr: SocketAddr, req: &Request) -> String {
    client_key(client_ip_from_headers(req.headers()), addr)
}

/// The rate-limit key for a client: its IP from the proxy's headers (or the
/// socket's), an IPv6 address reduced to its /64, the block one subscriber
/// gets, so one network cannot spread over 2^64 keys.
pub(crate) fn client_key(from_headers: Option<String>, peer: SocketAddr) -> String {
    match from_headers {
        Some(ip) => limit_key(&ip),
        None => limit_key(&peer.ip().to_string()),
    }
}

fn limit_key(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
                format!("{net}/64")
            }
        },
        Ok(std::net::IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.to_owned(),
    }
}

/// The client IP from the proxy's headers (`X-Real-IP`, then the first
/// `X-Forwarded-For` hop), as sent.
pub(crate) fn client_ip_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    header("x-real-ip")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            header("x-forwarded-for")
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod client_key_tests {
    use super::limit_key;

    #[test]
    fn ipv6_clients_are_keyed_by_their_64() {
        assert_eq!(limit_key("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(limit_key("2001:db8:1:2:ffff:1:2:3"), "2001:db8:1:2::/64");
        assert_ne!(limit_key("2001:db8:1:3::1"), limit_key("2001:db8:1:2::1"));
        assert_eq!(limit_key("198.51.100.7"), "198.51.100.7");
        assert_eq!(limit_key("::ffff:198.51.100.7"), "198.51.100.7");
    }
}

async fn limit(
    addr: SocketAddr,
    limiter: &ratelimit::RateLimiter,
    telemetry_scope: Option<&'static str>,
    req: Request,
    next: Next,
) -> Response {
    if !limiter.allow(&client_ip(addr, &req)) {
        if let Some(scope) = telemetry_scope {
            crate::telemetry::rate_limit_rejection(scope);
        }
        // `rateLimited`: this address asked too often (wait a minute), not the
        // account's lockout (`accountLocked`).
        return AppError::too_many_requests("too many requests")
            .with_details(serde_json::json!({ "code": "rateLimited" }))
            .into_response();
    }
    next.run(req).await
}

/// 30/hour/IP — checking a referral code before signing up.
pub async fn rate_limit_registration_code_check(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::REGISTRATION_CODE_CHECK, None, req, next).await
}

/// 10/min/IP — mirrors `LoginRateLimit`.
pub async fn rate_limit_login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::LOGIN, None, req, next).await
}

/// 120/min/IP — redeeming a session fork when an app opens.
pub async fn rate_limit_fork(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::FORK, None, req, next).await
}

/// 60/min/IP — a call link's info and SFU token, which need no account.
pub async fn rate_limit_call_link(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::CALL_LINK, None, req, next).await
}

/// 600/min/IP — a meeting's waiting room, which both sides ask about every
/// few seconds.
pub async fn rate_limit_call_link_poll(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::CALL_LINK_POLL, None, req, next).await
}

/// Coarse 120/min/IP outer wall. The handler additionally applies the primary
/// 30/min authenticated-account budget after JWT extraction.
pub async fn rate_limit_chat_keys(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::CHAT_KEYS_IP, Some("prekey_ip"), req, next).await
}

pub async fn rate_limit_chat_anonymous(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(
        addr,
        &ratelimit::CHAT_ANONYMOUS_IP,
        Some("anonymous_ip"),
        req,
        next,
    )
    .await
}

/// 5/hr/IP — mirrors `RecoveryRateLimit`.
pub async fn rate_limit_recovery(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::RECOVERY, None, req, next).await
}

/// 6000/min/IP — pre-authentication limit for forwarded multi-recipient
/// sends (a peer's group messages, all its users together).
pub async fn rate_limit_fed_multi(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(
        addr,
        &ratelimit::FED_MULTI_IP,
        Some("federation_ip"),
        req,
        next,
    )
    .await
}

/// 60/min/IP — coarse pre-authentication limit for server-to-server directory routes.
pub async fn rate_limit_fed_users(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(
        addr,
        &ratelimit::FED_USERS,
        Some("federation_ip"),
        req,
        next,
    )
    .await
}

/// 30/min/IP — `/api/users/by-address/{address}`.
pub async fn rate_limit_user_lookup(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::USER_LOOKUP, None, req, next).await
}

/// 10/hr/IP — `/api/auth/register`.
pub async fn rate_limit_register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::REGISTER, None, req, next).await
}

/// 20/hour/IP — reporting a public link, which needs no account.
pub async fn rate_limit_report(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::REPORT, None, req, next).await
}

/// 120/min/IP — every `/api/admin/*` route.
pub async fn rate_limit_admin(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::ADMIN, None, req, next).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use std::sync::LazyLock;
    use tower::ServiceExt;

    static TEST_LIMITER: LazyLock<ratelimit::RateLimiter> =
        LazyLock::new(|| ratelimit::RateLimiter::new(2, std::time::Duration::from_secs(60)));

    async fn test_layer(
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        req: Request,
        next: Next,
    ) -> Response {
        limit(addr, &TEST_LIMITER, None, req, next).await
    }

    fn req(ip: &str, real_ip: Option<&str>) -> Request<Body> {
        let mut r = Request::builder().uri("/ping");
        if let Some(h) = real_ip {
            r = r.header("x-real-ip", h);
        }
        let mut r = r.body(Body::empty()).unwrap();
        let addr: SocketAddr = format!("{ip}:1234").parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        r
    }

    /// Exceeding the per-IP limit returns 429; another client IP (here via the
    /// proxy-set X-Real-IP header, same TCP peer) keeps its own budget.
    #[tokio::test]
    async fn rate_limited_route_returns_429() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .route_layer(axum::middleware::from_fn(test_layer));

        // Two allowed, third (same client) is 429.
        for _ in 0..2 {
            let res = app
                .clone()
                .oneshot(req("10.0.0.1", Some("203.0.113.7")))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }
        let res = app
            .clone()
            .oneshot(req("10.0.0.1", Some("203.0.113.7")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        // Same proxy peer, different X-Real-IP → separate bucket, still allowed.
        let res = app
            .clone()
            .oneshot(req("10.0.0.1", Some("203.0.113.8")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
