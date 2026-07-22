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
use crate::{jwt, ratelimit, AppState};

/// An authenticated caller — mirrors what `authMW.Required()` puts in `c.Locals`.
pub struct AuthUser {
    pub user_id: String,
    /// Read by `AdminUser` and the admin handlers (server slice 7).
    #[allow(dead_code)]
    pub is_admin: bool,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or_else(|| AppError::unauthorized("unauthorized"))?;
        // validate_access_token rejects setup/pre-auth tokens (non-empty subject), exactly
        // as Required() does before trusting an access token.
        let (user_id, is_admin) = jwt::validate_access_token(&token, &state.config.jwt_secret)
            .map_err(|_| AppError::unauthorized("unauthorized"))?;
        Ok(AuthUser { user_id, is_admin })
    }
}

/// An authenticated admin — mirrors `Required()` + `AdminRequired()`.
/// Consumed by the admin handlers (server slice 7).
#[allow(dead_code)]
pub struct AdminUser {
    pub user_id: String,
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
        })
    }
}

/// Extracts the `Bearer <token>` value from the `Authorization` header — mirrors
/// `extractToken`.
fn bearer_token(parts: &Parts) -> Option<String> {
    let auth = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
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
    if let Some(ip) = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return ip.to_string();
    }
    if let Some(ip) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return ip.to_string();
    }
    addr.ip().to_string()
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
        return AppError::too_many_requests("too many requests").into_response();
    }
    next.run(req).await
}

/// 10/min/IP — mirrors `LoginRateLimit`.
pub async fn rate_limit_login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::LOGIN, None, req, next).await
}

/// 20/min/IP — mirrors `PreflightRateLimit`.
pub async fn rate_limit_preflight(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::PREFLIGHT, None, req, next).await
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

/// 10/hr/IP — `/api/auth/register`.
pub async fn rate_limit_register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::REGISTER, None, req, next).await
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
