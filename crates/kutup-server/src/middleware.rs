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

/// Peer-IP string used as the rate-limit key — mirrors Fiber's `c.IP()`.
fn client_ip(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

async fn limit(
    addr: SocketAddr,
    limiter: &ratelimit::RateLimiter,
    req: Request,
    next: Next,
) -> Response {
    if !limiter.allow(&client_ip(addr)) {
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
    limit(addr, &ratelimit::LOGIN, req, next).await
}

/// 20/min/IP — mirrors `PreflightRateLimit`.
pub async fn rate_limit_preflight(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::PREFLIGHT, req, next).await
}

/// 5/hr/IP — mirrors `RecoveryRateLimit`.
pub async fn rate_limit_recovery(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::RECOVERY, req, next).await
}

/// 60/min/IP — mirrors `FedUsersRateLimit` (the `/api/fed/users` route layer).
pub async fn rate_limit_fed_users(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    limit(addr, &ratelimit::FED_USERS, req, next).await
}
