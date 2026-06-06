//! kutup backend API — Rust rewrite of `backend/` (Axum + sqlx).
//!
//! Mirrors `backend/main.go`. This is the Phase-3 build: config, the Postgres pool +
//! migrations, the shared error/DTO layer, OpenAPI (utoipa) + swagger-ui, and the
//! cross-cutting middleware (CORS, tracing, panic recovery, 10 GB body limit). Route
//! groups (auth, files, collab, federation, …) are added in `build_router` as each
//! handler slice lands.

mod config;
mod db;
mod error;
mod handlers;
mod jwt;
mod middleware;
mod models;
mod openapi;
mod ratelimit;
mod ssrf;
mod storage;
mod totp;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::from_fn;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use sqlx::PgPool;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

use config::Config;
use error::AppError;
use models::HealthResponse;

/// Server build identifier returned by `/api/health`. Mirrors `main.buildVersion`
/// in Go (injected via `-ldflags` in release builds; `"dev"` otherwise).
const BUILD_VERSION: &str = "dev";

/// Max request body — mirrors the Fiber `BodyLimit: 10 GB`. Streaming upload routes
/// (tus) disable this per-route once they land (`DefaultBodyLimit::disable()`).
const BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024 * 1024;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub storage: storage::StorageService,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let config = Config::load();
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;
    tracing::info!("migrations applied");

    // Seed admin accounts from ADMIN_ACCOUNTS — mirrors main.bootstrapAdmins.
    bootstrap_admins(&pool, &config.admin_accounts).await;

    // Periodic pruning of the rate-limit + TOTP-block maps (replaces the Go init goroutines).
    ratelimit::spawn_cleanup();

    // S3 (SeaweedFS) storage client — mirrors services.NewStorage in main.go.
    let storage = storage::StorageService::new(
        &config.s3_endpoint,
        &config.s3_access_key,
        &config.s3_secret_key,
        &config.s3_bucket,
        &config.s3_region,
    );

    let state = AppState {
        pool,
        config: Arc::new(config),
        storage,
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("listening on :3000");
    // into_make_service_with_connect_info exposes the peer address so the rate-limit
    // layers can key on the client IP (Fiber's c.IP()).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Seeds admin accounts from `ADMIN_ACCOUNTS` (comma-separated `email:username:password`).
/// Admins must complete first-login setup to establish their E2EE key material — mirrors
/// `main.bootstrapAdmins`.
async fn bootstrap_admins(pool: &PgPool, accounts_env: &str) {
    if accounts_env.is_empty() {
        return;
    }
    for entry in accounts_env.split(',') {
        let parts: Vec<&str> = entry.trim().splitn(3, ':').collect();
        if parts.len() != 3 {
            tracing::warn!(
                "bootstrapAdmins: skipping malformed entry (expected email:username:password)"
            );
            continue;
        }
        let (email, username, password) = (parts[0].trim(), parts[1].trim(), parts[2].trim());
        if email.is_empty() || username.is_empty() || password.is_empty() {
            continue;
        }

        let exists: Option<i64> = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email=$1")
            .bind(email)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
        if exists.unwrap_or(0) > 0 {
            continue;
        }

        let hash = match bcrypt::hash(password, 10) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("bootstrapAdmins: bcrypt error for {email}: {e}");
                continue;
            }
        };

        let res = sqlx::query(
            r#"INSERT INTO users (
                email, username, login_key_hash,
                encrypted_master_key, master_key_nonce,
                encrypted_recovery_key, recovery_key_nonce,
                encrypted_private_key, private_key_nonce,
                public_key, kdf_salt, login_key_salt,
                is_admin, is_first_login
            ) VALUES ($1,$2,$3,'','','','','','','','','',true,true)"#,
        )
        .bind(email)
        .bind(username)
        .bind(&hash)
        .execute(pool)
        .await;
        match res {
            Ok(_) => tracing::info!("bootstrapAdmins: created admin account {email} (@{username})"),
            Err(e) => tracing::warn!("bootstrapAdmins: insert error for {email}: {e}"),
        }
    }
}

/// Builds the application router. Route groups are added here as handlers land.
fn build_router(state: AppState) -> Router {
    let cors = build_cors(&state.config.allowed_origins);

    use handlers::{auth, collections, devices, file_assets, file_versions, files};

    Router::new()
        // OpenAPI spec as JSON. The Go server served an interactive Swagger UI at
        // `/swagger/*`; the UI bundle is deferred (offline-build constraint, see
        // docs/roadmap.md) — the machine-readable spec lives here meanwhile.
        .route("/api-docs/openapi.json", get(openapi_json))
        .route("/api/health", get(health))
        // --- Auth routes (anonymous; rate-limited per the Go middleware chain) ---
        .route("/api/auth/settings", get(auth::get_public_settings))
        .route("/api/auth/register", post(auth::register))
        .route(
            "/api/auth/login/preflight",
            get(auth::get_login_preflight).route_layer(from_fn(middleware::rate_limit_preflight)),
        )
        .route(
            "/api/auth/login",
            post(auth::login).route_layer(from_fn(middleware::rate_limit_login)),
        )
        .route("/api/auth/login/2fa", post(auth::login_two_fa))
        .route(
            "/api/auth/recover/preflight",
            get(auth::get_recovery_preflight).route_layer(from_fn(middleware::rate_limit_recovery)),
        )
        .route(
            "/api/auth/recover",
            post(auth::recover).route_layer(from_fn(middleware::rate_limit_recovery)),
        )
        .route("/api/auth/refresh", post(auth::refresh))
        .route("/api/auth/complete-setup", post(auth::complete_setup))
        // --- User routes (authenticated via the AuthUser extractor) ---
        .route("/api/user/me", get(auth::get_me).patch(auth::update_me))
        .route("/api/user/2fa/setup", post(auth::setup_totp))
        .route("/api/user/2fa/verify", post(auth::verify_totp))
        .route("/api/user/2fa", delete(auth::disable_totp))
        .route("/api/users/by-email/:email", get(auth::get_user_by_email))
        // --- Collections (authenticated). Federated-share + fed-pubkey land in slice 6. ---
        .route(
            "/api/collections",
            get(collections::list_collections).post(collections::create_collection),
        )
        .route(
            "/api/collections/:id",
            get(collections::get_collection)
                .put(collections::update_collection)
                .delete(collections::delete_collection),
        )
        .route(
            "/api/collections/:id/color",
            patch(collections::update_collection_color),
        )
        .route(
            "/api/collections/:id/share",
            post(collections::share_collection),
        )
        .route("/api/collections/:id/files", get(files::list_files))
        // --- Devices (authenticated) ---
        .route("/api/devices", post(devices::register).get(devices::list))
        .route("/api/devices/:id", delete(devices::revoke))
        // --- Files (authenticated) ---
        .route("/api/files/upload", post(files::upload))
        .route("/api/files/:id/download", get(files::download))
        .route(
            "/api/files/:id",
            put(files::update_metadata).delete(files::delete),
        )
        .route("/api/files/:fileId/claim-seed", post(files::claim_seed))
        .route(
            "/api/files/:fileId/versions",
            get(file_versions::list).post(file_versions::record),
        )
        .route(
            "/api/files/:fileId/snapshot-blob",
            post(file_versions::upload_snapshot_blob),
        )
        .route(
            "/api/files/:fileId/versions/:vid/download",
            get(file_versions::download),
        )
        .route(
            "/api/files/:fileId/versions/:vid",
            patch(file_versions::patch),
        )
        .route(
            "/api/files/:fileId/assets/:assetId",
            put(file_assets::upload).get(file_assets::download),
        )
        // Layer order: outermost first. Panic recovery wraps everything so a handler
        // panic becomes a 500 (mirrors Fiber's `recover.New()`); tracing logs each
        // request; CORS + body limit gate inputs.
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .with_state(state)
}

/// Serves the generated OpenAPI document as JSON (utoipa replaces `swaggo/swag`).
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(openapi::ApiDoc::openapi())
}

/// Liveness / identity probe — mirrors `handlers/health.go` `Get`. Anonymous,
/// idempotent, no DB hit; returns `{name, version, tusVersions}`.
async fn health() -> Result<Json<HealthResponse>, AppError> {
    Ok(Json(HealthResponse {
        name: "kutup",
        version: BUILD_VERSION.to_string(),
        tus_versions: vec!["1.0.0"],
    }))
}

/// CORS allowlist (env-driven, never `*` with credentials) — mirrors the Fiber CORS
/// config in `main.go`. `withCredentials` (refresh cookie) is incompatible with a
/// wildcard, so origins are explicit. Header/method lists match the Go config.
fn build_cors(allowed_origins: &str) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .filter_map(|o| o.trim().parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ])
        .allow_headers([
            axum::http::header::ORIGIN,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::AUTHORIZATION,
            // tus.io resumable-upload headers (mirrors the Go AllowHeaders list).
            HeaderName::from_static("tus-resumable"),
            HeaderName::from_static("upload-length"),
            HeaderName::from_static("upload-offset"),
            HeaderName::from_static("upload-metadata"),
            HeaderName::from_static("upload-defer-length"),
            HeaderName::from_static("upload-concat"),
        ])
        .expose_headers([
            HeaderName::from_static("tus-resumable"),
            HeaderName::from_static("upload-offset"),
            HeaderName::from_static("upload-length"),
            axum::http::header::LOCATION,
        ])
}
