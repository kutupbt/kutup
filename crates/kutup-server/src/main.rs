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
mod models;
mod openapi;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method};
use axum::routing::get;
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

    let state = AppState {
        pool,
        config: Arc::new(config),
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("listening on :3000");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Builds the application router. Route groups are added here as handlers land.
fn build_router(state: AppState) -> Router {
    let cors = build_cors(&state.config.allowed_origins);

    Router::new()
        // OpenAPI spec as JSON. The Go server served an interactive Swagger UI at
        // `/swagger/*`; the UI bundle is deferred (offline-build constraint, see
        // docs/roadmap.md) — the machine-readable spec lives here meanwhile.
        .route("/api-docs/openapi.json", get(openapi_json))
        .route("/api/health", get(health))
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
