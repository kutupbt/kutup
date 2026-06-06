//! kutup backend API — Rust rewrite of `backend/` (Axum + sqlx).
//!
//! This is the Phase-3 scaffold: config, the Postgres pool + migrations, and an
//! Axum app serving `/api/health`. Handlers (auth, files, collab, federation,
//! …) land in subsequent slices; the route groups are added as each is wired.

mod config;
mod db;

use std::sync::Arc;

use axum::http::{HeaderName, HeaderValue, Method};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use sqlx::PgPool;
use tower_http::cors::CorsLayer;

use config::Config;

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
        .route("/api/health", get(health))
        .layer(cors)
        .with_state(state)
}

/// Liveness probe — mirrors `handlers/health.go` (no DB touch).
async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// CORS allowlist (env-driven, never `*` with credentials) — mirrors the Fiber
/// CORS config. `withCredentials` (refresh cookie) is incompatible with a
/// wildcard, so origins are explicit.
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
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::CONTENT_LENGTH,
            // tus.io resumable-upload headers.
            HeaderName::from_static("tus-resumable"),
            HeaderName::from_static("upload-length"),
            HeaderName::from_static("upload-metadata"),
            HeaderName::from_static("upload-offset"),
        ])
}
