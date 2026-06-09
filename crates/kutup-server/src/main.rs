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
mod hub;
mod jobs;
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
use axum::{Json, Router, ServiceExt};
use sqlx::PgPool;
use tower::Layer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::normalize_path::NormalizePathLayer;
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
    /// In-memory collab-room registry (one room per fileId) — mirrors the Go `Hub`.
    pub hub: Arc<hub::Hub>,
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

    // S3 (SeaweedFS) storage client — mirrors services.NewStorage in main.go.
    let storage = storage::StorageService::new(
        &config.s3_endpoint,
        &config.s3_access_key,
        &config.s3_secret_key,
        &config.s3_bucket,
        &config.s3_region,
    );

    // Subcommand dispatch — admin tooling that reuses the DB pool + storage without starting
    // the HTTP server. Mirrors the `os.Args[1]` switch in main.go (orphan-sweep). Runs to
    // completion and exits.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "orphan-sweep" {
        let code = run_orphan_sweep_cmd(&pool, &storage, &args[2..]).await;
        std::process::exit(code);
    }

    // Seed admin accounts from ADMIN_ACCOUNTS — mirrors main.bootstrapAdmins.
    bootstrap_admins(&pool, &config.admin_accounts).await;

    // Periodic pruning of the rate-limit + TOTP-block maps (replaces the Go init goroutines).
    ratelimit::spawn_cleanup();

    // Background maintenance jobs (version cleanup / quota reconcile / uploads sweeper) —
    // mirrors the three `go x.Run(...)` calls in main.go.
    jobs::spawn_all(pool.clone(), storage.clone());

    let state = AppState {
        pool,
        config: Arc::new(config),
        storage,
        hub: Arc::new(hub::Hub::new()),
    };

    // Trailing-slash normalization wraps the whole Router from the *outside* (a
    // `Router::layer` only runs for already-matched paths, so it can't rescue an unmatched
    // `/api/collections/`). This mirrors Fiber's default `StrictRouting = false`, which the
    // Go CLI relies on (it calls e.g. `/collections/` with a trailing slash).
    let app = NormalizePathLayer::trim_trailing_slash().layer(build_router(state));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("listening on :3000");
    // into_make_service_with_connect_info exposes the peer address so the rate-limit
    // layers can key on the client IP (Fiber's c.IP()). `ServiceExt` provides it for the
    // NormalizePath-wrapped service (not just a bare Router).
    axum::serve(
        listener,
        ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<SocketAddr>(
            app,
        ),
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

    use handlers::{
        admin, auth, collab, collections, devices, federation, fedproxy, file_assets,
        file_versions, files, shares, tus,
    };

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
        // --- Collections (authenticated). ---
        .route(
            "/api/collections",
            get(collections::list_collections).post(collections::create_collection),
        )
        // Static segment registered alongside `:id` (matchit prefers the literal).
        .route(
            "/api/collections/fed-pubkey",
            get(collections::fetch_remote_pubkey),
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
        .route(
            "/api/collections/:id/share-federated",
            post(collections::share_federated),
        )
        .route("/api/collections/:id/files", get(files::list_files))
        // --- Devices (authenticated) ---
        .route("/api/devices", post(devices::register).get(devices::list))
        .route("/api/devices/:id", delete(devices::revoke))
        // --- tus.io resumable uploads. The OPTIONS discovery is served by the
        // `tus_options_passthrough` layer (mirroring Fiber, which lets non-preflight
        // OPTIONS reach the handler); the rest authenticate via the AuthUser extractor
        // inside each handler. ---
        .route("/api/uploads", post(tus::create))
        .route(
            "/api/uploads/:id",
            patch(tus::patch).head(tus::head).delete(tus::delete),
        )
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
        // --- Collab-edit WebSocket. Auth (token + file access + device) happens inside the
        // handler before the upgrade (mirrors Go's PreUpgrade — browsers can't set headers
        // on `new WebSocket`, so the token may arrive via ?token=). ---
        .route("/api/files/:fileId/collab/ws", get(collab::ws))
        // --- Public shares. Create is authenticated; the read/download endpoints are
        // anonymous (the token is the capability). ---
        .route("/api/share", post(shares::create_public_share))
        .route("/api/share/:token", get(shares::get_public_share))
        .route(
            "/api/share/:token/files",
            get(shares::list_public_share_files),
        )
        .route(
            "/api/share/:token/download/:fileId",
            get(shares::download_public_share_file),
        )
        // --- Federation public endpoints (no auth — the access token is the capability;
        // called by remote kutup servers). `/fed/users` is rate-limited (60/min/IP). ---
        .route(
            "/api/fed/users",
            get(federation::get_user_by_username)
                .route_layer(from_fn(middleware::rate_limit_fed_users)),
        )
        .route("/api/fed/invites/:token", get(federation::get_invite))
        .route(
            "/api/fed/shares/:token/files",
            get(federation::list_share_files).post(federation::upload_share_file),
        )
        .route(
            "/api/fed/shares/:token/files/:fileId/download",
            get(federation::download_share_file),
        )
        .route(
            "/api/fed/shares/:token/files/:fileId",
            delete(federation::delete_share_file),
        )
        // --- Federation proxy (authenticated; the recipient's browser proxies to the
        // remote server through these so it never holds the remote token). ---
        .route(
            "/api/fed-proxy/incoming",
            post(fedproxy::add_incoming_share).get(fedproxy::list_incoming_shares),
        )
        .route(
            "/api/fed-proxy/incoming/:shareId",
            delete(fedproxy::remove_incoming_share),
        )
        .route(
            "/api/fed-proxy/:shareId/files",
            get(fedproxy::proxy_list_files),
        )
        .route(
            "/api/fed-proxy/:shareId/files/:fileId/download",
            get(fedproxy::proxy_download),
        )
        .route(
            "/api/fed-proxy/:shareId/upload",
            post(fedproxy::proxy_upload),
        )
        .route(
            "/api/fed-proxy/:shareId/files/:fileId",
            delete(fedproxy::proxy_delete),
        )
        // --- Admin (authenticated + isAdmin via the AdminUser extractor). ---
        .route(
            "/api/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/api/admin/users/:id",
            put(admin::update_user).delete(admin::delete_user),
        )
        .route("/api/admin/stats", get(admin::get_stats))
        .route(
            "/api/admin/settings",
            get(admin::get_settings).put(admin::update_settings),
        )
        // Layer order: with chained `.layer()` the *last* added is the outermost. The tus
        // OPTIONS passthrough is outermost here so it can answer tus discovery before CORS
        // swallows the OPTIONS (tower-http's CorsLayer, unlike Fiber, intercepts every
        // OPTIONS). Inner of it: CORS + body limit gate inputs; tracing logs each request;
        // panic recovery turns a handler panic into a 500 (mirrors Fiber's `recover.New()`).
        // NOTE: trailing-slash normalization is applied *outside* the Router in `main` (a
        // `Router::layer` runs only for matched paths, so it can't rescue `/collections/`).
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(from_fn(tus_options_passthrough))
        .with_state(state)
}

/// Serves the tus discovery response for non-preflight `OPTIONS` on the upload endpoints,
/// mirroring Fiber's CORS behaviour: a request with both `Origin` and
/// `Access-Control-Request-Method` is a real browser preflight and falls through to the
/// CORS layer; everything else (CLI/curl/tus discovery) reaches `tus::Options`. tower-http's
/// `CorsLayer`, unlike Fiber, intercepts *all* OPTIONS, so this layer sits outside it.
async fn tus_options_passthrough(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.method() == Method::OPTIONS {
        let path = req.uri().path();
        let is_uploads = path == "/api/uploads"
            || path
                .strip_prefix("/api/uploads/")
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'));
        let is_preflight = req.headers().contains_key(axum::http::header::ORIGIN)
            && req
                .headers()
                .contains_key(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD);
        if is_uploads && !is_preflight {
            return handlers::tus::options().await;
        }
    }
    next.run(req).await
}

/// Parses + runs the `orphan-sweep` subcommand — mirrors `cmd.RunOrphanSweep`. Dry-run by
/// default; `--delete` actually removes orphans. Returns the process exit code.
async fn run_orphan_sweep_cmd(
    pool: &PgPool,
    storage: &storage::StorageService,
    args: &[String],
) -> i32 {
    let mut delete = false;
    let mut age_floor = std::time::Duration::from_secs(24 * 3600);
    let mut page_sleep = std::time::Duration::from_millis(200);
    let mut prefix = "files/".to_string();
    for a in args {
        if a == "--delete" {
            delete = true;
        } else if let Some(v) = a.strip_prefix("--age-floor=") {
            match parse_go_duration(v) {
                Some(d) => age_floor = d,
                None => {
                    eprintln!("orphan-sweep: bad --age-floor: {v}");
                    return 1;
                }
            }
        } else if let Some(v) = a.strip_prefix("--page-sleep=") {
            match parse_go_duration(v) {
                Some(d) => page_sleep = d,
                None => {
                    eprintln!("orphan-sweep: bad --page-sleep: {v}");
                    return 1;
                }
            }
        } else if let Some(v) = a.strip_prefix("--prefix=") {
            prefix = v.to_string();
        } else {
            eprintln!("orphan-sweep: unknown arg: {a}");
            return 1;
        }
    }
    let mode = if delete { "DELETE" } else { "DRY-RUN" };
    tracing::info!(
        "orphan-sweep: starting mode={mode} age-floor={age_floor:?} page-sleep={page_sleep:?} prefix={prefix}"
    );
    match jobs::run_orphan_sweep(pool, storage, &prefix, age_floor, page_sleep, delete).await {
        Ok(r) => {
            tracing::info!(
                "orphan-sweep summary: pages={} keys={} orphans={} skipped-age={} skipped-shape={} deleted={} bytes-reclaimed={} mode={}",
                r.pages_scanned, r.keys_scanned, r.orphans_found, r.skipped_age,
                r.skipped_shape, r.deleted, r.bytes_reclaimed, mode
            );
            0
        }
        Err(e) => {
            eprintln!("orphan-sweep: failed: {e}");
            1
        }
    }
}

/// Parses the subset of Go `time.Duration` strings the sweep flags use (`24h`, `1h`, `30m`,
/// `200ms`, `0`). Returns `None` on anything unrecognised.
fn parse_go_duration(s: &str) -> Option<std::time::Duration> {
    if s == "0" {
        return Some(std::time::Duration::ZERO);
    }
    if let Some(n) = s.strip_suffix("ms") {
        return n.parse::<u64>().ok().map(std::time::Duration::from_millis);
    }
    if let Some(n) = s.strip_suffix('h') {
        return n
            .parse::<u64>()
            .ok()
            .map(|h| std::time::Duration::from_secs(h * 3600));
    }
    if let Some(n) = s.strip_suffix('m') {
        return n
            .parse::<u64>()
            .ok()
            .map(|m| std::time::Duration::from_secs(m * 60));
    }
    if let Some(n) = s.strip_suffix('s') {
        return n.parse::<u64>().ok().map(std::time::Duration::from_secs);
    }
    None
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
