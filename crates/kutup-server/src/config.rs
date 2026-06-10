//! Environment configuration — mirrors `backend/config/config.go`.

/// Server configuration loaded from the environment.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub s3_endpoint: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_bucket: String,
    pub s3_region: String,
    pub app_env: String,
    /// The single bootstrap admin account, `email:username:password`. Created at first boot;
    /// this is the protected "break-glass" admin. From `ADMIN_ACCOUNT`.
    pub admin_account: String,
    /// Email of the break-glass admin, derived from `admin_account`. Never demotable/
    /// disableable/deletable via the API/UI. Empty when `ADMIN_ACCOUNT` is unset.
    pub break_glass_admin_email: String,
    /// e.g. `https://kutup.example.com` — used for federation invite links.
    pub server_url: String,
    /// Comma-separated CORS allowlist (`*` allowed in dev only).
    pub allowed_origins: String,
    /// Total storage capacity advertised to the admin UI; 0 = unknown. Fallback/override when
    /// the live SeaweedFS probe is unavailable.
    pub storage_total_bytes: i64,
    /// SeaweedFS master endpoint probed for real capacity + usage (admin dashboard). Empty
    /// disables the probe (the admin UI then falls back to `storage_total_bytes`).
    pub seaweedfs_master_url: String,
}

impl Config {
    /// Loads config from the environment, panicking on missing required vars or
    /// a too-short JWT secret (mirrors the Go `Load`).
    pub fn load() -> Config {
        let cfg = Config {
            database_url: must_env("DATABASE_URL"),
            jwt_secret: must_env("JWT_SECRET"),
            s3_endpoint: must_env("S3_ENDPOINT"),
            s3_access_key: must_env("S3_ACCESS_KEY"),
            s3_secret_key: must_env("S3_SECRET_KEY"),
            s3_bucket: get_env("S3_BUCKET", "kutup-files"),
            s3_region: get_env("S3_REGION", "us-east-1"),
            app_env: get_env("APP_ENV", "development"),
            admin_account: get_env("ADMIN_ACCOUNT", ""),
            break_glass_admin_email: break_glass_email(&get_env("ADMIN_ACCOUNT", "")),
            server_url: get_env("SERVER_URL", "http://kutup.local"),
            allowed_origins: get_env(
                "ALLOWED_ORIGINS",
                "https://localhost:38443,tauri://localhost,http://tauri.localhost",
            ),
            storage_total_bytes: get_env_i64("STORAGE_TOTAL_BYTES", 0),
            seaweedfs_master_url: get_env("SEAWEEDFS_MASTER_URL", "http://seaweedfs-master:9333"),
        };
        if cfg.jwt_secret.len() < 32 {
            panic!("JWT_SECRET must be at least 32 characters long");
        }
        cfg
    }
}

/// Extracts the break-glass admin's email (the first field of `email:username:password`) —
/// mirrors `breakGlassEmail`. Empty when the account is unset or malformed.
fn break_glass_email(admin_account: &str) -> String {
    let acct = admin_account.trim();
    if acct.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = acct.splitn(3, ':').collect();
    if parts.len() != 3 {
        return String::new();
    }
    parts[0].trim().to_string()
}

fn must_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("required environment variable not set: {key}"))
}

fn get_env(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

fn get_env_i64(key: &str, fallback: i64) -> i64 {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v.parse().ok().filter(|&n| n >= 0).unwrap_or(fallback),
        _ => fallback,
    }
}
