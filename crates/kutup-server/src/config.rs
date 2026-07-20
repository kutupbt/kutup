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
    /// e.g. `https://kutup.example.com` — published as the federation API base.
    pub server_url: String,
    /// Comma-separated CORS allowlist (`*` allowed in dev only).
    pub allowed_origins: String,
    /// Total storage capacity advertised to the admin UI; 0 = unknown. Fallback/override when
    /// the live SeaweedFS probe is unavailable.
    pub storage_total_bytes: i64,
    /// SeaweedFS master endpoint probed for real capacity + usage (admin dashboard). Empty
    /// disables the probe (the admin UI then falls back to `storage_total_bytes`).
    pub seaweedfs_master_url: String,
    /// Days a trashed file/folder is kept before the sweeper purges it permanently.
    /// From `TRASH_RETENTION_DAYS`; 0 disables the automatic purge.
    pub trash_retention_days: i64,
    /// Unacked chat ciphertext retention. `0` disables expiry.
    pub chat_mailbox_retention_days: i64,
    /// Send-id idempotency-record retention. `0` disables expiry.
    pub chat_send_retention_days: i64,
    /// Chat devices with no authenticated activity for this many days are
    /// expired with their prekeys/mailbox. `0` disables expiry.
    pub chat_device_expiry_days: i64,
    /// Canonical DNS identity for the unified federation v2 stack.
    pub federation_server_name: String,
    /// Base64 raw 32-byte Ed25519 seed for unified federation v2.
    pub federation_signing_key: String,
    /// Rotation candidate consumed only by the explicit maintenance command.
    pub federation_next_signing_key: String,
    /// Test-only HTTP/private-network escape hatch for the v2 stack.
    pub federation_test_allow_private: bool,
    /// Base64 raw 32-byte Ed25519 seed for stable transparency checkpoints.
    /// This key is deliberately distinct from federation request signing.
    pub chat_transparency_signing_key: String,
    /// Comma-separated `witness-id=base64-ed25519-public-key` allowlist.
    pub chat_transparency_witnesses: String,
    /// Minimum configured witness attestations clients require on a head.
    pub chat_transparency_witness_quorum: i64,
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
            trash_retention_days: get_env_i64("TRASH_RETENTION_DAYS", 30),
            chat_mailbox_retention_days: get_env_i64("CHAT_MAILBOX_RETENTION_DAYS", 30),
            chat_send_retention_days: get_env_i64("CHAT_SEND_RETENTION_DAYS", 30),
            chat_device_expiry_days: get_env_i64("CHAT_DEVICE_EXPIRY_DAYS", 90),
            federation_server_name: get_env("FEDERATION_SERVER_NAME", ""),
            federation_signing_key: get_env("FEDERATION_SIGNING_KEY", ""),
            federation_next_signing_key: get_env("FEDERATION_NEXT_SIGNING_KEY", ""),
            federation_test_allow_private: get_env_bool("FEDERATION_TEST_ALLOW_PRIVATE", false),
            chat_transparency_signing_key: get_env("CHAT_TRANSPARENCY_SIGNING_KEY", ""),
            chat_transparency_witnesses: get_env("CHAT_TRANSPARENCY_WITNESSES", ""),
            chat_transparency_witness_quorum: get_env_i64("CHAT_TRANSPARENCY_WITNESS_QUORUM", 0),
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

fn get_env_bool(key: &str, fallback: bool) -> bool {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => true,
            "0" | "false" | "no" => false,
            _ => fallback,
        },
        _ => fallback,
    }
}
