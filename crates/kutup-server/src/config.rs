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
    /// Maximum simultaneously active chat devices per account. V1 permits
    /// 1..=10; device ids retain their independent libsignal wire range.
    pub chat_max_active_devices: u32,
    /// Maximum Chat-media plaintext-class bytes accepted per immutable object.
    /// Administrators may lower, but never raise, the V1 2 GiB protocol cap.
    pub chat_media_max_plaintext_bytes: u64,
    /// Days an ordinary Chat-media delivery copy remains available. `0`
    /// disables expiry. Protected history-media copies are independent.
    pub chat_media_delivery_retention_days: i64,
    /// Stable canonical DNS suffix used by every local Chat account. This is
    /// required even when inter-server federation is disabled.
    pub chat_server_name: String,
    /// Mail from outside (docs/plans/mail.md): Stalwart's bearer token for
    /// the RCPT hook and its LMTP password. Empty keeps mail off.
    pub mail_inbound_token: String,
    /// Where the LMTP receiver listens (internal network only).
    pub mail_lmtp_bind: String,
    /// Stalwart's submission port, for mail to outside recipients.
    pub mail_submission_addr: String,
    /// Outside recipients one account may send to per hour and per day, so
    /// one compromised account cannot burn the server's reputation.
    pub mail_send_per_hour: i64,
    pub mail_send_per_day: i64,
    /// Test stacks only (`APP_ENV=test`): an http origin every outside key
    /// lookup goes to instead of WKD and the key servers.
    pub mail_test_key_origin: String,
    /// Canonical DNS identity for the unified federation v2 stack.
    pub federation_server_name: String,
    /// Base64 raw 32-byte Ed25519 seed for unified federation v2.
    pub federation_signing_key: String,
    /// Rotation candidate consumed only by the explicit maintenance command.
    pub federation_next_signing_key: String,
    /// Test-only HTTP/private-network escape hatch for the v2 stack.
    pub federation_test_allow_private: bool,
    /// Offer group chats and group calls (`CHAT_GROUPS`, default on). Off,
    /// the server reports no groups, refuses the group routes, and the apps
    /// show direct chats only; groups made earlier stay stored, unreachable.
    pub chat_groups: bool,
    /// Fetch pages for Chat link previews on behalf of this server's users
    /// (`CHAT_LINK_PREVIEWS`, default on). The server then sees the links
    /// its users preview, never their messages.
    pub chat_link_previews: bool,
    /// Wake Chat devices whose browser is closed through Web Push
    /// (`CHAT_WEB_PUSH`, default on). Pushes are empty: the server cannot
    /// say what arrived.
    pub chat_web_push: bool,
    /// Push services the server sends to (`CHAT_WEB_PUSH_HOSTS`): exact
    /// hosts, or `.suffix` for a domain's subdomains.
    pub chat_web_push_hosts: String,
    /// The VAPID contact (`CHAT_WEB_PUSH_SUBJECT`): a `mailto:` or `https:`
    /// URL push services may use to reach the operator.
    pub chat_web_push_subject: String,
    /// Where the map relay keeps its tile cache (`MAPS_CACHE_DIR`;
    /// docs/plans/maps.md). Its size is an administrator setting.
    pub maps_cache_dir: String,
    /// STUN servers for Chat calls (`CHAT_STUN_URLS`, comma list).
    pub chat_stun_urls: String,
    /// TURN relays for Chat calls (`CHAT_TURN_URLS`, comma list of
    /// `turn:`/`turns:` URLs) and their coturn `static-auth-secret`
    /// (`CHAT_TURN_SECRET`). Without both, calls connect only directly.
    pub chat_turn_urls: String,
    pub chat_turn_secret: String,
    /// The LiveKit SFU for group calls this server hosts: the WebSocket URL
    /// browsers connect to (`CHAT_SFU_URL`) and its API key and secret
    /// (`CHAT_SFU_API_KEY`, `CHAT_SFU_API_SECRET`). Without them, accounts
    /// here can join group calls other servers host but not start one.
    pub chat_sfu_url: String,
    /// Where this server reaches the SFU's own API (`CHAT_SFU_API_URL`), to
    /// remove a participant or end a meeting. Empty: `CHAT_SFU_URL` with
    /// `ws` read as `http`.
    pub chat_sfu_api_url: String,
    pub chat_sfu_api_key: String,
    pub chat_sfu_api_secret: String,
    /// Complete authenticated sealed-sender service policy JSON. It contains
    /// public roots and root-signed online certificates, never an offline root.
    pub chat_sealed_sender_policy: String,
    /// Canonical base64 raw libsignal private key for the active online server
    /// certificate. This purpose-specific key issues only sender certificates.
    pub chat_sealed_sender_online_private_key: String,
    /// Complete canonical MLS ordering-service policy JSON. It is authenticated
    /// through the common federation policy chain before any MLS route opens.
    pub chat_mls_ordering_policy: String,
    /// Base64 raw 32-byte Ed25519 seed used only for MLS control-log votes.
    pub chat_mls_control_signing_key: String,
    /// Where each web app lives. Published by `/api/auth/settings` and enforced
    /// for session forks (a fork for `web-drive` is only consumable from `drive`).
    pub apps: AppOrigins,
}

/// The origins of the Kutup web apps (scheme://host[:port], no path).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AppOrigins {
    pub account: String,
    pub drive: String,
    pub chat: String,
    /// The Office home: a person's documents, spreadsheets and presentations,
    /// which are Drive files.
    pub office: String,
    /// The keyless OnlyOffice sandbox; embedded by drive, holds no session.
    pub editor: String,
    /// The Maps app (docs/plans/maps.md).
    pub maps: String,
    /// The Photos app (docs/plans/photos.md).
    pub photos: String,
    /// The Contacts app (docs/plans/contacts.md).
    pub contacts: String,
    /// The Mail app (docs/plans/mail.md).
    pub mail: String,
}

impl AppOrigins {
    /// The origin a forked child session must be consumed from.
    pub fn for_client(&self, client: crate::sessions::ClientType) -> Option<&str> {
        use crate::sessions::ClientType;
        match client {
            ClientType::WebAccount => Some(&self.account),
            ClientType::WebDrive => Some(&self.drive),
            ClientType::WebChat => Some(&self.chat),
            ClientType::WebMaps => Some(&self.maps),
            ClientType::WebPhotos => Some(&self.photos),
            ClientType::WebOffice => Some(&self.office),
            ClientType::WebContacts => Some(&self.contacts),
            ClientType::WebMail => Some(&self.mail),
            ClientType::Cli => None,
        }
    }
}

fn canonical_origin(name: &str, value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|e| format!("{name} is not a URL: {e}"))?;
    let origin = url.origin();
    if !origin.is_tuple() || !matches!(url.scheme(), "https" | "http") {
        return Err(format!("{name} must be an http(s) origin"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{name} must be a bare origin without a path"));
    }
    Ok(origin.ascii_serialization())
}

/// KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE,EDITOR,MAPS,PHOTOS,CONTACTS,MAIL}_URL win; otherwise KUTUP_BASE_DOMAIN gives
/// `https://<app>.<domain>`; otherwise development uses the Vite dev servers
/// (`http://<app>.localhost:<port>`) and production refuses to start.
pub fn resolve_app_origins(
    env: impl Fn(&str) -> Option<String>,
    app_env: &str,
) -> Result<AppOrigins, String> {
    let base = env("KUTUP_BASE_DOMAIN").filter(|v| !v.is_empty());
    let pick = |app: &str, var: &str, dev_port: u16| -> Result<String, String> {
        if let Some(explicit) = env(var).filter(|v| !v.is_empty()) {
            return canonical_origin(var, &explicit);
        }
        if let Some(domain) = &base {
            return canonical_origin("KUTUP_BASE_DOMAIN", &format!("https://{app}.{domain}"));
        }
        if app_env != "production" {
            return Ok(format!("http://{app}.localhost:{dev_port}"));
        }
        Err(format!("set KUTUP_BASE_DOMAIN or {var} in production"))
    };
    let origins = AppOrigins {
        account: pick("account", "KUTUP_ACCOUNT_URL", 5173)?,
        drive: pick("drive", "KUTUP_DRIVE_URL", 5174)?,
        chat: pick("chat", "KUTUP_CHAT_URL", 5175)?,
        office: pick("office", "KUTUP_OFFICE_URL", 5179)?,
        editor: pick("editor", "KUTUP_EDITOR_URL", 5176)?,
        maps: pick("maps", "KUTUP_MAPS_URL", 5177)?,
        photos: pick("photos", "KUTUP_PHOTOS_URL", 5178)?,
        contacts: pick("contacts", "KUTUP_CONTACTS_URL", 5180)?,
        mail: pick("mail", "KUTUP_MAIL_URL", 5181)?,
    };
    let all = [
        &origins.account,
        &origins.drive,
        &origins.chat,
        &origins.office,
        &origins.editor,
        &origins.maps,
        &origins.photos,
        &origins.contacts,
        &origins.mail,
    ];
    for (i, a) in all.iter().enumerate() {
        if all[i + 1..].contains(a) {
            return Err(format!(
                "each Kutup app needs its own origin; {a} is used twice"
            ));
        }
    }
    Ok(origins)
}

impl Config {
    /// Loads config from the environment, panicking on missing required vars or
    /// a too-short JWT secret (mirrors the Go `Load`).
    pub fn load() -> Config {
        let app_env = get_env("APP_ENV", "development");
        let chat_max_active_devices = get_env_i64("CHAT_MAX_ACTIVE_DEVICES", 10);
        if !(1..=10).contains(&chat_max_active_devices) {
            panic!("CHAT_MAX_ACTIVE_DEVICES must be between 1 and 10");
        }
        let chat_media_max_plaintext_bytes = get_env_i64(
            "CHAT_MEDIA_MAX_PLAINTEXT_BYTES",
            kutup_crypto::chat_media::MAX_CHAT_MEDIA_PLAINTEXT_BYTES as i64,
        );
        if !(1..=kutup_crypto::chat_media::MAX_CHAT_MEDIA_PLAINTEXT_BYTES as i64)
            .contains(&chat_media_max_plaintext_bytes)
        {
            panic!("CHAT_MEDIA_MAX_PLAINTEXT_BYTES must be between 1 and 2147483648");
        }
        let chat_mailbox_retention_days = get_env_i64("CHAT_MAILBOX_RETENTION_DAYS", 30);
        crate::site_settings::validate_chat_delivery_retention_days(chat_mailbox_retention_days)
            .unwrap_or_else(|error| panic!("CHAT_MAILBOX_RETENTION_DAYS: {error}"));
        let chat_media_delivery_retention_days =
            get_env_i64("CHAT_MEDIA_DELIVERY_RETENTION_DAYS", 45);
        crate::site_settings::validate_chat_delivery_retention_days(
            chat_media_delivery_retention_days,
        )
        .unwrap_or_else(|error| panic!("CHAT_MEDIA_DELIVERY_RETENTION_DAYS: {error}"));
        let federation_server_name = get_env("FEDERATION_SERVER_NAME", "");
        let chat_server_name = get_env(
            "CHAT_SERVER_NAME",
            if federation_server_name.is_empty() {
                "kutup.local"
            } else {
                &federation_server_name
            },
        );
        kutup_federation_proto::validate_server_name(&chat_server_name).unwrap_or_else(|error| {
            panic!("CHAT_SERVER_NAME must be a canonical DNS name: {error}")
        });
        if !federation_server_name.is_empty() && chat_server_name != federation_server_name {
            panic!(
                "CHAT_SERVER_NAME must match FEDERATION_SERVER_NAME when federation is configured"
            );
        }
        let app_env_for_apps = app_env.clone();
        let cfg = Config {
            database_url: must_env("DATABASE_URL"),
            jwt_secret: must_env("JWT_SECRET"),
            s3_endpoint: must_env("S3_ENDPOINT"),
            s3_access_key: must_env("S3_ACCESS_KEY"),
            s3_secret_key: must_env("S3_SECRET_KEY"),
            s3_bucket: get_env("S3_BUCKET", "kutup-files"),
            s3_region: get_env("S3_REGION", "us-east-1"),
            app_env,
            admin_account: get_env("ADMIN_ACCOUNT", ""),
            break_glass_admin_email: break_glass_email(&get_env("ADMIN_ACCOUNT", "")),
            server_url: get_env("SERVER_URL", "http://kutup.local"),
            allowed_origins: get_env("ALLOWED_ORIGINS", "https://localhost:38443"),
            storage_total_bytes: get_env_i64("STORAGE_TOTAL_BYTES", 0),
            // Set but blank turns the probe off (a store other than SeaweedFS).
            seaweedfs_master_url: std::env::var("SEAWEEDFS_MASTER_URL")
                .unwrap_or_else(|_| "http://seaweedfs-master:9333".to_string()),
            trash_retention_days: get_env_i64("TRASH_RETENTION_DAYS", 30),
            chat_mailbox_retention_days,
            chat_send_retention_days: get_env_i64("CHAT_SEND_RETENTION_DAYS", 30),
            chat_device_expiry_days: get_env_i64("CHAT_DEVICE_EXPIRY_DAYS", 90),
            chat_max_active_devices: chat_max_active_devices as u32,
            chat_media_max_plaintext_bytes: chat_media_max_plaintext_bytes as u64,
            chat_media_delivery_retention_days,
            chat_server_name,
            mail_inbound_token: get_env("MAIL_INBOUND_TOKEN", ""),
            mail_lmtp_bind: get_env("MAIL_LMTP_BIND", "0.0.0.0:2424"),
            mail_submission_addr: get_env("MAIL_SUBMISSION_ADDR", "stalwart:2587"),
            mail_send_per_hour: get_env_i64("MAIL_SEND_RECIPIENTS_PER_HOUR", 100),
            mail_send_per_day: get_env_i64("MAIL_SEND_RECIPIENTS_PER_DAY", 500),
            mail_test_key_origin: get_env("MAIL_TEST_KEY_ORIGIN", ""),
            federation_server_name,
            federation_signing_key: get_env("FEDERATION_SIGNING_KEY", ""),
            federation_next_signing_key: get_env("FEDERATION_NEXT_SIGNING_KEY", ""),
            federation_test_allow_private: get_env_bool("FEDERATION_TEST_ALLOW_PRIVATE", false),
            chat_groups: get_env_bool("CHAT_GROUPS", true),
            chat_link_previews: get_env_bool("CHAT_LINK_PREVIEWS", true),
            chat_web_push: get_env_bool("CHAT_WEB_PUSH", true),
            chat_web_push_hosts: get_env(
                "CHAT_WEB_PUSH_HOSTS",
                crate::web_push::DEFAULT_PUSH_HOSTS,
            ),
            chat_web_push_subject: get_env("CHAT_WEB_PUSH_SUBJECT", ""),
            maps_cache_dir: get_env("MAPS_CACHE_DIR", ""),
            chat_stun_urls: get_env("CHAT_STUN_URLS", ""),
            chat_turn_urls: get_env("CHAT_TURN_URLS", ""),
            chat_turn_secret: get_env("CHAT_TURN_SECRET", ""),
            chat_sfu_url: get_env("CHAT_SFU_URL", ""),
            chat_sfu_api_url: get_env("CHAT_SFU_API_URL", ""),
            chat_sfu_api_key: get_env("CHAT_SFU_API_KEY", ""),
            chat_sfu_api_secret: get_env("CHAT_SFU_API_SECRET", ""),
            chat_sealed_sender_policy: get_env("CHAT_SEALED_SENDER_POLICY", ""),
            chat_sealed_sender_online_private_key: get_env(
                "CHAT_SEALED_SENDER_ONLINE_PRIVATE_KEY",
                "",
            ),
            chat_mls_ordering_policy: get_env("CHAT_MLS_ORDERING_POLICY", ""),
            chat_mls_control_signing_key: get_env("CHAT_MLS_CONTROL_SIGNING_KEY", ""),
            apps: resolve_app_origins(|k| std::env::var(k).ok(), &app_env_for_apps)
                .unwrap_or_else(|error| panic!("app origins: {error}")),
        };
        if cfg.jwt_secret.len() < 32 {
            panic!("JWT_SECRET must be at least 32 characters long");
        }
        if !cfg.mail_inbound_token.is_empty() && cfg.mail_inbound_token.len() < 32 {
            panic!("MAIL_INBOUND_TOKEN must be at least 32 characters long");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn base_domain_derives_https_subdomains() {
        let o = resolve_app_origins(env(&[("KUTUP_BASE_DOMAIN", "example.org")]), "production")
            .unwrap();
        assert_eq!(o.account, "https://account.example.org");
        assert_eq!(o.drive, "https://drive.example.org");
        assert_eq!(o.chat, "https://chat.example.org");
        assert_eq!(o.office, "https://office.example.org");
        assert_eq!(o.editor, "https://editor.example.org");
        assert_eq!(o.maps, "https://maps.example.org");
        assert_eq!(o.photos, "https://photos.example.org");
        assert_eq!(o.contacts, "https://contacts.example.org");
        assert_eq!(o.mail, "https://mail.example.org");
    }

    #[test]
    fn explicit_urls_win_and_are_canonicalised() {
        let o = resolve_app_origins(
            env(&[
                ("KUTUP_BASE_DOMAIN", "example.org"),
                ("KUTUP_DRIVE_URL", "https://Files.Example.org/"),
            ]),
            "production",
        )
        .unwrap();
        assert_eq!(o.drive, "https://files.example.org");
        assert_eq!(o.chat, "https://chat.example.org");
    }

    #[test]
    fn development_falls_back_to_the_vite_dev_hosts() {
        let o = resolve_app_origins(env(&[]), "development").unwrap();
        assert_eq!(o.account, "http://account.localhost:5173");
        assert_eq!(o.drive, "http://drive.localhost:5174");
        assert_eq!(o.chat, "http://chat.localhost:5175");
        assert_eq!(o.office, "http://office.localhost:5179");
        assert_eq!(o.editor, "http://editor.localhost:5176");
        assert_eq!(o.maps, "http://maps.localhost:5177");
        assert_eq!(o.photos, "http://photos.localhost:5178");
        assert_eq!(o.contacts, "http://contacts.localhost:5180");
        assert_eq!(o.mail, "http://mail.localhost:5181");
    }

    #[test]
    fn production_requires_configuration() {
        assert!(resolve_app_origins(env(&[]), "production").is_err());
    }

    #[test]
    fn paths_and_shared_origins_are_rejected() {
        assert!(resolve_app_origins(
            env(&[
                ("KUTUP_BASE_DOMAIN", "example.org"),
                ("KUTUP_DRIVE_URL", "https://x.org/drive")
            ]),
            "production",
        )
        .is_err());
        assert!(resolve_app_origins(
            env(&[
                ("KUTUP_BASE_DOMAIN", "example.org"),
                ("KUTUP_CHAT_URL", "https://drive.example.org"),
            ]),
            "production",
        )
        .is_err());
    }
}
