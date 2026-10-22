//! Environment configuration — mirrors `backend/config/config.go`.

/// Server configuration loaded from the environment.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    /// The keys the OPAQUE server setups are sealed under
    /// (`OPAQUE_SETUP_KEYS`, docs/plans/opaque.md §5). Never logged.
    pub opaque_setup_keys: crate::opaque_setup::OpaqueSetupKeys,
    /// The keys end-to-end mail forwarding's proxy factors are sealed under
    /// (`MAIL_FORWARDING_KEYS`, `id:base64,…` like `OPAQUE_SETUP_KEYS`;
    /// docs/plans/mail-forwarding.md). Optional: without them, end-to-end
    /// forwarding can't be set up. Never logged.
    pub mail_forwarding_keys: crate::opaque_setup::OpaqueSetupKeys,
    /// The keys custom domains' DKIM keys are sealed under
    /// (`MAIL_DKIM_KEYS`, the same `id:base64,…` form;
    /// docs/plans/mail-custom-domains.md §4). Without them, custom domains
    /// are off. Never logged.
    pub mail_dkim_keys: crate::opaque_setup::OpaqueSetupKeys,
    pub s3_endpoint: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_bucket: String,
    pub s3_region: String,
    pub app_env: String,
    /// The single bootstrap admin account, `username:password` (the password
    /// may hold colons). Created at first boot; this is the
    /// protected "break-glass" admin. From `ADMIN_ACCOUNT`.
    pub admin_account: String,
    /// Username of the break-glass admin, from `admin_account`. Never demotable/
    /// disableable/deletable via the API/UI. Empty when `ADMIN_ACCOUNT` is unset.
    pub break_glass_admin_username: String,
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
    /// Who may send to addresses outside Kutup (`MAIL_OUTSIDE_SENDING`):
    /// off until the server's mail setup is checked, admins for the sending
    /// trial, then everyone.
    pub mail_outside_sending: OutsideSending,
    /// Messages one statement of a select-all batch changes at most
    /// (`MAIL_BATCH_CHUNK`, 5,000); each chunk is its own transaction.
    pub mail_batch_chunk: usize,
    /// Undo send's delay for accounts that did not choose one
    /// (`MAIL_DEFAULT_DELAY_SEND_SECONDS`: 0, 5, 10 or 20; 10, as Proton's).
    pub mail_default_delay_send_seconds: i32,
    /// An account's first days, and the outside recipients a day it may
    /// send to in them (most abuse comes from new accounts).
    pub mail_new_account_days: i64,
    pub mail_new_account_per_day: i64,
    /// Folders and labels an account may make (`MAIL_FOLDERS_PER_ACCOUNT`,
    /// `MAIL_LABELS_PER_ACCOUNT`), the levers a priced plan would use.
    /// Stalwart's host name (`MAIL_HOSTNAME`): the authserv-id of the
    /// Authentication-Results it writes, the only one trusted for DMARC.
    pub mail_hostname: String,
    /// The nameserver custom domains' checks ask (`MAIL_DNS_RESOLVER`,
    /// `host:port`, looked up once); the system's when unset. The server
    /// validates DNSSEC itself either way, but on a test stack
    /// (`MAIL_DNS_INSECURE`, with `APP_ENV=test` only), whose zones no root
    /// can vouch for.
    pub mail_dns_resolver: Option<String>,
    pub mail_dns_insecure: bool,
    /// How often custom domains' sweep runs (`MAIL_DOMAINS_SWEEP_SECONDS`).
    pub mail_domains_sweep_seconds: u64,
    /// `MAIL_DOMAINS_TIME_SCALE` (test stacks only): custom domains' periods
    /// divided by it, for the live tests.
    pub mail_domains_time_scale: i64,
    /// A backup MX the operator runs (`MAIL_BACKUP_MX`): a custom domain
    /// whose first MX is it counts as reaching us (Proton's `BACKUP`).
    pub mail_backup_mx: Option<String>,
    /// Stalwart's management API for custom domains (`MAIL_STALWART_URL`)
    /// and the password of the scoped account that may manage only domains and DKIM
    /// signatures (`MAIL_STALWART_DOMAINS_TOKEN`). Without the key, custom
    /// domains are off: Stalwart couldn't take their mail.
    pub mail_stalwart_url: String,
    pub mail_stalwart_domains_token: String,
    pub mail_folders_per_account: i64,
    /// `NAME_HOLD_DAYS` and `OLD_ADDRESS_RECEIVE_DAYS`: the first values of
    /// the name holds administrators set (`site_settings::name_holds`).
    pub name_hold_days: i64,
    pub old_address_receive_days: i64,
    /// `NAME_SWEEP_SECONDS`: how often old addresses are closed and held
    /// names freed on their dates (an hour; seconds on test stacks).
    pub name_sweep_seconds: i64,
    pub mail_labels_per_account: i64,
    /// Filters an account may have switched on (`MAIL_FILTERS_PER_ACCOUNT`).
    pub mail_filters_per_account: i64,
    /// Block, spam and allow entries an account may have (`MAIL_SENDER_RULES_PER_ACCOUNT`).
    pub mail_sender_rules_per_account: i64,
    /// Where an administrator forwards feedback for public tracking
    /// (`FEEDBACK_GITHUB_REPOSITORY`, `owner/repo`; default `kutupbt/kutup`,
    /// `off` for none). The apps also offer it to people who want to report
    /// there themselves; nothing is sent to it by the server.
    pub feedback_github_repository: Option<String>,
    /// Canonical DNS identity for the unified federation v2 stack.
    pub federation_server_name: String,
    /// Base64 raw 32-byte Ed25519 seed for unified federation v2.
    pub federation_signing_key: String,
    /// Rotation candidate consumed only by the explicit maintenance command.
    pub federation_next_signing_key: String,
    /// Test-only HTTP/private-network escape hatch for the v2 stack
    /// (`FEDERATION_TEST_ALLOW_PRIVATE`; APP_ENV=test only).
    pub federation_test_allow_private: bool,
    /// Test stacks: every rate limit's default raised (`RATE_LIMITS_RELAXED`;
    /// APP_ENV=test only).
    pub rate_limits_relaxed: bool,
    /// The registration mode written once, at startup, into a database that
    /// has none (`REGISTRATION_MODE`: on, code or off; default off). Never
    /// read after that: the stored mode is the only source
    /// (docs/plans/registration-codes.md).
    pub registration_mode: crate::registration::RegistrationMode,
    /// Offer group chats and group calls (`CHAT_GROUPS`, default off: groups
    /// return with the pairwise group design that replaces MLS, roadmap).
    /// Off, the server reports no groups, refuses the group routes, and the
    /// apps show direct chats only; groups made earlier stay stored,
    /// unreachable.
    pub chat_groups: bool,
    /// The most members (and open invitations) a group hosted here may have
    /// (`CHAT_GROUP_MAX_MEMBERS`, 1 to 256, default 256;
    /// docs/plans/pairwise-groups.md §7).
    pub chat_group_max_members: usize,
    /// The most groups this server hosts (`CHAT_GROUP_MAX_GROUPS`, default
    /// 100000): with the per-server creation limit, a peer can't fill it.
    pub chat_group_max_groups: i64,
    /// Sealed-federation flush locks held at once, each a Postgres session
    /// beside the main pool (`SEALED_FLUSH_LOCK_CONNECTIONS`, 1 to 64,
    /// default 4; docs/self-hosting.md).
    pub sealed_flush_lock_connections: u32,
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
    /// The keyless OnlyOffice sandbox; embedded by Office, holds no session.
    pub editor: String,
    /// The Maps app (docs/plans/maps.md).
    pub maps: String,
    /// The Photos app (docs/plans/photos.md).
    pub photos: String,
    /// The Contacts app (docs/plans/contacts.md).
    pub contacts: String,
    /// The Mail app (docs/plans/mail.md).
    pub mail: String,
    /// Kutup Pass, the password manager (docs/plans/pass.md).
    pub pass: String,
    /// The Calendar app (docs/plans/calendar.md).
    pub calendar: String,
}

impl AppOrigins {
    /// Placeholders while a configuration error is reported.
    fn unset() -> Self {
        let none = String::new;
        AppOrigins {
            account: none(),
            drive: none(),
            chat: none(),
            office: none(),
            editor: none(),
            maps: none(),
            photos: none(),
            contacts: none(),
            mail: none(),
            pass: none(),
            calendar: none(),
        }
    }

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
            ClientType::WebPass => Some(&self.pass),
            ClientType::WebCalendar => Some(&self.calendar),
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

/// KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE,EDITOR,MAPS,PHOTOS,CONTACTS,MAIL,PASS}_URL win; otherwise KUTUP_BASE_DOMAIN gives
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
        pass: pick("pass", "KUTUP_PASS_URL", 5182)?,
        calendar: pick("calendar", "KUTUP_CALENDAR_URL", 5183)?,
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
        &origins.pass,
        &origins.calendar,
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
        let env = Env::process();
        let cfg = Self::from_env(&env);
        if let Err(errors) = env.finish() {
            eprintln!("kutup-server: the configuration is not valid:");
            for error in errors {
                eprintln!("  {error}");
            }
            std::process::exit(2);
        }
        cfg
    }

    /// Reads every setting through `env`, which records each value it cannot
    /// read (a number that is not one, an unknown choice) instead of falling
    /// back to a default: a typo must stop the server, not change what it does.
    fn from_env(env: &Env) -> Config {
        let get_env = |key: &str, fallback: &str| env.string(key, fallback);
        let get_env_i64 = |key: &str, fallback: i64| env.int(key, fallback);
        let get_env_bool = |key: &str, fallback: bool| env.bool(key, fallback);
        let must_env = |key: &str| env.required(key);
        let app_env = env.choice(
            "APP_ENV",
            "development",
            &["development", "test", "production"],
        );
        let rate_limits_relaxed = env.bool("RATE_LIMITS_RELAXED", false);
        if rate_limits_relaxed && app_env != "test" {
            env.error("RATE_LIMITS_RELAXED may only be enabled with APP_ENV=test");
        }
        crate::ratelimit::configure(env, rate_limits_relaxed);
        let mail_domains_time_scale = get_env_i64("MAIL_DOMAINS_TIME_SCALE", 1).max(1);
        if mail_domains_time_scale > 1 && app_env != "test" {
            env.error("MAIL_DOMAINS_TIME_SCALE may only be set with APP_ENV=test");
        }
        let mail_dns_insecure = env.bool("MAIL_DNS_INSECURE", false);
        if mail_dns_insecure && app_env != "test" {
            env.error("MAIL_DNS_INSECURE may only be enabled with APP_ENV=test");
        }
        let registration_mode = crate::registration::RegistrationMode::parse(&env.choice(
            "REGISTRATION_MODE",
            "off",
            &["on", "code", "off"],
        ))
        .unwrap_or(crate::registration::RegistrationMode::Off);
        let federation_test_allow_private = env.bool("FEDERATION_TEST_ALLOW_PRIVATE", false);
        if federation_test_allow_private && app_env != "test" {
            env.error("FEDERATION_TEST_ALLOW_PRIVATE may only be enabled with APP_ENV=test");
        }
        let chat_group_max_members = get_env_i64("CHAT_GROUP_MAX_MEMBERS", 256);
        if !(1..=256).contains(&chat_group_max_members) {
            env.error("CHAT_GROUP_MAX_MEMBERS must be between 1 and 256");
        }
        let sealed_flush_lock_connections = get_env_i64("SEALED_FLUSH_LOCK_CONNECTIONS", 4);
        if !(1..=64).contains(&sealed_flush_lock_connections) {
            env.error("SEALED_FLUSH_LOCK_CONNECTIONS must be between 1 and 64");
        }
        let chat_group_max_groups = get_env_i64("CHAT_GROUP_MAX_GROUPS", 100_000);
        if chat_group_max_groups < 1 {
            env.error("CHAT_GROUP_MAX_GROUPS must be at least 1");
        }
        let chat_max_active_devices = get_env_i64("CHAT_MAX_ACTIVE_DEVICES", 10);
        if !(1..=10).contains(&chat_max_active_devices) {
            env.error("CHAT_MAX_ACTIVE_DEVICES must be between 1 and 10");
        }
        let chat_media_max_plaintext_bytes = get_env_i64(
            "CHAT_MEDIA_MAX_PLAINTEXT_BYTES",
            kutup_crypto::chat_media::MAX_CHAT_MEDIA_PLAINTEXT_BYTES as i64,
        );
        if !(1..=kutup_crypto::chat_media::MAX_CHAT_MEDIA_PLAINTEXT_BYTES as i64)
            .contains(&chat_media_max_plaintext_bytes)
        {
            env.error("CHAT_MEDIA_MAX_PLAINTEXT_BYTES must be between 1 and 2147483648");
        }
        let chat_mailbox_retention_days = get_env_i64("CHAT_MAILBOX_RETENTION_DAYS", 30);
        if let Err(error) =
            crate::site_settings::validate_chat_delivery_retention_days(chat_mailbox_retention_days)
        {
            env.error(format!("CHAT_MAILBOX_RETENTION_DAYS: {error}"));
        }
        let chat_media_delivery_retention_days =
            get_env_i64("CHAT_MEDIA_DELIVERY_RETENTION_DAYS", 45);
        if let Err(error) = crate::site_settings::validate_chat_delivery_retention_days(
            chat_media_delivery_retention_days,
        ) {
            env.error(format!("CHAT_MEDIA_DELIVERY_RETENTION_DAYS: {error}"));
        }
        let federation_server_name = get_env("FEDERATION_SERVER_NAME", "");
        let chat_server_name = get_env(
            "CHAT_SERVER_NAME",
            if federation_server_name.is_empty() {
                "kutup.local"
            } else {
                &federation_server_name
            },
        );
        if let Err(error) = kutup_federation_proto::validate_server_name(&chat_server_name) {
            env.error(format!(
                "CHAT_SERVER_NAME must be a canonical DNS name: {error}"
            ));
        }
        if !federation_server_name.is_empty() && chat_server_name != federation_server_name {
            env.error(
                "CHAT_SERVER_NAME must match FEDERATION_SERVER_NAME when federation is configured",
            );
        }
        let app_env_for_apps = app_env.clone();
        let cfg = Config {
            database_url: must_env("DATABASE_URL"),
            jwt_secret: must_env("JWT_SECRET"),
            opaque_setup_keys: {
                let value = env.opaque_setup_keys();
                if value.is_empty() {
                    Default::default()
                } else {
                    crate::opaque_setup::OpaqueSetupKeys::parse(&value).unwrap_or_else(|error| {
                        env.error(format!("OPAQUE_SETUP_KEYS: {error}"));
                        Default::default()
                    })
                }
            },
            mail_dkim_keys: match env.set("MAIL_DKIM_KEYS") {
                None => Default::default(),
                Some(value) => {
                    crate::opaque_setup::OpaqueSetupKeys::parse(&value).unwrap_or_else(|error| {
                        env.error(format!("MAIL_DKIM_KEYS: {error}"));
                        Default::default()
                    })
                }
            },
            mail_forwarding_keys: match env.set("MAIL_FORWARDING_KEYS") {
                None => Default::default(),
                Some(value) => {
                    crate::opaque_setup::OpaqueSetupKeys::parse(&value).unwrap_or_else(|error| {
                        env.error(format!("MAIL_FORWARDING_KEYS: {error}"));
                        Default::default()
                    })
                }
            },
            s3_endpoint: must_env("S3_ENDPOINT"),
            s3_access_key: must_env("S3_ACCESS_KEY"),
            s3_secret_key: must_env("S3_SECRET_KEY"),
            s3_bucket: get_env("S3_BUCKET", "kutup-files"),
            s3_region: get_env("S3_REGION", "us-east-1"),
            app_env,
            admin_account: get_env("ADMIN_ACCOUNT", ""),
            break_glass_admin_username: break_glass_username(&get_env("ADMIN_ACCOUNT", "")),
            server_url: get_env("SERVER_URL", "http://kutup.local"),
            allowed_origins: get_env("ALLOWED_ORIGINS", "https://localhost:38443"),
            storage_total_bytes: get_env_i64("STORAGE_TOTAL_BYTES", 0),
            // Set but blank turns the probe off (a store other than SeaweedFS).
            seaweedfs_master_url: env
                .raw("SEAWEEDFS_MASTER_URL")
                .unwrap_or_else(|| "http://seaweedfs-master:9333".to_string()),
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
            mail_outside_sending: OutsideSending::parse(&env.choice(
                "MAIL_OUTSIDE_SENDING",
                "off",
                &["off", "admins", "on"],
            )),
            mail_batch_chunk: match get_env_i64("MAIL_BATCH_CHUNK", 5_000) {
                0 => {
                    env.error("MAIL_BATCH_CHUNK must be at least 1");
                    1
                }
                chunk => chunk as usize,
            },
            mail_default_delay_send_seconds: match get_env_i64(
                "MAIL_DEFAULT_DELAY_SEND_SECONDS",
                10,
            ) {
                seconds @ (0 | 5 | 10 | 20) => seconds as i32,
                _ => {
                    env.error("MAIL_DEFAULT_DELAY_SEND_SECONDS must be 0, 5, 10 or 20");
                    10
                }
            },
            mail_new_account_days: get_env_i64("MAIL_NEW_ACCOUNT_DAYS", 7),
            mail_new_account_per_day: get_env_i64("MAIL_NEW_ACCOUNT_RECIPIENTS_PER_DAY", 50),
            mail_hostname: get_env("MAIL_HOSTNAME", "").trim().to_ascii_lowercase(),
            mail_dns_resolver: match get_env("MAIL_DNS_RESOLVER", "").trim() {
                "" => None,
                value
                    if value
                        .rsplit_once(':')
                        .is_some_and(|(_, port)| port.parse::<u16>().is_ok()) =>
                {
                    Some(value.to_owned())
                }
                _ => {
                    env.error("MAIL_DNS_RESOLVER must be a host:port");
                    None
                }
            },
            mail_dns_insecure,
            mail_domains_time_scale,
            mail_domains_sweep_seconds: (get_env_i64("MAIL_DOMAINS_SWEEP_SECONDS", 300)
                .clamp(5, 3600)) as u64,
            mail_stalwart_url: get_env("MAIL_STALWART_URL", "http://stalwart:8080"),
            mail_stalwart_domains_token: get_env("MAIL_STALWART_DOMAINS_TOKEN", ""),
            mail_backup_mx: Some(get_env("MAIL_BACKUP_MX", "").trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty()),
            mail_folders_per_account: get_env_i64("MAIL_FOLDERS_PER_ACCOUNT", 500),
            name_hold_days: get_env_i64("NAME_HOLD_DAYS", 180),
            old_address_receive_days: get_env_i64("OLD_ADDRESS_RECEIVE_DAYS", 90),
            name_sweep_seconds: get_env_i64("NAME_SWEEP_SECONDS", 3600).clamp(1, 86_400),
            mail_labels_per_account: get_env_i64("MAIL_LABELS_PER_ACCOUNT", 500),
            mail_filters_per_account: get_env_i64("MAIL_FILTERS_PER_ACCOUNT", 200),
            mail_sender_rules_per_account: get_env_i64("MAIL_SENDER_RULES_PER_ACCOUNT", 5000),
            feedback_github_repository: github_repository(&get_env(
                "FEEDBACK_GITHUB_REPOSITORY",
                "kutupbt/kutup",
            ))
            .unwrap_or_else(|error| {
                env.error(error);
                None
            }),
            federation_server_name,
            federation_signing_key: get_env("FEDERATION_SIGNING_KEY", ""),
            federation_next_signing_key: get_env("FEDERATION_NEXT_SIGNING_KEY", ""),
            federation_test_allow_private,
            rate_limits_relaxed,
            registration_mode,
            chat_groups: get_env_bool("CHAT_GROUPS", false),
            chat_group_max_members: chat_group_max_members.clamp(1, 256) as usize,
            sealed_flush_lock_connections: sealed_flush_lock_connections.clamp(1, 64) as u32,
            chat_group_max_groups: chat_group_max_groups.max(1),
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
            apps: resolve_app_origins(|k| env.raw(k), &app_env_for_apps).unwrap_or_else(|error| {
                env.error(format!("app origins: {error}"));
                AppOrigins::unset()
            }),
        };
        for origin in cfg.allowed_origins.split(',').map(str::trim) {
            if origin == "*" {
                if cfg.app_env == "production" {
                    env.error("ALLOWED_ORIGINS may not be * when APP_ENV=production");
                }
            } else if canonical_origin("ALLOWED_ORIGINS", origin).is_err() {
                env.error(format!(
                    "ALLOWED_ORIGINS: {origin:?} is not an http(s) origin"
                ));
            }
        }
        if url::Url::parse(&cfg.server_url).is_err() {
            env.error("SERVER_URL must be a URL");
        }
        if cfg.jwt_secret.len() < 32 {
            env.error("JWT_SECRET must be at least 32 characters long");
        }
        if !cfg.mail_inbound_token.is_empty() && cfg.mail_inbound_token.len() < 32 {
            env.error("MAIL_INBOUND_TOKEN must be at least 32 characters long");
        }
        if !cfg.admin_account.trim().is_empty() && parse_admin_account(&cfg.admin_account).is_none()
        {
            env.error(
                "ADMIN_ACCOUNT must be username:password (a username of 3 to 32 lowercase letters, digits, _ or -)",
            );
        }
        cfg
    }
}

/// The break-glass admin's username (the first field of `username:password`).
/// Empty when the account is unset or malformed.
fn break_glass_username(admin_account: &str) -> String {
    parse_admin_account(admin_account)
        .map(|(username, _)| username)
        .unwrap_or_default()
}

/// `ADMIN_ACCOUNT` as `(username, password)`: `username:password` (the
/// password may hold colons). A username that is not one an account may
/// have (lowercase letters, digits, `_` and `-`, 3 to 32) is refused, since
/// it could never sign in — so is the retired `email:username:password`.
pub(crate) fn parse_admin_account(admin_account: &str) -> Option<(String, String)> {
    let (username, password) = admin_account.trim().split_once(':')?;
    let username = username.trim();
    let valid = (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    (valid && !password.trim().is_empty())
        .then(|| (username.to_string(), password.trim().to_string()))
}

/// `owner/repo` on GitHub, or `off`. Anything else stops the server: a
/// mistyped repository would send people somewhere unexpected.
fn github_repository(value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let part = |p: &str| {
        !p.is_empty()
            && p.len() <= 100
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    match value.split_once('/') {
        Some((owner, repo)) if part(owner) && part(repo) => Ok(Some(value.to_string())),
        _ => Err(format!(
            "FEEDBACK_GITHUB_REPOSITORY must be owner/repo or off, not {value:?}"
        )),
    }
}

/// The environment as the server reads it: each value checked as it is read,
/// every problem recorded, all of them reported at once by `finish`.
type Lookup = Box<dyn Fn(&str) -> Option<String>>;

pub(crate) struct Env {
    lookup: Lookup,
    names: Box<dyn Fn() -> Vec<String>>,
    errors: std::cell::RefCell<Vec<String>>,
    /// Every name looked up: `.env.example` must list each one.
    read: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl Env {
    /// The process environment.
    pub(crate) fn process() -> Self {
        Self {
            lookup: Box::new(|key| std::env::var(key).ok()),
            names: Box::new(|| {
                std::env::vars_os()
                    .filter_map(|(k, _)| k.into_string().ok())
                    .collect()
            }),
            errors: std::cell::RefCell::new(Vec::new()),
            read: Default::default(),
        }
    }

    /// A fixed set of variables (tests).
    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let names: Vec<String> = map.keys().cloned().collect();
        Self {
            lookup: Box::new(move |key| map.get(key).cloned()),
            names: Box::new(move || names.clone()),
            errors: std::cell::RefCell::new(Vec::new()),
            read: Default::default(),
        }
    }

    pub(crate) fn error(&self, message: impl Into<String>) {
        self.errors.borrow_mut().push(message.into());
    }

    /// The value as set, even when blank.
    pub(crate) fn raw(&self, key: &str) -> Option<String> {
        self.read.borrow_mut().insert(key.to_owned());
        (self.lookup)(key)
    }

    /// The value, or `None` when unset or blank.
    pub(crate) fn set(&self, key: &str) -> Option<String> {
        self.raw(key).filter(|value| !value.trim().is_empty())
    }

    pub(crate) fn string(&self, key: &str, fallback: &str) -> String {
        self.set(key).unwrap_or_else(|| fallback.to_string())
    }

    /// `OPAQUE_SETUP_KEYS`, or the file `OPAQUE_SETUP_KEYS_FILE` names (a
    /// secret mounted as a file): exactly one of the two. Blank on an error.
    fn opaque_setup_keys(&self) -> String {
        match (
            self.set("OPAQUE_SETUP_KEYS"),
            self.set("OPAQUE_SETUP_KEYS_FILE"),
        ) {
            (Some(value), None) => value,
            (None, Some(path)) => match std::fs::read_to_string(path.trim()) {
                Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
                Ok(_) => {
                    self.error("OPAQUE_SETUP_KEYS_FILE names an empty file");
                    String::new()
                }
                Err(error) => {
                    self.error(format!("OPAQUE_SETUP_KEYS_FILE: {error}"));
                    String::new()
                }
            },
            (Some(_), Some(_)) => {
                self.error("set OPAQUE_SETUP_KEYS or OPAQUE_SETUP_KEYS_FILE, not both");
                String::new()
            }
            (None, None) => {
                self.error("OPAQUE_SETUP_KEYS (or OPAQUE_SETUP_KEYS_FILE) is required");
                String::new()
            }
        }
    }

    pub(crate) fn required(&self, key: &str) -> String {
        self.set(key).unwrap_or_else(|| {
            self.error(format!("{key} is required"));
            String::new()
        })
    }

    /// A whole number of zero or more.
    pub(crate) fn int(&self, key: &str, fallback: i64) -> i64 {
        match self.set(key) {
            None => fallback,
            Some(value) => match value.trim().parse::<i64>() {
                Ok(n) if n >= 0 => n,
                _ => {
                    self.error(format!(
                        "{key} must be a whole number of 0 or more, not {value:?}"
                    ));
                    fallback
                }
            },
        }
    }

    /// A whole number of one or more.
    pub(crate) fn positive(&self, key: &str, fallback: u64) -> u64 {
        match self.set(key) {
            None => fallback,
            Some(value) => match value.trim().parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => {
                    self.error(format!(
                        "{key} must be a whole number of 1 or more, not {value:?}"
                    ));
                    fallback
                }
            },
        }
    }

    pub(crate) fn bool(&self, key: &str, fallback: bool) -> bool {
        match self.set(key) {
            None => fallback,
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => true,
                "0" | "false" | "no" => false,
                _ => {
                    self.error(format!("{key} must be true or false, not {value:?}"));
                    fallback
                }
            },
        }
    }

    /// One of `choices` (compared without case), lowercased.
    pub(crate) fn choice(&self, key: &str, fallback: &str, choices: &[&str]) -> String {
        match self.set(key) {
            None => fallback.to_string(),
            Some(value) => {
                let value = value.trim().to_ascii_lowercase();
                if choices.contains(&value.as_str()) {
                    value
                } else {
                    self.error(format!(
                        "{key} must be one of {}, not {value:?}",
                        choices.join(", ")
                    ));
                    fallback.to_string()
                }
            }
        }
    }

    /// The set names starting with `prefix` that `known` does not list.
    pub(crate) fn unknown_with_prefix(
        &self,
        prefix: &str,
        known: &dyn Fn(&str) -> bool,
    ) -> Option<Vec<String>> {
        let names = (self.names)();
        let unknown: Vec<String> = names
            .into_iter()
            .filter(|name| name.starts_with(prefix) && !known(name))
            .collect();
        (!unknown.is_empty()).then_some(unknown)
    }

    /// Every problem found, or `Ok` when there was none.
    pub(crate) fn finish(&self) -> Result<(), Vec<String>> {
        let errors = self.errors.take();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_account_is_read_as_its_owner_meant() {
        let read = |v: &str| parse_admin_account(v);
        assert_eq!(
            read("admin:secret"),
            Some(("admin".into(), "secret".into()))
        );
        // A password with colons stays whole.
        assert_eq!(read("admin:pa:ss"), Some(("admin".into(), "pa:ss".into())));
        // The retired `email:username:password` form is refused, not misread.
        assert_eq!(read("a@b.c:admin:pa:ss"), None);
        assert_eq!(break_glass_username("a@b.c:admin:x"), "");
        // A username no account may have, or no password: refused.
        assert_eq!(read("Admin:secret"), None);
        assert_eq!(read("ad:secret"), None);
        assert_eq!(read("admin:"), None);
        assert_eq!(read("admin"), None);
        assert_eq!(break_glass_username("admin:x"), "admin");
    }
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
        assert_eq!(o.pass, "https://pass.example.org");
        assert_eq!(o.calendar, "https://calendar.example.org");
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
        assert_eq!(o.pass, "http://pass.localhost:5182");
        assert_eq!(o.calendar, "http://calendar.localhost:5183");
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

/// Who may send mail to addresses outside Kutup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutsideSending {
    Off,
    Admins,
    On,
}

impl OutsideSending {
    /// `off`, `admins` or `on`; anything else is off, so a typo never opens
    /// sending.
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "on" => OutsideSending::On,
            "admins" => OutsideSending::Admins,
            "off" => OutsideSending::Off,
            other => {
                tracing::warn!(
                    value = other,
                    "MAIL_OUTSIDE_SENDING is not off, admins or on; using off"
                );
                OutsideSending::Off
            }
        }
    }

    /// The value as stored and sent: `off`, `admins` or `on`.
    pub fn as_str(self) -> &'static str {
        match self {
            OutsideSending::Off => "off",
            OutsideSending::Admins => "admins",
            OutsideSending::On => "on",
        }
    }

    /// A stored or requested value, exactly `off`, `admins` or `on`.
    pub fn from_setting(value: &str) -> Option<Self> {
        match value {
            "off" => Some(OutsideSending::Off),
            "admins" => Some(OutsideSending::Admins),
            "on" => Some(OutsideSending::On),
            _ => None,
        }
    }

    pub fn allows(self, is_admin: bool) -> bool {
        match self {
            OutsideSending::On => true,
            OutsideSending::Admins => is_admin,
            OutsideSending::Off => false,
        }
    }
}

#[cfg(test)]
mod outside_sending_tests {
    use super::OutsideSending;

    #[test]
    fn the_stored_setting_is_exact() {
        for policy in [
            OutsideSending::Off,
            OutsideSending::Admins,
            OutsideSending::On,
        ] {
            assert_eq!(OutsideSending::from_setting(policy.as_str()), Some(policy));
        }
        assert_eq!(OutsideSending::from_setting("On"), None);
        assert_eq!(OutsideSending::from_setting("sometimes"), None);
    }

    #[test]
    fn outside_sending_parses_and_fails_closed() {
        assert_eq!(OutsideSending::parse("on"), OutsideSending::On);
        assert_eq!(OutsideSending::parse(" Admins "), OutsideSending::Admins);
        assert_eq!(OutsideSending::parse("off"), OutsideSending::Off);
        assert_eq!(OutsideSending::parse("yes"), OutsideSending::Off);
        assert!(OutsideSending::Admins.allows(true));
        assert!(!OutsideSending::Admins.allows(false));
        assert!(!OutsideSending::Off.allows(true));
        assert!(OutsideSending::On.allows(false));
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    const REQUIRED: &[(&str, &str)] = &[
        ("DATABASE_URL", "postgres://x"),
        ("JWT_SECRET", "0123456789abcdef0123456789abcdef"),
        (
            "OPAQUE_SETUP_KEYS",
            "1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        ("S3_ENDPOINT", "http://s3"),
        ("S3_ACCESS_KEY", "a"),
        ("S3_SECRET_KEY", "b"),
    ];

    fn errors(extra: &[(&str, &str)]) -> Vec<String> {
        let pairs: Vec<(&str, &str)> = REQUIRED.iter().chain(extra).copied().collect();
        let env = Env::from_pairs(&pairs);
        Config::from_env(&env);
        env.finish().err().unwrap_or_default()
    }

    #[test]
    fn a_valid_environment_has_no_errors() {
        assert_eq!(errors(&[]), Vec::<String>::new());
        assert_eq!(
            errors(&[("APP_ENV", "test"), ("RATE_LIMITS_RELAXED", "true")]),
            Vec::<String>::new()
        );
        // Test stacks only: not development (the default) either.
        assert!(errors(&[("RATE_LIMITS_RELAXED", "true")])
            .iter()
            .any(|e| e.starts_with("RATE_LIMITS_RELAXED")));
    }

    #[test]
    fn every_bad_value_is_reported_not_defaulted() {
        let found = errors(&[
            ("APP_ENV", "prod"),
            ("TRASH_RETENTION_DAYS", "thirty"),
            ("CHAT_GROUPS", "maybe"),
            ("MAIL_OUTSIDE_SENDING", "yes"),
            ("MAIL_DEFAULT_DELAY_SEND_SECONDS", "7"),
            ("RATE_LIMIT_LOGIN_PER_MIN", "0"),
            ("RATE_LIMIT_LOGN_PER_MIN", "50"),
            ("ADMIN_ACCOUNT", "a@b.c:admin:pw"),
        ]);
        for name in [
            "APP_ENV",
            "TRASH_RETENTION_DAYS",
            "CHAT_GROUPS",
            "MAIL_OUTSIDE_SENDING",
            "MAIL_DEFAULT_DELAY_SEND_SECONDS",
            "RATE_LIMIT_LOGIN_PER_MIN",
            "RATE_LIMIT_LOGN_PER_MIN",
            "ADMIN_ACCOUNT",
        ] {
            assert!(
                found.iter().any(|e| e.starts_with(name)),
                "{name} not reported: {found:?}"
            );
        }
    }

    #[test]
    fn missing_required_values_are_all_reported() {
        let env = Env::from_pairs(&[]);
        Config::from_env(&env);
        let found = env.finish().unwrap_err();
        for (name, _) in REQUIRED {
            assert!(
                found.iter().any(|e| e.starts_with(name)),
                "{name}: {found:?}"
            );
        }
    }

    #[test]
    fn test_switches_are_refused_in_production() {
        let found = errors(&[
            ("APP_ENV", "production"),
            ("KUTUP_BASE_DOMAIN", "example.org"),
            ("RATE_LIMITS_RELAXED", "true"),
            ("FEDERATION_TEST_ALLOW_PRIVATE", "true"),
            ("ALLOWED_ORIGINS", "*"),
        ]);
        for name in [
            "RATE_LIMITS_RELAXED",
            "FEDERATION_TEST_ALLOW_PRIVATE",
            "ALLOWED_ORIGINS",
        ] {
            assert!(
                found.iter().any(|e| e.starts_with(name)),
                "{name}: {found:?}"
            );
        }
        // The private-peer switch is for APP_ENV=test only.
        assert!(errors(&[("FEDERATION_TEST_ALLOW_PRIVATE", "true")])
            .iter()
            .any(|e| e.starts_with("FEDERATION_TEST_ALLOW_PRIVATE")));
    }

    #[test]
    fn opaque_setup_keys_from_a_file_or_the_variable_not_both() {
        let dir = std::env::temp_dir().join(format!("kutup-opaque-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("keys");
        std::fs::write(&file, "1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n").unwrap();
        let path = file.to_str().unwrap();
        let without: Vec<(&str, &str)> = REQUIRED
            .iter()
            .filter(|(k, _)| *k != "OPAQUE_SETUP_KEYS")
            .copied()
            .collect();
        let env =
            Env::from_pairs(&[without.as_slice(), &[("OPAQUE_SETUP_KEYS_FILE", path)]].concat());
        assert_eq!(
            env.opaque_setup_keys(),
            "1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert!(env.errors.borrow().is_empty());
        let both = Env::from_pairs(&[REQUIRED, &[("OPAQUE_SETUP_KEYS_FILE", path)]].concat());
        assert_eq!(both.opaque_setup_keys(), "");
        assert!(both.errors.borrow()[0].contains("not both"));
        let neither = Env::from_pairs(&without);
        assert_eq!(neither.opaque_setup_keys(), "");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod feedback_repository_tests {
    use super::github_repository;

    #[test]
    fn owner_slash_repo_or_off() {
        assert_eq!(
            github_repository("kutupbt/kutup"),
            Ok(Some("kutupbt/kutup".into()))
        );
        assert_eq!(
            github_repository(" my-org/my.repo_2 "),
            Ok(Some("my-org/my.repo_2".into()))
        );
        assert_eq!(github_repository("off"), Ok(None));
        assert_eq!(github_repository("OFF"), Ok(None));
    }

    #[test]
    fn a_url_or_a_bare_name_is_refused() {
        for value in ["https://github.com/kutupbt/kutup", "kutup"] {
            assert!(github_repository(value)
                .unwrap_err()
                .contains("FEEDBACK_GITHUB_REPOSITORY"));
        }
    }
}

/// `.env.example` is the one list of settings (docs/self-hosting.md): every
/// name the server reads and every name a compose file or script reads, each
/// exactly once, nothing else; and each setting the server reads reaches the
/// backend container from `.env`, unless Compose sets it itself.
#[cfg(test)]
mod env_example {
    use super::*;
    use std::collections::BTreeSet;

    const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

    /// Read by a compose file or a script, not by the server: the name and a
    /// file that reads it.
    const OUTSIDE_THE_SERVER: &[(&str, &str)] = &[
        ("POSTGRES_PASSWORD", "docker-compose.yml"),
        ("POSTGRES_DB", "docker-compose.yml"),
        ("POSTGRES_USER", "docker-compose.yml"),
        ("KUTUP_HTTP_PORT", "docker-compose.yml"),
        ("KUTUP_HTTPS_PORT", "docker-compose.yml"),
        ("CHAT_TURN_REALM", "docker-compose.yml"),
        ("CHAT_TURN_DENIED_PEER_IPS", "docker-compose.yml"),
        ("CHAT_SFU_TURN_DOMAIN", "docker-compose.yml"),
        ("KUTUP_ACME_EMAIL", "docker-compose.acme.yml"),
        ("KUTUP_ACME_DOMAINS", "docker-compose.acme.yml"),
        ("KUTUP_ACME_EXTRA_DOMAINS", "docker-compose.acme.yml"),
        ("KUTUP_ACME_STAGING", "docker-compose.acme.yml"),
        ("STALWART_ADMIN_SECRET", "docker-compose.mail.yml"),
        ("MAIL_SMTP_PORT", "docker-compose.mail.yml"),
        ("KUTUP_SERVER_IMAGE", "docker-compose.images.yml"),
        ("KUTUP_WEB_IMAGE", "docker-compose.images.yml"),
        (
            "KUTUP_STALWART_SETUP_IMAGE",
            "docker-compose.mail-images.yml",
        ),
        ("KUTUP_BACKUP_PASSPHRASE", "scripts/backup-postgres.sh"),
        ("KUTUP_BACKUP_KEEP_DAYS", "scripts/backup-postgres.sh"),
    ];

    /// Read by the server, but not from `.env` under Compose: it builds or
    /// fixes them itself (DATABASE_URL from POSTGRES_*, the cache directory,
    /// the port and mail's addresses inside its network, OPAQUE_SETUP_KEYS in
    /// place of the file) or only test stacks set them.
    const NOT_FROM_ENV_FILE: &[&str] = &[
        "DATABASE_URL",
        "MAPS_CACHE_DIR",
        "PORT",
        "MAIL_LMTP_BIND",
        "MAIL_SUBMISSION_ADDR",
        "OPAQUE_SETUP_KEYS_FILE",
        "MAIL_TEST_KEY_ORIGIN",
    ];

    /// The compose files a self-hoster combines (docs/self-hosting.md).
    const COMPOSE_FILES: &[&str] = &[
        "docker-compose.yml",
        "docker-compose.mail.yml",
        "docker-compose.acme.yml",
        "docker-compose.external-s3.yml",
        "docker-compose.images.yml",
        "docker-compose.mail-images.yml",
    ];

    fn file(path: &str) -> String {
        std::fs::read_to_string(format!("{ROOT}/{path}"))
            .unwrap_or_else(|error| panic!("{path}: {error}"))
    }

    /// Names read straight from the process environment, outside `Env`
    /// (`PORT`, the OpenTelemetry settings): the quoted name in
    /// `env::var("…")` or `nonempty_env("…")`, outside test modules.
    fn read_directly() -> BTreeSet<String> {
        fn walk(dir: &std::path::Path, found: &mut BTreeSet<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, found);
                    continue;
                }
                // Rust files only; a `*tests.rs` file is a test module.
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if !name.ends_with(".rs") || name.ends_with("tests.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let code = text.split("#[cfg(test)]").next().unwrap_or_default();
                for call in ["env::var(\"", "nonempty_env(\""] {
                    for rest in code.split(call).skip(1) {
                        let name: String = rest
                            .chars()
                            .take_while(|c| {
                                c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_'
                            })
                            .collect();
                        if !name.is_empty() {
                            found.insert(name);
                        }
                    }
                }
            }
        }
        let mut found = BTreeSet::new();
        walk(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
            &mut found,
        );
        found
    }

    /// Every name the server reads: all of `Config::from_env` (each read is
    /// unconditional), the rate limits it checks, and the direct reads.
    fn server_reads() -> BTreeSet<String> {
        let env = Env::from_pairs(&[]);
        Config::from_env(&env);
        let mut names = env.read.take();
        names.extend(read_directly());
        names
    }

    /// Each setting `.env.example` lists, as `NAME=` or commented `# NAME=`.
    fn listed() -> Vec<String> {
        file(".env.example")
            .lines()
            .filter_map(|line| {
                let line = line.strip_prefix("# ").unwrap_or(line);
                let (name, _) = line.split_once('=')?;
                (!name.is_empty()
                    && name.starts_with(|c: char| c.is_ascii_uppercase())
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                .then(|| name.to_owned())
            })
            .collect()
    }

    #[test]
    fn env_example_lists_every_setting_once() {
        let listed = listed();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let twice: Vec<&String> = listed
            .iter()
            .filter(|name| !seen.insert((*name).clone()))
            .collect();
        assert!(
            twice.is_empty(),
            ".env.example lists these twice: {twice:?}"
        );

        for (name, path) in OUTSIDE_THE_SERVER {
            assert!(file(path).contains(name), "{path} does not read {name}");
        }
        let server = server_reads();
        let mut expected = server.clone();
        expected.extend(OUTSIDE_THE_SERVER.iter().map(|(name, _)| name.to_string()));
        let missing: Vec<&String> = expected.difference(&seen).collect();
        assert!(
            missing.is_empty(),
            "read but not in .env.example: {missing:?}"
        );
        let unread: Vec<&String> = seen.difference(&expected).collect();
        assert!(
            unread.is_empty(),
            "in .env.example but read by nothing (or add it to OUTSIDE_THE_SERVER): {unread:?}"
        );
    }

    #[test]
    fn every_setting_reaches_the_backend_from_the_env_file() {
        let compose: String = COMPOSE_FILES.iter().map(|path| file(path)).collect();
        let unwired: Vec<String> = server_reads()
            .into_iter()
            .filter(|name| !NOT_FROM_ENV_FILE.contains(&name.as_str()))
            .filter(|name| !compose.contains(&format!("{name}: ${{{name}")))
            .collect();
        assert!(
            unwired.is_empty(),
            "the server reads these, but no compose file passes them from .env: {unwired:?}"
        );
    }
}
