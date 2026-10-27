//! In-memory rate limiting + brute-force tracking.
//!
//! Three layers of protection, all process-local state:
//!  - **Per-IP sliding-window limiters** — login, login preflight, register, recovery,
//!    federation user-lookup, and the admin API. Every limit is an entry in
//!    [`registry`]; the environment may set its first value (read and checked
//!    at boot), and `RATE_LIMITS_RELAXED` raises them on test stacks.
//!  - **Sign-in lockout and ceiling** — N wrong secrets for one account from one client
//!    IP lock that pair out (defaults 5 / 15 min; `LOGIN_LOCKOUT_THRESHOLD`,
//!    `LOGIN_LOCKOUT_MINUTES`), and wrong secrets from clients the account does not
//!    know are capped per account (`LOGIN_ACCOUNT_CEILING`); see `auth_check`.
//!  - **Per-pre-auth-token TOTP tracker** — blocks a token for 15 min after 5 failures.
//!
//! `spawn_cleanup` runs the periodic pruning for all of the above.

use kutup_crypto::primitives::{hash, Suite};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

mod registry;

pub use registry::{Limit, Per, Section, Spec, Unit, SPECS};

/// Every limit's current value, indexed by [`Limit`]: what each check reads,
/// so a check stays a lock and a vector (docs/plans/admin-rate-limits.md §3).
static VALUES: LazyLock<Vec<AtomicU64>> = LazyLock::new(|| {
    SPECS
        .iter()
        .map(|spec| AtomicU64::new(spec.default))
        .collect()
});

/// Accounts' own values of the limits that take them
/// ([`Spec::overridable`]), by account id: read by the limiters keyed by
/// that id.
static OVERRIDES: LazyLock<RwLock<Overrides>> = LazyLock::new(Default::default);

/// Accounts' own values, by account id.
type Overrides = HashMap<String, Vec<(Limit, u64)>>;

/// One account's own value of `limit`, if administrators set one.
pub fn account_override(limit: Limit, account: &str) -> Option<u64> {
    OVERRIDES
        .read()
        .unwrap()
        .get(account)?
        .iter()
        .find(|(each, _)| *each == limit)
        .map(|(_, value)| *value)
}

/// Every account's own values, as stored: `(account id, key, value)`. A row
/// for a limit that takes none, or outside its bounds, is ignored.
pub(crate) fn apply_overrides(rows: Vec<(String, String, i64)>) {
    let mut overrides = Overrides::new();
    for (account, key, value) in rows {
        let Some(spec) = SPECS.iter().find(|spec| spec.key == key) else {
            continue;
        };
        match u64::try_from(value) {
            Ok(value) if spec.overridable() && (1..=ceiling(spec)).contains(&value) => {
                overrides
                    .entry(account)
                    .or_default()
                    .push((spec.limit, value));
            }
            _ => tracing::warn!(
                limit = spec.key,
                "an account's rate limit {value} is ignored"
            ),
        }
    }
    *OVERRIDES.write().unwrap() = overrides;
}

/// Every account's own values, as stored (`user_setting_overrides`, keyed
/// `rate_limit.<key>`), by limit key.
pub async fn stored_overrides(
    pool: &sqlx::PgPool,
) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT user_id::text, substr(key, length($1) + 1), value FROM user_setting_overrides
         WHERE starts_with(key, $1)",
    )
    .bind(SETTING_PREFIX)
    .fetch_all(pool)
    .await
}

/// The values [`registry::ENV_SEEDS`] names, as the environment set them.
static SEEDS: OnceLock<HashMap<&'static str, u64>> = OnceLock::new();

/// Every limit's first value (what it is while administrators have set
/// none) and where it came from, indexed by [`Limit`].
static FIRST: OnceLock<Vec<(u64, FirstFrom)>> = OnceLock::new();

/// Where a limit's first value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum FirstFrom {
    Default,
    /// Its environment variable.
    Environment,
    /// A test stack's raised default (`RATE_LIMITS_RELAXED`).
    TestStack,
}

/// The `site_settings` key prefix of the values administrators set:
/// `rate_limit.<key>`.
pub const SETTING_PREFIX: &str = "rate_limit.";

/// A limit's first value and where it came from.
pub fn first(limit: Limit) -> (u64, FirstFrom) {
    FIRST
        .get()
        .map(|first| first[limit as usize])
        .unwrap_or((limit.spec().default, FirstFrom::Default))
}

/// The values administrators set, by limit (stored as `rate_limit.<key>`),
/// over the first values: what every check reads from now on. A stored
/// value outside the limit's bounds (a bound since lowered) is ignored, and
/// logged.
pub(crate) fn apply(stored: &HashMap<String, String>) {
    for spec in SPECS {
        let value = effective(
            spec,
            stored.get(spec.key),
            first(spec.limit).0,
            ceiling(spec),
        );
        VALUES[spec.limit as usize].store(value, Ordering::Relaxed);
    }
}

/// One limit's value: the stored one within its bounds, else its first.
fn effective(spec: &Spec, stored: Option<&String>, first: u64, ceiling: u64) -> u64 {
    let Some(text) = stored else { return first };
    match text.parse::<u64>() {
        Ok(value) if (1..=ceiling).contains(&value) => value,
        _ => {
            tracing::warn!(
                limit = spec.key,
                "stored rate limit {text:?} is out of bounds; using its first value"
            );
            first
        }
    }
}

/// The values administrators set, by limit key.
pub async fn stored(pool: &sqlx::PgPool) -> Result<HashMap<String, String>, sqlx::Error> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM site_settings WHERE starts_with(key, $1)")
            .bind(SETTING_PREFIX)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, value)| Some((key.strip_prefix(SETTING_PREFIX)?.to_owned(), value)))
        .collect())
}

/// Held across a reload's reads and its apply, so reloads apply in the
/// order they read: a periodic reload that read before a save can't land
/// after the saving backend's own reload and briefly undo it.
static RELOADING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reads the values administrators set (the site's and accounts' own) into
/// the snapshot; returns the site's, as stored.
pub async fn reload(pool: &sqlx::PgPool) -> Result<HashMap<String, String>, sqlx::Error> {
    let _order = RELOADING.lock().await;
    let site = stored(pool).await?;
    let accounts = stored_overrides(pool).await?;
    apply(&site);
    apply_overrides(accounts);
    Ok(site)
}

/// How often every backend rereads the values administrators set, so all
/// agree within this (the one that saves a change applies it at once).
const RELOAD_EVERY: Duration = Duration::from_secs(30);

/// Rereads the values administrators set every [`RELOAD_EVERY`].
pub fn spawn_reload(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RELOAD_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(error) = reload(&pool).await {
                tracing::warn!("rate limits not reloaded: {error}");
            }
        }
    });
}

/// Whether this is a test stack (`RATE_LIMITS_RELAXED`, test only): some
/// limits may go higher there ([`Spec::ceiling`]).
static TEST_STACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The highest value `spec` takes on this server.
pub fn ceiling(spec: &Spec) -> u64 {
    spec.ceiling(TEST_STACK.load(Ordering::Relaxed))
}

/// A limit's value now.
pub fn value(limit: Limit) -> u64 {
    VALUES[limit as usize].load(Ordering::Relaxed)
}

/// A limit's value now for one account: its own where administrators set
/// one ([`Spec::overridable`]), else the limit's. For the limits counted per
/// account outside a [`RateLimiter`] (database counters, byte budgets).
pub fn value_for(limit: Limit, account: &str) -> u64 {
    if limit.spec().overridable() {
        if let Some(own) = account_override(limit, account) {
            return own;
        }
    }
    value(limit)
}

/// A limit counted in the database (`chat_anonymous_rate_counters` and the
/// like): `(its value, its window in seconds)`.
pub fn budget(limit: Limit) -> (i64, i64) {
    let window = match limit.spec().unit {
        Unit::Events(window) => window,
        unit => unreachable!("{} is {unit:?}, not a budget", limit.spec().key),
    };
    (
        i64::try_from(value(limit)).unwrap_or(i64::MAX),
        window.as_secs() as i64,
    )
}

/// Reads every limit through the boot-time configuration pass (`Env`
/// records a bad value), before any limiter is first used: its environment
/// variable, else its default (raised on a test stack, `relaxed`). A
/// `RATE_LIMIT_*` name this server does not have stops it (a typo would
/// silently keep the default), as does a value outside the limit's bounds.
pub(crate) fn configure(env: &crate::config::Env, relaxed: bool) {
    let known = |name: &str| {
        SPECS.iter().any(|spec| spec.env == Some(name))
            || registry::ENV_SEEDS.iter().any(|(seed, _)| *seed == name)
    };
    if let Some(unknown) = env.unknown_with_prefix("RATE_LIMIT_", &known) {
        for name in unknown {
            env.error(format!("{name} is not a rate limit this server has"));
        }
    }
    TEST_STACK.store(relaxed, Ordering::Relaxed);
    let first = first_values(env, relaxed);
    for (spec, (value, _)) in SPECS.iter().zip(&first) {
        VALUES[spec.limit as usize].store(*value, Ordering::Relaxed);
    }
    let _ = FIRST.set(first);
    let seeds = registry::ENV_SEEDS
        .iter()
        .map(|&(name, default)| (name, env.positive(name, default)))
        .collect();
    let _ = SEEDS.set(seeds);
}

/// Every limit's first value: its environment variable, else its default
/// (raised on a test stack).
fn first_values(env: &crate::config::Env, relaxed: bool) -> Vec<(u64, FirstFrom)> {
    let mut first = Vec::with_capacity(SPECS.len());
    for spec in SPECS {
        let ceiling = spec.ceiling(relaxed);
        let (default, from) = if relaxed && spec.relaxed() {
            (registry::RELAXED, FirstFrom::TestStack)
        } else {
            (spec.default, FirstFrom::Default)
        };
        let configured = match spec.env.filter(|name| env.set(name).is_some()) {
            Some(name) => {
                let configured = env.positive(name, default);
                if configured > ceiling {
                    env.error(format!(
                        "{name} may be at most {ceiling} (100 times its default), not {configured}"
                    ));
                }
                (configured.min(ceiling), FirstFrom::Environment)
            }
            None => (default, from),
        };
        first.push(configured);
    }
    first
}

/// An [`registry::ENV_SEEDS`] value as configured at boot; its default where
/// nothing configured it (unit tests).
fn seed(name: &str) -> u64 {
    SEEDS
        .get()
        .and_then(|seeds| seeds.get(name).copied())
        .or_else(|| {
            registry::ENV_SEEDS
                .iter()
                .find(|(seed, _)| *seed == name)
                .map(|(_, default)| *default)
        })
        .expect("a seed the registry lists")
}

/// Where a limiter's limit comes from.
enum Bound {
    /// The registry's current value.
    Registered(Limit),
    /// Given with each check (`allow_up_to`): a limit kept in an
    /// administrators' setting of its own.
    PerCheck,
    #[cfg(test)]
    Fixed(u64),
    /// A value the test changes, apart from the shared snapshot that other
    /// tests' configuration writes.
    #[cfg(test)]
    Cell(&'static AtomicU64),
}

impl Bound {
    fn get(&self) -> u64 {
        match self {
            Bound::Registered(limit) => value(*limit),
            Bound::PerCheck => 0,
            #[cfg(test)]
            Bound::Fixed(limit) => *limit,
            #[cfg(test)]
            Bound::Cell(cell) => cell.load(Ordering::Relaxed),
        }
    }
}

/// How long a limiter's window is.
enum Span {
    Fixed(Duration),
    /// A limit's value, in minutes.
    Minutes(Limit),
}

impl Span {
    fn of(limit: Limit) -> Self {
        match limit.spec().unit {
            Unit::Events(window) => Span::Fixed(window),
            Unit::EventsPerLockout => Span::Minutes(Limit::LoginLockoutMinutes),
            unit => unreachable!("{} is {unit:?}, not counted in a window", limit.spec().key),
        }
    }

    fn get(&self) -> Duration {
        match self {
            Span::Fixed(window) => *window,
            Span::Minutes(limit) => Duration::from_secs(value(*limit).saturating_mul(60)),
        }
    }
}

/// Sliding-window limiter — mirrors `rateLimiter`.
pub struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    limit: Bound,
    window: Span,
}

impl RateLimiter {
    fn with(limit: Bound, window: Span) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            limit,
            window,
        }
    }

    /// A limiter for a registry entry: its value is read at each check, so
    /// a changed limit applies at the next one.
    pub(crate) fn registered(limit: Limit) -> Self {
        Self::with(Bound::Registered(limit), Span::of(limit))
    }

    /// A limiter whose limit comes with each check (`allow_up_to`,
    /// `has_room_up_to`): the plain checks refuse everything.
    pub(crate) fn per_check(window: Duration) -> Self {
        Self::with(Bound::PerCheck, Span::Fixed(window))
    }

    #[cfg(test)]
    pub(crate) fn new(limit: usize, window: Duration) -> Self {
        Self::with(Bound::Fixed(limit as u64), Span::Fixed(window))
    }

    /// The limit for `key`: an account's own value where the limit takes
    /// one and `key` is that account's id, else the limit's.
    fn limit(&self, key: &str) -> usize {
        let limit = match self.limit {
            Bound::Registered(limit) if limit.spec().overridable() => {
                account_override(limit, key).unwrap_or_else(|| value(limit))
            }
            ref bound => bound.get(),
        };
        usize::try_from(limit).unwrap_or(usize::MAX)
    }

    /// Records an attempt for `key`, returning false when over the limit — mirrors `Allow`.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_up_to(key, self.limit(key))
    }

    /// [`allow`](Self::allow) under `limit` instead of the limiter's own: for
    /// a limit administrators change while the server runs.
    pub fn allow_up_to(&self, key: &str, limit: usize) -> bool {
        let now = Instant::now();
        let window = self.window.get();
        let mut map = self.requests.lock().unwrap();
        let times = map.entry(key.to_string()).or_default();
        times.retain(|t| now.duration_since(*t) < window);
        if times.len() >= limit {
            return false;
        }
        times.push(now);
        true
    }

    /// Whether `key` is under its limit now, without recording an attempt
    /// (a budget charged only when something fails).
    pub fn has_room(&self, key: &str) -> bool {
        self.has_room_up_to(key, self.limit(key))
    }

    /// [`has_room`](Self::has_room) under `limit` instead of the limiter's
    /// own.
    pub fn has_room_up_to(&self, key: &str, limit: usize) -> bool {
        let now = Instant::now();
        let window = self.window.get();
        let mut map = self.requests.lock().unwrap();
        match map.get_mut(key) {
            Some(times) => {
                times.retain(|t| now.duration_since(*t) < window);
                times.len() < limit
            }
            None => true,
        }
    }

    /// Gives back the newest event of `key` (an attempt that turned out
    /// right).
    pub fn pop(&self, key: &str) {
        let mut map = self.requests.lock().unwrap();
        if let Some(times) = map.get_mut(key) {
            times.pop();
        }
    }

    /// Drops empty/expired entries — mirrors the Go `cleanup` goroutine body.
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();
        let window = self.window.get();
        let mut map = self.requests.lock().unwrap();
        map.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < window);
            !times.is_empty()
        });
    }
}

/// Recovery: 5 attempts / hour / IP (`RATE_LIMIT_RECOVERY_PER_HOUR`).
pub static RECOVERY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::Recovery));
/// Federation username lookup: 60 / minute / IP (`RATE_LIMIT_FED_USERS_PER_MIN`).
pub static FED_USERS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::FedUsers));
/// Forwarded multi-recipient sends that don't authenticate: 60 / minute /
/// IP (`RATE_LIMIT_FED_MULTI_FAILURES_PER_MIN`). Each request is charged
/// before it is read and given back once it authenticates, so a peer's
/// group messages are bounded by its origin budgets (administrators'
/// settings) alone, and a stranger's (bodies buffered, origins discovered)
/// by this.
pub static FED_MULTI_IP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::FedMultiFailures));
/// Login (+ the 2FA step): 10 / minute / IP (`RATE_LIMIT_LOGIN_PER_MIN`).
pub static LOGIN: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::registered(Limit::Login));
/// Session hand-off to an app: 120 / minute / IP (`RATE_LIMIT_FORK_PER_MIN`).
/// Every app a person opens redeems one fork, so a signed-in household
/// spends several a minute; a fork is redeemed with a one-time random
/// selector, not a credential, so this is a flood wall rather than a
/// guessing budget and must not share the login allowance.
pub static FORK: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::registered(Limit::Fork));
/// Opening and joining a call through a link, which need no account: 60 /
/// minute / IP (`RATE_LIMIT_CALL_LINK_PER_MIN`).
pub static CALL_LINK: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::CallLinks));
/// Waiting to be let into a meeting, and watching who waits: each side asks
/// every few seconds, and several people may share an address. 600 / minute
/// / IP (`RATE_LIMIT_CALL_LINK_POLL_PER_MIN`).
pub static CALL_LINK_POLL: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::CallLinkPolls));
/// Looking a user up by email: 30 / minute / IP (`RATE_LIMIT_USER_LOOKUP_PER_MIN`).
/// Sharing needs a handful; a higher rate is someone enumerating accounts.
pub static USER_LOOKUP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::UserLookup));
/// Register: 10 / hour / IP (`RATE_LIMIT_REGISTER_PER_HOUR`). Registration is rare
/// per-human; this mostly stops scripted account spam on open-registration servers.
pub static REGISTER: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::Register));
/// Checking a referral code before signing up: 30 / hour / IP, valid or not
/// (`RATE_LIMIT_REGISTRATION_CODE_CHECK_PER_HOUR`).
pub static REGISTRATION_CODE_CHECK: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::RegistrationCodeChecks));
/// Referral codes that admitted no one, from checks and sign-ups together:
/// 20 / hour / IP (`RATE_LIMIT_REGISTRATION_CODE_FAILURES_PER_HOUR`), so a
/// code cannot be guessed (100 bits would hold anyway).
pub static REGISTRATION_CODE_FAILURES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::RegistrationCodeFailures));
/// Reports on public links: 20 / hour / IP (`RATE_LIMIT_REPORT_PER_HOUR`). Anyone
/// may report, without an account; a person reports a few, a script many.
pub static REPORT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::Reports));
/// Feedback: 10 / hour / account (`RATE_LIMIT_FEEDBACK_PER_HOUR`). A person
/// sends a few; more is someone filling the administrators' inbox.
pub static FEEDBACK: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::Feedback));
/// Admin API: 120 / minute / IP (`RATE_LIMIT_ADMIN_PER_MIN`). The dashboard fires a
/// handful of requests per view; 120/min is generous for a human and a wall for a script.
pub static ADMIN: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::registered(Limit::Admin));
/// The groups relay: 240 requests / minute / signed-in account
/// (`RATE_LIMIT_CHAT_GROUP_RELAY_PER_MIN`). The relay can't see what it
/// passes on, so this is the wall it keeps for its own users.
pub static CHAT_GROUP_RELAY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupRelay));
/// The groups gateway: 6000 requests / minute / relay server
/// (`RATE_LIMIT_CHAT_GROUP_GATEWAY_RELAY_PER_MIN`): all of a peer's users
/// together.
pub static CHAT_GROUP_GATEWAY_RELAY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupGatewayRelay));
/// The groups gateway: 240 requests / minute / member pseudonym
/// (`RATE_LIMIT_CHAT_GROUP_PSEUDONYM_PER_MIN`).
pub static CHAT_GROUP_PSEUDONYM: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupPseudonym));
/// Group changes: 30 / minute / pseudonym
/// (`RATE_LIMIT_CHAT_GROUP_CHANGES_PSEUDONYM_PER_MIN`).
pub static CHAT_GROUP_CHANGES_PSEUDONYM: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupChangesPseudonym));
/// Group changes: 60 / minute / group
/// (`RATE_LIMIT_CHAT_GROUP_CHANGES_GROUP_PER_MIN`), so many members can't
/// flood one log.
pub static CHAT_GROUP_CHANGES_GROUP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupChangesGroup));
/// Link requests (join info): 30 / minute / group
/// (`RATE_LIMIT_CHAT_GROUP_LINK_PER_MIN`), so a link holder can't flood one.
pub static CHAT_GROUP_LINK: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupLink));
/// Joins from a link and requests to join that passed their link's proof,
/// per minute per relay server and group, as administrators set it
/// (`site_settings::chat_group_link_joins`, 120 at first).
pub static CHAT_GROUP_LINK_JOINS_RELAY_GROUP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::per_check(Duration::from_secs(60)));
/// The same, per minute per relay server across all groups (1200 at first).
pub static CHAT_GROUP_LINK_JOINS_RELAY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::per_check(Duration::from_secs(60)));

/// The link-join budgets' first values, before administrators set them,
/// `(per relay and group, per relay)`
/// (`RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_GROUP_PER_MIN`,
/// `RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_PER_MIN`), within the settings'
/// own bounds.
pub fn chat_group_link_joins_defaults() -> (i64, i64) {
    let read = |name| {
        i64::try_from(seed(name))
            .unwrap_or(i64::MAX)
            .clamp(1, crate::site_settings::MAX_LINK_JOINS_PER_MIN)
    };
    (
        read("RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_GROUP_PER_MIN"),
        read("RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_PER_MIN"),
    )
}
/// Failed group requests: 600 / minute / relay server
/// (`RATE_LIMIT_CHAT_GROUP_FAILURES_RELAY_PER_MIN`): charged only when a
/// request fails (unknown group, stranger, refused change), so junk from one
/// server is throttled without spending any group's budget.
pub static CHAT_GROUP_FAILURES_RELAY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupFailuresRelay));
/// A custom domain's "Refresh status": 30 an hour per account
/// (docs/plans/mail-custom-domains.md §2), each an uncached set of lookups.
pub static MAIL_DOMAIN_CHECKS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::MailDomainChecks));
/// New groups: 600 / hour / relay server
/// (`RATE_LIMIT_CHAT_GROUP_CREATES_RELAY_PER_HOUR`); `CHAT_GROUP_MAX_GROUPS`
/// caps the total.
pub static CHAT_GROUP_CREATES_RELAY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::GroupCreatesRelay));
/// Chat prekey-bundle fetch: 30 / minute / authenticated account
/// (`RATE_LIMIT_CHAT_KEYS_PER_MIN`). Bundle fetches consume one-time prekeys, so
/// this is the primary anti-drain budget regardless of source IP.
pub static CHAT_KEYS_ACCOUNT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatKeysAccount));

/// Link tokens asked for (docs/plans/account-identity-key.md).
pub static CHAT_LINK_TOKENS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatLinkTokens));
/// Provisioning sockets opened, per address: a device waiting to be linked
/// has no credential yet.
pub static CHAT_PROVISIONING_SOCKETS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatProvisioningSockets));
/// Provisioning messages relayed, per account.
pub static CHAT_PROVISIONING_RELAYS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatProvisioningRelays));
/// Identity distributions, per account.
pub static CHAT_IDENTITY_DISTRIBUTIONS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatIdentityDistributions));

/// Coarse 120 / minute / IP outer wall for chat bundle fetches. This is
/// deliberately looser than the account budget so unrelated mobile users behind
/// one CGNAT address do not consume each other's primary allowance.
pub static CHAT_KEYS_IP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatKeysAddress));

/// Anonymous sealed-delivery outer wall: 60 attempts/minute/IP. Durable
/// capability, recipient, and origin counters remain the authoritative layer.
pub static CHAT_ANONYMOUS_IP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::ChatAnonymousAddress));

// --- per-account login lockout ---

/// Wrong-secret tracker for the sign-in check (`auth_check`), keyed by a hash
/// of what the caller locks (an account or name with a client). Each attempt
/// takes its slot before the check (`reserve`), so parallel attempts get no
/// more than the threshold; a right secret clears it.
pub struct LoginLockout {
    state: Mutex<LockoutState>,
    threshold: Bound,
    ttl: Span,
}

struct LockoutState {
    /// Attempts counted, and when the last one came.
    failures: HashMap<String, (u32, Instant)>,
    locked_at: HashMap<String, Instant>,
}

impl LoginLockout {
    fn with(threshold: Bound, ttl: Span) -> Self {
        Self {
            state: Mutex::new(LockoutState {
                failures: HashMap::new(),
                locked_at: HashMap::new(),
            }),
            threshold,
            ttl,
        }
    }

    #[cfg(test)]
    fn new(threshold: u32, ttl: Duration) -> Self {
        Self::with(Bound::Fixed(threshold.into()), Span::Fixed(ttl))
    }

    fn key(subject: &str) -> String {
        hash_token(&subject.to_lowercase())
    }

    fn locked(&self, st: &mut LockoutState, key: &str) -> bool {
        if let Some(at) = st.locked_at.get(key).copied() {
            if at.elapsed() < self.ttl.get() {
                return true;
            }
            st.locked_at.remove(key);
            st.failures.remove(key);
        }
        false
    }

    /// Whether `subject` is locked out now.
    #[cfg(test)]
    fn is_locked(&self, subject: &str) -> bool {
        let key = Self::key(subject);
        let mut st = self.state.lock().unwrap();
        self.locked(&mut st, &key)
    }

    /// Takes a slot for one attempt: `false` while locked. The attempt counts
    /// as a miss until [`Self::succeeded`] says otherwise; the threshold-th
    /// one locks the subject for the cooldown.
    pub fn reserve(&self, subject: &str) -> bool {
        let key = Self::key(subject);
        let mut st = self.state.lock().unwrap();
        if self.locked(&mut st, &key) {
            return false;
        }
        let now = Instant::now();
        let entry = st.failures.entry(key.clone()).or_insert((0, now));
        if entry.1.elapsed() >= self.ttl.get() {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.1 = now;
        if u64::from(entry.0) >= self.threshold.get() {
            st.locked_at.insert(key, now);
        }
        true
    }

    /// A right secret: the subject's misses (and any lock) are cleared.
    pub fn succeeded(&self, subject: &str) {
        let key = Self::key(subject);
        let mut st = self.state.lock().unwrap();
        st.failures.remove(&key);
        st.locked_at.remove(&key);
    }

    fn cleanup(&self) {
        let mut st = self.state.lock().unwrap();
        let ttl = self.ttl.get();
        st.locked_at.retain(|_, at| at.elapsed() < ttl);
        // Counters expire one by one with the window: spraying many
        // subjects never resets anyone else's.
        st.failures.retain(|_, (_, last)| last.elapsed() < ttl);
    }
}

/// 5 failures → 15 min lockout (`LOGIN_LOCKOUT_THRESHOLD`, `LOGIN_LOCKOUT_MINUTES`).
pub static LOGIN_LOCKOUT: LazyLock<LoginLockout> = LazyLock::new(|| {
    LoginLockout::with(
        Bound::Registered(Limit::LoginLockoutThreshold),
        Span::Minutes(Limit::LoginLockoutMinutes),
    )
});

/// Attempts on one account from clients it does not know, all of them
/// together, in the lockout's window (`LOGIN_ACCOUNT_CEILING`, 20) and per
/// day (`LOGIN_ACCOUNT_DAILY_CEILING`, 200): the cap on guessing spread over
/// many addresses (`auth_check`). Slots are taken before the check and given
/// back on a right secret.
pub static LOGIN_CEILING: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::LoginAccountCeiling));

pub static LOGIN_DAILY_CEILING: LazyLock<WindowCounter> =
    LazyLock::new(|| WindowCounter::registered(Limit::LoginAccountDailyCeiling));

/// One source's share of an account's daily ceiling
/// (`LOGIN_SOURCE_DAILY_CEILING`, 20 a day per account and client): a
/// single address (or IPv6 /64) cannot use up the whole day alone.
pub static LOGIN_SOURCE_DAILY: LazyLock<WindowCounter> =
    LazyLock::new(|| WindowCounter::registered(Limit::LoginSourceDailyCeiling));

/// Counts per key over fixed windows, in a fixed-size table addressed by the
/// key's hash: memory stays the same however many keys are sprayed, and
/// nothing needs pruning. Two keys sharing a slot only make each other
/// stricter.
pub struct WindowCounter {
    slots: Mutex<Vec<(u64, u32)>>,
    limit: Bound,
    window_secs: u64,
}

const WINDOW_COUNTER_SLOTS: usize = 1 << 16;

impl WindowCounter {
    fn with(limit: Bound, window: Duration) -> Self {
        Self {
            slots: Mutex::new(vec![(0, 0); WINDOW_COUNTER_SLOTS]),
            limit,
            window_secs: window.as_secs().max(1),
        }
    }

    /// A counter for a registry entry counted in fixed windows.
    pub(crate) fn registered(limit: Limit) -> Self {
        match Span::of(limit) {
            Span::Fixed(window) => Self::with(Bound::Registered(limit), window),
            Span::Minutes(_) => unreachable!("{} has no fixed window", limit.spec().key),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(limit: u32, window: Duration) -> Self {
        Self::with(Bound::Fixed(limit.into()), window)
    }

    fn slot(key: &str) -> usize {
        let digest = hash(Suite::V1, key.as_bytes());
        (u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize)
            % WINDOW_COUNTER_SLOTS
    }

    fn window_now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            / self.window_secs
    }

    /// Takes one from `key`'s allowance in this window; `false` when none is left.
    pub fn allow(&self, key: &str) -> bool {
        let window = self.window_now();
        let mut slots = self.slots.lock().unwrap();
        let slot = &mut slots[Self::slot(key)];
        if slot.0 != window {
            *slot = (window, 0);
        }
        if u64::from(slot.1) >= self.limit.get() {
            return false;
        }
        slot.1 += 1;
        true
    }

    /// Gives one back (an attempt that turned out right).
    pub fn pop(&self, key: &str) {
        let window = self.window_now();
        let mut slots = self.slots.lock().unwrap();
        let slot = &mut slots[Self::slot(key)];
        if slot.0 == window {
            slot.1 = slot.1.saturating_sub(1);
        }
    }
}

/// Name checks (`available-hashes`): 120 a minute per account, enough for
/// "Keep both" over a large upload, not for guessing names fast.
pub static AVAILABLE_HASHES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::AvailableHashes));

/// Collaboration frames sent over HTTP (`POST …/collab/frames`, the CLI's
/// way in): 600 a minute per device, as many as a busy editing tab keeps.
pub static COLLAB_FRAME_POSTS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::CollabFramePosts));

/// Device registrations: 20 a minute per account (an editor app or the CLI
/// registering itself, docs/plans/one-device-list.md).
pub static DEVICE_REGISTRATIONS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::DeviceRegistrations));

/// Account head reads (the head, its chain, a scope's index): 300 a minute
/// per account, far above what a device checking before each listed write
/// needs.
pub static ACCOUNT_HEAD_READS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::AccountHeadReads));

/// Another server's renames asked of it (a lookup that found nothing fresh
/// kept): 60 per 15 minutes per account, so lookups cannot hammer a peer.
pub static RENAME_LOOKUPS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::RenameLookups));

/// Fetches of renames from one peer: 120 a minute per peer, whoever asks.
/// Accounts one account asks of one peer by id (real fetches only: answers
/// kept a short while serve the rest): 120 a minute per caller and peer.
pub static ACCOUNT_PEER_FETCHES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::AccountPeerFetches));

pub static RENAME_PEER_FETCHES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::RenamePeerFetches));

/// Rename announces taken from one peer: 600 a minute.
pub static RENAME_ANNOUNCES: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::RenameAnnounces));

/// Name checks before a rename: 30 per 15 minutes per account (registration
/// already says whether a name is taken).
pub static RENAME_CHECKS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::registered(Limit::RenameChecks));

// --- TOTP brute-force tracker (mirrors the `totpTracker` struct) ---

struct TotpTracker {
    attempts: HashMap<String, u32>,
    blocked_at: HashMap<String, Instant>,
}

static TOTP_TRACKER: LazyLock<Mutex<TotpTracker>> = LazyLock::new(|| {
    Mutex::new(TotpTracker {
        attempts: HashMap::new(),
        blocked_at: HashMap::new(),
    })
});

/// SHA-256 hex of a token — mirrors `hashToken` (tokens are never stored in the clear).
pub(crate) fn hash_token(token: &str) -> String {
    let digest = hash(Suite::V1, token.as_bytes());
    hex::encode(digest)
}

/// Whether this pre-auth token is currently blocked — mirrors `IsTOTPBlocked`.
pub fn is_totp_blocked(pre_auth_token: &str) -> bool {
    totp_blocked(hash_token(pre_auth_token))
}

/// Records a TOTP attempt result; returns false once the token is blocked — mirrors
/// `RecordTOTPAttempt`. Success clears the counter; the 5th failure blocks the token.
pub fn record_totp_attempt(pre_auth_token: &str, success: bool) -> bool {
    record_totp(hash_token(pre_auth_token), success)
}

/// The tracker's key for a signed-in account's second-factor checks
/// (renewing recovery codes, turning two-step sign-in off): one budget per
/// account, whichever session or grant guesses.
fn account_totp_key(account: uuid::Uuid) -> String {
    hash_token(&format!("account:{}", account.hyphenated()))
}

/// Whether the account's second-factor checks are blocked for now.
pub fn is_account_totp_blocked(account: uuid::Uuid) -> bool {
    totp_blocked(account_totp_key(account))
}

/// Records a signed-in second-factor check; false once the account is
/// blocked (after `totp_attempts` failures, for `totp_block_minutes`).
pub fn record_account_totp_attempt(account: uuid::Uuid, success: bool) -> bool {
    record_totp(account_totp_key(account), success)
}

fn totp_blocked(key: String) -> bool {
    let tracker = TOTP_TRACKER.lock().unwrap();
    tracker.blocked_at.contains_key(&key)
}

fn record_totp(key: String, success: bool) -> bool {
    let mut tracker = TOTP_TRACKER.lock().unwrap();

    if tracker.blocked_at.contains_key(&key) {
        return false;
    }
    if success {
        tracker.attempts.remove(&key);
        return true;
    }
    let count = tracker.attempts.entry(key.clone()).or_insert(0);
    *count += 1;
    if u64::from(*count) >= value(Limit::TotpAttempts) {
        tracker.blocked_at.insert(key, Instant::now());
        return false;
    }
    true
}

/// Prunes expired TOTP blocks — mirrors the Go `init()` cleanup goroutine.
fn cleanup_totp_tracker() {
    let now = Instant::now();
    let ttl = Span::Minutes(Limit::TotpBlockMinutes).get();
    let mut tracker = TOTP_TRACKER.lock().unwrap();
    let expired: Vec<String> = tracker
        .blocked_at
        .iter()
        .filter(|(_, t)| now.duration_since(**t) >= ttl)
        .map(|(k, _)| k.clone())
        .collect();
    for key in expired {
        tracker.blocked_at.remove(&key);
        tracker.attempts.remove(&key);
    }
}

/// Spawns the 5-minute background pruning task — replaces the Go `init()` goroutines.
pub fn spawn_cleanup() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(5 * 60));
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            RECOVERY.cleanup();
            FED_USERS.cleanup();
            FED_MULTI_IP.cleanup();
            RENAME_CHECKS.cleanup();
            RENAME_LOOKUPS.cleanup();
            RENAME_PEER_FETCHES.cleanup();
            ACCOUNT_PEER_FETCHES.cleanup();
            RENAME_ANNOUNCES.cleanup();
            LOGIN.cleanup();
            REGISTRATION_CODE_CHECK.cleanup();
            REGISTRATION_CODE_FAILURES.cleanup();
            FORK.cleanup();
            CALL_LINK.cleanup();
            CALL_LINK_POLL.cleanup();
            USER_LOOKUP.cleanup();
            REGISTER.cleanup();
            ADMIN.cleanup();
            CHAT_KEYS_ACCOUNT.cleanup();
            CHAT_KEYS_IP.cleanup();
            LOGIN_LOCKOUT.cleanup();
            LOGIN_CEILING.cleanup();
            AVAILABLE_HASHES.cleanup();
            COLLAB_FRAME_POSTS.cleanup();
            DEVICE_REGISTRATIONS.cleanup();
            CHAT_GROUP_RELAY.cleanup();
            CHAT_GROUP_GATEWAY_RELAY.cleanup();
            CHAT_GROUP_PSEUDONYM.cleanup();
            CHAT_GROUP_CHANGES_PSEUDONYM.cleanup();
            CHAT_GROUP_CHANGES_GROUP.cleanup();
            CHAT_GROUP_LINK.cleanup();
            CHAT_GROUP_LINK_JOINS_RELAY_GROUP.cleanup();
            CHAT_GROUP_LINK_JOINS_RELAY.cleanup();
            CHAT_GROUP_FAILURES_RELAY.cleanup();
            CHAT_GROUP_CREATES_RELAY.cleanup();
            cleanup_totp_tracker();
            // Per-feature limiters kept beside their handlers.
            crate::handlers::chat_link_preview::LINK_PREVIEWS.cleanup();
            crate::handlers::pass_icons::PASS_ICONS.cleanup();
            crate::handlers::pass_icons::PASS_ICON_FETCHES.cleanup();
            crate::handlers::mail_images::MAIL_IMAGES.cleanup();
            crate::handlers::mail_images::cleanup();
            crate::handlers::calendar::WRITES.cleanup();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> crate::config::Env {
        crate::config::Env::from_pairs(pairs)
    }

    #[test]
    fn first_values_take_the_environment_then_the_default() {
        let first = first_values(&env(&[("RATE_LIMIT_LOGIN_PER_MIN", "7")]), false);
        assert_eq!(first[Limit::Login as usize], (7, FirstFrom::Environment));
        assert_eq!(first[Limit::Register as usize], (10, FirstFrom::Default));
        assert_eq!(first[Limit::MapTiles as usize], (1200, FirstFrom::Default));

        // A test stack raises the RATE_LIMIT_* defaults only; a variable
        // still wins.
        let relaxed = first_values(&env(&[("RATE_LIMIT_LOGIN_PER_MIN", "7")]), true);
        assert_eq!(relaxed[Limit::Login as usize], (7, FirstFrom::Environment));
        assert_eq!(
            relaxed[Limit::Register as usize],
            (registry::RELAXED, FirstFrom::TestStack)
        );
        assert_eq!(
            relaxed[Limit::LoginLockoutThreshold as usize],
            (5, FirstFrom::Default)
        );
        assert_eq!(
            relaxed[Limit::MapTiles as usize],
            (1200, FirstFrom::Default)
        );
    }

    #[test]
    fn environment_values_out_of_bounds_stop_the_server() {
        let checked = env(&[
            ("RATE_LIMIT_LOGIN_PER_MIN", "0"),
            ("LOGIN_LOCKOUT_THRESHOLD", "501"),
            ("RATE_LIMIT_NOT_A_LIMIT", "3"),
        ]);
        let first = first_values(&checked, false);
        assert_eq!(first[Limit::LoginLockoutThreshold as usize].0, 500);
        let known = |name: &str| SPECS.iter().any(|spec| spec.env == Some(name));
        assert_eq!(
            checked.unknown_with_prefix("RATE_LIMIT_", &known),
            Some(vec!["RATE_LIMIT_NOT_A_LIMIT".to_owned()])
        );
        assert_eq!(checked.finish().map_err(|errors| errors.len()), Err(2));
    }

    #[test]
    fn stored_values_apply_within_bounds() {
        let spec = Limit::Login.spec();
        let stored = |text: &str| Some(text.to_owned());
        // Sign-in guards against guessing: 100 times its default, even on a
        // test stack.
        assert_eq!(spec.ceiling(false), 1000);
        assert_eq!(spec.ceiling(true), 1000);
        assert_eq!(Limit::ChatKeysAddress.spec().ceiling(true), 100_000);
        assert_eq!(Limit::ChatKeysAddress.spec().ceiling(false), 12_000);
        let ceiling = spec.ceiling(false);
        assert_eq!(effective(spec, None, 10, ceiling), 10);
        assert_eq!(effective(spec, stored("3").as_ref(), 10, ceiling), 3);
        assert_eq!(effective(spec, stored("1000").as_ref(), 10, ceiling), 1000);
        for refused in ["0", "1001", "-1", "many"] {
            assert_eq!(
                effective(spec, stored(refused).as_ref(), 10, ceiling),
                10,
                "{refused}"
            );
        }
    }

    #[test]
    fn registered_limiters_read_the_current_value() {
        // Its own value source: the configuration tests write the shared
        // snapshot while this runs.
        static CELL: AtomicU64 = AtomicU64::new(2);
        let limiter = RateLimiter::with(Bound::Cell(&CELL), Span::Fixed(Duration::from_secs(60)));
        assert!(limiter.allow("a"));
        assert!(limiter.allow("a"));
        assert!(!limiter.allow("a"));
        // Raised: applies at once.
        CELL.store(3, Ordering::Relaxed);
        assert!(limiter.allow("a"));
        // Lowered: the next check is held to it.
        CELL.store(1, Ordering::Relaxed);
        assert!(!limiter.allow("a"));
    }

    #[test]
    fn accounts_get_their_own_values_where_a_limit_takes_them() {
        // Nothing else in the tests uses these limits.
        let limiter = RateLimiter::registered(Limit::LiveLocationStreams);
        let account = "0b7c9a52-3a8e-4bb4-9a0e-6c1f2e1d0a11";
        apply_overrides(vec![
            (account.to_owned(), "live_location_streams".to_owned(), 1),
            // Not per account, out of bounds, unknown: ignored.
            (account.to_owned(), "reports".to_owned(), 1),
            (account.to_owned(), "pass_icons".to_owned(), 0),
            (account.to_owned(), "no_such_limit".to_owned(), 1),
        ]);
        assert_eq!(
            account_override(Limit::LiveLocationStreams, account),
            Some(1)
        );
        assert_eq!(account_override(Limit::Reports, account), None);
        assert_eq!(account_override(Limit::PassIcons, account), None);
        assert!(limiter.allow(account));
        assert!(!limiter.allow(account));
        assert!(limiter.allow("another-account"));
        apply_overrides(Vec::new());
        assert!(limiter.allow(account));
        assert!(!Limit::LoginAccountCeiling.spec().overridable());
        assert!(Limit::Feedback.spec().overridable());
    }

    #[test]
    fn limiter_blocks_after_limit() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.allow("ip"));
        assert!(rl.allow("ip"));
        assert!(rl.allow("ip"));
        assert!(!rl.allow("ip")); // 4th in window is denied
        assert!(rl.allow("other")); // separate key unaffected
    }

    #[test]
    fn totp_blocks_after_five_failures() {
        let token = "pre-auth-token-A";
        for _ in 0..4 {
            assert!(record_totp_attempt(token, false));
            assert!(!is_totp_blocked(token));
        }
        // 5th failure trips the block.
        assert!(!record_totp_attempt(token, false));
        assert!(is_totp_blocked(token));
        // Once blocked, further attempts stay denied.
        assert!(!record_totp_attempt(token, true));
    }

    #[test]
    fn an_accounts_second_factor_checks_block_after_five_failures() {
        let (account, other) = (
            uuid::Uuid::from_bytes([7; 16]),
            uuid::Uuid::from_bytes([8; 16]),
        );
        for _ in 0..4 {
            assert!(record_account_totp_attempt(account, false));
            assert!(!is_account_totp_blocked(account));
        }
        assert!(!record_account_totp_attempt(account, false));
        assert!(is_account_totp_blocked(account));
        assert!(!record_account_totp_attempt(account, true));
        // Another account, and a pre-auth token, keep their own budgets.
        assert!(!is_account_totp_blocked(other));
        assert!(!is_totp_blocked(&account.to_string()));
    }

    #[test]
    fn lockout_trips_after_threshold_and_expires() {
        let lo = LoginLockout::new(3, Duration::from_millis(50));
        let subject = "account:A";
        assert!(lo.reserve(subject));
        assert!(lo.reserve(subject));
        assert!(!lo.is_locked(subject));
        assert!(lo.reserve(subject)); // the 3rd attempt still runs, and locks
        assert!(lo.is_locked(subject));
        assert!(!lo.reserve(subject));
        // The lock expires after the TTL, and the counter with it.
        std::thread::sleep(Duration::from_millis(60));
        assert!(lo.reserve(subject));
        assert!(!lo.is_locked(subject));
    }

    #[test]
    fn lockout_success_clears_failures() {
        let lo = LoginLockout::new(3, Duration::from_secs(60));
        let subject = "account:B";
        lo.reserve(subject);
        lo.reserve(subject);
        lo.succeeded(subject); // a right secret resets the counter
        lo.reserve(subject);
        lo.reserve(subject);
        assert!(!lo.is_locked(subject));
    }

    #[test]
    fn window_counters_stay_fixed_size_and_give_back() {
        let counter = WindowCounter::new(3, Duration::from_secs(3600));
        assert!(counter.allow("a"));
        assert!(counter.allow("a"));
        assert!(counter.allow("a"));
        assert!(!counter.allow("a"));
        counter.pop("a");
        assert!(counter.allow("a"));
        // Spraying keys never grows it.
        for i in 0..200_000 {
            counter.allow(&format!("spray-{i}"));
        }
        assert_eq!(counter.slots.lock().unwrap().len(), WINDOW_COUNTER_SLOTS);
    }

    #[test]
    fn lockout_cleanup_keeps_other_subjects_counters() {
        let lo = LoginLockout::new(3, Duration::from_secs(60));
        lo.reserve("victim");
        lo.reserve("victim");
        for i in 0..20_000 {
            lo.reserve(&format!("spray-{i}"));
        }
        lo.cleanup();
        lo.reserve("victim");
        assert!(lo.is_locked("victim"));
    }

    #[test]
    fn totp_success_clears_counter() {
        let token = "pre-auth-token-B";
        assert!(record_totp_attempt(token, false));
        assert!(record_totp_attempt(token, false));
        assert!(record_totp_attempt(token, true)); // success resets
                                                   // Counter cleared: can fail 4 more times without blocking.
        for _ in 0..4 {
            assert!(record_totp_attempt(token, false));
        }
        assert!(!is_totp_blocked(token));
    }
}
