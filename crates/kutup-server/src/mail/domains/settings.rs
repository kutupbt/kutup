//! Custom domains' limits and switches (docs/plans/mail-custom-domains.md
//! §7, decided 2026-10-20): site settings an administrator edits, with a
//! per-user override for the per-account ones. Read on every use, so a
//! change applies at once.

use std::collections::HashMap;

use sqlx::PgPool;

use super::policy::Grace;

/// Who may add a custom domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Everyone,
    /// Verified domains wait for an administrator's approval.
    AdminsApprove,
    Off,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Everyone => "everyone",
            Mode::AdminsApprove => "approve",
            Mode::Off => "off",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "everyone" => Mode::Everyone,
            "approve" => Mode::AdminsApprove,
            "off" => Mode::Off,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    pub domains_per_account: i64,
    /// Every address an account has, its username's included.
    pub addresses_per_account: i64,
    pub domains_on_server: i64,
    pub adds_per_day: i64,
    pub pending_days: i64,
    pub catch_all: bool,
    pub catch_all_per_day: i64,
    pub grace_warn_days: i64,
    pub grace_stopped_hours: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: Mode::Everyone,
            domains_per_account: 3,
            addresses_per_account: 10,
            domains_on_server: 1000,
            adds_per_day: 10,
            pending_days: 14,
            catch_all: true,
            catch_all_per_day: 500,
            grace_warn_days: 14,
            grace_stopped_hours: 72,
        }
    }
}

/// The site-setting keys, each with its range.
pub const KEYS: [(&str, i64, i64); 9] = [
    ("mail_domains.per_account", 0, 100),
    ("mail_domains.addresses_per_account", 1, 1000),
    ("mail_domains.on_server", 0, 1_000_000),
    ("mail_domains.adds_per_day", 1, 1000),
    ("mail_domains.pending_days", 1, 365),
    ("mail_domains.catch_all_per_day", 0, 100_000),
    ("mail_domains.grace_warn_days", 1, 365),
    ("mail_domains.grace_stopped_hours", 1, 24 * 30),
    // 1 on, 0 off.
    ("mail_domains.catch_all", 0, 1),
];
pub const MODE_KEY: &str = "mail_domains.mode";

/// A value an administrator gives for `key`, checked against its range.
pub fn validate(key: &str, value: &str) -> Result<String, String> {
    if key == MODE_KEY {
        return Mode::parse(value)
            .map(|mode| mode.as_str().to_owned())
            .ok_or_else(|| "the mode is everyone, approve or off".to_owned());
    }
    let (_, low, high) = KEYS
        .iter()
        .find(|(k, _, _)| *k == key)
        .ok_or_else(|| format!("no setting {key}"))?;
    let number: i64 = value.parse().map_err(|_| format!("{key} takes a number"))?;
    if !(*low..=*high).contains(&number) {
        return Err(format!("{key} is between {low} and {high}"));
    }
    Ok(number.to_string())
}

impl Settings {
    /// The stored values over the defaults; one out of range keeps the
    /// default (it was checked when stored).
    pub fn from_stored(stored: &HashMap<String, String>) -> Self {
        let mut settings = Settings::default();
        let number = |key: &str, fallback: i64| {
            stored
                .get(key)
                .and_then(|value| validate(key, value).ok())
                .and_then(|value| value.parse().ok())
                .unwrap_or(fallback)
        };
        if let Some(mode) = stored.get(MODE_KEY).and_then(|v| Mode::parse(v)) {
            settings.mode = mode;
        }
        settings.domains_per_account = number(KEYS[0].0, settings.domains_per_account);
        settings.addresses_per_account = number(KEYS[1].0, settings.addresses_per_account);
        settings.domains_on_server = number(KEYS[2].0, settings.domains_on_server);
        settings.adds_per_day = number(KEYS[3].0, settings.adds_per_day);
        settings.pending_days = number(KEYS[4].0, settings.pending_days);
        settings.catch_all_per_day = number(KEYS[5].0, settings.catch_all_per_day);
        settings.grace_warn_days = number(KEYS[6].0, settings.grace_warn_days);
        settings.grace_stopped_hours = number(KEYS[7].0, settings.grace_stopped_hours);
        settings.catch_all = number(KEYS[8].0, 1) == 1;
        settings
    }

    pub async fn load(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM site_settings WHERE key LIKE 'mail_domains.%'")
                .fetch_all(pool)
                .await?;
        Ok(Settings::from_stored(&rows.into_iter().collect()))
    }

    /// `user`'s limits: the site's, with the user's override where set.
    pub async fn for_user(&self, pool: &PgPool, user: uuid::Uuid) -> Result<Self, sqlx::Error> {
        let row: Option<(Option<i32>, Option<i32>, Option<bool>)> = sqlx::query_as(
            "SELECT max_domains, max_addresses, catch_all FROM mail_domain_overrides WHERE user_id = $1",
        )
        .bind(user)
        .fetch_optional(pool)
        .await?;
        let mut settings = *self;
        if let Some((domains, addresses, catch_all)) = row {
            settings.domains_per_account = domains.map_or(settings.domains_per_account, i64::from);
            settings.addresses_per_account =
                addresses.map_or(settings.addresses_per_account, i64::from);
            settings.catch_all = catch_all.unwrap_or(settings.catch_all);
        }
        Ok(settings)
    }

    pub fn grace(&self) -> Grace {
        Grace {
            warn_for: self.grace_warn_days * 24 * 3600,
            stopped_for: self.grace_stopped_hours * 3600,
            ..Grace::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_decided_ones() {
        let settings = Settings::default();
        assert_eq!(settings.mode, Mode::Everyone);
        assert_eq!(
            (
                settings.domains_per_account,
                settings.addresses_per_account,
                settings.domains_on_server
            ),
            (3, 10, 1000)
        );
        assert_eq!(settings.grace().warn_for, 14 * 24 * 3600);
        assert_eq!(settings.grace().stopped_for, 72 * 3600);
    }

    #[test]
    fn stored_values_override_and_bad_ones_are_ignored() {
        let stored: HashMap<String, String> = [
            ("mail_domains.mode", "approve"),
            ("mail_domains.per_account", "5"),
            ("mail_domains.addresses_per_account", "0"),
            ("mail_domains.catch_all", "0"),
            ("mail_domains.grace_warn_days", "x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let settings = Settings::from_stored(&stored);
        assert_eq!(settings.mode, Mode::AdminsApprove);
        assert_eq!(settings.domains_per_account, 5);
        assert_eq!(
            settings.addresses_per_account, 10,
            "out of range keeps the default"
        );
        assert!(!settings.catch_all);
        assert_eq!(settings.grace_warn_days, 14);
    }

    #[test]
    fn values_are_checked_when_set() {
        assert_eq!(validate("mail_domains.mode", "off").unwrap(), "off");
        assert!(validate("mail_domains.mode", "maybe").is_err());
        assert_eq!(validate("mail_domains.per_account", "0").unwrap(), "0");
        assert!(validate("mail_domains.per_account", "101").is_err());
        assert!(validate("mail_domains.per_account", "-1").is_err());
        assert!(validate("mail_domains.nothing", "1").is_err());
    }
}
