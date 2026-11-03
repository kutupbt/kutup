//! Custom domains' limits and switches (docs/plans/mail-custom-domains.md
//! §7, decided 2026-10-20): site settings an administrator edits, with an
//! organization's own value for the ones that limit an organization (its
//! domains, its catch-all: docs/plans/organizations.md §7) and an account's
//! own for its address count. Read on every use, so a change applies at once.

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
    /// Domains an organization may hold (was per account before organizations).
    pub domains_per_organization: i64,
    /// Every address an account has, its username's included.
    pub addresses_per_account: i64,
    pub domains_on_server: i64,
    pub adds_per_day: i64,
    pub pending_days: i64,
    pub catch_all: bool,
    pub catch_all_per_day: i64,
    pub grace_warn_days: i64,
    pub grace_stopped_hours: i64,
    /// Owners' checks (`?refresh=1`) running at once on this server.
    pub refreshes_at_once: i64,
    /// The most one domain's whole check (every lookup) may take.
    pub check_timeout_seconds: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: Mode::Everyone,
            domains_per_organization: 3,
            addresses_per_account: 10,
            domains_on_server: 1000,
            adds_per_day: 10,
            pending_days: 14,
            catch_all: true,
            catch_all_per_day: 500,
            grace_warn_days: 14,
            grace_stopped_hours: 72,
            refreshes_at_once: 16,
            check_timeout_seconds: 60,
        }
    }
}

/// The site-setting keys, each with its range.
pub const KEYS: [(&str, i64, i64); 11] = [
    ("mail_domains.per_organization", 0, 100),
    ("mail_domains.addresses_per_account", 1, 1000),
    ("mail_domains.on_server", 0, 1_000_000),
    ("mail_domains.adds_per_day", 1, 1000),
    ("mail_domains.pending_days", 1, 365),
    ("mail_domains.catch_all_per_day", 0, 100_000),
    ("mail_domains.grace_warn_days", 1, 365),
    ("mail_domains.grace_stopped_hours", 1, 24 * 30),
    // 1 on, 0 off.
    ("mail_domains.catch_all", 0, 1),
    ("mail_domains.refreshes_at_once", 1, 1000),
    ("mail_domains.check_timeout_seconds", 10, 600),
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
        settings.domains_per_organization = number(KEYS[0].0, settings.domains_per_organization);
        settings.addresses_per_account = number(KEYS[1].0, settings.addresses_per_account);
        settings.domains_on_server = number(KEYS[2].0, settings.domains_on_server);
        settings.adds_per_day = number(KEYS[3].0, settings.adds_per_day);
        settings.pending_days = number(KEYS[4].0, settings.pending_days);
        settings.catch_all_per_day = number(KEYS[5].0, settings.catch_all_per_day);
        settings.grace_warn_days = number(KEYS[6].0, settings.grace_warn_days);
        settings.grace_stopped_hours = number(KEYS[7].0, settings.grace_stopped_hours);
        settings.catch_all = number(KEYS[8].0, 1) == 1;
        settings.refreshes_at_once = number(KEYS[9].0, settings.refreshes_at_once);
        settings.check_timeout_seconds = number(KEYS[10].0, settings.check_timeout_seconds);
        settings
    }

    pub async fn load(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM site_settings WHERE key LIKE 'mail_domains.%'")
                .fetch_all(pool)
                .await?;
        Ok(Settings::from_stored(&rows.into_iter().collect()))
    }

    /// The keys an organization may have its own value for.
    pub const ORGANIZATION_KEYS: [&'static str; 2] = [KEYS[0].0, KEYS[8].0];
    /// The key an account may have its own value for.
    pub const ACCOUNT_KEY: &'static str = KEYS[1].0;

    /// `organization`'s limits: the site's, with the organization's own
    /// values (`organization_setting_overrides`) where set and in range.
    pub async fn for_org<'e, E: sqlx::PgExecutor<'e>>(
        &self,
        executor: E,
        organization: uuid::Uuid,
    ) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT key, value FROM organization_setting_overrides
              WHERE organization_id = $1 AND key = ANY($2)",
        )
        .bind(organization)
        .bind(&Self::ORGANIZATION_KEYS[..])
        .fetch_all(executor)
        .await?;
        Ok(self.with_org_values(&rows))
    }

    fn with_org_values(&self, rows: &[(String, i64)]) -> Self {
        let mut settings = *self;
        for (key, value) in rows {
            let Ok(value) = validate(key, &value.to_string()) else {
                continue;
            };
            let value: i64 = value.parse().unwrap_or_default();
            if key == KEYS[0].0 {
                settings.domains_per_organization = value;
            } else if key == KEYS[8].0 {
                settings.catch_all = value == 1;
            }
        }
        settings
    }

    /// `account`'s address limit: the site's, with the account's own value
    /// (`user_setting_overrides`) where set and in range.
    pub async fn for_account(
        &self,
        pool: &PgPool,
        account: uuid::Uuid,
    ) -> Result<Self, sqlx::Error> {
        let own: Option<i64> = sqlx::query_scalar(
            "SELECT value FROM user_setting_overrides WHERE user_id = $1 AND key = $2",
        )
        .bind(account)
        .bind(Self::ACCOUNT_KEY)
        .fetch_optional(pool)
        .await?;
        let mut settings = *self;
        if let Some(value) = own.and_then(|v| validate(Self::ACCOUNT_KEY, &v.to_string()).ok()) {
            settings.addresses_per_account =
                value.parse().unwrap_or(settings.addresses_per_account);
        }
        Ok(settings)
    }

    pub fn grace(&self) -> Grace {
        Grace {
            confirm_after: super::scaled(Grace::default().confirm_after),
            warn_for: super::scaled(self.grace_warn_days * 24 * 3600),
            stopped_for: super::scaled(self.grace_stopped_hours * 3600),
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
                settings.domains_per_organization,
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
            ("mail_domains.per_organization", "5"),
            ("mail_domains.addresses_per_account", "0"),
            ("mail_domains.catch_all", "0"),
            ("mail_domains.grace_warn_days", "x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let settings = Settings::from_stored(&stored);
        assert_eq!(settings.mode, Mode::AdminsApprove);
        assert_eq!(settings.domains_per_organization, 5);
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
        assert_eq!(validate("mail_domains.per_organization", "0").unwrap(), "0");
        assert!(validate("mail_domains.per_organization", "101").is_err());
        assert!(validate("mail_domains.per_organization", "-1").is_err());
        assert!(validate("mail_domains.nothing", "1").is_err());
    }

    #[test]
    fn an_organization_has_its_own_domains_and_catch_all_only() {
        let site = Settings::default();
        let own = site.with_org_values(&[
            ("mail_domains.per_organization".into(), 7),
            ("mail_domains.catch_all".into(), 0),
            // Out of range: the site's stays.
            ("mail_domains.per_organization".into(), 500),
        ]);
        assert_eq!(own.domains_per_organization, 7);
        assert!(!own.catch_all);
        assert_eq!(own.addresses_per_account, site.addresses_per_account);
    }
}
