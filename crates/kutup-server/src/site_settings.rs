use sqlx::PgPool;

use crate::config::OutsideSending;

/// Who may send mail outside Kutup (`off`, `admins`, `on`), set under
/// Administration → Mail sending; `MAIL_OUTSIDE_SENDING` only seeds it.
pub const MAIL_OUTSIDE_SENDING: &str = "mail_outside_sending";

/// Writes `initial` (from `MAIL_OUTSIDE_SENDING`) as the outside-sending
/// policy when none is stored yet: an existing deployment keeps what it had,
/// and the administrators' choice wins from then on.
pub async fn seed_mail_outside_sending(
    pool: &PgPool,
    initial: OutsideSending,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
    )
    .bind(MAIL_OUTSIDE_SENDING)
    .bind(initial.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// The outside-sending policy now: the stored one, else `fallback`. Read on
/// every check, so a change applies at once, without a restart.
pub async fn mail_outside_sending(
    pool: &PgPool,
    fallback: OutsideSending,
) -> Result<OutsideSending, sqlx::Error> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key = $1")
            .bind(MAIL_OUTSIDE_SENDING)
            .fetch_optional(pool)
            .await?
            .and_then(|value| OutsideSending::from_setting(&value))
            .unwrap_or(fallback),
    )
}

pub const CHAT_MAILBOX_RETENTION_DAYS: &str = "chat_mailbox_retention_days";
pub const CHAT_MEDIA_DELIVERY_RETENTION_DAYS: &str = "chat_media_delivery_retention_days";
pub const MAX_CHAT_DELIVERY_RETENTION_DAYS: i64 = 3650;

pub fn validate_chat_delivery_retention_days(value: i64) -> Result<i64, &'static str> {
    if (0..=MAX_CHAT_DELIVERY_RETENTION_DAYS).contains(&value) {
        Ok(value)
    } else {
        Err("Chat delivery retention must be between 0 and 3650 days")
    }
}

/// Resolve an administrator override, falling back to validated environment
/// configuration. Zero consistently means that automatic expiry is disabled.
pub async fn chat_delivery_retention_days(
    pool: &PgPool,
    key: &str,
    fallback: i64,
) -> Result<i64, sqlx::Error> {
    let fallback = validate_chat_delivery_retention_days(fallback).unwrap_or_default();
    Ok(
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
            .bind(key)
            .fetch_optional(pool)
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| validate_chat_delivery_retention_days(value).ok())
            .unwrap_or(fallback),
    )
}

/// How long a name an account left (a rename, a deletion) stays held before
/// anyone may take it, and how long its old address still receives
/// (docs/plans/username-renames.md, "Names over time"); administrators set
/// both, `NAME_HOLD_DAYS` and `OLD_ADDRESS_RECEIVE_DAYS` only seed them.
pub const NAME_HOLD_DAYS: &str = "name_hold_days";
pub const OLD_ADDRESS_RECEIVE_DAYS: &str = "old_address_receive_days";

/// Holds of 30 days to 10 years; receiving from 0 days to the hold.
pub fn validate_name_holds(hold: i64, receive: i64) -> Result<(i64, i64), &'static str> {
    if !(30..=3650).contains(&hold) {
        return Err("a name is held for 30 to 3650 days");
    }
    if !(0..=hold).contains(&receive) {
        return Err("an old address receives for 0 days up to the hold");
    }
    Ok((hold, receive))
}

/// The name holds now, `(hold days, receive days)`: the stored ones, else
/// the configured ones, else the defaults (180, 90).
pub async fn name_holds(
    pool: &PgPool,
    config: &crate::config::Config,
) -> Result<(i64, i64), sqlx::Error> {
    let read = |key: &'static str| async move {
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
            .bind(key)
            .fetch_optional(pool)
            .await
            .map(|v| v.and_then(|v| v.parse::<i64>().ok()))
    };
    let hold = read(NAME_HOLD_DAYS).await?.unwrap_or(config.name_hold_days);
    let receive = read(OLD_ADDRESS_RECEIVE_DAYS)
        .await?
        .unwrap_or(config.old_address_receive_days);
    Ok(validate_name_holds(hold, receive).unwrap_or((180, 90)))
}

/// Joins from a group link and requests to join (docs/plans/pairwise-groups.md,
/// slice 3), per minute per relay server and group, and per relay server in
/// all, set under Administration → Server settings; the
/// `RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_*` variables only seed them.
pub const CHAT_GROUP_LINK_JOINS_PER_RELAY_GROUP: &str =
    "chat_group_link_joins_per_relay_group_per_min";
pub const CHAT_GROUP_LINK_JOINS_PER_RELAY: &str = "chat_group_link_joins_per_relay_per_min";
pub const MAX_LINK_JOINS_PER_MIN: i64 = 1_000_000;

pub fn validate_chat_group_link_joins(value: i64) -> Result<i64, &'static str> {
    if (1..=MAX_LINK_JOINS_PER_MIN).contains(&value) {
        Ok(value)
    } else {
        Err("link joins must be between 1 and 1000000 a minute")
    }
}

/// The link-join budgets now, `(per relay and group, per relay)`: the
/// stored ones, else the configured first values. Read on every join, so a
/// change applies at once.
pub async fn chat_group_link_joins(pool: &PgPool) -> Result<(i64, i64), sqlx::Error> {
    let (group_fallback, relay_fallback) = crate::ratelimit::chat_group_link_joins_defaults();
    let read = |key: &'static str, fallback: i64| async move {
        Ok::<_, sqlx::Error>(
            sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
                .bind(key)
                .fetch_optional(pool)
                .await?
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|value| validate_chat_group_link_joins(value).ok())
                .unwrap_or(fallback),
        )
    };
    Ok((
        read(CHAT_GROUP_LINK_JOINS_PER_RELAY_GROUP, group_fallback).await?,
        read(CHAT_GROUP_LINK_JOINS_PER_RELAY, relay_fallback).await?,
    ))
}

/// Group avatars on this home (docs/plans/pairwise-groups.md, "Avatar"):
/// the largest blob it takes (one of the avatar lengths), the most its
/// avatars may take per group (the current blob and a pending upload), and
/// how long an upload waits for a change to name it, set under
/// Administration → Server settings.
pub const CHAT_GROUP_AVATAR_MAX_BYTES: &str = "chat_group_avatar_max_bytes";
pub const CHAT_GROUP_AVATAR_STORAGE_BYTES: &str = "chat_group_avatar_storage_per_group_bytes";
pub const CHAT_GROUP_AVATAR_PENDING_SECONDS: &str = "chat_group_avatar_pending_seconds";

/// A home's avatar limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvatarLimits {
    pub max_bytes: i64,
    pub storage_bytes: i64,
    pub pending_seconds: i64,
}

impl AvatarLimits {
    /// The first values: the largest blob, room for two of them (so a
    /// group can always swap its avatar), a day.
    pub const DEFAULT: AvatarLimits = AvatarLimits {
        max_bytes: 41_001,
        storage_bytes: 2 * 41_001,
        pending_seconds: 24 * 3600,
    };
    /// The most storage a group's avatars may be given: two of the largest.
    pub const MAX_STORAGE_BYTES: i64 = 2 * 41_001;

    /// Checks the three together: the largest blob one of the avatar
    /// lengths, the storage room for two of them (a swap needs the old and
    /// the new) and at most two of the largest, the wait a minute to a week.
    pub fn validate(self) -> Result<Self, &'static str> {
        let lengths = kutup_chat_proto::group_route::GROUP_AVATAR_BLOB_LENGTHS;
        if !usize::try_from(self.max_bytes).is_ok_and(|value| lengths.contains(&value)) {
            return Err("the largest group avatar is 8233, 16425, 32809 or 41001 bytes");
        }
        if !(2 * self.max_bytes..=Self::MAX_STORAGE_BYTES).contains(&self.storage_bytes) {
            return Err(
                "group avatar storage is at least twice the largest avatar and at most 82002 bytes",
            );
        }
        if !(60..=7 * 24 * 3600).contains(&self.pending_seconds) {
            return Err("an avatar upload waits 60 seconds to a week");
        }
        Ok(self)
    }
}

/// The avatar limits now: the stored ones, else the first values; a stored
/// set that doesn't hold together (checked when stored) gives the first
/// values. Read on every upload and change.
pub async fn chat_group_avatar_limits(pool: &PgPool) -> Result<AvatarLimits, sqlx::Error> {
    let read = |key: &'static str| async move {
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
            .bind(key)
            .fetch_optional(pool)
            .await
            .map(|value| value.and_then(|value| value.parse::<i64>().ok()))
    };
    let default = AvatarLimits::DEFAULT;
    let limits = AvatarLimits {
        max_bytes: read(CHAT_GROUP_AVATAR_MAX_BYTES)
            .await?
            .unwrap_or(default.max_bytes),
        storage_bytes: read(CHAT_GROUP_AVATAR_STORAGE_BYTES)
            .await?
            .unwrap_or(default.storage_bytes),
        pending_seconds: read(CHAT_GROUP_AVATAR_PENDING_SECONDS)
            .await?
            .unwrap_or(default.pending_seconds),
    };
    Ok(limits.validate().unwrap_or(default))
}

/// How many group delivery capabilities one account may publish (one per
/// group it is in; docs/plans/pairwise-groups.md, slice 2 §2), set under
/// Administration → Server settings.
pub const CHAT_GROUP_CAPABILITIES_PER_ACCOUNT: &str = "chat_group_capabilities_per_account";
pub const DEFAULT_CHAT_GROUP_CAPABILITIES_PER_ACCOUNT: i64 = 1024;

pub fn validate_chat_group_capabilities_per_account(value: i64) -> Result<i64, &'static str> {
    if (1..=100_000).contains(&value) {
        Ok(value)
    } else {
        Err("group capabilities per account must be between 1 and 100000")
    }
}

/// The capability limit now: the stored one, else 1024.
pub async fn chat_group_capabilities_per_account(pool: &PgPool) -> Result<i64, sqlx::Error> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
            .bind(CHAT_GROUP_CAPABILITIES_PER_ACCOUNT)
            .fetch_optional(pool)
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| validate_chat_group_capabilities_per_account(value).ok())
            .unwrap_or(DEFAULT_CHAT_GROUP_CAPABILITIES_PER_ACCOUNT),
    )
}

/// A whole-number setting administrators set: its key, its field in
/// `/api/admin/settings`, its first value and its range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumericSetting {
    pub key: &'static str,
    pub field: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
}

impl NumericSetting {
    pub fn validate(&self, value: i64) -> Result<i64, String> {
        if (self.min..=self.max).contains(&value) {
            Ok(value)
        } else {
            Err(format!(
                "{} is between {} and {}",
                self.field, self.min, self.max
            ))
        }
    }

    /// The stored value, else the first value.
    pub async fn load(&self, pool: &PgPool) -> Result<i64, sqlx::Error> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
                .bind(self.key)
                .fetch_optional(pool)
                .await?
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|value| self.validate(value).ok())
                .unwrap_or(self.default),
        )
    }
}

/// Multi-recipient sends (docs/plans/pairwise-groups.md, slice 2 §1 and §4),
/// with Signal's values first: the largest message one recipient gets, the
/// request's size before its per-recipient headers, how many accounts one
/// request names, the bytes one address may send a minute, and the sends a
/// group capability takes a minute and a day.
pub const CHAT_MULTI_MAX_MESSAGE_BYTES: NumericSetting = NumericSetting {
    key: "chat_multi_max_message_bytes",
    field: "chatMultiMaxMessageBytes",
    default: 96 * 1024,
    min: 4 * 1024,
    max: 1024 * 1024,
};
pub const CHAT_MULTI_BASE_BYTES: NumericSetting = NumericSetting {
    key: "chat_multi_base_bytes",
    field: "chatMultiBaseBytes",
    default: 256 * 1024,
    min: 4 * 1024,
    max: 4 * 1024 * 1024,
};
pub const CHAT_MULTI_MAX_RECIPIENTS: NumericSetting = NumericSetting {
    key: "chat_multi_max_recipients",
    field: "chatMultiMaxRecipients",
    default: 256,
    min: 1,
    max: kutup_chat_proto::MAX_SEALED_MULTI_RECIPIENTS as i64,
};
pub const CHAT_MULTI_IP_BYTES_PER_MIN: NumericSetting = NumericSetting {
    key: "chat_multi_ip_bytes_per_min",
    field: "chatMultiIpBytesPerMin",
    default: 32 * 1024 * 1024,
    min: 1024 * 1024,
    max: 1024 * 1024 * 1024,
};
pub const CHAT_GROUP_CAPABILITY_SENDS_PER_MIN: NumericSetting = NumericSetting {
    key: "chat_group_capability_sends_per_min",
    field: "chatGroupCapabilitySendsPerMin",
    default: 120,
    min: 1,
    max: 100_000,
};
pub const CHAT_GROUP_CAPABILITY_SENDS_PER_DAY: NumericSetting = NumericSetting {
    key: "chat_group_capability_sends_per_day",
    field: "chatGroupCapabilitySendsPerDay",
    default: 10_000,
    min: 1,
    max: 10_000_000,
};
/// What one origin server may deliver here in multi-recipient sends a
/// minute, all its users together: requests and bytes (never counted per
/// stored recipient).
pub const CHAT_MULTI_ORIGIN_REQUESTS_PER_MIN: NumericSetting = NumericSetting {
    key: "chat_multi_origin_requests_per_min",
    field: "chatMultiOriginRequestsPerMin",
    default: 6_000,
    min: 1,
    max: 1_000_000,
};
pub const CHAT_MULTI_ORIGIN_BYTES_PER_MIN: NumericSetting = NumericSetting {
    key: "chat_multi_origin_bytes_per_min",
    field: "chatMultiOriginBytesPerMin",
    default: 512 * 1024 * 1024,
    min: 1024 * 1024,
    max: 16 * 1024 * 1024 * 1024,
};
/// Every multi-recipient setting, as `/api/admin/settings` lists them.
pub const CHAT_MULTI_SETTINGS: [NumericSetting; 8] = [
    CHAT_MULTI_MAX_MESSAGE_BYTES,
    CHAT_MULTI_BASE_BYTES,
    CHAT_MULTI_MAX_RECIPIENTS,
    CHAT_MULTI_IP_BYTES_PER_MIN,
    CHAT_GROUP_CAPABILITY_SENDS_PER_MIN,
    CHAT_GROUP_CAPABILITY_SENDS_PER_DAY,
    CHAT_MULTI_ORIGIN_REQUESTS_PER_MIN,
    CHAT_MULTI_ORIGIN_BYTES_PER_MIN,
];

/// Calendars (docs/plans/calendar.md, E1): how many one account owns, the
/// events one calendar holds, and the changes one events sync carries
/// (Proton's 25, its practical event cap, and its batch of 10).
pub const CALENDARS_PER_ACCOUNT: NumericSetting = NumericSetting {
    key: "calendars_per_account",
    field: "calendarsPerAccount",
    default: 25,
    min: 1,
    max: 1000,
};
pub const CALENDAR_EVENTS_PER_CALENDAR: NumericSetting = NumericSetting {
    key: "calendar_events_per_calendar",
    field: "calendarEventsPerCalendar",
    default: 25_000,
    min: 1,
    max: 1_000_000,
};
pub const CALENDAR_SYNC_BATCH: NumericSetting = NumericSetting {
    key: "calendar_sync_batch",
    field: "calendarSyncBatch",
    default: 10,
    min: 1,
    max: 100,
};
pub const CALENDAR_SETTINGS: [NumericSetting; 3] = [
    CALENDARS_PER_ACCOUNT,
    CALENDAR_EVENTS_PER_CALENDAR,
    CALENDAR_SYNC_BATCH,
];

/// Every whole-number setting `/api/admin/settings` lists by field.
pub fn numeric_settings() -> impl Iterator<Item = &'static NumericSetting> {
    CHAT_MULTI_SETTINGS.iter().chain(CALENDAR_SETTINGS.iter())
}

/// The multi-recipient limits now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiLimits {
    pub max_message_bytes: i64,
    pub base_bytes: i64,
    pub max_recipients: i64,
    pub ip_bytes_per_min: i64,
    pub capability_sends_per_min: i64,
    pub capability_sends_per_day: i64,
    pub origin_requests_per_min: i64,
    pub origin_bytes_per_min: i64,
}

pub async fn chat_multi_limits(pool: &PgPool) -> Result<MultiLimits, sqlx::Error> {
    Ok(MultiLimits {
        max_message_bytes: CHAT_MULTI_MAX_MESSAGE_BYTES.load(pool).await?,
        base_bytes: CHAT_MULTI_BASE_BYTES.load(pool).await?,
        max_recipients: CHAT_MULTI_MAX_RECIPIENTS.load(pool).await?,
        ip_bytes_per_min: CHAT_MULTI_IP_BYTES_PER_MIN.load(pool).await?,
        capability_sends_per_min: CHAT_GROUP_CAPABILITY_SENDS_PER_MIN.load(pool).await?,
        capability_sends_per_day: CHAT_GROUP_CAPABILITY_SENDS_PER_DAY.load(pool).await?,
        origin_requests_per_min: CHAT_MULTI_ORIGIN_REQUESTS_PER_MIN.load(pool).await?,
        origin_bytes_per_min: CHAT_MULTI_ORIGIN_BYTES_PER_MIN.load(pool).await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_holds_keep_receiving_within_the_hold() {
        assert_eq!(validate_name_holds(180, 90), Ok((180, 90)));
        assert_eq!(validate_name_holds(30, 0), Ok((30, 0)));
        assert!(validate_name_holds(29, 0).is_err());
        assert!(validate_name_holds(180, 181).is_err());
        assert!(validate_name_holds(3651, 90).is_err());
    }

    #[test]
    fn group_avatar_limits_hold_together() {
        let ok = AvatarLimits::DEFAULT;
        assert_eq!(ok.validate(), Ok(ok));
        for length in [8_233, 16_425, 32_809, 41_001] {
            let limits = AvatarLimits {
                max_bytes: length,
                storage_bytes: 2 * length,
                ..ok
            };
            assert_eq!(limits.validate(), Ok(limits));
        }
        let bad = |change: fn(&mut AvatarLimits)| {
            let mut limits = ok;
            change(&mut limits);
            limits.validate().is_err()
        };
        assert!(bad(|l| l.max_bytes = 40_000));
        // Room for a swap: twice the largest.
        assert!(bad(|l| l.storage_bytes = 41_001 + 8_233));
        assert!(bad(
            |l| l.storage_bytes = AvatarLimits::MAX_STORAGE_BYTES + 1
        ));
        assert!(bad(|l| l.pending_seconds = 59));
        assert!(bad(|l| l.pending_seconds = 7 * 24 * 3600 + 1));
        let small = AvatarLimits {
            max_bytes: 8_233,
            storage_bytes: 16_466,
            pending_seconds: 60,
        };
        assert_eq!(small.validate(), Ok(small));
    }

    #[test]
    fn group_capabilities_per_account_are_bounded() {
        assert_eq!(validate_chat_group_capabilities_per_account(1), Ok(1));
        assert_eq!(
            validate_chat_group_capabilities_per_account(
                DEFAULT_CHAT_GROUP_CAPABILITIES_PER_ACCOUNT
            ),
            Ok(1024)
        );
        assert!(validate_chat_group_capabilities_per_account(0).is_err());
        assert!(validate_chat_group_capabilities_per_account(100_001).is_err());
    }

    #[test]
    fn multi_settings_hold_their_ranges_and_firsts() {
        for &setting in numeric_settings() {
            assert_eq!(
                setting.validate(setting.default),
                Ok(setting.default),
                "{setting:?}"
            );
            assert!(setting.validate(setting.min - 1).is_err());
            assert!(setting.validate(setting.max + 1).is_err());
        }
        let fields: std::collections::BTreeSet<_> = numeric_settings().map(|s| s.field).collect();
        assert_eq!(fields.len(), numeric_settings().count(), "one field each");
    }

    #[test]
    fn link_joins_are_positive_and_bounded() {
        assert_eq!(validate_chat_group_link_joins(1), Ok(1));
        assert_eq!(validate_chat_group_link_joins(120), Ok(120));
        assert_eq!(
            validate_chat_group_link_joins(MAX_LINK_JOINS_PER_MIN),
            Ok(MAX_LINK_JOINS_PER_MIN)
        );
        assert!(validate_chat_group_link_joins(0).is_err());
        assert!(validate_chat_group_link_joins(MAX_LINK_JOINS_PER_MIN + 1).is_err());
    }

    #[test]
    fn delivery_retention_bounds_are_closed() {
        assert_eq!(validate_chat_delivery_retention_days(0), Ok(0));
        assert_eq!(validate_chat_delivery_retention_days(30), Ok(30));
        assert_eq!(
            validate_chat_delivery_retention_days(MAX_CHAT_DELIVERY_RETENTION_DAYS),
            Ok(MAX_CHAT_DELIVERY_RETENTION_DAYS)
        );
        assert!(validate_chat_delivery_retention_days(-1).is_err());
        assert!(
            validate_chat_delivery_retention_days(MAX_CHAT_DELIVERY_RETENTION_DAYS + 1).is_err()
        );
    }
}
