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

/// The largest `.kdbx` file Kutup Pass takes in an upload (an existing
/// vault brought in from KeePassXC or a backup), set under Administration →
/// Server settings. The browser opens a vault whole, so this bounds what an
/// upload makes it hold; a vault's own saves are never refused by it.
pub const PASS_VAULT_MAX_BYTES: &str = "pass_vault_max_bytes";
pub const PASS_VAULT_MAX_BYTES_DEFAULT: i64 = 64 * 1024 * 1024;

/// 1 MiB to 1 GiB.
pub fn validate_pass_vault_max_bytes(value: i64) -> Result<i64, &'static str> {
    if (1024 * 1024..=1024 * 1024 * 1024).contains(&value) {
        Ok(value)
    } else {
        Err("the largest Pass vault upload must be between 1 MiB and 1 GiB")
    }
}

/// The stored largest Pass vault upload, else its first value.
pub async fn pass_vault_max_bytes(pool: &PgPool) -> Result<i64, sqlx::Error> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
            .bind(PASS_VAULT_MAX_BYTES)
            .fetch_optional(pool)
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| validate_pass_vault_max_bytes(value).ok())
            .unwrap_or(PASS_VAULT_MAX_BYTES_DEFAULT),
    )
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

    /// The stored value, else the first value (on the pool, or in a
    /// transaction).
    pub async fn load<'e, E: sqlx::PgExecutor<'e>>(&self, executor: E) -> Result<i64, sqlx::Error> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT value FROM site_settings WHERE key=$1")
                .bind(self.key)
                .fetch_optional(executor)
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
/// request names, and the bytes one address may send a minute.
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
/// Group send endorsements (docs/plans/group-send-endorsements.md §3.6): the
/// multi-recipient sends one recipient account takes a minute across every
/// sender (the real limit; one over it gets its copy pairwise), and the
/// requests one token may make a minute (weak: it caps replays of one send).
pub const CHAT_MULTI_PER_RECIPIENT_PER_MIN: NumericSetting = NumericSetting {
    key: "chat_multi_per_recipient_per_min",
    field: "chatMultiPerRecipientPerMin",
    default: 1_200,
    min: 1,
    max: 1_000_000,
};
pub const CHAT_MULTI_PER_TOKEN_PER_MIN: NumericSetting = NumericSetting {
    key: "chat_multi_per_token_per_min",
    field: "chatMultiPerTokenPerMin",
    default: 60,
    min: 1,
    max: 100_000,
};
/// Endorsements one account may fetch a day from this server (§3.2; a
/// client needs one a day).
pub const CHAT_GROUP_SEND_ENDORSEMENTS_PER_DAY: NumericSetting = NumericSetting {
    key: "chat_group_send_endorsements_per_day",
    field: "chatGroupSendEndorsementsPerDay",
    default: 48,
    min: 1,
    max: 10_000,
};
/// Blobs one member may upload to one group a day, on the group's home
/// (§3.3; one a day, with room for retries).
pub const CHAT_GROUP_ENDORSEMENT_UPLOADS_PER_DAY: NumericSetting = NumericSetting {
    key: "chat_group_endorsement_uploads_per_day",
    field: "chatGroupEndorsementUploadsPerDay",
    default: 8,
    min: 1,
    max: 1_000,
};
/// The most blobs one endorsement read answers (§3.3); a page must fit one
/// sealed group answer, so at most 200.
pub const CHAT_GROUP_ENDORSEMENT_PAGE_SIZE: NumericSetting = NumericSetting {
    key: "chat_group_endorsement_page_size",
    field: "chatGroupEndorsementPageSize",
    default: 100,
    min: 1,
    max: kutup_chat_proto::group_send::MAX_ENDORSEMENT_PAGE as i64,
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
pub const CHAT_MULTI_SETTINGS: [NumericSetting; 11] = [
    CHAT_MULTI_MAX_MESSAGE_BYTES,
    CHAT_MULTI_BASE_BYTES,
    CHAT_MULTI_MAX_RECIPIENTS,
    CHAT_MULTI_IP_BYTES_PER_MIN,
    CHAT_MULTI_PER_RECIPIENT_PER_MIN,
    CHAT_MULTI_PER_TOKEN_PER_MIN,
    CHAT_MULTI_ORIGIN_REQUESTS_PER_MIN,
    CHAT_MULTI_ORIGIN_BYTES_PER_MIN,
    CHAT_GROUP_SEND_ENDORSEMENTS_PER_DAY,
    CHAT_GROUP_ENDORSEMENT_UPLOADS_PER_DAY,
    CHAT_GROUP_ENDORSEMENT_PAGE_SIZE,
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
/// The largest COUNT a repeating event takes (Proton's 49; the format's
/// 499 is for invitations, E4).
pub const CALENDAR_MAX_COUNT: NumericSetting = NumericSetting {
    key: "calendar_max_count",
    field: "calendarMaxCount",
    default: 49,
    min: 1,
    max: 499,
};
/// Reminders a member's list for one event takes, and for a calendar's
/// defaults (Proton's 10 and 5).
pub const CALENDAR_REMINDERS_PER_EVENT: NumericSetting = NumericSetting {
    key: "calendar_reminders_per_event",
    field: "calendarRemindersPerEvent",
    default: 10,
    min: 1,
    max: 50,
};
pub const CALENDAR_DEFAULT_REMINDERS: NumericSetting = NumericSetting {
    key: "calendar_default_reminders",
    field: "calendarDefaultReminders",
    default: 5,
    min: 1,
    max: 20,
};
/// How late a reminder may still fire, in seconds (Proton's web: a minute);
/// later ones are skipped.
pub const CALENDAR_REMINDER_LATENESS_SECONDS: NumericSetting = NumericSetting {
    key: "calendar_reminder_lateness_seconds",
    field: "calendarReminderLatenessSeconds",
    default: 60,
    min: 10,
    max: 3600,
};
/// How often the reminder job looks for due alarms, in seconds.
pub const CALENDAR_ALARM_TICK_SECONDS: NumericSetting = NumericSetting {
    key: "calendar_alarm_tick_seconds",
    field: "calendarAlarmTickSeconds",
    default: 20,
    min: 5,
    max: 300,
};
/// Due alarms the job takes at once (it takes batches until none is due).
pub const CALENDAR_ALARM_BATCH: NumericSetting = NumericSetting {
    key: "calendar_alarm_batch",
    field: "calendarAlarmBatch",
    default: 200,
    min: 10,
    max: 5000,
};
/// Of one batch, the most one account's alarms take: one account's many
/// never make everyone else's late.
pub const CALENDAR_ALARM_BATCH_PER_ACCOUNT: NumericSetting = NumericSetting {
    key: "calendar_alarm_batch_per_account",
    field: "calendarAlarmBatchPerAccount",
    default: 20,
    min: 1,
    max: 1000,
};
/// Reminder pushes and emails the job sends at the same time.
pub const CALENDAR_ALARM_SENDS: NumericSetting = NumericSetting {
    key: "calendar_alarm_sends",
    field: "calendarAlarmSends",
    default: 16,
    min: 1,
    max: 256,
};
/// The most alarms an account keeps (an event's reminders past it fire
/// nothing until others are gone).
pub const CALENDAR_ALARMS_PER_ACCOUNT: NumericSetting = NumericSetting {
    key: "calendar_alarms_per_account",
    field: "calendarAlarmsPerAccount",
    default: 10_000,
    min: 100,
    max: 1_000_000,
};
/// Browsers one account keeps taking reminder pushes (a new one past it
/// ends the longest-held).
pub const CALENDAR_PUSH_SUBSCRIPTIONS_PER_ACCOUNT: NumericSetting = NumericSetting {
    key: "calendar_push_subscriptions_per_account",
    field: "calendarPushSubscriptionsPerAccount",
    default: 10,
    min: 1,
    max: 100,
};
/// Events whose alarms the job recomputes at once after a member's
/// defaults or zone change.
pub const CALENDAR_RECOMPUTE_BATCH: NumericSetting = NumericSetting {
    key: "calendar_recompute_batch",
    field: "calendarRecomputeBatch",
    default: 500,
    min: 10,
    max: 10_000,
};
/// Alarms one page of `/api/calendar/alarms` answers.
pub const CALENDAR_ALARMS_PAGE: NumericSetting = NumericSetting {
    key: "calendar_alarms_page",
    field: "calendarAlarmsPage",
    default: 100,
    min: 10,
    max: 1000,
};
/// The widest window one events query asks, in days, and the events one
/// page answers.
pub const CALENDAR_WINDOW_DAYS: NumericSetting = NumericSetting {
    key: "calendar_window_days",
    field: "calendarWindowDays",
    default: 400,
    min: 1,
    max: 3660,
};
pub const CALENDAR_EVENTS_PAGE: NumericSetting = NumericSetting {
    key: "calendar_events_page",
    field: "calendarEventsPage",
    default: 1000,
    min: 10,
    max: 5000,
};
pub const CALENDAR_SETTINGS: [NumericSetting; 17] = [
    CALENDARS_PER_ACCOUNT,
    CALENDAR_EVENTS_PER_CALENDAR,
    CALENDAR_SYNC_BATCH,
    CALENDAR_MAX_COUNT,
    CALENDAR_REMINDERS_PER_EVENT,
    CALENDAR_DEFAULT_REMINDERS,
    CALENDAR_REMINDER_LATENESS_SECONDS,
    CALENDAR_ALARM_TICK_SECONDS,
    CALENDAR_ALARM_BATCH,
    CALENDAR_ALARM_BATCH_PER_ACCOUNT,
    CALENDAR_ALARM_SENDS,
    CALENDAR_ALARMS_PER_ACCOUNT,
    CALENDAR_RECOMPUTE_BATCH,
    CALENDAR_PUSH_SUBSCRIPTIONS_PER_ACCOUNT,
    CALENDAR_ALARMS_PAGE,
    CALENDAR_WINDOW_DAYS,
    CALENDAR_EVENTS_PAGE,
];

/// How long a Chat link token, and the provisioning socket of the device
/// it links, stay usable (docs/plans/account-identity-key.md).
pub const CHAT_LINK_TOKEN_SECONDS: NumericSetting = NumericSetting {
    key: "chat_link_token_seconds",
    field: "chatLinkTokenSeconds",
    default: 600,
    min: 60,
    max: 3600,
};
/// Link tokens one account may hold unused at once.
pub const CHAT_LINK_TOKENS_PER_ACCOUNT: NumericSetting = NumericSetting {
    key: "chat_link_tokens_per_account",
    field: "chatLinkTokensPerAccount",
    default: 3,
    min: 1,
    max: 20,
};
/// The largest provisioning message body relayed, in bytes (at most the
/// format's own, `MAX_PROVISION_BODY_BYTES`).
pub const CHAT_PROVISION_BODY_BYTES: NumericSetting = NumericSetting {
    key: "chat_provision_body_bytes",
    field: "chatProvisionBodyBytes",
    default: kutup_chat_proto::MAX_PROVISION_BODY_BYTES as i64,
    min: 4 * 1024,
    max: kutup_chat_proto::MAX_PROVISION_BODY_BYTES as i64,
};
/// Chat installations one account may have (Chat V1's hard cap is 10).
pub const CHAT_MAX_ACTIVE_DEVICES: NumericSetting = NumericSetting {
    key: "chat_max_active_devices",
    field: "chatMaxActiveDevices",
    default: 10,
    min: 1,
    max: 10,
};
/// How long a provisioning socket's ticket stays usable, in seconds.
pub const CHAT_PROVISIONING_TICKET_SECONDS: NumericSetting = NumericSetting {
    key: "chat_provisioning_ticket_seconds",
    field: "chatProvisioningTicketSeconds",
    default: 60,
    min: 10,
    max: 600,
};
/// Provisioning sockets one account may hold open at once.
pub const CHAT_PROVISIONING_SOCKETS_PER_ACCOUNT: NumericSetting = NumericSetting {
    key: "chat_provisioning_sockets_per_account",
    field: "chatProvisioningSocketsPerAccount",
    default: 3,
    min: 1,
    max: 20,
};
/// The largest sync one identity distribution carries to one device, in
/// bytes (its ciphertext).
pub const CHAT_DISTRIBUTION_MESSAGE_BYTES: NumericSetting = NumericSetting {
    key: "chat_distribution_message_bytes",
    field: "chatDistributionMessageBytes",
    default: 64 * 1024,
    min: 1024,
    max: 1024 * 1024,
};
pub const CHAT_IDENTITY_SETTINGS: [NumericSetting; 7] = [
    CHAT_LINK_TOKEN_SECONDS,
    CHAT_LINK_TOKENS_PER_ACCOUNT,
    CHAT_PROVISION_BODY_BYTES,
    CHAT_MAX_ACTIVE_DEVICES,
    CHAT_PROVISIONING_TICKET_SECONDS,
    CHAT_PROVISIONING_SOCKETS_PER_ACCOUNT,
    CHAT_DISTRIBUTION_MESSAGE_BYTES,
];

/// Two-factor sign-in (docs/plans/security-keys.md, D2): how many recovery
/// codes are made at once (Proton's 16).
pub const TWO_FACTOR_RECOVERY_CODES: NumericSetting = NumericSetting {
    key: "two_factor_recovery_codes",
    field: "twoFactorRecoveryCodes",
    default: 16,
    min: 4,
    max: 64,
};
pub const TWO_FACTOR_SETTINGS: [NumericSetting; 1] = [TWO_FACTOR_RECOVERY_CODES];
const KIB: i64 = 1024;
const MIB: i64 = 1024 * KIB;
const GIB: i64 = 1024 * MIB;
const TIB: i64 = 1024 * GIB;

/// Drive's upload limits and streaming (docs/plans/drive-block-format.md §7).
/// The largest file one upload stores, in ciphertext bytes. A block-format
/// object has at most 2^20 blocks of 4 MiB, so 4 TiB is the ceiling.
pub const DRIVE_UPLOAD_MAX_BYTES: NumericSetting = NumericSetting {
    key: "drive_upload_max_bytes",
    field: "driveUploadMaxBytes",
    default: 10 * GIB,
    min: MIB,
    max: 4 * TIB,
};
/// The largest saved version (an editor's snapshot or a new upload of a
/// file), in ciphertext bytes.
pub const DRIVE_VERSION_MAX_BYTES: NumericSetting = NumericSetting {
    key: "drive_version_max_bytes",
    field: "driveVersionMaxBytes",
    default: 2 * GIB,
    min: MIB,
    max: 4 * TIB,
};
/// The largest file a player streams rather than downloads first; 0 never
/// streams. Above the upload limit it changes nothing.
pub const DRIVE_STREAM_MAX_BYTES: NumericSetting = NumericSetting {
    key: "drive_stream_max_bytes",
    field: "driveStreamMaxBytes",
    default: 10 * GIB,
    min: 0,
    max: 4 * TIB,
};
/// Verified blocks one stream keeps (2 on iOS, where the client takes one
/// fewer).
pub const DRIVE_STREAM_CACHE_BLOCKS: NumericSetting = NumericSetting {
    key: "drive_stream_cache_blocks",
    field: "driveStreamCacheBlocks",
    default: 3,
    min: 1,
    max: 16,
};
/// Blocks a stream reads ahead of the one playing.
pub const DRIVE_STREAM_READAHEAD_BLOCKS: NumericSetting = NumericSetting {
    key: "drive_stream_readahead_blocks",
    field: "driveStreamReadaheadBlocks",
    default: 1,
    min: 0,
    max: 4,
};
/// Streams one tab plays at once.
pub const DRIVE_STREAM_MAX_CONCURRENT: NumericSetting = NumericSetting {
    key: "drive_stream_max_concurrent",
    field: "driveStreamMaxConcurrent",
    default: 3,
    min: 1,
    max: 8,
};
/// The most bytes one ranged answer carries, and so the federated part
/// size. The default holds one sealed block (4 MiB and its 40 bytes) whole.
pub const DRIVE_STREAM_RESPONSE_MAX_BYTES: NumericSetting = NumericSetting {
    key: "drive_stream_response_max_bytes",
    field: "driveStreamResponseMaxBytes",
    default: 5 * MIB,
    min: 256 * KIB,
    max: 16 * MIB,
};
/// Without a service worker, the largest file a player loads whole into
/// memory instead.
pub const DRIVE_STREAM_BLOB_FALLBACK_MAX_BYTES: NumericSetting = NumericSetting {
    key: "drive_stream_blob_fallback_max_bytes",
    field: "driveStreamBlobFallbackMaxBytes",
    default: GIB,
    min: 0,
    max: 4 * GIB,
};
pub const DRIVE_SETTINGS: [NumericSetting; 8] = [
    DRIVE_UPLOAD_MAX_BYTES,
    DRIVE_VERSION_MAX_BYTES,
    DRIVE_STREAM_MAX_BYTES,
    DRIVE_STREAM_CACHE_BLOCKS,
    DRIVE_STREAM_READAHEAD_BLOCKS,
    DRIVE_STREAM_MAX_CONCURRENT,
    DRIVE_STREAM_RESPONSE_MAX_BYTES,
    DRIVE_STREAM_BLOB_FALLBACK_MAX_BYTES,
];

/// Every whole-number setting `/api/admin/settings` lists by field.
pub fn numeric_settings() -> impl Iterator<Item = &'static NumericSetting> {
    CHAT_MULTI_SETTINGS
        .iter()
        .chain(CALENDAR_SETTINGS.iter())
        .chain(CHAT_IDENTITY_SETTINGS.iter())
        .chain(TWO_FACTOR_SETTINGS.iter())
        .chain(DRIVE_SETTINGS.iter())
}

/// The multi-recipient limits now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiLimits {
    pub max_message_bytes: i64,
    pub base_bytes: i64,
    pub max_recipients: i64,
    pub ip_bytes_per_min: i64,
    pub per_recipient_per_min: i64,
    pub per_token_per_min: i64,
    pub origin_requests_per_min: i64,
    pub origin_bytes_per_min: i64,
}

pub async fn chat_multi_limits(pool: &PgPool) -> Result<MultiLimits, sqlx::Error> {
    Ok(MultiLimits {
        max_message_bytes: CHAT_MULTI_MAX_MESSAGE_BYTES.load(pool).await?,
        base_bytes: CHAT_MULTI_BASE_BYTES.load(pool).await?,
        max_recipients: CHAT_MULTI_MAX_RECIPIENTS.load(pool).await?,
        ip_bytes_per_min: CHAT_MULTI_IP_BYTES_PER_MIN.load(pool).await?,
        per_recipient_per_min: CHAT_MULTI_PER_RECIPIENT_PER_MIN.load(pool).await?,
        per_token_per_min: CHAT_MULTI_PER_TOKEN_PER_MIN.load(pool).await?,
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
    fn a_pass_vault_upload_limit_stays_within_its_bounds() {
        assert!(validate_pass_vault_max_bytes(PASS_VAULT_MAX_BYTES_DEFAULT).is_ok());
        assert!(validate_pass_vault_max_bytes(1024 * 1024).is_ok());
        assert!(validate_pass_vault_max_bytes(1024 * 1024 - 1).is_err());
        assert!(validate_pass_vault_max_bytes(1024 * 1024 * 1024 + 1).is_err());
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
