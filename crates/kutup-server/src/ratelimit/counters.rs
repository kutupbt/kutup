//! Rate counters kept in the database (`rate_counters`): budgets every
//! server process must share, counted per fixed window of a scope and a
//! subject. The subject is always a 32-byte digest under the scope's own
//! label (a capability's hash, a recipient's or an origin's blinded id), so
//! the table holds no identity in the clear.
//!
//! [`Scope`] is the list of scopes (the table has no CHECK on it); its
//! stored value is `<area>.<kind>`. A row lives until two of its windows
//! have passed (`expires_at`); [`sweep`] deletes the expired ones.

use crate::error::AppResult;

/// What a counter counts. The stored value is [`Scope::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Sealed sender: bundle fetches per delivery capability.
    AnonymousCapabilityBundle,
    /// Sealed sender: sends per delivery capability and minute.
    AnonymousCapabilityMinute,
    /// Sealed sender: sends per delivery capability and day.
    AnonymousCapabilityDay,
    /// Sealed sender: sends per recipient.
    AnonymousRecipient,
    /// Sealed sender: sends per federated origin server.
    AnonymousFederationOrigin,
    /// Anonymous multi-recipient sends: bytes per client address and minute.
    AnonymousIpBytes,
    /// Multi-recipient sends from another server: requests per origin.
    AnonymousOriginMultiRequests,
    /// Multi-recipient sends from another server: bytes per origin.
    AnonymousOriginMultiBytes,
    /// Group send endorsements issued per account and day.
    AnonymousGroupSendIssue,
    /// Endorsement uploads per member and group and day.
    AnonymousGroupEndorsementUpload,
    /// Multi-recipient sends per group send token.
    AnonymousGroupSendToken,
    /// Multi-recipient sends per recipient.
    AnonymousMultiRecipient,
    /// Chat media: deliveries per capability and minute.
    MediaCapabilityMinute,
    /// Chat media: deliveries per capability and day.
    MediaCapabilityDay,
    /// Chat media: deliveries per recipient.
    MediaRecipient,
    /// Chat media: deliveries per federated origin server.
    MediaFederationOrigin,
    /// Wrong passwords per public link and address (`crate::link_password`).
    DriveLinkPassword,
}

impl Scope {
    /// Every scope (the tests' list).
    #[cfg(test)]
    pub const ALL: [Self; 17] = [
        Self::AnonymousCapabilityBundle,
        Self::AnonymousCapabilityMinute,
        Self::AnonymousCapabilityDay,
        Self::AnonymousRecipient,
        Self::AnonymousFederationOrigin,
        Self::AnonymousIpBytes,
        Self::AnonymousOriginMultiRequests,
        Self::AnonymousOriginMultiBytes,
        Self::AnonymousGroupSendIssue,
        Self::AnonymousGroupEndorsementUpload,
        Self::AnonymousGroupSendToken,
        Self::AnonymousMultiRecipient,
        Self::MediaCapabilityMinute,
        Self::MediaCapabilityDay,
        Self::MediaRecipient,
        Self::MediaFederationOrigin,
        Self::DriveLinkPassword,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnonymousCapabilityBundle => "chat.anonymous.capabilityBundle",
            Self::AnonymousCapabilityMinute => "chat.anonymous.capabilityMinute",
            Self::AnonymousCapabilityDay => "chat.anonymous.capabilityDay",
            Self::AnonymousRecipient => "chat.anonymous.recipient",
            Self::AnonymousFederationOrigin => "chat.anonymous.federationOrigin",
            Self::AnonymousIpBytes => "chat.anonymous.ipBytes",
            Self::AnonymousOriginMultiRequests => "chat.anonymous.originMultiRequests",
            Self::AnonymousOriginMultiBytes => "chat.anonymous.originMultiBytes",
            Self::AnonymousGroupSendIssue => "chat.anonymous.groupSendIssue",
            Self::AnonymousGroupEndorsementUpload => "chat.anonymous.groupEndorsementUpload",
            Self::AnonymousGroupSendToken => "chat.anonymous.groupSendToken",
            Self::AnonymousMultiRecipient => "chat.anonymous.multiRecipient",
            Self::MediaCapabilityMinute => "chat.media.capabilityMinute",
            Self::MediaCapabilityDay => "chat.media.capabilityDay",
            Self::MediaRecipient => "chat.media.recipient",
            Self::MediaFederationOrigin => "chat.media.federationOrigin",
            Self::DriveLinkPassword => "drive.linkPassword.linkAndAddress",
        }
    }
}

/// Adds `amount` to the subject's count in the scope's current window of
/// `window_seconds` and returns the new count. In the caller's transaction,
/// so a refused request's count can be rolled back with it where it should.
pub async fn add(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: Scope,
    subject: &[u8; 32],
    amount: i64,
    window_seconds: i64,
) -> AppResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO rate_counters (scope, subject, window_start, count, expires_at)
         VALUES (
             $1, $2,
             to_timestamp(floor(extract(epoch FROM now()) / $3) * $3),
             $4,
             to_timestamp(floor(extract(epoch FROM now()) / $3) * $3) + make_interval(secs => $3 * 2)
         )
         ON CONFLICT (scope, subject, window_start)
         DO UPDATE SET count = rate_counters.count + $4
         RETURNING count",
    )
    .bind(scope.as_str())
    .bind(subject.as_slice())
    .bind(window_seconds)
    .bind(amount)
    .fetch_one(&mut **tx)
    .await?)
}

/// Gives back one count reserved in the current window of `window_seconds`
/// (a try that turned out right). Nothing when the window has turned since:
/// the new one started from nothing.
pub async fn give_back(
    pool: &sqlx::PgPool,
    scope: Scope,
    subject: &[u8; 32],
    window_seconds: i64,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE rate_counters SET count = count - 1
          WHERE scope = $1 AND subject = $2 AND count > 0
            AND window_start = to_timestamp(floor(extract(epoch FROM now()) / $3) * $3)",
    )
    .bind(scope.as_str())
    .bind(subject.as_slice())
    .bind(window_seconds)
    .execute(pool)
    .await?;
    Ok(())
}

/// The subject's count in the scope's current window of `window_seconds`
/// (0 when none), and the seconds until that window ends. A read: nothing
/// is reserved.
pub async fn current(
    pool: &sqlx::PgPool,
    scope: Scope,
    subject: &[u8; 32],
    window_seconds: i64,
) -> AppResult<(i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT COALESCE((SELECT count FROM rate_counters
                           WHERE scope = $1 AND subject = $2
                             AND window_start = to_timestamp(floor(extract(epoch FROM now()) / $3) * $3)), 0),
                GREATEST(1, ceil($3 - (extract(epoch FROM now()) - floor(extract(epoch FROM now()) / $3) * $3)))::bigint",
    )
    .bind(scope.as_str())
    .bind(subject.as_slice())
    .bind(window_seconds)
    .fetch_one(pool)
    .await?)
}

/// Deletes the counters whose windows are over; the rows deleted.
pub async fn sweep(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM rate_counters WHERE expires_at <= now()")
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

#[cfg(test)]
mod tests {
    use super::Scope;

    #[test]
    fn scopes_are_namespaced_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for scope in Scope::ALL {
            let value = scope.as_str();
            let (area, kind) = value.rsplit_once('.').expect("<area>.<kind>");
            assert!(
                crate::site_settings::NAMESPACES.contains(&area.split('.').next().unwrap()),
                "{value}"
            );
            assert!(kind.chars().next().unwrap().is_ascii_lowercase(), "{value}");
            assert!(kind.chars().all(|c| c.is_ascii_alphanumeric()), "{value}");
            assert!(seen.insert(value), "{value} twice");
        }
    }
}
