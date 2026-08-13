use sqlx::PgPool;

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

#[cfg(test)]
mod tests {
    use super::*;

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
