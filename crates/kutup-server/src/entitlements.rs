//! Entitlements (docs/plans/w7-schema.md §5): what one account, or one
//! organization, has beyond the site's settings: its own value of a setting
//! that limits one account (`account_entitlements`), or one organization
//! (`organization_entitlements`), keyed as the setting is, with where the
//! value came from.
//!
//! A value in effect is the account's (or organization's) own, else the
//! site's, else the setting's first value (`NumericSetting::load_for`); a
//! value outside the setting's range is passed over. Usage counters
//! (`accounts.storage_used_bytes`) are not entitlements.
//!
//! Besides the registry's settings and the per-account rate limits
//! (`rate_limit.<key>`), the keys are:
//! - [`STORAGE_QUOTA`]: the account's storage pool (`crate::storage_pool`);
//! - [`PUBLIC_SHARING`]: whether it may share by public link, 0 or 1
//!   (`crate::public_sharing`);
//! - [`FEDERATION`]: whether it talks to other servers, 0 or 1
//!   (`crate::federation_switch`; the SQL function `kutup_account_federates`
//!   reads it).

use std::collections::HashMap;

use uuid::Uuid;

/// An account's storage quota, in bytes; without it the site's
/// `default_storage_quota_bytes` applies.
pub const STORAGE_QUOTA: &str = "account.storage_quota_bytes";

/// Whether an account may make and serve public links (1) or not (0);
/// without it, the site's switch alone decides.
pub const PUBLIC_SHARING: &str = "drive.public_sharing";

/// Whether an account talks to other servers (1) or not (0); without it,
/// the site's `federation_default`.
pub const FEDERATION: &str = "server.federation";

/// Where an entitlement came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// An administrator set it (or the administrators' default, written when
    /// the account was made).
    Admin,
    /// The account's plan (billing, not built yet, writes only these).
    #[allow(dead_code)]
    Plan,
    /// The account's organization (nothing grants from one yet).
    #[allow(dead_code)]
    Organization,
    /// The account holder's own choice (its federation switch).
    Account,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Plan => "plan",
            Self::Organization => "organization",
            Self::Account => "account",
        }
    }
}

/// Whose entitlement: an account's or an organization's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    Account(Uuid),
    Organization(Uuid),
}

impl Holder {
    fn id(self) -> Uuid {
        match self {
            Self::Account(id) | Self::Organization(id) => id,
        }
    }
}

/// One entitlement's value, if the holder has it.
pub async fn get<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    holder: Holder,
    key: &str,
) -> sqlx::Result<Option<i64>> {
    let sql = match holder {
        Holder::Account(_) => {
            "SELECT value FROM account_entitlements WHERE account_id = $1 AND key = $2"
        }
        Holder::Organization(_) => {
            "SELECT value FROM organization_entitlements WHERE organization_id = $1 AND key = $2"
        }
    };
    sqlx::query_scalar(sql)
        .bind(holder.id())
        .bind(key)
        .fetch_optional(executor)
        .await
}

/// The holder's entitlements among `keys`, by key.
pub async fn some<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    holder: Holder,
    keys: &[&str],
) -> sqlx::Result<HashMap<String, i64>> {
    let sql = match holder {
        Holder::Account(_) => {
            "SELECT key, value FROM account_entitlements WHERE account_id = $1 AND key = ANY($2)"
        }
        Holder::Organization(_) => {
            "SELECT key, value FROM organization_entitlements
              WHERE organization_id = $1 AND key = ANY($2)"
        }
    };
    Ok(sqlx::query_as::<_, (String, i64)>(sql)
        .bind(holder.id())
        .bind(keys)
        .fetch_all(executor)
        .await?
        .into_iter()
        .collect())
}

/// Every entitlement the holder has, by key.
pub async fn all<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    holder: Holder,
) -> sqlx::Result<HashMap<String, i64>> {
    let sql = match holder {
        Holder::Account(_) => "SELECT key, value FROM account_entitlements WHERE account_id = $1",
        Holder::Organization(_) => {
            "SELECT key, value FROM organization_entitlements WHERE organization_id = $1"
        }
    };
    Ok(sqlx::query_as::<_, (String, i64)>(sql)
        .bind(holder.id())
        .fetch_all(executor)
        .await?
        .into_iter()
        .collect())
}

/// Gives the holder `key` = `value` from `source`, replacing what it had.
pub async fn set<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    holder: Holder,
    key: &str,
    value: i64,
    source: Source,
) -> sqlx::Result<()> {
    let sql = match holder {
        Holder::Account(_) => {
            "INSERT INTO account_entitlements (account_id, key, value, source)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (account_id, key) DO UPDATE
                SET value = EXCLUDED.value, source = EXCLUDED.source, updated_at = now()"
        }
        Holder::Organization(_) => {
            "INSERT INTO organization_entitlements (organization_id, key, value, source)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (organization_id, key) DO UPDATE
                SET value = EXCLUDED.value, source = EXCLUDED.source, updated_at = now()"
        }
    };
    sqlx::query(sql)
        .bind(holder.id())
        .bind(key)
        .bind(value)
        .bind(source.as_str())
        .execute(executor)
        .await?;
    Ok(())
}

/// Takes `key` back from the holder: the site's value applies again.
pub async fn clear<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    holder: Holder,
    key: &str,
) -> sqlx::Result<()> {
    let sql = match holder {
        Holder::Account(_) => "DELETE FROM account_entitlements WHERE account_id = $1 AND key = $2",
        Holder::Organization(_) => {
            "DELETE FROM organization_entitlements WHERE organization_id = $1 AND key = $2"
        }
    };
    sqlx::query(sql)
        .bind(holder.id())
        .bind(key)
        .execute(executor)
        .await?;
    Ok(())
}

/// [`set`] for `Some`, [`clear`] for `None`.
pub async fn set_or_clear<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    holder: Holder,
    key: &str,
    value: Option<i64>,
    source: Source,
) -> sqlx::Result<()> {
    match value {
        Some(value) => set(executor, holder, key, value, source).await,
        None => clear(executor, holder, key).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set, read, replaced with its source, cleared; an organization's apart
    /// from an account's.
    #[tokio::test]
    async fn live_an_entitlement_is_set_read_and_cleared() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let account = Uuid::new_v4();
        sqlx::query("INSERT INTO accounts (id, username, identity_suite) VALUES ($1, $2, 2)")
            .bind(account)
            .bind(format!("ent{}", &account.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let holder = Holder::Account(account);
        assert_eq!(get(&pool, holder, STORAGE_QUOTA).await.unwrap(), None);
        set(&pool, holder, STORAGE_QUOTA, 5, Source::Admin)
            .await
            .unwrap();
        set(&pool, holder, STORAGE_QUOTA, 7, Source::Plan)
            .await
            .unwrap();
        assert_eq!(get(&pool, holder, STORAGE_QUOTA).await.unwrap(), Some(7));
        let source: String = sqlx::query_scalar(
            "SELECT source FROM account_entitlements WHERE account_id = $1 AND key = $2",
        )
        .bind(account)
        .bind(STORAGE_QUOTA)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(source, "plan");
        set(&pool, holder, FEDERATION, 0, Source::Account)
            .await
            .unwrap();
        assert_eq!(all(&pool, holder).await.unwrap().len(), 2);
        assert_eq!(
            some(&pool, holder, &[FEDERATION, PUBLIC_SHARING])
                .await
                .unwrap(),
            HashMap::from([(FEDERATION.to_owned(), 0)])
        );
        // No such organization: nothing of the account's shows there.
        assert_eq!(
            get(&pool, Holder::Organization(account), STORAGE_QUOTA)
                .await
                .unwrap(),
            None
        );
        set_or_clear(&pool, holder, STORAGE_QUOTA, None, Source::Admin)
            .await
            .unwrap();
        assert_eq!(get(&pool, holder, STORAGE_QUOTA).await.unwrap(), None);
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
        assert!(all(&pool, holder).await.unwrap().is_empty());
    }
}
