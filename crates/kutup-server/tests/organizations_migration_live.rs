//! The organizations migration (`20261027170000`,
//! docs/plans/organizations.md, O1) on a database with custom domains: it is
//! migrated to the one before and given an account holding two domains with
//! an administrator's limits, and another with only an address limit; then
//! migrated on. Each holder must own one organization of one with its
//! domains, and every limit must land where it now belongs.
//!
//! Needs `KUTUP_TEST_DB`: a database whose server it may make a disposable
//! database on (`organizations_migration`, dropped first).

use std::borrow::Cow;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

const ORGANIZATIONS_MIGRATION: i64 = 20261027170000;

async fn user(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (username, master_key_envelope, recovery_key_envelope, public_key,
                            account_authority_public_key, account_authority_key_id,
                            account_incarnation_id, drive_signing_public_key)
         VALUES ($1, '', '', '', '', '', '', '') RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn holders_become_owners_of_organizations_of_one() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        eprintln!("KUTUP_TEST_DB unset; skipping");
        return;
    };
    // A database of its own, so the migrations run from the start.
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::query("DROP DATABASE IF EXISTS organizations_migration")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("CREATE DATABASE organizations_migration")
        .execute(&admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&database_url).unwrap();
    url.set_path("/organizations_migration");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(url.as_str())
        .await
        .unwrap();

    let all = sqlx::migrate!("./migrations");
    let mut before = sqlx::migrate!("./migrations");
    before.migrations = Cow::Owned(
        all.migrations
            .iter()
            .filter(|migration| migration.version < ORGANIZATIONS_MIGRATION)
            .cloned()
            .collect(),
    );
    before.run(&pool).await.unwrap();

    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    for name in ["a.example", "b.example"] {
        sqlx::query(
            "INSERT INTO mail_domains (user_id, name, verify_code)
             VALUES ($1, $2, 'kutup-verification=abcdefghijklmnopqrstuvwxyz')",
        )
        .bind(alice)
        .bind(name)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO mail_domain_overrides (user_id, max_domains, max_addresses, catch_all)
         VALUES ($1, 7, 20, false), ($2, NULL, 30, NULL)",
    )
    .bind(alice)
    .bind(bob)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO site_settings (key, value) VALUES ('mail_domains.per_account', '5')")
        .execute(&pool)
        .await
        .unwrap();

    all.run(&pool).await.unwrap();

    // Alice owns one organization, named after her, holding both domains.
    let organizations: Vec<(Uuid, String, String, i16)> = sqlx::query_as(
        "SELECT o.id, o.name, m.role, m.state FROM organizations o
           JOIN organization_members m ON m.organization_id = o.id
          WHERE m.account_id = $1",
    )
    .bind(alice)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(organizations.len(), 1, "one organization per holder");
    let (organization, name, role, state) = organizations[0].clone();
    assert_eq!((name.as_str(), role.as_str(), state), ("alice", "owner", 1));
    let domains: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mail_domains WHERE organization_id = $1")
            .bind(organization)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(domains, 2);
    // Bob held no domain: no organization.
    let bobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM organization_members WHERE account_id = $1")
            .bind(bob)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bobs, 0);

    // The limits: domains and the catch-all on the organization, the
    // address counts on each account, the site's key renamed.
    let mut org_limits: Vec<(String, i64)> = sqlx::query_as(
        "SELECT key, value FROM organization_setting_overrides WHERE organization_id = $1",
    )
    .bind(organization)
    .fetch_all(&pool)
    .await
    .unwrap();
    org_limits.sort();
    assert_eq!(
        org_limits,
        [
            ("mail_domains.catch_all".to_owned(), 0),
            ("mail_domains.per_organization".to_owned(), 7)
        ]
    );
    for (account, expected) in [(alice, 20_i64), (bob, 30)] {
        let value: i64 = sqlx::query_scalar(
            "SELECT value FROM user_setting_overrides
              WHERE user_id = $1 AND key = 'mail_domains.addresses_per_account'",
        )
        .bind(account)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(value, expected);
    }
    let site: Option<String> = sqlx::query_scalar(
        "SELECT value FROM site_settings WHERE key = 'mail_domains.per_organization'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(site.as_deref(), Some("5"));
    pool.close().await;
    sqlx::query("DROP DATABASE organizations_migration")
        .execute(&admin)
        .await
        .unwrap();
}
