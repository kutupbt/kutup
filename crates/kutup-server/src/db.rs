//! Database pool + migrations — mirrors the Go `backend/db/db.go`.
//!
//! Migrations live in `crates/kutup-server/migrations/` (`NNN_name.up.sql` / `.down.sql` —
//! sqlx's reversible format), embedded at compile time. They are the original schema carried
//! over from the Go backend unchanged — the schema is the E2EE contract.

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Connects to Postgres and verifies the connection. Mirrors `Connect`.
pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(database_url)
        .await
        .context("connect pool")?;
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .context("ping db")?;
    Ok(pool)
}

/// Runs all pending migrations. Mirrors `Migrate`.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!().run(pool).await.context("migrate up")?;
    Ok(())
}

/// The schema a fork's own tables live in (docs/plans/w7-schema.md §14): the
/// core's baseline holds only core tables.
pub const ENTERPRISE_SCHEMA: &str = "enterprise";

/// Runs a fork's own migrations (`ENTERPRISE_MIGRATIONS`, a directory in
/// sqlx's format) after the core's: in the schema [`ENTERPRISE_SCHEMA`],
/// created if missing, with their own migrations table
/// (`enterprise._sqlx_migrations`), so the core's chain and the fork's never
/// meet. In them an unqualified name is the fork's (`enterprise` is the whole
/// search path); a core table is named with its schema (`public.accounts`).
pub async fn migrate_enterprise(pool: &PgPool, dir: &std::path::Path) -> Result<()> {
    migrate_schema(pool, dir, ENTERPRISE_SCHEMA).await
}

/// [`migrate_enterprise`] into `schema`.
async fn migrate_schema(pool: &PgPool, dir: &std::path::Path, schema: &str) -> Result<()> {
    let migrator = sqlx::migrate::Migrator::new(dir)
        .await
        .with_context(|| format!("read the migrations in {}", dir.display()))?;
    let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
    // Its own connection, closed after: the search path it sets goes with it.
    let mut conn = pool.acquire().await?.detach();
    let run = async {
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {quoted}"))
            .execute(&mut conn)
            .await
            .with_context(|| format!("create the schema {schema}"))?;
        sqlx::query(&format!("SET search_path TO {quoted}"))
            .execute(&mut conn)
            .await?;
        migrator
            .run(&mut conn)
            .await
            .with_context(|| format!("migrate up {schema}"))
    }
    .await;
    let _ = sqlx::Connection::close(conn).await;
    run
}

/// The tables the server may only add to (docs/plans/server-personal-data.md,
/// A8): no UPDATE or DELETE for the app role. The security events keep one
/// updatable column, a failure's `count`.
const APPEND_ONLY: &[&str] = &[
    "account_security_events",
    "admin_audit_log",
    "account_keys.destruction_events",
    "document_acknowledgements",
    "consents",
    "legal_documents",
];

/// As the owner (`owner`): gives the app role named in `app_url` what it
/// needs on every table, then takes UPDATE and DELETE back on the append-only
/// ones. Runs at each start after the migrations, so new tables are covered.
/// Foreign-key cascades still delete an account's events: Postgres runs them
/// as the table's owner.
pub async fn grant_app_role(owner: &PgPool, app_url: &str) -> Result<()> {
    use std::str::FromStr as _;
    let app = sqlx::postgres::PgConnectOptions::from_str(app_url)
        .context("DATABASE_URL")?
        .get_username()
        .to_owned();
    let owner_name: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(owner)
        .await
        .context("the owner role's name")?;
    anyhow::ensure!(
        app != owner_name,
        "DATABASE_OWNER_URL names the same role as DATABASE_URL ({app}): the server's own \
         role must be another one (docs/self-hosting.md, \"Database roles\")"
    );
    // A role that is a superuser, a member of the owner, or owns tables would
    // get around the grants: the logs would not be append-only for it.
    let (superuser, member, owns): (bool, bool, i64) = sqlx::query_as(
        "SELECT r.rolsuper,
                pg_has_role(r.rolname, current_user, 'MEMBER'),
                (SELECT count(*) FROM pg_tables
                  WHERE tableowner = r.rolname
                    AND schemaname IN ('public', 'account_keys', 'enterprise'))
           FROM pg_roles r WHERE r.rolname = $1",
    )
    .bind(&app)
    .fetch_optional(owner)
    .await
    .context("the server's role")?
    .with_context(|| format!("the database has no role {app} (DATABASE_URL)"))?;
    anyhow::ensure!(
        !superuser && !member && owns == 0,
        "the server's role {app} (DATABASE_URL) {}: the logs would not be append-only for it \
         (docs/self-hosting.md, \"Database roles\")",
        if superuser {
            "is a superuser"
        } else if member {
            "is a member of the owner role"
        } else {
            "owns tables"
        }
    );
    grant_role(owner, &app).await
}

/// [`grant_app_role`] for the role named `app`.
async fn grant_role(owner: &PgPool, app: &str) -> Result<()> {
    let role = format!("\"{}\"", app.replace('"', "\"\""));
    let mut statements = vec![
        format!("GRANT USAGE ON SCHEMA public, account_keys TO {role}"),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public, account_keys TO {role}"
        ),
        format!("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {role}"),
    ];
    // A fork's own tables, where its migrations made them.
    let enterprise: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)")
            .bind(ENTERPRISE_SCHEMA)
            .fetch_one(owner)
            .await
            .context("look for the enterprise schema")?;
    if enterprise {
        statements.extend([
            format!("GRANT USAGE ON SCHEMA {ENTERPRISE_SCHEMA} TO {role}"),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {ENTERPRISE_SCHEMA} TO {role}"
            ),
            format!(
                "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {ENTERPRISE_SCHEMA} TO {role}"
            ),
        ]);
    }
    for table in APPEND_ONLY {
        statements.push(format!(
            "REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM {role}"
        ));
    }
    statements.push(format!(
        "GRANT UPDATE (count) ON account_security_events TO {role}"
    ));
    // The admin log's ids are the chain's order: the server takes them from
    // the sequence, never names one, and never moves the sequence back.
    statements.push(format!("REVOKE INSERT ON admin_audit_log FROM {role}"));
    statements.push(format!(
        "GRANT INSERT (kind, actor_kind, actor_account_id, subject_account_id, at, payload, \
         count, chain_version, previous_hash, row_hash) ON admin_audit_log TO {role}"
    ));
    let sequence: Option<String> =
        sqlx::query_scalar("SELECT pg_get_serial_sequence('admin_audit_log', 'id')")
            .fetch_one(owner)
            .await
            .context("the admin log's sequence")?;
    if let Some(sequence) = sequence {
        statements.push(format!("REVOKE UPDATE ON SEQUENCE {sequence} FROM {role}"));
    }
    // Where retention cut the chain: the owner's alone.
    statements.push(format!(
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON admin_audit_anchor FROM {role}"
    ));
    let mut tx = owner.begin().await?;
    for statement in statements {
        sqlx::query(&statement)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("grant the app role: {statement}"))?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As a role granted the server's rights: the logs take inserts and a
    /// failure's count, nothing else; other tables stay writable.
    #[tokio::test]
    async fn live_the_logs_are_append_only_for_the_app_role() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let owner = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        migrate(&owner).await.unwrap();
        sqlx::query(
            "DO $$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kutup_append_test') THEN
                 CREATE ROLE kutup_append_test NOLOGIN;
               END IF;
             END $$",
        )
        .execute(&owner)
        .await
        .unwrap();
        grant_role(&owner, "kutup_append_test").await.unwrap();
        let mut tx = owner.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE kutup_append_test")
            .execute(&mut *tx)
            .await
            .unwrap();
        for statement in [
            "DELETE FROM account_security_events",
            "UPDATE account_security_events SET kind = 'signIn'",
            "DELETE FROM admin_audit_log",
            "UPDATE admin_audit_log SET kind = 'x'",
            "TRUNCATE admin_audit_log",
            "DELETE FROM account_keys.destruction_events",
            "UPDATE account_keys.destruction_events SET reference = 'x'",
            "DELETE FROM consents",
            "UPDATE consents SET given = true",
            "DELETE FROM document_acknowledgements",
            "UPDATE legal_documents SET url = 'x'",
            "INSERT INTO admin_audit_log (id, kind, actor_kind, payload) \
             VALUES (9223372036854775000, 'x', 'job', '{}')",
            "SELECT setval(pg_get_serial_sequence('admin_audit_log', 'id'), 1)",
            "INSERT INTO admin_audit_anchor (through_id, through_hash) VALUES (1, sha256('x'))",
            "UPDATE admin_audit_anchor SET through_id = 1",
        ] {
            sqlx::query("SAVEPOINT attempt")
                .execute(&mut *tx)
                .await
                .unwrap();
            let error = sqlx::query(statement).execute(&mut *tx).await.unwrap_err();
            assert!(
                error.to_string().contains("permission denied"),
                "{statement}: {error}"
            );
            sqlx::query("ROLLBACK TO SAVEPOINT attempt")
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        // A failure's count, inserts, and every other table: allowed.
        sqlx::query("UPDATE account_security_events SET count = count WHERE false")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT count(*) FROM admin_audit_log")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE false")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM account_keys.account_data_keys WHERE false")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }

    /// A fork's migrations: an empty set makes the schema `enterprise` and
    /// its own migrations table, and nothing else; one migration makes its
    /// table there, never in `public`, recorded in that schema's table, not
    /// the core's; run again, nothing changes.
    #[tokio::test]
    async fn live_enterprise_migrations_run_in_their_own_schema() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        migrate(&pool).await.unwrap();
        let core: i64 = sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();

        let empty = tempfile::tempdir().unwrap();
        migrate_enterprise(&pool, empty.path()).await.unwrap();
        let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM enterprise._sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(recorded, 0);

        // One migration, in a schema of its own for the test (the real
        // `enterprise` keeps only the empty set, so a rerun on this database
        // never finds a migration it lacks).
        let schema = format!(
            "enterprise_test_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("20990101000000_widgets.up.sql"),
            // A core table is named with its schema. (No foreign key to it
            // here: dropping the test's schema would then lock `accounts`
            // against the tests running beside it.)
            "CREATE TABLE widgets (id bigint PRIMARY KEY, account_id uuid);
             SELECT count(*) FROM public.accounts;",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("20990101000000_widgets.down.sql"),
            "DROP TABLE widgets;",
        )
        .unwrap();
        for _ in 0..2 {
            migrate_schema(&pool, dir.path(), &schema).await.unwrap();
        }
        let (in_schema, in_public): (bool, bool) = sqlx::query_as(
            "SELECT to_regclass($1 || '.widgets') IS NOT NULL, to_regclass('public.widgets') IS NOT NULL",
        )
        .bind(&schema)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(in_schema && !in_public);
        let versions: Vec<i64> = sqlx::query_scalar(&format!(
            "SELECT version FROM \"{schema}\"._sqlx_migrations"
        ))
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(versions, vec![20990101000000]);
        let core_after: i64 = sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(core_after, core, "the core's chain is untouched");
        // The pool's connections kept the default search path.
        let path: String = sqlx::query_scalar("SHOW search_path")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!path.contains("enterprise"), "{path}");
        sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
    }
}
