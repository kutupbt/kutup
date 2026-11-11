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

/// The tables the server may only add to (docs/plans/server-personal-data.md,
/// A8): no UPDATE or DELETE for the app role. The security events keep one
/// updatable column, a failure's `count`.
const APPEND_ONLY: &[&str] = &["account_security_events", "admin_audit_log"];

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
        "GRANT INSERT (admin_user_id, action, target_user_id, payload, occurred_at, \
         previous_hash, row_hash, chain_version) ON admin_audit_log TO {role}"
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
            "UPDATE admin_audit_log SET action = 'x'",
            "TRUNCATE admin_audit_log",
            "INSERT INTO admin_audit_log (id, admin_user_id, action, payload) \
             VALUES (9223372036854775000, gen_random_uuid(), 'x', '{}')",
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
        sqlx::query("UPDATE users SET updated_at = updated_at WHERE false")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM account_keys.account_data_keys WHERE false")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }
}
