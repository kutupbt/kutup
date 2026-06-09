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
