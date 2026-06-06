//! Database pool + migrations — mirrors `backend/db/db.go`.
//!
//! Migrations are the **existing** SQL under `backend/db/migrations/`
//! (`NNN_name.up.sql` / `.down.sql` — sqlx's reversible format), embedded at
//! compile time. The schema is the E2EE contract and is kept unchanged.

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
    sqlx::migrate!("../../backend/db/migrations")
        .run(pool)
        .await
        .context("migrate up")?;
    Ok(())
}
