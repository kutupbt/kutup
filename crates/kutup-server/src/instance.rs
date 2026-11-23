//! The server instance id (docs/plans/api-surface.md §5): 16 random bytes
//! minted the first time the server starts on an empty database, never
//! changed by the server afterwards. It names this database's lifetime: a
//! restore keeps it (backups carry the row), a wipe changes it. Clients
//! store it and, when they see another one, drop their local state for this
//! origin, keeping only their anti-rollback anchors.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use sqlx::{PgConnection, PgPool};

use crate::AppState;

/// The header every `/api/` answer carries the id in.
pub const INSTANCE_HEADER: &str = "x-kutup-instance";

/// Reads the instance id, minting it first when the database has none.
/// Base64url without padding, 22 characters.
pub async fn load_or_mint(conn: &mut PgConnection) -> Result<String, sqlx::Error> {
    let mut fresh = [0u8; 16];
    kutup_crypto::primitives::random(&mut fresh);
    sqlx::query("INSERT INTO server_instance (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(fresh.as_slice())
        .execute(&mut *conn)
        .await?;
    let id: Vec<u8> = sqlx::query_scalar("SELECT id FROM server_instance")
        .fetch_one(&mut *conn)
        .await?;
    Ok(encode(&id))
}

fn encode(id: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id)
}

/// `kutup-server reset-instance-id`: a new id on purpose, so every client
/// drops what it keeps for this server. Refused while any account exists:
/// with accounts, clients would forget a server that still holds their
/// data.
pub async fn reset(pool: &PgPool) -> anyhow::Result<String> {
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(pool)
        .await?;
    if accounts > 0 {
        anyhow::bail!(
            "refused: {accounts} account(s) exist; the instance id changes only on an empty server"
        );
    }
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM server_instance")
        .execute(&mut *tx)
        .await?;
    let id = load_or_mint(&mut tx).await?;
    tx.commit().await?;
    Ok(id)
}

/// Adds [`INSTANCE_HEADER`] to every `/api/` answer.
pub async fn instance_header(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut response = next.run(req).await;
    if api {
        if let Ok(value) = HeaderValue::from_str(&state.instance_id) {
            response.headers_mut().insert(INSTANCE_HEADER, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against a live database (the backup gate's): the id is minted once
    /// and read back by every later start; a database without the row (a
    /// wipe, here inside a rolled-back transaction) gets a new one; and a
    /// reset is refused while accounts exist.
    #[tokio::test]
    async fn live_the_instance_id_is_minted_once() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let first = load_or_mint(&mut conn).await.unwrap();
        assert_eq!(first.len(), 22);
        // A restart reads the same row.
        assert_eq!(load_or_mint(&mut conn).await.unwrap(), first);
        drop(conn);

        // An emptied database mints another.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("DELETE FROM server_instance")
            .execute(&mut *tx)
            .await
            .unwrap();
        let fresh = load_or_mint(&mut tx).await.unwrap();
        assert_ne!(fresh, first);
        tx.rollback().await.unwrap();

        // The gate's server has accounts: no reset.
        let refused = reset(&pool).await.unwrap_err().to_string();
        assert!(refused.contains("refused"), "{refused}");
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(load_or_mint(&mut conn).await.unwrap(), first);
    }
}
