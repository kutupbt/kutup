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
use sqlx::PgPool;

use crate::AppState;

/// The header every `/api/` answer carries the id in.
pub const INSTANCE_HEADER: &str = "x-kutup-instance";

/// Reads the instance id, minting it first when the database has none.
/// Base64url without padding, 22 characters.
pub async fn load_or_mint(pool: &PgPool) -> Result<String, sqlx::Error> {
    let mut fresh = [0u8; 16];
    kutup_crypto::primitives::random(&mut fresh);
    sqlx::query("INSERT INTO server_instance (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(fresh.as_slice())
        .execute(pool)
        .await?;
    let id: Vec<u8> = sqlx::query_scalar("SELECT id FROM server_instance")
        .fetch_one(pool)
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
    sqlx::query("DELETE FROM server_instance")
        .execute(pool)
        .await?;
    Ok(load_or_mint(pool).await?)
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
