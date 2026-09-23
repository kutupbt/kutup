//! Server-side sessions and session forking.
//!
//! Design: `docs/plans/multi-app-web-rewrite.md` ("Sessions and forking").
//!
//! - Every sign-in creates an `auth_sessions` row with a client type
//!   (`web-account`, `web-drive`, `web-chat`, `cli`, …). Access tokens carry the
//!   session id (`sid`) and every authenticated request checks the row is
//!   live, so revocation is immediate.
//! - Refresh tokens are opaque 32-byte secrets, stored as SHA-256 and rotated
//!   on every refresh. The previous hash is honoured for
//!   [`REFRESH_GRACE`] (two tabs refreshing with one cookie) by minting an
//!   access token without another rotation; a replay after the window is
//!   treated as theft and revokes the session.
//! - The account web app forks child sessions for drive/chat: it stores an
//!   opaque encrypted payload under a one-time selector (60 s), and the child
//!   origin consumes it. Revoking a parent revokes its children.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// Idle lifetime; every refresh slides it forward.
pub const SESSION_TTL: Duration = Duration::days(30);
/// How long a just-rotated refresh token still yields an access token.
pub const REFRESH_GRACE: Duration = Duration::seconds(60);
/// How long a fork hand-off waits for the child origin.
pub const FORK_TTL: Duration = Duration::seconds(60);
/// Upper bound on a fork payload (a local-state envelope of a few keys).
pub const MAX_FORK_PAYLOAD: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientType {
    WebAccount,
    WebDrive,
    WebChat,
    Cli,
}

impl ClientType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebAccount => "web-account",
            Self::WebDrive => "web-drive",
            Self::WebChat => "web-chat",
            Self::Cli => "cli",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "web-account" => Some(Self::WebAccount),
            "web-drive" => Some(Self::WebDrive),
            "web-chat" => Some(Self::WebChat),
            "cli" => Some(Self::Cli),
            _ => None,
        }
    }

    /// Web clients hold the refresh token in an HttpOnly cookie on their own
    /// origin; everything else receives it in the response body.
    pub fn uses_cookie(self) -> bool {
        !matches!(self, Self::Cli)
    }

    /// Clients that sign in with a password (the others are forked).
    pub fn signs_in_directly(self) -> bool {
        matches!(self, Self::WebAccount | Self::Cli)
    }

    /// Clients the account app may fork a session for.
    pub fn is_fork_child(self) -> bool {
        matches!(self, Self::WebDrive | Self::WebChat)
    }
}

/// A 32-byte random secret, base64url without padding (43 chars).
fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// Parse a presented secret; anything that is not 32 base64url bytes is
/// rejected before touching the database.
fn well_formed(secret: &str) -> bool {
    secret.len() == 43
        && URL_SAFE_NO_PAD
            .decode(secret)
            .map(|b| b.len() == 32)
            .unwrap_or(false)
}

fn truncate_user_agent(user_agent: Option<&str>) -> Option<String> {
    user_agent.map(|ua| ua.chars().take(512).collect())
}

pub struct IssuedSession {
    pub session_id: Uuid,
    pub refresh_token: String,
}

pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    client: ClientType,
    parent: Option<Uuid>,
    user_agent: Option<&str>,
) -> AppResult<IssuedSession> {
    let session_id = Uuid::new_v4();
    let refresh_token = new_secret();
    sqlx::query(
        "INSERT INTO auth_sessions
             (id, user_id, client_type, parent_session_id, refresh_token_hash, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(client.as_str())
    .bind(parent)
    .bind(hash_secret(&refresh_token))
    .bind(truncate_user_agent(user_agent))
    .bind(OffsetDateTime::now_utc() + SESSION_TTL)
    .execute(pool)
    .await?;
    Ok(IssuedSession {
        session_id,
        refresh_token,
    })
}

/// A live session as seen by an authenticated request.
#[derive(Clone, Debug)]
pub struct LiveSession {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub client: ClientType,
    pub is_admin: bool,
}

/// Confirms the session is neither revoked nor expired and the user is still
/// active. Called for every authenticated request.
pub async fn live(pool: &PgPool, session_id: Uuid, user_id: Uuid) -> AppResult<LiveSession> {
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT s.client_type, u.is_admin
         FROM auth_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL
           AND s.expires_at > now() AND u.is_active",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    let (client_type, is_admin) = row.ok_or_else(|| AppError::unauthorized("unauthorized"))?;
    let client =
        ClientType::parse(&client_type).ok_or_else(|| AppError::unauthorized("unauthorized"))?;
    Ok(LiveSession {
        session_id,
        user_id,
        client,
        is_admin,
    })
}

pub enum RefreshOutcome {
    /// A new refresh token was minted; send it (cookie or body).
    Rotated {
        session: LiveSession,
        refresh_token: String,
    },
    /// The token was just rotated by a concurrent refresh; the new one is
    /// already on its way to this client (same cookie jar). Mint an access
    /// token only.
    Grace { session: LiveSession },
}

/// Rotate a refresh token. Unknown, expired and revoked tokens are refused;
/// a rotated token replayed after the grace window revokes the session.
///
/// `via_cookie` is how the token arrived. A web session's token is only
/// accepted from its cookie and a CLI's only from the body, and the check
/// happens *before* rotation: a token presented the wrong way must not rotate
/// the session out from under its legitimate holder.
pub async fn refresh(
    pool: &PgPool,
    refresh_token: &str,
    via_cookie: bool,
) -> AppResult<RefreshOutcome> {
    if !well_formed(refresh_token) {
        return Err(AppError::unauthorized("invalid refresh token"));
    }
    let hash = hash_secret(refresh_token);
    let now = OffsetDateTime::now_utc();
    let mut tx = pool.begin().await?;

    type Row = (
        Uuid,
        Uuid,
        String,
        bool,
        bool,
        OffsetDateTime,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    );
    let current: Option<Row> = sqlx::query_as(
        "SELECT s.id, s.user_id, s.client_type, u.is_admin, u.is_active, s.expires_at, s.revoked_at, s.rotated_at
         FROM auth_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.refresh_token_hash = $1
         FOR UPDATE OF s",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((id, user_id, client_type, is_admin, is_active, expires_at, revoked_at, _)) =
        current
    {
        if revoked_at.is_some() || expires_at <= now || !is_active {
            return Err(AppError::unauthorized("session ended"));
        }
        let client = ClientType::parse(&client_type)
            .ok_or_else(|| AppError::unauthorized("session ended"))?;
        if client.uses_cookie() != via_cookie {
            return Err(AppError::unauthorized("invalid refresh token"));
        }
        let next = new_secret();
        sqlx::query(
            "UPDATE auth_sessions
             SET previous_refresh_token_hash = refresh_token_hash,
                 refresh_token_hash = $2, rotated_at = $3,
                 last_used_at = $3, expires_at = $4
             WHERE id = $1",
        )
        .bind(id)
        .bind(hash_secret(&next))
        .bind(now)
        .bind(now + SESSION_TTL)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(RefreshOutcome::Rotated {
            session: LiveSession {
                session_id: id,
                user_id,
                client,
                is_admin,
            },
            refresh_token: next,
        });
    }

    let previous: Option<Row> = sqlx::query_as(
        "SELECT s.id, s.user_id, s.client_type, u.is_admin, u.is_active, s.expires_at, s.revoked_at, s.rotated_at
         FROM auth_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.previous_refresh_token_hash = $1
         FOR UPDATE OF s",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, user_id, client_type, is_admin, is_active, expires_at, revoked_at, rotated_at)) =
        previous
    else {
        return Err(AppError::unauthorized("invalid refresh token"));
    };
    if revoked_at.is_some() || expires_at <= now || !is_active {
        return Err(AppError::unauthorized("session ended"));
    }
    let client =
        ClientType::parse(&client_type).ok_or_else(|| AppError::unauthorized("session ended"))?;
    if client.uses_cookie() != via_cookie {
        return Err(AppError::unauthorized("invalid refresh token"));
    }
    let within_grace = rotated_at.is_some_and(|at| now - at <= REFRESH_GRACE);
    if !within_grace {
        // A token that was rotated away long ago is being replayed: the
        // secret leaked. End the session and everything forked from it.
        revoke_tree(&mut tx, id, now).await?;
        tx.commit().await?;
        tracing::warn!(session_id = %id, "refresh token reuse detected; session revoked");
        return Err(AppError::unauthorized("session ended"));
    }
    tx.commit().await?;
    Ok(RefreshOutcome::Grace {
        session: LiveSession {
            session_id: id,
            user_id,
            client,
            is_admin,
        },
    })
}

async fn revoke_tree(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session_id: Uuid,
    now: OffsetDateTime,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = $2
         WHERE (id = $1 OR parent_session_id = $1) AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Sign out: revoke the whole sign-in this session belongs to — the root
/// (the account. session, or a CLI session) and every session forked from it.
pub async fn sign_out(pool: &PgPool, session_id: Uuid) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    let root: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT parent_session_id FROM auth_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(&mut *tx)
            .await?;
    let root = match root {
        Some(Some(parent)) => parent,
        Some(None) => session_id,
        None => return Ok(()),
    };
    revoke_tree(&mut tx, root, OffsetDateTime::now_utc()).await?;
    tx.commit().await?;
    Ok(())
}

/// Revoke one of the caller's sessions (and its children).
pub async fn revoke_owned(pool: &PgPool, user_id: Uuid, session_id: Uuid) -> AppResult<bool> {
    let owned: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth_sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    if owned.is_none() {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    revoke_tree(&mut tx, session_id, OffsetDateTime::now_utc()).await?;
    tx.commit().await?;
    Ok(true)
}

/// Revoke every session of the user except the caller's own sign-in (its
/// root and children). `keep = None` revokes everything, e.g. after a
/// password reset or when an admin disables the account.
pub async fn revoke_all_for_user(
    pool: &PgPool,
    user_id: Uuid,
    keep: Option<Uuid>,
) -> AppResult<()> {
    let keep_root: Option<Uuid> = match keep {
        Some(id) => {
            sqlx::query_scalar(
                "SELECT COALESCE(parent_session_id, id) FROM auth_sessions WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
        None => None,
    };
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL
           AND ($2::uuid IS NULL OR (id <> $2 AND parent_session_id IS DISTINCT FROM $2))",
    )
    .bind(user_id)
    .bind(keep_root)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub client_type: String,
    pub parent_session_id: Option<Uuid>,
    pub user_agent: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_used_at: OffsetDateTime,
}

pub async fn list(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<SessionRow>> {
    Ok(sqlx::query_as(
        "SELECT id, client_type, parent_session_id, user_agent, created_at, last_used_at
         FROM auth_sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
         ORDER BY last_used_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Store a fork hand-off for `child`, returning the one-time selector.
pub async fn create_fork(
    pool: &PgPool,
    parent: &LiveSession,
    child: ClientType,
    payload: &[u8],
) -> AppResult<String> {
    if parent.client != ClientType::WebAccount {
        return Err(AppError::forbidden(
            "only the account app can fork a session",
        ));
    }
    if !child.is_fork_child() {
        return Err(AppError::bad_request("this client type cannot be forked"));
    }
    if payload.is_empty() || payload.len() > MAX_FORK_PAYLOAD {
        return Err(AppError::bad_request("invalid fork payload"));
    }
    let selector = new_secret();
    sqlx::query("DELETE FROM auth_session_forks WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO auth_session_forks
             (selector_hash, parent_session_id, child_client_type, payload, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(hash_secret(&selector))
    .bind(parent.session_id)
    .bind(child.as_str())
    .bind(payload)
    .bind(OffsetDateTime::now_utc() + FORK_TTL)
    .execute(pool)
    .await?;
    Ok(selector)
}

pub struct ConsumedFork {
    pub issued: IssuedSession,
    pub user_id: Uuid,
    pub is_admin: bool,
    pub payload: Vec<u8>,
}

/// Consume a fork exactly once, creating the child session. The selector must
/// match, be unexpired, and have been minted for `child`; the parent must
/// still be live.
pub async fn consume_fork(
    pool: &PgPool,
    selector: &str,
    child: ClientType,
    user_agent: Option<&str>,
) -> AppResult<ConsumedFork> {
    if !well_formed(selector) || !child.is_fork_child() {
        return Err(AppError::unauthorized("invalid fork"));
    }
    let mut tx = pool.begin().await?;
    let fork: Option<(Uuid, String, Vec<u8>, OffsetDateTime)> = sqlx::query_as(
        "DELETE FROM auth_session_forks WHERE selector_hash = $1
         RETURNING parent_session_id, child_client_type, payload, expires_at",
    )
    .bind(hash_secret(selector))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((parent_id, child_type, payload, expires_at)) = fork else {
        return Err(AppError::unauthorized("invalid fork"));
    };
    if expires_at <= OffsetDateTime::now_utc() || child_type != child.as_str() {
        tx.commit().await?;
        return Err(AppError::unauthorized("invalid fork"));
    }
    let parent: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT s.user_id, u.is_admin FROM auth_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.is_active",
    )
    .bind(parent_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, is_admin)) = parent else {
        tx.commit().await?;
        return Err(AppError::unauthorized("invalid fork"));
    };
    let session_id = Uuid::new_v4();
    let refresh_token = new_secret();
    sqlx::query(
        "INSERT INTO auth_sessions
             (id, user_id, client_type, parent_session_id, refresh_token_hash, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(child.as_str())
    .bind(parent_id)
    .bind(hash_secret(&refresh_token))
    .bind(truncate_user_agent(user_agent))
    .bind(OffsetDateTime::now_utc() + SESSION_TTL)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ConsumedFork {
        issued: IssuedSession {
            session_id,
            refresh_token,
        },
        user_id,
        is_admin,
        payload,
    })
}

pub async fn set_local_key(pool: &PgPool, session: &LiveSession, key: &[u8]) -> AppResult<()> {
    if !session.client.uses_cookie() {
        return Err(AppError::bad_request("local keys are for web sessions"));
    }
    if key.len() != 32 {
        return Err(AppError::bad_request("local key must be 32 bytes"));
    }
    sqlx::query("UPDATE auth_sessions SET local_key = $2 WHERE id = $1")
        .bind(session.session_id)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn local_key(pool: &PgPool, session: &LiveSession) -> AppResult<Option<Vec<u8>>> {
    Ok(
        sqlx::query_scalar("SELECT local_key FROM auth_sessions WHERE id = $1")
            .bind(session.session_id)
            .fetch_one(pool)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_32_random_bytes_in_base64url() {
        let a = new_secret();
        let b = new_secret();
        assert_ne!(a, b);
        assert!(well_formed(&a));
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
    }

    #[test]
    fn malformed_secrets_are_rejected_before_the_database() {
        assert!(!well_formed(""));
        assert!(!well_formed("short"));
        assert!(!well_formed(&"A".repeat(44)));
        assert!(!well_formed(&"*".repeat(43)));
    }

    #[test]
    fn client_types_round_trip_and_classify() {
        for client in [
            ClientType::WebAccount,
            ClientType::WebDrive,
            ClientType::WebChat,
            ClientType::Cli,
        ] {
            assert_eq!(ClientType::parse(client.as_str()), Some(client));
        }
        assert_eq!(ClientType::parse("android-drive"), None);
        assert!(ClientType::WebAccount.signs_in_directly());
        assert!(ClientType::Cli.signs_in_directly());
        assert!(!ClientType::WebDrive.signs_in_directly());
        assert!(ClientType::WebChat.is_fork_child());
        assert!(!ClientType::WebAccount.is_fork_child());
        assert!(!ClientType::Cli.uses_cookie());
    }

    #[test]
    fn user_agents_are_bounded() {
        let long = "x".repeat(2000);
        assert_eq!(truncate_user_agent(Some(&long)).unwrap().len(), 512);
        assert_eq!(truncate_user_agent(None), None);
    }
}
