//! What changed an account's sign-in, kept for its owner to see
//! (`GET /api/user/security-events`, docs/api.md): a new password, a
//! recovery, a move to the server's current OPAQUE setup, an administrator's
//! reset. Each is written in the transaction of the change it records. No IP
//! addresses; a year, or the newest 500 per account.

use uuid::Uuid;

use crate::error::AppResult;

/// The most events kept per account, and for how long.
const KEEP: i64 = 500;
const KEEP_DAYS: i32 = 365;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    PasswordChange,
    Recovery,
    Rotate,
    AdminReset,
    AccountReset,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::PasswordChange => "passwordChange",
            Kind::Recovery => "recovery",
            Kind::Rotate => "rotate",
            Kind::AdminReset => "adminReset",
            Kind::AccountReset => "accountReset",
        }
    }
}

/// Records `kind` for `user_id` inside `tx`, made from `session` (copied:
/// its client and user agent) or by `admin`; the account's oldest events
/// past the limits go.
pub async fn record(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    kind: Kind,
    session: Option<Uuid>,
    admin: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO account_security_events
             (id, user_id, kind, acting_session_id, acting_client, acting_user_agent, admin_user_id)
         SELECT $1, $2, $3, $4, s.client_type, s.user_agent, $5
         FROM (SELECT 1) one
         LEFT JOIN auth_sessions s ON s.id = $4",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(kind.as_str())
    .bind(session)
    .bind(admin)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM account_security_events
         WHERE user_id = $1
           AND (at < now() - make_interval(days => $2)
                OR id IN (SELECT id FROM account_security_events WHERE user_id = $1
                          ORDER BY at DESC, id DESC OFFSET $3))",
    )
    .bind(user_id)
    .bind(KEEP_DAYS)
    .bind(KEEP)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// One event as its owner reads it.
#[derive(Debug, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub kind: String,
    pub at: time::OffsetDateTime,
    pub acting_session_id: Option<Uuid>,
    pub acting_client: Option<String>,
    pub acting_user_agent: Option<String>,
    pub by_admin: bool,
}

/// The account's events, newest first: after the event `cursor` (the last
/// one of a previous page) when given.
pub async fn list(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    cursor: Option<Uuid>,
    limit: i64,
) -> AppResult<Vec<Event>> {
    Ok(sqlx::query_as(
        "SELECT e.id, e.kind, e.at, e.acting_session_id, e.acting_client, e.acting_user_agent,
                e.kind IN ('adminReset', 'accountReset') AS by_admin
         FROM account_security_events e
         WHERE e.user_id = $1
           AND ($2::uuid IS NULL OR (e.at, e.id) < (
               SELECT c.at, c.id FROM account_security_events c
               WHERE c.id = $2 AND c.user_id = $1))
         ORDER BY e.at DESC, e.id DESC
         LIMIT $3",
    )
    .bind(user_id)
    .bind(cursor)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}
