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
    /// A new username (`old_name`, `new_name`).
    Rename,
    /// Receiving at a held name ended by its owner (`old_name`).
    NameDropped,
    /// Receiving at a held name ended by an administrator.
    NameClosed,
    /// A held name freed by an administrator before its date.
    NameFreed,
    /// A custom mail domain the account held, lost (`old_name` is the
    /// domain): another account proved it, or its DNS stopped proving it.
    DomainLost,
    /// Two-factor sign-in turned on (its recovery codes made).
    TwoFactorOn,
    /// Two-factor sign-in turned off: by the owner, an administrator, or the
    /// recovery phrase's path.
    TwoFactorOff,
    /// A recovery code took the second factor's place.
    RecoveryCodeUsed,
    /// New recovery codes made; the old ones stopped working.
    RecoveryCodesRenewed,
    /// A security key added (`new_name` is its name).
    SecurityKeyAdded,
    /// A security key removed (`old_name` is its name).
    SecurityKeyRemoved,
    /// A security key's counter went back: it may have been cloned, and is
    /// no longer used.
    SecurityKeyCompromised,
    /// The authenticator app turned on beside a security key (two-step
    /// sign-in was on already).
    AuthenticatorOn,
    /// The authenticator app turned off; security keys keep two-step
    /// sign-in on.
    AuthenticatorOff,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::PasswordChange => "passwordChange",
            Kind::Recovery => "recovery",
            Kind::Rotate => "rotate",
            Kind::AdminReset => "adminReset",
            Kind::AccountReset => "accountReset",
            Kind::Rename => "rename",
            Kind::NameDropped => "nameDropped",
            Kind::NameClosed => "nameClosed",
            Kind::NameFreed => "nameFreed",
            Kind::DomainLost => "domainLost",
            Kind::TwoFactorOn => "twoFactorOn",
            Kind::TwoFactorOff => "twoFactorOff",
            Kind::RecoveryCodeUsed => "recoveryCodeUsed",
            Kind::RecoveryCodesRenewed => "recoveryCodesRenewed",
            Kind::SecurityKeyAdded => "securityKeyAdded",
            Kind::SecurityKeyRemoved => "securityKeyRemoved",
            Kind::SecurityKeyCompromised => "securityKeyCompromised",
            Kind::AuthenticatorOn => "authenticatorOn",
            Kind::AuthenticatorOff => "authenticatorOff",
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
    insert(tx, user_id, kind, session, admin, None, None).await
}

/// [`record`] for an event about a name: the name it was about, and for a
/// rename the new one.
pub async fn record_names(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    kind: Kind,
    session: Option<Uuid>,
    admin: Option<Uuid>,
    old_name: &str,
    new_name: Option<&str>,
) -> AppResult<()> {
    insert(tx, user_id, kind, session, admin, Some(old_name), new_name).await
}

async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    kind: Kind,
    session: Option<Uuid>,
    admin: Option<Uuid>,
    old_name: Option<&str>,
    new_name: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO account_security_events
             (id, user_id, kind, acting_session_id, acting_client, acting_user_agent, admin_user_id,
              old_name, new_name)
         SELECT $1, $2, $3, $4, s.client_type, s.user_agent, $5, $6, $7
         FROM (SELECT 1) one
         LEFT JOIN auth_sessions s ON s.id = $4",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(kind.as_str())
    .bind(session)
    .bind(admin)
    .bind(old_name)
    .bind(new_name)
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
    pub old_name: Option<String>,
    pub new_name: Option<String>,
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
                e.kind IN ('adminReset', 'accountReset', 'nameClosed', 'nameFreed') AS by_admin,
                e.old_name, e.new_name
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
