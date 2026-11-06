//! What changed an account's sign-in, kept for its owner to see
//! (`GET /api/user/security-events`, docs/api.md): a new password, a
//! recovery, a move to the server's current OPAQUE setup, an administrator's
//! reset, a sign-in or a failed one. Each is written in the transaction of the
//! change it records. No IP addresses.
//!
//! The table is append-only for the server (docs/plans/server-personal-data.md,
//! A8): it may insert, and raise a failure's `count`, but not change or delete
//! a row. Old events go by the retention job ([`prune`]): the newest
//! [`KEEP`] per account, for the days the Privacy and retention setting says.

use uuid::Uuid;

use crate::error::AppResult;

/// The most events kept per account.
pub const KEEP: i64 = 500;
/// A failed sign-in within this many minutes of the same kind's last one is
/// counted into it instead of a row of its own.
const FOLD_MINUTES: i32 = 10;

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
    /// A security key added (`old_name` is its name, as for every key
    /// event).
    SecurityKeyAdded,
    /// A security key removed (`old_name` is its name).
    SecurityKeyRemoved,
    /// A security key's counter went back with no other use of it in flight:
    /// it may have been cloned, and is no longer used; its owner removes it
    /// (and adds it again, if it is theirs). `old_name` is its name.
    SecurityKeyCompromised,
    /// The authenticator app turned on beside a security key (two-step
    /// sign-in was on already).
    AuthenticatorOn,
    /// The authenticator app turned off; security keys keep two-step
    /// sign-in on.
    AuthenticatorOff,
    /// A sign-in completed (a session made).
    SignIn,
    /// A wrong password for this account (only when the sign-in named it);
    /// repeats fold into one row with a count.
    SignInFailedPassword,
    /// A wrong second step (code, security key or recovery code); repeats fold.
    SignInFailed2fa,
    /// A session signed out by its own device.
    SignOut,
    /// One session ended from another (Settings → Sessions).
    SessionRevoked,
    /// Every other session ended at once.
    AllSessionsRevoked,
    /// An administrator opened this account's data in the admin console.
    AdminAccess,
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
            Kind::SignIn => "signIn",
            Kind::SignInFailedPassword => "signInFailedPassword",
            Kind::SignInFailed2fa => "signInFailed2fa",
            Kind::SignOut => "signOut",
            Kind::SessionRevoked => "sessionRevoked",
            Kind::AllSessionsRevoked => "allSessionsRevoked",
            Kind::AdminAccess => "adminAccess",
        }
    }
}

/// Records `kind` for `user_id` inside `tx`, made from `session` (copied:
/// its client and user agent) or by `admin`.
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
    Ok(())
}

/// A repeatable event for `user_id` (a failed sign-in, an admin view):
/// counted into the same kind's last event
/// when that is under [`FOLD_MINUTES`] old, else recorded as a new one.
pub async fn record_folded(pool: &sqlx::PgPool, user_id: Uuid, kind: Kind) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    let folded = sqlx::query(
        "UPDATE account_security_events SET count = count + 1
          WHERE id = (SELECT id FROM account_security_events
                       WHERE user_id = $1 AND kind = $2
                         AND at > now() - make_interval(mins => $3)
                       ORDER BY at DESC, id DESC LIMIT 1)",
    )
    .bind(user_id)
    .bind(kind.as_str())
    .bind(FOLD_MINUTES)
    .execute(&mut *tx)
    .await?;
    if folded.rows_affected() == 0 {
        insert(&mut tx, user_id, kind, None, None, None, None).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The retention job's part: events older than `days`, and past the newest
/// [`KEEP`] of each account, go. Returns how many. Runs on the owner's
/// connection when the server has one (the server itself may not delete).
pub async fn prune(pool: &sqlx::PgPool, days: i64) -> AppResult<u64> {
    let gone = sqlx::query(
        "DELETE FROM account_security_events e
          WHERE e.at < now() - make_interval(days => $1::int)
             OR e.id IN (SELECT id FROM (
                    SELECT id, row_number() OVER (PARTITION BY user_id ORDER BY at DESC, id DESC) AS n
                      FROM account_security_events) ranked
                  WHERE ranked.n > $2)",
    )
    .bind(days)
    .bind(KEEP)
    .execute(pool)
    .await?;
    Ok(gone.rows_affected())
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
    /// How many times it happened (a failed sign-in's repeats folded).
    pub count: i32,
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
                e.old_name, e.new_name, e.count
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
