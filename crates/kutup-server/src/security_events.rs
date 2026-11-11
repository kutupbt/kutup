//! What changed an account's sign-in, kept for its owner to see
//! (`GET /api/user/security-events`, docs/api.md): a new password, a
//! recovery, a move to the server's current OPAQUE setup, an administrator's
//! reset, a sign-in or a failed one. Each is written in the transaction of the
//! change it records. No IP addresses.
//!
//! The table is append-only for the server (docs/plans/server-personal-data.md,
//! A8): it may insert, and raise a failure's `count`, but not change or delete
//! a row. Old events go by the retention job ([`prune`]), for the days the
//! Privacy and retention settings say, and past the newest of each kind they
//! keep per account.

use uuid::Uuid;

use crate::error::AppResult;

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
    /// The owner asked for the account to be deleted; it is closing.
    AccountClosing,
    /// A closing account was kept.
    AccountKept,
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
            Kind::AccountClosing => "accountClosing",
            Kind::AccountKept => "accountKept",
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
    let id = Uuid::new_v4();
    // What made it: the session's client, and its browser re-sealed for this
    // row (a session's own goes when the session does; the event stays).
    let acting: Option<(String, Option<Vec<u8>>)> = match session {
        Some(session) => {
            sqlx::query_as("SELECT client_type, client_sealed FROM auth_sessions WHERE id = $1")
                .bind(session)
                .fetch_optional(&mut **tx)
                .await?
        }
        None => None,
    };
    let (acting_client, client_sealed) = match (acting, session) {
        (Some((client, sealed)), Some(session)) => {
            let key = crate::client_family::account_key(tx, user_id).await?;
            let family = crate::client_family::open_with(
                &key,
                user_id,
                "auth_sessions",
                session,
                sealed.as_deref(),
            );
            let sealed =
                crate::client_family::seal_in(tx, user_id, "account_security_events", id, &family)
                    .await?;
            (Some(client), sealed)
        }
        _ => (None, None),
    };
    sqlx::query(
        "INSERT INTO account_security_events
             (id, user_id, kind, acting_session_id, acting_client, client_sealed, admin_user_id,
              old_name, new_name)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(user_id)
    .bind(kind.as_str())
    .bind(session)
    .bind(acting_client)
    .bind(client_sealed)
    .bind(admin)
    .bind(old_name)
    .bind(new_name)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A repeatable event for `user_id` (a failed sign-in, an admin view):
/// counted into the same kind's last event when that is younger than the fold
/// window (`security_event_fold_seconds`), else recorded as a new one.
pub async fn record_folded(pool: &sqlx::PgPool, user_id: Uuid, kind: Kind) -> AppResult<()> {
    let fold_seconds = crate::site_settings::SECURITY_EVENT_FOLD_SECONDS
        .load(pool)
        .await?;
    let mut tx = pool.begin().await?;
    // One at a time per account and kind: two at once would each find
    // nothing to fold into and both insert.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || '/' || $2, 0))")
        .bind(user_id)
        .bind(kind.as_str())
        .execute(&mut *tx)
        .await?;
    let folded = sqlx::query(
        "UPDATE account_security_events SET count = count + 1
          WHERE id = (SELECT id FROM account_security_events
                       WHERE user_id = $1 AND kind = $2
                         AND at > now() - make_interval(secs => $3)
                       ORDER BY at DESC, id DESC LIMIT 1)",
    )
    .bind(user_id)
    .bind(kind.as_str())
    .bind(fold_seconds as f64)
    .execute(&mut *tx)
    .await?;
    if folded.rows_affected() == 0 {
        insert(&mut tx, user_id, kind, None, None, None, None).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The retention job's part: events older than `days`, and past the newest
/// `kept_per_kind` of their kind for their account, go. Returns how many.
/// Runs on the owner's connection when the server has one (the server
/// itself may not delete).
pub async fn prune(pool: &sqlx::PgPool, days: i64, kept_per_kind: i64) -> AppResult<u64> {
    let gone = sqlx::query(
        "DELETE FROM account_security_events e
          WHERE (e.at < now() - make_interval(days => $1::int)
                 OR e.id IN (SELECT id FROM (
                        SELECT id, row_number() OVER (PARTITION BY user_id, kind
                                                      ORDER BY at DESC, id DESC) AS n
                          FROM account_security_events) ranked
                      WHERE ranked.n > $2))
            -- A legal hold keeps everything of its account (A5).
            AND NOT kutup_account_held(e.user_id)",
    )
    .bind(days)
    .bind(kept_per_kind)
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
    /// Its browser, opened.
    #[sqlx(skip)]
    pub client: crate::client_family::ClientFamily,
    pub client_sealed: Option<Vec<u8>>,
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
    let mut conn = pool.acquire().await?;
    let mut events: Vec<Event> = sqlx::query_as(
        "SELECT e.id, e.kind, e.at, e.acting_session_id, e.acting_client, e.client_sealed,
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
    .fetch_all(&mut *conn)
    .await?;
    let key = crate::client_family::account_key(&mut conn, user_id).await?;
    for event in &mut events {
        event.client = crate::client_family::open_with(
            &key,
            user_id,
            "account_security_events",
            event.id,
            event.client_sealed.as_deref(),
        );
    }
    Ok(events)
}
