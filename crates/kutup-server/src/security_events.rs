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
//!
//! Its columns are the admin log's (docs/plans/w7-schema.md §6): `kind` (a
//! [`Kind`]), `actor_kind` with `actor_account_id` (the administrator, or
//! the account itself when one of its sessions acted; none when no one is
//! known), `subject_account_id` (whose log it is), `at`, `payload` (the keys
//! in [`PAYLOAD_KEYS`]), `count`, and `chain_version` 0 with no hashes:
//! pruned per kind, this log is not chained. Which actors and names each kind
//! takes is the kind table's, held by [`insert`], not the database's.

use uuid::Uuid;

use crate::error::AppResult;

/// Who did an event (`actor_kind`, the same values as the admin log's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorKind {
    /// The account itself (or someone signing in as it).
    Account,
    /// An administrator.
    Admin,
    /// The server on its own (a job, a DNS check).
    Job,
}

impl ActorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ActorKind::Account => "account",
            ActorKind::Admin => "admin",
            ActorKind::Job => "job",
        }
    }
}

/// Which names an event's payload carries (`oldName`, and `newName`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Names {
    None,
    /// `oldName`: the name it was about.
    Old,
    /// `oldName` and `newName`.
    OldNew,
}

/// The payload keys an event may carry: what made it (a session's id, its
/// client, and its browser sealed for this row), and its names.
pub const PAYLOAD_KEYS: [&str; 5] = [
    "actingSessionId",
    "actingClient",
    "clientSealed",
    "oldName",
    "newName",
];

/// Declares [`Kind`]: each kind, its string, who may do it (the first is
/// who did it when no session or administrator is named) and its names.
/// The table replaces the database's per-kind checks
/// (docs/plans/w7-schema.md §6); [`insert`] holds every row to it.
macro_rules! kinds {
    ($($(#[$doc:meta])* $variant:ident = $name:literal [$($actor:ident),+] $names:ident),* $(,)?) => {
        /// Every kind of security event.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Kind {
            $($(#[$doc])* $variant),*
        }

        impl Kind {
            /// Every kind, for the table's own test.
            #[cfg(test)]
            pub const ALL: &'static [Kind] = &[$(Kind::$variant),*];

            /// The kind as the log stores it.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Kind::$variant => $name),*
                }
            }

            /// Who may do it; the first when the caller names no one.
            pub const fn actors(self) -> &'static [ActorKind] {
                match self {
                    $(Kind::$variant => &[$(ActorKind::$actor),+]),*
                }
            }

            /// The names its payload carries.
            pub const fn names(self) -> Names {
                match self {
                    $(Kind::$variant => Names::$names),*
                }
            }
        }
    };
}

kinds! {
    PasswordChange = "passwordChange" [Account] None,
    Recovery = "recovery" [Account] None,
    Rotate = "rotate" [Account] None,
    AdminReset = "adminReset" [Admin] None,
    AccountReset = "accountReset" [Admin] None,
    /// A new username (`oldName`, `newName`).
    Rename = "rename" [Account] OldNew,
    /// Receiving at a held name ended by its owner (`oldName`).
    NameDropped = "nameDropped" [Account] Old,
    /// Receiving at a held name ended by an administrator.
    NameClosed = "nameClosed" [Admin] Old,
    /// A held name freed by an administrator before its date.
    NameFreed = "nameFreed" [Admin] Old,
    /// A custom mail domain the account held, lost (`oldName` is the
    /// domain): another account proved it, or its DNS stopped proving it.
    DomainLost = "domainLost" [Job] Old,
    /// Two-factor sign-in turned on (its recovery codes made).
    TwoFactorOn = "twoFactorOn" [Account] None,
    /// Two-factor sign-in turned off: by the owner, an administrator, or the
    /// recovery phrase's path.
    TwoFactorOff = "twoFactorOff" [Account, Admin] None,
    /// A recovery code took the second factor's place.
    RecoveryCodeUsed = "recoveryCodeUsed" [Account] None,
    /// New recovery codes made; the old ones stopped working.
    RecoveryCodesRenewed = "recoveryCodesRenewed" [Account] None,
    /// A security key added (`oldName` is its name, as for every key
    /// event).
    SecurityKeyAdded = "securityKeyAdded" [Account] Old,
    /// A security key removed (`oldName` is its name).
    SecurityKeyRemoved = "securityKeyRemoved" [Account] Old,
    /// A security key's counter went back with no other use of it in flight:
    /// it may have been cloned, and is no longer used; its owner removes it
    /// (and adds it again, if it is theirs). `oldName` is its name.
    SecurityKeyCompromised = "securityKeyCompromised" [Account] Old,
    /// The authenticator app turned on beside a security key (two-step
    /// sign-in was on already).
    AuthenticatorOn = "authenticatorOn" [Account] None,
    /// The authenticator app turned off; security keys keep two-step
    /// sign-in on.
    AuthenticatorOff = "authenticatorOff" [Account] None,
    /// A sign-in completed (a session made).
    SignIn = "signIn" [Account] None,
    /// A wrong password for this account (only when the sign-in named it);
    /// repeats fold into one row with a count.
    SignInFailedPassword = "signInFailedPassword" [Account] None,
    /// A wrong second step (code, security key or recovery code); repeats fold.
    SignInFailed2fa = "signInFailed2fa" [Account] None,
    /// A session signed out by its own device.
    SignOut = "signOut" [Account] None,
    /// One session ended from another (Settings → Sessions).
    SessionRevoked = "sessionRevoked" [Account] None,
    /// Every other session ended at once.
    AllSessionsRevoked = "allSessionsRevoked" [Account] None,
    /// An administrator opened this account's data in the admin console
    /// (repeats fold, across administrators: no admin is named).
    AdminAccess = "adminAccess" [Admin] None,
    /// The owner asked for the account to be deleted; it is closing.
    AccountClosing = "accountClosing" [Account] None,
    /// A closing account was kept: by its owner or an administrator.
    AccountKept = "accountKept" [Account, Admin] None,
    /// A new master key and recovery phrase (docs/plans/mk-rotation-exercise.md);
    /// the account's other sign-ins end.
    MasterKeyRotated = "masterKeyRotated" [Account] None,
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

/// Who did `kind`: the administrator when one is named, else the account when
/// one of its sessions acted, else the kind's first actor; and the account
/// to name as the actor (the administrator, or the subject for a session;
/// none otherwise). An error when the kind's table doesn't allow the actor or
/// the names given aren't the kind's.
fn actor(
    subject: Uuid,
    kind: Kind,
    session: Option<Uuid>,
    admin: Option<Uuid>,
    old_name: Option<&str>,
    new_name: Option<&str>,
) -> AppResult<(ActorKind, Option<Uuid>)> {
    let (actor, account) = match (admin, session) {
        (Some(admin), _) => (ActorKind::Admin, Some(admin)),
        (None, Some(_)) => (ActorKind::Account, Some(subject)),
        (None, None) => (kind.actors()[0], None),
    };
    if !kind.actors().contains(&actor) {
        return Err(crate::error::AppError::internal(format!(
            "a {} security event is not done by {}",
            kind.as_str(),
            actor.as_str()
        )));
    }
    let names = match (old_name.is_some(), new_name.is_some()) {
        (false, false) => Names::None,
        (true, false) => Names::Old,
        (true, true) => Names::OldNew,
        (false, true) => {
            return Err(crate::error::AppError::internal(
                "a security event with a new name and no old one",
            ))
        }
    };
    if names != kind.names() {
        return Err(crate::error::AppError::internal(format!(
            "a {} security event's names are not {names:?}",
            kind.as_str()
        )));
    }
    Ok((actor, account))
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
    let (actor_kind, actor_account) = actor(user_id, kind, session, admin, old_name, new_name)?;
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
    // The payload: PAYLOAD_KEYS in order, an absent value no key; the sealed
    // client in standard padded base64 (as `kutup_b64`).
    let values: [Option<String>; PAYLOAD_KEYS.len()] = [
        session.map(|session| session.to_string()),
        acting_client,
        client_sealed.map(|sealed| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(sealed)
        }),
        old_name.map(str::to_owned),
        new_name.map(str::to_owned),
    ];
    let payload: serde_json::Map<String, serde_json::Value> = PAYLOAD_KEYS
        .iter()
        .zip(values)
        .filter_map(|(key, value)| Some(((*key).to_owned(), serde_json::Value::String(value?))))
        .collect();
    sqlx::query(
        "INSERT INTO account_security_events
             (id, kind, actor_kind, actor_account_id, subject_account_id, payload)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(kind.as_str())
    .bind(actor_kind.as_str())
    .bind(actor_account)
    .bind(user_id)
    .bind(serde_json::Value::Object(payload))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A repeatable event for `user_id` (a failed sign-in, an admin view):
/// counted into the same kind's last event when that is younger than the fold
/// window (`server.security_event_fold_seconds`), else recorded as a new one.
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
                       WHERE subject_account_id = $1 AND kind = $2
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
                        SELECT id, row_number() OVER (PARTITION BY subject_account_id, kind
                                                      ORDER BY at DESC, id DESC) AS n
                          FROM account_security_events) ranked
                      WHERE ranked.n > $2))
            -- A legal hold keeps everything of its account (A5).
            AND NOT kutup_account_held(e.subject_account_id)",
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
        "SELECT e.id, e.kind, e.at, (e.payload->>'actingSessionId')::uuid AS acting_session_id,
                e.payload->>'actingClient' AS acting_client,
                kutup_unb64(e.payload->>'clientSealed') AS client_sealed,
                e.actor_kind = 'admin' AS by_admin,
                e.payload->>'oldName' AS old_name, e.payload->>'newName' AS new_name, e.count
         FROM account_security_events e
         WHERE e.subject_account_id = $1
           AND ($2::uuid IS NULL OR (e.at, e.id) < (
               SELECT c.at, c.id FROM account_security_events c
               WHERE c.id = $2 AND c.subject_account_id = $1))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn camel(word: &str) -> bool {
        let mut bytes = word.bytes();
        bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && bytes.all(|b| b.is_ascii_alphanumeric())
    }

    /// One table names every kind: each string unique and camelCase, its
    /// actors listed once each, and the payload keys camelCase.
    #[test]
    fn every_kind_is_in_the_table_once() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in Kind::ALL {
            let name = kind.as_str();
            assert!(seen.insert(name), "{name} is listed twice");
            assert!(camel(name), "{name} is not camelCase");
            let actors = kind.actors();
            assert!(!actors.is_empty(), "{name} has no actor");
            for (i, actor) in actors.iter().enumerate() {
                assert!(!actors[..i].contains(actor), "{name}: {actor:?} twice");
            }
        }
        assert_eq!(seen.len(), Kind::ALL.len());
        for key in PAYLOAD_KEYS {
            assert!(camel(key), "payload key {key} is not camelCase");
        }
    }

    /// What the database's checks held before the table (w7-schema.md §6):
    /// which kinds an administrator may do, and which carry names.
    #[test]
    fn the_table_keeps_the_old_checks() {
        let by_admin: Vec<&str> = Kind::ALL
            .iter()
            .filter(|kind| kind.actors().contains(&ActorKind::Admin))
            .map(|kind| kind.as_str())
            .collect();
        assert_eq!(
            by_admin,
            [
                "adminReset",
                "accountReset",
                "nameClosed",
                "nameFreed",
                "twoFactorOff",
                "adminAccess",
                "accountKept"
            ]
        );
        let named: Vec<&str> = Kind::ALL
            .iter()
            .filter(|kind| kind.names() != Names::None)
            .map(|kind| kind.as_str())
            .collect();
        assert_eq!(
            named,
            [
                "rename",
                "nameDropped",
                "nameClosed",
                "nameFreed",
                "domainLost",
                "securityKeyAdded",
                "securityKeyRemoved",
                "securityKeyCompromised"
            ]
        );
        assert_eq!(Kind::Rename.names(), Names::OldNew);
    }

    #[test]
    fn the_actor_follows_the_table() {
        let (account, admin, session) =
            (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        // A session acts as its account; an administrator is named.
        assert_eq!(
            actor(account, Kind::SignIn, Some(session), None, None, None).unwrap(),
            (ActorKind::Account, Some(account))
        );
        assert_eq!(
            actor(account, Kind::TwoFactorOff, None, Some(admin), None, None).unwrap(),
            (ActorKind::Admin, Some(admin))
        );
        // No one named: the kind's first actor, no account.
        assert_eq!(
            actor(account, Kind::SignInFailedPassword, None, None, None, None).unwrap(),
            (ActorKind::Account, None)
        );
        assert_eq!(
            actor(account, Kind::AdminAccess, None, None, None, None).unwrap(),
            (ActorKind::Admin, None)
        );
        assert_eq!(
            actor(
                account,
                Kind::DomainLost,
                None,
                None,
                Some("a.example"),
                None
            )
            .unwrap(),
            (ActorKind::Job, None)
        );
        // Not the kind's actor, or not its names.
        assert!(actor(account, Kind::SignIn, None, Some(admin), None, None).is_err());
        assert!(actor(account, Kind::AdminReset, Some(session), None, None, None).is_err());
        assert!(actor(account, Kind::Rename, Some(session), None, Some("a"), None).is_err());
        assert!(actor(account, Kind::SignIn, Some(session), None, Some("a"), None).is_err());
        assert!(actor(account, Kind::NameDropped, Some(session), None, None, None).is_err());
        assert!(actor(account, Kind::Rename, Some(session), None, None, Some("b")).is_err());
        assert!(actor(
            account,
            Kind::Rename,
            Some(session),
            None,
            Some("a"),
            Some("b")
        )
        .is_ok());
    }
}
