//! The account head chain (docs/plans/rollback-protection.md).
//!
//! Every write of a listed value (a contact, a group-list entry, a mail folder, label or filter
//! name, the identity pins, a Pass vault secret) also writes the account's
//! next head, in its transaction: the head's sequence must be the current
//! one plus one (`409 head_conflict`), and once the account has a head, a
//! listed write without one is refused (`409 head_required`). The server
//! never opens a head; it reads its sequence in clear and keeps the newest
//! [`RETENTION`] + 1 (so a device anchored [`RETENTION`] heads back still gets
//! its whole segment, anchor included).
//!
//! Every listed write first takes [`lock`]: the account row, for update, and
//! the session checked live under it. That orders the account's listed writes
//! (two writes that both see no head yet cannot both commit, one with a first
//! head and one without), and refuses a write that started before a wipe: a
//! wipe changes the incarnation and revokes every session in one transaction
//! on that row, so a session still live under the lock is one of the current
//! incarnation. The head's compare-and-swap ([`advance`]) runs last in the
//! write's transaction.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The crate's window, which a client's "too old" is judged by: a gap of more
/// than this many heads. The server keeps one more (the anchor's own head).
pub const RETENTION: i64 = kutup_crypto::account_head::RETENTION as i64;

/// The most heads one `GET /api/account/heads` answers; the rest by `next`.
pub const PAGE: i64 = 200;

/// A listed write's account, locked for its transaction ([`lock`]).
pub struct Locked {
    user_id: Uuid,
    incarnation_id: String,
}

/// Takes the account row for update and checks, under it, that `session` is
/// still live (not revoked, nor its sign-in): the first step of every listed
/// write. `409 setupRequired` for an account with no keys yet.
pub async fn lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    session: Uuid,
) -> AppResult<Locked> {
    let incarnation_id: Option<String> = sqlx::query_scalar(
        "SELECT account_incarnation_id FROM users WHERE id = $1 AND is_active FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(incarnation_id) = incarnation_id else {
        return Err(AppError::unauthorized("unauthorized"));
    };
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM auth_sessions s
                         WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL
                           AND NOT EXISTS (SELECT 1 FROM auth_sessions p
                                            WHERE p.id = s.parent_session_id
                                              AND p.revoked_at IS NOT NULL))",
    )
    .bind(session)
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    if !live {
        return Err(AppError::unauthorized("unauthorized"));
    }
    if incarnation_id.is_empty() {
        return Err(AppError::conflict("the account has no keys yet")
            .with_details(json!({ "code": "setupRequired" })));
    }
    Ok(Locked {
        user_id,
        incarnation_id,
    })
}

/// A next head as a write carries it: its sealed bytes and the sequence they
/// say.
pub struct NextHead {
    sealed: Vec<u8>,
    sequence: i64,
}

impl NextHead {
    /// The `head` field of a listed write: none, or canonical base64 of a
    /// sealed head (`account_head::inspect` reads its sequence and refuses
    /// anything else).
    pub fn parse(value: Option<&str>) -> AppResult<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let sealed = STANDARD
            .decode(value)
            .ok()
            .filter(|bytes| STANDARD.encode(bytes) == value)
            .ok_or_else(|| AppError::bad_request("head is not canonical base64"))?;
        let sequence = kutup_crypto::account_head::inspect(&sealed)
            .map_err(|_| AppError::bad_request("head is not a sealed account head"))?;
        let sequence = i64::try_from(sequence)
            .ok()
            .filter(|s| *s >= 1)
            .ok_or_else(|| AppError::bad_request("head sequence is out of range"))?;
        Ok(Some(Self { sealed, sequence }))
    }

    /// [`NextHead::parse`] for a write that may or may not change a listed
    /// value: a head sent with a change that does not (a colour, a position,
    /// a filter's conditions) is refused, so a client never mistakes one for
    /// rollback-protected.
    pub fn parse_for(value: Option<&str>, listed: bool) -> AppResult<Option<Self>> {
        if value.is_some() && !listed {
            return Err(AppError::bad_request(
                "only a change of a listed value carries the account head",
            ));
        }
        Self::parse(value)
    }
}

fn head_conflict(current: Option<i64>) -> AppError {
    AppError::conflict("the account head moved: read it again")
        .with_details(json!({ "code": "head_conflict", "sequence": current }))
}

fn head_required() -> AppError {
    AppError::conflict("this account keeps a head: the write needs the next one")
        .with_details(json!({ "code": "head_required" }))
}

/// Last in a listed write's transaction, after [`lock`]: makes `next` the
/// account's head.
/// - No head yet and none given: nothing (the chain is not started).
/// - A head kept and none given: `head_required`.
/// - Given: its sequence must follow the current one, else `head_conflict`
///   (also with no head yet: a chain starts only with [`start`], on its
///   basis); older heads past the window go.
pub async fn advance(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    locked: &Locked,
    next: Option<&NextHead>,
) -> AppResult<()> {
    let user_id = locked.user_id;
    // The newest head (the account row, locked by `lock`, already orders the
    // account's listed writes; the primary key below is the second guard).
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT sequence FROM account_heads WHERE user_id = $1
         ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(next) = next else {
        return match current {
            Some(_) => Err(head_required()),
            None => Ok(()),
        };
    };
    // A chain starts only with `start`, on the basis it was made on.
    let Some(current) = current else {
        return Err(head_conflict(None));
    };
    if next.sequence != current + 1 {
        return Err(head_conflict(Some(current)));
    }
    insert(tx, locked, next, Some(current)).await
}

async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    locked: &Locked,
    next: &NextHead,
    current: Option<i64>,
) -> AppResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO account_heads (user_id, sequence, sealed, incarnation_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(locked.user_id)
    .bind(next.sequence)
    .bind(&next.sealed)
    .bind(&locked.incarnation_id)
    .execute(&mut **tx)
    .await;
    match inserted {
        Ok(_) => {}
        // Taken first (the account row's lock makes this a second guard).
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Err(head_conflict(current));
        }
        Err(error) => return Err(error.into()),
    }
    // RETENTION + 1 kept: from `next - RETENTION` to `next`.
    sqlx::query("DELETE FROM account_heads WHERE user_id = $1 AND sequence < $2")
        .bind(locked.user_id)
        .bind(next.sequence - RETENTION)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// The account's newest head: its sequence and sealed bytes.
pub async fn latest<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
) -> AppResult<Option<(i64, Vec<u8>)>> {
    Ok(sqlx::query_as(
        "SELECT sequence, sealed FROM account_heads WHERE user_id = $1
         ORDER BY sequence DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await?)
}

/// Up to [`PAGE`] heads from `from` toward the newest, oldest first, and the
/// sequence to ask from next when there are more. `None` when `from` is
/// further back than [`RETENTION`] from the newest (the client's "too old":
/// a gap of more than `RETENTION`); an empty list when `from` is above the
/// newest.
pub async fn segment(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    from: i64,
) -> AppResult<Option<(Vec<Vec<u8>>, Option<i64>)>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let newest = latest(&mut *tx, user_id)
        .await?
        .map(|(sequence, _)| sequence);
    let Some(newest) = newest else {
        return Ok(Some((Vec::new(), None)));
    };
    if from < newest - RETENTION {
        return Ok(None);
    }
    let heads: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT sealed FROM account_heads WHERE user_id = $1 AND sequence >= $2
         ORDER BY sequence LIMIT $3",
    )
    .bind(user_id)
    .bind(from)
    .bind(PAGE)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let last = from + heads.len() as i64 - 1;
    let next = (!heads.is_empty() && last < newest).then_some(last + 1);
    Ok(Some((heads, next)))
}

/// The kinds of listed values (`ScopeV1::scope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Contacts,
    MailNames,
    Pins,
    PassSecrets,
    ChatGroups,
    ChatContacts,
}

impl Scope {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "contacts" => Scope::Contacts,
            "mailNames" => Scope::MailNames,
            "pins" => Scope::Pins,
            "passSecrets" => Scope::PassSecrets,
            "chatGroups" => Scope::ChatGroups,
            "chatContacts" => Scope::ChatContacts,
            _ => return None,
        })
    }
}

impl Scope {
    /// Every scope, in the order the basis covers them.
    pub const ALL: [Scope; 6] = [
        Scope::Contacts,
        Scope::MailNames,
        Scope::Pins,
        Scope::PassSecrets,
        Scope::ChatGroups,
        Scope::ChatContacts,
    ];

    fn name(self) -> &'static str {
        match self {
            Scope::Contacts => "contacts",
            Scope::MailNames => "mailNames",
            Scope::Pins => "pins",
            Scope::PassSecrets => "passSecrets",
            Scope::ChatGroups => "chatGroups",
            Scope::ChatContacts => "chatContacts",
        }
    }
}

/// A scope's `(id, revision)` pairs, sorted by id. Ids per scope: a contact's
/// id; `folder:`, `label:` or `filter:` and the id for mail names (a folder
/// without a name, kept through an account reset, is left out until it is
/// named); `pins` for the one pin list; an entry's keyed id for the group
/// list and for the Chat contact list; the vault's file id for a Pass secret
/// (every one the account keeps, trashed or out of reach included: the secret
/// stays until its owner forgets it with a head).
async fn values(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    scope: Scope,
) -> AppResult<Vec<(String, i64)>> {
    let mut values: Vec<(String, i64)> = match scope {
        Scope::Contacts => {
            sqlx::query_as("SELECT uid, revision FROM contacts WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&mut *conn)
                .await?
        }
        Scope::Pins => {
            sqlx::query_as("SELECT 'pins', revision FROM identity_pins WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&mut *conn)
                .await?
        }
        Scope::MailNames => {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT 'folder:' || id, name_sealed FROM mail_folders
                  WHERE user_id = $1 AND name_sealed IS NOT NULL
                 UNION ALL SELECT 'label:' || id, name_sealed FROM mail_labels WHERE user_id = $1
                 UNION ALL SELECT 'filter:' || id, name_sealed FROM mail_filters WHERE user_id = $1",
            )
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await?;
            rows.into_iter()
                .map(|(id, name)| Ok((id, crate::revisions::mail_name(&name)? as i64)))
                .collect::<AppResult<_>>()?
        }
        Scope::PassSecrets => {
            let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
                "SELECT file_id::text, envelope FROM pass_vault_secrets WHERE user_id = $1",
            )
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await?;
            rows.into_iter()
                .map(|(id, envelope)| Ok((id, crate::handlers::pass::revision_of(&envelope)?)))
                .collect::<AppResult<_>>()?
        }
        Scope::ChatGroups => {
            sqlx::query_as("SELECT id, revision FROM chat_group_list WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&mut *conn)
                .await?
        }
        Scope::ChatContacts => {
            sqlx::query_as("SELECT id, revision FROM chat_contact_list WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&mut *conn)
                .await?
        }
    };
    values.sort();
    Ok(values)
}

/// What an account holds before its first head, as the server sees it: the
/// SHA-256 (hex) of every listed value's scope, id and revision. A first head
/// names the basis it was made on, so a listed write without a head that
/// landed in between (the head would not cover it) is caught, not trusted.
async fn basis(conn: &mut sqlx::PgConnection, user_id: Uuid) -> AppResult<String> {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    for scope in Scope::ALL {
        for (id, revision) in values(&mut *conn, user_id, scope).await? {
            hash.update(format!("{}\0{id}\0{revision}\n", scope.name()));
        }
    }
    Ok(hex::encode(hash.finalize()))
}

/// A scope's index with the head it goes with, read in one snapshot so the
/// two always agree (a write between two separate reads would look like a
/// rollback), and, before the account's first head, the basis to start the
/// chain on.
pub async fn index(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    scope: Scope,
) -> AppResult<(Option<Vec<u8>>, Vec<(String, i64)>, Option<String>)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let head = latest(&mut *tx, user_id).await?.map(|(_, sealed)| sealed);
    let values = values(&mut tx, user_id, scope).await?;
    let basis = match head {
        Some(_) => None,
        None => Some(basis(&mut tx, user_id).await?),
    };
    tx.commit().await?;
    Ok((head, values, basis))
}

/// Starts the account's chain: `next` (sequence 1), made on `basis` (as the
/// index gave it). Under [`lock`]: `409 head_conflict` when a head exists or
/// the basis moved (a listed write landed since).
pub async fn start(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    locked: &Locked,
    next: &NextHead,
    expected: &str,
) -> AppResult<()> {
    if next.sequence != 1 {
        return Err(AppError::bad_request("a chain starts at sequence 1"));
    }
    if latest(&mut **tx, locked.user_id).await?.is_some() {
        return Err(head_conflict(None));
    }
    if basis(&mut *tx, locked.user_id).await? != expected {
        return Err(head_conflict(None));
    }
    insert(tx, locked, next, None).await
}

/// The body of a listed write that says nothing else (a delete): the next
/// head, when the account keeps one.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeadOnly {
    /// The next sealed account head (base64).
    #[serde(default)]
    pub head: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::account_head::{check, seal, AccountHeadV1, HeadKeys, HeadStatus};

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    /// The whole segment from `from`, a page at a time, as a client reads it.
    async fn whole(pool: &sqlx::PgPool, user_id: Uuid, from: i64) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut from = from;
        loop {
            let (heads, next) = segment(pool, user_id, from).await.unwrap()?;
            out.extend(heads);
            match next {
                Some(next) => from = next,
                None => return Some(out),
            }
        }
    }

    /// The window, as the client judges it: a device anchored exactly
    /// RETENTION heads back is shown its whole segment and finds it descends
    /// (`extends`); one anchored RETENTION + 1 back gets "too old" (410), and
    /// the client says `tooOld`, not a fork.
    #[tokio::test]
    async fn live_the_window_matches_the_clients_too_old() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let user_id = Uuid::new_v4();
        let incarnation = "cd".repeat(32);
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                drive_private_key_envelope, public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', $3, '')",
        )
        .bind(user_id)
        .bind(format!("heads{}", &user_id.simple().to_string()[..12]))
        .bind(&incarnation)
        .execute(&pool)
        .await
        .unwrap();
        let locked = Locked {
            user_id,
            incarnation_id: incarnation.clone(),
        };
        let keys = HeadKeys::derive(&[9; 32]).unwrap();
        let writer = keys.writer("window").unwrap();
        let total = RETENTION + 5;
        let mut sealed: Vec<Vec<u8>> = Vec::new();
        let mut head = AccountHeadV1::first(&incarnation, &writer, vec![]).unwrap();
        for sequence in 1..=total {
            if sequence > 1 {
                head = head.next(sealed.last().unwrap(), &writer, vec![]).unwrap();
            }
            let bytes = seal(&keys, BINDING, &head).unwrap();
            let next = NextHead::parse(Some(&STANDARD.encode(&bytes)))
                .unwrap()
                .unwrap();
            let mut tx = pool.begin().await.unwrap();
            if sequence == 1 {
                let on = basis(&mut tx, user_id).await.unwrap();
                start(&mut tx, &locked, &next, &on).await.unwrap();
            } else {
                advance(&mut tx, &locked, Some(&next)).await.unwrap();
            }
            tx.commit().await.unwrap();
            sealed.push(bytes);
        }
        let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_heads WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(kept, RETENTION + 1);
        let current = sealed.last().unwrap();
        let anchored_at = |sequence: i64| {
            check(
                &keys,
                BINDING,
                &incarnation,
                None,
                &sealed[sequence as usize - 1],
                None,
            )
            .unwrap()
            .verified
            .unwrap()
            .anchor()
            .clone()
        };
        // A gap of exactly RETENTION: shown, and it descends.
        let at = total - RETENTION;
        let segment = whole(&pool, user_id, at).await.expect("within the window");
        assert_eq!(segment.len() as i64, RETENTION + 1);
        let checked = check(
            &keys,
            BINDING,
            &incarnation,
            Some(&anchored_at(at)),
            current,
            Some(&segment),
        )
        .unwrap();
        assert_eq!(checked.status, HeadStatus::Extends);
        // A gap of RETENTION + 1: too old, and the client agrees.
        let at = total - RETENTION - 1;
        assert!(whole(&pool, user_id, at).await.is_none());
        let checked = check(
            &keys,
            BINDING,
            &incarnation,
            Some(&anchored_at(at)),
            current,
            None,
        )
        .unwrap();
        assert_eq!(checked.status, HeadStatus::TooOld);
        // Above the newest: nothing to show.
        assert_eq!(whole(&pool, user_id, total + 1).await.unwrap().len(), 0);
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
