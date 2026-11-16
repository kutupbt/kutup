//! Each account's data key (docs/plans/server-personal-data.md, A2): the key
//! the server seals an account's server-side personal fields under
//! (`kutup_crypto::server_data`), kept in `account_keys.account_data_keys`
//! wrapped under an entry of the server key list (`OPAQUE_SETUP_KEYS`).
//!
//! - A key is made when an account first has something to seal, and goes with
//!   the account (the foreign key cascades): its fields are then unreadable
//!   in every copy, backups included, since the key schema is kept out of the
//!   database dump and its own dump is kept only briefly.
//! - A key wrapped under an older entry is wrapped again under the current one
//!   when it is used, and by a batched job ([`rewrap_some`]); an entry still
//!   wrapping keys must stay in the list ([`check_entries`]).
//! - A shared mail mailbox (a mail group) has a key of its own
//!   (`account_keys.mail_group_data_keys`), for its messages' sealed headers;
//!   it goes with the group. [`KeyOwner`] names whose key.

use kutup_crypto::server_data::{DataKey, Field};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::opaque_setup::OpaqueSetupKeys;

/// An account's first key's generation; a key that is lost is followed by
/// the next one.
const GENERATION: u32 = 1;

/// How many keys one run of the batched rewrap moves to the current entry.
pub const REWRAP_BATCH: i64 = 500;

fn current(keys: &OpaqueSetupKeys) -> AppResult<(u16, &[u8; 32])> {
    keys.current()
        .ok_or_else(|| AppError::internal("the server key list (OPAQUE_SETUP_KEYS) is empty"))
}

/// Whose data key: an account's, or a mail group's (a shared mailbox's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOwner {
    Account(Uuid),
    MailGroup(Uuid),
}

impl KeyOwner {
    pub fn id(self) -> Uuid {
        match self {
            KeyOwner::Account(id) | KeyOwner::MailGroup(id) => id,
        }
    }

    /// The table the keys are in, and the column naming their owner.
    fn table(self) -> (&'static str, &'static str) {
        match self {
            KeyOwner::Account(_) => TABLES[0],
            KeyOwner::MailGroup(_) => TABLES[1],
        }
    }

    fn of_table(index: usize, id: Uuid) -> Self {
        if index == 0 {
            KeyOwner::Account(id)
        } else {
            KeyOwner::MailGroup(id)
        }
    }
}

/// Every table of data keys, with the column naming the owner.
const TABLES: [(&str, &str); 2] = [
    ("account_keys.account_data_keys", "user_id"),
    ("account_keys.mail_group_data_keys", "group_id"),
];

/// The server key list, set once at start ([`install`]), for code that runs
/// inside a transaction and has no state to hand (the security log).
static KEYS: std::sync::OnceLock<OpaqueSetupKeys> = std::sync::OnceLock::new();

/// The server's pool, for flagging a lost key off the caller's connection.
static POOL: std::sync::OnceLock<PgPool> = std::sync::OnceLock::new();

/// Keeps the server key list for [`installed`], and the pool. At start, once.
pub fn install(keys: &OpaqueSetupKeys, pool: &PgPool) {
    let _ = KEYS.set(keys.clone());
    let _ = POOL.set(pool.clone());
}

/// The key list [`install`] kept; none before the server started (unit tests).
pub fn installed() -> Option<&'static OpaqueSetupKeys> {
    KEYS.get()
}

/// The account's data key of `generation` (the newest when None), when it
/// has one that opens. Never makes a key, and never writes: a key under an
/// older entry moves to the current one by the batched job
/// ([`rewrap_some`]), so a read takes no lock in its caller's transaction.
/// What was sealed under a key that is gone, or doesn't open, stays
/// unreadable ([`open`] says so).
pub async fn load(
    pool: &PgPool,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
    generation: Option<u32>,
) -> AppResult<Option<DataKey>> {
    let mut conn = pool.acquire().await?;
    load_in(&mut conn, keys, user_id, generation).await
}

/// [`load`] on a connection, so it runs in the caller's transaction.
pub async fn load_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
    generation: Option<u32>,
) -> AppResult<Option<DataKey>> {
    load_owner_in(conn, keys, KeyOwner::Account(user_id), generation).await
}

/// [`load_in`] for any owner.
pub async fn load_owner_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    owner: KeyOwner,
    generation: Option<u32>,
) -> AppResult<Option<DataKey>> {
    let (table, column) = owner.table();
    let stored: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT wrapped FROM {table}
          WHERE {column} = $1 AND ($2::integer IS NULL OR generation = $2)
          ORDER BY generation DESC LIMIT 1"
    ))
    .bind(owner.id())
    .bind(generation.map(|g| g as i32))
    .fetch_optional(&mut *conn)
    .await?;
    let Some(wrapped) = stored else {
        return Ok(None);
    };
    match DataKey::unwrap(&wrapped, owner.id().as_bytes(), |id| keys.get(id)) {
        Ok(key) => Ok(Some(key)),
        Err(_) => {
            // There, but it doesn't open: restored from another deployment,
            // or an entry's bytes changed under its id. Its fields are lost
            // as if it were gone; the operator is told loudly.
            lost(owner, &wrapped);
            Ok(None)
        }
    }
}

/// A key that doesn't open: an error in the log, and the account flagged for
/// the admin console. Off the caller's connection (on the server's pool, when
/// installed), so a read never waits.
fn lost(owner: KeyOwner, wrapped: &[u8]) {
    let entry = kutup_crypto::server_data::inspect_wrapped(wrapped)
        .map(|(entry, _)| entry.to_string())
        .unwrap_or_else(|_| "?".into());
    tracing::error!(
        ?owner,
        entry,
        "a data key does not open under the server key list: its sealed fields are lost"
    );
    // The admin console flags accounts; a mail group's loss is in the log.
    let KeyOwner::Account(user_id) = owner else {
        return;
    };
    if let Some(pool) = POOL.get().cloned() {
        tokio::spawn(async move {
            let _ = sqlx::query(
                "UPDATE users SET data_key_lost_at = now()
                  WHERE id = $1 AND data_key_lost_at IS NULL",
            )
            .bind(user_id)
            .execute(&pool)
            .await;
        });
    }
}

/// Every generation of the account's data key that opens, newest first (a
/// list opens its rows with the one each names). Never makes a key.
pub async fn load_all_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
) -> AppResult<Vec<DataKey>> {
    load_all_owner_in(conn, keys, KeyOwner::Account(user_id)).await
}

/// [`load_all_in`] for any owner.
pub async fn load_all_owner_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    owner: KeyOwner,
) -> AppResult<Vec<DataKey>> {
    let (table, column) = owner.table();
    let generations: Vec<i32> = sqlx::query_scalar(&format!(
        "SELECT generation FROM {table} WHERE {column} = $1 ORDER BY generation DESC"
    ))
    .bind(owner.id())
    .fetch_all(&mut *conn)
    .await?;
    let mut all = Vec::with_capacity(generations.len());
    for generation in generations {
        if let Some(key) = load_owner_in(&mut *conn, keys, owner, Some(generation as u32)).await? {
            all.push(key);
        }
    }
    Ok(all)
}

/// The account's data key for sealing: its newest generation [`load`]ed, or
/// made (wrapped under the current entry) when it has none that opens: a
/// lost one is followed by a new generation, so new fields seal again.
pub async fn key(pool: &PgPool, keys: &OpaqueSetupKeys, user_id: Uuid) -> AppResult<DataKey> {
    let mut conn = pool.acquire().await?;
    key_in(&mut conn, keys, user_id).await
}

/// [`key`] on a connection, so it runs in the caller's transaction (on that
/// one connection: never a second one while the transaction holds the
/// account's row).
pub async fn key_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
) -> AppResult<DataKey> {
    key_owner_in(conn, keys, KeyOwner::Account(user_id)).await
}

/// [`key_in`] for any owner.
pub async fn key_owner_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    owner: KeyOwner,
) -> AppResult<DataKey> {
    if let Some(key) = load_owner_in(&mut *conn, keys, owner, None).await? {
        return Ok(key);
    }
    let (table, column) = owner.table();
    let (current_id, current_entry) = current(keys)?;
    let newest: Option<i32> = sqlx::query_scalar(&format!(
        "SELECT max(generation) FROM {table} WHERE {column} = $1"
    ))
    .bind(owner.id())
    .fetch_one(&mut *conn)
    .await?;
    let generation = newest.map_or(GENERATION, |g| g as u32 + 1);
    let key = DataKey::generate(generation).map_err(internal)?;
    let wrapped = key
        .wrap(current_entry, current_id, owner.id().as_bytes())
        .map_err(internal)?;
    // Another request may make it first: then that one is the key.
    let made = sqlx::query(&format!(
        "INSERT INTO {table} ({column}, sealing_key_id, generation, wrapped)
         VALUES ($1, $2, $3, $4) ON CONFLICT ({column}, generation) DO NOTHING"
    ))
    .bind(owner.id())
    .bind(current_id as i16)
    .bind(generation as i32)
    .bind(&wrapped)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if made == 1 {
        return Ok(key);
    }
    load_owner_in(conn, keys, owner, None)
        .await?
        .ok_or_else(|| AppError::internal("a data key went while it was made"))
}

/// Wraps `key` again under the current entry, only if the row still holds
/// `old` (another instance may have done it already).
async fn rewrap(
    conn: &mut sqlx::PgConnection,
    owner: KeyOwner,
    key: &DataKey,
    old: &[u8],
    current_id: u16,
    current_entry: &[u8; 32],
) -> AppResult<()> {
    let (table, column) = owner.table();
    let wrapped = key
        .wrap(current_entry, current_id, owner.id().as_bytes())
        .map_err(internal)?;
    sqlx::query(&format!(
        "UPDATE {table} SET sealing_key_id = $2, wrapped = $3
          WHERE {column} = $1 AND generation = $5 AND wrapped = $4"
    ))
    .bind(owner.id())
    .bind(current_id as i16)
    .bind(&wrapped)
    .bind(old)
    .bind(key.generation() as i32)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Where the batched rewrap goes on from: the table (an index into the
/// tables of keys), and the last owner and generation it read there.
pub type RewrapCursor = (usize, Uuid, i32);

/// Where the batched rewrap starts.
pub const REWRAP_START: RewrapCursor = (0, Uuid::nil(), 0);

/// Moves up to [`REWRAP_BATCH`] keys still wrapped under an older entry to the
/// current one, table by table in owner order from after `after`. Returns how
/// many it moved and where to go on from: none once it reached the end, so
/// the next run starts over (a key that does not open is passed, never
/// retried at once ahead of the rest).
pub async fn rewrap_some(
    pool: &PgPool,
    keys: &OpaqueSetupKeys,
    after: RewrapCursor,
) -> AppResult<(u64, Option<RewrapCursor>)> {
    let (current_id, current_entry) = current(keys)?;
    let (index, after_id, after_generation) = after;
    let Some((table, column)) = TABLES.get(index) else {
        return Ok((0, None));
    };
    let rows: Vec<(Uuid, i32, Vec<u8>)> = sqlx::query_as(&format!(
        "SELECT {column}, generation, wrapped FROM {table}
          WHERE sealing_key_id <> $1 AND ({column}, generation) > ($3, $4)
          ORDER BY {column}, generation LIMIT $2"
    ))
    .bind(current_id as i16)
    .bind(REWRAP_BATCH)
    .bind(after_id)
    .bind(after_generation)
    .fetch_all(pool)
    .await?;
    // A full batch goes on in this table; otherwise the next table, if any.
    let next = if rows.len() as i64 == REWRAP_BATCH {
        rows.last()
            .map(|(id, generation, _)| (index, *id, *generation))
    } else {
        (index + 1 < TABLES.len()).then_some((index + 1, Uuid::nil(), 0))
    };
    let mut moved = 0;
    for (id, _, wrapped) in rows {
        let owner = KeyOwner::of_table(index, id);
        let Ok(key) = DataKey::unwrap(&wrapped, id.as_bytes(), |id| keys.get(id)) else {
            // Its entry is missing: `check_entries` stops the server before
            // this runs, so this is a key changed meanwhile; left as it is.
            continue;
        };
        let mut conn = pool.acquire().await?;
        rewrap(&mut conn, owner, &key, &wrapped, current_id, current_entry).await?;
        moved += 1;
    }
    Ok((moved, next))
}

/// At start: the keys' foreign key to the accounts is there. A restore that
/// adds it back over keys of accounts it doesn't hold fails to, and leaves the
/// keys without their cascade: deleting an account would then keep its key.
pub async fn check_cascade(pool: &PgPool) -> Result<(), String> {
    for (table, _) in TABLES {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint
                             WHERE conrelid = $1::regclass
                               AND contype = 'f' AND confdeltype = 'c')",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("read the constraints of {table}: {e}"))?;
        if !present {
            return Err(format!(
                "{table} has no foreign key to its owners (a restore skipped a step): \
                 delete the keys of owners that are not there and add it back \
                 (docs/self-hosting.md, \"Database backups\")"
            ));
        }
    }
    Ok(())
}

/// At start: every entry that still wraps a key must be in the list, else
/// those accounts' fields could not be read. Names the missing entries and how
/// many keys each wraps.
pub async fn check_entries(pool: &PgPool, keys: &OpaqueSetupKeys) -> Result<(), String> {
    let counts: Vec<(i16, i64)> = sqlx::query_as(
        "SELECT sealing_key_id, COUNT(*)
           FROM (SELECT sealing_key_id FROM account_keys.account_data_keys
                 UNION ALL
                 SELECT sealing_key_id FROM account_keys.mail_group_data_keys) k
          GROUP BY sealing_key_id ORDER BY sealing_key_id",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("read the account data keys: {e}"))?;
    let missing: Vec<String> = counts
        .iter()
        .filter(|(id, _)| {
            u16::try_from(*id)
                .ok()
                .and_then(|id| keys.get(id))
                .is_none()
        })
        .map(|(id, count)| format!("entry {id} wraps {count} data keys"))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the server key list (OPAQUE_SETUP_KEYS) lacks entries still in use: {}. \
             Put them back; an entry can be removed only once no key uses it \
             (docs/self-hosting.md, \"OPAQUE_SETUP_KEYS, the server key list\")",
            missing.join(", ")
        ))
    }
}

/// Seals `value` for the account's `field` (`table`, `column`, `row`).
pub async fn seal(
    pool: &PgPool,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
    (table, column, row): (&str, &str, &str),
    value: &[u8],
) -> AppResult<Vec<u8>> {
    let key = key(pool, keys, user_id).await?;
    key.seal(
        &Field {
            table,
            column,
            row,
            account_id: user_id.as_bytes(),
        },
        value,
    )
    .map_err(internal)
}

/// Opens the account's sealed `field`; None when it is destroyed: the
/// account's key is gone (deleted, or a restore brought back a field without
/// its key) or is not the one it was sealed under. Never makes a key.
pub async fn open(
    pool: &PgPool,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
    (table, column, row): (&str, &str, &str),
    sealed: &[u8],
) -> AppResult<Option<Zeroizing<Vec<u8>>>> {
    let generation = kutup_crypto::server_data::sealed_generation(sealed).map_err(internal)?;
    let Some(key) = load(pool, keys, user_id, Some(generation)).await? else {
        tracing::warn!(%user_id, table, column, "a sealed field has no account data key");
        return Ok(None);
    };
    let opened = key
        .open(
            &Field {
                table,
                column,
                row,
                account_id: user_id.as_bytes(),
            },
            sealed,
        )
        .ok();
    if opened.is_none() {
        tracing::warn!(%user_id, table, column, "a sealed field does not open under the account's key");
    }
    Ok(opened)
}

fn internal(error: kutup_crypto::error::CryptoError) -> AppError {
    AppError::internal(format!("account data key: {error}"))
}
