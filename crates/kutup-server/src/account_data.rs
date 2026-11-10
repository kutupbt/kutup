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

use kutup_crypto::server_data::{DataKey, Field};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::opaque_setup::OpaqueSetupKeys;

/// The generation every key has until keys are rotated per account.
const GENERATION: u32 = 1;

/// How many keys one run of the batched rewrap moves to the current entry.
pub const REWRAP_BATCH: i64 = 500;

fn current(keys: &OpaqueSetupKeys) -> AppResult<(u16, &[u8; 32])> {
    keys.current()
        .ok_or_else(|| AppError::internal("the server key list (OPAQUE_SETUP_KEYS) is empty"))
}

/// The server key list, set once at start ([`install`]), for code that runs
/// inside a transaction and has no state to hand (the security log).
static KEYS: std::sync::OnceLock<OpaqueSetupKeys> = std::sync::OnceLock::new();

/// Keeps the server key list for [`installed`]. At start, once.
pub fn install(keys: &OpaqueSetupKeys) {
    let _ = KEYS.set(keys.clone());
}

/// The key list [`install`] kept; none before the server started (unit tests).
pub fn installed() -> Option<&'static OpaqueSetupKeys> {
    KEYS.get()
}

/// The account's data key, when it has one, wrapped again under the current
/// entry when an older one wraps it. Never makes a key: what was sealed under
/// a key that is gone stays unreadable ([`open`] says so).
pub async fn load(
    pool: &PgPool,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
) -> AppResult<Option<DataKey>> {
    let mut conn = pool.acquire().await?;
    load_in(&mut conn, keys, user_id).await
}

/// [`load`] on a connection, so it runs in the caller's transaction.
pub async fn load_in(
    conn: &mut sqlx::PgConnection,
    keys: &OpaqueSetupKeys,
    user_id: Uuid,
) -> AppResult<Option<DataKey>> {
    let (current_id, current_entry) = current(keys)?;
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped FROM account_keys.account_data_keys WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(wrapped) = stored else {
        return Ok(None);
    };
    let (entry_id, _) = kutup_crypto::server_data::inspect_wrapped(&wrapped).map_err(internal)?;
    let key = DataKey::unwrap(&wrapped, user_id.as_bytes(), |id| keys.get(id)).map_err(|_| {
        AppError::internal(format!(
            "an account data key does not open under server key list entry {entry_id}"
        ))
    })?;
    if entry_id != current_id {
        rewrap(
            &mut *conn,
            user_id,
            &key,
            &wrapped,
            current_id,
            current_entry,
        )
        .await?;
    }
    Ok(Some(key))
}

/// The account's data key for sealing: [`load`]ed, or made (wrapped under the
/// current entry) when it has none yet. Only sealing makes one.
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
    if let Some(key) = load_in(&mut *conn, keys, user_id).await? {
        return Ok(key);
    }
    let (current_id, current_entry) = current(keys)?;
    let key = DataKey::generate(GENERATION).map_err(internal)?;
    let wrapped = key
        .wrap(current_entry, current_id, user_id.as_bytes())
        .map_err(internal)?;
    // Another request may make it first: then that one is the key.
    let made = sqlx::query(
        "INSERT INTO account_keys.account_data_keys
             (user_id, sealing_key_id, generation, wrapped)
         VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(current_id as i16)
    .bind(GENERATION as i32)
    .bind(&wrapped)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if made == 1 {
        return Ok(key);
    }
    load_in(conn, keys, user_id)
        .await?
        .ok_or_else(|| AppError::internal("an account data key went while it was made"))
}

/// Wraps `key` again under the current entry, only if the row still holds
/// `old` (another instance may have done it already).
async fn rewrap(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    key: &DataKey,
    old: &[u8],
    current_id: u16,
    current_entry: &[u8; 32],
) -> AppResult<()> {
    let wrapped = key
        .wrap(current_entry, current_id, user_id.as_bytes())
        .map_err(internal)?;
    sqlx::query(
        "UPDATE account_keys.account_data_keys SET sealing_key_id = $2, wrapped = $3
          WHERE user_id = $1 AND wrapped = $4",
    )
    .bind(user_id)
    .bind(current_id as i16)
    .bind(&wrapped)
    .bind(old)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Moves up to [`REWRAP_BATCH`] keys still wrapped under an older entry to the
/// current one, in account order from after `after`. Returns how many it
/// moved and where to go on from: none once it reached the end, so the next
/// run starts over (a key that does not open is passed, never retried at
/// once ahead of the rest).
pub async fn rewrap_some(
    pool: &PgPool,
    keys: &OpaqueSetupKeys,
    after: Uuid,
) -> AppResult<(u64, Option<Uuid>)> {
    let (current_id, current_entry) = current(keys)?;
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT user_id, wrapped FROM account_keys.account_data_keys
          WHERE sealing_key_id <> $1 AND user_id > $3
          ORDER BY user_id LIMIT $2",
    )
    .bind(current_id as i16)
    .bind(REWRAP_BATCH)
    .bind(after)
    .fetch_all(pool)
    .await?;
    let next = (rows.len() as i64 == REWRAP_BATCH)
        .then(|| rows.last().map(|(user_id, _)| *user_id))
        .flatten();
    let mut moved = 0;
    for (user_id, wrapped) in rows {
        let Ok(key) = DataKey::unwrap(&wrapped, user_id.as_bytes(), |id| keys.get(id)) else {
            // Its entry is missing: `check_entries` stops the server before
            // this runs, so this is a key changed meanwhile; left as it is.
            continue;
        };
        let mut conn = pool.acquire().await?;
        rewrap(
            &mut conn,
            user_id,
            &key,
            &wrapped,
            current_id,
            current_entry,
        )
        .await?;
        moved += 1;
    }
    Ok((moved, next))
}

/// At start: the keys' foreign key to the accounts is there. A restore that
/// adds it back over keys of accounts it doesn't hold fails to, and leaves the
/// keys without their cascade: deleting an account would then keep its key.
pub async fn check_cascade(pool: &PgPool) -> Result<(), String> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint
                         WHERE conrelid = 'account_keys.account_data_keys'::regclass
                           AND contype = 'f' AND confdeltype = 'c')",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("read the account data keys' constraints: {e}"))?;
    if present {
        Ok(())
    } else {
        Err(
            "the account data keys have no foreign key to the accounts (a restore \
             skipped a step): delete the keys of accounts that are not there and add it \
             back (docs/self-hosting.md, \"Database backups\")"
                .into(),
        )
    }
}

/// At start: every entry that still wraps a key must be in the list, else
/// those accounts' fields could not be read. Names the missing entries and how
/// many keys each wraps.
pub async fn check_entries(pool: &PgPool, keys: &OpaqueSetupKeys) -> Result<(), String> {
    let counts: Vec<(i16, i64)> = sqlx::query_as(
        "SELECT sealing_key_id, COUNT(*) FROM account_keys.account_data_keys
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
        .map(|(id, count)| format!("entry {id} wraps {count} account data keys"))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the server key list (OPAQUE_SETUP_KEYS) lacks entries still in use: {}. \
             Put them back; an entry can be removed only once no key uses it \
             (docs/self-hosting.md, \"Rotating the server key list\")",
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
    let Some(key) = load(pool, keys, user_id).await? else {
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
