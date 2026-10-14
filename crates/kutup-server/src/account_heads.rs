//! The account head chain (docs/plans/rollback-protection.md).
//!
//! Every write of a listed value (a contact, a mail folder, label or filter
//! name, the identity pins, a Pass vault secret) also writes the account's
//! next head, in its transaction: the head's sequence must be the current
//! one plus one (`409 head_conflict`), and once the account has a head, a
//! listed write without one is refused (`409 head_required`). The server
//! never opens a head; it reads its sequence in clear and keeps the newest
//! [`RETENTION`]. Two first heads at once meet on the primary key, and the
//! second is a `head_conflict` too.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// How many heads are kept: the crate's window, which a client's "too old"
/// is judged by.
pub const RETENTION: i64 = kutup_crypto::account_head::RETENTION as i64;

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

/// Inside the listed write's transaction: makes `next` the account's head.
/// - No head yet and none given: nothing (the account starts its chain at
///   its first write that carries one).
/// - A head kept and none given: `head_required`.
/// - Given: its sequence must follow the current one (1 for the first),
///   else `head_conflict`; older heads past the window go.
pub async fn advance(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    next: Option<&NextHead>,
) -> AppResult<()> {
    // The newest head, locked: a concurrent write of the same account waits
    // here, then meets the primary key below.
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
    if next.sequence != current.unwrap_or(0) + 1 {
        return Err(head_conflict(current));
    }
    let inserted =
        sqlx::query("INSERT INTO account_heads (user_id, sequence, sealed) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind(next.sequence)
            .bind(&next.sealed)
            .execute(&mut **tx)
            .await;
    match inserted {
        Ok(_) => {}
        // Another write took this sequence first (two first heads at once).
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Err(head_conflict(current));
        }
        Err(error) => return Err(error.into()),
    }
    sqlx::query("DELETE FROM account_heads WHERE user_id = $1 AND sequence <= $2")
        .bind(user_id)
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

/// The heads from `from` to the newest, oldest first. `None` when `from` is
/// past the kept window (the device's anchor is too old to show descent
/// from); an empty list when `from` is above the newest.
pub async fn segment(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    from: i64,
) -> AppResult<Option<Vec<Vec<u8>>>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let newest = latest(&mut *tx, user_id)
        .await?
        .map(|(sequence, _)| sequence);
    let Some(newest) = newest else {
        return Ok(Some(Vec::new()));
    };
    if from <= newest - RETENTION {
        return Ok(None);
    }
    let heads: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT sealed FROM account_heads WHERE user_id = $1 AND sequence >= $2
         ORDER BY sequence",
    )
    .bind(user_id)
    .bind(from)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(heads))
}

/// The kinds of listed values (`ScopeV1::scope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Contacts,
    MailNames,
    Pins,
    PassSecrets,
}

impl Scope {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "contacts" => Scope::Contacts,
            "mailNames" => Scope::MailNames,
            "pins" => Scope::Pins,
            "passSecrets" => Scope::PassSecrets,
            _ => return None,
        })
    }
}

/// A scope's index with the head it goes with, read in one snapshot so the
/// two always agree (a write between two separate reads would look like a
/// rollback): the newest head, and every value's `(id, revision)`, sorted
/// by id. Ids per scope: a contact's id; `folder:`, `label:` or `filter:`
/// and the id for mail names (a folder without a name, kept through an
/// account reset, is left out until it is named); `pins` for the one pin list; the vault's file
/// id for a Pass secret (every one the account keeps, trashed or out of reach
/// included: the secret stays until its owner forgets it with a head).
pub async fn index(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    scope: Scope,
) -> AppResult<(Option<Vec<u8>>, Vec<(String, i64)>)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let head = latest(&mut *tx, user_id).await?.map(|(_, sealed)| sealed);
    let mut values: Vec<(String, i64)> = match scope {
        Scope::Contacts => {
            sqlx::query_as("SELECT id::text, revision FROM contacts WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?
        }
        Scope::Pins => {
            sqlx::query_as("SELECT 'pins', revision FROM identity_pins WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&mut *tx)
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
            .fetch_all(&mut *tx)
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
            .fetch_all(&mut *tx)
            .await?;
            rows.into_iter()
                .map(|(id, envelope)| Ok((id, crate::handlers::pass::revision_of(&envelope)?)))
                .collect::<AppResult<_>>()?
        }
    };
    tx.commit().await?;
    values.sort();
    Ok((head, values))
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
    use kutup_crypto::account_head::{seal, AccountHeadV1, HeadKeys};

    /// The window: past `RETENTION` heads the oldest go, and a segment from
    /// before the window is too old, from inside it whole.
    #[tokio::test]
    async fn live_the_chain_keeps_the_window_and_says_too_old_past_it() {
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
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                drive_private_key_envelope, public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '', '')",
        )
        .bind(user_id)
        .bind(format!("heads{}", &user_id.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
        let keys = HeadKeys::derive(&[9; 32]).unwrap();
        let writer = keys.writer("window").unwrap();
        let binding = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        let total = RETENTION + 5;
        let mut head = AccountHeadV1::first(&"cd".repeat(32), &writer, vec![]).unwrap();
        for sequence in 1..=total {
            if sequence > 1 {
                let previous = seal(&keys, binding, &head).unwrap();
                head = head.next(&previous, &writer, vec![]).unwrap();
            }
            let next =
                NextHead::parse(Some(&STANDARD.encode(seal(&keys, binding, &head).unwrap())))
                    .unwrap();
            let mut tx = pool.begin().await.unwrap();
            advance(&mut tx, user_id, next.as_ref()).await.unwrap();
            tx.commit().await.unwrap();
        }
        let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_heads WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(kept, RETENTION);
        // The oldest kept is total - RETENTION + 1; anything at or below
        // total - RETENTION is past the window.
        assert!(segment(&pool, user_id, total - RETENTION)
            .await
            .unwrap()
            .is_none());
        let whole = segment(&pool, user_id, total - RETENTION + 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(whole.len() as i64, RETENTION);
        assert_eq!(
            segment(&pool, user_id, total + 1)
                .await
                .unwrap()
                .unwrap()
                .len(),
            0
        );
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
