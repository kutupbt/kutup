//! The account's stored roots (docs/plans/identity-root.md): five account
//! records sealed under the master key, which the server keeps and hands
//! back only to the account (after its password, or to its session). It
//! checks each record's form, purpose, binding and generation; it can open
//! none.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_record::{self, AccountRecordPurpose};
use kutup_crypto::account_roots::{RootGeneration, PURPOSES};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// One root record, checked.
pub struct Root {
    purpose: AccountRecordPurpose,
    object: Vec<u8>,
    envelope: Vec<u8>,
}

fn invalid(why: &str) -> AppError {
    AppError::bad_request(format!("accountRoots: {why}"))
        .with_details(serde_json::json!({ "code": "accountRootsInvalid" }))
}

/// A new account's roots (`accountRoots`, canonical base64): one record of
/// each purpose, the identity and Drive roots at generation 1, each well
/// formed and bound to the account's key `binding`.
pub fn checked_first(values: &[String], binding: &str) -> AppResult<Vec<Root>> {
    if values.len() != PURPOSES.len() {
        return Err(invalid("one record of each root"));
    }
    let mut roots = Vec::with_capacity(values.len());
    for value in values {
        let envelope = account_record::decode_canonical_b64(value)
            .map_err(|_| invalid("a record is not canonical base64"))?;
        let header =
            account_record::inspect(&envelope).map_err(|_| invalid("a record is malformed"))?;
        if !PURPOSES.contains(&header.purpose) {
            return Err(invalid("a record is not an account root"));
        }
        if roots
            .iter()
            .any(|root: &Root| root.purpose == header.purpose)
        {
            return Err(invalid("a root is given twice"));
        }
        // Every root's object is its generation: a new account's are 1.
        let object = RootGeneration::FIRST.object().to_vec();
        account_record::validate_for(&envelope, header.purpose, binding, &object)
            .map_err(|_| invalid("a record is not this account's first"))?;
        roots.push(Root {
            purpose: header.purpose,
            object,
            envelope,
        });
    }
    Ok(roots)
}

/// The roots' purposes as stored (`account_roots.purpose`), for `= ANY($n)`:
/// the keyring shares the table but is not a root.
pub fn purpose_codes() -> Vec<i16> {
    PURPOSES
        .iter()
        .map(|purpose| purpose.as_u16() as i16)
        .collect()
}

/// Stores `roots` for `user_id` (its first: an account that has none).
pub async fn store(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    roots: &[Root],
) -> AppResult<()> {
    for root in roots {
        sqlx::query(
            "INSERT INTO account_roots (account_id, purpose, object, envelope) VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(root.purpose.as_u16() as i16)
        .bind(&root.object)
        .bind(&root.envelope)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Drops every root of `user_id`: a reset makes new ones (with a new master
/// key, so the old ones would open for no one).
pub async fn delete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM account_roots WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// The newest generation of `user_id`'s Drive root: what its owner copies
/// (owned folder keys, link keys) are sealed under and name in their
/// revision (docs/plans/identity-rotation.md §3).
pub async fn drive_generation<'e, E>(executor: E, user_id: Uuid) -> AppResult<RootGeneration>
where
    E: sqlx::PgExecutor<'e>,
{
    // The object is the generation, u32 big-endian: bytes order as numbers.
    let object: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT object FROM account_roots WHERE account_id = $1 AND purpose = $2
         ORDER BY object DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(AccountRecordPurpose::DriveRoot.as_u16() as i16)
    .fetch_optional(executor)
    .await?;
    object
        .and_then(|object| <[u8; 4]>::try_from(object.as_slice()).ok())
        .and_then(|bytes| RootGeneration::new(u32::from_be_bytes(bytes)).ok())
        .ok_or_else(|| AppError::conflict("the account has no Drive root"))
}

/// Every root record of `user_id`, canonical base64, in purpose order and
/// newest generation first.
pub async fn load<'e, E>(executor: E, user_id: Uuid) -> AppResult<Vec<String>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT envelope FROM account_roots WHERE account_id = $1 AND purpose = ANY($2)
          ORDER BY purpose, object DESC",
    )
    .bind(user_id)
    .bind(purpose_codes())
    .fetch_all(executor)
    .await?;
    Ok(rows
        .iter()
        .map(|envelope| STANDARD.encode(envelope))
        .collect())
}

/// The account's master-key keyring (canonical base64): each
/// previous master key sealed under the one after it, newest first
/// (docs/plans/mk-rotation-exercise.md). Empty before a first rotation.
pub async fn load_keyring<'e, E>(executor: E, user_id: Uuid) -> AppResult<Vec<String>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT envelope FROM account_roots WHERE account_id = $1 AND purpose = $2
          ORDER BY object DESC",
    )
    .bind(user_id)
    .bind(AccountRecordPurpose::MasterKeyKeyring.as_u16() as i16)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .iter()
        .map(|envelope| STANDARD.encode(envelope))
        .collect())
}

/// What a client needs to open the account's keys besides its password or
/// session: the master key's generation, the keyring, the roots and the
/// authority the newest identity root must derive.
pub struct AccountKeys {
    pub master_key_generation: u32,
    pub master_keyring: Vec<String>,
    pub account_roots: Vec<String>,
    pub account_authority_public_key: String,
}

/// [`AccountKeys`] of `user_id`, read in one snapshot.
pub async fn account_keys(pool: &sqlx::PgPool, user_id: Uuid) -> AppResult<AccountKeys> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let (authority, generation): (String, i32) = sqlx::query_as(
        "SELECT kutup_b64(account_authority_public_key), master_key_generation FROM accounts
         WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let keys = AccountKeys {
        master_key_generation: u32::try_from(generation)
            .map_err(|_| AppError::internal("master_key_generation out of range"))?,
        master_keyring: load_keyring(&mut *tx, user_id).await?,
        account_roots: load(&mut *tx, user_id).await?,
        account_authority_public_key: authority,
    };
    tx.commit().await?;
    Ok(keys)
}

/// The caller's own roots and the authority the newest identity root must
/// derive.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountRootsResponse {
    /// The root records (account records, canonical base64), every kept
    /// generation.
    account_roots: Vec<String>,
    /// The account's authority public key (base64): the newest identity
    /// root's must equal it.
    account_authority_public_key: String,
    /// The master key's current generation, and every older key's keyring
    /// record (newest first): what opens records sealed before a rotation.
    master_key_generation: u32,
    master_keyring: Vec<String>,
}

/// `GET /api/account/roots` — the caller's own root records and master-key
/// keyring, for a client that holds the master key but not the roots.
#[utoipa::path(
    get,
    path = "/api/account/roots",
    tag = "account",
    security(("BearerAuth" = [])),
    responses((status = 200, body = AccountRootsResponse))
)]
pub async fn get(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let keys = account_keys(&state.pool, user_id).await?;
    Ok(Json(AccountRootsResponse {
        account_roots: keys.account_roots,
        account_authority_public_key: keys.account_authority_public_key,
        master_key_generation: keys.master_key_generation,
        master_keyring: keys.master_keyring,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::account_record::MasterKeyGeneration;
    use kutup_crypto::account_roots::AccountRoots;

    const BINDING: &str = "4b0a3c52-9a1e-4d1c-9a55-0d3f4f6e1b2a";

    fn first() -> Vec<String> {
        AccountRoots::generate()
            .seal(&[7u8; 32], MasterKeyGeneration::FIRST, BINDING)
            .unwrap()
            .iter()
            .map(|e| STANDARD.encode(e))
            .collect()
    }

    #[test]
    fn a_new_accounts_roots_are_checked() {
        assert_eq!(checked_first(&first(), BINDING).unwrap().len(), 5);
        // Another account's binding.
        assert!(checked_first(&first(), "5c1b4d63-0b2f-4e2d-8b66-1e4f5a7f2c3b").is_err());
        // One missing, one twice.
        let mut fewer = first();
        fewer.pop();
        assert!(checked_first(&fewer, BINDING).is_err());
        let mut doubled = first();
        doubled[4] = doubled[3].clone();
        assert!(checked_first(&doubled, BINDING).is_err());
        // Not base64, not a root.
        let mut garbage = first();
        garbage[0] = "not base64".into();
        assert!(checked_first(&garbage, BINDING).is_err());
        let mut other = first();
        other[0] = STANDARD.encode(
            account_record::seal(
                &[1u8; 32],
                &[7u8; 32],
                AccountRecordPurpose::ChatBackupRoot,
                MasterKeyGeneration::FIRST,
                BINDING,
            )
            .unwrap(),
        );
        assert!(checked_first(&other, BINDING).is_err());
        // An identity root of generation 2 is no first one.
        let mut second = first();
        second[0] = STANDARD.encode(
            account_record::seal_object(
                &[1u8; 32],
                &[7u8; 32],
                AccountRecordPurpose::IdentityRoot,
                MasterKeyGeneration::FIRST,
                BINDING,
                &RootGeneration::new(2).unwrap().object(),
            )
            .unwrap(),
        );
        assert!(checked_first(&second, BINDING).is_err());
    }

    /// An account's roots are stored with it and go with it.
    #[tokio::test]
    async fn live_an_accounts_roots_go_with_it() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO accounts (id, username, identity_suite, drive_key_binding_epoch, master_key_generation) VALUES ($1, $2, 2, 1, 1)")
            .bind(user)
            .bind(format!("roots{}", &user.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let roots = checked_first(&first(), BINDING).unwrap();
        let mut tx = pool.begin().await.unwrap();
        store(&mut tx, user, &roots).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(load(&pool, user).await.unwrap().len(), 5);
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert!(load(&pool, user).await.unwrap().is_empty());
    }
}
