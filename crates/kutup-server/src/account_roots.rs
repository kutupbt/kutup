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
        let object = match header.purpose {
            AccountRecordPurpose::IdentityRoot | AccountRecordPurpose::DriveRoot => {
                RootGeneration::FIRST.object().to_vec()
            }
            _ => Vec::new(),
        };
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

/// Stores `roots` for `user_id` (its first: an account that has none).
pub async fn store(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    roots: &[Root],
) -> AppResult<()> {
    for root in roots {
        sqlx::query(
            "INSERT INTO account_roots (user_id, purpose, object, envelope) VALUES ($1, $2, $3, $4)",
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
    sqlx::query("DELETE FROM account_roots WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Every root record of `user_id`, canonical base64, in purpose order and
/// newest generation first.
pub async fn load<'e, E>(executor: E, user_id: Uuid) -> AppResult<Vec<String>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT envelope FROM account_roots WHERE user_id = $1 ORDER BY purpose, object DESC",
    )
    .bind(user_id)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .iter()
        .map(|envelope| STANDARD.encode(envelope))
        .collect())
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
}

/// `GET /api/account/roots` — the caller's own root records, for a client
/// that holds the master key but not the roots.
#[utoipa::path(
    get,
    path = "/api/account/roots",
    tag = "account",
    security(("BearerAuth" = [])),
    responses((status = 200, body = AccountRootsResponse))
)]
pub async fn get(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let authority: String =
        sqlx::query_scalar("SELECT account_authority_public_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    Ok(Json(AccountRootsResponse {
        account_roots: load(&state.pool, user_id).await?,
        account_authority_public_key: authority,
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
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '')",
        )
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
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert!(load(&pool, user).await.unwrap().is_empty());
    }
}
