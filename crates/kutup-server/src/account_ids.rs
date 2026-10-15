//! Permanent account ids (docs/plans/account-ids.md): a person is their
//! server and their account id (`users.id`), never their name.

use kutup_crypto::account_ref::AccountRef;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// This server's account `user_id`.
pub fn local(server_name: &str, user_id: Uuid) -> AppResult<AccountRef> {
    AccountRef::new(server_name, &user_id.to_string())
        .map_err(|_| AppError::internal("this server's name or an account id is not canonical"))
}

/// An account as this server stored it (a share's recipient on another
/// server): checked when it was stored, so a fault here is internal.
pub fn stored(server: &str, account_id: Uuid) -> AppResult<AccountRef> {
    AccountRef::new(server, &account_id.to_string())
        .map_err(|_| AppError::internal("a stored account is not canonical"))
}

/// Another server's account, as a request or a peer names it: `400` when
/// either part is not canonical.
pub fn remote(server: &str, account_id: &str) -> AppResult<AccountRef> {
    AccountRef::new(server, account_id)
        .map_err(|_| AppError::bad_request("an account is a server and an account id"))
}

/// A peer's answer naming an account: a bad gateway when it is not canonical.
pub fn from_peer(server: &str, account_id: &str) -> AppResult<AccountRef> {
    AccountRef::new(server, account_id).map_err(|_| {
        AppError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "the other server named an account wrongly",
        )
    })
}

/// The key of the proofs `POST /api/auth/opaque/register/start` gives with a
/// minted account id, so that `register` takes back only an id this server
/// minted for that key binding (stateless, like the registration answer).
async fn proof_key(state: &crate::AppState) -> AppResult<[u8; 32]> {
    use hmac::{Hmac, Mac};
    static KEY: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();
    KEY.get_or_try_init(|| async {
        let root = crate::handlers::auth::fake_accounts_key(state).await?;
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&root).expect("any key length");
        mac.update(b"kutup/account-id-proof/v1\0");
        Ok::<_, AppError>(mac.finalize().into_bytes().into())
    })
    .await
    .copied()
}

fn proof_tag(key: &[u8; 32], key_binding: &str, account_id: Uuid) -> hmac::Hmac<sha2::Sha256> {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(key_binding.as_bytes());
    mac.update(&[0]);
    mac.update(account_id.as_bytes());
    mac
}

/// A new account id for a sign-up under `key_binding`, and its proof (hex).
/// The id is random, as Signal mints an ACI at registration; the client signs
/// its Drive key binding for it before the account exists.
pub async fn mint(state: &crate::AppState, key_binding: &str) -> AppResult<(Uuid, String)> {
    use hmac::Mac;
    let id = Uuid::new_v4();
    let key = proof_key(state).await?;
    Ok((
        id,
        hex::encode(proof_tag(&key, key_binding, id).finalize().into_bytes()),
    ))
}

/// The account id a sign-up gives back, if this server minted it for this
/// key binding and no account has, or ever had, it (ids are never reused: a
/// deleted account's is retired, so nobody can come back as that person).
pub async fn redeem(
    state: &crate::AppState,
    conn: &mut sqlx::PgConnection,
    key_binding: &str,
    account_id: &str,
    proof: &str,
) -> AppResult<Uuid> {
    use hmac::Mac;
    let invalid = || {
        AppError::bad_request("the account id was not given by this server")
            .with_details(serde_json::json!({ "code": "accountIdInvalid" }))
    };
    let id = Uuid::parse_str(account_id)
        .ok()
        .filter(|id| id.hyphenated().to_string() == account_id)
        .ok_or_else(invalid)?;
    let tag = hex::decode(proof).map_err(|_| invalid())?;
    let key = proof_key(state).await?;
    proof_tag(&key, key_binding, id)
        .verify_slice(&tag)
        .map_err(|_| invalid())?;
    let used: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)
             OR EXISTS (SELECT 1 FROM retired_account_ids WHERE id = $1)",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    if used {
        return Err(AppError::conflict("that account id is taken: start again")
            .with_details(serde_json::json!({ "code": "accountIdTaken" })));
    }
    Ok(id)
}

/// Retires a deleted account's id, in the deletion's transaction: no new
/// account is ever given it.
pub async fn retire(conn: &mut sqlx::PgConnection, account_id: Uuid) -> AppResult<()> {
    sqlx::query("INSERT INTO retired_account_ids (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
