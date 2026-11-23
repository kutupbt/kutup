//! Drive identity (docs/plans/drive-identity-pins.md): accounts' bindings of
//! their Drive keys to their authorities (signed at registration or
//! first-login setup), and an account's synced pins on other accounts.
//!
//! The server checks a binding before storing it but trusts nothing it says:
//! clients verify bindings themselves against the authorities they pinned.
//! The pin list is the one record of the account-records scope `pins`
//! (docs/plans/account-records.md), kept by the records store.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthAccount;
use crate::AppState;

/// The answer to sharing with an account still on identity suite 1 (an
/// X25519 Drive key, docs/plans/pq-shares.md): nothing is sealed to it; its
/// owner's next sign-in upgrades it.
pub(crate) fn keys_pending_upgrade() -> AppError {
    AppError::conflict(
        "this person's keys are being upgraded: share with them once they have signed in again",
    )
    .with_details(serde_json::json!({ "code": "keysPendingUpgrade" }))
}

/// Refuses (`keysPendingUpgrade`) a share to a local account that has no
/// keys yet: one an administrator made or reset, until its first sign-in
/// sets them up (`keys_set_up_at`).
pub(crate) async fn require_sealable<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: uuid::Uuid,
) -> AppResult<()> {
    let set_up: Option<bool> =
        sqlx::query_scalar("SELECT keys_set_up_at IS NOT NULL FROM accounts WHERE id = $1")
            .bind(user_id)
            .fetch_optional(executor)
            .await?;
    match set_up {
        Some(false) => Err(keys_pending_upgrade()),
        _ => Ok(()),
    }
}

/// The most accounts one identity lookup answers.
const MAX_IDENTITIES_PER_LOOKUP: usize = 100;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DriveIdentitiesRequest {
    /// Canonical `username@<this server>` addresses (at most 100).
    accounts: Vec<String>,
}

/// One account's published Drive identity.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DriveIdentity {
    /// Who it is: the server and the permanent account id.
    server: String,
    account_id: String,
    /// The address asked for, server-asserted: a lookup handle only.
    account: String,
    account_authority_public_key: String,
    drive_xwing_public_key: String,
    drive_signing_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    drive_key_binding: Option<String>,
    /// 2: an X-Wing Drive key. 1: an X25519 one, not yet upgraded; nothing is
    /// shared to it (`keysPendingUpgrade`; docs/plans/pq-shares.md).
    identity_suite: i16,
    /// The binding's epoch (1 today). Clients don't keep the highest per account
    /// yet; pins must record it before any epoch 2 is signed.
    drive_key_binding_epoch: i32,
}

/// `POST /api/v1/drive/identities` — the Drive identities of accounts on
/// this server, by exact address, many at once: a page that shows who shared
/// what checks every person with one request (docs/plans/drive-identity-pins.md).
/// Unknown or disabled accounts are left out. Rate-limited with the user
/// lookups, each request counting once.
#[utoipa::path(
    post,
    path = "/api/v1/drive/identities",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = DriveIdentitiesRequest,
    responses((status = 200, description = "The identities found", body = [DriveIdentity]))
)]
pub async fn drive_identities(
    State(state): State<AppState>,
    _user: AuthAccount,
    Json(req): Json<DriveIdentitiesRequest>,
) -> AppResult<Response> {
    if req.accounts.len() > MAX_IDENTITIES_PER_LOOKUP {
        return Err(AppError::bad_request("too many accounts in one lookup"));
    }
    let suffix = format!("@{}", state.config.chat_server_name);
    let usernames: Vec<String> = req
        .accounts
        .iter()
        .filter_map(|account| account.strip_suffix(&suffix))
        .filter(|username| !username.is_empty() && !username.contains('@'))
        .map(str::to_owned)
        .collect();
    type Row = (
        uuid::Uuid,
        String,
        String,
        String,
        String,
        Option<String>,
        i16,
        i32,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, username, kutup_b64(account_authority_public_key), kutup_b64(drive_xwing_public_key),
                kutup_b64(drive_signing_public_key),
                kutup_b64(drive_key_binding), identity_suite, drive_key_binding_epoch
           FROM accounts
          WHERE id IN (SELECT kutup_current_account(name) FROM unnest($1::text[]) AS name)
            AND state = 'active' AND keys_set_up_at IS NOT NULL",
    )
    .bind(&usernames)
    .fetch_all(&state.pool)
    .await?;
    let identities: Vec<DriveIdentity> = rows
        .into_iter()
        .map(
            |(id, username, authority, hpke, signing, binding, suite, epoch)| DriveIdentity {
                server: state.config.chat_server_name.clone(),
                account_id: id.to_string(),
                account: format!("{username}{suffix}"),
                account_authority_public_key: authority,
                drive_xwing_public_key: hpke,
                drive_signing_public_key: signing,
                drive_key_binding: binding,
                identity_suite: suite,
                drive_key_binding_epoch: epoch,
            },
        )
        .collect();
    Ok(Json(identities).into_response())
}
