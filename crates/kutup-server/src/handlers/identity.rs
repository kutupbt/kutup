//! Drive identity (docs/plans/drive-identity-pins.md): accounts' bindings of
//! their Drive keys to their authorities (signed at registration or
//! first-login setup), and an account's synced pins on other accounts.
//!
//! The server checks a binding before storing it but trusts nothing it says:
//! clients verify bindings themselves against the authorities they pinned.
//! The pin list is opaque here, sealed under a key only the account's master
//! key derives; the server keeps the latest revision and refuses a write that
//! does not name it (two apps writing at once: the second merges and retries).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::{revisions, AppState};

/// The account's sealed pin list.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsBody {
    /// The revision in the envelope's header (authenticated there).
    revision: i64,
    /// Base64 of the sealed list (`kutup_crypto::identity_pins`).
    envelope: String,
}

/// A new sealed list, stored on top of `baseRevision`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityPinsWrite {
    /// The revision the change started from; 0 before the first list.
    base_revision: i64,
    /// Base64 of the sealed list; its header's revision must be above
    /// `baseRevision`.
    envelope: String,
    /// The next sealed account head (base64), once the account keeps one.
    #[serde(default)]
    head: Option<String>,
}

/// `GET /api/user/identity-pins` — the latest list, or `404` before the first.
#[utoipa::path(
    get,
    path = "/api/user/identity-pins",
    tag = "auth",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The sealed list", body = IdentityPinsBody), (status = 404, description = "None yet"))
)]
pub async fn get_identity_pins(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    let row: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT revision, envelope FROM identity_pins WHERE user_id = $1")
            .bind(trusted_uuid(&user.user_id)?)
            .fetch_optional(&state.pool)
            .await?;
    let (revision, envelope) = row.ok_or_else(|| AppError::not_found("no identity pins yet"))?;
    Ok(Json(IdentityPinsBody {
        revision,
        envelope: STANDARD.encode(envelope),
    })
    .into_response())
}

/// `PUT /api/user/identity-pins` — store a new list if the stored one is
/// still `baseRevision` (none yet: 0) and the new list's revision is above
/// it. `409` with `code: "revision_conflict"` and the current revision when
/// another app wrote first.
#[utoipa::path(
    put,
    path = "/api/user/identity-pins",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = IdentityPinsWrite,
    responses(
        (status = 204, description = "Stored"),
        (status = 409, description = "Another list was stored first")
    )
)]
pub async fn put_identity_pins(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<IdentityPinsWrite>,
) -> AppResult<Response> {
    let id = trusted_uuid(&user.user_id)?;
    let envelope = STANDARD
        .decode(&req.envelope)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == req.envelope)
        .ok_or_else(|| AppError::bad_request("envelope is not canonical base64"))?;
    let revision = kutup_crypto::identity_pins::inspect(&envelope)
        .map_err(|_| AppError::bad_request("not an identity pin list"))?;
    let revision = revisions::check_follows(revision, req.base_revision)?;
    let head = crate::account_heads::NextHead::parse(req.head.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let locked = crate::account_heads::lock(&mut tx, id, user.session.session_id).await?;
    let stored = if req.base_revision == 0 {
        sqlx::query(
            "INSERT INTO identity_pins (user_id, revision, envelope) VALUES ($1, $2, $3)
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(id)
        .bind(revision)
        .bind(&envelope)
        .execute(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "UPDATE identity_pins SET revision = $2, envelope = $3, updated_at = NOW()
              WHERE user_id = $1 AND revision = $4",
        )
        .bind(id)
        .bind(revision)
        .bind(&envelope)
        .bind(req.base_revision)
        .execute(&mut *tx)
        .await?
    };
    if stored.rows_affected() == 1 {
        crate::account_heads::advance(&mut tx, &locked, head.as_ref()).await?;
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    drop(tx);
    let current: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM identity_pins WHERE user_id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    Err(revisions::conflict(
        "another list was stored first",
        current.unwrap_or(0),
    ))
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
    account: String,
    account_authority_public_key: String,
    drive_hpke_public_key: String,
    drive_signing_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    drive_key_binding: Option<String>,
}

/// `POST /api/users/drive-identities` — the Drive identities of accounts on
/// this server, by exact address, many at once: a page that shows who shared
/// what checks every person with one request (docs/plans/drive-identity-pins.md).
/// Unknown or disabled accounts are left out. Rate-limited with the user
/// lookups, each request counting once.
#[utoipa::path(
    post,
    path = "/api/users/drive-identities",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = DriveIdentitiesRequest,
    responses((status = 200, description = "The identities found", body = [DriveIdentity]))
)]
pub async fn drive_identities(
    State(state): State<AppState>,
    _user: AuthUser,
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
    let rows: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT username, account_authority_public_key, public_key, drive_signing_public_key, drive_key_binding
           FROM users
          WHERE username = ANY($1) AND is_active AND NOT is_first_login",
    )
    .bind(&usernames)
    .fetch_all(&state.pool)
    .await?;
    let identities: Vec<DriveIdentity> = rows
        .into_iter()
        .map(
            |(username, authority, hpke, signing, binding)| DriveIdentity {
                account: format!("{username}{suffix}"),
                account_authority_public_key: authority,
                drive_hpke_public_key: hpke,
                drive_signing_public_key: signing,
                drive_key_binding: binding,
            },
        )
        .collect();
    Ok(Json(identities).into_response())
}
