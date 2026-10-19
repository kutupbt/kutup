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

/// The answer to sharing with an account still on identity suite 1 (an
/// X25519 Drive key, docs/plans/pq-shares.md): nothing is sealed to it; its
/// owner's next sign-in upgrades it.
pub(crate) fn keys_pending_upgrade() -> AppError {
    AppError::conflict(
        "this person's keys are being upgraded: share with them once they have signed in again",
    )
    .with_details(serde_json::json!({ "code": "keysPendingUpgrade" }))
}

/// Refuses (`keysPendingUpgrade`) a share to a local account that is still
/// on identity suite 1.
pub(crate) async fn require_sealable<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: uuid::Uuid,
) -> AppResult<()> {
    let suite: Option<i16> = sqlx::query_scalar("SELECT identity_suite FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    match suite {
        Some(suite) if suite < kutup_crypto::identity::IDENTITY_SUITE as i16 => {
            Err(keys_pending_upgrade())
        }
        _ => Ok(()),
    }
}

/// An account's one-way move to identity suite 2 (docs/plans/pq-shares.md):
/// its Drive key, derived again from the master key as X-Wing, the binding
/// its unchanged authority signed for it, and the new private key (the
/// X-Wing seed) sealed as before.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentitySuiteUpgrade {
    /// Base64 of the 1216-byte X-Wing public key.
    public_key: String,
    /// Base64 of the suite-2 binding's signature.
    drive_key_binding: String,
    /// The binding's epoch (1 for the first suite-2 binding).
    drive_key_binding_epoch: u32,
    /// The X-Wing seed in its account envelope (purpose DriveHpkePrivateKey).
    drive_private_key_envelope: String,
}

/// `POST /api/account/identity-suite` — moves the account from identity suite
/// 1 (an X25519 Drive key) to suite 2 (X-Wing), once and only upward: the
/// suite must strictly rise, the binding must verify under the account's own
/// authority, and the key, binding and private key change together. The
/// client then publishes its next Chat manifest with the new key. `409` with
/// `code: identitySuiteCurrent` when the account is on suite 2 already.
#[utoipa::path(
    post,
    path = "/api/account/identity-suite",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = IdentitySuiteUpgrade,
    responses(
        (status = 204, description = "Upgraded"),
        (status = 400, description = "Not the account's binding, key or envelope"),
        (status = 409, description = "identitySuiteCurrent: nothing to upgrade")
    )
)]
pub async fn upgrade_identity_suite(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<IdentitySuiteUpgrade>,
) -> AppResult<StatusCode> {
    let id = trusted_uuid(&user.user_id)?;
    // The upgrade signs the first suite-2 binding; later epochs come only
    // with a key change of suite 2, which doesn't exist yet.
    if req.drive_key_binding_epoch != kutup_crypto::drive_key_binding::FIRST_DRIVE_KEY_BINDING_EPOCH
    {
        return Err(AppError::bad_request(
            "the upgrade's binding is the first suite-2 binding (epoch 1)",
        ));
    }
    let mut tx = state.pool.begin().await?;
    // An account still in its first-login setup has no keys to upgrade:
    // complete-setup registers suite-2 keys.
    let row: Option<(i16, String, String, String, bool)> = sqlx::query_as(
        "SELECT identity_suite, account_authority_public_key, drive_signing_public_key,
                COALESCE(key_binding, ''), is_first_login
           FROM users WHERE id = $1 AND is_active FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((suite, authority, signing, key_binding, first_login)) = row else {
        return Err(AppError::unauthorized("unauthorized"));
    };
    // Not a reason to end the session: the setup that is pending registers
    // suite-2 keys itself.
    if first_login {
        return Err(AppError::conflict("finish the account's setup first")
            .with_details(serde_json::json!({ "code": "setupPending" })));
    }
    if suite >= kutup_crypto::identity::IDENTITY_SUITE as i16 {
        return Err(
            AppError::conflict("this account's identity suite is current")
                .with_details(serde_json::json!({ "code": "identitySuiteCurrent" })),
        );
    }
    let account = crate::account_ids::local(&state.config.chat_server_name, id)?;
    crate::handlers::auth::verify_drive_key_binding(
        &account,
        &authority,
        req.drive_key_binding_epoch,
        &req.public_key,
        &signing,
        &req.drive_key_binding,
    )?;
    crate::handlers::auth::validate_account_envelope(
        &req.drive_private_key_envelope,
        kutup_crypto::account_envelope::AccountEnvelopePurpose::DriveHpkePrivateKey,
        &key_binding,
        "drivePrivateKeyEnvelope",
    )?;
    sqlx::query(
        "UPDATE users SET public_key = $2, drive_key_binding = $3,
                drive_private_key_envelope = $4, identity_suite = $5,
                drive_key_binding_epoch = $6, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.public_key)
    .bind(&req.drive_key_binding)
    .bind(&req.drive_private_key_envelope)
    .bind(kutup_crypto::identity::IDENTITY_SUITE as i16)
    .bind(req.drive_key_binding_epoch as i32)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
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
    drive_hpke_public_key: String,
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
        "SELECT id, username, account_authority_public_key, public_key, drive_signing_public_key,
                drive_key_binding, identity_suite, drive_key_binding_epoch
           FROM users
          WHERE id IN (SELECT kutup_current_user(name) FROM unnest($1::text[]) AS name)
            AND is_active AND NOT is_first_login",
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
                drive_hpke_public_key: hpke,
                drive_signing_public_key: signing,
                drive_key_binding: binding,
                identity_suite: suite,
                drive_key_binding_epoch: epoch,
            },
        )
        .collect();
    Ok(Json(identities).into_response())
}
