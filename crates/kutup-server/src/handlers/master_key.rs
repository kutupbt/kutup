//! `POST /api/account/master-key/rotate` — a new master key
//! (docs/plans/mk-rotation-exercise.md), in one transaction: the password
//! registered again with it, a new recovery phrase, the five roots re-wrapped,
//! the previous key kept in the keyring, the next account head sealed under
//! it, and the account's other sign-ins ended. The server checks every
//! record's header (purpose, binding, object, generation); it opens none.

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::account_record::{self, AccountRecordPurpose};
use kutup_crypto::account_roots::PURPOSES;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::account_heads::{self, NextHead};
use crate::error::{AppError, AppResult};
use crate::grants::{self, Purpose};
use crate::handlers::opaque::RecordUpload;
use crate::middleware::AuthUser;
use crate::security_events;
use crate::AppState;

// No Debug: it carries a one-time grant.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RotateRequest {
    /// A grant `for: masterKeyRotation`, from this session's reauth.
    grant: String,
    /// The password registered again (`register/start` with the grant).
    #[serde(flatten)]
    record: RecordUpload,
    /// The new master key under the new password's export key (purpose 1)
    /// and under the new recovery phrase (purpose 2), both at the next
    /// generation.
    master_key_envelope: String,
    recovery_key_envelope: String,
    /// The new recovery phrase's proof (32 bytes, base64).
    recovery_proof: String,
    /// The five roots sealed again under the new key: each the newest
    /// generation the account keeps of it.
    account_roots: Vec<String>,
    /// The previous master key under the new one (purpose 27; its object the
    /// previous generation).
    master_keyring: String,
    /// The next account head, sealed under the new key.
    head: String,
}

fn invalid(field: &str) -> AppError {
    AppError::bad_request(format!("{field} is not this rotation's"))
        .with_details(json!({ "code": "rotationInvalid", "field": field }))
}

/// A record of `purpose` for `binding` and `object`, sealed at `generation`:
/// its bytes, or `rotationInvalid` naming `field`.
fn checked(
    value: &str,
    purpose: AccountRecordPurpose,
    binding: &str,
    object: &[u8],
    generation: u32,
    field: &str,
) -> AppResult<Vec<u8>> {
    let envelope = account_record::decode_record_b64(value, purpose).map_err(|_| invalid(field))?;
    let header = account_record::validate_for(&envelope, purpose, binding, object)
        .map_err(|_| invalid(field))?;
    if header.generation.get() != generation {
        return Err(invalid(field));
    }
    Ok(envelope)
}

#[utoipa::path(
    post,
    path = "/api/account/master-key/rotate",
    tag = "account",
    security(("BearerAuth" = [])),
    request_body = RotateRequest,
    responses(
        (status = 204, description = "The new master key is the account's; its other sign-ins ended"),
        (status = 400, description = "rotationInvalid: a record is not this rotation's"),
        (status = 403, description = "grantInvalid"),
        (status = 409, description = "head_conflict (read the head again), opaqueKeyStale, or organizationKeys (the account holds organization keys or an escrow, which a rotation can't carry yet)")
    )
)]
pub async fn rotate(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<RotateRequest>, JsonRejection>,
) -> AppResult<Response> {
    let Json(req) = body.map_err(|_| AppError::bad_request("invalid request"))?;
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let session = user.session.session_id;
    let (record, server_key_id) = req.record.checked(&state)?;
    let recovery_verifier = crate::handlers::auth::hash_recovery_proof(&req.recovery_proof)?;

    let mut tx = state.pool.begin().await?;
    let (_, grant) = grants::take(&mut *tx, &req.grant, &[Purpose::MasterKeyRotation])
        .await?
        .ok_or_else(grants::invalid)?;
    if grant.user_id != user_id || grant.session_id != Some(session) {
        return Err(grants::invalid());
    }
    // The account row, locked: no listed write or other rotation between.
    let mut locked = account_heads::lock(&mut tx, user_id, session).await?;
    let current = locked.master_key_generation();
    let next = current
        .checked_add(1)
        .filter(|next| i32::try_from(*next).is_ok())
        .ok_or_else(|| AppError::bad_request("no master-key generation after this one"))?;
    let binding = locked.binding().to_owned();

    // An organization's escrow or key copy holds the old key; its routes
    // (docs/plans/organizations.md, O4) re-seal them with a rotation. Until
    // then such an account can't rotate, rather than lose its admins' access.
    let organization_keys: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM organization_member_escrows WHERE account_id = $1)
             OR EXISTS (SELECT 1 FROM organization_key_shares
                         WHERE account_id = $1 AND envelope IS NOT NULL)",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if organization_keys {
        return Err(AppError::conflict(
            "the account holds organization keys, which a rotation can't carry yet",
        )
        .with_details(json!({ "code": "organizationKeys" })));
    }

    checked(
        &req.master_key_envelope,
        AccountRecordPurpose::PasswordMasterKey,
        &binding,
        &[],
        next,
        "masterKeyEnvelope",
    )?;
    checked(
        &req.recovery_key_envelope,
        AccountRecordPurpose::RecoveryMasterKey,
        &binding,
        &[],
        next,
        "recoveryKeyEnvelope",
    )?;
    let keyring = checked(
        &req.master_keyring,
        AccountRecordPurpose::MasterKeyKeyring,
        &binding,
        &current.to_be_bytes(),
        next,
        "masterKeyring",
    )?;

    // Each root at the newest generation the account keeps of it, once.
    let newest: Vec<(i16, Vec<u8>)> = sqlx::query_as(
        // The object is the generation, 4 bytes big-endian: byte order is
        // number order (no max() for bytea).
        "SELECT DISTINCT ON (purpose) purpose, object FROM account_roots
          WHERE account_id = $1 AND purpose BETWEEN 22 AND 26
          ORDER BY purpose, object DESC",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    if req.account_roots.len() != PURPOSES.len() || newest.len() != PURPOSES.len() {
        return Err(invalid("accountRoots"));
    }
    let mut roots: Vec<(AccountRecordPurpose, Vec<u8>, Vec<u8>)> = Vec::with_capacity(5);
    for value in &req.account_roots {
        let bytes =
            account_record::decode_canonical_b64(value).map_err(|_| invalid("accountRoots"))?;
        let purpose = account_record::inspect(&bytes)
            .map_err(|_| invalid("accountRoots"))?
            .purpose;
        if !PURPOSES.contains(&purpose) || roots.iter().any(|(p, _, _)| *p == purpose) {
            return Err(invalid("accountRoots"));
        }
        let object = newest
            .iter()
            .find(|(p, _)| *p == purpose.as_u16() as i16)
            .map(|(_, object)| object.clone())
            .ok_or_else(|| invalid("accountRoots"))?;
        let envelope = checked(value, purpose, &binding, &object, next, "accountRoots")?;
        roots.push((purpose, object, envelope));
    }

    // The next head, sealed under the new key, after the newest.
    let head = NextHead::parse(Some(&req.head))?.ok_or_else(|| invalid("head"))?;
    locked.rotated_to(next);
    account_heads::advance(&mut tx, &locked, Some(&head)).await?;

    let updated = sqlx::query(
        "UPDATE accounts SET opaque_record = $3, opaque_suite = $4, opaque_server_key_id = $5,
                          master_key_envelope = kutup_unb64($6),
                          recovery_key_envelope = kutup_unb64($7),
                          recovery_key_verifier = $8, master_key_generation = $9
          WHERE id = $1 AND key_binding = $2::uuid AND master_key_generation = $10 AND is_active",
    )
    .bind(user_id)
    .bind(&binding)
    .bind(&record)
    .bind(kutup_crypto::opaque::SUITE as i16)
    .bind(server_key_id)
    .bind(&req.master_key_envelope)
    .bind(&req.recovery_key_envelope)
    .bind(&recovery_verifier)
    .bind(next as i32)
    .bind(current as i32)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(account_heads::master_key_stale());
    }
    for (purpose, object, envelope) in &roots {
        sqlx::query(
            "UPDATE account_roots SET envelope = $4
              WHERE account_id = $1 AND purpose = $2 AND object = $3",
        )
        .bind(user_id)
        .bind(purpose.as_u16() as i16)
        .bind(object)
        .bind(envelope)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO account_roots (account_id, purpose, object, envelope) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(AccountRecordPurpose::MasterKeyKeyring.as_u16() as i16)
    .bind(current.to_be_bytes().to_vec())
    .bind(&keyring)
    .execute(&mut *tx)
    .await?;

    // Every other sign-in holds the old key: they end, and sign in again.
    grants::end_all(&mut tx, user_id).await?;
    crate::sessions::revoke_all_for_user_in(&mut tx, user_id, Some(session)).await?;
    security_events::record(
        &mut tx,
        user_id,
        security_events::Kind::MasterKeyRotated,
        Some(session),
        None,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(%user_id, generation = next, "master key rotated");
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}
