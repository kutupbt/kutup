//! `POST /api/user/rebind` — moves an account's sealed keys from its old
//! sign-in email to its key binding (docs/plans/account-identity.md).
//!
//! The browser re-seals, right after a sign-in, everything bound to the old
//! string: the password and recovery wrappings of the master key (with a new
//! recovery check), the Drive private key, the Chat backup root, each mail
//! address key and each Pass vault secret. The server takes it only whole:
//! the password is proved again (a stolen session alone cannot swap the
//! recovery wrapping), every envelope must carry the key binding and its own
//! purpose, every row of the account must be covered, and all of it changes in
//! one transaction, or nothing does.

use std::collections::BTreeSet;

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::auth::{
    decode_canonical_base64_exact, hash_recovery_proof, is_key_binding, validate_account_envelope,
    verify_account_login_key,
};
use crate::handlers::pass::{rebind_vault_secrets, RebindVaultSecret};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::models::OkResponse;
use crate::AppState;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RebindMailKey {
    /// The mail address key's id.
    pub id: String,
    pub private_key_envelope: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RebindRequest {
    /// The password's login key, proved again.
    pub login_key: String,
    /// The account's key binding: drawn by the browser now (a UUID v4).
    pub key_binding: String,
    pub master_key_envelope: String,
    pub recovery_key_envelope: String,
    /// The recovery check derived from the phrase the reader typed, or from
    /// the new one they were shown.
    pub recovery_proof: String,
    pub drive_private_key_envelope: String,
    /// The Chat backup root, when the account has a backup.
    pub chat_backup_root_envelope: Option<String>,
    /// The root envelope it was re-sealed from, as the account's backup held
    /// it: replaced only if still so (a backup reset meanwhile is kept).
    pub chat_backup_root_from: Option<String>,
    #[serde(default)]
    pub mail_keys: Vec<RebindMailKey>,
    #[serde(default)]
    pub pass_vault_secrets: Vec<RebindVaultSecret>,
}

/// A re-sealed envelope is of the current suite (2: a key per envelope,
/// docs/plans/account-identity.md); the account's re-seal is the one moment
/// every secret is written again, so none stays on suite 1.
pub(crate) fn current_suite(envelope: Vec<u8>, field: &str) -> AppResult<Vec<u8>> {
    let header = account_envelope::inspect(&envelope)
        .map_err(|_| AppError::bad_request(format!("invalid {field}")))?;
    if header.suite != account_envelope::AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2 {
        return Err(AppError::bad_request(format!(
            "{field} must be sealed with the current suite"
        )));
    }
    Ok(envelope)
}

/// An account key (32 bytes sealed) for `binding`, of the current suite.
fn checked(
    value: &str,
    purpose: AccountEnvelopePurpose,
    binding: &str,
    field: &str,
) -> AppResult<Vec<u8>> {
    validate_account_envelope(value, purpose, binding, field)?;
    let envelope = account_envelope::decode_canonical_b64(value)
        .map_err(|_| AppError::bad_request(format!("invalid {field} encoding")))?;
    current_suite(envelope, field)
}

/// A secret of any length (a mail key's) for `binding`, of the current suite.
fn checked_secret(
    value: &str,
    purpose: AccountEnvelopePurpose,
    binding: &str,
    field: &str,
) -> AppResult<Vec<u8>> {
    let envelope = account_envelope::decode_canonical_b64(value)
        .map_err(|_| AppError::bad_request(format!("invalid {field} encoding")))?;
    let header = account_envelope::inspect(&envelope)
        .map_err(|_| AppError::bad_request(format!("invalid {field}")))?;
    if header.purpose != purpose
        || Some(header.canonical_login_email)
            != account_envelope::canonical_login_email(binding).ok()
    {
        return Err(AppError::bad_request(format!("invalid {field} binding")));
    }
    current_suite(envelope, field)
}

#[utoipa::path(
    post,
    path = "/api/user/rebind",
    tag = "auth",
    security(("BearerAuth" = [])),
    request_body = RebindRequest,
    responses(
        (status = 200, description = "Every sealed key now carries the key binding", body = OkResponse),
        (status = 400, description = "An envelope of the wrong purpose or binding, or a key binding that is not a UUID v4"),
        (status = 401, description = "The password does not match"),
        (status = 409, description = "Already done, or the account's keys changed meanwhile (sign in again)"),
    )
)]
pub async fn rebind(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<RebindRequest>,
) -> AppResult<Json<OkResponse>> {
    let user_id = trusted_uuid(&user.user_id)?;
    verify_account_login_key(&state, &user, &request.login_key).await?;
    let binding = request.key_binding.as_str();
    if !is_key_binding(binding) {
        return Err(AppError::bad_request("keyBinding is a lowercase UUID v4"));
    }
    let master = checked(
        &request.master_key_envelope,
        AccountEnvelopePurpose::PasswordMasterKey,
        binding,
        "masterKeyEnvelope",
    )?;
    let recovery = checked(
        &request.recovery_key_envelope,
        AccountEnvelopePurpose::RecoveryMasterKey,
        binding,
        "recoveryKeyEnvelope",
    )?;
    let drive = checked(
        &request.drive_private_key_envelope,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        binding,
        "drivePrivateKeyEnvelope",
    )?;
    let chat = request
        .chat_backup_root_envelope
        .as_deref()
        .map(|value| {
            checked(
                value,
                AccountEnvelopePurpose::ChatBackupRoot,
                binding,
                "chatBackupRootEnvelope",
            )
        })
        .transpose()?;
    let mut mail = Vec::with_capacity(request.mail_keys.len());
    for key in &request.mail_keys {
        let id = Uuid::parse_str(&key.id)
            .map_err(|_| AppError::bad_request("a mail key id is not a UUID"))?;
        let envelope = checked_secret(
            &key.private_key_envelope,
            AccountEnvelopePurpose::MailAddressPrivateKey,
            binding,
            "mailKeys",
        )?;
        mail.push((id, envelope));
    }
    decode_canonical_base64_exact(&request.recovery_proof, 32, "recoveryProof")?;
    let verifier = hash_recovery_proof(&request.recovery_proof)?;

    let mut tx = state.pool.begin().await?;
    let (envelope_binding, key_binding): (String, Option<String>) =
        sqlx::query_as("SELECT envelope_binding, key_binding FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if key_binding
        .as_deref()
        .is_some_and(|k| k == envelope_binding)
    {
        return Err(AppError::conflict("this account's keys are already bound"));
    }
    if key_binding.as_deref().is_some_and(|k| k != binding) {
        return Err(AppError::conflict(
            "this account already has another key binding",
        ));
    }

    // The Chat backup root: there exactly when the account has a backup.
    let backups: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_backups WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    match (&chat, backups) {
        (None, 0) => {}
        (Some(root), n) if n > 0 => {
            let from = request.chat_backup_root_from.as_deref().ok_or_else(|| {
                AppError::bad_request("chatBackupRootFrom is required with chatBackupRootEnvelope")
            })?;
            let replaced = sqlx::query(
                "UPDATE chat_backups SET root_envelope = $2 WHERE user_id = $1 AND root_envelope = $3",
            )
            .bind(user_id)
            .bind(STANDARD.encode(root))
            .bind(from)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if replaced == 0 {
                return Err(AppError::conflict(
                    "the Chat backup changed meanwhile; sign in again to finish",
                ));
            }
        }
        _ => {
            return Err(AppError::conflict(
                "the Chat backup changed meanwhile; sign in again to finish",
            ))
        }
    }

    // Every mail address key of the account's own addresses, each once.
    let held: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT k.id FROM mail_address_keys k JOIN mail_addresses a ON a.id = k.address_id
          WHERE a.user_id = $1 FOR UPDATE OF k",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();
    let named: BTreeSet<Uuid> = mail.iter().map(|(id, _)| *id).collect();
    if named.len() != mail.len() || named != held {
        return Err(AppError::conflict(
            "the mail keys changed meanwhile; sign in again to finish",
        ));
    }
    for (id, envelope) in &mail {
        sqlx::query("UPDATE mail_address_keys SET private_key_envelope = $2 WHERE id = $1")
            .bind(id)
            .bind(envelope)
            .execute(&mut *tx)
            .await?;
    }

    rebind_vault_secrets(&mut tx, user_id, binding, &request.pass_vault_secrets).await?;

    let updated = sqlx::query(
        "UPDATE users SET master_key_envelope = $2, recovery_key_envelope = $3,
                recovery_key_verifier = $4, drive_private_key_envelope = $5,
                key_binding = $6, envelope_binding = $6, updated_at = now()
          WHERE id = $1",
    )
    .bind(user_id)
    .bind(STANDARD.encode(&master))
    .bind(STANDARD.encode(&recovery))
    .bind(&verifier)
    .bind(STANDARD.encode(&drive))
    .bind(binding)
    .execute(&mut *tx)
    .await;
    if let Err(sqlx::Error::Database(error)) = &updated {
        if error.code().as_deref() == Some("23505") {
            return Err(AppError::conflict("keyBinding is taken; draw another"));
        }
    }
    updated?;
    tx.commit().await?;
    Ok(Json(OkResponse { ok: true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    #[test]
    fn a_re_seal_takes_the_current_suite_and_secrets_of_any_length() {
        use base64::Engine as _;
        let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
        let key = [9u8; 32];
        let master = |suite| {
            b64(account_envelope::seal_suite(
                suite,
                &[1u8; 32],
                &key,
                AccountEnvelopePurpose::PasswordMasterKey,
                BINDING,
                &[],
                &[3u8; 24],
            )
            .unwrap())
        };
        use account_envelope::AccountEnvelopeSuiteId::{
            XChaCha20Poly1305HkdfV2, XChaCha20Poly1305V1,
        };
        let field = "masterKeyEnvelope";
        assert!(checked(
            &master(XChaCha20Poly1305HkdfV2),
            AccountEnvelopePurpose::PasswordMasterKey,
            BINDING,
            field
        )
        .is_ok());
        assert!(checked(
            &master(XChaCha20Poly1305V1),
            AccountEnvelopePurpose::PasswordMasterKey,
            BINDING,
            field
        )
        .is_err());
        // A mail key's secret is longer than 32 bytes.
        let mail = b64(account_envelope::seal(
            &[5u8; 700],
            &key,
            AccountEnvelopePurpose::MailAddressPrivateKey,
            BINDING,
        )
        .unwrap());
        assert!(checked_secret(
            &mail,
            AccountEnvelopePurpose::MailAddressPrivateKey,
            BINDING,
            "mailKeys"
        )
        .is_ok());
        assert!(checked_secret(
            &mail,
            AccountEnvelopePurpose::DriveHpkePrivateKey,
            BINDING,
            "mailKeys"
        )
        .is_err());
        assert!(checked_secret(
            &mail,
            AccountEnvelopePurpose::MailAddressPrivateKey,
            "someone@else",
            "mailKeys"
        )
        .is_err());
    }
}
