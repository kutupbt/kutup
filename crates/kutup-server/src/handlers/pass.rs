//! Kutup Pass vault secrets (docs/plans/pass.md, "Vault secrets").
//!
//! Each person may keep, per vault they can open, the vault's password and
//! key file sealed under their master key (`kutup_crypto::pass_vault`), so
//! Kutup Pass and `kutup sync` unlock vaults with the Kutup sign-in. The
//! server stores the envelopes and checks only their public header; whoever
//! loses access to a vault loses its record too.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_file, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

/// The largest envelope kept: a password and a key file at their limits,
/// with the envelope's header.
const MAX_ENVELOPE_BYTES: usize = 4096 + 512;

/// One vault's sealed secret.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultSecretRow {
    file_id: String,
    /// Base64 of the account envelope (purpose `PassVaultSecret`).
    envelope: String,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PutVaultSecretRequest {
    /// Base64 of the account envelope (purpose `PassVaultSecret`).
    envelope: String,
}

/// `GET /api/pass/vault-secrets` — the caller's vault secrets, for vaults
/// they can still open.
#[utoipa::path(
    get,
    path = "/api/pass/vault-secrets",
    tag = "pass",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's sealed vault secrets", body = Vec<VaultSecretRow>))
)]
pub async fn list_vault_secrets(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(Uuid, Vec<u8>, OffsetDateTime, bool)> = sqlx::query_as(
        "SELECT s.file_id, s.envelope, s.updated_at, f.deleted_at IS NOT NULL
           FROM pass_vault_secrets s JOIN files f ON f.id = s.file_id
          WHERE s.user_id = $1
          ORDER BY s.file_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (file_id, envelope, updated_at, trashed) in rows {
        // A vault in the trash keeps its secret for a restore, unlisted.
        if trashed {
            continue;
        }
        if !can_access_file(&state.pool, user_id, file_id).await {
            // Access was taken away: the record goes with it.
            sqlx::query("DELETE FROM pass_vault_secrets WHERE user_id = $1 AND file_id = $2")
                .bind(user_id)
                .bind(file_id)
                .execute(&state.pool)
                .await?;
            continue;
        }
        out.push(VaultSecretRow {
            file_id: file_id.to_string(),
            envelope: STANDARD.encode(envelope),
            updated_at,
        });
    }
    Ok(Json(out).into_response())
}

/// `PUT /api/pass/vault-secrets/{fileId}` — keep (or replace) the caller's
/// secret for a vault they can open.
#[utoipa::path(
    put,
    path = "/api/pass/vault-secrets/{fileId}",
    tag = "pass",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "The vault's file id")),
    request_body = PutVaultSecretRequest,
    responses(
        (status = 204, description = "Stored"),
        (status = 400, description = "Not this account's vault secret"),
        (status = 404, description = "No such vault, or no access to it")
    )
)]
pub async fn put_vault_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    Json(req): Json<PutVaultSecretRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let envelope = STANDARD
        .decode(&req.envelope)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == req.envelope)
        .ok_or_else(|| AppError::bad_request("envelope is not canonical base64"))?;
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(AppError::bad_request("envelope is too large"));
    }
    let header = account_envelope::inspect(&envelope)
        .map_err(|_| AppError::bad_request("envelope is not an account envelope"))?;
    let login_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    if header.purpose != AccountEnvelopePurpose::PassVaultSecret
        || Some(header.canonical_login_email)
            != account_envelope::canonical_login_email(&login_email).ok()
    {
        return Err(AppError::bad_request(
            "envelope is not this account's vault secret",
        ));
    }
    let live: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM files WHERE id = $1 AND deleted_at IS NULL")
            .bind(file_id)
            .fetch_optional(&state.pool)
            .await?;
    if live.is_none() || !can_access_file(&state.pool, user_id, file_id).await {
        return Err(AppError::not_found("not found"));
    }
    sqlx::query(
        "INSERT INTO pass_vault_secrets (user_id, file_id, envelope) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, file_id) DO UPDATE SET envelope = $3, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(file_id)
    .bind(&envelope)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /api/pass/vault-secrets/{fileId}` — forget the caller's secret
/// for a vault.
#[utoipa::path(
    delete,
    path = "/api/pass/vault-secrets/{fileId}",
    tag = "pass",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "The vault's file id")),
    responses((status = 204, description = "Forgotten (or there was none)"))
)]
pub async fn delete_vault_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    sqlx::query("DELETE FROM pass_vault_secrets WHERE user_id = $1 AND file_id = $2")
        .bind(user_id)
        .bind(file_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
