//! An address's display name and signature (docs/plans/mail-parity.md, P2),
//! as Proton's Identity settings: the name outgoing mail carries in From,
//! and the signature the composer starts with.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

const MAX_NAME_CHARS: usize = 100;
const MAX_SIGNATURE_BYTES: usize = 10_000;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailIdentity {
    pub address: String,
    /// The name in From; the username when none is set.
    pub display_name: String,
    /// HTML; empty for none.
    pub signature: String,
}

async fn own_address(state: &AppState, user_id: Uuid) -> AppResult<(Uuid, String, String)> {
    sqlx::query_as(
        "SELECT a.id, a.address, u.username FROM mail_addresses a JOIN users u ON u.id = a.user_id
          WHERE a.user_id = $1 AND a.state = 'active'",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("this account has no mail address yet"))
}

async fn identity(state: &AppState, user_id: Uuid) -> AppResult<MailIdentity> {
    let (address_id, address, username) = own_address(state, user_id).await?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT display_name, signature FROM mail_identities WHERE address_id = $1")
            .bind(address_id)
            .fetch_optional(&state.pool)
            .await?;
    let (display_name, signature) = row.unwrap_or_default();
    Ok(MailIdentity {
        address,
        display_name: if display_name.is_empty() {
            username
        } else {
            display_name
        },
        signature,
    })
}

/// `GET /api/mail/identity` — the account address's display name and signature.
#[utoipa::path(
    get,
    path = "/api/mail/identity",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Display name and signature", body = MailIdentity))
)]
pub async fn get(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<MailIdentity>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(identity(&state, user_id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailIdentity {
    pub display_name: Option<String>,
    pub signature: Option<String>,
}

/// `PATCH /api/mail/identity`.
#[utoipa::path(
    patch,
    path = "/api/mail/identity",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = UpdateMailIdentity,
    responses(
        (status = 200, description = "Saved", body = MailIdentity),
        (status = 400, description = "A name over 100 characters or with control characters, a signature over 10 KB"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<UpdateMailIdentity>,
) -> AppResult<Json<MailIdentity>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let name = request.display_name.as_deref().map(str::trim);
    if let Some(name) = name {
        if name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(AppError::bad_request(
                "a display name is up to 100 characters, without control characters",
            ));
        }
    }
    if request
        .signature
        .as_ref()
        .is_some_and(|s| s.len() > MAX_SIGNATURE_BYTES)
    {
        return Err(AppError::bad_request("a signature is 10 KB at most"));
    }
    let (address_id, _, _) = own_address(&state, user_id).await?;
    sqlx::query(
        "INSERT INTO mail_identities (address_id, display_name, signature)
         VALUES ($1, COALESCE($2, ''), COALESCE($3, ''))
         ON CONFLICT (address_id) DO UPDATE SET
             display_name = COALESCE($2, mail_identities.display_name),
             signature = COALESCE($3, mail_identities.signature),
             updated_at = now()",
    )
    .bind(address_id)
    .bind(name)
    .bind(request.signature.as_deref())
    .execute(&state.pool)
    .await?;
    Ok(Json(identity(&state, user_id).await?))
}
