//! An address's display name and signature (docs/plans/mail-parity.md, P2),
//! as Proton's Identity settings: the name outgoing mail carries in From,
//! and the signature the composer starts with.

use axum::extract::{Query, State};
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

/// Which address: `addressId` (one of the caller's current addresses), or
/// the default address when none is named (Proton's identity is per
/// address; clients that name none keep the account's).
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct IdentityQuery {
    pub address_id: Option<String>,
}

async fn own_address(
    state: &AppState,
    user_id: Uuid,
    address_id: Option<&str>,
) -> AppResult<(Uuid, String, String)> {
    let not_found = || AppError::not_found("this account has no mail address yet");
    let address_id = match address_id {
        Some(id) => Uuid::parse_str(id).map_err(|_| not_found())?,
        None => {
            match crate::handlers::mail_addresses::default_address(state, user_id).await? {
                Some((id, _)) => id,
                // No address with a key yet: the account's own address.
                None => sqlx::query_scalar(
                    "SELECT id FROM mail_addresses
                      WHERE user_id = $1 AND state = 'active' AND domain_id IS NULL",
                )
                .bind(user_id)
                .fetch_optional(&state.pool)
                .await?
                .ok_or_else(not_found)?,
            }
        }
    };
    sqlx::query_as(
        "SELECT a.id, a.address, u.username FROM mail_addresses a JOIN users u ON u.id = a.user_id
          WHERE a.id = $1 AND a.user_id = $2 AND a.state = 'active'",
    )
    .bind(address_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(not_found)
}

/// Where a signature is sealed: the account is the row, so it moves with the
/// account to a new address (a rename) unchanged.
fn signature_field(account: &str) -> (&'static str, &'static str, &str) {
    ("mail_identities", "signature", account)
}

async fn identity(
    state: &AppState,
    user_id: Uuid,
    address_id: Option<&str>,
) -> AppResult<MailIdentity> {
    let (address_id, address, username) = own_address(state, user_id, address_id).await?;
    let row: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT display_name, signature_sealed FROM mail_identities WHERE address_id = $1",
    )
    .bind(address_id)
    .fetch_optional(&state.pool)
    .await?;
    let (display_name, sealed) = row.unwrap_or_default();
    // Sealed under the account's data key (docs/plans/server-personal-data.md,
    // A2); destroyed with it.
    let signature = match sealed {
        Some(sealed) => crate::account_data::open(
            &state.pool,
            &state.config.opaque_setup_keys,
            user_id,
            signature_field(&user_id.to_string()),
            &sealed,
        )
        .await?
        .and_then(|plain| String::from_utf8(plain.to_vec()).ok())
        .unwrap_or_default(),
        None => String::new(),
    };
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
    params(IdentityQuery),
    responses((status = 200, description = "Display name and signature", body = MailIdentity))
)]
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<IdentityQuery>,
) -> AppResult<Json<MailIdentity>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(
        identity(&state, user_id, query.address_id.as_deref()).await?,
    ))
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
    params(IdentityQuery),
    request_body = UpdateMailIdentity,
    responses(
        (status = 200, description = "Saved", body = MailIdentity),
        (status = 400, description = "A name over 100 characters or with control characters, a signature over 10 KB"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<IdentityQuery>,
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
    let (address_id, _, _) = own_address(&state, user_id, query.address_id.as_deref()).await?;
    let sealed = match request.signature.as_deref() {
        Some(signature) => Some(
            crate::account_data::seal(
                &state.pool,
                &state.config.opaque_setup_keys,
                user_id,
                signature_field(&user_id.to_string()),
                signature.as_bytes(),
            )
            .await?,
        ),
        None => None,
    };
    sqlx::query(
        "INSERT INTO mail_identities (address_id, display_name, signature_sealed)
         VALUES ($1, COALESCE($2, ''), $3)
         ON CONFLICT (address_id) DO UPDATE SET
             display_name = COALESCE($2, mail_identities.display_name),
             signature_sealed = COALESCE($3, mail_identities.signature_sealed),
             updated_at = now()",
    )
    .bind(address_id)
    .bind(name)
    .bind(sealed)
    .execute(&state.pool)
    .await?;
    Ok(Json(
        identity(&state, user_id, query.address_id.as_deref()).await?,
    ))
}
