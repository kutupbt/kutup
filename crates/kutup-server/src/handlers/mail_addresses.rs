//! An account's addresses as Proton's "Identity and addresses" manages them
//! (docs/plans/mail-custom-domains.md §5): their order, whose first enabled
//! address is the default, and disabling, enabling and deleting an address
//! on a custom domain.
//!
//! Disabling publishes the address's next signed key list with every key no
//! longer to be encrypted to (`FLAG_NOT_OBSOLETE` cleared), so senders and
//! WKD stop offering it; enabling publishes one with its primary key usable
//! again. Deleting frees the name (as removing its domain does) and keeps
//! its keys with the account: they open the mail it received, and never
//! encrypt or sign anything new.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::mail_key::FLAG_NOT_OBSOLETE;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::mail_keys::{begin_list_change, OwnMailAddress, UpdateKeyListRequest};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

fn coded(error: AppError, code: &str) -> AppError {
    error.with_details(json!({ "code": code }))
}

/// The account's default address: its first enabled current address, in its
/// order, with a primary key and on a domain usable now (the server's own,
/// or a custom one that is verified). It sends what names no From.
pub(crate) async fn default_address(
    state: &AppState,
    user_id: Uuid,
) -> AppResult<Option<(Uuid, String)>> {
    let rows: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT a.id, a.address, a.domain_id FROM mail_addresses a
          WHERE a.user_id = $1 AND a.state = 'active' AND a.disabled_at IS NULL
            AND EXISTS (SELECT 1 FROM mail_address_keys k
                         WHERE k.address_id = a.id AND k.is_primary)
          ORDER BY a.position, a.created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    for (id, address, domain_id) in rows {
        match domain_id {
            None => return Ok(Some((id, address))),
            Some(domain_id) => {
                if crate::mail::domains::usable_domain(state, domain_id).await? {
                    return Ok(Some((id, address)));
                }
            }
        }
    }
    Ok(None)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddressOrderRequest {
    /// Every current address of the account (enabled or disabled), in the
    /// new order; the first is the default and must be enabled.
    pub ids: Vec<String>,
}

/// `PUT /api/mail/addresses/order` — the account's addresses in a new order
/// (Proton's `PUT addresses/order`; "Set as default" moves one first). The
/// list names exactly the account's current addresses: a tab that missed one
/// added or deleted meanwhile gets `409 addressSetChanged`.
#[utoipa::path(
    put,
    path = "/api/mail/addresses/order",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = AddressOrderRequest,
    responses(
        (status = 204, description = "Ordered"),
        (status = 400, description = "A disabled address first (disabledDefault)"),
        (status = 409, description = "Not exactly the account's current addresses (addressSetChanged)"),
    )
)]
pub async fn order(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AddressOrderRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let ids: Vec<Uuid> = request
        .ids
        .iter()
        .map(|id| Uuid::parse_str(id))
        .collect::<Result<_, _>>()
        .map_err(|_| AppError::bad_request("ids are address ids"))?;
    let mut tx = state.pool.begin().await?;
    let current: Vec<(Uuid, bool)> = sqlx::query_as(
        "SELECT id, disabled_at IS NOT NULL FROM mail_addresses
          WHERE user_id = $1 AND state = 'active' ORDER BY id FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut named = ids.clone();
    named.sort();
    let held: Vec<Uuid> = current.iter().map(|(id, _)| *id).collect();
    if named != held {
        return Err(coded(
            AppError::conflict("the account's addresses changed: read them again"),
            "addressSetChanged",
        ));
    }
    let first_disabled = current
        .iter()
        .find(|(id, _)| Some(id) == ids.first())
        .is_some_and(|(_, disabled)| *disabled);
    if first_disabled {
        return Err(coded(
            AppError::bad_request("a disabled address cannot be default"),
            "disabledDefault",
        ));
    }
    for (position, id) in ids.iter().enumerate() {
        sqlx::query("UPDATE mail_addresses SET position = $2 WHERE id = $1")
            .bind(id)
            .bind(position as i32)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// One of the caller's current addresses on a custom domain, locked: its
/// address, and whether it is disabled. The account's own address (the
/// server's domain) is never disabled or deleted, as Proton's original one.
async fn custom_address(
    conn: &mut PgConnection,
    user_id: Uuid,
    address_id: Uuid,
) -> AppResult<bool> {
    let row: Option<(Option<Uuid>, bool)> = sqlx::query_as(
        "SELECT domain_id, disabled_at IS NOT NULL FROM mail_addresses
          WHERE id = $1 AND user_id = $2 AND state = 'active' FOR UPDATE",
    )
    .bind(address_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        None => Err(AppError::not_found("not found")),
        Some((None, _)) => Err(coded(
            AppError::conflict("the account's own address stays enabled"),
            "ownAddress",
        )),
        Some((Some(_), disabled)) => Ok(disabled),
    }
}

/// A caught address no longer is one: its domain's catch-all is cleared.
async fn clear_catch_all(conn: &mut PgConnection, address_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "UPDATE mail_domains SET catch_all_address_id = NULL WHERE catch_all_address_id = $1",
    )
    .bind(address_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn address_id(id: &str) -> AppResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| AppError::not_found("not found"))
}

/// `PUT /api/mail/addresses/{id}/disable` — Proton's Disable, with the
/// address's next signed key list: the same keys, none of them to be
/// encrypted to. The address neither receives nor sends; its catch-all
/// ends. The default address is moved down first (`409 defaultAddress`).
#[utoipa::path(
    put,
    path = "/api/mail/addresses/{id}/disable",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Address id")),
    request_body = UpdateKeyListRequest,
    responses(
        (status = 200, description = "The address, disabled", body = OwnMailAddress),
        (status = 400, description = "A key in the list is still to be encrypted to"),
        (status = 409, description = "The account's own address, the default, already disabled, or a stale key list"),
    )
)]
pub async fn disable(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateKeyListRequest>,
) -> AppResult<Json<OwnMailAddress>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address = address_id(&id)?;
    if default_address(&state, user_id).await?.map(|(id, _)| id) == Some(address) {
        return Err(coded(
            AppError::conflict("make another address default first"),
            "defaultAddress",
        ));
    }
    let mut change = begin_list_change(&state, user_id, &id, &request.key_list).await?;
    if custom_address(&mut change.tx, user_id, address).await? {
        return Err(coded(
            AppError::conflict("the address is disabled already"),
            "addressDisabled",
        ));
    }
    change.check_lists_exactly(None).await?;
    if change
        .signed
        .list
        .keys
        .iter()
        .any(|key| key.flags & FLAG_NOT_OBSOLETE != 0)
    {
        return Err(AppError::bad_request(
            "a disabled address's keys are not encrypted to",
        ));
    }
    sqlx::query("UPDATE mail_addresses SET disabled_at = now() WHERE id = $1")
        .bind(address)
        .execute(&mut *change.tx)
        .await?;
    clear_catch_all(&mut change.tx, address).await?;
    Ok(Json(change.finish(&state).await?))
}

/// `PUT /api/mail/addresses/{id}/enable` — Proton's Enable, with the
/// address's next signed key list: its primary key to be encrypted to again.
#[utoipa::path(
    put,
    path = "/api/mail/addresses/{id}/enable",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Address id")),
    request_body = UpdateKeyListRequest,
    responses(
        (status = 200, description = "The address, enabled", body = OwnMailAddress),
        (status = 400, description = "The primary key isn't to be encrypted to"),
        (status = 409, description = "Not disabled, or a stale key list"),
    )
)]
pub async fn enable(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateKeyListRequest>,
) -> AppResult<Json<OwnMailAddress>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address = address_id(&id)?;
    let mut change = begin_list_change(&state, user_id, &id, &request.key_list).await?;
    if !custom_address(&mut change.tx, user_id, address).await? {
        return Err(coded(
            AppError::conflict("the address is enabled already"),
            "addressEnabled",
        ));
    }
    change.check_lists_exactly(None).await?;
    let primary_usable = change
        .signed
        .list
        .keys
        .iter()
        .any(|key| key.primary && key.flags & FLAG_NOT_OBSOLETE != 0);
    if !primary_usable {
        return Err(AppError::bad_request(
            "an enabled address's primary key is encrypted to",
        ));
    }
    sqlx::query("UPDATE mail_addresses SET disabled_at = NULL WHERE id = $1")
        .bind(address)
        .execute(&mut *change.tx)
        .await?;
    Ok(Json(change.finish(&state).await?))
}

/// `PUT /api/mail/addresses/{id}/delete` — Proton's Delete for an address on
/// a custom domain, once disabled (Proton disables first): the name is free
/// for anyone again, and its keys stay with this account to open the mail it
/// received (never published, never used for new mail).
#[utoipa::path(
    put,
    path = "/api/mail/addresses/{id}/delete",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Address id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 409, description = "The account's own address, or not disabled yet (addressEnabled)"),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address = address_id(&id)?;
    let mut tx = state.pool.begin().await?;
    if !custom_address(&mut tx, user_id, address).await? {
        return Err(coded(
            AppError::conflict("disable the address first"),
            "addressEnabled",
        ));
    }
    sqlx::query("UPDATE mail_addresses SET state = 'freed', receive_until = NULL WHERE id = $1")
        .bind(address)
        .execute(&mut *tx)
        .await?;
    clear_catch_all(&mut tx, address).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
