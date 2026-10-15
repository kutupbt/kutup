//! Accounts by their permanent id (docs/plans/account-ids.md): what a client
//! holding someone's (server, account id) asks to show them by their address
//! now, or to read their identity again. Names reach an id only through the
//! address lookup (`/api/users/by-address`); everything else asks by id.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::drive_federation::{
    canonical_public_key, configured_stack, drive_spec, gateway_error, signed_app_error,
    signed_json, RemoteDriveUserResponse, JSON_CONTENT_TYPE,
};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

const MAX_IDENTITY_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ByIdQuery {
    /// The account's server; this one when left out.
    server: Option<String>,
}

/// This server's account `id`, as the identity lookups answer it.
async fn local_identity(
    state: &AppState,
    id: Uuid,
) -> AppResult<Option<RemoteDriveUserResponse>> {
    type Row = (String, String, String, String, String, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT username, public_key, account_incarnation_id, drive_signing_public_key,
                account_authority_public_key, drive_key_binding
           FROM users WHERE id = $1 AND is_active AND NOT is_first_login AND username IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let server = state.config.chat_server_name.clone();
    Ok(row.map(
        |(username, hpke, incarnation, signing, authority, binding)| RemoteDriveUserResponse {
            account: format!("{username}@{server}"),
            username,
            server,
            account_id: id.to_string(),
            drive_hpke_public_key: hpke,
            account_incarnation_id: incarnation,
            drive_signing_public_key: signing,
            account_authority_public_key: authority,
            drive_key_binding: binding,
        },
    ))
}

/// `GET /api/users/by-id/{accountId}?server=` — an account by its permanent
/// id: its address now (server-asserted, shown as a label) and its identity.
/// Another server's is asked of it through federation (its pinned identity,
/// never a URL from the query), limited per peer and once per account at a
/// time; rate-limited per caller like the address lookup.
#[utoipa::path(
    get,
    path = "/api/users/by-id/{accountId}",
    tag = "auth",
    security(("BearerAuth" = [])),
    params(("accountId" = String, Path, description = "Permanent account id"), ByIdQuery),
    responses(
        (status = 200, description = "The account", body = RemoteDriveUserResponse),
        (status = 404, description = "No such account")
    )
)]
pub async fn by_id(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(account_id): Path<String>,
    Query(query): Query<ByIdQuery>,
) -> AppResult<Response> {
    let local_server = state.config.chat_server_name.clone();
    let server = query.server.unwrap_or_else(|| local_server.clone());
    // A canonical server name and account id, or nothing is asked of anyone.
    let person = crate::account_ids::remote(&server, &account_id)?;
    let id = Uuid::parse_str(&person.account_id).expect("canonical");
    if person.server == local_server {
        return local_identity(&state, id)
            .await?
            .map(|found| Json(found).into_response())
            .ok_or_else(|| AppError::not_found("no such account"));
    }
    if !crate::ratelimit::ACCOUNT_PEER_FETCHES.allow(&person.server) {
        return Err(AppError::too_many_requests("too many lookups of that server")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    // One fetch per account at a time: the rest wait for it.
    let lock = crate::remote_renames::fetch_lock(&person.to_string());
    let _fetching = lock.lock().await;
    let federation = configured_stack(&state)?;
    let response = federation
        .send(
            &person.server,
            drive_spec(
                reqwest::Method::GET,
                format!("/api/fed/drive/accounts/{}", person.account_id),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                None,
                MAX_IDENTITY_RESPONSE_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("no such account"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("the other server answered {}", response.status),
        ));
    }
    let remote: RemoteDriveUserResponse = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid account"))?;
    if remote.server != person.server
        || remote.account_id != person.account_id
        || remote.account != format!("{}@{}", remote.username, person.server)
        || canonical_public_key(&remote.drive_hpke_public_key).is_err()
        || canonical_public_key(&remote.drive_signing_public_key).is_err()
        || canonical_public_key(&remote.account_authority_public_key).is_err()
        || remote.account_incarnation_id.len() != 64
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "the other server answered for another account",
        ));
    }
    Ok(Json(remote).into_response())
}

/// `GET /api/fed/drive/accounts/{accountId}` — signed: this server's account
/// by its permanent id, for a peer whose user holds it.
#[utoipa::path(
    get,
    path = "/api/fed/drive/accounts/{accountId}",
    tag = "drive federation",
    params(("accountId" = String, Path)),
    responses(
        (status = 200, description = "The account", body = RemoteDriveUserResponse),
        (status = 404, description = "No such account")
    )
)]
pub async fn fed_by_id(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/accounts/{account_id}");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            None,
            &[],
            kutup_federation_proto::FederationFeature::DriveV1,
        )
        .await?;
    let result = async {
        let person = crate::account_ids::remote(federation.server_name(), &account_id)?;
        local_identity(&state, Uuid::parse_str(&person.account_id).expect("canonical"))
            .await?
            .ok_or_else(|| AppError::not_found("no such account"))
    }
    .await;
    match result {
        Ok(found) => signed_json(federation, &authenticated, StatusCode::OK, &found),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}
