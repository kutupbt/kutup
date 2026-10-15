//! Accounts by their permanent id (docs/plans/account-ids.md): what a client
//! holding someone's (server, account id) asks to show them by their address
//! now, or to read their identity again. Names reach an id only through the
//! address lookup (`/api/users/by-address`); everything else asks by id.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::drive_federation::{
    configured_stack, drive_spec, gateway_error, remote_keys_consistent, signed_app_error,
    signed_json, RemoteDriveUserResponse, JSON_CONTENT_TYPE,
};
use kutup_crypto::account_ref::AccountRef;

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
async fn local_identity(state: &AppState, id: Uuid) -> AppResult<Option<RemoteDriveUserResponse>> {
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

/// What one fetch of another server's account answered: kept a short while
/// so the lookups made meanwhile, and just after, are answered from it.
#[derive(Clone)]
enum Fetched {
    Found(Box<RemoteDriveUserResponse>),
    Missing,
}

/// How long a fetched answer is served before the account is asked again.
const FRESH_FOR: Duration = Duration::from_secs(30);

type Slot = Arc<tokio::sync::Mutex<Option<(Instant, Fetched)>>>;

/// Per account (`aci:<id>@<server>`): its fetch in flight (the slot's lock)
/// and its last answer.
static FETCHES: LazyLock<std::sync::Mutex<HashMap<String, Slot>>> = LazyLock::new(Default::default);

fn slot(person: &AccountRef) -> Slot {
    let mut fetches = FETCHES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Dropped once nobody waits on them and their answer is stale.
    fetches.retain(|_, slot| {
        Arc::strong_count(slot) > 1
            || slot
                .try_lock()
                .map(|kept| {
                    kept.as_ref()
                        .is_some_and(|(at, _)| at.elapsed() < FRESH_FOR)
                })
                .unwrap_or(true)
    });
    fetches.entry(person.to_string()).or_default().clone()
}

/// `GET /api/users/by-id/{accountId}?server=` — an account by its permanent
/// id: its address now (server-asserted, shown as a label) and its identity.
/// Another server's is asked of it through federation (its pinned identity,
/// never a URL from the query): one fetch per account at a time, whose
/// answer serves every lookup of it made meanwhile and for a short while
/// after. Only a real fetch counts against the caller's limit for that peer,
/// so nobody's lookups use up anyone else's.
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
    user: AuthUser,
    Path(account_id): Path<String>,
    Query(query): Query<ByIdQuery>,
) -> AppResult<Response> {
    let local_server = state.config.chat_server_name.clone();
    let server = query.server.unwrap_or_else(|| local_server.clone());
    // A canonical server name and account id, or nothing is asked of anyone.
    let person = crate::account_ids::remote(&server, &account_id)?;
    if person.server == local_server {
        let id = Uuid::parse_str(&person.account_id).expect("canonical");
        return local_identity(&state, id)
            .await?
            .map(|found| Json(found).into_response())
            .ok_or_else(|| AppError::not_found("no such account"));
    }
    remote_account(&state, &user.user_id, &person)
        .await?
        .map(|found| Json(found).into_response())
        .ok_or_else(|| AppError::not_found("no such account"))
}

/// Another server's account by its id, for `caller` (a lookup, or a share
/// naming its recipient): the fetch in flight or a fresh answer when there
/// is one, else a fetch counted against the caller's limit for that peer.
/// `None` when that server has no such account.
pub(crate) async fn remote_account(
    state: &AppState,
    caller: &str,
    person: &AccountRef,
) -> AppResult<Option<RemoteDriveUserResponse>> {
    let slot = slot(person);
    let mut kept = slot.lock().await;
    let fetched = match kept.as_ref() {
        Some((at, fetched)) if at.elapsed() < FRESH_FOR => fetched.clone(),
        _ => {
            let limit_key = format!("{caller}|{}", person.server);
            if !crate::ratelimit::ACCOUNT_PEER_FETCHES.allow(&limit_key) {
                return Err(
                    AppError::too_many_requests("too many lookups of that server")
                        .with_details(serde_json::json!({ "code": "rateLimited" })),
                );
            }
            let fetched = fetch(state, person).await?;
            *kept = Some((Instant::now(), fetched.clone()));
            fetched
        }
    };
    Ok(match fetched {
        Fetched::Found(remote) => Some(*remote),
        Fetched::Missing => None,
    })
}

/// Asks `person`'s server for them; an answer for anyone else is refused.
async fn fetch(state: &AppState, person: &AccountRef) -> AppResult<Fetched> {
    let federation = configured_stack(state)?;
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
        return Ok(Fetched::Missing);
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
        || !remote_keys_consistent(&remote)
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "the other server answered for another account",
        ));
    }
    Ok(Fetched::Found(Box::new(remote)))
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
        local_identity(
            &state,
            Uuid::parse_str(&person.account_id).expect("canonical"),
        )
        .await?
        .ok_or_else(|| AppError::not_found("no such account"))
    }
    .await;
    match result {
        Ok(found) => signed_json(federation, &authenticated, StatusCode::OK, &found),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(id: &str) -> AccountRef {
        AccountRef::new("peer.test", id).unwrap()
    }

    #[tokio::test]
    async fn lookups_of_one_account_share_one_fetch_and_its_answer() {
        let alice = person("3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70");
        let first = slot(&alice);
        // Another lookup of the same account meanwhile waits on the same
        // fetch; another account has its own.
        assert!(Arc::ptr_eq(&first, &slot(&alice)));
        assert!(!Arc::ptr_eq(
            &first,
            &slot(&person("8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b"))
        ));
        // What the fetch kept answers the next lookup, while fresh.
        *first.lock().await = Some((Instant::now(), Fetched::Missing));
        drop(first);
        let again = slot(&alice);
        let kept = again.lock().await;
        assert!(matches!(kept.as_ref(), Some((at, Fetched::Missing)) if at.elapsed() < FRESH_FOR));
        drop(kept);
        // A stale answer nobody waits on is dropped: the next lookup fetches.
        *again.lock().await = Some((Instant::now() - FRESH_FOR, Fetched::Missing));
        drop(again);
        assert!(slot(&alice).lock().await.is_none());
    }
}
