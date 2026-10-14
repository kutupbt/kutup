//! The account head's read side (docs/plans/rollback-protection.md): the
//! newest head, a chain segment for the fork check, and a scope's index with
//! the head it goes with.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::account_heads::{self, Scope};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeadView {
    /// The newest sealed head (base64); none until the account's first write
    /// that carries one.
    head: Option<String>,
}

/// `GET /api/account/head` — the account's newest head.
#[utoipa::path(
    get,
    path = "/api/account/head",
    tag = "account",
    security(("BearerAuth" = [])),
    responses((status = 200, body = HeadView))
)]
pub async fn head(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let head = account_heads::latest(&state.pool, user_id).await?;
    Ok(Json(HeadView {
        head: head.map(|(_, sealed)| STANDARD.encode(sealed)),
    })
    .into_response())
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct HeadsQuery {
    /// The first sequence wanted (a device's anchor).
    from: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeadsView {
    /// Sealed heads (base64) from `from` to the newest, oldest first; empty
    /// when `from` is above the newest.
    heads: Vec<String>,
}

/// `GET /api/account/heads?from=n` — the chain from `n` to the newest, for a
/// device to check that the current head descends from its last own write.
/// `410` with `code: "tooOld"` when `n` is past the kept window
/// (`RETENTION` heads).
#[utoipa::path(
    get,
    path = "/api/account/heads",
    tag = "account",
    security(("BearerAuth" = [])),
    params(HeadsQuery),
    responses(
        (status = 200, body = HeadsView),
        (status = 410, description = "tooOld: past the kept window")
    )
)]
pub async fn heads(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<HeadsQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    if query.from < 1 {
        return Err(AppError::bad_request("from is a sequence of 1 or more"));
    }
    match account_heads::segment(&state.pool, user_id, query.from).await? {
        Some(heads) => Ok(Json(HeadsView {
            heads: heads.into_iter().map(|h| STANDARD.encode(h)).collect(),
        })
        .into_response()),
        None => Err(
            AppError::new(StatusCode::GONE, "that head is past the kept window")
                .with_details(serde_json::json!({ "code": "tooOld" })),
        ),
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexView {
    /// The newest sealed head (base64) the index goes with; none before the
    /// account's first.
    head: Option<String>,
    /// `[id, revision]` of every value of the scope, sorted by id.
    #[schema(value_type = Vec<Vec<serde_json::Value>>)]
    values: Vec<(String, i64)>,
}

/// `GET /api/account/index/{scope}` — a scope's `(id, revision)` pairs and
/// the head read with them (one snapshot). Scopes: `contacts`, `mailNames`,
/// `pins`, `passSecrets`; any other is `404` (a client treats it as a scope
/// with no index yet).
#[utoipa::path(
    get,
    path = "/api/account/index/{scope}",
    tag = "account",
    security(("BearerAuth" = [])),
    params(("scope" = String, Path, description = "contacts, mailNames, pins or passSecrets")),
    responses(
        (status = 200, body = IndexView),
        (status = 404, description = "No such scope")
    )
)]
pub async fn index(
    State(state): State<AppState>,
    user: AuthUser,
    Path(scope): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let scope = Scope::parse(&scope).ok_or_else(|| AppError::not_found("no such scope"))?;
    let (head, values) = account_heads::index(&state.pool, user_id, scope).await?;
    Ok(Json(IndexView {
        head: head.map(|h| STANDARD.encode(h)),
        values,
    })
    .into_response())
}
