//! Group invite link mailboxes (docs/chat-invite-links.md).
//!
//! A link's host keeps, under an id derived from the link's secret, the
//! group's sealed preview and the sealed requests to join. Members manage
//! the mailbox with a token only link holders can derive (the host stores
//! its SHA-256); requesters read or cancel their own request with a token
//! they chose. Accounts reach a remote host through their own server, which
//! forwards the operation over signed federation; the host records which
//! server each request came through, so administrators can check that the
//! sealed requester belongs to it.

use std::sync::LazyLock;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    InviteLinkCallV1, InviteLinkOperationV1, InviteLinkRequestEntryV1, InviteLinkResultV1,
    InviteRequestStatusV1, MAX_PENDING_INVITE_REQUESTS,
};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{active_policy, signed_federation_error, signed_federation_json};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;
use crate::AppState;

const FEDERATION_PATH: &str = "/api/fed/chat/invite-links";
/// Mailboxes one server may keep on a host.
const MAX_LINKS_PER_ORIGIN: i64 = 10_000;
/// Undecided requests from one server to one link.
const MAX_PENDING_PER_ORIGIN: i64 = 32;

static ACCOUNT_CALLS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(120, Duration::from_secs(60)));
static ACCOUNT_REQUESTS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(10, Duration::from_secs(60 * 60)));
static ORIGIN_CALLS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(600, Duration::from_secs(60)));

fn token_hash(token: &str) -> AppResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(token)
        .map_err(|_| AppError::bad_request("invite link token must be base64"))?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn status_code(status: InviteRequestStatusV1) -> i16 {
    match status {
        InviteRequestStatusV1::Pending => 0,
        InviteRequestStatusV1::Approved => 1,
        InviteRequestStatusV1::Denied => 2,
    }
}

fn status_from(code: i16) -> AppResult<InviteRequestStatusV1> {
    match code {
        0 => Ok(InviteRequestStatusV1::Pending),
        1 => Ok(InviteRequestStatusV1::Approved),
        2 => Ok(InviteRequestStatusV1::Denied),
        _ => Err(AppError::internal(
            "stored invite request status is invalid",
        )),
    }
}

fn link_missing() -> AppError {
    AppError::not_found("this group link no longer works")
}

async fn authorize_manager(pool: &PgPool, link_id: &str, manage_token: &str) -> AppResult<()> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT manage_hash FROM chat_invite_links WHERE link_id = $1")
            .bind(link_id)
            .fetch_optional(pool)
            .await?;
    match stored {
        None => Err(link_missing()),
        Some(hash) if hash == token_hash(manage_token)? => Ok(()),
        Some(_) => Err(AppError::forbidden("invite link token does not match")),
    }
}

/// Carry out one operation on a mailbox this server hosts. `origin` is the
/// server the operation came through (this one for its own accounts).
pub(crate) async fn execute(
    pool: &PgPool,
    origin: &str,
    operation: &InviteLinkOperationV1,
) -> AppResult<InviteLinkResultV1> {
    operation.validate().map_err(AppError::bad_request)?;
    match operation {
        InviteLinkOperationV1::Put {
            link_id,
            manage_token,
            preview,
        } => {
            let hash = token_hash(manage_token)?;
            let mut tx = pool.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5117))")
                .bind(origin)
                .execute(&mut *tx)
                .await?;
            let existing: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT manage_hash FROM chat_invite_links WHERE link_id = $1 FOR UPDATE",
            )
            .bind(link_id)
            .fetch_optional(&mut *tx)
            .await?;
            match existing {
                Some(stored) if stored != hash => {
                    return Err(AppError::forbidden("invite link token does not match"))
                }
                Some(_) => {
                    sqlx::query(
                        "UPDATE chat_invite_links SET preview = $2, touched_at = now()
                         WHERE link_id = $1",
                    )
                    .bind(link_id)
                    .bind(preview)
                    .execute(&mut *tx)
                    .await?;
                }
                None => {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM chat_invite_links WHERE origin_domain = $1",
                    )
                    .bind(origin)
                    .fetch_one(&mut *tx)
                    .await?;
                    if count >= MAX_LINKS_PER_ORIGIN {
                        return Err(AppError::too_many_requests(
                            "too many group links from this server",
                        ));
                    }
                    sqlx::query(
                        "INSERT INTO chat_invite_links (link_id, manage_hash, preview, origin_domain)
                         VALUES ($1, $2, $3, $4)",
                    )
                    .bind(link_id)
                    .bind(&hash)
                    .bind(preview)
                    .bind(origin)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            tx.commit().await?;
            Ok(InviteLinkResultV1::Done)
        }
        InviteLinkOperationV1::Delete {
            link_id,
            manage_token,
        } => {
            match authorize_manager(pool, link_id, manage_token).await {
                // Already gone: deleting again is not an error.
                Err(error) if error.status == StatusCode::NOT_FOUND => {}
                other => other?,
            }
            sqlx::query("DELETE FROM chat_invite_links WHERE link_id = $1")
                .bind(link_id)
                .execute(pool)
                .await?;
            Ok(InviteLinkResultV1::Done)
        }
        InviteLinkOperationV1::Preview { link_id } => {
            let preview: Option<String> =
                sqlx::query_scalar("SELECT preview FROM chat_invite_links WHERE link_id = $1")
                    .bind(link_id)
                    .fetch_optional(pool)
                    .await?;
            preview
                .map(|preview| InviteLinkResultV1::Preview { preview })
                .ok_or_else(link_missing)
        }
        InviteLinkOperationV1::Request {
            link_id,
            request,
            status_token,
        } => {
            let mut tx = pool.begin().await?;
            let exists: Option<String> = sqlx::query_scalar(
                "SELECT link_id FROM chat_invite_links WHERE link_id = $1 FOR UPDATE",
            )
            .bind(link_id)
            .fetch_optional(&mut *tx)
            .await?;
            if exists.is_none() {
                return Err(link_missing());
            }
            let (pending, from_origin): (i64, i64) = sqlx::query_as(
                "SELECT count(*), count(*) FILTER (WHERE origin_domain = $2)
                 FROM chat_invite_requests WHERE link_id = $1 AND status = 0",
            )
            .bind(link_id)
            .bind(origin)
            .fetch_one(&mut *tx)
            .await?;
            if pending >= MAX_PENDING_INVITE_REQUESTS as i64
                || from_origin >= MAX_PENDING_PER_ORIGIN
            {
                return Err(AppError::too_many_requests(
                    "this group has too many requests waiting; try again later",
                ));
            }
            let request_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO chat_invite_requests (id, link_id, origin_domain, request, status_hash)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(request_id)
            .bind(link_id)
            .bind(origin)
            .bind(request)
            .bind(token_hash(status_token)?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(InviteLinkResultV1::Requested { request_id })
        }
        InviteLinkOperationV1::Requests {
            link_id,
            manage_token,
        } => {
            authorize_manager(pool, link_id, manage_token).await?;
            sqlx::query("UPDATE chat_invite_links SET touched_at = now() WHERE link_id = $1")
                .bind(link_id)
                .execute(pool)
                .await?;
            let rows: Vec<(Uuid, String, String, i16, OffsetDateTime)> = sqlx::query_as(
                "SELECT id, origin_domain, request, status, created_at
                 FROM chat_invite_requests WHERE link_id = $1
                 ORDER BY created_at, id LIMIT $2",
            )
            .bind(link_id)
            .bind((MAX_PENDING_INVITE_REQUESTS * 2) as i64)
            .fetch_all(pool)
            .await?;
            let requests = rows
                .into_iter()
                .map(|(request_id, origin_domain, request, status, created_at)| {
                    Ok(InviteLinkRequestEntryV1 {
                        request_id,
                        origin_domain,
                        request,
                        status: status_from(status)?,
                        created_at_ms: (created_at.unix_timestamp_nanos() / 1_000_000) as i64,
                    })
                })
                .collect::<AppResult<Vec<_>>>()?;
            Ok(InviteLinkResultV1::Requests { requests })
        }
        InviteLinkOperationV1::Decide {
            link_id,
            manage_token,
            request_id,
            approve,
        } => {
            authorize_manager(pool, link_id, manage_token).await?;
            let status = if *approve {
                InviteRequestStatusV1::Approved
            } else {
                InviteRequestStatusV1::Denied
            };
            // The first decision stands; deciding again changes nothing.
            let done = sqlx::query(
                "UPDATE chat_invite_requests SET status = $3, decided_at = now()
                 WHERE id = $1 AND link_id = $2 AND status = 0",
            )
            .bind(request_id)
            .bind(link_id)
            .bind(status_code(status))
            .execute(pool)
            .await?;
            if done.rows_affected() == 0 {
                let exists: Option<i16> = sqlx::query_scalar(
                    "SELECT status FROM chat_invite_requests WHERE id = $1 AND link_id = $2",
                )
                .bind(request_id)
                .bind(link_id)
                .fetch_optional(pool)
                .await?;
                if exists.is_none() {
                    return Err(AppError::not_found("invite request not found"));
                }
            }
            Ok(InviteLinkResultV1::Done)
        }
        InviteLinkOperationV1::Status {
            link_id,
            request_id,
            status_token,
        } => {
            let status: Option<i16> = sqlx::query_scalar(
                "SELECT status FROM chat_invite_requests
                 WHERE id = $1 AND link_id = $2 AND status_hash = $3",
            )
            .bind(request_id)
            .bind(link_id)
            .bind(token_hash(status_token)?)
            .fetch_optional(pool)
            .await?;
            let status = status.ok_or_else(|| AppError::not_found("invite request not found"))?;
            Ok(InviteLinkResultV1::Status {
                status: status_from(status)?,
            })
        }
        InviteLinkOperationV1::Cancel {
            link_id,
            request_id,
            status_token,
        } => {
            sqlx::query(
                "DELETE FROM chat_invite_requests
                 WHERE id = $1 AND link_id = $2 AND status_hash = $3",
            )
            .bind(request_id)
            .bind(link_id)
            .bind(token_hash(status_token)?)
            .execute(pool)
            .await?;
            Ok(InviteLinkResultV1::Done)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/chat/invite-links",
    tag = "chat",
    operation_id = "callChatInviteLink",
    request_body = InviteLinkCallV1,
    responses(
        (status = 200, description = "The operation's result", body = InviteLinkResultV1),
        (status = 403, description = "The link token does not match"),
        (status = 404, description = "The link or request no longer exists, or groups are off"),
        (status = 429, description = "Too many operations or waiting requests"),
        (status = 502, description = "The link's host could not be reached"),
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn call(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(call): Json<InviteLinkCallV1>,
) -> AppResult<Json<InviteLinkResultV1>> {
    active_policy(&state).await?;
    call.validate().map_err(AppError::bad_request)?;
    if !ACCOUNT_CALLS.allow(&auth.user_id)
        || (matches!(call.operation, InviteLinkOperationV1::Request { .. })
            && !ACCOUNT_REQUESTS.allow(&auth.user_id))
    {
        return Err(AppError::too_many_requests(
            "too many group link requests; try again later",
        ));
    }
    let federation = state
        .federation
        .as_ref()
        .expect("active MLS policy requires federation");
    if call.host == federation.server_name() {
        return Ok(Json(
            execute(&state.pool, federation.server_name(), &call.operation).await?,
        ));
    }
    let body = serde_json::to_vec(&call.operation)
        .map_err(|error| AppError::internal(format!("serialize invite link call: {error}")))?;
    let response = federation
        .send(
            &call.host,
            FederationRequestSpec {
                feature: FederationFeature::ChatV1,
                method: Method::POST,
                path: FEDERATION_PATH.into(),
                query: None,
                content_type: "application/json".into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 2 * 1024 * 1024,
            },
        )
        .await
        .map_err(|error| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("the group link's server could not be reached: {error}"),
            )
        })?;
    if response.status != StatusCode::OK {
        let message = serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("the group link's server returned {}", response.status));
        return Err(match response.status {
            StatusCode::NOT_FOUND
            | StatusCode::FORBIDDEN
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_REQUEST => AppError::new(response.status, message),
            _ => AppError::new(StatusCode::BAD_GATEWAY, message),
        });
    }
    let result: InviteLinkResultV1 = serde_json::from_slice(&response.body).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "the group link's server sent an invalid answer",
        )
    })?;
    if !result.answers(&call.operation) {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "the group link's server sent an invalid answer",
        ));
    }
    Ok(Json(result))
}

pub(crate) async fn federated_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            FEDERATION_PATH,
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    if let Err(error) = active_policy(&state).await {
        return signed_federation_error(federation, &authenticated, error);
    }
    if authenticated.destination() != federation.server_name() {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::unauthorized("invite link federation routing mismatch"),
        );
    }
    if !ORIGIN_CALLS.allow(authenticated.origin()) {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::too_many_requests("too many group link operations"),
        );
    }
    let operation: InviteLinkOperationV1 = match serde_json::from_slice(&body) {
        Ok(operation) => operation,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid invite link operation"),
            )
        }
    };
    match execute(&state.pool, authenticated.origin(), &operation).await {
        Ok(result) => signed_federation_json(federation, &authenticated, StatusCode::OK, &result),
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

/// Forget mailboxes no member has looked at for `idle_days`, requests
/// decided more than a week ago, and requests nobody decided within
/// `idle_days`. Members' clients recreate a live link's mailbox when it is
/// gone, so only abandoned links disappear.
pub(crate) async fn sweep(pool: &PgPool, idle_days: i32) -> anyhow::Result<u64> {
    let links = sqlx::query(
        "DELETE FROM chat_invite_links WHERE touched_at < now() - ($1 * interval '1 day')",
    )
    .bind(idle_days)
    .execute(pool)
    .await?
    .rows_affected();
    let requests = sqlx::query(
        "DELETE FROM chat_invite_requests
         WHERE (status <> 0 AND decided_at < now() - interval '7 days')
            OR created_at < now() - ($1 * interval '1 day')",
    )
    .bind(idle_days)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(links + requests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hashes_are_sha256_of_the_decoded_token() {
        let token = STANDARD.encode([3u8; 32]);
        assert_eq!(
            token_hash(&token).unwrap(),
            Sha256::digest([3u8; 32]).to_vec()
        );
        assert!(token_hash("not base64!").is_err());
    }

    #[test]
    fn statuses_round_trip() {
        for status in [
            InviteRequestStatusV1::Pending,
            InviteRequestStatusV1::Approved,
            InviteRequestStatusV1::Denied,
        ] {
            assert_eq!(status_from(status_code(status)).unwrap(), status);
        }
        assert!(status_from(9).is_err());
    }
}
