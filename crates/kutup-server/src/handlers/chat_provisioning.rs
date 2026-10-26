//! Linking a Chat device, as Signal links one (docs/plans/account-identity-key.md):
//! an existing device asks for a one-time link token and sends the new
//! device the account identity in a provisioning message, encrypted to the
//! new device's ephemeral key from its link code. The server relays that
//! message once, between two sessions of one account, and keeps nothing.
//!
//! - `POST /api/chat/link-tokens` (device-authenticated): a token.
//! - `POST /api/chat/provisioning/ticket` (signed in): a ticket for the socket
//!   (a browser can't send headers on a WebSocket), as Chat's socket tickets.
//! - `GET /api/chat/provisioning?ticket=` (WebSocket): `{type: address}`, then
//!   at most one `{type: envelope}`; pings every 30 s; closed with 1000 after
//!   the envelope and 4408 when the link token's lifetime ends.
//! - `PUT /api/chat/provisioning/{address}` (device-authenticated): the
//!   envelope, to a socket of the same account; any other address is `404`.

use kutup_crypto::primitives::{hash, Suite};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use kutup_chat_proto::{
    decode_provisioning_address, ChatLinkTokenResponse, ProvisionEnvelopeV1,
    ProvisioningRelayRequest, ProvisioningSocketMessage, PROVISIONING_ADDRESS_LEN,
};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::chat_identity::authenticated_device;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::site_settings::{
    CHAT_LINK_TOKENS_PER_ACCOUNT, CHAT_LINK_TOKEN_SECONDS, CHAT_PROVISIONING_SOCKETS_PER_ACCOUNT,
    CHAT_PROVISIONING_TICKET_SECONDS, CHAT_PROVISION_BODY_BYTES,
};
use crate::{ratelimit, AppState};

/// Nothing the new device sends matters: its frames are small or refused.
const MAX_INCOMING_FRAME: usize = 1024;
const PING_EVERY: Duration = Duration::from_secs(30);
/// The close code at the end of the socket's life (the client shows a new
/// link code).
const CLOSE_EXPIRED: u16 = 4408;

type Address = [u8; PROVISIONING_ADDRESS_LEN];

/// A waiting socket: the account that opened it, and where its one
/// envelope goes.
type Waiting = (Uuid, oneshot::Sender<ProvisionEnvelopeV1>);
/// A socket ticket: the account, and when it lapses.
type Ticket = (Uuid, Instant);

/// The sockets waiting for their one envelope, by address. Kept in this
/// process: a deployment of several server processes needs the new device's
/// socket and the relay on the same one (or a shared relay), as Chat's own
/// sockets do.
static SOCKETS: LazyLock<Mutex<HashMap<Address, Waiting>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Socket tickets, by their hash.
static TICKETS: LazyLock<Mutex<HashMap<[u8; 32], Ticket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    kutup_crypto::primitives::random(&mut bytes);
    bytes
}

fn rate_limited() -> AppError {
    AppError::too_many_requests("too many requests")
        .with_details(serde_json::json!({ "code": "rateLimited" }))
}

/// `POST /api/chat/link-tokens` (device-authenticated): one single-use token
/// for one new device, lasting `chatLinkTokenSeconds`; at most
/// `chatLinkTokensPerAccount` unused at once (`409 linkTokenLimit`).
#[utoipa::path(
    post,
    path = "/api/chat/link-tokens",
    tag = "chat",
    operation_id = "createChatLinkToken",
    responses(
        (status = 200, description = "A link token", body = ChatLinkTokenResponse),
        (status = 401, description = "Missing or wrong device credential"),
        (status = 409, description = "As many unused tokens as allowed"),
        (status = 429, description = "Too many tokens asked for"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn create_link_token(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let device_id = authenticated_device(&state.pool, &headers, user_id).await?;
    if !ratelimit::CHAT_LINK_TOKENS.allow(&auth.user_id) {
        return Err(rate_limited());
    }
    let lifetime = CHAT_LINK_TOKEN_SECONDS.load(&state.pool).await?;
    let most = CHAT_LINK_TOKENS_PER_ACCOUNT
        .load_for(&state.pool, user_id)
        .await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    // Spent and lapsed tokens are kept only until the account asks again.
    sqlx::query(
        "DELETE FROM chat_link_tokens
          WHERE user_id = $1 AND (used_at IS NOT NULL OR expires_at <= now())",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    let unused: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_link_tokens WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if unused >= most {
        return Err(
            AppError::conflict("as many link tokens as allowed are unused")
                .with_details(serde_json::json!({ "code": "linkTokenLimit" })),
        );
    }
    let token: [u8; 32] = random();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(lifetime);
    sqlx::query(
        "INSERT INTO chat_link_tokens (token_hash, user_id, issued_by_device, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(hash(Suite::V1, token).to_vec())
    .bind(user_id)
    .bind(device_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(ChatLinkTokenResponse {
        token: URL_SAFE_NO_PAD.encode(token),
        expires_at: expires_at
            .format(&Rfc3339)
            .map_err(|_| AppError::internal("format expiry"))?,
    })
    .into_response())
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningTicketResponse {
    /// For `GET /api/chat/provisioning?ticket=`, once, within a minute.
    pub ticket: String,
}

/// `POST /api/chat/provisioning/ticket` (signed in; the device to be linked
/// has no Chat credential yet): a ticket for the provisioning socket.
#[utoipa::path(
    post,
    path = "/api/chat/provisioning/ticket",
    tag = "chat",
    operation_id = "createChatProvisioningTicket",
    responses(
        (status = 200, description = "A socket ticket", body = ProvisioningTicketResponse),
        (status = 429, description = "Too many sockets from this address"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn create_ticket(State(state): State<AppState>, auth: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    let lifetime = CHAT_PROVISIONING_TICKET_SECONDS.load(&state.pool).await?;
    let most = CHAT_PROVISIONING_SOCKETS_PER_ACCOUNT
        .load_for(&state.pool, user_id)
        .await?;
    // Open sockets and tickets not yet used both count: each ticket may
    // become a socket. The upgrade checks again (`socket`).
    let now = Instant::now();
    let mut tickets = TICKETS.lock().expect("provisioning tickets");
    tickets.retain(|_, (_, lapses)| *lapses > now);
    let unused = tickets
        .values()
        .filter(|(owner, _)| *owner == user_id)
        .count();
    if (open_sockets(user_id) + unused) as i64 >= most {
        return Err(too_many_sockets());
    }
    let ticket: [u8; 32] = random();
    tickets.insert(
        hash(Suite::V1, ticket).into(),
        (
            user_id,
            now + Duration::from_secs(u64::try_from(lifetime).unwrap_or(60)),
        ),
    );
    Ok(Json(ProvisioningTicketResponse {
        ticket: URL_SAFE_NO_PAD.encode(ticket),
    })
    .into_response())
}

fn too_many_sockets() -> AppError {
    AppError::too_many_requests("as many linking sockets as allowed are open")
        .with_details(serde_json::json!({ "code": "rateLimited" }))
}

fn open_sockets(user_id: Uuid) -> usize {
    SOCKETS
        .lock()
        .expect("provisioning sockets")
        .values()
        .filter(|(owner, _)| *owner == user_id)
        .count()
}

#[derive(Debug, Deserialize)]
pub struct SocketQuery {
    ticket: String,
}

/// `GET /api/chat/provisioning?ticket=` (WebSocket): the new device's
/// provisioning socket.
pub async fn socket(
    State(state): State<AppState>,
    Query(query): Query<SocketQuery>,
    upgrade: WebSocketUpgrade,
) -> AppResult<Response> {
    let ticket: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&query.ticket)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| AppError::unauthorized("invalid provisioning ticket"))?;
    let user_id = {
        let mut tickets = TICKETS.lock().expect("provisioning tickets");
        match tickets.remove(&<[u8; 32]>::from(hash(Suite::V1, ticket))) {
            Some((user_id, lapses)) if lapses > Instant::now() => user_id,
            _ => return Err(AppError::unauthorized("invalid provisioning ticket")),
        }
    };
    let lifetime = CHAT_LINK_TOKEN_SECONDS.load(&state.pool).await?;
    let lifetime = Duration::from_secs(u64::try_from(lifetime).unwrap_or(600));
    let most = CHAT_PROVISIONING_SOCKETS_PER_ACCOUNT
        .load_for(&state.pool, user_id)
        .await?;
    // The socket's place, taken under the lock that counts the account's
    // open sockets: concurrent upgrades can't pass the cap together.
    let address: Address = random();
    let (sender, envelope) = oneshot::channel();
    {
        let mut sockets = SOCKETS.lock().expect("provisioning sockets");
        let open = sockets
            .values()
            .filter(|(owner, _)| *owner == user_id)
            .count();
        if open as i64 >= most {
            return Err(too_many_sockets());
        }
        sockets.insert(address, (user_id, sender));
    }
    Ok(upgrade
        .max_message_size(MAX_INCOMING_FRAME)
        .max_frame_size(MAX_INCOMING_FRAME)
        .on_failed_upgrade(move |_| {
            SOCKETS
                .lock()
                .expect("provisioning sockets")
                .remove(&address);
        })
        .on_upgrade(move |socket| serve(socket, address, envelope, lifetime)))
}

async fn serve(
    socket: WebSocket,
    address: Address,
    mut envelope: oneshot::Receiver<ProvisionEnvelopeV1>,
    lifetime: Duration,
) {
    let (mut sink, mut stream) = socket.split();
    let first = ProvisioningSocketMessage::Address {
        address: URL_SAFE_NO_PAD.encode(address),
    };
    let close = |code: u16, reason: &'static str| {
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))
    };
    if let Ok(text) = serde_json::to_string(&first) {
        if sink.send(Message::Text(text)).await.is_ok() {
            let ends = tokio::time::sleep(lifetime);
            tokio::pin!(ends);
            let mut ping = tokio::time::interval(PING_EVERY);
            ping.tick().await;
            loop {
                tokio::select! {
                    received = &mut envelope => {
                        if let Ok(envelope) = received {
                            let message = ProvisioningSocketMessage::Envelope { envelope };
                            if let Ok(text) = serde_json::to_string(&message) {
                                let _ = sink.send(Message::Text(text)).await;
                            }
                            let _ = sink.send(close(1000, "relayed")).await;
                        }
                        break;
                    }
                    _ = &mut ends => {
                        let _ = sink.send(close(CLOSE_EXPIRED, "expired")).await;
                        break;
                    }
                    _ = ping.tick() => {
                        if sink.send(Message::Ping(Vec::new())).await.is_err() {
                            break;
                        }
                    }
                    incoming = stream.next() => match incoming {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        _ => {}
                    },
                }
            }
        }
    }
    SOCKETS
        .lock()
        .expect("provisioning sockets")
        .remove(&address);
}

/// `PUT /api/chat/provisioning/{address}` (device-authenticated): relay one
/// provisioning envelope to a socket of the caller's account. "No such
/// socket" and "another account's socket" are the same `404`, so addresses
/// can't be probed.
#[utoipa::path(
    put,
    path = "/api/chat/provisioning/{address}",
    tag = "chat",
    operation_id = "relayChatProvisioning",
    params(("address" = String, Path, description = "The socket's address (base64url)")),
    request_body = ProvisioningRelayRequest,
    responses(
        (status = 204, description = "Relayed"),
        (status = 400, description = "Malformed or too large"),
        (status = 401, description = "Missing or wrong device credential"),
        (status = 404, description = "No socket of this account at that address"),
        (status = 429, description = "Too many relays"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn relay(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Path(address): Path<String>,
    Json(request): Json<ProvisioningRelayRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    authenticated_device(&state.pool, &headers, user_id).await?;
    if !ratelimit::CHAT_PROVISIONING_RELAYS.allow(&auth.user_id) {
        return Err(rate_limited());
    }
    let most = CHAT_PROVISION_BODY_BYTES.load(&state.pool).await?;
    // The body's encoded size bounds the decoded one.
    if i64::try_from(request.envelope.body.len()).unwrap_or(i64::MAX) > most * 4 / 3 + 4 {
        return Err(AppError::bad_request(
            "the provisioning message is too large",
        ));
    }
    request.envelope.validate().map_err(AppError::bad_request)?;
    let not_found = || AppError::not_found("no such provisioning socket");
    let address = decode_provisioning_address(&address).map_err(|_| not_found())?;
    let sender = {
        let mut sockets = SOCKETS.lock().expect("provisioning sockets");
        match sockets.get(&address) {
            Some((owner, _)) if *owner == user_id => sockets.remove(&address).map(|(_, s)| s),
            _ => None,
        }
    };
    sender
        .ok_or_else(not_found)?
        .send(request.envelope)
        .map_err(|_| not_found())?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
