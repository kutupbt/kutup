//! ICE servers for Chat calls (docs/chat-calls.md).
//!
//! Call media flows between the browsers, encrypted by DTLS-SRTP with
//! fingerprints that travel inside the end-to-end encrypted call signals.
//! When a direct path fails, a TURN relay forwards the still-encrypted
//! packets. This server hands out short-lived TURN credentials in the
//! shared-secret scheme coturn's `use-auth-secret` understands
//! (username `<expiry>:<opaque id>`, password `base64(HMAC-SHA1(secret,
//! username))`), so the relay needs no account database.

use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;
use crate::AppState;

/// How long handed-out TURN credentials work.
const CREDENTIAL_TTL_SECONDS: i64 = 12 * 60 * 60;

static REQUESTS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(60, Duration::from_secs(60)));

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CallServersResponse {
    /// As `RTCConfiguration.iceServers` takes them.
    pub ice_servers: Vec<IceServer>,
    /// A TURN relay is configured, so calls can hide addresses ("always
    /// relay") and get through networks that block direct paths.
    pub relay: bool,
    /// When the TURN credentials stop working (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

fn split_urls(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The coturn REST-API credential for `user_id` until `expires_at`. The
/// username names a pseudonym, not the account, so the relay's logs don't.
fn turn_credential(secret: &str, user_id: &str, expires_at: i64) -> (String, String) {
    let pseudonym = hex::encode(&Sha256::digest(format!("kutup-turn:{secret}:{user_id}"))[..12]);
    let username = format!("{expires_at}:{pseudonym}");
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    (username, STANDARD.encode(mac.finalize().into_bytes()))
}

#[utoipa::path(
    get,
    path = "/api/chat/call-servers",
    tag = "chat",
    operation_id = "getChatCallServers",
    responses(
        (status = 200, description = "ICE servers for a call", body = CallServersResponse),
        (status = 429, description = "Too many requests"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn call_servers(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<CallServersResponse>> {
    if !REQUESTS.allow(&auth.user_id) {
        return Err(AppError::too_many_requests("too many call server requests"));
    }
    let config = &state.config;
    let mut ice_servers = Vec::new();
    let stun = split_urls(&config.chat_stun_urls);
    if !stun.is_empty() {
        ice_servers.push(IceServer {
            urls: stun,
            username: None,
            credential: None,
        });
    }
    let turn = split_urls(&config.chat_turn_urls);
    let relay = !turn.is_empty() && !config.chat_turn_secret.is_empty();
    let mut expires_at = None;
    if relay {
        let until = time::OffsetDateTime::now_utc().unix_timestamp() + CREDENTIAL_TTL_SECONDS;
        let (username, credential) = turn_credential(&config.chat_turn_secret, &auth.user_id, until);
        ice_servers.push(IceServer {
            urls: turn,
            username: Some(username),
            credential: Some(credential),
        });
        expires_at = Some(until);
    }
    Ok(Json(CallServersResponse {
        ice_servers,
        relay,
        expires_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_credentials_follow_the_coturn_rest_scheme() {
        let (username, password) = turn_credential("north-secret", "user-1", 1_700_000_000);
        let (prefix, pseudonym) = username.split_once(':').unwrap();
        assert_eq!(prefix, "1700000000");
        assert_eq!(pseudonym.len(), 24);
        assert!(!username.contains("user-1"));
        let mut mac = Hmac::<Sha1>::new_from_slice(b"north-secret").unwrap();
        mac.update(username.as_bytes());
        assert_eq!(password, STANDARD.encode(mac.finalize().into_bytes()));
        // Stable per account, different across accounts.
        assert_eq!(turn_credential("north-secret", "user-1", 1_700_000_000).0, username);
        assert_ne!(turn_credential("north-secret", "user-2", 1_700_000_000).0, username);
    }

    #[test]
    fn urls_are_a_comma_list() {
        assert_eq!(
            split_urls(" turn:a.test:3478?transport=udp , turns:a.test:5349,"),
            vec!["turn:a.test:3478?transport=udp", "turns:a.test:5349"]
        );
        assert!(split_urls("").is_empty());
    }
}
