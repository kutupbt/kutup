//! Web Push wake-ups for Chat devices whose browser is closed
//! (docs/chat-notifications.md).
//!
//! The server cannot say what arrived: messages are end-to-end encrypted and
//! usually sealed-sender. So a push is empty: it wakes the browser's service
//! worker, which shows a generic "new activity" notification, and opening
//! Chat shows the rest. A push goes out only when the device has no live
//! WebSocket, at most once a minute per device, and the push service keeps
//! only the latest one (`Topic`). Pushes carry a VAPID signature (RFC 8292)
//! with a P-256 key the server makes once and keeps in its database, and go
//! only to the push services on an allowlist, so a subscription cannot point
//! the server at an arbitrary URL.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::chat_hub::ChatHub;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// One push per device per this long; the push service keeps the latest.
const MIN_INTERVAL: Duration = Duration::from_secs(60);
/// A device that reconnects this soon (a page reload) is not pushed.
const GRACE: Duration = Duration::from_secs(5);
/// How long a push service keeps an undelivered wake-up.
const TTL_SECONDS: u32 = 24 * 60 * 60;
const MAX_ENDPOINT_BYTES: usize = 2048;
/// Where browsers' push services live: Chrome and Edge (FCM), Firefox
/// (Mozilla autopush), Safari (Apple), and Windows' own.
pub const DEFAULT_PUSH_HOSTS: &str =
    "fcm.googleapis.com,updates.push.services.mozilla.com,.push.apple.com,.notify.windows.com";

pub struct WebPush {
    sender: mpsc::UnboundedSender<(Uuid, i32)>,
    signing_key: SigningKey,
    public_key: String,
    hosts: Vec<String>,
    subject: String,
}

impl WebPush {
    /// Load (or make, once) the VAPID key and start the sender.
    pub async fn start(
        pool: PgPool,
        hub: ChatHub,
        hosts: &str,
        subject: String,
    ) -> anyhow::Result<Arc<Self>> {
        let signing_key = load_or_create_key(&pool).await?;
        let point = signing_key.verifying_key().to_encoded_point(false);
        let (sender, receiver) = mpsc::unbounded_channel();
        let push = Arc::new(Self {
            sender,
            public_key: URL_SAFE_NO_PAD.encode(point.as_bytes()),
            signing_key,
            hosts: parse_hosts(hosts),
            subject,
        });
        tokio::spawn(run(push.clone(), pool, hub, receiver));
        Ok(push)
    }

    /// The application server key browsers subscribe with (base64url).
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Something arrived for a device with no live connection.
    pub fn wake(&self, user_id: Uuid, device_id: i32) {
        let _ = self.sender.send((user_id, device_id));
    }

    /// An endpoint this server will send to: https, port 443, an allowed host.
    pub fn allowed_endpoint(&self, endpoint: &str) -> bool {
        endpoint_allowed(endpoint, &self.hosts)
    }

    /// The `Authorization` header for a push to `endpoint`.
    fn authorization(&self, endpoint: &reqwest::Url, now: u64) -> String {
        let audience = endpoint.origin().ascii_serialization();
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "aud": audience, "exp": now + 12 * 60 * 60, "sub": self.subject })
                .to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        format!(
            "vapid t={signing_input}.{}, k={}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            self.public_key
        )
    }
}

fn parse_hosts(hosts: &str) -> Vec<String> {
    hosts
        .split(',')
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

fn endpoint_allowed(endpoint: &str, hosts: &[String]) -> bool {
    if endpoint.len() > MAX_ENDPOINT_BYTES {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && hosts.iter().any(|allowed| match allowed.strip_prefix('.') {
            Some(suffix) => host.ends_with(&format!(".{suffix}")),
            None => &host == allowed,
        })
}

async fn load_or_create_key(pool: &PgPool) -> anyhow::Result<SigningKey> {
    if let Some(bytes) =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT private_key FROM chat_web_push_key WHERE id = 1")
            .fetch_optional(pool)
            .await?
    {
        return Ok(SigningKey::from_slice(&bytes)?);
    }
    let created = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    sqlx::query(
        "INSERT INTO chat_web_push_key (id, private_key) VALUES (1, $1) ON CONFLICT DO NOTHING",
    )
    .bind(created.to_bytes().to_vec())
    .execute(pool)
    .await?;
    // Another instance may have won the race: use whatever is stored.
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT private_key FROM chat_web_push_key WHERE id = 1")
            .fetch_one(pool)
            .await?;
    Ok(SigningKey::from_slice(&bytes)?)
}

async fn run(
    push: Arc<WebPush>,
    pool: PgPool,
    hub: ChatHub,
    mut receiver: mpsc::UnboundedReceiver<(Uuid, i32)>,
) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "web push: cannot build an HTTP client; pushes are off");
            return;
        }
    };
    // When each device was last pushed; shared with the sending tasks.
    let last_sent: Arc<Mutex<HashMap<(Uuid, i32), Instant>>> = Arc::default();
    let waiting: Arc<Mutex<HashSet<(Uuid, i32)>>> = Arc::default();
    while let Some(device) = receiver.recv().await {
        if !waiting.lock().expect("web push lock").insert(device) {
            continue;
        }
        let (push, pool, client, hub) = (push.clone(), pool.clone(), client.clone(), hub.clone());
        let (last_sent, waiting) = (last_sent.clone(), waiting.clone());
        tokio::spawn(async move {
            tokio::time::sleep(GRACE).await;
            waiting.lock().expect("web push lock").remove(&device);
            if !hub.connections(device.0, device.1).is_empty() {
                return;
            }
            if let Err(error) = send(&push, &pool, &client, device, &last_sent).await {
                tracing::warn!(error = format!("{error:#}"), "web push: wake-up failed");
            }
        });
    }
}

async fn send(
    push: &WebPush,
    pool: &PgPool,
    client: &reqwest::Client,
    (user_id, device_id): (Uuid, i32),
    last_sent: &Mutex<HashMap<(Uuid, i32), Instant>>,
) -> anyhow::Result<()> {
    let Some(endpoint) = sqlx::query_scalar::<_, String>(
        "SELECT endpoint FROM chat_push_subscriptions WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(());
    };
    if !push.allowed_endpoint(&endpoint) {
        // The allowlist changed since it was stored.
        forget(pool, user_id, device_id).await?;
        return Ok(());
    }
    {
        let now = Instant::now();
        let mut sent = last_sent.lock().expect("web push lock");
        if sent
            .get(&(user_id, device_id))
            .is_some_and(|at| now.duration_since(*at) < MIN_INTERVAL)
        {
            return Ok(());
        }
        sent.retain(|_, at| now.duration_since(*at) < MIN_INTERVAL);
        sent.insert((user_id, device_id), now);
    }
    let url = reqwest::Url::parse(&endpoint)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let response = client
        .post(url.clone())
        .header("Authorization", push.authorization(&url, now))
        .header("TTL", TTL_SECONDS.to_string())
        .header("Urgency", "high")
        // A newer wake-up replaces one still waiting at the push service.
        .header("Topic", "kutup-chat")
        // Push services want the length even of an empty body.
        .header(reqwest::header::CONTENT_LENGTH, "0")
        .body(Vec::new())
        .send()
        .await?;
    tracing::debug!(status = %response.status(), "web push: wake-up sent");
    match response.status() {
        status if status.is_success() => Ok(()),
        // The browser dropped the subscription.
        StatusCode::NOT_FOUND | StatusCode::GONE => forget(pool, user_id, device_id).await,
        status => anyhow::bail!("push service answered {status}"),
    }
}

async fn forget(pool: &PgPool, user_id: Uuid, device_id: i32) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM chat_push_subscriptions WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Wake `device` when it has no live connection to hear about new mailbox rows.
pub(crate) fn wake_if_offline(state: &AppState, user_id: Uuid, device_id: i32) {
    if let Some(push) = &state.web_push {
        if state.chat_hub.connections(user_id, device_id).is_empty() {
            push.wake(user_id, device_id);
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PushSubscriptionRequest {
    pub device_id: i32,
    /// The browser's `PushSubscription.endpoint`.
    pub endpoint: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DeviceQuery {
    pub device_id: i32,
}

async fn require_device(pool: &PgPool, user_id: Uuid, device_id: i32) -> AppResult<()> {
    let exists: Option<i32> = sqlx::query_scalar(
        "SELECT device_id FROM chat_devices WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    exists
        .map(drop)
        .ok_or_else(|| AppError::not_found("chat device not found"))
}

#[utoipa::path(
    put,
    path = "/api/chat/push-subscription",
    tag = "chat",
    operation_id = "putChatPushSubscription",
    request_body = PushSubscriptionRequest,
    responses(
        (status = 204, description = "This device is woken through the subscription"),
        (status = 400, description = "Not an endpoint of an allowed push service"),
        (status = 404, description = "Web Push is off here, or no such device"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn put_subscription(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<PushSubscriptionRequest>,
) -> AppResult<Response> {
    let push = state
        .web_push
        .as_ref()
        .ok_or_else(|| AppError::not_found("Web Push is off on this server"))?;
    if !push.allowed_endpoint(&request.endpoint) {
        return Err(AppError::bad_request(
            "this push service is not one the server sends to",
        ));
    }
    let user_id = trusted_uuid(&auth.user_id)?;
    require_device(&state.pool, user_id, request.device_id).await?;
    sqlx::query(
        "INSERT INTO chat_push_subscriptions (user_id, device_id, endpoint)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, device_id)
         DO UPDATE SET endpoint = EXCLUDED.endpoint, updated_at = now()",
    )
    .bind(user_id)
    .bind(request.device_id)
    .bind(&request.endpoint)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(
    delete,
    path = "/api/chat/push-subscription",
    tag = "chat",
    operation_id = "deleteChatPushSubscription",
    params(DeviceQuery),
    responses((status = 204, description = "This device is no longer woken")),
    security(("bearerAuth" = []))
)]
pub async fn delete_subscription(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<DeviceQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&auth.user_id)?;
    forget(&state.pool, user_id, query.device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;

    #[test]
    fn only_allowed_push_services() {
        let hosts = parse_hosts(DEFAULT_PUSH_HOSTS);
        for good in [
            "https://fcm.googleapis.com/fcm/send/abc",
            "https://updates.push.services.mozilla.com/wpush/v2/x",
            "https://web.push.apple.com/QG3",
            "https://wns2-par02p.notify.windows.com/w/?token=1",
        ] {
            assert!(endpoint_allowed(good, &hosts), "{good}");
        }
        for bad in [
            "http://fcm.googleapis.com/fcm/send/abc",
            "https://fcm.googleapis.com:8443/x",
            "https://evil.fcm.googleapis.com.attacker.test/x",
            "https://push.apple.com.attacker.test/x",
            "https://user@fcm.googleapis.com/x",
            "https://169.254.169.254/latest",
            "https://localhost/x",
            "not a url",
        ] {
            assert!(!endpoint_allowed(bad, &hosts), "{bad}");
        }
        assert!(!endpoint_allowed(
            &format!("https://fcm.googleapis.com/{}", "a".repeat(3000)),
            &hosts
        ));
    }

    #[test]
    fn vapid_header_is_a_signed_es256_token_for_the_push_origin() {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let (sender, _receiver) = mpsc::unbounded_channel();
        let push = WebPush {
            sender,
            public_key: URL_SAFE_NO_PAD.encode(point.as_bytes()),
            signing_key,
            hosts: parse_hosts(DEFAULT_PUSH_HOSTS),
            subject: "mailto:admin@example.test".into(),
        };
        let url = reqwest::Url::parse("https://fcm.googleapis.com/fcm/send/abc").unwrap();
        let header = push.authorization(&url, 1_000);
        let token = header
            .strip_prefix("vapid t=")
            .unwrap()
            .split(", k=")
            .next()
            .unwrap();
        assert!(header.ends_with(&format!("k={}", push.public_key)));
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert_eq!(claims["exp"], 1_000 + 12 * 60 * 60);
        assert_eq!(claims["sub"], "mailto:admin@example.test");
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        push.signing_key
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }
}
