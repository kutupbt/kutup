use std::sync::Arc;

use async_trait::async_trait;
use kutup_chat_core::{
    ChatError, ChatTransport, IdentityPinsRecord, IdentityPinsWrite, Result as CoreResult,
    SendOutcome,
};
use kutup_chat_proto::{
    AccountIdentityDistributionRequest, AccountManifestHistoryPageV3, AccountManifestPublicationV3,
    AccountManifestV3, AccountPreKeyBundlesResponse, ChatLinkTokenResponse, DeviceListMismatch,
    MailboxPage, PreKeyCountResponse, ProvisioningRelayRequest, RegisterChatDeviceRequestV2,
    RegisterChatDeviceResponse, ReplenishKeysRequest, SendMessagesRequest,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::types::{ChatHttpMethod, ChatHttpRequest, ChatHttpResponse, Result};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// One authenticated HTTP seam implemented by URLSession or OkHttp. Rust keeps
/// endpoint construction and every protocol DTO on its side of the boundary.
#[uniffi::export(foreign)]
// `async_trait` marks each method's boxed future `#[must_use]` without a
// message, which clippy reads as a second `must_use` on a `Result`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait ChatHttpClient: Send + Sync {
    async fn execute(&self, request: ChatHttpRequest) -> Result<ChatHttpResponse>;
}

pub(crate) struct NativeTransport {
    pub http: Arc<dyn ChatHttpClient>,
    /// `<deviceId>.<credential>` once the device is registered.
    pub device: std::sync::Mutex<Option<String>>,
}

impl NativeTransport {
    pub(crate) fn new(http: Arc<dyn ChatHttpClient>) -> Self {
        Self {
            http,
            device: std::sync::Mutex::new(None),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliveredResponse {
    #[serde(default)]
    deduplicated: bool,
}

#[async_trait(?Send)]
impl ChatTransport for NativeTransport {
    fn set_device_auth(&self, device_id: u32, credential: &str) {
        *self.device.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(format!("{device_id}.{credential}"));
    }

    async fn create_link_token(&self) -> CoreResult<ChatLinkTokenResponse> {
        self.json::<(), _>(ChatHttpMethod::Post, "/chat/link-tokens".into(), None)
            .await
    }

    async fn relay_provisioning(
        &self,
        address: &str,
        request: &ProvisioningRelayRequest,
    ) -> CoreResult<bool> {
        let response = self
            .request(
                ChatHttpMethod::Put,
                format!("/chat/provisioning/{}", urlencoding::encode(address)),
                Some(encode(request)?),
            )
            .await?;
        if response.status == 404 {
            return Ok(false);
        }
        ensure_success(&response)?;
        Ok(true)
    }

    async fn distribute_identity(
        &self,
        request: &AccountIdentityDistributionRequest,
    ) -> CoreResult<kutup_chat_core::DistributionOutcome> {
        let response = self
            .request(
                ChatHttpMethod::Put,
                "/chat/account-identity".into(),
                Some(encode(request)?),
            )
            .await?;
        if response.status == 409 || response.status == 410 {
            return Ok(kutup_chat_core::DistributionOutcome::Mismatch(decode(
                &response.body_json,
            )?));
        }
        ensure_success(&response)?;
        Ok(kutup_chat_core::DistributionOutcome::Accepted)
    }

    async fn register_device(&self, request: &RegisterChatDeviceRequestV2) -> CoreResult<u32> {
        let response: RegisterChatDeviceResponse = self
            .json(ChatHttpMethod::Post, "/chat/device".into(), Some(request))
            .await?;
        Ok(response.device_id)
    }

    async fn fetch_bundles(&self, account: &str) -> CoreResult<AccountPreKeyBundlesResponse> {
        self.json::<(), _>(ChatHttpMethod::Get, account_path(account, "/keys")?, None)
            .await
    }

    async fn fetch_sync_bundles(
        &self,
        account: &str,
        current_device_id: u32,
    ) -> CoreResult<AccountPreKeyBundlesResponse> {
        self.json::<(), _>(
            ChatHttpMethod::Get,
            account_path(account, &format!("/keys?syncDeviceId={current_device_id}"))?,
            None,
        )
        .await
    }

    async fn fetch_device_session(&self) -> CoreResult<String> {
        #[derive(serde::Deserialize)]
        struct DeviceSession {
            session: String,
        }
        let response = self
            .request(ChatHttpMethod::Get, "/device-session".into(), None)
            .await?;
        ensure_success(&response)?;
        decode::<DeviceSession>(&response.body_json).map(|body| body.session)
    }

    async fn fetch_manifest(&self, account: &str) -> CoreResult<Option<AccountManifestV3>> {
        let response = self
            .request(
                ChatHttpMethod::Get,
                account_path(account, "/manifest")?,
                None,
            )
            .await?;
        // Only the server's own "no manifest": another 404 must not read as
        // an account without a Chat identity, which this device would then
        // re-register.
        if response.status == 404
            && serde_json::from_str::<serde_json::Value>(&response.body_json)
                .is_ok_and(|body| body["code"] == "noManifest")
        {
            return Ok(None);
        }
        ensure_success(&response)?;
        decode(&response.body_json).map(Some)
    }

    async fn fetch_identity_pins(&self) -> CoreResult<Option<IdentityPinsRecord>> {
        let response = self
            .request(ChatHttpMethod::Get, "/user/identity-pins".into(), None)
            .await?;
        if response.status == 404 {
            return Ok(None);
        }
        ensure_success(&response)?;
        decode(&response.body_json).map(Some)
    }

    async fn store_identity_pins(&self, write: &IdentityPinsWrite) -> CoreResult<bool> {
        let response = self
            .request(
                ChatHttpMethod::Put,
                "/user/identity-pins".into(),
                // The server reads the revision from the envelope's header.
                // This transport writes no account head yet: the native
                // apps will (docs/roadmap.md), and a headed account refuses
                // the write (409), which pin sync takes as best effort.
                Some(encode(&serde_json::json!({
                    "baseRevision": write.base_revision,
                    "envelope": write.envelope,
                }))?),
            )
            .await?;
        if response.status == 409 {
            // An account that keeps a head refuses a list without one: this
            // client cannot write it yet (docs/roadmap.md). Not "another app
            // wrote first", which pin sync would read again and retry.
            let code = serde_json::from_str::<serde_json::Value>(&response.body_json)
                .ok()
                .and_then(|body| {
                    body.get("code")
                        .and_then(|code| code.as_str())
                        .map(str::to_owned)
                });
            if code.as_deref() == Some("head_required") {
                return Err(ChatError::Transport(
                    "this account's identity pins need the account head, which this client does not write yet".into(),
                ));
            }
            return Ok(false);
        }
        ensure_success(&response)?;
        Ok(true)
    }

    async fn publish_manifest(
        &self,
        manifest: &AccountManifestV3,
    ) -> CoreResult<AccountManifestPublicationV3> {
        self.json(
            ChatHttpMethod::Post,
            "/chat/manifest".into(),
            Some(manifest),
        )
        .await
    }

    async fn fetch_manifest_history(
        &self,
        account: &str,
        from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> CoreResult<AccountManifestHistoryPageV3> {
        self.json::<(), _>(
            ChatHttpMethod::Get,
            account_path(account, &format!("/manifest-history?fromSequence={from_sequence}&toSequence={to_sequence}&pageFromSequence={page_from_sequence}"))?,
            None,
        )
        .await
    }

    async fn prekey_count(&self, device_id: u32) -> CoreResult<PreKeyCountResponse> {
        self.json::<(), _>(
            ChatHttpMethod::Get,
            format!("/chat/keys/count?deviceId={device_id}"),
            None,
        )
        .await
    }

    async fn replenish_prekeys(
        &self,
        device_id: u32,
        request: &ReplenishKeysRequest,
    ) -> CoreResult<()> {
        let response = self
            .request(
                ChatHttpMethod::Put,
                format!("/chat/keys?deviceId={device_id}"),
                Some(encode(request)?),
            )
            .await?;
        ensure_success(&response)
    }

    async fn send(&self, account: &str, request: &SendMessagesRequest) -> CoreResult<SendOutcome> {
        let response = self
            .request(
                ChatHttpMethod::Post,
                account_path(account, "/messages")?,
                Some(encode(request)?),
            )
            .await?;
        if response.status == 409 {
            return decode::<DeviceListMismatch>(&response.body_json).map(SendOutcome::Mismatch);
        }
        ensure_success(&response)?;
        let delivered = if response.body_json.trim().is_empty() {
            DeliveredResponse {
                deduplicated: false,
            }
        } else {
            decode(&response.body_json)?
        };
        Ok(SendOutcome::Delivered {
            deduplicated: delivered.deduplicated,
        })
    }

    async fn send_sync(&self, request: &SendMessagesRequest) -> CoreResult<SendOutcome> {
        let response = self
            .request(
                ChatHttpMethod::Post,
                "/chat/sync/messages".into(),
                Some(encode(request)?),
            )
            .await?;
        if response.status == 409 {
            return decode::<DeviceListMismatch>(&response.body_json).map(SendOutcome::Mismatch);
        }
        ensure_success(&response)?;
        let delivered = if response.body_json.trim().is_empty() {
            DeliveredResponse {
                deduplicated: false,
            }
        } else {
            decode(&response.body_json)?
        };
        Ok(SendOutcome::Delivered {
            deduplicated: delivered.deduplicated,
        })
    }

    async fn drain(
        &self,
        device_id: u32,
        after: Option<u64>,
        limit: u32,
    ) -> CoreResult<MailboxPage> {
        let mut path = format!("/chat/messages?deviceId={device_id}&limit={limit}");
        if let Some(after) = after {
            path.push_str(&format!("&after={after}"));
        }
        self.json::<(), _>(ChatHttpMethod::Get, path, None).await
    }

    async fn ack(&self, device_id: u32, ids: &[String]) -> CoreResult<()> {
        #[derive(Serialize)]
        struct AckRequest<'a> {
            ids: &'a [String],
        }
        let response = self
            .request(
                ChatHttpMethod::Post,
                format!("/chat/messages/ack?deviceId={device_id}"),
                Some(encode(&AckRequest { ids })?),
            )
            .await?;
        ensure_success(&response)
    }
}

impl NativeTransport {
    async fn json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: ChatHttpMethod,
        path: String,
        body: Option<&B>,
    ) -> CoreResult<T> {
        let response = self
            .request(method, path, body.map(encode).transpose()?)
            .await?;
        ensure_success(&response)?;
        decode(&response.body_json)
    }

    async fn request(
        &self,
        method: ChatHttpMethod,
        path: String,
        body_json: Option<String>,
    ) -> CoreResult<ChatHttpResponse> {
        let chat_device = self
            .device
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let response = self
            .http
            .execute(ChatHttpRequest {
                method,
                path,
                body_json,
                chat_device,
            })
            .await
            .map_err(|error| ChatError::Transport(error.to_string()))?;
        if response.body_json.len() > MAX_RESPONSE_BYTES {
            return Err(ChatError::Transport(format!(
                "HTTP {} response exceeded {MAX_RESPONSE_BYTES} bytes",
                response.status
            )));
        }
        Ok(response)
    }
}

fn ensure_success(response: &ChatHttpResponse) -> CoreResult<()> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(ChatError::Transport(format!(
            "chat API returned HTTP {}",
            response.status
        )))
    }
}

fn encode<T: Serialize + ?Sized>(value: &T) -> CoreResult<String> {
    serde_json::to_string(value)
        .map_err(|error| ChatError::Transport(format!("encode request: {error}")))
}

fn decode<T: DeserializeOwned>(value: &str) -> CoreResult<T> {
    serde_json::from_str(value)
        .map_err(|error| ChatError::Transport(format!("decode response: {error}")))
}

/// `/chat/accounts/{accountId}{suffix}` with `server` as a query parameter:
/// Chat routes by account, never by address (docs/plans/account-ids.md).
fn account_path(account: &str, suffix: &str) -> CoreResult<String> {
    let account = kutup_chat_core::parse_account(account)?;
    let separator = if suffix.contains('?') { '&' } else { '?' };
    Ok(format!(
        "/chat/accounts/{}{suffix}{separator}server={}",
        urlencoding::encode(&account.account_id),
        urlencoding::encode(&account.server)
    ))
}
