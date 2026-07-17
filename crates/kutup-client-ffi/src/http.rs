use std::sync::Arc;

use async_trait::async_trait;
use kutup_chat_core::{ChatError, ChatTransport, Result as CoreResult, SendOutcome};
use kutup_chat_proto::{
    DeviceListMismatch, DeviceManifest, MailboxPage, PreKeyCountResponse, PublishManifestResponse,
    RegisterChatDeviceRequest, RegisterChatDeviceResponse, ReplenishKeysRequest,
    SendMessagesRequest, UserPreKeyBundlesResponse,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::types::{ChatHttpMethod, ChatHttpRequest, ChatHttpResponse, Result};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// One authenticated HTTP seam implemented by URLSession or OkHttp. Rust keeps
/// endpoint construction and every protocol DTO on its side of the boundary.
#[uniffi::export(foreign)]
#[async_trait]
pub trait ChatHttpClient: Send + Sync {
    async fn execute(&self, request: ChatHttpRequest) -> Result<ChatHttpResponse>;
}

pub(crate) struct NativeTransport {
    pub http: Arc<dyn ChatHttpClient>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliveredResponse {
    #[serde(default)]
    deduplicated: bool,
}

#[async_trait(?Send)]
impl ChatTransport for NativeTransport {
    async fn register_device(&self, request: &RegisterChatDeviceRequest) -> CoreResult<u32> {
        let response: RegisterChatDeviceResponse = self
            .json(ChatHttpMethod::Post, "/chat/device".into(), Some(request))
            .await?;
        Ok(response.device_id)
    }

    async fn fetch_bundles(
        &self,
        username: &str,
        transparency_tree_size: u64,
    ) -> CoreResult<UserPreKeyBundlesResponse> {
        self.json::<(), _>(
            ChatHttpMethod::Get,
            format!(
                "/chat/users/{}/keys?transparencyTreeSize={transparency_tree_size}",
                urlencoding::encode(username)
            ),
            None,
        )
        .await
    }

    async fn fetch_sync_bundles(
        &self,
        username: &str,
        current_device_id: u32,
        transparency_tree_size: u64,
    ) -> CoreResult<UserPreKeyBundlesResponse> {
        self.json::<(), _>(
            ChatHttpMethod::Get,
            format!(
                "/chat/users/{}/keys?syncDeviceId={current_device_id}&transparencyTreeSize={transparency_tree_size}",
                urlencoding::encode(username)
            ),
            None,
        )
        .await
    }

    async fn fetch_manifest(&self, username: &str) -> CoreResult<Option<DeviceManifest>> {
        let response = self
            .request(
                ChatHttpMethod::Get,
                format!("/chat/users/{}/manifest", urlencoding::encode(username)),
                None,
            )
            .await?;
        if response.status == 404 {
            return Ok(None);
        }
        ensure_success(&response)?;
        decode(&response.body_json).map(Some)
    }

    async fn publish_manifest(
        &self,
        manifest: &DeviceManifest,
        transparency_tree_size: u64,
    ) -> CoreResult<PublishManifestResponse> {
        self.json(
            ChatHttpMethod::Post,
            format!("/chat/manifest?transparencyTreeSize={transparency_tree_size}"),
            Some(manifest),
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

    async fn send(&self, username: &str, request: &SendMessagesRequest) -> CoreResult<SendOutcome> {
        let response = self
            .request(
                ChatHttpMethod::Post,
                format!("/chat/users/{}/messages", urlencoding::encode(username)),
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
        let response = self
            .http
            .execute(ChatHttpRequest {
                method,
                path,
                body_json,
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
