//! Chat core's transport over reqwest: the native FFI's (`kutup-client-ffi`
//! `http.rs`) with the calls the web transport adds (sealed sending, its
//! policy and sender certificates, profiles), so the engine takes the same
//! paths as in a browser. Anonymous calls carry no bearer token, as the
//! web's don't.

use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use kutup_chat_core::{
    ChatError, ChatTransport, IdentityPinsRecord, IdentityPinsWrite, Result, SendOutcome,
};
use kutup_chat_proto::{
    AccountManifestHistoryPageV1, AccountManifestPublicationV1, AccountManifestV1,
    ChatProfileResponse, DeviceListMismatch, MailboxPage, OwnChatProfileResponse,
    PreKeyCountResponse, PutChatProfileRequest, RegisterChatDeviceRequest,
    RegisterChatDeviceResponse, ReplenishKeysRequest, SealedBatchResponseV1,
    SealedBatchSubmissionV1, SealedMessageSubmissionV1, SendMessagesRequest,
    SenderCertificateResponseV1, UserPreKeyBundlesResponse,
};
use kutup_federation_proto::FederatedFeaturePolicyHistoryV1;
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::Api;

pub struct Transport {
    pub api: Api,
    /// The user's access token, replaced on every refresh.
    pub token: Rc<RefCell<String>>,
}

struct Answer {
    status: StatusCode,
    body: String,
}

fn transport_error(error: impl std::fmt::Display) -> ChatError {
    ChatError::Transport(error.to_string())
}

fn ensure_success(answer: &Answer) -> Result<()> {
    if answer.status.is_success() {
        Ok(())
    } else {
        Err(ChatError::Transport(format!(
            "chat API returned HTTP {}",
            answer.status.as_u16()
        )))
    }
}

fn decode<T: DeserializeOwned>(body: &str) -> Result<T> {
    serde_json::from_str(body).map_err(|e| transport_error(format!("decode response: {e}")))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Delivered {
    #[serde(default)]
    deduplicated: bool,
}

fn delivered(answer: &Answer) -> Result<SendOutcome> {
    if answer.status == StatusCode::CONFLICT {
        return decode::<DeviceListMismatch>(&answer.body).map(SendOutcome::Mismatch);
    }
    ensure_success(answer)?;
    let deduplicated = if answer.body.trim().is_empty() {
        false
    } else {
        decode::<Delivered>(&answer.body)?.deduplicated
    };
    Ok(SendOutcome::Delivered { deduplicated })
}

/// `/chat{scope}/accounts/{accountId}{suffix}` with `server` as a parameter.
fn account_path(account: &str, suffix: &str, anonymous: bool) -> Result<String> {
    let account = kutup_chat_core::parse_account(account)?;
    let separator = if suffix.contains('?') { '&' } else { '?' };
    let scope = if anonymous {
        "/chat/anonymous"
    } else {
        "/chat"
    };
    Ok(format!(
        "{scope}/accounts/{}{suffix}{separator}server={}",
        urlencoding::encode(&account.account_id),
        urlencoding::encode(&account.server)
    ))
}

impl Transport {
    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.api
            .http
            .request(method, self.api.url(path))
            .bearer_auth(self.token.borrow().as_str())
    }

    fn anonymous(&self, path: &str) -> RequestBuilder {
        self.api.http.post(self.api.url(path))
    }

    async fn send_request(&self, builder: RequestBuilder) -> Result<Answer> {
        let response = builder.send().await.map_err(transport_error)?;
        let status = response.status();
        let body = response.text().await.map_err(transport_error)?;
        Ok(Answer { status, body })
    }

    async fn call<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Answer> {
        let mut builder = self.request(method, path);
        if let Some(body) = body {
            builder = builder.json(body);
        }
        self.send_request(builder).await
    }

    async fn json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let answer = self.call(method, path, body).await?;
        ensure_success(&answer)?;
        decode(&answer.body)
    }

    async fn optional<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let answer = self.call::<()>(Method::GET, path, None).await?;
        if answer.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&answer)?;
        decode(&answer.body).map(Some)
    }
}

#[allow(clippy::double_must_use)]
#[async_trait(?Send)]
impl ChatTransport for Transport {
    async fn register_device(&self, request: &RegisterChatDeviceRequest) -> Result<u32> {
        let response: RegisterChatDeviceResponse = self
            .json(Method::POST, "/chat/device", Some(request))
            .await?;
        Ok(response.device_id)
    }

    async fn fetch_bundles(&self, account: &str) -> Result<UserPreKeyBundlesResponse> {
        self.json::<(), _>(Method::GET, &account_path(account, "/keys", false)?, None)
            .await
    }

    async fn fetch_sync_bundles(
        &self,
        account: &str,
        current_device_id: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        let path = account_path(
            account,
            &format!("/keys?syncDeviceId={current_device_id}"),
            false,
        )?;
        self.json::<(), _>(Method::GET, &path, None).await
    }

    async fn fetch_manifest(&self, account: &str) -> Result<Option<AccountManifestV1>> {
        self.optional(&account_path(account, "/manifest", false)?)
            .await
    }

    async fn fetch_manifest_history(
        &self,
        account: &str,
        from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        let suffix = format!("/manifest-history?fromSequence={from_sequence}&toSequence={to_sequence}&pageFromSequence={page_from_sequence}");
        self.json::<(), _>(Method::GET, &account_path(account, &suffix, false)?, None)
            .await
    }

    async fn fetch_sealed_sender_policy(
        &self,
        domain: &str,
    ) -> Result<FederatedFeaturePolicyHistoryV1> {
        let path = format!(
            "/chat/sealed-sender/domains/{}/policy",
            urlencoding::encode(domain)
        );
        self.json::<(), _>(Method::GET, &path, None).await
    }

    async fn fetch_sender_certificate(
        &self,
        device_id: u32,
    ) -> Result<SenderCertificateResponseV1> {
        let path = format!("/chat/sealed-sender/certificate?deviceId={device_id}");
        self.json::<(), _>(Method::POST, &path, None).await
    }

    async fn fetch_sealed_bundles(
        &self,
        account: &str,
        capability: &[u8; 16],
    ) -> Result<UserPreKeyBundlesResponse> {
        use base64::Engine as _;
        let body = serde_json::json!({
            "capability": base64::engine::general_purpose::STANDARD.encode(capability),
        });
        let answer = self
            .send_request(
                self.anonymous(&account_path(account, "/keys", true)?)
                    .json(&body),
            )
            .await?;
        ensure_success(&answer)?;
        decode(&answer.body)
    }

    async fn send_sealed(
        &self,
        account: &str,
        request: &SealedMessageSubmissionV1,
    ) -> Result<SendOutcome> {
        let answer = self
            .send_request(
                self.anonymous(&account_path(account, "/messages", true)?)
                    .json(request),
            )
            .await?;
        // The server's uniform refusal: the recipient no longer takes this
        // capability (only its exact answer counts).
        if answer.status == StatusCode::NOT_FOUND {
            let refused = serde_json::from_str::<Value>(&answer.body)
                .ok()
                .and_then(|body| body.get("error").cloned())
                == Some(Value::from("sealed delivery unavailable"));
            if refused {
                return Ok(SendOutcome::Refused);
            }
        }
        delivered(&answer)
    }

    async fn send_sealed_batch(
        &self,
        server: &str,
        batch: &SealedBatchSubmissionV1,
    ) -> Result<SealedBatchResponseV1> {
        let path = format!(
            "/chat/anonymous/messages/batch?server={}",
            urlencoding::encode(server)
        );
        let answer = self.send_request(self.anonymous(&path).json(batch)).await?;
        ensure_success(&answer)?;
        decode(&answer.body)
    }

    async fn fetch_identity_pins(&self) -> Result<Option<IdentityPinsRecord>> {
        self.optional("/user/identity-pins").await
    }

    async fn store_identity_pins(&self, write: &IdentityPinsWrite) -> Result<bool> {
        // No account head: these accounts never start one, so the server
        // takes the list alone (a headed account would answer 409).
        let body = serde_json::json!({
            "baseRevision": write.base_revision,
            "envelope": write.envelope,
        });
        let answer = self
            .call(Method::PUT, "/user/identity-pins", Some(&body))
            .await?;
        if answer.status == StatusCode::CONFLICT {
            return Ok(false);
        }
        ensure_success(&answer)?;
        Ok(true)
    }

    async fn publish_manifest(
        &self,
        manifest: &AccountManifestV1,
    ) -> Result<AccountManifestPublicationV1> {
        self.json(Method::POST, "/chat/manifest", Some(manifest))
            .await
    }

    async fn fetch_own_profile(&self) -> Result<Option<OwnChatProfileResponse>> {
        self.optional("/chat/profile").await
    }

    async fn publish_profile(
        &self,
        profile: &PutChatProfileRequest,
    ) -> Result<OwnChatProfileResponse> {
        self.json(Method::PUT, "/chat/profile", Some(profile)).await
    }

    async fn fetch_profile(
        &self,
        account: &str,
        version: &str,
        access_key: &[u8],
    ) -> Result<Option<ChatProfileResponse>> {
        use base64::Engine as _;
        let suffix = format!("/profile/{}", urlencoding::encode(version));
        let answer = self
            .send_request(
                self.request(Method::GET, &account_path(account, &suffix, false)?)
                    .header(
                        "X-Kutup-Profile-Access-Key",
                        base64::engine::general_purpose::STANDARD.encode(access_key),
                    ),
            )
            .await?;
        if answer.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&answer)?;
        decode(&answer.body).map(Some)
    }

    async fn prekey_count(&self, device_id: u32) -> Result<PreKeyCountResponse> {
        let path = format!("/chat/keys/count?deviceId={device_id}");
        self.json::<(), _>(Method::GET, &path, None).await
    }

    async fn replenish_prekeys(
        &self,
        device_id: u32,
        request: &ReplenishKeysRequest,
    ) -> Result<()> {
        let path = format!("/chat/keys?deviceId={device_id}");
        let answer = self.call(Method::PUT, &path, Some(request)).await?;
        ensure_success(&answer)
    }

    async fn send(&self, account: &str, request: &SendMessagesRequest) -> Result<SendOutcome> {
        let answer = self
            .call(
                Method::POST,
                &account_path(account, "/messages", false)?,
                Some(request),
            )
            .await?;
        delivered(&answer)
    }

    async fn send_sync(&self, request: &SendMessagesRequest) -> Result<SendOutcome> {
        let answer = self
            .call(Method::POST, "/chat/sync/messages", Some(request))
            .await?;
        delivered(&answer)
    }

    async fn drain(&self, device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage> {
        let mut path = format!("/chat/messages?deviceId={device_id}&limit={limit}");
        if let Some(after) = after {
            path.push_str(&format!("&after={after}"));
        }
        self.json::<(), _>(Method::GET, &path, None).await
    }

    async fn ack(&self, device_id: u32, ids: &[String]) -> Result<()> {
        let path = format!("/chat/messages/ack?deviceId={device_id}");
        let answer = self
            .call(
                Method::POST,
                &path,
                Some(&serde_json::json!({ "ids": ids })),
            )
            .await?;
        ensure_success(&answer)
    }
}
