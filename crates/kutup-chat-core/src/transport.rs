//! The transport port — the seam over the chat REST/WS API.
//!
//! Unlike [`ChatDb`](crate::ChatDb), transport is genuinely **async**: it does
//! network I/O, which pends. Each platform supplies its own implementation (the
//! desktop/CLI a reqwest client, the web client `fetch`, native the OS HTTP
//! stack); `kutup-chat-core` stays transport-agnostic and never links an HTTP
//! client. The engine (`engine.rs`) drives it, interleaving async transport calls
//! with the synchronous crypto/store ops.
//!
//! `#[async_trait(?Send)]` mirrors the engine's single-threaded, `Rc`-based
//! design (and the wasm world, where `fetch` futures are `!Send`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use kutup_chat_proto::{
    AccountManifestHistoryPageV1, AccountManifestPublicationV1, AccountManifestV1,
    AnonymousMlsKeyPackageRequestV1, ChatHistoryTransferAcceptanceV1,
    ChatHistoryTransferCompletionV1, ChatHistoryTransferFrameV1, ChatHistoryTransferRequestV1,
    ChatProfileResponse, DeviceListMismatch,
    IdentifiedMlsKeyPackageRequestV1, MailboxPage, MlsKeyPackageBundleV1, OwnChatProfileResponse,
    PreKeyCountResponse, PutChatProfileRequest, RegisterChatDeviceRequest, ReplenishKeysRequest,
    SendMessagesRequest, UserPreKeyBundlesResponse,
};
use kutup_federation_proto::FederatedFeaturePolicyHistoryV1;

/// The result of a `POST …/messages`. A `409 DeviceListMismatch` is modeled as a
/// value (not an error) because it is the expected, recoverable fan-out signal.
pub enum SendOutcome {
    /// Stored in every target device's mailbox. `deduplicated` is true when the
    /// server matched this `sendId` to an earlier delivery (an idempotent retry).
    Delivered { deduplicated: bool },
    /// The request's device set didn't match the recipient's active devices.
    Mismatch(DeviceListMismatch),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryTransferSummaryV1 {
    pub transfer_id: String,
    pub request: ChatHistoryTransferRequestV1,
    pub acceptance: Option<ChatHistoryTransferAcceptanceV1>,
    pub state: String,
    pub requesting_device_id: u32,
    pub responding_device_id: Option<u32>,
    pub frame_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryTransferListV1 {
    pub transfers: Vec<HistoryTransferSummaryV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryTransferFramePageV1 {
    pub transcript_hash: Option<String>,
    pub frames: Vec<ChatHistoryTransferFrameV1>,
}

/// The chat server, as the engine sees it. Implementations translate these to the
/// REST endpoints of `docs/chat-protocol.md` §4 and map non-2xx to
/// [`ChatError::Transport`](crate::ChatError::Transport) — except the 409 send
/// response, which they surface as [`SendOutcome::Mismatch`].
#[async_trait(?Send)]
pub trait ChatTransport {
    /// `POST /api/chat/device` — returns the server-assigned device id.
    async fn register_device(&self, req: &RegisterChatDeviceRequest) -> Result<u32>;

    /// `GET /api/chat/users/{username}/keys` — every active device's bundle
    /// (consumes one one-time prekey per device server-side).
    async fn fetch_bundles(&self, username: &str) -> Result<UserPreKeyBundlesResponse>;

    /// Fetch the local account's complete signed bundle set for an encrypted
    /// linked-device sync. The server does not consume one-time prekeys for
    /// `current_device_id`, because the engine never encrypts to itself.
    async fn fetch_sync_bundles(
        &self,
        _username: &str,
        _current_device_id: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement linked-device bundle fetches".into(),
        ))
    }

    /// Complete authenticated feature-policy history for an MLS ordering
    /// authority. Clients verify the federation identity and contiguous typed
    /// policy chain before accepting the authority's purpose-scoped key.
    async fn fetch_mls_ordering_policy(
        &self,
        _domain: &str,
    ) -> Result<FederatedFeaturePolicyHistoryV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement MLS ordering policy retrieval".into(),
        ))
    }

    /// Latest account-signed device manifest. `None` maps the endpoint's 404.
    async fn fetch_manifest(&self, _username: &str) -> Result<Option<AccountManifestV1>> {
        Err(crate::ChatError::Transport(
            "transport does not implement device manifests".into(),
        ))
    }

    /// Fetch one page of a complete signed manifest interval.
    async fn fetch_manifest_history(
        &self,
        _username: &str,
        _from_sequence: u64,
        _to_sequence: u64,
        _page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement account manifest history".into(),
        ))
    }

    /// Anonymous, capability-authenticated MLS KeyPackage retrieval. Browser
    /// implementations must omit bearer tokens, cookies, and session context.
    async fn fetch_anonymous_mls_key_packages(
        &self,
        _request: &AnonymousMlsKeyPackageRequestV1,
    ) -> Result<MlsKeyPackageBundleV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement anonymous MLS KeyPackage retrieval".into(),
        ))
    }

    async fn fetch_identified_mls_key_packages(
        &self,
        _request: &IdentifiedMlsKeyPackageRequestV1,
    ) -> Result<MlsKeyPackageBundleV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement identified MLS KeyPackage retrieval".into(),
        ))
    }

    async fn fetch_sealed_sender_policy(
        &self,
        _domain: &str,
    ) -> Result<FederatedFeaturePolicyHistoryV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement sealed sender policy retrieval".into(),
        ))
    }

    async fn fetch_sender_certificate(
        &self,
        _device_id: u32,
    ) -> Result<kutup_chat_proto::SenderCertificateResponseV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement sender certificate issuance".into(),
        ))
    }

    async fn fetch_sealed_bundles(
        &self,
        _username: &str,
        _capability: &[u8; 16],
    ) -> Result<UserPreKeyBundlesResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement anonymous prekey retrieval".into(),
        ))
    }

    async fn send_sealed(
        &self,
        _username: &str,
        _request: &kutup_chat_proto::SealedMessageSubmissionV1,
    ) -> Result<SendOutcome> {
        Err(crate::ChatError::Transport(
            "transport does not implement sealed delivery".into(),
        ))
    }

    /// Publish the caller's next account-signed manifest.
    async fn publish_manifest(
        &self,
        _manifest: &AccountManifestV1,
    ) -> Result<AccountManifestPublicationV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement device manifests".into(),
        ))
    }

    async fn create_history_transfer(&self, _request: &ChatHistoryTransferRequestV1) -> Result<()> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer creation".into(),
        ))
    }

    async fn list_history_transfers(&self, _device_id: u32) -> Result<HistoryTransferListV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer listing".into(),
        ))
    }

    async fn accept_history_transfer(
        &self,
        _transfer_id: &str,
        _device_id: u32,
        _acceptance: &ChatHistoryTransferAcceptanceV1,
    ) -> Result<()> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer acceptance".into(),
        ))
    }

    async fn upload_history_transfer_frame(
        &self,
        _transfer_id: &str,
        _device_id: u32,
        _frame: &ChatHistoryTransferFrameV1,
    ) -> Result<()> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer frame upload".into(),
        ))
    }

    async fn drain_history_transfer_frames(
        &self,
        _transfer_id: &str,
        _device_id: u32,
        _after: Option<u32>,
        _limit: u32,
    ) -> Result<HistoryTransferFramePageV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer frame drain".into(),
        ))
    }

    async fn complete_history_transfer(
        &self,
        _transfer_id: &str,
        _device_id: u32,
        _completion: &ChatHistoryTransferCompletionV1,
    ) -> Result<()> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer completion".into(),
        ))
    }

    async fn cancel_history_transfer(&self, _transfer_id: &str, _device_id: u32) -> Result<()> {
        Err(crate::ChatError::Transport(
            "transport does not implement history transfer cancellation".into(),
        ))
    }

    /// Owner-only read of the current opaque profile, including the wrapped
    /// random profile key used to initialize linked devices.
    async fn fetch_own_profile(&self) -> Result<Option<OwnChatProfileResponse>> {
        Err(crate::ChatError::Transport(
            "transport does not implement encrypted profiles".into(),
        ))
    }

    /// Publish one exact encrypted profile revision.
    async fn publish_profile(
        &self,
        _profile: &PutChatProfileRequest,
    ) -> Result<OwnChatProfileResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement encrypted profiles".into(),
        ))
    }

    /// Capability-gated local or federated peer profile read.
    async fn fetch_profile(
        &self,
        _username: &str,
        _version: &str,
        _access_key: &[u8],
    ) -> Result<Option<ChatProfileResponse>> {
        Err(crate::ChatError::Transport(
            "transport does not implement encrypted profiles".into(),
        ))
    }

    /// Remaining one-time EC/Kyber server pool sizes for the local device.
    async fn prekey_count(&self, _device_id: u32) -> Result<PreKeyCountResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement prekey counts".into(),
        ))
    }

    /// Idempotently publish locally persisted replacement prekeys.
    async fn replenish_prekeys(
        &self,
        _device_id: u32,
        _request: &ReplenishKeysRequest,
    ) -> Result<()> {
        Err(crate::ChatError::Transport(
            "transport does not implement prekey replenishment".into(),
        ))
    }

    /// `POST /api/chat/users/{username}/messages` — multi-device send.
    async fn send(&self, username: &str, req: &SendMessagesRequest) -> Result<SendOutcome>;

    /// `POST /api/chat/sync/messages` — encrypted transcript delivery to every
    /// other active device of the authenticated account.
    async fn send_sync(&self, _req: &SendMessagesRequest) -> Result<SendOutcome> {
        Err(crate::ChatError::Transport(
            "transport does not implement linked-device sends".into(),
        ))
    }

    /// `GET /api/chat/messages?deviceId&after&limit` — a drain page (oldest-first).
    async fn drain(&self, device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage>;

    /// `POST /api/chat/messages/ack` — delete processed envelopes.
    async fn ack(&self, device_id: u32, ids: &[String]) -> Result<()>;
}
