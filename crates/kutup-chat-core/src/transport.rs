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

use crate::error::Result;
use async_trait::async_trait;
use kutup_chat_proto::{
    AccountManifestHistoryPageV2, AccountManifestPublicationV2, AccountManifestV2,
    AccountPreKeyBundlesResponse, ChatProfileResponse, DeviceListMismatch, MailboxPage,
    OwnChatProfileResponse, PreKeyCountResponse, PutChatProfileRequest,
    RegisterChatDeviceRequestV2, ReplenishKeysRequest, SendMessagesRequest,
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
    /// Sealed delivery only: the server's uniform refusal ("sealed delivery
    /// unavailable"). The recipient no longer accepts this capability (they
    /// blocked the sender, so their profile key was replaced) or the account
    /// is gone. Nothing was stored.
    Refused,
}

/// The account's sealed identity pin list as the server stores it
/// (`GET/PUT /api/user/identity-pins`; docs/plans/drive-identity-pins.md).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsRecord {
    /// The revision in the sealed list's header, as the server read it.
    pub revision: u64,
    /// Canonical base64 of the sealed list (`kutup_crypto::identity_pins`).
    pub envelope: String,
}

/// A new sealed list for `PUT /api/user/identity-pins`: stored only if the
/// server still holds `base_revision` (0: none yet). The new revision is in
/// the envelope's header and must be above it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsWrite {
    pub base_revision: u64,
    pub envelope: String,
    /// The revision sealed in the envelope's header. Not sent to the server
    /// (it reads it from the header): a transport that writes the account
    /// head with the list (docs/plans/rollback-protection.md) names it there.
    pub revision: u64,
}

/// A group home's gateway key config and its identity history from the
/// pinned sequence on (`GET /api/chat/groups/gateway-key`), fetched through
/// this account's own server. Trusted only after the client follows the pin
/// through the history and verifies the config.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupGatewayAnswer {
    pub config: kutup_chat_proto::group_route::GroupGatewayKeyConfigV1,
    pub identity_history: Vec<kutup_federation_proto::FederationIdentityDocumentV1>,
}

/// One entry of the account's group list (`GET /api/chat/group-list`), as
/// the account head vouches for it: its opaque id, its revision (as the
/// server read it from the sealed header) and its sealed body
/// (docs/plans/pairwise-groups.md §5).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupListItem {
    pub id: String,
    pub revision: u64,
    pub envelope: String,
}

/// One entry of the account's Chat contact list (`GET /api/chat/contact-list`),
/// as the account head vouches for it (docs/plans/chat-contacts-sync.md).
pub type ContactListItem = GroupListItem;

/// How a contact list write went (`PUT /api/chat/contact-list/{id}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactListWrite {
    Stored,
    /// Another device wrote first: read the list again.
    Conflict,
    /// The list holds as many entries as it may (`contactListFull`): a new
    /// entry needs one evicted first.
    Full,
}

/// What this account's own server answered a relayed group request with
/// (`POST /api/chat/groups/relay/{homeServer}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupRelayOutcome {
    /// The home's oblivious answer, still sealed.
    Answered(Vec<u8>),
    /// The home couldn't open the request (a wrong or old key): fetch the
    /// config again.
    Unopenable,
    /// This account's relay limit.
    RateLimited,
    /// The home can't be reached.
    Unreachable,
    /// Groups are off on this account's server.
    GroupsOff,
}

/// The chat server, as the engine sees it. Implementations translate these to the
/// REST endpoints of `docs/chat-protocol.md` §4 and map non-2xx to
/// [`ChatError::Transport`](crate::ChatError::Transport) — except the 409 send
/// response, which they surface as [`SendOutcome::Mismatch`].
// `async_trait` marks each method's boxed future `#[must_use]` without a
// message, which clippy reads as a second `must_use` on a `Result`.
#[allow(clippy::double_must_use)]
#[async_trait(?Send)]
pub trait ChatTransport {
    /// `POST /api/chat/device` — returns the server-assigned device id.
    async fn register_device(&self, req: &RegisterChatDeviceRequestV2) -> Result<u32>;

    /// This device's id and credential, sent as `X-Kutup-Chat-Device` beside
    /// the session token on every device-bound call from now on (Signal's
    /// per-device password). Called once the device is registered or opened.
    fn set_device_auth(&self, _device_id: u32, _credential: &str) {}

    /// `POST /api/chat/link-tokens` (device-authenticated): one single-use
    /// token for linking one new device.
    async fn create_link_token(&self) -> Result<kutup_chat_proto::ChatLinkTokenResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement device linking".into(),
        ))
    }

    /// `PUT /api/chat/account-identity` (device-authenticated): the identity
    /// distribution. A `409` (devices that aren't the manifest's) or `410`
    /// (a message under a stale registration id) is [`DistributionOutcome::Mismatch`].
    async fn distribute_identity(
        &self,
        _request: &kutup_chat_proto::AccountIdentityDistributionRequest,
    ) -> Result<DistributionOutcome> {
        Err(crate::ChatError::Transport(
            "transport does not implement identity distribution".into(),
        ))
    }

    /// `PUT /api/chat/provisioning/{address}` (device-authenticated): relay
    /// one provisioning envelope to the new device's socket. `Ok(false)` is
    /// the server's `404`: no such socket of this account (closed, expired,
    /// or never this account's).
    async fn relay_provisioning(
        &self,
        _address: &str,
        _request: &kutup_chat_proto::ProvisioningRelayRequest,
    ) -> Result<bool> {
        Err(crate::ChatError::Transport(
            "transport does not implement device linking".into(),
        ))
    }

    /// Every method naming an account takes its string form,
    /// `aci:<uuid>@<server>` (docs/plans/account-ids.md): the transport routes
    /// by `server` and `accountId`, never by an address.
    ///
    /// `GET /api/chat/accounts/{accountId}/keys` — every active device's bundle
    /// (consumes one one-time prekey per device server-side).
    async fn fetch_bundles(&self, account: &str) -> Result<AccountPreKeyBundlesResponse>;

    /// Fetch the local account's complete signed bundle set for an encrypted
    /// linked-device sync. The server does not consume one-time prekeys for
    /// `current_device_id`, because the engine never encrypts to itself.
    async fn fetch_sync_bundles(
        &self,
        _account: &str,
        _current_device_id: u32,
    ) -> Result<AccountPreKeyBundlesResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement linked-device bundle fetches".into(),
        ))
    }

    /// Latest account-signed device manifest. `None` maps the endpoint's 404.
    async fn fetch_manifest(&self, _account: &str) -> Result<Option<AccountManifestV2>> {
        Err(crate::ChatError::Transport(
            "transport does not implement device manifests".into(),
        ))
    }

    /// Fetch one page of a complete signed manifest interval.
    async fn fetch_manifest_history(
        &self,
        _account: &str,
        _from_sequence: u64,
        _to_sequence: u64,
        _page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV2> {
        Err(crate::ChatError::Transport(
            "transport does not implement account manifest history".into(),
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
        _account: &str,
        _capability: &[u8; 16],
    ) -> Result<AccountPreKeyBundlesResponse> {
        Err(crate::ChatError::Transport(
            "transport does not implement anonymous prekey retrieval".into(),
        ))
    }

    async fn send_sealed(
        &self,
        _account: &str,
        _request: &kutup_chat_proto::SealedMessageSubmissionV1,
    ) -> Result<SendOutcome> {
        Err(crate::ChatError::Transport(
            "transport does not implement sealed delivery".into(),
        ))
    }

    /// `POST /api/chat/anonymous/messages/batch?server={server}`: sealed sends
    /// to several accounts of one server in one anonymous request, one result
    /// each, in order.
    async fn send_sealed_batch(
        &self,
        _server: &str,
        _batch: &kutup_chat_proto::SealedBatchSubmissionV1,
    ) -> Result<kutup_chat_proto::SealedBatchResponseV1> {
        Err(crate::ChatError::Transport(
            "transport does not implement sealed batches".into(),
        ))
    }

    /// The account's synced identity pins, shared with Drive and its other
    /// apps; `None` before the first list. A transport without them answers
    /// `None`, and Chat keeps to its own pins.
    async fn fetch_identity_pins(&self) -> Result<Option<IdentityPinsRecord>> {
        Ok(None)
    }

    /// Store `write` if the server still holds its base revision.
    /// `Ok(false)`: another app stored a list first.
    async fn store_identity_pins(&self, _write: &IdentityPinsWrite) -> Result<bool> {
        Err(crate::ChatError::Transport(
            "transport does not implement identity pins".into(),
        ))
    }

    /// Publish the caller's next account-signed manifest.
    async fn publish_manifest(
        &self,
        _manifest: &AccountManifestV2,
    ) -> Result<AccountManifestPublicationV2> {
        Err(crate::ChatError::Transport(
            "transport does not implement device manifests".into(),
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
        _account: &str,
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

    /// `POST /api/chat/accounts/{accountId}/messages` — multi-device send.
    async fn send(&self, account: &str, req: &SendMessagesRequest) -> Result<SendOutcome>;

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

    /// `GET /api/chat/groups/gateway-key?server={home}&fromSequence={from}`.
    async fn fetch_group_gateway(
        &self,
        _home: &str,
        _from_sequence: u64,
    ) -> Result<GroupGatewayAnswer> {
        Err(crate::error::ChatError::Transport(
            "this transport doesn't reach group homes".into(),
        ))
    }

    /// `POST /api/chat/groups/relay/{home}` with the sealed request.
    async fn relay_group_request(&self, _home: &str, _sealed: &[u8]) -> Result<GroupRelayOutcome> {
        Err(crate::error::ChatError::Transport(
            "this transport doesn't reach group homes".into(),
        ))
    }

    /// `GET /api/chat/contact-list`: every entry, each at the revision the
    /// verified account head lists (a list it doesn't vouch for is an error).
    async fn fetch_contact_list(&self) -> Result<Vec<ContactListItem>> {
        Err(crate::error::ChatError::Transport(
            "this transport keeps no contact list".into(),
        ))
    }

    /// `PUT /api/chat/contact-list/{id}` with the next account head, over
    /// `base_revision` (0: a new entry). `revision` is the one in the
    /// entry's sealed header.
    async fn store_contact_entry(
        &self,
        _id: &str,
        _base_revision: u64,
        _revision: u64,
        _envelope: &str,
    ) -> Result<ContactListWrite> {
        Err(crate::error::ChatError::Transport(
            "this transport keeps no contact list".into(),
        ))
    }

    /// `DELETE /api/chat/contact-list/{id}` at `revision` (an eviction):
    /// `false` when another device changed it first.
    async fn delete_contact_entry(&self, _id: &str, _revision: u64) -> Result<bool> {
        Err(crate::error::ChatError::Transport(
            "this transport keeps no contact list".into(),
        ))
    }

    /// `GET /api/chat/group-list`: every entry, each at the revision the
    /// verified account head lists (a list it doesn't vouch for is an error).
    async fn fetch_group_list(&self) -> Result<Vec<GroupListItem>> {
        Err(crate::error::ChatError::Transport(
            "this transport keeps no group list".into(),
        ))
    }

    /// `PUT /api/chat/group-list/{id}` with the next account head: `false`
    /// when the listed revision isn't `base_revision` (another device wrote
    /// first; read the list again). `revision` is the one in the entry's
    /// sealed header, where the server reads it; the account head lists it.
    async fn store_group_entry(
        &self,
        _id: &str,
        _base_revision: u64,
        _revision: u64,
        _envelope: &str,
    ) -> Result<bool> {
        Err(crate::error::ChatError::Transport(
            "this transport keeps no group list".into(),
        ))
    }
}
/// What the server answered an identity distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionOutcome {
    /// Stored: the new identity, keys and manifest are the account's.
    Accepted,
    /// `409`/`410`: the devices or their registration ids moved meanwhile.
    /// Nothing was stored; fetch the manifest and build it again.
    Mismatch(kutup_chat_proto::DeviceListMismatch),
}
