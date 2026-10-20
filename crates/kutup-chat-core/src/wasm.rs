//! Narrow wasm-bindgen facade over the platform-neutral engine.
//!
//! JavaScript owns authenticated HTTP (so the existing refresh-token and
//! selected-server behavior remains authoritative). Rust owns every protocol,
//! trust, persistence, and retry decision. The JS transport is deliberately a
//! DTO-only interface; no libsignal type crosses this boundary.

use std::rc::Rc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    AccountManifestHistoryPageV1, AccountManifestPublicationV1, AccountManifestV1,
    AnonymousMlsDeviceEnvelopeV1, ChatProfileResponse, CommitMlsControlBlockResponseV1,
    DeviceListMismatch, MailboxPage, MlsClientControlHistoryPageV1, MlsControlActionTypeV1,
    MlsConversationMemberV1, MlsGroupAuthorizationPolicyV1, MlsGroupCryptographicPolicyV1,
    MlsIncarnationRecoveryV1, MlsOrderingQuorumCertificateV1, MlsOrderingServicePolicyV1,
    MlsOwnerSetV1, OwnChatProfileResponse, PreKeyCountResponse, PutChatProfileRequest,
    RecoverMlsConversationResponseV1, RegisterChatDeviceRequest, RegisterChatDeviceResponse,
    ReplenishKeysRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

use crate::{
    AccountAuthority, AccountRef, AnonymousMlsRecipientDevice, ChatAttachmentDescriptorV1,
    ChatContent, ChatError, ChatTransport, ConversationId, Engine, InboundEnvelope,
    IndexedDbChatDb, MlsApplicationEnvelopeContext, MlsClient, MlsControlEnvelopeContext,
    ReceiveReport, Result, SendOutcome, VerifiedMlsCredential, VerifiedMlsKeyPackage,
};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_TYPES: &str = r#"
export interface KutupChatTransport {
  registerDevice(request: unknown): Promise<unknown>;
  fetchBundles(account: string): Promise<unknown>;
  fetchSyncBundles(account: string, currentDeviceId: number): Promise<unknown>;
  fetchMlsOrderingPolicy(domain: string): Promise<unknown>;
  fetchManifest(account: string): Promise<unknown | null>;
  fetchManifestHistory(account: string, fromSequence: string, toSequence: string, pageFromSequence: string): Promise<unknown>;
  fetchAnonymousMlsKeyPackages(request: unknown): Promise<unknown>;
  fetchIdentifiedMlsKeyPackages(request: unknown): Promise<unknown>;
  fetchSealedSenderPolicy(domain: string): Promise<unknown>;
  fetchSenderCertificate(deviceId: number): Promise<unknown>;
  fetchSealedBundles(account: string, capability: string): Promise<unknown>;
  publishManifest(manifest: unknown): Promise<unknown>;
  fetchIdentityPins(): Promise<{ revision: number; envelope: string } | null>;
  storeIdentityPins(write: { baseRevision: number; envelope: string; revision: number }): Promise<boolean>;
  fetchOwnProfile(): Promise<unknown | null>;
  publishProfile(profile: unknown): Promise<unknown>;
  fetchProfile(account: string, version: string, accessKey: string): Promise<unknown | null>;
  prekeyCount(deviceId: number): Promise<unknown>;
  replenishPrekeys(deviceId: number, request: unknown): Promise<void>;
  sendMessage(account: string, request: unknown): Promise<
    | { kind: "delivered"; deduplicated?: boolean }
    | { kind: "mismatch"; mismatch: unknown }
  >;
  sendSealedMessage(account: string, request: unknown): Promise<
    | { kind: "delivered"; deduplicated?: boolean }
    | { kind: "mismatch"; mismatch: unknown }
  >;
  sendSyncMessage(request: unknown): Promise<
    | { kind: "delivered"; deduplicated?: boolean }
    | { kind: "mismatch"; mismatch: unknown }
  >;
  drainMailbox(deviceId: number, after: string | null, limit: number): Promise<unknown>;
  ackMessages(deviceId: number, ids: string[]): Promise<void>;
}

export interface KutupChatContentView {
  version: number;
  kind: string;
  sentAt: string;
  seq: string;
  messageId: string;
  replyTo?: string;
  body: unknown;
  text?: string;
  attachment?: unknown;
  reaction?: unknown;
  mutation?: unknown;
  receipt?: unknown;
  typing?: unknown;
  disappearingTimer?: unknown;
  conversationState?: unknown;
  readPosition?: unknown;
  deleteForMe?: unknown;
  viewOnceOpened?: unknown;
  stickerSaved?: unknown;
  stickerRemoved?: unknown;
  sticker?: unknown;
  groupUpdate?: unknown;
  poll?: unknown;
  location?: unknown;
  liveLocation?: unknown;
  liveLocationStop?: unknown;
  pollVote?: unknown;
  pollTerminate?: unknown;
  mentions?: unknown;
  linkPreview?: unknown;
  forwarded?: boolean;
  viewOnce?: boolean;
  expiresAfterSeconds?: number;
  expiresAtMs?: number;
}

/** An account, for good (docs/plans/account-ids.md): never an address. */
export interface KutupChatAccount {
  server: string;
  accountId: string;
}

export type KutupChatConversationId =
  | { kind: "direct"; account: KutupChatAccount }
  | { kind: "group"; groupId: string };

export interface KutupChatHistoryEntry {
  id: string;
  conversation: KutupChatConversationId;
  /** Who wrote it: an account's string form, `aci:<uuid>@<server>` (this account's own when outgoing). Which chat: `conversation`. */
  sender: string;
  direction: "incoming" | "outgoing";
  senderDeviceId?: number;
  cursor?: string;
  timestampMs: number;
  delivered: boolean;
  deduplicated: boolean;
  /** A group message: how many member accounts it never reached. */
  failedRecipients?: number;
  /** A pairwise group message sent from here: how many member accounts this account's server hasn't taken it for yet. */
  waitingRecipients?: number;
  content: KutupChatContentView;
}

export type KutupChatContactState =
  | "pendingIncoming"
  | "pendingOutgoing"
  | "accepted"
  | "rejected"
  | "blocked";

export interface KutupChatContactRecord {
  peer: string;
  state: KutupChatContactState;
  previousState?: KutupChatContactState;
  revision: string;
  sourceDeviceId: number;
  updatedAtMs: number;
  syncPending: boolean;
}

export interface KutupChatProfile {
  displayName: string;
  avatar?: string;
  avatarContentType?: string;
  revision: string;
}

export interface KutupChatPeerProfile extends KutupChatProfile {
  peer: string;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "KutupChatTransport")]
    pub type JsChatTransport;

    #[wasm_bindgen(method, catch, js_name = registerDevice)]
    async fn js_register_device(
        this: &JsChatTransport,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchBundles)]
    async fn js_fetch_bundles(
        this: &JsChatTransport,
        account: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchSyncBundles)]
    async fn js_fetch_sync_bundles(
        this: &JsChatTransport,
        account: &str,
        current_device_id: u32,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchMlsOrderingPolicy)]
    async fn js_fetch_mls_ordering_policy(
        this: &JsChatTransport,
        domain: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchManifest)]
    async fn js_fetch_manifest(
        this: &JsChatTransport,
        account: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchManifestHistory)]
    async fn js_fetch_manifest_history(
        this: &JsChatTransport,
        account: &str,
        from_sequence: &str,
        to_sequence: &str,
        page_from_sequence: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchAnonymousMlsKeyPackages)]
    async fn js_fetch_anonymous_mls_key_packages(
        this: &JsChatTransport,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchIdentifiedMlsKeyPackages)]
    async fn js_fetch_identified_mls_key_packages(
        this: &JsChatTransport,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchSealedSenderPolicy)]
    async fn js_fetch_sealed_sender_policy(
        this: &JsChatTransport,
        domain: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchSenderCertificate)]
    async fn js_fetch_sender_certificate(
        this: &JsChatTransport,
        device_id: u32,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchSealedBundles)]
    async fn js_fetch_sealed_bundles(
        this: &JsChatTransport,
        account: &str,
        capability: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = publishManifest)]
    async fn js_publish_manifest(
        this: &JsChatTransport,
        manifest: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchOwnProfile)]
    async fn js_fetch_own_profile(this: &JsChatTransport) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchIdentityPins)]
    async fn js_fetch_identity_pins(
        this: &JsChatTransport,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = storeIdentityPins)]
    async fn js_store_identity_pins(
        this: &JsChatTransport,
        record: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = publishProfile)]
    async fn js_publish_profile(
        this: &JsChatTransport,
        profile: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchProfile)]
    async fn js_fetch_profile(
        this: &JsChatTransport,
        account: &str,
        version: &str,
        access_key: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = prekeyCount)]
    async fn js_prekey_count(
        this: &JsChatTransport,
        device_id: u32,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = replenishPrekeys)]
    async fn js_replenish_prekeys(
        this: &JsChatTransport,
        device_id: u32,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = sendMessage)]
    async fn js_send_message(
        this: &JsChatTransport,
        account: &str,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = sendSealedMessage)]
    async fn js_send_sealed_message(
        this: &JsChatTransport,
        account: &str,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    /// `POST /api/chat/anonymous/messages/batch?server=`: the
    /// `SealedBatchResponseV1`.
    #[wasm_bindgen(method, catch, js_name = sendSealedBatch)]
    async fn js_send_sealed_batch(
        this: &JsChatTransport,
        server: &str,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = sendSyncMessage)]
    async fn js_send_sync_message(
        this: &JsChatTransport,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = drainMailbox)]
    async fn js_drain_mailbox(
        this: &JsChatTransport,
        device_id: u32,
        after: JsValue,
        limit: u32,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = ackMessages)]
    async fn js_ack_messages(
        this: &JsChatTransport,
        device_id: u32,
        ids: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    /// `GET /api/chat/groups/gateway-key`: `{config, identityHistory}`.
    #[wasm_bindgen(method, catch, js_name = fetchGroupGateway)]
    async fn js_fetch_group_gateway(
        this: &JsChatTransport,
        home: &str,
        from_sequence: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    /// `POST /api/chat/groups/relay/{home}` with the sealed request:
    /// `{kind: "answered", body}` (base64) or `{kind: "unopenable" |
    /// "rateLimited" | "unreachable" | "groupsOff"}`.
    #[wasm_bindgen(method, catch, js_name = relayGroupRequest)]
    async fn js_relay_group_request(
        this: &JsChatTransport,
        home: &str,
        sealed: &[u8],
    ) -> std::result::Result<JsValue, JsValue>;

    /// The account's group list, as the verified account head lists it:
    /// `[{id, revision, envelope}]`.
    #[wasm_bindgen(method, catch, js_name = fetchGroupList)]
    async fn js_fetch_group_list(this: &JsChatTransport) -> std::result::Result<JsValue, JsValue>;

    /// One entry with the next account head (`{id, baseRevision, revision,
    /// envelope}`; `revision` is the sealed header's, for the account head
    /// only): `false` when another device wrote first.
    #[wasm_bindgen(method, catch, js_name = storeGroupEntry)]
    async fn js_store_group_entry(
        this: &JsChatTransport,
        write: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    /// The account's Chat contact list, as the verified account head lists
    /// it: `[{id, revision, envelope}]`.
    #[wasm_bindgen(method, catch, js_name = fetchContactList)]
    async fn js_fetch_contact_list(this: &JsChatTransport)
        -> std::result::Result<JsValue, JsValue>;

    /// One contact list entry with the next account head (`{id,
    /// baseRevision, revision, envelope}`): `"stored"`, `"conflict"` or
    /// `"full"`.
    #[wasm_bindgen(method, catch, js_name = storeContactEntry)]
    async fn js_store_contact_entry(
        this: &JsChatTransport,
        write: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    /// Removes one contact list entry (`{id, baseRevision}`): `false` when
    /// another device changed it first.
    #[wasm_bindgen(method, catch, js_name = deleteContactEntry)]
    async fn js_delete_contact_entry(
        this: &JsChatTransport,
        write: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContactEntryDelete<'a> {
    id: &'a str,
    base_revision: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupEntryWrite<'a> {
    id: &'a str,
    base_revision: u64,
    revision: u64,
    envelope: &'a str,
}

struct BrowserTransport {
    js: JsChatTransport,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum BrowserSendOutcome {
    Delivered {
        #[serde(default)]
        deduplicated: bool,
    },
    Mismatch {
        mismatch: DeviceListMismatch,
    },
    Refused,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum BrowserRelayOutcome {
    Answered { body: String },
    Unopenable,
    RateLimited,
    Unreachable,
    GroupsOff,
}

#[async_trait(?Send)]
impl ChatTransport for BrowserTransport {
    async fn fetch_group_gateway(
        &self,
        home: &str,
        from_sequence: u64,
    ) -> Result<crate::transport::GroupGatewayAnswer> {
        from_transport(
            self.js
                .js_fetch_group_gateway(home, &from_sequence.to_string())
                .await
                .map_err(transport_error)?,
        )
    }

    async fn relay_group_request(
        &self,
        home: &str,
        sealed: &[u8],
    ) -> Result<crate::transport::GroupRelayOutcome> {
        use crate::transport::GroupRelayOutcome as Outcome;
        let outcome: BrowserRelayOutcome = from_transport(
            self.js
                .js_relay_group_request(home, sealed)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserRelayOutcome::Answered { body } => Outcome::Answered(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| ChatError::Transport("relayed answer is not base64".into()))?,
            ),
            BrowserRelayOutcome::Unopenable => Outcome::Unopenable,
            BrowserRelayOutcome::RateLimited => Outcome::RateLimited,
            BrowserRelayOutcome::Unreachable => Outcome::Unreachable,
            BrowserRelayOutcome::GroupsOff => Outcome::GroupsOff,
        })
    }

    async fn fetch_group_list(&self) -> Result<Vec<crate::GroupListItem>> {
        from_transport(
            self.js
                .js_fetch_group_list()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn store_group_entry(
        &self,
        id: &str,
        base_revision: u64,
        revision: u64,
        envelope: &str,
    ) -> Result<bool> {
        let write = GroupEntryWrite {
            id,
            base_revision,
            revision,
            envelope,
        };
        from_transport(
            self.js
                .js_store_group_entry(to_transport(&write)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_contact_list(&self) -> Result<Vec<crate::transport::ContactListItem>> {
        from_transport(
            self.js
                .js_fetch_contact_list()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn store_contact_entry(
        &self,
        id: &str,
        base_revision: u64,
        revision: u64,
        envelope: &str,
    ) -> Result<crate::transport::ContactListWrite> {
        use crate::transport::ContactListWrite;
        let write = GroupEntryWrite {
            id,
            base_revision,
            revision,
            envelope,
        };
        let outcome: String = from_transport(
            self.js
                .js_store_contact_entry(to_transport(&write)?)
                .await
                .map_err(transport_error)?,
        )?;
        match outcome.as_str() {
            "stored" => Ok(ContactListWrite::Stored),
            "conflict" => Ok(ContactListWrite::Conflict),
            "full" => Ok(ContactListWrite::Full),
            other => Err(ChatError::Transport(format!(
                "unknown contact list answer {other}"
            ))),
        }
    }

    async fn delete_contact_entry(&self, id: &str, revision: u64) -> Result<bool> {
        let write = ContactEntryDelete {
            id,
            base_revision: revision,
        };
        from_transport(
            self.js
                .js_delete_contact_entry(to_transport(&write)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn register_device(&self, req: &RegisterChatDeviceRequest) -> Result<u32> {
        let response: RegisterChatDeviceResponse = from_transport(
            self.js
                .js_register_device(to_transport(req)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(response.device_id)
    }

    async fn fetch_bundles(&self, account: &str) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_bundles(account)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_sync_bundles(
        &self,
        account: &str,
        current_device_id: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sync_bundles(account, current_device_id)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_mls_ordering_policy(
        &self,
        domain: &str,
    ) -> Result<kutup_federation_proto::FederatedFeaturePolicyHistoryV1> {
        from_transport(
            self.js
                .js_fetch_mls_ordering_policy(domain)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_manifest(&self, account: &str) -> Result<Option<AccountManifestV1>> {
        from_transport(
            self.js
                .js_fetch_manifest(account)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_manifest_history(
        &self,
        account: &str,
        from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        from_transport(
            self.js
                .js_fetch_manifest_history(
                    account,
                    &from_sequence.to_string(),
                    &to_sequence.to_string(),
                    &page_from_sequence.to_string(),
                )
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_anonymous_mls_key_packages(
        &self,
        request: &kutup_chat_proto::AnonymousMlsKeyPackageRequestV1,
    ) -> Result<kutup_chat_proto::MlsKeyPackageBundleV1> {
        from_transport(
            self.js
                .js_fetch_anonymous_mls_key_packages(to_transport(request)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_identified_mls_key_packages(
        &self,
        request: &kutup_chat_proto::IdentifiedMlsKeyPackageRequestV1,
    ) -> Result<kutup_chat_proto::MlsKeyPackageBundleV1> {
        from_transport(
            self.js
                .js_fetch_identified_mls_key_packages(to_transport(request)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_sealed_sender_policy(
        &self,
        domain: &str,
    ) -> Result<kutup_federation_proto::FederatedFeaturePolicyHistoryV1> {
        from_transport(
            self.js
                .js_fetch_sealed_sender_policy(domain)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_sender_certificate(
        &self,
        device_id: u32,
    ) -> Result<kutup_chat_proto::SenderCertificateResponseV1> {
        from_transport(
            self.js
                .js_fetch_sender_certificate(device_id)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_sealed_bundles(
        &self,
        account: &str,
        capability: &[u8; 16],
    ) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sealed_bundles(account, &STANDARD.encode(capability))
                .await
                .map_err(transport_error)?,
        )
    }

    async fn publish_manifest(
        &self,
        manifest: &AccountManifestV1,
    ) -> Result<AccountManifestPublicationV1> {
        from_transport(
            self.js
                .js_publish_manifest(to_transport(manifest)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_identity_pins(&self) -> Result<Option<crate::IdentityPinsRecord>> {
        from_transport(
            self.js
                .js_fetch_identity_pins()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn store_identity_pins(&self, write: &crate::IdentityPinsWrite) -> Result<bool> {
        from_transport(
            self.js
                .js_store_identity_pins(to_transport(write)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_own_profile(&self) -> Result<Option<OwnChatProfileResponse>> {
        from_transport(
            self.js
                .js_fetch_own_profile()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn publish_profile(
        &self,
        profile: &PutChatProfileRequest,
    ) -> Result<OwnChatProfileResponse> {
        from_transport(
            self.js
                .js_publish_profile(to_transport(profile)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_profile(
        &self,
        account: &str,
        version: &str,
        access_key: &[u8],
    ) -> Result<Option<ChatProfileResponse>> {
        from_transport(
            self.js
                .js_fetch_profile(account, version, &STANDARD.encode(access_key))
                .await
                .map_err(transport_error)?,
        )
    }

    async fn prekey_count(&self, device_id: u32) -> Result<PreKeyCountResponse> {
        from_transport(
            self.js
                .js_prekey_count(device_id)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn replenish_prekeys(
        &self,
        device_id: u32,
        request: &ReplenishKeysRequest,
    ) -> Result<()> {
        self.js
            .js_replenish_prekeys(device_id, to_transport(request)?)
            .await
            .map_err(transport_error)?;
        Ok(())
    }

    async fn send(&self, account: &str, req: &SendMessagesRequest) -> Result<SendOutcome> {
        let outcome: BrowserSendOutcome = from_transport(
            self.js
                .js_send_message(account, to_transport(req)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserSendOutcome::Delivered { deduplicated } => {
                SendOutcome::Delivered { deduplicated }
            }
            BrowserSendOutcome::Mismatch { mismatch } => SendOutcome::Mismatch(mismatch),
            BrowserSendOutcome::Refused => {
                return Err(ChatError::Transport(
                    "identified delivery cannot be refused as sealed".into(),
                ))
            }
        })
    }

    async fn send_sealed(
        &self,
        account: &str,
        request: &kutup_chat_proto::SealedMessageSubmissionV1,
    ) -> Result<SendOutcome> {
        let outcome: BrowserSendOutcome = from_transport(
            self.js
                .js_send_sealed_message(account, to_transport(request)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserSendOutcome::Delivered { deduplicated } => {
                SendOutcome::Delivered { deduplicated }
            }
            BrowserSendOutcome::Mismatch { mismatch } => SendOutcome::Mismatch(mismatch),
            BrowserSendOutcome::Refused => SendOutcome::Refused,
        })
    }

    async fn send_sealed_batch(
        &self,
        server: &str,
        batch: &kutup_chat_proto::SealedBatchSubmissionV1,
    ) -> Result<kutup_chat_proto::SealedBatchResponseV1> {
        from_transport(
            self.js
                .js_send_sealed_batch(server, to_transport(batch)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn send_sync(&self, req: &SendMessagesRequest) -> Result<SendOutcome> {
        let outcome: BrowserSendOutcome = from_transport(
            self.js
                .js_send_sync_message(to_transport(req)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserSendOutcome::Delivered { deduplicated } => {
                SendOutcome::Delivered { deduplicated }
            }
            BrowserSendOutcome::Mismatch { mismatch } => SendOutcome::Mismatch(mismatch),
            BrowserSendOutcome::Refused => {
                return Err(ChatError::Transport(
                    "identified delivery cannot be refused as sealed".into(),
                ))
            }
        })
    }

    async fn drain(&self, device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage> {
        let after = after
            .map(|cursor| JsValue::from_str(&cursor.to_string()))
            .unwrap_or(JsValue::NULL);
        from_transport(
            self.js
                .js_drain_mailbox(device_id, after, limit)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn ack(&self, device_id: u32, ids: &[String]) -> Result<()> {
        self.js
            .js_ack_messages(device_id, to_transport(ids)?)
            .await
            .map_err(transport_error)?;
        Ok(())
    }
}

/// Browser-owned handle to one durable chat engine.
#[wasm_bindgen]
pub struct WasmChatClient {
    engine: Engine,
    authority: AccountAuthority,
    profile_wrapping_key: [u8; 32],
    /// Decoded search shards between queries (`search.rs`).
    search_cache: std::cell::RefCell<crate::search::ShardCache>,
}

impl Drop for WasmChatClient {
    fn drop(&mut self) {
        self.profile_wrapping_key.zeroize();
    }
}

impl WasmChatClient {
    fn mls_client(&self) -> MlsClient {
        MlsClient::new(Rc::clone(self.engine.session().db()))
    }

    /// History entries for timeline references (newest first, as given),
    /// built as the full history builds them; with `newest`, a group's
    /// messages still being sent are added at the top.
    /// History entries for search postings, in the postings' order; a
    /// posting whose record is gone is left out.
    async fn search_entries(
        &self,
        directory: &crate::timeline::Directory,
        postings: &[crate::search::Posting],
    ) -> Result<Vec<HistoryEntry>> {
        let mut starts: std::collections::HashMap<&str, crate::session::DisappearingExpiryStarts> =
            std::collections::HashMap::new();
        let mut entries = Vec::with_capacity(postings.len());
        for posting in postings {
            let key = posting.conversation.as_str();
            if !starts.contains_key(key) {
                starts.insert(key, self.expiry_starts(directory, key).await?);
            }
            entries.extend(self.load_entry(&posting.entry(), &starts[key]).await?);
        }
        Ok(entries)
    }

    /// Deadlines of incoming disappearing messages start when they were
    /// first seen, recorded by expiry starts indexed under the conversation.
    async fn expiry_starts(
        &self,
        directory: &crate::timeline::Directory,
        key: &str,
    ) -> Result<crate::session::DisappearingExpiryStarts> {
        use crate::timeline::{Source, EXPIRY_START};
        let db = self.engine.session().db().as_ref();
        let mut start_sent = Vec::new();
        for start in crate::timeline::flagged(db, directory, key, EXPIRY_START).await? {
            match start.source {
                Source::Sent => start_sent.extend(db.load_sent_message(&start.id).await?),
                Source::Inbox | Source::Mls => {}
            }
        }
        crate::session::collect_disappearing_expiry_starts(
            &start_sent,
            self.engine.session().user(),
        )
    }

    /// The history entry for one timeline reference, if its record is still
    /// there (an expiry start is none).
    async fn load_entry(
        &self,
        entry: &crate::timeline::EntryRef,
        starts: &crate::session::DisappearingExpiryStarts,
    ) -> Result<Option<HistoryEntry>> {
        use crate::timeline::{Source, EXPIRY_START};
        if entry.flags & EXPIRY_START != 0 {
            return Ok(None);
        }
        let db = self.engine.session().db().as_ref();
        let me = self.engine.session().user();
        let built = match entry.source {
            Source::Inbox => match db.load_message(&entry.id).await? {
                Some(message) => Some(HistoryEntry::incoming(message)?),
                None => None,
            },
            Source::Sent => match db.load_sent_message(&entry.id).await? {
                Some(message) => Some(HistoryEntry::outgoing(message, me)?),
                None => None,
            },
            Source::Mls => match db.load_mls_message(&entry.id).await? {
                Some(message) => Some(HistoryEntry::mls(message, me)?),
                None => None,
            },
        };
        Ok(built.map(|mut built| {
            built.apply_disappearing_deadline(starts);
            built
        }))
    }

    async fn timeline_entries(
        &self,
        directory: &crate::timeline::Directory,
        key: &str,
        refs: &[crate::timeline::EntryRef],
        newest: bool,
    ) -> Result<Vec<HistoryEntry>> {
        let starts = self.expiry_starts(directory, key).await?;
        let mut entries = Vec::with_capacity(refs.len());
        for entry in refs {
            entries.extend(self.load_entry(entry, &starts).await?);
        }
        if newest && key.starts_with("group:") {
            let delivered: std::collections::HashSet<String> =
                entries.iter().map(|entry| entry.id.clone()).collect();
            let me = self.engine.session().user().to_owned();
            let mut pending = Vec::new();
            for outgoing in self.mls_client().pending_application_messages().await? {
                let group = uuid::Uuid::from_bytes(outgoing.conversation_id).to_string();
                if format!("group:{group}") != key
                    || outgoing.content.is_empty()
                    || delivered.contains(&outgoing.send_id)
                    || is_invisible_control(&outgoing.content)?
                {
                    continue;
                }
                let mut entry = HistoryEntry::mls_pending(outgoing, &me)?;
                entry.apply_disappearing_deadline(&starts);
                pending.push(entry);
            }
            pending.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp_ms));
            pending.extend(entries);
            entries = pending;
        }
        Ok(entries)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationSummaryView {
    key: String,
    conversation: ConversationId,
    latest_ms: i64,
    unread: u32,
    /// Newest first.
    recent: Vec<HistoryEntry>,
    /// The newest disappearing-timer change, when it is older than `recent`.
    timer: Option<HistoryEntry>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SearchView {
    /// Newest first.
    entries: Vec<HistoryEntry>,
    /// What edits or deletes them, and what an edit hit acts on.
    related: Vec<HistoryEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupSendView {
    send_id: String,
    delivered: usize,
    pending: usize,
    /// Member accounts whose server refused it for good.
    failed: usize,
    /// Why this pass couldn't try it (it waits for the next).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn console_warn(message: &str);
}

impl From<crate::group_send::GroupSendSummary> for GroupSendView {
    fn from(summary: crate::group_send::GroupSendSummary) -> Self {
        Self {
            send_id: summary.send_id,
            delivered: summary.delivered,
            pending: summary.pending,
            failed: summary.failed,
            error: summary.error,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedGroupView {
    group_id: String,
    title_set: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum GroupSyncView {
    #[serde(rename_all = "camelCase")]
    Current {
        revision: u64,
        key_confirmed: bool,
    },
    Unreachable {
        reason: &'static str,
    },
    #[serde(rename_all = "camelCase")]
    MaybeRemoved {
        since_ms: i64,
    },
    Gone,
    /// More of the log still to read: not yet at the home's latest.
    Partial {
        revision: u64,
    },
}

impl From<crate::group_engine::GroupSync> for GroupSyncView {
    fn from(sync: crate::group_engine::GroupSync) -> Self {
        use crate::group_client::RouteFailure;
        use crate::group_engine::GroupSync;
        match sync {
            GroupSync::Current {
                revision,
                key_confirmed,
            } => Self::Current {
                revision,
                key_confirmed,
            },
            GroupSync::MaybeRemoved { since_ms } => Self::MaybeRemoved { since_ms },
            GroupSync::Unreachable(failure) => Self::Unreachable {
                reason: match failure {
                    RouteFailure::RateLimited => "rateLimited",
                    RouteFailure::Unreachable => "unreachable",
                    RouteFailure::GroupsOff => "groupsOff",
                },
            },
            GroupSync::Gone => Self::Gone,
            GroupSync::Partial { revision } => Self::Partial { revision },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupMemberWasmView {
    pseudonym: String,
    administrator: bool,
    joined_at_revision: u64,
    /// The account's string form when the binding verified; absent for an
    /// unverified member.
    account: Option<String>,
}

impl From<crate::group::GroupMemberView> for GroupMemberWasmView {
    fn from(member: crate::group::GroupMemberView) -> Self {
        Self {
            pseudonym: member.pseudonym,
            administrator: member.role == kutup_chat_proto::group::GroupRole::Administrator,
            joined_at_revision: member.joined_at_revision,
            account: member.verified.map(|verified| verified.account.to_string()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupSummaryView {
    group_id: String,
    title: Option<String>,
    /// `invited`, `requesting`, `member` or `gone`.
    status: &'static str,
    revision: Option<u64>,
    member_count: usize,
    /// Who invited this account, for an invitation (their account).
    inviter: Option<String>,
    /// A member's message named another history at a revision this device
    /// verified: the home may be showing members different states.
    fork_suspected: bool,
    /// When this device first learned of the group (ms).
    known_since_ms: Option<i64>,
    /// Who may rename it (`attributes`) and add members (`members`):
    /// `any`, `member`, `administrator` or `unsatisfiable`.
    access: Option<kutup_chat_proto::group::GroupAccessV1>,
}

impl From<crate::group_engine::GroupSummary> for GroupSummaryView {
    fn from(summary: crate::group_engine::GroupSummary) -> Self {
        use crate::group::GroupStatus;
        Self {
            group_id: summary.group_id,
            title: summary.title,
            status: match summary.status {
                GroupStatus::Invited { .. } => "invited",
                GroupStatus::Requesting => "requesting",
                GroupStatus::Member => "member",
                GroupStatus::Gone => "gone",
            },
            revision: summary.revision,
            member_count: summary.member_count,
            inviter: match &summary.status {
                GroupStatus::Invited { inviter, .. } => Some(inviter.clone()),
                _ => None,
            },
            fork_suspected: summary.fork_suspected,
            known_since_ms: summary.known_since_ms,
            access: summary.access,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationPageView {
    /// Newest first.
    entries: Vec<HistoryEntry>,
    /// Give back to continue with older entries; none at the start.
    before: Option<String>,
}

#[wasm_bindgen]
impl WasmChatClient {
    /// Open or restart-safely register the local device, then publish its
    /// account-signed manifest. The database name must be account scoped;
    /// `account` is this account's string form, `aci:<uuid>@<server>`;
    /// `display_name` is the name a first profile starts with (the
    /// username); `binding` is the account's key binding
    /// (`session.envelopeBinding`), which its own seals bind.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(
        database_name: String,
        account: String,
        display_name: String,
        sealed_sender_enabled: bool,
        master_key: Vec<u8>,
        binding: String,
        transport: JsChatTransport,
    ) -> std::result::Result<WasmChatClient, JsValue> {
        let master_key: [u8; 32] = master_key
            .try_into()
            .map_err(|_| js_error("chat account authority requires a 32-byte master key"))?;
        let authority = AccountAuthority::derive(&master_key).map_err(chat_error)?;
        let profile_wrapping_key =
            crate::profile::derive_wrapping_key(&master_key, &binding).map_err(chat_error)?;
        let db = Rc::new(
            IndexedDbChatDb::open(&database_name, &master_key)
                .await
                .map_err(chat_error)?,
        );
        let transport: Rc<dyn ChatTransport> = Rc::new(BrowserTransport { js: transport });
        let mut rng = OsRng.unwrap_err();
        // The device's account, for good: its string form.
        let account = crate::address::parse_account(&account)
            .map_err(chat_error)?
            .to_string();
        let mut engine = Engine::register(db, transport, account, 50, &mut rng)
            .await
            .map_err(chat_error)?;
        // One identity for every app of the account (docs/plans/drive-identity-pins.md).
        engine
            .enable_identity_pins(&master_key, &binding)
            .map_err(chat_error)?;
        engine
            .enable_group_list(&master_key, &binding)
            .map_err(chat_error)?;
        // The web writes a block at once (docs/plans/chat-contacts-sync.md).
        engine
            .enable_contact_list(
                &master_key,
                &binding,
                crate::contact_list::ContactListTiming {
                    block: crate::contact_list::BlockTiming::Immediate,
                },
            )
            .map_err(chat_error)?;
        engine.set_sealed_sender_enabled(sealed_sender_enabled);
        engine
            .sync_own_manifest(&authority, now_rfc3339())
            .await
            .map_err(chat_error)?;
        engine
            .initialize_profile(&profile_wrapping_key, &display_name, &mut rng)
            .await
            .map_err(chat_error)?;
        Ok(Self {
            engine,
            authority,
            profile_wrapping_key,
            search_cache: Default::default(),
        })
    }

    /// How many writes this browser's store has committed in this session:
    /// read before and after an operation, it tells whether anything changed.
    #[wasm_bindgen(js_name = storeCommits)]
    pub fn store_commits(&self) -> f64 {
        self.engine.session().db().commit_count() as f64
    }

    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> u32 {
        self.engine.session().device_id()
    }

    /// A new group on this account's server, this account its first
    /// administrator: its id.
    #[wasm_bindgen(js_name = createGroup)]
    /// `{groupId, titleSet}`: the group exists even when its title couldn't
    /// be set.
    pub async fn create_group(&mut self, title: String) -> std::result::Result<JsValue, JsValue> {
        let created = self.engine.create_group(&title).await.map_err(chat_error)?;
        to_output(&CreatedGroupView {
            group_id: created.group_id,
            title_set: created.title_set,
        })
    }

    #[wasm_bindgen(js_name = setGroupTitle)]
    pub async fn set_group_title(
        &mut self,
        group_id: String,
        title: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_title(&group_id, &title, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Removes a member, by their pseudonym (an administrator's right).
    #[wasm_bindgen(js_name = removeGroupMember)]
    pub async fn remove_group_member(
        &mut self,
        group_id: String,
        pseudonym: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .remove_group_member(&group_id, &pseudonym, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Makes a member an administrator, or a member again.
    #[wasm_bindgen(js_name = setGroupMemberAdmin)]
    pub async fn set_group_member_admin(
        &mut self,
        group_id: String,
        pseudonym: String,
        administrator: bool,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_member_admin(&group_id, &pseudonym, administrator, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Catches a group up with its home: `{kind: "current", revision,
    /// keyConfirmed}`, `{kind: "partial", revision}` (more of the log still
    /// to read), `{kind: "unreachable", reason}`, `{kind: "maybeRemoved",
    /// sinceMs}` or `{kind: "gone"}`.
    #[wasm_bindgen(js_name = syncGroup)]
    pub async fn sync_group(&mut self, group_id: String) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let outcome = self
            .engine
            .maintain_group(&group_id, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&GroupSyncView::from(outcome))
    }

    /// The group's members: their accounts when verified, never a key.
    #[wasm_bindgen(js_name = groupMembers)]
    pub async fn group_members(
        &mut self,
        group_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let members = self
            .engine
            .group_members(&group_id)
            .await
            .map_err(chat_error)?;
        to_output(
            &members
                .into_iter()
                .map(GroupMemberWasmView::from)
                .collect::<Vec<_>>(),
        )
    }

    /// Sends a text to a group: `{sendId, delivered, pending}` (member
    /// accounts reached, and still to reach, which `flushGroupOutbox` retries).
    #[wasm_bindgen(js_name = sendGroupText)]
    pub async fn send_group_text(
        &mut self,
        group_id: String,
        send_id: String,
        sent_at: String,
        text: String,
        reply_to: Option<String>,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content = ChatContent::text_with_id(&send_id, sent_at, seq, text)
            .with_reply_to(reply_to.as_deref())
            .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send_group_message(&group_id, &send_id, content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&GroupSendView::from(summary))
    }

    /// Delivers group messages still waiting (after a reconnect).
    #[wasm_bindgen(js_name = flushGroupOutbox)]
    pub async fn flush_group_outbox(&mut self) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let summaries = self
            .engine
            .flush_group_outbox(&mut rng)
            .await
            .map_err(chat_error)?;
        to_output(
            &summaries
                .into_iter()
                .map(GroupSendView::from)
                .collect::<Vec<_>>(),
        )
    }

    /// Invites accounts (their `aci:<uuid>@<server>` forms): how many
    /// invitations went out.
    #[wasm_bindgen(js_name = inviteToGroup)]
    pub async fn invite_to_group(
        &mut self,
        group_id: String,
        accounts: Vec<String>,
    ) -> std::result::Result<u32, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let sent = self
            .engine
            .invite_to_group(&group_id, &accounts, &mut rng)
            .await
            .map_err(chat_error)?;
        Ok(u32::try_from(sent).unwrap_or(u32::MAX))
    }

    /// Accepts an invitation; answers as `syncGroup` does.
    #[wasm_bindgen(js_name = acceptGroupInvite)]
    pub async fn accept_group_invite(
        &mut self,
        group_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let outcome = self
            .engine
            .accept_group_invite(&group_id, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&GroupSyncView::from(outcome))
    }

    #[wasm_bindgen(js_name = declineGroupInvite)]
    pub async fn decline_group_invite(
        &mut self,
        group_id: String,
    ) -> std::result::Result<(), JsValue> {
        self.engine
            .decline_group_invite(&group_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = leaveGroup)]
    pub async fn leave_group(&mut self, group_id: String) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .leave_group(&group_id, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Writes this device's due contact list entries now: before it signs
    /// out or unlinks itself (docs/plans/chat-contacts-sync.md).
    /// The account's lists, on a timer of their own: a device with nothing
    /// arriving still writes its due group and contact list entries, and
    /// follows what other devices changed (best effort).
    #[wasm_bindgen(js_name = syncAccountLists)]
    pub async fn sync_account_lists(&mut self) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        let _ = self.engine.sync_group_list_if_due(&mut rng).await;
        let _ = self.engine.sync_contact_list_if_due().await;
        Ok(())
    }

    #[wasm_bindgen(js_name = flushContactList)]
    pub async fn flush_contact_list(&mut self) -> std::result::Result<u32, JsValue> {
        let report = self
            .engine
            .flush_contact_list(true)
            .await
            .map_err(chat_error)?;
        // And the pin list's first meetings still waiting.
        let _ = self.engine.flush_identity_pins(true).await;
        Ok(u32::try_from(report.written).unwrap_or(u32::MAX))
    }

    /// Whether the account's contact list is full with nothing it may evict:
    /// a change (a block too) waits, and the person must be told.
    #[wasm_bindgen(js_name = contactListFull)]
    pub fn contact_list_full(&self) -> bool {
        self.engine.contact_list_full()
    }

    /// Writes this device's due group list entries now: before it signs out
    /// or unlinks itself, so a group just joined or left isn't missing from
    /// the account's list (docs/plans/pairwise-groups.md §5).
    #[wasm_bindgen(js_name = flushGroupList)]
    pub async fn flush_group_list(&mut self) -> std::result::Result<u32, JsValue> {
        let written = self
            .engine
            .flush_group_list(true)
            .await
            .map_err(chat_error)?;
        Ok(u32::try_from(written).unwrap_or(u32::MAX))
    }

    #[wasm_bindgen(js_name = listGroups)]
    pub async fn list_groups(&self) -> std::result::Result<JsValue, JsValue> {
        let groups = self.engine.list_groups().await.map_err(chat_error)?;
        to_output(
            &groups
                .into_iter()
                .map(GroupSummaryView::from)
                .collect::<Vec<_>>(),
        )
    }

    #[wasm_bindgen(js_name = syncManifest)]
    pub async fn sync_manifest(&mut self) -> std::result::Result<JsValue, JsValue> {
        let manifest = self
            .engine
            .sync_own_manifest(&self.authority, now_rfc3339())
            .await
            .map_err(chat_error)?;
        to_output(&manifest)
    }

    #[wasm_bindgen(js_name = revokeManifestDevice)]
    pub async fn revoke_manifest_device(
        &mut self,
        device_id: u32,
    ) -> std::result::Result<JsValue, JsValue> {
        let manifest = self
            .engine
            .revoke_manifest_device(&self.authority, device_id, now_rfc3339())
            .await
            .map_err(chat_error)?;
        to_output(&manifest)
    }

    #[wasm_bindgen(js_name = generateMlsKeyPackage)]
    pub async fn generate_mls_key_package(
        &self,
        manifest_version: String,
        now_seconds: String,
        expires_at_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let package = self
            .mls_client()
            .generate_key_package(
                parse_u64_string("manifest version", &manifest_version)?,
                self.device_id(),
                parse_i64_string("KeyPackage clock", &now_seconds)?,
                parse_i64_string("KeyPackage expiry", &expires_at_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&package)
    }

    #[wasm_bindgen(js_name = prepareMlsGroupGenesis)]
    pub async fn prepare_mls_group_genesis(
        &self,
        conversation_id: String,
        mls_group_id: Vec<u8>,
        creator: JsValue,
        authority_policies: JsValue,
        created_at_seconds: String,
        group_info: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("invalid MLS conversation id"))?;
        let creator: AccountRef = from_transport(creator).map_err(chat_error)?;
        let authority_policies: Vec<kutup_chat_proto::MlsOrderingServicePolicyV1> =
            from_transport(authority_policies).map_err(chat_error)?;
        let group_info: Option<kutup_chat_proto::MlsGroupInfoV1> =
            if group_info.is_null() || group_info.is_undefined() {
                None
            } else {
                Some(from_transport(group_info).map_err(chat_error)?)
            };
        let prepared = self
            .mls_client()
            .prepare_group_genesis_with_info(
                conversation_id,
                &mls_group_id,
                creator,
                &authority_policies,
                parse_i64_string("MLS genesis clock", &created_at_seconds)?,
                group_info,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    /// Stage a change of the group's name, description or picture; it is
    /// then published like a membership change.
    #[wasm_bindgen(js_name = prepareMlsGroupInfoChange)]
    pub async fn prepare_mls_group_info_change(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        group_info: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id =
            uuid::Uuid::parse_str(&proposal_id).map_err(|_| js_error("invalid MLS proposal id"))?;
        let group_info: kutup_chat_proto::MlsGroupInfoV1 =
            from_transport(group_info).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_group_info_change(
                &mls_group_id,
                proposal_id,
                group_info,
                parse_i64_string("MLS control clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = localMlsConversations)]
    pub async fn local_mls_conversations(&self) -> std::result::Result<JsValue, JsValue> {
        let records = self
            .mls_client()
            .local_conversations()
            .await
            .map_err(chat_error)?;
        to_output(&records)
    }

    #[wasm_bindgen(js_name = markMlsGroupGenesisPublished)]
    pub async fn mark_mls_group_genesis_published(
        &self,
        conversation_id: String,
        genesis_hash: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("invalid MLS conversation id"))?;
        let record = self
            .mls_client()
            .mark_group_genesis_published(conversation_id, &genesis_hash)
            .await
            .map_err(chat_error)?;
        to_output(&record)
    }

    #[wasm_bindgen(js_name = mlsGroupOwnerCredential)]
    pub async fn mls_group_owner_credential(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let credential = self
            .mls_client()
            .group_owner_credential(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&credential)
    }

    #[wasm_bindgen(js_name = mlsGroupState)]
    pub async fn mls_group_state(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let state = self
            .mls_client()
            .group_state(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&state)
    }

    #[wasm_bindgen(js_name = mlsGroupDevices)]
    pub async fn mls_group_devices(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let devices = self
            .mls_client()
            .group_devices(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&devices)
    }

    #[wasm_bindgen(js_name = prepareMlsMembershipChange)]
    pub async fn prepare_mls_membership_change(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        next_roster: JsValue,
        additions: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let next_roster: Vec<MlsConversationMemberV1> =
            from_transport(next_roster).map_err(chat_error)?;
        let additions: Vec<VerifiedMlsKeyPackage> =
            from_transport(additions).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_membership_change(
                &mls_group_id,
                proposal_id,
                &next_roster,
                &additions,
                parse_i64_string("MLS clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = prepareMlsDeviceSync)]
    pub async fn prepare_mls_device_sync(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        additions: JsValue,
        removed_device_ids: JsValue,
        now_seconds: String,
        account: Option<String>,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let additions: Vec<VerifiedMlsKeyPackage> =
            from_transport(additions).map_err(chat_error)?;
        let removed_device_ids: Vec<u32> =
            from_transport(removed_device_ids).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_device_sync(
                &mls_group_id,
                proposal_id,
                account.as_deref(),
                &additions,
                &removed_device_ids,
                parse_i64_string("MLS clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = pendingMlsMembershipChanges)]
    pub async fn pending_mls_membership_changes(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_membership_changes()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = buildMlsMembershipCommitRequest)]
    pub async fn build_mls_membership_commit_request(
        &self,
        mls_group_id: Vec<u8>,
        quorum_certificate: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let certificate: MlsOrderingQuorumCertificateV1 =
            from_transport(quorum_certificate).map_err(chat_error)?;
        let request = self
            .mls_client()
            .build_membership_commit_request(&mls_group_id, certificate)
            .await
            .map_err(chat_error)?;
        to_output(&request)
    }

    #[wasm_bindgen(js_name = finalizeMlsMembershipChange)]
    pub async fn finalize_mls_membership_change(
        &self,
        mls_group_id: Vec<u8>,
        acknowledgement: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let acknowledgement: CommitMlsControlBlockResponseV1 =
            from_transport(acknowledgement).map_err(chat_error)?;
        let finalized = self
            .mls_client()
            .finalize_membership_change(&mls_group_id, &acknowledgement)
            .await
            .map_err(chat_error)?;
        to_output(&finalized)
    }

    #[wasm_bindgen(js_name = prepareMlsAuthorityChange)]
    pub async fn prepare_mls_authority_change(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        authority_policies: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let policies: Vec<MlsOrderingServicePolicyV1> =
            from_transport(authority_policies).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_authority_change_from_policies(
                &mls_group_id,
                proposal_id,
                &policies,
                parse_i64_string("MLS clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = pendingMlsAuthorityChanges)]
    pub async fn pending_mls_authority_changes(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_authority_changes()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = recordMlsAuthorityPreviousQuorum)]
    pub async fn record_mls_authority_previous_quorum(
        &self,
        mls_group_id: Vec<u8>,
        certificate: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let certificate: MlsOrderingQuorumCertificateV1 =
            from_transport(certificate).map_err(chat_error)?;
        let request = self
            .mls_client()
            .record_authority_previous_quorum(&mls_group_id, certificate)
            .await
            .map_err(chat_error)?;
        to_output(&request)
    }

    #[wasm_bindgen(js_name = buildMlsAuthorityCommitRequest)]
    pub async fn build_mls_authority_commit_request(
        &self,
        mls_group_id: Vec<u8>,
        new_set_certificate: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let certificate: MlsOrderingQuorumCertificateV1 =
            from_transport(new_set_certificate).map_err(chat_error)?;
        let request = self
            .mls_client()
            .build_authority_commit_request(&mls_group_id, certificate)
            .await
            .map_err(chat_error)?;
        to_output(&request)
    }

    #[wasm_bindgen(js_name = finalizeMlsAuthorityChange)]
    pub async fn finalize_mls_authority_change(
        &self,
        mls_group_id: Vec<u8>,
        acknowledgement: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let acknowledgement: CommitMlsControlBlockResponseV1 =
            from_transport(acknowledgement).map_err(chat_error)?;
        let finalized = self
            .mls_client()
            .finalize_authority_change(&mls_group_id, &acknowledgement)
            .await
            .map_err(chat_error)?;
        to_output(&finalized)
    }

    #[wasm_bindgen(js_name = prepareMlsOwnerChange)]
    pub async fn prepare_mls_owner_change(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        next_roster: JsValue,
        next_owner_set: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let next_roster: Vec<MlsConversationMemberV1> =
            from_transport(next_roster).map_err(chat_error)?;
        let next_owner_set: MlsOwnerSetV1 = from_transport(next_owner_set).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_owner_change(
                &mls_group_id,
                proposal_id,
                &next_roster,
                next_owner_set,
                parse_i64_string("MLS clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = ensureMlsOwnerCandidate)]
    pub async fn ensure_mls_owner_candidate(
        &self,
        mls_group_id: Vec<u8>,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let candidate = self
            .mls_client()
            .ensure_owner_candidate(
                &mls_group_id,
                parse_i64_string("MLS owner-candidate clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&candidate)
    }

    #[wasm_bindgen(js_name = mlsOwnerCandidates)]
    pub async fn mls_owner_candidates(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let candidates = self
            .mls_client()
            .owner_candidates(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&candidates)
    }

    #[wasm_bindgen(js_name = createMlsOwnerCandidateMessage)]
    pub async fn create_mls_owner_candidate_message(
        &self,
        mls_group_id: Vec<u8>,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let entry = self
            .mls_client()
            .create_owner_candidate_message(
                &mls_group_id,
                parse_i64_string("MLS owner-candidate clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[wasm_bindgen(js_name = pendingMlsOwnerChanges)]
    pub async fn pending_mls_owner_changes(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_owner_changes()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = mlsOwnerChangeHasQuorum)]
    pub async fn mls_owner_change_has_quorum(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<bool, JsValue> {
        self.mls_client()
            .owner_change_has_quorum(&mls_group_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = createMlsOwnerApprovalRequestMessage)]
    pub async fn create_mls_owner_approval_request_message(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let entry = self
            .mls_client()
            .create_owner_approval_request_message(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    /// Ask to leave the group; `null` when this device already left.
    #[wasm_bindgen(js_name = requestMlsLeave)]
    pub async fn request_mls_leave(
        &self,
        mls_group_id: Vec<u8>,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let entry = self
            .mls_client()
            .request_leave(
                &mls_group_id,
                parse_i64_string("MLS leave clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[wasm_bindgen(js_name = createMlsInvitationAcceptanceMessage)]
    pub async fn create_mls_invitation_acceptance_message(
        &self,
        mls_group_id: Vec<u8>,
        invited_epoch: String,
        accepted_at_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let entry = self
            .mls_client()
            .create_invitation_acceptance_message(
                &mls_group_id,
                parse_u64_string("MLS invited epoch", &invited_epoch)?,
                parse_i64_string("MLS acceptance clock", &accepted_at_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[wasm_bindgen(js_name = pendingMlsOwnerApprovalRequests)]
    pub async fn pending_mls_owner_approval_requests(
        &self,
    ) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_owner_approval_requests()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = approveMlsOwnerApprovalRequest)]
    pub async fn approve_mls_owner_approval_request(
        &self,
        mls_group_id: Vec<u8>,
        approved_at_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let entry = self
            .mls_client()
            .approve_owner_approval_request(
                &mls_group_id,
                parse_i64_string("MLS owner-approval clock", &approved_at_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[wasm_bindgen(js_name = rejectMlsOwnerApprovalRequest)]
    pub async fn reject_mls_owner_approval_request(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<(), JsValue> {
        self.mls_client()
            .reject_owner_approval_request(&mls_group_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = buildMlsOwnerCommitRequest)]
    pub async fn build_mls_owner_commit_request(
        &self,
        mls_group_id: Vec<u8>,
        quorum_certificate: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let certificate: MlsOrderingQuorumCertificateV1 =
            from_transport(quorum_certificate).map_err(chat_error)?;
        let request = self
            .mls_client()
            .build_owner_commit_request(&mls_group_id, certificate)
            .await
            .map_err(chat_error)?;
        to_output(&request)
    }

    #[wasm_bindgen(js_name = finalizeMlsOwnerChange)]
    pub async fn finalize_mls_owner_change(
        &self,
        mls_group_id: Vec<u8>,
        acknowledgement: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let acknowledgement: CommitMlsControlBlockResponseV1 =
            from_transport(acknowledgement).map_err(chat_error)?;
        let finalized = self
            .mls_client()
            .finalize_owner_change(&mls_group_id, &acknowledgement)
            .await
            .map_err(chat_error)?;
        to_output(&finalized)
    }

    #[wasm_bindgen(js_name = prepareMlsClose)]
    pub async fn prepare_mls_close(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let prepared = self
            .mls_client()
            .prepare_close_conversation(
                &mls_group_id,
                proposal_id,
                parse_i64_string("MLS close clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = pendingMlsCloses)]
    pub async fn pending_mls_closes(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_closes()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = mlsCloseHasOwnerQuorum)]
    pub async fn mls_close_has_owner_quorum(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<bool, JsValue> {
        self.mls_client()
            .close_has_owner_quorum(&mls_group_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = buildMlsCloseCommitRequest)]
    pub async fn build_mls_close_commit_request(
        &self,
        mls_group_id: Vec<u8>,
        quorum_certificate: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let certificate: MlsOrderingQuorumCertificateV1 =
            from_transport(quorum_certificate).map_err(chat_error)?;
        let request = self
            .mls_client()
            .build_close_commit_request(&mls_group_id, certificate)
            .await
            .map_err(chat_error)?;
        to_output(&request)
    }

    #[wasm_bindgen(js_name = finalizeMlsClose)]
    pub async fn finalize_mls_close(
        &self,
        mls_group_id: Vec<u8>,
        acknowledgement: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let acknowledgement: CommitMlsControlBlockResponseV1 =
            from_transport(acknowledgement).map_err(chat_error)?;
        let finalized = self
            .mls_client()
            .finalize_close(&mls_group_id, &acknowledgement)
            .await
            .map_err(chat_error)?;
        to_output(&finalized)
    }

    #[wasm_bindgen(js_name = prepareMlsAuthorizationPolicyChange)]
    pub async fn prepare_mls_authorization_policy_change(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        next_policy: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let next_policy: MlsGroupAuthorizationPolicyV1 =
            from_transport(next_policy).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_authorization_policy_change(
                &mls_group_id,
                proposal_id,
                next_policy,
                parse_i64_string("MLS policy clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = prepareMlsCryptographicPolicyChange)]
    pub async fn prepare_mls_cryptographic_policy_change(
        &self,
        mls_group_id: Vec<u8>,
        proposal_id: String,
        next_policy: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let next_policy: MlsGroupCryptographicPolicyV1 =
            from_transport(next_policy).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_cryptographic_policy_change(
                &mls_group_id,
                proposal_id,
                next_policy,
                parse_i64_string("MLS policy clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = pendingMlsPolicyChanges)]
    pub async fn pending_mls_policy_changes(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_policy_changes()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = mlsPolicyChangeHasOwnerQuorum)]
    pub async fn mls_policy_change_has_owner_quorum(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<bool, JsValue> {
        self.mls_client()
            .policy_change_has_owner_quorum(&mls_group_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = buildMlsPolicyCommitRequest)]
    pub async fn build_mls_policy_commit_request(
        &self,
        mls_group_id: Vec<u8>,
        quorum_certificate: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let certificate: MlsOrderingQuorumCertificateV1 =
            from_transport(quorum_certificate).map_err(chat_error)?;
        let request = self
            .mls_client()
            .build_policy_commit_request(&mls_group_id, certificate)
            .await
            .map_err(chat_error)?;
        to_output(&request)
    }

    #[wasm_bindgen(js_name = finalizeMlsPolicyChange)]
    pub async fn finalize_mls_policy_change(
        &self,
        mls_group_id: Vec<u8>,
        acknowledgement: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let acknowledgement: CommitMlsControlBlockResponseV1 =
            from_transport(acknowledgement).map_err(chat_error)?;
        let finalized = self
            .mls_client()
            .finalize_policy_change(&mls_group_id, &acknowledgement)
            .await
            .map_err(chat_error)?;
        to_output(&finalized)
    }

    #[wasm_bindgen(js_name = prepareMlsGroupRecovery)]
    pub async fn prepare_mls_group_recovery(
        &self,
        mls_group_id: Vec<u8>,
        new_mls_group_id: Vec<u8>,
        proposal_id: String,
        authority_policies: JsValue,
        additions: JsValue,
        created_at_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS recovery proposal id must be a UUID"))?;
        let policies: Vec<MlsOrderingServicePolicyV1> =
            from_transport(authority_policies).map_err(chat_error)?;
        let additions: Vec<VerifiedMlsKeyPackage> =
            from_transport(additions).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_group_recovery(
                &mls_group_id,
                &new_mls_group_id,
                proposal_id,
                &policies,
                &additions,
                parse_i64_string("MLS recovery clock", &created_at_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&prepared)
    }

    #[wasm_bindgen(js_name = pendingMlsRecoveries)]
    pub async fn pending_mls_recoveries(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_recoveries()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = localMlsIncarnationHistory)]
    pub async fn local_mls_incarnation_history(&self) -> std::result::Result<JsValue, JsValue> {
        let history = self
            .mls_client()
            .local_incarnation_history()
            .await
            .map_err(chat_error)?;
        to_output(&history)
    }

    #[wasm_bindgen(js_name = mlsRecoveryHasOwnerQuorum)]
    pub async fn mls_recovery_has_owner_quorum(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<bool, JsValue> {
        self.mls_client()
            .recovery_has_owner_quorum(&mls_group_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = finalizeMlsGroupRecovery)]
    pub async fn finalize_mls_group_recovery(
        &self,
        mls_group_id: Vec<u8>,
        acknowledgement: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let acknowledgement: RecoverMlsConversationResponseV1 =
            from_transport(acknowledgement).map_err(chat_error)?;
        let finalized = self
            .mls_client()
            .finalize_group_recovery(&mls_group_id, &acknowledgement)
            .await
            .map_err(chat_error)?;
        to_output(&finalized)
    }

    #[wasm_bindgen(js_name = pendingMlsCommit)]
    pub async fn pending_mls_commit(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_commit(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = mergePendingMlsCommit)]
    pub async fn merge_pending_mls_commit(
        &self,
        mls_group_id: Vec<u8>,
        commit_hash: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let state = self
            .mls_client()
            .merge_pending_commit(&mls_group_id, &commit_hash)
            .await
            .map_err(chat_error)?;
        to_output(&state)
    }

    #[wasm_bindgen(js_name = rejectPendingMlsCommit)]
    pub async fn reject_pending_mls_commit(
        &self,
        mls_group_id: Vec<u8>,
        commit_hash: String,
    ) -> std::result::Result<(), JsValue> {
        self.mls_client()
            .reject_pending_commit(&mls_group_id, &commit_hash)
            .await
            .map_err(chat_error)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = joinMlsFromWelcomeWithControlHistory)]
    pub async fn join_mls_from_welcome_with_control_history(
        &self,
        envelope_id: String,
        cursor: String,
        send_id: String,
        mls_group_id: Vec<u8>,
        welcome: Vec<u8>,
        expected_members: JsValue,
        history_pages: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let envelope_id = uuid::Uuid::parse_str(&envelope_id)
            .map_err(|_| js_error("MLS mailbox envelope id must be a UUID"))?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("MLS mailbox send id must be a UUID"))?;
        let envelope = MlsControlEnvelopeContext {
            envelope_id,
            cursor,
            send_id,
        };
        let expected: Vec<VerifiedMlsCredential> =
            from_transport(expected_members).map_err(chat_error)?;
        let history_pages: Vec<Vec<u8>> = from_transport(history_pages).map_err(chat_error)?;
        let joined = self
            .mls_client()
            .join_from_welcome_with_control_history(
                &envelope,
                &mls_group_id,
                &welcome,
                &expected,
                &history_pages,
            )
            .await
            .map_err(chat_error)?;
        to_output(&joined)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = joinMlsFromRecoveryWelcome)]
    pub async fn join_mls_from_recovery_welcome(
        &self,
        envelope_id: String,
        cursor: String,
        send_id: String,
        mls_group_id: Vec<u8>,
        welcome: Vec<u8>,
        expected_members: JsValue,
        recovery: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let envelope_id = uuid::Uuid::parse_str(&envelope_id)
            .map_err(|_| js_error("MLS mailbox envelope id must be a UUID"))?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("MLS mailbox send id must be a UUID"))?;
        let envelope = MlsControlEnvelopeContext {
            envelope_id,
            cursor,
            send_id,
        };
        let expected: Vec<VerifiedMlsCredential> =
            from_transport(expected_members).map_err(chat_error)?;
        let recovery: MlsIncarnationRecoveryV1 = from_transport(recovery).map_err(chat_error)?;
        let joined = self
            .mls_client()
            .join_from_recovery_welcome(&envelope, &mls_group_id, &welcome, &expected, &recovery)
            .await
            .map_err(chat_error)?;
        to_output(&joined)
    }

    #[wasm_bindgen(js_name = inspectMlsWelcome)]
    pub async fn inspect_mls_welcome(
        &self,
        mls_group_id: Vec<u8>,
        welcome: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let inspection = self
            .mls_client()
            .inspect_welcome(&mls_group_id, &welcome)
            .await
            .map_err(chat_error)?;
        to_output(&inspection)
    }

    #[wasm_bindgen(js_name = resolveMlsWelcomeClaims)]
    pub async fn resolve_mls_welcome_claims(
        &mut self,
        claimed_members: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let claims: Vec<crate::ClaimedMlsCredential> =
            from_transport(claimed_members).map_err(chat_error)?;
        let verified = self
            .engine
            .resolve_mls_credential_claims(&claims)
            .await
            .map_err(chat_error)?;
        to_output(&verified)
    }

    #[wasm_bindgen(js_name = resolveMlsSenderClaim)]
    pub async fn resolve_mls_sender_claim(
        &mut self,
        claimed_sender: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let claim: crate::ClaimedMlsCredential =
            from_transport(claimed_sender).map_err(chat_error)?;
        let verified = self
            .engine
            .resolve_mls_sender_credential(&claim)
            .await
            .map_err(chat_error)?;
        to_output(&verified)
    }

    #[wasm_bindgen(js_name = fetchVerifiedMlsOrderingPolicy)]
    pub async fn fetch_verified_mls_ordering_policy(
        &self,
        domain: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let policy = self
            .engine
            .fetch_verified_mls_ordering_policy(&domain)
            .await
            .map_err(chat_error)?;
        to_output(&policy)
    }

    #[wasm_bindgen(js_name = fetchVerifiedMlsOrderingPolicyDetails)]
    pub async fn fetch_verified_mls_ordering_policy_details(
        &self,
        domain: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let history = self
            .engine
            .fetch_verified_mls_ordering_policy_details(&domain)
            .await
            .map_err(chat_error)?;
        to_output(&history)
    }

    #[wasm_bindgen(js_name = fetchVerifiedMlsKeyPackages)]
    pub async fn fetch_verified_mls_key_packages(
        &mut self,
        recipient: JsValue,
        capability: Vec<u8>,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let capability: [u8; 16] = capability.try_into().map_err(|_| {
            chat_error(ChatError::Invalid(
                "MLS delivery capability must contain exactly 16 bytes".into(),
            ))
        })?;
        let verified = self
            .engine
            .fetch_verified_anonymous_mls_key_packages(
                &recipient,
                &capability,
                parse_i64_string("MLS clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&verified)
    }

    #[wasm_bindgen(js_name = fetchVerifiedIdentifiedMlsKeyPackages)]
    pub async fn fetch_verified_identified_mls_key_packages(
        &mut self,
        recipient: JsValue,
        conversation_id: String,
        incarnation: String,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let verified = self
            .engine
            .fetch_verified_identified_mls_key_packages(
                &recipient,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                parse_i64_string("MLS clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&verified)
    }

    #[wasm_bindgen(js_name = verifiedManifestMlsDeviceIds)]
    pub async fn verified_manifest_mls_device_ids(
        &mut self,
        account: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let device_ids = self
            .engine
            .verified_manifest_mls_device_ids(&account)
            .await
            .map_err(chat_error)?;
        to_output(&device_ids)
    }

    #[wasm_bindgen(js_name = processedMlsControlEnvelope)]
    pub async fn processed_mls_control_envelope(
        &self,
        envelope_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let envelope_id = uuid::Uuid::parse_str(&envelope_id)
            .map_err(|_| js_error("MLS mailbox envelope id must be a UUID"))?;
        let receipt = self
            .mls_client()
            .processed_control_envelope(envelope_id)
            .await
            .map_err(chat_error)?;
        to_output(&receipt)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = applyOrderedInboundMlsMembershipCommit)]
    pub async fn apply_ordered_inbound_mls_membership_commit(
        &self,
        envelope_id: String,
        cursor: String,
        send_id: String,
        mls_group_id: Vec<u8>,
        commit: Vec<u8>,
        expected_members: JsValue,
        control_history_page: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let envelope_id = uuid::Uuid::parse_str(&envelope_id)
            .map_err(|_| js_error("MLS mailbox envelope id must be a UUID"))?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("MLS mailbox send id must be a UUID"))?;
        let envelope = MlsControlEnvelopeContext {
            envelope_id,
            cursor,
            send_id,
        };
        let expected: Vec<VerifiedMlsCredential> =
            from_transport(expected_members).map_err(chat_error)?;
        let page = MlsClientControlHistoryPageV1::from_canonical_bytes(&control_history_page)
            .map_err(|error| chat_error(ChatError::Protocol(error)))?;
        if page.commits.len() != 1 {
            return Err(js_error(
                "ordered inbound MLS Commit requires exactly one control-history entry",
            ));
        }
        let applied = self
            .mls_client()
            .apply_ordered_inbound_membership_commit(
                &envelope,
                &mls_group_id,
                &commit,
                &expected,
                &page.commits[0],
            )
            .await
            .map_err(chat_error)?;
        to_output(&applied)
    }

    #[wasm_bindgen(js_name = inspectInboundMlsCommit)]
    pub async fn inspect_inbound_mls_commit(
        &self,
        mls_group_id: Vec<u8>,
        commit: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let inspection = self
            .mls_client()
            .inspect_inbound_commit(&mls_group_id, &commit)
            .await
            .map_err(chat_error)?;
        to_output(&inspection)
    }

    #[wasm_bindgen(js_name = mlsGroupControlCredential)]
    pub async fn mls_group_control_credential(
        &self,
        mls_group_id: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let credential = self
            .mls_client()
            .group_control_credential(&mls_group_id)
            .await
            .map_err(chat_error)?;
        to_output(&credential)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = signMlsControlProposal)]
    pub async fn sign_mls_control_proposal(
        &self,
        mls_group_id: Vec<u8>,
        conversation_id: String,
        incarnation: String,
        proposal_id: String,
        base_epoch: String,
        action_type: u16,
        encrypted_payload: Vec<u8>,
        created_at_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let proposal_id = uuid::Uuid::parse_str(&proposal_id)
            .map_err(|_| js_error("MLS proposal id must be a UUID"))?;
        let action_type =
            MlsControlActionTypeV1::try_from(action_type).map_err(|error| js_error(&error))?;
        let proposal = self
            .mls_client()
            .sign_control_proposal(
                &mls_group_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                proposal_id,
                parse_u64_string("MLS base epoch", &base_epoch)?,
                action_type,
                &encrypted_payload,
                parse_i64_string("MLS proposal clock", &created_at_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&proposal)
    }

    #[wasm_bindgen(js_name = createMlsApplicationMessage)]
    pub async fn create_mls_application_message(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        plaintext: Vec<u8>,
        created_at_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let entry = self
            .mls_client()
            .create_application_message(
                &send_id,
                *conversation_id.as_bytes(),
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &plaintext,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsTextMessage)]
    pub async fn create_mls_text_message(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        text: String,
        created_at_ms: String,
        reply_to: Option<String>,
        expires_after_seconds: Option<u32>,
        extras: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let extras = parse_extras(extras)?;
        let entry = self
            .mls_client()
            .create_expiring_text_reply_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                &text,
                reply_to.as_deref(),
                expires_after_seconds,
                &extras,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsAttachmentMessage)]
    pub async fn create_mls_attachment_message(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        descriptor: JsValue,
        created_at_ms: String,
        expires_after_seconds: Option<u32>,
        extras: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let extras = parse_extras(extras)?;
        let descriptor: ChatAttachmentDescriptorV1 =
            from_transport(descriptor).map_err(chat_error)?;
        let entry = self
            .mls_client()
            .create_expiring_attachment_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                descriptor,
                expires_after_seconds,
                &extras,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    /// A poll, a vote in one, or its end, in a group.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsPollContent)]
    pub async fn create_mls_poll_content(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        kind: String,
        body: JsValue,
        created_at_ms: String,
        expires_after_seconds: Option<u32>,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let body: serde_json::Value = from_transport(body).map_err(chat_error)?;
        let entry = self
            .mls_client()
            .create_structured_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                parse_i64_string("MLS message clock", &created_at_ms)?,
                |seq| {
                    build_poll_content(&kind, &send_id, &sent_at, seq, &body, expires_after_seconds)
                },
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    /// The frame key of a group call in the group's current epoch.
    #[wasm_bindgen(js_name = exportMlsCallKey)]
    pub async fn export_mls_call_key(
        &self,
        mls_group_id: Vec<u8>,
        call_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let call_id = uuid::Uuid::parse_str(&call_id)
            .map_err(|_| js_error("group call id must be a UUID"))?;
        let (epoch, key) = self
            .mls_client()
            .export_call_key(&mls_group_id, call_id)
            .await
            .map_err(chat_error)?;
        #[derive(Serialize)]
        struct CallKey {
            epoch: String,
            key: Vec<u8>,
        }
        to_output(&CallKey {
            epoch: epoch.to_string(),
            key,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsReactionMessage)]
    pub async fn create_mls_reaction_message(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        target_message_id: String,
        emoji: String,
        active: bool,
        created_at_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let entry = self
            .mls_client()
            .create_reaction_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                &target_message_id,
                &emoji,
                active,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsMessageMutation)]
    pub async fn create_mls_message_mutation(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        target_message_id: String,
        operation: String,
        replacement_text: Option<String>,
        created_at_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let operation = parse_message_mutation_operation(&operation)?;
        let entry = self
            .mls_client()
            .create_message_mutation_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                &target_message_id,
                operation,
                replacement_text,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsReceiptMessage)]
    pub async fn create_mls_receipt_message(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        message_ids: Vec<String>,
        state: String,
        created_at_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let entry = self
            .mls_client()
            .create_receipt_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                message_ids,
                parse_receipt_state(&state)?,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsTypingMessage)]
    pub async fn create_mls_typing_message(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        active: bool,
        created_at_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let entry = self
            .mls_client()
            .create_typing_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                active,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = createMlsDisappearingTimer)]
    pub async fn create_mls_disappearing_timer(
        &self,
        send_id: String,
        conversation_id: String,
        incarnation: String,
        mls_group_id: Vec<u8>,
        sent_at: String,
        created_at_ms: String,
        duration_seconds: Option<u32>,
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let entry = self
            .mls_client()
            .create_disappearing_timer_application_message(
                &send_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &mls_group_id,
                &sent_at,
                duration_seconds,
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[wasm_bindgen(js_name = pendingMlsApplicationMessages)]
    pub async fn pending_mls_application_messages(&self) -> std::result::Result<JsValue, JsValue> {
        let pending = self
            .mls_client()
            .pending_application_messages()
            .await
            .map_err(chat_error)?;
        to_output(&pending)
    }

    #[wasm_bindgen(js_name = stageMlsApplicationDelivery)]
    pub async fn stage_mls_application_delivery(
        &self,
        send_id: String,
        recipient: JsValue,
        capability: Vec<u8>,
        packages: JsValue,
        now_seconds: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let capability: [u8; 16] = capability
            .try_into()
            .map_err(|_| js_error("MLS delivery capability must be 16 bytes"))?;
        let packages: Vec<VerifiedMlsKeyPackage> = from_transport(packages).map_err(chat_error)?;
        let staged = self
            .mls_client()
            .stage_application_delivery(
                &send_id,
                &recipient,
                capability,
                &packages,
                parse_i64_string("MLS delivery clock", &now_seconds)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&staged)
    }

    #[wasm_bindgen(js_name = noteMlsApplicationDeliveryAttempt)]
    pub async fn note_mls_application_delivery_attempt(
        &self,
        send_id: String,
        recipient: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let submission = self
            .mls_client()
            .note_application_delivery_attempt(&send_id, &recipient)
            .await
            .map_err(chat_error)?;
        to_output(&submission)
    }

    #[wasm_bindgen(js_name = markMlsApplicationRecipientDelivered)]
    pub async fn mark_mls_application_recipient_delivered(
        &self,
        send_id: String,
        recipient: String,
        deduplicated: bool,
    ) -> std::result::Result<JsValue, JsValue> {
        let history = self
            .mls_client()
            .mark_application_recipient_delivered(&send_id, &recipient, deduplicated)
            .await
            .map_err(chat_error)?;
        to_output(&history)
    }

    #[wasm_bindgen(js_name = inspectAnonymousMlsApplicationEnvelope)]
    pub async fn inspect_anonymous_mls_application_envelope(
        &self,
        recipient: JsValue,
        send_id: String,
        envelope: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("MLS application send id must be a UUID"))?;
        let envelope: AnonymousMlsDeviceEnvelopeV1 =
            from_transport(envelope).map_err(chat_error)?;
        let inspection = self
            .mls_client()
            .inspect_anonymous_application_envelope(&recipient, send_id, &envelope)
            .await
            .map_err(chat_error)?;
        to_output(&inspection)
    }

    #[wasm_bindgen(js_name = processedMlsApplicationEnvelope)]
    pub async fn processed_mls_application_envelope(
        &self,
        envelope_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let envelope_id = uuid::Uuid::parse_str(&envelope_id)
            .map_err(|_| js_error("MLS mailbox envelope id must be a UUID"))?;
        let receipt = self
            .mls_client()
            .processed_application_envelope(envelope_id)
            .await
            .map_err(chat_error)?;
        to_output(&receipt)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = applyAnonymousMlsApplicationEnvelope)]
    pub async fn apply_anonymous_mls_application_envelope(
        &self,
        envelope_id: String,
        cursor: String,
        send_id: String,
        server_timestamp: String,
        recipient: JsValue,
        envelope: JsValue,
        expected_sender: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let context = MlsApplicationEnvelopeContext {
            envelope_id: uuid::Uuid::parse_str(&envelope_id)
                .map_err(|_| js_error("MLS mailbox envelope id must be a UUID"))?,
            cursor,
            send_id: uuid::Uuid::parse_str(&send_id)
                .map_err(|_| js_error("MLS mailbox send id must be a UUID"))?,
            server_timestamp: parse_i64_string("MLS server timestamp", &server_timestamp)?,
        };
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let envelope: AnonymousMlsDeviceEnvelopeV1 =
            from_transport(envelope).map_err(chat_error)?;
        let expected_sender: VerifiedMlsCredential =
            from_transport(expected_sender).map_err(chat_error)?;
        let applied = self
            .mls_client()
            .apply_anonymous_application_envelope(&context, &recipient, &envelope, &expected_sender)
            .await
            .map_err(chat_error)?;
        to_output(&applied)
    }

    #[wasm_bindgen(js_name = markMlsApplicationDelivered)]
    pub async fn mark_mls_application_delivered(
        &self,
        send_id: String,
    ) -> std::result::Result<(), JsValue> {
        self.mls_client()
            .mark_application_delivered(&send_id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = noteMlsApplicationAttempt)]
    pub async fn note_mls_application_attempt(
        &self,
        send_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let entry = self
            .mls_client()
            .note_application_attempt(&send_id)
            .await
            .map_err(chat_error)?;
        to_output(&entry)
    }

    #[wasm_bindgen(js_name = decryptMlsApplicationMessage)]
    pub async fn decrypt_mls_application_message(
        &self,
        mls_group_id: Vec<u8>,
        ciphertext: Vec<u8>,
        expected_sender: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let expected: VerifiedMlsCredential =
            from_transport(expected_sender).map_err(chat_error)?;
        let message = self
            .mls_client()
            .decrypt_application_message(&mls_group_id, &ciphertext, &expected)
            .await
            .map_err(chat_error)?;
        to_output(&message)
    }

    #[wasm_bindgen(js_name = deriveMlsDeliveryCapability)]
    pub async fn derive_mls_delivery_capability(
        &self,
        mls_group_id: Vec<u8>,
        conversation_id: String,
        incarnation: String,
        recipient: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
        let capability = self
            .mls_client()
            .derive_delivery_capability(
                &mls_group_id,
                conversation_id,
                parse_u64_string("MLS incarnation", &incarnation)?,
                &recipient,
            )
            .await
            .map_err(chat_error)?;
        to_output(&capability)
    }

    #[wasm_bindgen(js_name = createAnonymousMlsSubmission)]
    pub async fn create_anonymous_mls_submission(
        &self,
        recipient: JsValue,
        send_id: String,
        capability: Vec<u8>,
        devices: JsValue,
        mls_ciphertext: Vec<u8>,
    ) -> std::result::Result<JsValue, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("anonymous MLS send id must be a UUID"))?;
        let capability: [u8; 16] = capability
            .try_into()
            .map_err(|_| js_error("anonymous MLS capability must be 16 bytes"))?;
        let devices: Vec<AnonymousMlsRecipientDevice> =
            from_transport(devices).map_err(chat_error)?;
        let submission = self
            .mls_client()
            .create_anonymous_submission(recipient, send_id, capability, &devices, &mls_ciphertext)
            .await
            .map_err(chat_error)?;
        to_output(&submission)
    }

    #[wasm_bindgen(js_name = openAnonymousMlsEnvelope)]
    pub async fn open_anonymous_mls_envelope(
        &self,
        recipient: JsValue,
        send_id: String,
        envelope: JsValue,
    ) -> std::result::Result<Vec<u8>, JsValue> {
        let recipient: AccountRef = from_transport(recipient).map_err(chat_error)?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("anonymous MLS send id must be a UUID"))?;
        let envelope: AnonymousMlsDeviceEnvelopeV1 =
            from_transport(envelope).map_err(chat_error)?;
        self.mls_client()
            .open_anonymous_envelope(&recipient, send_id, &envelope)
            .await
            .map_err(chat_error)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = sendText)]
    pub async fn send_text(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        text: String,
        reply_to: Option<String>,
        expires_after_seconds: Option<u32>,
        extras: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let extras = parse_extras(extras)?;
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let mut content = ChatContent::text_with_id(&send_id, sent_at, seq, text)
            .with_reply_to(reply_to.as_deref())
            .and_then(|content| content.with_extras(&extras))
            .map_err(|error| js_error(&error))?;
        if let Some(seconds) = expires_after_seconds {
            content = content
                .with_disappearing_after(seconds)
                .map_err(|error| js_error(&error))?;
        }
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = sendAttachment)]
    pub async fn send_attachment(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        descriptor: JsValue,
        expires_after_seconds: Option<u32>,
        extras: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let descriptor: ChatAttachmentDescriptorV1 =
            from_transport(descriptor).map_err(chat_error)?;
        let extras = parse_extras(extras)?;
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let mut content = ChatContent::attachment_with_id(&send_id, sent_at, seq, descriptor)
            .and_then(|content| content.with_extras(&extras))
            .map_err(|error| js_error(&error))?;
        if let Some(seconds) = expires_after_seconds {
            content = content
                .with_disappearing_after(seconds)
                .map_err(|error| js_error(&error))?;
        }
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    /// A poll, a vote in one, or its end (`kind` = `poll` | `pollVote` |
    /// `pollTerminate`), in a Direct chat or Note to Self.
    #[wasm_bindgen(js_name = sendPollContent)]
    pub async fn send_poll_content(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        kind: String,
        body: JsValue,
        expires_after_seconds: Option<u32>,
    ) -> std::result::Result<JsValue, JsValue> {
        let body: serde_json::Value = from_transport(body).map_err(chat_error)?;
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content =
            build_poll_content(&kind, &send_id, &sent_at, seq, &body, expires_after_seconds)
                .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = sendReaction)]
    pub async fn send_reaction(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        target_message_id: String,
        emoji: String,
        active: bool,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content =
            ChatContent::reaction_with_id(&send_id, sent_at, seq, target_message_id, emoji, active)
                .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = sendMessageMutation)]
    pub async fn send_message_mutation(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        target_message_id: String,
        operation: String,
        replacement_text: Option<String>,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content = ChatContent::message_mutation_with_id(
            &send_id,
            sent_at,
            seq,
            target_message_id,
            parse_message_mutation_operation(&operation)?,
            replacement_text,
        )
        .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = sendReceipt)]
    pub async fn send_receipt(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        message_ids: Vec<String>,
        state: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content = ChatContent::receipt_with_id(
            &send_id,
            sent_at,
            seq,
            message_ids,
            parse_receipt_state(&state)?,
        )
        .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = sendTyping)]
    pub async fn send_typing(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        active: bool,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content = ChatContent::typing_with_id(&send_id, sent_at, seq, active);
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    /// Send one call signal (offer, answer, ICE, hang-up, busy) to `peer`'s
    /// devices; like typing it is never history nor a transcript.
    #[wasm_bindgen(js_name = sendCallSignal)]
    pub async fn send_call_signal(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        signal: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let signal: kutup_chat_proto::CallSignalV1 = from_transport(signal).map_err(chat_error)?;
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content = ChatContent::call_with_id(&send_id, sent_at, seq, &signal)
            .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    /// Put a call into `peer`'s timeline on this device (writing it again
    /// for the same call replaces it).
    #[wasm_bindgen(js_name = recordCallLog)]
    pub async fn record_call_log(
        &mut self,
        peer: String,
        body: JsValue,
    ) -> std::result::Result<(), JsValue> {
        let body: kutup_chat_proto::CallLogBody = from_transport(body).map_err(chat_error)?;
        let content = ChatContent::call_log_with_id(body.call_id.to_string(), now_rfc3339(), &body)
            .map_err(|error| js_error(&error))?;
        self.engine
            .session_mut()
            .record_local_notice(&peer, &content)
            .await
            .map_err(chat_error)
    }

    /// Writes `peer`'s pending pin to the account's list now (they renamed):
    /// true when one was written.
    #[wasm_bindgen(js_name = writeIdentityPinNow)]
    pub async fn write_identity_pin_now(
        &mut self,
        peer: String,
    ) -> std::result::Result<bool, JsValue> {
        self.engine
            .write_identity_pin_now(&peer)
            .await
            .map_err(chat_error)
    }

    /// The pin Chat keeps for `peer` and hasn't written to the account's
    /// list yet: `{authorityPublicKey, since}`, or null.
    #[wasm_bindgen(js_name = pendingIdentityPin)]
    pub async fn pending_identity_pin(
        &mut self,
        peer: String,
    ) -> std::result::Result<JsValue, JsValue> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct PendingPin {
            authority_public_key: String,
            since: String,
        }
        let pending = self
            .engine
            .pending_identity_pin(&peer)
            .await
            .map_err(chat_error)?;
        to_output(&pending.map(|(authority_public_key, since)| PendingPin {
            authority_public_key,
            since,
        }))
    }

    /// The line saying `peer` (an account key) changed their username from
    /// `previous` to `current`, step `sequence` of their own verified rename
    /// chain; written once. True when it was written now.
    #[wasm_bindgen(js_name = recordPeerRenamed)]
    pub async fn record_peer_renamed(
        &mut self,
        peer: String,
        previous: String,
        current: String,
        sequence: f64,
    ) -> std::result::Result<bool, JsValue> {
        if !(sequence.is_finite()
            && sequence >= 1.0
            && sequence.fract() == 0.0
            && sequence <= 9_007_199_254_740_991.0)
        {
            return Err(js_error("a rename sequence is a positive integer"));
        }
        let body = kutup_chat_proto::PeerRenamedBody {
            previous,
            current,
            sequence: sequence as u64,
        };
        self.engine
            .session_mut()
            .record_peer_renamed(&peer, &body)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = sendDisappearingTimer)]
    pub async fn send_disappearing_timer(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        duration_seconds: Option<u32>,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content =
            ChatContent::disappearing_timer_with_id(&send_id, sent_at, seq, duration_seconds)
                .map_err(|error| js_error(&error))?;
        let summary = self
            .engine
            .send(&send_id, &peer, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    /// Sends a same-account control (`conversationState`, `readPosition` or
    /// `deleteForMe`) to this account's other devices through Note to Self.
    #[wasm_bindgen(js_name = sendAccountControl)]
    pub async fn send_account_control(
        &mut self,
        send_id: String,
        sent_at: String,
        kind: String,
        body: JsValue,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let content = match kind.as_str() {
            kutup_chat_proto::content::kind::CONVERSATION_STATE => {
                ChatContent::conversation_state_with_id(
                    &send_id,
                    sent_at,
                    seq,
                    from_transport(body).map_err(chat_error)?,
                )
            }
            kutup_chat_proto::content::kind::READ_POSITION => ChatContent::read_position_with_id(
                &send_id,
                sent_at,
                seq,
                from_transport(body).map_err(chat_error)?,
            ),
            kutup_chat_proto::content::kind::DELETE_FOR_ME => ChatContent::delete_for_me_with_id(
                &send_id,
                sent_at,
                seq,
                from_transport(body).map_err(chat_error)?,
            ),
            kutup_chat_proto::content::kind::STICKER_SAVED => ChatContent::sticker_saved_with_id(
                &send_id,
                sent_at,
                seq,
                from_transport(body).map_err(chat_error)?,
            ),
            kutup_chat_proto::content::kind::STICKER_REMOVED => {
                ChatContent::sticker_removed_with_id(
                    &send_id,
                    sent_at,
                    seq,
                    from_transport(body).map_err(chat_error)?,
                )
            }
            kutup_chat_proto::content::kind::VIEW_ONCE_OPENED => {
                ChatContent::view_once_opened_with_id(
                    &send_id,
                    sent_at,
                    seq,
                    from_transport(body).map_err(chat_error)?,
                )
            }
            _ => return Err(js_error("unknown same-account control")),
        }
        .map_err(|error| js_error(&error))?;
        let local_account = self.engine.session().user().to_owned();
        let summary = self
            .engine
            .send(&send_id, &local_account, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = startDisappearingExpiry)]
    pub async fn start_disappearing_expiry(
        &mut self,
        send_id: String,
        sent_at: String,
        conversation: JsValue,
        target_message_id: String,
        started_at_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let conversation: ConversationId = from_transport(conversation).map_err(chat_error)?;
        let content = ChatContent::disappearing_expiry_start_with_id(
            &send_id,
            sent_at,
            seq,
            conversation,
            target_message_id,
            parse_i64_string("disappearing expiry-start clock", &started_at_ms)?,
        )
        .map_err(|error| js_error(&error))?;
        let local_account = self.engine.session().user().to_owned();
        let summary = self
            .engine
            .send(&send_id, &local_account, &content, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    #[wasm_bindgen(js_name = mediaDeliveryCapability)]
    pub async fn media_delivery_capability(
        &self,
        peer: String,
    ) -> std::result::Result<String, JsValue> {
        let capability = self
            .engine
            .media_delivery_capability(&peer)
            .await
            .map_err(chat_error)?
            .ok_or_else(|| js_error("accepted contact media capability is unavailable"))?;
        Ok(STANDARD.encode(capability))
    }

    /// Flush crash-surviving sends, drain/decrypt/ack the mailbox, and return
    /// the new receive report. WebSocket notifications call this same source-
    /// of-truth reconciliation path.
    pub async fn reconcile(&mut self) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        // A message the server will not take right now stays queued and is
        // reported below; it must not keep the mailbox from being read, or
        // one stuck send would cut this device off from everything incoming
        // (and stop Chat from opening at all).
        let send_failures = self
            .engine
            .flush_outbox_collecting_failures(&mut rng)
            .await
            .map_err(chat_error)?
            .failed;
        // Contact controls are durable best-effort account sync. A temporary
        // failure must not prevent mailbox decrypt/ack; the marker/outbox retry.
        let _ = self
            .engine
            .flush_contact_syncs(&now_rfc3339(), &mut rng)
            .await;
        let _ = self
            .engine
            .flush_profile(&self.profile_wrapping_key, &now_rfc3339(), &mut rng)
            .await;
        // Group messages still on their way: best effort, retried each pass.
        if let Ok(summaries) = self.engine.flush_group_outbox(&mut rng).await {
            // A message that couldn't be tried this pass waits for the next;
            // why is worth seeing in the console.
            for error in summaries
                .iter()
                .filter_map(|summary| summary.error.as_deref())
            {
                console_warn(&format!(
                    "chat: a group message waits for the next pass: {error}"
                ));
            }
        }
        // The account's group list, every so often: groups another device
        // joined or left (best effort).
        let _ = self.engine.sync_group_list_if_due(&mut rng).await;
        // The account's contact list too: what another device changed, and
        // this device's due writes (best effort).
        let _ = self.engine.sync_contact_list_if_due().await;
        let mut report = self.engine.receive(&mut rng).await.map_err(chat_error)?;
        // A reply can promote pending-outgoing to accepted (or a new message
        // can supersede a prior rejection). Publish that newer revision after
        // the decrypt commit so delayed older controls cannot win elsewhere.
        let _ = self
            .engine
            .flush_contact_syncs(&now_rfc3339(), &mut rng)
            .await;
        report.profiles_refreshed = self.engine.refresh_profiles().await.unwrap_or_default();
        let mut view = ReceiveReportView::from(report);
        view.send_failures = send_failures
            .into_iter()
            .map(|failure| SendFailureView {
                send_id: failure.send_id,
                peer: failure.peer,
                error: failure.error.to_string(),
            })
            .collect();
        to_output(&view)
    }

    /// How long the server keeps undelivered messages (its
    /// `mailboxRetentionDays`, 0: for ever): a replaced prekey is kept that
    /// long plus a margin.
    #[wasm_bindgen(js_name = setMailboxRetentionDays)]
    pub fn set_mailbox_retention_days(&mut self, days: u32) {
        self.engine.set_mailbox_retention_days(days);
    }

    /// Fence this tab's writes behind the store's writer generation, at the
    /// start of each turn under the cross-tab lock. `takeOver` when the lock
    /// was taken from a tab that stopped answering: its writes are then
    /// refused if it resumes.
    #[wasm_bindgen(js_name = claimWriter)]
    pub async fn claim_writer(&self, take_over: bool) -> std::result::Result<f64, JsValue> {
        let generation = self
            .engine
            .session()
            .db()
            .claim_writer(take_over)
            .await
            .map_err(chat_error)?;
        Ok(generation as f64)
    }

    #[wasm_bindgen(js_name = maintainPrekeys)]
    pub async fn maintain_prekeys(&mut self) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let report = self
            .engine
            .maintain_prekeys(20, 50, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&report)
    }

    pub async fn history(&self) -> std::result::Result<JsValue, JsValue> {
        let incoming = self.engine.session().history().await.map_err(chat_error)?;
        let outgoing = self
            .engine
            .session()
            .sent_history()
            .await
            .map_err(chat_error)?;
        let mls = self
            .mls_client()
            .mls_application_history()
            .await
            .map_err(chat_error)?;
        let expiry_starts = self
            .engine
            .session()
            .disappearing_expiry_starts()
            .await
            .map_err(chat_error)?;
        let me = self.engine.session().user().to_owned();
        let mut history = Vec::with_capacity(incoming.len() + outgoing.len() + mls.len());
        for message in incoming {
            if is_contact_control(&message.content).map_err(chat_error)? {
                continue;
            }
            let mut entry = HistoryEntry::incoming(message).map_err(chat_error)?;
            entry.apply_disappearing_deadline(&expiry_starts);
            history.push(entry);
        }
        for message in outgoing {
            if is_contact_control(&message.content).map_err(chat_error)? {
                continue;
            }
            let mut entry = HistoryEntry::outgoing(message, &me).map_err(chat_error)?;
            entry.apply_disappearing_deadline(&expiry_starts);
            history.push(entry);
        }
        for message in mls {
            if is_invisible_control(&message.content).map_err(chat_error)? {
                continue;
            }
            let mut entry = HistoryEntry::mls(message, &me).map_err(chat_error)?;
            entry.apply_disappearing_deadline(&expiry_starts);
            history.push(entry);
        }
        // Group messages still going out show as sent-but-undelivered, with
        // the id their delivered row will have.
        let delivered_ids: std::collections::HashSet<String> =
            history.iter().map(|entry| entry.id.clone()).collect();
        for entry in self
            .mls_client()
            .pending_application_messages()
            .await
            .map_err(chat_error)?
        {
            if entry.content.is_empty()
                || delivered_ids.contains(&entry.send_id)
                || is_invisible_control(&entry.content).map_err(chat_error)?
            {
                continue;
            }
            let mut pending = HistoryEntry::mls_pending(entry, &me).map_err(chat_error)?;
            pending.apply_disappearing_deadline(&expiry_starts);
            history.push(pending);
        }
        history.sort_by(|left, right| {
            left.timestamp_ms
                .cmp(&right.timestamp_ms)
                .then_with(|| left.id.cmp(&right.id))
        });
        to_output(&history)
    }

    /// Conversations from their timelines (`timeline.rs`), newest activity
    /// first: each one's latest time, how many incoming messages are newer
    /// than `readThrough[key]` (milliseconds), its newest entries (`recent`
    /// plus the unread ones, up to 200 more) and its disappearing timer.
    /// Only `keys` when given. Reads headers and the newest chunks, not the
    /// whole history.
    #[wasm_bindgen(js_name = conversationSummaries)]
    pub async fn conversation_summaries(
        &self,
        read_through: JsValue,
        recent: u32,
        keys: Option<Vec<String>>,
    ) -> std::result::Result<JsValue, JsValue> {
        let read_through: std::collections::HashMap<String, f64> =
            if read_through.is_undefined() || read_through.is_null() {
                std::collections::HashMap::new()
            } else {
                serde_wasm_bindgen::from_value(read_through)
                    .map_err(|error| js_error(&format!("read positions: {error}")))?
            };
        let db = self.engine.session().db().as_ref();
        let Some(directory) = crate::timeline::load_directory(db)
            .await
            .map_err(chat_error)?
        else {
            return to_output(&Vec::<ConversationSummaryView>::new());
        };
        let wanted: Option<std::collections::HashSet<String>> =
            keys.map(|keys| keys.into_iter().collect());
        let mut summaries = Vec::with_capacity(directory.conversations.len());
        for (key, header) in &directory.conversations {
            if wanted.as_ref().is_some_and(|wanted| !wanted.contains(key)) {
                continue;
            }
            let through = read_through.get(key).copied().unwrap_or(0.0) as i64;
            let unread = crate::timeline::unread(db, &directory, key, through)
                .await
                .map_err(chat_error)?;
            let window = recent as usize + (unread as usize).min(200);
            let mut refs = crate::timeline::page(db, &directory, key, None, window)
                .await
                .map_err(chat_error)?;
            // The list shows the latest visible message: reach back to it past
            // a run of reactions, receipts or controls.
            let shows = |entry: &crate::timeline::EntryRef| {
                entry.flags & (crate::timeline::VISIBLE | crate::timeline::ROUTED)
                    == crate::timeline::VISIBLE
            };
            while refs.len() >= window && !refs.iter().any(shows) && refs.len() < window + 1_000 {
                let more = crate::timeline::page(db, &directory, key, refs.last(), 100)
                    .await
                    .map_err(chat_error)?;
                if more.is_empty() {
                    break;
                }
                let found = more.iter().position(shows);
                match found {
                    Some(at) => {
                        refs.extend(more.into_iter().take(at + 1));
                        break;
                    }
                    None => refs.extend(more),
                }
            }
            let entries = self
                .timeline_entries(&directory, key, &refs, true)
                .await
                .map_err(chat_error)?;
            let timer = match &header.timer {
                Some(timer) if !refs.contains(timer) => self
                    .timeline_entries(&directory, key, std::slice::from_ref(timer), false)
                    .await
                    .map_err(chat_error)?
                    .into_iter()
                    .next(),
                _ => None,
            };
            summaries.push(ConversationSummaryView {
                key: key.clone(),
                conversation: header.conversation.clone(),
                latest_ms: header.latest_ms(),
                unread,
                recent: entries,
                timer,
            });
        }
        summaries.sort_by_key(|summary| std::cmp::Reverse(summary.latest_ms));
        to_output(&summaries)
    }

    /// Search the history (`search.rs`): the entries whose words begin with
    /// every word of `query` (folded: İ/I/ı/i alike, accents removed),
    /// newest first, at most `limit`; with them the entries that edit or
    /// delete them and the messages an edit hit acts on, so the caller can
    /// show each as it stands. Entries are built as in the full history,
    /// disappearing deadlines included.
    #[wasm_bindgen(js_name = searchHistory)]
    pub async fn search_history(
        &self,
        query: String,
        limit: u32,
    ) -> std::result::Result<JsValue, JsValue> {
        let db = self.engine.session().db().as_ref();
        // Taken out for the query, so overlapping calls never share it.
        let mut cache = self.search_cache.take();
        let found = async {
            let hits = crate::search::query(db, &mut cache, &query, limit as usize).await?;
            let related = crate::search::related(db, &mut cache, &hits).await?;
            Ok::<_, ChatError>((hits, related))
        }
        .await;
        self.search_cache.replace(cache);
        let (hits, related) = found.map_err(chat_error)?;
        let Some(directory) = crate::timeline::load_directory(db)
            .await
            .map_err(chat_error)?
        else {
            return to_output(&SearchView::default());
        };
        let entries = self
            .search_entries(&directory, &hits)
            .await
            .map_err(chat_error)?;
        let related = self
            .search_entries(&directory, &related)
            .await
            .map_err(chat_error)?;
        to_output(&SearchView { entries, related })
    }

    /// The key of every conversation with a timeline, for work that reads
    /// the whole history one conversation at a time (the backup).
    #[wasm_bindgen(js_name = conversationKeys)]
    pub async fn conversation_keys(&self) -> std::result::Result<Vec<String>, JsValue> {
        let db = self.engine.session().db().as_ref();
        Ok(crate::timeline::load_directory(db)
            .await
            .map_err(chat_error)?
            .map(|directory| directory.conversations.into_keys().collect())
            .unwrap_or_default())
    }

    /// One conversation's entries, newest first, older than `before` (a
    /// cursor from an earlier page), at most `limit`; with the cursor to ask
    /// for the next page, or none at the start of the conversation.
    #[wasm_bindgen(js_name = conversationHistory)]
    pub async fn conversation_history(
        &self,
        key: String,
        before: Option<String>,
        limit: u32,
    ) -> std::result::Result<JsValue, JsValue> {
        let db = self.engine.session().db().as_ref();
        let Some(directory) = crate::timeline::load_directory(db)
            .await
            .map_err(chat_error)?
        else {
            return to_output(&ConversationPageView {
                entries: Vec::new(),
                before: None,
            });
        };
        let before = before
            .as_deref()
            .map(crate::timeline::from_cursor)
            .transpose()
            .map_err(chat_error)?;
        let refs = crate::timeline::page(db, &directory, &key, before.as_ref(), limit as usize)
            .await
            .map_err(chat_error)?;
        let next = if refs.len() < limit as usize {
            None
        } else {
            refs.last()
                .map(crate::timeline::cursor_of)
                .transpose()
                .map_err(chat_error)?
        };
        let entries = self
            .timeline_entries(&directory, &key, &refs, before.is_none())
            .await
            .map_err(chat_error)?;
        to_output(&ConversationPageView {
            entries,
            before: next,
        })
    }

    /// This account's own controls in Note to Self (list state, read
    /// positions, deletions, opened view-once media, stickers), oldest first.
    #[wasm_bindgen(js_name = accountControls)]
    pub async fn account_controls(&self) -> std::result::Result<JsValue, JsValue> {
        let db = self.engine.session().db().as_ref();
        let Some(directory) = crate::timeline::load_directory(db)
            .await
            .map_err(chat_error)?
        else {
            return to_output(&Vec::<HistoryEntry>::new());
        };
        let key = crate::timeline::direct(self.engine.session().user())
            .map_err(chat_error)?
            .key();
        let refs = crate::timeline::flagged(db, &directory, &key, crate::timeline::ACCOUNT_CONTROL)
            .await
            .map_err(chat_error)?;
        let mut entries = self
            .timeline_entries(&directory, &key, &refs, false)
            .await
            .map_err(chat_error)?;
        entries.reverse();
        to_output(&entries)
    }

    /// The conversations changed by this browser's commits after `since`
    /// (a `storeCommits` value), or `null` when that is no longer known.
    #[wasm_bindgen(js_name = changedConversations)]
    pub fn changed_conversations(&self, since: f64) -> std::result::Result<JsValue, JsValue> {
        to_output(
            &self
                .engine
                .session()
                .db()
                .changed_conversations(since as u64),
        )
    }

    #[wasm_bindgen(js_name = purgeExpiredMessages)]
    pub async fn purge_expired_messages(
        &mut self,
        now_ms: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let report = self
            .engine
            .session_mut()
            .purge_expired_history(parse_i64_string("disappearing-message clock", &now_ms)?)
            .await
            .map_err(chat_error)?;
        to_output(&report)
    }

    pub async fn contacts(&self) -> std::result::Result<JsValue, JsValue> {
        let contacts: Vec<ContactRecordView> = self
            .engine
            .contacts()
            .await
            .map_err(chat_error)?
            .into_iter()
            .map(Into::into)
            .collect();
        to_output(&contacts)
    }

    pub async fn profile(&self) -> std::result::Result<JsValue, JsValue> {
        let profile = self
            .engine
            .local_profile()
            .await
            .map_err(chat_error)?
            .ok_or_else(|| js_error("encrypted profile is not initialized"))?;
        to_output(&ProfileView::from(profile))
    }

    pub async fn profiles(&self) -> std::result::Result<JsValue, JsValue> {
        let profiles: Vec<PeerProfileView> = self
            .engine
            .peer_profiles()
            .await
            .map_err(chat_error)?
            .into_iter()
            .filter_map(PeerProfileView::from_profile)
            .collect();
        to_output(&profiles)
    }

    /// Take a newer profile revision from the server (the account app edits
    /// the profile) and tell contacts when it changed.
    #[wasm_bindgen(js_name = refreshProfile)]
    pub async fn refresh_profile(&mut self) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        let user = self.engine.session().user().to_string();
        self.engine
            .initialize_profile(&self.profile_wrapping_key, &user, &mut rng)
            .await
            .map_err(chat_error)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = setProfile)]
    pub async fn set_profile(
        &mut self,
        display_name: String,
        avatar: Option<String>,
        avatar_content_type: Option<String>,
        about: Option<String>,
    ) -> std::result::Result<JsValue, JsValue> {
        let avatar = avatar
            .map(|value| STANDARD.decode(value).map_err(ChatError::from))
            .transpose()
            .map_err(chat_error)?;
        let mut rng = OsRng.unwrap_err();
        let profile = self
            .engine
            .update_profile(
                &display_name,
                avatar,
                avatar_content_type,
                about,
                &self.profile_wrapping_key,
                &now_rfc3339(),
                &mut rng,
            )
            .await
            .map_err(chat_error)?;
        to_output(&ProfileView::from(profile))
    }

    #[wasm_bindgen(js_name = acceptContact)]
    pub async fn accept_contact(&mut self, peer: String) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let contact = self
            .engine
            .accept_contact(&peer, &now_rfc3339(), &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&ContactRecordView::from(contact))
    }

    #[wasm_bindgen(js_name = rejectContact)]
    pub async fn reject_contact(&mut self, peer: String) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let contact = self
            .engine
            .reject_contact(&peer, &now_rfc3339(), &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&ContactRecordView::from(contact))
    }

    #[wasm_bindgen(js_name = blockContact)]
    pub async fn block_contact(&mut self, peer: String) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let contact = self
            .engine
            .block_contact(&peer, &self.profile_wrapping_key, &now_rfc3339(), &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&ContactRecordView::from(contact))
    }

    #[wasm_bindgen(js_name = unblockContact)]
    pub async fn unblock_contact(&mut self, peer: String) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let contact = self
            .engine
            .unblock_contact(&peer, &now_rfc3339(), &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&ContactRecordView::from(contact))
    }

    /// The next send to anyone fetches and verifies their device list again.
    #[wasm_bindgen(js_name = forgetKnownDevices)]
    pub fn forget_known_devices(&mut self) {
        self.engine.forget_known_devices();
    }

    #[wasm_bindgen(js_name = pendingSendCount)]
    pub async fn pending_send_count(&self) -> std::result::Result<usize, JsValue> {
        self.engine.pending_send_count().await.map_err(chat_error)
    }

    #[wasm_bindgen(js_name = inboundAttention)]
    pub async fn inbound_attention(&self) -> std::result::Result<JsValue, JsValue> {
        let items = self.engine.inbound_attention().await.map_err(chat_error)?;
        let views: Vec<InboundEnvelopeView> = items.into_iter().map(Into::into).collect();
        to_output(&views)
    }

    #[wasm_bindgen(js_name = quarantineInbound)]
    pub async fn quarantine_inbound(&mut self, id: String) -> std::result::Result<(), JsValue> {
        self.engine
            .quarantine_inbound(&id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = resolveDeadLetter)]
    pub async fn resolve_dead_letter(&mut self, id: String) -> std::result::Result<(), JsValue> {
        self.engine
            .resolve_dead_letter(&id)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = safetyNumber)]
    pub async fn safety_number(&mut self, peer: String) -> std::result::Result<JsValue, JsValue> {
        let safety_number = self
            .engine
            .safety_number(&self.authority, &peer)
            .await
            .map_err(chat_error)?;
        to_output(&safety_number)
    }

    #[wasm_bindgen(js_name = verifySafetyNumber)]
    pub async fn verify_safety_number(
        &mut self,
        peer: String,
        scanned_payload: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let safety_number = self
            .engine
            .verify_safety_number(&self.authority, &peer, &scanned_payload)
            .await
            .map_err(chat_error)?;
        to_output(&safety_number)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendSummaryView {
    delivered: bool,
    deduplicated: bool,
    attempts: u32,
    safety_number_changes: Vec<String>,
}

impl From<crate::SendSummary> for SendSummaryView {
    fn from(summary: crate::SendSummary) -> Self {
        Self {
            delivered: summary.delivered,
            deduplicated: summary.deduplicated,
            attempts: summary.attempts,
            safety_number_changes: summary
                .safety_number_changes
                .into_iter()
                .map(|address| address.name())
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiveReportView {
    messages: Vec<ReceivedMessageView>,
    synced: Vec<String>,
    contact_synced: Vec<String>,
    profile_key_updated: Vec<String>,
    profiles_refreshed: Vec<String>,
    suppressed: Vec<String>,
    undecodable: Vec<String>,
    errors: Vec<InboundFailureView>,
    duplicates: Vec<String>,
    /// Unreadable envelopes given up on, the sender's session refreshed.
    repaired: Vec<String>,
    /// Queued messages that could not be delivered on this pass.
    send_failures: Vec<SendFailureView>,
    /// Group invitations that arrived.
    group_invites: Vec<GroupInviteView>,
    /// Group envelopes left queued until their sender can be confirmed.
    held: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupInviteView {
    group_id: String,
    from: String,
    request: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendFailureView {
    send_id: String,
    peer: String,
    error: String,
}

impl From<ReceiveReport> for ReceiveReportView {
    fn from(report: ReceiveReport) -> Self {
        Self {
            messages: report
                .messages
                .into_iter()
                .map(ReceivedMessageView::from)
                .collect(),
            synced: report.synced,
            contact_synced: report.contact_synced,
            profile_key_updated: report.profile_key_updated,
            profiles_refreshed: report.profiles_refreshed,
            suppressed: report.suppressed,
            undecodable: report.undecodable,
            errors: report
                .errors
                .into_iter()
                .map(InboundFailureView::from)
                .collect(),
            duplicates: report.duplicates,
            repaired: report.repaired,
            send_failures: Vec::new(),
            group_invites: report
                .group_invites
                .into_iter()
                .map(|notice| GroupInviteView {
                    group_id: notice.group_id,
                    from: notice.from,
                    request: notice.request,
                })
                .collect(),
            held: report.held,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileView {
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    about: Option<String>,
    revision: String,
}

impl From<crate::LocalProfile> for ProfileView {
    fn from(profile: crate::LocalProfile) -> Self {
        Self {
            display_name: profile.display_name,
            avatar: profile.avatar.map(|bytes| STANDARD.encode(bytes)),
            avatar_content_type: profile.avatar_content_type,
            about: profile.about,
            revision: profile.revision.to_string(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerProfileView {
    peer: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    about: Option<String>,
    revision: String,
}

impl PeerProfileView {
    fn from_profile(profile: crate::PeerProfile) -> Option<Self> {
        Some(Self {
            peer: profile.peer,
            display_name: profile.display_name?,
            avatar: profile.avatar.map(|bytes| STANDARD.encode(bytes)),
            avatar_content_type: profile.avatar_content_type,
            about: profile.about,
            revision: profile.revision.to_string(),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContactRecordView {
    peer: String,
    state: kutup_chat_proto::ContactState,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state: Option<kutup_chat_proto::ContactState>,
    revision: String,
    source_device_id: u32,
    updated_at_ms: i64,
    sync_pending: bool,
}

impl From<crate::ContactRecord> for ContactRecordView {
    fn from(contact: crate::ContactRecord) -> Self {
        Self {
            peer: contact.peer,
            state: contact.state,
            previous_state: contact.previous_state,
            revision: contact.revision.to_string(),
            source_device_id: contact.source_device_id,
            updated_at_ms: contact.updated_at_ms,
            sync_pending: contact.sync_pending,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceivedMessageView {
    id: String,
    conversation: ConversationId,
    peer: String,
    sender_device_id: u32,
    cursor: String,
    content: ContentView,
}

impl From<crate::ReceivedMessage> for ReceivedMessageView {
    fn from(message: crate::ReceivedMessage) -> Self {
        Self {
            id: message.id,
            conversation: message
                .content
                .group_context()
                .map(|context| ConversationId::Group {
                    group_id: context.group_id.clone(),
                })
                .unwrap_or_else(|| message.from.conversation()),
            peer: message.from.name(),
            sender_device_id: message.from.device_id,
            cursor: message.cursor.to_string(),
            content: message.content.into(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InboundFailureView {
    id: String,
    kind: String,
    error: String,
}

impl From<crate::InboundFailure> for InboundFailureView {
    fn from(failure: crate::InboundFailure) -> Self {
        Self {
            id: failure.id,
            kind: format!("{:?}", failure.kind),
            error: failure.error,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentView {
    version: u16,
    kind: String,
    sent_at: String,
    seq: String,
    message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    body: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment: Option<ChatAttachmentDescriptorV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reaction: Option<kutup_chat_proto::ReactionBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation: Option<kutup_chat_proto::MessageMutationBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<kutup_chat_proto::ReceiptBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typing: Option<kutup_chat_proto::TypingBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call: Option<kutup_chat_proto::CallSignalV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_log: Option<kutup_chat_proto::CallLogBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_call: Option<kutup_chat_proto::GroupCallBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disappearing_timer: Option<kutup_chat_proto::DisappearingTimerBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_state: Option<kutup_chat_proto::ConversationStateBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_position: Option<kutup_chat_proto::ReadPositionBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_for_me: Option<kutup_chat_proto::DeleteForMeBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view_once_opened: Option<kutup_chat_proto::ViewOnceOpenedBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sticker_saved: Option<kutup_chat_proto::StickerSavedBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sticker_removed: Option<kutup_chat_proto::StickerRemovedBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sticker: Option<kutup_chat_proto::StickerMarkV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_update: Option<kutup_chat_proto::GroupUpdateBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll: Option<kutup_chat_proto::PollBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<kutup_chat_proto::LocationBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_location: Option<kutup_chat_proto::LiveLocationBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_location_stop: Option<kutup_chat_proto::LiveLocationStopBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_vote: Option<kutup_chat_proto::PollVoteBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_terminate: Option<kutup_chat_proto::PollTerminateBody>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mentions: Vec<kutup_chat_proto::MentionV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_preview: Option<kutup_chat_proto::LinkPreviewV1>,
    /// Stands where a message from the peer could not be read.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    undecryptable: bool,
    /// The local line saying the peer's safety number changed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    safety_number_changed: bool,
    /// The local line saying the peer changed their username.
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_renamed: Option<kutup_chat_proto::PeerRenamedBody>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    forwarded: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    view_once: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_after_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<i64>,
}

impl From<ChatContent> for ContentView {
    fn from(content: ChatContent) -> Self {
        let text = content.as_text().map(|body| body.text);
        let attachment = content.as_attachment();
        let reaction = content.as_reaction();
        let mutation = content.as_message_mutation();
        let receipt = content.as_receipt();
        let typing = content.as_typing();
        let call = content.as_call();
        let call_log = content.as_call_log();
        let group_call = content.as_group_call();
        let disappearing_timer = content.as_disappearing_timer();
        let conversation_state = content.as_conversation_state();
        let read_position = content.as_read_position();
        let delete_for_me = content.as_delete_for_me();
        let view_once_opened = content.as_view_once_opened();
        let sticker_saved = content.as_sticker_saved();
        let sticker_removed = content.as_sticker_removed();
        let group_update = content.as_group_update();
        let undecryptable = content.is_undecryptable();
        let safety_number_changed = content.is_safety_number_changed();
        let peer_renamed = content.as_peer_renamed();
        let extras = content.extras().unwrap_or_default();
        let poll = content.as_poll();
        let location = content.as_location();
        let live_location = content.as_live_location();
        let live_location_stop = content.as_live_location_stop();
        let poll_vote = content.as_poll_vote();
        let poll_terminate = content.as_poll_terminate();
        let expires_after_seconds = content.disappearing_after_seconds().ok().flatten();
        Self {
            version: content.v,
            kind: content.kind,
            sent_at: content.sent_at,
            seq: content.seq.to_string(),
            message_id: content.message_id,
            reply_to: content.reply_to,
            body: content.body,
            text,
            attachment,
            reaction,
            mutation,
            receipt,
            typing,
            call,
            call_log,
            group_call,
            disappearing_timer,
            conversation_state,
            read_position,
            delete_for_me,
            view_once_opened,
            sticker_saved,
            sticker_removed,
            sticker: extras.sticker.clone(),
            group_update,
            poll,
            location,
            live_location,
            live_location_stop,
            poll_vote,
            poll_terminate,
            mentions: extras.mentions,
            link_preview: extras.link_preview,
            undecryptable,
            safety_number_changed,
            peer_renamed,
            forwarded: extras.forwarded,
            view_once: extras.view_once,
            expires_after_seconds,
            expires_at_ms: None,
        }
    }
}

fn parse_message_mutation_operation(
    operation: &str,
) -> std::result::Result<kutup_chat_proto::MessageMutationOperation, JsValue> {
    match operation {
        "edit" => Ok(kutup_chat_proto::MessageMutationOperation::Edit),
        "delete" => Ok(kutup_chat_proto::MessageMutationOperation::Delete),
        _ => Err(js_error("Chat message mutation operation is invalid")),
    }
}

fn parse_receipt_state(
    state: &str,
) -> std::result::Result<kutup_chat_proto::ReceiptState, JsValue> {
    match state {
        "delivered" => Ok(kutup_chat_proto::ReceiptState::Delivered),
        "read" => Ok(kutup_chat_proto::ReceiptState::Read),
        _ => Err(js_error("Chat receipt state is invalid")),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    id: String,
    conversation: ConversationId,
    /// Who wrote it: an account's string form, `aci:<uuid>@<server>`, this
    /// account's own for an outgoing entry. Which chat it belongs to is
    /// `conversation`.
    sender: String,
    direction: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_device_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    timestamp_ms: i64,
    delivered: bool,
    deduplicated: bool,
    /// A group message: how many member accounts it never reached.
    #[serde(skip_serializing_if = "is_zero")]
    failed_recipients: u32,
    /// A pairwise group message this account sent: how many member accounts
    /// this account's server hasn't taken it for yet (0: sent).
    #[serde(skip_serializing_if = "Option::is_none")]
    waiting_recipients: Option<u32>,
    content: ContentView,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl HistoryEntry {
    fn apply_disappearing_deadline(&mut self, starts: &crate::session::DisappearingExpiryStarts) {
        let Some(seconds) = self.content.expires_after_seconds else {
            return;
        };
        let base_ms = if self.direction == "outgoing" {
            Some(self.timestamp_ms)
        } else {
            starts
                .get(&(self.conversation.key(), self.content.message_id.clone()))
                .copied()
        };
        self.content.expires_at_ms =
            base_ms.map(|base_ms| base_ms.saturating_add(i64::from(seconds).saturating_mul(1_000)));
    }

    fn incoming(message: crate::InboxMessage) -> Result<Self> {
        let content = crate::timeline::content_or_unsupported(
            &message.content,
            &message.id,
            iso_time(message.received_at),
        );
        let id = content.message_id.clone();
        // A group's message sits in the same store, under its group.
        let conversation = crate::timeline::conversation_of(&message.peer, &message.content)?;
        Ok(Self {
            id,
            conversation,
            sender: message.peer,
            direction: "incoming",
            sender_device_id: Some(message.sender_device_id),
            cursor: Some(message.cursor.to_string()),
            timestamp_ms: message.received_at,
            delivered: true,
            deduplicated: false,
            failed_recipients: 0,
            waiting_recipients: None,
            content: content.into(),
        })
    }

    fn outgoing(message: crate::SentMessage, me: &str) -> Result<Self> {
        let content = crate::timeline::content_or_unsupported(
            &message.content,
            &message.send_id,
            iso_time(message.created_at),
        );
        let conversation = crate::timeline::conversation_of(&message.peer, &message.content)?;
        Ok(Self {
            id: message.send_id,
            conversation,
            sender: me.to_owned(),
            direction: "outgoing",
            sender_device_id: (message.sender_device_id != 0).then_some(message.sender_device_id),
            cursor: None,
            timestamp_ms: message.created_at,
            delivered: message.delivered,
            deduplicated: message.deduplicated,
            failed_recipients: message.failed_recipients,
            waiting_recipients: message.waiting_recipients,
            content: content.into(),
        })
    }

    /// A group message this device is still delivering.
    fn mls_pending(entry: crate::MlsOutboxEntry, me: &str) -> Result<Self> {
        let content = serde_json::from_slice::<ChatContent>(&entry.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        let group_id = uuid::Uuid::from_bytes(entry.conversation_id).to_string();
        Ok(Self {
            id: entry.send_id,
            conversation: ConversationId::Group { group_id },
            sender: me.to_owned(),
            direction: "outgoing",
            sender_device_id: None,
            cursor: None,
            timestamp_ms: entry.created_at,
            delivered: false,
            deduplicated: false,
            failed_recipients: 0,
            waiting_recipients: None,
            content: content.into(),
        })
    }

    fn mls(message: crate::MlsHistoryMessage, me: &str) -> Result<Self> {
        let content = crate::timeline::content_or_unsupported(
            &message.content,
            &message.message_id,
            iso_time(message.timestamp_ms),
        );
        let group_id = uuid::Uuid::from_bytes(message.conversation_id).to_string();
        Ok(Self {
            id: message.message_id,
            conversation: ConversationId::Group { group_id },
            sender: if message.outgoing {
                me.to_owned()
            } else {
                message.sender
            },
            direction: if message.outgoing {
                "outgoing"
            } else {
                "incoming"
            },
            sender_device_id: (!message.outgoing).then_some(message.sender_device_id),
            cursor: message.cursor.map(|cursor| cursor.to_string()),
            timestamp_ms: message.timestamp_ms,
            delivered: message.delivered,
            deduplicated: message.deduplicated,
            failed_recipients: 0,
            waiting_recipients: None,
            content: content.into(),
        })
    }
}

/// Content that does not decode is no control: it shows as unsupported.
fn is_contact_control(bytes: &[u8]) -> Result<bool> {
    Ok(crate::timeline::decodes_to(bytes, |kind| {
        matches!(
            kind,
            kutup_chat_proto::content::kind::CONTACT_CONTROL
                | kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
                | kutup_chat_proto::content::kind::TYPING
                | kutup_chat_proto::content::kind::CALL
                | kutup_chat_proto::content::kind::DISAPPEARING_EXPIRY_START
        )
    }))
}

/// Content that does not decode is no control: it shows as unsupported.
fn is_invisible_control(bytes: &[u8]) -> Result<bool> {
    Ok(crate::timeline::decodes_to(bytes, |kind| {
        matches!(
            kind,
            kutup_chat_proto::content::kind::GROUP_CONTROL
                | kutup_chat_proto::content::kind::CONTACT_CONTROL
                | kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
                | kutup_chat_proto::content::kind::TYPING
                | kutup_chat_proto::content::kind::CALL
                | kutup_chat_proto::content::kind::DISAPPEARING_EXPIRY_START
        )
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InboundEnvelopeView {
    id: String,
    cursor: String,
    state: String,
    attempts: u32,
    failure_kind: Option<String>,
    last_error: Option<String>,
    received_at: i64,
}

impl From<InboundEnvelope> for InboundEnvelopeView {
    fn from(item: InboundEnvelope) -> Self {
        Self {
            id: item.id,
            cursor: item.cursor.to_string(),
            state: format!("{:?}", item.state),
            attempts: item.attempts,
            failure_kind: item.failure_kind.map(|kind| format!("{kind:?}")),
            last_error: item.last_error,
            received_at: item.received_at,
        }
    }
}

/// Group invite links (docs/chat-invite-links.md): the link's secret stays
/// in the browser; these derive and seal what its host keeps.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteLinkKeysOutput {
    link_id: String,
    manage_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteLinkFragmentOutput {
    secret: String,
    host: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CallLinkKeysOutput {
    room_id: String,
    access_token: String,
    access_token_hash: String,
    frame_key: String,
}

/// A fresh public nonce for a new call link (docs/chat-calls.md).
fn local_cipher(
    master_key: &[u8],
    scope: &str,
) -> std::result::Result<crate::db::store_cipher::LocalCipher, JsValue> {
    let master_key: &[u8; 32] = master_key
        .try_into()
        .map_err(|_| js_error("local chat data requires a 32-byte master key"))?;
    crate::db::store_cipher::LocalCipher::new(master_key, scope).map_err(chat_error)
}

/// Seal small browser-side chat data (drafts, read positions, the backup
/// mirror's records) for this account (`scope`), one value per purpose, under
/// a key derived from the account master key (`db/store_cipher.rs`). One call
/// seals a whole batch.
#[wasm_bindgen(js_name = sealLocalData)]
pub fn seal_local_data(
    master_key: Vec<u8>,
    scope: String,
    purposes: Vec<String>,
    plaintexts: js_sys::Array,
) -> std::result::Result<js_sys::Array, JsValue> {
    let master_key = zeroize::Zeroizing::new(master_key);
    let local = local_cipher(&master_key, &scope)?;
    if purposes.len() != plaintexts.length() as usize {
        return Err(js_error("one purpose per value"));
    }
    let mut rng = rand_core::OsRng;
    let sealed = js_sys::Array::new();
    for (purpose, plaintext) in purposes.iter().zip(plaintexts.iter()) {
        let plaintext = zeroize::Zeroizing::new(js_sys::Uint8Array::new(&plaintext).to_vec());
        let value = local
            .seal(purpose, &plaintext, &mut rng)
            .map_err(chat_error)?;
        sealed.push(&js_sys::Uint8Array::from(value.as_slice()));
    }
    Ok(sealed)
}

/// Open what `sealLocalData` sealed, one value per purpose. A value that does
/// not open comes back as `null`, so one damaged value does not hide the rest.
#[wasm_bindgen(js_name = openLocalData)]
pub fn open_local_data(
    master_key: Vec<u8>,
    scope: String,
    purposes: Vec<String>,
    sealed: js_sys::Array,
) -> std::result::Result<js_sys::Array, JsValue> {
    let master_key = zeroize::Zeroizing::new(master_key);
    let local = local_cipher(&master_key, &scope)?;
    if purposes.len() != sealed.length() as usize {
        return Err(js_error("one purpose per value"));
    }
    let opened = js_sys::Array::new();
    for (purpose, value) in purposes.iter().zip(sealed.iter()) {
        match local.open(purpose, &js_sys::Uint8Array::new(&value).to_vec()) {
            Ok(plaintext) => opened.push(&js_sys::Uint8Array::from(plaintext.as_slice())),
            Err(_) => opened.push(&JsValue::NULL),
        };
    }
    Ok(opened)
}

#[wasm_bindgen(js_name = callLinkNonce)]
pub fn call_link_nonce() -> String {
    crate::call_link::new_call_link_nonce()
}

/// The secret of the link its owner made with `nonce`.
#[wasm_bindgen(js_name = callLinkOwnerSecret)]
pub fn call_link_owner_secret(
    master_key: String,
    nonce: String,
) -> std::result::Result<String, JsValue> {
    let master_key = zeroize::Zeroizing::new(master_key);
    crate::call_link::owner_call_link_secret(&master_key, &nonce)
        .map(|secret| secret.to_string())
        .map_err(chat_error)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CallLinkHostOutput {
    host_token: String,
    host_token_hash: String,
}

/// The owner's host token for the meeting made with `nonce`, and the hash
/// the server stores of it.
#[wasm_bindgen(js_name = callLinkHostToken)]
pub fn call_link_host_token(
    master_key: String,
    nonce: String,
) -> std::result::Result<JsValue, JsValue> {
    let master_key = zeroize::Zeroizing::new(master_key);
    let token =
        crate::call_link::owner_call_link_host_token(&master_key, &nonce).map_err(chat_error)?;
    let hash = crate::call_link::call_link_token_hash(&token).map_err(chat_error)?;
    to_output(&CallLinkHostOutput {
        host_token: token.to_string(),
        host_token_hash: hash,
    })
}

/// Seal one stay in a meeting for the account's own list of joined meetings.
#[wasm_bindgen(js_name = callLinkSealJoined)]
pub fn call_link_seal_joined(
    master_key: String,
    entry: JsValue,
) -> std::result::Result<String, JsValue> {
    let master_key = zeroize::Zeroizing::new(master_key);
    let entry: crate::call_link::JoinedMeetingV1 = from_transport(entry).map_err(chat_error)?;
    crate::call_link::seal_joined_meeting(&master_key, &entry).map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkOpenJoined)]
pub fn call_link_open_joined(
    master_key: String,
    sealed: String,
) -> std::result::Result<JsValue, JsValue> {
    let master_key = zeroize::Zeroizing::new(master_key);
    let entry = crate::call_link::open_joined_meeting(&master_key, &sealed).map_err(chat_error)?;
    to_output(&entry)
}

#[wasm_bindgen(js_name = callLinkKeys)]
pub fn call_link_keys(secret: String) -> std::result::Result<JsValue, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    let keys = crate::call_link::CallLinkKeys::derive(&secret).map_err(chat_error)?;
    to_output(&CallLinkKeysOutput {
        room_id: keys.room_id.clone(),
        access_token: keys.access_token.clone(),
        access_token_hash: keys.access_token_hash.clone(),
        frame_key: keys.frame_key.to_string(),
    })
}

#[wasm_bindgen(js_name = callLinkFragment)]
pub fn call_link_fragment_js(secret: String) -> std::result::Result<String, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    crate::call_link::call_link_fragment(&secret).map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkParse)]
pub fn call_link_parse(fragment: String) -> std::result::Result<String, JsValue> {
    crate::call_link::parse_call_link_fragment(&fragment)
        .map(|secret| secret.to_string())
        .map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkSealName)]
pub fn call_link_seal_name(secret: String, name: String) -> std::result::Result<String, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    crate::call_link::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.seal_name(&name))
        .map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkOpenName)]
pub fn call_link_open_name(secret: String, sealed: String) -> std::result::Result<String, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    crate::call_link::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.open_name(&sealed))
        .map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkSealInfo)]
pub fn call_link_seal_info(secret: String, info: JsValue) -> std::result::Result<String, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    let info: crate::call_link::CallLinkInfoV1 = from_transport(info).map_err(chat_error)?;
    crate::call_link::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.seal_info(&info))
        .map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkOpenInfo)]
pub fn call_link_open_info(
    secret: String,
    sealed: String,
) -> std::result::Result<JsValue, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    let info = crate::call_link::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.open_info(&sealed))
        .map_err(chat_error)?;
    to_output(&info)
}

#[wasm_bindgen(js_name = callLinkSealMessage)]
pub fn call_link_seal_message(
    secret: String,
    message: JsValue,
) -> std::result::Result<String, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    let message: crate::call_link::CallLinkMessageV1 =
        from_transport(message).map_err(chat_error)?;
    crate::call_link::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.seal_message(&message))
        .map_err(chat_error)
}

#[wasm_bindgen(js_name = callLinkOpenMessage)]
pub fn call_link_open_message(
    secret: String,
    sealed: String,
) -> std::result::Result<JsValue, JsValue> {
    let secret = zeroize::Zeroizing::new(secret);
    let message = crate::call_link::CallLinkKeys::derive(&secret)
        .and_then(|keys| keys.open_message(&sealed))
        .map_err(chat_error)?;
    to_output(&message)
}

fn invite_link_input(
    link: JsValue,
) -> std::result::Result<kutup_chat_proto::MlsGroupInviteLinkV1, JsValue> {
    from_transport(link).map_err(chat_error)
}

#[wasm_bindgen(js_name = inviteLinkNew)]
pub fn invite_link_new(
    host: String,
    approval_required: bool,
) -> std::result::Result<JsValue, JsValue> {
    let link = kutup_chat_proto::MlsGroupInviteLinkV1 {
        secret: crate::invite_link::new_invite_link_secret(),
        host,
        approval_required,
    };
    link.validate().map_err(|error| js_error(&error))?;
    to_output(&link)
}

#[wasm_bindgen(js_name = inviteLinkKeys)]
pub fn invite_link_keys(link: JsValue) -> std::result::Result<JsValue, JsValue> {
    let keys = crate::invite_link::InviteLinkKeys::for_link(&invite_link_input(link)?)
        .map_err(chat_error)?;
    to_output(&InviteLinkKeysOutput {
        link_id: keys.link_id.clone(),
        manage_token: keys.manage_token.clone(),
    })
}

#[wasm_bindgen(js_name = inviteLinkFragment)]
pub fn invite_link_fragment_js(link: JsValue) -> std::result::Result<String, JsValue> {
    crate::invite_link::invite_link_fragment(&invite_link_input(link)?).map_err(chat_error)
}

#[wasm_bindgen(js_name = inviteLinkParse)]
pub fn invite_link_parse(fragment: String) -> std::result::Result<JsValue, JsValue> {
    let (secret, host) =
        crate::invite_link::parse_invite_link_fragment(&fragment).map_err(chat_error)?;
    to_output(&InviteLinkFragmentOutput { secret, host })
}

#[wasm_bindgen(js_name = inviteLinkSealPreview)]
pub fn invite_link_seal_preview(
    link: JsValue,
    preview: JsValue,
) -> std::result::Result<String, JsValue> {
    let keys = crate::invite_link::InviteLinkKeys::for_link(&invite_link_input(link)?)
        .map_err(chat_error)?;
    let preview: kutup_chat_proto::InviteLinkPreviewV1 =
        from_transport(preview).map_err(chat_error)?;
    keys.seal_preview(&preview).map_err(chat_error)
}

#[wasm_bindgen(js_name = inviteLinkOpenPreview)]
pub fn invite_link_open_preview(
    link: JsValue,
    sealed: String,
) -> std::result::Result<JsValue, JsValue> {
    let keys = crate::invite_link::InviteLinkKeys::for_link(&invite_link_input(link)?)
        .map_err(chat_error)?;
    to_output(&keys.open_preview(&sealed).map_err(chat_error)?)
}

#[wasm_bindgen(js_name = inviteLinkSealRequest)]
pub fn invite_link_seal_request(
    link: JsValue,
    request: JsValue,
) -> std::result::Result<String, JsValue> {
    let keys = crate::invite_link::InviteLinkKeys::for_link(&invite_link_input(link)?)
        .map_err(chat_error)?;
    let request: kutup_chat_proto::InviteJoinRequestV1 =
        from_transport(request).map_err(chat_error)?;
    keys.seal_request(&request).map_err(chat_error)
}

#[wasm_bindgen(js_name = inviteLinkOpenRequest)]
pub fn invite_link_open_request(
    link: JsValue,
    sealed: String,
) -> std::result::Result<JsValue, JsValue> {
    let keys = crate::invite_link::InviteLinkKeys::for_link(&invite_link_input(link)?)
        .map_err(chat_error)?;
    to_output(&keys.open_request(&sealed).map_err(chat_error)?)
}

#[wasm_bindgen(js_name = inviteStatusToken)]
pub fn invite_status_token() -> String {
    crate::invite_link::new_invite_status_token()
}

/// The account's profile for the account app (docs/plans/unified-profile.md):
/// open it, and seal the next revision, from the master key alone.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountProfileView {
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_content_type: Option<String>,
    revision: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountProfileInput {
    display_name: String,
    #[serde(default)]
    about: Option<String>,
    /// Standard base64.
    #[serde(default)]
    avatar: Option<String>,
    #[serde(default)]
    avatar_content_type: Option<String>,
}

fn master_key_input(master_key: Vec<u8>) -> std::result::Result<[u8; 32], JsValue> {
    master_key
        .try_into()
        .map_err(|_| js_error("the account master key is 32 bytes"))
}

#[wasm_bindgen(js_name = accountProfileOpen)]
pub fn account_profile_open(
    master_key: Vec<u8>,
    current: JsValue,
    account: String,
    binding: String,
) -> std::result::Result<JsValue, JsValue> {
    let master_key = master_key_input(master_key)?;
    let current: kutup_chat_proto::PutChatProfileRequest =
        from_transport(current).map_err(chat_error)?;
    let profile = crate::profile::open_account_profile(
        &master_key,
        &current,
        &crate::address::parse_account(&account).map_err(chat_error)?,
        &binding,
    )
    .map_err(chat_error)?;
    to_output(&AccountProfileView {
        display_name: profile.display_name,
        about: profile.about,
        avatar: profile.avatar.map(|bytes| STANDARD.encode(bytes)),
        avatar_content_type: profile.avatar_content_type,
        revision: profile.revision.to_string(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileLookup {
    /// Standard base64 of the 32-byte profile key.
    key: String,
    version: String,
    /// Standard base64; sent as the access header when fetching.
    access_key: String,
}

fn profile_lookup_of(key: &[u8]) -> std::result::Result<ProfileLookup, JsValue> {
    Ok(ProfileLookup {
        key: STANDARD.encode(key),
        version: crate::profile::profile_version(key).map_err(chat_error)?,
        access_key: STANDARD.encode(crate::profile::profile_access_key(key).map_err(chat_error)?),
    })
}

/// The account's own profile key (to give to the people it shares files
/// with), opened from the master key.
#[wasm_bindgen(js_name = accountProfileKey)]
pub fn account_profile_key(
    master_key: Vec<u8>,
    current: JsValue,
    account: String,
    binding: String,
) -> std::result::Result<JsValue, JsValue> {
    let master_key = master_key_input(master_key)?;
    let current: kutup_chat_proto::PutChatProfileRequest =
        from_transport(current).map_err(chat_error)?;
    let profile = crate::profile::open_account_profile(
        &master_key,
        &current,
        &crate::address::parse_account(&account).map_err(chat_error)?,
        &binding,
    )
    .map_err(chat_error)?;
    to_output(&profile_lookup_of(&profile.key)?)
}

/// Where to fetch someone's profile, from their profile key.
#[wasm_bindgen(js_name = profileLookup)]
pub fn profile_lookup(key: String) -> std::result::Result<JsValue, JsValue> {
    let key = STANDARD
        .decode(key)
        .map_err(|_| js_error("a profile key is standard base64"))?;
    to_output(&profile_lookup_of(&key)?)
}

/// Open someone's fetched profile with their profile key.
#[wasm_bindgen(js_name = profileOpenPeer)]
pub fn profile_open_peer(
    peer: String,
    encrypted: JsValue,
    key: String,
) -> std::result::Result<JsValue, JsValue> {
    let key = STANDARD
        .decode(key)
        .map_err(|_| js_error("a profile key is standard base64"))?;
    let encrypted: kutup_chat_proto::ChatProfileResponse =
        from_transport(encrypted).map_err(chat_error)?;
    let profile = crate::profile::open_peer_profile(peer, &encrypted, &key).map_err(chat_error)?;
    to_output(&AccountProfileView {
        display_name: profile.display_name.unwrap_or_default(),
        about: profile.about,
        avatar: profile.avatar.map(|bytes| STANDARD.encode(bytes)),
        avatar_content_type: profile.avatar_content_type,
        revision: profile.revision.to_string(),
    })
}

#[wasm_bindgen(js_name = accountProfileSeal)]
pub fn account_profile_seal(
    master_key: Vec<u8>,
    current: JsValue,
    update: JsValue,
    account: String,
    binding: String,
) -> std::result::Result<JsValue, JsValue> {
    let master_key = master_key_input(master_key)?;
    let current: Option<kutup_chat_proto::PutChatProfileRequest> =
        if current.is_null() || current.is_undefined() {
            None
        } else {
            Some(from_transport(current).map_err(chat_error)?)
        };
    let update: AccountProfileInput = from_transport(update).map_err(chat_error)?;
    let avatar = update
        .avatar
        .map(|value| STANDARD.decode(value).map_err(ChatError::from))
        .transpose()
        .map_err(chat_error)?;
    let mut rng = OsRng.unwrap_err();
    let upload = crate::profile::seal_account_profile(
        &master_key,
        current.as_ref(),
        crate::profile::AccountProfileUpdate {
            display_name: update.display_name,
            avatar,
            avatar_content_type: update.avatar_content_type,
            about: update.about,
        },
        &crate::address::parse_account(&account).map_err(chat_error)?,
        &binding,
        &mut rng,
    )
    .map_err(chat_error)?;
    to_output(&upload)
}

fn to_transport<T: Serialize + ?Sized>(value: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|error| ChatError::Transport(format!("encode transport request: {error}")))
}

fn parse_u64_string(label: &str, value: &str) -> std::result::Result<u64, JsValue> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| js_error(&format!("{label} must be canonical unsigned decimal")))?;
    if parsed.to_string() != value {
        return Err(js_error(&format!(
            "{label} must be canonical unsigned decimal"
        )));
    }
    Ok(parsed)
}

fn parse_i64_string(label: &str, value: &str) -> std::result::Result<i64, JsValue> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| js_error(&format!("{label} must be canonical signed decimal")))?;
    if parsed.to_string() != value {
        return Err(js_error(&format!(
            "{label} must be canonical signed decimal"
        )));
    }
    Ok(parsed)
}

/// Builds structured content (polls, a place, a group call) from its JSON
/// body by kind; only a poll itself and a place may disappear.
fn build_poll_content(
    kind: &str,
    send_id: &str,
    sent_at: &str,
    seq: u64,
    body: &serde_json::Value,
    expires_after_seconds: Option<u32>,
) -> std::result::Result<ChatContent, String> {
    let decode = |what: &str| format!("Chat {what} body is malformed");
    let content = match kind {
        kutup_chat_proto::content::kind::POLL => ChatContent::poll_with_id(
            send_id,
            sent_at,
            seq,
            &serde_json::from_value(body.clone()).map_err(|_| decode("poll"))?,
        )?,
        kutup_chat_proto::content::kind::POLL_VOTE => ChatContent::poll_vote_with_id(
            send_id,
            sent_at,
            seq,
            &serde_json::from_value(body.clone()).map_err(|_| decode("poll vote"))?,
        )?,
        kutup_chat_proto::content::kind::POLL_TERMINATE => ChatContent::poll_terminate_with_id(
            send_id,
            sent_at,
            seq,
            &serde_json::from_value(body.clone()).map_err(|_| decode("poll end"))?,
        )?,
        kutup_chat_proto::content::kind::LOCATION => ChatContent::location_with_id(
            send_id,
            sent_at,
            seq,
            &serde_json::from_value(body.clone()).map_err(|_| decode("location"))?,
        )?,
        kutup_chat_proto::content::kind::LIVE_LOCATION => ChatContent::live_location_with_id(
            send_id,
            sent_at,
            seq,
            &serde_json::from_value(body.clone()).map_err(|_| decode("live location"))?,
        )?,
        kutup_chat_proto::content::kind::LIVE_LOCATION_STOP => {
            ChatContent::live_location_stop_with_id(
                send_id,
                sent_at,
                seq,
                &serde_json::from_value(body.clone()).map_err(|_| decode("live location stop"))?,
            )?
        }
        kutup_chat_proto::content::kind::GROUP_CALL => ChatContent::group_call_with_id(
            send_id,
            sent_at,
            seq,
            &serde_json::from_value(body.clone()).map_err(|_| decode("group call"))?,
        )?,
        _ => return Err("unknown Chat structured content".into()),
    };
    match expires_after_seconds {
        Some(seconds)
            if kind == kutup_chat_proto::content::kind::POLL
                || kind == kutup_chat_proto::content::kind::LOCATION
                || kind == kutup_chat_proto::content::kind::LIVE_LOCATION =>
        {
            content.with_disappearing_after(seconds)
        }
        _ => Ok(content),
    }
}

/// Optional extras of a visible message; absent means none.
fn parse_extras(
    value: JsValue,
) -> std::result::Result<kutup_chat_proto::VisibleMessageExtrasV1, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(Default::default());
    }
    from_transport(value).map_err(chat_error)
}

fn from_transport<T: DeserializeOwned>(value: JsValue) -> Result<T> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|error| ChatError::Transport(format!("decode transport response: {error}")))
}

fn to_output<T: Serialize + ?Sized>(value: &T) -> std::result::Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|error| js_error(&format!("encode chat result: {error}")))
}

fn transport_error(value: JsValue) -> ChatError {
    ChatError::Transport(js_value_message(&value))
}

fn chat_error(error: ChatError) -> JsValue {
    js_error(&error.to_string())
}

fn js_error(message: &str) -> JsValue {
    js_sys::Error::new(message).into()
}

fn js_value_message(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(value, &JsValue::from_str("message"))
                .ok()
                .and_then(|message| message.as_string())
        })
        .unwrap_or_else(|| format!("JavaScript transport rejected: {value:?}"))
}

/// `millis` since the epoch, as RFC 3339.
fn iso_time(millis: i64) -> String {
    js_sys::Date::new(&JsValue::from_f64(millis as f64))
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}

fn now_rfc3339() -> String {
    js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}

/// Measures the search index in this browser (`search::bench`): a fresh
/// encrypted store `name`, `count` messages written, rebuilt and queried.
/// Built only with the `bench` feature (scripts/bench-search-index.sh).
#[cfg(feature = "bench")]
#[wasm_bindgen(js_name = benchSearchIndex)]
pub async fn bench_search_index(name: String, count: u32) -> std::result::Result<JsValue, JsValue> {
    fn performance_now() -> f64 {
        let performance = js_sys::Reflect::get(&js_sys::global(), &"performance".into())
            .expect("a browser has performance");
        let now = js_sys::Reflect::get(&performance, &"now".into()).expect("performance.now");
        js_sys::Function::from(now)
            .call0(&performance)
            .ok()
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0)
    }
    let db = crate::IndexedDbChatDb::open(&name, &[7u8; 32])
        .await
        .map_err(chat_error)?;
    let report = crate::search::bench::run(&db, count as usize, performance_now)
        .await
        .map_err(chat_error)?;
    to_output(&report)
}
