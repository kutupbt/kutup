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
    AccountManifestHistoryPageV3, AccountManifestPublicationV3, AccountManifestV3,
    AccountPreKeyBundlesResponse, ChatProfileResponse, DeviceListMismatch, MailboxPage,
    OwnChatProfileResponse, PreKeyCountResponse, PutChatProfileRequest,
    RegisterChatDeviceRequestV2, RegisterChatDeviceResponse, ReplenishKeysRequest,
    SendMessagesRequest,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

use crate::{
    AccountAuthority, ChatAttachmentDescriptorV1, ChatContent, ChatError, ChatTransport,
    ConversationId, Engine, InboundEnvelope, IndexedDbChatDb, ReceiveReport, Result, SendOutcome,
};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_TYPES: &str = r#"
export interface KutupChatTransport {
  registerDevice(request: unknown): Promise<unknown>;
  /** This device's id and credential, for the `X-Kutup-Device` header on every device-bound call from now on. */
  setDeviceAuth(deviceId: number, credential: string): void;
  createLinkToken(): Promise<unknown>;
  /** `false` is the server's 404: the new device's socket is gone. */
  relayProvisioning(address: string, request: unknown): Promise<boolean>;
  distributeIdentity(request: unknown): Promise<
    | { kind: "accepted" }
    | { kind: "mismatch"; mismatch: unknown }
  >;
  fetchBundles(account: string): Promise<unknown>;
  fetchSyncBundles(account: string, currentDeviceId: number): Promise<unknown>;
  fetchDeviceSession(): Promise<string>;
  fetchManifest(account: string): Promise<unknown | null>;
  fetchManifestHistory(account: string, fromSequence: string, toSequence: string, pageFromSequence: string): Promise<unknown>;
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

    #[wasm_bindgen(method, catch, js_name = fetchDeviceSession)]
    async fn js_fetch_device_session(
        this: &JsChatTransport,
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

    /// `POST /api/chat/anonymous/messages/multi?server=`: a
    /// `MultiSendOutcome` (`{ kind: "answered", status, response }`,
    /// `peerUnavailable`, `tooLarge`, `rateLimited` or `tokenInvalid`).
    #[wasm_bindgen(method, catch, js_name = sendSealedMulti)]
    async fn js_send_sealed_multi(
        this: &JsChatTransport,
        server: &str,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    /// `GET /api/chat/group-send/endorsement`: a
    /// `GroupSendEndorsementResponseV1`.
    #[wasm_bindgen(method, catch, js_name = fetchGroupSendEndorsement)]
    async fn js_fetch_group_send_endorsement(
        this: &JsChatTransport,
    ) -> std::result::Result<JsValue, JsValue>;

    /// `GET /api/chat/group-send/params[?server=]`: a `GroupSendParamsV1`,
    /// or `null` when that server publishes none.
    #[wasm_bindgen(method, catch, js_name = fetchGroupSendParams)]
    async fn js_fetch_group_send_params(
        this: &JsChatTransport,
        server: Option<String>,
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

    #[wasm_bindgen(method, js_name = setDeviceAuth)]
    fn js_set_device_auth(this: &JsChatTransport, device_id: u32, credential: &str);

    #[wasm_bindgen(method, catch, js_name = createLinkToken)]
    async fn js_create_link_token(this: &JsChatTransport) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = relayProvisioning)]
    async fn js_relay_provisioning(
        this: &JsChatTransport,
        address: &str,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = distributeIdentity)]
    async fn js_distribute_identity(
        this: &JsChatTransport,
        request: JsValue,
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
enum BrowserDistributionOutcome {
    Accepted,
    Mismatch { mismatch: DeviceListMismatch },
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

    fn set_device_auth(&self, device_id: u32, credential: &str) {
        self.js.js_set_device_auth(device_id, credential);
    }

    async fn create_link_token(&self) -> Result<kutup_chat_proto::ChatLinkTokenResponse> {
        from_transport(
            self.js
                .js_create_link_token()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn relay_provisioning(
        &self,
        address: &str,
        request: &kutup_chat_proto::ProvisioningRelayRequest,
    ) -> Result<bool> {
        from_transport(
            self.js
                .js_relay_provisioning(address, to_transport(request)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn distribute_identity(
        &self,
        request: &kutup_chat_proto::AccountIdentityDistributionRequest,
    ) -> Result<crate::DistributionOutcome> {
        let outcome: BrowserDistributionOutcome = from_transport(
            self.js
                .js_distribute_identity(to_transport(request)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserDistributionOutcome::Accepted => crate::DistributionOutcome::Accepted,
            BrowserDistributionOutcome::Mismatch { mismatch } => {
                crate::DistributionOutcome::Mismatch(mismatch)
            }
        })
    }

    async fn register_device(&self, req: &RegisterChatDeviceRequestV2) -> Result<u32> {
        let response: RegisterChatDeviceResponse = from_transport(
            self.js
                .js_register_device(to_transport(req)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(response.device_id)
    }

    async fn fetch_bundles(&self, account: &str) -> Result<AccountPreKeyBundlesResponse> {
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
    ) -> Result<AccountPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sync_bundles(account, current_device_id)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_device_session(&self) -> Result<String> {
        from_transport(
            self.js
                .js_fetch_device_session()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_manifest(&self, account: &str) -> Result<Option<AccountManifestV3>> {
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
    ) -> Result<AccountManifestHistoryPageV3> {
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
    ) -> Result<AccountPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sealed_bundles(account, &STANDARD.encode(capability))
                .await
                .map_err(transport_error)?,
        )
    }

    async fn publish_manifest(
        &self,
        manifest: &AccountManifestV3,
    ) -> Result<AccountManifestPublicationV3> {
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

    async fn send_sealed_multi(
        &self,
        server: &str,
        submission: &kutup_chat_proto::SealedMultiSubmissionV1,
    ) -> Result<crate::transport::MultiSendOutcome> {
        from_transport(
            self.js
                .js_send_sealed_multi(server, to_transport(submission)?)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_group_send_endorsement(
        &self,
    ) -> Result<kutup_chat_proto::group_send::GroupSendEndorsementResponseV1> {
        from_transport(
            self.js
                .js_fetch_group_send_endorsement()
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_group_send_params(
        &self,
        server: Option<&str>,
    ) -> Result<Option<kutup_chat_proto::group_send::GroupSendParamsV1>> {
        let value = self
            .js
            .js_fetch_group_send_params(server.map(str::to_string))
            .await
            .map_err(transport_error)?;
        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }
        from_transport(value).map(Some)
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
                Source::Inbox => {}
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
        };
        Ok(built.map(|mut built| {
            built.apply_disappearing_deadline(starts);
            built
        }))
    }

    /// History entries for timeline references (newest first, as given),
    /// built as the full history builds them.
    async fn timeline_entries(
        &self,
        directory: &crate::timeline::Directory,
        key: &str,
        refs: &[crate::timeline::EntryRef],
    ) -> Result<Vec<HistoryEntry>> {
        let starts = self.expiry_starts(directory, key).await?;
        let mut entries = Vec::with_capacity(refs.len());
        for entry in refs {
            entries.extend(self.load_entry(entry, &starts).await?);
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

fn route_reason(failure: crate::group_client::RouteFailure) -> &'static str {
    use crate::group_client::RouteFailure;
    match failure {
        RouteFailure::RateLimited => "rateLimited",
        RouteFailure::Unreachable => "unreachable",
        RouteFailure::GroupsOff => "groupsOff",
    }
}

/// What a group link leads to: `{kind: "group", ...}`, `{kind: "invalid"}`
/// (reset, turned off, or the group gone) or `{kind: "unreachable", reason}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum GroupLinkPreviewView {
    #[serde(rename_all = "camelCase")]
    Group {
        group_id: String,
        title: Option<String>,
        description: Option<String>,
        member_count: u16,
        requires_approval: bool,
        /// This account's place in it already: `invited`, `requesting`,
        /// `member`, `gone`, or absent.
        status: Option<&'static str>,
        avatar: Option<GroupAvatarWasmView>,
    },
    Invalid,
    Unreachable {
        reason: &'static str,
    },
}

fn status_name(status: &crate::group::GroupStatus) -> &'static str {
    use crate::group::GroupStatus;
    match status {
        GroupStatus::Invited { .. } => "invited",
        GroupStatus::Requesting => "requesting",
        GroupStatus::Member => "member",
        GroupStatus::Gone => "gone",
    }
}

/// A group's picture: standard base64 and its type.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupAvatarWasmView {
    data: String,
    content_type: String,
}

impl From<crate::group_avatar::GroupAvatarImage> for GroupAvatarWasmView {
    fn from(image: crate::group_avatar::GroupAvatarImage) -> Self {
        Self {
            data: STANDARD.encode(&image.data),
            content_type: image.content_type,
        }
    }
}

/// A group's picture as fetched: `{kind: "image", data, contentType}`,
/// `{kind: "none"}` or `{kind: "unreachable", reason}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum GroupAvatarFetchView {
    #[serde(rename_all = "camelCase")]
    Image {
        data: String,
        content_type: String,
    },
    None,
    Unreachable {
        reason: &'static str,
    },
}

/// A join through a link: `{kind: "joined", sync}`, `{kind: "requested"}`,
/// `{kind: "invalid"}` or `{kind: "unreachable", reason}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum GroupLinkJoinView {
    Joined { sync: GroupSyncView },
    Requested,
    Invalid,
    Unreachable { reason: &'static str },
}

/// Where a request to join stands: `{kind: "pending"}`, `{kind: "joined",
/// sync}`, `{kind: "denied"}`, `{kind: "canceled"}` or `{kind:
/// "unreachable", reason}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum GroupRequestView {
    Pending,
    Joined { sync: GroupSyncView },
    Denied,
    Canceled,
    Unreachable { reason: &'static str },
}

impl From<crate::group_link::GroupRequestOutcome> for GroupRequestView {
    fn from(outcome: crate::group_link::GroupRequestOutcome) -> Self {
        use crate::group_link::GroupRequestOutcome;
        match outcome {
            GroupRequestOutcome::Pending => Self::Pending,
            GroupRequestOutcome::Joined(sync) => Self::Joined { sync: sync.into() },
            GroupRequestOutcome::Denied => Self::Denied,
            GroupRequestOutcome::Canceled => Self::Canceled,
            GroupRequestOutcome::Unreachable(failure) => Self::Unreachable {
                reason: route_reason(failure),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupLinkView {
    /// `off`, `join` or `approve`.
    mode: &'static str,
    /// The URL fragment to share, while the link is on.
    fragment: Option<String>,
}

impl From<crate::group_link::GroupLinkSettings> for GroupLinkView {
    fn from(link: crate::group_link::GroupLinkSettings) -> Self {
        use crate::group_link::GroupLinkMode;
        Self {
            mode: match link.mode {
                GroupLinkMode::Off => "off",
                GroupLinkMode::Join => "join",
                GroupLinkMode::Approve => "approve",
            },
            fragment: link.fragment,
        }
    }
}

fn link_mode(mode: &str) -> std::result::Result<crate::group_link::GroupLinkMode, JsValue> {
    use crate::group_link::GroupLinkMode;
    match mode {
        "off" => Ok(GroupLinkMode::Off),
        "join" => Ok(GroupLinkMode::Join),
        "approve" => Ok(GroupLinkMode::Approve),
        _ => Err(js_error("a group link mode is off, join or approve")),
    }
}

fn access_required(
    value: &str,
) -> std::result::Result<kutup_chat_proto::group::AccessRequired, JsValue> {
    use kutup_chat_proto::group::AccessRequired;
    match value {
        "member" => Ok(AccessRequired::Member),
        "administrator" => Ok(AccessRequired::Administrator),
        _ => Err(js_error("access is member or administrator")),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupRequestWasmView {
    pseudonym: String,
    requested_at_revision: u64,
    /// The account when the binding verified; absent otherwise.
    account: Option<String>,
    /// Its account is banned: it can't be approved.
    banned: bool,
    /// The account the entry names, verified or not.
    claimed: Option<String>,
    /// That account can't be checked now: not approvable yet.
    unconfirmed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupBanWasmView {
    /// The banned account, or absent for a pseudonym nobody verified.
    account: Option<String>,
    pseudonyms: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDetailsView {
    group_id: String,
    title: Option<String>,
    description: Option<String>,
    timer_seconds: u32,
    announcements_only: bool,
    terminated: bool,
    access: kutup_chat_proto::group::GroupAccessV1,
    link: GroupLinkView,
    administrator: bool,
    requests: Vec<GroupRequestWasmView>,
    bans: Vec<GroupBanWasmView>,
    banned_members: Vec<String>,
    /// No room on the ban list for another account: bans hold by pseudonym.
    ban_list_full: bool,
    ban_list_unreadable: bool,
    has_avatar: bool,
}

impl From<crate::group_settings::GroupDetails> for GroupDetailsView {
    fn from(details: crate::group_settings::GroupDetails) -> Self {
        Self {
            group_id: details.group_id,
            title: details.title,
            description: details.description,
            timer_seconds: details.timer_seconds,
            announcements_only: details.announcements_only,
            terminated: details.terminated,
            access: details.access,
            link: details.link.into(),
            administrator: details.administrator,
            requests: details
                .requests
                .into_iter()
                .map(|request| GroupRequestWasmView {
                    pseudonym: request.requester.pseudonym,
                    requested_at_revision: request.requester.requested_at_revision,
                    account: request
                        .requester
                        .verified
                        .map(|verified| verified.account.to_string()),
                    banned: request.banned,
                    claimed: request.requester.claimed.map(|account| account.to_string()),
                    unconfirmed: request.requester.unconfirmed,
                })
                .collect(),
            bans: details
                .bans
                .into_iter()
                .map(|ban| GroupBanWasmView {
                    account: ban.account.map(|account| account.to_string()),
                    pseudonyms: ban.pseudonyms,
                })
                .collect(),
            banned_members: details.banned_members,
            ban_list_full: details.ban_list_full,
            ban_list_unreadable: details.ban_list_unreadable,
            has_avatar: details.has_avatar,
        }
    }
}

impl From<crate::group_engine::GroupSync> for GroupSyncView {
    fn from(sync: crate::group_engine::GroupSync) -> Self {
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
                reason: route_reason(failure),
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
    /// This account may send there now (a member; not ended; an
    /// administrator while it is announcements-only).
    may_send: bool,
    announcements_only: bool,
    terminated: bool,
    timer_seconds: u32,
    /// The avatar blob's hash, when the group has one.
    avatar_hash: Option<String>,
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
            may_send: summary.may_send,
            announcements_only: summary.announcements_only,
            terminated: summary.terminated,
            timer_seconds: summary.timer_seconds,
            avatar_hash: summary.avatar_hash,
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
    /// Where this browser stands with the account's Chat identity:
    /// `"registered"` or `"registering"` (open it), `"link"` (another device
    /// of the account holds the identity: show "Link this device"), or
    /// `"reregister"` (the account has no Chat identity yet: this is its
    /// first device). A store from before the account identity counts as no
    /// device (docs/plans/account-identity-key.md).
    #[wasm_bindgen(js_name = installation)]
    pub async fn installation(
        database_name: String,
        account: String,
        master_key: Vec<u8>,
        transport: JsChatTransport,
    ) -> std::result::Result<String, JsValue> {
        let master_key = master_key_bytes(master_key)?;
        let db = IndexedDbChatDb::open(&database_name, &master_key)
            .await
            .map_err(chat_error)?;
        let transport = BrowserTransport { js: transport };
        let account = canonical_account(&account)?;
        Ok(match Engine::installation(&db, &transport, &account)
            .await
            .map_err(chat_error)?
        {
            crate::Installation::Registered { .. } => "registered",
            crate::Installation::Registering => "registering",
            crate::Installation::Unregistered {
                account_has_identity: true,
            } => "link",
            crate::Installation::Unregistered {
                account_has_identity: false,
            } => "reregister",
        }
        .to_string())
    }

    /// Open this browser's registered device (or finish a registration it
    /// started), then publish its manifest entry. The database name must be
    /// account scoped; `account` is this account's string form,
    /// `aci:<uuid>@<server>`; `display_name` is the name a first profile
    /// starts with (the username); `binding` is the account's key binding
    /// (`session.envelopeBinding`), which its own seals bind. A browser
    /// without a device is refused: ask `installation` first.
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
        let master_key = master_key_bytes(master_key)?;
        let db = Rc::new(
            IndexedDbChatDb::open(&database_name, &master_key)
                .await
                .map_err(chat_error)?,
        );
        let transport: Rc<dyn ChatTransport> = Rc::new(BrowserTransport { js: transport });
        let account = canonical_account(&account)?;
        let engine = match Engine::installation(db.as_ref(), transport.as_ref(), &account)
            .await
            .map_err(chat_error)?
        {
            crate::Installation::Registered { device_id } => {
                Engine::open(db, transport, account, device_id).await
            }
            crate::Installation::Registering => {
                Engine::resume_registration(db, transport, account).await
            }
            crate::Installation::Unregistered { .. } => {
                return Err(js_error(DEVICE_NOT_REGISTERED));
            }
        }
        .map_err(chat_error)?;
        Self::finish_open(
            engine,
            &master_key,
            &binding,
            &display_name,
            sealed_sender_enabled,
        )
        .await
    }

    /// Re-register this browser: a new account identity, this device alone
    /// in the account's manifest, every other device of the account dropped.
    /// The account's first Chat device does this; so does "I don't have my
    /// other devices". Contacts see the safety number change once.
    #[wasm_bindgen(js_name = reregister)]
    pub async fn reregister(
        database_name: String,
        account: String,
        display_name: String,
        sealed_sender_enabled: bool,
        master_key: Vec<u8>,
        binding: String,
        transport: JsChatTransport,
    ) -> std::result::Result<WasmChatClient, JsValue> {
        let master_key = master_key_bytes(master_key)?;
        let authority = AccountAuthority::derive(&master_key).map_err(chat_error)?;
        let db = Rc::new(
            IndexedDbChatDb::open(&database_name, &master_key)
                .await
                .map_err(chat_error)?,
        );
        let transport: Rc<dyn ChatTransport> = Rc::new(BrowserTransport { js: transport });
        let account = canonical_account(&account)?;
        let mut rng = OsRng.unwrap_err();
        let engine = Engine::reregister(
            db,
            transport,
            account,
            &authority,
            now_rfc3339(),
            50,
            &mut rng,
        )
        .await
        .map_err(chat_error)?;
        Self::finish_open(
            engine,
            &master_key,
            &binding,
            &display_name,
            sealed_sender_enabled,
        )
        .await
    }

    /// What every way of opening ends with: the account's lists and keys,
    /// sealed sender, this device in the account's manifest, the profile.
    async fn finish_open(
        mut engine: Engine,
        master_key: &[u8; 32],
        binding: &str,
        display_name: &str,
        sealed_sender_enabled: bool,
    ) -> std::result::Result<WasmChatClient, JsValue> {
        let authority = AccountAuthority::derive(master_key).map_err(chat_error)?;
        let profile_wrapping_key =
            crate::profile::derive_wrapping_key(master_key, binding).map_err(chat_error)?;
        let mut rng = OsRng.unwrap_err();
        // One identity for every app of the account (docs/plans/drive-identity-pins.md).
        engine
            .enable_identity_pins(master_key, binding)
            .map_err(chat_error)?;
        engine
            .enable_group_list(master_key, binding)
            .map_err(chat_error)?;
        // The web writes a block at once (docs/plans/chat-contacts-sync.md).
        engine
            .enable_contact_list(
                master_key,
                binding,
                crate::contact_list::ContactListTiming {
                    block: crate::contact_list::BlockTiming::Immediate,
                },
            )
            .map_err(chat_error)?;
        engine.set_sealed_sender_enabled(sealed_sender_enabled);
        // The account's identity: a kept sync from a run that stopped before
        // applying it, one that waits in the mailbox, or none (this device
        // missed it and is linked again).
        engine
            .catch_up_identity(&mut rng)
            .await
            .map_err(chat_error)?;
        engine
            .sync_own_manifest(&authority, now_rfc3339())
            .await
            .map_err(chat_error)?;
        engine
            .initialize_profile(&profile_wrapping_key, display_name, &mut rng)
            .await
            .map_err(chat_error)?;
        Ok(Self {
            engine,
            authority,
            profile_wrapping_key,
            search_cache: Default::default(),
        })
    }

    /// Link a new device of this account (Settings → Linked devices): `code`
    /// is the `kutup://link?…` code it shows, scanned or pasted. Sends it the
    /// account identity and the account's read-receipt and typing settings.
    /// `false`: the code has expired; the new device shows a new one.
    #[wasm_bindgen(js_name = linkDevice)]
    pub async fn link_device(
        &mut self,
        code: String,
        read_receipts: bool,
        typing_indicators: bool,
    ) -> std::result::Result<bool, JsValue> {
        self.engine
            .link_device(
                &code,
                crate::ProvisionedSettings {
                    read_receipts,
                    typing_indicators,
                },
                &self.authority,
            )
            .await
            .map_err(chat_error)
    }

    /// Reset the account's identity, keeping its devices but those in
    /// `remove` (a lost or stolen one), which leave the account. Contacts see
    /// the safety number change once. Returns the devices kept.
    #[wasm_bindgen(js_name = resetIdentity)]
    pub async fn reset_identity(
        &mut self,
        remove: Vec<u32>,
    ) -> std::result::Result<Vec<u32>, JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .reset_identity(&remove, now_rfc3339(), &mut rng)
            .await
            .map_err(chat_error)
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

    /// What a group link (its URL fragment) leads to, read before joining.
    #[wasm_bindgen(js_name = previewGroupLink)]
    pub async fn preview_group_link(
        &mut self,
        fragment: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let preview = self
            .engine
            .preview_group_link(&fragment)
            .await
            .map_err(chat_error)?;
        to_output(&match preview {
            Ok(Some(preview)) => GroupLinkPreviewView::Group {
                group_id: preview.group_id,
                title: preview.title,
                description: preview.description,
                member_count: preview.member_count,
                requires_approval: preview.requires_approval,
                status: preview.status.as_ref().map(status_name),
                avatar: preview.avatar.map(GroupAvatarWasmView::from),
            },
            Ok(None) => GroupLinkPreviewView::Invalid,
            Err(failure) => GroupLinkPreviewView::Unreachable {
                reason: route_reason(failure),
            },
        })
    }

    /// Joins through a link, or asks to when an administrator approves.
    #[wasm_bindgen(js_name = joinGroupByLink)]
    pub async fn join_group_by_link(
        &mut self,
        fragment: String,
    ) -> std::result::Result<JsValue, JsValue> {
        use crate::group_link::GroupLinkJoin;
        let mut rng = OsRng.unwrap_err();
        let joined = self
            .engine
            .join_group_by_link(&fragment, &mut rng)
            .await
            .map_err(chat_error)?;
        to_output(&match joined {
            GroupLinkJoin::Joined(sync) => GroupLinkJoinView::Joined { sync: sync.into() },
            GroupLinkJoin::Requested => GroupLinkJoinView::Requested,
            GroupLinkJoin::LinkInvalid => GroupLinkJoinView::Invalid,
            GroupLinkJoin::Unreachable(failure) => GroupLinkJoinView::Unreachable {
                reason: route_reason(failure),
            },
        })
    }

    /// Where this account's request to join stands, settled here.
    #[wasm_bindgen(js_name = checkGroupRequest)]
    pub async fn check_group_request(
        &mut self,
        group_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let outcome = self
            .engine
            .check_group_request(&group_id)
            .await
            .map_err(chat_error)?;
        to_output(&GroupRequestView::from(outcome))
    }

    /// Withdraws this account's request to join.
    #[wasm_bindgen(js_name = cancelGroupRequest)]
    pub async fn cancel_group_request(
        &mut self,
        group_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let outcome = self
            .engine
            .cancel_group_request(&group_id)
            .await
            .map_err(chat_error)?;
        to_output(&GroupRequestView::from(outcome))
    }

    /// The group's settings, requests and bans, from its verified state.
    #[wasm_bindgen(js_name = groupDetails)]
    pub async fn group_details(
        &mut self,
        group_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let details = self
            .engine
            .group_details(&group_id)
            .await
            .map_err(chat_error)?;
        to_output(&GroupDetailsView::from(details))
    }

    /// The link: `off`, `join` (anyone with it joins) or `approve`.
    #[wasm_bindgen(js_name = setGroupLink)]
    pub async fn set_group_link(
        &mut self,
        group_id: String,
        mode: String,
    ) -> std::result::Result<(), JsValue> {
        let mode = link_mode(&mode)?;
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_link(&group_id, mode, &mut rng)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = resetGroupLink)]
    pub async fn reset_group_link(&mut self, group_id: String) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .reset_group_link(&group_id, &mut rng)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = setGroupDescription)]
    pub async fn set_group_description(
        &mut self,
        group_id: String,
        description: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_description(&group_id, &description, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// The disappearing-messages timer in seconds; 0 turns it off.
    #[wasm_bindgen(js_name = setGroupTimer)]
    pub async fn set_group_timer(
        &mut self,
        group_id: String,
        seconds: u32,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_timer(&group_id, seconds, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Who may edit the details (`attributes`) and add members (`members`):
    /// `member` or `administrator`.
    #[wasm_bindgen(js_name = setGroupAccess)]
    pub async fn set_group_access(
        &mut self,
        group_id: String,
        attributes: String,
        members: String,
    ) -> std::result::Result<(), JsValue> {
        let (attributes, members) = (access_required(&attributes)?, access_required(&members)?);
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_access(&group_id, attributes, members, &mut rng)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = setGroupAnnouncementsOnly)]
    pub async fn set_group_announcements_only(
        &mut self,
        group_id: String,
        on: bool,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_announcements_only(&group_id, on, &mut rng)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = approveGroupRequest)]
    pub async fn approve_group_request(
        &mut self,
        group_id: String,
        pseudonym: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .approve_group_request(&group_id, &pseudonym, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Turns a request down; it is banned from the link, as Signal does.
    #[wasm_bindgen(js_name = denyGroupRequest)]
    pub async fn deny_group_request(
        &mut self,
        group_id: String,
        pseudonym: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .deny_group_request(&group_id, &pseudonym, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Removes and bans a member; `resetLink` changes the link too.
    #[wasm_bindgen(js_name = banGroupMember)]
    pub async fn ban_group_member(
        &mut self,
        group_id: String,
        pseudonym: String,
        reset_link: bool,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .ban_group_member(&group_id, &pseudonym, reset_link, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Lifts a ban, as `groupDetails` lists it.
    #[wasm_bindgen(js_name = unbanGroup)]
    pub async fn unban_group(
        &mut self,
        group_id: String,
        ban: JsValue,
    ) -> std::result::Result<(), JsValue> {
        let ban: GroupBanWasmView = from_transport(ban).map_err(chat_error)?;
        let ban = crate::group_settings::GroupBanView {
            account: ban
                .account
                .as_deref()
                .map(crate::address::parse_account)
                .transpose()
                .map_err(chat_error)?,
            pseudonyms: ban.pseudonyms,
        };
        let mut rng = OsRng.unwrap_err();
        self.engine
            .unban_group(&group_id, &ban, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Sets the group's avatar: `image` already scaled down (JPEG, PNG or
    /// WebP, under 40 KiB).
    #[wasm_bindgen(js_name = setGroupAvatar)]
    pub async fn set_group_avatar(
        &mut self,
        group_id: String,
        image: Vec<u8>,
        content_type: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .set_group_avatar(&group_id, &image, &content_type, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// The group's picture, checked against the hash its state names.
    #[wasm_bindgen(js_name = groupAvatar)]
    pub async fn group_avatar(
        &mut self,
        group_id: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let fetched = self
            .engine
            .group_avatar(&group_id)
            .await
            .map_err(chat_error)?;
        to_output(&match fetched {
            Ok(Some(image)) => GroupAvatarFetchView::Image {
                data: STANDARD.encode(&image.data),
                content_type: image.content_type,
            },
            Ok(None) => GroupAvatarFetchView::None,
            Err(failure) => GroupAvatarFetchView::Unreachable {
                reason: route_reason(failure),
            },
        })
    }

    #[wasm_bindgen(js_name = removeGroupAvatar)]
    pub async fn remove_group_avatar(
        &mut self,
        group_id: String,
    ) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .remove_group_avatar(&group_id, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Ends the group for everyone.
    #[wasm_bindgen(js_name = endGroup)]
    pub async fn end_group(&mut self, group_id: String) -> std::result::Result<(), JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .end_group(&group_id, &mut rng)
            .await
            .map_err(chat_error)
    }

    /// Removes every unverified or banned member: how many.
    #[wasm_bindgen(js_name = removeUnverifiedGroupMembers)]
    pub async fn remove_unverified_group_members(
        &mut self,
        group_id: String,
    ) -> std::result::Result<u32, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let removed = self
            .engine
            .remove_unverified_group_members(&group_id, &mut rng)
            .await
            .map_err(chat_error)?;
        Ok(u32::try_from(removed).unwrap_or(u32::MAX))
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
        let expiry_starts = self
            .engine
            .session()
            .disappearing_expiry_starts()
            .await
            .map_err(chat_error)?;
        let me = self.engine.session().user().to_owned();
        let mut history = Vec::with_capacity(incoming.len() + outgoing.len());
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
                .timeline_entries(&directory, key, &refs)
                .await
                .map_err(chat_error)?;
            let timer = match &header.timer {
                Some(timer) if !refs.contains(timer) => self
                    .timeline_entries(&directory, key, std::slice::from_ref(timer))
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
            .timeline_entries(&directory, &key, &refs)
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
            .timeline_entries(&directory, &key, &refs)
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
        let safety_number = self.engine.safety_number(&peer).await.map_err(chat_error)?;
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
            .verify_safety_number(&peer, &scanned_payload)
            .await
            .map_err(chat_error)?;
        to_output(&safety_number)
    }

    /// Mark the contact's identity verified (or clear it) by hand, after
    /// comparing the numbers. `identity_key` is the `identityKey` of the
    /// safety number the person compared.
    #[wasm_bindgen(js_name = setIdentityVerified)]
    pub async fn set_identity_verified(
        &mut self,
        peer: String,
        identity_key: String,
        verified: bool,
    ) -> std::result::Result<JsValue, JsValue> {
        let safety_number = self
            .engine
            .set_identity_verified(&peer, &identity_key, verified)
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

/// A request body for the browser transport, which sends it as JSON: maps as
/// plain objects (a JS `Map` would encode as `{}`).
fn to_transport<T: Serialize + ?Sized>(value: &T) -> Result<JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .map_err(|error| ChatError::Transport(format!("encode transport request: {error}")))
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
    match error {
        // The web links it again (`ChatServiceError('linkRequired')`).
        ChatError::LinkRequired => js_error(DEVICE_NOT_REGISTERED),
        error => js_error(&error.to_string()),
    }
}

/// The error a browser without a device of the account opens with.
const DEVICE_NOT_REGISTERED: &str = "chatDeviceNotRegistered";

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

fn master_key_bytes(master_key: Vec<u8>) -> std::result::Result<[u8; 32], JsValue> {
    master_key
        .try_into()
        .map_err(|_| js_error("chat account authority requires a 32-byte master key"))
}

/// The device's account, for good: its string form.
fn canonical_account(account: &str) -> std::result::Result<String, JsValue> {
    Ok(crate::address::parse_account(account)
        .map_err(chat_error)?
        .to_string())
}

/// The new device's side of linking (docs/plans/account-identity-key.md):
/// make one, show `linkCode(address)` once the provisioning socket gave its
/// address, and hand the envelope the socket delivers to `completeLink`.
#[wasm_bindgen]
pub struct WasmLinkingDevice {
    inner: crate::LinkingDevice,
    settings: Option<crate::ProvisionedSettings>,
}

impl Default for WasmLinkingDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmLinkingDevice {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: crate::LinkingDevice::new(),
            settings: None,
        }
    }

    /// `kutup://link?address=…&key=…`, for the QR code and to copy.
    #[wasm_bindgen(js_name = linkCode)]
    pub fn link_code(&self, address: String) -> std::result::Result<String, JsValue> {
        self.inner.link_code(&address).map_err(chat_error)
    }

    /// Check the provisioning envelope, register this browser with the
    /// identity it carries, and open it (as `WasmChatClient.open` does). The
    /// account's read-receipt and typing settings are then `readReceipts` and
    /// `typingIndicators`.
    #[wasm_bindgen(js_name = completeLink)]
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_link(
        &mut self,
        envelope: JsValue,
        database_name: String,
        account: String,
        display_name: String,
        sealed_sender_enabled: bool,
        master_key: Vec<u8>,
        binding: String,
        transport: JsChatTransport,
    ) -> std::result::Result<WasmChatClient, JsValue> {
        let envelope: kutup_chat_proto::ProvisionEnvelopeV1 =
            from_transport(envelope).map_err(chat_error)?;
        let master_key = master_key_bytes(master_key)?;
        let authority = AccountAuthority::derive(&master_key).map_err(chat_error)?;
        let db = Rc::new(
            IndexedDbChatDb::open(&database_name, &master_key)
                .await
                .map_err(chat_error)?,
        );
        let transport: Rc<dyn ChatTransport> = Rc::new(BrowserTransport { js: transport });
        let account = canonical_account(&account)?;
        let provision = self
            .inner
            .verify(transport.as_ref(), &account, &authority, &envelope)
            .await
            .map_err(chat_error)?;
        self.settings = Some(provision.settings);
        let mut rng = OsRng.unwrap_err();
        let engine = Engine::register_linked(db, transport, account, provision, 50, &mut rng)
            .await
            .map_err(chat_error)?;
        WasmChatClient::finish_open(
            engine,
            &master_key,
            &binding,
            &display_name,
            sealed_sender_enabled,
        )
        .await
    }

    #[wasm_bindgen(getter, js_name = readReceipts)]
    pub fn read_receipts(&self) -> Option<bool> {
        self.settings.map(|settings| settings.read_receipts)
    }

    #[wasm_bindgen(getter, js_name = typingIndicators)]
    pub fn typing_indicators(&self) -> Option<bool> {
        self.settings.map(|settings| settings.typing_indicators)
    }
}
