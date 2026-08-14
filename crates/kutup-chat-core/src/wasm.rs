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
    AccountAddress, AccountAuthority, AnonymousMlsRecipientDevice, ChatAttachmentDescriptorV1,
    ChatContent, ChatError, ChatTransport, ConversationId, Engine, InboundEnvelope,
    IndexedDbChatDb, MlsApplicationEnvelopeContext, MlsClient, MlsControlEnvelopeContext,
    ReceiveReport, Result, SendOutcome, VerifiedMlsCredential, VerifiedMlsKeyPackage,
};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_TYPES: &str = r#"
export interface KutupChatTransport {
  registerDevice(request: unknown): Promise<unknown>;
  fetchBundles(username: string): Promise<unknown>;
  fetchSyncBundles(username: string, currentDeviceId: number): Promise<unknown>;
  fetchMlsOrderingPolicy(domain: string): Promise<unknown>;
  fetchManifest(username: string): Promise<unknown | null>;
  fetchManifestHistory(username: string, fromSequence: string, toSequence: string, pageFromSequence: string): Promise<unknown>;
  fetchAnonymousMlsKeyPackages(request: unknown): Promise<unknown>;
  fetchIdentifiedMlsKeyPackages(request: unknown): Promise<unknown>;
  fetchSealedSenderPolicy(domain: string): Promise<unknown>;
  fetchSenderCertificate(deviceId: number): Promise<unknown>;
  fetchSealedBundles(username: string, capability: string): Promise<unknown>;
  publishManifest(manifest: unknown): Promise<unknown>;
  fetchOwnProfile(): Promise<unknown | null>;
  publishProfile(profile: unknown): Promise<unknown>;
  fetchProfile(username: string, version: string, accessKey: string): Promise<unknown | null>;
  prekeyCount(deviceId: number): Promise<unknown>;
  replenishPrekeys(deviceId: number, request: unknown): Promise<void>;
  sendMessage(username: string, request: unknown): Promise<
    | { kind: "delivered"; deduplicated?: boolean }
    | { kind: "mismatch"; mismatch: unknown }
  >;
  sendSealedMessage(username: string, request: unknown): Promise<
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
  messageId?: string;
  replyTo?: string;
  body: unknown;
  text?: string;
  attachment?: unknown;
  reaction?: unknown;
  mutation?: unknown;
  receipt?: unknown;
  typing?: unknown;
  disappearingTimer?: unknown;
  expiresAfterSeconds?: number;
  expiresAtMs?: number;
}

export interface KutupChatAccountAddress {
  username: string;
  server?: string;
}

export type KutupChatConversationId =
  | { kind: "direct"; address: KutupChatAccountAddress }
  | { kind: "group"; groupId: string };

export interface KutupChatHistoryEntry {
  id: string;
  conversation: KutupChatConversationId;
  /** @deprecated Use conversation. Retained while existing web/native callers migrate. */
  peer: string;
  direction: "incoming" | "outgoing";
  senderDeviceId?: number;
  cursor?: string;
  timestampMs: number;
  delivered: boolean;
  deduplicated: boolean;
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
        username: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchSyncBundles)]
    async fn js_fetch_sync_bundles(
        this: &JsChatTransport,
        username: &str,
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
        username: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchManifestHistory)]
    async fn js_fetch_manifest_history(
        this: &JsChatTransport,
        username: &str,
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
        username: &str,
        capability: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = publishManifest)]
    async fn js_publish_manifest(
        this: &JsChatTransport,
        manifest: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchOwnProfile)]
    async fn js_fetch_own_profile(this: &JsChatTransport) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = publishProfile)]
    async fn js_publish_profile(
        this: &JsChatTransport,
        profile: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchProfile)]
    async fn js_fetch_profile(
        this: &JsChatTransport,
        username: &str,
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
        username: &str,
        request: JsValue,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = sendSealedMessage)]
    async fn js_send_sealed_message(
        this: &JsChatTransport,
        username: &str,
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
}

#[async_trait(?Send)]
impl ChatTransport for BrowserTransport {
    async fn register_device(&self, req: &RegisterChatDeviceRequest) -> Result<u32> {
        let response: RegisterChatDeviceResponse = from_transport(
            self.js
                .js_register_device(to_transport(req)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(response.device_id)
    }

    async fn fetch_bundles(&self, username: &str) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_bundles(username)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_sync_bundles(
        &self,
        username: &str,
        current_device_id: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sync_bundles(username, current_device_id)
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

    async fn fetch_manifest(&self, username: &str) -> Result<Option<AccountManifestV1>> {
        from_transport(
            self.js
                .js_fetch_manifest(username)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_manifest_history(
        &self,
        username: &str,
        from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        from_transport(
            self.js
                .js_fetch_manifest_history(
                    username,
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
        username: &str,
        capability: &[u8; 16],
    ) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sealed_bundles(username, &STANDARD.encode(capability))
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
        username: &str,
        version: &str,
        access_key: &[u8],
    ) -> Result<Option<ChatProfileResponse>> {
        from_transport(
            self.js
                .js_fetch_profile(username, version, &STANDARD.encode(access_key))
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

    async fn send(&self, username: &str, req: &SendMessagesRequest) -> Result<SendOutcome> {
        let outcome: BrowserSendOutcome = from_transport(
            self.js
                .js_send_message(username, to_transport(req)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserSendOutcome::Delivered { deduplicated } => {
                SendOutcome::Delivered { deduplicated }
            }
            BrowserSendOutcome::Mismatch { mismatch } => SendOutcome::Mismatch(mismatch),
        })
    }

    async fn send_sealed(
        &self,
        username: &str,
        request: &kutup_chat_proto::SealedMessageSubmissionV1,
    ) -> Result<SendOutcome> {
        let outcome: BrowserSendOutcome = from_transport(
            self.js
                .js_send_sealed_message(username, to_transport(request)?)
                .await
                .map_err(transport_error)?,
        )?;
        Ok(match outcome {
            BrowserSendOutcome::Delivered { deduplicated } => {
                SendOutcome::Delivered { deduplicated }
            }
            BrowserSendOutcome::Mismatch { mismatch } => SendOutcome::Mismatch(mismatch),
        })
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
}

#[wasm_bindgen]
impl WasmChatClient {
    /// Open or restart-safely register the local device, then publish its
    /// account-signed manifest. The database name must be account scoped.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(
        database_name: String,
        user: String,
        server_name: String,
        sealed_sender_enabled: bool,
        master_key: Vec<u8>,
        transport: JsChatTransport,
    ) -> std::result::Result<WasmChatClient, JsValue> {
        let master_key: [u8; 32] = master_key
            .try_into()
            .map_err(|_| js_error("chat account authority requires a 32-byte master key"))?;
        let authority = AccountAuthority::derive(&master_key).map_err(chat_error)?;
        let profile_wrapping_key =
            crate::profile::derive_wrapping_key(&master_key).map_err(chat_error)?;
        let db = Rc::new(
            IndexedDbChatDb::open(&database_name)
                .await
                .map_err(chat_error)?,
        );
        let transport: Rc<dyn ChatTransport> = Rc::new(BrowserTransport { js: transport });
        let mut rng = OsRng.unwrap_err();
        let mut engine = Engine::register(db, transport, user.clone(), 50, &mut rng)
            .await
            .map_err(chat_error)?;
        engine.set_local_server(&server_name).map_err(chat_error)?;
        engine.set_sealed_sender_enabled(sealed_sender_enabled);
        engine
            .sync_own_manifest(&authority, now_rfc3339())
            .await
            .map_err(chat_error)?;
        engine
            .initialize_profile(&profile_wrapping_key, &user, &mut rng)
            .await
            .map_err(chat_error)?;
        Ok(Self {
            engine,
            authority,
            profile_wrapping_key,
        })
    }

    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> u32 {
        self.engine.session().device_id()
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
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("invalid MLS conversation id"))?;
        let creator: AccountAddress = from_transport(creator).map_err(chat_error)?;
        let authority_policies: Vec<kutup_chat_proto::MlsOrderingServicePolicyV1> =
            from_transport(authority_policies).map_err(chat_error)?;
        let prepared = self
            .mls_client()
            .prepare_group_genesis(
                conversation_id,
                &mls_group_id,
                creator,
                &authority_policies,
                parse_i64_string("MLS genesis clock", &created_at_seconds)?,
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
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
    ) -> std::result::Result<JsValue, JsValue> {
        let conversation_id = uuid::Uuid::parse_str(&conversation_id)
            .map_err(|_| js_error("MLS conversation id must be a UUID"))?;
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
                parse_i64_string("MLS message clock", &created_at_ms)?,
            )
            .await
            .map_err(chat_error)?;
        to_output(&entry)
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
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
        let recipient: AccountAddress = from_transport(recipient).map_err(chat_error)?;
        let send_id = uuid::Uuid::parse_str(&send_id)
            .map_err(|_| js_error("anonymous MLS send id must be a UUID"))?;
        let envelope: AnonymousMlsDeviceEnvelopeV1 =
            from_transport(envelope).map_err(chat_error)?;
        self.mls_client()
            .open_anonymous_envelope(&recipient, send_id, &envelope)
            .await
            .map_err(chat_error)
    }

    #[wasm_bindgen(js_name = sendText)]
    pub async fn send_text(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        text: String,
        reply_to: Option<String>,
        expires_after_seconds: Option<u32>,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let mut content = ChatContent::text_with_id(&send_id, sent_at, seq, text)
            .with_reply_to(reply_to.as_deref())
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
    ) -> std::result::Result<JsValue, JsValue> {
        let descriptor: ChatAttachmentDescriptorV1 =
            from_transport(descriptor).map_err(chat_error)?;
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let mut content = ChatContent::attachment_with_id(&send_id, sent_at, seq, descriptor)
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
        self.engine
            .flush_outbox_deferring_optional_failures(&mut rng)
            .await
            .map_err(chat_error)?;
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
        let mut report = self.engine.receive(&mut rng).await.map_err(chat_error)?;
        // A reply can promote pending-outgoing to accepted (or a new message
        // can supersede a prior rejection). Publish that newer revision after
        // the decrypt commit so delayed older controls cannot win elsewhere.
        let _ = self
            .engine
            .flush_contact_syncs(&now_rfc3339(), &mut rng)
            .await;
        report.profiles_refreshed = self.engine.refresh_profiles().await.unwrap_or_default();
        to_output(&ReceiveReportView::from(report))
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
        let imported = self
            .engine
            .session()
            .imported_history()
            .await
            .map_err(chat_error)?;
        let expiry_starts = self
            .engine
            .session()
            .disappearing_expiry_starts()
            .await
            .map_err(chat_error)?;
        let mut history =
            Vec::with_capacity(incoming.len() + outgoing.len() + mls.len() + imported.len());
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
            let mut entry = HistoryEntry::outgoing(message).map_err(chat_error)?;
            entry.apply_disappearing_deadline(&expiry_starts);
            history.push(entry);
        }
        for message in mls {
            if is_invisible_control(&message.content).map_err(chat_error)? {
                continue;
            }
            let mut entry = HistoryEntry::mls(message).map_err(chat_error)?;
            entry.apply_disappearing_deadline(&expiry_starts);
            history.push(entry);
        }
        for message in imported {
            if is_invisible_control(&message.content).map_err(chat_error)? {
                continue;
            }
            let mut entry = HistoryEntry::imported(message).map_err(chat_error)?;
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

    #[wasm_bindgen(js_name = setProfile)]
    pub async fn set_profile(
        &mut self,
        display_name: String,
        avatar: Option<String>,
        avatar_content_type: Option<String>,
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
    revision: String,
}

impl From<crate::LocalProfile> for ProfileView {
    fn from(profile: crate::LocalProfile) -> Self {
        Self {
            display_name: profile.display_name,
            avatar: profile.avatar.map(|bytes| STANDARD.encode(bytes)),
            avatar_content_type: profile.avatar_content_type,
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
    revision: String,
}

impl PeerProfileView {
    fn from_profile(profile: crate::PeerProfile) -> Option<Self> {
        Some(Self {
            peer: profile.peer,
            display_name: profile.display_name?,
            avatar: profile.avatar.map(|bytes| STANDARD.encode(bytes)),
            avatar_content_type: profile.avatar_content_type,
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
            conversation: message.from.conversation(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
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
    disappearing_timer: Option<kutup_chat_proto::DisappearingTimerBody>,
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
        let disappearing_timer = content.as_disappearing_timer();
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
            disappearing_timer,
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
    /// Compatibility field for the current direct-only web UI release.
    peer: String,
    direction: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_device_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    timestamp_ms: i64,
    delivered: bool,
    deduplicated: bool,
    content: ContentView,
}

impl HistoryEntry {
    fn apply_disappearing_deadline(&mut self, starts: &crate::session::DisappearingExpiryStarts) {
        let Some(seconds) = self.content.expires_after_seconds else {
            return;
        };
        let base_ms = if self.direction == "outgoing" {
            Some(self.timestamp_ms)
        } else {
            self.content.message_id.as_ref().and_then(|message_id| {
                starts
                    .get(&(self.conversation.key(), message_id.clone()))
                    .copied()
            })
        };
        self.content.expires_at_ms =
            base_ms.map(|base_ms| base_ms.saturating_add(i64::from(seconds).saturating_mul(1_000)));
    }

    fn incoming(message: crate::InboxMessage) -> Result<Self> {
        let content = serde_json::from_slice::<ChatContent>(&message.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        let id = content
            .message_id
            .clone()
            .unwrap_or_else(|| message.id.clone());
        let conversation = direct_conversation(&message.peer)?;
        Ok(Self {
            id,
            conversation,
            peer: message.peer,
            direction: "incoming",
            sender_device_id: Some(message.sender_device_id),
            cursor: Some(message.cursor.to_string()),
            timestamp_ms: message.received_at,
            delivered: true,
            deduplicated: false,
            content: content.into(),
        })
    }

    fn outgoing(message: crate::SentMessage) -> Result<Self> {
        let content = serde_json::from_slice::<ChatContent>(&message.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        let conversation = direct_conversation(&message.peer)?;
        Ok(Self {
            id: message.send_id,
            conversation,
            peer: message.peer,
            direction: "outgoing",
            sender_device_id: None,
            cursor: None,
            timestamp_ms: message.created_at,
            delivered: message.delivered,
            deduplicated: message.deduplicated,
            content: content.into(),
        })
    }

    fn mls(message: crate::MlsHistoryMessage) -> Result<Self> {
        let content = serde_json::from_slice::<ChatContent>(&message.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        let group_id = uuid::Uuid::from_bytes(message.conversation_id).to_string();
        Ok(Self {
            id: message.message_id,
            conversation: ConversationId::Group {
                group_id: group_id.clone(),
            },
            peer: if message.outgoing {
                group_id
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
            content: content.into(),
        })
    }

    fn imported(message: crate::ImportedHistoryRecordV1) -> Result<Self> {
        let content = serde_json::from_slice::<ChatContent>(&message.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        let peer = match &message.conversation {
            ConversationId::Direct { address } => address.canonical(),
            ConversationId::Group { group_id } if message.outgoing => group_id.clone(),
            ConversationId::Group { .. } => message.sender.clone(),
        };
        Ok(Self {
            id: format!(
                "imported:{}:{}",
                message.transfer_id, message.source_record_id
            ),
            conversation: message.conversation,
            peer,
            direction: if message.outgoing {
                "outgoing"
            } else {
                "incoming"
            },
            sender_device_id: (!message.outgoing).then_some(message.sender_device_id),
            cursor: None,
            timestamp_ms: message.timestamp_ms,
            delivered: message.delivered,
            deduplicated: false,
            content: content.into(),
        })
    }
}

fn direct_conversation(peer: &str) -> Result<ConversationId> {
    let address = peer
        .parse::<AccountAddress>()
        .map_err(|error| ChatError::Content(format!("invalid direct conversation: {error}")))?;
    Ok(ConversationId::direct(address))
}

fn is_contact_control(bytes: &[u8]) -> Result<bool> {
    let content = serde_json::from_slice::<ChatContent>(bytes)
        .map_err(|error| ChatError::Content(error.to_string()))?;
    Ok(matches!(
        content.kind.as_str(),
        kutup_chat_proto::content::kind::CONTACT_CONTROL
            | kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
            | kutup_chat_proto::content::kind::TYPING
            | kutup_chat_proto::content::kind::DISAPPEARING_EXPIRY_START
    ))
}

fn is_invisible_control(bytes: &[u8]) -> Result<bool> {
    let content = serde_json::from_slice::<ChatContent>(bytes)
        .map_err(|error| ChatError::Content(error.to_string()))?;
    Ok(matches!(
        content.kind.as_str(),
        kutup_chat_proto::content::kind::GROUP_CONTROL
            | kutup_chat_proto::content::kind::CONTACT_CONTROL
            | kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
            | kutup_chat_proto::content::kind::TYPING
            | kutup_chat_proto::content::kind::DISAPPEARING_EXPIRY_START
    ))
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

fn now_rfc3339() -> String {
    js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}
