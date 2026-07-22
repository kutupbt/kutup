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
    ChatProfileResponse, DeviceListMismatch, DeviceManifest, MailboxPage, OwnChatProfileResponse,
    PreKeyCountResponse, PublishManifestResponse, PutChatProfileRequest, RegisterChatDeviceRequest,
    RegisterChatDeviceResponse, ReplenishKeysRequest, SendMessagesRequest,
    TransparencyCheckpointResponse, UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

use crate::{
    AccountAddress, AccountAuthority, ChatContent, ChatError, ChatTransport, ConversationId,
    Engine, InboundEnvelope, IndexedDbChatDb, ManifestTrust, ReceiveReport, Result, SendOutcome,
    TransparencyMonitorState, TransparencyMonitorStatus,
};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_TYPES: &str = r#"
export interface KutupChatTransport {
  registerDevice(request: unknown): Promise<unknown>;
  fetchBundles(username: string, transparencyTreeSize: string): Promise<unknown>;
  fetchSyncBundles(username: string, currentDeviceId: number, transparencyTreeSize: string): Promise<unknown>;
  fetchTransparencyCheckpoint(scope: string, fromTreeSize: string): Promise<unknown>;
  fetchTransparencyPolicy(domain: string): Promise<unknown>;
  fetchManifest(username: string): Promise<unknown | null>;
  fetchManifestRange(username: string, fromVersion: string, toVersion: string, pageFromVersion: string, cursor: string | null, transparencyTreeSize: string): Promise<unknown>;
  fetchSealedSenderPolicy(domain: string): Promise<unknown>;
  fetchSenderCertificate(deviceId: number): Promise<unknown>;
  fetchSealedBundles(username: string, capability: string, transparencyTreeSize: string): Promise<unknown>;
  publishManifest(manifest: unknown, transparencyTreeSize: string): Promise<unknown>;
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
  body: unknown;
  text?: string;
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
        transparency_tree_size: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchSyncBundles)]
    async fn js_fetch_sync_bundles(
        this: &JsChatTransport,
        username: &str,
        current_device_id: u32,
        transparency_tree_size: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchTransparencyCheckpoint)]
    async fn js_fetch_transparency_checkpoint(
        this: &JsChatTransport,
        scope: &str,
        from_tree_size: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchTransparencyPolicy)]
    async fn js_fetch_transparency_policy(
        this: &JsChatTransport,
        domain: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchManifest)]
    async fn js_fetch_manifest(
        this: &JsChatTransport,
        username: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = fetchManifestRange)]
    async fn js_fetch_manifest_range(
        this: &JsChatTransport,
        username: &str,
        from_version: &str,
        to_version: &str,
        page_from_version: &str,
        cursor: JsValue,
        transparency_tree_size: &str,
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
        transparency_tree_size: &str,
    ) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = publishManifest)]
    async fn js_publish_manifest(
        this: &JsChatTransport,
        manifest: JsValue,
        transparency_tree_size: &str,
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

    async fn fetch_bundles(
        &self,
        username: &str,
        transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
        let transparency_tree_size = transparency_tree_size.to_string();
        from_transport(
            self.js
                .js_fetch_bundles(username, &transparency_tree_size)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_sync_bundles(
        &self,
        username: &str,
        current_device_id: u32,
        transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
        let transparency_tree_size = transparency_tree_size.to_string();
        from_transport(
            self.js
                .js_fetch_sync_bundles(username, current_device_id, &transparency_tree_size)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_transparency_checkpoint(
        &self,
        scope: &str,
        from_tree_size: u64,
    ) -> Result<TransparencyCheckpointResponse> {
        let from_tree_size = from_tree_size.to_string();
        from_transport(
            self.js
                .js_fetch_transparency_checkpoint(scope, &from_tree_size)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_transparency_policy(
        &self,
        domain: &str,
    ) -> Result<kutup_federation_proto::FederatedFeaturePolicyHistoryV1> {
        from_transport(
            self.js
                .js_fetch_transparency_policy(domain)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_manifest(&self, username: &str) -> Result<Option<DeviceManifest>> {
        from_transport(
            self.js
                .js_fetch_manifest(username)
                .await
                .map_err(transport_error)?,
        )
    }

    async fn fetch_manifest_range(
        &self,
        username: &str,
        from_version: u64,
        to_version: u64,
        page_from_version: u64,
        cursor: Option<&str>,
        transparency_tree_size: u64,
    ) -> Result<kutup_chat_proto::ManifestUpdateRangeProofV1> {
        from_transport(
            self.js
                .js_fetch_manifest_range(
                    username,
                    &from_version.to_string(),
                    &to_version.to_string(),
                    &page_from_version.to_string(),
                    cursor.map(JsValue::from_str).unwrap_or(JsValue::NULL),
                    &transparency_tree_size.to_string(),
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
        username: &str,
        capability: &[u8; 16],
        transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
        from_transport(
            self.js
                .js_fetch_sealed_bundles(
                    username,
                    &STANDARD.encode(capability),
                    &transparency_tree_size.to_string(),
                )
                .await
                .map_err(transport_error)?,
        )
    }

    async fn publish_manifest(
        &self,
        manifest: &DeviceManifest,
        transparency_tree_size: u64,
    ) -> Result<PublishManifestResponse> {
        let transparency_tree_size = transparency_tree_size.to_string();
        from_transport(
            self.js
                .js_publish_manifest(to_transport(manifest)?, &transparency_tree_size)
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
        transparency_policy: JsValue,
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
            .set_transparency_policy(from_transport(transparency_policy).map_err(chat_error)?)
            .map_err(chat_error)?;
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

    #[wasm_bindgen(js_name = sendText)]
    pub async fn send_text(
        &mut self,
        send_id: String,
        peer: String,
        sent_at: String,
        text: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        let seq = self
            .engine
            .session()
            .next_sent_seq()
            .await
            .map_err(chat_error)?;
        let summary = self
            .engine
            .send(
                &send_id,
                &peer,
                &ChatContent::text_with_id(&send_id, sent_at, seq, text),
                &mut rng,
            )
            .await
            .map_err(chat_error)?;
        to_output(&SendSummaryView::from(summary))
    }

    /// Flush crash-surviving sends, drain/decrypt/ack the mailbox, and return
    /// the new receive report. WebSocket notifications call this same source-
    /// of-truth reconciliation path.
    pub async fn reconcile(&mut self) -> std::result::Result<JsValue, JsValue> {
        let mut rng = OsRng.unwrap_err();
        self.engine
            .flush_outbox(&mut rng)
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

    #[wasm_bindgen(js_name = monitorTransparency)]
    pub async fn monitor_transparency(
        &mut self,
        scope: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let status = self
            .engine
            .monitor_transparency(&scope)
            .await
            .map_err(chat_error)?;
        to_output(&TransparencyMonitorStatusView::from(status))
    }

    #[wasm_bindgen(js_name = transparencyMonitorStatus)]
    pub async fn transparency_monitor_status(
        &self,
        scope: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let status = self
            .engine
            .transparency_monitor_status(&scope)
            .await
            .map_err(chat_error)?;
        match status {
            Some(status) => to_output(&TransparencyMonitorStatusView::from(status)),
            None => Ok(JsValue::UNDEFINED),
        }
    }

    pub async fn history(&self) -> std::result::Result<JsValue, JsValue> {
        let incoming = self.engine.session().history().await.map_err(chat_error)?;
        let outgoing = self
            .engine
            .session()
            .sent_history()
            .await
            .map_err(chat_error)?;
        let mut history = Vec::with_capacity(incoming.len() + outgoing.len());
        for message in incoming {
            if is_contact_control(&message.content).map_err(chat_error)? {
                continue;
            }
            history.push(HistoryEntry::incoming(message).map_err(chat_error)?);
        }
        for message in outgoing {
            if is_contact_control(&message.content).map_err(chat_error)? {
                continue;
            }
            history.push(HistoryEntry::outgoing(message).map_err(chat_error)?);
        }
        history.sort_by(|left, right| {
            left.timestamp_ms
                .cmp(&right.timestamp_ms)
                .then_with(|| left.id.cmp(&right.id))
        });
        to_output(&history)
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

    #[wasm_bindgen(js_name = verifyAuthority)]
    pub async fn verify_authority(
        &mut self,
        peer: String,
    ) -> std::result::Result<JsValue, JsValue> {
        let trust = self
            .engine
            .mark_authority_verified(&peer)
            .await
            .map_err(chat_error)?;
        to_output(&ManifestTrustView::from(trust))
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransparencyMonitorStatusView {
    scope: String,
    state: TransparencyMonitorState,
    last_checked_at_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_success_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tree_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl From<TransparencyMonitorStatus> for TransparencyMonitorStatusView {
    fn from(status: TransparencyMonitorStatus) -> Self {
        Self {
            scope: status.scope,
            state: status.state,
            last_checked_at_ms: status.last_checked_at_ms,
            last_success_at_ms: status.last_success_at_ms,
            tree_size: status.tree_size.map(|value| value.to_string()),
            detail: status.detail,
        }
    }
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
    body: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

impl From<ChatContent> for ContentView {
    fn from(content: ChatContent) -> Self {
        let text = content.as_text().map(|body| body.text);
        Self {
            version: content.v,
            kind: content.kind,
            sent_at: content.sent_at,
            seq: content.seq.to_string(),
            message_id: content.message_id,
            body: content.body,
            text,
        }
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestTrustView {
    peer: String,
    authority_key_id: String,
    self_authority_key: String,
    highest_version: String,
    manifest_hash: String,
    trust: String,
    transparency_position: Option<String>,
    continuity_gap: bool,
}

impl From<ManifestTrust> for ManifestTrustView {
    fn from(trust: ManifestTrust) -> Self {
        Self {
            peer: trust.peer,
            authority_key_id: trust.authority_key_id,
            self_authority_key: trust.self_authority_key,
            highest_version: trust.highest_version.to_string(),
            manifest_hash: trust.manifest_hash,
            trust: format!("{:?}", trust.trust),
            transparency_position: trust.transparency_position.map(|value| value.to_string()),
            continuity_gap: trust.continuity_gap,
        }
    }
}

fn to_transport<T: Serialize + ?Sized>(value: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|error| ChatError::Transport(format!("encode transport request: {error}")))
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
