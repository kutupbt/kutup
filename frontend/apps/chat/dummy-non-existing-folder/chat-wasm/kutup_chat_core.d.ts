/* tslint:disable */
/* eslint-disable */

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
    conversationState?: unknown;
    readPosition?: unknown;
    deleteForMe?: unknown;
    viewOnceOpened?: unknown;
    stickerSaved?: unknown;
    stickerRemoved?: unknown;
    sticker?: unknown;
    groupUpdate?: unknown;
    poll?: unknown;
    pollVote?: unknown;
    pollTerminate?: unknown;
    mentions?: unknown;
    linkPreview?: unknown;
    forwarded?: boolean;
    viewOnce?: boolean;
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



/**
 * Browser-owned handle to one durable chat engine.
 */
export class WasmChatClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    acceptContact(peer: string): Promise<any>;
    applyAnonymousMlsApplicationEnvelope(envelope_id: string, cursor: string, send_id: string, server_timestamp: string, recipient: any, envelope: any, expected_sender: any): Promise<any>;
    applyOrderedInboundMlsMembershipCommit(envelope_id: string, cursor: string, send_id: string, mls_group_id: Uint8Array, commit: Uint8Array, expected_members: any, control_history_page: Uint8Array): Promise<any>;
    approveMlsOwnerApprovalRequest(mls_group_id: Uint8Array, approved_at_seconds: string): Promise<any>;
    blockContact(peer: string): Promise<any>;
    buildMlsAuthorityCommitRequest(mls_group_id: Uint8Array, new_set_certificate: any): Promise<any>;
    buildMlsCloseCommitRequest(mls_group_id: Uint8Array, quorum_certificate: any): Promise<any>;
    buildMlsMembershipCommitRequest(mls_group_id: Uint8Array, quorum_certificate: any): Promise<any>;
    buildMlsOwnerCommitRequest(mls_group_id: Uint8Array, quorum_certificate: any): Promise<any>;
    buildMlsPolicyCommitRequest(mls_group_id: Uint8Array, quorum_certificate: any): Promise<any>;
    contacts(): Promise<any>;
    createAnonymousMlsSubmission(recipient: any, send_id: string, capability: Uint8Array, devices: any, mls_ciphertext: Uint8Array): Promise<any>;
    createMlsApplicationMessage(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, plaintext: Uint8Array, created_at_ms: string): Promise<any>;
    createMlsAttachmentMessage(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, descriptor: any, created_at_ms: string, expires_after_seconds: number | null | undefined, extras: any): Promise<any>;
    createMlsDisappearingTimer(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, created_at_ms: string, duration_seconds?: number | null): Promise<any>;
    createMlsInvitationAcceptanceMessage(mls_group_id: Uint8Array, invited_epoch: string, accepted_at_seconds: string): Promise<any>;
    createMlsMessageMutation(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, target_message_id: string, operation: string, replacement_text: string | null | undefined, created_at_ms: string): Promise<any>;
    createMlsOwnerApprovalRequestMessage(mls_group_id: Uint8Array): Promise<any>;
    createMlsOwnerCandidateMessage(mls_group_id: Uint8Array, now_seconds: string): Promise<any>;
    /**
     * A poll, a vote in one, or its end, in a group.
     */
    createMlsPollContent(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, kind: string, body: any, created_at_ms: string, expires_after_seconds?: number | null): Promise<any>;
    createMlsReactionMessage(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, target_message_id: string, emoji: string, active: boolean, created_at_ms: string): Promise<any>;
    createMlsReceiptMessage(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, message_ids: string[], state: string, created_at_ms: string): Promise<any>;
    createMlsTextMessage(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, text: string, created_at_ms: string, reply_to: string | null | undefined, expires_after_seconds: number | null | undefined, extras: any): Promise<any>;
    createMlsTypingMessage(send_id: string, conversation_id: string, incarnation: string, mls_group_id: Uint8Array, sent_at: string, active: boolean, created_at_ms: string): Promise<any>;
    decryptMlsApplicationMessage(mls_group_id: Uint8Array, ciphertext: Uint8Array, expected_sender: any): Promise<any>;
    deriveMlsDeliveryCapability(mls_group_id: Uint8Array, conversation_id: string, incarnation: string, recipient: any): Promise<any>;
    ensureMlsOwnerCandidate(mls_group_id: Uint8Array, now_seconds: string): Promise<any>;
    fetchVerifiedIdentifiedMlsKeyPackages(recipient: any, conversation_id: string, incarnation: string, now_seconds: string): Promise<any>;
    fetchVerifiedMlsKeyPackages(recipient: any, capability: Uint8Array, now_seconds: string): Promise<any>;
    fetchVerifiedMlsOrderingPolicy(domain: string): Promise<any>;
    fetchVerifiedMlsOrderingPolicyDetails(domain: string): Promise<any>;
    finalizeMlsAuthorityChange(mls_group_id: Uint8Array, acknowledgement: any): Promise<any>;
    finalizeMlsClose(mls_group_id: Uint8Array, acknowledgement: any): Promise<any>;
    finalizeMlsGroupRecovery(mls_group_id: Uint8Array, acknowledgement: any): Promise<any>;
    finalizeMlsMembershipChange(mls_group_id: Uint8Array, acknowledgement: any): Promise<any>;
    finalizeMlsOwnerChange(mls_group_id: Uint8Array, acknowledgement: any): Promise<any>;
    finalizeMlsPolicyChange(mls_group_id: Uint8Array, acknowledgement: any): Promise<any>;
    generateMlsKeyPackage(manifest_version: string, now_seconds: string, expires_at_seconds: string): Promise<any>;
    history(): Promise<any>;
    inboundAttention(): Promise<any>;
    inspectAnonymousMlsApplicationEnvelope(recipient: any, send_id: string, envelope: any): Promise<any>;
    inspectInboundMlsCommit(mls_group_id: Uint8Array, commit: Uint8Array): Promise<any>;
    inspectMlsWelcome(mls_group_id: Uint8Array, welcome: Uint8Array): Promise<any>;
    joinMlsFromRecoveryWelcome(envelope_id: string, cursor: string, send_id: string, mls_group_id: Uint8Array, welcome: Uint8Array, expected_members: any, recovery: any): Promise<any>;
    joinMlsFromWelcomeWithControlHistory(envelope_id: string, cursor: string, send_id: string, mls_group_id: Uint8Array, welcome: Uint8Array, expected_members: any, history_pages: any): Promise<any>;
    localMlsConversations(): Promise<any>;
    localMlsIncarnationHistory(): Promise<any>;
    maintainPrekeys(): Promise<any>;
    markMlsApplicationDelivered(send_id: string): Promise<void>;
    markMlsApplicationRecipientDelivered(send_id: string, recipient: string, deduplicated: boolean): Promise<any>;
    markMlsGroupGenesisPublished(conversation_id: string, genesis_hash: string): Promise<any>;
    mediaDeliveryCapability(peer: string): Promise<string>;
    mergePendingMlsCommit(mls_group_id: Uint8Array, commit_hash: string): Promise<any>;
    mlsCloseHasOwnerQuorum(mls_group_id: Uint8Array): Promise<boolean>;
    mlsGroupControlCredential(mls_group_id: Uint8Array): Promise<any>;
    mlsGroupDevices(mls_group_id: Uint8Array): Promise<any>;
    mlsGroupOwnerCredential(mls_group_id: Uint8Array): Promise<any>;
    mlsGroupState(mls_group_id: Uint8Array): Promise<any>;
    mlsOwnerCandidates(mls_group_id: Uint8Array): Promise<any>;
    mlsOwnerChangeHasQuorum(mls_group_id: Uint8Array): Promise<boolean>;
    mlsPolicyChangeHasOwnerQuorum(mls_group_id: Uint8Array): Promise<boolean>;
    mlsRecoveryHasOwnerQuorum(mls_group_id: Uint8Array): Promise<boolean>;
    noteMlsApplicationAttempt(send_id: string): Promise<any>;
    noteMlsApplicationDeliveryAttempt(send_id: string, recipient: string): Promise<any>;
    /**
     * Open or restart-safely register the local device, then publish its
     * account-signed manifest. The database name must be account scoped.
     */
    static open(database_name: string, user: string, server_name: string, sealed_sender_enabled: boolean, master_key: Uint8Array, transport: KutupChatTransport): Promise<WasmChatClient>;
    openAnonymousMlsEnvelope(recipient: any, send_id: string, envelope: any): Promise<Uint8Array>;
    pendingMlsApplicationMessages(): Promise<any>;
    pendingMlsAuthorityChanges(): Promise<any>;
    pendingMlsCloses(): Promise<any>;
    pendingMlsCommit(mls_group_id: Uint8Array): Promise<any>;
    pendingMlsMembershipChanges(): Promise<any>;
    pendingMlsOwnerApprovalRequests(): Promise<any>;
    pendingMlsOwnerChanges(): Promise<any>;
    pendingMlsPolicyChanges(): Promise<any>;
    pendingMlsRecoveries(): Promise<any>;
    pendingSendCount(): Promise<number>;
    prepareMlsAuthorityChange(mls_group_id: Uint8Array, proposal_id: string, authority_policies: any, now_seconds: string): Promise<any>;
    prepareMlsAuthorizationPolicyChange(mls_group_id: Uint8Array, proposal_id: string, next_policy: any, now_seconds: string): Promise<any>;
    prepareMlsClose(mls_group_id: Uint8Array, proposal_id: string, now_seconds: string): Promise<any>;
    prepareMlsCryptographicPolicyChange(mls_group_id: Uint8Array, proposal_id: string, next_policy: any, now_seconds: string): Promise<any>;
    prepareMlsDeviceSync(mls_group_id: Uint8Array, proposal_id: string, additions: any, removed_device_ids: any, now_seconds: string): Promise<any>;
    prepareMlsGroupGenesis(conversation_id: string, mls_group_id: Uint8Array, creator: any, authority_policies: any, created_at_seconds: string, group_info: any): Promise<any>;
    /**
     * Stage a change of the group's name, description or picture; it is
     * then published like a membership change.
     */
    prepareMlsGroupInfoChange(mls_group_id: Uint8Array, proposal_id: string, group_info: any, now_seconds: string): Promise<any>;
    prepareMlsGroupRecovery(mls_group_id: Uint8Array, new_mls_group_id: Uint8Array, proposal_id: string, authority_policies: any, additions: any, created_at_seconds: string): Promise<any>;
    prepareMlsMembershipChange(mls_group_id: Uint8Array, proposal_id: string, next_roster: any, additions: any, now_seconds: string): Promise<any>;
    prepareMlsOwnerChange(mls_group_id: Uint8Array, proposal_id: string, next_roster: any, next_owner_set: any, now_seconds: string): Promise<any>;
    processedMlsApplicationEnvelope(envelope_id: string): Promise<any>;
    processedMlsControlEnvelope(envelope_id: string): Promise<any>;
    profile(): Promise<any>;
    profiles(): Promise<any>;
    purgeExpiredMessages(now_ms: string): Promise<any>;
    quarantineInbound(id: string): Promise<void>;
    /**
     * Flush crash-surviving sends, drain/decrypt/ack the mailbox, and return
     * the new receive report. WebSocket notifications call this same source-
     * of-truth reconciliation path.
     */
    reconcile(): Promise<any>;
    recordMlsAuthorityPreviousQuorum(mls_group_id: Uint8Array, certificate: any): Promise<any>;
    rejectContact(peer: string): Promise<any>;
    rejectMlsOwnerApprovalRequest(mls_group_id: Uint8Array): Promise<void>;
    rejectPendingMlsCommit(mls_group_id: Uint8Array, commit_hash: string): Promise<void>;
    /**
     * Ask to leave the group; `null` when this device already left.
     */
    requestMlsLeave(mls_group_id: Uint8Array, now_seconds: string): Promise<any>;
    resolveDeadLetter(id: string): Promise<void>;
    resolveMlsSenderClaim(claimed_sender: any): Promise<any>;
    resolveMlsWelcomeClaims(claimed_members: any): Promise<any>;
    revokeManifestDevice(device_id: number): Promise<any>;
    safetyNumber(peer: string): Promise<any>;
    /**
     * Sends a same-account control (`conversationState`, `readPosition` or
     * `deleteForMe`) to this account's other devices through Note to Self.
     */
    sendAccountControl(send_id: string, sent_at: string, kind: string, body: any): Promise<any>;
    sendAttachment(send_id: string, peer: string, sent_at: string, descriptor: any, expires_after_seconds: number | null | undefined, extras: any): Promise<any>;
    sendDisappearingTimer(send_id: string, peer: string, sent_at: string, duration_seconds?: number | null): Promise<any>;
    sendMessageMutation(send_id: string, peer: string, sent_at: string, target_message_id: string, operation: string, replacement_text?: string | null): Promise<any>;
    /**
     * A poll, a vote in one, or its end (`kind` = `poll` | `pollVote` |
     * `pollTerminate`), in a Direct chat or Note to Self.
     */
    sendPollContent(send_id: string, peer: string, sent_at: string, kind: string, body: any, expires_after_seconds?: number | null): Promise<any>;
    sendReaction(send_id: string, peer: string, sent_at: string, target_message_id: string, emoji: string, active: boolean): Promise<any>;
    sendReceipt(send_id: string, peer: string, sent_at: string, message_ids: string[], state: string): Promise<any>;
    sendText(send_id: string, peer: string, sent_at: string, text: string, reply_to: string | null | undefined, expires_after_seconds: number | null | undefined, extras: any): Promise<any>;
    sendTyping(send_id: string, peer: string, sent_at: string, active: boolean): Promise<any>;
    setProfile(display_name: string, avatar?: string | null, avatar_content_type?: string | null, about?: string | null): Promise<any>;
    signMlsControlProposal(mls_group_id: Uint8Array, conversation_id: string, incarnation: string, proposal_id: string, base_epoch: string, action_type: number, encrypted_payload: Uint8Array, created_at_seconds: string): Promise<any>;
    stageMlsApplicationDelivery(send_id: string, recipient: any, capability: Uint8Array, packages: any, now_seconds: string): Promise<any>;
    startDisappearingExpiry(send_id: string, sent_at: string, conversation: any, target_message_id: string, started_at_ms: string): Promise<any>;
    syncManifest(): Promise<any>;
    unblockContact(peer: string): Promise<any>;
    verifySafetyNumber(peer: string, scanned_payload: string): Promise<any>;
    readonly deviceId: number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmchatclient_free: (a: number, b: number) => void;
    readonly wasmchatclient_acceptContact: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_applyAnonymousMlsApplicationEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: any, k: any, l: any) => any;
    readonly wasmchatclient_applyOrderedInboundMlsMembershipCommit: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: any, m: number, n: number) => any;
    readonly wasmchatclient_approveMlsOwnerApprovalRequest: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_blockContact: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_buildMlsAuthorityCommitRequest: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_buildMlsCloseCommitRequest: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_buildMlsMembershipCommitRequest: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_buildMlsOwnerCommitRequest: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_buildMlsPolicyCommitRequest: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_contacts: (a: number) => any;
    readonly wasmchatclient_createAnonymousMlsSubmission: (a: number, b: any, c: number, d: number, e: number, f: number, g: any, h: number, i: number) => any;
    readonly wasmchatclient_createMlsApplicationMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => any;
    readonly wasmchatclient_createMlsAttachmentMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: any, m: number, n: number, o: number, p: any) => any;
    readonly wasmchatclient_createMlsDisappearingTimer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => any;
    readonly wasmchatclient_createMlsInvitationAcceptanceMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly wasmchatclient_createMlsMessageMutation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number) => any;
    readonly wasmchatclient_createMlsOwnerApprovalRequestMessage: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_createMlsOwnerCandidateMessage: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_createMlsPollContent: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: any, o: number, p: number, q: number) => any;
    readonly wasmchatclient_createMlsReactionMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number) => any;
    readonly wasmchatclient_createMlsReceiptMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => any;
    readonly wasmchatclient_createMlsTextMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: any) => any;
    readonly wasmchatclient_createMlsTypingMessage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => any;
    readonly wasmchatclient_decryptMlsApplicationMessage: (a: number, b: number, c: number, d: number, e: number, f: any) => any;
    readonly wasmchatclient_deriveMlsDeliveryCapability: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any) => any;
    readonly wasmchatclient_deviceId: (a: number) => number;
    readonly wasmchatclient_ensureMlsOwnerCandidate: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_fetchVerifiedIdentifiedMlsKeyPackages: (a: number, b: any, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly wasmchatclient_fetchVerifiedMlsKeyPackages: (a: number, b: any, c: number, d: number, e: number, f: number) => any;
    readonly wasmchatclient_fetchVerifiedMlsOrderingPolicy: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_fetchVerifiedMlsOrderingPolicyDetails: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_finalizeMlsAuthorityChange: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_finalizeMlsClose: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_finalizeMlsGroupRecovery: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_finalizeMlsMembershipChange: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_finalizeMlsOwnerChange: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_finalizeMlsPolicyChange: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_generateMlsKeyPackage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly wasmchatclient_history: (a: number) => any;
    readonly wasmchatclient_inboundAttention: (a: number) => any;
    readonly wasmchatclient_inspectAnonymousMlsApplicationEnvelope: (a: number, b: any, c: number, d: number, e: any) => any;
    readonly wasmchatclient_inspectInboundMlsCommit: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_inspectMlsWelcome: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_joinMlsFromRecoveryWelcome: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: any, m: any) => any;
    readonly wasmchatclient_joinMlsFromWelcomeWithControlHistory: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: any, m: any) => any;
    readonly wasmchatclient_localMlsConversations: (a: number) => any;
    readonly wasmchatclient_localMlsIncarnationHistory: (a: number) => any;
    readonly wasmchatclient_maintainPrekeys: (a: number) => any;
    readonly wasmchatclient_markMlsApplicationDelivered: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_markMlsApplicationRecipientDelivered: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly wasmchatclient_markMlsGroupGenesisPublished: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_mediaDeliveryCapability: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mergePendingMlsCommit: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_mlsCloseHasOwnerQuorum: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsGroupControlCredential: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsGroupDevices: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsGroupOwnerCredential: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsGroupState: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsOwnerCandidates: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsOwnerChangeHasQuorum: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsPolicyChangeHasOwnerQuorum: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_mlsRecoveryHasOwnerQuorum: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_noteMlsApplicationAttempt: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_noteMlsApplicationDeliveryAttempt: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_open: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: any) => any;
    readonly wasmchatclient_openAnonymousMlsEnvelope: (a: number, b: any, c: number, d: number, e: any) => any;
    readonly wasmchatclient_pendingMlsApplicationMessages: (a: number) => any;
    readonly wasmchatclient_pendingMlsAuthorityChanges: (a: number) => any;
    readonly wasmchatclient_pendingMlsCloses: (a: number) => any;
    readonly wasmchatclient_pendingMlsCommit: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_pendingMlsMembershipChanges: (a: number) => any;
    readonly wasmchatclient_pendingMlsOwnerApprovalRequests: (a: number) => any;
    readonly wasmchatclient_pendingMlsOwnerChanges: (a: number) => any;
    readonly wasmchatclient_pendingMlsPolicyChanges: (a: number) => any;
    readonly wasmchatclient_pendingMlsRecoveries: (a: number) => any;
    readonly wasmchatclient_pendingSendCount: (a: number) => any;
    readonly wasmchatclient_prepareMlsAuthorityChange: (a: number, b: number, c: number, d: number, e: number, f: any, g: number, h: number) => any;
    readonly wasmchatclient_prepareMlsAuthorizationPolicyChange: (a: number, b: number, c: number, d: number, e: number, f: any, g: number, h: number) => any;
    readonly wasmchatclient_prepareMlsClose: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly wasmchatclient_prepareMlsCryptographicPolicyChange: (a: number, b: number, c: number, d: number, e: number, f: any, g: number, h: number) => any;
    readonly wasmchatclient_prepareMlsDeviceSync: (a: number, b: number, c: number, d: number, e: number, f: any, g: any, h: number, i: number) => any;
    readonly wasmchatclient_prepareMlsGroupGenesis: (a: number, b: number, c: number, d: number, e: number, f: any, g: any, h: number, i: number, j: any) => any;
    readonly wasmchatclient_prepareMlsGroupInfoChange: (a: number, b: number, c: number, d: number, e: number, f: any, g: number, h: number) => any;
    readonly wasmchatclient_prepareMlsGroupRecovery: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any, i: any, j: number, k: number) => any;
    readonly wasmchatclient_prepareMlsMembershipChange: (a: number, b: number, c: number, d: number, e: number, f: any, g: any, h: number, i: number) => any;
    readonly wasmchatclient_prepareMlsOwnerChange: (a: number, b: number, c: number, d: number, e: number, f: any, g: any, h: number, i: number) => any;
    readonly wasmchatclient_processedMlsApplicationEnvelope: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_processedMlsControlEnvelope: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_profile: (a: number) => any;
    readonly wasmchatclient_profiles: (a: number) => any;
    readonly wasmchatclient_purgeExpiredMessages: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_quarantineInbound: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_reconcile: (a: number) => any;
    readonly wasmchatclient_recordMlsAuthorityPreviousQuorum: (a: number, b: number, c: number, d: any) => any;
    readonly wasmchatclient_rejectContact: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_rejectMlsOwnerApprovalRequest: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_rejectPendingMlsCommit: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_requestMlsLeave: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasmchatclient_resolveDeadLetter: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_resolveMlsSenderClaim: (a: number, b: any) => any;
    readonly wasmchatclient_resolveMlsWelcomeClaims: (a: number, b: any) => any;
    readonly wasmchatclient_revokeManifestDevice: (a: number, b: number) => any;
    readonly wasmchatclient_safetyNumber: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_sendAccountControl: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any) => any;
    readonly wasmchatclient_sendAttachment: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any, i: number, j: any) => any;
    readonly wasmchatclient_sendDisappearingTimer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly wasmchatclient_sendMessageMutation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => any;
    readonly wasmchatclient_sendPollContent: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: any, k: number) => any;
    readonly wasmchatclient_sendReaction: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => any;
    readonly wasmchatclient_sendReceipt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => any;
    readonly wasmchatclient_sendText: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: any) => any;
    readonly wasmchatclient_sendTyping: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly wasmchatclient_setProfile: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => any;
    readonly wasmchatclient_signMlsControlProposal: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number) => any;
    readonly wasmchatclient_stageMlsApplicationDelivery: (a: number, b: number, c: number, d: any, e: number, f: number, g: any, h: number, i: number) => any;
    readonly wasmchatclient_startDisappearingExpiry: (a: number, b: number, c: number, d: number, e: number, f: any, g: number, h: number, i: number, j: number) => any;
    readonly wasmchatclient_syncManifest: (a: number) => any;
    readonly wasmchatclient_unblockContact: (a: number, b: number, c: number) => any;
    readonly wasmchatclient_verifySafetyNumber: (a: number, b: number, c: number, d: number, e: number) => any;
    readonly wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___wasm_bindgen_1008b6a7b07acaf3___JsValue__core_f0fd674eaa06beef___result__Result_____wasm_bindgen_1008b6a7b07acaf3___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined_______true_: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_Event__Event______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_IdbVersionChangeEvent__IdbVersionChangeEvent______true_: (a: number, b: number, c: any) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
