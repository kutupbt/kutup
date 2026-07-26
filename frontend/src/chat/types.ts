export interface ChatContentView {
  version: number
  kind: string
  sentAt: string
  seq: string
  messageId?: string
  body: unknown
  text?: string
}

export interface AccountAddress {
  username: string
  server?: string
}

export type ConversationId =
  | { kind: 'direct'; address: AccountAddress }
  | { kind: 'group'; groupId: string }

export interface ChatHistoryEntry {
  id: string
  conversation: ConversationId
  /** @deprecated Use conversation. */
  peer: string
  direction: 'incoming' | 'outgoing'
  senderDeviceId?: number
  cursor?: string
  timestampMs: number
  delivered: boolean
  deduplicated: boolean
  content: ChatContentView
}

export interface SendSummary {
  delivered: boolean
  deduplicated: boolean
  attempts: number
  safetyNumberChanges: string[]
}

export interface InboundFailure {
  id: string
  kind: string
  error: string
}

export interface ReceiveReport {
  messages: unknown[]
  synced: string[]
  contactSynced: string[]
  profileKeyUpdated: string[]
  profilesRefreshed: string[]
  suppressed: string[]
  undecodable: string[]
  errors: InboundFailure[]
  duplicates: string[]
}

export type ContactState =
  | 'pendingIncoming'
  | 'pendingOutgoing'
  | 'accepted'
  | 'rejected'
  | 'blocked'

export interface ContactRecord {
  peer: string
  state: ContactState
  previousState?: ContactState
  revision: string
  sourceDeviceId: number
  updatedAtMs: number
  syncPending: boolean
}

export interface ChatProfile {
  displayName: string
  avatar?: string
  avatarContentType?: string
  revision: string
}

export interface PeerChatProfile extends ChatProfile {
  peer: string
}

export interface InboundAttention {
  id: string
  cursor: string
  state: string
  attempts: number
  failureKind?: string
  lastError?: string
  receivedAt: number
}

export interface ChatCapabilities {
  enabled: boolean
  protocolVersion: number
  /** Untrusted, forward-compatible registry codes; select through suites.ts. */
  suites: number[]
  maxContentBytes: number
  mailboxRetentionDays: number
  deviceExpiryDays: number
  serverName?: string
  federation: boolean
  manifests: boolean
  profiles: boolean
  keyTransparency: boolean
  transparencyOperatorKeyId?: string
  transparencyOperatorPublicKey?: string
  transparencyWitnesses?: TransparencyVerifierKey[]
  transparencyWitnessQuorum?: number
  sealedSender: boolean
}

export interface TransparencyVerifierKey {
  witnessId: string
  keyId: string
  publicKey: string
}

export type TransparencyMonitorState = 'healthy' | 'unavailable' | 'verificationFailed'

export interface TransparencyMonitorStatus {
  scope: string
  state: TransparencyMonitorState
  lastCheckedAtMs: number
  lastSuccessAtMs?: number
  treeSize?: string
  detail?: string
}

export interface PendingMlsInvitation {
  conversationId: string
  incarnation: number
  mlsGroupId: string
  invitedEpoch: number
  expiresAt: number
}

export interface MlsInvitationDecision {
  conversationId: string
  incarnation: number
  accept: boolean
}

export interface MlsInvitationDecisionResponse {
  conversationId: string
  incarnation: number
  status: 'active' | 'rejected'
  idempotent: boolean
}

export type MlsMailboxDeliveryKind =
  | 'identified_request'
  | 'anonymous'
  | 'self_sync'
  | 'membership_control'

export interface MlsMailboxEnvelope {
  id: string
  cursor: string
  deliveryKind: MlsMailboxDeliveryKind
  conversationId?: string
  incarnation?: number
  sendId: string
  opaqueEnvelope: string
  serverTimestamp: number
}

export interface MlsMailboxPage {
  envelopes: MlsMailboxEnvelope[]
  nextCursor?: string
}

export interface LocalMlsGroupState {
  mlsGroupId: number[]
  epoch: number
}

export interface VerifiedMlsCredential {
  credentialIdentity: string
  credentialPublicKey: number[]
}

export interface ClaimedMlsCredential {
  credentialIdentity: string
  credentialPublicKey: number[]
}

export interface MlsWelcomeInspection {
  mlsGroupId: number[]
  epoch: number
  claimedMembers: ClaimedMlsCredential[]
}

export interface ChatTransportPort {
  registerDevice(request: unknown): Promise<unknown>
  fetchBundles(username: string, transparencyTreeSize: string): Promise<unknown>
  fetchSyncBundles(
    username: string,
    currentDeviceId: number,
    transparencyTreeSize: string,
  ): Promise<unknown>
  fetchTransparencyCheckpoint(scope: string, fromTreeSize: string): Promise<unknown>
  fetchTransparencyPolicy(domain: string): Promise<unknown>
  fetchManifest(username: string): Promise<unknown | null>
  fetchManifestPublication(
    username: string,
    transparencyTreeSize: string,
  ): Promise<unknown>
  fetchManifestRange(
    username: string,
    fromVersion: string,
    toVersion: string,
    pageFromVersion: string,
    cursor: string | null,
    transparencyTreeSize: string,
  ): Promise<unknown>
  fetchSealedSenderPolicy(domain: string): Promise<unknown>
  fetchSenderCertificate(deviceId: number): Promise<unknown>
  fetchSealedBundles(
    username: string,
    capability: string,
    transparencyTreeSize: string,
  ): Promise<unknown>
  publishManifest(manifest: unknown, transparencyTreeSize: string): Promise<unknown>
  fetchOwnProfile(): Promise<unknown | null>
  publishProfile(profile: unknown): Promise<unknown>
  fetchProfile(username: string, version: string, accessKey: string): Promise<unknown | null>
  prekeyCount(deviceId: number): Promise<unknown>
  replenishPrekeys(deviceId: number, request: unknown): Promise<void>
  publishMlsKeyPackages(request: unknown): Promise<unknown>
  mlsKeyPackageCount(deviceId: number): Promise<unknown>
  createMlsConversation(request: unknown): Promise<unknown>
  stageMlsMembershipDelivery(request: unknown): Promise<unknown>
  collectMlsOrderingVotes(request: unknown): Promise<unknown>
  commitMlsControlBlock(request: unknown): Promise<unknown>
  listMlsInvitations(): Promise<PendingMlsInvitation[]>
  respondMlsInvitation(
    request: MlsInvitationDecision,
  ): Promise<MlsInvitationDecisionResponse>
  drainMlsMailbox(
    deviceId: number,
    after?: string,
    limit?: number,
  ): Promise<MlsMailboxPage>
  ackMlsMailbox(deviceId: number, envelopeIds: string[]): Promise<void>
  publishMlsDeliveryCapability(request: unknown): Promise<void>
  fetchAnonymousMlsKeyPackages(request: unknown): Promise<unknown>
  submitAnonymousMlsMessage(request: unknown): Promise<unknown>
  sendMessage(
    username: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  sendSealedMessage(
    username: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  sendSyncMessage(
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  drainMailbox(deviceId: number, after: string | null, limit: number): Promise<unknown>
  ackMessages(deviceId: number, ids: string[]): Promise<void>
}

export interface WasmChatClientHandle {
  readonly deviceId: number
  generateMlsKeyPackage(
    manifestVersion: string,
    nowSeconds: string,
    expiresAtSeconds: string,
  ): Promise<unknown>
  createMlsGroup(mlsGroupId: Uint8Array): Promise<unknown>
  mlsGroupState(mlsGroupId: Uint8Array): Promise<LocalMlsGroupState | null>
  prepareMlsAddMembers(
    mlsGroupId: Uint8Array,
    additions: unknown,
    nowSeconds: string,
  ): Promise<unknown>
  prepareMlsRemoveMembers(
    mlsGroupId: Uint8Array,
    credentialIdentities: string[],
  ): Promise<unknown>
  pendingMlsCommit(mlsGroupId: Uint8Array): Promise<unknown | null>
  mergePendingMlsCommit(mlsGroupId: Uint8Array, commitHash: string): Promise<unknown>
  rejectPendingMlsCommit(mlsGroupId: Uint8Array, commitHash: string): Promise<void>
  joinMlsFromWelcome(
    mlsGroupId: Uint8Array,
    welcome: Uint8Array,
    expectedMembers: unknown,
  ): Promise<unknown>
  inspectMlsWelcome(
    mlsGroupId: Uint8Array,
    welcome: Uint8Array,
  ): Promise<MlsWelcomeInspection>
  resolveMlsWelcomeClaims(
    claimedMembers: ClaimedMlsCredential[],
  ): Promise<VerifiedMlsCredential[]>
  fetchVerifiedMlsKeyPackages(
    recipient: AccountAddress,
    capability: Uint8Array,
    nowSeconds: string,
  ): Promise<unknown[]>
  applyInboundMlsCommit(
    mlsGroupId: Uint8Array,
    commit: Uint8Array,
    expectedMembers: unknown,
  ): Promise<unknown>
  mlsGroupControlCredential(mlsGroupId: Uint8Array): Promise<unknown>
  signMlsControlProposal(
    mlsGroupId: Uint8Array,
    conversationId: string,
    incarnation: string,
    proposalId: string,
    baseEpoch: string,
    actionType: number,
    encryptedPayload: Uint8Array,
    createdAtSeconds: string,
  ): Promise<unknown>
  createMlsApplicationMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    plaintext: Uint8Array,
    createdAtMs: string,
  ): Promise<unknown>
  markMlsApplicationDelivered(sendId: string): Promise<void>
  noteMlsApplicationAttempt(sendId: string): Promise<unknown>
  decryptMlsApplicationMessage(
    mlsGroupId: Uint8Array,
    ciphertext: Uint8Array,
    expectedSender: unknown,
  ): Promise<unknown>
  deriveMlsDeliveryCapability(
    mlsGroupId: Uint8Array,
    conversationId: string,
    incarnation: string,
    recipient: AccountAddress,
  ): Promise<unknown>
  createAnonymousMlsSubmission(
    recipient: AccountAddress,
    sendId: string,
    capability: Uint8Array,
    devices: unknown,
    mlsCiphertext: Uint8Array,
  ): Promise<unknown>
  openAnonymousMlsEnvelope(
    recipient: AccountAddress,
    sendId: string,
    envelope: unknown,
  ): Promise<Uint8Array>
  history(): Promise<ChatHistoryEntry[]>
  contacts(): Promise<ContactRecord[]>
  profile(): Promise<ChatProfile>
  profiles(): Promise<PeerChatProfile[]>
  setProfile(
    displayName: string,
    avatar?: string,
    avatarContentType?: string,
  ): Promise<ChatProfile>
  acceptContact(peer: string): Promise<ContactRecord>
  rejectContact(peer: string): Promise<ContactRecord>
  blockContact(peer: string): Promise<ContactRecord>
  unblockContact(peer: string): Promise<ContactRecord>
  inboundAttention(): Promise<InboundAttention[]>
  maintainPrekeys(): Promise<unknown>
  monitorTransparency(scope: string): Promise<TransparencyMonitorStatus>
  pendingSendCount(): Promise<number>
  quarantineInbound(id: string): Promise<void>
  reconcile(): Promise<ReceiveReport>
  resolveDeadLetter(id: string): Promise<void>
  sendText(
    sendId: string,
    peer: string,
    sentAt: string,
    text: string,
  ): Promise<SendSummary>
  syncManifest(): Promise<unknown>
  transparencyMonitorStatus(scope: string): Promise<TransparencyMonitorStatus | undefined>
  verifyAuthority(peer: string): Promise<unknown>
  free(): void
}

export interface ChatWasmModule {
  default(input?: unknown): Promise<unknown>
  WasmChatClient: {
    open(
      databaseName: string,
      user: string,
      serverName: string,
      sealedSenderEnabled: boolean,
      masterKey: Uint8Array,
      transport: ChatTransportPort,
      transparencyPolicy: unknown,
    ): Promise<WasmChatClientHandle>
  }
}
