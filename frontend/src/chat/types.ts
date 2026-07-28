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
  /** Complete browser + local + federated MLS group path is available. */
  mlsGroups?: boolean
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
  privateControlState: {
    protocolVersion: number
    conversationId: string
    incarnation: number
    height: number
    epoch: number
  }
}

export interface MlsInboundCommitInspection {
  mlsGroupId: number[]
  epochBefore: number
  epochAfter: number
  commitHash: string
  claimedMembers: ClaimedMlsCredential[]
  privateControlState: MlsWelcomeInspection['privateControlState']
}

export interface LocalMlsConversationRecord {
  request: {
    genesis: {
      protocolVersion: number
      conversationId: string
      incarnation: number
      mlsGroupId: string
      kind: 'group'
      suite: number
      rosterCommitment: string
      memberCount: number
      authoritySet: {
        sequence: number
        authorities: Array<{
          domain: string
          keyId: string
          publicKey: string
        }>
        requiredQuorum: number
      }
      ownerSet: {
        sequence: number
        owners: Array<{ ownerId: string; publicKey: string }>
        requiredQuorum: number
      }
      initialEpoch: number
      createdAt: number
    }
    members: Array<{
      address: AccountAddress
      isAdmin: boolean
      ownerId?: string
    }>
  }
  status: 'pending_genesis' | 'active'
  serverGenesisHash?: string
  lastFinalizedHeight: number
  lastFinalizedEpoch: number
  lastBlockHash?: string
  currentRoster: MlsConversationMember[]
  currentAuthoritySet: MlsAuthoritySet
  currentOwnerSet: MlsOwnerSet
}

export interface PreparedMlsGroupGenesis {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface MlsConversationMember {
  address: AccountAddress
  isAdmin: boolean
  ownerId?: string
}

export interface MlsAuthoritySet {
  sequence: number
  authorities: Array<{
    domain: string
    keyId: string
    publicKey: string
  }>
  requiredQuorum: number
}

export interface MlsOwnerSet {
  sequence: number
  owners: Array<{ ownerId: string; publicKey: string }>
  requiredQuorum: number
}

export interface MlsOwnerCandidate {
  protocolVersion: number
  conversationId: string
  incarnation: number
  account: AccountAddress
  ownerId: string
  publicKey: string
  createdAt: number
  signature: string
}

export interface PendingMlsMembershipChange {
  mlsGroupId: number[]
  nextRoster: MlsConversationMember[]
  deliveries: unknown[]
  transition: {
    conversationId: string
    incarnation: number
    proposalId: string
  }
  voteRequest: {
    block: {
      conversationId: string
      incarnation: number
      height: number
      epochBefore: number
      epochAfter: number
    }
  }
  commitHash: string
  finalRequest?: unknown
}

export interface PreparedMlsMembershipChange {
  pending: {
    mlsGroupId: number[]
    epochBefore: number
    epochAfter: number
    commitHash: string
    commit: number[]
    welcome?: number[]
  }
  control: PendingMlsMembershipChange
}

export interface FinalizedMlsMembershipChange {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface PendingMlsAuthorityChange {
  mlsGroupId: number[]
  deliveries: unknown[]
  authorityChange: {
    nextAuthoritySet: MlsAuthoritySet
    deliveryTransition: {
      conversationId: string
      incarnation: number
      proposalId: string
    }
  }
  voteRequest: {
    block: {
      conversationId: string
      incarnation: number
      height: number
      epochBefore: number
      epochAfter: number
    }
  }
  commitHash: string
  previousSetCertificate?: unknown
  newVoteRequest?: unknown
  finalRequest?: unknown
}

export interface PreparedMlsAuthorityChange {
  pending: PreparedMlsMembershipChange['pending']
  control: PendingMlsAuthorityChange
}

export interface FinalizedMlsAuthorityChange {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface PendingMlsOwnerChange {
  mlsGroupId: number[]
  nextRoster: MlsConversationMember[]
  deliveries: unknown[]
  ownerChange: {
    nextOwnerSet: MlsOwnerSet
    deliveryTransition: {
      conversationId: string
      incarnation: number
      proposalId: string
    }
  }
  voteRequest: {
    block: {
      conversationId: string
      incarnation: number
      height: number
      epochBefore: number
      epochAfter: number
    }
  }
  commitHash: string
  finalRequest?: unknown
}

export interface PendingMlsOwnerApprovalRequest {
  mlsGroupId: number[]
  requester: AccountAddress
  request: {
    protocolVersion: number
    ownerSetSequence: number
    proposal: {
      conversationId: string
      incarnation: number
      proposalId: string
      baseEpoch: number
    }
    transitionDigest: string
    ownerChange: {
      nextOwnerSet: MlsOwnerSet
    }
    nextRoster: MlsConversationMember[]
    requestedAt: number
    expiresAt: number
  }
}

export interface PreparedMlsOwnerChange {
  pending: PreparedMlsMembershipChange['pending']
  control: PendingMlsOwnerChange
}

export interface FinalizedMlsOwnerChange {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface JoinedMlsConversation {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface ProcessedMlsControlEnvelope {
  envelopeId: string
  cursor: string
  sendId: string
  conversationId: string
  incarnation: number
  height: number
  epoch: number
  blockHash: string
}

export interface AppliedInboundMlsCommit {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
  receipt: ProcessedMlsControlEnvelope
  idempotent: boolean
}

export interface MlsControlHistoryPage {
  bytes: Uint8Array
  entryCount: number
  nextHeight?: string
}

export interface DerivedMlsDeliveryCapability {
  epoch: number
  capability: number[]
  verifierHash: number[]
}

export interface MlsOutboxDelivery {
  recipient: string
  submission: number[]
  attempts: number
  delivered: boolean
}

export interface MlsOutboxEntry {
  sendId: string
  conversationId: number[]
  incarnation: number
  mlsGroupId: number[]
  epoch: number
  contentDigest: number[]
  content: number[]
  ciphertext: number[]
  expectedRecipients: string[]
  deliveries: MlsOutboxDelivery[]
  createdAt: number
  attempts: number
}

export interface AnonymousMlsDeviceEnvelope {
  deviceId: number
  encapsulatedKey: string
  ciphertext: string
}

export interface AnonymousMlsSubmission {
  protocolVersion: number
  recipient: AccountAddress
  sendId: string
  capability: string
  suite: string
  envelopes: AnonymousMlsDeviceEnvelope[]
}

export interface MlsApplicationInspection {
  mlsGroupId: number[]
  conversationId: string
  incarnation: number
  epoch: number
  claimedSender: ClaimedMlsCredential
}

export interface MlsHistoryMessage {
  recordId: string
  messageId: string
  conversationId: number[]
  incarnation: number
  mlsGroupId: number[]
  epoch: number
  sender: string
  senderDeviceId: number
  outgoing: boolean
  cursor?: number
  transportDigest: number[]
  content: number[]
  timestampMs: number
  delivered: boolean
  deduplicated: boolean
}

export interface AppliedInboundMlsApplication {
  message: MlsHistoryMessage
  idempotent: boolean
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
  fetchMlsOrderingPolicy(domain: string): Promise<unknown>
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
  fetchMlsControlHistory(
    conversationId: string,
    incarnation: number,
    afterHeight: string,
    limit?: number,
  ): Promise<MlsControlHistoryPage>
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
  fetchIdentifiedMlsKeyPackages(request: unknown): Promise<unknown>
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
  prepareMlsGroupGenesis(
    conversationId: string,
    mlsGroupId: Uint8Array,
    creator: AccountAddress,
    authorityPolicies: unknown[],
    createdAtSeconds: string,
  ): Promise<PreparedMlsGroupGenesis>
  localMlsConversations(): Promise<LocalMlsConversationRecord[]>
  markMlsGroupGenesisPublished(
    conversationId: string,
    genesisHash: string,
  ): Promise<LocalMlsConversationRecord>
  mlsGroupOwnerCredential(mlsGroupId: Uint8Array): Promise<unknown>
  mlsGroupState(mlsGroupId: Uint8Array): Promise<LocalMlsGroupState | null>
  prepareMlsMembershipChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    nextRoster: MlsConversationMember[],
    additions: unknown,
    nowSeconds: string,
  ): Promise<PreparedMlsMembershipChange>
  pendingMlsMembershipChanges(): Promise<PendingMlsMembershipChange[]>
  buildMlsMembershipCommitRequest(
    mlsGroupId: Uint8Array,
    quorumCertificate: unknown,
  ): Promise<unknown>
  finalizeMlsMembershipChange(
    mlsGroupId: Uint8Array,
    acknowledgement: unknown,
  ): Promise<FinalizedMlsMembershipChange>
  prepareMlsAuthorityChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    authorityPolicies: unknown[],
    nowSeconds: string,
  ): Promise<PreparedMlsAuthorityChange>
  pendingMlsAuthorityChanges(): Promise<PendingMlsAuthorityChange[]>
  recordMlsAuthorityPreviousQuorum(
    mlsGroupId: Uint8Array,
    certificate: unknown,
  ): Promise<unknown>
  buildMlsAuthorityCommitRequest(
    mlsGroupId: Uint8Array,
    newSetCertificate: unknown,
  ): Promise<unknown>
  finalizeMlsAuthorityChange(
    mlsGroupId: Uint8Array,
    acknowledgement: unknown,
  ): Promise<FinalizedMlsAuthorityChange>
  prepareMlsOwnerChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    nextRoster: MlsConversationMember[],
    nextOwnerSet: MlsOwnerSet,
    nowSeconds: string,
  ): Promise<PreparedMlsOwnerChange>
  ensureMlsOwnerCandidate(
    mlsGroupId: Uint8Array,
    nowSeconds: string,
  ): Promise<MlsOwnerCandidate>
  mlsOwnerCandidates(mlsGroupId: Uint8Array): Promise<MlsOwnerCandidate[]>
  createMlsOwnerCandidateMessage(
    mlsGroupId: Uint8Array,
    nowSeconds: string,
  ): Promise<MlsOutboxEntry | null>
  pendingMlsOwnerChanges(): Promise<PendingMlsOwnerChange[]>
  mlsOwnerChangeHasQuorum(mlsGroupId: Uint8Array): Promise<boolean>
  createMlsOwnerApprovalRequestMessage(
    mlsGroupId: Uint8Array,
  ): Promise<MlsOutboxEntry | null>
  pendingMlsOwnerApprovalRequests(): Promise<PendingMlsOwnerApprovalRequest[]>
  approveMlsOwnerApprovalRequest(
    mlsGroupId: Uint8Array,
    approvedAtSeconds: string,
  ): Promise<MlsOutboxEntry | null>
  rejectMlsOwnerApprovalRequest(mlsGroupId: Uint8Array): Promise<void>
  buildMlsOwnerCommitRequest(
    mlsGroupId: Uint8Array,
    quorumCertificate: unknown,
  ): Promise<unknown>
  finalizeMlsOwnerChange(
    mlsGroupId: Uint8Array,
    acknowledgement: unknown,
  ): Promise<FinalizedMlsOwnerChange>
  pendingMlsCommit(mlsGroupId: Uint8Array): Promise<unknown | null>
  mergePendingMlsCommit(mlsGroupId: Uint8Array, commitHash: string): Promise<unknown>
  rejectPendingMlsCommit(mlsGroupId: Uint8Array, commitHash: string): Promise<void>
  joinMlsFromWelcomeWithControlHistory(
    envelopeId: string,
    cursor: string,
    sendId: string,
    mlsGroupId: Uint8Array,
    welcome: Uint8Array,
    expectedMembers: unknown,
    historyPages: Uint8Array[],
  ): Promise<JoinedMlsConversation>
  inspectMlsWelcome(
    mlsGroupId: Uint8Array,
    welcome: Uint8Array,
  ): Promise<MlsWelcomeInspection>
  resolveMlsWelcomeClaims(
    claimedMembers: ClaimedMlsCredential[],
  ): Promise<VerifiedMlsCredential[]>
  fetchVerifiedMlsOrderingPolicy(domain: string): Promise<unknown>
  fetchVerifiedMlsKeyPackages(
    recipient: AccountAddress,
    capability: Uint8Array,
    nowSeconds: string,
  ): Promise<unknown[]>
  fetchVerifiedIdentifiedMlsKeyPackages(
    recipient: AccountAddress,
    conversationId: string,
    incarnation: string,
    nowSeconds: string,
  ): Promise<unknown[]>
  processedMlsControlEnvelope(
    envelopeId: string,
  ): Promise<ProcessedMlsControlEnvelope | null>
  applyOrderedInboundMlsMembershipCommit(
    envelopeId: string,
    cursor: string,
    sendId: string,
    mlsGroupId: Uint8Array,
    commit: Uint8Array,
    expectedMembers: unknown,
    controlHistoryPage: Uint8Array,
  ): Promise<AppliedInboundMlsCommit>
  inspectInboundMlsCommit(
    mlsGroupId: Uint8Array,
    commit: Uint8Array,
  ): Promise<MlsInboundCommitInspection>
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
  createMlsTextMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    text: string,
    createdAtMs: string,
  ): Promise<MlsOutboxEntry>
  pendingMlsApplicationMessages(): Promise<MlsOutboxEntry[]>
  stageMlsApplicationDelivery(
    sendId: string,
    recipient: AccountAddress,
    capability: Uint8Array,
    packages: unknown[],
    nowSeconds: string,
  ): Promise<{
    entry: MlsOutboxEntry
    submission: AnonymousMlsSubmission
    idempotent: boolean
  }>
  noteMlsApplicationDeliveryAttempt(
    sendId: string,
    recipient: string,
  ): Promise<AnonymousMlsSubmission>
  markMlsApplicationRecipientDelivered(
    sendId: string,
    recipient: string,
    deduplicated: boolean,
  ): Promise<MlsHistoryMessage | null>
  inspectAnonymousMlsApplicationEnvelope(
    recipient: AccountAddress,
    sendId: string,
    envelope: AnonymousMlsDeviceEnvelope,
  ): Promise<MlsApplicationInspection>
  processedMlsApplicationEnvelope(
    envelopeId: string,
  ): Promise<MlsHistoryMessage | null>
  applyAnonymousMlsApplicationEnvelope(
    envelopeId: string,
    cursor: string,
    sendId: string,
    serverTimestamp: string,
    recipient: AccountAddress,
    envelope: AnonymousMlsDeviceEnvelope,
    expectedSender: VerifiedMlsCredential,
  ): Promise<AppliedInboundMlsApplication>
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
  ): Promise<DerivedMlsDeliveryCapability>
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
