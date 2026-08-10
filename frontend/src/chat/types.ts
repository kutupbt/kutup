export interface ChatContentView {
  version: number
  kind: string
  sentAt: string
  seq: string
  messageId?: string
  replyTo?: string
  body: unknown
  text?: string
  /** Present only after strict Rust descriptor validation. */
  attachment?: ChatAttachmentDescriptorV1
  reaction?: ChatReactionV1
}

export interface ChatReactionV1 {
  targetMessageId: string
  emoji: '👍' | '❤️' | '😂' | '😮' | '😢' | '🙏'
  active: boolean
}

export type ChatMediaClassV1 = 'file' | 'photo' | 'video' | 'audio'

export interface ChatMediaPreviewV1 {
  mimeType: string
  data: string
}

/** Exact E2EE attachment body validated again by the Rust Chat engine. */
export interface ChatAttachmentDescriptorV1 {
  version: 1
  suite: 1
  attachmentId: string
  originDomain: string
  retrievalToken: string
  ciphertextBytes: number
  ciphertextSha256: string
  attachmentKey: string
  plaintextBytes: number
  filename: string
  mimeType: string
  mediaClass: ChatMediaClassV1
  caption?: string
  width?: number
  height?: number
  durationMs?: number
  preview?: ChatMediaPreviewV1
}

export type ChatMediaConversationKindV1 = 'direct' | 'mls_group' | 'note_to_self'
export type ChatAttachmentLedgerStateV1 =
  | 'active'
  | 'cleared'
  | 'saved_to_drive'
  | 'expired'

export interface ChatAttachmentLedgerEntryV1 {
  version: 1
  conversationKind: ChatMediaConversationKindV1
  conversationReference: string
  messageId: string
  attachmentId: string
  storageReferenceId: string
  ciphertextBytes: number
  state: ChatAttachmentLedgerStateV1
  mediaClass: ChatMediaClassV1
  displayName: string
  updatedAtMs: number
  driveFileId?: string
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

export interface ChatDevice {
  deviceId: number
  suite: number
  name: string
  createdAt: string
  lastSeenAt?: string | null
}

export interface ChatHistoryTransferRequest {
  version: number
  transferId: string
  account: string
  requestingDeviceId: number
  createdAtUnix: number
  expiresAtUnix: number
  [key: string]: unknown
}

export interface ChatHistoryTransferSummary {
  transferId: string
  request: ChatHistoryTransferRequest
  acceptance?: unknown
  state: 'pending' | 'accepted' | string
  requestingDeviceId: number
  respondingDeviceId?: number
  frameCount: number
}

export interface ChatHistoryTransferList {
  transfers: ChatHistoryTransferSummary[]
}

export interface ChatHistoryTransferDownloadResult {
  ready: boolean
  frameCount: number
  importedCount?: number
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
  maximumActiveDevices: number
  serverName?: string
  federation: boolean
  manifests: boolean
  profiles: boolean
  sealedSender: boolean
  /** Complete browser + local + federated MLS group path is available. */
  mlsGroups?: boolean
  /** Present only after immutable media works locally, federated, and in the browser. */
  media?: {
    protocolVersion: number
    suites: number[]
    maximumPlaintextBytes: number
  }
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

export interface MlsInvitationFeedback {
  protocolVersion: number
  conversationId: string
  incarnation: number
  member: AccountAddress
  invitedEpoch: number
  decision: 'accepted' | 'rejected' | 'expired'
  decidedAt: number
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

export interface MlsConversationDevice {
  address: AccountAddress
  deviceId: number
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
    initialEpoch: number
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
    initialDevices?: MlsConversationDevice[]
  }
  status: 'pending_genesis' | 'active' | 'read_only' | 'closed'
  serverGenesisHash?: string
  recoveryDigest?: string
  lastFinalizedHeight: number
  lastFinalizedEpoch: number
  lastBlockHash?: string
  currentRoster: MlsConversationMember[]
  memberJoinedEpochs: Map<string, number>
  acceptedInvitationEpochs: Map<string, number>
  currentAuthoritySet: MlsAuthoritySet
  currentOwnerSet: MlsOwnerSet
  genesisAuthorizationPolicy: MlsGroupAuthorizationPolicy
  genesisCryptographicPolicy: MlsGroupCryptographicPolicy
  currentAuthorizationPolicy: MlsGroupAuthorizationPolicy
  currentCryptographicPolicy: MlsGroupCryptographicPolicy
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

export interface MlsOrderingServicePolicy {
  policyVersion: number
  canonicalDomain: string
  suite: number
  anonymousDeliverySuite: number
  controlSigningKeyId: string
  controlSigningPublicKey: string
  acceptsGroupOrdering: boolean
  maximumGroupMembers: number
  maximumAuthorities: number
  maximumControlPayloadBytes: number
  pendingMessageRequests: {
    maximumMessages: number
    maximumCiphertextBytes: number
    expirySeconds: number
  }
  abuseLimits: {
    anonymousAttemptsPerIpMinute: number
    capabilityBundleRequestsPerMinute: number
    sealedSendsPerCapabilityMinute: number
    sealedSendsPerCapabilityDay: number
    federatedSealedSendsPerOriginMinute: number
    maximumEnvelopesPerRequest: number
    maximumRequestBytes: number
  }
}

export interface VerifiedMlsOrderingPolicyEntry {
  sequence: number
  previousPolicyHash?: string
  policyHash: string
  payloadDigest: string
  issuedAt: number
  federationIdentityGeneration: number
  federationIdentityKeyId: string
  federationIdentityPublicKey: string
  policy: MlsOrderingServicePolicy
}

export interface VerifiedMlsOrderingPolicyHistory {
  domain: string
  policies: VerifiedMlsOrderingPolicyEntry[]
}

export interface MlsAuthorityPolicyInspection {
  domain: string
  history?: VerifiedMlsOrderingPolicyHistory
  currentMatchesGroupPin: boolean
  unavailable: boolean
}

export interface MlsGroupAuthorizationPolicy {
  policyVersion: 1
  sequence: number
  applicationSenders: 1 | 2
}

export interface MlsGroupCryptographicPolicy {
  policyVersion: 1
  sequence: number
  suite: 3
  requiredPrivateControlExtension: number
  maximumPastEpochs: 2
  anonymousDeliveryRequired: true
  paddingBlockBytes: 1024
  maximumApplicationPlaintextBytes: number
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
      actionType: number
    }
    transitionDigest: string
    ownerChange?: {
      nextOwnerSet: MlsOwnerSet
    }
    membershipTransition?: {
      conversationId: string
      incarnation: number
      proposalId: string
    }
    incarnationRecovery?: MlsIncarnationRecovery['plan']
    nextAuthorizationPolicy?: MlsGroupAuthorizationPolicy
    nextCryptographicPolicy?: MlsGroupCryptographicPolicy
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

export interface PendingMlsClose {
  mlsGroupId: number[]
  currentRoster: MlsConversationMember[]
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

export interface PreparedMlsClose {
  pending: PreparedMlsMembershipChange['pending']
  control: PendingMlsClose
}

export interface FinalizedMlsClose {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface PendingMlsPolicyChange {
  mlsGroupId: number[]
  nextAuthorizationPolicy?: MlsGroupAuthorizationPolicy
  nextCryptographicPolicy?: MlsGroupCryptographicPolicy
  currentRoster: MlsConversationMember[]
  deliveries: unknown[]
  transition: {
    conversationId: string
    incarnation: number
    proposalId: string
  }
  voteRequest: PendingMlsClose['voteRequest']
  commitHash: string
  finalRequest?: unknown
}

export interface PreparedMlsPolicyChange {
  pending: PreparedMlsMembershipChange['pending']
  control: PendingMlsPolicyChange
}

export interface FinalizedMlsPolicyChange {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
}

export interface VerifiedMlsKeyPackage {
  wire: {
    deviceId: number
    manifestVersion: number
    suite: number
    keyPackageRef: string
    keyPackage: string
    expiresAt: number
  }
  credential: VerifiedMlsCredential
  anonymousDeliveryPublicKey: number[]
}

export interface MlsIncarnationRecovery {
  plan: {
    protocolVersion: number
    conversationId: string
    previousIncarnation: number
    proposalId: string
    previousGenesisHash: string
    previousHeight: number
    previousEpoch: number
    previousBlockHash?: string
    previousRosterCommitment: string
    participantDomains: string[]
    newGenesis: LocalMlsConversationRecord['request']['genesis']
    deliveries: Array<{ destination: string; deliveryDigest: string }>
  }
  proposal: unknown
  ownerApproval: unknown
}

export interface RecoverMlsConversationRequest {
  recovery: MlsIncarnationRecovery
  creator: AccountAddress
  creatorDeviceId: number
  members: MlsConversationMember[]
  deliveries: unknown[]
}

export interface RecoverMlsConversationResponse {
  conversationId: string
  previousIncarnation: number
  incarnation: number
  recoveryDigest: string
  status: 'active'
}

export interface PendingMlsRecovery {
  mlsGroupId: number[]
  newMlsGroupId: number[]
  request: RecoverMlsConversationRequest
  commitHash: string
}

export interface PreparedMlsRecovery {
  pending: PreparedMlsMembershipChange['pending']
  control: PendingMlsRecovery
}

export interface FinalizedMlsRecovery {
  group: LocalMlsGroupState
  conversation: LocalMlsConversationRecord
  archivedIncarnation: LocalMlsConversationRecord
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
  genesisGroupId: string
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
  fetchBundles(username: string): Promise<unknown>
  fetchSyncBundles(
    username: string,
    currentDeviceId: number,
  ): Promise<unknown>
  fetchMlsOrderingPolicy(domain: string): Promise<unknown>
  fetchManifest(username: string): Promise<unknown | null>
  fetchManifestHistory(
    username: string,
    fromSequence: string,
    toSequence: string,
    pageFromSequence: string,
  ): Promise<unknown>
  fetchSealedSenderPolicy(domain: string): Promise<unknown>
  fetchSenderCertificate(deviceId: number): Promise<unknown>
  fetchSealedBundles(
    username: string,
    capability: string,
  ): Promise<unknown>
  publishManifest(manifest: unknown): Promise<unknown>
  createHistoryTransfer(request: unknown): Promise<void>
  listHistoryTransfers(deviceId: number): Promise<unknown>
  acceptHistoryTransfer(
    transferId: string,
    deviceId: number,
    acceptance: unknown,
  ): Promise<void>
  uploadHistoryTransferFrame(
    transferId: string,
    deviceId: number,
    index: number,
    frame: unknown,
  ): Promise<void>
  drainHistoryTransferFrames(
    transferId: string,
    deviceId: number,
    after: number | null,
    limit: number,
  ): Promise<unknown>
  completeHistoryTransfer(
    transferId: string,
    deviceId: number,
    completion: unknown,
  ): Promise<void>
  cancelHistoryTransfer(transferId: string, deviceId: number): Promise<void>
  fetchOwnProfile(): Promise<unknown | null>
  publishProfile(profile: unknown): Promise<unknown>
  fetchProfile(username: string, version: string, accessKey: string): Promise<unknown | null>
  prekeyCount(deviceId: number): Promise<unknown>
  replenishPrekeys(deviceId: number, request: unknown): Promise<void>
  publishMlsKeyPackages(request: unknown): Promise<unknown>
  mlsKeyPackageCount(deviceId: number): Promise<unknown>
  createMlsConversation(request: unknown): Promise<unknown>
  recoverMlsConversation(request: RecoverMlsConversationRequest): Promise<unknown>
  fetchMlsRecovery(
    conversationId: string,
    incarnation: number,
  ): Promise<MlsIncarnationRecovery>
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
  listMlsInvitationFeedback(): Promise<MlsInvitationFeedback[]>
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
  mlsGroupDevices(mlsGroupId: Uint8Array): Promise<MlsConversationDevice[]>
  prepareMlsMembershipChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    nextRoster: MlsConversationMember[],
    additions: unknown,
    nowSeconds: string,
  ): Promise<PreparedMlsMembershipChange>
  prepareMlsDeviceSync(
    mlsGroupId: Uint8Array,
    proposalId: string,
    additions: unknown,
    removedDeviceIds: number[],
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
  createMlsInvitationAcceptanceMessage(
    mlsGroupId: Uint8Array,
    invitedEpoch: string,
    acceptedAtSeconds: string,
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
  prepareMlsClose(
    mlsGroupId: Uint8Array,
    proposalId: string,
    nowSeconds: string,
  ): Promise<PreparedMlsClose>
  pendingMlsCloses(): Promise<PendingMlsClose[]>
  mlsCloseHasOwnerQuorum(mlsGroupId: Uint8Array): Promise<boolean>
  buildMlsCloseCommitRequest(
    mlsGroupId: Uint8Array,
    quorumCertificate: unknown,
  ): Promise<unknown>
  finalizeMlsClose(
    mlsGroupId: Uint8Array,
    acknowledgement: unknown,
  ): Promise<FinalizedMlsClose>
  prepareMlsAuthorizationPolicyChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    nextPolicy: MlsGroupAuthorizationPolicy,
    nowSeconds: string,
  ): Promise<PreparedMlsPolicyChange>
  prepareMlsCryptographicPolicyChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    nextPolicy: MlsGroupCryptographicPolicy,
    nowSeconds: string,
  ): Promise<PreparedMlsPolicyChange>
  pendingMlsPolicyChanges(): Promise<PendingMlsPolicyChange[]>
  mlsPolicyChangeHasOwnerQuorum(mlsGroupId: Uint8Array): Promise<boolean>
  buildMlsPolicyCommitRequest(
    mlsGroupId: Uint8Array,
    quorumCertificate: unknown,
  ): Promise<unknown>
  finalizeMlsPolicyChange(
    mlsGroupId: Uint8Array,
    acknowledgement: unknown,
  ): Promise<FinalizedMlsPolicyChange>
  prepareMlsGroupRecovery(
    mlsGroupId: Uint8Array,
    newMlsGroupId: Uint8Array,
    proposalId: string,
    authorityPolicies: unknown[],
    additions: VerifiedMlsKeyPackage[],
    createdAtSeconds: string,
  ): Promise<PreparedMlsRecovery>
  pendingMlsRecoveries(): Promise<PendingMlsRecovery[]>
  localMlsIncarnationHistory(): Promise<LocalMlsConversationRecord[]>
  mlsRecoveryHasOwnerQuorum(mlsGroupId: Uint8Array): Promise<boolean>
  finalizeMlsGroupRecovery(
    mlsGroupId: Uint8Array,
    acknowledgement: RecoverMlsConversationResponse,
  ): Promise<FinalizedMlsRecovery>
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
  joinMlsFromRecoveryWelcome(
    envelopeId: string,
    cursor: string,
    sendId: string,
    mlsGroupId: Uint8Array,
    welcome: Uint8Array,
    expectedMembers: VerifiedMlsCredential[],
    recovery: MlsIncarnationRecovery,
  ): Promise<JoinedMlsConversation>
  inspectMlsWelcome(
    mlsGroupId: Uint8Array,
    welcome: Uint8Array,
  ): Promise<MlsWelcomeInspection>
  resolveMlsWelcomeClaims(
    claimedMembers: ClaimedMlsCredential[],
  ): Promise<VerifiedMlsCredential[]>
  resolveMlsSenderClaim(
    claimedSender: ClaimedMlsCredential,
  ): Promise<VerifiedMlsCredential>
  fetchVerifiedMlsOrderingPolicy(domain: string): Promise<unknown>
  fetchVerifiedMlsOrderingPolicyDetails(
    domain: string,
  ): Promise<VerifiedMlsOrderingPolicyHistory>
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
  ): Promise<VerifiedMlsKeyPackage[]>
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
    replyTo?: string,
  ): Promise<MlsOutboxEntry>
  createMlsAttachmentMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    descriptor: ChatAttachmentDescriptorV1,
    createdAtMs: string,
  ): Promise<MlsOutboxEntry>
  createMlsReactionMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    targetMessageId: string,
    emoji: string,
    active: boolean,
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
  pendingSendCount(): Promise<number>
  quarantineInbound(id: string): Promise<void>
  reconcile(): Promise<ReceiveReport>
  resolveDeadLetter(id: string): Promise<void>
  sendText(
    sendId: string,
    peer: string,
    sentAt: string,
    text: string,
    replyTo?: string,
  ): Promise<SendSummary>
  sendAttachment(
    sendId: string,
    peer: string,
    sentAt: string,
    descriptor: ChatAttachmentDescriptorV1,
  ): Promise<SendSummary>
  sendReaction(
    sendId: string,
    peer: string,
    sentAt: string,
    targetMessageId: string,
    emoji: string,
    active: boolean,
  ): Promise<SendSummary>
  mediaDeliveryCapability(peer: string): Promise<string>
  syncManifest(): Promise<unknown>
  requestHistoryTransfer(): Promise<ChatHistoryTransferRequest>
  listHistoryTransfers(): Promise<ChatHistoryTransferList>
  approveHistoryTransfer(
    request: ChatHistoryTransferRequest,
    recordLimit: number,
    plaintextByteLimit: string,
  ): Promise<{ acceptance: unknown; frameCount: number }>
  downloadHistoryTransfer(transferId: string): Promise<ChatHistoryTransferDownloadResult>
  safetyNumber(peer: string): Promise<SafetyNumberV1>
  verifySafetyNumber(peer: string, scannedPayload: string): Promise<SafetyNumberV1>
  free(): void
}

export interface SafetyNumberV1 {
  localAccount: string
  peerAccount: string
  fingerprint: string
  qrPayload: string
  authorityKeyId: string
  trust: 'Tofu' | 'Verified' | 'Quarantined'
  continuityGap: boolean
  retainedAuthorityKeyId?: string
  quarantineReason?: string
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
    ): Promise<WasmChatClientHandle>
  }
}
