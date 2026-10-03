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
  mutation?: ChatMessageMutationV1
  receipt?: ChatReceiptV1
  typing?: ChatTypingV1
  /** A 1:1 call's signaling; live only, never in history. */
  call?: ChatCallSignal
  /** A call in the timeline, written by this device. */
  callLog?: ChatCallLog
  /** A group call started or ended (MLS only). */
  groupCall?: ChatGroupCall
  disappearingTimer?: ChatDisappearingTimerV1
  /** Same-account controls: only ever in Note to Self, from this account. */
  conversationState?: ChatConversationStateV1
  readPosition?: ChatReadPositionV1
  deleteForMe?: ChatDeleteForMeV1
  viewOnceOpened?: ChatViewOnceOpenedV1
  stickerSaved?: ChatStickerV1
  stickerRemoved?: { stickerId: string }
  /** The image attachment is a sticker. */
  sticker?: { emoji?: string }
  poll?: ChatPollV1
  /** A place sent once (docs/plans/maps.md). */
  location?: ChatLocationV1
  /** A live location: its stream and key (docs/plans/maps.md). */
  liveLocation?: ChatLiveLocationV1
  /** The sharer ended a live location early. */
  liveLocationStop?: { shareId: string }
  pollVote?: ChatPollVoteV1
  pollTerminate?: { targetMessageId: string }
  /** A group change, written by this device's engine from an applied Commit. */
  groupUpdate?: ChatGroupUpdate
  mentions?: ChatMentionV1[]
  linkPreview?: ChatLinkPreviewV1
  forwarded?: boolean
  viewOnce?: boolean
  expiresAfterSeconds?: number
  expiresAtMs?: number
}

/** "Muted until turned back on", as in Signal Desktop. */
export const MUTED_FOREVER_MS = Number.MAX_SAFE_INTEGER

/**
 * One conversation's list state on this account, replaced as a whole; the
 * record with the highest `(revision, sourceDeviceId)` wins on every device.
 */
export interface ChatConversationStateV1 {
  conversation: ConversationId
  revision: number
  sourceDeviceId: number
  updatedAtMs: number
  pinned: boolean
  archived: boolean
  mutedUntilMs?: number
  markedUnread: boolean
}

/**
 * Read up to and including `throughMessageId`; `readThroughMs` is the
 * reading device's time for that message, used when the message is not here.
 */
export interface ChatReadPositionV1 {
  conversation: ConversationId
  throughMessageId: string
  readThroughMs: number
}

/** `length` UTF-16 units from `start` of the text stand for `member` (canonical address). */
export interface ChatMentionV1 {
  start: number
  length: number
  member: string
}

/** A preview of an https link in the text, made by the sender. */
export interface ChatLinkPreviewV1 {
  url: string
  title: string
  description?: string
  /** JPEG, PNG or WebP, at most 24 KiB, standard base64. */
  image?: { contentType: 'image/jpeg' | 'image/png' | 'image/webp'; data: string }
}

/** What a visible message may carry beside its body. */
export interface ChatMessageExtras {
  mentions?: ChatMentionV1[]
  linkPreview?: ChatLinkPreviewV1
  forwarded?: boolean
  /** Attachments (photo or video) only. */
  viewOnce?: boolean
  /** A WebP or PNG image of at most 512 KiB sent as a sticker. */
  sticker?: { emoji?: string }
}

/** A sticker in this account's collection (image inline: WebP/PNG ≤ 48 KiB). */
export interface ChatStickerV1 {
  stickerId: string
  emoji?: string
  contentType: 'image/webp' | 'image/png'
  data: string
}

export const STICKER_IMAGE_MAX_BYTES = 48 * 1024

export const LINK_PREVIEW_IMAGE_MAX_BYTES = 24 * 1024

/** One visible change of an applied group Commit (members are canonical addresses). */
export type ChatGroupUpdateChange =
  | { type: 'nameChanged'; name: string }
  | { type: 'descriptionChanged'; description: string }
  | { type: 'pictureChanged'; removed: boolean }
  | { type: 'memberAdded' | 'memberRemoved' | 'memberLeft'; member: string }
  | { type: 'adminGranted' | 'adminRevoked' | 'ownerAdded' | 'ownerRemoved'; member: string }
  | { type: 'sendersChanged' | 'editorsChanged'; administratorsOnly: boolean }
  | { type: 'inviteLinkEnabled' | 'inviteLinkApprovalChanged'; approvalRequired: boolean }
  | { type: 'inviteLinkDisabled' | 'inviteLinkReset' }
  | { type: 'closed' }

export interface ChatGroupUpdate {
  /** Who made the change (canonical address). */
  actor: string
  changes: ChatGroupUpdateChange[]
}

/** A poll: 2–10 distinct options of up to 100 characters, a question of up to 200. */
export interface ChatPollV1 {
  question: string
  options: string[]
  allowMultiple?: boolean
}

/** A member's current choice (ascending option indexes; empty takes it back). */
export interface ChatPollVoteV1 {
  targetMessageId: string
  options: number[]
}

export const POLL_LIMITS = { question: 200, option: 100, minOptions: 2, maxOptions: 10 } as const

/** A place: degrees, and an optional label of up to 100 characters. */
export interface ChatLocationV1 {
  lat: number
  lon: number
  label?: string
}

export const LOCATION_LABEL_MAX = 100

/**
 * A live location's stream (docs/plans/maps.md "Live location"): generation 1
 * starts the share; each later generation is a new stream and key for the
 * same share.
 */
export interface ChatLiveLocationV1 {
  shareId: string
  generation: number
  /** The sharer's server, which holds the stream. */
  server: string
  /** 16 random bytes, lowercase hex. */
  streamId: string
  /** The stream key, standard base64 (32 bytes). */
  key: string
  /** Standard base64 (32 bytes); presented to read the stream. */
  readCapability: string
  /** When the share ends, Unix milliseconds. */
  untilMs: number
}

export const LIVE_LOCATION_MAX_MS = 8 * 3600 * 1000

/** A view-once photo or video was opened on one of this account's devices. */
export interface ChatViewOnceOpenedV1 {
  conversation: ConversationId
  messageId: string
  /** Canonical address of its sender. */
  sender: string
  timestampMs: number
  video: boolean
}

export interface ChatDeleteForMeV1 {
  conversation: ConversationId
  messageIds: string[]
}

export type ChatAccountControl =
  | { kind: 'conversationState'; body: ChatConversationStateV1 }
  | { kind: 'readPosition'; body: ChatReadPositionV1 }
  | { kind: 'deleteForMe'; body: ChatDeleteForMeV1 }
  | { kind: 'viewOnceOpened'; body: ChatViewOnceOpenedV1 }
  | { kind: 'stickerSaved'; body: ChatStickerV1 }
  | { kind: 'stickerRemoved'; body: { stickerId: string } }

export interface ChatReactionV1 {
  targetMessageId: string
  emoji: '👍' | '❤️' | '😂' | '😮' | '😢' | '🙏'
  active: boolean
}

export interface ChatMessageMutationV1 {
  targetMessageId: string
  operation: 'edit' | 'delete'
  replacementText?: string
}

export interface ChatReceiptV1 {
  messageIds: string[]
  state: 'delivered' | 'read'
}

export interface ChatTypingV1 {
  active: boolean
}

export interface ChatDisappearingTimerV1 {
  durationSeconds?: number
}

export interface ChatExpiryReport {
  expiredMessages: number
  expiredAttachmentIds: string[]
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
  backupMediaId?: string
  /** Account-local authenticated reference used only by continuous backup reconciliation. */
  backupMediaReferenceId?: string
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
  messages: ReceivedChatMessage[]
  synced: string[]
  contactSynced: string[]
  profileKeyUpdated: string[]
  profilesRefreshed: string[]
  suppressed: string[]
  undecodable: string[]
  errors: InboundFailure[]
  duplicates: string[]
}

export interface ReceivedChatMessage {
  id: string
  conversation: ConversationId
  peer: string
  senderDeviceId: number
  cursor: string
  content: ChatContentView
}

export type ChatCallMedia = 'audio' | 'video'

export interface ChatIceCandidate {
  candidate: string
  sdpMid?: string
  sdpMLineIndex?: number
}

export type ChatHangupReason =
  | 'normal'
  | 'declined'
  | 'answeredElsewhere'
  | 'declinedElsewhere'
  | 'unanswered'
  | 'failed'

export type ChatCallSignalKind =
  | { type: 'offer'; media: ChatCallMedia; sdp: string }
  | { type: 'answer'; sdp: string }
  | { type: 'ice'; candidates: ChatIceCandidate[] }
  | { type: 'hangup'; reason: ChatHangupReason }
  | { type: 'busy' }

/** One call signal (docs/chat-calls.md). */
export interface ChatCallSignal {
  callId: string
  /** The device that placed the call; replies go only to it. */
  callerDeviceId: number
  /** The callee device that answered, once one has. */
  calleeDeviceId?: number
  signal: ChatCallSignalKind
}

export type ChatCallOutcome = 'answered' | 'missed' | 'declined' | 'unanswered' | 'busy' | 'failed'

export interface ChatCallLog {
  callId: string
  incoming: boolean
  media: ChatCallMedia
  outcome: ChatCallOutcome
  startedAtMs: number
  /** For an answered call. */
  durationSeconds?: number
}

/** A group call's announcement to the group (docs/chat-calls.md). */
export interface ChatGroupCall {
  callId: string
  event: 'started' | 'ended'
  /** The server whose SFU hosts the room. */
  host: string
  /** 32 lowercase hex characters: the capability to join. */
  roomId: string
  media: ChatCallMedia
  /** Standard base64 of 32 bytes; keys the participant tags. */
  secret: string
}

/** A call signal received from `peer`'s device `senderDeviceId`. */
export interface ChatCallEvent {
  /** Canonical address of the other person. */
  peer: string
  senderDeviceId: number
  sentAt: string
  call: ChatCallSignal
}

export interface ChatCallServers {
  iceServers: RTCIceServer[]
  /** A TURN relay is available. */
  relay: boolean
  expiresAt?: number
}

export interface ChatTypingEvent {
  conversation: ConversationId
  sender: string
  active: boolean
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
  /** Signal's "about" line: one line, at most 140 characters. */
  about?: string
  revision: string
}

export const PROFILE_ABOUT_MAX_CHARS = 140

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
  /** The server fetches public pages for the sender's link previews. */
  linkPreviews?: boolean
  /** This server's SFU hosts group calls, so accounts here can start them. */
  groupCalls?: boolean
  /** VAPID key for Web Push wake-ups (base64url), when the server sends them. */
  webPushPublicKey?: string
  /** Present only after immutable media works locally, federated, and in the browser. */
  media?: {
    protocolVersion: number
    suites: number[]
    maximumPlaintextBytes: number
  }
  backup?: {
    protocolVersion: number
    suites: number[]
    protectionDomains: number[]
    defaultStorageQuotaBytes: number
    maximumSegmentCiphertextBytes: number
    maximumBaseCiphertextBytes: number
    segmentPageLimit: number
    deliveryMediaRetentionDays: number
    alwaysEnabled: boolean
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
  /** The group's name, description and picture, once it has them. */
  currentGroupInfo?: MlsGroupInfo
  /** This account asked to leave: read-only here until an administrator removes it. */
  left?: boolean
  /** Members who asked to leave and are not removed yet (canonical addresses). */
  departingMembers?: string[]
}

/** Encrypted in the group state; only members see it. */
export interface MlsGroupInfo {
  /** One more with every change, starting at one. */
  sequence: number
  /** 1 to 32 characters, no surrounding spaces. */
  name: string
  /** Up to 480 characters. */
  description?: string
  /** JPEG, PNG or WebP, at most 48 KiB, as standard base64. */
  avatar?: { contentType: 'image/jpeg' | 'image/png' | 'image/webp'; data: string }
  /** The group link, while it is on; only administrators change it. */
  inviteLink?: MlsGroupInviteLink
}

/** A group link (docs/chat-invite-links.md). */
export interface MlsGroupInviteLink {
  /** Standard base64 of 32 random bytes. */
  secret: string
  /** The server that keeps the link's mailbox. */
  host: string
  approvalRequired: boolean
}

/** What a link shows before joining; sealed so only link holders read it. */
export interface InviteLinkPreview {
  conversationId: string
  name: string
  description?: string
  avatar?: MlsGroupInfo['avatar']
  memberCount: number
  approvalRequired: boolean
}

export interface InviteJoinRequest {
  requester: AccountAddress
  createdAtMs: number
}

export type InviteRequestStatus = 'pending' | 'approved' | 'denied'

export type InviteLinkOperation =
  | { op: 'put'; linkId: string; manageToken: string; preview: string }
  | { op: 'delete'; linkId: string; manageToken: string }
  | { op: 'preview'; linkId: string }
  | { op: 'request'; linkId: string; request: string; statusToken: string }
  | { op: 'requests'; linkId: string; manageToken: string }
  | { op: 'decide'; linkId: string; manageToken: string; requestId: string; approve: boolean }
  | { op: 'status'; linkId: string; requestId: string; statusToken: string }
  | { op: 'cancel'; linkId: string; requestId: string; statusToken: string }

export interface InviteLinkRequestEntry {
  requestId: string
  /** The server the request came through: the requester's own. */
  originDomain: string
  request: string
  status: InviteRequestStatus
  createdAtMs: number
}

export type InviteLinkResult =
  | { result: 'done' }
  | { result: 'preview'; preview: string }
  | { result: 'requested'; requestId: string }
  | { result: 'requests'; requests: InviteLinkRequestEntry[] }
  | { result: 'status'; status: InviteRequestStatus }

/** The link functions of the chat WASM module. */
export interface InviteLinkCrypto {
  inviteLinkNew(host: string, approvalRequired: boolean): MlsGroupInviteLink
  inviteLinkKeys(link: MlsGroupInviteLink): { linkId: string; manageToken: string }
  inviteLinkFragment(link: MlsGroupInviteLink): string
  inviteLinkParse(fragment: string): { secret: string; host: string }
  inviteLinkSealPreview(link: MlsGroupInviteLink, preview: InviteLinkPreview): string
  inviteLinkOpenPreview(link: MlsGroupInviteLink, sealed: string): InviteLinkPreview
  inviteLinkSealRequest(link: MlsGroupInviteLink, request: InviteJoinRequest): string
  inviteLinkOpenRequest(link: MlsGroupInviteLink, sealed: string): InviteJoinRequest
  inviteStatusToken(): string
}

/** Someone waiting for an administrator to let them in (administrators see these). */
export interface GroupJoinRequest {
  conversationId: string
  /** Canonical address. */
  requester: string
  createdAtMs: number
}

/** A request this account made through a group link. */
export interface OwnJoinRequest {
  linkId: string
  host: string
  secret: string
  requestId: string
  statusToken: string
  conversationId: string
  groupName: string
  requestedAtMs: number
  /** `gone`: the link was turned off or reset before anyone decided. */
  status: 'pending' | 'denied' | 'gone'
}

export const MLS_GROUP_NAME_MAX_CHARS = 32
export const MLS_GROUP_DESCRIPTION_MAX_CHARS = 480
export const MLS_GROUP_AVATAR_MAX_BYTES = 48 * 1024

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
  /** Who may change the group's information: 1 members, 2 (or absent) administrators. */
  groupInfoEditors?: 1 | 2
}

export interface MlsGroupCryptographicPolicy {
  policyVersion: 1
  sequence: number
  suite: 3
  requiredPrivateControlExtension: number
  maximumPastEpochs: 2
  anonymousDeliveryRequired: true
  paddingBlockBytes: 160
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
  callInviteLink(host: string, operation: InviteLinkOperation): Promise<InviteLinkResult>
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
    groupInfo: MlsGroupInfo | null,
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
  prepareMlsGroupInfoChange(
    mlsGroupId: Uint8Array,
    proposalId: string,
    groupInfo: MlsGroupInfo,
    nowSeconds: string,
  ): Promise<PreparedMlsMembershipChange>
  /**
   * `account` (canonical `user@server`) names a fellow member whose leaves
   * are brought in line with their signed manifest; absent, this account's.
   */
  prepareMlsDeviceSync(
    mlsGroupId: Uint8Array,
    proposalId: string,
    additions: unknown,
    removedDeviceIds: number[],
    nowSeconds: string,
    account?: string,
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
  requestMlsLeave(mlsGroupId: Uint8Array, nowSeconds: string): Promise<MlsOutboxEntry | null>
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
  /**
   * The device ids of an account's current signed manifest, verified; empty
   * while any of them is not yet an MLS device.
   */
  verifiedManifestMlsDeviceIds(account: string): Promise<number[]>
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
    expiresAfterSeconds?: number,
    extras?: ChatMessageExtras | null,
  ): Promise<MlsOutboxEntry>
  createMlsAttachmentMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    descriptor: ChatAttachmentDescriptorV1,
    createdAtMs: string,
    expiresAfterSeconds?: number,
    extras?: ChatMessageExtras | null,
  ): Promise<MlsOutboxEntry>
  createMlsPollContent(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    kind: 'poll' | 'pollVote' | 'pollTerminate' | 'location' | 'liveLocation' | 'liveLocationStop' | 'groupCall',
    body: unknown,
    createdAtMs: string,
    expiresAfterSeconds?: number,
  ): Promise<MlsOutboxEntry>
  exportMlsCallKey(mlsGroupId: Uint8Array, callId: string): Promise<{ epoch: string; key: number[] }>
  createMlsDisappearingTimer(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    createdAtMs: string,
    durationSeconds?: number,
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
  createMlsMessageMutation(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    targetMessageId: string,
    operation: 'edit' | 'delete',
    replacementText: string | undefined,
    createdAtMs: string,
  ): Promise<MlsOutboxEntry>
  createMlsReceiptMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
    messageIds: string[],
    state: 'delivered' | 'read',
    createdAtMs: string,
  ): Promise<MlsOutboxEntry>
  createMlsTypingMessage(
    sendId: string,
    conversationId: string,
    incarnation: string,
    mlsGroupId: Uint8Array,
    sentAt: string,
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
  purgeExpiredMessages(nowMs: string): Promise<ChatExpiryReport>
  contacts(): Promise<ContactRecord[]>
  profile(): Promise<ChatProfile>
  profiles(): Promise<PeerChatProfile[]>
  setProfile(
    displayName: string,
    avatar?: string,
    avatarContentType?: string,
    about?: string,
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
    expiresAfterSeconds?: number,
    extras?: ChatMessageExtras | null,
  ): Promise<SendSummary>
  sendAttachment(
    sendId: string,
    peer: string,
    sentAt: string,
    descriptor: ChatAttachmentDescriptorV1,
    expiresAfterSeconds?: number,
    extras?: ChatMessageExtras | null,
  ): Promise<SendSummary>
  sendPollContent(
    sendId: string,
    peer: string,
    sentAt: string,
    kind: 'poll' | 'pollVote' | 'pollTerminate' | 'location' | 'liveLocation' | 'liveLocationStop',
    body: unknown,
    expiresAfterSeconds?: number,
  ): Promise<SendSummary>
  sendReaction(
    sendId: string,
    peer: string,
    sentAt: string,
    targetMessageId: string,
    emoji: string,
    active: boolean,
  ): Promise<SendSummary>
  sendMessageMutation(
    sendId: string,
    peer: string,
    sentAt: string,
    targetMessageId: string,
    operation: 'edit' | 'delete',
    replacementText?: string,
  ): Promise<SendSummary>
  sendReceipt(
    sendId: string,
    peer: string,
    sentAt: string,
    messageIds: string[],
    state: 'delivered' | 'read',
  ): Promise<SendSummary>
  sendTyping(
    sendId: string,
    peer: string,
    sentAt: string,
    active: boolean,
  ): Promise<SendSummary>
  sendCallSignal(sendId: string, peer: string, sentAt: string, signal: ChatCallSignal): Promise<SendSummary>
  refreshProfile(): Promise<void>
  recordCallLog(peer: string, body: ChatCallLog): Promise<void>
  sendDisappearingTimer(
    sendId: string,
    peer: string,
    sentAt: string,
    durationSeconds?: number,
  ): Promise<SendSummary>
  sendAccountControl(
    sendId: string,
    sentAt: string,
    kind: ChatAccountControl['kind'],
    body: ChatAccountControl['body'],
  ): Promise<SendSummary>
  startDisappearingExpiry(
    sendId: string,
    sentAt: string,
    conversation: ConversationId,
    targetMessageId: string,
    startedAtMs: string,
  ): Promise<SendSummary>
  mediaDeliveryCapability(peer: string): Promise<string>
  syncManifest(): Promise<unknown>
  revokeManifestDevice(deviceId: number): Promise<unknown>
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

/** The account's profile as the account app edits it (docs/plans/unified-profile.md). */
export interface AccountProfileView {
  displayName: string
  about?: string
  /** Standard base64. */
  avatar?: string
  avatarContentType?: string
  revision: string
}

export interface AccountProfileInput {
  displayName: string
  about?: string
  avatar?: string
  avatarContentType?: string
}

/** Where someone's profile is, from their profile key. */
export interface ProfileLookup {
  /** Standard base64 of the 32-byte profile key. */
  key: string
  version: string
  /** Standard base64; the `x-kutup-profile-access-key` header. */
  accessKey: string
}

export interface ChatWasmModule extends InviteLinkCrypto {
  /** The account's own profile key, from the master key. */
  accountProfileKey(masterKey: Uint8Array, current: unknown, account: string): ProfileLookup
  /** Where to fetch a profile, from its key (standard base64). */
  profileLookup(key: string): ProfileLookup
  /** Open someone's fetched profile with their key (standard base64). */
  profileOpenPeer(peer: string, encrypted: unknown, key: string): AccountProfileView
  /** Open the account's profile from the master key (no chat device). */
  accountProfileOpen(masterKey: Uint8Array, current: unknown, account: string): AccountProfileView
  /** Seal the next profile revision (or the first) as the account app. */
  accountProfileSeal(masterKey: Uint8Array, current: unknown | null, update: AccountProfileInput, account: string): unknown
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
