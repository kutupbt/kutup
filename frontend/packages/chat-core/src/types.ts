import type { AccountRef } from '@kutup/crypto/accountRef'

export type { AccountRef }
export interface ChatContentView {
  version: number
  kind: string
  sentAt: string
  seq: string
  messageId: string
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
  /** A group call started or ended (groups' calls are not built yet). */
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
  /** Stands where a message from the peer could not be read. */
  undecryptable?: boolean
  /** This device's line saying the peer's safety number changed (never sent). */
  safetyNumberChanged?: boolean
  /** This device's line saying the peer changed their username, from their own verified rename chain (never sent). */
  peerRenamed?: { previous: string; current: string; sequence: number }
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

/** `length` UTF-16 units from `start` of the text stand for `member`. */
export interface ChatMentionV1 {
  start: number
  length: number
  member: AccountRef
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

/** One visible change of an applied group Commit. */
export type ChatGroupUpdateChange =
  | { type: 'nameChanged'; name: string }
  | { type: 'descriptionChanged'; description: string }
  | { type: 'pictureChanged'; removed: boolean }
  | { type: 'memberAdded' | 'memberRemoved' | 'memberLeft'; member: AccountRef }
  | { type: 'adminGranted' | 'adminRevoked' | 'ownerAdded' | 'ownerRemoved'; member: AccountRef }
  | { type: 'sendersChanged' | 'editorsChanged'; administratorsOnly: boolean }
  | { type: 'inviteLinkEnabled' | 'inviteLinkApprovalChanged'; approvalRequired: boolean }
  | { type: 'inviteLinkDisabled' | 'inviteLinkReset' }
  | { type: 'closed' }
  /** The group's disappearing-messages timer; 0 is off. */
  | { type: 'timerChanged'; seconds: number }
  | { type: 'addersChanged'; administratorsOnly: boolean }
  | { type: 'membersInvited' | 'invitationsRevoked'; count: number }
  /** The actor joined, or asked to, or withdrew the request. */
  | { type: 'joinedByInvitation' | 'joinedFromLink' | 'joinRequested' | 'joinRequestCanceled' }
  | { type: 'joinRequestApproved' | 'joinRequestDenied' | 'memberBanned' | 'memberUnbanned'; member: AccountRef }

export interface ChatGroupUpdate {
  /** Who made the change. */
  actor: AccountRef
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
  /** Who sent it. */
  sender: AccountRef
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

/**
 * `mls_group` is the removed MLS groups' kind, kept so stored ledger records
 * still read; pairwise groups take no attachments yet.
 */
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

export type ConversationId =
  | { kind: 'direct'; account: AccountRef }
  | { kind: 'group'; groupId: string }

/**
 * A position in one tab's change journal (`ChatService.changesSince`):
 * its store commits, and how many times another tab wrote since it opened.
 */
export interface ChangeMark {
  commits: number
  epoch: number
}

export interface ChatHistoryEntry {
  id: string
  conversation: ConversationId
  /** Who wrote it: an account's key, `aci:<uuid>@<server>` (this account's own when outgoing). Which chat: `conversation`. */
  sender: string
  direction: 'incoming' | 'outgoing'
  senderDeviceId?: number
  cursor?: string
  timestampMs: number
  delivered: boolean
  deduplicated: boolean
  /** A group message: how many member accounts it never reached. */
  failedRecipients?: number
  /**
   * A pairwise group message sent from here: how many member accounts this
   * account's server hasn't taken it for yet (0: sent, still followed until
   * every member's server has it).
   */
  waitingRecipients?: number
  content: ChatContentView
}

export interface SendSummary {
  delivered: boolean
  deduplicated: boolean
  attempts: number
  safetyNumberChanges: string[]
}

/** A pairwise group this device knows (docs/plans/pairwise-groups.md). */
export interface ChatGroupSummary {
  /** 32 bytes, base64url: the group's id, from its master key. */
  groupId: string
  title?: string | null
  status: 'invited' | 'requesting' | 'member' | 'gone'
  revision?: number | null
  memberCount: number
  /** Who invited this account (`aci:<uuid>@<server>`), for an invitation. */
  inviter?: string | null
  /** A member's message named another history of the group than this device's. */
  forkSuspected: boolean
  /** When this device first learned of the group (made it or was invited), ms. */
  knownSinceMs?: number | null
  /** Who may rename it (`attributes`) and add members (`members`), as its verified state says. */
  access?: { attributes: ChatGroupAccessRequired; members: ChatGroupAccessRequired; addFromInviteLink: ChatGroupAccessRequired } | null
  /** This account may send there now: a member, the group not ended, an administrator while it is announcements-only. */
  maySend: boolean
  announcementsOnly: boolean
  terminated: boolean
  /** The group's disappearing-messages timer in seconds; 0 is off. */
  timerSeconds: number
  /** The avatar blob's hash, when the group has a picture: a new one means a new picture. */
  avatarHash?: string | null
}

/** A pairwise group's picture: standard base64 and its type. */
export interface ChatGroupAvatar {
  data: string
  contentType: string
}

export type ChatGroupAvatarFetch =
  | ({ kind: 'image' } & ChatGroupAvatar)
  | { kind: 'none' }
  | { kind: 'unreachable'; reason: string }

/** Who may do something in a group (Signal's `AccessControl.AccessRequired`). */
export type ChatGroupAccessRequired = 'any' | 'member' | 'administrator' | 'unsatisfiable'

/** A member of a pairwise group, as this device checked them. */
export interface ChatGroupMember {
  /** The member's key in this group: what changes about them name. */
  pseudonym: string
  administrator: boolean
  joinedAtRevision: number
  /** Their account when their binding verified; absent for an unverified member. */
  account?: string | null
}

/** What a group link leads to, read before joining. */
export type ChatGroupLinkPreview =
  | {
      kind: 'group'
      groupId: string
      title?: string | null
      description?: string | null
      memberCount: number
      requiresApproval: boolean
      /** This account's place in it already. */
      status?: ChatGroupSummary['status'] | null
      avatar?: ChatGroupAvatar | null
    }
  /** Reset, turned off, or the group gone. */
  | { kind: 'invalid' }
  | { kind: 'unreachable'; reason: string }

/** A join through a group link. */
export type ChatGroupLinkJoin =
  | { kind: 'joined'; sync: ChatGroupSync }
  /** Asked: an administrator sees it at their next sync. */
  | { kind: 'requested' }
  | { kind: 'invalid' }
  | { kind: 'unreachable'; reason: string }

/** Where this account's request to join a group stands. */
export type ChatGroupRequestOutcome =
  | { kind: 'pending' }
  | { kind: 'joined'; sync: ChatGroupSync }
  | { kind: 'denied' }
  | { kind: 'canceled' }
  | { kind: 'unreachable'; reason: string }

/** What the group link does: anyone with it joins, asks, or it is off. */
export type ChatGroupLinkMode = 'off' | 'join' | 'approve'

/** A request to join, as an administrator sees it. */
export interface ChatGroupRequest {
  pseudonym: string
  requestedAtRevision: number
  /** Their account when the binding verified. */
  account?: string | null
  /** Their account is banned: it can't be approved. */
  banned: boolean
  /** The account their entry names, verified or not. */
  claimed?: string | null
  /** That account can't be checked now: not approvable yet. */
  unconfirmed: boolean
}

/** A ban: an account with its banned pseudonyms, or a lone pseudonym nobody verified. */
export interface ChatGroupBan {
  account?: string | null
  pseudonyms: string[]
}

/** A pairwise group's settings, requests and bans, from its verified state. */
export interface ChatGroupDetails {
  groupId: string
  title?: string | null
  description?: string | null
  timerSeconds: number
  announcementsOnly: boolean
  terminated: boolean
  access: { attributes: ChatGroupAccessRequired; members: ChatGroupAccessRequired; addFromInviteLink: ChatGroupAccessRequired }
  link: { mode: ChatGroupLinkMode; fragment?: string | null }
  administrator: boolean
  requests: ChatGroupRequest[]
  bans: ChatGroupBan[]
  /** Members whose account is banned (back through the link): administrators remove them. */
  bannedMembers: string[]
  /** No room on the ban list for another account: a ban or denial holds for the pseudonym only. */
  banListFull: boolean
  /** The ban list doesn't open: bans can't be read or changed until it does. */
  banListUnreadable: boolean
  hasAvatar: boolean
}

/** How a catch-up with a group's home ended. */
export type ChatGroupSync =
  | { kind: 'current'; revision: number; keyConfirmed: boolean }
  | { kind: 'unreachable'; reason: string }
  | { kind: 'maybeRemoved'; sinceMs: number }
  | { kind: 'gone' }
  /** Moved on, with more of the log still to read. */
  | { kind: 'partial'; revision: number }

/** What a group send reached: member accounts delivered and still pending. */
export interface ChatGroupSend {
  sendId: string
  delivered: number
  pending: number
  /** Member accounts it never reached (refused for good, or a week passed). */
  failed: number
  /** Why this pass couldn't try it at all (it waits for the next). */
  error?: string
}

/** An invitation to a pairwise group that arrived. */
export interface ChatGroupInvite {
  groupId: string
  /** The inviter's account. */
  from: string
  /** From someone who isn't a contact: a message request. */
  request: boolean
}

/** The id of a pairwise group (32 bytes, base64url). */
export function isChatGroupId(groupId: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(groupId)
}

export interface InboundFailure {
  id: string
  kind: string
  error: string
}

export interface ReceiveReport {
  messages: ReceivedChatMessage[]
  /** Invitations to pairwise groups that arrived. */
  groupInvites?: ChatGroupInvite[]
  /** Group envelopes left queued until their sender can be confirmed. */
  held?: string[]
  synced: string[]
  contactSynced: string[]
  profileKeyUpdated: string[]
  profilesRefreshed: string[]
  suppressed: string[]
  undecodable: string[]
  errors: InboundFailure[]
  duplicates: string[]
  /** Unreadable envelopes given up on, the sender's session refreshed. */
  repaired?: string[]
  /** Queued messages that could not be delivered on this pass. */
  sendFailures?: Array<{ sendId: string; peer: string; error: string }>
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
  /** The other person's account key. */
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
  /**
   * Pairwise groups (docs/plans/pairwise-groups.md): this server hosts them
   * and relays to other homes (CHAT_GROUPS, with federation and sealed sender).
   */
  pairwiseGroups?: boolean
  /** The server fetches public pages for the sender's link previews. */
  linkPreviews?: boolean
  /** This server's SFU hosts group calls, so accounts here can start them. */
  groupCalls?: boolean
  /** This server's SFU hosts call links: calls anyone holding the link can join. */
  callLinks?: boolean
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

/** What a call link's secret gives its holder (docs/chat-calls.md). */
export interface CallLinkKeys {
  /** The SFU room: 32 lowercase hex characters. */
  roomId: string
  /** Presented to the host for an SFU token (standard base64). */
  accessToken: string
  /** What the host stores of the access token (standard base64). */
  accessTokenHash: string
  /** The media frame key (standard base64, 32 bytes). */
  frameKey: string
}

/** What a meeting is called and when it is, as its owner set them. */
export interface CallLinkInfo {
  title: string
  /** When it is planned to start (Unix milliseconds), if it is scheduled. */
  startsAtMs?: number
  /** How long it is planned to last; only with a start. */
  durationMinutes?: number
}

/** One message written during a meeting. */
export interface CallLinkMessage {
  /** 32 lowercase hex characters, chosen by the sender. */
  id: string
  text: string
  sentAtMs: number
}

/** The call link functions of the chat WASM module. Secrets are standard base64. */
export interface CallLinkCrypto {
  /** A fresh public nonce for a new link (32 lowercase hex characters). */
  callLinkNonce(): string
  /** The secret of the link its owner made with `nonce`, from the account master key (base64). */
  callLinkOwnerSecret(masterKey: string, nonce: string): string
  /**
   * The owner's host token for the meeting made with `nonce` and the hash
   * the server stores of it. Nobody the link is shared with can derive it.
   */
  callLinkHostToken(masterKey: string, nonce: string): { hostToken: string; hostTokenHash: string }
  callLinkKeys(secret: string): CallLinkKeys
  /** The part of the link's URL after `#`. */
  callLinkFragment(secret: string): string
  /** The secret a fragment carries; throws when it is not a call link. */
  callLinkParse(fragment: string): string
  /** Seal a participant's chosen name for the others in the call. */
  callLinkSealName(secret: string, name: string): string
  /** The name a participant sealed; throws when it was not made with this link. */
  callLinkOpenName(secret: string, sealed: string): string
  /** Seal the meeting's title and time for the host to keep. */
  callLinkSealInfo(secret: string, info: CallLinkInfo): string
  callLinkOpenInfo(secret: string, sealed: string): CallLinkInfo
  /** Seal a message written during the meeting, for the others in it. */
  callLinkSealMessage(secret: string, message: CallLinkMessage): string
  callLinkOpenMessage(secret: string, sealed: string): CallLinkMessage
  /**
   * Seal one stay in a meeting for the account's own list of joined
   * meetings, under a key from the account master key (base64).
   */
  callLinkSealJoined(masterKey: string, entry: JoinedMeetingRecord): string
  /** Throws when the record was not sealed by this account. */
  callLinkOpenJoined(masterKey: string, sealed: string): JoinedMeetingRecord
}

/** One stay in a meeting, as the account that joined keeps it. */
export interface JoinedMeetingRecord {
  /** The part of the link after `#`. */
  fragment: string
  title: string
  joinedAtMs: number
  seconds: number
}

export interface ChatTransportPort {
  registerDevice(request: unknown): Promise<unknown>
  setDeviceAuth(deviceId: number, credential: string): void
  createLinkToken(): Promise<unknown>
  relayProvisioning(address: string, request: unknown): Promise<boolean>
  distributeIdentity(
    request: unknown,
  ): Promise<{ kind: 'accepted' } | { kind: 'mismatch'; mismatch: unknown }>
  fetchBundles(account: string): Promise<unknown>
  fetchSyncBundles(
    account: string,
    currentDeviceId: number,
  ): Promise<unknown>
  fetchManifest(account: string): Promise<unknown | null>
  fetchManifestHistory(
    account: string,
    fromSequence: string,
    toSequence: string,
    pageFromSequence: string,
  ): Promise<unknown>
  fetchSealedSenderPolicy(domain: string): Promise<unknown>
  fetchSenderCertificate(deviceId: number): Promise<unknown>
  fetchSealedBundles(
    account: string,
    capability: string,
  ): Promise<unknown>
  publishManifest(manifest: unknown): Promise<unknown>
  /** The account's synced identity pins (docs/plans/drive-identity-pins.md); null before the first. */
  fetchIdentityPins(): Promise<{ revision: number; envelope: string } | null>
  /** Stores a new list if the server still holds `baseRevision` (0: none yet); false when another app wrote first. */
  storeIdentityPins(write: { baseRevision: number; envelope: string; revision: number }): Promise<boolean>
  fetchOwnProfile(): Promise<unknown | null>
  publishProfile(profile: unknown): Promise<unknown>
  fetchProfile(account: string, version: string, accessKey: string): Promise<unknown | null>
  prekeyCount(deviceId: number): Promise<unknown>
  replenishPrekeys(deviceId: number, request: unknown): Promise<void>
  sendMessage(
    account: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  sendSealedMessage(
    account: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
    | { kind: 'refused' }
  >
  /** The `SealedBatchResponseV1` of a sealed batch to accounts of `server`. */
  sendSealedBatch(server: string, request: unknown): Promise<unknown>
  sendSyncMessage(
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  drainMailbox(deviceId: number, after: string | null, limit: number): Promise<unknown>
  ackMessages(deviceId: number, ids: string[]): Promise<void>
  /** `GET /api/chat/groups/gateway-key`: `{config, identityHistory}`. */
  fetchGroupGateway(home: string, fromSequence: string): Promise<unknown>
  /** The account's group list, as the verified account head lists it. */
  fetchGroupList(): Promise<Array<{ id: string; revision: number; envelope: string }>>
  fetchContactList(): Promise<Array<{ id: string; revision: number; envelope: string }>>
  storeContactEntry(write: { id: string; baseRevision: number; revision: number; envelope: string }): Promise<'stored' | 'conflict' | 'full'>
  deleteContactEntry(write: { id: string; baseRevision: number }): Promise<boolean>
  /** One group-list entry with the next account head: false when another device wrote first. */
  storeGroupEntry(write: { id: string; baseRevision: number; revision: number; envelope: string }): Promise<boolean>
  /** `POST /api/chat/groups/relay/{home}` with a sealed group request. */
  relayGroupRequest(
    home: string,
    sealed: Uint8Array,
  ): Promise<
    | { kind: 'answered'; body: string }
    | { kind: 'unopenable' }
    | { kind: 'rateLimited' }
    | { kind: 'unreachable' }
    | { kind: 'groupsOff' }
  >
}

export interface WasmChatClientHandle {
  readonly deviceId: number
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
  /** Writes this browser's store has committed in this session. */
  storeCommits?(): number
  /** The conversations changed since a `storeCommits` mark (null: unknown). */
  changedConversations?(since: number): string[] | null
  /** Per-conversation summaries from the core's timelines. */
  conversationSummaries?(readThrough: Record<string, number>, recent: number, keys?: string[]): Promise<unknown>
  /** The key of every conversation with a timeline. */
  conversationKeys?(): Promise<string[]>
  /**
   * Search candidates from the core's index: entries whose words begin with
   * every word of `query`, newest first, at most `limit`, with what edits or
   * deletes them.
   */
  searchHistory?(query: string, limit: number): Promise<{ entries: ChatHistoryEntry[]; related: ChatHistoryEntry[] }>
  /** One newest-first page of a conversation. */
  conversationHistory?(key: string, before: string | undefined, limit: number): Promise<unknown>
  /** This account's own controls in Note to Self. */
  accountControls?(): Promise<ChatHistoryEntry[]>
  /** Fence this tab's writes behind the store's writer generation. */
  claimWriter?(takeOver: boolean): Promise<number>
  /** The server's mailbox retention (0: for ever); replaced prekeys are kept that long plus a margin. */
  setMailboxRetentionDays?(days: number): void
  /** The next send to anyone fetches their device list again. */
  forgetKnownDevices(): void
  pendingSendCount(): Promise<number>
  quarantineInbound(id: string): Promise<void>
  reconcile(): Promise<ReceiveReport>
  resolveDeadLetter(id: string): Promise<void>
  createGroup?(title: string): Promise<{ groupId: string; titleSet: boolean }>
  setGroupTitle?(groupId: string, title: string): Promise<void>
  syncGroup?(groupId: string): Promise<ChatGroupSync>
  groupMembers?(groupId: string): Promise<ChatGroupMember[]>
  listGroups?(): Promise<ChatGroupSummary[]>
  sendGroupText?(
    groupId: string,
    sendId: string,
    sentAt: string,
    text: string,
    replyTo?: string,
  ): Promise<ChatGroupSend>
  flushGroupOutbox?(): Promise<ChatGroupSend[]>
  inviteToGroup?(groupId: string, accounts: string[]): Promise<number>
  acceptGroupInvite?(groupId: string): Promise<ChatGroupSync>
  declineGroupInvite?(groupId: string): Promise<void>
  leaveGroup?(groupId: string): Promise<void>
  /** Writes the due group list entries now (before signing out); how many. */
  flushGroupList?(): Promise<number>
  /** Writes the due group and contact list entries and follows other devices' changes (a timer of its own). */
  syncAccountLists?(): Promise<void>
  /** Writes the due contact list entries now (before signing out); how many. */
  flushContactList?(): Promise<number>
  /** The contact list is full with nothing it may evict: changes (a block too) wait. */
  contactListFull?(): boolean
  removeGroupMember?(groupId: string, pseudonym: string): Promise<void>
  setGroupMemberAdmin?(groupId: string, pseudonym: string, administrator: boolean): Promise<void>
  previewGroupLink?(fragment: string): Promise<ChatGroupLinkPreview>
  joinGroupByLink?(fragment: string): Promise<ChatGroupLinkJoin>
  groupDetails?(groupId: string): Promise<ChatGroupDetails>
  setGroupAvatar?(groupId: string, image: Uint8Array, contentType: string): Promise<void>
  removeGroupAvatar?(groupId: string): Promise<void>
  groupAvatar?(groupId: string): Promise<ChatGroupAvatarFetch>
  checkGroupRequest?(groupId: string): Promise<ChatGroupRequestOutcome>
  cancelGroupRequest?(groupId: string): Promise<ChatGroupRequestOutcome>
  setGroupLink?(groupId: string, mode: ChatGroupLinkMode): Promise<void>
  resetGroupLink?(groupId: string): Promise<void>
  setGroupDescription?(groupId: string, description: string): Promise<void>
  setGroupTimer?(groupId: string, seconds: number): Promise<void>
  setGroupAccess?(groupId: string, attributes: 'member' | 'administrator', members: 'member' | 'administrator'): Promise<void>
  setGroupAnnouncementsOnly?(groupId: string, on: boolean): Promise<void>
  approveGroupRequest?(groupId: string, pseudonym: string): Promise<void>
  denyGroupRequest?(groupId: string, pseudonym: string): Promise<void>
  banGroupMember?(groupId: string, pseudonym: string, resetLink: boolean): Promise<void>
  unbanGroup?(groupId: string, ban: ChatGroupBan): Promise<void>
  endGroup?(groupId: string): Promise<void>
  removeUnverifiedGroupMembers?(groupId: string): Promise<number>
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
  /** The line saying `peer` changed their username (one step of their verified rename chain); once. True when written now. */
  recordPeerRenamed(peer: string, previous: string, current: string, sequence: number): Promise<boolean>
  pendingIdentityPin?(peer: string): Promise<{ authorityPublicKey: string; since: string } | null>
  writeIdentityPinNow?(peer: string): Promise<boolean>
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
  safetyNumber(peer: string): Promise<SafetyNumberV2>
  verifySafetyNumber(peer: string, scannedPayload: string): Promise<SafetyNumberV2>
  setIdentityVerified(peer: string, identityKey: string, verified: boolean): Promise<SafetyNumberV2>
  /** Link a new device of this account from its code; `false`: the code expired. */
  linkDevice(code: string, readReceipts: boolean, typingIndicators: boolean): Promise<boolean>
  /** Reset the account identity, keeping its devices but `remove`; the devices kept. */
  resetIdentity(remove: number[]): Promise<number[]>
  free(): void
}

/**
 * The safety number over both accounts' identity keys (libsignal's
 * fingerprint, as Signal's). `trust` is `Verified` when this identity was
 * verified, `Quarantined` while the account's authority is in question.
 */
export interface SafetyNumberV2 {
  localAccount: string
  peerAccount: string
  fingerprint: string
  qrPayload: string
  /** The peer's account identity key this number covers. */
  identityKey: string
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

export interface ChatWasmModule extends CallLinkCrypto {
  /**
   * The account's own profile key, from the master key and the key binding
   * (`session.envelopeBinding`) its own copy is wrapped to.
   */
  accountProfileKey(masterKey: Uint8Array, current: unknown, account: string, binding: string): ProfileLookup
  /** Where to fetch a profile, from its key (standard base64). */
  profileLookup(key: string): ProfileLookup
  /** Open someone's fetched profile with their key (standard base64). */
  profileOpenPeer(peer: string, encrypted: unknown, key: string): AccountProfileView
  /** Open the account's profile from the master key and key binding (no chat device). */
  accountProfileOpen(masterKey: Uint8Array, current: unknown, account: string, binding: string): AccountProfileView
  /**
   * Seal the next profile revision (or the first) as the account app: the
   * profile names `account`; its own copy of the key binds `binding`.
   */
  accountProfileSeal(masterKey: Uint8Array, current: unknown | null, update: AccountProfileInput, account: string, binding: string): unknown
  /** Seal small browser-side values for an account scope, one purpose each. */
  sealLocalData(masterKey: Uint8Array, scope: string, purposes: string[], plaintexts: Uint8Array[]): Uint8Array[]
  /** Open what `sealLocalData` sealed; a value that does not open is `null`. */
  openLocalData(masterKey: Uint8Array, scope: string, purposes: string[], sealed: Uint8Array[]): (Uint8Array | null)[]
  default(input?: unknown): Promise<unknown>
  WasmChatClient: {
    /**
     * Where this browser stands with the account's Chat identity
     * (docs/plans/account-identity-key.md): open it (`registered`,
     * `registering`), link it from another device (`link`), or register the
     * account's first Chat device (`reregister`).
     */
    installation(
      databaseName: string,
      account: string,
      masterKey: Uint8Array,
      transport: ChatTransportPort,
    ): Promise<ChatInstallation>
    open(
      databaseName: string,
      user: string,
      serverName: string,
      sealedSenderEnabled: boolean,
      masterKey: Uint8Array,
      /** The account's key binding (`session.envelopeBinding`), which its own seals bind. */
      binding: string,
      transport: ChatTransportPort,
    ): Promise<WasmChatClientHandle>
    /** A new account identity, this device alone; the account's other devices leave. */
    reregister(
      databaseName: string,
      user: string,
      serverName: string,
      sealedSenderEnabled: boolean,
      masterKey: Uint8Array,
      binding: string,
      transport: ChatTransportPort,
    ): Promise<WasmChatClientHandle>
  }
  WasmLinkingDevice: new () => WasmLinkingDeviceHandle
}

export type ChatInstallation = 'registered' | 'registering' | 'link' | 'reregister'

/** The new device's side of linking: one ephemeral key for one provisioning socket. */
export interface WasmLinkingDeviceHandle {
  /** `kutup://link?address=…&key=…`, for the QR code and to copy. */
  linkCode(address: string): string
  completeLink(
    envelope: unknown,
    databaseName: string,
    user: string,
    displayName: string,
    sealedSenderEnabled: boolean,
    masterKey: Uint8Array,
    binding: string,
    transport: ChatTransportPort,
  ): Promise<WasmChatClientHandle>
  /** The linking device's settings, once `completeLink` read them. */
  readonly readReceipts?: boolean
  readonly typingIndicators?: boolean
  free(): void
}
