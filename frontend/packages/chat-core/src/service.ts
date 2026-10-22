import api from '@kutup/session/client'
import { isAxiosError } from 'axios'
import { resolveApiBase } from '@kutup/session/apiBase'
import { ApiChatTransport, PEER_UNSUPPORTED } from './transport'
import { takeDeviceCredentialRefusal } from './device-auth'
import type {
  ChatCapabilities,
  ChangeMark,
  ChatAttachmentDescriptorV1,
  ChatDevice,
  ChatHistoryEntry,
  ChatExpiryReport,
  ContactRecord,
  ConversationId,
  InboundAttention,
  ChatProfile,
  ChatTypingEvent,
  ChatAccountControl,
  ChatMessageExtras,
  ChatLiveLocationV1,
  ChatLocationV1,
  ChatPollV1,
  ChatStickerV1,
  ChatViewOnceOpenedV1,
  ChatConversationStateV1,
  PeerChatProfile,
  ReceiveReport,
  SendSummary,
  LocalMlsConversationRecord,
  ChatCallEvent,
  ChatCallLog,
  ChatCallServers,
  ChatCallSignal,
  ChatGroupCall,
  GroupJoinRequest,
  InviteLinkCrypto,
  MlsGroupInfo,
  MlsGroupInviteLink,
  OwnJoinRequest,
  MlsInvitationFeedback,
  MlsAuthorityPolicyInspection,
  PendingMlsOwnerApprovalRequest,
  PendingMlsInvitation,
  SafetyNumberV2,
  ChatWasmModule,
  WasmChatClientHandle,
  WasmLinkingDeviceHandle,
} from './types'
import { isChatGroupId } from './types'
import type {
  ChatGroupMember,
  ChatGroupSend,
  ChatGroupAvatarFetch,
  ChatGroupBan,
  ChatGroupDetails,
  ChatGroupLinkJoin,
  ChatGroupLinkMode,
  ChatGroupLinkPreview,
  ChatGroupRequestOutcome,
  ChatGroupSummary,
  ChatGroupSync,
} from './types'
import { loadChatWasm } from './wasm'
import { EngineLock } from './engineLock'
import { SealedStorage } from './sealedStorage'
import {
  LiveTimeline,
  windowHistory,
  type ConversationSummary,
  type CoreConversationSummary,
  type CorePage,
} from './liveTimeline'
import { isSupportedChat } from './capabilities'
import {
  accountKey,
  conversationKey,
  directConversation,
  parseAccount,
  type AccountRef,
} from './identity'
import { matchesWords, searchableText, searchWords } from './search'
import { MlsConversationService, MlsSendError } from './mls-service'
import {
  INVITE_LINK_POLL_MS,
  InviteLinkService,
  type InviteLinkChange,
  type InviteLinkLookup,
} from './invite-links'
import { chatMediaCacheBindingV1, deliverChatMediaV1 } from './media'
import { privateCiphertextCacheForAccountV1 } from '@kutup/files/mediaCache'
import { ChatAttachmentLedger } from './attachment-ledger'
import {
  chatDeviceDatabaseName,
  completeRequestedLocalChatDeviceReset,
  forgetReplacedLocalChatDevice,
  rememberLocalChatDevice,
  replacedLocalChatDevice,
} from './local-store'
import {
  ChatBackupCoordinator,
  type BackupMediaSource,
  type ChatBackupView,
} from './backup'

type UpdateListener = () => void
type TypingListener = (event: ChatTypingEvent) => void

/**
 * `connecting` covers both the first connection and reconnecting after a
 * drop; `offline` is the browser saying it has no network.
 */
/** How often a tab checks for newly linked devices to add to its groups. */
const LINKED_DEVICE_CHECK_MS = 2 * 60_000
/**
 * How often an open tab checks its prekeys: tops up the one-time keys and
 * rotates the signed pair when due, also for a tab whose socket never drops
 * and one that only polls.
 */
const PREKEY_CHECK_MS = 60 * 60_000
/**
 * How often the account's lists get their due writes when nothing arrives
 * (reconcile does it too, but only when something does): the writes wait a
 * random 0–10 minutes, and a quiet device must still make them.
 */
const ACCOUNT_LISTS_MS = 60_000
/** The same in a hidden tab, where it only keeps the writes from waiting forever. */
const ACCOUNT_LISTS_HIDDEN_MS = 5 * 60_000

/**
 * How often each pairwise group is caught up with its home when nothing
 * arrives from it (docs/plans/pairwise-groups.md §11): administrators see
 * requests to join this way, never by a push that would tell the home who
 * they are. The first pass comes soon after the app opens.
 */
const GROUP_SYNC_MS = 10 * 60_000
/** In a tab left hidden: rarer, so a background tab costs the home little. */
const GROUP_SYNC_HIDDEN_MS = 30 * 60_000
const GROUP_SYNC_FIRST_MS = 15_000

/**
 * `polling`: the live socket cannot be opened (a gateway that blocks
 * WebSockets, say) but the server answers ordinary requests, so the mailbox
 * is read every few seconds instead.
 *
 * `deviceRemoved`: the server no longer knows this browser's Chat device (it
 * was revoked from another device, or expired unused). Nothing reconnects
 * it; it has to be set up again.
 */
export type ChatConnectionStatus = 'connected' | 'connecting' | 'polling' | 'offline' | 'deviceRemoved'

/** How often the mailbox is read while the live socket cannot be opened. */
const POLL_VISIBLE_MS = 5_000
/** In a hidden tab, where nobody is waiting for the next message. */
const POLL_HIDDEN_MS = 30_000
/** Failed socket attempts before polling starts: a restart or a hand-over needs none. */
const POLL_AFTER_ATTEMPTS = 2

/**
 * A pass that left group envelopes waiting (their sender not confirmable
 * yet) is followed by another, even with the socket open and nothing new
 * arriving: first after this, then twice as long each time up to the
 * engine's own longest back-off, and never sooner than the hidden-tab poll
 * in a hidden tab. A pass that leaves nothing waiting starts it over.
 */
const HELD_RETRY_FIRST_MS = 5_000
const HELD_RETRY_MAX_MS = 15 * 60_000

/** The protocol's limit on messages per delete-for-me control. */
const DELETE_FOR_ME_BATCH = 64

const PING_INTERVAL_MS = 25_000
const PONG_TIMEOUT_MS = 10_000

export type ChatServiceErrorCode =
  | 'browserUnsupported'
  | 'serverUnsupported'
  /**
   * Another device of the account holds its Chat identity: this browser is
   * linked from it (or re-registers, dropping the account's other devices).
   */
  | 'linkRequired'
  /** The account's contact list couldn't be read yet: the mailbox waits. */
  | 'contactListUnconfirmed'
  /** The server's contact list contradicts the account's verified state. */
  | 'contactListIntegrity'
  /** A group change refused, by the home or by this device's own check. */
  | 'groupNotAllowed'
  | 'groupLastAdministrator'
  | 'groupLimitReached'
  | 'groupEnded'
  | 'groupBanned'
  | 'groupAvatarTooLarge'
  | 'groupAvatarStorageFull'
  | 'groupAvatarMissing'
  | 'groupRefused'
  /** The group's home couldn't be reached. */
  | 'groupUnreachable'

const GROUP_REFUSALS: ReadonlyMap<string, ChatServiceErrorCode> = new Map([
  ['notAllowed', 'groupNotAllowed'],
  ['lastAdministrator', 'groupLastAdministrator'],
  ['limitReached', 'groupLimitReached'],
  ['terminated', 'groupEnded'],
  ['banned', 'groupBanned'],
  ['avatarTooLarge', 'groupAvatarTooLarge'],
  ['avatarStorageFull', 'groupAvatarStorageFull'],
  ['avatarMissing', 'groupAvatarMissing'],
])

/**
 * A failed group action, said as what it was: a refusal by its code (the
 * home's, or this device's own check before sending), or the home out of
 * reach. Anything else stays as it was.
 */
export function groupFailure(error: unknown): unknown {
  const message = error instanceof Error ? error.message : String(error)
  const refused = /refused(?: the change)?: (\w+)/.exec(message)
  if (refused) return new ChatServiceError(GROUP_REFUSALS.get(refused[1]!) ?? 'groupRefused')
  if (message.includes("group's server can't be reached")) return new ChatServiceError('groupUnreachable')
  return error
}

/** What the account-head checks say when the server shows another history or list than the verified one. */
const INTEGRITY_MARKERS = [
  'not the verified',
  "does not match the account's verified state",
  'history on the server is not',
  'contact list: an entry',
] as const

/**
 * A failed open because the account's contact list couldn't be followed:
 * its own code, so Chat says the messages are waiting rather than that it is
 * broken, and a list that contradicts the account's verified state is said
 * as such. Null for any other failure.
 */
export function contactListFailure(error: unknown): ChatServiceError | null {
  const message = error instanceof Error ? error.message : String(error)
  if (!message.includes('contact list unconfirmed')) return null
  return new ChatServiceError(INTEGRITY_MARKERS.some((marker) => message.includes(marker)) ? 'contactListIntegrity' : 'contactListUnconfirmed')
}

/**
 * The engine for this browser, as `options.install` says: the device it
 * has; the account's first one; a re-registration; or a linked device.
 */
async function openClientHandle(
  wasm: ChatWasmModule,
  transport: ApiChatTransport,
  databaseName: string,
  options: ChatServiceOptions,
): Promise<WasmChatClientHandle> {
  const args = [
    databaseName,
    accountKey(options.account),
    options.displayName,
    options.capabilities.sealedSender,
    options.masterKey,
    options.envelopeBinding,
    transport,
  ] as const
  const install = options.install ?? { kind: 'open' }
  if (install.kind === 'link') return await install.linking.completeLink(install.envelope, ...args)
  if (install.kind === 'reregister') return await wasm.WasmChatClient.reregister(...args)
  const state = await wasm.WasmChatClient.installation(
    databaseName,
    accountKey(options.account),
    options.masterKey,
    transport,
  )
  if (state === 'link') throw new ChatServiceError('linkRequired')
  // The account has no Chat identity yet: this is its first device.
  if (state === 'reregister') return await wasm.WasmChatClient.reregister(...args)
  return await wasm.WasmChatClient.open(...args)
}

export class ChatServiceError extends Error {
  constructor(readonly code: ChatServiceErrorCode) {
    super(code)
    this.name = 'ChatServiceError'
  }
}

export interface ChatServiceOptions {
  userId: string
  /** What the account's sealed keys are bound to (`session.envelopeBinding`). */
  envelopeBinding: string
  /** This account: its server and permanent id. */
  account: AccountRef
  /** The name a first profile starts with (the username). */
  displayName: string
  masterKey: Uint8Array
  capabilities: ChatCapabilities
  /**
   * How this browser gets its device (docs/plans/account-identity-key.md):
   * by default the one it has, or the account's first; `reregister` after the
   * person confirmed losing the account's other devices; `link` with the
   * provisioning envelope another device sent.
   */
  install?: ChatInstall
}

export type ChatInstall =
  | { kind: 'open' }
  | { kind: 'reregister' }
  | { kind: 'link'; linking: WasmLinkingDeviceHandle; envelope: unknown }

export interface ChatMediaStorageView {
  totalQuotaBytes: number
  totalUsedBytes: number
  driveBytes: number
  chatMediaBytes: number
  byConversation: Array<{ conversationReference: string; bytes: number }>
}

/**
 * One browser-tab facade. Every crypto operation takes a cross-tab Web Lock;
 * tabs may share one IndexedDB identity without racing ratchet read/commit
 * cycles. REST drain remains authoritative; WebSocket messages are hints.
 */
export class ChatService {
  readonly deviceId: number
  readonly capabilities: ChatCapabilities

  private readonly client: WasmChatClientHandle
  private readonly lockName: string
  private readonly engineLock: EngineLock
  /** The live window of the history (`liveTimeline.ts`). */
  private readonly timeline: LiveTimeline
  /** Writes by other tabs seen so far; their changes are not in this tab's journal. */
  private remoteWrites = 0
  /** Where the attachment ledger has followed the history to (`changesSince`). */
  private ledgerMark: ChangeMark | null = null
  /** Attachments still to be entered in the ledger, by message and attachment id. */
  private readonly pendingAttachments = new Map<string, ChatHistoryEntry>()
  /** Restored backup history by conversation, until the backup changes. */
  private restoredByKey: Promise<Map<string, ChatHistoryEntry[]>> | null = null
  /** The backup's `restoredVersion` that `restoredByKey` was read at. */
  private restoredByKeyVersion = -1
  /** Bumped on every change; history loads are shared within one revision. */
  private revision = 0
  private readonly historyCache = new Map<
    'all' | 'live',
    { revision: number; validUntil: number; value: Promise<ChatHistoryEntry[]> }
  >()
  /** Drafts, read positions and other small state, sealed for this account. */
  readonly sealedStorage: SealedStorage
  private readonly mlsWorkflowLockName: string
  private readonly channel: BroadcastChannel
  private readonly listeners = new Set<UpdateListener>()
  private readonly typingListeners = new Set<TypingListener>()
  private readonly attachmentExpiryListeners = new Set<(
    attachmentIds: readonly string[],
  ) => Promise<void> | void>()
  private socket: WebSocket | null = null
  private socketRetry: ReturnType<typeof setTimeout> | null = null
  private retryAttempt = 0
  private heartbeat: ReturnType<typeof setInterval> | null = null
  private pongDeadline: ReturnType<typeof setTimeout> | null = null
  private connection: ChatConnectionStatus = 'connecting'
  private pollTimer: ReturnType<typeof setTimeout> | null = null
  private heldRetry: ReturnType<typeof setTimeout> | null = null
  private heldRetryDelay = HELD_RETRY_FIRST_MS
  /** A polling loop runs (its timer may be between ticks, or a read in flight). */
  private polling = false
  private readonly connectionListeners = new Set<(status: ChatConnectionStatus) => void>()
  private readonly callListeners = new Set<(event: ChatCallEvent) => void>()
  private cachedCallServers: ChatCallServers | null = null
  private disposed = false
  private reconcilePromise: Promise<ReceiveReport> | null = null
  private reconcileAgain = false
  private readonly reportedSendFailures = new Set<string>()
  /** Peers whose server does not speak this Chat wire yet: messages to them wait. */
  private waitingPeers?: Set<string>
  private waitingPeerListeners?: Set<() => void>
  private readonly mls: MlsConversationService | null
  private readonly invites: InviteLinkService | null
  private inviteTimer: ReturnType<typeof setInterval> | null = null
  private linkedDeviceTimer: ReturnType<typeof setInterval> | null = null
  private prekeyTimer: ReturnType<typeof setInterval> | null = null
  private accountListsTimer: ReturnType<typeof setTimeout> | null = null
  private groupSyncTimer: ReturnType<typeof setTimeout> | null = null
  private backup: ChatBackupCoordinator | null = null
  private backupUnsubscribe: (() => void) | null = null

  private constructor(
    client: WasmChatClientHandle,
    engineLock: EngineLock,
    lockName: string,
    channelName: string,
    capabilities: ChatCapabilities,
    private readonly transport: ApiChatTransport,
    private readonly account: AccountRef,
    private readonly attachmentLedger: ChatAttachmentLedger | null,
    inviteCrypto: InviteLinkCrypto,
    sealedStorage: SealedStorage,
  ) {
    this.client = client
    this.sealedStorage = sealedStorage
    this.timeline = new LiveTimeline(
      {
        changes: async (mark) => {
          const { expiry, commits, keys } = await this.withLock(async () => {
            // Expired disappearing messages go first; their removal is a change.
            const expiry = await this.client.purgeExpiredMessages(String(Date.now()))
            return {
              expiry,
              commits: this.client.storeCommits?.() ?? 0,
              keys: this.client.changedConversations?.(mark) ?? null,
            }
          })
          await this.releaseExpiredAttachments(expiry)
          return { commits, keys }
        },
        accountControls: () => this.withLock(async () => await this.client.accountControls?.() ?? []),
        summaries: (readThrough, recent, keys) => this.withLock(async () =>
          (await this.client.conversationSummaries?.(readThrough, recent, keys) ?? []) as CoreConversationSummary[]),
        page: (key, before, limit) => this.withLock(async () =>
          (await this.client.conversationHistory?.(key, before, limit) ?? { entries: [] }) as CorePage),
      },
      (entry) => entry,
      (conversation) => ({ key: conversationKey(conversation), conversation }),
      conversationKey(directConversation(account)),
    )
    this.deviceId = client.deviceId
    this.lockName = lockName
    this.engineLock = engineLock
    this.mlsWorkflowLockName = `${lockName}:mls-workflow`
    this.capabilities = capabilities
    // Replaced prekeys are kept as long as the server may still hold a
    // message made with them.
    client.setMailboxRetentionDays?.(capabilities.mailboxRetentionDays)
    this.mls = capabilities.mlsGroups === true
      ? new MlsConversationService(
          client,
          transport,
          operation => this.withLock(operation),
          this.deviceId,
          account,
        )
      : null
    this.invites = this.mls
      ? new InviteLinkService(
          this.mls,
          transport,
          inviteCrypto,
          account,
          localStorageOrNull(),
        )
      : null
    this.channel = new BroadcastChannel(channelName)
    this.channel.onmessage = (message: MessageEvent<unknown>) => {
      const event = parseTypingBroadcast(message.data)
      const call = parseCallBroadcast(message.data)
      if (event) this.emitTyping(event, false)
      else if (call) this.emitCall(call, false)
      else {
        // Another tab wrote: this tab's journal does not know what.
        this.remoteWrites += 1
        this.timeline.invalidateAll()
        this.emitUpdate()
      }
    }
    window.addEventListener('online', this.handleOnline)
    window.addEventListener('offline', this.handleOffline)
    document.addEventListener('visibilitychange', this.handleVisibilityChange)
  }

  static async open(options: ChatServiceOptions): Promise<ChatService> {
    if (!navigator.locks) {
      throw new ChatServiceError('browserUnsupported')
    }

    const capabilities = options.capabilities
    if (!isSupportedChat(capabilities)) {
      throw new ChatServiceError('serverUnsupported')
    }

    await completeRequestedLocalChatDeviceReset(options.userId)
    const databaseName = await chatDeviceDatabaseName(options.userId)
    const scope = databaseName.slice(databaseName.indexOf(':') + 1)
    const lockName = `kutup-chat-engine:${scope}`
    const channelName = `kutup-chat-updates:${scope}`
    const wasm = await loadChatWasm()
    const transport = new ApiChatTransport()
    // One lock for opening and for every later operation, so opening does
    // not wait for ever behind a tab that froze while holding it.
    let opened: WasmChatClientHandle | null = null
    const engineLock = new EngineLock(
      lockName,
      async (takeOver) => { await opened?.claimWriter?.(takeOver) },
    )
    let client: WasmChatClientHandle
    try {
      client = await engineLock.run(async (tookOver) => {
        let handle: WasmChatClientHandle
        try {
          handle = await openClientHandle(wasm, transport, databaseName, options)
        } catch (error) {
          // This browser's device was removed while it was closed: it is
          // linked again (its history stays), like a new one.
          if (takeDeviceCredentialRefusal()) throw new ChatServiceError('linkRequired')
          throw error
        }
        // Taken over before there was a client to claim with: claim now.
        if (tookOver) await handle.claimWriter?.(true)
        opened = handle
        return handle
      })
    } catch (error) {
      engineLock.close()
      throw error
    }

    let attachmentLedger: ChatAttachmentLedger | null = null
    try {
      attachmentLedger = capabilities.media
        ? await ChatAttachmentLedger.open(options.masterKey)
        : null
    } catch (error) {
      client.free()
      engineLock.close()
      throw error
    }
    const service = new ChatService(
      client,
      engineLock,
      lockName,
      channelName,
      capabilities,
      transport,
      options.account,
      attachmentLedger,
      wasm,
      new SealedStorage(wasm, options.masterKey, scope),
    )
    try {
      if (capabilities.backup?.alwaysEnabled) {
        service.backup = await ChatBackupCoordinator.open({
          databaseName,
          envelopeBinding: options.envelopeBinding,
          masterKey: options.masterKey,
          deviceId: service.deviceId,
          history: () => service.liveHistory(),
          manifestSequence: async () => requireManifestSequence(
            await service.withLock(() => service.client.syncManifest()),
          ),
          mediaSources: () => service.backupMediaSources(),
          localMediaCiphertext: (descriptor, signal) =>
            privateCiphertextCacheForAccountV1(options.userId).readVerified(
              chatMediaCacheBindingV1(descriptor), signal,
            ),
          sealer: service.sealedStorage,
          conversations: client.conversationKeys && client.changedConversations && client.storeCommits
            ? {
                changes: (mark) => service.changesSince(mark),
                keys: () => service.conversationKeys(),
                entries: (key) => service.conversationEntries(key),
              }
            : undefined,
        })
        service.backupUnsubscribe = service.backup.subscribe(() => service.emitUpdate())
      }
      await service.initializeMls()
      await service.revokeReplacedDevice(options.userId)
      rememberLocalChatDevice(options.userId, service.deviceId)
      await service.reconcile()
      requestPersistentStorage()
      void service.maintainPrekeys()
      service.startPrekeyChecks()
      service.startAccountListSync()
      service.startGroupSync()
      void service.connectSocket()
      service.startInviteLinks()
      service.startLinkedDeviceChecks()
      return service
    } catch (error) {
      service.dispose()
      throw contactListFailure(error) ?? error
    }
  }

  subscribe(listener: UpdateListener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  /**
   * Whether this tab's socket to the server is up. Messages sent while it is
   * down wait in the outbox; the thread catches up when it returns.
   */
  connectionStatus(): ChatConnectionStatus {
    return this.connection
  }

  /** Try the socket again now instead of waiting out the backoff. */
  reconnect(): void {
    if (this.disposed) return
    if (this.socketRetry) {
      clearTimeout(this.socketRetry)
      this.socketRetry = null
    }
    this.retryAttempt = 0
    this.reconcileInBackground()
    void this.connectSocket()
  }

  subscribeConnection(listener: (status: ChatConnectionStatus) => void): () => void {
    this.connectionListeners.add(listener)
    return () => this.connectionListeners.delete(listener)
  }

  /**
   * Whether messages to `peer` wait because their server does not support
   * this Chat version yet (they go once it does).
   */
  isPeerWaiting(peer: string): boolean {
    return this.waitingPeers?.has(canonicalPeer(peer)) ?? false
  }

  subscribeWaitingPeers(listener: () => void): () => void {
    const listeners = (this.waitingPeerListeners ??= new Set())
    listeners.add(listener)
    return () => listeners.delete(listener)
  }

  private setWaitingPeers(next: Set<string>): void {
    const current = this.waitingPeers ?? new Set<string>()
    const same = next.size === current.size && [...next].every((peer) => current.has(peer))
    if (same) return
    this.waitingPeers = next
    for (const listener of this.waitingPeerListeners ?? []) listener()
  }

  subscribeTyping(listener: TypingListener): () => void {
    this.typingListeners.add(listener)
    return () => this.typingListeners.delete(listener)
  }

  subscribeAttachmentExpiry(
    listener: (attachmentIds: readonly string[]) => Promise<void> | void,
  ): () => void {
    this.attachmentExpiryListeners.add(listener)
    return () => this.attachmentExpiryListeners.delete(listener)
  }

  /**
   * The whole history, loaded once per change: the reload, the attachment
   * ledger and the backup share one load until something changes
   * (`emitUpdate`) or a disappearing message reaches its deadline.
   */
  history(): Promise<ChatHistoryEntry[]> {
    return this.cachedHistory('all', () => this.loadHistory())
  }

  private cachedHistory(
    kind: 'all' | 'live',
    load: () => Promise<ChatHistoryEntry[]>,
  ): Promise<ChatHistoryEntry[]> {
    const hit = this.historyCache.get(kind)
    if (hit && hit.revision === this.revision && Date.now() < hit.validUntil) return hit.value
    const entry = { revision: this.revision, validUntil: Infinity, value: load() }
    this.historyCache.set(kind, entry)
    entry.value.then(
      (entries) => { entry.validUntil = nextDeadline(entries) },
      () => { if (this.historyCache.get(kind) === entry) this.historyCache.delete(kind) },
    )
    return entry.value
  }

  private async loadHistory(): Promise<ChatHistoryEntry[]> {
    const [live, restored] = await Promise.all([
      this.liveHistory(),
      this.backup?.restoredHistoryAsync() ?? Promise.resolve([]),
    ])
    const merged = new Map(restored.map(entry => [entry.id, entry]))
    for (const entry of live) merged.set(entry.id, entry)
    return Array.from(merged.values()).sort((left, right) =>
      left.timestampMs - right.timestampMs || left.id.localeCompare(right.id))
  }

  backupStatus(): ChatBackupView | null {
    return this.backup?.view() ?? null
  }

  backupMediaCiphertext(
    mediaId: string,
    accessToken: string,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    if (!this.backup) throw new Error('encrypted Chat history is unavailable')
    return this.backup.fetchMediaCiphertext(mediaId, accessToken, signal)
  }

  private liveHistory(): Promise<ChatHistoryEntry[]> {
    return this.cachedHistory('live', () => this.loadLiveHistory())
  }

  /**
   * The live window: each conversation's newest and unread entries, its
   * timer and the account's controls, as one history, with the summaries
   * (unread counts against `readThroughFor`). Only what changed is read
   * again (`liveTimeline.ts`).
   */
  async liveWindow(
    readThroughFor: (controls: readonly ChatHistoryEntry[]) => Readonly<Record<string, number>>,
  ): Promise<{ history: ChatHistoryEntry[]; summaries: ConversationSummary[] }> {
    const [window, restored] = await Promise.all([
      this.timeline.refresh(readThroughFor),
      this.restoredHistory(),
    ])
    // Restored history counts as read: its newest entries per conversation
    // join the window, so a restored conversation is listed.
    const restoredRecent: ChatHistoryEntry[] = []
    for (const entries of restored.values()) restoredRecent.push(...entries.slice(-RESTORED_RECENT))
    return { history: windowHistory(window, restoredRecent), summaries: window.summaries }
  }

  /**
   * One page of a conversation (by app key), newest first, older than
   * `before`; for the conversation on screen. With no `before` in the
   * result, the page reaches the start, and the conversation's restored
   * history is included.
   */
  async conversationPage(
    key: string,
    before: string | undefined,
    limit: number,
  ): Promise<{ entries: ChatHistoryEntry[]; before?: string }> {
    const page = await this.timeline.page(key, before, limit)
    if (page.before !== undefined) return page
    const restored = (await this.restoredHistory()).get(key) ?? []
    const ids = new Set(page.entries.map((entry) => entry.id))
    const older = restored.filter((entry) => !ids.has(entry.id)).reverse()
    return { entries: [...page.entries, ...older] }
  }

  /**
   * For work that follows the history (the attachment ledger, the backup):
   * the conversations (the core's keys) this tab's writes changed since
   * `mark` (one this returned before), or `null` when that is not known (no
   * mark yet, another tab wrote, the journal no longer reaches back) and
   * everything should be looked at.
   */
  async changesSince(mark: ChangeMark | null): Promise<{ mark: ChangeMark; keys: string[] | null }> {
    return await this.withLock(async () => {
      const epoch = this.remoteWrites
      const commits = this.client.storeCommits?.()
      if (commits === undefined || !this.client.changedConversations) return { mark: { commits: 0, epoch }, keys: null }
      const keys = mark === null || mark.epoch !== epoch ? null : this.client.changedConversations(mark.commits)
      return { mark: { commits, epoch }, keys }
    })
  }

  /**
   * Candidates for a search, for `searchChatHistory` to decide on: from the
   * core's index, the entries whose words begin with every word of `query`
   * (newest first) with what edits or deletes them; and the restored
   * history that can match. Without an index (an older core), the whole
   * history.
   */
  async searchCandidates(query: string): Promise<ChatHistoryEntry[]> {
    const words = searchWords(query)
    if (words.length === 0) return []
    if (!this.client.searchHistory) return [...await this.history()]
    const [found, restored] = await Promise.all([
      this.withLock(() => this.client.searchHistory!(query, SEARCH_CANDIDATES)),
      this.restoredHistory(),
    ])
    const byId = new Map<string, ChatHistoryEntry>()
    // Restored history is held in memory: whatever can match, every edit or
    // deletion among it, and what those act on.
    const restoredEntries = [...restored.values()].flat()
    const targeted = new Set(restoredEntries.flatMap((entry) =>
      entry.content.mutation ? [entry.content.mutation.targetMessageId] : []))
    for (const entry of restoredEntries) {
      if (entry.content.mutation
          || (entry.content.messageId && targeted.has(entry.content.messageId))
          || matchesWords(searchWords(searchableText(entry)), words)) {
        byId.set(entry.id, entry)
      }
    }
    for (const entry of [...found.entries, ...found.related]) {
      const normalized = entry
      byId.set(normalized.id, normalized)
    }
    return [...byId.values()]
  }

  /** The core's key of every conversation. */
  async conversationKeys(): Promise<string[]> {
    return await this.withLock(async () => await this.client.conversationKeys?.() ?? [])
  }

  /** The newest `limit` entries of one conversation (the core's key), newest first. */
  private async newestEntries(key: string, limit: number): Promise<ChatHistoryEntry[]> {
    const page = await this.withLock(async () =>
      (await this.client.conversationHistory?.(key, undefined, limit) ?? { entries: [] }) as CorePage)
    return page.entries.map((entry) => entry)
  }

  /**
   * The entries of one conversation (the core's key), oldest first: those
   * of the full history that belong to it, without the controls that only
   * act on it from Note to Self.
   */
  async conversationEntries(key: string): Promise<ChatHistoryEntry[]> {
    const entries: ChatHistoryEntry[] = []
    let before: string | undefined
    do {
      const page = await this.withLock(async () =>
        (await this.client.conversationHistory?.(key, before, 500) ?? { entries: [] }) as CorePage)
      for (const entry of page.entries) {
        if (conversationKey(entry.conversation) === key) entries.push(entry)
      }
      before = page.before ?? undefined
    } while (before)
    return entries.reverse()
  }

  private restoredHistory(): Promise<Map<string, ChatHistoryEntry[]>> {
    if (!this.backup) return Promise.resolve(new Map())
    const version = this.backup.restoredVersion()
    if (!this.restoredByKey || this.restoredByKeyVersion !== version) {
      this.restoredByKeyVersion = version
      const loading = this.backup.restoredHistoryAsync().then((entries) => {
        const byKey = new Map<string, ChatHistoryEntry[]>()
        for (const entry of entries.map((value) => value)) {
          const key = conversationKey(entry.conversation)
          const list = byKey.get(key)
          if (list) list.push(entry)
          else byKey.set(key, [entry])
        }
        for (const list of byKey.values()) list.sort((left, right) => left.timestampMs - right.timestampMs)
        return byKey
      })
      loading.catch(() => { if (this.restoredByKey === loading) this.restoredByKey = null })
      this.restoredByKey = loading
    }
    return this.restoredByKey
  }

  private async loadLiveHistory(): Promise<ChatHistoryEntry[]> {
    const { history, expiry } = await this.withLock(async () => {
      const expiry = await this.client.purgeExpiredMessages(String(Date.now()))
      return { expiry, history: await this.client.history() }
    })
    await this.releaseExpiredAttachments(expiry)
    return history
  }

  async contacts(): Promise<ContactRecord[]> {
    return await this.withLock(() => this.client.contacts())
  }

  profile(): Promise<ChatProfile> {
    return this.withLock(() => this.client.profile())
  }

  devices(): Promise<ChatDevice[]> {
    return this.transport.listDevices()
  }

  async renameDevice(deviceId: number, name: string): Promise<ChatDevice[]> {
    await this.transport.renameDevice(deviceId, name)
    this.notifyPeers()
    return this.devices()
  }

  /**
   * After "Repair this browser": the device this browser was no longer has
   * any state anywhere, so it leaves the account's signed device list (and,
   * through it, the account's groups). Never fatal: if it cannot be done now
   * it is tried again on the next open, and Devices offers it by hand.
   */
  private async revokeReplacedDevice(userId: string): Promise<void> {
    const replaced = replacedLocalChatDevice(userId)
    if (replaced === null) return
    if (replaced === this.deviceId) {
      forgetReplacedLocalChatDevice(userId)
      return
    }
    try {
      const registered = (await this.devices()).some(device => device.deviceId === replaced)
      if (registered) await this.revokeDevice(replaced)
      forgetReplacedLocalChatDevice(userId)
    } catch (error) {
      console.warn('chat: could not revoke the device this browser replaced', error)
    }
  }

  async revokeDevice(deviceId: number): Promise<ChatDevice[]> {
    if (deviceId === this.deviceId) {
      throw new Error('the current Chat device cannot revoke itself')
    }
    await this.withMlsWorkflow(async () => {
      await this.transport.revokeDevice(deviceId)
      const manifest = await this.withLock(() => this.client.revokeManifestDevice(deviceId))
      if (!this.mls) return
      const sequence = requireManifestSequence(manifest)
      await this.mls.maintainKeyPackages(sequence)
      await this.mls.reconcileLinkedDevices(requireMlsManifestDeviceIds(manifest))
    })
    this.notifyPeers()
    return this.devices()
  }

  async profiles(): Promise<PeerChatProfile[]> {
    return await this.withLock(() => this.client.profiles())
  }

  async setProfile(
    displayName: string,
    avatar?: string,
    avatarContentType?: string,
    about?: string,
  ): Promise<ChatProfile> {
    const profile = await this.withLock(() =>
      this.client.setProfile(displayName, avatar, avatarContentType, about?.trim() || undefined),
    )
    this.notifyPeers()
    return profile
  }

  acceptContact(peer: string): Promise<ContactRecord> {
    return this.contactAction(peer, (corePeer) => this.client.acceptContact(corePeer))
  }

  rejectContact(peer: string): Promise<ContactRecord> {
    return this.contactAction(peer, (corePeer) => this.client.rejectContact(corePeer))
  }

  blockContact(peer: string): Promise<ContactRecord> {
    return this.contactAction(peer, (corePeer) => this.client.blockContact(corePeer))
  }

  unblockContact(peer: string): Promise<ContactRecord> {
    return this.contactAction(peer, (corePeer) => this.client.unblockContact(corePeer))
  }

  inboundAttention(): Promise<InboundAttention[]> {
    return this.withLock(() => this.client.inboundAttention())
  }

  async send(
    conversation: ConversationId,
    text: string,
    replyTo?: string,
    expiresAfterSeconds?: number,
    extras?: ChatMessageExtras,
  ): Promise<SendSummary> {
    if (conversation.kind === 'group' && isChatGroupId(conversation.groupId)) {
      // Slice 1 sends text and replies to a pairwise group; the composer
      // offers nothing else there yet.
      if (expiresAfterSeconds !== undefined || (extras && Object.keys(extras).length > 0)) {
        throw new Error('this group takes text and replies only for now')
      }
      const sent = await this.sendChatGroupText(conversation.groupId, text, replyTo)
      return { delivered: sent.pending === 0, deduplicated: false, attempts: 1, safetyNumberChanges: [] }
    }
    if (conversation.kind === 'group') {
      return this.groupSend(() =>
        this.requireMls().sendText(
          conversation.groupId,
          text,
          replyTo,
          expiresAfterSeconds,
          extras,
        ),
      )
    }
    const peer = accountKey(conversation.account)
    const sendId = crypto.randomUUID()
    const summary = await this.withLock(() =>
      this.client.sendText(
        sendId,
        peer,
        new Date().toISOString(),
        text,
        replyTo,
        expiresAfterSeconds,
        ...(extras ? [extras] : []),
      ),
    )
    this.notifyPeers()
    return summary
  }

  async sendAttachment(
    conversation: ConversationId,
    descriptor: ChatAttachmentDescriptorV1,
    storageReferenceId: string,
    expiresAfterSeconds?: number,
    extras?: ChatMessageExtras,
  ): Promise<SendSummary> {
    if (descriptor.originDomain !== this.capabilities.serverName) {
      throw new Error('attachment origin differs from the active homeserver')
    }
    const sendId = crypto.randomUUID()
    await this.recordAttachment(
      conversation,
      sendId,
      descriptor,
      storageReferenceId,
    )
    this.refuseChatGroup(conversation)
    if (conversation.kind === 'group') {
      return this.groupSend(() =>
        this.requireMls().sendAttachment(
          conversation.groupId,
          sendId,
          descriptor,
          expiresAfterSeconds,
          extras,
        ),
      )
    }
    const address = conversation.account
    const peer = accountKey(address)
    const self = this.selfKey()
    const capability = peer === self
      ? null
      : await this.withLock(() => this.client.mediaDeliveryCapability(peer))
    if (capability) {
      const receipt = await deliverChatMediaV1(descriptor, address, capability)
      if (receipt.status === 'storage_full') {
        throw new Error('recipient Chat-media storage is full')
      }
    }
    // The opaque destination copy must be durable before the descriptor can
    // enter the recipient's mailbox. A failed media receipt therefore never
    // creates a visibly broken attachment message.
    const summary = await this.withLock(() =>
      this.client.sendAttachment(
        sendId,
        peer,
        new Date().toISOString(),
        descriptor,
        expiresAfterSeconds,
        ...(extras ? [extras] : []),
      ),
    )
    this.notifyPeers()
    return summary
  }

  /** A new poll (with the chat's disappearing timer). */
  sendPoll(conversation: ConversationId, poll: ChatPollV1, expiresAfterSeconds?: number): Promise<SendSummary> {
    return this.sendPollContent(conversation, 'poll', poll, expiresAfterSeconds)
  }

  /**
   * A place, sent once (with the chat's disappearing timer). Coordinates are
   * kept to six decimals (about 10 cm); nothing more precise is sent.
   */
  sendLocation(conversation: ConversationId, location: ChatLocationV1, expiresAfterSeconds?: number): Promise<SendSummary> {
    const round = (value: number) => Math.round(value * 1e6) / 1e6
    const label = location.label?.trim()
    return this.sendPollContent(
      conversation,
      'location',
      { lat: round(location.lat), lon: round(location.lon), ...(label ? { label } : {}) },
      expiresAfterSeconds,
    )
  }

  /**
   * A live location's stream and key (docs/plans/maps.md): generation 1
   * starts the share (with the chat's disappearing timer); later ones hand
   * over a new stream.
   */
  sendLiveLocation(conversation: ConversationId, share: ChatLiveLocationV1, expiresAfterSeconds?: number): Promise<SendSummary> {
    return this.sendPollContent(conversation, 'liveLocation', share, share.generation === 1 ? expiresAfterSeconds : undefined)
  }

  /** End a live location this account is sharing. */
  stopLiveLocation(conversation: ConversationId, shareId: string): Promise<SendSummary> {
    return this.sendPollContent(conversation, 'liveLocationStop', { shareId })
  }

  /** This account's choice in a poll; an empty list takes the vote back. */
  votePoll(conversation: ConversationId, targetMessageId: string, options: number[]): Promise<SendSummary> {
    return this.sendPollContent(conversation, 'pollVote', { targetMessageId, options: [...options].sort((a, b) => a - b) })
  }

  /** End a poll this account made. */
  endPoll(conversation: ConversationId, targetMessageId: string): Promise<SendSummary> {
    return this.sendPollContent(conversation, 'pollTerminate', { targetMessageId })
  }

  private async sendPollContent(
    conversation: ConversationId,
    kind: 'poll' | 'pollVote' | 'pollTerminate' | 'location' | 'liveLocation' | 'liveLocationStop',
    body: unknown,
    expiresAfterSeconds?: number,
  ): Promise<SendSummary> {
    this.refuseChatGroup(conversation)
    if (conversation.kind === 'group') {
      return this.groupSend(() =>
        this.requireMls().sendPollContent(conversation.groupId, kind, body, expiresAfterSeconds),
      )
    }
    const peer = accountKey(conversation.account)
    const summary = await this.withLock(() =>
      this.client.sendPollContent(crypto.randomUUID(), peer, new Date().toISOString(), kind, body, expiresAfterSeconds),
    )
    this.notifyPeers()
    return summary
  }

  async sendReaction(
    conversation: ConversationId,
    targetMessageId: string,
    emoji: string,
    active: boolean,
  ): Promise<SendSummary> {
    this.refuseChatGroup(conversation)
    if (conversation.kind === 'group') {
      return this.groupSend(() =>
        this.requireMls().sendReaction(
          conversation.groupId,
          targetMessageId,
          emoji,
          active,
        ),
      )
    }
    const peer = accountKey(conversation.account)
    const summary = await this.withLock(() => this.client.sendReaction(
      crypto.randomUUID(),
      peer,
      new Date().toISOString(),
      targetMessageId,
      emoji,
      active,
    ))
    this.notifyPeers()
    return summary
  }

  async mutateMessage(
    conversation: ConversationId,
    targetMessageId: string,
    operation: 'edit' | 'delete',
    replacementText?: string,
  ): Promise<SendSummary> {
    this.refuseChatGroup(conversation)
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().mutateMessage(
          conversation.groupId,
          targetMessageId,
          operation,
          replacementText,
        ),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = accountKey(conversation.account)
    const summary = await this.withLock(() => this.client.sendMessageMutation(
      crypto.randomUUID(),
      peer,
      new Date().toISOString(),
      targetMessageId,
      operation,
      replacementText,
    ))
    this.notifyPeers()
    return summary
  }

  async sendReceipt(
    conversation: ConversationId,
    messageIds: string[],
    state: 'delivered' | 'read',
  ): Promise<SendSummary> {
    // Receipts in pairwise groups come with a later slice: nothing is sent.
    if (conversation.kind === 'group' && isChatGroupId(conversation.groupId)) {
      return { delivered: true, deduplicated: false, attempts: 0, safetyNumberChanges: [] }
    }
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendReceipt(conversation.groupId, messageIds, state),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = accountKey(conversation.account)
    const summary = await this.withLock(() => this.client.sendReceipt(
      crypto.randomUUID(),
      peer,
      new Date().toISOString(),
      messageIds,
      state,
    ))
    this.notifyPeers()
    return summary
  }

  async sendTyping(conversation: ConversationId, active: boolean): Promise<void> {
    // Typing in pairwise groups comes with a later slice.
    if (conversation.kind === 'group' && isChatGroupId(conversation.groupId)) return
    if (conversation.kind === 'group') {
      await this.withMlsWorkflow(() =>
        this.requireMls().sendTyping(conversation.groupId, active),
      )
      return
    }
    const peer = accountKey(conversation.account)
    const self = this.selfKey()
    if (peer === self) return
    await this.withLock(() => this.client.sendTyping(
      crypto.randomUUID(),
      peer,
      new Date().toISOString(),
      active,
    ))
  }

  /**
   * Send what is still waiting now, instead of at the next reconnect (the
   * outboxes survive reloads and are retried by every reconcile).
   */
  async retrySends(): Promise<void> {
    await this.reconcile()
  }

  /**
   * A group send. Once the message is encrypted into the durable MLS outbox
   * it will go out (every reconcile retries it), so a failure after that is
   * "not delivered yet", not "not sent": the message shows as pending with a
   * retry instead of coming back to the composer, where sending it again
   * would duplicate it.
   */
  private async groupSend(
    work: () => Promise<{ delivered: boolean; deduplicated: boolean; attempts: number }>,
  ): Promise<SendSummary> {
    try {
      const summary = await this.withMlsWorkflow(work)
      return { ...summary, safetyNumberChanges: [] }
    } catch (error) {
      if (error instanceof MlsSendError && error.stage !== 'conversation' && error.stage !== 'encryption') {
        console.warn('chat: group message queued; delivery failed at', error.stage, error.cause)
        return { delivered: false, deduplicated: false, attempts: 0, safetyNumberChanges: [] }
      }
      throw error
    } finally {
      this.notifyPeers()
    }
  }

  /** Send one call signal to `peer` (its devices; see docs/chat-calls.md). */
  async sendCallSignal(peer: AccountRef, call: ChatCallSignal): Promise<void> {
    const address = accountKey(peer)
    await this.withLock(() => this.client.sendCallSignal(
      crypto.randomUUID(),
      address,
      new Date().toISOString(),
      call,
    ))
  }

  /** Put a finished call into `peer`'s timeline on this device. */
  async recordCallLog(peer: AccountRef, body: ChatCallLog): Promise<void> {
    const address = accountKey(peer)
    await this.withLock(() => this.client.recordCallLog(address, body))
    this.notifyPeers()
  }

  /**
   * Put the line saying `peer` changed their username into their thread on
   * this device: one step of their own verified rename chain, written once.
   */
  async recordPeerRenamed(peer: AccountRef, rename: { from: string; to: string; sequence: number }): Promise<boolean> {
    const written = await this.withLock(() =>
      this.client.recordPeerRenamed(accountKey(peer), rename.from, rename.to, rename.sequence))
    if (written) this.notifyPeers()
    return written
  }

  /**
   * The pin Chat keeps for `peer` and hasn't written to the account's list
   * yet (a first meeting waits for a random moment), to follow their renames
   * against meanwhile; null once written.
   */
  async pendingIdentityPin(peer: AccountRef): Promise<{ authorityPublicKey: string; since: string } | null> {
    const client = this.client
    if (!client.pendingIdentityPin) return null
    return this.withLock(() => client.pendingIdentityPin!(accountKey(peer)))
  }

  /**
   * Writes `peer`'s pending pin to the account's list now, ahead of its
   * random moment (they renamed, so the list must know them and their old
   * address): true when one was written.
   */
  async writeIdentityPinNow(peer: AccountRef): Promise<boolean> {
    const client = this.client
    if (!client.writeIdentityPinNow) return false
    return this.withLock(() => client.writeIdentityPinNow!(accountKey(peer)))
  }

  /** ICE servers for a call: STUN, and TURN with fresh credentials when the server has a relay. */
  async callServers(): Promise<ChatCallServers> {
    const cached = this.cachedCallServers
    if (cached && (!cached.expiresAt || cached.expiresAt * 1000 - Date.now() > 60 * 60 * 1000)) return cached
    const response = await api.get<ChatCallServers>('/chat/call-servers')
    this.cachedCallServers = response.data
    return response.data
  }

  /** Announce a group call starting or ending to the group. */
  async sendGroupCall(groupId: string, body: ChatGroupCall): Promise<void> {
    await this.withMlsWorkflow(() => this.requireMls().sendPollContent(groupId, 'groupCall', body))
    this.notifyPeers()
  }

  /** A group call's frame key in the group's current epoch. */
  async groupCallKey(groupId: string, callId: string): Promise<{ epoch: number; key: Uint8Array }> {
    return this.requireMls().callKey(groupId, callId)
  }

  /** An SFU token for a group call's room, from its host (through this server). */
  async groupCallToken(host: string, roomId: string, participantId: string): Promise<{ url: string; token: string }> {
    const response = await api.post<{ url: string; token: string }>('/chat/group-calls/token', {
      host,
      roomId,
      participantId,
    })
    return response.data
  }

  subscribeCalls(listener: (event: ChatCallEvent) => void): () => void {
    this.callListeners.add(listener)
    return () => this.callListeners.delete(listener)
  }

  private emitCall(event: ChatCallEvent, broadcast: boolean): void {
    if (broadcast) this.channel.postMessage({ type: 'call', event })
    for (const listener of this.callListeners) listener(event)
  }

  async sendDisappearingTimer(
    conversation: ConversationId,
    durationSeconds?: number,
  ): Promise<SendSummary> {
    this.refuseChatGroup(conversation)
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendDisappearingTimer(conversation.groupId, durationSeconds),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = accountKey(conversation.account)
    const summary = await this.withLock(() => this.client.sendDisappearingTimer(
      crypto.randomUUID(),
      peer,
      new Date().toISOString(),
      durationSeconds,
    ))
    this.notifyPeers()
    return summary
  }

  /**
   * Pin, archive, mute or mark a conversation unread on all of this
   * account's devices. `revision` must be one more than the current
   * record's (0 when there is none).
   */
  async setConversationState(
    state: Omit<ChatConversationStateV1, 'sourceDeviceId' | 'updatedAtMs'>,
  ): Promise<void> {
    await this.sendAccountControl({
      kind: 'conversationState',
      body: { ...state, sourceDeviceId: this.deviceId, updatedAtMs: Date.now() },
    })
  }

  /** Tell this account's other devices how far a conversation has been read. */
  async markReadThrough(conversation: ConversationId, throughMessageId: string, readThroughMs: number): Promise<void> {
    await this.sendAccountControl({
      kind: 'readPosition',
      body: { conversation, throughMessageId, readThroughMs },
    })
  }

  /**
   * Remove messages from this account's history on all its devices; the
   * other people in the conversation keep theirs.
   */
  async deleteForMe(conversation: ConversationId, messageIds: readonly string[]): Promise<void> {
    for (let start = 0; start < messageIds.length; start += DELETE_FOR_ME_BATCH) {
      await this.sendAccountControl({
        kind: 'deleteForMe',
        body: { conversation, messageIds: messageIds.slice(start, start + DELETE_FOR_ME_BATCH) },
      })
    }
    // The purge that removes them runs with every history read, which the
    // update notice triggers.
  }

  /**
   * A view-once photo or video was opened (and its viewer closed): remove it
   * on all of this account's devices, leaving "Viewed" in its place.
   */
  async markViewOnceOpened(opened: ChatViewOnceOpenedV1): Promise<void> {
    await this.sendAccountControl({ kind: 'viewOnceOpened', body: opened })
  }

  /** Add a sticker to this account's collection (on all of its devices). */
  async saveSticker(sticker: Omit<ChatStickerV1, 'stickerId'>): Promise<string> {
    const stickerId = crypto.randomUUID()
    await this.sendAccountControl({ kind: 'stickerSaved', body: { stickerId, ...sticker } })
    return stickerId
  }

  async removeSticker(stickerId: string): Promise<void> {
    await this.sendAccountControl({ kind: 'stickerRemoved', body: { stickerId } })
  }

  private async sendAccountControl(control: ChatAccountControl): Promise<void> {
    await this.withLock(() => this.client.sendAccountControl(
      crypto.randomUUID(),
      new Date().toISOString(),
      control.kind,
      control.body,
    ))
    this.notifyPeers()
  }

  async startDisappearingExpiry(
    conversation: ConversationId,
    targetMessageId: string,
    startedAtMs = Date.now(),
  ): Promise<SendSummary> {
    const summary = await this.withLock(() => this.client.startDisappearingExpiry(
      crypto.randomUUID(),
      new Date(startedAtMs).toISOString(),
      conversation,
      targetMessageId,
      String(startedAtMs),
    ))
    this.notifyPeers()
    return summary
  }

  async chatMediaStorage(): Promise<ChatMediaStorageView> {
    if (!this.attachmentLedger) throw new Error('Chat media is not enabled')
    await this.withAttachmentLedgerLock(() => this.attachmentLedger!.sync())
    const response = await api.get<Omit<ChatMediaStorageView, 'byConversation'>>(
      '/chat/media/storage',
    )
    const byConversation = Array.from(
      this.attachmentLedger.totalsByConversation(),
      ([conversationReference, bytes]) => ({ conversationReference, bytes }),
    ).sort((left, right) => right.bytes - left.bytes)
    return { ...response.data, byConversation }
  }

  async clearChatMediaConversation(conversationReference: string): Promise<ChatMediaStorageView> {
    if (!this.attachmentLedger) throw new Error('Chat media is not enabled')
    await this.withAttachmentLedgerLock(async () => {
      await this.attachmentLedger!.sync()
      const targets = this.attachmentLedger!.activeEntries(conversationReference)
      const allActive = this.attachmentLedger!.activeEntries()
      const targetIds = new Set(targets.map(target => target.entityId))
      const keepAttachments = new Set(
        allActive
          .filter(entity => !targetIds.has(entity.entityId))
          .map(entity => entity.entry.attachmentId),
      )
      const clearedAttachments = new Set<string>()
      for (const target of targets) {
        const attachmentId = target.entry.attachmentId
        if (!keepAttachments.has(attachmentId) && !clearedAttachments.has(attachmentId)) {
          try {
            await api.delete(`/chat/media/references/${encodeURIComponent(attachmentId)}`)
          } catch (error: unknown) {
            const status = typeof error === 'object' && error !== null && 'response' in error
              ? (error as { response?: { status?: number } }).response?.status
              : undefined
            if (status !== 404) throw error
          }
          clearedAttachments.add(attachmentId)
        }
        await this.attachmentLedger!.markCleared(target.entityId, Date.now())
      }
    })
    this.backup?.schedule()
    return this.chatMediaStorage()
  }

  private async recordAttachment(
    conversation: ConversationId,
    messageId: string,
    descriptor: ChatAttachmentDescriptorV1,
    storageReferenceId: string,
  ): Promise<void> {
    if (!this.attachmentLedger) {
      throw new Error('Chat attachment ledger is unavailable')
    }
    await this.withAttachmentLedgerLock(async () => {
      await this.attachmentLedger!.sync()
      if (this.attachmentLedger!.hasAttachment(messageId, descriptor.attachmentId)) return
      await this.createAttachmentLedgerEntry(
        conversation,
        messageId,
        descriptor,
        storageReferenceId,
      )
    })
  }

  private async createAttachmentLedgerEntry(
    conversation: ConversationId,
    messageId: string,
    descriptor: ChatAttachmentDescriptorV1,
    storageReferenceId: string,
  ): Promise<void> {
    if (!this.attachmentLedger) throw new Error('Chat attachment ledger is unavailable')
    const address = conversation.kind === 'direct'
      ? accountKey(conversation.account)
      : conversation.groupId
    const self = this.selfKey()
    await this.attachmentLedger.create({
      version: 1,
      conversationKind: conversation.kind === 'group'
        ? 'mls_group'
        : address === self ? 'note_to_self' : 'direct',
      conversationReference: address,
      messageId,
      attachmentId: descriptor.attachmentId,
      storageReferenceId,
      ciphertextBytes: descriptor.ciphertextBytes,
      state: 'active',
      mediaClass: descriptor.mediaClass,
      displayName: descriptor.filename,
      updatedAtMs: Date.now(),
    })
  }

  /**
   * Drain the mailbox. A request while a drain runs (a socket hint for a
   * message that landed after that drain read the mailbox) is not folded
   * into it: one more drain follows, so the message shows without waiting
   * for the next hint.
   */
  /**
   * Reconcile where nobody waits for the result (a socket nudge, a timer, a
   * tab coming back). A failure is not the person's to handle: the next
   * nudge or retry runs it again.
   */
  /**
   * The server says this account's device list changed. Device lists held
   * from earlier fetches are dropped, so the next send fetches and verifies
   * them again instead of finding out from a refused send.
   */
  private devicesChanged(): void {
    this.withLock(async () => this.client.forgetKnownDevices())
      .then(() => this.emitUpdate())
      .catch(reportBackgroundFailure)
  }

  private reconcileInBackground(): void {
    this.reconcile().catch(reportBackgroundFailure)
  }

  reconcile(): Promise<ReceiveReport> {
    if (this.reconcilePromise) {
      this.reconcileAgain = true
      return this.reconcilePromise
    }
    this.reconcilePromise = this.withLock(async () => {
      const commits = this.client.storeCommits?.()
      const expiry = await this.client.purgeExpiredMessages(String(Date.now()))
      return { commits, expiry, report: await this.client.reconcile() }
    })
      .then(async ({ commits, expiry, report }) => {
        await this.releaseExpiredAttachments(expiry)
        // MLS groups go their own way: a failure there (an MLS device the
        // server no longer has, say after an identity reset) never holds
        // back what this pass took for direct conversations.
        let mlsTyping: ChatTypingEvent[] = []
        try {
          mlsTyping = await this.withMlsWorkflow(async () => {
            return await this.mls?.reconcile() ?? []
          })
        } catch (error) {
          reportBackgroundFailure(error)
        }
        // A queued message the server would not take stays queued, behind
        // nothing but its own conversation; it is tried again on every pass.
        const waiting = new Set<string>()
        for (const failure of report.sendFailures ?? []) {
          if (failure.error.includes(PEER_UNSUPPORTED)) waiting.add(canonicalPeer(failure.peer))
          if (this.reportedSendFailures.has(failure.sendId)) continue
          this.reportedSendFailures.add(failure.sendId)
          console.warn('chat: a queued message could not be sent yet', failure.error)
        }
        this.setWaitingPeers(waiting)
        if ((report.held?.length ?? 0) === 0) {
          this.heldRetryDelay = HELD_RETRY_FIRST_MS
        } else if (this.heldRetry === null && !this.disposed) {
          const delay = document.visibilityState === 'visible'
            ? this.heldRetryDelay
            : Math.max(this.heldRetryDelay, POLL_HIDDEN_MS)
          this.heldRetryDelay = Math.min(this.heldRetryDelay * 2, HELD_RETRY_MAX_MS)
          this.heldRetry = setTimeout(() => {
            this.heldRetry = null
            if (!this.disposed) this.reconcileInBackground()
          }, delay)
        }
        for (const message of report.messages ?? []) {
          if (message.conversation.kind !== 'direct' || !message.content.call) continue
          this.emitCall({
            peer: accountKey(message.conversation.account),
            senderDeviceId: message.senderDeviceId,
            sentAt: message.content.sentAt,
            call: message.content.call,
          }, true)
        }
        const directTyping = (report.messages ?? []).flatMap((message): ChatTypingEvent[] => {
          if (message.conversation.kind !== 'direct' || message.content.call) return []
          const account = message.conversation.account
          return [{
            conversation: directConversation(account),
            sender: accountKey(account),
            // A real encrypted message clears the sender's prior typing state
            // without adding a second control event.
            active: message.content.typing?.active ?? false,
          }]
        })
        for (const event of [...directTyping, ...mlsTyping]) this.emitTyping(event, true)
        // Most passes (a poll, a socket hint) find nothing: then nothing was
        // written, and neither this tab nor the others reload anything.
        const after = await this.withLock(async () => this.client.storeCommits?.())
        if (commits === undefined || after !== commits) {
          await this.reconcileAttachmentLedger()
          this.notifyPeers()
        } else {
          // An attachment whose server copy was not there yet (a delivery
          // still on its way from another server) is tried again on every
          // pass, as it was before passes that wrote nothing were skipped;
          // waiting for the next local write could leave it unrecorded for
          // long.
          const entered = this.pendingAttachments.size > 0 && await this.reconcileAttachmentLedger()
          // Invitations are kept on the server: a new one wrote nothing
          // here, but the list shows it. Other tabs list it on their own pass.
          if (this.mls?.takeInvitationsChanged() || entered) this.emitUpdate()
        }
        return report
      })
      .finally(() => {
        this.reconcilePromise = null
        if (this.reconcileAgain && !this.disposed) {
          this.reconcileAgain = false
          this.reconcileInBackground()
        }
      })
    return this.reconcilePromise
  }

  // ----- pairwise groups (docs/plans/pairwise-groups.md) -----

  /** What pairwise groups don't take yet (slice 1 sends text and replies). */
  private refuseChatGroup(conversation: ConversationId): void {
    if (conversation.kind === 'group' && isChatGroupId(conversation.groupId)) {
      throw new Error('this group takes text and replies only for now')
    }
  }

  private groupClient(): Required<Pick<WasmChatClientHandle,
    | 'createGroup' | 'setGroupTitle' | 'syncGroup' | 'groupMembers' | 'listGroups'
    | 'sendGroupText' | 'flushGroupOutbox' | 'inviteToGroup' | 'acceptGroupInvite'
    | 'declineGroupInvite' | 'leaveGroup' | 'removeGroupMember' | 'setGroupMemberAdmin'>> {
    const client = this.client
    if (this.capabilities.pairwiseGroups !== true || !client.createGroup || !client.listGroups
      || !client.syncGroup || !client.groupMembers || !client.setGroupTitle
      || !client.sendGroupText || !client.flushGroupOutbox || !client.inviteToGroup
      || !client.acceptGroupInvite || !client.declineGroupInvite || !client.leaveGroup
      || !client.removeGroupMember || !client.setGroupMemberAdmin) {
      throw new ChatServiceError('serverUnsupported')
    }
    return client as never
  }

  /** The pairwise groups this device knows: invitations, memberships, ended ones. */
  async chatGroups(): Promise<ChatGroupSummary[]> {
    const client = this.groupClient()
    return this.withLock(() => client.listGroups())
  }

  /**
   * A new group on this server, this account its first administrator, and
   * `members` (contacts' account keys) invited. The group exists even when
   * its title or an invitation didn't go out; `invited` says how many did.
   */
  async createChatGroup(
    title: string,
    members: string[],
  ): Promise<{ groupId: string; titleSet: boolean; invited: number }> {
    const client = this.groupClient()
    const created = await this.withLock(() => client.createGroup(title))
    let invited = 0
    if (members.length > 0) {
      const accounts = members.map(requireAccountKey)
      invited = await this.withLock(() => client.inviteToGroup(created.groupId, accounts))
        .catch((error: unknown) => {
          console.warn('chat: the group was made but its invitations did not go out', error)
          return 0
        })
    }
    this.notifyPeers()
    return { ...created, invited }
  }

  /** Catches a group up with its home. */
  async syncChatGroup(groupId: string): Promise<ChatGroupSync> {
    const client = this.groupClient()
    const sync = await this.withLock(() => client.syncGroup(groupId))
    this.notifyPeers()
    return sync
  }

  /** The group's members, each checked against their account's manifest. */
  async chatGroupMembers(groupId: string): Promise<ChatGroupMember[]> {
    const client = this.groupClient()
    return this.withLock(() => client.groupMembers(groupId))
  }

  async renameChatGroup(groupId: string, title: string): Promise<void> {
    await this.groupChange((client) => client.setGroupTitle(groupId, title))
  }

  /** Invites contacts (account keys): how many invitations went out. */
  async inviteToChatGroup(groupId: string, members: string[]): Promise<number> {
    const accounts = members.map(requireAccountKey)
    let invited = 0
    await this.groupChange(async (client) => {
      invited = await client.inviteToGroup(groupId, accounts)
    })
    return invited
  }

  async acceptChatGroupInvite(groupId: string): Promise<ChatGroupSync> {
    let sync: ChatGroupSync = { kind: 'unreachable', reason: 'unreachable' }
    await this.groupChange(async (client) => {
      sync = await client.acceptGroupInvite(groupId)
    })
    return sync
  }

  async declineChatGroupInvite(groupId: string): Promise<void> {
    await this.groupChange((client) => client.declineGroupInvite(groupId))
  }

  /**
   * Before this browser signs out: the account's group list gets the joins
   * and leaves still waiting for their delayed write
   * (docs/plans/pairwise-groups.md §5). Best effort, at most `waitMs`.
   */
  async flushGroupList(waitMs = 3000): Promise<void> {
    const client = this.client
    if (this.capabilities.pairwiseGroups !== true || !client.flushGroupList) return
    await Promise.race([
      this.withLock(() => client.flushGroupList!()).catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, waitMs)),
    ])
  }

  /**
   * Before this browser signs out: the account's contact list gets the
   * changes still waiting for their delayed write
   * (docs/plans/chat-contacts-sync.md). Best effort, at most `waitMs`.
   */
  async flushContactList(waitMs = 3000): Promise<void> {
    const client = this.client
    if (!client.flushContactList) return
    await Promise.race([
      this.withLock(() => client.flushContactList!()).catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, waitMs)),
    ])
  }

  /**
   * Whether the account's contact list is full with nothing it may evict: a
   * change (a block too) holds on this device but waits to be written, and
   * the person is told.
   */
  async contactListFull(): Promise<boolean> {
    const client = this.client
    if (!client.contactListFull) return false
    return await this.withLock(() => Promise.resolve(client.contactListFull!()))
  }

  async leaveChatGroup(groupId: string): Promise<void> {
    await this.groupChange((client) => client.leaveGroup(groupId))
  }

  async removeChatGroupMember(groupId: string, pseudonym: string): Promise<void> {
    await this.groupChange((client) => client.removeGroupMember(groupId, pseudonym))
  }

  async setChatGroupAdmin(groupId: string, pseudonym: string, administrator: boolean): Promise<void> {
    await this.groupChange((client) => client.setGroupMemberAdmin(groupId, pseudonym, administrator))
  }

  private async sendChatGroupText(groupId: string, text: string, replyTo?: string): Promise<ChatGroupSend> {
    const client = this.groupClient()
    const sendId = crypto.randomUUID()
    const sent = await this.withLock(() =>
      client.sendGroupText(groupId, sendId, new Date().toISOString(), text, replyTo),
    )
    this.notifyPeers()
    return sent
  }

  /** The link, settings and administrators' actions (slice 3). */
  private groupSettingsClient(): Required<Pick<WasmChatClientHandle,
    | 'previewGroupLink' | 'joinGroupByLink' | 'groupDetails' | 'setGroupLink' | 'resetGroupLink'
    | 'setGroupDescription' | 'setGroupTimer' | 'setGroupAccess' | 'setGroupAnnouncementsOnly'
    | 'approveGroupRequest' | 'denyGroupRequest' | 'banGroupMember' | 'unbanGroup' | 'endGroup'
    | 'removeUnverifiedGroupMembers' | 'checkGroupRequest' | 'cancelGroupRequest'
    | 'setGroupAvatar' | 'removeGroupAvatar' | 'groupAvatar'>> {
    this.groupClient()
    const client = this.client
    if (!client.previewGroupLink || !client.joinGroupByLink || !client.groupDetails
      || !client.setGroupLink || !client.resetGroupLink || !client.setGroupDescription
      || !client.setGroupTimer || !client.setGroupAccess || !client.setGroupAnnouncementsOnly
      || !client.approveGroupRequest || !client.denyGroupRequest || !client.banGroupMember
      || !client.unbanGroup || !client.endGroup || !client.removeUnverifiedGroupMembers
      || !client.checkGroupRequest || !client.cancelGroupRequest
      || !client.setGroupAvatar || !client.removeGroupAvatar || !client.groupAvatar) {
      throw new ChatServiceError('serverUnsupported')
    }
    return client as never
  }

  /** What a group link (its URL fragment) leads to, read before joining. */
  async previewChatGroupLink(fragment: string): Promise<ChatGroupLinkPreview> {
    const client = this.groupSettingsClient()
    return this.withLock(() => client.previewGroupLink(fragment))
  }

  /** Joins through a link, or asks to when an administrator approves. */
  async joinChatGroupByLink(fragment: string): Promise<ChatGroupLinkJoin> {
    const client = this.groupSettingsClient()
    const joined = await this.withLock(() => client.joinGroupByLink(fragment))
    this.notifyPeers()
    return joined
  }

  /** Where this account's request stands: approved ones join, denied ones end. */
  async checkChatGroupRequest(groupId: string): Promise<ChatGroupRequestOutcome> {
    const client = this.groupSettingsClient()
    const outcome = await this.withLock(() => client.checkGroupRequest(groupId))
    if (outcome.kind !== 'pending' && outcome.kind !== 'unreachable') this.notifyPeers()
    return outcome
  }

  /** Withdraws this account's request to join. */
  async cancelChatGroupRequest(groupId: string): Promise<ChatGroupRequestOutcome> {
    const client = this.groupSettingsClient()
    const outcome = await this.withLock(() => client.cancelGroupRequest(groupId))
    this.notifyPeers()
    return outcome
  }

  async chatGroupDetails(groupId: string): Promise<ChatGroupDetails> {
    const client = this.groupSettingsClient()
    return this.withLock(() => client.groupDetails(groupId))
  }

  async setChatGroupLink(groupId: string, mode: ChatGroupLinkMode): Promise<void> {
    await this.groupSettingsChange((client) => client.setGroupLink(groupId, mode))
  }

  async resetChatGroupLink(groupId: string): Promise<void> {
    await this.groupSettingsChange((client) => client.resetGroupLink(groupId))
  }

  async setChatGroupDescription(groupId: string, description: string): Promise<void> {
    await this.groupSettingsChange((client) => client.setGroupDescription(groupId, description))
  }

  /** The disappearing-messages timer in seconds; 0 turns it off. */
  async setChatGroupTimer(groupId: string, seconds: number): Promise<void> {
    await this.groupSettingsChange((client) => client.setGroupTimer(groupId, seconds))
  }

  async setChatGroupAccess(
    groupId: string,
    attributes: 'member' | 'administrator',
    members: 'member' | 'administrator',
  ): Promise<void> {
    await this.groupSettingsChange((client) => client.setGroupAccess(groupId, attributes, members))
  }

  async setChatGroupAnnouncementsOnly(groupId: string, on: boolean): Promise<void> {
    await this.groupSettingsChange((client) => client.setGroupAnnouncementsOnly(groupId, on))
  }

  async approveChatGroupRequest(groupId: string, pseudonym: string): Promise<void> {
    await this.groupSettingsChange((client) => client.approveGroupRequest(groupId, pseudonym))
  }

  /** Turns a request down; it is banned from the link, as Signal does. */
  async denyChatGroupRequest(groupId: string, pseudonym: string): Promise<void> {
    await this.groupSettingsChange((client) => client.denyGroupRequest(groupId, pseudonym))
  }

  async banChatGroupMember(groupId: string, pseudonym: string, resetLink: boolean): Promise<void> {
    await this.groupSettingsChange((client) => client.banGroupMember(groupId, pseudonym, resetLink))
  }

  async unbanChatGroup(groupId: string, ban: ChatGroupBan): Promise<void> {
    await this.groupSettingsChange((client) => client.unbanGroup(groupId, ban))
  }

  /** Sets the group's picture: `image` already scaled down on this device. */
  async setChatGroupAvatar(groupId: string, image: Uint8Array, contentType: string): Promise<void> {
    await this.groupSettingsChange((client) => client.setGroupAvatar(groupId, image, contentType))
  }

  /** The group's picture, checked against the hash its state names. */
  async chatGroupAvatar(groupId: string): Promise<ChatGroupAvatarFetch> {
    const client = this.groupSettingsClient()
    return this.withLock(() => client.groupAvatar(groupId))
  }

  async removeChatGroupAvatar(groupId: string): Promise<void> {
    await this.groupSettingsChange((client) => client.removeGroupAvatar(groupId))
  }

  /** Ends the group for everyone. */
  async endChatGroup(groupId: string): Promise<void> {
    await this.groupSettingsChange((client) => client.endGroup(groupId))
  }

  /** Removes every unverified or banned member: how many. */
  async removeUnverifiedChatGroupMembers(groupId: string): Promise<number> {
    let removed = 0
    await this.groupSettingsChange(async (client) => {
      removed = await client.removeUnverifiedGroupMembers(groupId)
    })
    return removed
  }

  private async groupSettingsChange(
    change: (client: ReturnType<ChatService['groupSettingsClient']>) => Promise<void>,
  ): Promise<void> {
    const client = this.groupSettingsClient()
    try {
      await this.withLock(() => change(client))
    } catch (error) {
      throw groupFailure(error)
    }
    this.notifyPeers()
  }

  private async groupChange(change: (client: ReturnType<ChatService['groupClient']>) => Promise<void>): Promise<void> {
    const client = this.groupClient()
    try {
      await this.withLock(() => change(client))
    } catch (error) {
      throw groupFailure(error)
    }
    this.notifyPeers()
  }

  async groups(): Promise<LocalMlsConversationRecord[]> {
    return this.requireMls().conversations()
  }

  async groupAuthorityPolicyDetails(
    conversationId: string,
  ): Promise<MlsAuthorityPolicyInspection[]> {
    return this.requireMls().authorityPolicyDetails(conversationId)
  }

  async groupInvitations(): Promise<PendingMlsInvitation[]> {
    return this.requireMls().invitations()
  }

  async groupInvitationFeedback(): Promise<MlsInvitationFeedback[]> {
    return this.requireMls().invitationFeedback()
  }

  /** A new group, named from the start when `name` is given (Signal asks for one). */
  async createGroup(initialMember?: AccountRef, name?: string): Promise<LocalMlsConversationRecord> {
    const result = await this.withMlsWorkflow(async () => {
      const mls = this.requireMls()
      const self = this.account
      const authorities = new Set([self.server])
      if (initialMember) authorities.add(initialMember.server)
      const created = await mls.createGroup(self, [...authorities].sort(), name)
      return initialMember
        ? await mls.addMember(created.conversation.request.genesis.conversationId, initialMember)
        : created
    })
    this.notifyPeers()
    return result.conversation
  }

  async acceptGroupInvitation(invitation: PendingMlsInvitation): Promise<void> {
    await this.withMlsWorkflow(() => this.requireMls().acceptInvitation(invitation))
    this.notifyPeers()
  }

  async rejectGroupInvitation(invitation: PendingMlsInvitation): Promise<void> {
    await this.withMlsWorkflow(() => this.requireMls().rejectInvitation(invitation))
    this.notifyPeers()
  }

  async addGroupMember(conversationId: string, member: AccountRef): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().addMember(
        conversationId,
        member,
      ),
    )
    this.notifyPeers()
  }

  async removeGroupMember(conversationId: string, member: AccountRef): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().removeMember(
        conversationId,
        member,
      ),
    )
    this.notifyPeers()
  }

  async setGroupAdministrator(
    conversationId: string,
    member: AccountRef,
    isAdmin: boolean,
  ): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().setAdministrator(
        conversationId,
        member,
        isAdmin,
      ),
    )
    this.notifyPeers()
  }

  async setGroupAuthorities(
    conversationId: string,
    authorityDomains: string[],
  ): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().setAuthorities(conversationId, authorityDomains),
    )
    this.notifyPeers()
  }

  async publishGroupOwnerCandidate(conversationId: string): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().publishOwnerCandidate(conversationId),
    )
    this.notifyPeers()
  }

  async setGroupOwner(
    conversationId: string,
    member: AccountRef,
    isOwner: boolean,
  ): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().setOwnerRole(
        conversationId,
        member,
        isOwner,
      ),
    )
    this.notifyPeers()
    return finalized !== null
  }

  async pendingGroupOwnerApprovals(): Promise<PendingMlsOwnerApprovalRequest[]> {
    return this.requireMls().pendingOwnerApprovalRequests()
  }

  async approveGroupOwnerGovernance(conversationId: string): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().approveOwnerGovernance(conversationId),
    )
    this.notifyPeers()
  }

  async rejectGroupOwnerGovernance(conversationId: string): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().rejectOwnerGovernance(conversationId),
    )
    this.notifyPeers()
  }

  async closeGroup(conversationId: string): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().closeConversation(conversationId),
    )
    this.notifyPeers()
    return finalized !== null
  }

  async setGroupApplicationSenders(
    conversationId: string,
    applicationSenders: 'members' | 'administrators',
  ): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().setApplicationSenderPolicy(conversationId, applicationSenders),
    )
    this.notifyPeers()
    return finalized !== null
  }

  /** Leave the group (see MlsConversationService.leaveGroup). */
  async leaveGroup(conversationId: string): Promise<void> {
    await this.withMlsWorkflow(() => this.requireMls().leaveGroup(conversationId))
    this.notifyPeers()
  }

  /** Rename the group, or change its description or picture. */
  async setGroupInfo(
    conversationId: string,
    info: Omit<MlsGroupInfo, 'sequence' | 'inviteLink'>,
  ): Promise<void> {
    await this.withMlsWorkflow(() => this.requireMls().setGroupInfo(conversationId, info))
    this.notifyPeers()
  }

  /**
   * Wake this device through a browser push subscription while Chat is
   * closed (`null` stops it). The push carries nothing: see docs/chat-notifications.md.
   */
  async setPushSubscription(endpoint: string | null): Promise<void> {
    if (endpoint) await api.put('/chat/push-subscription', { deviceId: this.deviceId, endpoint })
    else await api.delete('/chat/push-subscription', { params: { deviceId: this.deviceId } })
  }

  /** Turn a group's link on or off, reset it, or change whether joining needs approval. */
  async changeInviteLink(conversationId: string, change: InviteLinkChange): Promise<void> {
    await this.withMlsWorkflow(() => this.requireInvites().change(conversationId, change))
    this.notifyPeers()
  }

  /** The URL to share for a group's link. */
  inviteLinkUrl(link: MlsGroupInviteLink): string {
    return this.requireInvites().url(link, window.location.origin)
  }

  /** People waiting for an administrator of this account's groups (no network). */
  groupJoinRequests(): GroupJoinRequest[] {
    return this.invites?.joinRequests() ?? []
  }

  /** Look for new requests now (opening a group's details). */
  async refreshGroupJoinRequests(): Promise<void> {
    if (!this.invites) return
    const changed = await this.withMlsWorkflow(() => this.invites!.reconcileRequests(true))
    if (changed) this.emitUpdate()
  }

  async decideGroupJoinRequest(
    conversationId: string,
    requester: string,
    approve: boolean,
  ): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireInvites().decide(conversationId, requester, approve))
    this.notifyPeers()
  }

  /** What a group link leads to; throws an {@link InviteLinkError} when nowhere. */
  async lookUpInviteLink(url: string): Promise<InviteLinkLookup> {
    return this.requireInvites().lookUp(url)
  }

  async requestToJoin(lookup: InviteLinkLookup): Promise<OwnJoinRequest> {
    const request = await this.requireInvites().requestToJoin(lookup)
    this.notifyPeers()
    // An administrator may add at once when no approval is needed.
    setTimeout(() => void this.reconcileInviteLinks(true), 5_000)
    return request
  }

  ownJoinRequests(): OwnJoinRequest[] {
    return this.invites?.ownRequests() ?? []
  }

  async cancelJoinRequest(linkId: string): Promise<void> {
    await this.requireInvites().cancel(linkId)
    this.notifyPeers()
  }

  /**
   * Bring this account's newly linked devices into its groups without
   * waiting for this tab to be reopened (the manifest check is one request).
   */
  private startLinkedDeviceChecks(): void {
    if (!this.mls || this.linkedDeviceTimer) return
    this.linkedDeviceTimer = setInterval(() => {
      if (this.disposed) return
      void this.initializeMls().catch((error: unknown) =>
        console.warn('chat: linked device check failed', error))
      void this.refreshOwnProfile()
    }, LINKED_DEVICE_CHECK_MS)
  }

  /**
   * Each pass waits about a minute (five in a hidden tab), give or take a
   * fifth, so devices don't line up their list reads and writes.
   */
  private startAccountListSync(): void {
    const client = this.client
    if (this.accountListsTimer || !client.syncAccountLists) return
    const next = () => {
      if (this.disposed) return
      const base = document.visibilityState === 'visible' ? ACCOUNT_LISTS_MS : ACCOUNT_LISTS_HIDDEN_MS
      const delay = base * (0.8 + Math.random() * 0.4)
      this.accountListsTimer = setTimeout(() => {
        void this.withLock(() => client.syncAccountLists!())
          .catch((error: unknown) => console.warn('chat: the account lists could not be synced', error))
          .finally(next)
      }, delay)
    }
    next()
  }

  /**
   * Catches up every pairwise group this account is in, one at a time, at
   * jittered intervals: soon after opening, then about every ten minutes
   * (thirty in a hidden tab), give or take a fifth, so members' devices
   * don't line up.
   */
  private startGroupSync(): void {
    if (this.groupSyncTimer || this.capabilities.pairwiseGroups !== true) return
    const client = this.client
    if (!client.listGroups || !client.syncGroup) return
    const next = (base: number) => {
      if (this.disposed) return
      const delay = base * (0.8 + Math.random() * 0.4)
      this.groupSyncTimer = setTimeout(() => {
        void this.syncMemberGroups()
          .catch((error: unknown) => console.warn('chat: the groups could not be caught up', error))
          .finally(() => next(document.visibilityState === 'visible' ? GROUP_SYNC_MS : GROUP_SYNC_HIDDEN_MS))
      }, delay)
    }
    next(GROUP_SYNC_FIRST_MS)
  }

  private async syncMemberGroups(): Promise<void> {
    const client = this.groupClient()
    const groups = await this.withLock(() => client.listGroups())
    const settings = this.client.checkGroupRequest ? this.groupSettingsClient() : null
    for (const group of groups) {
      if (this.disposed) return
      // One group failing (its home unreachable) never stops the others.
      if (group.status === 'member') {
        await this.withLock(() => client.syncGroup(group.groupId)).catch((error: unknown) =>
          console.warn('chat: a group could not be caught up', error),
        )
      } else if (group.status === 'requesting' && settings) {
        // An approval or a denial is learnt here: the home tells nobody.
        await this.withLock(() => settings.checkGroupRequest(group.groupId)).catch((error: unknown) =>
          console.warn('chat: a request to join could not be checked', error),
        )
      }
    }
    this.notifyPeers()
  }

  private startPrekeyChecks(): void {
    if (this.prekeyTimer) return
    this.prekeyTimer = setInterval(() => {
      if (!this.disposed) void this.maintainPrekeys()
    }, PREKEY_CHECK_MS)
  }

  private startInviteLinks(): void {
    if (!this.invites || this.inviteTimer) return
    void this.reconcileInviteLinks()
    this.inviteTimer = setInterval(() => void this.reconcileInviteLinks(), INVITE_LINK_POLL_MS)
  }

  private async reconcileInviteLinks(force = false): Promise<void> {
    if (!this.invites || this.disposed) return
    try {
      const changed = await this.withMlsWorkflow(async () => {
        const requests = await this.invites!.reconcileRequests(force)
        const own = await this.invites!.reconcileOwnRequests(force)
        return requests || own
      })
      if (changed) this.notifyPeers()
    } catch (error) {
      console.warn('chat: group link check failed', error)
    }
  }

  private requireInvites(): InviteLinkService {
    if (!this.invites) throw new Error('MLS groups are not enabled by this server')
    return this.invites
  }

  /** Who may change the group's information; false when it waits for other owners. */
  async setGroupInfoEditors(
    conversationId: string,
    editors: 'members' | 'administrators',
  ): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().setGroupInfoEditors(conversationId, editors),
    )
    this.notifyPeers()
    return finalized !== null
  }

  async tightenGroupMaximumPlaintext(
    conversationId: string,
    maximumBytes: number,
  ): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().tightenMaximumApplicationPlaintext(conversationId, maximumBytes),
    )
    this.notifyPeers()
    return finalized !== null
  }

  async recoverGroup(
    conversationId: string,
    authorityDomains?: string[],
  ): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().recoverConversation(
        conversationId,
        authorityDomains,
      ),
    )
    this.notifyPeers()
    return finalized !== null
  }

  async maintainPrekeys(): Promise<void> {
    try {
      await this.withLock(() => this.client.maintainPrekeys())
    } catch {
      // Mail delivery remains usable; the next check or reconnect retries.
    }
  }

  async safetyNumber(peer: string): Promise<SafetyNumberV2> {
    const account = requireAccountKey(peer)
    return this.withLock(() => this.client.safetyNumber(account))
  }

  async verifySafetyNumber(peer: string, scannedPayload: string): Promise<SafetyNumberV2> {
    const account = requireAccountKey(peer)
    const verified = await this.withLock(() =>
      this.client.verifySafetyNumber(account, scannedPayload),
    )
    this.notifyPeers()
    return verified
  }

  /** Mark the contact's identity verified (or clear it) after comparing the numbers. */
  async setIdentityVerified(peer: string, identityKey: string, verified: boolean): Promise<SafetyNumberV2> {
    const account = requireAccountKey(peer)
    const safety = await this.withLock(() =>
      this.client.setIdentityVerified(account, identityKey, verified),
    )
    this.notifyPeers()
    return safety
  }

  /**
   * Link a new device of this account from the code it shows (scanned or
   * pasted), sending it the account identity and these settings. `false`:
   * the code expired, and the new device shows a new one.
   */
  async linkDevice(
    code: string,
    settings: { readReceipts: boolean; typingIndicators: boolean },
  ): Promise<boolean> {
    return await this.withLock(() =>
      this.client.linkDevice(code.trim(), settings.readReceipts, settings.typingIndicators),
    )
  }

  /**
   * Reset the account's identity, keeping its devices but `remove` (a lost or
   * stolen one), which leave the account. Contacts see the safety number
   * change once. Returns the devices kept.
   */
  async resetIdentity(remove: number[]): Promise<ChatDevice[]> {
    await this.withLock(() => this.client.resetIdentity(remove))
    this.notifyPeers()
    return this.devices()
  }

  async quarantineInbound(id: string): Promise<void> {
    await this.withLock(() => this.client.quarantineInbound(id))
    this.notifyPeers()
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    if (this.socketRetry) clearTimeout(this.socketRetry)
    if (this.heldRetry) clearTimeout(this.heldRetry)
    this.stopPolling()
    if (this.inviteTimer) clearInterval(this.inviteTimer)
    if (this.linkedDeviceTimer) clearInterval(this.linkedDeviceTimer)
    if (this.prekeyTimer) clearInterval(this.prekeyTimer)
    if (this.accountListsTimer) clearTimeout(this.accountListsTimer)
    if (this.groupSyncTimer) clearTimeout(this.groupSyncTimer)
    this.engineLock.close()
    this.stopHeartbeat()
    this.socket?.close()
    window.removeEventListener('online', this.handleOnline)
    window.removeEventListener('offline', this.handleOffline)
    document.removeEventListener('visibilitychange', this.handleVisibilityChange)
    this.channel.close()
    this.listeners.clear()
    this.typingListeners.clear()
    this.connectionListeners.clear()
    this.attachmentExpiryListeners.clear()
    this.attachmentLedger?.dispose()
    this.backupUnsubscribe?.()
    this.backup?.dispose()
    this.client.free()
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    return await this.engineLock.run(operation)
  }

  private async withAttachmentLedgerLock<T>(operation: () => Promise<T>): Promise<T> {
    return navigator.locks.request(
      `${this.lockName}:attachment-ledger`,
      { mode: 'exclusive' },
      operation,
    )
  }

  /**
   * Give every attachment in the history its ledger entry. The whole
   * history is looked at once per session (and when changes are not known);
   * after that only the newest entries of the conversations this tab's
   * writes changed. An attachment that cannot be entered yet (its delivery
   * still retrying, a message request not yet accepted) waits in
   * `pendingAttachments` and is tried again on every pass.
   */
  private async reconcileAttachmentLedger(): Promise<boolean> {
    if (!this.attachmentLedger) return false
    let entered = false
    const changes = await this.changesSince(this.ledgerMark)
    let seen: ChatHistoryEntry[] = []
    if (changes.keys === null) {
      seen = await this.history()
    } else {
      for (const key of changes.keys) seen.push(...await this.newestEntries(key, LEDGER_PAGE))
    }
    this.ledgerMark = changes.mark
    for (const message of seen) {
      const descriptor = message.content.attachment
      const messageId = message.content.messageId
      if (descriptor && messageId) this.pendingAttachments.set(`${messageId}\u0000${descriptor.attachmentId}`, message)
    }
    const contacts = await this.contacts()
    const accepted = new Set(
      contacts.filter(contact => contact.state === 'accepted').map(contact => contact.peer),
    )
    const self = this.selfKey()
    await this.withAttachmentLedgerLock(async () => {
      await this.attachmentLedger!.sync()
      // An expiry revision is durable and account-private. Retry its opaque
      // server-reference deletion after a crash or a transient network error;
      // DELETE is idempotent and a missing reference is already success.
      for (const entity of this.attachmentLedger!.entries()) {
        if (entity.entry.state === 'expired') {
          await this.deleteAttachmentReference(entity.entry.attachmentId)
        }
      }
      for (const [pendingKey, message] of [...this.pendingAttachments]) {
        const descriptor = message.content.attachment!
        const messageId = message.content.messageId
        if (this.attachmentLedger!.hasAttachment(messageId, descriptor.attachmentId)) {
          this.pendingAttachments.delete(pendingKey)
          continue
        }
        if (message.conversation.kind === 'direct') {
          const peer = accountKey(message.conversation.account)
          if (peer !== self && !accepted.has(peer)) continue
        }
        try {
          const response = await api.get<{
            attachmentId: string
            storageReferenceId: string
            ciphertextBytes: number
            ciphertextSha256: string
          }>(`/chat/media/references/${encodeURIComponent(descriptor.attachmentId)}`)
          const reference = response.data
          if (reference.attachmentId !== descriptor.attachmentId ||
              reference.ciphertextBytes !== descriptor.ciphertextBytes ||
              reference.ciphertextSha256 !== descriptor.ciphertextSha256) {
            throw new Error('Chat-media reference differs from its E2EE descriptor')
          }
          await this.createAttachmentLedgerEntry(
            message.conversation,
            messageId,
            descriptor,
            reference.storageReferenceId,
          )
          this.pendingAttachments.delete(pendingKey)
          entered = true
        } catch (error: unknown) {
          const status = typeof error === 'object' && error !== null && 'response' in error
            ? (error as { response?: { status?: number } }).response?.status
            : undefined
          // Delivery may still be retrying or a message request may be
          // unaccepted. A later reconcile retries without allocating storage.
          if (status !== 404) throw error
        }
      }
    })
    return entered
  }

  private async releaseExpiredAttachments(report: ChatExpiryReport): Promise<void> {
    if (report.expiredAttachmentIds.length === 0) return
    const expiredIds = new Set(report.expiredAttachmentIds)
    if (this.attachmentLedger) {
      await this.withAttachmentLedgerLock(async () => {
        await this.attachmentLedger!.sync()
        const targets = this.attachmentLedger!.activeEntries().filter(
          entity => expiredIds.has(entity.entry.attachmentId),
        )
        const expiredAt = Date.now()
        for (const target of targets) {
          await this.attachmentLedger!.markExpired(target.entityId, expiredAt)
        }
        for (const attachmentId of expiredIds) {
          await this.deleteAttachmentReference(attachmentId)
        }
      })
    }
    await Promise.allSettled([...this.attachmentExpiryListeners].map(
      listener => listener([...expiredIds]),
    ))
  }

  private async deleteAttachmentReference(attachmentId: string): Promise<void> {
    try {
      await api.delete(`/chat/media/references/${encodeURIComponent(attachmentId)}`)
    } catch (error: unknown) {
      const status = typeof error === 'object' && error !== null && 'response' in error
        ? (error as { response?: { status?: number } }).response?.status
        : undefined
      if (status !== 404) throw error
    }
  }

  /**
   * Serialize complete MLS workflows, including their network phases, across
   * tabs. The engine lock above still protects each durable cryptographic
   * transaction; this separate lock prevents reconciliation from observing a
   * prepared workflow and racing its order/finalize steps.
   */
  private async withMlsWorkflow<T>(operation: () => Promise<T>): Promise<T> {
    return await navigator.locks.request(
      this.mlsWorkflowLockName,
      { mode: 'exclusive' },
      async () => await operation(),
    )
  }

  private requireMls(): MlsConversationService {
    if (!this.mls) throw new Error('MLS groups are not enabled by this server')
    return this.mls
  }

  /** This account's key, `aci:<uuid>@<server>` (Note to Self's peer). */
  private selfKey(): string {
    return accountKey(this.account)
  }

  private backupMediaSources(): BackupMediaSource[] {
    return (this.attachmentLedger?.activeEntries() ?? []).map(({ entry }) => ({
      attachmentId: entry.attachmentId,
      referenceId: entry.storageReferenceId,
      ciphertextBytes: entry.ciphertextBytes,
    }))
  }

  private async initializeMls(): Promise<void> {
    await this.withMlsWorkflow(async () => {
      const manifest = await this.withLock(() => this.client.syncManifest())
      if (!this.mls) return
      const sequence = requireManifestSequence(manifest)
      await this.mls.maintainKeyPackages(sequence)
      await this.mls.reconcileLinkedDevices(requireMlsManifestDeviceIds(manifest))
      await this.mls.reconcileMemberDevices()
    })
  }

  private notifyPeers(): void {
    this.channel.postMessage({ type: 'updated' })
    this.emitUpdate()
    this.backup?.schedule()
  }

  private async contactAction(
    peer: string,
    action: (corePeer: string) => Promise<ContactRecord>,
  ): Promise<ContactRecord> {
    const corePeer = requireAccountKey(peer)
    const result = await this.withLock(() => action(corePeer))
    this.notifyPeers()
    return result
  }

  /** Something may have changed (here, in another tab, in the backup). */
  private emitUpdate(): void {
    this.revision += 1
    for (const listener of this.listeners) listener()
  }

  private emitTyping(event: ChatTypingEvent, broadcast: boolean): void {
    if (broadcast) this.channel.postMessage({ type: 'typing', event })
    for (const listener of this.typingListeners) listener(event)
  }

  private readonly handleOnline = (): void => this.wentOnline()

  private readonly handleOffline = (): void => this.wentOffline()

  private wentOnline(): void {
    this.backup?.online()
    void this.initializeMls().catch(reportBackgroundFailure).then(() => this.reconcileInBackground())
    this.reconnect()
  }

  private wentOffline(): void {
    this.stopPolling()
    this.setConnection('offline')
    // The socket may linger half-open; drop it so the reconnect starts clean.
    this.socket?.close()
  }

  private setConnection(status: ChatConnectionStatus): void {
    if (this.disposed || this.connection === status) return
    this.connection = status
    for (const listener of this.connectionListeners) listener(status)
  }

  private startHeartbeat(socket: WebSocket): void {
    this.stopHeartbeat()
    this.heartbeat = setInterval(() => {
      if (socket.readyState !== WebSocket.OPEN || this.pongDeadline) return
      socket.send(JSON.stringify({ type: 'ping' }))
      this.pongDeadline = setTimeout(() => {
        this.pongDeadline = null
        socket.close()
      }, PONG_TIMEOUT_MS)
    }, PING_INTERVAL_MS)
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) clearInterval(this.heartbeat)
    if (this.pongDeadline) clearTimeout(this.pongDeadline)
    this.heartbeat = null
    this.pongDeadline = null
  }

  private readonly handleVisibilityChange = (): void => {
    this.backup?.pageHidden()
    if (document.visibilityState === 'visible') {
      void this.initializeMls().catch(reportBackgroundFailure).then(() => this.reconcileInBackground())
      void this.refreshOwnProfile()
    }
  }

  /**
   * Take a newer version of the account's profile (edited in the account
   * app, docs/plans/unified-profile.md); the engine tells contacts.
   */
  private async refreshOwnProfile(): Promise<void> {
    try {
      await this.withLock(() => this.client.refreshProfile())
      this.notifyPeers()
    } catch (error) {
      console.warn('chat: profile refresh failed', error)
    }
  }

  private async connectSocket(): Promise<void> {
    if (this.disposed || this.socket?.readyState === WebSocket.OPEN) return
    if (this.socket?.readyState === WebSocket.CONNECTING) return
    this.socketDown()
    try {
      const response = await api.post<{ ticket: string }>('/chat/ws-ticket', null, {
        params: { deviceId: this.deviceId },
      })
      if (this.disposed) return
      const base = await resolveApiBase()
      const url = new URL(`${base.replace(/\/$/, '')}/chat/ws`, window.location.href)
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
      url.searchParams.set('ticket', response.data.ticket)
      const socket = new WebSocket(url)
      this.socket = socket
      socket.onopen = () => {
        this.retryAttempt = 0
        this.stopPolling()
        this.setConnection('connected')
        this.startHeartbeat(socket)
        void this.maintainPrekeys()
        void this.initializeMls().catch(reportBackgroundFailure).then(() => this.reconcileInBackground())
      }
      socket.onmessage = (event: MessageEvent<unknown>) => {
        if (isPong(event.data)) {
          if (this.pongDeadline) clearTimeout(this.pongDeadline)
          this.pongDeadline = null
          return
        }
        if (isDevicesChanged(event.data)) this.devicesChanged()
        this.reconcileInBackground()
      }
      socket.onerror = () => socket.close()
      socket.onclose = () => {
        if (this.socket !== socket) return
        this.socket = null
        this.stopHeartbeat()
        this.socketDown()
        this.scheduleSocketRetry()
      }
    } catch (error) {
      // The server answered that this device does not exist: retrying will
      // not bring it back, and "reconnecting" forever would hide that.
      // Only the server's own answer counts: a 404 from a proxy, or from a
      // server where Chat is off, says nothing about this device, and the
      // repair offered for a removed one drops what waits to be sent.
      if (isAxiosError(error) && isDeviceGone(error.response?.status, error.response?.data)) {
        this.stopPolling()
        this.setConnection('deviceRemoved')
        return
      }
      this.socketDown()
      this.scheduleSocketRetry()
    }
  }

  /** No socket right now. While polling works, that is what the status stays. */
  private socketDown(): void {
    if (navigator.onLine === false) this.setConnection('offline')
    else if (this.connection !== 'polling') this.setConnection('connecting')
  }

  /**
   * Read the mailbox on a timer for as long as the socket stays down. The
   * socket is still retried beside it and takes over the moment it opens.
   */
  private startPolling(): void {
    // One loop at a time: `pollTimer` is empty while a read is in flight,
    // so it cannot say whether one runs.
    if (this.disposed || this.polling) return
    this.polling = true
    const tick = (): void => {
      this.pollTimer = null
      if (
        this.disposed ||
        !this.polling ||
        this.socket?.readyState === WebSocket.OPEN ||
        this.connection === 'deviceRemoved' ||
        navigator.onLine === false
      ) {
        this.polling = false
        return
      }
      this.reconcile()
        .then(() => {
          if (this.socket?.readyState !== WebSocket.OPEN && this.connection === 'connecting') this.setConnection('polling')
        })
        .catch((error: unknown) => {
          // The server did not answer either: this is not a blocked socket.
          if (this.connection === 'polling') this.setConnection('connecting')
          reportBackgroundFailure(error)
        })
        .finally(() => {
          if (this.disposed || !this.polling || this.socket?.readyState === WebSocket.OPEN) {
            this.polling = false
            return
          }
          this.pollTimer = setTimeout(tick, document.visibilityState === 'visible' ? POLL_VISIBLE_MS : POLL_HIDDEN_MS)
        })
    }
    this.pollTimer = setTimeout(tick, 0)
  }

  private stopPolling(): void {
    if (this.pollTimer) clearTimeout(this.pollTimer)
    this.pollTimer = null
    this.polling = false
  }

  private scheduleSocketRetry(): void {
    if (this.disposed || this.socketRetry) return
    const delay = Math.min(30_000, 500 * 2 ** this.retryAttempt++)
    if (this.retryAttempt >= POLL_AFTER_ATTEMPTS) this.startPolling()
    this.socketRetry = setTimeout(() => {
      this.socketRetry = null
      if (!this.polling) this.reconcileInBackground()
      void this.connectSocket()
    }, delay)
  }
}

/**
 * Ask the browser to keep this origin's storage. Without it Chat's keys and
 * sessions are "best effort": the browser may evict them under disk
 * pressure, and Safari clears script-written storage of sites left unvisited
 * for a week. Browsers grant it by their own rules (engagement, an installed
 * app, a prompt in Firefox); a refusal changes nothing.
 */
function requestPersistentStorage(): void {
  try {
    void navigator.storage?.persist?.().catch(() => undefined)
  } catch {
    // Not available here.
  }
}

function reportBackgroundFailure(error: unknown): void {
  console.warn('chat: background sync failed; it runs again on the next update', error)
}

function isDevicesChanged(data: unknown): boolean {
  if (typeof data !== 'string' || data.length > 64) return false
  try {
    return (JSON.parse(data) as { type?: unknown }).type === 'devicesChanged'
  } catch {
    return false
  }
}

function isPong(data: unknown): boolean {
  if (typeof data !== 'string' || data.length > 64) return false
  try {
    return (JSON.parse(data) as { type?: unknown }).type === 'pong'
  } catch {
    return false
  }
}

function parseTypingBroadcast(value: unknown): ChatTypingEvent | null {
  if (!value || typeof value !== 'object') return null
  const message = value as { type?: unknown; event?: unknown }
  if (message.type !== 'typing' || !message.event || typeof message.event !== 'object') return null
  const event = message.event as Partial<ChatTypingEvent>
  if (typeof event.sender !== 'string' || typeof event.active !== 'boolean') return null
  if (event.conversation?.kind === 'group' && typeof event.conversation.groupId === 'string') {
    return event as ChatTypingEvent
  }
  if (event.conversation?.kind === 'direct') {
    const account = (event.conversation as { account?: unknown }).account
    if (account && typeof account === 'object') {
      const candidate = account as { server?: unknown; accountId?: unknown }
      if (
        typeof candidate.server === 'string'
        && typeof candidate.accountId === 'string'
        && parseAccount(`aci:${candidate.accountId}@${candidate.server}`)
      ) {
        return event as ChatTypingEvent
      }
    }
  }
  return null
}

/** A peer given as its account key; anything else (an address too) is refused. */
function requireAccountKey(peer: string): string {
  if (!parseAccount(peer)) throw new Error('not a chat account')
  return peer
}

function requireManifestSequence(value: unknown): number {
  if (
    typeof value !== 'object'
    || value === null
    || !('sequence' in value)
    || typeof value.sequence !== 'number'
    || !Number.isSafeInteger(value.sequence)
    || value.sequence < 1
  ) {
    throw new Error('signed account manifest returned an invalid sequence')
  }
  return value.sequence
}

function requireMlsManifestDeviceIds(value: unknown): number[] {
  if (
    typeof value !== 'object'
    || value === null
    || !('devices' in value)
    || !Array.isArray(value.devices)
    || value.devices.length < 1
    || value.devices.length > 10
  ) {
    throw new Error('signed device manifest returned an invalid MLS device set')
  }
  const manifestIds: number[] = []
  const mlsIds: number[] = []
  for (const entry of value.devices) {
    if (
      typeof entry !== 'object'
      || entry === null
      || !('deviceId' in entry)
      || typeof entry.deviceId !== 'number'
      || !Number.isSafeInteger(entry.deviceId)
      || entry.deviceId < 1
      || entry.deviceId > 127
    ) {
      throw new Error('signed device manifest contains an invalid device id')
    }
    manifestIds.push(entry.deviceId)
    if (!('mls' in entry) || entry.mls === null || entry.mls === undefined) continue
    if (typeof entry.mls !== 'object') {
      throw new Error('signed device manifest contains invalid MLS keys')
    }
    mlsIds.push(entry.deviceId)
  }
  if (new Set(manifestIds).size !== manifestIds.length) {
    throw new Error('signed device manifest repeats a device id')
  }
  if (mlsIds.length < 1) {
    throw new Error('signed device manifest has no MLS-capable device')
  }
  return mlsIds.sort((left, right) => left - right)
}

function localStorageOrNull(): Storage | null {
  try {
    return window.localStorage
  } catch {
    return null
  }
}

function parseCallBroadcast(value: unknown): ChatCallEvent | null {
  if (!value || typeof value !== 'object') return null
  const message = value as { type?: unknown; event?: unknown }
  if (message.type !== 'call' || !message.event || typeof message.event !== 'object') return null
  const event = message.event as Partial<ChatCallEvent>
  if (
    typeof event.peer !== 'string'
    || typeof event.senderDeviceId !== 'number'
    || typeof event.sentAt !== 'string'
    || !event.call
    || typeof event.call.callId !== 'string'
  ) {
    return null
  }
  return event as ChatCallEvent
}

/** The server's answer when it does not know this browser's Chat device. */
function isNoSuchDevice(body: unknown): boolean {
  return typeof body === 'object' && body !== null && (body as { error?: unknown }).error === 'no such chat device'
}

/**
 * The server's own answer that this browser's Chat device is gone: its
 * credential matches no live device of the account (`401 deviceCredential`:
 * removed here or on another device, or dropped by a re-registration), or the
 * older `404` for a device id it doesn't know.
 */
export function isDeviceGone(status: number | undefined, body: unknown): boolean {
  if (status === 401) {
    return typeof body === 'object' && body !== null && (body as { code?: unknown }).code === 'deviceCredential'
  }
  return status === 404 && isNoSuchDevice(body)
}

/** Newest entries per changed conversation the attachment ledger looks at. */
const LEDGER_PAGE = 100
/** Search candidates asked of the core's index (more than are shown: some are edited or deleted away). */
const SEARCH_CANDIDATES = 200

/** Restored entries per conversation that join the live window. */
const RESTORED_RECENT = 30

/** When the soonest disappearing message among `entries` is due (or never). */
function nextDeadline(entries: readonly ChatHistoryEntry[]): number {
  const now = Date.now()
  let next = Infinity
  for (const entry of entries) {
    const at = entry.content.expiresAtMs
    if (at !== undefined && at > now && at < next) next = at
  }
  return next
}

function canonicalPeer(peer: string): string {
  return peer.trim().toLowerCase()
}
