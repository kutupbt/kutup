import api from '@kutup/session/client'
import { resolveApiBase } from '@kutup/session/apiBase'
import { ApiChatTransport } from './transport'
import type {
  AccountAddress,
  ChatCapabilities,
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
  ChatPollV1,
  ChatStickerV1,
  ChatViewOnceOpenedV1,
  ChatConversationStateV1,
  PeerChatProfile,
  ReceiveReport,
  SendSummary,
  LocalMlsConversationRecord,
  GroupJoinRequest,
  InviteLinkCrypto,
  MlsGroupInfo,
  MlsGroupInviteLink,
  OwnJoinRequest,
  MlsInvitationFeedback,
  MlsAuthorityPolicyInspection,
  PendingMlsOwnerApprovalRequest,
  PendingMlsInvitation,
  SafetyNumberV1,
  WasmChatClientHandle,
} from './types'
import { loadChatWasm } from './wasm'
import { isSupportedChat } from './capabilities'
import {
  canonicalAccountAddress,
  parseAccountAddress,
  toCoreAccountAddress,
  withHomeServer,
} from './identity'
import { MlsConversationService } from './mls-service'
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
export type ChatConnectionStatus = 'connected' | 'connecting' | 'offline'

/** The protocol's limit on messages per delete-for-me control. */
const DELETE_FOR_ME_BATCH = 64

const PING_INTERVAL_MS = 25_000
const PONG_TIMEOUT_MS = 10_000

export type ChatServiceErrorCode = 'browserUnsupported' | 'serverUnsupported'

export class ChatServiceError extends Error {
  constructor(readonly code: ChatServiceErrorCode) {
    super(code)
    this.name = 'ChatServiceError'
  }
}

export interface ChatServiceOptions {
  userId: string
  email: string
  username: string
  masterKey: Uint8Array
  capabilities: ChatCapabilities
}

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
  private readonly connectionListeners = new Set<(status: ChatConnectionStatus) => void>()
  private disposed = false
  private reconcilePromise: Promise<ReceiveReport> | null = null
  private reconcileAgain = false
  private readonly mls: MlsConversationService | null
  private readonly invites: InviteLinkService | null
  private inviteTimer: ReturnType<typeof setInterval> | null = null
  private backup: ChatBackupCoordinator | null = null
  private backupUnsubscribe: (() => void) | null = null

  private constructor(
    client: WasmChatClientHandle,
    lockName: string,
    channelName: string,
    capabilities: ChatCapabilities,
    private readonly transport: ApiChatTransport,
    private readonly username: string,
    private readonly attachmentLedger: ChatAttachmentLedger | null,
    inviteCrypto: InviteLinkCrypto,
  ) {
    this.client = client
    this.deviceId = client.deviceId
    this.lockName = lockName
    this.mlsWorkflowLockName = `${lockName}:mls-workflow`
    this.capabilities = capabilities
    this.mls = capabilities.mlsGroups === true
      ? new MlsConversationService(
          client,
          transport,
          operation => this.withLock(operation),
          this.deviceId,
          { username, server: capabilities.serverName! },
        )
      : null
    this.invites = this.mls
      ? new InviteLinkService(
          this.mls,
          transport,
          inviteCrypto,
          { username, server: capabilities.serverName! },
          localStorageOrNull(),
        )
      : null
    this.channel = new BroadcastChannel(channelName)
    this.channel.onmessage = (message: MessageEvent<unknown>) => {
      const event = parseTypingBroadcast(message.data)
      if (event) this.emitTyping(event, false)
      else this.emitUpdate()
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
    const client = await navigator.locks.request(lockName, { mode: 'exclusive' }, () =>
      wasm.WasmChatClient.open(
        databaseName,
        options.username,
        capabilities.serverName!,
        capabilities.sealedSender,
        options.masterKey,
        transport,
      ),
    )

    let attachmentLedger: ChatAttachmentLedger | null = null
    try {
      attachmentLedger = capabilities.media
        ? await ChatAttachmentLedger.open(options.masterKey)
        : null
    } catch (error) {
      client.free()
      throw error
    }
    const service = new ChatService(
      client,
      lockName,
      channelName,
      capabilities,
      transport,
      options.username,
      attachmentLedger,
      wasm,
    )
    try {
      if (capabilities.backup?.alwaysEnabled) {
        service.backup = await ChatBackupCoordinator.open({
          databaseName,
          email: options.email,
          username: options.username,
          serverName: capabilities.serverName!,
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
        })
        service.backupUnsubscribe = service.backup.subscribe(() => service.emitUpdate())
      }
      await service.initializeMls()
      await service.reconcile()
      void service.maintainPrekeys()
      void service.connectSocket()
      service.startInviteLinks()
      return service
    } catch (error) {
      service.dispose()
      throw error
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
    void this.reconcile()
    void this.connectSocket()
  }

  subscribeConnection(listener: (status: ChatConnectionStatus) => void): () => void {
    this.connectionListeners.add(listener)
    return () => this.connectionListeners.delete(listener)
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

  async history(): Promise<ChatHistoryEntry[]> {
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

  private async liveHistory(): Promise<ChatHistoryEntry[]> {
    const { history, expiry } = await this.withLock(async () => {
      const expiry = await this.client.purgeExpiredMessages(String(Date.now()))
      return { expiry, history: await this.client.history() }
    })
    await this.releaseExpiredAttachments(expiry)
    return history.map((entry) => {
      if (entry.conversation.kind !== 'direct') return entry
      const address = withHomeServer(entry.conversation.address, this.capabilities.serverName)
      return {
        ...entry,
        conversation: { kind: 'direct' as const, address },
        peer: canonicalAccountAddress(address),
      }
    })
  }

  async contacts(): Promise<ContactRecord[]> {
    const contacts = await this.withLock(() => this.client.contacts())
    return contacts.map((contact) => {
      const parsed = parseAccountAddress(contact.peer)
      if (!parsed) return contact
      return {
        ...contact,
        peer: canonicalAccountAddress(
          withHomeServer(parsed, this.capabilities.serverName),
        ),
      }
    })
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
    const profiles = await this.withLock(() => this.client.profiles())
    return profiles.map((profile) => {
      const parsed = parseAccountAddress(profile.peer)
      if (!parsed) return profile
      return {
        ...profile,
        peer: canonicalAccountAddress(
          withHomeServer(parsed, this.capabilities.serverName),
        ),
      }
    })
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
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendText(
          conversation.groupId,
          text,
          replyTo,
          expiresAfterSeconds,
          extras,
        ),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
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
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendAttachment(
          conversation.groupId,
          sendId,
          descriptor,
          expiresAfterSeconds,
          extras,
        ),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const address = withHomeServer(conversation.address, this.capabilities.serverName)
    const peer = toCoreAccountAddress(address, this.capabilities.serverName)
    const self = `${this.username}@${this.capabilities.serverName}`
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
    kind: 'poll' | 'pollVote' | 'pollTerminate',
    body: unknown,
    expiresAfterSeconds?: number,
  ): Promise<SendSummary> {
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendPollContent(conversation.groupId, kind, body, expiresAfterSeconds),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
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
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendReaction(
          conversation.groupId,
          targetMessageId,
          emoji,
          active,
        ),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
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
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
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
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendReceipt(conversation.groupId, messageIds, state),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
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
    if (conversation.kind === 'group') {
      await this.withMlsWorkflow(() =>
        this.requireMls().sendTyping(conversation.groupId, active),
      )
      return
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
    const self = `${this.username}@${this.capabilities.serverName}`
    if (peer === self) return
    await this.withLock(() => this.client.sendTyping(
      crypto.randomUUID(),
      peer,
      new Date().toISOString(),
      active,
    ))
  }

  async sendDisappearingTimer(
    conversation: ConversationId,
    durationSeconds?: number,
  ): Promise<SendSummary> {
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendDisappearingTimer(conversation.groupId, durationSeconds),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
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
      ? canonicalAccountAddress(withHomeServer(
          conversation.address,
          this.capabilities.serverName,
        ))
      : conversation.groupId
    const self = `${this.username}@${this.capabilities.serverName}`
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
  reconcile(): Promise<ReceiveReport> {
    if (this.reconcilePromise) {
      this.reconcileAgain = true
      return this.reconcilePromise
    }
    this.reconcilePromise = this.withLock(async () => {
      const expiry = await this.client.purgeExpiredMessages(String(Date.now()))
      return { expiry, report: await this.client.reconcile() }
    })
      .then(async ({ expiry, report }) => {
        await this.releaseExpiredAttachments(expiry)
        const mlsTyping = await this.withMlsWorkflow(async () => {
          return await this.mls?.reconcile() ?? []
        })
        const directTyping = (report.messages ?? []).flatMap((message): ChatTypingEvent[] => {
          if (message.conversation.kind !== 'direct') return []
          const address = withHomeServer(
            message.conversation.address,
            this.capabilities.serverName,
          )
          return [{
            conversation: { kind: 'direct', address },
            sender: canonicalAccountAddress(address),
            // A real encrypted message clears the sender's prior typing state
            // without adding a second control event.
            active: message.content.typing?.active ?? false,
          }]
        })
        for (const event of [...directTyping, ...mlsTyping]) this.emitTyping(event, true)
        await this.reconcileAttachmentLedger()
        this.notifyPeers()
        return report
      })
      .finally(() => {
        this.reconcilePromise = null
        if (this.reconcileAgain && !this.disposed) {
          this.reconcileAgain = false
          void this.reconcile()
        }
      })
    return this.reconcilePromise
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
  async createGroup(initialMember?: AccountAddress, name?: string): Promise<LocalMlsConversationRecord> {
    const result = await this.withMlsWorkflow(async () => {
      const mls = this.requireMls()
      const self: AccountAddress = {
        username: this.currentUsername(),
        server: this.capabilities.serverName!,
      }
      const authorities = new Set([self.server!])
      if (initialMember) {
        const member = withHomeServer(initialMember, this.capabilities.serverName)
        if (!member.server) throw new Error('group member requires a server')
        authorities.add(member.server)
        initialMember = member
      }
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

  async addGroupMember(conversationId: string, member: AccountAddress): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().addMember(
        conversationId,
        withHomeServer(member, this.capabilities.serverName),
      ),
    )
    this.notifyPeers()
  }

  async removeGroupMember(conversationId: string, member: AccountAddress): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().removeMember(
        conversationId,
        withHomeServer(member, this.capabilities.serverName),
      ),
    )
    this.notifyPeers()
  }

  async setGroupAdministrator(
    conversationId: string,
    member: AccountAddress,
    isAdmin: boolean,
  ): Promise<void> {
    await this.withMlsWorkflow(() =>
      this.requireMls().setAdministrator(
        conversationId,
        withHomeServer(member, this.capabilities.serverName),
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
    member: AccountAddress,
    isOwner: boolean,
  ): Promise<boolean> {
    const finalized = await this.withMlsWorkflow(() =>
      this.requireMls().setOwnerRole(
        conversationId,
        withHomeServer(member, this.capabilities.serverName),
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
      // Mail delivery remains usable; the next open/online transition retries.
    }
  }

  async safetyNumber(peer: string): Promise<SafetyNumberV1> {
    const address = parseAccountAddress(peer)
    if (!address) throw new Error('invalid chat account address')
    return this.withLock(() =>
      this.client.safetyNumber(toCoreAccountAddress(address, this.capabilities.serverName)),
    )
  }

  async verifySafetyNumber(peer: string, scannedPayload: string): Promise<SafetyNumberV1> {
    const address = parseAccountAddress(peer)
    if (!address) throw new Error('invalid chat account address')
    const verified = await this.withLock(() =>
      this.client.verifySafetyNumber(
        toCoreAccountAddress(address, this.capabilities.serverName),
        scannedPayload,
      ),
    )
    this.notifyPeers()
    return verified
  }

  async quarantineInbound(id: string): Promise<void> {
    await this.withLock(() => this.client.quarantineInbound(id))
    this.notifyPeers()
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    if (this.socketRetry) clearTimeout(this.socketRetry)
    if (this.inviteTimer) clearInterval(this.inviteTimer)
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
    return await navigator.locks.request(
      this.lockName,
      { mode: 'exclusive' },
      async () => await operation(),
    )
  }

  private async withAttachmentLedgerLock<T>(operation: () => Promise<T>): Promise<T> {
    return navigator.locks.request(
      `${this.lockName}:attachment-ledger`,
      { mode: 'exclusive' },
      operation,
    )
  }

  private async reconcileAttachmentLedger(): Promise<void> {
    if (!this.attachmentLedger) return
    const [history, contacts] = await Promise.all([this.history(), this.contacts()])
    const accepted = new Set(
      contacts.filter(contact => contact.state === 'accepted').map(contact => contact.peer),
    )
    const self = `${this.username}@${this.capabilities.serverName}`
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
      for (const message of history) {
        const descriptor = message.content.attachment
        const messageId = message.content.messageId
        if (!descriptor || !messageId ||
            this.attachmentLedger!.hasAttachment(messageId, descriptor.attachmentId)) continue
        if (message.conversation.kind === 'direct') {
          const peer = canonicalAccountAddress(message.conversation.address)
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

  private currentUsername(): string {
    return this.username
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
    const address = parseAccountAddress(peer)
    if (!address) throw new Error('invalid chat account address')
    const corePeer = toCoreAccountAddress(address, this.capabilities.serverName)
    const result = await this.withLock(() => action(corePeer))
    this.notifyPeers()
    return result
  }

  private emitUpdate(): void {
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
    void this.initializeMls().then(() => this.reconcile())
    this.reconnect()
  }

  private wentOffline(): void {
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
    if (document.visibilityState === 'visible') void this.initializeMls().then(() => this.reconcile())
  }

  private async connectSocket(): Promise<void> {
    if (this.disposed || this.socket?.readyState === WebSocket.OPEN) return
    if (this.socket?.readyState === WebSocket.CONNECTING) return
    this.setConnection(navigator.onLine === false ? 'offline' : 'connecting')
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
        this.setConnection('connected')
        this.startHeartbeat(socket)
        void this.maintainPrekeys()
        void this.initializeMls().then(() => this.reconcile())
      }
      socket.onmessage = (event: MessageEvent<unknown>) => {
        if (isPong(event.data)) {
          if (this.pongDeadline) clearTimeout(this.pongDeadline)
          this.pongDeadline = null
          return
        }
        void this.reconcile()
      }
      socket.onerror = () => socket.close()
      socket.onclose = () => {
        if (this.socket !== socket) return
        this.socket = null
        this.stopHeartbeat()
        this.setConnection(navigator.onLine === false ? 'offline' : 'connecting')
        this.scheduleSocketRetry()
      }
    } catch {
      this.setConnection(navigator.onLine === false ? 'offline' : 'connecting')
      this.scheduleSocketRetry()
    }
  }

  private scheduleSocketRetry(): void {
    if (this.disposed || this.socketRetry) return
    const delay = Math.min(30_000, 500 * 2 ** this.retryAttempt++)
    this.socketRetry = setTimeout(() => {
      this.socketRetry = null
      void this.reconcile()
      void this.connectSocket()
    }, delay)
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
    const address = (event.conversation as { address?: unknown }).address
    if (address && typeof address === 'object') {
      const candidate = address as { username?: unknown; server?: unknown }
      if (
        typeof candidate.username === 'string'
        && (candidate.server === undefined || typeof candidate.server === 'string')
        && parseAccountAddress(canonicalAccountAddress(candidate as AccountAddress))
      ) {
        return event as ChatTypingEvent
      }
    }
  }
  return null
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
