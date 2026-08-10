import api from '@/api/client'
import { resolveApiBase } from '@/lib/apiBase'
import { ApiChatTransport } from './transport'
import type {
  AccountAddress,
  ChatCapabilities,
  ChatAttachmentDescriptorV1,
  ChatDevice,
  ChatHistoryEntry,
  ChatExpiryReport,
  ChatHistoryTransferDownloadResult,
  ChatHistoryTransferList,
  ChatHistoryTransferRequest,
  ContactRecord,
  ConversationId,
  InboundAttention,
  ChatProfile,
  ChatTypingEvent,
  PeerChatProfile,
  ReceiveReport,
  SendSummary,
  LocalMlsConversationRecord,
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
import { deliverChatMediaV1 } from './media'
import { ChatAttachmentLedger } from './attachment-ledger'

type UpdateListener = () => void
type TypingListener = (event: ChatTypingEvent) => void

function wasmRecord<T>(value: unknown): T {
  return (value instanceof Map ? Object.fromEntries(value) : value) as T
}

export type ChatServiceErrorCode = 'browserUnsupported' | 'serverUnsupported'

export class ChatServiceError extends Error {
  constructor(readonly code: ChatServiceErrorCode) {
    super(code)
    this.name = 'ChatServiceError'
  }
}

export interface ChatServiceOptions {
  userId: string
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
  private socket: WebSocket | null = null
  private socketRetry: ReturnType<typeof setTimeout> | null = null
  private retryAttempt = 0
  private disposed = false
  private reconcilePromise: Promise<ReceiveReport> | null = null
  private readonly mls: MlsConversationService | null

  private constructor(
    client: WasmChatClientHandle,
    lockName: string,
    channelName: string,
    capabilities: ChatCapabilities,
    private readonly transport: ApiChatTransport,
    private readonly username: string,
    private readonly attachmentLedger: ChatAttachmentLedger | null,
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
    this.channel = new BroadcastChannel(channelName)
    this.channel.onmessage = (message: MessageEvent<unknown>) => {
      const event = parseTypingBroadcast(message.data)
      if (event) this.emitTyping(event, false)
      else this.emitUpdate()
    }
    window.addEventListener('online', this.handleOnline)
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

    const scope = await accountScope(options.userId)
    const lockName = `kutup-chat-engine:${scope}`
    const channelName = `kutup-chat-updates:${scope}`
    const databaseName = `kutup-chat-v2:${scope}`
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
    )
    try {
      await service.initializeMls()
      await service.reconcile()
      void service.maintainPrekeys()
      void service.connectSocket()
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

  subscribeTyping(listener: TypingListener): () => void {
    this.typingListeners.add(listener)
    return () => this.typingListeners.delete(listener)
  }

  async history(): Promise<ChatHistoryEntry[]> {
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

  historyTransfers(): Promise<ChatHistoryTransferList> {
    return this.withLock(() => this.client.listHistoryTransfers())
  }

  async requestHistoryTransfer(): Promise<ChatHistoryTransferRequest> {
    const request = await this.withLock(() => this.client.requestHistoryTransfer())
    this.notifyPeers()
    return request
  }

  async approveHistoryTransfer(
    request: ChatHistoryTransferRequest,
  ): Promise<{ acceptance: unknown; frameCount: number }> {
    const result = wasmRecord<{ acceptance: unknown; frameCount: number }>(
      await this.withLock(() => this.client.approveHistoryTransfer(
        request,
        100_000,
        String(256 * 1024 * 1024),
      )),
    )
    this.notifyPeers()
    return result
  }

  async downloadHistoryTransfer(
    transferId: string,
  ): Promise<ChatHistoryTransferDownloadResult> {
    const result = wasmRecord<ChatHistoryTransferDownloadResult>(
      await this.withLock(() => this.client.downloadHistoryTransfer(transferId)),
    )
    if (result.ready) this.notifyPeers()
    return result
  }

  async revokeDevice(deviceId: number): Promise<ChatDevice[]> {
    if (deviceId === this.deviceId) {
      throw new Error('the current Chat device cannot revoke itself')
    }
    await this.withMlsWorkflow(async () => {
      await this.transport.revokeDevice(deviceId)
      const manifest = await this.withLock(() => this.client.syncManifest())
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
  ): Promise<ChatProfile> {
    const profile = await this.withLock(() =>
      this.client.setProfile(displayName, avatar, avatarContentType),
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
  ): Promise<SendSummary> {
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendText(
          conversation.groupId,
          text,
          replyTo,
          expiresAfterSeconds,
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
      ),
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

  reconcile(): Promise<ReceiveReport> {
    if (this.reconcilePromise) return this.reconcilePromise
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

  async createGroup(initialMember?: AccountAddress): Promise<LocalMlsConversationRecord> {
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
      const created = await mls.createGroup(self, [...authorities].sort())
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
    this.socket?.close()
    window.removeEventListener('online', this.handleOnline)
    document.removeEventListener('visibilitychange', this.handleVisibilityChange)
    this.channel.close()
    this.listeners.clear()
    this.typingListeners.clear()
    this.attachmentLedger?.dispose()
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
    if (!this.attachmentLedger || report.expiredAttachmentIds.length === 0) return
    const expiredIds = new Set(report.expiredAttachmentIds)
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

  private readonly handleOnline = (): void => {
    void this.initializeMls().then(() => this.reconcile())
  }

  private readonly handleVisibilityChange = (): void => {
    if (document.visibilityState === 'visible') void this.initializeMls().then(() => this.reconcile())
  }

  private async connectSocket(): Promise<void> {
    if (this.disposed || this.socket?.readyState === WebSocket.OPEN) return
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
        void this.maintainPrekeys()
        void this.initializeMls().then(() => this.reconcile())
      }
      socket.onmessage = () => {
        void this.reconcile()
      }
      socket.onerror = () => socket.close()
      socket.onclose = () => {
        if (this.socket === socket) this.socket = null
        this.scheduleSocketRetry()
      }
    } catch {
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

async function accountScope(userId: string): Promise<string> {
  const apiBase = await resolveApiBase()
  const canonicalServer = new URL(apiBase, window.location.href).href
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${canonicalServer}\0${userId}`),
  )
  return Array.from(new Uint8Array(digest).slice(0, 16), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
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
  const ids = value.devices.map((entry) => {
    if (
      typeof entry !== 'object'
      || entry === null
      || !('deviceId' in entry)
      || typeof entry.deviceId !== 'number'
      || !Number.isSafeInteger(entry.deviceId)
      || entry.deviceId < 1
      || entry.deviceId > 127
      || !('mls' in entry)
      || typeof entry.mls !== 'object'
      || entry.mls === null
    ) {
      throw new Error('signed device manifest contains a device without MLS keys')
    }
    return entry.deviceId
  }).sort((left, right) => left - right)
  if (new Set(ids).size !== ids.length) {
    throw new Error('signed device manifest repeats an MLS device id')
  }
  return ids
}
