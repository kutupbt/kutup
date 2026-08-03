import api from '@/api/client'
import { resolveApiBase } from '@/lib/apiBase'
import { ApiChatTransport } from './transport'
import type {
  AccountAddress,
  ChatCapabilities,
  ChatHistoryEntry,
  ContactRecord,
  ConversationId,
  InboundAttention,
  ChatProfile,
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

type UpdateListener = () => void

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
    transport: ApiChatTransport,
    private readonly username: string,
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
    this.channel.onmessage = () => this.emitUpdate()
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

    const service = new ChatService(
      client,
      lockName,
      channelName,
      capabilities,
      transport,
      options.username,
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

  async history(): Promise<ChatHistoryEntry[]> {
    const history = await this.withLock(() => this.client.history())
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

  async send(conversation: ConversationId, text: string): Promise<SendSummary> {
    if (conversation.kind === 'group') {
      const summary = await this.withMlsWorkflow(() =>
        this.requireMls().sendText(conversation.groupId, text),
      )
      this.notifyPeers()
      return { ...summary, safetyNumberChanges: [] }
    }
    const peer = toCoreAccountAddress(conversation.address, this.capabilities.serverName)
    const sendId = crypto.randomUUID()
    const summary = await this.withLock(() =>
      this.client.sendText(sendId, peer, new Date().toISOString(), text),
    )
    this.notifyPeers()
    return summary
  }

  reconcile(): Promise<ReceiveReport> {
    if (this.reconcilePromise) return this.reconcilePromise
    this.reconcilePromise = this.withLock(() => this.client.reconcile())
      .then(async (report) => {
        await this.withMlsWorkflow(async () => {
          await this.mls?.reconcile()
        })
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
    this.client.free()
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    return await navigator.locks.request(
      this.lockName,
      { mode: 'exclusive' },
      async () => await operation(),
    )
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
    if (!this.mls) return
    await this.withMlsWorkflow(async () => {
      const manifest = await this.withLock(() => this.client.syncManifest())
      const sequence = requireManifestSequence(manifest)
      await this.mls?.maintainKeyPackages(sequence)
      await this.mls?.reconcileLinkedDevices(requireMlsManifestDeviceIds(manifest))
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
