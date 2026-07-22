import api from '@/api/client'
import { resolveApiBase } from '@/lib/apiBase'
import { ApiChatTransport } from './transport'
import type {
  ChatCapabilities,
  ChatHistoryEntry,
  ContactRecord,
  ConversationId,
  InboundAttention,
  ChatProfile,
  PeerChatProfile,
  ReceiveReport,
  SendSummary,
  TransparencyMonitorStatus,
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

type UpdateListener = () => void

const TRANSPARENCY_MONITOR_INTERVAL_MS = 15 * 60 * 1000

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
  private readonly channel: BroadcastChannel
  private readonly listeners = new Set<UpdateListener>()
  private socket: WebSocket | null = null
  private socketRetry: ReturnType<typeof setTimeout> | null = null
  private transparencyTimer: ReturnType<typeof setInterval> | null = null
  private retryAttempt = 0
  private disposed = false
  private reconcilePromise: Promise<ReceiveReport> | null = null
  private readonly transparencyPromises = new Map<string, Promise<TransparencyMonitorStatus>>()

  private constructor(
    client: WasmChatClientHandle,
    lockName: string,
    channelName: string,
    capabilities: ChatCapabilities,
  ) {
    this.client = client
    this.deviceId = client.deviceId
    this.lockName = lockName
    this.capabilities = capabilities
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
    const transparencyPolicy = {
      scopes: [
        {
          scope: 'local',
          operatorKeyId: capabilities.transparencyOperatorKeyId!,
          operatorPublicKey: capabilities.transparencyOperatorPublicKey!,
          witnesses: capabilities.transparencyWitnesses ?? [],
          witnessQuorum: capabilities.transparencyWitnessQuorum ?? 0,
        },
      ],
    }
    const client = await navigator.locks.request(lockName, { mode: 'exclusive' }, () =>
      wasm.WasmChatClient.open(
        databaseName,
        options.username,
        capabilities.serverName!,
        capabilities.sealedSender,
        options.masterKey,
        transport,
        transparencyPolicy,
      ),
    )

    const service = new ChatService(client, lockName, channelName, capabilities)
    try {
      await service.reconcile()
      await service.monitorTransparency()
      service.startTransparencyMonitor()
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
    if (conversation.kind !== 'direct') {
      throw new Error('group conversations are not enabled by this server')
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
      .then((report) => {
        this.notifyPeers()
        return report
      })
      .finally(() => {
        this.reconcilePromise = null
      })
    return this.reconcilePromise
  }

  async maintainPrekeys(): Promise<void> {
    try {
      await this.withLock(() => this.client.maintainPrekeys())
    } catch {
      // Mail delivery remains usable; the next open/online transition retries.
    }
  }

  monitorTransparency(scope = 'local'): Promise<TransparencyMonitorStatus> {
    const existing = this.transparencyPromises.get(scope)
    if (existing) return existing
    const pending = this.withLock(() => this.client.monitorTransparency(scope))
      .then((status) => {
        this.notifyPeers()
        return status
      })
      .finally(() => {
        this.transparencyPromises.delete(scope)
      })
    this.transparencyPromises.set(scope, pending)
    return pending
  }

  transparencyStatus(scope = 'local'): Promise<TransparencyMonitorStatus | undefined> {
    return this.withLock(() => this.client.transparencyMonitorStatus(scope))
  }

  async verifyAuthority(peer: string): Promise<void> {
    const address = parseAccountAddress(peer)
    if (!address) throw new Error('invalid chat account address')
    await this.withLock(() =>
      this.client.verifyAuthority(toCoreAccountAddress(address, this.capabilities.serverName)),
    )
    this.notifyPeers()
  }

  async quarantineInbound(id: string): Promise<void> {
    await this.withLock(() => this.client.quarantineInbound(id))
    this.notifyPeers()
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    if (this.socketRetry) clearTimeout(this.socketRetry)
    if (this.transparencyTimer) clearInterval(this.transparencyTimer)
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
    void this.monitorTransparency()
  }

  private readonly handleVisibilityChange = (): void => {
    if (document.visibilityState === 'visible') void this.monitorTransparency()
  }

  private startTransparencyMonitor(): void {
    if (this.transparencyTimer) return
    this.transparencyTimer = setInterval(() => {
      if (document.visibilityState === 'visible') void this.monitorTransparency()
    }, TRANSPARENCY_MONITOR_INTERVAL_MS)
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
        void this.monitorTransparency()
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
