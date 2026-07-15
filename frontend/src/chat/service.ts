import api from '@/api/client'
import { resolveApiBase } from '@/lib/apiBase'
import { ApiChatTransport } from './transport'
import type {
  ChatCapabilities,
  ChatHistoryEntry,
  InboundAttention,
  ReceiveReport,
  SendSummary,
  WasmChatClientHandle,
} from './types'
import { loadChatWasm } from './wasm'
import { isSupportedChat } from './capabilities'

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
  private readonly channel: BroadcastChannel
  private readonly listeners = new Set<UpdateListener>()
  private socket: WebSocket | null = null
  private socketRetry: ReturnType<typeof setTimeout> | null = null
  private retryAttempt = 0
  private disposed = false
  private reconcilePromise: Promise<ReceiveReport> | null = null

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
        options.masterKey,
        transport,
      ),
    )

    const service = new ChatService(client, lockName, channelName, capabilities)
    try {
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

  history(): Promise<ChatHistoryEntry[]> {
    return this.withLock(() => this.client.history())
  }

  inboundAttention(): Promise<InboundAttention[]> {
    return this.withLock(() => this.client.inboundAttention())
  }

  async send(peer: string, text: string): Promise<SendSummary> {
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

  async verifyAuthority(peer: string): Promise<void> {
    await this.withLock(() => this.client.verifyAuthority(peer))
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
    this.socket?.close()
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

  private emitUpdate(): void {
    for (const listener of this.listeners) listener()
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
