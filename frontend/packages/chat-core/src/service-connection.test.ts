import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ChatService, type ChatConnectionStatus } from './service'

vi.mock('@kutup/session/client', () => ({
  default: {
    post: vi.fn().mockResolvedValue({ data: { ticket: 'ticket' } }),
  },
}))

vi.mock('@kutup/session/apiBase', () => ({
  resolveApiBase: vi.fn().mockResolvedValue('http://localhost/api'),
}))

class FakeSocket {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 3
  static instances: FakeSocket[] = []
  readyState = FakeSocket.CONNECTING
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: (() => void) | null = null
  onclose: (() => void) | null = null

  constructor(readonly url: URL) {
    FakeSocket.instances.push(this)
  }

  send(data: string) {
    this.sent.push(data)
  }

  close() {
    if (this.readyState === FakeSocket.CLOSED) return
    this.readyState = FakeSocket.CLOSED
    this.onclose?.()
  }

  open() {
    this.readyState = FakeSocket.OPEN
    this.onopen?.()
  }
}

function socketService() {
  const service = Object.create(ChatService.prototype) as ChatService
  Object.assign(service, {
    deviceId: 1,
    socket: null,
    socketRetry: null,
    retryAttempt: 0,
    heartbeat: null,
    pongDeadline: null,
    pollTimer: null,
    connection: 'connecting',
    connectionListeners: new Set(),
    disposed: false,
    maintainPrekeys: vi.fn().mockResolvedValue(undefined),
    initializeMls: vi.fn().mockResolvedValue(undefined),
    reconcile: vi.fn().mockResolvedValue({ received: 0 }),
    backup: null,
  })
  const statuses: ChatConnectionStatus[] = []
  service.subscribeConnection((status) => statuses.push(status))
  return { service, statuses }
}

async function connect(service: ChatService) {
  await (service as unknown as { connectSocket(): Promise<void> }).connectSocket()
  return FakeSocket.instances.at(-1)!
}

describe('ChatService connection status', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    FakeSocket.instances = []
    vi.stubGlobal('WebSocket', FakeSocket)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('reports connected once the socket opens and reconnecting after it drops', async () => {
    const { service, statuses } = socketService()
    const socket = await connect(service)
    socket.open()
    expect(service.connectionStatus()).toBe('connected')

    socket.close()
    expect(service.connectionStatus()).toBe('connecting')
    await vi.advanceTimersByTimeAsync(500)
    FakeSocket.instances.at(-1)!.open()
    expect(statuses).toEqual(['connected', 'connecting', 'connected'])
  })

  it('says the device was removed, and stops retrying, when the server does not know it', async () => {
    const { default: api } = await import('@kutup/session/client')
    const { AxiosError, AxiosHeaders } = await import('axios')
    const response = { status: 404, data: { error: 'no such chat device' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' }
    vi.mocked(api.post).mockRejectedValueOnce(new AxiosError('failed', '404', undefined, undefined, response as never))
    const { service, statuses } = socketService()
    await (service as unknown as { connectSocket(): Promise<void> }).connectSocket()
    expect(service.connectionStatus()).toBe('deviceRemoved')
    // No reconnect is scheduled: waiting does not bring a removed device back.
    await vi.advanceTimersByTimeAsync(60_000)
    expect(FakeSocket.instances).toHaveLength(0)
    expect(statuses).toEqual(['deviceRemoved'])
  })

  it('keeps retrying when the server is merely out of reach', async () => {
    const { default: api } = await import('@kutup/session/client')
    vi.mocked(api.post).mockRejectedValueOnce(new Error('Network Error'))
    const { service } = socketService()
    await (service as unknown as { connectSocket(): Promise<void> }).connectSocket()
    expect(service.connectionStatus()).toBe('connecting')
    await vi.advanceTimersByTimeAsync(500)
    expect(FakeSocket.instances).toHaveLength(1)
  })

  it('treats a socket that stops answering pings as dropped', async () => {
    const { service } = socketService()
    const socket = await connect(service)
    socket.open()

    await vi.advanceTimersByTimeAsync(25_000)
    expect(socket.sent).toEqual([JSON.stringify({ type: 'ping' })])
    socket.onmessage?.({ data: JSON.stringify({ type: 'pong' }) })
    await vi.advanceTimersByTimeAsync(10_000)
    expect(service.connectionStatus()).toBe('connected')

    await vi.advanceTimersByTimeAsync(15_000 + 10_000)
    expect(socket.readyState).toBe(FakeSocket.CLOSED)
    expect(service.connectionStatus()).toBe('connecting')
  })

  it('does not reconcile on a pong but does on any other frame', async () => {
    const { service } = socketService()
    const socket = await connect(service)
    socket.open()
    const reconcile = (service as unknown as { reconcile: ReturnType<typeof vi.fn> }).reconcile
    reconcile.mockClear()

    socket.onmessage?.({ data: JSON.stringify({ type: 'pong' }) })
    expect(reconcile).not.toHaveBeenCalled()
    socket.onmessage?.({ data: JSON.stringify({ type: 'drainMailbox' }) })
    expect(reconcile).toHaveBeenCalledTimes(1)
  })

  it('drops the device lists it holds when the server says the account\'s devices changed', async () => {
    const { service } = socketService()
    const forgetKnownDevices = vi.fn()
    const updates = vi.fn()
    Object.assign(service, {
      client: { forgetKnownDevices },
      listeners: new Set([updates]),
      withLock: (work: () => Promise<unknown>) => work(),
    })
    const socket = await connect(service)
    socket.open()
    await vi.advanceTimersByTimeAsync(0)
    const reconcile = (service as unknown as { reconcile: ReturnType<typeof vi.fn> }).reconcile
    reconcile.mockClear()

    socket.onmessage?.({ data: JSON.stringify({ type: 'drainMailbox' }) })
    expect(forgetKnownDevices).not.toHaveBeenCalled()
    socket.onmessage?.({ data: JSON.stringify({ type: 'devicesChanged' }) })
    await vi.advanceTimersByTimeAsync(0)
    expect(forgetKnownDevices).toHaveBeenCalledTimes(1)
    expect(updates).toHaveBeenCalledTimes(1)
    // Like any other frame, it also reads the mailbox.
    expect(reconcile).toHaveBeenCalledTimes(2)
  })

  it('reads the mailbox on a timer while the socket cannot be opened, and stops when it can', async () => {
    const { service, statuses } = socketService()
    const reconcile = (service as unknown as { reconcile: ReturnType<typeof vi.fn> }).reconcile
    // A gateway that refuses the upgrade: every socket closes before it opens.
    ;(await connect(service)).close()
    await vi.advanceTimersByTimeAsync(500)
    expect(service.connectionStatus()).toBe('connecting')
    FakeSocket.instances.at(-1)!.close()
    await vi.advanceTimersByTimeAsync(0)
    // The server answered an ordinary request: that is what Chat now runs on.
    expect(service.connectionStatus()).toBe('polling')

    reconcile.mockClear()
    await vi.advanceTimersByTimeAsync(15_000)
    expect(reconcile.mock.calls.length).toBeGreaterThanOrEqual(3)
    // Further refused sockets do not flip the notice back and forth.
    expect(statuses).toEqual(['polling'])

    // The network lets the socket through after all: it takes over.
    const socket = FakeSocket.instances.at(-1)!
    socket.open()
    expect(service.connectionStatus()).toBe('connected')
    await vi.advanceTimersByTimeAsync(0)
    reconcile.mockClear()
    await vi.advanceTimersByTimeAsync(20_000)
    expect(reconcile).not.toHaveBeenCalled()
  })

  it('says reconnecting, not polling, when the server does not answer at all', async () => {
    const { service } = socketService()
    const reconcile = (service as unknown as { reconcile: ReturnType<typeof vi.fn> }).reconcile
    reconcile.mockRejectedValue(new Error('Network Error'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    ;(await connect(service)).close()
    await vi.advanceTimersByTimeAsync(500)
    FakeSocket.instances.at(-1)!.close()
    await vi.advanceTimersByTimeAsync(6_000)
    expect(service.connectionStatus()).toBe('connecting')
    warn.mockRestore()
  })

  it('goes offline with the browser and reconnects at once when it is back', async () => {
    const { service } = socketService()
    const socket = await connect(service)
    socket.open()
    const handlers = service as unknown as { wentOffline(): void; wentOnline(): void }

    vi.stubGlobal('navigator', { ...navigator, onLine: false })
    handlers.wentOffline()
    expect(service.connectionStatus()).toBe('offline')
    expect(socket.readyState).toBe(FakeSocket.CLOSED)

    vi.stubGlobal('navigator', { ...navigator, onLine: true })
    handlers.wentOnline()
    await vi.advanceTimersByTimeAsync(0)
    expect(FakeSocket.instances).toHaveLength(2)
    FakeSocket.instances[1].open()
    expect(service.connectionStatus()).toBe('connected')
  })
})
