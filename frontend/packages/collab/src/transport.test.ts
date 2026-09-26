import { describe, it, expect, vi } from 'vitest'
import { CollabTransport } from './transport'

describe('CollabTransport', () => {
  it('queues frames sent before connect', () => {
    const t = new CollabTransport({
      url: 'ws://localhost',
      wsFactory: () => ({
        binaryType: '',
        addEventListener: () => {},
        removeEventListener: () => {},
        send: () => {},
        close: () => {},
        readyState: 0,  // CONNECTING
      } as unknown as WebSocket),
      onFrame: () => {},
      onHello: () => {},
      onError: () => {},
    })
    t.send(new Uint8Array([1, 2, 3]))
    expect(t.pendingCount()).toBe(1)
  })
})

/** Just enough WebSocket for connect/close cycles. */
class FakeWs {
  binaryType = ''
  readyState = 0
  private listeners = new Map<string, (() => void)[]>()
  addEventListener(type: string, fn: () => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn])
  }
  removeEventListener() {}
  send() {}
  close() {}
  emit(type: string) {
    for (const fn of this.listeners.get(type) ?? []) fn()
  }
}

describe('CollabTransport — URL factory', () => {
  it('asks for a fresh URL on every connect', async () => {
    const urls: string[] = []
    let n = 0
    const sockets: FakeWs[] = []
    new CollabTransport({
      url: async () => `ws://x/${++n}`,
      wsFactory: (u) => {
        urls.push(u)
        const ws = new FakeWs()
        sockets.push(ws)
        return ws as unknown as WebSocket
      },
      onFrame: () => {},
      onHello: () => {},
      onError: () => {},
    })
    await vi.waitFor(() => expect(urls).toEqual(['ws://x/1']))
    sockets[0]!.emit('close')
    await vi.waitFor(() => expect(urls).toEqual(['ws://x/1', 'ws://x/2']), { timeout: 5000 })
  })
})

/** A socket that can deliver messages. */
class MessageWs {
  binaryType = ''
  readyState = 1
  sent: unknown[] = []
  private listeners = new Map<string, ((ev: unknown) => void)[]>()
  addEventListener(type: string, fn: (ev: unknown) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn])
  }
  removeEventListener() {}
  send(data: unknown) {
    this.sent.push(data)
  }
  close() {}
  emit(type: string, ev?: unknown) {
    for (const fn of this.listeners.get(type) ?? []) fn(ev)
  }
}

describe('CollabTransport — log positions', () => {
  it('announces a position only after every frame before it is applied', async () => {
    const order: string[] = []
    let ws: MessageWs | null = null
    new CollabTransport({
      url: 'ws://x',
      wsFactory: () => (ws = new MessageWs()) as unknown as WebSocket,
      lastSeenSeq: () => 7,
      onFrame: async (bytes) => {
        // A slow decrypt must not let the position overtake the frame.
        await new Promise((resolve) => setTimeout(resolve, 20))
        order.push(`frame ${bytes[0]}`)
      },
      onHello: () => order.push('hello'),
      onPosition: (message) => {
        order.push(message.type === 'stored' ? `stored ${message.seq}` : `replayed ${message.throughSeq} from ${message.since}`)
      },
      onError: () => {},
    })
    await vi.waitFor(() => expect(ws).not.toBeNull())
    const socket = ws as unknown as MessageWs
    socket.emit('open')
    expect(socket.sent[0]).toBe(JSON.stringify({ type: 'resume', lastSeenSeq: 7 }))
    socket.emit('message', { data: JSON.stringify({ type: 'hello' }) })
    socket.emit('message', { data: new Uint8Array([8]).buffer })
    socket.emit('message', { data: JSON.stringify({ type: 'replayed', throughSeq: 8, floor: 0 }) })
    socket.emit('message', { data: new Uint8Array([9]).buffer })
    socket.emit('message', { data: JSON.stringify({ type: 'stored', seq: 9 }) })
    await vi.waitFor(() => expect(order).toHaveLength(5))
    expect(order).toEqual(['hello', 'frame 8', 'replayed 8 from 7', 'frame 9', 'stored 9'])
  })
})
