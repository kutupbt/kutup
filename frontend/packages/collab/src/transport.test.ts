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
