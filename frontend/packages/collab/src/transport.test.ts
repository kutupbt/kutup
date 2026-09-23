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
