// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import axios from 'axios'

vi.mock('./apiBase', () => ({ resolveApiBase: () => Promise.resolve('https://api.test') }))

const { default: api } = await import('./client')

/** What the adapter (the network) is handed as the body. */
async function sentBody(send: (body: Uint8Array) => Promise<unknown>): Promise<ArrayBuffer> {
  let sent: unknown
  const adapter = vi.fn((config: { data?: unknown }) => {
    sent = config.data
    return Promise.resolve({ data: null, status: 200, statusText: 'OK', headers: {}, config })
  })
  api.defaults.adapter = adapter as never
  axios.defaults.adapter = adapter as never
  // A view into a larger buffer, as WASM hands back a window on its memory.
  const memory = new Uint8Array(4096).fill(7)
  memory.set([1, 2, 3], 100)
  await send(memory.subarray(100, 103))
  expect(adapter).toHaveBeenCalled()
  return sent as ArrayBuffer
}

describe('a typed-array body goes as exactly its bytes', () => {
  it('on the shared client', async () => {
    const body = await sentBody((view) => api.post('/x', view))
    expect(body.byteLength).toBe(3)
    expect([...new Uint8Array(body)]).toEqual([1, 2, 3])
  })

  it('on the default instance (anonymous and raw calls)', async () => {
    const body = await sentBody((view) => axios.put('https://api.test/x', view))
    expect(body.byteLength).toBe(3)
    expect([...new Uint8Array(body)]).toEqual([1, 2, 3])
  })
})
