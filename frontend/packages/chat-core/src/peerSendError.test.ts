import { AxiosError, AxiosHeaders } from 'axios'
import { describe, expect, it, vi } from 'vitest'

const post = vi.fn()
vi.mock('axios', async (importOriginal) => {
  const actual = await importOriginal<typeof import('axios')>()
  return { ...actual, default: { ...actual.default, post: (...a: unknown[]) => post(...a) } }
})
vi.mock('@kutup/session/client', () => ({ default: { post: (...a: unknown[]) => post(...a) } }))
vi.mock('@kutup/session/apiBase', () => ({ apiBase: () => '/api' }))

import { ApiChatTransport, PEER_UNSUPPORTED } from './transport'

function answer(status: number, data: unknown) {
  return new AxiosError('x', 'ERR', undefined, undefined, {
    status, statusText: '', data, headers: {}, config: { headers: new AxiosHeaders() },
  })
}

describe('federated send answers', () => {
  it('a final refusal leaves the queue; a server without chat.v2 says so', async () => {
    const transport = new ApiChatTransport()
    post.mockRejectedValueOnce(answer(502, { error: 'refused', code: 'peerRefused' }))
    await expect(transport.sendSealedMessage('aci:00000000-0000-4000-8000-81b637d8fcd2@b.example', {})).resolves.toEqual({ kind: 'refused' })

    post.mockRejectedValueOnce(answer(503, { error: 'waits', code: PEER_UNSUPPORTED }))
    await expect(transport.sendSealedMessage('aci:00000000-0000-4000-8000-81b637d8fcd2@b.example', {})).rejects.toThrow(PEER_UNSUPPORTED)

    post.mockRejectedValueOnce(answer(503, { error: 'waits', code: PEER_UNSUPPORTED }))
    await expect(transport.sendMessage('aci:00000000-0000-4000-8000-81b637d8fcd2@b.example', {})).rejects.toThrow(PEER_UNSUPPORTED)

    // A plain 503 stays what it was.
    post.mockRejectedValueOnce(answer(503, { error: 'busy' }))
    await expect(transport.sendMessage('aci:00000000-0000-4000-8000-81b637d8fcd2@b.example', {})).rejects.toBeInstanceOf(AxiosError)
  })
})
