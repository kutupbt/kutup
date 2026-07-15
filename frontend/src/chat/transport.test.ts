import { afterEach, describe, expect, it, vi } from 'vitest'
import api from '@/api/client'
import { ApiChatTransport } from './transport'

afterEach(() => vi.restoreAllMocks())

describe('ApiChatTransport', () => {
  it('maps a successful send response to the engine outcome', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { stored: 2 } } as never)
    const transport = new ApiChatTransport()

    await expect(transport.sendMessage('bob/name', { envelopes: [] })).resolves.toEqual({
      kind: 'delivered',
      deduplicated: false,
    })
    expect(post).toHaveBeenCalledWith('/chat/users/bob%2Fname/messages', { envelopes: [] })
  })

  it('returns the typed mismatch body on 409', async () => {
    vi.spyOn(api, 'post').mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 409,
        data: { missingDevices: [2], staleDevices: [], extraDevices: [] },
      },
    })
    const transport = new ApiChatTransport()

    await expect(transport.sendMessage('bob', {})).resolves.toEqual({
      kind: 'mismatch',
      mismatch: { missingDevices: [2], staleDevices: [], extraDevices: [] },
    })
  })

  it('treats only a manifest 404 as an absent manifest', async () => {
    const get = vi.spyOn(api, 'get').mockRejectedValue({
      isAxiosError: true,
      response: { status: 404 },
    })
    const transport = new ApiChatTransport()

    await expect(transport.fetchManifest('bob')).resolves.toBeNull()

    get.mockRejectedValueOnce({ isAxiosError: true, response: { status: 503 } })
    await expect(transport.fetchManifest('bob')).rejects.toMatchObject({
      response: { status: 503 },
    })
  })

  it('serializes the lossless cursor and device id as query parameters', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { envelopes: [] } } as never)
    const transport = new ApiChatTransport()

    await transport.drainMailbox(7, '18446744073709551615', 500)
    expect(get).toHaveBeenCalledWith('/chat/messages', {
      params: { deviceId: 7, after: '18446744073709551615', limit: 500 },
    })
  })
})
