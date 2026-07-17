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

  it('uses the authenticated own-device endpoints for encrypted transcripts', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { devices: [] } } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { stored: 1 } } as never)
    const transport = new ApiChatTransport()

    await transport.fetchSyncBundles('alice/name', 7, '18446744073709551615')
    expect(get).toHaveBeenCalledWith('/chat/users/alice%2Fname/keys', {
      params: { syncDeviceId: 7, transparencyTreeSize: '18446744073709551615' },
    })

    await expect(transport.sendSyncMessage({ sendId: 'note-1' })).resolves.toEqual({
      kind: 'delivered',
      deduplicated: false,
    })
    expect(post).toHaveBeenCalledWith('/chat/sync/messages', { sendId: 'note-1' })
  })

  it('sends transparency checkpoints losslessly on manifest publication', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { manifest: {} } } as never)
    const transport = new ApiChatTransport()

    await transport.publishManifest({ version: 2 }, '18446744073709551615')
    expect(post).toHaveBeenCalledWith(
      '/chat/manifest',
      { version: 2 },
      { params: { transparencyTreeSize: '18446744073709551615' } },
    )
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

  it('keeps profile capabilities out of URLs and treats a missing profile as absent', async () => {
    const get = vi.spyOn(api, 'get')
      .mockResolvedValueOnce({ data: { version: 'v1' } } as never)
      .mockRejectedValueOnce({ isAxiosError: true, response: { status: 404 } })
    const put = vi.spyOn(api, 'put').mockResolvedValue({ data: { revision: 2 } } as never)
    const transport = new ApiChatTransport()

    await expect(transport.fetchProfile('alice/name', 'version/value', 'secret-key'))
      .resolves.toEqual({ version: 'v1' })
    expect(get).toHaveBeenNthCalledWith(
      1,
      '/chat/users/alice%2Fname/profile/version%2Fvalue',
      { headers: { 'X-Kutup-Profile-Access-Key': 'secret-key' } },
    )

    await expect(transport.fetchOwnProfile()).resolves.toBeNull()
    expect(get).toHaveBeenNthCalledWith(2, '/chat/profile')

    await expect(transport.publishProfile({ revision: 2 })).resolves.toEqual({ revision: 2 })
    expect(put).toHaveBeenCalledWith('/chat/profile', { revision: 2 })
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
