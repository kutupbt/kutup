import { afterEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import api from '@/api/client'
import { resolveApiBase } from '@/lib/apiBase'
import { ApiChatTransport } from './transport'

afterEach(() => vi.restoreAllMocks())

describe('ApiChatTransport', () => {
  it('lists and revokes authenticated Chat devices', async () => {
    const devices = [{
      deviceId: 2,
      suite: 1,
      name: 'Firefox on Linux',
      createdAt: '2026-08-09T10:00:00Z',
      lastSeenAt: null,
    }]
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { devices } } as never)
    const remove = vi.spyOn(api, 'delete').mockResolvedValue({ data: undefined } as never)
    const transport = new ApiChatTransport()

    await expect(transport.listDevices()).resolves.toEqual(devices)
    expect(get).toHaveBeenCalledWith('/chat/device')
    await expect(transport.revokeDevice(2)).resolves.toBeUndefined()
    expect(remove).toHaveBeenCalledWith('/chat/device/2')
  })

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

    await transport.fetchSyncBundles('alice/name', 7)
    expect(get).toHaveBeenCalledWith('/chat/users/alice%2Fname/keys', {
      params: { syncDeviceId: 7 },
    })

    await expect(transport.sendSyncMessage({ sendId: 'note-1' })).resolves.toEqual({
      kind: 'delivered',
      deduplicated: false,
    })
    expect(post).toHaveBeenCalledWith('/chat/sync/messages', { sendId: 'note-1' })
  })

  it('publishes complete signed account manifests', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { manifest: {} } } as never)
    const transport = new ApiChatTransport()

    await transport.publishManifest({ sequence: 2 })
    expect(post).toHaveBeenCalledWith('/chat/manifest', { sequence: 2 })
  })

  it('uses the authenticated opaque history-transfer relay contract', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { transfers: [] } } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: {} } as never)
    const put = vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    const remove = vi.spyOn(api, 'delete').mockResolvedValue({ data: {} } as never)
    const transport = new ApiChatTransport()
    const id = '11111111-1111-4111-8111-111111111111'

    await transport.createHistoryTransfer({ transferId: id })
    expect(post).toHaveBeenCalledWith('/chat/history-transfers', { transferId: id })
    await transport.listHistoryTransfers(2)
    expect(get).toHaveBeenCalledWith('/chat/history-transfers', { params: { deviceId: 2 } })
    await transport.acceptHistoryTransfer(id, 1, { respondingDeviceId: 1 })
    expect(put).toHaveBeenCalledWith(
      `/chat/history-transfers/${id}/acceptance`,
      { respondingDeviceId: 1 },
      { params: { deviceId: 1 } },
    )
    await transport.uploadHistoryTransferFrame(id, 1, 0, { index: 0 })
    expect(put).toHaveBeenCalledWith(
      `/chat/history-transfers/${id}/frames/0`,
      { index: 0 },
      { params: { deviceId: 1 } },
    )
    await transport.drainHistoryTransferFrames(id, 2, null, 64)
    expect(get).toHaveBeenCalledWith(`/chat/history-transfers/${id}/frames`, {
      params: { deviceId: 2, after: undefined, limit: 64 },
    })
    await transport.completeHistoryTransfer(id, 2, { frameCount: 1 })
    expect(post).toHaveBeenCalledWith(
      `/chat/history-transfers/${id}/completion`,
      { frameCount: 1 },
      { params: { deviceId: 2 } },
    )
    await transport.cancelHistoryTransfer(id, 2)
    expect(remove).toHaveBeenCalledWith(`/chat/history-transfers/${id}`, {
      params: { deviceId: 2 },
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

  it('fetches complete manifest history with lossless sequence bounds', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({
      data: { account: 'alice@remote.example', manifests: [{ sequence: 4 }] },
    } as never)
    const transport = new ApiChatTransport()

    await expect(
      transport.fetchManifestHistory(
        'alice@remote.example',
        '1',
        '18446744073709551615',
        '18446744073709551615',
      ),
    ).resolves.toMatchObject({ manifests: [{ sequence: 4 }] })
    expect(get).toHaveBeenCalledWith(
      '/chat/users/alice%40remote.example/manifest-history',
      {
        params: {
          fromSequence: '1',
          toSequence: '18446744073709551615',
          pageFromSequence: '18446744073709551615',
        },
      },
    )
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

  it('keeps anonymous MLS requests free of cookies and authorization', async () => {
    await resolveApiBase()
    const post = vi.spyOn(axios, 'post').mockResolvedValue({ data: { devices: [] } } as never)
    const transport = new ApiChatTransport()

    await expect(
      transport.fetchAnonymousMlsKeyPackages({ recipient: { username: 'bob' } }),
    ).resolves.toEqual({ devices: [] })
    expect(post).toHaveBeenCalledWith(
      expect.stringMatching(/\/chat\/mls\/anonymous\/key-packages$/),
      { recipient: { username: 'bob' } },
      { withCredentials: false, headers: { Authorization: undefined } },
    )

    await transport.submitAnonymousMlsMessage({ sendId: 'send-1' })
    expect(post).toHaveBeenLastCalledWith(
      expect.stringMatching(/\/chat\/mls\/anonymous\/messages$/),
      { sendId: 'send-1' },
      { withCredentials: false, headers: { Authorization: undefined } },
    )
  })

  it('uses authenticated routes for MLS invitation decisions', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: [] } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({
      data: {
        conversationId: '00000000-0000-0000-0000-000000000001',
        incarnation: 1,
        status: 'active',
        idempotent: false,
      },
    } as never)
    const transport = new ApiChatTransport()
    await expect(transport.listMlsInvitations()).resolves.toEqual([])
    expect(get).toHaveBeenCalledWith('/chat/mls/invitations')
    await expect(transport.listMlsInvitationFeedback()).resolves.toEqual([])
    expect(get).toHaveBeenCalledWith('/chat/mls/invitation-feedback')
    await transport.respondMlsInvitation({
      conversationId: '00000000-0000-0000-0000-000000000001',
      incarnation: 1,
      accept: true,
    })
    expect(post).toHaveBeenCalledWith('/chat/mls/invitations', {
      conversationId: '00000000-0000-0000-0000-000000000001',
      incarnation: 1,
      accept: true,
    })

    await expect(transport.drainMlsMailbox(7, '42', 64)).resolves.toEqual([])
    expect(get).toHaveBeenCalledWith('/chat/mls/messages/7', {
      params: { after: '42', limit: 64 },
    })
    await transport.ackMlsMailbox(7, [
      '00000000-0000-0000-0000-000000000002',
      '00000000-0000-0000-0000-000000000001',
    ])
    expect(post).toHaveBeenCalledWith('/chat/mls/messages/ack', {
      deviceId: 7,
      envelopeIds: [
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000002',
      ],
    })
  })

  it('retrieves MLS ordering history only through the same-origin policy route', async () => {
    const get = vi.spyOn(api, 'get')
    get.mockResolvedValueOnce({ data: { domain: 'authority.example' } })
    const transport = new ApiChatTransport()
    await expect(
      transport.fetchMlsOrderingPolicy('authority.example'),
    ).resolves.toEqual({ domain: 'authority.example' })
    expect(get).toHaveBeenCalledWith(
      '/chat/mls/domains/authority.example/policy',
    )
  })

  it('extracts the authenticated MLS group id from canonical control history', async () => {
    const page = {
      protocolVersion: 1,
      genesis: { mlsGroupId: 'BwcHBwcHBwcHBwcHBwcHBw==' },
      commits: [{ height: 1 }],
      nextHeight: '1',
    }
    const bytes = new TextEncoder().encode(JSON.stringify(page))
    const get = vi.spyOn(api, 'get').mockResolvedValue({
      data: bytes.buffer,
    } as never)
    const transport = new ApiChatTransport()

    const result = await transport.fetchMlsControlHistory(
      '00000000-0000-4000-8000-000000000001',
      1,
      '0',
      64,
    )
    expect(result).toMatchObject({
      entryCount: 1,
      nextHeight: '1',
      genesisGroupId: page.genesis.mlsGroupId,
    })
    expect([...result.bytes]).toEqual([...bytes])
    expect(get).toHaveBeenCalledWith(
      '/chat/mls/conversations/00000000-0000-4000-8000-000000000001/1/control-history',
      {
        params: { afterHeight: '0', limit: 64 },
        responseType: 'arraybuffer',
      },
    )
  })
})
