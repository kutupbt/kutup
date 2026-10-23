import { afterEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import api from '@kutup/session/client'
import { resolveApiBase } from '@kutup/session/apiBase'
import { ApiChatTransport } from './transport'

afterEach(() => vi.restoreAllMocks())

const ALICE = 'aci:00000000-0000-4000-8000-2bd806c97f0e@remote.example'
const BOB = 'aci:00000000-0000-4000-8000-81b637d8fcd2@b.test'

describe('ApiChatTransport', () => {
  it('lists, renames, and revokes authenticated Chat devices', async () => {
    const devices = [{
      deviceId: 2,
      suite: 1,
      name: 'Firefox on Linux',
      createdAt: '2026-08-09T10:00:00Z',
      lastSeenAt: null,
    }]
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { devices } } as never)
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: undefined } as never)
    const remove = vi.spyOn(api, 'delete').mockResolvedValue({ data: undefined } as never)
    const transport = new ApiChatTransport()

    await expect(transport.listDevices()).resolves.toEqual(devices)
    expect(get).toHaveBeenCalledWith('/chat/device')
    await expect(transport.renameDevice(2, 'Work laptop')).resolves.toBeUndefined()
    expect(patch).toHaveBeenCalledWith('/chat/device/2', { name: 'Work laptop' })
    await expect(transport.revokeDevice(2)).resolves.toBeUndefined()
    expect(remove).toHaveBeenCalledWith('/chat/device/2')
  })

  it('links, relays and distributes with their refusals said as outcomes', async () => {
    const transport = new ApiChatTransport()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { token: 't', expiresAt: 'x' } } as never)
    await expect(transport.createLinkToken()).resolves.toEqual({ token: 't', expiresAt: 'x' })
    expect(post).toHaveBeenCalledWith('/chat/link-tokens')

    const put = vi.spyOn(api, 'put').mockResolvedValueOnce({ data: undefined } as never)
    await expect(transport.relayProvisioning('a/b', { envelope: {} })).resolves.toBe(true)
    expect(put).toHaveBeenCalledWith('/chat/provisioning/a%2Fb', { envelope: {} })
    const gone = new axios.AxiosError('gone', '404', undefined, undefined, { status: 404 } as never)
    put.mockRejectedValueOnce(gone)
    await expect(transport.relayProvisioning('a', {})).resolves.toBe(false)

    put.mockResolvedValueOnce({ data: undefined } as never)
    await expect(transport.distributeIdentity({})).resolves.toEqual({ kind: 'accepted' })
    for (const status of [409, 410]) {
      const mismatch = { missingDevices: [3], staleDevices: [], extraDevices: [] }
      put.mockRejectedValueOnce(
        new axios.AxiosError('mismatch', String(status), undefined, undefined, { status, data: mismatch } as never),
      )
      await expect(transport.distributeIdentity({})).resolves.toEqual({ kind: 'mismatch', mismatch })
    }
    const refused = new axios.AxiosError('bad', '400', undefined, undefined, { status: 400 } as never)
    put.mockRejectedValueOnce(refused)
    await expect(transport.distributeIdentity({})).rejects.toBe(refused)
  })

  it('maps a successful send response to the engine outcome', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { stored: 2 } } as never)
    const transport = new ApiChatTransport()

    await expect(transport.sendMessage(BOB, { envelopes: [] })).resolves.toEqual({
      kind: 'delivered',
      deduplicated: false,
    })
    expect(post).toHaveBeenCalledWith(
      '/chat/accounts/00000000-0000-4000-8000-81b637d8fcd2/messages',
      { envelopes: [] },
      { params: { server: 'b.test' } },
    )
  })

  it('routes by account only, never by an address', async () => {
    const post = vi.spyOn(api, 'post')
    const transport = new ApiChatTransport()
    await expect(transport.sendMessage('bob@b.test', {})).rejects.toThrow('not an account reference')
    await expect(transport.fetchBundles('bob')).rejects.toThrow('not an account reference')
    expect(post).not.toHaveBeenCalled()
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

    await expect(transport.sendMessage(BOB, {})).resolves.toEqual({
      kind: 'mismatch',
      mismatch: { missingDevices: [2], staleDevices: [], extraDevices: [] },
    })
  })

  it('uses the authenticated own-device endpoints for encrypted transcripts', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { devices: [] } } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { stored: 1 } } as never)
    const transport = new ApiChatTransport()

    await transport.fetchSyncBundles(ALICE, 7)
    expect(get).toHaveBeenCalledWith('/chat/accounts/00000000-0000-4000-8000-2bd806c97f0e/keys', {
      params: { syncDeviceId: 7, server: 'remote.example' },
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

  it('treats only the server\'s noManifest 404 as an absent manifest', async () => {
    const get = vi.spyOn(api, 'get').mockRejectedValue({
      isAxiosError: true,
      response: { status: 404, data: { error: 'chat manifest not found', code: 'noManifest' } },
    })
    const transport = new ApiChatTransport()

    await expect(transport.fetchManifest(BOB)).resolves.toBeNull()

    // Another 404 (a proxy, Chat off) is no answer: never a re-registration.
    get.mockRejectedValueOnce({ isAxiosError: true, response: { status: 404, data: '' } })
    await expect(transport.fetchManifest(BOB)).rejects.toMatchObject({
      response: { status: 404 },
    })

    get.mockRejectedValueOnce({ isAxiosError: true, response: { status: 503 } })
    await expect(transport.fetchManifest(BOB)).rejects.toMatchObject({
      response: { status: 503 },
    })
  })

  it('fetches complete manifest history with lossless sequence bounds', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({
      data: { account: 'aci:00000000-0000-4000-8000-2bd806c97f0e@remote.example', manifests: [{ sequence: 4 }] },
    } as never)
    const transport = new ApiChatTransport()

    await expect(
      transport.fetchManifestHistory(
        'aci:00000000-0000-4000-8000-2bd806c97f0e@remote.example',
        '1',
        '18446744073709551615',
        '18446744073709551615',
      ),
    ).resolves.toMatchObject({ manifests: [{ sequence: 4 }] })
    expect(get).toHaveBeenCalledWith(
      '/chat/accounts/00000000-0000-4000-8000-2bd806c97f0e/manifest-history',
      {
        params: {
          server: 'remote.example',
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

    await expect(transport.fetchProfile(ALICE, 'version/value', 'secret-key'))
      .resolves.toEqual({ version: 'v1' })
    expect(get).toHaveBeenNthCalledWith(
      1,
      '/chat/accounts/00000000-0000-4000-8000-2bd806c97f0e/profile/version%2Fvalue',
      { params: { server: 'remote.example' }, headers: { 'X-Kutup-Profile-Access-Key': 'secret-key' } },
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

  it('sends sealed bundle fetches and messages to the anonymous account routes, unauthenticated', async () => {
    const base = await resolveApiBase()
    const post = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} } as never)
    const transport = new ApiChatTransport()
    const anonymous = { withCredentials: false, headers: { Authorization: undefined } }

    await transport.fetchSealedBundles(BOB, 'Y2Fw')
    expect(post).toHaveBeenLastCalledWith(
      `${base}/chat/anonymous/accounts/00000000-0000-4000-8000-81b637d8fcd2/keys`,
      { capability: 'Y2Fw' },
      { params: { server: 'b.test' }, ...anonymous },
    )
    await transport.sendSealedMessage(BOB, { sendId: 's-0' })
    expect(post).toHaveBeenLastCalledWith(
      `${base}/chat/anonymous/accounts/00000000-0000-4000-8000-81b637d8fcd2/messages`,
      { sendId: 's-0' },
      { params: { server: 'b.test' }, ...anonymous },
    )
  })

  it('sends a sealed batch anonymously to its destination server', async () => {
    const base = await resolveApiBase()
    const results = { results: [] }
    const post = vi.spyOn(axios, 'post').mockResolvedValue({ data: results } as never)
    const transport = new ApiChatTransport()
    await expect(transport.sendSealedBatch('b.test', { recipients: [] })).resolves.toEqual(results)
    expect(post).toHaveBeenLastCalledWith(
      `${base}/chat/anonymous/messages/batch`,
      { recipients: [] },
      { params: { server: 'b.test' }, withCredentials: false, headers: { Authorization: undefined } },
    )
  })

  it('a batch the server refuses as a whole is no answer: the engine keeps its legs for later', async () => {
    await resolveApiBase()
    const transport = new ApiChatTransport()
    for (const status of [429, 404, 503]) {
      const failure = new axios.AxiosError('failed', String(status), undefined, undefined, { status, data: { error: 'no' } } as never)
      vi.spyOn(axios, 'post').mockRejectedValueOnce(failure)
      await expect(transport.sendSealedBatch('b.test', { recipients: [] })).rejects.toBeTruthy()
    }
    // An older server without this Chat version says so, as for one send.
    const unsupported = new axios.AxiosError('failed', '503', undefined, undefined, { status: 503, data: { code: 'peerUnsupported' } } as never)
    vi.spyOn(axios, 'post').mockRejectedValueOnce(unsupported)
    await expect(transport.sendSealedBatch('b.test', { recipients: [] })).rejects.toThrow(/peerUnsupported/)
  })

  it('sends a multi-recipient group copy anonymously and maps each answer', async () => {
    const response = { refused: [], rateLimited: [], devices: [], stale: [] }
    const post = vi.spyOn(axios, 'post').mockResolvedValueOnce({ status: 200, data: response } as never)
    const transport = new ApiChatTransport()
    await expect(transport.sendSealedMulti('b.test', { sendId: 's' })).resolves
      .toEqual({ kind: 'answered', status: 200, response })
    expect(post).toHaveBeenCalledWith(
      expect.stringMatching(/\/chat\/anonymous\/messages\/multi$/),
      { sendId: 's' },
      { params: { server: 'b.test' }, withCredentials: false, headers: { Authorization: undefined } },
    )
    const answer = (status: number, data: unknown = {}) =>
      new axios.AxiosError('failed', String(status), undefined, undefined, { status, data } as never)
    const moved = { ...response, devices: [{ accountId: 'x', missingDevices: [2], extraDevices: [] }] }
    for (const [status, expected] of [
      [409, { kind: 'answered', status: 409, response: moved }],
      [410, { kind: 'answered', status: 410, response: moved }],
      [503, { kind: 'peerUnavailable' }],
      [404, { kind: 'peerUnavailable' }],
      [413, { kind: 'tooLarge' }],
      [429, { kind: 'rateLimited' }],
    ] as const) {
      post.mockRejectedValueOnce(answer(status, moved))
      await expect(transport.sendSealedMulti('b.test', {})).resolves.toEqual(expected)
    }
    post.mockRejectedValueOnce(new Error('offline'))
    await expect(transport.sendSealedMulti('b.test', {})).rejects.toBeTruthy()
  })

  it('sets the published group capabilities and says when the server takes no more', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValueOnce({ data: { count: 8 } } as never)
    const transport = new ApiChatTransport()
    const hashes = Array.from({ length: 8 }, (_, index) => `h${index}`)
    await expect(transport.setGroupCapabilities(hashes)).resolves.toEqual({ kind: 'set', count: 8 })
    expect(post).toHaveBeenCalledWith('/chat/group-capabilities/set', { hashes })
    post.mockRejectedValueOnce(new axios.AxiosError('full', '409', undefined, undefined,
      { status: 409, data: { error: 'too many', code: 'capabilityLimit' } } as never))
    await expect(transport.setGroupCapabilities(hashes)).resolves.toEqual({ kind: 'limitReached' })
    const other = new axios.AxiosError('conflict', '409', undefined, undefined, { status: 409, data: {} } as never)
    post.mockRejectedValueOnce(other)
    await expect(transport.setGroupCapabilities(hashes)).rejects.toBe(other)
  })

  it('reports only the server\'s own sealed refusal as refused', async () => {
    await resolveApiBase()
    const refusal = (data: unknown) => new axios.AxiosError('failed', '404', undefined, undefined, { status: 404, data } as never)
    const post = vi
      .spyOn(axios, 'post')
      .mockRejectedValueOnce(refusal({ error: 'sealed delivery unavailable' }))
      .mockRejectedValueOnce(refusal('<html>Not Found</html>'))
    const transport = new ApiChatTransport()

    await expect(transport.sendSealedMessage(BOB, { sendId: 's-1' })).resolves.toEqual({ kind: 'refused' })
    await expect(transport.sendSealedMessage(BOB, { sendId: 's-2' })).rejects.toThrow('failed')
    expect(post).toHaveBeenCalledTimes(2)
  })

  it('reaches a group home through this account\'s relay, with the answer still sealed', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { config: 'c', identityHistory: [] } } as never)
    const post = vi
      .spyOn(api, 'post')
      .mockResolvedValue({ data: new Uint8Array([1, 2, 3]).buffer } as never)
    const transport = new ApiChatTransport()

    await expect(transport.fetchGroupGateway('home.example', '4')).resolves.toEqual({ config: 'c', identityHistory: [] })
    expect(get).toHaveBeenCalledWith('/chat/groups/gateway-key', { params: { server: 'home.example', fromSequence: '4' } })

    // A view into a larger buffer (as WASM memory is): only its own bytes go.
    const memory = new Uint8Array([7, 7, 9, 9, 7])
    const sealed = memory.subarray(2, 4)
    await expect(transport.relayGroupRequest('home.example', sealed)).resolves.toEqual({ kind: 'answered', body: 'AQID' })
    const [path, body, options] = post.mock.calls[0]
    expect(path).toBe('/chat/groups/relay/home.example')
    expect(new Uint8Array(body as ArrayBuffer)).toEqual(new Uint8Array([9, 9]))
    expect(options).toEqual({ headers: { 'Content-Type': 'message/ohttp-req' }, responseType: 'arraybuffer' })
  })

  it('maps the relay\'s refusals to what the engine does next', async () => {
    const transport = new ApiChatTransport()
    for (const [status, kind] of [
      [400, 'unopenable'],
      [429, 'rateLimited'],
      [502, 'unreachable'],
      [404, 'groupsOff'],
    ] as const) {
      const failure = new axios.AxiosError('refused', String(status), undefined, undefined, { status } as never)
      vi.spyOn(api, 'post').mockRejectedValueOnce(failure)
      await expect(transport.relayGroupRequest('home.example', new Uint8Array([1]))).resolves.toEqual({ kind })
    }
    const other = new axios.AxiosError('boom', '500', undefined, undefined, { status: 500 } as never)
    vi.spyOn(api, 'post').mockRejectedValueOnce(other)
    await expect(transport.relayGroupRequest('home.example', new Uint8Array([1]))).rejects.toBe(other)
  })
})
