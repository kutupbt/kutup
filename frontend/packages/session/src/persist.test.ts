import { AxiosError, AxiosHeaders } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const refresh = vi.fn()
const get = vi.fn()
vi.mock('./client', () => ({
  default: { get: (...a: unknown[]) => get(...a), put: vi.fn() },
  getClientType: () => 'web-drive',
  refreshAccessToken: () => refresh(),
}))
const activateSession = vi.fn()
const fetchProfile = vi.fn()
vi.mock('./profile', () => ({
  activateSession: (...a: unknown[]) => activateSession(...a),
  fetchProfile: (...a: unknown[]) => fetchProfile(...a),
}))
const wasm = vi.fn()
vi.mock('@kutup/crypto/rustWasm', () => ({ getCryptoWasm: () => wasm() }))
const open = vi.fn()
vi.mock('@kutup/crypto/localState', () => ({
  LocalStatePurpose: { SessionFork: 2, WebSession: 3 },
  sealLocalState: vi.fn(),
  openLocalState: (...a: unknown[]) => open(...a),
}))

import { encodeKeys } from './keys'
import { restoreSession } from './persist'
import { PERSISTED_SESSION_KEY, readPersisted, writePersisted } from './persistedStore'

function httpError(status: number) {
  return new AxiosError('x', 'ERR', undefined, undefined, {
    status, statusText: '', data: {}, headers: {}, config: { headers: new AxiosHeaders() },
  })
}
const networkError = new AxiosError('Network Error', 'ERR_NETWORK')
const keys = { userId: 'u1', masterKey: new Uint8Array(32), privateKey: new Uint8Array(32), publicKey: 'p' }

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  writePersisted({ v: 1, sessionId: 'S1', userId: 'u1', blob: 'BLOB' })
  refresh.mockResolvedValue({ accessToken: 'AT', sessionId: 'S1' })
  get.mockResolvedValue({ data: { key: 'A'.repeat(43) + '=' } })
  wasm.mockResolvedValue({})
  fetchProfile.mockResolvedValue({ id: 'u1' })
  open.mockResolvedValue(encodeKeys(keys))
})

describe('restoreSession', () => {
  it('restores from the blob with the server-held key', async () => {
    expect(await restoreSession()).toBe('restored')
    expect(open).toHaveBeenCalledWith('BLOB', expect.any(Uint8Array), 3, 'web-drive:S1')
    // The profile came alongside the key, under the fresh token.
    expect(fetchProfile).toHaveBeenCalledWith('AT')
    expect(activateSession).toHaveBeenCalledWith(expect.objectContaining({ userId: 'u1' }), 'AT', 'S1', { id: 'u1' })
  })

  it('reports none without a blob, touching nothing', async () => {
    localStorage.removeItem(PERSISTED_SESSION_KEY)
    expect(await restoreSession()).toBe('none')
    expect(refresh).not.toHaveBeenCalled()
  })

  it.each([
    ['the session ended', () => refresh.mockRejectedValue(httpError(401))],
    ['the blob belongs to another session', () => refresh.mockResolvedValue({ accessToken: 'AT', sessionId: 'S2' })],
    ['the server has no local key', () => get.mockRejectedValue(httpError(404))],
    ['the blob does not open', () => open.mockRejectedValue('authentication failed')],
  ])('clears the blob when %s', async (_, arrange) => {
    arrange()
    expect(await restoreSession()).toBe('none')
    expect(readPersisted()).toBeNull()
  })

  it.each([
    ['the server is unreachable', () => refresh.mockRejectedValue(networkError)],
    ['the server fails', () => refresh.mockRejectedValue(httpError(503))],
    ['the key request is interrupted', () => get.mockRejectedValue(networkError)],
    ['the WASM runtime does not load', () => wasm.mockRejectedValue(new TypeError('Failed to fetch'))],
  ])('keeps the blob and rethrows when %s', async (_, arrange) => {
    arrange()
    await expect(restoreSession()).rejects.toBeDefined()
    expect(readPersisted()).not.toBeNull()
  })
})
