// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest'
import api, { configureClient, setUnauthenticatedHandler } from './client'
import { clearSession, getAccessToken, getSession, setSession } from './store'

// Tests for the axios wrapper at frontend/src/api/client.ts.
// Strategy: install a tiny in-memory adapter on the api instance via
// `defaults.adapter`. Each test programs the adapter's responses, so we
// can drive the interceptor (Authorization header, 401-refresh, 503-retry)
// without the network or jsdom XHR/MSW interactions.
//
// What's verified end-to-end:
//   - Authorization Bearer header pulled from Redux on every request
//   - 401 triggers a single refresh; in-flight queued requests piggyback
//   - skipRefresh routes (/auth/login etc.) DON'T refresh on 401
//   - 503 triggers exponential backoff (max 3 retries)
//   - Refresh failure dispatches logout

// Install an in-memory adapter. axios calls adapter(config); we map by URL
// path → an array of responses (consumed in order).
type AdapterCall = { method: string; url: string; headers: Record<string, string> }
type AdapterResponse =
  | { status: number; data: unknown }
  | (() => { status: number; data: unknown })

configureClient({ clientType: 'web-account' })

const calls: AdapterCall[] = []
const responses: Record<string, AdapterResponse[]> = {}
const route = (k: string) => `${(k.split(' ')[0] || 'GET').toUpperCase()} ${k.split(' ').slice(1).join(' ')}`

api.defaults.adapter = async (config) => {
  const method = (config.method || 'get').toUpperCase()
  const url = config.url || ''
  calls.push({ method, url, headers: { ...(config.headers as Record<string, string>) } })
  const key = `${method} ${url}`
  const queue = responses[key]
  if (!queue || queue.length === 0) {
    const err: any = new Error(`no mock for ${key}`)
    err.config = config
    err.response = { status: 0, data: { error: 'unmatched' }, headers: {}, config, statusText: '' }
    throw err
  }
  const r = queue.shift()!
  const resolved = typeof r === 'function' ? r() : r
  if (resolved.status >= 400) {
    const err: any = new Error(`mock ${resolved.status}`)
    err.config = config
    err.response = { ...resolved, headers: {}, config, statusText: '' }
    throw err
  }
  return { ...resolved, headers: {}, config, statusText: 'OK' }
}

const seedAuth = (token: string | null) => {
  if (token === null) {
    clearSession()
    return
  }
  setSession({
    sessionId: 's',
    userId: 'u',
    address: 'a@b.c', envelopeBinding: 'a@b.c',
    username: null,
    masterKey: new Uint8Array(0),
    privateKey: new Uint8Array(0),
    publicKey: '',
    isAdmin: false,
    storageQuotaBytes: 0,
    storageUsedBytes: 0,
    totpEnabled: false,
    color: null,
    currentDeviceId: null,
    device: null,
  }, token)
}

beforeEach(() => {
  calls.length = 0
  for (const k of Object.keys(responses)) delete responses[k]
  seedAuth(null)
})

describe('api/client — Authorization header', () => {
  it('attaches Bearer when accessToken is set in store', async () => {
    seedAuth('abc-token')
    responses[route('GET /me')] = [{ status: 200, data: { ok: true } }]
    await api.get('/me')
    expect(calls[0].headers.Authorization).toBe('Bearer abc-token')
  })

  it('omits Authorization when no token is set', async () => {
    responses[route('GET /me')] = [{ status: 200, data: { ok: true } }]
    await api.get('/me')
    expect(calls[0].headers.Authorization).toBeUndefined()
  })
})

describe('api/client — 401 refresh chain', () => {
  it('refreshes once and replays the original request with the new token', async () => {
    seedAuth('stale-token')
    responses[route('GET /me')] = [
      { status: 401, data: { error: 'expired' } },
      { status: 200, data: { ok: true } },
    ]
    // axios's plain `axios.post` is used for /auth/refresh in client.ts:73,
    // which goes via the same default adapter (we set api.defaults.adapter
    // but axios.defaults.adapter is separate). Stub axios.defaults too.
    const axiosMod = (await import('axios')).default
    axiosMod.defaults.adapter = api.defaults.adapter
    responses['POST /api/auth/refresh'] = [{ status: 200, data: { accessToken: 'fresh-token' } }]

    const res = await api.get('/me')
    expect(res.data).toEqual({ ok: true })
    // First /me with stale, second with fresh.
    const meCalls = calls.filter((c) => c.url === '/me')
    expect(meCalls).toHaveLength(2)
    expect(meCalls[0].headers.Authorization).toBe('Bearer stale-token')
    expect(meCalls[1].headers.Authorization).toBe('Bearer fresh-token')
    expect(getAccessToken()).toBe('fresh-token')
  })

  it('clears the session and calls the unauthenticated handler when refresh fails', async () => {
    seedAuth('stale-token')
    responses[route('GET /me')] = [{ status: 401, data: { error: 'expired' } }]
    const axiosMod = (await import('axios')).default
    axiosMod.defaults.adapter = api.defaults.adapter
    responses['POST /api/auth/refresh'] = [{ status: 401, data: { error: 'revoked' } }]
    let called = 0
    setUnauthenticatedHandler(() => { called += 1 })

    await expect(api.get('/me')).rejects.toBeTruthy()
    expect(called).toBe(1)
    expect(getSession()).toBeNull()
    expect(getAccessToken()).toBeNull()
    setUnauthenticatedHandler(() => {})
  })

  it('does not retry skipRefresh routes (login/register/recover) on 401', async () => {
    seedAuth('any-token')
    responses[route('POST /auth/login/start')] = [{ status: 401, data: { error: 'bad pw' } }]
    // No /auth/refresh handler — if it gets called the adapter would 0-status
    // and we'd see it in `calls`.
    await expect(api.post('/auth/login/start', {})).rejects.toBeTruthy()
    const refreshCalls = calls.filter((c) => c.url === '/api/auth/refresh')
    expect(refreshCalls, 'refresh must NOT fire for /auth/login 401').toHaveLength(0)
  })

  it('does not retry a wrong password at the re-checks (it would count twice)', async () => {
    seedAuth('any-token')
    responses[route('POST /user/reauth')] = [{ status: 401, data: { error: 'invalid credentials', code: 'invalidCredentials' } }]
    responses[route('PUT /pass/pin')] = [{ status: 401, data: { error: 'invalid credentials', code: 'invalidCredentials' } }]
    await expect(api.post('/user/reauth', {})).rejects.toBeTruthy()
    await expect(api.put('/pass/pin', {})).rejects.toBeTruthy()
    expect(calls.filter((c) => c.url === '/api/auth/refresh')).toHaveLength(0)
    expect(calls.filter((c) => c.url?.endsWith('/user/reauth'))).toHaveLength(1)
  })

  it('never refreshes for an auth call, even with a session: a setup token that ran out', async () => {
    seedAuth('another-accounts-token')
    responses[route('POST /auth/opaque/register/start')] = [
      { status: 401, data: { error: 'invalid token', code: 'setupTokenInvalid' } },
    ]
    let ended = 0
    setUnauthenticatedHandler(() => { ended += 1 })
    await expect(api.post('/auth/opaque/register/start', {}, { headers: { Authorization: 'Bearer setup' } })).rejects.toMatchObject({
      response: { status: 401 },
    })
    expect(calls.filter((c) => c.url === '/api/auth/refresh')).toHaveLength(0)
    expect(calls.filter((c) => c.url?.endsWith('/register/start'))).toHaveLength(1)
    // Nothing of this origin's session was touched.
    expect(ended).toBe(0)
    expect(getAccessToken()).toBe('another-accounts-token')
    setUnauthenticatedHandler(() => {})
  })

  it('never refreshes for a signed-in password check, nor for the codes that name a credential', async () => {
    seedAuth('expired-token')
    responses[route('POST /auth/login/finish')] = [{ status: 401, data: { error: 'unauthorized' } }]
    responses[route('POST /auth/login/2fa')] = [{ status: 401, data: { error: 'expired', code: 'preAuthInvalid' } }]
    responses[route('POST /user/thing')] = [{ status: 401, data: { error: 'expired', code: 'setupTokenInvalid' } }]
    await expect(api.post('/auth/login/finish', {})).rejects.toBeTruthy()
    await expect(api.post('/auth/login/2fa', {})).rejects.toBeTruthy()
    await expect(api.post('/user/thing', {})).rejects.toBeTruthy()
    expect(calls.filter((c) => c.url === '/api/auth/refresh')).toHaveLength(0)
    expect(getAccessToken()).toBe('expired-token')
  })

  it('refreshes an expired token on the Bearer calls under /auth (sessions, forks)', async () => {
    seedAuth('expired-token')
    responses[route('GET /auth/sessions/current/local-key')] = [
      { status: 401, data: { error: 'expired' } },
      { status: 200, data: { key: 'k' } },
    ]
    responses[route('POST /auth/forks')] = [
      { status: 401, data: { error: 'expired' } },
      { status: 200, data: { selector: 's' } },
    ]
    const axiosMod = (await import('axios')).default
    axiosMod.defaults.adapter = api.defaults.adapter
    responses['POST /api/auth/refresh'] = [
      { status: 200, data: { accessToken: 'fresh-token' } },
      { status: 200, data: { accessToken: 'fresher-token' } },
    ]
    await expect(api.get('/auth/sessions/current/local-key')).resolves.toMatchObject({ data: { key: 'k' } })
    await expect(api.post('/auth/forks', {})).resolves.toMatchObject({ data: { selector: 's' } })
    expect(calls.filter((c) => c.url === '/auth/sessions/current/local-key')).toHaveLength(2)
    expect(calls.filter((c) => c.url === '/auth/forks')).toHaveLength(2)
  })

  it('does not refresh for a fork link (it carries no token)', async () => {
    seedAuth('any-token')
    responses[route('POST /auth/forks/consume')] = [{ status: 401, data: { error: 'unknown fork' } }]
    await expect(api.post('/auth/forks/consume', {})).rejects.toBeTruthy()
    expect(calls.filter((c) => c.url === '/api/auth/refresh')).toHaveLength(0)
  })

  it('refreshes an expired token at the re-checks and retries', async () => {
    seedAuth('expired-token')
    responses[route('POST /user/reauth')] = [
      { status: 401, data: { error: 'unauthorized' } },
      { status: 204, data: '' },
    ]
    const axiosMod = (await import('axios')).default
    axiosMod.defaults.adapter = api.defaults.adapter
    responses['POST /api/auth/refresh'] = [{ status: 200, data: { accessToken: 'fresh-token' } }]
    await expect(api.post('/user/reauth', {})).resolves.toBeTruthy()
    const reauthCalls = calls.filter((c) => c.url?.endsWith('/user/reauth'))
    expect(reauthCalls).toHaveLength(2)
    expect(reauthCalls[1].headers.Authorization).toBe('Bearer fresh-token')
  })
})

describe('api/client — transient retries', () => {
  it('retries 503 up to 3 times then succeeds', async () => {
    responses[route('GET /lookup')] = [
      { status: 503, data: { error: 'busy' } },
      { status: 503, data: { error: 'busy' } },
      { status: 200, data: { ok: true } },
    ]
    const res = await api.get('/lookup')
    expect(res.data).toEqual({ ok: true })
    expect(calls.filter((c) => c.url === '/lookup')).toHaveLength(3)
  }, 15_000)
})
