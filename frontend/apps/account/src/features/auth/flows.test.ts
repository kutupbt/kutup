import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccountKeys } from './flows'

const post = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { post, get: vi.fn() } }))
vi.mock('@kutup/session/persist', () => ({ persistKeys: vi.fn() }))
vi.mock('@kutup/crypto', () => ({ toBase64: () => 'master' }))
vi.mock('@kutup/crypto/identityPins', () => ({ signDriveKeyBinding: vi.fn(() => Promise.resolve('binding')) }))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: vi.fn(() => Promise.resolve({ chat: { serverName: 'kutup.dev' } })) }))
vi.mock('@kutup/crypto/accountProtectionWorker', () => ({}))
vi.mock('@kutup/session/profile', () => ({ activateSession: vi.fn() }))

import { registerAndSignIn } from './flows'

function limited(): AxiosError {
  const response = { status: 429, data: { error: 'slow down' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', '429', undefined, undefined, response)
}

const keys = () => ({ loginKey: 'login', masterKey: new Uint8Array(32), privateKey: new Uint8Array(32), publicKey: new Uint8Array(32), keyBinding: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70' }) as unknown as AccountKeys

describe('registerAndSignIn', () => {
  beforeEach(() => post.mockReset())

  it('creates the account once when the sign-in half is retried', async () => {
    const paths: string[] = []
    let logins = 0
    post.mockImplementation((path: string) => {
      paths.push(path)
      if (path === '/auth/login' && ++logins === 1) return Promise.reject(limited())
      return Promise.resolve({ data: { userId: 'u1', accessToken: 'a' } })
    })
    const k = keys()
    await expect(registerAndSignIn('a', k)).rejects.toBeInstanceOf(AxiosError)
    await registerAndSignIn('a', k)
    expect(paths).toEqual(['/auth/register', '/auth/login', '/auth/login'])
    // The account's Drive key binding goes with it (docs/plans/drive-identity-pins.md).
    expect(post.mock.calls[0][1]).toMatchObject({ username: 'a', driveKeyBinding: 'binding' })
  })

  it('registers again after a failed registration', async () => {
    post.mockRejectedValueOnce(limited()).mockResolvedValue({ data: { userId: 'u1', accessToken: 'a' } })
    const k = keys()
    await expect(registerAndSignIn('a', k)).rejects.toBeInstanceOf(AxiosError)
    await registerAndSignIn('a', k)
    expect(post.mock.calls.map(([path]) => path as string)).toEqual(['/auth/register', '/auth/register', '/auth/login'])
  })
})

describe('completeSetup', () => {
  beforeEach(() => post.mockReset())

  it('sends the new keys with their Drive key binding', async () => {
    post.mockResolvedValue({ data: { userId: 'u1', accessToken: 'a', sessionId: 's' } })
    const { completeSetup } = await import('./flows')
    await completeSetup({ name: 'a@kutup.dev', username: 'a', setupToken: 'setup' }, keys())
    expect(post.mock.calls[0][0]).toBe('/auth/complete-setup')
    expect(post.mock.calls[0][1]).toMatchObject({ keyBinding: keys().keyBinding, driveKeyBinding: 'binding' })
    expect(post.mock.calls[0][2]).toMatchObject({ headers: { Authorization: 'Bearer setup' } })
  })
})
