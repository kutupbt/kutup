import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { RegistrationKeys } from '@kutup/crypto'

const post = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { post } }))
vi.mock('@kutup/session/persist', () => ({ persistKeys: vi.fn() }))
vi.mock('@kutup/crypto', () => ({}))
vi.mock('@kutup/crypto/accountProtectionWorker', () => ({}))
vi.mock('@kutup/session/profile', () => ({ activateSession: vi.fn() }))

import { registerAndSignIn } from './flows'

function limited(): AxiosError {
  const response = { status: 429, data: { error: 'slow down' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', '429', undefined, undefined, response)
}

const keys = () => ({ loginKey: 'login', masterKey: new Uint8Array(32), privateKey: new Uint8Array(32), publicKey: new Uint8Array(32) }) as unknown as RegistrationKeys

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
    await expect(registerAndSignIn('a@kutup.dev', 'a', k)).rejects.toBeInstanceOf(AxiosError)
    await registerAndSignIn('a@kutup.dev', 'a', k)
    expect(paths).toEqual(['/auth/register', '/auth/login', '/auth/login'])
  })

  it('registers again after a failed registration', async () => {
    post.mockRejectedValueOnce(limited()).mockResolvedValue({ data: { userId: 'u1', accessToken: 'a' } })
    const k = keys()
    await expect(registerAndSignIn('a@kutup.dev', 'a', k)).rejects.toBeInstanceOf(AxiosError)
    await registerAndSignIn('a@kutup.dev', 'a', k)
    expect(post.mock.calls.map(([path]) => path as string)).toEqual(['/auth/register', '/auth/register', '/auth/login'])
  })
})
