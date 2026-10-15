import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const opaqueLogin = vi.hoisted(() => vi.fn())
vi.mock('./opaque', () => ({ opaqueLogin }))
const client = vi.hoisted(() => ({
  freshAccessToken: vi.fn(() => Promise.resolve('token')),
  refreshOrEnd: vi.fn(() => Promise.resolve('fresh')),
  endSession: vi.fn(),
}))
vi.mock('./client', () => client)
vi.mock('./store', () => ({ getSession: () => ({ username: 'alice', address: 'alice@kutup.dev' }) }))
vi.mock('@kutup/crypto/opaqueWorker', () => ({ OpaqueAuthFailed: class OpaqueAuthFailed extends Error {} }))

import { OpaqueAuthFailed } from '@kutup/crypto/opaqueWorker'
import { accountGrant, ReauthLockedError, verifyAccountPassword, WrongPasswordError } from './reauth'

function refused(status: number, code?: string): AxiosError {
  const response = { status, data: code ? { error: 'x', code } : { error: 'x' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('refused', String(status), undefined, undefined, response)
}

beforeEach(() => {
  opaqueLogin.mockReset()
  for (const fn of Object.values(client)) fn.mockClear()
})

describe('accountGrant', () => {
  it('returns the grant and closes the sign-in', async () => {
    const close = vi.fn()
    opaqueLogin.mockResolvedValue({ data: { grant: 'kg1_x' }, signIn: { close } })
    await expect(accountGrant('pw', 'passwordChange')).resolves.toBe('kg1_x')
    expect(opaqueLogin).toHaveBeenCalledWith('pw', { purpose: 'reauth', for: 'passwordChange' })
    expect(close).toHaveBeenCalled()
  })

  it('a wrong password: refused here, or by the server with invalidCredentials', async () => {
    opaqueLogin.mockRejectedValueOnce(new OpaqueAuthFailed())
    await expect(accountGrant('pw', 'pass')).rejects.toBeInstanceOf(WrongPasswordError)
    opaqueLogin.mockRejectedValueOnce(refused(401, 'invalidCredentials'))
    await expect(accountGrant('pw', 'pass')).rejects.toBeInstanceOf(WrongPasswordError)
  })

  it('starts with a token that will last', async () => {
    opaqueLogin.mockResolvedValue({ data: { grant: 'g' }, signIn: { close: vi.fn() } })
    await accountGrant('pw', 'pass')
    expect(client.freshAccessToken.mock.invocationCallOrder[0]).toBeLessThan(opaqueLogin.mock.invocationCallOrder[0]!)
  })

  it('a token that ran out midway: refreshed, and the whole check run again from its start', async () => {
    opaqueLogin.mockRejectedValueOnce(refused(401)).mockResolvedValueOnce({ data: { grant: 'g' }, signIn: { close: vi.fn() } })
    await expect(accountGrant('pw', 'pass')).resolves.toBe('g')
    expect(client.refreshOrEnd).toHaveBeenCalledTimes(1)
    expect(opaqueLogin).toHaveBeenCalledTimes(2)
  })

  it('an ended sign-in is not a wrong password, and is tried again only once', async () => {
    const expired = refused(401)
    opaqueLogin.mockRejectedValue(expired)
    await expect(accountGrant('pw', 'pass')).rejects.toBe(expired)
    expect(opaqueLogin).toHaveBeenCalledTimes(2)
    client.refreshOrEnd.mockRejectedValueOnce(new Error('session gone'))
    opaqueLogin.mockClear()
    await expect(accountGrant('pw', 'pass')).rejects.toThrow('session gone')
    expect(opaqueLogin).toHaveBeenCalledTimes(1)
  })

  it('a wrong password is not retried', async () => {
    opaqueLogin.mockRejectedValue(refused(401, 'invalidCredentials'))
    await expect(accountGrant('pw', 'pass')).rejects.toBeInstanceOf(WrongPasswordError)
    expect(opaqueLogin).toHaveBeenCalledTimes(1)
    expect(client.refreshOrEnd).not.toHaveBeenCalled()
  })

  it('no token to be had: the session ends before any attempt', async () => {
    client.freshAccessToken.mockRejectedValueOnce(new Error('revoked'))
    await expect(accountGrant('pw', 'pass')).rejects.toThrow('revoked')
    expect(client.endSession).toHaveBeenCalled()
    expect(opaqueLogin).not.toHaveBeenCalled()
  })

  it('the lockout and the rate limit', async () => {
    opaqueLogin.mockRejectedValueOnce(refused(429, 'rateLimited'))
    await expect(accountGrant('pw', 'pass')).rejects.toMatchObject({ reason: 'rateLimited' })
    opaqueLogin.mockRejectedValueOnce(refused(429, 'accountLocked'))
    await expect(accountGrant('pw', 'pass')).rejects.toBeInstanceOf(ReauthLockedError)
  })
})

describe('verifyAccountPassword', () => {
  it('asks for no grant, and tells right from wrong', async () => {
    const close = vi.fn()
    opaqueLogin.mockResolvedValueOnce({ data: {}, signIn: { close } })
    await expect(verifyAccountPassword('pw')).resolves.toBe(true)
    expect(opaqueLogin).toHaveBeenCalledWith('pw', { purpose: 'reauth', for: 'verify' })
    expect(close).toHaveBeenCalled()
    opaqueLogin.mockRejectedValueOnce(new OpaqueAuthFailed())
    await expect(verifyAccountPassword('pw')).resolves.toBe(false)
  })

  it('the lockout is not a wrong password', async () => {
    opaqueLogin.mockRejectedValueOnce(refused(429, 'accountLocked'))
    await expect(verifyAccountPassword('pw')).rejects.toBeInstanceOf(ReauthLockedError)
  })
})
