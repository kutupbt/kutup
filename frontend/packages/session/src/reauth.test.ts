import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const opaqueLogin = vi.hoisted(() => vi.fn())
vi.mock('./opaque', () => ({ opaqueLogin }))
vi.mock('./store', () => ({ getSession: () => ({ username: 'alice', address: 'alice@kutup.dev' }) }))
vi.mock('@kutup/crypto/opaqueWorker', () => ({ OpaqueAuthFailed: class OpaqueAuthFailed extends Error {} }))

import { OpaqueAuthFailed } from '@kutup/crypto/opaqueWorker'
import { accountGrant, ReauthLockedError, verifyAccountPassword, WrongPasswordError } from './reauth'

function refused(status: number, code?: string): AxiosError {
  const response = { status, data: code ? { error: 'x', code } : { error: 'x' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('refused', String(status), undefined, undefined, response)
}

beforeEach(() => opaqueLogin.mockReset())

describe('accountGrant', () => {
  it('returns the grant and closes the sign-in', async () => {
    const close = vi.fn()
    opaqueLogin.mockResolvedValue({ data: { grant: 'kg1_x' }, signIn: { close } })
    await expect(accountGrant('pw', 'passwordChange')).resolves.toBe('kg1_x')
    expect(opaqueLogin).toHaveBeenCalledWith('alice', 'pw', { purpose: 'reauth', for: 'passwordChange' })
    expect(close).toHaveBeenCalled()
  })

  it('a wrong password: refused here, or by the server with invalidCredentials', async () => {
    opaqueLogin.mockRejectedValueOnce(new OpaqueAuthFailed())
    await expect(accountGrant('pw', 'pass')).rejects.toBeInstanceOf(WrongPasswordError)
    opaqueLogin.mockRejectedValueOnce(refused(401, 'invalidCredentials'))
    await expect(accountGrant('pw', 'pass')).rejects.toBeInstanceOf(WrongPasswordError)
  })

  it('an ended sign-in is not a wrong password', async () => {
    const expired = refused(401)
    opaqueLogin.mockRejectedValueOnce(expired)
    await expect(accountGrant('pw', 'pass')).rejects.toBe(expired)
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
    expect(opaqueLogin).toHaveBeenCalledWith('alice', 'pw', { purpose: 'reauth', for: 'verify' })
    expect(close).toHaveBeenCalled()
    opaqueLogin.mockRejectedValueOnce(new OpaqueAuthFailed())
    await expect(verifyAccountPassword('pw')).resolves.toBe(false)
  })

  it('the lockout is not a wrong password', async () => {
    opaqueLogin.mockRejectedValueOnce(refused(429, 'accountLocked'))
    await expect(verifyAccountPassword('pw')).rejects.toBeInstanceOf(ReauthLockedError)
  })
})
