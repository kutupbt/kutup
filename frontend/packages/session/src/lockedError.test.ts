import { AxiosError, AxiosHeaders } from 'axios'
import { describe, expect, it } from 'vitest'
import { lockedErrorFrom, ReauthLockedError } from './reauth'

function refused(status: number, data: unknown) {
  return new AxiosError('x', 'ERR', undefined, undefined, {
    status, statusText: '', data, headers: {}, config: { headers: new AxiosHeaders() },
  })
}

describe('lockedErrorFrom', () => {
  it('tells the address limit from the account lockout', () => {
    expect(lockedErrorFrom(refused(429, { code: 'rateLimited' }))?.reason).toBe('rateLimited')
    expect(lockedErrorFrom(refused(429, { code: 'accountLocked' }))?.reason).toBe('accountLocked')
    // An older server without a code: the lockout, as before.
    expect(lockedErrorFrom(refused(429, {}))).toBeInstanceOf(ReauthLockedError)
    expect(lockedErrorFrom(refused(401, {}))).toBeNull()
    expect(lockedErrorFrom(new Error('x'))).toBeNull()
  })
})
