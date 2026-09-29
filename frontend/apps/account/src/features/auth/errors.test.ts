import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { describe, expect, it } from 'vitest'
import { authErrorMessage } from './errors'

const t = ((key: string) => `t:${key}`) as Parameters<typeof authErrorMessage>[1]

function failed(status: number, error: string): AxiosError {
  const response = { status, data: { error }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', String(status), undefined, undefined, response)
}

describe('authErrorMessage', () => {
  it('shows rejected credentials in the person’s language, never the server’s English', () => {
    expect(authErrorMessage(failed(401, 'invalid credentials'), t, 'auth.errors.signInFailed')).toBe('t:auth.errors.signInFailed')
  })

  it('names a lockout and a lost connection', () => {
    expect(authErrorMessage(failed(429, 'slow down'), t, 'auth.errors.signInFailed')).toBe('t:auth.errors.locked')
    expect(authErrorMessage(new AxiosError('offline'), t, 'auth.errors.signInFailed')).toBe('t:auth.errors.network')
  })
})
