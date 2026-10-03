import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { isServerUnreachable } from './openFailure'

function http(status: number): AxiosError {
  const response = { status, data: {}, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', String(status), undefined, undefined, response)
}

describe('isServerUnreachable', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('is true when the server gave no answer or said "not now"', () => {
    expect(isServerUnreachable(new AxiosError('Network Error'))).toBe(true)
    expect(isServerUnreachable(http(502))).toBe(true)
    expect(isServerUnreachable(http(503))).toBe(true)
    expect(isServerUnreachable(http(429))).toBe(true)
    // The engine's own requests.
    expect(isServerUnreachable(new Error('transport: Request failed with status code 502'))).toBe(true)
    expect(isServerUnreachable(new Error('transport: Network Error'))).toBe(true)
  })

  it('is false when the server answered and the problem is this browser\'s state', () => {
    // A device the server no longer knows: waiting will not bring it back.
    expect(isServerUnreachable(http(404))).toBe(false)
    expect(isServerUnreachable(new Error('transport: Request failed with status code 404'))).toBe(false)
    expect(isServerUnreachable(new Error('device trust: active MLS conversation pin is unavailable'))).toBe(false)
    expect(isServerUnreachable(new Error('Chat backup record mutation sequence is invalid'))).toBe(false)
  })

  it('is true for anything while the browser is offline', () => {
    vi.stubGlobal('navigator', { onLine: false })
    expect(isServerUnreachable(new Error('device trust: anything'))).toBe(true)
  })
})
