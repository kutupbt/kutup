import { AxiosError } from 'axios'
import { describe, expect, it } from 'vitest'
import { classifyUploadError } from './uploadError'

const tus = (status: number, body: string) =>
  Object.assign(new Error('tus'), { originalResponse: { getStatus: () => status, getBody: () => body } })

describe('classifyUploadError', () => {
  it('tells the two quotas apart', () => {
    expect(classifyUploadError(tus(413, '{"error":"storage quota exceeded"}'))).toBe('quota')
    expect(classifyUploadError(tus(413, '{"error":"share upload quota exceeded"}'))).toBe('shareQuota')
  })
  it('reads federated (axios) failures too', () => {
    expect(classifyUploadError(new AxiosError('x', 'ERR', undefined, undefined, {
      status: 403, statusText: '', data: {}, headers: {}, config: {} as never,
    }))).toBe('forbidden')
    expect(classifyUploadError(new AxiosError('Network Error', 'ERR_NETWORK'))).toBe('network')
  })
})
