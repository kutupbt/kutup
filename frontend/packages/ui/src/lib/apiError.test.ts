import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { i18n } from '@kutup/i18n'
import { initReactI18next } from 'react-i18next'
import { beforeAll, describe, expect, it } from 'vitest'
import { apiErrorMessage } from './apiError'

function refused(status: number, data: unknown): AxiosError {
  const response = { status, data, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', String(status), undefined, undefined, response)
}

beforeAll(async () => {
  await i18n.use(initReactI18next).init({
    lng: 'tr',
    resources: { tr: { translation: { apiErrors: { keysPendingUpgrade: 'tekrar giriş', peerOutdated: 'eski sunucu', checkTimedOut: 'çok uzun sürdü' } } } },
  })
})

describe('apiErrorMessage', () => {
  it('says a known refusal in the user’s language, whatever its status', () => {
    expect(apiErrorMessage(refused(409, { error: 'in English', code: 'keysPendingUpgrade' }), 'fallback')).toBe('tekrar giriş')
    expect(apiErrorMessage(refused(502, { error: 'in English', code: 'peerOutdated' }), 'fallback')).toBe('eski sunucu')
    // A domain's DNS check that ran out of time (Refresh, Verify).
    expect(apiErrorMessage(refused(503, { error: 'in English', code: 'checkTimedOut' }), 'fallback')).toBe('çok uzun sürdü')
  })

  it('says it for a client error that stops before asking, by its code', () => {
    expect(apiErrorMessage(Object.assign(new Error('x'), { code: 'keysPendingUpgrade' }), 'fallback')).toBe('tekrar giriş')
    expect(apiErrorMessage(new Error('x'), 'fallback')).toBe('fallback')
  })

  it('keeps the server’s 4xx message otherwise, and the fallback for 5xx', () => {
    expect(apiErrorMessage(refused(409, { error: 'taken', code: 'other' }), 'fallback')).toBe('taken')
    expect(apiErrorMessage(refused(500, { error: 'internal' }), 'fallback')).toBe('fallback')
  })
})
