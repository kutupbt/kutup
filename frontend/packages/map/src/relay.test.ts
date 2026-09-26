import { afterEach, describe, expect, it } from 'vitest'
import { setAccessToken } from '@kutup/session/store'
import { relayRequest } from './relay'

describe('relayRequest', () => {
  afterEach(() => setAccessToken(''))

  it('sends the token only to this server’s relay', () => {
    setAccessToken('t0ken')
    expect(relayRequest('/api/maps/proxy/openfreemap/planet', 'https://drive.example.org')).toEqual({
      url: 'https://drive.example.org/api/maps/proxy/openfreemap/planet',
      headers: { Authorization: 'Bearer t0ken' },
    })
    expect(relayRequest('https://tiles.openfreemap.org/planet', 'https://drive.example.org')).toEqual({
      url: 'https://tiles.openfreemap.org/planet',
    })
    // Another API path on this origin is not a map request.
    expect(relayRequest('/api/user/me', 'https://drive.example.org').headers).toBeUndefined()
  })
})
