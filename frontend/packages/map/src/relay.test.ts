import { afterEach, describe, expect, it } from 'vitest'
import { setAccessToken } from '@kutup/session/store'
import { absoluteStyle, relayRequest } from './relay'

describe('relayRequest', () => {
  afterEach(() => setAccessToken(''))

  it('sends the token only to this server’s relay', () => {
    setAccessToken('t0ken')
    expect(relayRequest('/api/v1/maps/proxy/openfreemap/planet', 'https://drive.example.org')).toEqual({
      url: 'https://drive.example.org/api/v1/maps/proxy/openfreemap/planet',
      headers: { Authorization: 'Bearer t0ken' },
    })
    expect(relayRequest('https://tiles.openfreemap.org/planet', 'https://drive.example.org')).toEqual({
      url: 'https://tiles.openfreemap.org/planet',
    })
    // Another API path on this origin is not a map request.
    expect(relayRequest('/api/v1/account', 'https://drive.example.org').headers).toBeUndefined()
  })
})

describe('absoluteStyle', () => {
  it('makes the relayed sprite and glyphs absolute', () => {
    const style = {
      version: 8 as const,
      sources: {},
      layers: [],
      sprite: '/api/v1/maps/proxy/openfreemap/sprites/ofm_f384/ofm',
      glyphs: '/api/v1/maps/proxy/openfreemap/fonts/{fontstack}/{range}.pbf',
    }
    expect(absoluteStyle(style, 'https://maps.example.org')).toMatchObject({
      sprite: 'https://maps.example.org/api/v1/maps/proxy/openfreemap/sprites/ofm_f384/ofm',
      glyphs: 'https://maps.example.org/api/v1/maps/proxy/openfreemap/fonts/{fontstack}/{range}.pbf',
    })
  })

  it('leaves provider URLs and sprite lists alone or fixes each', () => {
    const style = {
      version: 8 as const,
      sources: {},
      layers: [],
      sprite: [{ id: 'a', url: '/api/v1/maps/proxy/x/a' }, { id: 'b', url: 'https://cdn.example/b' }],
      glyphs: 'https://cdn.example/{fontstack}/{range}.pbf',
    }
    expect(absoluteStyle(style, 'https://maps.example.org')).toMatchObject({
      sprite: [{ id: 'a', url: 'https://maps.example.org/api/v1/maps/proxy/x/a' }, { id: 'b', url: 'https://cdn.example/b' }],
      glyphs: 'https://cdn.example/{fontstack}/{range}.pbf',
    })
  })
})
