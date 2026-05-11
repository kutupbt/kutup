import { describe, it, expect } from 'vitest'
import { normalizeServerUrl } from './serverConfig'

describe('normalizeServerUrl', () => {
  it('rejects empty / whitespace input', () => {
    expect(normalizeServerUrl('')).toEqual({ ok: false, error: 'empty' })
    expect(normalizeServerUrl('   ')).toEqual({ ok: false, error: 'empty' })
  })

  it('prepends https:// to bare hosts', () => {
    expect(normalizeServerUrl('kutup.example.com')).toEqual({
      ok: true,
      url: 'https://kutup.example.com',
    })
  })

  it('accepts https:// URLs unchanged (modulo trailing slash)', () => {
    expect(normalizeServerUrl('https://kutup.example.com')).toEqual({
      ok: true,
      url: 'https://kutup.example.com',
    })
    expect(normalizeServerUrl('https://kutup.example.com/')).toEqual({
      ok: true,
      url: 'https://kutup.example.com',
    })
    expect(normalizeServerUrl('https://kutup.example.com:8443')).toEqual({
      ok: true,
      url: 'https://kutup.example.com:8443',
    })
  })

  it('strips path / query / hash', () => {
    expect(
      normalizeServerUrl('https://kutup.example.com/some/path?q=1#h'),
    ).toEqual({ ok: true, url: 'https://kutup.example.com' })
  })

  it('refuses http:// on non-local hosts', () => {
    expect(normalizeServerUrl('http://kutup.example.com')).toEqual({
      ok: false,
      error: 'insecure-http',
    })
  })

  it('allows http:// on localhost / loopback / .local', () => {
    expect(normalizeServerUrl('http://localhost:38443')).toEqual({
      ok: true,
      url: 'http://localhost:38443',
    })
    expect(normalizeServerUrl('http://127.0.0.1:8080')).toEqual({
      ok: true,
      url: 'http://127.0.0.1:8080',
    })
    expect(normalizeServerUrl('http://kutup.local')).toEqual({
      ok: true,
      url: 'http://kutup.local',
    })
  })

  it('rejects malformed URLs', () => {
    expect(normalizeServerUrl('htp://not a url')).toEqual({
      ok: false,
      error: 'invalid',
    })
    expect(normalizeServerUrl('ftp://kutup.example.com')).toEqual({
      ok: false,
      error: 'invalid',
    })
  })

  it('trims whitespace before processing', () => {
    expect(normalizeServerUrl('   https://kutup.example.com   ')).toEqual({
      ok: true,
      url: 'https://kutup.example.com',
    })
  })
})
