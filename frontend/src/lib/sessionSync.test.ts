import { describe, it, expect } from 'vitest'
import { sanitizeNext } from './sessionSync'

describe('sanitizeNext (open-redirect protection)', () => {
  it('passes through valid same-origin paths', () => {
    expect(sanitizeNext('/drive')).toBe('/drive')
    expect(sanitizeNext('/file/abc/def?x=1')).toBe('/file/abc/def?x=1')
  })

  it('rejects external URLs', () => {
    expect(sanitizeNext('https://evil.com/phish')).toBeNull()
    expect(sanitizeNext('http://evil.com')).toBeNull()
  })

  it('rejects protocol-relative URLs (the //evil.com bypass)', () => {
    // //evil.com would let the browser interpret this as a same-protocol
    // jump to evil.com. Rejecting "//" prefix is the canonical guard.
    expect(sanitizeNext('//evil.com/anything')).toBeNull()
  })

  it('rejects schemes like javascript: and data:', () => {
    expect(sanitizeNext('javascript:alert(1)')).toBeNull()
    expect(sanitizeNext('data:text/html,evil')).toBeNull()
  })

  it('rejects empty / null / undefined', () => {
    expect(sanitizeNext(null)).toBeNull()
    expect(sanitizeNext(undefined)).toBeNull()
    expect(sanitizeNext('')).toBeNull()
  })

  it('rejects non-leading-slash paths', () => {
    expect(sanitizeNext('drive')).toBeNull()
    expect(sanitizeNext('relative/path')).toBeNull()
  })
})
