import { describe, expect, it } from 'vitest'
import { fromBase64, toBase64 } from './base64'

describe('base64', () => {
  it('round-trips small inputs', () => {
    expect(toBase64(new Uint8Array([]))).toBe('')
    expect(toBase64(new TextEncoder().encode('kutup'))).toBe('a3V0dXA=')
    expect(new TextDecoder().decode(fromBase64('a3V0dXA='))).toBe('kutup')
  })

  it('encodes inputs far larger than one call can take (a large thumbnail)', () => {
    const bytes = new Uint8Array(1024 * 1024 + 7)
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + 7) & 0xff
    const encoded = toBase64(bytes)
    expect(encoded.length).toBe(Math.ceil(bytes.length / 3) * 4)
    // Compared as one buffer: a deep compare of a million elements is slow.
    expect(Buffer.from(fromBase64(encoded)).equals(Buffer.from(bytes))).toBe(true)
  })
})
