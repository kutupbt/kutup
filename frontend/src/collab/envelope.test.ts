import { describe, it, expect } from 'vitest'
import { pack, unpack, KIND, type Frame } from './envelope'

const sigBytes = new Uint8Array(64)
for (let i = 0; i < 64; i++) sigBytes[i] = i
const nonce = new Uint8Array(24)
for (let i = 0; i < 24; i++) nonce[i] = i + 1

describe('envelope', () => {
  it('round-trips a Frame', () => {
    const original: Frame = {
      version: 1,
      kind: KIND.YJS_UPDATE,
      docKeyId: 42,
      senderDeviceId: 1234n,
      sequence: 1n,
      nonce,
      ciphertext: new TextEncoder().encode('hello world'),
      signature: sigBytes,
    }
    const bytes = pack(original)
    const out = unpack(bytes)
    expect(out.version).toBe(1)
    expect(out.kind).toBe(KIND.YJS_UPDATE)
    expect(out.docKeyId).toBe(42)
    expect(out.senderDeviceId).toBe(1234n)
    expect(out.sequence).toBe(1n)
    expect(Array.from(out.nonce)).toEqual(Array.from(nonce))
    expect(new TextDecoder().decode(out.ciphertext)).toBe('hello world')
    expect(Array.from(out.signature)).toEqual(Array.from(sigBytes))
  })

  it('rejects too-short input', () => {
    expect(() => unpack(new Uint8Array(5))).toThrow()
  })
})
