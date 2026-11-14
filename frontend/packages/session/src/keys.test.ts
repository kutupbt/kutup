import { describe, expect, it } from 'vitest'
import { decodeKeys, encodeKeys, type SessionKeys } from './keys'
import { testRoots } from '@kutup/crypto/accountRoots.testing'

const base: SessionKeys = {
  userId: 'u1',
  masterKey: new Uint8Array(32).fill(1),
  roots: testRoots(1),
  privateKey: new Uint8Array(32).fill(2),
  publicKey: 'p',
  keyBinding: '0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90',
}
const device = {
  id: 7,
  publicKey: new Uint8Array(32).fill(3),
  privateKey: new Uint8Array(64).fill(4),
  credential: new Uint8Array(32).fill(5),
  manifestSequence: 12n,
}

describe('session keys', () => {
  it('keep the sign-in’s collaboration device with them', () => {
    const decoded = decodeKeys(encodeKeys({ ...base, device }))
    expect(decoded.device).toEqual(device)
    expect(decodeKeys(encodeKeys(base)).device).toBeUndefined()
  })

  it('keep the account’s roots with them', () => {
    expect(decodeKeys(encodeKeys(base)).roots).toEqual(base.roots)
  })

  it('refuse a form from before the roots (sign in again)', () => {
    const encoded = JSON.parse(new TextDecoder().decode(encodeKeys(base))) as Record<string, unknown>
    for (const old of [
      { ...encoded, v: 4, roots: undefined },
      { ...encoded, v: 2, roots: undefined },
      { ...encoded, roots: undefined },
      { ...encoded, roots: { ...base.roots, identityRoot: btoa('short') } },
      { ...encoded, roots: { ...base.roots, identityGeneration: 0 } },
    ]) {
      expect(() => decodeKeys(new TextEncoder().encode(JSON.stringify(old)))).toThrow()
    }
  })

  it('refuse a malformed device', () => {
    const encoded = JSON.parse(new TextDecoder().decode(encodeKeys({ ...base, device })))
    for (const bad of [
      { ...encoded.device, id: 0 },
      { ...encoded.device, privateKey: btoa('short') },
      { ...encoded.device, id: 128 },
      { ...encoded.device, credential: btoa('short') },
      { ...encoded.device, credential: undefined },
      { ...encoded.device, manifestSequence: '012' },
      { ...encoded.device, manifestSequence: 12 },
      { ...encoded.device, manifestSequence: '18446744073709551616' },
    ]) {
      const bytes = new TextEncoder().encode(JSON.stringify({ ...encoded, device: bad }))
      expect(() => decodeKeys(bytes)).toThrow()
    }
  })
})
