import { describe, expect, it } from 'vitest'
import { decodeKeys, encodeKeys, type SessionKeys } from './keys'

const base: SessionKeys = {
  userId: 'u1',
  masterKey: new Uint8Array(32).fill(1),
  privateKey: new Uint8Array(32).fill(2),
  publicKey: 'p',
  keyBinding: '0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90',
}
const device = {
  id: 7,
  publicKey: new Uint8Array(32).fill(3),
  privateKey: new Uint8Array(64).fill(4),
  issuedAtMs: 1_791_000_000_000,
}

describe('session keys', () => {
  it('keep the sign-in’s collaboration device with them', () => {
    const decoded = decodeKeys(encodeKeys({ ...base, device }))
    expect(decoded.device).toEqual(device)
    expect(decodeKeys(encodeKeys(base)).device).toBeUndefined()
  })

  it('still read the form without a device', () => {
    const v2 = new TextEncoder().encode(
      JSON.stringify({
        v: 2,
        userId: 'u1',
        masterKey: btoa(String.fromCharCode(...base.masterKey)),
        privateKey: btoa(String.fromCharCode(...base.privateKey)),
        publicKey: 'p',
        keyBinding: base.keyBinding,
      }),
    )
    expect(decodeKeys(v2).device).toBeUndefined()
  })

  it('refuse a malformed device', () => {
    const encoded = JSON.parse(new TextDecoder().decode(encodeKeys({ ...base, device })))
    for (const bad of [
      { ...encoded.device, id: 0 },
      { ...encoded.device, privateKey: btoa('short') },
      { ...encoded.device, issuedAtMs: 'soon' },
    ]) {
      const bytes = new TextEncoder().encode(JSON.stringify({ ...encoded, device: bad }))
      expect(() => decodeKeys(bytes)).toThrow()
    }
  })
})
