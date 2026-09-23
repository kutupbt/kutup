import { describe, it, expect } from 'vitest'
import { generateDeviceKeypair, encodePubKeyB64 } from './devices'

describe('devices', () => {
  it('generates a valid Ed25519 keypair', async () => {
    const kp = await generateDeviceKeypair()
    expect(kp.publicKey.length).toBe(32)
    expect(kp.privateKey.length).toBe(64)
  })
  it('encodes pubkey as base64', async () => {
    const kp = await generateDeviceKeypair()
    const b64 = encodePubKeyB64(kp.publicKey)
    expect(b64.length).toBeGreaterThan(40)
  })
})
