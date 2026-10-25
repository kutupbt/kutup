// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'

vi.mock('../../crypto/src/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})

import { generateDeviceKeypair, encodePubKeyB64 } from './devices'
import { ed25519Sign, ed25519Verify } from './sign'

describe('devices', () => {
  it('generates a valid Ed25519 keypair', async () => {
    const kp = await generateDeviceKeypair()
    expect(kp.publicKey.length).toBe(32)
    expect(kp.privateKey.length).toBe(64)
    // The stored form: seed, then the public key.
    expect(kp.privateKey.subarray(32)).toEqual(kp.publicKey)
  })
  it('signs frames its public key verifies', async () => {
    const kp = await generateDeviceKeypair()
    const frame = new TextEncoder().encode('frame')
    const signature = await ed25519Sign(frame, kp.privateKey)
    expect(await ed25519Verify(frame, signature, kp.publicKey)).toBe(true)
    expect(await ed25519Verify(new TextEncoder().encode('other'), signature, kp.publicKey)).toBe(false)
  })
  it('encodes pubkey as base64', async () => {
    const kp = await generateDeviceKeypair()
    const b64 = encodePubKeyB64(kp.publicKey)
    expect(b64.length).toBeGreaterThan(40)
  })
})
