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

import { generateSigningKey } from '@kutup/crypto/signing'
import { ed25519Sign, ed25519Verify } from './sign'

describe('device frame keys', () => {
  it('generates a valid Ed25519 keypair', async () => {
    const kp = await generateSigningKey()
    expect(kp.publicKey.length).toBe(32)
    expect(kp.privateKey.length).toBe(64)
    // The stored form: seed, then the public key.
    expect(kp.privateKey.subarray(32)).toEqual(kp.publicKey)
  })
  it('signs frames its public key verifies', async () => {
    const kp = await generateSigningKey()
    const frame = new TextEncoder().encode('frame')
    const signature = await ed25519Sign(frame, kp.privateKey)
    expect(await ed25519Verify(frame, signature, kp.publicKey)).toBe(true)
    expect(await ed25519Verify(new TextEncoder().encode('other'), signature, kp.publicKey)).toBe(false)
  })
})
