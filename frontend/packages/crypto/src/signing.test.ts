// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { createHasher, hash, toHex } from './hash'
import { generateSigningKey, sign, verify } from './signing'

const bytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16))

describe('the suite streaming hash', () => {
  it('is the one-shot hash, however the input is cut', async () => {
    const data = new Uint8Array(100_000).map((_, i) => i % 251)
    const hasher = await createHasher()
    hasher.update(data.subarray(0, 1))
    hasher.update(data.subarray(1, 70_000))
    hasher.update(new Uint8Array())
    hasher.update(data.subarray(70_000))
    expect(toHex(hasher.digest())).toBe(toHex(await hash(data)))
    const abc = await createHasher()
    abc.update(new TextEncoder().encode('abc'))
    expect(toHex(abc.digest())).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})

describe('the suite signature', () => {
  it('matches RFC 8032 test 2 from a libsodium-form key', async () => {
    const seed = bytes('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
    const publicKey = bytes('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
    const message = bytes('72')
    const expected =
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
    const privateKey = new Uint8Array([...seed, ...publicKey])
    expect(toHex(await sign(message, privateKey))).toBe(expected)
    expect(toHex(await sign(message, seed))).toBe(expected)
    expect(await verify(message, bytes(expected), publicKey)).toBe(true)
    expect(await verify(bytes('73'), bytes(expected), publicKey)).toBe(false)
    // A private key whose public half isn't its seed's is refused.
    const wrong = new Uint8Array([...seed, ...new Uint8Array(32)])
    await expect(sign(message, wrong)).rejects.toThrow()
  })

  it('makes keys that sign and verify', async () => {
    const pair = await generateSigningKey()
    expect(pair.publicKey).toHaveLength(32)
    expect(pair.privateKey).toHaveLength(64)
    expect(pair.privateKey.subarray(32)).toEqual(pair.publicKey)
    const signature = await sign(new Uint8Array([1, 2, 3]), pair.privateKey)
    expect(await verify(new Uint8Array([1, 2, 3]), signature, pair.publicKey)).toBe(true)
    expect(toHex((await generateSigningKey()).publicKey)).not.toBe(toHex(pair.publicKey))
  })
})
