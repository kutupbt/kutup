// @vitest-environment node
// jsdom mangles the Uint8Array typing libsodium's secretstream expects.
import { describe, it, expect, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../public/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../public/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})
import { encryptStream, decryptStream, generateKey } from './symmetric'

const enc = new TextEncoder()
const dec = new TextDecoder()

describe('symmetric — encryptStream/decryptStream (XChaCha20-Poly1305 secretstream)', () => {
  const context = {
    fileId: '11111111-1111-4111-8111-111111111111',
    collectionId: '22222222-2222-4222-8222-222222222222',
    epoch: 1,
  }

  it('round-trips a small payload (single chunk)', async () => {
    const key = await generateKey()
    const plaintext = enc.encode('a small file')
    const blob = await encryptStream(plaintext, key, context)
    // Drive header (48) + secretstream header (24) + frame overhead (17).
    expect(blob.length).toBe(48 + 24 + 17 + plaintext.length)
    const out = await decryptStream(blob, key, context)
    expect(dec.decode(out)).toBe('a small file')
  })

  it('round-trips a multi-chunk payload (>5 MB triggers split)', async () => {
    const key = await generateKey()
    // 5.5 MB — forces a chunk boundary.
    const size = 5 * 1024 * 1024 + 512 * 1024
    const plaintext = new Uint8Array(size)
    for (let i = 0; i < size; i++) plaintext[i] = (i * 31) & 0xff
    const blob = await encryptStream(plaintext, key, context)
    const out = await decryptStream(blob, key, context)
    expect(out.length).toBe(size)
    // Spot-check a few bytes rather than full equality (faster).
    expect(out[0]).toBe(plaintext[0])
    expect(out[size - 1]).toBe(plaintext[size - 1])
    expect(out[size / 2 | 0]).toBe(plaintext[size / 2 | 0])
  })

  it('round-trips empty bytes', async () => {
    const key = await generateKey()
    const blob = await encryptStream(new Uint8Array(0), key, context)
    expect(blob.length).toBe(48 + 24 + 17)
    const out = await decryptStream(blob, key, context)
    expect(out.length).toBe(0)
  })

  it('throws on wrong key', async () => {
    const k1 = await generateKey()
    const k2 = await generateKey()
    const blob = await encryptStream(enc.encode('hi'), k1, context)
    await expect(decryptStream(blob, k2, context)).rejects.toThrow()
  })

  it('throws on tampered chunk', async () => {
    const key = await generateKey()
    const blob = await encryptStream(enc.encode('payload-data'), key, context)
    // Flip a byte well past the header, in the encrypted-chunk region.
    blob[blob.length - 5] ^= 0xff
    await expect(decryptStream(blob, key, context)).rejects.toThrow()
  })

  it('rejects relocation to another file, collection, or epoch', async () => {
    const key = await generateKey()
    const blob = await encryptStream(enc.encode('bound payload'), key, context)
    await expect(decryptStream(blob, key, {
      ...context,
      fileId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(decryptStream(blob, key, {
      ...context,
      collectionId: '44444444-4444-4444-8444-444444444444',
    })).rejects.toThrow()
    await expect(decryptStream(blob, key, { ...context, epoch: 2 })).rejects.toThrow()
  })
})

describe('symmetric — generateKey', () => {
  it('returns 32-byte (256-bit) keys', async () => {
    const k = await generateKey()
    expect(k.length).toBe(32)
  })

  it('returns different keys on each call', async () => {
    const a = await generateKey()
    const b = await generateKey()
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })
})
