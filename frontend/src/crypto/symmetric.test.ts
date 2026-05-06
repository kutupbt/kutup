import { describe, it, expect } from 'vitest'
import {
  encrypt,
  decrypt,
  encryptStream,
  decryptStream,
  generateKey,
} from './symmetric'

const enc = new TextEncoder()
const dec = new TextDecoder()

describe('symmetric — encrypt/decrypt (XSalsa20-Poly1305 / secretbox)', () => {
  it('round-trips an arbitrary payload', async () => {
    const key = await generateKey()
    const plaintext = enc.encode('hello kutup — utf-8 åéîøü 🔐')
    const { ciphertext, nonce } = await encrypt(plaintext, key)
    expect(ciphertext.length).toBe(plaintext.length + 16) // +Poly1305 tag
    expect(nonce.length).toBe(24) // crypto_secretbox_NONCEBYTES
    const out = await decrypt(ciphertext, nonce, key)
    expect(dec.decode(out)).toBe('hello kutup — utf-8 åéîøü 🔐')
  })

  it('round-trips empty bytes', async () => {
    const key = await generateKey()
    const { ciphertext, nonce } = await encrypt(new Uint8Array(0), key)
    const out = await decrypt(ciphertext, nonce, key)
    expect(out.length).toBe(0)
  })

  it('produces a fresh random nonce per encrypt', async () => {
    const key = await generateKey()
    const a = await encrypt(enc.encode('same'), key)
    const b = await encrypt(enc.encode('same'), key)
    // Different nonces → different ciphertexts even for identical plaintext.
    expect(Array.from(a.nonce)).not.toEqual(Array.from(b.nonce))
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext))
  })

  it('throws on wrong key', async () => {
    const k1 = await generateKey()
    const k2 = await generateKey()
    const { ciphertext, nonce } = await encrypt(enc.encode('secret'), k1)
    await expect(decrypt(ciphertext, nonce, k2)).rejects.toThrow()
  })

  it('throws on tampered ciphertext (auth tag verifies)', async () => {
    const key = await generateKey()
    const { ciphertext, nonce } = await encrypt(enc.encode('integrity'), key)
    ciphertext[0] ^= 0xff
    // Note: libsodium-js throws its own "wrong secret key for the given
    // ciphertext" before our wrapper's Error fires; either message is fine.
    await expect(decrypt(ciphertext, nonce, key)).rejects.toThrow()
  })

  it('throws on tampered nonce', async () => {
    const key = await generateKey()
    const { ciphertext, nonce } = await encrypt(enc.encode('integrity'), key)
    nonce[0] ^= 0xff
    // Note: libsodium-js throws its own "wrong secret key for the given
    // ciphertext" before our wrapper's Error fires; either message is fine.
    await expect(decrypt(ciphertext, nonce, key)).rejects.toThrow()
  })
})

describe('symmetric — encryptStream/decryptStream (XChaCha20-Poly1305 secretstream)', () => {
  it('round-trips a small payload (single chunk)', async () => {
    const key = await generateKey()
    const plaintext = enc.encode('a small file')
    const blob = await encryptStream(plaintext, key)
    // header (24) + chunk overhead (17) + plaintext
    expect(blob.length).toBe(24 + 17 + plaintext.length)
    const out = await decryptStream(blob, key)
    expect(dec.decode(out)).toBe('a small file')
  })

  it('round-trips a multi-chunk payload (>5 MB triggers split)', async () => {
    const key = await generateKey()
    // 5.5 MB — forces a chunk boundary.
    const size = 5 * 1024 * 1024 + 512 * 1024
    const plaintext = new Uint8Array(size)
    for (let i = 0; i < size; i++) plaintext[i] = (i * 31) & 0xff
    const blob = await encryptStream(plaintext, key)
    const out = await decryptStream(blob, key)
    expect(out.length).toBe(size)
    // Spot-check a few bytes rather than full equality (faster).
    expect(out[0]).toBe(plaintext[0])
    expect(out[size - 1]).toBe(plaintext[size - 1])
    expect(out[size / 2 | 0]).toBe(plaintext[size / 2 | 0])
  })

  it('round-trips empty bytes', async () => {
    const key = await generateKey()
    const blob = await encryptStream(new Uint8Array(0), key)
    const out = await decryptStream(blob, key)
    expect(out.length).toBe(0)
  })

  it('throws on wrong key', async () => {
    const k1 = await generateKey()
    const k2 = await generateKey()
    const blob = await encryptStream(enc.encode('hi'), k1)
    await expect(decryptStream(blob, k2)).rejects.toThrow()
  })

  it('throws on tampered chunk', async () => {
    const key = await generateKey()
    const blob = await encryptStream(enc.encode('payload-data'), key)
    // Flip a byte well past the header, in the encrypted-chunk region.
    blob[blob.length - 5] ^= 0xff
    await expect(decryptStream(blob, key)).rejects.toThrow()
  })
})

describe('symmetric — generateKey', () => {
  it('returns 32-byte (256-bit) keys', async () => {
    const k = await generateKey()
    expect(k.length).toBe(32) // crypto_secretbox_KEYBYTES
  })

  it('returns different keys on each call', async () => {
    const a = await generateKey()
    const b = await generateKey()
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })
})
