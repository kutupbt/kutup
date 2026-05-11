// Unit tests for the chunk-by-chunk secretstream decryptor.
//
// Confidence we want:
//   1. Round-trip with the one-shot encryptStream() — proves the
//      decryptor consumes the same wire format the rest of kutup
//      produces.
//   2. Round-trip across the same boundary sizes streamEncryptor.test
//      uses — chunk-alignment is where AEAD code historically breaks.
//   3. Header-length guard rejects malformed inputs.
//   4. Out-of-order chunks raise the MAC error rather than silently
//      decrypting to garbage.
//
// Like streamEncryptor.test.ts, the bigger sizes are slow in jsdom +
// libsodium-wrappers-sumo (~10 s per 5 MB), so we cap round-trip
// sizes at PLAIN_CHUNK + 1 — multi-chunk correctness is implied by
// the per-chunk loop being a trivial pull-and-emit.

import { describe, it, expect } from 'vitest'
import { encryptStream } from './symmetric'
import { getSodium } from './sodium'
import { PLAIN_CHUNK, HEADER_BYTES, CIPHER_CHUNK } from './streamEncryptor'
import { newStreamDecryptor } from './streamDecryptor'

const ROUND_TRIP_SIZES = [
  0,
  1,
  1024,
  PLAIN_CHUNK - 1,
  PLAIN_CHUNK,
  PLAIN_CHUNK + 1,
] as const

const LIBSODIUM_TIMEOUT_MS = 60_000

async function genKey(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.crypto_secretstream_xchacha20poly1305_keygen()
}

// Split a `Uint8Array` produced by encryptStream() into the 24-byte
// header + a list of `CIPHER_CHUNK`-sized ciphertext chunks (last
// may be shorter). Mirrors what the streamDownload reader does on
// the wire.
function splitWire(blob: Uint8Array): { header: Uint8Array; chunks: Uint8Array[] } {
  const header = blob.subarray(0, HEADER_BYTES)
  const chunks: Uint8Array[] = []
  let off = HEADER_BYTES
  while (off < blob.length) {
    const end = Math.min(off + CIPHER_CHUNK, blob.length)
    chunks.push(blob.subarray(off, end))
    off = end
  }
  return { header, chunks }
}

describe('newStreamDecryptor', () => {
  it.each(ROUND_TRIP_SIZES)('round-trips %d-byte plaintext from encryptStream', async (n) => {
    const key = await genKey()
    const plain = new Uint8Array(n)
    for (let i = 0; i < n; i++) plain[i] = (i * 31 + 7) & 0xff

    const cipher = await encryptStream(plain, key)
    const { header, chunks } = splitWire(cipher)
    const dec = await newStreamDecryptor(key, header)

    // Empty plaintext: encryptStream emits ONLY the header — no
    // chunks. Decryptor is happy without any pull() call.
    if (chunks.length === 0) {
      expect(n).toBe(0)
      return
    }

    const recovered = new Uint8Array(n)
    let pos = 0
    let sawFinal = false
    for (let i = 0; i < chunks.length; i++) {
      const { plain: p, isFinal } = dec.pull(chunks[i])
      recovered.set(p, pos)
      pos += p.length
      if (isFinal) {
        sawFinal = true
        expect(i).toBe(chunks.length - 1)
      }
    }
    expect(sawFinal).toBe(true)
    expect(pos).toBe(n)
    expect(recovered).toEqual(plain)
  }, LIBSODIUM_TIMEOUT_MS)

  it('rejects a wrong-length header', async () => {
    const key = await genKey()
    await expect(newStreamDecryptor(key, new Uint8Array(8))).rejects.toThrow()
    await expect(newStreamDecryptor(key, new Uint8Array(25))).rejects.toThrow()
  })

  it('rejects tampered ciphertext (MAC fail)', async () => {
    const key = await genKey()
    const plain = new Uint8Array(64).fill(7)
    const cipher = await encryptStream(plain, key)
    const { header, chunks } = splitWire(cipher)
    // Flip one byte in the first chunk's body.
    const tampered = new Uint8Array(chunks[0])
    tampered[5] ^= 0xff
    const dec = await newStreamDecryptor(key, header)
    expect(() => dec.pull(tampered)).toThrow(/Stream decryption failed/)
  })

  it('rejects out-of-order chunks (MAC fail)', async () => {
    const key = await genKey()
    // 2-chunk file — swap them.
    const plain = new Uint8Array(PLAIN_CHUNK + 100)
    for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
    const cipher = await encryptStream(plain, key)
    const { header, chunks } = splitWire(cipher)
    expect(chunks.length).toBe(2)
    const dec = await newStreamDecryptor(key, header)
    // Pull the SECOND chunk first — nonce state mismatch → MAC fail.
    expect(() => dec.pull(chunks[1])).toThrow(/Stream decryption failed/)
  }, LIBSODIUM_TIMEOUT_MS)
})
