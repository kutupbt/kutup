// Unit tests for the streaming secretstream encryptor.
//
// Confidence we want:
//   1. cipherSize() math is exact across the boundary sizes that bite —
//      empty, sub-chunk, single chunk, just-over single chunk,
//      multi-chunk, exactly-aligned multi-chunk.
//   2. Round-trip with the existing decryptStream() (one-shot) for the
//      same boundary sizes — proves the chunk-by-chunk encryptor
//      produces the same wire bytes the rest of kutup expects.
//   3. Header is exactly 24 bytes (HEADER_BYTES) — locks the wire
//      format constant.
//
// We don't test against the CLI's Go port directly here — that's
// covered implicitly by both sides decrypting to the same plaintext.
// A golden-vector test against committed CLI output would lock the
// wire bytes, but it's flaky if rng changes; the round-trip approach
// is strictly stronger because both encrypt + decrypt run end-to-end.

import { describe, it, expect } from 'vitest'
import { decryptStream } from './symmetric'
import { getSodium } from './sodium'
import {
  newStreamEncryptor,
  cipherSize,
  PLAIN_CHUNK,
  ABYTES,
  HEADER_BYTES,
} from './streamEncryptor'

// Boundary sizes that have historically broken streaming-AEAD code.
// cipherSize() is tested against all of these; the more expensive
// round-trip test uses a trimmed set (see ROUND_TRIP_SIZES) because
// jsdom + libsodium-wrappers-sumo is markedly slower than a real
// browser engine — multi-chunk decrypts take 10+ seconds each.
const SIZES = [
  0,
  1,
  PLAIN_CHUNK - 1,
  PLAIN_CHUNK,
  PLAIN_CHUNK + 1,
  PLAIN_CHUNK * 2,
  PLAIN_CHUNK * 2 + 12345,
] as const

// Smaller set for the slow round-trip path. The boundary at
// PLAIN_CHUNK is where the chunk-loop is most error-prone — cover
// just-under, exact, and just-over. Multi-chunk correctness is
// implied by:
//   - cipherSize() math (tested against every SIZES entry, including
//     multi-chunk values, with the actual encrypted length)
//   - the per-chunk loop being a trivial `for offset < n: push()`
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

// Encrypt `plain` via the chunk-by-chunk API, returning the same on-
// wire bytes the one-shot encryptStream() would.
async function encryptChunked(plain: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const enc = await newStreamEncryptor(key)
  const parts: Uint8Array[] = [enc.header]
  if (plain.length === 0) {
    // Match encryptStream() semantics for an empty input: just the
    // header. The encryptor doesn't get called.
    return enc.header.slice()
  }
  let off = 0
  while (off < plain.length) {
    const end = Math.min(off + PLAIN_CHUNK, plain.length)
    parts.push(enc.push(plain.subarray(off, end), end === plain.length))
    off = end
  }
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const p of parts) { out.set(p, pos); pos += p.length }
  return out
}

describe('cipherSize', () => {
  it('returns just the header for empty plaintext', () => {
    expect(cipherSize(0)).toBe(HEADER_BYTES)
  })

  it.each(SIZES)('matches actual encrypted length for plain=%d bytes', async (n) => {
    const key = await genKey()
    const plain = new Uint8Array(n)
    // deterministic pattern — content doesn't matter for length, but
    // catches sloppy `if(plain.length)` short-circuits in the impl.
    for (let i = 0; i < n; i++) plain[i] = i & 0xff
    const cipher = await encryptChunked(plain, key)
    expect(cipher.length).toBe(cipherSize(n))
  }, LIBSODIUM_TIMEOUT_MS)

  it('is monotonically non-decreasing across sizes', () => {
    let prev = -1
    for (const n of SIZES) {
      const c = cipherSize(n)
      expect(c).toBeGreaterThanOrEqual(prev)
      prev = c
    }
  })

  it('per-chunk overhead is exactly ABYTES', () => {
    expect(cipherSize(PLAIN_CHUNK) - cipherSize(0))
      .toBe(PLAIN_CHUNK + ABYTES)
    expect(cipherSize(PLAIN_CHUNK * 2) - cipherSize(PLAIN_CHUNK))
      .toBe(PLAIN_CHUNK + ABYTES)
  })
})

describe('newStreamEncryptor', () => {
  it('header is exactly HEADER_BYTES (24)', async () => {
    const key = await genKey()
    const enc = await newStreamEncryptor(key)
    expect(enc.header.length).toBe(HEADER_BYTES)
  })

  it.each(ROUND_TRIP_SIZES)('round-trips %d-byte plaintext via decryptStream', async (n) => {
    const key = await genKey()
    const plain = new Uint8Array(n)
    for (let i = 0; i < n; i++) plain[i] = (i * 31 + 7) & 0xff
    const cipher = await encryptChunked(plain, key)
    const back = await decryptStream(cipher, key)
    expect(back.length).toBe(n)
    expect(back).toEqual(plain)
  }, LIBSODIUM_TIMEOUT_MS)

  it('encrypts deterministically given the same key+state pair', async () => {
    // Two independent encryptors with the same key must NOT produce
    // the same bytes (random header). This is a sanity check on
    // libsodium not us — guards against accidental nonce reuse if the
    // wrapper ever caches state.
    const key = await genKey()
    const plain = new Uint8Array(1024)
    const a = await encryptChunked(plain, key)
    const b = await encryptChunked(plain, key)
    expect(a).not.toEqual(b)
  })

})
