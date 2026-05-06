import { describe, it, expect } from 'vitest'
import {
  deriveKeyEncryptionKey,
  deriveLoginKey,
  generateKDFSalt,
} from './kdf'

// Argon2id with 64MB / 3 iterations / 4 threads is intentionally slow for
// password attack resistance. Each call is ~1-2s on a modern dev box, so
// keep this suite small and reuse derived keys where possible.

describe('kdf — Argon2id', () => {
  it('generateKDFSalt returns 16-byte salts (libsodium SALTBYTES)', async () => {
    const s = await generateKDFSalt()
    expect(s.length).toBe(16) // crypto_pwhash_SALTBYTES
  })

  it('returns different salts on each call', async () => {
    const a = await generateKDFSalt()
    const b = await generateKDFSalt()
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })

  it('deriveKeyEncryptionKey is deterministic for (password, salt)', async () => {
    const salt = await generateKDFSalt()
    const k1 = await deriveKeyEncryptionKey('my-test-password', salt)
    const k2 = await deriveKeyEncryptionKey('my-test-password', salt)
    expect(k1.length).toBe(32) // 256-bit
    expect(Array.from(k1)).toEqual(Array.from(k2))
  })

  it('different salts produce different keys for the same password', async () => {
    const sA = await generateKDFSalt()
    const sB = await generateKDFSalt()
    const kA = await deriveKeyEncryptionKey('shared-password', sA)
    const kB = await deriveKeyEncryptionKey('shared-password', sB)
    expect(Array.from(kA)).not.toEqual(Array.from(kB))
  })

  it('different passwords produce different keys for the same salt', async () => {
    const salt = await generateKDFSalt()
    const k1 = await deriveKeyEncryptionKey('password-one', salt)
    const k2 = await deriveKeyEncryptionKey('password-two', salt)
    expect(Array.from(k1)).not.toEqual(Array.from(k2))
  })

  it('deriveLoginKey produces a different key from deriveKeyEncryptionKey when called with different salts', async () => {
    // KDF is symmetric across the two functions (same Argon2id params); the
    // "domain separation" comes from supplying *different salts* to each call.
    // The login key and KEK MUST be derived from different salts so that
    // exposing the login key (sent to the server) doesn't leak the KEK.
    const kdfSalt = await generateKDFSalt()
    const loginSalt = await generateKDFSalt()
    const kek = await deriveKeyEncryptionKey('p', kdfSalt)
    const login = await deriveLoginKey('p', loginSalt)
    expect(Array.from(kek)).not.toEqual(Array.from(login))
  })

  it('deriveLoginKey is deterministic for (password, salt)', async () => {
    const salt = await generateKDFSalt()
    const a = await deriveLoginKey('login-password', salt)
    const b = await deriveLoginKey('login-password', salt)
    expect(a.length).toBe(32)
    expect(Array.from(a)).toEqual(Array.from(b))
  })
}, 120_000) // generous timeout — the suite does several Argon2id runs.
