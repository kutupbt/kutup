// @vitest-environment node
// Argon2id KDF benchmark — sets the perf floor for login + key wrap.
// Expect ~1-2 s/op with the current 64 MB / 3 iter / 4 thread params.
// If a regression drops this below ~250 ms it means the params got
// weakened — this bench is the canary.
import { bench, describe } from 'vitest'
import { deriveKeyEncryptionKey, generateKDFSalt } from './kdf'

const salt = await generateKDFSalt()

describe('Argon2id (64MB / 3 iter)', () => {
  bench('deriveKeyEncryptionKey', async () => {
    await deriveKeyEncryptionKey('benchmark-password-of-typical-length', salt)
  }, { time: 8_000 })  // ≥8 s of samples — KDF is slow, want stable µ.
})
