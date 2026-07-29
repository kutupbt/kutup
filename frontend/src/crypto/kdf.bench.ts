// @vitest-environment node
// Argon2id KDF benchmark — sets the perf floor for login + key wrap.
// Expect ~1-2 s/op with the current 64 MB / 3 iter / 1 lane params.
// If a regression drops this below ~250 ms it means the params got
// weakened — this bench is the canary.
import { bench, describe } from 'vitest'
import {
  ACCOUNT_PROTECTION_DEFAULTS,
  deriveAccountProtectionKeys,
  generateAccountProtectionSalt,
} from './kdf'
import { toBase64 } from './base64'

const config = {
  ...ACCOUNT_PROTECTION_DEFAULTS,
  salt: toBase64(generateAccountProtectionSalt()),
}

describe('Argon2id (64MB / 3 iter)', () => {
  bench('deriveAccountProtectionKeys', async () => {
    await deriveAccountProtectionKeys('benchmark-password-of-typical-length', config)
  }, { time: 8_000 })  // ≥8 s of samples — KDF is slow, want stable µ.
})
