import { describe, expect, it } from 'vitest'
import {
  ACCOUNT_PROTECTION_DEFAULTS,
  ACCOUNT_PROTECTION_SUITE_V1,
  generateAccountProtectionSalt,
} from './kdf'

describe('account-protection KDF browser adapter', () => {
  it('locks the V1 suite and complete Argon2id parameters', () => {
    expect(ACCOUNT_PROTECTION_DEFAULTS).toEqual({
      suite: ACCOUNT_PROTECTION_SUITE_V1,
      memoryKib: 65_536,
      iterations: 3,
      parallelism: 1,
    })
  })

  it('generates independent 16-byte salts', () => {
    const first = generateAccountProtectionSalt()
    const second = generateAccountProtectionSalt()
    expect(first).toHaveLength(16)
    expect(second).toHaveLength(16)
    expect(Array.from(first)).not.toEqual(Array.from(second))
  })
})
