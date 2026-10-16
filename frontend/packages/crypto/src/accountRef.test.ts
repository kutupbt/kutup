import { describe, expect, it } from 'vitest'
import crypto from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'
import { accountKeyOf, accountOfKey, isAccountKey } from './accountRef'

// The shared vectors Rust and WASM check (kutup-crypto account_ref).
const vectors = crypto.accountRef

describe('the account string form, checked synchronously', () => {
  it('takes exactly what Rust takes', () => {
    for (const valid of vectors.valid) {
      expect(isAccountKey(valid.string)).toBe(true)
      expect(accountOfKey(valid.string)).toEqual({ server: valid.server, accountId: valid.accountId })
      expect(accountKeyOf({ server: valid.server, accountId: valid.accountId })).toBe(valid.string)
    }
    for (const invalid of [...vectors.invalid, 'aci:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70@10.0.0.1', '']) {
      expect(isAccountKey(invalid)).toBe(false)
      expect(accountOfKey(invalid)).toBeNull()
    }
    // Leading zeros are not an IP address to Rust: a server name.
    expect(isAccountKey('aci:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70@01.2.3.4')).toBe(true)
    expect(() => accountKeyOf({ server: 'Kutup.dev', accountId: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70' })).toThrow()
  })
})
