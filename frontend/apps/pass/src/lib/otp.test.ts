import { describe, expect, it } from 'vitest'
import { otpFieldValue } from './otp'

describe('otpFieldValue', () => {
  it('keeps otpauth URIs and turns base32 secrets into one', () => {
    expect(otpFieldValue('otpauth://totp/a?secret=ABC', 'x')).toBe('otpauth://totp/a?secret=ABC')
    expect(otpFieldValue('gezd gnbv gy3t qojq', 'Banka')).toBe('otpauth://totp/Banka?secret=GEZDGNBVGY3TQOJQ&period=30&digits=6&algorithm=SHA1')
    expect(otpFieldValue('', 'x')).toBe('')
  })

  it('refuses what is neither', () => {
    expect(otpFieldValue('not a secret!', 'x')).toBeNull()
    expect(otpFieldValue('ABC', 'x')).toBeNull()
  })
})
