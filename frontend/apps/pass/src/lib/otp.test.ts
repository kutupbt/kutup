import { describe, expect, it } from 'vitest'
import { otpFieldValue, otpFormOf, otpUriOf } from './otp'

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

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'

describe('one-time code settings', () => {
  it('writes KeePassXC URIs, Steam with its encoder and five digits', () => {
    const uri = otpUriOf({ secret: SECRET.toLowerCase(), digits: 8, period: 60, algorithm: 'SHA256' }, 'Banka', 'ayşe')!
    const url = new URL(uri)
    expect(uri.startsWith('otpauth://totp/Banka:ay%C5%9Fe?')).toBe(true)
    expect(Object.fromEntries(url.searchParams)).toEqual({ secret: SECRET, period: '60', digits: '8', algorithm: 'SHA256', issuer: 'Banka' })
    const steam = new URL(otpUriOf({ secret: SECRET, digits: 'steam', period: 60, algorithm: 'SHA512' }, 'Steam', '')!)
    expect(steam.searchParams.get('encoder')).toBe('steam')
    expect(steam.searchParams.get('digits')).toBe('5')
    expect(steam.searchParams.get('period')).toBe('30')
    expect(otpUriOf({ secret: 'not!base32', digits: 6, period: 30, algorithm: 'SHA1' }, 'x', '')).toBeNull()
  })

  it('reads the form back from a URI or a bare secret', () => {
    const uri = otpUriOf({ secret: SECRET, digits: 7, period: 45, algorithm: 'SHA512' }, 'A', '')!
    expect(otpFormOf(uri)).toEqual({ secret: SECRET, digits: 7, period: 45, algorithm: 'SHA512' })
    expect(otpFormOf('otpauth://totp/x?secret=ABC&encoder=steam&digits=5').digits).toBe('steam')
    expect(otpFormOf('jbsw y3dp')).toMatchObject({ secret: 'JBSWY3DP', digits: 6, period: 30 })
    expect(otpFieldValue(SECRET, 'A')).toContain('secret=' + SECRET)
  })
})
