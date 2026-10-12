import { describe, expect, it } from 'vitest'
import { isOneTimeCodeSubject, oneTimeCode } from './oneTimeCode'

const now = Date.parse('2026-10-12T10:00:00Z')
const at = now - 60_000

describe('one-time codes', () => {
  it('knows code subjects, not promotions', () => {
    expect(isOneTimeCodeSubject('Your verification code')).toBe(true)
    expect(isOneTimeCodeSubject('Doğrulama kodunuz')).toBe(true)
    expect(isOneTimeCodeSubject('Kutup giriş kodu: 482913')).toBe(true)
    expect(isOneTimeCodeSubject('2-step verification')).toBe(true)
    expect(isOneTimeCodeSubject('Use code SAVE20 for 20% off')).toBe(false)
    expect(isOneTimeCodeSubject('Meeting notes')).toBe(false)
  })

  it('finds the code after "code:" or alone on its line', () => {
    expect(oneTimeCode({ subject: 'Your verification code', text: 'Hello,\nYour code is: 482913\nIt expires in 10 minutes.', at, now })).toBe('482913')
    expect(oneTimeCode({ subject: 'Doğrulama kodunuz', text: 'Merhaba,\n\n  730 215  \n\nBu kodu kimseyle paylaşmayın.', at, now })).toBe('730215')
    expect(oneTimeCode({ subject: 'Sign-in code', text: 'Enter this code:\nK7Q2ZP\n', at, now })).toBe('K7Q2ZP')
  })

  it('reads the subject alone, for the list', () => {
    expect(oneTimeCode({ subject: 'Kutup giriş kodu: 482913', at, now })).toBe('482913')
    expect(oneTimeCode({ subject: '482913 is your login code', at, now })).toBe('482913')
  })

  it('leaves out old mail, the send date and unclear cases', () => {
    expect(oneTimeCode({ subject: 'Kutup giriş kodu: 482913', at: now - 30 * 60_000, now })).toBeNull()
    expect(oneTimeCode({ subject: 'Your verification code', text: 'Sent 20261012.\nOrder 2026.', at, now })).toBeNull()
    expect(oneTimeCode({ subject: 'Your verification code', text: 'Pick 111111 or 222222.', at, now })).toBeNull()
    expect(oneTimeCode({ subject: 'Weekly report', text: 'code: 482913', at, now })).toBeNull()
  })
})
