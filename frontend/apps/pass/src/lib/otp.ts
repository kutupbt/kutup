// KeePassXC keeps an entry's TOTP secret in its `otp` field as an
// otpauth:// URI. People paste either that or a bare base32 secret.

const BASE32 = /^[A-Z2-7]+=*$/

/** The `otp` field value for what was pasted; `null` when it is neither form. */
export function otpFieldValue(input: string, label: string): string | null {
  const value = input.trim()
  if (!value) return ''
  if (/^otpauth:\/\/totp\//i.test(value)) return value
  const secret = value.replace(/[\s-]/g, '').toUpperCase()
  if (!BASE32.test(secret) || secret.replace(/=+$/, '').length < 16) return null
  const name = encodeURIComponent(label || 'Kutup Pass')
  return `otpauth://totp/${name}?secret=${secret.replace(/=+$/, '')}&period=30&digits=6&algorithm=SHA1`
}

export type OtpDigits = 6 | 7 | 8 | 'steam'
export type OtpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512'

/** What the setup form edits (KeePassXC's TOTP setup). */
export interface OtpForm {
  secret: string
  digits: OtpDigits
  period: number
  algorithm: OtpAlgorithm
}

export const DEFAULT_OTP_FORM: OtpForm = { secret: '', digits: 6, period: 30, algorithm: 'SHA1' }

/** The form's values from an `otp` field (a URI or a bare secret), the defaults for what it doesn't say. */
export function otpFormOf(value: string): OtpForm {
  const trimmed = value.trim()
  if (!/^otpauth:\/\/totp\//i.test(trimmed)) return { ...DEFAULT_OTP_FORM, secret: trimmed.replace(/[\s-]/g, '').toUpperCase() }
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return DEFAULT_OTP_FORM
  }
  const q = url.searchParams
  const steam = (q.get('encoder') ?? '').toLowerCase() === 'steam'
  const digits = Number(q.get('digits') ?? 6)
  const algorithm = (q.get('algorithm') ?? 'SHA1').toUpperCase()
  return {
    secret: (q.get('secret') ?? '').toUpperCase(),
    digits: steam ? 'steam' : digits === 7 || digits === 8 ? digits : 6,
    period: Math.min(300, Math.max(15, Number(q.get('period') ?? 30) || 30)),
    algorithm: algorithm === 'SHA256' || algorithm === 'SHA512' ? algorithm : 'SHA1',
  }
}

/**
 * The `otp` field for the form: an otpauth:// URI as KeePassXC writes it
 * (`encoder=steam` and five digits for Steam Guard); `null` for a secret
 * that isn't base32.
 */
export function otpUriOf(form: OtpForm, title: string, userName: string): string | null {
  const secret = form.secret.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '')
  if (!BASE32.test(secret) || secret.length < 16) return null
  const label = encodeURIComponent(title || 'Kutup Pass') + (userName ? `:${encodeURIComponent(userName)}` : '')
  const steam = form.digits === 'steam'
  const params = new URLSearchParams({
    secret,
    period: String(steam ? 30 : form.period),
    digits: String(steam ? 5 : form.digits),
    algorithm: steam ? 'SHA1' : form.algorithm,
  })
  if (title) params.set('issuer', title)
  if (steam) params.set('encoder', 'steam')
  return `otpauth://totp/${label}?${params.toString()}`
}
