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
