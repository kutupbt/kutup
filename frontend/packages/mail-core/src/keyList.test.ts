import { describe, expect, it } from 'vitest'
import { MAIL_KEY_FLAGS } from '@kutup/crypto'
import { encryptionOff, listEntries, withEncryptionOff } from './keyList'

const key = (fingerprint: string, flags: number, extra: { primary?: boolean; forwarding?: boolean } = {}) => ({
  fingerprint,
  sha256Fingerprint: fingerprint.repeat(2),
  primary: extra.primary ?? false,
  flags,
  forwarding: extra.forwarding,
})
const both = MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete

describe('key lists and forwarding (docs/plans/mail-forwarding.md)', () => {
  it('never lists a forwarding key', () => {
    const address = { keys: [key('aa', both, { primary: true }), key('bb', both, { forwarding: true })] }
    expect(listEntries(address).map((entry) => entry.fingerprint)).toEqual(['aa'])
  })

  it('reads encryption as off while any listed key says not to encrypt', () => {
    expect(encryptionOff({ keys: [key('aa', both, { primary: true })] })).toBe(false)
    expect(encryptionOff({ keys: [key('aa', both | MAIL_KEY_FLAGS.emailNoEncrypt, { primary: true })] })).toBe(true)
    // A forwarding key's flags say nothing about the address.
    expect(encryptionOff({ keys: [key('aa', both, { primary: true }), key('bb', MAIL_KEY_FLAGS.emailNoEncrypt, { forwarding: true })] })).toBe(false)
  })

  it('sets and clears the flag on every key, the rest unchanged', () => {
    const entries = listEntries({ keys: [key('aa', both, { primary: true }), key('cc', MAIL_KEY_FLAGS.notCompromised)] })
    const off = withEncryptionOff(entries, true)
    expect(off.every((entry) => entry.flags & MAIL_KEY_FLAGS.emailNoEncrypt)).toBe(true)
    expect(off[1].flags & MAIL_KEY_FLAGS.notObsolete).toBe(0)
    expect(withEncryptionOff(off, false)).toEqual(entries)
  })
})
