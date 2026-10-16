import { describe, expect, it } from 'vitest'
import { mailAccountOf, NoAddressKey, type OwnAddressRow } from './api'

// As `kutup_crypto::names::fold_address` (whose vectors are Rust's): the
// local part without `.`, `_` and `-`, all lowercase.
const fold = (address: string) => {
  const at = address.lastIndexOf('@')
  return at > 0 ? `${address.slice(0, at).replace(/[._-]/g, '').toLowerCase()}@${address.slice(at + 1).toLowerCase()}` : null
}
const self = { server: 'kutup.test', accountId: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70' }
const session = {
  masterKey: new Uint8Array(32),
  privateKey: new Uint8Array(32),
  userId: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70',
  envelopeBinding: 'binding',
  username: 'ada.lovelace',
}
const key = (id: string, primary: boolean) => ({ fingerprint: `fp-${id}`, publicKey: `pk-${id}`, privateKeyEnvelope: `env-${id}`, primary })

// After a rename: the current address first, the old ones after (docs/api.md).
const rows: OwnAddressRow[] = [
  { id: 'a2', address: 'ada.lovelace@kutup.test', state: 'active', keys: [key('new', true), key('new-old', false)] },
  { id: 'a1', address: 'ada.l@kutup.test', state: 'receiving', keys: [key('old', true)] },
  { id: 'a0', address: 'ada@kutup.test', state: 'closed', keys: [key('first', true)] },
]

describe('the mail account after a rename', () => {
  it('sends from the current address, wherever the server lists it', () => {
    const account = mailAccountOf([rows[1], rows[0], rows[2]], null, session, fold, self)
    expect(account.address).toBe('ada.lovelace@kutup.test')
    expect(account.key).toMatchObject({ address: 'ada.lovelace@kutup.test', fingerprint: 'fp-new' })
    expect(account.publicKey).toBe('pk-new')
    expect(account.name).toBe('ada.lovelace')
  })

  it('keeps the earlier addresses keys, each sealed for its own address', () => {
    const account = mailAccountOf(rows, null, session, fold, self)
    expect(account.olderKeys.map((k) => [k.address, k.fingerprint])).toEqual([
      ['ada.lovelace@kutup.test', 'fp-new-old'],
      ['ada.l@kutup.test', 'fp-old'],
      ['ada@kutup.test', 'fp-first'],
    ])
    expect(account.ownPublicKeys).toEqual(['pk-new', 'pk-new-old', 'pk-old', 'pk-first'])
    expect(account.addresses).toEqual(['ada.lovelace@kutup.test', 'ada.l@kutup.test', 'ada@kutup.test'])
  })

  it('knows its own addresses in any spelling, and no one else', () => {
    const account = mailAccountOf(rows, null, session, fold, self)
    for (const own of ['ada.lovelace@kutup.test', 'Ada_Lovelace@Kutup.Test', 'ADA-L@kutup.test', 'ada@kutup.test', 'a.d.a@kutup.test']) {
      expect(account.isOwnAddress(own)).toBe(true)
    }
    for (const other of ['ada@elsewhere.test', 'adal2@kutup.test', 'grace@kutup.test', '', null, undefined, 'not an address']) {
      expect(account.isOwnAddress(other)).toBe(false)
    }
  })

  it('has no account without a current address and its primary key', () => {
    expect(() => mailAccountOf(rows.slice(1), null, session, fold, self)).toThrow(NoAddressKey)
    expect(() => mailAccountOf([{ ...rows[0], keys: [] }], null, session, fold, self)).toThrow(NoAddressKey)
  })
  it('keeps a freed name\'s keys for its old mail, never as its own', () => {
    // ada@ was freed and may be Bob's now.
    const freed: OwnAddressRow[] = [rows[0], rows[1], { ...rows[2], state: 'freed' }]
    const account = mailAccountOf(freed, null, session, fold, self)
    expect(account.olderKeys.map((k) => k.fingerprint)).toContain('fp-first')
    expect(account.isOwnAddress('ada@kutup.test')).toBe(false)
    expect(account.ownPublicKeys).not.toContain('pk-first')
    expect(account.addresses).toEqual(['ada.lovelace@kutup.test', 'ada.l@kutup.test'])
    expect(account.isOwnAddress('ada.l@kutup.test')).toBe(true)
  })
})
