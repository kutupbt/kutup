import { describe, expect, it } from 'vitest'
import { asSender, mailAccountOf, NoAddressKey, UnverifiedOwnKeys, type CheckedOwnAddress } from './api'

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
// A key row as `checkedAddresses` leaves it: `listed` when its public key
// has the fingerprints the signed list names.
const key = (id: string, primary: boolean, listed = true) => ({
  fingerprint: `fp-${id}`,
  sha256Fingerprint: `sha-${id}`,
  publicKey: `pk-${id}`,
  privateKeyEnvelope: `env-${id}`,
  primary,
  flags: 3,
  listed,
})
/** The row's signed list: its listed keys, as the server rows say (tests change one side). */
const withList = (row: Omit<CheckedOwnAddress, 'verifiedList' | 'keyList'>): CheckedOwnAddress => ({
  ...row,
  keyList: { data: 'data', signature: 'signature' },
  verifiedList: {
    address: row.address,
    sequence: 1,
    issuedAt: '2026-10-20T00:00:00Z',
    keys: row.keys.filter((k) => k.listed).map(({ fingerprint, sha256Fingerprint, primary, flags }) => ({ fingerprint, sha256Fingerprint, primary, flags })),
    data: 'data',
    signature: 'signature',
    hash: 'hash',
  },
})

// After a rename: the current address first, the old ones after (docs/api.md).
const rows: CheckedOwnAddress[] = [
  withList({ id: 'a2', address: 'ada.lovelace@kutup.test', state: 'active', domainId: null, position: 0, disabled: false, keys: [key('new', true), key('new-old', false)] }),
  withList({ id: 'a1', address: 'ada.l@kutup.test', state: 'receiving', domainId: null, position: 0, disabled: false, keys: [key('old', true)] }),
  withList({ id: 'a0', address: 'ada@kutup.test', state: 'closed', domainId: null, position: 0, disabled: false, keys: [key('first', true)] }),
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
    expect(() => mailAccountOf([{ ...rows[0], keys: [], keyList: null, verifiedList: null }], null, session, fold, self)).toThrow(NoAddressKey)
    // A signed list whose key rows the server no longer lists: keys lost, not "none yet".
    expect(() => mailAccountOf([{ ...rows[0], keys: [] }], null, session, fold, self)).toThrow(UnverifiedOwnKeys)
  })

  it('takes a signed primary only when it is usable, and drops compromised keys from its own signers', () => {
    const flagged = (flags: Record<string, number>): CheckedOwnAddress => ({
      ...rows[0],
      verifiedList: { ...rows[0].verifiedList!, keys: rows[0].verifiedList!.keys.map((k) => ({ ...k, flags: flags[k.fingerprint] ?? k.flags })) },
    })
    // The signed primary marked obsolete or compromised: no account.
    expect(() => mailAccountOf([flagged({ 'fp-new': 1 })], null, session, fold, self)).toThrow(UnverifiedOwnKeys)
    expect(() => mailAccountOf([flagged({ 'fp-new': 2 })], null, session, fold, self)).toThrow(UnverifiedOwnKeys)
    // Another key marked compromised still opens old mail, but vouches for nothing.
    const account = mailAccountOf([flagged({ 'fp-new-old': 0 }), rows[1]], null, session, fold, self)
    expect(account.ownPublicKeys).toEqual(['pk-new', 'pk-old'])
    expect(account.olderKeys.map((k) => k.fingerprint)).toContain('fp-new-old')
  })
  it('seals drafts and Sent only to the primary the signed list names, never a key the server swapped in', () => {
    // The server marks a key of its own primary on the current address.
    const swapped: CheckedOwnAddress = {
      ...rows[0],
      keys: [{ ...key('server', true, false) }, { ...key('new', false) }, key('new-old', false)],
    }
    const account = mailAccountOf([swapped, rows[1], rows[2]], null, session, fold, self)
    expect(account.publicKey).toBe('pk-new')
    expect(account.key.fingerprint).toBe('fp-new')
    expect(account.ownPublicKeys).not.toContain('pk-server')
    // The signed primary's row carries another public key (unlisted): no account.
    const replaced: CheckedOwnAddress = { ...rows[0], keys: [{ ...key('new', true), listed: false }, key('new-old', false)] }
    expect(() => mailAccountOf([replaced], null, session, fold, self)).toThrow(UnverifiedOwnKeys)
    // No list this account signed: no account either.
    expect(() => mailAccountOf([{ ...rows[0], verifiedList: null }], null, session, fold, self)).toThrow(UnverifiedOwnKeys)
  })

  it('keeps a freed name\'s keys for its old mail, never as its own', () => {
    // ada@ was freed and may be Bob's now.
    const freed: CheckedOwnAddress[] = [rows[0], rows[1], { ...rows[2], state: 'freed' }]
    const account = mailAccountOf(freed, null, session, fold, self)
    expect(account.olderKeys.map((k) => k.fingerprint)).toContain('fp-first')
    expect(account.isOwnAddress('ada@kutup.test')).toBe(false)
    expect(account.ownPublicKeys).not.toContain('pk-first')
    expect(account.addresses).toEqual(['ada.lovelace@kutup.test', 'ada.l@kutup.test'])
    expect(account.isOwnAddress('ada.l@kutup.test')).toBe(true)
  })
})

describe('the account\'s addresses (Proton\'s Identity and addresses)', () => {
  const own = withList({ id: 'own', address: 'ada@kutup.test', state: 'active', domainId: null, position: 1, disabled: false, keys: [key('own', true)] })
  const work = withList({ id: 'work', address: 'ada@work.test', state: 'active', domainId: 'd1', position: 0, disabled: false, keys: [key('work', true)] })
  const old = withList({ id: 'old', address: 'old@work.test', state: 'active', domainId: 'd1', position: 2, disabled: true, keys: [key('old', true)] })
  const bare = withList({ id: 'bare', address: 'new@work.test', state: 'active', domainId: 'd1', position: 3, disabled: false, keys: [] })

  it('sends from the first enabled address in the account\'s order', () => {
    const account = mailAccountOf([work, own, old, bare], null, session, fold, self, { own: { displayName: 'Ada', signature: '' } })
    expect(account.addressId).toBe('work')
    expect(account.address).toBe('ada@work.test')
    // Every enabled address with a key sends, the default first; a disabled
    // one and one without keys don't.
    expect(account.senders.map((s) => s.addressId)).toEqual(['work', 'own'])
    expect(account.senders[1].name).toBe('Ada')
  })

  it('skips a disabled default and keeps every key for reading', () => {
    const account = mailAccountOf([{ ...work, disabled: true }, own], null, session, fold, self)
    expect(account.addressId).toBe('own')
    expect(account.olderKeys.map((k) => k.fingerprint)).toContain('fp-work')
  })

  it('writes as another address with its own key and name', () => {
    const account = mailAccountOf([work, own], null, session, fold, self, { own: { displayName: 'Ada L', signature: '' } })
    const asOwn = asSender(account, account.senders[1])
    expect(asOwn.addressId).toBe('own')
    expect(asOwn.address).toBe('ada@kutup.test')
    expect(asOwn.domain).toBe('kutup.test')
    expect(asOwn.key.fingerprint).toBe('fp-own')
    expect(asOwn.name).toBe('Ada L')
  })
})
