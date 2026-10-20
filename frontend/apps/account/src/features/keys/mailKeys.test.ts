import { describe, expect, it } from 'vitest'
import { signedEntries } from '@kutup/mail-core/keyList'
import { asSigned, changedEntries, entriesWithKey, KeyNotInList } from './mailKeys'

const a = { fingerprint: 'aa', sha256Fingerprint: '01', primary: true, flags: 3 }
const b = { fingerprint: 'bb', sha256Fingerprint: '02', primary: false, flags: 3 }

describe('key list changes', () => {
  it('moves the primary to one key', () => {
    expect(changedEntries([a, b], 'bb', { kind: 'makePrimary' }).map((k) => k.primary)).toEqual([false, true])
  })

  it('marks a key obsolete and back', () => {
    const obsolete = changedEntries([a, b], 'bb', { kind: 'obsolete', on: true })
    expect(obsolete[1].flags).toBe(1)
    expect(obsolete[0]).toEqual(a)
    expect(changedEntries(obsolete, 'bb', { kind: 'obsolete', on: false })[1].flags).toBe(3)
  })

  it('clears both flags for a compromised key, and restores trust in signatures alone', () => {
    const compromised = changedEntries([a, b], 'bb', { kind: 'compromised', on: true })
    expect(compromised[1].flags).toBe(0)
    expect(changedEntries(compromised, 'bb', { kind: 'compromised', on: false })[1].flags).toBe(1)
  })
})

describe('key list changes start from the signed list', () => {
  const list = {
    address: 'alice@kutup.test',
    sequence: 1,
    issuedAt: '2026-10-20T00:00:00Z',
    keys: [a, b],
    data: 'data',
    signature: 'signature',
    hash: 'current',
  }
  const row = (key: typeof a) => ({ ...key, id: key.fingerprint, publicKey: '', privateKeyEnvelope: '', createdAt: '' })
  // The server adds a key of its own as primary and drops a flag from another.
  const injected = { fingerprint: 'cc', sha256Fingerprint: '03', primary: true, flags: 3 }
  const address = {
    id: 'address',
    address: list.address,
    keys: [row({ ...a, primary: false }), row({ ...b, flags: 1 }), row(injected)],
    keyList: { data: 'data', signature: 'signature' },
    verifiedList: list,
  }

  it('never takes in a key the server added, nor a flag it changed', () => {
    const next = changedEntries(signedEntries(address), 'bb', { kind: 'obsolete', on: true })
    expect(next).toEqual([a, { ...b, flags: 1 }])
    expect(next.some((key) => key.fingerprint === 'cc')).toBe(false)
    expect(entriesWithKey(signedEntries(address), { fingerprint: 'dd', sha256Fingerprint: '04' }, true).map((key) => key.fingerprint)).toEqual(['aa', 'bb', 'dd'])
  })

  it('refuses to change a key the signed list lacks', () => {
    expect(() => changedEntries(signedEntries(address), 'cc', { kind: 'makePrimary' })).toThrow(KeyNotInList)
  })

  it('shows each key as the signed list has it', () => {
    expect(asSigned(address, address.keys[0])).toMatchObject({ primary: true, flags: 3 })
    expect(asSigned(address, address.keys[1])).toMatchObject({ flags: 3 })
    expect(asSigned(address, address.keys[2])).toBeNull()
  })
})
