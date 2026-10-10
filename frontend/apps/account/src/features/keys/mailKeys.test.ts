import { describe, expect, it } from 'vitest'
import { changedEntries } from './mailKeys'

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
