import { afterEach, describe, expect, it } from 'vitest'
import type { EntryView } from '../vault/types'
import { DEFAULT_PREFS, hasTotp, loadPrefs, savePrefs, sortEntries, tagQuery, vaultTags } from './entryList'

function entry(id: string, fields: Record<string, string>, extra: Partial<EntryView> = {}): EntryView {
  return {
    id,
    groupId: 'g',
    fields: Object.entries(fields).map(([key, value]) => ({ key, value, protected: false })),
    tags: [],
    icon: null,
    hasCustomIcon: false,
    customIcon: null,
    foregroundColor: null,
    backgroundColor: null,
    overrideUrl: '',
    qualityCheck: true,
    expires: false,
    expiry: null,
    created: null,
    modified: null,
    accessed: null,
    attachments: [],
    autoType: null,
    historyCount: 0,
    review: [],
    inRecycleBin: false,
    ...extra,
  }
}

const a = entry('a', { Title: 'Banka 10', UserName: 'zeynep' }, { modified: '2026-11-03T10:00:00', tags: ['iş', 'finans'] })
const b = entry('b', { Title: 'banka 9', UserName: 'ayşe' }, { modified: '2026-11-01T10:00:00', tags: ['finans'] })
const c = entry('c', { Title: 'Çiçekçi' }, { expires: true, expiry: '2026-12-01T00:00:00', tags: ['ev'], inRecycleBin: true })
const ids = (list: EntryView[]) => list.map((e) => e.id)

describe('the entry list', () => {
  afterEach(() => localStorage.clear())

  it('sorts text as words, numbers by value, and either way', () => {
    expect(ids(sortEntries([a, b, c], 'title', false))).toEqual(['b', 'a', 'c'])
    expect(ids(sortEntries([a, b, c], 'title', true))).toEqual(['c', 'a', 'b'])
    expect(ids(sortEntries([a, b, c], 'userName', false))).toEqual(['b', 'a', 'c'])
  })

  it('sorts by time, entries without one last either way', () => {
    expect(ids(sortEntries([a, b, c], 'modified', false))).toEqual(['b', 'a', 'c'])
    expect(ids(sortEntries([a, b, c], 'modified', true))).toEqual(['a', 'b', 'c'])
    expect(ids(sortEntries([a, b, c], 'expiry', false))).toEqual(['c', 'b', 'a'])
  })

  it('lists tags outside the bin with their counts', () => {
    expect(vaultTags({ entries: [a, b, c] })).toEqual([
      { tag: 'finans', count: 2 },
      { tag: 'iş', count: 1 },
    ])
    expect(tagQuery('a "b"')).toBe('tag:"a b"')
  })

  it('keeps the choice on this device, ignoring what it does not know', () => {
    expect(loadPrefs()).toEqual(DEFAULT_PREFS)
    savePrefs({ sort: 'modified', descending: true, columns: ['url', 'totp'] })
    expect(loadPrefs()).toEqual({ sort: 'modified', descending: true, columns: ['url', 'totp'] })
    localStorage.setItem('kutup-pass-list', JSON.stringify({ sort: 'colour', columns: ['url', 'size'] }))
    expect(loadPrefs()).toEqual({ sort: 'title', descending: false, columns: ['url'] })
    localStorage.setItem('kutup-pass-list', '{')
    expect(loadPrefs()).toEqual(DEFAULT_PREFS)
  })

  it('knows a one-time code', () => {
    expect(hasTotp(entry('t', { otp: 'otpauth://totp/x?secret=A' }))).toBe(true)
    expect(hasTotp(a)).toBe(false)
  })
})
